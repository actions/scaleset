package main

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/actions/scaleset"
	"github.com/actions/scaleset/listener"
	"github.com/docker/docker/api/types/container"
	dockerclient "github.com/docker/docker/client"
	"github.com/google/uuid"
)

type Scaler struct {
	runners        runnerState
	runnerImage    string
	scaleSetID     int
	dockerClient   *dockerclient.Client
	scalesetClient *scaleset.Client
	minRunners     int
	maxRunners     int
	logger         *slog.Logger
}

func (s *Scaler) Scale(ctx context.Context, msg *scaleset.RunnerScaleSetMessage) error {
	if msg == nil {
		return nil
	}
	for _, jobStarted := range msg.JobStartedMessages {
		if err := s.HandleJobStarted(ctx, jobStarted); err != nil {
			return fmt.Errorf("failed to handle job started: %w", err)
		}
	}
	for _, jobCompleted := range msg.JobCompletedMessages {
		if err := s.HandleJobCompleted(ctx, jobCompleted); err != nil {
			return fmt.Errorf("failed to handle job completed: %w", err)
		}
	}

	if _, err := s.HandleDesiredRunnerCount(ctx, msg.Statistics.TotalAssignedJobs); err != nil {
		return fmt.Errorf("failed to handle desired runner count: %w", err)
	}

	return nil
}

func (s *Scaler) HandleDesiredRunnerCount(ctx context.Context, count int) (int, error) {
	currentCount := s.runners.count()
	targetRunnerCount := min(s.maxRunners, s.minRunners+count)

	switch {
	case targetRunnerCount == currentCount:
		// No scaling needed
		return currentCount, nil
	case targetRunnerCount > currentCount:
		// Scale up
		scaleUp := targetRunnerCount - currentCount
		s.logger.Info(
			"Scaling up runners",
			slog.Int("currentCount", currentCount),
			slog.Int("desiredCount", targetRunnerCount),
			slog.Int("scaleUp", scaleUp),
		)

		for range scaleUp {
			if _, err := s.startRunner(ctx); err != nil {
				return 0, fmt.Errorf("failed to start runner: %w", err)
			}
		}

		return s.runners.count(), nil
	default:
		// No need to handle scale down events, since:
		// 1. JobCompleted events will first remove runners
		// 2. If the count is still below the current runner count, the JobCompleted event will be delivered in the next batch.
		// 3. Removal after JobCompleted events is handled synchronously.
		// 4. If the job is cancelled, the JobCompleted event will still be delivered.
	}
	return s.runners.count(), nil
}

func (s *Scaler) HandleJobStarted(ctx context.Context, jobInfo *scaleset.JobStarted) error {
	s.logger.Info(
		"Job started",
		slog.Int64("runnerRequestId", jobInfo.RunnerRequestID),
		slog.String("jobId", jobInfo.JobID),
	)
	s.runners.markBusy(jobInfo.RunnerName)
	return nil
}

func (s *Scaler) HandleJobCompleted(ctx context.Context, jobInfo *scaleset.JobCompleted) error {
	s.logger.Info("Job completed", slog.Int64("runnerRequestId", jobInfo.RunnerRequestID), slog.String("jobId", jobInfo.JobID))

	containerID := s.runners.markDone(jobInfo.RunnerName)
	if err := s.dockerClient.ContainerRemove(ctx, containerID, container.RemoveOptions{Force: true}); err != nil {
		return fmt.Errorf("failed to remove runner container: %w", err)
	}

	return nil
}

func (s *Scaler) startRunner(ctx context.Context) (string, error) {
	name := fmt.Sprintf("runner-%s", uuid.NewString()[:8])

	jit, err := s.scalesetClient.GenerateJitRunnerConfig(
		ctx,
		&scaleset.RunnerScaleSetJitRunnerSetting{
			Name: name,
		},
		s.scaleSetID,
	)
	if err != nil {
		return "", fmt.Errorf("failed to generate JIT config: %w", err)
	}

	c, err := s.dockerClient.ContainerCreate(
		ctx,
		&container.Config{
			Image: s.runnerImage,
			User:  "runner",
			Cmd:   []string{"/home/runner/run.sh"},
			Env: []string{
				fmt.Sprintf("ACTIONS_RUNNER_INPUT_JITCONFIG=%s", jit.EncodedJITConfig),
			},
		},
		nil,
		nil, nil,
		name,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create runner container: %w", err)
	}

	if err := s.dockerClient.ContainerStart(ctx, c.ID, container.StartOptions{}); err != nil {
		return "", fmt.Errorf("failed to start runner container: %w", err)
	}

	s.runners.addIdle(name, c.ID)
	return name, nil
}

func (s *Scaler) shutdown(ctx context.Context) {
	s.logger.Info("Shutting down runners")
	s.runners.mu.Lock()
	defer s.runners.mu.Unlock()

	for name, containerID := range s.runners.idle {
		s.logger.Info("Removing idle runner", slog.String("name", name), slog.String("containerID", containerID))
		if err := s.dockerClient.ContainerRemove(ctx, containerID, container.RemoveOptions{Force: true}); err != nil {
			s.logger.Error("Failed to remove idle runner container", slog.String("name", name), slog.String("containerID", containerID), slog.String("error", err.Error()))
		}
	}
	clear(s.runners.idle)

	for name, containerID := range s.runners.busy {
		s.logger.Info("Removing busy runner", slog.String("name", name), slog.String("containerID", containerID))
		if err := s.dockerClient.ContainerRemove(ctx, containerID, container.RemoveOptions{Force: true}); err != nil {
			s.logger.Error("Failed to remove busy runner container", slog.String("name", name), slog.String("containerID", containerID), slog.String("error", err.Error()))
		}
	}
	clear(s.runners.busy)
}

var _ listener.Scaler = (*Scaler)(nil)

type runnerState struct {
	mu   sync.Mutex
	idle map[string]string
	busy map[string]string
}

func (r *runnerState) count() int {
	r.mu.Lock()
	count := len(r.idle) + len(r.busy)
	r.mu.Unlock()
	return count
}

func (r *runnerState) markBusy(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state, ok := r.idle[name]
	if !ok {
		panic("marking non-existent runner busy")
	}
	delete(r.idle, name)
	r.busy[name] = state
}

func (r *runnerState) markDone(name string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.markDoneUnlocked(name)
}

func (r *runnerState) markDoneUnlocked(name string) string {
	containerID, ok := r.busy[name]
	if ok {
		delete(r.busy, name)
		return containerID
	}
	containerID, ok = r.idle[name]
	if ok {
		delete(r.idle, name)
		return containerID
	}
	panic("marking non-existent runner done")
}

func (r *runnerState) addIdle(name, containerID string) {
	r.mu.Lock()
	r.idle[name] = containerID
	r.mu.Unlock()
}
