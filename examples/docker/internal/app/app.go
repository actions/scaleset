// Package app contains the main application logic for managing GitHub Actions self-hosted runners using Docker containers.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"

	"github.com/actions/scaleset"
	"github.com/actions/scaleset/examples/docker/internal/config"
	"github.com/actions/scaleset/listener"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/google/uuid"
	dockerclient "github.com/moby/moby/client"
)

func Run(ctx context.Context, c config.Config) error {
	// Ensure that the config is valid
	if err := c.Validate(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	// Create a new scaleset scalesetClient
	scalesetClient, err := scaleset.NewClient(c.ConfigureURL, c.ActionsAuth())
	if err != nil {
		return err
	}

	// Get the runner group ID
	var runnerGroupID int
	switch c.RunnerGroup {
	case scaleset.DefaultRunnerGroup:
		runnerGroupID = 1
	default:
		runnerGroup, err := scalesetClient.GetRunnerGroupByName(ctx, c.RunnerGroup)
		if err != nil {
			return fmt.Errorf("failed to get runner group ID: %w", err)
		}
		runnerGroupID = runnerGroup.ID
	}

	// Create the runner scale set
	scaleSet, err := scalesetClient.CreateRunnerScaleSet(ctx, &scaleset.RunnerScaleSet{
		Name:          c.ScaleSetName,
		RunnerGroupID: runnerGroupID,
		Labels: []scaleset.Label{
			{
				Name: c.ScaleSetName,
				Type: "System",
			},
		},
		RunnerSetting: scaleset.RunnerSetting{
			Ephemeral:     true,
			DisableUpdate: true,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create runner scale set: %w", err)
	}

	defer func() {
		if err := scalesetClient.DeleteRunnerScaleSet(context.WithoutCancel(ctx), scaleSet.ID); err != nil {
			slog.Error("Failed to delete runner scale set", slog.Int("scaleSetID", scaleSet.ID), slog.String("error", err.Error()))
		}
	}()

	dockerClient, err := dockerclient.NewClientWithOpts(dockerclient.FromEnv, dockerclient.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create docker client: %w", err)
	}

	// Pull the runner image
	pull, err := dockerClient.ImagePull(ctx, c.RunnerImage, image.PullOptions{})
	if err != nil {
		return fmt.Errorf("failed to pull runner image: %w", err)
	}

	if _, err := io.ReadAll(pull); err != nil {
		return fmt.Errorf("failed to read image pull response: %w", err)
	}

	if err := pull.Close(); err != nil {
		return fmt.Errorf("failed to close image pull: %w", err)
	}

	logger := c.Logger()

	// Initialize and start the listener
	listener, err := listener.New(scalesetClient, listener.Config{
		ScaleSetID: scaleSet.ID,
		MinRunners: c.MinRunners,
		Logger:     logger.With("component", "listener"),
	})
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}

	handler := &AppHandler{
		logger: logger.With("component", "handler"),
		runners: runnerState{
			idle: make(map[string]string),
			busy: make(map[string]string),
		},
		runnerImage:    c.RunnerImage,
		minRunners:     c.MinRunners,
		dockerClient:   dockerClient,
		scalesetClient: scalesetClient,
		scaleSetID:     scaleSet.ID,
	}

	defer handler.shutdown(context.WithoutCancel(ctx))

	if err := listener.Run(ctx, handler); !errors.Is(err, context.Canceled) {
		return fmt.Errorf("listener run failed: %w", err)
	}
	return nil
}

type AppHandler struct {
	runners        runnerState
	runnerImage    string
	scaleSetID     int
	dockerClient   *dockerclient.Client
	scalesetClient *scaleset.Client
	minRunners     int
	logger         *slog.Logger
}

func (a *AppHandler) HandleDesiredRunnerCount(ctx context.Context, count int, jobsCompleted int) (int, error) {
	currentCount := a.runners.count()
	targetRunnerCount := min(a.minRunners + count)

	switch {
	case targetRunnerCount == currentCount:
		return currentCount, nil
	case targetRunnerCount > currentCount:
		scaleUp := targetRunnerCount - currentCount
		a.logger.Info(
			"Scaling down runners",
			slog.Int("currentCount", currentCount),
			slog.Int("desiredChange", scaleUp),
			slog.Int("newDesiredCount", targetRunnerCount),
		)

		var errs []error
		for range scaleUp {
			if _, err := a.startRunner(ctx); err != nil {
				errs = append(errs, err)
			}
		}

		for _, err := range errs {
			// TODO: should we return error?
			a.logger.Error("Failed to start runner", slog.String("error", err.Error()))
		}
		return a.runners.count(), nil
	default:
		// No need to handle scale down events, since:
		// 1. JobCompleted events will first remove runners
		// 2. If the count is still below the current runner count, the JobCompleted event will be delivered in the next batch.
		// 3. Removal after JobCompleted events is handled synchronously.
		// 4. If the job is cancelled, the JobCompleted event will still be delivered.
	}
	return a.runners.count(), nil
}

func (a *AppHandler) HandleJobStarted(ctx context.Context, jobInfo *scaleset.JobStarted) error {
	a.logger.Info("Job started", slog.Int64("runnerRequestId", jobInfo.RunnerRequestID), slog.String("jobId", jobInfo.JobID))
	a.runners.markBusy(jobInfo.RunnerName)
	return nil
}

func (a *AppHandler) HandleJobCompleted(ctx context.Context, jobInfo *scaleset.JobCompleted) error {
	a.logger.Info("Job completed", slog.Int64("runnerRequestId", jobInfo.RunnerRequestID), slog.String("jobId", jobInfo.JobID))

	containerID := a.runners.markDone(jobInfo.RunnerName)
	if err := a.dockerClient.ContainerRemove(ctx, containerID, container.RemoveOptions{Force: true}); err != nil {
		return fmt.Errorf("failed to remove runner container: %w", err)
	}

	return nil
}

func (a *AppHandler) startRunner(ctx context.Context) (string, error) {
	name := fmt.Sprintf("runner-%s", uuid.NewString()[:8])

	jit, err := a.scalesetClient.GenerateJitRunnerConfig(
		ctx,
		&scaleset.RunnerScaleSetJitRunnerSetting{
			Name: name,
		},
		a.scaleSetID,
	)
	if err != nil {
		return "", fmt.Errorf("failed to generate JIT config: %w", err)
	}

	c, err := a.dockerClient.ContainerCreate(
		ctx,
		&container.Config{
			Image: a.runnerImage,
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

	if err := a.dockerClient.ContainerStart(ctx, c.ID, container.StartOptions{}); err != nil {
		return "", fmt.Errorf("failed to start runner container: %w", err)
	}

	a.runners.addIdle(name, c.ID)
	return name, nil
}

func (a *AppHandler) shutdown(ctx context.Context) {
	a.logger.Info("Shutting down runners")
	a.runners.mu.Lock()
	defer a.runners.mu.Unlock()

	for name, containerID := range a.runners.idle {
		a.logger.Info("Removing idle runner", slog.String("name", name), slog.String("containerID", containerID))
		if err := a.dockerClient.ContainerRemove(ctx, containerID, container.RemoveOptions{Force: true}); err != nil {
			a.logger.Error("Failed to remove idle runner container", slog.String("name", name), slog.String("containerID", containerID), slog.String("error", err.Error()))
		}
	}

	for name, containerID := range a.runners.busy {
		a.logger.Info("Removing busy runner", slog.String("name", name), slog.String("containerID", containerID))
		if err := a.dockerClient.ContainerRemove(ctx, containerID, container.RemoveOptions{Force: true}); err != nil {
			a.logger.Error("Failed to remove busy runner container", slog.String("name", name), slog.String("containerID", containerID), slog.String("error", err.Error()))
		}
	}
}

var _ listener.Handler = (*AppHandler)(nil)

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
