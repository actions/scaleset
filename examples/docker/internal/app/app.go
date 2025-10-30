// Package app contains the main application logic for managing GitHub Actions self-hosted runners using Docker containers.
package app

import (
	"context"
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

	// Initialize and start the listener
	listener, err := listener.New(scalesetClient, listener.Config{
		ScaleSetID: scaleSet.ID,
		MinRunners: c.MinRunners,
		Logger:     slog.Default(),
	})
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}

	listener.Run(ctx, &AppHandler{
		logger: slog.Default(),
		state: runnerState{
			idle: make(map[string]string),
			busy: make(map[string]string),
		},
		runnerImage:    c.RunnerImage,
		minRunners:     c.MinRunners,
		dockerClient:   dockerClient,
		scalesetClient: scalesetClient,
		scaleSetID:     scaleSet.ID,
	})

	return nil
}

type AppHandler struct {
	state          runnerState
	runnerImage    string
	scaleSetID     int
	dockerClient   *dockerclient.Client
	scalesetClient *scaleset.Client
	minRunners     int
	logger         *slog.Logger
}

func (a *AppHandler) HandleDesiredRunnerCount(ctx context.Context, count int, jobsCompleted int) (int, error) {
	currentCount := a.state.totalCount()
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
		return a.state.totalCount(), nil
	default:
		// no need to handle scale down scenario since the completed runners are removed before we handle desired count
	}
	return currentCount, nil
}

func (a *AppHandler) HandleJobStarted(ctx context.Context, jobInfo *scaleset.JobStarted) error {
	a.logger.Info("Job started", slog.Int64("runnerRequestId", jobInfo.RunnerRequestID), slog.String("jobId", jobInfo.JobID))
	a.state.markBusy(jobInfo.RunnerName)
	return nil
}

func (a *AppHandler) HandleJobCompleted(ctx context.Context, jobInfo *scaleset.JobCompleted) error {
	a.logger.Info("Job completed", slog.Int64("runnerRequestId", jobInfo.RunnerRequestID), slog.String("jobId", jobInfo.JobID))

	containerID := a.state.markDone(jobInfo.RunnerName)
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

	a.state.addIdle(name, c.ID)
	return name, nil
}

var _ listener.Handler = (*AppHandler)(nil)

type runnerState struct {
	mu   sync.Mutex
	idle map[string]string
	busy map[string]string
}

func (r *runnerState) totalCount() int {
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
	if !ok {
		panic("marking non-existent runner done")
	}
	delete(r.busy, name)
	return containerID
}

func (r *runnerState) addIdle(name, containerID string) {
	r.mu.Lock()
	r.idle[name] = containerID
	r.mu.Unlock()
}
