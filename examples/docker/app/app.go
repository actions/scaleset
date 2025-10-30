package app

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/actions/scaleset"
	"github.com/actions/scaleset/examples/docker/config"
	"github.com/actions/scaleset/listener"
	"github.com/docker/docker/api/types/container"
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
	case "default":
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

	// Initialize and start the listener
	listener, err := listener.New(scalesetClient, listener.Config{
		ScaleSetID: scaleSet.ID,
		MinRunners: c.MinRunners,
		MaxRunners: c.MaxRunners,
		Logger:     slog.Default(),
	})
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}

	dockerClient, err := dockerclient.NewClientWithOpts(dockerclient.FromEnv, dockerclient.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create docker client: %w", err)
	}

	listener.Run(ctx, &AppHandler{
		logger:         slog.Default(),
		containers:     make(map[string]*containerMeta),
		runnerImage:    c.RunnerImage,
		dockerClient:   dockerClient,
		scalesetClient: scalesetClient,
		scaleSetID:     scaleSet.ID,
	})

	return nil
}

type AppHandler struct {
	containers     map[string]*containerMeta
	runnerImage    string
	scaleSetID     int
	dockerClient   *dockerclient.Client
	scalesetClient *scaleset.Client
	logger         *slog.Logger
}

func (a *AppHandler) HandleDesiredRunnerCount(ctx context.Context, count int, jobsCompleted int) (int, error) {
	currentCount := len(a.containers)
	switch {
	case count == currentCount:
		return currentCount, nil
	case count > currentCount:
		scaleUp := count - currentCount
		a.logger.Info(
			"Scaling down runners",
			slog.Int("currentCount", currentCount),
			slog.Int("desiredChange", scaleUp),
			slog.Int("newDesiredCount", count),
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
		return len(a.containers), nil
	default: // scale down
		desired := currentCount - count
		a.logger.Info("Scaling up runners", slog.Int("currentCount", currentCount), slog.Int("desiredChange", desired), slog.Int("newDesiredCount", count))
		// ignore for now
		return len(a.containers), nil
	}
}

func (a *AppHandler) HandleJobStarted(ctx context.Context, jobInfo *scaleset.JobStarted) error {
	a.logger.Info("Job started", slog.Int64("runnerRequestId", jobInfo.RunnerRequestID), slog.String("jobId", jobInfo.JobID))
	meta, ok := a.containers[jobInfo.RunnerName]
	if !ok {
		return fmt.Errorf("runner container not found: %s", jobInfo.RunnerName)
	}
	meta.state = stateBusy
	return nil
}

func (a *AppHandler) HandleJobCompleted(ctx context.Context, jobInfo *scaleset.JobCompleted) error {
	a.logger.Info("Job completed", slog.Int64("runnerRequestId", jobInfo.RunnerRequestID), slog.String("jobId", jobInfo.JobID))

	meta := a.containers[jobInfo.RunnerName]
	if err := a.dockerClient.ContainerRemove(ctx, meta.id, container.RemoveOptions{Force: true}); err != nil {
		return fmt.Errorf("failed to remove runner container: %w", err)
	}
	delete(a.containers, jobInfo.RunnerName)

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

	a.containers[name] = &containerMeta{
		id:    c.ID,
		state: stateIdle,
	}
	return name, nil
}

var _ listener.Handler = (*AppHandler)(nil)

type state int

const (
	stateIdle state = iota
	stateBusy
)

type containerMeta struct {
	id    string
	state state
}
