// Package listener provides a listener for GitHub Actions runner scale set messages.
package listener

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync/atomic"

	"github.com/actions/scaleset"
	"github.com/google/uuid"
)

// Config holds the configuration for the Listener.
type Config struct {
	// ScaleSetID is the ID of the runner scale set to listen to.
	ScaleSetID int
	// MaxRunners is the capacity of runners that can be handled at once.
	MaxRunners int
	// Logger is the logger to use for logging. Default is a no-op logger.
	Logger *slog.Logger
}

func (c *Config) defaults() {
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
}

// Validate returns an error if the configuration is invalid.
func (c *Config) Validate() error {
	c.defaults()

	if c.ScaleSetID == 0 {
		return errors.New("scaleSetID is required")
	}
	if c.MaxRunners < 0 || c.MaxRunners > math.MaxInt32 {
		return errors.New("maxRunners must be between 0 and MaxInt32")
	}
	return nil
}

// Client defines the interface for communicating with the scaleset API.
// In most cases, it should be scaleset.Client from the scaleset package.
// This interface is defined to allow for easier testing and mocking, as well
// as allowing wrappers around the scaleset client if needed.
type Client interface {
	GetMessage(ctx context.Context, lastMessageID, maxCapacity int) (*scaleset.RunnerScaleSetMessage, error)
	DeleteMessage(ctx context.Context, messageID int) error
	Session() scaleset.RunnerScaleSetSession
}

// MetricsRecorder defines the hook methods that will be called by the listener at
// various points in the message handling process. This allows for custom
// metrics to be collected without coupling the listener to a specific metrics
// implementation. The methods in this interface will be called with relevant
// information about the message handling process, such as the number of jobs
// started/completed, the desired runner count, and any errors that occur.
// Implementers can use this information to track the performance and behavior
// of the listener and the scaleset service.
type MetricsRecorder interface {
	RecordStatistics(statistics *scaleset.RunnerScaleSetStatistic)
	RecordJobStarted(msg *scaleset.JobStarted)
	RecordJobCompleted(msg *scaleset.JobCompleted)
	RecordhDesiredRunners(count int)
}

type discardMetricsRecorder struct{}

func (d *discardMetricsRecorder) RecordStatistics(statistics *scaleset.RunnerScaleSetStatistic) {}
func (d *discardMetricsRecorder) RecordJobStarted(msg *scaleset.JobStarted)                     {}
func (d *discardMetricsRecorder) RecordJobCompleted(msg *scaleset.JobCompleted)                 {}
func (d *discardMetricsRecorder) RecordhDesiredRunners(count int)                               {}

// Listener listens for messages from the scaleset service and handles them. It automatically handles session
// creation/deletion/refreshing and message polling and acking.
type Listener struct {
	// The main client responsible for communicating with the scaleset service
	client          Client
	metricsRecorder MetricsRecorder

	// Configuration for the listener
	scaleSetID       int
	maxRunners       atomic.Uint32
	latestStatistics *scaleset.RunnerScaleSetStatistic

	// configuration for the listener
	logger *slog.Logger
}

type Option func(*Listener)

func WithMetricsRecorder(recorder MetricsRecorder) Option {
	return func(l *Listener) {
		l.metricsRecorder = recorder
	}
}

// SetMaxRunners sets the capacity of the scaleset. It is concurrently
// safe to update the max runners during listener.Run.
func (l *Listener) SetMaxRunners(count int) {
	l.maxRunners.Store(uint32(count))
}

// New creates a new Listener with the given configuration.
func New(client Client, config Config, options ...Option) (*Listener, error) {
	if client == nil {
		return nil, errors.New("client is required")
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	listener := &Listener{
		client:          client,
		metricsRecorder: &discardMetricsRecorder{},
		scaleSetID:      config.ScaleSetID,
		logger:          config.Logger,
	}
	listener.SetMaxRunners(config.MaxRunners)

	for _, option := range options {
		option(listener)
	}

	return listener, nil
}

// Scaler defines the interface for handling scale set messages.
type Scaler interface {
	HandleJobStarted(ctx context.Context, jobInfo *scaleset.JobStarted) error
	HandleJobCompleted(ctx context.Context, jobInfo *scaleset.JobCompleted) error
	HandleDesiredRunnerCount(ctx context.Context, count int) (int, error)
}

// Run starts the listener and processes messages using the provided scaler.
func (l *Listener) Run(ctx context.Context, scaler Scaler) error {
	{
		initialSession := l.client.Session()

		if initialSession.SessionID == uuid.Nil {
			return fmt.Errorf("initial session is nil")
		}

		if initialSession.Statistics == nil {
			return fmt.Errorf("session statistics is nil")
		}

		l.handleStatistics(ctx, initialSession.Statistics)

		l.logger.Info(
			"Handling initial session statistics",
			slog.Int("totalAssignedJobs", initialSession.Statistics.TotalAssignedJobs),
		)
		desiredCount, err := scaler.HandleDesiredRunnerCount(ctx, initialSession.Statistics.TotalAssignedJobs)
		if err != nil {
			return fmt.Errorf("handling initial message failed: %w", err)
		}
		l.metricsRecorder.RecordhDesiredRunners(desiredCount)
	}

	var lastMessageID int
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		l.logger.Info("Getting next message", slog.Int("lastMessageID", lastMessageID))
		msg, err := l.client.GetMessage(
			ctx,
			lastMessageID,
			int(l.maxRunners.Load()),
		)
		if err != nil {
			return fmt.Errorf("failed to get message: %w", err)
		}

		if msg == nil {
			_, err := scaler.HandleDesiredRunnerCount(ctx, l.latestStatistics.TotalAssignedJobs)
			if err != nil {
				return fmt.Errorf("handling nil message failed: %w", err)
			}

			continue
		}

		lastMessageID = msg.MessageID

		// Remove cancellation from the context to avoid cancelling the message handling.
		if err := l.handleMessage(context.WithoutCancel(ctx), scaler, msg); err != nil {
			return fmt.Errorf("failed to handle message: %w", err)
		}
	}
}

func (l *Listener) handleMessage(ctx context.Context, handler Scaler, msg *scaleset.RunnerScaleSetMessage) error {
	l.handleStatistics(ctx, msg.Statistics)

	if err := l.client.DeleteMessage(ctx, msg.MessageID); err != nil {
		return fmt.Errorf("failed to delete message: %w", err)
	}

	for _, jobStarted := range msg.JobStartedMessages {
		l.metricsRecorder.RecordJobStarted(jobStarted)
		if err := handler.HandleJobStarted(ctx, jobStarted); err != nil {
			return fmt.Errorf("failed to handle job started: %w", err)
		}
	}
	for _, jobCompleted := range msg.JobCompletedMessages {
		l.metricsRecorder.RecordJobCompleted(jobCompleted)
		if err := handler.HandleJobCompleted(ctx, jobCompleted); err != nil {
			return fmt.Errorf("failed to handle job completed: %w", err)
		}
	}

	desiredCount, err := handler.HandleDesiredRunnerCount(ctx, msg.Statistics.TotalAssignedJobs)
	if err != nil {
		return fmt.Errorf("failed to handle desired runner count: %w", err)
	}
	l.metricsRecorder.RecordhDesiredRunners(desiredCount)

	return nil
}

func (l *Listener) handleStatistics(ctx context.Context, msg *scaleset.RunnerScaleSetStatistic) {
	l.latestStatistics = msg
	l.metricsRecorder.RecordStatistics(msg)
}
