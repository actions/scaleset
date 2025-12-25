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
	Session() *scaleset.RunnerScaleSetSession
}

type Option func(*Listener)

// Listener listens for messages from the scaleset service and handles them. It automatically handles session
// creation/deletion/refreshing and message polling and acking.
type Listener struct {
	// The main client responsible for communicating with the scaleset service
	client Client

	// Configuration for the listener
	scaleSetID int
	maxRunners atomic.Uint32

	// configuration for the listener
	logger *slog.Logger
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
		client:     client,
		scaleSetID: config.ScaleSetID,
		logger:     config.Logger,
	}
	listener.SetMaxRunners(config.MaxRunners)

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

		if initialSession == nil {
			return fmt.Errorf("initial session is nil")
		}

		if initialSession.Statistics == nil {
			return fmt.Errorf("session statistics is nil")
		}

		l.logger.Info(
			"Handling initial session statistics",
			slog.Int("totalAssignedJobs", initialSession.Statistics.TotalAssignedJobs),
		)
		if _, err := scaler.HandleDesiredRunnerCount(ctx, initialSession.Statistics.TotalAssignedJobs); err != nil {
			return fmt.Errorf("handling initial message failed: %w", err)
		}
	}

	var lastMessageID int
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		msg, err := l.client.GetMessage(
			ctx,
			lastMessageID,
			int(l.maxRunners.Load()),
		)
		if err != nil {
			return fmt.Errorf("failed to get message: %w", err)
		}

		if msg == nil {
			_, err := scaler.HandleDesiredRunnerCount(ctx, 0)
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
	if err := l.client.DeleteMessage(ctx, msg.MessageID); err != nil {
		return fmt.Errorf("failed to delete message: %w", err)
	}

	for _, jobStarted := range msg.JobStartedMessages {
		if err := handler.HandleJobStarted(ctx, jobStarted); err != nil {
			return fmt.Errorf("failed to handle job started: %w", err)
		}
	}
	for _, jobCompleted := range msg.JobCompletedMessages {
		if err := handler.HandleJobCompleted(ctx, jobCompleted); err != nil {
			return fmt.Errorf("failed to handle job completed: %w", err)
		}
	}

	if _, err := handler.HandleDesiredRunnerCount(ctx, msg.Statistics.TotalAssignedJobs); err != nil {
		return fmt.Errorf("failed to handle desired runner count: %w", err)
	}

	return nil
}
