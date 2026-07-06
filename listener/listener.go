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
	AcquireJobs(ctx context.Context, requestIDs []int64) ([]int64, error)
	Session() scaleset.RunnerScaleSetSession
}

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

type Option func(*Listener)

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

	for _, option := range options {
		option(listener)
	}

	return listener, nil
}

// Scaler defines the interface for handling scale set messages.
type Scaler interface {
	Scale(ctx context.Context, message *scaleset.RunnerScaleSetMessage) error
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

		if err := scaler.Scale(ctx, &scaleset.RunnerScaleSetMessage{
			MessageID:  -1, // Initial statistics message has no ID, the first message from the service will have ID 0
			Statistics: initialSession.Statistics,
		}); err != nil {
			return fmt.Errorf("failed to handle initial session statistics: %w", err)
		}

		l.logger.Info(
			"Handling initial session statistics",
			slog.Int("totalAssignedJobs", initialSession.Statistics.TotalAssignedJobs),
		)
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

		if msg != nil {
			lastMessageID = msg.MessageID
			if err := l.client.DeleteMessage(context.WithoutCancel(ctx), msg.MessageID); err != nil {
				return fmt.Errorf("failed to delete message: %w", err)
			}
		}

		if err := scaler.Scale(ctx, msg); err != nil {
			return fmt.Errorf("failed to scale: %w", err)
		}
	}
}
