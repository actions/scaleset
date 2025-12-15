// Package listener provides a listener for GitHub Actions runner scale set messages.
package listener

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/actions/scaleset"
	"github.com/google/uuid"
)

const (
	sessionCreationMaxRetries = 10
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
	CreateMessageSession(ctx context.Context, runnerScaleSetID int, owner string) (*scaleset.RunnerScaleSetSession, error)
	GetMessage(ctx context.Context, messageQueueURL, messageQueueAccessToken string, lastMessageID int, maxCapacity int) (*scaleset.RunnerScaleSetMessage, error)
	DeleteMessage(ctx context.Context, messageQueueURL, messageQueueAccessToken string, messageID int) error
	RefreshMessageSession(ctx context.Context, runnerScaleSetID int, sessionID uuid.UUID) (*scaleset.RunnerScaleSetSession, error)
	DeleteMessageSession(ctx context.Context, runnerScaleSetID int, sessionID uuid.UUID) error
}

// Listener listens for messages from the scaleset service and handles them. It automatically handles session
// creation/deletion/refreshing and message polling and acking.
type Listener struct {
	// The main client responsible for communicating with the scaleset service
	client Client

	// Configuration for the listener
	scaleSetID int
	maxRunners atomic.Uint32

	// lastMessageID keeps track of the last processed message ID
	lastMessageID int
	// hostname of the current machine
	hostname string
	// session represents the current message session
	session *scaleset.RunnerScaleSetSession

	// configuration for the listener
	logger *slog.Logger
}

// SetMaxRunners sets the capacity of the scaleset. It is concurrently
// safe to update the max runners during listener.Run.
func (l *Listener) SetMaxRunners(count int) {
	l.maxRunners.Store(uint32(count))
}

// New creates a new Listener with the given configuration.
func New(client Client, config Config) (*Listener, error) {
	if client == nil {
		return nil, errors.New("client is required")
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = uuid.NewString()
		config.Logger.Info("Failed to get hostname, fallback to uuid", "uuid", hostname, "error", err)
	}

	listener := &Listener{
		client:     client,
		scaleSetID: config.ScaleSetID,
		hostname:   hostname,
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
	l.logger.Info("Creating message session")
	if err := l.createSession(ctx); err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	defer func() {
		l.logger.Debug("Deleting message session")
		if err := l.deleteMessageSession(); err != nil {
			l.logger.Error(
				"failed to delete message session",
				slog.String("error", err.Error()),
			)
		}
	}()

	if l.session.Statistics == nil {
		return fmt.Errorf("session statistics is nil")
	}

	l.logger.Info("Message session created; listening for messages", "sessionID", l.session.SessionID)

	// Handle initial statistics
	if _, err := scaler.HandleDesiredRunnerCount(ctx, l.session.Statistics.TotalAssignedJobs); err != nil {
		return fmt.Errorf("handling initial message failed: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		msg, err := l.getMessage(ctx)
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

		// Remove cancellation from the context to avoid cancelling the message handling.
		if err := l.handleMessage(context.WithoutCancel(ctx), scaler, msg); err != nil {
			return fmt.Errorf("failed to handle message: %w", err)
		}
	}
}

func (l *Listener) handleMessage(ctx context.Context, handler Scaler, msg *scaleset.RunnerScaleSetMessage) error {
	l.lastMessageID = msg.MessageID
	if err := l.deleteLastMessage(ctx); err != nil {
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

func (l *Listener) createSession(ctx context.Context) error {
	var session *scaleset.RunnerScaleSetSession
	var retries int

	for {
		var err error
		session, err = l.client.CreateMessageSession(ctx, l.scaleSetID, l.hostname)
		if err == nil {
			break
		}

		clientErr := &scaleset.ActionsError{}
		if !errors.As(err, &clientErr) {
			return fmt.Errorf("failed to create session: %w", err)
		}

		if clientErr.StatusCode != http.StatusConflict {
			return fmt.Errorf("failed to create session: %w", err)
		}

		retries++
		if retries >= sessionCreationMaxRetries {
			return fmt.Errorf("failed to create session after %d retries: %w", retries, err)
		}

		l.logger.Info("Unable to create message session. Will try again in 30 seconds", "error", err.Error())

		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled: %w", ctx.Err())
		case <-time.After(30 * time.Second):
		}
	}

	statistics, err := json.Marshal(session.Statistics)
	if err != nil {
		return fmt.Errorf("failed to marshal statistics: %w", err)
	}
	l.logger.Info("Current runner scale set statistics.", "statistics", string(statistics))

	l.session = session

	return nil
}

func (l *Listener) getMessage(ctx context.Context) (*scaleset.RunnerScaleSetMessage, error) {
	l.logger.Info("Getting next message", "lastMessageID", l.lastMessageID)
	msg, err := l.client.GetMessage(
		ctx,
		l.session.MessageQueueURL,
		l.session.MessageQueueAccessToken,
		l.lastMessageID,
		int(l.maxRunners.Load()),
	)
	if err == nil { // if NO error
		return msg, nil
	}

	expiredError := &scaleset.ActionsError{}
	if !errors.As(err, &expiredError) || !expiredError.IsMessageQueueTokenExpired() {
		return nil, fmt.Errorf("failed to get next message: %w", err)
	}

	if err := l.refreshSession(ctx); err != nil {
		return nil, fmt.Errorf("failed to refresh message session: %w", err)
	}

	l.logger.Info("Getting next message", "lastMessageID", l.lastMessageID)

	msg, err = l.client.GetMessage(
		ctx,
		l.session.MessageQueueURL,
		l.session.MessageQueueAccessToken,
		l.lastMessageID,
		int(l.maxRunners.Load()),
	)
	if err != nil { // if error
		return nil, fmt.Errorf("failed to get next message after message session refresh: %w", err)
	}

	return msg, nil
}

func (l *Listener) deleteLastMessage(ctx context.Context) error {
	l.logger.Info("Deleting last message", "lastMessageID", l.lastMessageID)
	err := l.client.DeleteMessage(
		ctx,
		l.session.MessageQueueURL,
		l.session.MessageQueueAccessToken,
		l.lastMessageID,
	)
	if err == nil { // if NO error
		return nil
	}

	expiredError := &scaleset.ActionsError{}
	if !errors.As(err, &expiredError) || !expiredError.IsMessageQueueTokenExpired() {
		return fmt.Errorf("failed to delete last message: %w", err)
	}

	if err := l.refreshSession(ctx); err != nil {
		return fmt.Errorf("failed to refresh message session: %w", err)
	}

	err = l.client.DeleteMessage(
		ctx,
		l.session.MessageQueueURL,
		l.session.MessageQueueAccessToken,
		l.lastMessageID,
	)
	if err != nil {
		return fmt.Errorf("failed to delete last message after message session refresh: %w", err)
	}

	return nil
}

func (l *Listener) refreshSession(ctx context.Context) error {
	l.logger.Info("Message queue token is expired during GetNextMessage, refreshing...")
	session, err := l.client.RefreshMessageSession(
		ctx,
		l.session.RunnerScaleSet.ID,
		l.session.SessionID,
	)
	if err != nil {
		return fmt.Errorf("refresh message session failed. %w", err)
	}

	l.session = session
	return nil
}

func (l *Listener) deleteMessageSession() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	l.logger.Info("Deleting message session")

	if err := l.client.DeleteMessageSession(ctx, l.session.RunnerScaleSet.ID, l.session.SessionID); err != nil {
		return fmt.Errorf("failed to delete message session: %w", err)
	}

	return nil
}
