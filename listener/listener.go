// Package listener provides a listener for GitHub Actions runner scale set messages.
package listener

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/actions/scaleset"
	"github.com/google/uuid"
)

const (
	sessionCreationMaxRetries = 10
)

type Config struct {
	ScaleSetID int
	MinRunners int
	MaxRunners int
	Logger     *slog.Logger
}

func (c *Config) defaults() {
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
}

func (c *Config) Validate() error {
	c.defaults()

	if c.ScaleSetID == 0 {
		return errors.New("scaleSetID is required")
	}
	if c.MinRunners < 0 {
		return errors.New("minRunners must be greater than or equal to 0")
	}
	if c.MaxRunners < 0 {
		return errors.New("maxRunners must be greater than or equal to 0")
	}
	if c.MaxRunners > 0 && c.MinRunners > c.MaxRunners {
		return errors.New("minRunners must be less than or equal to maxRunners")
	}
	return nil
}

type Listener struct {
	// The main client responsible for communicating with the scaleset service
	client *scaleset.Client

	// Configuration for the listener
	scaleSetID int
	minRunners int
	maxRunners int

	// lastMessageID keeps track of the last processed message ID
	lastMessageID int64
	// hostname of the current machine
	hostname string
	// session represents the current message session
	session *scaleset.RunnerScaleSetSession

	// configuration for the listener
	logger *slog.Logger
}

func New(client *scaleset.Client, config Config) (*Listener, error) {
	if client == nil {
		return nil, errors.New("client is required")
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = uuid.NewString()
		config.Logger.Info("Failed to get hostname, fallback to uuid", "uuid", hostname, "error", err)
	}

	return &Listener{
		client:     client,
		scaleSetID: config.ScaleSetID,
		minRunners: config.MinRunners,
		maxRunners: config.MaxRunners,
		hostname:   hostname,
		logger:     config.Logger,
	}, nil
}

type Scaler interface {
	HandleJobStarted(ctx context.Context, jobInfo *scaleset.JobStarted) error
	HandleJobCompleted(ctx context.Context, jobInfo *scaleset.JobCompleted) error
	HandleDesiredRunnerCount(ctx context.Context, count int) (int, error)
}

func (l *Listener) Run(ctx context.Context, handler Scaler) error {
	l.logger.Info("Creating message session")
	if err := l.createSession(ctx); err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	defer func() {
		l.logger.Debug("Deleting message session")
		if err := l.deleteMessageSession(); err != nil {
			l.logger.Error("failed to delete message session", "error", err.Error())
		}
	}()

	if l.session.Statistics == nil {
		return fmt.Errorf("session statistics is nil")
	}

	l.logger.Info("Message session created; listening for messages", "sessionID", l.session.SessionID)

	// Handle initial statistics
	if _, err := handler.HandleDesiredRunnerCount(ctx, l.session.Statistics.TotalAssignedJobs); err != nil {
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
			_, err := handler.HandleDesiredRunnerCount(ctx, 0)
			if err != nil {
				return fmt.Errorf("handling nil message failed: %w", err)
			}

			continue
		}

		// Remove cancellation from the context to avoid cancelling the message handling.
		if err := l.handleMessage(context.WithoutCancel(ctx), handler, msg); err != nil {
			return fmt.Errorf("failed to handle message: %w", err)
		}
	}
}

func (l *Listener) handleMessage(ctx context.Context, handler Scaler, msg *scaleset.RunnerScaleSetMessage) error {
	parsedMsg, err := l.parseMessage(ctx, msg)
	if err != nil {
		return fmt.Errorf("failed to parse message: %w", err)
	}

	l.lastMessageID = msg.MessageID

	if err := l.deleteLastMessage(ctx); err != nil {
		return fmt.Errorf("failed to delete message: %w", err)
	}

	for _, jobStarted := range parsedMsg.jobsStarted {
		if err := handler.HandleJobStarted(ctx, jobStarted); err != nil {
			return fmt.Errorf("failed to handle job started: %w", err)
		}
	}
	for _, jobCompleted := range parsedMsg.jobsCompleted {
		if err := handler.HandleJobCompleted(ctx, jobCompleted); err != nil {
			return fmt.Errorf("failed to handle job completed: %w", err)
		}
	}

	if _, err := handler.HandleDesiredRunnerCount(ctx, parsedMsg.statistics.TotalAssignedJobs); err != nil {
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

		clientErr := &scaleset.HttpClientSideError{}
		if !errors.As(err, &clientErr) {
			return fmt.Errorf("failed to create session: %w", err)
		}

		if clientErr.Code != http.StatusConflict {
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
		l.maxRunners,
	)
	if err == nil { // if NO error
		return msg, nil
	}

	expiredError := &scaleset.MessageQueueTokenExpiredError{}
	if !errors.As(err, &expiredError) {
		return nil, fmt.Errorf("failed to get next message: %w", err)
	}

	if err := l.refreshSession(ctx); err != nil {
		return nil, err
	}

	l.logger.Info("Getting next message", "lastMessageID", l.lastMessageID)

	msg, err = l.client.GetMessage(
		ctx,
		l.session.MessageQueueURL,
		l.session.MessageQueueAccessToken,
		l.lastMessageID,
		l.maxRunners,
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

	expiredError := &scaleset.MessageQueueTokenExpiredError{}
	if !errors.As(err, &expiredError) {
		return fmt.Errorf("failed to delete last message: %w", err)
	}

	if err := l.refreshSession(ctx); err != nil {
		return err
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

type parsedMessage struct {
	statistics    *scaleset.RunnerScaleSetStatistic
	jobsStarted   []*scaleset.JobStarted
	jobsCompleted []*scaleset.JobCompleted
}

func (l *Listener) parseMessage(ctx context.Context, msg *scaleset.RunnerScaleSetMessage) (*parsedMessage, error) {
	if msg.MessageType != "RunnerScaleSetJobMessages" {
		l.logger.Info("Skipping message", "messageType", msg.MessageType)
		return nil, fmt.Errorf("invalid message type: %s", msg.MessageType)
	}

	l.logger.Info("Processing message", "messageId", msg.MessageID, "messageType", msg.MessageType)
	if msg.Statistics == nil {
		return nil, fmt.Errorf("invalid message: statistics is nil")
	}

	l.logger.Info("New runner scale set statistics.", "statistics", msg.Statistics)

	var batchedMessages []json.RawMessage
	if len(msg.Body) > 0 {
		if err := json.Unmarshal([]byte(msg.Body), &batchedMessages); err != nil {
			return nil, fmt.Errorf("failed to unmarshal batched messages: %w", err)
		}
	}

	parsedMsg := &parsedMessage{
		statistics: msg.Statistics,
	}

	for _, msg := range batchedMessages {
		var messageType scaleset.JobMessageType
		if err := json.Unmarshal(msg, &messageType); err != nil {
			return nil, fmt.Errorf("failed to decode job message type: %w", err)
		}

		switch messageType.MessageType {
		case scaleset.MessageTypeJobAssigned:
			var jobAssigned scaleset.JobAssigned
			if err := json.Unmarshal(msg, &jobAssigned); err != nil {
				return nil, fmt.Errorf("failed to decode job assigned: %w", err)
			}

			l.logger.Info("Job assigned message received", "jobId", jobAssigned.JobID)

		case scaleset.MessageTypeJobStarted:
			var jobStarted scaleset.JobStarted
			if err := json.Unmarshal(msg, &jobStarted); err != nil {
				return nil, fmt.Errorf("could not decode job started message. %w", err)
			}
			l.logger.Info("Job started message received.", "JobID", jobStarted.JobID, "RunnerId", jobStarted.RunnerID)
			parsedMsg.jobsStarted = append(parsedMsg.jobsStarted, &jobStarted)

		case scaleset.MessageTypeJobCompleted:
			var jobCompleted scaleset.JobCompleted
			if err := json.Unmarshal(msg, &jobCompleted); err != nil {
				return nil, fmt.Errorf("failed to decode job completed: %w", err)
			}

			l.logger.Info(
				"Job completed message received.",
				"JobID", jobCompleted.JobID,
				"Result", jobCompleted.Result,
				"RunnerId", jobCompleted.RunnerID,
				"RunnerName", jobCompleted.RunnerName,
			)
			parsedMsg.jobsCompleted = append(parsedMsg.jobsCompleted, &jobCompleted)

		default:
			l.logger.Info("unknown job message type.", "messageType", messageType.MessageType)
		}
	}

	return parsedMsg, ctx.Err()
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
