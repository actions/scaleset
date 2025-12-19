package scaleset

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"

	"github.com/google/uuid"
)

type MessageSessionClient struct {
	mu         sync.Mutex
	client     *Client
	scaleSetID int
	owner      string
	session    *RunnerScaleSetSession
}

func (c *MessageSessionClient) Close(ctx context.Context) error {
	return c.deleteMessageSession(ctx, c.scaleSetID, c.session.SessionID)
}

func (c *MessageSessionClient) createMessageSession(ctx context.Context) error {
	path := fmt.Sprintf("/%s/%d/sessions", scaleSetEndpoint, c.scaleSetID)

	newSession := &RunnerScaleSetSession{
		OwnerName: c.owner,
	}

	requestData, err := json.Marshal(newSession)
	if err != nil {
		return fmt.Errorf("failed to marshal new session: %w", err)
	}

	var createdSession RunnerScaleSetSession
	if err = c.client.doSessionRequest(
		ctx,
		http.MethodPost,
		path,
		bytes.NewBuffer(requestData),
		http.StatusOK,
		&createdSession,
	); err != nil {
		return fmt.Errorf("failed to do the session request: %w", err)
	}

	c.session = &createdSession

	return nil
}

// DeleteMessageSession deletes a message session for the specified runner scale set.
func (c *MessageSessionClient) deleteMessageSession(ctx context.Context, runnerScaleSetID int, sessionID uuid.UUID) error {
	path := fmt.Sprintf("/%s/%d/sessions/%s", scaleSetEndpoint, runnerScaleSetID, sessionID.String())
	return c.client.doSessionRequest(ctx, http.MethodDelete, path, nil, http.StatusNoContent, nil)
}

// RefreshMessageSession refreshes a message session for the specified runner scale set.
// This should be used when a MessageQueueTokenExpiredError is encountered.
func (c *MessageSessionClient) refreshMessageSession(ctx context.Context) error {
	path := fmt.Sprintf("/%s/%d/sessions/%s", scaleSetEndpoint, c.scaleSetID, c.session.SessionID.String())
	refreshedSession := &RunnerScaleSetSession{}
	if err := c.client.doSessionRequest(ctx, http.MethodPatch, path, nil, http.StatusOK, refreshedSession); err != nil {
		return fmt.Errorf("failed to do the session request: %w", err)
	}
	c.session = refreshedSession
	return nil
}

// GetMessage fetches a message from the runner scale set message queue. If there are no messages available, it returns (nil, nil).
// Unless a message is deleted after being processed (using DeleteMessage), it will be returned again in subsequent calls.
// If the current session token is expired, it returns a MessageQueueTokenExpiredError.
// In these cases the caller should refresh the session with RefreshMessageSession.
func (c *MessageSessionClient) GetMessage(ctx context.Context, lastMessageID int, maxCapacity int) (*RunnerScaleSetMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	message, err := c.getMessage(
		ctx,
		c.session.MessageQueueURL,
		c.session.MessageQueueAccessToken,
		lastMessageID,
		maxCapacity,
	)
	if err == nil {
		return message, nil
	}

	expiredError := &ActionsError{}
	if !errors.As(err, &expiredError) || !expiredError.IsMessageQueueTokenExpired() {
		return nil, fmt.Errorf("failed to get next message: %w", err)
	}

	if err := c.refreshMessageSession(ctx); err != nil {
		return nil, fmt.Errorf("failed to refresh message session: %w", err)
	}

	return c.getMessage(
		ctx,
		c.session.MessageQueueURL,
		c.session.MessageQueueAccessToken,
		lastMessageID,
		maxCapacity,
	)
}

func (c *MessageSessionClient) getMessage(ctx context.Context, messageQueueURL, messageQueueAccessToken string, lastMessageID int, maxCapacity int) (*RunnerScaleSetMessage, error) {
	u, err := url.Parse(messageQueueURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse message queue url: %w", err)
	}

	if lastMessageID > 0 {
		q := u.Query()
		q.Set("lastMessageId", strconv.Itoa(lastMessageID))
		u.RawQuery = q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create new request with context: %w", err)
	}

	req.Header.Set("Accept", "application/json; api-version=6.0-preview")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", messageQueueAccessToken))
	req.Header.Set("User-Agent", *c.client.userAgent.Load())
	req.Header.Set(HeaderScaleSetMaxCapacity, strconv.Itoa(maxCapacity))

	resp, err := c.client.do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to issue the request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusAccepted {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode != http.StatusUnauthorized {
			return nil, ParseActionsErrorFromResponse(resp)
		}

		body, err := io.ReadAll(resp.Body)
		body = trimByteOrderMark(body)
		if err != nil {
			return nil, &ActionsError{
				ActivityID: resp.Header.Get(headerActionsActivityID),
				StatusCode: resp.StatusCode,
				Err:        err,
			}
		}
		return nil, &ActionsError{
			ActivityID: resp.Header.Get(headerActionsActivityID),
			StatusCode: resp.StatusCode,
			Err: &messageQueueTokenExpiredError{
				message: string(body),
			},
		}
	}

	message, err := parseRunnerScaleSetMessageResponse(resp.Body)
	if err != nil {
		return nil, &ActionsError{
			StatusCode: resp.StatusCode,
			ActivityID: resp.Header.Get(headerActionsActivityID),
			Err:        err,
		}
	}

	return message, nil
}

// DeleteMessage deletes a message from the runner scale set message queue.
// This should typically be done after processing the message and acts as an acknowledgment.
// If the current session token is expired, it returns a MessageQueueTokenExpiredError.
// In these cases the caller should refresh the session with RefreshMessageSession.
func (c *MessageSessionClient) DeleteMessage(ctx context.Context, messageID int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	err := c.deleteMessage(
		ctx,
		c.session.MessageQueueURL,
		c.session.MessageQueueAccessToken,
		messageID,
	)
	if err == nil {
		return nil
	}

	expiredError := &ActionsError{}
	if !errors.As(err, &expiredError) || !expiredError.IsMessageQueueTokenExpired() {
		return fmt.Errorf("failed to delete message: %w", err)
	}

	if err := c.refreshMessageSession(ctx); err != nil {
		return fmt.Errorf("failed to refresh message session: %w", err)
	}

	return c.deleteMessage(
		ctx,
		c.session.MessageQueueURL,
		c.session.MessageQueueAccessToken,
		messageID,
	)
}

func (c *MessageSessionClient) deleteMessage(ctx context.Context, messageQueueURL, messageQueueAccessToken string, messageID int) error {
	u, err := url.Parse(messageQueueURL)
	if err != nil {
		return fmt.Errorf("failed to parse message queue url: %w", err)
	}

	u.Path = fmt.Sprintf("%s/%d", u.Path, messageID)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create new request with context: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", messageQueueAccessToken))
	req.Header.Set("User-Agent", *c.client.userAgent.Load())

	resp, err := c.client.do(req)
	if err != nil {
		return fmt.Errorf("failed to issue the request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil
	}

	if resp.StatusCode != http.StatusUnauthorized {
		return ParseActionsErrorFromResponse(resp)
	}

	body, err := io.ReadAll(resp.Body)
	body = trimByteOrderMark(body)
	if err != nil {
		return &ActionsError{
			ActivityID: resp.Header.Get(headerActionsActivityID),
			StatusCode: resp.StatusCode,
			Err:        err,
		}
	}
	return &ActionsError{
		ActivityID: resp.Header.Get(headerActionsActivityID),
		StatusCode: resp.StatusCode,
		Err: &messageQueueTokenExpiredError{
			message: string(body),
		},
	}
}

func (c *MessageSessionClient) Session() *RunnerScaleSetSession {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.session == nil {
		return nil
	}

	s := *c.session
	return &s
}
