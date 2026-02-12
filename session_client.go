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

// MessageSessionClient is a client used to interact with a message session for a runner scale set.
// It provides methods to Get and Delete messages from the message queue associated with the session,
// handling session token expiration and refreshing as needed.
//
// It is safe for concurrent use by multiple goroutines.
// Please do not forget to call Close when done to clean up the session.
type MessageSessionClient struct {
	mu sync.Mutex
	// inner client is the parent of the message session, allowing session refreshing
	// use this client to create (and potentially refresh the session) requests.
	innerClient *Client
	// commonClient uses different options than the original client
	// use this client for message session requests
	commonClient *commonClient
	scaleSetID   int
	owner        string
	session      *RunnerScaleSetSession
}

// Close deletes the message session associated with this client.
func (c *MessageSessionClient) Close(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
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
	if err = c.doSessionRequest(
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
	return c.doSessionRequest(ctx, http.MethodDelete, path, nil, http.StatusNoContent, nil)
}

// RefreshMessageSession refreshes a message session for the specified runner scale set.
// This should be used when a MessageQueueTokenExpiredError is encountered.
func (c *MessageSessionClient) refreshMessageSession(ctx context.Context) error {
	path := fmt.Sprintf("/%s/%d/sessions/%s", scaleSetEndpoint, c.scaleSetID, c.session.SessionID.String())
	refreshedSession := &RunnerScaleSetSession{}
	if err := c.doSessionRequest(ctx, http.MethodPatch, path, nil, http.StatusOK, refreshedSession); err != nil {
		return fmt.Errorf("failed to do the session request: %w", err)
	}
	c.session = refreshedSession
	return nil
}

// GetMessage fetches a message from the runner scale set message queue. If there are no messages available, it returns (nil, nil).
// Unless a message is deleted after being processed (using DeleteMessage), it will be returned again in subsequent calls.
// If the current session token is expired, it refreshes the session and tries one more time.
func (c *MessageSessionClient) GetMessage(ctx context.Context, lastMessageID int, maxCapacity int) (*RunnerScaleSetMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	message, err := c.getMessage(
		ctx,
		lastMessageID,
		maxCapacity,
	)
	if err == nil {
		return message, nil
	}

	if !errors.Is(err, MessageQueueTokenExpiredError) {
		return nil, fmt.Errorf("failed to get next message: %w", err)
	}

	if err := c.refreshMessageSession(ctx); err != nil {
		return nil, fmt.Errorf("failed to refresh message session: %w", err)
	}

	return c.getMessage(
		ctx,
		lastMessageID,
		maxCapacity,
	)
}

func (c *MessageSessionClient) getMessage(ctx context.Context, lastMessageID int, maxCapacity int) (*RunnerScaleSetMessage, error) {
	u, err := url.Parse(c.session.MessageQueueURL)
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
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.session.MessageQueueAccessToken))
	req.Header.Set("User-Agent", c.commonClient.userAgent)
	req.Header.Set(HeaderScaleSetMaxCapacity, strconv.Itoa(maxCapacity))

	resp, err := c.commonClient.do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to issue the request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusAccepted:
		return nil, nil

	case http.StatusOK:
		message, err := parseRunnerScaleSetMessageResponse(resp.Body)
		if err != nil {
			return nil, newRequestResponseError(req, resp, fmt.Errorf("failed to parse message response: %w", err))
		}
		return message, nil

	case http.StatusUnauthorized:
		return nil, newRequestResponseError(req, resp, MessageQueueTokenExpiredError)

	default:
		return nil, newRequestResponseError(req, resp, fmt.Errorf("unexpected status code %s", resp.Status))
	}
}

// DeleteMessage deletes a message from the runner scale set message queue.
// This should typically be done after processing the message and acts as an acknowledgment.
// If the current session token is expired, it refreshes the session and tries one more time.
func (c *MessageSessionClient) DeleteMessage(ctx context.Context, messageID int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	err := c.deleteMessage(ctx, messageID)
	if err == nil {
		return nil
	}

	if !errors.Is(err, MessageQueueTokenExpiredError) {
		return fmt.Errorf("failed to delete message: %w", err)
	}

	if err := c.refreshMessageSession(ctx); err != nil {
		return fmt.Errorf("failed to refresh message session: %w", err)
	}

	return c.deleteMessage(ctx, messageID)
}

func (c *MessageSessionClient) deleteMessage(ctx context.Context, messageID int) error {
	u, err := url.Parse(c.session.MessageQueueURL)
	if err != nil {
		return fmt.Errorf("failed to parse message queue url: %w", err)
	}

	u.Path = fmt.Sprintf("%s/%d", u.Path, messageID)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create new request with context: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.session.MessageQueueAccessToken))
	req.Header.Set("User-Agent", c.commonClient.userAgent)

	resp, err := c.commonClient.do(req)
	if err != nil {
		return fmt.Errorf("failed to issue the request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil
	}

	if resp.StatusCode != http.StatusUnauthorized {
		return newRequestResponseError(req, resp, fmt.Errorf("unexpected status code %s", resp.Status))
	}

	return newRequestResponseError(req, resp, MessageQueueTokenExpiredError)
}

func (c *MessageSessionClient) Session() RunnerScaleSetSession {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.session == nil {
		return RunnerScaleSetSession{}
	}

	return *c.session
}

func (c *MessageSessionClient) doSessionRequest(ctx context.Context, method, path string, requestData io.Reader, expectedResponseStatusCode int, responseUnmarshalTarget any) error {
	c.innerClient.mu.Lock()
	defer c.innerClient.mu.Unlock()

	req, err := c.innerClient.newActionsServiceRequest(ctx, method, path, requestData)
	if err != nil {
		return fmt.Errorf("failed to create new actions service request: %w", err)
	}

	// use potentially modified client to issue a request
	resp, err := c.commonClient.do(req)
	if err != nil {
		return fmt.Errorf("failed to issue the request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != expectedResponseStatusCode {
		return newRequestResponseError(req, resp, fmt.Errorf("unexpected status code %s", resp.Status))
	}

	if responseUnmarshalTarget == nil {
		return nil
	}

	if err := json.NewDecoder(resp.Body).Decode(responseUnmarshalTarget); err != nil {
		return newRequestResponseError(req, resp, fmt.Errorf("failed to unmarshal response body: %w", err))
	}

	return nil
}
