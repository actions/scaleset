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
	"sync/atomic"

	"github.com/google/uuid"
)

// MessageSessionClient is a client used to interact with a message session for a runner scale set.
// It provides methods to Get and Delete messages from the message queue associated with the session,
// handling session token expiration and refreshing as needed.
//
// It is safe for concurrent use by multiple goroutines.
// Please do not forget to call Close when done to clean up the session.
type MessageSessionClient struct {
	refreshMu sync.Mutex
	// inner client is the parent of the message session, allowing session refreshing
	// use this client to create (and potentially refresh the session) requests.
	innerClient *Client
	// commonClient uses different options than the original client
	// use this client for message session requests
	commonClient *commonClient
	scaleSetID   int
	owner        string
	session      atomic.Pointer[RunnerScaleSetSession]
}

// Close deletes the message session associated with this client.
func (c *MessageSessionClient) Close(ctx context.Context) error {
	session := c.Session()
	return c.deleteMessageSession(ctx, c.scaleSetID, session.SessionID)
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

	c.session.Store(&createdSession)

	return nil
}

// DeleteMessageSession deletes a message session for the specified runner scale set.
func (c *MessageSessionClient) deleteMessageSession(ctx context.Context, runnerScaleSetID int, sessionID uuid.UUID) error {
	path := fmt.Sprintf("/%s/%d/sessions/%s", scaleSetEndpoint, runnerScaleSetID, sessionID.String())
	return c.doSessionRequest(ctx, http.MethodDelete, path, nil, http.StatusNoContent, nil)
}

// RefreshMessageSession refreshes a message session for the specified runner scale set.
// This should be used when a MessageQueueTokenExpiredError is encountered.
func (c *MessageSessionClient) refreshMessageSession(ctx context.Context, expiredSession RunnerScaleSetSession) error {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()

	session := c.Session()
	if session.SessionID != expiredSession.SessionID || session.MessageQueueAccessToken != expiredSession.MessageQueueAccessToken {
		return nil
	}

	path := fmt.Sprintf("/%s/%d/sessions/%s", scaleSetEndpoint, c.scaleSetID, session.SessionID.String())
	refreshedSession := &RunnerScaleSetSession{}
	if err := c.doSessionRequest(ctx, http.MethodPatch, path, nil, http.StatusOK, refreshedSession); err != nil {
		return fmt.Errorf("failed to do the session request: %w", err)
	}

	c.session.Store(refreshedSession)
	return nil
}

// refreshOrRecreateSession refreshes the message session; when the service no
// longer knows the session (404 on the refresh), it creates a fresh session in
// place instead of failing. Without this, a broker-side session eviction is
// fatal to the caller on every token refresh even though a new session would
// work fine — and the caller's message cursor (lastMessageId, passed per
// request) survives re-creation. Only the 404 path re-creates; every other
// refresh failure surfaces exactly as before.
func (c *MessageSessionClient) refreshOrRecreateSession(ctx context.Context, expiredSession RunnerScaleSetSession) error {
	refreshErr := c.refreshMessageSession(ctx, expiredSession)
	if refreshErr == nil {
		return nil
	}
	if !errors.Is(refreshErr, NotFoundError) {
		return refreshErr
	}
	if createErr := c.recreateMessageSession(ctx, expiredSession); createErr != nil {
		return fmt.Errorf("%w (session was gone; re-create also failed: %v)", refreshErr, createErr)
	}
	return nil
}

// recreateMessageSession mirrors refreshMessageSession's locking and
// double-check: if another goroutine already replaced the session, do nothing.
func (c *MessageSessionClient) recreateMessageSession(ctx context.Context, expiredSession RunnerScaleSetSession) error {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()

	session := c.Session()
	if session.SessionID != expiredSession.SessionID {
		return nil
	}

	return c.createMessageSession(ctx)
}

// GetMessage fetches a message from the runner scale set message queue. If there are no messages available, it returns (nil, nil).
// Unless a message is deleted after being processed (using DeleteMessage), it will be returned again in subsequent calls.
// If the current session token is expired, it refreshes the session and tries one more time.
func (c *MessageSessionClient) GetMessage(ctx context.Context, lastMessageID int, maxCapacity int) (*RunnerScaleSetMessage, error) {
	session := c.Session()
	message, err := c.getMessage(
		ctx,
		session,
		lastMessageID,
		maxCapacity,
	)
	if err == nil {
		return message, nil
	}

	if !errors.Is(err, MessageQueueTokenExpiredError) {
		return nil, fmt.Errorf("failed to get next message: %w", err)
	}

	if err := c.refreshOrRecreateSession(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to refresh message session: %w", err)
	}

	return c.getMessage(
		ctx,
		c.Session(),
		lastMessageID,
		maxCapacity,
	)
}

func (c *MessageSessionClient) getMessage(ctx context.Context, session RunnerScaleSetSession, lastMessageID int, maxCapacity int) (*RunnerScaleSetMessage, error) {
	u, err := url.Parse(session.MessageQueueURL)
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
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", session.MessageQueueAccessToken))
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
	session := c.Session()
	err := c.deleteMessage(ctx, session, messageID)
	if err == nil {
		return nil
	}

	if !errors.Is(err, MessageQueueTokenExpiredError) {
		return fmt.Errorf("failed to delete message: %w", err)
	}

	if err := c.refreshOrRecreateSession(ctx, session); err != nil {
		return fmt.Errorf("failed to refresh message session: %w", err)
	}

	return c.deleteMessage(ctx, c.Session(), messageID)
}

func (c *MessageSessionClient) deleteMessage(ctx context.Context, session RunnerScaleSetSession, messageID int) error {
	u, err := url.Parse(session.MessageQueueURL)
	if err != nil {
		return fmt.Errorf("failed to parse message queue url: %w", err)
	}

	u.Path = fmt.Sprintf("%s/%d", u.Path, messageID)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create new request with context: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", session.MessageQueueAccessToken))
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
	session := c.session.Load()
	if session == nil {
		return RunnerScaleSetSession{}
	}

	return *session
}

// AcquireJobs acquires the given job request IDs from the runner scale set.
// If the current session token is expired, it refreshes the session and tries one more time.
func (c *MessageSessionClient) AcquireJobs(ctx context.Context, requestIDs []int64) ([]int64, error) {
	session := c.Session()
	ids, err := c.acquireJobs(ctx, session, requestIDs)
	if err == nil {
		return ids, nil
	}

	if !errors.Is(err, MessageQueueTokenExpiredError) {
		return nil, fmt.Errorf("failed to acquire jobs: %w", err)
	}

	if err := c.refreshOrRecreateSession(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to refresh message session: %w", err)
	}

	return c.acquireJobs(ctx, c.Session(), requestIDs)
}

func (c *MessageSessionClient) acquireJobs(ctx context.Context, session RunnerScaleSetSession, requestIDs []int64) ([]int64, error) {
	body, err := json.Marshal(requestIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request ids: %w", err)
	}

	path := fmt.Sprintf("/%s/%d/acquirejobs", scaleSetEndpoint, c.scaleSetID)

	req, err := c.innerClient.newActionsServiceRequest(ctx, http.MethodPost, path, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create acquire jobs request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", session.MessageQueueAccessToken))

	resp, err := c.commonClient.do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to issue acquire jobs request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, newRequestResponseError(req, resp, MessageQueueTokenExpiredError)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("unexpected status code %s", resp.Status))
	}

	var result acquireJobsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("failed to decode acquire jobs response: %w", err))
	}

	return result.Value, nil
}

func (c *MessageSessionClient) doSessionRequest(ctx context.Context, method, path string, requestData io.Reader, expectedResponseStatusCode int, responseUnmarshalTarget any) error {
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
		// A 404 on a session request means the service no longer knows the
		// session (or the scale set behind it). Surface the typed sentinel so
		// callers can distinguish "session evicted, safe to re-create" from
		// genuine failures.
		if resp.StatusCode == http.StatusNotFound {
			return newRequestResponseError(req, resp, NotFoundError)
		}
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
