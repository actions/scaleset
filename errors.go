package scaleset

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Header names for request IDs
const (
	headerActionsActivityID = "ActivityId"
	headerGitHubRequestID   = "X-GitHub-Request-Id"
)

type GitHubAPIError struct {
	StatusCode int
	RequestID  string
	Err        error
}

func (e *GitHubAPIError) Error() string {
	return fmt.Sprintf("github api error: StatusCode %d, RequestID %q: %v", e.StatusCode, e.RequestID, e.Err)
}

func (e *GitHubAPIError) Unwrap() error {
	return e.Err
}

type ActionsError struct {
	ActivityID string
	StatusCode int
	Err        error
}

func (e *ActionsError) Error() string {
	return fmt.Sprintf("actions error: StatusCode %d, ActivityId %q: %v", e.StatusCode, e.ActivityID, e.Err)
}

func (e *ActionsError) Unwrap() error {
	return e.Err
}

func (e *ActionsError) IsAgentNotFound() bool {
	return e.isException("AgentNotFoundException")
}

func (e *ActionsError) IsJobStillRunning() bool {
	return e.isException("JobStillRunningException")
}

func (e *ActionsError) IsMessageQueueTokenExpired() bool {
	if e == nil {
		return false
	}
	var err *messageQueueTokenExpiredError
	return errors.As(e.Err, &err)
}

func (e *ActionsError) IsAgentExists() bool {
	return e.isException("AgentExistsException")
}

func (e *ActionsError) isException(target string) bool {
	if e == nil {
		return false
	}
	if ex, ok := e.Err.(*actionsExceptionError); ok {
		return strings.Contains(ex.ExceptionName, target)
	}
	return false
}

type actionsExceptionError struct {
	ExceptionName string `json:"typeName,omitempty"`
	Message       string `json:"message,omitempty"`
}

func (e *actionsExceptionError) Error() string {
	return fmt.Sprintf("%s: %s", e.ExceptionName, e.Message)
}

func ParseActionsErrorFromResponse(response *http.Response) error {
	if response.ContentLength == 0 {
		return &ActionsError{
			ActivityID: response.Header.Get(headerActionsActivityID),
			StatusCode: response.StatusCode,
			Err:        errors.New("unknown exception"),
		}
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return &ActionsError{
			ActivityID: response.Header.Get(headerActionsActivityID),
			StatusCode: response.StatusCode,
			Err:        err,
		}
	}

	body = trimByteOrderMark(body)
	contentType := response.Header.Get("Content-Type")
	if len(contentType) > 0 && strings.Contains(contentType, "text/plain") {
		message := string(body)
		return &ActionsError{
			ActivityID: response.Header.Get(headerActionsActivityID),
			StatusCode: response.StatusCode,
			Err:        errors.New(message),
		}
	}

	var exception actionsExceptionError
	if err := json.Unmarshal(body, &exception); err != nil {
		return &ActionsError{
			ActivityID: response.Header.Get(headerActionsActivityID),
			StatusCode: response.StatusCode,
			Err:        err,
		}
	}

	return &ActionsError{
		ActivityID: response.Header.Get(headerActionsActivityID),
		StatusCode: response.StatusCode,
		Err:        &exception,
	}
}

type messageQueueTokenExpiredError struct {
	message string
}

func (e *messageQueueTokenExpiredError) Error() string {
	return fmt.Sprintf("message queue token expired: %s", e.message)
}

// NewMessageQueueTokenExpiredError creates a new MessageQueueTokenExpiredError.
//
// This function is mostly used by tests.
func NewMessageQueueTokenExpiredError(message string) error {
	return &messageQueueTokenExpiredError{
		message: message,
	}
}
