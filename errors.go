package scaleset

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type scalesetError string

func (e scalesetError) Error() string {
	return string(e)
}

var (
	RunnerNotFoundError           = scalesetError("runner not found")
	RunnerExistsError             = scalesetError("runner exists")
	JobStillRunningError          = scalesetError("job still running")
	MessageQueueTokenExpiredError = scalesetError("message queue token expired")
)

type actionsExceptionError struct {
	ExceptionName string `json:"typeName,omitempty"`
	Message       string `json:"message,omitempty"`
}

func (e actionsExceptionError) Error() string {
	return fmt.Sprintf("%s: %s", e.ExceptionName, e.Message)
}

// newRequestResponseError creates a detailed error message based on the HTTP request and response,
// including parsing the response body for known error formats.
//
// The sendRequest already parses errors using this method, so use this error if the client doesn't
// return an error, but the error is happening on the application logic level.
//
// Prefer creating errors using this function instead of manually constructing error messages since it automatically
// includes useful metadata like activity IDs and request IDs, and handles well-known error cases.
func newRequestResponseError(req *http.Request, resp *http.Response, err error) error {
	var sb strings.Builder
	fmt.Fprintf(&sb, "request %s %s failed", req.Method, req.URL.String())

	if resp == nil {
		return fmt.Errorf("%s: %w", sb.String(), err)
	}

	sb.WriteRune('(')
	fmt.Fprintf(&sb, "status=%q", resp.Status)
	if resp.Header.Get(headerActionsActivityID) != "" {
		fmt.Fprintf(&sb, ", activity_id=%q", resp.Header.Get(headerActionsActivityID))
	}

	if resp.Header.Get(headerGitHubRequestID) != "" {
		fmt.Fprintf(&sb, ", github_request_id=%q", resp.Header.Get(headerGitHubRequestID))
	}
	sb.WriteRune(')')

	if resp.Body == nil || resp.ContentLength == 0 {
		return fmt.Errorf("%s: %w: unknown error", sb.String(), err)
	}

	body, bodyErr := io.ReadAll(resp.Body)
	if bodyErr != nil {
		return fmt.Errorf("%s: %w: failed to read error response body: %w", sb.String(), err, bodyErr)
	}
	if len(body) == 0 {
		return fmt.Errorf("%s: %w: unknown error", sb.String(), err)
	}

	var scalesetErr scalesetError
	if errors.As(err, &scalesetErr) {
		return fmt.Errorf("%s: %w: %s", sb.String(), err, string(body))
	}

	contentType := resp.Header.Get("Content-Type")
	if len(contentType) > 0 && strings.Contains(contentType, "text/plain") {
		return fmt.Errorf("%s: %w: %s", sb.String(), err, string(body))
	}

	var exception actionsExceptionError
	if err := json.Unmarshal(body, &exception); err != nil {
		return fmt.Errorf("%s: %w: failed to unmarshal error response body: %q", sb.String(), err, string(body))
	}

	switch {
	case strings.Contains(exception.ExceptionName, "AgentExistsException"):
		return fmt.Errorf("%s: %w: %s", sb.String(), RunnerExistsError, exception.Message)
	case strings.Contains(exception.ExceptionName, "AgentNotFoundException"):
		return fmt.Errorf("%s: %w: %s", sb.String(), RunnerNotFoundError, exception.Message)
	case strings.Contains(exception.ExceptionName, "JobStillRunningException"):
		return fmt.Errorf("%s: %w: %s", sb.String(), JobStillRunningError, exception.Message)
	default:
		return fmt.Errorf("%s: %w: %w", sb.String(), err, exception)
	}
}
