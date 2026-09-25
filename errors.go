package scaleset

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// RequestResponseError describes a failed HTTP request or an unusable response.
// Use errors.As to inspect it and errors.Is to check its underlying causes,
// including the status and domain errors defined in this package.
type RequestResponseError struct {
	// Response is a snapshot of the failed attempt's response, or nil if none
	// is available (including cancellation between attempts).
	// Its Body is an independent, in-memory reader containing the original bytes
	// returned by the HTTP client (only the bytes received on a read failure).
	// The network body has already been closed. Headers, trailers, and other
	// response metadata are retained; Request may contain credentials.
	Response *http.Response

	// Err includes the original cause and any recognized HTTP/API errors.
	Err error
}

func (e *RequestResponseError) Error() string {
	if e.Err == nil {
		return "HTTP request failed"
	}
	return e.Err.Error()
}

func (e *RequestResponseError) Unwrap() error {
	return e.Err
}

var errMissingResponse = errors.New("HTTP client returned a nil response without an error")

type scalesetError string

func (e scalesetError) Error() string {
	return string(e)
}

var (
	RunnerNotFoundError           = scalesetError("runner not found")
	RunnerExistsError             = scalesetError("runner exists")
	JobStillRunningError          = scalesetError("job still running")
	MessageQueueTokenExpiredError = scalesetError("message queue token expired")
	// Top-level errors carrying the HTTP status code meanings.
	BadRequestError   = scalesetError("bad request")
	NotFoundError     = scalesetError("not found")
	UnauthorizedError = scalesetError("unauthorized")
	ConflictError     = scalesetError("conflict")
)

type actionsExceptionError struct {
	ExceptionName string `json:"typeName,omitempty"`
	Message       string `json:"message,omitempty"`
}

func (e actionsExceptionError) Error() string {
	return fmt.Sprintf("%s: %s", e.ExceptionName, e.Message)
}

// newRequestResponseError retains the response and cause, adding known API error
// classifications without dumping raw response bodies or request credentials.
func newRequestResponseError(req *http.Request, resp *http.Response, err error) error {
	body, bodyErr := bufferResponseBody(resp)
	if bodyErr != nil {
		err = errors.Join(err, fmt.Errorf("failed to read error response body: %w", bodyErr))
	}

	var snapshot *http.Response
	if resp != nil {
		copy := *resp
		copy.Header = resp.Header.Clone()
		copy.Trailer = resp.Trailer.Clone()
		copy.Body = io.NopCloser(bytes.NewReader(body))
		if copy.Request == nil {
			copy.Request = req
		}
		snapshot = &copy
		if copy.Request != nil {
			req = copy.Request
		}
	}

	var sb strings.Builder
	sb.WriteString("request")
	if req != nil {
		fmt.Fprintf(&sb, " %s", req.Method)
		if req.URL != nil {
			u := *req.URL
			u.User = nil
			u.RawQuery, u.Fragment, u.RawFragment = "", "", ""
			u.ForceQuery = false
			fmt.Fprintf(&sb, " %s", u.String())
		}
	}
	sb.WriteString(" failed")

	if resp != nil {
		sb.WriteRune('(')
		fmt.Fprintf(&sb, "status=%q", resp.Status)
		if resp.Header.Get(headerActionsActivityID) != "" {
			fmt.Fprintf(&sb, ", activity_id=%q", resp.Header.Get(headerActionsActivityID))
		}
		if resp.Header.Get(headerGitHubRequestID) != "" {
			fmt.Fprintf(&sb, ", github_request_id=%q", resp.Header.Get(headerGitHubRequestID))
		}
		sb.WriteRune(')')
		err = responseErrorCause(resp, body, err)
	}

	return &RequestResponseError{
		Response: snapshot,
		Err:      wrapResponseErrorType(resp, fmt.Errorf("%s: %w", sb.String(), err)),
	}
}

func responseErrorCause(resp *http.Response, body []byte, err error) error {
	// A successful response may contain tokens or JIT configuration, not an
	// API error. Do not reinterpret it when decoding or validation fails.
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return err
	}
	if len(body) == 0 {
		return fmt.Errorf("%w: unknown error", err)
	}

	var scalesetErr scalesetError
	if errors.As(err, &scalesetErr) {
		return err
	}

	var exception actionsExceptionError
	if parseErr := json.Unmarshal(trimByteOrderMark(body), &exception); parseErr != nil {
		if strings.Contains(resp.Header.Get("Content-Type"), "text/plain") {
			return err
		}
		return fmt.Errorf("%w: failed to unmarshal error response body: %w", err, parseErr)
	}

	switch {
	case strings.Contains(exception.ExceptionName, "AgentExistsException"):
		return fmt.Errorf("%w: %w: %w", err, RunnerExistsError, exception)
	case strings.Contains(exception.ExceptionName, "AgentNotFoundException"):
		return fmt.Errorf("%w: %w: %w", err, RunnerNotFoundError, exception)
	case strings.Contains(exception.ExceptionName, "JobStillRunningException"):
		return fmt.Errorf("%w: %w: %w", err, JobStillRunningError, exception)
	case exception.ExceptionName != "" || exception.Message != "":
		return fmt.Errorf("%w: %w", err, exception)
	default:
		return err
	}
}

func wrapResponseErrorType(resp *http.Response, err error) error {
	if resp == nil {
		return err
	}
	switch resp.StatusCode {
	case http.StatusBadRequest:
		return fmt.Errorf("%w: %w", BadRequestError, err)
	case http.StatusUnauthorized:
		return fmt.Errorf("%w: %w", UnauthorizedError, err)
	case http.StatusNotFound:
		return fmt.Errorf("%w: %w", NotFoundError, err)
	case http.StatusConflict:
		return fmt.Errorf("%w: %w", ConflictError, err)
	default:
		return err
	}
}
