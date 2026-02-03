package scaleset

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type readErrCloser struct{}

func (readErrCloser) Read([]byte) (int, error) { return 0, fmt.Errorf("read failed") }
func (readErrCloser) Close() error             { return nil }

func TestActionsExceptionError(t *testing.T) {
	t.Run("contains the exception name and message", func(t *testing.T) {
		err := actionsExceptionError{
			ExceptionName: "exception-name",
			Message:       "example error message",
		}

		s := err.Error()
		assert.Contains(t, s, "exception-name")
		assert.Contains(t, s, "example error message")
	})
}

func TestNewRequestResponseError(t *testing.T) {
	req := func(t *testing.T) *http.Request {
		t.Helper()
		u, err := url.Parse("https://example.com/org/repo")
		require.NoError(t, err)
		return &http.Request{Method: http.MethodGet, URL: u}
	}

	t.Run("resp is nil", func(t *testing.T) {
		base := errors.New("base")
		err := newRequestResponseError(req(t), nil, base)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "request GET https://example.com/org/repo failed")
		assert.True(t, errors.Is(err, base))
	})

	t.Run("resp body is nil", func(t *testing.T) {
		base := errors.New("base")
		resp := &http.Response{
			Status:        "500 Internal Server Error",
			StatusCode:    http.StatusInternalServerError,
			ContentLength: 123,
			Header:        make(http.Header),
			Body:          nil,
		}

		err := newRequestResponseError(req(t), resp, base)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown error")
		assert.True(t, errors.Is(err, base))
	})

	t.Run("empty body returns unknown error", func(t *testing.T) {
		base := errors.New("base")
		resp := &http.Response{
			Status:        "404 Not Found",
			StatusCode:    http.StatusNotFound,
			ContentLength: 0,
			Header:        make(http.Header),
		}
		resp.Header.Set(headerActionsActivityID, "activity-id")
		resp.Header.Set(headerGitHubRequestID, "request-id")

		err := newRequestResponseError(req(t), resp, base)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "status=\"404 Not Found\"")
		assert.Contains(t, err.Error(), "activity_id=\"activity-id\"")
		assert.Contains(t, err.Error(), "github_request_id=\"request-id\"")
		assert.Contains(t, err.Error(), "unknown error")
		assert.True(t, errors.Is(err, base))
	})

	t.Run("read body failure includes read error", func(t *testing.T) {
		base := errors.New("base")
		resp := &http.Response{
			Status:        "400 Bad Request",
			StatusCode:    http.StatusBadRequest,
			ContentLength: 1,
			Header:        make(http.Header),
			Body:          io.NopCloser(readErrCloser{}),
		}

		err := newRequestResponseError(req(t), resp, base)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read error response body")
		assert.True(t, errors.Is(err, base))
		assert.Contains(t, err.Error(), "read failed")
	})

	t.Run("unknown content length and empty body returns unknown error", func(t *testing.T) {
		base := errors.New("base")
		resp := &http.Response{
			Status:        "400 Bad Request",
			StatusCode:    http.StatusBadRequest,
			ContentLength: -1,
			Header:        make(http.Header),
			Body:          io.NopCloser(strings.NewReader("")),
		}

		err := newRequestResponseError(req(t), resp, base)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown error")
		assert.True(t, errors.Is(err, base))
	})

	t.Run("text/plain body is included", func(t *testing.T) {
		base := errors.New("base")
		body := "example plain text error"
		resp := &http.Response{
			Status:        "400 Bad Request",
			StatusCode:    http.StatusBadRequest,
			ContentLength: int64(len(body)),
			Header:        make(http.Header),
			Body:          io.NopCloser(strings.NewReader(body)),
		}
		resp.Header.Set("Content-Type", "text/plain")
		resp.Header.Set(headerActionsActivityID, "activity-id")

		err := newRequestResponseError(req(t), resp, base)
		require.Error(t, err)
		assert.Contains(t, err.Error(), body)
		assert.True(t, errors.Is(err, base))
	})

	t.Run("scalesetError in error chain uses raw body (no JSON parsing)", func(t *testing.T) {
		wrapped := fmt.Errorf("wrapped: %w", RunnerNotFoundError)
		body := `{"typeName":"AgentExistsException","message":"should not be parsed"}`
		resp := &http.Response{
			Status:        "404 Not Found",
			StatusCode:    http.StatusNotFound,
			ContentLength: int64(len(body)),
			Header:        make(http.Header),
			Body:          io.NopCloser(strings.NewReader(body)),
		}
		resp.Header.Set("Content-Type", "application/json")

		err := newRequestResponseError(req(t), resp, wrapped)
		require.Error(t, err)
		assert.True(t, errors.Is(err, RunnerNotFoundError))
		assert.Contains(t, err.Error(), body)
	})

	t.Run("known actions exception maps to sentinel error", func(t *testing.T) {
		base := errors.New("base")
		jsonBody := `{"typeName":"AgentExistsException","message":"runner already exists"}`
		resp := &http.Response{
			Status:        "409 Conflict",
			StatusCode:    http.StatusConflict,
			ContentLength: int64(len(jsonBody)),
			Header:        make(http.Header),
			Body:          io.NopCloser(strings.NewReader(jsonBody)),
		}
		resp.Header.Set("Content-Type", "application/json")

		err := newRequestResponseError(req(t), resp, base)
		require.Error(t, err)
		assert.True(t, errors.Is(err, RunnerExistsError))
		assert.False(t, errors.Is(err, base), "base error should not be wrapped for mapped exceptions")
		assert.Contains(t, err.Error(), "runner already exists")
	})

	t.Run("agent not found exception maps to sentinel error", func(t *testing.T) {
		base := errors.New("base")
		jsonBody := `{"typeName":"AgentNotFoundException","message":"missing"}`
		resp := &http.Response{
			Status:        "404 Not Found",
			StatusCode:    http.StatusNotFound,
			ContentLength: int64(len(jsonBody)),
			Header:        make(http.Header),
			Body:          io.NopCloser(strings.NewReader(jsonBody)),
		}
		resp.Header.Set("Content-Type", "application/json")

		err := newRequestResponseError(req(t), resp, base)
		require.Error(t, err)
		assert.True(t, errors.Is(err, RunnerNotFoundError))
		assert.False(t, errors.Is(err, base))
		assert.Contains(t, err.Error(), "missing")
	})

	t.Run("job still running exception maps to sentinel error", func(t *testing.T) {
		base := errors.New("base")
		jsonBody := `{"typeName":"JobStillRunningException","message":"still running"}`
		resp := &http.Response{
			Status:        "409 Conflict",
			StatusCode:    http.StatusConflict,
			ContentLength: int64(len(jsonBody)),
			Header:        make(http.Header),
			Body:          io.NopCloser(strings.NewReader(jsonBody)),
		}
		resp.Header.Set("Content-Type", "application/json")

		err := newRequestResponseError(req(t), resp, base)
		require.Error(t, err)
		assert.True(t, errors.Is(err, JobStillRunningError))
		assert.False(t, errors.Is(err, base))
		assert.Contains(t, err.Error(), "still running")
	})

	t.Run("invalid json returns unmarshal error and includes body", func(t *testing.T) {
		base := errors.New("base")
		bad := "not-json"
		resp := &http.Response{
			Status:        "400 Bad Request",
			StatusCode:    http.StatusBadRequest,
			ContentLength: int64(len(bad)),
			Header:        make(http.Header),
			Body:          io.NopCloser(strings.NewReader(bad)),
		}
		resp.Header.Set("Content-Type", "application/json")

		err := newRequestResponseError(req(t), resp, base)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unmarshal error response body")
		assert.Contains(t, err.Error(), "not-json")
		assert.False(t, errors.Is(err, base), "base error is not wrapped on JSON unmarshal failures")
	})

	t.Run("unknown json error wraps exception", func(t *testing.T) {
		base := errors.New("base")
		jsonBody := `{"typeName":"SomeException","message":"example error message"}`
		resp := &http.Response{
			Status:        "500 Internal Server Error",
			StatusCode:    http.StatusInternalServerError,
			ContentLength: int64(len(jsonBody)),
			Header:        make(http.Header),
			Body:          io.NopCloser(strings.NewReader(jsonBody)),
		}
		resp.Header.Set("Content-Type", "application/json")

		err := newRequestResponseError(req(t), resp, base)
		require.Error(t, err)
		assert.True(t, errors.Is(err, base))

		var ex actionsExceptionError
		assert.True(t, errors.As(err, &ex))
		assert.Equal(t, "SomeException", ex.ExceptionName)
		assert.Equal(t, "example error message", ex.Message)
	})
}
