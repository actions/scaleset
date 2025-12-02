package scaleset

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActionsError(t *testing.T) {
	t.Run("contains the status code, activity ID, and error", func(t *testing.T) {
		err := &ActionsError{
			ActivityID: "activity-id",
			StatusCode: 404,
			Err:        errors.New("example error description"),
		}

		s := err.Error()
		assert.Contains(t, s, "StatusCode 404")
		assert.Contains(t, s, "ActivityId \"activity-id\"")
		assert.Contains(t, s, "example error description")
	})

	t.Run("unwraps the error", func(t *testing.T) {
		err := &ActionsError{
			ActivityID: "activity-id",
			StatusCode: 404,
			Err: &actionsExceptionError{
				ExceptionName: "exception-name",
				Message:       "example error message",
			},
		}

		assert.Equal(t, err.Unwrap(), err.Err)
	})

	t.Run("is exception is ok", func(t *testing.T) {
		err := &ActionsError{
			ActivityID: "activity-id",
			StatusCode: 404,
			Err: &actionsExceptionError{
				ExceptionName: "exception-name",
				Message:       "example error message",
			},
		}

		var exception *actionsExceptionError
		assert.True(t, errors.As(err, &exception))

		assert.True(t, err.isException("exception-name"))
	})

	t.Run("is exception is not ok", func(t *testing.T) {
		tt := map[string]*ActionsError{
			"not an exception": {
				ActivityID: "activity-id",
				StatusCode: 404,
				Err:        errors.New("example error description"),
			},
			"not target exception": {
				ActivityID: "activity-id",
				StatusCode: 404,
				Err: &actionsExceptionError{
					ExceptionName: "exception-name",
					Message:       "example error message",
				},
			},
		}

		targetException := "target-exception"
		for name, err := range tt {
			t.Run(name, func(t *testing.T) {
				assert.False(t, err.isException(targetException))
			})
		}
	})

	t.Run("is agent exists exception", func(t *testing.T) {
		err := &ActionsError{
			ActivityID: "activity-id",
			StatusCode: 404,
			Err: &actionsExceptionError{
				ExceptionName: "AgentExistsException",
				Message:       "example error message",
			},
		}

		assert.True(t, err.IsAgentExists())
	})

	t.Run("is agent not found exception", func(t *testing.T) {
		err := &ActionsError{
			ActivityID: "activity-id",
			StatusCode: 404,
			Err: &actionsExceptionError{
				ExceptionName: "AgentNotFoundException",
				Message:       "example error message",
			},
		}

		assert.True(t, err.IsAgentNotFound())
	})

	t.Run("is job still running exception", func(t *testing.T) {
		err := &ActionsError{
			ActivityID: "activity-id",
			StatusCode: 404,
			Err: &actionsExceptionError{
				ExceptionName: "JobStillRunningException",
				Message:       "example error message",
			},
		}

		assert.True(t, err.IsJobStillRunning())
	})

	t.Run("is message queue token expired exception", func(t *testing.T) {
		err := &ActionsError{
			ActivityID: "activity-id",
			StatusCode: 404,
			Err: &messageQueueTokenExpiredError{
				message: "example error message",
			},
		}

		assert.True(t, err.IsMessageQueueTokenExpired())
	})
}

func TestActionsExceptionError(t *testing.T) {
	t.Run("contains the exception name and message", func(t *testing.T) {
		err := &actionsExceptionError{
			ExceptionName: "exception-name",
			Message:       "example error message",
		}

		s := err.Error()
		assert.Contains(t, s, "exception-name")
		assert.Contains(t, s, "example error message")
	})
}

func TestGitHubAPIError(t *testing.T) {
	t.Run("contains the status code, request ID, and error", func(t *testing.T) {
		err := &GitHubAPIError{
			StatusCode: 404,
			RequestID:  "request-id",
			Err:        errors.New("example error description"),
		}

		s := err.Error()
		assert.Contains(t, s, "StatusCode 404")
		assert.Contains(t, s, "RequestID \"request-id\"")
		assert.Contains(t, s, "example error description")
	})

	t.Run("unwraps the error", func(t *testing.T) {
		err := &GitHubAPIError{
			StatusCode: 404,
			RequestID:  "request-id",
			Err:        errors.New("example error description"),
		}

		assert.Equal(t, err.Unwrap(), err.Err)
	})
}

func TestParseActionsErrorFromResponse(t *testing.T) {
	t.Run("empty content length", func(t *testing.T) {
		response := &http.Response{
			ContentLength: 0,
			Header:        http.Header{},
			StatusCode:    404,
		}
		response.Header.Add(headerActionsActivityID, "activity-id")

		err := ParseActionsErrorFromResponse(response)
		require.Error(t, err)
		assert.Equal(t, "activity-id", err.(*ActionsError).ActivityID)
		assert.Equal(t, 404, err.(*ActionsError).StatusCode)
		assert.Equal(t, "unknown exception", err.(*ActionsError).Err.Error())
	})

	t.Run("contains text plain error", func(t *testing.T) {
		errorMessage := "example error message"
		response := &http.Response{
			ContentLength: int64(len(errorMessage)),
			StatusCode:    404,
			Header:        http.Header{},
			Body:          io.NopCloser(strings.NewReader(errorMessage)),
		}
		response.Header.Add(headerActionsActivityID, "activity-id")
		response.Header.Add("Content-Type", "text/plain")

		err := ParseActionsErrorFromResponse(response)
		require.Error(t, err)
		var actionsError *ActionsError
		assert.ErrorAs(t, err, &actionsError)
		assert.Equal(t, "activity-id", actionsError.ActivityID)
		assert.Equal(t, 404, actionsError.StatusCode)
		assert.Equal(t, errorMessage, actionsError.Err.Error())
	})

	t.Run("contains json error", func(t *testing.T) {
		errorMessage := `{"typeName":"exception-name","message":"example error message"}`
		response := &http.Response{
			ContentLength: int64(len(errorMessage)),
			StatusCode:    404,
			Header:        http.Header{},
			Body:          io.NopCloser(strings.NewReader(errorMessage)),
		}
		response.Header.Add(headerActionsActivityID, "activity-id")
		response.Header.Add("Content-Type", "application/json")

		err := ParseActionsErrorFromResponse(response)
		require.Error(t, err)
		var actionsError *ActionsError
		assert.ErrorAs(t, err, &actionsError)
		assert.Equal(t, "activity-id", actionsError.ActivityID)
		assert.Equal(t, 404, actionsError.StatusCode)

		inner, ok := actionsError.Err.(*actionsExceptionError)
		require.True(t, ok)
		assert.Equal(t, "exception-name", inner.ExceptionName)
		assert.Equal(t, "example error message", inner.Message)
	})

	t.Run("wrapped exception error", func(t *testing.T) {
		errorMessage := `{"typeName":"exception-name","message":"example error message"}`
		response := &http.Response{
			ContentLength: int64(len(errorMessage)),
			StatusCode:    404,
			Header:        http.Header{},
			Body:          io.NopCloser(strings.NewReader(errorMessage)),
		}
		response.Header.Add(headerActionsActivityID, "activity-id")
		response.Header.Add("Content-Type", "application/json")

		err := ParseActionsErrorFromResponse(response)
		require.Error(t, err)

		var actionsExceptionError *actionsExceptionError
		assert.ErrorAs(t, err, &actionsExceptionError)

		assert.Equal(t, "exception-name", actionsExceptionError.ExceptionName)
		assert.Equal(t, "example error message", actionsExceptionError.Message)
	})
}
