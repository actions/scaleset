package scaleset_test

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/actions/scaleset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActionsError(t *testing.T) {
	t.Run("contains the status code, activity ID, and error", func(t *testing.T) {
		err := &scaleset.ActionsError{
			ActivityID: "activity-id",
			StatusCode: 404,
			Err:        errors.New("example error description"),
		}

		s := err.Error()
		assert.Contains(t, s, "StatusCode 404")
		assert.Contains(t, s, "AcivityId \"activity-id\"")
		assert.Contains(t, s, "example error description")
	})

	t.Run("unwraps the error", func(t *testing.T) {
		err := &scaleset.ActionsError{
			ActivityID: "activity-id",
			StatusCode: 404,
			Err: &scaleset.ActionsExceptionError{
				ExceptionName: "exception-name",
				Message:       "example error message",
			},
		}

		assert.Equal(t, err.Unwrap(), err.Err)
	})

	t.Run("is exception is ok", func(t *testing.T) {
		err := &scaleset.ActionsError{
			ActivityID: "activity-id",
			StatusCode: 404,
			Err: &scaleset.ActionsExceptionError{
				ExceptionName: "exception-name",
				Message:       "example error message",
			},
		}

		var exception *scaleset.ActionsExceptionError
		assert.True(t, errors.As(err, &exception))

		assert.True(t, err.IsException("exception-name"))
	})

	t.Run("is exception is not ok", func(t *testing.T) {
		tt := map[string]*scaleset.ActionsError{
			"not an exception": {
				ActivityID: "activity-id",
				StatusCode: 404,
				Err:        errors.New("example error description"),
			},
			"not target exception": {
				ActivityID: "activity-id",
				StatusCode: 404,
				Err: &scaleset.ActionsExceptionError{
					ExceptionName: "exception-name",
					Message:       "example error message",
				},
			},
		}

		targetException := "target-exception"
		for name, err := range tt {
			t.Run(name, func(t *testing.T) {
				assert.False(t, err.IsException(targetException))
			})
		}
	})
}

func TestActionsExceptionError(t *testing.T) {
	t.Run("contains the exception name and message", func(t *testing.T) {
		err := &scaleset.ActionsExceptionError{
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
		err := &scaleset.GitHubAPIError{
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
		err := &scaleset.GitHubAPIError{
			StatusCode: 404,
			RequestID:  "request-id",
			Err:        errors.New("example error description"),
		}

		assert.Equal(t, err.Unwrap(), err.Err)
	})
}

func ParseActionsErrorFromResponse(t *testing.T) {
	t.Run("empty content length", func(t *testing.T) {
		response := &http.Response{
			ContentLength: 0,
			Header: http.Header{
				scaleset.HeaderActionsActivityID: []string{"activity-id"},
			},
			StatusCode: 404,
		}

		err := scaleset.ParseActionsErrorFromResponse(response)
		require.Error(t, err)
		assert.Equal(t, err.(*scaleset.ActionsError).ActivityID, "activity-id")
		assert.Equal(t, err.(*scaleset.ActionsError).StatusCode, 404)
		assert.Equal(t, err.(*scaleset.ActionsError).Err.Error(), "unknown exception")
	})

	t.Run("contains text plain error", func(t *testing.T) {
		errorMessage := "example error message"
		response := &http.Response{
			ContentLength: int64(len(errorMessage)),
			Header: http.Header{
				scaleset.HeaderActionsActivityID: []string{"activity-id"},
				"Content-Type":                   []string{"text/plain"},
			},
			StatusCode: 404,
			Body:       io.NopCloser(strings.NewReader(errorMessage)),
		}

		err := scaleset.ParseActionsErrorFromResponse(response)
		require.Error(t, err)
		var actionsError *scaleset.ActionsError
		assert.ErrorAs(t, err, &actionsError)
		assert.Equal(t, actionsError.ActivityID, "activity-id")
		assert.Equal(t, actionsError.StatusCode, 404)
		assert.Equal(t, actionsError.Err.Error(), errorMessage)
	})

	t.Run("contains json error", func(t *testing.T) {
		errorMessage := `{"typeName":"exception-name","message":"example error message"}`
		response := &http.Response{
			ContentLength: int64(len(errorMessage)),
			Header: http.Header{
				scaleset.HeaderActionsActivityID: []string{"activity-id"},
				"Content-Type":                   []string{"application/json"},
			},
			StatusCode: 404,
			Body:       io.NopCloser(strings.NewReader(errorMessage)),
		}

		err := scaleset.ParseActionsErrorFromResponse(response)
		require.Error(t, err)
		var actionsError *scaleset.ActionsError
		assert.ErrorAs(t, err, &actionsError)
		assert.Equal(t, actionsError.ActivityID, "activity-id")
		assert.Equal(t, actionsError.StatusCode, 404)

		inner, ok := actionsError.Err.(*scaleset.ActionsExceptionError)
		require.True(t, ok)
		assert.Equal(t, inner.ExceptionName, "exception-name")
		assert.Equal(t, inner.Message, "example error message")
	})

	t.Run("wrapped exception error", func(t *testing.T) {
		errorMessage := `{"typeName":"exception-name","message":"example error message"}`
		response := &http.Response{
			ContentLength: int64(len(errorMessage)),
			Header: http.Header{
				scaleset.HeaderActionsActivityID: []string{"activity-id"},
				"Content-Type":                   []string{"application/json"},
			},
			StatusCode: 404,
			Body:       io.NopCloser(strings.NewReader(errorMessage)),
		}

		err := scaleset.ParseActionsErrorFromResponse(response)
		require.Error(t, err)

		var actionsExceptionError *scaleset.ActionsExceptionError
		assert.ErrorAs(t, err, &actionsExceptionError)

		assert.Equal(t, actionsExceptionError.ExceptionName, "exception-name")
		assert.Equal(t, actionsExceptionError.Message, "example error message")
	})
}
