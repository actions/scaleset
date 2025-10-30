package scaleset_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/actions/scaleset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetMessage(t *testing.T) {
	ctx := context.Background()
	auth := &scaleset.ActionsAuth{
		Token: "token",
	}

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjI1MTYyMzkwMjJ9.tlrHslTmDkoqnc4Kk9ISoKoUNDfHo-kjlH-ByISBqzE"
	runnerScaleSetMessage := &scaleset.RunnerScaleSetMessage{
		MessageId:   1,
		MessageType: "rssType",
	}

	t.Run("Get Runner Scale Set Message", func(t *testing.T) {
		want := runnerScaleSetMessage
		response := []byte(`{"messageId":1,"messageType":"rssType"}`)
		s := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write(response)
		}))

		client, err := scaleset.NewClient(s.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		got, err := client.GetMessage(ctx, s.URL, token, 0, 10)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("GetMessage sets the last message id if not 0", func(t *testing.T) {
		want := runnerScaleSetMessage
		response := []byte(`{"messageId":1,"messageType":"rssType"}`)
		s := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			assert.Equal(t, "1", q.Get("lastMessageId"))
			w.Write(response)
		}))

		client, err := scaleset.NewClient(s.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		got, err := client.GetMessage(ctx, s.URL, token, 1, 10)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("Default retries on server error", func(t *testing.T) {
		retryMax := 1

		actualRetry := 0
		expectedRetry := retryMax + 1

		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			actualRetry++
		}))

		client, err := scaleset.NewClient(
			server.configURLForOrg("my-org"),
			auth,
			scaleset.WithRetryMax(retryMax),
			scaleset.WithRetryWaitMax(1*time.Millisecond),
		)
		require.NoError(t, err)

		_, err = client.GetMessage(ctx, server.URL, token, 0, 10)
		assert.NotNil(t, err)
		assert.Equalf(t, actualRetry, expectedRetry, "A retry was expected after the first request but got: %v", actualRetry)
	})

	t.Run("Message token expired", func(t *testing.T) {
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))

		client, err := scaleset.NewClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		_, err = client.GetMessage(ctx, server.URL, token, 0, 10)
		require.NotNil(t, err)

		var expectedErr *scaleset.MessageQueueTokenExpiredError
		require.True(t, errors.As(err, &expectedErr))
	})

	t.Run("Status code not found", func(t *testing.T) {
		want := scaleset.ActionsError{
			Err:        errors.New("unknown exception"),
			StatusCode: 404,
		}
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))

		client, err := scaleset.NewClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		_, err = client.GetMessage(ctx, server.URL, token, 0, 10)
		require.NotNil(t, err)
		assert.Equal(t, want.Error(), err.Error())
	})

	t.Run("Error when Content-Type is text/plain", func(t *testing.T) {
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "text/plain")
		}))

		client, err := scaleset.NewClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		_, err = client.GetMessage(ctx, server.URL, token, 0, 10)
		assert.NotNil(t, err)
	})

	t.Run("Capacity error handling", func(t *testing.T) {
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hc := r.Header.Get(scaleset.HeaderScaleSetMaxCapacity)
			c, err := strconv.Atoi(hc)
			require.NoError(t, err)
			assert.GreaterOrEqual(t, c, 0)

			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "text/plain")
		}))

		client, err := scaleset.NewClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		_, err = client.GetMessage(ctx, server.URL, token, 0, -1)
		require.Error(t, err)
		// Ensure we don't send requests with negative capacity
		assert.False(t, errors.Is(err, &scaleset.ActionsError{}))

		_, err = client.GetMessage(ctx, server.URL, token, 0, 0)
		assert.Error(t, err)
		var expectedErr *scaleset.ActionsError
		assert.ErrorAs(t, err, &expectedErr)
		assert.Equal(t, http.StatusBadRequest, expectedErr.StatusCode)
	})
}

func TestDeleteMessage(t *testing.T) {
	ctx := context.Background()
	auth := &scaleset.ActionsAuth{
		Token: "token",
	}

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjI1MTYyMzkwMjJ9.tlrHslTmDkoqnc4Kk9ISoKoUNDfHo-kjlH-ByISBqzE"
	runnerScaleSetMessage := &scaleset.RunnerScaleSetMessage{
		MessageId:   1,
		MessageType: "rssType",
	}

	t.Run("Delete existing message", func(t *testing.T) {
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))

		client, err := scaleset.NewClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		err = client.DeleteMessage(ctx, server.URL, token, runnerScaleSetMessage.MessageId)
		assert.Nil(t, err)
	})

	t.Run("Message token expired", func(t *testing.T) {
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))

		client, err := scaleset.NewClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		err = client.DeleteMessage(ctx, server.URL, token, 0)
		require.NotNil(t, err)
		var expectedErr *scaleset.MessageQueueTokenExpiredError
		assert.True(t, errors.As(err, &expectedErr))
	})

	t.Run("Error when Content-Type is text/plain", func(t *testing.T) {
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "text/plain")
		}))

		client, err := scaleset.NewClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		err = client.DeleteMessage(ctx, server.URL, token, runnerScaleSetMessage.MessageId)
		require.NotNil(t, err)
		var expectedErr *scaleset.ActionsError
		assert.True(t, errors.As(err, &expectedErr))
	},
	)

	t.Run("Default retries on server error", func(t *testing.T) {
		actualRetry := 0
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			actualRetry++
		}))

		retryMax := 1
		client, err := scaleset.NewClient(
			server.configURLForOrg("my-org"),
			auth,
			scaleset.WithRetryMax(retryMax),
			scaleset.WithRetryWaitMax(1*time.Nanosecond),
		)
		require.NoError(t, err)
		err = client.DeleteMessage(ctx, server.URL, token, runnerScaleSetMessage.MessageId)
		assert.NotNil(t, err)
		expectedRetry := retryMax + 1
		assert.Equalf(t, actualRetry, expectedRetry, "A retry was expected after the first request but got: %v", actualRetry)
	})

	t.Run("No message found", func(t *testing.T) {
		want := (*scaleset.RunnerScaleSetMessage)(nil)
		rsl, err := json.Marshal(want)
		require.NoError(t, err)

		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write(rsl)
		}))

		client, err := scaleset.NewClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		err = client.DeleteMessage(ctx, server.URL, token, runnerScaleSetMessage.MessageId+1)
		var expectedErr *scaleset.ActionsError
		require.True(t, errors.As(err, &expectedErr))
	})
}
