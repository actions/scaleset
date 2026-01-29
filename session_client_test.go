package scaleset

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestSessionRequestHandler(t *testing.T, session RunnerScaleSetSession) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		srv := r.Context().Value(ctxKeyServer).(*actionsServer)
		session.MessageQueueURL = srv.URL
		resp, err := json.Marshal(session)
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/json")
		w.Write(resp)
	}
}

func TestCreateMessageSession(t *testing.T) {
	ctx := context.Background()
	auth := actionsAuth{
		token: "token",
	}

	t.Run("CreateMessageSession unmarshals correctly", func(t *testing.T) {
		runnerScaleSet := RunnerScaleSet{
			ID:            1,
			Name:          "ScaleSet",
			CreatedOn:     time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC),
			RunnerSetting: RunnerSetting{},
		}

		var handleSessionRequest http.HandlerFunc
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handleSessionRequest(w, r)
		}))
		want := server.testRunnerScaleSetSession()
		handleSessionRequest = newTestSessionRequestHandler(t, want)

		client, err := newClient(
			testSystemInfo,
			server.configURLForOrg("my-org"),
			auth,
		)
		require.NoError(t, err)

		sessionClient, err := client.MessageSessionClient(ctx, runnerScaleSet.ID, "my-org")
		require.NoError(t, err)

		session := sessionClient.Session()
		require.NotEqual(t, session.SessionID, uuid.Nil)
		assert.Equal(t, want, session)
	})

	t.Run("CreateMessageSession includes actions exception details", func(t *testing.T) {
		owner := "foo"
		runnerScaleSet := RunnerScaleSet{
			ID:            1,
			Name:          "ScaleSet",
			CreatedOn:     time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC),
			RunnerSetting: RunnerSetting{},
		}

		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set(headerActionsActivityID, exampleRequestID)
			w.WriteHeader(http.StatusBadRequest)
			resp := []byte(`{"typeName": "CSharpExceptionNameHere","message": "could not do something"}`)
			w.Write(resp)
		}))

		client, err := newClient(
			testSystemInfo,
			server.configURLForOrg("my-org"),
			auth,
		)
		require.NoError(t, err)

		sessionClient, err := client.MessageSessionClient(context.Background(), runnerScaleSet.ID, owner)
		assert.Nil(t, sessionClient)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "status=\"400 Bad Request\"")
		assert.Contains(t, err.Error(), "activity_id=\""+exampleRequestID+"\"")

		var ex actionsExceptionError
		assert.True(t, errors.As(err, &ex))
		assert.Equal(t, "CSharpExceptionNameHere", ex.ExceptionName)
		assert.Equal(t, "could not do something", ex.Message)
	})

	t.Run("CreateMessageSession call is retried the correct amount of times", func(t *testing.T) {
		owner := "foo"
		runnerScaleSet := RunnerScaleSet{
			ID:            1,
			Name:          "ScaleSet",
			CreatedOn:     time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC),
			RunnerSetting: RunnerSetting{},
		}

		gotRetries := 0
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			gotRetries++
		}))

		retryMax := 3
		retryWaitMax := 1 * time.Microsecond

		wantRetries := retryMax + 1

		client, err := newClient(
			testSystemInfo,
			server.configURLForOrg("my-org"),
			auth,
			WithRetryMax(retryMax),
			WithRetryWaitMax(retryWaitMax),
		)
		require.NoError(t, err)

		_, err = client.MessageSessionClient(
			ctx,
			runnerScaleSet.ID,
			owner,
			WithRetryMax(retryMax),
			WithRetryWaitMax(retryWaitMax),
		)
		assert.NotNil(t, err)
		assert.Equalf(t, gotRetries, wantRetries, "CreateMessageSession got unexpected retry count: got=%v, want=%v", gotRetries, wantRetries)
	})
}

func TestGetMessage(t *testing.T) {
	ctx := context.Background()
	auth := actionsAuth{
		token: "token",
	}

	runnerScaleSetMessage := &RunnerScaleSetMessage{
		MessageID: 1,
	}

	t.Run("Get Runner Scale Set Message", func(t *testing.T) {
		want := runnerScaleSetMessage
		response := []byte(`{"messageId":1,"messageType":"RunnerScaleSetJobMessages"}`)

		var handleSessionRequest http.HandlerFunc
		s := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "sessions") {
				handleSessionRequest(w, r)
				return
			}
			w.Write(response)
		}))
		handleSessionRequest = newTestSessionRequestHandler(t, s.testRunnerScaleSetSession())

		client, err := newClient(
			testSystemInfo,
			s.configURLForOrg("my-org"),
			auth,
		)
		require.NoError(t, err)

		sessionClient, err := client.MessageSessionClient(ctx, 1, "my-org")
		require.NoError(t, err)

		got, err := sessionClient.GetMessage(ctx, 0, 10)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("GetMessage sets the last message id if not 0", func(t *testing.T) {
		want := runnerScaleSetMessage
		response := []byte(`{"messageId":1,"messageType":"RunnerScaleSetJobMessages"}`)
		var handleSessionRequest http.HandlerFunc
		s := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "sessions") {
				handleSessionRequest(w, r)
				return
			}
			q := r.URL.Query()
			assert.Equal(t, "1", q.Get("lastMessageId"))
			w.Write(response)
		}))
		handleSessionRequest = newTestSessionRequestHandler(t, s.testRunnerScaleSetSession())

		client, err := newClient(
			testSystemInfo,
			s.configURLForOrg("my-org"),
			auth,
		)
		require.NoError(t, err)

		sessionClient, err := client.MessageSessionClient(ctx, 1, "my-org")
		require.NoError(t, err)

		got, err := sessionClient.GetMessage(ctx, 1, 10)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("Default retries on server error", func(t *testing.T) {
		retryMax := 1

		actualRetry := 0
		expectedRetry := retryMax + 1

		var handleSessionRequest http.HandlerFunc
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "sessions") {
				handleSessionRequest(w, r)
				return
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			actualRetry++
		}))
		handleSessionRequest = newTestSessionRequestHandler(t, server.testRunnerScaleSetSession())

		client, err := newClient(
			testSystemInfo,
			server.configURLForOrg("my-org"),
			auth,
			WithRetryMax(retryMax),
			WithRetryWaitMax(1*time.Millisecond),
		)
		require.NoError(t, err)

		sessionClient, err := client.MessageSessionClient(
			ctx,
			1,
			"my-org",
			WithRetryMax(retryMax),
			WithRetryWaitMax(1*time.Millisecond),
		)
		require.NoError(t, err)

		msg, err := sessionClient.GetMessage(ctx, 0, 10)
		assert.Nil(t, msg)
		assert.NotNil(t, err)
		assert.Equalf(t, actualRetry, expectedRetry, "A retry was expected after the first request but got: %v", actualRetry)
	})

	t.Run("Message token expired", func(t *testing.T) {
		var handleSessionRequest http.HandlerFunc
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// create session
			if strings.HasSuffix(r.URL.Path, "sessions") {
				handleSessionRequest(w, r)
				return
			}
			// refresh
			if strings.Contains(r.URL.Path, "/sessions/") {
				// just set the same session
				handleSessionRequest(w, r)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		}))
		handleSessionRequest = newTestSessionRequestHandler(t, server.testRunnerScaleSetSession())

		client, err := newClient(
			testSystemInfo,
			server.configURLForOrg("my-org"),
			auth,
		)
		require.NoError(t, err)

		sessionClient, err := client.MessageSessionClient(ctx, 1, "my-org")
		require.NoError(t, err)

		msg, err := sessionClient.GetMessage(ctx, 0, 10)
		assert.Nil(t, msg)
		assert.ErrorIs(t, err, MessageQueueTokenExpiredError, "expected error to be MessageQueueTokenExpiredError but got: %v", err)
	})

	t.Run("Message token refreshed", func(t *testing.T) {
		want := runnerScaleSetMessage
		afterRefreshResponse := []byte(`{"messageId":1,"messageType":"RunnerScaleSetJobMessages"}`)
		var handleSessionRequest http.HandlerFunc
		type state int
		const (
			createSession state = iota
			firstGetMessage
			refreshToken
			secondGetMessage
		)
		currentState := createSession
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// create session
			if strings.HasSuffix(r.URL.Path, "sessions") {
				require.Equal(t, createSession, currentState)
				handleSessionRequest(w, r)
				currentState = firstGetMessage
				return
			}
			// refresh
			if strings.Contains(r.URL.Path, "/sessions/") {
				// just set the same session
				require.Equal(t, refreshToken, currentState)
				handleSessionRequest(w, r)
				currentState = secondGetMessage
				return
			}
			if currentState == firstGetMessage {
				w.WriteHeader(http.StatusUnauthorized)
				currentState = refreshToken
				return
			}
			require.Equal(t, secondGetMessage, currentState)
			w.Write(afterRefreshResponse)
		}))
		handleSessionRequest = newTestSessionRequestHandler(t, server.testRunnerScaleSetSession())

		client, err := newClient(
			testSystemInfo,
			server.configURLForOrg("my-org"),
			auth,
		)
		require.NoError(t, err)

		sessionClient, err := client.MessageSessionClient(ctx, 1, "my-org")
		require.NoError(t, err)

		got, err := sessionClient.GetMessage(ctx, 0, 10)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("Status code not found", func(t *testing.T) {
		var handleSessionRequest http.HandlerFunc
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "sessions") {
				handleSessionRequest(w, r)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		handleSessionRequest = newTestSessionRequestHandler(t, server.testRunnerScaleSetSession())

		client, err := newClient(
			testSystemInfo,
			server.configURLForOrg("my-org"),
			auth,
		)
		require.NoError(t, err)

		sessionClient, err := client.MessageSessionClient(ctx, 1, "my-org")
		require.NoError(t, err)

		msg, err := sessionClient.GetMessage(ctx, 0, 10)
		assert.Nil(t, msg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "status=\"404 Not Found\"")
		assert.Contains(t, err.Error(), "unknown error")
	})

	t.Run("Error when Content-Type is text/plain", func(t *testing.T) {
		plainBody := "example plain text error"
		var handleSessionRequest http.HandlerFunc
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "sessions") {
				handleSessionRequest(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(plainBody))
		}))
		handleSessionRequest = newTestSessionRequestHandler(t, server.testRunnerScaleSetSession())

		client, err := newClient(
			testSystemInfo,
			server.configURLForOrg("my-org"),
			auth,
		)
		require.NoError(t, err)

		sessionClient, err := client.MessageSessionClient(ctx, 1, "my-org")
		require.NoError(t, err)

		msg, err := sessionClient.GetMessage(ctx, 0, 10)
		assert.Nil(t, msg)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "status=\"400 Bad Request\"")
		assert.Contains(t, err.Error(), plainBody)
	})

	t.Run("Capacity error handling", func(t *testing.T) {
		plainBody := "capacity error"
		var handleSessionRequest http.HandlerFunc
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "sessions") {
				handleSessionRequest(w, r)
				return
			}
			hc := r.Header.Get(HeaderScaleSetMaxCapacity)
			c, err := strconv.Atoi(hc)
			require.NoError(t, err)
			assert.GreaterOrEqual(t, c, 0)
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(plainBody))
		}))
		handleSessionRequest = newTestSessionRequestHandler(t, server.testRunnerScaleSetSession())

		client, err := newClient(
			testSystemInfo,
			server.configURLForOrg("my-org"),
			auth,
		)
		require.NoError(t, err)

		sessionClient, err := client.MessageSessionClient(ctx, 1, "my-org")
		require.NoError(t, err)

		msg, err := sessionClient.GetMessage(ctx, 0, 0)
		assert.Nil(t, msg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "status=\"400 Bad Request\"")
		assert.Contains(t, err.Error(), plainBody)
	})
}

func TestDeleteMessage(t *testing.T) {
	ctx := context.Background()
	auth := actionsAuth{
		token: "token",
	}

	runnerScaleSetMessage := &RunnerScaleSetMessage{
		MessageID: 1,
	}

	t.Run("Delete existing message", func(t *testing.T) {
		var handleSessionRequest http.HandlerFunc
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "sessions") {
				handleSessionRequest(w, r)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		handleSessionRequest = newTestSessionRequestHandler(t, server.testRunnerScaleSetSession())

		client, err := newClient(
			testSystemInfo,
			server.configURLForOrg("my-org"),
			auth,
		)
		require.NoError(t, err)

		sessionClient, err := client.MessageSessionClient(ctx, 1, "my-org")
		require.NoError(t, err)

		err = sessionClient.DeleteMessage(ctx, runnerScaleSetMessage.MessageID)
		assert.Nil(t, err)
	})

	t.Run("Message token expired", func(t *testing.T) {
		var handleSessionRequest http.HandlerFunc
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// create session
			if strings.HasSuffix(r.URL.Path, "sessions") {
				handleSessionRequest(w, r)
				return
			}

			// refresh
			if strings.Contains(r.URL.Path, "/sessions/") {
				// just set the same session
				handleSessionRequest(w, r)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		}))
		handleSessionRequest = newTestSessionRequestHandler(t, server.testRunnerScaleSetSession())

		client, err := newClient(
			testSystemInfo,
			server.configURLForOrg("my-org"),
			auth,
		)
		require.NoError(t, err)

		sessionClient, err := client.MessageSessionClient(ctx, 1, "my-org")
		require.NoError(t, err)

		err = sessionClient.DeleteMessage(ctx, 0)
		require.NotNil(t, err)
		assert.ErrorIs(t, err, MessageQueueTokenExpiredError, "expected error to be MessageQueueTokenExpiredError but got: %v", err)
	})

	t.Run("message token refreshed", func(t *testing.T) {
		type state int
		const (
			createSession state = iota
			firstDeleteMessage
			refreshToken
			secondDeleteMessage
		)
		currentState := createSession

		var handleSessionRequest http.HandlerFunc
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// create session
			if strings.HasSuffix(r.URL.Path, "sessions") {
				require.Equal(t, createSession, currentState)
				handleSessionRequest(w, r)
				currentState = firstDeleteMessage
				return
			}
			// refresh
			if strings.Contains(r.URL.Path, "/sessions/") {
				// just set the same session
				require.Equal(t, refreshToken, currentState)
				handleSessionRequest(w, r)
				currentState = secondDeleteMessage
				return
			}
			if currentState == firstDeleteMessage {
				w.WriteHeader(http.StatusUnauthorized)
				currentState = refreshToken
				return
			}
			require.Equal(t, secondDeleteMessage, currentState)
			w.WriteHeader(http.StatusNoContent)
		}))
		handleSessionRequest = newTestSessionRequestHandler(t, server.testRunnerScaleSetSession())

		client, err := newClient(
			testSystemInfo,
			server.configURLForOrg("my-org"),
			auth,
		)
		require.NoError(t, err)

		sessionClient, err := client.MessageSessionClient(ctx, 1, "my-org")
		require.NoError(t, err)

		err = sessionClient.DeleteMessage(ctx, 0)
		require.NoError(t, err)
	})

	t.Run("Error when Content-Type is text/plain", func(t *testing.T) {
		plainBody := "example plain text error"
		var handleSessionRequest http.HandlerFunc
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "sessions") {
				handleSessionRequest(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(plainBody))
		}))
		handleSessionRequest = newTestSessionRequestHandler(t, server.testRunnerScaleSetSession())

		client, err := newClient(
			testSystemInfo,
			server.configURLForOrg("my-org"),
			auth,
		)
		require.NoError(t, err)

		sessionClient, err := client.MessageSessionClient(ctx, 1, "my-org")
		require.NoError(t, err)

		err = sessionClient.DeleteMessage(ctx, runnerScaleSetMessage.MessageID)
		require.NotNil(t, err)
		assert.Contains(t, err.Error(), "status=\"400 Bad Request\"")
		assert.Contains(t, err.Error(), plainBody)
	})

	t.Run("Default retries on server error", func(t *testing.T) {
		actualRetry := 0
		var handleSessionRequest http.HandlerFunc
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "sessions") {
				handleSessionRequest(w, r)
				return
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			actualRetry++
		}))
		handleSessionRequest = newTestSessionRequestHandler(t, server.testRunnerScaleSetSession())

		retryMax := 1
		client, err := newClient(
			testSystemInfo,
			server.configURLForOrg("my-org"),
			auth,
			WithRetryMax(retryMax),
			WithRetryWaitMax(1*time.Nanosecond),
		)
		require.NoError(t, err)

		sessionClient, err := client.MessageSessionClient(
			ctx,
			1,
			"my-org",
			WithRetryMax(retryMax),
			WithRetryWaitMax(1*time.Nanosecond),
		)
		require.NoError(t, err)

		err = sessionClient.DeleteMessage(ctx, runnerScaleSetMessage.MessageID)
		assert.NotNil(t, err)
		expectedRetry := retryMax + 1
		assert.Equalf(t, actualRetry, expectedRetry, "A retry was expected after the first request but got: %v", actualRetry)
	})

	t.Run("No message found", func(t *testing.T) {
		want := (*RunnerScaleSetMessage)(nil)
		rsl, err := json.Marshal(want)
		require.NoError(t, err)

		var handleSessionRequest http.HandlerFunc

		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "sessions") {
				handleSessionRequest(w, r)
				return
			}
			w.Write(rsl)
		}))
		handleSessionRequest = newTestSessionRequestHandler(t, server.testRunnerScaleSetSession())

		client, err := newClient(
			testSystemInfo,
			server.configURLForOrg("my-org"),
			auth,
		)
		require.NoError(t, err)

		sessionClient, err := client.MessageSessionClient(ctx, 1, "my-org")
		require.NoError(t, err)

		err = sessionClient.DeleteMessage(ctx, runnerScaleSetMessage.MessageID+1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected status code")
	})
}
