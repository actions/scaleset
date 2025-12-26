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

func testSession() *RunnerScaleSetSession {
	return &RunnerScaleSetSession{
		SessionID: uuid.New(),
		OwnerName: "foo",
		RunnerScaleSet: &RunnerScaleSet{
			ID:   1,
			Name: "ScaleSet",
		},
		MessageQueueURL:         "http://fake.github.com/123",
		MessageQueueAccessToken: "fake.jwt.here",
		Statistics: &RunnerScaleSetStatistic{
			TotalAvailableJobs:     0,
			TotalAcquiredJobs:      0,
			TotalAssignedJobs:      0,
			TotalRunningJobs:       0,
			TotalRegisteredRunners: 0,
			TotalBusyRunners:       0,
			TotalIdleRunners:       0,
		},
	}
}

func newTestSessionRequestHandler(t *testing.T, session *RunnerScaleSetSession) http.HandlerFunc {
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

		want := testSession()
		handleSessionRequest := newTestSessionRequestHandler(t, want)

		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handleSessionRequest(w, r)
		}))

		client, err := newClient(
			testSystemInfo,
			server.configURLForOrg("my-org"),
			auth,
		)
		require.NoError(t, err)

		sessionClient, err := client.MessageSessionClient(ctx, runnerScaleSet.ID, "my-org")
		require.NoError(t, err)

		session := sessionClient.Session()
		require.NotNil(t, session)

		assert.Equal(t, want, session)
	})

	t.Run("CreateMessageSession unmarshals errors into ActionsError", func(t *testing.T) {
		owner := "foo"
		runnerScaleSet := RunnerScaleSet{
			ID:            1,
			Name:          "ScaleSet",
			CreatedOn:     time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC),
			RunnerSetting: RunnerSetting{},
		}

		want := &ActionsError{
			ActivityID: exampleRequestID,
			StatusCode: http.StatusBadRequest,
			Err: &actionsExceptionError{
				ExceptionName: "CSharpExceptionNameHere",
				Message:       "could not do something",
			},
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

		errorTypeForComparison := &ActionsError{}
		assert.ErrorAs(t, err, &errorTypeForComparison)

		assert.Equal(t, want, errorTypeForComparison)
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

		handleSessionRequest := newTestSessionRequestHandler(t, testSession())
		s := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "sessions") {
				handleSessionRequest(w, r)
				return
			}
			w.Write(response)
		}))

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
		handleSessionRequest := newTestSessionRequestHandler(t, testSession())
		s := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "sessions") {
				handleSessionRequest(w, r)
				return
			}
			q := r.URL.Query()
			assert.Equal(t, "1", q.Get("lastMessageId"))
			w.Write(response)
		}))

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

		handleSessionRequest := newTestSessionRequestHandler(t, testSession())
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "sessions") {
				handleSessionRequest(w, r)
				return
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			actualRetry++
		}))

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
		handleSessionRequest := newTestSessionRequestHandler(t, testSession())
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

		var expectedErr *ActionsError
		require.ErrorAs(t, err, &expectedErr)
		assert.True(t, expectedErr.IsMessageQueueTokenExpired(), "expected error to be of type MessageQueueTokenExpiredError but got: %v", err)
	})

	t.Run("Message token refreshed", func(t *testing.T) {
		want := runnerScaleSetMessage
		afterRefreshResponse := []byte(`{"messageId":1,"messageType":"RunnerScaleSetJobMessages"}`)
		handleSessionRequest := newTestSessionRequestHandler(t, testSession())
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
		want := ActionsError{
			Err:        errors.New("unknown exception"),
			StatusCode: 404,
		}
		handleSessionRequest := newTestSessionRequestHandler(t, testSession())
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "sessions") {
				handleSessionRequest(w, r)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))

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
		var got *ActionsError
		require.ErrorAs(t, err, &got)
		assert.Equal(t, want.StatusCode, got.StatusCode)
		assert.Equal(t, want.Err.Error(), got.Err.Error())
	})

	t.Run("Error when Content-Type is text/plain", func(t *testing.T) {
		handleSessionRequest := newTestSessionRequestHandler(t, testSession())
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "sessions") {
				handleSessionRequest(w, r)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "text/plain")
		}))

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
	})

	t.Run("Capacity error handling", func(t *testing.T) {
		handleSessionRequest := newTestSessionRequestHandler(t, testSession())
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "sessions") {
				handleSessionRequest(w, r)
				return
			}
			hc := r.Header.Get(HeaderScaleSetMaxCapacity)
			c, err := strconv.Atoi(hc)
			require.NoError(t, err)
			assert.GreaterOrEqual(t, c, 0)

			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "text/plain")
		}))

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
		var expectedErr *ActionsError
		assert.ErrorAs(t, err, &expectedErr)
		assert.Equal(t, http.StatusBadRequest, expectedErr.StatusCode)
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
		handleSessionRequest := newTestSessionRequestHandler(t, testSession())
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "sessions") {
				handleSessionRequest(w, r)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}))

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
		handleSessionRequest := newTestSessionRequestHandler(t, testSession())
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
		var expectedErr *ActionsError
		require.ErrorAs(t, err, &expectedErr)
		assert.True(t, expectedErr.IsMessageQueueTokenExpired())
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

		handleSessionRequest := newTestSessionRequestHandler(t, testSession())
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
		handleSessionRequest := newTestSessionRequestHandler(t, testSession())
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "sessions") {
				handleSessionRequest(w, r)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "text/plain")
		}))

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
		var expectedErr *ActionsError
		assert.True(t, errors.As(err, &expectedErr))
	},
	)

	t.Run("Default retries on server error", func(t *testing.T) {
		actualRetry := 0
		handleSessionRequest := newTestSessionRequestHandler(t, testSession())
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "sessions") {
				handleSessionRequest(w, r)
				return
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			actualRetry++
		}))

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

		handleSessionRequest := newTestSessionRequestHandler(t, testSession())
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "sessions") {
				handleSessionRequest(w, r)
				return
			}
			w.Write(rsl)
		}))

		client, err := newClient(
			testSystemInfo,
			server.configURLForOrg("my-org"),
			auth,
		)
		require.NoError(t, err)

		sessionClient, err := client.MessageSessionClient(ctx, 1, "my-org")
		require.NoError(t, err)

		err = sessionClient.DeleteMessage(ctx, runnerScaleSetMessage.MessageID+1)
		var expectedErr *ActionsError
		require.True(t, errors.As(err, &expectedErr))
	})
}
