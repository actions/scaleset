package scaleset

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateMessageSession(t *testing.T) {
	ctx := context.Background()
	auth := &actionsAuth{
		token: "token",
	}

	t.Run("CreateMessageSession unmarshals correctly", func(t *testing.T) {
		owner := "foo"
		runnerScaleSet := RunnerScaleSet{
			ID:            1,
			Name:          "ScaleSet",
			CreatedOn:     time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC),
			RunnerSetting: RunnerSetting{},
		}

		want := &RunnerScaleSetSession{
			OwnerName: "foo",
			RunnerScaleSet: &RunnerScaleSet{
				ID:   1,
				Name: "ScaleSet",
			},
			MessageQueueURL:         "http://fake.github.com/123",
			MessageQueueAccessToken: "fake.jwt.here",
		}

		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			resp := []byte(`{
					"ownerName": "foo",
					"runnerScaleSet": {
						"id": 1,
						"name": "ScaleSet"
					},
					"messageQueueUrl": "http://fake.github.com/123",
					"messageQueueAccessToken": "fake.jwt.here"
				}`)
			w.Write(resp)
		}))

		client, err := newClient(
			testSystemInfo,
			server.configURLForOrg("my-org"),
			auth,
		)
		require.NoError(t, err)

		sessionClient, err := client.MakeMessageSessionClient(runnerScaleSet.ID, owner)
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

		sessionClient, err := client.MakeMessageSessionClient(context.Background(), runnerScaleSet.ID, owner)
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
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

		_, err = client.MakeMessageSessionClient(ctx, runnerScaleSet.ID, owner)
		assert.NotNil(t, err)
		assert.Equalf(t, gotRetries, wantRetries, "CreateMessageSession got unexpected retry count: got=%v, want=%v", gotRetries, wantRetries)
	})
}

func TestRefreshMessageSession(t *testing.T) {
	auth := &actionsAuth{
		token: "token",
	}

	t.Run("RefreshMessageSession call is retried the correct amount of times", func(t *testing.T) {
		runnerScaleSet := RunnerScaleSet{
			ID:            1,
			Name:          "ScaleSet",
			CreatedOn:     time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC),
			RunnerSetting: RunnerSetting{},
		}

		gotRetries := 0
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

		sessionID := uuid.New()

		_, err = client.RefreshMessageSession(context.Background(), runnerScaleSet.ID, sessionID)
		assert.NotNil(t, err)
		assert.Equalf(t, gotRetries, wantRetries, "CreateMessageSession got unexpected retry count: got=%v, want=%v", gotRetries, wantRetries)
	})
}

func TestGetMessage(t *testing.T) {
	ctx := context.Background()
	auth := &actionsAuth{
		token: "token",
	}

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjI1MTYyMzkwMjJ9.tlrHslTmDkoqnc4Kk9ISoKoUNDfHo-kjlH-ByISBqzE"
	runnerScaleSetMessage := &RunnerScaleSetMessage{
		MessageID: 1,
	}

	t.Run("Get Runner Scale Set Message", func(t *testing.T) {
		want := runnerScaleSetMessage
		response := []byte(`{"messageId":1,"messageType":"RunnerScaleSetJobMessages"}`)
		s := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write(response)
		}))

		client, err := newClient(
			testSystemInfo,
			s.configURLForOrg("my-org"),
			auth,
		)
		require.NoError(t, err)

		got, err := client.GetMessage(ctx, s.URL, token, 0, 10)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("GetMessage sets the last message id if not 0", func(t *testing.T) {
		want := runnerScaleSetMessage
		response := []byte(`{"messageId":1,"messageType":"RunnerScaleSetJobMessages"}`)
		s := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		client, err := newClient(
			testSystemInfo,
			server.configURLForOrg("my-org"),
			auth,
			WithRetryMax(retryMax),
			WithRetryWaitMax(1*time.Millisecond),
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

		client, err := newClient(
			testSystemInfo,
			server.configURLForOrg("my-org"),
			auth,
		)
		require.NoError(t, err)

		_, err = client.GetMessage(ctx, server.URL, token, 0, 10)
		require.NotNil(t, err)

		var expectedErr *ActionsError
		require.True(t, errors.As(err, &expectedErr))

		assert.True(t, expectedErr.IsMessageQueueTokenExpired())
	})

	t.Run("Status code not found", func(t *testing.T) {
		want := ActionsError{
			Err:        errors.New("unknown exception"),
			StatusCode: 404,
		}
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))

		client, err := newClient(
			testSystemInfo,
			server.configURLForOrg("my-org"),
			auth,
		)
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

		client, err := newClient(
			testSystemInfo,
			server.configURLForOrg("my-org"),
			auth,
		)
		require.NoError(t, err)

		_, err = client.GetMessage(ctx, server.URL, token, 0, 10)
		assert.NotNil(t, err)
	})

	t.Run("Capacity error handling", func(t *testing.T) {
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		_, err = client.GetMessage(ctx, server.URL, token, 0, 0)
		assert.Error(t, err)
		var expectedErr *ActionsError
		assert.ErrorAs(t, err, &expectedErr)
		assert.Equal(t, http.StatusBadRequest, expectedErr.StatusCode)
	})
}

func TestDeleteMessage(t *testing.T) {
	ctx := context.Background()
	auth := &actionsAuth{
		token: "token",
	}

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjI1MTYyMzkwMjJ9.tlrHslTmDkoqnc4Kk9ISoKoUNDfHo-kjlH-ByISBqzE"
	runnerScaleSetMessage := &RunnerScaleSetMessage{
		MessageID: 1,
	}

	t.Run("Delete existing message", func(t *testing.T) {
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))

		client, err := newClient(
			testSystemInfo,
			server.configURLForOrg("my-org"),
			auth,
		)
		require.NoError(t, err)

		err = client.DeleteMessage(ctx, server.URL, token, runnerScaleSetMessage.MessageID)
		assert.Nil(t, err)
	})

	t.Run("Message token expired", func(t *testing.T) {
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))

		client, err := newClient(
			testSystemInfo,
			server.configURLForOrg("my-org"),
			auth,
		)
		require.NoError(t, err)

		err = client.DeleteMessage(ctx, server.URL, token, 0)
		require.NotNil(t, err)
		var expectedErr *ActionsError
		require.ErrorAs(t, err, &expectedErr)
		assert.True(t, expectedErr.IsMessageQueueTokenExpired())
	})

	t.Run("Error when Content-Type is text/plain", func(t *testing.T) {
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "text/plain")
		}))

		client, err := newClient(
			testSystemInfo,
			server.configURLForOrg("my-org"),
			auth,
		)
		require.NoError(t, err)

		err = client.DeleteMessage(ctx, server.URL, token, runnerScaleSetMessage.MessageID)
		require.NotNil(t, err)
		var expectedErr *ActionsError
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
		client, err := newClient(
			testSystemInfo,
			server.configURLForOrg("my-org"),
			auth,
			WithRetryMax(retryMax),
			WithRetryWaitMax(1*time.Nanosecond),
		)
		require.NoError(t, err)
		err = client.DeleteMessage(ctx, server.URL, token, runnerScaleSetMessage.MessageID)
		assert.NotNil(t, err)
		expectedRetry := retryMax + 1
		assert.Equalf(t, actualRetry, expectedRetry, "A retry was expected after the first request but got: %v", actualRetry)
	})

	t.Run("No message found", func(t *testing.T) {
		want := (*RunnerScaleSetMessage)(nil)
		rsl, err := json.Marshal(want)
		require.NoError(t, err)

		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write(rsl)
		}))

		client, err := newClient(
			testSystemInfo,
			server.configURLForOrg("my-org"),
			auth,
		)
		require.NoError(t, err)

		err = client.DeleteMessage(ctx, server.URL, token, runnerScaleSetMessage.MessageID+1)
		var expectedErr *ActionsError
		require.True(t, errors.As(err, &expectedErr))
	})
}
