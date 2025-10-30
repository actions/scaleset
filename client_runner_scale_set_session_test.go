package scaleset

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const exampleRequestID = "5ddf2050-dae0-013c-9159-04421ad31b68"

func TestCreateMessageSession(t *testing.T) {
	ctx := context.Background()
	auth := &ActionsAuth{
		Token: "token",
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

		client, err := NewClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		got, err := client.CreateMessageSession(ctx, runnerScaleSet.ID, owner)
		require.NoError(t, err)
		assert.Equal(t, want, got)
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
			Err: &ActionsExceptionError{
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

		client, err := NewClient(server.configURLForOrg("my-org"), auth)
		require.NoError(t, err)

		_, err = client.CreateMessageSession(ctx, runnerScaleSet.ID, owner)
		require.NotNil(t, err)

		errorTypeForComparison := &ActionsError{}
		assert.True(
			t,
			errors.As(err, &errorTypeForComparison),
			"CreateMessageSession expected to be able to parse the error into ActionsError type: %v",
			err,
		)

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

		client, err := NewClient(
			server.configURLForOrg("my-org"),
			auth,
			WithRetryMax(retryMax),
			WithRetryWaitMax(retryWaitMax),
		)
		require.NoError(t, err)

		_, err = client.CreateMessageSession(ctx, runnerScaleSet.ID, owner)
		assert.NotNil(t, err)
		assert.Equalf(t, gotRetries, wantRetries, "CreateMessageSession got unexpected retry count: got=%v, want=%v", gotRetries, wantRetries)
	})
}

func TestDeleteMessageSession(t *testing.T) {
	ctx := context.Background()
	auth := &ActionsAuth{
		Token: "token",
	}

	t.Run("DeleteMessageSession call is retried the correct amount of times", func(t *testing.T) {
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

		client, err := NewClient(
			server.configURLForOrg("my-org"),
			auth,
			WithRetryMax(retryMax),
			WithRetryWaitMax(retryWaitMax),
		)
		require.NoError(t, err)

		sessionID := uuid.New()

		err = client.DeleteMessageSession(ctx, runnerScaleSet.ID, sessionID)
		assert.NotNil(t, err)
		assert.Equalf(t, gotRetries, wantRetries, "CreateMessageSession got unexpected retry count: got=%v, want=%v", gotRetries, wantRetries)
	})
}

func TestRefreshMessageSession(t *testing.T) {
	auth := &ActionsAuth{
		Token: "token",
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

		client, err := NewClient(
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
