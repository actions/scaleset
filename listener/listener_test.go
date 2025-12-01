package listener

import (
	"context"
	"errors"
	"math"
	"net/http"
	"testing"
	"time"

	"github.com/actions/scaleset"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Parallel()
	t.Run("invalid config", func(t *testing.T) {
		t.Parallel()
		var config Config
		assert.Error(t, config.Validate())
	})

	t.Run("valid config", func(t *testing.T) {
		t.Parallel()
		config := Config{
			ScaleSetID: 1,
		}
		assert.NoError(t, config.Validate())
	})

	t.Run("invalid max runners", func(t *testing.T) {
		t.Parallel()
		config := Config{
			ScaleSetID: 1,
			MaxRunners: -1,
		}
		assert.Error(t, config.Validate())
	})

	t.Run("zero max runners", func(t *testing.T) {
		t.Parallel()
		config := Config{
			ScaleSetID: 1,
			MaxRunners: math.MaxInt32 + 1,
		}
		assert.Error(t, config.Validate())
	})

	t.Run("creates listener", func(t *testing.T) {
		t.Parallel()
		config := Config{
			ScaleSetID: 1,
			MaxRunners: 5,
		}

		client := NewMockClient(t)
		l, err := New(client, config)
		require.Nil(t, err)
		assert.Equal(t, config.ScaleSetID, l.scaleSetID)
		assert.Equal(t, uint32(config.MaxRunners), l.maxRunners.Load())
	})
}

func TestListener_createSession(t *testing.T) {
	t.Parallel()
	t.Run("fail once", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()

		config := Config{
			ScaleSetID: 1,
			MaxRunners: 10,
		}

		client := NewMockClient(t)
		client.On(
			"CreateMessageSession",
			ctx,
			mock.Anything,
			mock.Anything,
		).Return(
			nil,
			assert.AnError,
		).Once()

		l, err := New(client, config)
		require.Nil(t, err)

		err = l.createSession(ctx)
		assert.NotNil(t, err)
	})

	t.Run("fail context", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		config := Config{
			ScaleSetID: 1,
		}

		client := NewMockClient(t)
		client.On(
			"CreateMessageSession",
			ctx,
			mock.Anything,
			mock.Anything,
		).Return(
			nil,
			scaleset.ParseActionsErrorFromResponse(&http.Response{
				StatusCode: http.StatusConflict,
			}),
		).Once()

		l, err := New(client, config)
		require.Nil(t, err)

		err = l.createSession(ctx)
		assert.True(t, errors.Is(err, context.DeadlineExceeded))
	})

	t.Run("sets session", func(t *testing.T) {
		t.Parallel()
		config := Config{
			ScaleSetID: 1,
		}

		client := NewMockClient(t)

		uuid := uuid.New()
		session := &scaleset.RunnerScaleSetSession{
			SessionID:               uuid,
			OwnerName:               "example",
			RunnerScaleSet:          &scaleset.RunnerScaleSet{},
			MessageQueueURL:         "https://example.com",
			MessageQueueAccessToken: "1234567890",
			Statistics:              nil,
		}
		client.On(
			"CreateMessageSession",
			mock.Anything,
			mock.Anything,
			mock.Anything,
		).Return(session, nil).Once()

		l, err := New(client, config)
		require.Nil(t, err)

		err = l.createSession(context.Background())
		assert.Nil(t, err)
		assert.Equal(t, session, l.session)
	})
}

func TestListener_getMessage(t *testing.T) {
	t.Parallel()

	t.Run("receives message", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		config := Config{
			ScaleSetID: 1,
			MaxRunners: 10,
		}

		client := NewMockClient(t)
		want := &scaleset.RunnerScaleSetMessage{
			MessageID: 1,
		}
		client.On(
			"GetMessage",
			ctx,
			mock.Anything,
			mock.Anything,
			mock.Anything,
			10,
		).Return(
			want,
			nil,
		).Once()

		l, err := New(client, config)
		require.Nil(t, err)
		l.session = &scaleset.RunnerScaleSetSession{}

		got, err := l.getMessage(ctx)
		assert.Nil(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("not expired error", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		config := Config{
			ScaleSetID: 1,
			MaxRunners: 10,
		}

		client := NewMockClient(t)
		client.On(
			"GetMessage",
			ctx,
			mock.Anything,
			mock.Anything,
			mock.Anything,
			10,
		).Return(
			nil,
			scaleset.ParseActionsErrorFromResponse(&http.Response{
				StatusCode: http.StatusNotFound,
			}),
		).Once()

		l, err := New(client, config)
		require.Nil(t, err)

		l.session = &scaleset.RunnerScaleSetSession{}

		_, err = l.getMessage(ctx)
		assert.NotNil(t, err)
	})

	t.Run("refresh and succeeds", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		config := Config{
			ScaleSetID: 1,
			MaxRunners: 10,
		}

		client := NewMockClient(t)

		uuid := uuid.New()
		session := &scaleset.RunnerScaleSetSession{
			SessionID:               uuid,
			OwnerName:               "example",
			RunnerScaleSet:          &scaleset.RunnerScaleSet{},
			MessageQueueURL:         "https://example.com",
			MessageQueueAccessToken: "1234567890",
			Statistics:              nil,
		}
		client.On(
			"RefreshMessageSession",
			ctx,
			mock.Anything,
			mock.Anything,
		).Return(session, nil).Once()

		client.On(
			"GetMessage",
			ctx,
			mock.Anything,
			mock.Anything,
			mock.Anything,
			10,
		).Return(
			nil,
			&scaleset.ActionsError{
				StatusCode: http.StatusUnauthorized,
				ActivityID: "1234",
				Err:        scaleset.NewMessageQueueTokenExpiredError("token expired"),
			},
		).Once()

		want := &scaleset.RunnerScaleSetMessage{
			MessageID: 1,
		}
		client.On(
			"GetMessage",
			ctx,
			mock.Anything,
			mock.Anything,
			mock.Anything,
			10,
		).Return(want, nil).Once()

		l, err := New(client, config)
		require.Nil(t, err)

		l.session = &scaleset.RunnerScaleSetSession{
			SessionID:      uuid,
			RunnerScaleSet: &scaleset.RunnerScaleSet{},
		}

		got, err := l.getMessage(ctx)
		assert.Nil(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("refresh and fails", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		config := Config{
			ScaleSetID: 1,
			MaxRunners: 10,
		}

		client := NewMockClient(t)

		uuid := uuid.New()
		session := &scaleset.RunnerScaleSetSession{
			SessionID:               uuid,
			OwnerName:               "example",
			RunnerScaleSet:          &scaleset.RunnerScaleSet{},
			MessageQueueURL:         "https://example.com",
			MessageQueueAccessToken: "1234567890",
			Statistics:              nil,
		}
		client.On(
			"RefreshMessageSession",
			ctx,
			mock.Anything,
			mock.Anything,
		).Return(session, nil).Once()

		client.On(
			"GetMessage",
			ctx,
			mock.Anything,
			mock.Anything,
			mock.Anything,
			10,
		).Return(
			nil,
			&scaleset.ActionsError{
				StatusCode: http.StatusUnauthorized,
				ActivityID: "1234",
				Err:        scaleset.NewMessageQueueTokenExpiredError("token expired"),
			},
		).Twice()

		l, err := New(client, config)
		require.Nil(t, err)

		l.session = &scaleset.RunnerScaleSetSession{
			SessionID:      uuid,
			RunnerScaleSet: &scaleset.RunnerScaleSet{},
		}

		got, err := l.getMessage(ctx)
		assert.NotNil(t, err)
		assert.Nil(t, got)
	})
}

func TestListener_refreshSession(t *testing.T) {
	t.Parallel()

	t.Run("successfully refreshes", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		config := Config{
			ScaleSetID: 1,
		}

		client := NewMockClient(t)

		newUUID := uuid.New()
		session := &scaleset.RunnerScaleSetSession{
			SessionID:               newUUID,
			OwnerName:               "example",
			RunnerScaleSet:          &scaleset.RunnerScaleSet{},
			MessageQueueURL:         "https://example.com",
			MessageQueueAccessToken: "1234567890",
			Statistics:              nil,
		}
		client.On(
			"RefreshMessageSession",
			ctx,
			mock.Anything,
			mock.Anything,
		).Return(session, nil).Once()

		l, err := New(client, config)
		require.Nil(t, err)

		oldUUID := uuid.New()
		l.session = &scaleset.RunnerScaleSetSession{
			SessionID:      oldUUID,
			RunnerScaleSet: &scaleset.RunnerScaleSet{},
		}

		err = l.refreshSession(ctx)
		assert.Nil(t, err)
		assert.Equal(t, session, l.session)
	})

	t.Run("fails to refresh", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		config := Config{
			ScaleSetID: 1,
		}

		client := NewMockClient(t)

		client.On(
			"RefreshMessageSession",
			ctx,
			mock.Anything,
			mock.Anything,
		).Return(nil, errors.New("error")).Once()

		l, err := New(client, config)
		require.Nil(t, err)

		oldUUID := uuid.New()
		oldSession := &scaleset.RunnerScaleSetSession{
			SessionID:      oldUUID,
			RunnerScaleSet: &scaleset.RunnerScaleSet{},
		}
		l.session = oldSession

		err = l.refreshSession(ctx)
		assert.NotNil(t, err)
		assert.Equal(t, oldSession, l.session)
	})
}

func TestListener_deleteLastMessage(t *testing.T) {
	t.Parallel()

	t.Run("successfully deletes", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		config := Config{
			ScaleSetID: 1,
		}

		client := NewMockClient(t)

		client.On(
			"DeleteMessage",
			ctx,
			mock.Anything,
			mock.Anything,
			mock.MatchedBy(
				func(lastMessageID any) bool {
					return lastMessageID.(int) == 5
				},
			),
		).Return(nil).Once()

		l, err := New(client, config)
		require.Nil(t, err)

		l.session = &scaleset.RunnerScaleSetSession{}
		l.lastMessageID = 5

		err = l.deleteLastMessage(ctx)
		assert.Nil(t, err)
	})

	t.Run("fails to delete", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		config := Config{
			ScaleSetID: 1,
		}

		client := NewMockClient(t)

		client.On(
			"DeleteMessage",
			ctx,
			mock.Anything,
			mock.Anything,
			mock.Anything,
		).Return(errors.New("error")).Once()

		l, err := New(client, config)
		require.Nil(t, err)

		l.session = &scaleset.RunnerScaleSetSession{}
		l.lastMessageID = 5

		err = l.deleteLastMessage(ctx)
		assert.NotNil(t, err)
	})

	t.Run("refresh and succeeds", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		config := Config{
			ScaleSetID: 1,
		}

		client := NewMockClient(t)

		newUUID := uuid.New()
		session := &scaleset.RunnerScaleSetSession{
			SessionID:               newUUID,
			OwnerName:               "example",
			RunnerScaleSet:          &scaleset.RunnerScaleSet{},
			MessageQueueURL:         "https://example.com",
			MessageQueueAccessToken: "1234567890",
			Statistics:              nil,
		}
		client.On(
			"RefreshMessageSession",
			ctx,
			mock.Anything,
			mock.Anything,
		).Return(session, nil).Once()

		client.On(
			"DeleteMessage",
			ctx,
			mock.Anything,
			mock.Anything,
			mock.Anything,
		).Return(
			&scaleset.ActionsError{
				StatusCode: http.StatusUnauthorized,
				ActivityID: "1234",
				Err:        scaleset.NewMessageQueueTokenExpiredError("token expired"),
			},
		).Once()

		client.On(
			"DeleteMessage",
			ctx,
			mock.Anything,
			mock.Anything,
			mock.MatchedBy(
				func(lastMessageID any) bool {
					return lastMessageID.(int) == 5
				},
			),
		).Return(nil).Once()

		l, err := New(client, config)
		require.Nil(t, err)

		oldUUID := uuid.New()
		l.session = &scaleset.RunnerScaleSetSession{
			SessionID:      oldUUID,
			RunnerScaleSet: &scaleset.RunnerScaleSet{},
		}
		l.lastMessageID = 5

		err = l.deleteLastMessage(ctx)
		assert.NoError(t, err)
	})

	t.Run("refresh and fails", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		config := Config{
			ScaleSetID: 1,
		}

		client := NewMockClient(t)

		newUUID := uuid.New()
		session := &scaleset.RunnerScaleSetSession{
			SessionID:               newUUID,
			OwnerName:               "example",
			RunnerScaleSet:          &scaleset.RunnerScaleSet{},
			MessageQueueURL:         "https://example.com",
			MessageQueueAccessToken: "1234567890",
			Statistics:              nil,
		}
		client.On(
			"RefreshMessageSession",
			ctx,
			mock.Anything,
			mock.Anything,
		).Return(session, nil).Once()

		client.On(
			"DeleteMessage",
			ctx,
			mock.Anything,
			mock.Anything,
			mock.Anything,
		).Return(
			&scaleset.ActionsError{
				StatusCode: http.StatusUnauthorized,
				ActivityID: "1234",
				Err:        scaleset.NewMessageQueueTokenExpiredError("token expired"),
			},
		).Twice()

		l, err := New(client, config)
		require.Nil(t, err)

		oldUUID := uuid.New()
		l.session = &scaleset.RunnerScaleSetSession{
			SessionID:      oldUUID,
			RunnerScaleSet: &scaleset.RunnerScaleSet{},
		}
		l.lastMessageID = 5

		err = l.deleteLastMessage(ctx)
		assert.Error(t, err)
	})
}

func TestListener_Run(t *testing.T) {
	t.Parallel()

	t.Run("create session fails", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		config := Config{
			ScaleSetID: 1,
		}

		client := NewMockClient(t)
		client.On(
			"CreateMessageSession",
			ctx,
			mock.Anything,
			mock.Anything,
		).Return(nil, assert.AnError).Once()

		l, err := New(client, config)
		require.Nil(t, err)

		err = l.Run(ctx, nil)
		assert.NotNil(t, err)
	})

	t.Run("call handle regardless of initial message", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())

		config := Config{
			ScaleSetID: 1,
		}

		client := NewMockClient(t)

		uuid := uuid.New()
		session := &scaleset.RunnerScaleSetSession{
			SessionID:               uuid,
			OwnerName:               "example",
			RunnerScaleSet:          &scaleset.RunnerScaleSet{},
			MessageQueueURL:         "https://example.com",
			MessageQueueAccessToken: "1234567890",
			Statistics:              &scaleset.RunnerScaleSetStatistic{},
		}
		client.On(
			"CreateMessageSession",
			ctx,
			mock.Anything,
			mock.Anything,
		).Return(session, nil).Once()
		client.On(
			"DeleteMessageSession",
			mock.Anything,
			session.RunnerScaleSet.ID,
			session.SessionID,
		).Return(nil).Once()

		l, err := New(client, config)
		require.Nil(t, err)

		var called bool
		handler := NewMockScaler(t)
		handler.On(
			"HandleDesiredRunnerCount",
			mock.Anything,
			mock.Anything,
		).
			Return(0, nil).
			Run(
				func(mock.Arguments) {
					called = true
					cancel()
				},
			).
			Once()

		err = l.Run(ctx, handler)
		assert.ErrorIs(t, err, context.Canceled)
		assert.True(t, called)
	})

	t.Run("cancel context after get message", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())

		config := Config{
			ScaleSetID: 1,
			MaxRunners: 10,
		}

		client := NewMockClient(t)
		uuid := uuid.New()
		session := &scaleset.RunnerScaleSetSession{
			SessionID:               uuid,
			OwnerName:               "example",
			RunnerScaleSet:          &scaleset.RunnerScaleSet{},
			MessageQueueURL:         "https://example.com",
			MessageQueueAccessToken: "1234567890",
			Statistics:              &scaleset.RunnerScaleSetStatistic{},
		}
		client.On(
			"CreateMessageSession",
			ctx,
			mock.Anything,
			mock.Anything,
		).Return(session, nil).Once()
		client.On(
			"DeleteMessageSession",
			mock.Anything,
			session.RunnerScaleSet.ID,
			session.SessionID,
		).Return(nil).Once()

		msg := &scaleset.RunnerScaleSetMessage{
			MessageID:  1,
			Statistics: &scaleset.RunnerScaleSetStatistic{},
		}
		client.On(
			"GetMessage",
			ctx,
			mock.Anything,
			mock.Anything,
			mock.Anything,
			10,
		).
			Return(msg, nil).
			Run(
				func(mock.Arguments) {
					cancel()
				},
			).
			Once()

		// Ensure delete message is called without cancel
		client.On(
			"DeleteMessage",
			context.WithoutCancel(ctx),
			mock.Anything,
			mock.Anything,
			mock.Anything,
		).Return(nil).Once()

		handler := NewMockScaler(t)
		handler.On(
			"HandleDesiredRunnerCount",
			mock.Anything,
			0,
		).
			Return(0, nil).
			Once()

		handler.On(
			"HandleDesiredRunnerCount",
			mock.Anything,
			mock.Anything,
		).
			Return(0, nil).
			Once()

		l, err := New(client, config)
		require.Nil(t, err)

		err = l.Run(ctx, handler)
		assert.ErrorIs(t, context.Canceled, err)
	})
}
