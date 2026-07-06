package listener

import (
	"context"
	"math"
	"testing"

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

func TestListener_Run(t *testing.T) {
	t.Parallel()

	t.Run("call handle regardless of initial message", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())

		config := Config{
			ScaleSetID: 1,
		}

		client := NewMockClient(t)

		uuid := uuid.New()
		initialStatistics := &scaleset.RunnerScaleSetStatistic{
			TotalAssignedJobs: 2,
		}
		session := scaleset.RunnerScaleSetSession{
			SessionID:               uuid,
			OwnerName:               "example",
			RunnerScaleSet:          &scaleset.RunnerScaleSet{},
			MessageQueueURL:         "https://example.com",
			MessageQueueAccessToken: "1234567890",
			Statistics:              initialStatistics,
		}

		client.On("Session").Return(session).Once()

		l, err := New(client, config)
		require.Nil(t, err)

		handler := NewMockScaler(t)
		handler.On("Scale", mock.Anything, mock.MatchedBy(func(message *scaleset.RunnerScaleSetMessage) bool {
			return message.Statistics == initialStatistics
		})).
			Run(func(mock.Arguments) { cancel() }).
			Return(nil).
			Once()

		err = l.Run(ctx, handler)
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("cancel context after get message", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())

		config := Config{
			ScaleSetID: 1,
			MaxRunners: 10,
		}

		uuid := uuid.New()
		initialStatistics := &scaleset.RunnerScaleSetStatistic{
			TotalAssignedJobs: 2,
		}

		session := scaleset.RunnerScaleSetSession{
			SessionID:               uuid,
			OwnerName:               "example",
			RunnerScaleSet:          &scaleset.RunnerScaleSet{},
			MessageQueueURL:         "https://example.com",
			MessageQueueAccessToken: "1234567890",
			Statistics:              initialStatistics,
		}

		msg := &scaleset.RunnerScaleSetMessage{
			MessageID: 1,
			Statistics: &scaleset.RunnerScaleSetStatistic{
				TotalAssignedJobs: 3,
			},
		}

		client := NewMockClient(t)
		handler := NewMockScaler(t)

		client.On("Session").Return(session).Once()
		handler.On("Scale", mock.Anything, mock.MatchedBy(func(message *scaleset.RunnerScaleSetMessage) bool {
			return message.Statistics == initialStatistics
		})).
			Return(nil).
			Once()

		client.On("GetMessage", ctx, mock.Anything, 10).
			Return(msg, nil).
			Run(func(mock.Arguments) { cancel() }).
			Once()

		// Ensure delete message is called without cancel
		client.On("DeleteMessage", context.WithoutCancel(ctx), mock.Anything).
			Return(nil).
			Once()

		handler.On("Scale", mock.Anything, msg).
			Return(nil).
			Once()

		l, err := New(client, config)
		require.Nil(t, err)

		err = l.Run(ctx, handler)
		assert.ErrorIs(t, context.Canceled, err)
	})
}
