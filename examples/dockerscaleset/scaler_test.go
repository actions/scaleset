package main

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/actions/scaleset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newRunnerState() *runnerState {
	return &runnerState{idle: map[string]string{}, busy: map[string]string{}}
}

func TestRunnerStateMarkBusy(t *testing.T) {
	r := newRunnerState()
	r.addIdle("runner-1", "container-1")

	assert.True(t, r.markBusy("runner-1"))
	assert.Equal(t, "container-1", r.busy["runner-1"])
	assert.Empty(t, r.idle)

	// A redelivered JobStarted must not panic or change state.
	assert.True(t, r.markBusy("runner-1"))
	assert.Equal(t, 1, r.count())

	assert.False(t, r.markBusy("unknown"))
	assert.Equal(t, 1, r.count())
}

func TestRunnerStateMarkDone(t *testing.T) {
	r := newRunnerState()
	r.addIdle("idle-runner", "container-idle")
	r.addIdle("busy-runner", "container-busy")
	require.True(t, r.markBusy("busy-runner"))

	id, ok := r.markDone("busy-runner")
	assert.True(t, ok)
	assert.Equal(t, "container-busy", id)

	id, ok = r.markDone("idle-runner")
	assert.True(t, ok)
	assert.Equal(t, "container-idle", id)

	// A redelivered JobCompleted, or one for a runner this process never started.
	id, ok = r.markDone("busy-runner")
	assert.False(t, ok)
	assert.Empty(t, id)
	assert.Equal(t, 0, r.count())
}

func TestScalerHandlesMessagesForUntrackedRunners(t *testing.T) {
	s := &Scaler{
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		runners: *newRunnerState(),
		// dockerClient is nil: an untracked runner must never reach ContainerRemove.
	}

	assert.NotPanics(t, func() {
		err := s.HandleJobStarted(context.Background(), &scaleset.JobStarted{RunnerName: "unknown"})
		assert.NoError(t, err)
	})
	assert.NotPanics(t, func() {
		err := s.HandleJobCompleted(context.Background(), &scaleset.JobCompleted{RunnerName: "unknown"})
		assert.NoError(t, err)
	})
}
