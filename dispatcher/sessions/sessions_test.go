package sessions

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/actions/scaleset"
	"github.com/google/uuid"

	"github.com/actions/scaleset/dispatcher/gh"
)

// fakeSession blocks on GetMessage until its context ends.
type fakeSession struct{}

func (fakeSession) GetMessage(ctx context.Context, _, _ int) (*scaleset.RunnerScaleSetMessage, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (fakeSession) DeleteMessage(context.Context, int) error              { return nil }
func (fakeSession) AcquireJobs(context.Context, []int64) ([]int64, error) { return nil, nil }
func (fakeSession) Close(context.Context) error                           { return nil }
func (fakeSession) Session() scaleset.RunnerScaleSetSession {
	return scaleset.RunnerScaleSetSession{SessionID: uuid.New(), Statistics: &scaleset.RunnerScaleSetStatistic{}}
}

// fakeAPI hands out a new scale set ID on every EnsureScaleSet, as GitHub
// does after the previous one was deleted.
type fakeAPI struct {
	gh.API
	mu   sync.Mutex
	next int
}

func (a *fakeAPI) EnsureScaleSet(context.Context, string, string) (int, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.next++
	return a.next, a.next > 1, nil
}

func (*fakeAPI) OpenSession(context.Context, string, int, string) (gh.Session, error) {
	return fakeSession{}, nil
}

type fakeHandler struct{ ids chan int }

func (h fakeHandler) OnScaleSet(_ string, id int)                          { h.ids <- id }
func (fakeHandler) OnStatistics(string, *scaleset.RunnerScaleSetStatistic) {}
func (fakeHandler) OnJobStarted(string, *scaleset.JobStarted)              {}
func (fakeHandler) OnJobCompleted(string, *scaleset.JobCompleted)          {}

func waitID(t *testing.T, ids chan int) int {
	t.Helper()
	select {
	case id := <-ids:
		return id
	case <-time.After(2 * time.Second):
		t.Fatal("no scale set adopted")
		return 0
	}
}

func TestInvalidateReopensOnANewScaleSet(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ids := make(chan int, 4)
	p := NewPool(Config{API: &fakeAPI{}, Handler: fakeHandler{ids: ids}, BackoffMin: time.Millisecond, BackoffMax: 10 * time.Millisecond})
	p.Start(ctx, []Spec{{Name: "queue", Repo: "repo", MaxRunners: 1}})
	if id := waitID(t, ids); id != 1 {
		t.Fatalf("first scale set %d", id)
	}
	waitState(t, p, StateActive)

	p.Invalidate("queue", 7) // not the open scale set: ignored
	select {
	case id := <-ids:
		t.Fatalf("reopened on %d after invalidating another scale set", id)
	case <-time.After(50 * time.Millisecond):
	}

	p.Invalidate("queue", 1)
	if id := waitID(t, ids); id != 2 {
		t.Fatalf("scale set %d after invalidation, want 2", id)
	}
	cancel()
	p.Wait()
}

func waitState(t *testing.T, p *Pool, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if p.States()["queue"] == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("state %q, want %q", p.States()["queue"], want)
}
