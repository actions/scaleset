package controller

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/actions/scaleset"
	"github.com/actions/scaleset/dispatcher/catalog"
	"github.com/actions/scaleset/dispatcher/claim"
	"github.com/actions/scaleset/dispatcher/gh"
	"github.com/actions/scaleset/dispatcher/metrics"
	"github.com/actions/scaleset/dispatcher/pods"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type testPods struct {
	PodAPI
	pod     *corev1.Pod
	patched chan string
	deleted []string
}

func (p *testPods) Managed() []*corev1.Pod    { return []*corev1.Pod{p.pod} }
func (p *testPods) RunnerPods() []*corev1.Pod { return p.Managed() }
func (p *testPods) Delete(_ context.Context, name string, _ types.UID) error {
	p.deleted = append(p.deleted, name)
	return nil
}
func (p *testPods) Patch(_ context.Context, name string, _ types.UID, _ map[string]string, _ map[string]string) error {
	p.patched <- name
	return nil
}

type testAPI struct{ gh.API }

func (testAPI) GenerateJIT(context.Context, string, int, string) (gh.JIT, error) {
	return gh.JIT{RunnerID: 1, Config: "config"}, nil
}

type testMailbox struct {
	Mailbox
	ready     time.Time
	delivered chan string
	payload   claim.Payload
}

func (m *testMailbox) Ready(string) (time.Time, bool) { return m.ready, true }
func (m *testMailbox) Deposit(name, _ string, p claim.Payload) error {
	m.payload = p
	m.delivered <- name
	return nil
}

func TestWarmRunnerAssignedAtFullCapacity(t *testing.T) {
	labels := pods.Labels{Prefix: "example.com/ci"}
	now := time.Now()
	p := &testPods{pod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "warm-one", UID: "uid", Labels: map[string]string{labels.Profile(): "light", labels.State(): pods.StateWarm}}, Spec: corev1.PodSpec{NodeName: "node-a"}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}, patched: make(chan string, 1)}
	mailbox := &testMailbox{ready: now, delivered: make(chan string, 1)}
	cat := &catalog.Catalog{Profiles: map[string]*catalog.Profile{"light": {Warm: 1, Nodes: []string{"node-a"}}}, Capacity: catalog.Capacity{Enforce: true, Nodes: map[string]catalog.NodeCapacity{"node-a": {Places: 1}}}}
	q := catalog.Queue{Name: "queue", Repo: "repo", Profile: "light", MaxRunners: 1, Spec: cat.ProfileSpec("light")}
	c := New(Config{Catalog: cat, Queues: []catalog.Queue{q}, API: testAPI{}, Pods: p, Mailbox: mailbox, Metrics: metrics.New(), Labels: labels, AgentImage: "registry/dispatcher@sha256:abc", Now: func() time.Time { return now }})
	c.OnScaleSet(q.Name, 1)
	c.mu.Lock()
	c.queues[q.Name].desired = 1
	c.mu.Unlock()
	c.Reconcile(context.Background())
	select {
	case name := <-mailbox.delivered:
		if name != p.pod.Name {
			t.Fatalf("assigned %q", name)
		}
		if got := mailbox.payload.Env[DispatcherImageEnv]; got != "registry/dispatcher@sha256:abc" {
			t.Fatalf("claim names dispatcher image %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("warm pod was not assigned at full capacity")
	}
}

// jitAPI answers every runner registration with err.
type jitAPI struct {
	gh.API
	err   error
	calls chan struct{}
}

func (a jitAPI) GenerateJIT(context.Context, string, int, string) (gh.JIT, error) {
	a.calls <- struct{}{}
	return gh.JIT{}, a.err
}

func warmSetup(api gh.API, gone func(string, int)) (*Controller, catalog.Queue) {
	labels := pods.Labels{Prefix: "example.com/ci"}
	now := time.Now()
	p := &testPods{pod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "warm-one", UID: "uid", Labels: map[string]string{labels.Profile(): "light", labels.State(): pods.StateWarm}}, Spec: corev1.PodSpec{NodeName: "node-a"}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}, patched: make(chan string, 1)}
	cat := &catalog.Catalog{Profiles: map[string]*catalog.Profile{"light": {Warm: 1, Nodes: []string{"node-a"}}}, Capacity: catalog.Capacity{Enforce: true, Nodes: map[string]catalog.NodeCapacity{"node-a": {Places: 1}}}}
	q := catalog.Queue{Name: "queue", Repo: "repo", Profile: "light", MaxRunners: 1, Spec: cat.ProfileSpec("light")}
	c := New(Config{Catalog: cat, Queues: []catalog.Queue{q}, API: api, Pods: p, Mailbox: &testMailbox{ready: now}, Metrics: metrics.New(), Labels: labels, Now: func() time.Time { return now }, OnScaleSetGone: gone})
	c.OnScaleSet(q.Name, 1)
	c.mu.Lock()
	c.queues[q.Name].desired = 1
	c.mu.Unlock()
	return c, q
}

// waitIdle waits until no runner start is in flight.
func waitIdle(t *testing.T, c *Controller) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		n := c.queues["queue"].inflight
		c.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("runner start still in flight")
}

func TestScaleSetGoneIsReportedOnceAndNotRetried(t *testing.T) {
	gone := make(chan [2]any, 4)
	api := jitAPI{err: fmt.Errorf("generate JIT config: %w", scaleset.NotFoundError), calls: make(chan struct{}, 16)}
	c, q := warmSetup(api, func(queue string, id int) { gone <- [2]any{queue, id} })
	c.Reconcile(context.Background())
	waitIdle(t, c)
	select {
	case g := <-gone:
		if g[0] != q.Name || g[1] != 1 {
			t.Fatalf("reported %v", g)
		}
	case <-time.After(time.Second):
		t.Fatal("scale set gone not reported")
	}
	// Until the sessions bring a scale set back, the queue starts nothing.
	for range 3 {
		c.Reconcile(context.Background())
		waitIdle(t, c)
	}
	if n := len(api.calls); n != 1 {
		t.Fatalf("GenerateJIT called %d times, want 1", n)
	}
	if len(gone) != 0 {
		t.Fatal("scale set gone reported twice")
	}
	c.OnScaleSet(q.Name, 2)
	c.mu.Lock()
	id := c.queues[q.Name].scaleSetID
	c.mu.Unlock()
	if id != 2 {
		t.Fatalf("scale set %d after recreation", id)
	}
}

func TestFailedRunnerCreationBacksOff(t *testing.T) {
	api := jitAPI{err: errors.New("HTTP 502"), calls: make(chan struct{}, 16)}
	c, _ := warmSetup(api, func(string, int) { t.Error("a 502 is not a deleted scale set") })
	for range 4 {
		c.Reconcile(context.Background())
		waitIdle(t, c)
	}
	if n := len(api.calls); n != 1 {
		t.Fatalf("GenerateJIT called %d times within the backoff, want 1", n)
	}
	c.mu.Lock()
	qs := c.queues["queue"]
	failures, retryAt, id := qs.failures, qs.retryAt, qs.scaleSetID
	c.mu.Unlock()
	if failures != 1 || !retryAt.After(c.cfg.Now()) || id != 1 {
		t.Fatalf("failures=%d retryAt=%v scaleSetID=%d", failures, retryAt, id)
	}
	// A second start of the same round failing counts once.
	c.provisionFailed(qs, 1, errors.New("HTTP 502"))
	if c.queues["queue"].failures != 1 {
		t.Fatalf("failures=%d after two failures of one round", c.queues["queue"].failures)
	}
}

func TestRunnerCreationBackoffSchedule(t *testing.T) {
	c, _ := warmSetup(jitAPI{calls: make(chan struct{}, 1)}, nil)
	now := time.Now()
	c.cfg.Now = func() time.Time { return now }
	qs := c.queues["queue"]
	for i, want := range []time.Duration{2, 4, 8, 16, 32, 60, 60} {
		c.provisionFailed(qs, 1, errors.New("HTTP 502"))
		if got := qs.retryAt.Sub(now); got != want*time.Second {
			t.Fatalf("failure %d: wait %v, want %v", i+1, got, want*time.Second)
		}
		now = qs.retryAt // next round
	}
	c.provisionSucceeded(qs)
	if qs.failures != 0 || !qs.retryAt.IsZero() {
		t.Fatalf("success kept failures=%d retryAt=%v", qs.failures, qs.retryAt)
	}
}

func TestServedByAddsTheDispatcherImageWithoutMutatingTheClaim(t *testing.T) {
	c := &Controller{cfg: Config{AgentImage: "registry/dispatcher@sha256:abc"}}
	in := claim.Payload{Env: map[string]string{"GOCACHE": "/c"}}
	out := c.servedBy(in)
	if out.Env[DispatcherImageEnv] != "registry/dispatcher@sha256:abc" || out.Env["GOCACHE"] != "/c" || len(in.Env) != 1 {
		t.Fatalf("servedBy: in %v, out %v", in.Env, out.Env)
	}
	if got := (&Controller{}).servedBy(claim.Payload{}); got.Env != nil {
		t.Fatalf("no agent image, env %v", got.Env)
	}
}

// After a restart, a busy pod survives until every queue of its repository
// has its scale set; another repository still unresolved does not block it.
func TestGCKeepsBusyPodsUntilTheirRepositoryIsResolved(t *testing.T) {
	labels := pods.Labels{Prefix: "example.com/ci"}
	p := &testPods{pod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "busy", Annotations: map[string]string{labels.ClaimedAnnotation(): "now"}, Labels: map[string]string{labels.Repo(): "r2", labels.ScaleSetID(): "7", labels.State(): pods.StateBusy}}}}
	c := New(Config{Catalog: &catalog.Catalog{Profiles: map[string]*catalog.Profile{"light": {}}}, Queues: []catalog.Queue{{Name: "a", Repo: "r1", Profile: "light"}, {Name: "b", Repo: "r2", Profile: "light"}, {Name: "c", Repo: "r2", Profile: "light"}}, Pods: p, Mailbox: &testMailbox{}, Metrics: metrics.New(), Labels: labels})
	for _, q := range []string{"", "b"} {
		if q != "" {
			c.OnScaleSet(q, 2)
		}
		if c.GC(context.Background(), false); len(p.deleted) != 0 {
			t.Fatalf("pod of an unresolved repository deleted (resolved: %q): %v", q, p.deleted)
		}
	}
	c.OnScaleSet("c", 3)
	if c.GC(context.Background(), false); len(p.deleted) != 1 {
		t.Fatalf("pod of an unknown scale set kept once its repository resolved: %v", p.deleted)
	}
}
