// Package controller turns the session statistics into runner pods: it
// counts the runners of every queue, asks the budget where new ones may
// start, hands out warm pods or creates cold ones, deletes finished pods and
// collects what is left behind.
package controller

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"maps"
	"math/big"
	"slices"
	"strconv"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/actions/scaleset"

	"github.com/actions/scaleset/dispatcher/budget"
	"github.com/actions/scaleset/dispatcher/catalog"
	"github.com/actions/scaleset/dispatcher/claim"
	"github.com/actions/scaleset/dispatcher/gh"
	"github.com/actions/scaleset/dispatcher/metrics"
	"github.com/actions/scaleset/dispatcher/pods"
	"github.com/actions/scaleset/dispatcher/sessions"
	"github.com/actions/scaleset/dispatcher/warmpool"
)

// Timing of the controller.
const (
	reconcileEvery = 15 * time.Second
	// Backoff of a queue whose runner creations fail.
	provisionRetryMin  = 2 * time.Second
	provisionRetryMax  = 60 * time.Second
	gcEvery            = 5 * time.Minute
	runnerGCEvery      = 15 * time.Minute
	completedGrace     = 60 * time.Second
	unclaimedMaxAge    = 10 * time.Minute
	lostMailboxMinAge  = 30 * time.Second
	warmNotReadyMaxAge = 10 * time.Minute
	scaleDownMinAge    = 2 * time.Minute
	// pendingMaxAge bounds how long a created or assigned pod is counted
	// before the pod cache shows it.
	pendingMaxAge = 2 * time.Minute
	// finishRetryAfter spaces the deletions of the same finished pod.
	finishRetryAfter = 30 * time.Second
	// warmStartupGrace lets the agents of existing warm pods report ready
	// again after a dispatcher start before they are judged stale.
	warmStartupGrace  = warmpool.ReadyTTL + time.Minute
	maxParallelStarts = 8
	runnerNamePrefix  = "ci-"
	warmCacheRoot     = "/mnt/language-cache"
)

// PodAPI is what the controller needs from the pod manager.
type PodAPI interface {
	Managed() []*corev1.Pod
	RunnerPods() []*corev1.Pod
	Get(name string) (*corev1.Pod, bool)
	Create(ctx context.Context, pod *corev1.Pod) (*corev1.Pod, error)
	Delete(ctx context.Context, name string, uid types.UID) error
	Patch(ctx context.Context, name string, uid types.UID, labels, annotations map[string]string) error
}

// Mailbox is what the controller needs from the claim server.
type Mailbox interface {
	Deposit(pod, uid string, p claim.Payload) error
	Pending(pod string) bool
	Ready(pod string) (time.Time, bool)
	Forget(pod string)
	// Delivered reports a configuration already handed to the pod's agent.
	Delivered(pod string) bool
}

// Config builds a Controller.
type Config struct {
	Catalog    *catalog.Catalog
	Queues     []catalog.Queue
	API        gh.API
	Pods       PodAPI
	Mailbox    Mailbox
	Renderer   *pods.Renderer
	Metrics    *metrics.Metrics
	Labels     pods.Labels
	AgentImage string
	Logger     *slog.Logger
	// OnScaleSetGone is called when GitHub answers not found for a scale
	// set while registering a runner: the sessions close it and adopt or
	// recreate the scale set by name (sessions.Pool.Invalidate).
	OnScaleSetGone func(queue string, scaleSetID int)
	// Now replaces the clock (tests).
	Now func() time.Time
}

// pendingPod is a pod created or assigned by the controller that the pod
// cache does not show yet (or not with its new labels). It is counted so the
// next reconciliation neither starts a second runner for the same job nor
// gives its place on the node away.
type pendingPod struct {
	queue      string // queue served; empty for a warm pod being created
	profile    string // warm pod being created
	node       string // node the pod was pinned to, empty if none
	scaleSetID int    // >0: seen once the cached pod carries this scale set
	at         time.Time
}

type queueState struct {
	q          catalog.Queue
	scaleSetID int
	desired    int
	inflight   int
	warmOK     bool
	// failures counts consecutive runner creations that failed; no new
	// runner is started for the queue before retryAt.
	failures int
	retryAt  time.Time
}

// Controller implements sessions.Handler.
type Controller struct {
	cfg     Config
	log     *slog.Logger
	planner budget.Planner
	warm    *warmpool.Pool
	notify  chan struct{}
	sem     chan struct{}

	mu        sync.Mutex
	queues    map[string]*queueState
	byID      map[int]*queueState
	assigned  map[string]time.Time // pod name → assignment time
	sources   map[string]string    // pod name → warm | cold
	warmInfl  map[string]int       // profile → warm pods being created
	pending   map[string]pendingPod
	finishing map[string]time.Time // finished pod → last deletion attempt
	started   time.Time
}

// New builds a Controller.
func New(cfg Config) *Controller {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	c := &Controller{
		cfg:       cfg,
		log:       cfg.Logger,
		notify:    make(chan struct{}, 1),
		sem:       make(chan struct{}, maxParallelStarts),
		queues:    map[string]*queueState{},
		byID:      map[int]*queueState{},
		assigned:  map[string]time.Time{},
		sources:   map[string]string{},
		warmInfl:  map[string]int{},
		pending:   map[string]pendingPod{},
		finishing: map[string]time.Time{},
	}
	c.warm = warmpool.New(cfg.Labels, cfg.Mailbox.Ready)
	for _, q := range cfg.Queues {
		c.queues[q.Name] = &queueState{q: q, desired: q.MinRunners, warmOK: cfg.Catalog.WarmCompatible(q)}
	}
	return c
}

// Warm exposes the warm pool (claim callbacks).
func (c *Controller) Warm() *warmpool.Pool { return c.warm }

func (c *Controller) kick() {
	select {
	case c.notify <- struct{}{}:
	default:
	}
}

func (c *Controller) metricsQueue(q catalog.Queue) metrics.Queue {
	return metrics.Queue{Name: q.Name, Namespace: c.cfg.Catalog.Runtime.Namespace, Repository: q.Repo}
}

// OnScaleSet implements sessions.Handler.
func (c *Controller) OnScaleSet(queue string, id int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	qs, ok := c.queues[queue]
	if !ok {
		return
	}
	if qs.scaleSetID != 0 && qs.scaleSetID != id {
		delete(c.byID, qs.scaleSetID)
	}
	qs.scaleSetID = id
	c.byID[id] = qs
}

// OnStatistics implements sessions.Handler: the wanted runner count is the
// assigned jobs, bounded by maxRunners, with minRunners as a floor.
func (c *Controller) OnStatistics(queue string, st *scaleset.RunnerScaleSetStatistic) {
	c.mu.Lock()
	qs, ok := c.queues[queue]
	if !ok {
		c.mu.Unlock()
		return
	}
	desired := min(max(st.TotalAssignedJobs, qs.q.MinRunners), qs.q.MaxRunners)
	changed := desired != qs.desired
	qs.desired = desired
	q := qs.q
	c.mu.Unlock()
	c.cfg.Metrics.SetStatistics(c.metricsQueue(q), st, desired, q.MinRunners, q.MaxRunners)
	if changed {
		c.kick()
	}
}

// OnJobStarted implements sessions.Handler.
func (c *Controller) OnJobStarted(queue string, j *scaleset.JobStarted) {
	repo := c.repoOf(queue)
	c.cfg.Metrics.JobStarted(repo, j)
	if p, ok := c.cfg.Pods.Get(j.RunnerName); ok && isManaged(p) {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := c.cfg.Pods.Patch(ctx, p.Name, p.UID, map[string]string{c.cfg.Labels.State(): pods.StateBusy}, nil); err != nil && !pods.IsGone(err) {
				c.cfg.Metrics.PodErrors.WithLabelValues("patch_busy").Inc()
			}
		}()
	}
}

// OnJobCompleted implements sessions.Handler. The runner pod exits by itself
// after its job; it is deleted after a grace period in case it does not.
func (c *Controller) OnJobCompleted(queue string, j *scaleset.JobCompleted) {
	c.cfg.Metrics.JobCompleted(c.repoOf(queue), j)
	if j.RunnerName == "" {
		return
	}
	name := j.RunnerName
	time.AfterFunc(completedGrace, func() {
		p, ok := c.cfg.Pods.Get(name)
		if !ok || !isManaged(p) {
			return
		}
		c.deletePod(context.Background(), p, "completed")
	})
}

func (c *Controller) repoOf(queue string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if qs, ok := c.queues[queue]; ok {
		return qs.q.Repo
	}
	return ""
}

func isManaged(p *corev1.Pod) bool {
	return p.Labels[pods.LabelManagedBy] == pods.ManagedByValue
}

// OnPod is the pod informer callback: finished pods are deleted, deleted
// pods are forgotten, and every change triggers a reconciliation.
func (c *Controller) OnPod(p *corev1.Pod, deleted bool) {
	if !isManaged(p) {
		c.kick() // an ARC pod changed the node usage
		return
	}
	if deleted {
		c.cfg.Mailbox.Forget(p.Name)
		c.warm.Release(p.Name)
		c.mu.Lock()
		delete(c.assigned, p.Name)
		delete(c.sources, p.Name)
		delete(c.pending, p.Name)
		delete(c.finishing, p.Name)
		c.mu.Unlock()
		c.kick()
		return
	}
	if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
		// Every status update of a finished pod lands here: delete it once,
		// and again only if it is still there a while later.
		now := c.cfg.Now()
		c.mu.Lock()
		last, busy := c.finishing[p.Name]
		if busy && now.Sub(last) < finishRetryAfter {
			c.mu.Unlock()
			return
		}
		c.finishing[p.Name] = now
		c.mu.Unlock()
		go c.deletePod(context.Background(), p, "finished")
	}
}

// OnClaimed records a configuration delivered to an agent.
func (c *Controller) OnClaimed(pod, uid string, _ time.Duration) {
	c.mu.Lock()
	at, ok := c.assigned[pod]
	source := c.sources[pod]
	c.mu.Unlock()
	if p, found := c.cfg.Pods.Get(pod); found && ok {
		c.cfg.Metrics.ObserveClaim(p.Labels[c.cfg.Labels.Profile()], source, c.cfg.Now().Sub(at))
	}
	go func() {
		// The annotation survives a dispatcher restart; until it is set the
		// mailbox (Delivered) protects the pod from the garbage collector.
		ann := map[string]string{c.cfg.Labels.ClaimedAnnotation(): c.cfg.Now().UTC().Format(time.RFC3339)}
		for attempt, delay := 0, time.Second; attempt < 5; attempt, delay = attempt+1, 2*delay {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err := c.cfg.Pods.Patch(ctx, pod, types.UID(uid), nil, ann)
			cancel()
			if err == nil || pods.IsGone(err) {
				return
			}
			c.cfg.Metrics.PodErrors.WithLabelValues("patch_claimed").Inc()
			time.Sleep(delay)
		}
	}()
}

// Run reconciles until ctx is done.
func (c *Controller) Run(ctx context.Context) {
	tick := time.NewTicker(reconcileEvery)
	defer tick.Stop()
	gc := time.NewTicker(gcEvery)
	defer gc.Stop()
	runnerGC := time.NewTicker(runnerGCEvery)
	defer runnerGC.Stop()
	c.mu.Lock()
	c.started = c.cfg.Now()
	c.mu.Unlock()
	c.GC(ctx, true)
	for {
		c.Reconcile(ctx)
		select {
		case <-ctx.Done():
			return
		case <-c.notify:
		case <-tick.C:
		case <-gc.C:
			c.GC(ctx, false)
		case <-runnerGC.C:
			c.GCRunners(ctx)
		}
	}
}

// queueRunners counts the live runner pods of every scale set.
func (c *Controller) queueRunners(all []*corev1.Pod) map[int][]*corev1.Pod {
	out := map[int][]*corev1.Pod{}
	for _, p := range all {
		if pods.Terminated(p) {
			continue
		}
		id, err := strconv.Atoi(p.Labels[c.cfg.Labels.ScaleSetID()])
		if err != nil {
			continue
		}
		out[id] = append(out[id], p)
	}
	return out
}

// Reconcile computes the missing runners and starts them.
func (c *Controller) Reconcile(ctx context.Context) {
	now := c.cfg.Now()
	managed := c.cfg.Pods.Managed()
	byID := c.queueRunners(managed)
	runnerPods := c.cfg.Pods.RunnerPods()
	usage := budget.UsageFromPods(runnerPods)
	// Pending pods are matched against the same snapshot as byID and usage:
	// the live cache may already show a pod the snapshot misses.
	snapshot := make(map[string]*corev1.Pod, len(managed)+len(runnerPods))
	for _, p := range runnerPods {
		snapshot[p.Name] = p
	}
	for _, p := range managed {
		snapshot[p.Name] = p
	}

	type surplus struct {
		qs   *queueState
		pods []*corev1.Pod
		n    int
	}
	var demands []budget.Demand
	var scaleDown []surplus

	c.mu.Lock()
	pendQueue, pendWarm := c.pendingCounts(now, snapshot, usage)
	for _, qs := range c.queues {
		if qs.scaleSetID == 0 {
			continue
		}
		pend := pendQueue[qs.q.Name]
		if now.Before(qs.retryAt) && qs.desired > len(byID[qs.scaleSetID])+qs.inflight+pend {
			continue
		}
		active := len(byID[qs.scaleSetID]) + qs.inflight + pend
		switch {
		case qs.desired > active:
			demands = append(demands, budget.Demand{
				Queue: qs.q.Name, Repo: qs.q.Repo, Profile: qs.q.Profile, Priority: qs.q.Priority,
				Nodes: preferred(qs.q.Spec), Missing: qs.desired - active,
			})
		case qs.desired < active && qs.inflight == 0 && pend == 0:
			scaleDown = append(scaleDown, surplus{qs: qs, pods: byID[qs.scaleSetID], n: active - qs.desired})
		}
	}
	c.mu.Unlock()

	// Assign already-running warm pods before charging the budget for new
	// pods. They already occupy a place, including when the node is full.
	slices.SortStableFunc(demands, func(a, b budget.Demand) int {
		if a.Priority == "high" && b.Priority != "high" {
			return -1
		}
		if a.Priority != "high" && b.Priority == "high" {
			return 1
		}
		return 0
	})
	for progress := true; progress; {
		progress = false
		served := map[string]bool{}
		for i := range demands {
			d := &demands[i]
			if d.Missing == 0 || served[d.Repo] {
				continue
			}
			c.mu.Lock()
			qs := c.queues[d.Queue]
			q, id, warmOK := qs.q, qs.scaleSetID, qs.warmOK
			c.mu.Unlock()
			if !warmOK {
				continue
			}
			{
				pod, ok := c.warm.Take(managed, q.Profile, q.Spec.Nodes, now)
				if !ok {
					continue
				}
				progress = true
				served[d.Repo] = true
				d.Missing--
				c.mu.Lock()
				qs.inflight++
				c.mu.Unlock()
				c.start(ctx, func() {
					defer func() {
						c.mu.Lock()
						qs.inflight--
						c.mu.Unlock()
						c.kick()
					}()
					if err := c.assignWarm(ctx, q, id, pod); err != nil {
						c.warm.Release(pod.Name)
						c.log.Warn("warm assignment failed", "queue", q.Name, "pod", pod.Name, "error", err)
						c.provisionFailed(qs, id, err)
						return
					}
					c.provisionSucceeded(qs)
				})
			}
		}
	}

	capacity := c.cfg.Catalog.Capacity
	res := c.planner.Plan(demands, usage, capacity)
	for _, g := range res.Grants {
		if g.Node != "" {
			usage[g.Node]++
		}
	}

	// Warm pods refill with what is left, after real jobs.
	var warmDemands []budget.Demand
	for _, name := range slices.Sorted(maps.Keys(c.cfg.Catalog.Profiles)) {
		p := c.cfg.Catalog.Profiles[name]
		counts := c.warm.Count(managed, name, now)
		c.cfg.Metrics.WarmPods.WithLabelValues(name, "ready").Set(float64(counts.Ready))
		c.cfg.Metrics.WarmPods.WithLabelValues(name, "starting").Set(float64(counts.Pending))
		c.mu.Lock()
		missing := p.Warm - counts.Total() - c.warmInfl[name] - pendWarm[name]
		c.mu.Unlock()
		if missing > 0 {
			spec := c.cfg.Catalog.ProfileSpec(name)
			warmDemands = append(warmDemands, budget.Demand{
				Queue: "warm:" + name, Repo: "warm:" + name, Profile: name, Nodes: preferred(spec), Missing: missing,
			})
		}
	}
	warmRes := c.planner.Plan(warmDemands, usage, capacity)

	blocked := map[string]int{}
	for k, v := range res.Blocked {
		blocked[k] += v
	}
	for _, name := range slices.Sorted(maps.Keys(c.cfg.Catalog.Profiles)) {
		c.cfg.Metrics.BudgetBlocked.WithLabelValues(name).Set(float64(blocked[name]))
	}
	for node, free := range budget.Free(usage, capacity) {
		c.cfg.Metrics.BudgetFree.WithLabelValues(node).Set(float64(free))
	}

	for _, g := range res.Grants {
		c.mu.Lock()
		qs := c.queues[g.Queue]
		qs.inflight++
		c.mu.Unlock()
		c.start(ctx, func() { c.provision(ctx, qs, g.Node) })
	}
	for _, g := range warmRes.Grants {
		profile := g.Queue[len("warm:"):]
		c.mu.Lock()
		c.warmInfl[profile]++
		c.mu.Unlock()
		c.start(ctx, func() { c.createWarm(ctx, profile, g.Node) })
	}
	for _, s := range scaleDown {
		c.scaleDown(ctx, s.qs, s.pods, s.n, now)
	}
}

// pendingCounts drops the pending pods the snapshot shows (or too old) and
// counts the others per queue and per warm profile. A pending pod pinned to a
// node and not yet cached is charged on that node. Called with c.mu held.
func (c *Controller) pendingCounts(now time.Time, snapshot map[string]*corev1.Pod, usage map[string]int) (map[string]int, map[string]int) {
	perQueue, perWarm := map[string]int{}, map[string]int{}
	for name, pp := range c.pending {
		p, cached := snapshot[name]
		seen := cached && (pp.scaleSetID == 0 || p.Labels[c.cfg.Labels.ScaleSetID()] == strconv.Itoa(pp.scaleSetID))
		if seen || now.Sub(pp.at) > pendingMaxAge {
			delete(c.pending, name)
			continue
		}
		if pp.queue != "" {
			perQueue[pp.queue]++
		} else {
			perWarm[pp.profile]++
		}
		if !cached && pp.node != "" && usage != nil {
			usage[pp.node]++
		}
	}
	return perQueue, perWarm
}

// forgetPod drops the controller's records of a pod that will not run.
func (c *Controller) forgetPod(name string) {
	c.mu.Lock()
	delete(c.assigned, name)
	delete(c.sources, name)
	delete(c.pending, name)
	c.mu.Unlock()
}

func (c *Controller) addPending(name string, pp pendingPod) {
	pp.at = c.cfg.Now()
	c.mu.Lock()
	c.pending[name] = pp
	c.mu.Unlock()
}

// preferred lists the allowed nodes, preferred ones first.
func preferred(s catalog.PodSpec) []string {
	var out []string
	for _, n := range s.PreferNodes {
		if slices.Contains(s.Nodes, n) {
			out = append(out, n)
		}
	}
	for _, n := range s.Nodes {
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

func (c *Controller) start(ctx context.Context, fn func()) {
	go func() {
		select {
		case c.sem <- struct{}{}:
		case <-ctx.Done():
			fn() // releases the in-flight counter without starting anything
			return
		}
		defer func() { <-c.sem }()
		fn()
	}()
}

// provision gives one runner to a queue: a warm pod when one is ready,
// otherwise a cold pod created with its configuration already deposited.
func (c *Controller) provision(ctx context.Context, qs *queueState, node string) {
	defer func() {
		c.mu.Lock()
		qs.inflight--
		c.mu.Unlock()
		c.kick()
	}()
	if ctx.Err() != nil {
		return
	}
	c.mu.Lock()
	q, id, warmOK := qs.q, qs.scaleSetID, qs.warmOK
	c.mu.Unlock()

	if warmOK && c.cfg.Catalog.Profiles[q.Profile].Warm > 0 {
		allowed := q.Spec.Nodes
		if node != "" {
			allowed = []string{node}
		}
		if p, ok := c.warm.Take(c.cfg.Pods.Managed(), q.Profile, allowed, c.cfg.Now()); ok {
			// The reservation is kept on success: the pod cache may still show
			// the pod as warm until the label patch arrives, and another queue
			// must not take it meanwhile. OnPod releases it on deletion.
			err := c.assignWarm(ctx, q, id, p)
			if err == nil {
				c.provisionSucceeded(qs)
				c.kick() // refill the reserve
				return
			}
			c.warm.Release(p.Name)
			c.log.Warn("warm assignment failed, creating a cold pod", "queue", q.Name, "pod", p.Name, "error", err)
			if gh.IsNotFound(err) {
				c.provisionFailed(qs, id, err)
				return
			}
		}
	}
	if err := c.createCold(ctx, q, id, node); err != nil {
		c.log.Warn("cold pod not created", "queue", q.Name, "error", err)
		c.provisionFailed(qs, id, err)
		return
	}
	c.provisionSucceeded(qs)
}

// provisionFailed backs the queue off. A scale set GitHub no longer knows
// is dropped until the sessions adopt or recreate one (OnScaleSet).
func (c *Controller) provisionFailed(qs *queueState, id int, err error) {
	c.mu.Lock()
	now := c.cfg.Now()
	// Starts granted in the same round fail together: they count once.
	if !now.Before(qs.retryAt) {
		qs.failures++
	}
	wait := provisionRetryMax
	if qs.failures <= 5 {
		wait = min(provisionRetryMin<<(qs.failures-1), provisionRetryMax)
	}
	qs.retryAt = now.Add(wait)
	gone := gh.IsNotFound(err) && id != 0 && qs.scaleSetID == id
	if gone {
		delete(c.byID, id)
		qs.scaleSetID = 0
	}
	queue := qs.q.Name
	c.mu.Unlock()
	if gone {
		c.log.Warn("scale set gone on GitHub, asking the session to recreate it", "queue", queue, "scaleSetID", id)
		if c.cfg.OnScaleSetGone != nil {
			c.cfg.OnScaleSetGone(queue, id)
		}
	}
}

func (c *Controller) provisionSucceeded(qs *queueState) {
	c.mu.Lock()
	qs.failures = 0
	qs.retryAt = time.Time{}
	c.mu.Unlock()
}

func (c *Controller) runnerName(profile string) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 5)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			panic(err)
		}
		b[i] = alphabet[n.Int64()]
	}
	return runnerNamePrefix + profile + "-" + string(b)
}

func (c *Controller) request(name string, q *catalog.Queue, profile string, spec catalog.PodSpec, node string, id int) pods.Request {
	req := pods.Request{
		Name:       name,
		Namespace:  c.cfg.Catalog.Runtime.Namespace,
		Queue:      q,
		Profile:    profile,
		Spec:       spec,
		ScaleSetID: id,
		ClaimURL:   c.cfg.Catalog.Runtime.ClaimURL,
		AgentImage: c.cfg.AgentImage,
		Labels:     c.cfg.Labels,
	}
	if node != "" {
		req.Nodes = []string{node}
	}
	return req
}

func (c *Controller) createCold(ctx context.Context, q catalog.Queue, id int, node string) error {
	name := c.runnerName(q.Profile)
	pod, err := c.cfg.Renderer.Render(c.request(name, &q, q.Profile, q.Spec, node, id))
	if err != nil {
		c.cfg.Metrics.PodErrors.WithLabelValues("render").Inc()
		return err
	}
	// Registered as assigned before the runner exists on GitHub, so the
	// runner garbage collector never sees it without a known pod name.
	now := c.cfg.Now()
	c.mu.Lock()
	c.assigned[name] = now
	c.sources[name] = "cold"
	c.mu.Unlock()
	forget := func() {
		c.mu.Lock()
		delete(c.assigned, name)
		delete(c.sources, name)
		c.mu.Unlock()
	}
	jit, err := c.cfg.API.GenerateJIT(ctx, q.Repo, id, name)
	if err != nil {
		forget()
		c.cfg.Metrics.PodErrors.WithLabelValues("jit").Inc()
		return err
	}
	pod.Annotations[c.cfg.Labels.RunnerIDAnnotation()] = strconv.FormatInt(jit.RunnerID, 10)
	pod.Annotations[c.cfg.Labels.AssignedAnnotation()] = now.UTC().Format(time.RFC3339)
	created, err := c.cfg.Pods.Create(ctx, pod)
	if err != nil {
		c.cfg.Metrics.PodErrors.WithLabelValues("create").Inc()
		c.removeRunner(q.Repo, jit.RunnerID)
		forget()
		return fmt.Errorf("create pod %s: %w", name, err)
	}
	c.addPending(name, pendingPod{queue: q.Name, node: node})
	if err := c.cfg.Mailbox.Deposit(name, string(created.UID), c.servedBy(claim.Payload{JITConfig: jit.Config, Repo: q.Repo})); err != nil {
		// The pod was deleted meanwhile: its runner would stay registered.
		c.removeRunner(q.Repo, jit.RunnerID)
		c.forgetPod(name)
		return err
	}
	c.cfg.Metrics.PodsCreated.WithLabelValues(q.Profile, "cold").Inc()
	c.log.Info("cold runner created", "queue", q.Name, "pod", name, "node", node)
	return nil
}

func (c *Controller) createWarm(ctx context.Context, profile, node string) {
	defer func() {
		c.mu.Lock()
		c.warmInfl[profile]--
		c.mu.Unlock()
	}()
	if ctx.Err() != nil {
		return
	}
	spec := c.cfg.Catalog.ProfileSpec(profile)
	name := c.runnerName(profile)
	pod, err := c.cfg.Renderer.Render(c.request(name, nil, profile, spec, node, 0))
	if err != nil {
		c.cfg.Metrics.PodErrors.WithLabelValues("render").Inc()
		c.log.Warn("warm pod not rendered", "profile", profile, "error", err)
		return
	}
	if _, err := c.cfg.Pods.Create(ctx, pod); err != nil {
		c.cfg.Metrics.PodErrors.WithLabelValues("create").Inc()
		c.log.Warn("warm pod not created", "profile", profile, "error", err)
		return
	}
	c.addPending(name, pendingPod{profile: profile, node: node})
	c.cfg.Metrics.PodsCreated.WithLabelValues(profile, "warm").Inc()
	c.log.Info("warm pod created", "profile", profile, "pod", name)
}

// assignWarm registers a runner named after the warm pod, labels the pod
// with its repository and deposits the configuration.
func (c *Controller) assignWarm(ctx context.Context, q catalog.Queue, id int, p *corev1.Pod) error {
	jit, err := c.cfg.API.GenerateJIT(ctx, q.Repo, id, p.Name)
	if err != nil {
		c.cfg.Metrics.PodErrors.WithLabelValues("jit").Inc()
		return err
	}
	now := c.cfg.Now()
	ann := map[string]string{
		c.cfg.Labels.QueueAnnotation():    q.Name,
		c.cfg.Labels.RunnerIDAnnotation(): strconv.FormatInt(jit.RunnerID, 10),
		c.cfg.Labels.AssignedAnnotation(): now.UTC().Format(time.RFC3339),
	}
	if err := c.cfg.Pods.Patch(ctx, p.Name, p.UID, pods.AssignedLabels(c.cfg.Labels, q.Repo, id), ann); err != nil {
		c.cfg.Metrics.PodErrors.WithLabelValues("patch_assign").Inc()
		c.removeRunner(q.Repo, jit.RunnerID)
		return err
	}
	c.mu.Lock()
	c.assigned[p.Name] = now
	c.sources[p.Name] = "warm"
	c.mu.Unlock()
	// The cache shows the pod as warm until the label patch arrives.
	c.addPending(p.Name, pendingPod{queue: q.Name, scaleSetID: id})
	payload := claim.Payload{JITConfig: jit.Config, Repo: q.Repo}
	for _, nc := range q.Spec.Caches {
		if nc.Type != catalog.CacheLanguage {
			continue
		}
		base := warmCacheRoot + "/language-caches/" + q.Repo
		payload.Preflight = &claim.Preflight{Root: warmCacheRoot, ServerNode: nc.ServerNode, Marker: nc.Marker}
		payload.StateDir = base + "/pods/" + string(p.UID)
		if q.Spec.CacheProfile != catalog.CacheProfileLocal {
			payload.Env = map[string]string{
				"GOCACHE":      base + "/go-build",
				"GOMODCACHE":   base + "/go-mod",
				"UV_CACHE_DIR": base + "/uv",
			}
		}
		break
	}
	if err := c.cfg.Mailbox.Deposit(p.Name, string(p.UID), c.servedBy(payload)); err != nil {
		// The pod was deleted meanwhile: its runner would stay registered.
		c.removeRunner(q.Repo, jit.RunnerID)
		c.forgetPod(p.Name)
		return err
	}
	c.log.Info("warm runner assigned", "queue", q.Name, "pod", p.Name, "node", p.Spec.NodeName)
	return nil
}

// scaleDown removes idle surplus runners: registered, not busy and assigned
// for a while (a runner just assigned may be about to receive its job).
func (c *Controller) scaleDown(ctx context.Context, qs *queueState, ps []*corev1.Pod, n int, now time.Time) {
	for _, p := range ps {
		if n == 0 {
			return
		}
		if p.Labels[c.cfg.Labels.State()] != pods.StateAssigned {
			continue
		}
		at, err := time.Parse(time.RFC3339, p.Annotations[c.cfg.Labels.AssignedAnnotation()])
		if err != nil || now.Sub(at) < scaleDownMinAge {
			continue
		}
		if id, err := strconv.ParseInt(p.Annotations[c.cfg.Labels.RunnerIDAnnotation()], 10, 64); err == nil {
			rmCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			err := c.cfg.API.RemoveRunner(rmCtx, qs.q.Repo, id)
			cancel()
			if gh.IsJobStillRunning(err) {
				continue
			}
			if err != nil {
				c.cfg.Metrics.PodErrors.WithLabelValues("remove_runner").Inc()
				continue
			}
		}
		c.deletePod(ctx, p, "scale_down")
		n--
	}
}

func (c *Controller) removeRunner(repo string, id int64) {
	if id == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := c.cfg.API.RemoveRunner(ctx, repo, id); err != nil && !gh.IsJobStillRunning(err) {
		c.cfg.Metrics.PodErrors.WithLabelValues("remove_runner").Inc()
		c.log.Warn("runner not removed", "repo", repo, "runnerID", id, "error", err)
	}
}

// deletePod deletes a pod; a pod that never received its configuration also
// gets its GitHub runner registration removed.
func (c *Controller) deletePod(ctx context.Context, p *corev1.Pod, reason string) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if !c.claimed(p) {
		if id, err := strconv.ParseInt(p.Annotations[c.cfg.Labels.RunnerIDAnnotation()], 10, 64); err == nil {
			c.removeRunner(p.Labels[c.cfg.Labels.Repo()], id)
		}
	}
	if err := c.cfg.Pods.Delete(ctx, p.Name, p.UID); err != nil {
		c.cfg.Metrics.PodErrors.WithLabelValues("delete").Inc()
		c.log.Warn("pod not deleted", "pod", p.Name, "reason", reason, "error", err)
		return
	}
	c.log.Info("pod deleted", "pod", p.Name, "reason", reason)
}

// claimed reports a pod whose agent received its configuration: annotated,
// or known to the mailbox while the annotation patch is still on its way.
func (c *Controller) claimed(p *corev1.Pod) bool {
	if _, ok := p.Annotations[c.cfg.Labels.ClaimedAnnotation()]; ok {
		return true
	}
	return c.cfg.Mailbox.Delivered(p.Name)
}

// GC deletes the managed pods nobody will use: pods of an unknown queue,
// assigned pods whose configuration was lost or never claimed, warm pods that
// never became ready.
func (c *Controller) GC(ctx context.Context, startup bool) {
	now := c.cfg.Now()
	c.mu.Lock()
	known := map[int]bool{}
	for id := range c.byID {
		known[id] = true
	}
	// The first GC runs before any queue has its scale set ID: a pod is only
	// "unknown" once every queue of its repository has its ID, so a restart
	// keeps the running pods, and one failing repository does not stop the
	// cleanup of the others. A repository absent from the catalog (removed, or
	// dropped when its visibility stays unknown) is ready, but its busy pods
	// finish their job.
	repoReady := map[string]bool{}
	for _, qs := range c.queues {
		ok, seen := repoReady[qs.q.Repo]
		repoReady[qs.q.Repo] = qs.scaleSetID != 0 && (ok || !seen)
	}
	c.mu.Unlock()

	for _, p := range c.cfg.Pods.Managed() {
		if pods.Terminated(p) {
			continue
		}
		state := p.Labels[c.cfg.Labels.State()]
		if state == pods.StateWarm {
			continue
		}
		id, err := strconv.Atoi(p.Labels[c.cfg.Labels.ScaleSetID()])
		if err == nil && !known[id] {
			if ready, inCatalog := repoReady[p.Labels[c.cfg.Labels.Repo()]]; ready || (!inCatalog && state != pods.StateBusy) {
				c.gcDelete(ctx, p, "unknown_queue")
				continue
			}
		}
		if state != pods.StateAssigned {
			continue
		}
		if c.claimed(p) {
			continue
		}
		at, err := time.Parse(time.RFC3339, p.Annotations[c.cfg.Labels.AssignedAnnotation()])
		if err != nil {
			at = p.CreationTimestamp.Time
		}
		age := now.Sub(at)
		switch {
		case age > unclaimedMaxAge:
			c.gcDelete(ctx, p, "unclaimed")
		case age > lostMailboxMinAge && !c.cfg.Mailbox.Pending(p.Name):
			// The configuration is not in memory (dispatcher restarted):
			// the agent will never get it.
			c.gcDelete(ctx, p, "lost_config")
		}
	}
	c.mu.Lock()
	started := c.started
	c.mu.Unlock()
	// Right after a start the ready reports are not known yet: every warm
	// pod would look stale.
	if started.IsZero() || now.Sub(started) >= warmStartupGrace {
		for _, p := range c.warm.Stale(c.cfg.Pods.Managed(), warmNotReadyMaxAge, now) {
			c.gcDelete(ctx, p, "warm_not_ready")
		}
	}
	if startup {
		c.GCRunners(ctx)
	}
}

func (c *Controller) gcDelete(ctx context.Context, p *corev1.Pod, reason string) {
	c.cfg.Metrics.GCRemoved.WithLabelValues("pod_" + reason).Inc()
	c.deletePod(ctx, p, reason)
}

// GCRunners removes the offline GitHub runners named ci-* that have no pod
// (pod deleted before its runner could unregister).
func (c *Controller) GCRunners(ctx context.Context) {
	podNames := map[string]bool{}
	for _, p := range c.cfg.Pods.Managed() {
		podNames[p.Name] = true
	}
	repos := map[string]bool{}
	c.mu.Lock()
	// A cold runner is registered just before its pod is created.
	for name := range c.assigned {
		podNames[name] = true
	}
	for _, qs := range c.queues {
		repos[qs.q.Repo] = true
	}
	c.mu.Unlock()
	for _, repo := range slices.Sorted(maps.Keys(repos)) {
		if ctx.Err() != nil {
			return
		}
		runners, err := c.cfg.API.ListRunners(ctx, repo)
		if err != nil {
			c.log.Warn("runners not listed", "repo", repo, "error", err)
			continue
		}
		for _, r := range runners {
			if !isDispatcherRunner(r.Name) || r.Status != "offline" || r.Busy || podNames[r.Name] || c.knownNow(r.Name) {
				continue
			}
			if err := c.cfg.API.RemoveRunner(ctx, repo, r.ID); err == nil {
				c.cfg.Metrics.GCRemoved.WithLabelValues("runner").Inc()
				c.log.Info("orphan runner removed", "repo", repo, "runner", r.Name)
			}
		}
	}
}

// knownNow re-checks a runner name right before its removal: the snapshot
// taken before listing every repository may predate a runner created since.
func (c *Controller) knownNow(name string) bool {
	c.mu.Lock()
	_, assigned := c.assigned[name]
	_, pending := c.pending[name]
	c.mu.Unlock()
	if assigned || pending {
		return true
	}
	_, cached := c.cfg.Pods.Get(name)
	return cached
}

func isDispatcherRunner(name string) bool {
	return len(name) > len(runnerNamePrefix) && name[:len(runnerNamePrefix)] == runnerNamePrefix
}

var _ sessions.Handler = (*Controller)(nil)

// DispatcherImageEnv names, in the runner environment, the image of the
// dispatcher that served the job: an acceptance job proves with it that it
// was served by the candidate under test, not by a previous dispatcher. The
// agent drops CI_DISPATCHER_* variables, hence the name.
const DispatcherImageEnv = "DISPATCHER_IMAGE"

// servedBy adds the dispatcher image to a claim, cold and warm pods alike.
func (c *Controller) servedBy(p claim.Payload) claim.Payload {
	if c.cfg.AgentImage == "" {
		return p
	}
	env := maps.Clone(p.Env)
	if env == nil {
		env = map[string]string{}
	}
	env[DispatcherImageEnv] = c.cfg.AgentImage
	p.Env = env
	return p
}
