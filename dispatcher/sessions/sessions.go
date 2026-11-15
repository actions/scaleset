// Package sessions keeps one message session open per queue.
//
// For each queue it adopts the scale set of that name (or creates it), opens
// a session and runs the scaleset listener. A session refused because
// another client holds it (an ARC listener still running) is retried with a
// capped exponential backoff; a scale set deleted on GitHub is recreated.
package sessions

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/actions/scaleset"
	"github.com/actions/scaleset/listener"

	"github.com/actions/scaleset/dispatcher/gh"
)

// Session states, exposed as ci_dispatcher_sessions{state}.
const (
	StateStarting = "starting"
	StateActive   = "active"
	StateConflict = "conflict"
	StateError    = "error"
)

// States lists every state, for metrics.
var States = []string{StateStarting, StateActive, StateConflict, StateError}

// Handler receives what the sessions learn. Calls for one queue are never
// concurrent; calls for different queues are.
type Handler interface {
	OnScaleSet(queue string, scaleSetID int)
	OnStatistics(queue string, st *scaleset.RunnerScaleSetStatistic)
	OnJobStarted(queue string, j *scaleset.JobStarted)
	OnJobCompleted(queue string, j *scaleset.JobCompleted)
}

// Spec is the part of a queue the session needs.
type Spec struct {
	Name       string
	Repo       string
	MaxRunners int
}

// Config builds a Pool.
type Config struct {
	API     gh.API
	Handler Handler
	// Owner names the session owner (the dispatcher pod name).
	Owner  string
	Logger *slog.Logger
	// OnState is called on every state change of a queue.
	OnState func(queue, state string)
	// OnError counts failures by reason.
	OnError func(reason string)
	// BackoffMin and BackoffMax bound the retry delay (1s and 60s).
	BackoffMin, BackoffMax time.Duration
}

// Pool runs the sessions.
type Pool struct {
	cfg Config
	wg  sync.WaitGroup
	mu  sync.Mutex
	st  map[string]string
	cur map[string]current
}

// current is the scale set a queue's session is open on.
type current struct {
	id          int
	cancel      context.CancelFunc
	invalidated bool
}

// NewPool builds a Pool.
func NewPool(cfg Config) *Pool {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.BackoffMin == 0 {
		cfg.BackoffMin = time.Second
	}
	if cfg.BackoffMax == 0 {
		cfg.BackoffMax = 60 * time.Second
	}
	return &Pool{cfg: cfg, st: map[string]string{}, cur: map[string]current{}}
}

// Start launches one goroutine per queue. Sessions stop when ctx is done.
func (p *Pool) Start(ctx context.Context, specs []Spec) {
	for _, s := range specs {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			p.run(ctx, s)
		}()
	}
}

// Wait blocks until every session is closed.
func (p *Pool) Wait() { p.wg.Wait() }

// States returns the current state of every queue.
func (p *Pool) States() map[string]string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]string, len(p.st))
	for k, v := range p.st {
		out[k] = v
	}
	return out
}

// Invalidate reports the scale set of a queue as gone on GitHub (a runner
// registration answered not found): the session on that scale set is closed
// and the next round adopts or recreates the scale set by name. A call for
// another scale set than the open one is ignored.
func (p *Pool) Invalidate(queue string, scaleSetID int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c, ok := p.cur[queue]
	if !ok || c.id != scaleSetID || c.invalidated {
		return
	}
	c.invalidated = true
	p.cur[queue] = c
	c.cancel()
}

// takeInvalidated clears the open scale set of a queue and reports whether
// it was invalidated.
func (p *Pool) takeInvalidated(queue string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	c := p.cur[queue]
	delete(p.cur, queue)
	return c.invalidated
}

func (p *Pool) setState(queue, state string) {
	p.mu.Lock()
	changed := p.st[queue] != state
	p.st[queue] = state
	p.mu.Unlock()
	if changed && p.cfg.OnState != nil {
		p.cfg.OnState(queue, state)
	}
}

func (p *Pool) failed(reason string) {
	if p.cfg.OnError != nil {
		p.cfg.OnError(reason)
	}
}

// backoff returns the next delay: doubled, capped, with up to 20% jitter.
func (p *Pool) backoff(prev time.Duration) time.Duration {
	next := prev * 2
	if next < p.cfg.BackoffMin {
		next = p.cfg.BackoffMin
	}
	if next > p.cfg.BackoffMax {
		next = p.cfg.BackoffMax
	}
	return next
}

func jitter(d time.Duration) time.Duration {
	return d + time.Duration(rand.Int64N(int64(d)/5+1)) // #nosec G404 -- retry backoff jitter, not security-sensitive
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(jitter(d))
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (p *Pool) run(ctx context.Context, s Spec) {
	log := p.cfg.Logger.With("queue", s.Name, "repo", s.Repo)
	p.setState(s.Name, StateStarting)
	var delay time.Duration
	for ctx.Err() == nil {
		began := time.Now()
		err := p.once(ctx, s, log)
		if ctx.Err() != nil {
			return
		}
		// A failure after a long healthy session starts the backoff over.
		if time.Since(began) > p.cfg.BackoffMax {
			delay = 0
		}
		if p.takeInvalidated(s.Name) {
			// Backed off like any failure: a scale set that keeps answering
			// not found must not be reopened in a tight loop.
			p.setState(s.Name, StateStarting)
			p.failed("not_found")
			log.Warn("scale set gone, adopting or recreating it")
			delay = p.backoff(delay)
			if !sleep(ctx, delay) {
				return
			}
			continue
		}
		switch {
		case err == nil:
			delay = 0
			continue
		case gh.IsConflict(err):
			p.setState(s.Name, StateConflict)
			p.failed("conflict")
			log.Info("session held by another client, waiting", "error", err)
		case gh.IsNotFound(err):
			// The scale set was deleted on GitHub: the next round creates it.
			p.setState(s.Name, StateStarting)
			p.failed("not_found")
			log.Warn("scale set not found, recreating", "error", err)
			delay = 0
			if !sleep(ctx, p.cfg.BackoffMin) {
				return
			}
			continue
		default:
			p.setState(s.Name, StateError)
			var rl *scaleset.RateLimitError
			if errors.As(err, &rl) {
				p.failed("rate_limit")
				if rl.RetryAfter > delay {
					delay = rl.RetryAfter
				}
			} else {
				p.failed("error")
			}
			log.Warn("session failed", "error", err)
		}
		delay = p.backoff(delay)
		if !sleep(ctx, delay) {
			return
		}
	}
}

// once adopts or creates the scale set, opens a session and listens until
// the session fails or ctx is done.
func (p *Pool) once(ctx context.Context, s Spec, log *slog.Logger) error {
	id, created, err := p.cfg.API.EnsureScaleSet(ctx, s.Repo, s.Name)
	if err != nil {
		return err
	}
	if created {
		log.Info("scale set created", "scaleSetID", id)
	}
	// The session runs under its own context so that Invalidate can close
	// it without stopping the queue.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	p.mu.Lock()
	p.cur[s.Name] = current{id: id, cancel: cancel}
	p.mu.Unlock()
	p.cfg.Handler.OnScaleSet(s.Name, id)

	session, err := p.cfg.API.OpenSession(ctx, s.Repo, id, p.cfg.Owner)
	if err != nil {
		return fmt.Errorf("open session: %w", err)
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if err := session.Close(closeCtx); err != nil {
			log.Warn("session not closed", "error", err)
		}
	}()
	p.setState(s.Name, StateActive)
	log.Info("session open", "scaleSetID", id)

	l, err := listener.New(session, listener.Config{
		ScaleSetID: id,
		MaxRunners: s.MaxRunners,
		Logger:     log.WithGroup("listener"),
	})
	if err != nil {
		return err
	}
	err = l.Run(ctx, &scaler{queue: s.Name, session: session, handler: p.cfg.Handler})
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// scaler adapts listener messages to the Handler.
type scaler struct {
	queue   string
	session gh.Session
	handler Handler
}

func (s *scaler) Scale(ctx context.Context, msg *scaleset.RunnerScaleSetMessage) error {
	if msg == nil {
		return nil
	}
	// Acquire first: a job not acquired stays unassigned. Acquiring an
	// already acquired job is a no-op, so a redelivered message is safe.
	if len(msg.JobAvailableMessages) > 0 {
		ids := make([]int64, 0, len(msg.JobAvailableMessages))
		for _, j := range msg.JobAvailableMessages {
			ids = append(ids, j.RunnerRequestID)
		}
		if _, err := s.session.AcquireJobs(ctx, ids); err != nil {
			return fmt.Errorf("acquire jobs: %w", err)
		}
	}
	for _, j := range msg.JobStartedMessages {
		s.handler.OnJobStarted(s.queue, j)
	}
	for _, j := range msg.JobCompletedMessages {
		s.handler.OnJobCompleted(s.queue, j)
	}
	if msg.Statistics != nil {
		s.handler.OnStatistics(s.queue, msg.Statistics)
	}
	return nil
}
