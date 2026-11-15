// Package warmpool keeps ready runner pods per profile, without a
// repository, and hands the oldest ready one to a queue that needs a runner.
//
// A warm pod is ready when its agent has called POST /v1/ready recently: the
// image is pulled, the init containers have run and the agent waits for a
// configuration. Assigning it only costs a JIT registration and a label
// patch, instead of a full pod start.
package warmpool

import (
	"slices"
	"sort"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/actions/scaleset/dispatcher/pods"
)

// ReadyTTL is how recent the last ready call must be. Agents call it before
// every long poll, so a live agent is never older than one poll.
const ReadyTTL = 2 * time.Minute

// ReadyFunc returns when a pod last reported ready.
type ReadyFunc func(pod string) (time.Time, bool)

// Pool tracks the warm pods being handed out, so two queues never take the
// same pod.
type Pool struct {
	labels   pods.Labels
	ready    ReadyFunc
	mu       sync.Mutex
	reserved map[string]bool
}

// New builds a Pool.
func New(l pods.Labels, ready ReadyFunc) *Pool {
	return &Pool{labels: l, ready: ready, reserved: map[string]bool{}}
}

// Counts of the warm pods of one profile.
type Counts struct {
	Ready   int
	Pending int
}

// Total is every warm pod that will be ready.
func (c Counts) Total() int { return c.Ready + c.Pending }

func (p *Pool) isWarm(pod *corev1.Pod, profile string) bool {
	return pod.Labels[p.labels.State()] == pods.StateWarm &&
		pod.Labels[p.labels.Profile()] == profile &&
		!pods.Terminated(pod)
}

func (p *Pool) isReady(pod *corev1.Pod, now time.Time) bool {
	if pod.Status.Phase != corev1.PodRunning {
		return false
	}
	t, ok := p.ready(pod.Name)
	return ok && now.Sub(t) <= ReadyTTL
}

// Count returns the warm pods of a profile, ready or still starting.
// Reserved pods are being assigned and no longer count.
func (p *Pool) Count(all []*corev1.Pod, profile string, now time.Time) Counts {
	p.mu.Lock()
	defer p.mu.Unlock()
	var c Counts
	for _, pod := range all {
		if !p.isWarm(pod, profile) || p.reserved[pod.Name] {
			continue
		}
		if p.isReady(pod, now) {
			c.Ready++
		} else {
			c.Pending++
		}
	}
	return c
}

// Take reserves the oldest ready warm pod of a profile running on one of the
// allowed nodes (any node when allowed is empty). The caller must Release it
// once assigned or on failure.
func (p *Pool) Take(all []*corev1.Pod, profile string, allowed []string, now time.Time) (*corev1.Pod, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var candidates []*corev1.Pod
	for _, pod := range all {
		if !p.isWarm(pod, profile) || p.reserved[pod.Name] || !p.isReady(pod, now) {
			continue
		}
		if len(allowed) > 0 && !slices.Contains(allowed, pod.Spec.NodeName) {
			continue
		}
		candidates = append(candidates, pod)
	}
	if len(candidates) == 0 {
		return nil, false
	}
	sort.Slice(candidates, func(i, j int) bool {
		a, b := candidates[i].CreationTimestamp, candidates[j].CreationTimestamp
		if a.Equal(&b) {
			return candidates[i].Name < candidates[j].Name
		}
		return a.Before(&b)
	})
	pod := candidates[0]
	p.reserved[pod.Name] = true
	return pod, true
}

// Release ends a reservation.
func (p *Pool) Release(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.reserved, name)
}

// Stale returns the warm pods that never became ready within maxAge (image
// pull failure, unschedulable): the garbage collector deletes them.
func (p *Pool) Stale(all []*corev1.Pod, maxAge time.Duration, now time.Time) []*corev1.Pod {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []*corev1.Pod
	for _, pod := range all {
		if pod.Labels[p.labels.State()] != pods.StateWarm || p.reserved[pod.Name] || pods.Terminated(pod) {
			continue
		}
		if now.Sub(pod.CreationTimestamp.Time) < maxAge {
			continue
		}
		if t, ok := p.ready(pod.Name); ok && now.Sub(t) <= ReadyTTL {
			continue
		}
		out = append(out, pod)
	}
	return out
}
