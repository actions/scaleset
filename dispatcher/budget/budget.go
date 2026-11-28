// Package budget decides how many runner pods can start and where, from the
// per-node places of the catalog and the runner pods already present.
//
// Requests are served one runner at a time, rotating across repositories
// (high priority repositories first), so a repository with a burst of jobs
// does not take every free place. With enforce off the plan grants everything
// and only reports what would have been blocked.
package budget

import (
	"maps"
	"slices"
	"sort"
	"sync"

	corev1 "k8s.io/api/core/v1"

	"github.com/actions/scaleset/dispatcher/catalog"
)

// Demand is the number of runners a queue is missing.
type Demand struct {
	Queue    string
	Repo     string
	Profile  string
	Priority string // high | normal
	// Nodes are the nodes allowed for the queue, preferred first.
	Nodes   []string
	Missing int
}

// Grant allows one runner for a queue. Node is the node chosen when the
// budget is enforced; empty lets the scheduler pick among the allowed nodes.
type Grant struct {
	Queue string
	Node  string
}

// Usage counts runner pods per node.
type Usage map[string]int

// Result of a plan.
type Result struct {
	Grants []Grant
	// Blocked counts, per profile, the runners refused (enforce) or that
	// would have been refused (enforce off).
	Blocked map[string]int
}

// Planner keeps the rotation between plans.
type Planner struct {
	mu     sync.Mutex
	cursor int
}

// Plan distributes free places among demands.
func (p *Planner) Plan(demands []Demand, usage Usage, capacity catalog.Capacity) Result {
	p.mu.Lock()
	start := p.cursor
	p.cursor++
	p.mu.Unlock()

	free := map[string]int{}
	for node, c := range capacity.Nodes {
		if !c.Auto {
			free[node] = c.Places - usage[node]
		}
	}
	room := func(node string) (bool, int) {
		f, capped := free[node]
		if !capped {
			return true, int(^uint(0) >> 1)
		}
		return f > 0, f
	}

	byRepo := map[string][]*Demand{}
	missing := map[*Demand]int{}
	for i := range demands {
		d := &demands[i]
		if d.Missing <= 0 {
			continue
		}
		byRepo[d.Repo] = append(byRepo[d.Repo], d)
		missing[d] = d.Missing
	}
	order := repoOrder(byRepo, start)
	queueCursor := map[string]int{}
	res := Result{Blocked: map[string]int{}}
	exhausted := map[*Demand]bool{}

	for {
		progressed := false
		for _, repo := range order {
			ds := byRepo[repo]
			// One runner per repository per round, from its next queue.
			for k := 0; k < len(ds); k++ {
				d := ds[(queueCursor[repo]+k)%len(ds)]
				if missing[d] == 0 || exhausted[d] {
					continue
				}
				queueCursor[repo] = (queueCursor[repo] + k + 1) % len(ds)
				node, ok := pick(d.Nodes, room)
				if !ok {
					res.Blocked[d.Profile] += missing[d]
					exhausted[d] = true
					if !capacity.Enforce {
						for range missing[d] {
							res.Grants = append(res.Grants, Grant{Queue: d.Queue})
						}
						missing[d] = 0
					}
					progressed = true
					break
				}
				if _, capped := free[node]; capped {
					free[node]--
				}
				g := Grant{Queue: d.Queue}
				if capacity.Enforce {
					g.Node = node
				}
				res.Grants = append(res.Grants, g)
				missing[d]--
				progressed = true
				break
			}
		}
		if !progressed {
			break
		}
	}
	return res
}

// pick returns the first allowed node with room, preferring uncapped order;
// among capped nodes the first with a free place wins (list order is the
// preference order).
func pick(nodes []string, room func(string) (bool, int)) (string, bool) {
	for _, n := range nodes {
		if ok, _ := room(n); ok {
			return n, true
		}
	}
	return "", false
}

// repoOrder lists repositories with high priority first, each class rotated
// by start so the first served repository changes between plans.
func repoOrder(byRepo map[string][]*Demand, start int) []string {
	var high, normal []string
	for _, repo := range slices.Sorted(maps.Keys(byRepo)) {
		if byRepo[repo][0].Priority == "high" {
			high = append(high, repo)
		} else {
			normal = append(normal, repo)
		}
	}
	return append(rotate(high, start), rotate(normal, start)...)
}

func rotate(s []string, n int) []string {
	if len(s) == 0 {
		return s
	}
	n %= len(s)
	return append(slices.Clone(s[n:]), s[:n]...)
}

// UsageFromPods counts the runner pods that hold a place on each node: every
// pod not terminated, scheduled or pinned to a single node.
func UsageFromPods(pods []*corev1.Pod) Usage {
	u := Usage{}
	for _, p := range pods {
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		node := p.Spec.NodeName
		if node == "" {
			node = pinnedNode(p)
		}
		if node != "" {
			u[node]++
		}
	}
	return u
}

// pinnedNode returns the only hostname a pending pod may run on, if any.
func pinnedNode(p *corev1.Pod) string {
	a := p.Spec.Affinity
	if a == nil || a.NodeAffinity == nil || a.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil {
		return ""
	}
	terms := a.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms
	if len(terms) != 1 {
		return ""
	}
	for _, e := range terms[0].MatchExpressions {
		if e.Key == "kubernetes.io/hostname" && e.Operator == corev1.NodeSelectorOpIn && len(e.Values) == 1 {
			return e.Values[0]
		}
	}
	return ""
}

// Free returns the free places per capped node (for metrics).
func Free(usage Usage, capacity catalog.Capacity) map[string]int {
	out := map[string]int{}
	for _, node := range slices.Sorted(maps.Keys(capacity.Nodes)) {
		c := capacity.Nodes[node]
		if !c.Auto {
			out[node] = c.Places - usage[node]
		}
	}
	return out
}

// SortGrants orders grants for stable logs.
func SortGrants(g []Grant) {
	sort.SliceStable(g, func(i, j int) bool { return g[i].Queue < g[j].Queue })
}
