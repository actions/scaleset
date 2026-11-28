package catalog

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"sort"
	"strings"
)

// Queue is one GitHub runner scale set served by the dispatcher: a
// repository and the profile actually used to build its pods.
type Queue struct {
	// Name is the scale set name, which is also the runs-on label.
	Name string
	// Repo is the exact GitHub repository name.
	Repo string
	// RequestedProfile is the profile the repository asked for; it gives the
	// queue name. Profile is the one used for pods: a public repository is
	// always served by the public profile, whatever it asked for, so that
	// existing workflow labels keep working.
	RequestedProfile string
	Profile          string
	Trust            string
	Priority         string
	MaxRunners       int
	MinRunners       int
	// Pod settings after every override.
	Spec PodSpec
}

// PodSpec is the fully resolved pod configuration of a queue.
type PodSpec struct {
	Template           string
	Image              string
	Resources          Resources
	DinD               *DinD
	DockerDataLimit    string
	WorkLimit          string
	Caches             []NamedCache
	Externals          *Externals
	DockerConfigSecret string
	InitImage          string
	Nodes              []string
	PreferNodes        []string
	NodeSelector       map[string]string
	Tolerations        []Toleration
	ImagePullSecrets   []string
	ServiceAccountName string
	CacheProfile       string
	Env                map[string]string
	Annotations        map[string]string
	Trust              string
}

// NamedCache is a cache with its catalog name.
type NamedCache struct {
	Name string
	Cache
}

// Visibility tells whether a repository is public. It is asked once per
// repository at startup; nil uses the catalog visibility for offline checks.
type Visibility func(repo string) (public bool, err error)

// Resolve returns every queue of the catalog, sorted by name. A public
// repository is checked against the public profile rules; an error is
// returned when a public repository is served and the public profile is
// missing.
func (c *Catalog) Resolve(visibility Visibility) ([]Queue, error) {
	public := map[string]bool{}
	for _, key := range slices.Sorted(maps.Keys(c.Repos)) {
		r := c.Repos[key]
		name := r.repoName(key)
		switch {
		case visibility != nil:
			p, err := visibility(name)
			if err != nil {
				return nil, fmt.Errorf("repo %s: visibility: %w", name, err)
			}
			public[name] = p || r.Visibility == "public"
		default:
			public[name] = r.Visibility == "public"
		}
		if public[name] {
			pp, ok := c.Profiles[c.Defaults.PublicProfile]
			if !ok || pp.Trust != TrustPublic {
				return nil, fmt.Errorf("repo %s is public but the public profile %q is not defined", name, c.Defaults.PublicProfile)
			}
		}
	}
	queues := c.resolveAll(public)
	for _, q := range queues {
		if q.Trust == TrustPublic {
			if bad := c.forbiddenPublic(q.Spec.Nodes); len(bad) > 0 {
				return nil, fmt.Errorf("queue %s: public pods cannot run on %v", q.Name, bad)
			}
		}
	}
	return queues, nil
}

// resolveAll builds the queues; public maps repository names to visibility.
func (c *Catalog) resolveAll(public map[string]bool) []Queue {
	var out []Queue
	for _, key := range slices.Sorted(maps.Keys(c.Repos)) {
		r := c.Repos[key]
		name := r.repoName(key)
		requested := r.Profiles
		if len(requested) == 0 {
			requested = c.Defaults.Profiles
		}
		for _, rp := range requested {
			used := rp
			if public[name] {
				used = c.Defaults.PublicProfile
			}
			out = append(out, c.resolveQueue(name, r, rp, used))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// QueueName gives the scale set name of a repository and requested profile.
func (c *Catalog) QueueName(repo string, r *Repo, profile string) string {
	if r != nil {
		if n, ok := r.FileNames[profile]; ok {
			return n
		}
	}
	pattern, ok := c.FileNames[profile]
	if !ok {
		pattern = c.FileNames["*"]
	}
	return strings.NewReplacer("{repo}", repo, "{profile}", profile).Replace(pattern)
}

func (c *Catalog) resolveQueue(repo string, r *Repo, requested, used string) Queue {
	p := c.Profiles[used]
	q := Queue{
		Name:             c.QueueName(repo, r, requested),
		Repo:             repo,
		RequestedProfile: requested,
		Profile:          used,
		Trust:            p.Trust,
		Priority:         "normal",
		MaxRunners:       c.Defaults.MaxRunners,
		MinRunners:       c.Defaults.MinRunners,
	}
	if r.Priority != "" {
		q.Priority = r.Priority
	}
	s := PodSpec{
		Template:           p.Template,
		Image:              p.Image,
		Resources:          cloneResources(p.Resources),
		DinD:               cloneDinD(p.DinD),
		DockerDataLimit:    p.DockerDataLimit,
		WorkLimit:          p.WorkLimit,
		Externals:          p.Externals,
		DockerConfigSecret: p.DockerConfigSecret,
		InitImage:          p.InitImage,
		Nodes:              slices.Clone(p.Nodes),
		PreferNodes:        slices.Clone(p.PreferNodes),
		NodeSelector:       maps.Clone(p.NodeSelector),
		Tolerations:        slices.Clone(p.Tolerations),
		ImagePullSecrets:   slices.Clone(p.ImagePullSecrets),
		ServiceAccountName: p.ServiceAccountName,
		CacheProfile:       c.Defaults.CacheProfile,
		Env:                maps.Clone(p.Env),
		Annotations:        maps.Clone(p.Annotations),
		Trust:              p.Trust,
	}
	for _, cn := range p.Caches {
		s.Caches = append(s.Caches, NamedCache{Name: cn, Cache: c.Caches[cn]})
	}
	// A public repository keeps its own per-repo knobs that cannot widen
	// trust (limits, runner counts) but never its node or cache overrides.
	apply := func(o Override) {
		if o.MaxRunners != nil {
			q.MaxRunners = *o.MaxRunners
		}
		if o.MinRunners != nil {
			q.MinRunners = *o.MinRunners
		}
		if o.Resources != nil {
			mergeResources(&s.Resources, *o.Resources)
		}
		if o.DockerDataLimit != "" {
			s.DockerDataLimit = o.DockerDataLimit
		}
		if o.DinDMemory != "" && s.DinD != nil {
			s.DinD.Memory = o.DinDMemory
		}
		if q.Trust == TrustPublic {
			return
		}
		if o.Image != "" {
			s.Image = o.Image
		}
		if nodes, changed, err := applyNodes(s.Nodes, o.Nodes); err == nil && changed {
			s.Nodes = nodes
		}
		if len(o.PreferNodes) > 0 {
			s.PreferNodes = slices.Clone(o.PreferNodes)
		}
		if o.ServiceAccountName != "" {
			s.ServiceAccountName = o.ServiceAccountName
		}
		if o.CacheProfile != "" {
			s.CacheProfile = o.CacheProfile
		}
		for k, v := range o.Env {
			if s.Env == nil {
				s.Env = map[string]string{}
			}
			s.Env[k] = v
		}
	}
	apply(r.Override)
	if o, ok := r.PerProfile[requested]; ok {
		apply(o)
	}
	if q.Trust == TrustPublic {
		s.CacheProfile = CacheProfileLocal
	}
	if q.MaxRunners < q.MinRunners {
		q.MaxRunners = q.MinRunners
	}
	q.Spec = s
	return q
}

func cloneResources(r Resources) Resources {
	return Resources{Requests: maps.Clone(r.Requests), Limits: maps.Clone(r.Limits)}
}

func mergeResources(dst *Resources, o Resources) {
	if dst.Requests == nil {
		dst.Requests = map[string]string{}
	}
	if dst.Limits == nil {
		dst.Limits = map[string]string{}
	}
	maps.Copy(dst.Requests, o.Requests)
	maps.Copy(dst.Limits, o.Limits)
}

func cloneDinD(d *DinD) *DinD {
	if d == nil {
		return nil
	}
	c := *d
	c.InsecureRegistries = slices.Clone(d.InsecureRegistries)
	return &c
}

// RepoNames returns the GitHub names of every catalog repository.
func (c *Catalog) RepoNames() []string {
	var out []string
	for _, key := range slices.Sorted(maps.Keys(c.Repos)) {
		out = append(out, c.Repos[key].repoName(key))
	}
	return out
}

// RemoveRepo drops the repository of that GitHub name (case-insensitive):
// its queues are not served. It reports whether a repository was removed.
func (c *Catalog) RemoveRepo(name string) bool {
	for key, r := range c.Repos {
		if strings.EqualFold(r.repoName(key), name) {
			delete(c.Repos, key)
			return true
		}
	}
	return false
}

// AddDiscovered adds repositories found by discovery that the catalog does
// not list yet, with the default settings.
func (c *Catalog) AddDiscovered(names []string) {
	known := map[string]bool{}
	for _, n := range c.RepoNames() {
		known[strings.ToLower(n)] = true
	}
	if c.Repos == nil {
		c.Repos = map[string]*Repo{}
	}
	for _, n := range names {
		if !repoNamePattern.MatchString(n) || known[strings.ToLower(n)] {
			continue
		}
		c.Repos[n] = &Repo{}
		known[strings.ToLower(n)] = true
	}
}

// ProfileSpec is the pod configuration of a profile without any repository
// override: what a warm pod of that profile runs.
func (c *Catalog) ProfileSpec(profile string) PodSpec {
	return c.resolveQueue("", &Repo{}, profile, profile).Spec
}

// WarmCompatible tells whether a warm pod of the queue profile can serve the
// queue: the queue must not override anything that changes the pod, apart
// from the nodes (checked against the node the warm pod runs on).
func (c *Catalog) WarmCompatible(q Queue) bool {
	a, b := q.Spec, c.ProfileSpec(q.Profile)
	a.Nodes, a.PreferNodes, b.Nodes, b.PreferNodes = nil, nil, nil, nil
	return reflect.DeepEqual(a, b)
}
