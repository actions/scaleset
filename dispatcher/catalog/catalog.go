// Package catalog loads, validates and resolves the ci-dispatcher catalog: the
// runner profiles, the repositories they serve and the per-node capacity.
//
// Validation is strict on purpose: an unknown key, an unknown profile or an
// unpinned image stops the dispatcher at startup instead of silently serving a
// queue with a default the operator did not choose.
package catalog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"sigs.k8s.io/yaml"
)

// Trust levels of a profile.
const (
	TrustPrivate = "private"
	TrustPublic  = "public"
)

// Template names shipped with the dispatcher.
const (
	TemplateDocker = "docker"
	TemplateLight  = "light"
)

// Cache kinds a profile can reference.
const (
	// CacheLanguage is a host path shared by every runner node and split by
	// repository (uv, go-build, go-mod), like the ARC language cache.
	CacheLanguage = "language"
	// CacheProxies injects package proxy settings (environment and an
	// optional APT configuration ConfigMap).
	CacheProxies = "proxies"
)

// Cache profiles of a repository (where language caches live).
const (
	CacheProfileShared = "nfs"
	CacheProfileLocal  = "local"
)

// Catalog is the root document.
type Catalog struct {
	GitHub    GitHub              `json:"github"`
	Discovery Discovery           `json:"discovery"`
	Runtime   Runtime             `json:"runtime"`
	Caches    map[string]Cache    `json:"caches"`
	Profiles  map[string]*Profile `json:"profiles"`
	Defaults  Defaults            `json:"defaults"`
	Repos     map[string]*Repo    `json:"repos"`
	Capacity  Capacity            `json:"capacity"`
	FileNames map[string]string   `json:"fileNames"`
	// Templates overrides or adds pod templates (Go text/template rendering
	// to a Pod manifest). The built-in docker and light templates are used
	// when a name is absent.
	Templates map[string]string `json:"templates"`
}

// GitHub identifies the account and its credentials.
type GitHub struct {
	Owner string `json:"owner"`
	// URL is the GitHub base URL (default https://github.com).
	URL string `json:"url"`
	// APIURL is the REST API base URL (default https://api.github.com).
	APIURL string `json:"apiURL"`
	Auth   Auth   `json:"auth"`
}

// Auth selects the credential type. The secret itself is never in the
// catalog: the chart mounts the referenced Secret and the dispatcher reads it
// from a file.
type Auth struct {
	Type           string    `json:"type"` // pat | app
	SecretRef      SecretRef `json:"secretRef"`
	AppClientID    string    `json:"appClientID"`
	InstallationID int64     `json:"installationID"`
	// PrivateKeyKey is the Secret key holding the App private key.
	PrivateKeyKey string `json:"privateKeyKey"`
}

// SecretRef points at the Kubernetes Secret holding the credential.
type SecretRef struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

// Discovery adds every repository the GitHub App installation can see.
type Discovery struct {
	Enabled bool `json:"enabled"`
}

// Runtime holds the cluster-side settings shared by every pod.
type Runtime struct {
	// Namespace where runner pods live.
	Namespace string `json:"namespace"`
	// ClaimURL is the in-cluster URL of the claim service, given to agents.
	ClaimURL string `json:"claimURL"`
	// AgentImage is the dispatcher image, which carries ci-runner-agent.
	// Empty means the image the dispatcher runs from (env CI_DISPATCHER_IMAGE).
	AgentImage string `json:"agentImage"`
	// ForbiddenPublicNodes never receive a public pod (control-plane, etcd).
	// Nodes labelled as control-plane or etcd are refused as well.
	ForbiddenPublicNodes []string `json:"forbiddenPublicNodes"`
	// LabelPrefix prefixes the dispatcher labels (profile, state, trust,
	// repo, scale-set-id). Default "ci-dispatcher".
	LabelPrefix string `json:"labelPrefix"`
}

// Cache describes a reusable cache or proxy setting.
type Cache struct {
	Type string `json:"type"`
	// language
	HostPath   string `json:"hostPath"`
	ServerNode string `json:"serverNode"`
	Marker     string `json:"marker"`
	// proxies
	Env          map[string]string `json:"env"`
	AptConfigMap string            `json:"aptConfigMap"`
}

// Resources mirrors the Kubernetes requests/limits maps with strings.
type Resources struct {
	Requests map[string]string `json:"requests,omitempty"`
	Limits   map[string]string `json:"limits,omitempty"`
}

// DinD configures the Docker sidecar of the docker template.
type DinD struct {
	Image              string   `json:"image"`
	Memory             string   `json:"memory"`
	CPU                string   `json:"cpu"`
	CPULimit           string   `json:"cpuLimit"`
	InsecureRegistries []string `json:"insecureRegistries"`
}

// Externals configures the shared runner externals cache (read-only host path
// filled by a DaemonSet).
type Externals struct {
	HostPath  string `json:"hostPath"`
	CacheKey  string `json:"cacheKey"`
	ConfigMap string `json:"configMap"`
}

// Toleration is the subset of corev1.Toleration the catalog accepts.
type Toleration struct {
	Key      string `json:"key"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
	Effect   string `json:"effect"`
}

// Profile describes one kind of runner pod.
type Profile struct {
	Template           string            `json:"template"`
	Image              string            `json:"image"`
	Resources          Resources         `json:"resources"`
	DinD               *DinD             `json:"dind"`
	DockerDataLimit    string            `json:"dockerDataLimit"`
	WorkLimit          string            `json:"workLimit"`
	Caches             []string          `json:"caches"`
	Externals          *Externals        `json:"externals"`
	DockerConfigSecret string            `json:"dockerConfigSecret"`
	InitImage          string            `json:"initImage"`
	Nodes              []string          `json:"nodes"`
	PreferNodes        []string          `json:"preferNodes"`
	NodeSelector       map[string]string `json:"nodeSelector"`
	Tolerations        []Toleration      `json:"tolerations"`
	ImagePullSecrets   []string          `json:"imagePullSecrets"`
	ServiceAccountName string            `json:"serviceAccountName"`
	Env                map[string]string `json:"env"`
	Annotations        map[string]string `json:"annotations"`
	Trust              string            `json:"trust"`
	Warm               int               `json:"warm"`
}

// Defaults apply to every repository unless overridden.
type Defaults struct {
	Profiles      []string `json:"profiles"`
	MaxRunners    int      `json:"maxRunners"`
	MinRunners    int      `json:"minRunners"`
	PublicProfile string   `json:"publicProfile"`
	CacheProfile  string   `json:"cacheProfile"`
}

// Override holds the per-repository (or per repository and profile) knobs.
type Override struct {
	Image              string            `json:"image,omitempty"`
	Resources          *Resources        `json:"resources,omitempty"`
	DockerDataLimit    string            `json:"dockerDataLimit,omitempty"`
	MaxRunners         *int              `json:"maxRunners,omitempty"`
	MinRunners         *int              `json:"minRunners,omitempty"`
	Nodes              []string          `json:"nodes,omitempty"`
	PreferNodes        []string          `json:"preferNodes,omitempty"`
	ServiceAccountName string            `json:"serviceAccountName,omitempty"`
	CacheProfile       string            `json:"cacheProfile,omitempty"`
	DinDMemory         string            `json:"dindMemory,omitempty"`
	Env                map[string]string `json:"env,omitempty"`
}

// Repo is a repository entry.
type Repo struct {
	Override `json:",inline"`
	// Name is the exact GitHub repository name when it differs from the key
	// (case, for example).
	Name       string              `json:"name,omitempty"`
	Profiles   []string            `json:"profiles,omitempty"`
	FileNames  map[string]string   `json:"fileNames,omitempty"`
	Priority   string              `json:"priority,omitempty"`
	PerProfile map[string]Override `json:"perProfile,omitempty"`
	// Visibility forces the trust decision (public|private) when the GitHub
	// API cannot be asked (tests, dry runs). Empty means ask GitHub.
	Visibility string `json:"visibility,omitempty"`
}

// Capacity is the per-node runner budget.
type Capacity struct {
	Enforce bool `json:"enforce"`
	// Nodes maps a node name to its runner places, or "auto" for no
	// dispatcher-side ceiling.
	Nodes map[string]NodeCapacity `json:"nodes"`
}

// NodeCapacity is either a number of places or Auto.
type NodeCapacity struct {
	Auto   bool
	Places int
}

// UnmarshalJSON accepts an integer or the string "auto".
func (n *NodeCapacity) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		if s != "auto" {
			return fmt.Errorf("node capacity must be an integer or \"auto\", got %q", s)
		}
		n.Auto = true
		return nil
	}
	var i int
	if err := json.Unmarshal(b, &i); err != nil {
		return fmt.Errorf("node capacity must be an integer or \"auto\": %w", err)
	}
	if i < 0 {
		return fmt.Errorf("node capacity must be positive, got %d", i)
	}
	n.Places = i
	return nil
}

// MarshalJSON is the inverse of UnmarshalJSON.
func (n NodeCapacity) MarshalJSON() ([]byte, error) {
	if n.Auto {
		return json.Marshal("auto")
	}
	return json.Marshal(n.Places)
}

var (
	repoNamePattern   = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	digestPattern     = regexp.MustCompile(`@sha256:[a-f0-9]{64}$`)
	k8sNamePattern    = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	profileNamePatten = regexp.MustCompile(`^[a-z][a-z0-9-]{0,20}$`)
	// Label values: repository names end up in pod labels.
	labelValuePattern  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]{0,61}[A-Za-z0-9])?$`)
	labelPrefixPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
)

// Load reads and validates a catalog file.
func Load(path string) (*Catalog, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- path given by the operator on the command line or in the Deployment
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	return Parse(raw)
}

// Parse decodes and validates a catalog document. Unknown keys are errors.
func Parse(raw []byte) (*Catalog, error) {
	js, err := yaml.YAMLToJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("catalog is not valid YAML: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(js))
	dec.DisallowUnknownFields()
	var c Catalog
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("catalog: %w", err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Catalog) applyDefaults() {
	if c.GitHub.URL == "" {
		c.GitHub.URL = "https://github.com"
	}
	if c.GitHub.APIURL == "" {
		c.GitHub.APIURL = "https://api.github.com"
	}
	if c.GitHub.Auth.Type == "" {
		c.GitHub.Auth.Type = "pat"
	}
	if c.Runtime.Namespace == "" {
		c.Runtime.Namespace = "default"
	}
	if c.Runtime.LabelPrefix == "" {
		c.Runtime.LabelPrefix = "ci-dispatcher"
	}
	if c.Defaults.MaxRunners == 0 {
		c.Defaults.MaxRunners = 6
	}
	if c.Defaults.PublicProfile == "" {
		c.Defaults.PublicProfile = "public"
	}
	if c.Defaults.CacheProfile == "" {
		c.Defaults.CacheProfile = CacheProfileShared
	}
	if len(c.Defaults.Profiles) == 0 {
		c.Defaults.Profiles = []string{TemplateDocker}
	}
	if c.FileNames == nil {
		c.FileNames = map[string]string{}
	}
	if _, ok := c.FileNames["*"]; !ok {
		c.FileNames["*"] = "{repo}-{profile}"
	}
	for _, p := range c.Profiles {
		if p == nil {
			continue
		}
		if p.Trust == "" {
			p.Trust = TrustPrivate
		}
	}
}

// Validate checks every rule that does not need the GitHub API or the
// cluster. Errors are joined so the operator sees all of them at once.
func (c *Catalog) Validate() error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if !repoNamePattern.MatchString(c.GitHub.Owner) {
		add("github.owner %q is invalid", c.GitHub.Owner)
	}
	switch c.GitHub.Auth.Type {
	case "pat":
		if c.GitHub.Auth.SecretRef.Name == "" || c.GitHub.Auth.SecretRef.Key == "" {
			add("github.auth.secretRef name and key are required")
		}
	case "app":
		if c.GitHub.Auth.SecretRef.Name == "" || c.GitHub.Auth.AppClientID == "" || c.GitHub.Auth.InstallationID == 0 || c.GitHub.Auth.PrivateKeyKey == "" {
			add("github.auth type app needs secretRef.name, appClientID, installationID and privateKeyKey")
		}
	default:
		add("github.auth.type %q is unknown (pat|app)", c.GitHub.Auth.Type)
	}
	if c.Discovery.Enabled && c.GitHub.Auth.Type != "app" {
		add("discovery needs github.auth.type app (it lists the installation repositories)")
	}
	if !k8sNamePattern.MatchString(c.Runtime.Namespace) {
		add("runtime.namespace %q is invalid", c.Runtime.Namespace)
	}
	if c.Runtime.ClaimURL == "" {
		add("runtime.claimURL is required")
	}
	if !labelPrefixPattern.MatchString(c.Runtime.LabelPrefix) {
		add("runtime.labelPrefix %q must be a DNS subdomain", c.Runtime.LabelPrefix)
	}

	for name, cache := range c.Caches {
		switch cache.Type {
		case CacheLanguage:
			if cache.HostPath == "" {
				add("cache %s: hostPath is required", name)
			}
		case CacheProxies:
		default:
			add("cache %s: type %q is unknown (%s|%s)", name, cache.Type, CacheLanguage, CacheProxies)
		}
	}

	if len(c.Profiles) == 0 {
		add("at least one profile is required")
	}
	for name, p := range c.Profiles {
		if p == nil {
			add("profile %s is empty", name)
			continue
		}
		errs = append(errs, c.validateProfile(name, p)...)
	}

	for _, name := range c.Defaults.Profiles {
		if _, ok := c.Profiles[name]; !ok {
			add("defaults.profiles: profile %q is unknown", name)
		}
	}
	if c.Defaults.MinRunners < 0 || c.Defaults.MaxRunners < c.Defaults.MinRunners {
		add("defaults: maxRunners must be >= minRunners >= 0")
	}
	if !validCacheProfile(c.Defaults.CacheProfile) {
		add("defaults.cacheProfile %q is unknown (nfs|local)", c.Defaults.CacheProfile)
	}
	if pp, ok := c.Profiles[c.Defaults.PublicProfile]; ok && pp != nil && pp.Trust != TrustPublic {
		add("defaults.publicProfile %q must have trust: public", c.Defaults.PublicProfile)
	}

	for key, r := range c.Repos {
		if r == nil {
			r = &Repo{}
			c.Repos[key] = r
		}
		errs = append(errs, c.validateRepo(key, r)...)
	}

	for pattern := range c.FileNames {
		if pattern != "*" {
			if _, ok := c.Profiles[pattern]; !ok {
				add("fileNames: profile %q is unknown", pattern)
			}
		}
	}
	for node := range c.Capacity.Nodes {
		if node == "" {
			add("capacity.nodes: empty node name")
		}
	}

	// Queue names must be unique across the whole catalog.
	if len(errs) == 0 {
		seen := map[string]string{}
		for _, q := range c.resolveAll(nil) {
			if prev, ok := seen[q.Name]; ok {
				add("queue name %q is used by %s and %s", q.Name, prev, q.Repo+"/"+q.RequestedProfile)
			}
			seen[q.Name] = q.Repo + "/" + q.RequestedProfile
		}
	}
	return errors.Join(errs...)
}

func validCacheProfile(s string) bool {
	return s == CacheProfileShared || s == CacheProfileLocal
}

func (c *Catalog) validateProfile(name string, p *Profile) []error {
	var errs []error
	add := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf("profile %s: "+format, append([]any{name}, args...)...))
	}
	if !profileNamePatten.MatchString(name) {
		add("name must match %s", profileNamePatten)
	}
	if p.Template == "" {
		add("template is required")
	} else if _, ok := c.Templates[p.Template]; !ok && p.Template != TemplateDocker && p.Template != TemplateLight {
		add("template %q is unknown", p.Template)
	}
	if err := checkImage(p.Image); err != nil {
		add("%v", err)
	}
	if p.Trust != TrustPrivate && p.Trust != TrustPublic {
		add("trust %q is unknown (private|public)", p.Trust)
	}
	if p.Warm < 0 {
		add("warm must be >= 0")
	}
	if len(p.Nodes) == 0 {
		add("nodes is required")
	}
	if p.Template == TemplateDocker && p.DinD == nil {
		add("template docker needs dind")
	}
	if p.DinD != nil && p.DinD.Image == "" {
		add("dind.image is required")
	}
	for _, cn := range p.Caches {
		cache, ok := c.Caches[cn]
		if !ok {
			add("cache %q is unknown", cn)
			continue
		}
		if p.Trust == TrustPublic && cache.Type == CacheLanguage {
			add("a public profile cannot mount the shared language cache %q", cn)
		}
	}
	if p.Trust == TrustPublic {
		if p.DockerConfigSecret != "" {
			add("a public profile cannot mount the registry credentials (dockerConfigSecret)")
		}
		if bad := c.forbiddenPublic(p.Nodes); len(bad) > 0 {
			add("public profile cannot run on %v (runtime.forbiddenPublicNodes)", bad)
		}
	}
	return errs
}

func (c *Catalog) forbiddenPublic(nodes []string) []string {
	var bad []string
	for _, n := range nodes {
		if slices.Contains(c.Runtime.ForbiddenPublicNodes, n) {
			bad = append(bad, n)
		}
	}
	return bad
}

func checkImage(image string) error {
	if image == "" {
		return errors.New("image is required")
	}
	if !digestPattern.MatchString(image) {
		return fmt.Errorf("image %q must be pinned by digest (@sha256:...)", image)
	}
	return nil
}

func (c *Catalog) validateRepo(key string, r *Repo) []error {
	var errs []error
	add := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf("repo %s: "+format, append([]any{key}, args...)...))
	}
	name := r.repoName(key)
	if !repoNamePattern.MatchString(key) || !repoNamePattern.MatchString(name) {
		add("name must match [A-Za-z0-9._-]+")
	}
	if !labelValuePattern.MatchString(name) {
		add("name %q cannot be a pod label value (63 characters, alphanumeric at both ends)", name)
	}
	for _, p := range r.Profiles {
		if _, ok := c.Profiles[p]; !ok {
			add("profile %q is unknown", p)
		}
	}
	for p := range r.FileNames {
		if _, ok := c.Profiles[p]; !ok {
			add("fileNames: profile %q is unknown", p)
		}
	}
	for p := range r.PerProfile {
		if _, ok := c.Profiles[p]; !ok {
			add("perProfile: profile %q is unknown", p)
		}
	}
	if r.Priority != "" && r.Priority != "high" && r.Priority != "normal" {
		add("priority %q is unknown (high|normal)", r.Priority)
	}
	if r.Visibility != "" && r.Visibility != "public" && r.Visibility != "private" {
		add("visibility %q is unknown (public|private)", r.Visibility)
	}
	check := func(where string, o Override) {
		if o.Image != "" {
			if err := checkImage(o.Image); err != nil {
				add("%s%v", where, err)
			}
		}
		if o.CacheProfile != "" && !validCacheProfile(o.CacheProfile) {
			add("%scacheProfile %q is unknown (nfs|local)", where, o.CacheProfile)
		}
		if o.MaxRunners != nil && *o.MaxRunners < 0 {
			add("%smaxRunners must be >= 0", where)
		}
		if o.MinRunners != nil && *o.MinRunners < 0 {
			add("%sminRunners must be >= 0", where)
		}
		if _, _, err := applyNodes(nil, o.Nodes); err != nil {
			add("%s%v", where, err)
		}
	}
	check("", r.Override)
	for p, o := range r.PerProfile {
		check("perProfile "+p+": ", o)
	}
	return errs
}

func (r *Repo) repoName(key string) string {
	if r != nil && r.Name != "" {
		return r.Name
	}
	return key
}

// applyNodes merges an override into a node list. An override whose entries
// all start with "+" adds nodes ("+node-c"); a plain list replaces; mixing
// both is an error.
func applyNodes(base, override []string) ([]string, bool, error) {
	if len(override) == 0 {
		return slices.Clone(base), false, nil
	}
	plus := 0
	for _, n := range override {
		if strings.HasPrefix(n, "+") {
			plus++
		}
	}
	switch plus {
	case 0:
		return slices.Clone(override), true, nil
	case len(override):
		out := slices.Clone(base)
		for _, n := range override {
			n = strings.TrimPrefix(n, "+")
			if n == "" {
				return nil, false, errors.New("nodes: empty entry after +")
			}
			if !slices.Contains(out, n) {
				out = append(out, n)
			}
		}
		return out, true, nil
	default:
		return nil, false, errors.New("nodes: either all entries add (+node) or none")
	}
}
