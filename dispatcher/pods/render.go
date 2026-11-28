// Package pods renders runner pods from a resolved queue and manages their
// life cycle in Kubernetes.
package pods

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"sort"
	"text/template"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"sigs.k8s.io/yaml"

	"github.com/actions/scaleset/dispatcher/catalog"
	"github.com/actions/scaleset/dispatcher/preflight"
)

//go:embed templates/*.yaml.tmpl
var builtinFS embed.FS

// Label and annotation keys. The prefix is configurable (Labels.Prefix) so a
// deployment can use its own domain; the component and repository labels
// keep the values ARC used, which network policies and tools select on.
const (
	LabelManagedBy      = "app.kubernetes.io/managed-by"
	LabelComponent      = "app.kubernetes.io/component"
	LabelARCRepository  = "actions.github.com/repository"
	ManagedByValue      = "ci-dispatcher"
	ComponentRunner     = "runner"
	StateWarm           = "warm"
	StateAssigned       = "assigned"
	StateBusy           = "busy"
	ClaimAudience       = "ci-dispatcher" // Kubernetes token audience name, not a credential
	AudienceMountDir    = "/var/run/secrets/ci-dispatcher"
	AudienceJWTFile     = AudienceMountDir + "/token"
	AgentBinDir         = "/agent-bin"
	AgentBinary         = AgentBinDir + "/ci-runner-agent"
	RunnerContainer     = "runner"
	AgentInitContainer  = "ci-runner-agent"
	tokenExpirationSecs = int64(600)
)

// Labels holds the label keys derived from the prefix.
type Labels struct {
	Prefix string
}

func (l Labels) key(name string) string { return l.Prefix + "/" + name }

// Profile is the label holding the profile name.
func (l Labels) Profile() string { return l.key("profile") }

// State is the label holding warm, assigned or busy.
func (l Labels) State() string { return l.key("state") }

// Trust is the label holding private or public.
func (l Labels) Trust() string { return l.key("trust") }

// Repo is the label holding the repository once assigned.
func (l Labels) Repo() string { return l.key("repo") }

// ScaleSetID is the label holding the scale set ID once assigned.
func (l Labels) ScaleSetID() string { return l.key("scale-set-id") }

// QueueAnnotation holds the scale set name once assigned.
func (l Labels) QueueAnnotation() string { return l.key("queue") }

// RunnerIDAnnotation holds the GitHub runner ID once assigned.
func (l Labels) RunnerIDAnnotation() string { return l.key("runner-id") }

// ClaimedAnnotation is set when the agent received its configuration.
func (l Labels) ClaimedAnnotation() string { return l.key("claimed-at") }

// AssignedAnnotation is set when the pod is given a repository.
func (l Labels) AssignedAnnotation() string { return l.key("assigned-at") }

// Request describes the pod to render.
type Request struct {
	Name      string
	Namespace string
	Queue     *catalog.Queue // nil for a warm pod
	Profile   string
	Spec      catalog.PodSpec
	// Nodes overrides Spec.Nodes (budget placement); empty keeps Spec.Nodes.
	Nodes      []string
	ScaleSetID int
	ClaimURL   string
	AgentImage string
	Labels     Labels
}

// EnvVar is a name/value pair given to templates in a stable order.
type EnvVar struct{ Name, Value string }

// TemplateData is what a pod template receives.
type TemplateData struct {
	Name, Namespace, Profile, Repo string
	Warm                           bool
	Spec                           catalog.PodSpec
	Nodes                          []string
	Language                       *catalog.NamedCache
	LocalCache                     bool
	ProxyEnv                       []EnvVar
	ExtraEnv                       []EnvVar
	AptConfigMap                   string
	InitImage                      string
	PreflightScript                string
}

// Renderer turns requests into pods.
type Renderer struct {
	templates map[string]*template.Template
}

var funcs = template.FuncMap{
	"quote": func(s string) (string, error) {
		b, err := json.Marshal(s)
		return string(b), err
	},
	"toJSON": func(v any) (string, error) {
		b, err := json.Marshal(v)
		return string(b), err
	},
	"default": func(def, v string) string {
		if v == "" {
			return def
		}
		return v
	},
}

// NewRenderer loads the built-in templates, then the catalog ones (which may
// replace a built-in of the same name).
func NewRenderer(custom map[string]string) (*Renderer, error) {
	r := &Renderer{templates: map[string]*template.Template{}}
	for _, name := range []string{catalog.TemplateDocker, catalog.TemplateLight} {
		raw, err := builtinFS.ReadFile("templates/" + name + ".yaml.tmpl")
		if err != nil {
			return nil, err
		}
		t, err := template.New(name).Funcs(funcs).Option("missingkey=error").Parse(string(raw))
		if err != nil {
			return nil, fmt.Errorf("template %s: %w", name, err)
		}
		r.templates[name] = t
	}
	for name, raw := range custom {
		t, err := template.New(name).Funcs(funcs).Option("missingkey=error").Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("template %s: %w", name, err)
		}
		r.templates[name] = t
	}
	return r, nil
}

func sortedEnv(m map[string]string) []EnvVar {
	out := make([]EnvVar, 0, len(m))
	for _, k := range slices.Sorted(maps.Keys(m)) {
		out = append(out, EnvVar{k, m[k]})
	}
	return out
}

// Data builds the template input of a request.
func Data(req Request) TemplateData {
	d := TemplateData{
		Name:            req.Name,
		Namespace:       req.Namespace,
		Profile:         req.Profile,
		Warm:            req.Queue == nil,
		Spec:            req.Spec,
		Nodes:           req.Spec.Nodes,
		InitImage:       req.Spec.InitImage,
		PreflightScript: preflight.Script,
		ExtraEnv:        sortedEnv(req.Spec.Env),
	}
	if d.InitImage == "" {
		d.InitImage = "busybox:1.37.0"
	}
	if len(req.Nodes) > 0 {
		d.Nodes = req.Nodes
	}
	if req.Queue != nil {
		d.Repo = req.Queue.Repo
	}
	proxyEnv := map[string]string{}
	for i := range req.Spec.Caches {
		c := req.Spec.Caches[i]
		switch c.Type {
		case catalog.CacheLanguage:
			if d.Language == nil {
				d.Language = &c
			}
		case catalog.CacheProxies:
			maps.Copy(proxyEnv, c.Env)
			if c.AptConfigMap != "" {
				d.AptConfigMap = c.AptConfigMap
			}
		}
	}
	d.ProxyEnv = sortedEnv(proxyEnv)
	d.LocalCache = d.Language == nil || req.Spec.CacheProfile == catalog.CacheProfileLocal
	return d
}

// Render produces the pod of a request, with every dispatcher invariant
// applied after the template.
func (r *Renderer) Render(req Request) (*corev1.Pod, error) {
	t, ok := r.templates[req.Spec.Template]
	if !ok {
		return nil, fmt.Errorf("unknown template %q", req.Spec.Template)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, Data(req)); err != nil {
		return nil, fmt.Errorf("render template %s: %w", req.Spec.Template, err)
	}
	var pod corev1.Pod
	if err := yaml.UnmarshalStrict(buf.Bytes(), &pod); err != nil {
		return nil, fmt.Errorf("template %s does not render a valid pod: %w", req.Spec.Template, err)
	}
	if err := applyInvariants(&pod, req); err != nil {
		return nil, err
	}
	return &pod, nil
}

// RenderYAML renders the pod as YAML (golden tests, dry runs).
func (r *Renderer) RenderYAML(req Request) ([]byte, error) {
	pod, err := r.Render(req)
	if err != nil {
		return nil, err
	}
	return yaml.Marshal(pod)
}

func applyInvariants(pod *corev1.Pod, req Request) error {
	runner := -1
	for i, c := range pod.Spec.Containers {
		if c.Name == RunnerContainer {
			runner = i
		}
	}
	if runner < 0 || len(pod.Spec.Containers) != 1 {
		return fmt.Errorf("template %s must render exactly one container named %q", req.Spec.Template, RunnerContainer)
	}
	if pod.Spec.HostNetwork || pod.Spec.HostPID || pod.Spec.HostIPC {
		return fmt.Errorf("template %s must not use host namespaces", req.Spec.Template)
	}

	pod.Name = req.Name
	pod.Namespace = req.Namespace
	pod.Labels = BaseLabels(req)
	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	if req.Queue != nil {
		pod.Annotations[req.Labels.QueueAnnotation()] = req.Queue.Name
	}
	pod.Spec.RestartPolicy = corev1.RestartPolicyNever
	pod.Spec.AutomountServiceAccountToken = new(bool)

	// The agent binary comes from the dispatcher image, copied into an
	// emptyDir before every other init container.
	agent := corev1.Container{
		Name:            AgentInitContainer,
		Image:           req.AgentImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Command:         []string{"/ci-runner-agent", "install", AgentBinary},
		SecurityContext: &corev1.SecurityContext{
			RunAsNonRoot:             ptr(true),
			AllowPrivilegeEscalation: ptr(false),
			ReadOnlyRootFilesystem:   ptr(true),
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		},
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("5m"),
				corev1.ResourceMemory: resource.MustParse("16Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("100m"),
				corev1.ResourceMemory: resource.MustParse("64Mi"),
			},
		},
		VolumeMounts: []corev1.VolumeMount{{Name: "agent-bin", MountPath: AgentBinDir}},
	}
	pod.Spec.InitContainers = append([]corev1.Container{agent}, pod.Spec.InitContainers...)
	pod.Spec.Volumes = append(pod.Spec.Volumes,
		corev1.Volume{Name: "agent-bin", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: ptr(resource.MustParse("64Mi"))}}},
		corev1.Volume{Name: "ci-dispatcher-token", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
			DefaultMode: ptr(int32(0o444)),
			Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
				Audience:          ClaimAudience,
				ExpirationSeconds: ptr(tokenExpirationSecs),
				Path:              "token",
			}}},
		}}},
	)
	c := &pod.Spec.Containers[runner]
	c.Command = []string{AgentBinary}
	c.Args = []string{"run"}
	c.VolumeMounts = append(c.VolumeMounts,
		corev1.VolumeMount{Name: "agent-bin", MountPath: AgentBinDir, ReadOnly: true},
		corev1.VolumeMount{Name: "ci-dispatcher-token", MountPath: AudienceMountDir, ReadOnly: true},
	)
	stateDir := ""
	for _, m := range c.VolumeMounts {
		if m.MountPath == "/mnt/runner-state" {
			stateDir = m.MountPath
		}
	}
	c.Env = append(c.Env,
		corev1.EnvVar{Name: "CI_DISPATCHER_CLAIM_URL", Value: req.ClaimURL},
		corev1.EnvVar{Name: "CI_DISPATCHER_TOKEN_FILE", Value: AudienceJWTFile},
		corev1.EnvVar{Name: "CI_DISPATCHER_STATE_DIR", Value: stateDir},
	)
	for _, v := range pod.Spec.Volumes {
		if v.Name == "ci-dispatcher-token" && v.Projected == nil {
			return fmt.Errorf("template %s must not define a volume named ci-dispatcher-token", req.Spec.Template)
		}
	}
	return nil
}

// BaseLabels returns the labels a pod carries at creation.
func BaseLabels(req Request) map[string]string {
	l := map[string]string{
		LabelManagedBy:       ManagedByValue,
		LabelComponent:       ComponentRunner,
		req.Labels.Profile(): req.Profile,
		req.Labels.Trust():   req.Spec.Trust,
		req.Labels.State():   StateWarm,
	}
	if req.Queue != nil {
		maps.Copy(l, AssignedLabels(req.Labels, req.Queue.Repo, req.ScaleSetID))
	}
	return l
}

// AssignedLabels are added when a pod is given to a repository.
func AssignedLabels(l Labels, repo string, scaleSetID int) map[string]string {
	return map[string]string{
		l.State():          StateAssigned,
		l.Repo():           repo,
		LabelARCRepository: repo,
		l.ScaleSetID():     fmt.Sprint(scaleSetID),
	}
}

// SortedKeys is a helper for stable output.
func SortedKeys(m map[string]string) []string {
	keys := slices.Collect(maps.Keys(m))
	sort.Strings(keys)
	return keys
}

func ptr[T any](v T) *T { return &v }
