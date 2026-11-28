package controller

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/actions/scaleset/dispatcher/catalog"
	"github.com/actions/scaleset/dispatcher/claim"
	"github.com/actions/scaleset/dispatcher/gh"
	"github.com/actions/scaleset/dispatcher/metrics"
	"github.com/actions/scaleset/dispatcher/pods"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

type coldTestPodAPI struct {
	PodAPI
	created *corev1.Pod
}

func (p *coldTestPodAPI) Create(_ context.Context, pod *corev1.Pod) (*corev1.Pod, error) {
	p.created = pod
	if p.created != nil {
		p.created.UID = types.UID("uid-cold")
	}
	return p.created, nil
}

type coldRemoveCall struct {
	repo string
	id   int64
}

type coldTestAPI struct {
	gh.API
	jit         gh.JIT
	removeCalls []coldRemoveCall
}

func (a *coldTestAPI) GenerateJIT(_ context.Context, _ string, _ int, _ string) (gh.JIT, error) {
	return a.jit, nil
}

func (a *coldTestAPI) RemoveRunner(_ context.Context, repo string, id int64) error {
	a.removeCalls = append(a.removeCalls, coldRemoveCall{repo: repo, id: id})
	return nil
}

type coldDeposit struct {
	name    string
	uid     string
	payload claim.Payload
}

type coldTestMailbox struct {
	Mailbox
	deposits []coldDeposit
	err      error
}

func (m *coldTestMailbox) Deposit(name, uid string, payload claim.Payload) error {
	m.deposits = append(m.deposits, coldDeposit{name: name, uid: uid, payload: payload})
	return m.err
}

func newColdTestConfig(t *testing.T, api gh.API, podAPI PodAPI, mailbox Mailbox, agentImage string) (Config, catalog.Queue) {
	t.Helper()

	renderer, err := pods.NewRenderer(nil)
	if err != nil {
		t.Fatalf("NewRenderer : %v", err)
	}

	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)

	cat := &catalog.Catalog{
		Profiles: map[string]*catalog.Profile{
			"light": {Nodes: []string{"node-a"}},
		},
		Runtime: catalog.Runtime{
			Namespace: "ci",
			ClaimURL:  "http://claim",
		},
	}

	q := catalog.Queue{
		Name:       "queue",
		Repo:       "repo",
		Profile:    "light",
		MaxRunners: 1,
		Spec:       cat.ProfileSpec("light"),
	}
	q.Spec.Template = catalog.TemplateLight
	q.Spec.Image = "runner-image"

	cfg := Config{
		Catalog:    cat,
		Queues:     []catalog.Queue{q},
		API:        api,
		Pods:       podAPI,
		Mailbox:    mailbox,
		Renderer:   renderer,
		Metrics:    metrics.New(),
		Labels:     pods.Labels{Prefix: "example.com/ci"},
		AgentImage: agentImage,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:        func() time.Time { return now },
	}

	return cfg, q
}

func TestColdClaimNamesTheDispatcherImage(t *testing.T) {
	const image = "registry/dispatcher@sha256:abc"

	api := &coldTestAPI{
		jit: gh.JIT{RunnerID: 7, Config: "jit"},
	}
	podAPI := &coldTestPodAPI{}
	mailbox := &coldTestMailbox{}

	cfg, q := newColdTestConfig(t, api, podAPI, mailbox, image)
	c := New(cfg)

	if err := c.createCold(context.Background(), q, 1, "node-a"); err != nil {
		t.Fatalf("createCold : %v", err)
	}

	if podAPI.created == nil {
		t.Fatal("le pod n'a pas été créé")
	}

	if len(mailbox.deposits) != 1 {
		t.Fatalf("nombre de dépôts dans la mailbox = %d, attendu 1", len(mailbox.deposits))
	}

	deposit := mailbox.deposits[0]
	if deposit.name != podAPI.created.Name {
		t.Errorf("dépôt name = %q, attendu %q", deposit.name, podAPI.created.Name)
	}
	if deposit.uid != string(podAPI.created.UID) {
		t.Errorf("dépôt uid = %q, attendu %q", deposit.uid, string(podAPI.created.UID))
	}

	payload := deposit.payload

	if got := payload.Env[DispatcherImageEnv]; got != image {
		t.Errorf("claim.Env[%s] = %q, attendu %q", DispatcherImageEnv, got, image)
	}

	if payload.JITConfig != api.jit.Config {
		t.Errorf("claim.JITConfig = %q, attendu %q", payload.JITConfig, api.jit.Config)
	}

	if len(api.removeCalls) != 0 {
		t.Errorf("nombre d'appels à RemoveRunner = %d, attendu 0", len(api.removeCalls))
	}
}

func TestColdClaimFailureRemovesTheRunner(t *testing.T) {
	const image = "registry/dispatcher@sha256:abc"

	api := &coldTestAPI{
		jit: gh.JIT{RunnerID: 7, Config: "jit"},
	}
	podAPI := &coldTestPodAPI{}
	mailbox := &coldTestMailbox{
		err: errors.New("deposit failed"),
	}

	cfg, q := newColdTestConfig(t, api, podAPI, mailbox, image)
	c := New(cfg)

	err := c.createCold(context.Background(), q, 1, "node-a")
	if err == nil {
		t.Fatal("createCold aurait dû renvoyer une erreur")
	}

	if len(api.removeCalls) != 1 {
		t.Fatalf("nombre d'appels à RemoveRunner = %d, attendu 1", len(api.removeCalls))
	}

	call := api.removeCalls[0]
	if call.repo != q.Repo {
		t.Errorf("RemoveRunner repo = %q, attendu %q", call.repo, q.Repo)
	}
	if call.id != api.jit.RunnerID {
		t.Errorf("RemoveRunner runnerID = %d, attendu %d", call.id, api.jit.RunnerID)
	}

	if podAPI.created == nil {
		t.Fatal("le pod n'a pas été créé avant l'échec du dépôt")
	}
	name := podAPI.created.Name

	c.mu.Lock()
	_, assigned := c.assigned[name]
	_, source := c.sources[name]
	_, pending := c.pending[name]
	c.mu.Unlock()

	if assigned {
		t.Errorf("le pod %q est encore suivi dans assigned", name)
	}
	if source {
		t.Errorf("le pod %q est encore suivi dans sources", name)
	}
	if pending {
		t.Errorf("le pod %q est encore suivi dans pending", name)
	}
}
