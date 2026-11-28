// Package claim serves the JIT runner configurations to the agents of the
// runner pods.
//
// An agent proves which pod it runs in with its projected service account
// token (audience ci-dispatcher). The dispatcher checks it with a
// TokenReview, reads the pod name and UID bound to the token, and only
// answers for a pod it manages. A configuration is handed out once, then
// erased from memory.
package claim

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/actions/scaleset/dispatcher/claim/protocol"
)

// Extra keys of a bound service account token.
const (
	extraPodName = "authentication.kubernetes.io/pod-name"
	extraPodUID  = "authentication.kubernetes.io/pod-uid"
)

// Identity is the pod a token is bound to.
type Identity struct {
	Namespace string
	PodName   string
	PodUID    string
}

// Reviewer validates a token.
type Reviewer interface {
	Review(ctx context.Context, token string) (Identity, error)
}

// ErrUnauthenticated is returned for any token that cannot be trusted.
var ErrUnauthenticated = errors.New("unauthenticated")

// TokenReviewer validates tokens with the Kubernetes TokenReview API.
type TokenReviewer struct {
	Client   kubernetes.Interface
	Audience string
}

// Review implements Reviewer.
func (r TokenReviewer) Review(ctx context.Context, token string) (Identity, error) {
	tr, err := r.Client.AuthenticationV1().TokenReviews().Create(ctx, &authnv1.TokenReview{
		Spec: authnv1.TokenReviewSpec{Token: token, Audiences: []string{r.Audience}},
	}, metav1.CreateOptions{})
	if err != nil {
		return Identity{}, err
	}
	return IdentityFromStatus(tr.Status, r.Audience)
}

// IdentityFromStatus extracts the bound pod from a TokenReview status.
func IdentityFromStatus(st authnv1.TokenReviewStatus, audience string) (Identity, error) {
	if !st.Authenticated || st.Error != "" {
		return Identity{}, ErrUnauthenticated
	}
	if !slices.Contains(st.Audiences, audience) {
		return Identity{}, ErrUnauthenticated
	}
	// system:serviceaccount:<namespace>:<name>
	parts := strings.Split(st.User.Username, ":")
	if len(parts) != 4 || parts[0] != "system" || parts[1] != "serviceaccount" {
		return Identity{}, ErrUnauthenticated
	}
	name, uid := first(st.User.Extra[extraPodName]), first(st.User.Extra[extraPodUID])
	if name == "" || uid == "" {
		return Identity{}, ErrUnauthenticated
	}
	return Identity{Namespace: parts[2], PodName: name, PodUID: uid}, nil
}

func first(v authnv1.ExtraValue) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

// Payload and Preflight are the protocol messages.
type (
	Payload   = protocol.Payload
	Preflight = protocol.Preflight
)

// PodLookup returns the cached pod of that name in the managed namespace.
type PodLookup func(name string) (*corev1.Pod, bool)

// Config builds a Server.
type Config struct {
	Namespace string
	Reviewer  Reviewer
	Lookup    PodLookup
	// Managed tells whether a pod belongs to the dispatcher.
	Managed func(*corev1.Pod) bool
	// MaxWait caps the long poll (default 50s).
	MaxWait time.Duration
	// ReviewRate bounds TokenReview calls per second (default 20).
	ReviewRate float64
	Logger     *slog.Logger
	// OnReady and OnClaimed are called after a successful request.
	OnReady   func(pod string)
	OnClaimed func(pod, uid string, waited time.Duration)
}

type box struct {
	uid       string
	payload   *Payload
	filled    chan struct{}
	delivered bool
	created   time.Time
}

// Per-client rate limit, applied before the shared TokenReview budget so a
// single pod hammering the endpoint cannot starve the others.
const (
	perClientRate  = 1
	perClientBurst = 5
	clientIdleTTL  = 10 * time.Minute
	// forgottenTTL keeps the names of deleted pods long enough to refuse a
	// late Deposit (pod deleted between its creation and the deposit).
	forgottenTTL = 30 * time.Minute
)

type clientLimiter struct {
	l    *rate.Limiter
	seen time.Time
}

// Server holds the mailboxes and serves the agents.
type Server struct {
	cfg       Config
	limiter   *rate.Limiter
	mu        sync.Mutex
	boxes     map[string]*box
	ready     map[string]time.Time
	forgotten map[string]time.Time
	clients   map[string]*clientLimiter
}

// New builds a Server.
func New(cfg Config) *Server {
	if cfg.MaxWait == 0 {
		cfg.MaxWait = 50 * time.Second
	}
	if cfg.ReviewRate == 0 {
		cfg.ReviewRate = 20
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return &Server{
		cfg:       cfg,
		limiter:   rate.NewLimiter(rate.Limit(cfg.ReviewRate), int(cfg.ReviewRate)*3),
		boxes:     map[string]*box{},
		ready:     map[string]time.Time{},
		forgotten: map[string]time.Time{},
		clients:   map[string]*clientLimiter{},
	}
}

// allowClient applies the per-client limit, keyed by the source IP (every
// runner pod has its own).
func (s *Server) allowClient(r *http.Request) bool {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[ip]
	if !ok {
		if len(s.clients) > 1024 {
			for k, v := range s.clients {
				if now.Sub(v.seen) > clientIdleTTL {
					delete(s.clients, k)
				}
			}
		}
		c = &clientLimiter{l: rate.NewLimiter(perClientRate, perClientBurst)}
		s.clients[ip] = c
	}
	c.seen = now
	return c.l.AllowN(now, 1)
}

func (s *Server) boxFor(pod string) *box {
	b, ok := s.boxes[pod]
	if !ok {
		b = &box{filled: make(chan struct{}), created: time.Now()}
		s.boxes[pod] = b
	}
	return b
}

// Deposit stores the payload of a pod. It fails if a payload was already
// deposited or delivered for that pod.
func (s *Server) Deposit(pod, uid string, p Payload) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, gone := s.forgotten[pod]; gone {
		return errors.New("pod " + pod + " was deleted")
	}
	b := s.boxFor(pod)
	if b.payload != nil || b.delivered {
		return errors.New("a configuration was already given to pod " + pod)
	}
	b.uid = uid
	b.payload = &p
	close(b.filled)
	return nil
}

// Pending reports a payload deposited and not yet delivered.
func (s *Server) Pending(pod string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.boxes[pod]
	return ok && b.payload != nil
}

// Delivered reports a configuration already handed to the pod's agent.
func (s *Server) Delivered(pod string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.boxes[pod]
	return ok && b.delivered
}

// Ready returns when the agent of a pod last said it was ready.
func (s *Server) Ready(pod string) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.ready[pod]
	return t, ok
}

// Forget drops everything known about a pod (deleted pod).
func (s *Server) Forget(pod string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.boxes[pod]; ok {
		b.payload = nil
	}
	delete(s.boxes, pod)
	delete(s.ready, pod)
	now := time.Now()
	for k, t := range s.forgotten {
		if now.Sub(t) > forgottenTTL {
			delete(s.forgotten, k)
		}
	}
	s.forgotten[pod] = now
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/ready", s.handleReady)
	mux.HandleFunc("GET /v1/claim", s.handleClaim)
	return mux
}

// authenticate returns the managed pod the request comes from.
func (s *Server) authenticate(r *http.Request) (*corev1.Pod, int) {
	h := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(h, "Bearer ")
	if !ok || token == "" || len(token) > 16<<10 {
		return nil, http.StatusUnauthorized
	}
	if !s.allowClient(r) || !s.limiter.Allow() {
		return nil, http.StatusTooManyRequests
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	id, err := s.cfg.Reviewer.Review(ctx, token)
	if err != nil {
		if !errors.Is(err, ErrUnauthenticated) {
			s.cfg.Logger.Warn("token review failed", "error", err)
			return nil, http.StatusServiceUnavailable
		}
		return nil, http.StatusUnauthorized
	}
	if id.Namespace != s.cfg.Namespace {
		return nil, http.StatusForbidden
	}
	pod, ok := s.cfg.Lookup(id.PodName)
	if !ok || string(pod.UID) != id.PodUID || !s.cfg.Managed(pod) {
		return nil, http.StatusForbidden
	}
	return pod, 0
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	pod, status := s.authenticate(r)
	if status != 0 {
		http.Error(w, http.StatusText(status), status)
		return
	}
	s.mu.Lock()
	s.ready[pod.Name] = time.Now()
	s.mu.Unlock()
	if s.cfg.OnReady != nil {
		s.cfg.OnReady(pod.Name)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleClaim(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	pod, status := s.authenticate(r)
	if status != 0 {
		http.Error(w, http.StatusText(status), status)
		return
	}
	wait := s.cfg.MaxWait
	if v := r.URL.Query().Get("wait"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= 0 && d < wait {
			wait = d
		}
	}
	s.mu.Lock()
	b := s.boxFor(pod.Name)
	if b.delivered {
		s.mu.Unlock()
		http.Error(w, "configuration already delivered", http.StatusGone)
		return
	}
	filled := b.filled
	s.mu.Unlock()

	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-filled:
	case <-timer.C:
		w.WriteHeader(http.StatusNoContent)
		return
	case <-r.Context().Done():
		return
	}

	s.mu.Lock()
	b, ok := s.boxes[pod.Name]
	if !ok || b.payload == nil || b.delivered || b.uid != string(pod.UID) {
		s.mu.Unlock()
		http.Error(w, "no configuration for this pod", http.StatusGone)
		return
	}
	payload := *b.payload
	b.payload = nil
	b.delivered = true
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		s.cfg.Logger.Warn("claim response not written", "pod", pod.Name, "error", err)
		return
	}
	if s.cfg.OnClaimed != nil {
		s.cfg.OnClaimed(pod.Name, string(pod.UID), time.Since(start))
	}
}
