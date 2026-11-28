// Package gh is the only package that talks to GitHub. It wraps the scaleset
// library of this module (scale sets, message sessions, JIT configurations)
// and the few REST calls the dispatcher needs (repository visibility, runner
// listing, installation repositories).
//
// Every client shares one *http.Client. Requests to the REST API host go
// through a single rate limiter, so a hundred queues starting together do not
// burst the account quota.
package gh

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/actions/scaleset"
	"github.com/actions/scaleset/listener"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/time/rate"
)

// DefaultRunnerGroupID is the runner group of repository-level scale sets.
const DefaultRunnerGroupID = 1

// Session is an open message session on one scale set.
type Session interface {
	listener.Client
	Close(ctx context.Context) error
}

// JIT is a just-in-time runner registration.
type JIT struct {
	RunnerID int64
	Config   string
}

// Runner is a self-hosted runner as listed by the REST API.
type Runner struct {
	ID     int64
	Name   string
	Status string // online | offline
	Busy   bool
}

// API is what the rest of the dispatcher needs from GitHub.
type API interface {
	EnsureScaleSet(ctx context.Context, repo, name string) (id int, created bool, err error)
	OpenSession(ctx context.Context, repo string, scaleSetID int, owner string) (Session, error)
	GenerateJIT(ctx context.Context, repo string, scaleSetID int, runnerName string) (JIT, error)
	RemoveRunner(ctx context.Context, repo string, runnerID int64) error
	ListRunners(ctx context.Context, repo string) ([]Runner, error)
	DeleteScaleSet(ctx context.Context, repo string, scaleSetID int) error
	IsPublic(ctx context.Context, repo string) (bool, error)
	InstallationRepos(ctx context.Context) ([]string, error)
}

// IsNotFound reports a deleted scale set or runner.
func IsNotFound(err error) bool {
	return errors.Is(err, scaleset.NotFoundError) || errors.Is(err, scaleset.RunnerNotFoundError)
}

// IsConflict reports a session already held by another client (an ARC
// listener still running for the same scale set, typically).
func IsConflict(err error) bool {
	if errors.Is(err, scaleset.ConflictError) {
		return true
	}
	return err != nil && strings.Contains(err.Error(), "SessionConflictException")
}

// IsJobStillRunning reports a runner that cannot be removed yet.
func IsJobStillRunning(err error) bool {
	return errors.Is(err, scaleset.JobStillRunningError)
}

// Credentials are read from files mounted by the chart, never from the
// catalog. They are re-read when the client is built.
type Credentials struct {
	AudienceJWTFile string
	AppClientID     string
	InstallationID  int64
	PrivateKeyFile  string
}

// Config builds a Client.
type Config struct {
	Owner       string
	GitHubURL   string
	APIURL      string
	Credentials Credentials
	SystemInfo  scaleset.SystemInfo
	// RESTRate and RESTBurst bound the requests sent to the REST API host.
	RESTRate  float64
	RESTBurst int
	Logger    *slog.Logger
	// OnRateLimit receives X-RateLimit-Remaining of every REST response.
	OnRateLimit func(remaining int)
	// HTTPClient replaces the shared client (tests).
	HTTPClient *http.Client
}

// Client implements API with one scaleset client per repository.
type Client struct {
	cfg     Config
	http    *http.Client
	logger  *slog.Logger
	pat     string
	appKey  *rsa.PrivateKey
	mu      sync.Mutex
	clients map[string]*scaleset.Client

	instMu      sync.Mutex
	instToken   string
	instExpires time.Time
}

// New builds a Client. It fails when the credential files cannot be read.
func New(cfg Config) (*Client, error) {
	if cfg.GitHubURL == "" {
		cfg.GitHubURL = "https://github.com"
	}
	if cfg.APIURL == "" {
		cfg.APIURL = "https://api.github.com"
	}
	if cfg.RESTRate == 0 {
		cfg.RESTRate = 5
	}
	if cfg.RESTBurst == 0 {
		cfg.RESTBurst = 20
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	c := &Client{cfg: cfg, logger: cfg.Logger, clients: map[string]*scaleset.Client{}}
	switch {
	case cfg.Credentials.AudienceJWTFile != "":
		raw, err := os.ReadFile(cfg.Credentials.AudienceJWTFile)
		if err != nil {
			return nil, fmt.Errorf("read GitHub token: %w", err)
		}
		c.pat = strings.TrimSpace(string(raw))
		if c.pat == "" {
			return nil, errors.New("GitHub token file is empty")
		}
	case cfg.Credentials.PrivateKeyFile != "":
		raw, err := os.ReadFile(cfg.Credentials.PrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("read GitHub App private key: %w", err)
		}
		key, err := jwt.ParseRSAPrivateKeyFromPEM(raw)
		if err != nil {
			return nil, fmt.Errorf("parse GitHub App private key: %w", err)
		}
		c.appKey = key
	default:
		return nil, errors.New("no GitHub credentials: set a token file or an App private key file")
	}

	base := cfg.HTTPClient
	if base == nil {
		base = scaleset.NewHTTPClient(scaleset.HTTPClientConfig{})
	}
	apiHost := ""
	if u, err := url.Parse(cfg.APIURL); err == nil {
		apiHost = u.Host
	}
	transport := base.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	c.http = &http.Client{
		Timeout: base.Timeout,
		Transport: &limitedTransport{
			base:        transport,
			host:        apiHost,
			limiter:     rate.NewLimiter(rate.Limit(cfg.RESTRate), cfg.RESTBurst),
			onRateLimit: cfg.OnRateLimit,
		},
	}
	return c, nil
}

// limitedTransport rate-limits the requests sent to the REST API host and
// reports the remaining quota. Long polls to the Actions service are not
// limited: each session holds one request open for about 50 seconds.
type limitedTransport struct {
	base        http.RoundTripper
	host        string
	limiter     *rate.Limiter
	onRateLimit func(int)
}

func (t *limitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != t.host {
		return t.base.RoundTrip(req)
	}
	if err := t.limiter.Wait(req.Context()); err != nil {
		return nil, err
	}
	resp, err := t.base.RoundTrip(req)
	if err == nil && t.onRateLimit != nil {
		if v := resp.Header.Get("X-RateLimit-Remaining"); v != "" {
			if n, perr := strconv.Atoi(v); perr == nil {
				t.onRateLimit(n)
			}
		}
	}
	return resp, err
}

func (c *Client) repoURL(repo string) string {
	return strings.TrimSuffix(c.cfg.GitHubURL, "/") + "/" + c.cfg.Owner + "/" + repo
}

// scalesetClient returns the cached client of a repository.
func (c *Client) scalesetClient(repo string) (*scaleset.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if sc, ok := c.clients[repo]; ok {
		return sc, nil
	}
	opts := []scaleset.HTTPOption{
		scaleset.WithHTTPClient(c.http),
		scaleset.WithLogger(c.logger.With("repo", repo)),
	}
	var (
		sc  *scaleset.Client
		err error
	)
	if c.pat != "" {
		sc, err = scaleset.NewClientWithPersonalAccessToken(scaleset.NewClientWithPersonalAccessTokenConfig{
			GitHubConfigURL:     c.repoURL(repo),
			PersonalAccessToken: c.pat,
			SystemInfo:          c.cfg.SystemInfo,
		}, opts...)
	} else {
		sc, err = scaleset.NewClientWithJWTProvider(scaleset.ClientWithJWTProviderConfig{
			GitHubConfigURL: c.repoURL(repo),
			InstallationID:  c.cfg.Credentials.InstallationID,
			SystemInfo:      c.cfg.SystemInfo,
		}, scaleset.JWTProviderFunc(c.appJWT), opts...)
	}
	if err != nil {
		return nil, fmt.Errorf("scaleset client for %s: %w", repo, err)
	}
	c.clients[repo] = sc
	return sc, nil
}

func (c *Client) appJWT(context.Context) (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    c.cfg.Credentials.AppClientID,
		IssuedAt:  jwt.NewNumericDate(now.Add(-60 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(now.Add(9 * time.Minute)),
	}
	return jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(c.appKey)
}

// EnsureScaleSet adopts the scale set of that name or creates it. Adoption
// lets the dispatcher take over a queue first created by ARC.
func (c *Client) EnsureScaleSet(ctx context.Context, repo, name string) (int, bool, error) {
	sc, err := c.scalesetClient(repo)
	if err != nil {
		return 0, false, err
	}
	existing, err := sc.GetRunnerScaleSet(ctx, DefaultRunnerGroupID, name)
	if err != nil {
		return 0, false, fmt.Errorf("get scale set %s: %w", name, err)
	}
	if existing != nil {
		return existing.ID, false, nil
	}
	created, err := sc.CreateRunnerScaleSet(ctx, &scaleset.RunnerScaleSet{
		Name:          name,
		RunnerGroupID: DefaultRunnerGroupID,
		Labels:        []scaleset.Label{{Name: name}},
		RunnerSetting: scaleset.RunnerSetting{DisableUpdate: true},
	})
	if err != nil {
		return 0, false, fmt.Errorf("create scale set %s: %w", name, err)
	}
	return created.ID, true, nil
}

// OpenSession opens a message session. It fails with a conflict when another
// client holds the session.
func (c *Client) OpenSession(ctx context.Context, repo string, scaleSetID int, owner string) (Session, error) {
	sc, err := c.scalesetClient(repo)
	if err != nil {
		return nil, err
	}
	return sc.MessageSessionClient(ctx, scaleSetID, owner)
}

// GenerateJIT registers a runner and returns its encoded configuration. The
// configuration is a secret until the runner consumes it.
func (c *Client) GenerateJIT(ctx context.Context, repo string, scaleSetID int, runnerName string) (JIT, error) {
	sc, err := c.scalesetClient(repo)
	if err != nil {
		return JIT{}, err
	}
	jit, err := sc.GenerateJitRunnerConfig(ctx, &scaleset.RunnerScaleSetJitRunnerSetting{Name: runnerName}, scaleSetID)
	if err != nil {
		return JIT{}, fmt.Errorf("generate JIT config for %s: %w", runnerName, err)
	}
	out := JIT{Config: jit.EncodedJITConfig}
	if jit.Runner != nil {
		out.RunnerID = int64(jit.Runner.ID)
	}
	return out, nil
}

// RemoveRunner unregisters a runner. A runner already gone is not an error.
func (c *Client) RemoveRunner(ctx context.Context, repo string, runnerID int64) error {
	sc, err := c.scalesetClient(repo)
	if err != nil {
		return err
	}
	if err := sc.RemoveRunner(ctx, runnerID); err != nil && !IsNotFound(err) {
		return err
	}
	return nil
}

// DeleteScaleSet deletes a scale set (test queues only; the dispatcher never
// deletes a queue on shutdown).
func (c *Client) DeleteScaleSet(ctx context.Context, repo string, scaleSetID int) error {
	sc, err := c.scalesetClient(repo)
	if err != nil {
		return err
	}
	return sc.DeleteRunnerScaleSet(ctx, scaleSetID)
}

// restToken returns the credential for the REST API.
func (c *Client) restToken(ctx context.Context) (string, error) {
	if c.pat != "" {
		return c.pat, nil
	}
	c.instMu.Lock()
	defer c.instMu.Unlock()
	if c.instToken != "" && time.Until(c.instExpires) > 5*time.Minute {
		return c.instToken, nil
	}
	appJWT, err := c.appJWT(ctx)
	if err != nil {
		return "", err
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	path := fmt.Sprintf("/app/installations/%d/access_tokens", c.cfg.Credentials.InstallationID)
	if err := c.rest(ctx, http.MethodPost, path, "Bearer "+appJWT, &out); err != nil {
		return "", fmt.Errorf("installation token: %w", err)
	}
	c.instToken, c.instExpires = out.Token, out.ExpiresAt
	return out.Token, nil
}

func (c *Client) rest(ctx context.Context, method, path, auth string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(c.cfg.APIURL, "/")+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Authorization", auth)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%s %s: %w", method, path, scaleset.NotFoundError)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s %s: HTTP %d", method, path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(body, out)
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	token, err := c.restToken(ctx)
	if err != nil {
		return err
	}
	scheme := "Bearer "
	if c.pat != "" {
		scheme = "token "
	}
	return c.rest(ctx, http.MethodGet, path, scheme+token, out)
}

// IsPublic tells whether a repository is public.
func (c *Client) IsPublic(ctx context.Context, repo string) (bool, error) {
	var out struct {
		Private    bool   `json:"private"`
		Visibility string `json:"visibility"`
	}
	if err := c.get(ctx, "/repos/"+c.cfg.Owner+"/"+repo, &out); err != nil {
		return false, err
	}
	return !out.Private, nil
}

// ListRunners lists the self-hosted runners of a repository.
func (c *Client) ListRunners(ctx context.Context, repo string) ([]Runner, error) {
	var all []Runner
	for page := 1; page <= 20; page++ {
		var out struct {
			TotalCount int `json:"total_count"`
			Runners    []struct {
				ID     int64  `json:"id"`
				Name   string `json:"name"`
				Status string `json:"status"`
				Busy   bool   `json:"busy"`
			} `json:"runners"`
		}
		path := fmt.Sprintf("/repos/%s/%s/actions/runners?per_page=100&page=%d", c.cfg.Owner, repo, page)
		if err := c.get(ctx, path, &out); err != nil {
			return nil, err
		}
		for _, r := range out.Runners {
			all = append(all, Runner{ID: r.ID, Name: r.Name, Status: r.Status, Busy: r.Busy})
		}
		if len(all) >= out.TotalCount || len(out.Runners) == 0 {
			break
		}
	}
	return all, nil
}

// InstallationRepos lists the repositories of the GitHub App installation
// that belong to the owner.
func (c *Client) InstallationRepos(ctx context.Context) ([]string, error) {
	if c.appKey == nil {
		return nil, errors.New("discovery needs GitHub App credentials")
	}
	var names []string
	for page := 1; page <= 20; page++ {
		var out struct {
			TotalCount   int `json:"total_count"`
			Repositories []struct {
				Name     string `json:"name"`
				Archived bool   `json:"archived"`
				Owner    struct {
					Login string `json:"login"`
				} `json:"owner"`
			} `json:"repositories"`
		}
		if err := c.get(ctx, fmt.Sprintf("/installation/repositories?per_page=100&page=%d", page), &out); err != nil {
			return nil, err
		}
		for _, r := range out.Repositories {
			if !r.Archived && strings.EqualFold(r.Owner.Login, c.cfg.Owner) {
				names = append(names, r.Name)
			}
		}
		if len(out.Repositories) == 0 || page*100 >= out.TotalCount {
			break
		}
	}
	return names, nil
}

var _ API = (*Client)(nil)
