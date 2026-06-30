// Package scaleset package provides a client to interact with GitHub Scale Set APIs.
package scaleset

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/go-retryablehttp"
)

const (
	runnerEndpoint   = "_apis/distributedtask/pools/0/agents"
	scaleSetEndpoint = "_apis/runtime/runnerscalesets"
)

var buildInfo clientBuildInfo

func init() {
	packageVersion, commitSHA := detectModuleVersionAndCommit()
	buildInfo = clientBuildInfo{
		version:   packageVersion,
		commitSHA: commitSHA,
	}
}

// HeaderScaleSetMaxCapacity is used to propagate the scale set max
// capacity when polling for messages.
const HeaderScaleSetMaxCapacity = "X-ScaleSetMaxCapacity"

// Client implements a GitHub Actions Scale Set client.
type Client struct {
	systemInfoMu sync.RWMutex
	adminTokenMu sync.RWMutex
	refreshMu    sync.Mutex

	// admin session info
	actionsServiceAdminToken actionsServiceAdminToken

	creds  actionsAuth
	config gitHubConfig

	commonClient
}

type clientBuildInfo struct {
	version   string
	commitSHA string
}

type debugInfo struct {
	HasProxy   bool   `json:"has_proxy"`
	HasRootCA  bool   `json:"has_root_ca"`
	SystemInfo string `json:"system_info"`
}

// DebugInfo returns a JSON string containing debug information about the client,
// including whether a proxy or custom root CA is configured, and the current system info.
// This method is intended for diagnostic and troubleshooting purposes.
func (c *Client) DebugInfo() string {
	info := debugInfo{
		HasProxy:   c.proxyFunc != nil,
		HasRootCA:  c.rootCAs != nil,
		SystemInfo: c.userAgentString(),
	}

	b, _ := json.Marshal(info)
	return string(b)
}

// GitHubAppAuth contains the GitHub App authentication credentials. All fields are required.
type GitHubAppAuth struct {
	// ClientID is the Client ID of the application (app id also works)
	ClientID string
	// InstallationID is the installation ID of the GitHub App
	InstallationID int64
	// PrivateKey is the private key of the GitHub App in PEM format
	PrivateKey string
}

// Validate returns an error if any required field is missing.
func (a *GitHubAppAuth) Validate() error {
	if a.ClientID == "" {
		return fmt.Errorf("client ID is required")
	}
	if a.InstallationID == 0 {
		return fmt.Errorf("app installation ID is required")
	}
	if a.PrivateKey == "" {
		return fmt.Errorf("app private key is required")
	}
	return nil
}

type actionsAuth struct {
	// token is a GitHub PAT (mutually exclusive with jwtProvider).
	token string
	// jwtProvider creates JWTs for GitHub App auth.
	jwtProvider JWTProvider
	// installationID is the GitHub App installation ID (used with jwtProvider).
	installationID int64
}

// validate does the basic validation check, ensuring that
// either GitHub App credentials (a JWT provider with an installation ID)
// or a personal access token is provided.
//
// This method does not validate the credentials against GitHub, so it does not
// check if the credentials are correct or have the necessary permissions.
func (a actionsAuth) validate() error {
	if a.token == "" && a.jwtProvider == nil {
		return fmt.Errorf("either GitHub App credentials or personal access token is required")
	}
	if a.token != "" && a.jwtProvider != nil {
		return fmt.Errorf("cannot provide both GitHub App credentials and personal access token")
	}
	if a.jwtProvider != nil && a.installationID == 0 {
		return fmt.Errorf("app installation ID is required")
	}
	return nil
}

// ProxyFunc defines the function signature for a proxy function.
type ProxyFunc func(req *http.Request) (*url.URL, error)

// SystemInfo contains information about the system that uses the
// scaleset client.
//
// For example, when Actions Runner Controller uses the scaleset API,
// it will set the following:
// - System: "actions-runner-controller"
// - Version: "release-version"
// - CommitSHA: "sha-of-the-release-commit"
// - Subsystem: "listener" or "controller"
type SystemInfo struct {
	// System is the name of the scale set implementation
	System string `json:"system"`
	// Version is the version of the client
	Version string `json:"version"`
	// CommitSHA is the git commit SHA of the client
	CommitSHA string `json:"commit_sha"`
	// ScaleSetID is the ID of the scale set
	ScaleSetID int `json:"scale_set_id"`
	// Subsystem is the subsystem such as listener, controller, etc.
	// Each system may pick its own subsystem name.
	Subsystem string `json:"subsystem"`
}

type ClientWithGitHubAppConfig struct {
	GitHubConfigURL string
	GitHubAppAuth   GitHubAppAuth
	SystemInfo      SystemInfo
}

// NewClientWithGitHubApp creates a new Client using GitHub App credentials.
func NewClientWithGitHubApp(config ClientWithGitHubAppConfig, options ...HTTPOption) (*Client, error) {
	if err := config.GitHubAppAuth.Validate(); err != nil {
		return nil, fmt.Errorf("invalid credentials: %w", err)
	}

	provider, err := newPEMJWTProvider(config.GitHubAppAuth.ClientID, config.GitHubAppAuth.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials: %w", err)
	}

	return newClient(
		config.SystemInfo,
		config.GitHubConfigURL,
		actionsAuth{
			jwtProvider:    provider,
			installationID: config.GitHubAppAuth.InstallationID,
		},
		options...,
	)
}

// NewClientWithPersonalAccessTokenConfig contains the configuration for creating a new Client using a personal access token.
type NewClientWithPersonalAccessTokenConfig struct {
	GitHubConfigURL     string
	PersonalAccessToken string
	SystemInfo          SystemInfo
}

// NewClientWithPersonalAccessToken creates a new Client using a personal access token.
func NewClientWithPersonalAccessToken(config NewClientWithPersonalAccessTokenConfig, options ...HTTPOption) (*Client, error) {
	return newClient(
		config.SystemInfo,
		config.GitHubConfigURL,
		actionsAuth{
			token: config.PersonalAccessToken,
		},
		options...,
	)
}

// ClientWithJWTProviderConfig contains the configuration for creating a new Client
// using a custom JWTProvider for GitHub App authentication.
type ClientWithJWTProviderConfig struct {
	GitHubConfigURL string
	InstallationID  int64
	SystemInfo      SystemInfo
}

// NewClientWithJWTProvider creates a new Client using a custom JWTProvider for GitHub App
// authentication. This enables KMS-backed signing where private key material never
// leaves the secure boundary.
func NewClientWithJWTProvider(config ClientWithJWTProviderConfig, provider JWTProvider, options ...HTTPOption) (*Client, error) {
	if provider == nil {
		return nil, fmt.Errorf("JWT provider is required")
	}
	if config.InstallationID == 0 {
		return nil, fmt.Errorf("installation ID is required")
	}
	return newClient(
		config.SystemInfo,
		config.GitHubConfigURL,
		actionsAuth{
			jwtProvider:    provider,
			installationID: config.InstallationID,
		},
		options...,
	)
}

func newClient(systemInfo SystemInfo, githubConfigURL string, creds actionsAuth, options ...HTTPOption) (*Client, error) {
	config, err := parseGitHubConfigFromURL(githubConfigURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse githubConfigURL: %w", err)
	}

	if err := creds.validate(); err != nil {
		return nil, fmt.Errorf("invalid credentials: %w", err)
	}

	httpClientOption := httpClientOption{
		retryMax:     4,
		retryWaitMax: 30 * time.Second,
	}
	httpClientOption.defaults()
	for _, option := range options {
		option(&httpClientOption)
	}

	commonClient := newCommonClient(
		systemInfo,
		httpClientOption,
	)

	ac := &Client{
		creds:        creds,
		config:       *config,
		commonClient: *commonClient,
	}

	return ac, nil
}

// SetSystemInfo updates the information about the system.
func (c *Client) SetSystemInfo(info SystemInfo) {
	c.systemInfoMu.Lock()
	defer c.systemInfoMu.Unlock()
	c.setSystemInfo(info)
}

// SystemInfo returns the current system info that the client
// has configured.
func (c *Client) SystemInfo() SystemInfo {
	c.systemInfoMu.RLock()
	defer c.systemInfoMu.RUnlock()
	return c.systemInfo
}

func (c *Client) userAgentString() string {
	c.systemInfoMu.RLock()
	defer c.systemInfoMu.RUnlock()
	return c.userAgent
}

type userAgent struct {
	SystemInfo
	BuildVersion   string `json:"build_version"`
	BuildCommitSHA string `json:"build_commit_sha"`
	Kind           string `json:"kind"`
}

func (c *Client) newGitHubAPIRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	u := c.config.gitHubAPIURL(path)
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("failed to create new GitHub API request: %w", err)
	}

	req.Header.Set("User-Agent", c.userAgentString())

	return req, nil
}

func (c *Client) newActionsServiceRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	return c.newActionsServiceRequestWithQuery(ctx, method, path, nil, body)
}

func (c *Client) newActionsServiceRequestWithQuery(ctx context.Context, method, path string, query url.Values, body io.Reader) (*http.Request, error) {
	adminToken, err := c.updateTokenIfNeeded(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to issue update token if needed: %w", err)
	}

	u, err := adminToken.requestURL(path, query)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create new request with context: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", adminToken.authorizationHeader)
	req.Header.Set("User-Agent", c.userAgentString())

	return req, nil
}

type actionsServiceAdminToken struct {
	token               string
	authorizationHeader string
	expiresAt           time.Time
	url                 string
}

func (t actionsServiceAdminToken) requestURL(path string, query url.Values) (string, error) {
	pathQuery := url.Values(nil)
	if pathOnly, rawQuery, ok := strings.Cut(path, "?"); ok {
		parsedQuery, err := url.ParseQuery(rawQuery)
		if err != nil {
			return "", fmt.Errorf("failed to parse query in path %q: %w", path, err)
		}
		path = pathOnly
		pathQuery = parsedQuery
	}

	requestURL := joinURLPath(t.url, path)

	q := make(url.Values, len(pathQuery)+len(query)+1)
	copyQueryValues(q, pathQuery)
	copyQueryValues(q, query)
	if q.Get("api-version") == "" {
		q.Set("api-version", "6.0-preview")
	}

	if rawQuery := q.Encode(); rawQuery != "" {
		requestURL += "?" + rawQuery
	}

	return requestURL, nil
}

func joinURLPath(base, path string) string {
	if base == "" {
		if path == "" {
			return ""
		}
		if strings.HasPrefix(path, "/") {
			return path
		}
		return "/" + path
	}
	if path == "" {
		return strings.TrimRight(base, "/")
	}
	if strings.HasPrefix(path, "/") {
		return strings.TrimRight(base, "/") + path
	}
	return strings.TrimRight(base, "/") + "/" + path
}

func copyQueryValues(dst, src url.Values) {
	for key, values := range src {
		dst[key] = append(dst[key], values...)
	}
}

// GetRunnerScaleSet fetches a runner scale set by its name within a runner group.
func (c *Client) GetRunnerScaleSet(ctx context.Context, runnerGroupID int, runnerScaleSetName string) (*RunnerScaleSet, error) {
	query := url.Values{
		"runnerGroupId": []string{strconv.Itoa(runnerGroupID)},
		"name":          []string{runnerScaleSetName},
	}
	req, err := c.newActionsServiceRequestWithQuery(ctx, http.MethodGet, scaleSetEndpoint, query, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create new actions service request: %w", err)
	}

	resp, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to issue the request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("unexpected status code: %d", resp.StatusCode))
	}

	var runnerScaleSetList runnerScaleSetsResponse
	if err := json.NewDecoder(resp.Body).Decode(&runnerScaleSetList); err != nil {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("failed to decode runner scale set list: %w", err))
	}

	switch runnerScaleSetList.Count {
	case 1:
		return &runnerScaleSetList.RunnerScaleSets[0], nil
	case 0:
		return nil, nil
	default:
		return nil, newRequestResponseError(req, resp, fmt.Errorf("multiple runner scale sets found with name %q", runnerScaleSetName))
	}
}

// ListRunnerScaleSets returns every runner scale set in the given runner group.
func (c *Client) ListRunnerScaleSets(ctx context.Context, runnerGroupID int) ([]RunnerScaleSet, error) {
	query := url.Values{
		"runnerGroupId": []string{strconv.Itoa(runnerGroupID)},
	}
	req, err := c.newActionsServiceRequestWithQuery(ctx, http.MethodGet, scaleSetEndpoint, query, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create new actions service request: %w", err)
	}

	resp, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to issue the request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("unexpected status code: %d", resp.StatusCode))
	}

	var list runnerScaleSetsResponse
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("failed to decode runner scale set list: %w", err))
	}

	return list.RunnerScaleSets, nil
}

// GetRunnerScaleSetByID fetches a runner scale set by its ID.
func (c *Client) GetRunnerScaleSetByID(ctx context.Context, runnerScaleSetID int) (*RunnerScaleSet, error) {
	path := fmt.Sprintf("/%s/%d", scaleSetEndpoint, runnerScaleSetID)
	req, err := c.newActionsServiceRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create new actions service request: %w", err)
	}

	resp, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to issue the request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("unexpected status code: %d", resp.StatusCode))
	}

	var runnerScaleSet *RunnerScaleSet
	if err := json.NewDecoder(resp.Body).Decode(&runnerScaleSet); err != nil {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("failed to decode runner scale set: %w", err))
	}
	return runnerScaleSet, nil
}

// GetRunnerGroupByName fetches a runner group by its name.
func (c *Client) GetRunnerGroupByName(ctx context.Context, runnerGroup string) (*RunnerGroup, error) {
	query := url.Values{"groupName": []string{runnerGroup}}
	req, err := c.newActionsServiceRequestWithQuery(ctx, http.MethodGet, "/_apis/runtime/runnergroups/", query, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create new actions service request: %w", err)
	}

	resp, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to issue the request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("unexpected status code: %d", resp.StatusCode))
	}

	var runnerGroupList RunnerGroupList
	if err := json.NewDecoder(resp.Body).Decode(&runnerGroupList); err != nil {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("failed to decode runner group list: %w", err))
	}

	switch runnerGroupList.Count {
	case 1:
		return &runnerGroupList.RunnerGroups[0], nil
	case 0:
		return nil, newRequestResponseError(req, resp, fmt.Errorf("no runner group found with name %q", runnerGroup))
	default:
		return nil, newRequestResponseError(req, resp, fmt.Errorf("multiple runner group found with name %q", runnerGroup))
	}
}

// applyDefaultLabelTypes ensures that each label in the runner scale set has a Type set,
// defaulting to "System" when the field is empty. This encapsulates the legacy API detail
// so that callers do not need to manage label types explicitly.
func applyDefaultLabelTypes(runnerScaleSet *RunnerScaleSet) {
	for i := range runnerScaleSet.Labels {
		if runnerScaleSet.Labels[i].Type == "" {
			runnerScaleSet.Labels[i].Type = "System"
		}
	}
}

func ensureLabels(runnerScaleSet *RunnerScaleSet) error {
	if len(runnerScaleSet.Labels) > 0 {
		return nil
	}

	if runnerScaleSet.Name == "" {
		return errors.New("runner scale set must have a name or at least one label")
	}

	runnerScaleSet.Labels = []Label{{Name: runnerScaleSet.Name, Type: "System"}}
	return nil
}

// CreateRunnerScaleSet creates a new runner scale set. Note that runner scale set names must be unique within a runner group.
func (c *Client) CreateRunnerScaleSet(ctx context.Context, runnerScaleSet *RunnerScaleSet) (*RunnerScaleSet, error) {
	if err := ensureLabels(runnerScaleSet); err != nil {
		return nil, fmt.Errorf("validating runner scale set: %w", err)
	}
	applyDefaultLabelTypes(runnerScaleSet)

	body, err := json.Marshal(runnerScaleSet)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal runner scale set: %w", err)
	}

	req, err := c.newActionsServiceRequest(ctx, http.MethodPost, scaleSetEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create new actions service request: %w", err)
	}

	resp, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to issue the request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("unexpected status code: %d", resp.StatusCode))
	}

	var createdRunnerScaleSet RunnerScaleSet
	if err := json.NewDecoder(resp.Body).Decode(&createdRunnerScaleSet); err != nil {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("failed to decode created runner scale set: %w", err))
	}

	return &createdRunnerScaleSet, nil
}

// UpdateRunnerScaleSet updates an existing runner scale set.
func (c *Client) UpdateRunnerScaleSet(ctx context.Context, runnerScaleSetID int, runnerScaleSet *RunnerScaleSet) (*RunnerScaleSet, error) {
	applyDefaultLabelTypes(runnerScaleSet)

	path := fmt.Sprintf("%s/%d", scaleSetEndpoint, runnerScaleSetID)

	body, err := json.Marshal(runnerScaleSet)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal runner scale set: %w", err)
	}

	req, err := c.newActionsServiceRequest(ctx, http.MethodPatch, path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create new actions service request: %w", err)
	}

	resp, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to issue the request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("unexpected status code: %d", resp.StatusCode))
	}

	var updatedRunnerScaleSet RunnerScaleSet
	if err := json.NewDecoder(resp.Body).Decode(&updatedRunnerScaleSet); err != nil {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("failed to decode updated runner scale set: %w", err))
	}
	return &updatedRunnerScaleSet, nil
}

// DeleteRunnerScaleSet deletes a runner scale set by its ID.
func (c *Client) DeleteRunnerScaleSet(ctx context.Context, runnerScaleSetID int) error {
	path := fmt.Sprintf("/%s/%d", scaleSetEndpoint, runnerScaleSetID)
	req, err := c.newActionsServiceRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return fmt.Errorf("failed to create new actions service request: %w", err)
	}

	resp, err := c.do(req)
	if err != nil {
		return fmt.Errorf("failed to issue the request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return newRequestResponseError(req, resp, fmt.Errorf("unexpected status code: %d", resp.StatusCode))
	}

	return nil
}

func parseRunnerScaleSetMessageResponse(respBody io.Reader) (*RunnerScaleSetMessage, error) {
	var messageResponse runnerScaleSetMessageResponse
	if err := json.NewDecoder(respBody).Decode(&messageResponse); err != nil {
		return nil, fmt.Errorf("failed to decode runner scale set message response: %w", err)
	}

	if messageResponse.MessageType != "RunnerScaleSetJobMessages" {
		return nil, fmt.Errorf("unsupported message type: %s", messageResponse.MessageType)
	}

	message := &RunnerScaleSetMessage{
		MessageID:  messageResponse.MessageID,
		Statistics: messageResponse.Statistics,
	}

	var batchedMessages []json.RawMessage
	if len(messageResponse.Body) > 0 {
		if err := json.Unmarshal([]byte(messageResponse.Body), &batchedMessages); err != nil {
			return nil, fmt.Errorf("failed to unmarshal batched messages: %w", err)
		}
	}

	for _, msg := range batchedMessages {
		var messageType JobMessageType
		if err := json.Unmarshal(msg, &messageType); err != nil {
			return nil, fmt.Errorf("failed to decode job message type: %w", err)
		}

		switch messageType.MessageType {
		case MessageTypeJobAvailable:
			var jobAvailable JobAvailable
			if err := json.Unmarshal(msg, &jobAvailable); err != nil {
				return nil, fmt.Errorf("failed to decode job available: %w", err)
			}

			message.JobAvailableMessages = append(message.JobAvailableMessages, &jobAvailable)

		case MessageTypeJobAssigned:
			var jobAssigned JobAssigned
			if err := json.Unmarshal(msg, &jobAssigned); err != nil {
				return nil, fmt.Errorf("failed to decode job assigned: %w", err)
			}

			message.JobAssignedMessages = append(message.JobAssignedMessages, &jobAssigned)

		case MessageTypeJobStarted:
			var jobStarted JobStarted
			if err := json.Unmarshal(msg, &jobStarted); err != nil {
				return nil, fmt.Errorf("could not decode job started message. %w", err)
			}

			message.JobStartedMessages = append(message.JobStartedMessages, &jobStarted)

		case MessageTypeJobCompleted:
			var jobCompleted JobCompleted
			if err := json.Unmarshal(msg, &jobCompleted); err != nil {
				return nil, fmt.Errorf("failed to decode job completed: %w", err)
			}

			message.JobCompletedMessages = append(message.JobCompletedMessages, &jobCompleted)

		default:
		}
	}

	return message, nil
}

// MessageSessionClient creates a new MessageSessionClient for the specified runner scale set ID and owner.
//
// It exposes client options that could be overwritten, providing ability to specify different retry policies or TLS settings, proxy, etc.
func (c *Client) MessageSessionClient(ctx context.Context, runnerScaleSetID int, owner string, options ...HTTPOption) (*MessageSessionClient, error) {
	// Copy original options
	httpClientOption := c.httpClientOption
	// Apply overwrites
	for _, option := range options {
		option(&httpClientOption)
	}
	// Instantiate a new common client
	commonClient := newCommonClient(
		c.SystemInfo(),
		httpClientOption,
	)

	client := &MessageSessionClient{
		innerClient:  c,
		commonClient: commonClient,
		owner:        owner,
		scaleSetID:   runnerScaleSetID,
	}

	if err := client.createMessageSession(ctx); err != nil {
		return nil, fmt.Errorf("failed to create message session: %w", err)
	}

	return client, nil
}

// GenerateJitRunnerConfig generates a JIT runner configuration for the specified runner scale set. This returns an encoded
// configuration that can be used to directly start a new runner.
func (c *Client) GenerateJitRunnerConfig(ctx context.Context, jitRunnerSetting *RunnerScaleSetJitRunnerSetting, scaleSetID int) (*RunnerScaleSetJitRunnerConfig, error) {
	path := fmt.Sprintf("/%s/%d/generatejitconfig", scaleSetEndpoint, scaleSetID)

	body, err := json.Marshal(jitRunnerSetting)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal runner settings: %w", err)
	}

	req, err := c.newActionsServiceRequest(ctx, http.MethodPost, path, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create new actions service request: %w", err)
	}

	resp, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to issue the request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("unexpected status code: %d", resp.StatusCode))
	}

	var runnerJitConfig *RunnerScaleSetJitRunnerConfig
	if err := json.NewDecoder(resp.Body).Decode(&runnerJitConfig); err != nil {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("failed to decode runner JIT config: %w", err))
	}

	return runnerJitConfig, nil
}

// GetRunner fetches a runner by its ID. This can be used to check if a runner exists.
func (c *Client) GetRunner(ctx context.Context, runnerID int) (*RunnerReference, error) {
	path := fmt.Sprintf("/%s/%d", runnerEndpoint, runnerID)

	req, err := c.newActionsServiceRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create new actions service request: %w", err)
	}

	resp, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to issue the request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("unexpected status code: %d", resp.StatusCode))
	}

	var runnerReference *RunnerReference
	if err := json.NewDecoder(resp.Body).Decode(&runnerReference); err != nil {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("failed to decode runner reference: %w", err))
	}

	return runnerReference, nil
}

// GetRunnerByName fetches a runner by its name. This can be used to check if a runner exists.
func (c *Client) GetRunnerByName(ctx context.Context, runnerName string) (*RunnerReference, error) {
	query := url.Values{"agentName": []string{runnerName}}
	req, err := c.newActionsServiceRequestWithQuery(ctx, http.MethodGet, runnerEndpoint, query, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create new actions service request: %w", err)
	}

	resp, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to issue the request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("unexpected status code: %d", resp.StatusCode))
	}

	var runnerList *RunnerReferenceList
	if err := json.NewDecoder(resp.Body).Decode(&runnerList); err != nil {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("failed to decode runner reference list: %w", err))
	}

	switch runnerList.Count {
	case 1:
		return &runnerList.RunnerReferences[0], nil
	case 0:
		return nil, nil
	default:
		return nil, fmt.Errorf("multiple runners found with name %q", runnerName)
	}
}

// RemoveRunner removes a runner by its ID.
func (c *Client) RemoveRunner(ctx context.Context, runnerID int64) error {
	path := fmt.Sprintf("/%s/%d", runnerEndpoint, runnerID)

	req, err := c.newActionsServiceRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return fmt.Errorf("failed to create new actions service request: %w", err)
	}

	resp, err := c.do(req)
	if err != nil {
		return fmt.Errorf("failed to issue the request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return newRequestResponseError(req, resp, fmt.Errorf("unexpected status code: %d", resp.StatusCode))
	}

	return nil
}

type registrationToken struct {
	Token     *string    `json:"token,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

func (c *Client) getRunnerRegistrationToken(ctx context.Context) (*registrationToken, error) {
	path, err := createRegistrationTokenPath(&c.config)
	if err != nil {
		return nil, fmt.Errorf("failed to create registration token path: %w", err)
	}

	var buf bytes.Buffer
	req, err := c.newGitHubAPIRequest(ctx, http.MethodPost, path, &buf)
	if err != nil {
		return nil, fmt.Errorf("failed to create new GitHub API request: %w", err)
	}

	bearerToken := ""

	if c.creds.token != "" {
		bearerToken = fmt.Sprintf("Bearer %v", c.creds.token)
	} else {
		accessToken, err := c.fetchAccessToken(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch access token: %w", err)
		}

		bearerToken = fmt.Sprintf("Bearer %v", accessToken.Token)
	}

	req.Header.Set("Content-Type", "application/vnd.github.v3+json")
	req.Header.Set("Authorization", bearerToken)

	c.logger.Info("getting runner registration token", "registrationTokenURL", req.URL.String())

	resp, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to issue the request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("failed to get runner registration token (%v)", resp.Status))
	}

	var registrationToken *registrationToken
	if err := json.NewDecoder(resp.Body).Decode(&registrationToken); err != nil {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("failed to decode runner registration token: %w", err))
	}

	return registrationToken, nil
}

// Format: https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app
type accessToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (c *Client) fetchAccessToken(ctx context.Context) (*accessToken, error) {
	accessTokenJWT, err := c.creds.jwtProvider.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWT for GitHub App auth: %w", err)
	}

	path := fmt.Sprintf("/app/installations/%v/access_tokens", c.creds.installationID)
	req, err := c.newGitHubAPIRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create new GitHub API request: %w", err)
	}

	req.Header.Set("Content-Type", "application/vnd.github+json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessTokenJWT))

	c.logger.Info("getting access token for GitHub App auth", "accessTokenURL", req.URL.String())

	resp, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to issue the request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("failed to get access token for GitHub App auth (%v)", resp.Status))
	}

	// Format: https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app
	var accessToken accessToken
	if err := json.NewDecoder(resp.Body).Decode(&accessToken); err != nil {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("failed to decode access token for GitHub App auth: %w", err))
	}
	return &accessToken, nil
}

type actionsServiceAdminConnection struct {
	ActionsServiceURL *string `json:"url,omitempty"`
	AdminToken        *string `json:"token,omitempty"`
}

func (c *Client) getActionsServiceAdminConnection(ctx context.Context, rt *registrationToken) (*actionsServiceAdminConnection, error) {
	path := "/actions/runner-registration"

	body := struct {
		URL         string `json:"url"`
		RunnerEvent string `json:"runner_event"`
	}{
		URL:         c.config.configURL.String(),
		RunnerEvent: "register",
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)

	if err := enc.Encode(body); err != nil {
		return nil, fmt.Errorf("failed to encode body: %w", err)
	}

	req, err := c.newGitHubAPIRequest(ctx, http.MethodPost, path, &buf)
	if err != nil {
		return nil, fmt.Errorf("failed to create new GitHub API request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("RemoteAuth %s", *rt.Token))

	c.logger.Info("getting Actions tenant URL and JWT", "registrationURL", req.URL.String())

	adminConnection, err := c.getActionsServiceAdminConnectionRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get actions service admin connection: %w", err)
	}

	return adminConnection, nil
}

func (c *Client) getActionsServiceAdminConnectionRequest(req *http.Request) (*actionsServiceAdminConnection, error) {
	retryableClient, err := c.newRetryableHTTPClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create retryable HTTP client: %w", err)
	}

	retryableClient.CheckRetry = func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		if resp != nil && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
			// Retry on 401 Unauthorized and 403 Forbidden
			return true, nil
		}

		return retryablehttp.DefaultRetryPolicy(ctx, resp, err)
	}
	// Adding custom error handler to also return response in case of error
	retryableClient.ErrorHandler = func(resp *http.Response, err error, numTries int) (*http.Response, error) {
		return resp, err
	}
	httpClient := retryableClient.StandardClient()

	resp, err := sendRequest(httpClient, req)
	if err != nil {
		return nil, fmt.Errorf("failed to issue the request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("unexpected status code: %d", resp.StatusCode))
	}

	var actionsServiceAdminConnection actionsServiceAdminConnection
	if err := json.NewDecoder(resp.Body).Decode(&actionsServiceAdminConnection); err != nil {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("failed to decode actions service admin connection: %w", err))
	}
	if actionsServiceAdminConnection.ActionsServiceURL == nil || *actionsServiceAdminConnection.ActionsServiceURL == "" {
		return nil, fmt.Errorf("actions service admin connection missing url")
	}
	if actionsServiceAdminConnection.AdminToken == nil || *actionsServiceAdminConnection.AdminToken == "" {
		return nil, fmt.Errorf("actions service admin connection missing token")
	}

	return &actionsServiceAdminConnection, nil
}

func createRegistrationTokenPath(config *gitHubConfig) (string, error) {
	switch config.scope {
	case gitHubScopeOrganization:
		path := fmt.Sprintf("/orgs/%s/actions/runners/registration-token", config.organization)
		return path, nil

	case gitHubScopeEnterprise:
		path := fmt.Sprintf("/enterprises/%s/actions/runners/registration-token", config.enterprise)
		return path, nil

	case gitHubScopeRepository:
		path := fmt.Sprintf("/repos/%s/%s/actions/runners/registration-token", config.organization, config.repository)
		return path, nil

	default:
		return "", fmt.Errorf("unknown scope for config url: %s", config.configURL)
	}
}

// Returns slice of body without utf-8 byte order mark.
// If BOM does not exist body is returned unchanged.
func trimByteOrderMark(body []byte) []byte {
	return bytes.TrimPrefix(body, []byte("\xef\xbb\xbf"))
}

func actionsServiceAdminTokenExpiresAt(jwtToken string) (time.Time, error) {
	type JwtClaims struct {
		jwt.RegisteredClaims
	}
	token, _, err := jwt.NewParser().ParseUnverified(jwtToken, &JwtClaims{})
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse jwt token: %w", err)
	}

	if claims, ok := token.Claims.(*JwtClaims); ok {
		return claims.ExpiresAt.Time, nil
	}

	return time.Time{}, fmt.Errorf("failed to parse token claims to get expire at")
}

func (c *Client) updateTokenIfNeeded(ctx context.Context) (actionsServiceAdminToken, error) {
	if token, ok := c.actionsServiceAdminTokenSnapshot(); ok {
		return token, nil
	}

	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()

	if token, ok := c.actionsServiceAdminTokenSnapshot(); ok {
		return token, nil
	}

	configURL := ""
	if c.config.configURL != nil {
		configURL = c.config.configURL.String()
	}
	if c.logger != nil {
		c.logger.Info("refreshing token", "githubConfigUrl", configURL)
	}
	rt, err := c.getRunnerRegistrationToken(ctx)
	if err != nil {
		return actionsServiceAdminToken{}, fmt.Errorf("failed to get runner registration token on refresh: %w", err)
	}

	adminConnInfo, err := c.getActionsServiceAdminConnection(ctx, rt)
	if err != nil {
		return actionsServiceAdminToken{}, fmt.Errorf("failed to get actions service admin connection on refresh: %w", err)
	}
	if adminConnInfo == nil || adminConnInfo.ActionsServiceURL == nil || adminConnInfo.AdminToken == nil {
		return actionsServiceAdminToken{}, fmt.Errorf("failed to get actions service admin connection on refresh: missing url or token")
	}

	expiresAt, err := actionsServiceAdminTokenExpiresAt(*adminConnInfo.AdminToken)
	if err != nil {
		return actionsServiceAdminToken{}, fmt.Errorf("failed to get admin token expire at on refresh: %w", err)
	}
	token := actionsServiceAdminToken{
		token:               *adminConnInfo.AdminToken,
		authorizationHeader: "Bearer " + *adminConnInfo.AdminToken,
		expiresAt:           expiresAt,
		url:                 *adminConnInfo.ActionsServiceURL,
	}

	c.adminTokenMu.Lock()
	c.actionsServiceAdminToken = token
	c.adminTokenMu.Unlock()

	return token, nil
}

func (c *Client) actionsServiceAdminTokenSnapshot() (actionsServiceAdminToken, bool) {
	c.adminTokenMu.RLock()
	defer c.adminTokenMu.RUnlock()

	token := c.actionsServiceAdminToken
	if token.authorizationHeader == "" && token.token != "" {
		token.authorizationHeader = fmt.Sprintf("Bearer %s", token.token)
	}

	if token.expiresAt.IsZero() || time.Now().Add(60*time.Second).After(token.expiresAt) {
		return actionsServiceAdminToken{}, false
	}

	return token, true
}

func detectModuleVersionAndCommit() (version string, commit string) {
	const modulePath = "github.com/actions/scaleset"

	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown", "unknown"
	}

	// If we are the main module (built from source in this repo), use vcs settings.
	if bi.Main.Path == modulePath {
		version = bi.Main.Version
		commit = "unknown"
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				commit = s.Value
			case "vcs.modified":
				// Optionally append a marker if the tree was dirty.
				if s.Value == "true" && commit != "unknown" {
					commit = commit + "-dirty"
				}
			}
		}
		if version == "" || version == "(devel)" {
			version = "devel"
		}
		if commit == "" {
			commit = "unknown"
		}
		return version, commit
	}

	// Otherwise search dependency list for our module.
	for _, dep := range bi.Deps {
		if dep.Path == modulePath {
			version = dep.Version
			commit = extractCommitFromVersion(version)
			return version, commit
		}
	}

	return "unknown", "unknown"
}

// new: parse commit from a pseudo-version (e.g. v0.0.0-20251031142550-8104f571eba7)
func extractCommitFromVersion(v string) string {
	// Semantic versions without pseudo part can't yield commit; return v directly.
	// Pseudo format: <base>-<timestamp>-<commit>
	parts := strings.Split(v, "-")
	if len(parts) < 3 {
		return v
	}
	commit := parts[len(parts)-1]
	if len(commit) >= 7 {
		return commit
	}
	return v
}
