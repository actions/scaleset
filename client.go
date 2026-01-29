// Package scaleset package provides a client to interact with GitHub Scale Set APIs.
package scaleset

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
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
	mu sync.Mutex // guards every public call

	// admin session info
	actionsServiceAdminToken          string
	actionsServiceAdminTokenExpiresAt time.Time
	actionsServiceURL                 string

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
	c.mu.Lock()
	defer c.mu.Unlock()
	info := debugInfo{
		HasProxy:   c.proxyFunc != nil,
		HasRootCA:  c.rootCAs != nil,
		SystemInfo: c.userAgent,
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
	// app is the GitHub app credentials
	app *GitHubAppAuth
	// GitHub PAT
	token string
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
	// Version is the version of the controller
	Version string `json:"version"`
	// CommitSHA is the git commit SHA of the controller
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
	return newClient(
		config.SystemInfo,
		config.GitHubConfigURL,
		actionsAuth{
			app: &config.GitHubAppAuth,
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

func newClient(systemInfo SystemInfo, githubConfigURL string, creds actionsAuth, options ...HTTPOption) (*Client, error) {
	config, err := parseGitHubConfigFromURL(githubConfigURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse githubConfigURL: %w", err)
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
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setSystemInfo(info)
}

// SystemInfo returns the current system info that the client
// has configured.
func (c *Client) SystemInfo() SystemInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.systemInfo
}

type userAgent struct {
	SystemInfo
	BuildVersion   string `json:"build_version"`
	BuildCommitSHA string `json:"build_commit_sha"`
}

func (c *Client) newGitHubAPIRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	u := c.config.gitHubAPIURL(path)
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("failed to create new GitHub API request: %w", err)
	}

	req.Header.Set("User-Agent", c.userAgent)

	return req, nil
}

func (c *Client) newActionsServiceRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	err := c.updateTokenIfNeeded(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to issue update token if needed: %w", err)
	}

	parsedPath, err := url.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("failed to parse path %q: %w", path, err)
	}

	urlString, err := url.JoinPath(c.actionsServiceURL, parsedPath.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to join path (actions_service_url=%q, parsedPath=%q): %w", c.actionsServiceURL, parsedPath.Path, err)
	}

	u, err := url.Parse(urlString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse url string %q: %w", urlString, err)
	}

	q := u.Query()
	maps.Copy(q, parsedPath.Query())

	if q.Get("api-version") == "" {
		q.Set("api-version", "6.0-preview")
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("failed to create new request with context: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.actionsServiceAdminToken))
	req.Header.Set("User-Agent", c.userAgent)

	return req, nil
}

// GetRunnerScaleSet fetches a runner scale set by its name within a runner group.
func (c *Client) GetRunnerScaleSet(ctx context.Context, runnerGroupID int, runnerScaleSetName string) (*RunnerScaleSet, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	path := fmt.Sprintf("/%s?runnerGroupId=%d&name=%s", scaleSetEndpoint, runnerGroupID, runnerScaleSetName)
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

// GetRunnerScaleSetByID fetches a runner scale set by its ID.
func (c *Client) GetRunnerScaleSetByID(ctx context.Context, runnerScaleSetID int) (*RunnerScaleSet, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

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

	var runnerScaleSet RunnerScaleSet
	if err := json.NewDecoder(resp.Body).Decode(&runnerScaleSet); err != nil {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("failed to decode runner scale set: %w", err))
	}
	return &runnerScaleSet, nil
}

// GetRunnerGroupByName fetches a runner group by its name.
func (c *Client) GetRunnerGroupByName(ctx context.Context, runnerGroup string) (*RunnerGroup, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	path := fmt.Sprintf("/_apis/runtime/runnergroups/?groupName=%s", runnerGroup)
	req, err := c.newActionsServiceRequest(ctx, http.MethodGet, path, nil)
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

// CreateRunnerScaleSet creates a new runner scale set. Note that runner scale set names must be unique within a runner group.
func (c *Client) CreateRunnerScaleSet(ctx context.Context, runnerScaleSet *RunnerScaleSet) (*RunnerScaleSet, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

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
	c.mu.Lock()
	defer c.mu.Unlock()

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
	c.mu.Lock()
	defer c.mu.Unlock()

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
	c.mu.Lock()
	defer c.mu.Unlock()

	// Copy original options
	httpClientOption := c.httpClientOption
	// Apply overwrites
	for _, option := range options {
		option(&httpClientOption)
	}
	// Instantiate a new common client
	commonClient := newCommonClient(
		c.systemInfo,
		httpClientOption,
	)

	client := &MessageSessionClient{
		innerClient:  c,
		commonClient: commonClient,
		owner:        owner,
		scaleSetID:   runnerScaleSetID,
		session:      nil,
	}

	if err := client.createMessageSession(ctx); err != nil {
		return nil, fmt.Errorf("failed to create message session: %w", err)
	}

	return client, nil
}

// GenerateJitRunnerConfig generates a JIT runner configuration for the specified runner scale set. This returns an encoded
// configuration that can be used to directly start a new runner.
func (c *Client) GenerateJitRunnerConfig(ctx context.Context, jitRunnerSetting *RunnerScaleSetJitRunnerSetting, scaleSetID int) (*RunnerScaleSetJitRunnerConfig, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

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
	c.mu.Lock()
	defer c.mu.Unlock()

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
	c.mu.Lock()
	defer c.mu.Unlock()

	path := fmt.Sprintf("/%s?agentName=%s", runnerEndpoint, runnerName)

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
	c.mu.Lock()
	defer c.mu.Unlock()

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
		accessToken, err := c.fetchAccessToken(ctx, c.creds.app)
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

func (c *Client) fetchAccessToken(ctx context.Context, creds *GitHubAppAuth) (*accessToken, error) {
	accessTokenJWT, err := createJWTForGitHubApp(creds)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT for GitHub app: %w", err)
	}

	path := fmt.Sprintf("/app/installations/%v/access_tokens", creds.InstallationID)
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

	if resp.StatusCode < 200 && resp.StatusCode > 299 {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("unexpected status code: %d", resp.StatusCode))
	}

	var actionsServiceAdminConnection actionsServiceAdminConnection
	if err := json.NewDecoder(resp.Body).Decode(&actionsServiceAdminConnection); err != nil {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("failed to decode actions service admin connection: %w", err))
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

func createJWTForGitHubApp(appAuth *GitHubAppAuth) (string, error) {
	// Encode as JWT
	// See https://docs.github.com/en/developers/apps/building-github-apps/authenticating-with-github-apps#authenticating-as-a-github-app

	// Going back in time a bit helps with clock skew.
	issuedAt := time.Now().Add(-60 * time.Second)
	// Max expiration date is 10 minutes.
	expiresAt := issuedAt.Add(9 * time.Minute)
	claims := &jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(issuedAt),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		Issuer:    appAuth.ClientID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(appAuth.PrivateKey))
	if err != nil {
		return "", fmt.Errorf("failed to parse RSA private key from PEM: %w", err)
	}

	return token.SignedString(privateKey)
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

func (c *Client) updateTokenIfNeeded(ctx context.Context) error {
	aboutToExpire := time.Now().Add(60 * time.Second).After(c.actionsServiceAdminTokenExpiresAt)
	if !aboutToExpire && !c.actionsServiceAdminTokenExpiresAt.IsZero() {
		return nil
	}

	c.logger.Info("refreshing token", "githubConfigUrl", c.config.configURL.String())
	rt, err := c.getRunnerRegistrationToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get runner registration token on refresh: %w", err)
	}

	adminConnInfo, err := c.getActionsServiceAdminConnection(ctx, rt)
	if err != nil {
		return fmt.Errorf("failed to get actions service admin connection on refresh: %w", err)
	}

	c.actionsServiceURL = *adminConnInfo.ActionsServiceURL
	c.actionsServiceAdminToken = *adminConnInfo.AdminToken
	c.actionsServiceAdminTokenExpiresAt, err = actionsServiceAdminTokenExpiresAt(*adminConnInfo.AdminToken)
	if err != nil {
		return fmt.Errorf("failed to get admin token expire at on refresh: %w", err)
	}

	return nil
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
