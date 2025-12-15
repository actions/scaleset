// Package scaleset package provides a client to interact with GitHub Scale Set APIs.
package scaleset

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/hashicorp/go-retryablehttp"
)

const (
	runnerEndpoint   = "_apis/distributedtask/pools/0/agents"
	scaleSetEndpoint = "_apis/runtime/runnerscalesets"
)

var (
	packageVersion string
	commitSHA      string
)

func init() {
	packageVersion, commitSHA = detectModuleVersionAndCommit()
}

// HeaderScaleSetMaxCapacity is used to propagate the scale set max
// capacity when polling for messages.
const HeaderScaleSetMaxCapacity = "X-ScaleSetMaxCapacity"

// Client implements a GitHub Actions Scale Set client.
type Client struct {
	httpClient *http.Client

	actionsMu                         sync.Mutex // guards actionsService fields
	actionsServiceAdminToken          string
	actionsServiceAdminTokenExpiresAt time.Time
	actionsServiceURL                 string

	retryMax     int
	retryWaitMax time.Duration

	creds  *actionsAuth
	config *gitHubConfig
	logger *slog.Logger

	buildInfo clientBuildInfo
	// systemInfoMu guards setting system info.
	systemInfoMu sync.Mutex
	systemInfo   SystemInfo

	// userAgent is computed based on buildInfo and systemInfo.
	// userAgent should be re-computed every time client.SetSystemInfo
	// is called.
	//
	// On every call, load the userAgent first locally so we can
	// avoid lock-unlock on every call.
	userAgent atomic.Pointer[string]

	rootCAs               *x509.CertPool
	tlsInsecureSkipVerify bool

	proxyFunc ProxyFunc
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

func (c *Client) DebugInfo() string {
	info := debugInfo{
		HasProxy:   c.proxyFunc != nil,
		HasRootCA:  c.rootCAs != nil,
		SystemInfo: *c.userAgent.Load(),
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

// Option defines a functional option for configuring the Client.
type Option func(*Client)

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

// WithLogger sets a custom logger for the Client.
func WithLogger(logger slog.Logger) Option {
	return func(c *Client) {
		c.logger = &logger
	}
}

// WithRetryMax sets the maximum number of retries for the Client.
func WithRetryMax(retryMax int) Option {
	return func(c *Client) {
		c.retryMax = retryMax
	}
}

// WithRetryWaitMax sets the maximum wait time between retries for the Client.
func WithRetryWaitMax(retryWaitMax time.Duration) Option {
	return func(c *Client) {
		c.retryWaitMax = retryWaitMax
	}
}

// WithRootCAs sets custom root certificate authorities for the Client.
func WithRootCAs(rootCAs *x509.CertPool) Option {
	return func(c *Client) {
		c.rootCAs = rootCAs
	}
}

// WithoutTLSVerify disables TLS certificate verification for the Client.
func WithoutTLSVerify() Option {
	return func(c *Client) {
		c.tlsInsecureSkipVerify = true
	}
}

// WithProxy sets a custom proxy function for the Client.
func WithProxy(proxyFunc ProxyFunc) Option {
	return func(c *Client) {
		c.proxyFunc = proxyFunc
	}
}

type ClientWithGitHubAppConfig struct {
	GitHubConfigURL string
	GitHubAppAuth   GitHubAppAuth
	SystemInfo      SystemInfo
}

// NewClientWithGitHubApp creates a new Client using GitHub App credentials.
func NewClientWithGitHubApp(config ClientWithGitHubAppConfig, options ...Option) (*Client, error) {
	creds := &actionsAuth{
		app: &config.GitHubAppAuth,
	}
	return newClient(
		config.SystemInfo,
		config.GitHubConfigURL,
		creds,
		options...,
	)
}

type NewClientWithPersonalAccessTokenConfig struct {
	GitHubConfigURL     string
	PersonalAccessToken string
	SystemInfo          SystemInfo
}

// NewClientWithPersonalAccessToken creates a new Client using a personal access token.
func NewClientWithPersonalAccessToken(config NewClientWithPersonalAccessTokenConfig, options ...Option) (*Client, error) {
	creds := &actionsAuth{
		token: config.PersonalAccessToken,
	}
	return newClient(
		config.SystemInfo,
		config.GitHubConfigURL,
		creds,
		options...,
	)
}

func newClient(systemInfo SystemInfo, githubConfigURL string, creds *actionsAuth, options ...Option) (*Client, error) {
	config, err := parseGitHubConfigFromURL(githubConfigURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse githubConfigURL: %w", err)
	}

	version, sha := detectModuleVersionAndCommit()

	ac := &Client{
		creds:  creds,
		config: config,
		logger: slog.New(slog.DiscardHandler),

		// retryablehttp defaults
		retryMax:     4,
		retryWaitMax: 30 * time.Second,

		buildInfo: clientBuildInfo{
			version:   version,
			commitSHA: sha,
		},
	}

	ac.SetSystemInfo(systemInfo)

	for _, option := range options {
		option(ac)
	}

	retryClient, err := ac.newRetryableHTTPClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create retryable HTTP client: %w", err)
	}
	ac.httpClient = retryClient.StandardClient()

	return ac, nil
}

func (c *Client) newRetryableHTTPClient() (*retryablehttp.Client, error) {
	retryClient := retryablehttp.NewClient()
	retryClient.Logger = c.logger
	retryClient.RetryMax = c.retryMax
	retryClient.RetryWaitMax = c.retryWaitMax
	retryClient.HTTPClient.Timeout = 5 * time.Minute // timeout must be > 1m to accomodate long polling

	transport, ok := retryClient.HTTPClient.Transport.(*http.Transport)
	if !ok {
		// this should always be true, because retryablehttp.NewClient() uses
		// cleanhttp.DefaultPooledTransport()
		return nil, fmt.Errorf("failed to get http transport from retryablehttp client")
	}
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}

	if c.rootCAs != nil {
		transport.TLSClientConfig.RootCAs = c.rootCAs
	}

	if c.tlsInsecureSkipVerify {
		transport.TLSClientConfig.InsecureSkipVerify = true
	}

	transport.Proxy = c.proxyFunc

	retryClient.HTTPClient.Transport = transport

	return retryClient, nil
}

// SetSystemInfo updates the information about the system.
func (c *Client) SetSystemInfo(info SystemInfo) {
	c.systemInfoMu.Lock()
	defer c.systemInfoMu.Unlock()
	c.systemInfo = info
	c.setUserAgent()
}

// SystemInfo returns the current system info that client
// has configured.
func (c *Client) SystemInfo() SystemInfo {
	c.systemInfoMu.Lock()
	defer c.systemInfoMu.Unlock()
	return c.systemInfo
}

type userAgent struct {
	SystemInfo
	BuildVersion   string `json:"build_version"`
	BuildCommitSHA string `json:"build_commit_sha"`
}

func (c *Client) setUserAgent() {
	b, _ := json.Marshal(userAgent{
		SystemInfo:     c.systemInfo,
		BuildVersion:   c.buildInfo.version,
		BuildCommitSHA: c.buildInfo.commitSHA,
	})
	userAgent := string(b)
	c.userAgent.Store(&userAgent)
}

func (c *Client) do(req *http.Request) (*http.Response, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client request failed: %w", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read the response body: %w", err)
	}
	err = resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close the response body: %w", err)
	}

	body = trimByteOrderMark(body)
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, nil
}

func (c *Client) newGitHubAPIRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	u := c.config.gitHubAPIURL(path)
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("failed to create new GitHub API request: %w", err)
	}

	req.Header.Set("User-Agent", *c.userAgent.Load())

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
	req.Header.Set("User-Agent", *c.userAgent.Load())

	return req, nil
}

// GetRunnerScaleSet fetches a runner scale set by its name within a runner group.
func (c *Client) GetRunnerScaleSet(ctx context.Context, runnerGroupID int, runnerScaleSetName string) (*RunnerScaleSet, error) {
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
		return nil, ParseActionsErrorFromResponse(resp)
	}

	var runnerScaleSetList *runnerScaleSetsResponse
	if err := json.NewDecoder(resp.Body).Decode(&runnerScaleSetList); err != nil {
		return nil, &ActionsError{
			StatusCode: resp.StatusCode,
			ActivityID: resp.Header.Get(headerActionsActivityID),
			Err:        err,
		}
	}
	if runnerScaleSetList.Count == 0 {
		return nil, nil
	}

	if runnerScaleSetList.Count > 1 {
		return nil, &ActionsError{
			StatusCode: resp.StatusCode,
			ActivityID: resp.Header.Get(headerActionsActivityID),
			Err:        fmt.Errorf("multiple runner scale sets found with name %q", runnerScaleSetName),
		}
	}

	return &runnerScaleSetList.RunnerScaleSets[0], nil
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
		return nil, ParseActionsErrorFromResponse(resp)
	}

	var runnerScaleSet *RunnerScaleSet
	if err := json.NewDecoder(resp.Body).Decode(&runnerScaleSet); err != nil {
		return nil, &ActionsError{
			StatusCode: resp.StatusCode,
			ActivityID: resp.Header.Get(headerActionsActivityID),
			Err:        err,
		}
	}
	return runnerScaleSet, nil
}

// GetRunnerGroupByName fetches a runner group by its name.
func (c *Client) GetRunnerGroupByName(ctx context.Context, runnerGroup string) (*RunnerGroup, error) {
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
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, &ActionsError{
				StatusCode: resp.StatusCode,
				ActivityID: resp.Header.Get(headerActionsActivityID),
				Err:        err,
			}
		}
		return nil, fmt.Errorf("unexpected status code: %w", &ActionsError{
			StatusCode: resp.StatusCode,
			ActivityID: resp.Header.Get(headerActionsActivityID),
			Err:        errors.New(string(body)),
		})
	}

	var runnerGroupList *RunnerGroupList
	err = json.NewDecoder(resp.Body).Decode(&runnerGroupList)
	if err != nil {
		return nil, &ActionsError{
			StatusCode: resp.StatusCode,
			ActivityID: resp.Header.Get(headerActionsActivityID),
			Err:        err,
		}
	}

	if runnerGroupList.Count == 0 {
		return nil, &ActionsError{
			StatusCode: resp.StatusCode,
			ActivityID: resp.Header.Get(headerActionsActivityID),
			Err:        fmt.Errorf("no runner group found with name %q", runnerGroup),
		}
	}

	if runnerGroupList.Count > 1 {
		return nil, &ActionsError{
			StatusCode: resp.StatusCode,
			ActivityID: resp.Header.Get(headerActionsActivityID),
			Err:        fmt.Errorf("multiple runner group found with name %q", runnerGroup),
		}
	}

	return &runnerGroupList.RunnerGroups[0], nil
}

// CreateRunnerScaleSet creates a new runner scale set. Note that runner scale set names must be unique within a runner group.
func (c *Client) CreateRunnerScaleSet(ctx context.Context, runnerScaleSet *RunnerScaleSet) (*RunnerScaleSet, error) {
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
		return nil, ParseActionsErrorFromResponse(resp)
	}
	var createdRunnerScaleSet *RunnerScaleSet
	if err := json.NewDecoder(resp.Body).Decode(&createdRunnerScaleSet); err != nil {
		return nil, &ActionsError{
			StatusCode: resp.StatusCode,
			ActivityID: resp.Header.Get(headerActionsActivityID),
			Err:        err,
		}
	}
	return createdRunnerScaleSet, nil
}

// UpdateRunnerScaleSet updates an existing runner scale set.
func (c *Client) UpdateRunnerScaleSet(ctx context.Context, runnerScaleSetID int, runnerScaleSet *RunnerScaleSet) (*RunnerScaleSet, error) {
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
		return nil, ParseActionsErrorFromResponse(resp)
	}

	var updatedRunnerScaleSet *RunnerScaleSet
	if err := json.NewDecoder(resp.Body).Decode(&updatedRunnerScaleSet); err != nil {
		return nil, &ActionsError{
			StatusCode: resp.StatusCode,
			ActivityID: resp.Header.Get(headerActionsActivityID),
			Err:        err,
		}
	}
	return updatedRunnerScaleSet, nil
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
		return ParseActionsErrorFromResponse(resp)
	}

	return nil
}

// GetMessage fetches a message from the runner scale set message queue. If there are no messages available, it returns (nil, nil).
// Unless a message is deleted after being processed (using DeleteMessage), it will be returned again in subsequent calls.
// If the current session token is expired, it returns a MessageQueueTokenExpiredError.
// In these cases the caller should refresh the session with RefreshMessageSession.
func (c *Client) GetMessage(ctx context.Context, messageQueueURL, messageQueueAccessToken string, lastMessageID int, maxCapacity int) (*RunnerScaleSetMessage, error) {
	u, err := url.Parse(messageQueueURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse message queue url: %w", err)
	}

	if lastMessageID > 0 {
		q := u.Query()
		q.Set("lastMessageId", strconv.Itoa(lastMessageID))
		u.RawQuery = q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create new request with context: %w", err)
	}

	req.Header.Set("Accept", "application/json; api-version=6.0-preview")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", messageQueueAccessToken))
	req.Header.Set("User-Agent", *c.userAgent.Load())
	req.Header.Set(HeaderScaleSetMaxCapacity, strconv.Itoa(maxCapacity))

	resp, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to issue the request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusAccepted {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode != http.StatusUnauthorized {
			return nil, ParseActionsErrorFromResponse(resp)
		}

		body, err := io.ReadAll(resp.Body)
		body = trimByteOrderMark(body)
		if err != nil {
			return nil, &ActionsError{
				ActivityID: resp.Header.Get(headerActionsActivityID),
				StatusCode: resp.StatusCode,
				Err:        err,
			}
		}
		return nil, &ActionsError{
			ActivityID: resp.Header.Get(headerActionsActivityID),
			StatusCode: resp.StatusCode,
			Err: &messageQueueTokenExpiredError{
				message: string(body),
			},
		}
	}

	message, err := c.parseRunnerScaleSetMessageResponse(resp.Body)
	if err != nil {
		return nil, &ActionsError{
			StatusCode: resp.StatusCode,
			ActivityID: resp.Header.Get(headerActionsActivityID),
			Err:        err,
		}
	}

	return message, nil
}

func (c *Client) parseRunnerScaleSetMessageResponse(respBody io.Reader) (*RunnerScaleSetMessage, error) {
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

// DeleteMessage deletes a message from the runner scale set message queue.
// This should typically be done after processing the message and acts as an acknowledgment.
// If the current session token is expired, it returns a MessageQueueTokenExpiredError.
// In these cases the caller should refresh the session with RefreshMessageSession.
func (c *Client) DeleteMessage(ctx context.Context, messageQueueURL, messageQueueAccessToken string, messageID int) error {
	u, err := url.Parse(messageQueueURL)
	if err != nil {
		return fmt.Errorf("failed to parse message queue url: %w", err)
	}

	u.Path = fmt.Sprintf("%s/%d", u.Path, messageID)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create new request with context: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", messageQueueAccessToken))
	req.Header.Set("User-Agent", *c.userAgent.Load())

	resp, err := c.do(req)
	if err != nil {
		return fmt.Errorf("failed to issue the request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil
	}

	if resp.StatusCode != http.StatusUnauthorized {
		return ParseActionsErrorFromResponse(resp)
	}

	body, err := io.ReadAll(resp.Body)
	body = trimByteOrderMark(body)
	if err != nil {
		return &ActionsError{
			ActivityID: resp.Header.Get(headerActionsActivityID),
			StatusCode: resp.StatusCode,
			Err:        err,
		}
	}
	return &ActionsError{
		ActivityID: resp.Header.Get(headerActionsActivityID),
		StatusCode: resp.StatusCode,
		Err: &messageQueueTokenExpiredError{
			message: string(body),
		},
	}
}

// CreateMessageSession creates a new message session for the specified runner scale set.
// The resulting session contains the message queue URL and access token used to GetMessage.
func (c *Client) CreateMessageSession(ctx context.Context, runnerScaleSetID int, owner string) (*RunnerScaleSetSession, error) {
	path := fmt.Sprintf("/%s/%d/sessions", scaleSetEndpoint, runnerScaleSetID)

	newSession := &RunnerScaleSetSession{
		OwnerName: owner,
	}

	requestData, err := json.Marshal(newSession)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal new session: %w", err)
	}

	var createdSession RunnerScaleSetSession
	if err = c.doSessionRequest(
		ctx,
		http.MethodPost,
		path,
		bytes.NewBuffer(requestData),
		http.StatusOK,
		&createdSession,
	); err != nil {
		return nil, fmt.Errorf("failed to do the session request: %w", err)
	}

	return &createdSession, nil
}

// DeleteMessageSession deletes a message session for the specified runner scale set.
func (c *Client) DeleteMessageSession(ctx context.Context, runnerScaleSetID int, sessionID uuid.UUID) error {
	path := fmt.Sprintf("/%s/%d/sessions/%s", scaleSetEndpoint, runnerScaleSetID, sessionID.String())
	return c.doSessionRequest(ctx, http.MethodDelete, path, nil, http.StatusNoContent, nil)
}

// RefreshMessageSession refreshes a message session for the specified runner scale set.
// This should be used when a MessageQueueTokenExpiredError is encountered.
func (c *Client) RefreshMessageSession(ctx context.Context, runnerScaleSetID int, sessionID uuid.UUID) (*RunnerScaleSetSession, error) {
	path := fmt.Sprintf("/%s/%d/sessions/%s", scaleSetEndpoint, runnerScaleSetID, sessionID.String())
	refreshedSession := &RunnerScaleSetSession{}
	if err := c.doSessionRequest(ctx, http.MethodPatch, path, nil, http.StatusOK, refreshedSession); err != nil {
		return nil, fmt.Errorf("failed to do the session request: %w", err)
	}
	return refreshedSession, nil
}

func (c *Client) doSessionRequest(ctx context.Context, method, path string, requestData io.Reader, expectedResponseStatusCode int, responseUnmarshalTarget any) error {
	req, err := c.newActionsServiceRequest(ctx, method, path, requestData)
	if err != nil {
		return fmt.Errorf("failed to create new actions service request: %w", err)
	}

	resp, err := c.do(req)
	if err != nil {
		return fmt.Errorf("failed to issue the request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == expectedResponseStatusCode {
		if responseUnmarshalTarget == nil {
			return nil
		}

		if err := json.NewDecoder(resp.Body).Decode(responseUnmarshalTarget); err != nil {
			return &ActionsError{
				StatusCode: resp.StatusCode,
				ActivityID: resp.Header.Get(headerActionsActivityID),
				Err:        err,
			}
		}

		return nil
	}

	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		return ParseActionsErrorFromResponse(resp)
	}

	body, err := io.ReadAll(resp.Body)
	body = trimByteOrderMark(body)
	if err != nil {
		return &ActionsError{
			StatusCode: resp.StatusCode,
			ActivityID: resp.Header.Get(headerActionsActivityID),
			Err:        err,
		}
	}

	return fmt.Errorf("unexpected status code: %w", &ActionsError{
		StatusCode: resp.StatusCode,
		ActivityID: resp.Header.Get(headerActionsActivityID),
		Err:        errors.New(string(body)),
	})
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
		return nil, ParseActionsErrorFromResponse(resp)
	}

	var runnerJitConfig *RunnerScaleSetJitRunnerConfig
	if err := json.NewDecoder(resp.Body).Decode(&runnerJitConfig); err != nil {
		return nil, &ActionsError{
			StatusCode: resp.StatusCode,
			ActivityID: resp.Header.Get(headerActionsActivityID),
			Err:        err,
		}
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
		return nil, ParseActionsErrorFromResponse(resp)
	}

	var runnerReference *RunnerReference
	if err := json.NewDecoder(resp.Body).Decode(&runnerReference); err != nil {
		return nil, &ActionsError{
			StatusCode: resp.StatusCode,
			ActivityID: resp.Header.Get(headerActionsActivityID),
			Err:        err,
		}
	}

	return runnerReference, nil
}

// GetRunnerByName fetches a runner by its name. This can be used to check if a runner exists.
func (c *Client) GetRunnerByName(ctx context.Context, runnerName string) (*RunnerReference, error) {
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
		return nil, ParseActionsErrorFromResponse(resp)
	}

	var runnerList *RunnerReferenceList
	if err := json.NewDecoder(resp.Body).Decode(&runnerList); err != nil {
		return nil, &ActionsError{
			StatusCode: resp.StatusCode,
			ActivityID: resp.Header.Get(headerActionsActivityID),
			Err:        err,
		}
	}

	if runnerList.Count == 0 {
		return nil, nil
	}

	if runnerList.Count > 1 {
		return nil, &ActionsError{
			StatusCode: resp.StatusCode,
			ActivityID: resp.Header.Get(headerActionsActivityID),
			Err:        fmt.Errorf("multiple runner found with name %s", runnerName),
		}
	}

	return &runnerList.RunnerReferences[0], nil
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
		return ParseActionsErrorFromResponse(resp)
	}

	return nil
}

type registrationToken struct {
	Token     *string    `json:"token,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

func (c *Client) getRunnerRegistrationToken(ctx context.Context) (*registrationToken, error) {
	path, err := createRegistrationTokenPath(c.config)
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
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read the body: %w", err)
		}
		return nil, &GitHubAPIError{
			StatusCode: resp.StatusCode,
			RequestID:  resp.Header.Get(headerGitHubRequestID),
			Err:        errors.New(string(body)),
		}
	}

	var registrationToken *registrationToken
	if err := json.NewDecoder(resp.Body).Decode(&registrationToken); err != nil {
		return nil, &GitHubAPIError{
			StatusCode: resp.StatusCode,
			RequestID:  resp.Header.Get(headerGitHubRequestID),
			Err:        err,
		}
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
		errMsg := fmt.Sprintf("failed to get access token for GitHub App auth (%v)", resp.Status)
		if body, err := io.ReadAll(resp.Body); err == nil {
			errMsg = fmt.Sprintf("%s: %s", errMsg, string(body))
		}

		return nil, &GitHubAPIError{
			StatusCode: resp.StatusCode,
			RequestID:  resp.Header.Get(headerGitHubRequestID),
			Err:        errors.New(errMsg),
		}
	}

	// Format: https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app
	var accessToken *accessToken
	if err = json.NewDecoder(resp.Body).Decode(&accessToken); err != nil {
		return nil, &GitHubAPIError{
			StatusCode: resp.StatusCode,
			RequestID:  resp.Header.Get(headerGitHubRequestID),
			Err:        err,
		}
	}
	return accessToken, nil
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

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to issue the request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		var actionsServiceAdminConnection *actionsServiceAdminConnection
		if err := json.NewDecoder(resp.Body).Decode(&actionsServiceAdminConnection); err != nil {
			return nil, &GitHubAPIError{
				StatusCode: resp.StatusCode,
				RequestID:  resp.Header.Get(headerGitHubRequestID),
				Err:        err,
			}
		}

		return actionsServiceAdminConnection, nil
	}

	var innerErr error
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		innerErr = err
	} else {
		innerErr = errors.New(string(body))
	}

	return nil, &GitHubAPIError{
		StatusCode: resp.StatusCode,
		RequestID:  resp.Header.Get(headerGitHubRequestID),
		Err:        innerErr,
	}
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
	c.actionsMu.Lock()
	defer c.actionsMu.Unlock()

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
