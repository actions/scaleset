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
	"math/rand"
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

type atomicValue[T any] struct {
	v atomic.Value
}

func (v *atomicValue[T]) CompareAndSwap(old, new T) (swapped bool) {
	return v.v.CompareAndSwap(old, new)
}

func (v *atomicValue[T]) Load() T {
	return v.v.Load().(T)
}

func (v *atomicValue[T]) Store(val T) {
	v.v.Store(val)
}

func (v *atomicValue[T]) Swap(new T) (old T) {
	return v.v.Swap(new).(T)
}

// HeaderScaleSetMaxCapacity used to propagate capacity information to the back-end
const HeaderScaleSetMaxCapacity = "X-ScaleSetMaxCapacity"

type Client struct {
	httpClient *http.Client

	actionsMu                         sync.Mutex // guards actionsService fields
	actionsServiceAdminToken          string
	actionsServiceAdminTokenExpiresAt time.Time
	actionsServiceURL                 string

	retryMax     int
	retryWaitMax time.Duration

	creds  *ActionsAuth
	config *GitHubConfig
	logger *slog.Logger

	userAgent atomicValue[string]

	rootCAs               *x509.CertPool
	tlsInsecureSkipVerify bool

	proxyFunc ProxyFunc
}

type GitHubAppAuth struct {
	// ClientID is the Client ID of the application (app id also works)
	ClientID string
	// InstallationID is the installation ID of the GitHub App
	InstallationID int64
	// PrivateKey is the private key of the GitHub App in PEM format
	PrivateKey string
}

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

type ActionsAuth struct {
	// AppCreds is the GitHub App credentials
	App *GitHubAppAuth
	// GitHub PAT
	Token string
}

type ProxyFunc func(req *http.Request) (*url.URL, error)

type Option func(*Client)

type UserAgentInfo struct {
	// System is the name of the scale set implementation
	System string
	// Version is the version of the controller
	Version string
	// CommitSHA is the git commit SHA of the controller
	CommitSHA string
	// ScaleSetID is the ID of the scale set
	ScaleSetID int
	// Subsystem is the subsystem such as listener, controller, etc.
	// Each system may pick its own subsystem name.
	Subsystem string
}

func (u UserAgentInfo) String() string {
	scaleSetID := "NA"
	if u.ScaleSetID > 0 {
		scaleSetID = strconv.Itoa(u.ScaleSetID)
	}

	version, sha := detectModuleVersionAndCommit()

	return fmt.Sprintf(
		"%s/%s (%s; %s) ScaleSetID/%s; client (%s; %s)",
		u.System,
		u.Version,
		u.CommitSHA,
		u.Subsystem,
		scaleSetID,
		version,
		sha,
	)
}

func WithLogger(logger slog.Logger) Option {
	return func(c *Client) {
		c.logger = &logger
	}
}

func WithRetryMax(retryMax int) Option {
	return func(c *Client) {
		c.retryMax = retryMax
	}
}

func WithRetryWaitMax(retryWaitMax time.Duration) Option {
	return func(c *Client) {
		c.retryWaitMax = retryWaitMax
	}
}

func WithRootCAs(rootCAs *x509.CertPool) Option {
	return func(c *Client) {
		c.rootCAs = rootCAs
	}
}

func WithoutTLSVerify() Option {
	return func(c *Client) {
		c.tlsInsecureSkipVerify = true
	}
}

func WithProxy(proxyFunc ProxyFunc) Option {
	return func(c *Client) {
		c.proxyFunc = proxyFunc
	}
}

func NewClient(githubConfigURL string, creds *ActionsAuth, options ...Option) (*Client, error) {
	config, err := ParseGitHubConfigFromURL(githubConfigURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse githubConfigURL: %w", err)
	}

	ac := &Client{
		creds:  creds,
		config: config,
		logger: slog.New(slog.DiscardHandler),

		// retryablehttp defaults
		retryMax:     4,
		retryWaitMax: 30 * time.Second,
	}

	version, sha := detectModuleVersionAndCommit()

	ac.userAgent.Store(
		UserAgentInfo{
			System:     "scaleset-client",
			Version:    version,
			CommitSHA:  sha,
			Subsystem:  "NA",
			ScaleSetID: 0,
		}.String())

	for _, option := range options {
		option(ac)
	}

	retryClient := retryablehttp.NewClient()
	retryClient.Logger = ac.logger

	retryClient.RetryMax = ac.retryMax
	retryClient.RetryWaitMax = ac.retryWaitMax

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

	if ac.rootCAs != nil {
		transport.TLSClientConfig.RootCAs = ac.rootCAs
	}

	if ac.tlsInsecureSkipVerify {
		transport.TLSClientConfig.InsecureSkipVerify = true
	}

	transport.Proxy = ac.proxyFunc

	retryClient.HTTPClient.Transport = transport
	ac.httpClient = retryClient.StandardClient()

	return ac, nil
}

// SetUserAgent updates the user agent
func (c *Client) SetUserAgent(info UserAgentInfo) {
	c.userAgent.Store(info.String())
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
	u := c.config.GitHubAPIURL(path)
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("failed to create new GitHub API request: %w", err)
	}

	req.Header.Set("User-Agent", c.userAgent.Load())

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
	req.Header.Set("User-Agent", c.userAgent.Load())

	return req, nil
}

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
		return nil, parseActionsErrorFromResponse(resp)
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
		return nil, parseActionsErrorFromResponse(resp)
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
		return nil, parseActionsErrorFromResponse(resp)
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
		return nil, parseActionsErrorFromResponse(resp)
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
		return parseActionsErrorFromResponse(resp)
	}

	return nil
}

// GetMessage fetches a message from the runner scale set message queue.
func (c *Client) GetMessage(ctx context.Context, messageQueueURL, messageQueueAccessToken string, lastMessageID int64, maxCapacity int) (*RunnerScaleSetMessage, error) {
	u, err := url.Parse(messageQueueURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse message queue url: %w", err)
	}

	if lastMessageID > 0 {
		q := u.Query()
		q.Set("lastMessageId", strconv.FormatInt(lastMessageID, 10))
		u.RawQuery = q.Encode()
	}

	if maxCapacity < 0 {
		return nil, fmt.Errorf("maxCapacity must be greater than or equal to 0")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create new request with context: %w", err)
	}

	req.Header.Set("Accept", "application/json; api-version=6.0-preview")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", messageQueueAccessToken))
	req.Header.Set("User-Agent", c.userAgent.Load())
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
			return nil, parseActionsErrorFromResponse(resp)
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
		return nil, &MessageQueueTokenExpiredError{
			activityID: resp.Header.Get(headerActionsActivityID),
			statusCode: resp.StatusCode,
			msg:        string(body),
		}
	}

	var message *RunnerScaleSetMessage
	if err := json.NewDecoder(resp.Body).Decode(&message); err != nil {
		return nil, &ActionsError{
			StatusCode: resp.StatusCode,
			ActivityID: resp.Header.Get(headerActionsActivityID),
			Err:        err,
		}
	}
	return message, nil
}

func (c *Client) DeleteMessage(ctx context.Context, messageQueueURL, messageQueueAccessToken string, messageID int64) error {
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
	req.Header.Set("User-Agent", c.userAgent.Load())

	resp, err := c.do(req)
	if err != nil {
		return fmt.Errorf("failed to issue the request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil
	}

	if resp.StatusCode != http.StatusUnauthorized {
		return parseActionsErrorFromResponse(resp)
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
	return &MessageQueueTokenExpiredError{
		activityID: resp.Header.Get(headerActionsActivityID),
		statusCode: resp.StatusCode,
		msg:        string(body),
	}
}

func (c *Client) CreateMessageSession(ctx context.Context, runnerScaleSetID int, owner string) (*RunnerScaleSetSession, error) {
	path := fmt.Sprintf("/%s/%d/sessions", scaleSetEndpoint, runnerScaleSetID)

	newSession := &RunnerScaleSetSession{
		OwnerName: owner,
	}

	requestData, err := json.Marshal(newSession)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal new session: %w", err)
	}

	createdSession := &RunnerScaleSetSession{}

	if err = c.doSessionRequest(ctx, http.MethodPost, path, bytes.NewBuffer(requestData), http.StatusOK, createdSession); err != nil {
		return nil, fmt.Errorf("failed to do the session request: %w", err)
	}

	return createdSession, nil
}

func (c *Client) DeleteMessageSession(ctx context.Context, runnerScaleSetID int, sessionID uuid.UUID) error {
	path := fmt.Sprintf("/%s/%d/sessions/%s", scaleSetEndpoint, runnerScaleSetID, sessionID.String())
	return c.doSessionRequest(ctx, http.MethodDelete, path, nil, http.StatusNoContent, nil)
}

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
		return parseActionsErrorFromResponse(resp)
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
		return nil, parseActionsErrorFromResponse(resp)
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

func (c *Client) GetRunner(ctx context.Context, runnerID int64) (*RunnerReference, error) {
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
		return nil, parseActionsErrorFromResponse(resp)
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
		return nil, parseActionsErrorFromResponse(resp)
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
		return parseActionsErrorFromResponse(resp)
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

	if c.creds.Token != "" {
		bearerToken = fmt.Sprintf("Bearer %v", c.creds.Token)
	} else {
		accessToken, err := c.fetchAccessToken(ctx, c.creds.App)
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

type ActionsServiceAdminConnection struct {
	ActionsServiceURL *string `json:"url,omitempty"`
	AdminToken        *string `json:"token,omitempty"`
}

func (c *Client) getActionsServiceAdminConnection(ctx context.Context, rt *registrationToken) (*ActionsServiceAdminConnection, error) {
	path := "/actions/runner-registration"

	body := struct {
		URL         string `json:"url"`
		RunnerEvent string `json:"runner_event"`
	}{
		URL:         c.config.ConfigURL.String(),
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

	retry := 0
	for {
		adminConnection, err := c.getActionsServiceAdminConnectionRequest(req)
		if err == nil {
			return adminConnection, nil
		}

		retry++
		if retry > 5 {
			return nil, fmt.Errorf("unable to register runner after 5 retries: %w", err)
		}

		var ghErr *GitHubAPIError
		if !errors.As(err, &ghErr) {
			return nil, fmt.Errorf("failed to get actions service admin connection: %w", err)
		}

		if ghErr.StatusCode != http.StatusUnauthorized && ghErr.StatusCode != http.StatusForbidden {
			return nil, fmt.Errorf("failed to get actions service admin connection: %w", ghErr)
		}

		c.logger.Debug("received unauthorized or forbidden response, retrying", "retryAttempt", retry, "statusCode", ghErr.StatusCode)

		// Add exponential backoff + jitter to avoid thundering herd
		// This will generate a backoff schedule:
		// 1: 1s
		// 2: 3s
		// 3: 4s
		// 4: 8s
		// 5: 17s
		baseDelay := 500 * time.Millisecond
		jitter := time.Duration(rand.Intn(1000))
		maxDelay := 20 * time.Second
		delay := min(baseDelay*(1<<retry)+jitter, maxDelay)

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("context cancelled while waiting to retry: %w", ctx.Err())
		case <-time.After(delay):
			// continue to next retry
		}
	}
}

func (c *Client) getActionsServiceAdminConnectionRequest(req *http.Request) (*ActionsServiceAdminConnection, error) {
	resp, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to issue the request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		var actionsServiceAdminConnection *ActionsServiceAdminConnection
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

func createRegistrationTokenPath(config *GitHubConfig) (string, error) {
	switch config.Scope {
	case GitHubScopeOrganization:
		path := fmt.Sprintf("/orgs/%s/actions/runners/registration-token", config.Organization)
		return path, nil

	case GitHubScopeEnterprise:
		path := fmt.Sprintf("/enterprises/%s/actions/runners/registration-token", config.Enterprise)
		return path, nil

	case GitHubScopeRepository:
		path := fmt.Sprintf("/repos/%s/%s/actions/runners/registration-token", config.Organization, config.Repository)
		return path, nil

	default:
		return "", fmt.Errorf("unknown scope for config url: %s", config.ConfigURL)
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

	c.logger.Info("refreshing token", "githubConfigUrl", c.config.ConfigURL.String())
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
