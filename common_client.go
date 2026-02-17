package scaleset

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/hashicorp/go-retryablehttp"
)

const (
	headerActionsActivityID = "ActivityId"
	headerGitHubRequestID   = "X-GitHub-Request-Id"
)

type commonClient struct {
	httpClient *http.Client

	systemInfo SystemInfo // never set directly, use setSystemInfoUnlocked

	userAgent string

	httpClientOption
}

func newCommonClient(systemInfo SystemInfo, httpClientOption httpClientOption) *commonClient {
	c := &commonClient{
		httpClientOption: httpClientOption,
	}
	c.setSystemInfo(systemInfo)

	retryableHTTPClient, err := httpClientOption.newRetryableHTTPClient()
	if err != nil {
		panic(fmt.Sprintf("failed to create retryable HTTP client: %v", err))
	}
	c.httpClient = retryableHTTPClient.StandardClient()

	return c
}

func (c *commonClient) newRetryableHTTPClient() (*retryablehttp.Client, error) {
	return c.httpClientOption.newRetryableHTTPClient()
}

func (c *commonClient) do(req *http.Request) (*http.Response, error) {
	return sendRequest(c.httpClient, req)
}

// sendRequest ensures that the request is sent and the response body is fully read and closed.
// It trims the BOM when present in the response body.
//
// Make sure to use this function instead of http.Client.Do directly to avoid issues.
func sendRequest(c *http.Client, req *http.Request) (*http.Response, error) {
	resp, err := c.Do(req)
	if err != nil {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("failed to send request: %w", err))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("failed to read the response body: %w", err))
	}
	if err := resp.Body.Close(); err != nil {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("failed to close the response body: %w", err))
	}

	body = trimByteOrderMark(body)
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, nil
}

type httpClientOption struct {
	logger                *slog.Logger
	retryMax              int
	retryWaitMax          time.Duration
	rootCAs               *x509.CertPool
	tlsInsecureSkipVerify bool
	proxyFunc             ProxyFunc
}

func (o *httpClientOption) defaults() {
	if o.logger == nil {
		o.logger = slog.New(slog.DiscardHandler)
	}
	if o.retryMax == 0 {
		o.retryMax = 4
	}
	if o.retryWaitMax == 0 {
		o.retryWaitMax = 30 * time.Second
	}
}

func (o *httpClientOption) newRetryableHTTPClient() (*retryablehttp.Client, error) {
	retryClient := retryablehttp.NewClient()
	retryClient.Logger = o.logger
	retryClient.RetryMax = o.retryMax
	retryClient.RetryWaitMax = o.retryWaitMax
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

	if o.rootCAs != nil {
		transport.TLSClientConfig.RootCAs = o.rootCAs
	}

	if o.tlsInsecureSkipVerify {
		transport.TLSClientConfig.InsecureSkipVerify = true
	}

	transport.Proxy = o.proxyFunc

	retryClient.HTTPClient.Transport = transport

	return retryClient, nil
}

func (c *commonClient) setSystemInfo(info SystemInfo) {
	c.systemInfo = info
	c.setUserAgent()
}

func (c *commonClient) setUserAgent() {
	b, _ := json.Marshal(userAgent{
		SystemInfo:     c.systemInfo,
		BuildVersion:   buildInfo.version,
		BuildCommitSHA: buildInfo.commitSHA,
		Kind:           "scaleset",
	})
	c.userAgent = string(b)
}

// HTTPOption defines a functional option for configuring the Client.
type HTTPOption func(*httpClientOption)

// WithLogger sets a custom logger for the Client.
// If nil is passed, discard handler will be used
func WithLogger(logger *slog.Logger) HTTPOption {
	return func(c *httpClientOption) {
		if logger == nil {
			logger = slog.New(slog.DiscardHandler)
		}
		c.logger = logger
	}
}

// WithRetryMax sets the maximum number of retries for the Client.
func WithRetryMax(retryMax int) HTTPOption {
	return func(c *httpClientOption) {
		c.retryMax = retryMax
	}
}

// WithRetryWaitMax sets the maximum wait time between retries for the Client.
func WithRetryWaitMax(retryWaitMax time.Duration) HTTPOption {
	return func(c *httpClientOption) {
		c.retryWaitMax = retryWaitMax
	}
}

// WithRootCAs sets custom root certificate authorities for the Client.
func WithRootCAs(rootCAs *x509.CertPool) HTTPOption {
	return func(c *httpClientOption) {
		c.rootCAs = rootCAs
	}
}

// WithoutTLSVerify disables TLS certificate verification for the Client.
func WithoutTLSVerify() HTTPOption {
	return func(c *httpClientOption) {
		c.tlsInsecureSkipVerify = true
	}
}

// WithProxy sets a custom proxy function for the Client.
func WithProxy(proxyFunc ProxyFunc) HTTPOption {
	return func(c *httpClientOption) {
		c.proxyFunc = proxyFunc
	}
}
