package scaleset

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"slices"
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
	logger *slog.Logger

	// Options for built-in retryable HTTP client.
	// Ignored when a custom retryable HTTP client or factory is provided.
	retryMax     int
	retryWaitMax time.Duration

	// fields added to the transport if specified
	rootCAs               *x509.CertPool
	tlsInsecureSkipVerify bool
	tlsClientCertificates []tls.Certificate
	proxyFunc             ProxyFunc
	timeout               time.Duration

	retryableHTTPClient        *retryablehttp.Client
	retryableHTTPClientFactory func() *retryablehttp.Client
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
	if o.timeout == 0 {
		o.timeout = 5 * time.Minute
	}
}

func (o *httpClientOption) newRetryableHTTPClient() (*retryablehttp.Client, error) {
	var retryClient *retryablehttp.Client
	if o.retryableHTTPClientFactory != nil {
		retryClient = o.retryableHTTPClientFactory()
		if retryClient == nil || retryClient.HTTPClient == nil {
			return nil, fmt.Errorf("retryable HTTP client factory returned a nil client")
		}
	} else if o.retryableHTTPClient != nil {
		retryClient = o.retryableHTTPClient
	} else {
		retryClient = retryablehttp.NewClient()
		retryClient.RetryMax = o.retryMax
		retryClient.RetryWaitMax = o.retryWaitMax
	}

	if retryClient.HTTPClient.Timeout == 0 {
		retryClient.HTTPClient.Timeout = o.timeout
	}

	retryClient.Logger = o.logger

	transport, ok := retryClient.HTTPClient.Transport.(*http.Transport)
	if !ok {
		// this should always be true, because retryablehttp.NewClient() uses
		// cleanhttp.DefaultPooledTransport()
		return nil, fmt.Errorf("failed to get http transport from retryablehttp client")
	}
	// HTTP/2 initialization can add handlers to this map.
	transport.TLSNextProto = maps.Clone(transport.TLSNextProto)
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	} else {
		// A fresh transport can still share its TLS config with another client.
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		// HTTP/2 initialization can append to the transport's protocol list.
		transport.TLSClientConfig.NextProtos = slices.Clone(transport.TLSClientConfig.NextProtos)
	}

	if o.rootCAs != nil {
		transport.TLSClientConfig.RootCAs = o.rootCAs
	}

	if o.tlsInsecureSkipVerify {
		transport.TLSClientConfig.InsecureSkipVerify = true
	}

	if len(o.tlsClientCertificates) > 0 {
		transport.TLSClientConfig.Certificates = append(
			slices.Clone(transport.TLSClientConfig.Certificates),
			o.tlsClientCertificates...,
		)
	}

	if o.proxyFunc != nil {
		transport.Proxy = o.proxyFunc
	}

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

// WithRetryableHTTPClint allows users to provide a custom retryable HTTP client.
// If not set, a default client will be used with the specified retry and timeout settings.
//
// Deprecated: Use WithRetryableHTTPClientFactory. Token refresh changes the
// retry policy, which can race with requests that share this client.
func WithRetryableHTTPClint(client *retryablehttp.Client) HTTPOption {
	return func(c *httpClientOption) {
		c.retryableHTTPClient = client
		c.retryableHTTPClientFactory = nil
	}
}

// WithRetryableHTTPClientFactory creates a custom client for each SDK HTTP client,
// including token refresh and message sessions. The factory must return a new
// retryable client, http.Client, and *http.Transport each time. The SDK applies
// HTTP options and can change the retry policy before it uses each client.
// The factory must be safe to call concurrently. The last custom-client option wins.
// A nil factory selects the default client.
func WithRetryableHTTPClientFactory(factory func() *retryablehttp.Client) HTTPOption {
	return func(c *httpClientOption) {
		c.retryableHTTPClientFactory = factory
		c.retryableHTTPClient = nil
	}
}

// WithLogger sets a custom logger for the Client.
// If nil is passed, a discard logger will be used.
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

// WithTLSClientCertificate configures a TLS client certificate for mTLS authentication.
// Note: The certificate is added to the TLS transport configuration and will be presented
// during TLS handshakes for ALL connections made by this client, not just proxy connections.
// If you need host-scoped certificate selection, consider using a custom transport with
// tls.Config.GetClientCertificate instead.
func WithTLSClientCertificate(cert tls.Certificate) HTTPOption {
	return func(c *httpClientOption) {
		// Message sessions copy options. Do not append into a parent's array.
		c.tlsClientCertificates = append(slices.Clone(c.tlsClientCertificates), cert)
	}
}

// WithTLSClientCertificateFromFile loads a TLS client certificate and key from files.
// This is a convenience function that wraps WithTLSClientCertificate.
// See WithTLSClientCertificate for important notes about certificate scope.
func WithTLSClientCertificateFromFile(certFile, keyFile string) (HTTPOption, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %w", err)
	}
	return WithTLSClientCertificate(cert), nil
}

// WithProxy sets a custom proxy function for the Client.
func WithProxy(proxyFunc ProxyFunc) HTTPOption {
	return func(c *httpClientOption) {
		c.proxyFunc = proxyFunc
	}
}

// WithTimeout sets a timeout for the Client.
func WithTimeout(duration time.Duration) HTTPOption {
	return func(c *httpClientOption) {
		c.timeout = duration
	}
}
