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

type commonClient struct {
	httpClient *http.Client

	buildInfo  clientBuildInfo
	systemInfo SystemInfo // never set directly, use setSystemInfoUnlocked

	userAgent string

	httpClientOption
}

func newCommonClient(systemInfo SystemInfo, httpClienhttpClientOption httpClientOption) *commonClient {
	c := &commonClient{
		buildInfo:        buildInfo,
		httpClientOption: httpClienhttpClientOption,
	}
	c.setSystemInfo(systemInfo)

	retryableHTTPClient, err := httpClienhttpClientOption.newRetryableHTTPClient()
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

type httpClientOption struct {
	logger                *slog.Logger
	retryMax              int
	retryWaitMax          time.Duration
	rootCAs               *x509.CertPool
	tlsInsecureSkipVerify bool
	proxyFunc             ProxyFunc
}

func (opt *httpClientOption) defaults() {
	if opt.logger == nil {
		opt.logger = slog.New(slog.DiscardHandler)
	}
	if opt.retryMax == 0 {
		opt.retryMax = 4
	}
	if opt.retryWaitMax == 0 {
		opt.retryWaitMax = 30 * time.Second
	}
}

func defaultHTTPClientOption() httpClientOption {
	var opt httpClientOption
	opt.defaults()
	return opt
}

func (c *httpClientOption) newRetryableHTTPClient() (*retryablehttp.Client, error) {
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

func (c *commonClient) setSystemInfo(info SystemInfo) {
	c.systemInfo = info
	c.setUserAgent()
}

func (c *commonClient) setUserAgent() {
	b, _ := json.Marshal(userAgent{
		SystemInfo:     c.systemInfo,
		BuildVersion:   c.buildInfo.version,
		BuildCommitSHA: c.buildInfo.commitSHA,
	})
	c.userAgent = string(b)
}

// HTTPOption defines a functional option for configuring the Client.
type HTTPOption func(*httpClientOption)

// WithLogger sets a custom logger for the Client.
func WithLogger(logger slog.Logger) HTTPOption {
	return func(c *httpClientOption) {
		c.logger = &logger
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
