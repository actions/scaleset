package scaleset

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

const (
	headerActionsActivityID = "ActivityId"
	headerGitHubRequestID   = "X-GitHub-Request-Id"
)

type commonClient struct {
	systemInfo SystemInfo // never set directly, use setSystemInfoUnlocked

	userAgent string

	httpClientOption
}

func newCommonClient(systemInfo SystemInfo, httpClientOption httpClientOption) *commonClient {
	c := &commonClient{
		httpClientOption: httpClientOption,
	}
	c.setSystemInfo(systemInfo)

	return c
}

type httpClientOption struct {
	logger *slog.Logger

	// httpClient is owned by its provider and treated as read-only. It is
	// shared by a Client and every message session derived from it.
	httpClient HTTPClient

	// retry is owned by the SDK. It is copied before a request adjusts it, so
	// a per-request policy never becomes visible to another request.
	retry RetryConfig
}

func (o *httpClientOption) defaults() {
	if o.logger == nil {
		o.logger = slog.New(slog.DiscardHandler)
	}
	if o.httpClient == nil {
		o.httpClient = NewHTTPClient(HTTPClientConfig{})
	}
}

// do sends req and returns its response, retrying according to the client's
// retry configuration. Any opts adjust that configuration for this request
// alone.
//
// It reads the response body to completion, closes it, trims a byte order
// mark when present, and replaces the body with the result. Use it rather
// than calling HTTPClient.Do directly.
func (c *commonClient) do(req *http.Request, opts ...retryOption) (*http.Response, error) {
	return c.doWith(c.httpClient, req, opts...)
}

// doWith is do, sending through client instead of the one the SDK was given.
// client may be a copy with a longer timeout. It is never the caller's value
// with a field written on it.
func (c *commonClient) doWith(client HTTPClient, req *http.Request, opts ...retryOption) (*http.Response, error) {
	resp, err := c.send(client, req, opts...)
	if err != nil {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("failed to send request: %w", err))
	}

	_, err = bufferResponseBody(resp)
	if err != nil {
		return nil, newRequestResponseError(req, resp, err)
	}

	return resp, nil
}

// bufferedResponseBody keeps the original bytes even after an endpoint's
// decoder has consumed the BOM-trimmed reader.
type bufferedResponseBody struct {
	*bytes.Reader
	raw []byte
}

func (*bufferedResponseBody) Close() error { return nil }

func bufferResponseBody(resp *http.Response) ([]byte, error) {
	if resp == nil {
		return nil, nil
	}
	if body, ok := resp.Body.(*bufferedResponseBody); ok {
		return body.raw, nil
	}

	var body []byte
	var readErr, closeErr error
	if resp.Body != nil {
		body, readErr = io.ReadAll(resp.Body)
		closeErr = resp.Body.Close()
	}
	resp.Body = &bufferedResponseBody{
		Reader: bytes.NewReader(trimByteOrderMark(body)),
		raw:    body,
	}
	if readErr != nil {
		readErr = fmt.Errorf("failed to read the response body: %w", readErr)
	}
	if closeErr != nil {
		closeErr = fmt.Errorf("failed to close the response body: %w", closeErr)
	}
	return body, errors.Join(readErr, closeErr)
}

// decodeJSONBody requires exactly one JSON value; a decoder alone accepts
// trailing garbage after a valid value. Endpoint-specific nulls remain valid.
func decodeJSONBody(body io.Reader, target any) error {
	decoder := json.NewDecoder(body)
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		if err != nil {
			return err
		}
		return errors.New("response body contains multiple JSON values")
	}
	return nil
}

// send runs the retry loop around the configured HTTP client.
//
// The policy for this call lives in a local copy of the configuration, so
// concurrent requests never observe one another's adjustments, and nothing
// owned by the caller is written to.
func (c *commonClient) send(client HTTPClient, req *http.Request, opts ...retryOption) (*http.Response, error) {
	cfg := c.retry
	for _, opt := range opts {
		opt(&cfg)
	}

	shouldRetry := cfg.shouldRetryFunc()
	backoff := cfg.backoffFunc()
	waitMin, waitMax := cfg.waits()

	for attempt := 0; ; attempt++ {
		attemptReq, err := requestForAttempt(req, attempt)
		if err != nil {
			return nil, err
		}

		resp, doErr := client.Do(attemptReq)
		if resp == nil && doErr == nil {
			return nil, errMissingResponse
		}

		retry, policyErr := shouldRetry(req.Context(), resp, doErr)
		if policyErr != nil {
			return resp, errors.Join(doErr, policyErr)
		}
		if !retry || attempt >= cfg.Max || !replayable(req) {
			return resp, doErr
		}

		wait := backoff(waitMin, waitMax, attempt, resp)
		c.logger.Debug("retrying request",
			"method", req.Method,
			"url", req.URL.Redacted(),
			"attempt", attempt+1,
			"wait", wait,
		)
		drainAndClose(resp)

		timer := time.NewTimer(wait)
		select {
		case <-req.Context().Done():
			timer.Stop()
			return nil, req.Context().Err()
		case <-timer.C:
		}
	}
}

// replayable reports whether a request can be sent more than once.
func replayable(req *http.Request) bool {
	return req.Body == nil || req.GetBody != nil
}

// requestForAttempt returns the request to send for the given attempt.
//
// Retries get a shallow copy holding a fresh body. The copy keeps the body of
// an earlier attempt from being replaced while the transport may still be
// writing it, and leaves the caller's request untouched.
func requestForAttempt(req *http.Request, attempt int) (*http.Request, error) {
	if attempt == 0 || req.Body == nil {
		return req, nil
	}

	body, err := req.GetBody()
	if err != nil {
		return nil, fmt.Errorf("failed to rewind request body for retry: %w", err)
	}

	retryReq := *req
	retryReq.Body = body

	return &retryReq, nil
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

// WithHTTPClient sends every SDK request through the given client.
//
// The SDK never modifies the client, its Transport, or its TLS configuration,
// so transport concerns - TLS, proxies, connection pooling, per-attempt
// timeouts - stay under the caller's control. Retries are layered above the
// client and keep their state per request, which makes it safe to share one
// client between a Client, its message sessions, and concurrent requests.
//
// Use NewHTTPClient to build one, or supply any implementation, including a
// client wrapping an instrumented http.RoundTripper. A nil client selects the
// SDK default.
func WithHTTPClient(client HTTPClient) HTTPOption {
	return func(c *httpClientOption) {
		c.httpClient = client
	}
}

// WithRetry replaces the retry configuration. A zero RetryConfig.Max disables
// retries. To adjust individual settings, start from DefaultRetryConfig.
func WithRetry(retry RetryConfig) HTTPOption {
	return func(c *httpClientOption) {
		c.retry = retry
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

// tlsConfigFromClient reports the TLS configuration an HTTP client will use,
// for tests that assert on transport settings.
func tlsConfigFromClient(client HTTPClient) (*tls.Config, bool) {
	transport, ok := transportOf(client)
	if !ok || transport.TLSClientConfig == nil {
		return nil, false
	}

	return transport.TLSClientConfig, true
}

// transportOf returns the *http.Transport behind an HTTP client, when there is
// one. A caller may supply any HTTPClient implementation, so the SDK only
// inspects a transport for diagnostics and never depends on finding it.
func transportOf(client HTTPClient) (*http.Transport, bool) {
	httpClient, ok := client.(*http.Client)
	if !ok {
		return nil, false
	}
	transport, ok := httpClient.Transport.(*http.Transport)

	return transport, ok
}
