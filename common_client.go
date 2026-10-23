package scaleset

import (
	"bytes"
	"context"
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
	cfg := c.retry
	for _, opt := range opts {
		opt(&cfg)
	}

	start := time.Now()
	sendReq := req
	budget := func(err error) error { return err }
	if cfg.MaxElapsed > 0 {
		// The budget context stays open until the body has been read: the
		// body is streamed under the context of the attempt that produced it.
		ctx, cancel := context.WithDeadlineCause(req.Context(), start.Add(cfg.MaxElapsed), MaxElapsedExceededError)
		defer cancel()
		sendReq = req.WithContext(ctx)

		// An error caused by the budget, rather than by the caller's own
		// context, is reported as a budget overrun.
		budget = func(err error) error {
			if errors.Is(context.Cause(ctx), MaxElapsedExceededError) {
				return fmt.Errorf("%w after %s: %w", MaxElapsedExceededError, cfg.MaxElapsed, err)
			}
			return err
		}
	}

	resp, err := c.send(client, sendReq, cfg, start)
	if err != nil {
		if resp != nil && resp.Body != nil {
			defer resp.Body.Close()
		}
		return nil, newRequestResponseError(req, resp, fmt.Errorf("failed to send request: %w", budget(err)))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		defer resp.Body.Close()
		return nil, newRequestResponseError(req, resp, fmt.Errorf("failed to read the response body: %w", budget(err)))
	}
	if err := resp.Body.Close(); err != nil {
		return nil, newRequestResponseError(req, resp, fmt.Errorf("failed to close the response body: %w", err))
	}

	resp.Body = io.NopCloser(bytes.NewReader(trimByteOrderMark(body)))

	return resp, nil
}

// send runs the retry loop around the configured HTTP client, under the
// retry policy cfg. start is when the request began, from which MaxElapsed is
// measured.
//
// cfg is a copy local to this call, so concurrent requests never observe one
// another's adjustments, and nothing owned by the caller is written to.
func (c *commonClient) send(client HTTPClient, req *http.Request, cfg RetryConfig, start time.Time) (*http.Response, error) {
	shouldRetry := cfg.shouldRetryFunc()
	backoff := cfg.backoffFunc()
	onRateLimit := cfg.onRateLimitFunc()
	waitMin, waitMax := cfg.waits()
	rateLimitRetries := 0

	for attempt := 0; ; attempt++ {
		attemptReq, err := requestForAttempt(req, attempt)
		if err != nil {
			return nil, err
		}

		attemptReq, cancelAttempt := withAttemptDeadline(attemptReq, cfg.attemptTimeout)
		resp, doErr := client.Do(attemptReq)
		var body []byte
		if doErr == nil && (cfg.attemptTimeout > 0 || resp != nil &&
			(resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests)) {
			body, doErr = readForRetry(resp)
		}

		var wait time.Duration
		rl, limited := rateLimitFromAttempt(req, resp, body, rateLimitRetries)
		if limited {
			// Rate-limited responses are decided by OnRateLimit alone.
			if ctxErr := req.Context().Err(); ctxErr != nil {
				drainAndClose(resp)
				cancelAttempt()
				return nil, ctxErr
			}
			if attempt >= cfg.Max || !replayable(req) {
				return withRateLimitRetries(req, cancelOnClose(resp, cancelAttempt), rateLimitRetries), doErr
			}

			var retry bool
			wait, retry = onRateLimit(req.Context(), rl)
			if ctxErr := req.Context().Err(); ctxErr != nil {
				drainAndClose(resp)
				cancelAttempt()
				return nil, ctxErr
			}
			if !retry {
				c.logger.Debug("not retrying: rate limit hook declined",
					"method", req.Method,
					"url", req.URL.Redacted(),
					"attempt", attempt+1,
					"kind", rl.Kind,
					"retry_after", rl.RetryAfter,
					"rate_limit_retries", rateLimitRetries,
				)
				return withRateLimitRetries(req, cancelOnClose(resp, cancelAttempt), rateLimitRetries), doErr
			}
			if wait <= 0 {
				wait = backoff(waitMin, waitMax, attempt, resp)
			}
		} else {
			// The policy sees the request's own context, so an attempt that ran
			// out of its window is retried like any other transport error.
			retry, policyErr := shouldRetry(req.Context(), resp, doErr)
			if policyErr != nil {
				drainAndClose(resp)
				cancelAttempt()
				return nil, policyErr
			}
			if !retry || attempt >= cfg.Max || !replayable(req) {
				return withRateLimitRetries(req, cancelOnClose(resp, cancelAttempt), rateLimitRetries), doErr
			}

			wait = backoff(waitMin, waitMax, attempt, resp)
		}

		// A wait that reaches or exceeds the context deadline or MaxElapsed
		// budget would only end in a context error, losing the
		// response that explains why the request failed. Return that response
		// now, as an exhausted retry does, so the caller sees it.
		if reason, ok := waitOutlasts(req, cfg.MaxElapsed, start, wait); ok {
			c.logger.Debug("not retrying: wait reaches or exceeds "+reason,
				"method", req.Method,
				"url", req.URL.Redacted(),
				"attempt", attempt+1,
				"wait", wait,
			)
			if ctxErr := req.Context().Err(); ctxErr != nil {
				drainAndClose(resp)
				cancelAttempt()
				return nil, ctxErr
			}
			return withRateLimitRetries(req, cancelOnClose(resp, cancelAttempt), rateLimitRetries), doErr
		}

		c.logger.Debug("retrying request",
			"method", req.Method,
			"url", req.URL.Redacted(),
			"attempt", attempt+1,
			"wait", wait,
		)
		drainAndClose(resp)
		cancelAttempt()

		timer := time.NewTimer(wait)
		select {
		case <-req.Context().Done():
			timer.Stop()
			return nil, req.Context().Err()
		case <-timer.C:
		}

		if limited {
			rateLimitRetries++
		}
	}
}

// withAttemptDeadline bounds one attempt by timeout, when it is positive. The
// returned cancel must run once the attempt's response is done with.
func withAttemptDeadline(req *http.Request, timeout time.Duration) (*http.Request, context.CancelFunc) {
	if timeout <= 0 {
		return req, func() {}
	}

	ctx, cancel := context.WithTimeout(req.Context(), timeout)

	return req.WithContext(ctx), cancel
}

// readForRetry buffers resp's body before the retry decision, under the
// attempt's context. Polls need this to retry stalled bodies; 403s and 429s
// need the message to distinguish primary and secondary limits.
func readForRetry(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if err != nil {
		// The status and headers, such as Retry-After, still inform the
		// retry policy and the final error. The body is gone.
		resp.Body = http.NoBody
		return nil, fmt.Errorf("failed to read the response body: %w", err)
	}

	body = trimByteOrderMark(body)
	resp.Body = io.NopCloser(bytes.NewReader(body))
	if closeErr != nil {
		return body, fmt.Errorf("failed to close the response body: %w", closeErr)
	}

	return body, nil
}

// cancelOnClose defers cancel until resp's body is closed, since the body is
// streamed under the context of the attempt that produced it. Without a body
// to read, cancel runs at once.
func cancelOnClose(resp *http.Response, cancel context.CancelFunc) *http.Response {
	if resp == nil || resp.Body == nil || resp.Body == http.NoBody {
		cancel()
		return resp
	}

	resp.Body = &cancelOnCloseBody{ReadCloser: resp.Body, cancel: cancel}

	return resp
}

// rateLimitFromAttempt uses the final error's classification without
// consuming the buffered response the caller will read.
func rateLimitFromAttempt(req *http.Request, resp *http.Response, body []byte, retries int) (*RateLimitError, bool) {
	if resp == nil ||
		(resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusTooManyRequests) {
		return nil, false
	}

	response := *resp
	response.Body = io.NopCloser(bytes.NewReader(trimByteOrderMark(body)))
	var rl *RateLimitError
	if !errors.As(newRequestResponseError(req, &response, errors.New("unexpected status")), &rl) {
		return nil, false
	}

	rl.Retries = retries
	rl.err = fmt.Errorf("request %s %s failed (status=%q)", req.Method, req.URL.Redacted(), resp.Status)

	return rl, true
}

// rateLimitRetriesKey is the context key under which send records, on the
// response's request, how many rate-limited retries preceded the response.
type rateLimitRetriesKey struct{}

// withRateLimitRetries records retries on resp, so that the *RateLimitError
// later built from it by newRequestResponseError reports them. The count
// travels with this response alone, which keeps concurrent requests apart.
//
// The derived context keeps the attempt's context as its parent, so the
// MaxElapsed budget that the response body is read under is unaffected.
func withRateLimitRetries(req *http.Request, resp *http.Response, retries int) *http.Response {
	if resp == nil || retries == 0 {
		return resp
	}

	sent := resp.Request
	if sent == nil {
		sent = req
	}
	resp.Request = sent.WithContext(context.WithValue(sent.Context(), rateLimitRetriesKey{}, retries))

	return resp
}

type cancelOnCloseBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelOnCloseBody) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}

// rateLimitRetriesOf reports the count recorded by withRateLimitRetries.
func rateLimitRetriesOf(resp *http.Response) int {
	if resp == nil || resp.Request == nil {
		return 0
	}
	retries, _ := resp.Request.Context().Value(rateLimitRetriesKey{}).(int)
	return retries
}

// waitOutlasts reports whether waiting wait before the next attempt would run
// to or past the request context's deadline, or the maxElapsed budget measured
// from start. The reason names the limit that would be reached.
func waitOutlasts(req *http.Request, maxElapsed time.Duration, start time.Time, wait time.Duration) (reason string, ok bool) {
	now := time.Now()
	if maxElapsed > 0 && wait >= maxElapsed-now.Sub(start) {
		return "MaxElapsed budget", true
	}
	if deadline, has := req.Context().Deadline(); has && !now.Add(wait).Before(deadline) {
		return "context deadline", true
	}
	return "", false
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
// timeouts - stay under the caller's control, except as noted for GetMessage
// below. Retries are layered above the client and keep their state per
// request. The client is shared between a Client, its message sessions, and
// concurrent requests, so Do must be safe for concurrent use, as it is for
// *http.Client.
//
// Use NewHTTPClient to build one, or supply any implementation, including a
// client wrapping an instrumented http.RoundTripper. A nil client, including a
// nil *http.Client, selects the SDK default.
//
// Per-attempt timeouts come from the client. A client without a Timeout, such
// as &http.Client{} or http.DefaultClient, puts no limit on an attempt;
// NewHTTPClient applies DefaultTimeout. MessageSessionClient.GetMessage is the
// exception: it bounds each poll attempt by MessagePollTimeout, and when a
// *http.Client has a shorter positive Timeout, it polls through a copy whose
// Timeout is raised to MessagePollTimeout. The supplied client is not
// modified.
func WithHTTPClient(client HTTPClient) HTTPOption {
	if hc, ok := client.(*http.Client); ok && hc == nil {
		client = nil
	}

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
	if !ok || httpClient == nil {
		return nil, false
	}
	// A client without a Transport sends through http.DefaultTransport.
	roundTripper := httpClient.Transport
	if roundTripper == nil {
		roundTripper = http.DefaultTransport
	}
	transport, ok := roundTripper.(*http.Transport)

	return transport, ok
}
