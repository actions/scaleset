package scaleset

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"runtime"
	"slices"
	"strconv"
	"time"
)

// HTTPClient is the transport seam of this SDK. Anything that can send an
// *http.Request satisfies it, including *http.Client.
//
// The SDK treats the client it is given as read-only: it never writes to the
// client, its Transport, or its TLS configuration. Retries are layered above
// it and keep their state per request, so a single HTTPClient may safely be
// shared between a Client, its message sessions, and concurrent goroutines.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// HTTPClientConfig describes the transport settings of an HTTP client built by
// NewHTTPClient. Every field is optional.
type HTTPClientConfig struct {
	// RootCAs is the set of certificate authorities used to verify servers.
	// Nil uses the host's trust store.
	RootCAs *x509.CertPool

	// Certificates are client certificates presented during TLS handshakes,
	// for mTLS. They are presented on every connection the client makes. For
	// host-scoped selection, build a client yourself and set
	// tls.Config.GetClientCertificate.
	Certificates []tls.Certificate

	// InsecureSkipVerify disables server certificate verification.
	// Use for testing only.
	InsecureSkipVerify bool

	// Proxy selects a proxy for a request. Nil uses http.ProxyFromEnvironment.
	Proxy ProxyFunc

	// Timeout bounds a single HTTP attempt, retries excluded.
	// Zero applies DefaultTimeout.
	Timeout time.Duration
}

// DefaultTimeout bounds a single HTTP attempt when HTTPClientConfig leaves
// Timeout unset.
//
// It is the client timeout the SDK applied before transport configuration
// moved to the caller.
const DefaultTimeout = 5 * time.Minute

// MessagePollTimeout is how long GetMessage waits for the service to finish
// a long poll.
//
// The service holds that request for about 50 seconds when the queue is
// empty, so this stays above one minute. Two minutes leaves room for that
// hold plus a slow connection, and a stuck poll fails here instead of
// sitting for DefaultTimeout.
const MessagePollTimeout = 2 * time.Minute

// Timeouts of the transport retryablehttp built through
// cleanhttp.DefaultPooledTransport. They are the previous defaults, not knobs.
const (
	defaultDialTimeout           = 30 * time.Second
	defaultDialKeepAlive         = 30 * time.Second
	defaultIdleConnTimeout       = 90 * time.Second
	defaultTLSHandshakeTimeout   = 10 * time.Second
	defaultExpectContinueTimeout = 1 * time.Second
)

// DefaultTransport returns the *http.Transport that the SDK uses when no HTTP
// client is supplied. The result is owned by the caller and safe to modify.
//
// Its timeouts are the ones the SDK used before, via cleanhttp's pooled
// transport. They are set explicitly so a replaced http.DefaultTransport, or
// a future stdlib default, cannot change them.
func DefaultTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   defaultDialTimeout,
			KeepAlive: defaultDialKeepAlive,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       defaultIdleConnTimeout,
		TLSHandshakeTimeout:   defaultTLSHandshakeTimeout,
		ExpectContinueTimeout: defaultExpectContinueTimeout,
		ForceAttemptHTTP2:     true,
		// The listener holds a long poll open per scale set alongside regular
		// API traffic, so the stdlib default of 2 idle connections per host
		// is low. This is the value cleanhttp used.
		MaxIdleConnsPerHost: runtime.GOMAXPROCS(0) + 1,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
	}
}

// NewHTTPClient builds an *http.Client from cfg, for use with WithHTTPClient.
//
// It exists so that the common cases - a custom CA bundle, a proxy, mTLS - do
// not require assembling a transport by hand. Anything it does not cover is a
// field away, because the result is an ordinary client:
//
//	httpClient := scaleset.NewHTTPClient(scaleset.HTTPClientConfig{RootCAs: pool})
//	httpClient.Transport.(*http.Transport).MaxIdleConnsPerHost = 100
//
//	client, err := scaleset.NewClientWithPersonalAccessToken(config,
//		scaleset.WithHTTPClient(httpClient),
//	)
//
// The returned client is owned by the caller. The SDK never modifies it.
func NewHTTPClient(cfg HTTPClientConfig) *http.Client {
	transport := DefaultTransport()

	transport.TLSClientConfig.RootCAs = cfg.RootCAs
	transport.TLSClientConfig.InsecureSkipVerify = cfg.InsecureSkipVerify
	transport.TLSClientConfig.Certificates = slices.Clone(cfg.Certificates)

	if cfg.Proxy != nil {
		transport.Proxy = cfg.Proxy
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}

// RetryConfig describes how the SDK retries a request. Retries are owned by
// the SDK rather than by the HTTP client, so that the policy can differ per
// request without mutating any shared state.
//
// WithRetry replaces this configuration wholesale. To adjust the defaults,
// start from DefaultRetryConfig:
//
//	retry := scaleset.DefaultRetryConfig()
//	retry.Max = 8
//	client, err := scaleset.NewClientWithPersonalAccessToken(config,
//		scaleset.WithRetry(retry),
//	)
type RetryConfig struct {
	// Max is the number of retries after the first attempt.
	// Zero disables retries.
	Max int

	// WaitMin is the base delay between attempts.
	// Zero applies DefaultRetryWaitMin.
	WaitMin time.Duration

	// WaitMax caps the delay between attempts.
	// Zero applies DefaultRetryWaitMax.
	WaitMax time.Duration

	// ShouldRetry reports whether an attempt should be retried. Returning a
	// non-nil error abandons the request with that error. Nil applies
	// DefaultShouldRetry.
	//
	// It may be called concurrently.
	ShouldRetry func(ctx context.Context, resp *http.Response, err error) (bool, error)

	// Backoff returns the delay before the next attempt, where attempt counts
	// from zero. Nil applies DefaultBackoff.
	//
	// It may be called concurrently.
	Backoff func(waitMin, waitMax time.Duration, attempt int, resp *http.Response) time.Duration
}

// Defaults applied to a RetryConfig that leaves the corresponding field unset.
const (
	DefaultRetryMax     = 4
	DefaultRetryWaitMin = 1 * time.Second
	DefaultRetryWaitMax = 30 * time.Second
)

// DefaultRetryConfig returns the retry configuration used when WithRetry is
// not supplied.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		Max:     DefaultRetryMax,
		WaitMin: DefaultRetryWaitMin,
		WaitMax: DefaultRetryWaitMax,
	}
}

func (c RetryConfig) shouldRetryFunc() func(context.Context, *http.Response, error) (bool, error) {
	if c.ShouldRetry != nil {
		return c.ShouldRetry
	}
	return DefaultShouldRetry
}

func (c RetryConfig) backoffFunc() func(time.Duration, time.Duration, int, *http.Response) time.Duration {
	if c.Backoff != nil {
		return c.Backoff
	}
	return DefaultBackoff
}

func (c RetryConfig) waits() (waitMin, waitMax time.Duration) {
	waitMin, waitMax = c.WaitMin, c.WaitMax
	if waitMin == 0 {
		waitMin = DefaultRetryWaitMin
	}
	if waitMax == 0 {
		waitMax = DefaultRetryWaitMax
	}
	return waitMin, waitMax
}

// DefaultShouldRetry retries transport errors, 429 Too Many Requests, and
// 5xx responses other than 501 Not Implemented. It does not retry once the
// request context is done, or when the transport reports a TLS certificate
// that cannot be verified, since neither improves on a second attempt.
func DefaultShouldRetry(ctx context.Context, resp *http.Response, err error) (bool, error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return false, ctxErr
	}

	if err != nil {
		return !isCertificateError(err), nil
	}

	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return true, nil
	case resp.StatusCode == 0:
		return true, nil
	case resp.StatusCode >= 500 && resp.StatusCode != http.StatusNotImplemented:
		return true, nil
	default:
		return false, nil
	}
}

func isCertificateError(err error) bool {
	var verificationErr *tls.CertificateVerificationError
	if errors.As(err, &verificationErr) {
		return true
	}

	var unknownAuthorityErr x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthorityErr) {
		return true
	}

	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return true
	}

	var invalidErr x509.CertificateInvalidError

	return errors.As(err, &invalidErr)
}

// DefaultBackoff waits for the Retry-After hint of a 429 or 503 response when
// the server sends one, and otherwise backs off exponentially from waitMin,
// capped at waitMax.
func DefaultBackoff(waitMin, waitMax time.Duration, attempt int, resp *http.Response) time.Duration {
	if resp != nil && (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable) {
		if wait, ok := parseRetryAfter(resp.Header.Get("Retry-After")); ok {
			return wait
		}
	}

	backoff := math.Ldexp(float64(waitMin), attempt)
	if backoff > float64(waitMax) || backoff > math.MaxInt64 {
		return waitMax
	}

	return time.Duration(backoff)
}

// parseRetryAfter reads a Retry-After header, which holds either a number of
// seconds or an HTTP date.
func parseRetryAfter(value string) (time.Duration, bool) {
	if value == "" {
		return 0, false
	}

	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds < 0 {
			return 0, false
		}
		return time.Duration(seconds) * time.Second, true
	}

	when, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}

	wait := time.Until(when)
	if wait < 0 {
		return 0, false
	}

	return wait, true
}

// retryOption adjusts a RetryConfig for a single request. It lets a call site
// vary the retry policy without touching state shared with other requests.
type retryOption func(*RetryConfig)

// retryOnStatus additionally retries the given status codes, keeping the rest
// of the configured policy intact.
func retryOnStatus(codes ...int) retryOption {
	return func(cfg *RetryConfig) {
		base := cfg.shouldRetryFunc()
		cfg.ShouldRetry = func(ctx context.Context, resp *http.Response, err error) (bool, error) {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return false, ctxErr
			}
			if resp != nil && slices.Contains(codes, resp.StatusCode) {
				return true, nil
			}
			return base(ctx, resp, err)
		}
	}
}

// clientForMessagePoll returns a client whose per-attempt timeout is at least
// MessagePollTimeout.
//
// A *http.Client with a shorter positive Timeout would cut the long poll off.
// The returned value is a copy; the client the caller supplied is not written.
// A zero Timeout already means no client timeout, and anything that is not a
// *http.Client has to allow MessagePollTimeout itself.
func clientForMessagePoll(client HTTPClient) HTTPClient {
	httpClient, ok := client.(*http.Client)
	if !ok || httpClient == nil || httpClient.Timeout == 0 || httpClient.Timeout >= MessagePollTimeout {
		return client
	}

	lifted := *httpClient
	lifted.Timeout = MessagePollTimeout

	return &lifted
}

// drainAndClose consumes a bounded prefix of a discarded response so that the
// underlying connection can be reused, then closes it.
func drainAndClose(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, drainLimit))
	_ = resp.Body.Close()
}

const drainLimit = 4096
