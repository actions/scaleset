package scaleset

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math"
	"math/rand/v2"
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
// it and keep their state per request, so the SDK adds no shared state of its
// own. It does call Do concurrently: a Client, its message sessions, and
// concurrent goroutines all share one HTTPClient, so an implementation must be
// safe for concurrent use, as *http.Client is.
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

// MessagePollTimeout is how long one GetMessage poll attempt waits for the
// service to finish.
//
// The service holds that request for about 50 seconds when the queue is
// empty, so this stays above one minute. Two minutes leaves room if that
// hold gets longer. A stuck attempt fails here instead of sitting for
// DefaultTimeout, and is then retried like any other failed attempt. Every
// attempt, including the poll after a token refresh, gets a new window of
// this length; none shares an earlier attempt's timer.
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
// request without mutating any shared state. WithRequestRetry adjusts it for
// the requests made with one context.
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

	// WaitMax caps the backoff DefaultBackoff computes between attempts.
	// Zero applies DefaultRetryWaitMax.
	//
	// It does not cap a Retry-After the server sends, which DefaultBackoff
	// honors in full; the request context still ends such a wait. A custom
	// Backoff receives WaitMax and decides whether to respect it.
	WaitMax time.Duration

	// MaxElapsed is the total time budget for a request, measured from the
	// start of the first attempt and covering the attempts, the waits between
	// them, and the read of the final response body. Zero means no budget.
	//
	// Every attempt runs under a context whose deadline is the end of the
	// budget, or the request context's own deadline when that comes first.
	// An attempt the budget cuts off ends the request with an error matching
	// MaxElapsedExceededError, which also matches context.DeadlineExceeded.
	// When the next wait alone would reach or exceed the budget, the SDK
	// stops retrying and reports the last response without waiting.
	//
	// The request context's deadline is honored the same way: a wait that
	// would reach or run past it is not taken, and the last response is
	// reported in place of a context error. When the caller cancels or its
	// deadline fires first, the request still ends with the context's error.
	MaxElapsed time.Duration

	// ShouldRetry reports whether an attempt should be retried. Returning a
	// non-nil error abandons the request with that error. Nil applies
	// DefaultShouldRetry. Rate-limited responses are decided by OnRateLimit
	// instead.
	//
	// resp and err are both non-nil when a message poll received a response
	// but could not read or close its body. After a failed read, resp carries
	// the status and headers with an empty body. For other requests, body
	// failures remain in the final error but do not become retryable
	// transport failures.
	//
	// It may be called concurrently.
	ShouldRetry func(ctx context.Context, resp *http.Response, err error) (bool, error)

	// Backoff returns the delay before the next attempt, where attempt counts
	// from zero. Nil applies DefaultBackoff. For a rate-limited response it
	// is used only when OnRateLimit retries with a zero wait.
	//
	// It may be called concurrently.
	Backoff func(waitMin, waitMax time.Duration, attempt int, resp *http.Response) time.Duration

	// attemptTimeout bounds each attempt on its own, so a retry gets a fresh
	// window rather than what an earlier attempt left. Only the SDK sets it,
	// per request, through withAttemptTimeout.
	attemptTimeout time.Duration

	// OnRateLimit decides whether and how long to wait before retrying a
	// rate-limited response (see RateLimitError). It replaces ShouldRetry and
	// Backoff for those responses. A zero wait with retry=true falls back to
	// Backoff. Max and MaxElapsed (and the ctx deadline) still apply.
	//
	// rl describes the response just received. rl.Retries counts the
	// rate-limited retries already made for this request, so a hook can stop
	// after a few and leave the rest to the caller, for example to requeue
	// the work. rl.Unwrap reports the method, URL, and status, but not the
	// response body. The body is buffered to classify secondary-limit
	// messages and remains available to the caller.
	// If the body cannot be read, status and headers can still identify a
	// rate limit. Read and close failures remain in the final error chain.
	//
	// When the hook declines and the context is still active, the request
	// returns without waiting, with a *RateLimitError with the same Retries.
	// Cancellation or a deadline reached during the hook takes precedence.
	//
	// Nil applies DefaultOnRateLimit, which keeps the SDK's default behavior.
	// RateLimitRetries builds a hook from per-kind limits. It may be called
	// concurrently.
	OnRateLimit func(ctx context.Context, rl *RateLimitError) (wait time.Duration, retry bool)
}

// Defaults applied to a RetryConfig that leaves the corresponding field unset.
const (
	DefaultRetryMax     = 4
	DefaultRetryWaitMin = 1 * time.Second
	DefaultRetryWaitMax = 30 * time.Second
)

// DefaultRetryConfig returns the retry configuration used when WithRetry is
// not supplied. It sets no MaxElapsed budget, so the request context's
// deadline is the only limit on the total time spent retrying: a wait that
// would reach or outlast it is skipped and the last response is reported
// instead.
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

func (c RetryConfig) onRateLimitFunc() func(context.Context, *RateLimitError) (time.Duration, bool) {
	if c.OnRateLimit != nil {
		return c.OnRateLimit
	}
	return DefaultOnRateLimit
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
// the server sends one, in full: waitMax does not cap it. Otherwise it backs
// off exponentially from waitMin, adds up to half of that delay again as
// random jitter, and caps the result at waitMax.
//
// The jitter keeps clients that failed together, such as listeners hitting
// the same 5xx, from retrying in lockstep. It never shortens the delay, so
// waitMin stays the minimum.
func DefaultBackoff(waitMin, waitMax time.Duration, attempt int, resp *http.Response) time.Duration {
	if resp != nil && (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable) {
		if wait, ok := parseRetryAfter(resp.Header.Get(headerRetryAfter), time.Now()); ok {
			return wait
		}
	}

	backoff := math.Ldexp(float64(waitMin), attempt)
	if backoff >= float64(waitMax) || backoff > math.MaxInt64 {
		return waitMax
	}

	wait := time.Duration(backoff)
	if spread := int64(wait / 2); spread > 0 {
		wait += time.Duration(rand.Int64N(spread + 1))
	}

	return min(wait, waitMax)
}

// DefaultOnRateLimit is the OnRateLimit hook used when none is configured. It
// keeps the behavior the SDK has without a hook: a 429 is retried, either
// kind, and a rate-limited 403 is not, matching DefaultShouldRetry.
//
// It returns a zero wait, so the delay comes from Backoff. DefaultBackoff
// waits for the full Retry-After the server sent, uncapped, and otherwise
// backs off exponentially. Retry-After is honored this way rather than
// through rl.RetryAfter so that a primary limit carrying only
// X-RateLimit-Reset does not block until the reset, and so that a custom
// Backoff still applies to 429 responses.
//
// The request-wide limits still apply: Max, MaxElapsed, and the context
// deadline. A wait that would outlast either of the last two is not taken,
// and the 429 is returned instead.
func DefaultOnRateLimit(_ context.Context, rl *RateLimitError) (time.Duration, bool) {
	return 0, rl.StatusCode == http.StatusTooManyRequests
}

// RateLimitRule limits the retries made for one kind of rate limit. See
// RateLimitRetries.
type RateLimitRule struct {
	// MaxRetries limits the request's rate-limited retry count when this
	// kind is received. The count includes both kinds. Zero returns the
	// rate-limited response immediately.
	MaxRetries int

	// MaxWait is the longest server-requested wait to accept. Zero means no
	// cap. A longer wait is rejected, not shortened. It does not cap the
	// Backoff fallback when the server gives no usable delay.
	MaxWait time.Duration
}

// RateLimitRetries returns an OnRateLimit hook that applies primary to a
// spent primary rate limit and secondary to any other rate limit. A 403 rate
// limit is treated the same as a 429 of the same kind.
//
// The hook retries while rl.Retries, the rate-limited retries already made
// for the request, is below the rule's MaxRetries and the server's
// RetryAfter fits within MaxWait. It waits for RetryAfter; when the server
// gave no hint, the wait falls back to Backoff.
//
// It suits callers that would rather give up quickly and come back later
// than block. A controller such as ARC can return immediately on a spent
// primary limit, absorb short secondary limits in place, and requeue the work
// after the error's RetryAfter otherwise:
//
//	retry := scaleset.DefaultRetryConfig()
//	retry.OnRateLimit = scaleset.RateLimitRetries(
//		scaleset.RateLimitRule{},
//		scaleset.RateLimitRule{MaxRetries: 2, MaxWait: 5 * time.Second},
//	)
//	client, err := scaleset.NewClientWithPersonalAccessToken(config,
//		scaleset.WithRetry(retry),
//	)
//
//	// Later, in the reconciler:
//	var rl *scaleset.RateLimitError
//	if errors.As(err, &rl) {
//		wait := rl.RetryAfter
//		if wait <= 0 {
//			wait = time.Minute
//		}
//		return ctrl.Result{RequeueAfter: wait}, nil
//	}
//
// Max, MaxElapsed, and the context deadline still apply on top of the rules.
func RateLimitRetries(primary, secondary RateLimitRule) func(context.Context, *RateLimitError) (time.Duration, bool) {
	return func(_ context.Context, rl *RateLimitError) (time.Duration, bool) {
		rule := secondary
		if rl.Kind == RateLimitPrimary {
			rule = primary
		}

		if rl.Retries >= rule.MaxRetries {
			return 0, false
		}
		if rule.MaxWait > 0 && rl.RetryAfter > rule.MaxWait {
			return 0, false
		}

		return rl.RetryAfter, true
	}
}

// parseRetryAfter reads a Retry-After header in either form RFC 9110 allows:
// a number of seconds, or an HTTP date measured from now.
//
// It reports false for a value it cannot use: an empty or malformed value, a
// negative number, a value that overflows time.Duration, or a date that has
// already passed.
func parseRetryAfter(value string, now time.Time) (time.Duration, bool) {
	if value == "" {
		return 0, false
	}

	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds < 0 || seconds > int64(math.MaxInt64/int64(time.Second)) {
			return 0, false
		}
		return time.Duration(seconds) * time.Second, true
	}

	when, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}

	return durationUntil(when, now)
}

// durationUntil returns how long from now until when. It reports false when
// when has passed, or when the gap does not fit in a time.Duration: Time.Sub
// saturates instead of failing, which would turn a far-future date into a
// delay of about 292 years.
func durationUntil(when, now time.Time) (time.Duration, bool) {
	wait := when.Sub(now)
	if wait < 0 || !now.Add(wait).Equal(when) {
		return 0, false
	}

	return wait, true
}

// retryOption adjusts a RetryConfig for a single request. It lets a call site
// vary the retry policy without touching state shared with other requests.
type retryOption func(*RetryConfig)

// retryOnStatus additionally retries the given status codes, keeping the rest
// of the configured policy intact.
//
// A listed status can also be a rate limit, such as a 403 with Retry-After,
// which OnRateLimit decides instead of ShouldRetry. When the caller left
// OnRateLimit unset, a listed status is retried even where
// DefaultOnRateLimit declines, with the wait taken from Backoff, as it was
// before the hook existed. A caller that sets OnRateLimit has asked to own
// every rate-limited response, so its decision stands.
func retryOnStatus(codes ...int) retryOption {
	return func(cfg *RetryConfig) {
		if cfg.OnRateLimit == nil {
			cfg.OnRateLimit = func(ctx context.Context, rl *RateLimitError) (time.Duration, bool) {
				if slices.Contains(codes, rl.StatusCode) {
					return 0, true
				}
				return DefaultOnRateLimit(ctx, rl)
			}
		}

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

// withAttemptTimeout bounds each attempt of a request by d, on its own,
// including reading its response body. A retry gets a new window of d instead
// of what an earlier attempt left, so a stuck attempt is retried rather than
// ending the request. The request context still bounds the request as a whole.
//
// Only use it for requests that are safe to repeat after a response arrived,
// such as the message poll: a body that fails to arrive is retried.
func withAttemptTimeout(d time.Duration) retryOption {
	return func(cfg *RetryConfig) {
		cfg.attemptTimeout = d
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
