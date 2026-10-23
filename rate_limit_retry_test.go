package scaleset

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rateLimitedStub answers every request with status and header.
func rateLimitedStub(calls *atomic.Int64, status int, header http.Header) httpClientFunc {
	return func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		resp := newStubResponse(req, status, `{"message":"rate limited"}`)
		for key, values := range canonical(header) {
			resp.Header[key] = values
		}
		resp.ContentLength = int64(len(`{"message":"rate limited"}`))
		resp.Header.Set("Content-Type", "application/json")
		return resp, nil
	}
}

func newStubCommonClient(stub HTTPClient, retry RetryConfig) *commonClient {
	opts := defaultHTTPClientOption()
	WithHTTPClient(stub)(&opts)
	WithRetry(retry)(&opts)
	return newCommonClient(testSystemInfo, opts)
}

// doRateLimited sends one request through client and returns the error the
// SDK builds for a non-2xx response, as every API method does.
func doRateLimited(t *testing.T, ctx context.Context, client *commonClient, opts ...retryOption) error {
	t.Helper()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://example.com/generatejitconfig", nil)
	require.NoError(t, err)

	resp, err := client.do(req, opts...)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return newRequestResponseError(req, resp, fmt.Errorf("unexpected status code: %d", resp.StatusCode))
}

func requireRateLimitError(t *testing.T, err error) *RateLimitError {
	t.Helper()
	var rl *RateLimitError
	require.ErrorAs(t, err, &rl)
	return rl
}

func TestDefaultOnRateLimit(t *testing.T) {
	for _, tc := range []struct {
		name      string
		rl        RateLimitError
		wantRetry bool
	}{
		{name: "secondary 429", rl: RateLimitError{Kind: RateLimitSecondary, StatusCode: http.StatusTooManyRequests, RetryAfter: time.Minute}, wantRetry: true},
		{name: "primary 429", rl: RateLimitError{Kind: RateLimitPrimary, StatusCode: http.StatusTooManyRequests, RetryAfter: time.Hour}, wantRetry: true},
		{name: "secondary 403", rl: RateLimitError{Kind: RateLimitSecondary, StatusCode: http.StatusForbidden, RetryAfter: time.Minute}},
		{name: "primary 403", rl: RateLimitError{Kind: RateLimitPrimary, StatusCode: http.StatusForbidden}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wait, retry := DefaultOnRateLimit(context.Background(), &tc.rl)
			assert.Equal(t, tc.wantRetry, retry)
			assert.Zero(t, wait, "the default leaves the wait to Backoff")
		})
	}
}

func TestRateLimitRetries(t *testing.T) {
	hook := RateLimitRetries(
		RateLimitRule{},
		RateLimitRule{MaxRetries: 2, MaxWait: 5 * time.Second},
	)

	for _, tc := range []struct {
		name      string
		rl        RateLimitError
		wantWait  time.Duration
		wantRetry bool
	}{
		{name: "primary returns immediately", rl: RateLimitError{Kind: RateLimitPrimary, StatusCode: http.StatusTooManyRequests, RetryAfter: time.Second}},
		{name: "primary 403 returns immediately", rl: RateLimitError{Kind: RateLimitPrimary, StatusCode: http.StatusForbidden}},
		{name: "secondary within limits", rl: RateLimitError{Kind: RateLimitSecondary, StatusCode: http.StatusTooManyRequests, RetryAfter: 3 * time.Second}, wantWait: 3 * time.Second, wantRetry: true},
		{name: "secondary 403 within limits", rl: RateLimitError{Kind: RateLimitSecondary, StatusCode: http.StatusForbidden, RetryAfter: 3 * time.Second, Retries: 1}, wantWait: 3 * time.Second, wantRetry: true},
		{name: "secondary at MaxWait", rl: RateLimitError{Kind: RateLimitSecondary, StatusCode: http.StatusTooManyRequests, RetryAfter: 5 * time.Second}, wantWait: 5 * time.Second, wantRetry: true},
		{name: "secondary without hint", rl: RateLimitError{Kind: RateLimitSecondary, StatusCode: http.StatusTooManyRequests}, wantRetry: true},
		{name: "secondary beyond MaxWait is not clamped", rl: RateLimitError{Kind: RateLimitSecondary, StatusCode: http.StatusTooManyRequests, RetryAfter: 6 * time.Second}},
		{name: "secondary retries spent", rl: RateLimitError{Kind: RateLimitSecondary, StatusCode: http.StatusTooManyRequests, Retries: 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wait, retry := hook(context.Background(), &tc.rl)
			assert.Equal(t, tc.wantRetry, retry)
			assert.Equal(t, tc.wantWait, wait)
		})
	}

	t.Run("zero MaxWait accepts any wait", func(t *testing.T) {
		hook := RateLimitRetries(RateLimitRule{MaxRetries: 1}, RateLimitRule{})
		wait, retry := hook(context.Background(), &RateLimitError{Kind: RateLimitPrimary, RetryAfter: time.Hour})
		assert.True(t, retry)
		assert.Equal(t, time.Hour, wait)
	})
}

// TestRateLimitDefaultsUnchanged pins the behavior without an OnRateLimit
// hook to what the SDK did before the hook existed.
func TestRateLimitDefaultsUnchanged(t *testing.T) {
	t.Run("429 is retried up to Max and reports the retries", func(t *testing.T) {
		t.Parallel()
		var calls atomic.Int64
		client := newStubCommonClient(
			rateLimitedStub(&calls, http.StatusTooManyRequests, http.Header{headerRetryAfter: {"0"}}),
			RetryConfig{Max: 3, WaitMin: time.Millisecond, WaitMax: time.Millisecond},
		)

		rl := requireRateLimitError(t, doRateLimited(t, context.Background(), client))
		assert.Equal(t, int64(4), calls.Load())
		assert.Equal(t, 3, rl.Retries)
		assert.Equal(t, http.StatusTooManyRequests, rl.StatusCode)
		assert.Contains(t, rl.Error(), "rate limited", "the response body must reach the error")
	})

	t.Run("429 waits for the full Retry-After", func(t *testing.T) {
		t.Parallel()
		var calls atomic.Int64
		client := newStubCommonClient(
			rateLimitedStub(&calls, http.StatusTooManyRequests, http.Header{headerRetryAfter: {"1"}}),
			// WaitMax is far below Retry-After: the hint is not capped.
			RetryConfig{Max: 1, WaitMin: time.Millisecond, WaitMax: time.Millisecond},
		)

		start := time.Now()
		rl := requireRateLimitError(t, doRateLimited(t, context.Background(), client))
		assert.GreaterOrEqual(t, time.Since(start), time.Second)
		assert.Equal(t, int64(2), calls.Load())
		assert.Equal(t, 1, rl.Retries)
	})

	t.Run("429 without Retry-After uses Backoff", func(t *testing.T) {
		t.Parallel()
		var calls atomic.Int64
		var mu sync.Mutex
		var attempts []int
		client := newStubCommonClient(
			rateLimitedStub(&calls, http.StatusTooManyRequests, http.Header{}),
			RetryConfig{
				Max: 2,
				Backoff: func(_, _ time.Duration, attempt int, resp *http.Response) time.Duration {
					mu.Lock()
					defer mu.Unlock()
					attempts = append(attempts, attempt)
					assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
					return time.Millisecond
				},
			},
		)

		rl := requireRateLimitError(t, doRateLimited(t, context.Background(), client))
		assert.Equal(t, int64(3), calls.Load())
		assert.Equal(t, []int{0, 1}, attempts)
		assert.Equal(t, 2, rl.Retries)
	})

	t.Run("primary 429 with only X-RateLimit-Reset uses Backoff, not the reset", func(t *testing.T) {
		t.Parallel()
		var calls atomic.Int64
		client := newStubCommonClient(
			rateLimitedStub(&calls, http.StatusTooManyRequests, http.Header{
				headerRateLimitRemaining: {"0"},
				headerRateLimitReset:     {unixString(time.Now().Add(time.Hour))},
			}),
			RetryConfig{Max: 2, WaitMin: time.Millisecond, WaitMax: time.Millisecond},
		)

		start := time.Now()
		rl := requireRateLimitError(t, doRateLimited(t, context.Background(), client))
		assert.Less(t, time.Since(start), 5*time.Second)
		assert.Equal(t, int64(3), calls.Load())
		assert.Equal(t, RateLimitPrimary, rl.Kind)
		assert.Equal(t, 2, rl.Retries)
	})

	t.Run("rate-limited 403 is not retried", func(t *testing.T) {
		t.Parallel()
		for name, header := range map[string]http.Header{
			"primary":     {headerRateLimitRemaining: {"0"}},
			"retry after": {headerRetryAfter: {"0"}},
		} {
			t.Run(name, func(t *testing.T) {
				var calls atomic.Int64
				client := newStubCommonClient(
					rateLimitedStub(&calls, http.StatusForbidden, header),
					RetryConfig{Max: 3, WaitMin: time.Millisecond, WaitMax: time.Millisecond},
				)

				rl := requireRateLimitError(t, doRateLimited(t, context.Background(), client))
				assert.Equal(t, int64(1), calls.Load())
				assert.Equal(t, 0, rl.Retries)
				assert.Equal(t, http.StatusForbidden, rl.StatusCode)
			})
		}
	})

	t.Run("Retries counts only rate-limited retries", func(t *testing.T) {
		t.Parallel()
		var calls atomic.Int64
		stub := httpClientFunc(func(req *http.Request) (*http.Response, error) {
			n := calls.Add(1)
			if n == 1 {
				return newStubResponse(req, http.StatusServiceUnavailable, ""), nil
			}
			resp := newStubResponse(req, http.StatusTooManyRequests, "")
			resp.Header.Set(headerRetryAfter, "0")
			return resp, nil
		})
		client := newStubCommonClient(stub, RetryConfig{Max: 2, WaitMin: time.Millisecond, WaitMax: time.Millisecond})

		rl := requireRateLimitError(t, doRateLimited(t, context.Background(), client))
		assert.Equal(t, int64(3), calls.Load())
		assert.Equal(t, 1, rl.Retries)
	})
}

// TestAdminConnectionRateLimitedForbidden covers the admin-connection request,
// which also retries 401 and 403 because a fresh registration token is not
// always usable at once. A rate-limited 403 there kept being retried with
// Backoff before OnRateLimit existed, and still is when no hook is set.
func TestAdminConnectionRateLimitedForbidden(t *testing.T) {
	adminRetry := retryOnStatus(http.StatusUnauthorized, http.StatusForbidden)

	t.Run("default retries a rate-limited 403 with Backoff", func(t *testing.T) {
		t.Parallel()
		var calls atomic.Int64
		stub := httpClientFunc(func(req *http.Request) (*http.Response, error) {
			if calls.Add(1) < 3 {
				resp := newStubResponse(req, http.StatusForbidden, "")
				// Retry-After would block for a minute if it were honored
				// here; before the hook, DefaultBackoff ignored it on a 403.
				resp.Header.Set(headerRetryAfter, "60")
				return resp, nil
			}
			return newStubResponse(req, http.StatusOK, ""), nil
		})
		client := newStubCommonClient(stub, RetryConfig{Max: DefaultRetryMax, WaitMax: time.Millisecond})

		start := time.Now()
		require.NoError(t, doRateLimited(t, context.Background(), client, adminRetry))
		assert.Less(t, time.Since(start), 5*time.Second)
		assert.Equal(t, int64(3), calls.Load())
	})

	t.Run("default exhausts Max on a primary 403", func(t *testing.T) {
		t.Parallel()
		var calls atomic.Int64
		client := newStubCommonClient(
			rateLimitedStub(&calls, http.StatusForbidden, http.Header{headerRateLimitRemaining: {"0"}}),
			RetryConfig{Max: 2, WaitMax: time.Millisecond},
		)

		rl := requireRateLimitError(t, doRateLimited(t, context.Background(), client, adminRetry))
		assert.Equal(t, int64(3), calls.Load())
		assert.Equal(t, 2, rl.Retries)
	})

	t.Run("a plain 401 and 403 are still retried", func(t *testing.T) {
		t.Parallel()
		for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
			var calls atomic.Int64
			client := newStubCommonClient(
				rateLimitedStub(&calls, status, http.Header{}),
				RetryConfig{Max: 2, WaitMax: time.Millisecond},
			)

			err := doRateLimited(t, context.Background(), client, adminRetry)
			require.Error(t, err)
			assert.Equal(t, int64(3), calls.Load())
			var rl *RateLimitError
			assert.False(t, errors.As(err, &rl))
		}
	})

	t.Run("a configured OnRateLimit decides", func(t *testing.T) {
		t.Parallel()
		var calls atomic.Int64
		client := newStubCommonClient(
			rateLimitedStub(&calls, http.StatusForbidden, http.Header{headerRateLimitRemaining: {"0"}}),
			RetryConfig{
				Max:         DefaultRetryMax,
				WaitMax:     time.Millisecond,
				OnRateLimit: RateLimitRetries(RateLimitRule{}, RateLimitRule{}),
			},
		)

		rl := requireRateLimitError(t, doRateLimited(t, context.Background(), client, adminRetry))
		assert.Equal(t, int64(1), calls.Load())
		assert.Equal(t, 0, rl.Retries)
	})
}

func TestOnRateLimitHook(t *testing.T) {
	t.Run("declining returns the response at once", func(t *testing.T) {
		t.Parallel()
		var calls, hookCalls atomic.Int64
		client := newStubCommonClient(
			rateLimitedStub(&calls, http.StatusTooManyRequests, http.Header{headerRetryAfter: {"30"}}),
			RetryConfig{
				Max: DefaultRetryMax,
				OnRateLimit: func(ctx context.Context, rl *RateLimitError) (time.Duration, bool) {
					hookCalls.Add(1)
					assert.NoError(t, ctx.Err())
					assert.Equal(t, 30*time.Second, rl.RetryAfter)
					assert.Equal(t, 0, rl.Retries)
					assert.Contains(t, rl.Error(), "POST http://example.com/generatejitconfig")
					return 0, false
				},
			},
		)

		start := time.Now()
		rl := requireRateLimitError(t, doRateLimited(t, context.Background(), client))
		assert.Less(t, time.Since(start), 5*time.Second)
		assert.Equal(t, int64(1), calls.Load())
		assert.Equal(t, int64(1), hookCalls.Load())
		assert.Equal(t, 0, rl.Retries)
		assert.Contains(t, rl.Error(), "rate limited", "the response body must not be drained")
	})

	t.Run("replaces ShouldRetry and Backoff", func(t *testing.T) {
		t.Parallel()
		var calls atomic.Int64
		var seen []int
		client := newStubCommonClient(
			rateLimitedStub(&calls, http.StatusForbidden, http.Header{headerRetryAfter: {"0"}}),
			RetryConfig{
				Max: 2,
				ShouldRetry: func(context.Context, *http.Response, error) (bool, error) {
					t.Error("ShouldRetry must not see a rate-limited response")
					return false, nil
				},
				Backoff: func(time.Duration, time.Duration, int, *http.Response) time.Duration {
					t.Error("Backoff must not run when the hook picks a wait")
					return 0
				},
				OnRateLimit: func(_ context.Context, rl *RateLimitError) (time.Duration, bool) {
					seen = append(seen, rl.Retries)
					return time.Millisecond, true
				},
			},
		)

		rl := requireRateLimitError(t, doRateLimited(t, context.Background(), client))
		assert.Equal(t, int64(3), calls.Load())
		assert.Equal(t, []int{0, 1}, seen, "the hook is not consulted once Max is spent")
		assert.Equal(t, 2, rl.Retries)
	})

	t.Run("a zero wait falls back to Backoff", func(t *testing.T) {
		t.Parallel()
		var calls, backoffCalls atomic.Int64
		client := newStubCommonClient(
			rateLimitedStub(&calls, http.StatusTooManyRequests, http.Header{}),
			RetryConfig{
				Max: 1,
				Backoff: func(time.Duration, time.Duration, int, *http.Response) time.Duration {
					backoffCalls.Add(1)
					return time.Millisecond
				},
				OnRateLimit: func(context.Context, *RateLimitError) (time.Duration, bool) {
					return 0, true
				},
			},
		)

		_ = requireRateLimitError(t, doRateLimited(t, context.Background(), client))
		assert.Equal(t, int64(2), calls.Load())
		assert.Equal(t, int64(1), backoffCalls.Load())
	})

	t.Run("a cancelled context short-circuits", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		var calls atomic.Int64
		stub := httpClientFunc(func(req *http.Request) (*http.Response, error) {
			calls.Add(1)
			cancel()
			return newStubResponse(req, http.StatusTooManyRequests, ""), nil
		})
		client := newStubCommonClient(stub, RetryConfig{
			Max: 3,
			OnRateLimit: func(context.Context, *RateLimitError) (time.Duration, bool) {
				t.Error("the hook must not run once the context is done")
				return 0, true
			},
		})

		err := doRateLimited(t, ctx, client)
		assert.ErrorIs(t, err, context.Canceled)
		assert.Equal(t, int64(1), calls.Load())
	})
}

func TestOnRateLimitHookContextExpires(t *testing.T) {
	for _, cause := range []string{"cancel", "deadline", "budget"} {
		for _, retry := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/retry=%t", cause, retry), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					var maxElapsed time.Duration
					wantErr := context.Canceled
					switch cause {
					case "deadline":
						var cancelDeadline context.CancelFunc
						ctx, cancelDeadline = context.WithTimeout(ctx, time.Second)
						defer cancelDeadline()
						wantErr = context.DeadlineExceeded
					case "budget":
						maxElapsed = time.Second
						wantErr = MaxElapsedExceededError
					}

					var calls, hookCalls int
					var body trackedResponseBody
					var attemptCtx context.Context
					stub := httpClientFunc(func(req *http.Request) (*http.Response, error) {
						calls++
						attemptCtx = req.Context()
						resp := newStubResponse(req, http.StatusTooManyRequests, "")
						body.Reader = strings.NewReader(`{"message":"rate limited"}`)
						resp.Body = &body
						return resp, nil
					})
					client := newStubCommonClient(stub, RetryConfig{
						Max:        3,
						MaxElapsed: maxElapsed,
						OnRateLimit: func(ctx context.Context, _ *RateLimitError) (time.Duration, bool) {
							hookCalls++
							if cause == "cancel" {
								cancel()
							} else {
								<-ctx.Done()
							}
							return time.Hour, retry
						},
					})

					err := doRateLimited(t, ctx, client, withAttemptTimeout(time.Hour))
					require.ErrorIs(t, err, wantErr)
					if cause == "budget" {
						assert.ErrorIs(t, err, context.DeadlineExceeded)
					} else {
						assert.NotErrorIs(t, err, MaxElapsedExceededError)
					}
					assert.Equal(t, 1, calls)
					assert.Equal(t, 1, hookCalls)
					assert.Equal(t, 1, body.closes)
					assert.Error(t, attemptCtx.Err(), "the attempt context must be released")
				})
			})
		}
	}
}

func TestRateLimitRetriesThroughClient(t *testing.T) {
	arc := RetryConfig{
		Max:     DefaultRetryMax,
		WaitMin: time.Millisecond,
		WaitMax: time.Millisecond,
		OnRateLimit: RateLimitRetries(
			RateLimitRule{},
			RateLimitRule{MaxRetries: 2, MaxWait: 5 * time.Second},
		),
	}

	t.Run("primary returns immediately", func(t *testing.T) {
		t.Parallel()
		var calls atomic.Int64
		client := newStubCommonClient(
			rateLimitedStub(&calls, http.StatusTooManyRequests, http.Header{
				headerRateLimitRemaining: {"0"},
				headerRateLimitReset:     {unixString(time.Now().Add(time.Hour))},
			}),
			arc,
		)

		rl := requireRateLimitError(t, doRateLimited(t, context.Background(), client))
		assert.Equal(t, int64(1), calls.Load())
		assert.Equal(t, RateLimitPrimary, rl.Kind)
		assert.Equal(t, 0, rl.Retries)
		assert.Greater(t, rl.RetryAfter, 59*time.Minute, "the caller can requeue after the reset")
	})

	t.Run("secondary retries twice", func(t *testing.T) {
		t.Parallel()
		var calls atomic.Int64
		client := newStubCommonClient(
			rateLimitedStub(&calls, http.StatusTooManyRequests, http.Header{headerRetryAfter: {"0"}}),
			arc,
		)

		rl := requireRateLimitError(t, doRateLimited(t, context.Background(), client))
		assert.Equal(t, int64(3), calls.Load())
		assert.Equal(t, RateLimitSecondary, rl.Kind)
		assert.Equal(t, 2, rl.Retries)
	})

	t.Run("secondary 403 is treated like a 429", func(t *testing.T) {
		t.Parallel()
		var calls atomic.Int64
		client := newStubCommonClient(
			rateLimitedStub(&calls, http.StatusForbidden, http.Header{headerRetryAfter: {"0"}}),
			arc,
		)

		rl := requireRateLimitError(t, doRateLimited(t, context.Background(), client))
		assert.Equal(t, int64(3), calls.Load())
		assert.Equal(t, http.StatusForbidden, rl.StatusCode)
		assert.Equal(t, 2, rl.Retries)
	})

	t.Run("a wait beyond MaxWait gives up without sleeping", func(t *testing.T) {
		t.Parallel()
		var calls atomic.Int64
		client := newStubCommonClient(
			rateLimitedStub(&calls, http.StatusTooManyRequests, http.Header{headerRetryAfter: {"60"}}),
			arc,
		)

		start := time.Now()
		rl := requireRateLimitError(t, doRateLimited(t, context.Background(), client))
		assert.Less(t, time.Since(start), time.Second)
		assert.Equal(t, int64(1), calls.Load())
		assert.Equal(t, time.Minute, rl.RetryAfter)
	})

	t.Run("the rule follows the kind", func(t *testing.T) {
		t.Parallel()
		retry := arc
		retry.OnRateLimit = RateLimitRetries(RateLimitRule{MaxRetries: 1}, RateLimitRule{})

		for kind, tc := range map[RateLimitKind]struct {
			header    http.Header
			wantCalls int64
		}{
			RateLimitPrimary:   {header: http.Header{headerRateLimitRemaining: {"0"}}, wantCalls: 2},
			RateLimitSecondary: {header: http.Header{headerRateLimitRemaining: {"10"}}, wantCalls: 1},
		} {
			var calls atomic.Int64
			client := newStubCommonClient(rateLimitedStub(&calls, http.StatusTooManyRequests, tc.header), retry)

			rl := requireRateLimitError(t, doRateLimited(t, context.Background(), client))
			assert.Equal(t, kind, rl.Kind)
			assert.Equal(t, tc.wantCalls, calls.Load(), kind.String())
			assert.Equal(t, int(tc.wantCalls-1), rl.Retries, kind.String())
		}
	})
}

func TestOnRateLimitResponseMessage(t *testing.T) {
	for _, tc := range []struct {
		name        string
		status      int
		contentType string
		body        string
		remaining   string
	}{
		{
			name:        "body-only JSON 403",
			status:      http.StatusForbidden,
			contentType: "application/json",
			body:        `{"message":"You have exceeded a secondary rate limit."}`,
		},
		{
			name:        "body-only plain text 403",
			status:      http.StatusForbidden,
			contentType: "text/plain",
			body:        "You have exceeded a secondary rate limit.",
		},
		{
			name:        "secondary message overrides spent primary quota on 403",
			status:      http.StatusForbidden,
			contentType: "application/json",
			body:        `{"message":"You have exceeded a secondary rate limit."}`,
			remaining:   "0",
		},
		{
			name:        "secondary message overrides spent primary quota on 429",
			status:      http.StatusTooManyRequests,
			contentType: "application/json",
			body:        `{"message":"You have exceeded a secondary rate limit."}`,
			remaining:   "0",
		},
		{
			name:        "JSON 403 with byte order mark",
			status:      http.StatusForbidden,
			contentType: "application/json",
			body:        "\xef\xbb\xbf" + `{"message":"You have exceeded a secondary rate limit."}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", tc.contentType)
				if tc.remaining != "" {
					w.Header().Set(headerRateLimitRemaining, tc.remaining)
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			t.Cleanup(server.Close)

			var seen []int
			client := newStubCommonClient(server.Client(), RetryConfig{
				Max: 3,
				OnRateLimit: func(_ context.Context, rl *RateLimitError) (time.Duration, bool) {
					assert.Equal(t, RateLimitSecondary, rl.Kind)
					seen = append(seen, rl.Retries)
					return time.Nanosecond, rl.Retries < 1
				},
			})
			req, err := http.NewRequest(http.MethodGet, server.URL, nil)
			require.NoError(t, err)

			resp, err := client.do(req)
			require.NoError(t, err)
			rl := requireRateLimitError(t, newRequestResponseError(req, resp, errors.New("unexpected status")))
			assert.Equal(t, int64(2), calls.Load())
			assert.Equal(t, []int{0, 1}, seen)
			assert.Equal(t, RateLimitSecondary, rl.Kind)
			assert.Equal(t, 1, rl.Retries)
			assert.Contains(t, rl.Error(), "You have exceeded a secondary rate limit.")
		})
	}
}

func TestRetryWithForbiddenResponseBodyError(t *testing.T) {
	for _, policy := range []struct {
		name      string
		opts      []retryOption
		poll      bool
		wantCalls int
	}{
		{name: "ordinary request", wantCalls: 1},
		{name: "message poll", opts: []retryOption{withAttemptTimeout(time.Hour)}, poll: true, wantCalls: 3},
		{name: "admin request", opts: []retryOption{retryOnStatus(http.StatusUnauthorized, http.StatusForbidden)}, wantCalls: 3},
	} {
		for _, failure := range []struct {
			name       string
			readFails  bool
			closeFails bool
		}{
			{name: "read", readFails: true},
			{name: "close", closeFails: true},
			{name: "read and close", readFails: true, closeFails: true},
		} {
			t.Run(policy.name+"/"+failure.name, func(t *testing.T) {
				t.Parallel()
				readErr := errors.New("failed to read response")
				closeErr := errors.New("failed to close response")
				var bodies []*trackedResponseBody
				var attemptCtxs []context.Context
				stub := httpClientFunc(func(req *http.Request) (*http.Response, error) {
					body := &trackedResponseBody{Reader: strings.NewReader(`{"message":"forbidden"}`)}
					if failure.readFails {
						body.Reader = iotest.ErrReader(readErr)
					}
					if failure.closeFails {
						body.closeErr = closeErr
					}
					bodies = append(bodies, body)
					attemptCtxs = append(attemptCtxs, req.Context())
					resp := newStubResponse(req, http.StatusForbidden, `{"message":"forbidden"}`)
					resp.Body = body
					return resp, nil
				})
				client := newStubCommonClient(stub, RetryConfig{
					Max:     2,
					WaitMin: time.Nanosecond,
					WaitMax: time.Nanosecond,
					ShouldRetry: func(ctx context.Context, resp *http.Response, err error) (bool, error) {
						if !policy.poll {
							assert.NoError(t, err, "buffering failures are not transport failures")
						}
						return DefaultShouldRetry(ctx, resp, err)
					},
					OnRateLimit: func(context.Context, *RateLimitError) (time.Duration, bool) {
						t.Error("an ordinary 403 must not invoke the rate-limit hook")
						return 0, false
					},
				})

				err := doRateLimited(t, context.Background(), client, policy.opts...)
				require.Error(t, err)
				if failure.readFails {
					assert.ErrorIs(t, err, readErr)
				}
				if failure.closeFails {
					assert.ErrorIs(t, err, closeErr)
				}
				var rl *RateLimitError
				assert.NotErrorAs(t, err, &rl)
				require.Len(t, bodies, policy.wantCalls)
				for i, body := range bodies {
					assert.Equal(t, 1, body.closes)
					if policy.poll {
						assert.ErrorIs(t, attemptCtxs[i].Err(), context.Canceled)
					}
				}
			})
		}
	}
}

func TestOnRateLimitWithResponseReadError(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		closeFails bool
	}{
		{name: "429 read failure", status: http.StatusTooManyRequests},
		{name: "403 read failure", status: http.StatusForbidden},
		{name: "429 read and close failures", status: http.StatusTooManyRequests, closeFails: true},
		{name: "403 read and close failures", status: http.StatusForbidden, closeFails: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			readErr := errors.New("connection reset while reading response")
			closeErr := errors.New("failed to close response")
			var calls atomic.Int64
			var bodies []*trackedResponseBody
			stub := httpClientFunc(func(req *http.Request) (*http.Response, error) {
				resp, err := rateLimitedStub(&calls, tc.status, http.Header{headerRetryAfter: {"60"}})(req)
				body := &trackedResponseBody{Reader: iotest.ErrReader(readErr)}
				if tc.closeFails {
					body.closeErr = closeErr
				}
				bodies = append(bodies, body)
				resp.Body = body
				return resp, err
			})
			var seen []int
			client := newStubCommonClient(stub, RetryConfig{
				Max: 3,
				ShouldRetry: func(context.Context, *http.Response, error) (bool, error) {
					t.Error("a failed body must not bypass the rate-limit hook")
					return false, nil
				},
				OnRateLimit: func(_ context.Context, rl *RateLimitError) (time.Duration, bool) {
					assert.Equal(t, time.Minute, rl.RetryAfter)
					seen = append(seen, rl.Retries)
					return time.Nanosecond, rl.Retries < 1
				},
			})

			err := doRateLimited(t, context.Background(), client)
			assert.ErrorIs(t, err, readErr)
			if tc.closeFails {
				assert.ErrorIs(t, err, closeErr)
			}
			rl := requireRateLimitError(t, err)
			assert.Equal(t, tc.status, rl.StatusCode)
			assert.Equal(t, int64(2), calls.Load())
			assert.Equal(t, []int{0, 1}, seen)
			assert.Equal(t, 1, rl.Retries)
			for _, body := range bodies {
				assert.Equal(t, 1, body.closes)
			}
		})
	}
}

func TestOnRateLimitWithResponseCloseError(t *testing.T) {
	for _, tc := range []struct {
		name            string
		statusCode      int
		contentType     string
		body            string
		retryAfter      string
		wantErr         error
		wantSyntaxError bool
	}{
		{name: "JSON", statusCode: http.StatusForbidden, contentType: "application/json", body: `{"message":"You have exceeded a secondary rate limit."}`},
		{name: "plain text", statusCode: http.StatusForbidden, contentType: "text/plain", body: "You have exceeded a secondary rate limit."},
		{name: "JSON with byte order mark", statusCode: http.StatusForbidden, contentType: "application/json", body: "\xef\xbb\xbf" + `{"message":"You have exceeded a secondary rate limit."}`},
		{name: "malformed JSON with rate-limit header", statusCode: http.StatusForbidden, contentType: "application/json", body: `{"message":"You have exceeded a secondary rate limit."`, retryAfter: "0", wantSyntaxError: true},
		{name: "mapped exception", statusCode: http.StatusForbidden, contentType: "application/json", body: `{"typeName":"AgentExistsException","message":"You have exceeded a secondary rate limit."}`, wantErr: RunnerExistsError},
		{name: "429 with malformed JSON", statusCode: http.StatusTooManyRequests, contentType: "application/json", body: `{"message":"You have exceeded a secondary rate limit."`, wantSyntaxError: true},
		{name: "429 with HTML", statusCode: http.StatusTooManyRequests, contentType: "text/html", body: "<html>You have exceeded a secondary rate limit.</html>", wantSyntaxError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			closeErr := errors.New("failed to close response")
			var bodies []*trackedResponseBody
			var attemptCtxs []context.Context
			stub := httpClientFunc(func(req *http.Request) (*http.Response, error) {
				body := &trackedResponseBody{Reader: strings.NewReader(tc.body), closeErr: closeErr}
				bodies = append(bodies, body)
				attemptCtxs = append(attemptCtxs, req.Context())
				resp := newStubResponse(req, tc.statusCode, "")
				resp.Body = body
				resp.ContentLength = int64(len(tc.body))
				resp.Header.Set("Content-Type", tc.contentType)
				if tc.retryAfter != "" {
					resp.Header.Set(headerRetryAfter, tc.retryAfter)
				}
				return resp, nil
			})
			var seen []int
			client := newStubCommonClient(stub, RetryConfig{
				Max: 3,
				ShouldRetry: func(context.Context, *http.Response, error) (bool, error) {
					t.Error("a failed close must not bypass the rate-limit hook")
					return false, nil
				},
				OnRateLimit: func(_ context.Context, rl *RateLimitError) (time.Duration, bool) {
					assert.Equal(t, RateLimitSecondary, rl.Kind)
					seen = append(seen, rl.Retries)
					return time.Nanosecond, rl.Retries < 1
				},
			})

			err := doRateLimited(t, context.Background(), client, withAttemptTimeout(time.Hour))
			require.ErrorIs(t, err, closeErr)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
			}
			if tc.wantSyntaxError {
				var syntaxErr *json.SyntaxError
				assert.ErrorAs(t, err, &syntaxErr)
			}
			rl := requireRateLimitError(t, err)
			assert.Equal(t, RateLimitSecondary, rl.Kind)
			assert.Equal(t, tc.statusCode, rl.StatusCode)
			assert.Equal(t, 1, rl.Retries)
			assert.Contains(t, rl.Error(), "You have exceeded a secondary rate limit.")
			assert.Equal(t, []int{0, 1}, seen)
			require.Len(t, bodies, 2)
			for i, body := range bodies {
				assert.Equal(t, 1, body.closes)
				assert.Error(t, attemptCtxs[i].Err(), "the attempt context must be released")
			}
		})
	}
}

func TestOnRateLimitRetrySafety(t *testing.T) {
	for _, tc := range []struct {
		name string
		max  int
		body io.Reader
	}{
		{name: "retries disabled"},
		{name: "body cannot be replayed", max: 3, body: io.NopCloser(strings.NewReader("payload"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int64
			client := newStubCommonClient(
				rateLimitedStub(&calls, http.StatusTooManyRequests, http.Header{}),
				RetryConfig{
					Max: tc.max,
					OnRateLimit: func(context.Context, *RateLimitError) (time.Duration, bool) {
						t.Error("the hook must not override retry safety")
						return time.Nanosecond, true
					},
				},
			)
			req, err := http.NewRequest(http.MethodPost, "http://example.com", tc.body)
			require.NoError(t, err)

			resp, err := client.do(req)
			require.NoError(t, err)
			rl := requireRateLimitError(t, newRequestResponseError(req, resp, errors.New("unexpected status")))
			assert.Equal(t, int64(1), calls.Load())
			assert.Zero(t, rl.Retries)
			assert.Contains(t, rl.Error(), "rate limited")
		})
	}
}

// TestOnRateLimitWaitBeyondLimits covers a hook that asks for a wait the
// request cannot afford: the deadline and MaxElapsed still bound it.
func TestOnRateLimitWaitBeyondLimits(t *testing.T) {
	hour := func(context.Context, *RateLimitError) (time.Duration, bool) {
		return time.Hour, true
	}

	for _, tc := range []struct {
		name  string
		retry RetryConfig
		ctx   func() (context.Context, context.CancelFunc)
	}{
		{
			name:  "context deadline",
			retry: RetryConfig{Max: DefaultRetryMax, OnRateLimit: hour},
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 5*time.Second)
			},
		},
		{
			name:  "MaxElapsed budget",
			retry: RetryConfig{Max: DefaultRetryMax, MaxElapsed: 5 * time.Second, OnRateLimit: hour},
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int64
			client := newStubCommonClient(
				rateLimitedStub(&calls, http.StatusTooManyRequests, http.Header{headerRetryAfter: {"0"}}),
				tc.retry,
			)

			ctx, cancel := tc.ctx()
			defer cancel()

			start := time.Now()
			err := doRateLimited(t, ctx, client)
			assert.Less(t, time.Since(start), time.Second)
			assert.NotErrorIs(t, err, context.DeadlineExceeded)
			assert.NotErrorIs(t, err, MaxElapsedExceededError)
			rl := requireRateLimitError(t, err)
			assert.Equal(t, int64(1), calls.Load())
			assert.Equal(t, 0, rl.Retries)
		})
	}

	// Through a real server, the body of the final response is read under
	// the MaxElapsed budget context. A later rate-limited retry must still
	// report the typed error, with its retries and the server's message.
	t.Run("MaxElapsed after a rate-limited retry, over HTTP", func(t *testing.T) {
		t.Parallel()
		var calls atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			retryAfter := "0"
			if calls.Add(1) > 1 {
				retryAfter = "60"
			}
			w.Header().Set(headerRetryAfter, retryAfter)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"message":"slow down"}`)
		}))
		t.Cleanup(server.Close)

		client := newStubCommonClient(server.Client(), RetryConfig{
			Max:         DefaultRetryMax,
			WaitMin:     time.Millisecond,
			WaitMax:     time.Millisecond,
			MaxElapsed:  5 * time.Second,
			OnRateLimit: RateLimitRetries(RateLimitRule{}, RateLimitRule{MaxRetries: 3}),
		})

		req, err := http.NewRequest(http.MethodGet, server.URL, nil)
		require.NoError(t, err)

		start := time.Now()
		resp, err := client.do(req)
		require.NoError(t, err)
		assert.Less(t, time.Since(start), time.Second)

		err = newRequestResponseError(req, resp, errors.New("unexpected status"))
		assert.NotErrorIs(t, err, MaxElapsedExceededError)
		rl := requireRateLimitError(t, err)
		assert.Equal(t, int64(2), calls.Load())
		assert.Equal(t, 1, rl.Retries)
		assert.Equal(t, time.Minute, rl.RetryAfter)
		assert.Contains(t, err.Error(), "slow down")
	})
}

// TestRateLimitRetriesConcurrent shares one client between requests that hit
// different rate limits. Each must report its own retries; run with -race.
func TestRateLimitRetriesConcurrent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("kind") == "primary" {
			w.Header().Set(headerRateLimitRemaining, "0")
		}
		w.Header().Set(headerRetryAfter, "0")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"message":"rate limited"}`)
	}))
	t.Cleanup(server.Close)

	client := newStubCommonClient(server.Client(), RetryConfig{
		Max:     DefaultRetryMax,
		WaitMin: time.Millisecond,
		WaitMax: time.Millisecond,
		OnRateLimit: RateLimitRetries(
			RateLimitRule{MaxRetries: 1},
			RateLimitRule{MaxRetries: 3},
		),
	})

	const workers = 16
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()

			kind, want := "secondary", 3
			if i%2 == 0 {
				kind, want = "primary", 1
			}

			req, err := http.NewRequest(http.MethodGet, server.URL+"?kind="+kind, nil)
			if !assert.NoError(t, err) {
				return
			}
			resp, err := client.do(req)
			if !assert.NoError(t, err) {
				return
			}

			var rl *RateLimitError
			if assert.ErrorAs(t, newRequestResponseError(req, resp, errors.New("unexpected status")), &rl) {
				assert.Equal(t, want, rl.Retries, kind)
			}
		}()
	}
	wg.Wait()
}
