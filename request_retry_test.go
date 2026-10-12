package scaleset

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fastRetry retries quickly, so tests can count attempts without waiting.
func fastRetry(maxRetries int) RetryConfig {
	return RetryConfig{Max: maxRetries, WaitMin: time.Millisecond, WaitMax: time.Millisecond}
}

func TestWithRequestRetryNilIsNoOp(t *testing.T) {
	ctx := context.Background()
	assert.Equal(t, ctx, WithRequestRetry(ctx, nil))

	outer := WithRequestRetry(ctx, func(c *RetryConfig) { c.Max = 1 })
	assert.Equal(t, outer, WithRequestRetry(outer, nil))
	assert.Len(t, requestRetryAdjusters(WithRequestRetry(outer, nil)), 1)

	var calls atomic.Int64
	client := newStubCommonClient(rateLimitedStub(&calls, http.StatusServiceUnavailable, nil), fastRetry(2))

	require.Error(t, doRateLimited(t, WithRequestRetry(ctx, nil), client))
	assert.Equal(t, int64(3), calls.Load(), "the client's policy applies unchanged")
}

func TestWithRequestRetryNests(t *testing.T) {
	t.Run("outer adjusters run first", func(t *testing.T) {
		var order []string
		record := func(name string) func(*RetryConfig) {
			return func(*RetryConfig) { order = append(order, name) }
		}

		parent := WithRequestRetry(WithRequestRetry(WithRequestRetry(context.Background(),
			record("a")), record("b")), record("c"))
		left := WithRequestRetry(parent, record("left"))
		right := WithRequestRetry(parent, record("right"))

		for _, tc := range []struct {
			name string
			ctx  context.Context
			want []string
		}{
			{"parent", parent, []string{"a", "b", "c"}},
			{"left", left, []string{"a", "b", "c", "left"}},
			{"right", right, []string{"a", "b", "c", "right"}},
		} {
			order = nil
			for _, adjust := range requestRetryAdjusters(tc.ctx) {
				adjust(&RetryConfig{})
			}
			assert.Equal(t, tc.want, order, tc.name)
		}
	})

	t.Run("each adjuster sees the one before it", func(t *testing.T) {
		t.Parallel()
		var calls atomic.Int64
		client := newStubCommonClient(rateLimitedStub(&calls, http.StatusServiceUnavailable, nil), fastRetry(DefaultRetryMax))

		ctx := WithRequestRetry(context.Background(), func(c *RetryConfig) {
			assert.Equal(t, DefaultRetryMax, c.Max, "the outer adjuster starts from the client's policy")
			c.Max = 1
		})
		ctx = WithRequestRetry(ctx, func(c *RetryConfig) {
			assert.Equal(t, 1, c.Max, "the inner adjuster runs after the outer one")
			c.Max += 1
		})

		require.Error(t, doRateLimited(t, ctx, client))
		assert.Equal(t, int64(3), calls.Load())
		assert.Equal(t, DefaultRetryMax, client.retry.Max, "the client's policy is not modified")
	})
}

// TestWithRequestRetryAffectsOnlyItsCall runs calls with and without an
// override side by side on one Client. Run with -race.
func TestWithRequestRetryAffectsOnlyItsCall(t *testing.T) {
	for name, adjust := range map[string]func(*RetryConfig){
		"Max is zero": func(c *RetryConfig) { c.Max = 0 },
		"OnRateLimit declines": func(c *RetryConfig) {
			c.OnRateLimit = func(context.Context, *RateLimitError) (time.Duration, bool) { return 0, false }
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var mu sync.Mutex
			calls := map[string]int{}
			server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				calls[r.URL.Path]++
				mu.Unlock()
				w.Header().Set(headerRetryAfter, "0")
				w.WriteHeader(http.StatusTooManyRequests)
			}))

			const retryMax = 2
			client, err := newClient(testSystemInfo, server.configURLForOrg("my-org"), actionsAuth{token: "token"},
				WithRetry(fastRetry(retryMax)))
			require.NoError(t, err)
			_, err = client.updateTokenIfNeeded(context.Background())
			require.NoError(t, err)

			const workers = 16
			var wg sync.WaitGroup
			for scaleSetID := range workers {
				wg.Add(1)
				go func() {
					defer wg.Done()

					ctx, wantRetries := context.Background(), retryMax
					if scaleSetID%2 == 1 {
						ctx, wantRetries = WithRequestRetry(ctx, adjust), 0
					}

					_, err := client.GenerateJitRunnerConfig(ctx, &RunnerScaleSetJitRunnerSetting{}, scaleSetID)
					var rl *RateLimitError
					if assert.ErrorAs(t, err, &rl) {
						assert.Equal(t, wantRetries, rl.Retries, "scale set %d", scaleSetID)
					}
				}()
			}
			wg.Wait()

			mu.Lock()
			defer mu.Unlock()
			for scaleSetID := range workers {
				want := retryMax + 1
				if scaleSetID%2 == 1 {
					want = 1
				}
				path := fmt.Sprintf("/tenant/123/%s/%d/generatejitconfig", scaleSetEndpoint, scaleSetID)
				assert.Equal(t, want, calls[path], "scale set %d", scaleSetID)
			}
			assert.Equal(t, retryMax, client.retry.Max, "the client's policy is not modified")
		})
	}
}

// TestWithRequestRetryKeepsAdminConnectionRetry checks that the SDK's own
// per-request options run after the caller's adjusters, so the admin
// connection keeps retrying 401 and 403 within the adjusted Max.
func TestWithRequestRetryKeepsAdminConnectionRetry(t *testing.T) {
	adminRetry := retryOnStatus(http.StatusUnauthorized, http.StatusForbidden)
	neverRetry := func(context.Context, *http.Response, error) (bool, error) { return false, nil }

	for _, tc := range []struct {
		name      string
		adjust    func(*RetryConfig)
		wantCalls int64
	}{
		{
			name:      "ShouldRetry declining everything",
			adjust:    func(c *RetryConfig) { c.ShouldRetry = neverRetry },
			wantCalls: 3,
		},
		{
			name: "a lower Max",
			adjust: func(c *RetryConfig) {
				c.Max = 1
				c.ShouldRetry = neverRetry
			},
			wantCalls: 2,
		},
		{
			name:      "Max of zero disables every retry",
			adjust:    func(c *RetryConfig) { c.Max = 0 },
			wantCalls: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
				var calls atomic.Int64
				client := newStubCommonClient(rateLimitedStub(&calls, status, nil), fastRetry(2))

				ctx := WithRequestRetry(context.Background(), tc.adjust)
				require.Error(t, doRateLimited(t, ctx, client, adminRetry))
				assert.Equal(t, tc.wantCalls, calls.Load(), "status %d", status)
			}
		})
	}
}

// TestWithRequestRetryMaxElapsed checks that a budget set per call is in
// place before the budget context is derived: it cuts off a slow attempt on a
// client that has no budget of its own.
func TestWithRequestRetryMaxElapsed(t *testing.T) {
	t.Parallel()

	const delay = 500 * time.Millisecond
	server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(delay):
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"encodedJITConfig":"config"}`))
	}))

	client, err := newClient(testSystemInfo, server.configURLForOrg("my-org"), actionsAuth{token: "token"},
		WithRetry(fastRetry(2)))
	require.NoError(t, err)
	require.Zero(t, client.retry.MaxElapsed)
	_, err = client.updateTokenIfNeeded(context.Background())
	require.NoError(t, err)

	ctx := WithRequestRetry(context.Background(), func(c *RetryConfig) {
		c.MaxElapsed = 50 * time.Millisecond
	})
	start := time.Now()
	_, err = client.GenerateJitRunnerConfig(ctx, &RunnerScaleSetJitRunnerSetting{}, 1)
	assert.Less(t, time.Since(start), delay)
	require.Error(t, err)
	assert.ErrorIs(t, err, MaxElapsedExceededError)
	assert.Contains(t, err.Error(), "MaxElapsed exceeded after 50ms")

	jit, err := client.GenerateJitRunnerConfig(context.Background(), &RunnerScaleSetJitRunnerSetting{}, 1)
	require.NoError(t, err, "a call without the override has no budget")
	assert.Equal(t, "config", jit.EncodedJITConfig)
}

func TestWithRequestRetryMessageSession(t *testing.T) {
	newSession := func(t *testing.T, calls *atomic.Int64, sessionRetry RetryConfig) *MessageSessionClient {
		var handleSessionRequest http.HandlerFunc
		server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "sessions") {
				handleSessionRequest(w, r)
				return
			}
			calls.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		handleSessionRequest = newTestSessionRequestHandler(t, server.testRunnerScaleSetSession())

		client, err := newClient(testSystemInfo, server.configURLForOrg("my-org"), actionsAuth{token: "token"},
			WithRetry(fastRetry(1)))
		require.NoError(t, err)

		sessionClient, err := client.MessageSessionClient(context.Background(), 1, "my-org", WithRetry(sessionRetry))
		require.NoError(t, err)
		return sessionClient
	}

	calls := map[string]func(context.Context, *MessageSessionClient) error{
		"GetMessage": func(ctx context.Context, c *MessageSessionClient) error {
			_, err := c.GetMessage(ctx, 0, 10)
			return err
		},
		"AcquireJobs": func(ctx context.Context, c *MessageSessionClient) error {
			_, err := c.AcquireJobs(ctx, []int64{1})
			return err
		},
		"DeleteMessage": func(ctx context.Context, c *MessageSessionClient) error {
			return c.DeleteMessage(ctx, 1)
		},
	}

	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int64
			sessionClient := newSession(t, &calls, fastRetry(3))

			ctx := WithRequestRetry(context.Background(), func(c *RetryConfig) {
				assert.Equal(t, 3, c.Max, "adjust starts from the session's own policy")
				c.Max = 0
			})
			require.Error(t, call(ctx, sessionClient))
			assert.Equal(t, int64(1), calls.Load(), "the override applies")

			calls.Store(0)
			require.Error(t, call(context.Background(), sessionClient))
			assert.Equal(t, int64(4), calls.Load(), "the session's policy is unchanged")
		})
	}

	t.Run("GetMessage gives up a wait beyond MaxElapsed", func(t *testing.T) {
		t.Parallel()
		var calls atomic.Int64
		sessionClient := newSession(t, &calls, fastRetry(3))

		// The poll window bounds each attempt, not the waits between them, so
		// the override's budget is what stops a wait beyond it.
		ctx := WithRequestRetry(context.Background(), func(c *RetryConfig) {
			c.Backoff = func(time.Duration, time.Duration, int, *http.Response) time.Duration {
				return 2 * MessagePollTimeout
			}
			c.MaxElapsed = MessagePollTimeout
		})

		start := time.Now()
		_, err := sessionClient.GetMessage(ctx, 0, 10)
		require.Error(t, err)
		assert.False(t, errors.Is(err, context.DeadlineExceeded))
		assert.Less(t, time.Since(start), 5*time.Second)
		assert.Equal(t, int64(1), calls.Load())
	})
}
