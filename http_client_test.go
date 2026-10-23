package scaleset

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"testing/synctest"
	"time"

	"github.com/actions/scaleset/internal/testserver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRetryOverrideDoesNotPersist covers the retry policy leaking from one
// request to the next.
//
// Token refresh retries 401 and 403, which no other request does. When that
// policy was installed on a client shared by every request, it stayed there:
// afterwards, ordinary requests silently retried authentication failures too.
func TestRetryOverrideDoesNotPersist(t *testing.T) {
	var calls atomic.Int64
	stub := httpClientFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		return newStubResponse(req, http.StatusUnauthorized, ""), nil
	})

	opts := defaultHTTPClientOption()
	WithHTTPClient(stub)(&opts)
	WithRetry(RetryConfig{Max: 2, WaitMax: time.Millisecond})(&opts)
	client := newCommonClient(testSystemInfo, opts)

	req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
	require.NoError(t, err)

	// Opting into retrying 401 gives one attempt plus two retries.
	resp, err := client.do(req, retryOnStatus(http.StatusUnauthorized))
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, int64(3), calls.Load())

	// The next request does not inherit it. A 401 is not retryable by default,
	// so this is a single attempt.
	calls.Store(0)
	_, err = client.do(req)
	require.NoError(t, err)
	assert.Equal(t, int64(1), calls.Load())
}

// TestTokenRefreshIsolatedFromInflightRequests exercises token refreshes
// landing in the middle of concurrent requests, which is the situation that
// used to be unsafe: the refresh installed its own retry policy by writing to
// the HTTP client every other request was reading from.
//
// Nothing here synchronizes the refreshes with the requests, so any shared
// mutable state reintroduced on this path shows up under -race.
func TestTokenRefreshIsolatedFromInflightRequests(t *testing.T) {
	const (
		workers     = 8
		expirations = 50
	)

	var refreshes atomic.Int64

	server := testserver.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":1,"name":"runner","runnerScaleSetId":1}`))
	}), testserver.WithActionsRegistrationTokenHandler(func(w http.ResponseWriter, r *http.Request) {
		refreshes.Add(1)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"url":"http://` + r.Host + `/tenant/123/","token":"` + testserver.DefaultActionsToken(t) + `"}`))
	}))

	client, err := newClient(
		testSystemInfo,
		server.ConfigURLForOrg("my-org"),
		actionsAuth{token: "token"},
		WithRetry(RetryConfig{Max: DefaultRetryMax, WaitMax: time.Millisecond}),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())

	var requests sync.WaitGroup
	for range workers {
		requests.Add(1)
		go func() {
			defer requests.Done()
			for ctx.Err() == nil {
				if _, err := client.GetRunner(ctx, 1); err != nil && ctx.Err() == nil {
					assert.NoError(t, err)
					return
				}
			}
		}()
	}

	// Expire the admin token repeatedly so that refreshes keep landing in the
	// middle of the requests above.
	for range expirations {
		client.adminTokenMu.Lock()
		client.actionsServiceAdminToken.expiresAt = time.Now().Add(-time.Second)
		client.adminTokenMu.Unlock()
		time.Sleep(time.Millisecond)
	}

	cancel()
	requests.Wait()

	// Guard against the test passing because no refresh ever happened.
	assert.Positive(t, refreshes.Load())
}

// TestSharedClientDuringTokenRefreshWithInflightRequests is the regression
// test for the data race this package was redesigned to remove.
//
// A single HTTP client is shared by every request, which is exactly the
// arrangement that used to be unsafe: a token refresh installed its own retry
// policy by writing CheckRetry and ErrorHandler onto that shared client while
// in-flight requests were reading them. Here the refresh is forced to land
// while sixteen requests are parked inside the JIT handler, so the write and
// the reads overlap with nothing synchronizing them.
//
// The scenario is taken from the reproduction in #128. Run against the code
// before this change, it reports a race in
// getActionsServiceAdminConnectionRequest; #128 needed a per-client factory to
// avoid it, whereas a shared client is safe here because the retry policy is
// copied per request instead of stored on the client.
func TestSharedClientDuringTokenRefreshWithInflightRequests(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const inflight = 16

		entered := make(chan struct{}, inflight)
		release := make(chan struct{})
		var jitCount, adminCount atomic.Int64

		shared := httpClientFunc(func(req *http.Request) (*http.Response, error) {
			code, body := http.StatusOK, ""
			switch {
			case strings.HasSuffix(req.URL.Path, "/registration-token"):
				code = http.StatusCreated
				body = `{"token":"registration-token"}`

			case req.URL.Path == "/actions/runner-registration":
				// Expire the first admin token quickly so the request made
				// after the workers are parked has to refresh it.
				expires := time.Now().Add(time.Hour)
				if adminCount.Add(1) == 1 {
					expires = time.Now().Add(61 * time.Second)
				}
				body = fmt.Sprintf(`{"url":"https://actions.example/","token":%q}`, unsignedJWT(t, expires))

			case strings.HasSuffix(req.URL.Path, "/generatejitconfig"):
				// Park every concurrent worker inside the handler, so they are
				// still in flight when the refresh happens.
				id := jitCount.Add(1)
				if id > 1 && id <= inflight+1 {
					entered <- struct{}{}
					<-release
				}
				body = fmt.Sprintf(`{"runner":{"id":%d},"encodedJITConfig":"config"}`, id)

			default:
				return nil, fmt.Errorf("unexpected request: %s %s", req.Method, req.URL)
			}

			return newStubResponse(req, code, body), nil
		})

		client, err := NewClientWithPersonalAccessToken(
			NewClientWithPersonalAccessTokenConfig{
				GitHubConfigURL:     "https://github.com/example-org",
				PersonalAccessToken: "example-token",
			},
			WithHTTPClient(shared),
		)
		require.NoError(t, err)

		generate := func(name string) error {
			_, err := client.GenerateJitRunnerConfig(
				t.Context(),
				&RunnerScaleSetJitRunnerSetting{Name: name, WorkFolder: "_work"},
				1,
			)
			return err
		}

		require.NoError(t, generate("warm"))

		var workers sync.WaitGroup
		errs := make([]error, inflight)
		for i := range inflight {
			workers.Go(func() { errs[i] = generate(fmt.Sprintf("inflight-%d", i)) })
		}
		for range inflight {
			<-entered
		}

		// Let the admin token expire while the workers are parked.
		time.Sleep(2 * time.Second)
		close(release)

		refreshErr := generate("refresh")
		workers.Wait()

		require.NoError(t, refreshErr)
		for _, err := range errs {
			assert.NoError(t, err)
		}

		// Guard against the test passing because no refresh ever happened.
		assert.Equal(t, int64(2), adminCount.Load())
	})
}

// TestSuppliedHTTPClientIsNotModified covers message session options reaching
// back into the HTTP client of the client that created them.
//
// A session copies its parent's options and applies overrides. Those overrides
// used to be applied by writing to the shared transport, so configuring a
// session reconfigured its parent.
func TestSuppliedHTTPClientIsNotModified(t *testing.T) {
	httpClient := NewHTTPClient(HTTPClientConfig{})
	transport, ok := transportOf(httpClient)
	require.True(t, ok)

	// Clone rather than dereference: a live transport's unexported fields are
	// its connection pool, which its own goroutines write to.
	before := transport.Clone()
	beforeTimeout := httpClient.Timeout

	var refreshes atomic.Int64

	server := testserver.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, _ = w.Write([]byte(`{"sessionId":"00000000-0000-0000-0000-000000000001","id":1,"name":"runner","runnerScaleSetId":1}`))
	}), testserver.WithActionsRegistrationTokenHandler(func(w http.ResponseWriter, r *http.Request) {
		refreshes.Add(1)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"url":"http://` + r.Host + `/tenant/123/","token":"` + testserver.DefaultActionsToken(t) + `"}`))
	}))

	client, err := newClient(
		testSystemInfo,
		server.ConfigURLForOrg("my-org"),
		actionsAuth{token: "token"},
		WithHTTPClient(httpClient),
	)
	require.NoError(t, err)

	_, err = client.GetRunner(context.Background(), 1)
	require.NoError(t, err)

	// Force a token refresh, the path that used to install its own retry
	// policy by writing to the shared client.
	client.adminTokenMu.Lock()
	client.actionsServiceAdminToken.expiresAt = time.Now().Add(-time.Second)
	client.adminTokenMu.Unlock()

	_, err = client.GetRunner(context.Background(), 1)
	require.NoError(t, err)

	session, err := client.MessageSessionClient(
		context.Background(), 1, "owner",
		WithRetry(RetryConfig{Max: 0}),
	)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, session.Close(context.Background())) })

	// The session shares the client, and therefore its connection pool.
	assert.Same(t, httpClient, client.httpClient)
	assert.Same(t, httpClient, session.commonClient.httpClient)

	// Its retry policy is its own.
	assert.Equal(t, 0, session.commonClient.retry.Max)
	assert.Equal(t, DefaultRetryMax, client.retry.Max)

	// Guard against the workload above never exercising a refresh.
	assert.Positive(t, refreshes.Load())

	// Nothing was written to the client that was handed in.
	assert.Same(t, transport, httpClient.Transport)
	assert.Equal(t, beforeTimeout, httpClient.Timeout, "Client.Timeout")
	assertConfigUnchanged(t, "Transport", reflect.ValueOf(before).Elem(), reflect.ValueOf(transport.Clone()).Elem())
}

// assertConfigUnchanged compares the configuration of two structs of the same
// type, field by field.
//
// It walks exported fields only. On http.Transport and tls.Config those are
// exactly the configuration knobs, while the unexported ones hold live state -
// connection pools, mutexes, session ticket keys - that changes as a matter of
// course and must not be compared.
//
// Comparing by walking rather than by listing field names is deliberate: a
// write the SDK should not be making is caught even if the field is added to
// the standard library, or to this package, after this test was written.
func assertConfigUnchanged(t *testing.T, label string, want, got reflect.Value) {
	t.Helper()

	typ := want.Type()
	for i := range typ.NumField() {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}

		name := label + "." + field.Name
		wantField, gotField := want.Field(i), got.Field(i)

		switch {
		case field.Type == reflect.TypeFor[*tls.Config]():
			if wantField.IsNil() || gotField.IsNil() {
				assert.Equal(t, wantField.IsNil(), gotField.IsNil(), name)
				continue
			}
			assertConfigUnchanged(t, name, wantField.Elem(), gotField.Elem())

		case field.Type.Kind() == reflect.Func:
			// Functions are comparable only against nil, so compare the code
			// each one points at.
			assert.Equal(t, wantField.Pointer(), gotField.Pointer(), name)

		default:
			assert.True(t, reflect.DeepEqual(wantField.Interface(), gotField.Interface()), name)
		}
	}
}

func TestRetryRewindsRequestBody(t *testing.T) {
	var bodies [][]byte
	var mu sync.Mutex
	stub := httpClientFunc(func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		require.NoError(t, err)

		mu.Lock()
		bodies = append(bodies, body)
		attempt := len(bodies)
		mu.Unlock()

		if attempt < 3 {
			return newStubResponse(req, http.StatusServiceUnavailable, ""), nil
		}
		return newStubResponse(req, http.StatusOK, ""), nil
	})

	opts := defaultHTTPClientOption()
	WithHTTPClient(stub)(&opts)
	WithRetry(RetryConfig{Max: 3, WaitMax: time.Millisecond})(&opts)
	client := newCommonClient(testSystemInfo, opts)

	payload := []byte(`{"hello":"world"}`)
	req, err := http.NewRequest(http.MethodPost, "http://example.com", bytes.NewReader(payload))
	require.NoError(t, err)

	resp, err := client.do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	require.Len(t, bodies, 3)
	for _, body := range bodies {
		assert.Equal(t, payload, body)
	}
}

func TestRetryStopsWhenContextIsDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	var calls atomic.Int64
	stub := httpClientFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		cancel()
		return newStubResponse(req, http.StatusServiceUnavailable, ""), nil
	})

	opts := defaultHTTPClientOption()
	WithHTTPClient(stub)(&opts)
	WithRetry(RetryConfig{Max: 5, WaitMax: time.Hour})(&opts)
	client := newCommonClient(testSystemInfo, opts)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com", nil)
	require.NoError(t, err)

	_, err = client.do(req)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, int64(1), calls.Load())
}

func TestDefaultShouldRetry(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		err    error
		want   bool
	}{
		{name: "success", status: http.StatusOK},
		{name: "not found", status: http.StatusNotFound},
		{name: "unauthorized", status: http.StatusUnauthorized},
		{name: "not implemented", status: http.StatusNotImplemented},
		{name: "too many requests", status: http.StatusTooManyRequests, want: true},
		{name: "internal server error", status: http.StatusInternalServerError, want: true},
		{name: "bad gateway", status: http.StatusBadGateway, want: true},
		{name: "transport error", err: errors.New("connection reset"), want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var resp *http.Response
			if tc.err == nil {
				resp = &http.Response{StatusCode: tc.status}
			}

			retry, err := DefaultShouldRetry(context.Background(), resp, tc.err)
			require.NoError(t, err)
			assert.Equal(t, tc.want, retry)
		})
	}

	t.Run("stops on a done context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		retry, err := DefaultShouldRetry(ctx, &http.Response{StatusCode: http.StatusInternalServerError}, nil)
		assert.False(t, retry)
		assert.ErrorIs(t, err, context.Canceled)
	})
}

func TestDefaultBackoff(t *testing.T) {
	t.Run("grows exponentially up to the cap, with jitter", func(t *testing.T) {
		waitMin, waitMax := time.Second, 8*time.Second
		for attempt, base := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 8 * time.Second} {
			for range 50 {
				got := DefaultBackoff(waitMin, waitMax, attempt, nil)
				assert.GreaterOrEqual(t, got, base, "attempt %d", attempt)
				assert.LessOrEqual(t, got, min(base+base/2, waitMax), "attempt %d", attempt)
			}
		}
	})

	t.Run("spreads concurrent clients", func(t *testing.T) {
		seen := make(map[time.Duration]struct{})
		for range 50 {
			seen[DefaultBackoff(time.Second, time.Minute, 2, nil)] = struct{}{}
		}
		assert.Greater(t, len(seen), 1, "every client would retry at the same instant")
	})

	t.Run("caps a huge attempt count", func(t *testing.T) {
		assert.Equal(t, time.Second, DefaultBackoff(time.Second, time.Second, 1000, nil))
	})

	t.Run("honors Retry-After seconds", func(t *testing.T) {
		resp := &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{"Retry-After": []string{"7"}}}
		assert.Equal(t, 7*time.Second, DefaultBackoff(time.Second, time.Hour, 0, resp))
	})

	t.Run("does not cap Retry-After at waitMax", func(t *testing.T) {
		resp := &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{"Retry-After": []string{"120"}}}
		assert.Equal(t, 2*time.Minute, DefaultBackoff(time.Second, 30*time.Second, 0, resp))
	})

	t.Run("honors Retry-After as a date", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Header:     http.Header{"Retry-After": []string{time.Now().Add(30 * time.Second).UTC().Format(http.TimeFormat)}},
		}
		assert.InDelta(t, 30*time.Second, DefaultBackoff(time.Second, time.Hour, 0, resp), float64(2*time.Second))
	})

	t.Run("ignores Retry-After on other statuses", func(t *testing.T) {
		resp := &http.Response{StatusCode: http.StatusInternalServerError, Header: http.Header{"Retry-After": []string{"7"}}}
		got := DefaultBackoff(time.Second, time.Hour, 0, resp)
		assert.GreaterOrEqual(t, got, time.Second)
		assert.LessOrEqual(t, got, 1500*time.Millisecond)
	})

	t.Run("ignores an unusable Retry-After", func(t *testing.T) {
		for _, value := range []string{"", "soon", "-5"} {
			resp := &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{"Retry-After": []string{value}}}
			got := DefaultBackoff(time.Second, time.Hour, 0, resp)
			assert.GreaterOrEqual(t, got, time.Second, "Retry-After: %q", value)
			assert.LessOrEqual(t, got, 1500*time.Millisecond, "Retry-After: %q", value)
		}
	})
}

// unsignedJWT builds a JWT with the given expiry. Only the claims are read
// when determining when the admin token needs refreshing.
func unsignedJWT(t *testing.T, expiresAt time.Time) string {
	t.Helper()

	encode := func(v string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(v))
	}

	header := encode(`{"alg":"none","typ":"JWT"}`)
	claims := encode(fmt.Sprintf(`{"exp":%d}`, expiresAt.Unix()))

	return header + "." + claims + "."
}

// ctxBoundReader fails once ctx is done, the way a response body streamed
// under a cancelled request context does.
type ctxBoundReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxBoundReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

func TestAttemptTimeout(t *testing.T) {
	newClient := func(client HTTPClient) *commonClient {
		return newCommonClient(testSystemInfo, httpClientOption{
			logger:     slog.New(slog.DiscardHandler),
			httpClient: client,
			retry:      RetryConfig{Max: 2, WaitMin: time.Millisecond, WaitMax: time.Millisecond},
		})
	}

	t.Run("the request context still bounds the request", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var attempts atomic.Int32
			client := newClient(httpClientFunc(func(req *http.Request) (*http.Response, error) {
				attempts.Add(1)
				<-req.Context().Done()
				return nil, req.Context().Err()
			}))

			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://actions.example/", nil)
			require.NoError(t, err)

			start := time.Now()
			_, err = client.doWith(client.httpClient, req, withAttemptTimeout(100*time.Millisecond))
			require.ErrorIs(t, err, context.DeadlineExceeded)
			assert.Equal(t, 150*time.Millisecond, time.Since(start))
			assert.EqualValues(t, 2, attempts.Load())
		})
	})

	t.Run("the body stays readable until it is closed", func(t *testing.T) {
		var attemptCtx context.Context
		client := newClient(httpClientFunc(func(req *http.Request) (*http.Response, error) {
			attemptCtx = req.Context()
			resp := newStubResponse(req, http.StatusOK, "")
			resp.Body = io.NopCloser(ctxBoundReader{ctx: attemptCtx, r: strings.NewReader("body")})
			return resp, nil
		}))

		req, err := http.NewRequest(http.MethodGet, "https://actions.example/", nil)
		require.NoError(t, err)

		resp, err := client.doWith(client.httpClient, req, withAttemptTimeout(time.Minute))
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "body", string(body))
		assert.ErrorIs(t, attemptCtx.Err(), context.Canceled, "the attempt context must be released once the body is read")
	})

	t.Run("a failed attempt releases its context", func(t *testing.T) {
		var attemptCtxs []context.Context
		client := newClient(httpClientFunc(func(req *http.Request) (*http.Response, error) {
			attemptCtxs = append(attemptCtxs, req.Context())
			return nil, errors.New("connection reset")
		}))

		req, err := http.NewRequest(http.MethodGet, "https://actions.example/", nil)
		require.NoError(t, err)

		_, err = client.doWith(client.httpClient, req, withAttemptTimeout(time.Minute))
		require.Error(t, err)
		require.Len(t, attemptCtxs, 3)
		for i, ctx := range attemptCtxs {
			assert.ErrorIs(t, ctx.Err(), context.Canceled, "attempt %d", i+1)
		}
	})

	t.Run("a failed body read keeps the response and releases the attempt", func(t *testing.T) {
		var attemptCtx context.Context
		client := newClient(httpClientFunc(func(req *http.Request) (*http.Response, error) {
			attemptCtx = req.Context()
			resp := newStubResponse(req, http.StatusNotFound, "")
			resp.Body = io.NopCloser(iotest.ErrReader(errors.New("connection reset")))
			return resp, nil
		}))
		client.retry.Max = 0

		req, err := http.NewRequest(http.MethodGet, "https://actions.example/", nil)
		require.NoError(t, err)

		_, err = client.doWith(client.httpClient, req, withAttemptTimeout(time.Minute))
		require.Error(t, err)
		assert.ErrorIs(t, err, NotFoundError, "the final error must keep the response status")
		assert.ErrorIs(t, attemptCtx.Err(), context.Canceled)
	})

	t.Run("no timeout does not retry a failed body read", func(t *testing.T) {
		var attempts atomic.Int32
		client := newClient(httpClientFunc(func(req *http.Request) (*http.Response, error) {
			attempts.Add(1)
			resp := newStubResponse(req, http.StatusOK, "")
			resp.Body = io.NopCloser(iotest.ErrReader(errors.New("connection reset")))
			return resp, nil
		}))

		req, err := http.NewRequest(http.MethodPost, "https://actions.example/", strings.NewReader("{}"))
		require.NoError(t, err)

		_, err = client.do(req)
		require.Error(t, err)
		assert.EqualValues(t, 1, attempts.Load(), "a request that reached the server must not be repeated")
	})

	t.Run("no timeout leaves the request context alone", func(t *testing.T) {
		var sent context.Context
		client := newClient(httpClientFunc(func(req *http.Request) (*http.Response, error) {
			sent = req.Context()
			return newStubResponse(req, http.StatusOK, ""), nil
		}))

		req, err := http.NewRequest(http.MethodGet, "https://actions.example/", nil)
		require.NoError(t, err)

		_, err = client.do(req)
		require.NoError(t, err)
		_, hasDeadline := sent.Deadline()
		assert.False(t, hasDeadline)
		assert.NoError(t, sent.Err())
	})
}

// TestRetryWaitBeyondDeadline covers a wait that cannot finish in time. ARC
// generates JIT configs under a reconcile deadline; sleeping through a long
// Retry-After used to end in a bare context error, losing the 429 that said
// why the request failed.
func TestRetryWaitBeyondDeadline(t *testing.T) {
	rateLimited := func(attempts *atomic.Int64) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			attempts.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set(headerRetryAfter, "60")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"message":"too many requests"}`))
		})
	}

	assertRateLimited := func(t *testing.T, err error, elapsed time.Duration) {
		t.Helper()
		require.Error(t, err)
		assert.Less(t, elapsed, 5*time.Second)
		assert.NotErrorIs(t, err, context.DeadlineExceeded)

		var rl *RateLimitError
		require.ErrorAs(t, err, &rl)
		assert.Equal(t, http.StatusTooManyRequests, rl.StatusCode)
		assert.Equal(t, 60*time.Second, rl.RetryAfter)
	}

	t.Run("context deadline", func(t *testing.T) {
		var attempts atomic.Int64
		server := newActionsServer(t, rateLimited(&attempts))
		client, err := newClient(testSystemInfo, server.configURLForOrg("my-org"), actionsAuth{token: "token"})
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		start := time.Now()
		_, err = client.GenerateJitRunnerConfig(ctx, &RunnerScaleSetJitRunnerSetting{}, 1)
		assertRateLimited(t, err, time.Since(start))
		assert.Equal(t, int64(1), attempts.Load())
	})

	t.Run("MaxElapsed budget", func(t *testing.T) {
		var attempts atomic.Int64
		server := newActionsServer(t, rateLimited(&attempts))
		retry := DefaultRetryConfig()
		retry.MaxElapsed = 200 * time.Millisecond
		client, err := newClient(testSystemInfo, server.configURLForOrg("my-org"), actionsAuth{token: "token"}, WithRetry(retry))
		require.NoError(t, err)

		start := time.Now()
		_, err = client.GenerateJitRunnerConfig(context.Background(), &RunnerScaleSetJitRunnerSetting{}, 1)
		assertRateLimited(t, err, time.Since(start))
		assert.Equal(t, int64(1), attempts.Load())
	})
}

func TestRetryWaitWithinDeadline(t *testing.T) {
	for _, tc := range []struct {
		name  string
		retry RetryConfig
		ctx   func() (context.Context, context.CancelFunc)
	}{
		{
			name:  "context deadline",
			retry: RetryConfig{Max: 2, WaitMin: time.Millisecond, WaitMax: 10 * time.Millisecond},
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 5*time.Second)
			},
		},
		{
			name:  "MaxElapsed budget",
			retry: RetryConfig{Max: 2, WaitMin: time.Millisecond, WaitMax: 10 * time.Millisecond, MaxElapsed: 5 * time.Second},
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int64
			stub := httpClientFunc(func(req *http.Request) (*http.Response, error) {
				if calls.Add(1) == 1 {
					resp := newStubResponse(req, http.StatusTooManyRequests, "")
					resp.Header.Set(headerRetryAfter, "0")
					return resp, nil
				}
				return newStubResponse(req, http.StatusOK, ""), nil
			})

			opts := defaultHTTPClientOption()
			WithHTTPClient(stub)(&opts)
			WithRetry(tc.retry)(&opts)
			client := newCommonClient(testSystemInfo, opts)

			ctx, cancel := tc.ctx()
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com", nil)
			require.NoError(t, err)

			resp, err := client.do(req)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, int64(2), calls.Load())
		})
	}
}

func TestRetryBackoffBeyondDeadlineReturnsServerError(t *testing.T) {
	var calls atomic.Int64
	stub := httpClientFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		return newStubResponse(req, http.StatusInternalServerError, "boom"), nil
	})

	opts := defaultHTTPClientOption()
	WithHTTPClient(stub)(&opts)
	WithRetry(RetryConfig{Max: 4, WaitMin: time.Hour, WaitMax: time.Hour})(&opts)
	client := newCommonClient(testSystemInfo, opts)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com", nil)
	require.NoError(t, err)

	resp, err := client.do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "boom", string(body), "the returned response must not be drained")
	assert.Equal(t, int64(1), calls.Load())
}

func TestRetryCancelDuringWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var calls atomic.Int64
	stub := httpClientFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		time.AfterFunc(20*time.Millisecond, cancel)
		return newStubResponse(req, http.StatusServiceUnavailable, ""), nil
	})

	opts := defaultHTTPClientOption()
	WithHTTPClient(stub)(&opts)
	WithRetry(RetryConfig{Max: 4, WaitMin: time.Hour, WaitMax: time.Hour, MaxElapsed: 2 * time.Hour})(&opts)
	client := newCommonClient(testSystemInfo, opts)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com", nil)
	require.NoError(t, err)

	_, err = client.do(req)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, int64(1), calls.Load())
}

func TestRetryCancelDuringBackoff(t *testing.T) {
	for _, poll := range []bool{false, true} {
		t.Run(fmt.Sprintf("poll=%t", poll), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			var calls int
			var attemptCtx context.Context
			body := trackedResponseBody{Reader: strings.NewReader(`{"message":"rate limited"}`)}
			stub := httpClientFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				attemptCtx = req.Context()
				resp := newStubResponse(req, http.StatusTooManyRequests, "")
				resp.Body = &body
				return resp, nil
			})
			opts := defaultHTTPClientOption()
			WithHTTPClient(stub)(&opts)
			WithRetry(RetryConfig{
				Max:        2,
				MaxElapsed: time.Minute,
				Backoff: func(time.Duration, time.Duration, int, *http.Response) time.Duration {
					cancel()
					return time.Hour
				},
			})(&opts)
			client := newCommonClient(testSystemInfo, opts)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://actions.example/", nil)
			require.NoError(t, err)

			var retryOpts []retryOption
			if poll {
				retryOpts = append(retryOpts, withAttemptTimeout(MessagePollTimeout))
			}
			resp, err := client.do(req, retryOpts...)
			require.ErrorIs(t, err, context.Canceled)
			assert.NotErrorIs(t, err, MaxElapsedExceededError)
			assert.Nil(t, resp)
			assert.Equal(t, 1, calls)
			assert.Equal(t, 1, body.closes)
			assert.ErrorIs(t, attemptCtx.Err(), context.Canceled)
		})
	}
}

func TestRetryWithoutDeadlineOrBudgetUsesAllRetries(t *testing.T) {
	var calls atomic.Int64
	stub := httpClientFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		return newStubResponse(req, http.StatusServiceUnavailable, ""), nil
	})

	opts := defaultHTTPClientOption()
	WithHTTPClient(stub)(&opts)
	WithRetry(RetryConfig{Max: 3, WaitMin: time.Millisecond, WaitMax: time.Millisecond})(&opts)
	client := newCommonClient(testSystemInfo, opts)

	req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
	require.NoError(t, err)

	resp, err := client.do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, int64(4), calls.Load())
}

// A Retry-After near the time.Duration limit used to wrap negative once the
// elapsed time was added to it, and pass the budget check.
func TestWaitOutlastsHugeWait(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
	require.NoError(t, err)

	const huge = time.Duration(1<<63 - 1)
	reason, ok := waitOutlasts(req, time.Minute, time.Now().Add(-time.Second), huge)
	assert.True(t, ok)
	assert.Equal(t, "MaxElapsed budget", reason)
}

func TestRetryMaxElapsedBoundsAttempts(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(slow.Close)

	newClient := func(retry RetryConfig) *commonClient {
		opts := defaultHTTPClientOption()
		WithRetry(retry)(&opts)
		return newCommonClient(testSystemInfo, opts)
	}

	t.Run("a slow attempt is cut off by the budget", func(t *testing.T) {
		client := newClient(RetryConfig{Max: 2, WaitMin: time.Millisecond, WaitMax: time.Millisecond, MaxElapsed: 200 * time.Millisecond})
		req, err := http.NewRequest(http.MethodGet, slow.URL, nil)
		require.NoError(t, err)

		start := time.Now()
		_, err = client.do(req)
		assert.Less(t, time.Since(start), time.Second)
		require.Error(t, err)
		assert.ErrorIs(t, err, MaxElapsedExceededError)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Contains(t, err.Error(), "MaxElapsed exceeded after 200ms")
	})

	t.Run("an earlier caller deadline wins", func(t *testing.T) {
		client := newClient(RetryConfig{Max: 2, WaitMin: time.Millisecond, WaitMax: time.Millisecond, MaxElapsed: 5 * time.Second})
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, slow.URL, nil)
		require.NoError(t, err)

		start := time.Now()
		_, err = client.do(req)
		assert.Less(t, time.Since(start), time.Second)
		require.Error(t, err)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
		assert.NotErrorIs(t, err, MaxElapsedExceededError)
	})

	t.Run("a caller cancel is reported as such", func(t *testing.T) {
		client := newClient(RetryConfig{Max: 2, WaitMin: time.Millisecond, WaitMax: time.Millisecond, MaxElapsed: 5 * time.Second})
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(100*time.Millisecond, cancel)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, slow.URL, nil)
		require.NoError(t, err)

		_, err = client.do(req)
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
		assert.NotErrorIs(t, err, MaxElapsedExceededError)
	})
}

// TestRetryMaxElapsedKeepsBodyReadable guards the budget context's lifetime:
// the response body is streamed under it, so it must stay open until doWith
// has read the body.
func TestRetryMaxElapsedKeepsBodyReadable(t *testing.T) {
	payload := bytes.Repeat([]byte("0123456789abcdef"), 64*1024) // 1 MiB
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		for chunk := range slices.Chunk(payload, 32*1024) {
			w.Write(chunk)
			w.(http.Flusher).Flush()
		}
	}))
	t.Cleanup(server.Close)

	opts := defaultHTTPClientOption()
	WithRetry(RetryConfig{Max: 2, MaxElapsed: 5 * time.Second})(&opts)
	client := newCommonClient(testSystemInfo, opts)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)

	resp, err := client.do(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, payload, body)
}

func TestRetryWaitAtDeadlineReturnsResponse(t *testing.T) {
	for _, useBudget := range []bool{false, true} {
		t.Run(fmt.Sprintf("MaxElapsed=%t", useBudget), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx := context.Background()
				retry := RetryConfig{
					Max: 2,
					Backoff: func(time.Duration, time.Duration, int, *http.Response) time.Duration {
						return time.Second
					},
				}
				if useBudget {
					retry.MaxElapsed = time.Second
				} else {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, time.Second)
					defer cancel()
				}

				var calls int
				stub := httpClientFunc(func(req *http.Request) (*http.Response, error) {
					calls++
					return newStubResponse(req, http.StatusServiceUnavailable, "unavailable"), nil
				})
				opts := defaultHTTPClientOption()
				WithHTTPClient(stub)(&opts)
				WithRetry(retry)(&opts)
				client := newCommonClient(testSystemInfo, opts)
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://actions.example/", nil)
				require.NoError(t, err)

				start := time.Now()
				resp, err := client.do(req)
				require.NoError(t, err)
				assert.Zero(t, time.Since(start))
				assert.Equal(t, 1, calls)
				assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Equal(t, "unavailable", string(body))
			})
		})
	}
}

func TestRetryMaxElapsedKeepsFirstCancellationCause(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		stub := httpClientFunc(func(req *http.Request) (*http.Response, error) {
			<-req.Context().Done()
			cancel()
			return nil, req.Context().Err()
		})
		opts := defaultHTTPClientOption()
		WithHTTPClient(stub)(&opts)
		WithRetry(RetryConfig{MaxElapsed: time.Second})(&opts)
		client := newCommonClient(testSystemInfo, opts)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://actions.example/", nil)
		require.NoError(t, err)

		_, err = client.do(req)
		require.ErrorIs(t, err, MaxElapsedExceededError)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
		assert.NotErrorIs(t, err, context.Canceled)
	})
}

type trackedResponseBody struct {
	io.Reader
	closes   int
	closeErr error
}

func (b *trackedResponseBody) Close() error {
	b.closes++
	return b.closeErr
}

func TestRetryMaxElapsedClosesStalledBody(t *testing.T) {
	for _, poll := range []bool{false, true} {
		t.Run(fmt.Sprintf("poll=%t", poll), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var body trackedResponseBody
				var attemptCtx context.Context
				var calls int
				stub := httpClientFunc(func(req *http.Request) (*http.Response, error) {
					calls++
					attemptCtx = req.Context()
					body.Reader = stalledReader{ctx: attemptCtx}
					resp := newStubResponse(req, http.StatusOK, "")
					resp.Body = &body
					return resp, nil
				})
				opts := defaultHTTPClientOption()
				WithHTTPClient(stub)(&opts)
				WithRetry(RetryConfig{Max: 2, MaxElapsed: time.Second})(&opts)
				client := newCommonClient(testSystemInfo, opts)
				req, err := http.NewRequest(http.MethodGet, "https://actions.example/", nil)
				require.NoError(t, err)

				var retryOpts []retryOption
				if poll {
					retryOpts = append(retryOpts, withAttemptTimeout(MessagePollTimeout))
				}
				start := time.Now()
				_, err = client.do(req, retryOpts...)
				require.ErrorIs(t, err, MaxElapsedExceededError)
				assert.ErrorIs(t, err, context.DeadlineExceeded)
				assert.Equal(t, time.Second, time.Since(start))
				assert.Equal(t, 1, calls)
				assert.Equal(t, 1, body.closes)
				assert.ErrorIs(t, attemptCtx.Err(), context.DeadlineExceeded)
			})
		})
	}
}
