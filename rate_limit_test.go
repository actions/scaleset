package scaleset

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, time.January, 2, 15, 4, 5, 0, time.UTC)

	for _, tc := range []struct {
		name   string
		value  string
		want   time.Duration
		wantOK bool
	}{
		{name: "empty", value: ""},
		{name: "seconds", value: "30", want: 30 * time.Second, wantOK: true},
		{name: "zero seconds", value: "0", want: 0, wantOK: true},
		{name: "http date", value: now.Add(45 * time.Second).Format(http.TimeFormat), want: 45 * time.Second, wantOK: true},
		{name: "rfc 850 date", value: now.Add(time.Minute).Format(time.RFC850), want: time.Minute, wantOK: true},
		{name: "date equal to now", value: now.Format(http.TimeFormat), want: 0, wantOK: true},
		{name: "past date", value: now.Add(-time.Minute).Format(http.TimeFormat)},
		{name: "negative seconds", value: "-5"},
		{name: "invalid", value: "soon"},
		{name: "fractional seconds", value: "1.5"},
		{name: "overflowing duration", value: "9223372036854775807"},
		{name: "overflowing integer", value: "99999999999999999999"},
		{name: "overflowing http date", value: "Fri, 31 Dec 9999 23:59:59 GMT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseRetryAfter(tc.value, now)
			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestRateLimitFromResponse(t *testing.T) {
	now := time.Date(2026, time.January, 2, 15, 4, 5, 0, time.UTC)

	for _, tc := range []struct {
		name           string
		status         int
		header         http.Header
		message        string
		wantOK         bool
		wantKind       RateLimitKind
		wantRetryAfter time.Duration
		wantReset      time.Time
	}{
		{
			name:     "429 without hints",
			status:   http.StatusTooManyRequests,
			header:   http.Header{},
			wantOK:   true,
			wantKind: RateLimitSecondary,
		},
		{
			name:           "429 with Retry-After seconds",
			status:         http.StatusTooManyRequests,
			header:         http.Header{headerRetryAfter: {"30"}},
			wantOK:         true,
			wantKind:       RateLimitSecondary,
			wantRetryAfter: 30 * time.Second,
		},
		{
			name:     "429 with zero Retry-After",
			status:   http.StatusTooManyRequests,
			header:   http.Header{headerRetryAfter: {"0"}},
			wantOK:   true,
			wantKind: RateLimitSecondary,
		},
		{
			name:           "429 with Retry-After date",
			status:         http.StatusTooManyRequests,
			header:         http.Header{headerRetryAfter: {now.Add(90 * time.Second).Format(http.TimeFormat)}},
			wantOK:         true,
			wantKind:       RateLimitSecondary,
			wantRetryAfter: 90 * time.Second,
		},
		{
			name:     "429 with past Retry-After date",
			status:   http.StatusTooManyRequests,
			header:   http.Header{headerRetryAfter: {now.Add(-time.Minute).Format(http.TimeFormat)}},
			wantOK:   true,
			wantKind: RateLimitSecondary,
		},
		{
			name:     "429 with negative Retry-After",
			status:   http.StatusTooManyRequests,
			header:   http.Header{headerRetryAfter: {"-5"}},
			wantOK:   true,
			wantKind: RateLimitSecondary,
		},
		{
			name:     "429 with invalid Retry-After",
			status:   http.StatusTooManyRequests,
			header:   http.Header{headerRetryAfter: {"soon"}},
			wantOK:   true,
			wantKind: RateLimitSecondary,
		},
		{
			name:     "429 with overflowing Retry-After",
			status:   http.StatusTooManyRequests,
			header:   http.Header{headerRetryAfter: {"9223372036854775807"}},
			wantOK:   true,
			wantKind: RateLimitSecondary,
		},
		{
			name:   "429 with remaining quota uses no reset for the delay",
			status: http.StatusTooManyRequests,
			header: http.Header{
				headerRateLimitRemaining: {"5"},
				headerRateLimitReset:     {unixString(now.Add(2 * time.Minute))},
			},
			wantOK:    true,
			wantKind:  RateLimitSecondary,
			wantReset: now.Add(2 * time.Minute),
		},
		{
			name:   "429 with spent primary limit",
			status: http.StatusTooManyRequests,
			header: http.Header{
				headerRateLimitRemaining: {"0"},
				headerRateLimitReset:     {unixString(now.Add(2 * time.Minute))},
			},
			wantOK:         true,
			wantKind:       RateLimitPrimary,
			wantRetryAfter: 2 * time.Minute,
			wantReset:      now.Add(2 * time.Minute),
		},
		{
			name:           "403 with Retry-After",
			status:         http.StatusForbidden,
			header:         http.Header{headerRetryAfter: {"60"}},
			wantOK:         true,
			wantKind:       RateLimitSecondary,
			wantRetryAfter: time.Minute,
		},
		{
			name:     "403 with secondary-limit message",
			status:   http.StatusForbidden,
			message:  "You have exceeded a secondary rate limit.",
			wantOK:   true,
			wantKind: RateLimitSecondary,
		},
		{
			name:     "403 with secondary limit and remaining primary quota",
			status:   http.StatusForbidden,
			header:   http.Header{headerRateLimitRemaining: {"10"}},
			message:  "You have exceeded a secondary rate limit.",
			wantOK:   true,
			wantKind: RateLimitSecondary,
		},
		{
			name:   "secondary-limit message takes precedence over spent primary quota",
			status: http.StatusForbidden,
			header: http.Header{
				headerRateLimitRemaining: {"0"},
				headerRateLimitReset:     {unixString(now.Add(2 * time.Minute))},
			},
			message:        "You have exceeded a secondary rate limit.",
			wantOK:         true,
			wantKind:       RateLimitSecondary,
			wantRetryAfter: 2 * time.Minute,
			wantReset:      now.Add(2 * time.Minute),
		},
		{
			name:   "secondary limit honors Retry-After before reset",
			status: http.StatusForbidden,
			header: http.Header{
				headerRetryAfter:         {"10"},
				headerRateLimitRemaining: {"0"},
				headerRateLimitReset:     {unixString(now.Add(2 * time.Minute))},
			},
			message:        "You have exceeded a secondary rate limit.",
			wantOK:         true,
			wantKind:       RateLimitSecondary,
			wantRetryAfter: 10 * time.Second,
			wantReset:      now.Add(2 * time.Minute),
		},
		{
			name:   "403 with spent primary limit",
			status: http.StatusForbidden,
			header: http.Header{
				headerRateLimitRemaining: {"0"},
				headerRateLimitReset:     {unixString(now.Add(2 * time.Minute))},
			},
			wantOK:         true,
			wantKind:       RateLimitPrimary,
			wantRetryAfter: 2 * time.Minute,
			wantReset:      now.Add(2 * time.Minute),
		},
		{
			name:   "Retry-After takes precedence over X-RateLimit-Reset",
			status: http.StatusForbidden,
			header: http.Header{
				headerRetryAfter:         {"10"},
				headerRateLimitRemaining: {"0"},
				headerRateLimitReset:     {unixString(now.Add(2 * time.Minute))},
			},
			wantOK:         true,
			wantKind:       RateLimitPrimary,
			wantRetryAfter: 10 * time.Second,
			wantReset:      now.Add(2 * time.Minute),
		},
		{
			name:   "zero Retry-After takes precedence over X-RateLimit-Reset",
			status: http.StatusForbidden,
			header: http.Header{
				headerRetryAfter:         {"0"},
				headerRateLimitRemaining: {"0"},
				headerRateLimitReset:     {unixString(now.Add(2 * time.Minute))},
			},
			wantOK:    true,
			wantKind:  RateLimitPrimary,
			wantReset: now.Add(2 * time.Minute),
		},
		{
			name:   "unusable Retry-After falls back to X-RateLimit-Reset",
			status: http.StatusForbidden,
			header: http.Header{
				headerRetryAfter:         {"soon"},
				headerRateLimitRemaining: {"0"},
				headerRateLimitReset:     {unixString(now.Add(2 * time.Minute))},
			},
			wantOK:         true,
			wantKind:       RateLimitPrimary,
			wantRetryAfter: 2 * time.Minute,
			wantReset:      now.Add(2 * time.Minute),
		},
		{
			name:   "past X-RateLimit-Reset",
			status: http.StatusForbidden,
			header: http.Header{
				headerRateLimitRemaining: {"0"},
				headerRateLimitReset:     {unixString(now.Add(-time.Minute))},
			},
			wantOK:    true,
			wantKind:  RateLimitPrimary,
			wantReset: now.Add(-time.Minute),
		},
		{
			name:   "invalid X-RateLimit-Reset",
			status: http.StatusForbidden,
			header: http.Header{
				headerRateLimitRemaining: {"0"},
				headerRateLimitReset:     {"later"},
			},
			wantOK:   true,
			wantKind: RateLimitPrimary,
		},
		{
			name:   "negative X-RateLimit-Reset",
			status: http.StatusForbidden,
			header: http.Header{
				headerRateLimitRemaining: {"0"},
				headerRateLimitReset:     {"-1"},
			},
			wantOK:   true,
			wantKind: RateLimitPrimary,
		},
		{
			name:   "overflowing X-RateLimit-Reset",
			status: http.StatusForbidden,
			header: http.Header{
				headerRateLimitRemaining: {"0"},
				headerRateLimitReset:     {"99999999999999999999"},
			},
			wantOK:   true,
			wantKind: RateLimitPrimary,
		},
		{
			name:   "X-RateLimit-Reset too far ahead for a duration",
			status: http.StatusForbidden,
			header: http.Header{
				headerRateLimitRemaining: {"0"},
				headerRateLimitReset:     {"253402300799"},
			},
			wantOK:    true,
			wantKind:  RateLimitPrimary,
			wantReset: time.Unix(253402300799, 0),
		},
		{
			name:   "429 with far-future Retry-After date",
			status: http.StatusTooManyRequests,
			header: http.Header{
				headerRetryAfter: {"Fri, 31 Dec 9999 23:59:59 GMT"},
			},
			wantOK:   true,
			wantKind: RateLimitSecondary,
		},
		{
			name:   "unrelated 403",
			status: http.StatusForbidden,
			header: http.Header{},
		},
		{
			name:    "403 message must have a word boundary",
			status:  http.StatusForbidden,
			message: "nonsecondary rate limit",
		},
		{
			name:    "404 with secondary-limit message",
			status:  http.StatusNotFound,
			message: "You have exceeded a secondary rate limit.",
		},
		{
			name:   "403 with remaining quota",
			status: http.StatusForbidden,
			header: http.Header{
				headerRateLimitRemaining: {"10"},
				headerRateLimitReset:     {unixString(now.Add(time.Minute))},
			},
		},
		{
			name:   "503 with Retry-After",
			status: http.StatusServiceUnavailable,
			header: http.Header{headerRetryAfter: {"30"}},
		},
		{
			name:   "200",
			status: http.StatusOK,
			header: http.Header{headerRateLimitRemaining: {"0"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rl, ok := rateLimitFromResponse(&http.Response{StatusCode: tc.status, Header: canonical(tc.header)}, tc.message, now)
			require.Equal(t, tc.wantOK, ok)
			if !ok {
				assert.Nil(t, rl)
				return
			}

			assert.Equal(t, tc.wantKind, rl.Kind)
			assert.Equal(t, tc.status, rl.StatusCode)
			assert.Equal(t, tc.wantRetryAfter, rl.RetryAfter)
			assert.True(t, tc.wantReset.Equal(rl.Reset), "Reset: want %v, got %v", tc.wantReset, rl.Reset)
		})
	}

	t.Run("nil response", func(t *testing.T) {
		rl, ok := rateLimitFromResponse(nil, "", now)
		assert.False(t, ok)
		assert.Nil(t, rl)
	})
}

func TestRateLimitKindString(t *testing.T) {
	assert.Equal(t, "primary", RateLimitPrimary.String())
	assert.Equal(t, "secondary", RateLimitSecondary.String())
	assert.Equal(t, "RateLimitKind(0)", RateLimitKind(0).String())
}

func TestRateLimitError(t *testing.T) {
	inner := errors.New("request POST https://example.com failed")

	t.Run("includes the retry-after and the underlying error", func(t *testing.T) {
		err := &RateLimitError{RetryAfter: 30 * time.Second, err: inner}
		assert.Equal(t, "rate limited (retry after 30s): request POST https://example.com failed", err.Error())
		assert.ErrorIs(t, err, inner)
	})

	t.Run("omits a zero retry-after", func(t *testing.T) {
		err := &RateLimitError{err: inner}
		assert.Equal(t, "rate limited: request POST https://example.com failed", err.Error())
	})

	t.Run("without an underlying error", func(t *testing.T) {
		err := &RateLimitError{}
		assert.Equal(t, "rate limited", err.Error())
		assert.NoError(t, err.Unwrap())
	})
}

func TestNewRequestResponseErrorRateLimit(t *testing.T) {
	newReq := func(t *testing.T) *http.Request {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, "https://example.com/_apis/runtime/runnerscalesets/1/generatejitconfig", nil)
		require.NoError(t, err)
		return req
	}

	newResp := func(status int, header http.Header, body string) *http.Response {
		header = canonical(header)
		header.Set("Content-Type", "application/json")
		header.Set(headerActionsActivityID, "activity-id")
		return &http.Response{
			Status:        http.StatusText(status),
			StatusCode:    status,
			ContentLength: int64(len(body)),
			Header:        header,
			Body:          io.NopCloser(strings.NewReader(body)),
		}
	}

	exception := `{"typeName":"ConfigureTooManyRunnersException","message":"too many runners"}`

	t.Run("429 becomes a RateLimitError that keeps the full context", func(t *testing.T) {
		base := errors.New("unexpected status code: 429")
		resp := newResp(http.StatusTooManyRequests, http.Header{headerRetryAfter: {"30"}}, exception)

		err := newRequestResponseError(newReq(t), resp, base)

		var rl *RateLimitError
		require.ErrorAs(t, err, &rl)
		assert.Equal(t, RateLimitSecondary, rl.Kind)
		assert.Equal(t, http.StatusTooManyRequests, rl.StatusCode)
		assert.Equal(t, 30*time.Second, rl.RetryAfter)
		assert.ErrorIs(t, err, base)

		var ex actionsExceptionError
		require.ErrorAs(t, err, &ex)
		assert.Equal(t, "ConfigureTooManyRunnersException", ex.ExceptionName)

		msg := err.Error()
		assert.Contains(t, msg, "retry after 30s")
		assert.Contains(t, msg, "request POST https://example.com/_apis/runtime/runnerscalesets/1/generatejitconfig failed")
		assert.Contains(t, msg, `activity_id="activity-id"`)
		assert.Contains(t, msg, "too many runners")
	})

	t.Run("rate-limited 403 becomes a RateLimitError", func(t *testing.T) {
		resp := newResp(http.StatusForbidden, http.Header{headerRateLimitRemaining: {"0"}}, `{"message":"API rate limit exceeded"}`)

		err := newRequestResponseError(newReq(t), resp, errors.New("unexpected status code: 403"))

		var rl *RateLimitError
		require.ErrorAs(t, err, &rl)
		assert.Equal(t, RateLimitPrimary, rl.Kind)
		assert.Equal(t, http.StatusForbidden, rl.StatusCode)
	})

	for _, tc := range []struct {
		name        string
		body        string
		contentType string
		wantLimit   bool
	}{
		{
			name:      "secondary limit without headers",
			body:      `{"message":"You have exceeded a secondary rate limit. Please wait a few minutes before you try again."}`,
			wantLimit: true,
		},
		{
			name:      "secondary limit with mixed case",
			body:      `{"message":"You have exceeded a SECONDARY RATE LIMIT."}`,
			wantLimit: true,
		},
		{
			name:      "secondary limit with JSON escapes",
			body:      `{"message":"You have exceeded a secondary \u0072ate limit."}`,
			wantLimit: true,
		},
		{
			name:        "plain text secondary limit",
			body:        "You have exceeded a secondary rate limit.",
			contentType: "text/plain; charset=utf-8",
			wantLimit:   true,
		},
		{
			name: "secondary limit mentioned outside the message",
			body: `{"message":"Resource not accessible by integration","documentation":"secondary rate limits"}`,
		},
		{
			name: "secondary limit mentioned in malformed JSON",
			body: `{"message":"You have exceeded a secondary rate limit."`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := errors.New("unexpected status code: 403")
			resp := newResp(http.StatusForbidden, nil, tc.body)
			resp.Header.Set(headerGitHubRequestID, "request-id")
			if tc.contentType != "" {
				resp.Header.Set("Content-Type", tc.contentType)
			}

			err := newRequestResponseError(newReq(t), resp, base)

			var rl *RateLimitError
			require.Equal(t, tc.wantLimit, errors.As(err, &rl))
			if !tc.wantLimit {
				return
			}

			assert.Equal(t, RateLimitSecondary, rl.Kind)
			assert.Equal(t, http.StatusForbidden, rl.StatusCode)
			assert.Zero(t, rl.RetryAfter)
			assert.True(t, rl.Reset.IsZero())
			assert.ErrorIs(t, err, base)
			assert.Contains(t, err.Error(), "request POST https://example.com/_apis/runtime/runnerscalesets/1/generatejitconfig failed")
			assert.Contains(t, err.Error(), `activity_id="activity-id"`)
			assert.Contains(t, err.Error(), `github_request_id="request-id"`)
			if tc.contentType == "" {
				var ex actionsExceptionError
				require.ErrorAs(t, err, &ex)
				assert.Contains(t, strings.ToLower(ex.Message), "secondary rate limit")
			}
		})
	}

	t.Run("unrelated 403 is untouched", func(t *testing.T) {
		base := errors.New("unexpected status code: 403")
		resp := newResp(http.StatusForbidden, http.Header{}, `{"typeName":"AccessDeniedException","message":"forbidden"}`)

		err := newRequestResponseError(newReq(t), resp, base)

		var rl *RateLimitError
		assert.False(t, errors.As(err, &rl))
		assert.ErrorIs(t, err, base)
		assert.NotContains(t, err.Error(), "rate limited")
	})

	t.Run("other statuses keep their sentinel errors", func(t *testing.T) {
		resp := newResp(http.StatusNotFound, http.Header{headerRetryAfter: {"30"}}, `{"message":"missing"}`)

		err := newRequestResponseError(newReq(t), resp, errors.New("unexpected status code: 404"))

		var rl *RateLimitError
		assert.False(t, errors.As(err, &rl))
		assert.ErrorIs(t, err, NotFoundError)
	})
}

func TestRateLimitErrorAfterRetriesAreExhausted(t *testing.T) {
	var attempts atomic.Int64
	server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(headerRetryAfter, "120")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"typeName":"ConfigureTooManyRunnersException","message":"too many runners"}`))
	}))

	client, err := newClient(
		testSystemInfo,
		server.configURLForOrg("my-org"),
		actionsAuth{token: "token"},
		WithRetry(RetryConfig{
			Max:     2,
			WaitMin: time.Millisecond,
			WaitMax: time.Millisecond,
			// Ignore Retry-After so the test does not wait two minutes.
			Backoff: func(waitMin, _ time.Duration, _ int, _ *http.Response) time.Duration {
				return waitMin
			},
		}),
	)
	require.NoError(t, err)

	_, err = client.GenerateJitRunnerConfig(context.Background(), &RunnerScaleSetJitRunnerSetting{}, 1)
	require.Error(t, err)
	assert.Equal(t, int64(3), attempts.Load())

	var rl *RateLimitError
	require.ErrorAs(t, err, &rl)
	assert.Equal(t, RateLimitSecondary, rl.Kind)
	assert.Equal(t, http.StatusTooManyRequests, rl.StatusCode)
	assert.Equal(t, 120*time.Second, rl.RetryAfter)
	assert.Equal(t, 2, rl.Retries)
	assert.Contains(t, err.Error(), "ConfigureTooManyRunnersException")
}

func TestSecondaryRateLimitErrorFromRegistrationToken(t *testing.T) {
	var attempts atomic.Int64
	client, err := newClient(
		testSystemInfo,
		"https://github.com/my-org",
		actionsAuth{token: "token"},
		WithHTTPClient(httpClientFunc(func(req *http.Request) (*http.Response, error) {
			attempts.Add(1)
			assert.Equal(t, http.MethodPost, req.Method)
			assert.Equal(t, "/orgs/my-org/actions/runners/registration-token", req.URL.Path)
			resp := newStubResponse(req, http.StatusForbidden, `{"message":"You have exceeded a secondary rate limit."}`)
			resp.ContentLength = -1
			return resp, nil
		})),
		WithRetry(RetryConfig{
			Max:     2,
			WaitMin: time.Millisecond,
			WaitMax: time.Millisecond,
		}),
	)
	require.NoError(t, err)

	_, err = client.getRunnerRegistrationToken(context.Background())

	var rl *RateLimitError
	require.ErrorAs(t, err, &rl)
	assert.Equal(t, RateLimitSecondary, rl.Kind)
	assert.Equal(t, http.StatusForbidden, rl.StatusCode)
	assert.Zero(t, rl.RetryAfter)
	assert.Contains(t, err.Error(), "You have exceeded a secondary rate limit.")
	assert.Equal(t, int64(1), attempts.Load(), "classification must not enable automatic retries for 403s")
}

// canonical rebuilds h with canonical keys, as a received response has.
// Header literals keep keys such as X-RateLimit-Remaining verbatim, which
// Header.Get would not find.
func canonical(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for key, values := range h {
		for _, value := range values {
			out.Add(key, value)
		}
	}
	return out
}

func unixString(t time.Time) string {
	return strconv.FormatInt(t.Unix(), 10)
}
