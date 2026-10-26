package scaleset

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func assertResponseError(t *testing.T, err error, status int, body string) *http.Response {
	t.Helper()
	var responseErr *RequestResponseError
	require.ErrorAs(t, err, &responseErr)
	require.NotNil(t, responseErr.Response)
	assert.Equal(t, status, responseErr.Response.StatusCode)
	assert.Same(t, responseErr.Err, errors.Unwrap(responseErr))
	got, readErr := io.ReadAll(responseErr.Response.Body)
	require.NoError(t, readErr)
	assert.Equal(t, body, string(got))
	require.NoError(t, responseErr.Response.Body.Close())
	return responseErr.Response
}

func newResponseTestClients(t *testing.T, transport HTTPClient) (*Client, *MessageSessionClient) {
	t.Helper()
	client, err := NewClientWithPersonalAccessToken(
		NewClientWithPersonalAccessTokenConfig{
			GitHubConfigURL:     "https://github.com/example",
			PersonalAccessToken: "test-token",
		},
		WithHTTPClient(transport),
		WithRetry(RetryConfig{}),
	)
	require.NoError(t, err)
	client.actionsServiceAdminToken = actionsServiceAdminToken{
		token:     "test-admin-token",
		url:       "https://actions.example",
		expiresAt: time.Now().Add(time.Hour),
	}
	session := &MessageSessionClient{
		innerClient:  client,
		commonClient: &client.commonClient,
		scaleSetID:   1,
		owner:        "test",
	}
	session.session.Store(&RunnerScaleSetSession{
		SessionID:               uuid.MustParse("00000000-0000-0000-0000-000000000001"),
		MessageQueueURL:         "https://actions.example/queue",
		MessageQueueAccessToken: "test-queue-token",
	})
	return client, session
}

func TestResponseErrorRequiredBodies(t *testing.T) {
	endpoints := []struct {
		name string
		call func(*Client, *MessageSessionClient) error
	}{
		{"get scale set", func(c *Client, _ *MessageSessionClient) error {
			_, err := c.GetRunnerScaleSet(t.Context(), 1, "test")
			return err
		}},
		{"list scale sets", func(c *Client, _ *MessageSessionClient) error {
			_, err := c.ListRunnerScaleSets(t.Context(), 1)
			return err
		}},
		{"get scale set by ID", func(c *Client, _ *MessageSessionClient) error {
			_, err := c.GetRunnerScaleSetByID(t.Context(), 1)
			return err
		}},
		{"get runner group", func(c *Client, _ *MessageSessionClient) error {
			_, err := c.GetRunnerGroupByName(t.Context(), "test")
			return err
		}},
		{"create scale set", func(c *Client, _ *MessageSessionClient) error {
			_, err := c.CreateRunnerScaleSet(t.Context(), &RunnerScaleSet{Name: "test"})
			return err
		}},
		{"update scale set", func(c *Client, _ *MessageSessionClient) error {
			_, err := c.UpdateRunnerScaleSet(t.Context(), 1, &RunnerScaleSet{Name: "test"})
			return err
		}},
		{"generate JIT config", func(c *Client, _ *MessageSessionClient) error {
			_, err := c.GenerateJitRunnerConfig(t.Context(), &RunnerScaleSetJitRunnerSetting{}, 1)
			return err
		}},
		{"get runner", func(c *Client, _ *MessageSessionClient) error {
			_, err := c.GetRunner(t.Context(), 1)
			return err
		}},
		{"get runner by name", func(c *Client, _ *MessageSessionClient) error {
			_, err := c.GetRunnerByName(t.Context(), "test")
			return err
		}},
		{"create session", func(c *Client, _ *MessageSessionClient) error {
			_, err := c.MessageSessionClient(t.Context(), 1, "test")
			return err
		}},
		{"refresh session", func(_ *Client, s *MessageSessionClient) error {
			return s.refreshMessageSession(t.Context(), s.Session())
		}},
		{"acquire jobs", func(_ *Client, s *MessageSessionClient) error {
			_, err := s.AcquireJobs(t.Context(), []int64{1})
			return err
		}},
		{"get message", func(_ *Client, s *MessageSessionClient) error {
			_, err := s.GetMessage(t.Context(), 0, 1)
			return err
		}},
	}
	for _, endpoint := range endpoints {
		for _, tc := range []struct {
			name    string
			body    string
			nilBody bool
			cause   error
			syntax  bool
		}{
			{name: "empty", cause: io.EOF},
			{name: "absent body", nilBody: true, cause: io.EOF},
			{name: "whitespace", body: " \r\n\t", cause: io.EOF},
			{name: "truncated JSON", body: `{"token":`, cause: io.ErrUnexpectedEOF},
			{name: "malformed JSON", body: "<html>upstream failed</html>", syntax: true},
			{name: "BOM and trailing garbage", body: "\xef\xbb\xbf{} garbage", syntax: true},
			{name: "multiple JSON values", body: "{} {}"},
		} {
			t.Run(endpoint.name+"/"+tc.name, func(t *testing.T) {
				client, session := newResponseTestClients(t, httpClientFunc(func(req *http.Request) (*http.Response, error) {
					resp := newStubResponse(req, http.StatusOK, tc.body)
					resp.Header.Set(headerGitHubRequestID, "required-body-id")
					if tc.nilBody {
						resp.Body = nil
					}
					return resp, nil
				}))
				err := endpoint.call(client, session)
				resp := assertResponseError(t, err, http.StatusOK, tc.body)
				assert.Equal(t, "required-body-id", resp.Header.Get(headerGitHubRequestID))
				if tc.cause != nil {
					assert.ErrorIs(t, err, tc.cause)
				}
				if tc.syntax {
					var syntaxErr *json.SyntaxError
					assert.ErrorAs(t, err, &syntaxErr)
				}
			})
		}
	}
}

func TestResponseErrorMetadataAndClassification(t *testing.T) {
	base := errors.New("original cause")
	for _, tc := range []struct {
		status int
		body   string
		want   error
		domain error
	}{
		{http.StatusUnauthorized, `{"message":"bad credentials"}`, UnauthorizedError, nil},
		{http.StatusBadRequest, "", BadRequestError, nil},
		{http.StatusNotFound, `{"typeName":"AgentNotFoundException","message":"missing"}`, NotFoundError, RunnerNotFoundError},
		{http.StatusConflict, `{"typeName":"AgentExistsException","message":"exists"}`, ConflictError, RunnerExistsError},
		{http.StatusConflict, `{"typeName":"JobStillRunningException","message":"running"}`, ConflictError, JobStillRunningError},
		{http.StatusBadGateway, "<html>proxy unavailable</html>", nil, nil},
	} {
		t.Run(fmt.Sprintf("%d/%v", tc.status, tc.domain), func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "https://user:secret@example.com/api?token=private#fragment", nil)
			require.NoError(t, err)
			resp := newStubResponse(req, tc.status, tc.body)
			resp.Proto, resp.ProtoMajor, resp.ProtoMinor = "HTTP/2.0", 2, 0
			resp.ContentLength = -1
			resp.Header.Set(headerActionsActivityID, "activity-id")
			resp.Header.Set(headerGitHubRequestID, "github-id")
			resp.Trailer = http.Header{"X-Trailer": {"trailer-value"}}

			err = newRequestResponseError(req, resp, base)
			got := assertResponseError(t, err, tc.status, tc.body)
			assert.ErrorIs(t, err, base)
			if tc.want != nil {
				assert.ErrorIs(t, err, tc.want)
			}
			if tc.domain != nil {
				assert.ErrorIs(t, err, tc.domain)
			}
			assert.NotSame(t, resp, got)
			assert.Same(t, req, got.Request)
			assert.Equal(t, resp.Status, got.Status)
			assert.Equal(t, "HTTP/2.0", got.Proto)
			assert.EqualValues(t, -1, got.ContentLength)
			assert.Equal(t, "activity-id", got.Header.Get(headerActionsActivityID))
			assert.Equal(t, "github-id", got.Header.Get(headerGitHubRequestID))
			assert.Equal(t, "trailer-value", got.Trailer.Get("X-Trailer"))
			resp.Header.Set(headerGitHubRequestID, "changed")
			resp.Trailer.Set("X-Trailer", "changed")
			assert.Equal(t, "github-id", got.Header.Get(headerGitHubRequestID))
			assert.Equal(t, "trailer-value", got.Trailer.Get("X-Trailer"))
			assert.NotContains(t, err.Error(), "secret")
			assert.NotContains(t, err.Error(), "private")
			assert.NotContains(t, err.Error(), "fragment")
		})
	}
}

func TestResponseErrorURLRedaction(t *testing.T) {
	const rawURL = "https://sensitive-user:sensitive-password@actions.example/queue?token=sensitive-query#sensitive-fragment"
	const safeURL = "https://actions.example/queue"
	for _, tc := range []struct {
		name       string
		status     int
		retry      bool
		wait       time.Duration
		maxElapsed time.Duration
		calls      int
		log        string
	}{
		{
			name: "rate limit declined", status: http.StatusTooManyRequests,
			calls: 1, log: "rate limit hook declined",
		},
		{
			name: "wait exceeds budget", status: http.StatusTooManyRequests,
			retry: true, wait: time.Hour, maxElapsed: time.Minute,
			calls: 1, log: "wait reaches or exceeds MaxElapsed budget",
		},
		{
			name: "ordinary retry", status: http.StatusServiceUnavailable,
			calls: 2, log: "retrying request",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls, hooks int
			client := newStubCommonClient(httpClientFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				assert.Equal(t, rawURL, req.URL.String())
				return newStubResponse(req, tc.status, `{"message":"unavailable"}`), nil
			}), RetryConfig{
				Max: 1, MaxElapsed: tc.maxElapsed,
				Backoff: func(time.Duration, time.Duration, int, *http.Response) time.Duration {
					return time.Nanosecond
				},
				OnRateLimit: func(_ context.Context, rl *RateLimitError) (time.Duration, bool) {
					hooks++
					assert.Contains(t, rl.Error(), safeURL)
					assert.NotContains(t, rl.Error(), "sensitive-")
					return tc.wait, tc.retry
				},
			})
			var logs bytes.Buffer
			client.logger = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, rawURL, nil)
			require.NoError(t, err)

			resp, err := client.do(req)
			require.NoError(t, err)
			responseErr := newRequestResponseError(req, resp, errors.New("unexpected status"))
			snapshot := assertResponseError(t, responseErr, tc.status, `{"message":"unavailable"}`)
			assert.Equal(t, rawURL, snapshot.Request.URL.String())
			assert.Equal(t, rawURL, req.URL.String())
			assert.Equal(t, tc.calls, calls)
			if tc.status == http.StatusTooManyRequests {
				assert.Equal(t, 1, hooks)
			} else {
				assert.Zero(t, hooks)
			}
			assert.Contains(t, logs.String(), tc.log)
			assert.Contains(t, logs.String(), `"url":"`+safeURL+`"`)
			assert.NotContains(t, logs.String(), "sensitive-")
			assert.Equal(t, 1, strings.Count(logs.String(), "\n"))
			assert.NotContains(t, logs.String(), "\r")
			var entry map[string]any
			require.NoError(t, json.Unmarshal(logs.Bytes(), &entry))
			assert.Equal(t, "DEBUG", entry["level"])
			assert.Equal(t, safeURL, entry["url"])
			assert.Contains(t, responseErr.Error(), safeURL)
			assert.NotContains(t, responseErr.Error(), "sensitive-")
		})
	}
}

func TestResponseErrorListRunnerScaleSets(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		err  bool
	}{
		{name: "null object", body: "null", err: true},
		{name: "empty object", body: "{}"},
		{name: "empty list", body: `{"count":0,"value":[]}`},
		{name: "null list", body: `{"count":0,"value":null}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := newResponseTestClients(t, httpClientFunc(func(req *http.Request) (*http.Response, error) {
				return newStubResponse(req, http.StatusOK, tc.body), nil
			}))
			got, err := client.ListRunnerScaleSets(t.Context(), 1)
			if tc.err {
				assertResponseError(t, err, http.StatusOK, tc.body)
				assert.Nil(t, got)
			} else {
				require.NoError(t, err)
				assert.Empty(t, got)
			}
		})
	}
}

type responseTestBody struct {
	io.Reader
	readErr  error
	closeErr error
	closes   int
}

func (b *responseTestBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	if err == io.EOF && b.readErr != nil {
		err = b.readErr
	}
	return n, err
}

func (b *responseTestBody) Close() error {
	b.closes++
	return b.closeErr
}

func TestResponseErrorBodyLifecycle(t *testing.T) {
	readErr, closeErr := errors.New("read failure"), errors.New("close failure")
	sendErr, policyErr := errors.New("send failure"), errors.New("policy failure")
	for _, tc := range []struct {
		name      string
		readErr   error
		closeErr  error
		sendErr   error
		policyErr error
		poll      bool
	}{
		{name: "read error", readErr: readErr},
		{name: "close error", closeErr: closeErr},
		{name: "read and close errors", readErr: readErr, closeErr: closeErr},
		{name: "transport response and error", sendErr: sendErr},
		{name: "policy abort retains transport cause and response", sendErr: sendErr, policyErr: policyErr},
		{name: "context abort retains response", policyErr: context.Canceled},
		{name: "poll read error", readErr: readErr, poll: true},
		{name: "poll close error", closeErr: closeErr, poll: true},
		{name: "poll read and close errors", readErr: readErr, closeErr: closeErr, poll: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := "\xef\xbb\xbf{\"token\":\"private-body\"}"
			body := &responseTestBody{Reader: strings.NewReader(raw), readErr: tc.readErr, closeErr: tc.closeErr}
			var attemptCtx context.Context
			client, session := newResponseTestClients(t, httpClientFunc(func(req *http.Request) (*http.Response, error) {
				attemptCtx = req.Context()
				resp := newStubResponse(req, http.StatusOK, "")
				resp.Body = body
				return resp, tc.sendErr
			}))
			if tc.policyErr != nil {
				client.retry.ShouldRetry = func(context.Context, *http.Response, error) (bool, error) {
					return false, tc.policyErr
				}
			}
			var err error
			if tc.poll {
				_, err = session.GetMessage(t.Context(), 0, 1)
			} else {
				_, err = client.GetRunner(t.Context(), 1)
			}
			assertResponseError(t, err, http.StatusOK, raw)
			for _, cause := range []error{tc.readErr, tc.closeErr, tc.sendErr, tc.policyErr} {
				if cause != nil {
					assert.ErrorIs(t, err, cause)
				}
			}
			assert.Equal(t, 1, body.closes)
			assert.NotContains(t, err.Error(), "private-body")
			if tc.poll {
				assert.ErrorIs(t, attemptCtx.Err(), context.Canceled)
			}
		})
	}
}

func TestResponseErrorRateLimitRetries(t *testing.T) {
	readErr, closeErr := errors.New("read failure"), errors.New("close failure")
	for _, tc := range []struct {
		name        string
		status      int
		contentType string
		body        string
		remaining   string
		kind        RateLimitKind
		readErr     error
		closeErr    error
	}{
		{
			name: "JSON with byte order mark", status: http.StatusTooManyRequests,
			contentType: "application/json", body: "\xef\xbb\xbf" + `{"message":"secondary rate limit"}`,
			remaining: "0", kind: RateLimitSecondary,
		},
		{
			name: "plain text", status: http.StatusForbidden,
			contentType: "text/plain", body: "secondary rate limit",
			kind: RateLimitSecondary, closeErr: closeErr,
		},
		{
			name: "partial JSON", status: http.StatusTooManyRequests,
			contentType: "application/json", body: `{"message":"secondary rate limit"}`,
			remaining: "0", kind: RateLimitPrimary, readErr: readErr, closeErr: closeErr,
		},
		{
			name: "partial plain text", status: http.StatusForbidden,
			contentType: "text/plain", body: "secondary rate limit",
			remaining: "0", kind: RateLimitPrimary, readErr: readErr,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var bodies []*responseTestBody
			client, _ := newResponseTestClients(t, httpClientFunc(func(req *http.Request) (*http.Response, error) {
				body := &responseTestBody{
					Reader: strings.NewReader(tc.body), readErr: tc.readErr, closeErr: tc.closeErr,
				}
				bodies = append(bodies, body)
				resp := newStubResponse(req, tc.status, "")
				resp.Body = body
				resp.Header.Set("Content-Type", tc.contentType)
				resp.Header.Set(headerRateLimitRemaining, tc.remaining)
				resp.Header.Set(headerGitHubRequestID, fmt.Sprintf("attempt-%d", len(bodies)))
				return resp, nil
			}))
			var seen []int
			ctx := WithRequestRetry(t.Context(), func(cfg *RetryConfig) {
				cfg.Max = 2
				cfg.OnRateLimit = func(_ context.Context, rl *RateLimitError) (time.Duration, bool) {
					assert.Equal(t, tc.kind, rl.Kind)
					seen = append(seen, rl.Retries)
					return time.Nanosecond, rl.Retries < 1
				}
			})

			_, err := client.GetRunner(ctx, 1)
			resp := assertResponseError(t, err, tc.status, tc.body)
			rl := requireRateLimitError(t, err)
			assert.Equal(t, tc.kind, rl.Kind)
			assert.Equal(t, 1, rl.Retries)
			assert.Equal(t, []int{0, 1}, seen)
			assert.Equal(t, "attempt-2", resp.Header.Get(headerGitHubRequestID))
			for _, cause := range []error{tc.readErr, tc.closeErr} {
				if cause != nil {
					assert.ErrorIs(t, err, cause)
				}
			}
			require.Len(t, bodies, 2)
			for _, body := range bodies {
				assert.Equal(t, 1, body.closes)
			}
			assert.Zero(t, client.retry.Max)
			assert.Nil(t, client.retry.OnRateLimit)
		})
	}
}

func TestResponseErrorNoResponse(t *testing.T) {
	for _, cause := range []error{nil, context.DeadlineExceeded, io.ErrClosedPipe} {
		t.Run(fmt.Sprint(cause), func(t *testing.T) {
			client, _ := newResponseTestClients(t, httpClientFunc(func(*http.Request) (*http.Response, error) {
				return nil, cause
			}))
			_, err := client.GetRunner(t.Context(), 1)
			var responseErr *RequestResponseError
			require.ErrorAs(t, err, &responseErr)
			assert.Nil(t, responseErr.Response)
			if cause != nil {
				assert.ErrorIs(t, err, cause)
			} else {
				assert.ErrorContains(t, err, "nil response")
			}
		})
	}
	retry, err := DefaultShouldRetry(t.Context(), nil, nil)
	assert.False(t, retry)
	assert.ErrorIs(t, err, errMissingResponse)
}

func TestResponseErrorFinalRetry(t *testing.T) {
	var bodies []*responseTestBody
	client, _ := newResponseTestClients(t, httpClientFunc(func(req *http.Request) (*http.Response, error) {
		body := &responseTestBody{Reader: strings.NewReader(fmt.Sprintf("attempt %d", len(bodies)+1))}
		bodies = append(bodies, body)
		resp := newStubResponse(req, http.StatusServiceUnavailable, "")
		resp.Header.Set(headerGitHubRequestID, fmt.Sprintf("request-%d", len(bodies)))
		resp.Body = body
		return resp, nil
	}))
	client.retry = RetryConfig{Max: 1, WaitMax: time.Nanosecond}
	_, err := client.GetRunner(t.Context(), 1)
	resp := assertResponseError(t, err, http.StatusServiceUnavailable, "attempt 2")
	assert.Equal(t, "request-2", resp.Header.Get(headerGitHubRequestID))
	require.Len(t, bodies, 2)
	for _, body := range bodies {
		assert.Equal(t, 1, body.closes)
	}
}

func TestResponseErrorAuthentication(t *testing.T) {
	stages := []struct {
		name   string
		path   string
		status int
		body   string
	}{
		{"installation access token", "/app/installations/1/access_tokens", http.StatusCreated, `{"token":"installation-token"}`},
		{"runner registration token", "/orgs/example/actions/runners/registration-token", http.StatusCreated, `{"token":"registration-token"}`},
		{"admin connection", "/actions/runner-registration", http.StatusOK, fmt.Sprintf(`{"url":"https://actions.example","token":%q}`, unsignedJWT(t, time.Now().Add(time.Hour)))},
	}
	for target, stage := range stages {
		type authResponseCase struct {
			name    string
			status  int
			body    string
			nilBody bool
			cause   error
		}
		cases := []authResponseCase{
			{name: "empty body", status: stage.status, cause: io.EOF},
			{name: "absent body", status: stage.status, nilBody: true, cause: io.EOF},
			{name: "truncated JSON", status: stage.status, body: "{", cause: io.ErrUnexpectedEOF},
			{name: "null body", status: stage.status, body: "null"},
			{name: "missing fields", status: stage.status, body: "{}"},
			{name: "missing token", status: stage.status, body: `{"url":"https://actions.example","token":""}`},
			{name: "unauthorized", status: http.StatusUnauthorized, body: `{"message":"bad credentials"}`, cause: UnauthorizedError},
			{name: "server error", status: http.StatusBadGateway, body: "<html>bad gateway</html>"},
			{name: "unexpected no content", status: http.StatusNoContent},
		}
		if stage.name == "admin connection" {
			cases = append(cases,
				authResponseCase{name: "missing url", status: stage.status, body: `{"token":"private-token"}`},
				authResponseCase{name: "invalid JWT", status: stage.status, body: `{"url":"https://actions.example","token":"private-token"}`},
				authResponseCase{name: "JWT missing expiration", status: stage.status, body: `{"url":"https://actions.example","token":"eyJhbGciOiJub25lIn0.e30."}`},
			)
		}
		for _, tc := range cases {
			t.Run(stage.name+"/"+tc.name, func(t *testing.T) {
				calls := 0
				client, _ := newResponseTestClients(t, httpClientFunc(func(req *http.Request) (*http.Response, error) {
					require.LessOrEqual(t, calls, target, "must not continue with invalid credentials")
					current := calls
					calls++
					assert.Equal(t, stages[current].path, req.URL.Path)
					if current < target {
						return newStubResponse(req, stages[current].status, stages[current].body), nil
					}
					resp := newStubResponse(req, tc.status, tc.body)
					resp.Header.Set(headerGitHubRequestID, "auth-request-id")
					if tc.nilBody {
						resp.Body = nil
					}
					return resp, nil
				}))
				client.actionsServiceAdminToken = actionsServiceAdminToken{}
				client.creds = actionsAuth{
					installationID: 1,
					jwtProvider: JWTProviderFunc(func(context.Context) (string, error) {
						return "test-jwt", nil
					}),
				}
				_, err := client.GetRunner(t.Context(), 1)
				resp := assertResponseError(t, err, tc.status, tc.body)
				assert.Equal(t, target+1, calls)
				assert.Equal(t, stage.path, resp.Request.URL.Path)
				assert.Equal(t, "auth-request-id", resp.Header.Get(headerGitHubRequestID))
				if tc.cause != nil {
					assert.ErrorIs(t, err, tc.cause)
				}
				assert.NotContains(t, err.Error(), "private-token")
				assert.True(t, client.actionsServiceAdminToken.expiresAt.IsZero())
			})
		}
	}
}

func TestResponseErrorAuthenticationURLLogs(t *testing.T) {
	for _, format := range []string{"text", "json"} {
		t.Run(format, func(t *testing.T) {
			jwt := unsignedJWT(t, time.Now().Add(time.Hour))
			client, _ := newResponseTestClients(t, httpClientFunc(func(req *http.Request) (*http.Response, error) {
				switch {
				case strings.HasSuffix(req.URL.Path, "/access_tokens"):
					return newStubResponse(req, http.StatusCreated, `{"token":"installation-token"}`), nil
				case strings.HasSuffix(req.URL.Path, "/registration-token"):
					return newStubResponse(req, http.StatusCreated, `{"token":"registration-token"}`), nil
				default:
					require.Equal(t, "/actions/runner-registration", req.URL.Path)
					return newStubResponse(req, http.StatusOK, fmt.Sprintf(`{"url":"https://actions.example","token":%q}`, jwt)), nil
				}
			}))
			const organization = "example\r\nlevel=ERROR msg=\"forged\""
			client.config.organization = organization
			client.config.configURL.Path = "/" + organization
			client.config.configURL.User = url.UserPassword("sensitive-user", "sensitive-password")
			client.config.configURL.RawQuery = "token=sensitive-query"
			client.config.configURL.Fragment = "sensitive-fragment"
			client.actionsServiceAdminToken = actionsServiceAdminToken{}
			client.creds = actionsAuth{
				installationID: 1,
				jwtProvider: JWTProviderFunc(func(context.Context) (string, error) {
					return "test-jwt", nil
				}),
			}
			var logs bytes.Buffer
			if format == "text" {
				client.logger = slog.New(slog.NewTextHandler(&logs, nil))
			} else {
				client.logger = slog.New(slog.NewJSONHandler(&logs, nil))
			}

			_, err := client.updateTokenIfNeeded(t.Context())
			require.NoError(t, err)
			assert.Equal(t, 4, strings.Count(logs.String(), "\n"))
			assert.NotContains(t, logs.String(), "\r")
			assert.NotContains(t, logs.String(), "sensitive-")
			assert.Contains(t, logs.String(), "%0D%0Alevel=ERROR")
			for _, key := range []string{"githubConfigUrl", "accessTokenURL", "registrationTokenURL", "registrationURL"} {
				assert.Contains(t, logs.String(), key)
			}
			if format == "json" {
				for line := range strings.SplitSeq(strings.TrimSpace(logs.String()), "\n") {
					var entry map[string]any
					require.NoError(t, json.Unmarshal([]byte(line), &entry))
					assert.Equal(t, "INFO", entry["level"])
				}
			}
		})
	}
}

func TestResponseErrorFinalAuthRetry(t *testing.T) {
	attempts := 0
	client, _ := newResponseTestClients(t, httpClientFunc(func(req *http.Request) (*http.Response, error) {
		if strings.HasSuffix(req.URL.Path, "/registration-token") {
			return newStubResponse(req, http.StatusCreated, `{"token":"registration-token"}`), nil
		}
		require.Equal(t, "/actions/runner-registration", req.URL.Path)
		attempts++
		status := http.StatusCreated
		switch attempts {
		case 1:
			status = http.StatusUnauthorized
		case 2:
			status = http.StatusForbidden
		}
		resp := newStubResponse(req, status, "")
		resp.Header.Set(headerGitHubRequestID, fmt.Sprintf("auth-%d", attempts))
		return resp, nil
	}))
	client.actionsServiceAdminToken = actionsServiceAdminToken{}
	client.retry = RetryConfig{Max: 2, WaitMax: time.Nanosecond}
	_, err := client.GetRunner(t.Context(), 1)
	resp := assertResponseError(t, err, http.StatusCreated, "")
	assert.ErrorIs(t, err, io.EOF)
	assert.NotErrorIs(t, err, UnauthorizedError)
	assert.Equal(t, "auth-3", resp.Header.Get(headerGitHubRequestID))
	assert.Equal(t, 3, attempts)
}

func TestResponseErrorFinalSessionResponse(t *testing.T) {
	for _, endpoint := range []struct {
		name string
		call func(*MessageSessionClient) error
	}{
		{"get message", func(s *MessageSessionClient) error {
			_, err := s.GetMessage(t.Context(), 0, 1)
			return err
		}},
		{"delete message", func(s *MessageSessionClient) error {
			return s.DeleteMessage(t.Context(), 1)
		}},
		{"acquire jobs", func(s *MessageSessionClient) error {
			_, err := s.AcquireJobs(t.Context(), []int64{1})
			return err
		}},
	} {
		for _, finalStatus := range []int{http.StatusUnauthorized, http.StatusServiceUnavailable} {
			t.Run(fmt.Sprintf("%s/%d", endpoint.name, finalStatus), func(t *testing.T) {
				requests, refreshes := 0, 0
				var refreshed RunnerScaleSetSession
				client, session := newResponseTestClients(t, httpClientFunc(func(req *http.Request) (*http.Response, error) {
					if req.Method == http.MethodPatch {
						refreshes++
						body, err := json.Marshal(refreshed)
						require.NoError(t, err)
						return newStubResponse(req, http.StatusOK, string(body)), nil
					}
					requests++
					if requests == 1 {
						return newStubResponse(req, http.StatusUnauthorized, "initial 401"), nil
					}
					resp := newStubResponse(req, finalStatus, "terminal response")
					resp.Header.Set(headerGitHubRequestID, "terminal-id")
					return resp, nil
				}))
				refreshed = session.Session()
				refreshed.MessageQueueAccessToken = "refreshed-token"
				err := endpoint.call(session)
				resp := assertResponseError(t, err, finalStatus, "terminal response")
				assert.Equal(t, "terminal-id", resp.Header.Get(headerGitHubRequestID))
				assert.Equal(t, 2, requests)
				assert.Equal(t, 1, refreshes)
				assert.Equal(t, 0, client.retry.Max)
				if finalStatus == http.StatusUnauthorized {
					assert.ErrorIs(t, err, MessageQueueTokenExpiredError)
					assert.ErrorIs(t, err, UnauthorizedError)
				} else {
					assert.NotErrorIs(t, err, MessageQueueTokenExpiredError)
				}
			})
		}
	}

	t.Run("failed refresh retains refresh response", func(t *testing.T) {
		_, session := newResponseTestClients(t, httpClientFunc(func(req *http.Request) (*http.Response, error) {
			if req.Method == http.MethodPatch {
				return newStubResponse(req, http.StatusOK, ""), nil
			}
			return newStubResponse(req, http.StatusUnauthorized, "initial 401"), nil
		}))
		original := session.Session()
		_, err := session.GetMessage(t.Context(), 0, 1)
		resp := assertResponseError(t, err, http.StatusOK, "")
		assert.ErrorIs(t, err, io.EOF)
		assert.Equal(t, http.MethodPatch, resp.Request.Method)
		assert.Equal(t, original, session.Session())
	})
}

func TestResponseErrorOptionalBodiesAndStatuses(t *testing.T) {
	for _, endpoint := range []struct {
		name   string
		status int
		call   func(*Client, *MessageSessionClient) error
	}{
		{"delete scale set", http.StatusNoContent, func(c *Client, _ *MessageSessionClient) error {
			return c.DeleteRunnerScaleSet(t.Context(), 1)
		}},
		{"remove runner", http.StatusNoContent, func(c *Client, _ *MessageSessionClient) error {
			return c.RemoveRunner(t.Context(), 1)
		}},
		{"close session", http.StatusNoContent, func(_ *Client, s *MessageSessionClient) error {
			return s.Close(t.Context())
		}},
		{"delete message", http.StatusNoContent, func(_ *Client, s *MessageSessionClient) error {
			return s.DeleteMessage(t.Context(), 1)
		}},
		{"empty poll", http.StatusAccepted, func(_ *Client, s *MessageSessionClient) error {
			message, err := s.GetMessage(t.Context(), 0, 1)
			assert.Nil(t, message)
			return err
		}},
	} {
		for _, nilBody := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/nil=%t", endpoint.name, nilBody), func(t *testing.T) {
				client, session := newResponseTestClients(t, httpClientFunc(func(req *http.Request) (*http.Response, error) {
					resp := newStubResponse(req, endpoint.status, "")
					if nilBody {
						resp.Body = nil
					}
					return resp, nil
				}))
				require.NoError(t, endpoint.call(client, session))
			})
		}
		t.Run(endpoint.name+"/unexpected success status", func(t *testing.T) {
			client, session := newResponseTestClients(t, httpClientFunc(func(req *http.Request) (*http.Response, error) {
				return newStubResponse(req, http.StatusCreated, ""), nil
			}))
			assertResponseError(t, endpoint.call(client, session), http.StatusCreated, "")
		})
	}
}

func TestResponseErrorInvalidLists(t *testing.T) {
	for _, endpoint := range []struct {
		name string
		call func(*Client) error
	}{
		{"runner", func(c *Client) error {
			_, err := c.GetRunnerByName(t.Context(), "test")
			return err
		}},
		{"runner group", func(c *Client) error {
			_, err := c.GetRunnerGroupByName(t.Context(), "test")
			return err
		}},
		{"scale set", func(c *Client) error {
			_, err := c.GetRunnerScaleSet(t.Context(), 1, "test")
			return err
		}},
	} {
		t.Run(endpoint.name, func(t *testing.T) {
			const body = `{"count":1,"value":[]}`
			client, _ := newResponseTestClients(t, httpClientFunc(func(req *http.Request) (*http.Response, error) {
				return newStubResponse(req, http.StatusOK, body), nil
			}))
			assertResponseError(t, endpoint.call(client), http.StatusOK, body)
		})
	}

	t.Run("null runner list", func(t *testing.T) {
		client, _ := newResponseTestClients(t, httpClientFunc(func(req *http.Request) (*http.Response, error) {
			return newStubResponse(req, http.StatusOK, "null"), nil
		}))
		_, err := client.GetRunnerByName(t.Context(), "test")
		assertResponseError(t, err, http.StatusOK, "null")
	})
}

// A required object decodes from null without error, so these endpoints used
// to report success without a value. Lookups such as GetRunnerScaleSetByID
// keep treating null as not found.
func TestResponseErrorNullObject(t *testing.T) {
	for _, endpoint := range []struct {
		name string
		call func(*Client, *MessageSessionClient) error
	}{
		{"create scale set", func(c *Client, _ *MessageSessionClient) error {
			_, err := c.CreateRunnerScaleSet(t.Context(), &RunnerScaleSet{Name: "test"})
			return err
		}},
		{"update scale set", func(c *Client, _ *MessageSessionClient) error {
			_, err := c.UpdateRunnerScaleSet(t.Context(), 1, &RunnerScaleSet{Name: "test"})
			return err
		}},
		{"jit config", func(c *Client, _ *MessageSessionClient) error {
			_, err := c.GenerateJitRunnerConfig(t.Context(), &RunnerScaleSetJitRunnerSetting{}, 1)
			return err
		}},
		{"create session", func(c *Client, _ *MessageSessionClient) error {
			_, err := c.MessageSessionClient(t.Context(), 1, "test")
			return err
		}},
		{"refresh session", func(_ *Client, s *MessageSessionClient) error {
			return s.refreshMessageSession(t.Context(), s.Session())
		}},
	} {
		t.Run(endpoint.name, func(t *testing.T) {
			client, session := newResponseTestClients(t, httpClientFunc(func(req *http.Request) (*http.Response, error) {
				return newStubResponse(req, http.StatusOK, "null"), nil
			}))
			original := session.Session()
			assertResponseError(t, endpoint.call(client, session), http.StatusOK, "null")
			assert.Equal(t, original, session.Session())
		})
	}
}

func TestResponseErrorNullLookups(t *testing.T) {
	for _, endpoint := range []struct {
		name string
		call func(*Client) error
	}{
		{"scale set by ID", func(c *Client) error {
			result, err := c.GetRunnerScaleSetByID(t.Context(), 1)
			assert.Nil(t, result)
			return err
		}},
		{"runner by ID", func(c *Client) error {
			result, err := c.GetRunner(t.Context(), 1)
			assert.Nil(t, result)
			return err
		}},
	} {
		t.Run(endpoint.name, func(t *testing.T) {
			client, _ := newResponseTestClients(t, httpClientFunc(func(req *http.Request) (*http.Response, error) {
				return newStubResponse(req, http.StatusOK, "null"), nil
			}))
			require.NoError(t, endpoint.call(client))
		})
	}
}

func TestResponseErrorMissingRequestMetadata(t *testing.T) {
	cause := errors.New("original error")
	t.Run("missing response request uses the sent request", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)
		resp := &http.Response{StatusCode: http.StatusBadGateway}
		got := assertResponseError(t, newRequestResponseError(req, resp, cause), http.StatusBadGateway, "")
		assert.Same(t, req, got.Request)
		assert.Nil(t, resp.Request)
	})
	t.Run("no request metadata", func(t *testing.T) {
		err := newRequestResponseError(nil, &http.Response{StatusCode: http.StatusBadGateway}, cause)
		assertResponseError(t, err, http.StatusBadGateway, "")
		assert.ErrorIs(t, err, cause)
	})
}
