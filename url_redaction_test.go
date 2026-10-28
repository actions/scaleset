package scaleset

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
			defer resp.Body.Close()
			responseErr := newRequestResponseError(req, resp, errors.New("unexpected status"))
			require.Error(t, responseErr)
			assert.Equal(t, rawURL, resp.Request.URL.String())
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

	t.Run("no response", func(t *testing.T) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, rawURL, nil)
		require.NoError(t, err)
		cause := errors.New("transport failed")
		responseErr := newRequestResponseError(req, nil, cause)
		assert.ErrorIs(t, responseErr, cause)
		assert.Contains(t, responseErr.Error(), safeURL)
		assert.NotContains(t, responseErr.Error(), "sensitive-")
		assert.Equal(t, rawURL, req.URL.String())
	})
}

func TestResponseErrorAuthenticationURLLogs(t *testing.T) {
	for _, format := range []string{"text", "json"} {
		t.Run(format, func(t *testing.T) {
			jwt := unsignedJWT(t, time.Now().Add(time.Hour))
			client, err := NewClientWithPersonalAccessToken(
				NewClientWithPersonalAccessTokenConfig{
					GitHubConfigURL:     "https://github.com/example",
					PersonalAccessToken: "test-token",
				},
				WithHTTPClient(httpClientFunc(func(req *http.Request) (*http.Response, error) {
					switch {
					case strings.HasSuffix(req.URL.Path, "/access_tokens"):
						return newStubResponse(req, http.StatusCreated, `{"token":"installation-token"}`), nil
					case strings.HasSuffix(req.URL.Path, "/registration-token"):
						return newStubResponse(req, http.StatusCreated, `{"token":"registration-token"}`), nil
					default:
						require.Equal(t, "/actions/runner-registration", req.URL.Path)
						return newStubResponse(req, http.StatusOK, fmt.Sprintf(`{"url":"https://actions.example","token":%q}`, jwt)), nil
					}
				})),
				WithRetry(RetryConfig{}),
			)
			require.NoError(t, err)
			const organization = "example\r\nlevel=ERROR msg=\"forged\""
			client.config.organization = organization
			client.config.configURL.Path = "/" + organization
			client.config.configURL.User = url.UserPassword("sensitive-user", "sensitive-password")
			client.config.configURL.RawQuery = "token=sensitive-query"
			client.config.configURL.Fragment = "sensitive-fragment"
			originalURL := client.config.configURL.String()
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

			_, err = client.updateTokenIfNeeded(t.Context())
			require.NoError(t, err)
			assert.Equal(t, originalURL, client.config.configURL.String())
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
