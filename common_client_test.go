package scaleset

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/actions/scaleset/internal/testserver"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http/httpproxy"
)

func defaultHTTPClientOption() httpClientOption {
	var opt httpClientOption
	opt.defaults()
	return opt
}

func TestClient_Do(t *testing.T) {
	t.Run("trims byte order mark from response if present", func(t *testing.T) {
		t.Run("when there is no body", func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			}))
			defer server.Close()

			client := newCommonClient(
				testSystemInfo,
				defaultHTTPClientOption(),
			)

			req, err := http.NewRequest("GET", server.URL, nil)
			require.NoError(t, err)

			resp, err := client.do(req)
			require.NoError(t, err)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Empty(t, string(body))
		})

		responses := []string{
			"\xef\xbb\xbf{\"foo\":\"bar\"}",
			"{\"foo\":\"bar\"}",
		}

		for _, response := range responses {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(response))
			}))
			defer server.Close()

			client := newCommonClient(
				testSystemInfo,
				defaultHTTPClientOption(),
			)

			req, err := http.NewRequest("GET", server.URL, nil)
			require.NoError(t, err)

			resp, err := client.do(req)
			require.NoError(t, err)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, "{\"foo\":\"bar\"}", string(body))
		}
	})
}

func TestClientProxy(t *testing.T) {
	serverCalled := false

	proxy := testserver.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverCalled = true
	}))

	proxyConfig := &httpproxy.Config{
		HTTPProxy: proxy.URL,
	}
	proxyFunc := func(req *http.Request) (*url.URL, error) {
		return proxyConfig.ProxyFunc()(req.URL)
	}

	opts := defaultHTTPClientOption()
	WithProxy(proxyFunc)(&opts)

	client := newCommonClient(
		testSystemInfo,
		opts,
	)

	req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
	require.NoError(t, err)

	_, err = client.do(req)
	require.NoError(t, err)

	assert.True(t, serverCalled)
}

func TestUserAgent(t *testing.T) {
	version, sha := detectModuleVersionAndCommit()
	userAgentInfo := SystemInfo{
		System:     "actions-runner-controller",
		Version:    "0.1.0",
		CommitSHA:  "1234567890abcdef",
		ScaleSetID: 10,
		Subsystem:  "test",
	}

	client := newCommonClient(
		testSystemInfo,
		defaultHTTPClientOption(),
	)

	got := client.userAgent
	wantInfo := userAgent{
		SystemInfo:     testSystemInfo,
		BuildCommitSHA: sha,
		BuildVersion:   version,
		Kind:           "scaleset",
	}
	b, err := json.Marshal(wantInfo)
	require.NoError(t, err, "failed to marshal expected user agent")
	want := string(b)

	assert.Equal(t, want, got)

	client.setSystemInfo(SystemInfo{
		System:     "actions-runner-controller",
		Version:    "0.1.0",
		CommitSHA:  "1234567890abcdef",
		ScaleSetID: 10,
		Subsystem:  "test",
	})

	got = client.userAgent
	wantInfo = userAgent{
		SystemInfo:     userAgentInfo,
		BuildCommitSHA: sha,
		BuildVersion:   version,
		Kind:           "scaleset",
	}
	b, err = json.Marshal(wantInfo)
	require.NoError(t, err, "failed to marshal expected user agent after SetSystemInfo")
	want = string(b)

	assert.Equal(t, want, got)
}

// TestWithRetryableHTTPClient verifies that a custom retryable HTTP client
// provided via WithRetryableHTTPClient is actually used instead of the built-in one
func TestWithRetryableHTTPClient(t *testing.T) {
	t.Run("uses custom retryable client instead of built-in", func(t *testing.T) {
		attemptCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attemptCount++
			if attemptCount == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"result": "success"}`))
		}))
		defer server.Close()

		// Create a custom retryable HTTP client with specific retry configuration
		customRetryClient := retryablehttp.NewClient()
		customRetryClient.RetryMax = 3
		customRetryClient.RetryWaitMax = 10 * time.Millisecond

		// Create options with the custom retryable client
		opts := defaultHTTPClientOption()
		WithRetryableHTTPClint(customRetryClient)(&opts)

		// Verify that the custom client is set in options
		assert.NotNil(t, opts.retryableHTTPClient)
		assert.Equal(t, customRetryClient, opts.retryableHTTPClient)

		// Create the common client with custom retryable client
		client := newCommonClient(testSystemInfo, opts)

		// Make a request that will trigger a retry
		req, err := http.NewRequest("GET", server.URL, nil)
		require.NoError(t, err)

		resp, err := client.do(req)
		require.NoError(t, err)

		// Should succeed after retry
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, attemptCount)

		// Verify that the client used is the custom one by checking newRetryableHTTPClient
		retrievedRetryClient, err := client.newRetryableHTTPClient()
		require.NoError(t, err)
		assert.Equal(t, customRetryClient, retrievedRetryClient, "should return the custom retryable client")
	})

	t.Run("respects custom client's retry configuration over built-in defaults", func(t *testing.T) {
		attemptCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attemptCount++
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()

		// Create custom client with limited retries
		customRetryClient := retryablehttp.NewClient()
		customRetryClient.RetryMax = 1 // Only 1 retry (2 total attempts)
		customRetryClient.RetryWaitMax = 5 * time.Millisecond

		opts := defaultHTTPClientOption()
		WithRetryableHTTPClint(customRetryClient)(&opts)

		client := newCommonClient(testSystemInfo, opts)

		req, err := http.NewRequest("GET", server.URL, nil)
		require.NoError(t, err)

		resp, err := client.do(req)
		// When all retries are exhausted with a retryable error, the client gives up
		// and an error is returned
		if err != nil {
			// Expected: request failed after exhausting retries
			assert.Contains(t, err.Error(), "giving up after 2 attempt(s)")
		} else {
			// Or the final response is returned
			assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
		}
		// Should have tried 1 initial + 1 retry = 2 times total
		assert.Equal(t, 2, attemptCount)
	})
}
