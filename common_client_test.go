package scaleset

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/actions/scaleset/internal/testserver"
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
	}
	b, err = json.Marshal(wantInfo)
	require.NoError(t, err, "failed to marshal expected user agent after SetSystemInfo")
	want = string(b)

	assert.Equal(t, want, got)
}
