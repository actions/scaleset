package scaleset

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/actions/scaleset/internal/testserver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http/httpproxy"
)

// httpClientFunc adapts a function to the HTTPClient interface, so a test can
// stand in for a transport without running a server.
type httpClientFunc func(req *http.Request) (*http.Response, error)

func (f httpClientFunc) Do(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newStubResponse(req *http.Request, statusCode int, body string) *http.Response {
	return &http.Response{
		Status:     http.StatusText(statusCode),
		StatusCode: statusCode,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}

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
	WithHTTPClient(NewHTTPClient(HTTPClientConfig{Proxy: proxyFunc}))(&opts)

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

func TestWithLogger(t *testing.T) {
	newJSONHandler := func() slog.Handler {
		return slog.NewJSONHandler(
			io.Discard,
			&slog.HandlerOptions{
				AddSource: true,
				Level:     slog.LevelError,
			},
		)
	}
	t.Run("WithLogger(nil) sets a discard logger on raw httpClientOption", func(t *testing.T) {
		opts := httpClientOption{}
		WithLogger(nil)(&opts)
		require.NotNil(t, opts.logger, "WithLogger(nil) should set a discard logger, not leave it nil")
		assert.Equal(t, slog.DiscardHandler, opts.logger.Handler(), "WithLogger(nil) should set a discard logger handler")
	})

	t.Run("WithLogger(customLogger) assigns the provided logger", func(t *testing.T) {
		handler := newJSONHandler()
		customLogger := slog.New(handler)
		opts := httpClientOption{}
		WithLogger(customLogger)(&opts)
		require.Equal(t, customLogger, opts.logger, "WithLogger should assign the provided logger")
		assert.Equal(t, handler, opts.logger.Handler(), "WithLogger should set the provided logger handler")
	})

	t.Run("WithLogger(nil) leaves the client with a discard logger", func(t *testing.T) {
		opts := httpClientOption{}
		WithLogger(nil)(&opts)
		opts.defaults()
		client := newCommonClient(testSystemInfo, opts)
		require.NotNil(t, client.logger)
		assert.Equal(t, slog.DiscardHandler, client.logger.Handler())
	})

	t.Run("WithLogger(customLogger) propagates the logger to the client", func(t *testing.T) {
		handler := newJSONHandler()
		customLogger := slog.New(handler)
		opts := httpClientOption{}
		WithLogger(customLogger)(&opts)
		opts.defaults()
		client := newCommonClient(testSystemInfo, opts)
		assert.Same(t, customLogger, client.logger)
		assert.Equal(t, handler, client.logger.Handler())
	})
}

// TestWithHTTPClient verifies that a caller-supplied HTTP client is the one
// used, and that the SDK layers its own retries above it.
func TestWithHTTPClient(t *testing.T) {
	t.Run("uses the supplied client", func(t *testing.T) {
		var calls int
		stub := httpClientFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			return newStubResponse(req, http.StatusOK, `{"result":"success"}`), nil
		})

		opts := defaultHTTPClientOption()
		WithHTTPClient(stub)(&opts)
		client := newCommonClient(testSystemInfo, opts)

		req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
		require.NoError(t, err)

		resp, err := client.do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 1, calls)
	})

	t.Run("retries the supplied client and returns the final response", func(t *testing.T) {
		var calls int
		stub := httpClientFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return newStubResponse(req, http.StatusServiceUnavailable, ""), nil
			}
			return newStubResponse(req, http.StatusOK, `{"result":"success"}`), nil
		})

		opts := defaultHTTPClientOption()
		WithHTTPClient(stub)(&opts)
		WithRetry(RetryConfig{Max: 3, WaitMax: time.Millisecond})(&opts)
		client := newCommonClient(testSystemInfo, opts)

		req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
		require.NoError(t, err)

		resp, err := client.do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, calls)
	})

	t.Run("returns the last response once retries are exhausted", func(t *testing.T) {
		var calls int
		stub := httpClientFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			return newStubResponse(req, http.StatusServiceUnavailable, `{"message":"unavailable"}`), nil
		})

		opts := defaultHTTPClientOption()
		WithHTTPClient(stub)(&opts)
		WithRetry(RetryConfig{Max: 1, WaitMax: time.Millisecond})(&opts)
		client := newCommonClient(testSystemInfo, opts)

		req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
		require.NoError(t, err)

		// The response is handed back rather than discarded, so callers can
		// build an error that carries the status, headers, and body.
		resp, err := client.do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
		assert.Equal(t, 2, calls)
	})

	t.Run("a zero retry config disables retries", func(t *testing.T) {
		var calls int
		stub := httpClientFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			return newStubResponse(req, http.StatusServiceUnavailable, ""), nil
		})

		opts := defaultHTTPClientOption()
		WithHTTPClient(stub)(&opts)
		WithRetry(RetryConfig{})(&opts)
		client := newCommonClient(testSystemInfo, opts)

		req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
		require.NoError(t, err)

		_, err = client.do(req)
		require.NoError(t, err)
		assert.Equal(t, 1, calls)
	})
}

func TestNewHTTPClient(t *testing.T) {
	t.Run("applies client certificates", func(t *testing.T) {
		cert, err := tls.LoadX509KeyPair("testdata/leaf.crt", "testdata/leaf.key")
		require.NoError(t, err)

		client := NewHTTPClient(HTTPClientConfig{Certificates: []tls.Certificate{cert, cert}})

		tlsConfig, ok := tlsConfigFromClient(client)
		require.True(t, ok)
		assert.Len(t, tlsConfig.Certificates, 2)
	})

	t.Run("does not alias the caller's certificate slice", func(t *testing.T) {
		cert, err := tls.LoadX509KeyPair("testdata/leaf.crt", "testdata/leaf.key")
		require.NoError(t, err)

		certs := make([]tls.Certificate, 1, 4)
		certs[0] = cert
		client := NewHTTPClient(HTTPClientConfig{Certificates: certs})

		tlsConfig, ok := tlsConfigFromClient(client)
		require.True(t, ok)
		tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
		assert.Len(t, certs, 1)
		assert.Empty(t, certs[:cap(certs)][1].Certificate)
	})

	t.Run("applies TLS and timeout settings", func(t *testing.T) {
		pool := x509.NewCertPool()
		client := NewHTTPClient(HTTPClientConfig{
			RootCAs:            pool,
			InsecureSkipVerify: true,
			Timeout:            time.Minute,
		})

		assert.Equal(t, time.Minute, client.Timeout)
		tlsConfig, ok := tlsConfigFromClient(client)
		require.True(t, ok)
		assert.Same(t, pool, tlsConfig.RootCAs)
		assert.True(t, tlsConfig.InsecureSkipVerify)
	})

	t.Run("defaults the timeout", func(t *testing.T) {
		assert.Equal(t, 5*time.Minute, DefaultTimeout)
		assert.Equal(t, DefaultTimeout, NewHTTPClient(HTTPClientConfig{}).Timeout)
	})

	t.Run("keeps the previous transport timeouts", func(t *testing.T) {
		transport := DefaultTransport()

		assert.Equal(t, 30*time.Second, defaultDialTimeout)
		assert.Equal(t, 30*time.Second, defaultDialKeepAlive)
		assert.Equal(t, 90*time.Second, transport.IdleConnTimeout)
		assert.Equal(t, 10*time.Second, transport.TLSHandshakeTimeout)
		assert.Equal(t, time.Second, transport.ExpectContinueTimeout)
		assert.Equal(t, 100, transport.MaxIdleConns)
		assert.Equal(t, runtime.GOMAXPROCS(0)+1, transport.MaxIdleConnsPerHost)
	})

	t.Run("returns an independent transport each time", func(t *testing.T) {
		first := NewHTTPClient(HTTPClientConfig{})
		second := NewHTTPClient(HTTPClientConfig{})
		assert.NotSame(t, first, second)
		assert.NotSame(t, first.Transport, second.Transport)

		firstTLS, ok := tlsConfigFromClient(first)
		require.True(t, ok)
		secondTLS, ok := tlsConfigFromClient(second)
		require.True(t, ok)
		assert.NotSame(t, firstTLS, secondTLS)
	})
}
