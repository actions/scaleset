package scaleset

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRetryableHTTPClientFactory(t *testing.T) {
	opts := defaultHTTPClientOption()
	WithRetryableHTTPClientFactory(func() *retryablehttp.Client {
		client := retryablehttp.NewClient()
		client.RetryMax = 7
		client.RetryWaitMax = time.Second
		return client
	})(&opts)
	first, err := opts.newRetryableHTTPClient()
	require.NoError(t, err)
	second, err := opts.newRetryableHTTPClient()
	require.NoError(t, err)
	assert.NotSame(t, first, second)
	assert.NotSame(t, first.HTTPClient, second.HTTPClient)
	assert.NotSame(t, first.HTTPClient.Transport, second.HTTPClient.Transport)
	assert.Equal(t, 7, second.RetryMax)
	assert.Equal(t, time.Second, second.RetryWaitMax)
	assert.Equal(t, opts.timeout, second.HTTPClient.Timeout)
	assert.Same(t, opts.logger, second.Logger)
	second.RetryMax = 1
	assert.Equal(t, 7, first.RetryMax)
}

func TestRetryableHTTPClientFactoryRejectsNil(t *testing.T) {
	for _, client := range []*retryablehttp.Client{nil, {}} {
		opts := defaultHTTPClientOption()
		WithRetryableHTTPClientFactory(func() *retryablehttp.Client { return client })(&opts)
		_, err := opts.newRetryableHTTPClient()
		require.ErrorContains(t, err, "factory returned a nil client")
	}
}

func TestRetryableHTTPClientOptionPrecedence(t *testing.T) {
	legacy := retryablehttp.NewClient()
	factory := WithRetryableHTTPClientFactory(retryablehttp.NewClient)
	for _, factoryLast := range []bool{false, true} {
		opts := defaultHTTPClientOption()
		if factoryLast {
			WithRetryableHTTPClint(legacy)(&opts)
			factory(&opts)
		} else {
			factory(&opts)
			WithRetryableHTTPClint(legacy)(&opts)
		}
		client, err := opts.newRetryableHTTPClient()
		require.NoError(t, err)
		if factoryLast {
			assert.NotSame(t, legacy, client)
		} else {
			assert.Same(t, legacy, client)
		}
	}
}

type factoryRoundTripper func(*http.Request) (*http.Response, error)

func (f factoryRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestCustomClientRefreshWithInflightJIT(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const inflight = 16
		entered := make(chan struct{}, inflight)
		release := make(chan struct{})
		var jitCount, adminCount, clientCount atomic.Int64
		factory := func() *retryablehttp.Client {
			clientCount.Add(1)
			client := retryablehttp.NewClient()
			client.HTTPClient.Transport.(*http.Transport).RegisterProtocol("https", factoryRoundTripper(func(req *http.Request) (*http.Response, error) {
				code, body := http.StatusOK, ""
				switch {
				case strings.HasSuffix(req.URL.Path, "/registration-token"):
					code = http.StatusCreated
					body = `{"token":"registration-token"}`
				case req.URL.Path == "/actions/runner-registration":
					expires := time.Now().Add(time.Hour)
					if adminCount.Add(1) == 1 {
						expires = time.Now().Add(61 * time.Second)
					}
					claims := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, expires.Unix())))
					token := "eyJhbGciOiJub25lIn0." + claims + "."
					body = fmt.Sprintf(`{"url":"https://actions.example/","token":%q}`, token)
				case strings.HasSuffix(req.URL.Path, "/generatejitconfig"):
					id := jitCount.Add(1)
					if id > 1 && id <= inflight+1 {
						entered <- struct{}{}
						<-release
					}
					body = fmt.Sprintf(`{"runner":{"id":%d},"encodedJITConfig":"config"}`, id)
				default:
					return nil, fmt.Errorf("unexpected request: %s %s", req.Method, req.URL)
				}
				return &http.Response{
					StatusCode: code, Header: make(http.Header), Request: req,
					Body: io.NopCloser(strings.NewReader(body)),
				}, nil
			}))
			return client
		}
		client, err := NewClientWithPersonalAccessToken(NewClientWithPersonalAccessTokenConfig{
			GitHubConfigURL: "https://github.com/example-org", PersonalAccessToken: "example-token",
		}, WithRetryableHTTPClientFactory(factory))
		require.NoError(t, err)
		generate := func(ctx context.Context, name string) error {
			_, err := client.GenerateJitRunnerConfig(ctx, &RunnerScaleSetJitRunnerSetting{Name: name, WorkFolder: "_work"}, 1)
			return err
		}
		require.NoError(t, generate(t.Context(), "warm"))
		var workers sync.WaitGroup
		errs := make([]error, inflight)
		for i := range inflight {
			workers.Go(func() { errs[i] = generate(t.Context(), fmt.Sprintf("inflight-%d", i)) })
		}
		for range inflight {
			<-entered
		}
		time.Sleep(2 * time.Second)
		close(release)
		refreshErr := generate(t.Context(), "refresh")
		workers.Wait()
		require.NoError(t, refreshErr)
		for _, err := range errs {
			assert.NoError(t, err)
		}
		assert.Equal(t, int64(2), adminCount.Load())
		assert.GreaterOrEqual(t, clientCount.Load(), int64(3))
	})
}

func TestRetryableHTTPClientFactoryIsolatesMessageSession(t *testing.T) {
	server := newActionsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Write([]byte(`{"sessionId":"00000000-0000-0000-0000-000000000001"}`))
	}))
	client, err := newClient(testSystemInfo, server.configURLForOrg("example-org"), actionsAuth{token: "token"},
		WithRetryableHTTPClientFactory(retryablehttp.NewClient))
	require.NoError(t, err)
	parent := client.httpClient.Transport.(*retryablehttp.RoundTripper).Client
	parentTransport := parent.HTTPClient.Transport.(*http.Transport)
	logger := slog.New(slog.DiscardHandler)
	session, err := client.MessageSessionClient(t.Context(), 1, "owner", WithLogger(logger), WithoutTLSVerify())
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, session.Close(context.Background())) })
	child := session.commonClient.httpClient.Transport.(*retryablehttp.RoundTripper).Client
	childTransport := child.HTTPClient.Transport.(*http.Transport)
	assert.NotSame(t, parent, child)
	assert.NotSame(t, parent.HTTPClient, child.HTTPClient)
	assert.NotSame(t, parentTransport, childTransport)
	assert.Same(t, logger, child.Logger)
	assert.NotSame(t, logger, parent.Logger)
	assert.True(t, childTransport.TLSClientConfig.InsecureSkipVerify)
	assert.False(t, parentTransport.TLSClientConfig.InsecureSkipVerify)
}

func TestRetryableHTTPClientFactoryCopiesTLSConfig(t *testing.T) {
	shared := &tls.Config{
		Certificates: make([]tls.Certificate, 1, 4),
		NextProtos:   make([]string, 1, 4),
	}
	shared.NextProtos[0] = "h2"
	opts := defaultHTTPClientOption()
	WithRetryableHTTPClientFactory(func() *retryablehttp.Client {
		client := retryablehttp.NewClient()
		client.HTTPClient.Transport.(*http.Transport).TLSClientConfig = shared
		return client
	})(&opts)
	parent, err := opts.newRetryableHTTPClient()
	require.NoError(t, err)
	parentConfig := parent.HTTPClient.Transport.(*http.Transport).TLSClientConfig
	const sessions = 16
	configs := make([]*tls.Config, sessions)
	errs := make([]error, sessions)
	var workers sync.WaitGroup
	for i := range sessions {
		workers.Go(func() {
			childOpts := opts
			WithoutTLSVerify()(&childOpts)
			WithTLSClientCertificate(tls.Certificate{Certificate: [][]byte{{byte(i)}}})(&childOpts)
			child, err := childOpts.newRetryableHTTPClient()
			errs[i] = err
			if err == nil {
				transport := child.HTTPClient.Transport.(*http.Transport)
				// This also initializes HTTP/2, as the first request would.
				transport.CloseIdleConnections()
				configs[i] = transport.TLSClientConfig
			}
		})
	}
	workers.Go(func() {
		for range sessions {
			// The HTTP transport clones the TLS config before a handshake.
			assert.False(t, parentConfig.Clone().InsecureSkipVerify)
		}
	})
	workers.Wait()
	for i, config := range configs {
		require.NoError(t, errs[i])
		assert.NotSame(t, parentConfig, config)
		assert.True(t, config.InsecureSkipVerify)
		require.Len(t, config.Certificates, 2)
		assert.Equal(t, []byte{byte(i)}, config.Certificates[1].Certificate[0])
	}
	assert.False(t, shared.InsecureSkipVerify)
	assert.False(t, parentConfig.InsecureSkipVerify)
	assert.Empty(t, shared.Certificates[:cap(shared.Certificates)][1].Certificate)
	assert.Empty(t, shared.NextProtos[:cap(shared.NextProtos)][1])
}

func TestMessageSessionCertificateOptionsDoNotShareArray(t *testing.T) {
	opts := defaultHTTPClientOption()
	opts.tlsClientCertificates = make([]tls.Certificate, 3, 4)
	const sessions = 16
	children := make([]httpClientOption, sessions)
	var workers sync.WaitGroup
	for i := range sessions {
		workers.Go(func() {
			// MessageSessionClient copies the parent options before overrides.
			children[i] = opts
			WithTLSClientCertificate(tls.Certificate{Certificate: [][]byte{{byte(i)}}})(&children[i])
		})
	}
	workers.Wait()
	for i, child := range children {
		require.Len(t, child.tlsClientCertificates, 4)
		assert.Equal(t, []byte{byte(i)}, child.tlsClientCertificates[3].Certificate[0])
	}
	assert.Empty(t, opts.tlsClientCertificates[:cap(opts.tlsClientCertificates)][3].Certificate)
}

func TestRetryableHTTPClientFactoryCopiesProtocolHandlers(t *testing.T) {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	shared := make(map[string]func(string, *tls.Conn) http.RoundTripper)
	opts := defaultHTTPClientOption()
	WithRetryableHTTPClientFactory(func() *retryablehttp.Client {
		client := retryablehttp.NewClient()
		transport := client.HTTPClient.Transport.(*http.Transport)
		transport.Protocols = protocols
		transport.TLSNextProto = shared
		return client
	})(&opts)
	var workers sync.WaitGroup
	for range 16 {
		client, err := opts.newRetryableHTTPClient()
		require.NoError(t, err)
		workers.Go(client.HTTPClient.CloseIdleConnections)
	}
	workers.Wait()
	assert.Empty(t, shared)
}
