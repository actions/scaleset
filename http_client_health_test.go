package scaleset

import (
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type blackholedConnection struct {
	front, back net.Conn
	frozen      atomic.Bool
}

// blackholeProxy drops bytes on existing sockets without closing them. New
// connections keep working, as when a network rebind loses old NAT state.
type blackholeProxy struct {
	listener net.Listener
	mu       sync.Mutex
	pairs    []*blackholedConnection
	count    atomic.Int32
}

func newBlackholeProxy(t *testing.T, backend string) *blackholeProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	p := &blackholeProxy{listener: ln}
	var wg sync.WaitGroup
	accepted := make(chan struct{})
	wg.Go(func() {
		defer close(accepted)
		for {
			front, err := ln.Accept()
			if err != nil {
				return
			}
			back, err := net.DialTimeout("tcp", backend, time.Second)
			if err != nil {
				_ = front.Close()
				continue
			}
			pair := &blackholedConnection{front: front, back: back}
			p.mu.Lock()
			p.pairs = append(p.pairs, pair)
			p.mu.Unlock()
			p.count.Add(1)
			for _, direction := range [][2]net.Conn{{front, back}, {back, front}} {
				wg.Go(func() {
					dst, src := direction[0], direction[1]
					defer dst.Close()
					defer src.Close()
					buffer := make([]byte, 32<<10)
					for {
						n, err := src.Read(buffer)
						if n > 0 && !pair.frozen.Load() {
							if _, writeErr := dst.Write(buffer[:n]); writeErr != nil {
								return
							}
						}
						if err != nil {
							return
						}
					}
				})
			}
		}
	})
	t.Cleanup(func() {
		require.NoError(t, ln.Close())
		<-accepted
		// The accept loop has stopped, so there can be no more pairs or goroutines.
		for _, pair := range p.pairs {
			_ = pair.front.Close()
			_ = pair.back.Close()
		}
		wg.Wait()
	})
	return p
}

func (p *blackholeProxy) freeze() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, pair := range p.pairs {
		pair.frozen.Store(true)
	}
}

func TestHTTP2BlackholeRecovery(t *testing.T) {
	for _, mode := range []string{"without health checks", "with health checks", "HTTP1 fallback"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			server.EnableHTTP2 = true
			server.StartTLS()
			t.Cleanup(server.Close)
			proxy := newBlackholeProxy(t, server.Listener.Addr().String())
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			client := NewHTTPClient(HTTPClientConfig{
				RootCAs: roots,
				Timeout: 300 * time.Millisecond,
				Proxy:   func(*http.Request) (*url.URL, error) { return nil, nil },
			})
			t.Cleanup(client.CloseIdleConnections)
			transport := client.Transport.(*http.Transport)
			require.NotNil(t, transport.HTTP2)
			require.Equal(t, 30*time.Second, transport.HTTP2.SendPingTimeout)
			require.Equal(t, 10*time.Second, transport.HTTP2.PingTimeout)
			// Exercise the production settings with shorter detection timers.
			transport.HTTP2.SendPingTimeout = 40 * time.Millisecond
			transport.HTTP2.PingTimeout = 40 * time.Millisecond
			if mode == "without health checks" {
				transport.HTTP2.SendPingTimeout = 0
			}
			expectedProtocol := 2
			if mode == "HTTP1 fallback" {
				transport.Protocols = new(http.Protocols)
				transport.Protocols.SetHTTP1(true)
				expectedProtocol = 1
			}
			check := func() error {
				response, err := client.Get("https://" + proxy.listener.Addr().String())
				if err != nil {
					return err
				}
				defer response.Body.Close()
				_, err = io.Copy(io.Discard, response.Body)
				require.NoError(t, err)
				require.Equal(t, expectedProtocol, response.ProtoMajor)
				require.Equal(t, http.StatusNoContent, response.StatusCode)
				return nil
			}
			require.NoError(t, check())
			proxy.freeze()
			recovered := false
			for range 3 {
				if err := check(); err == nil {
					recovered = true
					break
				}
			}
			t.Logf("recovered=%v accepted_connections=%d", recovered, proxy.count.Load())
			if mode == "without health checks" {
				assert.False(t, recovered, "canceled HTTP/2 streams must reproduce reuse of the silent connection")
				assert.EqualValues(t, 1, proxy.count.Load())
			} else {
				assert.True(t, recovered, "a subsequent request must reconnect")
				assert.GreaterOrEqual(t, proxy.count.Load(), int32(2))
			}
		})
	}
}

func TestHTTP2HealthChecksPreserveHealthyLongPoll(t *testing.T) {
	var connections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// No application response during several ping intervals. The HTTP/2
		// server still answers protocol pings and must not be disconnected.
		time.Sleep(250 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client := NewHTTPClient(HTTPClientConfig{
		RootCAs: roots,
		Timeout: 2 * time.Second,
		Proxy:   func(*http.Request) (*url.URL, error) { return nil, nil },
	})
	t.Cleanup(client.CloseIdleConnections)
	transport := client.Transport.(*http.Transport)
	require.NotNil(t, transport.HTTP2)
	transport.HTTP2.SendPingTimeout = 20 * time.Millisecond
	transport.HTTP2.PingTimeout = 40 * time.Millisecond
	for range 2 {
		response, err := client.Get(server.URL)
		require.NoError(t, err)
		_, err = io.Copy(io.Discard, response.Body)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		require.Equal(t, 2, response.ProtoMajor)
		require.Equal(t, http.StatusNoContent, response.StatusCode)
	}
	assert.EqualValues(t, 1, connections.Load(), "healthy long polls must share the original connection")
}
