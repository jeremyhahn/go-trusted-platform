package webservice

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/gorilla/mux"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webserver/embed"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/jwt"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errCA964 is the typed failure the fake CA returns when told to fail.
type errCA964 struct{ reason string }

func (e errCA964) Error() string { return "fake CA: " + e.reason }

// fakeTLSCA964 serves a fixed server TLS config the way the real CA does:
// it returns the configured config or a typed error, and records the key
// attributes it was asked for.
type fakeTLSCA964 struct {
	trustedca.CACertificateAuthority
	config   *tls.Config
	err      error
	gotAttrs *xkmssdk.KeyAttributes
	calls    int

	xsigned    bool
	gotXSigner crypto.Signer
}

func (f *fakeTLSCA964) TLSConfigWithXSigner(_ context.Context, attrs *xkmssdk.KeyAttributes, xsigner crypto.Signer) (*tls.Config, error) {
	f.calls++
	f.xsigned = true
	f.gotAttrs = attrs
	f.gotXSigner = xsigner
	if f.err != nil {
		return nil, f.err
	}
	return f.config, nil
}

func (f *fakeTLSCA964) ServerTLSConfig(_ context.Context, attrs *xkmssdk.KeyAttributes, _ bool) (*tls.Config, error) {
	f.calls++
	f.gotAttrs = attrs
	if f.err != nil {
		return nil, f.err
	}
	return f.config, nil
}

// newCert964 generates a self-signed ECDSA certificate in memory.
func newCert964(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func newTLSServer964(t *testing.T, ca *fakeTLSCA964) *WebServerV1 {
	t.Helper()
	server := newMinimalServer(t)
	server.config = &v1.Config{Name: "web-964"}
	server.ca = ca
	server.keyAttributes = &xkmssdk.KeyAttributes{}
	return server
}

func TestCoverage964_ReloadCertificate(t *testing.T) {
	initial := newCert964(t, "initial")
	next := newCert964(t, "next")

	tests := []struct {
		name        string
		ca          *fakeTLSCA964
		noReloader  bool
		unavailable bool
		failed      bool
	}{
		{name: "no live listener", ca: &fakeTLSCA964{}, noReloader: true, unavailable: true},
		{name: "CA error", ca: &fakeTLSCA964{err: errCA964{reason: "sealed"}}, failed: true},
		{name: "CA returns no certificate", ca: &fakeTLSCA964{config: &tls.Config{}}, failed: true},
		{name: "GetCertificate error", ca: &fakeTLSCA964{config: &tls.Config{
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				return nil, errCA964{reason: "no key"}
			},
		}}, failed: true},
		{name: "certificate list", ca: &fakeTLSCA964{config: &tls.Config{Certificates: []tls.Certificate{next}}}},
		{name: "GetCertificate", ca: &fakeTLSCA964{config: &tls.Config{
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &next, nil },
		}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newTLSServer964(t, tt.ca)
			if !tt.noReloader {
				reloader, err := bootstrap.NewCertReloader(&initial)
				require.NoError(t, err)
				server.certReloader.Store(reloader)
			}

			err := server.ReloadCertificate(context.Background())

			switch {
			case tt.unavailable:
				var target ErrCertReloaderUnavailable
				require.ErrorAs(t, err, &target)
				assert.Equal(t, "web-964", target.Webservice)
				assert.Zero(t, tt.ca.calls, "no CA call without a live listener")
				assert.Nil(t, server.CertReloader())
			case tt.failed:
				var target ErrCertReloadFailed
				require.ErrorAs(t, err, &target)
				assert.Equal(t, "web-964", target.Webservice)
				assert.NotEmpty(t, target.Error())
				assert.Equal(t, initial.Certificate[0], server.CertReloader().Current().Certificate[0],
					"a failed reload keeps the serving certificate")
			default:
				require.NoError(t, err)
				assert.Same(t, server.keyAttributes, tt.ca.gotAttrs)
				assert.Equal(t, next.Certificate[0], server.CertReloader().Current().Certificate[0])
			}
		})
	}
}

func TestCoverage964_ReloadFailedUnwrapsCause(t *testing.T) {
	cause := errCA964{reason: "sealed"}
	server := newTLSServer964(t, &fakeTLSCA964{err: cause})
	initial := newCert964(t, "initial")
	reloader, err := bootstrap.NewCertReloader(&initial)
	require.NoError(t, err)
	server.certReloader.Store(reloader)

	err = server.ReloadCertificate(context.Background())

	var got errCA964
	require.ErrorAs(t, err, &got)
	assert.Equal(t, "sealed", got.reason)
	assert.Contains(t, err.Error(), "web-964")
	assert.Contains(t, ErrCertReloaderUnavailable{Webservice: "web-964"}.Error(), "web-964")
}

func TestCoverage964_BuildTLSConfig(t *testing.T) {
	cert := newCert964(t, "server")

	t.Run("passes the CA server config through", func(t *testing.T) {
		ca := &fakeTLSCA964{config: &tls.Config{Certificates: []tls.Certificate{cert}}}
		server := newTLSServer964(t, ca)

		tlsConfig, err := server.buildTLSConfig(context.Background())

		require.NoError(t, err)
		require.Len(t, tlsConfig.Certificates, 1)
		assert.Equal(t, cert.Certificate[0], tlsConfig.Certificates[0].Certificate[0])
		assert.Same(t, server.keyAttributes, ca.gotAttrs)
	})

	t.Run("returns the CA error", func(t *testing.T) {
		server := newTLSServer964(t, &fakeTLSCA964{err: errCA964{reason: "sealed"}})

		tlsConfig, err := server.buildTLSConfig(context.Background())

		assert.Nil(t, tlsConfig)
		var target errCA964
		require.ErrorAs(t, err, &target)
	})
}

// useWebFS964 swaps the embedded frontend for an in-memory one.
func useWebFS964(t *testing.T) {
	t.Helper()
	previous := embed.WebFS
	t.Cleanup(func() { embed.WebFS = previous })
	embed.WebFS = fstest.MapFS{
		"index.html":                         {Data: []byte("root-index")},
		"app.js":                             {Data: []byte("app-js")},
		"new.html":                           {Data: []byte("rewritten")},
		"docs/index.html":                    {Data: []byte("docs-index")},
		"devices/__placeholder__/index.html": {Data: []byte("device-placeholder")},
	}
}

func TestCoverage964_ServeEmbeddedFiles(t *testing.T) {
	useWebFS964(t)
	server := newMinimalServer(t)
	rules := []*v1.RewriteRule{
		{Pattern: "(", Target: "/never.html"},
		{Pattern: "^/old$", Target: "/new.html"},
	}
	handler := server.serveEmbeddedFiles("index.html", rules)

	tests := []struct {
		name   string
		path   string
		status int
		body   string
	}{
		{name: "root serves the index", path: "/", status: http.StatusOK, body: "root-index"},
		{name: "file", path: "/app.js", status: http.StatusOK, body: "app-js"},
		{name: "directory serves its index", path: "/docs", status: http.StatusOK, body: "docs-index"},
		{name: "rewrite rule", path: "/old", status: http.StatusOK, body: "rewritten"},
		{name: "dynamic route placeholder", path: "/devices/abc123", status: http.StatusOK, body: "device-placeholder"},
		{name: "SPA fallback", path: "/settings/profile", status: http.StatusOK, body: "root-index"},
		{name: "missing API path is a 404", path: "/api/v1/missing", status: http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))

			assert.Equal(t, tt.status, rec.Code)
			if tt.body != "" {
				assert.Equal(t, tt.body, rec.Body.String())
			}
			assert.NotContains(t, rec.Body.String(), "never")
		})
	}
}

func TestCoverage964_ServeEmbeddedFileMissingIs404(t *testing.T) {
	useWebFS964(t)
	server := newMinimalServer(t)
	rec := httptest.NewRecorder()

	server.serveEmbeddedFile(rec, httptest.NewRequest(http.MethodGet, "/gone", nil), "gone.html")

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestCoverage964_FindPlaceholderFallback(t *testing.T) {
	useWebFS964(t)

	assert.Equal(t, "devices/__placeholder__/index.html", findPlaceholderFallback("devices/abc", "index.html"))
	assert.Equal(t, "devices/__placeholder__/index.html", findPlaceholderFallback("devices/abc/", "index.html"))
	assert.Empty(t, findPlaceholderFallback("", "index.html"))
	assert.Empty(t, findPlaceholderFallback("zones/abc", "index.html"))
}

func TestCoverage964_EnsureDirectoryExists(t *testing.T) {
	server := newMinimalServer(t)

	t.Run("creates the directory and its index", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "vhost")

		require.NoError(t, server.ensureDirectoryExists(dir, "www.example.com", "index.html"))

		data, err := os.ReadFile(filepath.Join(dir, "index.html"))
		require.NoError(t, err)
		assert.True(t, strings.Contains(string(data), "www.example.com"))
	})

	t.Run("a file in the way is a wrapped error", func(t *testing.T) {
		blocker := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))

		err := server.ensureDirectoryExists(filepath.Join(blocker, "vhost"), "www.example.com", "index.html")

		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Contains(t, wrapped.Error(), "failed to create directory")
		assert.NotNil(t, errors.Unwrap(wrapped))
	})
}

// newListenerServer964 builds a server bound to 127.0.0.1 on ephemeral ports.
func newListenerServer964(t *testing.T, ca *fakeTLSCA964) *WebServerV1 {
	t.Helper()
	cfg := &v1.Config{Name: "web-964", BindHost: "127.0.0.1"}
	server := newSurfaceServer(t, cfg, nil)
	server.ctx = context.Background()
	server.ca = ca
	server.keyAttributes = &xkmssdk.KeyAttributes{}
	server.closeChan = make(chan bool, 1)
	server.plainServer = server.limits.newHTTPServer(nil)
	return server
}

// announceListener964 reports the address an http.Server starts serving on.
func announceListener964(srv *http.Server) <-chan string {
	addrs := make(chan string, 1)
	srv.BaseContext = func(l net.Listener) context.Context {
		addrs <- l.Addr().String()
		return context.Background()
	}
	return addrs
}

func TestCoverage964_StartHTTPSServesTheCACertificate(t *testing.T) {
	cert := newCert964(t, "tls-964")
	server := newListenerServer964(t, &fakeTLSCA964{config: &tls.Config{Certificates: []tls.Certificate{cert}}})
	server.httpServer.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("secure"))
	})
	addrs := announceListener964(server.httpServer)

	go server.startHTTPS()
	addr := <-addrs
	// startHTTPS stores the HTTP/3 listener before it serves TCP, so it is
	// set once the TCP address is announced.
	h3 := server.h3.Load()
	require.NotNil(t, h3, "startHTTPS keeps its HTTP/3 listener")
	udpAddr := h3.conn.LocalAddr().String()
	// Cleanups run last-in first-out: Shutdown runs first, then the probe
	// asserts the HTTP/3 socket was released.
	t.Cleanup(func() {
		probe, err := net.ListenPacket("udp", udpAddr)
		require.NoError(t, err, "Shutdown releases the HTTP/3 socket")
		require.NoError(t, probe.Close())
		select {
		case <-h3.done:
		default:
			t.Error("Shutdown returned before HTTP/3 Serve did")
		}
	})
	t.Cleanup(server.Shutdown)

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
	resp, err := client.Get("https://" + addr + "/")
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.Equal(t, "secure", string(body))
	require.NotEmpty(t, resp.TLS.PeerCertificates)
	assert.Equal(t, cert.Certificate[0], resp.TLS.PeerCertificates[0].Raw)
	require.NotNil(t, server.CertReloader(), "the live listener exposes its reloader")
	assert.Equal(t, []string{"h3", "h2", "http/1.1"}, server.httpServer.TLSConfig.NextProtos)
}

// startHTTP3Server964 runs startHTTPS with handler and returns the server,
// its HTTP/3 listener, the listener's URL and an HTTP/3 client transport
// that trusts the server certificate.
func startHTTP3Server964(t *testing.T, handler http.Handler) (*WebServerV1, *h3Listener, string, *http3.Transport) {
	t.Helper()
	cert := newCert964(t, "h3-964")
	server := newListenerServer964(t, &fakeTLSCA964{config: &tls.Config{Certificates: []tls.Certificate{cert}}})
	server.httpServer.Handler = handler
	addrs := announceListener964(server.httpServer)

	go server.startHTTPS()
	<-addrs
	h3 := server.h3.Load()
	require.NotNil(t, h3, "startHTTPS keeps its HTTP/3 listener")

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	transport := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
	return server, h3, "https://" + h3.conn.LocalAddr().String() + "/", transport
}

// getHTTP3964 runs one GET over transport and delivers the body, or the
// error that ended the request.
func getHTTP3964(transport *http3.Transport, url string) <-chan h3Result964 {
	results := make(chan h3Result964, 1)
	go func() {
		resp, err := (&http.Client{Transport: transport}).Get(url)
		if err != nil {
			results <- h3Result964{err: err}
			return
		}
		body, readErr := io.ReadAll(resp.Body)
		results <- h3Result964{body: string(body), err: errors.Join(readErr, resp.Body.Close())}
	}()
	return results
}

type h3Result964 struct {
	body string
	err  error
}

func TestCoverage964_ShutdownDrainsAnInFlightHTTP3Request(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server, h3, url, transport := startHTTP3Server964(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-release:
			if _, err := w.Write([]byte("drained")); err != nil {
				t.Errorf("write the drained response: %v", err)
			}
		case <-r.Context().Done():
		}
	}))
	results := getHTTP3964(transport, url)
	<-started

	shutdown := make(chan struct{})
	go func() {
		server.Shutdown()
		close(shutdown)
	}()
	// Serve returns once Shutdown has closed the HTTP/3 listener, so the
	// request is still in flight while the server shuts down.
	<-h3.done
	close(release)

	result := <-results
	require.NoError(t, result.err, "Shutdown lets the in-flight HTTP/3 request finish")
	assert.Equal(t, "drained", result.body)
	// The client closes its connection, which ends the drain.
	require.NoError(t, transport.Close())
	<-shutdown

	probe, err := net.ListenPacket("udp", h3.conn.LocalAddr().String())
	require.NoError(t, err, "Shutdown releases the HTTP/3 socket")
	require.NoError(t, probe.Close())
}

func TestCoverage964_ShutdownHTTP3ClosesWhenTheContextExpires(t *testing.T) {
	started := make(chan struct{})
	server, h3, url, transport := startHTTP3Server964(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	t.Cleanup(func() { require.NoError(t, server.httpServer.Close()) })
	results := getHTTP3964(transport, url)
	<-started

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := server.shutdownHTTP3(ctx)

	var shutdownErr *ErrHTTP3Shutdown
	require.ErrorAs(t, err, &shutdownErr)
	assert.Equal(t, "drain", shutdownErr.Step)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Contains(t, err.Error(), "HTTP/3 shutdown drain")
	require.Error(t, (<-results).err, "Close aborts the request the drain could not finish")
	select {
	case <-h3.done:
	default:
		t.Error("shutdownHTTP3 returned before HTTP/3 Serve did")
	}
	probe, err := net.ListenPacket("udp", h3.conn.LocalAddr().String())
	require.NoError(t, err, "the Close fallback still releases the HTTP/3 socket")
	require.NoError(t, probe.Close())
	require.NoError(t, transport.Close())
}

func TestCoverage964_ShutdownWithoutHTTPSSkipsHTTP3(t *testing.T) {
	server := newListenerServer964(t, &fakeTLSCA964{})
	require.Nil(t, server.h3.Load(), "startHTTPS never ran")
	assert.NotPanics(t, server.Shutdown)
	assert.Nil(t, server.h3.Load())
}

func TestCoverage964_StartHTTPServesThePlaintextHandler(t *testing.T) {
	server := newListenerServer964(t, &fakeTLSCA964{})
	addrs := announceListener964(server.plainServer)

	go server.startHTTP(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	addr := <-addrs

	resp, err := http.Get("http://" + addr + "/")
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.Equal(t, http.StatusTeapot, resp.StatusCode)
	server.Shutdown()
	closed, err := http.Get("http://" + addr + "/")
	if closed != nil {
		require.NoError(t, closed.Body.Close())
	}
	assert.Error(t, err, "Shutdown closes the plaintext listener")
}

func TestCoverage964_RegisterVirtualHosts(t *testing.T) {
	home := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(home, "blocker"), []byte("x"), 0o600))
	server := newMinimalServer(t)
	server.config = &v1.Config{
		Home:  home,
		Index: "index.html",
		VirtualHosts: &[]v1.VirtualHost{
			{Home: "empty"},
			{
				Hosts: []string{"www.example.com"},
				Home:  "www",
				CORS: &v1.CORSConfig{
					AllowedOrigins: []string{"https://app.example.com"},
					AllowedMethods: []string{http.MethodGet},
				},
			},
			{Hosts: []string{"blocked.example.com"}, Home: "blocker"},
		},
	}
	root := mux.NewRouter()

	server.registerVirtualHosts(root)

	t.Run("a static host gets its directory and default index", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://www.example.com/", nil)
		req.Header.Set("Origin", "https://app.example.com")
		rec := httptest.NewRecorder()

		root.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "www.example.com")
		assert.Equal(t, "https://app.example.com", rec.Header().Get("Access-Control-Allow-Origin"))
		assert.DirExists(t, filepath.Join(home, "www"))
	})

	tests := []struct {
		name string
		host string
	}{
		{name: "a host whose directory cannot be created is not mounted", host: "blocked.example.com"},
		{name: "a host with no names is not mounted", host: "empty.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			root.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://"+tt.host+"/", nil))
			assert.Equal(t, http.StatusNotFound, rec.Code)
		})
	}
	assert.NoDirExists(t, filepath.Join(home, "empty"))
}

// jwtRegistry964 supplies the one registry entry the constructor reads.
type jwtRegistry964 struct {
	v1.RestHandlerRegistry
}

func (jwtRegistry964) JSONWebTokenHandler() jwt.TokenHandler { return nil }

func TestCoverage964_NewWebServerV1(t *testing.T) {
	ca := &fakeTLSCA964{}
	attrs := &xkmssdk.KeyAttributes{}
	cfg := &v1.Config{Name: "web-964", BindHost: "127.0.0.1"}

	server := NewWebServerV1(context.Background(), true, newTestLogger(), ca, nil, cfg, jwtRegistry964{}, attrs)

	require.NotNil(t, server)
	assert.Equal(t, "/api/v1", server.baseURI)
	assert.Same(t, cfg, server.config)
	assert.Same(t, attrs, server.keyAttributes)
	assert.True(t, server.debug)
	assert.Equal(t, v1.SurfaceFull, server.surface)
	assert.Nil(t, server.limiter, "the full surface has no per-source limit unless configured")
	assert.Same(t, server.router, server.httpServer.Handler)
	require.NotNil(t, server.httpServer)
	require.NotNil(t, server.plainServer)
	assert.Nil(t, server.CertReloader(), "no reloader before the TLS listener starts")
	server.Shutdown()
}

func TestCoverage964_NewWebServerV1EdgeBuildsAndClosesItsLimiter(t *testing.T) {
	cfg := edgeConfig()

	server := NewWebServerV1(context.Background(), false, newTestLogger(), &fakeTLSCA964{}, nil, cfg, jwtRegistry964{}, nil)

	assert.Equal(t, v1.SurfaceEdge, server.surface)
	require.NotNil(t, server.limiter, "an edge listener limits each source by default")
	server.Shutdown()
	_, open := <-server.closeChan
	assert.True(t, open, "Shutdown signals Run once")
	_, open = <-server.closeChan
	assert.False(t, open, "then closes the channel")
}

func TestCoverage964_RunBuildsRoutesUntilShutdown(t *testing.T) {
	cfg := edgeConfig()
	cfg.Port, cfg.TLSPort = 0, 0
	server := newSurfaceServer(t, cfg, &edgeRegistry{acme: stubACME{}})
	server.closeChan = make(chan bool, 1)
	done := make(chan struct{})

	go func() {
		server.Run()
		close(done)
	}()
	server.Shutdown()
	<-done

	server.routerMutex.Lock()
	handler := server.httpServer.Handler
	server.routerMutex.Unlock()
	require.NotNil(t, handler, "Run mounts the router before it blocks")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://other.example.com/", nil))
	assert.Equal(t, http.StatusMisdirectedRequest, rec.Code, "an edge listener refuses hosts it does not serve")
}

func TestCoverage964_ServeEmbeddedFileDirectoryServesItsIndex(t *testing.T) {
	useWebFS964(t)
	server := newMinimalServer(t)
	rec := httptest.NewRecorder()

	server.serveEmbeddedFile(rec, httptest.NewRequest(http.MethodGet, "/docs/", nil), "docs")

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "docs-index", rec.Body.String())
}

func TestCoverage964_BuildTLSConfigCrossSign(t *testing.T) {
	cert := newCert964(t, "xsigned")

	t.Run("cross-signed config comes from the CA with itself as signer", func(t *testing.T) {
		ca := &fakeTLSCA964{config: &tls.Config{Certificates: []tls.Certificate{cert}}}
		server := newTLSServer964(t, ca)
		server.config.Certificate.ACME = &v1.ACMEIdentityConfig{
			CrossSign: &trustedca.ACMECrossSignConfig{DirectoryURL: "https://acme.example.com/directory"},
		}

		tlsConfig, err := server.buildTLSConfig(context.Background())

		require.NoError(t, err)
		assert.True(t, ca.xsigned, "the cross-sign path asks for the cross-signed config")
		assert.Same(t, ca, ca.gotXSigner)
		require.Len(t, tlsConfig.Certificates, 1)
	})

	t.Run("an invalid cross-sign directory is refused before the CA", func(t *testing.T) {
		ca := &fakeTLSCA964{config: &tls.Config{}}
		server := newTLSServer964(t, ca)
		server.config.Certificate.ACME = &v1.ACMEIdentityConfig{
			CrossSign: &trustedca.ACMECrossSignConfig{DirectoryURL: "://acme.example.com"},
		}

		tlsConfig, err := server.buildTLSConfig(context.Background())

		require.Error(t, err)
		assert.Nil(t, tlsConfig)
		assert.Zero(t, ca.calls)
	})

	t.Run("a CA cross-sign error is returned", func(t *testing.T) {
		ca := &fakeTLSCA964{err: errCA964{reason: "sealed"}}
		server := newTLSServer964(t, ca)
		server.config.Certificate.ACME = &v1.ACMEIdentityConfig{
			CrossSign: &trustedca.ACMECrossSignConfig{DirectoryURL: "https://acme.example.com/directory"},
		}

		_, err := server.buildTLSConfig(context.Background())

		var target errCA964
		require.ErrorAs(t, err, &target)
	})
}

func TestCoverage964_ProvisioningZoneMissingNamesItsCause(t *testing.T) {
	err := &ErrProvisioningZoneMissing{Name: "prov", Cause: errCA964{reason: "no zone"}}

	assert.Contains(t, err.Error(), `"prov"`)
	assert.Contains(t, err.Error(), "no zone")
}
