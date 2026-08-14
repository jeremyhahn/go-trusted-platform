package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// fakeAuth is a configurable AuthChain for unit tests.
type fakeAuth struct {
	decision *AuthDecision
	err      error
	// lastRoute captures the compiled route passed to Authenticate.
	mu        sync.Mutex
	lastRoute *CompiledRoute
}

func (f *fakeAuth) Authenticate(ctx context.Context, r *http.Request, route *CompiledRoute) (*AuthDecision, error) {
	f.mu.Lock()
	f.lastRoute = route
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.decision, nil
}

func (f *fakeAuth) routeSeen() *CompiledRoute {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastRoute
}

// fakeTrust is a configurable TrustResolver for unit tests.
type fakeTrust struct {
	cfg *tls.Config
	err error

	mu         sync.Mutex
	trustClass string
	endpoint   string
}

func (f *fakeTrust) ClientTLSConfig(ctx context.Context, trustClass, endpoint string) (*tls.Config, error) {
	f.mu.Lock()
	f.trustClass = trustClass
	f.endpoint = endpoint
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.cfg, nil
}

// captureSink records audit events for assertions. The mutex is test-only.
type captureSink struct {
	mu     sync.Mutex
	events []AuditEvent
}

func (s *captureSink) Record(ctx context.Context, ev AuditEvent) {
	s.mu.Lock()
	s.events = append(s.events, ev)
	s.mu.Unlock()
}

func (s *captureSink) last(t *testing.T) AuditEvent {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.events) == 0 {
		t.Fatal("no audit events recorded")
	}
	return s.events[len(s.events)-1]
}

// testLogger returns a logger that discards output so tests stay quiet.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 4}))
}

// publicConfig returns a minimal valid config with one wildcard public route
// to the given backend URL.
func publicConfig(backendURL string) Config {
	return Config{
		Listeners: []ListenerConfig{{ID: "main", Address: "127.0.0.1:0"}},
		Routes: []RouteConfig{{
			ID:         "svc",
			PathPrefix: "/",
			PoolID:     "pool",
			Auth:       AuthRequirements{Mode: AuthModePublic},
		}},
		Pools: []BackendPoolConfig{{
			ID:       "pool",
			Backends: []BackendConfig{{URL: backendURL}},
		}},
	}
}

// newPublicEngine builds an engine with one public wildcard route and a
// capture audit sink.
func newPublicEngine(t *testing.T, backendURL string) (*Engine, *captureSink) {
	t.Helper()
	sink := &captureSink{}
	e, err := New(publicConfig(backendURL), Deps{Audit: sink, Logger: testLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e, sink
}

// okBackend starts an httptest backend that echoes selected request state in
// response headers and writes "ok".
func okBackend(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Echo-Path", r.URL.Path)
		w.Header().Set("Echo-Host", r.Host)
		w.Header().Set("Echo-XFF", r.Header.Get("X-Forwarded-For"))
		w.Header().Set("Echo-XFP", r.Header.Get("X-Forwarded-Proto"))
		w.Header().Set("Echo-XFH", r.Header.Get("X-Forwarded-Host"))
		w.Header().Set("Echo-XFCC", r.Header.Get("X-Forwarded-Client-Cert"))
		w.Header().Set("Echo-TP-Identity", r.Header.Get("X-TP-Identity"))
		w.Header().Set("Echo-TP-Zone", r.Header.Get("X-TP-Zone"))
		if _, err := w.Write([]byte("ok")); err != nil {
			t.Errorf("backend write: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// genTestCert generates a self-signed server certificate for 127.0.0.1 and
// localhost, returning the certificate and a root pool trusting it.
func genTestCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "proxy-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// closeBody closes a response body, failing the test on error.
func closeBody(t *testing.T, resp *http.Response) {
	t.Helper()
	if err := resp.Body.Close(); err != nil {
		t.Errorf("close body: %v", err)
	}
}

// readBody reads and closes a response body.
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer closeBody(t, resp)
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}
