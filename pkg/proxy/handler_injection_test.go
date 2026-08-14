package proxy

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// captureBackend records the headers of the last forwarded request.
type captureBackend struct {
	srv *httptest.Server

	mu   sync.Mutex
	last http.Header
}

func newCaptureBackend(t *testing.T) *captureBackend {
	t.Helper()
	b := &captureBackend{}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		b.last = r.Header.Clone()
		b.mu.Unlock()
		if _, err := w.Write([]byte("ok")); err != nil {
			t.Errorf("backend write: %v", err)
		}
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func (b *captureBackend) header() http.Header {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.last
}

// newInjectionEngine builds an engine with one mtls route configured by
// mutate and an allowing fakeAuth with the given identity.
func newInjectionEngine(t *testing.T, backendURL string, id *ClientIdentity, mutate func(*Config)) (*Engine, *captureSink) {
	t.Helper()
	cfg := authConfig(backendURL)
	if mutate != nil {
		mutate(&cfg)
	}
	sink := &captureSink{}
	e, err := New(cfg, Deps{
		Auth:      &fakeAuth{decision: &AuthDecision{Allowed: true, Identity: id}},
		Audit:     sink,
		Logger:    testLogger(),
		ServerTLS: &tls.Config{MinVersion: tls.VersionTLS13},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e, sink
}

// TestServeHTTPInjectsIdentityHeaders verifies trusted identity headers reach
// the backend after an allow decision.
func TestServeHTTPInjectsIdentityHeaders(t *testing.T) {
	backend := newCaptureBackend(t)
	id := fullIdentity()
	e, _ := newInjectionEngine(t, backend.srv.URL, id, nil)
	req := httptest.NewRequest(http.MethodGet, "http://svc.example.com/secure", nil)
	req.Header.Set(headerTPClientID, "spoofed")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	h := backend.header()
	want := map[string]string{
		headerForwardedClientCert: `Hash=deadbeef;Subject="CN=device-1,O=Test Org";URI=spiffe://platform/device-1`,
		headerTPClientID:          "client-1",
		headerTPDeviceID:          "ab12",
		headerTPClientZone:        "trusted",
		headerTPAuthMethod:        "mtls",
		headerTPAttested:          "false",
		headerTPCertFingerprint:   "deadbeef",
	}
	for k, v := range want {
		if got := h.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
}

// TestServeHTTPMTLSStripsAuthorization verifies mtls routes never forward
// inbound bearer credentials.
func TestServeHTTPMTLSStripsAuthorization(t *testing.T) {
	backend := newCaptureBackend(t)
	e, _ := newInjectionEngine(t, backend.srv.URL, fullIdentity(), nil)
	req := httptest.NewRequest(http.MethodGet, "http://svc.example.com/secure", nil)
	req.Header.Set(headerAuthorization, "Bearer inbound-secret")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := backend.header().Get(headerAuthorization); got != "" {
		t.Errorf("Authorization = %q, want stripped on mtls route", got)
	}
}

// TestServeHTTPPublicKeepsAuthorization verifies public routes forward the
// caller's Authorization untouched.
func TestServeHTTPPublicKeepsAuthorization(t *testing.T) {
	backend := newCaptureBackend(t)
	e, err := New(publicConfig(backend.srv.URL), Deps{Logger: testLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://svc.example.com/x", nil)
	req.Header.Set(headerAuthorization, "Bearer inbound")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := backend.header().Get(headerAuthorization); got != "Bearer inbound" {
		t.Errorf("Authorization = %q, want preserved on public route", got)
	}
}

// TestServeHTTPAllowWithoutIdentitySkipsInjection verifies an allow decision
// with no identity forwards without identity headers.
func TestServeHTTPAllowWithoutIdentitySkipsInjection(t *testing.T) {
	backend := newCaptureBackend(t)
	e, _ := newInjectionEngine(t, backend.srv.URL, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "http://svc.example.com/secure", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := backend.header().Get(headerTPAttested); got != "" {
		t.Errorf("X-TP-Attested = %q, want unset without identity", got)
	}
}

// TestNewFailsClosedWithProductionChain verifies New rejects a token route
// against the real Phase 2 chain, whose token capability is absent.
func TestNewFailsClosedWithProductionChain(t *testing.T) {
	chain, err := NewAuthChain(AuthChainConfig{MTLS: &fakeMTLSAuth{}, Logger: testLogger()})
	if err != nil {
		t.Fatalf("NewAuthChain: %v", err)
	}
	cfg := authConfig("http://10.0.0.1:8080")
	cfg.Routes[0].Auth.Mode = AuthModeToken
	_, err = New(cfg, Deps{
		Auth:      chain,
		Logger:    testLogger(),
		ServerTLS: &tls.Config{MinVersion: tls.VersionTLS13},
	})
	if !errors.Is(err, ErrTokenAuthNotConfigured) {
		t.Fatalf("New = %v, want ErrTokenAuthNotConfigured", err)
	}
}
