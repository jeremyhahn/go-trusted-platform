package proxy

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// authConfig returns a config with one mtls route to the given backend.
func authConfig(backendURL string) Config {
	cfg := publicConfig(backendURL)
	cfg.Routes[0].Auth.Mode = AuthModeMTLS
	return cfg
}

// newAuthEngine builds an engine with one mtls route, the given auth chain,
// and a capture sink.
func newAuthEngine(t *testing.T, backendURL string, auth AuthChain) (*Engine, *captureSink) {
	t.Helper()
	sink := &captureSink{}
	e, err := New(authConfig(backendURL), Deps{
		Auth:      auth,
		Audit:     sink,
		Logger:    testLogger(),
		ServerTLS: &tls.Config{MinVersion: tls.VersionTLS13},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e, sink
}

func TestServeHTTPPublicRouteForwards(t *testing.T) {
	backend := okBackend(t)
	e, _ := newPublicEngine(t, backend.URL)
	req := httptest.NewRequest(http.MethodGet, "http://svc.example.com/hello", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "ok" {
		t.Fatalf("body = %q, want ok", rec.Body.String())
	}
	if got := rec.Header().Get("Echo-Path"); got != "/hello" {
		t.Errorf("backend path = %q, want /hello", got)
	}
	if rec.Header().Get("Echo-XFF") == "" {
		t.Error("X-Forwarded-For not set on backend request")
	}
	if got := rec.Header().Get("Echo-XFP"); got != "http" {
		t.Errorf("X-Forwarded-Proto = %q, want http", got)
	}
	if got := rec.Header().Get("Echo-XFH"); got != "svc.example.com" {
		t.Errorf("X-Forwarded-Host = %q, want svc.example.com", got)
	}
	m := e.Metrics()
	if m.Routes["svc"].Requests != 1 {
		t.Errorf("requests = %d, want 1", m.Routes["svc"].Requests)
	}
	if m.Routes["svc"].BytesOut == 0 {
		t.Error("bytesOut = 0, want > 0")
	}
}

// TestServeHTTPStripsIdentityHeaders pins the security-critical guarantee
// that inbound X-Forwarded-Client-Cert and X-TP-* headers never reach the
// backend, including non-canonical header keys.
func TestServeHTTPStripsIdentityHeaders(t *testing.T) {
	backend := okBackend(t)
	e, _ := newPublicEngine(t, backend.URL)
	req := httptest.NewRequest(http.MethodGet, "http://svc.example.com/", nil)
	req.Header.Set("X-Forwarded-Client-Cert", "spoofed-cert")
	req.Header.Set("X-TP-Identity", "spoofed-identity")
	// Non-canonical key set directly on the map to bypass canonicalization.
	req.Header["x-tp-zone"] = []string{"spoofed-zone"}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Echo-XFCC"); got != "" {
		t.Errorf("X-Forwarded-Client-Cert reached backend: %q", got)
	}
	if got := rec.Header().Get("Echo-TP-Identity"); got != "" {
		t.Errorf("X-TP-Identity reached backend: %q", got)
	}
	if got := rec.Header().Get("Echo-TP-Zone"); got != "" {
		t.Errorf("x-tp-zone reached backend: %q", got)
	}
}

func TestServeHTTPNoRoute(t *testing.T) {
	backend := okBackend(t)
	sink := &captureSink{}
	cfg := publicConfig(backend.URL)
	cfg.Routes[0].Hosts = []string{"only.example.com"}
	e, err := New(cfg, Deps{Audit: sink, Logger: testLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://other.example.com/x", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	var body errorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Error != "no route" {
		t.Errorf("body.Error = %q, want no route", body.Error)
	}
	ev := sink.last(t)
	if ev.Decision != DecisionNoRoute {
		t.Errorf("audit decision = %q, want %q", ev.Decision, DecisionNoRoute)
	}
	if e.Metrics().NotFound != 1 {
		t.Errorf("NotFound = %d, want 1", e.Metrics().NotFound)
	}
}

func TestServeHTTPAuthAllow(t *testing.T) {
	backend := okBackend(t)
	auth := &fakeAuth{decision: &AuthDecision{
		Allowed:  true,
		Identity: &ClientIdentity{ID: "client-1", DeviceID: "dev-1", Zone: "z1", AuthMethod: "mtls"},
	}}
	e, sink := newAuthEngine(t, backend.URL, auth)
	req := httptest.NewRequest(http.MethodGet, "http://svc.example.com/secure", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if route := auth.routeSeen(); route == nil || route.Config().ID != "svc" {
		t.Fatal("auth chain did not receive the compiled route")
	}
	ev := sink.last(t)
	if ev.Decision != DecisionAllow || ev.ClientID != "client-1" || ev.DeviceID != "dev-1" ||
		ev.Zone != "z1" || ev.AuthMethod != "mtls" || ev.RouteID != "svc" {
		t.Fatalf("allow audit event = %+v", ev)
	}
}

func TestServeHTTPAuthDeny(t *testing.T) {
	backend := okBackend(t)
	auth := &fakeAuth{decision: &AuthDecision{Allowed: false, Reason: "zone mismatch"}}
	e, sink := newAuthEngine(t, backend.URL, auth)
	req := httptest.NewRequest(http.MethodGet, "http://svc.example.com/secure", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	var body errorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Error != "forbidden" || body.Reason != "zone mismatch" {
		t.Fatalf("body = %+v", body)
	}
	ev := sink.last(t)
	if ev.Decision != DecisionDeny || ev.Reason != "zone mismatch" {
		t.Fatalf("deny audit event = %+v", ev)
	}
	if e.Metrics().Routes["svc"].Denied != 1 {
		t.Errorf("denied = %d, want 1", e.Metrics().Routes["svc"].Denied)
	}
}

func TestServeHTTPAuthNilDecisionDenies(t *testing.T) {
	backend := okBackend(t)
	auth := &fakeAuth{decision: nil}
	e, sink := newAuthEngine(t, backend.URL, auth)
	req := httptest.NewRequest(http.MethodGet, "http://svc.example.com/secure", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for nil decision", rec.Code)
	}
	if ev := sink.last(t); ev.Reason != "denied" {
		t.Fatalf("audit reason = %q, want denied", ev.Reason)
	}
}

func TestServeHTTPAuthErrorFailsClosed(t *testing.T) {
	backend := okBackend(t)
	auth := &fakeAuth{err: errors.New("attestation service unreachable")}
	e, sink := newAuthEngine(t, backend.URL, auth)
	req := httptest.NewRequest(http.MethodGet, "http://svc.example.com/secure", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	ev := sink.last(t)
	if ev.Decision != DecisionError || ev.Reason != "attestation service unreachable" {
		t.Fatalf("error audit event = %+v", ev)
	}
	if e.Metrics().Routes["svc"].Errors != 1 {
		t.Errorf("errors = %d, want 1", e.Metrics().Routes["svc"].Errors)
	}
}

func TestServeHTTPStripPrefix(t *testing.T) {
	backend := okBackend(t)
	cfg := publicConfig(backend.URL)
	cfg.Routes[0].PathPrefix = "/api"
	cfg.Routes[0].StripPrefix = true
	e, err := New(cfg, Deps{Logger: testLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tests := []struct {
		path string
		want string
	}{
		{"/api/v1/things", "/v1/things"},
		{"/api", "/"},
	}
	for _, tt := range tests {
		req := httptest.NewRequest(http.MethodGet, "http://svc.example.com"+tt.path, nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if got := rec.Header().Get("Echo-Path"); got != tt.want {
			t.Errorf("backend path for %q = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestServeHTTPPreserveHost(t *testing.T) {
	backend := okBackend(t)
	backendHost := mustParseURL(t, backend.URL).Host
	tests := []struct {
		name         string
		preserveHost bool
		wantHost     string
	}{
		{"preserve inbound host", true, "svc.example.com"},
		{"default backend host", false, backendHost},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := publicConfig(backend.URL)
			cfg.Routes[0].PreserveHost = tt.preserveHost
			e, err := New(cfg, Deps{Logger: testLogger()})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			req := httptest.NewRequest(http.MethodGet, "http://svc.example.com/", nil)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			if got := rec.Header().Get("Echo-Host"); got != tt.wantHost {
				t.Errorf("backend host = %q, want %q", got, tt.wantHost)
			}
		})
	}
}

func TestServeHTTPBackendFailure(t *testing.T) {
	// A closed backend guarantees a dial failure without any timeout wait.
	backend := httptest.NewServer(http.NotFoundHandler())
	backendURL := backend.URL
	backend.Close()
	sink := &captureSink{}
	e, err := New(publicConfig(backendURL), Deps{Audit: sink, Logger: testLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://svc.example.com/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	var body errorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Error != "bad gateway" {
		t.Errorf("body.Error = %q, want bad gateway", body.Error)
	}
	if ev := sink.last(t); ev.Decision != DecisionError || ev.RouteID != "svc" {
		t.Fatalf("backend error audit event = %+v", ev)
	}
	if e.Metrics().Routes["svc"].Errors != 1 {
		t.Errorf("errors = %d, want 1", e.Metrics().Routes["svc"].Errors)
	}
}

func TestServeHTTPRoundRobinAcrossBackends(t *testing.T) {
	b1 := okBackend(t)
	b2 := okBackend(t)
	cfg := publicConfig(b1.URL)
	cfg.Pools[0].Backends = append(cfg.Pools[0].Backends, BackendConfig{URL: b2.URL})
	e, err := New(cfg, Deps{Logger: testLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	hosts := make(map[string]int)
	for i := 0; i < 4; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://svc.example.com/", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		hosts[rec.Header().Get("Echo-Host")]++
	}
	if len(hosts) != 2 {
		t.Fatalf("requests reached %d distinct backends, want 2: %v", len(hosts), hosts)
	}
	for host, n := range hosts {
		if n != 2 {
			t.Errorf("backend %q served %d requests, want 2", host, n)
		}
	}
}

func TestStripIdentityHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("X-Forwarded-Client-Cert", "cert")
	h.Set("X-TP-Identity", "id")
	h.Set("Authorization", "Bearer tok")
	h.Set("X-Tpm", "keep") // no trailing dash: not an identity header
	h["x-forwarded-client-cert"] = []string{"lower"}
	h["X-TP-ZONE"] = []string{"upper"}
	stripIdentityHeaders(h)
	for _, k := range []string{"X-Forwarded-Client-Cert", "X-Tp-Identity"} {
		if len(h.Values(k)) != 0 {
			t.Errorf("header %q not stripped", k)
		}
	}
	if _, ok := h["X-Forwarded-Client-Cert"]; ok {
		t.Error("non-canonical x-forwarded-client-cert not stripped")
	}
	if _, ok := h["X-Tp-Zone"]; ok {
		t.Error("non-canonical X-TP-ZONE not stripped")
	}
	if h.Get("Authorization") != "Bearer tok" {
		t.Error("Authorization must be preserved")
	}
	if h.Get("X-Tpm") != "keep" {
		t.Error("X-Tpm must be preserved")
	}
}

func TestIsIdentityHeader(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{"X-Forwarded-Client-Cert", true},
		{"x-forwarded-client-cert", true},
		{"X-TP-Identity", true},
		{"x-tp-anything", true},
		{"X-Tp-", true},
		{"X-Tpm", false},
		{"X-Forwarded-For", false},
		{"Authorization", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := isIdentityHeader(tt.key); got != tt.want {
			t.Errorf("isIdentityHeader(%q) = %v, want %v", tt.key, got, tt.want)
		}
	}
}

func TestStripRequestPrefix(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		rawPath     string
		prefix      string
		wantPath    string
		wantRawPath string
	}{
		{"basic", "/api/v1", "", "/api", "/v1", ""},
		{"exact prefix", "/api", "", "/api", "/", ""},
		{"root prefix untouched", "/api/v1", "", "/", "/api/v1", ""},
		{"empty prefix untouched", "/api/v1", "", "", "/api/v1", ""},
		{"rawpath stripped in lockstep", "/api/a b", "/api/a%20b", "/api", "/a b", "/a%20b"},
		{"diverging rawpath cleared", "/api/x", "/other/x", "/api", "/x", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &url.URL{Path: tt.path, RawPath: tt.rawPath}
			stripRequestPrefix(u, tt.prefix)
			if u.Path != tt.wantPath {
				t.Errorf("Path = %q, want %q", u.Path, tt.wantPath)
			}
			if u.RawPath != tt.wantRawPath {
				t.Errorf("RawPath = %q, want %q", u.RawPath, tt.wantRawPath)
			}
		})
	}
}

func TestEnsureLeadingSlash(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", "/"},
		{"v1", "/v1"},
		{"/v1", "/v1"},
	}
	for _, tt := range tests {
		if got := ensureLeadingSlash(tt.in); got != tt.want {
			t.Errorf("ensureLeadingSlash(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestWriteJSONError(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSONError(rec, testLogger(), http.StatusForbidden, "forbidden", "why")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	var body errorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Error != "forbidden" || body.Reason != "why" {
		t.Fatalf("body = %+v", body)
	}
}

func TestWriteJSONErrorFailingWriter(t *testing.T) {
	// A writer that fails must not panic; the encode error is logged.
	writeJSONError(&failingResponseWriter{}, testLogger(), http.StatusNotFound, "no route", "")
}

// failingResponseWriter fails every write to exercise the encode error path.
type failingResponseWriter struct{ header http.Header }

func (f *failingResponseWriter) Header() http.Header {
	if f.header == nil {
		f.header = http.Header{}
	}
	return f.header
}

func (f *failingResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("client gone")
}

func (f *failingResponseWriter) WriteHeader(int) {}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url %q: %v", raw, err)
	}
	return u
}
