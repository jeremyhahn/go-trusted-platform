// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package controlplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
)

type stubCollector struct {
	snap *gwstate.Snapshot
	err  error
}

func (c *stubCollector) Collect(_ context.Context) (*gwstate.Snapshot, error) {
	return c.snap, c.err
}

func TestNewReporter_ValidatesConfig(t *testing.T) {
	cases := []struct {
		cfg     ReporterConfig
		wantErr bool
		field   string
	}{
		{
			cfg:     ReporterConfig{GatewayID: "g", Collector: &stubCollector{}},
			wantErr: true,
			field:   "CPBaseURL",
		},
		{
			cfg:     ReporterConfig{CPBaseURL: "http://x", Collector: &stubCollector{}},
			wantErr: true,
			field:   "GatewayID",
		},
		{
			cfg:     ReporterConfig{CPBaseURL: "http://x", GatewayID: "g"},
			wantErr: true,
			field:   "Collector",
		},
	}
	for _, tc := range cases {
		_, err := NewReporter(tc.cfg)
		if !tc.wantErr {
			if err != nil {
				t.Errorf("field %q: unexpected error: %v", tc.field, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("field %q: expected ErrMissingField, got nil", tc.field)
			continue
		}
		e, ok := err.(ErrMissingField)
		if !ok {
			t.Errorf("field %q: expected ErrMissingField, got %T: %v", tc.field, err, err)
			continue
		}
		if e.Field != tc.field {
			t.Errorf("expected missing field %q, got %q", tc.field, e.Field)
		}
	}
	// Happy path with defaults.
	if _, err := NewReporter(ReporterConfig{
		CPBaseURL: "http://x",
		GatewayID: "g",
		Collector: &stubCollector{},
	}); err != nil {
		t.Errorf("happy path: %v", err)
	}
}

func TestNewReporter_DefaultHTTPClientUsesRootCAs(t *testing.T) {
	// When RootCAs is set and no HTTPClient is provided, the default
	// client must carry the pool in its TLS config.
	pool := x509.NewCertPool()

	r, err := NewReporter(ReporterConfig{
		CPBaseURL: "https://cp.example.com:8443",
		GatewayID: "gw-1",
		Collector: &stubCollector{snap: &gwstate.Snapshot{}},
		RootCAs:   pool,
	})
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}

	tr, ok := r.cfg.HTTPClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", r.cfg.HTTPClient.Transport)
	}
	if tr.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig must not be nil when RootCAs is set")
	}
	if tr.TLSClientConfig.RootCAs != pool {
		t.Error("TLSClientConfig.RootCAs does not match the provided pool")
	}
	if tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Error("expected TLS 1.2 minimum version")
	}
}

func TestNewReporter_DefaultHTTPClientNilRootCAsUsesSystemRoots(t *testing.T) {
	// When RootCAs is nil, the default TLS config must have a nil RootCAs
	// field so the system trust store is consulted.
	r, err := NewReporter(ReporterConfig{
		CPBaseURL: "https://cp.example.com:8443",
		GatewayID: "gw-2",
		Collector: &stubCollector{snap: &gwstate.Snapshot{}},
	})
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}

	tr, ok := r.cfg.HTTPClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", r.cfg.HTTPClient.Transport)
	}
	if tr.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig must not be nil")
	}
	if tr.TLSClientConfig.RootCAs != nil {
		t.Error("RootCAs must be nil when not configured (falls back to system roots)")
	}
}

func TestReporter_PushOnce_PostsTelemetry(t *testing.T) {
	var received atomic.Int32
	var mu sync.Mutex
	var lastBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/gateway/telemetry" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		mu.Lock()
		b := make([]byte, r.ContentLength)
		r.Body.Read(b)
		lastBody = b
		mu.Unlock()
		received.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, `{"code":200,"success":true}`)
	}))
	defer srv.Close()

	r, err := NewReporter(ReporterConfig{
		CPBaseURL:  srv.URL,
		GatewayID:  "gw-test",
		HTTPClient: srv.Client(),
		Collector: &stubCollector{snap: &gwstate.Snapshot{
			Hostname: "gw.example",
			Health:   gwstate.HealthState{Status: "healthy"},
		}},
	})
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}
	if err := r.pushOnce(context.Background()); err != nil {
		t.Fatalf("pushOnce: %v", err)
	}
	if received.Load() != 1 {
		t.Errorf("expected 1 POST, got %d", received.Load())
	}
	var got gwstate.Snapshot
	if err := json.Unmarshal(lastBody, &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got.GatewayID != "gw-test" {
		t.Errorf("server received gateway_id = %q, want gw-test", got.GatewayID)
	}
}

func TestReporter_FetchDesiredConfig(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/gateway/desired-config/gw-test" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{"code":200,"success":true,"payload":{"gateway_id":"gw-test","config":{"version":"rev-9","nat":{"snat_internal_cidr":"10.0.100.0/24"}}}}`)
	}))
	defer srv.Close()
	r, _ := NewReporter(ReporterConfig{
		CPBaseURL:  srv.URL,
		GatewayID:  "gw-test",
		HTTPClient: srv.Client(),
		Collector:  &stubCollector{snap: &gwstate.Snapshot{}},
	})
	cfg, err := r.FetchDesiredConfig(context.Background())
	if err != nil {
		t.Fatalf("FetchDesiredConfig: %v", err)
	}
	if cfg.Version != "rev-9" || cfg.NAT == nil || cfg.NAT.SNATInternalCIDR != "10.0.100.0/24" {
		t.Errorf("typed document not decoded: %+v", cfg)
	}
	if cfg.GatewayID != "gw-test" {
		t.Errorf("gateway id should be filled from the envelope, got %q", cfg.GatewayID)
	}
}

// TestReporter_FetchDesiredConfigRefusesWhatItCannotApply: a document
// carrying a section this build does not know, or no document at all, is
// a typed rejection rather than a silently narrowed config.
func TestReporter_FetchDesiredConfigRefusesWhatItCannotApply(t *testing.T) {
	for name, body := range map[string]string{
		"unknown section": `{"code":200,"success":true,"payload":{"gateway_id":"gw-test","config":{"sdn":{"bgp_asn":65001}}}}`,
		"invalid field":   `{"code":200,"success":true,"payload":{"gateway_id":"gw-test","config":{"nat":{"snat_internal_cidr":"nope"}}}}`,
		"no document":     `{"code":200,"success":true,"payload":{"gateway_id":"gw-test"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintln(w, body)
			}))
			defer srv.Close()
			r, _ := NewReporter(ReporterConfig{
				CPBaseURL:  srv.URL,
				GatewayID:  "gw-test",
				HTTPClient: srv.Client(),
				Collector:  &stubCollector{snap: &gwstate.Snapshot{}},
			})
			if _, err := r.FetchDesiredConfig(context.Background()); err == nil {
				t.Fatal("expected a typed rejection")
			}
		})
	}
}

func TestReporter_Start_StopsOnContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	r, _ := NewReporter(ReporterConfig{
		CPBaseURL:  srv.URL,
		GatewayID:  "gw-test",
		Interval:   10 * time.Millisecond,
		HTTPClient: srv.Client(),
		Collector:  &stubCollector{snap: &gwstate.Snapshot{}},
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Start(ctx) }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Errorf("Start returned %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Start did not exit after cancel")
	}
}

// TestReporter_FetchDesiredConfigEscapesGatewayID proves the gateway ID
// is escaped into the path rather than interpolated raw. A configured ID
// containing '/' would otherwise re-target the request at a different
// control-plane route entirely.
func TestReporter_FetchDesiredConfigEscapesGatewayID(t *testing.T) {
	const trickyID = "gw/../state"
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{"code":200,"success":true,"payload":{"config":{}}}`)
	}))
	defer srv.Close()
	r, err := NewReporter(ReporterConfig{
		CPBaseURL:  srv.URL,
		GatewayID:  trickyID,
		HTTPClient: srv.Client(),
		Collector:  &stubCollector{snap: &gwstate.Snapshot{}},
	})
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}
	if _, err := r.FetchDesiredConfig(context.Background()); err != nil {
		t.Fatalf("FetchDesiredConfig: %v", err)
	}
	want := "/api/v1/gateway/desired-config/" + url.PathEscape(trickyID)
	if gotPath != want {
		t.Fatalf("request path = %q, want %q — the gateway ID escaped its path segment", gotPath, want)
	}
}

// TestReporter_TrailingSlashBaseURLHitsTheRoute covers the mild form of
// the base-URL defect. Raw concatenation turned "https://cp/" into
// "https://cp//api/v1/gateway/telemetry"; a leading double slash is a
// different path, and servers that redirect it commonly turn the POST
// into a GET, so telemetry silently stops being recorded.
func TestReporter_TrailingSlashBaseURLHitsTheRoute(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.EscapedPath(), r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r, err := NewReporter(ReporterConfig{
		CPBaseURL:  srv.URL + "/",
		GatewayID:  "gw-test",
		HTTPClient: srv.Client(),
		Collector:  &stubCollector{snap: &gwstate.Snapshot{}},
	})
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}
	if err := r.pushOnce(context.Background()); err != nil {
		t.Fatalf("pushOnce: %v", err)
	}
	if gotPath != "/api/v1/gateway/telemetry" {
		t.Fatalf("request path = %q, want %q", gotPath, "/api/v1/gateway/telemetry")
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("method = %q, want POST", gotMethod)
	}
}

// TestNewReporter_RejectsBaseURLSuffixComponents is the loud form. A
// base carrying a query parses with an EMPTY path, so appending the
// route buried it in the query string and every push went to "/" — the
// reporter started, reported nothing unusual, and never reached the
// control plane. These are refused at construction instead.
func TestNewReporter_RejectsBaseURLSuffixComponents(t *testing.T) {
	cases := map[string]string{
		"query":       "https://cp.example.com:8443?tenant=x",
		"fragment":    "https://cp.example.com:8443#frag",
		"path prefix": "https://cp.example.com:8443/platform",
		"relative":    "cp.example.com:8443",
	}
	for name, base := range cases {
		t.Run(name, func(t *testing.T) {
			rep, err := NewReporter(ReporterConfig{
				CPBaseURL: base,
				GatewayID: "gw-test",
				Collector: &stubCollector{snap: &gwstate.Snapshot{}},
			})
			if err == nil {
				t.Fatalf("NewReporter accepted %q; a base that re-targets the route must be refused", base)
			}
			if rep != nil {
				t.Fatal("a refused base must not yield a reporter")
			}
		})
	}
}

// TestNormalizeBaseURLAgreesWithConfigValidate keeps the two layers from
// drifting. Config.Validate is what an operator sees and carries the
// better messages; normalizeBaseURL is the constructor's own guarantee.
// Encoding the agreement here means a rule added to one and forgotten in
// the other fails a test rather than shipping as a gap.
func TestNormalizeBaseURLAgreesWithConfigValidate(t *testing.T) {
	// https-only bases, so the scheme rule (which normalizeBaseURL
	// deliberately does not enforce) cannot account for a disagreement.
	// Every other rule, userinfo included, must hold at both layers.
	cases := map[string]bool{
		"https://cp.example.com:8443":          true,
		"https://cp.example.com:8443/":         true,
		"https://[fe80::1%25eth0]:8443":        true,
		"https://cp.example.com:8443/platform": false,
		"https://cp.example.com:8443?tenant=x": false,
		"https://cp.example.com:8443#frag":     false,
		"https://user:pw@cp.example.com:8443":  false,
		"https://":                             false,
	}
	for base, wantOK := range cases {
		t.Run(base, func(t *testing.T) {
			cfgErr := (&Config{
				Enabled:  true,
				BaseURL:  base,
				CertFile: "/dev/null",
				KeyFile:  "/dev/null",
			}).Validate()
			_, normErr := normalizeBaseURL(base)
			if (cfgErr == nil) != wantOK {
				t.Fatalf("Config.Validate err = %v, want ok=%v", cfgErr, wantOK)
			}
			if (normErr == nil) != wantOK {
				t.Fatalf("normalizeBaseURL err = %v, want ok=%v", normErr, wantOK)
			}
		})
	}
}

// TestNormalizeBaseURLPreservesIPv6Zone pins the reason the prefix is
// rebuilt through url.URL.String() rather than by concatenating u.Host.
// url.Parse DECODES an RFC 6874 zone identifier into Host, so
// concatenating it produces "[fe80::1%eth0]" — which http.NewRequest
// then refuses to reparse ("invalid URL escape"), failing every push
// against an otherwise valid link-local control plane.
func TestNormalizeBaseURLPreservesIPv6Zone(t *testing.T) {
	const raw = "https://[fe80::1%25eth0]:8443/"

	base, err := normalizeBaseURL(raw)
	if err != nil {
		t.Fatalf("normalizeBaseURL(%q): %v", raw, err)
	}
	if base != "https://[fe80::1%25eth0]:8443" {
		t.Fatalf("normalized = %q, want the zone left percent-encoded", base)
	}
	// The property that actually matters: the result can still be built
	// into a request. A decoded zone fails here, not at normalization.
	req, err := http.NewRequest(http.MethodPost, base+"/api/v1/gateway/telemetry", nil)
	if err != nil {
		t.Fatalf("the normalized base does not survive http.NewRequest: %v", err)
	}
	if req.URL.EscapedPath() != "/api/v1/gateway/telemetry" {
		t.Fatalf("request path = %q, want /api/v1/gateway/telemetry", req.URL.EscapedPath())
	}
}
