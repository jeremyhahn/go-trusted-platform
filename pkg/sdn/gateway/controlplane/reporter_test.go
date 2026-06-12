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
		_, _ = fmt.Fprintln(w, `{"code":200,"success":true,"payload":{"gateway_id":"gw-test","config":{"sdn":{"bgp_asn":65001}}}}`)
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
	if cfg["sdn"] == nil {
		t.Errorf("expected sdn key in config, got %v", cfg)
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
