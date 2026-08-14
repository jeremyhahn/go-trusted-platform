package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"testing"
)

func TestEngineStartServesPlainHTTP(t *testing.T) {
	backend := okBackend(t)
	e, _ := newPublicEngine(t, backend.URL)
	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		if err := e.Stop(context.Background()); err != nil {
			t.Errorf("Stop: %v", err)
		}
	})
	status := e.Status()
	if len(status.Listeners) != 1 {
		t.Fatalf("listeners = %d, want 1", len(status.Listeners))
	}
	addr := status.Listeners[0].BoundAddress
	if addr == "" {
		t.Fatal("BoundAddress empty after Start")
	}
	resp, err := http.Get("http://" + addr + "/hello")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	if body := readBody(t, resp); body != "ok" {
		t.Fatalf("body = %q, want ok", body)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestEngineStartTwice(t *testing.T) {
	backend := okBackend(t)
	e, _ := newPublicEngine(t, backend.URL)
	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		if err := e.Stop(context.Background()); err != nil {
			t.Errorf("Stop: %v", err)
		}
	})
	if err := e.Start(); !errors.Is(err, ErrEngineStarted) {
		t.Fatalf("second Start err = %v, want ErrEngineStarted", err)
	}
}

func TestEngineStartBadAddress(t *testing.T) {
	backend := okBackend(t)
	cfg := publicConfig(backend.URL)
	cfg.Listeners = append(cfg.Listeners, ListenerConfig{ID: "bad", Address: "256.256.256.256:1"})
	e, err := New(cfg, Deps{Logger: testLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = e.Start()
	var lerr *ListenerError
	if !errors.As(err, &lerr) {
		t.Fatalf("Start err = %v, want *ListenerError", err)
	}
	if lerr.ID != "bad" {
		t.Fatalf("ListenerError.ID = %q, want bad", lerr.ID)
	}
	// The failed Start must fully roll back so Stop is a no-op and Start can
	// be retried.
	if err := e.Stop(context.Background()); err != nil {
		t.Fatalf("Stop after failed Start: %v", err)
	}
}

func TestEngineServesTLSWithHTTP2(t *testing.T) {
	backend := okBackend(t)
	cert, roots := genTestCert(t)
	cfg := publicConfig(backend.URL)
	e, err := New(cfg, Deps{
		Logger: testLogger(),
		ServerTLS: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		if err := e.Stop(context.Background()); err != nil {
			t.Errorf("Stop: %v", err)
		}
	})
	status := e.Status()
	if !status.Listeners[0].TLS {
		t.Error("ListenerStatus.TLS = false, want true")
	}
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true,
	}}
	resp, err := client.Get("https://" + status.Listeners[0].BoundAddress + "/hello")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	if body := readBody(t, resp); body != "ok" {
		t.Fatalf("body = %q, want ok", body)
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("proto = %s, want HTTP/2", resp.Proto)
	}
}

func TestEngineTLSListenerH1Only(t *testing.T) {
	backend := okBackend(t)
	cert, roots := genTestCert(t)
	cfg := publicConfig(backend.URL)
	cfg.Listeners[0].Protocols = []string{ProtocolH1}
	e, err := New(cfg, Deps{
		Logger: testLogger(),
		ServerTLS: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		if err := e.Stop(context.Background()); err != nil {
			t.Errorf("Stop: %v", err)
		}
	})
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true,
	}}
	resp, err := client.Get("https://" + e.Status().Listeners[0].BoundAddress + "/hello")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	if body := readBody(t, resp); body != "ok" {
		t.Fatalf("body = %q, want ok", body)
	}
	if resp.ProtoMajor != 1 {
		t.Fatalf("proto = %s, want HTTP/1.1 on an h1-only listener", resp.Proto)
	}
}

func TestEngineStopNotStarted(t *testing.T) {
	backend := okBackend(t)
	e, _ := newPublicEngine(t, backend.URL)
	if err := e.Stop(context.Background()); err != nil {
		t.Fatalf("Stop on unstarted engine = %v, want nil", err)
	}
}

func TestServerProtocols(t *testing.T) {
	tests := []struct {
		name   string
		in     []string
		wantH1 bool
		wantH2 bool
	}{
		{"empty enables both", nil, true, true},
		{"h1 only", []string{ProtocolH1}, true, false},
		{"h2 only", []string{ProtocolH2}, false, true},
		{"both explicit", []string{ProtocolH1, ProtocolH2}, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := serverProtocols(tt.in)
			if p.HTTP1() != tt.wantH1 {
				t.Errorf("HTTP1() = %v, want %v", p.HTTP1(), tt.wantH1)
			}
			if p.HTTP2() != tt.wantH2 {
				t.Errorf("HTTP2() = %v, want %v", p.HTTP2(), tt.wantH2)
			}
		})
	}
}
