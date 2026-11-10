// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package proxysvc

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"

	"github.com/jeremyhahn/go-trusted-platform/pkg/proxy"
)

// fakeAuditClient is a configurable AuditClient that records every emitted
// event and signals a buffered channel per call so goroutine-based
// emissions (SDKAuditSink.Record) can be observed deterministically.
type fakeAuditClient struct {
	err error

	mu  sync.Mutex
	got []*iamsdk.AuditEvent
	sig chan struct{}
}

func newFakeAuditClient() *fakeAuditClient {
	return &fakeAuditClient{sig: make(chan struct{}, 16)}
}

func (f *fakeAuditClient) RecordAsync(ctx context.Context, event *iamsdk.AuditEvent) error {
	f.mu.Lock()
	f.got = append(f.got, event)
	f.mu.Unlock()
	f.sig <- struct{}{}
	return f.err
}

// wait blocks until at least one RecordAsync call has landed and returns
// the most recent event.
func (f *fakeAuditClient) wait(t *testing.T) *iamsdk.AuditEvent {
	t.Helper()
	select {
	case <-f.sig:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for RecordAsync")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.got[len(f.got)-1]
}

func (f *fakeAuditClient) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.got)
}

// blockingAuditClient blocks inside RecordAsync until release is closed, so
// tests can prove SDKAuditSink.Record never blocks its caller on it.
type blockingAuditClient struct {
	release chan struct{}
	done    chan struct{}
}

func (b *blockingAuditClient) RecordAsync(ctx context.Context, event *iamsdk.AuditEvent) error {
	<-b.release
	close(b.done)
	return nil
}

// notifyWriter is an io.Writer that buffers everything written to it and
// signals ch on every write, so a test can wait for a specific log line
// without a fixed sleep.
type notifyWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
	ch  chan struct{}
}

func newNotifyWriter() *notifyWriter {
	return &notifyWriter{ch: make(chan struct{}, 16)}
}

func (w *notifyWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	n, err := w.buf.Write(p)
	w.mu.Unlock()
	select {
	case w.ch <- struct{}{}:
	default:
	}
	return n, err
}

func (w *notifyWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// waitForContains blocks until the buffered output contains substr or the
// timeout elapses.
func (w *notifyWriter) waitForContains(t *testing.T, substr string) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		if strings.Contains(w.String(), substr) {
			return
		}
		select {
		case <-w.ch:
		case <-deadline:
			t.Fatalf("timed out waiting for log output containing %q; got: %s", substr, w.String())
		}
	}
}

// --- AuditConfig.Validate ---

func TestAuditConfigValidate(t *testing.T) {
	t.Run("disabled skips validation", func(t *testing.T) {
		c := &AuditConfig{Enabled: false}
		if err := c.Validate(); err != nil {
			t.Fatalf("disabled section should not validate: %v", err)
		}
	})

	t.Run("enabled requires quicbaas-addr", func(t *testing.T) {
		c := &AuditConfig{Enabled: true}
		err := c.Validate()
		var target *ErrAuditConfig
		if !errors.As(err, &target) {
			t.Fatalf("expected *ErrAuditConfig, got %v (%T)", err, err)
		}
		if target.Field != "quicbaas-addr" {
			t.Errorf("field = %q, want quicbaas-addr", target.Field)
		}
	})

	t.Run("enabled with address is valid", func(t *testing.T) {
		c := &AuditConfig{Enabled: true, QuicBaaSAddr: "/run/quicbaas.sock"}
		if err := c.Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

// --- LazyAuditClient ---

func TestNewLazyAuditClient_NilDial(t *testing.T) {
	_, err := NewLazyAuditClient(nil)
	var target *ErrNilDialFunc
	if !errors.As(err, &target) {
		t.Fatalf("expected *ErrNilDialFunc, got %v (%T)", err, err)
	}
}

func TestLazyAuditClient_DialsOnceOnSuccess(t *testing.T) {
	inner := newFakeAuditClient()
	dialCalls := 0
	lazy, err := NewLazyAuditClient(func(ctx context.Context) (AuditClient, error) {
		dialCalls++
		return inner, nil
	})
	if err != nil {
		t.Fatalf("NewLazyAuditClient: %v", err)
	}

	if err := lazy.RecordAsync(context.Background(), &iamsdk.AuditEvent{Action: "a"}); err != nil {
		t.Fatalf("first RecordAsync: %v", err)
	}
	if err := lazy.RecordAsync(context.Background(), &iamsdk.AuditEvent{Action: "b"}); err != nil {
		t.Fatalf("second RecordAsync: %v", err)
	}

	if dialCalls != 1 {
		t.Errorf("dial calls = %d, want 1 (connection reused)", dialCalls)
	}
	if inner.callCount() != 2 {
		t.Errorf("inner call count = %d, want 2", inner.callCount())
	}
}

func TestLazyAuditClient_RetriesAfterDialFailure(t *testing.T) {
	dialCalls := 0
	dialErr := errors.New("connection refused")
	lazy, err := NewLazyAuditClient(func(ctx context.Context) (AuditClient, error) {
		dialCalls++
		return nil, dialErr
	})
	if err != nil {
		t.Fatalf("NewLazyAuditClient: %v", err)
	}

	if err := lazy.RecordAsync(context.Background(), &iamsdk.AuditEvent{}); err == nil {
		t.Fatal("expected error from failed dial")
	} else {
		var target *ErrAuditDialFailed
		if !errors.As(err, &target) {
			t.Fatalf("expected *ErrAuditDialFailed, got %v (%T)", err, err)
		}
	}
	if err := lazy.RecordAsync(context.Background(), &iamsdk.AuditEvent{}); err == nil {
		t.Fatal("expected error from failed dial (second attempt)")
	}
	if dialCalls != 2 {
		t.Errorf("dial calls = %d, want 2 (retry on next call after failure)", dialCalls)
	}
}

// --- NewSDKAuditSink ---

func TestNewSDKAuditSink_NilClient(t *testing.T) {
	_, err := NewSDKAuditSink(SDKAuditSinkConfig{})
	var target *ErrNilAuditClient
	if !errors.As(err, &target) {
		t.Fatalf("expected *ErrNilAuditClient, got %v (%T)", err, err)
	}
}

func TestNewSDKAuditSink_Defaults(t *testing.T) {
	sink, err := NewSDKAuditSink(SDKAuditSinkConfig{Client: newFakeAuditClient()})
	if err != nil {
		t.Fatalf("NewSDKAuditSink: %v", err)
	}
	if sink.service != DefaultAuditService {
		t.Errorf("service = %q, want %q", sink.service, DefaultAuditService)
	}
	if sink.timeout != DefaultAuditTimeout {
		t.Errorf("timeout = %v, want %v", sink.timeout, DefaultAuditTimeout)
	}
	if sink.logger == nil {
		t.Error("logger should default to slog.Default()")
	}
}

var _ proxy.AuditSink = (*SDKAuditSink)(nil)

// --- SDKAuditSink.Record: decision -> event mapping ---

func TestSDKAuditSink_Record_MapsDecisionToEvent(t *testing.T) {
	client := newFakeAuditClient()
	sink, err := NewSDKAuditSink(SDKAuditSinkConfig{
		Client:      client,
		Service:     "test-service",
		Environment: "test-env",
		Logger:      gateTestLogger(),
	})
	if err != nil {
		t.Fatalf("NewSDKAuditSink: %v", err)
	}

	now := time.Now()
	ev := proxy.AuditEvent{
		Time:       now,
		RouteID:    "route-1",
		ClientID:   "client-1",
		DeviceID:   "device-1",
		Zone:       "zone-a",
		Decision:   proxy.DecisionDeny,
		Reason:     "mtls required",
		AuthMethod: "mtls",
		RemoteAddr: "10.0.0.1:1234",
		Method:     "GET",
		Path:       "/api/x",
	}
	sink.Record(context.Background(), ev)

	got := client.wait(t)
	if got.Action != "proxy_route_decision" {
		t.Errorf("Action = %q", got.Action)
	}
	if got.Outcome != iamsdk.AuditOutcomeDenied {
		t.Errorf("Outcome = %v, want AuditOutcomeDenied", got.Outcome)
	}
	if got.Message != "mtls required" {
		t.Errorf("Message = %q", got.Message)
	}
	if !got.Timestamp.Equal(now) {
		t.Errorf("Timestamp = %v, want %v", got.Timestamp, now)
	}
	if got.Actor == nil || got.Actor.ID != "client-1" || got.Actor.IPAddress != "10.0.0.1:1234" {
		t.Errorf("Actor = %+v", got.Actor)
	}
	if got.Resource == nil || got.Resource.ID != "route-1" || got.Resource.Type != "proxy_route" {
		t.Errorf("Resource = %+v", got.Resource)
	}
	if got.Request == nil || got.Request.Method != "GET" || got.Request.Path != "/api/x" {
		t.Errorf("Request = %+v", got.Request)
	}
	if got.Context == nil || got.Context.Service != "test-service" || got.Context.Environment != "test-env" {
		t.Errorf("Context = %+v", got.Context)
	}
	if got.Details["zone"] != "zone-a" || got.Details["device_id"] != "device-1" || got.Details["auth_method"] != "mtls" {
		t.Errorf("Details = %+v", got.Details)
	}
}

func TestAuditOutcome_Mapping(t *testing.T) {
	cases := map[string]iamsdk.AuditOutcome{
		proxy.DecisionAllow:   iamsdk.AuditOutcomeSuccess,
		proxy.DecisionDeny:    iamsdk.AuditOutcomeDenied,
		proxy.DecisionError:   iamsdk.AuditOutcomeError,
		proxy.DecisionNoRoute: iamsdk.AuditOutcomeFailure,
		"unknown-decision":    iamsdk.AuditOutcomeFailure,
	}
	for decision, want := range cases {
		if got := auditOutcome(decision); got != want {
			t.Errorf("auditOutcome(%q) = %v, want %v", decision, got, want)
		}
	}
}

// --- SDKAuditSink.Record: never blocks the caller ---

func TestSDKAuditSink_Record_DoesNotBlock(t *testing.T) {
	client := &blockingAuditClient{release: make(chan struct{}), done: make(chan struct{})}
	sink, err := NewSDKAuditSink(SDKAuditSinkConfig{Client: client, Logger: gateTestLogger()})
	if err != nil {
		t.Fatalf("NewSDKAuditSink: %v", err)
	}

	start := time.Now()
	sink.Record(context.Background(), proxy.AuditEvent{Decision: proxy.DecisionAllow})
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("Record blocked the caller for %v", elapsed)
	}

	close(client.release)
	select {
	case <-client.done:
	case <-time.After(2 * time.Second):
		t.Fatal("detached emission never completed")
	}
}

// --- SDKAuditSink.Record: fail open ---

func TestSDKAuditSink_Record_FailOpenOnEmissionError(t *testing.T) {
	nw := newNotifyWriter()
	logger := slog.New(slog.NewTextHandler(nw, &slog.HandlerOptions{Level: slog.LevelWarn}))
	client := newFakeAuditClient()
	client.err = errors.New("quicbaasd rejected the event")

	sink, err := NewSDKAuditSink(SDKAuditSinkConfig{Client: client, Logger: logger})
	if err != nil {
		t.Fatalf("NewSDKAuditSink: %v", err)
	}

	// Must not panic even though the emission fails.
	sink.Record(context.Background(), proxy.AuditEvent{RouteID: "r1", Decision: proxy.DecisionAllow})

	nw.waitForContains(t, "audit event emission failed")
}

// --- End-to-end: a real proxy.Engine forwards decisions through the seam ---

func TestSDKAuditSink_EngineIntegration(t *testing.T) {
	client := newFakeAuditClient()
	sink, err := NewSDKAuditSink(SDKAuditSinkConfig{Client: client, Logger: gateTestLogger()})
	if err != nil {
		t.Fatalf("NewSDKAuditSink: %v", err)
	}

	engine, err := proxy.New(proxy.Config{
		Listeners: []proxy.ListenerConfig{{ID: "l1", Address: "127.0.0.1:0"}},
		Routes: []proxy.RouteConfig{{
			ID:         "public",
			PathPrefix: "/",
			PoolID:     "p1",
			Auth:       proxy.AuthRequirements{Mode: proxy.AuthModePublic},
		}},
		Pools: []proxy.BackendPoolConfig{{
			ID:       "p1",
			Backends: []proxy.BackendConfig{{URL: "http://127.0.0.1:1"}},
		}},
	}, proxy.Deps{Audit: sink, Logger: gateTestLogger()})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://svc.example.com/anything", nil)
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	got := client.wait(t)
	if got.Resource == nil || got.Resource.ID != "public" {
		t.Errorf("expected the engine's route decision to reach the SDK sink, got Resource = %+v", got.Resource)
	}
}
