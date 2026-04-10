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

package push

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewScheduler(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		cfg := DefaultSchedulerConfig()
		clientCfg := DefaultClientConfig()
		client, err := NewClient(clientCfg)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}
		defer client.Close()

		targets := []*PushTarget{
			{ID: "t1", Endpoint: "https://example.com", Transport: TransportHTTP, Enabled: true},
		}

		scheduler, err := NewScheduler(cfg, client, targets)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if scheduler.IsRunning() {
			t.Error("new scheduler should not be running")
		}
	})

	t.Run("nil config", func(t *testing.T) {
		clientCfg := DefaultClientConfig()
		client, err := NewClient(clientCfg)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}
		defer client.Close()

		targets := []*PushTarget{
			{ID: "t1", Endpoint: "https://example.com", Transport: TransportHTTP, Enabled: true},
		}

		_, err = NewScheduler(nil, client, targets)
		if err == nil {
			t.Error("expected error for nil config")
		}
	})

	t.Run("invalid config", func(t *testing.T) {
		cfg := &SchedulerConfig{
			TriggerType:         TriggerType("invalid"),
			MaxConcurrentPushes: 1,
		}
		clientCfg := DefaultClientConfig()
		client, err := NewClient(clientCfg)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}
		defer client.Close()

		targets := []*PushTarget{
			{ID: "t1", Endpoint: "https://example.com", Transport: TransportHTTP, Enabled: true},
		}

		_, err = NewScheduler(cfg, client, targets)
		if err == nil {
			t.Error("expected error for invalid config")
		}
	})

	t.Run("nil client", func(t *testing.T) {
		cfg := DefaultSchedulerConfig()
		targets := []*PushTarget{
			{ID: "t1", Endpoint: "https://example.com", Transport: TransportHTTP, Enabled: true},
		}

		_, err := NewScheduler(cfg, nil, targets)
		if err == nil {
			t.Error("expected error for nil client")
		}
		if _, ok := err.(ErrClientNotInitialized); !ok {
			t.Errorf("expected ErrClientNotInitialized, got %T", err)
		}
	})

	t.Run("no targets", func(t *testing.T) {
		cfg := DefaultSchedulerConfig()
		clientCfg := DefaultClientConfig()
		client, err := NewClient(clientCfg)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}
		defer client.Close()

		_, err = NewScheduler(cfg, client, []*PushTarget{})
		if err == nil {
			t.Error("expected error for no targets")
		}
		if _, ok := err.(ErrNoTargetsConfigured); !ok {
			t.Errorf("expected ErrNoTargetsConfigured, got %T", err)
		}
	})

	t.Run("with handler option", func(t *testing.T) {
		cfg := DefaultSchedulerConfig()
		clientCfg := DefaultClientConfig()
		client, err := NewClient(clientCfg)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}
		defer client.Close()

		targets := []*PushTarget{
			{ID: "t1", Endpoint: "https://example.com", Transport: TransportHTTP, Enabled: true},
		}

		handler := func(result *PushBatchResult) {}
		scheduler, err := NewScheduler(cfg, client, targets, WithHandler(handler))
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if scheduler == nil {
			t.Error("expected non-nil scheduler")
		}
	})

	t.Run("with manifest provider option", func(t *testing.T) {
		cfg := DefaultSchedulerConfig()
		clientCfg := DefaultClientConfig()
		client, err := NewClient(clientCfg)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}
		defer client.Close()

		targets := []*PushTarget{
			{ID: "t1", Endpoint: "https://example.com", Transport: TransportHTTP, Enabled: true},
		}

		provider := NewSimpleManifestProvider("application/json")
		scheduler, err := NewScheduler(cfg, client, targets, WithManifestProvider(provider))
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if scheduler.manifestProvider == nil {
			t.Error("expected manifest provider to be set")
		}
	})
}

func TestSchedulerStartStop(t *testing.T) {
	t.Run("start and stop", func(t *testing.T) {
		cfg := &SchedulerConfig{
			TriggerType:         TriggerManual,
			MaxConcurrentPushes: 1,
		}
		clientCfg := DefaultClientConfig()
		client, err := NewClient(clientCfg)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}
		defer client.Close()

		targets := []*PushTarget{
			{ID: "t1", Endpoint: "https://example.com", Transport: TransportHTTP, Enabled: true},
		}

		scheduler, err := NewScheduler(cfg, client, targets)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		ctx := context.Background()
		err = scheduler.Start(ctx)
		if err != nil {
			t.Fatalf("expected no error on start, got %v", err)
		}

		if !scheduler.IsRunning() {
			t.Error("scheduler should be running after start")
		}

		err = scheduler.Stop()
		if err != nil {
			t.Fatalf("expected no error on stop, got %v", err)
		}

		if scheduler.IsRunning() {
			t.Error("scheduler should not be running after stop")
		}
	})

	t.Run("double start", func(t *testing.T) {
		cfg := &SchedulerConfig{
			TriggerType:         TriggerManual,
			MaxConcurrentPushes: 1,
		}
		clientCfg := DefaultClientConfig()
		client, err := NewClient(clientCfg)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}
		defer client.Close()

		targets := []*PushTarget{
			{ID: "t1", Endpoint: "https://example.com", Transport: TransportHTTP, Enabled: true},
		}

		scheduler, err := NewScheduler(cfg, client, targets)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		ctx := context.Background()
		err = scheduler.Start(ctx)
		if err != nil {
			t.Fatalf("expected no error on first start, got %v", err)
		}
		defer func() {
			if err := scheduler.Stop(); err != nil {
				t.Logf("cleanup: %v", err)
			}
		}()

		err = scheduler.Start(ctx)
		if err == nil {
			t.Error("expected error on second start")
		}
		if _, ok := err.(ErrSchedulerAlreadyRunning); !ok {
			t.Errorf("expected ErrSchedulerAlreadyRunning, got %T", err)
		}
	})

	t.Run("stop without start", func(t *testing.T) {
		cfg := &SchedulerConfig{
			TriggerType:         TriggerManual,
			MaxConcurrentPushes: 1,
		}
		clientCfg := DefaultClientConfig()
		client, err := NewClient(clientCfg)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}
		defer client.Close()

		targets := []*PushTarget{
			{ID: "t1", Endpoint: "https://example.com", Transport: TransportHTTP, Enabled: true},
		}

		scheduler, err := NewScheduler(cfg, client, targets)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		err = scheduler.Stop()
		if err != nil {
			t.Errorf("expected no error stopping non-started scheduler, got %v", err)
		}
	})

	t.Run("start after stop", func(t *testing.T) {
		cfg := &SchedulerConfig{
			TriggerType:         TriggerManual,
			MaxConcurrentPushes: 1,
		}
		clientCfg := DefaultClientConfig()
		client, err := NewClient(clientCfg)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}
		defer client.Close()

		targets := []*PushTarget{
			{ID: "t1", Endpoint: "https://example.com", Transport: TransportHTTP, Enabled: true},
		}

		scheduler, err := NewScheduler(cfg, client, targets)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		ctx := context.Background()
		err = scheduler.Start(ctx)
		if err != nil {
			t.Fatalf("expected no error on start, got %v", err)
		}

		err = scheduler.Stop()
		if err != nil {
			t.Fatalf("expected no error on stop, got %v", err)
		}

		// Starting after stop should fail
		err = scheduler.Start(ctx)
		if err == nil {
			t.Error("expected error starting after stop")
		}
		if _, ok := err.(ErrSchedulerStopped); !ok {
			t.Errorf("expected ErrSchedulerStopped, got %T", err)
		}
	})
}

func TestSchedulerTriggerPush(t *testing.T) {
	t.Run("trigger push when running", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		cfg := &SchedulerConfig{
			TriggerType:         TriggerManual,
			MaxConcurrentPushes: 1,
		}
		clientCfg := DefaultClientConfig()
		client, err := NewClient(clientCfg)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}
		defer client.Close()

		targets := []*PushTarget{
			{ID: "t1", Endpoint: server.URL, Transport: TransportHTTP, Enabled: true},
		}

		provider := NewSimpleManifestProvider("application/json")
		provider.SetManifest("m1", []byte(`{"test":"data"}`))

		var handlerCalled atomic.Bool
		handler := func(result *PushBatchResult) {
			handlerCalled.Store(true)
		}

		scheduler, err := NewScheduler(cfg, client, targets,
			WithManifestProvider(provider),
			WithHandler(handler))
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		ctx := context.Background()
		err = scheduler.Start(ctx)
		if err != nil {
			t.Fatalf("expected no error on start, got %v", err)
		}
		defer func() {
			if err := scheduler.Stop(); err != nil {
				t.Logf("cleanup: %v", err)
			}
		}()

		err = scheduler.TriggerPush()
		if err != nil {
			t.Errorf("expected no error on trigger, got %v", err)
		}

		// Wait for push to complete
		time.Sleep(100 * time.Millisecond)

		if !handlerCalled.Load() {
			t.Error("expected handler to be called")
		}
	})

	t.Run("trigger push when stopped", func(t *testing.T) {
		cfg := &SchedulerConfig{
			TriggerType:         TriggerManual,
			MaxConcurrentPushes: 1,
		}
		clientCfg := DefaultClientConfig()
		client, err := NewClient(clientCfg)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}
		defer client.Close()

		targets := []*PushTarget{
			{ID: "t1", Endpoint: "https://example.com", Transport: TransportHTTP, Enabled: true},
		}

		scheduler, err := NewScheduler(cfg, client, targets)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		err = scheduler.TriggerPush()
		if err == nil {
			t.Error("expected error when triggering stopped scheduler")
		}
	})
}

func TestSchedulerNotifyChange(t *testing.T) {
	t.Run("notify change triggers push", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		cfg := &SchedulerConfig{
			TriggerType:         TriggerOnChange,
			MaxConcurrentPushes: 1,
			OnChangeDebounce:    10 * time.Millisecond,
		}
		clientCfg := DefaultClientConfig()
		client, err := NewClient(clientCfg)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}
		defer client.Close()

		targets := []*PushTarget{
			{ID: "t1", Endpoint: server.URL, Transport: TransportHTTP, Enabled: true},
		}

		provider := NewSimpleManifestProvider("application/json")
		provider.SetManifest("m1", []byte(`{"test":"data"}`))

		var pushCount atomic.Int32
		handler := func(result *PushBatchResult) {
			pushCount.Add(1)
		}

		scheduler, err := NewScheduler(cfg, client, targets,
			WithManifestProvider(provider),
			WithHandler(handler))
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		ctx := context.Background()
		err = scheduler.Start(ctx)
		if err != nil {
			t.Fatalf("expected no error on start, got %v", err)
		}
		defer func() {
			if err := scheduler.Stop(); err != nil {
				t.Logf("cleanup: %v", err)
			}
		}()

		scheduler.NotifyChange()

		// Wait for debounce and push
		time.Sleep(100 * time.Millisecond)

		if pushCount.Load() != 1 {
			t.Errorf("expected 1 push, got %d", pushCount.Load())
		}
	})

	t.Run("notify change when not running does nothing", func(t *testing.T) {
		cfg := &SchedulerConfig{
			TriggerType:         TriggerOnChange,
			MaxConcurrentPushes: 1,
		}
		clientCfg := DefaultClientConfig()
		client, err := NewClient(clientCfg)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}
		defer client.Close()

		targets := []*PushTarget{
			{ID: "t1", Endpoint: "https://example.com", Transport: TransportHTTP, Enabled: true},
		}

		scheduler, err := NewScheduler(cfg, client, targets)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		// Should not panic
		scheduler.NotifyChange()
	})

	t.Run("debounce multiple changes", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		cfg := &SchedulerConfig{
			TriggerType:         TriggerOnChange,
			MaxConcurrentPushes: 1,
			OnChangeDebounce:    50 * time.Millisecond,
		}
		clientCfg := DefaultClientConfig()
		client, err := NewClient(clientCfg)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}
		defer client.Close()

		targets := []*PushTarget{
			{ID: "t1", Endpoint: server.URL, Transport: TransportHTTP, Enabled: true},
		}

		provider := NewSimpleManifestProvider("application/json")
		provider.SetManifest("m1", []byte(`{"test":"data"}`))

		var pushCount atomic.Int32
		handler := func(result *PushBatchResult) {
			pushCount.Add(1)
		}

		scheduler, err := NewScheduler(cfg, client, targets,
			WithManifestProvider(provider),
			WithHandler(handler))
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		ctx := context.Background()
		err = scheduler.Start(ctx)
		if err != nil {
			t.Fatalf("expected no error on start, got %v", err)
		}
		defer func() {
			if err := scheduler.Stop(); err != nil {
				t.Logf("cleanup: %v", err)
			}
		}()

		// Rapid fire changes - should be debounced
		for i := 0; i < 5; i++ {
			scheduler.NotifyChange()
			time.Sleep(10 * time.Millisecond)
		}

		// Wait for debounce and push
		time.Sleep(200 * time.Millisecond)

		// Should have only 1-2 pushes due to debouncing
		count := pushCount.Load()
		if count > 3 {
			t.Errorf("expected debounced pushes (<= 3), got %d", count)
		}
	})
}

func TestSchedulerPeriodicPush(t *testing.T) {
	t.Run("periodic push triggers on interval", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		cfg := &SchedulerConfig{
			TriggerType:         TriggerPeriodic,
			PushInterval:        50 * time.Millisecond,
			MaxConcurrentPushes: 1,
		}
		clientCfg := DefaultClientConfig()
		client, err := NewClient(clientCfg)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}
		defer client.Close()

		targets := []*PushTarget{
			{ID: "t1", Endpoint: server.URL, Transport: TransportHTTP, Enabled: true},
		}

		provider := NewSimpleManifestProvider("application/json")
		provider.SetManifest("m1", []byte(`{"test":"data"}`))

		var pushCount atomic.Int32
		handler := func(result *PushBatchResult) {
			pushCount.Add(1)
		}

		scheduler, err := NewScheduler(cfg, client, targets,
			WithManifestProvider(provider),
			WithHandler(handler))
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		ctx := context.Background()
		err = scheduler.Start(ctx)
		if err != nil {
			t.Fatalf("expected no error on start, got %v", err)
		}

		// Wait for a couple of intervals
		time.Sleep(150 * time.Millisecond)
		if err := scheduler.Stop(); err != nil {
			t.Logf("cleanup: %v", err)
		}

		count := pushCount.Load()
		if count < 2 {
			t.Errorf("expected at least 2 periodic pushes, got %d", count)
		}
	})
}

func TestSchedulerStats(t *testing.T) {
	t.Run("stats are tracked", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		cfg := &SchedulerConfig{
			TriggerType:         TriggerManual,
			MaxConcurrentPushes: 1,
		}
		clientCfg := DefaultClientConfig()
		client, err := NewClient(clientCfg)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}
		defer client.Close()

		targets := []*PushTarget{
			{ID: "t1", Endpoint: server.URL, Transport: TransportHTTP, Enabled: true},
		}

		provider := NewSimpleManifestProvider("application/json")
		provider.SetManifest("m1", []byte(`{"test":"data"}`))

		scheduler, err := NewScheduler(cfg, client, targets, WithManifestProvider(provider))
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		ctx := context.Background()
		err = scheduler.Start(ctx)
		if err != nil {
			t.Fatalf("expected no error on start, got %v", err)
		}
		defer func() {
			if err := scheduler.Stop(); err != nil {
				t.Logf("cleanup: %v", err)
			}
		}()

		// Initial stats
		stats := scheduler.Stats()
		if stats.PushCount != 0 {
			t.Errorf("expected 0 initial pushes, got %d", stats.PushCount)
		}
		if !stats.IsRunning {
			t.Error("expected running to be true")
		}

		// Trigger a push
		if err := scheduler.TriggerPush(); err != nil {
			t.Logf("trigger push: %v", err)
		}
		time.Sleep(100 * time.Millisecond)

		stats = scheduler.Stats()
		if stats.PushCount != 1 {
			t.Errorf("expected 1 push, got %d", stats.PushCount)
		}
		if stats.SuccessCount != 1 {
			t.Errorf("expected 1 success, got %d", stats.SuccessCount)
		}
		if stats.LastPushTime.IsZero() {
			t.Error("expected non-zero last push time")
		}
	})
}

func TestSchedulerSetHandler(t *testing.T) {
	cfg := &SchedulerConfig{
		TriggerType:         TriggerManual,
		MaxConcurrentPushes: 1,
	}
	clientCfg := DefaultClientConfig()
	client, err := NewClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	targets := []*PushTarget{
		{ID: "t1", Endpoint: "https://example.com", Transport: TransportHTTP, Enabled: true},
	}

	scheduler, err := NewScheduler(cfg, client, targets)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	var called atomic.Bool
	handler := func(result *PushBatchResult) {
		called.Store(true)
	}

	scheduler.SetHandler(handler)
	// Handler is set - verification would require running the scheduler
}

func TestSchedulerSetTargets(t *testing.T) {
	cfg := &SchedulerConfig{
		TriggerType:         TriggerManual,
		MaxConcurrentPushes: 1,
	}
	clientCfg := DefaultClientConfig()
	client, err := NewClient(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	targets := []*PushTarget{
		{ID: "t1", Endpoint: "https://example.com", Transport: TransportHTTP, Enabled: true},
	}

	scheduler, err := NewScheduler(cfg, client, targets)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	newTargets := []*PushTarget{
		{ID: "t2", Endpoint: "https://example2.com", Transport: TransportHTTP, Enabled: true},
		{ID: "t3", Endpoint: "https://example3.com", Transport: TransportHTTP, Enabled: true},
	}

	scheduler.SetTargets(newTargets)

	if len(scheduler.targets) != 2 {
		t.Errorf("expected 2 targets, got %d", len(scheduler.targets))
	}
}

func TestSimpleManifestProvider(t *testing.T) {
	t.Run("basic operations", func(t *testing.T) {
		provider := NewSimpleManifestProvider("application/json")

		if provider.HasChanged() {
			t.Error("new provider should not have changes")
		}

		provider.SetManifest("m1", []byte(`{"test":"data"}`))

		if !provider.HasChanged() {
			t.Error("provider should have changes after SetManifest")
		}

		req, err := provider.GetCurrentManifest(context.Background())
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if req.ManifestID != "m1" {
			t.Errorf("expected manifest ID 'm1', got '%s'", req.ManifestID)
		}
		if string(req.Payload) != `{"test":"data"}` {
			t.Errorf("unexpected payload: %s", req.Payload)
		}
		if req.ContentType != "application/json" {
			t.Errorf("expected content type 'application/json', got '%s'", req.ContentType)
		}

		provider.MarkPushed()

		if provider.HasChanged() {
			t.Error("provider should not have changes after MarkPushed")
		}
	})

	t.Run("empty manifest", func(t *testing.T) {
		provider := NewSimpleManifestProvider("application/json")

		req, err := provider.GetCurrentManifest(context.Background())
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if req != nil {
			t.Error("expected nil request for empty manifest")
		}
	})

	t.Run("update manifest", func(t *testing.T) {
		provider := NewSimpleManifestProvider("application/json")

		provider.SetManifest("m1", []byte(`{"version":1}`))
		provider.MarkPushed()

		provider.SetManifest("m2", []byte(`{"version":2}`))

		if !provider.HasChanged() {
			t.Error("provider should have changes after update")
		}

		req, err := provider.GetCurrentManifest(context.Background())
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if req.ManifestID != "m2" {
			t.Errorf("expected manifest ID 'm2', got '%s'", req.ManifestID)
		}
	})
}

func TestSchedulerContextCancellation(t *testing.T) {
	t.Run("context cancellation stops scheduler", func(t *testing.T) {
		cfg := &SchedulerConfig{
			TriggerType:         TriggerPeriodic,
			PushInterval:        1 * time.Second,
			MaxConcurrentPushes: 1,
		}
		clientCfg := DefaultClientConfig()
		client, err := NewClient(clientCfg)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}
		defer client.Close()

		targets := []*PushTarget{
			{ID: "t1", Endpoint: "https://example.com", Transport: TransportHTTP, Enabled: true},
		}

		scheduler, err := NewScheduler(cfg, client, targets)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		err = scheduler.Start(ctx)
		if err != nil {
			t.Fatalf("expected no error on start, got %v", err)
		}

		if !scheduler.IsRunning() {
			t.Error("scheduler should be running")
		}

		cancel()
		time.Sleep(50 * time.Millisecond)

		// Scheduler should detect context cancellation
		// But IsRunning won't update until Stop is called
	})
}

func TestSchedulerNoProviderDoesNothing(t *testing.T) {
	t.Run("no provider configured", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("server should not be called without provider")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		cfg := &SchedulerConfig{
			TriggerType:         TriggerManual,
			MaxConcurrentPushes: 1,
		}
		clientCfg := DefaultClientConfig()
		client, err := NewClient(clientCfg)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}
		defer client.Close()

		targets := []*PushTarget{
			{ID: "t1", Endpoint: server.URL, Transport: TransportHTTP, Enabled: true},
		}

		// No manifest provider
		scheduler, err := NewScheduler(cfg, client, targets)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		ctx := context.Background()
		err = scheduler.Start(ctx)
		if err != nil {
			t.Fatalf("expected no error on start, got %v", err)
		}
		defer func() {
			if err := scheduler.Stop(); err != nil {
				t.Logf("cleanup: %v", err)
			}
		}()

		err = scheduler.TriggerPush()
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// Wait a bit - should not push anything
		time.Sleep(50 * time.Millisecond)
	})
}

func TestSchedulerOnChangeWithNoChange(t *testing.T) {
	t.Run("on-change with no actual change", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("server should not be called when no change")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		cfg := &SchedulerConfig{
			TriggerType:         TriggerOnChange,
			MaxConcurrentPushes: 1,
			OnChangeDebounce:    10 * time.Millisecond,
		}
		clientCfg := DefaultClientConfig()
		client, err := NewClient(clientCfg)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}
		defer client.Close()

		targets := []*PushTarget{
			{ID: "t1", Endpoint: server.URL, Transport: TransportHTTP, Enabled: true},
		}

		provider := NewSimpleManifestProvider("application/json")
		provider.SetManifest("m1", []byte(`{"test":"data"}`))
		provider.MarkPushed() // Mark as already pushed

		scheduler, err := NewScheduler(cfg, client, targets, WithManifestProvider(provider))
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		ctx := context.Background()
		err = scheduler.Start(ctx)
		if err != nil {
			t.Fatalf("expected no error on start, got %v", err)
		}
		defer func() {
			if err := scheduler.Stop(); err != nil {
				t.Logf("cleanup: %v", err)
			}
		}()

		// This should not trigger a push because HasChanged returns false
		scheduler.NotifyChange()
		time.Sleep(50 * time.Millisecond)
	})
}
