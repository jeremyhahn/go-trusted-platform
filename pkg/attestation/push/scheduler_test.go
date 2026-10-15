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
	"testing/synctest"
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

		observer := newPushObserver()

		scheduler, err := NewScheduler(cfg, client, targets,
			WithManifestProvider(provider),
			WithHandler(observer.handle))
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

		// Wait on the push the scheduler actually completed, not on a
		// duration it is assumed to fit inside.
		observer.awaitPushes(t, 1)
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
		// The debounce window runs on synctest time (#284).
		synctest.Test(t, func(t *testing.T) {
			cfg := &SchedulerConfig{
				TriggerType:         TriggerOnChange,
				MaxConcurrentPushes: 1,
				OnChangeDebounce:    10 * time.Millisecond,
			}
			clientCfg := DefaultClientConfig()
			httpClient := &http.Client{Transport: statusTransport(http.StatusOK)}
			client, err := NewClient(clientCfg, WithHTTPClient(httpClient))
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}
			defer client.Close()

			targets := []*PushTarget{
				{ID: "t1", Endpoint: inMemoryEndpoint, Transport: TransportHTTP, Enabled: true},
			}

			provider := NewSimpleManifestProvider("application/json")
			provider.SetManifest("m1", []byte(`{"test":"data"}`))

			observer := newPushObserver()

			scheduler, err := NewScheduler(cfg, client, targets,
				WithManifestProvider(provider),
				WithHandler(observer.handle))
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

			// What is asserted is that the change produced exactly one push.
			observer.awaitPushes(t, 1)

			if err := scheduler.Stop(); err != nil {
				t.Fatalf("Stop() error = %v", err)
			}
			if got := observer.Count(); got != 1 {
				t.Errorf("expected 1 push, got %d", got)
			}
		})
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
		// The debounce window runs on synctest time (#284).
		synctest.Test(t, func(t *testing.T) {
			cfg := &SchedulerConfig{
				TriggerType:         TriggerOnChange,
				MaxConcurrentPushes: 1,
				OnChangeDebounce:    50 * time.Millisecond,
			}
			clientCfg := DefaultClientConfig()
			httpClient := &http.Client{Transport: statusTransport(http.StatusOK)}
			client, err := NewClient(clientCfg, WithHTTPClient(httpClient))
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}
			defer client.Close()

			targets := []*PushTarget{
				{ID: "t1", Endpoint: inMemoryEndpoint, Transport: TransportHTTP, Enabled: true},
			}

			provider := NewSimpleManifestProvider("application/json")
			provider.SetManifest("m1", []byte(`{"test":"data"}`))

			observer := newPushObserver()

			scheduler, err := NewScheduler(cfg, client, targets,
				WithManifestProvider(provider),
				WithHandler(observer.handle))
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

			// Rapid fire changes, issued back to back. The 10ms sleeps that
			// used to separate them were the defect: on a loaded host one of
			// them stretched, the burst was no longer a burst, and what the
			// assertion measured stopped being coalescing at all (#207).
			//
			// What this pins is the coalescing a caller sees: a burst that
			// arrives faster than the scheduler consumes it becomes one push,
			// because NotifyChange's change channel holds a single pending
			// item. It does NOT pin handleChange's pendingDebounce guard: a
			// burst this fast may never reach handleChange more than once.
			// TestSchedulerDebounceWindow pins the guard.
			for i := 0; i < 5; i++ {
				scheduler.NotifyChange()
			}

			observer.awaitPushes(t, 1)

			// Stop before asserting. A second debounce window can only be
			// armed after the first one fires, and it would need another
			// full OnChangeDebounce to push; Stop cancels it before the
			// bubble's clock moves again, so the count below is exact
			// rather than an upper bound.
			if err := scheduler.Stop(); err != nil {
				t.Fatalf("Stop() error = %v", err)
			}
			if got := observer.Count(); got != 1 {
				t.Errorf("a burst of 5 changes must coalesce into 1 push, got %d", got)
			}
		})
	})
}

// TestSchedulerDebounceWindow pins handleChange's pendingDebounce guard and
// the point at which a window is disarmed (#241). Both run through Start and
// NotifyChange, the production path, and wait on the run loop's own decision
// rather than on a wall-clock window.
func TestSchedulerDebounceWindow(t *testing.T) {
	newOnChangeScheduler := func(t *testing.T, endpoint string, debounce time.Duration, observer *changeObserver) *Scheduler {
		t.Helper()

		cfg := &SchedulerConfig{
			TriggerType:         TriggerOnChange,
			MaxConcurrentPushes: 1,
			OnChangeDebounce:    debounce,
		}
		client, err := NewClient(DefaultClientConfig())
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Logf("cleanup: %v", err)
			}
		})

		targets := []*PushTarget{
			{ID: "t1", Endpoint: endpoint, Transport: TransportHTTP, Enabled: true},
		}

		provider := NewSimpleManifestProvider("application/json")
		provider.SetManifest("m1", []byte(`{"test":"data"}`))

		scheduler, err := NewScheduler(cfg, client, targets,
			WithManifestProvider(provider),
			withChangeObserver(observer.handle))
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if err := scheduler.Start(context.Background()); err != nil {
			t.Fatalf("expected no error on start, got %v", err)
		}
		return scheduler
	}

	t.Run("change inside an armed window is suppressed", func(t *testing.T) {
		// The window is far longer than the test, so it is still armed when
		// the second change arrives however slow the host is; nothing pushes.
		observer := newChangeObserver()
		scheduler := newOnChangeScheduler(t, "https://example.com", time.Hour, observer)
		defer func() {
			if err := scheduler.Stop(); err != nil {
				t.Logf("cleanup: %v", err)
			}
		}()

		scheduler.NotifyChange()
		if observer.awaitDecision(t) {
			t.Fatal("the first change must arm a window, not be suppressed")
		}

		// The run loop is free again as soon as the window is armed, so this
		// change reaches handleChange rather than being coalesced in changeCh.
		scheduler.NotifyChange()
		if !observer.awaitDecision(t) {
			t.Error("a change inside an armed window must be suppressed, not arm a second window")
		}
	})

	t.Run("change during an in-flight push arms a new window", func(t *testing.T) {
		entered := make(chan struct{}, changeObserverBuffer)
		release := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			entered <- struct{}{}
			<-release
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()
		defer close(release)

		observer := newChangeObserver()
		scheduler := newOnChangeScheduler(t, server.URL, time.Millisecond, observer)
		defer func() {
			if err := scheduler.Stop(); err != nil {
				t.Logf("cleanup: %v", err)
			}
		}()

		scheduler.NotifyChange()
		if observer.awaitDecision(t) {
			t.Fatal("the first change must arm a window, not be suppressed")
		}

		// The window has elapsed and its push is now held in the server.
		select {
		case <-entered:
		case <-time.After(testDeadline):
			t.Fatalf("debounce window did not push within %s", testDeadline)
		}

		// That push may have read the manifest before this change, so the
		// change must arm a window of its own rather than be dropped.
		scheduler.NotifyChange()
		if observer.awaitDecision(t) {
			t.Error("a change during an in-flight push must arm a new window, not be suppressed")
		}
	})
}

func TestSchedulerPeriodicPush(t *testing.T) {
	t.Run("periodic push triggers on interval", func(t *testing.T) {
		// The push interval runs on synctest time (#284).
		synctest.Test(t, func(t *testing.T) {
			cfg := &SchedulerConfig{
				TriggerType:         TriggerPeriodic,
				PushInterval:        50 * time.Millisecond,
				MaxConcurrentPushes: 1,
			}
			clientCfg := DefaultClientConfig()
			httpClient := &http.Client{Transport: statusTransport(http.StatusOK)}
			client, err := NewClient(clientCfg, WithHTTPClient(httpClient))
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}
			defer client.Close()

			targets := []*PushTarget{
				{ID: "t1", Endpoint: inMemoryEndpoint, Transport: TransportHTTP, Enabled: true},
			}

			provider := NewSimpleManifestProvider("application/json")
			provider.SetManifest("m1", []byte(`{"test":"data"}`))

			observer := newPushObserver()

			scheduler, err := NewScheduler(cfg, client, targets,
				WithManifestProvider(provider),
				WithHandler(observer.handle))
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			ctx := context.Background()
			err = scheduler.Start(ctx)
			if err != nil {
				t.Fatalf("expected no error on start, got %v", err)
			}

			// The property is that the ticker keeps firing, so wait for a
			// second push to actually happen. The old form asserted that two
			// pushes fit inside 150ms of wall clock, and on a loaded host
			// only one did (#207). The interval now only sets how fast they
			// arrive.
			observer.awaitPushes(t, 2)

			if err := scheduler.Stop(); err != nil {
				t.Logf("cleanup: %v", err)
			}
		})
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

		observer := newPushObserver()

		scheduler, err := NewScheduler(cfg, client, targets,
			WithManifestProvider(provider),
			WithHandler(observer.handle))
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

		// The stats are read once the push has completed, not once a
		// hopeful 100ms has elapsed.
		observer.awaitPushes(t, 1)

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

		// No sleep: nothing here observes the cancellation, and IsRunning
		// does not change until Stop is called. Stop joins the scheduler's
		// goroutines, which is the only synchronisation this subtest needs.
		if err := scheduler.Stop(); err != nil {
			t.Errorf("Stop() after cancellation error = %v", err)
		}
		if scheduler.IsRunning() {
			t.Error("scheduler should not report running after Stop")
		}
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

		// Waiting cannot prove a negative, so drive the push directly: with
		// no manifest provider, executePush must return before it counts a
		// push or contacts a target. The server above fails the test if it
		// is ever reached.
		scheduler.executePush(TriggerManual)

		if got := scheduler.Stats().PushCount; got != 0 {
			t.Errorf("expected 0 pushes without a manifest provider, got %d", got)
		}
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

		// This should not trigger a push because HasChanged returns false.
		scheduler.NotifyChange()

		// And again, waiting cannot prove a negative: drive the on-change
		// push directly so the HasChanged guard is provably exercised rather
		// than merely not observed to fire.
		scheduler.executePush(TriggerOnChange)

		if got := scheduler.Stats().PushCount; got != 0 {
			t.Errorf("an unchanged manifest must not push, got %d pushes", got)
		}
	})
}
