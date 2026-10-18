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

package daemon

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"
)

// NOTE: TestDaemon_stopServer was removed as part of Unix IPC refactoring.
// The Unix socket server was replaced with gRPC over Unix Domain Sockets.

func TestDaemon_autoStartServices(t *testing.T) {
	t.Run("starts only enabled services", func(t *testing.T) {
		config := testConfig("/tmp/test-daemon-autostart-enabled.sock")

		// Configure one enabled and one disabled service
		config.Services = map[string]ServiceConfig{
			"tpm": {
				Enabled:    true,
				AutoStart:  true,
				Timeout:    5 * time.Second,
				MaxRetries: 3,
			},
			"dns": {
				Enabled:    false, // Disabled
				AutoStart:  true,
				Timeout:    5 * time.Second,
				MaxRetries: 3,
			},
		}

		// autoStarted closes when the auto-start pass has finished. Waiting on
		// ONE service is not enough here: autoStartServices ranges over
		// d.config.Services, a map, so iteration order is random and svc1
		// having started says nothing about whether svc2 has been reached.
		// That is what made this flaky at -count=3.
		autoStarted := make(chan struct{})
		var autoStartOnce sync.Once
		d, err := New(config, withAutoStartObserver(func() {
			autoStartOnce.Do(func() { close(autoStarted) })
		}))
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}
		defer d.ForceStop()

		// Register both services
		svc1 := newMockService("tpm")
		svc2 := newMockService("dns")

		_ = d.RegisterService(svc1)
		_ = d.RegisterService(svc2)

		ctx := context.Background()
		err = d.Start(ctx)
		if err != nil {
			t.Fatalf("Start() error: %v", err)
		}

		// Wait for the whole pass, not for one service.
		<-autoStarted

		// Only enabled service should be started
		if svc1.startCount.Load() < 1 {
			t.Error("enabled service should have been started")
		}

		if svc2.startCount.Load() > 0 {
			t.Error("disabled service should not have been started")
		}
	})

	t.Run("starts only autostart services", func(t *testing.T) {
		config := testConfig("/tmp/test-daemon-autostart-flag.sock")

		// Configure one with autostart and one without
		config.Services = map[string]ServiceConfig{
			"tpm": {
				Enabled:    true,
				AutoStart:  true, // AutoStart enabled
				Timeout:    5 * time.Second,
				MaxRetries: 3,
			},
			"dns": {
				Enabled:    true,
				AutoStart:  false, // AutoStart disabled
				Timeout:    5 * time.Second,
				MaxRetries: 3,
			},
		}

		// autoStarted closes when the auto-start pass has finished. Waiting on
		// ONE service is not enough here: autoStartServices ranges over
		// d.config.Services, a map, so iteration order is random and svc1
		// having started says nothing about whether svc2 has been reached.
		// That is what made this flaky at -count=3.
		autoStarted := make(chan struct{})
		var autoStartOnce sync.Once
		d, err := New(config, withAutoStartObserver(func() {
			autoStartOnce.Do(func() { close(autoStarted) })
		}))
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}
		defer d.ForceStop()

		// Register both services
		svc1 := newMockService("tpm")
		svc2 := newMockService("dns")

		_ = d.RegisterService(svc1)
		_ = d.RegisterService(svc2)

		ctx := context.Background()
		err = d.Start(ctx)
		if err != nil {
			t.Fatalf("Start() error: %v", err)
		}

		// Wait for the whole pass, not for one service.
		<-autoStarted

		// Only autostart service should be started
		if svc1.startCount.Load() < 1 {
			t.Error("autostart service should have been started")
		}

		if svc2.startCount.Load() > 0 {
			t.Error("non-autostart service should not have been started")
		}
	})

	t.Run("skips unregistered services", func(t *testing.T) {
		config := testConfig("/tmp/test-daemon-autostart-unregistered.sock")

		// Configure service that won't be registered
		config.Services = map[string]ServiceConfig{
			"tpm": {
				Enabled:    true,
				AutoStart:  true,
				Timeout:    5 * time.Second,
				MaxRetries: 3,
			},
			"dns": {
				Enabled:    true,
				AutoStart:  true,
				Timeout:    5 * time.Second,
				MaxRetries: 3,
			},
		}

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}
		defer d.ForceStop()

		// Only register tpm service, not dns
		svc := newMockService("tpm")
		_ = d.RegisterService(svc)

		ctx := context.Background()
		err = d.Start(ctx)
		if err != nil {
			t.Fatalf("Start() error: %v", err)
		}

		// Wait for the auto-start goroutine to start it, rather than assuming
		// 100ms was enough. The count is the real condition.
		svc.awaitStarts(t, 1)

		// Only registered service should be started
		if svc.startCount.Load() < 1 {
			t.Error("registered service should have been started")
		}

		// Verify no panic occurred from unregistered service
		if !d.IsRunning() {
			t.Error("daemon should still be running")
		}
	})

	t.Run("continues on service start error", func(t *testing.T) {
		config := testConfig("/tmp/test-daemon-autostart-error.sock")

		config.Services = map[string]ServiceConfig{
			"tpm": {
				Enabled:    true,
				AutoStart:  true,
				Timeout:    5 * time.Second,
				MaxRetries: 3,
			},
			"dns": {
				Enabled:    true,
				AutoStart:  true,
				Timeout:    5 * time.Second,
				MaxRetries: 3,
			},
		}

		// autoStarted closes when the auto-start pass has finished. Waiting on
		// ONE service is not enough here: autoStartServices ranges over
		// d.config.Services, a map, so iteration order is random and svc1
		// having started says nothing about whether svc2 has been reached.
		// That is what made this flaky at -count=3.
		autoStarted := make(chan struct{})
		var autoStartOnce sync.Once
		d, err := New(config, withAutoStartObserver(func() {
			autoStartOnce.Do(func() { close(autoStarted) })
		}))
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}
		defer d.ForceStop()

		// Register services - first one will fail
		svc1 := newMockService("tpm")
		svc1.startErr = ErrServiceAlreadyRunning{ServiceName: "tpm"}
		svc2 := newMockService("dns")

		_ = d.RegisterService(svc1)
		_ = d.RegisterService(svc2)

		ctx := context.Background()
		err = d.Start(ctx)
		if err != nil {
			t.Fatalf("Start() error: %v", err)
		}

		// Wait for the whole pass, not for one service.
		<-autoStarted

		// Both should have been attempted
		if svc1.startCount.Load() < 1 {
			t.Error("first service should have been attempted")
		}

		if svc2.startCount.Load() < 1 {
			t.Error("second service should have been attempted despite first failing")
		}

		// Daemon should still be running
		if !d.IsRunning() {
			t.Error("daemon should still be running despite service start failure")
		}
	})

	t.Run("handles empty services map", func(t *testing.T) {
		config := testConfig("/tmp/test-daemon-autostart-empty.sock")
		config.Services = map[string]ServiceConfig{} // Empty services

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}
		defer d.ForceStop()

		ctx := context.Background()
		err = d.Start(ctx)
		if err != nil {
			t.Fatalf("Start() error: %v", err)
		}

		// Daemon should be running
		if !d.IsRunning() {
			t.Error("daemon should be running")
		}
	})
}

func TestGetHostname(t *testing.T) {
	t.Run("returns hostname", func(t *testing.T) {
		hostname := getHostname()

		if hostname == "" {
			t.Error("hostname should not be empty")
		}

		// Verify it matches os.Hostname when available
		expected, err := os.Hostname()
		if err == nil && hostname != expected {
			t.Errorf("hostname = %q, want %q", hostname, expected)
		}
	})

	t.Run("returns unknown on error", func(t *testing.T) {
		// This is harder to test directly without mocking os.Hostname,
		// but we can at least verify the function handles errors gracefully
		hostname := getHostname()

		// Should never panic and should return a string
		if hostname == "" {
			t.Error("hostname should not be empty even on error")
		}

		// The actual hostname or "unknown" are both valid
		if hostname != "unknown" {
			// Verify it's a valid hostname
			if _, err := os.Hostname(); err != nil {
				t.Errorf("expected 'unknown' when os.Hostname fails, got %q", hostname)
			}
		}
	})
}

func TestDaemon_New_SocketServerError(t *testing.T) {
	t.Run("returns error on invalid socket configuration", func(t *testing.T) {
		config := testConfig("/nonexistent/directory/that/does/not/exist/daemon.sock")

		d, err := New(config)

		// The socket server creation might not fail immediately,
		// it typically fails on Start(). But if it does fail, verify proper handling.
		if err != nil {
			// Expected in some cases - verify daemon is nil
			if d != nil {
				t.Error("daemon should be nil when New() returns error")
			}
		} else if d != nil {
			// Clean up if created
			_ = d.ForceStop()
		}
	})
}

func TestDaemon_StartStop_RaceCondition(t *testing.T) {
	t.Run("concurrent start and stop operations", func(t *testing.T) {
		config := testConfig("/tmp/test-daemon-race.sock")

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}
		defer d.ForceStop()

		ctx := context.Background()

		// Start daemon
		err = d.Start(ctx)
		if err != nil {
			t.Fatalf("Start() error: %v", err)
		}

		// Attempt concurrent operations. Both readers wait on one start
		// signal so their loops overlap under the race detector.
		start := make(chan struct{})
		done := make(chan bool, 2)

		go func() {
			<-start
			for i := 0; i < 100; i++ {
				_ = d.IsRunning()
			}
			done <- true
		}()

		go func() {
			<-start
			for i := 0; i < 100; i++ {
				_ = d.SocketPath()
			}
			done <- true
		}()

		close(start)

		// Wait for concurrent operations
		<-done
		<-done

		// Stop should still work
		err = d.Stop(ctx)
		if err != nil {
			t.Errorf("Stop() error after concurrent operations: %v", err)
		}
	})
}

func TestDaemon_ServiceRegistration_EdgeCases(t *testing.T) {
	t.Run("register service after daemon started", func(t *testing.T) {
		config := testConfig("/tmp/test-daemon-register-after-start.sock")

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}
		defer d.ForceStop()

		ctx := context.Background()

		// Start daemon first
		err = d.Start(ctx)
		if err != nil {
			t.Fatalf("Start() error: %v", err)
		}

		// Register service after start
		svc := newMockService("test")
		err = d.RegisterService(svc)
		if err != nil {
			t.Errorf("RegisterService() after Start() error: %v", err)
		}

		// Verify service was registered
		if d.Service().services["test"] == nil {
			t.Error("service should be registered")
		}
	})
}

func TestDaemon_Shutdown_WithErrors(t *testing.T) {
	t.Run("shutdown with handler error", func(t *testing.T) {
		config := testConfig("/tmp/test-daemon-shutdown-handler-error.sock")

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}

		// Replace shutdown handler with one that returns error
		d.service.SetShutdownHandler(func() error {
			return ErrShutdownFailed{Reason: "handler failed"}
		})

		ctx := context.Background()

		// Start daemon
		err = d.Start(ctx)
		if err != nil {
			t.Fatalf("Start() error: %v", err)
		}

		// Stop should complete without panicking even with handler error
		_ = d.Stop(ctx)

		// Running flag should be cleared
		if d.running.Load() {
			t.Error("running flag should be cleared after stop")
		}
	})
}
