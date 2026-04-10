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
	"log/slog"
	"os"
	"testing"
)

// TestNewTenantService_NilApplication tests that NewTenantService returns
// an error when called with a nil application.
func TestNewTenantService_NilApplication(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := NewTenantService(nil, logger)

	if err == nil {
		t.Fatal("expected error when application is nil")
	}

	if svc != nil {
		t.Error("expected nil service when error returned")
	}

	errInvalid, ok := err.(ErrInvalidConfig)
	if !ok {
		t.Errorf("expected ErrInvalidConfig, got %T: %v", err, err)
	}

	expectedReason := "application is required for tenant service"
	if errInvalid.Reason != expectedReason {
		t.Errorf("unexpected error reason: got %q, want %q", errInvalid.Reason, expectedReason)
	}
}

// TestTenantService_IsRunning tests the IsRunning method of TenantService.
func TestTenantService_IsRunning(t *testing.T) {
	// Create a zero-value TenantService to test IsRunning
	svc := &TenantService{
		logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}

	t.Run("initially not running", func(t *testing.T) {
		if svc.IsRunning() {
			t.Error("expected IsRunning to return false initially")
		}
	})

	t.Run("running after start", func(t *testing.T) {
		svc.running.Store(true)
		if !svc.IsRunning() {
			t.Error("expected IsRunning to return true after setting")
		}
	})

	t.Run("not running after stop", func(t *testing.T) {
		svc.running.Store(false)
		if svc.IsRunning() {
			t.Error("expected IsRunning to return false after clearing")
		}
	})
}

// TestTenantService_Name tests the Name method of TenantService.
func TestTenantService_Name(t *testing.T) {
	svc := &TenantService{}

	name := svc.Name()
	if name != "tenant" {
		t.Errorf("expected name 'tenant', got %s", name)
	}
}

// TestTenantService_TenantManager tests the TenantManager accessor.
func TestTenantService_TenantManager(t *testing.T) {
	svc := &TenantService{}

	// When not initialized, TenantManager should return nil
	tm := svc.TenantManager()
	if tm != nil {
		t.Error("expected nil TenantManager when not initialized")
	}
}

// TestTenantService_StartStop tests the Start and Stop lifecycle methods.
func TestTenantService_StartStop(t *testing.T) {
	svc := &TenantService{
		logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}
	ctx := context.Background()

	t.Run("start sets running", func(t *testing.T) {
		err := svc.Start(ctx)
		if err != nil {
			t.Errorf("Start failed: %v", err)
		}
		if !svc.IsRunning() {
			t.Error("expected IsRunning to return true after Start")
		}
	})

	t.Run("start is idempotent", func(t *testing.T) {
		svc.running.Store(true)
		err := svc.Start(ctx)
		if err != nil {
			t.Errorf("Start failed: %v", err)
		}
		if !svc.IsRunning() {
			t.Error("expected IsRunning to remain true")
		}
	})

	t.Run("stop clears running", func(t *testing.T) {
		svc.running.Store(true)
		err := svc.Stop(ctx)
		if err != nil {
			t.Errorf("Stop failed: %v", err)
		}
		if svc.IsRunning() {
			t.Error("expected IsRunning to return false after Stop")
		}
	})

	t.Run("stop is idempotent", func(t *testing.T) {
		svc.running.Store(false)
		err := svc.Stop(ctx)
		if err != nil {
			t.Errorf("Stop failed: %v", err)
		}
		if svc.IsRunning() {
			t.Error("expected IsRunning to remain false")
		}
	})
}

// TestTenantService_StartStopCycle tests a full start/stop cycle.
func TestTenantService_StartStopCycle(t *testing.T) {
	svc := &TenantService{
		logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}
	ctx := context.Background()

	// Initial state
	if svc.IsRunning() {
		t.Error("service should not be running initially")
	}

	// Start
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if !svc.IsRunning() {
		t.Error("service should be running after Start")
	}

	// Stop
	if err := svc.Stop(ctx); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	if svc.IsRunning() {
		t.Error("service should not be running after Stop")
	}

	// Restart
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Restart failed: %v", err)
	}
	if !svc.IsRunning() {
		t.Error("service should be running after restart")
	}
}

// TestTenantService_ContextCancellation tests behavior with cancelled context.
func TestTenantService_ContextCancellation(t *testing.T) {
	svc := &TenantService{
		logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}

	t.Run("cancelled context for Start", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err := svc.Start(ctx)
		if err != nil {
			t.Errorf("Start with cancelled context should not error: %v", err)
		}
	})

	t.Run("cancelled context for Stop", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		svc.running.Store(true)
		err := svc.Stop(ctx)
		if err != nil {
			t.Errorf("Stop with cancelled context should not error: %v", err)
		}
	})
}

// TestTenantService_ConcurrentAccess tests that TenantService is safe for
// concurrent access.
func TestTenantService_ConcurrentAccess(t *testing.T) {
	svc := &TenantService{
		logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}
	ctx := context.Background()

	done := make(chan bool, 20)

	// Concurrent reads
	for i := 0; i < 10; i++ {
		go func() {
			_ = svc.IsRunning()
			_ = svc.Name()
			_ = svc.TenantManager()
			done <- true
		}()
	}

	// Concurrent writes
	for i := 0; i < 5; i++ {
		go func() {
			_ = svc.Start(ctx)
			done <- true
		}()
		go func() {
			_ = svc.Stop(ctx)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 20; i++ {
		<-done
	}
}
