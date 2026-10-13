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

package workload

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
)

func setupLifecycleManager(t *testing.T, enabled bool) (*LifecycleManager, ChainManager) {
	t.Helper()

	tpm := NewSoftwareTPM()
	cm := NewChainManager(WithTPMDevice(tpm), WithLogger(testLogger()))

	ctx := context.Background()
	cfg := &config.WorkloadConfig{
		Enabled:             enabled,
		PCR:                 14,
		PCRBank:             "sha256",
		IncludeImageDigest:  true,
		IncludeContainerID:  true,
		IncludeWorkloadType: true,
	}

	if err := cm.Initialize(ctx, cfg); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	lm, err := NewLifecycleManager(cm, cfg, WithLifecycleLogger(testLogger()))
	if err != nil {
		t.Fatalf("NewLifecycleManager failed: %v", err)
	}

	return lm, cm
}

func TestNewLifecycleManager(t *testing.T) {
	t.Run("valid creation", func(t *testing.T) {
		tpm := NewSoftwareTPM()
		cm := NewChainManager(WithTPMDevice(tpm), WithLogger(testLogger()))

		ctx := context.Background()
		cfg := testConfig()
		if err := cm.Initialize(ctx, cfg); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		lm, err := NewLifecycleManager(cm, cfg, WithLifecycleLogger(testLogger()))
		if err != nil {
			t.Fatalf("NewLifecycleManager failed: %v", err)
		}

		if lm == nil {
			t.Fatal("lifecycle manager should not be nil")
		}
	})

	t.Run("nil chain manager", func(t *testing.T) {
		cfg := testConfig()
		_, err := NewLifecycleManager(nil, cfg)
		if err == nil {
			t.Error("expected error for nil chain manager")
		}

		_, ok := err.(ErrInvalidConfig)
		if !ok {
			t.Errorf("expected ErrInvalidConfig, got %T", err)
		}
	})

	t.Run("nil config", func(t *testing.T) {
		tpm := NewSoftwareTPM()
		cm := NewChainManager(WithTPMDevice(tpm), WithLogger(testLogger()))

		ctx := context.Background()
		if err := cm.Initialize(ctx, testConfig()); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		_, err := NewLifecycleManager(cm, nil)
		if err == nil {
			t.Error("expected error for nil config")
		}

		_, ok := err.(ErrInvalidConfig)
		if !ok {
			t.Errorf("expected ErrInvalidConfig, got %T", err)
		}
	})
}

func TestLifecycleManager_OnWorkloadStart(t *testing.T) {
	t.Run("valid start with PCR extension", func(t *testing.T) {
		lm, cm := setupLifecycleManager(t, true)
		ctx := context.Background()

		err := lm.OnWorkloadStart(ctx, WorkloadTypeContainer, "container-123", "sha256:abc123")
		if err != nil {
			t.Fatalf("OnWorkloadStart failed: %v", err)
		}

		// Verify chain was extended
		history := cm.GetChainHistory()
		if len(history) != 1 {
			t.Errorf("chain length = %d, want 1", len(history))
		}

		// Verify workload is tracked as active
		if !lm.IsWorkloadActive("container-123") {
			t.Error("workload should be active")
		}

		// Verify event was recorded
		events := lm.GetEventHistory()
		if len(events) != 1 {
			t.Errorf("event count = %d, want 1", len(events))
		}
		if events[0].Type != WorkloadEventStart {
			t.Errorf("event type = %s, want %s", events[0].Type, WorkloadEventStart)
		}
		if events[0].WorkloadID != "container-123" {
			t.Errorf("workload ID = %s, want container-123", events[0].WorkloadID)
		}
		if events[0].ChainEntry == nil {
			t.Error("chain entry should not be nil when enabled")
		}
	})

	t.Run("valid start without PCR extension", func(t *testing.T) {
		lm, cm := setupLifecycleManager(t, false) // PCR extension disabled
		ctx := context.Background()

		err := lm.OnWorkloadStart(ctx, WorkloadTypeVM, "vm-456", "sha256:xyz789")
		if err != nil {
			t.Fatalf("OnWorkloadStart failed: %v", err)
		}

		// Chain should be empty (disabled)
		history := cm.GetChainHistory()
		if history != nil {
			t.Errorf("chain should be empty when disabled, got %d entries", len(history))
		}

		// Workload should still be tracked
		if !lm.IsWorkloadActive("vm-456") {
			t.Error("workload should be active even when PCR extension disabled")
		}

		// Event should be recorded without chain entry
		events := lm.GetEventHistory()
		if len(events) != 1 {
			t.Errorf("event count = %d, want 1", len(events))
		}
		if events[0].ChainEntry != nil {
			t.Error("chain entry should be nil when disabled")
		}
	})

	t.Run("invalid workload type", func(t *testing.T) {
		lm, _ := setupLifecycleManager(t, true)
		ctx := context.Background()

		err := lm.OnWorkloadStart(ctx, WorkloadType("invalid"), "id", "digest")
		if err == nil {
			t.Error("expected error for invalid workload type")
		}

		_, ok := err.(ErrInvalidWorkloadType)
		if !ok {
			t.Errorf("expected ErrInvalidWorkloadType, got %T", err)
		}
	})

	t.Run("empty workload ID", func(t *testing.T) {
		lm, _ := setupLifecycleManager(t, true)
		ctx := context.Background()

		err := lm.OnWorkloadStart(ctx, WorkloadTypeContainer, "", "digest")
		if err == nil {
			t.Error("expected error for empty workload ID")
		}

		_, ok := err.(ErrInvalidWorkloadID)
		if !ok {
			t.Errorf("expected ErrInvalidWorkloadID, got %T", err)
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		lm, _ := setupLifecycleManager(t, true)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := lm.OnWorkloadStart(ctx, WorkloadTypeContainer, "id", "digest")
		if err == nil {
			t.Error("expected error for canceled context")
		}

		_, ok := err.(ErrContextCanceled)
		if !ok {
			t.Errorf("expected ErrContextCanceled, got %T", err)
		}
	})

	t.Run("after close", func(t *testing.T) {
		lm, _ := setupLifecycleManager(t, true)
		if err := lm.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		ctx := context.Background()
		err := lm.OnWorkloadStart(ctx, WorkloadTypeContainer, "id", "digest")
		if err == nil {
			t.Error("expected error after close")
		}
	})
}

func TestLifecycleManager_OnWorkloadStop(t *testing.T) {
	t.Run("valid stop", func(t *testing.T) {
		lm, _ := setupLifecycleManager(t, true)
		ctx := context.Background()

		// Start workload first
		if err := lm.OnWorkloadStart(ctx, WorkloadTypeContainer, "container-123", "sha256:abc123"); err != nil {
			t.Fatalf("OnWorkloadStart failed: %v", err)
		}

		if !lm.IsWorkloadActive("container-123") {
			t.Error("workload should be active after start")
		}

		// Stop workload
		if err := lm.OnWorkloadStop(ctx, WorkloadTypeContainer, "container-123"); err != nil {
			t.Fatalf("OnWorkloadStop failed: %v", err)
		}

		if lm.IsWorkloadActive("container-123") {
			t.Error("workload should not be active after stop")
		}

		// Verify event count
		events := lm.GetEventHistory()
		if len(events) != 2 {
			t.Errorf("event count = %d, want 2", len(events))
		}

		// Verify stop event
		stopEvent := events[1]
		if stopEvent.Type != WorkloadEventStop {
			t.Errorf("event type = %s, want %s", stopEvent.Type, WorkloadEventStop)
		}
	})

	t.Run("stop untracked workload", func(t *testing.T) {
		lm, _ := setupLifecycleManager(t, true)
		ctx := context.Background()

		// Stop without starting (workload not tracked)
		err := lm.OnWorkloadStop(ctx, WorkloadTypeContainer, "untracked-id")
		if err != nil {
			t.Fatalf("OnWorkloadStop failed: %v", err)
		}

		// Event should still be recorded
		events := lm.GetEventHistory()
		if len(events) != 1 {
			t.Errorf("event count = %d, want 1", len(events))
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		lm, _ := setupLifecycleManager(t, true)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := lm.OnWorkloadStop(ctx, WorkloadTypeContainer, "id")
		if err == nil {
			t.Error("expected error for canceled context")
		}

		_, ok := err.(ErrContextCanceled)
		if !ok {
			t.Errorf("expected ErrContextCanceled, got %T", err)
		}
	})

	t.Run("after close", func(t *testing.T) {
		lm, _ := setupLifecycleManager(t, true)
		if err := lm.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		ctx := context.Background()
		err := lm.OnWorkloadStop(ctx, WorkloadTypeContainer, "id")
		if err == nil {
			t.Error("expected error after close")
		}
	})
}

func TestLifecycleManager_GetActiveWorkloads(t *testing.T) {
	t.Run("empty initially", func(t *testing.T) {
		lm, _ := setupLifecycleManager(t, true)

		workloads := lm.GetActiveWorkloads()
		if len(workloads) != 0 {
			t.Errorf("active workloads = %d, want 0", len(workloads))
		}
	})

	t.Run("multiple active workloads", func(t *testing.T) {
		lm, _ := setupLifecycleManager(t, true)
		ctx := context.Background()

		// Start multiple workloads
		if err := lm.OnWorkloadStart(ctx, WorkloadTypeContainer, "c1", "d1"); err != nil {
			t.Fatalf("OnWorkloadStart c1 failed: %v", err)
		}
		if err := lm.OnWorkloadStart(ctx, WorkloadTypeVM, "v1", "d2"); err != nil {
			t.Fatalf("OnWorkloadStart v1 failed: %v", err)
		}
		if err := lm.OnWorkloadStart(ctx, WorkloadTypeContainer, "c2", "d3"); err != nil {
			t.Fatalf("OnWorkloadStart c2 failed: %v", err)
		}

		workloads := lm.GetActiveWorkloads()
		if len(workloads) != 3 {
			t.Errorf("active workloads = %d, want 3", len(workloads))
		}
	})

	t.Run("returns copy", func(t *testing.T) {
		lm, _ := setupLifecycleManager(t, true)
		ctx := context.Background()

		if err := lm.OnWorkloadStart(ctx, WorkloadTypeContainer, "c1", "d1"); err != nil {
			t.Fatalf("OnWorkloadStart failed: %v", err)
		}

		workloads1 := lm.GetActiveWorkloads()
		workloads2 := lm.GetActiveWorkloads()

		// Modify workloads1
		workloads1[0].WorkloadID = "modified"

		// workloads2 should not be affected
		if workloads2[0].WorkloadID == "modified" {
			t.Error("GetActiveWorkloads should return a copy")
		}
	})
}

func TestLifecycleManager_GetEventHistory(t *testing.T) {
	t.Run("correct order", func(t *testing.T) {
		lm, _ := setupLifecycleManager(t, true)
		ctx := context.Background()

		// Create a sequence of events
		if err := lm.OnWorkloadStart(ctx, WorkloadTypeContainer, "c1", "d1"); err != nil {
			t.Fatalf("OnWorkloadStart c1 failed: %v", err)
		}
		if err := lm.OnWorkloadStart(ctx, WorkloadTypeVM, "v1", "d2"); err != nil {
			t.Fatalf("OnWorkloadStart v1 failed: %v", err)
		}
		if err := lm.OnWorkloadStop(ctx, WorkloadTypeContainer, "c1"); err != nil {
			t.Fatalf("OnWorkloadStop c1 failed: %v", err)
		}

		events := lm.GetEventHistory()
		if len(events) != 3 {
			t.Errorf("event count = %d, want 3", len(events))
		}

		// Verify order
		if events[0].Type != WorkloadEventStart || events[0].WorkloadID != "c1" {
			t.Error("first event should be start c1")
		}
		if events[1].Type != WorkloadEventStart || events[1].WorkloadID != "v1" {
			t.Error("second event should be start v1")
		}
		if events[2].Type != WorkloadEventStop || events[2].WorkloadID != "c1" {
			t.Error("third event should be stop c1")
		}
	})

	t.Run("returns copy", func(t *testing.T) {
		lm, _ := setupLifecycleManager(t, true)
		ctx := context.Background()

		if err := lm.OnWorkloadStart(ctx, WorkloadTypeContainer, "c1", "d1"); err != nil {
			t.Fatalf("OnWorkloadStart failed: %v", err)
		}

		events1 := lm.GetEventHistory()
		events2 := lm.GetEventHistory()

		// Modify events1
		events1[0].WorkloadID = "modified"

		// events2 should not be affected
		if events2[0].WorkloadID == "modified" {
			t.Error("GetEventHistory should return a copy")
		}
	})
}

func TestLifecycleManager_IsWorkloadActive(t *testing.T) {
	lm, _ := setupLifecycleManager(t, true)
	ctx := context.Background()

	if lm.IsWorkloadActive("nonexistent") {
		t.Error("non-existent workload should not be active")
	}

	if err := lm.OnWorkloadStart(ctx, WorkloadTypeContainer, "c1", "d1"); err != nil {
		t.Fatalf("OnWorkloadStart failed: %v", err)
	}

	if !lm.IsWorkloadActive("c1") {
		t.Error("started workload should be active")
	}

	if err := lm.OnWorkloadStop(ctx, WorkloadTypeContainer, "c1"); err != nil {
		t.Fatalf("OnWorkloadStop failed: %v", err)
	}

	if lm.IsWorkloadActive("c1") {
		t.Error("stopped workload should not be active")
	}
}

func TestLifecycleManager_GetEventCount(t *testing.T) {
	lm, _ := setupLifecycleManager(t, true)
	ctx := context.Background()

	if lm.GetEventCount() != 0 {
		t.Error("event count should be 0 initially")
	}

	if err := lm.OnWorkloadStart(ctx, WorkloadTypeContainer, "c1", "d1"); err != nil {
		t.Fatalf("OnWorkloadStart failed: %v", err)
	}
	if lm.GetEventCount() != 1 {
		t.Error("event count should be 1 after start")
	}

	if err := lm.OnWorkloadStop(ctx, WorkloadTypeContainer, "c1"); err != nil {
		t.Fatalf("OnWorkloadStop failed: %v", err)
	}
	if lm.GetEventCount() != 2 {
		t.Error("event count should be 2 after stop")
	}
}

func TestLifecycleManager_GetActiveWorkloadCount(t *testing.T) {
	lm, _ := setupLifecycleManager(t, true)
	ctx := context.Background()

	if lm.GetActiveWorkloadCount() != 0 {
		t.Error("active count should be 0 initially")
	}

	if err := lm.OnWorkloadStart(ctx, WorkloadTypeContainer, "c1", "d1"); err != nil {
		t.Fatalf("OnWorkloadStart c1 failed: %v", err)
	}
	if err := lm.OnWorkloadStart(ctx, WorkloadTypeVM, "v1", "d2"); err != nil {
		t.Fatalf("OnWorkloadStart v1 failed: %v", err)
	}

	if lm.GetActiveWorkloadCount() != 2 {
		t.Error("active count should be 2")
	}

	if err := lm.OnWorkloadStop(ctx, WorkloadTypeContainer, "c1"); err != nil {
		t.Fatalf("OnWorkloadStop failed: %v", err)
	}

	if lm.GetActiveWorkloadCount() != 1 {
		t.Error("active count should be 1 after stop")
	}
}

func TestLifecycleManager_Close(t *testing.T) {
	t.Run("releases resources", func(t *testing.T) {
		lm, _ := setupLifecycleManager(t, true)
		ctx := context.Background()

		// Add some activity
		if err := lm.OnWorkloadStart(ctx, WorkloadTypeContainer, "c1", "d1"); err != nil {
			t.Fatalf("OnWorkloadStart failed: %v", err)
		}

		if err := lm.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		// Operations after close should fail
		err := lm.OnWorkloadStart(ctx, WorkloadTypeContainer, "c2", "d2")
		if err == nil {
			t.Error("expected error after close")
		}
	})

	t.Run("double close is safe", func(t *testing.T) {
		lm, _ := setupLifecycleManager(t, true)

		if err := lm.Close(); err != nil {
			t.Fatalf("first Close failed: %v", err)
		}

		if err := lm.Close(); err != nil {
			t.Fatalf("second Close failed: %v", err)
		}
	})
}

func TestLifecycleHook_Interface(t *testing.T) {
	// Verify LifecycleManager implements LifecycleHook interface (compile-time check)
	var _ LifecycleHook = (*LifecycleManager)(nil)

	lm, _ := setupLifecycleManager(t, true)
	if lm == nil {
		t.Fatal("LifecycleManager should not be nil")
	}
}

func TestWorkloadEventType(t *testing.T) {
	if WorkloadEventStart != "start" {
		t.Errorf("WorkloadEventStart = %s, want start", WorkloadEventStart)
	}
	if WorkloadEventStop != "stop" {
		t.Errorf("WorkloadEventStop = %s, want stop", WorkloadEventStop)
	}
}
