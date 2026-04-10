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

//go:build !iam

package daemon

import (
	"context"
	"testing"
)

// TestNewIAMService_Stub tests the NewIAMService stub function.
// This test verifies that when IAM is not enabled (no iam build tag),
// NewIAMService returns nil with an appropriate error.
func TestNewIAMService_Stub(t *testing.T) {
	t.Run("returns error when IAM not enabled", func(t *testing.T) {
		svc, err := NewIAMService(nil, nil)

		if err == nil {
			t.Fatal("expected error when IAM not enabled")
		}

		if svc != nil {
			t.Error("expected nil service when error returned")
		}

		// Verify error type
		errInvalid, ok := err.(ErrInvalidConfig)
		if !ok {
			t.Errorf("expected ErrInvalidConfig, got %T", err)
		}

		expectedReason := "IAM service not enabled (build with -tags iam)"
		if errInvalid.Reason != expectedReason {
			t.Errorf("unexpected error reason: got %q, want %q", errInvalid.Reason, expectedReason)
		}
	})
}

// TestIAMServiceStub_AllMethods tests all methods on the IAMService stub.
// Since NewIAMService returns nil for the stub, we test with a zero-value struct.
func TestIAMServiceStub_AllMethods(t *testing.T) {
	svc := &IAMService{}
	ctx := context.Background()

	t.Run("Start returns nil", func(t *testing.T) {
		err := svc.Start(ctx)
		if err != nil {
			t.Errorf("unexpected error from Start: %v", err)
		}
	})

	t.Run("Stop returns nil", func(t *testing.T) {
		err := svc.Stop(ctx)
		if err != nil {
			t.Errorf("unexpected error from Stop: %v", err)
		}
	})

	t.Run("IsRunning returns false", func(t *testing.T) {
		if svc.IsRunning() {
			t.Error("expected IsRunning to return false")
		}
	})

	t.Run("Name returns iam", func(t *testing.T) {
		name := svc.Name()
		if name != "iam" {
			t.Errorf("expected name 'iam', got %s", name)
		}
	})
}

// TestIAMServiceStub_NilService verifies behavior with nil service pointer.
func TestIAMServiceStub_NilService(t *testing.T) {
	t.Run("nil service is handled gracefully", func(t *testing.T) {
		// First call NewIAMService to verify it returns nil
		svc, err := NewIAMService(nil, nil)

		if err == nil {
			t.Fatal("expected error when IAM not enabled")
		}

		if svc != nil {
			t.Fatal("expected nil service when IAM not enabled")
		}
	})
}

// TestIAMServiceStub_StartStopCycle verifies the start/stop lifecycle.
func TestIAMServiceStub_StartStopCycle(t *testing.T) {
	svc := &IAMService{}
	ctx := context.Background()

	t.Run("start then stop", func(t *testing.T) {
		// Start should succeed (no-op)
		if err := svc.Start(ctx); err != nil {
			t.Errorf("Start failed: %v", err)
		}

		// Stop should succeed (no-op)
		if err := svc.Stop(ctx); err != nil {
			t.Errorf("Stop failed: %v", err)
		}
	})

	t.Run("multiple starts are safe", func(t *testing.T) {
		for i := 0; i < 3; i++ {
			if err := svc.Start(ctx); err != nil {
				t.Errorf("Start %d failed: %v", i, err)
			}
		}
	})

	t.Run("multiple stops are safe", func(t *testing.T) {
		for i := 0; i < 3; i++ {
			if err := svc.Stop(ctx); err != nil {
				t.Errorf("Stop %d failed: %v", i, err)
			}
		}
	})
}

// TestIAMServiceStub_ContextCancellation verifies context handling.
func TestIAMServiceStub_ContextCancellation(t *testing.T) {
	svc := &IAMService{}

	t.Run("cancelled context for Start", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		// Stub should return nil even with cancelled context
		err := svc.Start(ctx)
		if err != nil {
			t.Errorf("Start with cancelled context should not error: %v", err)
		}
	})

	t.Run("cancelled context for Stop", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		// Stub should return nil even with cancelled context
		err := svc.Stop(ctx)
		if err != nil {
			t.Errorf("Stop with cancelled context should not error: %v", err)
		}
	})
}
