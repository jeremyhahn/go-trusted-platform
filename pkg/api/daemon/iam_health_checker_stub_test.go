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

	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
)

// TestNewIAMServiceHealthChecker_NilService_Stub tests that passing nil to
// NewIAMServiceHealthChecker returns nil.
func TestNewIAMServiceHealthChecker_NilService_Stub(t *testing.T) {
	checker := NewIAMServiceHealthChecker(nil)
	if checker != nil {
		t.Error("expected nil checker when service is nil")
	}
}

// TestNewIAMServiceHealthChecker_ValidService_Stub tests that passing a valid
// service to NewIAMServiceHealthChecker returns a non-nil checker.
func TestNewIAMServiceHealthChecker_ValidService_Stub(t *testing.T) {
	svc := &IAMService{}
	checker := NewIAMServiceHealthChecker(svc)
	if checker == nil {
		t.Error("expected non-nil checker when service is valid")
	}
}

// TestIAMServiceHealthChecker_Name_Stub tests the Name method.
func TestIAMServiceHealthChecker_Name_Stub(t *testing.T) {
	svc := &IAMService{}
	checker := NewIAMServiceHealthChecker(svc)
	if checker == nil {
		t.Fatal("checker should not be nil")
	}

	name := checker.Name()
	if name != "iam" {
		t.Errorf("expected name 'iam', got %q", name)
	}
}

// TestIAMServiceHealthChecker_Check_NilService_Stub tests Check with nil service.
// This tests the path where the checker is created but service becomes nil.
func TestIAMServiceHealthChecker_Check_NilService_Stub(t *testing.T) {
	// Manually create a checker with nil service
	checker := &IAMServiceHealthChecker{service: nil}

	result := checker.Check(context.Background())

	if result.Status != health.StatusUnhealthy {
		t.Errorf("expected StatusUnhealthy, got %v", result.Status)
	}
	if result.Message != "IAM service reference is nil" {
		t.Errorf("unexpected message: %q", result.Message)
	}
	if result.Duration <= 0 {
		t.Error("expected positive duration")
	}
}

// TestIAMServiceHealthChecker_Check_NotRunning_Stub tests Check when service is not running.
func TestIAMServiceHealthChecker_Check_NotRunning_Stub(t *testing.T) {
	svc := &IAMService{} // Stub always returns false for IsRunning()
	checker := NewIAMServiceHealthChecker(svc)
	if checker == nil {
		t.Fatal("checker should not be nil")
	}

	result := checker.Check(context.Background())

	// In stub mode, IsRunning() always returns false
	if result.Status != health.StatusUnhealthy {
		t.Errorf("expected StatusUnhealthy, got %v", result.Status)
	}
	if result.Message != "IAM service is not running" {
		t.Errorf("unexpected message: %q", result.Message)
	}
	if result.Details["running"] != false {
		t.Error("expected running=false in details")
	}
}

// TestIAMServiceHealthChecker_MultipleChecks_Stub tests that multiple checks work correctly.
func TestIAMServiceHealthChecker_MultipleChecks_Stub(t *testing.T) {
	svc := &IAMService{}
	checker := NewIAMServiceHealthChecker(svc)

	for i := 0; i < 3; i++ {
		result := checker.Check(context.Background())
		if result.Name != "iam" {
			t.Errorf("check %d: unexpected name %q", i, result.Name)
		}
		if result.Status != health.StatusUnhealthy {
			t.Errorf("check %d: expected StatusUnhealthy, got %v", i, result.Status)
		}
	}
}

// TestIAMServiceHealthChecker_ConcurrentChecks_Stub tests that concurrent checks are safe.
func TestIAMServiceHealthChecker_ConcurrentChecks_Stub(t *testing.T) {
	svc := &IAMService{}
	checker := NewIAMServiceHealthChecker(svc)

	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			result := checker.Check(context.Background())
			if result.Name != "iam" {
				t.Errorf("unexpected name in concurrent check: %q", result.Name)
			}
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestIAMServiceHealthChecker_ContextCancelled_Stub tests Check with cancelled context.
func TestIAMServiceHealthChecker_ContextCancelled_Stub(t *testing.T) {
	svc := &IAMService{}
	checker := NewIAMServiceHealthChecker(svc)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Check should still work even with cancelled context
	result := checker.Check(ctx)
	if result.Name != "iam" {
		t.Errorf("unexpected name: %q", result.Name)
	}
	// The check doesn't actually use the context, so it should complete normally
}
