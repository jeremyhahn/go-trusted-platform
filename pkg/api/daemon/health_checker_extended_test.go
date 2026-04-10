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
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
)

func TestIAMServiceHealthChecker_WithStub(t *testing.T) {
	t.Run("Check returns unhealthy for non-running stub", func(t *testing.T) {
		svc := &IAMService{}
		checker := NewIAMServiceHealthChecker(svc)

		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}

		if result.Message != "IAM service is not running" {
			t.Errorf("Message = %v, want 'IAM service is not running'", result.Message)
		}
	})

	t.Run("creates checker for stub service", func(t *testing.T) {
		svc := &IAMService{}
		checker := NewIAMServiceHealthChecker(svc)

		if checker == nil {
			t.Error("NewIAMServiceHealthChecker() should not return nil for stub service")
		}

		if checker.Name() != "iam" {
			t.Errorf("Name() = %v, want iam", checker.Name())
		}
	})
}

func TestTenantServiceHealthChecker_WithStub(t *testing.T) {
	t.Run("Check returns unhealthy for non-running stub", func(t *testing.T) {
		svc := &TenantService{}
		checker := NewTenantServiceHealthChecker(svc)

		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}

		if result.Message != "tenant service is not running" {
			t.Errorf("Message = %v, want 'tenant service is not running'", result.Message)
		}
	})

	t.Run("creates checker for stub service", func(t *testing.T) {
		svc := &TenantService{}
		checker := NewTenantServiceHealthChecker(svc)

		if checker == nil {
			t.Error("NewTenantServiceHealthChecker() should not return nil for stub service")
		}

		if checker.Name() != "tenant" {
			t.Errorf("Name() = %v, want tenant", checker.Name())
		}
	})
}

func TestSDNServiceHealthChecker_WithNilOVS(t *testing.T) {
	t.Run("Check returns unhealthy when OVS client is nil", func(t *testing.T) {
		svc := &SDNService{}
		checker := NewSDNServiceHealthChecker(svc)

		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}

		if result.Message != "OVS client not initialized" {
			t.Errorf("Message = %v, want 'OVS client not initialized'", result.Message)
		}
	})
}

func TestKMSServiceHealthChecker_WithStub(t *testing.T) {
	t.Run("Check returns unhealthy for non-running service", func(t *testing.T) {
		svc := &KMSService{}
		checker := NewKMSServiceHealthChecker(svc)

		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
	})

	t.Run("creates checker for stub service", func(t *testing.T) {
		svc := &KMSService{}
		checker := NewKMSServiceHealthChecker(svc)

		if checker == nil {
			t.Error("NewKMSServiceHealthChecker() should not return nil for service")
		}

		if checker.Name() != "kms" {
			t.Errorf("Name() = %v, want kms", checker.Name())
		}
	})
}
