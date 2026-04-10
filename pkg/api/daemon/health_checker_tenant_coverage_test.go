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

// TestTenantServiceHealthChecker_HealthyPath tests the TenantServiceHealthChecker.Check
// function healthy path to improve coverage on line 433.
// This test requires the 'tenant' build tag to access the full TenantService struct.
func TestTenantServiceHealthChecker_HealthyPath(t *testing.T) {
	t.Run("Check returns healthy when service is running", func(t *testing.T) {
		service := &TenantService{}
		service.running.Store(true)

		checker := NewTenantServiceHealthChecker(service)
		if checker == nil {
			t.Fatal("NewTenantServiceHealthChecker returned nil for valid service")
		}

		result := checker.Check(context.Background())

		if result.Status != health.StatusHealthy {
			t.Errorf("Status = %v, want StatusHealthy", result.Status)
		}
		if result.Message != "tenant service is healthy" {
			t.Errorf("Message = %v, want 'tenant service is healthy'", result.Message)
		}
		if result.Details["running"] != true {
			t.Errorf("Details[running] = %v, want true", result.Details["running"])
		}
		if _, ok := result.Details["response_time_ms"]; !ok {
			t.Error("Details[response_time_ms] should be set for healthy service")
		}
	})

	t.Run("Check returns unhealthy when service is not running", func(t *testing.T) {
		service := &TenantService{}
		service.running.Store(false)

		checker := NewTenantServiceHealthChecker(service)
		result := checker.Check(context.Background())

		if result.Status != health.StatusUnhealthy {
			t.Errorf("Status = %v, want StatusUnhealthy", result.Status)
		}
		if result.Message != "tenant service is not running" {
			t.Errorf("Message = %v, want 'tenant service is not running'", result.Message)
		}
		if result.Details["running"] != false {
			t.Errorf("Details[running] = %v, want false", result.Details["running"])
		}
	})

	t.Run("Check transitions from unhealthy to healthy", func(t *testing.T) {
		service := &TenantService{}
		checker := NewTenantServiceHealthChecker(service)

		// Start stopped
		service.running.Store(false)
		result1 := checker.Check(context.Background())
		if result1.Status != health.StatusUnhealthy {
			t.Errorf("Initial status = %v, want StatusUnhealthy", result1.Status)
		}

		// Transition to running
		service.running.Store(true)
		result2 := checker.Check(context.Background())
		if result2.Status != health.StatusHealthy {
			t.Errorf("After start status = %v, want StatusHealthy", result2.Status)
		}
	})

	t.Run("Check transitions from healthy to unhealthy", func(t *testing.T) {
		service := &TenantService{}
		checker := NewTenantServiceHealthChecker(service)

		// Start running
		service.running.Store(true)
		result1 := checker.Check(context.Background())
		if result1.Status != health.StatusHealthy {
			t.Errorf("Initial status = %v, want StatusHealthy", result1.Status)
		}

		// Transition to stopped
		service.running.Store(false)
		result2 := checker.Check(context.Background())
		if result2.Status != health.StatusUnhealthy {
			t.Errorf("After stop status = %v, want StatusUnhealthy", result2.Status)
		}
	})

	t.Run("Concurrent access is safe", func(t *testing.T) {
		service := &TenantService{}
		service.running.Store(true)
		checker := NewTenantServiceHealthChecker(service)

		done := make(chan bool)
		for i := 0; i < 10; i++ {
			go func() {
				result := checker.Check(context.Background())
				if result.Status != health.StatusHealthy {
					t.Errorf("Status = %v, want StatusHealthy", result.Status)
				}
				done <- true
			}()
		}

		for i := 0; i < 10; i++ {
			<-done
		}
	})
}
