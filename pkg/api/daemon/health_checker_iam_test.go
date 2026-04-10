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

//go:build iam

package daemon

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
)

// TestIAMServiceHealthChecker_Running tests the IAM health checker
// when the service is running. This test only runs when built with
// the 'iam' build tag.
func TestIAMServiceHealthChecker_Running(t *testing.T) {
	t.Run("Check returns healthy when service is running", func(t *testing.T) {
		// Create an IAM service and simulate running state
		service := &IAMService{}
		service.running.Store(true)

		checker := NewIAMServiceHealthChecker(service)
		result := checker.Check(context.Background())

		if result.Status != health.StatusHealthy {
			t.Errorf("Status = %v, want StatusHealthy", result.Status)
		}
		if result.Message != "IAM service is healthy" {
			t.Errorf("Message = %v, want 'IAM service is healthy'", result.Message)
		}
		if result.Details["running"] != true {
			t.Errorf("Details[running] = %v, want true", result.Details["running"])
		}
		if _, ok := result.Details["response_time_ms"]; !ok {
			t.Error("Details[response_time_ms] should be set")
		}
	})
}
