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
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
)

// IAMServiceHealthChecker wraps the IAMService for health checking.
type IAMServiceHealthChecker struct {
	service *IAMService
}

// NewIAMServiceHealthChecker creates a new health checker for the IAM service.
func NewIAMServiceHealthChecker(service *IAMService) *IAMServiceHealthChecker {
	if service == nil {
		return nil
	}
	return &IAMServiceHealthChecker{
		service: service,
	}
}

// Name returns the name of the IAM service.
func (c *IAMServiceHealthChecker) Name() string {
	return "iam"
}

// Check performs a health check on the IAM service.
func (c *IAMServiceHealthChecker) Check(ctx context.Context) health.ComponentHealth {
	start := time.Now()
	componentHealth := health.ComponentHealth{
		Name:        c.Name(),
		Status:      health.StatusUnknown,
		LastChecked: start,
		Details:     make(map[string]any),
	}

	if c.service == nil {
		componentHealth.Status = health.StatusUnhealthy
		componentHealth.Message = "IAM service reference is nil"
		componentHealth.Duration = time.Since(start)
		return componentHealth
	}

	if !c.service.IsRunning() {
		componentHealth.Status = health.StatusUnhealthy
		componentHealth.Message = "IAM service is not running"
		componentHealth.Details["running"] = false
		componentHealth.Duration = time.Since(start)
		return componentHealth
	}

	componentHealth.Details["running"] = true

	componentHealth.Status = health.StatusHealthy
	componentHealth.Message = "IAM service is healthy"
	componentHealth.Duration = time.Since(start)
	componentHealth.Details["response_time_ms"] = float64(componentHealth.Duration.Microseconds()) / 1000.0

	return componentHealth
}
