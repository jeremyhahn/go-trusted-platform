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

// TimeUnsyncedMessage is the health message a node reports while its clock
// cannot be trusted. Fleet monitoring keys on it: a node that boots past the
// startup gate under warn-and-continue stays visible here instead of silently
// corrupting attestation freshness, ACME issuance, DANE signature windows,
// and JWT validity.
const TimeUnsyncedMessage = "time-unsynced"

// ntpHealthTimeout bounds the control-socket poll a health check performs so
// a wedged chronyd never stalls the health endpoint.
const ntpHealthTimeout = 5 * time.Second

// NTPServiceHealthChecker reports the node's clock trustworthiness.
type NTPServiceHealthChecker struct {
	backend NTPBackend
}

// NewNTPServiceHealthChecker creates a health checker for time
// synchronization. It returns nil when the node has no `ntp:` section, so the
// component is simply absent rather than permanently unhealthy.
func NewNTPServiceHealthChecker(backend NTPBackend) *NTPServiceHealthChecker {
	if backend == nil {
		return nil
	}
	return &NTPServiceHealthChecker{backend: backend}
}

// Name returns the health component name.
func (c *NTPServiceHealthChecker) Name() string { return "ntp" }

// Check reports healthy only when chronyd disciplines the clock at a usable
// stratum with no post-convergence anomaly. Anything else is degraded and
// carries the time-unsynced marker.
func (c *NTPServiceHealthChecker) Check(ctx context.Context) health.ComponentHealth {
	start := time.Now()
	componentHealth := health.ComponentHealth{
		Name:        c.Name(),
		Status:      health.StatusUnknown,
		LastChecked: start,
		Details:     make(map[string]any),
	}

	if c.backend == nil {
		componentHealth.Status = health.StatusUnhealthy
		componentHealth.Message = "ntp backend reference is nil"
		componentHealth.Duration = time.Since(start)
		return componentHealth
	}

	pollCtx, cancel := context.WithTimeout(ctx, ntpHealthTimeout)
	defer cancel()

	status, err := c.backend.Status(pollCtx)
	if err != nil {
		componentHealth.Status = health.StatusUnhealthy
		componentHealth.Message = TimeUnsyncedMessage + ": " + err.Error()
		componentHealth.Duration = time.Since(start)
		return componentHealth
	}

	componentHealth.Details["synced"] = status.Synced
	componentHealth.Details["stratum"] = status.Stratum
	componentHealth.Details["leap_status"] = status.LeapStatus
	componentHealth.Details["offset_seconds"] = status.OffsetSeconds
	componentHealth.Details["root_dispersion"] = status.RootDispersion
	componentHealth.Details["sources_reachable"] = status.SourcesReachable
	componentHealth.Details["sources_total"] = status.SourcesTotal
	componentHealth.Details["mode"] = status.Mode

	switch {
	case status.Healthy():
		componentHealth.Status = health.StatusHealthy
		componentHealth.Message = "clock synchronized"
	case status.Anomaly:
		componentHealth.Status = health.StatusDegraded
		componentHealth.Message = TimeUnsyncedMessage + ": " + status.AnomalyReason
		componentHealth.Details["anomaly"] = true
	default:
		componentHealth.Status = health.StatusDegraded
		componentHealth.Message = TimeUnsyncedMessage
	}

	componentHealth.Duration = time.Since(start)
	componentHealth.Details["response_time_ms"] = float64(componentHealth.Duration.Microseconds()) / 1000.0
	return componentHealth
}
