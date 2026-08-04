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

// Package health provides the platform component-health registry layered on
// the shared quicbaas SDK health-probe framework. The status vocabulary is
// the shared quicbaas HealthCheckStatus (plus a platform-local StatusUnknown
// for checks that time out before reporting). The Registry adds platform
// extensions the shared framework does not provide: parallel timeout-bounded
// checks, per-component queries, Details-bearing results, and aggregate
// counts consumed by the platform gRPC/REST health APIs.
package health

import (
	"time"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
)

// HealthStatus represents the health status of a component or system.
// It is an alias of the shared quicbaas SDK health status so platform
// health states interoperate with the stack-wide health-probe framework.
type HealthStatus = quicbaas.HealthCheckStatus

const (
	// StatusHealthy indicates the component is fully operational.
	StatusHealthy = quicbaas.HealthCheckStatusHealthy

	// StatusDegraded indicates the component is operational but with reduced capability.
	StatusDegraded = quicbaas.HealthCheckStatusDegraded

	// StatusUnhealthy indicates the component is not operational.
	StatusUnhealthy = quicbaas.HealthCheckStatusUnhealthy

	// StatusUnknown indicates the health status could not be determined.
	// This is a platform-local extension of the shared status set (e.g.
	// reported when a check times out before producing a result).
	StatusUnknown HealthStatus = "unknown"
)

// ComponentHealth represents the health status of a single component.
type ComponentHealth struct {
	// Name is the unique identifier for the component.
	Name string `json:"name"`

	// Status is the current health status of the component.
	Status HealthStatus `json:"status"`

	// Message provides human-readable information about the health status.
	Message string `json:"message,omitempty"`

	// LastChecked is the timestamp of the last health check.
	LastChecked time.Time `json:"last_checked"`

	// Duration is how long the health check took to complete.
	Duration time.Duration `json:"duration_ns"`

	// Details contains additional component-specific health information.
	Details map[string]any `json:"details,omitempty"`
}

// SystemHealth represents the aggregate health status of the entire system.
type SystemHealth struct {
	// Status is the overall health status of the system.
	Status HealthStatus `json:"status"`

	// Components contains health information for each registered component.
	Components []ComponentHealth `json:"components"`

	// Timestamp is when this health check was performed.
	Timestamp time.Time `json:"timestamp"`

	// TotalDuration is the total time taken to perform all health checks.
	TotalDuration time.Duration `json:"total_duration_ns"`

	// HealthyCount is the number of healthy components.
	HealthyCount int `json:"healthy_count"`

	// DegradedCount is the number of degraded components.
	DegradedCount int `json:"degraded_count"`

	// UnhealthyCount is the number of unhealthy components.
	UnhealthyCount int `json:"unhealthy_count"`

	// UnknownCount is the number of components with unknown status.
	UnknownCount int `json:"unknown_count"`
}

// RegistryConfig holds configuration options for the health registry.
type RegistryConfig struct {
	// MaxCheckers is the maximum number of health checkers that can be registered.
	// A value of 0 means unlimited.
	MaxCheckers int

	// DefaultTimeout is the default timeout for health checks.
	DefaultTimeout time.Duration
}

// DefaultRegistryConfig returns a RegistryConfig with sensible defaults.
func DefaultRegistryConfig() RegistryConfig {
	return RegistryConfig{
		MaxCheckers:    100,
		DefaultTimeout: 30 * time.Second,
	}
}
