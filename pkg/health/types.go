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

package health

import (
	"encoding/json"
	"time"
)

// HealthStatus represents the health status of a component or system.
type HealthStatus string

const (
	// StatusHealthy indicates the component is fully operational.
	StatusHealthy HealthStatus = "healthy"

	// StatusDegraded indicates the component is operational but with reduced capability.
	StatusDegraded HealthStatus = "degraded"

	// StatusUnhealthy indicates the component is not operational.
	StatusUnhealthy HealthStatus = "unhealthy"

	// StatusUnknown indicates the health status could not be determined.
	StatusUnknown HealthStatus = "unknown"
)

// String returns the string representation of the health status.
func (s HealthStatus) String() string {
	return string(s)
}

// IsHealthy returns true if the status indicates healthy operation.
func (s HealthStatus) IsHealthy() bool {
	return s == StatusHealthy
}

// IsDegraded returns true if the status indicates degraded operation.
func (s HealthStatus) IsDegraded() bool {
	return s == StatusDegraded
}

// IsUnhealthy returns true if the status indicates unhealthy operation.
func (s HealthStatus) IsUnhealthy() bool {
	return s == StatusUnhealthy
}

// IsUnknown returns true if the status is unknown.
func (s HealthStatus) IsUnknown() bool {
	return s == StatusUnknown
}

// MarshalJSON implements json.Marshaler for HealthStatus.
func (s HealthStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(s))
}

// UnmarshalJSON implements json.Unmarshaler for HealthStatus.
func (s *HealthStatus) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	*s = HealthStatus(str)
	return nil
}

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

// DurationString returns a human-readable duration string.
func (c ComponentHealth) DurationString() string {
	return c.Duration.String()
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

// TotalDurationString returns a human-readable total duration string.
func (s SystemHealth) TotalDurationString() string {
	return s.TotalDuration.String()
}

// ComponentCount returns the total number of components.
func (s SystemHealth) ComponentCount() int {
	return len(s.Components)
}

// CheckConfig holds configuration options for health checks.
type CheckConfig struct {
	// Timeout is the maximum time allowed for a single health check.
	Timeout time.Duration

	// Parallel determines whether to run health checks in parallel.
	Parallel bool

	// FailFast stops checking on first failure if true.
	FailFast bool

	// IncludeDetails determines whether to include detailed information.
	IncludeDetails bool
}

// DefaultCheckConfig returns a CheckConfig with sensible defaults.
func DefaultCheckConfig() CheckConfig {
	return CheckConfig{
		Timeout:        30 * time.Second,
		Parallel:       true,
		FailFast:       false,
		IncludeDetails: true,
	}
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

// ThresholdConfig holds threshold values for resource-based health checks.
type ThresholdConfig struct {
	// WarningThreshold is the threshold at which status becomes degraded.
	WarningThreshold float64

	// CriticalThreshold is the threshold at which status becomes unhealthy.
	CriticalThreshold float64
}

// DiskThresholdConfig holds threshold configuration for disk health checks.
type DiskThresholdConfig struct {
	// UsageWarning is the disk usage percentage that triggers degraded status.
	UsageWarning float64

	// UsageCritical is the disk usage percentage that triggers unhealthy status.
	UsageCritical float64

	// MinFreeBytes is the minimum free bytes required for healthy status.
	MinFreeBytes uint64
}

// DefaultDiskThresholdConfig returns sensible defaults for disk thresholds.
func DefaultDiskThresholdConfig() DiskThresholdConfig {
	return DiskThresholdConfig{
		UsageWarning:  80.0,
		UsageCritical: 95.0,
		MinFreeBytes:  1024 * 1024 * 100, // 100MB
	}
}

// MemoryThresholdConfig holds threshold configuration for memory health checks.
type MemoryThresholdConfig struct {
	// UsageWarning is the memory usage percentage that triggers degraded status.
	UsageWarning float64

	// UsageCritical is the memory usage percentage that triggers unhealthy status.
	UsageCritical float64

	// MinFreeBytes is the minimum free bytes required for healthy status.
	MinFreeBytes uint64
}

// DefaultMemoryThresholdConfig returns sensible defaults for memory thresholds.
func DefaultMemoryThresholdConfig() MemoryThresholdConfig {
	return MemoryThresholdConfig{
		UsageWarning:  80.0,
		UsageCritical: 95.0,
		MinFreeBytes:  1024 * 1024 * 50, // 50MB
	}
}

// GoroutineThresholdConfig holds threshold configuration for goroutine health checks.
type GoroutineThresholdConfig struct {
	// WarningCount is the goroutine count that triggers degraded status.
	WarningCount int

	// CriticalCount is the goroutine count that triggers unhealthy status.
	CriticalCount int
}

// DefaultGoroutineThresholdConfig returns sensible defaults for goroutine thresholds.
func DefaultGoroutineThresholdConfig() GoroutineThresholdConfig {
	return GoroutineThresholdConfig{
		WarningCount:  1000,
		CriticalCount: 10000,
	}
}
