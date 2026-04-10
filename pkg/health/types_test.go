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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHealthStatus_String(t *testing.T) {
	tests := []struct {
		name     string
		status   HealthStatus
		expected string
	}{
		{
			name:     "healthy status",
			status:   StatusHealthy,
			expected: "healthy",
		},
		{
			name:     "degraded status",
			status:   StatusDegraded,
			expected: "degraded",
		},
		{
			name:     "unhealthy status",
			status:   StatusUnhealthy,
			expected: "unhealthy",
		},
		{
			name:     "unknown status",
			status:   StatusUnknown,
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.status.String())
		})
	}
}

func TestHealthStatus_IsHealthy(t *testing.T) {
	tests := []struct {
		name     string
		status   HealthStatus
		expected bool
	}{
		{name: "healthy", status: StatusHealthy, expected: true},
		{name: "degraded", status: StatusDegraded, expected: false},
		{name: "unhealthy", status: StatusUnhealthy, expected: false},
		{name: "unknown", status: StatusUnknown, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.status.IsHealthy())
		})
	}
}

func TestHealthStatus_IsDegraded(t *testing.T) {
	tests := []struct {
		name     string
		status   HealthStatus
		expected bool
	}{
		{name: "healthy", status: StatusHealthy, expected: false},
		{name: "degraded", status: StatusDegraded, expected: true},
		{name: "unhealthy", status: StatusUnhealthy, expected: false},
		{name: "unknown", status: StatusUnknown, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.status.IsDegraded())
		})
	}
}

func TestHealthStatus_IsUnhealthy(t *testing.T) {
	tests := []struct {
		name     string
		status   HealthStatus
		expected bool
	}{
		{name: "healthy", status: StatusHealthy, expected: false},
		{name: "degraded", status: StatusDegraded, expected: false},
		{name: "unhealthy", status: StatusUnhealthy, expected: true},
		{name: "unknown", status: StatusUnknown, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.status.IsUnhealthy())
		})
	}
}

func TestHealthStatus_IsUnknown(t *testing.T) {
	tests := []struct {
		name     string
		status   HealthStatus
		expected bool
	}{
		{name: "healthy", status: StatusHealthy, expected: false},
		{name: "degraded", status: StatusDegraded, expected: false},
		{name: "unhealthy", status: StatusUnhealthy, expected: false},
		{name: "unknown", status: StatusUnknown, expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.status.IsUnknown())
		})
	}
}

func TestHealthStatus_JSON(t *testing.T) {
	t.Run("marshal", func(t *testing.T) {
		statuses := []HealthStatus{StatusHealthy, StatusDegraded, StatusUnhealthy, StatusUnknown}
		for _, status := range statuses {
			data, err := json.Marshal(status)
			require.NoError(t, err)

			var result string
			err = json.Unmarshal(data, &result)
			require.NoError(t, err)
			assert.Equal(t, status.String(), result)
		}
	})

	t.Run("unmarshal", func(t *testing.T) {
		tests := []struct {
			input    string
			expected HealthStatus
		}{
			{`"healthy"`, StatusHealthy},
			{`"degraded"`, StatusDegraded},
			{`"unhealthy"`, StatusUnhealthy},
			{`"unknown"`, StatusUnknown},
		}

		for _, tt := range tests {
			var status HealthStatus
			err := json.Unmarshal([]byte(tt.input), &status)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, status)
		}
	})

	t.Run("unmarshal invalid", func(t *testing.T) {
		var status HealthStatus
		err := json.Unmarshal([]byte(`123`), &status)
		assert.Error(t, err)
	})
}

func TestComponentHealth_DurationString(t *testing.T) {
	ch := ComponentHealth{
		Duration: 100 * time.Millisecond,
	}
	assert.Equal(t, "100ms", ch.DurationString())
}

func TestSystemHealth_TotalDurationString(t *testing.T) {
	sh := SystemHealth{
		TotalDuration: 500 * time.Millisecond,
	}
	assert.Equal(t, "500ms", sh.TotalDurationString())
}

func TestSystemHealth_ComponentCount(t *testing.T) {
	sh := SystemHealth{
		Components: []ComponentHealth{
			{Name: "comp1"},
			{Name: "comp2"},
			{Name: "comp3"},
		},
	}
	assert.Equal(t, 3, sh.ComponentCount())
}

func TestDefaultCheckConfig(t *testing.T) {
	config := DefaultCheckConfig()

	assert.Equal(t, 30*time.Second, config.Timeout)
	assert.True(t, config.Parallel)
	assert.False(t, config.FailFast)
	assert.True(t, config.IncludeDetails)
}

func TestDefaultRegistryConfig(t *testing.T) {
	config := DefaultRegistryConfig()

	assert.Equal(t, 100, config.MaxCheckers)
	assert.Equal(t, 30*time.Second, config.DefaultTimeout)
}

func TestDefaultDiskThresholdConfig(t *testing.T) {
	config := DefaultDiskThresholdConfig()

	assert.Equal(t, 80.0, config.UsageWarning)
	assert.Equal(t, 95.0, config.UsageCritical)
	assert.Equal(t, uint64(1024*1024*100), config.MinFreeBytes)
}

func TestDefaultMemoryThresholdConfig(t *testing.T) {
	config := DefaultMemoryThresholdConfig()

	assert.Equal(t, 80.0, config.UsageWarning)
	assert.Equal(t, 95.0, config.UsageCritical)
	assert.Equal(t, uint64(1024*1024*50), config.MinFreeBytes)
}

func TestDefaultGoroutineThresholdConfig(t *testing.T) {
	config := DefaultGoroutineThresholdConfig()

	assert.Equal(t, 1000, config.WarningCount)
	assert.Equal(t, 10000, config.CriticalCount)
}
