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

package metrics

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	assert.True(t, config.Enabled)
	assert.Equal(t, "trusted_platform", config.Namespace)
	assert.Equal(t, "/metrics", config.Path)
	assert.Equal(t, 9090, config.Port)
	assert.Equal(t, "localhost", config.Host)
	assert.Equal(t, 15*time.Second, config.CollectInterval)
	assert.True(t, config.EnableRuntimeMetrics)
	assert.True(t, config.EnableProcessMetrics)
	assert.NotNil(t, config.BucketDefaults)
	assert.NotNil(t, config.Labels)
}

func TestDefaultHistogramBuckets(t *testing.T) {
	buckets := DefaultHistogramBuckets()

	assert.NotEmpty(t, buckets.Latency)
	assert.NotEmpty(t, buckets.Size)
	assert.NotEmpty(t, buckets.Duration)

	// Verify latency buckets are in ascending order
	for i := 1; i < len(buckets.Latency); i++ {
		assert.Greater(t, buckets.Latency[i], buckets.Latency[i-1])
	}

	// Verify size buckets are in ascending order
	for i := 1; i < len(buckets.Size); i++ {
		assert.Greater(t, buckets.Size[i], buckets.Size[i-1])
	}

	// Verify duration buckets are in ascending order
	for i := 1; i < len(buckets.Duration); i++ {
		assert.Greater(t, buckets.Duration[i], buckets.Duration[i-1])
	}
}

func TestConfigValidate_Success(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
	}{
		{
			name:   "default config",
			config: DefaultConfig(),
		},
		{
			name: "minimal config",
			config: &Config{
				Enabled:         true,
				Namespace:       "test",
				Path:            "/test-metrics",
				Port:            8080,
				Host:            "0.0.0.0",
				CollectInterval: 5 * time.Second,
			},
		},
		{
			name: "disabled metrics",
			config: &Config{
				Enabled: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			assert.NoError(t, err)
		})
	}
}

func TestConfigValidate_Errors(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError string
	}{
		{
			name: "empty namespace",
			config: &Config{
				Enabled:         true,
				Namespace:       "",
				Path:            "/metrics",
				Port:            9090,
				Host:            "localhost",
				CollectInterval: 15 * time.Second,
			},
			expectError: "Namespace",
		},
		{
			name: "empty path",
			config: &Config{
				Enabled:         true,
				Namespace:       "test",
				Path:            "",
				Port:            9090,
				Host:            "localhost",
				CollectInterval: 15 * time.Second,
			},
			expectError: "Path",
		},
		{
			name: "invalid port - too low",
			config: &Config{
				Enabled:         true,
				Namespace:       "test",
				Path:            "/metrics",
				Port:            0,
				Host:            "localhost",
				CollectInterval: 15 * time.Second,
			},
			expectError: "Port",
		},
		{
			name: "invalid port - too high",
			config: &Config{
				Enabled:         true,
				Namespace:       "test",
				Path:            "/metrics",
				Port:            70000,
				Host:            "localhost",
				CollectInterval: 15 * time.Second,
			},
			expectError: "Port",
		},
		{
			name: "empty host",
			config: &Config{
				Enabled:         true,
				Namespace:       "test",
				Path:            "/metrics",
				Port:            9090,
				Host:            "",
				CollectInterval: 15 * time.Second,
			},
			expectError: "Host",
		},
		{
			name: "invalid collect interval",
			config: &Config{
				Enabled:         true,
				Namespace:       "test",
				Path:            "/metrics",
				Port:            9090,
				Host:            "localhost",
				CollectInterval: 500 * time.Millisecond,
			},
			expectError: "CollectInterval",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			require.Error(t, err)

			var configErr ErrInvalidConfiguration
			require.ErrorAs(t, err, &configErr)
			assert.Contains(t, configErr.Field, tt.expectError)
		})
	}
}

func TestConfigWithSubsystem(t *testing.T) {
	base := DefaultConfig()
	base.Subsystem = "original"

	derived := base.WithSubsystem("api")

	assert.Equal(t, "original", base.Subsystem)
	assert.Equal(t, "api", derived.Subsystem)

	// Verify other fields are copied
	assert.Equal(t, base.Namespace, derived.Namespace)
	assert.Equal(t, base.Port, derived.Port)
	assert.Equal(t, base.Enabled, derived.Enabled)
}

func TestConfigWithLabels(t *testing.T) {
	base := DefaultConfig()
	base.Labels = map[string]string{
		"environment": "test",
		"version":     "1.0",
	}

	newLabels := map[string]string{
		"region": "us-west",
		"zone":   "a",
	}

	derived := base.WithLabels(newLabels)

	// Original should be unchanged
	assert.Len(t, base.Labels, 2)
	assert.Equal(t, "test", base.Labels["environment"])

	// Derived should have all labels
	assert.Len(t, derived.Labels, 4)
	assert.Equal(t, "test", derived.Labels["environment"])
	assert.Equal(t, "1.0", derived.Labels["version"])
	assert.Equal(t, "us-west", derived.Labels["region"])
	assert.Equal(t, "a", derived.Labels["zone"])
}

func TestConfigWithLabels_Overwrite(t *testing.T) {
	base := DefaultConfig()
	base.Labels = map[string]string{
		"environment": "test",
	}

	newLabels := map[string]string{
		"environment": "production",
	}

	derived := base.WithLabels(newLabels)

	// Original should be unchanged
	assert.Equal(t, "test", base.Labels["environment"])

	// Derived should have overwritten value
	assert.Equal(t, "production", derived.Labels["environment"])
}

func TestHistogramBuckets_Coverage(t *testing.T) {
	buckets := DefaultHistogramBuckets()

	// Verify latency buckets cover expected range
	assert.Equal(t, 0.001, buckets.Latency[0])                     // 1ms
	assert.Equal(t, 10.0, buckets.Latency[len(buckets.Latency)-1]) // 10s

	// Verify size buckets cover expected range
	assert.Equal(t, float64(1024), buckets.Size[0])                       // 1KB
	assert.Equal(t, float64(10485760), buckets.Size[len(buckets.Size)-1]) // 10MB

	// Verify duration buckets cover expected range
	assert.Equal(t, float64(1), buckets.Duration[0])                          // 1s
	assert.Equal(t, float64(3600), buckets.Duration[len(buckets.Duration)-1]) // 1h
}
