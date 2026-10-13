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
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCollector_Success(t *testing.T) {
	config := DefaultConfig()
	config.Port = 19090 // Use different port to avoid conflicts

	collector, err := NewCollector(config)
	require.NoError(t, err)
	require.NotNil(t, collector)
	assert.NotNil(t, collector.metrics)
	assert.False(t, collector.IsRunning())
}

func TestNewCollector_NilConfig(t *testing.T) {
	collector, err := NewCollector(nil)
	require.NoError(t, err)
	require.NotNil(t, collector)
	assert.NotNil(t, collector.config)
}

func TestNewCollector_DisabledMetrics(t *testing.T) {
	config := DefaultConfig()
	config.Enabled = false

	collector, err := NewCollector(config)
	assert.Error(t, err)
	assert.Nil(t, collector)

	var metricsErr ErrMetricsNotEnabled
	assert.ErrorAs(t, err, &metricsErr)
}

func TestNewCollector_InvalidConfig(t *testing.T) {
	config := DefaultConfig()
	config.Port = 0 // Invalid port

	collector, err := NewCollector(config)
	assert.Error(t, err)
	assert.Nil(t, collector)
}

func TestCollector_StartStop(t *testing.T) {
	config := DefaultConfig()
	config.Port = 19091
	config.CollectInterval = 1 * time.Second // Use valid interval

	collector, err := NewCollector(config)
	require.NoError(t, err)

	ctx := context.Background()

	// Start collector
	err = collector.Start(ctx)
	require.NoError(t, err)
	assert.True(t, collector.IsRunning())

	// Wait a bit for metrics collection
	time.Sleep(200 * time.Millisecond)

	// Verify daemon start time was set
	// (We can't easily verify the actual value without accessing the metric)

	// Stop collector
	err = collector.Stop(ctx)
	require.NoError(t, err)
	assert.False(t, collector.IsRunning())
}

func TestCollector_StartTwice(t *testing.T) {
	config := DefaultConfig()
	config.Port = 19092

	collector, err := NewCollector(config)
	require.NoError(t, err)

	ctx := context.Background()

	err = collector.Start(ctx)
	require.NoError(t, err)
	defer func() {
		if err := collector.Stop(ctx); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	// Try to start again
	err = collector.Start(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already running")
}

func TestCollector_StopBeforeStart(t *testing.T) {
	config := DefaultConfig()
	config.Port = 19093

	collector, err := NewCollector(config)
	require.NoError(t, err)

	ctx := context.Background()

	err = collector.Stop(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not running")
}

func TestCollector_MetricsEndpoint(t *testing.T) {
	config := DefaultConfig()
	config.Port = 19094

	collector, err := NewCollector(config)
	require.NoError(t, err)

	ctx := context.Background()

	err = collector.Start(ctx)
	require.NoError(t, err)
	defer func() {
		if err := collector.Stop(ctx); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(150 * time.Millisecond)

	// Test metrics endpoint
	resp, err := http.Get("http://" + collector.Address() + config.Path)
	require.NoError(t, err)
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/plain")
}

func TestCollector_HealthEndpoint(t *testing.T) {
	config := DefaultConfig()
	config.Port = 19095

	collector, err := NewCollector(config)
	require.NoError(t, err)

	ctx := context.Background()

	err = collector.Start(ctx)
	require.NoError(t, err)
	defer func() {
		if err := collector.Stop(ctx); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(150 * time.Millisecond)

	// Test health endpoint
	resp, err := http.Get("http://" + collector.Address() + "/health")
	require.NoError(t, err)
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestCollector_Metrics(t *testing.T) {
	config := DefaultConfig()
	config.Port = 19096

	collector, err := NewCollector(config)
	require.NoError(t, err)

	metrics := collector.Metrics()
	require.NotNil(t, metrics)
	assert.NotNil(t, metrics.SDNPortStateChanges)
	assert.NotNil(t, metrics.HTTPRequests)
}

func TestCollector_Handler(t *testing.T) {
	configA := DefaultConfig()
	configA.Namespace = "instance_a"
	collectorA, err := NewCollector(configA)
	require.NoError(t, err)

	configB := DefaultConfig()
	configB.Namespace = "instance_b"
	collectorB, err := NewCollector(configB)
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	collectorA.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, configA.Path, nil))

	require.Equal(t, http.StatusOK, recorder.Code)
	body := recorder.Body.String()
	assert.Contains(t, body, "instance_a_")
	assert.Contains(t, body, "go_goroutines")
	assert.NotContains(t, body, "instance_b_")
	assert.NotNil(t, collectorB.Handler())
}

func TestCollector_Address(t *testing.T) {
	config := DefaultConfig()
	config.Host = "127.0.0.1"
	config.Port = 19098

	collector, err := NewCollector(config)
	require.NoError(t, err)

	address := collector.Address()
	assert.Equal(t, "127.0.0.1:19098", address)
}

func TestCollector_RuntimeMetricsCollection(t *testing.T) {
	config := DefaultConfig()
	config.Port = 19099
	config.CollectInterval = 1 * time.Second // Use valid interval
	config.EnableRuntimeMetrics = true

	collector, err := NewCollector(config)
	require.NoError(t, err)

	ctx := context.Background()

	err = collector.Start(ctx)
	require.NoError(t, err)
	defer func() {
		if err := collector.Stop(ctx); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	// Wait for at least one collection cycle
	time.Sleep(1200 * time.Millisecond)

	// Metrics should have been collected
	// (We can't easily verify values without scraping the registry)
}

func TestCollector_DisabledRuntimeMetrics(t *testing.T) {
	config := DefaultConfig()
	config.Port = 19100
	config.EnableRuntimeMetrics = false
	config.EnableProcessMetrics = false

	collector, err := NewCollector(config)
	require.NoError(t, err)

	ctx := context.Background()

	err = collector.Start(ctx)
	require.NoError(t, err)
	defer func() {
		if err := collector.Stop(ctx); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	// Collection loop should not be started when both are disabled
	time.Sleep(100 * time.Millisecond)
}

func TestCollector_CollectMetrics(t *testing.T) {
	config := DefaultConfig()
	config.Port = 19101

	collector, err := NewCollector(config)
	require.NoError(t, err)

	// Manually trigger metric collection
	collector.collectMetrics()

	// Verify uptime was set (should be very small)
	// We can't easily check the value without accessing metrics directly
}

func TestCollector_CollectRuntimeMetrics(t *testing.T) {
	config := DefaultConfig()
	config.Port = 19102

	collector, err := NewCollector(config)
	require.NoError(t, err)

	// Manually trigger runtime metrics collection
	collector.collectRuntimeMetrics()

	// Metrics should be populated
	// Verification would require scraping the registry
}

func TestCollector_StopTimeout(t *testing.T) {
	config := DefaultConfig()
	config.Port = 19107

	collector, err := NewCollector(config)
	require.NoError(t, err)

	ctx := context.Background()

	err = collector.Start(ctx)
	require.NoError(t, err)

	// Create a context with very short timeout
	stopCtx, cancel := context.WithTimeout(ctx, 1*time.Nanosecond)
	defer cancel()

	// Stop should still work even with expired context
	// (uses its own 5s timeout internally)
	err = collector.Stop(stopCtx)
	assert.NoError(t, err)
}
