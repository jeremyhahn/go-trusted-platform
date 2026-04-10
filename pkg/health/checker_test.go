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
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQuicBaaSChecker(t *testing.T) {
	t.Run("healthy check", func(t *testing.T) {
		checker := NewQuicBaaSChecker(func(ctx context.Context) error {
			return nil
		})

		assert.Equal(t, "quicbaas", checker.Name())

		health := checker.Check(context.Background())
		assert.Equal(t, StatusHealthy, health.Status)
		assert.Equal(t, "quicbaas", health.Name)
		assert.Contains(t, health.Message, "responding")
		assert.NotZero(t, health.Duration)
		assert.Contains(t, health.Details, "response_time_ms")
	})

	t.Run("unhealthy check", func(t *testing.T) {
		expectedErr := errors.New("connection refused")
		checker := NewQuicBaaSChecker(func(ctx context.Context) error {
			return expectedErr
		})

		health := checker.Check(context.Background())
		assert.Equal(t, StatusUnhealthy, health.Status)
		assert.Contains(t, health.Message, "connection refused")
		assert.Contains(t, health.Details, "error")
	})

	t.Run("nil ping function", func(t *testing.T) {
		checker := NewQuicBaaSChecker(nil)

		health := checker.Check(context.Background())
		assert.Equal(t, StatusUnhealthy, health.Status)
		assert.Contains(t, health.Message, "not configured")
	})

	t.Run("with custom name", func(t *testing.T) {
		checker := NewQuicBaaSChecker(
			func(ctx context.Context) error { return nil },
			WithQuicBaaSName("custom-db"),
		)

		assert.Equal(t, "custom-db", checker.Name())
	})
}

func TestOVSChecker(t *testing.T) {
	t.Run("healthy check", func(t *testing.T) {
		checker := NewOVSChecker(func(ctx context.Context) error {
			return nil
		})

		assert.Equal(t, "ovs", checker.Name())

		health := checker.Check(context.Background())
		assert.Equal(t, StatusHealthy, health.Status)
		assert.Equal(t, "ovs", health.Name)
		assert.Contains(t, health.Message, "responding")
		assert.Contains(t, health.Details, "socket_path")
		assert.Contains(t, health.Details, "response_time_ms")
	})

	t.Run("unhealthy check", func(t *testing.T) {
		expectedErr := errors.New("socket not found")
		checker := NewOVSChecker(func(ctx context.Context) error {
			return expectedErr
		})

		health := checker.Check(context.Background())
		assert.Equal(t, StatusUnhealthy, health.Status)
		assert.Contains(t, health.Message, "socket not found")
	})

	t.Run("nil check function", func(t *testing.T) {
		checker := NewOVSChecker(nil)

		health := checker.Check(context.Background())
		assert.Equal(t, StatusUnhealthy, health.Status)
		assert.Contains(t, health.Message, "not configured")
	})

	t.Run("with custom options", func(t *testing.T) {
		checker := NewOVSChecker(
			func(ctx context.Context) error { return nil },
			WithOVSName("custom-ovs"),
			WithOVSSocketPath("/custom/path/db.sock"),
		)

		assert.Equal(t, "custom-ovs", checker.Name())
		health := checker.Check(context.Background())
		assert.Equal(t, "/custom/path/db.sock", health.Details["socket_path"])
	})
}

func TestDiskChecker(t *testing.T) {
	t.Run("healthy check on root", func(t *testing.T) {
		checker := NewDiskChecker(
			WithDiskPath("/"),
			WithDiskThresholds(DiskThresholdConfig{
				UsageWarning:  80.0,
				UsageCritical: 95.0,
				MinFreeBytes:  1024,
			}),
		)

		assert.Equal(t, "disk", checker.Name())

		health := checker.Check(context.Background())
		// On most systems root should have some space
		require.NotEqual(t, StatusUnknown, health.Status)
		assert.Equal(t, "disk", health.Name)
		assert.Contains(t, health.Details, "path")
		assert.Contains(t, health.Details, "total_bytes")
		assert.Contains(t, health.Details, "free_bytes")
		assert.Contains(t, health.Details, "used_bytes")
		assert.Contains(t, health.Details, "usage_percent")
	})

	t.Run("invalid path", func(t *testing.T) {
		checker := NewDiskChecker(
			WithDiskPath("/nonexistent/path/that/should/not/exist"),
			WithDiskName("invalid-disk"),
		)

		health := checker.Check(context.Background())
		assert.Equal(t, StatusUnhealthy, health.Status)
		assert.Contains(t, health.Details, "error")
	})

	t.Run("with custom name", func(t *testing.T) {
		checker := NewDiskChecker(WithDiskName("custom-disk"))
		assert.Equal(t, "custom-disk", checker.Name())
	})
}

func TestMemoryChecker(t *testing.T) {
	t.Run("healthy check with high thresholds", func(t *testing.T) {
		checker := NewMemoryChecker(
			WithMemoryThresholds(MemoryThresholdConfig{
				UsageWarning:  99.0,
				UsageCritical: 99.9,
				MinFreeBytes:  1024,
			}),
		)

		assert.Equal(t, "memory", checker.Name())

		health := checker.Check(context.Background())
		// With high thresholds, should be healthy
		assert.Equal(t, StatusHealthy, health.Status)
		assert.Equal(t, "memory", health.Name)
		assert.Contains(t, health.Details, "alloc_bytes")
		assert.Contains(t, health.Details, "sys_bytes")
		assert.Contains(t, health.Details, "heap_in_use")
		assert.Contains(t, health.Details, "num_gc")
		assert.Contains(t, health.Details, "usage_percent")
	})

	t.Run("degraded with low warning threshold", func(t *testing.T) {
		checker := NewMemoryChecker(
			WithMemoryThresholds(MemoryThresholdConfig{
				UsageWarning:  0.001, // Very low threshold
				UsageCritical: 99.9,
				MinFreeBytes:  1024,
			}),
		)

		health := checker.Check(context.Background())
		// Should be degraded due to low warning threshold
		assert.Equal(t, StatusDegraded, health.Status)
	})

	t.Run("unhealthy with critical threshold", func(t *testing.T) {
		checker := NewMemoryChecker(
			WithMemoryThresholds(MemoryThresholdConfig{
				UsageWarning:  0.001,
				UsageCritical: 0.001, // Very low threshold
				MinFreeBytes:  1024,
			}),
		)

		health := checker.Check(context.Background())
		// Should be unhealthy due to low critical threshold
		assert.Equal(t, StatusUnhealthy, health.Status)
	})

	t.Run("with custom name", func(t *testing.T) {
		checker := NewMemoryChecker(WithMemoryName("custom-memory"))
		assert.Equal(t, "custom-memory", checker.Name())
	})
}

func TestGoroutineChecker(t *testing.T) {
	t.Run("healthy check with high thresholds", func(t *testing.T) {
		checker := NewGoroutineChecker(
			WithGoroutineThresholds(GoroutineThresholdConfig{
				WarningCount:  100000,
				CriticalCount: 1000000,
			}),
		)

		assert.Equal(t, "goroutines", checker.Name())

		health := checker.Check(context.Background())
		// With high thresholds, should be healthy
		assert.Equal(t, StatusHealthy, health.Status)
		assert.Equal(t, "goroutines", health.Name)
		assert.Contains(t, health.Details, "count")
		assert.Contains(t, health.Details, "num_cpu")
		assert.Contains(t, health.Details, "gomaxprocs")
		assert.Contains(t, health.Details, "warning_threshold")
		assert.Contains(t, health.Details, "critical_threshold")
	})

	t.Run("degraded with low warning threshold", func(t *testing.T) {
		checker := NewGoroutineChecker(
			WithGoroutineThresholds(GoroutineThresholdConfig{
				WarningCount:  1, // Very low threshold
				CriticalCount: 1000000,
			}),
		)

		health := checker.Check(context.Background())
		// Should be degraded due to low warning threshold
		assert.Equal(t, StatusDegraded, health.Status)
	})

	t.Run("unhealthy with critical threshold", func(t *testing.T) {
		checker := NewGoroutineChecker(
			WithGoroutineThresholds(GoroutineThresholdConfig{
				WarningCount:  1,
				CriticalCount: 1, // Very low threshold
			}),
		)

		health := checker.Check(context.Background())
		// Should be unhealthy due to low critical threshold
		assert.Equal(t, StatusUnhealthy, health.Status)
	})

	t.Run("with custom name", func(t *testing.T) {
		checker := NewGoroutineChecker(WithGoroutineName("custom-goroutines"))
		assert.Equal(t, "custom-goroutines", checker.Name())
	})
}

func TestCustomChecker(t *testing.T) {
	t.Run("healthy custom check", func(t *testing.T) {
		checker := NewCustomChecker("custom", func(ctx context.Context) ComponentHealth {
			return ComponentHealth{
				Name:        "custom",
				Status:      StatusHealthy,
				Message:     "all good",
				LastChecked: time.Now(),
			}
		})

		assert.Equal(t, "custom", checker.Name())

		health := checker.Check(context.Background())
		assert.Equal(t, StatusHealthy, health.Status)
		assert.Equal(t, "all good", health.Message)
	})

	t.Run("nil check function", func(t *testing.T) {
		checker := NewCustomChecker("nil-checker", nil)

		health := checker.Check(context.Background())
		assert.Equal(t, StatusUnhealthy, health.Status)
		assert.Contains(t, health.Message, "not configured")
	})
}

func TestHealthChecker_ContextCancellation(t *testing.T) {
	t.Run("quicbaas respects context cancellation", func(t *testing.T) {
		checker := NewQuicBaaSChecker(func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		})

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		health := checker.Check(ctx)
		assert.Equal(t, StatusUnhealthy, health.Status)
	})

	t.Run("ovs respects context cancellation", func(t *testing.T) {
		checker := NewOVSChecker(func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		})

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		health := checker.Check(ctx)
		assert.Equal(t, StatusUnhealthy, health.Status)
	})
}
