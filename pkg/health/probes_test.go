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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProbeType_String(t *testing.T) {
	tests := []struct {
		probe    ProbeType
		expected string
	}{
		{ProbeLiveness, "liveness"},
		{ProbeReadiness, "readiness"},
		{ProbeStartup, "startup"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.probe.String())
		})
	}
}

func TestLivenessProbe(t *testing.T) {
	t.Run("type", func(t *testing.T) {
		probe := NewLivenessProbe(nil)
		assert.Equal(t, ProbeLiveness, probe.Type())
	})

	t.Run("nil check function returns true", func(t *testing.T) {
		probe := NewLivenessProbe(nil)

		result := probe.Check(context.Background())
		assert.True(t, result)

		ok, timestamp := probe.LastCheck()
		assert.True(t, ok)
		assert.False(t, timestamp.IsZero())
	})

	t.Run("check returns true", func(t *testing.T) {
		probe := NewLivenessProbe(func(ctx context.Context) bool {
			return true
		})

		result := probe.Check(context.Background())
		assert.True(t, result)

		ok, _ := probe.LastCheck()
		assert.True(t, ok)
	})

	t.Run("check returns false", func(t *testing.T) {
		probe := NewLivenessProbe(func(ctx context.Context) bool {
			return false
		})

		result := probe.Check(context.Background())
		assert.False(t, result)

		ok, _ := probe.LastCheck()
		assert.False(t, ok)
	})

	t.Run("respects context", func(t *testing.T) {
		probe := NewLivenessProbe(func(ctx context.Context) bool {
			select {
			case <-ctx.Done():
				return false
			case <-time.After(10 * time.Millisecond):
				return true
			}
		})

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		result := probe.Check(ctx)
		assert.False(t, result)
	})
}

func TestReadinessProbe(t *testing.T) {
	t.Run("type", func(t *testing.T) {
		probe := NewReadinessProbe(nil)
		assert.Equal(t, ProbeReadiness, probe.Type())
	})

	t.Run("nil check function returns false", func(t *testing.T) {
		probe := NewReadinessProbe(nil)

		result := probe.Check(context.Background())
		assert.False(t, result)

		ok, timestamp := probe.LastCheck()
		assert.False(t, ok)
		assert.False(t, timestamp.IsZero())
	})

	t.Run("check returns true", func(t *testing.T) {
		probe := NewReadinessProbe(func(ctx context.Context) bool {
			return true
		})

		result := probe.Check(context.Background())
		assert.True(t, result)

		ok, _ := probe.LastCheck()
		assert.True(t, ok)
	})

	t.Run("check returns false", func(t *testing.T) {
		probe := NewReadinessProbe(func(ctx context.Context) bool {
			return false
		})

		result := probe.Check(context.Background())
		assert.False(t, result)

		ok, _ := probe.LastCheck()
		assert.False(t, ok)
	})
}

func TestStartupProbe(t *testing.T) {
	t.Run("type", func(t *testing.T) {
		probe := NewStartupProbe(nil)
		assert.Equal(t, ProbeStartup, probe.Type())
	})

	t.Run("nil check function returns false", func(t *testing.T) {
		probe := NewStartupProbe(nil)

		result := probe.Check(context.Background())
		assert.False(t, result)
		assert.False(t, probe.HasStarted())
	})

	t.Run("initially not started", func(t *testing.T) {
		probe := NewStartupProbe(func(ctx context.Context) bool {
			return false
		})

		assert.False(t, probe.HasStarted())
		result := probe.Check(context.Background())
		assert.False(t, result)
		assert.False(t, probe.HasStarted())
	})

	t.Run("becomes started after success", func(t *testing.T) {
		callCount := 0
		probe := NewStartupProbe(func(ctx context.Context) bool {
			callCount++
			return callCount >= 2 // Succeed on second call
		})

		// First check - fails
		result := probe.Check(context.Background())
		assert.False(t, result)
		assert.False(t, probe.HasStarted())

		// Second check - succeeds
		result = probe.Check(context.Background())
		assert.True(t, result)
		assert.True(t, probe.HasStarted())

		// Subsequent checks always return true
		result = probe.Check(context.Background())
		assert.True(t, result)
	})

	t.Run("always returns true after started", func(t *testing.T) {
		probe := NewStartupProbe(func(ctx context.Context) bool {
			return true
		})

		// Start up
		probe.Check(context.Background())
		assert.True(t, probe.HasStarted())

		// Even with nil check, should return true
		probe.checkFunc = nil
		result := probe.Check(context.Background())
		assert.True(t, result)
	})
}

func TestRegistryBasedProbe(t *testing.T) {
	t.Run("liveness probe passes unless unhealthy", func(t *testing.T) {
		registry := NewRegistry()
		err := registry.Register(&mockChecker{name: "test", status: StatusHealthy})
		require.NoError(t, err)

		probe := NewRegistryBasedLivenessProbe(registry)
		assert.Equal(t, ProbeLiveness, probe.Type())

		result := probe.Check(context.Background())
		assert.True(t, result)

		ok, _ := probe.LastCheck()
		assert.True(t, ok)
	})

	t.Run("liveness probe fails when unhealthy", func(t *testing.T) {
		registry := NewRegistry()
		err := registry.Register(&mockChecker{name: "test", status: StatusUnhealthy})
		require.NoError(t, err)

		probe := NewRegistryBasedLivenessProbe(registry)

		result := probe.Check(context.Background())
		assert.False(t, result)
	})

	t.Run("liveness probe passes when degraded", func(t *testing.T) {
		registry := NewRegistry()
		err := registry.Register(&mockChecker{name: "test", status: StatusDegraded})
		require.NoError(t, err)

		probe := NewRegistryBasedLivenessProbe(registry)

		result := probe.Check(context.Background())
		assert.True(t, result)
	})

	t.Run("readiness probe requires healthy", func(t *testing.T) {
		registry := NewRegistry()
		err := registry.Register(&mockChecker{name: "test", status: StatusHealthy})
		require.NoError(t, err)

		probe := NewRegistryBasedReadinessProbe(registry)
		assert.Equal(t, ProbeReadiness, probe.Type())

		result := probe.Check(context.Background())
		assert.True(t, result)
	})

	t.Run("readiness probe fails when degraded", func(t *testing.T) {
		registry := NewRegistry()
		err := registry.Register(&mockChecker{name: "test", status: StatusDegraded})
		require.NoError(t, err)

		probe := NewRegistryBasedReadinessProbe(registry)

		result := probe.Check(context.Background())
		assert.False(t, result)
	})
}

func TestCompositeProbe(t *testing.T) {
	t.Run("type", func(t *testing.T) {
		probe := NewCompositeProbe(ProbeLiveness, nil)
		assert.Equal(t, ProbeLiveness, probe.Type())
	})

	t.Run("empty probes returns true", func(t *testing.T) {
		probe := NewCompositeProbe(ProbeLiveness, nil)

		result := probe.Check(context.Background())
		assert.True(t, result)
	})

	t.Run("all probes must pass with require all", func(t *testing.T) {
		probes := []Probe{
			NewLivenessProbe(func(ctx context.Context) bool { return true }),
			NewLivenessProbe(func(ctx context.Context) bool { return true }),
		}

		probe := NewCompositeProbe(ProbeLiveness, probes, WithRequireAll(true))

		result := probe.Check(context.Background())
		assert.True(t, result)
	})

	t.Run("fails if any probe fails with require all", func(t *testing.T) {
		probes := []Probe{
			NewLivenessProbe(func(ctx context.Context) bool { return true }),
			NewLivenessProbe(func(ctx context.Context) bool { return false }),
		}

		probe := NewCompositeProbe(ProbeLiveness, probes, WithRequireAll(true))

		result := probe.Check(context.Background())
		assert.False(t, result)
	})

	t.Run("passes if any probe passes without require all", func(t *testing.T) {
		probes := []Probe{
			NewLivenessProbe(func(ctx context.Context) bool { return false }),
			NewLivenessProbe(func(ctx context.Context) bool { return true }),
		}

		probe := NewCompositeProbe(ProbeLiveness, probes, WithRequireAll(false))

		result := probe.Check(context.Background())
		assert.True(t, result)
	})

	t.Run("fails if all probes fail without require all", func(t *testing.T) {
		probes := []Probe{
			NewLivenessProbe(func(ctx context.Context) bool { return false }),
			NewLivenessProbe(func(ctx context.Context) bool { return false }),
		}

		probe := NewCompositeProbe(ProbeLiveness, probes, WithRequireAll(false))

		result := probe.Check(context.Background())
		assert.False(t, result)
	})

	t.Run("last check returns correct values", func(t *testing.T) {
		probe := NewCompositeProbe(ProbeLiveness, []Probe{
			NewLivenessProbe(func(ctx context.Context) bool { return true }),
		})

		probe.Check(context.Background())

		ok, timestamp := probe.LastCheck()
		assert.True(t, ok)
		assert.False(t, timestamp.IsZero())
	})
}

func TestProbe_Concurrency(t *testing.T) {
	t.Run("liveness probe concurrent checks", func(t *testing.T) {
		var callCount atomic.Int32
		probe := NewLivenessProbe(func(ctx context.Context) bool {
			callCount.Add(1)
			return true
		})

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				probe.Check(context.Background())
			}()
		}

		wg.Wait()
		assert.Equal(t, int32(100), callCount.Load())
	})

	t.Run("startup probe concurrent checks", func(t *testing.T) {
		var callCount atomic.Int32
		probe := NewStartupProbe(func(ctx context.Context) bool {
			callCount.Add(1)
			return true
		})

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				probe.Check(context.Background())
			}()
		}

		wg.Wait()
		assert.True(t, probe.HasStarted())
		// After started, checkFunc is not called, but due to concurrency
		// it might be called a few times before started is set
		assert.True(t, callCount.Load() >= 1)
	})
}
