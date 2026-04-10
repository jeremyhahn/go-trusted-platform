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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockChecker struct {
	name   string
	status HealthStatus
	delay  time.Duration
}

func (m *mockChecker) Name() string {
	return m.name
}

func (m *mockChecker) Check(ctx context.Context) ComponentHealth {
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return ComponentHealth{
				Name:        m.name,
				Status:      StatusUnknown,
				Message:     "check cancelled",
				LastChecked: time.Now(),
			}
		}
	}
	return ComponentHealth{
		Name:        m.name,
		Status:      m.status,
		Message:     "mock check",
		LastChecked: time.Now(),
	}
}

func TestNewRegistry(t *testing.T) {
	t.Run("default options", func(t *testing.T) {
		registry := NewRegistry()
		require.NotNil(t, registry)

		assert.Equal(t, 0, registry.Count())
		assert.Empty(t, registry.List())
	})

	t.Run("with max checkers option", func(t *testing.T) {
		registry := NewRegistry(WithMaxCheckers(5))
		require.NotNil(t, registry)

		// Register 5 checkers
		for i := 0; i < 5; i++ {
			err := registry.Register(&mockChecker{name: string(rune('a' + i))})
			require.NoError(t, err)
		}

		// 6th should fail
		err := registry.Register(&mockChecker{name: "f"})
		assert.Error(t, err)
		var errFull ErrRegistryFull
		assert.True(t, errors.As(err, &errFull))
		assert.Equal(t, 5, errFull.MaxCheckers)
	})

	t.Run("with default timeout option", func(t *testing.T) {
		registry := NewRegistry(WithDefaultTimeout(10 * time.Second))
		require.NotNil(t, registry)
	})
}

func TestRegistry_Register(t *testing.T) {
	t.Run("successful registration", func(t *testing.T) {
		registry := NewRegistry()

		err := registry.Register(&mockChecker{name: "test"})
		require.NoError(t, err)

		assert.Equal(t, 1, registry.Count())
		assert.Contains(t, registry.List(), "test")
	})

	t.Run("duplicate registration", func(t *testing.T) {
		registry := NewRegistry()

		err := registry.Register(&mockChecker{name: "test"})
		require.NoError(t, err)

		err = registry.Register(&mockChecker{name: "test"})
		assert.Error(t, err)
		var errDup ErrCheckerAlreadyRegistered
		assert.True(t, errors.As(err, &errDup))
		assert.Equal(t, "test", errDup.Name)
	})

	t.Run("nil checker", func(t *testing.T) {
		registry := NewRegistry()

		err := registry.Register(nil)
		assert.Error(t, err)
	})

	t.Run("empty name", func(t *testing.T) {
		registry := NewRegistry()

		err := registry.Register(&mockChecker{name: ""})
		assert.Error(t, err)
		var errName ErrInvalidCheckerName
		assert.True(t, errors.As(err, &errName))
	})

	t.Run("register on closed registry", func(t *testing.T) {
		registry := NewRegistry()
		require.NoError(t, registry.Close())

		err := registry.Register(&mockChecker{name: "test"})
		assert.Error(t, err)
		var errClosed ErrRegistryClosed
		assert.True(t, errors.As(err, &errClosed))
	})
}

func TestRegistry_Unregister(t *testing.T) {
	t.Run("successful unregistration", func(t *testing.T) {
		registry := NewRegistry()

		err := registry.Register(&mockChecker{name: "test"})
		require.NoError(t, err)
		assert.Equal(t, 1, registry.Count())

		err = registry.Unregister("test")
		require.NoError(t, err)
		assert.Equal(t, 0, registry.Count())
	})

	t.Run("unregister non-existent", func(t *testing.T) {
		registry := NewRegistry()

		err := registry.Unregister("nonexistent")
		assert.Error(t, err)
		var errNotReg ErrCheckerNotRegistered
		assert.True(t, errors.As(err, &errNotReg))
	})

	t.Run("unregister on closed registry", func(t *testing.T) {
		registry := NewRegistry()
		err := registry.Register(&mockChecker{name: "test"})
		require.NoError(t, err)
		require.NoError(t, registry.Close())

		err = registry.Unregister("test")
		assert.Error(t, err)
		var errClosed ErrRegistryClosed
		assert.True(t, errors.As(err, &errClosed))
	})
}

func TestRegistry_Check(t *testing.T) {
	t.Run("all healthy", func(t *testing.T) {
		registry := NewRegistry()

		err := registry.Register(&mockChecker{name: "comp1", status: StatusHealthy})
		require.NoError(t, err)
		err = registry.Register(&mockChecker{name: "comp2", status: StatusHealthy})
		require.NoError(t, err)

		health := registry.Check(context.Background())

		assert.Equal(t, StatusHealthy, health.Status)
		assert.Equal(t, 2, len(health.Components))
		assert.Equal(t, 2, health.HealthyCount)
		assert.Equal(t, 0, health.DegradedCount)
		assert.Equal(t, 0, health.UnhealthyCount)
	})

	t.Run("one degraded", func(t *testing.T) {
		registry := NewRegistry()

		err := registry.Register(&mockChecker{name: "comp1", status: StatusHealthy})
		require.NoError(t, err)
		err = registry.Register(&mockChecker{name: "comp2", status: StatusDegraded})
		require.NoError(t, err)

		health := registry.Check(context.Background())

		assert.Equal(t, StatusDegraded, health.Status)
		assert.Equal(t, 1, health.HealthyCount)
		assert.Equal(t, 1, health.DegradedCount)
	})

	t.Run("one unhealthy", func(t *testing.T) {
		registry := NewRegistry()

		err := registry.Register(&mockChecker{name: "comp1", status: StatusHealthy})
		require.NoError(t, err)
		err = registry.Register(&mockChecker{name: "comp2", status: StatusUnhealthy})
		require.NoError(t, err)

		health := registry.Check(context.Background())

		assert.Equal(t, StatusUnhealthy, health.Status)
		assert.Equal(t, 1, health.HealthyCount)
		assert.Equal(t, 1, health.UnhealthyCount)
	})

	t.Run("empty registry", func(t *testing.T) {
		registry := NewRegistry()

		health := registry.Check(context.Background())

		assert.Equal(t, StatusHealthy, health.Status)
		assert.Equal(t, 0, len(health.Components))
	})

	t.Run("closed registry", func(t *testing.T) {
		registry := NewRegistry()
		require.NoError(t, registry.Close())

		health := registry.Check(context.Background())

		assert.Equal(t, StatusUnhealthy, health.Status)
	})

	t.Run("components sorted by name", func(t *testing.T) {
		registry := NewRegistry()

		err := registry.Register(&mockChecker{name: "zebra", status: StatusHealthy})
		require.NoError(t, err)
		err = registry.Register(&mockChecker{name: "apple", status: StatusHealthy})
		require.NoError(t, err)
		err = registry.Register(&mockChecker{name: "middle", status: StatusHealthy})
		require.NoError(t, err)

		health := registry.Check(context.Background())

		assert.Equal(t, "apple", health.Components[0].Name)
		assert.Equal(t, "middle", health.Components[1].Name)
		assert.Equal(t, "zebra", health.Components[2].Name)
	})

	t.Run("timeout handling", func(t *testing.T) {
		registry := NewRegistry(WithDefaultTimeout(50 * time.Millisecond))

		err := registry.Register(&mockChecker{
			name:   "slow",
			status: StatusHealthy,
			delay:  200 * time.Millisecond,
		})
		require.NoError(t, err)

		health := registry.Check(context.Background())

		// Should timeout and return unknown
		require.Equal(t, 1, len(health.Components))
		assert.Equal(t, StatusUnknown, health.Components[0].Status)
		assert.Contains(t, health.Components[0].Message, "timed out")
	})
}

func TestRegistry_CheckComponent(t *testing.T) {
	t.Run("existing component", func(t *testing.T) {
		registry := NewRegistry()

		err := registry.Register(&mockChecker{name: "test", status: StatusHealthy})
		require.NoError(t, err)

		health, err := registry.CheckComponent(context.Background(), "test")
		require.NoError(t, err)

		assert.Equal(t, "test", health.Name)
		assert.Equal(t, StatusHealthy, health.Status)
	})

	t.Run("non-existent component", func(t *testing.T) {
		registry := NewRegistry()

		_, err := registry.CheckComponent(context.Background(), "nonexistent")
		assert.Error(t, err)
		var errNotFound ErrComponentNotFound
		assert.True(t, errors.As(err, &errNotFound))
		assert.Equal(t, "nonexistent", errNotFound.Name)
	})

	t.Run("closed registry", func(t *testing.T) {
		registry := NewRegistry()
		err := registry.Register(&mockChecker{name: "test", status: StatusHealthy})
		require.NoError(t, err)
		require.NoError(t, registry.Close())

		_, err = registry.CheckComponent(context.Background(), "test")
		assert.Error(t, err)
		var errClosed ErrRegistryClosed
		assert.True(t, errors.As(err, &errClosed))
	})
}

func TestRegistry_List(t *testing.T) {
	registry := NewRegistry()

	err := registry.Register(&mockChecker{name: "beta"})
	require.NoError(t, err)
	err = registry.Register(&mockChecker{name: "alpha"})
	require.NoError(t, err)
	err = registry.Register(&mockChecker{name: "gamma"})
	require.NoError(t, err)

	list := registry.List()

	// Should be sorted alphabetically
	assert.Equal(t, []string{"alpha", "beta", "gamma"}, list)
}

func TestRegistry_Count(t *testing.T) {
	registry := NewRegistry()

	assert.Equal(t, 0, registry.Count())

	err := registry.Register(&mockChecker{name: "a"})
	require.NoError(t, err)
	assert.Equal(t, 1, registry.Count())

	err = registry.Register(&mockChecker{name: "b"})
	require.NoError(t, err)
	assert.Equal(t, 2, registry.Count())

	err = registry.Unregister("a")
	require.NoError(t, err)
	assert.Equal(t, 1, registry.Count())
}

func TestRegistry_Close(t *testing.T) {
	t.Run("successful close", func(t *testing.T) {
		registry := NewRegistry()

		err := registry.Register(&mockChecker{name: "test"})
		require.NoError(t, err)

		err = registry.Close()
		require.NoError(t, err)

		// Should be cleared
		assert.Equal(t, 0, registry.Count())
	})

	t.Run("double close", func(t *testing.T) {
		registry := NewRegistry()

		err := registry.Close()
		require.NoError(t, err)

		err = registry.Close()
		assert.Error(t, err)
		var errClosed ErrRegistryClosed
		assert.True(t, errors.As(err, &errClosed))
	})
}

func TestRegistry_Concurrency(t *testing.T) {
	t.Run("concurrent registration", func(t *testing.T) {
		registry := NewRegistry()
		var wg sync.WaitGroup

		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				name := string(rune('a' + (idx % 26)))
				if err := registry.Register(&mockChecker{name: name, status: StatusHealthy}); err != nil {
					var alreadyRegistered ErrCheckerAlreadyRegistered
					if !errors.As(err, &alreadyRegistered) {
						t.Logf("unexpected register error: %v", err)
					}
				}
			}(i)
		}

		wg.Wait()
		// Some registrations will fail due to duplicates, but should not panic
		assert.True(t, registry.Count() > 0)
		assert.True(t, registry.Count() <= 26) // Max unique names
	})

	t.Run("concurrent checks", func(t *testing.T) {
		registry := NewRegistry()

		for i := 0; i < 10; i++ {
			err := registry.Register(&mockChecker{
				name:   string(rune('a' + i)),
				status: StatusHealthy,
			})
			require.NoError(t, err)
		}

		var wg sync.WaitGroup
		var healthyCount atomic.Int32

		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				health := registry.Check(context.Background())
				if health.Status == StatusHealthy {
					healthyCount.Add(1)
				}
			}()
		}

		wg.Wait()
		assert.Equal(t, int32(50), healthyCount.Load())
	})

	t.Run("concurrent register and check", func(t *testing.T) {
		registry := NewRegistry()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		var wg sync.WaitGroup

		// Register goroutine
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				select {
				case <-ctx.Done():
					return
				default:
					if err := registry.Register(&mockChecker{
						name:   string(rune('A' + (i % 26))),
						status: StatusHealthy,
					}); err != nil {
						var alreadyRegistered ErrCheckerAlreadyRegistered
						if !errors.As(err, &alreadyRegistered) {
							t.Logf("unexpected register error: %v", err)
						}
					}
				}
			}
		}()

		// Check goroutine
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				select {
				case <-ctx.Done():
					return
				default:
					registry.Check(context.Background())
				}
			}
		}()

		wg.Wait()
		// Should not panic or deadlock
	})
}
