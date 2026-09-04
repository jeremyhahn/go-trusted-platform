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
}

func (m *mockChecker) Name() string {
	return m.name
}

func (m *mockChecker) Check(ctx context.Context) ComponentHealth {
	return ComponentHealth{
		Name:        m.name,
		Status:      m.status,
		Message:     "mock check",
		LastChecked: time.Now(),
	}
}

// gatedChecker answers only once the test releases it, and deliberately never
// looks at its context. That is what a checker which ignores its deadline looks
// like from the registry's side: enforcing the deadline is the registry's job,
// and a checker cannot be trusted to do it (see the checkOutcome doc comment).
//
// Because the answer arrives only on the test's say-so, tests built on it never
// race two durations against each other. A loaded host makes them slower, never
// wrong.
type gatedChecker struct {
	name    string
	status  HealthStatus
	release chan struct{}
	once    sync.Once
}

// newGatedChecker returns a checker that blocks until finish is called. The
// release is also wired to t.Cleanup, so its goroutine can never outlive the
// test even if the test never releases it itself.
func newGatedChecker(t *testing.T, name string, status HealthStatus) *gatedChecker {
	t.Helper()
	c := &gatedChecker{name: name, status: status, release: make(chan struct{})}
	t.Cleanup(c.finish)
	return c
}

// finish lets a blocked check return. It is idempotent, so a test may release
// the checker itself and still have the Cleanup release run.
func (c *gatedChecker) finish() {
	c.once.Do(func() { close(c.release) })
}

func (c *gatedChecker) Name() string {
	return c.name
}

func (c *gatedChecker) Check(ctx context.Context) ComponentHealth {
	<-c.release
	return ComponentHealth{
		Name:        c.name,
		Status:      c.status,
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
		// The checker does not answer at all until the test releases it, so the
		// deadline is the only thing that can end the wait. Nothing here races
		// one duration against another: previously this asserted that a 50ms
		// timeout beat a 200ms delay, and on a loaded host it did not (#221).
		registry := NewRegistry(WithDefaultTimeout(10 * time.Millisecond))

		err := registry.Register(newGatedChecker(t, "slow", StatusHealthy))
		require.NoError(t, err)

		health := registry.Check(context.Background())

		require.Equal(t, 1, len(health.Components))
		assert.Equal(t, StatusUnknown, health.Components[0].Status)
		assert.Contains(t, health.Components[0].Message, "timed out")
		assert.Equal(t, context.DeadlineExceeded.Error(), health.Components[0].Details["error"])
	})

	t.Run("a check that answers within its budget is reported as it answered", func(t *testing.T) {
		// The companion to the case above: the deadline must not swallow a
		// result that genuinely arrived in time.
		registry := NewRegistry(WithDefaultTimeout(time.Hour))

		checker := newGatedChecker(t, "prompt", StatusHealthy)
		checker.finish() // the answer is ready before the sweep starts
		require.NoError(t, registry.Register(checker))

		health := registry.Check(context.Background())

		require.Equal(t, 1, len(health.Components))
		assert.Equal(t, StatusHealthy, health.Components[0].Status)
		assert.Equal(t, "mock check", health.Components[0].Message)
	})
}

// TestCheckOutcome pins the rule that decides between a checker's answer and an
// expired deadline. executeCheck's select can have both cases ready at once and
// Go picks between ready cases at random, so this decision — not the branch the
// runtime happened to take — is what the registry reports (#221).
func TestCheckOutcome(t *testing.T) {
	checker := &mockChecker{name: "component", status: StatusHealthy}
	answered := &ComponentHealth{Name: "component", Status: StatusHealthy, Message: "mock check"}

	t.Run("an answer within the budget is reported as it stands", func(t *testing.T) {
		got := checkOutcome(checker, answered, nil)

		assert.Equal(t, StatusHealthy, got.Status)
		assert.Equal(t, "mock check", got.Message)
	})

	t.Run("an answer past the deadline is recorded as a timeout", func(t *testing.T) {
		// The regression guard for #221. A checker that overran its budget
		// reported healthy on a loaded host because this answer was taken at
		// face value. Note what is and is not at stake: a checker that never
		// returns is reported correctly either way, because it never produces
		// an answer to prefer. This rule is what stops a component slow enough
		// to blow its deadline from being recorded as healthy anyway.
		got := checkOutcome(checker, answered, context.DeadlineExceeded)

		assert.Equal(t, StatusUnknown, got.Status)
		assert.Equal(t, "health check timed out", got.Message)
		assert.Equal(t, context.DeadlineExceeded.Error(), got.Details["error"])
		assert.Equal(t, "component", got.Name)
	})

	t.Run("no answer and an expired deadline is a timeout", func(t *testing.T) {
		got := checkOutcome(checker, nil, context.DeadlineExceeded)

		assert.Equal(t, StatusUnknown, got.Status)
		assert.Equal(t, "health check timed out", got.Message)
		assert.Equal(t, context.DeadlineExceeded.Error(), got.Details["error"])
	})

	t.Run("a cancelled run reports the cancellation, not a deadline", func(t *testing.T) {
		// Check inherits the caller's context, so a cancelled request must say
		// so rather than claiming the component was too slow.
		got := checkOutcome(checker, nil, context.Canceled)

		assert.Equal(t, StatusUnknown, got.Status)
		assert.Equal(t, context.Canceled.Error(), got.Details["error"])
	})

	t.Run("neither an answer nor an expiry is unknown, not a fabricated result", func(t *testing.T) {
		// Unreachable through executeCheck, which only calls in from a
		// completed check or an expired deadline; defined so the function is
		// total rather than returning a zero-valued ComponentHealth.
		got := checkOutcome(checker, nil, nil)

		assert.Equal(t, StatusUnknown, got.Status)
		assert.Equal(t, "health check produced no result", got.Message)
		assert.Equal(t, "component", got.Name)
		assert.Nil(t, got.Details)
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
