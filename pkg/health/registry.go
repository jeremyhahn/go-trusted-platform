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
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Registry is the interface for managing health checkers.
type Registry interface {
	// Register adds a health checker to the registry.
	Register(checker HealthChecker) error

	// Unregister removes a health checker from the registry.
	Unregister(name string) error

	// Check performs health checks on all registered components.
	Check(ctx context.Context) SystemHealth

	// CheckComponent performs a health check on a specific component.
	CheckComponent(ctx context.Context, name string) (ComponentHealth, error)

	// List returns the names of all registered health checkers.
	List() []string

	// Count returns the number of registered health checkers.
	Count() int

	// Close closes the registry and releases resources.
	Close() error
}

// RegistryOption is a functional option for configuring the registry.
type RegistryOption func(*registryImpl)

// WithMaxCheckers sets the maximum number of checkers allowed.
func WithMaxCheckers(max int) RegistryOption {
	return func(r *registryImpl) {
		r.config.MaxCheckers = max
	}
}

// WithDefaultTimeout sets the default timeout for health checks.
func WithDefaultTimeout(timeout time.Duration) RegistryOption {
	return func(r *registryImpl) {
		r.config.DefaultTimeout = timeout
	}
}

// registryImpl is the thread-safe implementation of the Registry interface.
type registryImpl struct {
	checkers map[string]HealthChecker
	mu       sync.RWMutex
	config   RegistryConfig
	closed   atomic.Bool
}

// NewRegistry creates a new health check registry.
func NewRegistry(opts ...RegistryOption) Registry {
	r := &registryImpl{
		checkers: make(map[string]HealthChecker),
		config:   DefaultRegistryConfig(),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Register adds a health checker to the registry.
func (r *registryImpl) Register(checker HealthChecker) error {
	if r.closed.Load() {
		return ErrRegistryClosed{}
	}

	if checker == nil {
		return ErrInvalidCheckerName{Name: "", Reason: "checker cannot be nil"}
	}

	name := checker.Name()
	if name == "" {
		return ErrInvalidCheckerName{Name: "", Reason: "name cannot be empty"}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed.Load() {
		return ErrRegistryClosed{}
	}

	if _, exists := r.checkers[name]; exists {
		return ErrCheckerAlreadyRegistered{Name: name}
	}

	if r.config.MaxCheckers > 0 && len(r.checkers) >= r.config.MaxCheckers {
		return ErrRegistryFull{MaxCheckers: r.config.MaxCheckers}
	}

	r.checkers[name] = checker
	return nil
}

// Unregister removes a health checker from the registry.
func (r *registryImpl) Unregister(name string) error {
	if r.closed.Load() {
		return ErrRegistryClosed{}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed.Load() {
		return ErrRegistryClosed{}
	}

	if _, exists := r.checkers[name]; !exists {
		return ErrCheckerNotRegistered{Name: name}
	}

	delete(r.checkers, name)
	return nil
}

// Check performs health checks on all registered components.
func (r *registryImpl) Check(ctx context.Context) SystemHealth {
	start := time.Now()
	health := SystemHealth{
		Status:    StatusUnknown,
		Timestamp: start,
	}

	if r.closed.Load() {
		health.Status = StatusUnhealthy
		health.TotalDuration = time.Since(start)
		return health
	}

	r.mu.RLock()
	checkers := make([]HealthChecker, 0, len(r.checkers))
	for _, checker := range r.checkers {
		checkers = append(checkers, checker)
	}
	r.mu.RUnlock()

	if len(checkers) == 0 {
		health.Status = StatusHealthy
		health.TotalDuration = time.Since(start)
		return health
	}

	// Run checks in parallel
	results := make(chan ComponentHealth, len(checkers))
	var wg sync.WaitGroup

	for _, checker := range checkers {
		wg.Add(1)
		go func(c HealthChecker) {
			defer wg.Done()
			checkCtx, cancel := context.WithTimeout(ctx, r.config.DefaultTimeout)
			defer cancel()

			result := r.executeCheck(checkCtx, c)
			results <- result
		}(checker)
	}

	// Wait for all checks to complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	health.Components = make([]ComponentHealth, 0, len(checkers))
	for result := range results {
		health.Components = append(health.Components, result)

		switch result.Status {
		case StatusHealthy:
			health.HealthyCount++
		case StatusDegraded:
			health.DegradedCount++
		case StatusUnhealthy:
			health.UnhealthyCount++
		default:
			health.UnknownCount++
		}
	}

	// Sort components by name for deterministic output
	sort.Slice(health.Components, func(i, j int) bool {
		return health.Components[i].Name < health.Components[j].Name
	})

	// Determine overall status
	health.Status = r.calculateOverallStatus(health)
	health.TotalDuration = time.Since(start)

	return health
}

// CheckComponent performs a health check on a specific component.
func (r *registryImpl) CheckComponent(ctx context.Context, name string) (ComponentHealth, error) {
	if r.closed.Load() {
		return ComponentHealth{}, ErrRegistryClosed{}
	}

	r.mu.RLock()
	checker, exists := r.checkers[name]
	r.mu.RUnlock()

	if !exists {
		return ComponentHealth{}, ErrComponentNotFound{Name: name}
	}

	checkCtx, cancel := context.WithTimeout(ctx, r.config.DefaultTimeout)
	defer cancel()

	return r.executeCheck(checkCtx, checker), nil
}

// List returns the names of all registered health checkers.
func (r *registryImpl) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.checkers))
	for name := range r.checkers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Count returns the number of registered health checkers.
func (r *registryImpl) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.checkers)
}

// Close closes the registry and releases resources.
func (r *registryImpl) Close() error {
	if r.closed.Swap(true) {
		return ErrRegistryClosed{}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Clear all checkers
	r.checkers = make(map[string]HealthChecker)
	return nil
}

// executeCheck runs a health check with proper timeout handling.
//
// Both select cases can be ready at the same instant — the checker answered at
// or after its deadline — and Go chooses among ready cases uniformly at random.
// The branch the runtime happens to take therefore cannot be allowed to decide
// the outcome, so it only records whether an answer arrived; checkOutcome makes
// the decision, once, from that answer and the deadline. See its doc comment
// for why that matters.
func (r *registryImpl) executeCheck(ctx context.Context, checker HealthChecker) ComponentHealth {
	done := make(chan ComponentHealth, 1)

	go func() {
		done <- checker.Check(ctx)
	}()

	var answer *ComponentHealth
	select {
	case result := <-done:
		answer = &result
	case <-ctx.Done():
	}

	return checkOutcome(checker, answer, ctx.Err())
}

// checkOutcome decides what a component reports once its check has either
// answered or run out of time. result is what the checker returned, or nil when
// it has not returned one; expiry is the check context's error sampled at the
// moment of the decision.
//
// A checker's answer is authoritative only while its budget is intact. Once
// expiry is non-nil the check has overrun its deadline, and its answer says
// what the component looked like at an unknown time past the point the registry
// stopped waiting — so the timeout is recorded instead.
//
// The case this rules out is a check that blows its budget and then finishes.
// A checker that never returns is already reported correctly: it never sends on
// done, so the deadline is the only ready case. The hazard is the degrading
// component, not the wedged one — without this rule a component slow enough to
// overrun its deadline has its late answer reported at face value on roughly
// half the runs that reach here (issue #221: observed on a loaded host as a
// 200ms check reporting healthy against a 50ms deadline).
//
// Sampling expiry once, in the caller, keeps the decision total and free of
// wall-clock timing: the same inputs always produce the same outcome.
func checkOutcome(checker HealthChecker, result *ComponentHealth, expiry error) ComponentHealth {
	if expiry == nil {
		if result != nil {
			return *result
		}
		// executeCheck reaches checkOutcome only from a completed check or an
		// expired deadline, so this is unreachable through it. It is defined
		// rather than left to a zero value so the function is total: nothing
		// known, reported as nothing known.
		return ComponentHealth{
			Name:        checker.Name(),
			Status:      StatusUnknown,
			Message:     "health check produced no result",
			LastChecked: time.Now(),
		}
	}

	return ComponentHealth{
		Name:        checker.Name(),
		Status:      StatusUnknown,
		Message:     "health check timed out",
		LastChecked: time.Now(),
		Details: map[string]any{
			"error": expiry.Error(),
		},
	}
}

// calculateOverallStatus determines the overall system health based on component statuses.
func (r *registryImpl) calculateOverallStatus(health SystemHealth) HealthStatus {
	if health.UnhealthyCount > 0 {
		return StatusUnhealthy
	}
	if health.DegradedCount > 0 {
		return StatusDegraded
	}
	if health.UnknownCount > 0 && health.HealthyCount == 0 {
		return StatusUnknown
	}
	return StatusHealthy
}
