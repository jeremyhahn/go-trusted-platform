package health

import (
	"context"
	"testing"
	"time"
)

// newProbeRegistry returns a registry holding one checker per status.
func newProbeRegistry(t *testing.T, statuses ...HealthStatus) Registry {
	t.Helper()
	registry := NewRegistry()
	t.Cleanup(func() {
		if err := registry.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	names := []string{"alpha", "bravo", "charlie", "delta"}
	for i, status := range statuses {
		if err := registry.Register(&mockChecker{name: names[i], status: status}); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}
	return registry
}

func TestLiveness_AlwaysAlive(t *testing.T) {
	probe := Liveness()
	if !probe.OK || probe.Status != StatusHealthy {
		t.Fatalf("Liveness() = %+v, want OK and healthy", probe)
	}
	if probe.Timestamp.IsZero() {
		t.Error("Liveness() has a zero timestamp")
	}
}

func TestReadinessAndAggregate_FollowTheRegistryVerdict(t *testing.T) {
	cases := []struct {
		name          string
		statuses      []HealthStatus
		wantStatus    HealthStatus
		wantReady     bool
		wantAggregate bool
	}{
		{"all healthy", []HealthStatus{StatusHealthy, StatusHealthy}, StatusHealthy, true, true},
		{"one degraded", []HealthStatus{StatusHealthy, StatusDegraded}, StatusDegraded, true, false},
		{"one unhealthy", []HealthStatus{StatusHealthy, StatusDegraded, StatusUnhealthy}, StatusUnhealthy, false, false},
		{"no checkers", nil, StatusHealthy, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			registry := newProbeRegistry(t, tc.statuses...)

			ready := Readiness(context.Background(), registry)
			if ready.OK != tc.wantReady || ready.Status != tc.wantStatus {
				t.Errorf("Readiness = %+v, want OK=%v status=%s", ready, tc.wantReady, tc.wantStatus)
			}
			aggregate := Aggregate(context.Background(), registry)
			if aggregate.OK != tc.wantAggregate || aggregate.Status != tc.wantStatus {
				t.Errorf("Aggregate = %+v, want OK=%v status=%s", aggregate, tc.wantAggregate, tc.wantStatus)
			}
		})
	}
}

// A checker that never answers must not hold the probe: the registry's
// per-check deadline reports it unknown, which is not unhealthy, so the
// platform stays ready but is not healthy.
func TestReadiness_HungCheckerDoesNotBlock(t *testing.T) {
	registry := NewRegistry(WithDefaultTimeout(20 * time.Millisecond))
	t.Cleanup(func() {
		if err := registry.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	if err := registry.Register(newGatedChecker(t, "hung", StatusHealthy)); err != nil {
		t.Fatalf("Register: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ready := Readiness(ctx, registry)
	if ctx.Err() != nil {
		t.Fatal("Readiness waited for the hung checker past the caller's deadline")
	}
	if !ready.OK || ready.Status != StatusUnknown {
		t.Errorf("Readiness with a timed-out checker = %+v, want ready and unknown", ready)
	}
	if aggregate := Aggregate(ctx, registry); aggregate.OK {
		t.Errorf("Aggregate with a timed-out checker = %+v, want not OK", aggregate)
	}
}

func TestReadinessAndAggregate_ClosedRegistryIsNotReady(t *testing.T) {
	registry := NewRegistry()
	if err := registry.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if ready := Readiness(context.Background(), registry); ready.OK || ready.Status != StatusUnhealthy {
		t.Errorf("Readiness on a closed registry = %+v, want unhealthy and not ready", ready)
	}
	if aggregate := Aggregate(context.Background(), registry); aggregate.OK {
		t.Errorf("Aggregate on a closed registry = %+v, want not OK", aggregate)
	}
}

// An unwired registry keeps the documented fail-open answer (api.md §6).
func TestReadinessAndAggregate_NilRegistryFailsOpen(t *testing.T) {
	if ready := Readiness(context.Background(), nil); !ready.OK || ready.Status != StatusHealthy {
		t.Errorf("Readiness(nil) = %+v, want ready and healthy", ready)
	}
	if aggregate := Aggregate(context.Background(), nil); !aggregate.OK || aggregate.Status != StatusHealthy {
		t.Errorf("Aggregate(nil) = %+v, want OK and healthy", aggregate)
	}
}
