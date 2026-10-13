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

package daemon

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health/grpc_health_v1"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// stubRegistryComponent is a health.HealthChecker whose verdict the test
// controls, so registry aggregation can be driven without standing up a
// real service.
type stubRegistryComponent struct {
	name   string
	status health.HealthStatus
}

func (c *stubRegistryComponent) Name() string { return c.name }

func (c *stubRegistryComponent) Check(ctx context.Context) health.ComponentHealth {
	return health.ComponentHealth{Name: c.name, Status: c.status}
}

// newWiredHealthService builds the health service exactly as daemon.New
// wires it: an aggregate checker over the platform registry, and no
// RegisterService call. Tests that assert on the shipped configuration must
// go through here rather than registering service names of their own.
func newWiredHealthService(t *testing.T, components ...*stubRegistryComponent) *HealthGRPCService {
	t.Helper()

	registry := health.NewRegistry()
	t.Cleanup(func() { _ = registry.Close() })

	for _, c := range components {
		require.NoError(t, registry.Register(c))
	}

	svc := NewHealthGRPCService(logging.DefaultLogger())
	svc.RegisterHealthChecker(daemonHealthCheckerName, NewRegistryHealthChecker(registry))

	return svc
}

// TestHealthGRPCService_IsNotEnumerable is a SECURITY assertion, not a
// behavioural one.
//
// "/grpc.health.v1.Health/Check" is in grpcTCPSkipMethods,
// so on the TCP listener this RPC answers unauthenticated callers. Check
// distinguishes a registered name (returns a status) from an unregistered
// one (returns NOT_FOUND), which means any name that is registered becomes
// discoverable by guessing.
//
// The daemon therefore registers NO service names -- only an aggregate
// checker. This test pins that: a real component name must be as invisible
// as a fabricated one.
//
// If this test fails, someone added a RegisterService call. That is a
// service-inventory disclosure on an unauthenticated endpoint. Remove the
// RegisterService call; do not relax this test.
func TestHealthGRPCService_IsNotEnumerable(t *testing.T) {
	ctx := context.Background()
	svc := newWiredHealthService(t,
		&stubRegistryComponent{name: "ca", status: health.StatusHealthy},
		&stubRegistryComponent{name: "kms", status: health.StatusHealthy},
	)

	probes := []string{
		"ca",                    // a real registered component
		"kms",                   // another real one
		daemonHealthCheckerName, // the aggregate checker's own key
		"platform.v1.CAService", // a plausible gRPC service name
		"definitely-not-a-real-service",
	}

	for _, name := range probes {
		t.Run(name, func(t *testing.T) {
			resp, err := svc.Check(ctx, &grpc_health_v1.HealthCheckRequest{Service: name})

			require.Error(t, err, "every name must be indistinguishable; %q leaked", name)
			assert.Nil(t, resp)
			assert.Equal(t, codes.NotFound, grpcstatus.Code(err),
				"probe %q must answer NOT_FOUND like any other name", name)
		})
	}
}

// TestHealthGRPCService_CheckersOnly_ReportsUnhealthy covers the
// configuration the daemon actually ships: health checkers registered, no
// service names.
//
// The existing CheckOverallHealth tests all call RegisterService alongside
// RegisterHealthChecker, so the checkers-only path was never exercised --
// and it used to short-circuit to SERVING regardless of what the checkers
// said, which would leave a load balancer routing to a dead daemon.
func TestHealthGRPCService_CheckersOnly_ReportsUnhealthy(t *testing.T) {
	ctx := context.Background()
	empty := &grpc_health_v1.HealthCheckRequest{}

	t.Run("healthy components report SERVING", func(t *testing.T) {
		svc := newWiredHealthService(t,
			&stubRegistryComponent{name: "ca", status: health.StatusHealthy})

		resp, err := svc.Check(ctx, empty)

		require.NoError(t, err)
		assert.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, resp.Status)
	})

	t.Run("an unhealthy component reports NOT_SERVING", func(t *testing.T) {
		svc := newWiredHealthService(t,
			&stubRegistryComponent{name: "ca", status: health.StatusHealthy},
			&stubRegistryComponent{name: "kms", status: health.StatusUnhealthy})

		resp, err := svc.Check(ctx, empty)

		require.NoError(t, err)
		assert.Equal(t, grpc_health_v1.HealthCheckResponse_NOT_SERVING, resp.Status,
			"a checkers-only service must still be able to report a sick node")
	})

	t.Run("a degraded component stays SERVING", func(t *testing.T) {
		svc := newWiredHealthService(t,
			&stubRegistryComponent{name: "ca", status: health.StatusDegraded})

		resp, err := svc.Check(ctx, empty)

		require.NoError(t, err)
		assert.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, resp.Status,
			"degraded keeps the node in rotation on purpose; draining it can cascade")
	})

	t.Run("no components at all reports SERVING", func(t *testing.T) {
		svc := newWiredHealthService(t)

		resp, err := svc.Check(ctx, empty)

		require.NoError(t, err)
		assert.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, resp.Status)
	})
}

func TestNewRegistryHealthChecker(t *testing.T) {
	ctx := context.Background()

	t.Run("nil registry is healthy rather than a panic", func(t *testing.T) {
		assert.NoError(t, NewRegistryHealthChecker(nil).HealthCheck(ctx))
	})

	t.Run("unhealthy registry returns ErrDaemonUnhealthy with a count", func(t *testing.T) {
		registry := health.NewRegistry()
		t.Cleanup(func() { _ = registry.Close() })
		require.NoError(t, registry.Register(
			&stubRegistryComponent{name: "kms", status: health.StatusUnhealthy}))

		err := NewRegistryHealthChecker(registry).HealthCheck(ctx)

		require.Error(t, err)
		unhealthy, ok := err.(ErrDaemonUnhealthy)
		require.True(t, ok, "want ErrDaemonUnhealthy, got %T", err)
		assert.Equal(t, 1, unhealthy.UnhealthyCount)
		assert.NotContains(t, unhealthy.Error(), "kms",
			"component names must not reach an unauthenticated health response")
	})
}

// TestHealthGRPCService_ShutdownDrains pins that a daemon on its way down
// reports NOT_SERVING, so a load balancer stops sending it work before the
// listeners disappear.
func TestHealthGRPCService_ShutdownDrains(t *testing.T) {
	ctx := context.Background()
	svc := newWiredHealthService(t,
		&stubRegistryComponent{name: "ca", status: health.StatusHealthy})

	resp, err := svc.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	require.NoError(t, err)
	require.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, resp.Status)

	svc.Shutdown()

	resp, err = svc.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	require.NoError(t, err)
	assert.Equal(t, grpc_health_v1.HealthCheckResponse_NOT_SERVING, resp.Status)
}
