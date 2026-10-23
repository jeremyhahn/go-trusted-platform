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

package v1

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// connectHealthSDK serves the webservice router on a TLS listener and
// connects the SDK's REST transport to it with no credential. Connect's
// liveness probe has to succeed against the real root routes.
func connectHealthSDK(t *testing.T, registry health.Registry) platformv1.PlatformDaemonClient {
	t.Helper()
	root := newGatedTestRouter(t, &testHandlerRegistry{
		tokenHandler:   &anonymousAuth{},
		healthRegistry: registry,
	})
	server := httptest.NewTLSServer(root)
	t.Cleanup(server.Close)

	tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	adapter, err := sdkrest.Connect(context.Background(),
		platform.NewOptions(platform.WithRESTAddr(server.URL), platform.WithTLSConfig(tlsConfig)))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, adapter.Close()) })

	return platformv1.NewPlatformDaemonClient(adapter.Connection())
}

// The SDK's three PlatformDaemon health claims resolve against the
// webservice listener, unauthenticated, and a failed probe comes back as its
// verdict, as it does over gRPC.
func TestHealthProbes_SDKRESTRoundTrip(t *testing.T) {
	cases := []struct {
		status     health.HealthStatus
		wantStatus platformv1.HealthStatus
		wantReady  bool
	}{
		{health.StatusHealthy, platformv1.HealthStatus_HEALTH_STATUS_HEALTHY, true},
		{health.StatusDegraded, platformv1.HealthStatus_HEALTH_STATUS_DEGRADED, true},
		{health.StatusUnhealthy, platformv1.HealthStatus_HEALTH_STATUS_UNHEALTHY, false},
	}
	for _, tc := range cases {
		t.Run(string(tc.status), func(t *testing.T) {
			registry := health.NewRegistry()
			t.Cleanup(func() {
				if err := registry.Close(); err != nil {
					t.Errorf("Close: %v", err)
				}
			})
			require.NoError(t, registry.Register(&fixedHealthChecker{name: "component-kms", status: tc.status}))
			client := connectHealthSDK(t, registry)
			ctx := context.Background()

			live, err := client.Liveness(ctx, &platformv1.LivenessRequest{})
			require.NoError(t, err)
			assert.True(t, live.GetAlive())

			ready, err := client.Readiness(ctx, &platformv1.ReadinessRequest{})
			require.NoError(t, err)
			assert.Equal(t, tc.wantReady, ready.GetReady())
			assert.Equal(t, tc.wantStatus, ready.GetStatus())

			summary, err := client.GetHealth(ctx, &platformv1.GetHealthRequest{})
			require.NoError(t, err)
			assert.Equal(t, tc.wantStatus, summary.GetStatus())
			assert.Empty(t, summary.GetComponents(), "the unauthenticated GetHealth names a component")
		})
	}
}
