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

package rest

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// probeServer answers the liveness probe Connect sends, and every other
// path with code and body.
func probeServer(code int, body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/live" {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	})
}

func TestProbeRoutes(t *testing.T) {
	for method, want := range map[string]string{
		platformv1.PlatformDaemon_GetHealth_FullMethodName: "/health",
		platformv1.PlatformDaemon_Liveness_FullMethodName:  "/health/live",
		platformv1.PlatformDaemon_Readiness_FullMethodName: "/health/ready",
	} {
		path, verb := mapGRPCMethodToREST(method)
		assert.Equal(t, want, path, method)
		assert.Equal(t, http.MethodGet, verb, method)
	}
}

// A probe that fails answers 503 with the verdict in the body; the SDK
// returns that verdict, as gRPC does, rather than an error.
func TestInvokeProbe_503CarriesTheVerdict(t *testing.T) {
	conn := connectTo(t, probeServer(http.StatusServiceUnavailable,
		`{"ready":false,"status":"HEALTH_STATUS_UNHEALTHY","timestamp":"2026-10-14T01:02:03Z"}`))

	var ready platformv1.ReadinessResponse
	err := conn.Invoke(context.Background(), platformv1.PlatformDaemon_Readiness_FullMethodName,
		&platformv1.ReadinessRequest{}, &ready)

	require.NoError(t, err)
	assert.False(t, ready.GetReady())
	assert.Equal(t, platformv1.HealthStatus_HEALTH_STATUS_UNHEALTHY, ready.GetStatus())
}

// A 503 that is not the probe's message — a proxy's error page — is not a
// verdict and stays Unavailable.
func TestInvokeProbe_503WithoutAVerdictIsAnError(t *testing.T) {
	conn := connectTo(t, probeServer(http.StatusServiceUnavailable, `<html>upstream unavailable</html>`))

	var summary platformv1.GetHealthResponse
	err := conn.Invoke(context.Background(), platformv1.PlatformDaemon_GetHealth_FullMethodName,
		&platformv1.GetHealthRequest{}, &summary)

	assert.Equal(t, codes.Unavailable, status.Code(err), "error = %v", err)
}

// Only the probes read a 503 as an answer; any other method's 503 is an error.
func TestInvokeNonProbe_503IsAnError(t *testing.T) {
	conn := connectTo(t, probeServer(http.StatusServiceUnavailable, `{"version":"1"}`))

	var version platformv1.GetVersionResponse
	err := conn.Invoke(context.Background(), platformv1.PlatformDaemon_GetVersion_FullMethodName,
		&platformv1.GetVersionRequest{}, &version)

	assert.Equal(t, codes.Unavailable, status.Code(err), "error = %v", err)
}

// Connect probes liveness, so a degraded platform — /health answering 503 —
// is still one the client connects to.
func TestConnect_ProbesLivenessNotAggregateHealth(t *testing.T) {
	conn := connectTo(t, probeServer(http.StatusServiceUnavailable,
		`{"status":"HEALTH_STATUS_DEGRADED","timestamp":"2026-10-14T01:02:03Z"}`))

	var summary platformv1.GetHealthResponse
	require.NoError(t, conn.Invoke(context.Background(), platformv1.PlatformDaemon_GetHealth_FullMethodName,
		&platformv1.GetHealthRequest{}, &summary))
	assert.Equal(t, platformv1.HealthStatus_HEALTH_STATUS_DEGRADED, summary.GetStatus())
}
