// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

//go:build integration

package ntp

import (
	"context"
	"os"
	"strings"
	"time"
)

// Environment variable names for service endpoints. Kept in sync with
// build/docker/devcontainer/run-integration-tests.sh.
const (
	EnvPlatformGRPCEndpoint = "PLATFORM_GRPC_ENDPOINT"
	EnvPlatformRESTEndpoint = "PLATFORM_REST_ENDPOINT"
	EnvPlatformQUICEndpoint = "PLATFORM_QUIC_ENDPOINT"
	EnvPlatformMCPEndpoint  = "PLATFORM_MCP_ENDPOINT"
	EnvPlatformUnixSocket   = "PLATFORM_UNIX_SOCKET"
	EnvPlatformCTL          = "PLATFORMCTL_PATH"
)

// ServiceEndpoints carries the resolved endpoints for one integration run.
type ServiceEndpoints struct {
	PlatformGRPC string
	PlatformREST string
	PlatformQUIC string
	PlatformMCP  string
	PlatformUnix string
	PlatformCTL  string
}

// GetServiceEndpoints resolves the endpoints from the environment with the
// devcontainer defaults.
func GetServiceEndpoints() *ServiceEndpoints {
	return &ServiceEndpoints{
		PlatformGRPC: envOr(EnvPlatformGRPCEndpoint, "localhost:10443"),
		PlatformREST: envOr(EnvPlatformRESTEndpoint, "https://localhost:8443"),
		PlatformQUIC: envOr(EnvPlatformQUICEndpoint, "localhost:9444"),
		PlatformMCP:  envOr(EnvPlatformMCPEndpoint, "http://localhost:9445"),
		PlatformUnix: envOr(EnvPlatformUnixSocket, "/run/platformd.sock"),
		PlatformCTL:  envOr(EnvPlatformCTL, "platformctl"),
	}
}

// envOr returns the environment value for key, or fallback when unset.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// notConfiguredMarkers are the substrings every transport surfaces when the
// devcontainer's platformd has no `ntp:` section. The suite treats that as a
// valid contract outcome — it still proves the route/opcode/tool is wired —
// while any other failure is a real regression.
var notConfiguredMarkers = []string{
	"ntp service is not configured",
	"time synchronization is not enabled",
	"service not available: ntp",
	"quic service unavailable: ntp",
	"unavailable",
	"503",
}

// IsNotConfigured reports whether err is the "no ntp: section" surface.
func IsNotConfigured(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, marker := range notConfiguredMarkers {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// noReachableSourceMarkers are the substrings every transport surfaces when a
// manual step is requested with no reachable source. The condition is a
// conflict (REST 409), not a failure of the wiring.
var noReachableSourceMarkers = []string{
	"no reachable time source",
	"conflict",
	"409",
}

// IsNoReachableSource reports whether err is the step-conflict surface.
func IsNoReachableSource(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, marker := range noReachableSourceMarkers {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// SkipIfNotIntegration skips the test when INTEGRATION_TEST is not set, which
// is how the devcontainer runner gates every suite.
func SkipIfNotIntegration(t interface {
	Skip(args ...any)
}) {
	if os.Getenv("INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration test: INTEGRATION_TEST not set")
	}
}

// ShortContext derives a bounded per-call context.
func ShortContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 30*time.Second)
}
