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
		PlatformMCP:  envOr(EnvPlatformMCPEndpoint, "https://localhost:9445"),
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
// devcontainer's platformd has no `ntp:` section. The suite fails on that
// with ErrNTPNotConfigured, naming the missing section; any other failure is
// reported as itself. A bare Unavailable or 503 is not one of them: chronyd
// not answering its control socket (ntp.ErrControlUnavailable) carries the
// same class (docs/ntp/api.md §5), and naming it "no ntp: section" sent the
// diagnosis to a config that has one.
var notConfiguredMarkers = []string{
	"ntp service is not configured",
	"time synchronization is not enabled",
	"service not available: ntp",
	"quic service unavailable: ntp",
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

// ErrNTPNotConfigured is the missing prerequisite the suite fails on when
// platformd answers that it has no `ntp:` section: the NTP service is not
// running, so nothing the suite asserts can be checked.
type ErrNTPNotConfigured struct {
	Transport string
	Err       error
}

// Error implements the error interface.
func (e ErrNTPNotConfigured) Error() string {
	return e.Transport + ": platformd has no ntp: section, so its NTP service is not running; " +
		"the integration daemon's config (test/integration/config.yaml) needs one: " + e.Err.Error()
}

// Unwrap returns the transport's refusal.
func (e ErrNTPNotConfigured) Unwrap() error { return e.Err }

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

// ShortContext derives a bounded per-call context.
func ShortContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 30*time.Second)
}
