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

package orchestrator

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

// containsAny reports whether err's message contains one of markers,
// compared case-insensitively. A nil err matches nothing.
func containsAny(err error, markers []string) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, marker := range markers {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// notConfiguredMarkers are the substrings every transport surfaces when
// platformd has no go-quicbaas orchestrator client
// (orchestrator.ErrNotConfigured) or no OrchestratorService at all.
var notConfiguredMarkers = []string{
	"orchestrator client is not configured",
	"service not available: orchestrator",
	"quic service unavailable: orchestrator",
}

// IsNotConfigured reports whether err is the "no orchestrator" surface.
func IsNotConfigured(err error) bool {
	return containsAny(err, notConfiguredMarkers)
}

// notFoundMarkers are the substrings the transports carry for a gRPC
// NotFound: the status code name, the HTTP status, and the plain phrase the
// MCP and QUIC error bodies use.
var notFoundMarkers = []string{
	"notfound",
	"not found",
	"404",
}

// IsNotFound reports whether err is the not-found class.
func IsNotFound(err error) bool {
	return containsAny(err, notFoundMarkers)
}

// invalidArgumentMarkers are the substrings the transports carry for an
// InvalidArgument refusal: the service layer's own messages, the REST SDK's
// client-side refusal of an empty path field, the gRPC code name and the HTTP
// status.
var invalidArgumentMarkers = []string{
	"is required",
	"must not be negative",
	"requires non-zero",
	"invalidargument",
	"invalid argument",
	"400",
}

// IsInvalidArgument reports whether err is the invalid-argument class.
func IsInvalidArgument(err error) bool {
	return containsAny(err, invalidArgumentMarkers)
}

// ErrOrchestratorNotConfigured is the missing prerequisite the suite fails on
// when platformd answers that it has no go-quicbaas orchestrator client:
// nothing the suite asserts can be checked without one.
type ErrOrchestratorNotConfigured struct {
	Transport string
	Err       error
}

// Error implements the error interface.
func (e ErrOrchestratorNotConfigured) Error() string {
	return e.Transport + ": platformd has no go-quicbaas orchestrator client, so the " +
		"OrchestratorService cannot reach the agent fleet; the integration daemon " +
		"needs its embedded go-quicbaas SDK running: " + e.Err.Error()
}

// Unwrap returns the transport's refusal.
func (e ErrOrchestratorNotConfigured) Unwrap() error { return e.Err }

// ShortContext derives a bounded per-call context.
func ShortContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 30*time.Second)
}
