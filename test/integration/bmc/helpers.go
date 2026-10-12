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

// Package bmc_integration provides multi-protocol integration test helpers
// and adapters for BMC (Baseboard Management Controller) services.

//go:build integration

package bmc_integration

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
)

// =============================================================================
// Environment Variable Constants
// =============================================================================

const (
	// EnvIntegrationTest is the environment variable that must be set to run
	// integration tests. Set INTEGRATION_TEST=1 to enable.
	EnvIntegrationTest = "INTEGRATION_TEST"

	// EnvPlatformdSocket is the Unix socket path for platformd.
	EnvPlatformdSocket = "PLATFORMD_SOCKET"

	// EnvPlatformAPIEndpoint is the environment variable for the platformd REST endpoint.
	EnvPlatformAPIEndpoint = "PLATFORM_API_ENDPOINT"

	// EnvPlatformGRPCEndpoint is the environment variable for platformd gRPC endpoint.
	EnvPlatformGRPCEndpoint = "PLATFORM_GRPC_ENDPOINT"

	// EnvPlatformQUICEndpoint is the environment variable for platformd QUIC endpoint.
	EnvPlatformQUICEndpoint = "PLATFORM_QUIC_ENDPOINT"

	// EnvPlatformMCPEndpoint is the environment variable for platformd MCP endpoint.
	EnvPlatformMCPEndpoint = "PLATFORM_MCP_ENDPOINT"

	// EnvPlatformctlBinary is the path to the platformctl binary.
	EnvPlatformctlBinary = "PLATFORMCTL_BINARY"
)

// =============================================================================
// Default Endpoints
// =============================================================================

const (
	// DefaultPlatformdSocket is the default Unix socket path.
	DefaultPlatformdSocket = "/run/platformd.sock"

	// DefaultPlatformAPIEndpoint is the default platformd REST endpoint.
	DefaultPlatformAPIEndpoint = "http://127.0.0.1:8443"

	// DefaultPlatformGRPCEndpoint is the default platformd gRPC endpoint.
	DefaultPlatformGRPCEndpoint = "127.0.0.1:10443"

	// DefaultPlatformQUICEndpoint is the default platformd QUIC endpoint.
	DefaultPlatformQUICEndpoint = "127.0.0.1:9444"

	// DefaultPlatformMCPEndpoint is the default platformd MCP endpoint.
	DefaultPlatformMCPEndpoint = "127.0.0.1:9445"

	// DefaultPlatformctlBinary is the default binary name when not specified.
	DefaultPlatformctlBinary = "platformctl"

	// DefaultCommandTimeout is the default timeout for CLI commands.
	DefaultCommandTimeout = 30 * time.Second
)

// =============================================================================
// Skip Helpers
// =============================================================================

// SkipIfNotIntegration skips the test if the INTEGRATION_TEST environment
// variable is not set. This ensures integration tests only run when explicitly
// requested, preventing accidental execution during normal unit testing.
func SkipIfNotIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv(EnvIntegrationTest) == "" {
		t.Skip("Skipping integration test. Set INTEGRATION_TEST=1 to run.")
	}
}

// =============================================================================
// Endpoint Configuration
// =============================================================================

// ServiceEndpoints contains all configured service endpoints.
type ServiceEndpoints struct {
	PlatformdSocket string
	PlatformAPI     string
	PlatformGRPC    string
	PlatformQUIC    string
	PlatformMCP     string
}

// GetServiceEndpoints returns service endpoints from environment
// variables with sensible defaults.
func GetServiceEndpoints() ServiceEndpoints {
	return ServiceEndpoints{
		PlatformdSocket: getEnvOrDefault(EnvPlatformdSocket, DefaultPlatformdSocket),
		PlatformAPI:     getEnvOrDefault(EnvPlatformAPIEndpoint, DefaultPlatformAPIEndpoint),
		PlatformGRPC:    getEnvOrDefault(EnvPlatformGRPCEndpoint, DefaultPlatformGRPCEndpoint),
		PlatformQUIC:    getEnvOrDefault(EnvPlatformQUICEndpoint, DefaultPlatformQUICEndpoint),
		PlatformMCP:     getEnvOrDefault(EnvPlatformMCPEndpoint, DefaultPlatformMCPEndpoint),
	}
}

// getEnvOrDefault returns the environment variable value or the default if not set.
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// =============================================================================
// Test Context Helpers
// =============================================================================

// DefaultTestContext returns a context with a reasonable timeout for integration tests.
func DefaultTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), DefaultBMCTestTimeout)
}

// =============================================================================
// Not-Implemented / Tolerated-Failure Detection
// =============================================================================

// daemonWithoutApp is the suffix of the refusal every transport returns when
// platformd runs without an App, so no BMC enroller is wired
// (ErrBMCEnrollerNotConfigured in pkg/api/daemon, ErrBMCEnrollerNotAvailable in
// pkg/webservice/v1/bmc). It names that one deployment gap and nothing else;
// a missing surface is matched by type through surface.IsNotImplemented (#487).
const daemonWithoutApp = "(daemon started without App)"

// isEnrollServiceUnavailable returns true if the error indicates the enrollment
// ceremony service is not wired or available on the current transport. Tests
// use this to distinguish a deployment-config gap (acceptable outcome) from a
// genuine test failure.
func isEnrollServiceUnavailable(err error) bool {
	if err == nil {
		return false
	}
	var unavailable ErrEnrollServiceUnavailable
	if errors.As(err, &unavailable) || surface.IsNotImplemented(err) {
		return true
	}
	return strings.Contains(err.Error(), daemonWithoutApp)
}

// isRestoreServiceUnavailable returns true if the error indicates the factory-
// certificate restore service is not wired or available on the current transport.
// Tests use this to distinguish a deployment-config gap (acceptable outcome) from
// a genuine transport failure.
func isRestoreServiceUnavailable(err error) bool {
	if err == nil {
		return false
	}
	switch err.(type) {
	case ErrRestoreServiceUnavailable:
		return true
	}
	return false
}
