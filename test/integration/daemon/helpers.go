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

// Package daemon provides integration test helpers for daemon services.
// These helpers provide reusable functions for testing daemon operations
// across all protocol adapters.

//go:build integration

package daemon

import (
	"context"
	"os"
	"strings"
	"time"
)

// =============================================================================
// Environment Variable Constants
// =============================================================================

const (
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
	return context.WithTimeout(context.Background(), 60*time.Second)
}

// LongRunningTestContext returns a context with a longer timeout for tests
// that may take more time.
func LongRunningTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Minute)
}

// ShortTestContext returns a context with a short timeout for quick operations.
func ShortTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

// =============================================================================
// Health Status Constants
// =============================================================================

const (
	// HealthStatusHealthy indicates a healthy component.
	HealthStatusHealthy = "healthy"

	// HealthStatusDegraded indicates a degraded component.
	HealthStatusDegraded = "degraded"

	// HealthStatusUnhealthy indicates an unhealthy component.
	HealthStatusUnhealthy = "unhealthy"
)

// =============================================================================
// Service Status Constants
// =============================================================================

const (
	// ServiceStatusStopped indicates a stopped service.
	ServiceStatusStopped = "stopped"

	// ServiceStatusStarting indicates a starting service.
	ServiceStatusStarting = "starting"

	// ServiceStatusRunning indicates a running service.
	ServiceStatusRunning = "running"

	// ServiceStatusStopping indicates a stopping service.
	ServiceStatusStopping = "stopping"

	// ServiceStatusError indicates a service in error state.
	ServiceStatusError = "error"
)

// =============================================================================
// Protobuf Enum Normalization Helpers
// =============================================================================

// normalizeHealthStatus converts a protobuf HealthStatus enum string to
// the lowercase test-expected value. Protobuf enums return values like
// "HEALTH_STATUS_HEALTHY" but tests expect "healthy".
func normalizeHealthStatus(s string) string {
	switch s {
	case "HEALTH_STATUS_HEALTHY":
		return HealthStatusHealthy
	case "HEALTH_STATUS_DEGRADED":
		return HealthStatusDegraded
	case "HEALTH_STATUS_UNHEALTHY":
		return HealthStatusUnhealthy
	default:
		return strings.ToLower(strings.TrimPrefix(s, "HEALTH_STATUS_"))
	}
}

// normalizeSystemStatus converts a protobuf SystemStatus enum string to
// the lowercase test-expected value. Protobuf enums return values like
// "SYSTEM_STATUS_READY" but tests expect "ready".
func normalizeSystemStatus(s string) string {
	switch s {
	case "SYSTEM_STATUS_READY":
		return "ready"
	case "SYSTEM_STATUS_INITIALIZING":
		return "initializing"
	case "SYSTEM_STATUS_DEGRADED":
		return "degraded"
	case "SYSTEM_STATUS_UNAVAILABLE":
		return "unavailable"
	case "SYSTEM_STATUS_SHUTTING_DOWN":
		return "shutting_down"
	default:
		return strings.ToLower(strings.TrimPrefix(s, "SYSTEM_STATUS_"))
	}
}

// normalizeServiceStatus converts a protobuf ServiceStatus enum string to
// the lowercase test-expected value. Protobuf enums return values like
// "SERVICE_STATUS_RUNNING" but tests expect "running".
func normalizeServiceStatus(s string) string {
	switch s {
	case "SERVICE_STATUS_RUNNING":
		return ServiceStatusRunning
	case "SERVICE_STATUS_STOPPED":
		return ServiceStatusStopped
	case "SERVICE_STATUS_STARTING":
		return ServiceStatusStarting
	case "SERVICE_STATUS_STOPPING":
		return ServiceStatusStopping
	case "SERVICE_STATUS_ERROR":
		return ServiceStatusError
	default:
		return strings.ToLower(strings.TrimPrefix(s, "SERVICE_STATUS_"))
	}
}
