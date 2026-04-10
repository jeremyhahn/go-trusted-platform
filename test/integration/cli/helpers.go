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

//go:build integration

package cli

import (
	"fmt"
	"os"
	"testing"
)

// Environment variable names for service endpoints
const (
	EnvPlatformGRPCEndpoint = "PLATFORM_GRPC_ENDPOINT"
	EnvPlatformRESTEndpoint = "PLATFORM_REST_ENDPOINT"
	EnvPlatformQUICEndpoint = "PLATFORM_QUIC_ENDPOINT"
	EnvPlatformMCPEndpoint  = "PLATFORM_MCP_ENDPOINT"
	EnvPlatformUnixSocket   = "PLATFORM_UNIX_SOCKET"
	EnvPlatformCTL          = "PLATFORMCTL_PATH"
	EnvIntegrationTest      = "INTEGRATION_TEST"
)

// ServiceEndpoints contains default endpoints for all protocols.
type ServiceEndpoints struct {
	PlatformGRPC string
	PlatformREST string
	PlatformQUIC string
	PlatformMCP  string
	PlatformUnix string
	PlatformCTL  string
}

// GetServiceEndpoints returns the default service endpoints.
func GetServiceEndpoints() *ServiceEndpoints {
	return &ServiceEndpoints{
		PlatformGRPC: getEnvOrDefault(EnvPlatformGRPCEndpoint, "localhost:10443"),
		PlatformREST: getEnvOrDefault(EnvPlatformRESTEndpoint, "https://localhost:8443"),
		PlatformQUIC: getEnvOrDefault(EnvPlatformQUICEndpoint, "localhost:9444"),
		PlatformMCP:  getEnvOrDefault(EnvPlatformMCPEndpoint, "localhost:9445"),
		PlatformUnix: getEnvOrDefault(EnvPlatformUnixSocket, "/run/platformd.sock"),
		PlatformCTL:  getEnvOrDefault(EnvPlatformCTL, "platformctl"),
	}
}

// getEnvOrDefault returns the environment variable value or a default.
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// SkipIfNotIntegration skips the test if not running integration tests.
func SkipIfNotIntegration(t *testing.T) {
	if os.Getenv(EnvIntegrationTest) == "" {
		t.Skip("Skipping integration test: INTEGRATION_TEST not set")
	}
}

// =============================================================================
// Error Types
// =============================================================================

// ErrConnectionFailed indicates a connection failure.
type ErrConnectionFailed struct {
	Protocol string
	Endpoint string
	Err      error
}

func (e ErrConnectionFailed) Error() string {
	return fmt.Sprintf("%s connection failed to %s: %v", e.Protocol, e.Endpoint, e.Err)
}

func (e ErrConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrCallFailed indicates a protocol call failure.
type ErrCallFailed struct {
	Protocol string
	Method   string
	Err      error
}

func (e ErrCallFailed) Error() string {
	return fmt.Sprintf("%s call %s failed: %v", e.Protocol, e.Method, e.Err)
}

func (e ErrCallFailed) Unwrap() error {
	return e.Err
}

// ErrInvalidResponse indicates an invalid response from the server.
type ErrInvalidResponse struct {
	Protocol string
	Method   string
	Message  string
}

func (e ErrInvalidResponse) Error() string {
	return fmt.Sprintf("%s call %s returned invalid response: %s", e.Protocol, e.Method, e.Message)
}

// ErrServiceNotFound indicates a service was not found.
type ErrServiceNotFound struct {
	ServiceType string
}

func (e ErrServiceNotFound) Error() string {
	return fmt.Sprintf("service not found: %s", e.ServiceType)
}

// ErrContextNotFound indicates a context was not found.
type ErrContextNotFound struct {
	ContextName string
}

func (e ErrContextNotFound) Error() string {
	return fmt.Sprintf("context not found: %s", e.ContextName)
}

// ErrConfigSectionNotFound indicates a config section was not found.
type ErrConfigSectionNotFound struct {
	Section string
}

func (e ErrConfigSectionNotFound) Error() string {
	return fmt.Sprintf("config section not found: %s", e.Section)
}

// ErrInvalidShell indicates an invalid shell type.
type ErrInvalidShell struct {
	Shell string
}

func (e ErrInvalidShell) Error() string {
	return fmt.Sprintf("invalid shell type: %s", e.Shell)
}

// =============================================================================
// Test Utilities
// =============================================================================

// ValidServiceTypes returns the list of valid service types.
func ValidServiceTypes() []string {
	return []string{
		"tpm",
		"sdn",
		"compute",
		"dns",
		"acme",
		"webservice",
		"attestation",
	}
}

// ValidShellTypes returns the list of valid shell types for completion.
func ValidShellTypes() []string {
	return []string{
		"bash",
		"zsh",
		"fish",
		"powershell",
	}
}

// ValidContextTypes returns the list of valid context types.
func ValidContextTypes() []string {
	return []string{
		"local",
		"remote",
	}
}

// ValidHealthStatuses returns the list of valid health statuses.
func ValidHealthStatuses() []string {
	return []string{
		"HEALTHY",
		"DEGRADED",
		"UNHEALTHY",
		"UNKNOWN",
	}
}

// ValidServiceStatuses returns the list of valid service statuses.
func ValidServiceStatuses() []string {
	return []string{
		"RUNNING",
		"STOPPED",
		"STARTING",
		"STOPPING",
		"ERROR",
		"UNKNOWN",
	}
}

// ValidSystemStatuses returns the list of valid system statuses.
func ValidSystemStatuses() []string {
	return []string{
		"READY",
		"INITIALIZING",
		"DEGRADED",
		"UNAVAILABLE",
		"SHUTTING_DOWN",
		"UNKNOWN",
	}
}

// ContainsString checks if a slice contains a string.
func ContainsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
