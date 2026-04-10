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

// Package pxe provides integration test helpers for PXE provisioning services.
// These helpers provide reusable functions for creating test devices,
// managing state transitions, and performing assertions in integration tests.

//go:build integration

package pxe

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
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

	// EnvPlatformAPIEndpoint is the environment variable for platform-api REST endpoint.
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

	// DefaultPlatformAPIEndpoint is the default platform-api REST endpoint.
	DefaultPlatformAPIEndpoint = "127.0.0.1:8443"

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
// Provisioning States
// =============================================================================

const (
	// StateDiscovered indicates the device has been discovered on the network.
	StateDiscovered = "discovered"

	// StateBooting indicates the device is PXE booting.
	StateBooting = "booting"

	// StateInstalling indicates the device is installing the OS.
	StateInstalling = "installing"

	// StateInstallComplete indicates the OS installation has completed.
	StateInstallComplete = "install_complete"

	// StateEnrolling indicates the device is enrolling with the PKI.
	StateEnrolling = "enrolling"

	// StateEnrolled indicates the device has completed PKI enrollment.
	StateEnrolled = "enrolled"

	// StateAuthorizing indicates the device is authorizing for production network.
	StateAuthorizing = "authorizing"

	// StateAuthorized indicates the device is authorized for production network.
	StateAuthorized = "authorized"

	// StateFailed indicates the provisioning process has failed.
	StateFailed = "failed"

	// StateQuarantined indicates the device has been quarantined.
	StateQuarantined = "quarantined"
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
// Test Data Generators
// =============================================================================

// GenerateTestMAC generates a unique MAC address for testing.
// The MAC is in the locally administered address range (second nibble is 2, 6, A, or E).
// Format: 02:xx:xx:xx:xx:xx where xx values are derived from timestamp.
func GenerateTestMAC(prefix string) string {
	now := time.Now().UnixNano()
	return fmt.Sprintf("02:%02x:%02x:%02x:%02x:%02x",
		(now>>40)&0xff,
		(now>>32)&0xff,
		(now>>24)&0xff,
		(now>>16)&0xff,
		(now>>8)&0xff,
	)
}

// GenerateTestPortID generates a unique OVS port ID for testing.
func GenerateTestPortID(prefix string) string {
	return fmt.Sprintf("%s-port-%d", prefix, time.Now().UnixNano())
}

// GenerateTestCertSerial generates a unique certificate serial for testing.
func GenerateTestCertSerial() string {
	return fmt.Sprintf("CERT-%d", time.Now().UnixNano())
}

// =============================================================================
// Test Context Helpers
// =============================================================================

// DefaultTestContext returns a context with a reasonable timeout for integration tests.
func DefaultTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 60*time.Second)
}

// LongRunningTestContext returns a context with a longer timeout for tests
// that may take more time (e.g., full provisioning workflows).
func LongRunningTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Minute)
}

// ShortTestContext returns a context with a short timeout for quick operations.
func ShortTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

// =============================================================================
// Default Test Options
// =============================================================================

// DefaultRegisterOptions returns default device registration options for tests.
func DefaultRegisterOptions(prefix string) RegisterDeviceOptions {
	return RegisterDeviceOptions{
		MACAddress: GenerateTestMAC(prefix),
		PortID:     GenerateTestPortID(prefix),
	}
}

// =============================================================================
// Test Cleanup Helpers
// =============================================================================

// CleanupDevice removes a test device if it exists.
// This is a helper for ensuring test cleanup even on test failures.
func CleanupDevice(ctx context.Context, cmd PXECommands, deviceID string) error {
	if deviceID == "" {
		return nil
	}
	_, err := cmd.RemoveDevice(ctx, deviceID)
	return err
}

// CleanupDevices removes multiple test devices.
func CleanupDevices(ctx context.Context, cmd PXECommands, deviceIDs []string) {
	for _, id := range deviceIDs {
		_ = CleanupDevice(ctx, cmd, id)
	}
}

// =============================================================================
// State Transition Helpers
// =============================================================================

// ValidStateTransitions maps source states to valid target states.
var ValidStateTransitions = map[string][]string{
	StateDiscovered:      {StateBooting, StateFailed, StateQuarantined},
	StateBooting:         {StateInstalling, StateFailed, StateQuarantined},
	StateInstalling:      {StateInstallComplete, StateFailed, StateQuarantined},
	StateInstallComplete: {StateEnrolling, StateFailed, StateQuarantined},
	StateEnrolling:       {StateEnrolled, StateFailed, StateQuarantined},
	StateEnrolled:        {StateAuthorizing, StateFailed, StateQuarantined},
	StateAuthorizing:     {StateAuthorized, StateFailed, StateQuarantined},
	StateAuthorized:      {StateQuarantined},
	StateFailed:          {StateDiscovered, StateQuarantined},
	StateQuarantined:     {StateDiscovered},
}

// IsValidTransition checks if a state transition is valid.
func IsValidTransition(from, to string) bool {
	allowed, exists := ValidStateTransitions[from]
	if !exists {
		return false
	}
	for _, state := range allowed {
		if state == to {
			return true
		}
	}
	return false
}

// GetValidTargetStates returns valid target states for a given source state.
func GetValidTargetStates(from string) []string {
	return ValidStateTransitions[from]
}

// =============================================================================
// Assertion Helpers
// =============================================================================

// AssertDeviceState asserts that a device is in the expected state.
func AssertDeviceState(t *testing.T, device *GetDeviceResult, expectedState string) {
	t.Helper()
	if device.State != expectedState {
		t.Errorf("Expected device state %q, got %q", expectedState, device.State)
	}
}

// AssertDeviceVLAN asserts that a device is on the expected VLAN.
func AssertDeviceVLAN(t *testing.T, device *GetDeviceResult, expectedVLAN uint16) {
	t.Helper()
	if device.CurrentVLAN != expectedVLAN {
		t.Errorf("Expected device VLAN %d, got %d", expectedVLAN, device.CurrentVLAN)
	}
}

// AssertEventCount asserts that a device has the expected number of events.
func AssertEventCount(t *testing.T, events *GetEventsResult, expectedCount int) {
	t.Helper()
	if len(events.Events) != expectedCount {
		t.Errorf("Expected %d events, got %d", expectedCount, len(events.Events))
	}
}
