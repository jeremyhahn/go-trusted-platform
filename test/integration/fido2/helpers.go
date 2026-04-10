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

package fido2

import (
	"fmt"
	"os"
	"testing"
)

// Environment variable names for service endpoints and configuration.
const (
	EnvPlatformGRPCEndpoint = "PLATFORM_GRPC_ENDPOINT"
	EnvPlatformRESTEndpoint = "PLATFORM_REST_ENDPOINT"
	EnvPlatformQUICEndpoint = "PLATFORM_QUIC_ENDPOINT"
	EnvPlatformMCPEndpoint  = "PLATFORM_MCP_ENDPOINT"
	EnvPlatformUnixSocket   = "PLATFORM_UNIX_SOCKET"
	EnvPlatformCTL          = "PLATFORMCTL_PATH"

	// FIDO2-specific environment variables
	EnvFIDO2Device     = "FIDO2_TEST_DEVICE"
	EnvFIDO2Passphrase = "FIDO2_TEST_PASSPHRASE"
	EnvFIDO2Available  = "FIDO2_DEVICE_AVAILABLE"
	EnvLUKSAvailable   = "LUKS_DEVICE_AVAILABLE"
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
		PlatformGRPC: "localhost:10443",
		PlatformREST: "https://localhost:8443",
		PlatformQUIC: "localhost:9444",
		PlatformMCP:  "localhost:9445",
		PlatformUnix: "/run/platformd.sock",
		PlatformCTL:  "platformctl",
	}
}

// TestConfig contains configuration for FIDO2 integration tests.
type TestConfig struct {
	Device          string
	Passphrase      string
	FIDO2Available  bool
	LUKSAvailable   bool
	SkipDestructive bool
	DefaultSlot     int
	DefaultRP       string
	DefaultUser     string
}

// GetTestConfig returns the test configuration from environment variables.
func GetTestConfig() *TestConfig {
	config := &TestConfig{
		Device:          os.Getenv(EnvFIDO2Device),
		Passphrase:      os.Getenv(EnvFIDO2Passphrase),
		FIDO2Available:  os.Getenv(EnvFIDO2Available) == "true",
		LUKSAvailable:   os.Getenv(EnvLUKSAvailable) == "true",
		SkipDestructive: os.Getenv("SKIP_DESTRUCTIVE_TESTS") == "true",
		DefaultSlot:     3,
		DefaultRP:       "luks-test",
		DefaultUser:     "luks-test-user",
	}

	// Use defaults if not set
	if config.Device == "" {
		config.Device = "/dev/vda2"
	}

	return config
}

// SkipIfNotIntegration skips the test if not running integration tests.
func SkipIfNotIntegration(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration test: INTEGRATION_TEST not set")
	}
}

// SkipIfNoFIDO2Device skips the test if no FIDO2 device is available.
func SkipIfNoFIDO2Device(t *testing.T) {
	if os.Getenv(EnvFIDO2Available) != "true" {
		t.Skip("Skipping test: No FIDO2 device available (set FIDO2_DEVICE_AVAILABLE=true)")
	}
}

// SkipIfNoLUKSDevice skips the test if no LUKS device is available.
func SkipIfNoLUKSDevice(t *testing.T) {
	if os.Getenv(EnvLUKSAvailable) != "true" {
		t.Skip("Skipping test: No LUKS device available (set LUKS_DEVICE_AVAILABLE=true)")
	}
}

// SkipIfNotRoot skips the test if not running as root.
func SkipIfNotRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Skipping test: must be run as root")
	}
}

// SkipDestructiveTest skips tests that modify LUKS device state.
func SkipDestructiveTest(t *testing.T) {
	if os.Getenv("SKIP_DESTRUCTIVE_TESTS") == "true" {
		t.Skip("Skipping destructive test: SKIP_DESTRUCTIVE_TESTS=true")
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

// ErrFIDO2DeviceNotAvailable indicates no FIDO2 device is present.
type ErrFIDO2DeviceNotAvailable struct {
	Reason string
}

func (e ErrFIDO2DeviceNotAvailable) Error() string {
	return fmt.Sprintf("FIDO2 device not available: %s", e.Reason)
}

// ErrLUKSDeviceNotAvailable indicates no LUKS device is present.
type ErrLUKSDeviceNotAvailable struct {
	Device string
	Reason string
}

func (e ErrLUKSDeviceNotAvailable) Error() string {
	return fmt.Sprintf("LUKS device not available (%s): %s", e.Device, e.Reason)
}

// ErrTokenNotFound indicates a FIDO2 token was not found.
type ErrTokenNotFound struct {
	TokenID string
}

func (e ErrTokenNotFound) Error() string {
	return fmt.Sprintf("FIDO2 token not found: %s", e.TokenID)
}

// ErrKeyslotNotFound indicates a keyslot was not found.
type ErrKeyslotNotFound struct {
	Slot int
}

func (e ErrKeyslotNotFound) Error() string {
	return fmt.Sprintf("keyslot not found: %d", e.Slot)
}

// ErrEnrollmentFailed indicates FIDO2 enrollment failed.
type ErrEnrollmentFailed struct {
	Reason string
}

func (e ErrEnrollmentFailed) Error() string {
	return fmt.Sprintf("FIDO2 enrollment failed: %s", e.Reason)
}

// ErrRemovalFailed indicates FIDO2 token removal failed.
type ErrRemovalFailed struct {
	Reason string
}

func (e ErrRemovalFailed) Error() string {
	return fmt.Sprintf("FIDO2 token removal failed: %s", e.Reason)
}

// ErrUnlockTestFailed indicates FIDO2 unlock test failed.
type ErrUnlockTestFailed struct {
	Reason string
}

func (e ErrUnlockTestFailed) Error() string {
	return fmt.Sprintf("FIDO2 unlock test failed: %s", e.Reason)
}

// ErrRootRequired indicates root privileges are required.
type ErrRootRequired struct{}

func (e ErrRootRequired) Error() string {
	return "this operation requires root privileges"
}

// ErrInvalidResponse indicates an unexpected response format.
type ErrInvalidResponse struct {
	Method string
	Reason string
}

func (e ErrInvalidResponse) Error() string {
	return fmt.Sprintf("invalid response from %s: %s", e.Method, e.Reason)
}
