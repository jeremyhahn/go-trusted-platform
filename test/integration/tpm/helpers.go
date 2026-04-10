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

package tpm

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

// SkipIfNotIntegration skips the test if not running integration tests.
func SkipIfNotIntegration(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") == "" {
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

// ErrTPMNotAvailable indicates the TPM is not available.
type ErrTPMNotAvailable struct {
	Reason string
}

func (e ErrTPMNotAvailable) Error() string {
	return fmt.Sprintf("TPM not available: %s", e.Reason)
}

// ErrKeyNotFound indicates a key was not found.
type ErrKeyNotFound struct {
	KeyType string
	Handle  uint32
}

func (e ErrKeyNotFound) Error() string {
	return fmt.Sprintf("key not found: %s at handle 0x%08X", e.KeyType, e.Handle)
}

// ErrSealedDataNotFound indicates sealed data was not found.
type ErrSealedDataNotFound struct {
	CN string
}

func (e ErrSealedDataNotFound) Error() string {
	return fmt.Sprintf("sealed data not found: %s", e.CN)
}
