//go:build integration

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

// Package tenant provides integration test adapters for Tenant services.
// This file provides helper functions for tenant integration tests.
package tenant

import (
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

// SkipIfNotIntegration skips the test if not running in integration mode
func SkipIfNotIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration test. Set INTEGRATION_TEST=1 to run.")
	}
}

// GenerateTestTenantName generates a unique tenant name for testing
func GenerateTestTenantName(prefix string) string {
	return "test-tenant-" + prefix + "-" + uuid.New().String()[:8]
}

// GenerateTestDisplayName generates a unique display name for testing
func GenerateTestDisplayName(prefix string) string {
	return "Test Tenant " + prefix + " " + uuid.New().String()[:4]
}

// DefaultComputeQuota returns default compute quota settings for tests
func DefaultComputeQuota() *ComputeQuotaUpdate {
	return &ComputeQuotaUpdate{
		MaxVMs:        10,
		MaxContainers: 50,
		MaxVCPUs:      32,
		MaxMemoryMB:   65536, // 64GB
		MaxDiskGB:     500,
	}
}

// DefaultNetworkQuota returns default network quota settings for tests
func DefaultNetworkQuota() *NetworkQuotaUpdate {
	return &NetworkQuotaUpdate{
		MaxBridges:       5,
		MaxPorts:         100,
		MaxBandwidthMbps: 10000, // 10Gbps
	}
}

// DefaultStorageQuota returns default storage quota settings for tests
func DefaultStorageQuota() *StorageQuotaUpdate {
	return &StorageQuotaUpdate{
		MaxVolumesGB: 1000,
		MaxSnapshots: 50,
	}
}

// DefaultVLANRange returns a default VLAN range for tests
func DefaultVLANRange() *VLANRangeOption {
	return &VLANRangeOption{
		Start: 100,
		End:   199,
	}
}

// DefaultLabels returns default labels for test tenants
func DefaultLabels() map[string]string {
	return map[string]string{
		"environment": "test",
		"created-by":  "integration-test",
	}
}

// DefaultAnnotations returns default annotations for test tenants
func DefaultAnnotations() map[string]string {
	return map[string]string{
		"description":    "Integration test tenant",
		"created-at":     time.Now().UTC().Format(time.RFC3339),
		"test-framework": "go-test",
	}
}

// GetRESTEndpoint returns the REST API endpoint
func GetRESTEndpoint() string {
	if endpoint := os.Getenv("TENANT_REST_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return "https://localhost:8443"
}

// GetGRPCEndpoint returns the gRPC API endpoint
func GetGRPCEndpoint() string {
	if endpoint := os.Getenv("TENANT_GRPC_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return "localhost:10443"
}

// GetQUICEndpoint returns the QUIC API endpoint
func GetQUICEndpoint() string {
	if endpoint := os.Getenv("TENANT_QUIC_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return "localhost:9444"
}

// GetMCPEndpoint returns the MCP API endpoint
func GetMCPEndpoint() string {
	if endpoint := os.Getenv("TENANT_MCP_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return "http://localhost:9445"
}

// GetSocketPath returns the Unix socket path
func GetSocketPath() string {
	if path := os.Getenv("TENANT_SOCKET_PATH"); path != "" {
		return path
	}
	return "/run/platformd.sock"
}

// GetCLIPath returns the path to the platformctl CLI
func GetCLIPath() string {
	if path := os.Getenv("PLATFORMCTL_PATH"); path != "" {
		return path
	}
	return "platformctl"
}

// Endpoints contains all API endpoints for tenant operations
type Endpoints struct {
	REST   string
	GRPC   string
	QUIC   string
	MCP    string
	Socket string
	CLI    string
}

// GetEndpoints returns all configured endpoints
func GetEndpoints() *Endpoints {
	return &Endpoints{
		REST:   GetRESTEndpoint(),
		GRPC:   GetGRPCEndpoint(),
		QUIC:   GetQUICEndpoint(),
		MCP:    GetMCPEndpoint(),
		Socket: GetSocketPath(),
		CLI:    GetCLIPath(),
	}
}
