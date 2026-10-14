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

//go:build iam && codec_msgpack && codec_cbor && codec_json

package daemon

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
)

// =============================================================================
// Daemon TPM2Service Tests - daemon.go coverage
// =============================================================================

func TestDaemon_TPM2Service(t *testing.T) {
	t.Run("TPM2Service returns nil when not set", func(t *testing.T) {
		socketPath := fmt.Sprintf("/tmp/test-tpm2svc-%d.sock", os.Getpid())
		defer os.Remove(socketPath)

		config := testConfig(socketPath)
		config.EnableREST = false
		config.EnableMCP = false
		config.EnableQUIC = false

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}

		// TPM2Service should return nil when not configured
		svc := d.TPM2Service()
		assert.Nil(t, svc)
	})
}

// =============================================================================
// KMS Data Key Generation Error Tests - errors.go coverage
// =============================================================================

func TestErrorTypes_KMSDataKeyErrors(t *testing.T) {
	t.Run("ErrKMSDataKeyGenerationFailed", func(t *testing.T) {
		cause := assert.AnError
		err := ErrKMSDataKeyGenerationFailed{KeyID: "test-key-123", Cause: cause}
		errMsg := err.Error()
		assert.Contains(t, errMsg, "KMS data key generation failed")
		assert.Contains(t, errMsg, "test-key-123")
		assert.Equal(t, cause, err.Unwrap())
	})
}

// =============================================================================
// MCP Service Provider Health Operations Tests
// =============================================================================

func TestMCPServiceProvider_HealthOperations(t *testing.T) {
	provider := &MCPServiceProvider{}
	ctx := context.Background()

	t.Run("Health without daemon", func(t *testing.T) {
		result, err := provider.Health(ctx)
		assert.Nil(t, result)
		assert.Error(t, err)
	})

	t.Run("Liveness without daemon", func(t *testing.T) {
		result, err := provider.Liveness(ctx)
		assert.Nil(t, result)
		assert.Error(t, err)
	})

	t.Run("Readiness without daemon", func(t *testing.T) {
		result, err := provider.Readiness(ctx)
		assert.Nil(t, result)
		assert.Error(t, err)
	})
}

// =============================================================================
// MCP Service VTPMCreate Tests - mcp_service.go coverage
// =============================================================================

func TestMCPService_VTPMCreate_NoService(t *testing.T) {
	provider := &MCPServiceProvider{}
	ctx := context.Background()

	t.Run("VTPMCreate without vTPM service", func(t *testing.T) {
		result, err := provider.VTPMCreate(ctx, "test-vtpm", "ECC")
		assert.Nil(t, result)
		assert.Error(t, err)
	})
}

// =============================================================================
// MCP Service DNS Operations Tests - mcp_service.go coverage
// =============================================================================

func TestMCPService_DNSListZones_NoService(t *testing.T) {
	provider := &MCPServiceProvider{}
	ctx := context.Background()

	t.Run("DNSListZones without DNS service", func(t *testing.T) {
		result, err := provider.DNSListZones(ctx)
		assert.Nil(t, result)
		assert.Error(t, err)
	})
}

// =============================================================================
// MCP Service Device Operations Tests - mcp_service.go coverage
// =============================================================================

func TestMCPService_DeviceOperations_NoService(t *testing.T) {
	provider := &MCPServiceProvider{}
	ctx := context.Background()

	t.Run("DeviceRegister without device service", func(t *testing.T) {
		result, err := provider.DeviceRegister(ctx, &mcp.DeviceRegisterRequest{Model: "device-001", Serial: "test-device"})
		assert.Nil(t, result)
		assert.Error(t, err)
	})

	t.Run("DeviceList without device service", func(t *testing.T) {
		result, err := provider.DeviceList(ctx, nil)
		assert.Nil(t, result)
		assert.Error(t, err)
	})

	t.Run("DeviceDelete without device service", func(t *testing.T) {
		err := provider.DeviceDelete(ctx, "device-001")
		assert.Error(t, err)
	})

	t.Run("DeviceUpdate without device service", func(t *testing.T) {
		err := provider.DeviceUpdate(ctx, "device-001", nil)
		assert.Error(t, err)
	})
}

// =============================================================================
// MCP Service SDN Operations Tests - mcp_service.go coverage
// =============================================================================

func TestMCPService_SDNOperations_NoService(t *testing.T) {
	provider := &MCPServiceProvider{}
	ctx := context.Background()

	t.Run("SDNSetPortState without SDN service", func(t *testing.T) {
		_, err := provider.SDNSetPortState(ctx, "br0", "eth0", "up", mcp.PortRates{})
		assert.Error(t, err)
	})

	t.Run("SDNListPolicies without SDN service", func(t *testing.T) {
		result, err := provider.SDNListPolicies(ctx, "", "")
		assert.Nil(t, result)
		assert.Error(t, err)
	})

	t.Run("SDNGetPortStats without SDN service", func(t *testing.T) {
		result, err := provider.SDNGetPortStats(ctx, "br0", "eth0")
		assert.Nil(t, result)
		assert.Error(t, err)
	})

	t.Run("SDNGetFlowStats without SDN service", func(t *testing.T) {
		result, err := provider.SDNGetFlowStats(ctx, "br0", "0x1")
		assert.Nil(t, result)
		assert.Error(t, err)
	})
}
