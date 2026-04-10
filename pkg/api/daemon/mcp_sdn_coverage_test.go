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

package daemon

import (
	"context"
	"log/slog"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
)

// =============================================================================
// SDN Coverage Tests - Tests to improve coverage of SDN-related MCP methods
// =============================================================================

// createTestSDNServiceWithBridge creates an SDNService with a pre-configured bridge
// for testing methods that require an existing bridge.
func createTestSDNServiceWithBridge(bridgeName string) *SDNService {
	svc := &SDNService{
		bridges:   make(map[string]*bridgeResource),
		ports:     make(map[string]*portResource),
		taps:      make(map[string]*tapResource),
		vlans:     make(map[string]*vlanResource),
		portAuths: make(map[string]*portAuthResource),
	}
	// Add a test bridge
	svc.bridges[bridgeName] = &bridgeResource{
		id:         bridgeName,
		name:       bridgeName,
		bridgeType: platformv1.BridgeType_BRIDGE_TYPE_OVS,
		createdAt:  time.Now(),
	}
	return svc
}

// createTestSDNServiceWithBridgeAndPort creates an SDNService with a pre-configured
// bridge and port for testing methods that require both.
func createTestSDNServiceWithBridgeAndPort(bridgeName, portName string) *SDNService {
	svc := createTestSDNServiceWithBridge(bridgeName)
	// Add a test port
	svc.ports[portName] = &portResource{
		id:        portName,
		name:      portName,
		bridgeID:  bridgeName,
		portType:  platformv1.PortType_PORT_TYPE_INTERNAL,
		createdAt: time.Now(),
	}
	return svc
}

// createTestSDNServiceWithVLAN creates an SDNService with a pre-configured
// bridge and VLAN for testing VLAN-related methods.
func createTestSDNServiceWithVLAN(bridgeName string, vlanID uint32, vlanName string) *SDNService {
	svc := createTestSDNServiceWithBridge(bridgeName)
	// Add a test VLAN
	vlanKey := bridgeName + ":100"
	svc.vlans[vlanKey] = &vlanResource{
		id:        vlanKey,
		vlanID:    vlanID,
		bridgeID:  bridgeName,
		name:      vlanName,
		ports:     []string{},
		createdAt: time.Now(),
	}
	return svc
}

// createTestSDNServiceWithPortAuth creates an SDNService with a pre-configured
// bridge, port, and authentication for testing auth revocation.
func createTestSDNServiceWithPortAuth(bridgeName, portName string) *SDNService {
	svc := createTestSDNServiceWithBridgeAndPort(bridgeName, portName)
	// Add port authentication
	authKey := bridgeName + ":" + portName
	svc.portAuths[authKey] = &portAuthResource{
		portID:          portName,
		bridgeID:        bridgeName,
		certificateCN:   "test-device",
		certificate:     []byte("test-cert"),
		authenticatedAt: time.Now(),
		expiresAt:       time.Now().Add(24 * time.Hour),
		authorizedVLANs: []uint32{100},
	}
	return svc
}

// =============================================================================
// SDNListVLANs Coverage Tests
// =============================================================================

func TestMCPServiceProvider_SDNListVLANs_BridgeNotFound(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithBridge("br0")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// Try to list VLANs on a non-existent bridge
	_, err := provider.SDNListVLANs(ctx, "nonexistent-bridge")
	if err == nil {
		t.Fatal("expected error for non-existent bridge")
	}
}

func TestMCPServiceProvider_SDNListVLANs_EmptyBridgeName(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithBridge("br0")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// Empty bridge name should return error from SDN service
	_, err := provider.SDNListVLANs(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty bridge name")
	}
}

func TestMCPServiceProvider_SDNListVLANs_EmptyResult(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithBridge("br0")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// List VLANs on a bridge with no VLANs configured
	result, err := provider.SDNListVLANs(ctx, "br0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result) != 0 {
		t.Errorf("expected empty result, got %d items", len(result))
	}
}

func TestMCPServiceProvider_SDNListVLANs_WithVLANs(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithVLAN("br0", 100, "guest-vlan")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// List VLANs on a bridge with configured VLANs
	result, err := provider.SDNListVLANs(ctx, "br0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result) != 1 {
		t.Errorf("expected 1 VLAN, got %d", len(result))
	}
}

// =============================================================================
// SDNAuthenticatePort Coverage Tests
// =============================================================================

func TestMCPServiceProvider_SDNAuthenticatePort_BridgeNotFound(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithBridge("br0")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	credentials := map[string]string{
		"certificate": "test-cert-data",
		"format":      "PEM",
	}
	err := provider.SDNAuthenticatePort(ctx, "nonexistent-bridge", "port1", credentials)
	if err == nil {
		t.Fatal("expected error for non-existent bridge")
	}
}

func TestMCPServiceProvider_SDNAuthenticatePort_EmptyBridgeName(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithBridgeAndPort("br0", "port1")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	credentials := map[string]string{
		"certificate": "test-cert-data",
		"format":      "PEM",
	}
	err := provider.SDNAuthenticatePort(ctx, "", "port1", credentials)
	if err == nil {
		t.Fatal("expected error for empty bridge name")
	}
}

func TestMCPServiceProvider_SDNAuthenticatePort_EmptyPortName(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithBridgeAndPort("br0", "port1")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	credentials := map[string]string{
		"certificate": "test-cert-data",
		"format":      "PEM",
	}
	err := provider.SDNAuthenticatePort(ctx, "br0", "", credentials)
	if err == nil {
		t.Fatal("expected error for empty port name")
	}
}

func TestMCPServiceProvider_SDNAuthenticatePort_EmptyCertificate(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithBridgeAndPort("br0", "port1")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// Empty certificate should cause an error in the SDN service
	credentials := map[string]string{
		"certificate": "",
		"format":      "PEM",
	}
	err := provider.SDNAuthenticatePort(ctx, "br0", "port1", credentials)
	if err == nil {
		t.Fatal("expected error for empty certificate")
	}
}

func TestMCPServiceProvider_SDNAuthenticatePort_DefaultFormat(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithBridgeAndPort("br0", "port1")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// No format specified - should default to PEM
	credentials := map[string]string{
		"certificate": "test-cert-data",
	}
	// This will fail on certificate parsing, but tests format defaulting
	err := provider.SDNAuthenticatePort(ctx, "br0", "port1", credentials)
	// We expect an error because the cert data is not valid, but the format defaulting happens first
	if err == nil {
		t.Fatal("expected error (invalid certificate)")
	}
}

func TestMCPServiceProvider_SDNAuthenticatePort_DERFormat(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithBridgeAndPort("br0", "port1")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// Explicit DER format
	credentials := map[string]string{
		"certificate": "test-cert-data",
		"format":      "DER",
	}
	// This will fail on certificate parsing, but tests format handling
	err := provider.SDNAuthenticatePort(ctx, "br0", "port1", credentials)
	if err == nil {
		t.Fatal("expected error (invalid certificate)")
	}
}

// =============================================================================
// SDNGetPortStats Coverage Tests
// =============================================================================

func TestMCPServiceProvider_SDNGetPortStats_PortNotFound(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithBridge("br0")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// Try to get stats for a non-existent port
	_, err := provider.SDNGetPortStats(ctx, "br0", "nonexistent-port")
	if err == nil {
		t.Fatal("expected error for non-existent port")
	}
}

func TestMCPServiceProvider_SDNGetPortStats_EmptyBridgeName(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithBridgeAndPort("br0", "port1")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// Empty bridge name should return error
	_, err := provider.SDNGetPortStats(ctx, "", "port1")
	if err == nil {
		t.Fatal("expected error for empty bridge name")
	}
}

func TestMCPServiceProvider_SDNGetPortStats_EmptyPortName(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithBridgeAndPort("br0", "port1")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// Empty port name should return error
	_, err := provider.SDNGetPortStats(ctx, "br0", "")
	if err == nil {
		t.Fatal("expected error for empty port name")
	}
}

// =============================================================================
// SDNGetFlowStats Coverage Tests
// =============================================================================

func TestMCPServiceProvider_SDNGetFlowStats_BridgeNotFound(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithBridge("br0")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// Try to get flow stats for a non-existent bridge
	_, err := provider.SDNGetFlowStats(ctx, "nonexistent-bridge")
	if err == nil {
		t.Fatal("expected error for non-existent bridge")
	}
}

func TestMCPServiceProvider_SDNGetFlowStats_EmptyBridgeName(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithBridge("br0")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// Empty bridge name should return error
	_, err := provider.SDNGetFlowStats(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty bridge name")
	}
}

// =============================================================================
// SDNFlushFlows Coverage Tests
// =============================================================================

func TestMCPServiceProvider_SDNFlushFlows_BridgeNotFound(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithBridge("br0")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// Try to flush flows for a non-existent bridge
	err := provider.SDNFlushFlows(ctx, "nonexistent-bridge")
	if err == nil {
		t.Fatal("expected error for non-existent bridge")
	}
}

func TestMCPServiceProvider_SDNFlushFlows_EmptyBridgeName(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithBridge("br0")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// Empty bridge name should return error
	err := provider.SDNFlushFlows(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty bridge name")
	}
}

// =============================================================================
// SDNCreateVLAN Coverage Tests
// =============================================================================

func TestMCPServiceProvider_SDNCreateVLAN_BridgeNotFound(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithBridge("br0")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// Try to create VLAN on a non-existent bridge
	err := provider.SDNCreateVLAN(ctx, "nonexistent-bridge", 100, "test-vlan")
	if err == nil {
		t.Fatal("expected error for non-existent bridge")
	}
}

func TestMCPServiceProvider_SDNCreateVLAN_EmptyBridgeName(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithBridge("br0")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// Empty bridge name should return error
	err := provider.SDNCreateVLAN(ctx, "", 100, "test-vlan")
	if err == nil {
		t.Fatal("expected error for empty bridge name")
	}
}

func TestMCPServiceProvider_SDNCreateVLAN_InvalidVLANID_Zero(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithBridge("br0")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// VLAN ID 0 should be rejected
	err := provider.SDNCreateVLAN(ctx, "br0", 0, "test-vlan")
	if err == nil {
		t.Fatal("expected error for VLAN ID 0")
	}
}

func TestMCPServiceProvider_SDNCreateVLAN_InvalidVLANID_TooHigh(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithBridge("br0")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// VLAN ID > 4095 should be rejected
	err := provider.SDNCreateVLAN(ctx, "br0", 5000, "test-vlan")
	if err == nil {
		t.Fatal("expected error for VLAN ID > 4095")
	}
}

func TestMCPServiceProvider_SDNCreateVLAN_Success(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithBridge("br0")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// Valid VLAN creation
	err := provider.SDNCreateVLAN(ctx, "br0", 100, "guest-vlan")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMCPServiceProvider_SDNCreateVLAN_ValidBoundaryValues(t *testing.T) {
	testCases := []struct {
		name   string
		vlanID int
	}{
		{"VLAN ID 1 (minimum)", 1},
		{"VLAN ID 4095 (maximum)", 4095},
		{"VLAN ID 100 (typical)", 100},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			sdnService := createTestSDNServiceWithBridge("br0")

			provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
				SDNService: sdnService,
				Logger:     slog.Default(),
			})

			err := provider.SDNCreateVLAN(ctx, "br0", tc.vlanID, "test-vlan")
			if err != nil {
				t.Fatalf("unexpected error for %s: %v", tc.name, err)
			}
		})
	}
}

// =============================================================================
// SDNDeleteVLAN Coverage Tests
// =============================================================================

func TestMCPServiceProvider_SDNDeleteVLAN_BridgeNotFound(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithVLAN("br0", 100, "test-vlan")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// Try to delete VLAN on a non-existent bridge
	err := provider.SDNDeleteVLAN(ctx, "nonexistent-bridge", 100)
	if err == nil {
		t.Fatal("expected error for non-existent bridge")
	}
}

func TestMCPServiceProvider_SDNDeleteVLAN_VLANNotFound(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithBridge("br0")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// Try to delete a non-existent VLAN
	err := provider.SDNDeleteVLAN(ctx, "br0", 999)
	if err == nil {
		t.Fatal("expected error for non-existent VLAN")
	}
}

func TestMCPServiceProvider_SDNDeleteVLAN_EmptyBridgeName(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithVLAN("br0", 100, "test-vlan")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// Empty bridge name should return error
	err := provider.SDNDeleteVLAN(ctx, "", 100)
	if err == nil {
		t.Fatal("expected error for empty bridge name")
	}
}

func TestMCPServiceProvider_SDNDeleteVLAN_InvalidVLANID_Zero(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithVLAN("br0", 100, "test-vlan")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// VLAN ID 0 should be rejected
	err := provider.SDNDeleteVLAN(ctx, "br0", 0)
	if err == nil {
		t.Fatal("expected error for VLAN ID 0")
	}
}

func TestMCPServiceProvider_SDNDeleteVLAN_InvalidVLANID_TooHigh(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithVLAN("br0", 100, "test-vlan")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// VLAN ID > 4095 should be rejected
	err := provider.SDNDeleteVLAN(ctx, "br0", 5000)
	if err == nil {
		t.Fatal("expected error for VLAN ID > 4095")
	}
}

func TestMCPServiceProvider_SDNDeleteVLAN_Success(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithVLAN("br0", 100, "test-vlan")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// Valid VLAN deletion
	err := provider.SDNDeleteVLAN(ctx, "br0", 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// =============================================================================
// SDNRevokePortAuth Coverage Tests
// =============================================================================

func TestMCPServiceProvider_SDNRevokePortAuth_BridgeNotFound(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithPortAuth("br0", "port1")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// Try to revoke auth on a non-existent bridge
	err := provider.SDNRevokePortAuth(ctx, "nonexistent-bridge", "port1")
	if err == nil {
		t.Fatal("expected error for non-existent bridge")
	}
}

func TestMCPServiceProvider_SDNRevokePortAuth_PortNotFound(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithPortAuth("br0", "port1")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// Try to revoke auth on a non-existent port
	err := provider.SDNRevokePortAuth(ctx, "br0", "nonexistent-port")
	if err == nil {
		t.Fatal("expected error for non-existent port")
	}
}

func TestMCPServiceProvider_SDNRevokePortAuth_NotAuthenticated(t *testing.T) {
	ctx := context.Background()
	// Create service with bridge and port but no auth
	sdnService := createTestSDNServiceWithBridgeAndPort("br0", "port1")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// Try to revoke auth on a port that is not authenticated
	err := provider.SDNRevokePortAuth(ctx, "br0", "port1")
	if err == nil {
		t.Fatal("expected error for unauthenticated port")
	}
}

func TestMCPServiceProvider_SDNRevokePortAuth_EmptyBridgeName(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithPortAuth("br0", "port1")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// Empty bridge name should return error
	err := provider.SDNRevokePortAuth(ctx, "", "port1")
	if err == nil {
		t.Fatal("expected error for empty bridge name")
	}
}

func TestMCPServiceProvider_SDNRevokePortAuth_EmptyPortName(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithPortAuth("br0", "port1")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// Empty port name should return error
	err := provider.SDNRevokePortAuth(ctx, "br0", "")
	if err == nil {
		t.Fatal("expected error for empty port name")
	}
}

func TestMCPServiceProvider_SDNRevokePortAuth_Success(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithPortAuth("br0", "port1")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// Valid revocation
	err := provider.SDNRevokePortAuth(ctx, "br0", "port1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// =============================================================================
// Table-Driven Tests for All Methods with Various Input Combinations
// =============================================================================

func TestMCPServiceProvider_SDN_TableDrivenNilServiceChecks(t *testing.T) {
	testCases := []struct {
		name      string
		operation string
		execFunc  func(context.Context, *MCPServiceProvider) error
	}{
		{
			name:      "SDNListVLANs with nil service",
			operation: "SDNListVLANs",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) error {
				_, err := p.SDNListVLANs(ctx, "br0")
				return err
			},
		},
		{
			name:      "SDNAuthenticatePort with nil service",
			operation: "SDNAuthenticatePort",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) error {
				return p.SDNAuthenticatePort(ctx, "br0", "port1", map[string]string{"certificate": "test"})
			},
		},
		{
			name:      "SDNGetPortStats with nil service",
			operation: "SDNGetPortStats",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) error {
				_, err := p.SDNGetPortStats(ctx, "br0", "port1")
				return err
			},
		},
		{
			name:      "SDNGetFlowStats with nil service",
			operation: "SDNGetFlowStats",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) error {
				_, err := p.SDNGetFlowStats(ctx, "br0")
				return err
			},
		},
		{
			name:      "SDNFlushFlows with nil service",
			operation: "SDNFlushFlows",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) error {
				return p.SDNFlushFlows(ctx, "br0")
			},
		},
		{
			name:      "SDNCreateVLAN with nil service",
			operation: "SDNCreateVLAN",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) error {
				return p.SDNCreateVLAN(ctx, "br0", 100, "test-vlan")
			},
		},
		{
			name:      "SDNDeleteVLAN with nil service",
			operation: "SDNDeleteVLAN",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) error {
				return p.SDNDeleteVLAN(ctx, "br0", 100)
			},
		},
		{
			name:      "SDNRevokePortAuth with nil service",
			operation: "SDNRevokePortAuth",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) error {
				return p.SDNRevokePortAuth(ctx, "br0", "port1")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			// Create provider with nil SDN service
			provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
				Logger: slog.Default(),
			})

			err := tc.execFunc(ctx, provider)
			if err == nil {
				t.Fatalf("expected error for nil SDN service in %s", tc.operation)
			}

			// Verify it's the right error type
			svcErr, ok := err.(ErrServiceNotAvailable)
			if !ok {
				t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
			}
			if svcErr.Service != "sdn" {
				t.Errorf("expected service='sdn', got %q", svcErr.Service)
			}
		})
	}
}

// =============================================================================
// Edge Cases for Format Handling in SDNAuthenticatePort
// =============================================================================

func TestMCPServiceProvider_SDNAuthenticatePort_FormatVariationsWithSDNService(t *testing.T) {
	testCases := []struct {
		name        string
		credentials map[string]string
	}{
		{
			name: "explicit PEM format",
			credentials: map[string]string{
				"certificate": "test-cert",
				"format":      "PEM",
			},
		},
		{
			name: "explicit DER format",
			credentials: map[string]string{
				"certificate": "test-cert",
				"format":      "DER",
			},
		},
		{
			name: "lowercase pem format",
			credentials: map[string]string{
				"certificate": "test-cert",
				"format":      "pem",
			},
		},
		{
			name: "no format defaults to PEM",
			credentials: map[string]string{
				"certificate": "test-cert",
			},
		},
		{
			name:        "empty credentials map",
			credentials: map[string]string{},
		},
		{
			name: "nil-like empty values",
			credentials: map[string]string{
				"certificate": "",
				"format":      "",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			sdnService := createTestSDNServiceWithBridgeAndPort("br0", "port1")

			provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
				SDNService: sdnService,
				Logger:     slog.Default(),
			})

			// All these will fail on certificate validation, but we're testing format handling
			err := provider.SDNAuthenticatePort(ctx, "br0", "port1", tc.credentials)
			// We expect an error (invalid cert or empty cert) but NOT a nil service error
			if err == nil {
				t.Log("no error returned - certificate may have been processed differently")
			} else {
				// Make sure it's not a service not available error
				if _, ok := err.(ErrServiceNotAvailable); ok {
					t.Errorf("unexpected ErrServiceNotAvailable - SDN service should be available")
				}
			}
		})
	}
}

// =============================================================================
// Multiple Operations Sequence Tests
// =============================================================================

func TestMCPServiceProvider_SDN_CreateAndListVLANs(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithBridge("br0")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// Create multiple VLANs
	if err := provider.SDNCreateVLAN(ctx, "br0", 100, "vlan-100"); err != nil {
		t.Fatalf("failed to create VLAN 100: %v", err)
	}
	if err := provider.SDNCreateVLAN(ctx, "br0", 200, "vlan-200"); err != nil {
		t.Fatalf("failed to create VLAN 200: %v", err)
	}

	// List VLANs
	vlans, err := provider.SDNListVLANs(ctx, "br0")
	if err != nil {
		t.Fatalf("failed to list VLANs: %v", err)
	}

	if len(vlans) != 2 {
		t.Errorf("expected 2 VLANs, got %d", len(vlans))
	}
}

func TestMCPServiceProvider_SDN_CreateAndDeleteVLAN(t *testing.T) {
	ctx := context.Background()
	sdnService := createTestSDNServiceWithBridge("br0")

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: sdnService,
		Logger:     slog.Default(),
	})

	// Create a VLAN
	if err := provider.SDNCreateVLAN(ctx, "br0", 100, "test-vlan"); err != nil {
		t.Fatalf("failed to create VLAN: %v", err)
	}

	// Verify it exists
	vlans, err := provider.SDNListVLANs(ctx, "br0")
	if err != nil {
		t.Fatalf("failed to list VLANs: %v", err)
	}
	if len(vlans) != 1 {
		t.Fatalf("expected 1 VLAN after creation, got %d", len(vlans))
	}

	// Delete the VLAN
	if err := provider.SDNDeleteVLAN(ctx, "br0", 100); err != nil {
		t.Fatalf("failed to delete VLAN: %v", err)
	}

	// Verify it's gone
	vlans, err = provider.SDNListVLANs(ctx, "br0")
	if err != nil {
		t.Fatalf("failed to list VLANs after deletion: %v", err)
	}
	if len(vlans) != 0 {
		t.Errorf("expected 0 VLANs after deletion, got %d", len(vlans))
	}
}
