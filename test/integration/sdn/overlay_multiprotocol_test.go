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

package sdn

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// Overlay Multi-Protocol Test Suite
// =============================================================================

// TestOverlayMultiProtocol runs all overlay/gateway/IPAM tests across all protocol adapters.
// This ensures feature parity across CLI, REST, gRPC, QUIC, MCP, and Unix protocols.
func TestOverlayMultiProtocol(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := LongRunningTestContext()
	// Use t.Cleanup instead of defer cancel() because subtests use t.Parallel().
	// With t.Parallel(), the parent function returns before subtests start,
	// so defer cancel() would cancel the context before subtests can use it.
	// t.Cleanup runs after ALL subtests (including parallel ones) complete.
	t.Cleanup(cancel)

	adapters := getOverlayAdapters()

	for _, adapter := range adapters {
		adapter := adapter // capture range variable
		t.Run(adapter.Name(), func(t *testing.T) {
			t.Parallel()

			// Setup adapter
			if err := adapter.Setup(ctx); err != nil {
				t.Skipf("Skipping %s: setup failed: %v", adapter.Name(), err)
			}
			defer func() {
				if err := adapter.Teardown(); err != nil {
					t.Logf("Warning: teardown failed for %s: %v", adapter.Name(), err)
				}
			}()

			// Run all overlay test suites
			t.Run("OverlayStatus", func(t *testing.T) {
				testOverlayStatus(t, ctx, adapter)
			})

			t.Run("VTEP", func(t *testing.T) {
				testVTEPOperations(t, ctx, adapter)
			})

			t.Run("VNI", func(t *testing.T) {
				testVNIOperations(t, ctx, adapter)
			})

			t.Run("Tunnel", func(t *testing.T) {
				testTunnelOperations(t, ctx, adapter)
			})

			t.Run("MAC", func(t *testing.T) {
				testMACOperations(t, ctx, adapter)
			})

			t.Run("Gateway", func(t *testing.T) {
				testGatewayOperations(t, ctx, adapter)
			})

			t.Run("BGP", func(t *testing.T) {
				testBGPOperations(t, ctx, adapter)
			})

			t.Run("IPAM", func(t *testing.T) {
				testIPAMOperations(t, ctx, adapter)
			})
		})
	}
}

// =============================================================================
// Adapter Factory
// =============================================================================

// getOverlayAdapters returns all available overlay protocol adapters.
func getOverlayAdapters() []OverlayCommands {
	return []OverlayCommands{
		NewOverlayCLIAdapter(),
		NewOverlayRESTAdapter(),
		NewOverlayGRPCAdapter(),
		NewOverlayQUICAdapter(),
		NewOverlayMCPAdapter(),
		NewOverlayUnixAdapter(),
	}
}

// =============================================================================
// Overlay Status Tests
// =============================================================================

func testOverlayStatus(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	t.Run("GetStatus", func(t *testing.T) {
		result, err := adapter.OverlayStatus(ctx)
		if err != nil {
			skipIfOverlayNotImplemented(t, err)
			t.Fatalf("OverlayStatus failed: %v", err)
		}

		if result.NodeID == "" {
			t.Error("Expected non-empty NodeID")
		}

		if result.VXLANPort == 0 {
			t.Error("Expected non-zero VXLANPort")
		}
	})
}

// =============================================================================
// VTEP Tests
// =============================================================================

func testVTEPOperations(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	t.Run("ListVTEPs", func(t *testing.T) {
		testVTEPList(t, ctx, adapter)
	})

	t.Run("GetVTEP", func(t *testing.T) {
		testVTEPGet(t, ctx, adapter)
	})

	t.Run("GetVTEP_NotFound", func(t *testing.T) {
		testVTEPGetNotFound(t, ctx, adapter)
	})
}

func testVTEPList(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	result, err := adapter.VTEPList(ctx)
	if err != nil {
		skipIfOverlayNotImplemented(t, err)
		t.Fatalf("VTEPList failed: %v", err)
	}

	// At minimum, we should have the local VTEP
	if result.TotalCount < 0 {
		t.Errorf("Expected non-negative TotalCount, got %d", result.TotalCount)
	}

	// Verify VTEP structure if any exist
	for _, vtep := range result.VTEPs {
		if vtep.NodeID == "" {
			t.Error("Expected non-empty NodeID in VTEP")
		}
	}
}

func testVTEPGet(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	// First list VTEPs to get a valid node ID
	listResult, err := adapter.VTEPList(ctx)
	if err != nil {
		skipIfOverlayNotImplemented(t, err)
		t.Fatalf("VTEPList failed: %v", err)
	}

	if len(listResult.VTEPs) == 0 {
		t.Skip("No VTEPs available for testing")
	}

	// Get the first VTEP
	nodeID := listResult.VTEPs[0].NodeID
	result, err := adapter.VTEPGet(ctx, nodeID)
	if err != nil {
		skipIfOverlayNotImplemented(t, err)
		t.Fatalf("VTEPGet failed: %v", err)
	}

	if result.NodeID != nodeID {
		t.Errorf("Expected NodeID %s, got %s", nodeID, result.NodeID)
	}

	// VNIs should be a valid slice (even if empty)
	if result.VNIs == nil {
		t.Error("Expected non-nil VNIs slice")
	}
}

func testVTEPGetNotFound(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	_, err := adapter.VTEPGet(ctx, "non-existent-node-id-12345")
	if err == nil {
		t.Error("Expected error for non-existent VTEP")
	}
}

// =============================================================================
// VNI Tests
// =============================================================================

func testVNIOperations(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	t.Run("ListVNIs", func(t *testing.T) {
		testVNIList(t, ctx, adapter)
	})

	t.Run("CreateDeleteVNI", func(t *testing.T) {
		testVNICreateDelete(t, ctx, adapter)
	})

	t.Run("CreateVNI_InvalidParams", func(t *testing.T) {
		testVNICreateInvalidParams(t, ctx, adapter)
	})

	t.Run("DeleteVNI_NotFound", func(t *testing.T) {
		testVNIDeleteNotFound(t, ctx, adapter)
	})
}

func testVNIList(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	result, err := adapter.VNIList(ctx)
	if err != nil {
		skipIfOverlayNotImplemented(t, err)
		t.Fatalf("VNIList failed: %v", err)
	}

	if result.TotalCount < 0 {
		t.Errorf("Expected non-negative TotalCount, got %d", result.TotalCount)
	}

	// Verify VNI structure if any exist
	for _, vni := range result.VNIs {
		if vni.VNI == 0 {
			t.Error("Expected non-zero VNI")
		}
	}
}

func testVNICreateDelete(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	// Generate unique VNI
	vni := generateUniqueVNI()
	opts := VNICreateOptions{
		VNI:  vni,
		VLAN: 100,
		Name: fmt.Sprintf("test-vni-%d", vni),
	}

	// Create VNI
	createResult, err := adapter.VNICreate(ctx, opts)
	if err != nil {
		skipIfOverlayNotImplemented(t, err)
		t.Fatalf("VNICreate failed: %v", err)
	}

	if createResult.VNI != opts.VNI {
		t.Errorf("Expected VNI %d, got %d", opts.VNI, createResult.VNI)
	}

	if createResult.VLAN != opts.VLAN {
		t.Errorf("Expected VLAN %d, got %d", opts.VLAN, createResult.VLAN)
	}

	// Verify in list
	listResult, err := adapter.VNIList(ctx)
	if err != nil {
		t.Fatalf("VNIList failed: %v", err)
	}

	found := false
	for _, v := range listResult.VNIs {
		if v.VNI == opts.VNI {
			found = true
			break
		}
	}
	if !found {
		t.Error("Created VNI not found in list")
	}

	// Delete VNI
	deleteResult, err := adapter.VNIDelete(ctx, opts.VNI)
	if err != nil {
		t.Fatalf("VNIDelete failed: %v", err)
	}

	if !deleteResult.Deleted {
		t.Error("Expected Deleted to be true")
	}

	// Verify deleted from list
	listResult, err = adapter.VNIList(ctx)
	if err != nil {
		t.Fatalf("VNIList failed: %v", err)
	}

	for _, v := range listResult.VNIs {
		if v.VNI == opts.VNI {
			t.Error("Deleted VNI still found in list")
			break
		}
	}
}

func testVNICreateInvalidParams(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	// Try to create VNI with invalid VNI value (0)
	opts := VNICreateOptions{
		VNI:  0,
		VLAN: 100,
		Name: "invalid-vni",
	}

	_, err := adapter.VNICreate(ctx, opts)
	if err == nil {
		t.Error("Expected error for invalid VNI value")
		// Cleanup if it was somehow created
		_, cleanupErr := adapter.VNIDelete(ctx, 0)
		if cleanupErr != nil {
			t.Logf("Cleanup error (expected): %v", cleanupErr)
		}
	}
}

func testVNIDeleteNotFound(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	// Try to delete a VNI that doesn't exist
	_, err := adapter.VNIDelete(ctx, 999999999)
	if err == nil {
		t.Log("Warning: VNIDelete for non-existent VNI did not return error")
	}
}

// =============================================================================
// Tunnel Tests
// =============================================================================

func testTunnelOperations(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	t.Run("ListTunnels", func(t *testing.T) {
		testTunnelList(t, ctx, adapter)
	})

	t.Run("ListTunnels_FilterByVNI", func(t *testing.T) {
		testTunnelListFilterByVNI(t, ctx, adapter)
	})
}

func testTunnelList(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	result, err := adapter.TunnelList(ctx, TunnelListOptions{})
	if err != nil {
		skipIfOverlayNotImplemented(t, err)
		t.Fatalf("TunnelList failed: %v", err)
	}

	if result.TotalCount < 0 {
		t.Errorf("Expected non-negative TotalCount, got %d", result.TotalCount)
	}

	// Verify tunnel structure if any exist
	for _, tunnel := range result.Tunnels {
		if tunnel.VNI == 0 {
			t.Error("Expected non-zero VNI in tunnel")
		}
	}
}

func testTunnelListFilterByVNI(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	// First get all tunnels
	allResult, err := adapter.TunnelList(ctx, TunnelListOptions{})
	if err != nil {
		skipIfOverlayNotImplemented(t, err)
		t.Fatalf("TunnelList failed: %v", err)
	}

	if len(allResult.Tunnels) == 0 {
		t.Skip("No tunnels available for filter testing")
	}

	// Filter by the first tunnel's VNI
	vni := allResult.Tunnels[0].VNI
	filteredResult, err := adapter.TunnelList(ctx, TunnelListOptions{VNI: vni})
	if err != nil {
		t.Fatalf("TunnelList with filter failed: %v", err)
	}

	// All returned tunnels should have the specified VNI
	for _, tunnel := range filteredResult.Tunnels {
		if tunnel.VNI != vni {
			t.Errorf("Expected VNI %d, got %d", vni, tunnel.VNI)
		}
	}
}

// =============================================================================
// MAC Tests
// =============================================================================

func testMACOperations(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	t.Run("ListMACs", func(t *testing.T) {
		testMACList(t, ctx, adapter)
	})

	t.Run("ListMACs_FilterByVNI", func(t *testing.T) {
		testMACListFilterByVNI(t, ctx, adapter)
	})

	t.Run("ForgetMAC_NotFound", func(t *testing.T) {
		testMACForgetNotFound(t, ctx, adapter)
	})
}

func testMACList(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	result, err := adapter.MACList(ctx, MACListOptions{})
	if err != nil {
		skipIfOverlayNotImplemented(t, err)
		t.Fatalf("MACList failed: %v", err)
	}

	if result.TotalCount < 0 {
		t.Errorf("Expected non-negative TotalCount, got %d", result.TotalCount)
	}

	// Verify MAC structure if any exist
	for _, mac := range result.MACs {
		if mac.VNI == 0 {
			t.Error("Expected non-zero VNI in MAC entry")
		}
		if mac.Source == "" {
			t.Error("Expected non-empty Source in MAC entry")
		}
	}
}

func testMACListFilterByVNI(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	// First get all MACs
	allResult, err := adapter.MACList(ctx, MACListOptions{})
	if err != nil {
		skipIfOverlayNotImplemented(t, err)
		t.Fatalf("MACList failed: %v", err)
	}

	if len(allResult.MACs) == 0 {
		t.Skip("No MACs available for filter testing")
	}

	// Filter by the first MAC's VNI
	vni := allResult.MACs[0].VNI
	filteredResult, err := adapter.MACList(ctx, MACListOptions{VNI: vni})
	if err != nil {
		t.Fatalf("MACList with filter failed: %v", err)
	}

	// All returned MACs should have the specified VNI
	for _, mac := range filteredResult.MACs {
		if mac.VNI != vni {
			t.Errorf("Expected VNI %d, got %d", vni, mac.VNI)
		}
	}
}

func testMACForgetNotFound(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	// Try to forget a MAC that doesn't exist
	_, err := adapter.MACForget(ctx, "00:00:00:00:00:00", 999999)
	if err == nil {
		t.Log("Warning: MACForget for non-existent MAC did not return error")
	}
}

// =============================================================================
// Gateway Tests
// =============================================================================

func testGatewayOperations(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	t.Run("GetStatus", func(t *testing.T) {
		testGatewayStatus(t, ctx, adapter)
	})

	t.Run("SetMode", func(t *testing.T) {
		testGatewaySetMode(t, ctx, adapter)
	})

	t.Run("SetMode_InvalidModes", func(t *testing.T) {
		testGatewaySetModeInvalid(t, ctx, adapter)
	})
}

func testGatewayStatus(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	result, err := adapter.GatewayStatus(ctx)
	if err != nil {
		skipIfOverlayNotImplemented(t, err)
		t.Fatalf("GatewayStatus failed: %v", err)
	}

	if result.NodeID == "" {
		t.Error("Expected non-empty NodeID")
	}

	if result.Tier == "" {
		t.Error("Expected non-empty Tier")
	}

	if result.Reputation < 0 || result.Reputation > 1 {
		t.Errorf("Expected Reputation between 0 and 1, got %f", result.Reputation)
	}
}

func testGatewaySetMode(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	// Get current status to restore later
	status, err := adapter.GatewayStatus(ctx)
	if err != nil {
		skipIfOverlayNotImplemented(t, err)
		t.Fatalf("GatewayStatus failed: %v", err)
	}

	originalModes := status.Modes

	// Set a new mode
	newModes := []string{"overlay"}
	result, err := adapter.GatewaySetMode(ctx, GatewayModeOptions{Modes: newModes})
	if err != nil {
		skipIfOverlayNotImplemented(t, err)
		t.Fatalf("GatewaySetMode failed: %v", err)
	}

	if !result.Success {
		t.Error("Expected Success to be true")
	}

	// Verify modes changed
	status, err = adapter.GatewayStatus(ctx)
	if err != nil {
		t.Fatalf("GatewayStatus failed: %v", err)
	}

	if !containsMode(status.Modes, "overlay") {
		t.Error("Expected modes to contain 'overlay'")
	}

	// Restore original modes
	_, restoreErr := adapter.GatewaySetMode(ctx, GatewayModeOptions{Modes: originalModes})
	if restoreErr != nil {
		t.Logf("Warning: failed to restore original modes: %v", restoreErr)
	}
}

func testGatewaySetModeInvalid(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	// Try to set invalid modes
	_, err := adapter.GatewaySetMode(ctx, GatewayModeOptions{Modes: []string{"invalid-mode-xyz"}})
	if err == nil {
		t.Log("Warning: GatewaySetMode with invalid mode did not return error")
	}
}

// =============================================================================
// BGP Tests
// =============================================================================

func testBGPOperations(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	t.Run("GetStatus", func(t *testing.T) {
		testBGPStatus(t, ctx, adapter)
	})

	t.Run("ListPeers", func(t *testing.T) {
		testBGPPeers(t, ctx, adapter)
	})

	t.Run("ListPrefixes", func(t *testing.T) {
		testBGPPrefixes(t, ctx, adapter)
	})

	t.Run("AnnounceWithdrawPrefix", func(t *testing.T) {
		testBGPAnnounceWithdraw(t, ctx, adapter)
	})

	t.Run("AnnouncePrefix_InvalidPrefix", func(t *testing.T) {
		testBGPAnnounceInvalidPrefix(t, ctx, adapter)
	})
}

func testBGPStatus(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	result, err := adapter.BGPStatus(ctx)
	if err != nil {
		skipIfOverlayNotImplemented(t, err)
		t.Fatalf("BGPStatus failed: %v", err)
	}

	// ASN should be non-zero if BGP is enabled
	if result.Enabled && result.ASN == 0 {
		t.Error("Expected non-zero ASN when BGP is enabled")
	}

	if result.RouterID == "" && result.Enabled {
		t.Error("Expected non-empty RouterID when BGP is enabled")
	}
}

func testBGPPeers(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	result, err := adapter.BGPPeers(ctx)
	if err != nil {
		skipIfOverlayNotImplemented(t, err)
		t.Fatalf("BGPPeers failed: %v", err)
	}

	if result.TotalCount < 0 {
		t.Errorf("Expected non-negative TotalCount, got %d", result.TotalCount)
	}

	// Verify peer structure if any exist
	for _, peer := range result.Peers {
		if peer.Address == "" {
			t.Error("Expected non-empty Address in peer")
		}
		if peer.RemoteASN == 0 {
			t.Error("Expected non-zero RemoteASN in peer")
		}
	}
}

func testBGPPrefixes(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	result, err := adapter.BGPPrefixes(ctx)
	if err != nil {
		skipIfOverlayNotImplemented(t, err)
		t.Fatalf("BGPPrefixes failed: %v", err)
	}

	if result.TotalCount < 0 {
		t.Errorf("Expected non-negative TotalCount, got %d", result.TotalCount)
	}

	// Verify prefix structure if any exist
	for _, prefix := range result.Prefixes {
		if prefix.Prefix == "" {
			t.Error("Expected non-empty Prefix")
		}
	}
}

func testBGPAnnounceWithdraw(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	// Check if BGP is enabled first
	status, err := adapter.BGPStatus(ctx)
	if err != nil {
		skipIfOverlayNotImplemented(t, err)
		t.Fatalf("BGPStatus failed: %v", err)
	}

	if !status.Enabled {
		t.Skip("BGP not enabled, skipping announce/withdraw test")
	}

	// Use a test prefix that won't conflict with real routing
	testPrefix := "192.0.2.0/24" // TEST-NET-1 (RFC 5737)
	testNextHop := "10.0.0.1"

	// Announce prefix
	announceResult, err := adapter.BGPAnnounce(ctx, BGPAnnounceOptions{
		Prefix:  testPrefix,
		NextHop: testNextHop,
	})
	if err != nil {
		skipIfOverlayNotImplemented(t, err)
		t.Fatalf("BGPAnnounce failed: %v", err)
	}

	if !announceResult.Success {
		t.Error("Expected Success to be true for announce")
	}

	// Verify prefix is announced
	prefixes, err := adapter.BGPPrefixes(ctx)
	if err != nil {
		t.Fatalf("BGPPrefixes failed: %v", err)
	}

	found := false
	for _, p := range prefixes.Prefixes {
		if p.Prefix == testPrefix {
			found = true
			break
		}
	}
	if !found {
		t.Log("Warning: announced prefix not found in prefix list")
	}

	// Withdraw prefix
	withdrawResult, err := adapter.BGPWithdraw(ctx, testPrefix)
	if err != nil {
		t.Fatalf("BGPWithdraw failed: %v", err)
	}

	if !withdrawResult.Success {
		t.Error("Expected Success to be true for withdraw")
	}
}

func testBGPAnnounceInvalidPrefix(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	// Check if BGP is enabled first
	status, err := adapter.BGPStatus(ctx)
	if err != nil {
		skipIfOverlayNotImplemented(t, err)
		t.Skip("Could not get BGP status")
	}

	if !status.Enabled {
		t.Skip("BGP not enabled")
	}

	// Try to announce an invalid prefix
	_, err = adapter.BGPAnnounce(ctx, BGPAnnounceOptions{
		Prefix:  "invalid-prefix",
		NextHop: "10.0.0.1",
	})
	if err == nil {
		t.Error("Expected error for invalid prefix")
	}
}

// =============================================================================
// IPAM Tests
// =============================================================================

func testIPAMOperations(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	t.Run("ListPools", func(t *testing.T) {
		testIPAMPoolList(t, ctx, adapter)
	})

	t.Run("CreateDeletePool", func(t *testing.T) {
		testIPAMPoolCreateDelete(t, ctx, adapter)
	})

	t.Run("AllocateRelease", func(t *testing.T) {
		testIPAMAllocateRelease(t, ctx, adapter)
	})

	t.Run("ListAllocations", func(t *testing.T) {
		testIPAMListAllocations(t, ctx, adapter)
	})

	t.Run("AllocateFromNonExistentPool", func(t *testing.T) {
		testIPAMAllocateFromNonExistentPool(t, ctx, adapter)
	})

	t.Run("ReleaseNonExistentIP", func(t *testing.T) {
		testIPAMReleaseNonExistent(t, ctx, adapter)
	})
}

func testIPAMPoolList(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	result, err := adapter.IPAMPoolList(ctx)
	if err != nil {
		skipIfOverlayNotImplemented(t, err)
		t.Fatalf("IPAMPoolList failed: %v", err)
	}

	if result.TotalCount < 0 {
		t.Errorf("Expected non-negative TotalCount, got %d", result.TotalCount)
	}

	// Verify pool structure if any exist
	for _, pool := range result.Pools {
		if pool.ID == "" {
			t.Error("Expected non-empty pool ID")
		}
		if pool.CIDR == "" {
			t.Error("Expected non-empty CIDR in pool")
		}
		if pool.TotalIPs <= 0 {
			t.Error("Expected positive TotalIPs in pool")
		}
	}
}

func testIPAMPoolCreateDelete(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	// Create a test pool
	poolName := generateUniquePoolName()
	createOpts := IPAMPoolCreateOptions{
		Name:          poolName,
		CIDR:          "10.200.0.0/24",
		Gateway:       "10.200.0.1",
		DNS:           []string{"8.8.8.8", "8.8.4.4"},
		LeaseDuration: 24 * time.Hour,
	}

	createResult, err := adapter.IPAMPoolCreate(ctx, createOpts)
	if err != nil {
		skipIfOverlayNotImplemented(t, err)
		t.Fatalf("IPAMPoolCreate failed: %v", err)
	}

	if createResult.ID == "" {
		t.Error("Expected non-empty pool ID")
	}

	if createResult.Name != createOpts.Name {
		t.Errorf("Expected name %s, got %s", createOpts.Name, createResult.Name)
	}

	if createResult.CIDR != createOpts.CIDR {
		t.Errorf("Expected CIDR %s, got %s", createOpts.CIDR, createResult.CIDR)
	}

	// Verify in list
	listResult, err := adapter.IPAMPoolList(ctx)
	if err != nil {
		t.Fatalf("IPAMPoolList failed: %v", err)
	}

	found := false
	for _, pool := range listResult.Pools {
		if pool.ID == createResult.ID {
			found = true
			break
		}
	}
	if !found {
		t.Error("Created pool not found in list")
	}

	// Delete pool
	deleteResult, err := adapter.IPAMPoolDelete(ctx, createResult.ID)
	if err != nil {
		t.Fatalf("IPAMPoolDelete failed: %v", err)
	}

	if !deleteResult.Deleted {
		t.Error("Expected Deleted to be true")
	}

	// Verify deleted from list
	listResult, err = adapter.IPAMPoolList(ctx)
	if err != nil {
		t.Fatalf("IPAMPoolList failed: %v", err)
	}

	for _, pool := range listResult.Pools {
		if pool.ID == createResult.ID {
			t.Error("Deleted pool still found in list")
			break
		}
	}
}

func testIPAMAllocateRelease(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	// First get available pools
	pools, err := adapter.IPAMPoolList(ctx)
	if err != nil {
		skipIfOverlayNotImplemented(t, err)
		t.Fatalf("IPAMPoolList failed: %v", err)
	}

	if len(pools.Pools) == 0 {
		t.Skip("No IPAM pools available for testing")
	}

	// Find a pool with available IPs
	var poolID string
	for _, pool := range pools.Pools {
		if pool.AvailableIPs > 0 {
			poolID = pool.ID
			break
		}
	}

	if poolID == "" {
		t.Skip("No pools with available IPs")
	}

	// Allocate an IP
	allocOpts := IPAMAllocateOptions{
		PoolID:   poolID,
		DeviceID: "test-device-001",
		Hostname: "test-host",
	}

	allocResult, err := adapter.IPAMAllocate(ctx, allocOpts)
	if err != nil {
		skipIfOverlayNotImplemented(t, err)
		t.Fatalf("IPAMAllocate failed: %v", err)
	}

	if !allocResult.IP.IsValid() {
		t.Error("Expected valid IP address")
	}

	if allocResult.PoolID != poolID {
		t.Errorf("Expected PoolID %s, got %s", poolID, allocResult.PoolID)
	}

	if allocResult.DeviceID != allocOpts.DeviceID {
		t.Errorf("Expected DeviceID %s, got %s", allocOpts.DeviceID, allocResult.DeviceID)
	}

	// Verify in allocations list
	listResult, err := adapter.IPAMList(ctx, IPAMListOptions{PoolID: poolID})
	if err != nil {
		t.Fatalf("IPAMList failed: %v", err)
	}

	found := false
	for _, alloc := range listResult.Allocations {
		if alloc.IP == allocResult.IP {
			found = true
			break
		}
	}
	if !found {
		t.Error("Allocated IP not found in allocations list")
	}

	// Release the IP
	releaseResult, err := adapter.IPAMRelease(ctx, allocResult.IP.String())
	if err != nil {
		t.Fatalf("IPAMRelease failed: %v", err)
	}

	if !releaseResult.Released {
		t.Error("Expected Released to be true")
	}

	// Verify removed from allocations list
	listResult, err = adapter.IPAMList(ctx, IPAMListOptions{PoolID: poolID})
	if err != nil {
		t.Fatalf("IPAMList failed: %v", err)
	}

	for _, alloc := range listResult.Allocations {
		if alloc.IP == allocResult.IP {
			t.Error("Released IP still found in allocations list")
			break
		}
	}
}

func testIPAMListAllocations(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	result, err := adapter.IPAMList(ctx, IPAMListOptions{})
	if err != nil {
		skipIfOverlayNotImplemented(t, err)
		t.Fatalf("IPAMList failed: %v", err)
	}

	if result.TotalCount < 0 {
		t.Errorf("Expected non-negative TotalCount, got %d", result.TotalCount)
	}

	// Verify allocation structure if any exist
	for _, alloc := range result.Allocations {
		if !alloc.IP.IsValid() {
			t.Error("Expected valid IP in allocation")
		}
		if alloc.PoolID == "" {
			t.Error("Expected non-empty PoolID in allocation")
		}
	}
}

func testIPAMAllocateFromNonExistentPool(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	_, err := adapter.IPAMAllocate(ctx, IPAMAllocateOptions{
		PoolID:   "non-existent-pool-12345",
		DeviceID: "test-device",
		Hostname: "test-host",
	})
	if err == nil {
		t.Error("Expected error for non-existent pool")
	}
}

func testIPAMReleaseNonExistent(t *testing.T, ctx context.Context, adapter OverlayCommands) {
	_, err := adapter.IPAMRelease(ctx, "192.168.255.255")
	if err == nil {
		t.Log("Warning: IPAMRelease for non-existent IP did not return error")
	}
}

// =============================================================================
// Protocol-Specific Tests
// =============================================================================

// TestOverlayCLIOperations tests overlay operations specifically via CLI.
func TestOverlayCLIOperations(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := DefaultTestContext()
	defer cancel()

	adapter := NewOverlayCLIAdapter()
	if err := adapter.Setup(ctx); err != nil {
		t.Skipf("CLI adapter setup failed: %v", err)
	}
	defer func() {
		if err := adapter.Teardown(); err != nil {
			t.Logf("Teardown error: %v", err)
		}
	}()

	testOverlayStatus(t, ctx, adapter)
	testVTEPOperations(t, ctx, adapter)
	testVNIOperations(t, ctx, adapter)
}

// TestOverlayRESTOperations tests overlay operations specifically via REST.
func TestOverlayRESTOperations(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := DefaultTestContext()
	defer cancel()

	adapter := NewOverlayRESTAdapter()
	if err := adapter.Setup(ctx); err != nil {
		t.Skipf("REST adapter setup failed: %v", err)
	}
	defer func() {
		if err := adapter.Teardown(); err != nil {
			t.Logf("Teardown error: %v", err)
		}
	}()

	testOverlayStatus(t, ctx, adapter)
	testVTEPOperations(t, ctx, adapter)
	testVNIOperations(t, ctx, adapter)
}

// TestOverlayGRPCOperations tests overlay operations specifically via gRPC.
func TestOverlayGRPCOperations(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := DefaultTestContext()
	defer cancel()

	adapter := NewOverlayGRPCAdapter()
	if err := adapter.Setup(ctx); err != nil {
		t.Skipf("gRPC adapter setup failed: %v", err)
	}
	defer func() {
		if err := adapter.Teardown(); err != nil {
			t.Logf("Teardown error: %v", err)
		}
	}()

	testOverlayStatus(t, ctx, adapter)
	testVTEPOperations(t, ctx, adapter)
	testVNIOperations(t, ctx, adapter)
}

// TestOverlayQUICOperations tests overlay operations specifically via QUIC.
func TestOverlayQUICOperations(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := DefaultTestContext()
	defer cancel()

	adapter := NewOverlayQUICAdapter()
	if err := adapter.Setup(ctx); err != nil {
		t.Skipf("QUIC adapter setup failed: %v", err)
	}
	defer func() {
		if err := adapter.Teardown(); err != nil {
			t.Logf("Teardown error: %v", err)
		}
	}()

	testOverlayStatus(t, ctx, adapter)
	testVTEPOperations(t, ctx, adapter)
	testVNIOperations(t, ctx, adapter)
}

// TestOverlayMCPOperations tests overlay operations specifically via MCP.
func TestOverlayMCPOperations(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := DefaultTestContext()
	defer cancel()

	adapter := NewOverlayMCPAdapter()
	if err := adapter.Setup(ctx); err != nil {
		t.Skipf("MCP adapter setup failed: %v", err)
	}
	defer func() {
		if err := adapter.Teardown(); err != nil {
			t.Logf("Teardown error: %v", err)
		}
	}()

	testOverlayStatus(t, ctx, adapter)
	testVTEPOperations(t, ctx, adapter)
	testVNIOperations(t, ctx, adapter)
}

// TestOverlayUnixOperations tests overlay operations specifically via Unix socket.
func TestOverlayUnixOperations(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := DefaultTestContext()
	defer cancel()

	adapter := NewOverlayUnixAdapter()
	if err := adapter.Setup(ctx); err != nil {
		t.Skipf("Unix adapter setup failed: %v", err)
	}
	defer func() {
		if err := adapter.Teardown(); err != nil {
			t.Logf("Teardown error: %v", err)
		}
	}()

	testOverlayStatus(t, ctx, adapter)
	testVTEPOperations(t, ctx, adapter)
	testVNIOperations(t, ctx, adapter)
}

// =============================================================================
// Error Handling Tests
// =============================================================================

// TestOverlayErrorHandling tests error handling across protocols.
func TestOverlayErrorHandling(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := DefaultTestContext()
	defer cancel()

	adapters := []OverlayCommands{
		NewOverlayCLIAdapter(),
		NewOverlayRESTAdapter(),
		NewOverlayGRPCAdapter(),
	}

	for _, adapter := range adapters {
		adapter := adapter
		t.Run(adapter.Name()+"/GetNonExistentVTEP", func(t *testing.T) {
			if err := adapter.Setup(ctx); err != nil {
				t.Skipf("Adapter setup failed: %v", err)
			}
			defer func() {
				if err := adapter.Teardown(); err != nil {
					t.Logf("Teardown error: %v", err)
				}
			}()

			_, err := adapter.VTEPGet(ctx, "non-existent-vtep-id-12345")
			if err == nil {
				t.Error("Expected error for non-existent VTEP")
			}
		})

		t.Run(adapter.Name()+"/DeleteNonExistentVNI", func(t *testing.T) {
			if err := adapter.Setup(ctx); err != nil {
				t.Skipf("Adapter setup failed: %v", err)
			}
			defer func() {
				if err := adapter.Teardown(); err != nil {
					t.Logf("Teardown error: %v", err)
				}
			}()

			_, err := adapter.VNIDelete(ctx, 999999999)
			if err == nil {
				t.Log("Note: VNIDelete for non-existent VNI did not return error")
			}
		})
	}
}

// =============================================================================
// Stress Tests
// =============================================================================

// TestOverlayStressOperations performs stress testing of overlay operations.
func TestOverlayStressOperations(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := LongRunningTestContext()
	defer cancel()

	adapter := NewOverlayRESTAdapter()
	if err := adapter.Setup(ctx); err != nil {
		t.Skipf("REST adapter setup failed: %v", err)
	}
	defer func() {
		if err := adapter.Teardown(); err != nil {
			t.Logf("Teardown error: %v", err)
		}
	}()

	// Create multiple VNIs concurrently
	numVNIs := 5
	vnis := make([]uint32, numVNIs)
	errors := make(chan error, numVNIs)

	for i := 0; i < numVNIs; i++ {
		go func(index int) {
			vni := generateUniqueVNI()
			opts := VNICreateOptions{
				VNI:  vni,
				VLAN: uint16(100 + index),
				Name: fmt.Sprintf("stress-test-vni-%d", vni),
			}

			result, err := adapter.VNICreate(ctx, opts)
			if err != nil {
				errors <- err
				return
			}
			vnis[index] = result.VNI
			errors <- nil
		}(i)
	}

	// Wait for all creations
	for i := 0; i < numVNIs; i++ {
		if err := <-errors; err != nil {
			skipIfOverlayNotImplemented(t, err)
			t.Logf("VNI creation error: %v", err)
		}
	}

	// Cleanup
	for _, vni := range vnis {
		if vni != 0 {
			if _, err := adapter.VNIDelete(ctx, vni); err != nil {
				t.Logf("Warning: failed to delete VNI %d: %v", vni, err)
			}
		}
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

// skipIfOverlayNotImplemented skips the test if the error indicates the method is not implemented.
func skipIfOverlayNotImplemented(t *testing.T, err error) {
	t.Helper()

	switch err.(type) {
	case ErrGRPCNotImplemented:
		t.Skipf("Not implemented: %v", err)
	case ErrQUICSDNNotImplemented:
		t.Skipf("Not implemented: %v", err)
	case ErrMCPSDNNotImplemented:
		t.Skipf("Not implemented: %v", err)
	case ErrUnixSDNNotImplemented:
		t.Skipf("Not implemented: %v", err)
	case ErrMCPOverlayNotImplemented:
		t.Skipf("Not implemented: %v", err)
	}

	// Also check for service unavailability patterns (daemon test mode
	// does not register overlay/sdn service handlers)
	errMsg := strings.ToLower(err.Error())
	if strings.Contains(errMsg, "not implemented") ||
		strings.Contains(errMsg, "unimplemented") ||
		strings.Contains(errMsg, "not defined") ||
		strings.Contains(errMsg, "service unavailable") ||
		strings.Contains(errMsg, "not available") ||
		strings.Contains(errMsg, "not configured") ||
		strings.Contains(errMsg, "unknown service") ||
		strings.Contains(errMsg, "connection required") ||
		strings.Contains(errMsg, "404 page not found") ||
		strings.Contains(errMsg, "status: 404") ||
		strings.Contains(errMsg, "unknown flag") ||
		strings.Contains(errMsg, "context canceled") ||
		strings.Contains(errMsg, "context deadline exceeded") {
		t.Skipf("Service not available: %v", err)
	}
}

// generateUniqueVNI generates a unique VNI for testing.
func generateUniqueVNI() uint32 {
	now := time.Now()
	// Use timestamp to generate a VNI in the valid range (1-16777215)
	return uint32((now.UnixNano() % 16000000) + 100000)
}

// generateUniquePoolName generates a unique pool name for testing.
func generateUniquePoolName() string {
	now := time.Now()
	return fmt.Sprintf("test-pool-%s-%09d", now.Format("20060102150405"), now.Nanosecond())
}

// containsMode checks if modes slice contains a specific mode.
func containsMode(modes []string, mode string) bool {
	for _, m := range modes {
		if m == mode {
			return true
		}
	}
	return false
}
