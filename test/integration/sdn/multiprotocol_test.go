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
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
)

// =============================================================================
// Multi-Protocol Test Suite
// =============================================================================

// TestSDNMultiProtocol runs all SDN tests across all protocol adapters.
// This ensures feature parity across CLI, REST, gRPC, QUIC, MCP, and Unix protocols.
// Adapters run sequentially to avoid OVS lock contention when 6 adapters
// hit the same backend in parallel, which causes cascading timeouts and hangs.
func TestSDNMultiProtocol(t *testing.T) {
	SkipIfNotIntegration(t)
	SkipIfSDNUnavailable(t)

	adapters := []SDNCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}

	gate := helpers.NewAdapterGate(t, "sdn", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter // capture range variable
		t.Run(adapter.Name(), func(t *testing.T) {
			// Each adapter gets its own 2-minute context to avoid
			// one slow adapter starving subsequent ones.
			adapterCtx, adapterCancel := context.WithTimeout(context.Background(), 2*time.Minute)
			t.Cleanup(adapterCancel)

			// Setup adapter
			t.Logf("[%s] setting up adapter", adapter.Name())
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(adapterCtx))
			defer adapter.Teardown()

			// Run all SDN test suites
			t.Logf("[%s] starting Bridge tests", adapter.Name())
			t.Run("Bridge", func(t *testing.T) {
				testBridgeOperations(t, adapterCtx, adapter)
			})

			t.Logf("[%s] starting Port tests", adapter.Name())
			t.Run("Port", func(t *testing.T) {
				testPortOperations(t, adapterCtx, adapter)
			})

			t.Logf("[%s] starting Flow tests", adapter.Name())
			t.Run("Flow", func(t *testing.T) {
				testFlowOperations(t, adapterCtx, adapter)
			})

			t.Logf("[%s] starting VLAN tests", adapter.Name())
			t.Run("VLAN", func(t *testing.T) {
				testVLANOperations(t, adapterCtx, adapter)
			})

			t.Logf("[%s] starting Policy tests", adapter.Name())
			t.Run("Policy", func(t *testing.T) {
				testPolicyOperations(t, adapterCtx, adapter)
			})

			t.Logf("[%s] all test suites completed", adapter.Name())
		})
	}
}

// =============================================================================
// Bridge Tests
// =============================================================================

// testBridgeOperations tests all bridge operations.
func testBridgeOperations(t *testing.T, ctx context.Context, adapter SDNCommands) {
	t.Run("CreateBridge", func(t *testing.T) {
		testBridgeCreate(t, ctx, adapter)
	})

	t.Run("GetBridge", func(t *testing.T) {
		testBridgeGet(t, ctx, adapter)
	})

	t.Run("ListBridges", func(t *testing.T) {
		testBridgeList(t, ctx, adapter)
	})

	t.Run("DeleteBridge", func(t *testing.T) {
		testBridgeDelete(t, ctx, adapter)
	})

	t.Run("BridgeLifecycle", func(t *testing.T) {
		testBridgeLifecycle(t, ctx, adapter)
	})
}

func testBridgeCreate(t *testing.T, ctx context.Context, adapter SDNCommands) {
	opts := DefaultBridgeOptions("test-create")

	result, err := adapter.BridgeCreate(ctx, opts)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("BridgeCreate failed: %v", err)
	}

	if result.BridgeID == "" {
		t.Error("Expected non-empty BridgeID")
	}

	if result.Type != opts.Type {
		t.Errorf("Expected Type %s, got %s", opts.Type, result.Type)
	}

	if result.Status == "" {
		t.Error("Expected non-empty Status")
	}

	// Cleanup
	adapter.BridgeDelete(ctx, result.BridgeID, BridgeDeleteOptions{Force: true})
}

func testBridgeGet(t *testing.T, ctx context.Context, adapter SDNCommands) {
	// Create a bridge first
	createOpts := DefaultBridgeOptions("test-get")
	createResult, err := adapter.BridgeCreate(ctx, createOpts)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("BridgeCreate failed: %v", err)
	}

	defer adapter.BridgeDelete(ctx, createResult.BridgeID, BridgeDeleteOptions{Force: true})

	// Get the bridge
	result, err := adapter.BridgeGet(ctx, createResult.BridgeID)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("BridgeGet failed: %v", err)
	}

	if result.BridgeID == "" {
		t.Error("Expected non-empty BridgeID")
	}

	if result.Name != createOpts.Name {
		t.Errorf("Expected Name %s, got %s", createOpts.Name, result.Name)
	}
}

func testBridgeList(t *testing.T, ctx context.Context, adapter SDNCommands) {
	// Create some bridges
	bridge1Opts := DefaultBridgeOptions("test-list-1")
	bridge1, err := adapter.BridgeCreate(ctx, bridge1Opts)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("BridgeCreate failed: %v", err)
	}
	defer adapter.BridgeDelete(ctx, bridge1.BridgeID, BridgeDeleteOptions{Force: true})

	bridge2Opts := DefaultBridgeOptions("test-list-2")
	bridge2, err := adapter.BridgeCreate(ctx, bridge2Opts)
	if err != nil {
		t.Fatalf("BridgeCreate failed: %v", err)
	}
	defer adapter.BridgeDelete(ctx, bridge2.BridgeID, BridgeDeleteOptions{Force: true})

	// List bridges
	result, err := adapter.BridgeList(ctx, BridgeListOptions{Limit: 100})
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("BridgeList failed: %v", err)
	}

	if len(result.Bridges) < 2 {
		t.Errorf("Expected at least 2 bridges, got %d", len(result.Bridges))
	}
}

func testBridgeDelete(t *testing.T, ctx context.Context, adapter SDNCommands) {
	// Create a bridge
	createOpts := DefaultBridgeOptions("test-delete")
	createResult, err := adapter.BridgeCreate(ctx, createOpts)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("BridgeCreate failed: %v", err)
	}

	// Delete the bridge
	result, err := adapter.BridgeDelete(ctx, createResult.BridgeID, BridgeDeleteOptions{Force: true})
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("BridgeDelete failed: %v", err)
	}

	if !result.Deleted {
		t.Error("Expected Deleted to be true")
	}

	// Verify bridge is deleted
	_, err = adapter.BridgeGet(ctx, createResult.BridgeID)
	if err == nil {
		t.Error("Expected error getting deleted bridge")
	}
}

func testBridgeLifecycle(t *testing.T, ctx context.Context, adapter SDNCommands) {
	// Create bridge
	lifecycleID := GenerateUniqueBridgeName("lifecycle")
	createOpts := BridgeCreateOptions{
		BridgeID:    lifecycleID,
		Name:        lifecycleID,
		Description: "Test bridge for lifecycle testing",
		Type:        "ovs",
		FailMode:    "secure",
		MTU:         9000,
	}

	createResult, err := adapter.BridgeCreate(ctx, createOpts)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("BridgeCreate failed: %v", err)
	}

	// Get and verify
	getResult, err := adapter.BridgeGet(ctx, createResult.BridgeID)
	if err != nil {
		t.Fatalf("BridgeGet failed: %v", err)
	}

	if getResult.MTU != createOpts.MTU {
		t.Errorf("Expected MTU %d, got %d", createOpts.MTU, getResult.MTU)
	}

	// Delete
	deleteResult, err := adapter.BridgeDelete(ctx, createResult.BridgeID, BridgeDeleteOptions{Force: true})
	if err != nil {
		t.Fatalf("BridgeDelete failed: %v", err)
	}

	if !deleteResult.Deleted {
		t.Error("Expected bridge to be deleted")
	}
}

// =============================================================================
// Port Tests
// =============================================================================

// testPortOperations tests all port operations.
func testPortOperations(t *testing.T, ctx context.Context, adapter SDNCommands) {
	t.Run("AddPort", func(t *testing.T) {
		testPortAdd(t, ctx, adapter)
	})

	t.Run("DeletePort", func(t *testing.T) {
		testPortDelete(t, ctx, adapter)
	})

	t.Run("GetPortState", func(t *testing.T) {
		testPortGetState(t, ctx, adapter)
	})

	t.Run("SetPortState", func(t *testing.T) {
		testPortSetState(t, ctx, adapter)
	})

	t.Run("GetPortStats", func(t *testing.T) {
		testPortGetStats(t, ctx, adapter)
	})
}

func testPortAdd(t *testing.T, ctx context.Context, adapter SDNCommands) {
	// Create a bridge first
	bridgeOpts := DefaultBridgeOptions("port-add-test")
	bridge, err := adapter.BridgeCreate(ctx, bridgeOpts)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("BridgeCreate failed: %v", err)
	}
	defer adapter.BridgeDelete(ctx, bridge.BridgeID, BridgeDeleteOptions{Force: true})

	// Add a port
	portOpts := DefaultPortOptions(bridge.BridgeID, "port1")
	result, err := adapter.PortAdd(ctx, portOpts)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("PortAdd failed: %v", err)
	}

	if result.PortID == "" {
		t.Error("Expected non-empty PortID")
	}
}

func testPortDelete(t *testing.T, ctx context.Context, adapter SDNCommands) {
	// Create a bridge and port
	bridgeOpts := DefaultBridgeOptions("port-delete-test")
	bridge, err := adapter.BridgeCreate(ctx, bridgeOpts)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("BridgeCreate failed: %v", err)
	}
	defer adapter.BridgeDelete(ctx, bridge.BridgeID, BridgeDeleteOptions{Force: true})

	portOpts := DefaultPortOptions(bridge.BridgeID, "port-to-delete")
	port, err := adapter.PortAdd(ctx, portOpts)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("PortAdd failed: %v", err)
	}

	// Delete the port
	result, err := adapter.PortDelete(ctx, bridge.BridgeID, port.PortID)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("PortDelete failed: %v", err)
	}

	if !result.Deleted {
		t.Error("Expected Deleted to be true")
	}
}

func testPortGetState(t *testing.T, ctx context.Context, adapter SDNCommands) {
	// Create a bridge and port
	bridgeOpts := DefaultBridgeOptions("port-state-test")
	bridge, err := adapter.BridgeCreate(ctx, bridgeOpts)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("BridgeCreate failed: %v", err)
	}
	defer adapter.BridgeDelete(ctx, bridge.BridgeID, BridgeDeleteOptions{Force: true})

	portOpts := DefaultPortOptions(bridge.BridgeID, "state-port")
	port, err := adapter.PortAdd(ctx, portOpts)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("PortAdd failed: %v", err)
	}

	// Get port state
	result, err := adapter.PortGetState(ctx, bridge.BridgeID, port.PortID)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("PortGetState failed: %v", err)
	}

	if result.PortID == "" {
		t.Error("Expected non-empty PortID")
	}

	if result.AdminState == "" {
		t.Error("Expected non-empty AdminState")
	}
}

func testPortSetState(t *testing.T, ctx context.Context, adapter SDNCommands) {
	// Create a bridge and port
	bridgeOpts := DefaultBridgeOptions("port-setstate-test")
	bridge, err := adapter.BridgeCreate(ctx, bridgeOpts)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("BridgeCreate failed: %v", err)
	}
	defer adapter.BridgeDelete(ctx, bridge.BridgeID, BridgeDeleteOptions{Force: true})

	portOpts := DefaultPortOptions(bridge.BridgeID, "setstate-port")
	port, err := adapter.PortAdd(ctx, portOpts)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("PortAdd failed: %v", err)
	}

	// Set port state, ingress policing (10 Mbps, 1 Mbit burst) and egress
	// shaping (20 Mbps, 2 Mbit burst).
	stateOpts := PortSetStateOptions{
		AdminState:   "down",
		IngressRate:  10_000_000,
		IngressBurst: 1_000_000,
		EgressRate:   20_000_000,
		EgressBurst:  2_000_000,
	}

	result, err := adapter.PortSetState(ctx, bridge.BridgeID, port.PortID, stateOpts)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("PortSetState failed: %v", err)
	}

	if result.AdminState != "down" {
		t.Errorf("Expected AdminState 'down', got '%s'", result.AdminState)
	}

	// Open vSwitch stores policing in kbps and kb.
	for column, want := range map[string]string{"ingress_policing_rate": "10000", "ingress_policing_burst": "1000"} {
		out, err := exec.CommandContext(ctx, "ovs-vsctl", "get", "interface", portOpts.Name, column).CombinedOutput()
		if err != nil {
			t.Fatalf("ovs-vsctl get %s: %v: %s", column, err, out)
		}
		if got := strings.TrimSpace(string(out)); got != want {
			t.Errorf("%s = %s, want %s", column, got, want)
		}
	}

	// Egress shaping is a linux-htb QoS on the port, stored in bps.
	out, err := exec.CommandContext(ctx, "ovs-vsctl", "get", "port", portOpts.Name, "qos").CombinedOutput()
	if err != nil {
		t.Fatalf("ovs-vsctl get port qos: %v: %s", err, out)
	}
	qosUUID := strings.TrimSpace(string(out))
	for column, want := range map[string]string{"type": "linux-htb", "other_config:max-rate": `"20000000"`} {
		out, err := exec.CommandContext(ctx, "ovs-vsctl", "get", "qos", qosUUID, column).CombinedOutput()
		if err != nil {
			t.Fatalf("ovs-vsctl get qos %s: %v: %s", column, err, out)
		}
		if got := strings.TrimSpace(string(out)); got != want {
			t.Errorf("qos %s = %s, want %s", column, got, want)
		}
	}
}

func testPortGetStats(t *testing.T, ctx context.Context, adapter SDNCommands) {
	// Create a bridge and port
	bridgeOpts := DefaultBridgeOptions("port-stats-test")
	bridge, err := adapter.BridgeCreate(ctx, bridgeOpts)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("BridgeCreate failed: %v", err)
	}
	defer adapter.BridgeDelete(ctx, bridge.BridgeID, BridgeDeleteOptions{Force: true})

	portOpts := DefaultPortOptions(bridge.BridgeID, "stats-port")
	port, err := adapter.PortAdd(ctx, portOpts)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("PortAdd failed: %v", err)
	}

	// Get port stats
	result, err := adapter.PortGetStats(ctx, bridge.BridgeID, port.PortID)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("PortGetStats failed: %v", err)
	}

	if result.PortID == "" {
		t.Error("Expected non-empty PortID")
	}

	// Stats should be initialized (at minimum 0)
	if result.RetrievedAt.IsZero() {
		t.Error("Expected non-zero RetrievedAt")
	}
}

// =============================================================================
// Flow Tests
// =============================================================================

// testFlowOperations tests all flow operations.
func testFlowOperations(t *testing.T, ctx context.Context, adapter SDNCommands) {
	t.Run("AddFlow", func(t *testing.T) {
		testFlowAdd(t, ctx, adapter)
	})

	t.Run("DeleteFlow", func(t *testing.T) {
		testFlowDelete(t, ctx, adapter)
	})

	t.Run("ListFlows", func(t *testing.T) {
		testFlowList(t, ctx, adapter)
	})
}

func testFlowAdd(t *testing.T, ctx context.Context, adapter SDNCommands) {
	// Create a bridge
	bridgeOpts := DefaultBridgeOptions("flow-add-test")
	bridge, err := adapter.BridgeCreate(ctx, bridgeOpts)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("BridgeCreate failed: %v", err)
	}
	defer adapter.BridgeDelete(ctx, bridge.BridgeID, BridgeDeleteOptions{Force: true})

	// Add a flow
	flowOpts := DefaultFlowOptions(bridge.BridgeID, "flow1")
	result, err := adapter.FlowAdd(ctx, flowOpts)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("FlowAdd failed: %v", err)
	}

	// The server assigns the ID: it is the cookie the flow was installed
	// with ("flow-<cookie>"), so a delete or a stats query names exactly
	// this flow. The requested name is only a label (#614).
	if _, err := ovs.ParseFlowID(result.FlowID); err != nil {
		t.Errorf("FlowAdd returned ID %q, which names no single flow: %v", result.FlowID, err)
	}
}

func testFlowDelete(t *testing.T, ctx context.Context, adapter SDNCommands) {
	// Create a bridge and flow
	bridgeOpts := DefaultBridgeOptions("flow-delete-test")
	bridge, err := adapter.BridgeCreate(ctx, bridgeOpts)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("BridgeCreate failed: %v", err)
	}
	defer adapter.BridgeDelete(ctx, bridge.BridgeID, BridgeDeleteOptions{Force: true})

	flowOpts := DefaultFlowOptions(bridge.BridgeID, "flow-to-delete")
	flow, err := adapter.FlowAdd(ctx, flowOpts)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("FlowAdd failed: %v", err)
	}

	// Delete the flow
	result, err := adapter.FlowDelete(ctx, bridge.BridgeID, flow.FlowID)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("FlowDelete failed: %v", err)
	}

	if !result.Deleted {
		t.Error("Expected Deleted to be true")
	}
}

func testFlowList(t *testing.T, ctx context.Context, adapter SDNCommands) {
	// Create a bridge and flows
	bridgeOpts := DefaultBridgeOptions("flow-list-test")
	bridge, err := adapter.BridgeCreate(ctx, bridgeOpts)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("BridgeCreate failed: %v", err)
	}
	defer adapter.BridgeDelete(ctx, bridge.BridgeID, BridgeDeleteOptions{Force: true})

	// Add flows with different priorities so OVS treats them as distinct rules
	flow1Opts := DefaultFlowOptions(bridge.BridgeID, "flow-list-1")
	flow1Opts.Priority = 100
	flow1, err := adapter.FlowAdd(ctx, flow1Opts)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("FlowAdd failed: %v", err)
	}
	defer adapter.FlowDelete(ctx, bridge.BridgeID, flow1.FlowID)

	flow2Opts := DefaultFlowOptions(bridge.BridgeID, "flow-list-2")
	flow2Opts.Priority = 200
	flow2, err := adapter.FlowAdd(ctx, flow2Opts)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("FlowAdd failed: %v", err)
	}
	defer adapter.FlowDelete(ctx, bridge.BridgeID, flow2.FlowID)

	// List flows
	result, err := adapter.FlowList(ctx, bridge.BridgeID, FlowListOptions{Limit: 100})
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("FlowList failed: %v", err)
	}

	if len(result.Flows) < 2 {
		t.Errorf("Expected at least 2 flows, got %d", len(result.Flows))
	}
}

// =============================================================================
// VLAN Tests
// =============================================================================

// testVLANOperations tests all VLAN operations.
func testVLANOperations(t *testing.T, ctx context.Context, adapter SDNCommands) {
	t.Run("CreateVLAN", func(t *testing.T) {
		testVLANCreate(t, ctx, adapter)
	})

	t.Run("DeleteVLAN", func(t *testing.T) {
		testVLANDelete(t, ctx, adapter)
	})

	t.Run("ListVLANs", func(t *testing.T) {
		testVLANList(t, ctx, adapter)
	})
}

func testVLANCreate(t *testing.T, ctx context.Context, adapter SDNCommands) {
	// Create a bridge for the VLAN (required by SDN service)
	bridgeOpts := DefaultBridgeOptions("vlan-create-test")
	bridge, err := adapter.BridgeCreate(ctx, bridgeOpts)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("BridgeCreate failed: %v", err)
	}
	defer adapter.BridgeDelete(ctx, bridge.BridgeID, BridgeDeleteOptions{Force: true})

	vlanID := GenerateUniqueVLANID()
	opts := DefaultVLANOptions(vlanID, bridge.BridgeID)

	result, err := adapter.VLANCreate(ctx, opts)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("VLANCreate failed: %v", err)
	}

	if result.VLANID != opts.VLANID {
		t.Errorf("Expected VLANID %d, got %d", opts.VLANID, result.VLANID)
	}

	// Cleanup
	adapter.VLANDelete(ctx, bridge.BridgeID, result.VLANID)
}

func testVLANDelete(t *testing.T, ctx context.Context, adapter SDNCommands) {
	// Create a bridge for the VLAN (required by SDN service)
	bridgeOpts := DefaultBridgeOptions("vlan-delete-test")
	bridge, err := adapter.BridgeCreate(ctx, bridgeOpts)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("BridgeCreate failed: %v", err)
	}
	defer adapter.BridgeDelete(ctx, bridge.BridgeID, BridgeDeleteOptions{Force: true})

	vlanID := GenerateUniqueVLANID()
	opts := DefaultVLANOptions(vlanID, bridge.BridgeID)

	vlan, err := adapter.VLANCreate(ctx, opts)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("VLANCreate failed: %v", err)
	}

	result, err := adapter.VLANDelete(ctx, bridge.BridgeID, vlan.VLANID)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("VLANDelete failed: %v", err)
	}

	if !result.Deleted {
		t.Error("Expected Deleted to be true")
	}
}

func testVLANList(t *testing.T, ctx context.Context, adapter SDNCommands) {
	// Create a bridge for VLANs (required by SDN service)
	bridgeOpts := DefaultBridgeOptions("vlan-list-test")
	bridge, err := adapter.BridgeCreate(ctx, bridgeOpts)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("BridgeCreate failed: %v", err)
	}
	defer adapter.BridgeDelete(ctx, bridge.BridgeID, BridgeDeleteOptions{Force: true})

	// Create some VLANs
	vlan1, err := adapter.VLANCreate(ctx, DefaultVLANOptions(GenerateUniqueVLANID(), bridge.BridgeID))
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("VLANCreate failed: %v", err)
	}
	defer adapter.VLANDelete(ctx, bridge.BridgeID, vlan1.VLANID)

	vlan2, err := adapter.VLANCreate(ctx, DefaultVLANOptions(GenerateUniqueVLANID(), bridge.BridgeID))
	if err != nil {
		t.Fatalf("VLANCreate failed: %v", err)
	}
	defer adapter.VLANDelete(ctx, bridge.BridgeID, vlan2.VLANID)

	// List VLANs
	result, err := adapter.VLANList(ctx, VLANListOptions{BridgeID: bridge.BridgeID, Limit: 100})
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("VLANList failed: %v", err)
	}

	if len(result.VLANs) < 2 {
		t.Errorf("Expected at least 2 VLANs, got %d", len(result.VLANs))
	}
}

// =============================================================================
// Policy Tests
// =============================================================================

// testPolicyOperations tests all policy operations.
func testPolicyOperations(t *testing.T, ctx context.Context, adapter SDNCommands) {
	t.Run("ApplyPolicy", func(t *testing.T) {
		testPolicyApply(t, ctx, adapter)
	})

	t.Run("GetPolicy", func(t *testing.T) {
		testPolicyGet(t, ctx, adapter)
	})

	t.Run("ListPolicies", func(t *testing.T) {
		testPolicyList(t, ctx, adapter)
	})
}

func testPolicyApply(t *testing.T, ctx context.Context, adapter SDNCommands) {
	// Create a bridge for the policy (required by SDN service for flow rules)
	bridgeOpts := DefaultBridgeOptions("policy-apply-test")
	bridge, err := adapter.BridgeCreate(ctx, bridgeOpts)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("BridgeCreate failed: %v", err)
	}
	defer adapter.BridgeDelete(ctx, bridge.BridgeID, BridgeDeleteOptions{Force: true})

	policyID := GenerateUniqueBridgeName("policy")
	opts := DefaultPolicyOptions(policyID, bridge.BridgeID)

	result, err := adapter.PolicyApply(ctx, opts)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("PolicyApply failed: %v", err)
	}

	if result.PolicyID == "" {
		t.Error("Expected non-empty PolicyID")
	}

	if result.Status == "" {
		t.Error("Expected non-empty Status")
	}
}

func testPolicyGet(t *testing.T, ctx context.Context, adapter SDNCommands) {
	// Create a bridge for the policy (required by SDN service for flow rules)
	bridgeOpts := DefaultBridgeOptions("policy-get-test")
	bridge, err := adapter.BridgeCreate(ctx, bridgeOpts)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("BridgeCreate failed: %v", err)
	}
	defer adapter.BridgeDelete(ctx, bridge.BridgeID, BridgeDeleteOptions{Force: true})

	// Apply a policy first
	policyID := GenerateUniqueBridgeName("policy-get")
	applyOpts := DefaultPolicyOptions(policyID, bridge.BridgeID)

	applied, err := adapter.PolicyApply(ctx, applyOpts)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("PolicyApply failed: %v", err)
	}

	// Get the policy
	result, err := adapter.PolicyGet(ctx, applied.PolicyID)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("PolicyGet failed: %v", err)
	}

	if result.PolicyID == "" {
		t.Error("Expected non-empty PolicyID")
	}

	if result.Type != applyOpts.Type {
		t.Errorf("Expected Type %s, got %s", applyOpts.Type, result.Type)
	}
}

func testPolicyList(t *testing.T, ctx context.Context, adapter SDNCommands) {
	// Create a bridge for the policies (required by SDN service for flow rules)
	bridgeOpts := DefaultBridgeOptions("policy-list-test")
	bridge, err := adapter.BridgeCreate(ctx, bridgeOpts)
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("BridgeCreate failed: %v", err)
	}
	defer adapter.BridgeDelete(ctx, bridge.BridgeID, BridgeDeleteOptions{Force: true})

	// Apply some policies
	policy1, err := adapter.PolicyApply(ctx, DefaultPolicyOptions(GenerateUniqueBridgeName("policy-list-1"), bridge.BridgeID))
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("PolicyApply failed: %v", err)
	}
	_ = policy1 // Keep reference for potential cleanup

	policy2, err := adapter.PolicyApply(ctx, DefaultPolicyOptions(GenerateUniqueBridgeName("policy-list-2"), bridge.BridgeID))
	if err != nil {
		t.Fatalf("PolicyApply failed: %v", err)
	}
	_ = policy2 // Keep reference for potential cleanup

	// List policies
	result, err := adapter.PolicyList(ctx, PolicyListOptions{Limit: 100})
	if err != nil {
		surface.SkipIfNotImplemented(t, err)
		t.Fatalf("PolicyList failed: %v", err)
	}

	if len(result.Policies) < 2 {
		t.Errorf("Expected at least 2 policies, got %d", len(result.Policies))
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

// =============================================================================
// Protocol-Specific Tests
// =============================================================================

// TestCLISDNOperations tests SDN operations specifically via CLI.
func TestCLISDNOperations(t *testing.T) {
	SkipIfNotIntegration(t)
	SkipIfSDNUnavailable(t)

	ctx, cancel := DefaultTestContext()
	defer cancel()

	adapter := NewCLIAdapter()
	helpers.RequireAdapterSetup(t, "sdn", "CLI", adapter.Setup(ctx))
	defer adapter.Teardown()

	testBridgeOperations(t, ctx, adapter)
}

// TestRESTSDNOperations tests SDN operations specifically via REST.
func TestRESTSDNOperations(t *testing.T) {
	SkipIfNotIntegration(t)
	SkipIfSDNUnavailable(t)

	ctx, cancel := DefaultTestContext()
	defer cancel()

	adapter := NewRESTAdapter()
	helpers.RequireAdapterSetup(t, "sdn", "REST", adapter.Setup(ctx))
	defer adapter.Teardown()

	testBridgeOperations(t, ctx, adapter)
}

// TestGRPCSDNOperations tests SDN operations specifically via gRPC.
func TestGRPCSDNOperations(t *testing.T) {
	SkipIfNotIntegration(t)
	SkipIfSDNUnavailable(t)

	ctx, cancel := DefaultTestContext()
	defer cancel()

	adapter := NewGRPCAdapter()
	helpers.RequireAdapterSetup(t, "sdn", "gRPC", adapter.Setup(ctx))
	defer adapter.Teardown()

	testBridgeOperations(t, ctx, adapter)
}

// TestQUICSDNOperations tests SDN operations specifically via QUIC.
func TestQUICSDNOperations(t *testing.T) {
	SkipIfNotIntegration(t)
	SkipIfSDNUnavailable(t)

	ctx, cancel := DefaultTestContext()
	defer cancel()

	adapter := NewQUICAdapter()
	helpers.RequireAdapterSetup(t, "sdn", "QUIC", adapter.Setup(ctx))
	defer adapter.Teardown()

	testBridgeOperations(t, ctx, adapter)
}

// TestMCPSDNOperations tests SDN operations specifically via MCP.
func TestMCPSDNOperations(t *testing.T) {
	SkipIfNotIntegration(t)
	SkipIfSDNUnavailable(t)

	ctx, cancel := DefaultTestContext()
	defer cancel()

	adapter := NewMCPAdapter()
	helpers.RequireAdapterSetup(t, "sdn", "MCP", adapter.Setup(ctx))
	defer adapter.Teardown()

	testBridgeOperations(t, ctx, adapter)
}

// TestUnixSDNOperations tests SDN operations specifically via Unix socket.
func TestUnixSDNOperations(t *testing.T) {
	SkipIfNotIntegration(t)
	SkipIfSDNUnavailable(t)

	ctx, cancel := DefaultTestContext()
	defer cancel()

	adapter := NewUnixAdapter()
	helpers.RequireAdapterSetup(t, "sdn", "Unix", adapter.Setup(ctx))
	defer adapter.Teardown()

	testBridgeOperations(t, ctx, adapter)
}

// =============================================================================
// Error Handling Tests
// =============================================================================

// TestSDNErrorHandling tests error handling across protocols.
func TestSDNErrorHandling(t *testing.T) {
	SkipIfNotIntegration(t)
	SkipIfSDNUnavailable(t)

	ctx, cancel := DefaultTestContext()
	defer cancel()

	adapters := []SDNCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
	}

	gate := helpers.NewAdapterGate(t, "sdn", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter
		t.Run(adapter.Name()+"/GetNonExistentBridge", func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			defer adapter.Teardown()

			_, err := adapter.BridgeGet(ctx, "non-existent-bridge-id-12345")
			if err == nil {
				t.Error("Expected error for non-existent bridge")
			}
		})

		t.Run(adapter.Name()+"/DeleteNonExistentBridge", func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			defer adapter.Teardown()

			_, err := adapter.BridgeDelete(ctx, "non-existent-bridge-id-12345", BridgeDeleteOptions{})
			if err == nil {
				t.Error("Expected error for non-existent bridge")
			}
		})
	}
}

// =============================================================================
// Stress Tests
// =============================================================================

// TestSDNStressOperations performs stress testing of SDN operations.
func TestSDNStressOperations(t *testing.T) {
	SkipIfNotIntegration(t)
	SkipIfSDNUnavailable(t)

	ctx, cancel := LongRunningTestContext()
	defer cancel()

	adapter := NewRESTAdapter()
	helpers.RequireAdapterSetup(t, "sdn", "REST", adapter.Setup(ctx))
	defer adapter.Teardown()

	// Create multiple bridges concurrently
	numBridges := 10
	bridgeIDs := make([]string, numBridges)
	errors := make(chan error, numBridges)

	for i := 0; i < numBridges; i++ {
		go func(index int) {
			opts := DefaultBridgeOptions("stress-test")
			opts.BridgeID = GenerateUniqueBridgeName("stress")

			result, err := adapter.BridgeCreate(ctx, opts)
			if err != nil {
				errors <- err
				return
			}
			bridgeIDs[index] = result.BridgeID
			errors <- nil
		}(i)
	}

	// Wait for all creations
	for i := 0; i < numBridges; i++ {
		if err := <-errors; err != nil {
			surface.SkipIfNotImplemented(t, err)
			t.Logf("Bridge creation error: %v", err)
		}
	}

	// Cleanup: every create has returned above, so nothing is still in flight
	for _, bridgeID := range bridgeIDs {
		if bridgeID != "" {
			adapter.BridgeDelete(ctx, bridgeID, BridgeDeleteOptions{Force: true})
		}
	}
}
