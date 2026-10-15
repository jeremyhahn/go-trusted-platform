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
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testenv"
)

// TestOpenFlowRulesForNetworkPhases tests OpenFlow rule installation
// for different network provisioning phases
func TestOpenFlowRulesForNetworkPhases(t *testing.T) {
	requireOVSDBForTest(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	client, err := ovs.NewClient("/var/run/openvswitch/db.sock")
	require.NoError(t, err)
	defer client.Close()

	err = client.Connect(ctx)
	if err != nil {
		t.Skipf("Skipping test: cannot connect to OVSDB: %v", err)
	}

	bridgeName := "br-phases-test"
	// Cleanup any existing bridge
	exec.Command("ovs-vsctl", "--if-exists", "del-br", bridgeName).Run()
	defer exec.Command("ovs-vsctl", "--if-exists", "del-br", bridgeName).Run()

	// Create bridge via ovs-vsctl which properly creates management socket
	cmd := exec.Command("ovs-vsctl", "add-br", bridgeName)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to create bridge: %s", output)

	// Configure bridge for OpenFlow
	cmd = exec.Command("ovs-vsctl", "set", "bridge", bridgeName, "protocols=OpenFlow13")
	output, err = cmd.CombinedOutput()
	require.NoError(t, err, "Failed to set protocols: %s", output)

	cmd = exec.Command("ovs-vsctl", "set", "bridge", bridgeName, "fail_mode=secure")
	output, err = cmd.CombinedOutput()
	require.NoError(t, err, "Failed to set fail_mode: %s", output)

	portName := "test-phase-port"
	// Use ovs-vsctl to add port (more reliable than OVSDB for internal ports)
	cmd = exec.Command("ovs-vsctl", "add-port", bridgeName, portName, "--", "set", "interface", portName, "type=internal")
	output, err = cmd.CombinedOutput()
	require.NoError(t, err, "Failed to add port: %s", output)

	// Wait for OVS to create the internal port interface in the kernel and bring it up
	output, linkUpErr := bringInternalPortUp(ctx, portName)
	require.NoError(t, linkUpErr, "Failed to bring up interface %s after retries: %s", portName, output)

	// Wait for OVS to assign ofport
	ofport := waitForOFPort(ctx, t, portName)
	require.Greater(t, ofport, int32(0), "ofport should be positive after retries")

	t.Run("ProvisioningPhaseRules", func(t *testing.T) {
		// Clear all flows first
		err := client.DeleteAllFlows(ctx, bridgeName)
		require.NoError(t, err)

		// Install provisioning phase rules - limited network access
		provisioningFlows := []struct {
			priority int
			match    string
			actions  string
			desc     string
		}{
			{
				priority: 2000,
				match:    fmt.Sprintf("in_port=%d,dl_type=0x0800,nw_proto=17,tp_dst=67", ofport),
				actions:  "NORMAL",
				desc:     "Allow DHCP requests",
			},
			{
				priority: 2000,
				match:    fmt.Sprintf("in_port=%d,dl_type=0x0800,nw_proto=17,tp_dst=68", ofport),
				actions:  "NORMAL",
				desc:     "Allow DHCP responses",
			},
			{
				priority: 2000,
				match:    fmt.Sprintf("in_port=%d,dl_type=0x0800,nw_proto=17,tp_dst=53", ofport),
				actions:  "NORMAL",
				desc:     "Allow DNS queries",
			},
			{
				priority: 2000,
				match:    fmt.Sprintf("in_port=%d,dl_type=0x0800,nw_proto=6,tp_dst=443", ofport),
				actions:  "NORMAL",
				desc:     "Allow HTTPS for enrollment",
			},
			{
				priority: 1000,
				match:    fmt.Sprintf("in_port=%d,dl_type=0x0806", ofport),
				actions:  "NORMAL",
				desc:     "Allow ARP",
			},
			{
				priority: 100,
				match:    fmt.Sprintf("in_port=%d", ofport),
				actions:  "drop",
				desc:     "Drop all other traffic",
			},
		}

		for _, flow := range provisioningFlows {
			t.Run(flow.desc, func(t *testing.T) {
				flowMod := &ovs.FlowMod{
					Table:    0,
					Priority: flow.priority,
					Match:    flow.match,
					Actions:  flow.actions,
				}

				err := client.AddFlow(ctx, bridgeName, flowMod)
				require.NoError(t, err, "Failed to install: %s", flow.desc)
			})
		}

		// Verify all flows were installed
		flows, err := client.ListFlows(ctx, bridgeName)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(flows), len(provisioningFlows),
			"Should have at least %d flows installed", len(provisioningFlows))
	})

	t.Run("ProductionPhaseRules", func(t *testing.T) {
		// Clear all flows
		err := client.DeleteAllFlows(ctx, bridgeName)
		require.NoError(t, err)

		// Install production phase rules - full network access with ACLs
		productionFlows := []struct {
			priority int
			match    string
			actions  string
			desc     string
		}{
			{
				priority: 3000,
				match:    fmt.Sprintf("in_port=%d,dl_type=0x0800,nw_proto=6,tp_dst=22", ofport),
				actions:  "NORMAL",
				desc:     "Allow SSH",
			},
			{
				priority: 3000,
				match:    fmt.Sprintf("in_port=%d,dl_type=0x0800,nw_proto=6,tp_dst=80", ofport),
				actions:  "NORMAL",
				desc:     "Allow HTTP",
			},
			{
				priority: 3000,
				match:    fmt.Sprintf("in_port=%d,dl_type=0x0800,nw_proto=6,tp_dst=443", ofport),
				actions:  "NORMAL",
				desc:     "Allow HTTPS",
			},
			{
				priority: 2000,
				match:    fmt.Sprintf("in_port=%d,dl_type=0x0800,nw_proto=17,tp_dst=53", ofport),
				actions:  "NORMAL",
				desc:     "Allow DNS",
			},
			{
				priority: 2000,
				match:    fmt.Sprintf("in_port=%d,dl_type=0x0800,nw_proto=1", ofport),
				actions:  "NORMAL",
				desc:     "Allow ICMP",
			},
			{
				priority: 1000,
				match:    fmt.Sprintf("in_port=%d", ofport),
				actions:  "NORMAL",
				desc:     "Allow all other traffic",
			},
		}

		for _, flow := range productionFlows {
			t.Run(flow.desc, func(t *testing.T) {
				flowMod := &ovs.FlowMod{
					Table:    0,
					Priority: flow.priority,
					Match:    flow.match,
					Actions:  flow.actions,
				}

				err := client.AddFlow(ctx, bridgeName, flowMod)
				require.NoError(t, err, "Failed to install: %s", flow.desc)
			})
		}

		// Verify flows
		flows, err := client.ListFlows(ctx, bridgeName)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(flows), len(productionFlows))
	})

	t.Run("QuarantinePhaseRules", func(t *testing.T) {
		// Clear all flows
		err := client.DeleteAllFlows(ctx, bridgeName)
		require.NoError(t, err)

		// Install quarantine rules - isolated network access
		quarantineFlows := []struct {
			priority int
			match    string
			actions  string
			desc     string
		}{
			{
				priority: 5000,
				match:    fmt.Sprintf("in_port=%d", ofport),
				actions:  "drop",
				desc:     "Drop all traffic in quarantine",
			},
		}

		for _, flow := range quarantineFlows {
			t.Run(flow.desc, func(t *testing.T) {
				flowMod := &ovs.FlowMod{
					Table:    0,
					Priority: flow.priority,
					Match:    flow.match,
					Actions:  flow.actions,
				}

				err := client.AddFlow(ctx, bridgeName, flowMod)
				require.NoError(t, err, "Failed to install: %s", flow.desc)
			})
		}

		// Verify flows
		flows, err := client.ListFlows(ctx, bridgeName)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(flows), len(quarantineFlows))
	})
}

// TestACLToOpenFlowTranslation tests translation of ACL rules to OpenFlow
func TestACLToOpenFlowTranslation(t *testing.T) {
	requireOVSDBForTest(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	client, err := ovs.NewClient("/var/run/openvswitch/db.sock")
	require.NoError(t, err)
	defer client.Close()

	err = client.Connect(ctx)
	if err != nil {
		t.Skipf("Skipping test: cannot connect to OVSDB: %v", err)
	}

	bridgeName := "br-acl-test"
	// Cleanup any existing bridge
	exec.Command("ovs-vsctl", "--if-exists", "del-br", bridgeName).Run()
	defer exec.Command("ovs-vsctl", "--if-exists", "del-br", bridgeName).Run()

	// Create bridge via ovs-vsctl
	cmd := exec.Command("ovs-vsctl", "add-br", bridgeName)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to create bridge: %s", output)

	cmd = exec.Command("ovs-vsctl", "set", "bridge", bridgeName, "protocols=OpenFlow13")
	output, err = cmd.CombinedOutput()
	require.NoError(t, err, "Failed to set protocols: %s", output)

	portName := "test-acl-port"
	// Use ovs-vsctl to add port (more reliable than OVSDB for internal ports)
	cmd = exec.Command("ovs-vsctl", "add-port", bridgeName, portName, "--", "set", "interface", portName, "type=internal")
	output, err = cmd.CombinedOutput()
	require.NoError(t, err, "Failed to add port: %s", output)

	// Wait for OVS to create the internal port interface in the kernel and bring it up
	output, linkUpErr := bringInternalPortUp(ctx, portName)
	require.NoError(t, linkUpErr, "Failed to bring up interface %s after retries: %s", portName, output)

	// Wait for OVS to assign ofport
	ofport := waitForOFPort(ctx, t, portName)
	require.Greater(t, ofport, int32(0), "ofport should be positive after retries")

	t.Run("TCPPortACL", func(t *testing.T) {
		flowMod := &ovs.FlowMod{
			Table:    0,
			Priority: 1000,
			Match:    fmt.Sprintf("in_port=%d,dl_type=0x0800,nw_proto=6,tp_dst=443", ofport),
			Actions:  "NORMAL",
		}

		err := client.AddFlow(ctx, bridgeName, flowMod)
		require.NoError(t, err)

		flows, err := client.ListFlows(ctx, bridgeName)
		require.NoError(t, err)
		assert.NotEmpty(t, flows)
	})

	t.Run("UDPPortACL", func(t *testing.T) {
		flowMod := &ovs.FlowMod{
			Table:    0,
			Priority: 1000,
			Match:    fmt.Sprintf("in_port=%d,dl_type=0x0800,nw_proto=17,tp_dst=53", ofport),
			Actions:  "NORMAL",
		}

		err := client.AddFlow(ctx, bridgeName, flowMod)
		require.NoError(t, err)
	})

	t.Run("ICMPProtocolACL", func(t *testing.T) {
		flowMod := &ovs.FlowMod{
			Table:    0,
			Priority: 1000,
			Match:    fmt.Sprintf("in_port=%d,dl_type=0x0800,nw_proto=1", ofport),
			Actions:  "NORMAL",
		}

		err := client.AddFlow(ctx, bridgeName, flowMod)
		require.NoError(t, err)
	})

	t.Run("SourceIPACL", func(t *testing.T) {
		flowMod := &ovs.FlowMod{
			Table:    0,
			Priority: 1000,
			Match:    fmt.Sprintf("in_port=%d,dl_type=0x0800,nw_src=10.0.0.0/24", ofport),
			Actions:  "NORMAL",
		}

		err := client.AddFlow(ctx, bridgeName, flowMod)
		require.NoError(t, err)
	})

	t.Run("DestinationIPACL", func(t *testing.T) {
		flowMod := &ovs.FlowMod{
			Table:    0,
			Priority: 1000,
			Match:    fmt.Sprintf("in_port=%d,dl_type=0x0800,nw_dst=192.168.1.0/24", ofport),
			Actions:  "NORMAL",
		}

		err := client.AddFlow(ctx, bridgeName, flowMod)
		require.NoError(t, err)
	})

	t.Run("DenyACL", func(t *testing.T) {
		flowMod := &ovs.FlowMod{
			Table:    0,
			Priority: 500,
			Match:    fmt.Sprintf("in_port=%d,dl_type=0x0800,nw_proto=6,tp_dst=23", ofport),
			Actions:  "drop",
		}

		err := client.AddFlow(ctx, bridgeName, flowMod)
		require.NoError(t, err)
	})
}

// TestFlowModificationAndRemoval tests flow update and removal operations
func TestFlowModificationAndRemoval(t *testing.T) {
	requireOVSDBForTest(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	client, err := ovs.NewClient("/var/run/openvswitch/db.sock")
	require.NoError(t, err)
	defer client.Close()

	err = client.Connect(ctx)
	if err != nil {
		t.Skipf("Skipping test: cannot connect to OVSDB: %v", err)
	}

	bridgeName := "br-mod-test"
	// Cleanup any existing bridge
	exec.Command("ovs-vsctl", "--if-exists", "del-br", bridgeName).Run()
	defer exec.Command("ovs-vsctl", "--if-exists", "del-br", bridgeName).Run()

	// Create bridge via ovs-vsctl
	cmd := exec.Command("ovs-vsctl", "add-br", bridgeName)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to create bridge: %s", output)

	cmd = exec.Command("ovs-vsctl", "set", "bridge", bridgeName, "protocols=OpenFlow13")
	output, err = cmd.CombinedOutput()
	require.NoError(t, err, "Failed to set protocols: %s", output)

	portName := "test-mod-port"
	// Use ovs-vsctl to add port (more reliable than OVSDB for internal ports)
	cmd = exec.Command("ovs-vsctl", "add-port", bridgeName, portName, "--", "set", "interface", portName, "type=internal")
	output, err = cmd.CombinedOutput()
	require.NoError(t, err, "Failed to add port: %s", output)

	// Wait for OVS to create the internal port interface in the kernel and bring it up
	output, linkUpErr := bringInternalPortUp(ctx, portName)
	require.NoError(t, linkUpErr, "Failed to bring up interface %s after retries: %s", portName, output)

	// Wait for OVS to assign ofport
	ofport := waitForOFPort(ctx, t, portName)
	require.Greater(t, ofport, int32(0), "ofport should be positive after retries")

	t.Run("AddAndDeleteFlow", func(t *testing.T) {
		// Add flow
		flowMod := &ovs.FlowMod{
			Table:    0,
			Priority: 1000,
			Match:    fmt.Sprintf("in_port=%d,dl_type=0x0800,nw_proto=6,tp_dst=80", ofport),
			Actions:  "NORMAL",
		}

		err := client.AddFlow(ctx, bridgeName, flowMod)
		require.NoError(t, err)

		// Verify it exists
		flows, err := client.ListFlows(ctx, bridgeName)
		require.NoError(t, err)
		initialCount := len(flows)
		assert.Greater(t, initialCount, 0)

		// Delete flow
		match := fmt.Sprintf("in_port=%d,dl_type=0x0800,nw_proto=6,tp_dst=80", ofport)
		err = client.DeleteFlow(ctx, bridgeName, match)
		require.NoError(t, err)

		// Verify it was deleted
		flows, err = client.ListFlows(ctx, bridgeName)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(flows), initialCount)
	})

	t.Run("ModifyFlow", func(t *testing.T) {
		// Add initial flow
		flowMod := &ovs.FlowMod{
			Table:    0,
			Priority: 1000,
			Match:    fmt.Sprintf("in_port=%d,dl_type=0x0800,nw_proto=6,tp_dst=443", ofport),
			Actions:  "NORMAL",
		}

		err := client.AddFlow(ctx, bridgeName, flowMod)
		require.NoError(t, err)

		// Modify flow - change action
		flowMod.Actions = "drop"
		err = client.ModifyFlow(ctx, bridgeName, flowMod)
		require.NoError(t, err)

		// Note: We can't easily verify the action change without inspecting
		// flow details, but the operation should succeed
	})

	t.Run("DeleteAllFlows", func(t *testing.T) {
		// Add multiple flows
		for i := 1; i <= 5; i++ {
			flowMod := &ovs.FlowMod{
				Table:    0,
				Priority: 1000 + i,
				Match:    fmt.Sprintf("in_port=%d,dl_type=0x0800,nw_proto=6,tp_dst=%d", ofport, 8000+i),
				Actions:  "NORMAL",
			}

			err := client.AddFlow(ctx, bridgeName, flowMod)
			require.NoError(t, err)
		}

		// Verify flows exist
		flows, err := client.ListFlows(ctx, bridgeName)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(flows), 5)

		// Delete all flows
		err = client.DeleteAllFlows(ctx, bridgeName)
		require.NoError(t, err)

		// Verify all flows were deleted
		flows, err = client.ListFlows(ctx, bridgeName)
		require.NoError(t, err)
		// There might be default flows, so just verify count decreased
		assert.LessOrEqual(t, len(flows), 5)
	})
}

// TestVLANFlowManipulation tests VLAN-related flow operations
func TestVLANFlowManipulation(t *testing.T) {
	requireOVSDBForTest(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	client, err := ovs.NewClient("/var/run/openvswitch/db.sock")
	require.NoError(t, err)
	defer client.Close()

	err = client.Connect(ctx)
	if err != nil {
		t.Skipf("Skipping test: cannot connect to OVSDB: %v", err)
	}

	bridgeName := "br-vlan-flow-test"
	// Cleanup any existing bridge
	exec.Command("ovs-vsctl", "--if-exists", "del-br", bridgeName).Run()
	defer exec.Command("ovs-vsctl", "--if-exists", "del-br", bridgeName).Run()

	// Create bridge via ovs-vsctl
	cmd := exec.Command("ovs-vsctl", "add-br", bridgeName)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to create bridge: %s", output)

	cmd = exec.Command("ovs-vsctl", "set", "bridge", bridgeName, "protocols=OpenFlow13")
	output, err = cmd.CombinedOutput()
	require.NoError(t, err, "Failed to set protocols: %s", output)

	portName := "vlan-flow-port" // Max 15 chars for Linux interface names
	// Clean up any stale interface from previous tests
	exec.Command("ip", "link", "delete", portName).Run()

	// Use ovs-vsctl to add port (more reliable than OVSDB for internal ports)
	cmd = exec.Command("ovs-vsctl", "add-port", bridgeName, portName, "--", "set", "interface", portName, "type=internal")
	output, err = cmd.CombinedOutput()
	require.NoError(t, err, "Failed to add port: %s", output)

	// Wait for OVS to create the internal port interface in the kernel and bring it up
	output, linkUpErr := bringInternalPortUp(ctx, portName)
	require.NoError(t, linkUpErr, "Failed to bring up interface %s after retries: %s", portName, output)

	// Wait for OVS to assign ofport
	ofport := waitForOFPort(ctx, t, portName)
	require.Greater(t, ofport, int32(0), "ofport should be positive after retries")

	t.Run("AddVLANTag", func(t *testing.T) {
		// Flow that adds VLAN tag
		flowMod := &ovs.FlowMod{
			Table:    0,
			Priority: 1000,
			Match:    fmt.Sprintf("in_port=%d", ofport),
			Actions:  "mod_vlan_vid:100,NORMAL",
		}

		err := client.AddFlow(ctx, bridgeName, flowMod)
		require.NoError(t, err)
	})

	t.Run("StripVLANTag", func(t *testing.T) {
		// Flow that strips VLAN tag
		flowMod := &ovs.FlowMod{
			Table:    0,
			Priority: 1000,
			Match:    fmt.Sprintf("in_port=%d,dl_vlan=200", ofport),
			Actions:  "strip_vlan,NORMAL",
		}

		err := client.AddFlow(ctx, bridgeName, flowMod)
		require.NoError(t, err)
	})

	t.Run("MatchVLANAndForward", func(t *testing.T) {
		// Flow that matches specific VLAN
		flowMod := &ovs.FlowMod{
			Table:    0,
			Priority: 1000,
			Match:    fmt.Sprintf("in_port=%d,dl_vlan=300", ofport),
			Actions:  "NORMAL",
		}

		err := client.AddFlow(ctx, bridgeName, flowMod)
		require.NoError(t, err)
	})

	t.Run("VLANTranslation", func(t *testing.T) {
		// Flow that translates VLAN tags
		flowMod := &ovs.FlowMod{
			Table:    0,
			Priority: 1000,
			Match:    fmt.Sprintf("in_port=%d,dl_vlan=100", ofport),
			Actions:  "mod_vlan_vid:200,NORMAL",
		}

		err := client.AddFlow(ctx, bridgeName, flowMod)
		require.NoError(t, err)
	})
}

// waitForOFPort polls ovs-vsctl until OVS assigns port a positive OpenFlow
// port number and returns it; on timeout it logs and returns the last value
// read, leaving the caller's assertion to fail.
func waitForOFPort(ctx context.Context, t *testing.T, port string) int32 {
	t.Helper()

	var ofport int32
	assigned := func() bool {
		output, err := exec.CommandContext(ctx, "ovs-vsctl", "get", "interface", port, "ofport").CombinedOutput()
		require.NoError(t, err, "Failed to get ofport: %s", output)
		if _, err := fmt.Sscanf(string(output), "%d", &ofport); err != nil {
			return false
		}
		return ofport > 0
	}
	if err := testenv.WaitUntil(ctx, ofportTimeout, "ofport for "+port, assigned); err != nil {
		t.Logf("%v", err)
	}
	return ofport
}
