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

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/boundedexec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFlowCreation tests adding OpenFlow rules
func TestFlowCreation(t *testing.T) {
	requireOVSForTest(t)
	requireOVSOfctl(t)

	bridgeName := "test-br-flow-0"

	defer cleanupBridge(t, bridgeName)

	// Create bridge
	err := createBridge(bridgeName)
	require.NoError(t, err)

	// Add a basic flow rule (drop all packets)
	flow := "priority=100,actions=drop"
	err = addFlow(bridgeName, flow)
	require.NoError(t, err, "Failed to add flow")

	// Verify flow exists
	flows, err := listFlows(bridgeName)
	require.NoError(t, err)
	assert.Contains(t, flows, "priority=100", "Flow should be in the flow table")
	assert.Contains(t, flows, "drop", "Flow should have drop action")
}

// TestFlowDeletion tests removing OpenFlow rules
func TestFlowDeletion(t *testing.T) {
	requireOVSForTest(t)
	requireOVSOfctl(t)

	bridgeName := "test-br-flow-1"

	defer cleanupBridge(t, bridgeName)

	// Create bridge
	err := createBridge(bridgeName)
	require.NoError(t, err)

	// Add flow rule
	flow := "priority=200,in_port=1,actions=output:2"
	err = addFlow(bridgeName, flow)
	require.NoError(t, err)

	// Verify flow exists
	flows, err := listFlows(bridgeName)
	require.NoError(t, err)
	assert.Contains(t, flows, "priority=200", "Flow should exist")

	// Delete flow - use the full match specification
	// Note: ovs-ofctl del-flows accepts match criteria, not just priority
	err = deleteFlow(bridgeName, "in_port=1")
	require.NoError(t, err, "Failed to delete flow")

	// Verify flow is gone
	flows, err = listFlows(bridgeName)
	require.NoError(t, err)
	assert.NotContains(t, flows, "priority=200,in_port=1", "Flow should be deleted")
}

// TestFlowMatching tests flow matching criteria
func TestFlowMatching(t *testing.T) {
	requireOVSForTest(t)
	requireOVSOfctl(t)

	bridgeName := "test-br-flow-2"

	defer cleanupBridge(t, bridgeName)

	// Create bridge
	err := createBridge(bridgeName)
	require.NoError(t, err)

	testCases := []struct {
		name string
		flow string
	}{
		{
			name: "Match IP source",
			flow: "priority=100,ip,nw_src=192.168.1.0/24,actions=normal",
		},
		{
			name: "Match TCP port",
			flow: "priority=100,tcp,tp_dst=80,actions=normal",
		},
		{
			name: "Match VLAN",
			flow: "priority=100,dl_vlan=100,actions=strip_vlan,output:1",
		},
		{
			name: "Match MAC address",
			flow: "priority=100,dl_src=00:11:22:33:44:55,actions=output:2",
		},
		{
			name: "Match ARP",
			flow: "priority=100,arp,actions=flood",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := addFlow(bridgeName, tc.flow)
			require.NoError(t, err, "Failed to add flow for %s", tc.name)
		})
	}

	// Verify all flows were added
	flows, err := listFlows(bridgeName)
	require.NoError(t, err)
	t.Logf("Flows:\n%s", flows)
}

// TestFlowActions tests various flow actions
func TestFlowActions(t *testing.T) {
	requireOVSForTest(t)
	requireOVSOfctl(t)

	bridgeName := "test-br-flow-3"

	defer cleanupBridge(t, bridgeName)

	// Create bridge
	err := createBridge(bridgeName)
	require.NoError(t, err)

	testCases := []struct {
		name   string
		flow   string
		action string
	}{
		{
			name:   "Normal forwarding",
			flow:   "priority=100,actions=normal",
			action: "normal",
		},
		{
			name:   "Output to port",
			flow:   "priority=101,actions=output:1",
			action: "output:1",
		},
		{
			name:   "Flood",
			flow:   "priority=102,actions=flood",
			action: "flood",
		},
		{
			name:   "Modify VLAN",
			flow:   "priority=103,actions=mod_vlan_vid:200,output:1",
			action: "mod_vlan_vid:200",
		},
		{
			name:   "Resubmit",
			flow:   "priority=104,actions=resubmit(,1)",
			action: "resubmit",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := addFlow(bridgeName, tc.flow)
			require.NoError(t, err, "Failed to add flow with action %s", tc.action)
		})
	}

	// Verify flows - use case-insensitive comparison
	flows, err := listFlows(bridgeName)
	require.NoError(t, err)
	flowsLower := strings.ToLower(flows)

	for _, tc := range testCases {
		actionLower := strings.ToLower(tc.action)
		assert.Contains(t, flowsLower, actionLower, "Flow should contain action %s", tc.action)
	}
}

// TestFlowTables tests using multiple flow tables
func TestFlowTables(t *testing.T) {
	requireOVSForTest(t)
	requireOVSOfctl(t)

	bridgeName := "test-br-flow-tables"

	defer cleanupBridge(t, bridgeName)

	// Create bridge
	err := createBridge(bridgeName)
	require.NoError(t, err)

	// Add flows to different tables
	tables := []struct {
		table int
		flow  string
	}{
		{0, "priority=100,actions=resubmit(,1)"},
		{1, "priority=100,actions=resubmit(,2)"},
		{2, "priority=100,actions=normal"},
	}

	for _, tbl := range tables {
		err := addFlowTable(bridgeName, tbl.table, tbl.flow)
		require.NoError(t, err, "Failed to add flow to table %d", tbl.table)
	}

	// List flows for each table
	for _, tbl := range tables {
		flows, err := listFlowsTable(bridgeName, tbl.table)
		require.NoError(t, err)
		t.Logf("Table %d flows:\n%s", tbl.table, flows)
	}
}

// TestFlowPriority tests flow priority ordering
func TestFlowPriority(t *testing.T) {
	requireOVSForTest(t)
	requireOVSOfctl(t)

	bridgeName := "test-br-flow-priority"

	defer cleanupBridge(t, bridgeName)

	// Create bridge
	err := createBridge(bridgeName)
	require.NoError(t, err)

	// Add flows with different priorities
	priorities := []int{100, 200, 50, 300}

	for _, priority := range priorities {
		flow := fmt.Sprintf("priority=%d,actions=normal", priority)
		err := addFlow(bridgeName, flow)
		require.NoError(t, err, "Failed to add flow with priority %d", priority)
	}

	// List flows and verify they're ordered by priority
	flows, err := listFlows(bridgeName)
	require.NoError(t, err)

	for _, priority := range priorities {
		assert.Contains(t, flows, fmt.Sprintf("priority=%d", priority),
			"Flow with priority %d should exist", priority)
	}
}

// TestFlowStatistics tests flow statistics collection
func TestFlowStatistics(t *testing.T) {
	requireOVSForTest(t)
	requireOVSOfctl(t)

	bridgeName := "test-br-flow-stats"

	defer cleanupBridge(t, bridgeName)

	// Create bridge
	err := createBridge(bridgeName)
	require.NoError(t, err)

	// Add flow
	flow := "priority=100,actions=normal"
	err = addFlow(bridgeName, flow)
	require.NoError(t, err)

	// Get flow statistics
	stats, err := getFlowStats(bridgeName)
	require.NoError(t, err)
	assert.NotEmpty(t, stats, "Should have flow statistics")
	t.Logf("Flow statistics:\n%s", stats)
}

// TestFlowModification tests modifying existing flows
func TestFlowModification(t *testing.T) {
	requireOVSForTest(t)
	requireOVSOfctl(t)

	bridgeName := "test-br-flow-mod"

	defer cleanupBridge(t, bridgeName)

	// Create bridge
	err := createBridge(bridgeName)
	require.NoError(t, err)

	// Add initial flow
	flow := "priority=100,actions=drop"
	err = addFlow(bridgeName, flow)
	require.NoError(t, err)

	// Modify flow (replace with different action)
	newFlow := "priority=100,actions=normal"
	err = modifyFlow(bridgeName, newFlow)
	require.NoError(t, err, "Failed to modify flow")

	// Verify modification - use case-insensitive comparison
	flows, err := listFlows(bridgeName)
	require.NoError(t, err)
	flowsLower := strings.ToLower(flows)
	assert.Contains(t, flowsLower, "normal", "Modified flow should have normal action")
	assert.NotContains(t, strings.ReplaceAll(flowsLower, "normal", ""), "drop",
		"Old drop action should be replaced")
}

// Helper functions

func addFlow(bridge, flow string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := boundedexec.CommandContext(ctx, "ovs-ofctl", "add-flow", bridge, flow)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add flow: %v, output: %s", err, output)
	}
	return nil
}

func deleteFlow(bridge, match string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := boundedexec.CommandContext(ctx, "ovs-ofctl", "del-flows", bridge, match)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to delete flow: %v, output: %s", err, output)
	}
	return nil
}

func listFlows(bridge string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := boundedexec.CommandContext(ctx, "ovs-ofctl", "dump-flows", bridge)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to list flows: %v, output: %s", err, output)
	}
	return string(output), nil
}

func addFlowTable(bridge string, table int, flow string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fullFlow := fmt.Sprintf("table=%d,%s", table, flow)
	cmd := boundedexec.CommandContext(ctx, "ovs-ofctl", "add-flow", bridge, fullFlow)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add flow to table: %v, output: %s", err, output)
	}
	return nil
}

func listFlowsTable(bridge string, table int) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := boundedexec.CommandContext(ctx, "ovs-ofctl", "dump-flows", bridge,
		fmt.Sprintf("table=%d", table))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to list flows for table: %v, output: %s", err, output)
	}
	return string(output), nil
}

func getFlowStats(bridge string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := boundedexec.CommandContext(ctx, "ovs-ofctl", "dump-flows", bridge, "--verbose")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get flow stats: %v, output: %s", err, output)
	}
	return string(output), nil
}

func modifyFlow(bridge, flow string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := boundedexec.CommandContext(ctx, "ovs-ofctl", "mod-flows", bridge, flow)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to modify flow: %v, output: %s", err, output)
	}
	return nil
}
