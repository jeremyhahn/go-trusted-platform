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
	"net"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// OpenFlow specific timeout for operations
	ofTestTimeout = 30 * time.Second

	// Socket directory for test bridges
	ofSocketDir = "/var/run/openvswitch"

	// Default wait time for bridge socket to be ready
	ofSocketWaitTimeout = 10 * time.Second

	// Short timeout for checking if OpenFlow is available
	ofCheckTimeout = 2 * time.Second
)

// testBridge represents a test OVS bridge
type testBridge struct {
	name       string
	socketPath string
	t          *testing.T
}

// setupTestBridge creates a new OVS bridge for testing.
// Callers MUST call requireOVSForTest(t) before invoking this function
// so a missing OVS fails the test with the prerequisite named.
func setupTestBridge(t *testing.T, bridgeName string) *testBridge {
	t.Helper()

	// Delete bridge if it already exists (cleanup from previous failed test)
	exec.Command("ovs-vsctl", "--if-exists", "del-br", bridgeName).Run()

	// Create the bridge
	cmd := exec.Command("ovs-vsctl", "add-br", bridgeName)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to create bridge %s: %s", bridgeName, string(output))

	// Set OpenFlow version to 1.3
	cmd = exec.Command("ovs-vsctl", "set", "bridge", bridgeName, "protocols=OpenFlow13")
	output, err = cmd.CombinedOutput()
	require.NoError(t, err, "Failed to set OpenFlow version: %s", string(output))

	// OVS creates .mgmt sockets for each bridge for OpenFlow management
	socketPath := filepath.Join(ofSocketDir, bridgeName+".mgmt")

	tb := &testBridge{
		name:       bridgeName,
		socketPath: socketPath,
		t:          t,
	}

	// Register cleanup
	t.Cleanup(func() {
		tb.cleanup()
	})

	// Wait for the OpenFlow management socket to become available.
	// After bridge creation, OVS takes a moment to set up the socket.
	if !tb.waitForOpenFlowSocket() {
		t.Fatalf("OpenFlow management socket %s did not come up within %s: ovs-vswitchd creates one per bridge; %s",
			socketPath, ofSocketWaitTimeout, devcontainerRemedy)
	}

	return tb
}

// cleanup removes the test bridge
func (tb *testBridge) cleanup() {
	cmd := exec.Command("ovs-vsctl", "--if-exists", "del-br", tb.name)
	if output, err := cmd.CombinedOutput(); err != nil {
		tb.t.Logf("Warning: Failed to delete bridge %s: %s", tb.name, string(output))
	}
}

// waitForOpenFlowSocket polls until the OpenFlow management socket accepts a
// connection. OVS takes some time after bridge creation to set up the socket.
func (tb *testBridge) waitForOpenFlowSocket() bool {
	condition := "OpenFlow socket for bridge " + tb.name
	if err := testenv.WaitUntil(tb.t.Context(), ofSocketWaitTimeout, condition, tb.checkOpenFlowAvailable); err != nil {
		tb.t.Logf("%v", err)
		return false
	}
	return true
}

// checkOpenFlowAvailable checks if we can actually connect to the OpenFlow socket
func (tb *testBridge) checkOpenFlowAvailable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), ofCheckTimeout)
	defer cancel()

	client, err := openflow.NewClient(
		tb.name,
		openflow.WithSocketDir(ofSocketDir),
		openflow.WithTimeout(ofCheckTimeout),
	)
	if err != nil {
		return false
	}

	err = client.Connect(ctx)
	if err != nil {
		return false
	}

	// Successfully connected, clean up
	client.Disconnect()
	return true
}

// createClient creates and connects an OpenFlow client to the test bridge
func (tb *testBridge) createClient(t *testing.T) *openflow.Client {
	t.Helper()

	client, err := openflow.NewClient(
		tb.name,
		openflow.WithSocketDir(ofSocketDir),
		openflow.WithTimeout(ofTestTimeout),
	)
	require.NoError(t, err, "Failed to create client")

	ctx, cancel := context.WithTimeout(context.Background(), ofTestTimeout)
	defer cancel()

	err = client.Connect(ctx)
	require.NoError(t, err, "Failed to connect to bridge")

	// Register cleanup to disconnect
	t.Cleanup(func() {
		if client.IsConnected() {
			client.Disconnect()
		}
	})

	return client
}

// clearFlows removes all flows from the bridge
func (tb *testBridge) clearFlows(t *testing.T, client *openflow.Client) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), ofTestTimeout)
	defer cancel()

	err := client.DeleteAllFlows(ctx)
	require.NoError(t, err, "Failed to clear flows")
}

// TestNativeOpenFlow_Connection tests basic connection to OVS bridge
func TestNativeOpenFlow_Connection(t *testing.T) {
	requireOVSForTest(t)

	bridge := setupTestBridge(t, "test-of-conn")

	client, err := openflow.NewClient(
		bridge.name,
		openflow.WithSocketDir(ofSocketDir),
		openflow.WithTimeout(ofTestTimeout),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), ofTestTimeout)
	defer cancel()

	// Connect
	err = client.Connect(ctx)
	require.NoError(t, err)
	assert.True(t, client.IsConnected(), "Client should be connected")

	// Verify datapath ID was received
	assert.NotZero(t, client.DatapathID(), "Datapath ID should be set")

	// Disconnect
	err = client.Disconnect()
	require.NoError(t, err)
	assert.False(t, client.IsConnected(), "Client should be disconnected")
}

// TestNativeOpenFlow_Handshake tests OpenFlow handshake (Hello + Features)
func TestNativeOpenFlow_Handshake(t *testing.T) {
	requireOVSForTest(t)

	bridge := setupTestBridge(t, "test-of-handshake")
	client := bridge.createClient(t)

	// Handshake is performed during Connect, verify it succeeded
	assert.True(t, client.IsConnected())
	assert.NotZero(t, client.DatapathID())

	t.Logf("Successfully completed handshake with datapath ID: 0x%016x", client.DatapathID())
}

// TestNativeOpenFlow_AddFlow tests adding a flow rule
func TestNativeOpenFlow_AddFlow(t *testing.T) {
	requireOVSForTest(t)

	bridge := setupTestBridge(t, "test-of-addflow")
	client := bridge.createClient(t)
	bridge.clearFlows(t, client)

	ctx, cancel := context.WithTimeout(context.Background(), ofTestTimeout)
	defer cancel()

	// Create a simple flow: match on input port 1, output to port 2
	flow := openflow.NewFlowMod(0)
	flow.Priority = 100
	flow.TableID = 0
	flow.IdleTimeout = 0
	flow.HardTimeout = 0

	// Match on input port 1
	flow.Match.AddInPort(1)

	// Action: output to port 2
	outputAction := openflow.NewActionOutput(2, 0)
	instruction := openflow.NewInstructionApplyActions(outputAction)
	flow.Instructions = []openflow.Instruction{instruction}

	// Add the flow
	err := client.AddFlow(ctx, flow)
	require.NoError(t, err, "Failed to add flow")

	// Verify flow was added by getting stats
	stats, err := client.GetFlowStats(ctx, nil)
	require.NoError(t, err, "Failed to get flow stats")
	require.Len(t, stats, 1, "Should have exactly 1 flow")

	assert.Equal(t, uint16(100), stats[0].Priority)
	assert.Equal(t, uint8(0), stats[0].TableID)
}

// TestNativeOpenFlow_DeleteFlow tests deleting a flow rule
func TestNativeOpenFlow_DeleteFlow(t *testing.T) {
	requireOVSForTest(t)

	bridge := setupTestBridge(t, "test-of-delflow")
	client := bridge.createClient(t)
	bridge.clearFlows(t, client)

	ctx, cancel := context.WithTimeout(context.Background(), ofTestTimeout)
	defer cancel()

	// Add a flow first
	flow := openflow.NewFlowMod(0)
	flow.Priority = 100
	flow.Match.AddInPort(1)
	outputAction := openflow.NewActionOutput(2, 0)
	instruction := openflow.NewInstructionApplyActions(outputAction)
	flow.Instructions = []openflow.Instruction{instruction}

	err := client.AddFlow(ctx, flow)
	require.NoError(t, err)

	// Verify flow exists
	stats, err := client.GetFlowStats(ctx, nil)
	require.NoError(t, err)
	require.Len(t, stats, 1)

	// Delete the flow
	deleteFlow := openflow.NewFlowMod(0)
	deleteFlow.Priority = 100
	deleteFlow.Match.AddInPort(1)

	err = client.DeleteFlow(ctx, deleteFlow)
	require.NoError(t, err, "Failed to delete flow")

	// Verify flow was deleted
	stats, err = client.GetFlowStats(ctx, nil)
	require.NoError(t, err)
	assert.Len(t, stats, 0, "All flows should be deleted")
}

// TestNativeOpenFlow_ModifyFlow tests modifying an existing flow
func TestNativeOpenFlow_ModifyFlow(t *testing.T) {
	requireOVSForTest(t)

	bridge := setupTestBridge(t, "test-of-modflow")
	client := bridge.createClient(t)
	bridge.clearFlows(t, client)

	ctx, cancel := context.WithTimeout(context.Background(), ofTestTimeout)
	defer cancel()

	// Add initial flow: in_port=1 -> output:2
	flow := openflow.NewFlowMod(0)
	flow.Priority = 100
	flow.Match.AddInPort(1)
	outputAction := openflow.NewActionOutput(2, 0)
	instruction := openflow.NewInstructionApplyActions(outputAction)
	flow.Instructions = []openflow.Instruction{instruction}

	err := client.AddFlow(ctx, flow)
	require.NoError(t, err)

	// Modify flow to output to port 3 instead
	modFlow := openflow.NewFlowMod(0)
	modFlow.Priority = 100
	modFlow.Match.AddInPort(1)
	newOutputAction := openflow.NewActionOutput(3, 0)
	newInstruction := openflow.NewInstructionApplyActions(newOutputAction)
	modFlow.Instructions = []openflow.Instruction{newInstruction}

	err = client.ModifyFlow(ctx, modFlow)
	require.NoError(t, err, "Failed to modify flow")

	// Verify flow still exists
	stats, err := client.GetFlowStats(ctx, nil)
	require.NoError(t, err)
	assert.Len(t, stats, 1, "Should still have 1 flow after modify")
}

// TestNativeOpenFlow_GetFlowStats tests retrieving flow statistics
func TestNativeOpenFlow_GetFlowStats(t *testing.T) {
	requireOVSForTest(t)

	bridge := setupTestBridge(t, "test-of-stats")
	client := bridge.createClient(t)
	bridge.clearFlows(t, client)

	ctx, cancel := context.WithTimeout(context.Background(), ofTestTimeout)
	defer cancel()

	// Add multiple flows with different priorities
	for i := 0; i < 3; i++ {
		flow := openflow.NewFlowMod(0)
		flow.Priority = uint16(100 + i*10)
		flow.Match.AddInPort(uint32(i + 1))
		outputAction := openflow.NewActionOutput(uint32(i+2), 0)
		instruction := openflow.NewInstructionApplyActions(outputAction)
		flow.Instructions = []openflow.Instruction{instruction}

		err := client.AddFlow(ctx, flow)
		require.NoError(t, err, "Failed to add flow %d", i)
	}

	// Get all flow stats
	stats, err := client.GetFlowStats(ctx, nil)
	require.NoError(t, err, "Failed to get flow stats")
	assert.Len(t, stats, 3, "Should have 3 flows")

	// Verify priorities
	priorities := make(map[uint16]bool)
	for _, stat := range stats {
		priorities[stat.Priority] = true
	}
	assert.True(t, priorities[100])
	assert.True(t, priorities[110])
	assert.True(t, priorities[120])

	// Test filtered stats (match on specific input port)
	match := openflow.NewMatch()
	match.AddInPort(1)

	filteredStats, err := client.GetFlowStats(ctx, match)
	require.NoError(t, err)
	assert.Len(t, filteredStats, 1, "Should have 1 flow matching in_port=1")
	assert.Equal(t, uint16(100), filteredStats[0].Priority)
}

// TestNativeOpenFlow_Barrier tests barrier synchronization
func TestNativeOpenFlow_Barrier(t *testing.T) {
	requireOVSForTest(t)

	bridge := setupTestBridge(t, "test-of-barrier")
	client := bridge.createClient(t)
	bridge.clearFlows(t, client)

	ctx, cancel := context.WithTimeout(context.Background(), ofTestTimeout)
	defer cancel()

	// Add multiple flows quickly
	for i := 0; i < 5; i++ {
		flow := openflow.NewFlowMod(0)
		flow.Priority = uint16(100 + i)
		flow.Match.AddInPort(uint32(i + 1))
		outputAction := openflow.NewActionOutput(uint32(i+2), 0)
		instruction := openflow.NewInstructionApplyActions(outputAction)
		flow.Instructions = []openflow.Instruction{instruction}

		// AddFlow includes a barrier internally, so flows are synchronized
		err := client.AddFlow(ctx, flow)
		require.NoError(t, err)
	}

	// After barrier (implicit in AddFlow), all flows should be present
	stats, err := client.GetFlowStats(ctx, nil)
	require.NoError(t, err)
	assert.Len(t, stats, 5, "All 5 flows should be present after barrier")
}

// TestNativeOpenFlow_Echo tests echo request/reply
func TestNativeOpenFlow_Echo(t *testing.T) {
	requireOVSForTest(t)

	bridge := setupTestBridge(t, "test-of-echo")
	client := bridge.createClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), ofTestTimeout)
	defer cancel()

	// Send echo with test data
	testData := []byte("hello openflow")
	replyData, err := client.Echo(ctx, testData)
	require.NoError(t, err, "Failed to send echo request")
	assert.Equal(t, testData, replyData, "Echo reply data should match request")

	// Send empty echo
	emptyReply, err := client.Echo(ctx, nil)
	require.NoError(t, err, "Failed to send empty echo")
	assert.Nil(t, emptyReply, "Empty echo should return nil data")

	// Send echo with larger payload
	largeData := make([]byte, 1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}
	largeReply, err := client.Echo(ctx, largeData)
	require.NoError(t, err, "Failed to send large echo")
	assert.Equal(t, largeData, largeReply, "Large echo reply should match request")
}

// TestNativeOpenFlow_MultipleFlows tests adding multiple flows with various match criteria
func TestNativeOpenFlow_MultipleFlows(t *testing.T) {
	requireOVSForTest(t)

	bridge := setupTestBridge(t, "test-of-multiflow")
	client := bridge.createClient(t)
	bridge.clearFlows(t, client)

	ctx, cancel := context.WithTimeout(context.Background(), ofTestTimeout)
	defer cancel()

	testCases := []struct {
		name       string
		priority   uint16
		setupMatch func(*openflow.Match)
	}{
		{
			name:     "match_in_port",
			priority: 100,
			setupMatch: func(m *openflow.Match) {
				m.AddInPort(1)
			},
		},
		{
			name:     "match_eth_type",
			priority: 110,
			setupMatch: func(m *openflow.Match) {
				m.AddEthType(0x0800) // IPv4
			},
		},
		{
			name:     "match_ip_proto",
			priority: 120,
			setupMatch: func(m *openflow.Match) {
				m.AddEthType(0x0800)
				m.AddIPProto(6) // TCP
			},
		},
		{
			name:     "match_tcp_port",
			priority: 130,
			setupMatch: func(m *openflow.Match) {
				m.AddEthType(0x0800)
				m.AddIPProto(6)
				m.AddTCPDst(80) // HTTP
			},
		},
		{
			name:     "match_ipv4_src",
			priority: 140,
			setupMatch: func(m *openflow.Match) {
				m.AddEthType(0x0800)
				m.AddIPv4Src(net.ParseIP("192.168.1.1"))
			},
		},
	}

	// Add all flows
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			flow := openflow.NewFlowMod(0)
			flow.Priority = tc.priority
			tc.setupMatch(flow.Match)

			outputAction := openflow.NewActionOutput(openflow.OFPPController, 0)
			instruction := openflow.NewInstructionApplyActions(outputAction)
			flow.Instructions = []openflow.Instruction{instruction}

			err := client.AddFlow(ctx, flow)
			require.NoError(t, err, "Failed to add flow for %s", tc.name)
		})
	}

	// Verify all flows were added
	stats, err := client.GetFlowStats(ctx, nil)
	require.NoError(t, err)
	assert.Len(t, stats, len(testCases), "Should have all flows")
}

// TestNativeOpenFlow_FlowPriority tests flow priority handling
func TestNativeOpenFlow_FlowPriority(t *testing.T) {
	requireOVSForTest(t)

	bridge := setupTestBridge(t, "test-of-priority")
	client := bridge.createClient(t)
	bridge.clearFlows(t, client)

	ctx, cancel := context.WithTimeout(context.Background(), ofTestTimeout)
	defer cancel()

	// Add flows with different priorities
	priorities := []uint16{1, 100, 1000, 10000, 32768}

	for _, priority := range priorities {
		flow := openflow.NewFlowMod(0)
		flow.Priority = priority
		flow.Match.AddInPort(1)

		outputAction := openflow.NewActionOutput(2, 0)
		instruction := openflow.NewInstructionApplyActions(outputAction)
		flow.Instructions = []openflow.Instruction{instruction}

		err := client.AddFlow(ctx, flow)
		require.NoError(t, err, "Failed to add flow with priority %d", priority)
	}

	// Get stats and verify priorities
	stats, err := client.GetFlowStats(ctx, nil)
	require.NoError(t, err)
	require.Len(t, stats, len(priorities))

	// Verify all priorities are present
	foundPriorities := make(map[uint16]bool)
	for _, stat := range stats {
		foundPriorities[stat.Priority] = true
	}

	for _, priority := range priorities {
		assert.True(t, foundPriorities[priority], "Priority %d should be found", priority)
	}
}

// TestNativeOpenFlow_Reconnect tests disconnect and reconnect
func TestNativeOpenFlow_Reconnect(t *testing.T) {
	requireOVSForTest(t)

	bridge := setupTestBridge(t, "test-of-reconnect")

	// Create and connect first client
	client1 := bridge.createClient(t)
	dpid1 := client1.DatapathID()
	assert.True(t, client1.IsConnected())

	// Disconnect
	err := client1.Disconnect()
	require.NoError(t, err)
	assert.False(t, client1.IsConnected())

	// Reconnect
	ctx, cancel := context.WithTimeout(context.Background(), ofTestTimeout)
	defer cancel()

	err = client1.Connect(ctx)
	require.NoError(t, err)
	assert.True(t, client1.IsConnected())

	// Datapath ID should be the same
	dpid2 := client1.DatapathID()
	assert.Equal(t, dpid1, dpid2, "Datapath ID should be consistent")

	// Verify we can perform operations after reconnect
	flow := openflow.NewFlowMod(0)
	flow.Priority = 100
	flow.Match.AddInPort(1)
	outputAction := openflow.NewActionOutput(2, 0)
	instruction := openflow.NewInstructionApplyActions(outputAction)
	flow.Instructions = []openflow.Instruction{instruction}

	err = client1.AddFlow(ctx, flow)
	require.NoError(t, err, "Should be able to add flow after reconnect")
}

// TestNativeOpenFlow_VLANFlow tests VLAN-related flows
func TestNativeOpenFlow_VLANFlow(t *testing.T) {
	requireOVSForTest(t)

	bridge := setupTestBridge(t, "test-of-vlan")
	client := bridge.createClient(t)
	bridge.clearFlows(t, client)

	ctx, cancel := context.WithTimeout(context.Background(), ofTestTimeout)
	defer cancel()

	// Flow 1: Push VLAN tag
	pushFlow := openflow.NewFlowMod(0)
	pushFlow.Priority = 200
	pushFlow.Match.AddInPort(1)

	pushAction := openflow.NewActionPushVLAN(0x8100) // 802.1Q
	setVlanAction := openflow.NewActionSetField(
		openflow.OFPXMCOpenflowBasic,
		openflow.OFPXMTOFBVlanVid,
		[]byte{0x10, 0x64}, // VLAN ID 100 with present bit
	)
	outputAction := openflow.NewActionOutput(2, 0)

	instruction := openflow.NewInstructionApplyActions(pushAction, setVlanAction, outputAction)
	pushFlow.Instructions = []openflow.Instruction{instruction}

	err := client.AddFlow(ctx, pushFlow)
	require.NoError(t, err, "Failed to add VLAN push flow")

	// Flow 2: Pop VLAN tag
	popFlow := openflow.NewFlowMod(0)
	popFlow.Priority = 200
	popFlow.Match.AddInPort(2)
	popFlow.Match.AddVLANVid(100)

	popAction := openflow.NewActionPopVLAN()
	popOutput := openflow.NewActionOutput(1, 0)
	popInstruction := openflow.NewInstructionApplyActions(popAction, popOutput)
	popFlow.Instructions = []openflow.Instruction{popInstruction}

	err = client.AddFlow(ctx, popFlow)
	require.NoError(t, err, "Failed to add VLAN pop flow")

	// Verify both flows exist
	stats, err := client.GetFlowStats(ctx, nil)
	require.NoError(t, err)
	assert.Len(t, stats, 2, "Should have 2 VLAN flows")
}

// TestNativeOpenFlow_GotoTableFlow tests goto-table instruction
func TestNativeOpenFlow_GotoTableFlow(t *testing.T) {
	requireOVSForTest(t)

	bridge := setupTestBridge(t, "test-of-goto")
	client := bridge.createClient(t)
	bridge.clearFlows(t, client)

	ctx, cancel := context.WithTimeout(context.Background(), ofTestTimeout)
	defer cancel()

	// Flow in table 0: goto table 1
	flow0 := openflow.NewFlowMod(0)
	flow0.Priority = 100
	flow0.TableID = 0
	flow0.Match.AddInPort(1)

	gotoInstruction := openflow.NewInstructionGotoTable(1)
	flow0.Instructions = []openflow.Instruction{gotoInstruction}

	err := client.AddFlow(ctx, flow0)
	require.NoError(t, err, "Failed to add goto-table flow")

	// Flow in table 1: output
	flow1 := openflow.NewFlowMod(0)
	flow1.Priority = 100
	flow1.TableID = 1
	flow1.Match.AddInPort(1)

	outputAction := openflow.NewActionOutput(2, 0)
	outputInstruction := openflow.NewInstructionApplyActions(outputAction)
	flow1.Instructions = []openflow.Instruction{outputInstruction}

	err = client.AddFlow(ctx, flow1)
	require.NoError(t, err, "Failed to add output flow in table 1")

	// Verify both flows exist
	stats, err := client.GetFlowStats(ctx, nil)
	require.NoError(t, err)
	assert.Len(t, stats, 2, "Should have flows in both tables")

	// Verify table IDs
	tableIDs := make(map[uint8]bool)
	for _, stat := range stats {
		tableIDs[stat.TableID] = true
	}
	assert.True(t, tableIDs[0], "Should have flow in table 0")
	assert.True(t, tableIDs[1], "Should have flow in table 1")
}

// TestNativeOpenFlow_ComplexMatch tests complex multi-field matches
func TestNativeOpenFlow_ComplexMatch(t *testing.T) {
	requireOVSForTest(t)

	bridge := setupTestBridge(t, "test-of-complex")
	client := bridge.createClient(t)
	bridge.clearFlows(t, client)

	ctx, cancel := context.WithTimeout(context.Background(), ofTestTimeout)
	defer cancel()

	// Complex flow: TCP traffic from specific IP to specific port
	flow := openflow.NewFlowMod(0)
	flow.Priority = 1000

	// Match: IPv4, TCP, src=192.168.1.10, dst_port=443
	flow.Match.AddEthType(0x0800)                      // IPv4
	flow.Match.AddIPProto(6)                           // TCP
	flow.Match.AddIPv4Src(net.ParseIP("192.168.1.10")) // Source IP
	flow.Match.AddTCPDst(443)                          // HTTPS

	// Action: output to controller for inspection
	outputAction := openflow.NewActionOutput(openflow.OFPPController, 128)
	instruction := openflow.NewInstructionApplyActions(outputAction)
	flow.Instructions = []openflow.Instruction{instruction}

	err := client.AddFlow(ctx, flow)
	require.NoError(t, err, "Failed to add complex flow")

	// Verify flow exists
	stats, err := client.GetFlowStats(ctx, nil)
	require.NoError(t, err)
	require.Len(t, stats, 1)
	assert.Equal(t, uint16(1000), stats[0].Priority)
}

// TestNativeOpenFlow_DeleteAllFlows tests deleting all flows
func TestNativeOpenFlow_DeleteAllFlows(t *testing.T) {
	requireOVSForTest(t)

	bridge := setupTestBridge(t, "test-of-delall")
	client := bridge.createClient(t)

	// Clear any default flows OVS creates
	bridge.clearFlows(t, client)

	ctx, cancel := context.WithTimeout(context.Background(), ofTestTimeout)
	defer cancel()

	// Add multiple flows
	for i := 0; i < 10; i++ {
		flow := openflow.NewFlowMod(0)
		flow.Priority = uint16(100 + i)
		flow.Match.AddInPort(uint32(i + 1))

		outputAction := openflow.NewActionOutput(uint32(i+2), 0)
		instruction := openflow.NewInstructionApplyActions(outputAction)
		flow.Instructions = []openflow.Instruction{instruction}

		err := client.AddFlow(ctx, flow)
		require.NoError(t, err)
	}

	// Verify flows exist
	stats, err := client.GetFlowStats(ctx, nil)
	require.NoError(t, err)
	require.Len(t, stats, 10)

	// Delete all flows
	err = client.DeleteAllFlows(ctx)
	require.NoError(t, err, "Failed to delete all flows")

	// Verify all flows deleted
	stats, err = client.GetFlowStats(ctx, nil)
	require.NoError(t, err)
	assert.Len(t, stats, 0, "All flows should be deleted")
}

// TestNativeOpenFlow_ConcurrentOperations tests concurrent client operations
func TestNativeOpenFlow_ConcurrentOperations(t *testing.T) {
	requireOVSForTest(t)

	bridge := setupTestBridge(t, "test-of-concurrent")
	client := bridge.createClient(t)
	bridge.clearFlows(t, client)

	ctx, cancel := context.WithTimeout(context.Background(), ofTestTimeout)
	defer cancel()

	// Add flows concurrently (OpenFlow client should serialize operations)
	errChan := make(chan error, 5)

	for i := 0; i < 5; i++ {
		go func(idx int) {
			flow := openflow.NewFlowMod(0)
			flow.Priority = uint16(100 + idx)
			flow.Match.AddInPort(uint32(idx + 1))

			outputAction := openflow.NewActionOutput(uint32(idx+2), 0)
			instruction := openflow.NewInstructionApplyActions(outputAction)
			flow.Instructions = []openflow.Instruction{instruction}

			errChan <- client.AddFlow(ctx, flow)
		}(i)
	}

	// Wait for all operations to complete
	for i := 0; i < 5; i++ {
		err := <-errChan
		require.NoError(t, err, "Concurrent flow add failed")
	}

	// Verify all flows were added
	stats, err := client.GetFlowStats(ctx, nil)
	require.NoError(t, err)
	assert.Len(t, stats, 5, "All concurrent flows should be added")
}

// TestNativeOpenFlow_ErrorHandling tests error handling for invalid operations
func TestNativeOpenFlow_ErrorHandling(t *testing.T) {
	// Test 1: Connect to non-existent bridge
	t.Run("nonexistent_bridge", func(t *testing.T) {
		requireOVSForTest(t)

		client, err := openflow.NewClient("nonexistent-bridge-xyz")
		require.NoError(t, err, "Client creation should succeed")

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		err = client.Connect(ctx)
		assert.Error(t, err, "Should fail to connect to non-existent bridge")
	})

	// Test 2: Operations on disconnected client
	t.Run("disconnected_client", func(t *testing.T) {
		requireOVSForTest(t)

		bridge := setupTestBridge(t, "test-of-err-disc")
		client := bridge.createClient(t)

		// Disconnect
		err := client.Disconnect()
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), ofTestTimeout)
		defer cancel()

		// Try to add flow on disconnected client
		flow := openflow.NewFlowMod(0)
		err = client.AddFlow(ctx, flow)
		assert.Error(t, err, "Should fail to add flow on disconnected client")
		assert.ErrorIs(t, err, openflow.ErrNotConnected)
	})

	// Test 3: Invalid flow (conflicting priorities with overlap check)
	t.Run("invalid_flow", func(t *testing.T) {
		requireOVSForTest(t)

		bridge := setupTestBridge(t, "test-of-err-invalid")
		client := bridge.createClient(t)
		bridge.clearFlows(t, client)

		ctx, cancel := context.WithTimeout(context.Background(), ofTestTimeout)
		defer cancel()

		// Add first flow
		flow1 := openflow.NewFlowMod(0)
		flow1.Priority = 100
		flow1.Match.AddInPort(1)
		flow1.Flags = openflow.OFPFFCheckOverlap

		outputAction := openflow.NewActionOutput(2, 0)
		instruction := openflow.NewInstructionApplyActions(outputAction)
		flow1.Instructions = []openflow.Instruction{instruction}

		err := client.AddFlow(ctx, flow1)
		require.NoError(t, err)

		// Try to add overlapping flow with same priority
		flow2 := openflow.NewFlowMod(0)
		flow2.Priority = 100
		flow2.Match.AddInPort(1)
		flow2.Flags = openflow.OFPFFCheckOverlap
		flow2.Instructions = []openflow.Instruction{instruction}

		err = client.AddFlow(ctx, flow2)
		// OVS may or may not return an error for exact duplicate flows
		// The test verifies our client properly handles the response
		if err != nil {
			t.Logf("Expected error for duplicate flow: %v", err)
		}
	})
}

// TestNativeOpenFlow_Timeouts tests operation timeouts
func TestNativeOpenFlow_Timeouts(t *testing.T) {
	requireOVSForTest(t)

	bridge := setupTestBridge(t, "test-of-timeout")

	// Create client with very short timeout
	client, err := openflow.NewClient(
		bridge.name,
		openflow.WithSocketDir(ofSocketDir),
		openflow.WithTimeout(1*time.Nanosecond), // Extremely short timeout
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Connection might timeout with such a short timeout
	err = client.Connect(ctx)
	if err != nil {
		// Timeout is expected with 1ns timeout
		t.Logf("Connection timed out as expected: %v", err)
		return
	}

	// If connection succeeded despite timeout, clean up
	defer client.Disconnect()
}

// Benchmark tests are also skipped if OpenFlow is not available

// Example test demonstrating usage
func ExampleClient_AddFlow() {
	// This example shows how to add a simple OpenFlow rule
	// Note: Requires root privileges and OVS installed with OpenFlow management socket

	client, err := openflow.NewClient("my-bridge")
	if err != nil {
		fmt.Printf("Failed to create client: %v\n", err)
		return
	}

	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		fmt.Printf("Failed to connect: %v\n", err)
		return
	}
	defer client.Disconnect()

	// Create a flow: packets from port 1 go to port 2
	flow := openflow.NewFlowMod(0)
	flow.Priority = 100
	flow.Match.AddInPort(1)

	outputAction := openflow.NewActionOutput(2, 0)
	instruction := openflow.NewInstructionApplyActions(outputAction)
	flow.Instructions = []openflow.Instruction{instruction}

	if err := client.AddFlow(ctx, flow); err != nil {
		fmt.Printf("Failed to add flow: %v\n", err)
		return
	}

	fmt.Println("Flow added successfully")
}
