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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// noContextFlags returns CommonFlags with nil GetContext, which causes
// cli.NewBaseCommand to return ErrNoContextSet{}.
func noContextFlags() *cli.CommonFlags {
	return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
}

// assertNoContextError verifies the error is cli.ErrNoContextSet.
func assertNoContextError(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	assert.IsType(t, cli.ErrNoContextSet{}, err)
}

// =============================================================================
// Bridge run* functions
// parseBridgeType is called BEFORE NewBaseCommand, so invalid type errors first.
// Valid type + nil context -> ErrNoContextSet.
// =============================================================================

func TestRunBridgeCreate_NoContext(t *testing.T) {
	err := runBridgeCreate(noContextFlags(), "br0", "test-bridge", "ovs",
		"desc", "0000000000000001", "secure", true, false, 1500)
	assertNoContextError(t, err)
}

func TestRunBridgeCreate_InvalidBridgeType(t *testing.T) {
	err := runBridgeCreate(noContextFlags(), "br0", "test-bridge", "invalid-type",
		"desc", "", "", false, false, 0)
	require.Error(t, err)
	assert.IsType(t, ErrInvalidBridgeType{}, err)
}

func TestRunBridgeGet_NoContext(t *testing.T) {
	err := runBridgeGet(noContextFlags(), "br0")
	assertNoContextError(t, err)
}

func TestRunBridgeList_NoContext(t *testing.T) {
	err := runBridgeList(noContextFlags(), "", "", 0, "")
	assertNoContextError(t, err)
}

func TestRunBridgeList_WithFilters_NoContext(t *testing.T) {
	err := runBridgeList(noContextFlags(), "ovs", "up", 10, "cursor-abc")
	assertNoContextError(t, err)
}

func TestRunBridgeDelete_NoContext(t *testing.T) {
	err := runBridgeDelete(noContextFlags(), "br0", false, false, false)
	assertNoContextError(t, err)
}

func TestRunBridgeDelete_WithOptions_NoContext(t *testing.T) {
	err := runBridgeDelete(noContextFlags(), "br0", true, true, true)
	assertNoContextError(t, err)
}

// =============================================================================
// Flow run* functions
// NewBaseCommand is called BEFORE action parsing, so NoContext returns first.
// =============================================================================

func TestRunFlowAdd_NoContext(t *testing.T) {
	err := runFlowAdd(noContextFlags(), "br0", "flow-1", 0, 100,
		80, "aa:bb:cc:dd:ee:ff", "", 0x0800, "10.0.0.1", "",
		[]string{"output"}, 1)
	assertNoContextError(t, err)
}

func TestRunFlowAdd_NoContext_WithInvalidActions(t *testing.T) {
	// NewBaseCommand is called before action parsing, so NoContext returns first
	err := runFlowAdd(noContextFlags(), "br0", "flow-1", 0, 100,
		0, "", "", 0, "", "", []string{"bad-action-type"}, 0)
	assertNoContextError(t, err)
}

func TestRunFlowDelete_NoContext(t *testing.T) {
	err := runFlowDelete(noContextFlags(), "br0", "flow-1")
	assertNoContextError(t, err)
}

func TestRunFlowList_NoContext(t *testing.T) {
	err := runFlowList(noContextFlags(), "br0", -1, 0, "")
	assertNoContextError(t, err)
}

func TestRunFlowList_WithPagination_NoContext(t *testing.T) {
	err := runFlowList(noContextFlags(), "br0", 0, 50, "cursor-xyz")
	assertNoContextError(t, err)
}

// =============================================================================
// Gateway run* functions
// =============================================================================

func TestRunGatewayStatus_NoContext(t *testing.T) {
	err := runGatewayStatus(noContextFlags())
	assertNoContextError(t, err)
}

func TestRunGatewayModeSet_NoContext(t *testing.T) {
	err := runGatewayModeSet(noContextFlags(), []string{"overlay", "edge"})
	assertNoContextError(t, err)
}

func TestRunBGPStatus_NoContext(t *testing.T) {
	err := runBGPStatus(noContextFlags())
	assertNoContextError(t, err)
}

func TestRunBGPPeers_NoContext(t *testing.T) {
	err := runBGPPeers(noContextFlags())
	assertNoContextError(t, err)
}

func TestRunBGPAnnounce_NoContext(t *testing.T) {
	err := runBGPAnnounce(noContextFlags(), "2001:DB8::/36", "10.0.0.1")
	assertNoContextError(t, err)
}

func TestRunBGPWithdraw_NoContext(t *testing.T) {
	err := runBGPWithdraw(noContextFlags(), "2001:DB8::/36")
	assertNoContextError(t, err)
}

func TestRunBGPRoutes_NoContext(t *testing.T) {
	err := runBGPRoutes(noContextFlags())
	assertNoContextError(t, err)
}

// =============================================================================
// IPAM run* functions
// =============================================================================

func TestRunIPAMPoolList_NoContext(t *testing.T) {
	err := runIPAMPoolList(noContextFlags(), "")
	assertNoContextError(t, err)
}

func TestRunIPAMAllocate_NoContext(t *testing.T) {
	err := runIPAMAllocate(noContextFlags(), "pool-1", "device-1", "host-1")
	assertNoContextError(t, err)
}

func TestRunIPAMRelease_NoContext(t *testing.T) {
	err := runIPAMRelease(noContextFlags(), "10.0.0.5")
	assertNoContextError(t, err)
}

func TestRunIPAMAllocations_NoContext(t *testing.T) {
	err := runIPAMAllocations(noContextFlags(), "pool-1")
	assertNoContextError(t, err)
}

// =============================================================================
// Overlay run* functions
// =============================================================================

func TestRunOverlayStatus_NoContext(t *testing.T) {
	err := runOverlayStatus(noContextFlags())
	assertNoContextError(t, err)
}

func TestRunVTEPList_NoContext(t *testing.T) {
	err := runVTEPList(noContextFlags())
	assertNoContextError(t, err)
}

func TestRunVTEPGet_NoContext(t *testing.T) {
	err := runVTEPGet(noContextFlags(), "node-1")
	assertNoContextError(t, err)
}

func TestRunVNIList_NoContext(t *testing.T) {
	err := runVNIList(noContextFlags())
	assertNoContextError(t, err)
}

func TestRunVNICreate_NoContext(t *testing.T) {
	err := runVNICreate(noContextFlags(), 100, 10, "test-vni")
	assertNoContextError(t, err)
}

func TestRunVNIDelete_NoContext(t *testing.T) {
	err := runVNIDelete(noContextFlags(), 100)
	assertNoContextError(t, err)
}

func TestRunTunnelList_NoContext(t *testing.T) {
	err := runTunnelList(noContextFlags(), 100)
	assertNoContextError(t, err)
}

func TestRunMACList_NoContext(t *testing.T) {
	err := runMACList(noContextFlags(), 100)
	assertNoContextError(t, err)
}

func TestRunMACForget_NoContext(t *testing.T) {
	err := runMACForget(noContextFlags(), "aa:bb:cc:dd:ee:ff", 100)
	assertNoContextError(t, err)
}

// =============================================================================
// Policy run* functions
// NewBaseCommand is called BEFORE parsePolicyType, so NoContext returns first.
// =============================================================================

func TestRunPolicyApply_NoContext(t *testing.T) {
	err := runPolicyApply(noContextFlags(), "pol-1", "test-policy", "acl",
		"desc", "br0", 100, true)
	assertNoContextError(t, err)
}

func TestRunPolicyApply_NoContext_InvalidType(t *testing.T) {
	// NewBaseCommand fails before parsePolicyType is reached
	err := runPolicyApply(noContextFlags(), "pol-1", "test-policy", "bad-type",
		"desc", "br0", 100, true)
	assertNoContextError(t, err)
}

func TestRunPolicyGet_NoContext(t *testing.T) {
	err := runPolicyGet(noContextFlags(), "pol-1")
	assertNoContextError(t, err)
}

func TestRunPolicyList_NoContext(t *testing.T) {
	err := runPolicyList(noContextFlags(), "", "", 0, "")
	assertNoContextError(t, err)
}

func TestRunPolicyList_WithFilters_NoContext(t *testing.T) {
	err := runPolicyList(noContextFlags(), "acl", "br0", 25, "cursor")
	assertNoContextError(t, err)
}

// =============================================================================
// Port run* functions
// parsePortType is called BEFORE NewBaseCommand, so invalid type errors first.
// =============================================================================

func TestRunPortAdd_NoContext(t *testing.T) {
	// parsePortType succeeds with "internal", then NewBaseCommand fails
	err := runPortAdd(noContextFlags(), "br0", "port-1", "eth0", "internal",
		100, "eth0", "aa:bb:cc:dd:ee:ff", 1500, "up")
	assertNoContextError(t, err)
}

func TestRunPortAdd_InvalidPortType(t *testing.T) {
	// parsePortType fails before NewBaseCommand is called
	err := runPortAdd(noContextFlags(), "br0", "port-1", "eth0", "invalid-port-type",
		0, "", "", 0, "")
	require.Error(t, err)
	assert.IsType(t, ErrInvalidPortType{}, err)
}

func TestRunPortDelete_NoContext(t *testing.T) {
	err := runPortDelete(noContextFlags(), "br0", "port-1")
	assertNoContextError(t, err)
}

func TestRunPortGetState_NoContext(t *testing.T) {
	err := runPortGetState(noContextFlags(), "br0", "port-1")
	assertNoContextError(t, err)
}

func TestRunPortSetState_NoContext(t *testing.T) {
	err := runPortSetState(noContextFlags(), "br0", "port-1", "up", 1000, 2000)
	assertNoContextError(t, err)
}

func TestRunPortGetStats_NoContext(t *testing.T) {
	err := runPortGetStats(noContextFlags(), "br0", "port-1")
	assertNoContextError(t, err)
}

// =============================================================================
// VLAN run* functions
// =============================================================================

func TestRunVLANCreate_NoContext(t *testing.T) {
	err := runVLANCreate(noContextFlags(), 100, "test-vlan", "desc", []string{"br0"})
	assertNoContextError(t, err)
}

func TestRunVLANCreate_NoBridges_NoContext(t *testing.T) {
	err := runVLANCreate(noContextFlags(), 200, "vlan-200", "", nil)
	assertNoContextError(t, err)
}

func TestRunVLANDelete_NoContext(t *testing.T) {
	err := runVLANDelete(noContextFlags(), "br0", 100)
	assertNoContextError(t, err)
}

func TestRunVLANList_NoContext(t *testing.T) {
	err := runVLANList(noContextFlags(), "br0", 0, "")
	assertNoContextError(t, err)
}

func TestRunVLANList_WithPagination_NoContext(t *testing.T) {
	err := runVLANList(noContextFlags(), "br0", 50, "cursor-1")
	assertNoContextError(t, err)
}

// =============================================================================
// Command construction — RunE invocation coverage
// =============================================================================

func TestBridgeGetCommand_RunE_NoContext(t *testing.T) {
	cmd := newBridgeGetCommand(noContextFlags)
	err := cmd.RunE(cmd, []string{"br0"})
	assertNoContextError(t, err)
}

func TestBridgeListCommand_RunE_NoContext(t *testing.T) {
	cmd := newBridgeListCommand(noContextFlags)
	err := cmd.RunE(cmd, nil)
	assertNoContextError(t, err)
}

func TestBridgeDeleteCommand_RunE_NoContext(t *testing.T) {
	cmd := newBridgeDeleteCommand(noContextFlags)
	err := cmd.RunE(cmd, []string{"br0"})
	assertNoContextError(t, err)
}

func TestGatewayStatusCommand_RunE_NoContext(t *testing.T) {
	cmd := newGatewayStatusCommand(noContextFlags)
	err := cmd.RunE(cmd, nil)
	assertNoContextError(t, err)
}

func TestOverlayStatusCommand_RunE_NoContext(t *testing.T) {
	cmd := newOverlayStatusCommand(noContextFlags)
	err := cmd.RunE(cmd, nil)
	assertNoContextError(t, err)
}

func TestPolicyGetCommand_RunE_NoContext(t *testing.T) {
	cmd := newPolicyGetCommand(noContextFlags)
	err := cmd.RunE(cmd, []string{"pol-1"})
	assertNoContextError(t, err)
}

func TestVLANDeleteCommand_RunE_NoContext(t *testing.T) {
	cmd := newVLANDeleteCommand(noContextFlags)
	err := cmd.RunE(cmd, []string{"100"})
	assertNoContextError(t, err)
}

// =============================================================================
// Gateway BGP command — subcommand RunE coverage
// =============================================================================

func TestGatewayBGPCommand_SubcommandRunE(t *testing.T) {
	cmd := newGatewayBGPCommand(noContextFlags)
	subs := cmd.Commands()

	// Verify all 5 subcommands exist
	assert.Len(t, subs, 5)

	expectedNames := []string{"status", "peers", "announce", "withdraw", "routes"}
	for _, name := range expectedNames {
		found := false
		for _, sub := range subs {
			if sub.Name() == name {
				found = true
				assert.NotNil(t, sub.RunE, "subcommand %s should have RunE", name)
				break
			}
		}
		assert.True(t, found, "expected subcommand %s not found", name)
	}
}

func TestGatewayModeCommand_SetSubcommand(t *testing.T) {
	cmd := newGatewayModeCommand(noContextFlags)
	subs := cmd.Commands()
	require.Len(t, subs, 1)
	assert.Equal(t, "set", subs[0].Name())
	assert.NotNil(t, subs[0].RunE)
}

// =============================================================================
// Overlay subcommand construction — RunE coverage
// =============================================================================

func TestOverlayVTEPCommand_SubcommandRunE(t *testing.T) {
	cmd := newOverlayVTEPCommand(noContextFlags)
	subs := cmd.Commands()
	require.Len(t, subs, 2, "vtep should have list and get subcommands")

	for _, sub := range subs {
		assert.NotNil(t, sub.RunE, "subcommand %s should have RunE", sub.Name())
	}
}

func TestOverlayVNICommand_SubcommandRunE(t *testing.T) {
	cmd := newOverlayVNICommand(noContextFlags)
	subs := cmd.Commands()
	require.Len(t, subs, 3, "vni should have list, create, delete subcommands")

	for _, sub := range subs {
		assert.NotNil(t, sub.RunE, "subcommand %s should have RunE", sub.Name())
	}
}

func TestOverlayTunnelCommand_SubcommandRunE(t *testing.T) {
	cmd := newOverlayTunnelCommand(noContextFlags)
	subs := cmd.Commands()
	require.Len(t, subs, 1, "tunnel should have list subcommand")
	assert.NotNil(t, subs[0].RunE)
}

func TestOverlayMACCommand_SubcommandRunE(t *testing.T) {
	cmd := newOverlayMACCommand(noContextFlags)
	subs := cmd.Commands()
	require.Len(t, subs, 2, "mac should have list and forget subcommands")

	for _, sub := range subs {
		assert.NotNil(t, sub.RunE, "subcommand %s should have RunE", sub.Name())
	}
}

// =============================================================================
// IPAM subcommand construction
// =============================================================================

func TestIPAMPoolCommand_SubcommandRunE(t *testing.T) {
	cmd := newIPAMPoolCommand(noContextFlags)
	subs := cmd.Commands()
	require.Len(t, subs, 5, "pool should have create, get, update, delete, and list subcommands")

	names := make(map[string]bool, len(subs))
	for _, sub := range subs {
		assert.NotNil(t, sub.RunE, "subcommand %s should have RunE", sub.Name())
		names[sub.Name()] = true
	}
	for _, want := range []string{"create", "get", "update", "delete", "list"} {
		assert.True(t, names[want], "pool should have %s subcommand", want)
	}
}
