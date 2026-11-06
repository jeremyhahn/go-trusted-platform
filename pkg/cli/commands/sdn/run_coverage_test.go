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
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
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

func TestRunBridgeDelete_NoContext(t *testing.T) {
	err := runBridgeDelete(noContextFlags(), "br0", false, false, false)
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

func TestRunFlowDelete_NoContext(t *testing.T) {
	err := runFlowDelete(noContextFlags(), "br0", "flow-1")
	assertNoContextError(t, err)
}

func TestRunFlowList_NoContext(t *testing.T) {
	err := runFlowList(noContextFlags(), "br0", -1, 0, "")
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

func TestRunPolicyGet_NoContext(t *testing.T) {
	err := runPolicyGet(noContextFlags(), "pol-1")
	assertNoContextError(t, err)
}

func TestRunPolicyList_NoContext(t *testing.T) {
	err := runPolicyList(noContextFlags(), "", "", 0, "")
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
	err := runPortSetState(noContextFlags(), &platformv1.SetPortStateRequest{
		BridgeId: "br0", PortId: "port-1", AdminState: "up",
		IngressRate: 1000, IngressBurst: 2000, EgressRate: 3000, EgressBurst: 4000,
	})
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

func TestRunVLANDelete_NoContext(t *testing.T) {
	err := runVLANDelete(noContextFlags(), "br0", 100)
	assertNoContextError(t, err)
}

func TestRunVLANList_NoContext(t *testing.T) {
	err := runVLANList(noContextFlags(), "br0", 0, "")
	assertNoContextError(t, err)
}

// =============================================================================
// Command construction — RunE invocation coverage
// =============================================================================

// =============================================================================
// Gateway BGP command — subcommand RunE coverage
// =============================================================================

// =============================================================================
// Overlay subcommand construction — RunE coverage
// =============================================================================

// =============================================================================
// IPAM subcommand construction
// =============================================================================
