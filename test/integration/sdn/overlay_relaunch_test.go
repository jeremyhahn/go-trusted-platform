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
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/modes"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
)

// These tests relaunch an overlay (#557) on a live OVS bridge over the flows
// its predecessor left, and prove the relaunch reconciles by generation
// instead of flushing.

const (
	ovlRLBridge = "tp-ovl-rl"
	ovlRLNS     = "tpovlrl"
	ovlRLVNI    = 10557
	ovlRLVLAN   = 557
	ovlRLCIDR   = "10.55.7.2/24"

	// ovlRLForeignCookie is a firewall generation sharing the bridge.
	ovlRLForeignCookie uint64 = 0xF1BE000100000557
)

var (
	ovlRLLocalIP     = netip.MustParseAddr("10.55.7.1")
	ovlRLKeptMAC     = net.HardwareAddr{0x02, 0x05, 0x57, 0x00, 0x00, 0x10}
	ovlRLKeptIP      = netip.MustParseAddr("10.55.7.10")
	ovlRLStaleMAC    = net.HardwareAddr{0x02, 0x05, 0x57, 0x00, 0x00, 0x20}
	ovlRLStaleIP     = netip.MustParseAddr("10.55.7.20")
	ovlRLUnknownVTEP = netip.MustParseAddr("10.55.7.200")
)

// TestOverlay_RelaunchReconcilesByGeneration starts an overlay that learns
// two hosts, then, with its flows still on the bridge as a killed process
// leaves them, a relaunched overlay that learns one. The relaunch removes no
// flow its predecessor left; the sweep then deletes only the predecessor's
// generation, which takes the host nobody re-learned with it, and leaves the
// relaunch's flows and another owner's untouched.
func TestOverlay_RelaunchReconcilesByGeneration(t *testing.T) {
	requireOVSForTest(t)

	bridge := setupTestBridge(t, ovlRLBridge)
	// The overlay owns this bridge: drop the default NORMAL flow.
	runCmd(t, "ovs-ofctl", "-O", "OpenFlow13", "del-flows", bridge.name)
	runCmd(t, "ovs-ofctl", "-O", "OpenFlow13", "add-flow", bridge.name,
		fmt.Sprintf("cookie=0x%x,table=%d,priority=1,in_port=LOCAL,actions=drop", ovlRLForeignCookie, modes.TableCTGate))
	ep := createNSEndpoint(t, bridge.name, ovlRLNS, ovlRLCIDR, ovlRLVLAN)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	ovsClient := newOVSDBClient(t)
	dumpBridgeOnFailure(t, bridge.name)

	// The predecessor stays connected and idle: its flows stay on the
	// bridge, as they do when the process is killed.
	old := startOverlay(ctx, t, ovlRLBridge, ovlRLLocalIP, ovsClient, bridge.createClient(t), ep.HostIf)
	require.NoError(t, old.AddVNI(ctx, ovlRLVNI, ovlRLVLAN))
	require.NoError(t, old.LearnMAC(ctx, ovlRLVNI, ovlRLKeptMAC, ovlRLKeptIP))
	require.NoError(t, old.LearnMAC(ctx, ovlRLVNI, ovlRLStaleMAC, ovlRLStaleIP))
	before := ovlRLFlows(ctx, t, ovsClient)
	oldCookies := ovlRLCookies(before)
	require.Len(t, oldCookies, 1, "the predecessor installs one generation")
	require.NotEmpty(t, ovlRLFlowsFor(before, ovlRLStaleMAC), "precondition: the stale host has flows")

	next := startOverlay(ctx, t, ovlRLBridge, ovlRLLocalIP, ovsClient, bridge.createClient(t), ep.HostIf)
	require.NoError(t, next.AddVNI(ctx, ovlRLVNI, ovlRLVLAN))
	require.NoError(t, next.LearnMAC(ctx, ovlRLVNI, ovlRLKeptMAC, ovlRLKeptIP))

	relaunched := ovlRLFlows(ctx, t, ovsClient)
	t.Run("RelaunchRemovesNoFlowItsPredecessorLeft", func(t *testing.T) {
		for id := range before {
			assert.Contains(t, relaunched, id, "relaunch removed %s", id)
		}
	})

	newCookies := ovlRLCookies(relaunched)
	for cookie := range oldCookies {
		delete(newCookies, cookie)
	}
	require.Len(t, newCookies, 1, "the relaunch installs one new generation")

	t.Run("SweepDeletesOnlyThePredecessorsGeneration", func(t *testing.T) {
		// Revoking a VTEP sweeps a pending predecessor at once.
		require.NoError(t, next.RevokeVTEP(ctx, ovlRLUnknownVTEP))

		swept := ovlRLFlows(ctx, t, ovsClient)
		for id, cookie := range swept {
			assert.Contains(t, newCookies, cookie, "%s kept an older generation", id)
		}
		assert.Empty(t, ovlRLFlowsFor(swept, ovlRLStaleMAC), "the host nobody re-learned is gone")
		assert.NotEmpty(t, ovlRLFlowsFor(swept, ovlRLKeptMAC), "the re-learned host stays")
		for id, cookie := range relaunched {
			if _, ok := newCookies[cookie]; ok {
				assert.Contains(t, swept, id, "the sweep removed the relaunch's %s", id)
			}
		}

		foreign, err := ovsClient.GetFlowStats(ctx, ovlRLBridge,
			fmt.Sprintf("cookie=0x%x/0xffffffffffffffff", ovlRLForeignCookie))
		require.NoError(t, err)
		assert.Len(t, foreign, 1, "another owner's flow is untouched")
	})
}

// ovlRLFlows is the overlay's flows on the bridge, of every generation,
// keyed by table, priority and match, with their cookies.
func ovlRLFlows(ctx context.Context, t *testing.T, client *ovs.Client) map[string]uint64 {
	t.Helper()
	flows, err := client.GetFlowStats(ctx, ovlRLBridge,
		fmt.Sprintf("cookie=0x%x/0x%x", modes.OverlayCookie, ovs.OwnerCookieMask))
	require.NoError(t, err, "dump the overlay's flows")
	out := make(map[string]uint64, len(flows))
	for _, flow := range flows {
		cookie, err := strconv.ParseUint(strings.TrimPrefix(flow.Cookie, "0x"), 16, 64)
		require.NoError(t, err, "cookie %q", flow.Cookie)
		out[fmt.Sprintf("table=%d,priority=%d,%s", flow.Table, flow.Priority, flow.Match)] = cookie
	}
	return out
}

// ovlRLCookies is the set of cookies the flows carry.
func ovlRLCookies(flows map[string]uint64) map[uint64]struct{} {
	cookies := make(map[uint64]struct{})
	for _, cookie := range flows {
		cookies[cookie] = struct{}{}
	}
	return cookies
}

// ovlRLFlowsFor is the flows that match mac.
func ovlRLFlowsFor(flows map[string]uint64, mac net.HardwareAddr) []string {
	var out []string
	for id := range flows {
		if strings.Contains(id, mac.String()) {
			out = append(out, id)
		}
	}
	return out
}
