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
	"errors"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestRunCommands_ServerFailure proves every run function surfaces a
// backend failure as its typed error, carrying the server's message, and
// prints nothing.
func TestRunCommands_ServerFailure(t *testing.T) {
	rec, flags := startSDNServer(t, cli.OutputFormatJSON)
	rec.failWith(errBackendDown)
	cmd := &cobra.Command{}
	vip := &vipTargetFlags{protocol: "tcp", address: "10.0.0.1", port: 80}
	zone := uint32(7)
	keep := func(p *platformv1.IPAMPool) *platformv1.UpdateIPAMPoolRequest {
		return &platformv1.UpdateIPAMPoolRequest{Id: p.GetId()}
	}

	operationFailed := map[string]func() error{
		"bridge create": func() error {
			return runBridgeCreate(flags, "br0", "br0", "ovs", "", "", "", false, false, 1500)
		},
		"bridge get":    func() error { return runBridgeGet(flags, "br0") },
		"bridge list":   func() error { return runBridgeList(flags, "", "", 10, "") },
		"bridge delete": func() error { return runBridgeDelete(flags, "br0", false, false, false) },
		"flow add": func() error {
			return runFlowAdd(flags, "br0", "f1", 0, 100, 0, "", "", 0, "", "", []string{"drop"}, 0)
		},
		"flow delete":  func() error { return runFlowDelete(flags, "br0", "f1") },
		"flow list":    func() error { return runFlowList(flags, "br0", -1, 10, "") },
		"policy apply": func() error { return runPolicyApply(flags, "p1", "p1", "acl", "", "br0", 1, true) },
		"policy get":   func() error { return runPolicyGet(flags, "p1") },
		"policy list":  func() error { return runPolicyList(flags, "", "", 10, "") },
		"port add":     func() error { return runPortAdd(flags, "br0", "p1", "eth1", "internal", 0, "", "", 0, "") },
		"port delete":  func() error { return runPortDelete(flags, "br0", "eth1") },
		"port state":   func() error { return runPortGetState(flags, "br0", "eth1") },
		"port set-state": func() error {
			return runPortSetState(flags, &platformv1.SetPortStateRequest{BridgeId: "br0", PortId: "eth1"})
		},
		"port stats":  func() error { return runPortGetStats(flags, "br0", "eth1") },
		"vlan create": func() error { return runVLANCreate(flags, 100, "v100", "", []string{"br0"}) },
		"vlan delete": func() error { return runVLANDelete(flags, "br0", 100) },
		"vlan list":   func() error { return runVLANList(flags, "br0", 10, "") },
	}
	for op, run := range operationFailed {
		t.Run(op, func(t *testing.T) {
			out, err := captureStdout(t, run)
			var opErr *cli.ErrOperationFailed
			require.True(t, errors.As(err, &opErr), "got %T: %v", err, err)
			assert.Equal(t, op, opErr.Operation)
			assert.Contains(t, err.Error(), "backend down")
			assert.Empty(t, out)
		})
	}

	wrapped := map[string]func() error{
		"failed to get gateway status":          func() error { return runGatewayStatus(flags) },
		"failed to set gateway mode":            func() error { return runGatewayModeSet(flags, []string{"edge"}) },
		"failed to get BGP status":              func() error { return runBGPStatus(flags) },
		"failed to list BGP peers":              func() error { return runBGPPeers(flags) },
		"failed to announce prefix":             func() error { return runBGPAnnounce(flags, "10.0.0.0/24", "") },
		"failed to withdraw prefix":             func() error { return runBGPWithdraw(flags, "10.0.0.0/24") },
		"failed to list announced prefixes":     func() error { return runBGPRoutes(flags) },
		"failed to get load balancer status":    func() error { return runLBStatus(flags) },
		"failed to add VIP":                     func() error { return runLBVIPAdd(flags, vip, "round_robin", []string{"10.0.1.1:8080"}) },
		"failed to remove VIP":                  func() error { return runLBVIPRemove(flags, vip) },
		"failed to get VIP":                     func() error { return runLBVIPGet(flags, vip) },
		"failed to list VIPs":                   func() error { return runLBVIPList(flags) },
		"failed to set VIP backends":            func() error { return runLBVIPSetBackends(flags, vip, []string{"10.0.1.1:8080"}) },
		"failed to get NAT64 status":            func() error { return runNAT64Status(flags) },
		"failed to measure flow programming":    func() error { return runPerfFlows(flags, 10, false, "br0") },
		"failed to read datapath counters":      func() error { return runPerfDatapath(flags, "br0") },
		"failed to read conntrack summary":      func() error { return runPerfConntrack(flags, &zone) },
		"failed to list gateway snapshots":      func() error { return runGatewaySnapshot(cmd, flags, "", true) },
		"failed to get the gateway snapshot":    func() error { return runGatewaySnapshot(cmd, flags, "gw-1", false) },
		"failed to list gateway admitted VTEPs": func() error { return runGatewayAdmittedVTEPs(cmd, flags, "") },
		"failed to get gateway admitted VTEP":   func() error { return runGatewayAdmittedVTEPGet(cmd, flags, "", "10.0.0.2") },
		"failed to list IPAM pools":             func() error { return runIPAMPoolList(flags, "") },
		"failed to get IPAM pool":               func() error { return runIPAMPoolGet(flags, "pool-1") },
		"failed to create IPAM pool": func() error {
			return runIPAMPoolCreate(flags, &platformv1.CreateIPAMPoolRequest{Name: "lab", Cidr: "10.9.0.0/24"})
		},
		"failed to read IPAM pool before update": func() error { return runIPAMPoolUpdate(flags, "pool-1", keep) },
		"failed to delete IPAM pool":             func() error { return runIPAMPoolDelete(flags, "pool-1") },
		"failed to allocate IP":                  func() error { return runIPAMAllocate(flags, "pool-1", "dev-1", "") },
		"failed to release IP":                   func() error { return runIPAMRelease(flags, "10.9.0.5") },
		"failed to list allocations":             func() error { return runIPAMAllocations(flags, "pool-1") },
		"failed to get overlay status":           func() error { return runOverlayStatus(flags) },
		"failed to list VTEPs":                   func() error { return runVTEPList(flags) },
		"failed to get VTEP":                     func() error { return runVTEPGet(flags, "node-1") },
		"failed to list VNIs":                    func() error { return runVNIList(flags) },
		"failed to create VNI":                   func() error { return runVNICreate(flags, 5000, 100, "lab") },
		"failed to delete VNI":                   func() error { return runVNIDelete(flags, 5000) },
		"failed to list tunnels":                 func() error { return runTunnelList(flags, 5000) },
		"failed to list remote MACs":             func() error { return runMACList(flags, 5000) },
		"failed to forget MAC":                   func() error { return runMACForget(flags, "aa:bb:cc:dd:ee:ff", 5000) },
		"failed to list network zones":           func() error { return runZoneList(flags, "") },
		"failed to create network zone":          func() error { return runZoneCreate(flags, &zoneFlags{name: "lab", offset: 9}) },
		"failed to update network zone":          func() error { return runZoneUpdate(flags, &zoneFlags{name: "lab", isolate: true}) },
		"failed to delete network zone":          func() error { return runZoneDelete(flags, "lab") },
	}
	for msg, run := range wrapped {
		t.Run(msg, func(t *testing.T) {
			out, err := captureStdout(t, run)
			var wrapErr *WrappedError
			require.True(t, errors.As(err, &wrapErr), "got %T: %v", err, err)
			assert.Equal(t, msg, wrapErr.Msg)
			assert.Contains(t, err.Error(), "backend down")
			assert.Empty(t, out)
		})
	}
}
