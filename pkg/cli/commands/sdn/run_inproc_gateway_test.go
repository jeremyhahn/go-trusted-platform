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
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestRunGateway_InProcess(t *testing.T) {
	rec, flags := startSDNServer(t, cli.OutputFormatJSON)

	reads := map[string]func() error{
		"GetGatewayStatus":      func() error { return runGatewayStatus(flags) },
		"GetBGPStatus":          func() error { return runBGPStatus(flags) },
		"ListBGPPeers":          func() error { return runBGPPeers(flags) },
		"ListAnnouncedPrefixes": func() error { return runBGPRoutes(flags) },
		"GetLBStatus":           func() error { return runLBStatus(flags) },
		"ListVIPs":              func() error { return runLBVIPList(flags) },
		"GetNAT64Status":        func() error { return runNAT64Status(flags) },
	}
	for method, run := range reads {
		t.Run(method, func(t *testing.T) {
			out, err := captureStdout(t, run)
			require.NoError(t, err)
			assert.NotEmpty(t, out)
			rec.request(t, method)
		})
	}

	t.Run("mode set", func(t *testing.T) {
		_, err := captureStdout(t, func() error { return runGatewayModeSet(flags, []string{"edge", "transit"}) })
		require.NoError(t, err)
		assert.NotZero(t, rec.request(t, "SetGatewayMode").(*platformv1.SetGatewayModeRequest).GetModes())
	})

	t.Run("bgp announce", func(t *testing.T) {
		out, err := captureStdout(t, func() error { return runBGPAnnounce(flags, "10.8.0.0/24", "10.0.0.1") })
		require.NoError(t, err)
		assert.Equal(t, "Prefix 10.8.0.0/24 announced successfully\n", out)
		req := rec.request(t, "AnnouncePrefix").(*platformv1.AnnouncePrefixRequest)
		assert.Equal(t, "10.8.0.0/24", req.GetPrefix())
		assert.Equal(t, "10.0.0.1", req.GetNextHop())
	})

	t.Run("bgp withdraw", func(t *testing.T) {
		out, err := captureStdout(t, func() error { return runBGPWithdraw(flags, "10.8.0.0/24") })
		require.NoError(t, err)
		assert.Equal(t, "Prefix 10.8.0.0/24 withdrawn successfully\n", out)
		rec.request(t, "WithdrawPrefix")
	})
}

func TestRunLBVIP_InProcess(t *testing.T) {
	rec, flags := startSDNServer(t, cli.OutputFormatJSON)
	vip := &vipTargetFlags{protocol: "tcp", address: "10.0.0.1", port: 80}

	t.Run("add parses backends", func(t *testing.T) {
		_, err := captureStdout(t, func() error {
			return runLBVIPAdd(flags, vip, "hash", []string{"10.0.1.1:8080", "10.0.1.2:8080:5"})
		})
		require.NoError(t, err)
		cfg := rec.request(t, "AddVIP").(*platformv1.AddVIPRequest).GetVip()
		assert.Equal(t, "10.0.0.1", cfg.GetAddress())
		assert.Equal(t, uint32(80), cfg.GetPort())
		assert.Equal(t, "tcp", cfg.GetProtocol())
		assert.Equal(t, "hash", cfg.GetAlgorithm())
		require.Len(t, cfg.GetBackends(), 2)
		assert.Equal(t, "10.0.1.2", cfg.GetBackends()[1].GetAddress())
		assert.Equal(t, uint32(5), cfg.GetBackends()[1].GetWeight())
	})

	invalid := map[string]func() error{
		"add":          func() error { return runLBVIPAdd(flags, vip, "", []string{"10.0.1.1"}) },
		"set-backends": func() error { return runLBVIPSetBackends(flags, vip, []string{"10.0.1.1:0"}) },
	}
	for name, run := range invalid {
		t.Run(name+" rejects a bad backend before dialing", func(t *testing.T) {
			before := len(rec.requests)
			err := run()
			var specErr *ErrInvalidBackendSpec
			require.True(t, errors.As(err, &specErr), "got %T: %v", err, err)
			assert.Contains(t, err.Error(), "expected address:port[:weight]")
			assert.Len(t, rec.requests, before)
		})
	}

	t.Run("remove", func(t *testing.T) {
		out, err := captureStdout(t, func() error { return runLBVIPRemove(flags, vip) })
		require.NoError(t, err)
		assert.Equal(t, "VIP tcp/10.0.0.1:80 removed successfully\n", out)
		req := rec.request(t, "RemoveVIP").(*platformv1.RemoveVIPRequest)
		assert.Equal(t, "10.0.0.1", req.GetAddress())
		assert.Equal(t, uint32(80), req.GetPort())
	})

	t.Run("get", func(t *testing.T) {
		_, err := captureStdout(t, func() error { return runLBVIPGet(flags, vip) })
		require.NoError(t, err)
		req := rec.request(t, "GetVIP").(*platformv1.GetVIPRequest)
		assert.Equal(t, "tcp", req.GetProtocol())
		assert.Equal(t, "10.0.0.1", req.GetAddress())
	})

	t.Run("set backends", func(t *testing.T) {
		_, err := captureStdout(t, func() error { return runLBVIPSetBackends(flags, vip, []string{"10.0.1.3:9090"}) })
		require.NoError(t, err)
		req := rec.request(t, "SetVIPBackends").(*platformv1.SetVIPBackendsRequest)
		assert.Equal(t, uint32(80), req.GetPort())
		require.Len(t, req.GetBackends(), 1)
		assert.Equal(t, uint32(9090), req.GetBackends()[0].GetPort())
	})
}

func TestRunPerf_InProcess(t *testing.T) {
	rec, flags := startSDNServer(t, cli.OutputFormatJSON)

	t.Run("flows", func(t *testing.T) {
		_, err := captureStdout(t, func() error { return runPerfFlows(flags, 500, true, "br-int") })
		require.NoError(t, err)
		req := rec.request(t, "GetPerfFlows").(*platformv1.GetPerfFlowsRequest)
		assert.Equal(t, uint32(500), req.GetCount())
		assert.True(t, req.GetBatch())
		assert.Equal(t, "br-int", req.GetBridge())
	})

	t.Run("datapath", func(t *testing.T) {
		_, err := captureStdout(t, func() error { return runPerfDatapath(flags, "br-int") })
		require.NoError(t, err)
		assert.Equal(t, "br-int", rec.request(t, "GetPerfDatapath").(*platformv1.GetPerfDatapathRequest).GetBridge())
	})

	t.Run("conntrack one zone", func(t *testing.T) {
		zone := uint32(7)
		_, err := captureStdout(t, func() error { return runPerfConntrack(flags, &zone) })
		require.NoError(t, err)
		req := rec.request(t, "GetPerfConntrack").(*platformv1.GetPerfConntrackRequest)
		require.NotNil(t, req.Zone)
		assert.Equal(t, uint32(7), req.GetZone())
	})

	t.Run("conntrack every zone", func(t *testing.T) {
		_, err := captureStdout(t, func() error { return runPerfConntrack(flags, nil) })
		require.NoError(t, err)
		assert.Nil(t, rec.request(t, "GetPerfConntrack").(*platformv1.GetPerfConntrackRequest).Zone)
	})
}

// tableCommand returns a command whose output lands in the returned buffer.
func tableCommand() (*cobra.Command, *bytes.Buffer) {
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	return cmd, &out
}

func TestRunGatewaySnapshot_InProcess(t *testing.T) {
	gw1 := &platformv1.GatewaySnapshot{GatewayId: "gw-1"}
	gw2 := &platformv1.GatewaySnapshot{GatewayId: "gw-2"}

	t.Run("--all with --gateway-id is refused before dialing", func(t *testing.T) {
		rec, flags := startSDNServer(t, cli.OutputFormatTable)
		cmd, out := tableCommand()
		err := runGatewaySnapshot(cmd, flags, "gw-1", true)
		var argErr *ErrSnapshotArguments
		require.True(t, errors.As(err, &argErr), "got %T: %v", err, err)
		assert.Equal(t, "gateway snapshot: --all and --gateway-id name different reads; use one", err.Error())
		assert.Empty(t, out.String())
		assert.Empty(t, rec.requests)
	})

	t.Run("one snapshot as a table", func(t *testing.T) {
		rec, flags := startSDNServer(t, cli.OutputFormatTable)
		rec.respond("GetGatewaySnapshot", &platformv1.GetGatewaySnapshotResponse{Snapshot: gw1})
		cmd, out := tableCommand()
		require.NoError(t, runGatewaySnapshot(cmd, flags, "gw-1", false))
		assert.Equal(t, "Gateway:  gw-1\n", out.String())
		assert.Equal(t, "gw-1", rec.request(t, "GetGatewaySnapshot").(*platformv1.GetGatewaySnapshotRequest).GetGatewayId())
	})

	t.Run("every snapshot as a table, blank line between", func(t *testing.T) {
		rec, flags := startSDNServer(t, cli.OutputFormatTable)
		rec.respond("ListGatewaySnapshots", &platformv1.ListGatewaySnapshotsResponse{Snapshots: []*platformv1.GatewaySnapshot{gw1, gw2}})
		cmd, out := tableCommand()
		require.NoError(t, runGatewaySnapshot(cmd, flags, "", true))
		assert.Equal(t, "Gateway:  gw-1\n\nGateway:  gw-2\n", out.String())
	})

	t.Run("JSON", func(t *testing.T) {
		rec, flags := startSDNServer(t, cli.OutputFormatJSON)
		rec.respond("GetGatewaySnapshot", &platformv1.GetGatewaySnapshotResponse{Snapshot: gw1})
		rec.respond("ListGatewaySnapshots", &platformv1.ListGatewaySnapshotsResponse{Snapshots: []*platformv1.GatewaySnapshot{gw1, gw2}})
		cmd, table := tableCommand()

		one, err := captureStdout(t, func() error { return runGatewaySnapshot(cmd, flags, "", false) })
		require.NoError(t, err)
		assert.Contains(t, one, `"gateway_id": "gw-1"`)

		all, err := captureStdout(t, func() error { return runGatewaySnapshot(cmd, flags, "", true) })
		require.NoError(t, err)
		assert.Contains(t, all, `"gateway_id": "gw-2"`)
		assert.Empty(t, table.String())
	})
}

func TestRunGatewayAdmittedVTEPs_InProcess(t *testing.T) {
	admitted := &platformv1.GatewayAdmittedVTEP{
		Vtep: "10.0.0.2", DeviceId: 7, HostId: "h1", Serial: "s1",
		AllocationId: "a1", BaselineSource: "ek", ProfileId: 3,
		VerdictAt: timestamppb.New(time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)),
	}
	const admittedLine = "  10.0.0.2        device=7 host=h1 serial=s1 allocation=a1 baseline=ek profile=3 verdict=2026-10-19T12:00:00Z\n"

	t.Run("empty list as a table", func(t *testing.T) {
		rec, flags := startSDNServer(t, cli.OutputFormatTable)
		cmd, out := tableCommand()
		require.NoError(t, runGatewayAdmittedVTEPs(cmd, flags, "gw-1"))
		assert.Equal(t, "no admitted VTEPs\n", out.String())
		assert.Equal(t, "gw-1", rec.request(t, "ListGatewayAdmittedVTEPs").(*platformv1.ListGatewayAdmittedVTEPsRequest).GetGatewayId())
	})

	t.Run("list as a table", func(t *testing.T) {
		rec, flags := startSDNServer(t, cli.OutputFormatTable)
		rec.respond("ListGatewayAdmittedVTEPs", &platformv1.ListGatewayAdmittedVTEPsResponse{
			Vteps: []*platformv1.GatewayAdmittedVTEP{admitted, {Vtep: "10.0.0.3"}},
		})
		cmd, out := tableCommand()
		require.NoError(t, runGatewayAdmittedVTEPs(cmd, flags, ""))
		assert.Equal(t, "Admitted VTEPs\n"+admittedLine+
			"  10.0.0.3        device=0 host= serial= allocation= baseline= profile=0 verdict=-\n", out.String())
	})

	t.Run("one as a table", func(t *testing.T) {
		rec, flags := startSDNServer(t, cli.OutputFormatTable)
		rec.respond("GetGatewayAdmittedVTEP", &platformv1.GetGatewayAdmittedVTEPResponse{Vtep: admitted})
		cmd, out := tableCommand()
		require.NoError(t, runGatewayAdmittedVTEPGet(cmd, flags, "gw-1", "10.0.0.2"))
		assert.Equal(t, admittedLine, out.String())
		req := rec.request(t, "GetGatewayAdmittedVTEP").(*platformv1.GetGatewayAdmittedVTEPRequest)
		assert.Equal(t, "gw-1", req.GetGatewayId())
		assert.Equal(t, "10.0.0.2", req.GetVtep())
	})

	t.Run("JSON", func(t *testing.T) {
		rec, flags := startSDNServer(t, cli.OutputFormatJSON)
		rec.respond("GetGatewayAdmittedVTEP", &platformv1.GetGatewayAdmittedVTEPResponse{Vtep: admitted})
		rec.respond("ListGatewayAdmittedVTEPs", &platformv1.ListGatewayAdmittedVTEPsResponse{Vteps: []*platformv1.GatewayAdmittedVTEP{admitted}})
		cmd, table := tableCommand()

		one, err := captureStdout(t, func() error { return runGatewayAdmittedVTEPGet(cmd, flags, "", "10.0.0.2") })
		require.NoError(t, err)
		assert.Contains(t, one, `"host_id": "h1"`)

		all, err := captureStdout(t, func() error { return runGatewayAdmittedVTEPs(cmd, flags, "") })
		require.NoError(t, err)
		assert.Contains(t, all, `"serial": "s1"`)
		assert.Empty(t, table.String())
	})
}

func TestPrintGatewayAdmittedVTEP_Nil(t *testing.T) {
	var out bytes.Buffer
	printGatewayAdmittedVTEP(&out, nil)
	assert.Equal(t, "no admitted VTEP\n", out.String())
}

func TestRunIPAM_InProcess(t *testing.T) {
	rec, flags := startSDNServer(t, cli.OutputFormatJSON)
	pool := &platformv1.IPAMPool{Id: "pool-1", Name: "lab"}
	rec.respond("GetIPAMPool", &platformv1.GetIPAMPoolResponse{Pool: pool})
	rec.respond("UpdateIPAMPool", &platformv1.UpdateIPAMPoolResponse{Pool: pool})

	t.Run("pool list", func(t *testing.T) {
		_, err := captureStdout(t, func() error { return runIPAMPoolList(flags, "control-plane") })
		require.NoError(t, err)
		assert.Equal(t, "control-plane", rec.request(t, "ListIPAMPools").(*platformv1.ListIPAMPoolsRequest).GetZone())
	})

	t.Run("pool get", func(t *testing.T) {
		out, err := captureStdout(t, func() error { return runIPAMPoolGet(flags, "pool-1") })
		require.NoError(t, err)
		assert.Contains(t, out, `"pool-1"`)
		assert.Equal(t, "pool-1", rec.request(t, "GetIPAMPool").(*platformv1.GetIPAMPoolRequest).GetId())
	})

	t.Run("pool create", func(t *testing.T) {
		_, err := captureStdout(t, func() error {
			return runIPAMPoolCreate(flags, &platformv1.CreateIPAMPoolRequest{Name: "lab", Cidr: "10.9.0.0/24"})
		})
		require.NoError(t, err)
		assert.Equal(t, "10.9.0.0/24", rec.request(t, "CreateIPAMPool").(*platformv1.CreateIPAMPoolRequest).GetCidr())
	})

	t.Run("pool update builds from the current pool", func(t *testing.T) {
		var seen *platformv1.IPAMPool
		build := func(current *platformv1.IPAMPool) *platformv1.UpdateIPAMPoolRequest {
			seen = current
			return &platformv1.UpdateIPAMPoolRequest{Id: current.GetId(), Name: "renamed"}
		}
		out, err := captureStdout(t, func() error { return runIPAMPoolUpdate(flags, "pool-1", build) })
		require.NoError(t, err)
		assert.Contains(t, out, `"pool-1"`)
		assert.Equal(t, "lab", seen.GetName())
		req := rec.request(t, "UpdateIPAMPool").(*platformv1.UpdateIPAMPoolRequest)
		assert.Equal(t, "pool-1", req.GetId())
		assert.Equal(t, "renamed", req.GetName())
	})

	t.Run("pool update failure after a good read", func(t *testing.T) {
		rec.failOn("UpdateIPAMPool", errBackendDown)
		t.Cleanup(func() { rec.failOn("UpdateIPAMPool", nil) })
		out, err := captureStdout(t, func() error {
			return runIPAMPoolUpdate(flags, "pool-1", func(p *platformv1.IPAMPool) *platformv1.UpdateIPAMPoolRequest {
				return &platformv1.UpdateIPAMPoolRequest{Id: p.GetId()}
			})
		})
		var wrapErr *WrappedError
		require.True(t, errors.As(err, &wrapErr), "got %T: %v", err, err)
		assert.Equal(t, "failed to update IPAM pool", wrapErr.Msg)
		assert.Empty(t, out)
	})

	t.Run("pool delete", func(t *testing.T) {
		out, err := captureStdout(t, func() error { return runIPAMPoolDelete(flags, "pool-1") })
		require.NoError(t, err)
		assert.JSONEq(t, `{"pool_id":"pool-1","deleted":true}`, out)
		assert.Equal(t, "pool-1", rec.request(t, "DeleteIPAMPool").(*platformv1.DeleteIPAMPoolRequest).GetId())
	})

	t.Run("allocate", func(t *testing.T) {
		_, err := captureStdout(t, func() error { return runIPAMAllocate(flags, "pool-1", "dev-1", "node1") })
		require.NoError(t, err)
		req := rec.request(t, "AllocateIP").(*platformv1.AllocateIPRequest)
		assert.Equal(t, "pool-1", req.GetPoolId())
		assert.Equal(t, "dev-1", req.GetDeviceId())
		assert.Equal(t, "node1", req.GetHostname())
	})

	t.Run("release", func(t *testing.T) {
		out, err := captureStdout(t, func() error { return runIPAMRelease(flags, "10.9.0.5") })
		require.NoError(t, err)
		assert.JSONEq(t, `{"ip":"10.9.0.5","released":true}`, out)
		assert.Equal(t, "10.9.0.5", rec.request(t, "ReleaseIP").(*platformv1.ReleaseIPRequest).GetIp())
	})

	t.Run("allocations", func(t *testing.T) {
		_, err := captureStdout(t, func() error { return runIPAMAllocations(flags, "pool-1") })
		require.NoError(t, err)
		assert.Equal(t, "pool-1", rec.request(t, "ListAllocations").(*platformv1.ListAllocationsRequest).GetPoolId())
	})
}

func TestRunOverlay_InProcess(t *testing.T) {
	rec, flags := startSDNServer(t, cli.OutputFormatJSON)

	reads := map[string]func() error{
		"GetOverlayStatus": func() error { return runOverlayStatus(flags) },
		"ListVTEPs":        func() error { return runVTEPList(flags) },
		"ListVNIs":         func() error { return runVNIList(flags) },
	}
	for method, run := range reads {
		t.Run(method, func(t *testing.T) {
			out, err := captureStdout(t, run)
			require.NoError(t, err)
			assert.NotEmpty(t, out)
			rec.request(t, method)
		})
	}

	t.Run("vtep get", func(t *testing.T) {
		_, err := captureStdout(t, func() error { return runVTEPGet(flags, "node-1") })
		require.NoError(t, err)
		assert.Equal(t, "node-1", rec.request(t, "GetVTEP").(*platformv1.GetVTEPRequest).GetNodeId())
	})

	t.Run("vni create", func(t *testing.T) {
		_, err := captureStdout(t, func() error { return runVNICreate(flags, 5000, 100, "lab") })
		require.NoError(t, err)
		cfg := rec.request(t, "CreateVNI").(*platformv1.CreateVNIRequest).GetConfig()
		assert.Equal(t, uint32(5000), cfg.GetVni())
		assert.Equal(t, uint32(100), cfg.GetVlan())
		assert.Equal(t, "lab", cfg.GetName())
	})

	t.Run("vni delete", func(t *testing.T) {
		out, err := captureStdout(t, func() error { return runVNIDelete(flags, 5000) })
		require.NoError(t, err)
		assert.Equal(t, "VNI 5000 deleted successfully\n", out)
		assert.Equal(t, uint32(5000), rec.request(t, "DeleteVNI").(*platformv1.DeleteVNIRequest).GetVni())
	})

	t.Run("tunnels", func(t *testing.T) {
		_, err := captureStdout(t, func() error { return runTunnelList(flags, 5000) })
		require.NoError(t, err)
		assert.Equal(t, uint32(5000), rec.request(t, "ListTunnels").(*platformv1.ListTunnelsRequest).GetVni())
	})

	t.Run("macs", func(t *testing.T) {
		_, err := captureStdout(t, func() error { return runMACList(flags, 5000) })
		require.NoError(t, err)
		assert.Equal(t, uint32(5000), rec.request(t, "ListRemoteMACs").(*platformv1.ListRemoteMACsRequest).GetVni())
	})

	t.Run("mac forget", func(t *testing.T) {
		out, err := captureStdout(t, func() error { return runMACForget(flags, "aa:bb:cc:dd:ee:ff", 5000) })
		require.NoError(t, err)
		assert.Equal(t, "MAC aa:bb:cc:dd:ee:ff forgotten from VNI 5000\n", out)
		req := rec.request(t, "ForgetMAC").(*platformv1.ForgetMACRequest)
		assert.Equal(t, "aa:bb:cc:dd:ee:ff", req.GetMac())
		assert.Equal(t, uint32(5000), req.GetVni())
	})
}

func TestErrorTypes(t *testing.T) {
	assert.Equal(t, "invalid VNI: x", (&MessageError{Msg: "invalid VNI: x"}).Error())

	wrapped := &WrappedError{Msg: "failed to list VNIs", Err: errBackendDown}
	assert.Equal(t, "failed to list VNIs: "+errBackendDown.Error(), wrapped.Error())
	assert.ErrorIs(t, wrapped, errBackendDown)
	assert.NotErrorIs(t, &WrappedError{Msg: "m", Err: errors.New("other")}, errBackendDown)

	assert.Equal(t, `invalid backend "x": expected address:port[:weight]`, (&ErrInvalidBackendSpec{Spec: "x"}).Error())
}

// TestCommandTree_DispatchesToServer drives each cobra command from argv to
// the RPC it must reach, proving every RunE closure wires its flags through.
func TestCommandTree_DispatchesToServer(t *testing.T) {
	rec, flags := startSDNServer(t, cli.OutputFormatJSON)
	rec.respond("GetIPAMPool", &platformv1.GetIPAMPoolResponse{Pool: &platformv1.IPAMPool{Id: "pool-1"}})

	cases := []struct {
		args   []string
		method string
	}{
		{[]string{"bridge", "create", "--id", "b1", "--name", "br0", "--type", "ovs"}, "CreateBridge"},
		{[]string{"flow", "add", "--bridge", "br0", "--id", "f1", "--table", "0", "--priority", "1", "--action", "drop"}, "AddFlow"},
		{[]string{"flow", "delete", "f1", "--bridge", "br0"}, "DeleteFlow"},
		{[]string{"flow", "list", "--bridge", "br0"}, "ListFlows"},
		{[]string{"policy", "apply", "--id", "p1", "--name", "p1", "--type", "acl", "--priority", "1", "--bridge", "br0"}, "ApplyPolicy"},
		{[]string{"policy", "list", "--type", "acl"}, "ListPolicies"},
		{[]string{"port", "add", "--bridge", "br0", "--id", "p1", "--name", "eth1", "--type", "internal"}, "AddPort"},
		{[]string{"port", "delete", "eth1", "--bridge", "br0"}, "DeletePort"},
		{[]string{"port", "state", "eth1", "--bridge", "br0"}, "GetPort"},
		{[]string{"port", "set-state", "eth1", "--bridge", "br0", "--admin-state", "up"}, "SetPortState"},
		{[]string{"port", "stats", "eth1", "--bridge", "br0"}, "GetPortStats"},
		{[]string{"vlan", "create", "--id", "100", "--name", "v100", "--bridge", "br0"}, "CreateVLAN"},
		{[]string{"vlan", "delete", "100", "--bridge", "br0"}, "DeleteVLAN"},
		{[]string{"vlan", "list", "--bridge", "br0"}, "ListVLANs"},
		{[]string{"zone", "list"}, "ListNetworkZones"},
		{[]string{"zone", "create", "--name", "lab", "--offset", "9"}, "CreateNetworkZone"},
		{[]string{"zone", "update", "--name", "lab", "--isolate"}, "UpdateNetworkZone"},
		{[]string{"zone", "delete", "--name", "lab"}, "DeleteNetworkZone"},
		{[]string{"overlay", "vtep", "list"}, "ListVTEPs"},
		{[]string{"overlay", "vtep", "get", "node-1"}, "GetVTEP"},
		{[]string{"overlay", "vni", "list"}, "ListVNIs"},
		{[]string{"overlay", "vni", "create", "--vni", "5000", "--vlan", "100"}, "CreateVNI"},
		{[]string{"overlay", "vni", "delete", "5000"}, "DeleteVNI"},
		{[]string{"overlay", "tunnel", "list"}, "ListTunnels"},
		{[]string{"overlay", "mac", "list"}, "ListRemoteMACs"},
		{[]string{"overlay", "mac", "forget", "aa:bb:cc:dd:ee:ff", "--vni", "5000"}, "ForgetMAC"},
		{[]string{"gateway", "mode", "set", "--modes", "edge"}, "SetGatewayMode"},
		{[]string{"gateway", "bgp", "status"}, "GetBGPStatus"},
		{[]string{"gateway", "bgp", "peers"}, "ListBGPPeers"},
		{[]string{"gateway", "bgp", "announce", "--prefix", "10.8.0.0/24"}, "AnnouncePrefix"},
		{[]string{"gateway", "bgp", "withdraw", "--prefix", "10.8.0.0/24"}, "WithdrawPrefix"},
		{[]string{"gateway", "bgp", "routes"}, "ListAnnouncedPrefixes"},
		{[]string{"gateway", "snapshot"}, "GetGatewaySnapshot"},
		{[]string{"gateway", "overlay", "vteps"}, "ListGatewayAdmittedVTEPs"},
		{[]string{"gateway", "overlay", "vteps", "get", "10.0.0.2"}, "GetGatewayAdmittedVTEP"},
		{[]string{"gateway", "lb", "status"}, "GetLBStatus"},
		{[]string{"gateway", "lb", "vip", "add", "--address", "10.0.0.1", "--port", "80", "--backend", "10.0.1.1:8080"}, "AddVIP"},
		{[]string{"gateway", "lb", "vip", "remove", "--address", "10.0.0.1", "--port", "80"}, "RemoveVIP"},
		{[]string{"gateway", "lb", "vip", "get", "--address", "10.0.0.1", "--port", "80"}, "GetVIP"},
		{[]string{"gateway", "lb", "vip", "list"}, "ListVIPs"},
		{[]string{"gateway", "lb", "vip", "set-backends", "--address", "10.0.0.1", "--port", "80", "--backend", "10.0.1.1:8080"}, "SetVIPBackends"},
		{[]string{"gateway", "nat64", "status"}, "GetNAT64Status"},
		{[]string{"gateway", "perf", "flows", "--count", "10"}, "GetPerfFlows"},
		{[]string{"gateway", "perf", "datapath"}, "GetPerfDatapath"},
		{[]string{"gateway", "perf", "conntrack", "--zone", "7"}, "GetPerfConntrack"},
		{[]string{"ipam", "pool", "list"}, "ListIPAMPools"},
		{[]string{"ipam", "pool", "get", "--id", "pool-1"}, "GetIPAMPool"},
		{[]string{"ipam", "pool", "create", "--name", "lab", "--cidr", "10.9.0.0/24"}, "CreateIPAMPool"},
		{[]string{"ipam", "pool", "update", "--id", "pool-1", "--name", "renamed"}, "UpdateIPAMPool"},
		{[]string{"ipam", "pool", "delete", "--id", "pool-1"}, "DeleteIPAMPool"},
		{[]string{"ipam", "allocate", "--pool-id", "pool-1", "--device-id", "dev-1"}, "AllocateIP"},
		{[]string{"ipam", "release", "--ip", "10.9.0.5"}, "ReleaseIP"},
		{[]string{"ipam", "allocations"}, "ListAllocations"},
	}
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			rec.mu.Lock()
			delete(rec.requests, tc.method)
			rec.mu.Unlock()

			root := NewCommand(func() *cli.CommonFlags { return flags })
			root.SetArgs(tc.args)
			root.SetOut(&bytes.Buffer{})
			root.SetErr(&bytes.Buffer{})
			_, err := captureStdout(t, root.Execute)
			require.NoError(t, err)
			rec.request(t, tc.method)
		})
	}
}

// TestCommandTree_RejectsBadArguments proves argument validation in the
// RunE closures returns its typed error without reaching the server.
func TestCommandTree_RejectsBadArguments(t *testing.T) {
	rec, flags := startSDNServer(t, cli.OutputFormatJSON)

	t.Run("vni delete with a non-numeric VNI", func(t *testing.T) {
		root := NewCommand(func() *cli.CommonFlags { return flags })
		root.SetArgs([]string{"overlay", "vni", "delete", "lab"})
		root.SetOut(&bytes.Buffer{})
		root.SetErr(&bytes.Buffer{})
		err := root.Execute()
		var msgErr *MessageError
		require.True(t, errors.As(err, &msgErr), "got %T: %v", err, err)
		assert.Equal(t, "invalid VNI: lab", msgErr.Error())
	})

	t.Run("conntrack zone out of range", func(t *testing.T) {
		root := NewCommand(func() *cli.CommonFlags { return flags })
		root.SetArgs([]string{"gateway", "perf", "conntrack", "--zone", "70000"})
		root.SetOut(&bytes.Buffer{})
		root.SetErr(&bytes.Buffer{})
		err := root.Execute()
		var zoneErr *ErrInvalidConntrackZone
		require.True(t, errors.As(err, &zoneErr), "got %T: %v", err, err)
		assert.Equal(t, int32(70000), zoneErr.Zone)
	})

	assert.Empty(t, rec.requests)
}
