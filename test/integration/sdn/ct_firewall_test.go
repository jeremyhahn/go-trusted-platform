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
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ct"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/firewall"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

const (
	ctFWBridge = "tp-ctfw"

	// All endpoints share zone alpha's VLAN wire so every packet enters
	// alpha's conntrack gate; the destination subnet selects the matrix
	// verdict (alpha→beta allowed, alpha→gamma denied).
	ctFWVLANAlpha = 100
	ctFWVLANBeta  = 101
	ctFWVLANGamma = 102

	ctFWSubnetAlpha = "10.230.1.0/24"
	ctFWSubnetBeta  = "10.230.2.0/24"
	ctFWSubnetGamma = "10.230.3.0/24"

	ctFWClientIP  = "10.230.1.5"
	ctFWAllowedIP = "10.230.2.5"
	ctFWDeniedIP  = "10.230.3.5"

	// The IPv6 leg of each zone (#554): the same three endpoints are
	// dual-stack, so the IPv6 verdicts are exercised on the same bridge.
	ctFWSubnet6Alpha = "fd00:230:1::/64"
	ctFWSubnet6Beta  = "fd00:230:2::/64"
	ctFWSubnet6Gamma = "fd00:230:3::/64"
	ctFWClientIP6    = "fd00:230:1::5"
	ctFWAllowedIP6   = "fd00:230:2::5"
	ctFWDeniedIP6    = "fd00:230:3::5"

	ctFWServerPort = 9090
)

// ctFWZones builds the three-zone config: alpha may reach beta (AllowTo),
// alpha→gamma has no declared path and is denied by the default-deny
// matrix.
func ctFWZones() []zone.ZoneConfig {
	return []zone.ZoneConfig{
		{Name: "alpha", AllowTo: []zone.ZonePath{{Zone: "beta"}}},
		{Name: "beta"},
		{Name: "gamma"},
	}
}

// ctFWNetworks maps each zone onto its VLAN + subnet.
func ctFWNetworks() map[zone.Zone]zoneflows.NetworkSummary {
	return map[zone.Zone]zoneflows.NetworkSummary{
		"alpha": {VLAN: ctFWVLANAlpha, Subnet: ctFWSubnetAlpha, Subnet6: ctFWSubnet6Alpha},
		"beta":  {VLAN: ctFWVLANBeta, Subnet: ctFWSubnetBeta, Subnet6: ctFWSubnet6Beta},
		"gamma": {VLAN: ctFWVLANGamma, Subnet: ctFWSubnetGamma, Subnet6: ctFWSubnet6Gamma},
	}
}

// newOVSDBClient creates and connects the OVSDB client used by the ct
// firewall and perf harnesses.
func newOVSDBClient(t *testing.T) *ovs.Client {
	t.Helper()
	client, err := ovs.NewClient("/var/run/openvswitch/db.sock")
	require.NoError(t, err, "create OVSDB client")
	t.Cleanup(func() { client.Close() })
	return client
}

// installPipelinePlumbing installs the minimal base-pipeline context the
// gateway normally provides around the ct services on a standalone test
// bridge: table 0 diverts everything into the table 10 gate, and table 30
// (the overlay pipeline continuation) forwards via NORMAL.
func installPipelinePlumbing(t *testing.T, client *ovs.Client, bridge string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	plumbing := []*ovs.FlowMod{
		{Table: 0, Priority: 1, Actions: "goto_table:10"},
		{Table: 30, Priority: 0, Actions: "normal"},
	}
	require.NoError(t, client.AddFlows(ctx, bridge, plumbing), "install pipeline plumbing")
}

// startEchoServer starts a line-echo TCP server inside the namespace and
// returns its shutdown function.
func startEchoServer(t *testing.T, ns, addr string) func() {
	t.Helper()

	listener, err := nsListen(ns, addr)
	require.NoError(t, err, "listen in %s on %s", ns, addr)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				scanner := bufio.NewScanner(c)
				for scanner.Scan() {
					fmt.Fprintf(c, "echo:%s\n", scanner.Text())
				}
			}(conn)
		}
	}()

	stop := func() {
		listener.Close()
		wg.Wait()
	}
	t.Cleanup(stop)
	return stop
}

// TestCTFirewallPipeline drives real traffic through the conntrack
// firewall pipeline (tables 10-gate/20/21) on a live OVS bridge:
// allowed-pair TCP round-trips and shows up in dpctl/dump-conntrack,
// denied-pair connects time out fast, and invalid-state packets hit the
// +inv+trk drop rule.
func TestCTFirewallPipeline(t *testing.T) {
	requireOVSForTest(t)
	SkipIfSDNUnavailable(t)

	bridge := setupTestBridge(t, ctFWBridge)
	client := newOVSDBClient(t)

	installPipelinePlumbing(t, client, bridge.name)

	// Endpoints: all on alpha's VLAN wire, one IP per zone subnet, with
	// on-link routes so cross-subnet traffic stays L2-adjacent.
	nsClient := createNSEndpoint(t, bridge.name, "tpfw-a", ctFWClientIP+"/24", ctFWVLANAlpha,
		ctFWSubnetBeta, ctFWSubnetGamma)
	nsAllowed := createNSEndpoint(t, bridge.name, "tpfw-b", ctFWAllowedIP+"/24", ctFWVLANAlpha,
		ctFWSubnetAlpha)
	nsDenied := createNSEndpoint(t, bridge.name, "tpfw-c", ctFWDeniedIP+"/24", ctFWVLANAlpha,
		ctFWSubnetAlpha)
	// The IPv6 legs (#554).
	addNSAddress(t, nsClient, ctFWClientIP6+"/64", ctFWSubnet6Beta, ctFWSubnet6Gamma)
	addNSAddress(t, nsAllowed, ctFWAllowedIP6+"/64", ctFWSubnet6Alpha)
	addNSAddress(t, nsDenied, ctFWDeniedIP6+"/64", ctFWSubnet6Alpha)

	// Build the real firewall service against the live bridge.
	controller, err := policy.NewOVSFlowController(client)
	require.NoError(t, err, "create flow controller")

	fwService, err := firewall.New(firewall.Deps{
		Controller: controller,
		OVS:        client,
		Config: firewall.Config{
			DefaultPolicy: firewall.PolicyDeny,
			Bridge:        bridge.name,
		},
		Zones:     ctFWZones,
		Networks:  ctFWNetworks,
		Allocator: ct.NewZoneAllocator(nil),
	})
	require.NoError(t, err, "create firewall service")

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	require.NoError(t, fwService.Start(ctx), "start firewall service")
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer stopCancel()
		if stopErr := fwService.Stop(stopCtx); stopErr != nil {
			t.Logf("firewall stop: %v", stopErr)
		}
	})

	serverAddr := fmt.Sprintf("%s:%d", ctFWAllowedIP, ctFWServerPort)
	startEchoServer(t, "tpfw-b", serverAddr)
	startEchoServer(t, "tpfw-c", fmt.Sprintf("%s:%d", ctFWDeniedIP, ctFWServerPort))
	serverAddr6 := net.JoinHostPort(ctFWAllowedIP6, fmt.Sprintf("%d", ctFWServerPort))
	startEchoServer(t, "tpfw-b", serverAddr6)
	startEchoServer(t, "tpfw-c", net.JoinHostPort(ctFWDeniedIP6, fmt.Sprintf("%d", ctFWServerPort)))

	// establishedConn must stay open across the subtests below: its
	// conntrack entry has to remain ESTABLISHED for the dump assertion and
	// its socket alive for the invalid-state packet generation, so the
	// parent test owns its lifetime (a subtest t.Cleanup would FIN-close it
	// the moment that subtest returns, decaying the entry to TIME_WAIT).
	var establishedConn net.Conn
	t.Cleanup(func() {
		if establishedConn != nil {
			establishedConn.Close()
		}
	})

	t.Run("AllowedPairConnects", func(t *testing.T) {
		conn, dialErr := nsDial("tpfw-a", serverAddr, 5*time.Second)
		require.NoError(t, dialErr, "allowed pair alpha→beta must connect")
		establishedConn = conn

		fmt.Fprintln(conn, "hello")
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
		reply, readErr := bufio.NewReader(conn).ReadString('\n')
		require.NoError(t, readErr, "echo round-trip")
		require.Equal(t, "echo:hello\n", reply)
	})

	t.Run("EstablishedFlowInConntrack", func(t *testing.T) {
		require.NotNil(t, establishedConn, "requires AllowedPairConnects")

		// The established flow must appear in the datapath conntrack
		// table via the new appctl client, in a non-zero firewall zone.
		waitFor(ctx, t, "established conntrack entry", 200*time.Millisecond, 10*time.Second, func() bool {
			dump, dumpErr := client.DumpConntrack(ctx, -1)
			if dumpErr != nil {
				t.Logf("dump-conntrack: %v", dumpErr)
				return false
			}
			for _, line := range strings.Split(dump, "\n") {
				if strings.Contains(line, ctFWClientIP) &&
					strings.Contains(line, ctFWAllowedIP) &&
					strings.Contains(line, "ESTABLISHED") {
					return true
				}
			}
			return false
		})

		summary := ovs.ParseConntrackSummary(mustDumpConntrack(ctx, t, client))
		require.Greater(t, summary.Total, 0, "conntrack summary must count the flow")
	})

	t.Run("DeniedPairTimesOut", func(t *testing.T) {
		_, dialErr := nsDial("tpfw-a", fmt.Sprintf("%s:%d", ctFWDeniedIP, ctFWServerPort), 2*time.Second)
		require.Error(t, dialErr, "denied pair alpha→gamma must not connect")
	})

	// The same matrix, enforced on the IPv6 legs (#554): before the compiler
	// emitted IPv6 twins, both of these connected — IPv6 matched no rule and
	// fell through the default deny.
	t.Run("IPv6AllowedPairConnects", func(t *testing.T) {
		conn, dialErr := nsDial("tpfw-a", serverAddr6, 5*time.Second)
		require.NoError(t, dialErr, "allowed pair alpha→beta must connect over IPv6")
		t.Cleanup(func() { conn.Close() })
		fmt.Fprintln(conn, "hello6")
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
		reply, readErr := bufio.NewReader(conn).ReadString('\n')
		require.NoError(t, readErr, "IPv6 echo round-trip")
		require.Equal(t, "echo:hello6\n", reply)
	})

	t.Run("IPv6DeniedPairTimesOut", func(t *testing.T) {
		_, dialErr := nsDial("tpfw-a", net.JoinHostPort(ctFWDeniedIP6, fmt.Sprintf("%d", ctFWServerPort)), 2*time.Second)
		require.Error(t, dialErr, "denied pair alpha→gamma must not connect over IPv6")
	})

	t.Run("InvalidStatePacketsDropped", func(t *testing.T) {
		require.NotNil(t, establishedConn, "requires AllowedPairConnects")

		// Disable loose conntrack pickup so mid-stream packets without a
		// conntrack entry classify as INVALID, then flush the entry and
		// push data over the still-open socket.
		prev := strings.TrimSpace(runCmd(t, "sysctl", "-n", "net.netfilter.nf_conntrack_tcp_loose"))
		runCmd(t, "sysctl", "-w", "net.netfilter.nf_conntrack_tcp_loose=0")
		t.Cleanup(func() {
			runCmdQuiet("sysctl", "-w", "net.netfilter.nf_conntrack_tcp_loose="+prev)
		})

		_, appctlErr := client.AppCtl(ctx, "dpctl/flush-conntrack")
		require.NoError(t, appctlErr, "flush conntrack")

		// Mid-stream writes now produce untracked non-SYN packets; TCP
		// retransmits several. They must hit the +inv+trk drop rule.
		fmt.Fprintln(establishedConn, "orphaned")

		waitFor(ctx, t, "invalid-state drop counter", 500*time.Millisecond, 15*time.Second, func() bool {
			fmt.Fprintln(establishedConn, "orphaned-again")
			flows, statsErr := client.GetFlowStats(ctx, bridge.name, "table=21")
			if statsErr != nil {
				t.Logf("flow stats: %v", statsErr)
				return false
			}
			for _, flow := range flows {
				if strings.Contains(flow.Match, "ct_state=+inv+trk") && flow.PacketCount > 0 {
					return true
				}
			}
			return false
		})
	})
}

// mustDumpConntrack dumps the full conntrack table or fails the test.
func mustDumpConntrack(ctx context.Context, t *testing.T, client *ovs.Client) string {
	t.Helper()
	dump, err := client.DumpConntrack(ctx, -1)
	require.NoError(t, err, "dump conntrack")
	return dump
}
