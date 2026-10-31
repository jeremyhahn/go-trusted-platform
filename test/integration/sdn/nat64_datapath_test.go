//go:build integration && nat64vm

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
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testenv"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/boundedexec"
)

// The NAT64 datapath end to end (#601): an IPv6-only client on an OVS
// bridge reaches an IPv4-only server through a real gatewayd gateway running
// the nat64 section ALONE -- the gateway's own pipeline, the table-10 gate,
// the table-20 divert, the table-27 hand-off to the translator port, and the
// Jool instance the driver built. Nothing here is a fake.
//
// Topology, inside the NAT64 VM:
//
//	n64cli (2001:db8:6::10, 10.64.0.10) --veth-- [ bridge ] --internal-- n64gw  2001:db8:6::1, 10.64.0.1 (the router)
//	                                             [        ] --internal-- nat640 (the translator port)
//	host: 192.0.2.1 (pool4) --veth-- n64srv (192.0.2.2)
//
// The client resolves 64:ff9b::192.0.2.2 by RFC 6052 embedding, as DNS64
// would, and pings it.
const (
	n64Bridge     = "tp-n64"
	n64ClientNS   = "n64cli"
	n64ServerNS   = "n64srv"
	n64RouterPort = "n64gw"
	n64XlatPort   = "nat640"
	n64ServerHost = "n64s-h"
	n64ServerPeer = "n64s-p"

	n64ClientV6 = "2001:db8:6::10"
	n64RouterV6 = "2001:db8:6::1"
	n64ClientV4 = "10.64.0.10"
	n64RouterV4 = "10.64.0.1"
	n64Pool4    = "192.0.2.1"
	n64ServerV4 = "192.0.2.2"
	// n64Target is 192.0.2.2 embedded in the well-known prefix.
	n64Target = "64:ff9b::c000:202"
	n64VLAN   = 300
)

// n64Topology builds the bridge, the client, the router and translator
// ports and the IPv4 server. vlan, when nonzero, puts the client and the
// router in that VLAN: the client sends tagged, the router port is an
// access port.
func n64Topology(t *testing.T, vlan int) {
	t.Helper()
	bridge := setupTestBridge(t, n64Bridge)

	runCmd(t, "sysctl", "-qw", "net.ipv4.conf.all.forwarding=1")
	runCmd(t, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")

	// The client is dual-stack only so the IPv4 leg can prove that traffic
	// the divert does not claim still crosses the bridge.
	cli := createNSEndpoint(t, bridge.name, n64ClientNS, n64ClientV4+"/24", vlan)
	addNSAddress(t, cli, n64ClientV6+"/64")
	runCmd(t, "ip", "netns", "exec", n64ClientNS, "ip", "-6", "route", "add", "default", "via", n64RouterV6, "dev", cli.DataIf)

	routerArgs := []string{"add-port", bridge.name, n64RouterPort, "--", "set", "interface", n64RouterPort, "type=internal"}
	if vlan != 0 {
		routerArgs = append(routerArgs, "--", "set", "port", n64RouterPort, "tag="+strconv.Itoa(vlan))
	}
	runCmd(t, "ovs-vsctl", routerArgs...)
	runCmd(t, "ovs-vsctl", "add-port", bridge.name, n64XlatPort, "--", "set", "interface", n64XlatPort, "type=internal")
	t.Cleanup(func() {
		runCmdQuiet("ovs-vsctl", "--if-exists", "del-port", bridge.name, n64RouterPort)
		runCmdQuiet("ovs-vsctl", "--if-exists", "del-port", bridge.name, n64XlatPort)
	})
	runCmd(t, "ip", "link", "set", n64RouterPort, "up")
	runCmd(t, "ip", "link", "set", n64XlatPort, "up")
	runCmd(t, "ip", "addr", "add", n64RouterV4+"/24", "dev", n64RouterPort)
	runCmd(t, "ip", "-6", "addr", "add", n64RouterV6+"/64", "dev", n64RouterPort, "nodad")

	runCmdQuiet("ip", "netns", "del", n64ServerNS)
	runCmdQuiet("ip", "link", "del", n64ServerHost)
	t.Cleanup(func() {
		runCmdQuiet("ip", "link", "del", n64ServerHost)
		runCmdQuiet("ip", "netns", "del", n64ServerNS)
	})
	runCmd(t, "ip", "netns", "add", n64ServerNS)
	runCmd(t, "ip", testenv.VethArgs(n64ServerHost, n64ServerPeer)...)
	runCmd(t, "ip", "link", "set", n64ServerPeer, "netns", n64ServerNS)
	runCmd(t, "ip", "addr", "add", n64Pool4+"/24", "dev", n64ServerHost)
	runCmd(t, "ip", "link", "set", n64ServerHost, "up")
	runCmd(t, "ip", "netns", "exec", n64ServerNS, "ip", "link", "set", "lo", "up")
	runCmd(t, "ip", "netns", "exec", n64ServerNS, "ip", "link", "set", n64ServerPeer, "up")
	runCmd(t, "ip", "netns", "exec", n64ServerNS, "ip", "addr", "add", n64ServerV4+"/24", "dev", n64ServerPeer)
}

// n64Ping pings from the client namespace and reports whether a reply came
// back.
func n64Ping(t *testing.T, args ...string) (bool, string) {
	t.Helper()
	full := append([]string{"netns", "exec", n64ClientNS, "ping", "-c", "2", "-W", "2"}, args...)
	out, err := exec.Command("ip", full...).CombinedOutput()
	return err == nil, string(out)
}

// n64Gateway starts a gateway whose only datapath section is nat64.
func n64Gateway(t *testing.T, ctx context.Context, zones []gateway.NAT64ClientZoneConfig) *gateway.Gateway {
	t.Helper()
	client := newOVSDBClient(t)
	rt := newGatewayRuntime(t, client, n64Bridge, nil, nil)
	cfg := baseGatewayConfig("gw-nat64", rt)
	cfg.NAT64 = &gateway.NAT64Config{
		Enabled:        true,
		Instance:       "tp-nat64-e2e",
		TranslatorPort: n64XlatPort,
		Pool4: gateway.NAT64Pool4Config{
			Addresses:      []string{n64Pool4},
			PortRangeStart: 61001,
			PortRangeEnd:   65535,
		},
		ClientZones: zones,
	}
	cleanupInstance(t, "tp-nat64-e2e")
	return startGatewayForTest(t, ctx, cfg)
}

// n64Diagnose logs the bridge's flow table, the neighbour cache and the
// translator's counters, so a red run says where the frame went instead
// of only that it did not come back.
func n64Diagnose(t *testing.T) {
	t.Helper()
	for _, args := range [][]string{
		{"ovs-ofctl", "-O", "OpenFlow13", "dump-flows", n64Bridge},
		{"ovs-vsctl", "show"},
		{"ip", "-6", "neigh"},
		{"jool", "--instance", "tp-nat64-e2e", "stats", "display", "--csv"},
	} {
		out, err := boundedexec.Command(args[0], args[1:]...).CombinedOutput()
		t.Logf("$ %v (err=%v)\n%s", args, err, out)
	}
}

// n64RequirePing pings and, when the reply does not come, logs the
// datapath before failing.
func n64RequirePing(t *testing.T, target, why string) {
	t.Helper()
	ok, out := n64Ping(t, target)
	if !ok {
		n64Diagnose(t)
	}
	require.True(t, ok, "%s:\n%s", why, out)
}

// sessionsFor reports the translator's ICMP sessions for the client.
func sessionsFor(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("jool", "--instance", "tp-nat64-e2e", "session", "display", "--icmp", "--csv", "--numeric").CombinedOutput()
	require.NoError(t, err, "%s", out)
	return string(out)
}

func testNAT64Datapath(t *testing.T, vlan int, zones []gateway.NAT64ClientZoneConfig) {
	requireJool(t)
	requireOVSForTest(t)
	n64Topology(t, vlan)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	t.Run("NegativeControl_NoGatewayNoTranslation", func(t *testing.T) {
		ok, out := n64Ping(t, n64Target)
		require.False(t, ok, "with no gateway the prefix must be unreachable; otherwise the test proves nothing: %s", out)
	})

	gw := n64Gateway(t, ctx, zones)
	require.True(t, gw.HasService(gateway.ServiceNAT64))

	t.Run("IPv6ClientReachesIPv4Server", func(t *testing.T) {
		n64RequirePing(t, n64Target, "the translated ping must be answered")
		require.Contains(t, sessionsFor(t), n64ClientV6, "the reply came back through a Jool session for the client")
	})

	// The divert claims only the prefix; everything else meets the
	// pipeline's table-20 miss. Before #614's fix a nat64-only gateway
	// dropped all of it.
	t.Run("UnclaimedIPv6StillCrossesTheBridge", func(t *testing.T) {
		n64RequirePing(t, n64RouterV6, "neighbour discovery and IPv6 to the router must pass the table-20 miss")
	})
	t.Run("IPv4StillCrossesTheBridge", func(t *testing.T) {
		n64RequirePing(t, n64RouterV4, "ARP and IPv4 must pass the table-20 miss")
	})

	t.Run("StopRemovesTheTranslator", func(t *testing.T) {
		require.NoError(t, gw.Stop(ctx))
		out, err := exec.Command("jool", "instance", "display", "--csv").CombinedOutput()
		require.NoError(t, err, "%s", out)
		require.NotContains(t, string(out), "tp-nat64-e2e", "a clean Stop removes the instance")
		ok, _ := n64Ping(t, n64Target)
		require.False(t, ok, "after Stop nothing translates")
	})
}

// TestNAT64Datapath_UntaggedEveryZone: no client-zones, so every frame to
// the prefix is diverted; the client is untagged.
func TestNAT64Datapath_UntaggedEveryZone(t *testing.T) {
	testNAT64Datapath(t, 0, nil)
}

// TestNAT64Datapath_TaggedClientZone: the client sits in VLAN 300 and only
// that zone is named, so the divert matches its tag and the hand-off strips
// it before the frame reaches the host-side translator port.
func TestNAT64Datapath_TaggedClientZone(t *testing.T) {
	testNAT64Datapath(t, n64VLAN, []gateway.NAT64ClientZoneConfig{{Name: "iot", VLAN: n64VLAN}})
}
