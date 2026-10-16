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

package modes

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
)

// ovlBaseTable is the base pipeline of the default test config, as the
// switch holds it.
var ovlBaseTable = []string{
	"t=0 p=0 any -> goto:10",
	"t=10 p=0 any -> goto:30",
	"t=10 p=200 in_port=7 -> drop",
	"t=20 p=0 any -> goto:30",
	"t=30 p=0 any -> goto:40",
	"t=30 p=250 in_port=7,eth_dst=02:aa:aa:aa:aa:aa -> drop",
	"t=30 p=300 tun_id=50000,eth_dst=02:00:00:00:00:0a -> goto:50",
	"t=40 p=0 any -> goto:60",
	"t=40 p=210 in_port=3,eth_type=0x86dd,ip_proto=58,icmpv6_type=135,ipv6_src=:: -> goto:60",
	"t=50 p=0 any -> drop",
	"t=60 p=0 any -> drop",
	"t=70 p=0 any -> output:3",
	"t=70 p=100 in_port=3 -> output:IN_PORT",
}

// testBuilder is the builder of the default test config: VXLAN port 7,
// access port 3.
func testBuilder(t *testing.T) *flowBuilder {
	t.Helper()
	b, err := newFlowBuilder(overlayConfig(newFakeSpeaker()), overlayPorts{vxlan: 7, access: 3})
	require.NoError(t, err)
	return b
}

// planned runs a plan through a fake switch and commits it.
func planned(t *testing.T, sw *fakeSwitch, table *flowTable, release, acquire []*openflow.FlowMod) []*openflow.FlowMod {
	t.Helper()
	plan, err := table.plan(release, acquire)
	require.NoError(t, err)
	require.NoError(t, sw.SendFlowMods(context.Background(), plan.mods))
	plan.commit()
	return plan.mods
}

func commandsOf(mods []*openflow.FlowMod) []uint8 {
	out := make([]uint8, 0, len(mods))
	for _, m := range mods {
		out = append(out, m.Command)
	}
	return out
}

func TestFlowTable_Plan(t *testing.T) {
	b := testBuilder(t)
	allowB := b.decapAllow(ovlL3VNI, ovlVTEPB)

	t.Run("a flow is added with its first holder and deleted with its last", func(t *testing.T) {
		sw, table := newFakeSwitch(), newFlowTable()

		mods := planned(t, sw, table, nil, []*openflow.FlowMod{allowB})
		assert.Equal(t, []uint8{openflow.OFPFCAdd}, commandsOf(mods))

		mods = planned(t, sw, table, nil, []*openflow.FlowMod{b.decapAllow(ovlL3VNI, ovlVTEPB)})
		assert.Empty(t, mods, "a second holder of the same flow sends nothing")

		mods = planned(t, sw, table, []*openflow.FlowMod{allowB}, nil)
		assert.Empty(t, mods, "the flow stays while one holder is left")
		assert.Len(t, sw.matching("tun_src=10.0.0.2"), 1)

		mods = planned(t, sw, table, []*openflow.FlowMod{allowB}, nil)
		assert.Equal(t, []uint8{openflow.OFPFCDeleteStrict}, commandsOf(mods))
		assert.Empty(t, sw.table())
	})

	t.Run("changed instructions replace the flow in place", func(t *testing.T) {
		sw, table := newFakeSwitch(), newFlowTable()
		toB := b.remoteRoute(netip.MustParsePrefix("10.2.0.0/24"), 124, ovlVTEPB, ovlRouterMACB)
		toC := b.remoteRoute(netip.MustParsePrefix("10.2.0.0/24"), 124, ovlVTEPC, ovlRouterMACB)
		planned(t, sw, table, nil, []*openflow.FlowMod{toB})

		mods := planned(t, sw, table, []*openflow.FlowMod{toB}, []*openflow.FlowMod{toC})

		assert.Equal(t, []uint8{openflow.OFPFCAdd}, commandsOf(mods), "an add replaces, no delete")
		require.Len(t, sw.table(), 1)
		assert.Contains(t, sw.table()[0], "set:tun_dst=10.0.0.3")
	})

	t.Run("adds come before deletes", func(t *testing.T) {
		sw, table := newFakeSwitch(), newFlowTable()
		allowC := b.decapAllow(ovlL3VNI, ovlVTEPC)
		planned(t, sw, table, nil, []*openflow.FlowMod{allowB})

		mods := planned(t, sw, table, []*openflow.FlowMod{allowB}, []*openflow.FlowMod{allowC})

		assert.Equal(t, []uint8{openflow.OFPFCAdd, openflow.OFPFCDeleteStrict}, commandsOf(mods))
		assert.Equal(t, []string{"t=10 p=300 in_port=7,tun_id=50000,tun_src=10.0.0.3 -> goto:20"}, sw.table())
	})

	t.Run("a plan left uncommitted changes nothing", func(t *testing.T) {
		table := newFlowTable()
		_, err := table.plan(nil, []*openflow.FlowMod{allowB})
		require.NoError(t, err)

		plan, err := table.plan(nil, []*openflow.FlowMod{allowB})
		require.NoError(t, err)
		assert.Len(t, plan.mods, 1, "the flow is still to be added")
	})

	t.Run("releasing a flow never acquired fails", func(t *testing.T) {
		table := newFlowTable()

		_, err := table.plan([]*openflow.FlowMod{allowB}, nil)

		var flowErr *ErrFlowOperationFailed
		require.ErrorAs(t, err, &flowErr)
		assert.Equal(t, "release", flowErr.Operation)
		assert.ErrorIs(t, err, ErrFlowNotTracked)
	})

	t.Run("reset forgets every flow", func(t *testing.T) {
		table := newFlowTable()
		planned(t, newFakeSwitch(), table, nil, []*openflow.FlowMod{allowB})

		table.reset()

		_, err := table.plan([]*openflow.FlowMod{allowB}, nil)
		assert.ErrorIs(t, err, ErrFlowNotTracked)
	})

	toB := b.remoteRoute(netip.MustParsePrefix("10.2.0.0/24"), 124, ovlVTEPB, ovlRouterMACB)
	toC := b.remoteRoute(netip.MustParsePrefix("10.2.0.0/24"), 124, ovlVTEPC, ovlRouterMACB)

	t.Run("the surviving holder's flow is put back when the installed one's holder lets go", func(t *testing.T) {
		sw, table := newFakeSwitch(), newFlowTable()
		planned(t, sw, table, nil, []*openflow.FlowMod{toB})

		mods := planned(t, sw, table, nil, []*openflow.FlowMod{toC})
		assert.Equal(t, []uint8{openflow.OFPFCAdd}, commandsOf(mods), "the newest holder's flow is installed")
		assert.Len(t, sw.matching("set:tun_dst=10.0.0.3"), 1)

		mods = planned(t, sw, table, []*openflow.FlowMod{toC}, nil)
		assert.Equal(t, []uint8{openflow.OFPFCAdd}, commandsOf(mods), "the other holder's flow goes back")
		require.Len(t, sw.table(), 1)
		assert.Contains(t, sw.table()[0], "set:tun_dst=10.0.0.2")

		mods = planned(t, sw, table, []*openflow.FlowMod{toB}, nil)
		assert.Equal(t, []uint8{openflow.OFPFCDeleteStrict}, commandsOf(mods))
		assert.Empty(t, sw.table())
	})

	t.Run("releasing a holder whose flow is not installed sends nothing", func(t *testing.T) {
		sw, table := newFakeSwitch(), newFlowTable()
		planned(t, sw, table, nil, []*openflow.FlowMod{toB})
		planned(t, sw, table, nil, []*openflow.FlowMod{toC})

		mods := planned(t, sw, table, []*openflow.FlowMod{toB}, nil)

		assert.Empty(t, mods)
		require.Len(t, sw.table(), 1)
		assert.Contains(t, sw.table()[0], "set:tun_dst=10.0.0.3")
	})

	t.Run("releasing instructions no holder asked for fails", func(t *testing.T) {
		sw, table := newFakeSwitch(), newFlowTable()
		planned(t, sw, table, nil, []*openflow.FlowMod{toB})

		_, err := table.plan([]*openflow.FlowMod{toC}, nil)

		assert.ErrorIs(t, err, ErrFlowNotTracked)
	})

	t.Run("the restore mods undo a partly applied plan", func(t *testing.T) {
		sw, table := newFakeSwitch(), newFlowTable()
		allowC := b.decapAllow(ovlL3VNI, ovlVTEPC)
		planned(t, sw, table, nil, []*openflow.FlowMod{allowB, toB})
		committed := sw.table()

		plan, err := table.plan([]*openflow.FlowMod{allowB, toB}, []*openflow.FlowMod{allowC, toC})
		require.NoError(t, err)
		sw.refuse(0, nil)
		err = sw.SendFlowMods(context.Background(), plan.mods)
		var partial *openflow.ErrBatchPartialFailure
		require.ErrorAs(t, err, &partial)
		require.NotEqual(t, committed, sw.table(), "the mods around the refused one were applied")

		require.NoError(t, sw.SendFlowMods(context.Background(), plan.restore))
		assert.Equal(t, committed, sw.table())

		planned(t, sw, table, []*openflow.FlowMod{allowB, toB}, []*openflow.FlowMod{allowC, toC})
		assert.Len(t, sw.matching("tun_src=10.0.0.3"), 1)
		assert.Len(t, sw.matching("set:tun_dst=10.0.0.3"), 1)
		assert.Len(t, sw.table(), 2)
	})
}

func TestFlowTable_StrictDelete(t *testing.T) {
	b := testBuilder(t)
	flow := b.decapAllow(ovlL2VNI, ovlVTEPB)

	d := strictDelete(flow)

	assert.Equal(t, uint8(openflow.OFPFCDeleteStrict), d.Command)
	assert.Equal(t, OverlayCookie, d.Cookie)
	assert.Equal(t, ^uint64(0), d.CookieMask)
	assert.Equal(t, flow.TableID, d.TableID)
	assert.Equal(t, flow.Priority, d.Priority)
	assert.Same(t, flow.Match, d.Match)
	assert.Empty(t, d.Instructions)
}

func TestFailClosed(t *testing.T) {
	t.Run("orders the pipeline fail-closed whatever order it comes in", func(t *testing.T) {
		b := testBuilder(t)
		flows := append(b.base(), b.decapAllow(ovlL2VNI, ovlVTEPB), b.decapAllow(ovlL2VNI, ovlVTEPC))
		slices.Reverse(flows)

		assertFailClosed(t, failClosed(flows))
	})

	t.Run("keeps the order of flows of one table and priority", func(t *testing.T) {
		b := testBuilder(t)
		first, second := b.decapAllow(ovlL2VNI, ovlVTEPC), b.decapAllow(ovlL2VNI, ovlVTEPB)

		ordered := failClosed([]*openflow.FlowMod{first, second})

		assert.Equal(t, []*openflow.FlowMod{first, second}, ordered)
	})

	t.Run("an empty set stays empty", func(t *testing.T) {
		assert.Empty(t, failClosed(nil))
	})
}

func TestFlowBuilder_Base(t *testing.T) {
	t.Run("routing with an L3VNI", func(t *testing.T) {
		sw := newFakeSwitch()
		require.NoError(t, sw.SendFlowMods(context.Background(), testBuilder(t).base()))

		assert.Equal(t, ovlBaseTable, sw.table())
	})

	t.Run("only access frames reach the anycast gateway", func(t *testing.T) {
		b := testBuilder(t)
		sw := newFakeSwitch()
		require.NoError(t, sw.SendFlowMods(context.Background(), b.base()))
		require.NoError(t, sw.SendFlowMods(context.Background(), b.segment(ovlL2VNI, &overlaySegment{vlan: ovlVLAN})))

		assert.Equal(t, "goto:50", sw.lookup(t, TableMACLearning, "in_port=3", "tun_id=10100", "eth_dst=02:aa:aa:aa:aa:aa"))
		assert.Equal(t, "drop", sw.lookup(t, TableMACLearning, "in_port=7", "tun_id=10100", "eth_dst=02:aa:aa:aa:aa:aa"),
			"a tunnelled frame does not bypass the L3VNI's decap authorisation")
		assert.Equal(t, "goto:50", sw.lookup(t, TableMACLearning, "in_port=7", "tun_id=50000", "eth_dst=02:00:00:00:00:0a"),
			"routed frames from VTEPs arrive on the L3VNI")
	})

	t.Run("bridging only", func(t *testing.T) {
		cfg := overlayConfig(newFakeSpeaker())
		cfg.AnycastGateways, cfg.Subnets, cfg.AnycastGatewayMAC, cfg.L3VNI = nil, nil, nil, 0
		b, err := newFlowBuilder(cfg, overlayPorts{vxlan: 7, access: 3})
		require.NoError(t, err)
		sw := newFakeSwitch()
		require.NoError(t, sw.SendFlowMods(context.Background(), b.base()))

		assert.Empty(t, sw.matching("goto:50"), "nothing routes")
		assert.Len(t, sw.table(), 11)
	})
}

func TestFlowBuilder_Segment(t *testing.T) {
	b := testBuilder(t)

	t.Run("floods to the access port and every listed VTEP", func(t *testing.T) {
		sw := newFakeSwitch()
		segment := &overlaySegment{vlan: ovlVLAN, flood: []netip.Addr{ovlVTEPB, ovlVTEPC}}
		require.NoError(t, sw.SendFlowMods(context.Background(), b.segment(ovlL2VNI, segment)))

		assert.True(t, sw.has("t=10 p=100 in_port=3,vlan=100 -> pop_vlan,set:tun_id=10100 goto:20"))
		assert.True(t, sw.has("t=60 p=100 tun_id=10100 -> push_vlan,set:vlan=100,output:3,pop_vlan,"+
			"set:tun_dst=10.0.0.2,output:7,set:tun_dst=10.0.0.3,output:7"))
		assert.True(t, sw.has("t=10 p=300 in_port=7,tun_id=10100,tun_src=10.0.0.2 -> goto:20"))
		assert.True(t, sw.has("t=10 p=300 in_port=7,tun_id=10100,tun_src=10.0.0.3 -> goto:20"))
		assert.Len(t, sw.matching("t=40 ", "arp_tpa=10.1.0.1"), 1, "the gateway answers ARP")
		assert.True(t, sw.has("t=30 p=300 in_port=3,tun_id=10100,eth_dst=02:aa:aa:aa:aa:aa -> goto:50"),
			"the routed VNI's frames for the gateway MAC enter routing")
	})

	t.Run("an empty flood list reaches the access port only", func(t *testing.T) {
		sw := newFakeSwitch()
		require.NoError(t, sw.SendFlowMods(context.Background(), b.segment(ovlL2VNI, &overlaySegment{vlan: ovlVLAN})))

		assert.True(t, sw.has("t=60 p=100 tun_id=10100 -> push_vlan,set:vlan=100,output:3,pop_vlan"))
		assert.Empty(t, sw.matching("tun_src="), "no VTEP is authorised")
	})

	t.Run("each VNI answers ARP for its own gateway only", func(t *testing.T) {
		cfg := overlayConfig(newFakeSpeaker())
		cfg.AnycastGateways[ovlL2VNI+1] = netip.MustParseAddr("10.2.0.1")
		perVNI, err := newFlowBuilder(cfg, overlayPorts{vxlan: 7, access: 3})
		require.NoError(t, err)
		sw := newFakeSwitch()
		require.NoError(t, sw.SendFlowMods(context.Background(), perVNI.segment(ovlL2VNI+1, &overlaySegment{vlan: ovlVLAN + 1})))
		require.NoError(t, sw.SendFlowMods(context.Background(), perVNI.segment(ovlL2VNI+2, &overlaySegment{vlan: ovlVLAN + 2})))

		assert.Len(t, sw.matching("t=40 ", "arp_tpa=10.2.0.1"), 1, "the second VNI's gateway answers")
		assert.Empty(t, sw.matching("t=40 ", "arp_tpa=10.1.0.1"), "another VNI's gateway is not answered")
		assert.Empty(t, sw.matching("t=40 ", "vlan=102"), "a VNI without a gateway answers no ARP")
	})
}

func TestFlowBuilder_ARPReply(t *testing.T) {
	b := testBuilder(t)
	sw := newFakeSwitch()

	require.NoError(t, sw.SendFlowMods(context.Background(),
		[]*openflow.FlowMod{b.arpReply(ovlL2VNI, ovlVLAN, ovlRemoteIP, ovlRemoteMAC)}))

	assert.Equal(t, []string{
		"t=40 p=200 in_port=3,tun_id=10100,eth_type=0x806,arp_op=1,arp_tpa=10.1.0.20 -> " +
			"move:eth_src->eth_dst,set:eth_src=02:00:00:00:02:20,set:arp_op=2," +
			"move:arp_sha->arp_tha,set:arp_sha=02:00:00:00:02:20," +
			"move:arp_spa->arp_tpa,set:arp_spa=10.1.0.20," +
			"push_vlan,set:vlan=100,output:IN_PORT",
	}, sw.table())
	require.NoError(t, sw.SendFlowMods(context.Background(), b.base()))
	assert.Equal(t, "goto:60", sw.lookup(t, TableARP, "in_port=7", "tun_id=10100", "eth_type=0x806"),
		"only ARP from the access port is answered")
}

func TestFlowBuilder_Host(t *testing.T) {
	b := testBuilder(t)

	t.Run("a local host is delivered on the access port and routed to", func(t *testing.T) {
		sw := newFakeSwitch()
		host := &overlayHost{mac: ovlHostMAC, ips: map[netip.Addr]irbBinding{ovlHostIP: {}}}
		require.NoError(t, sw.SendFlowMods(context.Background(), b.host(ovlL2VNI, ovlVLAN, host)))

		assert.True(t, sw.has("t=30 p=200 tun_id=10100,eth_dst=02:00:00:00:01:10 -> push_vlan,set:vlan=100 goto:70"))
		assert.True(t, sw.has("t=50 p=200 eth_type=0x800,ipv4_dst=10.1.0.10 -> dec_ttl,set:eth_src=02:aa:aa:aa:aa:aa,"+
			"set:eth_dst=02:00:00:00:01:10,push_vlan,set:vlan=100 goto:70"))
		assert.Len(t, sw.matching("t=40 ", "arp_tpa=10.1.0.10"), 1)
		assert.Empty(t, sw.matching("t=10 "), "a local host authorises no decap")
	})

	t.Run("a routable remote host is reached over the L3VNI", func(t *testing.T) {
		sw := newFakeSwitch()
		host := &overlayHost{mac: ovlRemoteMAC, vtep: ovlVTEPB, ips: map[netip.Addr]irbBinding{
			ovlRemoteIP: {l3vni: ovlL3VNI, routerMAC: ovlRouterMACB},
		}}
		require.NoError(t, sw.SendFlowMods(context.Background(), b.host(ovlL2VNI, ovlVLAN, host)))

		assert.True(t, sw.has("t=30 p=200 tun_id=10100,eth_dst=02:00:00:00:02:20 -> set:tun_dst=10.0.0.2,output:7"))
		assert.True(t, sw.has("t=50 p=200 eth_type=0x800,ipv4_dst=10.1.0.20 -> dec_ttl,set:eth_src=02:00:00:00:00:0a,"+
			"set:eth_dst=02:00:00:00:00:0b,set:tun_id=50000,set:tun_dst=10.0.0.2,output:7"))
		assert.True(t, sw.has("t=10 p=300 in_port=7,tun_id=50000,tun_src=10.0.0.2 -> goto:20"))
	})

	t.Run("a remote host in another IP-VRF is bridged, not routed", func(t *testing.T) {
		sw := newFakeSwitch()
		host := &overlayHost{mac: ovlRemoteMAC, vtep: ovlVTEPB, ips: map[netip.Addr]irbBinding{
			ovlRemoteIP: {l3vni: ovlL3VNI + 1, routerMAC: ovlRouterMACB},
		}}
		require.NoError(t, sw.SendFlowMods(context.Background(), b.host(ovlL2VNI, ovlVLAN, host)))

		assert.Empty(t, sw.matching("t=50 "))
		assert.Empty(t, sw.matching("t=10 "))
		assert.Len(t, sw.matching("t=30 "), 1)
	})

	t.Run("IPv6 bindings and the MAC-only route add no IPv4 flows", func(t *testing.T) {
		sw := newFakeSwitch()
		host := &overlayHost{mac: ovlHostMAC, ips: map[netip.Addr]irbBinding{
			{}: {}, netip.MustParseAddr("fd00::10"): {},
		}}
		require.NoError(t, sw.SendFlowMods(context.Background(), b.host(ovlL2VNI, ovlVLAN, host)))

		assert.Len(t, sw.table(), 1)
		assert.Empty(t, sw.matching("eth_type=0x800"))
		assert.Empty(t, sw.matching("t=40 "), "the ND controller owns the punt, not the host")
	})
}

// A bridge-only VNI beside a routed one stays bridged: routing is decided
// per VNI by its anycast gateway, not by whether any VNI has one.
func TestFlowBuilder_RoutingIsPerVNI(t *testing.T) {
	const bridged, bridgedVLAN = ovlL2VNI + 1, ovlVLAN + 1
	b := testBuilder(t)
	localIP, remoteIP := netip.MustParseAddr("10.9.0.10"), netip.MustParseAddr("10.9.0.20")
	sw := newFakeSwitch()
	install := func(flows []*openflow.FlowMod) { require.NoError(t, sw.SendFlowMods(context.Background(), flows)) }
	install(b.base())
	install(b.segment(ovlL2VNI, &overlaySegment{vlan: ovlVLAN}))
	install(b.segment(bridged, &overlaySegment{vlan: bridgedVLAN}))
	install(b.host(ovlL2VNI, ovlVLAN, &overlayHost{mac: ovlHostMAC, ips: map[netip.Addr]irbBinding{ovlHostIP: {}}}))
	install(b.host(bridged, bridgedVLAN, &overlayHost{mac: net.HardwareAddr{0x02, 0, 0, 0, 0x09, 0x10},
		ips: map[netip.Addr]irbBinding{localIP: {}}}))
	install(b.host(bridged, bridgedVLAN, &overlayHost{mac: net.HardwareAddr{0x02, 0, 0, 0, 0x09, 0x20}, vtep: ovlVTEPB,
		ips: map[netip.Addr]irbBinding{remoteIP: {l3vni: ovlL3VNI, routerMAC: ovlRouterMACB}}}))

	t.Run("the routed VNI routes", func(t *testing.T) {
		assert.Equal(t, "goto:50", sw.lookup(t, TableMACLearning, "in_port=3", "tun_id=10100", "eth_dst=02:aa:aa:aa:aa:aa"))
		assert.Len(t, sw.matching("t=50 ", "ipv4_dst=10.1.0.10"), 1, "a host route to the routed VNI's host")
	})

	t.Run("the bridge-only VNI does not", func(t *testing.T) {
		assert.Equal(t, "goto:40", sw.lookup(t, TableMACLearning, "in_port=3", "tun_id=10101", "eth_dst=02:aa:aa:aa:aa:aa"),
			"a frame for the gateway MAC on a bridge-only VNI is bridged, not routed")
		assert.Empty(t, sw.matching("t=30 ", "tun_id=10101", "eth_dst=02:aa:aa:aa:aa:aa"), "no gateway-MAC ingress")
		assert.Empty(t, sw.matching("t=50 ", "ipv4_dst=10.9.0.10"), "no host route to a local host")
		assert.Empty(t, sw.matching("t=50 ", "ipv4_dst=10.9.0.20"), "no host route to a remote host")
		assert.Empty(t, sw.matching("t=10 ", "tun_id=50000"), "no L3VNI decap for a bridged host")
		assert.Len(t, sw.matching("t=30 ", "tun_id=10101"), 2, "both hosts are still bridged to")
	})
}

func TestFlowBuilder_Prefix(t *testing.T) {
	b := testBuilder(t)
	sw := newFakeSwitch()

	require.NoError(t, sw.SendFlowMods(context.Background(), b.prefix(netip.MustParsePrefix("10.2.0.0/24"),
		&overlayPrefixRoute{vtep: ovlVTEPC, routerMAC: ovlRouterMACB})))

	assert.True(t, sw.has("t=50 p=124 eth_type=0x800,ipv4_dst=10.2.0.0/24 -> dec_ttl,set:eth_src=02:00:00:00:00:0a,"+
		"set:eth_dst=02:00:00:00:00:0b,set:tun_id=50000,set:tun_dst=10.0.0.3,output:7"))
	assert.True(t, sw.has("t=10 p=300 in_port=7,tun_id=50000,tun_src=10.0.0.3 -> goto:20"))
	assert.Contains(t, sw.lookup(t, TableL3Routing, "eth_type=0x800", "ipv4_dst=10.2.0.77"), "tun_dst=10.0.0.3")
}

func TestNewFlowBuilder(t *testing.T) {
	t.Run("without an L3VNI there is no router MAC", func(t *testing.T) {
		cfg := overlayConfig(newFakeSpeaker())
		cfg.L3VNI = 0

		b, err := newFlowBuilder(cfg, overlayPorts{vxlan: 7, access: 3})

		require.NoError(t, err)
		assert.Nil(t, b.routerMAC)
		assert.Len(t, b.arpSwap, 3)
	})

	t.Run("with an L3VNI the router MAC is the EVPN one", func(t *testing.T) {
		b := testBuilder(t)

		assert.Equal(t, ovlRouterMAC, b.routerMAC)
		assert.True(t, b.routes(ovlL2VNI))
		assert.False(t, b.routes(ovlL2VNI+1), "a VNI without a gateway is bridged only")
	})
}

func TestEncodeVLAN(t *testing.T) {
	assert.Equal(t, []byte{0x10, 0x64}, encodeVLAN(100), "OFPVID_PRESENT is set")
	assert.Equal(t, []byte{0x1f, 0xfe}, encodeVLAN(4094))
}
