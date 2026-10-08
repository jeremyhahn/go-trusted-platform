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
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
)

// fromVTEP is a frame arriving on the VXLAN port from vtep with tun_id vni.
func fromVTEP(vni uint32, vtep netip.Addr) []string {
	return []string{"in_port=7", "tun_id=" + strconv.FormatUint(uint64(vni), 10), "tun_src=" + vtep.String()}
}

func assertVTEPFailed(t *testing.T, err error, operation string) *ErrVTEPOperationFailed {
	t.Helper()
	var vtepErr *ErrVTEPOperationFailed
	require.ErrorAs(t, err, &vtepErr)
	assert.Equal(t, operation, vtepErr.Operation)
	return vtepErr
}

func TestOverlayModeHandler_IMETRoute(t *testing.T) {
	t.Run("authorises decap only from VTEPs placed on the VNI", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)

		require.NoError(t, f.route(t, imet(ovlL2VNI, ovlVTEPB)))

		assert.Equal(t, "goto:20", f.sw.lookup(t, TableVXLANDecap, fromVTEP(ovlL2VNI, ovlVTEPB)...))
		assert.Equal(t, "drop", f.sw.lookup(t, TableVXLANDecap, fromVTEP(ovlL2VNI, ovlVTEPC)...),
			"a VTEP not on the VNI is dropped")
		assert.Equal(t, "drop", f.sw.lookup(t, TableVXLANDecap, fromVTEP(ovlL2VNI+1, ovlVTEPB)...),
			"a VTEP on the VNI cannot inject into another")
		assert.Equal(t, "drop", f.sw.lookup(t, TableVXLANDecap, fromVTEP(ovlL3VNI, ovlVTEPB)...),
			"Type-3 does not authorise the L3VNI")
	})

	t.Run("replicates BUM traffic to every VTEP on the VNI", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)

		require.NoError(t, f.route(t, imet(ovlL2VNI, ovlVTEPC)))
		require.NoError(t, f.route(t, imet(ovlL2VNI, ovlVTEPB)))
		require.NoError(t, f.route(t, imet(ovlL2VNI, ovlVTEPB)), "a repeat changes nothing")

		assert.Equal(t, "push_vlan,set:vlan=100,output:3,pop_vlan,"+
			"set:tun_dst=10.0.0.2,output:7,set:tun_dst=10.0.0.3,output:7",
			f.sw.lookup(t, TableEgress, "tun_id=10100"))
		assert.Equal(t, 2, f.handler.GetStatus().RemoteVTEPCount)
	})

	t.Run("a withdrawal stops replication and decap from the VTEP", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		require.NoError(t, f.route(t, imet(ovlL2VNI, ovlVTEPB)))
		require.NoError(t, f.route(t, imet(ovlL2VNI, ovlVTEPC)))

		require.NoError(t, f.route(t, withdraw(imet(ovlL2VNI, ovlVTEPB))))
		require.NoError(t, f.route(t, withdraw(imet(ovlL2VNI, ovlVTEPB))), "a repeat changes nothing")

		assert.Equal(t, "drop", f.sw.lookup(t, TableVXLANDecap, fromVTEP(ovlL2VNI, ovlVTEPB)...))
		assert.Equal(t, "push_vlan,set:vlan=100,output:3,pop_vlan,set:tun_dst=10.0.0.3,output:7",
			f.sw.lookup(t, TableEgress, "tun_id=10100"))
	})

	t.Run("routes for a VNI not carried change nothing", func(t *testing.T) {
		f := newOverlayFixture(t, nil)

		require.NoError(t, f.route(t, imet(ovlL2VNI, ovlVTEPB)))

		assert.Equal(t, ovlBaseTable, f.sw.table())
	})

	t.Run("a refused VTEP is not placed on the VNI", func(t *testing.T) {
		admitter := &recordingAdmitter{refused: map[netip.Addr]bool{ovlVTEPB: true}}
		f := newOverlayFixture(t, func(c *OverlayModeConfig) { c.Admitter = admitter }).withVNI(t)

		err := f.route(t, imet(ovlL2VNI, ovlVTEPB))

		assertVTEPFailed(t, err, "admit")
		assert.ErrorIs(t, err, errAdmissionRefused)
		assert.Equal(t, []string{"10100@10.0.0.2"}, admitter.asked)
		assert.Equal(t, "drop", f.sw.lookup(t, TableVXLANDecap, fromVTEP(ovlL2VNI, ovlVTEPB)...))
	})

	t.Run("an IPv6 or unspecified VTEP is refused", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)

		assert.ErrorIs(t, f.route(t, imet(ovlL2VNI, netip.MustParseAddr("fd00::2"))), ErrInvalidVTEPIP)
		assert.ErrorIs(t, f.route(t, imet(ovlL2VNI, netip.IPv4Unspecified())), ErrInvalidVTEPIP)
	})

	t.Run("a switch refusing the flows leaves the list as it was", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		f.sw.fail(errSwitchDown)

		err := f.route(t, imet(ovlL2VNI, ovlVTEPB))

		assertVTEPFailed(t, err, "flood list")
		f.sw.fail(nil)
		assert.Zero(t, f.handler.GetStatus().RemoteVTEPCount)
		require.NoError(t, f.route(t, imet(ovlL2VNI, ovlVTEPB)), "the route applies once the switch is back")
		assert.Equal(t, "goto:20", f.sw.lookup(t, TableVXLANDecap, fromVTEP(ovlL2VNI, ovlVTEPB)...))
	})
}

func TestOverlayModeHandler_MACIPRoute(t *testing.T) {
	t.Run("encapsulates to the VTEP, answers ARP and routes over the L3VNI", func(t *testing.T) {
		admitter := &recordingAdmitter{}
		f := newOverlayFixture(t, func(c *OverlayModeConfig) { c.Admitter = admitter }).withVNI(t)

		require.NoError(t, f.route(t, macip(ovlVTEPB, ovlRemoteMAC, ovlRemoteIP)))

		assert.Equal(t, "set:tun_dst=10.0.0.2,output:7",
			f.sw.lookup(t, TableMACLearning, "tun_id=10100", "eth_dst=02:00:00:00:02:20"))
		assert.Contains(t, f.sw.lookup(t, TableARP, "in_port=3", "tun_id=10100", "eth_type=0x806", "arp_op=1",
			"arp_tpa=10.1.0.20"), "set:arp_sha=02:00:00:00:02:20")
		assert.Equal(t, "dec_ttl,set:eth_src=02:00:00:00:00:0a,set:eth_dst=02:00:00:00:00:0b,"+
			"set:tun_id=50000,set:tun_dst=10.0.0.2,output:7",
			f.sw.lookup(t, TableL3Routing, "eth_type=0x800", "ipv4_dst=10.1.0.20"))
		assert.Equal(t, "goto:20", f.sw.lookup(t, TableVXLANDecap, fromVTEP(ovlL3VNI, ovlVTEPB)...),
			"routed replies from the VTEP are accepted on the L3VNI")
		assert.Equal(t, "goto:50", f.sw.lookup(t, TableMACLearning, "tun_id=50000", "eth_dst=02:00:00:00:00:0a"))
		assert.Equal(t, []string{"10100@10.0.0.2", "50000@10.0.0.2"}, admitter.asked)
	})

	t.Run("a second route of the same VTEP adds a binding", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		second := netip.MustParseAddr("10.1.0.21")
		require.NoError(t, f.route(t, macip(ovlVTEPB, ovlRemoteMAC, ovlRemoteIP)))

		require.NoError(t, f.route(t, macip(ovlVTEPB, ovlRemoteMAC, second)))

		entry, err := f.handler.LookupMAC(ovlL2VNI, ovlRemoteMAC)
		require.NoError(t, err)
		assert.Equal(t, []netip.Addr{ovlRemoteIP, second}, entry.IPs)
		assert.Len(t, f.sw.matching("t=50 ", "tun_dst=10.0.0.2"), 2)
		assert.Len(t, f.sw.matching("t=10 ", "tun_src=10.0.0.2"), 1, "one decap flow serves both")
	})

	t.Run("a MAC moving to another VTEP takes everything with it", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		require.NoError(t, f.route(t, macip(ovlVTEPB, ovlRemoteMAC, ovlRemoteIP)))
		require.NoError(t, f.route(t, macip(ovlVTEPB, ovlRemoteMAC, netip.MustParseAddr("10.1.0.21"))))

		require.NoError(t, f.route(t, macip(ovlVTEPC, ovlRemoteMAC, ovlRemoteIP)))

		assert.Equal(t, "set:tun_dst=10.0.0.3,output:7",
			f.sw.lookup(t, TableMACLearning, "tun_id=10100", "eth_dst=02:00:00:00:02:20"))
		assert.Empty(t, f.sw.matching("10.0.0.2"), "nothing is left of B")
		assert.Empty(t, f.sw.matching("10.1.0.21"), "B's other binding left with the MAC")
	})

	t.Run("withdrawals remove a binding, and the MAC with its last", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		second := netip.MustParseAddr("10.1.0.21")
		require.NoError(t, f.route(t, macip(ovlVTEPB, ovlRemoteMAC, ovlRemoteIP)))
		require.NoError(t, f.route(t, macip(ovlVTEPB, ovlRemoteMAC, second)))

		require.NoError(t, f.route(t, withdraw(macip(ovlVTEPB, ovlRemoteMAC, ovlRemoteIP))))

		assert.Empty(t, f.sw.matching("10.1.0.20"))
		assert.Equal(t, "set:tun_dst=10.0.0.2,output:7",
			f.sw.lookup(t, TableMACLearning, "tun_id=10100", "eth_dst=02:00:00:00:02:20"))
		assert.Equal(t, "goto:20", f.sw.lookup(t, TableVXLANDecap, fromVTEP(ovlL3VNI, ovlVTEPB)...))

		require.NoError(t, f.route(t, withdraw(macip(ovlVTEPB, ovlRemoteMAC, second))))

		assert.Empty(t, f.sw.matching("02:00:00:00:02:20"))
		assert.Equal(t, "drop", f.sw.lookup(t, TableVXLANDecap, fromVTEP(ovlL3VNI, ovlVTEPB)...))
	})

	t.Run("stale and unknown withdrawals change nothing", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		require.NoError(t, f.route(t, macip(ovlVTEPB, ovlRemoteMAC, ovlRemoteIP)))
		before := f.sw.table()

		require.NoError(t, f.route(t, withdraw(macip(ovlVTEPC, ovlRemoteMAC, ovlRemoteIP))), "the MAC left C")
		require.NoError(t, f.route(t, withdraw(macip(ovlVTEPB, ovlRemoteMAC, netip.MustParseAddr("10.1.0.99")))))
		require.NoError(t, f.route(t, withdraw(macip(ovlVTEPB, ovlHostMAC, ovlRemoteIP))))

		assert.Equal(t, before, f.sw.table())
	})

	t.Run("a binding in another IP-VRF is bridged, not routed", func(t *testing.T) {
		admitter := &recordingAdmitter{}
		f := newOverlayFixture(t, func(c *OverlayModeConfig) { c.Admitter = admitter }).withVNI(t)
		route := macip(ovlVTEPB, ovlRemoteMAC, ovlRemoteIP)
		route.MACIP.L3VNI = ovlL3VNI + 1

		require.NoError(t, f.route(t, route))

		assert.Len(t, f.sw.matching("eth_dst=02:00:00:00:02:20"), 1)
		assert.Empty(t, f.sw.matching("t=50 ", "10.1.0.20"))
		assert.Equal(t, []string{"10100@10.0.0.2"}, admitter.asked, "the L3VNI is not asked for")
	})

	t.Run("without ARP suppression only the gateway is answered", func(t *testing.T) {
		f := newOverlayFixture(t, func(c *OverlayModeConfig) { c.ARPSuppression = false }).withVNI(t)

		require.NoError(t, f.route(t, macip(ovlVTEPB, ovlRemoteMAC, ovlRemoteIP)))

		assert.Equal(t, []string{"10.1.0.1"}, arpTargets(f.sw.matching("t=40 ", "arp_tpa=")))
	})

	t.Run("a VTEP refused on the L3VNI installs nothing", func(t *testing.T) {
		admitter := &recordingAdmitter{refused: map[netip.Addr]bool{ovlVTEPB: true}}
		f := newOverlayFixture(t, func(c *OverlayModeConfig) { c.Admitter = admitter }).withVNI(t)

		err := f.route(t, macip(ovlVTEPB, ovlRemoteMAC, ovlRemoteIP))

		assertVTEPFailed(t, err, "admit")
		assert.Empty(t, f.sw.matching("02:00:00:00:02:20"))
	})

	t.Run("routes for an unknown VNI or an invalid MAC change nothing", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		before := f.sw.table()
		unknown := macip(ovlVTEPB, ovlRemoteMAC, ovlRemoteIP)
		unknown.MACIP.VNI = ovlL2VNI + 1

		require.NoError(t, f.route(t, unknown))
		require.NoError(t, f.route(t, macip(ovlVTEPB, net.HardwareAddr{1, 2}, ovlRemoteIP)))
		require.NoError(t, f.route(t, &bgp.EVPNRouteData{Type: bgp.EVPNTypeMACIPAdvertisement}))
		require.NoError(t, f.route(t, nil))
		require.NoError(t, f.route(t, &bgp.EVPNRouteData{Type: bgp.EVPNTypeEthernetSegment}))

		assert.Equal(t, before, f.sw.table())
	})

	t.Run("a switch refusing the flows installs nothing", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		f.sw.fail(errSwitchDown)

		err := f.route(t, macip(ovlVTEPB, ovlRemoteMAC, ovlRemoteIP))

		assertMACFailed(t, err, "install remote")
		f.sw.fail(nil)
		_, err = f.handler.LookupMAC(ovlL2VNI, ovlRemoteMAC)
		assert.ErrorIs(t, err, ErrMACNotFound)
	})

	t.Run("a switch applying part of the flows is put back", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		before := f.sw.table()
		f.sw.refuse(1, nil)

		err := f.route(t, macip(ovlVTEPB, ovlRemoteMAC, ovlRemoteIP))

		assertMACFailed(t, err, "install remote")
		var partial *openflow.ErrBatchPartialFailure
		assert.ErrorAs(t, err, &partial)
		assert.Equal(t, before, f.sw.table(), "no flow the table does not hold is left")
		require.NoError(t, f.route(t, macip(ovlVTEPB, ovlRemoteMAC, ovlRemoteIP)), "the route applies on a retry")
		assert.Equal(t, "set:tun_dst=10.0.0.2,output:7",
			f.sw.lookup(t, TableMACLearning, "tun_id=10100", "eth_dst=02:00:00:00:02:20"))
	})

	t.Run("a switch refusing the put-back says the flows may have drifted", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		f.sw.refuse(1, errSwitchDown)

		err := f.route(t, macip(ovlVTEPB, ovlRemoteMAC, ovlRemoteIP))

		assertMACFailed(t, err, "install remote")
		f.sw.fail(nil)
		var resyncErr *ErrFlowResyncFailed
		require.ErrorAs(t, err, &resyncErr)
		assert.ErrorIs(t, resyncErr, errSwitchDown)
	})

	t.Run("the next change after a refused put-back rebuilds the switch from the committed flows", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		f.sw.refuse(1, errSwitchDown)
		var resyncErr *ErrFlowResyncFailed
		require.ErrorAs(t, f.route(t, macip(ovlVTEPB, ovlRemoteMAC, ovlRemoteIP)), &resyncErr)
		f.sw.fail(nil)
		require.NotEmpty(t, f.sw.matching("tun_src=10.0.0.2"), "the refused batch left a decap flow behind")

		require.NoError(t, f.route(t, imet(ovlL2VNI, ovlVTEPC)))

		want := newOverlayFixture(t, nil).withVNI(t)
		require.NoError(t, want.route(t, imet(ovlL2VNI, ovlVTEPC)))
		assert.Equal(t, want.sw.table(), f.sw.table(), "the switch holds exactly the committed flows")
		assert.Empty(t, f.sw.matching("tun_src=10.0.0.2"), "no stale decap authorisation survives")
	})

	t.Run("a refused rebuild is tried again on the next change", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		f.sw.refuse(1, errSwitchDown)
		require.Error(t, f.route(t, macip(ovlVTEPB, ovlRemoteMAC, ovlRemoteIP)))

		var resyncErr *ErrFlowResyncFailed
		require.ErrorAs(t, f.route(t, imet(ovlL2VNI, ovlVTEPC)), &resyncErr, "the rebuild is refused")
		f.sw.fail(nil)
		require.NoError(t, f.route(t, imet(ovlL2VNI, ovlVTEPC)))

		want := newOverlayFixture(t, nil).withVNI(t)
		require.NoError(t, want.route(t, imet(ovlL2VNI, ovlVTEPC)))
		assert.Equal(t, want.sw.table(), f.sw.table())
	})

	t.Run("a rebuild installs every drop before the flows it outranks, in the same order every time", func(t *testing.T) {
		var orders [][]string
		for range 5 {
			f := newOverlayFixture(t, nil).withVNI(t)
			require.NoError(t, f.route(t, imet(ovlL2VNI, ovlVTEPC)))
			f.sw.refuse(1, errSwitchDown)
			require.Error(t, f.route(t, macip(ovlVTEPB, ovlRemoteMAC, ovlRemoteIP)))
			f.sw.fail(nil)
			mark := f.sw.batchCount()

			require.NoError(t, f.route(t, imet(ovlL2VNI, ovlVTEPB)))

			rebuild := f.sw.batchesSince(mark)[0]
			require.Equal(t, uint8(openflow.OFPFCDelete), rebuild[0].Command, "the rebuild starts with the flush")
			assertFailClosed(t, rebuild)
			orders = append(orders, describeMods(rebuild))
		}
		for _, order := range orders[1:] {
			assert.Equal(t, orders[0], order)
		}
	})

	t.Run("a switch refusing a withdrawal keeps the MAC", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		require.NoError(t, f.route(t, macip(ovlVTEPB, ovlRemoteMAC, ovlRemoteIP)))
		f.sw.fail(errSwitchDown)

		err := f.route(t, withdraw(macip(ovlVTEPB, ovlRemoteMAC, ovlRemoteIP)))

		assertMACFailed(t, err, "withdraw remote")
		f.sw.fail(nil)
		_, err = f.handler.LookupMAC(ovlL2VNI, ovlRemoteMAC)
		assert.NoError(t, err)
	})
}

func TestOverlayModeHandler_BindingConflict(t *testing.T) {
	conflicts := []struct {
		name  string
		mac   net.HardwareAddr
		ip    netip.Addr
		owner string
	}{
		{name: "the anycast gateway's MAC", mac: ovlAnycastMAC, ip: ovlRemoteIP, owner: "anycast gateway MAC"},
		{name: "the anycast gateway's IP", mac: ovlRemoteMAC, ip: ovlAnycastIP, owner: "anycast gateway IP"},
	}
	for _, tt := range conflicts {
		t.Run("a remote binding claiming "+tt.name+" is refused", func(t *testing.T) {
			f := newOverlayFixture(t, nil).withVNI(t)
			require.NoError(t, f.handler.LearnMAC(context.Background(), ovlL2VNI, ovlHostMAC, ovlHostIP))
			before := f.sw.table()

			err := f.route(t, macip(ovlVTEPB, tt.mac, tt.ip))

			assertMACFailed(t, err, "install remote")
			var conflict *ErrBindingConflict
			require.ErrorAs(t, err, &conflict)
			assert.Equal(t, tt.owner, conflict.Owner)
			assert.Equal(t, before, f.sw.table(), "the gateway's and the host's flows are untouched")
			assert.Equal(t, uint64(1), f.handler.GetStatus().RefusedBindings)
			_, err = f.handler.LookupMAC(ovlL2VNI, tt.mac)
			assert.ErrorIs(t, err, ErrMACNotFound)
		})
	}

	t.Run("a refused binding leaves the MAC's other bindings", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		require.NoError(t, f.route(t, macip(ovlVTEPB, ovlRemoteMAC, ovlRemoteIP)))

		require.Error(t, f.route(t, macip(ovlVTEPB, ovlRemoteMAC, ovlAnycastIP)))

		entry, err := f.handler.LookupMAC(ovlL2VNI, ovlRemoteMAC)
		require.NoError(t, err)
		assert.Equal(t, []netip.Addr{ovlRemoteIP}, entry.IPs)
	})

	t.Run("a binding claiming a local host's IP bridges the MAC and holds the IP back", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		require.NoError(t, f.handler.LearnMAC(context.Background(), ovlL2VNI, ovlHostMAC, ovlHostIP))

		require.NoError(t, f.route(t, macip(ovlVTEPB, ovlRemoteMAC, ovlHostIP)))

		assert.Equal(t, "set:tun_dst=10.0.0.2,output:7",
			f.sw.lookup(t, TableMACLearning, "tun_id=10100", "eth_dst=02:00:00:00:02:20"),
			"the MAC is bridged to its VTEP while its IP is held back")
		assert.Contains(t, f.sw.lookup(t, TableARP, "in_port=3", "tun_id=10100", "eth_type=0x806", "arp_op=1",
			"arp_tpa=10.1.0.10"), "set:arp_sha=02:00:00:00:01:10", "the local host still answers for its IP")
		assert.Contains(t, f.sw.lookup(t, TableL3Routing, "eth_type=0x800", "ipv4_dst=10.1.0.10"),
			"set:eth_dst=02:00:00:00:01:10", "the local host still holds the host route")
		assert.Equal(t, uint64(1), f.handler.GetStatus().RefusedBindings)
		entry, err := f.handler.LookupMAC(ovlL2VNI, ovlRemoteMAC)
		require.NoError(t, err)
		assert.Equal(t, ovlVTEPB, entry.VTEPIP)
		assert.Empty(t, entry.IPs)
	})

	t.Run("a held binding applies once the local host holding the IP is forgotten", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		require.NoError(t, f.handler.LearnMAC(context.Background(), ovlL2VNI, ovlHostMAC, ovlHostIP))
		require.NoError(t, f.route(t, macip(ovlVTEPB, ovlRemoteMAC, ovlHostIP)))

		require.NoError(t, f.handler.ForgetMAC(context.Background(), ovlL2VNI, ovlHostMAC))

		assert.Contains(t, f.sw.lookup(t, TableARP, "in_port=3", "tun_id=10100", "eth_type=0x806", "arp_op=1",
			"arp_tpa=10.1.0.10"), "set:arp_sha=02:00:00:00:02:20")
		assert.Contains(t, f.sw.lookup(t, TableL3Routing, "eth_type=0x800", "ipv4_dst=10.1.0.10"), "tun_dst=10.0.0.2")
		entry, err := f.handler.LookupMAC(ovlL2VNI, ovlRemoteMAC)
		require.NoError(t, err)
		assert.Equal(t, []netip.Addr{ovlHostIP}, entry.IPs)
	})

	t.Run("a held binding applies once the VNI of the local host holding the IP is removed", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		require.NoError(t, f.handler.AddVNI(context.Background(), ovlL2VNI+1, ovlVLAN+1))
		require.NoError(t, f.handler.LearnMAC(context.Background(), ovlL2VNI+1, ovlHostMAC, ovlHostIP))
		require.NoError(t, f.route(t, macip(ovlVTEPB, ovlRemoteMAC, ovlHostIP)))

		require.NoError(t, f.handler.RemoveVNI(context.Background(), ovlL2VNI+1))

		assert.Contains(t, f.sw.lookup(t, TableL3Routing, "eth_type=0x800", "ipv4_dst=10.1.0.10"), "tun_dst=10.0.0.2")
	})

	t.Run("a held binding withdrawn before the local host goes is never applied", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		require.NoError(t, f.handler.LearnMAC(context.Background(), ovlL2VNI, ovlHostMAC, ovlHostIP))
		require.NoError(t, f.route(t, macip(ovlVTEPB, ovlRemoteMAC, ovlRemoteIP)))
		require.NoError(t, f.route(t, macip(ovlVTEPB, ovlRemoteMAC, ovlHostIP)))

		require.NoError(t, f.route(t, withdraw(macip(ovlVTEPB, ovlRemoteMAC, ovlHostIP))))
		require.NoError(t, f.handler.ForgetMAC(context.Background(), ovlL2VNI, ovlHostMAC))

		assert.Empty(t, f.sw.matching("arp_tpa=10.1.0.10"))
		entry, err := f.handler.LookupMAC(ovlL2VNI, ovlRemoteMAC)
		require.NoError(t, err)
		assert.Equal(t, []netip.Addr{ovlRemoteIP}, entry.IPs, "the MAC's other binding stays")
	})

	t.Run("a MAC whose only binding is held goes with its withdrawal", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		require.NoError(t, f.handler.LearnMAC(context.Background(), ovlL2VNI, ovlHostMAC, ovlHostIP))
		require.NoError(t, f.route(t, macip(ovlVTEPB, ovlRemoteMAC, ovlHostIP)))

		require.NoError(t, f.route(t, withdraw(macip(ovlVTEPB, ovlRemoteMAC, ovlHostIP))))

		_, err := f.handler.LookupMAC(ovlL2VNI, ovlRemoteMAC)
		assert.ErrorIs(t, err, ErrMACNotFound)
		assert.Empty(t, f.sw.matching("eth_dst=02:00:00:00:02:20"))
	})

	t.Run("a switch refusing a held binding's flows fails the forget and keeps it held", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		require.NoError(t, f.handler.LearnMAC(context.Background(), ovlL2VNI, ovlHostMAC, ovlHostIP))
		require.NoError(t, f.route(t, macip(ovlVTEPB, ovlRemoteMAC, ovlHostIP)))
		f.sw.failAfter(1, errSwitchDown) // the forget's own batch applies

		err := f.handler.ForgetMAC(context.Background(), ovlL2VNI, ovlHostMAC)

		assertMACFailed(t, err, "release held")
		f.sw.fail(nil)
		entry, lookupErr := f.handler.LookupMAC(ovlL2VNI, ovlRemoteMAC)
		require.NoError(t, lookupErr)
		assert.Empty(t, entry.IPs, "the binding stays held")
		require.NoError(t, f.route(t, macip(ovlVTEPB, ovlRemoteMAC, ovlRemoteIP)),
			"the next route for the MAC applies what it held")
		entry, lookupErr = f.handler.LookupMAC(ovlL2VNI, ovlRemoteMAC)
		require.NoError(t, lookupErr)
		assert.Equal(t, []netip.Addr{ovlHostIP, ovlRemoteIP}, entry.IPs)
	})

	t.Run("a local MAC moving to a remote VTEP is not a conflict", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		require.NoError(t, f.handler.LearnMAC(context.Background(), ovlL2VNI, ovlHostMAC, ovlHostIP))

		require.NoError(t, f.route(t, macip(ovlVTEPB, ovlHostMAC, ovlHostIP)))

		entry, err := f.handler.LookupMAC(ovlL2VNI, ovlHostMAC)
		require.NoError(t, err)
		assert.Equal(t, ovlVTEPB, entry.VTEPIP)
		assert.Zero(t, f.handler.GetStatus().RefusedBindings)
	})
}

// arpTargets returns the arp_tpa each ARP-reply flow answers for.
func arpTargets(flows []string) []string {
	var out []string
	for _, f := range flows {
		match, _, _ := strings.Cut(f, " -> ")
		for _, field := range strings.FieldsFunc(match, func(r rune) bool { return r == ',' || r == ' ' }) {
			if target, ok := strings.CutPrefix(field, "arp_tpa="); ok {
				out = append(out, target)
			}
		}
	}
	return out
}

func TestOverlayModeHandler_PrefixRoute(t *testing.T) {
	t.Run("routes a prefix through its VTEP, the longest prefix first", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)

		require.NoError(t, f.route(t, prefixRoute(ovlVTEPC, "10.2.0.0/16")))
		require.NoError(t, f.route(t, prefixRoute(ovlVTEPB, "10.2.3.9/24")))

		assert.Contains(t, f.sw.lookup(t, TableL3Routing, "eth_type=0x800", "ipv4_dst=10.2.3.7"), "tun_dst=10.0.0.2")
		assert.Contains(t, f.sw.lookup(t, TableL3Routing, "eth_type=0x800", "ipv4_dst=10.2.4.7"), "tun_dst=10.0.0.3")
		assert.Equal(t, "drop", f.sw.lookup(t, TableL3Routing, "eth_type=0x800", "ipv4_dst=10.3.0.1"))
		assert.Equal(t, "goto:20", f.sw.lookup(t, TableVXLANDecap, fromVTEP(ovlL3VNI, ovlVTEPC)...))
		assert.Equal(t, 2, f.handler.GetStatus().PrefixCount)
	})

	t.Run("the lowest VTEP carries a prefix, the next takes over", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		require.NoError(t, f.route(t, prefixRoute(ovlVTEPC, "10.2.0.0/24")))
		require.NoError(t, f.route(t, prefixRoute(ovlVTEPB, "10.2.0.0/24")))

		assert.Contains(t, f.sw.lookup(t, TableL3Routing, "eth_type=0x800", "ipv4_dst=10.2.0.7"), "tun_dst=10.0.0.2")
		assert.Equal(t, "drop", f.sw.lookup(t, TableVXLANDecap, fromVTEP(ovlL3VNI, ovlVTEPC)...),
			"only the carrying VTEP is authorised")

		require.NoError(t, f.route(t, withdraw(prefixRoute(ovlVTEPB, "10.2.0.0/24"))))

		assert.Contains(t, f.sw.lookup(t, TableL3Routing, "eth_type=0x800", "ipv4_dst=10.2.0.7"), "tun_dst=10.0.0.3")
		assert.Equal(t, "drop", f.sw.lookup(t, TableVXLANDecap, fromVTEP(ovlL3VNI, ovlVTEPB)...))

		require.NoError(t, f.route(t, withdraw(prefixRoute(ovlVTEPC, "10.2.0.0/24"))))

		assert.Equal(t, "drop", f.sw.lookup(t, TableL3Routing, "eth_type=0x800", "ipv4_dst=10.2.0.7"))
		assert.Empty(t, f.sw.matching("tun_src="))
		assert.Zero(t, f.handler.GetStatus().PrefixCount)
	})

	t.Run("a host route outranks the prefix", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		require.NoError(t, f.route(t, prefixRoute(ovlVTEPC, "10.1.0.0/24")))

		require.NoError(t, f.route(t, macip(ovlVTEPB, ovlRemoteMAC, ovlRemoteIP)))

		assert.Contains(t, f.sw.lookup(t, TableL3Routing, "eth_type=0x800", "ipv4_dst=10.1.0.20"), "tun_dst=10.0.0.2")
	})

	t.Run("a route without the router MAC is refused", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		route := prefixRoute(ovlVTEPC, "10.2.0.0/24")
		route.RouterMAC = nil

		err := f.route(t, route)

		assertVTEPFailed(t, err, "route")
		assert.ErrorIs(t, err, ErrRouterMACRequired)
	})

	t.Run("a refused VTEP routes nothing", func(t *testing.T) {
		admitter := &recordingAdmitter{refused: map[netip.Addr]bool{ovlVTEPC: true}}
		f := newOverlayFixture(t, func(c *OverlayModeConfig) { c.Admitter = admitter }).withVNI(t)

		err := f.route(t, prefixRoute(ovlVTEPC, "10.2.0.0/24"))

		assert.ErrorIs(t, err, errAdmissionRefused)
		assert.Equal(t, []string{"50000@10.0.0.3"}, admitter.asked)
		assert.Empty(t, f.sw.matching("10.2.0.0"))
	})

	t.Run("other IP-VRFs, IPv6 and a VTEP without segments change nothing", func(t *testing.T) {
		f := newOverlayFixture(t, nil)
		require.NoError(t, f.route(t, prefixRoute(ovlVTEPC, "10.2.0.0/24")), "no segment yet")
		f.withVNI(t)
		before := f.sw.table()
		other := prefixRoute(ovlVTEPC, "10.2.0.0/24")
		other.PrefixData.VNI = ovlL3VNI + 1

		require.NoError(t, f.route(t, other))
		require.NoError(t, f.route(t, prefixRoute(ovlVTEPC, "fd00:2::/64")))

		assert.Equal(t, before, f.sw.table())
	})

	t.Run("a VTEP without an L3VNI ignores Type-5 routes", func(t *testing.T) {
		f := newOverlayFixture(t, func(c *OverlayModeConfig) { c.L3VNI = 0 }).withVNI(t)
		before := f.sw.table()

		require.NoError(t, f.route(t, prefixRoute(ovlVTEPC, "10.2.0.0/24")))

		assert.Equal(t, before, f.sw.table())
	})

	t.Run("a switch refusing the route keeps the routing as it was", func(t *testing.T) {
		f := newOverlayFixture(t, nil).withVNI(t)
		require.NoError(t, f.route(t, prefixRoute(ovlVTEPC, "10.2.0.0/24")))
		f.sw.fail(errSwitchDown)

		err := f.route(t, prefixRoute(ovlVTEPB, "10.2.0.0/24"))

		assertVTEPFailed(t, err, "prefix route")
		f.sw.fail(nil)
		assert.Contains(t, f.sw.lookup(t, TableL3Routing, "eth_type=0x800", "ipv4_dst=10.2.0.7"), "tun_dst=10.0.0.3")
		require.NoError(t, f.route(t, withdraw(prefixRoute(ovlVTEPC, "10.2.0.0/24"))),
			"the table still knows only C's route")
		assert.Zero(t, f.handler.GetStatus().PrefixCount)
	})
}

// TestOverlayModeHandler_EVPNEvents drives the overlay the way a fabric
// does: routes received from the BGP speaker, through the EVPN manager.
func TestOverlayModeHandler_EVPNEvents(t *testing.T) {
	f := newOverlayFixture(t, nil).withVNI(t)
	receive := func(route *bgp.EVPNRouteData) {
		t.Helper()
		f.sw.drainSends()
		f.speaker.events <- &bgp.Event{Path: &bgp.Path{EVPN: route}}
		f.sw.awaitSend(t)
	}

	receive(importable(t, imet(ovlL2VNI, ovlVTEPB), ovlL2VNI))

	assert.Equal(t, "goto:20", f.sw.lookup(t, TableVXLANDecap, fromVTEP(ovlL2VNI, ovlVTEPB)...))
	assert.Contains(t, f.sw.lookup(t, TableEgress, "tun_id=10100"), "set:tun_dst=10.0.0.2,output:7")

	receive(importable(t, macip(ovlVTEPB, ovlRemoteMAC, ovlRemoteIP), ovlL2VNI, ovlL3VNI))

	assert.Equal(t, "set:tun_dst=10.0.0.2,output:7",
		f.sw.lookup(t, TableMACLearning, "tun_id=10100", "eth_dst=02:00:00:00:02:20"))
	assert.Contains(t, f.sw.lookup(t, TableL3Routing, "eth_type=0x800", "ipv4_dst=10.1.0.20"), "set:tun_id=50000")

	receive(withdraw(importable(t, macip(ovlVTEPB, ovlRemoteMAC, ovlRemoteIP), ovlL2VNI, ovlL3VNI)))

	assert.Empty(t, f.sw.matching("02:00:00:00:02:20"))
	assert.Equal(t, "drop", f.sw.lookup(t, TableVXLANDecap, fromVTEP(ovlL3VNI, ovlVTEPB)...))
	assert.Equal(t, "goto:20", f.sw.lookup(t, TableVXLANDecap, fromVTEP(ovlL2VNI, ovlVTEPB)...),
		"B is still on the VNI")
}

// TestOverlayModeHandler_EVPNNextHopChange checks that a route sent again
// with a new next hop leaves its old VTEP neither routed nor authorised.
func TestOverlayModeHandler_EVPNNextHopChange(t *testing.T) {
	f := newOverlayFixture(t, nil).withVNI(t)
	route := importable(t, prefixRoute(ovlVTEPB, "10.2.0.0/24"), ovlL3VNI)
	f.sw.drainSends()
	f.speaker.events <- &bgp.Event{Path: &bgp.Path{EVPN: route}}
	f.sw.awaitSend(t)
	require.Equal(t, "goto:20", f.sw.lookup(t, TableVXLANDecap, fromVTEP(ovlL3VNI, ovlVTEPB)...))

	moved := importable(t, prefixRoute(ovlVTEPC, "10.2.0.0/24"), ovlL3VNI)
	moved.RD = route.RD
	f.sw.drainSends()
	f.speaker.events <- &bgp.Event{Path: &bgp.Path{EVPN: moved}}
	f.sw.awaitSend(t) // the route at B withdrawn
	f.sw.awaitSend(t) // the route at C installed

	assert.Contains(t, f.sw.lookup(t, TableL3Routing, "eth_type=0x800", "ipv4_dst=10.2.0.7"), "tun_dst=10.0.0.3")
	assert.Equal(t, "drop", f.sw.lookup(t, TableVXLANDecap, fromVTEP(ovlL3VNI, ovlVTEPB)...),
		"the old next hop is no longer authorised")
	assert.Equal(t, "goto:20", f.sw.lookup(t, TableVXLANDecap, fromVTEP(ovlL3VNI, ovlVTEPC)...))
	assert.Equal(t, 1, f.handler.GetStatus().PrefixCount)
}

// TestOverlayModeHandler_EVPNIRBRouteTarget checks that a Type-2 route is
// routed over the L3VNI only when it carries the IP-VRF's route target.
func TestOverlayModeHandler_EVPNIRBRouteTarget(t *testing.T) {
	f := newOverlayFixture(t, nil).withVNI(t)
	f.sw.drainSends()

	f.speaker.events <- &bgp.Event{Path: &bgp.Path{EVPN: importable(t, macip(ovlVTEPB, ovlRemoteMAC, ovlRemoteIP), ovlL2VNI)}}
	f.sw.awaitSend(t)

	assert.Equal(t, "set:tun_dst=10.0.0.2,output:7",
		f.sw.lookup(t, TableMACLearning, "tun_id=10100", "eth_dst=02:00:00:00:02:20"), "the MAC is bridged")
	assert.Empty(t, f.sw.matching("t=50 ", "10.1.0.20"), "the host is not routed")
	assert.Equal(t, "drop", f.sw.lookup(t, TableVXLANDecap, fromVTEP(ovlL3VNI, ovlVTEPB)...),
		"the VTEP is not authorised on the L3VNI")
}
