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
	"encoding/binary"
	"net"
	"net/netip"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
)

// OverlayCookie is the owner id of every flow the overlay handler installs:
// gatewayd's 0xF1BE prefix with the overlay's 0x0005, beside the pipeline
// (0xF1BE0000), firewall (0xF1BE0001), NAT (0xF1BE0002), load balancer
// (0xF1BE0003), NAT64 (0xF1BE0004) and perf (0xF1BE00FF) owners. Each Start
// stamps a fresh flow generation in the low 32 bits (ovs.NewGenerationCookie),
// so the flows a killed predecessor left are told apart from the successor's
// by cookie alone (#557). Stop deletes under ovs.OwnerCookieMask, every
// generation.
const OverlayCookie uint64 = 0xF1BE000500000000

// legacyOverlayCookie is the exact cookie every overlay flow carried before
// flows were stamped with generations (#557). Its owner bits are the
// pipeline's, so neither the generation sweep's owner match nor Stop's
// selects it. It is kept so a gatewayd upgraded over OVS state an older
// release left deletes those flows by exact cookie, with the stale
// generations, rather than keeping unrelearned host flows and VTEP decap
// authorisations for ever.
const legacyOverlayCookie uint64 = 0xF1BE000000000005

// OverlayNDCookie tags the overlay's ND punt flows, which the ND controller
// owns apart from every other overlay flow: they expire unless it refreshes
// them, and it removes them alone when it falls back to the flood. It
// carries no generation: the controller routes packet-ins by this exact
// cookie, so a successor answers, or floods, the solicitations its
// predecessor's punts send it until they lapse or it refreshes them.
const OverlayNDCookie uint64 = 0xF1BE000600000000

// Flow priorities of the overlay pipeline. Within a table a more specific
// purpose outranks a broader one; priority 0 is each table's miss.
const (
	// Table 10: an authorised decap outranks the drop of every other
	// tunnelled frame, which outranks access ingress. All three outrank
	// the services' table-10 gates (priority 1-2), so no gate lets an
	// unauthorised tunnelled frame through.
	priorityDecapAllow    uint16 = 300
	priorityDecapDrop     uint16 = 200
	priorityAccessIngress uint16 = 100

	// Table 30: frames for the gateway's own MAC route before any MAC
	// lookup. A tunnelled frame for the anycast gateway MAC is dropped:
	// its ingress VTEP routes it, and only the L3VNI's router MAC flow,
	// which outranks the drop, routes frames from VTEPs.
	priorityRouterMAC     uint16 = 300
	priorityRemoteGateway uint16 = 250
	priorityHostMAC       uint16 = 200

	// Table 40: a DAD probe floods before any punt can take it.
	priorityNDDAD    uint16 = 210
	priorityARPReply uint16 = 200
	priorityNDPunt   uint16 = 200

	// Table 50: host routes outrank every prefix route; a prefix route
	// sits at priorityPrefixBase plus its length, so the longest wins.
	priorityHostRoute  uint16 = 200
	priorityPrefixBase uint16 = 100

	// Table 60.
	priorityFlood uint16 = 100

	// Table 70: a frame going back to the access port it came in on.
	priorityHairpin uint16 = 100

	priorityMiss uint16 = 0
)

// Ethernet types and the ARP opcode the pipeline matches and writes.
const (
	ethTypeIPv4 uint16 = 0x0800
	ethTypeARP  uint16 = 0x0806
	ethTypeIPv6 uint16 = 0x86dd
	ethTypeVLAN uint16 = 0x8100
	arpRequest  uint16 = 1
	arpReply    uint16 = 2

	ipProtoICMPv6 uint8 = 58
	icmpv6NS      uint8 = 135
)

// overlayPorts are the OpenFlow numbers of the two ports the overlay
// forwards between: the flow-based VXLAN port and the access trunk that
// carries every local VNI as a VLAN.
type overlayPorts struct {
	vxlan  uint32
	access uint32
}

// flowBuilder turns overlay state into flows. Its methods are pure: the
// same input always yields the same flows, which is what lets flowTable
// diff them.
type flowBuilder struct {
	ports overlayPorts

	// cookie is the overlay's owner id with this start's flow generation.
	cookie uint64

	// anycastIPs, per L2VNI, and anycastMAC are the distributed gateway;
	// empty and nil when routing is off.
	anycastIPs map[uint32]netip.Addr
	anycastMAC net.HardwareAddr

	// l3vni and routerMAC are the IP-VRF of symmetric IRB; zero and nil
	// when it is off.
	l3vni     uint32
	routerMAC net.HardwareAddr

	// arpSuppression answers ARP for every known binding, not only the
	// gateway.
	arpSuppression bool

	// arpSwap turns an ARP request into the reply's addressing: the
	// requester becomes the target.
	arpSwap []openflow.Action

	// ndPuntAction sends a neighbor solicitation to the controller through
	// the ND meter.
	ndPuntAction openflow.Action
}

// newFlowBuilder builds the ARP rewrite once; a field-width mismatch there
// is a programming error the constructor reports rather than hides.
func newFlowBuilder(cfg *OverlayModeConfig, ports overlayPorts, cookie uint64) (*flowBuilder, error) {
	moves := [][2]uint32{
		{openflow.OXMHeader(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBEthSrc, 6),
			openflow.OXMHeader(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBEthDst, 6)},
		{openflow.OXMHeader(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBArpSha, 6),
			openflow.OXMHeader(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBArpTha, 6)},
		{openflow.OXMHeader(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBArpSpa, 4),
			openflow.OXMHeader(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBArpTpa, 4)},
	}
	b := &flowBuilder{
		ports:          ports,
		cookie:         cookie,
		anycastIPs:     cfg.AnycastGateways,
		anycastMAC:     cfg.AnycastGatewayMAC,
		l3vni:          cfg.L3VNI,
		arpSuppression: cfg.ARPSuppression,
	}
	punt, err := openflow.NewActionController2(overlayNDMeterID)
	if err != nil {
		return nil, err
	}
	b.ndPuntAction = punt
	if cfg.L3VNI != 0 {
		b.routerMAC = cfg.EVPNConfig.RouterMAC
	}
	for _, m := range moves {
		move, err := openflow.NewActionRegMove(m[0], m[1])
		if err != nil {
			return nil, err
		}
		b.arpSwap = append(b.arpSwap, move)
	}
	return b, nil
}

// routes reports whether vni is routed. Only a VNI with an anycast gateway
// is, so a bridge-only VNI beside routed ones stays bridged.
func (b *flowBuilder) routes(vni uint32) bool {
	_, ok := b.anycastIPs[vni]
	return ok
}

// flow builds one overlay flow; a nil match matches everything and no
// instructions drop.
func (b *flowBuilder) flow(table uint8, priority uint16, match *openflow.Match, instructions ...openflow.Instruction) *openflow.FlowMod {
	f := openflow.NewFlowMod(0)
	f.Cookie = b.cookie
	f.TableID = table
	f.Priority = priority
	if match != nil {
		f.Match = match
	}
	f.Instructions = instructions
	return f
}

// base is the pipeline every overlay frame runs through, before any VNI
// or route exists.
//
//	0   → 10
//	10  tunnelled and not authorised → drop; otherwise → 30
//	20  (the services' conntrack gate) miss → 30
//	30  router MAC on the L3VNI → 50 (and, from segment, the gateway MAC
//	    from access on a routed VNI); gateway MAC from a VTEP → drop;
//	    miss → 40
//	40  a DAD probe from access → 60, outranking every ND punt; miss → 60
//	50  miss → drop: a routed frame without a route
//	60  miss → drop: a frame with no segment to flood in
//	70  back out the access port, or out IN_PORT when it came from there
func (b *flowBuilder) base() []*openflow.FlowMod {
	fromVXLAN := openflow.NewMatch()
	fromVXLAN.AddInPort(b.ports.vxlan)

	fromAccess := openflow.NewMatch()
	fromAccess.AddInPort(b.ports.access)

	flows := []*openflow.FlowMod{
		b.flow(TableIngress, priorityMiss, nil, openflow.NewInstructionGotoTable(TableVXLANDecap)),
		b.flow(TableVXLANDecap, priorityDecapDrop, fromVXLAN),
		b.flow(TableVXLANDecap, priorityMiss, nil, openflow.NewInstructionGotoTable(TableMACLearning)),
		b.flow(TableCTGate, priorityMiss, nil, openflow.NewInstructionGotoTable(TableMACLearning)),
		b.flow(TableMACLearning, priorityMiss, nil, openflow.NewInstructionGotoTable(TableARP)),
		b.flow(TableARP, priorityNDDAD, b.dadProbe(), openflow.NewInstructionGotoTable(TableEgress)),
		b.flow(TableARP, priorityMiss, nil, openflow.NewInstructionGotoTable(TableEgress)),
		b.flow(TableL3Routing, priorityMiss, nil),
		b.flow(TableEgress, priorityMiss, nil),
		b.flow(TableLocalDelivery, priorityHairpin, fromAccess,
			openflow.NewInstructionApplyActions(openflow.NewActionOutput(openflow.OFPPInPort, 0))),
		b.flow(TableLocalDelivery, priorityMiss, nil,
			openflow.NewInstructionApplyActions(openflow.NewActionOutput(b.ports.access, 0))),
	}
	if b.anycastMAC != nil {
		// Every VTEP answers for the gateway itself, so a frame for it that
		// arrives tunnelled is dropped on whichever VNI carries it.
		tunnelledToGateway := openflow.NewMatch()
		tunnelledToGateway.AddInPort(b.ports.vxlan)
		tunnelledToGateway.AddEthDst(b.anycastMAC)
		flows = append(flows, b.flow(TableMACLearning, priorityRemoteGateway, tunnelledToGateway))
	}
	if b.l3vni != 0 {
		toRouter := openflow.NewMatch()
		toRouter.AddTunnelID(uint64(b.l3vni))
		toRouter.AddEthDst(b.routerMAC)
		flows = append(flows, b.flow(TableMACLearning, priorityRouterMAC, toRouter,
			openflow.NewInstructionGotoTable(TableL3Routing)))
	}
	return flows
}

// segment is the flows of one L2VNI: access ingress onto the segment, the
// gateway's ARP reply, ingress replication to every VTEP placed on it, and
// the decap authorisation of each of those VTEPs.
func (b *flowBuilder) segment(vni uint32, s *overlaySegment) []*openflow.FlowMod {
	ingress := openflow.NewMatch()
	ingress.AddInPort(b.ports.access)
	ingress.AddVLANVid(s.vlan)

	onSegment := openflow.NewMatch()
	onSegment.AddTunnelID(uint64(vni))

	// Deliver locally first: OpenFlow never outputs to the ingress port,
	// so a frame from the access port reaches only the VTEPs and a frame
	// from the VXLAN port only the access port — split horizon.
	flood := append([]openflow.Action{
		openflow.NewActionPushVLAN(ethTypeVLAN),
		openflow.NewActionSetField(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBVlanVid, encodeVLAN(s.vlan)),
		openflow.NewActionOutput(b.ports.access, 0),
		openflow.NewActionPopVLAN(),
	}, b.vtepFlood(s)...)

	flows := []*openflow.FlowMod{
		b.flow(TableVXLANDecap, priorityAccessIngress, ingress,
			openflow.NewInstructionApplyActions(
				openflow.NewActionPopVLAN(),
				openflow.NewActionSetTunnelID(uint64(vni))),
			openflow.NewInstructionGotoTable(TableCTGate)),
		b.flow(TableEgress, priorityFlood, onSegment, openflow.NewInstructionApplyActions(flood...)),
	}
	if gateway, ok := b.anycastIPs[vni]; ok {
		// Only a routed VNI's frames for the gateway MAC enter routing.
		toGateway := openflow.NewMatch()
		toGateway.AddInPort(b.ports.access)
		toGateway.AddTunnelID(uint64(vni))
		toGateway.AddEthDst(b.anycastMAC)
		flows = append(flows,
			b.flow(TableMACLearning, priorityRouterMAC, toGateway, openflow.NewInstructionGotoTable(TableL3Routing)),
			b.arpReply(vni, s.vlan, gateway, b.anycastMAC))
	}
	for _, vtep := range s.flood {
		flows = append(flows, b.decapAllow(vni, vtep))
	}
	return flows
}

// vtepFlood is ingress replication: one copy to every VTEP placed on the
// segment.
func (b *flowBuilder) vtepFlood(s *overlaySegment) []openflow.Action {
	flood := make([]openflow.Action, 0, 2*len(s.flood))
	for _, vtep := range s.flood {
		flood = append(flood,
			openflow.NewActionSetTunDst(vtep),
			openflow.NewActionOutput(b.ports.vxlan, 0))
	}
	return flood
}

// decapAllow admits frames tunnelled from vtep on vni. They join the
// pipeline at the services' gate, as access traffic does.
func (b *flowBuilder) decapAllow(vni uint32, vtep netip.Addr) *openflow.FlowMod {
	match := openflow.NewMatch()
	match.AddInPort(b.ports.vxlan)
	match.AddTunnelID(uint64(vni))
	match.AddTunIPv4Src(vtep)
	return b.flow(TableVXLANDecap, priorityDecapAllow, match, openflow.NewInstructionGotoTable(TableCTGate))
}

// arpReply answers, in the switch, an ARP request from the access port
// for ip on vni with mac, sending the reply back out the port it came in
// on, tagged with the segment's VLAN.
func (b *flowBuilder) arpReply(vni uint32, vlan uint16, ip netip.Addr, mac net.HardwareAddr) *openflow.FlowMod {
	match := openflow.NewMatch()
	match.AddInPort(b.ports.access)
	match.AddTunnelID(uint64(vni))
	match.AddEthType(ethTypeARP)
	match.AddField(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBArpOp, uint16Bytes(arpRequest), nil)
	ip4 := ip.As4()
	match.AddField(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBArpTpa, ip4[:], nil)

	actions := []openflow.Action{
		b.arpSwap[0], // eth_src -> eth_dst
		openflow.NewActionSetField(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBEthSrc, mac),
		openflow.NewActionSetField(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBArpOp, uint16Bytes(arpReply)),
		b.arpSwap[1], // arp_sha -> arp_tha
		openflow.NewActionSetField(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBArpSha, mac),
		b.arpSwap[2], // arp_spa -> arp_tpa
		openflow.NewActionSetField(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBArpSpa, ip4[:]),
		openflow.NewActionPushVLAN(ethTypeVLAN),
		openflow.NewActionSetField(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBVlanVid, encodeVLAN(vlan)),
		openflow.NewActionOutput(openflow.OFPPInPort, 0),
	}
	return b.flow(TableARP, priorityARPReply, match, openflow.NewInstructionApplyActions(actions...))
}

// ndPunt sends a neighbor solicitation from the access port for target on
// vni to the controller, which answers it, instead of flooding it. The meter
// rides on the controller action. The flow carries a hard timeout, which
// the controller refreshes: a controller that dies without removing it
// stops taking the solicitations from the flood for no longer than that.
// The ND controller owns these flows, not the flow table; host flows do not
// include them.
func (b *flowBuilder) ndPunt(vni uint32, target netip.Addr) *openflow.FlowMod {
	match := b.solicitation()
	match.AddTunnelID(uint64(vni))
	targetBytes := target.As16()
	match.AddField(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBIPv6NdTarget, targetBytes[:], nil)

	f := b.flow(TableARP, priorityNDPunt, match, openflow.NewInstructionApplyActions(b.ndPuntAction))
	f.Cookie = OverlayNDCookie
	f.HardTimeout = overlayNDPuntHardTimeout
	return f
}

// dadProbe matches a duplicate address detection probe from the access
// port: a solicitation from the unspecified address. The owner must defend
// its address, so a probe is never answered and always floods.
func (b *flowBuilder) dadProbe() *openflow.Match {
	match := b.solicitation()
	unspecified := netip.IPv6Unspecified().As16()
	match.AddField(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBIPv6Src, unspecified[:], nil)
	return match
}

// solicitation matches a neighbor solicitation from the access port.
func (b *flowBuilder) solicitation() *openflow.Match {
	match := openflow.NewMatch()
	match.AddInPort(b.ports.access)
	match.AddEthType(ethTypeIPv6)
	match.AddIPProto(ipProtoICMPv6)
	match.AddField(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBICMPv6Type, []byte{icmpv6NS}, nil)
	return match
}

// host is the flows of one MAC on vni: bridging to it, the ARP replies for
// its IPv4 bindings and, on a routed VNI, a host route to each. A local host
// is reached on the access port, a remote one through its VTEP.
func (b *flowBuilder) host(vni uint32, vlan uint16, h *overlayHost) []*openflow.FlowMod {
	toMAC := openflow.NewMatch()
	toMAC.AddTunnelID(uint64(vni))
	toMAC.AddEthDst(h.mac)

	var flows []*openflow.FlowMod
	if h.local() {
		flows = append(flows, b.flow(TableMACLearning, priorityHostMAC, toMAC,
			openflow.NewInstructionApplyActions(b.tagFor(vlan)...),
			openflow.NewInstructionGotoTable(TableLocalDelivery)))
	} else {
		flows = append(flows, b.flow(TableMACLearning, priorityHostMAC, toMAC,
			openflow.NewInstructionApplyActions(
				openflow.NewActionSetTunDst(h.vtep),
				openflow.NewActionOutput(b.ports.vxlan, 0))))
	}

	for _, ip := range h.sortedIPs() {
		if !ip.Is4() {
			continue
		}
		if b.arpSuppression {
			flows = append(flows, b.arpReply(vni, vlan, ip, h.mac))
		}
		if !b.routes(vni) {
			continue
		}
		if h.local() {
			flows = append(flows, b.localRoute(ip, vlan, h.mac))
			continue
		}
		if irb := h.ips[ip]; routable(b.l3vni, irb) {
			flows = append(flows,
				b.remoteRoute(netip.PrefixFrom(ip, 32), priorityHostRoute, h.vtep, irb.routerMAC),
				b.decapAllow(b.l3vni, h.vtep))
		}
	}
	return flows
}

// prefix is the flows of a Type-5 route: a route to the prefix through
// its VTEP, and the decap authorisation of that VTEP on the L3VNI.
func (b *flowBuilder) prefix(p netip.Prefix, r *overlayPrefixRoute) []*openflow.FlowMod {
	return []*openflow.FlowMod{
		b.remoteRoute(p, priorityPrefixBase+uint16(p.Bits()), r.vtep, r.routerMAC),
		b.decapAllow(b.l3vni, r.vtep),
	}
}

// localRoute routes to a host on this VTEP: it leaves the gateway as a
// frame from the anycast MAC on the host's segment.
func (b *flowBuilder) localRoute(ip netip.Addr, vlan uint16, mac net.HardwareAddr) *openflow.FlowMod {
	actions := append([]openflow.Action{
		openflow.NewActionDecNwTTL(),
		openflow.NewActionSetField(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBEthSrc, b.anycastMAC),
		openflow.NewActionSetField(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBEthDst, mac),
	}, b.tagFor(vlan)...)
	return b.flow(TableL3Routing, priorityHostRoute, b.ipv4Dst(netip.PrefixFrom(ip, 32)),
		openflow.NewInstructionApplyActions(actions...),
		openflow.NewInstructionGotoTable(TableLocalDelivery))
}

// remoteRoute routes to dst through a remote VTEP over the L3VNI
// (symmetric IRB): router MAC to router MAC, the remote VTEP routing the
// last hop.
func (b *flowBuilder) remoteRoute(dst netip.Prefix, priority uint16, vtep netip.Addr, remoteRouterMAC net.HardwareAddr) *openflow.FlowMod {
	return b.flow(TableL3Routing, priority, b.ipv4Dst(dst),
		openflow.NewInstructionApplyActions(
			openflow.NewActionDecNwTTL(),
			openflow.NewActionSetField(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBEthSrc, b.routerMAC),
			openflow.NewActionSetField(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBEthDst, remoteRouterMAC),
			openflow.NewActionSetTunnelID(uint64(b.l3vni)),
			openflow.NewActionSetTunDst(vtep),
			openflow.NewActionOutput(b.ports.vxlan, 0)))
}

// ipv4Dst matches IPv4 frames to dst; a /32 matches the address exactly.
func (b *flowBuilder) ipv4Dst(dst netip.Prefix) *openflow.Match {
	match := openflow.NewMatch()
	match.AddEthType(ethTypeIPv4)
	addr := dst.Addr().As4()
	if dst.Bits() == 32 {
		match.AddIPv4Dst(net.IP(addr[:]))
		return match
	}
	match.AddIPv4DstMasked(net.IP(addr[:]), net.CIDRMask(dst.Bits(), 32))
	return match
}

// tagFor tags a frame with a segment's VLAN for the access port.
func (b *flowBuilder) tagFor(vlan uint16) []openflow.Action {
	return []openflow.Action{
		openflow.NewActionPushVLAN(ethTypeVLAN),
		openflow.NewActionSetField(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBVlanVid, encodeVLAN(vlan)),
	}
}

// encodeVLAN encodes a VLAN ID with the OFPVID_PRESENT bit.
func encodeVLAN(vlan uint16) []byte {
	return uint16Bytes(vlan | 0x1000)
}

// uint16Bytes encodes v in network byte order.
func uint16Bytes(v uint16) []byte {
	return binary.BigEndian.AppendUint16(nil, v)
}
