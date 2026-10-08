# EVPN Control Plane

## Overview

EVPN (RFC 7432) over VXLAN (RFC 8365) is the overlay's control plane: each
VTEP tells the others which MACs, MAC/IP bindings and prefixes sit behind it,
and which VNIs it serves. `bgp.EVPNManager` (`pkg/sdn/bgp/evpn.go`) owns the
VTEP's EVPN state; it originates through the speaker and imports what the
speaker's best-path watch delivers. Every route is built and parsed with GoBGP
v4's native constructors (`pkg/sdn/bgp/evpn_codec.go`); the platform has no
hand-rolled EVPN encoding.

| Type | Name | Status |
|------|------|--------|
| 1 | Ethernet Auto-Discovery | not used (single-homed VTEPs) |
| 2 | MAC/IP Advertisement | implemented, symmetric IRB |
| 3 | Inclusive Multicast Ethernet Tag | implemented, ingress replication |
| 4 | Ethernet Segment | not used |
| 5 | IP Prefix (RFC 9136) | implemented, interface-less |

A received Type-1 or Type-4 route is dropped with `ErrUnsupportedRouteType`.

## Topology

VTEPs are iBGP l2vpn-evpn route-reflector clients; the route reflectors run on
the control-plane nodes (`route-reflector: true`, an IPv4 `cluster-id`, and
`route-reflector-client: true` on each VTEP neighbor — see
[configuration.md](configuration.md)). Each session carries its own EVPN prefix
limit, `max-evpn-prefixes` (default 100000), separate from the unicast one.

Routes are originated into the global RIB with an explicit RD and route
targets. GoBGP VRFs are not used: import is decided by the manager from the
route targets of the VNIs it has joined.

## Route distinguishers and route targets

**RD.** Every route carries a Type-1 RD `VTEP-IPv4:index` (RFC 7432 §7.9).
Each EVI (L2VNI) and each IP-VRF (L3VNI) on a VTEP gets its own index, assigned
in join order and reused after a leave: the first EVI joined with an L3VNI gets
`:1` and its IP-VRF `:2`. `EVPNManager.RouteDistinguisher(l2vni)` reports an
EVI's RD. A received route with any other RD type is dropped.

**RT.** Route targets are auto-derived (RFC 8365 §5.1.2.1) as a two-octet
AS-specific RT `ASN:value`, where `ASN` is the private overlay ASN
(`OverlayASN`, 64512–65534) and

```
value = Type(3 bits) = 1 (VXLAN) | D-ID (4 bits) | VNI (24 bits)
      = 1<<28 | DomainID<<24 | VNI
```

so VNI 10100 in domain 0 under ASN 65000 is `65000:268445556`. An EVI exports
and imports its L2VNI's RT; an IP-VRF its L3VNI's RT. `AutoRouteTarget`
returns `ErrRouteTargetInvalid` for an ASN or D-ID out of range and
`ErrInvalidVNI` for a VNI outside 1–16777215. The session policy allowlists
(below) are written in the same `as:value` form.

## Labels

The VNI travels in the 24-bit MPLS label field unshifted (RFC 8365 §5.1.3):
the label bytes on the wire are the raw VNI. This holds for the Type-2 labels,
the Type-5 label and the PMSI tunnel label of the Type-3 route. Every route
carries the BGP Encapsulation community with tunnel type VXLAN.

## Type-3: Inclusive Multicast

`JoinVNI(ctx, l2vni, l3vni)` places the VTEP on an L2VNI: it assigns the EVI
its RD, imports its RT, originates its Type-3 route and imports the routes
already received for the VNI. The route carries a PMSI tunnel attribute of type
ingress replication naming the VTEP, with the VNI as its label. The Type-3
routes received for a VNI form its ingress-replication list,
`RemoteVTEPs(vni)` (sorted). `LeaveVNI` withdraws the EVI's Type-3 route and
its local Type-2 routes, and the IP-VRF's Type-5 routes when no other EVI uses
it.

## Type-2: MAC/IP and symmetric IRB

`AdvertiseMACIP` originates a MAC-only or a MAC/IP route for a MAC learned on
the VTEP. When the EVI was joined with an L3VNI the route is a symmetric-IRB
route: it carries both labels (L2VNI, then L3VNI), both route targets, and the
Router's MAC extended community (`RouterMAC`). Remote routes feed
`RemoteMAC(vni, mac)` and, for ARP suppression, `LookupMACForIP(vni, ip)`.
A received route is imported by its MAC-VRF route target; its L3VNI label and
Router's MAC are taken only when it also carries the route target of the EVI's
IP-VRF (RFC 9135 §5.1). Without it the handlers are told the route with no
L3VNI and no Router's MAC, so the MAC is bridged and not routed.

### MAC Mobility (RFC 7432 §15)

Each Type-2 route carries a MAC Mobility sequence number.

- A VTEP advertising a MAC another VTEP holds uses that VTEP's sequence plus
  one, so its route wins and the other VTEP withdraws (§15.1).
- The highest sequence wins; a tie goes to the lowest VTEP address.
- A remote route that beats the local one withdraws the local routes.
- A MAC that moves `Mobility.MaxMoves` times (default 5) within
  `Mobility.Window` (180s) is a duplicate: it is frozen for `Mobility.Hold`
  (180s), during which received routes for it are ignored and a local
  advertisement fails with `ErrDampeningActive`.

## Type-5: IP Prefix

`AdvertisePrefix(ctx, l3vni, prefix)` originates an interface-less Type-5 route
in the IP-VRF of an L3VNI: the L3VNI label, the IP-VRF's RD and RT, and the
Router's MAC. A received Type-5 route is accepted in the gateway-address model
(a gateway IP, no Router's MAC) or the interface-less model (the Router's MAC).

The manager decodes the gateway IP into `PrefixRoute.GatewayIP` but nothing
acts on it. The overlay data plane routes only the interface-less model
(RFC 9136 §4.4.1): it sends a prefix to the advertising VTEP's Router's MAC,
ignores the gateway IP, and refuses a route without a Router's MAC with
`ErrRouterMACRequired`. A route in the gateway-address model is imported,
but it is never routed.

## Decoding received routes (RFC 7606)

A path whose NLRI does not parse, that is not EVPN, or whose RD is not Type-1
is dropped (`ErrRouteDecodingFailed`). A path whose NLRI parses but whose
attributes are unusable is **treated as a withdrawal** of that NLRI
(`ErrTreatAsWithdraw`): no next hop, no VXLAN encapsulation community, more
than one distinct Router's MAC or MAC Mobility community, a non-unicast
Router's MAC, a label outside the 24-bit VNI range, an L3VNI label without the
Router's MAC, a Type-3 route without an ingress-replication PMSI tunnel naming
an endpoint, or an interface-less Type-5 route without the Router's MAC. The
decoder is fuzzed (`FuzzDecodeEVPNPath`).

Routes the VTEP originated itself (its own RD or next hop) are ignored on
import.

## Route handlers

`RegisterHandler` subscribes the data plane to imported changes: a route when a
MAC, VTEP or prefix becomes reachable or moves, and the same route with
`IsWithdraw` set when it goes. A Type-2 add names where the MAC is now; a
Type-2 withdrawal from the VTEP holding the MAC removes that one binding (the
MAC stays at the VTEP while it advertises others), and the last one the MAC.
A local route displacing a remote one is not reported: the data plane learned
the local MAC itself. A route sent again with a new next hop (Type-2, Type-5)
or a new PMSI tunnel endpoint (Type-3) is reported as the withdrawal of the
route at the old VTEP and then the new route, so the old VTEP is neither
routed to nor authorised. A Type-3 route is named by the originator address in
its NLRI, which its withdrawal also carries; its tunnel endpoint is the PMSI
tunnel's.

Handlers are told the changes **one at a time, in the order they were made**:
received routes on the manager's event goroutine, and synchronously from
`JoinVNI` (the routes already received) and `WithdrawMACIP` (a remote route
taking the MAC back). Every path that changes the imported state holds one
ordering lock from the change until the handlers have been told, so a route
withdrawn while a join waits on BGP is never reported added after its
withdrawal. A VNI being joined imports nothing until its Type-3 route is
advertised; until then it is not joined (`LeaveVNI`, `AdvertiseMACIP` and
`AdvertisePrefix` return `ErrVNINotJoined`). A second `JoinVNI` of that VNI
waits for the first's outcome, or its own context: it returns nil once the
VNI is joined and makes its own attempt when the first was rolled back, so
it is never told a join succeeded that failed. `WithdrawMACIP` tells the handlers
where the MAC went before it withdraws the local route, so a failed withdrawal
(`ErrRouteWithdrawalFailed`) still hands the MAC over. The manager keeps the
route it could not withdraw: calling `WithdrawMACIP` again withdraws it, as
does `LeaveVNI`, and advertising the binding again drops it. Handlers run without the
lock the manager's lookups take, but a handler must not call `JoinVNI`,
`LeaveVNI` or `WithdrawMACIP`.
The overlay data plane that consumes them is
[../gateway/overlay-mode.md](../gateway/overlay-mode.md).

### Session policy: route-target allowlists

What an l2vpn-evpn peer may send and be sent is decided per neighbor by route
target, under `policy` (see [configuration.md](configuration.md)):

```yaml
peers:
  - address: 10.4.0.1
    families: [evpn]
    max-evpn-prefixes: 100000
    policy:
      import-route-targets: ["65000:268445556"]   # admit a route carrying one of these
      export-route-targets: ["65000:268445556"]   # announce a route carrying one of these
```

Both directions default to reject (RFC 8212). A route is admitted when it
carries **at least one** listed route target; an empty list admits nothing, so an
EVPN neighbor without route targets exchanges no EVPN routes. The filter is a
statement in the speaker's global import or export policy, matched on the
neighbor, the l2vpn-evpn family and an extended-community set; GoBGP ignores
per-neighbor policy on anything but a route-server client, which is why the
policy is global (#717). Unicast prefix allowlists never match an EVPN route,
and the route-target statement never admits a unicast one.

`max-evpn-prefixes` is the session's EVPN route limit, separate from the
unicast `max-prefixes`; size it to VTEPs x MACs. The default is 100000.

## Tests

`pkg/sdn/bgp/evpn_session_test.go` runs three in-process GoBGP speakers — a
route reflector and two VTEPs on loopback — and proves Type-2/3/5 exchange with
the derived RDs and RTs, a VNI using all 24 label bits, both VNIs and the Router's MAC on a
symmetric-IRB Type-2 route, a MAC moving A→B→A with sequence numbers 1 and 2,
and 1200 MACs reflected across the session. `evpn_codec_test.go` checks the
label bytes on the wire.
