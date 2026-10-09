# SDN Overlay Mode

## Overview

Overlay mode (`pkg/sdn/gateway/modes`, `OverlayModeHandler`) makes a node a
VXLAN Tunnel Endpoint. It forwards between one local access port, which
carries every local VNI as a VLAN, and remote VTEPs. Everything is driven
by EVPN routes:

| Route | Becomes |
|-------|---------|
| Type-2 MAC/IP | MAC forwarding to the VTEP; the binding's ARP reply; its IRB host route |
| Type-3 IMET | ingress replication to the VTEP; decap authorisation of the VTEP on the VNI |
| Type-5 IP prefix | a prefix route through the VTEP over the L3VNI |

The route formats, RD/RT derivation and MAC Mobility rules are in
[../bgp/evpn.md](../bgp/evpn.md). The VXLAN port is described in
[../overlay/architecture.md](../overlay/architecture.md).

Everything the handler does is OpenFlow on one bridge: there is no
packet-in path, no controller-side ARP handling and no kernel VXLAN device
per peer.

## Data Plane

### One flow-based VXLAN port

`Start` creates one VXLAN port per bridge with `remote_ip=flow` and
`key=flow`: the flows set the tunnel destination (`set_field:tun_dst`) and
VNI (`set_field:tun_id`) of each frame they send to it, and match the VNI
(`tun_id`) and source VTEP (`tun_src`) of each frame received on it. A new
remote VTEP is a flow change, never a port change.

The underlay must carry 9000-byte inner frames: the VTEP config refuses an
underlay MTU below 9050 bytes (`vxlan.MinimumUnderlayMTU`: the 9000-byte
`vxlan.OverlayMTU` plus 50 bytes of encapsulation).

### Pipeline

| Table | Name | Function |
|-------|------|----------|
| 0 | Ingress | everything → 10 |
| 10 | VXLAN decap | access ingress (VLAN → VNI); decap authorisation; every other tunnelled frame dropped |
| 20–29 | Services | NAT64 (firewall, NAT and load balancer are refused beside the overlay); miss → 30 |
| 30 | MAC | anycast MAC from the access port, or router MAC on the L3VNI → 50; anycast MAC from a VTEP → drop; known MAC → its VTEP or 70; miss → 40 |
| 40 | ARP | ARP replies in the switch; miss → 60 |
| 50 | L3 | host and prefix routes (symmetric IRB); miss → drop |
| 60 | Egress | flood: the access port, then every VTEP on the VNI; miss → drop |
| 70 | Local delivery | out the access port (`IN_PORT` when it came from there) |

Every overlay flow carries `OverlayCookie` (`0xF1BE000000000005`); `Start`
and `Stop` remove them with one cookie-scoped delete.

### Decap authorisation

A tunnelled frame enters the pipeline only through a table-10 flow
matching `in_port=vxlan, tun_id=<VNI>, tun_src=<VTEP>` (priority 300). Any
other frame from the VXLAN port hits the drop at priority 200. A VTEP is
authorised:

- on an L2VNI, while its Type-3 route places it there;
- on the L3VNI, while one of its Type-2 IRB bindings or a Type-5 route it
  carries is installed.

So a VTEP can inject only into the VNIs EVPN says it serves. Before a
route is installed the handler asks the configured `VTEPAdmitter` whether
the VTEP may carry the VNI; a refusal leaves the route uninstalled and is
returned as `ErrVTEPOperationFailed{Operation: "admit"}`. The admitter is
required with EVPN: a config with `EVPNConfig` and no `Admitter` is refused
with `ErrAdmitterNil`, so no route is ever installed unvetted.

`RevokeVTEP` withdraws every route a VTEP has installed through the same
route handlers an EVPN withdrawal uses. It also bumps the VTEP's revocation
epoch under the handler lock; a route handler reads the epoch before it asks
the admitter and installs only while it is unchanged. A route admitted just
before a revocation therefore fails with `ErrVTEPRevoked` instead of
re-installing the decap the revocation removed. A withdrawal the switch
refuses does not stop the others: every route is tried and the failures are
joined.

A Type-2 route may not claim an address this VTEP answers for. Its ARP
reply and host route would share a flow identity with the gateway's or a
local host's and take their traffic.

- A route claiming the anycast gateway's MAC or IP is refused whole and
  never retried. The handler logs a warning, counts it in
  `OverlayModeStatus.RefusedBindings`, and returns
  `ErrMACOperationFailed{Operation: "install remote"}` wrapping an
  `ErrBindingConflict` that names the owner.
- A route claiming an IP a local host holds on any VNI is held back, not
  refused. It still bridges its MAC to the advertising VTEP; only its ARP
  reply and host route wait. It is logged and counted the same way, and
  `LookupMAC` lists the MAC without the held IP. When the local host goes
  (`ForgetMAC`, `RemoveVNI` of its VNI, or the MAC moving to a remote
  VTEP), every held binding no local host still answers for is applied. A
  failure to apply one is returned as `ErrMACOperationFailed{Operation:
  "release held"}`, and the binding stays held until the next route for
  that MAC. A withdrawal drops a held binding like any other.

This is what keeps a VM that comes back on another VTEP with a new MAC (a
rebuilt VM, a failover VIP) reachable before its old local entry is
forgotten. A route for a MAC local on the same VNI is no conflict: that is
the MAC moving away, which MAC Mobility has already settled.

### BUM traffic

Ingress replication, from Type-3 routes: the VNI's table-60 flow outputs
the frame to the access port (VLAN-tagged), then once per remote VTEP on
the VNI. OpenFlow never outputs to a frame's ingress port, which gives
split horizon: a flooded frame from a VTEP is never sent back into the
fabric, and a local one never back to the access port.

### ARP suppression

ARP requests from the access port for the anycast gateway — and, with
`ARPSuppression`, for every known IPv4 binding, local or remote — are
answered by a table-40 flow that rewrites the request into the reply and
sends it back out `IN_PORT`. Unanswered ARP floods like other BUM traffic.

### Symmetric IRB

With `AnycastGatewayIP`/`AnycastGatewayMAC`, every VTEP is the same
gateway: frames from the access port to the anycast MAC go to table 50. A
tunnelled frame to the anycast MAC is dropped: its ingress VTEP routes it,
so it never needs this one's gateway, and routing it here would let any VTEP
authorised on an L2VNI reach table 50 without the L3VNI's decap
authorisation.

- A local host route rewrites the MACs (anycast MAC → host MAC), tags the
  host's VLAN and delivers locally.
- With an `L3VNI` and the EVPN router MAC, a remote host route (from a
  Type-2 route naming the same L3VNI and a router MAC) or a Type-5 prefix
  route sends the frame router MAC to router MAC on the L3VNI to the
  remote VTEP, which routes the last hop. Frames arriving on the L3VNI
  for this VTEP's router MAC go to table 50.

Host routes outrank prefix routes; among prefixes the longest wins. When
several VTEPs advertise one prefix, the lowest VTEP address carries it and
a withdrawal falls back to the next. Only IPv4 is routed.

## Control Plane

| Handler call | EVPN action |
|--------------|-------------|
| `AddVNI(vni, vlan)` | segment flows installed, then `JoinVNI(vni, L3VNI)`: the Type-3 route is originated and the routes already received are replayed. A refused join removes the segment again |
| `RemoveVNI(vni)` | `LeaveVNI(vni)`, then everything on the VNI is removed — and the Type-5 prefixes with the last VNI |
| `LearnMAC(vni, mac, ip)` | local delivery flows installed, then `AdvertiseMACIP`. A failed advertisement leaves the flows; learning again retries it |
| `ForgetMAC(vni, mac)` | local flows removed, then `WithdrawMACIP` for each binding. A withdrawal BGP refuses fails the call and is remembered; forgetting the MAC again retries it until BGP takes it, and `RemoveVNI` or `Stop` withdraws it with the VNI. Learning the binding again drops it |
| imported route change | the registered handler installs or removes the flows above |

A switch can apply part of a flow batch and refuse the rest
(`openflow.ErrBatchPartialFailure`). When it refuses any of a change, the
handler sends the mods that put every flow the batch touched back to what
it had committed, so the switch and the handler's state are as they were
and the operation or route can be applied again. A refused start flushes
the overlay flows instead. If the switch refuses the put-back too, the
error carries an `ErrFlowResyncFailed`: the switch may then hold flows the
handler does not track. The handler marks its flows drifted, and the next
change of any kind first flushes the overlay's flows (by cookie) and
installs every flow it has committed, so stale flows such as a decap
authorisation do not survive. A switch refusing that rebuild fails the
change with an `ErrFlowResyncFailed`, and the rebuild is tried again on
the change after. The OpenFlow client has no reconnect hook, so a
reconnect alone does not trigger the rebuild; the next change does.

OVS applies a batch one mod at a time, not atomically, and the OpenFlow
client has no bundle support, so the start and the rebuild send the flows
after the flush in a fail-closed order, the same on every rebuild: the
pipeline's last table first, so a goto only ever reaches a table that is
already complete and the table-0 goto that admits frames comes last, and
within a table the highest priority first, so the table-10 drop of
unauthorised tunnelled frames is in place before the table's miss. No
tunnelled frame from an unauthorised VTEP passes while a batch is landing.

Flows several objects need — every host behind one VTEP needs that VTEP's
L3VNI decap flow — are reference counted: installed with the first and
deleted with the last. Holders of one flow can disagree on what it does;
the handler keeps each holder's version, installs the newest, and when the
installed version's last holder lets go, installs the newest version still
held rather than deleting the flow.

## Configuration

`OverlayModeConfig`:

| Field | Meaning |
|-------|---------|
| `VTEPConfig` | local IPv4 VTEP, underlay interface and MTU, VXLAN UDP port |
| `EVPNConfig` | EVPN manager; nil bridges local hosts only |
| `BridgeName`, `AccessPort` | the bridge, and the port carrying the VNIs as VLANs |
| `ARPSuppression` | answer ARP for every known binding |
| `AnycastGatewayIP`, `AnycastGatewayMAC` | both or neither; turns on routing |
| `L3VNI` | the IP-VRF of symmetric IRB; needs the anycast gateway and `EVPNConfig.RouterMAC` |
| `Admitter` | vets remote VTEPs; required with `EVPNConfig` (`ErrAdmitterNil`) |

## In gatewayd

The `gateway.overlay` section runs this handler in gatewayd. It carries the
VTEP address, underlay interface/MTU, access port, overlay ASN, RR peers and
the admission settings below. The OpenFlow table hand-off goes through
`TerminalOverlay`: gatewayd records bridge ownership and secure fail-mode but
installs no pipeline-cookie defaults, so the overlay handler is the only owner
of the table-0, 10, 20, 30, 40, 50, 60 and 70 miss entries.

The overlay is refused beside the firewall, NAT or load balancer
(`ErrOverlayServiceConflict`). Those services lay their flows out for the
NORMAL terminal (NAT, for one, installs a table-10 miss), and under this
pipeline the table-10 miss is what drops tunnelled frames from unadmitted
VTEPs. NAT64 hands off through tables 20-29 and may run beside it.

| Field | Default | Meaning |
|-------|---------|---------|
| `overlay-asn` | required | private 2-octet ASN (64512-65534); the auto-derived route targets carry it in a 2-octet field |
| `vnis` | required | the L2VNIs joined at start: each `vni` (1-16777215) with the access-port `vlan` (1-4094) that carries it. At least one, at most `max-vnis`; no VNI or VLAN repeats |
| `default-vni` | none | must be one of `vnis` |
| `verdict-max-age` | 15m | oldest attestation verdict that still admits a VTEP |
| `verdict-clock-skew` | 30s | how far past the gateway's clock a verdict's attestation time may lie |
| `admission-sweep-interval` | 30s | period of the re-admission sweep |

A field that fails validation is reported as `ErrOverlayConfigInvalid`, naming
the YAML key.

Start joins every entry of `vnis` (`AddVNI`, which with RR peers also joins it
in EVPN) before the service counts as running. A join that fails stops the
handler and the speaker again and fails the start with the join's error, so
nothing is left half-running. The service is healthy only while the handler
runs and carries every configured VNI: a running handler with no VNI forwards
nothing, and used to report healthy anyway.

### VTEP admission

`gateway.VTEPAdmitter` decides whether a remote VTEP may hold decap state. In
order:

1. The VTEP address is a fabric-zone IPAM allocation, and the allocation names
   a numeric device ID.
2. The platform holds that device.
3. The device's latest recorded verdict passed against a signed baseline.
4. The verdict's attestation time is set, at most `verdict-clock-skew` ahead
   of the gateway's clock, and at most `verdict-max-age` old. A verdict without
   an attestation time is refused, not dated by when it was recorded.
5. The verdict names the device's serial whenever the device record has one.

A missing record (allocation, device or verdict) is a denial. Any other read
error is an outage (`ErrOverlayAdmissionUnavailable`). The route is refused
for now, but the error is not a judgement on the VTEP.

gatewayd reads all three records from platformd over the SDK. EVPN hands
routes to handlers one at a time, so the fabric allocations are kept in an
index keyed by address, and a route for an indexed VTEP makes no IPAM call.
An address missing from the index makes gatewayd list the fabric pools again.
Concurrent misses share one listing. Each sweep refreshes the index, so a
released allocation leaves it within one interval. A failed listing keeps the
previous index. The verdict's attestation time is the report's `attested_at`
and nothing else; when the report was collected or served is not used.

### Re-admission sweep

Every `admission-sweep-interval` the sweep reads the handler's installed set
(`InstalledVTEPs`: every remote VTEP with flood-list, host or prefix state)
and runs admission again for each VTEP. Policy does not depend on the VNI, so
one decision covers all of a VTEP's VNIs. A denial revokes the VTEP
(`RevokeVTEP`), so a verdict that ages past `verdict-max-age` or turns failed,
cryptographically or not, withdraws decap within one interval. An outage keeps
the VTEP only while its last admitting verdict is still within
`verdict-max-age`; after that the VTEP is revoked. A revocation that fails
does not stop the sweep: every failure is joined into the sweep's error and
logged.

The sweep then runs admission for every refused VTEP (`RefusedVTEPs`: each
remote VTEP a route was refused or revoked from that the EVPN manager still
holds routes for) and replays the routes of each one it now admits. BGP does
not send an unchanged route again, so a route refused before its device had a
passing verdict is installed only by a replay.

`ListAdmittedVTEPs` reports this installed set, with the verdict behind each
admission.

### Replaying refused routes

The overlay handler marks a VTEP refused whenever admission refuses one of its
routes, a revocation lands during a route's admission, or the VTEP is revoked.
`ReplayVTEP` hands the routes the EVPN manager holds from that VTEP (its IMET
and prefix routes, and each MAC route at the VTEP the MAC is active at) back
through the same route handlers, which run admission again. The replay holds
the EVPN manager's notification lock, as every route change does, so a
withdrawal received meanwhile is never undone by a replay of the route it
withdrew. A replay that fails leaves the VTEP refused for the next one. A
refused VTEP whose routes have all been withdrawn is forgotten.

### Revocation on a failed verdict

gatewayd does not wait for the sweep when a device's attestation fails. It
follows platformd's device verdict stream
(`AttestationService.StreamDeviceVerdicts`, over the same gRPC or Unix
connection it reads the records on), which carries every verdict platformd
records (see [Device verdict events](../../attestation/engineering.md#device-verdict-events)).
gatewayd authenticates by its Unix-socket peer or its mTLS certificate, so it
sees every tenant's devices; a tenant's token sees only that tenant's.
A failed verdict, cryptographic or an absence of evidence, makes gatewayd
revoke every VTEP of the device at once (`VTEPAdmitter.RevokeDevice`): the
VTEPs it admitted for the device, and the device's fabric allocations. A
passed verdict replays every refused VTEP among the device's fabric
allocations that admission now lets in, so a device attested after its routes
arrived is brought up without waiting for the sweep. The admitter reads the
verdict back from platformd rather than trusting the event, so a passing event
whose record is not yet readable replays nothing and the sweep brings the
device up instead.

The stream does not replay what was recorded while gatewayd was disconnected,
and platformd cuts gatewayd off if it falls more than 64 verdicts behind.
gatewayd follows a broken stream again after 5s, and the sweep remains the
backstop: it re-reads the latest verdict of every installed and every refused
VTEP, so a missed failure still withdraws decap, and a missed pass still
admits the device, within one interval.

### Trust assumptions

- **IPAM writers.** Admission trusts the fabric IPAM allocation to bind a VTEP
  address to the right device. Anyone who can write fabric allocations can
  point an address at a healthy device's verdict. The serial match narrows
  this only for devices that have a serial on record. IPAM write access is
  therefore part of the overlay's trust base.
- **Underlay source addresses.** Decap authorisation matches the outer source
  IP. On an underlay without source validation, a host can send VXLAN under an
  admitted VTEP's address. The control for that is the authenticated underlay
  (the IPsec underlay), not admission.

## See Also

- [VXLAN Overlay](../overlay/architecture.md) - the VXLAN port and VTEP manager
- [BGP EVPN](../bgp/evpn.md) - EVPN route exchange
- [Gateway Architecture](architecture.md) - Core gateway design
