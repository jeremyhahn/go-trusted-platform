# VXLAN Overlay Architecture

## System Overview

The overlay is EVPN over VXLAN. BGP EVPN carries what each VTEP serves;
OpenFlow on one OVS bridge forwards it. Four pieces divide the work:

| Piece | Package | Owns |
|-------|---------|------|
| EVPN manager | `pkg/sdn/bgp` (`EVPNManager`) | Type-2/3/5 routes: origination, import, MAC Mobility. See [../bgp/evpn.md](../bgp/evpn.md) |
| VTEP manager | `pkg/sdn/vxlan` (`VTEPManager`) | the one flow-based VXLAN port on the bridge |
| Overlay mode handler | `pkg/sdn/gateway/modes` (`OverlayModeHandler`) | the data plane: every overlay flow, built from EVPN routes. See [../gateway/overlay-mode.md](../gateway/overlay-mode.md) |
| Overlay controller | `pkg/sdn/overlay` (`Controller`) | the API-facing registry of VNIs, VTEPs and remote MACs; joins a VNI's EVI to originate its Type-3 route |

```
              BGP EVPN (Type-2 / 3 / 5)
                        |
                 +--------------+
                 | EVPNManager  |
                 +--------------+
                        | route events
                        v
  +--------------------------------------------+
  | OverlayModeHandler                          |
  |  flows: decap authorisation, MAC, ARP,      |
  |  IRB routes, ingress replication            |
  +--------------------------------------------+
        | OpenFlow                  | OVSDB
        v                           v
  +--------------------------------------------+
  | OVS bridge (br-int)                         |
  |   access port   <-->   vxlan-evpn           |
  |   (VNIs as VLANs)      remote_ip=flow       |
  |                        key=flow             |
  +--------------------------------------------+
                        |
                 underlay (UDP 4789)
```

## The VXLAN Port

There is exactly one VXLAN port per bridge, `vxlan-evpn`
(`vxlan.DefaultPortName`), created by `VTEPManager.Start` with
`remote_ip=flow`, `key=flow`, `local_ip` set to the local VTEP and
`dst_port` set to the VXLAN UDP port. Flows choose each frame's
destination VTEP (`tun_dst`) and VNI (`tun_id`) and match the VNI and
source VTEP (`tun_src`) of each frame received on it. Adding or losing a
remote VTEP changes flows, never ports: there are no per-peer or per-VNI
tunnel ports.

`Start` adopts a port of that name that already has these options, and
refuses one that does not (`vxlan.ErrPortConflict`) instead of
rewriting it. `Stop` deletes the port. `OFPort()` is the OpenFlow port
number the flows output to.

## Encapsulation and MTU

```
+-----------+----------+---------+-----------+-------------------------+
| Outer Eth | Outer IP | UDP     | VXLAN     | inner frame             |
| 14 B      | 20 B     | 8 B     | 8 B (VNI) | up to the overlay MTU   |
+-----------+----------+---------+-----------+-------------------------+
            src: local VTEP, dst: tun_dst      UDP dst 4789
```

The overlay MTU is 9000 bytes (`vxlan.OverlayMTU`) and encapsulation
adds 50 (`vxlan.VXLANOverhead`), so the underlay must carry 9050 bytes
(`vxlan.MinimumUnderlayMTU`). A VTEP config with a smaller underlay MTU
is refused rather than fragmenting. Platform switch ports run 9216
(`netplan.MTU`), the default.

## Data Plane

The OpenFlow pipeline, decap authorisation, BUM ingress replication,
ARP suppression and symmetric IRB are specified in
[../gateway/overlay-mode.md](../gateway/overlay-mode.md). In short:

- a frame from the VXLAN port enters the pipeline only when its
  `tun_src` is a VTEP EVPN places on its `tun_id`; every other tunnelled
  frame is dropped;
- a known MAC goes to its VTEP, unknown and broadcast frames are
  replicated to every VTEP on the VNI (from Type-3 routes);
- ARP for known bindings and the anycast gateway is answered by a flow,
  with no packet-in;
- routed traffic crosses the L3VNI router MAC to router MAC.

## Overlay Controller

`overlay.Controller` is the overlay surface of the multi-protocol API
(see [api-reference.md](api-reference.md)). It keeps VNIs, VTEPs, tunnel
records and remote MACs in an in-memory `overlay.StateManager`, expires
learned remote MACs after `MACExpiration`, and reports health from its
OVS and OpenFlow clients and the VTEP manager. With `EnableEVPN`, adding
a VNI with `AdvertiseIMET` joins its EVI (`EVPNManager.JoinVNI`), which
originates the Type-3 route, and removing it leaves the EVI. VNI numbers
follow the reference network plan: overlay network n of environment E is
VNI E·100000+n (`netplan.VNI`).

The controller programs no flows and creates no ports; its records are
bookkeeping for the API. The data plane is the overlay mode handler's.

## Overlay IPsec

With `sdn.overlay.ipsec` enabled (see
[configuration.md](configuration.md#overlay-ipsec-sdnoverlayipsec)), the
underlay between VTEPs runs inside host-to-host IPsec. `pkg/sdn/ipsec`
drives strongSwan's charon, which holds the keys and runs IKEv2; platform
code never touches key material or ESP.

| Piece | Package | Owns |
|-------|---------|------|
| VICI client | `pkg/sdn/ipsec/vici` | charon's control socket: commands, streamed commands, events |
| Configuration | `pkg/sdn/ipsec` (`Config`) | the `overlay.ipsec` section and its derived timers |
| Controller | `pkg/sdn/ipsec` (`Controller`) | the peer set, one charon connection per peer, eviction, the identity check |
| Fail-closed floor | `pkg/sdn/ipsec` (`Filter`, `BlockPolicy`) | the nftables table and XFRM block policies that leave no cleartext path when charon is down |

### VICI client

`vici.Conn` speaks strongSwan's VICI wire protocol directly (packets with
a 4-byte length, at most 512 KiB; messages of key/value pairs, lists and
sections). Values are byte strings, so DER certificates and CRLs travel
unencoded, and a message holds the slices it is given so a PIN can be
wiped after the send.

- `Call` returns the response. A response with `success=no` comes back
  with a `*vici.CommandError` carrying charon's `errmsg`; responses without
  a `success` key (`version`, `list-*`) succeed.
- `CallStreaming` registers for the command's event (`list-sas` →
  `list-sa`), hands each event to a callback, returns the final response,
  then unregisters.
- `Subscribe` and `NextEvent` read events such as `ike-updown`. Events
  that arrive during another exchange are queued, up to 1024, then the
  connection fails (`vici.ErrEventBacklog`).
- Exchanges are serialised. A transport failure, a malformed packet, an
  unexpected packet type or a context cancelled mid-exchange closes the
  connection, because the stream position is then unknown. A refused
  command, `CMD_UNKNOWN` or `EVENT_UNKNOWN` leaves it usable.

### Peer connections

The controller's peers are the `static-peers` (route reflectors and
gateways), plus every VTEP that an admitted Type-3 route names, minus the
evicted. A VTEP is a peer while any VNI's route names it. Before a route
counts, the controller asks the overlay's VTEP admitter
(`modes.VTEPAdmitter`, restated as `ipsec.Admitter`). A refusal leaves the
VTEP out and is returned to the route handler. Routes naming the local
address, the other address family or a non-unicast address are ignored.
`Controller.HandleEVPNRoute` is a `bgp.EVPNRouteHandler`.

Each peer gets one connection, `vtep-<address>`, with no wildcard:

| Setting | Value |
|---------|-------|
| IKE | v2, `local_addrs`/`remote_addrs` the two VTEP addresses, `mobike=no`, `unique=replace`, `dpd_delay=30s`, `reauth_time` from [Timers](#timers) |
| Authentication | `pubkey` on both sides; `local.id` is the local address, and `remote.id` is the peer address with `revocation=strict` |
| CHILD_SA `overlay` | `mode=transport`, `local_ts`/`remote_ts` `dynamic` (every packet between the pair: VXLAN and BGP tcp/179 alike), `start_action`/`dpd_action`/`close_action` `trap`, `replay_window` from the configuration |
| IKE proposal | `aes256gcm16-prfsha384-ecp384-ke1_mlkem768`; the `fips` build drops `ke1_mlkem768` |
| ESP proposal | `aes256gcm16-ecp384-ke1_mlkem768-esn` (the key exchange makes every rekey PFS); the `fips` build drops `ke1_mlkem768` |

The trap means a peer's SA is negotiated by the first packet to it. A
closed or dead SA returns to the trap, never to cleartext. The connection
names no certificate or key. charon picks the certificate loaded with
`load-cert` whose SAN is the local address, and the key in the loaded token
that matches it.

`Attach` hands the controller a VICI session. It unloads any `vtep-`
connection charon holds for a peer that is gone, then loads every peer's
connection. Connections without the prefix are left alone. `Detach` drops
the session when charon goes away. Peers are still tracked while detached,
and the next `Attach` pushes them, so a charon restart re-converges.

`Evict(peer)` is the eviction primitive, applied in this order:

1. Add a kernel drop for the peer's packets, IKE included. This step holds
   even when charon is absent.
2. Unload the peer's connection, which removes its trap.
3. Force-terminate the peer's IKE_SAs.

The peer stays evicted, whatever routes name it, until `Readmit`. Fleet-wide
eviction is orchestrated elsewhere.

`HandleEvent` checks every `ike-updown` event for a `vtep-` connection
coming up: the peer must have authenticated as exactly the address the SA
runs to. charon already pins `remote.id`; the check holds that pin to
account. On a mismatch the SA is terminated and an
`*ipsec.IdentityMismatchError` is returned. The check runs on VICI events
rather than an updown script, because a script cannot reach the 0600 socket
and cannot stop an SA.

### Fail-closed floor

Two kernel layers, both owned by platformd and independent of charon,
make sure nothing crosses the fabric in cleartext. With charon stopped,
no SA and no trap exists, and both layers drop VXLAN and BGP alike.

`ipsec.Filter` writes the nftables table `inet tp_ipsec`. Its chains,
`fabric_in` and `fabric_out`, hook input and output at priority -10 with
policy accept, and only judge packets on `fabric-interface`:

| Order | Inbound (`iifname`) | Outbound (`oifname`) |
|-------|---------------------|----------------------|
| 1 | ICMPv6 types 133–137 (neighbour discovery) accepted | the same |
| 2 | source in `@evicted` dropped | destination in `@evicted` dropped |
| 3 | ESP accepted (local address family) | ESP accepted |
| 4 | UDP 500→500 and 4500→4500 over `ike-rate`/`ike-burst` per source dropped, the rest accepted | UDP 500→500 and 4500→4500 accepted |
| 5 | `meta secpath exists` (decrypted by an SA) accepted | `rt ipsec exists` (routed into an SA) accepted |
| 6 | everything else dropped | everything else dropped |

The per-source IKE limit is a dynamic set (`ike_meter`, entries expire a
minute after a source's last packet). It complements charon's
`cookie_threshold` and `init_limit_half_open`. The table only narrows:
the host filter (`tp_host`) still has to accept ESP and IKE on the fabric.
Cleartext ICMP, path-MTU messages included, is dropped. The underlay MTU
requirement in [Encapsulation and MTU](#encapsulation-and-mtu) is what
makes that safe.

`Apply` replaces the whole table in one transaction, so there is never
a moment without it. `Remove` deletes it. `Filter` is the controller's
`Dropper`. `Drop`/`Undrop` change the `evicted` set in place. A drop
recorded before `Apply` is installed with the table, and a re-`Apply`
keeps every drop.

`ipsec.BlockPolicy` installs XFRM policies at priority 2^30. A larger
number is a lower priority, so these sit below every policy charon
installs. Direction `out` blocks everything from the local address, and
direction `in` blocks everything to it. A packet passes only when one of
charon's policies (a trap, or an SA's) takes precedence and sends it
through ESP. charon's IKE sockets carry bypass socket policies, which
the kernel checks first. On an IPv6 underlay, ICMPv6 types 133–137 are
allowed in both directions one priority step above the blocks.
`Install` is idempotent, and exemptions go in before blocks. `Remove`
deletes the blocks first.

Both need CAP_NET_ADMIN. `NewFilter` takes nftables connection options
and `NewBlockPolicy` takes a network namespace, so either can be pinned
to a namespace.

### Timers

The VTEP certificate outlives three tolerated control-plane outages
(`cert-lifetime` ≥ 3 × `cp-outage-tolerance`, default 72h against 24h).
IKE reauthentication (`reauth_time`) runs at half the lifetime, so each
SA re-proves its identity, and rechecks revocation, after the certificate
has been renewed at the same mark.

## Errors

| Error | Package | Meaning |
|-------|---------|---------|
| `ErrUnderlayNotReady` | `vxlan` | the VTEP config names no underlay interface |
| `ErrPortConflict` | `vxlan` | a port with the VTEP's name exists with other options |
| `ErrOVSOperationFailed` | `vxlan` | OVSDB refused a port create, read or delete |
| `ErrVTEPOperationFailed` | `modes` | a route's VTEP was refused admission or is not a usable IPv4 VTEP |
| `ErrFlowOperationFailed` | `modes` | the switch refused a flow change; the flows the batch touched are put back, so the switch and handler state are unchanged |
| `ErrBindingConflict` | `modes` | a Type-2 route claimed the anycast gateway's MAC or IP; refused whole and counted in `RefusedBindings`. A route claiming a local host's IP is not an error: its MAC is bridged and its IP held back until the local host goes |
| `ErrFlowResyncFailed` | `modes` | the switch refused the put-back too, or the rebuild after one; the next change flushes the overlay flows and reinstalls the committed ones before applying anything |
| `ConfigError` | `ipsec` | an `overlay.ipsec` field broke a rule; names the field and wraps an `ipsec.Err*` sentinel |
| `CommandError` | `vici` | charon ran a command and refused it (`success=no`); carries `errmsg` |
| `ErrUnknownCommand`, `ErrUnknownEvent` | `vici` | charon does not know the command or event; the connection stays usable |
| `PeerError` | `ipsec` | a step on one peer failed (`admit`, `load-conn`, `unload-conn`, `drop`, `undrop`, `list-sas`, `terminate`, `evict`, `readmit`); names the peer and wraps the cause |
| `OpError` | `ipsec` | an operation not tied to one peer failed: `get-conns` during `Attach`, `nftables apply`/`remove`, `xfrm install`/`remove` |
| `ErrFamilyMismatch` | `ipsec` | `Filter.Drop`/`Undrop` named a peer of the other address family (inside a `PeerError`) |
| `IdentityMismatchError` | `ipsec` | an SA came up with a peer identity other than its address; the SA was terminated |
| `ErrNotEvicted` | `ipsec` | `Readmit` named a peer that is not evicted |

## See Also

- [Overlay mode (data plane)](../gateway/overlay-mode.md)
- [BGP EVPN](../bgp/evpn.md)
- [Configuration](configuration.md)
- [Operations](operations.md)
- [SDN Architecture](../architecture.md)
