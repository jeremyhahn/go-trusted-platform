# VXLAN Overlay Architecture

## System Overview

The overlay is EVPN over VXLAN. BGP EVPN carries what each VTEP serves;
OpenFlow on one OVS bridge forwards it. Four pieces divide the work:

| Piece | Package | Owns |
|-------|---------|------|
| EVPN manager | `pkg/sdn/bgp` (`EVPNManager`) | Type-2/3/5 routes: origination, import, MAC Mobility. See [../bgp/evpn.md](../bgp/evpn.md) |
| VTEP manager | `pkg/sdn/vxlan` (`VTEPManager`) | the one flow-based VXLAN port on the bridge |
| Overlay mode handler | `pkg/sdn/gateway/modes` (`OverlayModeHandler`) | the data plane: every overlay flow, built from EVPN routes. See [the overlay handler](../../gateway/engineering.md#the-overlay-handler-overlaymodehandler) |
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
[the overlay handler](../../gateway/engineering.md#the-overlay-handler-overlaymodehandler). In short:

- a frame from the VXLAN port enters the pipeline only when its
  `tun_src` is a VTEP EVPN places on its `tun_id`; every other tunnelled
  frame is dropped;
- a known MAC goes to its VTEP, unknown and broadcast frames are
  replicated to every VTEP on the VNI (from Type-3 routes);
- ARP for known IPv4 bindings and the anycast gateway is answered by a
  flow. An IPv6 NS for a known target is punted through a metered controller
  action to a packet-in controller. The controller sends a proxy NA on the
  segment VLAN, and the NS is not flooded (RFC 9161). Unknown targets and
  DAD probes flood. The punts are the only thing that can withhold an NS from
  the flood, so they exist only while a live controller can answer:
  - they carry a 12 s hard timeout that the controller refreshes;
  - stop removes them;
  - any meter or queue drop, or refused packet-out, withdraws them for a
    hold-down of 30 s, doubling on repeated fallbacks up to 8 minutes;
  - a lost OpenFlow connection is redialled; the whole pipeline is rebuilt
    from the committed state and the meter reinstalled, since a restarted
    switch keeps neither, and the punts return after the hold-down. The
    rebuild first reads the VXLAN and access ports' OpenFlow numbers again,
    which a restart can change, and regenerates the flows on them; until
    both resolve, no overlay flow or punt goes on the switch. A meter the
    switch refuses is retried every poll, and the punts stay off (every NS
    floods) until it is accepted;
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
| VICI adapter | `pkg/sdn/ipsec` (`Session`, `EventStream`, `Dialer`; `VICIDialer`) | charon's control socket through `github.com/strongswan/govici`, and the socket check |
| Configuration | `pkg/sdn/ipsec` (`Config`) | the `overlay.ipsec` section and its derived timers |
| Controller | `pkg/sdn/ipsec` (`Controller`) | the peer set, one charon connection per peer, eviction, the identity check |
| Fail-closed floor | `pkg/sdn/ipsec` (`Filter`, `BlockPolicy`) | the nftables table and XFRM block policies that leave no cleartext path when charon is down |
| Tunnel identity | `pkg/sdn/ipsec` (`TunnelIdentity`, `IdentityProvider`; `FileIdentity`) | the tunnel certificate, its chain and the token key charon signs with |
| Runner | `pkg/sdn/ipsec` (`Runner`) | the connection to charon: dial, attach, follow events, reconnect |
| Service | `pkg/sdn/ipsec` (`Service`) | all of the above on a platformd node: the floor at start, then the runner, the fabric interface watch and the CRL feed |

### VICI adapter

The controller speaks to charon through three small interfaces: `Session`
(the commands it sends), `EventStream` (`ike-updown` events) and `Dialer`
(opens both). `VICIDialer` implements them over govici, which owns the
wire protocol. Each command failure is a `*ipsec.CommandError` naming the
command. The session reads every reply itself rather than trusting govici
to flag it: a reply, or a streamed `list-sa` event, carrying `success`
other than `yes` is a refusal — `Err` is `ErrCommandRefused` and `Reason`
is charon's `errmsg` (`no errmsg` when charon sent none). Any other
failure wraps govici's error. A refused command is never taken as done:
the controller marks no connection loaded and keeps no identity, and the
peer stays unsynced for the next retry.

VICI carries no authentication: whoever can open the socket commands
charon, and whoever serves it receives the credentials platformd loads.
`VICIDialer` therefore checks both ends of every connection (govici's
`WithDialContext` hands it the dial):

1. It opens the path itself with `O_PATH|O_NOFOLLOW`, so a symlink is
   opened rather than followed, and `fstat`s the descriptor. The result
   must be a socket, mode 0600, owned by platformd's effective user.
2. It connects through `/proc/self/fd/N`, not the path. The checks and the
   connect see the same inode, so a socket swapped in under the path after
   the checks is never reached.
3. On the connected socket, `SO_PEERCRED` (`pkg/util/peercred`) must name
   `VICIDialer.Charon`. That is the uid the serving process listened as:
   the kernel records the credentials of the `listen` call. charon creates
   the socket before it drops from root to the `strongswan` user, so for
   the shipped package the uid is 0. This is an assumption, taken from how
   strongSwan orders plugin loading and the privilege drop. It has not
   been checked against a running charon, because the transport suite
   needs Docker.

A refusal is a `*ipsec.SocketError` wrapping `ErrNotSocket`,
`ErrSocketMode`, `ErrSocketOwner` or `ErrSocketPeer`. A refused path is
never connected to, and nothing is sent over a refused peer.

Commands and events use separate connections. govici ends every event
channel of a session when its connection drops, and `Session.Done` closes
then; that is how a dead command connection is noticed.

### Tunnel identity

charon authenticates with the VTEP's tunnel certificate and the token key
behind it. `Attach` asks the `IdentityProvider` for a `TunnelIdentity`
every time, so a renewed certificate is loaded on the next attach.
`FileIdentity` reads the chain from `certificate-file` and the token PIN
from the first line of `token.pin-file`. The identity is refused unless
the leaf carries the local address as an IP SAN, a key ID is named, and
the chain ends in a self-signed root.

| Step | VICI command | Body |
|------|--------------|------|
| Leaf | `load-cert` | `type=X509`, `flag=NONE`, the DER |
| Chain | `load-cert` | `type=X509`, `flag=CA`, each DER in turn |
| Key | `load-token` | `handle` (hex CKA_ID), `slot`, `module` (the strongswan.conf module name; empty searches every module), `pin` |

The PIN lives in a memguard enclave (`quicbaas/sdk/go/xkms/secure`). It
is opened only for the `load-token` call. The message's `pin` value is a string that
aliases the locked buffer, not a copy, and the key is unset before the
buffer is destroyed. govici's encoder still copies the bytes into its
own unlocked frame buffer, which it does not wipe; closing that gap needs
an upstream change.

### CRLs

charon never fetches CRLs; they are pushed to `Controller.PushCRL`. On a
platformd node the `Service` reads them from `crl-files` at start and every
minute (`CRLRefresh`), so the CA's CRL distribution writes the files and
platformd picks up a replaced one within the minute. A file that cannot be
read is logged and the others are still pushed. The controller keeps the newest CRL per issuer (a
higher CRL number wins, or the later `thisUpdate` when either has no
number) and loads it with `load-cert type=X509_CRL` at once if charon is
attached. Every peer connection sets `revocation=strict`, so a peer whose
status is unknown is refused.

A held CRL that charon fails to load is not taken as loaded. Its issuer
stays pending (`Status.UnloadedCRLs`) and signals the runner, which retries
it through `Converge` with the backoff in [Runner](#runner). The same CRL
pushed again is loaded again rather than ignored as already held. Until it
loads, charon checks that issuer's peers against the CRL it held before,
or none.

Before a CRL is kept, `PushCRL` checks it, and refuses it with an
`OpError` (`verify crl`) if it fails; the CRL already held for the issuer
stays:

- it must be signed by a CA of the tunnel identity (`CheckSignatureFrom`
  against a chain certificate whose subject is the CRL's issuer), or
  `ErrCRLUntrusted`;
- its `nextUpdate` must be in the future, or `ErrCRLStale`.

The CAs are those of the identity the provider holds now, not the one last
loaded. A renewal under a new intermediate is followed at once, and a
CRL of an intermediate no longer in the chain is refused. CRLs are held
per issuer, keyed by the issuer name and authority key ID.

While the provider has no valid identity (before the first certificate
lands, say), there is nothing to verify a CRL against, so a current CRL
is queued instead of refused. The queue keeps the newest CRL per issuer
for at most 8 issuers, and `ErrCRLQueueFull` refuses another issuer
(`OpError`, `queue crl`). A stale CRL is refused at once. The next
`Attach` verifies the queued CRLs against the identity it loads, before
it loads the CRLs and any connection, and the next `PushCRL` that finds
an identity does the same. A queued CRL that fails is dropped, and its
`verify crl` error is returned without detaching the controller.
`Status.PendingCRLs` counts the queued issuers.

The identity is refused (`ErrNoRoot`) unless its chain ends in a
self-signed root, so the root's own CRL always has its CA in the chain.

**Strict mode, an assumption.** Per the strongSwan `swanctl.conf`
documentation, `revocation=strict` fails authentication unless the
certificate is known to be unrevoked. A missing CRL and an expired one
(stale, past `nextUpdate`) both leave the status unknown, so both fail.
This has not been checked against a running charon (the transport suite
needs Docker). Two consequences follow:

- a node's IKE comes up only once a current CRL for each issuer in the
  peers' chains has been pushed;
- the CRL `nextUpdate` must be further out than `cp-outage-tolerance`.
  charon cannot refresh a CRL during a control-plane outage, so a CRL that
  expires inside the outage takes the whole fabric down with it.

### Runner

`Runner.Run` keeps the controller attached until its context ends:

1. Subscribe to `ike-updown` on one connection, then dial the command
   connection.
2. `Attach` loads the tunnel identity, then every held CRL, then lists
   charon's connections and loads every peer's. A failure before the
   connections ends the attempt with the controller detached. A peer that
   fails to load leaves the session up. Last, every IKE_SA charon holds is
   audited (see [Peer connections](#peer-connections)).
3. Pass each event to `HandleEvent` until either connection ends, then
   `Detach`.

Between attempts the runner waits on a timer, starting at 500ms and
doubling to 30s. An attempt that attached resets the wait. Because the
identity, the CRLs and the peers are pushed on every attach, a charon
restart re-converges with nothing lost.

Work the controller fails to finish is not dropped. This covers a CRL
charon failed to load, a peer connection that failed to load or unload,
an evicted peer's SAs that
could not be ended, a kernel drop that failed, and an audit that could
not run. Each failure is recorded and signals the runner. The runner then
calls `Controller.Converge` after a wait that starts at 500ms and doubles
to 30s while retries fail. While charon is away, the runner still retries
failed kernel drops between connection attempts.

govici queues up to 256 events and drops any it cannot queue. When the
event stream finds its queue full, or one short of full, events may have
been lost. It then marks the next event `Lost`, and `HandleEvent` audits
every SA instead of checking only that event.

### Startup in platformd

`ipsec.NewService` builds everything from the `overlay.ipsec` section:
the file identity, the floor, the controller, and a runner dialing the
VICI socket. platformd's `daemon.New` builds it and calls `Install` before
the overlay controller registers the local VTEP, so nothing is sent on
the fabric before the floor is in. A section that cannot be built (a
`ConfigError`; `certificate-file` and `crl-files` are required here) or a
floor that cannot be installed (`FloorError`) stops platformd from
starting. The overlay controller failing after the floor is in is only
logged.

The SAs carry only traffic between `local-address` and its peers, and the
floor drops everything else on `fabric-interface`, so the overlay's VTEP is
that endpoint. With the overlay enabled, `daemon.resolveOverlayVTEP`
decides the VTEP once, between building the service and installing the
floor: the address is `local-address` and the VXLAN underlay interface is
`fabric-interface`, never the node's public IPv4. When the two cannot agree
(`local-address` is not an address of `fabric-interface`, the interface
cannot be read, or `overlay.underlay-interface` names another one) it
returns an `OverlayVTEPError`, the built service is closed, and platformd
stops before the floor or the controller starts. The controller registers
the address it is handed.

`Daemon.Start` runs the service in the background and `Stop` ends it:
the runner, the `BlockPolicy.Watch` loop (run again after each failure,
waiting from 500ms and doubling to 30s) and the CRL feed. The floor is
never removed, so a stopped platformd leaves the fabric dark rather than
open.

platformd has no EVPN route source, so its controller admits no VTEP a
route names (`ErrNoVTEPAdmission`): its peers are the static peers.
gatewayd does not host the overlay (it refuses `ServiceOverlay`), so it
runs no IPsec.

### Status

`Controller.Status` reports whether charon is attached, the peers, the
evicted peers, and the work still pending:

- `DropPending`: evicted peers whose kernel drop failed;
- `Unsynced`: peers whose connection or SAs charon does not hold as wanted;
- `AuditPending`: an SA audit is due;
- `UnloadedCRLs`: issuers whose held CRL charon failed to load.

It also reports how many issuers' CRLs are held and how many are queued
awaiting an identity (`PendingCRLs`), and the tunnel
certificate's renewal state (`CertificateStatus`): serial, validity,
time to expiry, `RenewalDue` from half its lifetime and `Alert` from
three quarters.

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

`Attach` hands the controller a VICI session. After the identity and the
CRLs (see [Runner](#runner)), it unloads any `vtep-` connection charon
holds for a peer that is gone, then loads every peer's connection.
Connections without the prefix are left alone. `Detach` drops the session
when charon goes away. Peers are still tracked while detached, and the
next `Attach` pushes them, so a charon restart re-converges.

`Evict(peer)` is the eviction primitive, applied in this order:

1. Add a kernel drop for the peer's packets, IKE included. This step holds
   even when charon is absent.
2. Unload the peer's connection, which removes its trap.
3. Force-terminate the peer's IKE_SAs.

Every step runs even when an earlier one fails, and the failures are
returned joined. A failed drop does not leave the connection and SAs up.
Nothing is rolled back. The peer stays evicted, `Status` shows the step
still pending (`DropPending` or `Unsynced`), and `Converge` retries it. An
eviction while detached drops the peer at once. The next `Attach` unloads
the connection, and its audit ends the SAs that charon kept meanwhile.
`Readmit` lifts the drop. A drop that never went in is not lifted. The
connection is then reloaded.

The peer stays evicted, whatever routes name it, until `Readmit`. Fleet-wide
eviction is orchestrated elsewhere.

`HandleEvent` checks every `ike-updown` event for a `vtep-` connection
coming up: the peer must have authenticated as exactly the address the SA
runs to. charon already pins `remote.id`; the check holds that pin to
account. On a mismatch the SA is terminated and an
`*ipsec.IdentityMismatchError` is returned. An SA that comes up for an
evicted peer is terminated as well. The check runs on VICI events
rather than an updown script, because a script cannot reach the 0600 socket
and cannot stop an SA.

`Audit` applies the same check to every IKE_SA charon holds
(`list-sas` with no connection named). It runs on every `Attach`, and
`HandleEvent` runs it for an event marked `Lost`, so an SA whose
`ike-updown` was never seen is still checked. An audit that cannot list
the SAs, or fails to end one, stays pending for `Converge`.

### Fail-closed floor

Two kernel layers, both owned by platformd and independent of charon,
make sure nothing crosses the fabric in cleartext. With charon stopped,
no SA and no trap exists, and both layers drop VXLAN and BGP alike.

`ipsec.Filter` writes the nftables table `inet tp_ipsec`. Its chains,
`fabric_in`, `fabric_fwd` and `fabric_out`, hook input, forward and output
at priority -10 with policy accept, and only judge packets that enter or
leave by `fabric-interface`:

| Order | Inbound (`iifname`) | Outbound (`oifname`) |
|-------|---------------------|----------------------|
| 1 | link ICMPv6 accepted (below) | the same |
| 2 | source in `@evicted` dropped | destination in `@evicted` dropped |
| 3 | ESP accepted (local address family) | ESP accepted |
| 4 | UDP 500→500 and 4500→4500 accepted while the source's `ike_meter` update succeeds within `ike-rate`/`ike-burst` | UDP 500→500 and 4500→4500 accepted |
| 5 | `meta secpath exists` (decrypted by an SA) accepted | `rt ipsec exists` (routed into an SA) accepted |
| 6 | everything else dropped | everything else dropped |

`fabric_fwd` judges traffic routed through the node whose `iifname` or
`oifname` is the fabric: source or destination in `@evicted` dropped,
`meta secpath exists` accepted, everything else dropped. Link ICMPv6 and
IKE are never routed, so neither is exempt there.

ESP is not exempt in `fabric_fwd` either, and the XFRM `fwd` block has no
ESP exemption, so the two forward layers agree: routed ESP does not pass.
The overlay never needs it. The VTEP's own ESP starts and ends at
`local-address` and is judged by `fabric_in` and `fabric_out`. ESP that
the node would route is another host's tunnel, and a VTEP is not a
transit router for the underlay. An exemption in one layer only would
also be dead: the XFRM block drops everything routed out by the fabric
interface that no SA of charon's carries.

The fabric interface is therefore dedicated to the underlay. Routed
north-south traffic out of the fabric NIC is blocked by design, by both
layers. A node whose uplink or routed LAN shares that NIC loses it while
the overlay is enabled, and needs its own interface for that traffic.

The per-source IKE limit is a dynamic set (`ike_meter`, at most 65535
sources, entries expire a minute after a source's last packet). The rule
accepts only when the meter update succeeds and the source is within its
rate. Over the rate, and when the meter is full and cannot take a new
source, the update fails and the packet falls to the final drop, so a flood
of spoofed sources fills the meter without opening it. It complements
charon's `cookie_threshold` and `init_limit_half_open`. The table only
narrows: the host filter (`tp_host`) still has to accept ESP and IKE on the
fabric.

The link ICMPv6 is what an IPv6 underlay needs before any SA exists:
neighbour solicitation and advertisement (135, 136) and MLD (130–132,
143), which multicast snooping on the fabric switches relies on. Router
solicitation and advertisement (133, 134) are added only with
`underlay-slaac`, for an underlay addressed by SLAAC; it is off by default,
because an unauthenticated advertisement can readdress or reroute the node.
Redirect (137) is never exempt. Every other cleartext ICMP, path-MTU
messages included, is dropped. The underlay MTU requirement in
[Encapsulation and MTU](#encapsulation-and-mtu) is what makes that safe.

`Apply` replaces the whole table in one transaction, so there is never
a moment without it. `Remove` deletes it. `Filter` is the controller's
`Dropper`. `Drop`/`Undrop` change the `evicted` set in place. A drop
recorded before `Apply` is installed with the table, and a re-`Apply`
keeps every drop.

`ipsec.BlockPolicy` installs XFRM policies at priority 2^30. A larger
number is a lower priority, so these sit below every policy charon
installs. Direction `out` blocks everything from the local address,
direction `in` blocks everything to it, and direction `fwd`, bound to the
fabric interface's index, blocks everything routed out of the fabric. A
packet passes only when one of charon's policies (a trap, or an SA's) takes
precedence and sends it through ESP. charon's IKE sockets carry bypass
socket policies, which the kernel checks first. On an IPv6 underlay, the
link ICMPv6 types above are allowed in both directions one priority step
above the blocks. `Install` resolves the fabric interface (it must exist),
is idempotent, and puts exemptions in before blocks. `Remove` deletes the
blocks first, the forward block for the interface index it is installed
for.

XFRM selects an interface only by index, and an interface that is deleted
and created again (a bond or VLAN the network configuration rebuilds)
comes back under a new one. `Watch` keeps the forward block on it. It
subscribes to the namespace's netlink link events, moves the block to the
interface's current index, then moves it again on every event for a link
of the fabric interface's name. A move installs the new block before it
deletes the old, so there is no gap. While the interface is gone the block
stays on the old index. `Watch` moves nothing while no floor is installed.
It returns nil when its context ends, and an error when the subscription
fails or ends (`ErrLinkWatchEnded`) or a move fails. The caller runs it
again after a wait, and its first move catches up on any change it missed.
The nftables filter needs no such watch: it matches the interface by name.

Both need CAP_NET_ADMIN. `NewFilter` takes nftables connection options
and `NewBlockPolicy` takes a network namespace, so either can be pinned
to a namespace.

The ipsec integration suite applies both to a node in a network namespace
and checks them on a real kernel ([../engineering.md](../engineering.md),
§9.3). It covers three things: no cleartext path, and no routed ESP, in any
direction for each layer alone and for both, eviction ahead of the ESP and
IKE accepts, and a full `ike_meter` that refuses new sources.

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
| `ErrSwitchNotRestored` | `modes` | an overlay change while the switch has reconnected but the ports' OpenFlow numbers have not been read again; the ND poll retries them, and the change can be made once they resolve |
| `ErrOverlayPortUnresolved` | `modes` | OVS gave no usable OpenFlow number for the VXLAN or access port, at start or after a reconnect |
| `ErrOFPortUnassigned` | `vxlan` | OVS reports the VXLAN port with ofport -1, an interface it could not attach |
| `ConfigError` | `ipsec` | an `overlay.ipsec` field broke a rule; names the field and wraps an `ipsec.Err*` sentinel |
| `CommandError` | `ipsec` | a VICI command failed: charon refused it (`ErrCommandRefused`, its `errmsg` in `Reason`) or the connection failed under it |
| `SocketError` | `ipsec` | the VICI socket was refused (`ErrNotSocket`, `ErrSocketMode`, `ErrSocketOwner`, `ErrSocketPeer`) or could not be opened, connected to, or have its peer read |
| `CloseError` | `ipsec` | a close failed after another failure; matches both |
| `ErrCharonGone` | `ipsec` | a connection to charon ended; the runner reconnects |
| `ErrInvalidMessage` | `ipsec` | a request lacked what charon needs: a credential without data, a token key without an ID |
| `ErrNoCertificate`, `ErrCertificateAddress`, `ErrNoKeyID`, `ErrNoRoot` | `ipsec` | the tunnel identity has no certificate, its leaf does not name the local address, it names no key, or its chain does not end in a self-signed root (inside an `OpError`, `identity`) |
| `ErrCRLQueueFull` | `ipsec` | a CRL arrived while there was no identity to verify it against, and the queue already holds 8 issuers (inside an `OpError`, `queue crl`) |
| `ErrMissingDependency` | `ipsec` | a constructor or `Attach` was handed a nil collaborator |
| `PeerError` | `ipsec` | a step on one peer failed (`admit`, `load-conn`, `unload-conn`, `drop`, `undrop`, `list-sas`, `terminate`, `evict`, `readmit`); names the peer and wraps the cause |
| `OpError` | `ipsec` | an operation not tied to one peer failed: `identity`, `load-cert`, `load-token`, `load-cert x509crl` or `get-conns` during `Attach`, `list-sas` during an audit, `parse crl`, `verify crl` or `queue crl` in `PushCRL`, `verify crl` for a queued CRL during `Attach`, `nftables apply`/`remove`, `xfrm install`/`remove`, `xfrm watch`/`rebind` in `BlockPolicy.Watch` |
| `ErrLinkWatchEnded` | `ipsec` | the netlink link subscription `BlockPolicy.Watch` follows the fabric interface by ended (inside an `OpError`, `xfrm watch`) |
| `ErrCRLStale`, `ErrCRLUntrusted` | `ipsec` | a pushed CRL had no `nextUpdate` or one already passed, or was not signed by a CA of the tunnel identity (inside an `OpError`, `verify crl`); the CRL held for that issuer stays |
| `ErrFamilyMismatch` | `ipsec` | `Filter.Drop`/`Undrop` named a peer of the other address family (inside a `PeerError`) |
| `IdentityMismatchError` | `ipsec` | an SA came up with a peer identity other than its address; the SA was terminated, or the termination is pending and joined to this error |
| `ErrNotEvicted` | `ipsec` | `Readmit` named a peer that is not evicted |
| `FloorError` | `ipsec` | `Service.Install` could not put the fail-closed floor in; wraps the `OpError` (`nftables apply` or `xfrm install`). platformd refuses to start |
| `ErrNoVTEPAdmission` | `ipsec` | a route named a VTEP on a node with no EVPN route source; only static peers are admitted |
| `OverlayVTEPError` | `daemon` | the overlay VTEP would sit outside the IPsec it runs beside: `local-address` is not on `fabric-interface` (`ErrVTEPNotOnFabric`), the interface could not be read, or `underlay-interface` names another interface (`ErrUnderlayNotFabric`). Names the address and interface; platformd refuses to start before the floor goes in |

## See Also

- [Overlay handler (data plane)](../../gateway/engineering.md#the-overlay-handler-overlaymodehandler)
- [BGP EVPN](../bgp/evpn.md)
- [Configuration](configuration.md)
- [Operations](operations.md)
- [SDN Architecture](../architecture.md)
