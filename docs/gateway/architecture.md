# Edge Gateway Architecture

> **Status: NORMATIVE** · Scope: `pkg/sdn/gateway/`, `pkg/proxy/`, `cmd/gatewayd` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: architecture (this file) · [engineering.md](engineering.md) ·
> [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> Longer-form material predating this migration lives in
> [`docs/sdn/gateway/`](../sdn/gateway/) and has not been re-verified.

## The problem

Every network the platform touches has an edge: a WAN link, an IoT segment, an
upstream that speaks BGP, a client that arrives over HTTPS. Those terminations
have nothing to do with each other technically, but they share one property —
**they are where untrusted traffic meets the platform**. Scattering them across
the control plane would put untrusted termination in the same process as the
Raft cluster and the API surface.

## The shape chosen

A **separate binary** — `gatewayd` — running the **edge/gateway node role**.
Roles are configuration, not binaries: `platformd` runs as control-plane or
worker; `gatewayd` is the edge. A gateway terminates and routes; it does not
serve the composed platform SDK.

Its capabilities are **independently enabled service sections**
(`pkg/sdn/gateway/node.go`):

| Constant | Value | What it does |
|---|---|---|
| `ServiceOverlay` | `overlay` | VXLAN/EVPN overlay participation |
| `ServiceEdge` | `edge` | IoT / P2P edge termination |
| `ServiceTransit` | `transit` | BGP transit for IP blocks |
| `ServiceBGP` | `bgp` | BGP speaker |
| `ServiceFirewall` | `firewall` | Packet filtering |
| `ServiceDHCP` | `dhcp` | DHCP service |
| `ServicePXE` | `pxe` | Network boot |
| `ServiceLoadBalancer` | `load-balancer` | VIP load balancing |
| `ServiceNAT` | `nat` | Network address translation |
| `ServiceTunnels` | `tunnels` | Tunnel management |
| `ServiceProxy` | `proxy` | The trusted authenticating reverse proxy |
| `ServiceHostFW` | `hostfw` | The nftables host packet filter |
| `ServiceManagementVPN` | `management-vpn` | The attested remote-access VPN (design only; refused) |

**Note the value spelling: `load-balancer` and `management-vpn`, hyphenated**,
while the others are single words. Configuration that writes `loadbalancer`
will not match.

### `GatewayMode` is deprecated compatibility, not the model

`pkg/sdn/gateway/compat.go:26` declares `GatewayMode uint8` — a bitmask with
three values (`GatewayModeOverlay`, `GatewayModeEdge`, `GatewayModeTransit`) —
carrying an explicit deprecation notice: *"Gateway services are now
config-driven. Use GatewayConfig service sections instead of mode flags. This
type is retained for API compatibility during the migration period."*

It maps only three of the services (`serviceToMode` / `modeToService`).
**Do not model a gateway as a mode.** The bitmask cannot express the other
services, and anything built on it will be wrong for a gateway that runs
firewall, DHCP, PXE, LB, NAT, tunnels or proxy. `SetGatewayMode` still exists
as an RPC and `platformctl sdn gateway mode set` still exists as a verb — both
are the compatibility surface.

### Alternatives rejected

| Alternative | Why it was rejected |
|---|---|
| **Run edge services inside `platformd`** | Puts untrusted WAN and IoT termination in the same process as the Raft cluster and the composed API. A gateway compromise would be a control-plane compromise. |
| **A `mode` bitmask as the configuration model** | Tried, and retained only for compatibility. Most services have no bit. Every added service would need a new bit and a new mapping in two directions. |
| **A separate binary per edge function** | Eleven binaries to deploy, version and attest, all sharing the same datapath and the same node identity. One binary with config-driven sections keeps the attestation surface singular. |
| **A general-purpose reverse proxy in front of the platform** | An off-the-shelf proxy authenticates a user or a token. The trusted proxy authenticates against the platform's own identity chain and consults the SDN zone matrix, so a route's reachability follows network zoning rather than being configured twice. |
| **Letting the gateway serve the composed SDK** | Then the edge would need the whole stack's surface at the point where untrusted traffic lands. Gateways consume control-plane configuration; they do not re-export it. |

### IPv6-only clients — NAT64, DNS64 and 464XLAT (R6, spike #595)

An IPv6-only client zone (RFC 6146 NAT64 with RFC 6147 DNS64, and RFC 6877
464XLAT for clients that need literal IPv4) is a Phase 5 feature. The spike
measured the alternatives on 2026-09-08 and the decision is:

- **The PLAT is the Jool kernel translator, packaged by Alpine.** The gateway
  owns the Jool instance the way it owns nftables and the OVS bridge: it
  renders the configuration, drives it, watches it, and refuses to start the
  section when the module is not loadable. Alpine 3.22 ships
  `jool-modules-lts`, `jool-tools` and `jool-tools-openrc`, so the fleet's
  `linux-lts` kernel gets the module from the distribution, not from an
  out-of-tree build the platform would have to attest.
- **DNS64 is the CoreDNS `dns64` plugin inside `pkg/dns`,** enabled per zone
  with the prefix the translator uses (the well-known `64:ff9b::/96` or a
  site prefix). It is a directive and a Corefile stanza, not new code.
- **A Go userspace translator stays the portable fallback,** behind the
  existing NAT service's uplink pool model, for hosts where the module is
  unavailable. Its ceiling was measured (below) and is the reason it is not
  the default.
- **eBPF is deferred, not rejected.** It is the right long-term shape for a
  translator the gateway itself loads, but it adds a clang/BTF toolchain and
  a verifier-bound program to the build surface for no current need.
- **464XLAT's CLAT is the client's job.** Android, iOS, Windows and NetworkManager
  ship a CLAT that discovers the prefix by RFC 7050 (AAAA for
  `ipv4only.arpa`), which DNS64 answers. The gateway is the PLAT only.

| Option | Measured / known | Why it is or is not the default |
|---|---|---|
| **Jool kernel module (chosen)** | Alpine 3.22 packages `jool-modules-lts-6.12.108-r0`, `jool-tools-4.1.14-r0`, `jool-tools-openrc`; full RFC 6146/7915 including ICMP, fragments and session timeouts; line rate on the fleet's NICs | Distribution-packaged and kernel-resident. The gateway drives it exactly as it drives nftables — a rendered configuration, applied and verified. The only cost is a module dependency the section checks at start. |
| Go userspace translator (fallback) | Spike `test/spike/nat64` (`//go:build spike`): one goroutine per direction, a lock-guarded binding table, two TUNs, UDP/TCP only. 24-core Xeon Gold 6258R, user namespace, bidirectional with echo, three 5 s runs each: **1.0–1.14 Gbit/s goodput at 1200 B (106k–119k pps)**; **85–88 Mbit/s at 64 B (165k–171k pps)** | The pps ceiling, not the bandwidth, is the limit: ~170k pps without per-core fan-out means small-packet workloads saturate one core at a fraction of a 10 GbE uplink. Every packet crosses the kernel boundary twice. RFC 7915 ICMP, fragment and timeout handling is all code to write and maintain, and it is one more parser process under R14. Kept because it needs nothing from the kernel. |
| OVS-native | `ct(nat)` cannot rewrite between address families; OpenFlow has no header-family transform | Not implementable in the pipeline. The pipeline's role is the gate: a table-27 divert of `dl_type=0x86dd, ipv6_dst=<prefix>/96` to the translator port, instead of today's `prioIPv6Pass` pass-through. |
| Tayga (userspace, packaged elsewhere) | Not in Alpine 3.22; single-threaded TUN, stateless (needs a NAT44 stage behind it) | Same ceiling as the Go translator with a second dependency and no session state. |
| eBPF XDP/TC translator | No measurement; verifier limits fragments and ICMP error translation; needs BTF and a clang toolchain in the build | Deferred: revisit if the fleet ever runs a kernel Alpine does not package Jool for. |

The trade-off the table settles is **dependency versus ceiling**: a kernel
module the distribution ships, or a translator the platform ships whose
small-packet rate is one core wide. The gateway already depends on the
distribution kernel for OVS, XFRM, WireGuard and nftables; one more module in
that set is a smaller surface than a second packet parser in the daemon. The
packet path, the section shape and the follow-up issues are in
[engineering.md](engineering.md) §5 "IPv6-only clients".

## Component boundaries

| Piece | Package | Notes |
|---|---|---|
| Gateway node model, service registry | `pkg/sdn/gateway/node.go`, `types.go`, `runtime.go`, `handlers.go` | The service constants, the builder table that turns an enabled section into a running backend, and the refusals for sections that have none |
| Supervisor seam | `pkg/sdn/gateway/supervised.go` | `ServiceSupervisor`, the handler that relays a section to a child process, and `ServiceReports` |
| Supervisor IPC | `pkg/sdn/gateway/ipc/` | gRPC over a Unix socket, `SO_PEERCRED` uid policy; the contract is `ipc/proto/ipc.proto` |
| Deprecated mode compatibility | `pkg/sdn/gateway/compat.go` | Do not build on it |
| Mode implementations | `pkg/sdn/gateway/modes/` — `edge.go`, `edge_p2p.go`, `edge_pxe.go`, `overlay.go`, `transit.go` | |
| Firewall, load balancer, perf | `pkg/sdn/gateway/services/{firewall,loadbalancer,perf}` | |
| Control-plane liaison | `pkg/sdn/gateway/controlplane/` | State reporting and desired-config fetch |
| Gateway state | `pkg/sdn/gateway/state/` | |
| Zone service | `pkg/sdn/gateway/zone_service.go` | Network zones at the edge |
| P2P discovery | `pkg/sdn/gateway/p2p/` | **Build-tag gated (`platform_p2p`)**; the P2P trusted network is planned, not implemented |
| Proxy service adapter | `pkg/sdn/gateway/proxysvc/` | |
| **The trusted reverse proxy** | `pkg/proxy/` | Its own package: `authchain.go`, `attestation.go`, `tokenauth.go`, `policy.go`, `balancer.go`, `router.go`, `listener.go`, `handler.go`, `identity.go`, `audit.go`, `metrics.go`, `transport.go`, `config.go`, `deps.go`, `errors.go` |
| Binary | `cmd/gatewayd/main.go` | |
| **Import closure** | enforced by `pkg/arch/gatewayguard_test.go` | Separate from the layer guard; never weaken it |

The §R capability row is *"Edge gateway and trusted reverse proxy (routes,
pools, zones)"*, Tier 1, reached through `services/gateway` and
`services/proxy`.

`gatewayd` has its **own import-closure guard test**
(`pkg/arch/gatewayguard_test.go`), separate from the layer guard. That is
deliberate: the binary that terminates untrusted traffic should not silently
acquire the whole platform's dependency tree.

## The trusted reverse proxy

`pkg/proxy/` is what makes this a *trusted* gateway rather than a router with a
proxy bolted on. Three files carry the distinction:

- **`authchain.go`** — a chain of authentication mechanisms rather than one.
- **`attestation.go`** — attestation is one of the links, so a route can require
  the *client machine* to be attested, not merely the user authenticated.
- **`tokenauth.go`** — broker-token validation. The platform validates the `scp`
  claim offline; it is **not** a token-authorization decision point and does not
  run an authorization engine for tokens.

`policy.go` and the `GetZoneMatrix` RPC connect proxy routing to SDN zones: a
route's reachability is derived from network zoning rather than configured
separately and left to drift.

## Data flow — a request arriving at the edge

1. TLS terminates on the proxy listener (`listener.go`).
2. The auth chain runs (`authchain.go`): token validation, client attestation,
   identity resolution — in the order the chain is configured.
3. Policy is evaluated against the zone matrix (`policy.go`).
4. The router picks a route (`router.go`), the balancer picks a backend from its
   pool (`balancer.go`).
5. The request is forwarded (`transport.go`), and the decision is audited
   (`audit.go`) and counted (`metrics.go`).

Steps 2 and 3 fail closed. A route with no matching policy is not reachable.

## The host packet filter

Open vSwitch filters what crosses the bridge. It structurally cannot filter
traffic addressed to the host itself — the daemons' listeners, ssh, the tunnel
endpoints — and until #569 nothing did: no host filter existed anywhere in
`pkg/`. The gateway is the node that sits on the public side, so it carries one:
`pkg/sdn/gateway/services/hostfw`.

The shape is **declarative and derived, not hand-written**. The filter is
rendered from a `Ruleset` — the **listener inventory** the daemons declare from
their resolved configuration (`ListenerInventory`), the operator's `extra`
listeners for services the platform does not own (sshd on the management leg),
the WAN **peer allowances** (ESP and GRE only from named peer addresses), the
**tunnel interfaces** on which BGP (TCP 179) and BFD (UDP 3784) are admitted,
and a rate limit for ICMP with neighbour discovery always allowed. A listener
nobody declared is unreachable by construction; adding one to a daemon without
adding it to the inventory fails a test before it fails in the field.

It is **interface-scoped**: every allow names the interface it applies to, so a
port opened for the overlay is not opened on the WAN. The rendered table is one
nftables table, `inet tp_host`, with an input chain whose policy is `drop`;
nothing outside that table is ever read or written, so it composes with any
other table the host carries.

Two layers carry it, because a daemon that starts after the network is up
leaves a window:

1. **Install time** — `Config.BaseRulesetPath` names the `.nft` file the boot
   loads (`nft -f`) before any daemon runs. The service rewrites it atomically
   on every successful reconcile, so it is always the last known-good ruleset.
2. **Runtime** — `Service.Reconcile` re-renders from the live inventory and
   replaces the table in one netlink transaction when the fingerprint changed
   or the table went missing. A failed apply is rolled back to the previous
   ruleset; a failed rollback is reported as `RollbackError` and the service
   refuses to claim health until a later reconcile succeeds.

`unfiltered:` exists for a rollout that must not lock an operator out of the
management leg before its listeners are in the inventory; the rendered ruleset
names every such interface so the exception is visible, not implicit.

## Tunnels, transports and uplinks

The gateway reaches its transit relays over point-to-point tunnels
(`pkg/sdn/tunnel`, #582). A tunnel is a **carrier** (GRE, GRE6, IPIP) under a
**transport**: `gre` (plain, the relays' shape today), `ipsec` (the carrier
wrapped in ESP through the kernel's XFRM framework — AES-256-GCM, FIPS-approved,
keys resolved from the platform key store through a `KeyProvider`, never carried
in configuration) or `wireguard` (a kernel WireGuard interface, compiled out of
FIPS builds because its primitives are not approved). The kernel does the
cryptography; the platform does the keys, and zeroizes its copy once the kernel
holds it. Install is fail-closed — protection before carrier — and `Rekey`
rotates SAs in place so the peer can rotate in lockstep without a session drop.

Each WAN uplink owns a **routing table** and `ip rule`s (`UplinkManager`): the
uplink's own addresses and every tunnel's outer endpoint pair are steered into
its table, so a tunnel sourced on one ISP never egresses through the other when
the main table's default changes. This replaces the ASR's `tunnel route-via …
mandatory` and return-path PBR. Liveness is BFD on the BGP session (#556), not
vendor keepalives.

## Trust boundaries

1. **Internet / IoT segment → gateway.** The primary boundary. Everything
   arriving here is untrusted.
2. **Gateway → control plane.** The gateway reports state and fetches desired
   configuration (`pkg/sdn/gateway/controlplane/`, and the REST control-plane
   routes under `/api/v1/gateway`). It consumes configuration; it does not
   author it. The fetched document is a typed, closed contract
   (`gwstate.DesiredConfig`) applied declaratively by `Gateway.Apply`, and the
   outcome rides back in the telemetry snapshot (#555).
3. **Proxy → backend.** Crossed after authentication and policy. A backend pool
   trusts that the proxy did its job, which is why the auth chain fails closed.
4. **BGP peer → gateway.** A BGP session accepts routes from an external
   speaker. Prefix filtering is the control, and it is configuration.
   `RouteSigningKey` in `pkg/sdn/gateway/modes/transit.go` is a single
   in-process Ed25519 key whose signature `AnnouncePrefix` computes and
   discards — nothing is attached to an announcement — so it is
   experimental, not a control (epic #553, ruling R11).
5. **Management VPN.** (Design for the attested remote-access service: [`docs/vpn/`](../vpn/).) `ManagementVPNConfig` (WireGuard) exists so administrators
   reach management endpoints through an authenticated tunnel rather than being
   dual-homed onto a data zone. Gateways should expose it by default.
6. **The host itself.** Traffic *to* the gateway's own addresses never crosses
   the OVS pipeline; the nftables host filter (`services/hostfw`) is the only
   control in front of the daemons' listeners and the tunnel endpoints, and it
   is derived from the listener inventory rather than written by hand.

## A service section is a running backend or a refused start

Before #568 the gateway kept a `ServiceHandler` per section whose `Start` set
a boolean. A gateway with `firewall.enabled: true` reported `firewall: active`
while nothing installed a flow; `IsActive` was the record of a config key, not
of a process. That is the failure the reporter cannot see and the operator
cannot distinguish from a working node, so it is gone.

`handlers.go` holds one **builder table** — service name → constructor of a
`backedService` (`Start`, `Stop`, `Active`, `Healthy`) — and one **refusal
table** — service name → the reason no builder exists. `NewGateway` walks the
enabled sections in a fixed order and registers a `backedServiceHandler` for
every name in the builder table and a `refusedServiceHandler` for every name in
the refusal table. There is no third kind.

| Section | Backend the handler drives | Refused until |
|---|---|---|
| `firewall` | `services/firewall` over the runtime's OVS bridge | — |
| `nat` | `services/nat` | — |
| `load-balancer` | `services/loadbalancer` | — |
| `hostfw` | `services/hostfw` with the listener inventory `HostRuntime` carries | — |
| `tunnels` | `pkg/sdn/tunnel` manager, every configured tunnel ensured, rolled back on the first failure; `ipsec` and `wireguard` keys resolved through `HostRuntime.SecretResolver` | — |
| `transit` (or a `bgp` section) | `pkg/sdn/bgp` speaker with secrets resolved through `HostRuntime.SecretResolver`, every configured neighbour added | — |
| `proxy` | registered by `gatewayd serve` assembly (`proxysvc`), not by the table | — |
| `overlay` | — | the overlay config has no VTEP fields and the encap flow has no output action (#553) |
| `edge` | — | the edge constructor needs an IPv6 pool, ACME toggles and a FROST pool the runtime does not inject (#553) |
| `dhcp` | — | gatewayd has no IPAM allocator (#553) |
| `pxe` | — | the PXE controller needs a serving interface, address and range the section does not carry; platformd's iPXE server provisions today (#553) |
| `management-vpn` | — | a design (`docs/vpn/`, #558) with no implementation |

A `backedServiceHandler` builds its backend on `Start` and drops it on `Stop`,
so `IsActive` is true exactly while a backend exists and `Health` is the
backend's own answer. A `refusedServiceHandler` fails `Start` with
`ErrServiceUnavailable{Service, Reason}`; `Gateway.Start` surfaces it as
`ErrStartupFailed{Phase: "service-start"}` and rolls back what already started.
**An enabled section the gateway cannot run stops the daemon with the reason
in the log; it never reports as running.** The row moves from the refusal table
to the builder table when the implementation lands, and nowhere else.

The builders need host resources the OVS runtime does not model — the host
filter's listener inventory and applier, the tunnel manager, the BGP server
and the secret resolver. Those travel in `GatewayConfig.Host`
(`HostRuntime`, `yaml:"-"`), assembled by `gatewayd serve` from the resolved
configuration: the proxy listeners become the host filter's inventory
(`ProxyListenerInventory`), so a port the proxy binds is a port the filter
admits and nothing else is. A `HostRuntime` field left nil takes the
production default (the netlink applier, a real tunnel manager, an in-process
GoBGP server); tests inject fakes through the same fields. The secret resolver
is the one exception with no production default: it is the platform secret
store from the `secret-store:` section, and where it is absent a service that
names a reference fails closed rather than running unauthenticated.

## The supervisor seam: a section can be a handler for a child process

The same registration walk has a third mode, and it is the one an internet
edge runs in (#557). When `GatewayConfig.Supervisor` is set, **every** enabled
section registers a `supervisedServiceHandler` instead — the builder and
refusal tables are not consulted, because in that model the service is built
inside a child process and this process only relays:

| Call | What it does under a supervisor |
|---|---|
| `Start` | asks the supervisor to bring the owning child process up and the service active inside it |
| `Stop` | releases the service; the child stops once none of its services remain |
| `IsActive` | the child's own verdict, read over the IPC — never a bool this process set |
| `Health` | `ErrServiceUnhealthy{Service, Cause}` when the child is down, over its restart budget, or reports the service unhealthy |

Two consequences are deliberate. `Gateway.Apply` forwards the whole desired
document to the supervisor and records the state the datapath child reports,
rather than reconciling anything locally — the services it would reconcile are
not in this process. And the parent installs no base pipeline: `Runtime` is nil
here because the datapath child holds the OVSDB connection and owns the bridge.

`ServiceReports()` is the one place liveness is collected: one
`{Name, Active, Health}` per registered handler in registration order. The
snapshot's per-component health is derived from it, and the IPC's `Status`
returns it verbatim, so parent and child describe a service the same way.

## The supervisor <-> service-process contract

`pkg/sdn/gateway/ipc` is that IPC: gRPC over a Unix socket per child process, authenticated **only** by the kernel's `SO_PEERCRED`
(`pkg/util/peercred`, shared with platformd's Unix transport). There is no
token and no certificate — a local socket peer's uid is kernel-verified and
cannot be forged.

| Service | Method | Who may call it |
|---|---|---|
| `ProcessControlService` | `Status`, `Snapshot` | the supervisor's uid (root) |
| `DatapathService` | `ApplyDesired` | the supervisor, plus the parser class's unprivileged uid |

The supervisor is root and the parser class runs unprivileged, so the uid is
the whole authorization question. `Policy` is the per-service uid table; an RPC for a service it does not know is
refused (`ErrUnknownService`), so the policy fails closed rather than defaulting
to allow. Structured documents ride as JSON inside the messages:
`gwstate.Snapshot` and `gwstate.DesiredConfig` are already the schema the
control plane, the reporter and the reconciler share, and both ends of the
socket are the same binary — redeclaring them in proto would be a second schema
to keep in step. `ApplyDesired` returns the child's reconciliation state
**beside** its apply error rather than only failing, so a partial apply is still
reportable.

## The base OpenFlow pipeline is the runtime's

Every datapath service — the firewall into the conntrack tables (20/21), NAT
into table 25, the load balancer into table 26 — gates traffic out of
**table 10**, and relies on something having routed table 0 into table 10
first. Until #567 that something was the overlay mode handler, which nothing
in a running binary constructs, so a bridge carried **no table-0 flow at all**:
OVS's implicit table-0 miss is `NORMAL`, every gate was dead, and a gateway
reporting `firewall: healthy` forwarded every packet it claimed to drop.

`GatewayRuntime.EnsurePipeline` (`pkg/sdn/gateway/pipeline.go`) now installs
the hand-off itself, from `Gateway.Start` **before** any service handler
starts (handler iteration is map-random; the pipeline must exist before the
first gate), and `RemovePipeline` tears it down after the last service stops.
It is deliberately not a `ServiceHandler`.

| Property | Value |
|---|---|
| Flows | table 0 → `goto_table:10`, table 10 → `goto_table:30`, table 30 → terminal; all **priority 0**, so a platformd flow in table 0 still wins its match and a service gate in table 10 still diverts |
| Cookie | `CookiePipeline` `0xF1BE0000…` under the gateway's `0xF1BE` owner prefix |
| Terminal | `normal` by default — identical to the bridge's behaviour before the pipeline existed for traffic no service claims. `overlay` is refused (`ErrPipelineTerminalUnavailable`) until the overlay service owns egress: the overlay config has no VTEP port and the table-60 encap flow has no output action |
| `fail_mode` | held at **`secure`** while the pipeline is installed, restored on removal — a controller loss must not fall back to `NORMAL` around the firewall |
| Ownership | recorded in the bridge's `external_ids` (`tp-pipeline-owner=gatewayd:<id>`, `tp-pipeline-terminal`); a bridge another gateway holds is refused (`ErrPipelineOwned`); a crashed gateway's own stale record is reclaimed |
| When | only when a datapath service (firewall, NAT, load balancer, overlay) is enabled and a runtime is injected; a proxy-only or telemetry-only gateway leaves the bridge untouched |

**The two firewalls compose.** platformd programs per-port admission flows on
the same bridge with terminal `normal`, which on a shared bridge would be a
hole straight through the gatewayd firewall. platformd's compilers now carry a
`Terminal` (`zoneflows.TerminalGatewayPipeline` = `goto_table:10`), and
`zoneflows.TerminalForBridge` reads the owner from the bridge's `external_ids`.
The hand-off is **dormant today**: platformd observes and logs the owner but
keeps `normal`, because a flow that points at table 10 blackholes the port the
moment gatewayd stops and empties it — flipping it needs the owner-change
reconcile the supervised process model brings (#557). See
[`docs/sdn/architecture.md`](../sdn/architecture.md) §Trust boundaries.

## High availability

A site's hosts point at one first-hop address per segment, and a gateway pair
must be able to hold it. The mechanism depends on the segment (epic #553,
ruling R7; the handbook's doc 00 amendment is jeremyhahn/handbook#39):

- **Plain L2 segments** (the transit VLAN, management, the public /24 and its
  IPv6 /64) — **VRRPv3** (RFC 5798), `pkg/sdn/fhrp`. One protocol for IPv4 and
  IPv6, one group per virtual router ID and family: the address owner
  (priority 255) or the highest priority is master, advertises every
  `advert-interval-cs` centiseconds to 224.0.0.18 / ff02::12 with TTL 255, and
  holds the virtual addresses; backups take over when
  `3 × Master_Adver_Interval + Skew_Time` passes without an advertisement, or
  after `Skew_Time` when the master announces its release (priority 0). A
  takeover programs the addresses over netlink and announces them with a
  gratuitous ARP / unsolicited neighbour advertisement. Preemption and accept
  mode are per group. The state machine is pure and clock-injected
  (`fhrp.Group`), the sockets and address programming sit behind
  `fhrp.Transport` and `fhrp.Programmer`, and the speaker (`fhrp.Speaker`) is
  a gateway service (`Start/Stop/Active/Health`) the handler table builds
  (#568).
- **Overlay segments** — the **EVPN distributed anycast gateway** (RFC 9135)
  the overlay pipeline already programs per VNI in
  `pkg/sdn/gateway/modes/overlay.go` (`installAnycastGatewayFlows`): every
  gateway answers for the segment's gateway MAC/IP locally, so there is no
  election to run.

The duplicate-address guard (`pkg/sdn/arp`) is told which addresses are
shared (`arp.WithSharedAddress`) so the peer's virtual MAC answering for the
virtual address is not a conflict; any other MAC still is.

**Not implemented:** NAT/conntrack state replication between the pair
(ruling R8: stateless failover first — sessions re-establish) and any
Raft-coordinated VIP takeover. `pkg/sdn/cluster/gateway_partitions.go` still
declares partition keys for such a design; it is referenced by nothing and is
kept only until R8 decides whether conntrack/NAT-session replication uses it or
replaces it. The legacy descriptions under [`docs/sdn/gateway/`](../sdn/gateway/)
and [`docs/sdn/bgp/README.md`](../sdn/bgp/README.md) that described other HA
models are marked superseded (#559).

## Telemetry is one document, derived from the services

Everything a gateway programs is visible without a shell on the box, through
one document: `gwstate.Snapshot`. The gateway assembles it from its own
services — the BGP speaker's session table, the tunnel manager's links and
uplink tables, the host filter's applied ruleset, the NAT plan, the base
pipeline — and four consumers read that one document:

| Consumer | Path |
|---|---|
| Control plane | `POST /api/v1/gateway/telemetry` on the reporter's tick, cached in the state store, read back at `GET /api/v1/gateway/state[/{id}]` |
| gRPC / Unix / QUIC / MCP | `GetGatewaySnapshot` / `ListGatewaySnapshots`, served from that store on a control plane and from the live gateway on a node that runs one |
| WebUI | Networking → Gateway, fleet table plus the per-gateway datapath detail |
| Prometheus | the gatewayd `metrics:` endpoint, a pull collector over the same snapshot |

One derivation means the four cannot disagree. The two rules that make the
document trustworthy — an unrun section is **absent** rather than zeroed, and
an unreadable section is **omitted and logged** rather than guessed — are in
[`engineering.md`](engineering.md) §8 with the per-section provenance table.

## What this feature deliberately does not do

- **It does not serve the composed platform SDK.** Gateways terminate and route.
- **It does not decide token authorization.** It validates broker tokens offline.
- **It does not implement the P2P trusted network.** `pkg/sdn/gateway/p2p/` is
  libp2p peer discovery behind the `platform_p2p` build tag. The P2P/DHT
  designs are planned work with no implementation; do not build against them.
- **It does not own the port authentication state machine.** That is SDN —
  [`docs/sdn/`](../sdn/).
- **It is not configured by `GatewayMode`.** See above.
