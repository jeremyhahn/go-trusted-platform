# SDN — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/sdn/` (excluding `pkg/sdn/gateway/`), `pkg/switch/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> Design and boundaries: [architecture.md](architecture.md). Transport matrix:
> [api.md](api.md). The edge gateway is a separate feature —
> [`docs/gateway/`](../gateway/).

---

## 1. Package layout

`pkg/sdn/` is the largest subsystem in the repository: seventeen sub-packages
plus four files at the root.

| Package | Holds |
|---|---|
| `pkg/sdn/ovs` | Open vSwitch / OVSDB client |
| `pkg/sdn/openflow` | OpenFlow protocol and flow programming |
| `pkg/sdn/policy` | **Port authentication state machine**, quarantine, zone flows, enrollment hook |
| `pkg/sdn/ipam` | IP address management |
| `pkg/sdn/dhcp` | DHCP server |
| `pkg/sdn/vlan`, `pkg/sdn/vxlan`, `pkg/sdn/tunnel` | Segmentation and encapsulation |
| `pkg/sdn/overlay` | VXLAN/EVPN overlay control |
| `pkg/sdn/bgp` | BGP speaker (EVPN control plane and prefix announcement) |
| `pkg/sdn/fabric` | Multi-host fabric composition |
| `pkg/sdn/zone` | Network zones |
| `pkg/sdn/arp`, `pkg/sdn/ct` | ARP handling (table reader + RFC 5227 duplicate-address detection), connection tracking |
| `pkg/sdn/netlink` | Host networking via netlink (TAP, links, routes) |
| `pkg/sdn/cluster` | Cluster-wide SDN state |
| `pkg/sdn/gateway` | **Not this feature** — see [`docs/gateway/`](../gateway/) |
| root: `config.go`, `errors.go`, `identity.go`, `zone_index.go` | Configuration, typed errors, port identity, zone lookup |

`pkg/switch/` is separate and small: physical switch management — `ssh.go`,
`ssh_manager.go`, `cisco_nexus.go`, `factory.go`, `manager_factory.go`,
`noop.go`, `noop_manager.go`, `service.go`, `types.go`, `errors.go`.

`pkg/sdn/netlink` is one of the packages `make test` deliberately excludes
because it needs real host networking; it is covered by `make integration-test`.

## 2. The port authentication state machine

This is the feature's core, and the thing most likely to be got wrong.

**It is IDevID-certificate port authentication, not EAP/RADIUS.** A port is
authorised because the device on it presented a valid IDevID certificate, not
because a RADIUS server said so. Nothing in `pkg/sdn/policy` speaks EAP.

`PortState` (`pkg/sdn/policy/types.go:26`) is an `int` with eight values:

| Constant | `String()` | Meaning |
|---|---|---|
| `PortStateUnconnected` | `unconnected` | Port not yet detected |
| `PortStateProvisioning` | `provisioning` | Limited access, enough to enroll |
| `PortStateEnrolled` | `enrolled` | Device enrolled, awaiting activation |
| `PortStateUnauthorized` | `unauthorized` | Not authenticated |
| `PortStateAuthenticating` | `authenticating` | Authentication in progress |
| `PortStateAuthorized` | `authorized` | Authenticated and authorised |
| `PortStateQuarantined` | `quarantined` | Isolated VLAN for scanning or remediation |
| `PortStateBlocked` | `blocked` | Blocked on policy violation |

**Transitions are an explicit allowlist**, not free movement
(`pkg/sdn/policy/state.go:187`):

```
unconnected   -> provisioning | blocked
provisioning  -> enrolled | unauthorized | authenticating | authorized | blocked
enrolled      -> authorized | provisioning | blocked
unauthorized  -> authenticating | provisioning | blocked
authenticating-> authorized | unauthorized
```

Two consequences that are easy to miss:

- **Every state can reach `blocked`, and `blocked` is not in any source list.**
  A blocked port does not transition out on its own; unblocking is an
  administrative action.
- **`enrolled` can return to `provisioning`** — that is the re-enrollment path,
  and it is deliberate. Removing it would make a re-provisioned device
  unrecoverable without physically moving it.
- **Enrollment completion without a registered port is not an error.**
  MAC-to-port mappings exist only for devices that attached through the OVS
  fabric (connect-time registration). A device enrolling over the management
  LAN — a worker joining the control plane before any fabric attach — has no
  port, so the enrollment hook (`pkg/sdn/policy/enrollment_hook.go`) logs a
  WARN, records the pending activation keyed by serial (carrying the device
  MAC), and returns success: the certificate is issued on the validated
  attestation. The state machine engages once the device attaches — the
  connect-time path registers the MAC-to-port mapping and applies the
  provisioning phase — and a later activation resolves the deferred port
  from the MAC. Every failure downstream of a known port (policy engine,
  state transition) still fails closed.

`PortStateUnconnected` is `iota`, so it is the **zero value**. An uninitialised
`PortState` therefore reads as `unconnected`, which is the safe default: a port
nothing knows about carries no authorisation.

## 3. Configuration

`sdn.Config` (`pkg/sdn/config.go:263`), with these nested types:
`OVSConfig`, `DPDKConfig`, `IPAMConfig`, `PoolConfig`, `DHCPConfig`,
`NetworkConfig`, `OverlayConfig`, `GatewayConfig`, `TransitConfig`,
`ManagementVPNConfig`, `ZoneServiceConfig`, `IdentityConfig`.

YAML keys observed on these structs: `backend`, `bridge`, `cidr`, `controller`,
`datapath`, `dhcp`, `enabled`, `encode_zone_in_cert`, `gateway`, `init`,
`interface`, `name`, `socket`, `vlan`, `zone`.

**`encode_zone_in_cert` is a trust decision, not a formatting one.** When true,
a device's network zone is carried inside its IDevID certificate, so the zone is
attested rather than asserted at connection time. Turning it off moves zone
assignment to something the device can influence.

### Validation errors — the config fails closed and loudly

`pkg/sdn/config.go` declares twenty-two typed errors, which is unusual density
and tells you where the sharp edges are:

| Error | Fires when |
|---|---|
| `ErrInvalidConfig`, `ErrInvalidOVSSocket`, `ErrInvalidBridge` | Basic wiring wrong |
| `ErrInvalidPoolName`, `ErrInvalidPoolCIDR`, `ErrInvalidNetworkPool` | IPAM pool malformed |
| `ErrDuplicatePoolName`, `ErrDuplicateNetworkVLAN`, `ErrDuplicateNetworkName`, `ErrDuplicateNetworkSubnet` | Two definitions collide |
| `ErrMissingNetworkZone`, `ErrUnknownNetworkZone`, `ErrPoolZoneUndeclared`, `ErrNetworkPoolZoneMismatch`, `ErrManagementVPNUnknownZone` | Zone graph inconsistent |
| `ErrInvalidNetworkVLAN`, `ErrInvalidTransitVLAN`, `ErrSubnetPoolMismatch` | Segmentation inconsistent |
| `ErrIPAMBackendUnconfigured`, `ErrIPAMBackendUnknown`, `ErrIPAMBackendP2PRequired` | IPAM backend selection wrong |
| `ErrInvalidTCPolicy`, `ErrTCPolicyWithoutHWOffload`, `ErrDPDKRequiresNetdev` | Datapath combination impossible |

The last three encode hardware constraints in the type system: a traffic-control
policy without hardware offload, and DPDK without a `netdev` datapath, are
configurations the kernel cannot honour. They are rejected at load, not
discovered as packet loss.

**The zone errors are the ones that will bite.** Five of the twenty-two are
about zones referring to things that do not exist or do not agree. Zones are the
unit segmentation hangs off; get the zone graph right first and most of the rest
follows.

## 4. Invariants

1. **A port's state is authoritative in the control plane, and flows follow
   it.** `zone_flow_manager.go` and `ovs_flow_controller.go` translate state into
   OpenFlow rules. Programming a flow that contradicts port state is a bug, not
   an override.
2. **A quarantined port is on an isolated VLAN, not merely marked.** Quarantine
   is enforced in the datapath (`quarantine.go`, `quarantine_manager.go`); a
   quarantine that only changed a database row would be no quarantine.
3. **Zone membership is decided once, at authorisation.** With
   `encode_zone_in_cert` the zone comes from the certificate; without it, from
   configuration. Either way the device does not choose it.
4. **VLAN, subnet, pool and zone must agree.** The four duplicate/mismatch error
   families exist because an inconsistency here produces silent cross-zone
   reachability — the failure mode segmentation exists to prevent. `subnet6:`
   joins the same uniqueness check and must be an IPv6 prefix.
5. **The zone firewall compiler is dual-stack.** `pkg/sdn/policy/zoneflows`
   emits an IPv6 twin (`dl_type=0x86dd`, `ipv6_dst`) for every IPv4 rule and
   the ICMPv6 neighbor-discovery allowances that pair with ARP; a static test
   (`assertFamilyParity`) fails the build if a rule has no twin. Server
   addresses in the zone templates are rendered in their own family, so an
   IPv6 DNS or ACME server never becomes an invalid `nw_dst`. Details:
   [`firewall/architecture.md`](firewall/architecture.md) §Table 21.
6. **`FlushFlows` is destructive and unconditional.** It has an RPC and a CLI
   verb; there is no per-flow filter on it.

## 5. Error semantics and fail-closed paths

Every configuration error in §3 is raised at load and prevents the SDN
subsystem starting. That is the intended behaviour: a partially valid network
policy is worse than none, because it looks like it is working.

At runtime, the fail-closed paths are: an unauthenticated port stays in
`unauthorized` (no default-allow), an unknown zone is refused rather than
mapped to a default, and a failed IDevID validation moves the port toward
`unauthorized`/`blocked` rather than leaving it where it was.

A port the fabric has never seen is not a fail-closed subject: there is no
port to hold closed, so enrollment does not fail on it (§2) — enforcement
attaches when the port appears.

**Bridge addressing is the sixth fail-closed path.** Before `initBridgeIPs`
(`pkg/app/sdn.go`) assigns a configured address to an OVS bridge, it probes
the segment for that address: `arp.DuplicateAddressDetector.Check` sends three
RFC 5227 ARP probes on the bridge interface — sender protocol address
`0.0.0.0`, so no receiver caches the probe itself — and listens one second
after each. A reply, or another host's request, carrying that address from a
MAC that is not ours is a defence, and the address is refused.

The refusal is narrow by design, and the boundaries matter:

- **A measured conflict fails the address closed, not the daemon.** The
  address is not assigned, the conflict is recorded on the `App`, and the loop
  moves to the next bridge. `initBridgeIPs` still returns nil so bring-up
  continues: a node that is wrong about one address is still worth having on
  its others.
- **An unusable probe fails open, but never silently.** No `CAP_NET_RAW`, an
  interface that is not visible, a non-Linux build — none of these say
  anything about the segment, and refusing an address over a broken diagnostic
  would take a control plane offline for no measured reason. The assignment
  proceeds. The unguarded assignment is *recorded* as a
  `BridgeAddressProbeUnavailable` (bridge, address, cause) and reported
  degraded, because the one outcome a guard must never produce is a node that
  stopped guarding and still looks healthy.
- **The detector never reports itself.** AF_PACKET sockets see the frames they
  transmit, so a defence whose sender MAC equals the bridge's own MAC is
  discarded.
- **There is no configuration knob.** The guard is always on. The platform
  runs no first-party protocol that deliberately shares a bridge address
  between two stations (no VRRP/HSRP speaker of its own), so there is nothing
  to opt out of. If that changes, the knob is a decision to record in
  `docs/00` first, not an option to add here.

The typed errors are `arp.ConflictError` (both hardware addresses, the
interface, and the address) and the `app.ErrBridgeAddressConflict` refusal
wrapped around it, which is the message operators grep for.

Quarantine never degrades silently. Three rules, all enforced:

0. **A present-but-unreadable zone extension is invalid policy input.**
   Only a genuinely absent `OIDTPNetworkZone` extension falls back to the
   profile zone (pre-Z3 compatibility). A malformed extension makes
   `buildPortPolicy` build no policy and return
   `ErrZoneExtensionInvalid` — it never falls open to the trusted policy.

1. **A quarantine policy carries the quarantine VLAN, never the trusted
   one.** On a zone mismatch `buildPortPolicy` sets `VLAN` to the profile's
   failure-network VLAN, or its provisioning VLAN when no failure network is
   declared, and drops the production ACLs. A quarantine VLAN equal to the
   trusted VLAN is `ErrQuarantinePolicyContradiction`; a profile with
   neither VLAN is `ErrQuarantineVLANUnavailable`. Both build no policy, so
   activation fails closed.
2. **The engine's VLAN-direct fallback refuses quarantine-zone policies.**
   `Engine.ApplyPolicy` falls back to a VLAN-direct path when no
   `ZoneFlowManager` is configured (the daemon tolerates its absence). That
   path cannot enforce zone isolation, so a policy declaring the quarantine
   zone (resolved from `Config.Zones` by `LifecycleRoleQuarantine`, default
   `quarantine`) is refused with `ErrZoneEnforcementUnavailable` before any
   state or datapath change. The enrollment hook surfaces it as a hard
   activation failure, not as a successful quarantine. Hook construction
   does not fail on a missing zone manager — that would take the whole
   device service down; the fail-closed belongs at policy application.

Zone cross-check runs only when the hook is built with a `PolicyExtractor`
and the resolved zone set. The production wiring
(`pkg/daemon/commands/sdn_enrollment_init.go`) passes both — the daemon's
resolved zones feed the `X509PolicyExtractor` and the quarantine-zone
resolution — and `TestSDNEnrollmentHookWiring_ZoneMismatchQuarantines`
proves through that exact config that a mismatched certificate zone
quarantines instead of being silently accepted.

## 6. Physical switches

`pkg/switch/` manages real hardware over SSH. `factory.go` and
`manager_factory.go` select an implementation; `cisco_nexus.go` is the one
vendor implementation; `noop.go`/`noop_manager.go` are the null implementations
used when no physical switch is present and in tests.

The surface is deliberately narrow — five RPCs (`SwitchService` in
`pkg/api/grpc/proto/switch.proto`): `ListPorts`, `GetPortStatus`,
`SetPortVLAN`, `EnablePort`, `DisablePort`. Physical switch management is
VLAN assignment and port enable/disable, nothing more. Do not grow it into a
general switch-configuration API.

## 7. Test strategy

| Layer | Location | Covers |
|---|---|---|
| Unit | `pkg/sdn/**/*_test.go`, `pkg/switch/*_test.go` | State machine transitions, config validation, flow generation, IPAM allocation |
| Integration | `test/integration/sdn/`, `test/integration/network/` | OVS bridges, flows, port auth against a real datapath |

`pkg/sdn/netlink` is excluded from `make test` and needs `make integration-test`.
`noop.go` in `pkg/switch/` is the fixture that lets switch-dependent paths run
without hardware.

BGP peer health is tested by calling `PeerManager.checkPeerHealth` directly:
what the subtests assert is what a health check does to a peer, which is a
property of the check and not of how many checks fit inside a wall-clock window.
The old form slept 200ms against a 50ms interval and, on a loaded host, landed
on the wrong element of the mock's scripted state list (issue #223). One subtest
still runs the monitor to pin that the ticker performs checks at all; it
advances on `GetPeerState` calls observed through the mock speaker, so the
interval only sets how fast they arrive. `StopHealthMonitor` joins the monitor
goroutine, so the post-stop read is not a race.

**Known repo-wide gap:** no `CommandDefinition` type exists in this repository
(grepped 2026-08-18), so the CLI parity requirement in
`conventions/feature-docs.md` §4 is unmet repo-wide.

## 8. Observability

`pkg/sdn/policy/monitor.go` watches port state. Flow logs stream over gRPC as
`SDNService.StreamFlowLogs` — the only streaming RPC in the SDN service, and
the right tool when you need to see what the datapath is actually doing rather
than what the control plane believes.

`platformctl sdn port stats <port-id>` and `sdn perf` surface counters;
`sdn perf conntrack` and `sdn perf datapath` reach the connection-tracking and
datapath statistics.

The guard has two reportable outcomes, and they are not interchangeable. A
**refused address** is not on the wire and something is broken now. An
**unprobed address** is on the wire and may be perfectly fine, but nothing
checked it.

| Signal | Where | Lifetime |
|---|---|---|
| Log line — the `sdn: refusing to assign …` refusal, with `bridge`, `address`, `local_mac`, `responder_mac` | platformd bring-up log | the log |
| Log line — `SDN: duplicate-address probe unavailable, assigning address unguarded`, with `bridge`, `address`, `error` | platformd bring-up log | the log |
| Platform event — type `EVENT_TYPE_ERROR`, severity `CRITICAL`, source `sdn.addressing`, both MACs in metadata. Refusals only: an unprobed address is not an incident, it is missing evidence | `PlatformDaemon.StreamEvents` | delivered to whoever is streaming when the daemon starts |
| Health component `sdn-addressing` — `degraded`, message prefixed `address-conflict`, one `conflicts` detail entry per refused address | every health transport | until the node restarts with the addressing fixed |
| Health component `sdn-addressing` — `degraded`, message prefixed `probe-unavailable`, one `probe_unavailable` detail entry per unprobed address carrying the cause | every health transport | until the node restarts with the probe working |

When both are present the component reports both, refusal first, because it is
the one with a live consequence. `conflict_count` and
`probe_unavailable_count` are always in the details, including on a healthy
node, so a consumer can distinguish "nothing to report" from "not reported".

The health component is the durable signal. The guard runs once, inside App
bring-up, before any transport is listening, so the event is replayed when the
daemon wires its event stream and a client that connects later will not see
it — but it can read the component at any time.

## 9. Related

- [architecture.md](architecture.md) · [api.md](api.md) · [cli.md](cli.md) · [user.md](user.md)
- [`docs/gateway/`](../gateway/) — gatewayd, BGP, IPAM at the edge, reverse proxy
- [`docs/switch/`](../switch/) — physical switch detail
- Deep dives carried over and not re-verified in this pass: [802.1x.md](802.1x.md),
  [configuration.md](configuration.md), [provisioning.md](provisioning.md),
  [testing.md](testing.md), and the `bgp/`, `dhcp/`, `fabric/`, `firewall/`,
  `ipam/`, `overlay/`, `performance/`, `tunnel/` subdirectories
