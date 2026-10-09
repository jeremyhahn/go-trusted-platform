# SDN — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/sdn/` (excluding `pkg/sdn/gateway/`), `pkg/switch/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> Design and boundaries: [architecture.md](architecture.md). Transport matrix:
> [api.md](api.md). The edge gateway is a separate feature —
> [`docs/gateway/`](../gateway/).

---

## 1. Package layout

`pkg/sdn/` is the largest subsystem in the repository: seventeen sub-packages
plus a handful of files at the root.

| Package | Holds |
|---|---|
| `pkg/sdn/ovs` | Open vSwitch / OVSDB client |
| `pkg/sdn/openflow` | OpenFlow protocol and flow programming |
| `pkg/sdn/policy` | **Port authentication state machine**, quarantine, zone flows, enrollment hook |
| `pkg/sdn/ipam` | IP address management |
| `pkg/sdn/dhcp` | DHCP server |
| `pkg/sdn/netplan` | **The network plan**: the only place VLAN IDs, subnets, VNIs, IPAM pools, reserved ranges and port-class VLAN lists are derived |
| `pkg/sdn/vxlan`, `pkg/sdn/tunnel` | Encapsulation |
| `pkg/sdn/overlay` | VXLAN/EVPN overlay control |
| `pkg/sdn/bgp` | BGP speaker (EVPN control plane and prefix announcement) |
| `pkg/sdn/fabric` | Physical switch fabric: switches, peers, LAGs, port classes |
| `pkg/sdn/zone` | Underlay zones: built-ins at fixed offsets, owner-defined zones, policy matrix |
| `pkg/sdn/arp`, `pkg/sdn/ct` | ARP handling (table reader + RFC 5227 duplicate-address detection), connection tracking |
| `pkg/sdn/netlink` | Host networking via netlink (TAP, links, routes) |
| `pkg/sdn/cluster` | Cluster-wide SDN state |
| `pkg/sdn/gateway` | **Not this feature** — see [`docs/gateway/`](../gateway/) |
| root: `config.go`, `errors.go`, `identity.go`, `networks.go` | Configuration (builds the plan), typed errors, port identity, per-zone flow summaries |

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

`sdn.Config` (`pkg/sdn/config.go`) carries `Environment` (a
`netplan.Environment`), `Zones`, and the nested `OVSConfig`, `DPDKConfig`,
`IPAMConfig`, `PoolConfig`, `DHCPConfig`, `OverlayConfig`, `GatewayConfig`,
`fabric.FabricConfig`, `ManagementVPNConfig` and `IdentityConfig`. There is
no per-network or per-VLAN configuration: `Validate` resolves the zones,
validates them and derives the plan, which `Config.Plan()` returns.

**`encode_zone_in_cert` is a trust decision, not a formatting one.** When true,
a device's network zone is carried inside its IDevID certificate, so the zone is
attested rather than asserted at connection time. Turning it off moves zone
assignment to something the device can influence.

### Validation errors — the config fails closed and loudly

| Error | Package | Fires when |
|---|---|---|
| `ErrInvalidConfig`, `ErrInvalidOVSSocket`, `ErrInvalidBridge` | `sdn` | Basic wiring wrong |
| `ErrEnvironmentRequired` | `sdn` | SDN enabled without `environment:` |
| `ErrInvalidPoolName`, `ErrInvalidPoolCIDR`, `ErrDuplicatePoolName` | `sdn` | An explicit IPAM pool malformed |
| `ErrPoolNameReserved`, `ErrPoolOverlap`, `ErrPoolZoneUndeclared` | `sdn` | An explicit pool collides with the plan |
| `ErrManagementVPNUnknownZone` | `sdn` | The VPN names an undeclared zone |
| `ErrIPAMBackendUnconfigured`, `ErrIPAMBackendUnknown`, `ErrIPAMBackendP2PRequired` | `sdn` | IPAM backend selection wrong |
| `ErrInvalidTCPolicy`, `ErrTCPolicyWithoutHWOffload`, `ErrDPDKRequiresNetdev` | `sdn` | Datapath combination impossible |
| `ErrBuiltinIdentity`, `ErrOmitRequired`, `ErrOmitUnknown` | `zone` | A built-in zone renumbered, re-classed or omitted when required |
| `ErrOwnerZoneOffset`, `ErrDuplicateOffset`, `ErrOwnerZonePortClass`, `ErrOwnerZoneField`, `ErrReservedZoneName` | `zone` | An owner-defined zone malformed |
| `ErrPrivilegedAccessRequired` | `zone` | A path into control-plane or management without an audited override |
| `ErrLifecycleRoleCount`, `ErrUnknownZoneRef`, `ErrOOBWithInternetIngress` | `zone` | Zone graph inconsistent |
| `ErrEnvironmentID`, `ErrBase`, `ErrULA`, `ErrOverride` | `netplan` | Environment inputs malformed |
| `ErrDuplicateVLAN`, `ErrOverlap`, `ErrVLANOutOfRange` | `netplan` | Two zones collide, or a zone lands in the IPAM pool, link-local space or host-services `/64` |

The datapath errors encode hardware constraints in the type system: a
traffic-control policy without hardware offload, and DPDK without a `netdev`
datapath, are configurations the kernel cannot honour. They are rejected at
load, not discovered as packet loss.

**The numbering errors are the ones that will bite on a non-reference site.**
An override moves one zone; it cannot land on another zone's VLAN or subnet,
in the IPAM pool, or in a reserved range. The plan refuses the whole
configuration rather than guessing.

### The terminal of an allow rule (#567)

`zoneflows.ZoneFlowConfig.Terminal`, `zoneflows.MatrixRuleConfig.Terminal`,
`policy.ZoneFlowManagerConfig.Terminal` and `policy.Config.Terminal` carry one
value through every compiler that emits an allow rule: the zone templates
(`GeneratorSet.Generate`), the inter-zone matrix (`CompileMatrixRules`) and
the per-port rule generator (`RuleGenerator`). `zoneflows.ApplyTerminal`
rewrites only the bare `normal` terminal (and the `…,normal` suffix of a
`mod_vlan_vid` allow); drops and outputs are never touched, and no match
string changes. `CompileStatefulMatrixRules` ignores it — its rules live
inside the gateway's own pipeline. The bridge `external_ids` keys
(`zoneflows.PipelineOwnerKey`, `PipelineTerminalKey`) and
`zoneflows.TerminalForBridge` are the shared definition both daemons read;
platformd's `pipelineTerminalForBridge` (`pkg/daemon/commands/quarantine_init.go`)
observes the owner and keeps the terminal `normal` until owner-change
reconcile lands.

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
7. **A flow string is encoded completely or refused.** Every service writes
   its flows in the ovs-ofctl grammar. `pkg/sdn/ovs` (`parseMatchString`,
   `parseActions`) encodes them to OpenFlow itself, and an unknown match field
   or action is an error (`unsupported match field` / `unsupported action`),
   never skipped. Until #718 the encoder skipped what it did not know, so flows
   were installed broader or weaker than written, and the logs said nothing:
   - the zone compiler's `ipv6_dst` matches and ICMPv6 `icmp_type`
     allowances (invariant 5) were installed without those fields;
   - the NAT service's per-uplink `load:N->NXM_NX_REG0[]` / `reg0=N`
     selection never reached OVS;
   - the load balancer's reply mark and `resubmit` were dropped;
   - the compute adapter's `set_field:` actions were dropped.

   The grammar now covers:
   - `regN=V[/M]` matches;
   - `icmp_type`/`icmp_code` (ICMPv6 under `nw_proto=58`);
   - `ipv6_src`/`ipv6_dst` (address or prefix);
   - the protocol keywords (`ip`, `tcp`, `icmp6`, ...);
   - `load:V->NXM_NX_REGn[a..b]`, `resubmit(,T)` and
     `set_field:V->{eth,ip}_{src,dst}`;
   - `vlan_vid=V[/M]`, the raw OXM VLAN_VID: `vlan_vid=0x1000/0x1000`
     matches every tagged frame, which `dl_vlan` cannot say. The NAT64
     hand-off uses it to strip the tag of exactly those frames (#614).

   An unparseable cookie is `ErrInvalidCookie`, never cookie 0 (#614). The
   cookie is how a flow's owner deletes it.

   The new encodings are pinned against `ovs-ofctl parse-actions`
   (`pkg/sdn/ovs/flow_grammar_test.go`, `pkg/sdn/openflow/nicira_test.go`).
   A flow dump's `table=` and `cookie=V/M` scope the stats request; they are
   not match fields.

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
- **There is no opt-out knob; there is a shared-address declaration.** The
  guard is always on. The one protocol the platform runs that deliberately
  shares an address between two stations is the gateway's VRRPv3 speaker
  (`pkg/sdn/fhrp`, RFC 5798 — epic #553 ruling R7, handbook amendment
  jeremyhahn/handbook#39). It declares each virtual address to the detector
  with `arp.WithSharedAddress(ip, virtualMAC)`: a defence of that address
  from the group's virtual MAC (`00:00:5e:00:01:{vrid}` / `00:00:5e:00:02:{vrid}`)
  is accepted, a defence from any other MAC is still a `ConflictError`, and
  an undeclared address is guarded exactly as before. Nothing else may
  widen the guard.

The typed errors are `arp.ConflictError` (both hardware addresses, the
interface, and the address) and the `app.ErrBridgeAddressConflict` refusal
wrapped around it, which is the message operators grep for.

Quarantine never degrades silently. Three rules, all enforced:

0. **A present-but-unreadable zone extension is invalid policy input.**
   Only a genuinely absent `OIDTPNetworkZone` extension falls back to the
   profile zone (pre-Z3 compatibility). A malformed extension makes
   `buildPortPolicy` build no policy and return
   `ErrZoneExtensionInvalid` — it never falls open to the trusted policy.

1. **A quarantine policy carries the quarantine VLAN, never the admitted
   one.** On a zone mismatch `buildPortPolicy` sets `VLAN` to the profile's
   failure-network VLAN, or its provisioning VLAN when no failure network is
   declared, and drops the production ACLs. A quarantine VLAN equal to the
   admitted VLAN is `ErrQuarantinePolicyContradiction`; a profile with
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
| Unit, real GoBGP | `pkg/sdn/bgp/rtc_dynamic_gobgp_test.go` | RT-Constrain filtering of EVPN routes; dynamic neighbours admitted only from the fabric prefix (§9.4) |
| Integration | `test/integration/ipsec/` (`make integration-test-ipsec`) | musl charon peers in netns, IKEv2 through the go-xkms PKCS#11 module, ESP checked with `ip xfrm`; the fail-closed floor, eviction and IKE limiter on a real kernel (§9.3) |

`pkg/sdn/netlink` is excluded from `make test` and needs `make integration-test`.
`noop.go` in `pkg/switch/` is the fixture that lets switch-dependent paths run
without hardware.

BGP routing policy is tested against two real GoBGP speakers peered over
loopback in the same process (`pkg/sdn/bgp/policy_session_test.go`), not
against the mock server. A mock accepts whatever policy it is handed, which is
how a per-peer policy GoBGP never applies passed every test until #717. The
session tests assert what each speaker's RIB and adjacency tables actually hold:
an out-of-allowlist route is present in Adj-RIB-In and absent from the RIB, and
an out-of-allowlist export is absent from Adj-RIB-Out and from the peer, for an
eBGP ipv4/ipv6 unicast session and an iBGP l2vpn-evpn session. The same file
proves the EVPN prefix limit: 1500 EVPN routes hold the session, and a peer
over its configured `max-evpn-prefixes` loses it. Each session comes up in
about two seconds (GoBGP's minimum connect retry); waits poll the real
condition with a bound.

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

## 9. IPsec transport: the build and what the spike measured (#716)

The overlay's IPsec transport (release plan §5.2, #709) rests on four things:

- a strongSwan build the platform owns;
- charon signing with keys held behind the go-xkms PKCS#11 module;
- GoBGP features the route reflectors need;
- kernels that carry the datapath.

Spike S (#716) built the first, measured the other three, and pinned what it
found in tests. Nothing in this section is wired into platformd yet; the
control path (`pkg/sdn/ipsec`, VICI) is #709.

### 9.1 The strongSwan build

`build/docker/strongswan-builder` produces `trusted-platform-strongswan`: charon
(IKEv2 only) and swanctl, strongSwan **6.0.7**, built for Alpine 3.22 (musl) on
amd64 and arm64 and packaged as signed apks with an OpenRC service.
`make strongswan-build | strongswan-verify | strongswan-clean`; the builder's
README carries the detail.

- **Source.** The tarball must have a good signature by the strongSwan release
  key *and* the pinned SHA-256. gpgv accepts any key in its keyring, so the
  `VALIDSIG` primary-key fingerprint is also compared with the pin
  (`948F158A4E76A27BF3D07532DF42C170B34DBA77`).
- **Plugins.** `openssl pkcs11 vici counters nonce kernel-netlink socket-default
  pem revocation constraints updown`, built with `--disable-defaults
  --disable-ikev1`.
  - The package step fails if any other plugin is installed.
  - The plan's "openssl, pkcs11, swanctl, vici only" is honoured for crypto,
    keys and control. The rest are the infrastructure charon cannot run
    without: `nonce` (IKE nonces), `kernel-netlink` (XFRM), `socket-default`
    (UDP 500/4500), `pem`, `revocation` (CRL checks, for
    `revocation=strict`), `constraints` (the tunnel CA's name constraints)
    and `updown` (the identity check the plan puts in the updown hook).
  - `counters` is forced on by configure whenever `vici` is enabled.
  - There is deliberately no `x509` plugin. The openssl plugin decodes X.509
    certificates and CRLs (`CERT_DECODE` for `CERT_X509`/`CERT_X509_CRL`).
    The suite asserts that certificates load and that no X.509/CRL decoder
    is missing. OCSP and attribute certificates are not decodable, and the
    platform's push-CRL revocation needs neither.
  - PSK authentication lives in charon's core and cannot be compiled out, so
    connections must say `auth = pubkey`.
- **Privilege.** charon is built `--with-user=strongswan --with-group=strongswan
  --with-capabilities=libcap`. It starts as root, then runs as `strongswan`
  with `CapEff=0x1000` (`CAP_NET_ADMIN` only), as the suite measures. The vici
  plugin creates the socket as `strongswan` (0660); the packaged service
  re-owns it to the platform user at 0600 (§9.6).
- **Plugin load order.** charon loads its plugins, the PKCS#11 provider
  included, *before* it drops root. A provider that authenticates its caller
  at `C_Initialize` therefore sees uid 0. The node-local xkms server's
  SO_PEERCRED check (plan §5.2) must allow for this, or authenticate per
  session.
- **ML-KEM.** Alpine 3.22's OpenSSL provides ML-KEM-768 through the openssl
  plugin. The suite negotiates
  `AES_GCM_16_256/PRF_HMAC_SHA2_384/ECP_384/KE1_ML_KEM_768` (RFC 9370 hybrid)
  for IKE and `aes256gcm16-ecp384-ke1_mlkem768-esn` for the CHILD_SA. No `ml`
  plugin is needed.
- **arm64.** The arm64 apk builds natively under binfmt/qemu-user. That
  requires the qemu that `make binfmt` now registers (`tonistiigi/binfmt`,
  qemu 10.2.3, pinned by digest). Under the qemu 7.2 that `make init` used to
  register (`multiarch/qemu-user-static`), Alpine's gcc 14 segfaulted in `cc1`
  and `collect2` on two consecutive builds.

### 9.2 PKCS#11 on musl: the module cannot be loaded in-process

**Result:** charon cannot dlopen the go-xkms module on musl, on either arch, and
neither can a musl `p11-kit server`. The working path is charon →
`p11-kit-client.so` → a p11-kit **0.26** server running under **glibc** that
hosts the module.

What was measured, with the module built from go-xkms v0.17.0-alpha (what
go.mod resolves) and from main, `-buildmode=c-shared`, Go 1.27, against Alpine
3.22 musl 1.2.5:

| Attempt | amd64 | arm64 (qemu-user) |
|---|---|---|
| `dlopen` from a C program | refused: `initial-exec TLS resolves to dynamic definition` (musl then segfaults formatting that error for the module) | SIGSEGV inside `dlopen` |
| Loaded at start-up (`LD_PRELOAD`), so the TLS check passes | the Go runtime crashes in `runtime.sysargs` (argc garbage, argv nil) for one library; another happened to start | loads, then crashes on the first Go call |
| `p11-kit server` (musl) hosting the module | the per-connection `p11-kit-remote` child dies with SIGSEGV | not run; same loader |
| `p11-kit server` (glibc) hosting the module, charon on musl loading `p11-kit-client.so` | **works**: IKEv2 established, ESP installed (§9.3) | **works**: IKEv2 established, ESP installed, in an aarch64 VM (§9.3) |

The cause is two independent properties of a gc-toolchain c-shared object,
neither of which the platform can change:

- **Initial-exec TLS.** The Go runtime reaches its `g` through initial-exec
  TLS: `R_X86_64_TPOFF64` with `DF_STATIC_TLS` on amd64,
  `R_AARCH64_TLS_TPREL64` on arm64. musl reserves no surplus static TLS, so
  it satisfies those relocations only for objects loaded at program start.
- **Missing argc/argv.** musl calls `DT_INIT_ARRAY` entries with no
  arguments, while Go's c-shared `rt0` reads argc, argv and envp from them,
  as glibc passes.

Both are golang/go#13492, still open. Preloading avoids the first only by
relying on undefined register contents for the second, so it is not an option.

The plan's fallback as written ("`p11-kit server` hosting the module") does not
work on musl either: p11-kit's server is a musl process that dlopens the
module. It works only when the server is a glibc process. #709 packages that
host as a glibc root filesystem beside the musl userland (§9.6). charon's side
is `pkcs11 { modules { xkms { path = /usr/lib/pkcs11/p11-kit-client.so } } }`,
plus `P11_KIT_SERVER_ADDRESS` in `/etc/conf.d/charon`.

Three defects stood between that path and a working IKE_AUTH:

1. **p11-kit RPC versions must match (≥ 0.26 on both ends).** Alpine 3.22's
   client is 0.26.2. Against a 0.24.1 (Debian bookworm) or 0.25.5 (trixie)
   server it does not fail; it silently corrupts byte-array attributes:
   `CKA_ID 01` arrives as `01000000`, labels disappear and key usage becomes
   `none`. 0.26.2 (Ubuntu 26.04) and 0.26.5 (sid) servers are correct. The
   module host is Ubuntu 26.04 for this reason, and §9.6 enforces the pin.
2. **go-xkms: offline mode could not be initialized again after
   `C_Finalize`.** p11-kit's server initializes, finalizes and initializes
   every provider, so the second `C_Initialize` returned
   `CKR_DEVICE_ERROR`. Fixed in go-xkms#1387.
3. **go-xkms: raw `CKM_ECDSA` failed on every Go 1.27 build.** Go 1.27's
   `ecdsa.PrivateKey.Sign` refuses `crypto.Hash(0)`. strongSwan's pkcs11
   plugin hashes locally and always signs with raw `CKM_ECDSA`, so charon's
   IKE_AUTH failed with `C_Sign() failed: FUNCTION_FAILED`. Fixed in go-xkms
   v0.48.0-alpha: #1387 fixed the module's offline path, and #1388 has the
   service infer the hash of a raw digest from its length.

The suite builds the module from `IPSEC_XKMS_VERSION`, go-xkms
**v0.48.0-alpha**, the first release with both fixes. In that release the raw
`NONE` ECDSA path infers the digest's hash from its length (go-xkms#1388):
28, 32, 48 or 64 bytes, which covers strongSwan's SHA-2 digests. The go-xkms
that go.mod resolves (v0.17.0-alpha) predates both fixes, and the platform
catches up when go-quicbaas adopts that release.

**Also observed:** `pkcs11-tool --keypairgen` leaves the token's private key
`extractable`. A sign-only IKE key should be created non-extractable by the
xkms KMS API that sets its label and CKA_ID (plan §5.2, PR 0).

**TPM2 vs software.** The spike's token is the module's offline (embedded)
mode: a software key store, sealed under the user PIN (`passphrase`). Offline
mode has no TPM2 backend. A TPM2-held IKE key comes with the node-local xkms
server (plan §5.2), which this spike does not have yet.

### 9.3 The ipsec integration suite

`make integration-test-ipsec` (devcontainer, `test/integration/ipsec/`) builds
the apks (charon and the module host, §9.6) and two Alpine root filesystems with
the apks installed through apk (with their signatures checked). Each peer runs in
its own network namespace with charon and the module host started by the
packaged OpenRC services, and has its own token:

1. The P-256 IKE key is generated **on the token** through
   `p11-kit-client.so`, the same path charon uses.
2. The public key is certified by a test CA, with the fabric address as the
   only SAN and EKU `id-kp-ipsecIKE`.
3. charon loads the private key from the token (`load-token`).

| Test | Proves |
|---|---|
| `TestESPTransportThroughPKCS11Module` | <ul><li>both peers sign IKE_AUTH with the token key (`ECDSA_WITH_SHA*_DER`) and verify each other</li><li>the IKE SA uses the ML-KEM-768 hybrid</li><li>`ip xfrm state` holds one inbound and one outbound transport-mode `rfc4106(gcm(aes))` SA with a 16-byte ICV, ESN and `replay_window 1024`</li><li>the SPIs agree crosswise and a ping is carried by the SAs (packet counters)</li><li>the policies require ESP</li><li>charon runs as `strongswan` with `CAP_NET_ADMIN` only, and the VICI socket is mode 0600 owned by the platform user; the p11-kit socket is mode 0660, group `strongswan`</li></ul> |
| `TestUntrustedPeerIsRefused` | a peer certified by another CA is refused (`AUTHENTICATION_FAILED`) and no SA reaches the kernel |
| `TestFloorLeavesNoCleartextPath` | with no charon running, VXLAN and BGP do not cross the [fail-closed floor](overlay/architecture.md#fail-closed-floor) in any direction: to and from the node, and routed through it into and out of the fabric. ESP routed through the node, into and out of the fabric, does not cross it either, so the two forward layers agree. The nftables filter alone, the XFRM block policies alone (whose forward block covers only what is routed out through the fabric interface) and both together are each checked against a positive control on the same flows |
| `TestEvictedPeerIsDroppedBeforeESP` | an evicted peer's ESP (in and out) and IKE stop at the filter, although both are accepted before the eviction and again once it is lifted |
| `TestIKELimiterHoldsWithAFullMeter` | with the IKE meter full (65535 sources), IKE from one more source is dropped while a source already in the meter is still admitted |
| `TestSuiteInARM64VM` | the first two tests above, cross-compiled for arm64, pass inside an aarch64 VM (`qemu-system-aarch64`, TCG, Alpine `linux-virt` 6.12): arm64 charon, arm64 p11-kit-client, arm64 module host, real aarch64 XFRM |

**Why a VM for arm64.** qemu-user cannot stand in for it, and a qemu upgrade
does not change that:

- qemu's linux-user mode refuses `NETLINK_XFRM` sockets with
  `EPROTONOSUPPORT`, measured on 7.2 and on 10.2.3.
- It also answers route-rule writes on `NETLINK_ROUTE` with `Not supported`.
- charon's `kernel-ipsec` feature is a critical dependency of libcharon, so an
  arm64 charon under binfmt aborts at start-up (`initialization failed -
  aborting charon`). It does get as far as loading `p11-kit-client.so` and
  listing the go-xkms token's mechanisms over the RPC.

So the suite cross-compiles itself for arm64 and runs inside a VM:

- **Kernel.** Alpine's `vmlinuz-virt` is an EFI zboot image, which qemu
  7.2's `-kernel` cannot load. The VM's Dockerfile extracts the raw `Image`
  from the zboot header.
- **Inputs.** The tarballs reach the VM as read-only virtio disks and the
  test binary over 9p.
- **CPU model.** `cortex-a72`, because `-cpu max` emulates pointer
  authentication slowly enough to make unpacking the module host take
  110 s instead of 9 s.

The suite container runs with `--init`. supervise-daemon's `--stop` waits for
the supervisor's PID to disappear, and with `go test` as PID 1 the exited
supervisor stays a zombie, so `rc-service charon stop` never returns.

### 9.4 GoBGP: RT-Constrain and prefix-restricted dynamic neighbours

**Result:** both are supported by `github.com/osrg/gobgp/v4` v4.9.0 for
l2vpn-evpn, as the real-GoBGP tests in `pkg/sdn/bgp/rtc_dynamic_gobgp_test.go`
demonstrate.

- **RT-Constrain (RFC 4684) filters EVPN routes per peer.**
  - Once a peer has negotiated RTC, every non-RTC path to it is dropped unless
    one of its route targets matches that peer's membership
    (`pkg/server/server.go:487-500`, `peer.go:538-550`).
  - EVPN is in the route-target index (`isVPNFamily`,
    `internal/pkg/table/table.go:262-272`). A new membership re-advertises
    the matching EVPN routes (`server.go:1351-1430`).
  - Membership is reflected to route-reflector clients (`peer.go:577`).
  - A VTEP originates its membership in the global RIB with `AddPath` of
    `NewRouteTargetMembershipNLRI`, with no GoBGP VRFs, which fits the plan's
    model.
  - `TestRealGoBGP_RTConstrainFiltersEVPN`: a reflector with clients A, B
    and C. B, which joined only RT 100, never receives A's RT 200 route,
    while C, which joined RT 200, does. B receives it once it joins.
- **Dynamic neighbours.**
  - An incoming session with no configured neighbour is matched to the
    longest dynamic-neighbour prefix (`server.go:445-465`). It is built from
    the peer group's configuration, including families, RR client, policy
    and BFD (`peer.go:67-97`, `server.go:347-380`).
  - Anything else is accepted and then closed before a byte is sent.
  - `TestRealGoBGP_DynamicNeighborsAdmitOnlyTheFabric`: a VTEP inside
    `127.0.0.0/29` establishes EVPN with a reflector that has no configured
    neighbours, and an address outside the prefix gets EOF with zero bytes.
- **Gaps** to design around:
  - `ListPeer` reports a dynamic peer's address only in
    `State.NeighborAddress` (`Conf` stays zero, `peer.go:68-80`).
  - Dynamic prefixes are ordered by comparing masks as strings, so keep one
    fabric prefix per family.
  - A refused speaker produces no FSM event.
  - Admission is by source address alone. The plan's per-neighbour checks
    (certificate SAN equals session address, allowed RTs and VNIs) are the
    platform's to add.
  - **One speaker per process, or start them all before any peers.** GoBGP
    keeps its route-selection options in package variables
    (`table.SelectionOptions`, `table.UseMultiplePaths`). `StartBgp` writes
    them (`server.go:2697-2698`) and every server's FSM reads them
    (`table_manager.go:379`). A second `BgpServer` started in the same
    process while the first has a session up is a data race, and CI's race
    job caught it in this spike's test. Its options would also silently
    replace the first's. A node that runs an RR and a VTEP speaker in one
    platformd must therefore give both the same options and start both
    before either peers.

### 9.5 Kernel configuration

**The check.** `build/docker/kernel-config/platform-required.config` holds the
plan's list:

- **datapath:** `OPENVSWITCH`, `OPENVSWITCH_VXLAN`, `VXLAN`
- **IPsec:** `INET_ESP`, `INET6_ESP`, `XFRM_USER`, `CRYPTO_GCM`
- **conntrack and NAT:** `NF_CONNTRACK`, `NF_CONNTRACK_ZONES`, `NF_NAT`,
  `NF_NAT_OVS`, `NF_CT_PROTO_SCTP`
- **VRF:** `NET_VRF`
- **vsock:** `VSOCKETS`, `VIRTIO_VSOCKETS`, `VHOST_VSOCK`
- **hardening:** `MODULE_SIG_FORCE`, `SECURITY_LOCKDOWN_LSM`, `IMA_APPRAISE`,
  `SCHED_CORE`, `CRYPTO_FIPS` and the DRBGs

It also lists the dependencies those options need to survive `olddefconfig`.

`require-config.sh` beside it is the one check both kernel builders run. The
fips kernel (x86_64) and the virt kernel (arm64) bake it in through a BuildKit
named context, so `pkg/iso` and `pkg/diskimage/virtkernel` invocations get it
too. A dropped option fails the build with exit 3, and
`pkg/diskimage/virtkernel/requireconfig_test.go` tests the check.
`make -C build/docker/<builder> config-check` runs the configuration step
alone. It passes on both kernels. Its first run caught `NET_VRF` being dropped
by both defconfigs: it needs `IP_ADVANCED_ROUTER`, `IP_MULTIPLE_TABLES`,
`IPV6_MULTIPLE_TABLES` and `NET_L3_MASTER_DEV`.

**Kconfig findings:**

- SCTP NAT has no symbol of its own. `nf_nat_proto.c` rewrites SCTP under
  `CONFIG_NF_CT_PROTO_SCTP`.
- `NF_NAT_OVS` is selected by `OPENVSWITCH` when `NF_NAT` is on.
- `IMA_APPRAISE` needs `IMA`, `INTEGRITY` and `SECURITY`.
- `SCHED_CORE` needs `SCHED_SMT`.
- `CRYPTO_FIPS` needs `CRYPTO_MANAGER_DISABLE_TESTS` unset (it defaults to
  y in 6.12) and `MODULE_SIG`.
- Built in is not switched on: IMA appraisal needs a policy, lockdown a
  mode, FIPS `fips=1`.

**Alpine's kernels** (`make kernel-config-check-alpine`, y or m accepted):

| Kernel | Missing |
|---|---|
| `linux-lts` 6.12.111, x86_64 and aarch64 | `MODULE_SIG_FORCE`, `INTEGRITY`, `IMA`, `IMA_APPRAISE`, `CRYPTO_DRBG_HASH`, `CRYPTO_DRBG_CTR`, `CRYPTO_FIPS`, and `CRYPTO_MANAGER_DISABLE_TESTS` is set |
| `linux-rpi` 6.12.85, aarch64 | the same, except `INTEGRITY` is present; also `VIRTIO_VSOCKETS`, `MODULE_SIG`, `SECURITY_LOCKDOWN_LSM`, `SCHED_SMT`, `SCHED_CORE` |

Every datapath, IPsec, conntrack/NAT, VRF and vsock option is in both
`linux-lts` builds, so the overlay itself runs on Alpine's kernels; what they
lack is the hardening.

- FIPS nodes already boot the fips kernel.
- On `linux-lts`, `module.sig_enforce=1` stands in for `MODULE_SIG_FORCE`,
  but there is no IMA.
- `linux-rpi` has no module signing, lockdown or core scheduling. A Pi that
  needs them needs a platform-built kernel, as the virt kernel already is
  for the QEMU stand-in.

### 9.6 Packaging on a node (#709)

Two apks and their OpenRC subpackages, built by one `abuild` run in
`build/docker/strongswan-builder` into one signed repository per architecture:

| Package | Carries |
|---|---|
| `trusted-platform-strongswan` | charon, swanctl, `strongswan.d/trusted-platform.conf` and `strongswan.d/charon/pkcs11.conf`; depends on `p11-kit-server>=0.26` for `p11-kit-client.so` |
| `trusted-platform-strongswan-openrc` | the `charon` service and `/etc/conf.d/charon` |
| `trusted-platform-p11-host` | the glibc module-host root filesystem as one archive (`/usr/share/xkms-p11-host/rootfs.tar`, with its sha256) and `p11-kit-pin-check`; creates the `xkms-p11` user the server runs as; depends on `p11-kit-server>=0.26` |
| `trusted-platform-p11-host-openrc` | the `xkms-p11-kit` service and `/etc/conf.d/xkms-p11-kit` |

**Settings** (`/etc/strongswan.d/trusted-platform.conf`):

- `make_before_break = yes`, so a rekey installs the new SA before the old one
  goes;
- `cookie_threshold` and `init_limit_half_open`, the half-open IKE_SA limits
  that bound a flood of IKE_SA_INITs;
- the plugin set of §9.1 and nothing else (`load` is templated from the
  builder Makefile's `STRONGSWAN_PLUGINS`, the same list the package step
  checks);
- the VICI socket at the fixed path `/run/charon.vici`, which `swanctl` reads
  as well.

**`charon` service.** `need`s `net` and `xkms-p11-kit`, so charon never starts
without its key store. charon drops to `strongswan` and runs under
`socket-takeover` (below), which gives the vici plugin's socket to the account
platformd runs as (`CHARON_VICI_USER`/`CHARON_VICI_GROUP`, default `root:root`:
the installer runs platformd as root) at mode 0600 once charon has handed it to
`strongswan`. The VICI dialer refuses a socket its own uid does not own, so
the two accounts change together. A respawned charon recreates the
socket and the takeover runs again with it, so the window is that of one start,
not one health-check interval. The service refuses to start when that user or
group does not exist, and its start waits for the first takeover (owner and
mode 0600 both, since charon creates the socket as root first). The installer
adds `xkms-p11-kit` and `charon` to the default runlevel whenever their
`-openrc` packages are installed, and both generated platformd scripts start
`after charon`, so platformd finds the socket served at boot.

**`xkms-p11-kit` service.** Unpacks the root filesystem under
`/var/lib/xkms-p11-host` (again whenever the apk brings a different archive),
bind-mounts `/proc`, `/dev`, `/run/p11-kit` and the node's `/var/lib/xkms`
into it and runs `p11-kit server` in a chroot, which hosts
`libxkms_pkcs11.so` on `/run/p11-kit/xkms.sock`. The server runs under
`socket-takeover` too, which sets the socket to mode 0660, owner `xkms-p11`,
group `strongswan` (`XKMS_P11_SOCKET_GROUP`), after every (re)start.

The server runs as `xkms-p11`, the apk's own system user, which owns
`/var/lib/xkms` (0700) and `/run/p11-kit` and nothing else. The service keeps
root for the mounts, the chroot and the handover, and the server drops to the
user inside the chroot with `setpriv` (no new privileges, no supplementary
groups). `command_user` cannot do this: it drops before `chroot` runs.

The server exports one token, `pkcs11:token=trusted-platform-ipsec`, not every
token the module has. A token's label is blank until it is initialized, so an
uninitialized token is invisible through the socket, and nothing in charon's
group can initialize it and become its SO. An operator labels it, as root,
with the service stopped:

```sh
install -m 0600 /dev/stdin /run/xkms-p11-kit.so-pin   # the SO PIN, root's
rc-service xkms-p11-kit init_token
```

`init_token` refuses a PIN file that is not root's with mode 0600. It loads the
module directly in the chroot as `xkms-p11`, labels the token, and removes the
file once that succeeds. The user PIN and the IKE key are then set through the
socket.

**`socket-takeover`.** Both services run their daemon through this wrapper,
which supervise-daemon starts again on each respawn. It removes a stale socket,
starts a detached watcher and `exec`s the daemon, so supervise-daemon signals
and reaps the daemon itself. The watcher waits until the socket exists and is
owned by the daemon's own user, then sets the mode and hands it over, mode
first. The wait is bounded (`CHARON_TAKEOVER_TRIES`, 10 s;
`XKMS_P11_TAKEOVER_TRIES`, 30 s, for the slow first module load): a daemon that
never serves the socket, or whose socket cannot be handed over, is stopped so
supervise-daemon restarts it.

**The version pin.** A 0.26 client against an older server corrupts CKA_ID
(§9.2), so the 0.26 minimum is enforced four times, and none can be configured
away: the `p11-kit-server>=0.26` dependency of both apks, the module-host
Dockerfile (`dpkg --compare-versions ... ge 0.26`), the module-host `APKBUILD`
(`p11-kit-pin-check` on the version recorded in the archive) and the service
start (the same check on the unpacked root filesystem).

**The module host archive** comes from `make ipsec-module-host`
(`build/docker/strongswan-builder/modulehost/Dockerfile`, the module built
against glibc). `make strongswan-build` takes it, and `XKMS_VERSION` (the
go-xkms release, which becomes the apk's version), as inputs.

**Media.** `pkg/iso` `PlatformPackages()` names the four built apks and
`p11-kit-server` from the Alpine mirror. `--platform-apk-dir` on
`platformctl iso create` and `platformctl diskimage create` points at the
builder's output; the install media, the factory image and the netboot sets all
get them through the one `StageInstallMedia` hook, into the offline
`apks-prefetch` repository. Without the flag the media carry none of them.
`pkg/iso` fails the build when the directory lacks an apk, the index does not
list it, or an apk is unreadable. The builder containers run without host bind
mounts (`pkg/diskimage/runner`, `build/docker/run-builder.sh`), so the
directory is copied in, not mounted. `TestPlatformPackages_MatchTheBuilder` and
`pkg/arch/ipsec_packaging_test.go` fail when the apk names, socket paths,
plugin placeholders or the pin differ between the builder, the services, the
media and the suite.

## 10. Related

- [architecture.md](architecture.md) · [api.md](api.md) · [cli.md](cli.md) · [user.md](user.md)
- [`docs/gateway/`](../gateway/) — gatewayd, BGP, IPAM at the edge, reverse proxy
- [`docs/switch/`](../switch/) — physical switch detail
- Deep dives carried over and not re-verified in this pass: [802.1x.md](802.1x.md),
  [configuration.md](configuration.md), [provisioning.md](provisioning.md),
  [testing.md](testing.md), and the `bgp/`, `dhcp/`, `fabric/`, `firewall/`,
  `ipam/`, `overlay/`, `performance/`, `tunnel/` subdirectories
