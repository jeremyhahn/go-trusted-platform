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
| `pkg/sdn/arp`, `pkg/sdn/ct` | ARP handling, connection tracking |
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
   reachability — the failure mode segmentation exists to prevent.
5. **`FlushFlows` is destructive and unconditional.** It has an RPC and a CLI
   verb; there is no per-flow filter on it.

## 5. Error semantics and fail-closed paths

Every configuration error in §3 is raised at load and prevents the SDN
subsystem starting. That is the intended behaviour: a partially valid network
policy is worse than none, because it looks like it is working.

At runtime, the fail-closed paths are: an unauthenticated port stays in
`unauthorized` (no default-allow), an unknown zone is refused rather than
mapped to a default, and a failed IDevID validation moves the port toward
`unauthorized`/`blocked` rather than leaving it where it was.

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

## 9. Related

- [architecture.md](architecture.md) · [api.md](api.md) · [cli.md](cli.md) · [user.md](user.md)
- [`docs/gateway/`](../gateway/) — gatewayd, BGP, IPAM at the edge, reverse proxy
- [`docs/switch/`](../switch/) — physical switch detail
- Deep dives carried over and not re-verified in this pass: [802.1x.md](802.1x.md),
  [configuration.md](configuration.md), [provisioning.md](provisioning.md),
  [testing.md](testing.md), and the `bgp/`, `dhcp/`, `fabric/`, `firewall/`,
  `ipam/`, `overlay/`, `performance/`, `tunnel/` subdirectories
