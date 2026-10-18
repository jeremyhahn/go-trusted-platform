# SDN Architecture

> **Status: NORMATIVE** · Scope: `pkg/sdn/` (excluding `pkg/sdn/gateway/`), `pkg/switch/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: architecture (this file) · [engineering.md](engineering.md) ·
> [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> **Verification scope.** Package boundaries, the port state machine,
> configuration errors, CLI verbs and the transport matrix were re-checked
> against code on 2026-08-18. The diagrams and narrative below predate the
> feature-folder migration and were carried over rather than re-derived.

## The problem

A trusted-computing platform cannot inherit its network's trust model from the
network. A switch port that forwards because a cable is plugged into it makes
every other control — attestation, tenancy, workload admission — conditional on
physical access nobody is checking.

## The shape chosen

**The port is the enforcement point, and a device certificate is what opens
it.** A device presents an IDevID; the control plane validates it, decides the
device's zone, and programs OpenFlow rules that match that decision. Until then
the port is on a provisioning-only path or in quarantine.

Segmentation is layered: **zones** (the trust boundary), **VLANs** (the L2
boundary within a host), and **VXLAN/EVPN** (the L2 boundary across hosts).
Zones are the unit everything else is checked against, which is why five of the
twenty-two configuration errors are about the zone graph.

### Alternatives rejected

| Alternative | Why it was rejected |
|---|---|
| **802.1X with EAP and a RADIUS server** | It adds a second identity system, a second credential store and a second failure domain alongside the platform's own device identity. The platform already issues IDevIDs and already knows which device is which; making the network ask a RADIUS server the same question is duplication with a new outage mode. The state machine here validates certificates directly. |
| **Shelling out to `ovs-vsctl` / `ovs-ofctl`** | External command dependencies mean parsing human-oriented output, no typed errors, and a binary that must be present and version-matched on every node. The OVSDB and OpenFlow clients are implemented in Go. |
| **Trusting a VLAN tag as the trust boundary** | A VLAN tag is asserted by whatever is on the wire. A zone carried in an IDevID certificate (`encode_zone_in_cert`) is attested. VLANs remain the *mechanism*; zones are the *decision*. |
| **Letting an unauthenticated port default to a guest VLAN with internet access** | That converts an authentication failure into working connectivity, which is how default-allow gets shipped. An unauthenticated port reaches enrollment and nothing else. |
| **A `blocked` state that ages out** | Auto-recovery from a policy violation means the violation is not enforced, only delayed. `blocked` is a source state for no transition; clearing it is an administrative act. |
| **Validating network configuration lazily** | An inconsistent zone/pool/VLAN graph produces silent cross-zone reachability — traffic going where it should not, with nothing logged. Validation is eager and the subsystem refuses to start. |

## Component boundaries

| Piece | Package | Owner |
|---|---|---|
| OVS / OVSDB client, OpenFlow | `pkg/sdn/ovs`, `pkg/sdn/openflow` | this repo |
| Port authentication state machine, quarantine, zone flows | `pkg/sdn/policy` | this repo |
| IPAM, DHCP | `pkg/sdn/ipam`, `pkg/sdn/dhcp` | this repo |
| Network plan (all numbering), VXLAN, tunnels, overlay | `pkg/sdn/netplan`, `vxlan`, `tunnel`, `overlay` | this repo |
| BGP speaker | `pkg/sdn/bgp` | this repo |
| Fabric, zones, cluster state | `pkg/sdn/fabric`, `zone`, `cluster` | this repo |
| Host networking (TAP, links, routes) | `pkg/sdn/netlink` | this repo |
| Physical switches | `pkg/switch` | this repo |
| **Edge gateway and reverse proxy** | `pkg/sdn/gateway`, `pkg/proxy` — [`docs/gateway/`](../gateway/) | this repo, separate feature |
| **Device certificates (IDevID) and the CA** | consumed through the quicbaas SDK | **not this repo** |
| **Device identity records and enrollment** | `pkg/device` — [`docs/device/`](../device/) | this repo |
| **Workload admission policy (OPA)** | `pkg/policy/opa` | this repo |

The §R capability row is *"SDN — bridges, ports, flows, IDevID port
authentication, VXLAN/EVPN overlay, IPAM, physical switch management"*, Tier 1,
reached through `services/sdn`, `services/overlay` and `services/switch` in the
platform SDK.

**Port authentication is a distinct engine from platform OPA.** `pkg/sdn/policy`
is the port state machine; `pkg/policy/opa` decides container admission. They
answer different questions and neither is a token-authorization decision point.

**The API does not reach the engine yet, so it refuses port authentication.**
The daemon builds the engine for quarantine and enrollment only (`initSDNPolicy`,
`pkg/daemon/commands/quarantine_init.go`), and it has no certificate validator
that checks the chain to the platform anchor and that the certificate is an
IDevID. Until both exist, `SDNService.AuthenticatePort` and `RevokePortAuth`
refuse on every transport with `policy.ErrPortAuthNotEnforced`
(`FailedPrecondition`) and keep no state ([api.md](api.md) §4, #304).

## Data flow — a device joining the network

1. Link comes up. Port state is `unconnected`.
2. The port moves to `provisioning`: flows permit only enrollment traffic.
3. The device enrolls and obtains an IDevID. Port state becomes `enrolled`.
4. The device activates; its certificate is validated. Port state moves through
   `authenticating` to `authorized`.
5. The zone is decided — from the certificate when `encode_zone_in_cert` is on,
   from configuration otherwise — and `zone_flow_manager` programs the flows
   that put the port in that zone's VLAN.
6. If any check fails, the port goes to `quarantined` (isolated VLAN,
   remediable) or `blocked` (administrative).

Steps 5 and 6 happen in the datapath. A quarantine that only set a database
field would not be a quarantine.

This flow describes a device attached through the OVS fabric. A device that
enrolls over the management LAN — a worker joining the control plane before
any fabric attach — has no port when enrollment completes: the certificate is
issued on the strength of the validated attestation, and the port state
machine engages when the device later attaches and the fabric learns its
port. The port is the enforcement point; with no port in the fabric there is
nothing to open, and refusing the certificate would enforce nothing.

## Trust boundaries

1. **Device → port.** Crossed by the IDevID certificate. Everything on the
   device side is untrusted until it validates.
2. **Certificate → zone.** With `encode_zone_in_cert`, the zone is inside the
   attested certificate. Without it, the zone comes from configuration keyed on
   something the device asserts — a weaker binding, and a deliberate choice
   somebody made.
3. **Host → host.** Crossed by VXLAN tunnels. The overlay transport network is
   its own segment; a compromised overlay endpoint reaches other endpoints.
4. **Control plane → physical switch.** Crossed by SSH. The switch's own
   credentials are outside the platform's trust chain.
5. **platformd's admission flows → gatewayd's pipeline.** On a bridge the two
   daemons share, platformd's per-port allow rules end in a *terminal*
   (`zoneflows.Terminal`): `normal` on a bridge platformd has to itself, and
   `goto_table:10` (`TerminalGatewayPipeline`) on one whose base pipeline
   gatewayd owns, so admission composes with the gateway's inter-zone
   verdicts instead of bypassing them. The owner is read from the bridge's
   `external_ids` (`zoneflows.TerminalForBridge`; gatewayd writes it from
   `GatewayRuntime.EnsurePipeline`, #567). The hand-off is dormant today —
   platformd logs the owner and keeps `normal` — until the owner-change
   reconcile exists (#557); see
   [`docs/gateway/architecture.md`](../gateway/architecture.md).

## What this feature deliberately does not do

- **It does not speak EAP or RADIUS.** Certificate validation is direct.
- **It does not issue certificates.** The CA is reached through the stack.
- **It does not run the edge gateway.** BGP announcement, NAT, DHCP relay at the
  edge, PXE and the reverse proxy are [`docs/gateway/`](../gateway/), even
  though `sdn gateway` is where the CLI puts them.
- **It does not manage physical switches beyond VLAN assignment and port
  enable/disable.** Five operations, and that is the whole intended surface.
- **It does not make workload admission decisions.** That is platform OPA.
- **It does not defend an address it already holds.** The duplicate-address
  guard runs once, before assignment, and refuses a contested address. It is
  not a continuous RFC 5227 conflict-resolution loop. The one address a node
  *does* share with a peer on purpose is a first-hop redundancy address: the
  gateway's VRRPv3 speaker (`pkg/sdn/fhrp`, RFC 5798; epic #553 ruling R7,
  recorded for the handbook in jeremyhahn/handbook#39) holds the segment's
  virtual address on whichever gateway is master, and the guard is told about
  it (`arp.WithSharedAddress`) so a defence from the group's virtual MAC is
  the group answering, not a conflict. Any other MAC on that address is still
  refused. The earlier rule here — "no first-party VRRP/HSRP speaker, ever" —
  was written before the gateway pair replaced the site's routers and is
  superseded by that ruling.

## Overview

The SDN subsystem provides certificate-based network access control with
OpenFlow for dynamic policy enforcement. All components are implemented in pure
Go without external command dependencies.

> **Corrected 2026-08-18.** This paragraph previously described the subsystem as
> "using 802.1X principles". It is IDevID-certificate port authentication: there
> is no EAP exchange and no RADIUS server anywhere in `pkg/sdn/policy`. The
> phrase led readers to look for an authenticator they would not find.

## Component Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                             Policy Engine                                │
│  (pkg/sdn/policy)                                                        │
│  ┌─────────────────────┐  ┌─────────────────────┐  ┌──────────────────┐  │
│  │ Port State Machine  │  │ Certificate Policy  │  │ Flow Rule        │  │
│  │ - State transitions │  │ - X.509 extraction  │  │ - ACL generation │  │
│  │ - Event handling    │  │ - Tenant ID         │  │ - VLAN rules     │  │
│  └─────────────────────┘  │ - VLAN assignment   │  │ - DROP rules     │  │
│                           └─────────────────────┘  └──────────────────┘  │
└───────────────┬────────────────────────────┬─────────────────────────────┘
                │                            │
    ┌───────────▼───────────┐      ┌─────────▼─────────┐
    │      OVS Client       │      │    ARP Reader     │
    │   (pkg/sdn/ovs)       │      │  (pkg/sdn/arp)    │
    │                       │      │                   │
    │  ┌─────────────────┐  │      │  Parse entries:   │
    │  │ OVSDB JSON-RPC  │  │      │  203.0.113.1      │
    │  │ - transact      │  │      │  0x1 0x2          │
    │  │ - list_dbs      │  │      │  aa:bb:cc:dd:ee:ff│
    │  │ - get_schema    │  │      │  * eth0           │
    │  └─────────────────┘  │      └───────────────────┘
    │                       │
    │  ┌─────────────────┐  │
    │  │ Bridge Mgmt     │  │
    │  │ - Create/Delete │  │
    │  │ - List          │  │
    │  └─────────────────┘  │
    │                       │
    │  ┌─────────────────┐  │
    │  │ Port Mgmt       │  │
    │  │ - Add/Remove    │  │
    │  │ - VLAN config   │  │
    │  │ - State (up/dn) │  │
    │  └─────────────────┘  │
    └───────────┬───────────┘
                │
    ┌───────────▼───────────┐
    │    OpenFlow Client    │
    │  (pkg/sdn/openflow)   │
    │                       │
    │  ┌─────────────────┐  │
    │  │ OF 1.3 Binary   │  │
    │  │ - Hello         │  │
    │  │ - Features      │  │
    │  │ - FlowMod       │  │
    │  │ - Barrier       │  │
    │  └─────────────────┘  │
    │                       │
    │  ┌─────────────────┐  │
    │  │ Match Fields    │  │
    │  │ - in_port       │  │
    │  │ - eth_dst/src   │  │
    │  │ - ip_dst/src    │  │
    │  │ - tcp/udp_dst   │  │
    │  └─────────────────┘  │
    │                       │
    │  ┌─────────────────┐  │
    │  │ Actions         │  │
    │  │ - output        │  │
    │  │ - set_vlan      │  │
    │  │ - pop_vlan      │  │
    │  │ - drop          │  │
    │  └─────────────────┘  │
    └───────────────────────┘
```

## Package Details

### pkg/sdn/arp

Pure Go ARP: a table reader, and the duplicate-address detector that guards
bridge addressing. Neither shells out — no `arping`, no `ip`.

The table reader parses `/proc/net/arp` directly without external commands.

```go
// Entry represents an ARP table entry
// Parse format: 203.0.113.1 0x1 0x2 aa:bb:cc:dd:ee:ff * eth0
type Entry struct {
    IP        string
    HWType    int
    Flags     int
    HWAddress string
    Mask      string
    Device    string
}
```

Key features:
- Reads real-time ARP cache from kernel
- Filters incomplete entries (00:00:00:00:00:00)
- Thread-safe lookups
- No external dependencies

`DuplicateAddressDetector` is the RFC 5227 probe platformd runs before it
assigns an address to an OVS bridge. It opens a raw `AF_PACKET` socket bound
to the bridge and filtered to the ARP EtherType, sends three probes whose
sender protocol address is `0.0.0.0`, and listens a second after each. A reply
or request carrying the probed address from a foreign MAC is a
`ConflictError` naming both hardware addresses.

```go
// ProbeTransport opens probe sessions; the production transport is the raw
// AF_PACKET socket, and tests substitute a fake so no test touches a segment.
type ProbeTransport interface {
    Open(iface string) (ProbeSession, error)
}
```

The interval is fixed rather than randomised as the RFC suggests: platformd
probes a few statically configured addresses once per boot, not a fleet of
clients booting together, so the probe storm the randomisation defends against
cannot arise. See [engineering.md](engineering.md) §5 for what the platform
does with the verdict.

### pkg/sdn/openflow

Native OpenFlow 1.3 protocol implementation over Unix socket.

**Supported Messages:**
- Hello / FeaturesRequest / FeaturesReply
- FlowMod (add/modify/delete)
- MultipartRequest/Reply (flow stats)
- BarrierRequest/Reply
- EchoRequest/Reply

**Match Fields:**
- in_port, eth_dst, eth_src, eth_type
- ip_dst, ip_src, ip_proto
- tcp_dst, udp_dst, vlan_vid

**Actions:**
- output, set_vlan, pop_vlan, drop, goto_table

```go
// Binary message format (big-endian)
type Header struct {
    Version uint8  // 0x04 for OF 1.3
    Type    uint8  // Message type
    Length  uint16 // Total length
    Xid     uint32 // Transaction ID
}
```

### pkg/sdn/ovs

OVSDB client implementing RFC 7047 JSON-RPC 2.0 protocol.

**Operations:**
- Transact (insert, update, delete, mutate, select)
- List databases
- Get schema
- Echo

**Managed Tables:**
- Bridge
- Port
- Interface
- Open_vSwitch

```go
// OVSDB transaction operation
type Operation struct {
    Op      string                 `json:"op"`
    Table   string                 `json:"table"`
    Where   []Condition            `json:"where,omitempty"`
    Row     map[string]interface{} `json:"row,omitempty"`
    Columns []string               `json:"columns,omitempty"`
}
```

### pkg/sdn/netlink

TAP device management using netlink protocol.

- Create/delete TAP devices
- Set link state (up/down)
- Set device owner (UID/GID)
- MTU configuration

### pkg/sdn/policy

802.1X-style port authentication with certificate-based policies.

**Port State Machine:**

```
┌────────────────────────┐
│      Unconnected       │  Port not detected
└───────────┬────────────┘
            │ device connects
┌───────────▼────────────┐
│      Provisioning      │  VLAN 998 - Limited access
│                        │  (DHCP, DNS, HTTPS to platform)
└───────────┬────────────┘
            │ enrollment complete
┌───────────▼────────────┐
│        Enrolled        │  Still VLAN 998 - Awaiting activation
└───────────┬────────────┘
            │ client activates
┌───────────▼────────────┐
│       Authorized       │  Production VLAN - Full access per ACLs
└───────────┬────────────┘
            │ cert expired/compliance
┌───────────▼────────────┐
│      Quarantined       │  VLAN 666 - Isolated for remediation
└───────────┬────────────┘
            │ cert revoked
┌───────────▼────────────┐
│        Blocked         │  DROP all traffic
└────────────────────────┘
```

**Certificate Policy Extraction:**

Policies encoded in IDevID certificate extensions:
- Tenant ID (from Subject.Organization)
- VLAN assignment (custom OID or profile lookup)
- ACL rules (from profile)
- Rate limits (future)

## OVS/OVSDB Integration

```
┌───────────────────┐            ┌─────────────────────┐
│     Platform      │            │    ovsdb-server     │
│   (SDN Client)    │            │                     │
│                   │   Unix     │   ┌─────────────┐   │
│  ┌─────────────┐  │  Socket    │   │ Open_vSwitch│   │
│  │ OVS Client  │──────┬───────────>│ Bridge      │   │
│  └─────────────┘  │   │        │   │ Port        │   │
│                   │   │        │   │ Interface   │   │
└───────────────────┘   │        └───┴─────────────┴───┘
                        │                  │
                        │        ┌─────────▼─────────┐
                        │        │   ovs-vswitchd    │
                        │        │                   │
                        └───────>│  ┌─────────────┐  │
                          Mgmt   │  │  OpenFlow   │  │
                         Socket  │  │  Datapath   │  │
                                 │  └─────────────┘  │
                                 └───────────────────┘
```

### Connection Flow

```
Client                             ovsdb-server
   │                                     │
   │──── Connect (Unix socket) ─────────>│
   │                                     │
   │──── list_dbs ──────────────────────>│
   │<─── ["Open_vSwitch"] ───────────────│
   │                                     │
   │──── transact [ops...] ─────────────>│
   │<─── [{uuid, rows}, ...] ────────────│
```

## OpenFlow Integration

```
Client                             ovs-vswitchd
   │                                     │
   │──── Connect (br0.mgmt socket) ─────>│
   │                                     │
   │──── Hello (OF 1.3) ────────────────>│
   │<─── Hello (OF 1.3) ─────────────────│
   │                                     │
   │──── FeaturesRequest ───────────────>│
   │<─── FeaturesReply ──────────────────│
   │                                     │
   │──── FlowMod (add flow) ────────────>│
   │──── BarrierRequest ────────────────>│
   │<─── BarrierReply ───────────────────│
```

## TAP/Netlink Integration

```
┌───────────────────┐            ┌───────────────────┐
│     Platform      │            │   Linux Kernel    │
│  (Compute Orch.)  │            │                   │
│                   │  Netlink   │   ┌───────────┐   │
│  ┌─────────────┐  │  Socket    │   │  TAP/TUN  │   │
│  │ TAP Manager │──────┬───────────>│  Driver   │   │
│  └─────────────┘  │   │        │   └───────────┘   │
│                   │   │        │         │         │
└───────────────────┘   │        │   ┌─────▼─────┐   │
                        │        │   │ veth pair │   │
      VM (QEMU)         │        │   └───────────┘   │
   ┌─────────────┐      │        │         │         │
   │ virtio-net  │──────┴────────┼─────────┘         │
   └─────────────┘               │                   │
                                 └───────────────────┘
```

## Thread Safety

All clients use mutex protection for concurrent access:
- OVSDB client: Single connection, serialized requests
- OpenFlow client: Atomic transaction IDs, pending response map
- ARP reader: Lock-free reads from /proc filesystem
- Policy engine: RWMutex for state machine access

## Error Handling

All packages use typed errors:

```go
// pkg/sdn/ovs/errors.go
var (
    ErrNotConnected      = errors.New("not connected to OVSDB")
    ErrBridgeNotFound    = errors.New("bridge not found")
    ErrPortNotFound      = errors.New("port not found")
    ErrTransactionFailed = errors.New("OVSDB transaction failed")
    ErrInvalidSocket     = errors.New("invalid socket path")
    ErrConnectionFailed  = errors.New("connection failed")
    ErrConnectionClosed  = errors.New("connection closed")
)

// pkg/sdn/openflow/errors.go
var (
    ErrNotConnected     = errors.New("not connected")
    ErrVersionMismatch  = errors.New("OpenFlow version mismatch")
    ErrTimeout          = errors.New("operation timed out")
    ErrSocketNotFound   = errors.New("management socket not found")
)

// pkg/sdn/policy/errors.go
var (
    ErrInvalidPortID     = errors.New("invalid port ID")
    ErrInvalidPolicy     = errors.New("invalid policy")
    ErrInvalidState      = errors.New("invalid state transition")
    ErrInvalidVLAN       = errors.New("invalid VLAN ID")
    ErrPolicyNotFound    = errors.New("policy not found")
    ErrFlowInstallFailed = errors.New("flow installation failed")
    ErrFlowDeleteFailed  = errors.New("flow deletion failed")
)
```

## The network plan (`pkg/sdn/netplan`)

Every number the SDN uses is derived in one place. `netplan.New` takes the
environment (`sdn.environment`: number _E_, IPv4 base, ULA `/48`, explicit
overrides) and the resolved zone set, and returns an immutable `Plan`:

| The plan answers | From |
|------------------|------|
| A zone's VLAN, IPv4 and IPv6 subnets, gateway | `E·100+n`, `<base>.E.n.0/24`, `<ula>:<VLAN digits>::/64`, `.1` |
| The zone for a VLAN or an address | reverse lookups over the zones |
| The IPAM pools to seed | one per zone (DHCP range from `.50`) and one per IPAM range |
| The reserved, never-allocatable ranges | gateway HA sync `/31`, host services, every gateway address |
| A port class's VLANs | the zones that are members of the class |
| An overlay network's VNI | `E·100000+n` |

`sdn.Config.Validate` resolves the zones, validates them and builds the plan;
`Config.Plan()` hands it to the policy engine, the gateway runtime, the
overlay controller, IPAM seeding, the switch fabric and the installer. No
package keeps a VLAN constant, and a component that needs a VLAN without a
plan fails with a typed error rather than guessing.

The lifecycle flow templates per zone (provisioning, quarantine) are in
[configuration.md](configuration.md#per-zone-openflow-templates).

## Performance Considerations

- OpenFlow client maintains connection pool per bridge
- Related OVSDB operations (e.g., bridge/port/interface creation) are combined into single multi-operation transactions
- ARP lookups are O(n) but table is typically small
- Policy engine caches port states in memory
- Flow rules use priority-based matching for efficiency

## Security Considerations

1. **Unix Socket Authentication** - OVSDB and OpenFlow use Unix sockets
2. **Certificate Validation** - IDevID certificates validated before policy
3. **Flow Rule Isolation** - Each port has isolated flow rules
4. **VLAN Segmentation** - Provisioning and quarantine VLANs isolated
5. **Defense in Depth** - Both OpenFlow DROP and OVSDB admin_state=down for blocking

## Bridges on a host

Every platform host has two OVS bridges, with separate jobs:

```
                 switch trunk (port class gateway / hypervisor)
                                  │
                ┌─────────────────▼─────────────────┐
                │ br-fabric                          │  sdn.ovs.bridge
                │  bond0 (trunk)                     │
                │  host zone ports: fabric VTEP,     │  one internal port per
                │  control-plane, hypervisor, ...    │  zone the host addresses
                └────────────────────────────────────┘
                ┌────────────────────────────────────┐
                │ br-int                              │  compute / qemu bridge
                │  vnetN (VMs), ctr-* (containers)    │  never carries the trunk
                └────────────────────────────────────┘
```

- **`br-fabric`** carries the physical trunk and the host's own zone
  addresses. For every `network.bonds[].vlans[]` entry `{zone, ipv4-address}`
  platformd creates an OVS internal port named `zone<VLAN>` (`zone406` for
  control-plane in environment 4) on the bond's bridge, tagged with the zone's
  VLAN from the plan, runs the duplicate-address guard (#508) and assigns the
  address. The bridge's own interface carries no address: an untagged address
  would land on the trunk's native VLAN, provisioning. The lifecycle and
  matrix flows of the policy engine are programmed here.
- **`br-int`** is the integration bridge for workload ports. Nothing patches
  it to `br-fabric`: workloads reach the network only through the overlay
  (EVPN/VXLAN, #709), never on an underlay VLAN.
