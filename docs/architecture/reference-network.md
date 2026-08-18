# Reference Network Architecture

This document defines the **reference network architecture** for go-trusted-platform. It describes
the platform's **zone model**, addressing, device lifecycle, and management access — the same design
across every deployment topology, from a single box to a high-availability cluster.

> **Scope.** This reference covers the **platform tier only**. It is hardware-agnostic and makes no
> assumptions about any surrounding site, office, or home network. Deployments that coexist with
> other networks keep those entirely separate and document them in their own deployment docs — they
> are never part of this reference. All VLAN numbers and subnets here are defaults; everything is
> configurable.

## The core idea: zones

A network segment (a VLAN/subnet) and its **security policy** are two different things. Hardcoding
"VLAN 200 = production" couples them and can't express "make *this* subnet public" or "have three
trusted subnets." So the platform decouples them:

> A **zone** is a named trust/exposure classification that carries policy. **Subnets are assigned to
> zones.** The platform derives *all* enforcement — SDN flow rules, firewall policy, compute
> placement, DNS naming, identity, and compliance controls — from the **zone**, not the VLAN number.

You declare a subnet and its zone; the platform automatically applies that zone's policy everywhere.
VLAN numbers become plain L2 segment identifiers with no inherent meaning.

### Zone taxonomy

| Zone | Trust state | Exposure | Auto-applied policy |
|------|-------------|----------|---------------------|
| `provisioning` | onboarding (pre-trust) | none | DHCP / iPXE / TFTP / DNS / ACME only |
| `quarantine` | untrusted / failed | none | auth + remediation only; fully isolated |
| **`trusted`** | enrolled + attested + compliant | **internal** | east-west per device profile; **no internet ingress** |
| **`public`** | enrolled + attested | **internet-facing** | internet ingress; **isolated from `trusted`** (defense-in-depth) |
| `storage` | attested | internal | storage protocols only; isolated, high-bandwidth |
| `tenant` | attested | isolated | per-tenant isolation (one micro-zone per tenant) |
| `management` | n/a (shared OOB) | OOB | IPMI/BMC/console; **never routes to any data zone** |

`trusted` (internal, protected) and `public` (internet-facing) are the two primary operational
zones — the classic trusted/DMZ split. Both hold *enrolled, attested* hosts; the difference is
**exposure**. `quarantine` and `provisioning` are the lifecycle zones; `storage`/`tenant`/
`management` are special-purpose.

### Assigning subnets to zones

```yaml
networks:
  - {name: corp,     subnet: 198.18.0.0/24, vlan: 200,  zone: trusted}
  - {name: web,      subnet: 203.0.113.0/24,  vlan: 1000, zone: public}    # e.g. your public IP block
  - {name: backups,  subnet: 172.16.203.0/24, vlan: 203,  zone: storage}
  - {name: onboard,  subnet: 172.16.201.0/24, vlan: 201,  zone: provisioning}
```

Mark any subnet `public` or `trusted` (or any zone) and the platform wires up the matching policy.
Multiple subnets may share a zone; a public IP block is simply a `zone: public` subnet — there is
no special "edge" VLAN.

## Inter-zone policy matrix

Default is **deny** between zones; the platform installs these allowances:

| From ↓ \ To → | trusted | public | storage | provisioning | quarantine | tenant | mgmt |
|---------------|:-------:|:------:|:-------:|:------------:|:----------:|:------:|:----:|
| **trusted** | allow (per profile) | declared service paths only | allow | — | — | — | — |
| **public** | **deny** | allow | — | — | — | — | — |
| **storage** | allow (clients) | — | allow | — | — | — | — |
| **provisioning** | — | — | — | — | — | — | CP services only (DHCP/DNS/ACME) |
| **quarantine** | — | — | — | — | — | — | auth + remediation only |
| **tenant** | — | — | per-tenant | — | — | isolated per tenant | — |
| Internet | — | **ingress → public** | — | — | — | — | — |

Key rules: `public → trusted` is **denied** (a compromised internet-facing host cannot reach
internal workloads); `trusted → public` is allowed only on declared service paths; `quarantine` and
`provisioning` reach only the control-plane services they need; `management` is OOB and never
touches a data zone.

## Integration across the platform

The zone is a single policy primitive enforced uniformly at every layer:

- **SDN (OVS/OpenFlow):** every OVS port is tagged with its subnet's zone. Flow rules are generated
  from **per-zone templates** (see [Flow rules](#flow-rules)) plus the inter-zone matrix above.
- **Compute (VMs):** a device profile declares `zone:`; the platform places the VM on a subnet in
  that zone and applies the zone policy to its vNIC (OVS port). Re-homing a workload = re-tag + re-place.
- **Containers:** container networks map to zones (CNI / network-policy selector) — the same
  identity model as VMs.
- **Identity (zero-trust tie-in):** the workload's **IDevID / ACME certificate encodes its zone**
  (X.509 extension and/or SAN naming). Policy can then follow *cryptographic identity*, not just IP
  — a workload proves "I am in `trusted`" and the SDN enforces accordingly.
- **DNS naming (convention, not coupling):** a host in zone _Z_ is named `<host>.Z.<domain>` and the
  control-plane authoritative DNS auto-creates the per-zone subdomain. DNS **reflects** zone
  membership for readability and discovery, but is **never the security boundary** — enforcement
  lives in the SDN/identity layer, so DNS spoofing cannot grant access. Names and policy stay
  aligned but independent.
- **Compliance:** each zone is a control boundary — NIST **SC-7** (boundary protection between
  zones), **SC-4** (tenant isolation), **AC-4** (the inter-zone flow matrix). Audit and report per zone.

## Addressing

Platform subnets default to `172.16.0.0/16` with the mnemonic **VLAN _N_ → `172.16.N.0/24`** for the
well-known defaults. Under the zone model the VLAN number is just a segment ID; the zone carries the
meaning, so the defaults are a convenience, not a constraint.

| Default subnet | VLAN | Default zone |
|----------------|-----:|--------------|
| 198.18.0.0/24 | 200 | trusted |
| 172.16.201.0/24 | 201 | provisioning |
| 172.16.202.0/24 | 202 | quarantine |
| 172.16.203.0/24 | 203 | storage |
| 172.17.0.0/16+ | 1000+ | tenant |
| (deployment public IP block) | — | public |
| (deployment OOB net) | 50 | management |
| 172.16.0.0/24 (/31s) | 10 | transit (gateway ↔ upstream/BGP) |

`management` and `transit` are shared/edge concerns, not data zones. Point-to-point links use
`172.16.0.0/24` carved into /31s.

## Deployment topologies

Same zone model for all three. Node **roles**: Control Plane (platformd *server* mode:
CA/ACME/IAM/KMS/DNS), Gateway (platformd *client* mode: DHCP/iPXE/DNS-forward/BGP/OVS/NAT, runs the
zone flow rules), Compute Worker (platformd *client* mode: QEMU/KVM + Podman workloads).

| Topology | Nodes | Roles | Zones typically present |
|----------|-------|-------|-------------------------|
| **Single-Node** | 1 | CP + Gateway + Worker on one box | trusted, provisioning, quarantine on one OVS bridge |
| **Three-Node** | 3 | 1 CP (standalone, PebbleDB) · 1 Gateway · 1 Compute Worker | + transit on the gateway; storage/public optional |
| **HA Cluster** | 7+ | 3 CP (Raft quorum) · 2 Gateway · 2+ Compute Worker | + storage (resilient), public (if internet-facing), tenant (if multi-tenant) |

Gateway **modes** (Overlay `0x01` / Edge `0x02` / Transit `0x04`) are independent feature toggles —
e.g. Transit advertises a `public`-zone subnet via BGP. They don't change the zone model.

## Storage

Two distinct things both called "storage":

1. **Control-plane state** (CA/IAM/KMS/DNS): handled by the topology, not the network — local
   PebbleDB on the CP for Single/Three-Node; **Raft-backed QuicBaaS** across 3 CPs for HA. Not a zone.
2. **Workload/bulk storage** (VM disks, datasets, backups): served over the **`storage` zone**.

The workload-storage **provider is a configurable role**:

| | Default | Options |
|--|---------|---------|
| Single-Node | Local disk (no storage network) | — |
| Three-Node | Compute Worker uses **local** storage | a `storage`-zone subnet backed by a NAS/SAN **or** a storage VM — physical or virtual |
| HA Cluster | Resilient `storage` zone | **dedicated** storage nodes **or** hyperconverged (replicated across workers) |

Co-located or dedicated, physical or virtual — bound in deployment config. Give the `storage` zone a
**dedicated 10GbE+ NIC** (VLANs isolate security, not bandwidth). Keep storage backends for
different trust zones on **separate disks/pools** — a shared datastore is a cross-zone data path
even with the network isolated.

## Management access

Two planes, neither implicitly bridging zones:

1. **Out-of-band hardware (`management` zone, shared):** IPMI/BMC/console on a separate NIC; never
   routes to a data zone.
2. **Platform control plane → WireGuard admin VPN on the gateway.** Admins reach control/management
   endpoints through an authenticated WireGuard tunnel into a small admin subnet that gateway policy
   restricts to management endpoints only. Operator workstations are **never dual-homed** onto a
   data zone — they authenticate in through the one enforced, logged chokepoint. Gateways SHOULD
   expose this endpoint by default.

## Device lifecycle

```
   Device connects (untagged) ─► VLAN 1 DEFAULT (logged, unknown)
        │ classified
        ▼
   provisioning zone ── DHCP/PXE/DNS/ACME ──► (OS installed, IDevID issued, zone stamped in cert)
        │
        ▼
   assigned to its zone per device profile        ┌─ minor violation → remediated ─┐
   - trusted / public / storage / tenant          └──────────────┬─────────────────┘
        │ severe violation     compliance failure                ▲
        ▼                          ▼                              │
   Port DOWN (BLOCKED)        quarantine zone ────────────────────┘
   zero access                auth + remediation only
```

**Blocked devices** are not put in a "blocked zone" — the OVS port is administratively disabled
(`SetPortState(..., PortStateDown)`): zero access (not even ARP), no lateral movement, clear audit.

## Flow rules (OVS / OpenFlow) — per-zone templates

Rules are generated per zone from templates; `<zone-vlan>` is the segment carrying that zone.

### quarantine — auth/remediation only
```bash
ovs-ofctl add-flow br0 "priority=900,in_port=<port>,dl_vlan=<quarantine>,dl_type=0x0806,actions=normal"               # ARP
ovs-ofctl add-flow br0 "priority=850,in_port=<port>,dl_vlan=<quarantine>,udp,tp_src=68,tp_dst=67,actions=normal"      # DHCP
ovs-ofctl add-flow br0 "priority=800,in_port=<port>,dl_vlan=<quarantine>,udp,nw_dst=<dns_ip>,tp_dst=53,actions=normal"
ovs-ofctl add-flow br0 "priority=700,in_port=<port>,dl_vlan=<quarantine>,tcp,nw_dst=<remediation_ip>,tp_dst=443,actions=normal"
ovs-ofctl add-flow br0 "priority=100,in_port=<port>,dl_vlan=<quarantine>,actions=drop"                                # default deny
```

### provisioning — PXE + enrollment
```bash
ovs-ofctl add-flow br0 "priority=900,in_port=<port>,dl_vlan=<provisioning>,dl_type=0x0806,actions=normal"             # ARP
ovs-ofctl add-flow br0 "priority=850,in_port=<port>,dl_vlan=<provisioning>,udp,tp_src=68,tp_dst=67,actions=normal"    # DHCP
ovs-ofctl add-flow br0 "priority=800,in_port=<port>,dl_vlan=<provisioning>,udp,tp_dst=53,actions=normal"              # DNS
ovs-ofctl add-flow br0 "priority=750,in_port=<port>,dl_vlan=<provisioning>,udp,tp_dst=69,actions=normal"              # TFTP
ovs-ofctl add-flow br0 "priority=700,in_port=<port>,dl_vlan=<provisioning>,tcp,nw_dst=<acme_ip>,tp_dst=443,actions=normal"  # ACME
ovs-ofctl add-flow br0 "priority=50,in_port=<port>,dl_vlan=<provisioning>,actions=drop"                               # default deny
```

### trusted / public (inter-zone matrix)
```bash
ovs-ofctl add-flow br0 "priority=100,in_port=<port>,dl_vlan=<trusted>,actions=normal"                                 # trusted east-west per profile
# public is isolated from trusted (defense-in-depth): only declared trusted→public service paths
ovs-ofctl add-flow br0 "priority=200,dl_vlan=<public>,ip,nw_dst=<trusted_subnet>,actions=drop"                        # public ↛ trusted
ovs-ofctl add-flow br0 "priority=100,in_port=<port>,dl_vlan=<public>,actions=normal"                                  # public ingress/egress
```

## Physical interface recommendations

| Interface | Zones | Purpose |
|-----------|-------|---------|
| NIC 0 (1+GbE) | `management` only | Out-of-band (separate network) |
| NIC 1 (10+GbE) | trusted / public / provisioning / quarantine (trunk) | Data zones |
| NIC 2–3 (10+GbE) | `storage` only | Storage (bonded, dedicated high bandwidth) |

## Switch port model

The upstream switch ports mirror the node roles. This is the contract the
platform's switch management (`fabric.switches` / `port_assignments`,
post-enrollment VLAN moves) programs and assumes:

| Port class | Mode | VLANs | Rationale |
|------------|------|-------|-----------|
| Gateway data port | 802.1Q trunk (LACP/vPC when bonded) | all platform zone VLANs (default 200–203) | The gateway serves DHCP/PXE on `provisioning`, routes/filters every zone, and runs the OVS flow templates — it must see all zone tags. |
| Control-plane data port | 802.1Q trunk (LACP/vPC when bonded) | all platform zone VLANs | The CP participates in `trusted` and reaches `provisioning`/`quarantine` for enrollment and remediation services. |
| Compute/worker data port | **access** | one VLAN, driven by the device lifecycle | Untagged access is what lets a factory NIC's PXE ROM (which cannot tag) boot into `provisioning`. The platform then flips the access VLAN through the lifecycle: `provisioning` (201) at enrollment → assigned zone (`trusted` 200 by default) → `quarantine` (202) on violation → port administratively down when blocked. |
| Storage port | access on the `storage` VLAN (203); trunk only for hyperconverged workers | storage | Dedicated bandwidth; no cross-zone tags. |
| Inter-switch peer-link / platform uplink | trunk | all platform zone VLANs | vPC/MLAG peers and the link toward the platform's L3 gateway. |

Rules that keep the tiers honest:

- Platform zone VLANs are trunked **only** to platform node ports, the
  inter-switch peer-link, and the platform's L3 gateway (the platform
  gateway node, or an interim site router before gatewayd cutover). They
  are never extended to site firewalls, campus access switches, or any
  non-platform host — address-range separation plus VLAN scoping is the
  tier boundary.
- The `management` VLAN is the only deliberately shared plane (BMC/OOB),
  and it never routes to a data zone.
- A compute port's access VLAN is owned by the platform lifecycle — an
  operator changing it by hand bypasses the enrollment state machine.

## Configuration

```yaml
# /etc/trusted-platform/config.yaml
sdn:
  enabled: true
  bridge_name: "br0"

  # Zones carry policy; subnets are assigned to a zone.
  zones:                 # built-in zones (extend as needed)
    - {name: trusted,      internet_ingress: false}
    - {name: public,       internet_ingress: true,  isolate_from: [trusted]}
    - {name: provisioning, services: [dhcp, tftp, dns, acme]}
    - {name: quarantine,   services: [auth, remediation]}
    - {name: storage,      isolate: true}
    - {name: tenant,       isolate_per_tenant: true}
    - {name: management,   oob: true, route_to_data: false}

  networks:              # subnet -> zone (defaults shown)
    - {name: trusted-default,      subnet: "198.18.0.0/24", vlan: 200,  zone: trusted}
    - {name: provisioning-default, subnet: "172.16.201.0/24", vlan: 201,  zone: provisioning}
    - {name: quarantine-default,   subnet: "172.16.202.0/24", vlan: 202,  zone: quarantine}
    - {name: storage-default,      subnet: "172.16.203.0/24", vlan: 203,  zone: storage}
    # public/tenant subnets are deployment-specific:
    # - {name: web, subnet: "203.0.113.0/24", vlan: 1000, zone: public}

  dns:
    zone_subdomains: true            # <host>.<zone>.<domain>; reflects (does not enforce) zones
  identity:
    encode_zone_in_cert: true        # IDevID/ACME cert carries the zone (policy follows identity)

  transit: {vlan: 10, p2p: "172.16.0.0/24"}
  management_vpn: {enabled: true, type: wireguard, allow_to: [management]}

  services:
    provisioning: {acme_server: "172.16.201.10", dns_server: "172.16.201.1", dhcp_range: "172.16.201.100-172.16.201.200"}
    quarantine:   {remediation_server: "172.16.202.10", dns_server: "172.16.202.1"}
```

### Default constants

```go
// pkg/sdn/zone/defaults.go
type Zone string
const (
    ZoneTrusted      Zone = "trusted"       // internal, attested (was "production")
    ZonePublic       Zone = "public"        // internet-facing, isolated from trusted
    ZoneProvisioning Zone = "provisioning"
    ZoneQuarantine   Zone = "quarantine"
    ZoneStorage      Zone = "storage"
    ZoneTenant       Zone = "tenant"
    ZoneManagement   Zone = "management"    // shared OOB, separate NIC
)

// pkg/sdn/vlan/defaults.go — default segment IDs for the well-known zone subnets
const (
    DefaultTrustedVLAN      = uint16(200)
    DefaultProvisioningVLAN = uint16(201)
    DefaultQuarantineVLAN   = uint16(202)
    DefaultStorageVLAN      = uint16(203)
    DefaultCloudTenantBaseVLAN = uint16(1000)
    DefaultTransitVLAN      = uint16(10)
    DefaultManagementVLAN   = uint16(50)
    DefaultVLAN = uint16(1)                 // IEEE 802.1Q default catch-all
    MinVLANID, MaxVLANID = uint16(1), uint16(4094)
)
```

Configuration precedence (highest first): **device profile → environment variables → platform
config YAML → default constants**.

## Future considerations

- **IPv6:** ULA `fd00::/8` internal, GUA for `public`, dual-stack flow rules, RA/DHCPv6 in `provisioning`.
- **Tenant scaling beyond ~3,000 VLANs:** VXLAN overlay (24-bit VNI), per-tenant routing domains.
- **External SDN controllers:** ONOS / OpenDaylight / NSX / Kubernetes network policies — zones map
  to their policy/identity primitives.

## Related documentation

- [Deployment Reference](deployment-reference.md) — topologies, node roles, bootstrap
- [Platform Modes](platform-modes.md) — Local / P2P / Hosted control-plane modes
- [Security Model](security-model.md) — trust boundaries and threat model
- [SDN Gateway](../sdn/gateway/README.md) — gateway modes and implementation
