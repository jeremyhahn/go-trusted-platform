# Reference Network Architecture

This document defines the **reference network architecture** for go-trusted-platform. It describes
the platform's network tiers, VLANs, addressing, device lifecycle, and management access — the
same design across every deployment topology, from a single box to a high-availability cluster.

> **Scope.** This reference covers the **platform tier only**. It is hardware-agnostic and makes no
> assumptions about any surrounding site, office, or home network. Deployments that coexist with
> other networks (shared switches, an enterprise LAN, a lab) keep those networks **entirely
> separate** and document them in their own deployment docs — they are never part of this
> reference. All VLAN numbers and subnets here are defaults and are fully configurable.

## Design principles

- **One scheme everywhere.** The VLAN/subnet design is identical for all topologies (Single-Node,
  Three-Node, HA Cluster). Topologies differ only in node count and role placement — never in the
  network design. This is what makes deployments standardized and predictable.
- **Memorable mnemonic.** Platform VLANs live in the **200-series**, and **VLAN _N_ → `172.16.N.0/24`**
  (e.g. VLAN 200 = `198.18.0.0/24`). You can derive the subnet from the VLAN and vice versa — no
  lookup table.
- **Three VLANs are enough to start.** PRODUCTION, PROVISIONING, and QUARANTINE deliver a working
  trust lifecycle. Everything else (storage, DMZ, tenants) is **opt-in**.
- **Zero-trust segmentation.** Every device proves identity before leaving provisioning. Tiers do
  not route to each other implicitly; crossings happen only through enforced, authenticated points
  (the gateway, and the management VPN).

## Network tiers & VLANs

| VLAN | Name | Subnet | Always present? | Purpose |
|-----:|------|--------|-----------------|---------|
| 200 | PRODUCTION | 198.18.0.0/24 | ✅ | Enrolled, attested workloads (east-west; **no direct internet ingress**) |
| 201 | PROVISIONING | 172.16.201.0/24 | ✅ | Onboarding — DHCP, iPXE/TFTP, DNS, ACME enrollment |
| 202 | QUARANTINE | 172.16.202.0/24 | ✅ | Non-compliant / untrusted hosts — auth + remediation only |
| 203 | STORAGE | 172.16.203.0/24 | optional | Workload/bulk storage tier (see [Storage](#storage)) |
| 210 | DMZ | 172.16.210.0/24 | optional | Public-facing services (single-tier default; see below) |
| 1000+ | TENANT | 172.17.0.0/16+ | optional | Multi-tenant isolated workloads |
| 10 | TRANSIT | 172.16.0.0/24 (P2P /31s) | edge | Gateway ↔ upstream routers / BGP |
| 50 | MANAGEMENT | deployment-defined | shared | Out-of-band IPMI/BMC/console — **separate NIC, never routes to data** |
| 1 | DEFAULT | — | — | IEEE 802.1Q catch-all; carries no addressed network |

**Point-to-point links** use `172.16.0.0/24` carved into /31s (router↔router, router↔gateway,
switch uplinks) — 128 links of capacity, kept out of the host subnets.

### PRODUCTION (200) vs DMZ (210) — the key distinction

"Trusted" on the platform means **identity-trusted**: every node on PRODUCTION has proven its
identity (IDevID certificate via ACME) and passed compliance. It does **not** mean "safe to expose
to the internet."

- **PRODUCTION (200)** is internal east-west workloads. Nothing on the public internet reaches it
  directly.
- **DMZ (210)** is the controlled buffer where services that **must** accept inbound internet
  traffic live (web front-ends, public APIs, load balancers, reverse proxies). It is isolated so
  that a compromise of an internet-facing service **cannot pivot straight into PRODUCTION**.

Inbound flow: `Internet → Gateway (transit/NAT) → DMZ (210) → controlled hop → PRODUCTION (200) → STORAGE (203)`.
The DMZ is **optional** — a deployment that exposes no public services omits it. When present, it
defaults to a single VLAN (210); deployments needing defense-in-depth expand it to a three-tier
web/app/db DMZ (210 PUBLIC / 211 PRIVATE / 212 DATA).

## Deployment topologies

The same VLAN scheme applies to all three. Node **roles** are Control Plane (platformd *server*
mode: CA/ACME/IAM/KMS/DNS), Gateway (platformd *client* mode: DHCP/iPXE/DNS-forward/BGP/OVS/NAT),
and Compute Worker (platformd *client* mode: QEMU/KVM + Podman workloads).

| Topology | Nodes | Roles | VLANs typically present |
|----------|-------|-------|-------------------------|
| **Single-Node** | 1 | CP + Gateway + Worker on one box | 200/201/202 on one OVS bridge; 50 OOB; 10 only if it runs its own transit/BGP |
| **Three-Node** | 3 | 1 CP (standalone, PebbleDB) · 1 Gateway · 1 Compute Worker | core 200/201/202 + 10 transit on the gateway; 203/210 optional |
| **HA Cluster** | 7+ | 3 CP (Raft quorum) · 2 Gateway · 2+ Compute Worker | core + 203 STORAGE (resilient) + 210 DMZ (if public) + 1000+ TENANT (if multi-tenant) + 10 transit on both gateways |

Gateway **modes** (Overlay `0x01` / Edge `0x02` / Transit `0x04`) are independent feature toggles
on gateway nodes — a gateway can run one or several at once. They do not change the VLAN design.

## Storage

Distinguish two different things both called "storage":

1. **Control-plane state** (CA, IAM, KMS, authoritative DNS): handled by the topology, not the
   network. Single-Node and Three-Node use local PebbleDB on the control-plane node; HA replicates
   it via **Raft-backed QuicBaaS** across the 3 control-plane nodes. This is *not* a network tier.
2. **Workload / bulk storage** (VM disks, datasets, backups): served over the optional **STORAGE
   tier (VLAN 203)**.

For workload storage, the **storage provider is a configurable role**, not a fixed placement:

| | Default | Options |
|--|---------|---------|
| **Single-Node** | Local disk (no storage network) | — |
| **Three-Node** | Compute Worker uses **local** storage | Attach a **STORAGE tier (203)** backed by a NAS/SAN **or** a storage VM — **physical or virtual** |
| **HA Cluster** | Resilient **STORAGE tier (203)** | **Dedicated** storage nodes **or** hyperconverged (replicated across Compute Workers) |

The provider may be **co-located or dedicated, physical or virtual**, bound in deployment config.
The storage tier should ride a **dedicated 10GbE+ NIC** (VLANs isolate security, not bandwidth —
backup traffic can otherwise saturate the production trunk). Keep workload-storage backends for
different trust tiers on **separate disks/pools** — a shared datastore is a cross-tier data path
even when the network is isolated.

## Management access

Two distinct management planes, neither of which implicitly bridges tiers:

1. **Out-of-band hardware (VLAN 50, shared):** IPMI/BMC/console for power, recovery, and console.
   On a separate physical NIC; **must never route to any data VLAN**. Shared infrastructure not
   owned by the platform.
2. **Platform control plane → WireGuard admin VPN on the gateway.** Administrators reach the
   platform's control/management endpoints (platformctl API, control plane) by bringing up an
   authenticated **WireGuard** tunnel to a gateway node, landing in a small admin-VPN subnet that
   gateway policy restricts to **management endpoints only** — not production workloads or storage.

This means an operator workstation is **never dual-homed** onto a platform data VLAN. It stays on
its own network and authenticates in through the one enforced, logged chokepoint. A compromise of
the operator's network cannot reach the platform without also holding the WireGuard key and passing
gateway policy. Gateway nodes SHOULD expose this WireGuard management endpoint by default.

## Device lifecycle

```
   Device connects (untagged)
        │
        ▼
   VLAN 1 (DEFAULT) ── logged/monitored, unknown
        │ classified for provisioning
        ▼
   VLAN 201 (PROVISIONING) ── DHCP, TFTP, DNS, HTTP(S), ACME
        │ OS installed, ACME-enrolled (IDevID issued)
        ▼
   Production VLAN (per device profile)            ┌─ minor violation ─┐
   - 200 PRODUCTION                                │   remediated      │
   - 210–212 DMZ                                   └───────┬───────────┘
   - 1000+ TENANT                                          ▲
        │ severe violation        compliance failure       │
        ▼                              ▼                    │
   Port DOWN (BLOCKED)            VLAN 202 (QUARANTINE) ─────┘
   zero network access           auth + remediation only
```

**Blocked devices** are not placed in a "blocked VLAN" — the OVS port is administratively disabled
(`SetPortState(..., PortStateDown)`): zero access (not even ARP), no lateral movement, clear audit.

## Flow rules (OVS / OpenFlow)

### Quarantine (VLAN 202) — minimal connectivity for auth/remediation
```bash
ovs-ofctl add-flow br0 "priority=900,in_port=<port>,dl_vlan=202,dl_type=0x0806,actions=normal"               # ARP
ovs-ofctl add-flow br0 "priority=850,in_port=<port>,dl_vlan=202,udp,tp_src=68,tp_dst=67,actions=normal"      # DHCP
ovs-ofctl add-flow br0 "priority=850,dl_vlan=202,udp,tp_src=67,tp_dst=68,actions=normal"
ovs-ofctl add-flow br0 "priority=800,in_port=<port>,dl_vlan=202,udp,nw_dst=<dns_ip>,tp_dst=53,actions=normal" # DNS (internal only)
ovs-ofctl add-flow br0 "priority=700,in_port=<port>,dl_vlan=202,tcp,nw_dst=<remediation_ip>,tp_dst=443,actions=normal"
ovs-ofctl add-flow br0 "priority=100,in_port=<port>,dl_vlan=202,actions=drop"                                # default deny
```

### Provisioning (VLAN 201) — PXE boot + certificate enrollment
```bash
ovs-ofctl add-flow br0 "priority=900,in_port=<port>,dl_vlan=201,dl_type=0x0806,actions=normal"               # ARP
ovs-ofctl add-flow br0 "priority=850,in_port=<port>,dl_vlan=201,udp,tp_src=68,tp_dst=67,actions=normal"      # DHCP
ovs-ofctl add-flow br0 "priority=850,dl_vlan=201,udp,tp_src=67,tp_dst=68,actions=normal"
ovs-ofctl add-flow br0 "priority=800,in_port=<port>,dl_vlan=201,udp,tp_dst=53,actions=normal"                # DNS
ovs-ofctl add-flow br0 "priority=800,in_port=<port>,dl_vlan=201,tcp,tp_dst=53,actions=normal"
ovs-ofctl add-flow br0 "priority=750,in_port=<port>,dl_vlan=201,udp,tp_dst=69,actions=normal"                # TFTP (PXE)
ovs-ofctl add-flow br0 "priority=700,in_port=<port>,dl_vlan=201,tcp,nw_dst=<acme_ip>,tp_dst=443,actions=normal"  # ACME
ovs-ofctl add-flow br0 "priority=650,in_port=<port>,dl_vlan=201,tcp,tp_dst=80,actions=normal"                # repos
ovs-ofctl add-flow br0 "priority=650,in_port=<port>,dl_vlan=201,tcp,tp_dst=443,actions=normal"
ovs-ofctl add-flow br0 "priority=50,in_port=<port>,dl_vlan=201,actions=drop"                                 # default deny
```

### Production / DMZ
```bash
ovs-ofctl add-flow br0 "priority=100,in_port=<port>,dl_vlan=200,actions=normal"                              # production per-profile ACLs
# Optional 3-tier DMZ: PRIVATE(211) accepts only PUBLIC(210); DATA(212) accepts only PRIVATE(211)
ovs-ofctl add-flow br0 "priority=200,in_port=<port>,dl_vlan=211,ip,nw_src=172.16.210.0/24,actions=normal"
ovs-ofctl add-flow br0 "priority=100,in_port=<port>,dl_vlan=211,actions=drop"
ovs-ofctl add-flow br0 "priority=200,in_port=<port>,dl_vlan=212,ip,nw_src=172.16.211.0/24,actions=normal"
ovs-ofctl add-flow br0 "priority=100,in_port=<port>,dl_vlan=212,actions=drop"
```

## Physical interface recommendations

| Interface | VLANs | Purpose |
|-----------|-------|---------|
| NIC 0 (1+GbE) | VLAN 50 only | Out-of-band management (separate network) |
| NIC 1 (10+GbE) | 200–212 (trunk) | Production + DMZ |
| NIC 2–3 (10+GbE) | VLAN 203 only | Storage (bonded, dedicated high bandwidth) |

VLANs isolate security, not bandwidth — all VLANs on a trunk share one pipe. Storage and the OOB
management plane each warrant their own NIC.

## Configuration

VLAN and subnet assignments are fully configurable; the values below are the reference defaults.

```yaml
# /etc/trusted-platform/config.yaml
sdn:
  enabled: true
  bridge_name: "br0"

  vlans:                 # defaults — override per deployment
    production: 200
    provisioning: 201
    quarantine: 202
    storage: 203         # optional tier
    dmz: 210             # optional; expand to dmz_public/private/data for 3-tier
    cloud_tenant_base: 1000
    transit: 10
    management: 50       # shared OOB (separate NIC)

  subnets:               # VLAN N -> 172.16.N.0/24
    production:   "198.18.0.0/24"
    provisioning: "172.16.201.0/24"
    quarantine:   "172.16.202.0/24"
    storage:      "172.16.203.0/24"
    dmz:          "172.16.210.0/24"
    p2p:          "172.16.0.0/24"     # /31 point-to-point links

  storage:
    provider: local      # local | tier
    placement: colocated # colocated | dedicated   (when provider: tier)
    medium: virtual      # physical | virtual       (when provider: tier)

  management_vpn:
    enabled: true        # gateway WireGuard admin endpoint
    type: wireguard
    admin_subnet: "172.16.250.0/24"
    allow_to: ["management"]   # least-privilege: control plane only

  services:
    provisioning:
      acme_server: "172.16.201.10"
      dns_server:  "172.16.201.1"
      dhcp_range:  "172.16.201.100-172.16.201.200"
    quarantine:
      remediation_server: "172.16.202.10"
      dns_server: "172.16.202.1"
```

### Default constants

```go
// pkg/sdn/vlan/defaults.go
const (
    DefaultProductionVLAN   = uint16(200)
    DefaultProvisioningVLAN = uint16(201)
    DefaultQuarantineVLAN   = uint16(202)
    DefaultStorageVLAN      = uint16(203)   // optional
    DefaultDMZVLAN          = uint16(210)   // optional (single-tier default)
    DefaultCloudTenantBaseVLAN = uint16(1000)
    DefaultTransitVLAN      = uint16(10)
    DefaultManagementVLAN   = uint16(50)    // shared OOB, separate NIC

    DefaultVLAN = uint16(1)                 // IEEE 802.1Q default
    MinVLANID   = uint16(1)
    MaxVLANID   = uint16(4094)
)
```

Configuration precedence (highest first): **device profile → environment variables → platform
config YAML → default constants**.

## Future considerations

- **IPv6:** ULA `fd00::/8` for internal tiers, GUA for internet-facing services, dual-stack flow
  rules, RA/DHCPv6 in PROVISIONING.
- **Tenant scaling beyond ~3,000 VLANs:** VXLAN overlay (24-bit VNI) and per-tenant routing domains.
- **External SDN controllers:** ONOS / OpenDaylight / NSX / Kubernetes network policies.

## Related documentation

- [Deployment Reference](deployment-reference.md) — topologies, node roles, bootstrap
- [Platform Modes](platform-modes.md) — Local / P2P / Hosted control-plane modes
- [Security Model](security-model.md) — trust boundaries and threat model
- [SDN Gateway](../sdn/gateway/README.md) — gateway modes and implementation
