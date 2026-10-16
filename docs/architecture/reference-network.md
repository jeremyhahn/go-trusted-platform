# Reference Network Architecture

> **Status: REFERENCE** · Last verified: 2026-10-13
> The approved reference network: zones, VLANs, subnets, port classes and overlays (#708).

This is the reference network for go-trusted-platform: how a deployment lays out its VLANs, subnets,
switch ports and overlays. The same model applies to every topology, from a single box to an HA
cluster.

> **Implementation.** The zone model, the addressing, the port classes and host addressing by role are implemented (#708): every number
> below is derived by `pkg/sdn/netplan`. The EVPN overlay service is #709, tenant VRFs and the
> platform VRF's overlay attachment follow it, and gateway HA is #596 and #710. Where a section
> depends on one of those, it says so.

> **Scope.** This covers the platform tier only. Any site, office or home network beside it is out
> of scope and stays separate. Every number here is a default, and the address base is
> configurable.

## Principles

1. **Underlay and overlay are separate.** The switch carries a small, fixed set of **underlay VLANs**
   per environment: transit, fabric, management, storage and so on. Workloads, public services and
   tenants live on **overlay networks** (EVPN/VXLAN) that the SDN creates. They never live on switch
   VLANs.
2. **Trust comes from identity, not from a segment.** There is no "trusted" zone. OVS and the
   overlay admit only a node that presents a valid IDevID, so every SDN-created network is trusted
   by construction. `public` is simply an overlay that the gateway exposes to the internet.
3. **The switch is pure L2.** It has no SVIs, no routing and no ACLs. The switch only moves frames
   on the VLANs each port class is allowed to carry.
4. **Routing lives in VRFs.** Routing inside a VRF is distributed (symmetric IRB, RFC 9135): every
   VTEP routes for the VRFs it hosts. The gateway is the only router *between* VRFs and *to the
   outside*, so the VRF is the policy boundary.
5. **One predictable numbering scheme.** A VLAN ID tells you its environment and zone, and it maps
   directly to its IPv4 subnet, its IPv6 subnet and its VNI range.

## Environments

VLANs are allocated in **environment blocks of 100**. The hundreds digit is the environment number
_E_. A deployment uses as many blocks as it has environments. For example:

| Block | VLANs | Example use |
|------:|-------|-------------|
| 2 | 200–299 | dev |
| 3 | 300–399 | staging |
| 4 | 400–499 | prod |

The dev/staging/prod assignment is only an example; the reference speaks of "an environment block".
The platform uses VLANs 200–4094, so _E_ runs from 2 to 40 (block 40 ends at 4094). VLANs 1–199 are
left to whatever site network sits beside the platform. Each block is self-contained: the platform
never trunks a VLAN from one environment into another.

> **Switch caveat.** Cisco NX-OS reserves VLANs 3968–4094 by default, which covers all of block 40
> and offsets 68–99 of block 39. On such a switch either keep those environments below block 39,
> move the reserved range (`system vlan <id> reserve`), or override the affected zones' VLANs.

## Zones: the offsets inside a block

Every environment has the same built-in zones, at the same offsets. The examples use block 4.

| Offset | Zone | Example | Purpose |
|:------:|------|--------:|---------|
| x00 | `transit` | 400 | Gateway edge: upstream handoff and BGP peering |
| x01 | `fabric` | 401 | VXLAN underlay: VTEPs and EVPN between gateways and hypervisors |
| x02 | `management` | 402 | Out-of-band: BMCs only |
| x03 | `hypervisor` | 403 | Live migration between hypervisors |
| x04 | `quarantine` | 404 | Non-compliant or failed nodes: authentication and remediation only |
| x05 | `provisioning` | 405 | Onboarding: DHCP, PXE/iPXE, TFTP, DNS, ACME enrollment |
| x06 | `control-plane` | 406 | Control-plane nodes: CA, ACME, IAM, KMS, DNS, Raft |
| x07 | `storage` | 407 | Block and object storage traffic (for example NVMe/TCP) |
| x08 | `backup` | 408 | Backup traffic to backup targets |
| x09–x99 | owner-defined | 409–499 | Zones the deployment's owner adds |

The built-in zones' **numbering is fixed**: an operator can tune a built-in zone's policy, but never
its offset, its port classes or its lifecycle role. `fabric`, `provisioning`, `quarantine` and
`control-plane` cannot be omitted; the others can, when a deployment has no use for them.

`public`, tenant networks and every workload network are **overlays**, not zones (see
[Overlay networks](#overlay-networks)). `platform`, `tenant`, `public` and the retired `trusted`
cannot name a zone. The old tenant VLAN range (1000+) no longer exists, and **tenants never create
zones**.

### Owner-defined zones

The owner may add zones at offsets x09–x99. Each one gets, like a built-in zone, its own VLAN
(_E_·100+_n_), its own `/24`, its own ULA `/64` and its own policy, and it names the port classes
that carry it: `gateway`, `hypervisor` or both (the peer-link carries every zone). An owner-defined
zone carries no lifecycle role and is never out-of-band.

A zone whose `allow_to` opens a path into `control-plane` or `management` beyond the reference
defaults needs an explicit, audited override: `privileged_access` with a `reason` and an
`approved_by`. The platform logs every such path as an audit record each time it loads the
configuration.

```yaml
sdn:
  zones:
    - name: lab
      offset: 9
      port_classes: [hypervisor]
      isolate: true
      allow_to:
        - {zone: storage, services: [storage]}
```

### Routing and inter-zone policy

The default between zones is **deny**. These are the built-in policies; an operator may tune them.

| Zone | Routed? | Allowed |
|------|---------|---------|
| `transit` | By the gateway, as its upstream edge | Upstream and peering traffic, and gateway-to-gateway traffic in a pair. Nothing else attaches |
| `fabric` | No (single L2 segment) | VXLAN, BGP and IPsec between VTEPs |
| `management` | Never by the platform. Only an external management firewall routes it | Admin networks and the admin VPN to BMCs. Never reaches another zone |
| `hypervisor` | No | Live migration between hypervisors (TLS) |
| `quarantine` | By the gateway | DHCP inside the zone; the control plane's DNS, authentication and remediation endpoints only |
| `provisioning` | By the gateway | DHCP inside the zone; the control plane's TFTP, HTTP, DNS and ACME enrollment services only |
| `control-plane` | By the gateway | Traffic between control-plane nodes. Control-plane APIs reach enrolled nodes over the platform VRF, not through another zone |
| `storage` | No | Storage protocols between storage clients and targets (TLS) |
| `backup` | By the gateway, to declared backup targets only | Backup streams, encrypted at source |

## Addressing

### IPv4

VLAN _N_ maps to the subnet **`10.(N ÷ 100).(N mod 100).0/24`**. The `10.0.0.0/8` base is
configurable (any IPv4 `/8`).

Each environment owns the `/16` `10.E.0.0/16`, split in half:

| Range | Use |
|-------|-----|
| `10.E.0.0/17` | **VLAN-mapped underlay.** VLAN _E·100+n_ is `10.E.n.0/24`. `10.E.100.0`–`10.E.127.255` maps no VLAN and is where a wider fabric goes |
| `10.E.128.0/17` | **IPAM pool**, split below |

The IPAM pool is split into fixed ranges:

| Range | Prefix | Holds |
|-------|--------|-------|
| Tunnel point-to-point | `10.E.128.0/22` | `/31` links of tunnels and transit peerings (512) |
| Loopbacks | `10.E.132.0/22` | Router and VTEP loopback `/32`s (1024) |
| Platform service VIPs | `10.E.136.0/21` | Platform service VIPs (2048) |
| Platform-VRF hosts | `10.E.144.0/20` | One platform-VRF address per attested host (4096) |
| Growth | `10.E.160.0/19` | Unallocated |
| Tenant default pools | `10.E.192.0/18` | Tenant overlay subnets are carved from it (64 `/24`s) |

Within a zone subnet, the reference hosts are:

- `.1`: the gateway (a VRRP address when there is a gateway pair)
- `.2` and `.3`: the gateway nodes
- `.10`–`.19`: control-plane nodes
- `.20`–`.49`: other statically addressed hosts (compute and storage nodes)
- `.50`–`.254`: DHCP, where a zone serves it

Every zone gets an IPAM pool with its subnet, its gateway reserved and a dynamic (DHCP) range from
`.50`, so pool, DHCP scope and VLAN are always derived, never configured.

### Reserved ranges

These are never allocatable:

| Range | Why |
|-------|-----|
| `10.E.128.0/31` | The gateway HA sync link: a direct cable between the gateways of a pair (node 0 takes `.0`, node 1 `.1`) |
| `169.254.169.253` | The per-VRF host-services address (DNS, metadata). The same address answers in every VRF |
| `<ULA>:ffff::/64` | The IPv6 counterpart for per-VRF host services |
| `.1` of every subnet | The gateway address of each zone, and the distributed anycast gateway of each overlay subnet |

### IPv6

Each deployment takes one **ULA `/48`** (RFC 4193, random global ID). The subnet ID is the VLAN
digits, so VLAN 406 in `fd12:3456:789a::/48` is `fd12:3456:789a:406::/64`. Public IPv6 comes from
the operator's own allocation, for example a provider-independent `/36`. It lives on overlays and is
announced by the gateways.

### VNIs

An overlay network's VNI is **`E·100000 + n`**. Environment 4 uses VNIs 400001–499999, so the VNI
also names the environment it belongs to.

### Budgets

| Resource | Budget | When it runs out |
|----------|--------|------------------|
| VTEPs per environment | about 230 on a `/24` fabric (`.20`–`.254` less the DHCP needs of the zone) | Override the fabric subnet with a shorter prefix, for example `10.E.100.0/22` |
| Overlay networks (VNIs) per environment | 99,999 | Use another environment block |
| Conntrack zones per host | 65,535 | Shared by every environment on the host: staging VMs on prod hosts share one budget |

### Overrides for non-reference sites

A site that cannot follow the reference overrides single zones explicitly. The zone keeps its
offset; only where it lives changes. The IPv6 subnet follows the reference VLAN digits unless it is
overridden too.

```yaml
sdn:
  environment:
    id: 4
    base: 10.0.0.0/8
    ula: fd12:3456:789a::/48
    overrides:
      - {zone: fabric, subnet: 10.4.100.0/22}         # a wider fabric
      - {zone: control-plane, vlan: 3006, subnet: 192.0.2.0/24}
```

Overrides may not collide: two zones on one VLAN, overlapping subnets, a zone inside the IPAM pool,
the link-local space or the host-services `/64` all fail validation.

### Worked example: environment 4

| VLAN | Zone | IPv4 | IPv6 |
|-----:|------|------|------|
| 400 | transit | 10.4.0.0/24 | fd12:3456:789a:400::/64 |
| 401 | fabric | 10.4.1.0/24 | fd12:3456:789a:401::/64 |
| 402 | management | 10.4.2.0/24 | fd12:3456:789a:402::/64 |
| 403 | hypervisor | 10.4.3.0/24 | fd12:3456:789a:403::/64 |
| 404 | quarantine | 10.4.4.0/24 | fd12:3456:789a:404::/64 |
| 405 | provisioning | 192.0.2.0/24 | fd12:3456:789a:405::/64 |
| 406 | control-plane | 10.4.6.0/24 | fd12:3456:789a:406::/64 |
| 407 | storage | 10.4.7.0/24 | fd12:3456:789a:407::/64 |
| 408 | backup | 10.4.8.0/24 | fd12:3456:789a:408::/64 |
| — | IPAM pool | 10.4.128.0/17 | from the same /48 |
| — | public (overlay) | 203.0.113.0/24 | 2001:db8::/36 |

(`203.0.113.0/24` and `2001:db8::/36` are documentation ranges. Use your own public allocation.)

## Host addressing

A host holds an address **only on the zones it uses**. There is no multi-homing beyond that.

| Host role | Zones it may address |
|-----------|----------------------|
| control-plane | `fabric` (its VTEP), `control-plane`, and `hypervisor` and `storage` when it hosts VMs or mounts storage |
| compute | `fabric` (its VTEP), `hypervisor`, and `storage` when it mounts storage |
| gateway | Exempt: it routes and NATs by role |

- Every non-gateway host has a fabric address, and no address on the VLANs it only passes through
  to guests.
- IP forwarding is off on every host except gateways, and the host firewall drops traffic between
  its interfaces.
- **Platform VRF**: each attested host has exactly one platform-VRF address,
  from the platform-VRF hosts range, held in a Linux VRF on the host rather than on an underlay
  interface. Platform services reach hosts there, so hosts stay single-homed on the underlay. The
  VRF reaches the network through the fabric VTEP once the platform overlay lands (#709).

The installer enforces this: `network.role` selects the rules, and an address outside the role's
zones, a DHCP interface on a non-gateway host, or `ip-forward` on a non-gateway host fails
validation. The installer writes the forwarding sysctls, the host firewall and the VRF.

## Overlay networks

Every network the SDN creates is an **EVPN/VXLAN overlay**. That includes the `public` network,
tenant networks and workload networks.

- **Transport.** VTEPs sit on the gateways and hypervisors, on the environment's `fabric` VLAN.
  EVPN runs over BGP between them.
- **Admission.** A VTEP joins only after it has attested with a valid IDevID. That identity is what
  makes an overlay trusted, so there is no separate trusted segment.
- **Addressing.** An overlay's IPv4 comes from the environment's IPAM pool, or from a public block
  for `public`. Its IPv6 comes from the deployment's ULA `/48` or the public allocation.
- **First hop.** Every VTEP provides the first-hop address as an EVPN distributed anycast gateway
  (RFC 9135), so routing inside a VRF happens where the traffic enters.
- **Isolation.** Overlays are isolated from each other. Traffic between VRFs, and between an overlay
  and a zone, passes the gateway's policy.
- **One public network.** All of the platform's internet exposure collapses into a single `public`
  overlay that the gateways announce over BGP. Only the platform exposes services to the internet,
  and only through `public`: an internal or site network beside the platform runs no DMZ of its
  own. Lighting it needs the overlay service (#709) and gateway HA (#596,
  #710).

On a host, the physical trunk rides the OVS bridge **`br-fabric`**, which also holds the host's own
zone addresses as internal ports. Workload ports sit on a separate integration bridge, **`br-int`**,
which never carries the trunk.

### Overlay threat model

| Threat | Control | Status |
|--------|---------|--------|
| A rogue host joins the fabric VLAN and injects VXLAN or BGP | VTEP admission requires an attested IDevID; overlay traffic is IPsec-protected between VTEPs | #709 |
| A compromised workload sends tagged or spoofed frames into the underlay | Workload ports are on `br-int`, which never carries the trunk | Implemented (#708); per-port tag and source hygiene on `br-int` is #709 |
| A tenant reaches another tenant with overlapping addresses | Each tenant is its own VRF; only the gateway routes between VRFs | Tenant VRFs follow #709 |
| A host is used as a router between zones | Forwarding is off and the host firewall drops inter-interface traffic on every non-gateway host | Implemented (#708) |
| A zone is opened into the control plane by configuration | Paths into `control-plane` or `management` beyond the reference need an audited `privileged_access` override | Implemented (#708) |

## Switch port model

Each port class carries its own allowed VLAN list. **No port is trunked the whole block.** Every
platform port uses **MTU 9216**, so VXLAN encapsulation never fragments.

| Port class | Mode | Allowed VLANs | Notes |
|------------|------|---------------|-------|
| `gateway` | 802.1Q trunk (LACP/vPC when bonded) | x00, x01, and the zones the gateway routes: x04, x05, x06, x08 | The only class that carries `transit` |
| `hypervisor` (compute and control-plane nodes) | 802.1Q trunk | x01, x03–x08; **native = x05 `provisioning`** | The native VLAN lets a factory NIC PXE-boot into `provisioning` |
| `bmc` | access | x02 | The only class that carries `management` |
| `mgmt-uplink` | 802.1Q trunk | x02 | The one platform VLAN an external management firewall sees |
| `peer-link` (vPC/MLAG) | 802.1Q trunk | every underlay VLAN of the block | |

An owner-defined zone joins the `gateway` and/or `hypervisor` classes it names, and the peer-link.
The lists are derived from the zone set: a port is configured by its class, never by a VLAN list.

On a hypervisor, OVS takes the whole trunk on `br-fabric`. The host holds an address only on the
zones it uses (see [Host addressing](#host-addressing)). An enrolled node's port lifecycle is
driven by the platform: `provisioning` at enrollment, the zones of its role's port class once
attested, `quarantine` on violation, and the port administratively down when blocked. An operator
changing it by hand bypasses the enrollment state machine.

## Device lifecycle

```
Device connects ──► provisioning (x05, native VLAN): DHCP / PXE / DNS / ACME
        │           OS installed, IDevID issued
        ▼
Attested ──► the port carries its role's zones (port class gateway or hypervisor)
        │
        ├── compliance failure ──► quarantine (x04): auth + remediation only ──► re-attest
        └── severe violation ────► port DOWN: zero access, audited
```

A blocked device is not placed in a "blocked zone". Its port is administratively disabled
(`SetPortState(..., PortStateDown)` in OVS, `shutdown` on a switch port), so it gets no access at
all, not even ARP.

### Flow templates (OVS/OpenFlow)

The lifecycle zones are enforced per port from templates. OVS applies a port's
VLAN configuration only in its `NORMAL` action, so the flow tables see each
frame as received: an access port's frames, and a trunk's native-VLAN frames,
carry no VLAN header and are matched as untagged (`vlan_tci=0x0000/0x1fff`);
a trunk's tagged zones are matched with `dl_vlan=<vlan>`. Below, `<ingress>` is
one or the other.

```bash
# quarantine: authentication and remediation only
ovs-ofctl add-flow br-fabric "priority=900,in_port=<port>,<ingress>,dl_type=0x0806,actions=normal"
ovs-ofctl add-flow br-fabric "priority=850,in_port=<port>,<ingress>,udp,tp_src=68,tp_dst=67,actions=normal"
ovs-ofctl add-flow br-fabric "priority=800,in_port=<port>,<ingress>,udp,nw_dst=<dns_ip>,tp_dst=53,actions=normal"
ovs-ofctl add-flow br-fabric "priority=700,in_port=<port>,<ingress>,tcp,nw_dst=<remediation_ip>,tp_dst=443,actions=normal"
ovs-ofctl add-flow br-fabric "priority=100,in_port=<port>,<ingress>,actions=drop"

# provisioning (native on a hypervisor trunk: <ingress> = vlan_tci=0x0000/0x1fff)
ovs-ofctl add-flow br-fabric "priority=900,in_port=<port>,<ingress>,dl_type=0x0806,actions=normal"
ovs-ofctl add-flow br-fabric "priority=850,in_port=<port>,<ingress>,udp,tp_src=68,tp_dst=67,actions=normal"
ovs-ofctl add-flow br-fabric "priority=800,in_port=<port>,<ingress>,udp,tp_dst=53,actions=normal"
ovs-ofctl add-flow br-fabric "priority=750,in_port=<port>,<ingress>,udp,tp_dst=69,actions=normal"
ovs-ofctl add-flow br-fabric "priority=700,in_port=<port>,<ingress>,tcp,nw_dst=<acme_ip>,tp_dst=443,actions=normal"
ovs-ofctl add-flow br-fabric "priority=50,in_port=<port>,<ingress>,actions=drop"
```

## Management access

- **Hardware out-of-band.** The `management` VLAN carries **BMCs only**, on access ports. The
  platform never routes that VLAN. Only an external management firewall routes it, and only from
  admin networks and the admin VPN.
- **Admin VPN.** Administrators reach the control plane through an authenticated VPN on the
  gateway, into an admin network that policy limits to management endpoints. Workstations are never
  dual-homed onto a platform zone. The VPN uses **IPsec in FIPS builds**; WireGuard is available
  **only in non-FIPS builds**.

## Compliance

This section targets deployments that must meet FedRAMP, PCI DSS or HIPAA.

| Control | How the reference meets it |
|---------|----------------------------|
| Encryption in transit on the overlay | **IPsec on the OVS VXLAN tunnels**, keyed from the IDevID-derived certificates, using FIPS-validated cryptography (#709) |
| Encryption in transit on the underlay | Per protocol: libvirt live migration over TLS (`hypervisor`), NVMe/TCP with TLS (`storage`), QUIC for control-plane traffic (`control-plane`), and backups encrypted at source (`backup`) |
| Administrative access | IPsec admin VPN in FIPS builds. BMCs reachable only through the management firewall |
| Boundary protection (NIST SC-7, AC-4) | Default-deny between zones and overlays. The gateway is the only router between VRFs and to the outside. Paths into the control plane beyond the reference are audited |
| Separation of the platform from other networks | **Compliant deployments use dedicated platform switches.** A switch shared with another network puts that network in audit scope |

## Deployment topologies

Node roles:

- **Control plane:** platformd in server mode, running CA, ACME, IAM, KMS and DNS.
- **Gateway:** gatewayd, handling routing, NAT, BGP, firewall and overlay.
- **Compute:** platformd in client mode, running QEMU/KVM and Podman.

All three topologies use the same zones.

| Topology | Nodes | Zones in use | Ports |
|----------|-------|--------------|-------|
| **Standalone** | 1 box: control plane, gateway and compute | All zones on one host-local OVS bridge. `fabric`/`hypervisor` are local, and the overlay needs no second VTEP | One trunk (or none, for an isolated lab) |
| **Dedicated** | 1 control plane, 1 gateway, N compute | All zones. `transit` on the gateway only | Gateway trunk, hypervisor trunks for the control plane and compute, BMC access ports |
| **HA** | 3 control plane (Raft), 2 gateways, N compute | All zones. Gateway pair: VRRP on the zone VLANs, HA sync on `10.E.128.0/31`, anycast on overlays | As dedicated, on a vPC/MLAG switch pair |

For hardware, bootstrap and checklists per topology, see
[Deployment Reference](deployment-reference.md).

## Configuration

| Where | Key | What it sets |
|-------|-----|--------------|
| platformd and gatewayd | `sdn.environment` | `id` (_E_), `base` (IPv4 `/8`), `ula` (`/48`), `overrides` |
| platformd and gatewayd | `sdn.zones` | Built-in policy tuning and owner-defined zones |
| platformd | `sdn.fabric` | `switches`, `peers` (with `peer-link-ports`), `lags`, and `ports` with a `class` each |
| platformd | `sdn.ipam.pools` | Explicit pools beside the derived ones (for example a public block) |
| Every node | `network.role`, `network.ip-forward`, `network.platform-vrf` | Host addressing by role |
| Every node | `network.bonds[].vlans[].zone` | A host address on a zone; the VLAN is derived |
| `bootstrap.yaml` | `environment`, `zones`, `switch.port_assignments[].class` | The same plan for the bootstrap orchestrator's switch phase |

See [SDN configuration](../sdn/configuration.md) for every key, and the profile templates under
`configs/platform/templates/` for complete examples on block 4.

## Related documentation

- [Deployment Reference](deployment-reference.md): topologies, node roles, bootstrap
- [Gateway](../gateway/architecture.md): gateway services, HA, overlay status
- [Security Model](../security/architecture.md): trust boundaries and threat model
- [SDN](../sdn/README.md): bridges, ports, flows, port authentication
