# Reference Network Architecture

This is the reference network for go-trusted-platform: how a deployment lays out its VLANs, subnets,
switch ports and overlays. The same model applies to every topology, from a single box to an HA
cluster.

> **Status.** The design was approved by the owner on 2026-09-26. The code is being brought in line
> with it: the zone model and addressing in #708, the EVPN overlay service in #709, and gateway
> HA in #596 and #710. When a component's documentation describes what the code does *today*,
> it says so and links the issue.

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
3. **The switch is pure L2.** It has no SVIs, no routing and no ACLs. Gateways route and enforce
   policy. The switch only moves frames on the VLANs each port class is allowed to carry.
4. **One predictable numbering scheme.** A VLAN ID tells you its environment and zone, and it maps
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
The platform uses VLANs 200–4094. VLANs 1–199 are left to whatever site network sits beside the
platform. Each block is self-contained: the platform never trunks a VLAN from one environment into
another.

## Zones: the offsets inside a block

Every environment has the same zones, at the same offsets. The examples use block 4.

| Offset | Zone | Example | Purpose |
|:------:|------|--------:|---------|
| x00 | `transit` | 400 | Gateway edge: upstream handoff and BGP peering |
| x01 | `fabric` | 401 | VXLAN underlay: VTEPs and EVPN between gateways and hypervisors |
| x02 | `management` | 402 | Out-of-band: BMC/IPMI and consoles |
| x03 | `hypervisor` | 403 | Live migration between hypervisors |
| x04 | `quarantine` | 404 | Non-compliant or failed nodes: authentication and remediation only |
| x05 | `provisioning` | 405 | Onboarding: DHCP, PXE/iPXE, TFTP, DNS, ACME enrollment |
| x06 | `control-plane` | 406 | Control-plane nodes: CA, ACME, IAM, KMS, DNS, Raft |
| x07 | `storage` | 407 | Block and object storage traffic (for example NVMe/TCP) |
| x08 | `backup` | 408 | Backup traffic to backup targets |
| x09–x99 | reserved | 409–499 | Future zones; unused |

`public`, tenant networks and every workload network are **overlays**, not zones on this list (see
[Overlay networks](#overlay-networks)). The old tenant VLAN range (1000+) no longer exists.

### Routing and inter-zone policy

The default between zones is **deny**. The gateway is the only router on the platform tier.

> **Proposal:** the Routed and Allowed columns below are derived from the design by the Software
> Department. The owner has not ruled on them item by item; #708 confirms them when it implements the
> policy.

| Zone | Routed? | Allowed |
|------|---------|---------|
| `transit` | By the gateway, as its upstream edge | Upstream and peering traffic, and gateway-to-gateway traffic in a pair. Nothing else attaches |
| `fabric` | No (single L2 segment) | VXLAN between VTEPs, IPsec-protected (see [Compliance](#compliance)) |
| `management` | Never by the platform. Only an external management firewall routes it | Admin networks and the admin VPN to BMCs. Never reaches another zone |
| `hypervisor` | No | Live migration between hypervisors (TLS) |
| `quarantine` | By the gateway | The control plane's authentication and remediation endpoints only |
| `provisioning` | By the gateway | The control plane's enrollment services (DHCP, PXE/TFTP, DNS, ACME) only |
| `control-plane` | By the gateway | Control-plane APIs to enrolled nodes and overlays on declared service paths. Admin access through the VPN |
| `storage` | No | Storage protocols between storage clients and targets (TLS) |
| `backup` | By the gateway, to declared backup targets only | Backup streams, encrypted at source |

## Addressing

### IPv4

VLAN _N_ maps to the subnet **`10.(N ÷ 100).(N mod 100).0/24`**. The `10.0.0.0/8` base is
configurable.

Each environment owns the `/16` `10.E.0.0/16`, split in half:

| Range | Use |
|-------|-----|
| `10.E.0.0/17` | **VLAN-mapped underlay.** VLAN _E·100+n_ is `10.E.n.0/24` |
| `10.E.128.0/17` | **IPAM pool.** Overlay networks, loopbacks, and tunnel point-to-point links |

Within a zone subnet, the reference hosts are:

- `.1`: the gateway (a VRRP address when there is a gateway pair)
- `.2` and `.3`: the gateway nodes
- `.10`–`.19`: control-plane nodes
- `.50`–`.254`: DHCP, where a zone serves it

### IPv6

Each deployment takes one **ULA `/48`** (RFC 4193, random global ID). The subnet ID is the VLAN
digits, so VLAN 406 in `fd12:3456:789a::/48` is `fd12:3456:789a:406::/64`. Public IPv6 comes from
the operator's own allocation, for example a provider-independent `/36`. It lives on overlays and is
announced by the gateways.

### VNIs

An overlay network's VNI is **`E·100000 + n`**. Environment 4 uses VNIs 400001–499999, so the VNI
also names the environment it belongs to.

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

## Overlay networks

Every network the SDN creates is an **EVPN/VXLAN overlay**. That includes the `public` network,
tenant networks and workload networks.

- **Transport.** VTEPs sit on the gateways and hypervisors, on the environment's `fabric` VLAN.
  EVPN runs over BGP between them.
- **Admission.** A VTEP joins only after it has attested with a valid IDevID. That identity is what
  makes an overlay trusted, so there is no separate trusted segment.
- **Addressing.** An overlay's IPv4 comes from the environment's IPAM pool, or from a public block
  for `public`. Its IPv6 comes from the deployment's ULA `/48` or the public allocation.
- **First hop.** The gateways provide the first-hop address as an EVPN distributed anycast gateway
  (RFC 9135), so every gateway answers locally.
- **Isolation.** Overlays are isolated from each other. Traffic between them, and between an overlay
  and a zone, passes the gateway's policy.
- **Public exposure.** A public block is an overlay the gateway announces over BGP. Lighting it needs
  the overlay service (#709) and gateway HA (#596, #710).

## Switch port model

Each port class carries its own allowed VLAN list. **No port is trunked the whole block.** Every
platform port uses **MTU 9216**, so VXLAN encapsulation never fragments.

| Port class | Mode | Allowed VLANs | Notes |
|------------|------|---------------|-------|
| Gateway | 802.1Q trunk (LACP/vPC when bonded) | x00, x01, and the zones the gateway routes: x04, x05, x06, x08 | The only class that carries `transit` |
| Hypervisor (compute and control-plane nodes) | 802.1Q trunk | x01, x03–x08; **native = x05 `provisioning`** | The native VLAN lets a factory NIC PXE-boot into `provisioning` |
| BMC | access | x02 | The only class that carries `management` |
| Management firewall uplink | 802.1Q trunk | x02 | The one platform VLAN an external firewall sees |
| Inter-switch (vPC/MLAG peer-link) | 802.1Q trunk | the block's underlay VLANs | |

> **Proposal:** the gateway VLAN list, the firewall uplink row and the inter-switch row are derived
> from the design, not stated by it. Confirm them with #708.

On a hypervisor, OVS takes the whole trunk. The host holds an address only on the zones it uses
itself: its VTEP on `fabric`, migration on `hypervisor`, and a storage client on `storage`. It has
**no IP on the VLANs it passes through** to guests. An enrolled node's port lifecycle is driven by
the platform: `provisioning` at enrollment, the node's zones once attested, `quarantine` on
violation, and the port administratively down when blocked. An operator changing it by hand
bypasses the enrollment state machine.

## Device lifecycle

```
Device connects ──► provisioning (x05, native VLAN): DHCP / PXE / DNS / ACME
        │           OS installed, IDevID issued
        ▼
Attested ──► admitted to the fabric and its overlays; the port carries its zones
        │
        ├── compliance failure ──► quarantine (x04): auth + remediation only ──► re-attest
        └── severe violation ────► port DOWN: zero access, audited
```

A blocked device is not placed in a "blocked zone". Its OVS port is administratively disabled
(`SetPortState(..., PortStateDown)`), so it gets no access at all, not even ARP.

### Flow templates (OVS/OpenFlow)

The lifecycle zones are enforced per port from templates. `<vlan>` is the environment's zone VLAN.

```bash
# quarantine: authentication and remediation only
ovs-ofctl add-flow br0 "priority=900,in_port=<port>,dl_vlan=<quarantine>,dl_type=0x0806,actions=normal"
ovs-ofctl add-flow br0 "priority=850,in_port=<port>,dl_vlan=<quarantine>,udp,tp_src=68,tp_dst=67,actions=normal"
ovs-ofctl add-flow br0 "priority=800,in_port=<port>,dl_vlan=<quarantine>,udp,nw_dst=<dns_ip>,tp_dst=53,actions=normal"
ovs-ofctl add-flow br0 "priority=700,in_port=<port>,dl_vlan=<quarantine>,tcp,nw_dst=<remediation_ip>,tp_dst=443,actions=normal"
ovs-ofctl add-flow br0 "priority=100,in_port=<port>,dl_vlan=<quarantine>,actions=drop"

# provisioning: DHCP, DNS, TFTP, ACME
ovs-ofctl add-flow br0 "priority=900,in_port=<port>,dl_vlan=<provisioning>,dl_type=0x0806,actions=normal"
ovs-ofctl add-flow br0 "priority=850,in_port=<port>,dl_vlan=<provisioning>,udp,tp_src=68,tp_dst=67,actions=normal"
ovs-ofctl add-flow br0 "priority=800,in_port=<port>,dl_vlan=<provisioning>,udp,tp_dst=53,actions=normal"
ovs-ofctl add-flow br0 "priority=750,in_port=<port>,dl_vlan=<provisioning>,udp,tp_dst=69,actions=normal"
ovs-ofctl add-flow br0 "priority=700,in_port=<port>,dl_vlan=<provisioning>,tcp,nw_dst=<acme_ip>,tp_dst=443,actions=normal"
ovs-ofctl add-flow br0 "priority=50,in_port=<port>,dl_vlan=<provisioning>,actions=drop"
```

## Management access

- **Hardware out-of-band.** BMCs sit on the environment's `management` VLAN, on access ports. The
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
| Encryption in transit on the overlay | **IPsec on the OVS VXLAN tunnels**, keyed from the IDevID-derived certificates, using FIPS-validated cryptography |
| Encryption in transit on the underlay | Per protocol: libvirt live migration over TLS (`hypervisor`), NVMe/TCP with TLS (`storage`), QUIC for control-plane traffic (`control-plane`), and backups encrypted at source (`backup`) |
| Administrative access | IPsec admin VPN in FIPS builds. BMCs reachable only through the management firewall |
| Boundary protection (NIST SC-7, AC-4) | Default-deny between zones and overlays. The gateway is the only router |
| Separation of the platform from other networks | **Compliant deployments use dedicated platform switches.** A switch shared with another network puts that network in audit scope |

## Deployment topologies

Node roles:

- **Control plane:** platformd in server mode, running CA, ACME, IAM, KMS and DNS.
- **Gateway:** gatewayd, handling routing, NAT, BGP, firewall and overlay.
- **Compute:** platformd in client mode, running QEMU/KVM and Podman.

All three topologies use the same zones.

| Topology | Nodes | Zones in use | Ports |
|----------|-------|--------------|-------|
| **Standalone** | 1 box: control plane, gateway and compute | All zones on one OVS bridge. `fabric`/`hypervisor` are local, and the overlay needs no second VTEP | One trunk (or none, for an isolated lab) |
| **Dedicated** | 1 control plane, 1 gateway, N compute | All zones. `transit` on the gateway only | Gateway trunk, hypervisor trunks for the control plane and compute, BMC access ports |
| **HA** | 3 control plane (Raft), 2 gateways, N compute | All zones. Gateway pair: VRRP on the zone VLANs, anycast on overlays | As dedicated, on a vPC/MLAG switch pair |

For hardware, bootstrap and checklists per topology, see
[Deployment Reference](deployment-reference.md).

## Configuration

The configuration schema for environments, the address base and port classes is defined in #708.
Until it lands, [SDN configuration](../sdn/configuration.md) documents what the code accepts today.
Today's code uses zone `trusted` and fixed VLAN defaults.

## Related documentation

- [Deployment Reference](deployment-reference.md): topologies, node roles, bootstrap
- [Gateway](../gateway/architecture.md): gateway services, HA, overlay status
- [Security Model](security-model.md): trust boundaries and threat model
- [SDN](../sdn/README.md): bridges, ports, flows, port authentication

