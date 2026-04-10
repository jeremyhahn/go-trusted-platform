# Reference Network Architecture

This document defines the reference VLAN architecture for go-trusted-platform deployments. go-trusted-platform is a public cloud/hosting platform providing trusted computing services.

> **Important:** The reference architecture uses the 200-series VLAN range (200-219) to avoid conflicts with existing network infrastructure in customer environments. All VLAN numbers are fully configurable via platform configuration (see [Configuration](#configuration) section). The 50-series is reserved for shared management networks outside platform control.

> **Note:** Enterprise deployments with dedicated network engineering teams may customize this architecture to meet specific requirements. This reference design provides a solid foundation that can be extended as needed.

## Overview

The reference network architecture implements a zero-trust network model where every device must prove its identity before gaining network access. Network segmentation is enforced through VLANs managed by Open vSwitch (OVS) with OpenFlow rules controlling traffic flow.

**Goals:**

- **Security:** Isolate untrusted and compromised devices from production networks
- **Device Lifecycle:** Support the full provisioning-to-production device lifecycle
- **Compliance:** Meet requirements for HIPAA, FedRAMP, and PCI-DSS
- **Simplicity:** Use memorable VLAN numbers with clear semantic meaning

## Network Zones

The architecture defines three distinct network zones with strict isolation boundaries:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Network Zones                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────────────┐  ┌──────────────────────────┐                │
│  │   INFRASTRUCTURE         │  │        DMZ               │                │
│  │   (VLANs 200-209)        │  │    (VLANs 210-219)       │                │
│  │                          │  │                          │                │
│  │ Production workloads,    │  │  Public-facing services, │                │
│  │ provisioning, storage,   │  │  defense-in-depth with   │                │
│  │ quarantine               │  │  multi-tier architecture │                │
│  └────────┬─────────────────┘  └────────┬─────────────────┘                │
│           │                             │                                   │
│           └─────────────────┬───────────┘                                   │
│                             │                                               │
│                ┌────────────▼────────────┐                                  │
│                │     CLOUD TENANT        │                                  │
│                │    (VLANs 1000+)        │                                  │
│                │                         │                                  │
│                │  Multi-tenant workloads │                                  │
│                │  with full isolation    │                                  │
│                └─────────────────────────┘                                  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

| Zone | VLANs | Purpose | Compliance Control |
|------|-------|---------|-------------------|
| Infrastructure | 200-209 | Platform operations, workloads, provisioning | Management plane isolation (NIST SC-7) |
| DMZ | 210-219 | Public-facing services with defense-in-depth | Boundary protection (NIST SC-7) |
| Cloud Tenant | 1000+ | Multi-tenant workloads | Tenant isolation (NIST SC-4) |
| Management (shared) | 50 | Out-of-band IPMI/iLO (separate physical NICs) | Not platform-owned |

## Network Space

The reference architecture uses a single Class B private network for platform operations:

| Property | Value |
|----------|-------|
| Platform Network | 198.18.0.0/21 |
| Infrastructure Zone | 198.18.0.0/24 - 172.16.209.0/24 |
| DMZ Zone | 172.16.210.0/24 - 172.16.219.0/24 |
| Full Network | 172.16.0.0/16 |
| Usable Addresses | 65,534 |
| Address Range | 172.16.0.1 - 172.16.255.254 |

For larger deployments requiring cloud tenant isolation, additional /16 blocks (172.17.0.0/16, etc.) can be allocated.

### Point-to-Point Reserved (172.16.0.0/24)

The first /24 subnet is reserved for point-to-point links between network infrastructure devices.

| Purpose | Addressing |
|---------|------------|
| Router-to-router links | /31 subnets |
| Router-to-firewall links | /31 subnets |
| Switch uplinks | /31 subnets |
| Capacity | 128 point-to-point links |

## VLAN Scheme

### Zone 1: Infrastructure (VLANs 200-209)

Core platform operations, workloads, provisioning, and device lifecycle services.

| VLAN | Name | Subnet | Purpose | Access Policy |
|------|------|--------|---------|---------------|
| 200 | PRODUCTION | 198.18.0.0/24 | Production workloads | East-west traffic, full access per profile |
| 201 | PROVISIONING | 172.16.201.0/24 | PXE boot and enrollment | DHCP, TFTP, DNS, ACME |
| 202 | QUARANTINE | 172.16.202.0/24 | Compromised/untrusted hosts | Auth service, remediation only |
| 203 | STORAGE | 172.16.203.0/24 | Backup and storage traffic | iSCSI, NFS, backup agents |

### Zone 2: DMZ (VLANs 210-219)

Public-facing services with defense-in-depth architecture.

| VLAN | Name | Subnet | Purpose | Access Policy |
|------|------|--------|---------|---------------|
| 210 | DMZ_PUBLIC | 172.16.210.0/24 | Public-facing services | Internet ingress, DMZ_PRIVATE egress |
| 211 | DMZ_PRIVATE | 172.16.211.0/24 | DMZ backend services | DMZ_PUBLIC ingress, DMZ_DATA egress |
| 212 | DMZ_DATA | 172.16.212.0/24 | DMZ database tier | DMZ_PRIVATE ingress only |

### Zone 3: Cloud Tenant (VLANs 1000+)

Dynamic allocation for multi-tenant workloads.

| VLAN | Name | Subnet | Purpose | Access Policy |
|------|------|--------|---------|---------------|
| 1000+ | CLOUD_TENANT | 172.17.0.0/16+ | Multi-tenant workloads | Per-tenant policies |

### Shared VLANs (Not Platform-Owned)

| VLAN | Name | Purpose |
|------|------|---------|
| 50 | MANAGEMENT | IPMI/iLO out-of-band management on separate physical NICs |
| 10 | TRANSIT | Router transit links to upstream routers (BGP) |
| 1 | DEFAULT | IEEE 802.1Q default (catch-all for untagged, not platform-managed) |

### Unallocated (VLANs 23-49, 51-199, 220-999)

For future allocation and enterprise customization.

## VLAN Design Rationale

### VLAN 200 (Production)

Primary production VLAN for platform workloads:

- Production workloads receive assignments in this VLAN during normal operation
- East-west traffic within platform infrastructure
- Full access per device profile (can be further subdivided via ACLs)
- Devices transition here after successful enrollment and compliance

### VLAN 201 (Provisioning)

Controlled access for device enrollment:

- DHCP for IP address assignment
- TFTP for PXE boot firmware
- HTTP/HTTPS for OS installation
- DNS for name resolution
- ACME for certificate enrollment

Once a device completes enrollment and receives its IDevID certificate, it transitions to VLAN 200 (PRODUCTION).

### VLAN 202 (Quarantine)

Isolation VLAN for compromised or untrusted devices:

- Devices with compliance failures are moved here
- Minimal access: authentication service and remediation servers only
- Full traffic logging for forensic analysis
- Devices must re-enroll to exit quarantine

### VLAN 203 (Storage)

Dedicated network for backup and storage traffic:

- iSCSI, NFS, and backup agent traffic
- High-bandwidth requirements
- **Recommended:** Dedicated 10GbE+ NIC to avoid trunk saturation
- Security isolation of backup data streams

### VLANs 210-212 (DMZ)

Three-tier DMZ architecture for defense in depth:

- **DMZ_PUBLIC (210):** Internet-facing services (load balancers, web servers, WAF)
- **DMZ_PRIVATE (211):** Backend services supporting frontend (app servers, API gateways)
- **DMZ_DATA (212):** DMZ database tier (isolated from production databases)

Traffic flow: Internet → DMZ_PUBLIC → DMZ_PRIVATE → DMZ_DATA

No direct path from internet to production networks.

### VLAN 50 (Management - Shared, Not Platform-Owned)

Dedicated out-of-band management network on separate physical NICs:

- IPMI/iLO/iDRAC interfaces
- Console servers and KVM switches
- Network device management interfaces
- Monitoring infrastructure (Prometheus, Grafana, log aggregators)
- Must never route to/from production VLANs
- Typically uses dedicated NIC 0 (separate from production NIC 1)

### VLANs 1000+ (Cloud Tenants)

Dynamic allocation for cloud workloads and multi-tenant isolation:

- Each tenant receives dedicated VLAN(s)
- Complete network isolation between tenants
- Per-tenant ACL policies
- Approximately 3,000 tenant VLANs available (1000-4094)

## Physical Interface Recommendations

For production deployments, consider dedicated physical interfaces:

```
┌─────────────────────────────────────────────────────────────────┐
│                        Server/Host                              │
├─────────────────────────────────────────────────────────────────┤
│  NIC 0 (1+GbE)     │  NIC 1 (10+GbE)    │  NIC 2-3 (10+GbE)     │
│  Management VLAN 50│  Production VLANs  │  Storage VLAN 203     │
│  (IPMI, monitoring)│  (trunked:         │  (dedicated, high BW) │
│                    │   200-212)         │                       │
└─────────────────────────────────────────────────────────────────┘
```

| Interface | VLANs | Purpose |
|-----------|-------|---------|
| NIC 0 | VLAN 50 only | Out-of-band management (separate network) |
| NIC 1 | VLAN 200-212 | Production traffic (trunk: infrastructure + DMZ) |
| NIC 2-3 | VLAN 203 only | Storage/backup (bonded, dedicated high BW) |

**Why separate management interface?**

VLAN 50 is shared infrastructure not owned by the platform. It must be isolated on a separate physical NIC to prevent platform issues from impacting management access to IPMI/iLO.

**Why dedicated storage interface?**

VLANs provide security isolation, not bandwidth isolation. All VLANs on a trunk share the same physical pipe. Backup traffic can saturate the trunk, impacting production traffic during incidents.

## Blocked Devices

Devices requiring complete network isolation (severe policy violations, active threats) are not placed in a "blocked VLAN." Instead, the OVS port is administratively disabled:

```go
// Block a port completely
flowController.SetPortState(ctx, portName, ovs.PortStateDown)

// Restore a port
flowController.SetPortState(ctx, portName, ovs.PortStateUp)
```

**Benefits:**

- Zero network access (not even ARP)
- No possibility of lateral movement
- No traffic processing overhead
- Clear operational state (port up/down)
- Simple to audit and verify

## Device Lifecycle Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Device Lifecycle                                  │
└─────────────────────────────────────────────────────────────────────────────┘

   ┌──────────┐
   │  Device  │
   │ Connects │
   └────┬─────┘
        │ Untagged traffic
        ▼
┌───────────────────┐
│  VLAN 1           │
│  (DEFAULT)        │ Catch-all for unknown devices
│                   │
│  Logged and       │
│  monitored        │
└────────┬──────────┘
         │ Classified for provisioning
         ▼
┌───────────────────┐
│  VLAN 201         │
│  (PROVISIONING)   │
│                   │
│  Access to:       │
│  - DHCP/TFTP      │
│  - DNS            │
│  - HTTP/HTTPS     │
│  - ACME server    │
└────────┬──────────┘
         │ OS installed, ACME enrolled
         ▼
┌───────────────────┐          ┌────────────────┐
│  Production VLAN  │          │  Minor         │
│  (per profile)    │◄─────────│  Violation     │
│                   │          │  Remediated    │
│  - VLAN 200       │          └────────────────┘
│  - VLAN 210-212   │                 ▲
│  - VLAN 1000+     │                 │
│                   │          ┌──────┴─────────┐
│  Full access per  │          │  VLAN 202      │
│  device profile   ├─────────►│  (QUARANTINE)  │
│  ACLs             │          │                │
└────────┬──────────┘          │  Limited:      │
         │                     │  - Auth svc    │
         │ Severe violation    │  - Remediation │
         ▼                     └────────────────┘
┌───────────────────┐          ┌────────────────┐
│  Port DOWN        │          │  Remediated    │
│  (BLOCKED)        │─────────►│  and verified  │─────► Production VLAN
│                   │          └────────────────┘
│  Zero network     │
│  access           │
└───────────────────┘
```

## Flow Rules

### Quarantine Flows (VLAN 202)

The quarantine VLAN allows minimal connectivity for authentication and remediation.

```bash
# Priority 900: Allow ARP for address resolution
ovs-ofctl add-flow br0 "priority=900,in_port=<port>,dl_vlan=202,dl_type=0x0806,actions=normal"

# Priority 850: Allow DHCP for IP assignment
ovs-ofctl add-flow br0 "priority=850,in_port=<port>,dl_vlan=202,udp,tp_src=68,tp_dst=67,actions=normal"
ovs-ofctl add-flow br0 "priority=850,dl_vlan=202,udp,tp_src=67,tp_dst=68,actions=normal"

# Priority 800: Allow DNS to internal server only
ovs-ofctl add-flow br0 "priority=800,in_port=<port>,dl_vlan=202,udp,nw_dst=<dns_ip>,tp_dst=53,actions=normal"

# Priority 700: Allow HTTPS to remediation servers
ovs-ofctl add-flow br0 "priority=700,in_port=<port>,dl_vlan=202,tcp,nw_dst=<remediation_ip>,tp_dst=443,actions=normal"

# Priority 100: Drop everything else (default deny)
ovs-ofctl add-flow br0 "priority=100,in_port=<port>,dl_vlan=202,actions=drop"
```

### Provisioning Flows (VLAN 201)

The provisioning VLAN enables PXE boot and certificate enrollment.

```bash
# Priority 900: Allow ARP
ovs-ofctl add-flow br0 "priority=900,in_port=<port>,dl_vlan=201,dl_type=0x0806,actions=normal"

# Priority 850: Allow DHCP
ovs-ofctl add-flow br0 "priority=850,in_port=<port>,dl_vlan=201,udp,tp_src=68,tp_dst=67,actions=normal"
ovs-ofctl add-flow br0 "priority=850,dl_vlan=201,udp,tp_src=67,tp_dst=68,actions=normal"

# Priority 800: Allow DNS (UDP and TCP)
ovs-ofctl add-flow br0 "priority=800,in_port=<port>,dl_vlan=201,udp,tp_dst=53,actions=normal"
ovs-ofctl add-flow br0 "priority=800,in_port=<port>,dl_vlan=201,tcp,tp_dst=53,actions=normal"

# Priority 750: Allow TFTP for PXE boot
ovs-ofctl add-flow br0 "priority=750,in_port=<port>,dl_vlan=201,udp,tp_dst=69,actions=normal"

# Priority 700: Allow HTTPS to ACME server (443, 8443, 9443)
ovs-ofctl add-flow br0 "priority=700,in_port=<port>,dl_vlan=201,tcp,nw_dst=<acme_ip>,tp_dst=443,actions=normal"
ovs-ofctl add-flow br0 "priority=700,in_port=<port>,dl_vlan=201,tcp,nw_dst=<acme_ip>,tp_dst=8443,actions=normal"
ovs-ofctl add-flow br0 "priority=700,in_port=<port>,dl_vlan=201,tcp,nw_dst=<acme_ip>,tp_dst=9443,actions=normal"

# Priority 650: Allow HTTP/HTTPS for package repositories
ovs-ofctl add-flow br0 "priority=650,in_port=<port>,dl_vlan=201,tcp,tp_dst=80,actions=normal"
ovs-ofctl add-flow br0 "priority=650,in_port=<port>,dl_vlan=201,tcp,tp_dst=443,actions=normal"

# Priority 50: Drop everything else (default deny)
ovs-ofctl add-flow br0 "priority=50,in_port=<port>,dl_vlan=201,actions=drop"
```

### Production Flows

Production VLANs apply device-profile-specific ACLs.

```bash
# Example: Production workload (VLAN 200) with profile-specific access
ovs-ofctl add-flow br0 "priority=100,in_port=<port>,dl_vlan=200,actions=normal"

# Example: DMZ backend (VLAN 211) ingress from frontend only
ovs-ofctl add-flow br0 "priority=200,in_port=<port>,dl_vlan=211,ip,nw_src=172.16.210.0/24,actions=normal"
ovs-ofctl add-flow br0 "priority=100,in_port=<port>,dl_vlan=211,actions=drop"

# Example: DMZ database (VLAN 212) ingress from backend only
ovs-ofctl add-flow br0 "priority=200,in_port=<port>,dl_vlan=212,ip,nw_src=172.16.211.0/24,actions=normal"
ovs-ofctl add-flow br0 "priority=100,in_port=<port>,dl_vlan=212,actions=drop"

# Example: DMZ public (VLAN 210) with internet ingress
ovs-ofctl add-flow br0 "priority=100,in_port=<port>,dl_vlan=210,actions=normal"
```

## Configuration

VLAN assignments are fully configurable. The reference architecture defines default values that can be overridden via platform configuration or device profiles.

### Platform Configuration (YAML)

Configure VLAN assignments in the platform configuration file:

```yaml
# /etc/trusted-platform/config.yaml
sdn:
  enabled: true
  bridge_name: "br0"

  # VLAN assignments (defaults shown - override as needed)
  vlans:
    # Zone 1: Infrastructure
    production: 200
    provisioning: 201
    quarantine: 202
    storage: 203

    # Zone 2: DMZ
    dmz_public: 210
    dmz_private: 211
    dmz_data: 212

    # Zone 3: Cloud Tenant
    cloud_tenant_base: 1000

  # Subnet assignments (must match VLAN assignments)
  subnets:
    production: "198.18.0.0/24"
    provisioning: "172.16.201.0/24"
    quarantine: "172.16.202.0/24"
    storage: "172.16.203.0/24"
    dmz_public: "172.16.210.0/24"
    dmz_private: "172.16.211.0/24"
    dmz_data: "172.16.212.0/24"

  # Service IPs within VLANs
  services:
    provisioning:
      acme_server: "172.16.201.10"
      dns_server: "172.16.201.1"
      dhcp_range: "172.16.201.100-172.16.201.200"
    quarantine:
      remediation_server: "172.16.202.10"
      dns_server: "172.16.202.1"
```

### Device Profile VLAN Assignment

Device profiles define which production VLAN a device is assigned to after enrollment:

```yaml
# Device profile example
device_profiles:
  - name: "workload-default"
    role: "server"
    production_vlan: 200       # PRODUCTION VLAN
    network:
      use_dhcp: true
      gateway: "198.18.0.1"
      dns: ["198.18.0.1"]

  - name: "dmz-frontend"
    role: "web-server"
    production_vlan: 210       # DMZ_PUBLIC VLAN
    network:
      use_dhcp: true
      gateway: "172.16.210.1"
      dns: ["172.16.210.1"]
    acls:
      - name: "allow-internet"
        match: { src: "0.0.0.0/0" }
        action: "permit"
      - name: "allow-backend"
        match: { dst: "172.16.211.0/24" }
        action: "permit"

  - name: "dmz-backend"
    role: "app-server"
    production_vlan: 211       # DMZ_PRIVATE VLAN
    network:
      use_dhcp: true
      gateway: "172.16.211.1"
      dns: ["172.16.211.1"]
    acls:
      - name: "allow-frontend"
        match: { src: "172.16.210.0/24" }
        action: "permit"
      - name: "allow-database"
        match: { dst: "172.16.212.0/24" }
        action: "permit"

  - name: "dmz-database"
    role: "database"
    production_vlan: 212       # DMZ_DATA VLAN
    network:
      use_dhcp: true
      gateway: "172.16.212.1"
      dns: ["172.16.212.1"]
    acls:
      - name: "backend-only"
        match: { src: "172.16.211.0/24" }
        action: "permit"
      - name: "deny-all"
        action: "deny"
```

### Default Constants

Default VLAN assignments are defined as constants for use when configuration is not provided:

```go
// pkg/sdn/vlan/defaults.go
const (
    // Zone 1: Infrastructure (defaults)
    DefaultProductionVLAN   = uint16(200)
    DefaultProvisioningVLAN = uint16(201)
    DefaultQuarantineVLAN   = uint16(202)
    DefaultStorageVLAN      = uint16(203)

    // Zone 2: DMZ (defaults)
    DefaultDMZPublicVLAN  = uint16(210)
    DefaultDMZPrivateVLAN = uint16(211)
    DefaultDMZDataVLAN    = uint16(212)

    // Zone 3: Cloud Tenant (defaults)
    DefaultCloudTenantBaseVLAN = uint16(1000)

    // Shared VLANs (not platform-owned)
    DefaultManagementVLAN = uint16(50)   // IPMI/iLO on separate physical NIC

    // IEEE 802.1Q defaults and limits (not configurable)
    DefaultVLAN = uint16(1)              // IEEE 802.1Q default VLAN
    MinVLANID   = uint16(1)
    MaxVLANID   = uint16(4094)
)
```

### Service Configuration (Go)

Services read VLAN assignments from the platform configuration:

```go
// Load from platform config (uses defaults if not specified)
config := &pxe.ServiceConfig{
    BridgeName:       platformConfig.SDN.BridgeName,
    ProductionVLAN:   platformConfig.SDN.VLANs.Production,      // 200
    ProvisioningVLAN: platformConfig.SDN.VLANs.Provisioning,    // 201
    QuarantineVLAN:   platformConfig.SDN.VLANs.Quarantine,      // 202
    StorageVLAN:      platformConfig.SDN.VLANs.Storage,         // 203
    ACMEServerIPs:    platformConfig.SDN.Services.Provisioning.ACMEServer,
    DNSServerIPs:     platformConfig.SDN.Services.Provisioning.DNSServer,
}
```

### Environment Variable Overrides

For quick testing or container deployments, VLAN assignments can be overridden via environment variables:

```bash
# Override specific VLANs (using 200-series as base)
export SDN_VLAN_PRODUCTION=200
export SDN_VLAN_PROVISIONING=201
export SDN_VLAN_QUARANTINE=202
export SDN_VLAN_STORAGE=203

# Override subnets
export SDN_SUBNET_PRODUCTION="198.18.0.0/24"
export SDN_SUBNET_PROVISIONING="172.16.201.0/24"
export SDN_SUBNET_QUARANTINE="172.16.202.0/24"
export SDN_SUBNET_STORAGE="172.16.203.0/24"
```

### Configuration Precedence

VLAN assignments are resolved in this order (highest priority first):

1. **Device Profile** - Per-device production VLAN assignment
2. **Environment Variables** - Runtime overrides
3. **Platform Config YAML** - Deployment-specific configuration
4. **Default Constants** - Reference architecture defaults

## Future Considerations

### IPv6 Addressing

The current architecture focuses on IPv4. IPv6 support will require:

- Unique Local Addresses (ULA) for internal networks: fd00::/8
- Global unicast addresses for internet-facing services
- Dual-stack flow rules for transitional deployments
- Router Advertisement (RA) and DHCPv6 in provisioning VLAN

### Cloud Tenant Scaling

For deployments requiring more than 3,000 tenant VLANs:

- VXLAN overlay networks (24-bit VNI = 16 million segments)
- Per-tenant routing domains
- Integration with cloud SDN controllers (OpenStack Neutron, Kubernetes CNI)

### External SDN Controller Integration

The reference architecture can integrate with external SDN controllers:

- ONOS for carrier-grade deployments
- OpenDaylight for enterprise SDN
- VMware NSX for hybrid cloud
- Kubernetes network policies for container workloads

## Related Documentation

- [System Architecture](README.md) - Overall platform architecture
- [Security Model](security-model.md) - Security boundaries and threat model
- [SDN Package](../sdn/) - Software-defined networking implementation
- [PXE Provisioning](../compute/pxe/) - Device provisioning service
