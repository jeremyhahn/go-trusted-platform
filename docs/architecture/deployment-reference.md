# Deployment Reference Architecture

This document defines how to physically deploy the go-trusted-platform across different scales and environments. It complements the existing architecture docs which describe the platform's design (see [reference.md](reference.md), [reference-network.md](reference-network.md), [binary-separation.md](binary-separation.md), and [platform-modes.md](platform-modes.md)).

This guide covers:
- Topology patterns for different deployment sizes
- Node roles and hardware requirements
- Network layout and infrastructure
- Bootstrap scenarios
- Hardware recommendations for each tier
- Security tiers based on TPM availability

---

## Deployment Topology Patterns

### 1. Single-Node Deployment

**Use case:** Development, testing, proof-of-concept, edge deployments.

Everything runs on a single box in combined mode (control plane + gateway + worker).

```
┌─────────────────────────────────┐
│  Single Combined Node           │
│  (Control + Gateway + Worker)   │
│                                 │
│  • platformd (server mode)      │
│  • All services in-process      │
│  • Local pebble storage         │
│  • REST/gRPC/QUIC/Unix APIs     │
│  • 1x NIC (internal network)    │
└────────────┬────────────────────┘
             │
        ┌────┴────┐
        │          │
    ┌───▼──┐  ┌───▼──┐
    │Device│  │Device│
    │  1   │  │  2   │
    └──────┘  └──────┘
```

**Hardware Requirements:**
- 1x server with 8GB+ RAM
- 128GB+ storage (SSD preferred)
- TPM 2.0 (hardware or software vTPM)
- Network connectivity (1x NIC for bootstrap)

**Installation:**
- Boot from custom USB ISO with Secure Boot keys
- Run `platformctl firstboot` to seal LUKS key to TPM
- Ready for enrollment/management via CLI or REST API

---

### 2. Three-Node Deployment (Non-Clustered, Recommended)

**Use case:** Production starting point, small enterprises, branch offices.

Recommended production baseline: 1 control-plane node (standalone, pebble storage) + 1 gateway + 1 compute worker. Gateway and compute are CLIENT configs that auto-enroll with the control-plane CA via ACME.

```
                    Internet
                       │
                  Core Router
                  (BGP, NAT)
                       │
                  ┌────┴────┐
                  │  Switch  │
                  └────┬────┘
         ┌─────────────┼─────────────┐
         │             │             │
    ┌────▼────┐  ┌─────▼─────┐  ┌───▼──────┐
    │  gw-01  │  │   cp-01   │  │compute-01│
    │ Gateway │  │  Control  │  │  Worker  │
    │         │  │  Plane    │  │          │
    │ DHCP    │  │ CA/ACME   │  │ QEMU/KVM │
    │ iPXE    │  │ DNS       │  │ Podman   │
    │ BGP     │  │ IAM/KMS   │  │          │
    │ OVS     │  │ QuicBaaS  │  │          │
    └─────────┘  └───────────┘  └──────────┘
     (CLIENT)     (SERVER)       (CLIENT)
```

**Hardware Requirements:**
- Control Plane (cp-01): 4 CPU, 16GB RAM, 256GB SSD, TPM 2.0
- Gateway (gw-01): 4 CPU, 8GB RAM, 128GB SSD, TPM 2.0, dual 1GbE NICs
- Compute (compute-01): 4 CPU, 16GB+ RAM, 256GB+ SSD, TPM 2.0

**Architecture:**
- No Raft consensus — standalone control plane with local pebble storage
- Gateway and compute are CLIENT mode — auto-enroll with CP's ACME server
- Control plane runs CA, ACME, DNS (authoritative), IAM, KMS, QuicBaaS
- Gateway runs DHCP, iPXE, BGP, OVS, DNS (forwarding to CP)
- Compute runs QEMU/KVM for VMs and Podman (embedded) for containers

**Bootstrap:**
```
platformctl bootstrap run --config deployments/three-node/bootstrap.yaml
```

---

### 3. High-Availability Cluster

**Use case:** Production workloads requiring fault tolerance and redundancy.

3 control-plane nodes (Raft consensus) + 2 gateway nodes (HA pair) + N compute workers. Supports loss of 1 CP and 1 GW while maintaining service.

```
                    Internet
              ┌────────┴────────┐
         Core Router A     Core Router B
              │                 │
              └────────┬────────┘
                  Core Switch
                  (vPC pair)
         ┌─────────┬───┴───┬─────────┐
         │         │       │         │
    ┌────▼───┐┌────▼───┐   │    ┌────▼───┐
    │  gw-01 ││  gw-02 │   │    │compute │
    │Gateway ││Gateway │   │    │nodes   │
    │(HA)    ││(HA)    │   │    │(N)     │
    └────────┘└────────┘   │    └────────┘
                      ┌────▼────────────┐
                      │  Control Plane  │
                      │  cp-01 ── cp-02 │
                      │     \  cp-03    │
                      │   (Raft cluster)│
                      └─────────────────┘
```

**Hardware Requirements:**
- Control Plane (3 nodes): 4 CPU, 16GB RAM, 256GB SSD, TPM 2.0 each
- Gateway (2 nodes): 4 CPU, 8GB RAM, 128GB SSD, TPM 2.0, dual 1GbE NICs each
- Compute (N nodes): 4 CPU, 16GB+ RAM, 256GB+ SSD, TPM 2.0 each

**Architecture:**
- 3 CP nodes form Raft consensus for replicated CA, IAM, KMS, DNS (authoritative)
- QuicBaaS with Raft-backed storage for distributed data
- 2 GW nodes in active-active or active-passive HA configuration
- Gateways provide DHCP, iPXE, BGP, OVS, DNS (forwarding to CP nodes)
- N compute workers auto-enroll with CP's ACME server
- Can sustain failure of 1 CP node (maintains 2/3 quorum) and 1 GW node

**Bootstrap:**
```
platformctl bootstrap run --config deployments/ha-cluster/bootstrap.yaml
```

---

## Node Roles

| Role | Binary | Config Mode | Services | Min Hardware |
|------|--------|-------------|----------|-------------|
| **Control Plane** | platformd | Server | CA, ACME, IAM, KMS, DNS (authoritative), QuicBaaS | 4 CPU, 16GB RAM, 256GB SSD, TPM 2.0 |
| **Gateway** | platformd | Client | DHCP, iPXE, TFTP, DNS (forwarding), BGP, OVS, NAT | 4 CPU, 8GB RAM, 128GB SSD, TPM 2.0, 2+ NICs |
| **Compute Worker** | platformd | Client | QEMU/KVM, Podman (embedded), workloads | 4 CPU, 16GB+ RAM, 256GB+ SSD, TPM 2.0 |

### Control Plane Nodes

- Run in **server mode** with optional Raft consensus (single-node or clustered)
- Host CA with ACME server, IAM, KMS, DNS (authoritative), QuicBaaS
- API endpoints (REST, gRPC, QUIC, MCP, Unix) for management and client enrollment
- In 3-node deployment: standalone with local pebble storage
- In HA cluster: Raft-backed QuicBaaS with replicated state (tolerate 1 node failure with 3-node cluster)
- Never host application workloads directly
- Typically on VLAN 201 (provisioning) or VLAN 50 (management)

### Gateway Nodes

- Run in **client mode** — auto-enroll with control-plane CA via custom ACME extensions (enroll-01, device-attest-01)
- Bridge between the provisioning, management, and data zones (trusted/public); runs the per-zone flow rules
- Provide DHCP scope and iPXE/TFTP for device bootstrap
- Recursive DNS forwarder for the data zones (queries forwarded to control-plane authoritative DNS)
- BGP peering with upstream routers for WAN traffic
- OVS switches for VLAN management and network isolation
- NAT/firewall rules for network segmentation
- Require 2+ network interfaces (minimum: one to core switch, one to rack/production switch)
- In 3-node: single gateway node
- In HA cluster: 2+ gateways in active-active or active-passive configuration

### Compute Worker Nodes

- Run in **client mode** — auto-enroll with control-plane CA via ACME
- Host application workloads (QEMU/KVM virtual machines, Podman embedded containers)
- Report to control plane for policy enforcement and resource management
- Optional: hardware TPM for workload attestation and vTPM provision for guests
- Guest VMs can have vTPM 2.0 for attestation chains
- No requirement to run management services
- Connected to the `trusted` zone (VLAN 200); `storage` zone (VLAN 203) if used

---

## Network Layout

### Physical Network Diagram

```
┌────────────────────────────────────────────────────────────────┐
│                         INTERNET                               │
└──────────────┬────────────────────────────────────────────────┘
               │
        ┌──────┴──────┐
        │             │
   ┌────▼────┐   ┌────▼────┐
   │ ISP A   │   │ ISP B   │
   │(BGP AS) │   │(BGP AS) │
   └────┬────┘   └────┬────┘
        │             │
   ┌────▼─────────────▼────┐
   │  Upstream Routers     │
   │  (BGP transit)        │
   │  VLAN 10 (P2P /31s)   │
   └────┬────────────────┬─┘
        │                │
   ┌────▼────┐      ┌────▼────┐
   │Gateway A│──────│Gateway B│  HA Pair
   │         │      │         │  (active/standby
   │VLAN 10  │      │VLAN 10  │   or active-active)
   │200-210  │      │200-210  │
   └────┬────┘      └────┬────┘
        │                │
        │ Trunk uplink   │ (all VLANs)
        │                │
   ┌────┴────────────────┴────┐
   │   Core Switch            │
   │   (VLAN trunking)        │
   │   1x port per rack       │
   └────┬─────────┬───────────┘
        │         │
   ┌────▼──┐ ┌────▼──┐
   │Rack A │ │Rack B │ (and more)
   │       │ │       │
   │  CP1  │ │  CP2  │ Control plane
   │  GW1  │ │  GW2  │ Gateways
   │  W1-5 │ │  W6-10│ Workers
   │       │ │       │
   └───────┘ └───────┘

VLAN Connectivity:
• Upstream routers: VLAN 10 transit (P2P /31s), BGP
• Gateways: VLAN 10 (transit) + platform VLANs 200-210 (routing between them)
• Rack switches: platform VLANs trunked from the gateways
• CP nodes: VLAN 201 (provisioning) + VLAN 50 OOB
• GW nodes: all platform VLANs (enforce policy between them)
• Worker nodes: VLAN 200 (trusted) + VLAN 201 bootstrap; VLAN 203 (storage) if used
```

### Zones & VLAN Assignments

Policy is driven by **zones**, not VLAN numbers — see [reference-network.md](reference-network.md)
for the full zone model. Subnets are assigned to a zone; the platform applies that zone's policy.
The default segment IDs use the mnemonic **VLAN _N_ → `172.16.N.0/24`**.

**Default zone subnets (`trusted`/`provisioning`/`quarantine` are the working baseline):**
- VLAN 200 → `198.18.0.0/24` — zone **`trusted`** (enrolled, attested, internal workloads)
- VLAN 201 → `172.16.201.0/24` — zone **`provisioning`** (PXE, DHCP, DNS, ACME enrollment)
- VLAN 202 → `172.16.202.0/24` — zone **`quarantine`** (non-compliant/untrusted; isolated)
- VLAN 203 → `172.16.203.0/24` — zone **`storage`** (optional workload/bulk storage tier)
- VLAN 1000+ → `172.17.0.0/16+` — zone **`tenant`** (optional multi-tenant isolation)
- *(deployment public IP block)* — zone **`public`** (internet-facing; isolated from `trusted`).
  A public block is just a `public`-zone subnet — there is no dedicated "edge"/DMZ VLAN number.

**Shared / edge:**
- VLAN 10 (transit): gateway ↔ upstream routers / BGP; P2P /31s from `172.16.0.0/24`
- VLAN 50 (management): out-of-band IPMI/BMC/console — separate NIC, never routes to a data zone
- VLAN 1 (default): IEEE 802.1Q catch-all (no addressed network)

> The platform tier is self-contained. Any surrounding site/office/home network is kept entirely
> separate and is **not** part of this reference — see the deployment's own network docs.

---

## Bootstrap Scenarios

### M6 Barrier-Unseal Gate (applies to every scenario)

Every `platformd serve` invocation honors the M6 init-only invariant:
remote transports do not bind until the storage barrier reports
`initialized=true, sealed=false`. At startup the daemon binds:

| Surface | Bind | Endpoints |
|---------|------|-----------|
| Unix socket | `/run/platformd.sock` | full local surface (operator + `platformctl --transport unix`) |
| Loopback HTTP | `127.0.0.1:9446` | `GET /healthz`, `POST /init`, `POST /unseal` |

Production transports (REST `8443`, gRPC `10443`, QUIC `9444`, MCP `9445`)
remain unbound while the gate is active. The implementation lives in
`pkg/daemon/commands/serve_barrier_gate.go`; the ceremony backend behind
`POST /init` is the canonical quicbaas SDK `Security().Ceremony()`
handler, and `POST /unseal` drives the platform-side `barrier.Manager`
(for single-secret unseals and Shamir share submissions).

Operational implications:

- **Reverse-proxies and load balancers** should health-check
  `/healthz` over the loopback or over the Unix socket — the public TLS
  listeners simply do not exist during boot.
- **Recovery procedures** that submit Shamir shares against `POST
  /unseal` must reach the daemon via the Unix socket or
  `127.0.0.1:9446` until the threshold is met.
- **Development environments** can skip the gate entirely by starting
  with `--barrier-strategy none`, which wires the qrdb `StrategyNone`
  seal strategy and makes the daemon transition directly to unsealed at
  boot. PIN flags become optional under this strategy.

### Single-Node Deployment

**USB ISO Installation**

```
Admin Laptop
    │
    ├── Generate custom ISO with Secure Boot keys
    │   platformctl iso build --output=myplatform.iso
    │
    ├── Write to USB: dd if=myplatform.iso of=/dev/sdX
    │
    └── Boot node from USB
        ├── BIOS: Enroll custom Secure Boot keys
        ├── Boot: Linux kernel with custom signature
        ├── Platform-initrd: Unlock LUKS (first boot uses keyfile)
        ├── platformctl firstboot: Seal LUKS key to TPM
        └── Node ready for management via CLI or REST API
```

**Cloud / Container Alternative**

For virtual environments where USB is impractical:

```
Admin Host
    │
    ├── Start single-node platformd: make run-single
    │
    ├── Configure DHCP/TFTP (PXE) in network namespace
    │
    ├── Network devices boot via PXE
    │   ├── DHCP assigns IP
    │   ├── TFTP downloads platform-initrd.efi
    │   ├── Kernel loads, mounts platform-initrd
    │   └── Enrollment begins
    │
    └── Management via platformctl or REST API
```

---

### Three-Node Deployment

**Automated Bootstrap**

```
platformctl bootstrap run --config deployments/three-node/bootstrap.yaml

deployments/three-node/bootstrap.yaml:
  network:
    provisioning_vlan: 201
    gateway_ip: 172.16.201.1
  dhcp:
    range: 172.16.201.100-172.16.201.200
  dns:
    zone: trusted-platform.local
  devices:
    - hostname: cp-01
      mac: aa:bb:cc:dd:ee:01
      role: control-plane
      ip: 172.16.201.10
    - hostname: gw-01
      mac: aa:bb:cc:dd:ee:02
      role: gateway
      ip: 172.16.201.20
    - hostname: compute-01
      mac: aa:bb:cc:dd:ee:03
      role: worker
      ip: 172.16.201.30

Process:
1. Bootstrap server provisions all three nodes:
   • ISC DHCP with MAC→IP mappings
   • TFTP/iPXE menu for each role
   • DNS zone for ACME challenges (enroll-01)

2. Each node boots PXE:
   ├── DHCP request (matched by MAC → role assignment)
   ├── TFTP downloads platform-initrd.efi
   ├── Kernel + initramfs boot
   ├── Platform-initrd unlock via bootstrap TPM policy
   ├── Execute role-specific enrollment (enroll-01 ACME challenge)
   └── Get IDevID + IAK certs from control plane CA

3. Bootstrap monitors enrollment:
   • Watches DNS for enroll-01 ACME records
   • Approves enrollments based on config
   • Assigns gateway and workers as CLIENT mode
   • Creates network policies (VLAN, firewall)

4. Post-boot:
   • cp-01 starts in server mode
   • gw-01 and compute-01 start in client mode
   • All nodes enroll and converge
   • Network comes live
```

---

### High-Availability Cluster

**Automated Bootstrap**

```
platformctl bootstrap run --config deployments/ha-cluster/bootstrap.yaml

deployments/ha-cluster/bootstrap.yaml:
  network:
    provisioning_vlan: 201
    gateway_ip: 172.16.201.1
  dhcp:
    range: 172.16.201.100-172.16.201.250
  dns:
    zone: trusted-platform.local
  devices:
    # Control plane (Raft cluster)
    - hostname: cp-01
      mac: aa:bb:cc:dd:ee:01
      role: control-plane
      ip: 172.16.201.10
    - hostname: cp-02
      mac: aa:bb:cc:dd:ee:02
      role: control-plane
      ip: 172.16.201.11
    - hostname: cp-03
      mac: aa:bb:cc:dd:ee:03
      role: control-plane
      ip: 172.16.201.12
    # Gateways (HA pair)
    - hostname: gw-01
      mac: aa:bb:cc:dd:ee:04
      role: gateway
      ip: 172.16.201.20
    - hostname: gw-02
      mac: aa:bb:cc:dd:ee:05
      role: gateway
      ip: 172.16.201.21
    # Compute workers
    - hostname: compute-01
      mac: aa:bb:cc:dd:ee:06
      role: worker
      ip: 172.16.201.30
    # ... additional compute workers

Process:
1. Bootstrap server provisions 3 CP + 2 GW + N workers:
   • DHCP with MAC→IP→role mappings
   • TFTP/iPXE menus for each role
   • DNS zone for ACME (enroll-01 challenges)

2. Each node boots PXE independently:
   ├── DHCP assigns IP based on MAC
   ├── TFTP downloads role-specific platform-initrd.efi
   ├── Kernel + initramfs boot
   ├── Execute role-specific enrollment
   ├── Get IDevID + IAK certs from control plane CA
   └── Node ready to join cluster

3. Bootstrap monitors enrollment:
   • Watches DNS for enroll-01 ACME records
   • Approves enrollments
   • Assigns CP nodes to Raft cluster
   • Assigns GW and workers as CLIENT mode
   • Creates network policies

4. Post-boot cluster convergence:
   • cp-01, cp-02, cp-03 form Raft quorum
   • QuicBaaS initializes with 3-node replication
   • gw-01 and gw-02 enroll and configure HA pair
   • Workers enroll and connect to control plane
   • Network comes live with redundancy
```

See [bootstrap/pxe-bootstrap.md](../bootstrap/pxe-bootstrap.md) and [bootstrap/deployer.md](../bootstrap/deployer.md).

---

## Hardware Recommendations

### Single-Node Deployment (Dev/Test)

Suitable for development, testing, proof-of-concept, edge deployments.

**Physical Hardware**
- x86_64 system with 8GB+ RAM
- 128GB+ storage (SSD preferred)
- TPM 2.0 (hardware or vTPM via swtpm)
- 1x NIC for network

**Virtual Machines (on KVM/ESXi/Hyper-V)**
- 4 vCPU, 8GB vRAM
- 128GB virtual disk
- vTPM 2.0 (via swtpm backend)
- NAT or bridge network mode

**Cost:** $0-500 (reused hardware) or $1000-2000 (dedicated).

---

### Three-Node Deployment (Production Starting Point)

Suitable for production proof-of-concept, small enterprises, branch offices.

**Control Plane (1 node)**

Recommended: Supermicro SYS-5015A-TREEP or equivalent
- 4 cores (Intel Xeon D-1600 or AMD EPYC Embedded)
- 16GB ECC RAM
- 256GB NVMe SSD
- Hardware TPM 2.0
- Dual 1GbE NICs
- IPMI 2.0 for OOB management

Per-node cost: $1500-2500

**Gateway (1 node)**

Recommended: Same specs as CP
- 4 cores, 8GB RAM
- 128GB SSD
- Hardware TPM 2.0
- **Dual 1GbE NICs minimum** (core switch + rack switch)
- IPMI 2.0

Per-node cost: $1200-2000

**Compute Worker (1 node)**

Recommended: Supermicro SYS-1014S-TNRT or equivalent (1U)
- 4 cores
- 16GB RAM
- 256GB SSD
- Hardware TPM 2.0
- Single 1GbE NIC
- IPMI 2.0

Per-node cost: $1500-2500

**Network Infrastructure**
- 1x Managed switch (24-48 ports, VLAN support): $200-500
- 1x Router (BGP capable): $100-300

**Total 3-node deployment: $4500-8000**

---

### High-Availability Cluster (Production + Redundancy)

Suitable for production workloads requiring fault tolerance.

**Control Plane (3 nodes for Raft quorum)**

Recommended: Supermicro SYS-5015A-TREEP or equivalent (3x)
- 4 cores each (Intel Xeon D-1600 or AMD EPYC Embedded)
- 16GB ECC RAM per node
- 256GB NVMe SSD per node
- Hardware TPM 2.0 per node
- Dual 1GbE NICs per node
- IPMI 2.0

Per-node cost: $1500-2500
3-node total: $4500-7500

**Gateway (2 nodes for HA pair)**

Recommended: Same as CP or slightly higher throughput
- 4 cores, 8GB RAM per node
- 128GB SSD per node
- Hardware TPM 2.0 per node
- **Dual 1GbE NICs minimum** per node
- IPMI 2.0

Per-node cost: $1200-2000
2-node total: $2400-4000

**Compute Workers (N nodes, minimum 2)**

Recommended: Supermicro SYS-1014S-TNRT or equivalent
- 4 cores per node
- 16GB+ RAM per node
- 256GB+ SSD per node
- Hardware TPM 2.0 per node
- Single 1GbE NIC per node

Per-node cost: $1500-2500
For 2 workers: $3000-5000

**Network Infrastructure**
- 2x Core routers (BGP, dual ISP): $200-600 total
- 2x Managed switches (48-port, VLAN, 10GbE uplinks): $400-1000 total
- Optional: Redundant power supplies and networking

**Total 7-node HA cluster (3 CP + 2 GW + 2 workers): $10k-18k**

Scales to 10+ nodes by adding compute workers at $1500-2500 per node.

---

## Security Tiers

Hardware TPM availability determines the security tier of a deployment. Map tiers to your environment:

### Tier 1: Full Security (Recommended for Production)

**Hardware TPM 2.0 + Secure Boot + LUKS**

- All nodes have hardware TPM 2.0 (Trusted Computing Group certified)
- Secure Boot enabled with custom UEFI keys (enrolled per-node)
- LUKS encrypted root filesystem
- LUKS unlock key sealed to TPM PCRs
- Attestation quotes from workload VMs (vTPM 2.0 in guests)

**Security Properties:**
- Hardware root of trust (TPM-based)
- Boot integrity measurement (PCR attestation)
- Encrypted storage with trusted unlock
- Workload isolation via vTPM

**Deployment:** All Supermicro/Dell/HPE nodes with discrete TPM 2.0 module.

**Cost impact:** +$100-200 per node for TPM module (if not integrated).

### Tier 2: Partial Security (Development/Testing)

**Software TPM 2.0 (swtpm) + Secure Boot (optional)**

- Virtual TPM on all nodes (swtpm 0.7+)
- Secure Boot optional (self-signed keys)
- LUKS encrypted root filesystem
- LUKS unlock key sealed to vTPM PCRs
- Platform-initrd same code path as Tier 1

**Security Properties:**
- Software root of trust (acceptable for dev/test)
- Boot integrity measurement (PCR-based)
- Encrypted storage
- **Warning:** vTPM not isolated from host root (hypervisor can access)

**Deployment:** VMs, containers, all-in-one dev boxes.

**Use cases:** CI/CD testing, local development, proof-of-concept.

**Cost impact:** None (swtpm is free, included in hypervisor).

### Tier 3: Development/Lab (Minimal Security)

**No TPM, Self-Signed Certs, Software Keystore**

- No hardware or software TPM
- Self-signed TLS certificates (rotate frequently)
- Unencrypted filesystem (or LUKS with passphrase only)
- Software keystore with no sealing

**Security Properties:**
- No hardware root of trust
- No attestation capabilities
- Weaker isolation between services
- Acceptable only for lab/training

**Deployment:** Development laptops, training labs, CI environments.

**Use cases:** Development, testing, demo environments.

**Cost impact:** Negative (no TPM required, simpler setup).

---

## Deployment Checklist

### Single-Node Deployment

**Pre-Deployment**
- [ ] Procure 1 server (8GB+ RAM, 128GB+ SSD, TPM 2.0)
- [ ] Prepare custom USB ISO with Secure Boot keys
- [ ] Plan network connectivity (1-2 NICs, static IP or DHCP)

**Bootstrap**
- [ ] Write ISO to USB: `dd if=myplatform.iso of=/dev/sdX`
- [ ] Boot node from USB, enroll Secure Boot keys in BIOS
- [ ] Run `platformctl firstboot` to seal LUKS key to TPM
- [ ] Verify TPM attestation quotes
- [ ] Verify network connectivity

**Configuration**
- [ ] Configure CA with root certificate
- [ ] Set up IAM users and roles (optional)
- [ ] Configure DNS if needed
- [ ] Deploy applications/services

---

### Three-Node Deployment

**Pre-Deployment**
- [ ] Procure 3 servers (1 CP at 16GB RAM, 1 GW at 8GB RAM, 1 compute at 16GB RAM)
- [ ] Procure 1 managed switch with VLAN support
- [ ] Plan network layout (zones: VLAN 201 provisioning, VLAN 200 trusted, public block as needed)
- [ ] Prepare `deployments/three-node/bootstrap.yaml` with device manifests and MAC addresses
- [ ] Prepare custom platform-initrd.efi

**Bootstrap**
- [ ] Configure provisioning network (DHCP server, TFTP, DNS)
- [ ] Run `platformctl bootstrap run --config deployments/three-node/bootstrap.yaml`
- [ ] Boot all nodes via PXE in order: CP first, then GW and compute workers
- [ ] Monitor enrollment via DNS (watch for enroll-01 ACME records)
- [ ] Verify all nodes enrolled and healthy in platform logs

**Configuration**
- [ ] Verify cp-01 started in server mode
- [ ] Verify gw-01 and compute-01 enrolled as client mode
- [ ] Configure CA with root + intermediate certificates
- [ ] Set up IAM users, roles, policies
- [ ] Configure DNS zones (internal)
- [ ] Configure DHCP scopes per VLAN
- [ ] Configure firewall rules between VLANs
- [ ] Test inter-VLAN connectivity
- [ ] Deploy applications to compute worker

**Validation**
- [ ] Verify DHCP and iPXE working on gateway
- [ ] Test DNS resolution from all nodes
- [ ] Test certificate enrollment and renewal
- [ ] Verify client-mode auto-enrollment worked

---

### High-Availability Cluster

**Pre-Deployment**
- [ ] Procure 7+ servers (3 CP at 16GB RAM, 2 GW at 8GB RAM, 2+ compute at 16GB+ RAM)
- [ ] Procure 2 managed switches with VLAN and 10GbE support
- [ ] Procure 2 routers with BGP support
- [ ] Plan network topology (multiple VLANs, core switch, rack switches, routers)
- [ ] Plan IP addressing (each node, each VLAN, each service)
- [ ] Prepare `deployments/ha-cluster/bootstrap.yaml` with full device manifest
- [ ] Prepare custom platform-initrd.efi with cluster bootstrap policy

**Bootstrap**
- [ ] Configure core router and switches (VLAN trunking, BGP)
- [ ] Configure provisioning gateway (DHCP, TFTP, DNS)
- [ ] Run `platformctl bootstrap run --config deployments/ha-cluster/bootstrap.yaml`
- [ ] Boot all nodes via PXE: CP nodes first (parallel), then GW, then workers
- [ ] Monitor enrollment via DNS
- [ ] Verify all nodes enrolled and healthy

**Configuration**
- [ ] Form Raft cluster from 3 CP nodes
- [ ] Verify QuicBaaS replication across 3 nodes
- [ ] Configure CA with root + intermediate certificates
- [ ] Set up IAM users, roles, policies
- [ ] Configure DNS zones and secondary replication (if multi-site)
- [ ] Configure DHCP on both gateways with failover
- [ ] Configure HA pair for gateways (active-active or active-passive)
- [ ] Configure BGP routing from gateways to upstream
- [ ] Configure firewall rules and network policies
- [ ] Test inter-VLAN connectivity from all sites

**Redundancy Testing**
- [ ] Simulate CP node failure — verify cluster remains operational with 2/3 quorum
- [ ] Simulate GW node failure — verify network services still available
- [ ] Simulate network partition — verify split-brain prevention
- [ ] Simulate node recovery — verify rejoin and state synchronization

**Production Readiness**
- [ ] Configure backup/replication for stateful services
- [ ] Set up monitoring (Prometheus, alerting on all nodes)
- [ ] Set up centralized logging (ELK, Splunk, or similar)
- [ ] Configure certificate renewal (ACME auto-renewal)
- [ ] Document runbooks (bootstrap, recovery, node replacement, scaling)
- [ ] Train operations team on failover procedures

---

## Typical Deployment Timelines

| Deployment Profile | Setup Time | Bootstrap | Validation | Go-Live |
|-------------------|-----------|-----------|-----------|---------|
| Single-Node | 1-2 hours | 30 min | 30 min | 2-3 hours total |
| Three-Node | 4-8 hours | 1-2 hours | 2-4 hours | 1 day |
| HA Cluster (7 nodes) | 12-24 hours | 2-3 hours | 4-8 hours | 2-3 days |
| HA Cluster (15+ nodes) | 2-3 days | 4-6 hours | 8-16 hours | 1 week (with validation) |

**Setup time includes:**
- Hardware procurement and racking (or VM allocation)
- Network infrastructure provisioning (switches, VLANs, routers)
- Bootstrap config preparation (bootstrap.yaml, device manifests)
- Custom ISO/platform-initrd build

**Bootstrap time includes:**
- PXE boot sequence for all nodes
- Enrollment via enroll-01 ACME challenge
- Certificate issuance for IDevID and IAK

**Validation time includes:**
- Enrollment verification (DNS records, logs)
- Service health checks (CP, GW, workers)
- Inter-VLAN connectivity tests
- Failover scenario testing (for HA only)

**Assumes:**
- Hardware procurement already complete
- Network infrastructure in place
- Network bandwidth sufficient for parallel PXE boots
- No compliance/audit delays

---

## Related Documentation

- [Reference Architecture](reference.md) - IoT reference use case and system requirements
- [Reference Network Architecture](reference-network.md) - VLAN design and network segmentation
- [Binary Separation](binary-separation.md) - Three-binary architecture and privilege model
- [Platform Modes](platform-modes.md) - Local, P2P, and Hosted control plane modes
- [Bootstrap Overview](../bootstrap/overview.md) - Trust bootstrap strategies
- [PXE Bootstrap](../bootstrap/pxe-bootstrap.md) - Automated network bootstrap
- [Manual Nodes](../bootstrap/manual-nodes.md) - Manual node enrollment
- [Day Zero Configuration](../bootstrap/day-zero.md) - Initial platform setup
