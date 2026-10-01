# Platform Operational Modes

go-trusted-platform supports three operational modes for control plane functionality. A deployment operates in ONE mode. P2P mode supports optional federation where nodes can run local services while participating in the network.

## Mode Overview

```
LOCAL MODE                 P2P MODE                  HOSTED MODE
(Isolated/Enterprise)      (Distributed/Global)      (Premium Managed)

┌─────────────────┐        ┌─────────────────┐       ┌─────────────────┐
│ Local Control   │        │  P2P DHT Network│       │ Hosted Control  │
│ Plane (Raft)    │        │                 │       │ Plane (Premium) │
│ ┌─────────────┐ │        │ ┌─────────────┐ │       │ ┌─────────────┐ │
│ │ Local CA    │ │        │ │ FROST CA    │ │       │ │ Hosted CA   │ │
│ │ Local IAM   │ │        │ │ (threshold) │ │       │ │ Hosted IAM  │ │
│ │ Local DNS   │ │        │ ├─────────────┤ │       │ │ Hosted KMS  │ │
│ │ Local KMS   │ │        │ │ Distributed │ │       │ │ Managed HA  │ │
│ └─────────────┘ │        │ │ IAM/OIDC    │ │       │ └─────────────┘ │
│       │         │        │ └─────────────┘ │       │       │         │
│       ▼         │        │       │         │       │       ▼         │
│ ┌─────────────┐ │        │       ▼         │       │ ┌─────────────┐ │
│ │ Data Plane  │ │        │ ┌─────────────┐ │       │ │ Data Plane  │ │
│ │ (on-prem)   │ │        │ │ P2P Nodes   │ │       │ │ (flexible)  │ │
│ └─────────────┘ │        │ └─────────────┘ │       │ └─────────────┘ │
└─────────────────┘        └─────────────────┘       └─────────────────┘

- Own CA hierarchy         - FROST threshold CA      - Managed CA/IAM
- Own IAM/OIDC             - Distributed IAM         - SLA-backed HA
- Any network type         - Global P2P network      - Flexible deployment
- Enterprise controlled    - Decentralized           - Premium support
```

## Local Mode: Local Control Plane

**Use Cases**: Enterprise datacenters, air-gapped environments, private networks, compliance-restricted deployments

### Architecture

A local control plane consists of one or more nodes running in server mode, providing centralized services to data plane nodes:

```
┌────────────────────────────────────────────────────┐
│              Local Control Plane                   │
│                                                    │
│  ┌─────────┐  ┌──────────┐  ┌──────────┐           │
│  │ Node 1  │──│ Node 2   │──│ Node 3   │  Raft     │
│  │ (Leader)│  │(Follower)│  │(Follower)│  Cluster  │
│  └────┬────┘  └────┬─────┘  └────┬─────┘           |
│       │            │             │                 │
│       └────────────┼─────────────┘                 │
│                    │                               │
│  Services:         │                               │
│  • Certificate Authority (local PKI)               │
│  • IAM (QuicBaaS-backed, ABAC policies)            |
│  • DNS (zone management)                           │
│  • KMS (key management)                            │
│  • SDN Controller (802.1X, OpenFlow)               │
└────────────────────┬───────────────────────────────┘
                     │
         ┌───────────┼───────────┐
         │           │           │
    ┌────▼────┐ ┌────▼────┐ ┌────▼────┐
    │  Data   │ │  Data   │ │  Data   │
    │  Plane  │ │  Plane  │ │  Plane  │
    │  Node   │ │  Node   │ │  Node   │
    └─────────┘ └─────────┘ └─────────┘

    Data plane nodes run in Client Mode:
    • Get certificates from local CA
    • Authenticate via local IAM
    • Run workloads (VMs, containers)
```

### Key Characteristics

| Aspect | Description |
|--------|-------------|
| **CA** | Local PKI hierarchy (root + intermediates) |
| **IAM** | Server/Client mode with ABAC policies |
| **Identity** | IDevID from local CA via ACME enroll-01 |
| **Clustering** | Raft consensus for HA (3+ nodes recommended) |
| **Network** | Air-gapped, private, or internet-connected |
| **Governance** | Centralized administration |

### Status

~85% complete (Phases A-L of roadmap)

## P2P Mode: P2P Network

**Use Cases**: Distributed IoT networks, global edge deployments, decentralized services, AI agent marketplace

### Architecture

The P2P network uses a distributed hash table (DHT) with threshold cryptography for decentralized control:

```
┌─────────────────────────────────────────────────────────────┐
│                     P2P DHT Network                         │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              FROST Threshold CA                      │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐     │   │
│  │  │Ed25519-A│ │Ed25519-B│ │ P-256-A │ │ P-256-B │     │   │
│  │  │  Pool   │ │  Pool   │ │  Pool   │ │  Pool   │     │   │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘     │   │
│  │            33% threshold, hourly rotation            │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                 Kademlia DHT                         │   │
│  │                                                      │   │
│  │  ┌─────┐  ┌─────┐  ┌─────┐  ┌─────┐  ┌─────┐         │   │
│  │  │Node │──│Node │──│Node │──│Node │──│Node │  ...    │   │
│  │  └─────┘  └─────┘  └─────┘  └─────┘  └─────┘         │   │
│  │                                                      │   │
│  │  160-bit node IDs, O(log N) routing                  │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  Services (Distributed):                                    │
│  • FROST CA (threshold signatures)                          │
│  • Distributed IAM/OIDC                                     │
│  • DHT-based service discovery                              │
│  • PBFT consensus (5-node committees)                       │
│  • Reputation system                                        │
└─────────────────────────────────────────────────────────────┘
```

### Key Characteristics

| Aspect | Description |
|--------|-------------|
| **CA** | FROST threshold signatures (33% threshold, 4-pool system) |
| **IAM** | Distributed via QuicBaaS + DHT |
| **Identity** | IDevID from FROST CA with trust level extension |
| **Consensus** | PBFT (5-node committees, VRF-selected) |
| **Network** | Global P2P, internet-connected |
| **Governance** | Reputation-based, collaborative |

### Status

Planned (Phase N of roadmap)

### Federation Enhancement (Optional)

P2P mode supports an optional federation layer where nodes can run their own local services while maintaining P2P network membership:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     FEDERATED P2P MODE NODE                             │
│                                                                         │
│  ┌──────────────────────────────────────┐  ┌─────────────────────────┐  │
│  │        LOCAL SERVICES (Optional)     │  │   P2P PARTICIPATION     │  │
│  │  ┌────────────┐  ┌────────────────┐  │  │  ┌─────────────────┐    │  │
│  │  │ Local CA   │  │ Local IAM      │  │  │  │ FROST Identity  │    │  │
│  │  │ (own PKI)  │  │ (own policies) │  │  │  │ DHT Routing     │    │  │
│  │  └────────────┘  └────────────────┘  │  │  │ Reputation      │    │  │
│  │  ┌────────────┐  ┌────────────────┐  │  │  │ PBFT Consensus  │    │  │
│  │  │ Local DNS  │  │ Local KMS      │  │  │  └─────────────────┘    │  │
│  │  │ (own zone) │  │ (own keys)     │  │  │                         │  │
│  │  └────────────┘  └────────────────┘  │  │  P2P services still     │  │
│  │                                      │  │  available as fallback  │  │
│  │  Serves: myorg.example.com           │  │  or shared namespace    │  │
│  └──────────────────────────────────────┘  └─────────────────────────┘  │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                    CROSS-CERTIFICATION LAYER                      │  │
│  │  My CA ←── Cross-Cert ──→ Partner CA ←── Cross-Cert ──→ FROST CA  │  │
│  │  Trust Anchors: [my-root, partner-root, frost-root]               │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

**Key Concepts:**

| Concept | Description |
|---------|-------------|
| **FROST Identity** | Mandatory - your "passport" to the P2P network |
| **Local Services** | Optional - run your own CA, IAM, DNS, KMS for your domain |
| **Cross-Certification** | Bilateral trust agreements with partner organizations |
| **Dual Identity** | FROST cert (network) + Local cert (domain) |

**Node Types in P2P Mode:**

| Type | Description | Use Case |
|------|-------------|----------|
| **Simple P2P Node** | FROST identity only, uses shared P2P services | IoT devices, edge nodes, simple participation |
| **Federated Node** | FROST identity + local services + cross-certs | Enterprise with sovereignty needs |

**Federation Benefits:**
- Run own CA/IAM while participating in global P2P network
- Cross-certify with trusted partners for web of trust
- Maintain data sovereignty with local services
- P2P services available as fallback if local services fail

See [Federation Protocol](../dht/22-federation.md) for detailed design.

## Hosted Mode: Hosted Control Plane

**Use Cases**: Startups, SMBs, enterprises wanting managed infrastructure, rapid deployment without operational overhead

### Architecture

The Hosted Control Plane provides a premium managed control plane with flexible data plane deployment:

```
┌──────────────────────────────────────────────────────────────────────┐
│                    HOSTED CONTROL PLANE (Premium)                    │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │                   Managed Control Plane                         │ │
│  │  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐        │ │
│  │  │ Hosted CA │ │Hosted IAM │ │Hosted KMS │ │Hosted DNS │        │ │
│  │  │ (HA Raft) │ │ (Server)  │ │ (HA Raft) │ │ (zones)   │        │ │
│  │  └───────────┘ └───────────┘ └───────────┘ └───────────┘        │ │
│  │                                                                 │ │
│  │  • Multi-region HA       • 99.9% SLA        • Auto-backup       │ │
│  │  • Managed upgrades      • 24/7 support     • Audit logging     │ │
│  └─────────────────────────────────────────────────────────────────┘ │
└────────────────────────────┬─────────────────────────────────────────┘
                             │ mTLS + gRPC/QUIC
           ┌─────────────────┼─────────────────┐
           │                 │                 │
           ▼                 ▼                 ▼
┌───────────────────┐ ┌───────────────┐ ┌──────────────────────────────┐
│  FULLY HOSTED     │ │  ON-PREMISES  │ │         HYBRID               │
│  DATA PLANE       │ │  DATA PLANE   │ │       DATA PLANE             │
│                   │ │               │ │                              │
│ ┌───────────────┐ │ │┌─────────────┐│ │┌────────────┐ ┌────────────┐ │
│ │ Data Plane    │ │ ││ Data Plane  ││ ││ Hosted DP  │ │ On-Prem DP │ │
│ │ Node (hosted) │ │ ││ Node        ││ ││ Nodes      │ │ Nodes      │ │
│ │ • Low latency │ │ ││ (on-prem)   ││ ││            │ │            │ │
│ │ • VM/Container│ │ ││ • Workloads ││ ││ • Workloads│ │ • Workloads│ │
│ └───────────────┘ │ ││ • Full ctrl ││ │└────────────┘ └────────────┘ │
└───────────────────┘ │└─────────────┘│ │                              │
                      └───────────────┘ └──────────────────────────────┘
```

### Data Plane Deployment Options

| Option | Description | Use Case |
|--------|-------------|----------|
| **Fully Hosted** | Data plane runs in hosted environment | Quick start, no on-prem infra |
| **On-Premises** | Data plane on-prem, control plane hosted | Data sovereignty, existing infra |
| **Hybrid** | Data plane in both hosted and on-prem | Burst capacity, geo-distribution |

### Hosted Deployment Models

Hosted mode supports multiple deployment models to meet various requirements:

| Deployment | Description | Use Case |
|------------|-------------|----------|
| **Public Cloud** | Hosted control plane on public cloud | SaaS, rapid onboarding |
| **Private Cloud** | Dedicated hosted instance in customer VPC | Compliance, data residency |
| **Air-gapped** | On-prem managed instance, no internet | Government, defense, critical infrastructure |

### Key Characteristics

| Aspect | Description |
|--------|-------------|
| **CA** | Hosted CA with dedicated tenant PKI hierarchy |
| **IAM** | Hosted IAM Server, data plane uses standard client config |
| **Identity** | IDevID from hosted CA via ACME enroll-01 |
| **Clustering** | Managed multi-region HA (customer invisible) |
| **Network** | Public cloud, private cloud, or air-gapped |
| **Governance** | Customer-defined policies, managed operations |

### Status

Planned (Phase O of roadmap)

## Data Plane: Unified Across All Modes

**Key Insight**: Data plane nodes work identically across all modes. The only difference is the `acme.client.directory` URL they point to.

```yaml
# Data plane node configuration - SAME for all modes
# Only the directory URL changes based on which control plane you're connecting to

acme:
  client:
    # Local mode: https://local-control-plane.internal/api/v1/acme/directory
    # P2P mode:   https://p2p.letstrust.net/api/v1/acme/directory
    # Hosted mode: https://cp.letstrust.com/api/v1/acme/directory
    directory: ${CONTROL_PLANE_ACME_DIRECTORY}
    enrollment:
      challenge: enroll-8081
      ip: ${PREFERRED_IP}
    account:
      email: hostmaster@mydevice.example.com
      # ... standard account config
```

**What happens when a data plane node connects:**
1. Node contacts ACME directory URL
2. Performs EK endorsement via `endorse-01`
3. Performs device enrollment via `enroll-01`
4. Receives IAK and IDevID certificates
5. DNS records created automatically
6. Node is now authenticated and can communicate on the network

**This works the same whether the control plane is:**
- A local Raft cluster (Local mode)
- A P2P FROST CA (P2P mode)
- A premium hosted service (Hosted mode)

## Mode Selection

| Requirement | Local | P2P | Hosted |
|-------------|-------|-----|--------|
| Air-gapped networks | Yes | No | Yes (private/air-gapped deployment) |
| Private networks (internet-connected) | Yes | No | Yes |
| Public internet deployment | Yes | Yes | Yes |
| Compliance requiring central control | Yes | Limited | Yes |
| Single organization ownership | Yes | No (federated: Yes) | Yes |
| Global distribution | Limited | Yes | Yes |
| Decentralized governance | No | Yes | No |
| No single point of failure for CA | HA only | Yes (FROST) | Yes (Managed HA) |
| No operational overhead | No (self-managed) | Yes | Yes |
| Data sovereignty (on-prem data) | Yes | Yes (federated: full) | Yes (hybrid option) |
| Rapid deployment | Moderate | Simple | Yes |
| Federation/cross-certification | No | Yes (optional) | No |
| Own CA while on shared network | No | Yes (federated) | No |

## Mixed Use Cases

Organizations may run **separate deployments** in different modes:

```
Enterprise Network         Hosted Service            P2P Network
┌───────────────────┐     ┌───────────────────┐     ┌───────────────────┐
│ Local Mode        │     │ Hosted Mode       │     │ P2P Mode          │
│ Control Plane     │     │ Control Plane     │     │ DHT Network       │
│ ┌─────┐ ┌─────┐   │     │ (managed)         │     │                   │
│ │Node1│ │Node2│   │     │       │           │     │  ┌─────┐ ┌─────┐  │
│ └─────┘ └─────┘   │     │       ▼           │     │  │NodeX│ │NodeY│  │
│ ┌─────┐ ┌─────┐   │     │ ┌───────────────┐ │     │  └─────┘ └─────┘  │
│ │Node3│ │Node4│   │     │ │On-prem nodes  │ │     │                   │
│ └─────┘ └─────┘   │     │ │(data plane)   │ │     │  FROST CA         │
└───────────────────┘     │ └───────────────┘ │     │  Distributed IAM  │
                          └───────────────────┘     └───────────────────┘
Isolated (air-gapped)     Managed + On-prem data    Decentralized
```

**Key Point**: Separate deployments, not federated. Different nodes, different identities, no bridging between modes.

## Related Documentation

- [IAM Architecture](../iam/architecture.md) - Local mode IAM (Server/Client)
- [Security Model](security-model.md) - Zero-trust security architecture
- [DHT Overview](../dht/00-README.md) - P2P mode architecture
- [DHT Certificate Authority](../dht/05-certificate-authority.md) - FROST CA design
- [Federation Protocol](../dht/22-federation.md) - P2P mode federation enhancement
- [P2P DNS](../dht/23-p2p-dns.md) - DNS resolution for P2P nodes
