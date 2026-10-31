# Trusted DHT Design Documentation

> **Status: NORMATIVE** · Scope: the planned `dht` feature (docs/SPEC.md:53); design only, no code exists · Last verified: 2026-10-21
> Conflicts with this document are defects. Fix them here first.

Part of [go-trusted-platform](https://github.com/jeremyhahn/go-trusted-platform) - a design; no code exists (the planned package is `pkg/dht/`, which is not in the tree). See [architecture.md](architecture.md) §1.

A Distributed Hash Table for the Trusted Computing Platform, providing decentralized key-value storage, consensus, reputation, and cryptographic services. The DHT integrates directly with platform services including TPM 2.0, XKMS (hardware RNG), certificate authority, and QuicBaaS storage.

**Key Integration Points:**
- **RNG**: Hardware-backed via go-xkms (TPM2 > PKCS#11 > Software)
- **Storage**: QuicBaaS for persistent DHT state
- **Attestation**: TPM 2.0 for node identity and quotes
- **Certificates**: go-xkms for distributed PKI (the platform's own `pkg/ca` and `pkg/acme` in this repository, built on the go-xkms re-exports of the go-quicbaas SDK)
- **Crypto**: go-frost/go-frostdkg for threshold signatures

---

## Document Index

| # | Document | Description |
|---|----------|-------------|
| 00 | **README** (this file) | Navigation hub and quick reference |
| 01 | [System Overview](01-system-overview.md) | Architecture diagrams, component relationships, process flows |
| 02 | [Network Architecture](02-network-architecture.md) | Hierarchical Kademlia DHT, IPv6, routing, P2P swarm |
| 03 | [Security and Trust](03-security-trust.md) | STRIDE model, security constants, TPM policies, incident response |
| 04 | [Cryptographic Protocols](04-cryptographic-protocols.md) | FROST signatures, DKG protocol, wire protocol, key management |
| 05 | [Certificate Authority](05-certificate-authority.md) | Distributed CA, threshold signatures, certificate lifecycle |
| 06 | [Consensus and Coordination](06-consensus-coordination.md) | VRF selection, PBFT consensus, coordinator roles, genesis |
| 07 | [Currency and Transactions](07-currency-transactions.md) | UTXO model, sharded ledger, cross-shard protocol, recovery |
| 08 | [Content Distribution](08-content-distribution.md) | Block storage, OS images, updates, git repositories, boot |
| 09 | [Defense and Reputation](09-defense-reputation.md) | Reputation system, collaborative defense, penalties (CANONICAL) |
| 10 | [Governance and Economics](10-governance-economics.md) | Voting, upgrades, economic model, privacy features |
| 11 | [Operations](11-operations.md) | Deployment, monitoring, telemetry, partition handling |
| 12 | [Secure Content Storage](12-secure-content-storage.md) | Key Share Partitioning (KSP), data classification, encryption |
| 13 | [Service Discovery](13-service-discovery.md) | DHT Search, service marketplace, e-commerce, payment escrow |
| 14 | [Browser Extension](14-browser-extension.md) | Chrome/Firefox extension, Gateway API, external DHT access |
| 15 | [AI Agent Collaboration](15-ai-agent-collaboration.md) | Agent identity, chat rooms, workload distribution, MCP tools |
| 16 | [DDoS Protection](16-ddos-protection.md) | Network-wide DDoS protection, PoW challenges, threat intelligence |
| 17 | [Untrusted Nodes](17-untrusted-nodes.md) | Untrusted node work assignment, scrutiny levels, misbehavior penalties |
| 18 | [Platformd P2P Mode](18-platformd-p2p.md) | P2P network participation, ACME enrollment, cluster integration |
| 19 | [Service Contracts](19-service-contracts.md) | ServiceContract hierarchy, e-commerce, compute, storage contracts |
| 20 | [Service Provider Requirements](20-service-provider-requirements.md) | Client eligibility criteria, trust/reputation requirements |
| 21 | [AI Arbitration System](21-ai-arbitration-system.md) | AI-based arbitrators, hybrid arbitration, TPM-bound agents |
| 22 | [Federation Protocol](22-federation.md) | P2P mode federation, cross-certification, enterprise interoperability |
| 23 | [P2P DNS](23-p2p-dns.md) | Distributed DNS resolution, automatic naming, custom domains |
| 24 | [QuicBaaS Schema](24-quicbaas-schema.md) | DHT state storage schema, key naming, indexes, migrations |
| 25 | [KMS FROST Lifecycle](25-kms-frost-lifecycle.md) | FROST share storage, rotation, backup, TPM-KMS integration |
| 26 | [Organization Identity](26-organization-identity.md) | Organization identity model |
| -- | [Constants Reference](00-CONSTANTS.md) | Canonical reference for all system constants and thresholds |
| -- | [Wire Protocol](wire-protocol.md) | Protocol buffers, message types, transport options |
| -- | [API Reference](api-reference.md) | Multi-protocol API overview |
| -- | [REST API](api-reference-rest.md) | REST endpoint specifications |
| -- | [gRPC API](api-reference-grpc.md) | gRPC service methods |
| -- | [QUIC API](api-reference-quic.md) | QUIC transport usage |
| -- | [MCP API](api-reference-mcp.md) | MCP tools for AI agents |
| -- | [Unix Socket API](api-reference-unix.md) | Unix socket IPC |
| -- | [Gateway API](api-reference-gateway.md) | Browser extension gateway |
| -- | [Roadmap](ROADMAP.md) | Pointer to [`docs/archive/dht-ROADMAP.md`](../archive/dht-ROADMAP.md): implementation roadmap, phases, and security audit |

---

## Quick Reference: Where to Find What

| Topic | Document | Section |
|-------|----------|---------|
| Role eligibility thresholds | [09-defense-reputation.md](09-defense-reputation.md) | Role Eligibility Thresholds (CANONICAL) |
| Security constants | [03-security-trust.md](03-security-trust.md) | Security Constants (CANONICAL) |
| DHT parameters | [03-security-trust.md](03-security-trust.md) | DHT Parameters |
| TPM requirements | [03-security-trust.md](03-security-trust.md) | TPM Trust Policy |
| FROST threshold signatures | [04-cryptographic-protocols.md](04-cryptographic-protocols.md) | FROST Implementation |
| CA rotation schedule | [05-certificate-authority.md](05-certificate-authority.md) | Rotation Schedule |
| Reputation growth formula | [09-defense-reputation.md](09-defense-reputation.md) | Reputation Growth Formula |
| Violation penalties | [09-defense-reputation.md](09-defense-reputation.md) | Penalty Matrix |
| Transaction validation | [07-currency-transactions.md](07-currency-transactions.md) | UTXO Model |
| Content block storage | [08-content-distribution.md](08-content-distribution.md) | Block Chunking |
| Network boot process | [08-content-distribution.md](08-content-distribution.md) | iPXE Boot |
| Governance voting | [10-governance-economics.md](10-governance-economics.md) | Upgrade Governance |
| Key Share Partitioning | [12-secure-content-storage.md](12-secure-content-storage.md) | KSP Algorithm |
| Data classification | [12-secure-content-storage.md](12-secure-content-storage.md) | Data Classification System |
| Per-content security config | [12-secure-content-storage.md](12-secure-content-storage.md) | Per-Content Security Configuration |
| Hardware RNG | [03-security-trust.md](03-security-trust.md) | Random Number Generation |
| Binary TPM trust policy | [03-security-trust.md](03-security-trust.md) | TPM Trust Policy (CANONICAL) |
| IDevID enrollment | [05-certificate-authority.md](05-certificate-authority.md) | Node IDevID Enrollment (CANONICAL) |
| Service marketplace | [13-service-discovery.md](13-service-discovery.md) | Service Advertisement |
| DHT search interface | [13-service-discovery.md](13-service-discovery.md) | Search Service Interface |
| Payment escrow | [13-service-discovery.md](13-service-discovery.md) | Payment and Escrow |
| Browser extension | [14-browser-extension.md](14-browser-extension.md) | Extension Architecture |
| Gateway API | [14-browser-extension.md](14-browser-extension.md) | Gateway API for Extensions |
| AI agent identity | [15-ai-agent-collaboration.md](15-ai-agent-collaboration.md) | Agent Identity |
| Agent chat rooms | [15-ai-agent-collaboration.md](15-ai-agent-collaboration.md) | Chat Rooms |
| Workload distribution | [15-ai-agent-collaboration.md](15-ai-agent-collaboration.md) | Workload Distribution |
| Agent MCP tools | [15-ai-agent-collaboration.md](15-ai-agent-collaboration.md) | MCP Tools for Agents |
| DDoS protection layers | [16-ddos-protection.md](16-ddos-protection.md) | 5-Layer Architecture |
| Proof-of-Work constants | [16-ddos-protection.md](16-ddos-protection.md) | Security Constants (CANONICAL) |
| IP reputation system | [16-ddos-protection.md](16-ddos-protection.md) | Layer 2: Rate Limiting |
| Threat intelligence | [16-ddos-protection.md](16-ddos-protection.md) | Layer 5: Collaborative Intelligence |
| Untrusted node work types | [17-untrusted-nodes.md](17-untrusted-nodes.md) | Work Types for Untrusted Nodes |
| Scrutiny levels | [17-untrusted-nodes.md](17-untrusted-nodes.md) | Scrutiny Levels (CANONICAL) |
| Misbehavior penalties | [17-untrusted-nodes.md](17-untrusted-nodes.md) | Penalty Matrix |
| Misbehavior detection | [17-untrusted-nodes.md](17-untrusted-nodes.md) | Misbehavior Detection |
| Untrusted penalty matrix | [17-untrusted-nodes.md](17-untrusted-nodes.md) | Penalty Matrix |
| Untrusted capabilities | [17-untrusted-nodes.md](17-untrusted-nodes.md) | Untrusted Node Capabilities |
| ACME enroll-01 | [18-platformd-p2p.md](18-platformd-p2p.md) | ACME enroll-01 Challenge |
| ACME endorse-01 | [18-platformd-p2p.md](18-platformd-p2p.md) | ACME endorse-01 Challenge |
| Cluster-P2P integration | [18-platformd-p2p.md](18-platformd-p2p.md) | Cluster-P2P Integration |
| ServiceContract structure | [19-service-contracts.md](19-service-contracts.md) | ServiceContract Structure |
| E-commerce contracts | [19-service-contracts.md](19-service-contracts.md) | ECommerceServiceTerms |
| Compute contracts | [19-service-contracts.md](19-service-contracts.md) | ComputeServiceTerms |
| Partition recovery | [06-consensus-coordination.md](06-consensus-coordination.md) | Partition Recovery Protocol |
| Coordinator rotation | [06-consensus-coordination.md](06-consensus-coordination.md) | Coordinator Rotation Epochs |
| VRF seed generation | [06-consensus-coordination.md](06-consensus-coordination.md) | VRF Seed Commit-Reveal Scheme |
| Sequence validation | [06-consensus-coordination.md](06-consensus-coordination.md) | Contiguous Sequence Numbers |
| CT log verification | [05-certificate-authority.md](05-certificate-authority.md) | CT Log Append-Only Verification |
| Arbiter selection | [19-service-contracts.md](19-service-contracts.md) | Arbiter Selection and Anti-Collusion |
| Contract automation | [19-service-contracts.md](19-service-contracts.md) | Contract Automation |
| Automation triggers | [19-service-contracts.md](19-service-contracts.md) | AutomationTrigger Structure |
| Trigger configs | [19-service-contracts.md](19-service-contracts.md) | Trigger-Specific Configurations |
| TriggerEngine interface | [19-service-contracts.md](19-service-contracts.md) | TriggerEngine Interface |
| OPA/Rego conditions | [19-service-contracts.md](19-service-contracts.md) | OPA/Rego Custom Conditions (Phase 2) |
| Human arbitration scope | [19-service-contracts.md](19-service-contracts.md) | What Cannot Be Automated |
| DAG epoch boundaries | [07-currency-transactions.md](07-currency-transactions.md) | DAG Epoch Boundaries |
| DKG progress tracking | [04-cryptographic-protocols.md](04-cryptographic-protocols.md) | DKG Progress Tracking |
| Manufacturer CA recovery | [05-certificate-authority.md](05-certificate-authority.md) | Manufacturer CA Compromise Recovery |
| CA pool bootstrap | [05-certificate-authority.md](05-certificate-authority.md) | Total CA Pool Failure Recovery |
| Coordinator slashing | [07-currency-transactions.md](07-currency-transactions.md) | 3PC Coordinator Slashing |
| Shard assignment | [07-currency-transactions.md](07-currency-transactions.md) | Dynamic Shard Assignment |
| Parent proofs | [07-currency-transactions.md](07-currency-transactions.md) | Parent Proof in Transaction Structure |
| BFT finality | [07-currency-transactions.md](07-currency-transactions.md) | BFT Finality Committee |
| DAG total ordering | [07-currency-transactions.md](07-currency-transactions.md) | DAG Total Ordering via PBFT |
| Nonce expiration | [04-cryptographic-protocols.md](04-cryptographic-protocols.md) | Nonce Expiration Validation |
| Gateway selection | [02-network-architecture.md](02-network-architecture.md) | Gateway Promotion and Selection |
| TPM verification protocol | [03-security-trust.md](03-security-trust.md) | TPM Verification Protocol |
| Trust level enforcement | [03-security-trust.md](03-security-trust.md) | Trust Level Enforcement |
| Trust downgrade protocol | [03-security-trust.md](03-security-trust.md) | Trust Downgrade Protocol |
| Deterministic judge selection | [03-security-trust.md](03-security-trust.md) | Deterministic Judge Selection |
| DKG recovery protocol | [04-cryptographic-protocols.md](04-cryptographic-protocols.md) | DKG Recovery Protocol |
| DKG abort prevention | [04-cryptographic-protocols.md](04-cryptographic-protocols.md) | DKG Abort Griefing Prevention |
| DKG disruption accountability | [04-cryptographic-protocols.md](04-cryptographic-protocols.md) | DKG Disruption Accountability System |
| DKG penalty enforcement | [04-cryptographic-protocols.md](04-cryptographic-protocols.md) | Penalty Tiers and Enforcement |
| DKG appeals process | [04-cryptographic-protocols.md](04-cryptographic-protocols.md) | Appeals Process |
| Anti-cartel CA selection | [05-certificate-authority.md](05-certificate-authority.md) | Anti-Cartel VRF-Based Selection |
| 3PC coordinator slashing | [06-consensus-coordination.md](06-consensus-coordination.md) | 3PC Coordinator Slashing |
| Cross-shard lock TTL | [07-currency-transactions.md](07-currency-transactions.md) | Cross-Shard Lock TTL |
| VRF-based pool selection | [12-secure-content-storage.md](12-secure-content-storage.md) | VRF-Based Pool Selection |
| Distributed manifest security | [12-secure-content-storage.md](12-secure-content-storage.md) | Distributed Manifest Security |
| Share distribution protocol | [12-secure-content-storage.md](12-secure-content-storage.md) | Share Distribution Protocol |
| Client requirements | [13-service-discovery.md](13-service-discovery.md) | Client Requirements |
| Client eligibility | [13-service-discovery.md](13-service-discovery.md) | Client Eligibility Verification |
| Preset requirements | [13-service-discovery.md](13-service-discovery.md) | Preset Requirement Templates |
| Judge anti-collusion | [09-defense-reputation.md](09-defense-reputation.md) | PBFT-Style Quorum Judgment |
| Confirmation ring prevention | [09-defense-reputation.md](09-defense-reputation.md) | Confirmation Ring Prevention |
| Flash loan protection | [10-governance-economics.md](10-governance-economics.md) | Flash Loan Protection |
| Work credits system | [10-governance-economics.md](10-governance-economics.md) | Work Credits System |
| Weighted gateway selection | [10-governance-economics.md](10-governance-economics.md) | Weighted Gateway Selection |
| Service requirements | [20-service-provider-requirements.md](20-service-provider-requirements.md) | ServiceRequirements Structure |
| Provider trust requirements | [20-service-provider-requirements.md](20-service-provider-requirements.md) | Provider-Configurable Requirements |
| Requirement presets | [20-service-provider-requirements.md](20-service-provider-requirements.md) | Requirement Presets |
| AI arbitrator selection | [21-ai-arbitration-system.md](21-ai-arbitration-system.md) | AI Arbitrator Selection |
| AI arbitration process | [21-ai-arbitration-system.md](21-ai-arbitration-system.md) | AI Arbitration Process |
| Hybrid arbitration | [21-ai-arbitration-system.md](21-ai-arbitration-system.md) | Hybrid Arbitration |
| ArbitratorType enum | [19-service-contracts.md](19-service-contracts.md) | ArbitratorType Selection |
| AI arbitrator config | [19-service-contracts.md](19-service-contracts.md) | AIArbitratorConfig |
| Quantum-resistant crypto | [03-security-trust.md](03-security-trust.md) | Quantum-Resistant Cryptography |
| ML-DSA signatures | [03-security-trust.md](03-security-trust.md) | Quantum-Safe Signature Operations |
| ML-KEM encryption | [03-security-trust.md](03-security-trust.md) | Hybrid Encryption Scheme |
| Quantum migration strategy | [03-security-trust.md](03-security-trust.md) | Migration Strategy |
| SDN network isolation | [02-network-architecture.md](02-network-architecture.md) | SDN Integration for Network Isolation |
| VLAN-based isolation | [02-network-architecture.md](02-network-architecture.md) | VLAN-Based Network Isolation |
| 802.1X port authentication | [02-network-architecture.md](02-network-architecture.md) | 802.1X Port-Based Authentication |
| OpenFlow integration | [02-network-architecture.md](02-network-architecture.md) | OpenFlow 1.3 Integration |
| QuicBaaS integration | [01-system-overview.md](01-system-overview.md) | Platform Services Integration |
| QuicBaaS IAM | [01-system-overview.md](01-system-overview.md) | IAM: Multi-Tenant Identity |
| QuicBaaS KMS | [01-system-overview.md](01-system-overview.md) | KMS: Distributed Key Management |
| QuicBaaS secrets | [01-system-overview.md](01-system-overview.md) | Secrets: Vault-Style Management |
| QuicBaaS object storage | [01-system-overview.md](01-system-overview.md) | Object Storage (Native API) |
| QuicBaaS vector search | [01-system-overview.md](01-system-overview.md) | Vector Search: HNSW Indexing |
| GPU compute resources | [19-service-contracts.md](19-service-contracts.md) | GPU Compute Resources |
| GPU passthrough | [19-service-contracts.md](19-service-contracts.md) | GPU Passthrough via QEMU/KVM |
| GPU attestation | [19-service-contracts.md](19-service-contracts.md) | GPU Attestation Requirements |
| GPU pricing model | [19-service-contracts.md](19-service-contracts.md) | GPU Pricing Model |
| Genesis trustee safeguards | [04-cryptographic-protocols.md](04-cryptographic-protocols.md) | Genesis Trustee Recovery Safeguards |
| CT log fork resistance | [04-cryptographic-protocols.md](04-cryptographic-protocols.md) | CT Log Fork Resistance |
| Adaptive CA threshold | [04-cryptographic-protocols.md](04-cryptographic-protocols.md) | Adaptive CA Pool Threshold |
| Quantum migration security | [03-security-trust.md](03-security-trust.md) | Quantum Migration Security |
| Quantum downgrade protection | [03-security-trust.md](03-security-trust.md) | Downgrade Attack Prevention |
| TPM quote timing security | [03-security-trust.md](03-security-trust.md) | TPM Quote Timing Security |
| Network-aware freshness | [03-security-trust.md](03-security-trust.md) | Network-Aware Freshness Windows |
| VLAN security hardening | [02-network-architecture.md](02-network-architecture.md) | VLAN Security Hardening |
| MAC spoofing prevention | [02-network-architecture.md](02-network-architecture.md) | Anti-Spoof OpenFlow Rules |
| Network efficiency at scale | [02-network-architecture.md](02-network-architecture.md) | Network Efficiency at Scale |
| IPv6 /36 capacity analysis | [02-network-architecture.md](02-network-architecture.md) | IPv6 /36 Capacity Analysis |
| Negative caching | [02-network-architecture.md](02-network-architecture.md) | NegativeCache Implementation |
| Message batching | [02-network-architecture.md](02-network-architecture.md) | MessageBatcher Implementation |
| RTT-aware peer selection | [02-network-architecture.md](02-network-architecture.md) | RTTTracker Implementation |
| GPU security hardening | [19-service-contracts.md](19-service-contracts.md) | GPU Security and Attestation Hardening |
| GPU attestation chain | [19-service-contracts.md](19-service-contracts.md) | GPUAttestationChain Verification |
| Periodic GPU re-attestation | [19-service-contracts.md](19-service-contracts.md) | PeriodicGPUReAttestation |
| Vector search isolation | [01-system-overview.md](01-system-overview.md) | Vector Search Tenant Isolation |
| Cross-tenant protection | [01-system-overview.md](01-system-overview.md) | Cross-Tenant Attack Vectors |
| FROST signer selection | [04-cryptographic-protocols.md](04-cryptographic-protocols.md) | Deterministic Signer Selection |
| FROST nonce pool | [04-cryptographic-protocols.md](04-cryptographic-protocols.md) | Nonce Pool Management |
| FROST share storage | [25-kms-frost-lifecycle.md](25-kms-frost-lifecycle.md) | Share Storage Format |
| FROST share rotation | [25-kms-frost-lifecycle.md](25-kms-frost-lifecycle.md) | FROST Share Refresh Protocol |
| FROST share backup | [25-kms-frost-lifecycle.md](25-kms-frost-lifecycle.md) | Backup and Recovery |
| DKG commit-reveal | [04-cryptographic-protocols.md](04-cryptographic-protocols.md) | DKG Commit-Reveal Protocol |
| DKG state transfer | [04-cryptographic-protocols.md](04-cryptographic-protocols.md) | DKG Coordinator State Transfer |
| QuicBaaS schema | [24-quicbaas-schema.md](24-quicbaas-schema.md) | Schema Definitions |
| DHT key naming | [24-quicbaas-schema.md](24-quicbaas-schema.md) | Key Naming Conventions |
| Schema migrations | [24-quicbaas-schema.md](24-quicbaas-schema.md) | Migration Scripts |
| VRF commit-reveal | [06-consensus-coordination.md](06-consensus-coordination.md) | VRF Seed Commit-Reveal Scheme |
| Fencing tokens | [06-consensus-coordination.md](06-consensus-coordination.md) | Fencing Tokens |
| 3PC termination | [07-currency-transactions.md](07-currency-transactions.md) | 3PC Termination Protocol |
| Coordinator heartbeat | [07-currency-transactions.md](07-currency-transactions.md) | Coordinator Heartbeat During 3PC |
| Coordinator slashing | [07-currency-transactions.md](07-currency-transactions.md) | Coordinator Accountability and Slashing |
| Role eligibility staggering | [09-defense-reputation.md](09-defense-reputation.md) | Role Eligibility Staggering |
| Promotion anomaly detection | [09-defense-reputation.md](09-defense-reputation.md) | Promotion Anomaly Detection |
| AI model governance | [21-ai-arbitration-system.md](21-ai-arbitration-system.md) | AI Model Governance |
| Bias detection | [21-ai-arbitration-system.md](21-ai-arbitration-system.md) | Bias Detection Framework |
| Clock synchronization | [03-security-trust.md](03-security-trust.md) | Clock Synchronization Parameters |
| EK certificate CT | [03-security-trust.md](03-security-trust.md) | Certificate Transparency for TPM EK |
| Rolling upgrade | [11-operations.md](11-operations.md) | Rolling Upgrade Procedure |
| Node recovery | [11-operations.md](11-operations.md) | Node Recovery Procedure |
| Disaster recovery | [11-operations.md](11-operations.md) | Disaster Recovery Procedures |
| DHT routing cache | [02-network-architecture.md](02-network-architecture.md) | DHT Routing Optimizations |
| Eclipse attack prevention | [02-network-architecture.md](02-network-architecture.md) | Eclipse Attack Prevention |
| Hot key handling | [02-network-architecture.md](02-network-architecture.md) | Hot Key Handling |
| Counting Bloom filter | [16-ddos-protection.md](16-ddos-protection.md) | Counting Bloom Filter |
| Rate limit state | [16-ddos-protection.md](16-ddos-protection.md) | Rate Limit State Management |
| BGP security | [16-ddos-protection.md](16-ddos-protection.md) | BGP Security and Route Validation |
| PBFT phase timeouts | [06-consensus-coordination.md](06-consensus-coordination.md) | PBFT Phase Timeouts |
| Partition detection thresholds | [06-consensus-coordination.md](06-consensus-coordination.md) | Partition Detection Thresholds |
| Three-way partition resolution | [06-consensus-coordination.md](06-consensus-coordination.md) | Edge Cases and Complex Partitions |
| Partition timeout escalation | [06-consensus-coordination.md](06-consensus-coordination.md) | Partition Timeout Escalation |
| Hierarchical CA architecture | [05-certificate-authority.md](05-certificate-authority.md) | Hierarchical CA Architecture for Ultra-Scale |
| CA pool scaling | [05-certificate-authority.md](05-certificate-authority.md) | Scaling Thresholds |
| Regional CA routing | [05-certificate-authority.md](05-certificate-authority.md) | HierarchicalCARouter |
| Federation overview | [22-federation.md](22-federation.md) | Overview |
| Federated P2P mode concept | [22-federation.md](22-federation.md) | Federated P2P Mode Concept |
| Cross-certification protocol | [22-federation.md](22-federation.md) | Cross-Certification Protocol |
| Federation trust model | [22-federation.md](22-federation.md) | Trust Model: Hierarchical with Cross-Certification |
| Dual identity (FROST + Local) | [22-federation.md](22-federation.md) | Device Identity Options |
| Peering agreements | [22-federation.md](22-federation.md) | Peering Agreements |
| Federation configuration | [22-federation.md](22-federation.md) | Configuration Example |
| Federation use cases | [22-federation.md](22-federation.md) | Use Cases |
| P2P DNS 4-layer architecture | [23-p2p-dns.md](23-p2p-dns.md) | P2P DNS Architecture |
| Automatic DNS namespace | [23-p2p-dns.md](23-p2p-dns.md) | Layer 1: P2P DNS Namespace |
| DHT-DNS records | [23-p2p-dns.md](23-p2p-dns.md) | Layer 2: DHT-DNS Records |
| Gateway DNS service | [23-p2p-dns.md](23-p2p-dns.md) | Layer 3: Gateway DNS Service |
| Custom domains | [23-p2p-dns.md](23-p2p-dns.md) | Layer 4: Custom Domain Support |
| DNSSEC key hierarchy | [23-p2p-dns.md](23-p2p-dns.md) | DNSSEC Key Hierarchy |
| DNS security model | [23-p2p-dns.md](23-p2p-dns.md) | Security Considerations |

---

## Architecture Layers

```
+-----------------------------------------------------------------------+
|                         APPLICATION LAYER                             |
|  +--------------+ +--------------+ +--------------+ +--------------+  |
|  |    Wallet    | |  Git Repos   | |  OS Images   | |   Updates    |  |
|  +------+-------+ +------+-------+ +------+-------+ +------+-------+  |
+---------|----------------|----------------|----------------|----------+
          |                |                |                |
+-----------------------------------------------------------------------+
|                           SERVICE LAYER                               |
|  +--------------+ +--------------+ +--------------+ +--------------+  |
|  |   Currency   | |   Content    | |    Boot      | |   Registry   |  |
|  |  (Sharded)   | |   Storage    | |   Server     | |  (Approval)  |  |
|  +------+-------+ +------+-------+ +------+-------+ +------+-------+  |
+---------|----------------|----------------|----------------|----------+
          |                |                |                |
+-----------------------------------------------------------------------+
|                          CONSENSUS LAYER                              |
|  +--------------+ +--------------+ +--------------+ +--------------+  |
|  | Coordinator  | |   Defense    | |  Reputation  | |  Governance  |  |
|  |   (PBFT)     | |   (Quorum)   | |    System    | |   (Voting)   |  |
|  +------+-------+ +------+-------+ +------+-------+ +------+-------+  |
+---------|----------------|----------------|----------------|----------+
          |                |                |                |
+-----------------------------------------------------------------------+
|                        CRYPTOGRAPHIC LAYER                            |
|  +--------------+ +--------------+ +--------------+ +--------------+  |
|  |    FROST     | |     DKG      | |      CA      | |     TPM      |  |
|  |  Signatures  | |   Protocol   | |   (IDevID)   | |  Attestation |  |
|  +------+-------+ +------+-------+ +------+-------+ +------+-------+  |
+---------|----------------|----------------|----------------|----------+
          |                |                |                |
+-----------------------------------------------------------------------+
|                           NETWORK LAYER                               |
|  +--------------+ +--------------+ +--------------+ +--------------+  |
|  |   Kademlia   | |  P2P Swarm   | |    IPv6      | |     BGP      |  |
|  |     DHT      | |   (Blocks)   | | 2001:db8::   | |   Routing    |  |
|  +--------------+ +--------------+ +--------------+ +--------------+  |
+-----------------------------------------------------------------------+
```

---

## Node Roles

All role eligibility thresholds are defined in [09-defense-reputation.md](09-defense-reputation.md) (CANONICAL).

| Role | Reputation | Min Days | Capabilities |
|------|------------|----------|--------------|
| **Leaf** | 0.0+ | 0 | DHT routing, transaction confirmation |
| **CA Participant** | 0.90+ | 120 | Certificate generation, trust decisions |
| **Hub** | 0.80+ | 110 | Routing hub, regional caching |
| **Gateway** | 0.85+ | 175 | External connectivity, IPv4 bridge |
| **AI Arbitrator** | 0.85+ | — | Contract dispute resolution |
| **Coordinator** | 0.95+ | 185 | Consensus leadership, governance |

---

## DHT Key Patterns

```
Content Blocks:     block:{sha256-hash}
File Manifests:     manifest:{type}:{identifier}
OS Images:          os:{distro}:{version}:{arch}:{variant}
Git Repos:          git:{org}:{repo}:{branch}
Updates:            update:{package}:{version}
Update Channel:     updates:{package}:latest
Approved Repos:     approved-repos:{org}:{repo}
Node Info:          node:{node-id}
Reputation:         rep:{node-id}
Transactions:       tx:{txid}
Shard State:        shard:{shard-id}:state
KSP Manifest:       ksp:{owner-id}:{content-hash}
KSP Block:          kspblock:{pool}:{block-hash}

Service Discovery:
Service:            service:{service-id}
Services by Type:   services:type:{service-type}
Services by Tag:    services:tag:{tag}
Services by Node:   services:node:{node-id}
Search Cache:       services:search:{hash}

AI Agent Collaboration:
Agent:              agent:{agent-id}
Agents by Node:     agent:node:{node-id}
Agents by Cap:      agent:capability:{capability}
Chat Room:          room:{room-id}
Room Members:       room:members:{room-id}
Room Messages:      room:messages:{room-id}:{timestamp}
Task:               task:{task-id}
Subtask:            task:subtask:{subtask-id}

DDoS Protection:
Threat Report:         threat:{ip-hash}
IP Reputation:         iprep:{ip-hash}
PoW Solution:          pow:{solution-hash}
Blacklist:             blacklist:{ip-hash}

Service Contracts:
Contract:              contract:{contract-id}
Provider Contracts:    contract:provider:{node-id}
Consumer Contracts:    contract:consumer:{node-id}
Contract by Type:      contract:type:{service-type}
Escrow State:          contract:escrow:{contract-id}

P2P DNS:
DNS Record:            dns:{domain}:{record-type}
Domain Owner:          domain-owner:{domain}
DNS Zone:              dns-zone:{zone}
Gateway DNS Index:     dns-gateway:{gateway-id}

Federation:
Cross-Cert:            cross-cert:{issuer-hash}:{subject-hash}
Federation Registry:   fed-registry:{node-id}
Peering Agreement:     peering:{org-a}:{org-b}
```

---

## Security Model Summary

Full security architecture in [03-security-trust.md](03-security-trust.md).

| Principle | Implementation |
|-----------|----------------|
| **Zero Trust** | All nodes start at reputation 0.0 |
| **TPM Required** | All nodes must have TPM (hardware or swtpm) |
| **Binary Trust** | Trusted (hardware TPM + whitelisted EK) or Untrusted (all other) |
| **Hardware RNG** | TPM2/PKCS#11 priority, software fallback only |
| **FROST Signatures** | 4-pool threshold signatures (t=33%) |
| **Measured Boot** | TPM PCR chain from UEFI to application |
| **Evidence-Based Defense** | TPM-attested proofs for violations |
| **IDevID via Privacy CA** | Nodes obtain IDevID via ACME enroll-01 challenge |
| **Non-Configurable Security** | Core parameters are compile-time constants |

### Key Security Constants

```
TPM Version:        2.0 (required)
Quote Freshness:    +/-100ms
CA Threshold:       33%
CA Pool Size:       0.1% of network (min 100, max 10M)
CA Rotation:        1 hour
Kademlia K:         20
Kademlia Alpha:     3
```

---

## Implementation Status

| Component | Package | Status |
|-----------|---------|--------|
| Content Storage | `pkg/content/` | Planned |
| Update System | `pkg/updates/` | Planned |
| OS Images | `pkg/osimage/` | Planned |
| Boot System | `pkg/boot/` | Planned — the existing `pkg/boot/` is the platform's local boot-manager CLI, not a DHT boot server |
| Defense System | `pkg/defense/` | Planned |
| Git Storage | `pkg/git/` | Planned |
| DHT Core | `pkg/dht/core/` | Planned |
| Service Discovery | `pkg/dht/discovery/` | Planned |
| Browser Gateway | `pkg/dht/gateway/` | Planned |
| AI Agent Collaboration | `pkg/dht/agent/` | Planned |
| DDoS Protection | `pkg/defense/ddos/` | Planned |
| Untrusted Node Work | `pkg/defense/work/` | Planned |
| Service Contracts | `pkg/dht/contract/` | Planned |
| Service Requirements | `pkg/dht/requirements/` | Planned |
| AI Arbitration | `pkg/dht/arbitration/` | Planned |
| P2P DNS | `pkg/dht/dns/` | Planned |
| Federation | `pkg/dht/federation/` | Planned |

---

## Document Conventions

- **CANONICAL**: Sections marked as canonical are the single source of truth for that topic
- **Cross-References**: Documents reference each other by filename and section
- **Code Examples**: All code examples are from actual implementation or planned implementation
- **Version History**: Each document includes revision history at the end

---

**Document Version**: 1.8
**Last Updated**: 2026-01-10
**Consolidated From**: 31 original documents + 13 new feature documents
**Architecture Review**: VRF commit-reveal, fencing tokens, partition-aware PBFT, 3PC termination protocol, hierarchical CA, DKG state transfer
**Platform Integration**: Quantum-resistant crypto (ML-DSA/ML-KEM), SDN/VLAN isolation, go-quicbaas (IAM/KMS/Secrets), GPU compute
**Network Scale**: IPv6 /36 capacity analysis, hierarchical CA for 1B+ nodes, network efficiency optimizations
**Federation**: Cross-certification, P2P DNS, zero-trust security model
**New Documents**: 24-quicbaas-schema.md (DHT storage), 25-kms-frost-lifecycle.md (FROST share management)
