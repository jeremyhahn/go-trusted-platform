# System Overview

> **Status: PLANNED** · Scope: design only, no implementation · Last verified: 2026-10-20

This document shows how all components of the Trusted DHT system fit together.

> **Note**: For canonical reputation thresholds and role eligibility requirements, see [09-defense-reputation.md](09-defense-reputation.md) Section "Role Eligibility Thresholds (CANONICAL)".

## High-Level Architecture

```
                            TRUSTED DHT NETWORK
+-------------------------------------------------------------------------+
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  |                 COORDINATOR LAYER (Rep 0.95+)                     |  |
|  |  +-----------------------------------------------------+          |  |
|  |  |              21-Node PBFT Committee                 |          |  |
|  |  |  +-----+ +-----+ +-----+     +-------+ +-------+    |          |  |
|  |  |  | C1  | | C2  | | ... | ... | C20   | | C21   |    |          |  |
|  |  |  +--+--+ +--+--+ +--+--+     +---+---+ +---+---+    |          |  |
|  |  |     +------+-------+-----------+----------+         |          |  |
|  |  |                    | Consensus Decisions            |          |  |
|  |  +--------------------+--------------------------------+          |  |
|  +---------------------------+---------------------------------------+  |
|                              |                                          |
|  +---------------------------+---------------------------------------+  |
|  |                    GATEWAY LAYER (Rep 0.85+)                      |  |
|  |  +-------------+ +-------------+ +-------------+                  |  |
|  |  |  Gateway 1  | |  Gateway 2  | |  Gateway 3  | ...              |  |
|  |  | IPv4 Bridge | | Boot Server | | Content CDN |                  |  |
|  |  +------+------+ +------+------+ +------+------+                  |  |
|  +---------+--------------+--------------+---------------------------+  |
|            |              |              |                              |
|  +---------+--------------+--------------+---------------------------+  |
|  |                      HUB LAYER (Rep 0.80+)                        |  |
|  |  +-------------+ +-------------+ +-------------+                  |  |
|  |  |    Hub 1    | |    Hub 2    | |    Hub 3    | ...              |  |
|  |  |  Routing    | |  Routing    | |  Routing    |                  |  |
|  |  | Multi-Rgn   | | Multi-Rgn   | | Multi-Rgn   |                  |  |
|  |  +------+------+ +------+------+ +------+------+                  |  |
|  +---------+--------------+--------------+---------------------------+  |
|            |              |              |                              |
|  +---------+--------------+--------------+---------------------------+  |
|               CA PARTICIPANT LAYER (Rep 0.90+)                    |  |
|  |  +--------------+ +--------------+ +--------------+               |  |
|  |  |  CA Pool 1   | |  CA Pool 2   | |  CA Pool 3   | ... (4)       |  |
|  |  | FROST Signer | | FROST Signer | | FROST Signer |               |  |
|  |  +------+-------+ +------+-------+ +------+-------+               |  |
|  |         +--------------------+--------------------+               |  |
|  |                              | IDevID Certificates                |  |
|  +------------------------------+------------------------------------+  |
|                                 |                                       |
|  +------------------------------+------------------------------------+  |
|  |                    LEAF NODE LAYER (Rep 0.0+)                     |  |
|  |  +-----+ +-----+ +-----+ +-----+ +-----+ +-----+ +-----+          |  |
|  |  |Leaf | |Leaf | |Leaf | |Leaf | |Leaf | |Leaf | |Leaf | ...      |  |
|  |  +-----+ +-----+ +-----+ +-----+ +-----+ +-----+ +-----+          |  |
|  |                     Kademlia DHT Routing                          |  |
|  +-------------------------------------------------------------------+  |
|                                                                         |
+-------------------------------------+-----------------------------------+
                                      |
                                      v
+-------------------------------------+-----------------------------------+
|                         QUICBAAS PLATFORM LAYER                         |
|  +-------------+ +-------------+ +-------------+ +-------------+        |
|  |  Database   | |    IAM      | |    KMS      | |   Secrets   |        |
|  | Multi-Raft  | | ABAC Policy | | TPM/PKCS#11 | |  Vault-API  |        |
|  +------+------+ +------+------+ +------+------+ +------+------+        |
|         |              |              |              |                  |
|  +------+--------------+--------------+--------------+------+           |
|  |               QuicBaaS Service Mesh                      |           |
|  +------+--------------+--------------+--------------+------+           |
|         |              |              |              |                  |
|  +------+------+ +-----+------+ +-----+------+ +-----+------+           |
|  |   Object    | |   Vector   | |   Event    | |   Audit    |           |
|  |   Storage   | |   Search   | |   Stream   | |   Trail    |           |
|  +-------------+ +------------+ +------------+ +------------+           |
+-------------------------------------------------------------------------+
                                  |
                                  | IPv6: 2001:db8::/36
                                  v
                            [ INTERNET ]
```

### Role Summary (Canonical Thresholds)

| Role | Reputation | Capabilities |
|------|------------|--------------|
| Coordinator | 0.95+ | Network-wide coordination, consensus leadership, emergency governance |
| Gateway | 0.85+ | Bridge to external networks, API endpoints, protocol translation |
| Hub | 0.80+ | Routing hub, multi-region connections, data caching |
| CA Participant | 0.90+ | FROST signing, certificate generation, trust decisions |
| Leaf | 0.0+ | DHT routing, transaction confirmation, basic participation |

## Component Interaction Map

```
+--------------------------------------------------------------------------+
|                         TRUSTED DHT COMPONENTS                           |
+--------------------------------------------------------------------------+
|                                                                          |
|  +----------------+        +----------------+        +----------------+  |
|  |    NETWORK     |        |    SECURITY    |        |   CONSENSUS    |  |
|  |                |        |                |        |                |  |
|  | - Kademlia DHT |<------>| - TPM          |<------>| - Coordinator  |  |
|  | - P2P Swarm    |        | - FROST CA     |        | - PBFT(21-node)|  |
|  | - IPv6 Routing |        | - Key Mgmt     |        | - VRF Selection|  |
|  | - BGP Announce |        | - Attestation  |        | - Quorum Vote  |  |
|  +-------+--------+        +-------+--------+        +-------+--------+  |
|          |                         |                         |           |
|          |                         |                         |           |
|          v                         v                         v           |
|  +----------------+        +----------------+        +----------------+  |
|  |    STORAGE     |        |   REPUTATION   |        |    DEFENSE     |  |
|  |                |        |                |        |                |  |
|  | - Content Blks |<------>| - Score Track  |<------>| - Monitoring   |  |
|  | - Merkle Trees |        | - Role Promo   |        | - Evidence     |  |
|  | - Manifests    |        | - Bootstrapping|        | - Judgment     |  |
|  | - Git Bundles  |        | - Decay/Growth |        | - Penalties    |  |
|  +-------+--------+        +-------+--------+        +-------+--------+  |
|          |                         |                         |           |
|          |                         |                         |           |
|          v                         v                         v           |
|  +----------------+        +----------------+        +----------------+  |
|  |    CURRENCY    |        |   GOVERNANCE   |        |  DISTRIBUTION  |  |
|  |                |        |                |        |                |  |
|  | - UTXO Ledger  |<------>| - Upgrades     |<------>| - OS Images    |  |
|  | - Sharding     |        | - Voting       |        | - Updates      |  |
|  | - Cross-Shard  |        | - Partitions   |        | - Boot Server  |  |
|  | - Economics    |        | - Privacy Opts |        | - Git Registry |  |
|  +-------+--------+        +-------+--------+        +-------+--------+  |
|          |                         |                         |           |
|          +-------------------------+-------------------------+           |
|                                    |                                     |
|                                    v                                     |
|  +------------------------------------------------------------------+   |
|  |                    QUICBAAS PLATFORM SERVICES                     |   |
|  |                                                                   |   |
|  |  +------------+ +------------+ +------------+ +------------+      |   |
|  |  |  Database  | |    IAM     | |    KMS     | |  Secrets   |      |   |
|  |  +------------+ +------------+ +------------+ +------------+      |   |
|  |  +------------+ +------------+ +------------+ +------------+      |   |
|  |  |   Object   | |   Vector   | |   Event    | |   Audit    |      |   |
|  |  |  Storage   | |   Search   | |   Stream   | |   Trail    |      |   |
|  |  +------------+ +------------+ +------------+ +------------+      |   |
|  +------------------------------------------------------------------+   |
|                                                                          |
+--------------------------------------------------------------------------+
```

## Data Flow Architecture

### Content Storage Flow

```
                    CONTENT STORAGE FLOW

Producer                    DHT Network                   Consumer
--------                    -----------                   --------

+---------+
|  File   |
| (10 GB) |
+----+----+
     |
     v
+-------------+
| Chunk into  |
| 1MB Blocks  |
+-----+-------+
      |
      v
+-------------+         +---------------------+
|Build Merkle |         |                     |
|    Tree     |         |                     |
+-----+-------+         |                     |
      |                 |    DHT Storage      |
      v                 |                     |
+-------------+         |  block:abc123...    |<--------+
|FROST Sign   |-------->|  block:def456...    |         |
| Manifest    |         |  block:789abc...    |         |
+-------------+         |  manifest:file:xyz  |         |
                        |                     |         |
                        +---------------------+         |
                                                        |
                                              +---------+----+
                                              | Fetch Blocks |
                                              | via P2P Swarm|
                                              +---------+----+
                                                        |
                                              +---------v----+
                                              |Verify Merkle |
                                              |   + FROST    |
                                              +---------+----+
                                                        |
                                              +---------v----+
                                              |  Reassemble  |
                                              |    File      |
                                              +--------------+
```

### Network Boot Flow

```
                          NETWORK BOOT FLOW

+-----------------------------------------------------------------------+
|                                                                       |
|  1. POWER ON                                                          |
|     |                                                                 |
|     v                                                                 |
|  +-------------+    2. UEFI Secure Boot verifies iPXE                 |
|  |    UEFI     |-------------------------------------+                |
|  |  Firmware   |                                     |                |
|  +-------------+                                     v                |
|                                             +-------------+           |
|                                             |    iPXE     |           |
|                                             |  Firmware   |           |
|                                             +------+------+           |
|                                                    |                  |
|  3. iPXE fetches boot script from gateway          |                  |
|     +----------------------------------------------+                  |
|     |                                                                 |
|     v                                                                 |
|  +-------------+    4. Boot menu displayed                            |
|  |   Gateway   |-------------------------------------+                |
|  | Boot Server |                                     |                |
|  +-------------+                                     v                |
|                                             +-------------+           |
|                                             | OS Selection|           |
|                                             |Alpine/Ubuntu|           |
|                                             |   /Fedora   |           |
|                                             +------+------+           |
|                                                    |                  |
|  5. Download kernel + initramfs from DHT           |                  |
|     +----------------------------------------------+                  |
|     |                                                                 |
|     v                                                                 |
|  +-------------+    TPM measures each stage (PCR extend)              |
|  |    DHT      |-------------------------------------+                |
|  |   Network   |                                     |                |
|  +-------------+                                     v                |
|                                             +-------------+           |
|                                             |   TPM 2.0   |           |
|                                             | PCR 0,1,2,4 |           |
|                                             | PCR 7,8,9,14|           |
|                                             +------+------+           |
|                                                    |                  |
|  6. Initramfs runs provisioning                    |                  |
|     +----------------------------------------------+                  |
|     |                                                                 |
|     v                                                                 |
|  +---------------------------------------------------------------+    |
|  |                       PROVISIONING                            |    |
|  |  +---------+  +---------+  +---------+  +---------+           |    |
|  |  |Generate |  |   TPM   |  | Request |  |  Join   |           |    |
|  |  |Identity |->| Attest- |->| IDevID  |->|   DHT   |           |    |
|  |  |   Key   |  |  ation  |  |  Cert   |  | Network |           |    |
|  |  +---------+  +---------+  +---------+  +---------+           |    |
|  +---------------------------------------------------------------+    |
|                                                                       |
|  7. Node joins network as leaf (reputation = 0.0)                     |
|                                                                       |
+-----------------------------------------------------------------------+
```

### Transaction Flow (Cross-Shard)

```
                    CROSS-SHARD TRANSACTION FLOW

+----------------------------------------------------------------------------+
|                                                                            |
|  Sender (Shard 0)              Coordinator              Receiver (Shard 2) |
|  ------------------            -----------              -----------------  |
|                                                                            |
|  +-------------+                                                           |
|  | Create Tx   |                                                           |
|  | Input: S0   |                                                           |
|  | Output: S2  |                                                           |
|  +------+------+                                                           |
|         |                                                                  |
|         | 1. Submit                                                        |
|         v                                                                  |
|  +------------------------------------------------------------------+      |
|  |                    PHASE 1: PREPARE                              |      |
|  |                                                                  |      |
|  |  Shard 0                 Coordinator                Shard 2      |      |
|  |  +---------+            +---------+               +---------+    |      |
|  |  | Lock    |<-----------|Prepare  |-------------->| Reserve |    |      |
|  |  | Input   |            | Request |               | Space   |    |      |
|  |  +----+----+            +----+----+               +----+----+    |      |
|  |       |                      |                         |         |      |
|  |       | PREPARED             |               PREPARED  |         |      |
|  |       +----------------------+-------------------------+         |      |
|  +----------------------------------+-------------------------------+      |
|                                 |                                          |
|  +------------------------------+-----------------------------------+      |
|  |                    PHASE 2: COMMIT                               |      |
|  |                              |                                   |      |
|  |  Shard 0            +-------+-------+               Shard 2      |      |
|  |  +---------+        |   Commit      |              +---------+   |      |
|  |  | Consume |<-------|   Decision    |------------->| Create  |   |      |
|  |  | Input   |        |(7-of-21 PBFT) |              | Output  |   |      |
|  |  +----+----+        +-------+-------+              +----+----+   |      |
|  |       |                     |                           |        |      |
|  |       | COMMITTED           |              COMMITTED    |        |      |
|  |       +---------------------+---------------------------+        |      |
|  +---------------------------------+--------------------------------+      |
|                                |                                           |
|  +-----------------------------+------------------------------------+      |
|  |                    PHASE 3: COMPLETE                             |      |
|  |                             |                                    |      |
|  |  Shard 0            +------+------+                 Shard 2      |      |
|  |  +---------+        |  Complete   |                +---------+   |      |
|  |  | Release |<-------|    Tx       |--------------->| Confirm |   |      |
|  |  |  Lock   |        |             |                |  UTXO   |   |      |
|  |  +---------+        +-------------+                +---------+   |      |
|  +------------------------------------------------------------------+      |
|                                                                            |
+----------------------------------------------------------------------------+
```

### Defense and Penalty Flow

```
                    COLLABORATIVE DEFENSE FLOW

+------------------------------------------------------------------------+
|                                                                         |
|  Observer Nodes                Judgment                    Accused Node |
|  --------------                --------                    ------------ |
|                                                                         |
|  +-------------+                                                        |
|  |  Monitor    |                                                        |
|  |  Behavior   |                                                        |
|  | - Response  |                                                        |
|  | - Integrity |                                                        |
|  | - Protocol  |                                                        |
|  +------+------+                                                        |
|         |                                                               |
|         | Anomaly Detected                                              |
|         v                                                               |
|  +-------------+                                                        |
|  |  Collect    |                                                        |
|  |  Evidence   |                                                        |
|  | - TPM Quote |                                                        |
|  | - Logs      |                                                        |
|  | - Proofs    |                                                        |
|  +------+------+                                                        |
|         |                                                               |
|         | Submit Evidence                                               |
|         v                                                               |
|  +-----------------------------------------------------------------+    |
|  |                    EVIDENCE PACKET                              |    |
|  |  +-----------------------------------------------------------+  |    |
|  |  | PacketID:     SHA256(reporter||accused||timestamp)        |  |    |
|  |  | ReporterID:   node-abc123                                 |  |    |
|  |  | AccusedID:    node-xyz789                                 |  |    |
|  |  | Violation:    data_manipulation                           |  |    |
|  |  | Severity:     major                                       |  |    |
|  |  | TPMQuote:     <attested proof>                            |  |    |
|  |  | Signature:    <reporter signature>                        |  |    |
|  |  +-----------------------------------------------------------+  |    |
|  +------------------------------+----------------------------------+    |
|                             |                                           |
|  Corroboration Required     |                                           |
|  +--------------------------+--------------------------------------+    |
|  |                                                                  |   |
|  |  Observer 1          Observer 2          Observer 3              |   |
|  |  +---------+        +---------+        +---------+               |   |
|  |  |Confirm  |        |Confirm  |        |Confirm  |               |   |
|  |  |+Sign    |        |+Sign    |        |+Sign    |               |   |
|  |  +----+----+        +----+----+        +----+----+               |   |
|  |       +------------------+-------------------+                   |   |
|  |                         | Quorum Met (3+ corroborations)         |   |
|  +-------------------------+----------------------------------------+   |
|                            |                                            |
|                            v                                            |
|  +------------------------------------------------------------------+   |
|  |                    JUDGMENT (PBFT)                               |   |
|  |                                                                  |   |
|  |  +--+ +--+ +--+ +--+ +--+ +--+ +--+ +--+ +--+ +--+ +--+           |   |
|  |  |J1| |J2| |J3| |J4| |J5| |J6| |J7| |J8| |J9| |10| |11| 11 Judges|   |
|  |  |Y | |Y | |Y | |N | |Y | |Y | |Y | |N | |Y | |N | |N | 7-of-11  |   |
|  |  +--+ +--+ +--+ +--+ +--+ +--+ +--+ +--+ +--+ +--+ +--+ = GUILTY  |   |
|  |                                                                  |   |
|  |  NOTE: 7-of-11 quorum prevents judge collusion attacks.           |   |
|  |  See 09-defense-reputation.md for E1 mitigation details.         |   |
|  +-----------------------------+------------------------------------+   |
|                            |                                            |
|                            v                                            |
|  +------------------------------------------------------------------+   |
|  |                    PENALTY EXECUTION                             |   |
|  |                                                                  |   |
|  |  +------------------------------------------------------------+  |   |
|  |  | Severity: major                                            |  |   |
|  |  | Penalty:  -0.30 reputation + 1000 token slash              |  |   |
|  |  |                                                            |  |   |
|  |  | Reward Distribution:                                       |  |   |
|  |  |   Primary Reporter: 600 tokens (60%)                       |  |   |
|  |  |   Corroborators:    300 tokens (30% split)                 |  |   |
|  |  |   Treasury:         100 tokens (10%)                       |  |   |
|  |  +------------------------------------------------------------+  |   |
|  +------------------------------------------------------------------+   |
|                                                                         |
+-------------------------------------------------------------------------+
```

## Security Boundaries

```
+---------------------------------------------------------------------------+
|                         TRUST BOUNDARIES                                  |
+---------------------------------------------------------------------------+
|                                                                           |
|  HARDWARE ROOT OF TRUST                                                   |
|  +-----------------------------------------------------------------+      |
|  |  TPM 2.0                                                        |      |
|  |  +-- Sealed Identity Key (PCR 0,2,7)                            |      |
|  |  +-- Measured Boot Chain (PCR 0-9,14)                           |      |
|  |  +-- Attestation Quotes (Fresh Nonce)                           |      |
|  |  +-- Monotonic Counter (Replay Protection)                      |      |
|  +-----------------------------------------------------------------+      |
|                                    |                                      |
|                                    v                                      |
|  CRYPTOGRAPHIC TRUST                                                      |
|  +-----------------------------------------------------------------+      |
|  |  FROST Threshold Signatures                                     |      |
|  |  +-- 4 Signing Pools (t=33% threshold)                          |      |
|  |  +-- DKG for Key Generation                                     |      |
|  |  +-- Resharing on Pool Changes                                  |      |
|  |  +-- No Single Point of Failure                                 |      |
|  +-----------------------------------------------------------------+      |
|                                    |                                      |
|                                    v                                      |
|  DISTRIBUTED TRUST                                                        |
|  +-----------------------------------------------------------------+      |
|  |  Consensus Mechanisms                                           |      |
|  |  +-- PBFT (21-node, 7-of-21 threshold)                          |      |
|  |  +-- VRF Committee Selection (Unpredictable)                    |      |
|  |  +-- Reputation System (0.0 to 1.0)                             |      |
|  |  +-- Evidence-Based Penalties                                   |      |
|  +-----------------------------------------------------------------+      |
|                                    |                                      |
|                                    v                                      |
|  ZERO TRUST PERIMETER                                                     |
|  +-----------------------------------------------------------------+      |
|  |  Node Security                                                  |      |
|  |  +-- All Nodes Start at Reputation 0.0                          |      |
|  |  +-- Certificate Required (IDevID from CA)                      |      |
|  |  +-- Continuous Monitoring (Behavior)                           |      |
|  |  +-- Instant Revocation on Violation                            |      |
|  +-----------------------------------------------------------------+      |
|                                                                           |
+---------------------------------------------------------------------------+
```

## 8. Platform Services Integration

The Trusted DHT integrates with **go-quicbaas** to provide enterprise-grade platform services for state persistence, identity management, cryptographic operations, and content distribution. QuicBaaS serves as the foundational infrastructure layer beneath the DHT network.

### Integration Architecture

```
+-------------------------------------------------------------------------+
|                         TRUSTED DHT NETWORK                             |
|  +-------------------------------------------------------------------+  |
|  |  Coordinator | Gateway | Hub | CA Participant | Leaf Node         |  |
|  +-------------------------------+-----------------------------------+  |
+----------------------------------+--------------------------------------+
                                   |
                                   | gRPC / QUIC / Unix Socket
                                   v
+-------------------------------------------------------------------------+
|                       QUICBAAS PLATFORM SERVICES                        |
|                                                                         |
|  +-------------+  +-------------+  +-------------+  +-------------+     |
|  |  DATABASE   |  |    IAM      |  |    KMS      |  |   SECRETS   |     |
|  | Multi-Raft  |  | Multi-Tenant|  | TPM/PKCS#11 |  | Vault-Style |     |
|  |  KV Store   |  |    ABAC     |  |   /Cloud    |  |   Engine    |     |
|  +------+------+  +------+------+  +------+------+  +------+------+     |
|         |                |                |                |            |
|  +------+----------------+----------------+----------------+------+     |
|  |                   QuicBaaS Service Core                        |     |
|  +------+----------------+----------------+----------------+------+     |
|         |                |                |                |            |
|  +------+------+  +------+------+  +------+------+  +------+------+     |
|  |   OBJECT    |  |   VECTOR    |  |   EVENT     |  |   AUDIT     |     |
|  |   STORAGE   |  |   SEARCH    |  |   STREAM    |  |   TRAIL     |     |
|  | Native API  |  |    HNSW     |  |   Pub/Sub   |  | Immutable   |     |
|  +-------------+  +-------------+  +-------------+  +-------------+     |
|                                                                         |
+-------------------------------------------------------------------------+
```

### 8.1 Database: Multi-Raft Distributed KV Store

QuicBaaS provides a Multi-Raft distributed key-value store for DHT state persistence with strong consistency guarantees.

**DHT State Persisted:**
- Node routing tables and k-bucket state
- Reputation scores and history
- UTXO ledger shards
- Content manifests and block metadata
- Certificate revocation lists
- Governance proposals and votes

**Key Features:**
- Multi-Raft consensus across geographic regions
- Automatic sharding with consistent hashing
- Point-in-time recovery and snapshots
- Cross-region replication for disaster recovery

**API Usage:**
```go
// DHT node state persistence via QuicBaaS
db := quicbaas.NewClient(ctx, quicbaas.Config{
    Endpoints: []string{"quicbaas-1:9443", "quicbaas-2:9443"},
    TLSConfig: tlsConfig,
})

// Store routing table state
err := db.Put(ctx, "dht:routing:"+nodeID, routingTableBytes)

// Atomic reputation update with transaction
tx := db.Begin(ctx)
tx.Put("dht:reputation:"+nodeID, newScore)
tx.Put("dht:reputation:history:"+nodeID+":"+timestamp, delta)
tx.Commit()
```

### 8.2 IAM: Multi-Tenant Identity with ABAC Policies

QuicBaaS IAM provides multi-tenant identity management with Attribute-Based Access Control (ABAC) for fine-grained service authorization.

**Authorization Scopes:**
- Node role permissions (leaf, hub, gateway, coordinator, CA participant)
- Service-to-service authentication
- API endpoint access control
- Resource quotas per tenant/node

**ABAC Policy Example:**
```yaml
# QuicBaaS IAM policy for DHT coordinator access
apiVersion: iam.quicbaas.io/v1
kind: Policy
metadata:
  name: coordinator-access
spec:
  effect: allow
  principals:
    - role: coordinator
      reputationMin: 0.95
  actions:
    - dht:consensus:propose
    - dht:consensus:vote
    - dht:shard:coordinate
  conditions:
    - attribute: node.attestation.valid
      operator: equals
      value: true
    - attribute: node.certificate.notExpired
      operator: equals
      value: true
```

**Integration Points:**
- IDevID certificate validation
- TPM attestation verification
- Role-based capability assignment
- Audit logging of all authorization decisions

### 8.3 KMS: Distributed Key Management

QuicBaaS KMS provides distributed key management with multiple backend support for cryptographic operations.

**Supported Backends:**
- **TPM 2.0**: Hardware-bound keys for node identity and attestation
- **PKCS#11**: HSM integration for CA signing operations
- **Cloud KMS**: AWS KMS, GCP Cloud KMS, Azure Key Vault for hybrid deployments
- **Software**: Development and testing environments

**Key Types Managed:**
- Node identity keys (IDevID/LDevID)
- FROST signing shares for CA pools
- Encryption keys for content at rest
- Session keys for P2P communication

**API Usage:**
```go
// KMS operations via QuicBaaS
kms := quicbaas.NewKMSClient(ctx, kmsConfig)

// Sign with TPM-bound key
signature, err := kms.Sign(ctx, &kms.SignRequest{
    KeyID:     "tpm://node-identity",
    Algorithm: kms.ECDSA_P256_SHA256,
    Digest:    messageHash,
})

// Retrieve FROST signing share
share, err := kms.GetKey(ctx, &kms.GetKeyRequest{
    KeyID:   "frost://ca-pool-1/share-3",
    Backend: kms.BackendPKCS11,
})
```

### 8.4 Secrets: Vault-Style Secrets Management

QuicBaaS Secrets provides Vault-compatible secrets management for service credentials and sensitive configuration.

**Secret Types:**
- Bootstrap credentials for new nodes
- API keys for external service integration
- Database connection strings
- TLS certificates and private keys
- Encryption passphrases

**Features:**
- Dynamic secret generation with TTL
- Automatic rotation policies
- Lease management and renewal
- Encryption at rest with envelope encryption
- Access audit trail

**API Usage:**
```go
// Secrets management via QuicBaaS
secrets := quicbaas.NewSecretsClient(ctx, secretsConfig)

// Retrieve bootstrap credentials (auto-rotated)
cred, err := secrets.Get(ctx, &secrets.GetRequest{
    Path:    "dht/bootstrap/node-credentials",
    Version: secrets.VersionLatest,
})

// Store service credential with TTL
err = secrets.Put(ctx, &secrets.PutRequest{
    Path:  "dht/services/coordinator-api-key",
    Value: apiKeyBytes,
    TTL:   24 * time.Hour,
})
```

### 8.5 Object Storage: Native Content Distribution

QuicBaaS provides native object storage for content distribution, replacing traditional S3-style interfaces with a purpose-built API optimized for DHT workloads.

**Content Types Stored:**
- OS images and boot artifacts
- Software update packages
- Git bundle archives
- Large binary content blocks
- Merkle tree nodes

**Native API Advantages:**
- Streaming upload/download with backpressure
- Content-addressed storage with deduplication
- Integrated integrity verification
- Multi-region replication with consistency controls
- Direct DHT node access without gateway overhead

**API Usage:**
```go
// Object storage via QuicBaaS native API
objects := quicbaas.NewObjectClient(ctx, objectConfig)

// Store content block with content-addressing
result, err := objects.Put(ctx, &objects.PutRequest{
    Bucket:     "dht-content",
    Key:        "blocks/" + contentHash,
    Body:       blockReader,
    ContentMD5: md5Hash,
    Metadata: map[string]string{
        "manifest": manifestID,
        "index":    strconv.Itoa(blockIndex),
    },
})

// Stream retrieval with range support
reader, err := objects.Get(ctx, &objects.GetRequest{
    Bucket: "dht-content",
    Key:    "images/alpine-3.19-x86_64.iso",
    Range:  &objects.Range{Start: offset, End: offset + chunkSize},
})
```

### 8.6 Vector Search: AI Agent Capability Matching

QuicBaaS Vector Search provides HNSW (Hierarchical Navigable Small World) indexing for AI agent capability matching and semantic discovery.

**Use Cases:**
- Service capability discovery via semantic search
- AI agent skill matching for task routing
- Content similarity search for deduplication
- Anomaly detection in node behavior patterns

**Index Configuration:**
```go
// Vector search via QuicBaaS
vectors := quicbaas.NewVectorClient(ctx, vectorConfig)

// Create capability index
err := vectors.CreateIndex(ctx, &vectors.CreateIndexRequest{
    Name:       "agent-capabilities",
    Dimensions: 768,  // Embedding dimension
    Metric:     vectors.MetricCosine,
    Algorithm:  vectors.AlgorithmHNSW,
    HNSWConfig: &vectors.HNSWConfig{
        M:              16,
        EfConstruction: 200,
        EfSearch:       100,
    },
})

// Index agent capabilities
err = vectors.Upsert(ctx, &vectors.UpsertRequest{
    Index: "agent-capabilities",
    Vectors: []vectors.Vector{
        {
            ID:       agentID,
            Values:   capabilityEmbedding,
            Metadata: map[string]interface{}{
                "node_id":    nodeID,
                "reputation": reputation,
                "roles":      []string{"compute", "storage"},
            },
        },
    },
})

// Search for matching capabilities
results, err := vectors.Query(ctx, &vectors.QueryRequest{
    Index:   "agent-capabilities",
    Vector:  taskRequirementEmbedding,
    TopK:    10,
    Filter: &vectors.Filter{
        Field:    "reputation",
        Operator: vectors.OpGTE,
        Value:    0.5,
    },
})
```

### Vector Search Tenant Isolation

Vector similarity search can leak information across tenant boundaries if not properly isolated. QuicBaaS implements strict tenant separation to prevent cross-tenant data inference attacks.

```go
// pkg/quicbaas/vector_isolation.go

// VectorSearchIsolation enforces strict tenant separation for vector queries
type VectorSearchIsolation struct {
    // Strict isolation - vectors never leave tenant boundary
    EnableStrictIsolation    bool

    // Encrypted vectors - vectors encrypted with tenant key
    EnableVectorEncryption   bool

    // Index isolation - separate HNSW graphs per tenant
    EnableIndexIsolation     bool

    // Query filtering - enforce tenant filter on all queries
    EnforceQueryFilter       bool
}

// TenantVectorStore provides isolated vector storage per tenant
type TenantVectorStore struct {
    tenantID       TenantID
    encryptionKey  []byte           // Tenant-specific vector encryption key
    hnswIndex      *HNSWGraph       // Isolated HNSW index
    vectorStore    *VectorStorage   // Tenant-isolated storage
}

// IsolatedVectorSearch prevents cross-tenant information leakage
func (s *TenantVectorStore) Search(
    ctx context.Context,
    query []byte,
    k int,
) ([]VectorResult, error) {
    // Step 1: Verify query comes from authorized tenant
    callerTenant, err := extractTenantFromContext(ctx)
    if err != nil {
        return nil, ErrTenantNotAuthenticated
    }

    if callerTenant != s.tenantID {
        // CRITICAL: Cross-tenant query attempt
        logSecurityEvent(&SecurityEvent{
            Type:            EventCrossTenantQuery,
            SourceTenant:    callerTenant,
            TargetTenant:    s.tenantID,
            Timestamp:       time.Now(),
        })
        return nil, ErrCrossTenantAccessDenied
    }

    // Step 2: Query only this tenant's isolated index
    // NEVER use global index - always tenant-specific HNSW graph
    results, err := s.hnswIndex.SearchKNN(query, k)
    if err != nil {
        return nil, fmt.Errorf("vector search failed: %w", err)
    }

    // Step 3: Double-check all results belong to this tenant
    for _, result := range results {
        if result.TenantID != s.tenantID {
            // This should NEVER happen with isolated indexes
            // If it does, it's a critical security bug
            panic(&CriticalSecurityViolation{
                Type:   "cross_tenant_vector_leak",
                Source: s.tenantID,
                Target: result.TenantID,
            })
        }
    }

    return results, nil
}

// VectorEncryption prevents vectors from being compared across tenants
type VectorEncryption struct {
    // Each tenant has unique key - vectors encrypted differently
    // Prevents inference even if attacker accesses raw storage
}

func (s *TenantVectorStore) EncryptVector(vector []byte) ([]byte, error) {
    // Use tenant-specific key with AES-256-GCM
    block, _ := aes.NewCipher(s.encryptionKey)
    gcm, _ := cipher.NewGCM(block)

    nonce := make([]byte, gcm.NonceSize())
    rand.Read(nonce)

    return gcm.Seal(nonce, nonce, vector, nil), nil
}
```

**Vector Security Controls:**

| Security Control | Purpose | Default |
|------------------|---------|---------|
| Index Isolation | Separate HNSW graph per tenant | **Enabled** |
| Query Filter Enforcement | All queries include tenant filter | **Enabled** |
| Vector Encryption | Tenant-specific encryption | Enabled |
| Cross-Tenant Audit | Log any cross-boundary attempts | **Enabled** |
| Result Validation | Verify all results match query tenant | **Enabled** |

**Cross-Tenant Attack Vectors Mitigated:**

1. **Similarity Inference**: Attacker cannot use similarity search to infer other tenants' data
2. **Index Pollution**: Attacker cannot inject vectors that affect other tenants' results
3. **Side-Channel via Timing**: Index isolation prevents timing attacks across tenants
4. **Raw Storage Access**: Vector encryption prevents direct data extraction

### Service Dependencies

| DHT Component | QuicBaaS Services Used |
|---------------|------------------------|
| Leaf Node | Database, IAM, Secrets |
| CA Participant | Database, IAM, KMS, Secrets, Audit Trail |
| Hub | Database, IAM, Object Storage, Vector Search |
| Gateway | Database, IAM, Object Storage, Vector Search |
| Coordinator | Database, IAM, KMS, Secrets, Event Stream |

### Implementation Reference

The go-quicbaas SDK provides the reference implementation for all platform services. Access via SDK imports:

- QuicBaaS SDK at `github.com/jeremyhahn/go-quicbaas/sdk/go` provides:
  - Multi-Raft KV store (Database service)
  - Identity and ABAC policies (IAM service)
  - Key management service (KMS)
  - Secrets engine (Secrets service)
  - Native object storage (Objects service)
  - HNSW vector search (Vector service)

Never import directly from `pkg/` directories; always use the `sdk/go` paths for clean abstraction.

## Related Documents

### Core Design Documents

- [02-architecture-layers.md](02-architecture-layers.md) - Network layer architecture and node roles
- [03-security-trust.md](03-security-trust.md) - Security model and trust boundaries
- [04-cryptographic-protocols.md](04-cryptographic-protocols.md) - FROST signatures, DKG, and key management
- [05-certificate-authority.md](05-certificate-authority.md) - Distributed CA architecture

### Coordination and Currency

- [06-consensus-coordination.md](06-consensus-coordination.md) - PBFT consensus and coordinator committee
- [07-currency-transactions.md](07-currency-transactions.md) - UTXO ledger and cross-shard transactions

### Distribution and Defense

- [08-content-distribution.md](08-content-distribution.md) - Content storage, boot server, updates, and git registry
- [09-defense-reputation.md](09-defense-reputation.md) - **CANONICAL source for reputation thresholds and role eligibility** - Collaborative defense and reputation system

### Governance and Operations

- [10-governance-economics.md](10-governance-economics.md) - Protocol governance and token economics
- [11-operations.md](11-operations.md) - Genesis, network partitions, and telemetry
