# Federation Protocol for P2P Mode

> **Status: NORMATIVE** · Scope: the planned `dht` feature (docs/SPEC.md:53); design only, no code exists · Last verified: 2026-10-21
> Conflicts with this document are defects. Fix them here first.

## 1. Overview

Federation is an enhancement for P2P mode that enables organizations to maintain sovereignty over their local infrastructure while participating in the global P2P network. This hybrid approach allows nodes to run their own Certificate Authority (CA), Identity and Access Management (IAM), Domain Name System (DNS), and Key Management Service (KMS) while still benefiting from the decentralized trust, routing, and coordination provided by the DHT network.

**Key Benefits:**

- **Organizational Sovereignty:** Maintain control over identity issuance and policy
- **Interoperability:** Cross-certification enables trust between federated organizations
- **Flexibility:** Choose which services to run locally vs. consume from P2P network
- **Web of Trust:** Bilateral and unilateral trust agreements between organizations
- **Compliance:** Meet regulatory requirements for data residency and identity management

> **Cross-References:**
> - P2P mode fundamentals: [18-platformd-p2p.md](18-platformd-p2p.md)
> - Certificate authority: [05-certificate-authority.md](05-certificate-authority.md)
> - Security and trust: [03-security-trust.md](03-security-trust.md)
> - Network architecture: [02-network-architecture.md](02-network-architecture.md)
> - Organization identity: [26-organization-identity.md](26-organization-identity.md)

---

## 2. Organization Identity vs Federation

It is critical to distinguish between two related but distinct concepts in the trusted platform:

### P2P Organization Identity

**P2P Organization Identity** is the anti-Sybil mechanism that binds nodes to real-world entities within the P2P network. See [26-organization-identity.md](26-organization-identity.md) for complete details.

- **Purpose**: Prevents single-entity dominance of CA pools and network roles
- **Verification Methods**:
  - **Domain verification**: DNS TXT record at `_trusted-platform-org.<domain>` proves domain ownership
  - **Economic verification**: Staking 1,000 coins for 180 days demonstrates economic commitment
- **OrganizationID Derivation**:
  - Domain-based: `OrganizationID = SHA256(domain + IDevID_fingerprint)`
  - Economic-based: `OrganizationID = SHA256(wallet_id)`
- **Constraints Enforced**:
  - Maximum 5% of CA pool per organization
  - Compounding stake requirements for additional nodes
  - Minimum 20 unique organizations required at network maturity

### Federated Organization

**Federated Organization** refers to cross-organizational trust relationships that enable certificate and attestation acceptance between independently operated PKI hierarchies.

- **Purpose**: Enable sovereign organizations to interoperate while maintaining control over their identity infrastructure
- **Mechanism**: Cross-certification of CA certificates between organizations
- **Capabilities**:
  - IAM federation (SAML/OIDC)
  - Policy sharing
  - Service mesh integration
  - DNS zone delegation

### Key Distinctions

| Aspect | P2P Organization Identity | Federated Organization |
|--------|---------------------------|------------------------|
| **Scope** | Individual nodes within P2P network | Trust between organizations |
| **Purpose** | Anti-Sybil, CA pool diversity | Cross-org interoperability |
| **Verification** | Domain DNS TXT or economic stake | Cross-certification agreements |
| **Identity Binding** | OrganizationID in node state | Cross-certificates in trust anchors |
| **CA Pool Constraint** | Yes (5% max per org) | No (local CA separate from FROST) |
| **Requires** | Domain or coins | Bilateral/unilateral agreements |

### Relationship Between Concepts

A federated organization may have one or more P2P Organization Identities:

- **Single P2P org**: Federated org uses one domain for all nodes
- **Multiple P2P orgs**: Large federated org registers multiple domains/stakes
- **No P2P org**: Federated org with local-only nodes (no P2P participation)

```
+------------------------------------------------------------------+
|                    FEDERATED ORGANIZATION (Org A)                 |
|                                                                   |
|  Cross-Certified With: Org B, Org C                              |
|  Local CA: cn=Org A Root CA                                       |
|                                                                   |
|  +---------------------------+  +---------------------------+     |
|  | P2P Organization:         |  | P2P Organization:         |     |
|  | OrgID: SHA256(east.orga.  |  | OrgID: SHA256(west.orga.  |     |
|  |        com + IDevID)      |  |        com + IDevID)      |     |
|  |                           |  |                           |     |
|  | Nodes: 10                 |  | Nodes: 8                  |     |
|  | CA Pool Nodes: 2 (5% max) |  | CA Pool Nodes: 2 (5% max) |     |
|  +---------------------------+  +---------------------------+     |
+------------------------------------------------------------------+
```

---

## 3. Federated P2P Mode Architecture

A federated node maintains dual capabilities: local enterprise services AND full P2P network participation.

```
+------------------------------------------------------------------------+
|                     FEDERATED P2P MODE NODE                             |
+------------------------------------------------------------------------+
|                                                                         |
|  LOCAL SERVICES                    |    P2P PARTICIPATION               |
|  (Organizational Sovereignty)      |    (Network Citizenship)           |
|                                    |                                    |
|  +----------------------------+    |    +----------------------------+  |
|  |          CA                |    |    |     FROST Identity         |  |
|  |  - Own Root CA             |    |    |  - Network passport        |  |
|  |  - Intermediate CAs        |    |    |  - DHT node identity       |  |
|  |  - Device certificates     |    |    |  - Threshold signatures    |  |
|  +----------------------------+    |    +----------------------------+  |
|                                    |                                    |
|  +----------------------------+    |    +----------------------------+  |
|  |          IAM               |    |    |     DHT Routing            |  |
|  |  - Users/Groups            |    |    |  - Kademlia participation  |  |
|  |  - ABAC Policies           |    |    |  - Content discovery       |  |
|  |  - SSO/Federation          |    |    |  - Service location        |  |
|  +----------------------------+    |    +----------------------------+  |
|                                    |                                    |
|  +----------------------------+    |    +----------------------------+  |
|  |          DNS               |    |    |     Reputation             |  |
|  |  - Internal zones          |    |    |  - Earn reputation         |  |
|  |  - Split horizon           |    |    |  - Role eligibility        |  |
|  |  - Service records         |    |    |  - Trust scoring           |  |
|  +----------------------------+    |    +----------------------------+  |
|                                    |                                    |
|  +----------------------------+    |    +----------------------------+  |
|  |          KMS               |    |    |     PBFT Consensus         |  |
|  |  - Key storage             |    |    |  - Coordinator votes       |  |
|  |  - Encryption keys         |    |    |  - Governance              |  |
|  |  - Signing keys            |    |    |  - Network decisions       |  |
|  +----------------------------+    |    +----------------------------+  |
|                                    |                                    |
+------------------------------------+------------------------------------+
|                                                                         |
|                    CROSS-CERTIFICATION LAYER                            |
|  +-------------------------------------------------------------------+  |
|  |  - Trust anchors from partner organizations                       |  |
|  |  - Bilateral/unilateral certification agreements                  |  |
|  |  - Certificate path validation across trust domains               |  |
|  |  - Revocation status aggregation (CRL + OCSP + DHT gossip)        |  |
|  +-------------------------------------------------------------------+  |
|                                                                         |
+------------------------------------------------------------------------+
```

---

## 4. Architecture Layers

The federation architecture supports multiple deployment patterns within the same P2P network.

```
+-------------------------------------------------------------------------+
|                        FEDERATED P2P NETWORK                             |
+-------------------------------------------------------------------------+
|                                                                          |
|   FEDERATED ORG A              FEDERATED ORG B           SIMPLE P2P      |
|   (Full Sovereignty)           (Full Sovereignty)        NODE (ORG C)    |
|                                                                          |
|   +------------------+         +------------------+      +-------------+ |
|   | +----+ +----+    |         | +----+ +----+    |      |             | |
|   | | CA | |IAM |    |         | | CA | |IAM |    |      |   FROST     | |
|   | +----+ +----+    |         | +----+ +----+    |      |   CA Only   | |
|   | +----+ +----+    |         | +----+ +----+    |      |             | |
|   | |DNS | |KMS |    |         | |DNS | |KMS |    |      |  No local   | |
|   | +----+ +----+    |         | +----+ +----+    |      |  services   | |
|   +--------+---------+         +--------+---------+      +------+------+ |
|            |                            |                       |        |
|            | Cross-Cert                 | Cross-Cert            |        |
|            |<-------------------------->|                       |        |
|            |                            |                       |        |
|   +--------+----------------------------+----------------------------+   |
|   |                       P2P BACKBONE (DHT)                          |   |
|   |                                                                   |   |
|   |  +------------+  +------------+  +------------+  +------------+   |   |
|   |  | Kademlia   |  | FROST CA   |  | Reputation |  | Consensus  |   |   |
|   |  | Routing    |  | Pool       |  | System     |  | (PBFT)     |   |   |
|   |  +------------+  +------------+  +------------+  +------------+   |   |
|   |                                                                   |   |
|   +-------------------------------------------------------------------+   |
|                                                                          |
|   Legend:                                                                |
|   [====] Cross-certification trust relationship                          |
|   [----] P2P network participation                                       |
|                                                                          |
+-------------------------------------------------------------------------+
```

**Organization Types:**

| Type | Local Services | FROST Identity | Cross-Certification | Use Case |
|------|----------------|----------------|---------------------|----------|
| **Federated** | CA, IAM, DNS, KMS | Required | Yes (bilateral/unilateral) | Enterprise, regulated industries |
| **Simple P2P** | None | Required | No (trusts FROST only) | Edge devices, personal nodes |

---

## 5. Trust Model: Hierarchical with Cross-Certification

### Trust Architecture

Each federated participant operates its own PKI hierarchy while establishing trust relationships with other organizations through cross-certification.

**Trust Principles:**

1. **Each federated participant has its own CA hierarchy**
   - Root CA (offline, airgapped)
   - Intermediate CAs (online, domain-specific)
   - Issuing CAs (device certificates, user certificates)

2. **Cross-certifies with peers through bilateral agreements**
   - Mutual trust between organizations
   - Constrained by name constraints and path length
   - Time-bounded validity

3. **Optionally trusts FROST CA**
   - Trust P2P-issued certificates
   - Bridge to non-federated nodes
   - Configurable trust level

4. **Manages trust anchors independently**
   - Full control over which CAs to trust
   - Can revoke trust at any time
   - Policy-based trust decisions

### Trust Chain Resolution

```
                    TRUST CHAIN RESOLUTION
+------------------------------------------------------------------------+
|                                                                         |
|  SCENARIO 1: Device from Own Org (Org A)                               |
|  +------------------------------------------------------------------+  |
|  |  Device Cert --> Org A Intermediate CA --> Org A Root CA         |  |
|  |                                                                   |  |
|  |  Result: DIRECT TRUST (shortest path)                            |  |
|  +------------------------------------------------------------------+  |
|                                                                         |
|  SCENARIO 2: Device from Partner Org (Org B)                           |
|  +------------------------------------------------------------------+  |
|  |  Device Cert --> Org B Intermediate CA --> Org B Root CA         |  |
|  |                            |                                      |  |
|  |                            v                                      |  |
|  |                    Cross-Certificate                              |  |
|  |                            |                                      |  |
|  |                            v                                      |  |
|  |                    Org A Intermediate CA --> Org A Root CA        |  |
|  |                                                                   |  |
|  |  Result: CROSS-CERT CHAIN (bilateral agreement)                  |  |
|  +------------------------------------------------------------------+  |
|                                                                         |
|  SCENARIO 3: Device from P2P Network (Simple Node)                     |
|  +------------------------------------------------------------------+  |
|  |  Device Cert (IDevID) --> FROST Privacy CA Pool                  |  |
|  |                                                                   |  |
|  |  Result: FROST CA CHAIN (if FROST CA trusted)                    |  |
|  +------------------------------------------------------------------+  |
|                                                                         |
|  SCENARIO 4: Unknown Device                                            |
|  +------------------------------------------------------------------+  |
|  |  Device Cert --> ??? (no chain to trusted anchor)                |  |
|  |                                                                   |  |
|  |  Result: NOT TRUSTED (reject)                                    |  |
|  +------------------------------------------------------------------+  |
|                                                                         |
+------------------------------------------------------------------------+
```

### Trust Decision Matrix

| Certificate Source | Has Cross-Cert | FROST CA Trusted | Trust Decision |
|--------------------|----------------|------------------|----------------|
| Own organization | N/A | N/A | **TRUSTED** |
| Partner with bilateral | Yes | N/A | **TRUSTED** (within constraints) |
| Partner with unilateral | Yes (one-way) | N/A | **TRUSTED** (if we issued cross-cert) |
| Simple P2P node | No | Yes | **TRUSTED** (FROST chain) |
| Simple P2P node | No | No | **NOT TRUSTED** |
| Unknown | No | N/A | **NOT TRUSTED** |

---

## 6. Cross-Certification Protocol

Cross-certification enables two organizations to establish mutual trust through certificate issuance.

### Cross-Certification Structure

```yaml
cross_certification:
  # Issuing organization (the one creating this cross-cert)
  issuer:
    organization: "Org A"
    ca_subject: "CN=Org A Intermediate CA,O=Org A,C=US"
    ca_fingerprint: "sha256:abc123..."

  # Subject organization (the one being cross-certified)
  subject:
    organization: "Org B"
    ca_subject: "CN=Org B Root CA,O=Org B,C=DE"
    ca_fingerprint: "sha256:def456..."

  # Agreement terms
  agreement:
    type: bilateral          # bilateral or unilateral
    trust_level: intermediate  # root, intermediate, or leaf-only
    valid_from: "2026-01-10T00:00:00Z"
    valid_until: "2027-01-10T00:00:00Z"
    renewal_policy: manual   # manual, auto-renew, or notify

  # Constraints on cross-certified certificates
  constraints:
    permitted_domains:
      - "*.orgb.example.com"
      - "*.devices.orgb.internal"
    excluded_domains:
      - "*.admin.orgb.example.com"
    permitted_purposes:
      - serverAuth
      - clientAuth
      - deviceAttest
    excluded_purposes:
      - codeSigning
      - emailProtection
    max_path_length: 1       # Limit chain depth

  # Revocation information
  revocation:
    crl_url: "https://ca.orgb.example.com/crl"
    crl_refresh_interval: 1h
    ocsp_url: "https://ocsp.orgb.example.com"
    ocsp_timeout: 5s
    dht_gossip_enabled: true  # Use DHT for fast revocation

  # Audit and compliance
  audit:
    log_all_validations: true
    certificate_transparency: true
    ct_log_url: "https://ct.orgb.example.com/log"
```

### Cross-Certification Workflow

```
Org A (Initiator)                                    Org B (Responder)
      |                                                     |
      | 1. Propose Cross-Certification                      |
      |---------------------------------------------------->|
      |    - Include Org A Root CA certificate              |
      |    - Proposed constraints and validity              |
      |                                                     |
      |                    2. Review and Accept             |
      |<----------------------------------------------------|
      |    - Include Org B Root CA certificate              |
      |    - Agreed constraints and validity                |
      |                                                     |
      | 3. Issue Cross-Certificate for Org B CA             |
      |    - Signed by Org A Intermediate CA                |
      |    - Contains Org B CA public key                   |
      |    - Includes agreed constraints                    |
      |                                                     |
      |                    4. Issue Cross-Certificate       |
      |<----------------------------------------------------|
      |    - Signed by Org B Intermediate CA                |
      |    - Contains Org A CA public key                   |
      |    - Includes agreed constraints                    |
      |                                                     |
      | 5. Publish to DHT (optional)                        |
      |---------------------------------------------------->|
      |    - Register in federation registry                |
      |                                                     |
      | 6. Verify Bidirectional Trust                       |
      |<--------------------------------------------------->|
      |    - Test certificate validation both ways          |
      |                                                     |
```

---

## 7. Design Decisions

### 7.1 FROST CA Identity: MANDATORY

**Decision:** All federated nodes MUST have a FROST CA identity.

**Rationale:**

- **FROST identity = Network passport:** Required for DHT participation
- **Without FROST identity:** Node operates in Local mode (standalone), not federated P2P mode
- **Dual identity model:** Federated nodes have TWO identities:
  - **FROST identity:** For network-level operations (routing, reputation, consensus)
  - **Local identity:** For domain-specific operations (enterprise PKI, IAM)

```
+--------------------------------------------------------------------+
|                    FEDERATED NODE IDENTITIES                        |
+--------------------------------------------------------------------+
|                                                                     |
|  FROST IDENTITY (Network)          LOCAL IDENTITY (Domain)         |
|  +---------------------------+     +---------------------------+   |
|  |                           |     |                           |   |
|  | - IDevID from FROST CA    |     | - Cert from Local CA      |   |
|  | - DHT NodeID derived      |     | - Enterprise subject DN   |   |
|  | - Reputation tracking     |     | - Domain-specific attrs   |   |
|  | - Role eligibility        |     | - Policy enforcement      |   |
|  | - Consensus voting        |     | - SSO integration         |   |
|  |                           |     |                           |   |
|  +---------------------------+     +---------------------------+   |
|             |                                  |                    |
|             |   Used For:                      |   Used For:        |
|             |   - P2P routing                  |   - Internal auth  |
|             |   - DHT operations               |   - Service mesh   |
|             |   - Cross-org discovery          |   - User access    |
|             |                                  |                    |
+--------------------------------------------------------------------+
```

### 7.2 Cross-Certification Storage: HYBRID

**Decision:** Cross-certification data stored in BOTH local config AND optional DHT registry.

**Local Configuration (Core Partners):**

```yaml
federation:
  cross_certifications:
    local:
      # Always loaded at startup - critical partners
      - path: /etc/platformd/cross-certs/org-b.yaml
        priority: high
        required: true
      - path: /etc/platformd/cross-certs/org-c.yaml
        priority: medium
        required: true

    # DHT discovery for additional partners
    discovery:
      enabled: true
      registry_key: "federation:cross-certs:myorg"
      refresh_interval: 1h
      max_discovered: 100
      trust_on_discovery: false  # Require manual approval
```

**Why Hybrid:**

| Aspect | Local Config | DHT Registry |
|--------|--------------|--------------|
| Startup dependency | No network needed | Requires DHT access |
| Trust model | Pre-approved | Discovery + approval |
| Update mechanism | File change + reload | Automatic refresh |
| Use case | Critical partners | Dynamic federation |

### 7.3 Revocation Model: PKI + DHT GOSSIP

**Decision:** Use traditional PKI revocation (CRL/OCSP) combined with DHT gossip for faster propagation.

**Revocation Sources:**

```
+------------------------------------------------------------------------+
|                     REVOCATION CHECK FLOW                               |
+------------------------------------------------------------------------+
|                                                                         |
|  Certificate Validation Request                                         |
|         |                                                               |
|         v                                                               |
|  +------+------+                                                        |
|  | Check DHT   |  <-- Fastest: ~50ms                                   |
|  | Gossip Cache|      In-memory cache of gossip messages               |
|  +------+------+                                                        |
|         |                                                               |
|    Not Found                                                            |
|         |                                                               |
|         v                                                               |
|  +------+------+                                                        |
|  | Check OCSP  |  <-- Fast: ~100-500ms                                 |
|  | Responder   |      Real-time status                                 |
|  +------+------+                                                        |
|         |                                                               |
|    No Response                                                          |
|         |                                                               |
|         v                                                               |
|  +------+------+                                                        |
|  | Check CRL   |  <-- Slower: cached locally                           |
|  | (Cached)    |      Periodic refresh                                 |
|  +------+------+                                                        |
|         |                                                               |
|         v                                                               |
|  +------+------+                                                        |
|  |   Result    |                                                        |
|  +-------------+                                                        |
|                                                                         |
+------------------------------------------------------------------------+
```

**DHT Gossip Protocol:**

```yaml
revocation_gossip:
  message_type: "revocation"
  payload:
    cert_serial: "abc123..."
    cert_fingerprint: "sha256:..."
    issuer_dn: "CN=Org A Intermediate CA,O=Org A"
    revocation_time: "2026-01-10T15:30:00Z"
    reason: "keyCompromise"  # CRL reason code
    signature: "..."         # Signed by issuing CA
  propagation:
    ttl: 24h
    max_hops: 10
    priority: high
```

### 7.4 Federation Registry: OPT-IN

**Decision:** DHT-based registry for discoverable federated nodes is opt-in.

**Registry Entry Structure:**

```yaml
federation_registry:
  # Unique identifier in DHT
  registry_key: "federation:org:myorg.example.com"

  # Node information
  node:
    node_id: "QmABC123..."
    frost_identity: "sha256:frost-cert-fingerprint"
    domain: "myorg.example.com"

  # Metadata for discovery
  metadata:
    organization_name: "My Organization Inc."
    organization_type: "enterprise"  # enterprise, research, government, personal
    industry: "healthcare"
    region: "us-west-2"
    established: "2020-01-15"

  # Federation capabilities
  capabilities:
    ca_cross_certification: true
    iam_federation: true
    dns_delegation: false
    kms_escrow: false

  # Requirements for federation
  requirements:
    minimum_reputation: 0.80
    minimum_age_days: 90
    trust_level: trusted
    attestation_required: true

  # Contact for federation requests
  contact:
    federation_endpoint: "https://federation.myorg.example.com/api/v1"
    public_key: "-----BEGIN PUBLIC KEY-----..."
    response_sla: "48h"

  # Signature for authenticity
  signature:
    signer: "QmABC123..."
    timestamp: "2026-01-10T00:00:00Z"
    signature: "..."
```

---

## 8. Federation Services

| Service | Local Mode | P2P Fallback | Cross-Org Mechanism |
|---------|------------|--------------|---------------------|
| **CA** | Own PKI hierarchy | FROST CA for IDevID | Cross-certification |
| **IAM** | Own users, groups, policies | DHT IAM (shared identity) | Federation agreements (SAML/OIDC) |
| **DNS** | Own authoritative zones | DHT discovery service | Zone delegation / forwarding |
| **KMS** | Own key storage (HSM/TPM) | None (keys never leave org) | Key escrow agreements (optional) |

### Service Interaction Matrix

```
+-------------------------------------------------------------------------+
|                    SERVICE INTERACTION PATTERNS                          |
+-------------------------------------------------------------------------+
|                                                                          |
|  LOCAL USER                 FEDERATED USER             P2P NODE          |
|  (Org A Employee)           (Org B Partner)            (Anonymous)       |
|                                                                          |
|       |                          |                          |            |
|       v                          v                          v            |
|  +---------+                +---------+                +---------+       |
|  | Local   |                | Cross-  |                | FROST   |       |
|  | IAM     |                | Cert    |                | IDevID  |       |
|  | Authn   |                | + IAM   |                | Only    |       |
|  +---------+                | Fed     |                +---------+       |
|       |                     +---------+                     |            |
|       v                          |                          v            |
|  +---------+                     v                     +---------+       |
|  | Local   |                +---------+                | DHT     |       |
|  | CA      |                | Verify  |                | Service |       |
|  | Verify  |                | Chain   |                | Only    |       |
|  +---------+                +---------+                +---------+       |
|       |                          |                          |            |
|       +------------+-------------+-------------+------------+            |
|                    |                           |                         |
|                    v                           v                         |
|              +----------+               +----------+                     |
|              | Internal |               | External |                     |
|              | Services |               | Services |                     |
|              +----------+               +----------+                     |
|                                                                          |
+-------------------------------------------------------------------------+
```

---

## 9. Device Identity Options

Federated organizations can choose from multiple device identity configurations:

### Option 1: Local-Only Identity

Device has IDevID only from local CA. Cannot participate in P2P network directly.

```yaml
device_identity:
  type: local_only
  primary_identity:
    source: local_ca
    certificate: "/var/lib/platformd/certs/device-idevid.pem"
    key_handle: 0x81000001  # TPM persistent handle
    issuer: "CN=Org A Device CA,O=Org A"
  secondary_identity: null
  trust_anchors:
    - "/etc/platformd/ca/org-a-root.pem"
```

**Characteristics:**

- Full organizational control
- No P2P routing capability
- Must use gateway for P2P access
- Best for: Air-gapped environments, high-security devices

### Option 2: Dual Identity (Recommended for Federation)

Device has both local CA identity AND FROST CA identity.

```yaml
device_identity:
  type: dual
  primary_identity:
    source: local_ca
    certificate: "/var/lib/platformd/certs/local-idevid.pem"
    key_handle: 0x81000001
    issuer: "CN=Org A Device CA,O=Org A"
    use_for:
      - internal_auth
      - service_mesh
      - enterprise_apps
  secondary_identity:
    source: frost_ca
    certificate: "/var/lib/platformd/certs/frost-idevid.pem"
    key_handle: 0x81000002
    issuer: "CN=FROST Privacy CA,O=Trusted DHT"
    use_for:
      - p2p_routing
      - dht_operations
      - cross_org_discovery
      - reputation_tracking
  trust_anchors:
    local:
      - "/etc/platformd/ca/org-a-root.pem"
    cross_certified:
      - "/etc/platformd/ca/org-b-cross-cert.pem"
    frost:
      - "/etc/platformd/ca/frost-root.pem"
  identity_binding:
    enabled: true
    binding_type: attestation  # Prove both identities on same TPM
```

**Characteristics:**

- Full organizational sovereignty for internal operations
- Full P2P participation capability
- Can earn reputation and assume roles
- Best for: Enterprise nodes requiring both internal and P2P access

### Option 3: P2P-Only Identity

Device has only FROST CA identity. Simpler but less organizational autonomy.

```yaml
device_identity:
  type: p2p_only
  primary_identity:
    source: frost_ca
    certificate: "/var/lib/platformd/certs/frost-idevid.pem"
    key_handle: 0x81000001
    issuer: "CN=FROST Privacy CA,O=Trusted DHT"
  secondary_identity: null
  trust_anchors:
    - "/etc/platformd/ca/frost-root.pem"
```

**Characteristics:**

- Simplest configuration
- Full P2P participation
- No local PKI overhead
- Best for: Edge devices, personal nodes, simple deployments

---

## 10. Organization Identity Integration

Each federated node has both a device-level identity and an organizational identity. Understanding the distinction and relationship between these identifiers is essential for proper federation configuration.

### Identity Types

| Identity | Derivation | Purpose | Scope |
|----------|------------|---------|-------|
| **OwnerID** | `SHA256(IDevID pubkey)` | Identifies the TPM/device | Device-level attestation |
| **OrganizationID** | `SHA256(domain + IDevID)` or `SHA256(wallet_id)` | Identifies the organization | CA pool constraints, anti-Sybil |
| **NodeID** | Derived from FROST identity | DHT routing identifier | Network participation |

### OwnerID vs OrganizationID

**OwnerID** identifies the physical TPM and device:
- Derived from the IDevID public key fingerprint
- Unique per hardware device
- Used for device-level attestation and verification
- Cannot be transferred between devices

**OrganizationID** identifies the real-world entity operating nodes:
- Derived from verified domain or economic stake
- Shared across all nodes belonging to the organization
- Used for CA pool diversity constraints (max 5% per org)
- Subject to verification renewal (90 days domain / 180 days economic)

```go
// Identity relationship example
type NodeIdentity struct {
    // Device-level (unique per TPM)
    OwnerID       [32]byte  // SHA256(IDevID_pubkey)
    IDevIDCert    []byte    // IDevID certificate

    // Organization-level (shared across org nodes)
    OrganizationID [32]byte // SHA256(domain + IDevID) or SHA256(wallet_id)
    OrgVerification VerificationType // domain or economic

    // Network-level (P2P participation)
    NodeID        [32]byte  // DHT routing identifier
    FROSTIdentity []byte    // FROST CA certificate
}
```

### CA Pool Constraints

CA pool diversity constraints apply at the **OrganizationID** level, not the OwnerID level:

```go
// CA Pool selection uses OrganizationID
type CAPoolConstraints struct {
    // Organization constraint (primary anti-Sybil)
    MaxPercentPerOrg  float64 // 0.05 (5%)
    MinUniqueOrgs     int     // 20

    // Network diversity (secondary)
    MaxPercentPerASN  float64 // 0.15 (15%)
    MinUniqueASNs     int     // 7
}

// Example: Org with 10 nodes
// - If CA pool size = 100, max org nodes in pool = 5 (5%)
// - Compounding stake: Node 1 = 100, Node 2 = 120, Node 3 = 144, etc.
```

### Cross-Organization Verification

Federated trust policies can reference OrganizationIDs for verifier diversity requirements:

```yaml
attestation_policy:
  # Minimum verifiers from different organizations
  min_verifier_orgs: 3

  # Cross-org verification counts toward diversity
  cross_org_verification:
    enabled: true
    # Verifications from cross-certified orgs count
    include_federated_orgs: true
    # Weight for cross-org vs same-org verification
    cross_org_weight: 1.0
    same_org_weight: 0.5

  # Specific organization trust levels
  org_trust_levels:
    # Reference by OrganizationID
    "sha256:abc123...":
      trust_level: high
      verification_weight: 1.0
    "sha256:def456...":
      trust_level: standard
      verification_weight: 0.8
```

### Federation Configuration with Organization Identity

```yaml
federation:
  enabled: true

  # Organization identity binding
  organization:
    # P2P organization identity (required for P2P participation)
    p2p_org_id: "sha256:abc123..."
    verification_type: domain
    domain: "myorg.example.com"

    # Federated organization (cross-certification)
    federated:
      name: "My Organization Inc."
      ca_dn: "CN=My Org Root CA,O=My Organization Inc,C=US"

  # Cross-certification with organization awareness
  cross_certifications:
    - partner_org_id: "sha256:def456..."
      partner_domain: "partner.example.com"
      cross_cert_path: "/etc/platformd/cross-certs/partner.pem"
      # Trust verifications from partner org
      verification_trust:
        accept_attestations: true
        min_verifier_orgs_override: 2  # Lower if partner included

  # Verifier diversity requirements
  attestation_verification:
    min_verifiers: 5
    min_verifier_orgs: 3
    include_cross_certified_orgs: true
```

---

## 11. Control Plane P2P Participation

Federated nodes run a control plane that manages both local services and P2P participation.

```
+-------------------------------------------------------------------------+
|                    FEDERATED CONTROL PLANE                               |
+-------------------------------------------------------------------------+
|                                                                          |
|  +-------------------------------------------------------------------+  |
|  |                    CONTROL PLANE (Federated Node)                  |  |
|  |                                                                    |  |
|  |  LOCAL SERVICES              |     P2P INTERFACE                   |  |
|  |  +------------------------+  |     +------------------------+      |  |
|  |  |          CA            |  |     |      Full Node         |      |  |
|  |  |  - Issue local certs   |  |     |  - DHT routing        |      |  |
|  |  |  - Cross-cert mgmt     |  |     |  - Reputation track   |      |  |
|  |  +------------------------+  |     |  - Role participation  |      |  |
|  |  |          IAM           |  |     |  - Consensus voting   |      |  |
|  |  |  - User auth           |  |     +------------------------+      |  |
|  |  |  - Policy enforce      |  |                |                    |  |
|  |  +------------------------+  |                |                    |  |
|  |  |          DNS           |  |                |                    |  |
|  |  |  - Zone management     |  |                |                    |  |
|  |  |  - Service discovery   |  |                |                    |  |
|  |  +------------------------+  |                |                    |  |
|  +------------------------------|----------------+--------------------+  |
|                                 |                |                       |
+---------------------------------|----------------+-----------------------+
                                  |                |
                                  v                v
+-------------------------------------------------------------------------+
|                         LEAF NODES                                       |
|                                                                          |
|   +-------------+    +-------------+    +-------------+                  |
|   | Leaf Node 1 |    | Leaf Node 2 |    | Leaf Node 3 |                  |
|   | (Direct P2P)|    | (Direct P2P)|    |(Via Control)|                  |
|   +------+------+    +------+------+    +------+------+                  |
|          |                  |                  |                         |
|          |                  |                  |                         |
|          +------------------+-------+----------+                         |
|                                     |                                    |
|                    Leaf nodes may participate:                           |
|                    - Directly in P2P (with FROST identity)              |
|                    - Via Control Plane (proxy mode)                      |
|                                                                          |
+-------------------------------------------------------------------------+
```

### Role Promotion for Federated Nodes

Federated nodes follow the same role promotion rules as any P2P node:

| Role | Reputation Threshold | Minimum Age | Notes for Federated |
|------|---------------------|-------------|---------------------|
| Leaf | 0.0+ | 0 days | Immediate P2P participation |
| CA Participant | 0.90+ | 120 days | Can join FROST CA pool |
| Hub | 0.80+ | 110 days | Regional routing hub |
| Gateway | 0.85+ | 175 days | External connectivity |
| Coordinator | 0.95+ | 185 days | Consensus leadership |

**Federated Node Advantages:**

- **Higher uptime:** Enterprise infrastructure = more reliable
- **More resources:** Better hardware, network connectivity
- **Faster reputation growth:** Consistent availability earns reputation faster
- **Natural role promotion:** Often reach Coordinator status

**Important Separation:**

```
Local CA and FROST CA pool membership are COMPLETELY SEPARATE.

+----------------------------------+----------------------------------+
|         LOCAL CA ROLE            |        FROST CA ROLE             |
+----------------------------------+----------------------------------+
| - Determined by organization     | - Determined by P2P reputation   |
| - Issues organization certs      | - Issues network IDevIDs         |
| - Controlled by local policy     | - Controlled by network rules    |
| - No reputation required         | - Requires 0.80+ reputation      |
| - Immediate upon deployment      | - Requires 80+ days              |
+----------------------------------+----------------------------------+

A federated node can be:
  - Local CA admin + FROST CA participant (both roles)
  - Local CA admin + FROST Leaf node (not yet qualified)
  - Neither (pure consumer node)
```

---

## 12. Peering Agreements

Beyond CA cross-certification, federated organizations can establish comprehensive peering agreements.

### Agreement Types

1. **IAM Federation (SSO Across Organizations)**
   - SAML 2.0 / OIDC trust establishment
   - Attribute mapping between identity systems
   - Session management across boundaries

2. **Policy Sharing (Mutual Policy Recognition)**
   - Recognize partner's device policies
   - Share attestation requirements
   - Mutual compliance frameworks

3. **Device Profiles (Shared Attestation Requirements)**
   - Common PCR values for platform integrity
   - Agreed firmware/software baselines
   - Shared vulnerability databases

4. **Service Mesh (Cross-Org Service Discovery)**
   - Register services in partner's namespace
   - mTLS between organization services
   - Load balancing and failover

### Peering Configuration

```yaml
peering_agreements:
  org_b:
    organization: "Org B Inc."
    agreement_id: "peer-orga-orgb-2026-001"
    effective_date: "2026-01-10T00:00:00Z"
    expiration_date: "2027-01-10T00:00:00Z"

    # IAM Federation
    iam_federation:
      enabled: true
      protocol: oidc
      issuer: "https://idp.orgb.example.com"
      client_id: "orga-federation"
      client_secret_ref: "vault:peering/orgb/oidc-secret"
      scopes:
        - openid
        - profile
        - groups
      attribute_mapping:
        sub: "user_id"
        email: "email"
        groups: "roles"
      allowed_groups:
        - "orgb-partners"
        - "orgb-admins"

    # Policy Sharing
    policy_sharing:
      enabled: true
      recognized_policies:
        - name: "orgb-device-baseline"
          policy_id: "pol-orgb-device-001"
          version: "1.2.0"
          hash: "sha256:abc123..."
      shared_attestation:
        pcr_0: "required"  # BIOS
        pcr_7: "required"  # Secure Boot
        firmware_versions:
          min: "2.0.0"

    # Service Mesh
    service_mesh:
      enabled: true
      namespace: "orgb-services"
      services:
        - name: "orgb-api"
          endpoint: "https://api.orgb.example.com"
          mtls_required: true
        - name: "orgb-storage"
          endpoint: "https://storage.orgb.example.com"
          mtls_required: true
      load_balancing:
        strategy: round_robin
        health_check_interval: 30s

    # Contact and SLA
    contact:
      technical: "tech@orgb.example.com"
      security: "security@orgb.example.com"
    sla:
      availability: "99.9%"
      response_time: "4h"
      incident_notification: "1h"
```

---

## 13. Configuration Example

Complete configuration for P2P mode with Federation Enhancement:

```yaml
# /etc/platformd/config.yaml
platform:
  # Operating mode: p2p with federation
  mode: p2p

  # DHT network configuration
  dht:
    bootstrap_peers:
      - "/ip4/192.0.2.10/tcp/9444/p2p/QmBootstrap1"
      - "/ip4/192.0.2.11/tcp/9444/p2p/QmBootstrap2"
      - "/dns4/bootstrap.trusted-dht.io/tcp/9444/p2p/QmBootstrap3"
    listen_addresses:
      - "/ip4/0.0.0.0/tcp/9444"
      - "/ip6/::/tcp/9444"
      - "/ip4/0.0.0.0/udp/9444/quic"

  # FROST CA configuration (required for federation)
  frost_ca:
    pool_threshold: 0.33
    enrollment:
      privacy_ca_url: "https://privacy-ca.trusted-dht.io/acme"
      cert_path: "/var/lib/platformd/certs/frost-idevid.pem"
      key_handle: 0x81000002
      renew_before_expiry: 168h

  # Federation configuration
  federation:
    enabled: true
    domain: "myorg.example.com"
    organization:
      name: "My Organization Inc."
      type: "enterprise"
      industry: "technology"

    # Local CA configuration
    local_ca:
      enabled: true
      root_ca:
        certificate: "/etc/platformd/ca/root-ca.pem"
        # Key stored in HSM, not filesystem
      intermediate_ca:
        certificate: "/etc/platformd/ca/intermediate-ca.pem"
        key_handle: 0x81010001  # TPM handle
      issuance_policy:
        max_validity: 90d
        key_types:
          - EC-P256
          - EC-P384
        allowed_purposes:
          - serverAuth
          - clientAuth
          - deviceAttest

    # Local IAM configuration
    local_iam:
      enabled: true
      backend: "quicbaas"  # Uses QuicBaaS IAM
      policies_path: "/etc/platformd/iam/policies/"
      default_role: "viewer"
      admin_groups:
        - "platform-admins"

    # Local DNS configuration
    local_dns:
      enabled: true
      authoritative_zones:
        - "myorg.example.com"
        - "devices.myorg.internal"
      upstream_resolvers:
        - "8.8.8.8"
        - "1.1.1.1"
      dht_fallback: true  # Use DHT for unknown domains

    # Cross-certification configuration
    cross_certification:
      # Core partners (always loaded)
      local_certifications:
        - partner: "orgb.example.com"
          cross_cert: "/etc/platformd/cross-certs/orgb.pem"
          constraints:
            permitted_domains:
              - "*.orgb.example.com"
            max_path_length: 1
        - partner: "orgc.example.com"
          cross_cert: "/etc/platformd/cross-certs/orgc.pem"
          constraints:
            permitted_domains:
              - "*.orgc.example.com"
            max_path_length: 2

      # DHT discovery (optional)
      discovery:
        enabled: true
        registry_key: "federation:discover:myorg.example.com"
        refresh_interval: 1h
        auto_approve: false  # Manual approval required
        minimum_reputation: 0.80

    # Trust anchors
    trust_anchors:
      # Own organization
      local:
        - "/etc/platformd/ca/root-ca.pem"
      # FROST CA (for P2P nodes)
      frost:
        trust_enabled: true
        certificate: "/etc/platformd/ca/frost-root.pem"
      # Cross-certified partners
      cross_certified:
        - "/etc/platformd/cross-certs/orgb.pem"
        - "/etc/platformd/cross-certs/orgc.pem"

    # Federation registry (opt-in publication)
    registry:
      publish: true
      discoverable: true
      capabilities:
        ca_cross_certification: true
        iam_federation: true
        dns_delegation: false
      requirements:
        minimum_reputation: 0.80
        minimum_age_days: 90
        attestation_required: true

# TPM configuration
tpm:
  device: "/dev/tpmrm0"
  quote_pcrs: [0, 2, 7]
  ek_cert_path: "/var/lib/platformd/tpm/ek.crt"
```

---

## 14. Node Types Summary

| Attribute | Simple P2P Node | Federated Node |
|-----------|-----------------|----------------|
| **FROST Identity** | Yes (required) | Yes (required) |
| **Local CA** | No | Yes |
| **Local IAM** | No | Yes |
| **Local DNS** | No | Optional |
| **Local KMS** | No | Optional |
| **Cross-Certification** | No | Yes |
| **P2P Routing** | Full | Full |
| **Reputation** | Earns normally | Earns normally |
| **Role Eligibility** | All roles | All roles |
| **Identity Sources** | FROST only | FROST + Local |
| **Governance Voting** | Yes | Yes |
| **Organizational Sovereignty** | None | Full |

---

## 15. Use Cases

| Use Case | Challenge | How Federation Helps |
|----------|-----------|---------------------|
| **Healthcare Consortium** | HIPAA compliance, patient data sovereignty | Each hospital maintains own CA/IAM; cross-certify for inter-hospital device trust |
| **Supply Chain Network** | Multiple companies, diverse trust requirements | Each company runs own PKI; federate for shipment tracking, IoT sensors |
| **Research Network** | University collaboration, data sharing | Each institution controls access; cross-cert for shared compute resources |
| **Multi-Cloud Deployment** | Hybrid cloud, consistent identity | Single organization across clouds; local CA per cloud, unified trust |
| **IoT Ecosystem** | Device manufacturers, fleet operators | Manufacturer issues device certs; fleet operator cross-certs for management |
| **Government Interoperability** | Agency boundaries, compliance | Each agency sovereign; bilateral agreements for inter-agency operations |
| **Financial Services** | Regulatory requirements, audit trails | Each institution's own PKI; cross-cert for clearing, settlement |

### Detailed Example: Healthcare Consortium

```
+-------------------------------------------------------------------------+
|                 HEALTHCARE CONSORTIUM FEDERATION                         |
+-------------------------------------------------------------------------+
|                                                                          |
|  HOSPITAL A                HOSPITAL B                 RESEARCH LAB       |
|  +------------------+      +------------------+       +---------------+  |
|  | Local CA         |      | Local CA         |       | Local CA      |  |
|  | - Patient devices|      | - Patient devices|       | - Lab equip   |  |
|  | - Staff certs    |      | - Staff certs    |       | - Researcher  |  |
|  +--------+---------+      +--------+---------+       +-------+-------+  |
|           |                         |                         |          |
|           | Cross-Cert              | Cross-Cert              |          |
|           +-------------------------+-------------------------+          |
|                                     |                                    |
|                                     v                                    |
|                    +--------------------------------+                    |
|                    |     CONSORTIUM TRUST ANCHOR    |                    |
|                    |  (Optional consortium root CA) |                    |
|                    +--------------------------------+                    |
|                                     |                                    |
|                                     v                                    |
|           +---------------------------------------------------+          |
|           |              P2P BACKBONE (DHT)                   |          |
|           |  - Secure messaging between hospitals             |          |
|           |  - Patient record lookup (encrypted)              |          |
|           |  - Research data sharing                          |          |
|           |  - Device attestation verification                |          |
|           +---------------------------------------------------+          |
|                                                                          |
|  Benefits:                                                               |
|  - HIPAA compliance: Each hospital controls own patient data            |
|  - Interoperability: Cross-cert enables secure data exchange            |
|  - Research: Lab can access anonymized data from multiple hospitals     |
|  - Audit: Full chain of trust for all operations                        |
|                                                                          |
+-------------------------------------------------------------------------+
```

---

## 16. Trade-offs

| Aspect | P2P Only | Federated P2P |
|--------|----------|---------------|
| **Complexity** | Lower | Higher |
| **Setup Time** | Minutes | Hours to days |
| **Autonomy** | Shared governance | Full sovereignty |
| **Trust Model** | Single (FROST CA) | Multiple (FROST + Local + Cross-cert) |
| **Configuration** | Simple YAML | Extensive configuration |
| **Maintenance** | Network handles | Organization responsibility |
| **Compliance** | Limited | Full control |
| **Identity Control** | FROST issues all | Organization issues local |
| **Interoperability** | Automatic | Requires agreements |
| **Recovery** | Network-assisted | Self-managed |
| **Cost** | Lower (shared infra) | Higher (own infrastructure) |
| **Use Case** | Simple participation, edge nodes | Enterprise, regulated industries |

### Decision Guide

**Choose P2P Only when:**
- Deploying edge devices or personal nodes
- No regulatory compliance requirements
- Minimal infrastructure available
- Trust in FROST CA is sufficient
- Quick deployment is priority

**Choose Federated P2P when:**
- Enterprise deployment with existing PKI
- Regulatory requirements (HIPAA, PCI-DSS, SOX)
- Need organizational sovereignty over identity
- Multiple organizations need to interoperate
- Existing IAM/directory services to integrate
- Custom trust policies required

---

## 17. Implementation Phases

### Phase N.2: Federation Enhancement

Core federation capabilities enabling enterprise participation.

- [ ] Dual identity support (FROST + Local)
- [ ] Cross-certification protocol
- [ ] Local CA integration
- [ ] Local IAM integration
- [ ] Trust anchor management
- [ ] Certificate chain validation
- [ ] Revocation aggregation (CRL + OCSP + DHT)
- [ ] Federation configuration schema
- [ ] Basic peering agreements
- [ ] Federation registry (DHT-based)
- [ ] Cross-org service discovery
- [ ] Documentation and guides

### Phase N.3: Advanced Federation

Enterprise features and advanced interoperability.

- [ ] IAM federation (SAML/OIDC)
- [ ] Policy sharing framework
- [ ] Device profile sharing
- [ ] Service mesh integration
- [ ] Multi-organization consensus
- [ ] Federation governance
- [ ] Audit and compliance tools
- [ ] Federation analytics
- [ ] Automated cross-cert renewal
- [ ] Trust policy templates
- [ ] Federation API (REST/gRPC)
- [ ] Federation CLI tools
- [ ] Integration test suite

---

## 18. Related Documentation

- [18-platformd-p2p.md](18-platformd-p2p.md) - P2P mode fundamentals and enrollment
- [05-certificate-authority.md](05-certificate-authority.md) - FROST CA and IDevID
- [03-security-trust.md](03-security-trust.md) - Trust model and security constants
- [02-network-architecture.md](02-network-architecture.md) - DHT network topology
- [09-defense-reputation.md](09-defense-reputation.md) - Reputation system and role eligibility
- [06-consensus-coordination.md](06-consensus-coordination.md) - Coordinator roles and PBFT
- [26-organization-identity.md](26-organization-identity.md) - P2P organization identity and anti-Sybil

---

## Revision History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2026-01-10 | Initial federation specification | Technical Documentation Team |
| 1.3 | 2026-01-10 | Added Section 2 (Organization Identity vs Federation), Section 10 (Organization Identity Integration); clarified OwnerID vs OrganizationID distinction; linked to 26-organization-identity.md; updated section numbering | Technical Documentation Team |

---

**Document Version**: 1.3
**Last Updated**: 2026-01-10
**Author**: Technical Documentation Team
**Status**: Design Specification
