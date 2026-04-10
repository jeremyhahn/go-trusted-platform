# P2P DNS Architecture

## Overview

P2P DNS provides distributed name resolution for P2P leaf nodes that do not have their own control plane. Unlike Local mode deployments where a control plane server provides DNS for data plane nodes, P2P mode requires a decentralized approach to naming and resolution.

The architecture is built on 4 layers that provide:
1. **Automatic naming** - Every P2P node gets a resolvable name during enrollment
2. **Distributed records** - DNS records stored in the DHT, signed by node identities
3. **Global resolution** - Gateway DNS servers query the DHT for P2P domains
4. **Custom domains** - Users can bring their own domains into the P2P namespace

> **Cross-References:**
> - Network architecture: [02-network-architecture.md](02-network-architecture.md)
> - Certificate authority: [05-certificate-authority.md](05-certificate-authority.md)
> - Service discovery: [13-service-discovery.md](13-service-discovery.md)
> - Platformd P2P mode: [18-platformd-p2p.md](18-platformd-p2p.md)

---

## The Problem

In **Local mode** deployments, a control plane server provides DNS services for its data plane nodes:

```
+-------------------+      DNS Query      +------------------+
|   Client          |-------------------->|  Control Plane   |
|                   |<--------------------| (Local DNS)      |
+-------------------+      DNS Response   +------------------+
                                                    |
                                          Data Plane Nodes
                                          - node1.local.example.com
                                          - node2.local.example.com
```

In **P2P mode**, leaf nodes join directly to the DHT network without a dedicated control plane. They need:

| Requirement | Problem |
|-------------|---------|
| **Their own identity** | Other nodes need to reach them by name, not just IP address |
| **Service discovery** | Finding services on the network requires resolvable names |
| **Custom domains** | Users with their own domains want them resolvable in P2P context |

Without centralized infrastructure, leaf nodes have no way to:
- Register DNS names
- Resolve other P2P node names
- Use their own domain names

---

## 4-Layer DNS Architecture

```
+==============================================================================+
|                         P2P DNS ARCHITECTURE                                 |
+==============================================================================+
|                                                                              |
|  LAYER 4: CUSTOM DOMAINS (Optional)                                          |
|  +------------------------------------------------------------------------+  |
|  |  myapp.example.com    api.mydomain.org    service.company.io           |  |
|  |                                                                        |  |
|  |  - User proves ownership via ACME DNS-01 challenge                     |  |
|  |  - Delegate zone to P2P DNS (NS records at registrar)                  |  |
|  |  - Store DNS records in DHT, signed by IDevID                          |  |
|  +------------------------------------------------------------------------+  |
|                                     |                                        |
|                                     v                                        |
|  LAYER 3: GATEWAY DNS SERVICE (Resolution)                                   |
|  +------------------------------------------------------------------------+  |
|  |                     +------------------+                               |  |
|  |  DNS Query -------->| Gateway Node 1   |-----+                         |  |
|  |  (UDP/TCP 53)       | (Anycast)        |     |                         |  |
|  |                     +------------------+     |   DHT Lookup            |  |
|  |                                              |   + Signature           |  |
|  |                     +------------------+     |   Verification          |  |
|  |  DNS Query -------->| Gateway Node 2   |-----+                         |  |
|  |  (UDP/TCP 53)       | (Anycast)        |     |                         |  |
|  |                     +------------------+     v                         |  |
|  |                                        +----------+                    |  |
|  |  Leaf nodes configure:                 |   DHT    |                    |  |
|  |  dns.p2p.trusted-platform.io           +----------+                    |  |
|  +------------------------------------------------------------------------+  |
|                                     |                                        |
|                                     v                                        |
|  LAYER 2: DHT-DNS RECORDS (Distributed)                                      |
|  +------------------------------------------------------------------------+  |
|  |  DHT Keys:                        Record Storage:                      |  |
|  |  dns:{domain}:A      ---->        IPv4 address                         |  |
|  |  dns:{domain}:AAAA   ---->        IPv6 address                         |  |
|  |  dns:{domain}:CNAME  ---->        Canonical name                       |  |
|  |  dns:{domain}:TXT    ---->        Text records                         |  |
|  |  dns:{domain}:SRV    ---->        Service location                     |  |
|  |                                                                        |  |
|  |  ALL records signed by node's IDevID (proves ownership)                |  |
|  +------------------------------------------------------------------------+  |
|                                     |                                        |
|                                     v                                        |
|  LAYER 1: P2P DNS NAMESPACE (Automatic)                                      |
|  +------------------------------------------------------------------------+  |
|  |  Every P2P node automatically receives:                                |  |
|  |                                                                        |  |
|  |     <node-id-short>.p2p.trusted-platform.io                            |  |
|  |                                                                        |  |
|  |  Example: abc123def456.p2p.trusted-platform.io --> Node's IPv6         |  |
|  |                                                                        |  |
|  |  Created automatically during ACME enroll-01:                          |  |
|  |  1. Node receives IDevID certificate                                   |  |
|  |  2. FROST CA creates DNS record in DHT                                 |  |
|  |  3. Record signed by CA pool (threshold signature)                     |  |
|  |  4. Node is immediately resolvable                                     |  |
|  +------------------------------------------------------------------------+  |
|                                                                              |
+==============================================================================+
```

---

## Layer 1: P2P DNS Namespace (Automatic)

Every node that joins the P2P network receives an automatic DNS name during the ACME enroll-01 enrollment process.

### Automatic Naming During Enrollment

```
Node                                    FROST CA (Privacy CA Pool)
 |                                               |
 |  1. ACME enroll-01 Challenge                  |
 |---------------------------------------------->|
 |     - CSR with IDevID public key              |
 |     - TPM Quote                               |
 |                                               |
 |                              2. Verify TPM attestation
 |                              3. Issue IDevID certificate
 |                              4. Derive node-id-short:
 |                                 SHA256(IDevID pubkey)[:12]
 |                                               |
 |                              5. Create DNS record in DHT:
 |                                 Key: dns:<node-id>.p2p.trusted-platform.io:AAAA
 |                                 Value: Node's IPv6 address
 |                                 Signature: FROST threshold signature
 |                                               |
 |<----- IDevID Certificate + DNS Record --------|
 |                                               |
 | 6. Node is immediately resolvable:            |
 |    abc123def456.p2p.trusted-platform.io       |
 |                                               |
```

### DNS Name Format

```
<node-id-short>.p2p.trusted-platform.io

Where:
  node-id-short = first 12 characters of SHA256(IDevID public key)
                  encoded as lowercase hexadecimal

Example:
  IDevID Public Key --> SHA256 --> abc123def456789...
  DNS Name: abc123def456.p2p.trusted-platform.io
```

### DHT Key Pattern

```
dns:abc123def456.p2p.trusted-platform.io:AAAA --> 2602:F5BB:0001::1234
dns:abc123def456.p2p.trusted-platform.io:A    --> (via gateway NAT64 if needed)
```

### Why 12 Characters?

| Length | Collision Probability | DNS Label Valid |
|--------|----------------------|-----------------|
| 8 chars | ~1 in 4 billion | Yes |
| 12 chars | ~1 in 281 trillion | Yes |
| 16 chars | ~1 in 18 quintillion | Yes |
| 20 chars | Original NodeID | Yes |

12 characters (48 bits) provides sufficient collision resistance for DNS naming while remaining human-readable and well under the 63-character DNS label limit.

---

## Layer 2: DHT-DNS Records

DNS records are stored in the DHT with cryptographic signatures proving ownership.

### DNSRecord Structure

```go
// DNSRecord represents a DNS record stored in the DHT
type DNSRecord struct {
    // DNS record fields
    Domain    string    `json:"domain"`     // Fully qualified domain name
    Type      string    `json:"type"`       // A, AAAA, CNAME, TXT, SRV, MX
    Value     string    `json:"value"`      // Record value
    TTL       uint32    `json:"ttl"`        // Time-to-live in seconds
    Priority  uint16    `json:"priority,omitempty"`  // For MX/SRV records

    // Ownership and authentication
    OwnerID   [32]byte  `json:"owner_id"`   // SHA256 of owner's IDevID pubkey
    Signature []byte    `json:"signature"`  // IDevID signature over record
    Timestamp time.Time `json:"timestamp"`  // Record creation/update time
    ExpiresAt time.Time `json:"expires_at"` // Record expiration
}
```

### DHT Key Schema

| Record Type | DHT Key Format | Example |
|-------------|---------------|---------|
| IPv4 Address | `dns:{domain}:A` | `dns:mynode.p2p.trusted-platform.io:A` |
| IPv6 Address | `dns:{domain}:AAAA` | `dns:mynode.p2p.trusted-platform.io:AAAA` |
| Canonical Name | `dns:{domain}:CNAME` | `dns:www.example.com:CNAME` |
| Text Record | `dns:{domain}:TXT` | `dns:_dmarc.example.com:TXT` |
| Service Locator | `dns:{domain}:SRV` | `dns:_https._tcp.example.com:SRV` |
| Mail Exchange | `dns:{domain}:MX` | `dns:example.com:MX` |

### Ownership Model

| Namespace | Owner | How Ownership Established |
|-----------|-------|--------------------------|
| `*.p2p.trusted-platform.io` | FROST CA | Created during enrollment, signed by CA pool |
| Custom domains | Node that proved ownership | Via ACME DNS-01 challenge |

### Record Signature Verification

```go
// VerifyDNSRecord validates a DNS record's signature
func VerifyDNSRecord(record *DNSRecord, trustedCAs []*x509.Certificate) error {
    // 1. Reconstruct signed data
    signedData := encodeDNSRecordForSigning(record)

    // 2. For P2P namespace records, verify CA pool signature
    if isP2PNamespace(record.Domain) {
        return verifyFROSTSignature(signedData, record.Signature, trustedCAs)
    }

    // 3. For custom domains, verify owner's IDevID signature
    ownerCert, err := lookupOwnerCertificate(record.OwnerID)
    if err != nil {
        return fmt.Errorf("owner certificate not found: %w", err)
    }

    return verifyIDevIDSignature(signedData, record.Signature, ownerCert)
}
```

---

## Layer 3: Gateway DNS Service

Gateway nodes run authoritative DNS servers that resolve P2P domain queries by looking up records in the DHT.

```
                           INTERNET
                              |
              +---------------+---------------+
              |               |               |
              v               v               v
       +------------+  +------------+  +------------+
       |  Gateway   |  |  Gateway   |  |  Gateway   |
       |  Node 1    |  |  Node 2    |  |  Node 3    |
       | (Anycast)  |  | (Anycast)  |  | (Anycast)  |
       +------+-----+  +------+-----+  +------+-----+
              |               |               |
              +---------------+---------------+
                              |
                              v
                    +-----------------+
                    |   DHT Network   |
                    | (Kademlia Mesh) |
                    +-----------------+
                              |
         +--------------------+--------------------+
         |                    |                    |
         v                    v                    v
   +----------+         +----------+         +----------+
   | Record   |         | Record   |         | Record   |
   | Replica  |         | Replica  |         | Replica  |
   +----------+         +----------+         +----------+
```

### Gateway DNS Query Flow

```
Client                      Gateway DNS              DHT Network
  |                              |                        |
  | 1. DNS Query (UDP/TCP 53)   |                        |
  |   abc123.p2p.t-p.io AAAA    |                        |
  |---------------------------->|                        |
  |                              |                        |
  |                              | 2. Check local cache   |
  |                              |    (miss)              |
  |                              |                        |
  |                              | 3. DHT GET             |
  |                              |    dns:abc123.p2p.t-p.io:AAAA
  |                              |----------------------->|
  |                              |                        |
  |                              |<----- DNSRecord -------|
  |                              |                        |
  |                              | 4. Verify signature    |
  |                              |    (FROST or IDevID)   |
  |                              |                        |
  |                              | 5. Cache (respecting TTL)
  |                              |                        |
  | 6. DNS Response             |                        |
  |   abc123.p2p.t-p.io         |                        |
  |   AAAA 2602:F5BB::1234      |                        |
  |<----------------------------|                        |
  |                              |                        |
```

### Gateway DNS Responsibilities

| Responsibility | Implementation |
|----------------|----------------|
| Listen on UDP/TCP port 53 | Standard DNS server interface |
| Accept standard DNS queries | RFC 1035 compliant |
| Query DHT for P2P domain records | Kademlia GET with key derivation |
| Verify record signatures | FROST for P2P namespace, IDevID for custom |
| Cache responses | Respecting TTL from DNSRecord |
| Forward non-P2P domains | Optional upstream DNS for fallback |
| Anycast for global availability | Multiple gateways share same IP |

### Gateway DNS Implementation

```go
// GatewayDNS handles DNS queries for P2P domains
type GatewayDNS struct {
    dht          *DHT
    cache        *DNSCache
    upstreamDNS  []string  // Fallback for non-P2P domains
    trustedCAs   []*x509.Certificate
    listenAddr   string
}

// HandleQuery processes incoming DNS queries
func (g *GatewayDNS) HandleQuery(ctx context.Context, q *dns.Question) (*dns.Msg, error) {
    // Check if this is a P2P domain
    if !isP2PDomain(q.Name) {
        // Forward to upstream DNS
        return g.forwardToUpstream(ctx, q)
    }

    // Check cache first
    if cached := g.cache.Get(q.Name, q.Qtype); cached != nil {
        return cached, nil
    }

    // Build DHT key
    dhtKey := fmt.Sprintf("dns:%s:%s", q.Name, dns.TypeToString[q.Qtype])

    // Query DHT
    record, err := g.dht.Get(ctx, dhtKey)
    if err != nil {
        return nil, ErrRecordNotFound
    }

    // Verify signature
    if err := VerifyDNSRecord(record, g.trustedCAs); err != nil {
        return nil, fmt.Errorf("signature verification failed: %w", err)
    }

    // Build DNS response
    response := g.buildDNSResponse(q, record)

    // Cache the response
    g.cache.Set(q.Name, q.Qtype, response, time.Duration(record.TTL)*time.Second)

    return response, nil
}
```

### Leaf Node Configuration

Leaf nodes configure gateway DNS as their resolver:

```yaml
# /etc/platformd/config.yaml
dns:
  resolvers:
    - dns.p2p.trusted-platform.io  # Primary: P2P gateway DNS
    - 1.1.1.1                       # Fallback: Cloudflare DNS
    - 8.8.8.8                       # Fallback: Google DNS
```

---

## Layer 4: Custom Domain Support

Users with their own domains can integrate them into the P2P DNS system.

### Onboarding Flow

```
Step 1: User owns domain
+----------------------------------+
|  User's Domain: myapp.example.com|
|  Current registrar: GoDaddy      |
+----------------------------------+
                |
                v
Step 2: Prove ownership via ACME DNS-01
+----------------------------------+
|  1. Request DNS-01 challenge     |
|  2. Create TXT record:           |
|     _acme-challenge.myapp        |
|     Value: <challenge-token>     |
|  3. CA verifies TXT record       |
|  4. Ownership proof stored       |
+----------------------------------+
                |
                v
Step 3: Delegate zone to P2P DNS
+----------------------------------+
|  At registrar, add NS records:   |
|  myapp.example.com NS            |
|    ns1.p2p.trusted-platform.io   |
|    ns2.p2p.trusted-platform.io   |
+----------------------------------+
                |
                v
Step 4: Create records in DHT
+----------------------------------+
|  User creates signed records:    |
|  dns:myapp.example.com:A         |
|  dns:myapp.example.com:AAAA      |
|  dns:myapp.example.com:TXT       |
|  (Signed with node's IDevID)     |
+----------------------------------+
                |
                v
Step 5: Resolution works globally
+----------------------------------+
|  Any DNS query for              |
|  myapp.example.com              |
|  --> Delegated to P2P gateway   |
|  --> DHT lookup                 |
|  --> Returns user's records     |
+----------------------------------+
```

### DomainOwnership Structure

```go
// DomainOwnership proves a node owns a custom domain
type DomainOwnership struct {
    // Domain being claimed
    Domain      string    `json:"domain"`

    // Owner identification
    OwnerID     [32]byte  `json:"owner_id"`      // SHA256 of owner's IDevID pubkey

    // ACME DNS-01 proof
    ACMEProof   *ACMEProof `json:"acme_proof"`

    // CA verification
    CASignature []byte    `json:"ca_signature"`   // FROST CA signature over ownership
    VerifiedAt  time.Time `json:"verified_at"`    // When ownership was verified
    ExpiresAt   time.Time `json:"expires_at"`     // Ownership proof expiration
}

// ACMEProof contains the DNS-01 challenge proof
type ACMEProof struct {
    ChallengeToken string    `json:"challenge_token"`
    KeyAuth        string    `json:"key_auth"`
    VerifiedAt     time.Time `json:"verified_at"`
    OrderURL       string    `json:"order_url"`
}

// DHT key: domain-owner:{domain}
// Example: domain-owner:myapp.example.com
```

### Custom Domain Registration

```go
// RegisterCustomDomain claims ownership of a domain
func (n *Node) RegisterCustomDomain(ctx context.Context, domain string) error {
    // Step 1: Request ACME DNS-01 challenge
    challenge, err := n.acmeClient.RequestDNS01Challenge(ctx, domain)
    if err != nil {
        return fmt.Errorf("failed to request challenge: %w", err)
    }

    // Step 2: User creates TXT record at registrar (manual step)
    // _acme-challenge.{domain} TXT {challenge.Token}
    log.Printf("Create TXT record: _acme-challenge.%s = %s", domain, challenge.Token)

    // Step 3: Wait for challenge verification
    if err := n.acmeClient.WaitForChallenge(ctx, challenge); err != nil {
        return fmt.Errorf("challenge verification failed: %w", err)
    }

    // Step 4: Create ownership proof
    ownership := &DomainOwnership{
        Domain:     domain,
        OwnerID:    sha256.Sum256(n.idevid.PublicKey),
        ACMEProof:  challenge.Proof,
        VerifiedAt: time.Now(),
        ExpiresAt:  time.Now().Add(90 * 24 * time.Hour), // 90 days
    }

    // Step 5: Get CA signature over ownership
    ownership.CASignature, err = n.requestCASignature(ctx, ownership)
    if err != nil {
        return fmt.Errorf("failed to get CA signature: %w", err)
    }

    // Step 6: Store in DHT
    key := fmt.Sprintf("domain-owner:%s", domain)
    return n.dht.Put(ctx, key, ownership)
}
```

---

## DNSSEC Key Management

DNSSEC requires a hierarchical key management model to maintain the chain of trust from zone apex to individual records.

### Hierarchical Key Model

```
+==============================================================================+
|                        DNSSEC KEY HIERARCHY                                  |
+==============================================================================+
|                                                                              |
|  TIER 1: P2P NAMESPACE (p2p.trusted-platform.io)                            |
|  +------------------------------------------------------------------------+  |
|  |                                                                        |  |
|  |         +--------+   +--------+   +--------+   +--------+              |  |
|  |         | CA     |   | CA     |   | CA     |   | CA     |              |  |
|  |         | Node 1 |   | Node 2 |   | Node 3 |   | Node N |              |  |
|  |         +----+---+   +----+---+   +----+---+   +----+---+              |  |
|  |              |            |            |            |                  |  |
|  |              |   Key Share 1/N (FROST Threshold)    |                  |  |
|  |              +------------+------------+------------+                  |  |
|  |                           |                                            |  |
|  |                           v                                            |  |
|  |                  +------------------+                                  |  |
|  |                  |  KSK + ZSK       |  Zone keys held by FROST pool    |  |
|  |                  | (Threshold Sig)  |  33% threshold for signing       |  |
|  |                  +------------------+                                  |  |
|  |                                                                        |  |
|  +------------------------------------------------------------------------+  |
|                                                                              |
|  TIER 2: FEDERATED ZONES (orgA.example.com)                                 |
|  +------------------------------------------------------------------------+  |
|  |                                                                        |  |
|  |     +-----------------------------+                                    |  |
|  |     |   Federated Control Plane   |                                    |  |
|  |     |                             |                                    |  |
|  |     |   +---------------------+   |                                    |  |
|  |     |   | DNSSEC Key Manager  |   |  KSK + ZSK held by federated      |  |
|  |     |   | - KSK (long-lived)  |   |  control plane server             |  |
|  |     |   | - ZSK (rotates)     |   |                                    |  |
|  |     |   +---------------------+   |                                    |  |
|  |     |             |               |                                    |  |
|  |     +-------------|---------------+                                    |  |
|  |                   |                                                    |  |
|  |         Signs records for all leaf nodes in zone                       |  |
|  |                                                                        |  |
|  +------------------------------------------------------------------------+  |
|                                                                              |
|  TIER 3: CUSTOM DOMAINS (myapp.example.com - single owner)                  |
|  +------------------------------------------------------------------------+  |
|  |                                                                        |  |
|  |     +-----------------------------+                                    |  |
|  |     |   Domain Owner's Node       |                                    |  |
|  |     |                             |                                    |  |
|  |     |   +---------------------+   |  KSK + ZSK held by domain owner    |  |
|  |     |   | DNSSEC Keys (TPM)   |   |  Keys stored in TPM                |  |
|  |     |   | - KSK               |   |  Owner signs own records           |  |
|  |     |   | - ZSK               |   |                                    |  |
|  |     |   +---------------------+   |                                    |  |
|  |     |                             |                                    |  |
|  |     +-----------------------------+                                    |  |
|  |                                                                        |  |
|  +------------------------------------------------------------------------+  |
|                                                                              |
+==============================================================================+
```

### Why Leaf Nodes Cannot Sign Their Own DNSSEC Records

Leaf nodes in the P2P namespace **cannot** sign their own DNSSEC records because:

1. **They do not hold the zone's ZSK**: The Zone Signing Key for `p2p.trusted-platform.io` is held by the FROST CA pool
2. **DNSSEC requires chain of trust from zone apex**: Each RRSIG must chain up to the zone's DNSKEY
3. **Each leaf holding its own key would break the chain**: DNS resolvers verify `RRSIG -> DNSKEY -> DS -> parent zone`

### Leaf Node DNS Update Flow (Federated)

```
Leaf Node                    Federated Control Plane           DNS/DHT
    |                                   |                         |
    | 1. DNS Update Request             |                         |
    |    (signed by IDevID)             |                         |
    |---------------------------------->|                         |
    |                                   |                         |
    |                   2. Verify IDevID|                         |
    |                      - Chain to CA|                         |
    |                      - Trust level|                         |
    |                      - Node ID    |                         |
    |                                   |                         |
    |                   3. Create DNS   |                         |
    |                      record       |                         |
    |                                   |                         |
    |                   4. Sign with    |                         |
    |                      zone ZSK     |                         |
    |                      (DNSSEC RRSIG)                         |
    |                                   |                         |
    |                                   | 5. Store record + RRSIG |
    |                                   |------------------------>|
    |                                   |                         |
    |                                   |<---- Confirmation ------|
    |                                   |                         |
    |<-- Update Confirmed --------------|                         |
    |                                   |                         |
```

### P2P Namespace DNSSEC (Tier 1)

The `p2p.trusted-platform.io` zone uses FROST threshold signatures:

```go
// P2PNamespaceDNSSEC handles DNSSEC for the P2P namespace
type P2PNamespaceDNSSEC struct {
    // FROST key shares for KSK and ZSK
    kskShare *FROSTKeyShare  // Key Signing Key share
    zskShare *FROSTKeyShare  // Zone Signing Key share

    // Pool configuration
    threshold  int  // e.g., 33% of nodes
    totalNodes int
}

// SignDNSRecord creates an RRSIG for a DNS record
func (d *P2PNamespaceDNSSEC) SignDNSRecord(ctx context.Context, record *DNSRecord) (*RRSIG, error) {
    // Create signing data (wire format)
    rrsetData := encodeRRSet(record)

    // Initiate FROST threshold signing
    session, err := d.initiateSigningSession(ctx, rrsetData)
    if err != nil {
        return nil, fmt.Errorf("failed to initiate signing: %w", err)
    }

    // Collect signature shares from threshold nodes
    shares, err := d.collectSignatureShares(ctx, session)
    if err != nil {
        return nil, fmt.Errorf("failed to collect shares: %w", err)
    }

    // Aggregate into final signature
    signature := d.aggregateShares(shares)

    return &RRSIG{
        TypeCovered: record.Type,
        Algorithm:   dnssec.ED25519,
        Labels:      countLabels(record.Domain),
        OrigTTL:     record.TTL,
        Expiration:  uint32(record.ExpiresAt.Unix()),
        Inception:   uint32(record.Timestamp.Unix()),
        KeyTag:      d.zskKeyTag,
        SignerName:  "p2p.trusted-platform.io.",
        Signature:   signature,
    }, nil
}
```

---

## Integration with Federation

Federated deployments have two options for DNS integration:

```
+==============================================================================+
|                    FEDERATION DNS INTEGRATION                                |
+==============================================================================+
|                                                                              |
|  +----------------------------------+    +--------------------------------+  |
|  |     FEDERATED CONTROL PLANE      |    |      P2P BACKBONE              |  |
|  |                                  |    |                                |  |
|  |  +----------------------------+  |    |  +------------------------+    |  |
|  |  |    Local DNS Server        |  |    |  |    Gateway DNS         |    |  |
|  |  |    (orgA.example.com)      |  |    |  | (p2p.trusted-platform.io)   |  |
|  |  +-------------+--------------+  |    |  +-----------+------------+    |  |
|  |                |                 |    |              |                 |  |
|  |                v                 |    |              v                 |  |
|  |  +----------------------------+  |    |  +------------------------+    |  |
|  |  |    Leaf Nodes              |  |    |  |       DHT Network      |    |  |
|  |  |  - node1.orgA.example.com  |  |    |  |   (Record Storage)     |    |  |
|  |  |  - node2.orgA.example.com  |  |    |  +------------------------+    |  |
|  |  +----------------------------+  |    |                                |  |
|  +----------------------------------+    +--------------------------------+  |
|                                                                              |
|  OPTION A: Federated Node Authoritative                                      |
|  +------------------------------------------------------------------------+  |
|  |  - Control plane is authoritative DNS for its zone                     |  |
|  |  - DHT serves as backup/replication                                    |  |
|  |  - Local queries go direct, external via DHT                           |  |
|  +------------------------------------------------------------------------+  |
|                                                                              |
|  OPTION B: Federated Node Delegates to P2P DNS                              |
|  +------------------------------------------------------------------------+  |
|  |  - Control plane delegates zone to P2P gateway DNS                     |  |
|  |  - All DNS stored in DHT                                               |  |
|  |  - Control plane only signs records (DNSSEC)                           |  |
|  +------------------------------------------------------------------------+  |
|                                                                              |
+==============================================================================+
```

---

## Configuration Examples

### Leaf Node (P2P Only)

```yaml
# /etc/platformd/config.yaml
# Leaf node - automatic DNS naming, no configuration needed

# DNS name is automatically assigned during enrollment:
#   <node-id>.p2p.trusted-platform.io

dns:
  # Use P2P gateway DNS as primary resolver
  resolvers:
    - dns.p2p.trusted-platform.io
    - 1.1.1.1   # Fallback: Cloudflare
    - 8.8.8.8   # Fallback: Google

  # No local DNS server (leaf nodes don't serve DNS)
  server:
    enabled: false
```

### Custom Domain

```yaml
# /etc/platformd/config.yaml
# Node with custom domain

dns:
  resolvers:
    - dns.p2p.trusted-platform.io
    - 1.1.1.1

  # Custom domain configuration
  custom_domains:
    - domain: myapp.example.com
      # Prove ownership via ACME DNS-01
      acme_challenge: dns-01

      # Records to create in DHT
      records:
        - type: A
          value: "${node.ipv4}"
          ttl: 300

        - type: AAAA
          value: "${node.ipv6}"
          ttl: 300

        - type: TXT
          value: "v=spf1 -all"
          ttl: 3600

        - type: TXT
          name: "_dmarc"
          value: "v=DMARC1; p=reject"
          ttl: 3600

    - domain: api.example.com
      acme_challenge: dns-01
      records:
        - type: AAAA
          value: "${node.ipv6}"
          ttl: 60
```

### Federated Node with Local DNS

```yaml
# /etc/platformd/config.yaml
# Federated control plane with local DNS authority

federation:
  enabled: true
  role: control_plane

  # Local DNS server configuration
  local_dns:
    enabled: true

    # Zone this server is authoritative for
    zone: "orgA.example.com."

    # Store records in DHT as backup
    dht_backup: true

    # Forward queries for P2P domains to gateway
    forward_p2p_to_gateway: true

    # DNSSEC configuration
    dnssec:
      enabled: true
      ksk_algorithm: ED25519
      zsk_algorithm: ED25519
      zsk_rotation_days: 30

  # Leaf node DNS pattern
  leaf_dns_pattern: "{node_name}.orgA.example.com"
```

---

## Security Considerations

| Threat | Mitigation |
|--------|------------|
| **DNS spoofing** | All records signed by IDevID or FROST CA - signature verified before use |
| **Domain hijacking** | Ownership proven via ACME DNS-01 challenge, stored with CA signature |
| **DHT pollution** | Only records signed by valid IDevID certificates are accepted |
| **Stale records** | TTL + expiry timestamps, periodic renewal required |
| **Gateway compromise** | Anycast across multiple gateways + clients can verify signatures |
| **DNSSEC chain break** | Hierarchical key model maintains proper chain of trust |
| **Replay attacks** | Timestamps + expiration prevent old records from being replayed |
| **Man-in-the-middle** | TLS for DNS-over-HTTPS/TLS, DNSSEC for UDP/TCP |

### Record Validation

```go
// ValidateDNSRecord performs comprehensive validation
func ValidateDNSRecord(record *DNSRecord) error {
    // 1. Check expiration
    if time.Now().After(record.ExpiresAt) {
        return ErrRecordExpired
    }

    // 2. Check timestamp is not in future
    if record.Timestamp.After(time.Now().Add(5 * time.Minute)) {
        return ErrTimestampInFuture
    }

    // 3. Verify signature
    if err := VerifyDNSRecord(record, trustedCAs); err != nil {
        return fmt.Errorf("signature invalid: %w", err)
    }

    // 4. For custom domains, verify ownership
    if !isP2PNamespace(record.Domain) {
        ownership, err := lookupDomainOwnership(record.Domain)
        if err != nil {
            return ErrNoOwnershipProof
        }
        if ownership.OwnerID != record.OwnerID {
            return ErrOwnerMismatch
        }
        if time.Now().After(ownership.ExpiresAt) {
            return ErrOwnershipExpired
        }
    }

    return nil
}
```

---

## DHT Key Patterns Summary

| Purpose | Key Pattern | Example |
|---------|-------------|---------|
| DNS A record | `dns:{domain}:A` | `dns:mynode.p2p.trusted-platform.io:A` |
| DNS AAAA record | `dns:{domain}:AAAA` | `dns:mynode.p2p.trusted-platform.io:AAAA` |
| DNS CNAME record | `dns:{domain}:CNAME` | `dns:www.example.com:CNAME` |
| DNS TXT record | `dns:{domain}:TXT` | `dns:_dmarc.example.com:TXT` |
| DNS SRV record | `dns:{domain}:SRV` | `dns:_https._tcp.example.com:SRV` |
| DNS MX record | `dns:{domain}:MX` | `dns:example.com:MX` |
| Domain ownership | `domain-owner:{domain}` | `domain-owner:myapp.example.com` |

---

## Implementation Phases

### Phase N.1.5: Basic P2P DNS

- [ ] Implement DNSRecord struct and serialization
- [ ] Create DHT key derivation for DNS records
- [ ] Automatic DNS record creation during enroll-01
- [ ] FROST CA signs P2P namespace records
- [ ] Basic Gateway DNS server implementation
- [ ] DNS record signature verification
- [ ] Local DNS caching with TTL respect
- [ ] Leaf node resolver configuration
- [ ] Unit tests for all components
- [ ] Integration tests with DHT

### Phase N.1.6: Custom Domains

- [ ] ACME DNS-01 challenge implementation
- [ ] DomainOwnership struct and storage
- [ ] CA signature for ownership proofs
- [ ] Custom domain record creation API
- [ ] Ownership expiration and renewal
- [ ] DNS record update/delete for custom domains
- [ ] Multi-record support per domain
- [ ] platformctl DNS management commands
- [ ] Integration tests for custom domains
- [ ] Documentation and examples

### Phase N.2: Federated DNS

- [ ] Local DNS server for federated control planes
- [ ] Zone file generation from DHT records
- [ ] DNSSEC key generation and management
- [ ] KSK/ZSK rotation automation
- [ ] DHT backup for federated zones
- [ ] Cross-zone forwarding
- [ ] Federated node DNSSEC signing
- [ ] Leaf node DNS update protocol
- [ ] Integration tests for federation
- [ ] Multi-protocol API exposure (REST, gRPC, QUIC, MCP, Unix)

---

## Related Documentation

- [02-network-architecture.md](02-network-architecture.md) - DHT network topology and Kademlia routing
- [05-certificate-authority.md](05-certificate-authority.md) - FROST CA and IDevID enrollment
- [13-service-discovery.md](13-service-discovery.md) - Service registration and discovery in DHT
- [18-platformd-p2p.md](18-platformd-p2p.md) - Platformd P2P mode and enrollment flow
- [19-service-contracts.md](19-service-contracts.md) - Service contracts and SLA definitions

---

**Document Version:** 1.0
**Last Updated:** 2026-01-10
**Author:** Platform Documentation Team
