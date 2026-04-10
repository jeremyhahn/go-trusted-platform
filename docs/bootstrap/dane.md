# DANE (DNS-based Authentication of Named Entities)

DANE uses DNSSEC-authenticated TLSA DNS records to verify TLS certificate chains without requiring a certificate authority to be pre-trusted. The platform implements RFC 6698 (DANE) and RFC 7671 (DANE certificate usage rollover).

## TLSA Record Types

The platform publishes two TLSA record types, distinguished by the **Usage** field:

### DANE-TA (Usage=2): CA Authentication

Pins the **intermediate or root CA certificate**:

```
_8443._tcp.server.example.com. 3600 IN TLSA 2 1 1 <CA-SPKI-SHA256>
```

**Characteristics:**
- Rarely changes (CA lifetime = years)
- Should be published always
- Survives certificate renewal
- Provides defense-in-depth against rogue CAs

### DANE-EE (Usage=3): End-Entity Authentication

Pins the **leaf server certificate**:

```
_8443._tcp.server.example.com. 3600 IN TLSA 3 1 1 <LEAF-SPKI-SHA256>
```

**Characteristics:**
- Changes on every certificate renewal
- Requires RFC 7671 pre-publication rollover
- Strongest security (pins exact cert in use)
- Must be managed carefully during rollover

**Configuration:** Enable via `dns.dane.publish-dane-ee: true`

## TLSA Record Format

```
_<port>._tcp.<hostname>.  <ttl>  IN  TLSA  <usage>  <selector>  <matching-type>  <digest>
```

| Field | Values | Meaning |
|-------|--------|---------|
| `port` | 8443 | Bootstrap/REST API port |
| `hostname` | server.example.com | Server FQDN |
| `ttl` | 3600 | DNS record time-to-live |
| `usage` | 2 (TA), 3 (EE) | Certificate type pinning |
| `selector` | 1 | Hash the SPKI (Subject Public Key Info) |
| `matching-type` | 1 | SHA-256 digest |
| `digest` | hex string | SPKI SHA-256 hash (lowercase hex) |

### DNSSEC Requirement

TLSA records must be DNSSEC-signed and validated:

```yaml
dns:
  dnssec:
    enabled: true
  dane:
    enabled: true
```

Without DNSSEC, the TLSA records are not authenticated and bootstrap cannot verify them.

## Certificate Renewal and Rollover

### Simple Renewal (DANE-TA only)

When the root CA renews, update the TLSA-TA record immediately:

1. New CA cert issued
2. `DANEPublisher.PublishForCertificate()` called
3. TLSA-TA record replaced with new CA SPKI hash
4. Zone re-signed with DNSSEC
5. Clients fetch new CA cert via bootstrap

DNS propagation time is typically 5-30 minutes. Existing client connections continue using the old CA until they reconnect.

### Pre-Publication Rollover (DANE-EE, RFC 7671)

When a leaf certificate renews with key rotation:

**Phase 1: Pre-Publish** (Duration = 2 × TTL)
1. New TLSA-EE record published alongside old record
2. DNS caches begin serving both records
3. Some clients see new record, some see old (during cache invalidation)
4. New certificate not yet loaded in TLS stack

**Phase 2: Activation**
1. Timer expires (2 × TTL)
2. New certificate loaded into TLS stack atomically
3. `CertReloader.Reload()` swaps certificate pointer
4. New clients get new cert, old clients finish draining

**Phase 3: Completion**
1. Old TLSA-EE record removed
2. Zone re-signed
3. Rollover completes, state returns to idle

**Example Timeline (TTL=3600):**
- T+0:00 — New DANE-EE record published, both old+new in DNS
- T+2:00 — New cert activated in TLS stack (after 2h delay)
- T+2:10 — Old TLSA-EE record removed, zone re-signed

### Key Reuse Optimization

If the **public key does not change** (Selector=1 SPKI hash unchanged):

```yaml
dns:
  dane:
    key-reuse: true
```

Rollover completes **immediately**:
1. New certificate loaded into TLS stack
2. Existing TLSA record still valid (SPKI unchanged)
3. No pre-publish delay
4. Clients seamlessly transition

**When applicable:**
- Wildcard certificate renewal with same key
- Self-signed leaf cert renewal with held key
- Symmetric algorithm (RSA/ECDSA) unchanged

**When NOT applicable:**
- Key rotation (new RSA 2048, ECDSA P-256, Ed25519)
- Algorithm change (RSA → ECDSA)

## Rollover State Machine

The `RolloverManager` tracks rollover progress atomically:

```
[Idle]
  ↓ (BeginRollover called)
[PrePublish] — New TLSA published, wait 2×TTL
  ↓ (timeout)
[Activated] — New cert loaded, old draining
  ↓ (old TLSA removed)
[Complete]
  ↓
[Idle]
```

**State tracking:**

```go
type RolloverPhase uint32

const (
    RolloverIdle       RolloverPhase = iota  // No rollover in progress
    RolloverPrePublish                       // New record published
    RolloverActivated                        // New cert active, old draining
    RolloverComplete                         // Cleanup done
)
```

## Configuration

```yaml
dns:
  dane:
    enabled: true                      # Master on/off switch
    auto-generate: true                # Auto-publish TLSA on cert renewal
    default-port: 8443                 # Port in TLSA name
    ttl: 3600                          # TLSA record TTL
    publish-dane-ee: true              # Also publish DANE-EE (Usage=3)
    key-reuse: true                    # Skip pre-publish if SPKI unchanged
    rollover-ttl: 0                    # Custom pre-publish delay
                                       # (0 = use 2 × default-ttl)
    default-selector: 1                # Always 1 (SPKI)
    default-matching-type: 1           # Always 1 (SHA-256)
```

**TTL Considerations:**

- Higher TTL: Longer DANE cache, slower rollover
- Lower TTL: Faster rollover, higher DNS load
- Typical: 3600-7200 seconds

**Rollover Delay:**

If `rollover-ttl: 0`, computed as `2 × ttl`. Example:
- `ttl: 3600` → Rollover delay = 7200 seconds = 2 hours
- Can override: `rollover-ttl: 1800` → 30 minute pre-publish

## Verification

### Fetch TLSA Record

```bash
dig +dnssec _8443._tcp.server.example.com TLSA
```

Expected output:
```
_8443._tcp.server.example.com. 3600 IN TLSA 2 1 1 abc123def456...
_8443._tcp.server.example.com. 3600 IN TLSA 3 1 1 def456abc123...
```

The `ad` flag indicates DNSSEC validation:
```bash
dig +dnssec @8.8.8.8 _8443._tcp.server.example.com TLSA | grep ad
```

### Compute SPKI Hash

```bash
# Extract SPKI from cert
openssl x509 -in cert.pem -pubkey -noout | \
  openssl pkey -pubin -outform DER | \
  sha256sum | \
  xxd -r -p | \
  base64
```

Should match the `digest` field in TLSA record (in hex).

## Rollover Workflow

1. **Trigger renewal** — CA issues new certificate
2. **Call** `RolloverManager.BeginRollover(newCert, newTLSCert, hostname, port, zoneName)`
3. Manager checks:
   - If `key-reuse=true` and SPKI unchanged → immediate rollover
   - Otherwise → pre-publish new TLSA, start timer
4. **Phase 1 (Pre-Publish):** New TLSA in DNS for 2×TTL
5. **Phase 2 (Activation):** Timer expires, `CertReloader.Reload()` swaps cert
6. **Phase 3 (Completion):** Old TLSA removed, zone re-signed
7. **Done:** State returns to idle, ready for next renewal

## Related Standards

- **RFC 6698** — TLSA DNS Resource Record, DANE specification
- **RFC 7671** — DANE Certificate Usage Rollover (pre-publication)
- **RFC 4034** — DNSSEC Protocol Specification
