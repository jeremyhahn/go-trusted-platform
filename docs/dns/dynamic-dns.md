# Dynamic DNS (DDNS)

## Overview

Dynamic DNS (DDNS) enables programmatic updates to DNS records without manual zone file editing. The Trusted Platform implements RFC 2136 DNS UPDATE protocol with TSIG authentication for secure, automated record management.

### What is Dynamic DNS

Dynamic DNS allows devices and services to update their DNS records automatically when IP addresses change or when records need modification. Unlike traditional static DNS where records are manually configured, DDNS provides:

- Automatic IP address updates for devices with dynamic IPs
- Programmatic record management for automation workflows
- Self-service device registration for onboarding
- Secure parent zone updates for DNSSEC delegation

### RFC 2136 DNS UPDATE Protocol

RFC 2136 defines the DNS UPDATE message format for adding, deleting, and modifying DNS resource records. Key characteristics:

| Aspect | Description |
|--------|-------------|
| Transport | UDP/TCP port 53 |
| Authentication | TSIG (RFC 2845) or SIG(0) |
| Atomicity | All updates in a message succeed or fail together |
| Prerequisites | Optional conditions that must be met before update |
| Zones | Updates scoped to a single zone |

### Use Cases

| Use Case | Description |
|----------|-------------|
| Device Registration | Devices register their hostnames on network join |
| IP Address Updates | Update A/AAAA records when DHCP assigns new address |
| KSK Rollover | Submit new DS records to parent zone during key rotation |
| ACME DNS-01 | Create TXT records for certificate validation |
| Service Discovery | Register SRV records for service endpoints |
| Reverse DNS | Update PTR records for reverse lookups |

## DDNS Client

The Trusted Platform provides a built-in DDNS client for performing RFC 2136 updates against local and remote DNS servers.

### Features

| Feature | Description |
|---------|-------------|
| RFC 2136 Compliant | Full implementation of DNS UPDATE protocol |
| TSIG Authentication | RFC 2845 transaction signatures for secure updates |
| Automatic Retry | Exponential backoff with configurable retry count |
| Multiple Servers | Failover support for redundant nameservers |
| Zone Discovery | Automatic zone detection from FQDN |
| Transaction Logging | Full audit trail of update operations |

### Supported Operations

| Operation | Description | RFC Section |
|-----------|-------------|-------------|
| Add | Create new resource record | RFC 2136 Section 2.5.1 |
| Delete | Remove existing resource record | RFC 2136 Section 2.5.2 |
| DeleteRRset | Remove all records of a type | RFC 2136 Section 2.5.2 |
| DeleteAll | Remove all records for a name | RFC 2136 Section 2.5.3 |
| Update | Atomic delete + add (replace) | Combined operation |

### Supported Record Types

| Record Type | Use Case | Notes |
|-------------|----------|-------|
| A | IPv4 host registration | Primary use case for device registration |
| AAAA | IPv6 host registration | Dual-stack device support |
| TXT | ACME DNS-01 challenges | Certificate validation records |
| DS | DNSSEC delegation | Parent zone chain of trust |
| PTR | Reverse DNS lookups | IP to hostname mapping |
| CNAME | Alias records | Service endpoint aliases |
| SRV | Service discovery | Service location records |
| MX | Mail server updates | Dynamic mail routing |

## TSIG Authentication

TSIG (Transaction Signature) provides message authentication for DNS updates using shared secret keys.

### Supported Algorithms

| Algorithm | OID | Security | Recommendation |
|-----------|-----|----------|----------------|
| hmac-sha256 | hmac-sha256.sig-alg.reg.int | High | Recommended |
| hmac-sha512 | hmac-sha512.sig-alg.reg.int | Very High | High security environments |
| hmac-sha384 | hmac-sha384.sig-alg.reg.int | Very High | Alternative to SHA-512 |
| hmac-md5 | hmac-md5.sig-alg.reg.int | Low | Legacy only, not recommended |

### Key Management

TSIG keys are managed through the platform's key management infrastructure:

| Storage | Description | Use Case |
|---------|-------------|----------|
| go-quicbaas | Platform datastore with encryption | Standard deployments |
| TPM-sealed | Hardware-bound key protection | Production environments |
| Configuration | Base64 in config file | Development/testing only |

**TPM-Sealed Keys:**

For production deployments, TSIG secrets are sealed to the TPM:

```go
// TSIG key sealed to TPM PCR values
tsigKey := &entities.TSIGKey{
    Name:      "ddns-key",
    Algorithm: "hmac-sha256",
    Secret:    tpmSealedSecret,
    Sealed:    true,
    PCRs:      []int{0, 1, 2, 3, 7},
}
```

**Per-Server and Per-Zone Keys:**

Keys can be scoped to specific servers or zones for fine-grained access control:

| Scope | Description |
|-------|-------------|
| Server-specific | Key valid only for a specific nameserver |
| Zone-specific | Key authorized for updates in a single zone |
| Wildcard | Key authorized for multiple zones (use sparingly) |

## Configuration

### Client Configuration

```yaml
ddns:
  enabled: true
  retry-count: 3
  retry-delay: 30s
  timeout: 10s
  servers:
    - name: parent-ns1
      address: ns1.parent.example.com:53
      zone: parent.example.com.
      tsig:
        name: ddns-key
        algorithm: hmac-sha256
        secret: base64-encoded-secret
    - name: parent-ns2
      address: ns2.parent.example.com:53
      zone: parent.example.com.
      tsig:
        name: ddns-key
        algorithm: hmac-sha256
        secret: base64-encoded-secret
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | false | Enable DDNS client |
| `retry-count` | int | 3 | Number of retry attempts on failure |
| `retry-delay` | duration | 30s | Initial delay between retries (exponential backoff) |
| `timeout` | duration | 10s | Timeout for each update request |
| `servers` | list | - | List of target DNS servers |

### Server Entry Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `name` | string | Yes | Friendly name for the server |
| `address` | string | Yes | Server address with port (host:port) |
| `zone` | string | Yes | Zone this server is authoritative for |
| `tsig.name` | string | Yes | TSIG key name |
| `tsig.algorithm` | string | Yes | HMAC algorithm identifier |
| `tsig.secret` | string | Yes | Base64-encoded shared secret |

### Server Configuration

Configure the platform DNS server to accept dynamic updates:

```yaml
dns:
  allow-registration: true
  allow-external-registration: false
  allow-internal-registration: true

  ddns:
    enabled: true
    require-tsig: true
    allowed-update-types:
      - A
      - AAAA
      - TXT
      - PTR
    rate-limit:
      requests-per-minute: 60
      burst: 10
```

### Server Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `allow-registration` | bool | false | Master switch for registration |
| `allow-external-registration` | bool | false | Allow public zone updates |
| `allow-internal-registration` | bool | true | Allow internal zone updates |
| `ddns.enabled` | bool | false | Enable RFC 2136 UPDATE handling |
| `ddns.require-tsig` | bool | true | Require TSIG authentication |
| `ddns.allowed-update-types` | list | - | Whitelist of updatable record types |
| `ddns.rate-limit.requests-per-minute` | int | 60 | Rate limit for updates |
| `ddns.rate-limit.burst` | int | 10 | Burst allowance for rate limiting |

## Usage

### Device Registration

**Register device with auto-detected IP:**

```bash
# Auto-detect local IP and register
platformctl dns update mydevice.internal --auto
```

**Register with specific IP address:**

```bash
# Register A record with explicit IP
platformctl dns update mydevice.internal 192.168.1.100

# Register AAAA record for IPv6
platformctl dns update mydevice.internal 2001:db8::1 --type AAAA
```

**Remove registration:**

```bash
# Delete A record
platformctl dns delete mydevice.internal

# Delete specific record type
platformctl dns delete mydevice.internal --type AAAA
```

### Programmatic Usage

```go
import (
    "context"
    "github.com/jeremyhahn/go-trusted-platform/pkg/dns/ddns"
    "github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
)

// Create DDNS client
client, err := ddns.NewClient(ddns.ClientConfig{
    RetryCount: 3,
    RetryDelay: 30 * time.Second,
    Timeout:    10 * time.Second,
    Servers: []ddns.ServerConfig{
        {
            Name:    "ns1",
            Address: "ns1.example.com:53",
            Zone:    "example.com.",
            TSIG: ddns.TSIGConfig{
                Name:      "ddns-key",
                Algorithm: "hmac-sha256",
                Secret:    "base64secret==",
            },
        },
    },
})
if err != nil {
    return err
}

// Add A record
err = client.UpdateA(ctx, ddns.OpAdd, &entities.ARecord{
    Name:  "server1",
    Value: "192.168.1.50",
    TTL:   3600,
})
if err != nil {
    return fmt.Errorf("failed to add A record: %w", err)
}

// Update (replace) A record
err = client.UpdateA(ctx, ddns.OpUpdate, &entities.ARecord{
    Name:  "server1",
    Value: "192.168.1.51",
    TTL:   3600,
})

// Delete A record
err = client.UpdateA(ctx, ddns.OpDelete, &entities.ARecord{
    Name: "server1",
})

// Update DS record for DNSSEC
err = client.UpdateDS(ctx, ddns.OpAdd, &entities.DSRecord{
    Name:       "child.example.com.",
    KeyTag:     12345,
    Algorithm:  13, // ECDSAP256SHA256
    DigestType: 2,  // SHA-256
    Digest:     "abc123...",
    TTL:        3600,
})

// Add TXT record for ACME DNS-01
err = client.UpdateTXT(ctx, ddns.OpAdd, &entities.TXTRecord{
    Name:  "_acme-challenge.www",
    Value: "gfj9Xq...Rg85nM",
    TTL:   300,
})
```

### Batch Updates

```go
// Create batch update
batch := ddns.NewBatch()

// Add multiple records to batch
batch.Add(ddns.OpAdd, &entities.ARecord{
    Name:  "web1",
    Value: "192.168.1.10",
    TTL:   3600,
})
batch.Add(ddns.OpAdd, &entities.ARecord{
    Name:  "web2",
    Value: "192.168.1.11",
    TTL:   3600,
})
batch.Add(ddns.OpDelete, &entities.ARecord{
    Name: "old-server",
})

// Execute batch atomically
err := client.ExecuteBatch(ctx, batch)
```

## Security Considerations

### TSIG Key Protection

| Practice | Description |
|----------|-------------|
| TPM Sealing | Use TPM-sealed keys in production environments |
| Key Rotation | Rotate TSIG keys on a regular schedule (quarterly recommended) |
| Scope Limitation | Limit key scope to specific zones or servers |
| Secret Length | Use keys with at least 256 bits of entropy |
| Secure Distribution | Use secure channels for initial key distribution |

**Key rotation example:**

```go
// Generate new TSIG key
newKey, err := ddns.GenerateTSIGKey(ddns.TSIGKeyConfig{
    Name:      "ddns-key-2025q1",
    Algorithm: "hmac-sha256",
    Bits:      256,
})

// Seal to TPM
sealedKey, err := tpm.Seal(newKey.Secret, tpm.SealConfig{
    PCRs: []int{0, 1, 2, 3, 7},
})

// Store in datastore
err = keyStore.Save(ctx, &entities.TSIGKey{
    Name:      newKey.Name,
    Algorithm: newKey.Algorithm,
    Secret:    sealedKey,
    Sealed:    true,
    CreatedAt: time.Now(),
    ExpiresAt: time.Now().AddDate(0, 3, 0), // 3 months
})
```

### Access Control

| Control | Description |
|---------|-------------|
| Source IP Validation | Restrict updates to known IP addresses when possible |
| Rate Limiting | Prevent abuse with request rate limits |
| Zone Restrictions | Limit which zones accept dynamic updates |
| Record Type Whitelist | Only allow updates to specific record types |
| Audit Logging | Log all update operations with full details |

### Network Security

| Recommendation | Description |
|----------------|-------------|
| Private Networks | Use private networks for internal zone updates |
| DNS over TLS | Consider DoT for updates over untrusted networks |
| Firewall Rules | Restrict port 53 access to authorized clients |
| VPN | Route updates through VPN for remote devices |

## Integration with DNSSEC Rollover

DDNS plays a critical role in automated DNSSEC key rollover by updating DS records in parent zones.

### KSK Rollover Workflow

```
Child Zone                    DDNS Client                   Parent Zone
    |                              |                              |
    | 1. Generate new KSK          |                              |
    |----------------------------->|                              |
    |                              |                              |
    | 2. Create DS from DNSKEY     |                              |
    |----------------------------->|                              |
    |                              |                              |
    | 3. TPM attestation           |                              |
    |    (time-limited TSIG)       |                              |
    |----------------------------->|                              |
    |                              |                              |
    |                              | 4. DNS UPDATE with DS        |
    |                              |----------------------------->|
    |                              |                              |
    |                              |          5. Verify TSIG      |
    |                              |          6. Apply update     |
    |                              |                              |
    |                              | 7. NOERROR response          |
    |                              |<-----------------------------|
    |                              |                              |
    | 8. Verify DS propagation     |                              |
    |----------------------------->|                              |
    |                              |                              |
    | 9. Complete rollover         |                              |
    |----------------------------->|                              |
```

### Implementation

```go
// During KSK rollover
func (r *KeyRollover) submitDSToParent(ctx context.Context) error {
    // Generate DS record from new KSK
    dsRecord, err := r.generateDS(r.newKSK)
    if err != nil {
        return fmt.Errorf("failed to generate DS: %w", err)
    }

    // Get time-limited TSIG from TPM attestation
    tsig, err := r.attestation.GetTimeLimitedTSIG(ctx, ddns.TSIGConfig{
        Duration:  1 * time.Hour,
        Algorithm: "hmac-sha256",
    })
    if err != nil {
        return fmt.Errorf("failed to get attested TSIG: %w", err)
    }

    // Create DDNS client with attested TSIG
    client, err := ddns.NewClient(ddns.ClientConfig{
        Servers: r.config.ParentServers,
        TSIG:    tsig,
    })
    if err != nil {
        return fmt.Errorf("failed to create DDNS client: %w", err)
    }

    // Submit DS record to parent
    err = client.UpdateDS(ctx, ddns.OpAdd, dsRecord)
    if err != nil {
        return fmt.Errorf("failed to submit DS to parent: %w", err)
    }

    // Verify DS propagation
    err = r.verifyDSPropagation(ctx, dsRecord)
    if err != nil {
        return fmt.Errorf("DS propagation verification failed: %w", err)
    }

    return nil
}
```

## Error Handling

### DNS RCODE Values

| RCODE | Name | Meaning | Recommended Action |
|-------|------|---------|-------------------|
| 0 | NOERROR | Update successful | Continue workflow |
| 1 | FORMERR | Malformed request | Check request format |
| 2 | SERVFAIL | Server error | Retry with backoff |
| 3 | NXDOMAIN | Name does not exist | Check zone and name |
| 4 | NOTIMP | Not implemented | Server lacks UPDATE support |
| 5 | REFUSED | Update refused | Check TSIG and permissions |
| 8 | NXRRSET | RRset does not exist | May be expected for delete |
| 9 | NOTAUTH | Not authoritative | Check zone configuration |
| 10 | NOTZONE | Name not in zone | Check FQDN matches zone |

### Error Types

```go
var (
    // TSIG errors
    ErrTSIGKeyNotFound     = errors.New("TSIG key not found")
    ErrTSIGVerifyFailed    = errors.New("TSIG verification failed")
    ErrTSIGAlgorithmInvalid = errors.New("invalid TSIG algorithm")

    // Update errors
    ErrUpdateRefused       = errors.New("update refused by server")
    ErrUpdateTimeout       = errors.New("update request timed out")
    ErrUpdateNotAuth       = errors.New("server not authoritative for zone")
    ErrUpdatePrereqFailed  = errors.New("update prerequisite not met")

    // Configuration errors
    ErrNoServersConfigured = errors.New("no DDNS servers configured")
    ErrInvalidServerAddress = errors.New("invalid server address")
)
```

### Retry Logic

The client implements exponential backoff for transient failures:

```go
// Retry configuration
RetryConfig{
    MaxAttempts:    3,
    InitialDelay:   30 * time.Second,
    MaxDelay:       5 * time.Minute,
    Multiplier:     2.0,
    RetryableCodes: []int{SERVFAIL}, // Only retry server errors
}
```

## CLI Reference

### Update Commands

| Command | Description |
|---------|-------------|
| `platformctl dns update <fqdn> <ip>` | Add or update A/AAAA record |
| `platformctl dns update <fqdn> --auto` | Auto-detect IP and update |
| `platformctl dns update <fqdn> --type <type>` | Specify record type |

### Delete Commands

| Command | Description |
|---------|-------------|
| `platformctl dns delete <fqdn>` | Remove A record |
| `platformctl dns delete <fqdn> --type <type>` | Remove specific record type |
| `platformctl dns delete <fqdn> --all` | Remove all records for name |

### Common Options

| Option | Description |
|--------|-------------|
| `--server <addr>` | Override configured server |
| `--zone <zone>` | Specify zone for update |
| `--ttl <seconds>` | Set record TTL (default: 3600) |
| `--type <type>` | Record type (A, AAAA, TXT, PTR) |
| `--auto` | Auto-detect local IP address |
| `--dry-run` | Show what would be done without executing |
| `--verbose` | Enable verbose output |

### Examples

```bash
# Register device with default TTL
platformctl dns update myhost.trusted-platform.internal 192.168.1.100

# Register with custom TTL
platformctl dns update myhost.trusted-platform.internal 192.168.1.100 --ttl 7200

# Auto-detect IP and register
platformctl dns update myhost.trusted-platform.internal --auto

# Update IPv6 record
platformctl dns update myhost.trusted-platform.internal 2001:db8::1 --type AAAA

# Delete A record
platformctl dns delete myhost.trusted-platform.internal

# Delete all records for a name
platformctl dns delete myhost.trusted-platform.internal --all

# Dry run to see what would happen
platformctl dns update myhost.trusted-platform.internal 192.168.1.100 --dry-run

# Use specific server
platformctl dns update myhost.trusted-platform.internal 192.168.1.100 \
  --server ns1.trusted-platform.internal:53
```

## Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| REFUSED response | Invalid TSIG or permissions | Verify TSIG key and algorithm match |
| SERVFAIL response | Server internal error | Check server logs, retry later |
| NOTAUTH response | Wrong server for zone | Verify server is authoritative |
| Timeout | Network or server issue | Check connectivity, increase timeout |
| TSIG verification failed | Clock skew or key mismatch | Sync clocks, verify key configuration |

### Debugging

```bash
# Enable debug logging
platformctl dns update myhost.internal 192.168.1.100 --verbose

# Check TSIG key configuration
platformctl dns tsig list

# Test connectivity to nameserver
platformctl dns ping ns1.trusted-platform.internal:53

# Verify current record
dig @ns1.trusted-platform.internal myhost.trusted-platform.internal A
```

## Attestation-Gated Updates

### Overview

TPM attestation-gated DNS updates require devices to prove platform integrity before modifications are accepted. This provides an additional layer of security beyond TSIG authentication by cryptographically verifying that the requesting device is in a known-good state before allowing any DNS changes.

Attestation-gated updates ensure:

| Guarantee | Description |
|-----------|-------------|
| Platform Integrity | Device firmware and software are unmodified |
| Device Identity | Request originates from an authorized device |
| Freshness | Quote is recent, preventing replay attacks |
| Policy Compliance | PCR values match expected boot configuration |

### Zone-Level Configuration

Enable attestation requirements at the zone level:

```yaml
dns:
  zones:
    - name: "secure.example.com."
      attestation:
        required: true
        max-age: 5m
        pcr-policy: "standard-boot"
        allowed-ek-certs:
          - "/path/to/manufacturer-ca.pem"
        fallback: deny  # deny, allow-with-warning, cached-quote
```

### Attestation Workflow

The following diagram illustrates the complete attestation flow for DNS updates:

```
Client                     Attestation Service              DNS Server
  |                               |                              |
  | 1. Request attestation        |                              |
  |------------------------------>|                              |
  |                               |                              |
  | 2. Challenge (nonce)          |                              |
  |<------------------------------|                              |
  |                               |                              |
  | 3. TPM Quote + PCRs           |                              |
  |------------------------------>|                              |
  |                               |                              |
  |       4. Verify quote         |                              |
  |       5. Check PCR policy     |                              |
  |                               |                              |
  | 6. Attestation token          |                              |
  |<------------------------------|                              |
  |                               |                              |
  | 7. DNS UPDATE + attestation token                            |
  |------------------------------------------------------------->|
  |                               |                              |
  |                               |          8. Validate token   |
  |                               |          9. Apply update     |
  |                               |                              |
  | 10. NOERROR response                                         |
  |<-------------------------------------------------------------|
```

**Workflow Steps:**

1. Client requests attestation from the attestation service
2. Attestation service returns a cryptographic nonce challenge
3. Client generates TPM quote including PCR values and the nonce
4. Attestation service verifies the quote signature using the EK certificate
5. Attestation service checks PCR values against the configured policy
6. If verification passes, attestation service issues a time-limited token
7. Client includes the attestation token with the DNS UPDATE request
8. DNS server validates the token signature and expiration
9. DNS server applies the requested update
10. DNS server returns success response to client

### Attestation Token Format

The attestation token is a signed JSON structure:

```json
{
  "version": 1,
  "issued": "2025-01-15T10:30:00Z",
  "expires": "2025-01-15T10:35:00Z",
  "device_id": "device-001.secure.example.com",
  "ek_fingerprint": "sha256:abc123def456...",
  "pcr_digest": "sha256:789xyz...",
  "allowed_operations": ["add", "update", "delete"],
  "allowed_zones": ["secure.example.com."],
  "signature": "base64-encoded-signature"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `version` | int | Token format version |
| `issued` | timestamp | Token issuance time |
| `expires` | timestamp | Token expiration time |
| `device_id` | string | Unique device identifier |
| `ek_fingerprint` | string | SHA-256 fingerprint of EK certificate |
| `pcr_digest` | string | Hash of verified PCR values |
| `allowed_operations` | list | Permitted DNS operations |
| `allowed_zones` | list | Zones this token authorizes |
| `signature` | string | Attestation service signature |

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `required` | bool | false | Require attestation for all updates in this zone |
| `max-age` | duration | 5m | Maximum age of attestation quote before requiring refresh |
| `pcr-policy` | string | - | Named PCR policy to enforce (defined in attestation config) |
| `fallback` | string | deny | Behavior when attestation unavailable: `deny`, `allow-with-warning`, `cached-quote` |
| `token-validity` | duration | 5m | How long issued tokens remain valid |

**Fallback Modes:**

| Mode | Description | Use Case |
|------|-------------|----------|
| `deny` | Reject all updates without valid attestation | Production environments |
| `allow-with-warning` | Allow update but log security warning | Migration periods |
| `cached-quote` | Accept previously cached attestation | Brief TPM unavailability |

### PCR Policy Configuration

Define named PCR policies for different security requirements:

```yaml
attestation:
  pcr-policies:
    standard-boot:
      description: "Standard secure boot configuration"
      pcrs:
        0:
          description: "UEFI firmware"
          expected: "sha256:abc123..."
        7:
          description: "Secure Boot state"
          expected: "sha256:def456..."
        8:
          description: "Kernel command line"
          expected: any  # Allow any value
        9:
          description: "initrd hash"
          expected: any

    high-security:
      description: "Locked-down boot configuration"
      pcrs:
        0:
          expected: "sha256:abc123..."
        1:
          expected: "sha256:111222..."
        2:
          expected: "sha256:333444..."
        7:
          expected: "sha256:def456..."
        8:
          expected: "sha256:kernel-params..."
        9:
          expected: "sha256:initrd-hash..."
```

| PCR | Measurement | Typical Use |
|-----|-------------|-------------|
| 0 | BIOS/UEFI firmware | Detect firmware tampering |
| 7 | Secure Boot state | Verify boot policy active |
| 8 | Kernel command line | Detect boot parameter changes |
| 9 | initrd hash | Verify initial ramdisk integrity |

### CLI Usage

Use the `--attest` flag to perform attestation-gated updates:

```bash
# Update with attestation
platformctl dns update myhost.secure.example.com 192.168.1.100 --attest

# Specify attestation service
platformctl dns update myhost.secure.example.com 192.168.1.100 \
  --attest \
  --attestation-service https://attest.example.com:8443

# Delete with attestation
platformctl dns delete myhost.secure.example.com --attest

# Check attestation status
platformctl dns attest status

# Force attestation refresh
platformctl dns attest refresh
```

**CLI Options:**

| Option | Description |
|--------|-------------|
| `--attest` | Enable attestation for this operation |
| `--attestation-service <url>` | Override default attestation service URL |
| `--attest-timeout <duration>` | Timeout for attestation operations (default: 30s) |
| `--attest-refresh` | Force new attestation even if cached token is valid |

### Error Handling

| Error | RCODE | Description | Resolution |
|-------|-------|-------------|------------|
| Attestation required | REFUSED | Zone requires attestation but none provided | Add `--attest` flag to command |
| Attestation expired | REFUSED | Token has exceeded its validity period | Re-attest with `--attest-refresh` |
| PCR policy mismatch | REFUSED | Device PCR values do not match expected policy | Verify device boot configuration |
| EK not authorized | REFUSED | Device EK certificate not in allowed list | Add device EK CA to zone configuration |

**Error Response Example:**

```json
{
  "rcode": 5,
  "rcode_name": "REFUSED",
  "error": "attestation_required",
  "message": "Zone secure.example.com. requires TPM attestation for updates",
  "details": {
    "zone": "secure.example.com.",
    "attestation_service": "https://attest.example.com:8443",
    "help": "Retry with --attest flag"
  }
}
```

### Programmatic Usage

```go
import (
    "context"
    "github.com/jeremyhahn/go-trusted-platform/pkg/dns/ddns"
    "github.com/jeremyhahn/go-trusted-platform/pkg/attestation"
)

// Create attestation client
attestClient, err := attestation.NewClient(attestation.ClientConfig{
    ServiceURL: "https://attest.example.com:8443",
    TPMPath:    "/dev/tpmrm0",
    Timeout:    30 * time.Second,
})
if err != nil {
    return err
}

// Get attestation token
token, err := attestClient.Attest(ctx)
if err != nil {
    return fmt.Errorf("attestation failed: %w", err)
}

// Create DDNS client with attestation
client, err := ddns.NewClient(ddns.ClientConfig{
    Servers: []ddns.ServerConfig{
        {
            Name:    "ns1",
            Address: "ns1.secure.example.com:53",
            Zone:    "secure.example.com.",
            TSIG:    tsigConfig,
        },
    },
    Attestation: &ddns.AttestationConfig{
        Token: token,
    },
})
if err != nil {
    return err
}

// Perform attested update
err = client.UpdateA(ctx, ddns.OpAdd, &entities.ARecord{
    Name:  "myhost",
    Value: "192.168.1.100",
    TTL:   3600,
})
```

## See Also

- [DNS Architecture](architecture.md) - System architecture overview
- [Zones](zones.md) - Zone management
- [Records](records.md) - DNS record types
- [DNSSEC](dnssec.md) - DNSSEC signing and validation
- [DNSSEC Rollover](dnssec-rollover.md) - Key rollover procedures
- [Security](security.md) - Security model and best practices
