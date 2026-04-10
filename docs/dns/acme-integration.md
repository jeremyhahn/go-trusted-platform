# ACME DNS Integration

## Overview

The Trusted Platform DNS module provides integrated dns-01 ACME challenge support for automated certificate issuance. This integration enables seamless certificate management with automatic DNSSEC signing of challenge records when DNSSEC is enabled for a zone.

| Feature | Description |
|---------|-------------|
| **dns-01 Challenge** | RFC 8555 compliant DNS challenge for domain validation |
| **DNSSEC Integration** | Automatic signing of challenge TXT records |
| **Wildcard Support** | Required method for wildcard certificate issuance |
| **Multi-Domain** | Single certificate for multiple domains |
| **Automatic Cleanup** | Challenge records removed after validation |

## How dns-01 Works

The dns-01 challenge proves domain ownership by requiring the client to provision a specific TXT record in DNS.

### Challenge Flow

```
1. Client requests certificate from ACME server
2. ACME server provides challenge token
3. Platform creates TXT record at _acme-challenge.<domain>
4. ACME server queries TXT record via DNS
5. ACME server validates token matches expected value
6. Platform removes TXT record after validation
7. Certificate issued upon successful validation
```

### TXT Record Format

The challenge creates a TXT record with the following structure:

| Field | Value |
|-------|-------|
| Name | `_acme-challenge.<domain>` |
| Type | TXT |
| TTL | 60 (short-lived) |
| Value | Base64URL-encoded SHA-256 of key authorization |

### Example

For domain `example.com`:

```
_acme-challenge.example.com. 60 IN TXT "gfj9Xq...base64-token"
```

## DNSSEC Integration

When DNSSEC is enabled for a zone, challenge TXT records are automatically signed to provide cryptographic proof of authenticity.

### Automatic Signing

The signing process occurs transparently during challenge provisioning:

1. TXT record created for `_acme-challenge.<domain>`
2. RRSIG generated using Zone Signing Key (ZSK)
3. Both TXT and RRSIG records stored in zone
4. ACME server validates with full DNSSEC chain
5. Records removed after challenge completion

### Flow Diagram

```
ACME Challenge Request
        │
        ▼
┌───────────────────────────┐
│ ACMEDNSAdapter            │
│ .AddTXTRecord()           │
└───────────────────────────┘
        │
        ▼
┌───────────────────────────┐
│ DNSSECSigner              │
│ .SignRRSet(TXT)           │
└───────────────────────────┘
        │
        ▼
┌───────────────────────────┐
│ Zone                      │
│ .AddRRSIGRecord()         │
└───────────────────────────┘
        │
        ▼
┌───────────────────────────┐
│ Service                   │
│ .Save(zone)               │
└───────────────────────────┘
        │
        ▼
┌───────────────────────────┐
│ ACME Server               │
│ DNS Lookup + Validation   │
└───────────────────────────┘
        │
        ▼
┌───────────────────────────┐
│ ACMEDNSAdapter            │
│ .RemoveTXTRecord()        │
└───────────────────────────┘
        │
        ▼
┌───────────────────────────┐
│ Remove associated RRSIG   │
└───────────────────────────┘
```

### DNSSEC Validation Benefits

| Benefit | Description |
|---------|-------------|
| **Authenticity** | Proves TXT record originates from zone owner |
| **Integrity** | Detects tampering during DNS transit |
| **Non-repudiation** | Cryptographic proof of record creation |
| **High-Assurance** | Required by some CAs for EV certificates |

## Configuration

### Enable dns-01 Challenge

Configure the webservice to use dns-01 challenges with the integrated DNS server:

```yaml
webservice:
  acme:
    enabled: true
    challenges:
      - dns-01
    dns:
      zone: example.com.
      auto-sign: true  # Enable DNSSEC signing of challenge records
      ttl: 60          # Short TTL for challenge records
```

### DNS Server Configuration

Ensure the DNS server is properly configured with the target zone:

```yaml
dns:
  public:
    port: 8053
    forwarders:
      - 8.8.8.8
      - 4.4.4.4
    zone:
      name: example.com.
      ttl: 3600
      description: "Public zone with ACME support"
      internal: false
      dnssec-enabled: true
      records:
        soa:
          name: "example.com."
          mname: "ns1.example.com."
          rname: "hostmaster.example.com."
          serial: 1
          refresh: 86400
          retry: 7200
          expire: 86400
          min-ttl: 3600
        ns:
          - name: "example.com."
            value: "ns1.example.com."
            ttl: 3600
```

### Full Configuration Example

```yaml
dns:
  allow-registration: true
  default-ttl: 3600
  public-ipv4: "203.0.113.50"

  # Service-specific QuicBaaS settings
  shard-id: 2
  partition: dns

  public:
    port: 8053
    forwarders:
      - 8.8.8.8
    zone:
      name: example.com.
      dnssec-enabled: true

webservice:
  acme:
    enabled: true
    directory: "https://acme-v02.api.letsencrypt.org/directory"
    email: "admin@example.com"
    challenges:
      - dns-01
    dns:
      zone: example.com.
      auto-sign: true
```

## Supported ACME Providers

The dns-01 challenge is supported by all RFC 8555 compliant Certificate Authorities:

| Provider | Directory URL | Notes |
|----------|---------------|-------|
| **Let's Encrypt (Production)** | `https://acme-v02.api.letsencrypt.org/directory` | Rate limits apply |
| **Let's Encrypt (Staging)** | `https://acme-staging-v02.api.letsencrypt.org/directory` | Testing environment |
| **ZeroSSL** | `https://acme.zerossl.com/v2/DV90` | External account required |
| **Buypass** | `https://api.buypass.com/acme/directory` | European CA |
| **SSL.com** | `https://acme.ssl.com/sslcom-dv-rsa` | Commercial CA |

## Wildcard Certificates

The dns-01 challenge is the only ACME challenge type that supports wildcard certificate issuance.

### Issue Wildcard Certificate

```bash
# Certificate for *.example.com
platformctl cert issue \
  --domain "*.example.com" \
  --challenge dns-01
```

### Wildcard with Base Domain

```bash
# Certificate for both example.com and *.example.com
platformctl cert issue \
  --domain example.com \
  --domain "*.example.com" \
  --challenge dns-01
```

### Challenge Record Location

For wildcard domains, the challenge record is placed at the base domain:

| Certificate | Challenge Record Location |
|-------------|--------------------------|
| `*.example.com` | `_acme-challenge.example.com` |
| `*.sub.example.com` | `_acme-challenge.sub.example.com` |

## Multi-Domain Certificates

Issue a single certificate covering multiple domains (SAN certificate):

```bash
platformctl cert issue \
  --domain example.com \
  --domain www.example.com \
  --domain api.example.com \
  --domain mail.example.com \
  --challenge dns-01
```

### Multi-Domain Challenge Flow

Each domain requires its own challenge validation:

```
1. Request certificate for [example.com, www.example.com, api.example.com]
2. ACME server issues challenges for each domain
3. Platform creates TXT records:
   - _acme-challenge.example.com
   - _acme-challenge.www.example.com
   - _acme-challenge.api.example.com
4. ACME server validates all challenges
5. Platform removes all TXT records
6. Single certificate issued with all SANs
```

## Internal Zones

For internal zones that are not publicly resolvable, alternative approaches are required:

### Option 1: Internal ACME Server

Use an ACME server that can validate internal DNS:

```yaml
webservice:
  acme:
    enabled: true
    directory: "https://internal-acme.company.local/directory"
    challenges:
      - dns-01
    dns:
      zone: internal.company.local.
```

### Option 2: Alternative Challenge Types

Use HTTP-01 or TLS-ALPN-01 challenges instead:

```yaml
webservice:
  acme:
    enabled: true
    challenges:
      - http-01      # Requires port 80 access
      - tls-alpn-01  # Requires port 443 access
```

### Option 3: Self-Signed Certificates

For fully internal environments, use platform-issued certificates:

```bash
platformctl ca issue \
  --domain internal.example.local \
  --issuer platform-ca \
  --output internal.crt
```

## Unified Scheduler Integration

The platform scheduler automates certificate renewal using dns-01 challenges:

### Scheduler Configuration

```yaml
scheduler:
  enabled: true
  jobs:
    acme-renewal:
      enabled: true
      schedule: "0 0 * * *"    # Daily check
      threshold: 30d           # Renew 30 days before expiry
      challenge: dns-01
      retry:
        attempts: 3
        delay: 1h
```

### Renewal Process

```
1. Scheduler checks certificate expiration daily
2. Certificates expiring within threshold queued for renewal
3. dns-01 challenge initiated automatically
4. New certificate installed upon successful issuance
5. Old certificate archived
```

### Manual Renewal

```bash
# Check certificate status
platformctl cert status --domain example.com

# Force renewal
platformctl cert renew --domain example.com --force
```

## Error Handling

### Common Issues

| Error | Cause | Solution |
|-------|-------|----------|
| `DNS propagation timeout` | TXT record not visible to ACME server | Increase propagation wait time, verify zone is publicly resolvable |
| `DNSSEC validation failed` | Signature expired or invalid | Check RRSIG validity period, verify key configuration |
| `Challenge not found` | Wrong zone configured | Verify zone name matches domain, check zone is loaded |
| `Unauthorized` | Domain not controlled | Ensure DNS zone is authoritative for domain |
| `Rate limited` | Too many requests | Wait for rate limit reset, use staging environment for testing |
| `CAA record issue` | CAA prevents issuance | Add CAA record allowing your CA |

### Debugging Commands

```bash
# Check TXT record exists
dig TXT _acme-challenge.example.com @localhost -p 8053

# Verify DNSSEC signatures
dig TXT _acme-challenge.example.com @localhost -p 8053 +dnssec

# Check zone is loaded
platformctl dns zone show example.com.

# View challenge status
platformctl acme challenge status --domain example.com

# Check DNS propagation externally
dig TXT _acme-challenge.example.com @8.8.8.8
```

### Logging

Enable verbose logging for ACME operations:

```yaml
logging:
  level: debug
  modules:
    acme: debug
    dns: debug
```

Log entries include:
- Challenge creation and deletion
- DNS record operations
- DNSSEC signing operations
- ACME server communications

## Security Considerations

### Challenge Isolation

| Aspect | Protection |
|--------|------------|
| **Ephemeral Records** | TXT records exist only during validation window |
| **Automatic Cleanup** | Records removed on success or failure |
| **No Persistence** | Challenge data not stored after completion |
| **Timeout Enforcement** | Stale challenges automatically cleaned |

### DNSSEC Security Benefits

| Benefit | Description |
|---------|-------------|
| **Authenticity Proof** | Cryptographic proof TXT record is genuine |
| **Spoofing Prevention** | Prevents DNS cache poisoning attacks |
| **Man-in-the-Middle Protection** | Validates record integrity end-to-end |
| **High-Assurance Compliance** | Required by some CAs for EV/OV certificates |

### Access Control

Restrict who can trigger ACME operations (PROPOSED - Not yet implemented):

> **Note:** IAM policy integration is a planned feature. The configuration shown below is a proposed format.

Currently, access control is managed through mTLS client certificates configured in the webservices section:

```yaml
# Current implementation: mTLS-based access control
webservices:
  - name: acme-server
    mtls:
      enabled: true
      client-ca: /etc/platform/certs/client-ca.crt
```

### CAA Records

Configure CAA records to restrict certificate issuance:

```bash
# Allow only Let's Encrypt to issue certificates
platformctl dns record add \
  --zone example.com. \
  --type CAA \
  --name example.com. \
  --flags 0 \
  --tag issue \
  --value "letsencrypt.org"

# Allow wildcard issuance
platformctl dns record add \
  --zone example.com. \
  --type CAA \
  --name example.com. \
  --flags 0 \
  --tag issuewild \
  --value "letsencrypt.org"

# Configure incident reporting
platformctl dns record add \
  --zone example.com. \
  --type CAA \
  --name example.com. \
  --flags 0 \
  --tag iodef \
  --value "mailto:security@example.com"
```

## API Reference

### REST Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/acme/challenge/dns` | Initiate dns-01 challenge |
| GET | `/api/v1/acme/challenge/{id}` | Get challenge status |
| DELETE | `/api/v1/acme/challenge/{id}` | Cancel challenge |

### Example: Initiate Challenge

```bash
curl -X POST https://platform.example.com/api/v1/acme/challenge/dns \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "provider": "letsencrypt"
  }'
```

### Example: Check Status

```bash
curl -X GET https://platform.example.com/api/v1/acme/challenge/chall_abc123 \
  -H "Authorization: Bearer <token>"
```

## Related Documentation

- [DNSSEC](dnssec.md) - DNSSEC signing and validation
- [Configuration](configuration.md) - Complete DNS configuration reference
- [Zones](zones.md) - Zone management
- [Records](records.md) - DNS record types
- [Troubleshooting](troubleshooting.md) - Common issues and solutions
- [ACME Server](../ca/acme.md) - Platform ACME server documentation
- [CA Documentation](../ca/README.md) - Certificate Authority overview
