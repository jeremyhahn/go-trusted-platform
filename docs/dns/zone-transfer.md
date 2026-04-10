# DNS Zone Transfers (AXFR/IXFR)

> **Status: Planned Feature**
>
> This document describes the planned zone transfer functionality for the Trusted Platform DNS service. Implementation is scheduled for a future release.

## Overview

Zone transfers allow secondary DNS servers to obtain zone data from primary servers, providing redundancy and load distribution for DNS resolution. The Trusted Platform will implement both full (AXFR) and incremental (IXFR) zone transfers with strong security controls including TSIG authentication and IP-based access control lists.

### Why Zone Transfers Matter

Zone transfers are essential for DNS infrastructure resilience:

| Benefit | Description |
|---------|-------------|
| **Redundancy** | Secondary servers continue serving queries if primary fails |
| **Load Distribution** | Query load distributed across multiple servers |
| **Geographic Distribution** | Place secondaries closer to users for lower latency |
| **Disaster Recovery** | Zone data replicated for recovery scenarios |

### Transfer Types

| Type | RFC | Description | Use Case |
|------|-----|-------------|----------|
| **AXFR** | RFC 5936 | Full zone transfer - complete zone data | Initial synchronization, recovery, key rotations |
| **IXFR** | RFC 1995 | Incremental zone transfer - only changes | Regular updates, bandwidth optimization |

### Transfer Protocol Flow

```
┌─────────────────┐                              ┌─────────────────┐
│  Primary DNS    │                              │  Secondary DNS  │
│    Server       │                              │     Server      │
└────────┬────────┘                              └────────┬────────┘
         │                                                │
         │  1. SOA Query (check serial)                   │
         │◀───────────────────────────────────────────────│
         │                                                │
         │  2. SOA Response (serial: 2025010101)          │
         │───────────────────────────────────────────────▶│
         │                                                │
         │     [Secondary compares serials]               │
         │     [If different, request transfer]           │
         │                                                │
         │  3. AXFR/IXFR Request + TSIG                   │
         │◀───────────────────────────────────────────────│
         │                                                │
         │     [Primary validates TSIG]                   │
         │     [Primary checks ACL]                       │
         │                                                │
         │  4. Zone Data + TSIG                           │
         │───────────────────────────────────────────────▶│
         │                                                │
         │     [Secondary validates TSIG]                 │
         │     [Secondary loads zone data]                │
         │                                                │
```

## Primary Server Configuration

Configure the primary DNS server to allow zone transfers to authorized secondary servers.

### Full Configuration

```yaml
dns:
  zone-transfer:
    enabled: true
    axfr:
      enabled: true
      max-time: 300s
    ixfr:
      enabled: true
      history-size: 100
    tsig:
      required: true
      keys:
        - name: "xfer-key.example.com."
          algorithm: "hmac-sha256"
          secret: "${ZONE_TRANSFER_KEY}"
    allow-transfer:
      - address: "192.168.1.10"
        key: "xfer-key.example.com."
        zones: ["example.com.", "example.org."]
    notify:
      enabled: true
      targets:
        - "192.168.1.10:53"
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | false | Master switch for zone transfers |
| `axfr.enabled` | bool | true | Enable full zone transfers |
| `axfr.max-time` | duration | 300s | Maximum time for AXFR completion |
| `ixfr.enabled` | bool | true | Enable incremental transfers |
| `ixfr.history-size` | int | 100 | Number of zone versions to retain for IXFR |
| `tsig.required` | bool | true | Require TSIG authentication |
| `notify.enabled` | bool | true | Send NOTIFY on zone changes |

### TSIG Key Configuration

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `name` | string | Yes | TSIG key name (FQDN with trailing dot) |
| `algorithm` | string | Yes | HMAC algorithm (hmac-sha256 recommended) |
| `secret` | string | Yes | Base64-encoded shared secret |

### Access Control Configuration

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `address` | string | Yes | IP address or CIDR of allowed secondary |
| `key` | string | No | Required TSIG key name for this server |
| `zones` | list | No | Zones this server can transfer (empty = all) |

## Secondary Server Configuration

Configure secondary DNS servers to obtain zone data from primary servers.

### Full Configuration

```yaml
dns:
  secondary:
    enabled: true
    zones:
      - name: "example.com."
        primary:
          address: "192.168.1.1:53"
          tsig:
            name: "xfer-key.example.com."
            algorithm: "hmac-sha256"
            secret: "${ZONE_TRANSFER_KEY}"
        refresh:
          interval: 3600s
          retry: 600s
          expire: 86400s
        transfer:
          prefer-ixfr: true
          max-retries: 3
          retry-delay: 30s
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | false | Enable secondary server mode |
| `zones[].name` | string | Required | Zone name to transfer |
| `zones[].primary.address` | string | Required | Primary server address (host:port) |
| `zones[].refresh.interval` | duration | 3600s | SOA refresh interval |
| `zones[].refresh.retry` | duration | 600s | Retry interval on failure |
| `zones[].refresh.expire` | duration | 86400s | Zone expiration time |
| `zones[].transfer.prefer-ixfr` | bool | true | Prefer IXFR over AXFR when possible |
| `zones[].transfer.max-retries` | int | 3 | Maximum transfer retry attempts |
| `zones[].transfer.retry-delay` | duration | 30s | Delay between retry attempts |

### Refresh Behavior

The secondary server follows SOA-based refresh timing:

| Timer | Source | Description |
|-------|--------|-------------|
| **Refresh** | SOA REFRESH field | Check primary for updates |
| **Retry** | SOA RETRY field | Retry interval after failed refresh |
| **Expire** | SOA EXPIRE field | Stop serving zone if primary unreachable |

## Security

Zone transfers must be protected to prevent unauthorized access to zone data and potential reconnaissance by attackers.

### TSIG Authentication (Required)

TSIG (Transaction Signature) provides message authentication for zone transfers:

| Property | Description |
|----------|-------------|
| **Message Integrity** | Cryptographic signature prevents tampering |
| **Origin Authentication** | Verifies request comes from authorized server |
| **Replay Protection** | Time-based tokens prevent replay attacks |
| **Algorithm Support** | HMAC-SHA256, HMAC-SHA384, HMAC-SHA512 |

**TSIG Configuration Best Practices:**

```yaml
tsig:
  required: true  # Never disable in production
  keys:
    - name: "xfer-key.example.com."
      algorithm: "hmac-sha256"  # Minimum recommended
      secret: "${ZONE_TRANSFER_KEY}"  # Environment variable, never hardcode
```

### IP-Based ACLs

Restrict zone transfers to known secondary server addresses:

```yaml
allow-transfer:
  # Single IP address
  - address: "192.168.1.10"
    key: "xfer-key.example.com."

  # CIDR notation for multiple servers
  - address: "10.0.0.0/24"
    key: "datacenter-key.example.com."
    zones: ["internal.example.com."]
```

### Zone-Scoped Keys

Use different TSIG keys for different zones to limit blast radius:

```yaml
tsig:
  keys:
    # Key for public zones
    - name: "public-xfer.example.com."
      algorithm: "hmac-sha256"
      secret: "${PUBLIC_ZONE_KEY}"

    # Key for internal zones (different secret)
    - name: "internal-xfer.example.com."
      algorithm: "hmac-sha512"  # Higher security for internal
      secret: "${INTERNAL_ZONE_KEY}"

allow-transfer:
  - address: "192.168.1.10"
    key: "public-xfer.example.com."
    zones: ["example.com.", "example.org."]

  - address: "10.0.0.10"
    key: "internal-xfer.example.com."
    zones: ["internal.example.com."]
```

### Rate Limiting

Prevent abuse through transfer rate limits:

```yaml
zone-transfer:
  rate-limit:
    transfers-per-minute: 10
    max-concurrent: 5
    cooldown: 60s
```

| Limit | Default | Description |
|-------|---------|-------------|
| `transfers-per-minute` | 10 | Maximum transfers per minute per source |
| `max-concurrent` | 5 | Maximum concurrent transfer sessions |
| `cooldown` | 60s | Minimum time between transfers for same zone |

### Security Checklist

| Requirement | Implementation |
|-------------|----------------|
| TSIG authentication | `tsig.required: true` |
| IP-based restrictions | Configure `allow-transfer` ACLs |
| Zone scoping | Use zone-specific TSIG keys |
| Rate limiting | Enable transfer rate limits |
| Audit logging | All transfers logged with source IP |
| Key rotation | Rotate TSIG keys quarterly |

## NOTIFY Protocol

The NOTIFY protocol (RFC 1996) enables immediate zone synchronization when changes occur on the primary server.

### NOTIFY Flow Diagram

```
                          Zone Update Event
                                 │
                                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│                         Primary DNS Server                           │
├──────────────────────────────────────────────────────────────────────┤
│  1. Zone update received (DDNS, manual edit, key rollover)           │
│  2. SOA serial incremented                                           │
│  3. Zone re-signed (if DNSSEC enabled)                               │
│  4. NOTIFY message generated                                         │
└────────────────────────────────┬─────────────────────────────────────┘
                                 │
                                 │ NOTIFY (example.com. SOA)
                                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│                        Secondary DNS Server                          │
├──────────────────────────────────────────────────────────────────────┤
│  5. NOTIFY received                                                  │
│  6. SOA query sent to primary                                        │
└────────────────────────────────┬─────────────────────────────────────┘
                                 │
                                 │ SOA Query
                                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│                         Primary DNS Server                           │
├──────────────────────────────────────────────────────────────────────┤
│  7. SOA response (new serial)                                        │
└────────────────────────────────┬─────────────────────────────────────┘
                                 │
                                 │ SOA Response (serial: 2025010102)
                                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│                        Secondary DNS Server                          │
├──────────────────────────────────────────────────────────────────────┤
│  8. Compare serials (local: 2025010101, remote: 2025010102)          │
│  9. Serial different - initiate transfer                             │
│ 10. IXFR request (or AXFR if IXFR unavailable)                       │
└────────────────────────────────┬─────────────────────────────────────┘
                                 │
                                 │ IXFR Request + TSIG
                                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│                         Primary DNS Server                           │
├──────────────────────────────────────────────────────────────────────┤
│ 11. Validate TSIG signature                                          │
│ 12. Check ACL permissions                                            │
│ 13. Generate incremental changes (or full zone if AXFR)              │
│ 14. Send zone data with TSIG                                         │
└────────────────────────────────┬─────────────────────────────────────┘
                                 │
                                 │ Zone Data + TSIG
                                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│                        Secondary DNS Server                          │
├──────────────────────────────────────────────────────────────────────┤
│ 15. Validate TSIG signature                                          │
│ 16. Apply zone changes                                               │
│ 17. Update local SOA serial                                          │
│ 18. Zone synchronized                                                │
└──────────────────────────────────────────────────────────────────────┘
```

### NOTIFY Configuration

```yaml
notify:
  enabled: true
  targets:
    - "192.168.1.10:53"
    - "192.168.1.11:53"
  retry-count: 3
  retry-interval: 30s
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | true | Enable NOTIFY on zone changes |
| `targets` | list | - | Secondary server addresses |
| `retry-count` | int | 3 | NOTIFY retry attempts |
| `retry-interval` | duration | 30s | Interval between retries |

## CLI Commands

### Zone Transfer Management

| Command | Description |
|---------|-------------|
| `platformctl dns transfer request` | Manually request zone transfer |
| `platformctl dns transfer status` | View transfer status and history |
| `platformctl dns transfer list-allowed` | List authorized transfer clients |
| `platformctl dns transfer allow` | Add transfer authorization |
| `platformctl dns transfer notify` | Send NOTIFY to secondaries |

### Request Zone Transfer

```bash
# Request AXFR from primary
platformctl dns transfer request \
  --zone example.com. \
  --server 192.168.1.1:53 \
  --type axfr

# Request IXFR (incremental)
platformctl dns transfer request \
  --zone example.com. \
  --server 192.168.1.1:53 \
  --type ixfr \
  --serial 2025010101
```

### Check Transfer Status

```bash
# View transfer status for a zone
platformctl dns transfer status --zone example.com.

# Output:
# Zone: example.com.
# Type: Secondary
# Primary: 192.168.1.1:53
# Serial: 2025010102
# Last Transfer: 2025-01-15T10:30:00Z
# Transfer Type: IXFR
# Status: Synchronized
# Next Refresh: 2025-01-15T11:30:00Z
```

### List Allowed Transfers

```bash
# List all authorized transfer clients
platformctl dns transfer list-allowed

# Output:
# ADDRESS         KEY                      ZONES
# 192.168.1.10    xfer-key.example.com.    example.com., example.org.
# 10.0.0.10       internal-key.example.com. internal.example.com.
```

### Add Transfer Authorization

```bash
# Allow a new secondary server
platformctl dns transfer allow \
  --address 192.168.1.20 \
  --key xfer-key.example.com. \
  --zones example.com.,example.org.
```

### Send NOTIFY

```bash
# Manually trigger NOTIFY to all secondaries
platformctl dns transfer notify --zone example.com.

# Send to specific server
platformctl dns transfer notify \
  --zone example.com. \
  --target 192.168.1.10:53
```

### CLI Options Reference

| Option | Description |
|--------|-------------|
| `--zone` | Zone name (FQDN with trailing dot) |
| `--server` | Primary server address (host:port) |
| `--type` | Transfer type: axfr or ixfr |
| `--serial` | SOA serial for IXFR base |
| `--address` | Secondary server IP address |
| `--key` | TSIG key name |
| `--zones` | Comma-separated list of zones |
| `--target` | NOTIFY target address |
| `--verbose` | Enable verbose output |
| `--dry-run` | Show actions without executing |

## Error Handling

### Transfer Error Codes

| Error | Description | Resolution |
|-------|-------------|------------|
| `ErrTransferRefused` | Transfer denied by primary | Verify TSIG and ACL configuration |
| `ErrTSIGVerifyFailed` | TSIG signature invalid | Check key name, algorithm, and secret |
| `ErrTransferTimeout` | Transfer did not complete | Increase timeout, check network |
| `ErrIXFRUnavailable` | IXFR history not available | Fall back to AXFR |
| `ErrSerialMismatch` | Unexpected serial in response | Retry or force AXFR |
| `ErrZoneNotAuthoritative` | Server not authoritative | Verify zone configuration |

### Troubleshooting

```bash
# Enable debug logging for transfers
platformctl dns transfer request \
  --zone example.com. \
  --server 192.168.1.1:53 \
  --verbose

# Verify TSIG key configuration
platformctl dns tsig verify --key xfer-key.example.com.

# Test connectivity to primary
platformctl dns ping 192.168.1.1:53

# Check zone SOA serial
dig @192.168.1.1 example.com. SOA +short
```

## Related Documentation

| Document | Description |
|----------|-------------|
| [Security](security.md) | Security model and TPM integration |
| [Dynamic DNS](dynamic-dns.md) | RFC 2136 dynamic updates |
| [Zones](zones.md) | Zone management and configuration |
| [DNSSEC](dnssec.md) | DNSSEC signing and validation |
| [DNSSEC Rollover](dnssec-rollover.md) | Key rollover procedures |
| [Architecture](architecture.md) | DNS system architecture |

## See Also

- [RFC 5936 - DNS Zone Transfer Protocol (AXFR)](https://datatracker.ietf.org/doc/html/rfc5936)
- [RFC 1995 - Incremental Zone Transfer in DNS (IXFR)](https://datatracker.ietf.org/doc/html/rfc1995)
- [RFC 1996 - DNS NOTIFY](https://datatracker.ietf.org/doc/html/rfc1996)
- [RFC 2845 - TSIG](https://datatracker.ietf.org/doc/html/rfc2845)
- [RFC 8945 - Secret Key Transaction Authentication for DNS (TSIG)](https://datatracker.ietf.org/doc/html/rfc8945)
