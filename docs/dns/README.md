# Trusted Platform DNS

> **Status: REFERENCE** · Last verified: 2026-10-15
> Overview of the authoritative DNS subsystem in `pkg/dns/` and its documents.

Enterprise-grade DNS subsystem integrated with the Trusted Platform.

## Overview

Trusted Platform DNS provides a fully integrated DNS service built on CoreDNS with dual-zone architecture for internal and public domains. It leverages the platform datastore for zone persistence and supports dynamic record management with hardware-backed security through TPM integration.

## Key Features

| Feature | Description |
|---------|-------------|
| **Dual-Zone Architecture** | Separate internal and public DNS servers with zone isolation |
| **CoreDNS-Based** | Built on CoreDNS with custom TrustedPlatform plugin |
| **Zone Persistence** | Zone data stored in platform datastore (local or distributed) |
| **Dynamic Registration** | Automatic zone and record creation for platform devices |
| **Macro Expansion** | Configuration macros for dynamic IP and hostname resolution |
| **Query Validation** | RFC-compliant query validation with injection protection |
| **Security Logging** | Security events logged for internal zone query violations |
| **Forwarding Support** | Configurable upstream DNS forwarders per zone |

## Architecture Decision

**Integrated DNS module within Trusted Platform** - NOT a separate project.

| Aspect | Decision |
|--------|----------|
| Architecture | DNS built into platformd as optional module |
| Binary | Built into `platformd`; there is no separate DNS binary |
| Activation | Configure `dns` section in platform config |
| Implementation | CoreDNS with custom TrustedPlatform plugin |

**Rationale:**
- Single binary simplifies deployment and maintenance
- Zone data benefits from platform datastore guarantees
- Shared security infrastructure with platform components
- Unified configuration model

## Quick Start

### Enable DNS

```yaml
# config.yaml
dns:
  allow-registration: true
  allow-external-registration: false
  allow-internal-registration: true
  default-ttl: 3600
  private-ipv4: "192.0.2.100"
  public-ipv4: "203.0.113.50"

  # QuicBaaS storage configuration
  quicbaas:
    storage-backend: pebble
    data-dir: trusted-data/quicbaas
    wal-dir: trusted-data/quicbaas/wal
    node-id: 1
    cache-size: 67108864
    log-level: warn
    consistency-level: linearizable

  internal:
    port: 9053
    forwarders:
      - "192.0.2.1"
    zone:
      name: "example.internal."
      ttl: 3600
      description: "Internal zone"
      internal: true
      records:
        soa:
          name: "example.internal."
          mname: "ns1.example.internal."
          rname: "hostmaster.example.internal."
          serial: 1
          refresh: 86400
          retry: 7200
          expire: 86400
          min_ttl: 3600
          ttl: 3600
        ns:
          - name: "example.internal."
            value: "ns1.example.internal."
            ttl: 3600
        a:
          - name: "ns1"
            value: "${PRIVATE_IPv4}"
            ttl: 3600
          - name: "${HOSTNAME}"
            value: "${PRIVATE_IPv4}"
            ttl: 3600

  public:
    port: 8053
    forwarders:
      - "8.8.8.8"
      - "8.8.4.4"
    zone:
      name: "example.com."
      ttl: 3600
      description: "Public zone"
      internal: false
      records:
        soa:
          name: "example.com."
          mname: "ns1.example.com."
          rname: "hostmaster.example.com."
          serial: 1
          refresh: 86400
          retry: 7200
          expire: 86400
          min_ttl: 3600
          ttl: 3600
        ns:
          - name: "example.com."
            value: "ns1.example.com."
            ttl: 3600
        a:
          - name: "ns1"
            value: "${PUBLIC_IPv4}"
            ttl: 3600
          - name: "www"
            value: "${PUBLIC_IPv4}"
            ttl: 3600
```

### Query the DNS Server

```bash
# Query internal zone
dig @localhost -p 9053 myhost.example.internal A

# Query public zone
dig @localhost -p 8053 www.example.com A

# Query SOA record
dig @localhost -p 9053 example.internal SOA
```

### Register a Device

There is no `platformctl dns` command group ([cli.md](cli.md)). Devices
register through the REST API:

```bash
curl -X POST https://localhost:8443/api/v1/dns/register \
  -H "Content-Type: application/json" \
  -d '{"fqdn": "newhost.example.internal", "ip": "192.0.2.50"}'
```

## Architecture Overview

The DNS subsystem is built around three core components:

```
┌───────────────────┐     ┌───────────────────┐     ┌───────────────────┐
│   CoreDNS with    │     │  TrustedPlatform  │     │     Platform      │
│  TrustedPlatform  │────▶│   DNS Service     │────▶│    Datastore      │
│      Plugin       │     │                   │     │                   │
└─────────┬─────────┘     └─────────┬─────────┘     └───────────────────┘
          │                         │
          ▼                         ▼
┌───────────────────┐     ┌───────────────────┐
│  Internal Server  │     │   Public Server   │
│    Port 9053      │     │    Port 8053      │
└───────────────────┘     └───────────────────┘
```

**CoreDNS Plugin Integration**: Custom `trustedPlatform` plugin handles query processing, zone lookup, and security enforcement.

**DNS Service Layer**: Manages zone operations, device registration, and record management through the ZoneDAO abstraction.

**Datastore Persistence**: Zones are persisted using the platform datastore with support for local and distributed backends.

For detailed architecture information, see [architecture.md](architecture.md).

## Supported Record Types

| Record Type | Description |
|-------------|-------------|
| **A** | IPv4 address mapping |
| **AAAA** | IPv6 address mapping |
| **CNAME** | Canonical name alias |
| **MX** | Mail exchange server |
| **NS** | Name server delegation |
| **SOA** | Start of Authority |
| **SRV** | Service location |
| **TXT** | Text records (SPF, DKIM, etc.) |
| **CAA** | Certificate Authority Authorization |
| **TLSA** | DANE certificate pinning |
| **DNSKEY** | DNSSEC public key |
| **DS** | Delegation signer |
| **RRSIG** | Resource record signature |

## Configuration Macros

The DNS subsystem supports dynamic macro expansion in zone configurations:

| Macro | Description |
|-------|-------------|
| `${PUBLIC_IPv4}` | Public IPv4 address from config |
| `${PUBLIC_IPv6}` | Public IPv6 address from config |
| `${PRIVATE_IPv4}` | Private IPv4 address from config |
| `${PRIVATE_IPv6}` | Private IPv6 address from config |
| `${HOSTNAME}` | Local system hostname |
| `${PUBLIC_DOMAIN}` | Public zone name |
| `${PRIVATE_DOMAIN}` | Private zone name |
| `${PUBLIC_FQDN}` | Hostname + public domain |
| `${PRIVATE_FQDN}` | Hostname + private domain |
| `${PREFERRED_IP}` | System preferred IPv4 address |

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | System architecture and component design |
| [Zones](zones.md) | Zone management and configuration |
| [Records](records.md) | DNS record types and management |
| [Resolution](resolution.md) | Query resolution and forwarding |
| [DNSSEC](dnssec.md) | DNSSEC signing and validation |
| [DNSSEC Rollover](dnssec-rollover.md) | Key rollover: not implemented; what the code does with zone keys |
| [DANE/TLSA](dane.md) | DANE certificate pinning and TLSA records |
| [Dynamic DNS](dynamic-dns.md) | RFC 2136 UPDATE: not implemented; how records change today |
| [DoT/DoH](dot-doh.md) | DNS over TLS/HTTPS (planned) |
| [Zone Transfer](zone-transfer.md) | Outbound AXFR to TSIG-authenticated secondaries |
| [ACME Integration](acme-integration.md) | DNS-01 challenge support |
| [Configuration](configuration.md) | Complete configuration reference |
| [CLI](cli.md) | Why there is no `platformctl dns` group, and what to use instead |
| [Security](security.md) | Security model and best practices |
| [Operations](operations.md) | Operations, monitoring, and capacity planning |
| [API Reference](api-reference.md) | REST and gRPC API documentation |
| [Troubleshooting](troubleshooting.md) | Common issues and solutions |

## Integration with Platform Components

| Component | Integration |
|-----------|-------------|
| **KMS** | DNSSEC keys in the go-quicbaas KMS software store ([security.md](security.md)) |
| **ACME** | dns-01 TXT records for BMC certificates; dns-01 verification in the ACME server ([acme-integration.md](acme-integration.md)) |
| **IAM/ABAC** | Access control for zone and record management |
| **Datastore** | Persistent storage for zones and records |

## Security Model

### Zone Isolation

- **Internal zones** are only accessible via the internal DNS server
- **Public queries** for internal zones are silently dropped
- Security violations are logged with full audit trail

### Query Validation

- RFC 1035 compliant query validation
- Protection against DNS injection attacks
- Maximum domain length enforcement (253 characters)
- Label length validation (63 characters max)
- Invalid character rejection

### Access Control

- Zone registration can be enabled/disabled globally
- Separate controls for internal and external zone registration
- IP address validation ensures internal zones use private IPs
- Public zones require public IP addresses

### Audit Logging

Security events include:
- Internal zone queries from public server
- Registration attempts
- Zone modifications
- Configuration changes

## Planned Features

| Feature | Status | Description |
|---------|--------|-------------|
| DNSSEC Signing | Implemented | One KSK and one ZSK per zone, in the go-quicbaas KMS ([dnssec.md](dnssec.md)) |
| Dynamic DNS (RFC 2136) | Not implemented | No UPDATE server or client ([dynamic-dns.md](dynamic-dns.md)) |
| DNS-01 ACME Challenges | Implemented | TXT records for BMC certificates; verification in the ACME server ([acme-integration.md](acme-integration.md)) |
| Key Rollover Automation | Not implemented | No scheduler, API route or CLI verb ([dnssec-rollover.md](dnssec-rollover.md)) |
| Multi-Backend KMS | Implemented | Software, TPM2, PKCS#11, Cloud KMS |
| DANE/TLSA | Implemented | Certificate pinning with auto-generation |
| CAA Records | Implemented | Certificate Authority Authorization |
| Zone Transfer (AXFR) | Implemented | Outbound AXFR to TSIG-authenticated secondaries; IXFR is answered as a full AXFR ([zone-transfer.md](zone-transfer.md)) |
| Response Rate Limiting | Planned | DDoS mitigation |
| DNS-over-TLS | Planned | Encrypted DNS transport ([spec](dot-doh.md)) |
| DNS-over-HTTPS | Planned | DoH endpoint support ([spec](dot-doh.md)) |

## See Also

- [KMS Documentation](../kms/architecture.md)
- [TPM Documentation](../tpm/README.md)
- [IAM Documentation](../iam/architecture.md)
- [ACME Documentation](../ca/acme.md)
- [Platform Architecture](../daemon/architecture.md)
