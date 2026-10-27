# DNS Record Types

> **Status: REFERENCE** · Last verified: 2026-10-15
> The record types a platform zone stores and serves.

## Overview

The Trusted Platform DNS service supports standard DNS record types and DNSSEC extensions. Records are organized within zones and stored in the platform's datastore. Each record type has specific fields and use cases for resolving domain names, mail routing, service discovery, and cryptographic validation.

## Record Types

### Standard Records

| Type | Purpose | Description |
|------|---------|-------------|
| **A** | IPv4 Address | Maps hostname to IPv4 address |
| **AAAA** | IPv6 Address | Maps hostname to IPv6 address |
| **CAA** | CA Authorization | Controls which CAs can issue certificates |
| **CNAME** | Canonical Name | Alias pointing to another hostname |
| **MX** | Mail Exchange | Mail server for domain with priority |
| **NS** | Name Server | Authoritative nameserver for zone |
| **SOA** | Start of Authority | Zone metadata and authority info |
| **SRV** | Service | Service location with port and priority |
| **TLSA** | TLS Authentication | Associates TLS certificate with domain (DANE) |
| **TXT** | Text | Arbitrary text data (SPF, DKIM, verification) |

### DNSSEC Records

| Type | Purpose | Description |
|------|---------|-------------|
| **DNSKEY** | DNS Key | Public key for zone signing |
| **DS** | Delegation Signer | Hash of child zone DNSKEY |
| **RRSIG** | Resource Record Signature | Cryptographic signature over RRset |
| **NSEC** | Next Secure | Authenticated denial of existence, generated at signing |
| **NSEC3** | Next Secure v3 | Hashed denial of existence, generated at signing when `nsec-mode: nsec3` |
| **NSEC3PARAM** | NSEC3 parameters | Published with NSEC3 chains |

## Record Structure

### RecordSet

The `RecordSet` contains all records for a zone:

```go
type RecordSet struct {
    ARecords          []*ARecord
    AAAARecords       []*AAAARecord
    CAARecords        []*CAARecord
    CNAMERecords      []*CNAMERecord
    DNSKEYRecords     []*DNSKEYRecord
    DSRecords         []*DSRecord
    MXRecords         []*MXRecord
    NSECRecords       []*NSECRecord
    NSEC3Records      []*NSEC3Record
    NSEC3PARAMRecords []*NSEC3PARAMRecord
    NSRecords         []*NSRecord
    RRSIGRecords      []*RRSIGRecord
    SOARecord         SOARecord
    SRVRecords        []*SRVRecord
    TLSARecords       []*TLSARecord
    TXTRecords        []*TXTRecord
}
```

`pkg/dns/entities/records.go` defines it. The YAML keys below are the `yaml`
tags. The config loader decodes through the `mapstructure` tags, which differ
for five fields: `min_ttl`, `key_tag`, `original_ttl`, `type_covered` and
`matching_type`. In the `dns:` section of the platform config only the
underscore spelling is read; the hyphenated spelling is ignored.

## Owner names

Every record's `name` field is its OWNER — the name the record answers for, and
the only name it answers for. Three forms are accepted and mean the same thing
once resolved against the zone:

| Form | Example in zone `example.com.` | Owner |
|---|---|---|
| Relative | `www` | `www.example.com.` |
| Apex marker | `@` (or omitted) | `example.com.` |
| Fully qualified | `www.example.com.` | `www.example.com.` |

Matching is case-insensitive and exact: a record named `www` answers
`www.example.com.` and NOT `www.anything.example.com.`. Wildcards are not
supported — a `*` owner is matched literally. A record intended for the zone
apex must use `@` or the zone's own name; an apex NS record stored under some
other fully qualified name is not an apex NS record and does not answer one.

The SOA is the exception: it is owned by the zone apex whatever its `name`
field says. See [resolution.md](resolution.md#name-matching).

### A Record

Maps a hostname to an IPv4 address.

```yaml
a:
  - name: "www"
    value: "192.0.2.100"
    ttl: 3600
  - name: "@"           # Zone apex
    value: "192.0.2.1"
    ttl: 3600
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Owner name: relative (`www`), `@` for the apex, or fully qualified |
| `value` | string | IPv4 address |
| `ttl` | uint32 | Time-to-live in seconds (optional) |

### AAAA Record

Maps a hostname to an IPv6 address.

```yaml
aaaa:
  - name: "www"
    value: "2001:db8::1"
    ttl: 3600
  - name: "mail"
    value: "2001:db8::25"
    ttl: 3600
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Hostname |
| `value` | string | IPv6 address |
| `ttl` | uint32 | Time-to-live in seconds (optional) |

### CNAME Record

Creates an alias that points to another hostname.

```yaml
cname:
  - name: "www"
    value: "example.com."
    ttl: 3600
  - name: "ftp"
    value: "files.example.com."
    ttl: 3600
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Alias hostname |
| `value` | string | Target FQDN (must end with dot) |
| `ttl` | uint32 | Time-to-live in seconds (optional) |

### MX Record

Specifies mail exchange servers for the domain.

```yaml
mx:
  - name: "example.com."
    value: "mail1.example.com."
    priority: 10
    ttl: 3600
  - name: "example.com."
    value: "mail2.example.com."
    priority: 20
    ttl: 3600
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Domain receiving mail |
| `value` | string | Mail server FQDN |
| `priority` | uint16 | Lower priority = preferred |
| `ttl` | uint32 | Time-to-live in seconds (optional) |

### NS Record

Delegates authority to nameservers.

```yaml
ns:
  - name: "example.com."
    value: "ns1.example.com."
    ttl: 3600
  - name: "example.com."
    value: "ns2.example.com."
    ttl: 3600
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Zone name |
| `value` | string | Nameserver FQDN |
| `ttl` | uint32 | Time-to-live in seconds (optional) |

### SOA Record

Start of Authority - required for every zone.

```yaml
soa:
  name: "example.com."
  mname: "ns1.example.com."
  rname: "hostmaster.example.com."
  serial: 2024010101
  refresh: 86400
  retry: 7200
  expire: 604800
  min_ttl: 3600
  ttl: 3600
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Zone name |
| `mname` | string | Primary nameserver FQDN |
| `rname` | string | Admin email (`@` replaced with `.`) |
| `serial` | uint32 | Zone serial (increment on changes) |
| `refresh` | uint32 | Seconds before refresh check |
| `retry` | uint32 | Seconds before retry on failure |
| `expire` | uint32 | Seconds before zone expiration |
| `min_ttl` | uint32 | Minimum TTL for negative caching |
| `ttl` | uint32 | SOA record TTL (optional) |

### SRV Record

Service location for protocols like SIP, XMPP, LDAP.

```yaml
srv:
  - name: "_sip._tcp.example.com."
    target: "sipserver.example.com."
    port: 5060
    priority: 10
    weight: 20
    ttl: 3600
  - name: "_ldap._tcp.example.com."
    target: "ldap.example.com."
    port: 389
    priority: 0
    weight: 100
    ttl: 3600
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Service name (`_service._proto.domain.`) |
| `target` | string | Server FQDN |
| `port` | uint16 | Service port number |
| `priority` | uint16 | Lower = preferred |
| `weight` | uint16 | Load balancing within same priority |
| `ttl` | uint32 | Time-to-live in seconds (optional) |

### TXT Record

Stores arbitrary text data for SPF, DKIM, domain verification.

```yaml
txt:
  - name: "example.com."
    value: "v=spf1 include:_spf.google.com ~all"
    ttl: 3600
  - name: "_dmarc.example.com."
    value: "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
    ttl: 3600
  - name: "google._domainkey.example.com."
    value: "v=DKIM1; k=rsa; p=MIIBIjAN..."
    ttl: 3600
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Record name |
| `value` | string | Text content |
| `ttl` | uint32 | Time-to-live in seconds (optional) |

### DNSKEY Record

Public key used for DNSSEC zone signing.

```yaml
key:
  - name: "example.com."
    flags: 257        # 256=ZSK, 257=KSK
    protocol: 3       # Always 3
    algorithm: 13     # ECDSAP256SHA256
    key: "base64-encoded-public-key..."
    ttl: 3600
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Zone name |
| `flags` | uint16 | Key flags (256=ZSK, 257=KSK) |
| `protocol` | uint8 | Protocol (always 3) |
| `algorithm` | uint8 | DNSSEC algorithm number |
| `key` | string | Base64-encoded public key |
| `id` | uint64 | Key identifier |
| `ttl` | uint32 | Time-to-live in seconds (optional) |

**Algorithm Values:**

| Value | Algorithm |
|-------|-----------|
| 8 | RSA/SHA-256 |
| 10 | RSA/SHA-512 |
| 13 | ECDSA P-256/SHA-256 |
| 14 | ECDSA P-384/SHA-384 |
| 15 | Ed25519 |
| 16 | Ed448 |

### DS Record

Delegation Signer - links parent zone to child zone DNSKEY.

```yaml
ds:
  - name: "child.example.com."
    key_tag: 12345
    algorithm: 13
    digest_type: 2
    digest: "hexadecimal-digest-value..."
    ttl: 3600
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Delegated zone name |
| `key_tag` | uint16 | Key tag of referenced DNSKEY |
| `algorithm` | uint8 | DNSKEY algorithm |
| `digest_type` | uint8 | Digest algorithm (2=SHA-256, 4=SHA-384) |
| `digest` | string | Hex-encoded digest of DNSKEY |
| `id` | uint64 | Record identifier |
| `ttl` | uint32 | Time-to-live in seconds (optional) |

### RRSIG Record

Resource Record Signature - cryptographic signature over an RRset.

```yaml
rrsig:
  - name: "www.example.com."
    type_covered: "A"
    algorithm: 13
    labels: 3
    original_ttl: 3600
    expiration: "20250201000000"
    inception: "20250101000000"
    key_tag: 12345
    signer: "example.com."
    signature: "base64-encoded-signature..."
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Owner of the signed RRset; empty means the zone apex (optional) |
| `type_covered` | string | Record type being signed |
| `algorithm` | uint8 | Signing algorithm |
| `labels` | uint8 | Number of labels in owner name |
| `original_ttl` | uint32 | Original TTL of covered RRset |
| `expiration` | string | Signature expiration (YYYYMMDDHHmmSS) |
| `inception` | string | Signature inception (YYYYMMDDHHmmSS) |
| `key_tag` | uint16 | Tag of signing key |
| `signer` | string | Signing zone name |
| `signature` | string | Base64-encoded signature |

### CAA Record

Certification Authority Authorization - controls which CAs can issue certificates for a domain.

```yaml
caa:
  - name: "example.com."
    flags: 0
    tag: "issue"
    value: "letsencrypt.org"
    ttl: 3600
  - name: "example.com."
    flags: 0
    tag: "issuewild"
    value: "letsencrypt.org"
    ttl: 3600
  - name: "example.com."
    flags: 0
    tag: "iodef"
    value: "mailto:security@example.com"
    ttl: 3600
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Domain name |
| `ttl` | uint32 | Time-to-live in seconds (optional) |
| `flags` | uint8 | CAA flags (0=not critical, 128=critical) |
| `tag` | string | Property tag (issue, issuewild, iodef) |
| `value` | string | CA domain or reporting URI |

**Tag Values:**

| Tag | Description |
|-----|-------------|
| `issue` | Authorize CA to issue standard certificates |
| `issuewild` | Authorize CA to issue wildcard certificates |
| `iodef` | Report policy violations (mailto: or https: URI) |

**Flags:**

| Value | Meaning |
|-------|---------|
| 0 | Non-critical - CA may ignore if tag is unknown |
| 128 | Critical - CA must refuse if tag is unknown |

### TLSA Record

Transport Layer Security Authentication - associates TLS certificate with domain for DANE.

Record name format: `_<port>._<protocol>.<hostname>`

```yaml
tlsa:
  - name: "_443._tcp.www.example.com."
    usage: 3
    selector: 1
    matching_type: 1
    data: "sha256-hash-of-certificate..."
    ttl: 3600
  - name: "_25._tcp.mail.example.com."
    usage: 2
    selector: 0
    matching_type: 2
    data: "sha512-hash-of-certificate..."
    ttl: 3600
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Record name (`_port._protocol.hostname`) |
| `ttl` | uint32 | Time-to-live in seconds (optional) |
| `usage` | uint8 | Certificate usage (0-3) |
| `selector` | uint8 | Certificate selector (0-1) |
| `matching_type` | uint8 | Matching type (0-2) |
| `data` | string | Certificate association data |

**Usage Values:**

| Value | Name | Description |
|-------|------|-------------|
| 0 | PKIX-TA | CA constraint with PKIX validation |
| 1 | PKIX-EE | Service certificate constraint with PKIX validation |
| 2 | DANE-TA | Trust anchor assertion (no PKIX validation) |
| 3 | DANE-EE | Domain-issued certificate (no PKIX validation) |

**Selector Values:**

| Value | Description |
|-------|-------------|
| 0 | Full certificate (DER encoding) |
| 1 | SubjectPublicKeyInfo (SPKI) |

**Matching Type Values:**

| Value | Description |
|-------|-------------|
| 0 | Full data (no hash) |
| 1 | SHA-256 hash |
| 2 | SHA-512 hash |

## Record Operations

### Adding Records

**Programmatically:**

```go
// Add A record to zone
zone.AddARecord(&entities.ARecord{
    Name:  "newhost",
    Value: "192.0.2.50",
    TTL:   3600,
})

// Save zone
err := dnsService.Save(ctx, zone)
```

**Using helper functions:**

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/dns"

// Create records using helper functions
aRecord := dns.NewARecord("www", "192.0.2.100", 3600)
aaaaRecord := dns.NewAAAARecord("www", "2001:db8::1", 3600)
cnameRecord := dns.NewCNAMERecord("alias", "target.example.com.", 3600)
mxRecord := dns.NewMXRecord("example.com.", "mail.example.com.", 10, 3600)
nsRecord := dns.NewNSRecord("example.com.", "ns1.example.com.", 3600)
txtRecord := dns.NewTXTRecord("example.com.", "v=spf1 -all", 3600)
srvRecord := dns.NewSRVRecord("_sip._tcp", "sip.example.com.", 5060, 10, 20, 3600)

// DNSSEC records
dnskeyRecord := dns.NewDNSKEYRecord("example.com.", "publickey...", 257, 3, 13, 3600)
dsRecord := dns.NewDSRecord("child.example.com.", 12345, 13, 2, "digest...", 3600)
rrsigRecord := dns.NewRRSIGRecord("www", "A", 13, 3, 3600, "20250201", "20250101", 12345, "example.com.", "signature...")

// SOA record
soaRecord := dns.NewSOARecord(
    "example.com.",           // name
    "ns1.example.com.",       // mname
    "hostmaster.example.com.", // rname
    2024010101,               // serial
    86400,                    // refresh
    7200,                     // retry
    604800,                   // expire
    3600,                     // minimumTTL
    3600,                     // ttl
)
```

### Updating Records

Records are updated by modifying the zone and saving:

```go
// Get zone
zone, err := dnsService.Zone(ctx, "example.com")

// Find and update A record
for _, record := range zone.RecordSet.ARecords {
    if record.Name == "www" {
        record.Value = "192.0.2.200"
        record.TTL = 7200
    }
}

// Increment SOA serial
zone.RecordSet.SOARecord.Serial++

// Save changes
err = dnsService.Save(ctx, zone)
```

### Deleting Records

**Remove by name:**

```go
zone.RemoveARecord("oldhost")
zone.RemoveAAAARecord("oldhost")
zone.RemoveCNAMERecord("oldalias")
zone.RemoveMXRecord("example.com.")
zone.RemoveNSRecord("example.com.")
zone.RemoveTXTRecord("example.com.")
zone.RemoveSRVRecord("_sip._tcp")
zone.RemoveDNSKEYRecord("example.com.")
zone.RemoveDSRecord("child.example.com.")
zone.RemoveRRSIGRecord("example.com.")

// Save changes
err := dnsService.Save(ctx, zone)
```

### Listing Records

```go
zone, err := dnsService.Zone(ctx, "example.com")

// Access all records
aRecords := zone.RecordSet.ARecords
aaaaRecords := zone.RecordSet.AAAARecords
cnameRecords := zone.RecordSet.CNAMERecords
mxRecords := zone.RecordSet.MXRecords
nsRecords := zone.RecordSet.NSRecords
soaRecord := zone.RecordSet.SOARecord
srvRecords := zone.RecordSet.SRVRecords
txtRecords := zone.RecordSet.TXTRecords
dnskeyRecords := zone.RecordSet.DNSKEYRecords
dsRecords := zone.RecordSet.DSRecords
rrsigRecords := zone.RecordSet.RRSIGRecords
```

## Special Records

### SOA Record

- **One per zone**: Each zone must have exactly one SOA record
- **Serial management**: Increment serial number on every zone change
- **Timing parameters**: Control zone transfer and caching behavior

**Serial number conventions:**

| Format | Example | Description |
|--------|---------|-------------|
| YYYYMMDDnn | 2024010101 | Date-based with revision |
| Increment | 1, 2, 3... | Simple sequential |
| Unix timestamp | 1704067200 | Seconds since epoch |

### NS Records

- **Minimum two**: Production zones should have at least 2 NS records
- **Delegation**: NS records delegate authority for subdomains
- **Glue records**: A records for NS servers within same zone

```yaml
ns:
  - name: "example.com."
    value: "ns1.example.com."
    ttl: 86400
  - name: "example.com."
    value: "ns2.example.com."
    ttl: 86400

a:
  # Glue records for nameservers
  - name: "ns1"
    value: "192.0.2.10"
    ttl: 86400
  - name: "ns2"
    value: "192.0.2.11"
    ttl: 86400
```

### DNSKEY Record

- **Key types**: KSK (257) for signing DNSKEY RRset, ZSK (256) for other records
- **Key rotation**: Maintain overlap periods when rotating keys
- **Algorithm selection**: Use ECDSA (13, 14) or EdDSA (15, 16) for new zones

### DS Record

- **Parent zone**: DS records are published in parent zone
- **Chain of trust**: Links child zone DNSKEY to parent zone
- **Digest algorithm**: SHA-256 (2) recommended, SHA-384 (4) for higher security

### RRSIG Record

- **Signature validity**: Set appropriate expiration windows
- **Covered types**: Each record type gets its own RRSIG
- **Inception/expiration**: Use absolute timestamps

## Records Without a CLI

`platformctl dns record` ([cli.md](cli.md)) adds, updates, lists, reads and
deletes records. The API equivalents are REST `/api/v1/dns/zones/{zone}/records`
or gRPC `DNSService`; [api-reference-rest.md](api-reference-rest.md) has the
request bodies. REST has no record update route: delete and re-add.

## See Also

- [DNS Zones](zones.md) - Zone management guide
- [Platform Configuration](configuration.md) - Full configuration reference
- [Security Documentation](../security/architecture.md) - Security model and DNSSEC
