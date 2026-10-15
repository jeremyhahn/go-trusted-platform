# DNS over TLS / DNS over HTTPS

> **Status: NORMATIVE** · Scope: planned DNS over TLS and DNS over HTTPS; not implemented
> Conflicts with this document are defects. Fix them here first.

This document describes the planned architecture and configuration for DNS over TLS (DoT) and DNS over HTTPS (DoH) support in the Trusted Platform DNS subsystem. Implementation is scheduled for a future release.

## Overview

DNS over TLS (DoT) and DNS over HTTPS (DoH) provide encrypted transport for DNS queries, protecting against eavesdropping and manipulation of DNS traffic between clients and resolvers.

### Protocol Comparison

| Aspect | DNS over TLS (DoT) | DNS over HTTPS (DoH) |
|--------|-------------------|---------------------|
| **RFC** | RFC 7858 | RFC 8484 |
| **Port** | 853 (dedicated) | 443 (shared with HTTPS) |
| **Transport** | TLS 1.2/1.3 over TCP | HTTPS (HTTP/2 or HTTP/3) |
| **Identification** | Easily identified by port | Blends with HTTPS traffic |
| **Firewall** | Can be blocked by port | Difficult to distinguish |
| **Wire Format** | DNS wire format | DNS wire format or JSON |
| **HTTP Methods** | N/A | GET, POST |
| **Caching** | TCP connection reuse | HTTP caching headers |

### Benefits

| Benefit | DoT | DoH |
|---------|-----|-----|
| **Query Privacy** | Yes | Yes |
| **Response Integrity** | Yes | Yes |
| **Metadata Protection** | Partial | Yes |
| **Firewall Traversal** | Limited | Strong |
| **CDN Integration** | No | Yes |

## Threat Model

### Threats Addressed

| Threat | Description | Mitigation |
|--------|-------------|------------|
| **Query Eavesdropping** | Third parties observing DNS queries | TLS encryption |
| **Response Manipulation** | Attackers modifying DNS responses | TLS integrity |
| **Metadata Leakage** | Revealing query patterns | Encrypted transport |
| **ISP Interception** | Network operators logging/modifying DNS | End-to-end encryption |
| **DNS Fingerprinting** | Profiling users by queries | Traffic blending (DoH) |
| **Man-in-the-Middle** | Attackers intercepting queries | Certificate validation |

### Threats Not Addressed

| Threat | Reason | Mitigation |
|--------|--------|------------|
| **Server-side logging** | Resolver can still log queries | Policy, trust relationship |
| **Traffic analysis** | Query timing/size observable | Padding (RFC 7830) |
| **IP address exposure** | Server sees client IP | Anonymous proxies |
| **Compromised resolver** | Resolver returns malicious data | DNSSEC validation |

### Security Model

```
+-------------+          +------------------+          +----------------+
|   Client    |  DoT/DoH |  Trusted         |  DNS     |  Authoritative |
|             |<-------->|  Platform DNS    |<-------->|  Servers       |
+-------------+   TLS    +------------------+   UDP    +----------------+
      |                         |
      |                         |
      v                         v
  Encrypted               May use DNSSEC
  Query/Response          for validation
```

## Architecture

### High-Level Architecture

```
                          Trusted Platform DNS
+-----------------------------------------------------------------------+
|                                                                       |
|  +------------------+    +------------------+    +-----------------+  |
|  |  DoT Listener    |    |  DoH Listener    |    | Standard DNS    |  |
|  |  Port 853        |    |  Port 443        |    | Port 53/8053    |  |
|  +--------+---------+    +--------+---------+    +--------+--------+  |
|           |                       |                       |           |
|           +----------+------------+-----------+-----------+           |
|                      |                        |                       |
|                      v                        v                       |
|           +--------------------+    +--------------------+            |
|           | TLS Termination    |    | HTTP/2 Handler    |            |
|           +--------+-----------+    +--------+-----------+            |
|                    |                         |                        |
|                    +------------+------------+                        |
|                                 |                                     |
|                                 v                                     |
|                    +------------------------+                         |
|                    | Unified Query Handler  |                         |
|                    +------------------------+                         |
|                                 |                                     |
|            +--------------------+--------------------+                |
|            |                    |                    |                |
|            v                    v                    v                |
|    +---------------+    +---------------+    +---------------+       |
|    | Zone Resolver |    | Forwarder     |    | Cache         |       |
|    +---------------+    +---------------+    +---------------+       |
|                                                                       |
+-----------------------------------------------------------------------+
```

### Component Responsibilities

| Component | Responsibility |
|-----------|----------------|
| **DoT Listener** | Accept TLS connections on port 853, unwrap DNS queries |
| **DoH Listener** | HTTP/2 server on port 443, parse /dns-query requests |
| **TLS Termination** | Validate certificates, manage TLS sessions |
| **HTTP/2 Handler** | Parse HTTP requests, handle GET/POST methods |
| **Unified Query Handler** | Process DNS queries from all transports |
| **Zone Resolver** | Resolve queries against local zones |
| **Forwarder** | Forward queries to upstream resolvers |
| **Cache** | Cache responses for performance |

## TLS Configuration

### Certificate Configuration

```yaml
dns:
  tls:
    # Certificate source
    certificate:
      # Use platform CA to issue certificates
      source: platform-ca

      # Alternative: specify certificate files directly
      # source: file
      # cert-file: /etc/trusted-platform/certs/dns.crt
      # key-file: /etc/trusted-platform/certs/dns.key

      # Certificate parameters (for platform-ca source)
      common-name: dns.example.com
      san:
        - dns.example.com
        - "*.dns.example.com"
      validity: 365d

    # Minimum TLS version
    min-version: "1.2"

    # Preferred TLS version
    preferred-version: "1.3"

    # Cipher suites (TLS 1.2)
    cipher-suites:
      - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
      - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
      - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
      - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
      - TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
      - TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256

    # Elliptic curves preference
    curves:
      - X25519
      - CurveP384
      - CurveP256

    # ALPN protocols
    alpn:
      - h2           # HTTP/2 for DoH
      - dot          # DNS over TLS

    # Session resumption
    session-tickets: true
    session-cache-size: 10000

    # OCSP stapling
    ocsp-stapling: true
```

### TLS Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `min-version` | string | `1.2` | Minimum TLS version |
| `preferred-version` | string | `1.3` | Preferred TLS version |
| `cipher-suites` | []string | (secure defaults) | TLS 1.2 cipher suites |
| `curves` | []string | (secure defaults) | Elliptic curves preference |
| `alpn` | []string | `[h2, dot]` | ALPN protocols |
| `session-tickets` | bool | `true` | Enable session tickets |
| `ocsp-stapling` | bool | `true` | Enable OCSP stapling |

### Platform CA Integration

When using `source: platform-ca`, certificates are automatically issued and renewed:

```yaml
dns:
  tls:
    certificate:
      source: platform-ca
      issuer: intermediate-ca      # CA to issue from
      key-type: ecdsa-p256         # Key type
      validity: 365d               # Certificate validity
      renewal-threshold: 30d       # Renew 30 days before expiry
```

## DNS over TLS Configuration

### DoT Server Configuration

```yaml
dns:
  dot:
    # Enable DNS over TLS
    enabled: true

    # Listen address and port
    listen: 0.0.0.0
    port: 853

    # Connection limits
    max-connections: 1000
    max-connections-per-client: 10

    # Connection timeouts
    idle-timeout: 300s
    read-timeout: 10s
    write-timeout: 10s

    # TCP keep-alive
    keep-alive:
      enabled: true
      interval: 30s
      count: 3

    # Query pipelining
    pipelining: true
    max-pipelined-queries: 10

    # Response padding (RFC 7830)
    padding:
      enabled: true
      block-size: 468    # Pad to multiples of 468 bytes
```

### DoT Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable DoT server |
| `port` | int | `853` | DoT listen port |
| `max-connections` | int | `1000` | Maximum total connections |
| `max-connections-per-client` | int | `10` | Per-client connection limit |
| `idle-timeout` | duration | `300s` | Connection idle timeout |
| `read-timeout` | duration | `10s` | Read timeout per query |
| `write-timeout` | duration | `10s` | Write timeout per response |
| `pipelining` | bool | `true` | Enable query pipelining |
| `max-pipelined-queries` | int | `10` | Max pipelined queries |

### DoT Wire Format

DNS over TLS uses standard DNS wire format with a 2-byte length prefix:

```
+-----+-----+-----+-----+-----+-----+...+-----+
| Length (2 bytes)    | DNS Message (variable)|
+-----+-----+-----+-----+-----+-----+...+-----+
```

## DNS over HTTPS Configuration

### DoH Server Configuration

```yaml
dns:
  doh:
    # Enable DNS over HTTPS
    enabled: true

    # Listen address and port
    listen: 0.0.0.0
    port: 443

    # HTTP path for DNS queries
    path: /dns-query

    # HTTP/2 settings
    http2:
      enabled: true
      max-concurrent-streams: 100
      max-header-list-size: 8192
      initial-window-size: 65535

    # HTTP/3 settings (experimental)
    http3:
      enabled: false
      port: 443

    # CORS configuration (for browser clients)
    cors:
      enabled: true
      allowed-origins:
        - "*"
      allowed-methods:
        - GET
        - POST
      allowed-headers:
        - Content-Type
        - Accept
      max-age: 86400

    # Content types
    content-types:
      query:
        - application/dns-message
        - application/dns-json
      response:
        - application/dns-message
        - application/dns-json

    # Caching headers
    cache:
      enabled: true
      min-ttl: 60
      max-ttl: 86400

    # Response padding
    padding:
      enabled: true
      block-size: 468
```

### DoH Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable DoH server |
| `port` | int | `443` | DoH listen port |
| `path` | string | `/dns-query` | HTTP path for queries |
| `http2.enabled` | bool | `true` | Enable HTTP/2 |
| `http2.max-concurrent-streams` | int | `100` | Max concurrent HTTP/2 streams |
| `http3.enabled` | bool | `false` | Enable HTTP/3 (experimental) |
| `cors.enabled` | bool | `true` | Enable CORS headers |

### DoH Wire Formats

DoH supports two request methods with different wire formats:

#### GET Request (Base64URL)

```
GET /dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB HTTP/2
Host: dns.example.com
Accept: application/dns-message
```

The `dns` parameter contains the base64url-encoded DNS query.

#### POST Request (Binary)

```
POST /dns-query HTTP/2
Host: dns.example.com
Content-Type: application/dns-message
Accept: application/dns-message
Content-Length: 29

<binary DNS message>
```

#### Response Format

```
HTTP/2 200 OK
Content-Type: application/dns-message
Content-Length: 45
Cache-Control: max-age=300

<binary DNS message>
```

### JSON Wire Format (Optional)

DoH also supports JSON format for debugging and simple clients:

**Request:**
```
GET /dns-query?name=www.example.com&type=A HTTP/2
Host: dns.example.com
Accept: application/dns-json
```

**Response:**
```json
{
  "Status": 0,
  "TC": false,
  "RD": true,
  "RA": true,
  "AD": true,
  "CD": false,
  "Question": [
    {
      "name": "www.example.com.",
      "type": 1
    }
  ],
  "Answer": [
    {
      "name": "www.example.com.",
      "type": 1,
      "TTL": 300,
      "data": "93.184.216.34"
    }
  ]
}
```

## mTLS Client Authentication

Enable mutual TLS for authenticated DNS access.

### mTLS Configuration

```yaml
dns:
  tls:
    # Client certificate authentication
    client-auth:
      # Enable mTLS
      enabled: false

      # Client CA certificates
      ca-file: /etc/trusted-platform/certs/client-ca.crt

      # Require valid client certificate
      required: false

      # Verify client certificate against CRL
      crl-check: true

      # OCSP verification for client certs
      ocsp-check: true

    # Client certificate policies
    client-policies:
      # Allow queries based on certificate attributes
      - match:
          subject-cn: "*.internal.example.com"
        zones:
          - internal.example.com.
        allow:
          - query
          - zone-transfer

      - match:
          subject-ou: "Network Devices"
        zones:
          - "*"
        allow:
          - query
```

### mTLS Use Cases

| Use Case | Configuration |
|----------|---------------|
| **Internal resolvers** | Require client certs for all queries |
| **Zone transfer** | Require client certs for AXFR/IXFR |
| **Administrative access** | Client certs for management API |
| **Device authentication** | Validate device certificates |

## Integration with Platform Components

### Platform CA Integration

```yaml
dns:
  tls:
    certificate:
      source: platform-ca
      # CA issues certificates for DoT/DoH
```

The platform CA automatically:
- Issues TLS certificates for DNS servers
- Renews certificates before expiration
- Publishes TLSA records for DANE validation

### DANE Integration

Automatic TLSA record generation for DoT/DoH services:

```yaml
dns:
  dane:
    enabled: true
    auto-generate: true
    services:
      - port: 853
        protocol: tcp
        name: "DNS over TLS"
      - port: 443
        protocol: tcp
        name: "DNS over HTTPS"
```

### IAM Integration

Access control for encrypted DNS (PROPOSED - Not yet implemented):

> **Note:** IAM policy integration is a planned feature. The configuration shown below is a proposed format.

```yaml
# PROPOSED - Future IAM policy configuration
# Currently, access control is managed through mTLS client certificates
# configured in the webservices section

webservices:
  - name: dns-api
    mtls:
      enabled: true
      client-ca: /etc/platform/certs/client-ca.crt
```

## Implementation Roadmap

### Phase 1: Foundation (Priority: High)

| Task | Description | Status |
|------|-------------|--------|
| TLS infrastructure | Shared TLS configuration | Planned |
| Certificate management | Integration with platform CA | Planned |
| DoT listener | Basic DoT server implementation | Planned |
| Query handler | Unified query processing | Planned |

### Phase 2: DoT Complete (Priority: High)

| Task | Description | Status |
|------|-------------|--------|
| Connection management | Pooling, limits, keep-alive | Planned |
| Query pipelining | Multiple queries per connection | Planned |
| Response padding | RFC 7830 padding support | Planned |
| Metrics and logging | DoT-specific metrics | Planned |

### Phase 3: DoH Implementation (Priority: Medium)

| Task | Description | Status |
|------|-------------|--------|
| HTTP/2 server | HTTP/2 handler for DoH | Planned |
| Wire format support | DNS wire format and JSON | Planned |
| GET/POST methods | Both request methods | Planned |
| Cache headers | HTTP caching integration | Planned |
| CORS support | Browser client support | Planned |

### Phase 4: Security Hardening (Priority: High)

| Task | Description | Status |
|------|-------------|--------|
| mTLS support | Client certificate authentication | Planned |
| Rate limiting | Per-client query limits | Planned |
| DDoS protection | Connection and query limits | Planned |
| Security logging | Audit trail for encrypted DNS | Planned |

### Phase 5: Advanced Features (Priority: Medium)

| Task | Description | Status |
|------|-------------|--------|
| HTTP/3 (QUIC) | Experimental HTTP/3 support | Planned |
| DANE auto-publish | Automatic TLSA generation | Planned |
| Session resumption | TLS session tickets | Planned |
| 0-RTT support | TLS 1.3 0-RTT queries | Planned |

### Phase 6: Observability (Priority: Medium)

| Task | Description | Status |
|------|-------------|--------|
| Prometheus metrics | DoT/DoH specific metrics | Planned |
| Distributed tracing | Request tracing | Planned |
| Health endpoints | Readiness/liveness probes | Planned |
| Performance tuning | Optimization and benchmarks | Planned |

## CLI Commands (Planned)

### Server Management

```bash
# Start DoT/DoH servers
platformctl dns server start --dot --doh

# Check server status
platformctl dns server status

# Reload TLS certificates
platformctl dns server reload --tls
```

### Certificate Management

```bash
# Issue certificate for DNS server
platformctl dns tls issue --hostname dns.example.com

# Show current certificate
platformctl dns tls show

# Renew certificate
platformctl dns tls renew
```

### Testing and Diagnostics

```bash
# Test DoT connection
platformctl dns test --dot --server dns.example.com:853

# Test DoH connection
platformctl dns test --doh --server https://dns.example.com/dns-query

# Query via DoT
dig @dns.example.com +tls www.example.com A

# Query via DoH
curl -H "accept: application/dns-json" \
  "https://dns.example.com/dns-query?name=www.example.com&type=A"
```

## Related Documentation

| Document | Description |
|----------|-------------|
| [Security](security.md) | DNS security model |
| [DANE](dane.md) | DANE/TLSA integration |
| [Configuration](configuration.md) | Complete configuration reference |
| [Architecture](architecture.md) | DNS system architecture |
| [CA Documentation](../ca/architecture.md) | Certificate Authority overview |

## See Also

- [RFC 7858 - DNS over TLS](https://datatracker.ietf.org/doc/html/rfc7858)
- [RFC 8484 - DNS over HTTPS](https://datatracker.ietf.org/doc/html/rfc8484)
- [RFC 7830 - DNS Query Name Padding](https://datatracker.ietf.org/doc/html/rfc7830)
- [RFC 8310 - DNS over TLS and DTLS Usage Profiles](https://datatracker.ietf.org/doc/html/rfc8310)
- [RFC 9250 - DNS over QUIC](https://datatracker.ietf.org/doc/html/rfc9250)
