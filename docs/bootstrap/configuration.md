# Bootstrap Configuration Reference

## Server Configuration

Server bootstrap publishes CA bundles via DANE TLSA records and optional Noise_NK server.

### DNS Resolver (Platform-Wide Default)

Located under `dns.resolver.*` in platform config. All DNS consumers (bootstrap,
ACME, installer) use this as the platform-wide default. Service-level overrides
(such as `bootstrap-client.dns-server`) take precedence when explicitly configured.

```yaml
dns:
  resolver:
    servers:
      - address: "127.0.0.1"        # Primary DNS server address
        port: 8053                   # Platform public DNS port
    fallback:
      - "1.1.1.1:53"                # Cloudflare public DNS
      - "8.8.8.8:53"                # Google public DNS
    search-domains:                  # Optional search domains for resolv.conf
      - example.internal
    local-forwarder:
      enabled: false                 # Enable local dnsmasq forwarding
      listen: "127.0.0.1:53"        # Local listener address
      cache-size: 1000               # DNS cache entries
```

**Default Values**

| Field | Default | Notes |
|-------|---------|-------|
| `servers[0].address` | 127.0.0.1 | Loopback for servers running CoreDNS |
| `servers[0].port` | 8053 | Platform public DNS port |
| `fallback` | 1.1.1.1, 8.8.8.8 | Used when primary unreachable |
| `local-forwarder.enabled` | false | Enable on clients with non-standard DNS ports |
| `local-forwarder.listen` | 127.0.0.1:53 | Bind address for local forwarder |
| `local-forwarder.cache-size` | 1000 | Number of cached entries |

### DANE Configuration

Located under `dns.dane.*` in platform config:

```yaml
dns:
  dane:
    enabled: true                    # Enable DANE TLSA publishing
    auto-generate: true              # Auto-publish TLSA on certificate renewal
    default-port: 8443               # Bootstrap server port for TLSA
    ttl: 3600                        # TLSA record TTL (seconds)
    default-usage: 2                 # 2=DANE-TA, 3=DANE-EE (use 2 for stability)
    default-selector: 1              # 1=SPKI (subject public key hash)
    default-matching-type: 1         # 1=SHA-256
    publish-dane-ee: true            # Also publish Usage=3 (DANE-EE) for leaf cert
    key-reuse: true                  # Skip pre-publish delay if SPKI hash unchanged
    rollover-ttl: 0                  # Custom rollover delay (0=use 2xTTL)
```

**Default Values**

| Field | Default | Notes |
|-------|---------|-------|
| `enabled` | false | Enable in production with DNSSEC |
| `auto-generate` | false | Set true for automatic TLSA management |
| `default-port` | 8443 | Match webservice TLS port |
| `ttl` | 3600 | DNS cache TTL |
| `publish-dane-ee` | false | Requires DNSSEC and frequent updates |
| `key-reuse` | false | Selector 1 + no key rotation |
| `rollover-ttl` | 0 | Computed as 2 * DefaultTTL if 0 |

### Noise Server Configuration

Located under `bootstrap.noise.*`:

```yaml
bootstrap:
  noise:
    enabled: false                   # Enable Noise_NK bootstrap server
    listen-addr: ":9446"             # Bind address and port
    max-connections: 100             # Concurrent connections
    read-timeout: 10s                # Socket read timeout
    write-timeout: 10s               # Socket write timeout
```

**When to Enable**

- Air-gapped networks (no DNS/DNSSEC)
- High-assurance environments requiring no DNS dependency
- Early bootstrap before DNS is operational

## Client Configuration

Client bootstrap fetches CA bundle from server before TLS. Located under `bootstrap-client.*`:

```yaml
bootstrap-client:
  strategy: dane                              # dane|noise|spki|embedded|auto
  server-url: "https://10.99.99.2:8443"      # REST endpoint for DANE/SPKI
  dns-server: "10.99.99.2:8053"              # Optional service-level override
  bundle-path: "/api/v1/ca/bootstrap"        # REST path for CA bundle
  per-method-timeout: 15s                    # Timeout per bootstrap attempt
  install-to-system-trust: true              # Write to system cert store
  noise:
    server-addr: "10.99.99.2:9446"           # Noise server address (noise only)
    server-static-key: "base64-encoded-key"  # Server's Curve25519 pubkey (noise only)
  spki:
    pin: "sha256/XXXXXXXX..."                # SPKI pin base64 (spki only)
```

### DNS Resolution Priority

The bootstrap client determines the DNS server address using the following
priority order:

1. **`dns.resolver.servers[0]`** -- platform-wide default from the `dns.resolver`
   section. This is the recommended configuration point.
2. **`bootstrap-client.dns-server`** -- explicit service-level override. Use this
   only when the bootstrap DNS server differs from the platform default.
3. **Fallback** -- constructed from the server IP address and default public DNS
   port (8053). Used by the test tool when no config is available.

**Recommended client config** using `dns.resolver` instead of per-service DNS:

```yaml
dns:
  resolver:
    servers:
      - address: "10.99.99.2"
        port: 8053
    search-domains:
      - example.internal
    local-forwarder:
      enabled: true
      listen: "127.0.0.1:53"
      cache-size: 1000

bootstrap-client:
  strategy: dane
  server-url: "https://10.99.99.2:8443"
  # dns-server is omitted -- derived from dns.resolver.servers[0]
  bundle-path: "/api/v1/ca/bootstrap"
  per-method-timeout: 15s
  install-to-system-trust: true
```

### Strategy Selection

**dane** (Default)
- Requires: DNSSEC-validating resolver
- Benefits: No secrets to manage, automatic rollover
- Reliability: Depends on DNS availability
- Config:
  ```yaml
  strategy: dane
  server-url: "https://server.example.com:8443"
  dns-server: "8.8.8.8:53"
  bundle-path: "/api/v1/ca/bootstrap"
  ```

**noise**
- Requires: Server's static Curve25519 public key (distributed out-of-band)
- Benefits: No DNS/DNSSEC dependency, high assurance
- Reliability: Direct TCP connection to server
- Config:
  ```yaml
  strategy: noise
  noise:
    server-addr: "server.example.com:9446"
    server-static-key: "aEroKDZNvHnfJCSYxlXuOu8MNLIvJnYuLRDNS5gxdxs="
  ```

**spki**
- Requires: Server's certificate SPKI SHA-256 hash
- Benefits: No out-of-band secrets, resilient to DNSSEC misconfigs
- Reliability: Depends on initial cert pinning accuracy
- Config:
  ```yaml
  strategy: spki
  server-url: "https://server.example.com:8443"
  bundle-path: "/api/v1/ca/bootstrap"
  spki:
    pin: "sha256/sMgbLWtKLKr4Yp8P2C3N5C8K2L1M9N7O6P5Q4R3S2T1U"
  ```

**embedded**
- Requires: CA certificate baked into ISO at build time
- Benefits: No network required, maximum simplicity
- Reliability: Hardcoded, no runtime fetch
- Config:
  ```yaml
  strategy: embedded
  ```

**auto**
- Tries multiple methods in priority order: DANE -> Noise -> SPKI
- Succeeds on first method that works
- Config:
  ```yaml
  strategy: auto
  server-url: "https://server.example.com:8443"
  dns-server: "8.8.8.8:53"
  bundle-path: "/api/v1/ca/bootstrap"
  per-method-timeout: 15s
  noise:
    server-addr: "server.example.com:9446"
    server-static-key: "aEroKDZNvHnfJCSYxlXuOu8MNLIvJnYuLRDNS5gxdxs="
  spki:
    pin: "sha256/sMgbLWtKLKr4Yp8P2C3N5C8K2L1M9N7O6P5Q4R3S2T1U"
  ```

## Environment Variable Overrides

Bootstrap client respects environment variables (if configured):

```bash
BOOTSTRAP_STRATEGY=noise
BOOTSTRAP_SERVER_URL=https://server.example.com:8443
BOOTSTRAP_DNS_SERVER=8.8.8.8:53
BOOTSTRAP_BUNDLE_PATH=/api/v1/ca/bootstrap
BOOTSTRAP_PER_METHOD_TIMEOUT=15s
BOOTSTRAP_INSTALL_TO_SYSTEM_TRUST=true
BOOTSTRAP_NOISE_SERVER_ADDR=server.example.com:9446
BOOTSTRAP_NOISE_SERVER_STATIC_KEY=aEroKDZNvHnfJCSYxlXuOu8MNLIvJnYuLRDNS5gxdxs=
BOOTSTRAP_SPKI_PIN=sha256/sMgbLWtKLKr4Yp8P2C3N5C8K2L1M9N7O6P5Q4R3S2T1U
```

## Complete Examples

### Server with DANE Rollover

```yaml
dns:
  resolver:
    servers:
      - address: "127.0.0.1"
        port: 8053
    fallback:
      - "1.1.1.1:53"
      - "8.8.8.8:53"
    local-forwarder:
      enabled: false
  dane:
    enabled: true
    auto-generate: true
    default-port: 8443
    ttl: 3600
    default-usage: 2
    default-selector: 1
    default-matching-type: 1
    publish-dane-ee: true
    key-reuse: true
    rollover-ttl: 7200
  dnssec:
    enabled: true

bootstrap:
  noise:
    enabled: false
```

### Server with Noise Fallback

```yaml
bootstrap:
  noise:
    enabled: true
    listen-addr: ":9446"
    max-connections: 100
    read-timeout: 10s
    write-timeout: 10s

dns:
  resolver:
    servers:
      - address: "127.0.0.1"
        port: 8053
  dane:
    enabled: false
```

### Client DANE Bootstrap

```yaml
dns:
  resolver:
    servers:
      - address: "10.99.99.2"
        port: 8053
    search-domains:
      - example.internal
    local-forwarder:
      enabled: true
      listen: "127.0.0.1:53"
      cache-size: 1000

bootstrap-client:
  strategy: dane
  server-url: "https://10.99.99.2:8443"
  # dns-server derived from dns.resolver.servers[0]
  bundle-path: "/api/v1/ca/bootstrap"
  per-method-timeout: 15s
  install-to-system-trust: true
```

### Client Auto Bootstrap

```yaml
dns:
  resolver:
    servers:
      - address: "10.99.99.2"
        port: 8053
    search-domains:
      - example.internal

bootstrap-client:
  strategy: auto
  server-url: "https://server.example.com:8443"
  # dns-server derived from dns.resolver.servers[0]
  bundle-path: "/api/v1/ca/bootstrap"
  per-method-timeout: 15s
  install-to-system-trust: true
  noise:
    server-addr: "server.example.com:9446"
    server-static-key: "aEroKDZNvHnfJCSYxlXuOu8MNLIvJnYuLRDNS5gxdxs="
  spki:
    pin: "sha256/sMgbLWtKLKr4Yp8P2C3N5C8K2L1M9N7O6P5Q4R3S2T1U"
```

## Validation Rules

The platform enforces:

- `strategy` is required and must be one of: `dane`, `noise`, `spki`, `embedded`, `auto`
- DANE strategy requires either `dns.resolver.servers[0]` or `dns-server` to be set
- Noise strategy requires `noise.server-addr` and `noise.server-static-key`
- SPKI strategy requires `spki.pin` to be set
- `per-method-timeout` must not be negative
