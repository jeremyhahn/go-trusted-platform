# Bootstrap Configuration Reference

## Architecture Note: Trust Resolver Layering

The platform trust resolver is a thin wrapper over the canonical generic
resolver that lives in `go-xkms/pkg/trust/resolver`, reached through the
QuicBaaS SDK re-export (`go-quicbaas/sdk/go/xkms/trust/resolver`).

The platform layer owns:
- Three class constants (`default`, `bmc`, `internal`) used as scope names.
- Per-class strategy allowlists (see Validation Rules below).
- `platform-ca` → `provider-ca` normalisation: the platform YAML spells the
  strategy `platform-ca`; the generic resolver receives `provider-ca`.
- TOFU pin-store threading: `WithTOFUPinStore` must be supplied at resolver
  construction for any class that lists `tofu` in its strategies chain.

Strategy dispatch, per-strategy fetch logic, caching, and install are all
owned by the generic resolver in go-xkms.

## Server Configuration

Server bootstrap publishes CA bundles via DANE TLSA records and optional Noise_NK server.

### DNS Resolver (Platform-Wide Default)

Located under `dns.resolver.*` in platform config. All DNS consumers (bootstrap,
ACME, installer) use this as the platform-wide default. Service-level overrides
(such as `trust.default.dane.dns-server`) take precedence when explicitly configured.

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

Client trust bootstrap fetches the CA bundle from the server before TLS can be
established. Located under `trust.*` in platform config. The `trust:` section
carries one scope per trust class -- `default` (provisioning/CP trust), `bmc`
(BMC endpoints), and `internal` (platform-internal mTLS sites). Each scope
declares an ordered `strategies` chain; the resolver attempts each strategy in
order until one succeeds.

```yaml
trust:
  default:
    strategies: [dane, noise, spki]            # Ordered fetch chain
    server-url: "https://10.99.99.2:8443"      # REST endpoint for DANE/SPKI
    hostname: "server.example.com"             # DANE TLSA lookup name (required when server-url is an IP)
    bundle-path: "/api/v1/ca/bootstrap"        # REST path for CA bundle
    per-method-timeout: 15s                    # Timeout per strategy attempt
    install-to-system-trust: true              # Write to system cert store
    dane:
      dns-server: "10.99.99.2:8053"            # Optional service-level override
    noise:
      server-addr: "10.99.99.2:9446"           # Noise server address (noise only)
      server-static-key: "<64-hex-curve25519>" # Server's hex-encoded Curve25519 pubkey (noise only)
    spki:
      pin: "<64-hex-sha256>"                   # Hex SHA-256 of server SPKI (spki only)
      # pin-file: /etc/trusted-platform/bootstrap-spki-pin  # or read the pin from disk
```

### DNS Resolution Priority

The trust resolver determines the DANE DNS server address using the following
priority order:

1. **`trust.default.dane.dns-server`** -- explicit service-level override. Use
   this only when the bootstrap DNS server differs from the platform default.
2. **`dns.resolver.servers[0]`** -- platform-wide default from the `dns.resolver`
   section. This is the recommended configuration point; the platform populates
   `dane.dns-server` from it automatically when the override is omitted.
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

trust:
  default:
    strategies: [dane]
    server-url: "https://10.99.99.2:8443"
    hostname: "server.example.com"
    # dane.dns-server is omitted -- derived from dns.resolver.servers[0]
    bundle-path: "/api/v1/ca/bootstrap"
    per-method-timeout: 15s
    install-to-system-trust: true
```

### Strategy Selection

**dane** (Default)
- Requires: DNSSEC-validating resolver
- Benefits: No secrets to manage, automatic rollover
- Reliability: Depends on DNS availability
- Allowed in: `default`, `bmc`
- Config:
  ```yaml
  trust:
    default:
      strategies: [dane]
      server-url: "https://server.example.com:8443"
      bundle-path: "/api/v1/ca/bootstrap"
      dane:
        dns-server: "8.8.8.8:53"
  ```

**noise**
- Requires: Server's static Curve25519 public key (distributed out-of-band)
- Benefits: No DNS/DNSSEC dependency, high assurance
- Reliability: Direct TCP connection to server
- Allowed in: `default`
- Config:
  ```yaml
  trust:
    default:
      strategies: [noise]
      noise:
        server-addr: "server.example.com:9446"
        server-static-key: "1f4b...64-hex-chars...9d2c"
  ```

**spki**
- Requires: Server's certificate SPKI SHA-256 hash (64 hex chars)
- Benefits: No out-of-band secrets, resilient to DNSSEC misconfigs
- Reliability: Depends on initial cert pinning accuracy
- Allowed in: `default`, `bmc`
- Config:
  ```yaml
  trust:
    default:
      strategies: [spki]
      server-url: "https://server.example.com:8443"
      bundle-path: "/api/v1/ca/bootstrap"
      spki:
        pin: "a1b2...64-hex-chars...c3d4"
  ```

**embedded**
- Requires: CA certificate baked into ISO at build time
- Benefits: No network required, maximum simplicity
- Reliability: Hardcoded, no runtime fetch
- Allowed in: `default`
- Config:
  ```yaml
  trust:
    default:
      strategies: [embedded]
  ```

**tofu** (Trust-on-First-Use)
- Requires: A `TOFUPinStore` injected at resolver construction time via
  `WithTOFUPinStore`. On first connection the server's leaf SPKI pin is
  captured and persisted; subsequent connections verify the stored pin.
- Benefits: Zero configuration, self-provisioning for environments without
  DANE DNS or pre-distributed keys. Suitable for BMC enrollment (the captured
  BMC pin becomes the credential for all subsequent SPKI verifications).
- Risks: First connection is unauthenticated (trust-on-first-use). Only
  suitable when the initial connection occurs over a trusted provisioning
  network or is confirmed by an operator via the confirm hook.
- Allowed in: `default`, `bmc`
- **TOFU is never an implicit fallback — it MUST be listed explicitly** in the
  `strategies` chain. Environments without DANE publishing should use
  `[dane, noise, spki, tofu]` with a comment explaining the semantics.
- Config:
  ```yaml
  trust:
    # Recommended chain for environments without DANE publishing.
    # TOFU captures and pins the server certificate on first contact.
    # Subsequent connections verify the stored pin; any certificate change
    # requires manual pin rotation in the TOFU store.
    default:
      strategies: [dane, noise, spki, tofu]
      server-url: "https://server.example.com:8443"
      bundle-path: "/api/v1/ca/bootstrap"
      per-method-timeout: 15s
    bmc:
      # Phase 3 BMC trust chain. TOFU captures the BMC SPKI on first contact;
      # remove tofu once DANE TLSA records for <hostname>-bmc.<zone> are live.
      strategies: [dane, spki, ca-file, tofu]
      dane:
        dns-server: "127.0.0.1:8053"   # platform public DNS
  ```

**ca-file**
- Requires: A CA bundle PEM file on local disk
- Benefits: Offline, no network dependency
- Allowed in: `bmc`
- Config:
  ```yaml
  trust:
    bmc:
      strategies: [ca-file]
      ca-file: /etc/trusted-platform/bmc-ca.pem
  ```

### BMC TLSA naming convention

BMC DANE TLSA records are published at:

```
_443._tcp.<hostname>-bmc.<internal-zone>
```

For example, if the node hostname is `lab-node-2` and the internal zone is
`example.internal`, the TLSA record lives at:

```
_443._tcp.lab-node-2-bmc.example.internal
```

The BMC enroll ceremony and the AutoCertManager rotation hook publish this
record automatically. Until the record is published, the `tofu` strategy in
the BMC chain handles first contact. Once the TLSA record is live, remove
`tofu` from the chain — either in the template directly or in your override
file:

```yaml
trust:
  bmc:
    strategies: [dane, spki, ca-file]
```

**platform-ca**
- Requires: Platform CA bundle provider injected via `WithPlatformCA`
- Benefits: Automatically uses the platform's own CA; no external config
- Allowed in: `internal` only
- Config:
  ```yaml
  trust:
    internal:
      strategies: [platform-ca]
  ```

**Ordered chain** (replaces the old `auto` strategy)
- List multiple strategies; the resolver attempts each in order and succeeds
  on the first one that works
- Config:
  ```yaml
  trust:
    default:
      strategies: [dane, noise, spki]
      server-url: "https://server.example.com:8443"
      bundle-path: "/api/v1/ca/bootstrap"
      per-method-timeout: 15s
      dane:
        dns-server: "8.8.8.8:53"
      noise:
        server-addr: "server.example.com:9446"
        server-static-key: "1f4b...64-hex-chars...9d2c"
      spki:
        pin: "a1b2...64-hex-chars...c3d4"
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

trust:
  default:
    strategies: [dane]
    server-url: "https://10.99.99.2:8443"
    hostname: "server.example.com"
    # dane.dns-server derived from dns.resolver.servers[0]
    bundle-path: "/api/v1/ca/bootstrap"
    per-method-timeout: 15s
    install-to-system-trust: true
```

### Client Ordered-Chain Bootstrap

```yaml
dns:
  resolver:
    servers:
      - address: "10.99.99.2"
        port: 8053
    search-domains:
      - example.internal

trust:
  default:
    strategies: [dane, noise, spki]
    server-url: "https://server.example.com:8443"
    # dane.dns-server derived from dns.resolver.servers[0]
    bundle-path: "/api/v1/ca/bootstrap"
    per-method-timeout: 15s
    install-to-system-trust: true
    noise:
      server-addr: "server.example.com:9446"
      server-static-key: "1f4b...64-hex-chars...9d2c"
    spki:
      pin: "a1b2...64-hex-chars...c3d4"
```

### Client Without DANE (TOFU Fallback)

Environments that have not yet set up DNSSEC or DANE publishing should include
`tofu` at the end of the chain so the first connection establishes a stored pin
that all subsequent connections verify against.

```yaml
trust:
  # TOFU captures and stores the server's SPKI hash on first contact.
  # Subsequent connections verify against the stored hash exactly like spki.
  # TOFU requires a TOFUPinStore; the platform wires one automatically when
  # a storage backend is available (after the QuicBaaS SDK is initialized).
  default:
    strategies: [dane, noise, spki, tofu]
    server-url: "https://server.example.com:8443"
    bundle-path: "/api/v1/ca/bootstrap"
    per-method-timeout: 15s
    install-to-system-trust: true
```

## Validation Rules

The platform enforces:

- `strategies` is required per scope and each entry must be allowed for the
  scope's class:
  - `default` allows `dane`, `noise`, `spki`, `embedded`, `tofu`
  - `bmc` allows `dane`, `spki`, `ca-file`, `tofu`
  - `internal` allows only `platform-ca`
- When a `noise` sub-config is present, `noise.server-addr` and
  `noise.server-static-key` are required
- When an `spki` sub-config sets `pin-file`, the file must be readable; its
  contents populate `spki.pin`. A scope without any pin is still valid because
  a PinStore may supply per-endpoint pins at resolution time
- When `tofu` is listed in any scope, a `TOFUPinStore` must be injected at
  resolver construction time via `WithTOFUPinStore`; omitting it returns
  `ErrTOFUPinStoreRequired`
- `per-method-timeout` must not be negative

Whether a strategy can actually run (e.g. DANE has a DNS server, SPKI has a
resolved pin) is determined at fetch time: an unconfigured strategy fails its
attempt and the resolver falls through to the next strategy in the chain.
