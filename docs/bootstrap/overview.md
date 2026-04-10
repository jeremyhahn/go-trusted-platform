# Bootstrap Overview

Bootstrap solves the certificate chicken-and-egg problem: how do you establish a trusted connection to fetch the CA certificate before the CA certificate is available?

The platform provides four complementary strategies for secure trust bootstrap, each with different trust sources and deployment models.

## Bootstrap Strategies

| Strategy | Trust Source | When | Port |
|----------|-------------|------|------|
| **dane** | DNSSEC | Runtime | 8443 (REST) |
| **noise** | Pre-shared Curve25519 key | Runtime | 9446 |
| **spki** | Pre-shared cert SPKI hash | Runtime | 8443 (REST) |
| **embedded** | Embedded CA cert | Build time | N/A |
| **auto** | Multi-method fallback | Runtime | Multiple |

## Architecture

### Server-Side Components

The server publishes and serves CA bundles through multiple channels:

- **DANE Publisher**: Computes TLSA records from X.509 certificates and publishes them to the DNS zone with DNSSEC signatures
- **Bootstrap REST Endpoint**: Serves PEM CA bundles unauthenticated at `/api/v1/ca/bootstrap`
- **Noise Server**: Listens on port 9446, performs Noise_NK handshake, returns CA bundle
- **Rollover Manager**: Orchestrates RFC 7671 pre-publication DANE-EE rollover during certificate renewal

### Client-Side Components

Clients fetch and install the CA bundle before TLS connections:

- **Bootstrap Client**: Map-based strategy dispatch (`fetchDANE`, `fetchNoise`, `fetchSPKI`, `fetchEmbedded`, `fetchAuto`)
- **Auto Bootstrapper**: Tries multiple methods in priority order, stops at first success
- **System Trust Installation**: Optional write to system certificate store (e.g., `/usr/local/share/ca-certificates/`)

## Trust Model

**DANE Strategy (Recommended)**

```
1. Client queries DNSSEC-signed TLSA record: _8443._tcp.server.example.com.
2. DNSSEC validates the DNS RRset
3. TLSA record contains CA cert fingerprint (DANE-TA usage=2)
4. Client verifies server cert chain against TLSA
5. Secure bootstrap without pre-shared secrets
```

**Noise Strategy (High Assurance)**

```
1. Server generates ephemeral Curve25519 keypair
2. Public key distributed out-of-band to client
3. Client performs Noise_NK handshake with known server pubkey
4. Encrypted channel established without certificates
5. CA bundle transmitted over authenticated, encrypted link
```

**SPKI Strategy (Rapid Deployment)**

```
1. Server cert SPKI hash pre-computed: openssl x509 -pubkey -noout | sha256sum
2. Client configured with SPKI pin
3. Client connects to server, verifies cert SPKI matches pin
4. CA bundle downloaded over pinned connection
```

**Embedded Strategy (Offline Trust)**

```
1. CA certificate baked into ISO at build time
2. No network fetch required
3. Platform initiates enrollment using embedded trust root
4. Suitable for air-gapped deployments
```

## Certificate Renewal and Rollover

When the CA renews its certificate:

1. **Pre-publish Phase**: New TLSA record published alongside old record
   - TTL = 2x DefaultTTL (default 7200 seconds)
   - DNS caches expire the old record
   - Clients gradually transition to new TLSA

2. **Activation Phase**: New certificate loaded into TLS stack
   - CertReloader performs atomic pointer swap
   - Old TLSA record draining client connections

3. **Completion Phase**: Old TLSA records removed
   - Zone re-signed with DNSSEC
   - Rollover state returns to idle

**Key Reuse Optimization** (Selector=1/SPKI unchanged):
- Rollover completes immediately (no pre-publish delay)
- Useful for frequent certificate updates

## Implementation Details

### DANE TLSA Record Format

```
_<port>._tcp.<hostname>. <ttl> IN TLSA <usage> <selector> <matching-type> <digest>

Example:
_8443._tcp.server.example.com. 3600 IN TLSA 2 1 1 <SHA256-SPKI-hash>
```

- **Usage 2 (DANE-TA)**: Pins the CA certificate (seldom changes)
- **Usage 3 (DANE-EE)**: Pins the end-entity certificate (changes on renewal)
- **Selector 1 (SPKI)**: Hash the subject public key (survives key rotation with same algo)
- **Matching Type 1 (SHA-256)**: Digest algorithm

### Noise Protocol

- Uses go-truststrap's `noiseboot.Server`
- Pattern: Noise_NK (No static client key, server known)
- Static key generated on server startup
- Client connects to `<server-addr>`, completes handshake with `<server-static-key>`
- Returns CA bundle in single message

## Related Concepts

- **RFC 6698**: DANE (DNS-based Authentication of Named Entities)
- **RFC 7671**: DANE Certificate Usage Rollover
- **Noise Protocol Framework**: https://noiseprotocol.org/
- **go-truststrap**: Upstream bootstrap library providing DANE, Noise, SPKI implementations
