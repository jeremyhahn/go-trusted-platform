# Bootstrap REST API Reference

The bootstrap endpoint serves CA certificate bundles without authentication, enabling clients to fetch the trust root before establishing TLS connections.

## Endpoint

**GET** `/api/v1/ca/bootstrap`

Unauthenticated endpoint that returns the platform's CA certificate bundle in PEM format.

## Authentication

None. This endpoint is intentionally public to support trust bootstrap before TLS is operational.

## Query Parameters

Optional filtering parameters (applied server-side):

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `store_type` | string | all | Filter certificates by keystore: `software`, `tpm2`, or `all` |
| `algorithm` | string | all | Filter certificates by algorithm: `rsa`, `ecdsa`, `ed25519`, or `all` |

## Response

**Status:** 200 OK

**Content-Type:** `application/x-pem-file` or `text/plain`

**Body:** PEM-encoded X.509 certificate bundle (PKCS#7 or chain)

```
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAJC1...
...
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDYTCCAkmgAwIBAgIJAKB2...
...
-----END CERTIFICATE-----
```

## Error Responses

| Status | Description |
|--------|-------------|
| 404 | CA bundle not found (should not occur in normal operation) |
| 500 | Internal server error |

## Examples

### Fetch CA Bundle (DANE)

```bash
curl -o ca-bundle.pem https://server.example.com:8443/api/v1/ca/bootstrap
```

With DNSSEC TLSA verification (go-truststrap handles this):

```bash
truststrap -strategy dane \
  -server-url https://server.example.com:8443 \
  -dns-server 8.8.8.8:53 \
  -bundle-path /api/v1/ca/bootstrap
```

### Fetch CA Bundle (SPKI)

With SPKI pin verification (go-truststrap handles this):

```bash
truststrap -strategy spki \
  -server-url https://server.example.com:8443 \
  -spki-pin sha256/sMgbLWtKLKr4Yp8P2C3N5C8K2L1M9N7O6P5Q4R3S2T1U \
  -bundle-path /api/v1/ca/bootstrap
```

### Filter by Algorithm

```bash
curl 'https://server.example.com:8443/api/v1/ca/bootstrap?algorithm=ecdsa' \
  -o ca-bundle-ecdsa.pem
```

### Filter by Keystore

```bash
curl 'https://server.example.com:8443/api/v1/ca/bootstrap?store_type=software' \
  -o ca-bundle-software.pem
```

### Insecure (Testing Only)

```bash
# Skip TLS verification - NOT SECURE
curl -k https://server.example.com:8443/api/v1/ca/bootstrap
```

## Integration with Client Bootstrap

The platform's bootstrap client uses this endpoint via configured strategy:

```go
// Client fetches bundle using DANE verification
client, err := bootstrap.NewClient(&bootstrap.ClientConfig{
    Strategy:         bootstrap.StrategyDANE,
    ServerURL:        "https://server.example.com:8443",
    DNSServer:        "8.8.8.8:53",
    BundlePath:       "/api/v1/ca/bootstrap",
    PerMethodTimeout: 15 * time.Second,
}, logger)

bundlePEM, err := client.FetchCABundle(ctx)
if err != nil {
    log.Fatal(err)
}

// Optionally install to system trust store
err = client.InstallToSystemTrust(bundlePEM, "/usr/local/share/ca-certificates/platform-ca.crt")
```

## Server Configuration

Enable the endpoint via CA configuration:

```yaml
certificate-authority:
  platform-ca: 1
  auto-import-issuing-ca: true
  system-cert-pool: false
```

The webservice hosting the endpoint must have TLS enabled:

```yaml
webservices:
  - name: public
    tls-port: 8443
    certificate:
      subject:
        cn: server.example.com
```

## Client Configuration

Configure the bootstrap client to use this endpoint:

```yaml
bootstrap-client:
  strategy: dane
  server-url: "https://server.example.com:8443"
  dns-server: "8.8.8.8:53"
  bundle-path: "/api/v1/ca/bootstrap"
  per-method-timeout: 15s
  install-to-system-trust: true
```

## Implementation Notes

- **PEM Format:** PKCS#7 compatible, all certificates in chain
- **Order:** Root CA → Intermediate CA → Leaf (if present)
- **Caching:** HTTP caching headers respected (cache until renewal)
- **Rate Limiting:** No built-in limits; deploy behind load balancer if needed
- **Logging:** All bootstrap requests logged with IP, strategy used (if tracked)

## Related

- [Bootstrap Overview](./overview.md)
- [DANE Configuration](./dane.md)
- [Client Configuration](./configuration.md)
