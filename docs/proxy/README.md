# Trusted Authenticating Reverse Proxy

The platform's flagship gatewayd service: an L7 reverse proxy that puts
legacy applications behind trusted-computing authentication without
changing a line of their code.

- **platformd** owns the configuration (routes, backend pools, zone
  matrix) and serves it over every API protocol
  ([api-reference.md](api-reference.md)).
- **gatewayd** runs the data plane: the `pkg/proxy` engine assembled by
  `pkg/sdn/gateway/proxysvc`, syncing platformd configuration over the
  sdk/go client and hot-reloading with zero dropped connections.

## Why not Envoy / Traefik / nginx?

General-purpose proxies authenticate with secrets someone can steal:
bearer tokens, static client certs, basic auth. This proxy authenticates
with the platform's hardware root of trust and its SDN policy model:

| Capability | This proxy | Generic proxy |
|------------|-----------|---------------|
| Client identity | Platform-CA mTLS, optional TCG IDevID (hardware-bound device identity); DPoP sender-constrained platform tokens (RFC 9449) for token clients | Any CA, no device binding; replayable bearers |
| Attestation | Routes can require a fresh, platformd-verified TPM attestation manifest (`require-attestation`) before admitting a device | None |
| Authorization | SDN network-zone from an X.509 extension in the client cert, enforced against the same compiled zone matrix that programs OVS L2/L3 flow rules; token scopes with qrdb wildcard semantics; per-route OPA policies | Path/header rules, disjoint from network policy |
| Backend identity | mTLS from the proxy's platform identity plus trusted `X-TP-Client-*` headers (every inbound `X-TP-*` header is stripped before auth, so backends can trust them unconditionally) | Header injection without spoofing defense |
| Config source of truth | platformd store, versioned, synced over authenticated SDK transports | Files / xDS / labels |
| Fail-closed composition | Refuses to start or reload with any auth requirement its chain cannot enforce | Silently serves misconfig |

The result: one consistent zone policy from L2 (VLAN/OVS conntrack
firewall) through L7 (this proxy), all anchored in the same certificates
the platform issues at enrollment.

## Documents

| Document | Content |
|----------|---------|
| [architecture.md](architecture.md) | Engine, auth chain (mTLS + token + attestation + OPA), gatewayd assembly, sync loop |
| [configuration.md](configuration.md) | gatewayd `proxy:` section, static/runtime merge semantics |
| [security.md](security.md) | Threat model and fail-closed guarantees |
| [api-reference.md](api-reference.md) | platformd multi-protocol configuration API |

## Quick start

```yaml
# /etc/gatewayd/config.yaml
proxy:
  enabled: true
  tls:
    cert-file: /etc/gatewayd/tls/server.pem
    key-file: /etc/gatewayd/tls/server-key.pem
  listeners:
    - id: https
      address: :8443
  routes:
    - id: legacy-app
      path-prefix: /
      pool: legacy
      auth:
        mode: mtls
        allowed-zones: [control-plane]
  pools:
    - id: legacy
      backends:
        - url: http://10.0.10.20:8080
  sync:
    enabled: true
    interval: 15s
  platformd:
    protocol: unix
    socket: /run/platformd.sock
```

```bash
gatewayd serve --config /etc/gatewayd/config.yaml

# Provision runtime routes from anywhere:
platformctl proxy pool add --id legacy --backend http://10.0.10.20:8080
platformctl proxy route add --id legacy-app --path-prefix / --pool legacy \
  --auth-mode mtls --allowed-zone control-plane
```

## Testing

- Unit: `go test ./pkg/proxy/... ./pkg/sdn/gateway/proxysvc/...`
- Integration (devcontainer, all protocols + live traffic + hot reload):
  `make integration-test-proxy`
