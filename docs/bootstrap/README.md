# Bootstrap Documentation

Comprehensive guide to the platform's bootstrap features: certificate trust bootstrapping and PXE network bootstrapping.

## Contents

### Certificate Trust Bootstrap

Solves the chicken-and-egg problem of establishing trust before the CA certificate is available.

- **[Overview](./overview.md)** -- Architecture, strategies, trust models
  - Four bootstrap strategies (DANE, Noise, SPKI, Embedded)
  - Server-side components (DANE Publisher, Noise Server, Rollover Manager)
  - Client-side components (Bootstrap Client, Auto Bootstrapper)
  - Certificate renewal and rollover process

- **[Configuration](./configuration.md)** -- Full server and client config reference
  - DANE configuration fields with defaults
  - Noise server settings
  - Client strategy selection and examples

- **[DANE](./dane.md)** -- DANE-specific detailed documentation
  - TLSA record types, RFC 6698 and RFC 7671
  - Rollover state machine and timing

- **[API Reference (REST)](./api-reference-rest.md)** -- REST bootstrap endpoint

### PXE Network Bootstrap

Single-command greenfield deployment of bare metal infrastructure.

- **[PXE Bootstrap](./pxe-bootstrap.md)** -- Overview, phases, CLI commands
- **[Day Zero Guide](./day-zero.md)** -- Step-by-step first deployment
- **[Config Reference](./config-reference.md)** -- Complete bootstrap.yaml reference
- **[Deployer](./deployer.md)** -- Bootstrap container deployment targets
- **[Switch Management](./switch-management.md)** -- Physical switch auto-configuration
- **[Manual Nodes](./manual-nodes.md)** -- Provisioning nodes without BMC

## Quick Start

### Trust Bootstrap (Client)

```yaml
trust:
  default:
    strategies: [dane]
    server-url: "https://server.example.com:8443"
    dane:
      dns-server: "8.8.8.8:53"
    bundle-path: "/api/v1/ca/bootstrap"
    per-method-timeout: 15s
    install-to-system-trust: true
```

### PXE Network Bootstrap

```bash
# Full deployment from bare metal
platformctl bootstrap run --config bootstrap.yaml

# Discovery only
platformctl bootstrap discover --config bootstrap.yaml

# Check node health
platformctl bootstrap status --config bootstrap.yaml
```

## Strategy Comparison (Trust)

| Strategy | Trust Source | Setup | Best For |
|----------|--------------|-------|----------|
| **DANE** | DNSSEC | Medium (need DNS zone) | Default, most deployments |
| **Noise** | Pre-shared key | Low (distribute key) | Air-gapped, high assurance |
| **SPKI** | Cert hash | Low (compute hash once) | Rapid deployment, testing |
| **Embedded** | Hardcoded cert | High (rebuild ISO) | Air-gapped, offline |
| **Multi-method** | First success | Medium | Fallback to any available |
