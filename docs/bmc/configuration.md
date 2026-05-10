# BMC Configuration

How to configure BMC connectivity in device templates and profiles.

## Device Template BMC Configuration

BMC settings are defined in device templates and inherited by profiles created from those templates.

```yaml
device_template:
  name: "dell-r640-ipmi"
  description: "Dell PowerEdge R640 with IPMI BMC"
  bmc:
    address: ""          # Set per-profile
    port: 623            # Default IPMI port
    username: ""         # Set per-profile or via credential store
    password: ""         # Set per-profile or via credential store
    protocol: "ipmi"     # "ipmi" or "redfish"
```

## Per-Profile BMC Configuration

Each device profile overrides the template with host-specific values.

```yaml
device_profile:
  template_id: 1
  serial_number: "DELL-R640-001"
  bmc:
    address: "10.10.0.101"
    port: 623
    username: "admin"
    password: "vault://bmc/dell-r640-001"
    protocol: "ipmi"
```

## Configuration Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `address` | string | yes | - | BMC IP address or hostname |
| `port` | int | no | 623 | BMC network port |
| `username` | string | yes | - | BMC authentication username |
| `password` | string | yes | - | BMC authentication password or vault reference |
| `protocol` | string | no | `ipmi` | Protocol: `ipmi` or `redfish` |
| `encryption-key` | string | no | - | Hex-encoded KG key for IPMI 2.0 RAKP (optional) |
| `skip-tls-verify` | bool | no | false | Skip TLS verify on Redfish (self-signed initial BMC certs) |
| `ca-cert-path` | string | no | - | Custom CA bundle for Redfish TLS verification |
| `certificate` | object | no | - | BMC web-server TLS identity (see below) |
| `key` | object | no | - | Private-key config for the cert (see below) |
| `backend` | string | no | `auto` | Cert-deployment backend: `auto`, `redfish`, or `smc-cgi` |
| `allow_cgi_fallback` | bool | no | `false` | Enable auto-mode selection of the Supermicro ATEN CGI cert backend. Gated until hardware validation clears (see `../operations/x10-smc-cgi-validation.md`). Explicit `backend: smc-cgi` bypasses this gate. |

## BMC TLS Identity

When `certificate:` and `key:` are both set, platformd manages the
BMC's web-server TLS certificate automatically: issues at boot,
deploys via the configured backend, and re-issues before expiry via
the platform's scheduler.

```yaml
bmc:
  address: bmc-node-17.internal
  port: 443
  username: admin
  password: "vault://bmc/node-17"
  protocol: redfish
  skip-tls-verify: true         # allow the initial self-signed cert

  # Cert identity -- same shape as webservice.certificate
  certificate:
    subject:
      cn: bmc-node-17.internal
    sans:
      dns: [bmc-node-17.internal]
    acme:
      request:
        authz_type: dns
        challenge_type: dns-01  # ENFORCED -- http-01 is rejected
    valid: 90                   # days

  key:
    algorithm: ECDSA
    cn: bmc-node-17.internal

  backend: auto                 # auto | redfish | smc-cgi
  allow_cgi_fallback: false     # enable auto-mode CGI selection for Supermicro X10
```

### dns-01 is mandatory for BMC

Platform config validation rejects `challenge_type != "dns-01"` for
BMC identities. BMCs live on isolated management VLANs unreachable
from ACME servers, so http-01 validation cannot succeed. Enforcement
is at config-load time -- misconfigured YAML surfaces an operator
error immediately, not at first renewal.

The platform's authoritative DNS service is the challenge provider.

### Backend selection

| `backend` | Resolved path |
|---|---|
| `auto` (default, or empty) | Vendor probe -> `bmc.RecommendCertBackend`. Supermicro -> `smc-cgi` (gated by `allow_cgi_fallback`); others -> `redfish` |
| `redfish` | Redfish `CertificateService.ReplaceCertificate` -- X11+, iDRAC9+, iLO5+ |
| `smc-cgi` | Supermicro ATEN CGI `upload_ssl.cgi` -- X10 hardware, pre-Redfish CertificateService firmware. Bypasses the `allow_cgi_fallback` gate. |

The `smc-cgi` backend in `auto` mode is **gated** behind hardware
validation until an operator runs the procedure at
`../operations/x10-smc-cgi-validation.md` and flips the
`allow_cgi_fallback` flag. Explicit pinning bypasses the gate.

## Credential Management

BMC credentials should not be stored in plaintext configuration files. Supported credential sources:

### Vault References

Prefix the password with `vault://` to retrieve credentials from the platform's secret store:

```yaml
bmc:
  password: "vault://bmc/server-001"
```

### Environment Variables

Use environment variable references for CI/CD pipelines:

```yaml
bmc:
  username: "${BMC_USERNAME}"
  password: "${BMC_PASSWORD}"
```

## Protocol Selection

### IPMI

Best for legacy hardware and environments where broad compatibility is needed. Uses UDP port 623 by default.

```yaml
bmc:
  protocol: "ipmi"
  port: 623
```

### Redfish

Recommended for modern hardware. Uses HTTPS (TCP 443) and provides richer system information.

```yaml
bmc:
  protocol: "redfish"
  port: 443
```

## Validation

The configuration is validated when a BMC client is created. The following checks are performed:

- `address` must be non-empty
- `port` must be between 1 and 65535
- `protocol` must be `ipmi` or `redfish`

Invalid configurations return typed errors (`bmc.ErrInvalidConfig`) with the specific field and reason.

## CLI Configuration

Create a device template with BMC settings:

```bash
platformctl device template create \
  --name "dell-r640-ipmi" \
  --bmc-address "10.10.0.101" \
  --bmc-port 623 \
  --bmc-username "admin" \
  --bmc-password "vault://bmc/dell-r640-001" \
  --bmc-protocol "ipmi"
```

Create a profile from the template:

```bash
platformctl device template create-profile \
  --template-id 1 \
  --serial "DELL-R640-001" \
  --bmc-address "10.10.0.101"
```
