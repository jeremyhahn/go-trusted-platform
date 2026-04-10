# Device Templates

## Overview

The Device Template system provides reusable reference architecture configurations
for deploying go-trusted-platform on specific hardware. The workflow is:

1. **Templates** -- Filesystem-based YAML configs organized by vendor/model/role.
   These contain complete, working configurations with sensible defaults.
2. **Overrides** -- Optional YAML files containing only site-specific values
   (hostnames, IPs, serials, credentials). Merged on top of the template.
3. **Device Configs** -- The final merged result used to build ISOs and provision nodes.

Templates are designed to be version-controlled and shared across deployments.
Overrides keep per-site secrets and addressing out of the shared templates.

## Shipped Templates

Templates are located at `configs/platform/templates/` and follow the structure:

```
configs/platform/templates/
  vendor/
    model/
      control-plane.yaml
      gateway.yaml
      compute.yaml
```

### Available Templates

| Vendor | Model | Roles | Status |
|--------|-------|-------|--------|
| Supermicro | X10SDV-TP8F | control-plane, gateway, compute | Production |
| Dell | PowerEdge R640 | control-plane, gateway, compute | Placeholder |

## Quick Start

### Deploy with template defaults

```bash
platformctl iso create \
  --platform-config configs/platform/templates/supermicro/x10sdv-tp8f/control-plane.yaml
```

### Deploy with overrides (production)

```bash
platformctl iso create \
  --platform-config configs/platform/templates/supermicro/x10sdv-tp8f/control-plane.yaml \
  --overrides /path/to/my-overrides.yaml
```

## Override Files

An override file uses the same YAML structure as a template but only includes
the fields you want to change. All other values are inherited from the template.

### Example Override

```yaml
os:
  hostname: cp-01

network:
  interfaces:
    - name: eth0
      type: dhcp

tpm:
  idevid:
    serial: MY-SERIAL-001
```

### Common Override Fields

| Field | Description |
|-------|-------------|
| `os.hostname` | Per-node hostname |
| `network.*` | Site-specific IPs, nameservers, interfaces |
| `tpm.idevid.serial` | Actual chassis serial number |
| `domain` | Your domain name |
| `hostmaster` | SOA contact email |
| All `password:` fields | Replace placeholder credentials |
| NIC interface names | Match actual hardware (`ip link`) |
| `webservices[].sans` | DNS SANs for TLS certificates |

## Custom Templates Directory

Use `--templates-dir` to point at your own templates directory:

```bash
platformctl iso create \
  --templates-dir /path/to/my-templates \
  --platform-config my-templates/vendor/model/role.yaml \
  --overrides site-overrides.yaml
```

On `platformd --init`, templates from the configured directory are imported
into QuicBaaS, making them available through the API and web UI for
profile creation and management.

## Secret URI Schemes

Templates use URI schemes for all password and PIN fields instead of literal
values. This allows templates to be safely version-controlled and shared
without exposing secrets.

| Scheme | Example | Description |
|--------|---------|-------------|
| `autogen://` | `autogen://32/base64` | Generate random bytes at first boot |
| `kms://` | `kms://platform/secrets/luks-passphrase` | Resolve from QuicBaaS KMS |
| `encrypted://` | `encrypted://base64data` | Decrypt using the device IDevID certificate |

### autogen://

The `autogen://` scheme generates cryptographically random values during
first-boot provisioning. The URI path specifies length and encoding:

- `autogen://32/base64` -- 32 random bytes, base64-encoded. Used for
  passphrases, LUKS keys, and other high-entropy secrets.
- `autogen://6/numeric` -- 6-digit numeric PIN. Used for TPM SO-PIN and
  user-PIN fields.

### kms://

The `kms://` scheme resolves a secret by path from the QuicBaaS KMS. This
is the steady-state scheme after bootstrap completes and secrets have been
migrated into the KMS. Templates never ship with `kms://` URIs; they are
written into the config automatically after migration.

### encrypted://

The `encrypted://` scheme contains base64-encoded ciphertext that is
decrypted using the device's IDevID certificate private key. This is used
for secrets delivered to a specific device during provisioning, ensuring
only the intended hardware can decrypt them.

## Bootstrap Secrets Lifecycle

Secrets follow a defined lifecycle from template to KMS-managed storage:

1. **First boot** -- The provisioning system resolves all `autogen://` URIs
   in the merged config to random values. No secrets exist on disk or in the
   KMS at this point.
2. **TPM and KMS initialization** -- The generated values are used to
   initialize the TPM (SO-PIN, user-PIN) and seed the local KMS keystore.
3. **KMS migration** -- Secrets are stored into QuicBaaS KMS under
   well-known paths derived from the device identity.
4. **Config rewrite** -- The on-disk config file is updated, replacing
   resolved literal values with `kms://` references pointing to the KMS
   paths where each secret now lives.
5. **Subsequent boots** -- The platform loads secrets from the KMS using
   the `kms://` URIs. The original `autogen://` values are never stored
   in plaintext on disk after migration completes.

This lifecycle ensures that templates remain free of secrets, generated
values have a minimal exposure window, and all secrets converge into the
KMS as the single source of truth.

## BMC Configuration

Templates include a `bmc:` section that describes the baseboard management
controller for the hardware model. This enables automated lifecycle
management including power control, firmware updates, and reimaging through
IPMI 2.0 RMCP+ and Redfish APIs.

```yaml
bmc:
  address: autogen://0/placeholder
  username: ADMIN
  password: autogen://32/base64
  protocol: redfish
```

Template BMC credentials are placeholders. Override them with real BMC
credentials in your private override file:

```yaml
bmc:
  address: 10.0.1.100
  username: admin
  password: "your-bmc-password"
```

With BMC credentials in place, the platform can:

- Power-cycle nodes for reimaging without physical access.
- Mount virtual media for PXE-free OS installation.
- Monitor hardware health sensors and thermal state.
- Trigger self-healing by automatically rebuilding failed nodes from
  their stored deployment profile.

## Platform PINs

Templates include `platform.so-pin` and `platform.user-pin` fields using
the `autogen://6/numeric` scheme:

```yaml
platform:
  so-pin: "autogen://6/numeric"
  user-pin: "autogen://6/numeric"
```

These PINs are generated automatically during first-boot provisioning.
There is no need to pass PINs on the command line or store them in override
files. After bootstrap, PINs are migrated to the KMS along with all other
secrets and the config is rewritten with `kms://` references.

## Bootstrap Integration

The `bootstrap.yaml` file references templates by role and applies per-node
overrides automatically during fleet provisioning:

```yaml
nodes:
  - hostname: cp-01
    role: control-plane
    template: supermicro/x10sdv-tp8f/control-plane.yaml
    overrides:
      os:
        hostname: cp-01
      network:
        interfaces:
          - name: eno1
            address: 10.0.1.10/24

  - hostname: gw-01
    role: gateway
    template: supermicro/x10sdv-tp8f/gateway.yaml
    overrides:
      os:
        hostname: gw-01
```

## Automation

The platform API supports creating deployment profiles from templates
combined with overrides. This enables:

- **Self-healing** -- Nodes that fail reprovisioning can be rebuilt from
  their stored profile without manual intervention.
- **Fleet scaling** -- New nodes of a given role are provisioned by
  applying the role template with node-specific overrides.
- **Audit trail** -- Every deployed configuration traces back to a
  versioned template plus a set of overrides.

Profiles are stored in QuicBaaS and accessible via all platform protocols
(REST, gRPC, QUIC, MCP, Unix socket).
