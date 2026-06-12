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

Templates are located at `configs/platform/templates/` and organized first by
deployment profile, then by vendor and hardware model:

```
configs/platform/templates/
  dedicated/          # 3-node: 1 CP + 1 GW + 1 compute (active)
    README.md         ← profile architecture + operational contract
    vendor/
      model/
        control-plane.yaml
        gateway.yaml
        compute.yaml
  single-node/        # All-in-one (CP + GW + compute on one box)
    README.md
    default.yaml
  high-availability/  # HA cluster (planned)
```

Each profile directory has its own `README.md` describing the topology,
role responsibilities, bond/bridge layout, DNS strategy, and the
expected override precedence. When a template shape changes, the
profile's README is updated in the same commit so it stays the
single source of truth for the profile's contract. See
[`configs/platform/templates/dedicated/README.md`](../configs/platform/templates/dedicated/README.md)
for the current production reference.

### Deployment Profiles

| Profile | Layout | Status |
|---------|--------|--------|
| `dedicated` | 3 dedicated nodes: 1 CP, 1 GW, 1 compute | **Active** |
| `single-node` | CP + GW + compute colocated on one node | Planned |
| `high-availability` | 3 CP, 2 GW, 2 compute with Raft consensus | Planned |

### Available Templates

| Vendor | Model Family | Profile | Roles | Status |
|--------|--------------|---------|-------|--------|
| Supermicro | X10 (X10SDV-TP8F, etc.) | dedicated | control-plane, gateway, compute | Production |
| Dell | PowerEdge R640 | dedicated | control-plane, gateway, compute | Phase 2 (UNTESTED) |

## Quick Start

### Default ISO (no flags — single-node)

```bash
platformctl iso create
```

With no flags, `iso create` uses the single-node template at
`configs/platform/templates/single-node/default.yaml` and bakes the
merged config into the ISO. This matches the reference-architecture
single-node deployment (CP + GW on one box) documented in
`docs/architecture/deployment-reference.md` §1.

### Deploy with a specific role template (baked into ISO)

```bash
platformctl iso create \
  --platform-config configs/platform/templates/dedicated/supermicro/x10/control-plane.yaml
```

### Deploy with overrides (template + site-specific overrides, baked)

```bash
platformctl iso create \
  --platform-config configs/platform/templates/dedicated/supermicro/x10/control-plane.yaml \
  --overrides /path/to/my-overrides.yaml
```

### Shared ISO with dynamic per-node config (multi-node bootstrap)

```bash
platformctl iso create \
  --config-server http://deployer.lan:8080/config/mac
```

In this mode the ISO carries only a kernel cmdline pointer to the
pxeboot HTTP config server. Per-node merged configs are published
by the bootstrap orchestrator keyed by MAC address. A single ISO
installs CP, GW, and compute correctly. See
`docs/bootstrap/config-delivery.md` for the full flow.

### Hybrid (dynamic preferred, baked as fallback)

```bash
platformctl iso create \
  --config-server http://deployer.lan:8080/config/mac \
  --platform-config configs/platform/templates/single-node/default.yaml
```

Useful when the config server might be unreachable at install time —
the baked config acts as a safety net.

---

## Delivery Modes

| Mode | Flags | Config location | When to use |
|------|-------|-----------------|-------------|
| **Default baked** | (none) | ISO: `/media/cdrom/configs/installer.yaml` | Single-node deploys |
| **Custom baked** | `--platform-config [--overrides]` | ISO | Per-role ISOs in multi-node |
| **Dynamic** | `--config-server URL` | Orchestrator HTTP `/config/mac/<mac>/installer.yaml` | Fleet bootstrap, shared ISO |
| **Hybrid** | `--config-server URL --platform-config X` | Dynamic with baked fallback | Multi-node with unreliable config-server reach |

See `docs/architecture/bootstrap-flow.md` §3 for the install-time
priority chain that picks between modes.

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
| `kms://` | `kms://<path>?ensure=true&len=32&enc=base64` | Canonical scheme: ensure-persist-or-fetch from QuicBaaS KMS |
| `encrypted://` | `encrypted://base64data` | Decrypt using the device IDevID certificate |

### kms:// (canonical)

The `kms://` scheme is the canonical secret URI. It identifies a secret by
path in the QuicBaaS KMS and, when the `?ensure=true` query parameter is
present, applies the Vault-style generate-on-first-boot / return-on-subsequent-boot
semantics via `SecretsService.EnsureSecret` and a distributed lock:

- `kms://ca/root/keys/0/password?ensure=true&len=32&enc=base64`
  -- ensures a 32-byte base64-encoded secret exists at the given path.
  First call generates and persists; every subsequent call returns the same
  stable bytes.
- Query parameters:
  - `ensure=true` -- opt in to the ensure semantics (generate-and-persist)
  - `len=N` -- requested byte length
  - `enc=base64` or `enc=numeric` -- encoding of the returned value
- Paths are short-form. The tenant and node identifiers are
  implicitly prepended at resolution time by
  `LocalSecretsResolver.WithIdentity`, using `platform.tenant_id` and
  the node hostname. Templates must not embed `tenants/…/nodes/…`
  literals or `{{tenant}}` / `{{node}}` placeholders.

### encrypted://

The `encrypted://` scheme contains base64-encoded ciphertext that is
decrypted using the device's IDevID certificate private key. This is used
for secrets delivered to a specific device during provisioning, ensuring
only the intended hardware can decrypt them.

## Secrets Lifecycle

Secrets follow a single unified lifecycle:

1. **Template load** -- The platform loads the merged template+overrides
   config. All `kms://?ensure=true` URIs are placeholders at this point.
2. **First boot** -- On first resolution, `SecretsService.EnsureSecret`
   takes a distributed lock on the KMS path, generates a random value per
   the URI spec (`len`, `enc`), persists it in the QuicBaaS KMS, and
   returns the generated bytes.
3. **Subsequent boots** -- Every future resolution returns the same stored
   bytes -- the URI becomes fully deterministic after first use.
4. **Rotation** -- Delete the KMS path (or use a rotation API) to force
   regeneration on next boot.

This unified model replaces the older `autogen://` + migration pattern --
secrets are born in the KMS and stay there, with no intermediate plaintext
on-disk state.

## BMC Configuration

Templates include a `bmc:` section that describes the baseboard management
controller for the hardware model. This enables automated lifecycle
management including power control, firmware updates, and reimaging through
IPMI 2.0 RMCP+ and Redfish APIs.

```yaml
bmc:
  address: 198.18.0.1
  username: admin
  password: "kms://bmc/password?ensure=true&len=16&enc=base64"
  protocol: ipmi
```

Template BMC passwords use the canonical `kms://?ensure=` scheme so the
first provisioning run generates a random password and persists it in the
KMS. Override the `address`, `username`, and (if needed) `password` with
real values in your private override file:

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

## BMC Trust Chain (trust.bmc)

Every template that ships a `bmc:` section also ships a `trust:` section with
a `bmc:` class scope. The `trust.bmc` class configures the TLS trust chain used
when the platform connects to BMC endpoints (Redfish, IPMI-over-TLS, vendor
CGI endpoints).

### Chain ordering

All shipped templates use the canonical Phase 3 BMC trust chain:

```yaml
trust:
  bmc:
    # BMC endpoint trust chain. First strategy to succeed wins.
    # tofu is first-contact only — REMOVE it once DANE TLSA records for
    # <hostname>-bmc.<internal-zone> are published (bmc enroll does this).
    strategies: [dane, spki, ca-file, tofu]
    dane:
      dns-server: "127.0.0.1:8053"   # local or CP public DNS
```

Strategies are attempted left-to-right; the first that succeeds is used:

| Strategy | When it succeeds |
|----------|-----------------|
| `dane` | DNSSEC-validated TLSA record exists at `_443._tcp.<hostname>-bmc.<internal-zone>` |
| `spki` | A pinned SPKI SHA-256 hash matches the BMC's leaf certificate |
| `ca-file` | The BMC certificate chains to the PEM bundle at `trust.bmc.ca-file` |
| `tofu` | First connection: captures and pins the BMC leaf SPKI. Subsequent connections verify the stored pin. |

### TLSA record naming convention

BMC TLSA records are published at:

```
_443._tcp.<hostname>-bmc.<internal-zone>
```

For example, if the node hostname is `lab-node-2` and the internal zone is
`example.internal`, the TLSA record lives at:

```
_443._tcp.lab-node-2-bmc.example.internal
```

The enroll ceremony and the AutoCertManager rotation hook publish this record
automatically when BMC enrollment completes.

### Explicit-TOFU rule

TOFU is **never an implicit fallback**. It appears in the template chain
explicitly, with a comment instructing operators to remove it once DANE TLSA
records are live. The template comment reads:

> tofu is first-contact only — REMOVE it once DANE TLSA records for
> `<hostname>-bmc.<internal-zone>` are published (bmc enroll does this).

Environments where DANE TLSA records are already published can remove `tofu`
from the strategies list in their override file:

```yaml
trust:
  bmc:
    strategies: [dane, spki, ca-file]
```

### Deprecated fields

The following `bmc:` fields that provided ad-hoc TLS configuration are
deprecated and will be removed in a future release. The `trust.bmc` chain
supersedes them:

| Deprecated field | Replacement |
|-----------------|-------------|
| `bmc.skip-tls-verify` | Remove the field; use `trust.bmc` strategies instead. Never skip TLS verification. |
| `bmc.ca-cert-path` | Move the path to `trust.bmc.ca-file`; add `ca-file` to the strategies chain. |

## Platform PINs

Templates include `platform.so-pin` and `platform.user-pin` fields using
the canonical `kms://?ensure=` scheme:

```yaml
platform:
  so-pin:   "kms://platform/so-pin?ensure=true&len=8&enc=numeric"
  user-pin: "kms://platform/user-pin?ensure=true&len=6&enc=numeric"
```

These PINs are generated automatically during first-boot provisioning.
There is no need to pass PINs on the command line or store them in override
files -- `SecretsService.EnsureSecret` generates and persists them on first
resolve and returns the same stable bytes on every subsequent boot.

## Bootstrap Integration

The `bootstrap.yaml` file references templates by role and applies per-node
overrides automatically during fleet provisioning:

```yaml
nodes:
  - hostname: cp-01
    role: control-plane
    template: dedicated/supermicro/x10/control-plane.yaml
    overrides:
      os:
        hostname: cp-01
      network:
        interfaces:
          - name: eno1
            address: 10.0.1.10/24

  - hostname: gw-01
    role: gateway
    template: dedicated/supermicro/x10/gateway.yaml
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
