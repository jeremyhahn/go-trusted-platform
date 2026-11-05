# Device Templates

> **Status: REFERENCE** · Last verified: 2026-10-15
> Device templates and the profiles made from them.

Device templates are reusable configuration blueprints for device provisioning. A template contains a full platform configuration (`app.App`) that can be copied to create device profiles with device-specific customizations.

## Lifecycle

```
Device Template ──(copy + customize)──▶ Device Profile ──(assign device)──▶ Device Config
```

- **Template**: Reusable blueprint, never assigned to a device
- **Profile**: Device-specific config ready for provisioning, optionally bound to a device identity (TPM EK serial or MAC address)
- **Device Config**: A profile once a device has fetched and applied it

## Creating Templates

Use `platformctl device template`, the REST API or the web UI.

### CLI

`platformctl device template` (`pkg/cli/commands/device/template.go`) has the
verbs `create`, `get <id>`, `list`, `update <id>`, `delete <id>` and
`create-profile <template-id>`. `create` and `update` take `--name`,
`--description`, `--role` and `--config-file` (the platform config, YAML or
JSON). `create-profile` takes `--name`, `--model`, `--role`, `--zone`,
`--ek-serial`, `--mac` and `--ek-cert` as the profile overrides.

```bash
platformctl device template create --name edge-server-v1 --role server \
  --config-file platform-config.yaml
platformctl device template create-profile 1 --name edge-01 \
  --mac 52:54:00:12:34:56
```

### REST API

```bash
# Create template (singular path — POST /api/v1/devices/templates is the
# bootstrap seeder's {role, template} upload, see docs/device/api.md §4.1)
curl -X POST https://platform:8443/api/v1/device/templates \
  -H "Content-Type: application/json" \
  -d '{
    "name": "edge-server-v1",
    "description": "Edge server with TPM sealing and LUKS encryption",
    "role": "server",
    "config": "<base64 of the platform config YAML>"
  }'

# List templates
curl https://platform:8443/api/v1/device/templates

# Get template, or find it by name
curl https://platform:8443/api/v1/device/templates/1
curl https://platform:8443/api/v1/device/templates/name/edge-server-v1
```

`config` is the platform config YAML as raw bytes, so in JSON it is a base64
string (`TemplateRequest`, `pkg/webservice/v1/device/template_types.go`). The
fields may also be sent wrapped in a `template` object. `PUT` and `DELETE` on
`/api/v1/device/templates/{id}` update and delete a template.

### Web UI

Navigate to **Devices > Templates** to manage templates through the web interface.

## Creating Profiles from Templates

### REST API

```bash
curl -X POST https://platform:8443/api/v1/device/templates/1/create-profile \
  -H "Content-Type: application/json" \
  -d '{
    "overrides": {
      "name": "edge-01",
      "ek_serial": "ABC123DEF456",
      "mac_address": "52:54:00:12:34:56"
    }
  }'
```

The body is optional. `overrides` takes the device profile request fields
(`ProfileRequest`, `pkg/webservice/v1/device/types.go`); a body that does not
decode is refused with `400`. The answer is `201` with the new profile. The web
UI offers the same at **Devices > Templates > (template) > Create Profile**.

## vTPM Integration

When the compute QEMU provider starts a VM for a profile it generates the VM's
vTPM (`GeneratorService.GenerateForProfile`, `pkg/vtpm/generator.go`). The
generator binds the vTPM's EK serial and EK certificate to the profile only
when a `ProfileAssigner` is set, and no production code sets one
(`SetProfileAssigner` has no caller). Today, set `ek_serial` (and `ek_cert`) on
the profile yourself, or let config delivery match the device by MAC.

## Configuration Structure

Templates use the standard `app.App` configuration structure
(`pkg/app/app.go`), which includes:

| Section | Purpose |
|---------|---------|
| `disk` | Partitioning, LUKS encryption, LVM |
| `os` | OS type, version, packages, IMA |
| `network` | Interfaces, bridges, bonds, VLANs |
| `certificate-authority` | CA configuration |
| `dns` | DNS zones, DNSSEC |
| `webservice` | Web service, TLS, CORS |
| `tpm` | TPM configuration, PCR policy |
| `seal-pcrs` | PCR registers for LUKS sealing |
| `bootstrap` | Server-side bootstrap orchestrator (see [Bootstrap](../bootstrap/user.md)) |
| `trust` | Peer trust resolver: `trust.bootstrap`, `trust.bmc` (see `docs/trust/`) |
