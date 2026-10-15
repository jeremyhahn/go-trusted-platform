# Device Templates

> **Status: REFERENCE**
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

### CLI

```bash
# Create from a YAML config file
platformctl device template create --name "edge-server-v1" \
  --role server \
  --config /path/to/platform-config.yaml

# List templates
platformctl device template list

# Get template details
platformctl device template get --id 1
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
    "config": { ... }
  }'

# List templates
curl https://platform:8443/api/v1/device/templates

# Get template
curl https://platform:8443/api/v1/device/templates/1
```

### Web UI

Navigate to **Devices > Templates** to manage templates through the web interface.

## Creating Profiles from Templates

```bash
# Create profile from template with overrides
platformctl device template to-profile --id 1 \
  --ek-serial "ABC123DEF456" \
  --hostname "edge-01.example.com" \
  --ip "10.0.1.100/24"
```

### REST API

```bash
curl -X POST https://platform:8443/api/v1/devices/templates/1/create-profile \
  -H "Content-Type: application/json" \
  -d '{
    "ek_serial": "ABC123DEF456",
    "mac_address": "52:54:00:12:34:56",
    "overrides": {
      "hostname": "edge-01.example.com"
    }
  }'
```

## vTPM Integration

When generating a vTPM bundle for a profile, the EK certificate serial number is automatically extracted and assigned to the profile. This makes the profile discoverable during boot.

```bash
# Generate vTPM bundle for profile (EK serial auto-assigned)
platformctl vtpm generate --profile-id 5

# The profile is now discoverable by EK serial at boot time
```

## Configuration Structure

Templates use the standard `app.App` configuration structure which includes:

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
| `bootstrap` | Trust bootstrap (Noise, DANE) |
