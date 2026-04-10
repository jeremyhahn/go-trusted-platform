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
