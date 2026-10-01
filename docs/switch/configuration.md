# Switch Configuration Guide

## Platform Configuration

The switch management feature is configured via the platform daemon's main config file. Add a `switches:` section to your platform config YAML.

### Basic Configuration Structure

```yaml
switches:
  - name: switch-identifier
    vendor: cisco-nexus
    host: 10.0.1.50
    port: 22
    user: admin
    password: kms://my-secret-ref
    vlans:
      - id: 100
        name: provisioning
        subnet: 192.168.100.0/24
      - id: 200
        name: production
        subnet: 203.0.113.0/24
    ports:
      - port: Eth1/1-10
        mode: access
        access_vlan: 100
```

## Configuration Fields

### Root Switch Object

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | Yes | - | Unique identifier for this switch (used in APIs and logs). If not provided, `host` is used as fallback. |
| `vendor` | string | Yes | - | Switch platform: `cisco-nexus`, or `noop` for testing. |
| `host` | string | Yes | - | IP address or hostname of the switch. |
| `port` | int | No | 22 | SSH port for remote access. |
| `user` | string | Yes | - | SSH username for authentication. |
| `password` | string | Conditional* | - | SSH password. Use `kms://ref` to reference platform secrets. Not required if `ssh_key` is provided. |
| `ssh_key` | string | Conditional* | - | Path to SSH private key file (e.g., `/etc/certs/switch.key`). Not required if `password` is provided. |
| `vlans` | array | No | [] | VLANs to create during initial setup (informational for runtime). |
| `ports` | array | No | [] | Port configurations for initial setup (informational for runtime). |

*Conditional: Either `password` or `ssh_key` must be provided (or both).

### VLANConfig Object

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `id` | int | Yes | - | VLAN ID (1-4094). |
| `name` | string | Yes | - | VLAN name (for switch configuration). |
| `subnet` | string | No | - | IP subnet in CIDR notation (informational, stored for reference). |
| `description` | string | No | - | Optional description of the VLAN's purpose. |

### PortConfig Object

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `port` | string | Yes | - | Port identifier(s). Examples: `Eth1/1`, `Eth1/3-5`, `Po1`. Ranges supported on vendors that allow it. |
| `mode` | string | Yes | - | Port mode: `access` or `trunk`. |
| `vlans` | array | No | - | VLAN IDs allowed on trunk ports. Required if `mode: trunk`. |
| `access_vlan` | int | No | - | VLAN ID for access ports. Required if `mode: access`. |
| `native_vlan` | int | No | 0 (none) | Native (untagged) VLAN of a trunk. Must be one of `vlans`; only a trunk has one. A hypervisor-class port uses the environment's `provisioning` VLAN. |
| `mtu` | int | No | 0 (leave as is) | Port MTU, 1500–9216. Platform ports run 9216 so VXLAN never fragments. |
| `description` | string | No | - | Port description (e.g., "Server-01" or "Uplink"). |

`GeneratePortCommands` validates every port with `ValidatePortConfig` before
emitting any command; an invalid port fails with `ErrPortConfigFailed` naming
the port. In a bootstrap run these fields are not written by hand: the switch
phase derives them from each port's class ([switch management](../bootstrap/switch-management.md)).

## Examples

### Example 1: Single Cisco Nexus Switch (SSH Key Auth)

```yaml
switches:
  - name: core-switch-01
    vendor: cisco-nexus
    host: 10.0.1.50
    port: 22
    user: automation
    ssh_key: /etc/certs/automation.key
    vlans:
      - id: 100
        name: provisioning
        subnet: 192.168.100.0/24
        description: "Device provisioning VLAN"
      - id: 200
        name: production
        subnet: 203.0.113.0/24
        description: "Production devices"
    ports:
      - port: Eth1/1
        mode: access
        access_vlan: 100
        description: "Provisioning port A"
      - port: Eth1/2
        mode: access
        access_vlan: 100
        description: "Provisioning port B"
      - port: Eth1/3-10
        mode: access
        access_vlan: 100
        description: "Provisioning rack 1 (8 ports)"
      - port: Eth1/48
        mode: trunk
        vlans: [100, 200]
        description: "Uplink to distribution switch"
```

### Example 2: Multiple Switches with Encrypted Password

```yaml
switches:
  - name: access-switch-rack-1
    vendor: cisco-nexus
    host: 10.0.2.50
    user: admin
    password: kms://switch-rack-1-password
    vlans:
      - id: 100
        name: provisioning
        subnet: 192.168.100.0/24
      - id: 200
        name: production
        subnet: 203.0.113.0/24
    ports:
      - port: Eth1/1-48
        mode: access
        access_vlan: 100

  - name: access-switch-rack-2
    vendor: cisco-nexus
    host: 10.0.3.50
    user: admin
    password: kms://switch-rack-2-password
    vlans:
      - id: 100
        name: provisioning
        subnet: 192.168.100.0/24
      - id: 200
        name: production
        subnet: 203.0.113.0/24
    ports:
      - port: Eth1/1-48
        mode: access
        access_vlan: 100
```

### Example 3: Cisco IOS Device (IOS-XE)

Cisco IOS uses slightly different port naming but the same CLI commands:

```yaml
switches:
  - name: catalyst-switch
    vendor: cisco-nexus  # Same vendor (IOS-compatible CLI)
    host: 10.0.1.60
    user: admin
    ssh_key: /etc/certs/catalyst.key
    vlans:
      - id: 100
        name: provisioning
        subnet: 192.168.100.0/24
      - id: 200
        name: production
        subnet: 203.0.113.0/24
    ports:
      - port: GigabitEthernet1/0/1
        mode: access
        access_vlan: 100
      - port: GigabitEthernet1/0/2-48
        mode: access
        access_vlan: 100
      - port: TenGigabitEthernet1/1/1
        mode: trunk
        vlans: [100, 200]
```

### Example 4: Testing with No-op Manager

For development/testing without physical switches:

```yaml
switches:
  - name: test-switch
    vendor: noop
    # No host/user/password required for noop vendor
```

## Authentication

### SSH Key Authentication (Recommended)

```yaml
switches:
  - name: switch-01
    vendor: cisco-nexus
    host: 10.0.1.50
    user: automation
    ssh_key: /etc/certs/switch.key  # PEM format, must exist
```

**Key Requirements:**
- File must be readable by the platform daemon process
- Supported formats: RSA, ED25519, ECDSA (standard PEM format)
- Permissions: `0600` (read-only by owner)
- Example: `ssh-keygen -t ed25519 -f /etc/certs/switch.key -N ""`

### Password Authentication

```yaml
switches:
  - name: switch-01
    vendor: cisco-nexus
    host: 10.0.1.50
    user: admin
    password: "kms://switch-admin-secret"
```

**Plaintext passwords are not recommended in config files.** Use the `kms://` prefix to reference secrets stored in the platform KMS (described below).

### Encrypted Password References

Passwords can reference KMS-managed secrets using the `kms://` scheme:

```yaml
password: kms://my-secret-name
```

The platform resolves the secret at startup:
- Looks up the secret named `my-secret-name` from its secret store
- Decrypts using platform KMS
- Provides the plaintext to SSH authenticator
- Never logs the plaintext password

**To store a switch password:**
```bash
# Use platform CLI (if available)
platformctl secrets set switch-admin-secret "your-password-here"

# Or via REST API
curl -X POST https://platform:8443/secrets \
  -H "Content-Type: application/json" \
  -d '{"name": "switch-admin-secret", "value": "your-password-here"}'
```

## Startup Behavior

When the platform daemon starts:

1. **Load config** from YAML file
2. **Validate** switch configurations:
   - Check required fields (name, vendor, host, user)
   - Check SSH auth (password or ssh_key)
   - Check host is reachable (on first use, not at startup)
3. **Create Service** with all switches (if any configured)
4. **Lazy SSH connections**:
   - SSH connection not established at startup
   - Connected on first Manager method call
   - Kept open for subsequent calls
   - Closed when Service is destroyed (shutdown)

**If no switches configured:**
- Switch Service is not created
- Device activation works fine (VLAN transition is a no-op)
- Useful for small deployments without managed switches

## Port Naming Conventions

Port names vary by platform. Use the names your switch reports:

### Cisco Nexus / IOS-XE
- `Eth1/1`, `Eth1/48`: 10/100/1000 interfaces
- `Eth1/1-48`: Port range
- `Eth2/1`: Multi-slot chassis
- `Po1`: Port channel (LAG)

### Cisco IOS Catalyst
- `GigabitEthernet1/0/1`, `GigabitEthernet1/0/48`
- `FastEthernet1/0/1`: Older models
- `TenGigabitEthernet1/1/1`: Uplink
- `Port-channel1`: LAG

### Arista EOS (Coming Soon)
- `Ethernet1`, `Ethernet48`: Standard
- `Ethernet1-48`: Port range
- `Port-Channel1`: LAG

To find your switch's port names, SSH in and run:
```
show interfaces status
show interfaces brief
```

## Validation

Platform validates switch configurations at startup:

```go
// Required fields
if config.Host == "" { return ErrInvalidConfig{Field: "host", ...} }
if config.User == "" { return ErrInvalidConfig{Field: "user", ...} }

// SSH auth (one of these required)
if config.SSHKey == "" && config.Password == "" {
    return ErrInvalidConfig{Field: "ssh_key", Reason: "either ssh_key or password must be provided"}
}

// VLAN range (informational)
for _, vlan := range config.VLANs {
    if vlan.ID < 1 || vlan.ID > 4094 {
        return ErrInvalidConfig{Field: "vlans.id", ...}
    }
}

// Port range parsing (validated on use)
// Examples: "Eth1/1" (single), "Eth1/1-10" (range), "Eth1/1,Eth1/3" (list)
```

## Troubleshooting

### "unsupported vendor"
- Check vendor name in config (case-sensitive): `cisco-nexus`, `noop`
- Ensure switch package is imported in daemon

### "ssh connection failed"
- Verify host/port: `ssh -p 22 admin@10.0.1.50`
- Check SSH key permissions: `ls -la /etc/certs/switch.key`
- Verify user exists on switch: `show users`

### "command failed"
- Common on untrusted first connection: Check host key verification
- Port naming mismatch: Run `show interfaces status` on switch to see names
- VLAN doesn't exist: Ensure VLAN 200 is created before SetPortVLAN

### "port not found"
- Verify port name format for your switch model
- Some switches use `Ethernet1/1` vs `Eth1/1`
- Check if port is physically present and not disabled

### Debugging

Enable debug logging in daemon config:

```yaml
logging:
  level: debug
```

Switch operations will log:
```
DEBUG switchmgmt: ssh set port vlan command="configure terminal"
DEBUG switchmgmt: ssh set port vlan command="interface Eth1/3"
DEBUG switchmgmt: ssh set port vlan command="switchport mode access"
```

## Migration from Manual Configuration

If you currently manage switches manually:

1. **Export existing VLANs** from your switch (`show vlan brief`)
2. **List port configurations** (`show run | include switchport`)
3. **Add to platform config** (vlans and ports sections)
4. **Test with noop vendor** first (no actual changes)
5. **Deploy to production** with real vendor once verified

## Security Best Practices

1. **Use SSH keys**: Stronger than passwords, no typos
2. **Limit SSH user privileges**: Use read-only user if only querying status
3. **Network isolation**: Place switches on isolated management VLAN
4. **Audit logging**: Keep audit logs of who made changes
5. **Encryption at rest**: Encrypt SSH key files on filesystem
6. **Encryption in transit**: Always use SSH (port 22), never Telnet
7. **Secret rotation**: Rotate SSH keys and passwords regularly

## Performance Tuning

### Connection Timeout
SSH connections default to standard OS timeouts (usually 5-30 seconds). No configuration needed.

### Batch Operations
Currently, each SetPortVLAN is one command set. For moving many ports:
```go
// Instead of:
for _, port := range ports {
    mgr.SetPortVLAN(ctx, port, 200)  // N SSH commands
}

// Consider calling SetPortVLAN in parallel:
for _, port := range ports {
    go mgr.SetPortVLAN(ctx, port, 200)  // Concurrent requests
}
```

### Output Parsing
SSH output parsing uses regex (no external parsers). Performance is negligible unless parsing thousands of ports.
