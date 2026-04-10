# platformctl Reference

`platformctl` is the command-line interface for managing and interacting with the Trusted Platform. It connects to `platformd` via Unix socket (local) or HTTPS with mTLS (remote).

## Synopsis

```
platformctl [command] [options]
```

## Commands

### status

Display the current status of the Trusted Platform and its services.

```bash
platformctl status
platformctl status -o json
```

Output includes:
- System status (READY, INITIALIZING, DEGRADED, UNAVAILABLE)
- Platform info (hostname, version, FIPS mode)
- System info (OS, architecture, memory, uptime)
- TPM info (version, manufacturer, firmware)
- Running services

### health

Display the health status of the platform and components.

```bash
# Basic health check
platformctl health

# Detailed component health
platformctl health --detailed
platformctl health -d
```

| Option | Description |
|--------|-------------|
| `--detailed`, `-d` | Show detailed component health |

### version

Display version information for client and server.

```bash
# Show client and server versions
platformctl version

# Show client version only
platformctl version --client
```

| Option | Description |
|--------|-------------|
| `--client` | Show client version only |

### service

Manage platform services. Services include: tpm, sdn, compute, dns, acme, webservice, attestation.

#### service list

List all services and their status.

```bash
platformctl service list
platformctl service list -o json
```

#### service status

Get detailed status of a specific service.

```bash
platformctl service status tpm
platformctl service status webservice
```

#### service start

Start a platform service.

```bash
platformctl service start webservice
platformctl service start dns
```

#### service stop

Stop a platform service.

```bash
# Graceful stop
platformctl service stop webservice

# Force stop with timeout
platformctl service stop webservice --force --timeout 10
```

| Option | Description |
|--------|-------------|
| `--force`, `-f` | Force stop the service |
| `--timeout`, `-t` | Timeout in seconds (default: 30) |

#### service restart

Restart a platform service.

```bash
platformctl service restart webservice
platformctl service restart dns --timeout 60
```

| Option | Description |
|--------|-------------|
| `--timeout`, `-t` | Timeout in seconds (default: 30) |

### config

Manage platform configuration.

#### config get

Get platform configuration.

```bash
# Get all configuration
platformctl config get

# Get specific section
platformctl config get tpm
platformctl config get webservice
```

#### config set

Set configuration values.

```bash
# Set values (runtime only)
platformctl config set webservice port=8443 tls=true

# Set and persist to disk
platformctl config set webservice port=8443 --persist
```

| Option | Description |
|--------|-------------|
| `--persist`, `-p` | Persist changes to disk |

#### config reload

Reload configuration from disk.

```bash
platformctl config reload
```

### context

Manage connection contexts for local and remote platform connections.

#### context list

List all configured contexts.

```bash
platformctl context list
```

#### context current

Show the currently active context.

```bash
platformctl context current
```

#### context use

Switch to a different context.

```bash
platformctl context use remote
platformctl context use local
```

#### context add

Add a new connection context.

```bash
# Add local context
platformctl context add local-dev --type local --socket-path /run/platformd.sock

# Add remote context with mTLS
platformctl context add production \
  --type remote \
  --server https://platform.example.com:8443 \
  --ca-cert /path/to/ca.crt \
  --client-cert /path/to/client.crt \
  --client-key /path/to/client.key

# Add remote context for development (requires CA cert)
platformctl context add dev-remote \
  --type remote \
  --server https://localhost:8443 \
  --ca-cert /path/to/ca.crt
```

| Option | Description |
|--------|-------------|
| `--type`, `-t` | Context type: local or remote |
| `--socket-path` | Unix socket path (local contexts) |
| `--server` | Server address (remote contexts) |
| `--ca-cert` | CA certificate path |
| `--client-cert` | Client certificate path |
| `--client-key` | Client key path |
| `--ca-cert` | CA certificate for server verification |

#### context delete

Delete a connection context.

```bash
platformctl context delete old-context
```

### db

Database operations for QuicBaaS datastore management.

#### db list

List all partitions (entity types) and their entity counts.

```bash
platformctl db list
platformctl db list --config-dir /etc/trusted-platform
```

Known partitions:
- `organizations` - User organizations
- `users` - User accounts
- `registrations` - Registration requests
- `roles` - User roles
- `webauthn` - WebAuthn credentials
- `devices` - Registered devices
- `devices/profiles` - Device profiles
- `dns/zones` - DNS zones
- `blob` - Binary large objects

Example output:
```
QuicBaaS Partitions (/etc/trusted-platform/datastore)
------------------------------------------------------------
PARTITION          COUNT   STATUS
organizations      1       active
users              3       active
registrations      0       empty
roles              2       active
webauthn           0       empty
devices            1       active
devices/profiles   0       empty
dns/zones          5       active
blob               0       empty
------------------------------------------------------------
Total: 12 entities across 5 active partitions
```

#### db dump

Export QuicBaaS data to JSON or YAML files.

```bash
# Dump all data to JSON files
platformctl db dump --output ./backup

# Dump with pretty printing
platformctl db dump --output ./backup --pretty

# Dump only DNS zones
platformctl db dump --output ./backup --partition dns/zones

# Dump to YAML format
platformctl db dump --output ./backup --format yaml

# Use a specific config directory
platformctl db dump --output ./backup --config-dir /etc/trusted-platform
```

| Option | Description |
|--------|-------------|
| `--output`, `-o` | Output directory for exported files (default: `./quicbaas-dump`) |
| `--format`, `-f` | Output format: `json` or `yaml` (default: `json`) |
| `--partition`, `-p` | Filter by partition (e.g., `dns/zones`, `users`) |
| `--pretty` | Pretty print output with indentation |
| `--config-dir` | Platform configuration directory |

Output structure:
```
<output>/
  organizations/
    1.json
    2.json
  users/
    1.json
    2.json
  dns/
    zones/
      1.json
```

### firstboot

Perform first-boot TPM PCR sealing after system installation.

This command runs after `switch_root` when the real filesystem is mounted. It reads the LUKS key from the installer container and seals it to the TPM with PCR policy for secure automatic boot unlocking.

```bash
# Run firstboot with automatic LUKS device detection
platformctl firstboot

# Run firstboot with explicit LUKS device
platformctl firstboot --luks-device /dev/sda2

# Run firstboot with TPM-only mode (removes password keyslot)
platformctl firstboot --luks-device /dev/sda2 --tpm-only

# Run firstboot with custom PCR selection
platformctl firstboot --pcrs 0,1,2,3,7
```

| Option | Description |
|--------|-------------|
| `--luks-device` | LUKS device path (auto-detect if not specified) |
| `--tpm-auto-unseal` | Enable TPM auto-unseal (default: true) |
| `--tpm-only` | Remove password keyslot after sealing (TPM-only unlock) |
| `--swtpm-state-dir` | swtpm state directory (default: /var/lib/swtpm) |
| `--efi-mount` | EFI partition mount point (default: /boot/efi) |
| `--pcrs` | PCR registers to seal against (reads from config if not specified) |
| `--config` | Platform configuration file |
| `--tpm-path` | TPM device path (default: /dev/tpmrm0) |
| `--xkms-dir` | XKMS storage directory |
| `--fips` | Enable FIPS mode |
| `--verbose, -v` | Enable verbose logging |
| `--debug` | Enable debug logging |

The command performs:
- Platform TPM provisioning (EK, SRK, IAK, IDevID)
- LUKS key extraction from encrypted installer container
- TPM sealing with PCR policy for boot integrity verification
- Cleanup of plain key files for security
- Installation and enablement of platformd service

This command is typically called by a systemd service or OpenRC init script after the first boot following installation.

### completion

Generate shell completion scripts.

```bash
# Bash
platformctl completion bash

# Zsh
platformctl completion zsh

# Fish
platformctl completion fish

# PowerShell
platformctl completion powershell
```

## Output Formats

Use `--output` or `-o` to change output format:

```bash
# Table format (default)
platformctl status

# JSON format
platformctl status -o json

# YAML format
platformctl status -o yaml
```

## Examples

### Monitor Platform Health

```bash
# Quick health check
platformctl health

# Watch service status
watch -n 5 'platformctl service list'
```

### Manage Services

```bash
# Start all web services
platformctl service start webservice

# Restart with timeout
platformctl service restart dns --timeout 60

# Check specific service
platformctl service status attestation
```

### Multi-Environment Setup

```bash
# Add production context
platformctl context add prod \
  --type remote \
  --server https://prod.example.com:8443 \
  --ca-cert /etc/platformctl/prod-ca.crt \
  --client-cert /etc/platformctl/client.crt \
  --client-key /etc/platformctl/client.key

# Switch to production
platformctl context use prod

# Check production status
platformctl status

# Switch back to local
platformctl context use local
```

### Scripting

```bash
#!/bin/bash
# Check platform is healthy before deployment

status=$(platformctl health -o json | jq -r '.status')
if [ "$status" != "HEALTH_STATUS_HEALTHY" ]; then
    echo "Platform unhealthy: $status"
    exit 1
fi

echo "Platform healthy, proceeding..."
```

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | General error |

## See Also

- [platformd Reference](platformd.md)
- [CLI Overview](README.md)
