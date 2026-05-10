# CLI Reference

The Trusted Platform provides three command-line binaries:

| Binary | Purpose | Documentation |
|--------|---------|---------------|
| `platform-initrd` | Initramfs boot operations (LUKS unlock, recovery) | [platform-initrd.md](platform-initrd.md) |
| `platformd` | Platform daemon providing all services | [platformd.md](platformd.md) |
| `platformctl` | CLI client for interacting with platformd | [platformctl.md](platformctl.md) |

## Installation

### Build from Source

```bash
# Build all binaries
make build

# Build individual binaries
make platformd
make platformctl
make platform-initrd

# Install system-wide
sudo make install
```

### Binary Locations

After installation:
- `/usr/local/bin/platform-initrd` (~22MB)
- `/usr/local/bin/platformd` (~65MB)
- `/usr/local/bin/platformctl` (~52MB)

## Quick Start

### Start the Platform Daemon

```bash
# Initialize and start with default config
platformd serve --init

# Start with custom config
platformd serve --config /etc/platformd/config.yaml

# Start in debug mode
platformd serve --debug
```

### Use the Client CLI

```bash
# Check platform status
platformctl status

# View health
platformctl health --detailed

# TPM operations
platformctl tpm info
platformctl tpm provision

# Certificate Authority
platformctl ca list
platformctl ca sign --csr request.csr

# Key Management
platformctl kms key list
platformctl kms secrets list
```

## Configuration

### platformctl Configuration

The client stores configuration in `~/.config/platformctl/config.yaml`:

```yaml
current-context: local
contexts:
  - name: local
    type: local
    local:
      socket-path: /run/platformd.sock
  - name: remote
    type: remote
    remote:
      server: https://platform.example.com:8443
      ca-cert: /path/to/ca.crt
      client-cert: /path/to/client.crt
      client-key: /path/to/client.key
```

### platformd Configuration

The daemon reads configuration from `/etc/platformd/config.yaml` by default.

## Global Options

All commands support these global options:

| Option | Short | Description |
|--------|-------|-------------|
| `--help` | `-h` | Display help |
| `--debug` | `-d` | Enable debug logging |
| `--config` | `-c` | Path to config file |

### platformctl Connection Options

| Option | Description |
|--------|-------------|
| `--context` | Context to use (overrides current-context) |
| `--server` | Server address override (implies remote context). Default: gRPC over `/run/platformd.sock` when omitted, gRPC TCP against the address when set |
| `--server-name` | TLS SNI / certificate verification hostname override |
| `--transport` | Transport protocol override: `unix`, `grpc`, `rest`, `quic`, `mcp`, `embedded`. Default: `grpc` over the Unix socket (or `grpc` TCP when `--server` is set) |
| `--output`, `-o` | Output format: `table`, `json`, `yaml` |
| `--verbose`, `-v` | Verbose output |
| `--no-color` | Disable colored output (also honors `NO_COLOR`) |

The corresponding environment variables (`PLATFORMCTL_CONFIG`,
`PLATFORMCTL_CONTEXT`, `PLATFORMCTL_SERVER`, `PLATFORMCTL_SERVER_NAME`,
`PLATFORMCTL_TRANSPORT`, `PLATFORMCTL_OUTPUT`) follow kubectl precedence:
flag > env > config file > built-in default.

See [global-flags.md](global-flags.md) for the authoritative reference.

## Shell Completion

Generate shell completion scripts:

```bash
# Bash
platformctl completion bash > /etc/bash_completion.d/platformctl

# Zsh
platformctl completion zsh > "${fpath[1]}/_platformctl"

# Fish
platformctl completion fish > ~/.config/fish/completions/platformctl.fish
```

## Documentation

- [platform-initrd Reference](platform-initrd.md) - Boot binary for initramfs
- [platformctl Reference](platformctl.md) - Client CLI commands
- [platformd Reference](platformd.md) - Daemon commands and options
- [Man Pages](../man/) - Detailed command documentation
- [Binary Architecture](../architecture/binary-separation.md) - Three-binary architecture details
