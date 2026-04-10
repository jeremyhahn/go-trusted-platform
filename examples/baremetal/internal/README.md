# Trusted Platform Internal DNS Example

This example demonstrates running Trusted Platform using only internal DNS names (no public domains).

## Prerequisites

The server runs DNS on two ports:
- Public DNS: port 8053 (for external domains)
- Internal DNS: port 8054 (for .internal domains)

**Important**: These must be different ports to avoid conflicts.

To use standard DNS resolution:

```bash
# Option 1: Use the dns-forward helper
make dns-forward  # Shows DNS forwarding options

# Option 2: Configure systemd-resolved (recommended)
sudo resolvectl dns <interface> <server-ip>
sudo resolvectl domain <interface> '~internal'

# Option 3: Quick test with port forwarding (use internal DNS port)
sudo socat UDP4-LISTEN:53,fork,reuseaddr UDP4:<server-ip>:8054
```

See `dns-forwarding.md` for detailed setup options.

### Running DNS on Port 53

To run DNS on standard port 53 without root:

```bash
# 1. Enable port 53 binding capability
make setcap

# 2. Edit server/config.yaml to change DNS ports:
#    dns:
#      public:
#        port: 53
#      internal:
#        port: 53

# 3. Run server normally
make run-server
```

**Note**: As of v0.0.7-alpha.1, the `config gen` command supports custom DNS ports via `--dns-public-port` and `--dns-internal-port` flags.

## Quick Start

```bash
# Setup
make all

# Run (in separate terminals)
make run-server     # Terminal 1 - Starts DNS on ports 8053/8054
make run-client     # Terminal 2 - Connects to server

# Test WebAuthn
make firefox        # Opens https://client-001.internal:9443
```

## Important Notes

1. The server uses hostname `server` and client uses `client-001`
2. If using `/etc/hosts`, add:
   ```
   127.0.0.1    localhost server.internal
   <client-ip>  client-001.internal
   ```
3. Or use the DNS service which automatically resolves these hostnames

## Configuration

- Internal domain: `internal`
- Server: `server.internal:8443`
- Client: `client-001.internal:9443`
- DNS: Port 8053 on server

The server's DNS service automatically serves records for all `.internal` domains.