# Docker Trusted Platform Example

Docker-based demonstration of the Trusted Platform with automated certificate management.

## Requirements

- Docker & Docker Compose V2
- Make
- Go development environment

## Quick Start

```bash
# Build and start
make all && make up

# Launch Firefox with trusted certificates  
make firefox

# View logs
make logs

# Clean up
make down && make clean
```

## Services

**Server** (`platform.local:8443`)
- Certificate Authority (Root & Intermediate)
- ACME server
- DNS server
- Web services with TLS

**Client** (`edge-001.platform.local:9443`)  
- Auto-enrolls with server via ACME
- Web services with TLS

## Firefox Integration

`make firefox` automatically:
- Extracts and trusts all CA certificates (RSA, ECDSA, Ed25519)
- Manages /etc/hosts entries
- Launches Firefox with proper domain names

## Commands

| Command | Description |
|---------|-------------|
| `make all` | Build everything |
| `make up` | Start containers |
| `make firefox` | Launch Firefox with trusted CAs |
| `make status` | Check service status |
| `make logs` | View container logs |
| `make clean` | Remove all generated files |

## Notes

- Uses TPM simulators for development
- Certificates generated on startup
- Hosts entries managed automatically