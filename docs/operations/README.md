# Operations Documentation

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [../daemon/user.md](../daemon/user.md). `platformctl daemon`, `backup`, `restore` and `cluster` are not registered commands, `platformd` has only `serve` and `version` (no `config`), and `../../CONTRIBUTING.md` does not exist.

Complete guide to deploying, running, and maintaining go-trusted-platform in production.

## Quick Start

Get up and running quickly:

```bash
# 1. Install platform
wget https://github.com/jeremyhahn/go-trusted-platform/releases/download/v0.9.0/platformd
chmod +x platformd

# 2. Generate configuration
./platformd config gen --init --domain=example.test --platform-dir trusted-data

# 3. Start platform (requires root for TPM access)
sudo ./platformd serve --config config.yaml --enable-mtls

# 4. Verify running
sleep 5
platformctl daemon status

# 5. Check health
curl -k https://localhost:8443/health
```

## Documentation Structure

### Deployment

Start here when installing go-trusted-platform for the first time.

- **[Deployment Guide](deployment-guide.md)** — Installation, configuration, and deployment modes
  - Prerequisites and system requirements
  - Binary and container installation
  - Configuration file structure and options
  - Standalone, clustered, and mixed deployments
  - Docker Compose and Kubernetes deployment
  - Network setup and TLS configuration
  - Post-deployment configuration

### Operations

Day-to-day operations and maintenance.

- **[Operational Runbook](operational-runbook.md)** — Procedures and commands
- **[Gateway Bring-up](gateway-bringup.md)** — Standing a gateway beside the routers it will replace, with zero blast radius
  - Starting/stopping the platform
  - Health checks and monitoring
  - Barrier unsealing and sealing
  - Certificate management and rotation
  - Service management
  - DNS operations
  - TPM management
  - Cluster operations
  - Key management
  - Backup and recovery procedures
  - Emergency procedures

### Data Protection

Backup, recovery, and disaster response.

- **[Backup & Recovery Guide](backup-recovery.md)** — Data protection strategies
  - Backup strategy (local, cloud, incremental)
  - Automated backup scheduling
  - Barrier shares backup and recovery
  - CA certificate and key backup
  - Configuration backup
  - Data integrity verification
  - Complete disaster recovery procedures
  - Partial failure recovery (node loss, corruption)
  - Backup validation and monitoring

### Troubleshooting

Diagnosis and resolution of issues.

- **[Troubleshooting Guide](troubleshooting.md)** — Issue diagnosis and fixes
  - Quick diagnostics
  - Startup failures
  - TLS and certificate issues
  - Barrier and sealing problems
  - Service connectivity issues
  - TPM issues
  - Database and storage issues
  - Cluster problems
  - Performance issues
  - Log analysis

## Deployment Modes

Choose based on your requirements:

| Mode | Nodes | HA | Use Case |
|------|-------|----|----|
| **Standalone** | 1 | No | Development, edge devices, small deployments |
| **Clustered** | 3+ | Yes | Production, high availability |
| **Mixed** | N/A | Partial | Hybrid, gradual migration |
| **Dedicated** | 10+ | Yes | Enterprise, strict isolation |

See [Deployment Guide](deployment-guide.md#deployment-modes) for detailed comparison.

## Configuration

### Essential Configuration

Minimum viable config for any deployment:

```yaml
platform-dir: /var/lib/trusted-platform
domain: example.test
hostmaster: hostmaster@example.test

quicbaas:
  storage-backend: pebble
  data-dir: /var/lib/trusted-platform/quicbaas
  cache-size: 67108864

tpm:
  device: /dev/tpmrm0
  simulator: false
```

### Complete Configuration Reference

See [Configuration Reference](../configuration/) for all available options.

### Configuration File Locations

- **Global config**: `/etc/trusted-platform/config.yaml`
- **Data directory**: `/var/lib/trusted-platform/`
- **Log directory**: `/var/log/trusted-platform/`
- **Systemd service**: `/etc/systemd/system/platformd.service`

## Multi-Protocol API

All services expose consistent APIs across multiple protocols:

| Protocol | Transport | Port | Clients |
|----------|-----------|------|---------|
| REST | HTTPS | 8443 | Web, curl, SDKs |
| gRPC | TCP+TLS | 10443 | Go, Rust, Node.js |
| QUIC | UDP+TLS | 9444 | Mobile, edge |
| MCP | HTTP+TLS | 9445 | LLM agents |
| Unix | Socket | /run/platformd.sock | Local CLI |

For integration examples, see [API Reference](../api/).

## Health and Monitoring

### Health Endpoints

```bash
# Full status (JSON)
curl -k https://localhost:8443/health

# Readiness probe (for load balancers)
curl -k https://localhost:8443/ready

# Liveness probe (for orchestration)
curl -k https://localhost:8443/healthz

# Prometheus metrics
curl -k https://localhost:8443/metrics | grep platform
```

### CLI Commands

```bash
# Overall status
platformctl daemon status

# Service status
platformctl service status

# Cluster status
platformctl cluster status

# View logs
platformctl daemon logs --level error --since "1h"

# Performance profiling
platformctl daemon debug pprof profile
```

## Common Procedures

### Barrier Unseal

Required when platform starts in sealed state. `platformd` never unseals the
barrier itself, whatever the seal strategy (`tpm2` included): it waits at the
barrier gate until an operator supplies a secret or shares. See
[Unsealing after a restart](../barrier/user.md#unsealing-after-a-restart).

```bash
# Check status
platformctl barrier status

# Single-secret barrier
sudo platformctl barrier unseal --passphrase <passphrase>

# Or Shamir barrier: submit shares until the threshold is met
sudo platformctl barrier unseal-shares --share <s1> --share <s2> --share <s3>

# Verify unsealed
platformctl barrier status
```

### Certificate Rotation

Automatic rotation every 90 days. Manual rotation:

```bash
# Force rotation
sudo platformctl ca rotate

# Verify new certificate
platformctl ca info

# Update clients to trust new CA
sudo cp /var/lib/trusted-platform/ca/cert.pem \
    /usr/local/share/ca-certificates/platform-ca.crt
sudo update-ca-certificates
```

### Service Restart

Restart a service without stopping platform:

```bash
# Restart CA service
platformctl service restart --service ca

# Restart DNS service
platformctl service restart --service dns

# Verify running
platformctl service status
```

### Cluster Operations

```bash
# View cluster members
platformctl cluster members

# Check leader
platformctl cluster leader

# Add node (on new node)
# 1. Configure with join-addresses pointing to existing member
# 2. Start platform
# 3. Node auto-joins

# Remove node (from any member)
platformctl cluster remove-node --id 3
```

### Backup and Restore

```bash
# Create backup
platformctl backup create --output backup-$(date +%Y%m%d).tar.gz

# Restore from backup
sudo platformctl restore backup-20260329.tar.gz --verify

# List available backups
platformctl backup list

# Enable automated backups
platformctl backup enable \
    --destination /var/backups/platform \
    --schedule "0 * * * *"
```

## Systemd Integration

### Service File

Create `/etc/systemd/system/platformd.service`:

```ini
[Unit]
Description=Trusted Platform Daemon
Documentation=https://github.com/jeremyhahn/go-trusted-platform
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=root
Group=root
ExecStart=/usr/local/bin/platformd serve --config /etc/trusted-platform/config.yaml --enable-mtls
Restart=on-failure
RestartSec=10

# Security hardening
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

### Enable and Start

```bash
sudo systemctl daemon-reload
sudo systemctl enable platformd
sudo systemctl start platformd

# Monitor
sudo journalctl -u platformd -f

# Stop
sudo systemctl stop platformd
```

## Container Deployment

### Docker

```bash
# Build image
docker build -f build/docker/Dockerfile -t platformd:latest .

# Run container
docker run -d \
    --name platformd \
    -p 8443:8443 \
    -p 10443:10443 \
    -v /var/lib/trusted-platform:/var/lib/trusted-platform \
    platformd:latest \
    serve --config /var/lib/trusted-platform/config.yaml
```

### Docker Compose

```bash
cd go-trusted-platform
docker compose -f configs/platform/cluster/docker-compose.yaml up -d

# View logs
docker compose logs -f platformd

# Stop
docker compose down
```

### Kubernetes

```bash
# Install via Helm
helm repo add trusted-platform https://github.com/jeremyhahn/go-trusted-platform/releases/helm
helm install platformd trusted-platform/platformd \
    --namespace trusted-platform \
    --create-namespace \
    --set replicaCount=3
```

## Performance Tuning

### Database Cache

Increase for larger working sets:

```yaml
quicbaas:
  cache-size: 268435456  # 256MB for production
```

### Worker Threads

For high concurrency:

```yaml
services:
  worker-threads: 16
```

### Memory Limits

Set via systemd:

```ini
[Service]
MemoryMax=8G
```

Or via environment:

```bash
GOMEMLIMIT=4GiB sudo ./platformd serve --config config.yaml --enable-mtls
```

## Compliance

Platform supports compliance frameworks:

- **FIPS 140-3** — Cryptographic validation
- **PCI-DSS** — Payment card data
- **HIPAA** — Healthcare data
- **SOC2** — Security and availability
- **ISO 27001** — Information security

For compliance details, see [Security Architecture](../architecture/security.md).

## Security Best Practices

1. **Encrypt backups** — Always encrypt data at rest
2. **Separate encryption keys** — Store keys away from data
3. **Rotate credentials** — Regular credential rotation
4. **Monitor logs** — Alert on errors and warnings
5. **Test restores** — Monthly backup integrity tests
6. **Version control config** — Track changes in git
7. **Audit access** — Log all administrative actions
8. **Patch promptly** — Update to latest version
9. **Use strong passwords** — Minimum 16 characters
10. **Enable mTLS** — Enforce mutual TLS between services

For detailed security information, see [Security Architecture](../architecture/security.md).

## Support and Resources

### Documentation

- [Deployment Guide](deployment-guide.md) — Installation and setup
- [Operational Runbook](operational-runbook.md) — Day-to-day operations
- [Troubleshooting Guide](troubleshooting.md) — Issue diagnosis
- [Backup & Recovery](backup-recovery.md) — Data protection
- [Architecture](../architecture/) — System design and security

### API Documentation

- [REST API](../api/rest-reference.md)
- [gRPC API](../api/grpc-reference.md)
- [CLI Reference](../daemon/cli.md)

### Community

- **GitHub Issues**: https://github.com/jeremyhahn/go-trusted-platform/issues
- **Discord**: https://discord.gg/TuJex32b
- **Email**: support@automatethethings.com

### Commercial Support

For enterprise support, SLAs, and consulting:
- licensing@automatethethings.com

## Version Information

- **Latest Release**: v0.9.0
- **Go Version**: 1.26+
- **Min Linux**: Kernel 5.4
- **License**: AGPL-3.0 or Commercial

## Contribution

We welcome contributions! See [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines.

## License

go-trusted-platform is dual-licensed:
- GNU Affero General Public License v3.0 (AGPL-3.0)
- Commercial License (contact licensing@automatethethings.com)
