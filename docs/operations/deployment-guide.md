# Deployment Guide

Comprehensive guide for deploying go-trusted-platform in various environments.

## Prerequisites

### System Requirements

- **OS**: Linux (Debian 11+, Ubuntu 20.04+, Alpine)
- **CPU**: 2+ cores for embedded mode, 4+ for cluster
- **RAM**: 4GB minimum (8GB+ recommended for production)
- **Disk**: 20GB+ SSD (depends on data retention)
- **Network**: TLS 1.3 enforced everywhere (port 8443 REST, 10443 gRPC, 9444 QUIC, 9445 MCP)

### Software Dependencies

Core dependencies (auto-installed via package manager):
- Go 1.26+ (if building from source)
- OpenSSL 3.0+ (for TLS)
- Linux kernel 5.4+ (for TPM 2.0 support)

Optional dependencies:
- TPM 2.0 device or simulator (swtpm)
- Open vSwitch (for SDN features)
- Docker/Podman (for container deployment)
- systemd (for service management)

### Network Ports

| Protocol | Port | Purpose | Access |
|----------|------|---------|--------|
| REST | 8443 | Web API, Swagger UI | HTTPS/TLS 1.3 |
| gRPC | 10443 | Service-to-service | TCP/TLS 1.3 |
| QUIC | 9444 | Low-latency clients | UDP/TLS 1.3 |
| MCP | 9445 | LLM integration | HTTP/TLS 1.3 |
| Unix | /run/platformd.sock | Local CLI | Unix socket |
| DNS | 53 | DNS service | UDP/TCP |
| OVS | 6632 | SDN controller | TCP |

## Installation

### Binary Installation

Download pre-built binaries:

```bash
# Check latest release
wget https://github.com/jeremyhahn/go-trusted-platform/releases/download/v0.9.0/platformd-linux-amd64
wget https://github.com/jeremyhahn/go-trusted-platform/releases/download/v0.9.0/platformctl-linux-amd64

# Make executable
chmod +x platformd-linux-amd64 platformctl-linux-amd64

# Install to PATH
sudo mv platformd-linux-amd64 /usr/local/bin/platformd
sudo mv platformctl-linux-amd64 /usr/local/bin/platformctl
```

### From Source

Build using the Makefile (requires Go 1.26+):

```bash
cd go-trusted-platform

# Install dependencies
make init

# Build binaries
make build

# Binaries in ./bin/
./bin/platformd --version
./bin/platformctl --version
```

With FIPS compliance:

```bash
make build-fips
```

### Docker Installation

```bash
# Pull official image
docker pull ghcr.io/jeremyhahn/platformd:latest

# Or build locally
docker build -f build/docker/Dockerfile -t platformd:latest .
```

## Configuration

### Initial Setup

Generate a default configuration:

```bash
# Create configuration and initialize platform
./platformd config gen \
    --init \
    --domain=example.test \
    --platform-dir trusted-data \
    --debug=false \
    --fips=false

# This generates:
# - config.yaml (configuration file)
# - trusted-data/ (data directory)
# - trusted-data/etc/ (config directory)
# - trusted-data/log/ (log directory)
```

### Configuration File

The generated `config.yaml` contains:

```yaml
# Platform directories
platform-dir: /var/lib/trusted-platform
config-dir: /etc/trusted-platform
log-dir: /var/log/trusted-platform

# Domain and contact
domain: example.test
hostmaster: hostmaster@example.test

# QuicBaaS storage configuration
quicbaas:
  storage-backend: pebble      # pebble (embedded) or raft (clustered)
  data-dir: /var/lib/trusted-platform/quicbaas
  cache-size: 67108864         # 64MB
  consistency-level: linearizable

# TPM configuration
tpm:
  device: /dev/tpmrm0          # or /dev/tpm0 for non-resource-manager
  simulator: false              # true for development
  encrypt-sessions: true

# Certificate Authority
certificate-authority:
  platform-ca: 1
  auto-import-issuing-ca: true

# Web services
webservice:
  port: 8080
  tls-port: 8443
  enabled: true
  cert-cache-dir: /var/cache/trusted-platform/web

# Enable all protocols
api:
  rest:
    enabled: true
    port: 8443
  grpc:
    enabled: true
    port: 10443
  quic:
    enabled: true
    port: 9444
  mcp:
    enabled: true
    port: 9445
```

### Security Configuration

#### TLS Configuration

Platform CA automatically generates TLS certificates:

```yaml
# TLS 1.3 enforced everywhere (no downgrade)
tls:
  min-version: "1.3"
  max-version: "1.3"
  cipher-suites:
    - TLS_AES_256_GCM_SHA384
    - TLS_CHACHA20_POLY1305_SHA256
    - TLS_AES_128_GCM_SHA256

# mTLS for service-to-service
mtls:
  enabled: true
  client-ca-pool: /etc/trusted-platform/client-ca.pem
  require-client-cert: true
```

#### TPM Initialization

Initialize TPM on first boot:

```bash
# Check TPM status
platformctl tpm info

# Provision TPM with platform policy
sudo platformctl tpm provision --enable-policy-pcr

# Verify initialization
platformctl tpm info
```

#### Barrier Initialization

Initialize the cryptographic barrier (Shamir secret sharing):

```bash
# Initialize barrier with software strategy (development)
sudo platformctl barrier init --strategy software --shares 5 --threshold 3

# Or use TPM strategy (production)
sudo platformctl barrier init --strategy tpm2 --key-handle 0x81000003

# Generate unseal shares
sudo platformctl barrier shares generate --count 5

# Print shares (store securely)
sudo platformctl barrier shares print
```

## Standalone Deployment

Single-node deployment with embedded QuicBaaS.

### Quick Start

```bash
# 1. Generate configuration
./platformd config gen --init --domain=example.test --platform-dir trusted-data

# 2. Start platform (requires root for TPM access)
sudo ./platformd serve --config config.yaml

# 3. Verify startup
sleep 5
platformctl daemon status

# 4. Check all services
platformctl service status
```

### Systemd Service

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
ExecStart=/usr/local/bin/platformd serve --config /etc/trusted-platform/config.yaml
Restart=on-failure
RestartSec=10

# Security hardening
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
PrivateTmp=yes
ProtectClock=yes
ProtectHostname=yes
ProtectKernelLogs=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictRealtime=yes
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable platformd
sudo systemctl start platformd

# Monitor
sudo journalctl -u platformd -f
```

## Clustered Deployment

Multi-node deployment with Raft consensus for high availability.

### Bootstrap Node (Node 1)

On the first node, initialize the Raft cluster:

```yaml
# /etc/trusted-platform/server1.yaml
domain: server1.example.com
platform-dir: /var/lib/trusted-platform

quicbaas:
  storage-backend: raft
  data-dir: /var/lib/trusted-platform/quicbaas
  node-id: 1
  raft-address: "10.0.1.1:63000"
  join-addresses: []           # Empty for bootstrap
  cache-size: 67108864
  consistency-level: linearizable

tpm:
  device: /dev/tpmrm0
  simulator: false
```

Start the bootstrap node:

```bash
sudo ./platformd serve --config server1.yaml
```

### Follower Nodes (Node 2+)

On additional nodes:

```yaml
# /etc/trusted-platform/server2.yaml
domain: server2.example.com
platform-dir: /var/lib/trusted-platform

quicbaas:
  storage-backend: raft
  data-dir: /var/lib/trusted-platform/quicbaas
  node-id: 2
  raft-address: "10.0.1.2:63000"
  join-addresses:
    - "10.0.1.1:63000"        # Bootstrap node
  cache-size: 67108864
  consistency-level: linearizable
```

Start follower nodes:

```bash
sudo ./platformd serve --config server2.yaml
```

### Verify Cluster

```bash
# From any node, check cluster status
platformctl cluster status

# View cluster members
platformctl cluster members

# Check leader election
platformctl cluster leader
```

### Load Balancer Configuration

For client connections, deploy a load balancer (VIP 10.0.0.1):

```bash
# Keepalived configuration for VIP
vrrp_instance VI_1 {
    state MASTER
    interface eth0
    virtual_router_id 51
    priority 100
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass 1111
    }
    virtual_ipaddress {
        10.0.0.1/24
    }
}

# HAProxy for load balancing
listen platformd-rest
    bind 10.0.0.1:8443
    mode tcp
    balance roundrobin
    server node1 10.0.1.1:8443
    server node2 10.0.1.2:8443
    server node3 10.0.1.3:8443

listen platformd-grpc
    bind 10.0.0.1:10443
    mode tcp
    balance roundrobin
    server node1 10.0.1.1:10443
    server node2 10.0.1.2:10443
    server node3 10.0.1.3:10443
```

## Container Deployment

### Docker Compose

For development and testing:

```bash
cd go-trusted-platform
docker compose -f configs/platform/cluster/docker-compose.yaml up -d

# View logs
docker compose logs -f platformd

# Stop
docker compose down
```

### Kubernetes

Deploy with Helm chart:

```bash
# Add repository
helm repo add trusted-platform https://github.com/jeremyhahn/go-trusted-platform/releases/helm
helm repo update

# Install with high availability
helm install platformd trusted-platform/platformd \
    --namespace trusted-platform \
    --create-namespace \
    --values values.yaml \
    --set replicaCount=3 \
    --set persistence.size=20Gi

# Monitor
kubectl get pods -n trusted-platform
kubectl logs -n trusted-platform -f deployment/platformd
```

### Docker Swarm

```bash
# Create secrets
echo "example.test" | docker secret create domain -
docker secret create tls-cert < /etc/trusted-platform/certs/server.crt
docker secret create tls-key < /etc/trusted-platform/certs/server.key

# Deploy service
docker service create \
    --name platformd \
    --secret domain \
    --secret tls-cert \
    --secret tls-key \
    --publish 8443:8443 \
    --publish 10443:10443 \
    ghcr.io/jeremyhahn/platformd:latest \
    serve --config /run/secrets/config

# Scale
docker service scale platformd=3
```

## Network Setup

### TLS Certificate Chain

The platform uses self-signed CA certificates. On first startup:

1. Platform CA generates its own certificate
2. CA issues TLS certificates for all services
3. Clients must trust the platform CA

**Trust the CA:**

```bash
# Extract platform CA certificate
platformctl ca info --output pem > /tmp/platform-ca.pem

# Trust on Linux
sudo cp /tmp/platform-ca.pem /usr/local/share/ca-certificates/platform-ca.crt
sudo update-ca-certificates

# Trust on macOS
sudo security add-trusted-cert -d -r trustRoot /tmp/platform-ca.pem

# Trust in Go applications
export PLATFORM_CA=/tmp/platform-ca.pem
```

### mTLS Client Configuration

For client certificates:

```bash
# Generate client certificate
platformctl ca issue \
    --cn=my-client \
    --type client \
    --output-key my-client-key.pem \
    --output-cert my-client-cert.pem

# Use in gRPC client
grpcurl -cert my-client-cert.pem \
    -key my-client-key.pem \
    -cacert /tmp/platform-ca.pem \
    localhost:10443 list
```

### DNS Configuration

If using platform's DNS server:

```bash
# Update /etc/resolv.conf
nameserver 127.0.0.1

# Or configure systemd-resolved
sudo mkdir -p /etc/systemd/resolved.conf.d
echo "[Resolve]" | sudo tee /etc/systemd/resolved.conf.d/platform.conf
echo "DNS=127.0.0.1" | sudo tee -a /etc/systemd/resolved.conf.d/platform.conf
sudo systemctl restart systemd-resolved
```

## Health Checks

### Readiness Probe

```bash
# HTTP readiness
curl -k https://localhost:8443/ready

# Expected response
HTTP 200 OK
{"status":"ready","components":{"ca":"ready","dns":"ready"}}
```

### Liveness Probe

```bash
# HTTP liveness
curl -k https://localhost:8443/healthz

# Expected response
HTTP 200 OK
{"status":"alive"}
```

### CLI Status Check

```bash
# Full daemon status
platformctl daemon status

# Service-specific
platformctl service status --service ca
platformctl service status --service dns
platformctl service status --service kms
```

## Post-Deployment

### Enable Features

```bash
# Enable DNS server
platformctl dns enable

# Enable DNSSEC
platformctl dns dnssec enable --enable-signing

# Enable TLS
platformctl tls enable

# Enable SDN (requires Open vSwitch)
platformctl sdn enable
```

### Set Admin Users

```bash
# Create admin user
platformctl iam user create \
    --email=admin@example.test \
    --name="Platform Admin" \
    --role=admin

# Create API service account
platformctl iam service-account create \
    --name=api-client \
    --role=operator
```

### Configure Backup

```bash
# Enable automatic backups
platformctl backup enable \
    --schedule="0 2 * * *" \
    --destination=s3://backups/platform

# Verify backup
platformctl backup status
```

## Troubleshooting

### Platform Won't Start

```bash
# Check configuration syntax
./platformd config validate --config config.yaml

# Run with debug logging
./platformd serve --config config.yaml --log-level debug

# Check systemd logs
journalctl -u platformd -n 50
```

### TLS Certificate Issues

```bash
# View current certificate
platformctl ca info

# Force certificate rotation
sudo platformctl ca rotate

# Re-trust CA
platformctl ca info --output pem | sudo tee /usr/local/share/ca-certificates/platform-ca.crt
sudo update-ca-certificates
```

### TPM Issues

```bash
# Verify TPM is accessible
platformctl tpm info

# Reset TPM (warning: clears all keys)
sudo platformctl tpm clear

# Re-provision TPM
sudo platformctl tpm provision
```

### Cluster Issues

```bash
# Check cluster health
platformctl cluster status

# View Raft logs
platformctl cluster logs --node 1 --limit 20

# Force leader election
platformctl cluster leader --force
```

See [Troubleshooting Guide](troubleshooting.md) for more solutions.

## Related Documentation

- [Operational Runbook](operational-runbook.md) - Start/stop procedures, unsealing
- [Backup & Recovery](backup-recovery.md) - Data protection strategies
- [Security Architecture](../architecture/security.md) - Trust model and threat model
- [Cluster Configuration](../cluster/configuration.md) - Advanced cluster setup
- [Configuration Reference](../configuration/) - Complete YAML reference
