# Operational Runbook

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [../daemon/user.md](../daemon/user.md) and each feature folder's `user.md`. `platformctl backup`, `restore`, `cluster`, `daemon`, `dns` and `storage` are not registered commands, and `platformd` has no `config` subcommand.

Day-to-day operational procedures for running go-trusted-platform.

## Quick Reference

### Starting the Platform

```bash
# Start with systemd
sudo systemctl start platformd
sudo systemctl status platformd

# Or manually
sudo ./platformd serve --config config.yaml --enable-mtls

# Monitor startup
sleep 10
platformctl daemon status
```

### Checking Service Status

```bash
# Overall platform status
platformctl daemon status

# Individual service status
platformctl service status

# Specific service
platformctl service status --service ca
platformctl service status --service dns
platformctl service status --service kms
```

### Stopping the Platform

```bash
# Graceful shutdown
sudo systemctl stop platformd

# Force stop
sudo systemctl kill platformd

# Verify stopped
sudo systemctl status platformd
```

## Barrier Operations

The barrier is a cryptographic storage barrier using Shamir secret sharing. Services requiring unsealed storage will be unavailable while sealed.

### Check Barrier Status

```bash
# View barrier state
platformctl barrier status

# Expected output (unsealed):
Barrier Status:
  State: unsealed
  Strategy: software
  Shares: 5
  Threshold: 3
  Last Unsealed: 2026-03-29T15:30:00Z

# Or sealed:
Barrier Status:
  State: sealed
  Strategy: tpm2
  Sealed Since: 2026-03-29T15:29:00Z
```

### Unseal the Barrier

`platformd` never unseals the barrier itself, whatever the seal strategy
(`tpm2` and `pkcs11` included). It waits at the barrier gate until an operator
supplies a secret or shares. See
[Unsealing after a restart](../barrier/user.md#unsealing-after-a-restart).

#### Single-Secret Unseal

```bash
sudo platformctl barrier unseal --passphrase <passphrase>

# Verify unsealed
platformctl barrier status
```

#### Shamir Unseal

```bash
# Unseal with shares (threshold=3, need any 3 of 5)
sudo platformctl barrier unseal-shares --share <s1> --share <s2> --share <s3>

# Or one share per line from a file
sudo platformctl barrier unseal-shares --shares-file <shares-file>
```

### Initialize Barrier

First-time barrier setup:

```bash
# Initialize with software strategy (development)
sudo platformctl barrier init \
    --strategy software \
    --shares 5 \
    --threshold 3

# Or TPM strategy (production)
sudo platformctl barrier init \
    --strategy tpm2 \
    --key-handle 0x81000003

# Or PKCS11 (HSM)
sudo platformctl barrier init \
    --strategy pkcs11 \
    --hsm-module /usr/lib/softhsm/libsofthsm2.so \
    --token "SoftHSM v2"

# Verify initialization
platformctl barrier status
```

### Generate and Store Shares

```bash
# Generate new shares (regenerate escrow)
sudo platformctl barrier shares generate --count 5

# Print shares to console (save these!)
sudo platformctl barrier shares print

# Export to files
sudo platformctl barrier shares export --output /tmp/barrier-shares/

# Print QR codes for mobile wallet
sudo platformctl barrier shares qr
```

### Seal the Barrier

Manually seal barrier (requires unsealing before critical operations):

```bash
# Seal barrier
sudo platformctl barrier seal

# Verify sealed
platformctl barrier status
```

## Health and Monitoring

### Health Endpoint

```bash
# Full health status (JSON)
curl -k https://localhost:8443/health

# Response:
{
  "status": "ready",
  "components": {
    "ca": {"status": "ready"},
    "dns": {"status": "ready"},
    "database": {"status": "ready"},
    "disk": {"status": "ready"},
    "memory": {"status": "ready"}
  }
}

# Readiness check (used by load balancers)
curl -k https://localhost:8443/ready
# Returns 200 if ready, 503 if not

# Liveness check (used by container orchestration)
curl -k https://localhost:8443/healthz
# Returns 200 if alive, 503 if dead
```

### Monitoring

```bash
# View all metrics
curl -k https://localhost:8443/metrics

# Filter metrics
curl -k https://localhost:8443/metrics | grep platform

# Prometheus scrape config
cat > prometheus.yml <<EOF
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: platformd
    scheme: https
    tls_config:
      insecure_skip_verify: true  # Only for testing
    static_configs:
      - targets: ['localhost:8443']
EOF
```

### Log Analysis

```bash
# View logs with systemd
sudo journalctl -u platformd -n 100
sudo journalctl -u platformd --since "1 hour ago"
sudo journalctl -u platformd -f  # Follow

# View file logs
tail -f /var/log/trusted-platform/platformd.log

# Filter by level
sudo journalctl -u platformd PRIORITY=err
sudo journalctl -u platformd PRIORITY=warning

# Search for errors
sudo journalctl -u platformd | grep -i error
```

### Log Levels

Configure logging level:

```yaml
# In config.yaml
logging:
  level: info    # debug, info, warn, error
  format: json   # json or text
  output: syslog # stdout, file, syslog
```

Change at runtime:

```bash
# Set log level
platformctl daemon logs --level debug

# View current level
platformctl daemon logs --level
```

## Certificate Management

### View Current Certificate

```bash
# View platform CA certificate
platformctl ca info

# View in detail
platformctl ca info --verbose

# Export certificate
platformctl ca info --output pem > /tmp/ca.pem
platformctl ca info --output der > /tmp/ca.der
```

### Rotate TLS Certificate

The platform automatically rotates TLS certificates every 90 days. Manual rotation:

```bash
# Force rotation
sudo platformctl ca rotate --force

# Verify new cert
platformctl ca info

# Update clients to trust new CA
platformctl ca info --output pem | \
    sudo tee /usr/local/share/ca-certificates/platform-ca.crt
sudo update-ca-certificates
```

### Issue Client Certificates

For mTLS connections:

```bash
# Generate client certificate
platformctl ca issue \
    --cn=my-client \
    --type client \
    --expires=365d \
    --output-cert /tmp/client.pem \
    --output-key /tmp/client-key.pem

# Use in requests
curl -k \
    --cert /tmp/client.pem \
    --key /tmp/client-key.pem \
    https://localhost:8443/health
```

### Revoke Certificate

```bash
# List issued certificates
platformctl ca list

# Revoke certificate
platformctl ca revoke --serial 0x1234567890

# Verify revocation
platformctl ca crl  # View CRL
```

## Service Management

### Start Individual Service

```bash
# Start CA service
platformctl service start --service ca

# Start DNS service
platformctl service start --service dns

# Start all services
platformctl service start --all
```

### Stop Individual Service

```bash
# Stop CA service
platformctl service stop --service ca

# Stop all services (except core)
platformctl service stop --all
```

### Restart Service

```bash
# Restart service
platformctl service restart --service ca

# Verify running
platformctl service status --service ca
```

### Enable/Disable Service

```bash
# Disable service (won't auto-start)
platformctl service disable --service ca

# Enable service (auto-start on daemon restart)
platformctl service enable --service ca

# Verify state
platformctl service status --service ca
```

## DNS Operations

### Enable DNS Service

```bash
# Enable DNS
platformctl dns enable

# Verify running
platformctl dns status
```

### Add DNS Record

```bash
# Add A record
platformctl dns record add \
    --zone example.test \
    --name www \
    --type A \
    --value 192.168.1.1 \
    --ttl 3600

# Add CNAME record
platformctl dns record add \
    --zone example.test \
    --name alias \
    --type CNAME \
    --value www.example.test

# Add MX record
platformctl dns record add \
    --zone example.test \
    --name "" \
    --type MX \
    --value "10 mail.example.test"
```

### Test DNS

```bash
# Query DNS server
dig @localhost www.example.test

# Use specific record type
dig @localhost www.example.test A

# Test with nslookup
nslookup www.example.test localhost

# Test with systemd-resolved
resolvectl query www.example.test
```

### DNSSEC Operations

```bash
# Enable DNSSEC
platformctl dns dnssec enable

# Sign zone
platformctl dns dnssec sign --zone example.test

# View DNSSEC status
platformctl dns dnssec status

# Validate DNSSEC
dig +dnssec www.example.test

# View DS record (for delegation)
platformctl dns dnssec ds-record --zone example.test
```

## TPM Operations

### Check TPM Status

```bash
# View TPM information
platformctl tpm info

# Check handles
platformctl tpm handles

# View TPM policies
platformctl tpm policies
```

### Provision TPM

```bash
# Initial TPM provisioning
sudo platformctl tpm provision

# Enable PCR policy
sudo platformctl tpm provision --enable-policy-pcr

# Verify
platformctl tpm info
```

### Seal Data to TPM

```bash
# Seal a secret to TPM
echo "my-secret" | sudo platformctl tpm seal \
    --pcrs 0,1,7 \
    --output /tmp/sealed.bin

# Unseal (requires matching PCR values)
sudo platformctl tpm unseal --input /tmp/sealed.bin
```

### Clear TPM

```bash
# Warning: Clears all keys and policies
sudo platformctl tpm clear

# Re-provision after clear
sudo platformctl tpm provision
```

## Key Management

### List Keys

```bash
# List all keys
platformctl kms keys list

# List keys in TPM
platformctl kms keys list --keystore tpm2

# List keys in software storage
platformctl kms keys list --keystore software
```

### Generate Key

```bash
# Generate RSA key
platformctl kms key generate \
    --algorithm RSA \
    --size 4096 \
    --name my-rsa-key \
    --keystore tpm2

# Generate ECDSA key
platformctl kms key generate \
    --algorithm ECDSA \
    --curve P-256 \
    --name my-ecdsa-key \
    --keystore tpm2
```

### Rotate Key

```bash
# Rotate key (generates new, old retained)
platformctl kms key rotate --name my-key

# View key versions
platformctl kms key versions --name my-key
```

## Cluster Operations

### Check Cluster Status

```bash
# View cluster members
platformctl cluster status

# View cluster members detailed
platformctl cluster members

# View current leader
platformctl cluster leader

# Check Raft health
platformctl cluster raft status
```

### Join Node to Cluster

On new node:

```bash
# Configure with existing cluster member
# In config.yaml:
quicbaas:
  join-addresses:
    - "10.0.1.1:63000"  # Existing member

# Start node (automatically joins)
sudo ./platformd serve --config config.yaml --enable-mtls

# Verify joined
platformctl cluster members
```

### Force Leader Election

```bash
# View current leader
platformctl cluster leader

# Force election
sudo platformctl cluster leader --force

# Verify new leader
platformctl cluster leader
```

### View Raft Logs

```bash
# View recent Raft logs
platformctl cluster logs --limit 50

# Follow logs
platformctl cluster logs -f

# Export for analysis
platformctl cluster logs --export raft-logs.json
```

### Remove Node from Cluster

```bash
# Remove node (keep data)
platformctl cluster remove-node --id 3

# Remove node and clean data
platformctl cluster remove-node --id 3 --wipe
```

## Backup and Recovery

### Create Manual Backup

```bash
# Backup to file
platformctl backup create --output backup-$(date +%Y%m%d-%H%M%S).tar.gz

# Backup to S3
platformctl backup create --destination s3://my-bucket/backups/

# Verify backup
tar tzf backup-20260329-153000.tar.gz | head -20
```

### List Backups

```bash
# List local backups
platformctl backup list

# List S3 backups
platformctl backup list --destination s3://my-bucket/backups/
```

### Restore from Backup

```bash
# Restore latest backup
sudo platformctl restore latest --verify

# Restore specific backup
sudo platformctl restore backup-20260329-153000.tar.gz --verify

# Verify after restore
platformctl daemon status
```

### Backup Schedule

```bash
# Enable daily backups at 2 AM
platformctl backup schedule \
    --enable \
    --time "02:00" \
    --destination /var/backups/platform

# View schedule
platformctl backup schedule --info

# Disable scheduled backups
platformctl backup schedule --disable
```

## Troubleshooting

### Platform Won't Start

```bash
# Check configuration
./platformd config validate --config config.yaml

# Run with debug logging
sudo ./platformd serve --config config.yaml --enable-mtls --log-level debug 2>&1 | head -50

# Check systemd service
sudo systemctl status platformd -l
sudo journalctl -u platformd -n 50 -p err
```

### Service Not Responding

```bash
# Check service status
platformctl service status --service ca

# Check connectivity
curl -k https://localhost:8443/health

# Check logs
platformctl daemon logs --level error --since "5m"

# Restart service
platformctl service restart --service ca
```

### High CPU Usage

```bash
# Check goroutine count
platformctl daemon status | grep goroutines

# View active goroutines
platformctl daemon debug goroutines

# Check for stuck operations
platformctl daemon debug pprof profile > cpu.prof
go tool pprof cpu.prof
```

### Disk Space Issues

```bash
# Check platform data usage
du -sh /var/lib/trusted-platform/*

# View database size
platformctl storage size

# Clean old logs
find /var/log/trusted-platform -name "*.log" -mtime +30 -delete

# Compact database
sudo platformctl storage compact
```

### Memory Issues

```bash
# Check memory usage
platformctl daemon status | grep memory

# Force garbage collection
platformctl daemon gc

# Profile heap
platformctl daemon debug heap > heap.prof
go tool pprof heap.prof
```

## Emergency Procedures

### Panic Recovery

If platform crashes:

```bash
# Check if running
sudo systemctl status platformd

# If crashed, restart
sudo systemctl restart platformd

# Monitor startup
sudo journalctl -u platformd -f

# After restart, verify
platformctl daemon status
```

### Data Corruption Recovery

If database is corrupted:

```bash
# Stop platform
sudo systemctl stop platformd

# Create backup of corrupted data
sudo cp -r /var/lib/trusted-platform/quicbaas /var/lib/trusted-platform/quicbaas.corrupt

# Repair database
sudo platformctl storage repair

# Start platform
sudo systemctl start platformd

# Verify
platformctl daemon status
```

### Complete Recovery from Disaster

```bash
# 1. Stop platform
sudo systemctl stop platformd

# 2. Restore from backup
sudo platformctl restore backup-latest.tar.gz --verify

# 3. Verify restoration
ls -la /var/lib/trusted-platform/

# 4. Start platform
sudo systemctl start platformd

# 5. Run health checks
platformctl daemon status
platformctl cluster status
```

## Performance Tuning

### Database Cache

```yaml
# In config.yaml
quicbaas:
  cache-size: 67108864  # Increase for larger working set
  # 256MB for production
  # cache-size: 268435456
```

### Thread Pool

```yaml
# Tune worker threads
services:
  worker-threads: 8  # Increase for high concurrency
```

### Memory Settings

```bash
# Increase Go runtime memory limit
GOMEMLIMIT=4GiB sudo ./platformd serve --config config.yaml --enable-mtls
```

### Resource Limits

```ini
# In systemd service
[Service]
MemoryMax=8G
CPUQuota=400%
LimitNOFILE=65535
```

## Related Documentation

- [Deployment Guide](deployment-guide.md) - Installation and configuration
- [Backup & Recovery](backup-recovery.md) - Data protection procedures
- [Troubleshooting](troubleshooting.md) - Issue diagnosis and resolution
- [Security Architecture](../architecture/security.md) - Trust and threat models
- [Health Monitoring](../health/README.md) - Health check framework
