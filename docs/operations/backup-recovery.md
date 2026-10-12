# Backup and Recovery Guide

Data protection and disaster recovery procedures for go-trusted-platform.

## Overview

go-trusted-platform manages critical data including cryptographic keys, certificates, configurations, and application data. This guide covers backup strategies, automated recovery, and disaster response.

### What Gets Backed Up

| Component | Location | Criticality | Frequency |
|-----------|----------|------------|-----------|
| QuicBaaS Database | `/var/lib/trusted-platform/quicbaas/` | Critical | Every backup |
| CA Keys & Certs | `/var/lib/trusted-platform/ca/` | Critical | Every backup |
| Configuration | `/etc/trusted-platform/` | Critical | Every backup |
| TPM Keys | TPM Hardware | Critical | Never (hardware-bound) |
| DNS Records | `/var/lib/trusted-platform/quicbaas/dns/` | Important | Every backup |
| Audit Logs | `/var/log/trusted-platform/` | Important | Rotated daily |
| Barrier Shares | `/var/lib/trusted-platform/barrier/` | Critical | Manual only |

### Recovery Objectives

| Metric | Target |
|--------|--------|
| RPO (Recovery Point Objective) | 1 hour |
| RTO (Recovery Time Objective) | 15 minutes |
| Retention Period | 90 days |
| Backup Frequency | Hourly |
| Test Frequency | Monthly |

## Backup Strategy

### Local Backup

Recommended for standalone and small deployments.

#### Configuration

```yaml
# In config.yaml
backup:
  enabled: true
  destination: /var/backups/trusted-platform
  schedule: "0 * * * *"           # Hourly
  retention: 2160                  # 90 days (90*24)
  compression: gzip
  encryption: aes-256-gcm
  encryption-key: ${BACKUP_KEY}    # Use environment variable
```

#### Enable Automated Backups

```bash
# Create backup directory
sudo mkdir -p /var/backups/trusted-platform
sudo chown root:root /var/backups/trusted-platform
sudo chmod 700 /var/backups/trusted-platform

# Enable backups in config
platformctl backup enable \
    --destination /var/backups/trusted-platform \
    --schedule "0 * * * *" \
    --retention 2160

# Verify enabled
platformctl backup status
```

#### Create Manual Backup

```bash
# Backup everything
platformctl backup create \
    --output /var/backups/trusted-platform/backup-$(date +%Y%m%d-%H%M%S).tar.gz \
    --compress gzip

# Backup with encryption
platformctl backup create \
    --output backup.tar.gz.enc \
    --encrypt aes-256-gcm \
    --password "$(cat /etc/trusted-platform/backup-password)"

# Verify backup
tar tzf /var/backups/trusted-platform/backup-*.tar.gz | head -20

# List backup contents
platformctl backup list --info
```

#### Backup Storage

Store backups securely:

```bash
# On NFS mount
sudo mount -t nfs nfs-server:/export/backups /mnt/backups
sudo platformctl backup create --destination /mnt/backups/

# Verify NFS connectivity
sudo df /mnt/backups/
```

### Cloud Backup

For high availability and disaster recovery.

#### AWS S3

```yaml
# In config.yaml
backup:
  enabled: true
  destination: s3://my-backup-bucket/platformd
  schedule: "0 * * * *"
  retention: 2160
  encryption: aes-256-gcm
  s3:
    region: us-east-1
    credentials:
      access-key: ${AWS_ACCESS_KEY}
      secret-key: ${AWS_SECRET_KEY}
    storage-class: STANDARD_IA
```

Enable S3 backups:

```bash
# Set AWS credentials
export AWS_ACCESS_KEY="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Enable S3 backups
platformctl backup enable \
    --destination s3://my-backup-bucket/platformd \
    --schedule "0 * * * *" \
    --retention 2160

# Verify
aws s3 ls s3://my-backup-bucket/platformd/ --recursive
```

#### Google Cloud Storage

```yaml
backup:
  destination: gs://my-backup-bucket/platformd
  gcs:
    project-id: my-project
    credentials-file: /etc/trusted-platform/gcs-credentials.json
```

#### Azure Blob Storage

```yaml
backup:
  destination: azure://my-container/platformd
  azure:
    storage-account: myaccount
    storage-key: ${AZURE_STORAGE_KEY}
```

### Cluster Backup

For Raft-based clusters, replicas provide built-in redundancy.

```bash
# View replica status
platformctl cluster members

# Each node maintains full copy of data
# Loss of single node is non-fatal
# Loss of quorum (e.g., 2 of 3) requires recovery
```

Additional backup for cluster:

```bash
# Backup from leader
ssh server1 platformctl backup create --output cluster-backup.tar.gz

# Backup from follower
ssh server2 platformctl backup create --output cluster-backup.tar.gz

# Both contain identical data
```

## Incremental Backups

For large deployments, incremental backups reduce storage:

```bash
# Create full backup
platformctl backup create \
    --output full-backup-$(date +%Y%m%d).tar.gz \
    --type full

# Create incremental backup (next day)
platformctl backup create \
    --output incremental-backup-$(date +%Y%m%d).tar.gz \
    --type incremental \
    --since "1 day ago"

# Storage savings: ~80-90% smaller than full backups
```

Restore from incremental:

```bash
# Restore full backup first
sudo platformctl restore full-backup-20260329.tar.gz

# Restore incremental
sudo platformctl restore incremental-backup-20260330.tar.gz

# Result: data state as of incremental backup date
```

## Barrier Shares Backup

The barrier uses Shamir secret sharing. Backup shares safely:

```bash
# Export shares to secure location
sudo platformctl barrier shares export --output /tmp/shares/

# Each share alone is useless (threshold-3 of 5 required)
# Store in different physical locations:
# - Share 1: Safe deposit box (bank)
# - Share 2: Office safe
# - Share 3: Home safe
# - Share 4: Cloud storage (encrypted)
# - Share 5: Off-site backup

# Encrypt shares before cloud storage
openssl enc -aes-256-cbc -in share-4.enc -out share-4.enc.enc

# Print QR codes for mobile wallets
sudo platformctl barrier shares qr
```

Recovery from shares. There is no secret-less unseal: `platformd` never unseals
the barrier itself, whatever the seal strategy (`tpm2` included). See
[Unsealing after a restart](../barrier/user.md#unsealing-after-a-restart).

```bash
# Reconstruct with any 3 shares
sudo platformctl barrier unseal-shares --share <s1> --share <s2> --share <s4>
```

## CA Certificate and Key Backup

Critical for PKI continuity:

```bash
# Export CA certificate
platformctl ca info --output pem > ca-certificate.pem

# Export CA public key
platformctl ca info --output pem --public-key > ca-public-key.pem

# CA private key is in barrier storage (cannot be exported)
# Backup via general backup procedures

# Verify CA backup
openssl x509 -in ca-certificate.pem -text -noout
```

Recovery CA keys:

```bash
# If CA database is lost, import from backup
sudo platformctl ca import --certificate ca-certificate.pem

# Create new CA with same identity
platformctl ca create \
    --cn="ca.example.test" \
    --import-issuing-ca ca-certificate.pem
```

## Configuration Backup

Backup configuration separately for version control:

```bash
# Export configuration
platformctl config export > config-backup.yaml

# Secure storage
gpg -e -r admin@example.test config-backup.yaml
rm config-backup.yaml

# Store in git (with encryption)
git add config-backup.yaml.gpg
git commit -m "Config backup $(date +%Y-%m-%d)"
git push

# Restore configuration
gpg -d config-backup.yaml.gpg > config.yaml
diff config.yaml /etc/trusted-platform/config.yaml
```

## Data Integrity Verification

### Verify Backup Integrity

```bash
# Check backup file integrity
platformctl backup verify backup-20260329.tar.gz

# List contents
tar tzf backup-20260329.tar.gz | wc -l

# Extract and verify
mkdir /tmp/verify
tar xzf backup-20260329.tar.gz -C /tmp/verify/
ls -la /tmp/verify/
```

### Restore Test

Monthly test restore to verify backups work:

```bash
# Create test server
docker run -it ubuntu:latest /bin/bash

# Copy backup
docker cp backup-20260329.tar.gz container:/tmp/

# Restore in test environment
docker exec container platformctl restore /tmp/backup-20260329.tar.gz --verify

# Verify services
docker exec container platformctl daemon status
docker exec container platformctl service status

# Document results
echo "RESTORE TEST: PASSED" > restore-test-20260329.txt
```

## Disaster Recovery Plan

### Complete Failure Recovery

If entire installation is lost:

#### Step 1: Restore Infrastructure

```bash
# 1. Restore hardware/VMs
# 2. Install OS
# 3. Install dependencies
sudo apt-get update
sudo apt-get install -y go curl wget git

# 4. Install platform binaries
wget https://github.com/jeremyhahn/go-trusted-platform/releases/download/v0.9.0/platformd
wget https://github.com/jeremyhahn/go-trusted-platform/releases/download/v0.9.0/platformctl
chmod +x platformd platformctl
sudo mv platformd platformctl /usr/local/bin/
```

#### Step 2: Restore Configuration

```bash
# Restore backup
platformctl restore backup-20260329.tar.gz --verify

# Verify configuration
platformctl config validate

# Verify data directory
ls -la /var/lib/trusted-platform/
```

#### Step 3: Restore Barrier

```bash
# Obtain Shamir shares (from emergency contacts)
# Assuming 3 of 5 available

sudo platformctl barrier unseal \
    --share share-1.enc \
    --share share-2.enc \
    --share share-3.enc

# Verify unsealed
platformctl barrier status
```

#### Step 4: Restore CA and Keys

```bash
# CA was backed up, should be in backup
platformctl ca info

# If CA import needed
platformctl ca import --certificate ca-certificate.pem

# Issue new TLS certificates if needed
platformctl ca rotate --force
```

#### Step 5: Start Platform

```bash
# Start platform daemon
sudo systemctl start platformd

# Monitor startup
sleep 30
platformctl daemon status

# Verify services
platformctl service status

# Check health
curl -k https://localhost:8443/health
```

#### Step 6: Verify Data

```bash
# Verify DNS records
platformctl dns list

# Verify CA certificates
platformctl ca list

# Verify cluster
platformctl cluster status
```

### Partial Failure Recovery

#### Single Node Loss (Cluster)

```bash
# If node 2 fails in 3-node cluster:
# 1. Node automatically marked down
# 2. Services remain available (quorum intact)
# 3. Replace failed node

# On replacement node:
# Create new config with new node-id and join addresses
# Start platform
# Node automatically syncs data from cluster
```

#### Database Corruption

```bash
# If database is corrupted:
sudo systemctl stop platformd

# Backup corrupted data
sudo cp -r /var/lib/trusted-platform/quicbaas /var/lib/trusted-platform/quicbaas.corrupt

# Repair database
sudo platformctl storage repair

# If repair fails, restore from backup
sudo platformctl restore latest-backup.tar.gz --verify

sudo systemctl start platformd

# Verify
platformctl daemon status
```

#### Lost Barrier Shares

```bash
# There is no secret-less unseal, whatever the seal strategy (tpm2
# included); working hardware does not replace the shares.
# 1. Contact emergency contacts for shares
# 2. Reconstruct from threshold number of shares:
sudo platformctl barrier unseal-shares --share <s1> --share <s2> --share <s3>
# 3. Or recover with recovery shares, if they were generated:
sudo platformctl barrier recovery recover --share <r1> --share <r2> --share <r3>
# 4. If insufficient shares, complete infrastructure recovery required
```

See [Recovery keys](../barrier/user.md#recovery-keys).

## Backup Validation Checklist

Before declaring backup complete:

- [ ] Backup file exists and is readable
- [ ] Backup size is reasonable (not suspiciously small)
- [ ] Backup integrity verification passes
- [ ] Backup contains expected directories (quicbaas, ca, etc)
- [ ] Backup is readable after 30 days (test restore)
- [ ] Encryption key is stored securely separately
- [ ] Multiple copies exist in different locations
- [ ] Test restore completed successfully
- [ ] Services started and responded to health checks
- [ ] All data verified after restore

## Backup Schedule

### Recommended Schedule

```
Frequency: Hourly (automated)
Retention: 90 days
Full backups: Weekly (Sunday)
Incremental: Daily
Offsite: Daily to cloud
Shamir shares: On initialization, quarterly review
Configuration: After any changes
```

### Cron Jobs

```cron
# Hourly backups
0 * * * * root /usr/local/bin/platformctl backup create --destination /var/backups/trusted-platform/

# Weekly full backup
0 2 0 * * root /usr/local/bin/platformctl backup create --destination /var/backups/trusted-platform/ --type full

# S3 sync (daily)
0 3 * * * root aws s3 sync /var/backups/trusted-platform/ s3://my-bucket/backups/ --region us-east-1

# Cleanup old backups (>90 days)
0 4 * * * root find /var/backups/trusted-platform/ -name "backup-*.tar.gz" -mtime +90 -delete

# Monthly restore test
0 5 1 * * root /usr/local/bin/platformctl backup test-restore
```

## Backup Monitoring

### Alert on Backup Failure

```bash
# Check backup status
platformctl backup status

# Alert if no backup in 2 hours
if [[ $(date -d "$(platformctl backup status | grep "Last Backup")" +%s) -lt $(date +%s) - 7200 ]]; then
    send_alert "Backup failed: no successful backup in 2 hours"
fi
```

### Prometheus Metrics

```yaml
# Backup metrics
platform_backup_timestamp_seconds     # Last successful backup time
platform_backup_size_bytes            # Backup size
platform_backup_duration_seconds      # Backup duration
platform_backup_status                # 1=success, 0=failed
```

## Best Practices

1. **Test regularly** - Monthly test restores are critical
2. **Geographic diversity** - Keep copies in different locations
3. **Encryption** - Always encrypt backups at rest
4. **Separate keys** - Store encryption keys separately from backups
5. **Version control** - Track configuration changes in git
6. **Documentation** - Document all secrets management procedures
7. **Access control** - Restrict backup access to authorized personnel
8. **Automation** - Automate backup scheduling and verification
9. **Monitoring** - Alert on backup failures immediately
10. **Disaster drills** - Annual complete recovery test

## Related Documentation

- [Operational Runbook](operational-runbook.md) - Day-to-day procedures
- [Deployment Guide](deployment-guide.md) - Installation and configuration
- [Troubleshooting](troubleshooting.md) - Issue diagnosis and recovery
- [Cluster Configuration](../cluster/configuration.md) - Raft replication setup
