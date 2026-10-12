# Troubleshooting Guide

Diagnosis and resolution procedures for common go-trusted-platform issues.

## Quick Diagnostics

Start with automated diagnostics:

```bash
# Run full diagnostic suite
sudo platformctl diag run --full

# Save diagnostics for support
sudo platformctl diag export > diagnostics-$(date +%Y%m%d-%H%M%S).tar.gz
```

## Startup Failures

### Platform Won't Start

**Symptoms:** `systemctl start platformd` fails or exits immediately

**Diagnosis:**

```bash
# Check service status
sudo systemctl status platformd -l

# View logs
sudo journalctl -u platformd -n 50 -p err

# Run validation
./platformd config validate --config config.yaml

# Run with debug output
sudo ./platformd serve --config config.yaml --log-level debug 2>&1 | head -100
```

**Common Causes and Fixes:**

| Cause | Error Message | Fix |
|-------|---------------|-----|
| Invalid config | `failed to parse config` | Run `platformd config validate` |
| Missing directories | `permission denied creating /var/lib/...` | `sudo mkdir -p /var/lib/trusted-platform && sudo chmod 700` |
| Port in use | `address already in use :8443` | Check with `sudo lsof -i :8443` and kill process |
| TPM not accessible | `failed to open tpm device` | `ls -la /dev/tpm* /dev/tpmrm*` and verify permissions |
| Config file not found | `no such file or directory` | Use full path: `--config /etc/trusted-platform/config.yaml` |

**Resolution Steps:**

```bash
# 1. Validate configuration
./platformd config validate --config config.yaml

# 2. Check file permissions
ls -la /var/lib/trusted-platform/
ls -la /etc/trusted-platform/config.yaml

# 3. Check required directories exist
mkdir -p /var/lib/trusted-platform/{log,quicbaas,ca}
mkdir -p /etc/trusted-platform

# 4. Start with debug logging
sudo ./platformd serve --config config.yaml --log-level debug &
sleep 5
kill %1

# 5. Check logs for specific errors
sudo journalctl -u platformd --since "5 minutes ago"
```

### Out of Memory on Startup

**Symptoms:** Process killed by OOM killer, crash on startup

**Diagnosis:**

```bash
# Check available memory
free -h

# Check QuicBaaS cache size
grep cache-size config.yaml

# Check memory limits
systemctl show platformd -p MemoryLimit
```

**Fixes:**

```yaml
# In config.yaml, reduce cache
quicbaas:
  cache-size: 33554432  # Reduce from 64MB to 32MB
```

```bash
# Increase system memory
# Or run fewer services simultaneously

# Monitor memory during startup
watch -n1 'free -h && ps aux | grep platformd'
```

### Configuration Parsing Errors

**Symptoms:** `error parsing config.yaml` on startup

**Diagnosis:**

```bash
# Validate YAML syntax
python3 -m yaml config.yaml

# Or use online validator
cat config.yaml | curl -X POST -d @- https://www.yamllint.com/

# Check Go can parse it
./platformd config validate --config config.yaml
```

**Common Issues:**

```yaml
# WRONG: Invalid indentation
quicbaas:
    storage-backend: pebble  # Bad: 4 spaces
  cache-size: 67108864       # Bad: 2 spaces

# RIGHT: Consistent indentation
quicbaas:
  storage-backend: pebble    # Good: 2 spaces
  cache-size: 67108864       # Good: 2 spaces

# WRONG: Unquoted values with special chars
domain: example.test-1  # Hyphen requires quotes in some contexts

# RIGHT: Quote when in doubt
domain: "example.test"
```

## TLS and Certificate Issues

### Certificate Validation Errors

**Symptoms:** `certificate verify failed`, `x509: certificate signed by unknown authority`

**Diagnosis:**

```bash
# Check certificate
openssl x509 -in /var/lib/trusted-platform/ca/certificate.pem -text -noout

# Check certificate chain
openssl verify -CAfile /var/lib/trusted-platform/ca/certificate.pem \
    /var/lib/trusted-platform/ca/certificate.pem

# Check what clients see
echo | openssl s_client -connect localhost:8443 2>/dev/null | grep -A5 "subject="
```

**Fixes:**

```bash
# Trust the platform CA certificate
sudo cp /var/lib/trusted-platform/ca/certificate.pem \
    /usr/local/share/ca-certificates/platform-ca.crt
sudo update-ca-certificates

# In Go code
client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{
            RootCAs: certPool,  // Load platform CA here
        },
    },
}

# In curl
curl -k --cacert /var/lib/trusted-platform/ca/certificate.pem \
    https://localhost:8443/health
```

### Certificate Expired

**Symptoms:** `certificate has expired`, `not valid after`

**Diagnosis:**

```bash
# Check expiration
platformctl ca info | grep -A2 "Not After"

# Calculate days until expiration
openssl x509 -enddate -noout -in /var/lib/trusted-platform/ca/certificate.pem
```

**Fix:**

```bash
# Rotate certificate (generates new, old retired)
sudo platformctl ca rotate

# Verify new cert
platformctl ca info | grep -A2 "Not After"

# Update clients
sudo cp /var/lib/trusted-platform/ca/certificate.pem \
    /usr/local/share/ca-certificates/platform-ca.crt
sudo update-ca-certificates
```

### mTLS Connection Refused

**Symptoms:** `tls: alert unknown ca`, connection refused on gRPC

**Diagnosis:**

```bash
# Test with explicit certs
grpcurl -cert client.pem -key client-key.pem \
    -cacert ca.pem localhost:10443 list

# Check certificate is from platform CA
openssl x509 -in client.pem -issuer -noout
```

**Fix:**

```bash
# Generate valid client certificate from platform CA
platformctl ca issue \
    --cn=my-client \
    --type client \
    --output-cert client.pem \
    --output-key client-key.pem

# Verify issuer matches platform CA
openssl verify -CAfile ca.pem client.pem
```

## Barrier and Sealing Issues

### Barrier Sealed on Startup

**Symptoms:** Services unavailable, `barrier: sealed, waiting for unseal command`

**Diagnosis:**

```bash
# Check barrier status
platformctl barrier status

# Check the seal strategy and Shamir layout
grep -A5 "barrier:" config.yaml
```

**Fixes:** This is expected after every restart. `platformd` never unseals the
barrier itself, whatever the seal strategy (`tpm2` included); an operator
unseals it. See
[Unsealing after a restart](../barrier/user.md#unsealing-after-a-restart).

```bash
# Single-secret barrier
sudo platformctl barrier unseal --passphrase <passphrase>

# Or Shamir barrier
sudo platformctl barrier unseal-shares --share <s1> --share <s2> --share <s3>

# Verify unsealed
platformctl barrier status
```

### Lost Barrier Shares

**Symptoms:** Cannot unseal barrier, shares not found

**Diagnosis:**

```bash
# Check for shares on disk
ls -la /var/lib/trusted-platform/barrier/shares/

# If not found, contact emergency contacts
echo "Need to retrieve Shamir shares from emergency contacts"
```

**Recovery:**

```bash
# There is no secret-less unseal, whatever the seal strategy (tpm2
# included). A Shamir barrier needs a threshold of shares.

# If shares needed, obtain from:
# - Emergency contacts
# - Cloud storage (if backed up)
# - Off-site locations

# Submit the threshold number of shares
sudo platformctl barrier unseal-shares \
    --share <s1> --share <s2> --share <s3>
```

Without a threshold of barrier shares, recovery shares made earlier with
`platformctl barrier recovery generate` are the remaining path; see
[Recovery keys](../barrier/user.md#recovery-keys).

```bash
sudo platformctl barrier recovery recover --share <r1> --share <r2> --share <r3>
```

### Barrier Unseal Fails

**Symptoms:** `invalid unseal response`, unseal fails with valid shares

**Diagnosis:**

```bash
# Check shares exist and are readable
file /var/lib/trusted-platform/barrier/shares/*

# Verify share count
ls -1 /var/lib/trusted-platform/barrier/shares/ | wc -l

# Check if meets threshold
grep threshold config.yaml
```

**Fixes:**

```bash
# Ensure using correct threshold number of shares
# If threshold is 3, provide at least 3

# Verify share integrity
platformctl barrier shares validate --share share-1.enc

# Try providing more shares than threshold
sudo platformctl barrier unseal \
    --share share-1.enc \
    --share share-2.enc \
    --share share-3.enc \
    --share share-4.enc
```

## Service Connectivity Issues

### Service Not Responding

**Symptoms:** Timeout connecting to service, connection refused

**Diagnosis:**

```bash
# Check if service is running
platformctl service status --service ca

# Check service port is listening
ss -tlnp | grep 8443
ss -tlnp | grep 10443
ss -ulnp | grep 9444

# Test connectivity
curl -k https://localhost:8443/health
grpcurl localhost:10443 list
nc -zv localhost 9444
```

**Fixes:**

```bash
# Restart service
platformctl service restart --service ca

# Check logs
platformctl daemon logs --service ca --level error

# Verify network connectivity
ping localhost

# Check firewall
sudo iptables -L -n | grep 8443
```

### Port Already in Use

**Symptoms:** `address already in use :8443`

**Diagnosis:**

```bash
# Find process using port
sudo lsof -i :8443
sudo netstat -tulpn | grep 8443

# Get PID
ps aux | grep <PID>
```

**Fixes:**

```bash
# Kill process using port
sudo kill -9 <PID>

# Or change platform port in config
# In config.yaml:
api:
  rest:
    port: 8444  # Changed from 8443

# Restart platform
sudo systemctl restart platformd
```

### gRPC Connection Timeout

**Symptoms:** gRPC calls hang or timeout

**Diagnosis:**

```bash
# Test gRPC connectivity
grpcurl -plaintext localhost:10443 list

# Check gRPC port is listening
ss -tlnp | grep 10443

# Enable gRPC debug logging
export GODEBUG=http2debug=2
grpcurl localhost:10443 list 2>&1 | head -50
```

**Fixes:**

```bash
# Ensure gRPC is enabled in config
grep -A2 "grpc:" config.yaml

# Restart with debug logging
sudo journalctl -u platformd -f
platformctl service restart --service ca

# Check logs for gRPC errors
grep -i grpc /var/log/trusted-platform/platformd.log
```

## TPM Issues

### TPM Device Not Found

**Symptoms:** `cannot access tpm device`, tpm info fails

**Diagnosis:**

```bash
# Check TPM device exists
ls -la /dev/tpm* /dev/tpmrm*

# Check TPM availability
cat /proc/cmdline | grep -i tpm

# Check permissions
sudo getcap /dev/tpmrm0
```

**Fixes:**

```bash
# For resource manager (recommended)
ls -la /dev/tpmrm0

# If not available, use standard TPM
# In config.yaml:
tpm:
  device: /dev/tpm0

# For systemd, ensure service has TPM access
# In systemd service:
[Service]
DeviceAllow=/dev/tpm0 rw
DeviceAllow=/dev/tpmrm0 rw
```

### TPM Initialization Failed

**Symptoms:** TPM provision fails, `failed to initialize tpm`

**Diagnosis:**

```bash
# Check TPM info
platformctl tpm info

# Check if already provisioned
platformctl tpm info | grep -i provisioned

# Try clearing TPM
sudo platformctl tpm clear
```

**Fixes:**

```bash
# Clear TPM (WARNING: destroys all keys)
sudo platformctl tpm clear

# Re-provision
sudo platformctl tpm provision

# With policy
sudo platformctl tpm provision --enable-policy-pcr

# Verify
platformctl tpm info
```

### PCR Mismatch

**Symptoms:** TPM sealed data cannot unseal, PCR mismatch

**Diagnosis:**

```bash
# View current PCR values
platformctl tpm pcr read --pcrs 0,1,7

# Reseal with current values
echo "Need to remeasure or adjust PCR policy"
```

**Fixes:**

```bash
# Reseal with current PCR state
platformctl tpm seal --recalculate-pcrs \
    --input /tmp/my-secret \
    --output /tmp/sealed.bin

# Or disable PCR verification for testing
platformctl tpm seal --no-verify-pcrs \
    --input /tmp/my-secret \
    --output /tmp/sealed.bin
```

## Database and Storage Issues

### Database Locked

**Symptoms:** `database is locked`, cannot acquire lock

**Diagnosis:**

```bash
# Check database processes
ps aux | grep quicbaas
lsof /var/lib/trusted-platform/quicbaas/

# Check file locks
fuser /var/lib/trusted-platform/quicbaas/*

# Check if multiple instances running
systemctl is-active platformd
ps aux | grep platformd
```

**Fixes:**

```bash
# Kill extra instances
sudo killall platformd

# Restart
sudo systemctl restart platformd

# If still locked, force remove lock file
sudo rm -f /var/lib/trusted-platform/quicbaas/.lock
sudo systemctl restart platformd
```

### Database Corruption

**Symptoms:** `data corruption detected`, `invalid database header`

**Diagnosis:**

```bash
# Check database integrity
platformctl storage check

# View database status
platformctl storage info

# Check filesystem
sudo fsck -n /var/lib/trusted-platform
```

**Fixes:**

```bash
# Step 1: Backup corrupted data
sudo cp -r /var/lib/trusted-platform/quicbaas \
    /var/lib/trusted-platform/quicbaas.corrupt

# Step 2: Attempt repair
sudo platformctl storage repair

# Step 3: Restart
sudo systemctl restart platformd

# Step 4: Verify
platformctl daemon status

# If repair fails, restore from backup
sudo platformctl restore latest-backup.tar.gz
```

### Disk Space Low

**Symptoms:** `no space left on device`, writes fail

**Diagnosis:**

```bash
# Check disk usage
df -h /var/lib/trusted-platform

# Check data directory size
du -sh /var/lib/trusted-platform/*

# Identify large files
find /var/lib/trusted-platform -type f -size +100M
```

**Fixes:**

```bash
# Clean logs
find /var/log/trusted-platform -name "*.log" -mtime +30 -delete

# Compact database
sudo platformctl storage compact

# Clear temporary files
sudo rm -rf /tmp/platform*

# Archive old backups
tar czf /archive/old-backups.tar.gz -C /var/backups/trusted-platform .
rm -rf /var/backups/trusted-platform/*

# Check filesystem for cleanup
sudo du -sh /var/*  # Identify large dirs
```

## Cluster Issues

### Node Down

**Symptoms:** One cluster member unreachable, cluster degraded

**Diagnosis:**

```bash
# Check cluster status
platformctl cluster status

# Check member status
platformctl cluster members

# Check network connectivity
ping <node-ip>
nc -zv <node-ip> 63000  # Raft port
```

**Fixes:**

```bash
# If node recovers, it auto-rejoins
# Monitor startup
ssh node2 sudo journalctl -u platformd -f

# If node permanently lost, remove it
platformctl cluster remove-node --id 2

# Verify removed
platformctl cluster members
```

### Quorum Lost

**Symptoms:** `lost quorum`, cluster unavailable, promotion fails

**Diagnosis:**

```bash
# Check member count
platformctl cluster members | wc -l

# Need majority for quorum
# 3 nodes need 2 alive
# 5 nodes need 3 alive
```

**Recovery:**

```bash
# Identify which node was leader
platformctl cluster leader

# Bring that node back online (highest priority)
ssh leader-node sudo systemctl start platformd

# If leader permanently lost, wait for follower election
# Takes 2-3 seconds after leader down
sleep 5
platformctl cluster leader

# If still no quorum, force bootstrapping
sudo platformctl cluster bootstrap
```

### Raft Log Corruption

**Symptoms:** Raft logs corrupted, node won't rejoin

**Diagnosis:**

```bash
# Check Raft logs
platformctl cluster logs --limit 10

# Node stuck, not syncing
platformctl cluster status | grep node
```

**Fixes:**

```bash
# On affected node:
# Stop node
ssh node2 sudo systemctl stop platformd

# Backup Raft logs
ssh node2 sudo cp -r /var/lib/trusted-platform/quicbaas/raft \
    /var/lib/trusted-platform/quicbaas/raft.backup

# Clear Raft logs
ssh node2 sudo rm -rf /var/lib/trusted-platform/quicbaas/raft/*

# Restart node (will rejoin and sync)
ssh node2 sudo systemctl start platformd

# Monitor sync
ssh node2 sudo journalctl -u platformd -f | grep raft
```

## Performance Issues

### High CPU Usage

**Symptoms:** `platformd` using 100% CPU, system slow

**Diagnosis:**

```bash
# Check CPU usage
top -p $(pgrep platformd)

# Check goroutine count
platformctl daemon debug goroutines | head -20

# Profile CPU
platformctl daemon debug pprof profile --seconds 30 > cpu.prof
go tool pprof cpu.prof
```

**Causes and Fixes:**

| Cause | Detection | Fix |
|-------|-----------|-----|
| Stuck goroutine | `too many goroutines` | Restart platformd |
| Infinite loop in service | `high CPU single thread` | Check service logs |
| Raft consensus issue | `raft` in goroutine stacks | Check cluster status |
| DNS recursion loop | `dns` in goroutine stacks | Check DNS configuration |

**Fix:**

```bash
# Identify problematic goroutine
platformctl daemon debug stacks | grep -A10 "on CPU"

# Restart service
platformctl service restart --service <service>

# Or restart platform
sudo systemctl restart platformd
```

### High Memory Usage

**Symptoms:** Memory grows over time, OOM killer triggers

**Diagnosis:**

```bash
# Check memory usage
ps aux | grep platformd | head -1

# Profile heap
platformctl daemon debug heap --seconds 10 > heap.prof
go tool pprof heap.prof

# Check for memory leaks
# Compare heap profiles over time
platformctl daemon debug heap > heap1.prof
sleep 300
platformctl daemon debug heap > heap2.prof
go tool pprof -base heap1.prof heap2.prof
```

**Fixes:**

```bash
# Force garbage collection
platformctl daemon gc

# Reduce cache size
# In config.yaml:
quicbaas:
  cache-size: 33554432  # Reduce to 32MB

# Restart
sudo systemctl restart platformd

# Monitor memory
watch -n5 'ps aux | grep platformd | head -1'
```

### Slow Requests

**Symptoms:** API responses take >1 second, timeouts

**Diagnosis:**

```bash
# Check request latency
curl -w "@curl-format.txt" -o /dev/null -s \
    https://localhost:8443/health

# Trace request
strace -e trace=network curl https://localhost:8443/health 2>&1 | grep -i time

# Check service logs
platformctl daemon logs --level debug --since "1m"
```

**Causes and Fixes:**

| Cause | Detection | Fix |
|-------|-----------|-----|
| High CPU | CPU high during requests | See CPU troubleshooting |
| High memory pressure | Memory near limit | See memory troubleshooting |
| Disk I/O | `iowait` high in `top` | Check disk speed, reduce concurrent requests |
| Network latency | `nc` to port slow | Check network, firewall rules |

**Performance optimization:**

```yaml
# In config.yaml, increase concurrency
services:
  worker-threads: 16  # Increase for parallel requests
```

## Log Analysis

### Enable Debug Logging

```bash
# In systemd service:
[Service]
Environment="LOG_LEVEL=debug"

# Or at runtime:
platformctl daemon logs --level debug

# View debug logs
sudo journalctl -u platformd --since "30 minutes ago"
```

### Search Logs for Errors

```bash
# Errors in last 24 hours
sudo journalctl -u platformd -p err --since "24 hours ago"

# Warnings
sudo journalctl -u platformd -p warning --since "1 hour ago"

# Specific service
sudo journalctl -u platformd -p err | grep "dns:"

# Export for analysis
sudo journalctl -u platformd -o json > logs.json
jq '.MESSAGE' logs.json | grep -i error
```

### Common Error Messages

| Error | Cause | Fix |
|-------|-------|-----|
| `connection refused` | Service not running | Restart service |
| `permission denied` | Wrong permissions on file/device | `sudo chown root:root`, `chmod 600` |
| `address already in use` | Port conflict | Kill process using port |
| `certificate verify failed` | Trust chain broken | Re-trust CA certificate |
| `database is locked` | Multiple processes accessing | Kill extra instances |
| `context deadline exceeded` | Timeout | Increase timeout, check load |

## Support and Escalation

### Gather Diagnostic Information

```bash
# Run diagnostic suite
sudo platformctl diag run --full

# Export for support
sudo platformctl diag export > diagnostics.tar.gz

# Include system information
uname -a > system-info.txt
free -h >> system-info.txt
df -h >> system-info.txt

# Include configuration (redact secrets!)
grep -v -E "(password|key|secret|token)" config.yaml > config-redacted.yaml
```

### Get Professional Support

- **GitHub Issues**: https://github.com/jeremyhahn/go-trusted-platform/issues
- **Discord Community**: https://discord.gg/TuJex32b
- **Commercial Support**: licensing@automatethethings.com

Include in support request:
1. Diagnostic bundle
2. Configuration (redacted)
3. Recent logs
4. Steps to reproduce
5. Expected vs actual behavior

## Related Documentation

- [Operational Runbook](operational-runbook.md) - Procedures and commands
- [Deployment Guide](deployment-guide.md) - Configuration and setup
- [Backup & Recovery](backup-recovery.md) - Data recovery procedures
