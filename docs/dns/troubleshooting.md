# DNS Troubleshooting Guide

Practical debugging guide for diagnosing and resolving DNS issues in the Trusted Platform.

## Overview

This guide covers common DNS issues and their solutions, diagnostic commands, and log analysis techniques. The Trusted Platform DNS server operates on separate ports for public (8053) and internal (9053) zones by default.

### Troubleshooting Approach

| Step | Action | Tools |
|------|--------|-------|
| 1 | Check server status | `platformctl`, `dig` |
| 2 | Verify zone configuration | `platformctl`, logs |
| 3 | Test record resolution | `dig`, `nslookup` |
| 4 | Validate DNSSEC | `dig +dnssec`, `delv` |
| 5 | Analyze logs | Server logs, audit logs |

## Quick Diagnostics

### Check Server Status

```bash
# Check DNS server status
platformctl dns server status

# Test public zone server (port 8053)
dig @localhost -p 8053 example.com SOA

# Test internal zone server (port 9053)
dig @localhost -p 9053 example.internal SOA

# Check if server is listening
ss -tlnp | grep -E '8053|9053'
```

### Check Zone Status

```bash
# Show zone details
platformctl dns zone show example.com

# Query all records in zone
dig @localhost -p 8053 example.com ANY

# List all zones
platformctl dns zone list
```

### Check DNSSEC Status

```bash
# Show DNSSEC status
platformctl dns dnssec status example.com

# Query DNSKEY records with DNSSEC validation
dig @localhost -p 8053 example.com DNSKEY +dnssec

# Verify DNSSEC chain
delv @localhost -p 8053 example.com A +rtrace
```

## Common Issues

### Server Won't Start

| Symptom | Cause | Solution |
|---------|-------|----------|
| `bind: address already in use` | Port conflict | Change port or stop conflicting server |
| `permission denied` | Non-root on privileged port | Use ports > 1024 or run with capabilities |
| `failed to load config` | Invalid YAML syntax | Validate configuration file |
| `datastore connection failed` | Database unavailable | Check datastore connectivity |
| `TPM not available` | TPM device missing | Verify TPM device or use software keys |

**Diagnosing Port Conflicts:**

```bash
# Find process using the port
ss -tlnp | grep 53
lsof -i :53

# Stop conflicting service (e.g., systemd-resolved)
sudo systemctl stop systemd-resolved

# Or change DNS server port
# In config.yaml:
dns:
  public:
    port: 8053
  internal:
    port: 9053
```

**Running on Privileged Ports:**

```bash
# Option 1: Use port redirection
sudo iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 8053
sudo iptables -t nat -A PREROUTING -p tcp --dport 53 -j REDIRECT --to-port 8053

# Option 2: Grant capability
sudo setcap cap_net_bind_service=+ep /usr/local/bin/platform-dns
```

### Zone Not Found

| Symptom | Cause | Solution |
|---------|-------|----------|
| `NXDOMAIN` for zone apex | Zone not created | Create zone with `platformctl dns zone create` |
| `REFUSED` | Zone name mismatch | Check trailing dot in zone name |
| `SERVFAIL` | Datastore error | Check datastore connectivity and logs |

**Troubleshooting Steps:**

```bash
# 1. List all zones to verify zone exists
platformctl dns zone list

# 2. Check zone name format (must have trailing dot internally)
platformctl dns zone show example.com.

# 3. Verify datastore connectivity
platformctl datastore status

# 4. Check server logs for errors
journalctl -u platform-dns -f
```

### Record Not Resolving

| Symptom | Cause | Solution |
|---------|-------|----------|
| `NXDOMAIN` | Record does not exist | Add record with `platformctl dns record add` |
| `NOERROR` but empty | Wrong record type | Query correct type (A vs AAAA) |
| Stale data | Cached response | Clear cache or wait for TTL expiry |
| Wrong IP returned | Multiple records | Check all records for the name |

**Troubleshooting Steps:**

```bash
# 1. List all records in zone
platformctl dns record list example.com

# 2. Query specific record type
dig @localhost -p 8053 www.example.com A +short
dig @localhost -p 8053 www.example.com AAAA +short

# 3. Check for CNAME chain
dig @localhost -p 8053 www.example.com CNAME

# 4. Query with trace to see resolution path
dig @localhost -p 8053 www.example.com A +trace

# 5. Clear cache if applicable
platformctl dns cache flush
```

### DNSSEC Validation Failures

| Error | Cause | Solution |
|-------|-------|----------|
| `RRSIG expired` | Signature validity period passed | Re-sign zone with `platformctl dns zone sign` |
| `DNSKEY missing` | Key not published in zone | Regenerate and publish key |
| `DS mismatch` | Parent zone has outdated DS | Submit new DS to parent |
| `bogus` response | Signature verification failed | Check key configuration, re-sign zone |
| `algorithm unsupported` | Client doesn't support algorithm | Use common algorithm (ECDSAP256SHA256) |
| `no valid RRSIG` | Zone not properly signed | Enable DNSSEC and sign zone |

**Troubleshooting Steps:**

```bash
# 1. Check DNSSEC status
platformctl dns dnssec status example.com

# 2. Verify DNSKEY records exist
dig @localhost -p 8053 example.com DNSKEY +dnssec +multi

# 3. Check signature validity
dig @localhost -p 8053 example.com A +dnssec | grep RRSIG

# 4. Verify with delv
delv @localhost -p 8053 example.com A +rtrace

# 5. Check DS record at parent
dig example.com DS @parent-ns.tld

# 6. Re-sign zone if needed
platformctl dns zone sign example.com --force
```

### Dynamic DNS Update Failures

| RCODE | Meaning | Solution |
|-------|---------|----------|
| `REFUSED` | Authentication failed | Check TSIG key name and secret |
| `NOTAUTH` | Server not authoritative | Verify primary server address |
| `SERVFAIL` | Internal server error | Check server logs |
| `NXRRSET` | Prerequisite not met | Check update prerequisites |
| `NOTZONE` | Zone not found | Verify zone exists |

**Troubleshooting Steps:**

```bash
# 1. Verify TSIG key configuration
platformctl dns tsig show update-key

# 2. Test dynamic update with nsupdate
nsupdate -k /path/to/update.key << EOF
server localhost 8053
zone example.com.
update add test.example.com. 300 A 192.0.2.100
send
EOF

# 3. Check server logs for update attempts
grep "dynamic update" /var/log/platform-dns.log

# 4. Verify zone allows updates
platformctl dns zone show example.com | grep -i update
```

### ACME Challenge Failures

| Issue | Cause | Solution |
|-------|-------|----------|
| Challenge timeout | TXT record not created | Verify ACME integration configured |
| Validation failed | DNS propagation delay | Increase propagation wait time |
| Invalid signature | DNSSEC signing failed | Check DNSSEC status, re-sign |
| Wrong value | Stale TXT record | Clean up old challenges |

**Troubleshooting Steps:**

```bash
# 1. Check if TXT record was created
dig @localhost -p 8053 _acme-challenge.example.com TXT

# 2. Verify record value matches challenge
platformctl dns record list example.com | grep _acme-challenge

# 3. Test external resolution
dig _acme-challenge.example.com TXT

# 4. Check DNSSEC on challenge record
dig @localhost -p 8053 _acme-challenge.example.com TXT +dnssec

# 5. Verify ACME configuration
platformctl acme config show
```

### Query Security Violations

| Error | Cause | Solution |
|-------|-------|----------|
| `public query for internal zone` | Client on wrong port | Direct internal queries to port 9053 |
| `unauthorized zone transfer` | Missing AXFR credentials | Configure zone transfer authentication |
| `rate limited` | Too many queries | Check rate limit settings |

**Troubleshooting Steps:**

```bash
# 1. Internal zones (*.internal) use port 9053
dig @localhost -p 9053 host.example.internal A

# 2. Public zones use port 8053
dig @localhost -p 8053 www.example.com A

# 3. Check zone type
platformctl dns zone show example.internal | grep type
```

## Log Analysis

### Enable Debug Logging

```yaml
# config.yaml
logging:
  level: debug
  dns:
    queries: true
    responses: true
    updates: true
    transfers: true
```

### Log Locations

| Log Type | Location | Contents |
|----------|----------|----------|
| Server logs | stdout or `/var/log/platform-dns.log` | Operational events |
| Query logs | Configured log path | DNS queries and responses |
| Security logs | Security log file | Access violations, auth failures |
| Audit logs | Datastore | Zone changes, key operations |

### Key Log Messages

**Successful Operations:**

```
INFO  Inbound DNS query qname=example.com qtype=A client=192.168.1.100
INFO  DNS response qname=example.com qtype=A rcode=NOERROR answers=1
INFO  Zone signed zone=example.com keys=2 rrsigs=15
INFO  Dynamic update accepted zone=example.com name=host.example.com type=A
```

**Error Conditions:**

```
ERROR received public query for internal zone zone=example.internal client=192.168.1.100
ERROR DNSSEC signing failed zone=example.com error="key not found"
ERROR dynamic update refused zone=example.com error="TSIG verification failed"
ERROR zone transfer denied zone=example.com client=10.0.0.50 error="unauthorized"
```

**Warning Conditions:**

```
WARN  RRSIG expires soon zone=example.com expires_in=2h
WARN  rate limit exceeded client=192.168.1.100 queries=1000
WARN  cache size approaching limit current=950MB max=1024MB
```

### Log Filtering

```bash
# Filter by zone
grep "zone=example.com" /var/log/platform-dns.log

# Filter by client
grep "client=192.168.1.100" /var/log/platform-dns.log

# Filter errors only
grep "ERROR" /var/log/platform-dns.log

# Filter DNSSEC events
grep -E "(DNSSEC|RRSIG|DNSKEY)" /var/log/platform-dns.log

# Follow logs in real-time
tail -f /var/log/platform-dns.log | grep -E "(ERROR|WARN)"
```

## Diagnostic Commands

### DNS Queries

```bash
# Basic A record query
dig @localhost -p 8053 example.com A

# Query with full details
dig @localhost -p 8053 example.com A +noall +answer +authority +additional

# Query with DNSSEC validation
dig @localhost -p 8053 example.com A +dnssec +multi

# Trace resolution path
dig @localhost -p 8053 example.com A +trace

# Query specific record type
dig @localhost -p 8053 example.com MX
dig @localhost -p 8053 example.com TXT
dig @localhost -p 8053 example.com SOA

# Reverse lookup
dig @localhost -p 8053 -x 192.0.2.1

# Check NSEC3 parameters
dig @localhost -p 8053 example.com NSEC3PARAM

# Query for ANY records (may be limited)
dig @localhost -p 8053 example.com ANY
```

### DNSSEC Verification

```bash
# Check DNSKEY records
dig @localhost -p 8053 example.com DNSKEY +dnssec +multi

# Check DS record at parent
dig example.com DS @parent-ns.tld

# Verify complete chain of trust
delv @localhost -p 8053 example.com A +rtrace

# Check signature expiration
dig @localhost -p 8053 example.com RRSIG | grep -E "RRSIG.*A"

# Verify specific key tag
dig @localhost -p 8053 example.com DNSKEY | grep "12345"
```

### Network Diagnostics

```bash
# Check listening ports
ss -tlnp | grep -E '8053|9053'
netstat -tulpn | grep -E '8053|9053'

# Test TCP connectivity
nc -zv localhost 8053
nc -zv localhost 9053

# Test UDP connectivity
nc -zuv localhost 8053

# Capture DNS traffic
sudo tcpdump -i lo port 8053 -w dns.pcap
sudo tcpdump -i any port 8053 -nn

# Analyze captured traffic
tcpdump -r dns.pcap -nn

# Check firewall rules
iptables -L -n | grep 53
```

### Platform CLI Diagnostics

```bash
# Server health check
platformctl dns server status
platformctl dns server health

# Zone diagnostics
platformctl dns zone show example.com
platformctl dns zone validate example.com

# Record diagnostics
platformctl dns record list example.com
platformctl dns record show example.com www A

# DNSSEC diagnostics
platformctl dns dnssec status example.com
platformctl dns dnssec keys example.com
platformctl dns dnssec verify example.com

# Datastore diagnostics
platformctl datastore status
```

## Recovery Procedures

### Corrupted Zone Recovery

```bash
# 1. Export current zone (if possible)
platformctl dns zone export example.com > backup.zone

# 2. Delete corrupted zone
platformctl dns zone delete example.com --force

# 3. Recreate zone
platformctl dns zone create example.com

# 4. Import records from backup
platformctl dns zone import example.com < backup.zone

# 5. Re-enable DNSSEC if needed
platformctl dns dnssec enable example.com

# 6. Sign zone
platformctl dns zone sign example.com

# 7. Verify zone
platformctl dns zone validate example.com
```

### DNSSEC Key Recovery

**ZSK Compromise:**

```bash
# 1. Generate new ZSK immediately
platformctl dns dnssec rollover example.com --key zsk --emergency

# 2. Re-sign zone with new key
platformctl dns zone sign example.com --force

# 3. Revoke old key
platformctl dns dnssec revoke example.com --key-tag <old-tag>
```

**KSK Compromise:**

```bash
# 1. Generate new KSK
platformctl dns dnssec rollover example.com --key ksk --emergency

# 2. Generate new DS record
platformctl dns dnssec show-ds example.com

# 3. Submit new DS to parent zone immediately

# 4. Re-sign zone
platformctl dns zone sign example.com --force

# 5. After DS propagation, remove old KSK
platformctl dns dnssec revoke example.com --key-tag <old-tag>
```

### Datastore Recovery

```bash
# 1. Stop DNS server
platformctl dns server stop

# 2. Check datastore status
platformctl datastore status

# 3. Restore datastore from backup
platformctl datastore restore --from /backup/dns-backup.db

# 4. Verify zones restored
platformctl dns zone list

# 5. Restart DNS server
platformctl dns server start

# 6. Verify resolution
dig @localhost -p 8053 example.com SOA
```

### Signature Expiration Recovery

```bash
# 1. Check which zones have expired signatures
platformctl dns dnssec check-expiration

# 2. Re-sign affected zones
platformctl dns zone sign example.com --force

# 3. Verify new signatures
dig @localhost -p 8053 example.com A +dnssec | grep RRSIG

# 4. Set up monitoring for future expiration
platformctl dns dnssec monitor --enable
```

## Performance Tuning

### Query Performance

| Setting | Default | Tuned | Impact |
|---------|---------|-------|--------|
| Read buffer size | 4KB | 16KB | Faster large responses |
| Write buffer size | 4KB | 16KB | Faster large queries |
| Worker threads | Auto | CPU count | Parallelism |
| Cache size | 256MB | 1024MB | More cached responses |

```yaml
# config.yaml - performance tuning
dns:
  performance:
    read_buffer_size: 16384
    write_buffer_size: 16384
    worker_threads: 8

  cache:
    enabled: true
    max_size: 1024MB
    max_ttl: 86400
    negative_ttl: 300
```

### Resolver Optimization

```yaml
dns:
  resolver:
    # Use multiple forwarders for redundancy
    forwarders:
      - 8.8.8.8:53
      - 8.8.4.4:53
      - 1.1.1.1:53

    # Connection pooling
    max_connections: 100
    idle_timeout: 60s

    # Timeout settings
    query_timeout: 5s
    retry_count: 3
```

### DNSSEC Signing Performance

```yaml
dnssec:
  # Use hardware acceleration when available
  hardware_acceleration: true

  # Parallel signing
  signing_threads: 4

  # Pre-compute signatures
  signature_cache: true

  # Batch signing operations
  batch_size: 1000
```

## Getting Help

### Before Requesting Support

1. **Check logs** - Review server logs for error messages
2. **Gather diagnostics** - Run diagnostic commands listed above
3. **Document steps** - Note what you've tried and results
4. **Collect configuration** - Sanitize and include relevant config

### Information to Include

```bash
# Collect diagnostic bundle
platformctl support-bundle --output dns-debug.tar.gz

# Include:
# - Server version
platformctl version

# - DNS configuration (sanitized)
platformctl dns config show

# - Zone list
platformctl dns zone list

# - Server status
platformctl dns server status

# - Recent logs
journalctl -u platform-dns --since "1 hour ago" > dns-logs.txt
```

### Useful Resources

| Resource | Description |
|----------|-------------|
| [Architecture](architecture.md) | DNS system architecture |
| [Zones](zones.md) | Zone management guide |
| [DNSSEC](dnssec.md) | DNSSEC signing documentation |
| [Key Rollover](dnssec-rollover.md) | Key rollover procedures |
| [Dynamic DNS](dynamic-dns.md) | Dynamic update guide |
| [ACME Integration](acme-integration.md) | Certificate automation |

## Related Documentation

| Document | Description |
|----------|-------------|
| [README](README.md) | DNS overview |
| [Configuration](../configuration.md) | Platform configuration |
| [KMS](../kms/README.md) | Key management |
| [TPM](../tpm/README.md) | TPM integration |
