# DNS Operations Guide

> **Status: REFERENCE**
> Day-to-day operational procedures for the Trusted Platform DNS subsystem.

## Overview

This guide covers operational aspects of managing the DNS subsystem including monitoring, maintenance, backup and recovery, and capacity planning. These procedures ensure reliable DNS service delivery and enable proactive issue detection.

### Operational Responsibilities

| Area | Description |
|------|-------------|
| **Monitoring** | Health checks, metrics collection, alerting |
| **Maintenance** | Scheduled tasks, updates, housekeeping |
| **Backup/Recovery** | Zone backups, disaster recovery procedures |
| **Capacity Planning** | Resource sizing, performance optimization |

## Monitoring

### Health Check Configuration

Enable health checks to monitor DNS server status:

```yaml
dns:
  health:
    enabled: true
    endpoint: "/health"
    port: 8054
    checks:
      zone-loaded: true
      resolver-available: true
      dnssec-valid: true
      datastore-connected: true
```

### Health Check Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Overall health status |
| `/health/ready` | GET | Readiness probe for load balancers |
| `/health/live` | GET | Liveness probe for orchestrators |
| `/health/zones` | GET | Zone loading status |
| `/health/dnssec` | GET | DNSSEC signing status |

**Health Check Response:**

```json
{
  "status": "healthy",
  "timestamp": "2025-01-15T10:30:00Z",
  "checks": {
    "zone-loaded": {
      "status": "pass",
      "zones": 5
    },
    "resolver-available": {
      "status": "pass",
      "forwarders": ["8.8.8.8", "8.8.4.4"]
    },
    "dnssec-valid": {
      "status": "pass",
      "signed_zones": 3
    },
    "datastore-connected": {
      "status": "pass",
      "backend": "LOCAL"
    }
  }
}
```

### Metrics

The DNS subsystem exposes Prometheus-compatible metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `dns_queries_total` | Counter | Total DNS queries received (labels: zone, type, rcode) |
| `dns_query_duration_seconds` | Histogram | Query processing latency |
| `dns_responses_total` | Counter | Total DNS responses sent (labels: zone, rcode) |
| `dns_zone_records` | Gauge | Number of records per zone (labels: zone, type) |
| `dns_cache_size` | Gauge | Current cache size in bytes |
| `dns_cache_hits_total` | Counter | Cache hit count |
| `dns_dnssec_signatures` | Gauge | Number of active signatures per zone |
| `dns_dnssec_signature_expiry` | Gauge | Time until signature expiration (seconds) |

### Prometheus Configuration

Configure Prometheus to scrape DNS metrics:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'trusted-platform-dns'
    static_configs:
      - targets: ['localhost:8054']
    metrics_path: '/metrics'
    scrape_interval: 15s
    scrape_timeout: 10s
```

### Grafana Dashboard

Key metrics to display:

```
# Query rate panel
rate(dns_queries_total[5m])

# Query latency panel (p99)
histogram_quantile(0.99, rate(dns_query_duration_seconds_bucket[5m]))

# Error rate panel
rate(dns_responses_total{rcode!="NOERROR"}[5m]) / rate(dns_responses_total[5m])

# Cache hit ratio panel
rate(dns_cache_hits_total[5m]) / rate(dns_queries_total[5m])

# DNSSEC signature expiry panel
dns_dnssec_signature_expiry
```

## Alerting

### Alert Rules

Configure alerting rules for critical DNS conditions:

```yaml
# dns-alerts.yaml
groups:
  - name: dns-alerts
    rules:
      - alert: DNSQueryLatencyHigh
        expr: histogram_quantile(0.99, rate(dns_query_duration_seconds_bucket[5m])) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "DNS query latency is high"
          description: "99th percentile query latency is {{ $value | humanizeDuration }} (threshold: 100ms)"

      - alert: DNSSECSignatureExpiring
        expr: dns_dnssec_signature_expiry < 86400
        for: 1h
        labels:
          severity: critical
        annotations:
          summary: "DNSSEC signature expiring soon"
          description: "Zone {{ $labels.zone }} signature expires in {{ $value | humanizeDuration }}"

      - alert: DNSZoneStale
        expr: time() - dns_zone_last_update > 86400
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "DNS zone has not been updated"
          description: "Zone {{ $labels.zone }} last updated {{ $value | humanizeDuration }} ago"

      - alert: DNSServerDown
        expr: up{job="trusted-platform-dns"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "DNS server is down"
          description: "DNS server on {{ $labels.instance }} is not responding"

      - alert: DNSErrorRateHigh
        expr: rate(dns_responses_total{rcode!="NOERROR"}[5m]) / rate(dns_responses_total[5m]) > 0.05
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "DNS error rate is elevated"
          description: "Error rate is {{ $value | humanizePercentage }} (threshold: 5%)"

      - alert: DNSCacheFullness
        expr: dns_cache_size / dns_cache_max_size > 0.9
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "DNS cache is nearly full"
          description: "Cache is {{ $value | humanizePercentage }} full"
```

### Alert Notification

Configure alert routing for DNS alerts:

```yaml
# alertmanager.yml
route:
  group_by: ['alertname', 'zone']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h
  receiver: 'dns-team'
  routes:
    - match:
        severity: critical
      receiver: 'dns-oncall'
      continue: true

receivers:
  - name: 'dns-team'
    email_configs:
      - to: 'dns-team@example.com'

  - name: 'dns-oncall'
    pagerduty_configs:
      - service_key: '<pagerduty-key>'
```

## Backup and Recovery

### Zone Backup

#### Manual Backup

Export zones for backup:

```bash
# Backup a single zone
platformctl dns zone export example.com --output /backup/dns/example.com.zone

# Backup all zones
platformctl dns zone export --all --output-dir /backup/dns/zones/

# Backup with DNSSEC keys
platformctl dns zone export example.com \
  --include-keys \
  --output /backup/dns/example.com.zone

# Backup zone to stdout (for piping)
platformctl dns zone export example.com | gzip > /backup/dns/example.com.zone.gz
```

#### Scheduled Backup Configuration

Configure automated backups:

```yaml
# config.yaml
dns:
  backup:
    enabled: true
    schedule: "0 2 * * *"  # Daily at 2 AM
    retention: 30          # Keep 30 days of backups
    destination: "/backup/dns"
    compress: true
    include-keys: true
    notify-on-failure: true
```

**Backup Script Example:**

```bash
#!/bin/bash
# /etc/cron.daily/dns-backup

BACKUP_DIR="/backup/dns/$(date +%Y%m%d)"
RETENTION_DAYS=30

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Export all zones
platformctl dns zone export --all \
  --include-keys \
  --output-dir "$BACKUP_DIR"

# Compress backups
tar -czf "$BACKUP_DIR.tar.gz" -C "$(dirname $BACKUP_DIR)" "$(basename $BACKUP_DIR)"
rm -rf "$BACKUP_DIR"

# Clean old backups
find /backup/dns -name "*.tar.gz" -mtime +$RETENTION_DAYS -delete

# Verify backup integrity
platformctl dns zone verify --backup "$BACKUP_DIR.tar.gz"
```

### Recovery Procedures

#### Zone Recovery

Restore zones from backup:

```bash
# Restore a single zone
platformctl dns zone import /backup/dns/example.com.zone

# Restore all zones from backup directory
platformctl dns zone import --all --from-dir /backup/dns/zones/

# Restore from compressed backup
gunzip -c /backup/dns/example.com.zone.gz | platformctl dns zone import -

# Restore with DNSSEC re-signing
platformctl dns zone import /backup/dns/example.com.zone --resign
```

#### Full DNS Recovery

Complete recovery procedure:

```bash
# 1. Stop DNS server
platformctl dns server stop

# 2. Verify backup integrity
platformctl dns zone verify --backup /backup/dns/20250115.tar.gz

# 3. Extract backup
tar -xzf /backup/dns/20250115.tar.gz -C /tmp/dns-restore/

# 4. Clear existing zones (if needed)
platformctl dns zone delete --all --force

# 5. Import all zones
platformctl dns zone import --all --from-dir /tmp/dns-restore/

# 6. Verify zones loaded
platformctl dns zone list

# 7. Re-sign zones if keys were not included
platformctl dns zone sign --all

# 8. Start DNS server
platformctl dns server start

# 9. Verify resolution
dig @localhost -p 8053 example.com SOA

# 10. Clean up
rm -rf /tmp/dns-restore/
```

### Verification Commands

Verify backup and recovery integrity:

```bash
# Verify backup file
platformctl dns zone verify --backup /backup/dns/example.com.zone

# Compare backup to live zone
platformctl dns zone diff /backup/dns/example.com.zone example.com

# Verify DNSSEC signatures after restore
platformctl dns dnssec verify example.com

# Check zone serial numbers
dig @localhost -p 8053 example.com SOA +short
```

## Capacity Planning

### Resource Requirements

| Zones | Records | Memory | CPU | Disk |
|-------|---------|--------|-----|------|
| 1-10 | < 1,000 | 256 MB | 1 core | 100 MB |
| 10-50 | 1,000-10,000 | 512 MB | 2 cores | 500 MB |
| 50-100 | 10,000-50,000 | 1 GB | 4 cores | 2 GB |
| 100-500 | 50,000-200,000 | 4 GB | 8 cores | 10 GB |
| 500+ | 200,000+ | 8+ GB | 16+ cores | 50+ GB |

### Query Capacity

| CPU Cores | Queries per Second (QPS) | Notes |
|-----------|--------------------------|-------|
| 1 | 10,000 | Development/testing |
| 2 | 25,000 | Small deployments |
| 4 | 50,000 | Medium deployments |
| 8 | 100,000 | Large deployments |
| 16 | 200,000+ | High-traffic environments |

### Performance Tuning

```yaml
# config.yaml - performance optimization
dns:
  performance:
    # Worker threads (default: CPU count)
    worker-threads: 8

    # Buffer sizes
    read-buffer-size: 16384
    write-buffer-size: 16384

    # Connection pooling
    max-connections: 1000
    connection-timeout: 30s

  cache:
    enabled: true
    max-size: 1024MB
    max-ttl: 86400
    negative-ttl: 300

  # Service-specific QuicBaaS settings
  shard-id: 2
  partition: dns
```

### Scaling Guidelines

| Metric | Threshold | Action |
|--------|-----------|--------|
| CPU utilization | > 70% sustained | Add CPU cores or scale out |
| Memory utilization | > 80% | Increase memory allocation |
| Query latency (p99) | > 100ms | Optimize queries, add caching |
| Cache hit ratio | < 80% | Increase cache size |
| Error rate | > 1% | Investigate root cause |

## Maintenance Windows

### Enable Maintenance Mode

```bash
# Enable maintenance mode
platformctl dns maintenance enable \
  --message "Scheduled maintenance: DNSSEC key rotation" \
  --expected-duration 30m

# Check maintenance status
platformctl dns maintenance status

# Disable maintenance mode
platformctl dns maintenance disable
```

### Maintenance Mode Behavior

| Feature | Behavior in Maintenance Mode |
|---------|------------------------------|
| Query resolution | Continues normally |
| Dynamic updates | Queued or rejected |
| Zone transfers | Paused |
| Health checks | Return degraded status |
| Monitoring | Alerts suppressed |

### Rolling Update Procedure (HA)

For high-availability deployments:

```bash
# 1. Identify nodes in cluster
platformctl dns cluster nodes

# 2. Start rolling update
for node in $(platformctl dns cluster nodes --quiet); do
  echo "Updating node: $node"

  # Drain node from load balancer
  platformctl dns cluster drain $node

  # Wait for connections to close
  sleep 30

  # Perform maintenance
  platformctl dns maintenance enable --node $node

  # Apply updates
  # ... perform update tasks ...

  # Verify node health
  platformctl dns health check --node $node

  # Re-enable node
  platformctl dns maintenance disable --node $node
  platformctl dns cluster undrain $node

  # Wait for node to stabilize
  sleep 60
done

# 3. Verify cluster health
platformctl dns cluster health
```

### Scheduled Maintenance Tasks

| Task | Frequency | Description |
|------|-----------|-------------|
| Log rotation | Daily | Rotate and compress logs |
| Cache cleanup | Weekly | Clear stale cache entries |
| Zone validation | Weekly | Verify zone integrity |
| DNSSEC re-sign | As needed | Refresh expiring signatures |
| Backup verification | Monthly | Test backup restoration |
| Performance review | Monthly | Analyze metrics and capacity |

## Logging

### Log Configuration

```yaml
# config.yaml
logging:
  level: info
  format: json
  output: /var/log/platform-dns/dns.log

  dns:
    # Enable query logging (caution: high volume)
    queries: false

    # Enable response logging
    responses: false

    # Log security events
    security: true

    # Log zone changes
    zone-changes: true

    # Log DNSSEC operations
    dnssec-operations: true
```

### Log Levels

| Level | Description | Use Case |
|-------|-------------|----------|
| `debug` | Verbose debugging | Development, troubleshooting |
| `info` | Operational events | Normal operations |
| `warn` | Warning conditions | Degraded performance |
| `error` | Error conditions | Failures requiring attention |

### Log Rotation

Configure log rotation:

```yaml
# config.yaml
logging:
  rotation:
    enabled: true
    max-size: 100MB
    max-files: 10
    max-age: 30d
    compress: true
```

**Logrotate Configuration:**

```
# /etc/logrotate.d/platform-dns
/var/log/platform-dns/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 platform-dns platform-dns
    postrotate
        platformctl dns server reload-logs
    endscript
}
```

### Log Analysis

```bash
# View recent errors
journalctl -u platform-dns --since "1 hour ago" | grep ERROR

# Count queries by type
grep "query_type" /var/log/platform-dns/dns.log | \
  jq -r '.query_type' | sort | uniq -c | sort -rn

# Find slow queries
grep "query_duration" /var/log/platform-dns/dns.log | \
  jq -r 'select(.query_duration_ms > 100)'

# Security event summary
grep "security" /var/log/platform-dns/dns.log | \
  jq -r '.event' | sort | uniq -c
```

## Operational Runbooks

### Daily Checks

```bash
#!/bin/bash
# Daily DNS health check

echo "=== DNS Daily Health Check ==="

# Server status
platformctl dns server status

# Zone count and status
platformctl dns zone list --summary

# DNSSEC status
platformctl dns dnssec status --all

# Recent errors
platformctl dns logs --since "24h" --level error --count 10

# Metrics summary
platformctl dns metrics summary
```

### Weekly Maintenance

```bash
#!/bin/bash
# Weekly DNS maintenance

echo "=== Weekly DNS Maintenance ==="

# Validate all zones
platformctl dns zone validate --all

# Check DNSSEC signature expiration
platformctl dns dnssec check-expiration

# Cache statistics and cleanup
platformctl dns cache stats
platformctl dns cache cleanup --stale

# Backup verification
platformctl dns backup verify --latest

# Performance report
platformctl dns metrics report --period 7d
```

## Related Documentation

| Document | Description |
|----------|-------------|
| [Troubleshooting](troubleshooting.md) | Diagnostic procedures and solutions |
| [Configuration](configuration.md) | Complete configuration reference |
| [Security](security.md) | Security model and best practices |
| [DNSSEC](dnssec.md) | DNSSEC signing configuration |
| [DNSSEC Rollover](dnssec-rollover.md) | Key rollover procedures |
| [Architecture](architecture.md) | System architecture overview |

## See Also

- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Alerting](https://grafana.com/docs/grafana/latest/alerting/)
- [CoreDNS Metrics](https://coredns.io/plugins/metrics/)
