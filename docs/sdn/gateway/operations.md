# Gateway Operations Guide

## Overview

This guide covers day-to-day operations for unified gateway nodes, including mode management, health monitoring, failover procedures, load balancer operations, NAT troubleshooting, IPv6 allocation issues, IoT onboarding, and performance tuning.

## Gateway Mode Management

### Viewing Current Mode Configuration

```bash
# View gateway status including active modes
platformctl sdn gateway status

# Expected output:
# Gateway Status
# ==============
# Node ID:        gw-na-east-01
# Underlay IP:    10.0.0.1
# Overlay IP:     2602:f5bb:1::1
# Status:         active
# Uptime:         14d 5h 32m
#
# Active Modes:
#   Overlay:   enabled (VTEP active, 15 VNIs)
#   Edge:      enabled (ACME running, 234 sessions)
#   Transit:   enabled (BGP established, 3 peers)
#
# Cluster:
#   Role:      primary
#   Peers:     3/3 healthy
#   VIPs:      5 owned
```

### Enabling a Mode

```bash
# Enable transit mode on existing gateway
platformctl sdn gateway mode enable transit

# Output:
# Enabling Transit Mode
# =====================
# Status:     initializing
# BGP ASN:    65001
# Router ID:  10.0.0.1
#
# Initializing BGP speaker...    done
# Loading routing table...       done
# Connecting to coordinators...  done
# Establishing ISP peers...      pending
#
# Transit mode enabled. Peer sessions establishing.

# Verify mode active
platformctl sdn gateway status | grep "Transit"
# Transit:   enabled (BGP establishing, 0/3 peers)

# Wait for peers to establish
watch platformctl sdn gateway bgp peers
```

### Disabling a Mode

```bash
# Disable edge mode (graceful)
platformctl sdn gateway mode disable edge --graceful

# Output:
# Disabling Edge Mode (graceful)
# ==============================
# Current sessions:    234
# Draining timeout:    60s
#
# Stopping new connections...    done
# Draining active sessions...    45/234 remaining
# Draining active sessions...    12/234 remaining
# Draining active sessions...    0/234 remaining
# Stopping ACME server...        done
# Stopping DHT bootstrap...      done
# Releasing IPv6 allocations...  done
#
# Edge mode disabled.

# Force disable (immediate, not recommended)
platformctl sdn gateway mode disable edge --force
```

### Mode Prerequisites

| Mode | Prerequisites | Verification |
|------|---------------|--------------|
| Overlay | OVS running, VTEP IP assigned | `ovs-vsctl show` |
| Edge | Public IP, TLS certificates | `curl https://localhost:8443/health` |
| Transit | BGP ASN assigned, ISP peering configured | `platformctl sdn gateway bgp status` |

### Upgrading Mode Configuration

```bash
# Update mode configuration without restart
platformctl sdn gateway mode config update --file /etc/platformd/gateway-updated.yaml

# Verify new configuration applied
platformctl sdn gateway mode config show

# Reload specific mode
platformctl sdn gateway mode reload overlay
```

## Health Monitoring

### Gateway Health Dashboard

```bash
# Comprehensive health report
platformctl sdn gateway health

# Expected output:
# Gateway Health Report
# =====================
# Overall Status: healthy
#
# Component Health:
#   Cluster:      healthy (3/3 peers)
#   Overlay:      healthy (15 VNIs, 30 tunnels)
#   Edge:         healthy (ACME active, DHT active)
#   Transit:      warning (2/3 BGP peers established)
#   Load Balancer: healthy (5 VIPs, 10 backends)
#
# Resource Usage:
#   CPU:          45% (4 cores)
#   Memory:       2.3 GB / 8 GB (29%)
#   Connections:  12,456 / 100,000
#   File Descriptors: 8,234 / 65,535
#
# Warnings:
#   - BGP peer ISP-Backup not established (5m 32s)
#
# Recommendations:
#   - Investigate ISP-Backup peer connectivity
```

### Component-Specific Health

```bash
# Cluster health
platformctl sdn gateway health cluster

# Output:
# Cluster Health
# ==============
# State:         healthy
# Local Role:    primary
#
# Peers:
#   gw-na-east-02   10.0.0.2    healthy    2ms RTT     2s ago
#   gw-na-east-03   10.0.0.3    healthy    3ms RTT     1s ago
#   gw-na-west-01   10.0.1.1    healthy    15ms RTT    2s ago
#
# VIP Ownership:
#   2602:f5bb::100   local      api-gateway
#   2602:f5bb::101   peer-02    web-frontend
#   2602:f5bb::102   local      acme-server

# Overlay health
platformctl sdn gateway health overlay

# Edge health
platformctl sdn gateway health edge

# Transit health
platformctl sdn gateway health transit

# Load balancer health
platformctl sdn gateway health loadbalancer
```

### Setting Up Alerting

```bash
# View current alert configuration
platformctl sdn gateway alerts config

# Configure alert thresholds
platformctl sdn gateway alerts config set \
  --cpu-warning 70 \
  --cpu-critical 90 \
  --memory-warning 80 \
  --memory-critical 95 \
  --peer-missed-threshold 2 \
  --bgp-flap-threshold 5

# Test alert notification
platformctl sdn gateway alerts test

# View active alerts
platformctl sdn gateway alerts list
```

### Health Check Endpoints

| Endpoint | Protocol | Purpose |
|----------|----------|---------|
| `/health` | HTTP | Overall gateway health |
| `/health/ready` | HTTP | Readiness probe (K8s) |
| `/health/live` | HTTP | Liveness probe (K8s) |
| `/metrics` | HTTP | Prometheus metrics |
| `gRPC health.Check` | gRPC | gRPC health check |

```bash
# HTTP health check
curl -s http://localhost:8080/health | jq

# Output:
# {
#   "status": "healthy",
#   "components": {
#     "cluster": "healthy",
#     "overlay": "healthy",
#     "edge": "healthy",
#     "transit": "warning"
#   },
#   "uptime": "14d 5h 32m"
# }
```

## Failover Procedures

### Planned Failover (Maintenance)

**Step 1: Prepare for Maintenance**

```bash
# Check current VIP ownership
platformctl sdn gateway vip list

# Output:
# VIP               SERVICE         OWNER         PRIORITY
# 2602:f5bb::100    api-gateway     local         100
# 2602:f5bb::101    web-frontend    gw-na-east-02 100
# 2602:f5bb::102    acme-server     local         100

# Note VIPs to migrate
```

**Step 2: Enter Maintenance Mode**

```bash
# Enable maintenance mode (stops accepting new traffic)
platformctl sdn gateway maintenance enable

# Output:
# Entering Maintenance Mode
# =========================
# Stopping new connections...     done
# Advertising reduced priority... done
# Status: maintenance mode active
#
# Current state:
#   Connections draining: 1,234
#   VIPs migrating:       2
```

**Step 3: Wait for Drain and Migration**

```bash
# Monitor drain progress
watch platformctl sdn gateway maintenance status

# Output:
# Maintenance Status
# ==================
# Mode:           draining
# Connections:    456 remaining (was 1,234)
# VIPs:           migrated to gw-na-east-02
# Est. Complete:  ~2 minutes
```

**Step 4: Perform Maintenance**

```bash
# Once fully drained
platformctl sdn gateway maintenance status
# Status: ready for maintenance

# Perform maintenance tasks (upgrade, restart, etc.)
systemctl stop platformd
# ... maintenance ...
systemctl start platformd
```

**Step 5: Exit Maintenance Mode**

```bash
# Resume normal operation
platformctl sdn gateway maintenance disable

# Output:
# Exiting Maintenance Mode
# ========================
# Restoring normal priority...   done
# Re-establishing peers...       done
# VIP ownership:                 reclaiming based on priority
#
# Status: active
```

### Unplanned Failover (Node Failure)

When a gateway node fails unexpectedly:

**Step 1: Detect Failure**

```bash
# On healthy peer, check for failures
platformctl sdn gateway cluster status

# Output:
# Cluster Status
# ==============
# Local:      gw-na-east-02 (healthy)
#
# Peers:
#   gw-na-east-01   10.0.0.1    FAILED    missed 5 heartbeats
#   gw-na-east-03   10.0.0.3    healthy   2s ago
#
# Failover Status:
#   Triggered:      2026-01-19 14:32:15
#   VIPs claimed:   2 (from gw-na-east-01)
#   Sessions moved: 1,234
```

**Step 2: Verify VIP Migration**

```bash
# Confirm VIPs moved to surviving nodes
platformctl sdn gateway vip list

# Output:
# VIP               SERVICE         OWNER         STATUS
# 2602:f5bb::100    api-gateway     local         active (claimed from gw-na-east-01)
# 2602:f5bb::101    web-frontend    local         active
# 2602:f5bb::102    acme-server     gw-na-east-03 active (claimed from gw-na-east-01)
```

**Step 3: Monitor for Recovery**

```bash
# Watch for failed node to recover
watch platformctl sdn gateway cluster status

# When recovered, VIPs may migrate back based on priority
```

**Step 4: Post-Incident Review**

```bash
# Export failover event log
platformctl sdn gateway failover history --since "2 hours ago"

# Output:
# Failover History
# ================
# TIME                 EVENT              NODE           VIPs    DURATION
# 2026-01-19 14:32:15  peer_failure       gw-na-east-01  2       -
# 2026-01-19 14:32:17  vip_claimed        local          1       2s
# 2026-01-19 14:32:18  vip_claimed        gw-na-east-03  1       3s
# 2026-01-19 14:45:00  peer_recovered     gw-na-east-01  -       -
# 2026-01-19 14:45:05  vip_preempted      gw-na-east-01  2       12m 48s
```

### Split-Brain Prevention

```bash
# Check for split-brain condition
platformctl sdn gateway cluster split-brain-check

# If split-brain detected:
# Split-Brain Warning
# ===================
# Detected: Multiple nodes claiming same VIP
# VIP: 2602:f5bb::100
# Claimants: gw-na-east-01, gw-na-east-02
#
# Automatic Resolution:
#   Higher priority node (gw-na-east-01) will retain VIP
#   Lower priority node (gw-na-east-02) will release

# Force resolution if automatic fails
platformctl sdn gateway cluster resolve-split-brain
```

## Load Balancer Management

### VIP Operations

```bash
# List all VIPs
platformctl sdn gateway lb vip list

# Output:
# VIP               PORT   PROTO  SERVICE         BACKENDS  ACTIVE  HEALTH
# 2602:f5bb::100    443    tcp    api-gateway     4         4       100%
# 2602:f5bb::101    80     tcp    web-frontend    8         7       87%
# 2602:f5bb::102    443    tcp    acme-server     2         2       100%

# Show VIP details
platformctl sdn gateway lb vip show 2602:f5bb::100

# Output:
# VIP: 2602:f5bb::100
# ===================
# Port:        443/tcp
# Service:     api-gateway
# Algorithm:   maglev
# Persistence: source_ip (1h TTL)
#
# Backends:
#   10.0.1.1:8443   weight=100  healthy   rtt=2ms   conns=345
#   10.0.1.2:8443   weight=100  healthy   rtt=3ms   conns=312
#   10.0.1.3:8443   weight=100  healthy   rtt=2ms   conns=356
#   10.0.1.4:8443   weight=100  healthy   rtt=4ms   conns=298
#
# Statistics:
#   Total Connections:    1,234,567
#   Active Connections:   1,311
#   Bytes In:             45.2 GB
#   Bytes Out:            123.4 GB
```

### Backend Management

```bash
# Add backend to VIP
platformctl sdn gateway lb backend add \
  --vip 2602:f5bb::100 \
  --address 10.0.1.5 \
  --port 8443 \
  --weight 100

# Remove backend (drains connections first)
platformctl sdn gateway lb backend remove \
  --vip 2602:f5bb::100 \
  --address 10.0.1.5 \
  --drain-timeout 60s

# Set backend weight (for gradual rollout)
platformctl sdn gateway lb backend weight \
  --vip 2602:f5bb::100 \
  --address 10.0.1.5 \
  --weight 50

# Disable backend (maintenance)
platformctl sdn gateway lb backend disable \
  --vip 2602:f5bb::100 \
  --address 10.0.1.5

# Enable backend
platformctl sdn gateway lb backend enable \
  --vip 2602:f5bb::100 \
  --address 10.0.1.5
```

### Health Check Tuning

```bash
# View health check configuration for VIP
platformctl sdn gateway lb vip health-config show 2602:f5bb::100

# Modify health check
platformctl sdn gateway lb vip health-config set 2602:f5bb::100 \
  --type http \
  --path /health \
  --interval 5s \
  --timeout 2s \
  --healthy-threshold 2 \
  --unhealthy-threshold 3

# View health check results
platformctl sdn gateway lb vip health-status 2602:f5bb::100

# Output:
# Health Check Status: 2602:f5bb::100
# ===================================
# BACKEND       STATUS    LAST-CHECK  RTT    FAILURES
# 10.0.1.1:8443 healthy   2s ago      15ms   0
# 10.0.1.2:8443 healthy   1s ago      18ms   0
# 10.0.1.3:8443 unhealthy 3s ago      -      3 (connection refused)
# 10.0.1.4:8443 healthy   2s ago      12ms   0
```

### Connection Draining

```bash
# Drain specific backend
platformctl sdn gateway lb drain \
  --vip 2602:f5bb::100 \
  --backend 10.0.1.3 \
  --timeout 120s

# Monitor drain progress
platformctl sdn gateway lb drain-status --vip 2602:f5bb::100 --backend 10.0.1.3

# Cancel drain
platformctl sdn gateway lb drain-cancel --vip 2602:f5bb::100 --backend 10.0.1.3
```

## NAT Troubleshooting

### Viewing NAT State

```bash
# List NAT sessions
platformctl sdn gateway nat sessions

# Output:
# PROTO  INTERNAL           EXTERNAL          REMOTE             STATE     AGE
# tcp    10.0.1.10:45678    23.143.36.10:1024 93.184.216.34:443  ESTAB     5m
# udp    10.0.1.11:53421    23.143.36.10:1025 8.8.8.8:53         -         2s
# tcp    10.0.1.12:34567    23.143.36.10:1026 151.101.1.69:443   TIME_WAIT 1m

# Filter by internal IP
platformctl sdn gateway nat sessions --internal 10.0.1.10

# Filter by external IP
platformctl sdn gateway nat sessions --external 23.143.36.10
```

### SNAT Pool Status

```bash
# View SNAT pool usage
platformctl sdn gateway nat snat-pools

# Output:
# SNAT Pool Status
# ================
# Pool: egress-pool
#   Addresses: 23.143.36.10, 23.143.36.11
#   Port Range: 1024-65535
#   Usage:
#     23.143.36.10: 12,456 / 64,512 ports (19%)
#     23.143.36.11: 8,234 / 64,512 ports (13%)
#   Total Sessions: 20,690

# Check for port exhaustion
platformctl sdn gateway nat snat-pools --check-exhaustion

# Warning if any address > 80% port usage
```

### CGNAT Operations

```bash
# View CGNAT allocations
platformctl sdn gateway nat cgnat list

# Output:
# INTERNAL         PORT-BLOCK      EXTERNAL         SESSIONS
# 100.64.0.1       1024-2047       23.143.36.20     234
# 100.64.0.2       2048-3071       23.143.36.20     156
# 100.64.0.3       3072-4095       23.143.36.20     89

# Check CGNAT port block usage
platformctl sdn gateway nat cgnat usage

# Expand port block for heavy user
platformctl sdn gateway nat cgnat expand --internal 100.64.0.1 --blocks 2
```

### NAT Troubleshooting Common Issues

**Connectivity Issues:**

```bash
# Check if NAT session exists for connection
platformctl sdn gateway nat lookup \
  --proto tcp \
  --internal 10.0.1.10:45678 \
  --remote 93.184.216.34:443

# Output:
# NAT Session Found
# =================
# Protocol:    tcp
# Internal:    10.0.1.10:45678
# External:    23.143.36.10:1024
# Remote:      93.184.216.34:443
# State:       ESTABLISHED
# Created:     5m ago
# Bytes In:    12,456
# Bytes Out:   45,678

# If not found, check firewall rules
platformctl sdn gateway nat rules list | grep 10.0.1.10
```

**Port Exhaustion:**

```bash
# Identify top port consumers
platformctl sdn gateway nat top-consumers

# Output:
# Top NAT Port Consumers
# ======================
# INTERNAL        SESSIONS  PORTS    % OF POOL
# 10.0.1.50       5,234     5,234    8.1%
# 10.0.1.51       3,456     3,456    5.4%
# 10.0.1.52       2,345     2,345    3.6%

# Investigate heavy consumer
platformctl sdn gateway nat sessions --internal 10.0.1.50 | head -20

# Consider rate limiting or expanding pool
```

**Hairpin NAT Issues:**

```bash
# Check hairpin NAT configuration
platformctl sdn gateway nat hairpin status

# If internal hosts can't reach external IP of internal services:
platformctl sdn gateway nat hairpin enable --vip 2602:f5bb::100
```

## IPv6 Allocation Issues

### Viewing Allocations

```bash
# List all IPv6 allocations
platformctl sdn gateway ipam allocations

# Output:
# IP                      DEVICE          HOSTNAME    ALLOCATED       STATUS
# 2602:f5bb:1::1000       node-abc123     web-01      14d ago         active
# 2602:f5bb:1::1001       node-def456     db-01       10d ago         active
# 2602:f5bb:1::1002       node-ghi789     cache-01    5d ago          active

# Check allocation for specific device
platformctl sdn gateway ipam allocation show node-abc123
```

### Allocation Failures

**Pool Exhausted:**

```bash
# Check pool utilization
platformctl sdn gateway ipam pool status

# Output:
# IPv6 Pool Status
# ================
# Pool:        2602:f5bb:0001::/48
# Allocated:   1,234
# Available:   ~281 trillion
# Usage:       0.00000000044%
#
# Status:      healthy (infinite addresses available)

# If somehow exhausted (shouldn't happen with /48):
platformctl sdn gateway ipam pool expand --cidr 2602:f5bb:0002::/48
```

**Duplicate Allocation:**

```bash
# Check for duplicates
platformctl sdn gateway ipam duplicates

# Output:
# Duplicate Allocations Found
# ===========================
# IP: 2602:f5bb:1::1000
#   Device: node-abc123 (allocated 14d ago)
#   Device: node-xyz999 (allocated 2m ago)  <- CONFLICT
#
# Resolution: newer allocation will be reassigned

# Force reassignment
platformctl sdn gateway ipam reassign node-xyz999
```

**Stale Allocations:**

```bash
# Find stale allocations (devices not seen recently)
platformctl sdn gateway ipam stale --inactive-days 30

# Output:
# Stale Allocations (inactive > 30 days)
# ======================================
# IP                      DEVICE          LAST-SEEN       STATUS
# 2602:f5bb:1::2000       node-old001     45d ago         stale
# 2602:f5bb:1::2001       node-old002     60d ago         stale

# Release stale allocation
platformctl sdn gateway ipam release 2602:f5bb:1::2000

# Bulk release stale allocations
platformctl sdn gateway ipam cleanup --inactive-days 60 --dry-run
platformctl sdn gateway ipam cleanup --inactive-days 60
```

### Manual Allocation/Release

```bash
# Manually allocate IP to device
platformctl sdn gateway ipam allocate \
  --device node-newhost \
  --hostname web-prod-01 \
  --ip 2602:f5bb:1::5000  # Optional: specific IP

# Release allocation
platformctl sdn gateway ipam release --device node-newhost

# Reserve IP range (prevent automatic allocation)
platformctl sdn gateway ipam reserve \
  --start 2602:f5bb:1::f000 \
  --end 2602:f5bb:1::ffff \
  --reason "Reserved for infrastructure"
```

## IoT Onboarding Issues

### ACME Challenge Failures

```bash
# View recent onboarding sessions
platformctl sdn gateway edge acme sessions

# Output:
# SESSION           DEVICE        STATE        STARTED     CHALLENGE
# sess-abc123       tpm-001       pending      2m ago      endorse-01
# sess-def456       tpm-002       failed       5m ago      endorse-01
# sess-ghi789       tpm-003       completed    10m ago     enroll-01

# Get details on failed session
platformctl sdn gateway edge acme session show sess-def456

# Output:
# ACME Session: sess-def456
# =========================
# Device:        tpm-002
# State:         failed
# Challenge:     endorse-01 (TPM endorsement)
# Error:         EK certificate validation failed
# Details:       EK cert issuer not in trusted list
#
# Timeline:
#   14:25:00  Session started
#   14:25:01  Challenge issued: endorse-01
#   14:25:05  Response received
#   14:25:05  Validation failed: unknown EK issuer
```

**Common ACME Errors:**

| Error | Cause | Solution |
|-------|-------|----------|
| EK cert validation failed | Unknown TPM manufacturer | Add CA to trusted list |
| Quote verification failed | TPM attestation mismatch | Check PCR values |
| Nonce mismatch | Replay or timing issue | Retry challenge |
| Certificate request invalid | Malformed CSR | Check device implementation |
| Rate limit exceeded | Too many attempts | Wait and retry |

### DHT Bootstrap Issues

```bash
# Check DHT bootstrap status
platformctl sdn gateway edge dht status

# Output:
# DHT Bootstrap Status
# ====================
# State:           active
# Listening:       :10443
# Connections:     1,234
# Requests (1h):   45,678
#
# Response Stats:
#   k-closest:     avg 18.5 nodes
#   Coordinators:  included: 100%

# View bootstrap requests
platformctl sdn gateway edge dht requests --tail 20

# Check if device can reach bootstrap
platformctl sdn gateway edge dht test-client --device-ip 192.168.1.100
```

### Onboarding Rate Limiting

```bash
# Check rate limit status
platformctl sdn gateway edge rate-limits

# Output:
# Rate Limit Status
# =================
# Tier        Limit      Current    Remaining
# trusted     100/s      45/s       55/s
# untrusted   10/s       8/s        2/s
# new         5/s        5/s        0/s (throttled)
#
# Throttled IPs (last hour):
#   192.168.1.50    exceeded new tier (5/s) by 50%

# Temporarily increase limit for specific IP
platformctl sdn gateway edge rate-limit exempt 192.168.1.50 --duration 1h
```

## Performance Tuning

### Resource Optimization

```bash
# View current resource usage
platformctl sdn gateway perf stats

# Output:
# Performance Statistics
# ======================
#
# CPU:
#   User:        35%
#   System:      10%
#   Softirq:     8%
#   Idle:        47%
#
# Memory:
#   Used:        2.3 GB
#   Cached:      1.2 GB
#   Available:   5.5 GB
#
# Network:
#   Rx:          2.5 Gbps
#   Tx:          3.1 Gbps
#   Rx Drops:    0
#   Tx Drops:    0
#
# Connections:
#   Active:      12,456
#   Rate:        234/s
#   Peak:        18,234 (14:30)

# Get tuning recommendations
platformctl sdn gateway perf recommend

# Output:
# Performance Recommendations
# ===========================
# 1. Consider enabling RSS (Receive Side Scaling)
#    Current: 1 queue, Recommended: 4 queues
#    Command: ethtool -L eth0 combined 4
#
# 2. Increase socket buffer sizes
#    Current: rmem_max=212992
#    Recommended: rmem_max=16777216
#    Command: sysctl -w net.core.rmem_max=16777216
#
# 3. Enable busy polling for low latency
#    Command: sysctl -w net.core.busy_poll=50
```

### Connection Tuning

```bash
# View connection limits
platformctl sdn gateway perf connections

# Output:
# Connection Limits
# =================
# Max Connections:     100,000
# Current:             12,456
# Available:           87,544
#
# Per-Source Limits:
#   Trusted:           10,000
#   Untrusted:         1,000
#   New:               100
#
# File Descriptors:
#   Limit:             65,535
#   Used:              15,234
#   Available:         50,301

# Adjust connection limits
platformctl sdn gateway perf connections set \
  --max-connections 200000 \
  --per-source-trusted 20000
```

### Latency Optimization

```bash
# View latency metrics
platformctl sdn gateway perf latency

# Output:
# Latency Metrics
# ===============
# Component          P50      P95      P99      Max
# Packet rx->tx      0.1ms    0.3ms    0.8ms    2.1ms
# LB decision        0.02ms   0.05ms   0.1ms    0.5ms
# NAT lookup         0.01ms   0.02ms   0.05ms   0.2ms
# Health check       2ms      5ms      10ms     50ms
# BGP update         1ms      3ms      5ms      15ms

# Enable latency tracing (temporary, impacts performance)
platformctl sdn gateway perf trace enable --duration 5m

# View trace results
platformctl sdn gateway perf trace results

# Disable tracing
platformctl sdn gateway perf trace disable
```

### Throughput Optimization

```bash
# View throughput metrics
platformctl sdn gateway perf throughput

# Output:
# Throughput Metrics
# ==================
# Direction    Current    Peak       Capacity   Utilization
# Inbound      2.5 Gbps   4.2 Gbps   10 Gbps    25%
# Outbound     3.1 Gbps   5.1 Gbps   10 Gbps    31%
#
# Per-Protocol:
#   TCP:       4.8 Gbps (85%)
#   UDP:       0.6 Gbps (11%)
#   VXLAN:     0.2 Gbps (4%)
#
# Bottlenecks: None detected

# Enable hardware offload (if supported)
platformctl sdn gateway perf offload enable --type vxlan
platformctl sdn gateway perf offload enable --type checksum
```

## Diagnostic Commands Summary

```bash
# Overall status
platformctl sdn gateway status

# Health check
platformctl sdn gateway health

# Cluster status
platformctl sdn gateway cluster status

# Mode status
platformctl sdn gateway mode status

# VIP list
platformctl sdn gateway vip list

# NAT sessions
platformctl sdn gateway nat sessions | head -20

# IPv6 allocations
platformctl sdn gateway ipam allocations | head -20

# ACME sessions
platformctl sdn gateway edge acme sessions

# Performance stats
platformctl sdn gateway perf stats

# Export diagnostic bundle
platformctl sdn gateway diagnostic-bundle --output /tmp/gw-diag.tar.gz
```

## Maintenance Checklist

### Daily Checks

- [ ] Gateway health status
- [ ] BGP peer status (if transit mode)
- [ ] VIP health
- [ ] Alert review

### Weekly Checks

- [ ] NAT port utilization
- [ ] IPv6 pool utilization
- [ ] Connection trends
- [ ] Performance metrics review

### Monthly Checks

- [ ] Capacity planning review
- [ ] Stale allocation cleanup
- [ ] Certificate expiration check
- [ ] Failover test

## See Also

- [Architecture](architecture.md) - Gateway architecture overview
- [Configuration](configuration.md) - Configuration reference
- [Overlay Mode](overlay-mode.md) - SDN overlay operations
- [Edge Mode](edge-mode.md) - Edge gateway operations
- [Transit Mode](transit-mode.md) - BGP transit operations
- [Load Balancer](loadbalancer.md) - Load balancer configuration
- [BGP Troubleshooting](../bgp/troubleshooting.md) - BGP-specific troubleshooting
