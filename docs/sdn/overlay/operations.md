# VXLAN Overlay Operations Guide

## Overview

This guide covers day-to-day operations for the VXLAN overlay network, including VTEP management, VNI lifecycle, tunnel monitoring, MAC table operations, and capacity planning.

## VTEP Management

### Adding a New Host to the Overlay

When adding a new compute host to the overlay network:

**1. Verify Prerequisites**

```bash
# Check underlay connectivity from new host
ping -c 3 10.0.0.1  # Existing VTEP

# Verify MTU supports VXLAN (must be >= 1550, ideally 9000)
ip link show eth0 | grep mtu
# mtu 9000 qdisc mq state UP mode DEFAULT

# Verify OVS is running
systemctl status openvswitch-switch
ovs-vsctl show
```

**2. Configure the New VTEP**

```bash
# On the new host, verify VTEP configuration
platformctl sdn overlay vtep show

# Expected output:
# VTEP Configuration
# ==================
# Node ID:          node-005
# VTEP IP:          10.0.0.5
# Underlay Iface:   eth0
# Underlay MTU:     9000
# VXLAN Port:       4789
# Status:           initializing
```

**3. Register the VTEP**

```bash
# Start the overlay service (if not already running)
systemctl start platformd

# Verify VTEP registered with cluster
platformctl sdn overlay vtep list

# Expected output:
# NODE-ID    VTEP-IP     STATUS    ACTIVE-VNIS  LAST-HEARTBEAT
# node-001   10.0.0.1    healthy   15           2s ago
# node-002   10.0.0.2    healthy   15           1s ago
# node-005   10.0.0.5    healthy   0            <1s ago
```

**4. Verify Tunnel Establishment**

```bash
# Check tunnels from new host
platformctl sdn overlay tunnel list

# Expected output:
# LOCAL-VTEP  REMOTE-VTEP  VNI       STATE    RTT      LAST-CHECK
# 10.0.0.5    10.0.0.1     1000100   healthy  1.2ms    2s ago
# 10.0.0.5    10.0.0.1     1000200   healthy  1.1ms    2s ago
# 10.0.0.5    10.0.0.2     1000100   healthy  0.8ms    1s ago
# 10.0.0.5    10.0.0.2     1000200   healthy  0.9ms    1s ago

# Verify OVS VXLAN ports created
ovs-vsctl show | grep -A 3 vxlan
```

### Removing a Host from the Overlay

**1. Drain Workloads**

```bash
# List active VNIs on the host
platformctl sdn overlay vni list --local

# Migrate or stop VMs on this host before proceeding
```

**2. Graceful Deregistration**

```bash
# Deregister VTEP (notifies other hosts)
platformctl sdn overlay vtep deregister

# Verify deregistration
platformctl sdn overlay vtep list
# Host should no longer appear
```

**3. Clean Up Local State**

```bash
# Remove VXLAN ports from OVS
platformctl sdn overlay cleanup

# Stop overlay service
systemctl stop platformd

# Verify OVS cleanup
ovs-vsctl show | grep vxlan
# Should be empty
```

### VTEP Health Monitoring

```bash
# Check VTEP health status
platformctl sdn overlay vtep health

# Expected output:
# VTEP Health Report
# ==================
# Node ID:      node-001
# Status:       healthy
# Uptime:       14d 5h 32m
# Last Check:   2s ago
#
# Tunnel Health:
#   Healthy:    4/4
#   Unhealthy:  0
#   Degraded:   0
#
# Performance:
#   Avg RTT:    1.2ms
#   Max RTT:    3.1ms
#   Packet Loss: 0.00%
```

**Warning Signs:**

| Metric | Warning | Critical | Action |
|--------|---------|----------|--------|
| RTT | >50ms | >100ms | Check underlay congestion |
| Packet Loss | >0.1% | >1% | Check physical links |
| Missed Heartbeats | 2 | 4 | Node may be failing |
| Tunnel State | degraded | unhealthy | Check remote VTEP |

## VNI Management

### Creating a Virtual Network

**1. Create the VNI**

```bash
# Create VNI mapped to VLAN 100
platformctl sdn overlay vni create \
  --vni 1000100 \
  --vlan 100 \
  --name "production-web"

# Expected output:
# VNI Created
# ===========
# VNI:        1000100
# VLAN:       100
# Name:       production-web
# Multicast:  (head-end replication)
# Status:     active
```

**2. Verify VNI on All Hosts**

```bash
# List VNIs across cluster
platformctl sdn overlay vni list

# Expected output:
# VNI       VLAN  NAME            MEMBERS  MACS   STATUS
# 1000100   100   production-web  3        245    active
# 1000200   200   production-db   3        128    active
# 1000300   300   development     2        56     active
```

**3. Verify OpenFlow Rules**

```bash
# Check encapsulation rules installed
ovs-ofctl dump-flows br-int table=30 | grep tun_id=1000100

# Expected output shows encap rules:
# cookie=0x1000100, priority=100,metadata=100 actions=set_field:1000100->tun_id,goto_table:40
```

### Deleting a Virtual Network

**1. Verify No Active Ports**

```bash
# Check for active ports in the VNI
platformctl sdn overlay vni show 1000100

# If ports exist, migrate or remove them first
# PORT         MAC                STATUS     LAST-SEEN
# tap-vm001    aa:bb:cc:dd:ee:01  active     <1s ago
```

**2. Delete the VNI**

```bash
# Delete the VNI
platformctl sdn overlay vni delete 1000100

# Confirm deletion
platformctl sdn overlay vni list | grep 1000100
# Should return no results

# Verify OpenFlow rules removed
ovs-ofctl dump-flows br-int | grep 1000100
# Should return no results
```

**Warning:** Deleting a VNI with active ports will disrupt connectivity for those devices.

### VNI Capacity Planning

```bash
# Get VNI statistics
platformctl sdn overlay vni stats

# Expected output:
# VNI Statistics
# ==============
# Total VNIs:         15
# Active VNIs:        12
# Total MACs:         1,245
# Total Tunnels:      30
#
# Per-VNI Breakdown:
# VNI       MACS    REMOTE-VTEPS  FLOWS  BUM-TRAFFIC
# 1000100   245     3             735    12 pps
# 1000200   128     3             384    8 pps
# 1000300   56      2             168    3 pps
```

**Capacity Guidelines:**

| Resource | Default Limit | Warning | Action |
|----------|---------------|---------|--------|
| MACs per VNI | 65,536 | 50,000 | Consider splitting VNI |
| VNIs per Host | 4,096 | 3,000 | Add more hosts |
| Tunnels per Host | 1,024 | 800 | Review topology |
| Flows per Bridge | 100,000 | 80,000 | Optimize flow rules |

## Tunnel Monitoring and Health Checks

### Real-time Tunnel Monitoring

```bash
# Watch tunnel status in real-time
platformctl sdn overlay tunnel watch

# Output updates every 2 seconds:
# Tunnel Status (refreshing every 2s, Ctrl+C to exit)
# ====================================================
# LOCAL-VTEP  REMOTE-VTEP  VNI       STATE    RTT      CHANGES
# 10.0.0.1    10.0.0.2     1000100   healthy  1.2ms    0
# 10.0.0.1    10.0.0.2     1000200   healthy  1.1ms    0
# 10.0.0.1    10.0.0.3     1000100   healthy  2.3ms    0
```

### Diagnosing Tunnel Issues

**Tunnel Not Establishing:**

```bash
# Check if remote VTEP is reachable
ping 10.0.0.2

# Check VXLAN UDP port connectivity
nc -zuv 10.0.0.2 4789

# Verify no firewall blocking
iptables -L -n | grep 4789
ip6tables -L -n | grep 4789

# Check OVS port state
ovs-vsctl list interface | grep -A 5 vxlan

# Verify tunnel endpoint in QuicBaaS
platformctl sdn overlay vtep get node-002
```

**Tunnel Flapping:**

```bash
# Check tunnel history
platformctl sdn overlay tunnel history --remote 10.0.0.2

# Expected output:
# Tunnel History: 10.0.0.1 -> 10.0.0.2
# =====================================
# TIME                 STATE      RTT     EVENT
# 2026-01-19 14:30:00  healthy    1.2ms   established
# 2026-01-19 14:35:22  unhealthy  -       timeout (no response)
# 2026-01-19 14:35:32  healthy    1.1ms   recovered
# 2026-01-19 14:40:15  unhealthy  -       timeout (no response)
# 2026-01-19 14:40:25  healthy    1.3ms   recovered

# Check underlay for packet loss
ping -c 100 10.0.0.2 | tail -3
# 100 packets transmitted, 98 received, 2% packet loss
```

**High Latency:**

```bash
# Trace underlay path
traceroute 10.0.0.2

# Check for congestion
platformctl sdn overlay metrics --tunnel 10.0.0.2

# Expected output:
# Tunnel Metrics: 10.0.0.1 -> 10.0.0.2
# ====================================
# RTT (current):   45.2ms
# RTT (avg):       12.3ms
# RTT (p99):       52.1ms
# Packet Loss:     0.5%
# Throughput:      8.2 Gbps
# Queue Drops:     124
```

### Forcing Tunnel Rebuild

```bash
# Force tunnel reestablishment (use with caution)
platformctl sdn overlay tunnel reset --remote 10.0.0.2

# Verify new tunnel
platformctl sdn overlay tunnel show --remote 10.0.0.2
```

## MAC Table Management

### Viewing MAC Tables

```bash
# List all MACs for a VNI
platformctl sdn overlay mac list --vni 1000100

# Expected output:
# MAC               IP             VTEP        PORT        AGE      TYPE
# aa:bb:cc:dd:ee:01 10.100.0.10    local       tap-vm001   5m       learned
# aa:bb:cc:dd:ee:02 10.100.0.11    10.0.0.2    -           3m       remote
# aa:bb:cc:dd:ee:03 10.100.0.12    10.0.0.3    -           8m       remote

# Search for specific MAC
platformctl sdn overlay mac find aa:bb:cc:dd:ee:02

# Expected output:
# MAC Address: aa:bb:cc:dd:ee:02
# =============================
# VNI:         1000100
# IP:          10.100.0.11
# VTEP:        10.0.0.2 (node-002)
# Type:        remote
# Learned At:  2026-01-19 14:25:00
# Expires At:  2026-01-19 14:30:00
# Flow Cookie: 0x1000100000002
```

### Clearing MAC Entries

**Clear Single MAC:**

```bash
# Remove stale MAC entry
platformctl sdn overlay mac forget aa:bb:cc:dd:ee:02 --vni 1000100

# Verify removal
platformctl sdn overlay mac find aa:bb:cc:dd:ee:02
# MAC not found
```

**Clear All MACs for VNI:**

```bash
# Clear all MACs (triggers relearning)
platformctl sdn overlay mac clear --vni 1000100

# Warning: This causes temporary traffic flooding until MACs are relearned
```

**Force MAC Move:**

```bash
# When a VM migrates and MAC is stuck on old VTEP
platformctl sdn overlay mac move \
  --mac aa:bb:cc:dd:ee:01 \
  --vni 1000100 \
  --from-vtep 10.0.0.2 \
  --to-vtep 10.0.0.3

# Verify move
platformctl sdn overlay mac find aa:bb:cc:dd:ee:01
```

### MAC Table Aging

```bash
# View MAC aging statistics
platformctl sdn overlay mac stats --vni 1000100

# Expected output:
# MAC Table Statistics: VNI 1000100
# =================================
# Total Entries:     245
# Local Entries:     45
# Remote Entries:    200
# Capacity:          65,536 (0.4% used)
#
# Aging:
#   Aged Out (1h):   12
#   Average Age:     4m 32s
#   Oldest Entry:    12m 15s
#
# Learning:
#   Learned (1h):    24
#   Moves (1h):      3
#   Duplicates:      0
```

## ARP Suppression Monitoring

### ARP Cache Status

```bash
# View ARP suppression cache
platformctl sdn overlay arp list --vni 1000100

# Expected output:
# IP             MAC               STATUS    AGE      HITS
# 10.100.0.10    aa:bb:cc:dd:ee:01 active    5m       1,234
# 10.100.0.11    aa:bb:cc:dd:ee:02 active    3m       567
# 10.100.0.12    aa:bb:cc:dd:ee:03 stale     12m      23
```

### ARP Suppression Statistics

```bash
# View ARP suppression effectiveness
platformctl sdn overlay arp stats

# Expected output:
# ARP Suppression Statistics
# ==========================
#
# Cache:
#   Entries:         1,245
#   Capacity:        16,384 (7.6% used)
#   Hit Rate:        94.2%
#
# Traffic Reduction:
#   ARP Requests:    12,456 (last hour)
#   Proxied:         11,736 (94.2%)
#   Flooded:         720 (5.8%)
#   Broadcast Saved: ~11.7k packets/hour
#
# Per-VNI Breakdown:
#   VNI       ENTRIES  HIT-RATE  FLOODED
#   1000100   245      96.1%     156
#   1000200   128      93.5%     234
#   1000300   56       91.2%     330
```

### Troubleshooting ARP Issues

**ARP Not Resolving:**

```bash
# Check if ARP entry exists
platformctl sdn overlay arp find 10.100.0.15 --vni 1000100

# If missing, check if device is active
platformctl sdn overlay mac list --vni 1000100 | grep -i "10.100.0.15"

# Force ARP learning (device must respond)
arping -I br-int 10.100.0.15
```

**Stale ARP Entries:**

```bash
# Clear stale ARP entry
platformctl sdn overlay arp clear 10.100.0.12 --vni 1000100

# Clear all stale entries
platformctl sdn overlay arp purge-stale --vni 1000100
```

## Capacity Planning

### Resource Monitoring

```bash
# Overall overlay capacity report
platformctl sdn overlay capacity

# Expected output:
# Overlay Capacity Report
# =======================
#
# VTEPs:
#   Active:          5
#   Capacity:        unlimited
#   Status:          healthy
#
# VNIs:
#   Active:          15
#   Limit:           4,096
#   Usage:           0.4%
#
# MAC Tables:
#   Total Entries:   1,245
#   Limit:           65,536 per VNI
#   Largest VNI:     1000100 (245 entries, 0.4%)
#
# Tunnels:
#   Active:          30 (5 VTEPs x 6 VNIs avg)
#   Limit:           1,024 per host
#   Usage:           2.9%
#
# OpenFlow:
#   Total Flows:     3,245
#   Limit:           100,000
#   Usage:           3.2%
#
# Recommendations:
#   - All resources within normal limits
#   - No action required
```

### Growth Projections

```bash
# Project capacity needs
platformctl sdn overlay capacity project --months 6

# Expected output:
# 6-Month Capacity Projection
# ===========================
#
# Based on current growth rate:
#   VNI growth:      +2/month
#   MAC growth:      +150/month
#   VTEP growth:     +1/month
#
# Projected at 6 months:
#   VNIs:            27 (0.7% of capacity)
#   MACs:            2,145 (3.3% of capacity)
#   VTEPs:           11
#   Tunnels:         99
#
# Status: No capacity concerns for next 6 months
```

## Backup and Recovery

### Backing Up Overlay State

```bash
# Export overlay configuration
platformctl sdn overlay backup --output /backup/overlay-$(date +%Y%m%d).json

# Expected output:
# Overlay Backup Created
# ======================
# File:       /backup/overlay-20260119.json
# VTEPs:      5
# VNIs:       15
# MACs:       1,245
# Tunnels:    30
# Size:       2.3 MB
```

**Backup Contents:**

| Component | Included | Restoration |
|-----------|----------|-------------|
| VTEP Registry | Yes | Auto-registered on restart |
| VNI Definitions | Yes | Restored on import |
| MAC Tables | No | Relearned automatically |
| Tunnel State | No | Reestablished automatically |
| OpenFlow Rules | No | Regenerated from VNI/MAC state |

### Restoring Overlay State

**After Node Failure:**

```bash
# New node joins cluster automatically
# VTEP state is pulled from QuicBaaS
# Tunnels establish automatically
# MACs are relearned from traffic

# Verify recovery
platformctl sdn overlay status
```

**Full Cluster Recovery:**

```bash
# If QuicBaaS cluster is restored from backup
platformctl sdn overlay restore --input /backup/overlay-20260119.json

# Verify restoration
platformctl sdn overlay vni list
platformctl sdn overlay vtep list
```

### Disaster Recovery Checklist

1. **Verify QuicBaaS Cluster Health**
   ```bash
   platformctl datastore status
   ```

2. **Check All VTEPs Registered**
   ```bash
   platformctl sdn overlay vtep list
   ```

3. **Verify VNI Membership**
   ```bash
   platformctl sdn overlay vni list
   ```

4. **Confirm Tunnel Establishment**
   ```bash
   platformctl sdn overlay tunnel list
   ```

5. **Test East-West Connectivity**
   ```bash
   # From VM on host A, ping VM on host B
   ping <vm-b-ip>
   ```

6. **Verify ARP Suppression**
   ```bash
   platformctl sdn overlay arp stats
   ```

## Common Operational Tasks

### Task: Add New Tenant VLAN

```bash
# 1. Create VNI for new VLAN
platformctl sdn overlay vni create \
  --vni 1000400 \
  --vlan 400 \
  --name "tenant-acme"

# 2. Verify on all hosts
platformctl sdn overlay vni list | grep 1000400

# 3. Add ports to the VLAN (via policy engine)
platformctl sdn policy set-vlan tap-vm010 400
```

### Task: Migrate VM to Another Host

```bash
# Before migration: Note current VTEP
platformctl sdn overlay mac find aa:bb:cc:dd:ee:10 --vni 1000100
# VTEP: 10.0.0.1 (node-001)

# Perform VM migration (hypervisor-specific)
# ...

# After migration: Verify MAC moved
platformctl sdn overlay mac find aa:bb:cc:dd:ee:10 --vni 1000100
# VTEP: 10.0.0.2 (node-002)

# If MAC stuck, force update
platformctl sdn overlay mac move \
  --mac aa:bb:cc:dd:ee:10 \
  --vni 1000100 \
  --to-vtep 10.0.0.2
```

### Task: Investigate Broadcast Storm

```bash
# Check BUM traffic levels
platformctl sdn overlay bum stats

# Identify source
platformctl sdn overlay bum top --vni 1000100

# Expected output:
# Top BUM Sources (VNI 1000100)
# =============================
# MAC               TYPE        PPS     SOURCE
# ff:ff:ff:ff:ff:ff broadcast   1,234   tap-vm005
# 01:00:5e:00:00:01 multicast   567     tap-vm008
# aa:bb:cc:dd:ee:99 unknown     45      10.0.0.2

# Quarantine offending port
platformctl sdn policy block tap-vm005
```

### Task: Upgrade Overlay Software

```bash
# 1. Verify current version
platformctl version

# 2. Put node in maintenance mode
platformctl sdn overlay maintenance --enable

# 3. Drain sessions (graceful)
platformctl sdn overlay drain --timeout 60s

# 4. Perform upgrade
systemctl stop platformd
# ... upgrade steps ...
systemctl start platformd

# 5. Exit maintenance mode
platformctl sdn overlay maintenance --disable

# 6. Verify health
platformctl sdn overlay status
```

## See Also

- [Architecture](architecture.md) - VXLAN overlay architecture
- [Configuration](configuration.md) - Configuration reference
- [API Reference](api-reference.md) - REST/gRPC API documentation
- [CLI Usage](../cli-usage.md) - Complete CLI reference
