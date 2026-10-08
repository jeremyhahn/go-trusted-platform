# VXLAN Overlay Operations Guide

## Overview

This guide covers day-to-day operations for the VXLAN overlay network,
including VTEP management, VNI lifecycle, tunnel monitoring, and MAC
table operations.

The overlay CLI surface is `platformctl sdn overlay` with the
subcommands `status`, `vtep list|get`, `vni list|create|delete`,
`tunnel list`, and `mac list|forget`.

## Overlay Status

```bash
platformctl sdn overlay status
platformctl sdn overlay status -o json
```

Shows the node ID and VTEP IP, the number of known VTEPs, VNIs,
tunnels, and remote MACs, and the overall health status.

## VTEP Management

### Adding a New Host to the Overlay

When adding a new compute host to the overlay network:

**1. Verify Prerequisites**

```bash
# Check underlay connectivity from new host
ping -c 3 10.0.0.1  # Existing VTEP

# Verify MTU carries an encapsulated 9000-byte frame (must be >= 9050)
ip link show eth0 | grep mtu
# mtu 9216 qdisc mq state UP mode DEFAULT

# Verify OVS is running
systemctl status openvswitch-switch
ovs-vsctl show
```

**2. Start the Overlay Service**

```bash
# Start platformd with the overlay enabled; the VTEP registers itself
systemctl start platformd

# Verify the local VTEP is registered
platformctl sdn overlay vtep list

# Inspect the new VTEP by node ID
platformctl sdn overlay vtep get node-005
```

**3. Verify Tunnel Establishment**

```bash
# Check tunnels from the new host
platformctl sdn overlay tunnel list

# Verify the one flow-based VXLAN port (remote_ip=flow, key=flow);
# there is no port per remote VTEP
ovs-vsctl list interface vxlan-evpn
```

### Removing a Host from the Overlay

```bash
# 1. Migrate or stop workloads on the host first

# 2. Stop the overlay service on the host
systemctl stop platformd

# 3. From another node, verify the VTEP is gone
platformctl sdn overlay vtep list
```

### VTEP Health Monitoring

```bash
# Overall overlay health (VTEP/VNI/tunnel/MAC counts, health status)
platformctl sdn overlay status

# Per-VTEP details
platformctl sdn overlay vtep get node-001

# Poll for changes
watch platformctl sdn overlay vtep list
```

## VNI Management

### Creating a Virtual Network

```bash
# Create VNI mapped to VLAN 100
platformctl sdn overlay vni create --vni 1000100 --vlan 100 --name production-web

# Verify the VNI is registered
platformctl sdn overlay vni list
platformctl sdn overlay vni list -o yaml

# Where the overlay mode handler runs, verify its decap flows: one
# tun_id/tun_src flow per remote VTEP on the VNI (../gateway/overlay-mode.md)
ovs-ofctl -O OpenFlow13 dump-flows br-int table=10
```

### Deleting a Virtual Network

```bash
# Check for remote MACs still active in the VNI before deleting
platformctl sdn overlay mac list --vni 1000100

# Delete the VNI
platformctl sdn overlay vni delete 1000100

# Confirm deletion
platformctl sdn overlay vni list | grep 1000100
# Should return no results
```

**Warning:** Deleting a VNI with active ports will disrupt connectivity
for those devices.

## Tunnel Monitoring

```bash
# List all VXLAN tunnels
platformctl sdn overlay tunnel list

# Filter by VNI
platformctl sdn overlay tunnel list --vni 1000100

# Poll for changes
watch platformctl sdn overlay tunnel list
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

# Verify the remote VTEP is registered
platformctl sdn overlay vtep get node-002
```

**Suspected Underlay Problems:**

```bash
# Check underlay for packet loss
ping -c 100 10.0.0.2 | tail -3

# Trace underlay path
traceroute 10.0.0.2

# Interface counters and drops
ip -s link show
```

## MAC Table Management

MAC entries are learned from remote VTEPs via EVPN.

### Viewing MAC Tables

```bash
# List all remote MACs
platformctl sdn overlay mac list

# Filter by VNI
platformctl sdn overlay mac list --vni 1000100

# Find a specific MAC
platformctl sdn overlay mac list --vni 1000100 | grep -i aa:bb:cc:dd:ee:02
```

### Clearing MAC Entries

```bash
# Remove a stale MAC entry from the FDB (relearned via EVPN if still active)
platformctl sdn overlay mac forget aa:bb:cc:dd:ee:02 --vni 1000100

# Verify removal
platformctl sdn overlay mac list --vni 1000100 | grep -i aa:bb:cc:dd:ee:02
# Should return no results
```

## Recovery

Overlay state is rebuilt automatically: VTEPs re-register when
platformd starts, tunnels re-establish from the VTEP registry, and MAC
entries are relearned via EVPN. There is no separate backup/restore
step for overlay state.

### Recovery Checklist

1. **Check All VTEPs Registered**
   ```bash
   platformctl sdn overlay vtep list
   ```

2. **Verify VNI Membership**
   ```bash
   platformctl sdn overlay vni list
   ```

3. **Confirm Tunnel Establishment**
   ```bash
   platformctl sdn overlay tunnel list
   ```

4. **Test East-West Connectivity**
   ```bash
   # From VM on host A, ping VM on host B
   ping <vm-b-ip>
   ```

## Common Operational Tasks

### Task: Add New Tenant VLAN

```bash
# 1. Create VNI for the new VLAN
platformctl sdn overlay vni create --vni 1000400 --vlan 400 --name tenant-acme

# 2. Verify on all hosts
platformctl sdn overlay vni list | grep 1000400
```

### Task: Migrate VM to Another Host

```bash
# Before migration: note the current VTEP for the VM's MAC
platformctl sdn overlay mac list --vni 1000100 | grep -i aa:bb:cc:dd:ee:10

# Perform VM migration (hypervisor-specific)
# ...

# After migration: verify the MAC moved to the new VTEP
platformctl sdn overlay mac list --vni 1000100 | grep -i aa:bb:cc:dd:ee:10

# If the entry is stale, forget it and let EVPN relearn from the new host
platformctl sdn overlay mac forget aa:bb:cc:dd:ee:10 --vni 1000100
```

### Task: Upgrade Overlay Software

```bash
# 1. Verify current version
platformctl version

# 2. Migrate or stop workloads on this host

# 3. Perform upgrade
systemctl stop platformd
# ... upgrade steps ...
systemctl start platformd

# 4. Verify health
platformctl sdn overlay status
platformctl sdn overlay tunnel list
```

## See Also

- [Architecture](architecture.md) - VXLAN overlay architecture
- [Configuration](configuration.md) - Configuration reference
- [API Reference](api-reference.md) - REST/gRPC API documentation
- [CLI Usage](../cli-usage.md) - Complete CLI reference
