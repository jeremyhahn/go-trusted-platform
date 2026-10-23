# VXLAN Overlay Operations Guide

> **Status: REFERENCE** · Last verified: 2026-10-15
> Day-to-day overlay operations.

## Overview

This guide covers day-to-day operations for the VXLAN overlay network,
including VTEP management, VNI lifecycle, tunnel monitoring, and MAC
table operations.

The overlay CLI surface is `platformctl sdn overlay` with the
subcommands `status`, `vtep list|get`, `vni list|create|delete`,
`tunnel list`, and `mac list|forget`.

These commands read platformd's overlay controller, whose records hold
the local VTEP and the VNIs only: nothing feeds it remote VTEPs, tunnels
or learned MACs (see
[Overlay Controller](architecture.md#overlay-controller)). On platformd
`vtep list` shows this node alone, and `tunnel list` and `mac list` print
nothing. The remote VTEPs and MACs EVPN delivers live in the gateway's
overlay data plane:

```bash
# Remote VTEPs a gateway admitted (omit --gateway-id for this node)
platformctl sdn gateway overlay vteps
platformctl sdn gateway overlay get 10.0.0.2

# The overlay counters: VNIs, remote VTEPs, local and remote MACs, ND
platformctl sdn gateway snapshot -o json
```

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
# On a gateway, check the new VTEP was admitted from its EVPN routes
platformctl sdn gateway overlay vteps

# Verify the one flow-based VXLAN port (remote_ip=flow, key=flow);
# there is no port per remote VTEP
ovs-vsctl list interface vxlan-evpn
```

### Removing a Host from the Overlay

```bash
# 1. Migrate or stop workloads on the host first

# 2. Stop the overlay service on the host
systemctl stop platformd

# 3. From a gateway, verify the VTEP is gone once its routes are withdrawn
platformctl sdn gateway overlay vteps
```

### VTEP Health Monitoring

```bash
# Overall overlay health (VTEP/VNI/tunnel/MAC counts, health status)
platformctl sdn overlay status

# Local VTEP details
platformctl sdn overlay vtep get node-001

# Remote VTEPs, as a gateway admitted them
watch platformctl sdn gateway overlay vteps
```

## VNI Management

### Creating a Virtual Network

```bash
# Create VNI mapped to VLAN 100 (--name is accepted and not stored)
platformctl sdn overlay vni create --vni 1000100 --vlan 100

# Verify the VNI is registered
platformctl sdn overlay vni list
platformctl sdn overlay vni list -o yaml

# Where the overlay mode handler runs, verify its decap flows: one
# tun_id/tun_src flow per remote VTEP on the VNI (docs/gateway/engineering.md §5a)
ovs-ofctl -O OpenFlow13 dump-flows br-int table=10
```

### Deleting a Virtual Network

```bash
# Check for MACs still active in the VNI before deleting (gateway counters)
platformctl sdn gateway snapshot -o json

# Delete the VNI
platformctl sdn overlay vni delete 1000100

# Confirm deletion
platformctl sdn overlay vni list | grep 1000100
# Should return no results
```

**Warning:** Deleting a VNI with active ports will disrupt connectivity
for those devices.

## Tunnel Monitoring

There is no tunnel per remote VTEP to list: one flow-based VXLAN port
carries every VNI, and `platformctl sdn overlay tunnel list` prints
nothing on platformd. Monitor the remote VTEPs a gateway admitted:

```bash
platformctl sdn gateway overlay vteps
watch platformctl sdn gateway overlay vteps
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

# Verify a gateway admitted the remote VTEP
platformctl sdn gateway overlay get 10.0.0.2
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

Remote MACs are learned from EVPN Type-2 routes by the gateway's overlay
mode handler, which holds them as flows; the snapshot counts them
(`local_mac_count`, `remote_mac_count`). `platformctl sdn overlay mac list`
and `mac forget` act on the overlay controller's records, which nothing
fills on platformd, so the list is empty and `forget` answers not found.

```bash
platformctl sdn gateway snapshot -o json
```

## Recovery

Overlay state is rebuilt automatically: the local VTEP re-registers when
platformd starts, and a gateway relearns remote VTEPs and MACs from EVPN.
The controller keeps its records in memory, so VNIs created through the
API are not kept across a platformd restart. A relaunched gateway
process keeps the overlay flows on the bridge forwarding while EVPN
re-learns them, and sweeps the ones nobody re-advertised once the BGP
graceful-restart time has passed. There is no separate
backup/restore step for overlay state.

### Recovery Checklist

1. **Check All VTEPs Registered**
   ```bash
   platformctl sdn overlay vtep list
   ```

2. **Verify VNI Membership**
   ```bash
   platformctl sdn overlay vni list
   ```

3. **Confirm Remote VTEPs**
   ```bash
   platformctl sdn gateway overlay vteps
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
platformctl sdn overlay vni create --vni 1000400 --vlan 400

# 2. Verify on all hosts
platformctl sdn overlay vni list | grep 1000400
```

### Task: Migrate VM to Another Host

```bash
# Perform VM migration (hypervisor-specific)
# ...

# The new host advertises the MAC with a higher MAC Mobility sequence;
# the gateway's flows follow the newest route. Check the counters:
platformctl sdn gateway snapshot -o json
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
platformctl sdn gateway overlay vteps
```


## See Also

- [Architecture](architecture.md) - VXLAN overlay architecture
- [Configuration](configuration.md) - Configuration reference
- [API Reference](api-reference.md) - REST/gRPC API documentation
- [CLI Usage](../cli-usage.md) - Complete CLI reference
