# DHCP CLI Usage

## Overview

The `platformctl sdn dhcp` commands provide comprehensive management of the DHCP service including server status, lease management, pool statistics, and interface configuration. This document covers all available commands, their options, and common operational workflows.

## Command Structure

```
platformctl sdn dhcp <subcommand> [options]

Subcommands:
  status     Show DHCP server status
  stats      Show server statistics
  lease      Manage DHCP leases
  pool       Pool information and statistics
  interface  Interface configuration
  pxe        PXE boot configuration
```

## Server Status

### Show DHCP Server Status

Displays the current state of the DHCP server including running state, interfaces, and backend configuration.

```bash
platformctl sdn dhcp status [options]

Options:
  -o, --output    Output format: text|json|yaml (default: text)
```

**Example:**

```bash
$ platformctl sdn dhcp status

DHCP Server Status
==================

Server State:
  Running:            true
  Uptime:             7d 12h 34m
  IPAM Backend:       quicbaas

Interfaces:
  INTERFACE   ADDRESS         POOL-ID         NETWORK   STATE
  eth0        192.168.1.1     internal-pool   private   active
  eth1        10.0.0.1        public-pool     public    active
  br-prov     192.168.100.1   provisioning    private   active

PXE Boot:
  Enabled:            true
  TFTP Server:        192.168.1.10
  Default Boot File:  pxelinux.0

Global Options:
  Default Lease:      24h
  Renewal (T1):       12h
  Rebind (T2):        21h
```

**JSON Output:**

```bash
$ platformctl sdn dhcp status -o json
{
  "running": true,
  "uptime_seconds": 648840,
  "ipam_backend": "quicbaas",
  "interfaces": [
    {
      "name": "eth0",
      "address": "192.168.1.1",
      "pool_id": "internal-pool",
      "network": "private",
      "state": "active"
    }
  ],
  "pxe": {
    "enabled": true,
    "next_server": "192.168.1.10",
    "boot_file": "pxelinux.0"
  },
  "default_lease_duration": "24h0m0s"
}
```

### Show Server Statistics

Displays DHCP message statistics and performance metrics.

```bash
platformctl sdn dhcp stats [options]

Options:
  -o, --output    Output format: text|json|yaml (default: text)
  --reset         Reset statistics counters
```

**Example:**

```bash
$ platformctl sdn dhcp stats

DHCP Server Statistics
======================

Message Counters:
  MESSAGE TYPE      RECEIVED    SENT
  DISCOVER          12,456      -
  OFFER             -           12,400
  REQUEST           12,345      -
  ACK               -           12,290
  NAK               -           55
  RELEASE           1,234       -
  DECLINE           12          -
  INFORM            567         567

Error Counters:
  Pool Exhausted:       3
  Invalid Requests:     15
  Allocation Failures:  8

Performance:
  Avg Response Time:    1.2ms
  Peak Response Time:   15ms
  Active Leases:        8,456
```

## Lease Management

### List Leases

Displays all active DHCP leases.

```bash
platformctl sdn dhcp lease list [options]

Options:
  -o, --output    Output format: text|json|yaml (default: text)
  --pool          Filter by pool ID
  --interface     Filter by interface
  --state         Filter by state: active|expired|reserved
  --expired       Include expired leases
```

**Example:**

```bash
$ platformctl sdn dhcp lease list

DHCP Leases
===========

MAC ADDRESS         IP ADDRESS      HOSTNAME        POOL            EXPIRES         STATE
aa:bb:cc:dd:ee:01   192.168.1.10    webserver-1     internal-pool   23h 45m         active
aa:bb:cc:dd:ee:02   192.168.1.11    webserver-2     internal-pool   22h 30m         active
aa:bb:cc:dd:ee:03   192.168.1.12    database-1      internal-pool   12h 15m         active
aa:bb:cc:dd:ee:04   10.0.0.10       edge-device-1   public-pool     7h 22m          active
11:22:33:44:55:66   192.168.100.5   -               provisioning    10m 30s         active

Total: 5 active leases
```

**Filter by Pool:**

```bash
$ platformctl sdn dhcp lease list --pool internal-pool

DHCP Leases (Pool: internal-pool)
=================================

MAC ADDRESS         IP ADDRESS      HOSTNAME        EXPIRES         STATE
aa:bb:cc:dd:ee:01   192.168.1.10    webserver-1     23h 45m         active
aa:bb:cc:dd:ee:02   192.168.1.11    webserver-2     22h 30m         active
aa:bb:cc:dd:ee:03   192.168.1.12    database-1      12h 15m         active

Total: 3 active leases
```

### Get Lease by MAC

Retrieves detailed information about a specific lease.

```bash
platformctl sdn dhcp lease get --mac <MAC> [options]

Options:
  --mac           MAC address (required)
  -o, --output    Output format: text|json|yaml (default: text)
```

**Example:**

```bash
$ platformctl sdn dhcp lease get --mac aa:bb:cc:dd:ee:01

Lease Details
=============

MAC Address:      aa:bb:cc:dd:ee:01
IP Address:       192.168.1.10
Hostname:         webserver-1
Pool ID:          internal-pool
Interface:        eth0

Lease Timing:
  State:          active
  Allocated:      2024-01-15 10:30:00 UTC
  Expires:        2024-01-16 10:30:00 UTC
  Remaining:      23h 45m

DHCP Options Sent:
  Subnet Mask:    255.255.255.0
  Router:         192.168.1.1
  DNS:            8.8.8.8, 8.8.4.4
  Domain:         example.local
  Lease Time:     86400s

Client Info:
  Vendor Class:   PXEClient:Arch:00000
  Client ID:      01:aa:bb:cc:dd:ee:01
  Request Count:  3
```

### Get Lease by IP

Retrieves lease information by IP address.

```bash
platformctl sdn dhcp lease get-ip --ip <IP> [options]

Options:
  --ip            IP address (required)
  -o, --output    Output format: text|json|yaml (default: text)
```

**Example:**

```bash
$ platformctl sdn dhcp lease get-ip --ip 192.168.1.10
# (Same output as get by MAC)
```

### Release Lease

Manually releases a DHCP lease, returning the IP to the pool.

```bash
platformctl sdn dhcp lease release [options]

Options:
  --mac           Release by MAC address
  --ip            Release by IP address
  --force         Force release without confirmation
```

**Example:**

```bash
$ platformctl sdn dhcp lease release --mac aa:bb:cc:dd:ee:01
Lease for aa:bb:cc:dd:ee:01 (192.168.1.10) released successfully

$ platformctl sdn dhcp lease release --ip 192.168.1.10
Lease for 192.168.1.10 (aa:bb:cc:dd:ee:01) released successfully
```

### Reserve IP for MAC

Creates a static reservation for a MAC address.

```bash
platformctl sdn dhcp lease reserve [options]

Options:
  --mac           MAC address (required)
  --ip            IP address to reserve (required)
  --hostname      Hostname for the reservation
  --pool          Pool ID (required)
```

**Example:**

```bash
$ platformctl sdn dhcp lease reserve \
  --mac aa:bb:cc:dd:ee:ff \
  --ip 192.168.1.100 \
  --hostname important-server \
  --pool internal-pool
Reservation created: aa:bb:cc:dd:ee:ff -> 192.168.1.100
```

### List Reservations

Shows all static IP reservations.

```bash
platformctl sdn dhcp lease reservations [options]

Options:
  -o, --output    Output format: text|json|yaml (default: text)
  --pool          Filter by pool ID
```

**Example:**

```bash
$ platformctl sdn dhcp lease reservations

Static Reservations
===================

MAC ADDRESS         IP ADDRESS      HOSTNAME            POOL
aa:bb:cc:dd:ee:ff   192.168.1.100   important-server    internal-pool
11:22:33:44:55:66   192.168.1.101   critical-db         internal-pool

Total: 2 reservations
```

### Delete Reservation

Removes a static IP reservation.

```bash
platformctl sdn dhcp lease unreserve --mac <MAC>

Options:
  --mac       MAC address (required)
  --force     Force deletion without confirmation
```

**Example:**

```bash
$ platformctl sdn dhcp lease unreserve --mac aa:bb:cc:dd:ee:ff
Reservation deleted: aa:bb:cc:dd:ee:ff
```

## Pool Management

### List Pools

Shows all DHCP pools with usage statistics.

```bash
platformctl sdn dhcp pool list [options]

Options:
  -o, --output    Output format: text|json|yaml (default: text)
```

**Example:**

```bash
$ platformctl sdn dhcp pool list

DHCP Pools
==========

POOL ID          CIDR              GATEWAY       TOTAL   ALLOCATED   AVAILABLE   UTILIZATION
internal-pool    192.168.1.0/24    192.168.1.1   254     156         98          61.4%
public-pool      10.0.0.0/24       10.0.0.1      254     45          209         17.7%
provisioning     192.168.100.0/24  192.168.100.1 254     12          242         4.7%

Total: 3 pools, 213 allocations
```

### Show Pool Details

Displays detailed information about a specific pool.

```bash
platformctl sdn dhcp pool show <pool-id> [options]

Options:
  -o, --output    Output format: text|json|yaml (default: text)
```

**Example:**

```bash
$ platformctl sdn dhcp pool show internal-pool

Pool Details: internal-pool
===========================

Configuration:
  CIDR:           192.168.1.0/24
  Gateway:        192.168.1.1
  Range Start:    192.168.1.10
  Range End:      192.168.1.250

Allocation Statistics:
  Total IPs:      241
  Allocated:      156
  Available:      85
  Reserved:       5
  Utilization:    64.7%

DHCP Options:
  Subnet Mask:    255.255.255.0
  Router:         192.168.1.1
  DNS:            8.8.8.8, 8.8.4.4
  Domain:         example.local
  Lease Time:     24h
  Renewal (T1):   12h
  Rebind (T2):    21h

Bound Interfaces:
  - eth0 (192.168.1.1)
```

### Pool Statistics

Shows allocation trends and usage patterns.

```bash
platformctl sdn dhcp pool stats <pool-id> [options]

Options:
  -o, --output    Output format: text|json|yaml (default: text)
  --period        Time period: 1h|24h|7d|30d (default: 24h)
```

**Example:**

```bash
$ platformctl sdn dhcp pool stats internal-pool --period 24h

Pool Statistics: internal-pool (Last 24h)
=========================================

Utilization Trend:
  Peak:           78% (14:30 UTC)
  Low:            52% (04:00 UTC)
  Average:        65%

Allocation Activity:
  New Leases:     45
  Renewals:       312
  Releases:       23
  Declines:       2

Lease Duration Distribution:
  < 1h:           5%
  1-4h:           15%
  4-12h:          30%
  12-24h:         50%
```

## Interface Configuration

### List Interfaces

Shows all DHCP-enabled interfaces.

```bash
platformctl sdn dhcp interface list [options]

Options:
  -o, --output    Output format: text|json|yaml (default: text)
```

**Example:**

```bash
$ platformctl sdn dhcp interface list

DHCP Interfaces
===============

INTERFACE   ADDRESS         NETWORK   POOL-ID         STATE     LEASES
eth0        192.168.1.1     private   internal-pool   active    156
eth1        10.0.0.1        public    public-pool     active    45
br-prov     192.168.100.1   private   provisioning    active    12
```

### Show Interface Details

Displays detailed interface configuration.

```bash
platformctl sdn dhcp interface show <interface> [options]

Options:
  -o, --output    Output format: text|json|yaml (default: text)
```

**Example:**

```bash
$ platformctl sdn dhcp interface show eth0

Interface Details: eth0
=======================

Configuration:
  Address:        192.168.1.1
  Network Type:   private
  Pool ID:        internal-pool
  State:          active

DHCP Options:
  Subnet Mask:    255.255.255.0
  Router:         192.168.1.1
  DNS:            8.8.8.8, 8.8.4.4
  Domain:         example.local
  Lease Time:     24h
  NTP:            pool.ntp.org
  MTU:            1500

Statistics:
  Active Leases:  156
  Discover:       12,456
  Offer:          12,400
  Request:        12,345
  Ack:            12,290
```

### Update Interface Options

Updates DHCP options for an interface.

```bash
platformctl sdn dhcp interface set-option <interface> [options]

Options:
  --dns           DNS servers (comma-separated)
  --domain        Domain name
  --lease-time    Lease duration
  --router        Default gateway
  --ntp           NTP servers (comma-separated)
  --mtu           Interface MTU
```

**Example:**

```bash
$ platformctl sdn dhcp interface set-option eth0 \
  --dns 1.1.1.1,8.8.8.8 \
  --domain corp.example.com \
  --lease-time 48h
Interface eth0 options updated

$ platformctl sdn dhcp interface set-option br-prov \
  --lease-time 15m \
  --dns 192.168.100.1
Interface br-prov options updated
```

## PXE Configuration

### Show PXE Status

Displays PXE boot configuration.

```bash
platformctl sdn dhcp pxe status [options]

Options:
  -o, --output    Output format: text|json|yaml (default: text)
```

**Example:**

```bash
$ platformctl sdn dhcp pxe status

PXE Boot Configuration
======================

State:              enabled
TFTP Server:        192.168.1.10
TFTP Root:          /var/lib/tftpboot
Default Boot File:  pxelinux.0

Architecture Mappings:
  ARCH CODE   ARCHITECTURE        BOOT FILE
  0           Intel x86 BIOS      pxelinux.0
  7           EFI x86-64 (UEFI)   shimx64.efi
  11          ARM64 UEFI          shimaa64.efi

Recent PXE Clients:
  MAC ADDRESS         ARCH        BOOT FILE       TIME
  aa:bb:cc:dd:ee:01   BIOS        pxelinux.0      5m ago
  11:22:33:44:55:66   UEFI x64    shimx64.efi     12m ago
```

### Set PXE Server

Updates the PXE TFTP server address.

```bash
platformctl sdn dhcp pxe set-server --address <IP>

Options:
  --address     TFTP server IP address (required)
```

**Example:**

```bash
$ platformctl sdn dhcp pxe set-server --address 192.168.1.20
PXE TFTP server updated to 192.168.1.20
```

### Set Boot File

Updates the default or architecture-specific boot file.

```bash
platformctl sdn dhcp pxe set-bootfile [options]

Options:
  --file        Boot file name (required)
  --arch        Architecture code (optional, sets default if omitted)
```

**Example:**

```bash
# Set default boot file
$ platformctl sdn dhcp pxe set-bootfile --file ipxe.pxe
Default boot file updated to ipxe.pxe

# Set architecture-specific boot file
$ platformctl sdn dhcp pxe set-bootfile --file grubx64.efi --arch 7
Boot file for architecture 7 (UEFI x64) updated to grubx64.efi
```

### List Architecture Mappings

Shows all architecture-to-bootfile mappings.

```bash
platformctl sdn dhcp pxe architectures [options]

Options:
  -o, --output    Output format: text|json|yaml (default: text)
```

**Example:**

```bash
$ platformctl sdn dhcp pxe architectures

PXE Architecture Mappings
=========================

CODE  NAME                BOOT FILE
0     Intel x86 BIOS      pxelinux.0
6     EFI IA32            bootia32.efi
7     EFI x86-64          shimx64.efi
9     EFI Byte Code       -
10    ARM 32-bit UEFI     -
11    ARM 64-bit UEFI     shimaa64.efi
15    x86-64 UEFI HTTP    http://boot.example.com/bootx64.efi
```

## Troubleshooting Commands

### Debug DHCP Transaction

Traces a DHCP transaction for a specific MAC address.

```bash
platformctl sdn dhcp debug transaction --mac <MAC> [options]

Options:
  --mac           MAC address to trace (required)
  --duration      Trace duration (default: 60s)
  --verbose       Show packet details
```

**Example:**

```bash
$ platformctl sdn dhcp debug transaction --mac aa:bb:cc:dd:ee:01 --duration 30s

Tracing DHCP for aa:bb:cc:dd:ee:01 (30s)...

[00:00:02] DISCOVER received on eth0
           Client: aa:bb:cc:dd:ee:01
           Options: Hostname=webserver, Vendor=PXEClient
[00:00:02] OFFER sent
           IP: 192.168.1.10, Lease: 86400s
[00:00:02] REQUEST received
           Requested IP: 192.168.1.10
[00:00:02] ACK sent
           IP: 192.168.1.10, Lease: 86400s

Transaction Summary:
  Duration:       245ms
  Result:         Success
  IP Assigned:    192.168.1.10
```

### Check Pool Health

Diagnoses pool allocation issues.

```bash
platformctl sdn dhcp debug pool <pool-id> [options]

Options:
  -o, --output    Output format: text|json|yaml (default: text)
```

**Example:**

```bash
$ platformctl sdn dhcp debug pool internal-pool

Pool Health Check: internal-pool
================================

Status: HEALTHY

Checks:
  [OK] Pool has available addresses (85 available)
  [OK] Gateway address is valid
  [OK] CIDR is properly configured
  [OK] No duplicate allocations detected
  [OK] All leases have valid expiry times

Warnings:
  [WARN] Utilization at 64.7% - consider expanding pool

Recent Allocation Failures: 0 (last 24h)
```

### View DHCP Logs

Shows DHCP server logs.

```bash
platformctl sdn dhcp logs [options]

Options:
  --lines         Number of lines to show (default: 50)
  --follow        Follow log output
  --level         Filter by level: debug|info|warn|error
  --mac           Filter by MAC address
  --interface     Filter by interface
```

**Example:**

```bash
$ platformctl sdn dhcp logs --lines 10 --level warn

2024-01-15T10:30:15Z WARN  pool exhaustion approaching: internal-pool at 85%
2024-01-15T10:28:45Z WARN  DECLINE received: 192.168.1.50 (conflict detected by client)
2024-01-15T09:15:30Z WARN  unknown MAC aa:bb:cc:dd:ee:99 requested specific IP
```

### Test DHCP Configuration

Validates DHCP configuration without starting the server.

```bash
platformctl sdn dhcp test-config [options]

Options:
  --config        Path to config file (default: /etc/trusted-platform/platform.yaml)
```

**Example:**

```bash
$ platformctl sdn dhcp test-config

DHCP Configuration Test
=======================

[OK] Server configuration valid
[OK] Interface eth0 configuration valid
[OK] Interface eth1 configuration valid
[OK] Pool internal-pool valid (254 addresses)
[OK] Pool public-pool valid (254 addresses)
[OK] PXE configuration valid
[OK] IPAM backend connection successful

All checks passed. Configuration is valid.
```

## Example Workflows

### Finding a Device by MAC Address

```bash
# 1. Get lease information
$ platformctl sdn dhcp lease get --mac aa:bb:cc:dd:ee:01

# 2. Check lease history
$ platformctl sdn dhcp logs --mac aa:bb:cc:dd:ee:01 --lines 20
```

### Troubleshooting DHCP Failure

```bash
# 1. Check server status
$ platformctl sdn dhcp status

# 2. Check pool availability
$ platformctl sdn dhcp pool show internal-pool

# 3. Debug the transaction
$ platformctl sdn dhcp debug transaction --mac aa:bb:cc:dd:ee:01

# 4. Check logs for errors
$ platformctl sdn dhcp logs --level error --lines 20
```

### Setting Up PXE Boot

```bash
# 1. Enable PXE
$ platformctl sdn dhcp pxe set-server --address 192.168.1.10

# 2. Configure boot files for different architectures
$ platformctl sdn dhcp pxe set-bootfile --file pxelinux.0 --arch 0
$ platformctl sdn dhcp pxe set-bootfile --file shimx64.efi --arch 7
$ platformctl sdn dhcp pxe set-bootfile --file shimaa64.efi --arch 11

# 3. Verify configuration
$ platformctl sdn dhcp pxe status
```

### Managing Static Reservations

```bash
# 1. Create reservation for critical server
$ platformctl sdn dhcp lease reserve \
  --mac aa:bb:cc:dd:ee:ff \
  --ip 192.168.1.100 \
  --hostname critical-server \
  --pool internal-pool

# 2. Verify reservation
$ platformctl sdn dhcp lease reservations

# 3. If device already has a different IP, release it first
$ platformctl sdn dhcp lease release --mac aa:bb:cc:dd:ee:ff --force
```

### Monitoring Pool Capacity

```bash
# 1. Check current utilization
$ platformctl sdn dhcp pool list

# 2. Get detailed stats
$ platformctl sdn dhcp pool stats internal-pool --period 7d

# 3. Set up alert threshold (via platform config)
# See configuration documentation
```

### Clearing Stale Leases

```bash
# 1. List expired leases
$ platformctl sdn dhcp lease list --expired

# 2. Release specific stale lease
$ platformctl sdn dhcp lease release --mac aa:bb:cc:dd:ee:01 --force

# 3. Bulk cleanup (use with caution)
$ platformctl sdn dhcp lease list --expired -o json | \
  jq -r '.leases[].mac' | \
  xargs -I {} platformctl sdn dhcp lease release --mac {} --force
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PLATFORM_DHCP_TIMEOUT` | Command timeout | 30s |
| `PLATFORM_DHCP_VERBOSE` | Enable verbose output | false |

## Configuration File

DHCP CLI commands respect settings in `~/.platformctl.yaml` or `/etc/trusted-platform/platformctl.yaml`:

```yaml
sdn:
  dhcp:
    default_output: json
    timeout: 60s
```

## See Also

- [DHCP Architecture](architecture.md) - DHCP service architecture
- [Configuration](configuration.md) - DHCP configuration reference
- [Plugins](plugins.md) - IPAM and PXE plugin documentation
- [API Reference](api-reference.md) - API overview
- [SDN CLI Usage](../cli-usage.md) - Main SDN CLI reference
