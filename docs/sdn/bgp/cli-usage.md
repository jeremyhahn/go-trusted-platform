# BGP CLI Usage

## Overview

The `platformctl sdn gateway bgp` commands provide comprehensive management of BGP operations for both EVPN overlay networking and IP transit routing. This document covers all available commands, their options, and common operational workflows.

## Command Structure

```
platformctl sdn gateway bgp <subcommand> [options]

Subcommands:
  status     Show BGP speaker status
  peers      List BGP peers and their state
  routes     List announced/received prefixes
  announce   Announce a prefix
  withdraw   Withdraw a prefix
  evpn       EVPN-specific operations
  transit    Transit-specific operations
```

## BGP Status

### Show BGP Speaker Status

Displays the current state of the BGP speaker including ASN, router ID, peer counts, and prefix statistics.

```bash
platformctl sdn gateway bgp status [options]

Options:
  -o, --output    Output format: text|json|yaml (default: text)
```

**Example:**

```bash
$ platformctl sdn gateway bgp status

BGP Speaker Status
==================

Speaker Configuration:
  Router ID:      23.143.36.1
  Local ASN:      65001
  Speaker Role:   backbone
  Listen Port:    179
  Running:        true

Peer Summary:
  Total Peers:    4
  Established:    3
  Active:         1
  Idle:           0

Route Summary:
  IPv6 Prefixes Announced:  12
  IPv4 Prefixes Announced:  1
  EVPN Routes:              47
  Total RIB Entries:        156

Features:
  EVPN:           enabled
  Transit:        enabled
  RPKI:           enabled
  Route Signing:  enabled
  Dampening:      enabled
```

**JSON Output:**

```bash
$ platformctl sdn gateway bgp status -o json
{
  "router_id": "23.143.36.1",
  "local_asn": 65001,
  "speaker_role": "backbone",
  "listen_port": 179,
  "running": true,
  "peer_summary": {
    "total": 4,
    "established": 3,
    "active": 1,
    "idle": 0
  },
  "route_summary": {
    "ipv6_announced": 12,
    "ipv4_announced": 1,
    "evpn_routes": 47,
    "total_rib": 156
  },
  "features": {
    "evpn": true,
    "transit": true,
    "rpki": true,
    "route_signing": true,
    "dampening": true
  }
}
```

## BGP Peers

### List BGP Peers

Displays all configured BGP peers and their current state.

```bash
platformctl sdn gateway bgp peers [options]

Options:
  -o, --output    Output format: text|json|yaml (default: text)
  --state         Filter by state: established|active|idle|connect
  --type          Filter by type: ebgp|ibgp
```

**Example:**

```bash
$ platformctl sdn gateway bgp peers

BGP Peers
=========

NEIGHBOR         REMOTE-AS  TYPE   STATE        UPTIME      PREFIXES  DESCRIPTION
198.51.100.1     64500      eBGP   Established  5d12h34m    3/12      ISP-Primary
203.0.113.1      64501      eBGP   Established  3d08h22m    2/12      ISP-Backup
10.0.0.2         65001      iBGP   Established  7d00h15m    47/47     Backbone-2
10.0.0.3         65001      iBGP   Active       -           0/0       Backbone-3 (connecting)

Legend: PREFIXES = Received/Sent
```

**Show Detailed Peer Information:**

```bash
$ platformctl sdn gateway bgp peers -o json
{
  "peers": [
    {
      "address": "198.51.100.1",
      "remote_asn": 64500,
      "type": "ebgp",
      "state": "Established",
      "uptime_seconds": 476054,
      "description": "ISP-Primary",
      "prefixes_received": 3,
      "prefixes_sent": 12,
      "messages_received": 45678,
      "messages_sent": 45690,
      "families": ["ipv4-unicast", "ipv6-unicast"],
      "bfd_enabled": true,
      "bfd_state": "up",
      "graceful_restart": true,
      "last_error": ""
    }
  ]
}
```

### Filter Peers by State

```bash
# Show only established peers
$ platformctl sdn gateway bgp peers --state established

# Show only eBGP peers
$ platformctl sdn gateway bgp peers --type ebgp
```

## Prefix Announcements

### List Announced Prefixes

Shows all prefixes currently being announced via BGP.

```bash
platformctl sdn gateway bgp routes [options]

Options:
  -o, --output    Output format: text|json|yaml (default: text)
  --family        Filter by address family: ipv4|ipv6|evpn
  --received      Show received prefixes instead of announced
```

**Example:**

```bash
$ platformctl sdn gateway bgp routes

Announced Prefixes
==================

PREFIX                  NEXT-HOP        AS-PATH     ORIGIN  COMMUNITY         STATUS
2602:F5BB::/36         2602:F5BB::1    65001       IGP     65001:100         Active
2602:F5BB:0001::/48    2602:F5BB::1    65001       IGP     65001:300         Active
23.143.36.0/24         23.143.36.1     65001       IGP     65001:100         Active

Total: 3 prefixes announced
```

**Show Received Prefixes:**

```bash
$ platformctl sdn gateway bgp routes --received

Received Prefixes
=================

PREFIX          NEXT-HOP        FROM            AS-PATH         LOCAL-PREF  MED
::/0            198.51.100.1    198.51.100.1    64500           100         0
0.0.0.0/0       198.51.100.1    198.51.100.1    64500           100         0
10.10.0.0/16    10.0.0.2        10.0.0.2        65001           200         0

Total: 3 prefixes received
```

### Announce a Prefix

Announces a new prefix to BGP peers.

```bash
platformctl sdn gateway bgp announce --prefix <PREFIX> [options]

Options:
  --prefix        Prefix to announce (required)
  --next-hop      Next hop address (default: local router IP)
  --community     BGP community (can be specified multiple times)
  --as-prepend    Number of times to prepend local AS
  --med           MED value
  --local-pref    Local preference (for iBGP)
  --no-export     Add no-export community
  --sign          Request coordinator signatures (default: true for transit)
```

**Examples:**

```bash
# Basic prefix announcement
$ platformctl sdn gateway bgp announce --prefix 2602:F5BB:1234::/48
Prefix 2602:F5BB:1234::/48 announced successfully

# Announce with custom next-hop
$ platformctl sdn gateway bgp announce --prefix 2602:F5BB:1234::/48 --next-hop 2602:F5BB::1

# Announce with community tags
$ platformctl sdn gateway bgp announce --prefix 2602:F5BB:1234::/48 \
  --community 65001:100 --community 65001:300

# Announce with AS-path prepending (make less preferred)
$ platformctl sdn gateway bgp announce --prefix 2602:F5BB:1234::/48 --as-prepend 3

# Announce blackhole route for DDoS mitigation
$ platformctl sdn gateway bgp announce --prefix 2602:F5BB:1234:5678::/64 \
  --community 65001:666
```

### Withdraw a Prefix

Withdraws a previously announced prefix.

```bash
platformctl sdn gateway bgp withdraw --prefix <PREFIX>

Options:
  --prefix    Prefix to withdraw (required)
  --force     Force withdrawal without confirmation
```

**Examples:**

```bash
# Withdraw a prefix
$ platformctl sdn gateway bgp withdraw --prefix 2602:F5BB:1234::/48
Prefix 2602:F5BB:1234::/48 withdrawn successfully

# Force withdrawal without confirmation
$ platformctl sdn gateway bgp withdraw --prefix 2602:F5BB:1234::/48 --force
```

## EVPN Commands

### Show EVPN Status

```bash
platformctl sdn gateway bgp evpn status [options]

Options:
  -o, --output    Output format: text|json|yaml (default: text)
```

**Example:**

```bash
$ platformctl sdn gateway bgp evpn status

EVPN Status
===========

State:        enabled
RD Auto:      65001:<VNI>
RT Auto:      65001:<VNI>
VNI Range:    10000-19999

Route Types:
  Type-2 (MAC/IP):      47 routes
  Type-3 (Multicast):   12 routes
  Type-5 (IP Prefix):   8 routes

VNI Summary:
  Active VNIs:          12
  Local MACs:           156
  Remote MACs:          423
```

### List EVPN Routes

```bash
platformctl sdn gateway bgp evpn routes [options]

Options:
  -o, --output    Output format: text|json|yaml (default: text)
  --type          Filter by route type: 2|3|5 (MAC/IP, Multicast, IP Prefix)
  --vni           Filter by VNI
  --mac           Filter by MAC address
```

**List Type-2 (MAC/IP) Routes:**

```bash
$ platformctl sdn gateway bgp evpn routes --type 2

EVPN Type-2 Routes (MAC/IP)
===========================

RD              VNI     MAC                 IP              NEXT-HOP      SEQ
65001:10000     10000   aa:bb:cc:dd:ee:01   192.168.1.10    10.0.0.1      0
65001:10000     10000   aa:bb:cc:dd:ee:02   192.168.1.11    10.0.0.2      0
65001:10001     10001   aa:bb:cc:dd:ee:03   192.168.2.10    10.0.0.1      0

Total: 3 routes
```

**List Type-3 (Multicast) Routes:**

```bash
$ platformctl sdn gateway bgp evpn routes --type 3

EVPN Type-3 Routes (Inclusive Multicast)
========================================

RD              VNI     ORIGINATOR      PMSI-TYPE
65001:10000     10000   10.0.0.1        Ingress Replication
65001:10000     10000   10.0.0.2        Ingress Replication
65001:10001     10001   10.0.0.1        Ingress Replication

Total: 3 routes
```

**List Type-5 (IP Prefix) Routes:**

```bash
$ platformctl sdn gateway bgp evpn routes --type 5

EVPN Type-5 Routes (IP Prefix)
==============================

RD              VNI     PREFIX              NEXT-HOP      GATEWAY-MAC
65001:10000     10000   192.168.1.0/24      10.0.0.1      aa:bb:cc:00:00:01
65001:10001     10001   192.168.2.0/24      10.0.0.1      aa:bb:cc:00:00:01

Total: 2 routes
```

### Advertise EVPN MAC/IP

```bash
platformctl sdn gateway bgp evpn advertise-mac [options]

Options:
  --mac       MAC address (required)
  --ip        IP address (optional, for ARP suppression)
  --vni       VNI to advertise in (required)
```

**Example:**

```bash
$ platformctl sdn gateway bgp evpn advertise-mac \
  --mac aa:bb:cc:dd:ee:ff \
  --ip 192.168.1.100 \
  --vni 10000
MAC/IP advertised successfully
```

### Withdraw EVPN MAC/IP

```bash
platformctl sdn gateway bgp evpn withdraw-mac [options]

Options:
  --mac       MAC address (required)
  --vni       VNI (required)
```

**Example:**

```bash
$ platformctl sdn gateway bgp evpn withdraw-mac --mac aa:bb:cc:dd:ee:ff --vni 10000
MAC withdrawn successfully
```

## Transit Commands

### Show Transit Status

```bash
platformctl sdn gateway bgp transit status [options]

Options:
  -o, --output    Output format: text|json|yaml (default: text)
```

**Example:**

```bash
$ platformctl sdn gateway bgp transit status

Transit Mode Status
===================

State:          enabled
Speaker Role:   backbone
RPKI:           enabled

Announced Prefixes:
  IPv6:
    - 2602:F5BB::/36 (aggregate)
    - 2602:F5BB:0001::/48 (region-1)
  IPv4:
    - 23.143.36.0/24

RPKI Validation:
  Server:         rpki-validator.example.com:8323
  Last Refresh:   5m ago
  Valid ROAs:     2
  Cache Status:   fresh

Dampening:
  Suppressed Routes:  0
  Half-Life:          15m
```

### RPKI Validation Status

```bash
platformctl sdn gateway bgp transit rpki [options]

Options:
  -o, --output    Output format: text|json|yaml (default: text)
  --prefix        Check specific prefix validation
```

**Example:**

```bash
$ platformctl sdn gateway bgp transit rpki

RPKI Validation Status
======================

RTR Servers:
  SERVER                          PORT   STATE       SERIAL   PREFIXES
  rpki-validator.example.com      8323   Connected   12345    2
  rpki-backup.example.com         8323   Standby     12344    2

ROA Cache:
  Valid ROAs:         2
  Last Refresh:       5m ago
  Next Refresh:       5m
  Cache Lifetime:     1h

Platform ROAs:
  PREFIX              MAX-LEN   ASN     VALIDITY
  2602:F5BB::/36      /48       65001   Valid
  23.143.36.0/24      /24       65001   Valid
```

**Check Prefix Validation:**

```bash
$ platformctl sdn gateway bgp transit rpki --prefix 2602:F5BB::/36
Prefix 2602:F5BB::/36: VALID (ROA: ASN 65001, max-length /48)
```

### Dampening Status

```bash
platformctl sdn gateway bgp transit dampening [options]

Options:
  -o, --output    Output format: text|json|yaml (default: text)
  --suppressed    Show only suppressed routes
```

**Example:**

```bash
$ platformctl sdn gateway bgp transit dampening

BGP Dampening Status
====================

Configuration:
  Half-Life:          15m
  Suppress Threshold: 2000
  Reuse Threshold:    750
  Max Suppress Time:  60m

Dampened Routes:
  PREFIX              PENALTY   SUPPRESSED   REUSE-IN
  (none)

Flap History:
  PREFIX                  FLAPS   LAST-FLAP      PENALTY
  2602:F5BB:0001::/48     2       1h23m ago      150
```

### Route Signing Status

```bash
platformctl sdn gateway bgp transit signing [options]

Options:
  -o, --output    Output format: text|json|yaml (default: text)
```

**Example:**

```bash
$ platformctl sdn gateway bgp transit signing

Route Signing Status
====================

State:        enabled
Quorum:       3 signatures required

Coordinators:
  COORDINATOR                      STATUS      LATENCY    LAST-SIGN
  coordinator-1.example.com:9443   Connected   12ms       5m ago
  coordinator-2.example.com:9443   Connected   15ms       5m ago
  coordinator-3.example.com:9443   Connected   18ms       5m ago

Recent Signing Operations:
  PREFIX                  TIME        SIGNATURES   RESULT
  2602:F5BB::/36          5m ago      3/3          Success
  2602:F5BB:0001::/48     1h ago      3/3          Success
```

## Troubleshooting Commands

### Debug BGP Session

```bash
platformctl sdn gateway bgp debug session <peer-address> [options]

Options:
  --duration    Debug duration (default: 30s)
  --verbose     Show packet-level details
```

**Example:**

```bash
$ platformctl sdn gateway bgp debug session 198.51.100.1 --duration 10s

Debugging BGP session to 198.51.100.1 for 10s...

[00:00:01] KEEPALIVE sent
[00:00:02] KEEPALIVE received
[00:00:05] UPDATE received: 1 NLRI, 0 withdrawn
[00:00:08] KEEPALIVE sent
[00:00:09] KEEPALIVE received

Session Summary:
  Messages Sent:      2
  Messages Received:  3
  Updates Received:   1
  Errors:             0
```

### Check Route Propagation

```bash
platformctl sdn gateway bgp debug route <prefix> [options]

Options:
  -o, --output    Output format: text|json|yaml (default: text)
```

**Example:**

```bash
$ platformctl sdn gateway bgp debug route 2602:F5BB::/36

Route Propagation Analysis
==========================

Prefix: 2602:F5BB::/36

Local State:
  Origin:         IGP
  Next-Hop:       2602:F5BB::1
  AS-Path:        65001
  Communities:    65001:100
  RPKI:           Valid

Peer Advertisements:
  PEER              STATE         AS-PATH SENT      COMMUNITY SENT
  198.51.100.1      Advertised    65001             65001:100
  203.0.113.1       Advertised    65001 65001 65001 65001:100
  10.0.0.2          Advertised    65001             65001:100

Signing Status:
  Signatures:       3/3
  Last Signed:      5m ago
```

### View BGP Logs

```bash
platformctl sdn gateway bgp logs [options]

Options:
  --lines       Number of lines to show (default: 50)
  --follow      Follow log output
  --level       Filter by level: debug|info|warn|error
  --peer        Filter by peer address
```

**Example:**

```bash
$ platformctl sdn gateway bgp logs --lines 10 --level warn

2024-01-15T10:30:15Z WARN  peer 10.0.0.3: connection refused, retrying in 30s
2024-01-15T10:28:45Z WARN  route dampening: prefix 2602:F5BB:0002::/48 penalty increased to 1500
```

## Example Workflows

### Announcing a New Regional Prefix

```bash
# 1. Verify BGP speaker is running
$ platformctl sdn gateway bgp status
# Confirm: Running: true

# 2. Check RPKI ROA exists for the prefix
$ platformctl sdn gateway bgp transit rpki --prefix 2602:F5BB:1234::/48
# Should show: Valid

# 3. Announce the prefix
$ platformctl sdn gateway bgp announce --prefix 2602:F5BB:1234::/48 \
  --community 65001:300

# 4. Verify announcement
$ platformctl sdn gateway bgp routes | grep 2602:F5BB:1234

# 5. Check peer propagation
$ platformctl sdn gateway bgp debug route 2602:F5BB:1234::/48
```

### Checking Peer Health

```bash
# 1. List all peers
$ platformctl sdn gateway bgp peers

# 2. If a peer is not Established, check details
$ platformctl sdn gateway bgp peers -o json | jq '.peers[] | select(.state != "Established")'

# 3. Debug the session
$ platformctl sdn gateway bgp debug session 10.0.0.3

# 4. Check logs for errors
$ platformctl sdn gateway bgp logs --peer 10.0.0.3 --level error
```

### Troubleshooting Route Not Visible

```bash
# 1. Verify local announcement
$ platformctl sdn gateway bgp routes | grep <prefix>

# 2. Check RPKI status
$ platformctl sdn gateway bgp transit rpki --prefix <prefix>

# 3. Check if route is dampened
$ platformctl sdn gateway bgp transit dampening --suppressed

# 4. Verify route signing
$ platformctl sdn gateway bgp transit signing

# 5. Check peer advertisement
$ platformctl sdn gateway bgp debug route <prefix>
```

### Emergency Blackhole for DDoS

```bash
# 1. Announce blackhole route
$ platformctl sdn gateway bgp announce \
  --prefix 2602:F5BB:1234:5678::/64 \
  --community 65001:666

# 2. Verify announcement
$ platformctl sdn gateway bgp routes | grep 2602:F5BB:1234:5678

# 3. When attack subsides, withdraw
$ platformctl sdn gateway bgp withdraw --prefix 2602:F5BB:1234:5678::/64 --force
```

### EVPN MAC Learning Verification

```bash
# 1. Check EVPN status
$ platformctl sdn gateway bgp evpn status

# 2. Verify MAC is advertised locally
$ platformctl sdn gateway bgp evpn routes --type 2 --mac aa:bb:cc:dd:ee:ff

# 3. Check VNI routes
$ platformctl sdn gateway bgp evpn routes --vni 10000

# 4. Verify multicast tree
$ platformctl sdn gateway bgp evpn routes --type 3 --vni 10000
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PLATFORM_BGP_TIMEOUT` | Command timeout | 30s |
| `PLATFORM_BGP_VERBOSE` | Enable verbose output | false |

## Configuration File

BGP CLI commands respect settings in `~/.platformctl.yaml` or `/etc/trusted-platform/platformctl.yaml`:

```yaml
sdn:
  gateway:
    bgp:
      default_output: json
      timeout: 60s
```

## See Also

- [BGP Architecture](architecture.md) - BGP architecture and speaker topology
- [EVPN](evpn.md) - EVPN implementation details
- [Transit](transit.md) - BGP transit mode and IP block management
- [Configuration](configuration.md) - BGP configuration reference
- [SDN CLI Usage](../cli-usage.md) - Main SDN CLI reference
