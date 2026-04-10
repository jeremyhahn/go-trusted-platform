# BGP Troubleshooting Guide

## Overview

This guide provides diagnostic procedures and solutions for common BGP issues in the go-trusted-platform BGP service, covering peer session problems, route advertisement issues, EVPN troubleshooting, RPKI validation failures, and dampening investigation.

## Peer Session Issues

### Session Not Establishing

**Symptoms:**
- Peer state stuck in `Active` or `Connect`
- No routes exchanged
- Session timer expiring

**Step 1: Check Peer Configuration**

```bash
# View peer status
platformctl sdn gateway bgp peers

# Expected output:
# NEIGHBOR       AS      STATE        UP/DOWN   SENT    RECEIVED  DESCRIPTION
# 198.51.100.1   64500   Active       5m        0       0         ISP-Primary
# 10.0.0.2       65001   Established  14d       12345   54321     Backbone-2

# Get detailed peer info
platformctl sdn gateway bgp peer show 198.51.100.1

# Check configuration matches remote side:
# - Local AS matches remote peer's expectation
# - Remote AS is correct
# - MD5 password matches (if used)
```

**Step 2: Verify Network Connectivity**

```bash
# Test TCP connectivity to BGP port
nc -zv 198.51.100.1 179
# Connection to 198.51.100.1 179 port [tcp/bgp] succeeded!

# If connection fails, check routing
traceroute 198.51.100.1

# Check local firewall
iptables -L -n | grep 179
ip6tables -L -n | grep 179

# Verify BGP is listening
ss -tlnp | grep 179
# LISTEN  0  128  0.0.0.0:179  0.0.0.0:*  users:(("platformd",pid=1234,fd=15))
```

**Step 3: Check Authentication**

```bash
# View connection attempts in logs
journalctl -u platformd --since "1 hour ago" | grep -i "bgp.*198.51.100.1"

# Common authentication errors:
# "TCP MD5 signature mismatch" - Password doesn't match
# "Unexpected AS in OPEN message" - Remote AS misconfigured
# "Bad BGP identifier" - Router ID conflict
```

**Step 4: Verify TTL Security (if enabled)**

```bash
# Check TTL security configuration
platformctl sdn gateway bgp peer show 198.51.100.1 --json | jq '.ttl_security'

# If enabled, ensure direct connectivity (TTL must be high)
# For eBGP, TTL security typically requires TTL >= 254
```

**Solutions:**

| Issue | Solution |
|-------|----------|
| MD5 mismatch | Verify password on both sides |
| Wrong AS | Correct `remote_asn` in config |
| Firewall blocking | Allow TCP/179 bidirectionally |
| TTL too low | Disable TTL security or ensure direct link |
| Router ID conflict | Change router ID to unique value |

### Session Flapping

**Symptoms:**
- Session repeatedly transitions between `Established` and `Active`
- High notification message counts
- Route churn

**Step 1: Identify Flap Pattern**

```bash
# View session history
platformctl sdn gateway bgp peer history 198.51.100.1

# Expected output:
# TIME                 STATE         DURATION   REASON
# 2026-01-19 14:30:00  Established   2m 15s     -
# 2026-01-19 14:32:15  Idle          5s         Hold Timer Expired
# 2026-01-19 14:32:20  Established   3m 45s     -
# 2026-01-19 14:36:05  Idle          5s         Hold Timer Expired
```

**Step 2: Analyze Notification Messages**

```bash
# Check BGP notifications
platformctl sdn gateway bgp notifications --peer 198.51.100.1

# Common notifications:
# Error 4, Subcode 0: Hold Timer Expired
# Error 6, Subcode 1: Maximum Prefix Reached
# Error 6, Subcode 2: Administrative Shutdown
# Error 6, Subcode 4: Peer Deconfigured
```

**Step 3: Check for Resource Exhaustion**

```bash
# Check CPU/memory
top -p $(pgrep platformd)

# Check file descriptors
ls -la /proc/$(pgrep platformd)/fd | wc -l

# Check BGP memory usage
platformctl sdn gateway bgp stats --json | jq '.memory'
```

**Step 4: Examine Hold Timer**

```bash
# View negotiated timers
platformctl sdn gateway bgp peer show 198.51.100.1 --json | jq '.timers'

# Output:
# {
#   "negotiated_hold_time": 90,
#   "keepalive_interval": 30,
#   "last_keepalive_sent": "2s ago",
#   "last_keepalive_received": "28s ago"
# }

# If keepalives are delayed, check for CPU saturation
```

**Step 5: Enable BFD (if not already)**

```bash
# BFD provides faster failure detection
# Check BFD status
platformctl sdn gateway bgp bfd show 198.51.100.1

# Enable BFD
platformctl sdn gateway bgp peer modify 198.51.100.1 --bfd-enable
```

**Solutions:**

| Cause | Solution |
|-------|----------|
| Hold timer too aggressive | Increase hold time to 180s |
| Network instability | Enable BFD, investigate link |
| CPU overload | Scale resources, reduce routes |
| Memory exhaustion | Increase memory, reduce table size |
| Prefix limit exceeded | Increase limit or filter routes |

## Route Advertisement Issues

### Routes Not Being Advertised

**Symptoms:**
- Local routes exist but not seen by peer
- Peer receives fewer routes than expected
- Specific prefixes missing

**Step 1: Verify Route in Local RIB**

```bash
# Check local routing table
platformctl sdn gateway bgp routes local

# Search for specific prefix
platformctl sdn gateway bgp routes local | grep "2602:F5BB::/36"

# Expected output:
# PREFIX           NEXT-HOP    AS-PATH   ORIGIN  LOCAL-PREF  STATUS
# 2602:F5BB::/36   0.0.0.0     -         IGP     100         active
```

**Step 2: Check Export Policy**

```bash
# View export policy for peer
platformctl sdn gateway bgp peer show 198.51.100.1 --json | jq '.export_policy'

# Test prefix against policy
platformctl sdn gateway bgp policy test \
  --prefix "2602:F5BB::/36" \
  --direction export \
  --peer 198.51.100.1

# Output:
# Policy Evaluation: 2602:F5BB::/36 -> 198.51.100.1
# =================================================
# Policy: export-to-isp
# Rule 1: prefix_list "platform-aggregates" -> MATCH
# Action: accept, set_community [65001:100]
# Result: ACCEPT
```

**Step 3: Check Address Family Negotiation**

```bash
# Verify AFI/SAFI negotiated
platformctl sdn gateway bgp peer show 198.51.100.1 --json | jq '.address_families'

# Output:
# [
#   {"afi": "ipv4", "safi": "unicast", "state": "negotiated"},
#   {"afi": "ipv6", "safi": "unicast", "state": "negotiated"}
# ]

# If AFI/SAFI not negotiated, routes won't be sent
```

**Step 4: Check Route Signing (if required)**

```bash
# For coordinator-signed routes
platformctl sdn gateway bgp routes signing-status

# Output:
# PREFIX           SIGNATURES  REQUIRED  STATUS
# 2602:F5BB::/36   3           3         signed
# 23.143.36.0/24   2           3         pending (awaiting coordinator-3)

# If not fully signed, route won't be announced
```

**Step 5: View Advertised Routes to Peer**

```bash
# Show routes actually advertised to peer
platformctl sdn gateway bgp routes advertised --peer 198.51.100.1

# If empty or missing routes, policy is blocking
```

**Solutions:**

| Issue | Solution |
|-------|----------|
| Policy blocking | Modify export policy |
| AFI/SAFI not negotiated | Enable address family on both sides |
| Route not signed | Check coordinator connectivity |
| Next-hop unreachable | Set next-hop-self |
| IBGP without full mesh | Configure route reflector |

### Routes Not Being Received

**Symptoms:**
- Expected routes not in local table
- Peer claims to be advertising routes
- Specific prefixes filtered

**Step 1: Check Received Routes (Unfiltered)**

```bash
# View routes received before import policy
platformctl sdn gateway bgp routes received --peer 198.51.100.1 --unfiltered

# Compare with filtered view
platformctl sdn gateway bgp routes received --peer 198.51.100.1

# Difference shows routes being filtered
```

**Step 2: Test Import Policy**

```bash
# Test specific prefix against import policy
platformctl sdn gateway bgp policy test \
  --prefix "0.0.0.0/0" \
  --direction import \
  --peer 198.51.100.1

# Check if prefix is being filtered
```

**Step 3: Check RPKI Validation (if enabled)**

```bash
# Check RPKI status for received routes
platformctl sdn gateway bgp routes received --peer 198.51.100.1 --show-rpki

# Output:
# PREFIX           NEXT-HOP       AS-PATH        RPKI-STATUS
# 0.0.0.0/0        198.51.100.1   64500          valid
# 192.0.2.0/24     198.51.100.1   64500 65000    invalid (wrong AS)
# 203.0.113.0/24   198.51.100.1   64500 65100    not-found
```

**Step 4: Check Prefix Limits**

```bash
# View prefix counts
platformctl sdn gateway bgp peer show 198.51.100.1 --json | jq '.prefix_counts'

# Output:
# {
#   "ipv4_unicast": {"received": 4500, "limit": 5000, "warning": 4000},
#   "ipv6_unicast": {"received": 2100, "limit": 5000, "warning": 4000}
# }

# If at limit, no new routes accepted
```

## EVPN Route Problems

### Type-2 Routes Not Propagating

**Symptoms:**
- MAC/IP not learned on remote VTEPs
- ARP failing across overlay
- East-west traffic blackholed

**Step 1: Verify Type-2 Route Exists Locally**

```bash
# List local EVPN Type-2 routes
platformctl sdn gateway bgp evpn routes --type 2

# Expected output:
# RD             MAC               IP            VNI     VTEP        STATUS
# 65001:10000    aa:bb:cc:dd:ee:01 192.168.1.10  10000   10.0.0.1    active

# Check specific MAC
platformctl sdn gateway bgp evpn route find --mac aa:bb:cc:dd:ee:01

```

**Step 2: Check EVPN Address Family**

```bash
# Verify EVPN negotiated with peers
platformctl sdn gateway bgp peers --json | jq '.[].address_families[] | select(.afi=="l2vpn")'

# Must show "evpn" SAFI as "negotiated"
```

**Step 3: Verify Route Target Configuration**

```bash
# Check RT import/export
platformctl sdn gateway bgp evpn config show

# Output:
# EVPN Configuration
# ==================
# RD Type:      type1 (IP:assigned)
# RD Value:     10.0.0.1:10000
#
# Route Targets:
#   VNI 10000:  import 65001:10000, export 65001:10000
#   VNI 20000:  import 65001:20000, export 65001:20000

# Remote VTEP must have matching RT import
```

**Step 4: Check for Route Suppression**

```bash
# MAC mobility might suppress routes
platformctl sdn gateway bgp evpn mac-mobility --mac aa:bb:cc:dd:ee:01

# Output:
# MAC Mobility: aa:bb:cc:dd:ee:01
# ===============================
# Current Sequence: 5
# Move Count (window): 3
# Status: normal
# Last Move: 2026-01-19 14:30:00
```

**Solutions:**

| Issue | Solution |
|-------|----------|
| RT mismatch | Verify RT configuration on all VTEPs |
| EVPN not negotiated | Enable l2vpn-evpn address family |
| Duplicate detection | Clear MAC or wait for freeze timer |
| VNI not configured | Add VNI to EVPN configuration |

### Type-3 Routes Missing (BUM Traffic Issues)

**Symptoms:**
- Broadcast not reaching all VTEPs
- DHCP failing in overlay
- New MAC discovery failing

**Step 1: List Type-3 Routes**

```bash
# Check inclusive multicast routes
platformctl sdn gateway bgp evpn routes --type 3

# Each VTEP should have a Type-3 route per VNI
# VTEP          VNI     RD             STATUS
# 10.0.0.1      10000   65001:10000    active
# 10.0.0.2      10000   65001:10000    active
# 10.0.0.3      10000   65001:10000    active
```

**Step 2: Verify PMSI Tunnel Attribute**

```bash
# Check tunnel type in Type-3 route
platformctl sdn gateway bgp evpn route show --type 3 --vni 10000 --vtep 10.0.0.1 --json

# Should show ingress replication tunnel
```

**Step 3: Check VNI Membership**

```bash
# Verify VNI exists on all participating VTEPs
platformctl sdn overlay vni show 10000

# If VTEP missing, Type-3 route won't be generated
```

## Transit Route Issues

### Aggregate Not Being Announced

**Symptoms:**
- /36 aggregate not seen by ISP
- More-specific routes not summarized
- Traffic taking suboptimal path

**Step 1: Verify Aggregation Configuration**

```bash
# Check aggregation status
platformctl sdn gateway bgp aggregates

# Output:
# PREFIX           CONTRIBUTORS  STATUS     SUPPRESS-MAP
# 2602:F5BB::/36   12            active     summary-only
# 23.143.36.0/24   3             active     summary-only

# If missing contributors, check regional routes
```

**Step 2: Check Contributing Routes**

```bash
# List routes contributing to aggregate
platformctl sdn gateway bgp aggregate show 2602:F5BB::/36

# Output:
# Aggregate: 2602:F5BB::/36
# =========================
# Contributors:
#   2602:F5BB:0001::/48  via 10.0.0.2  (DC-East)
#   2602:F5BB:0002::/48  via 10.0.0.3  (DC-West)
#   2602:F5BB:0003::/48  via 10.0.0.4  (DC-Central)
# ...
```

**Step 3: Verify Backbone Role**

```bash
# Only backbone speakers announce aggregates
platformctl sdn gateway bgp config show --json | jq '.speaker.role'

# Must be "backbone" to announce aggregates
```

**Step 4: Check Route Signing**

```bash
# Aggregates require coordinator signatures
platformctl sdn gateway bgp routes signing-status | grep "2602:F5BB::/36"

# All required signatures must be present
```

### More-Specifics Leaking to ISPs

**Symptoms:**
- ISP seeing regional /48s instead of /36
- Routing inconsistency
- BGP table bloat at ISPs

**Step 1: Check Suppress Map**

```bash
# Verify summary-only is enabled
platformctl sdn gateway bgp aggregate show 2602:F5BB::/36 --json | jq '.summary_only'

# Should be true
```

**Step 2: Check Export Policy**

```bash
# Verify policy filters more-specifics
platformctl sdn gateway bgp policy test \
  --prefix "2602:F5BB:0001::/48" \
  --direction export \
  --peer 198.51.100.1

# Should show: REJECT (more-specific suppressed)
```

**Step 3: Review Advertised Routes**

```bash
# Check what's actually going to ISP
platformctl sdn gateway bgp routes advertised --peer 198.51.100.1

# Should only show aggregate
```

## RPKI Validation Failures

### Routes Being Rejected as Invalid

**Symptoms:**
- Valid routes marked RPKI invalid
- Traffic blackholed
- Connectivity issues to specific destinations

**Step 1: Check RPKI Status**

```bash
# View RPKI validation status
platformctl sdn gateway bgp rpki status

# Output:
# RPKI Status
# ===========
# State:       connected
# Server:      rpki-validator.example.com:8323
# Last Sync:   2026-01-19 14:25:00
# ROAs:        245,678
# Serials:     current: 12345, session: 1
```

**Step 2: Query Specific Prefix**

```bash
# Check ROA for specific prefix
platformctl sdn gateway bgp rpki query --prefix 192.0.2.0/24 --asn 64500

# Output:
# RPKI Query: 192.0.2.0/24 origin AS64500
# =======================================
# Status:     invalid
# Reason:     ROA exists for AS65000, not AS64500
# ROAs Found:
#   192.0.2.0/24 max-len /24 AS65000
```

**Step 3: Investigate ROA Issues**

```bash
# List all ROAs for a prefix
platformctl sdn gateway bgp rpki roas --prefix 192.0.2.0/24

# If ROA is incorrect, contact prefix owner
# If ROA is missing for your prefix, create one
```

**Step 4: Check RPKI Server Health**

```bash
# Test RPKI server connectivity
platformctl sdn gateway bgp rpki test-server

# Output:
# Server:      rpki-validator.example.com:8323
# TCP Connect: success (5ms)
# RTR Session: active
# PDU Rx:      serial-notify
# Status:      healthy
```

**Step 5: Force RPKI Refresh**

```bash
# If cache might be stale
platformctl sdn gateway bgp rpki refresh

# Wait for sync completion
watch platformctl sdn gateway bgp rpki status
```

**Solutions:**

| Issue | Solution |
|-------|----------|
| ROA mismatch | Contact prefix owner to update ROA |
| RPKI server down | Fail over to backup server |
| Stale cache | Force refresh |
| False positives | Temporarily set not-found to accept |

### Not-Found Policy Concerns

**Symptoms:**
- Many routes showing "not-found"
- Unsure if routes are legitimate
- Balancing security vs. connectivity

**Step 1: Analyze Not-Found Routes**

```bash
# List routes with RPKI not-found
platformctl sdn gateway bgp routes received --rpki-status not-found

# Review for suspicious patterns
# - Unknown origins
# - Unusual AS paths
# - Recently appeared routes
```

**Step 2: Check ROA Coverage Statistics**

```bash
# View RPKI coverage statistics
platformctl sdn gateway bgp rpki coverage

# Output:
# RPKI Coverage Statistics
# ========================
# Total Routes Evaluated: 125,456
# Valid:                  78,234 (62.4%)
# Invalid:                1,245 (1.0%)
# Not-Found:              45,977 (36.6%)
#
# Note: Global ROA coverage is approximately 40-50%
# Not-found is expected for many legitimate routes
```

## Dampening Investigation

### Route Being Dampened

**Symptoms:**
- Route suppressed despite being available
- Connectivity intermittent
- Route shows "damped" status

**Step 1: Check Dampening Status**

```bash
# List dampened routes
platformctl sdn gateway bgp dampening list

# Output:
# PREFIX           PEER           PENALTY  SUPPRESS  REUSE   STATUS
# 192.0.2.0/24     198.51.100.1   2500     2000      750     suppressed
# 203.0.113.0/24   198.51.100.1   1200     2000      750     decaying
```

**Step 2: View Dampening History**

```bash
# See flap history for specific route
platformctl sdn gateway bgp dampening history --prefix 192.0.2.0/24

# Output:
# Dampening History: 192.0.2.0/24
# ===============================
# TIME                 EVENT      PENALTY  STATUS
# 2026-01-19 14:00:00  withdrawn  +1000    normal
# 2026-01-19 14:05:00  announced  +0       normal
# 2026-01-19 14:10:00  withdrawn  +1000    normal
# 2026-01-19 14:15:00  announced  +0       normal
# 2026-01-19 14:20:00  withdrawn  +1000    suppressed (penalty=2500)
# 2026-01-19 14:25:00  announced  +0       suppressed (penalty=2100)
```

**Step 3: Calculate Time to Reuse**

```bash
# Estimate when route will be reused
platformctl sdn gateway bgp dampening estimate --prefix 192.0.2.0/24

# Output:
# Estimated Time to Reuse: 23 minutes
# Current Penalty: 2100
# Reuse Threshold: 750
# Half-Life: 15 minutes
```

**Step 4: Clear Dampening (if justified)**

```bash
# Manually clear dampening for a route
platformctl sdn gateway bgp dampening clear --prefix 192.0.2.0/24

# Warning: Route may be dampened again if it continues to flap
```

**Step 5: Investigate Flap Cause**

```bash
# Check peer stability
platformctl sdn gateway bgp peer history 198.51.100.1

# Check for network issues at source
# Contact upstream provider if their route is flapping
```

### Adjusting Dampening Parameters

```bash
# View current dampening configuration
platformctl sdn gateway bgp dampening config

# Output:
# Dampening Configuration
# =======================
# Enabled:            true
# Half-Life:          15 minutes
# Suppress Threshold: 2000
# Reuse Threshold:    750
# Max Suppress Time:  60 minutes

# Modify parameters (requires restart)
# Edit config file or use:
platformctl sdn gateway bgp dampening modify \
  --half-life 20m \
  --suppress-threshold 3000 \
  --reuse-threshold 1000
```

## Debug Logging

### Enabling Debug Logs

```bash
# Enable BGP debug logging
platformctl sdn gateway bgp debug enable --level debug

# Filter by component
platformctl sdn gateway bgp debug enable --component peer --level debug
platformctl sdn gateway bgp debug enable --component route --level debug
platformctl sdn gateway bgp debug enable --component policy --level debug

# View debug output
journalctl -u platformd -f | grep bgp
```

### Debug Categories

| Category | Use Case |
|----------|----------|
| `peer` | Session establishment, keepalives, notifications |
| `route` | Route processing, best path selection |
| `policy` | Policy evaluation, filtering decisions |
| `rpki` | RPKI validation, cache updates |
| `evpn` | EVPN route handling, MAC/IP learning |
| `update` | BGP UPDATE message processing |
| `fsm` | Finite state machine transitions |

### Disable Debug Logging

```bash
# Disable when done (important for performance)
platformctl sdn gateway bgp debug disable

# Or set back to info level
platformctl sdn gateway bgp debug enable --level info
```

## Packet Capture Tips

### Capturing BGP Traffic

```bash
# Capture BGP traffic on all interfaces
tcpdump -i any -w /tmp/bgp-capture.pcap port 179

# Capture for specific peer
tcpdump -i eth0 -w /tmp/bgp-peer.pcap host 198.51.100.1 and port 179

# Capture with verbose output (live)
tcpdump -i eth0 -nn -v port 179
```

### Analyzing BGP Captures

```bash
# Use tshark to decode BGP
tshark -r /tmp/bgp-capture.pcap -Y bgp -V

# Filter for specific message types
tshark -r /tmp/bgp-capture.pcap -Y "bgp.type == 2"  # UPDATE
tshark -r /tmp/bgp-capture.pcap -Y "bgp.type == 3"  # NOTIFICATION

# Export BGP updates for analysis
tshark -r /tmp/bgp-capture.pcap -Y bgp.update -T fields \
  -e ip.src -e bgp.nlri_prefix -e bgp.as_path
```

### Common BGP Message Types

| Type | Name | When to Look |
|------|------|--------------|
| 1 | OPEN | Session establishment issues |
| 2 | UPDATE | Route advertisement problems |
| 3 | NOTIFICATION | Session teardown, errors |
| 4 | KEEPALIVE | Hold timer issues |
| 5 | ROUTE-REFRESH | Policy change triggers |

## Common Error Messages

### Error Message Reference

| Error Message | Cause | Solution |
|---------------|-------|----------|
| "Hold Timer Expired" | Keepalives not received | Check network path, CPU load |
| "Peer De-configured" | Admin removed peer | Verify configuration |
| "Maximum Prefix Reached" | Too many routes from peer | Increase limit or filter |
| "Connection Refused" | BGP not listening or firewall | Check service status, firewall |
| "TCP MD5 signature mismatch" | Wrong password | Verify MD5 secret |
| "Unexpected AS" | AS number mismatch | Correct peer AS configuration |
| "Bad BGP Identifier" | Router ID conflict | Use unique router ID |
| "RPKI validation failed" | Origin AS doesn't match ROA | Contact prefix owner |
| "Route dampened" | Too many flaps | Wait or investigate cause |
| "Coordinator signature missing" | Route signing failed | Check coordinator connectivity |

### Notification Code Reference

| Error | Subcode | Description |
|-------|---------|-------------|
| 1 | 1 | Message Header Error - Connection Not Synchronized |
| 1 | 2 | Message Header Error - Bad Message Length |
| 1 | 3 | Message Header Error - Bad Message Type |
| 2 | 1 | OPEN Message Error - Unsupported Version |
| 2 | 2 | OPEN Message Error - Bad Peer AS |
| 2 | 3 | OPEN Message Error - Bad BGP Identifier |
| 2 | 4 | OPEN Message Error - Unsupported Optional Parameter |
| 3 | 1 | UPDATE Message Error - Malformed Attribute List |
| 3 | 2 | UPDATE Message Error - Unrecognized Well-known Attribute |
| 4 | 0 | Hold Timer Expired |
| 5 | 0 | Finite State Machine Error |
| 6 | 1 | Cease - Maximum Prefix Reached |
| 6 | 2 | Cease - Administrative Shutdown |
| 6 | 3 | Cease - Peer De-configured |
| 6 | 4 | Cease - Administrative Reset |

## Diagnostic Commands Summary

```bash
# Quick health check
platformctl sdn gateway bgp status

# Peer summary
platformctl sdn gateway bgp peers

# Route counts
platformctl sdn gateway bgp routes summary

# RPKI status
platformctl sdn gateway bgp rpki status

# Dampening status
platformctl sdn gateway bgp dampening list

# EVPN routes
platformctl sdn gateway bgp evpn routes

# Export diagnostic bundle
platformctl sdn gateway bgp diagnostic-bundle --output /tmp/bgp-diag.tar.gz
```

## See Also

- [Architecture](architecture.md) - BGP architecture overview
- [Configuration](configuration.md) - BGP configuration reference
- [EVPN](evpn.md) - EVPN-specific documentation
- [Transit](transit.md) - Transit routing documentation
- [Gateway Operations](../gateway/operations.md) - Gateway operational procedures
