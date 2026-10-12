# BGP Troubleshooting Guide

## Overview

This guide provides diagnostic procedures for common BGP issues in the
go-trusted-platform BGP service, covering peer session problems, route
advertisement issues, EVPN troubleshooting, RPKI validation, and route
dampening.

The CLI diagnostic surface is `platformctl sdn gateway bgp` with the
subcommands `status`, `peers`, `routes`, `announce`, and `withdraw`
(see [CLI Usage](cli-usage.md)). RPKI validation and route dampening
run inside the speaker and surface through configuration and daemon
logs rather than dedicated CLI subcommands.

## Peer Session Issues

### Session Not Establishing

**Symptoms:**

- Peer state stuck in `Active` or `Connect`
- No routes exchanged

**Step 1: Check Peer State**

```bash
# View peer states
platformctl sdn gateway bgp peers
platformctl sdn gateway bgp peers -o json
```

**Step 2: Verify Basic Connectivity**

```bash
# Can we reach the peer?
ping <peer-address>

# Is TCP 179 reachable?
nc -zv <peer-address> 179

# Is anything blocking BGP?
iptables -L -n | grep 179
```

**Step 3: Check Configuration Both Sides**

Verify local and remote ASN, router ID uniqueness, and any TCP MD5
secret match the remote side's configuration. See
[Configuration](configuration.md) for the `bgp` config section.

**Step 4: Watch the Session Attempt**

```bash
# Live view of the OPEN exchange (or the failure)
tcpdump -i eth0 -nn -v host <peer-address> and port 179

# Daemon-side session events
journalctl -u platformd | grep -i bgp
```

### Session Flapping

**Symptoms:**

- Session repeatedly established then torn down
- Hold timer expirations in the logs

**Checks:**

```bash
# Watch for state changes
watch platformctl sdn gateway bgp peers

# Look for NOTIFICATION messages and hold-timer events
journalctl -u platformd | grep -i bgp | grep -i "notification\|hold"

# Rule out underlay packet loss
ping -c 100 <peer-address> | tail -3
```

Common causes: unstable underlay links, CPU saturation delaying
keepalives, MTU blackholes on the peering link, or an aggressive hold
timer on either side.

## Route Advertisement Issues

### Routes Not Being Advertised

```bash
# 1. Confirm the speaker believes it is announcing the prefix
platformctl sdn gateway bgp routes

# 2. If missing, announce it
platformctl sdn gateway bgp announce --prefix 2001:db8::/36

# 3. Confirm the peer session carrying it is established
platformctl sdn gateway bgp peers

# 4. Verify on the wire
tcpdump -i eth0 -nn host <peer-address> and port 179
```

If the prefix appears in `bgp routes` but the remote side does not see
it, check the remote side's import policy and prefix filters.

### Routes Not Being Received

Received-route inspection is not exposed via the CLI today. Verify from
the remote speaker that it is advertising, then confirm forwarding
behavior on this node (`ip route get <destination>`), and check the
daemon logs for UPDATE processing errors:

```bash
journalctl -u platformd | grep -i bgp | grep -i update
```

## EVPN Route Problems

EVPN route handling runs inside the speaker; its effects are visible
through the overlay CLI.

### Remote MACs Not Propagating

```bash
# 1. MACs learned via EVPN from remote VTEPs
platformctl sdn overlay mac list --vni <VNI>

# 2. Are the VTEPs registered and tunnels up?
platformctl sdn overlay vtep list
platformctl sdn overlay tunnel list --vni <VNI>

# 3. Is the BGP session between the VTEPs established?
platformctl sdn gateway bgp peers

# 4. Check EVPN processing in the logs
journalctl -u platformd | grep -i evpn
```

If a stale entry points at the wrong VTEP after a VM migration, remove
it and let EVPN relearn:

```bash
platformctl sdn overlay mac forget <mac> --vni <VNI>
```

### BUM Traffic Issues

Broadcast/unknown-unicast/multicast delivery depends on the VTEP flood
list. Verify every participating VTEP appears in
`platformctl sdn overlay vtep list` and that tunnels exist between them
for the affected VNI.

## RPKI Validation Failures

RPKI origin validation is implemented in the speaker
(`pkg/sdn/bgp/rpki.go`) and configured via the BGP configuration; there
is no dedicated CLI subcommand.

**If valid routes are being rejected:**

1. Check the RPKI validator connection and validation decisions in the
   daemon logs: `journalctl -u platformd | grep -i rpki`
2. Verify the ROA for the affected prefix against public RPKI data
   (e.g., your RIR's ROA lookup) — the origin ASN and max-length must
   match what is being announced.
3. If the ROA is wrong, the prefix owner must update it; do not disable
   validation as a workaround.

## Dampening Investigation

Route-flap dampening is implemented in the speaker
(`pkg/sdn/bgp/dampening.go`). A route that flaps repeatedly accumulates
penalty and is suppressed until the penalty decays below the reuse
threshold.

**If a route seems suppressed:**

```bash
# Confirm the flapping in the logs
journalctl -u platformd | grep -i bgp | grep <prefix>
```

Fix the underlying flap cause (unstable link or session) first — the
route is reused automatically once the penalty decays. Dampening
parameters are part of the BGP configuration; see
[Configuration](configuration.md).

## Debug Logging

BGP events log through the daemon logger. Raise the daemon log level to
`debug` in the platform configuration and restart, then follow the BGP
component output:

```bash
journalctl -u platformd -f | grep -i bgp
```

Remember to restore the normal log level afterwards — debug logging on
a busy speaker is expensive.

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

# Announced prefixes
platformctl sdn gateway bgp routes

# EVPN effects (overlay view)
platformctl sdn overlay mac list
platformctl sdn overlay vtep list

# Daemon-side BGP events
journalctl -u platformd | grep -i bgp
```

## See Also

- [CLI Usage](cli-usage.md) - BGP CLI reference
- [Architecture](architecture.md) - BGP architecture overview
- [Configuration](configuration.md) - BGP configuration reference
- [EVPN](evpn.md) - EVPN-specific documentation
- [Transit](transit.md) - Transit routing documentation
- [Gateway](../../gateway/user.md) - Gateway operational procedures
