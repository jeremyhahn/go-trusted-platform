# BGP CLI Usage

## Overview

The `platformctl sdn gateway bgp` commands manage the BGP speaker used
for EVPN overlay networking and IP transit routing. Every command works
over all client protocols (REST, gRPC, QUIC, MCP, Unix) and honors the
global `-o/--output table|json|yaml` flag.

## Command Structure

```
platformctl sdn gateway bgp <subcommand> [options]

Subcommands:
  status     Show BGP speaker status
  peers      List configured BGP peers
  routes     List announced prefixes
  announce   Announce a prefix
  withdraw   Withdraw a previously announced prefix
```

## Speaker Status

```bash
platformctl sdn gateway bgp status
platformctl sdn gateway bgp status -o json
```

Shows:

- Local ASN and router ID
- Peer count and established peers
- Number of announced prefixes
- Running state

## Peers

```bash
platformctl sdn gateway bgp peers
platformctl sdn gateway bgp peers -o json
```

Lists all configured BGP peers. To filter, pipe the JSON output:

```bash
# Peers that are not established
platformctl sdn gateway bgp peers -o json | jq '.peers[] | select(.state != "Established")'
```

## Announced Prefixes

```bash
platformctl sdn gateway bgp routes
```

Lists all prefixes currently being announced by this speaker.

## Announce a Prefix

```bash
platformctl sdn gateway bgp announce --prefix <PREFIX> [--next-hop <NEXT-HOP>]

Options:
  --prefix     Prefix to announce (required)
  --next-hop   Next hop address (optional)

Examples:
  platformctl sdn gateway bgp announce --prefix 2001:DB8:1234::/48
  platformctl sdn gateway bgp announce --prefix 203.0.113.0/24 --next-hop 10.0.0.1
```

## Withdraw a Prefix

```bash
platformctl sdn gateway bgp withdraw --prefix <PREFIX>

Examples:
  platformctl sdn gateway bgp withdraw --prefix 2001:DB8:1234::/48
```

## Common Workflows

### Verify a Prefix is Being Announced

```bash
platformctl sdn gateway bgp status
platformctl sdn gateway bgp routes | grep 2001:DB8:1234
```

### Investigate a Peer That Won't Establish

```bash
# 1. Confirm the peer is configured and check its state
platformctl sdn gateway bgp peers

# 2. Check daemon logs for session events on the gateway node
journalctl -u platformd | grep -i bgp
```

## EVPN and Transit Features

EVPN route handling (MAC/IP advertisement, VNI membership) and transit
policy features are managed by the daemon itself and are not exposed as
dedicated CLI subcommands today. Overlay-facing EVPN state is visible
through the overlay CLI:

```bash
# MACs learned via EVPN from remote VTEPs
platformctl sdn overlay mac list --vni <VNI>

# VTEPs and tunnels
platformctl sdn overlay vtep list
platformctl sdn overlay tunnel list
```

See [EVPN](evpn.md) and [Transit](transit.md) for the underlying
architecture.

## See Also

- [README](README.md) — BGP service overview
- [Configuration](configuration.md) — BGP configuration reference
- [Troubleshooting](troubleshooting.md) — Session and route debugging
- [SDN CLI Usage](../cli-usage.md) — Full SDN CLI reference
