# DHCP CLI Usage

## Overview

There is currently **no `platformctl sdn dhcp` command group**. The
DHCP server is an in-process service configured via the `sdn.dhcp` YAML
section (see [Configuration](configuration.md)); it starts and stops
with the daemon and has no dedicated CLI or wire API.

## Observing DHCP State

DHCP allocation is backed by the platform IPAM system, so lease-related
state is visible through the IPAM CLI:

```bash
# Pools backing DHCP allocation (utilization, CIDR, gateway, zone)
platformctl sdn ipam pool list
platformctl sdn ipam pool get --id <pool-id>

# Current allocations (all pools, or one pool)
platformctl sdn ipam allocations
platformctl sdn ipam allocations --pool-id <pool-id>

# Release an allocation
platformctl sdn ipam release --ip 10.0.0.50
```

Server-side visibility (interfaces, leases, PXE decisions) is available
through the daemon logs.

## Common Workflows

### Verify DHCP is Serving a Segment

```bash
# 1. Confirm the pool for the segment exists and has capacity
platformctl sdn ipam pool list

# 2. Trigger a client renewal on a test host, then confirm the allocation
platformctl sdn ipam allocations --pool-id <pool-id>
```

### Reclaim an Address

```bash
platformctl sdn ipam release --ip <ip>
```

## See Also

- [README](README.md) — Service overview and architecture
- [Configuration](configuration.md) — `sdn.dhcp` YAML reference
- [API Reference](api-reference.md) — Go service interface
- [SDN CLI Usage](../cli-usage.md) — Full SDN CLI reference
