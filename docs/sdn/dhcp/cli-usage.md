# DHCP CLI Usage

> **Status: REFERENCE** · Last verified: 2026-10-15
> Why there is no `platformctl sdn dhcp` command group.

## Overview

There is **no `platformctl sdn dhcp` command group**. The DHCP engine is an
in-process library (see [README](README.md)) and no daemon runs it today:
platformd's `sdn.dhcp` section only logs the zones it would serve, and
gatewayd refuses its `dhcp:` section (see [Configuration](configuration.md)).

## Observing Pool State

The engine allocates from the platform IPAM system, so the pools it would
serve are visible through the IPAM CLI. With no daemon running the engine,
the allocations listed are not DHCP leases today:

```bash
# Pools (utilization, CIDR, gateway, zone)
platformctl sdn ipam pool list
platformctl sdn ipam pool get --id <pool-id>

# Current allocations (all pools, or one pool)
platformctl sdn ipam allocations
platformctl sdn ipam allocations --pool-id <pool-id>

# Release an allocation
platformctl sdn ipam release --ip 10.0.0.50
```

## Common Workflows

### Reclaim an Address

```bash
platformctl sdn ipam release --ip <ip>
```

## See Also

- [README](README.md) — Service overview and architecture
- [Configuration](configuration.md) — `sdn.dhcp` YAML reference
- [API Reference](api-reference.md) — Go service interface
- [SDN CLI Usage](../cli-usage.md) — Full SDN CLI reference
