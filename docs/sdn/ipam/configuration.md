# IPAM Configuration Reference

## Overview

This document provides a comprehensive configuration reference for the IPAM service, covering pool configuration, backend selection, zone assignment, seed reconciliation, lease management, and operational parameters.

## Configuration Structure

### YAML Configuration

```yaml
sdn:
  ipam:
    # Backend selection: "memory" (default), "quicbaas", or "dht" (requires platform_p2p build tag)
    backend: "quicbaas"

    # Pool definitions (seed-only: created when missing, never overwritten at runtime)
    pools:
      - name: "production"
        cidr: "10.0.0.0/24"
        gateway: "10.0.0.1"
        zone: "trusted"               # optional; inherited from network.zone when omitted
        default_lease_duration: "24h"
        inactivity_timeout: "720h"

      - name: "provisioning"
        cidr: "10.1.0.0/24"
        gateway: "10.1.0.1"
        zone: "provisioning"

    # Lease management
    lease:
      default_duration: "24h"
      max_duration: "168h"
      renewal_threshold: "20%"
      inactivity_timeout: "720h"
      expiration_check_interval: "1h"
```

## Backend Selection

The `backend` field controls which storage engine is used for IPAM state.
Valid values are `"memory"` (default when omitted), `"quicbaas"`, and `"dht"`.

### Memory Backend

In-memory storage for development and testing:

```yaml
sdn:
  ipam:
    backend: memory
```

**Characteristics:**

| Property | Value |
|----------|-------|
| Persistence | None (data lost on restart) |
| Consistency | Strong (single instance) |
| Performance | Fastest |
| Use Case | Development, testing, single-node |

### QuicBaaS Backend

Production backend with Raft-based distributed consensus:

```yaml
sdn:
  ipam:
    backend: quicbaas
```

Requires the platform QuicBaaS SDK client to be configured under the top-level `quicbaas:` section. If the SDK client is not configured when `platformd` starts, the service returns `ErrIPAMBackendUnconfigured`.

**Characteristics:**

| Property | Value |
|----------|-------|
| Persistence | Raft log + snapshots |
| Consistency | Strong (Raft consensus) |
| Performance | Moderate (network consensus) |
| Use Case | Production, multi-node clusters |

### DHT Backend

Distributed backend for P2P environments. Requires the binary to be built with the `platform_p2p` build tag:

```
go build -tags platform_p2p ./cmd/platformd
```

```yaml
sdn:
  ipam:
    backend: dht
```

If `backend: dht` is set but the binary was built without `platform_p2p`, `platformd` returns `ErrIPAMBackendP2PRequired` at startup.

**Characteristics:**

| Property | Value |
|----------|-------|
| Persistence | DHT network (replicated) |
| Consistency | Eventual (claim-based) |
| Performance | Variable (network dependent) |
| Use Case | P2P networks, decentralized deployments |

## Pool Configuration

### Pool Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `name` | string | Yes | - | Unique pool name |
| `cidr` | string | Yes | - | Network prefix (CIDR notation) |
| `gateway` | string | No | - | Gateway IP address |
| `zone` | string | No | inherited | Zone for zone-filtered queries |
| `description` | string | No | "" | Pool description |
| `tags` | []string | No | [] | Classification tags |
| `default_lease_duration` | duration | No | 0 (no expiry) | Default lease time |
| `inactivity_timeout` | duration | No | 720h | Inactivity expiration |

### Zone Field

The `zone` field on a pool enables zone-filtered queries via `ListPoolsByZone`. It is a string matching one of the resolved zone names declared in the `sdn.zones` section (or the built-in zone set).

Zone resolution order at `Validate()` time:

1. If a pool's `zone` is empty **and** a network entry references the pool, the network's `zone` is inherited in-place. The pool's YAML on disk is not modified — the inheritance is runtime-only.
2. If a pool has an explicit `zone` that differs from a referencing network's `zone`, `Validate()` returns `ErrNetworkPoolZoneMismatch`.
3. If a pool has an explicit `zone` that is not declared in the resolved zone set, `Validate()` returns `ErrPoolZoneUndeclared`. This check applies to standalone pools (not referenced by any network) as well.

**Allocation stamping:** when an IP is allocated from a pool, the `Allocation.Zone` field is set to the pool's zone automatically. The `AllocationRequest.Zone` field is informational and is not currently used to select a pool; use `PoolID` for explicit targeting.

### Seeding Semantics

The `pools` list in IPAM config is a **seed list**, not an authoritative runtime state. On startup `initIPAMPools`:

1. Creates the backend allocator.
2. For each pool in config: if a pool with that name already exists in the backend, it is **skipped** (no mutation). If it does not exist, it is created with the zone from config.
3. Existing pools and their allocations are never deleted or overwritten by the seed step.

This means:
- Operators can change a runtime pool's zone or CIDR by editing the backend directly; the config will not override it on next boot.
- New pools can be added to config and they will be created on the next start.
- Removing a pool from config does not delete it from the backend.

### Zone Derivation from Subnets

When `sdn.ipam` is not explicitly configured but `network.subnets` entries exist (from the installer config), `platformd` automatically derives IPAM pools from internal subnets. The zone is derived from the subnet name using these mappings:

| Subnet name | Derived zone |
|------------|-------------|
| `production` | `trusted` |
| `provisioning` | `provisioning` |
| `quarantine` | `quarantine` |
| `storage` | `storage` |
| `management` | `management` |
| *(any other)* | `trusted` (with a warning log) |

Explicit pool config entries take precedence: if a pool with the same name exists in `sdn.ipam.pools`, the subnet-derived entry is skipped.

### Pool Validation Rules

| Rule | Validation |
|------|------------|
| Name | Non-empty, unique across all pools |
| CIDR | Valid IPv4 or IPv6 prefix |
| Zone | Must be a declared zone name when set (validated after zone resolution) |
| Gateway | Must be within CIDR range if specified |
| Lease Duration | Non-negative duration |
| Inactivity Timeout | Non-negative duration |

## Zone-Filtered Queries

```go
// Returns all pools in the "provisioning" zone.
pools, err := allocator.ListPoolsByZone(ctx, "provisioning")

// An empty zone string returns all pools (equivalent to ListPools).
all, err := allocator.ListPoolsByZone(ctx, "")
```

`ListPoolsByZone` is available on all three backends (memory, quicbaas, dht).

## Lease Configuration

### Global Lease Settings

```yaml
sdn:
  ipam:
    lease:
      default_duration: "24h"
      max_duration: "168h"
      renewal_threshold: "20%"
      inactivity_timeout: "720h"
      expiration_check_interval: "1h"
```

### Per-Pool Lease Override

```yaml
pools:
  - name: "short-lease"
    cidr: "10.1.0.0/24"
    zone: "provisioning"
    default_lease_duration: "1h"
    inactivity_timeout: "4h"

  - name: "no-expiry"
    cidr: "10.2.0.0/24"
    zone: "management"
    default_lease_duration: "0"
    inactivity_timeout: "0"
```

## Allocation Request

```go
// Automatic allocation from a zone-tagged pool
req := &ipam.AllocationRequest{
    PoolID:   "production",
    DeviceID: "vm-001",
    Hostname: "webserver-01",
}
alloc, err := allocator.Allocate(ctx, req)
// alloc.Zone == "trusted" (stamped from pool)

// Specific IP
req := &ipam.AllocationRequest{
    PoolID:      "production",
    DeviceID:    "db-001",
    RequestedIP: netip.MustParseAddr("10.0.0.100"),
}
```

## Complete Example

```yaml
sdn:
  enabled: true
  backend: quicbaas

  ipam:
    backend: quicbaas
    pools:
      - name: "production"
        cidr: "10.0.0.0/24"
        gateway: "10.0.0.1"
        zone: "trusted"
        default_lease_duration: "24h"
        inactivity_timeout: "720h"

      - name: "provisioning"
        cidr: "10.1.0.0/24"
        gateway: "10.1.0.1"
        zone: "provisioning"
        default_lease_duration: "8h"
        inactivity_timeout: "48h"

      - name: "management"
        cidr: "192.168.1.0/24"
        gateway: "192.168.1.1"
        zone: "management"
        default_lease_duration: "0"

    lease:
      default_duration: "24h"
      max_duration: "168h"
      renewal_threshold: "20%"
      inactivity_timeout: "720h"
      expiration_check_interval: "1h"

  networks:
    - name: "production-net"
      vlan: 10
      zone: trusted          # today's built-in zone; the reference design replaces it (#708)
      pool: "production"

    - name: "provisioning-net"
      vlan: 20
      zone: provisioning
      pool: "provisioning"
```

## See Also

- [Architecture](architecture.md) - IPAM architecture and design
- [API Reference](api-reference.md) - API overview
- [REST API](api-reference-rest.md) - REST endpoints
- [gRPC API](api-reference-grpc.md) - gRPC service methods
