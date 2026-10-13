# Cluster Configuration

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [architecture.md](architecture.md) and its siblings; describes an API surface and a `platformctl cluster` CLI that do not exist.

This document provides the complete configuration reference for go-trusted-platform cluster deployments.

## Configuration Overview

Cluster mode is enabled by configuring the `quicbaas` section in the platform configuration file with the `raft` storage backend.

## QuicBaaS Configuration

The quicbaas section configures the persistent storage backend for the platform.

### Complete QuicBaaS Schema

```yaml
quicbaas:
  # Storage backend type: memory, file, pebble, raft
  # - pebble: High-performance local storage (default)
  # - raft: Distributed Raft consensus for HA clusters
  storage-backend: pebble

  # Directory for QuicBaaS data files (PebbleDB)
  data-dir: /var/lib/trusted-platform/quicbaas

  # Write-ahead log directory (defaults to data-dir/wal)
  wal-dir: /var/lib/trusted-platform/quicbaas/wal

  # Unique node identifier in the cluster
  # Must be unique across all nodes (1, 2, 3, etc.)
  node-id: 1

  # In-memory cache size in bytes
  # Default: 67108864 (64MB)
  cache-size: 67108864

  # Logging verbosity: debug, info, warn, error
  # Default: warn
  log-level: warn

  # Read consistency level: linearizable, strong, eventual
  # Default: linearizable
  consistency-level: linearizable

  # Raft address advertised to peers (required with join-addresses;
  # must be routable: loopback, 0.0.0.0 or empty is refused)
  raft-address: "192.168.1.10:63000"

  # Raft transport bind address (optional; empty binds raft-address)
  raft-listen-address: ""

  # Peer addresses to join (required for raft backend)
  join-addresses:
    - "192.168.1.11:63000"
    - "192.168.1.12:63000"
```

## Configuration Parameters

### QuicBaaS Parameters

#### storage-backend

| Property | Value |
|----------|-------|
| Type | string |
| Required | No |
| Default | `pebble` |
| Values | `memory`, `file`, `pebble`, `raft` |

Storage backend type:
- `memory`: In-memory storage, no persistence (testing only)
- `file`: Simple file-based storage (development)
- `pebble`: High-performance local storage (default, single-node)
- `raft`: Distributed Raft consensus (HA clusters)

#### data-dir

| Property | Value |
|----------|-------|
| Type | string |
| Required | Yes |
| Example | `/var/lib/trusted-platform/quicbaas` |

Directory for QuicBaaS's PebbleDB storage files. Contains SST files, manifests, and metadata. Ensure sufficient disk space and fast storage (SSD recommended).

#### wal-dir

| Property | Value |
|----------|-------|
| Type | string |
| Required | No |
| Default | `<data-dir>/wal` |
| Example | `/var/lib/trusted-platform/quicbaas/wal` |

Directory for write-ahead log files. Can be placed on separate disk for better performance.

#### node-id

| Property | Value |
|----------|-------|
| Type | uint64 |
| Required | Yes |
| Range | 1 to 2^64-1 |
| Example | `1` |

Unique identifier for this node in the Raft cluster. Typically assigned sequentially (1, 2, 3). Must never be reused - if a node is replaced, use a new ID.

#### cache-size

| Property | Value |
|----------|-------|
| Type | int64 (bytes) |
| Required | No |
| Default | 67108864 (64MB) |
| Example | `134217728` (128MB) |

In-memory cache for frequently accessed data. Larger values improve read performance but consume more memory.

Recommendations:
- Development: 8-32MB
- Production (light): 64-128MB
- Production (heavy): 256-512MB

#### log-level

| Property | Value |
|----------|-------|
| Type | string |
| Required | No |
| Default | `warn` |
| Values | `debug`, `info`, `warn`, `error` |

QuicBaaS logging verbosity. Use `debug` only for troubleshooting.

#### consistency-level

| Property | Value |
|----------|-------|
| Type | string |
| Required | No |
| Default | `linearizable` |
| Values | `linearizable`, `strong`, `eventual` |

Default read consistency level:

| Level | Description | Use Case |
|-------|-------------|----------|
| `linearizable` | Reads see most recent committed write. Uses ReadIndex optimization. | Default for most applications |
| `strong` | Full Raft consensus on every read. Highest latency. | Critical reads requiring absolute consistency |
| `eventual` | Reads from local node, may be stale. Lowest latency. | Non-critical reads, analytics |

#### raft-address

| Property | Value |
|----------|-------|
| Type | string |
| Required | Yes, when `join-addresses` is set |
| Default | empty (a single node advertises nothing to peers) |
| Env | `PLATFORMD_QUICBAAS_RAFT_ADDRESS` |
| Flag | `platformd serve --raft-address` |
| Example | `192.168.1.10:63000` |

The address this node advertises to its peers; they dial it, so it must be reachable by every peer. A node with `join-addresses` and a loopback, unspecified (`0.0.0.0`, `::`) or empty `raft-address` refuses to start with `ErrRaftAdvertiseAddress`, which names the setting. The platform never guesses or probes for an address.

#### raft-listen-address

| Property | Value |
|----------|-------|
| Type | string |
| Required | No |
| Default | empty: binds `raft-address` |
| Env | `PLATFORMD_QUICBAAS_RAFT_LISTEN_ADDRESS` |
| Flag | `platformd serve --raft-listen-address` |
| Example | `0.0.0.0:63000` |

The local address the Raft transport binds. Set it when the bind differs from the advertised address, for example behind NAT, with a container port mapping or for a wildcard bind.

#### join-addresses

| Property | Value |
|----------|-------|
| Type | []string |
| Required | Yes (for raft backend) |
| Example | `["192.168.1.11:63000", "192.168.1.12:63000"]` |

List of peer node addresses to join. Should include all other nodes in the cluster.

## Deployment Examples

### Single-Node (Standalone)

Minimal configuration for development or non-HA deployments:

```yaml
quicbaas:
  storage-backend: pebble
  data-dir: /var/lib/trusted-platform/quicbaas
  wal-dir: /var/lib/trusted-platform/quicbaas/wal
  node-id: 1
  cache-size: 67108864
  log-level: warn
  consistency-level: linearizable
```

### Three-Node Cluster

Production HA configuration:

**Node 1 (192.168.1.10):**
```yaml
quicbaas:
  storage-backend: raft
  data-dir: /var/lib/trusted-platform/quicbaas
  wal-dir: /var/lib/trusted-platform/quicbaas/wal
  node-id: 1
  raft-address: "192.168.1.10:63000"
  join-addresses:
    - "192.168.1.11:63000"
    - "192.168.1.12:63000"
  cache-size: 134217728
  log-level: info
  consistency-level: linearizable
```

**Node 2 (192.168.1.11):**
```yaml
quicbaas:
  storage-backend: raft
  data-dir: /var/lib/trusted-platform/quicbaas
  wal-dir: /var/lib/trusted-platform/quicbaas/wal
  node-id: 2
  raft-address: "192.168.1.11:63000"
  join-addresses:
    - "192.168.1.10:63000"
    - "192.168.1.12:63000"
  cache-size: 134217728
  log-level: info
  consistency-level: linearizable
```

**Node 3 (192.168.1.12):**
```yaml
quicbaas:
  storage-backend: raft
  data-dir: /var/lib/trusted-platform/quicbaas
  wal-dir: /var/lib/trusted-platform/quicbaas/wal
  node-id: 3
  raft-address: "192.168.1.12:63000"
  join-addresses:
    - "192.168.1.10:63000"
    - "192.168.1.11:63000"
  cache-size: 134217728
  log-level: info
  consistency-level: linearizable
```

### Five-Node Cluster

For higher fault tolerance (tolerates 2 node failures):

```yaml
# Template - adjust node-id and raft-address per node
quicbaas:
  storage-backend: raft
  data-dir: /var/lib/trusted-platform/quicbaas
  wal-dir: /var/lib/trusted-platform/quicbaas/wal
  node-id: ${NODE_ID}  # 1, 2, 3, 4, or 5
  raft-address: "${NODE_IP}:63000"
  join-addresses: ${PEER_ADDRESSES}
  cache-size: 268435456  # 256MB
  log-level: info
  consistency-level: linearizable
```

## Environment Variables

platformd's environment prefix is `PLATFORMD_`. The precedence is flags > environment > file > defaults. The two Raft addresses are always bound. Any other key is overridden from the environment only when the configuration file declares it, because viper consults the environment only for keys it knows.

| Variable | Config Path | Example |
|----------|-------------|---------|
| `PLATFORMD_QUICBAAS_RAFT_ADDRESS` | `quicbaas.raft-address` | `192.168.1.10:63000` |
| `PLATFORMD_QUICBAAS_RAFT_LISTEN_ADDRESS` | `quicbaas.raft-listen-address` | `0.0.0.0:63000` |
| `PLATFORMD_QUICBAAS_STORAGE_BACKEND` | `quicbaas.storage-backend` | `pebble` |
| `PLATFORMD_QUICBAAS_DATA_DIR` | `quicbaas.data-dir` | `/var/lib/trusted-platform/quicbaas` |
| `PLATFORMD_QUICBAAS_WAL_DIR` | `quicbaas.wal-dir` | `/var/lib/trusted-platform/quicbaas/wal` |
| `PLATFORMD_QUICBAAS_NODE_ID` | `quicbaas.node-id` | `1` |
| `PLATFORMD_QUICBAAS_CACHE_SIZE` | `quicbaas.cache-size` | `134217728` |
| `PLATFORMD_QUICBAAS_LOG_LEVEL` | `quicbaas.log-level` | `info` |
| `PLATFORMD_QUICBAAS_CONSISTENCY_LEVEL` | `quicbaas.consistency-level` | `linearizable` |

## Performance Tuning

### Cache Sizing

```yaml
# Memory available vs cache size
# < 4GB RAM:   32-64MB
# 4-8GB RAM:   64-128MB
# 8-16GB RAM:  128-256MB
# > 16GB RAM:  256-512MB

quicbaas:
  cache-size: 134217728  # 128MB
```

### Storage Placement

For optimal performance, place data on fast storage (SSD/NVMe):

```yaml
quicbaas:
  data-dir: /ssd/trusted-platform/quicbaas
  wal-dir: /ssd/trusted-platform/quicbaas/wal
```

### Read Consistency Trade-offs

```yaml
# High consistency (default) - all reads see latest writes
quicbaas:
  consistency-level: linearizable  # 1-5ms latency

# Maximum consistency - full consensus per read
quicbaas:
  consistency-level: strong  # 10-50ms latency

# Low latency - may read stale data
quicbaas:
  consistency-level: eventual  # <1ms latency
```

## Validation

The configuration is validated at startup. Common validation errors:

| Error | Cause | Fix |
|-------|-------|-----|
| `data directory is required` | Missing `data-dir` | Specify `data-dir` |
| `node ID must be > 0` | `node-id: 0` | Use positive integer for `node-id` |
| `cache size cannot be negative` | Negative `cache-size` | Use positive value for `cache-size` |
| `invalid consistency level` | Invalid `consistency-level` | Use `linearizable`, `strong`, or `eventual` |
| `quicbaas.raft-address "…" is not routable` | `join-addresses` set with a loopback, unspecified or empty `raft-address` | Set a routable `raft-address` (file, `PLATFORMD_QUICBAAS_RAFT_ADDRESS` or `--raft-address`) |

## Related Documentation

- [Architecture](architecture.md) - Cluster architecture overview
- [Bootstrap](user.md) - Cluster setup procedures
- [Operations](user.md) - Operational procedures
- [QuicBaaS Integration](../architecture/quicbaas-integration.md) - Service layer details
