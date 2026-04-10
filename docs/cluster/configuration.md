# Cluster Configuration

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

  # Raft cluster address (required for raft backend)
  raft-address: "192.168.1.10:63000"

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
| Required | Yes (for raft backend) |
| Example | `192.168.1.10:63000` |

Address for Raft cluster communication. Must be reachable by all peer nodes.

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

Configuration values can be overridden using environment variables:

| Variable | Config Path | Example |
|----------|-------------|---------|
| `PLATFORM_QUICBAAS_STORAGE_BACKEND` | `quicbaas.storage-backend` | `pebble` |
| `PLATFORM_QUICBAAS_DATA_DIR` | `quicbaas.data-dir` | `/var/lib/trusted-platform/quicbaas` |
| `PLATFORM_QUICBAAS_WAL_DIR` | `quicbaas.wal-dir` | `/var/lib/trusted-platform/quicbaas/wal` |
| `PLATFORM_QUICBAAS_NODE_ID` | `quicbaas.node-id` | `1` |
| `PLATFORM_QUICBAAS_CACHE_SIZE` | `quicbaas.cache-size` | `134217728` |
| `PLATFORM_QUICBAAS_LOG_LEVEL` | `quicbaas.log-level` | `info` |
| `PLATFORM_QUICBAAS_CONSISTENCY` | `quicbaas.consistency-level` | `linearizable` |
| `PLATFORM_QUICBAAS_RAFT_ADDRESS` | `quicbaas.raft-address` | `192.168.1.10:63000` |

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
| `raft address required` | Missing `raft-address` for raft backend | Specify `raft-address` |

## Related Documentation

- [Architecture](architecture.md) - Cluster architecture overview
- [Bootstrap](bootstrap.md) - Cluster setup procedures
- [Operations](operations.md) - Operational procedures
- [QuicBaaS Integration](../architecture/quicbaas-integration.md) - Service layer details
