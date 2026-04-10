# IPAM Configuration Reference

## Overview

This document provides a comprehensive configuration reference for the IPAM service, covering pool configuration, backend settings, lease management, and operational parameters.

## Configuration Structure

### YAML Configuration

```yaml
sdn:
  ipam:
    # Enable IPAM service
    enabled: true

    # Backend configuration
    backend:
      type: "quicbaas"  # memory, quicbaas, dht
      quicbaas:
        partition: "sdn/ipam"
        max_retries: 10
        request_timeout: "30s"
      dht:
        claim_timeout: "5s"
        propagation_delay: "100ms"
        max_allocation_retries: 50

    # Pool definitions
    pools:
      - id: "prod-v4"
        name: "Production IPv4"
        cidr: "10.0.0.0/24"
        gateway: "10.0.0.1"
        default_lease_duration: "24h"
        inactivity_timeout: "720h"  # 30 days
        tags:
          - "production"
          - "internal"

      - id: "prod-v6"
        name: "Production IPv6"
        cidr: "2602:F5BB:1234::/64"
        gateway: "2602:F5BB:1234::1"
        tags:
          - "production"
          - "public"

    # Lease management
    lease:
      default_duration: "24h"
      max_duration: "168h"  # 7 days
      renewal_threshold: "20%"  # Renew when 20% time remaining
      inactivity_timeout: "720h"  # 30 days
      expiration_check_interval: "1h"

    # Logging
    logging:
      level: "info"
      format: "json"

    # Metrics
    metrics:
      enabled: true
      port: 9180
```

## Backend Configuration

### Memory Backend

In-memory storage for development and testing:

```yaml
sdn:
  ipam:
    backend:
      type: "memory"
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
    backend:
      type: "quicbaas"
      quicbaas:
        # QuicBaaS partition for IPAM data
        partition: "sdn/ipam"

        # Maximum retry attempts for CAS conflicts
        max_retries: 10

        # Request timeout for QuicBaaS operations
        request_timeout: "30s"

        # Entity type prefixes
        entity_prefixes:
          pool: "ipam_pool"
          allocation: "ipam_allocation"
          index: "ipam_index"
```

**Characteristics:**

| Property | Value |
|----------|-------|
| Persistence | Raft log + snapshots |
| Consistency | Strong (Raft consensus) |
| Performance | Moderate (network consensus) |
| Use Case | Production, multi-node clusters |

**QuicBaaS Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `partition` | string | "sdn/ipam" | QuicBaaS data partition |
| `max_retries` | int | 10 | CAS conflict retry count |
| `request_timeout` | duration | 30s | Operation timeout |

### DHT Backend

Distributed backend for P2P environments (requires `platform_p2p` build tag):

```yaml
sdn:
  ipam:
    backend:
      type: "dht"
      dht:
        # Timeout for claim verification
        claim_timeout: "5s"

        # Delay before verifying claim
        propagation_delay: "100ms"

        # Maximum random IP attempts
        max_allocation_retries: 50

        # DHT operation timeout
        operation_timeout: "10s"

        # Key prefixes
        key_prefixes:
          pool: "/ipam/pool/"
          allocation: "/ipam/alloc/"
          device: "/ipam/device/"
```

**Characteristics:**

| Property | Value |
|----------|-------|
| Persistence | DHT network (replicated) |
| Consistency | Eventual (claim-based) |
| Performance | Variable (network dependent) |
| Use Case | P2P networks, decentralized deployments |

**DHT Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `claim_timeout` | duration | 5s | Claim verification timeout |
| `propagation_delay` | duration | 100ms | Wait before verification |
| `max_allocation_retries` | int | 50 | Random IP retry limit |
| `operation_timeout` | duration | 10s | DHT operation timeout |

## Pool Configuration

### Pool Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `id` | string | Yes | - | Unique pool identifier |
| `name` | string | Yes | - | Human-readable name |
| `cidr` | string | Yes | - | Network prefix (CIDR notation) |
| `gateway` | string | No | - | Gateway IP address |
| `description` | string | No | "" | Pool description |
| `tags` | []string | No | [] | Classification tags |
| `default_lease_duration` | duration | No | 0 (no expiry) | Default lease time |
| `inactivity_timeout` | duration | No | 720h | Inactivity expiration |

### Pool Definition

```yaml
pools:
  # IPv4 Production Pool
  - id: "prod-v4"
    name: "Production IPv4"
    cidr: "10.0.0.0/24"
    gateway: "10.0.0.1"
    description: "Internal production workloads"
    tags:
      - "production"
      - "internal"
    default_lease_duration: "24h"
    inactivity_timeout: "720h"

  # IPv6 Production Pool
  - id: "prod-v6"
    name: "Production IPv6"
    cidr: "2602:F5BB:1234::/64"
    gateway: "2602:F5BB:1234::1"
    tags:
      - "production"
      - "public"
    default_lease_duration: "0"  # No expiry

  # Development Pool
  - id: "dev-v4"
    name: "Development"
    cidr: "192.168.100.0/24"
    gateway: "192.168.100.1"
    tags:
      - "development"
    default_lease_duration: "1h"
    inactivity_timeout: "24h"

  # DHCP Pool
  - id: "dhcp-pool"
    name: "DHCP Dynamic Pool"
    cidr: "192.168.1.0/24"
    gateway: "192.168.1.1"
    default_lease_duration: "8h"
    inactivity_timeout: "24h"
```

### Pool Validation Rules

| Rule | Validation |
|------|------------|
| ID | Non-empty, unique across all pools |
| Name | Non-empty, unique across all pools |
| CIDR | Valid IPv4 or IPv6 prefix |
| Gateway | Must be within CIDR range if specified |
| Lease Duration | Non-negative duration |
| Inactivity Timeout | Non-negative duration |

### Computed Pool Statistics

| Field | Calculation |
|-------|-------------|
| `total_ips` | Pool size (excludes network/broadcast for IPv4) |
| `allocated_ips` | Count of active allocations |
| `available_ips` | total_ips - allocated_ips |
| `utilization_pct` | (allocated_ips / total_ips) * 100 |

## Lease Configuration

### Global Lease Settings

```yaml
sdn:
  ipam:
    lease:
      # Default lease duration for pools without explicit setting
      default_duration: "24h"

      # Maximum allowed lease duration
      max_duration: "168h"  # 7 days

      # Renew when this percentage of lease time remains
      renewal_threshold: "20%"

      # Mark inactive allocations as expired after this duration
      inactivity_timeout: "720h"  # 30 days

      # How often to check for expired allocations
      expiration_check_interval: "1h"
```

### Lease Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `default_duration` | duration | 24h | Default lease time |
| `max_duration` | duration | 168h | Maximum lease time |
| `renewal_threshold` | string | "20%" | When to allow renewal |
| `inactivity_timeout` | duration | 720h | Inactivity expiration |
| `expiration_check_interval` | duration | 1h | Expiration scan interval |

### Lease Behavior

```
Allocation Timeline:

|-------- Lease Duration (24h) --------|
|                                      |
|        |-------- Renew Window -------| (last 20%)
|        |                             |
Created  Renewal   Expiration          |
         Allowed   Warning             Expired
```

### Per-Pool Lease Override

```yaml
pools:
  - id: "short-lease"
    name: "Short Lease Pool"
    cidr: "10.1.0.0/24"
    default_lease_duration: "1h"  # Override global default
    inactivity_timeout: "4h"

  - id: "no-expiry"
    name: "Permanent Allocations"
    cidr: "10.2.0.0/24"
    default_lease_duration: "0"   # Never expires
    inactivity_timeout: "0"       # No inactivity timeout
```

## Allocation Request Configuration

### Request Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `pool_id` | string | Yes | Target pool ID |
| `device_id` | string | Yes | Device identifier |
| `hostname` | string | No | Device hostname |
| `description` | string | No | Allocation description |
| `tags` | []string | No | Allocation tags |
| `metadata` | map[string]string | No | Custom key-value data |
| `requested_ip` | string | No | Specific IP (for AllocateSpecific) |
| `lease_duration` | duration | No | Override pool default |

### Allocation Request Examples

```go
// Automatic allocation
req := &ipam.AllocationRequest{
    PoolID:   "prod-v4",
    DeviceID: "vm-001",
    Hostname: "webserver-01",
    Tags:     []string{"web", "frontend"},
    Metadata: map[string]string{
        "environment": "production",
        "owner":       "platform-team",
    },
}

// Specific IP allocation
req := &ipam.AllocationRequest{
    PoolID:      "prod-v4",
    DeviceID:    "db-001",
    RequestedIP: netip.MustParseAddr("10.0.0.100"),
    Hostname:    "database-01",
    Metadata: map[string]string{
        "role": "primary",
    },
}

// Custom lease duration
req := &ipam.AllocationRequest{
    PoolID:        "dhcp-pool",
    DeviceID:      "laptop-001",
    LeaseDuration: 4 * time.Hour,
}
```

## Logging Configuration

```yaml
sdn:
  ipam:
    logging:
      # Log level: debug, info, warn, error
      level: "info"

      # Output format: json, text
      format: "json"

      # Component-specific levels
      components:
        allocator: "info"
        backend: "debug"
        lease: "info"

      # Output configuration
      output:
        stdout: true
        file:
          enabled: true
          path: "/var/log/platform/ipam.log"
          max_size: "100M"
          max_age: "7d"
          compress: true
```

### Log Levels

| Level | Description |
|-------|-------------|
| `debug` | Detailed debugging information |
| `info` | General operational messages |
| `warn` | Warning conditions |
| `error` | Error conditions |

### Structured Log Examples

```json
{
  "level": "info",
  "time": "2026-01-19T10:30:00Z",
  "component": "ipam",
  "msg": "IP allocated",
  "pool_id": "prod-v4",
  "ip": "10.0.0.50",
  "device_id": "vm-001",
  "hostname": "webserver"
}

{
  "level": "warn",
  "time": "2026-01-19T10:31:00Z",
  "component": "ipam",
  "msg": "pool utilization high",
  "pool_id": "prod-v4",
  "utilization_pct": 85.5,
  "available_ips": 37
}
```

## Metrics Configuration

```yaml
sdn:
  ipam:
    metrics:
      # Enable Prometheus metrics
      enabled: true

      # Metrics HTTP port
      port: 9180

      # Metrics path
      path: "/metrics"

      # Metric types to collect
      types:
        pool_stats: true
        allocation_latency: true
        backend_operations: true
        lease_events: true
```

### Available Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `ipam_pools_total` | Gauge | - | Total pool count |
| `ipam_pool_total_ips` | Gauge | pool_id, name | Total IPs per pool |
| `ipam_pool_allocated_ips` | Gauge | pool_id, name | Allocated IPs per pool |
| `ipam_pool_available_ips` | Gauge | pool_id, name | Available IPs per pool |
| `ipam_pool_utilization_ratio` | Gauge | pool_id, name | Utilization (0-1) |
| `ipam_allocations_total` | Counter | pool_id, status | Total allocations |
| `ipam_releases_total` | Counter | pool_id | Total releases |
| `ipam_allocation_duration_seconds` | Histogram | pool_id, backend | Allocation latency |
| `ipam_backend_errors_total` | Counter | backend, operation | Backend errors |
| `ipam_lease_renewals_total` | Counter | pool_id | Lease renewals |
| `ipam_lease_expirations_total` | Counter | pool_id | Lease expirations |

## Environment Variables

Configuration values can be sourced from environment variables:

| Variable | Description | Example |
|----------|-------------|---------|
| `IPAM_BACKEND_TYPE` | Backend type | quicbaas |
| `IPAM_DEFAULT_LEASE` | Default lease duration | 24h |
| `IPAM_INACTIVITY_TIMEOUT` | Inactivity timeout | 720h |
| `IPAM_LOG_LEVEL` | Log level | info |
| `IPAM_METRICS_PORT` | Metrics port | 9180 |

```yaml
# Using environment variables
sdn:
  ipam:
    backend:
      type: ${IPAM_BACKEND_TYPE}
    lease:
      default_duration: ${IPAM_DEFAULT_LEASE}
      inactivity_timeout: ${IPAM_INACTIVITY_TIMEOUT}
    logging:
      level: ${IPAM_LOG_LEVEL}
    metrics:
      port: ${IPAM_METRICS_PORT}
```

## Complete Example

```yaml
sdn:
  ipam:
    enabled: true

    backend:
      type: "quicbaas"
      quicbaas:
        partition: "sdn/ipam"
        max_retries: 10
        request_timeout: "30s"

    pools:
      # Production IPv4
      - id: "prod-v4"
        name: "Production IPv4"
        cidr: "10.0.0.0/24"
        gateway: "10.0.0.1"
        description: "Primary production workloads"
        tags:
          - "production"
          - "internal"
        default_lease_duration: "24h"
        inactivity_timeout: "720h"

      # Production IPv6
      - id: "prod-v6"
        name: "Production IPv6"
        cidr: "2602:F5BB:1234::/64"
        gateway: "2602:F5BB:1234::1"
        tags:
          - "production"
          - "public"
        default_lease_duration: "0"

      # Development
      - id: "dev-v4"
        name: "Development"
        cidr: "192.168.100.0/24"
        gateway: "192.168.100.1"
        tags:
          - "development"
        default_lease_duration: "1h"
        inactivity_timeout: "24h"

      # Edge/IoT
      - id: "edge-v6"
        name: "Edge IoT Pool"
        cidr: "2602:F5BB:5678::/48"
        gateway: "2602:F5BB:5678::1"
        tags:
          - "edge"
          - "iot"
        default_lease_duration: "168h"  # 7 days
        inactivity_timeout: "720h"

    lease:
      default_duration: "24h"
      max_duration: "168h"
      renewal_threshold: "20%"
      inactivity_timeout: "720h"
      expiration_check_interval: "1h"

    logging:
      level: "info"
      format: "json"
      output:
        stdout: true
        file:
          enabled: true
          path: "/var/log/platform/ipam.log"
          max_size: "100M"
          max_age: "7d"
          compress: true

    metrics:
      enabled: true
      port: 9180
      path: "/metrics"
```

## See Also

- [Architecture](architecture.md) - IPAM architecture and design
- [API Reference](api-reference.md) - API overview
- [REST API](api-reference-rest.md) - REST endpoints
- [gRPC API](api-reference-grpc.md) - gRPC service methods
