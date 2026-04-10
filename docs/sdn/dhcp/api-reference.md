# DHCP API Reference

## Overview

The DHCP service exposes APIs via multiple protocols following the platform's multi-protocol standards. This document provides an overview of the available APIs and links to protocol-specific documentation.

## Supported Protocols

| Protocol | Transport | Port | Use Case |
|----------|-----------|------|----------|
| REST | HTTP/HTTPS | 8443 | Web clients, external systems |
| gRPC | TCP | 10443 | High-performance service-to-service |
| QUIC | UDP | 9444 | Low-latency, mobile clients |
| MCP | stdio/HTTP | 9445 | AI/LLM integration |
| Unix | Unix Socket | /run/platformd.sock | Local IPC, CLI |

## API Capabilities

### Lease Management

- List active leases
- Get lease by MAC address
- Get lease by IP address
- Release lease
- Expire old leases

### Server Operations

- Get server status
- Get server statistics
- Start/Stop server
- Update interface options

### Pool Information

- Get pool utilization
- List allocations by pool

## Protocol-Specific Documentation

| Document | Description |
|----------|-------------|
| [REST API Reference](api-reference-rest.md) | REST endpoint documentation |
| [gRPC API Reference](api-reference-grpc.md) | gRPC service documentation |

## Service Interface

The DHCP service implements the `Server` interface, which is the abstraction used by all API handlers:

```go
type Server interface {
    // Start starts the DHCP server on all configured interfaces.
    Start(ctx context.Context) error

    // Stop stops the DHCP server gracefully.
    Stop(ctx context.Context) error

    // Running returns true if the server is currently running.
    Running() bool

    // GetLease retrieves a lease by MAC address.
    GetLease(mac net.HardwareAddr) (*Lease, bool)

    // GetLeaseByIP retrieves a lease by IP address.
    GetLeaseByIP(ip netip.Addr) (*Lease, bool)

    // ListLeases returns all current leases.
    ListLeases() []*Lease

    // ReleaseLease releases a lease by MAC address.
    ReleaseLease(mac net.HardwareAddr) error

    // Stats returns current server statistics.
    Stats() ServerStats
}
```

## Data Types

### Lease

```go
type Lease struct {
    IP          netip.Addr
    MAC         net.HardwareAddr
    Hostname    string
    PoolID      string
    Interface   string
    ClientID    []byte
    VendorClass string
    UserClass   string
    LeasedAt    time.Time
    ExpiresAt   time.Time
    RenewedAt   time.Time
    State       LeaseState
}
```

### LeaseState

```go
type LeaseState int

const (
    LeaseStateActive   LeaseState = iota  // Lease in use
    LeaseStateExpired                      // Lease expired
    LeaseStateReleased                     // Explicitly released
    LeaseStateDeclined                     // Client declined
)
```

### ServerStats

```go
type ServerStats struct {
    StartedAt       time.Time
    PacketsReceived uint64
    PacketsSent     uint64
    DiscoverCount   uint64
    OfferCount      uint64
    RequestCount    uint64
    AckCount        uint64
    NakCount        uint64
    ReleaseCount    uint64
    DeclineCount    uint64
    InformCount     uint64
    ErrorCount      uint64
    ActiveLeases    int
}
```

## Authentication

All API endpoints require mTLS authentication with a valid platform certificate. The certificate must be:

- Issued by the platform CA
- Not expired or revoked
- Have appropriate permissions for DHCP operations

## Rate Limiting

| Operation Type | Requests/Min |
|----------------|--------------|
| Lease read | 200 |
| Lease write | 60 |
| Status read | 200 |
| Stats read | 100 |

Rate limit headers:
- `X-RateLimit-Limit`: Maximum requests per window
- `X-RateLimit-Remaining`: Remaining requests in window
- `X-RateLimit-Reset`: Unix timestamp when window resets

## Error Codes

| Code | Description |
|------|-------------|
| `lease_not_found` | No lease exists for the specified MAC/IP |
| `invalid_mac` | MAC address format is invalid |
| `invalid_ip` | IP address format is invalid |
| `server_not_running` | DHCP server is not running |
| `pool_exhausted` | No available IPs in the pool |
| `lease_expired` | Lease has already expired |
| `interface_not_found` | Network interface not found |

## CLI Usage

The `platformctl` CLI provides DHCP management commands:

```bash
# List all active leases
platformctl sdn dhcp lease list

# Get lease by MAC
platformctl sdn dhcp lease get --mac aa:bb:cc:dd:ee:ff

# Get lease by IP
platformctl sdn dhcp lease get --ip 192.168.1.100

# Release a lease
platformctl sdn dhcp lease release --mac aa:bb:cc:dd:ee:ff

# Show server status
platformctl sdn dhcp status

# Show server statistics
platformctl sdn dhcp stats

# JSON output
platformctl sdn dhcp lease list --json
```

## See Also

- [README](README.md) - Package overview
- [Architecture](architecture.md) - Component design
- [Configuration](configuration.md) - Configuration reference
- [REST API Reference](api-reference-rest.md) - REST endpoints
- [gRPC API Reference](api-reference-grpc.md) - gRPC services
- [SDN CLI Usage](../cli-usage.md) - CLI commands
