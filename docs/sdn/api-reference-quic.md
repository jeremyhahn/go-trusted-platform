# SDN QUIC API Reference

Endpoint: `localhost:9444` (UDP)

Requires mTLS authentication via QUIC TLS configuration.

## Overview

QUIC provides low-latency, multiplexed communication ideal for mobile clients and unreliable networks. The SDN QUIC API uses a binary protocol over QUIC streams.

## Connection

```go
import (
    "context"
    "crypto/tls"
    "github.com/quic-go/quic-go"
)

tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{clientCert},
    RootCAs:      caCertPool,
    NextProtos:   []string{"sdn-quic-v1"},
}

conn, err := quic.DialAddr(ctx, "localhost:9444", tlsConfig, nil)
stream, err := conn.OpenStreamSync(ctx)
```

## Message Format

```
+----------------+----------------+------------------+
| Type (1 byte)  | Length (4 bytes) | Payload (JSON)  |
+----------------+----------------+------------------+
```

## Message Types

| Type | Name | Description |
|------|------|-------------|
| 0x01 | CreateBridge | Create bridge |
| 0x02 | GetBridge | Get bridge |
| 0x03 | DeleteBridge | Delete bridge |
| 0x04 | ListBridges | List bridges |
| 0x11 | AddPort | Add port |
| 0x12 | DeletePort | Delete port |
| 0x13 | GetPortState | Get port state |
| 0x14 | SetPortState | Set port state |
| 0x15 | GetPortStats | Get port stats |
| 0x21 | AddFlow | Add flow |
| 0x22 | DeleteFlow | Delete flow |
| 0x23 | ListFlows | List flows |
| 0x31 | CreateVLAN | Create VLAN |
| 0x32 | DeleteVLAN | Delete VLAN |
| 0x33 | ListVLANs | List VLANs |
| 0x41 | ApplyPolicy | Apply policy |
| 0x42 | GetPolicy | Get policy |
| 0x43 | ListPolicies | List policies |
| 0x80 | Response | Response message |
| 0xFF | Error | Error response |

## Request/Response Examples

### Create Bridge

Request:
```
Type: 0x01
Payload: {"name": "br0"}
```

Response:
```
Type: 0x80
Payload: {"uuid": "a1b2c3d4...", "name": "br0"}
```

### Add Port

Request:
```
Type: 0x11
Payload: {"bridge": "br0", "name": "eth0"}
```

Response:
```
Type: 0x80
Payload: {"uuid": "c3d4e5f6...", "name": "eth0", "interfaces": ["eth0"]}
```

### Add Flow

Request:
```
Type: 0x21
Payload: {
  "bridge": "br0",
  "flow": {
    "priority": 100,
    "match": {"in_port": 1, "eth_type": 2048},
    "actions": [{"type": "output", "port": 2}]
  }
}
```

Response:
```
Type: 0x80
Payload: {"cookie": 12345678901234567890, "priority": 100}
```

### Apply Policy

Request:
```
Type: 0x41
Payload: {
  "port": "eth0",
  "policy": {
    "tenant_id": "tenant-a",
    "vlan": 100,
    "acls": [
      {"priority": 100, "match": {}, "action": {"type": "allow"}}
    ]
  }
}
```

Response:
```
Type: 0x80
Payload: {"port": "eth0", "tenant_id": "tenant-a", "vlan": 100}
```

### Error Response

```
Type: 0xFF
Payload: {"code": "BRIDGE_NOT_FOUND", "message": "Bridge br0 not found"}
```

## Go Client Example

```go
import (
    "encoding/binary"
    "encoding/json"
    sdn "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic/sdn"
)

client, err := sdn.NewClient(ctx, "localhost:9444", tlsConfig)
defer client.Close()

// Create bridge
bridge, err := client.CreateBridge(ctx, "br0")

// Add port
port, err := client.AddPort(ctx, "br0", "eth0")

// Get port state
state, err := client.GetPortState(ctx, "eth0")

// Add flow
flow := &sdn.Flow{
    Priority: 100,
    Match:    sdn.FlowMatch{InPort: 1},
    Actions:  []sdn.FlowAction{{Type: "output", Port: 2}},
}
resp, err := client.AddFlow(ctx, "br0", flow)

// Apply policy
policy := &sdn.PortPolicy{
    TenantID: "tenant-a",
    VLAN:     100,
}
result, err := client.ApplyPolicy(ctx, "eth0", policy)
```

## Stream Multiplexing

QUIC supports multiple concurrent streams. Each operation opens a new stream:

```go
// Parallel operations
var wg sync.WaitGroup
for i := 0; i < 10; i++ {
    wg.Add(1)
    go func(portNum int) {
        defer wg.Done()
        port := fmt.Sprintf("eth%d", portNum)
        client.AddPort(ctx, "br0", port)
    }(i)
}
wg.Wait()
```

## Connection Pooling

The client maintains a connection pool for high-throughput scenarios:

```go
client, err := sdn.NewClient(ctx, "localhost:9444", tlsConfig,
    sdn.WithMaxStreams(100),
    sdn.WithIdleTimeout(30*time.Second),
)
```

## Error Codes

| Code | Description |
|------|-------------|
| BRIDGE_NOT_FOUND | Bridge does not exist |
| BRIDGE_EXISTS | Bridge already exists |
| PORT_NOT_FOUND | Port does not exist |
| INVALID_VLAN | Invalid VLAN ID |
| POLICY_NOT_FOUND | Policy does not exist |
| PROTOCOL_ERROR | Protocol encoding error |
| CONNECTION_CLOSED | Connection terminated |
