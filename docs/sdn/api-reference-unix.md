# SDN Unix Socket API Reference

Socket: `/run/platformd.sock`

Unix sockets provide local IPC for CLI and local applications.

## Connection

```go
import (
    "net"
    "encoding/json"
)

conn, err := net.Dial("unix", "/run/platformd.sock")
defer conn.Close()
```

## Protocol

JSON-RPC 2.0 over Unix socket.

### Request Format

```json
{
  "jsonrpc": "2.0",
  "method": "sdn.MethodName",
  "params": {},
  "id": 1
}
```

### Response Format

```json
{
  "jsonrpc": "2.0",
  "result": {},
  "id": 1
}
```

### Error Format

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32000,
    "message": "Bridge not found",
    "data": {"code": "BRIDGE_NOT_FOUND"}
  },
  "id": 1
}
```

## Methods

### sdn.CreateBridge

```json
{
  "jsonrpc": "2.0",
  "method": "sdn.CreateBridge",
  "params": {"name": "br0"},
  "id": 1
}
```

Response:
```json
{
  "jsonrpc": "2.0",
  "result": {"uuid": "a1b2c3d4...", "name": "br0"},
  "id": 1
}
```

### sdn.GetBridge

```json
{
  "jsonrpc": "2.0",
  "method": "sdn.GetBridge",
  "params": {"name": "br0"},
  "id": 2
}
```

### sdn.DeleteBridge

```json
{
  "jsonrpc": "2.0",
  "method": "sdn.DeleteBridge",
  "params": {"name": "br0"},
  "id": 3
}
```

### sdn.ListBridges

```json
{
  "jsonrpc": "2.0",
  "method": "sdn.ListBridges",
  "params": {},
  "id": 4
}
```

### sdn.AddPort

```json
{
  "jsonrpc": "2.0",
  "method": "sdn.AddPort",
  "params": {"bridge": "br0", "name": "eth0"},
  "id": 5
}
```

### sdn.DeletePort

```json
{
  "jsonrpc": "2.0",
  "method": "sdn.DeletePort",
  "params": {"bridge": "br0", "port": "eth0"},
  "id": 6
}
```

### sdn.GetPortState

```json
{
  "jsonrpc": "2.0",
  "method": "sdn.GetPortState",
  "params": {"port": "eth0"},
  "id": 7
}
```

Response:
```json
{
  "jsonrpc": "2.0",
  "result": {"port": "eth0", "state": "up", "of_port": 1},
  "id": 7
}
```

### sdn.SetPortState

```json
{
  "jsonrpc": "2.0",
  "method": "sdn.SetPortState",
  "params": {"port": "eth0", "state": "down"},
  "id": 8
}
```

### sdn.GetPortStats

```json
{
  "jsonrpc": "2.0",
  "method": "sdn.GetPortStats",
  "params": {"port": "eth0"},
  "id": 9
}
```

Response:
```json
{
  "jsonrpc": "2.0",
  "result": {
    "port": "eth0",
    "rx_packets": 1000,
    "tx_packets": 950,
    "rx_bytes": 102400,
    "tx_bytes": 97280,
    "rx_errors": 0,
    "tx_errors": 0
  },
  "id": 9
}
```

### sdn.AddFlow

```json
{
  "jsonrpc": "2.0",
  "method": "sdn.AddFlow",
  "params": {
    "bridge": "br0",
    "flow": {
      "priority": 100,
      "match": {"in_port": 1, "eth_type": 2048},
      "actions": [{"type": "output", "port": 2}]
    }
  },
  "id": 10
}
```

### sdn.DeleteFlow

```json
{
  "jsonrpc": "2.0",
  "method": "sdn.DeleteFlow",
  "params": {
    "bridge": "br0",
    "match": {"in_port": 1}
  },
  "id": 11
}
```

### sdn.ListFlows

```json
{
  "jsonrpc": "2.0",
  "method": "sdn.ListFlows",
  "params": {"bridge": "br0"},
  "id": 12
}
```

### sdn.CreateVLAN

```json
{
  "jsonrpc": "2.0",
  "method": "sdn.CreateVLAN",
  "params": {"vlan_id": 100, "name": "tenant-a"},
  "id": 13
}
```

### sdn.DeleteVLAN

```json
{
  "jsonrpc": "2.0",
  "method": "sdn.DeleteVLAN",
  "params": {"vlan_id": 100},
  "id": 14
}
```

### sdn.ListVLANs

```json
{
  "jsonrpc": "2.0",
  "method": "sdn.ListVLANs",
  "params": {},
  "id": 15
}
```

### sdn.ApplyPolicy

```json
{
  "jsonrpc": "2.0",
  "method": "sdn.ApplyPolicy",
  "params": {
    "port": "eth0",
    "policy": {
      "tenant_id": "tenant-a",
      "vlan": 100,
      "acls": [
        {"priority": 100, "match": {}, "action": {"type": "allow"}}
      ]
    }
  },
  "id": 16
}
```

### sdn.GetPolicy

```json
{
  "jsonrpc": "2.0",
  "method": "sdn.GetPolicy",
  "params": {"port": "eth0"},
  "id": 17
}
```

### sdn.ListPolicies

```json
{
  "jsonrpc": "2.0",
  "method": "sdn.ListPolicies",
  "params": {},
  "id": 18
}
```

## CLI Usage

The `platformctl` CLI uses the Unix socket by default:

```bash
# Bridge operations
platformctl sdn bridge create br0
platformctl sdn bridge get br0
platformctl sdn bridge delete br0
platformctl sdn bridge list

# Port operations
platformctl sdn port add br0 eth0
platformctl sdn port delete br0 eth0
platformctl sdn port state eth0
platformctl sdn port state eth0 --set down
platformctl sdn port stats eth0

# Flow operations
platformctl sdn flow add br0 --priority 100 --match in_port=1 --action output=2
platformctl sdn flow delete br0 --match in_port=1
platformctl sdn flow list br0

# VLAN operations
platformctl sdn vlan create 100 --name tenant-a
platformctl sdn vlan delete 100
platformctl sdn vlan list

# Policy operations
platformctl sdn policy apply eth0 --tenant tenant-a --vlan 100
platformctl sdn policy get eth0
platformctl sdn policy list
```

## Go Client Example

```go
import (
    "net"
    "encoding/json"
)

type Request struct {
    JSONRPC string      `json:"jsonrpc"`
    Method  string      `json:"method"`
    Params  interface{} `json:"params"`
    ID      int         `json:"id"`
}

type Response struct {
    JSONRPC string          `json:"jsonrpc"`
    Result  json.RawMessage `json:"result,omitempty"`
    Error   *RPCError       `json:"error,omitempty"`
    ID      int             `json:"id"`
}

conn, _ := net.Dial("unix", "/run/platformd.sock")
encoder := json.NewEncoder(conn)
decoder := json.NewDecoder(conn)

// Create bridge
req := Request{
    JSONRPC: "2.0",
    Method:  "sdn.CreateBridge",
    Params:  map[string]string{"name": "br0"},
    ID:      1,
}
encoder.Encode(req)

var resp Response
decoder.Decode(&resp)
```

## Error Codes

| Code | Description |
|------|-------------|
| -32700 | Parse error |
| -32600 | Invalid request |
| -32601 | Method not found |
| -32602 | Invalid params |
| -32603 | Internal error |
| -32000 | Bridge not found |
| -32001 | Bridge exists |
| -32002 | Port not found |
| -32003 | Invalid VLAN |
| -32004 | Policy not found |
| -32005 | Transaction failed |
