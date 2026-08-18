# SDN Architecture

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Archived 2026-08-18. This file lived beside a lower-case sibling of the
> same name in `docs/sdn/`, which makes the repository impossible to check
> out on a case-insensitive filesystem — and this repository publishes to a
> public host where contributors have those. Its content is a strict subset
> of the surviving file: same title, same section structure, fewer sections.
>
> **Superseded by:** `docs/sdn/architecture.md`


## Overview

The SDN subsystem provides certificate-based network access control using
802.1X principles with OpenFlow for dynamic policy enforcement.

## Component Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           Policy Engine                             │
│  (pkg/sdn/policy)                                                   │
│  - Port state machine                                               │
│  - Certificate policy extraction                                    │
│  - Flow rule generation                                             │
└─────────────────┬───────────────────────────────────┬───────────────┘
                  │                                   │
        ┌─────────▼─────────┐               ┌─────────▼─────────┐
        │    OVS Client     │               │    ARP Reader     │
        │  (pkg/sdn/ovs)    │               │  (pkg/sdn/arp)    │
        │  - OVSDB JSON-RPC │               │  - /proc/net/arp  │
        │  - Bridge/Port    │               │  - MAC lookup     │
        └─────────┬─────────┘               └───────────────────┘
                  │
        ┌─────────▼─────────┐
        │  OpenFlow Client  │
        │ (pkg/sdn/openflow)│
        │  - OF 1.3 binary  │
        │  - Flow add/del   │
        └───────────────────┘
```

## Package Details

### pkg/sdn/arp

Pure Go ARP table reader. Parses `/proc/net/arp` directly without
external commands.

```go
// Parse entry: 192.168.1.1 0x1 0x2 aa:bb:cc:dd:ee:ff * eth0
type Entry struct {
    IP        string
    HWType    int
    Flags     int
    HWAddress string
    Mask      string
    Device    string
}
```

Key features:
- Reads real-time ARP cache from kernel
- Filters incomplete entries (00:00:00:00:00:00)
- Thread-safe lookups

### pkg/sdn/openflow

Native OpenFlow 1.3 protocol implementation over Unix socket.

**Supported Messages:**
- Hello / FeaturesRequest / FeaturesReply
- FlowMod (add/modify/delete)
- MultipartRequest/Reply (flow stats)
- BarrierRequest/Reply
- EchoRequest/Reply

**Match Fields:**
- in_port, eth_dst, eth_src, eth_type
- ip_dst, ip_src, ip_proto
- tcp_dst, udp_dst

**Actions:**
- output, set_vlan, pop_vlan, drop, goto_table

```go
// Binary message format (big-endian)
type Header struct {
    Version uint8  // 0x04 for OF 1.3
    Type    uint8  // Message type
    Length  uint16 // Total length
    Xid     uint32 // Transaction ID
}
```

### pkg/sdn/ovs

OVSDB client implementing RFC 7047 JSON-RPC 2.0 protocol.

**Operations:**
- Transact (insert, update, delete, mutate, select)
- List databases
- Get schema
- Echo

**Managed Tables:**
- Bridge
- Port
- Interface
- Open_vSwitch

```go
// OVSDB transaction
type Operation struct {
    Op      string                 `json:"op"`
    Table   string                 `json:"table"`
    Where   []Condition            `json:"where,omitempty"`
    Row     map[string]interface{} `json:"row,omitempty"`
    Columns []string               `json:"columns,omitempty"`
}
```

### pkg/sdn/netlink

TAP device management using netlink protocol.

- Create/delete TAP devices
- Set link state (up/down)
- Set device owner (UID/GID)
- MTU configuration

### pkg/sdn/policy

802.1X-style port authentication with certificate-based policies.

**Port State Machine:**
```
         ┌───────────────────────┐
         │     Unconnected       │
         └───────────┬───────────┘
                     │ device connects
         ┌───────────▼───────────┐
         │     Provisioning      │ Limited network access
         └───────────┬───────────┘
                     │ enrollment complete
         ┌───────────▼───────────┐
         │       Enrolled        │ Awaiting activation
         └───────────┬───────────┘
                     │ client activates
         ┌───────────▼───────────┐
         │      Authorized       │ Full access (profile zone)
         └───────────┬───────────┘
                     │ cert revoked/expired
         ┌───────────▼───────────┐
         │  Quarantined/Blocked  │
         └───────────────────────┘
```

**Certificate Policy Extraction:**
Policies encoded in IDevID certificate extensions:
- Tenant ID (custom OID)
- VLAN assignment
- ACL rules
- Rate limits

## Protocol Details

### OVSDB Connection

```
Client                             ovsdb-server
   │                                     │
   │──── Connect (Unix socket) ─────────>│
   │                                     │
   │──── list_dbs ──────────────────────>│
   │<─── ["Open_vSwitch"] ───────────────│
   │                                     │
   │──── transact [ops...] ─────────────>│
   │<─── [{uuid, rows}, ...] ────────────│
```

### OpenFlow Connection

```
Client                             ovs-vswitchd
   │                                     │
   │──── Connect (br0.mgmt socket) ─────>│
   │                                     │
   │──── Hello (OF 1.3) ────────────────>│
   │<─── Hello (OF 1.3) ─────────────────│
   │                                     │
   │──── FeaturesRequest ───────────────>│
   │<─── FeaturesReply ──────────────────│
   │                                     │
   │──── FlowMod (add flow) ────────────>│
   │──── BarrierRequest ────────────────>│
   │<─── BarrierReply ───────────────────│
```

## Thread Safety

All clients use mutex protection for concurrent access:
- OVSDB client: Single connection, serialized requests
- OpenFlow client: Atomic transaction IDs, pending response map
- ARP reader: Lock-free reads from /proc filesystem

## Error Handling

All packages use typed errors:

```go
// pkg/sdn/ovs/errors.go
var (
    ErrNotConnected      = errors.New("not connected to OVSDB")
    ErrBridgeNotFound    = errors.New("bridge not found")
    ErrPortNotFound      = errors.New("port not found")
    ErrTransactionFailed = errors.New("OVSDB transaction failed")
)

// pkg/sdn/openflow/errors.go
var (
    ErrNotConnected     = errors.New("not connected")
    ErrVersionMismatch  = errors.New("OpenFlow version mismatch")
    ErrTimeout          = errors.New("operation timed out")
)
```
