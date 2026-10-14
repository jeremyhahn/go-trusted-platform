# VXLAN Overlay QUIC API Reference

## Overview

| Property | Value |
|----------|-------|
| Transport | QUIC (UDP 9444, mTLS) |
| Encoding | msgpack request/response frames |
| Category opcode | `0x2E` (Overlay) |
| Handler source | `pkg/api/quic/overlay_handlers.go` |

Overlay requests use the extended-opcode scheme: the category opcode
`0x2E` selects the overlay handler and a sub-opcode selects the
operation.

## Operations

| Sub-opcode | Operation | Description |
|-----------|-----------|-------------|
| `0x01` | Status | Overlay status (node ID, VTEP, counts, health) |
| `0x02` | ListVTEPs | List all known VTEPs |
| `0x03` | GetVTEP | Get VTEP by ID |
| `0x04` | ListVNIs | List configured VNIs |
| `0x05` | CreateVNI | Create a VNI |
| `0x06` | DeleteVNI | Delete a VNI |
| `0x07` | ListTunnels | List VXLAN tunnels |
| `0x08` | ListMACs | List learned MACs (VNI filter) |
| `0x09` | ForgetMAC | Remove a learned MAC |
| `0x0A` | TunnelStats | One tunnel's counters (remote VTEP, optional VNI) |

## Payload Types

Payloads are msgpack-encoded structs defined in
`sdk/go/wire/quicwire/overlay.go`, shared by the daemon handler and the SDK
QUIC adapter. For example the status response:

```go
type OverlayStatusInfo struct {
    Enabled      bool   `codec:"enabled"`
    NodeID       string `codec:"node_id,omitempty"`
    Mode         string `codec:"mode"`
    LocalVTEP    string `codec:"local_vtep"`
    VXLANPort    uint16 `codec:"vxlan_port,omitempty"`
    VTEPCount    int    `codec:"vtep_count"`
    VNICount     int    `codec:"vni_count"`
    TunnelCount  int    `codec:"tunnel_count"`
    MACCount     int    `codec:"mac_count"`
    UplinkIface  string `codec:"uplink_iface,omitempty"`
    MTU          int    `codec:"mtu"`
    EncapType    string `codec:"encap_type"`
    HealthStatus string `codec:"health_status"`
}
```

`CreateVNI` takes `OverlayCreateVNIRequest`; its `VLAN` field (0-4094, 0 maps
no VLAN) reaches the controller's `VNIConfig`.

List requests carry `limit` and `offset`; a page holds 100 entries by default
and at most 1000, and a negative offset is refused with `InvalidRequest`. List
responses carry `count`, the length of the page, and `total`, the number of
entries in all. `ListTunnels` and `ListMACs` return only the given VNI when
`vni` is non-zero. The SDK QUIC adapter pages until it holds `total` entries,
so `Overlay().List*` returns every entry.

## Errors

Typed sentinel errors map onto QUIC error frames, including: overlay
service not available, VTEP/VNI/MAC/tunnel not found, VNI already exists,
invalid VNI (must be 1-16777215), invalid VLAN (must be 0-4094; answered
`StatusInvalidArgument`, the class REST answers 400 for), invalid MAC
address format, and a
missing or malformed remote VTEP address.

`TunnelStats` takes `{remote_vtep, vni}` (`OverlayTunnelStatsRequest`); a
VNI of 0 selects the first tunnel to the remote VTEP. It answers
`{tunnel, timestamp}` with the tunnel gRPC `GetTunnelStats` returns, or
NotFound when no tunnel matches.

## Client Usage

The platformctl CLI exercises this surface with
`--transport quic`:

```bash
platformctl --transport quic sdn overlay status
platformctl --transport quic sdn overlay vni create --vni 1000100 --vlan 100
```

## See Also

- [API Reference](api-reference.md) — Overview and data types
