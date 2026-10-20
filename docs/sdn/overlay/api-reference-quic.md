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
| `0x01` | Status | Overlay status (node ID, VTEP, counts, IPsec unpeered VTEPs, health) |
| `0x02` | ListVTEPs | List all known VTEPs |
| `0x03` | GetVTEP | Get VTEP by ID |
| `0x04` | ListVNIs | List configured VNIs |
| `0x05` | CreateVNI | Create a VNI |
| `0x06` | DeleteVNI | Delete a VNI |
| `0x07` | ListTunnels | List VXLAN tunnels |
| `0x08` | ListMACs | List learned MACs (VNI filter) |
| `0x09` | ForgetMAC | Remove a learned MAC |

## Payload Types

Payloads are msgpack-encoded structs; keys follow the `codec` tags in
`pkg/api/quic/overlay_handlers.go`. For example the status response:

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
    UnpeeredVTEPs int    `codec:"unpeered_vteps"`
    UplinkIface  string `codec:"uplink_iface,omitempty"`
    MTU          int    `codec:"mtu"`
    EncapType    string `codec:"encap_type"`
    HealthStatus string `codec:"health_status"`
}
```

List responses are paginated with a default limit of 100 and a maximum
of 1000 entries per page.

## Errors

Typed sentinel errors map onto QUIC error frames, including: overlay
service not available, VTEP/VNI/MAC not found, VNI already exists,
invalid VNI (must be 1-16777215), and invalid MAC address format.

## Client Usage

The platformctl CLI exercises this surface with
`--transport quic`:

```bash
platformctl --transport quic sdn overlay status
platformctl --transport quic sdn overlay vni create --vni 1000100 --vlan 100
```

## See Also

- [API Reference](api-reference.md) — Overview and data types
