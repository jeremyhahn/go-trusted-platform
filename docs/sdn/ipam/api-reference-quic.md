# IPAM QUIC API Reference

IPAM operations ride the gateway QUIC surface: category opcode `0x2F`
(Gateway) with the IPAM sub-opcodes, served on UDP port 9444 (mTLS).
Payloads are msgpack-encoded (`pkg/api/quic/gateway_handlers.go`).

## IPAM Sub-opcodes

| Sub-opcode | Operation |
|-----------|-----------|
| `0x08` | GatewayListIPAMPools |
| `0x09` | GatewayAllocateIP |
| `0x0A` | GatewayReleaseIP |
| `0x0B` | GatewayListAllocations |
| `0x0C` | GatewayCreateIPAMPool |
| `0x0D` | GatewayDeleteIPAMPool |
| `0x0E` | GatewayGetIPAMPool |
| `0x0F` | GatewayUpdateIPAMPool |

List responses are paginated (default 100, max 1000 entries).

Pool payloads (`IPAMPoolInfo`) and the create request carry the allocation
window as `reserved`, `range_start` and `range_end`. The update request
replaces the window only when `update_window` is true, with exactly the
values given. A reserved address or a window that does not fit the CIDR
answers `StatusInvalidArgument` (`ErrGatewayIPAMWindow`).

## Client Usage

```bash
platformctl --transport quic sdn ipam pool list
platformctl --transport quic sdn ipam allocate --pool-id pool1 --device-id vm-123
platformctl --transport quic sdn ipam allocations --pool-id pool1
```

## See Also

- [API Reference](api-reference.md) — Overview
- [Gateway QUIC API Reference](../gateway/api-reference-quic.md)
