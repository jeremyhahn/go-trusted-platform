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

Pools carry no DNS servers on any transport. Before #730, the QUIC (and MCP)
create request accepted a `dns` field and dropped it; that field no longer
exists.

### Allocate and release

Allocation and release go through the daemon's IPAM allocator, the same one
gRPC and REST use. Before #730, both verbs answered
`gateway feature not configured`, even though `0x0B` already listed that
allocator's allocations.

`GatewayAllocateIPRequest` (`0x09`):

| Field | Required | Meaning |
|---|---|---|
| `pool_id` | yes | Pool to allocate from |
| `owner` | yes | The device the address is allocated to. gRPC and REST call it `device_id` and also require it. A missing owner gets `StatusInvalidArgument`. |
| `ip_address` | no | Allocate this specific address. If another allocation holds it, the answer is `StatusAlreadyExists`. |
| `type` | no | `dynamic` (default) or `static`. `static` requires `ip_address`. Any other value gets `StatusInvalidArgument`. |
| `hostname` | no | Recorded with the allocation |
| `ttl` | no | Lease in seconds; overrides the pool default |
| `labels` | no | Recorded as allocation metadata |
| `mac_address` | — | IPAM records no MAC address, so a request carrying one gets `StatusInvalidArgument` rather than silently losing it |

The response carries the allocation (`IPAllocationInfo`): `owner` is its
device, and `created_at`, `updated_at` and `expires_at` are Unix seconds.

`GatewayReleaseIPRequest` (`0x0A`) needs only `ip_address`, as release does
on gRPC, REST and the CLI. `pool_id` is optional. When it is given, an address
held in a different pool answers `StatusNotFound` and is not released.
Releasing an address with no active allocation also answers `StatusNotFound`.

`GatewayListAllocations` (`0x0B`) lists only allocations that still hold their
address. The same rule applies on gRPC and REST: a released allocation is
never listed. Before #730, REST still listed released allocations.

## Client Usage

```bash
platformctl --transport quic sdn ipam pool list
platformctl --transport quic sdn ipam allocate --pool-id pool1 --device-id vm-123
platformctl --transport quic sdn ipam allocations --pool-id pool1
```

## See Also

- [API Reference](api-reference.md) — Overview
- [Gateway QUIC API Reference](../gateway/api-reference-quic.md)
