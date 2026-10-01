# Gateway QUIC API Reference

Endpoint: UDP port 9444, mTLS required.

Gateway requests use the extended-opcode scheme: category opcode `0x2F`
(Gateway) selects the gateway handler and a sub-opcode selects the
operation. Payloads are msgpack-encoded; keys follow the `codec` tags in
`pkg/api/quic/gateway_handlers.go`, `gateway_lb_handlers.go`, and
`gateway_perf_handlers.go`.

## Operations

| Sub-opcode | Operation |
|-----------|-----------|
| `0x01` | GatewayStatus |
| `0x02` | GatewaySetMode |
| `0x03` | GatewayBGPStatus |
| `0x04` | GatewayBGPPeers |
| `0x05` | GatewayAnnouncePrefix |
| `0x06` | GatewayWithdrawPrefix |
| `0x07` | GatewayListPrefixes |
| `0x08` | GatewayListIPAMPools |
| `0x09` | GatewayAllocateIP |
| `0x0A` | GatewayReleaseIP |
| `0x0B` | GatewayListAllocations |
| `0x0C` | GatewayCreateIPAMPool |
| `0x0D` | GatewayDeleteIPAMPool |
| `0x0E` | GatewayGetIPAMPool |
| `0x0F` | GatewayUpdateIPAMPool |
| `0x10` | GatewayListNetworkZones |
| `0x11` | GatewayCreateNetworkZone |
| `0x12` | GatewayUpdateNetworkZone |
| `0x13` | GatewayDeleteNetworkZone |
| `0x14` | retired (was GatewayAssignNetworkZone; networks are zones since #708, never reused) |
| `0x30` | GatewayLBAddVIP |
| `0x31` | GatewayLBRemoveVIP |
| `0x32` | GatewayLBGetVIP |
| `0x33` | GatewayLBListVIPs |
| `0x34` | GatewayLBSetVIPBackends |
| `0x35` | GatewayLBStatus |
| `0x36` | GatewayPerfFlows (MUTATES bridge flow tables) |
| `0x37` | GatewayPerfDatapath |
| `0x38` | GatewayPerfConntrack |

List responses are paginated (default 100, max 1000 entries).

## Client Usage

```bash
platformctl --transport quic sdn gateway status
platformctl --transport quic sdn gateway lb vip list
platformctl --transport quic sdn gateway perf datapath
```

## See Also

- [gRPC API Reference](api-reference-grpc.md) — Message semantics
- [Operations Guide](operations.md)
