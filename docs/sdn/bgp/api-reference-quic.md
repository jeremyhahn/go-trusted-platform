# BGP QUIC API Reference

BGP operations ride the gateway QUIC surface: category opcode `0x2F`
(Gateway) with the BGP sub-opcodes, served on UDP port 9444 (mTLS).
Payloads are msgpack-encoded (`pkg/api/quic/gateway_handlers.go`).

## BGP Sub-opcodes

| Sub-opcode | Operation |
|-----------|-----------|
| `0x03` | GatewayBGPStatus |
| `0x04` | GatewayBGPPeers |
| `0x05` | GatewayAnnouncePrefix |
| `0x06` | GatewayWithdrawPrefix |
| `0x07` | GatewayListPrefixes |

## Client Usage

```bash
platformctl --transport quic sdn gateway bgp status
platformctl --transport quic sdn gateway bgp peers
platformctl --transport quic sdn gateway bgp announce --prefix 2001:db8::/36
```

## See Also

- [Gateway QUIC API Reference](../gateway/api-reference-quic.md)
- [CLI Usage](cli-usage.md)
