# Gateway QUIC API Reference

Gateway QUIC commands use category `0x2F`.

| Opcode | Name | Description |
|---|---|---|
| `0x01` | `OpGatewayStatus` | Gateway node status. |
| `0x02` | `OpGatewaySetMode` | Deprecated compatibility mode setter. |
| `0x03` | `OpGatewayBGPStatus` | BGP speaker status. Empty body. |
| `0x04` | `OpGatewayBGPPeers` | List BGP peers. |
| `0x05` | `OpGatewayAnnouncePrefix` | Announce a prefix with a next hop. |
| `0x06` | `OpGatewayWithdrawPrefix` | Withdraw an announced prefix. |
| `0x07` | `OpGatewayListPrefixes` | List announced prefixes. |
| `0x15` | `OpGatewaySnapshot` | Read one gateway snapshot. |
| `0x16` | `OpGatewayListSnapshots` | List reported gateway snapshots. |
| `0x17` | `OpGatewayAdmittedVTEP` | Read one admitted overlay VTEP by IP address. |
| `0x18` | `OpGatewayListAdmittedVTEPs` | List admitted overlay VTEPs. |

The BGP sub-opcodes share their wire shapes with the SDK through
`sdk/go/wire/quicwire/gateway_bgp.go`. An announce that sets `local_pref`,
`med`, `communities` or `labels` is refused with `StatusInvalidArgument`: the
service carries a prefix and a next hop only. With no BGP speaker every BGP
sub-opcode answers `StatusUnavailable` ([api.md](api.md) §3).

`OpGatewayBGPPeers` and `OpGatewayListPrefixes` answer one page: at most
`limit` entries (100 when unset, capped at 1000) starting at `offset`, with
`count` for the page and `total` for the whole list. A negative `offset` is
refused with `StatusInvalidRequest`. The SDK's QUIC client pages through
until it has `total` entries, so `ListBGPPeers` and `ListAnnouncedPrefixes`
return the whole list, as they do over gRPC.

The snapshot payload includes an `overlay` object when gatewayd runs the overlay
service. It includes local VTEP metadata, admitted VTEPs and ND counters for
punted, answered, meter-dropped, queue-dropped and fell-through packets.
