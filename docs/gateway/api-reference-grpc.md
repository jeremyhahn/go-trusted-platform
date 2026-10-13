# Gateway gRPC API Reference

The gateway service is defined in `pkg/api/grpc/proto/gateway.proto` and served
by `platform.v1.GatewayService`.

| RPC | Description |
|---|---|
| `GetGatewayStatus` | Gateway node status. |
| `SetGatewayMode` | Deprecated compatibility mode setter. |
| `GetGatewaySnapshot` | Read one gateway snapshot. |
| `ListGatewaySnapshots` | List reported gateway snapshots. |
| `GetGatewayAdmittedVTEP` | Read one admitted overlay VTEP by IP address. |
| `ListGatewayAdmittedVTEPs` | List admitted overlay VTEPs. |
| `GetBGPStatus` | BGP speaker status. Requires `sdn:read`. |
| `ListBGPPeers` | List BGP peers. Requires `sdn:read`. |
| `ListAnnouncedPrefixes` | List announced prefixes. Requires `sdn:read`. |
| `AnnouncePrefix` | Announce a prefix with a next hop. Requires `sdn:write`. |
| `WithdrawPrefix` | Withdraw an announced prefix. Requires `sdn:write`. |

Unix socket clients use the same RPCs over gRPC on the configured platformd
socket.

`GatewaySnapshot.overlay` carries overlay runtime status, admitted VTEPs and ND
counters. `GatewayAdmittedVTEP` is returned by both direct admitted-VTEP RPCs
and the snapshot overlay list.

With no BGP speaker the BGP RPCs answer `Unavailable`; a malformed prefix or
next hop answers `InvalidArgument` ([api.md](api.md) §3, §11).
