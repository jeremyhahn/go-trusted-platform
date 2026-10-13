# Gateway Unix Socket API Reference

Unix socket clients use the gRPC gateway service over the configured platformd
socket. The RPC surface is the same as [api-reference-grpc.md](api-reference-grpc.md).

| RPC | Description |
|---|---|
| `GetGatewayStatus` | Gateway node status. |
| `SetGatewayMode` | Deprecated compatibility mode setter. |
| `GetGatewaySnapshot` | Read one gateway snapshot. |
| `ListGatewaySnapshots` | List reported gateway snapshots. |
| `GetGatewayAdmittedVTEP` | Read one admitted overlay VTEP by IP address. |
| `ListGatewayAdmittedVTEPs` | List admitted overlay VTEPs. |
| `GetBGPStatus` | BGP speaker status. |
| `ListBGPPeers` | List BGP peers. |
| `ListAnnouncedPrefixes` | List announced prefixes. |
| `AnnouncePrefix` | Announce a prefix with a next hop. |
| `WithdrawPrefix` | Withdraw an announced prefix. |

The overlay status shape, admitted-VTEP results, BGP results and BGP errors
match gRPC exactly.
