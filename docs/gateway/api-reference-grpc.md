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

Unix socket clients use the same RPCs over gRPC on the configured platformd
socket.

`GatewaySnapshot.overlay` carries overlay runtime status, admitted VTEPs and ND
counters. `GatewayAdmittedVTEP` is returned by both direct admitted-VTEP RPCs
and the snapshot overlay list.
