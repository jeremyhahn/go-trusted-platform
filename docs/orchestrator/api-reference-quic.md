# Orchestrator QUIC API Reference

> **Status: REFERENCE** · Last verified: 2026-10-22
> The orchestrator sub-opcodes under `0x66`, the wire format and the QUIC status bytes.

| Property | Value |
|----------|-------|
| Endpoint | `host:9444` (UDP, QUIC + TLS 1.3) |
| Category opcode | `0x66` (`OpOrchestratorCategory`, `sdk/go/wire/quicwire/orchestrator_opcodes.go`) |
| Sub-opcode range | `0x01`-`0x0A` (`OrchestratorSub*`) |
| Message format | sub-opcode byte + MessagePack-encoded `platform.v1` request |
| Handler | `handleOrchestratorCategory` (`pkg/api/daemon/quic_orchestrator.go`) |
| Scopes | `pkg/api/quic/opcode_permissions.go` |
| SDK adapter | `sdk/go/transport/quic/aab_orchestrator.go` |

`payload[0]` selects the sub-operation and `payload[1:]` is the request.
Every request carries a body, even an empty message. The handler dispatches
through the `orchestratorQUICHandlers` map and calls the same
`OrchestratorGRPCService` instance the other transports call.

## Sub-Opcodes

| Sub-opcode | Constant | Operation | Request / response messages | Scope |
|-----------|----------|-----------|------------------------------|-------|
| `0x01` | `OrchestratorSubHealth` | Health | `OrchestratorHealthRequest` / `OrchestratorHealthResponse` | `orchestrator:read` |
| `0x02` | `OrchestratorSubListAgents` | ListAgents | `ListOrchestratorAgentsRequest` / `ListOrchestratorAgentsResponse` | `orchestrator:read` |
| `0x03` | `OrchestratorSubGetAgent` | GetAgent | `GetOrchestratorAgentRequest` / `GetOrchestratorAgentResponse` | `orchestrator:read` |
| `0x04` | `OrchestratorSubDisableAgent` | DisableAgent | `DisableOrchestratorAgentRequest` / `DisableOrchestratorAgentResponse` | `orchestrator:write` |
| `0x05` | `OrchestratorSubEnableAgent` | EnableAgent | `EnableOrchestratorAgentRequest` / `EnableOrchestratorAgentResponse` | `orchestrator:write` |
| `0x06` | `OrchestratorSubListSessions` | ListSessions | `ListOrchestratorSessionsRequest` / `ListOrchestratorSessionsResponse` | `orchestrator:read` |
| `0x07` | `OrchestratorSubCloseSession` | CloseSession | `CloseOrchestratorSessionRequest` / `CloseOrchestratorSessionResponse` | `orchestrator:write` |
| `0x08` | `OrchestratorSubListJobs` | ListJobs | `ListOrchestratorJobsRequest` / `ListOrchestratorJobsResponse` | `orchestrator:read` |
| `0x09` | `OrchestratorSubGetJob` | GetJob | `GetOrchestratorJobRequest` / `GetOrchestratorJobResponse` | `orchestrator:read` |
| `0x0A` | `OrchestratorSubCancelJob` | CancelJob | `CancelOrchestratorJobRequest` / `CancelOrchestratorJobResponse` | `orchestrator:write` |

## Wire Format

The `platform.v1` orchestrator messages are oneof-free, so the generated pb
structs encode and decode directly through the payload codec. The SDK QUIC
adapter maps each gRPC method to `0x66` and its sub-opcode, encodes the pb
request, prepends the sub-opcode, and decodes the response payload into the
pb reply.

## Status Bytes

The gRPC code of a failed call becomes a status byte
(`grpcDelegateCodeToQUICStatus`, `pkg/api/daemon/quic_grpc_delegates.go`):

| gRPC status | QUIC status |
|-------------|-------------|
| `INVALID_ARGUMENT` | `StatusInvalidArgument` |
| `NOT_FOUND` | `StatusNotFound` |
| `ALREADY_EXISTS` | `StatusAlreadyExists` |
| `PERMISSION_DENIED` | `StatusPermissionDenied` |
| `FAILED_PRECONDITION` | `StatusInvalidRequest` |
| `UNAVAILABLE` | `StatusUnavailable` |
| `DEADLINE_EXCEEDED` | `StatusTimeout` |
| anything else | `StatusInternalError` |

An empty payload or an undecodable body is `StatusInvalidRequest`, and a
daemon with no orchestrator service answers `StatusUnavailable` naming the
service. An unknown sub-opcode is refused by the authorization guard, which
has no scope for it; a handler reached without one answers
`StatusNotImplemented`.

## SDK Usage

```go
client, err := platform.Connect(ctx, platform.NewOptions(
    platform.WithOnlyProtocol(platform.ProtocolQUIC),
    platform.WithQUICAddr("localhost:9444"),
    platform.WithTLSConfig(tlsConfig)))
agent, err := client.Orchestrator().GetAgent(ctx, &platformv1.GetOrchestratorAgentRequest{
    TenantId: "t1", AgentId: "agent-7",
})
```
