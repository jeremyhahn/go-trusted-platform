# NTP QUIC API Reference

| Property | Value |
|----------|-------|
| Endpoint | `host:9444` (UDP, QUIC + TLS 1.3) |
| Category opcode | `0x50` (`OpNTPCategory`, `sdk/go/wire/quicwire/ntp_opcodes.go`) |
| Sub-opcodes | `0x01`-`0x03` |
| Message format | Sub-opcode byte + codec-encoded `platform.v1` pb struct |
| Handler | `pkg/api/daemon/quic_ntp.go` |
| SDK mapping | `sdk/go/transport/quic/aab_ntp.go` |

## Opcode allocation

The single-byte QUIC opcode space is otherwise fully allocated, so NTP
reclaims `0x50` — the head of the never-implemented `OpProv*` range,
whose provisioning surface actually ships under
`OpProvisioningCategory` (`0xCF`). This follows the same precedent as
`OpAttestCollectHost` (repurposed from the never-implemented
`OpAttestGetEK`) and `OpVMExtendedCategory` (repurposed from
`OpVMDeactivate`). `0x51`-`0x55` remain reserved for NTP growth.

The reclaim is pinned by the dispatch guard
(`pkg/api/daemon/quic_dispatch_guard_test.go`), which asserts byte
ownership for the whole `0x00`-`0xFF` space.

## Sub-Opcodes

| Sub-opcode | Operation | Request / response messages |
|-----------|-----------|------------------------------|
| `0x01` | GetStatus | `GetNTPStatusRequest` / `GetNTPStatusResponse` |
| `0x02` | ListSources | `ListNTPSourcesRequest` / `ListNTPSourcesResponse` |
| `0x03` | Step | `StepNTPClockRequest` / `StepNTPClockResponse` |

## Wire Format

All three requests are **empty messages**, so the SDK adapter sends a
one-byte payload containing only the sub-opcode; the daemon dispatcher
tolerates a zero-length sub-payload. Responses are the generated
`platform.v1` messages encoded verbatim.

This matters: the payload codec keys MessagePack maps on **Go field
names**, not proto JSON names. Because both sides encode and decode the
same generated pb structs, the field names match by construction — no
mirror wire structs, no silent field drops. `sdk/go/transport/quic`
registers the mapping in an init that runs before the adapter's
category-invariant assertion, so a method routed to `0x50` without a
sub-opcode entry panics at startup rather than failing in production.

## Status Bytes

The QUIC surface delegates to the shared `NTPGRPCService`, so the typed
`pkg/ntp` error → gRPC code mapping is reused and then translated to
wire statuses:

| gRPC code | QUIC status |
|-----------|-------------|
| `Unavailable` | `StatusUnavailable` (`0x0A`) |
| `Aborted` (no reachable source) | `StatusAlreadyExists` (`0x06`, the wire's conflict status) |
| `InvalidArgument` | `StatusInvalidArgument` (`0x09`) |
| `DeadlineExceeded` | `StatusTimeout` (`0x05`) |
| anything else | `StatusInternalError` (`0x04`) |

A missing sub-opcode byte returns `StatusInvalidRequest`; an unknown
sub-opcode returns `StatusNotImplemented`.

## Authorization

`DefaultOpcodePermissions` records `ntp:read` for the category opcode —
the floor scope every NTP caller needs. Because one opcode multiplexes
both reads and the write, per-operation enforcement (`ntp:write` for
`Step`) lives in the gRPC method catalog and the MCP tool catalog, which
is the same arrangement every other category opcode uses.

## SDK Usage

```go
client, err := platform.Connect(ctx, platform.NewOptions(
    platform.WithOnlyProtocol(platform.ProtocolQUIC),
    platform.WithQUICAddr("cp.example.com:9444"),
    platform.WithTLSConfig(tlsConfig)))

ntpClient := ntp.NewClientFromGRPC(client.NTP())
sources, err := ntpClient.Sources(ctx)
```
