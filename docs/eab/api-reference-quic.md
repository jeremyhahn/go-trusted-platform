# EAB QUIC API Reference

| Property | Value |
|----------|-------|
| Endpoint | `host:9444` (UDP, QUIC + TLS 1.3) |
| Category opcode | `0xCF` (`OpProvisioningCategory`) — shared with config delivery |
| Sub-opcode range | `0x10`-`0x1A` (`EABSub*`, `pkg/api/quic/eab_opcodes.go`) |
| Message format | Sub-opcode byte + codec-encoded `platform.v1` pb struct |
| Handler | `pkg/api/daemon/quic_eab.go` |

The single-byte QUIC opcode space (0x00-0xFF) is fully allocated, so
EAB multiplexes under the existing provisioning category — EAB
credentials exist solely to authenticate the provisioning flow, making
`0xCF` the semantically correct home. `payload[0]` selects the
sub-operation; the daemon routes the EAB sub-range before delegating
the rest to the config delivery dispatcher, so the two families never
collide (`0x01`-`0x07` config delivery, `0x08`-`0x0F` reserved,
`0x10`-`0x1A` EAB).

## Sub-Opcodes

| Sub-opcode | Operation | Request / response messages |
|-----------|-----------|------------------------------|
| `0x10` | CreateCredential | `CreateEABCredentialRequest` / `CreateEABCredentialResponse` |
| `0x11` | GetCredential | `GetEABCredentialRequest` / `GetEABCredentialResponse` |
| `0x12` | GetCredentialByKeyID | `GetEABCredentialByKeyIDRequest` / `GetEABCredentialResponse` |
| `0x13` | ListCredentials | `ListEABCredentialsRequest` / `ListEABCredentialsResponse` |
| `0x14` | RevokeCredential | `RevokeEABCredentialRequest` / `RevokeEABCredentialResponse` |
| `0x15` | ValidateCredential | `ValidateEABCredentialRequest` / `ValidateEABCredentialResponse` |
| `0x16` | DeleteCredential | `DeleteEABCredentialRequest` / `DeleteEABCredentialResponse` |
| `0x17` | GetCredentialQRCode | `GetEABCredentialQRCodeRequest` / `GetEABCredentialQRCodeResponse` |
| `0x18` | GetEnrollmentURL | `GetEABEnrollmentURLRequest` / `GetEABEnrollmentURLResponse` |
| `0x19` | MarkCredentialUsed | `MarkEABCredentialUsedRequest` / `MarkEABCredentialUsedResponse` |
| `0x1A` | CleanupExpiredCredentials | `CleanupExpiredEABCredentialsRequest` / `CleanupExpiredEABCredentialsResponse` |

## Wire Format

Every `platform.v1` EAB message is **oneof-free**, so the generated pb
structs encode/decode directly through the payload codec (which keys on
exact Go field names) — no mirror wire structs and no flattening. The
SDK QUIC adapter (`sdk/go/transport/quic`) encodes the pb request,
prepends the sub-opcode, and decodes the response payload straight into
the pb reply.

## Status Bytes

The QUIC surface delegates to the shared `EABGRPCService`, so the typed
`pkg/eab` error → gRPC code mapping is reused by construction and then
translated to QUIC status bytes using the same table as config
delivery: `NotFound` → `StatusNotFound`, `InvalidArgument` →
`StatusInvalidArgument`, `FailedPrecondition` (expired / revoked /
already-used) → `StatusInvalidRequest`, `Unavailable` (service not
configured) → `StatusUnavailable`, everything else →
`StatusInternalError`.

## SDK Usage

```go
client, err := platform.NewClient(ctx,
    platform.WithOnlyProtocol(platform.ProtocolQUIC),
    platform.WithQUICAddr("localhost:9444"),
    platform.WithTLSConfig(tlsConfig))
eabClient, err := eab.NewClient(client.Transport())
cred, err := eabClient.CreateCredential(ctx, &platformv1.CreateEABCredentialRequest{
    ProfileId: 7, TenantId: "tenant-1", ExpiresInSeconds: 86400,
})
```
