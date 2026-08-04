# Config Delivery QUIC API Reference

| Property | Value |
|----------|-------|
| Endpoint | `host:9444` (UDP, QUIC + TLS 1.3) |
| Category opcode | `0xCF` (`OpProvisioningCategory`) |
| Message format | Sub-opcode byte + codec-encoded payload (MessagePack by default) |
| Handler | `pkg/api/daemon/quic_configdelivery.go` |

The provisioning verbs multiplex under a single category opcode: the **first
byte of the request payload selects the sub-operation**, following the same
pattern as `OpSwitchCategory` (0xCC), `OpKMSExtendedCategory` (0xCD), and
`OpSecretsCategory` (0xCE). The QUIC handler delegates to the same
`ConfigDeliveryGRPCService` as the gRPC transport, so semantics and error
mapping are shared by construction.

## Sub-Opcodes

| Sub-opcode | Operation | Request body | Response body |
|-----------|-----------|--------------|---------------|
| `0x01` | GetNonce | *(none — payload is the sub-opcode byte only)* | `{nonce}` |
| `0x02` | FetchConfig | FetchConfig wire struct | flattened tri-state (below) |
| `0x03` | SignDigest | SignDigest wire struct | `{signature, cert_pem}` |
| `0x04` | PollSession | `{session_id}` | flattened tri-state (below) |
| `0x05` | FulfillSession | `{session_id, profile_id}` | `{status: "fulfilled"}` |
| `0x06` | ListSessions | *(none — payload is the sub-opcode byte only)* | `{sessions: [...]}` |
| `0x07` | GetSession | `{session_id}` | `{session}` |

Sub-opcodes `0x08`-`0x0F` are reserved for config delivery growth. The
EAB credential service shares this category opcode with sub-opcodes
`0x10`-`0x1A` (the single-byte opcode space is fully allocated); see
[docs/eab/api-reference-quic.md](../eab/api-reference-quic.md). The
daemon routes the EAB sub-range first
(`pkg/api/daemon/quic_eab.go::handleEABCategorySub`) and falls through
to the config delivery dispatcher for everything else.

```
Request:                          Response:
+--------+--------+---------+     +--------+---------+
| OpCode | SubOp  | Payload |     | Status | Payload |
| (0xCF) | (1B)   | (codec) |     | (1B)   | (codec) |
+--------+--------+---------+     +--------+---------+
```

## Wire Structs

The QUIC payload codec keys on **exact Go field names** (struct tags are
ignored), so the wire structs mirror the `platform.v1` protobuf messages
field-for-field. Request structs use the pb field layout
(`EkSerial`, `MacAddress`, `EkCert`, `EabKeyId`, `EabHmac`, `Nonce`, plus
`Digest`/`KeyRef` for SignDigest). Session objects reuse
`platformv1.ProvisioningSession` directly (no oneof, round-trips by field
name).

## Flattened Oneof Responses

`FetchConfigResponse` and `PollSessionResponse` use a protobuf `oneof` that
cannot round-trip through the codec, so they are **flattened** into single
wire structs with a `Result` string discriminator:

**FetchConfig** (`ConfigDeliveryFetchConfigResponse`):

| Field | Populated when |
|-------|----------------|
| `Result` | always — `"delivered"` or `"pending"` |
| `ConfigJson`, `Status` | `Result == "delivered"` |
| `SessionId`, `ProvisionUrl`, `PollIntervalSeconds` | `Result == "pending"` |

**PollSession** (`ConfigDeliveryPollSessionResponse`):

| Field | Populated when |
|-------|----------------|
| `Result` | always — `"delivered"` or `"pending"` |
| `ConfigJson`, `Status` | `Result == "delivered"` |
| `PendingStatus` | `Result == "pending"` (value `"pending"`) |

The SDK QUIC transport (`sdk/go/transport/quic/provisioning.go`) decodes the
flat form and rebuilds the pb oneof, so SDK callers see identical replies to
a gRPC call.

## Status Bytes

gRPC codes from the shared error-matcher tables translate to QUIC status
bytes:

| gRPC code | QUIC status |
|-----------|-------------|
| `InvalidArgument` | `StatusInvalidArgument` |
| `Unauthenticated` | `StatusUnauthorized` |
| `PermissionDenied` | `StatusPermissionDenied` |
| `NotFound` | `StatusNotFound` |
| `FailedPrecondition` | `StatusInvalidRequest` |
| `Unavailable` | `StatusUnavailable` |
| `Internal` (and unknown) | `StatusInternalError` |

An unknown sub-opcode (outside both the config delivery and EAB
families) returns `StatusNotImplemented`; a missing `session_id`
returns `StatusInvalidArgument` before dispatch.

## SDK Usage

```go
client, err := platform.NewClient(ctx,
    platform.WithOnlyProtocol(platform.ProtocolQUIC),
    platform.WithQUICAddr("localhost:9444"),
    platform.WithTLSConfig(tlsConfig))   // NextProtos set by the transport
prov := provision.NewClientFromGRPC(client.ConfigDelivery())
```
