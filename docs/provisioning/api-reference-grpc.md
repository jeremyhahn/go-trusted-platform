# Config Delivery gRPC API Reference

| Property | Value |
|----------|-------|
| Service | `platform.v1.ConfigDeliveryService` |
| Proto | `pkg/api/grpc/proto/configdelivery.proto` |
| Endpoint | `host:10443` (TLS/mTLS) |
| Also served on | Unix socket (`/run/platformd.sock`, see [api-reference-unix.md](api-reference-unix.md)) |

The gRPC surface is backed by the same `configdelivery.Service` as REST, so
authentication (EAB + single-use nonce + EK binding) and semantics are
identical; only the wire binding differs.

## Service Definition

```protobuf
service ConfigDeliveryService {
  rpc GetNonce(GetNonceRequest) returns (GetNonceResponse);
  rpc FetchConfig(FetchConfigRequest) returns (FetchConfigResponse);
  rpc SignDigest(SignDigestRequest) returns (SignDigestResponse);
  rpc PollSession(PollSessionRequest) returns (PollSessionResponse);
  rpc FulfillSession(FulfillSessionRequest) returns (FulfillSessionResponse);
  rpc ListSessions(ListSessionsRequest) returns (ListSessionsResponse);
  rpc GetSession(GetSessionRequest) returns (GetSessionResponse);
}
```

## Messages

### FetchConfig

```protobuf
message FetchConfigRequest {
  string ek_serial = 1;
  string mac_address = 2;
  string ek_cert = 3;      // standard-base64 DER EK certificate
  string eab_key_id = 4;
  string eab_hmac = 5;     // base64url HMAC key
  string nonce = 6;
}

message FetchConfigResponse {
  oneof result {
    DeliveredConfig delivered = 1;   // config_json (JSON bytes) + status "ok"
    PendingSession pending = 2;      // session_id, provision_url, poll_interval_seconds
  }
}
```

`DeliveredConfig.config_json` is the JSON encoding of the merged device
config — identical content to the REST `config` field.

### SignDigest

`SignDigestRequest` mirrors `FetchConfigRequest` plus `bytes digest` (the
pre-computed message digest) and `string key_ref` (only `"db"` is remotely
signed; empty defaults to `"db"`). `SignDigestResponse` carries
`bytes signature` and `bytes cert_pem`.

### Sessions

```protobuf
message PollSessionResponse {
  oneof result {
    DeliveredConfig delivered = 1;
    string pending_status = 2;       // "pending"
  }
}

message FulfillSessionRequest { string session_id = 1; uint64 profile_id = 2; }
message FulfillSessionResponse { string status = 1; }  // "fulfilled"

message ProvisioningSession {
  string id = 1;
  string ek_serial = 2;
  string mac_address = 3;
  string tenant_id = 4;
  uint64 profile_id = 5;
  DeviceProfile profile = 6;
  bool fulfilled = 7;
  google.protobuf.Timestamp created_at = 8;
  google.protobuf.Timestamp expires_at = 9;
}
```

## Error Codes

Typed service errors map to gRPC status codes via ordered matcher tables in
`pkg/api/daemon/configdelivery_grpc_service.go`:

| Condition | Code |
|-----------|------|
| Malformed request, missing fields, spent/expired nonce, unparseable EK cert | `InvalidArgument` |
| EAB validation failure (FetchConfig) | `Unauthenticated` |
| EAB validation failure (SignDigest), EK cert required/mismatch | `PermissionDenied` |
| Unknown session or profile | `NotFound` |
| Expired or already-fulfilled session | `InvalidArgument` |
| `FulfillSession` with `profile_id` missing or 0 (`configdelivery.ErrProfileIDRequired`) | `InvalidArgument` |
| Profile not provisioned for remote signing | `FailedPrecondition` |
| Session fulfilled without a resolved profile (PollSession) | `Internal` |
| No DB key signer / no profile service | `Unavailable` |
| Service not constructed (missing daemon deps) | `Unavailable` |
| Anything else | `Internal` |

## SDK Usage

```go
import (
    platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
    _ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/grpc"
    provision "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/provision"
)

client, err := platform.NewClient(ctx,
    platform.WithOnlyProtocol(platform.ProtocolGRPC),
    platform.WithGRPCAddr("localhost:10443"),
    platform.WithTLSConfig(tlsConfig))
if err != nil { ... }
defer client.Close()

prov := provision.NewClientFromGRPC(client.ConfigDelivery())
nonce, err := prov.GetNonce(ctx)
sessions, err := prov.ListSessions(ctx)
```

The same `provision.Client` works unchanged over REST, QUIC, MCP, Unix, and
embedded transports — pass the corresponding `platform.WithOnlyProtocol` and
address option.
