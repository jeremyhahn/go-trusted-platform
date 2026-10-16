# DNS gRPC API Reference

> **Status: REFERENCE** · Last verified: 2026-10-15
> The `DNSService` gRPC surface as declared in
> `pkg/api/grpc/proto/platform_dns.proto`. The cross-transport matrix is
> [api.md](api.md).

| Property | Value |
|----------|-------|
| Service | `platform.v1.DNSService` |
| Port | 10443 |
| Transport | TCP with TLS (the Unix socket carries the same service, see [api-reference-unix.md](api-reference-unix.md)) |
| Go package | `github.com/jeremyhahn/go-trusted-platform/sdk/go/gen` (`platformv1`) |

## Service Definition

```protobuf
service DNSService {
  // Zone operations
  rpc CreateZone(CreateZoneRequest) returns (CreateZoneResponse);
  rpc GetZone(GetZoneRequest) returns (GetZoneResponse);
  rpc UpdateZone(UpdateZoneRequest) returns (UpdateZoneResponse);
  rpc DeleteZone(DeleteZoneRequest) returns (DeleteZoneResponse);
  rpc ListZones(ListZonesRequest) returns (ListZonesResponse);

  // Record operations
  rpc AddRecord(AddRecordRequest) returns (AddRecordResponse);
  rpc DeleteRecord(DeleteRecordRequest) returns (DeleteRecordResponse);
  rpc UpdateRecord(UpdateRecordRequest) returns (UpdateRecordResponse);
  rpc ListRecords(ListRecordsRequest) returns (ListRecordsResponse);

  // DNSSEC operations
  rpc SignZone(SignZoneRequest) returns (SignZoneResponse);
  rpc GetDNSSECStatus(GetDNSSECStatusRequest) returns (GetDNSSECStatusResponse);

  // Resolution
  rpc Resolve(ResolveRequest) returns (ResolveResponse);

  // Registration
  rpc Register(RegisterRequest) returns (RegisterResponse);
}
```

There is no `GetRecord` rpc: list the zone's records with a `type` and pick
the name ([api.md](api.md) §2). There is no separate TLSA rpc: add a `Record`
of type `RECORD_TYPE_TLSA`.

## Requests and Responses

| RPC | Request fields | Response fields |
|-----|----------------|-----------------|
| `CreateZone` | `name`, `ttl`, `description`, `internal`, `soa`, `ns_records` | `status`, `zone` |
| `GetZone` | `name` | `zone` |
| `UpdateZone` | `name`, `ttl`, `description` | `status`, `zone` |
| `DeleteZone` | `name` | `status` |
| `ListZones` | `internal_only`, `public_only`, `pagination` | `zones`, `pagination` |
| `AddRecord` | `zone_name`, `record` | `status`, `zone` |
| `DeleteRecord` | `zone_name`, `type`, `name` | `status`, `zone` |
| `UpdateRecord` | `zone_name`, `old_record`, `new_record` | `status`, `zone` |
| `ListRecords` | `zone_name`, `type` | `records` |
| `SignZone` | `zone_name` | `status`, `zone` |
| `GetDNSSECStatus` | `zone_name` | `status` (`enabled`, `zone_signed`, `keys`, `ds_records`, `algorithm`, `key_size`) |
| `Resolve` | `fqdn`, `type` | `records`, `authoritative` |
| `Register` | `fqdn`, `ip` | `status`, `zone` |

## Records

A `Record` is a `RecordType` plus a `oneof` body:

```protobuf
message Record {
  RecordType type = 1;
  oneof record {
    ARecord a = 2;
    AAAARecord aaaa = 3;
    CNAMERecord cname = 4;
    MXRecord mx = 5;
    NSRecord ns = 6;
    TXTRecord txt = 7;
    SRVRecord srv = 8;
    CAARecord caa = 9;
    TLSARecord tlsa = 10;
  }
}
```

`RecordType` runs from `RECORD_TYPE_A` (1) to `RECORD_TYPE_NSEC3PARAM` (16).
A zone's `RecordSet` carries `soa` and one repeated field per type
(`a_records`, `aaaa_records`, `tlsa_records`, …), including the DNSSEC types a
signed zone holds.

## Example

```go
import (
    "crypto/tls"

    platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
)

conn, err := grpc.NewClient("localhost:10443",
    grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
if err != nil {
    return err
}
client := platformv1.NewDNSServiceClient(conn)

_, err = client.AddRecord(ctx, &platformv1.AddRecordRequest{
    ZoneName: "example.internal.",
    Record: &platformv1.Record{
        Type: platformv1.RecordType_RECORD_TYPE_A,
        Record: &platformv1.Record_A{
            A: &platformv1.ARecord{Name: "server01", Value: "192.0.2.10", Ttl: 300},
        },
    },
})
```

## Errors

Status codes follow [api.md](api.md) §5: `NOT_FOUND` for an unknown zone or
record (including a zone of another tenant), `ALREADY_EXISTS` for a taken zone
name, `INVALID_ARGUMENT` for a malformed request or unsupported record type,
`PERMISSION_DENIED` for a missing `dns:*` scope.

With no `dns:` section the answer is `UNAVAILABLE` with an `ErrorInfo` detail,
reason `SERVICE_NOT_CONFIGURED` and metadata `service=dns`. Every method checks
for the backend before it reads the request, so an empty request answers
`UNAVAILABLE` too, not `INVALID_ARGUMENT`.
