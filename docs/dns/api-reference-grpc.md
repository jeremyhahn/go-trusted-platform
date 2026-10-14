# DNS gRPC API Reference

gRPC service definition for the DNS service.

| Property | Value |
|----------|-------|
| Service | `dns.DNSService` |
| Port | 9443 |
| Transport | TCP with TLS |

## Service Definition

```protobuf
syntax = "proto3";
package dns;

service DNSService {
  // Zone operations
  rpc CreateZone(CreateZoneRequest) returns (Zone);
  rpc GetZone(GetZoneRequest) returns (Zone);
  rpc UpdateZone(UpdateZoneRequest) returns (Zone);
  rpc DeleteZone(DeleteZoneRequest) returns (DeleteZoneResponse);
  rpc ListZones(ListZonesRequest) returns (ListZonesResponse);

  // Record operations
  rpc AddRecord(AddRecordRequest) returns (Record);
  rpc GetRecord(GetRecordRequest) returns (Record);
  rpc UpdateRecord(UpdateRecordRequest) returns (Record);
  rpc DeleteRecord(DeleteRecordRequest) returns (DeleteRecordResponse);
  rpc ListRecords(ListRecordsRequest) returns (ListRecordsResponse);

  // TLSA/DANE
  rpc AddTLSARecord(AddTLSARecordRequest) returns (TLSARecord);

  // Resolution
  rpc Resolve(ResolveRequest) returns (ResolveResponse);
}
```

## Zone Operations

### CreateZone

```protobuf
message CreateZoneRequest {
  string name = 1;
  uint32 ttl = 2;
  string description = 3;
  bool internal = 4;
  RecordSet records = 5;
}

message Zone {
  uint64 id = 1;
  string name = 2;
  uint32 ttl = 3;
  string description = 4;
  bool internal = 5;
  RecordSet records = 6;
}
```

**Go Example:**
```go
resp, err := client.CreateZone(ctx, &dns.CreateZoneRequest{
    Name:        "myzone.internal.",
    Ttl:         3600,
    Description: "My zone",
    Internal:    true,
    Records: &dns.RecordSet{
        Soa: &dns.SOARecord{
            Name:   "myzone.internal.",
            Mname:  "ns1.myzone.internal.",
            Rname:  "hostmaster.myzone.internal.",
            Serial: 1,
        },
    },
})
```

### GetZone

```protobuf
message GetZoneRequest {
  string name = 1;
}
```

**Go Example:**
```go
zone, err := client.GetZone(ctx, &dns.GetZoneRequest{
    Name: "myzone.internal.",
})
```

### UpdateZone

```protobuf
message UpdateZoneRequest {
  string name = 1;
  uint32 ttl = 2;
  string description = 3;
  RecordSet records = 4;
}
```

### DeleteZone

```protobuf
message DeleteZoneRequest {
  string name = 1;
}

message DeleteZoneResponse {
  bool deleted = 1;
  string zone_name = 2;
}
```

### ListZones

```protobuf
message ListZonesRequest {
  bool internal = 1;
  uint32 limit = 2;
  uint32 offset = 3;
}

message ListZonesResponse {
  repeated Zone zones = 1;
  uint32 total = 2;
  uint32 limit = 3;
  uint32 offset = 4;
}
```

## Record Operations

### AddRecord

```protobuf
message AddRecordRequest {
  string zone_name = 1;
  string type = 2;
  string name = 3;
  string value = 4;
  uint32 ttl = 5;
  uint32 priority = 6;  // MX, SRV
  uint32 weight = 7;    // SRV
  uint32 port = 8;      // SRV
  string target = 9;    // SRV
}

message Record {
  string type = 1;
  string name = 2;
  string value = 3;
  uint32 ttl = 4;
  uint32 priority = 5;
  uint32 weight = 6;
  uint32 port = 7;
  string target = 8;
}
```

**Go Example:**
```go
record, err := client.AddRecord(ctx, &dns.AddRecordRequest{
    ZoneName: "myzone.internal.",
    Type:     "A",
    Name:     "server01",
    Value:    "192.168.1.100",
    Ttl:      3600,
})
```

### GetRecord

```protobuf
message GetRecordRequest {
  string zone_name = 1;
  string type = 2;
  string name = 3;
}
```

### UpdateRecord

```protobuf
message UpdateRecordRequest {
  string zone_name = 1;
  string type = 2;
  string name = 3;
  string value = 4;
  uint32 ttl = 5;
}
```

### DeleteRecord

```protobuf
message DeleteRecordRequest {
  string zone_name = 1;
  string type = 2;
  string name = 3;
}

message DeleteRecordResponse {
  bool deleted = 1;
  string type = 2;
  string name = 3;
}
```

### ListRecords

```protobuf
message ListRecordsRequest {
  string zone_name = 1;
  string type = 2;  // optional filter
}

message ListRecordsResponse {
  string zone_name = 1;
  RecordSet records = 2;
}
```

## TLSA/DANE

### AddTLSARecord

```protobuf
message AddTLSARecordRequest {
  string zone_name = 1;
  string name = 2;
  uint32 usage = 3;
  uint32 selector = 4;
  uint32 matching_type = 5;
  bytes certificate = 6;
  uint32 ttl = 7;
}

message TLSARecord {
  string name = 1;
  uint32 usage = 2;
  uint32 selector = 3;
  uint32 matching_type = 4;
  string certificate_data = 5;
  uint32 ttl = 6;
}
```

**Go Example:**
```go
tlsa, err := client.AddTLSARecord(ctx, &dns.AddTLSARecordRequest{
    ZoneName:     "example.com.",
    Name:         "_443._tcp.www",
    Usage:        3,
    Selector:     1,
    MatchingType: 1,
    Certificate:  certData,
    Ttl:          3600,
})
```

## Resolution

### Resolve

```protobuf
message ResolveRequest {
  string fqdn = 1;
  RecordType type = 2;
}

message ResolveResponse {
  repeated Record records = 1;
  bool authoritative = 2;
}
```

`fqdn` is required (`InvalidArgument` without it); `RECORD_TYPE_UNSPECIFIED`
returns every type. The longest managed zone suffix of `fqdn` answers with
only the records `fqdn` owns ([resolution.md](resolution.md#api-resolve)).
With no records, `authoritative` is `true` inside a managed zone and `false`
outside every one. A type resolution does not serve (SOA, the DNSSEC types) is
`InvalidArgument`.

**Go Example:**
```go
resp, err := client.Resolve(ctx, &platformv1.ResolveRequest{
    Fqdn: "ns1.example.internal.",
    Type: platformv1.RecordType_RECORD_TYPE_A,
})
```

## Message Types

```protobuf
message RecordSet {
  SOARecord soa = 1;
  repeated ARecord a = 2;
  repeated AAAARecord aaaa = 3;
  repeated CNAMERecord cname = 4;
  repeated MXRecord mx = 5;
  repeated NSRecord ns = 6;
  repeated SRVRecord srv = 7;
  repeated TXTRecord txt = 8;
  repeated TLSARecord tlsa = 9;
}

message SOARecord {
  string name = 1;
  string mname = 2;
  string rname = 3;
  uint32 serial = 4;
  uint32 refresh = 5;
  uint32 retry = 6;
  uint32 expire = 7;
  uint32 min_ttl = 8;
  uint32 ttl = 9;
}

message ARecord {
  string name = 1;
  string value = 2;
  uint32 ttl = 3;
}

message AAAARecord {
  string name = 1;
  string value = 2;
  uint32 ttl = 3;
}

message MXRecord {
  string name = 1;
  string value = 2;
  uint32 priority = 3;
  uint32 ttl = 4;
}

message SRVRecord {
  string name = 1;
  string target = 2;
  uint32 port = 3;
  uint32 priority = 4;
  uint32 weight = 5;
  uint32 ttl = 6;
}
```

## Error Handling

gRPC status codes map to DNS errors:

| gRPC Code | DNS Error |
|-----------|-----------|
| `NOT_FOUND` | zone_not_found, record_not_found |
| `ALREADY_EXISTS` | zone_already_exists, record_already_exists |
| `INVALID_ARGUMENT` | invalid_zone_name, invalid_ip_address |
| `UNAUTHENTICATED` | unauthorized |
| `PERMISSION_DENIED` | forbidden |

**Go Example:**
```go
zone, err := client.GetZone(ctx, req)
if err != nil {
    if status.Code(err) == codes.NotFound {
        // Handle zone not found
    }
}
```

## Client Setup

```go
import (
    "crypto/tls"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
    dns "github.com/trusted-platform/api/dns/v1"
)

func NewDNSClient(addr string, tlsConfig *tls.Config) (dns.DNSServiceClient, error) {
    creds := credentials.NewTLS(tlsConfig)
    conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(creds))
    if err != nil {
        return nil, err
    }
    return dns.NewDNSServiceClient(conn), nil
}
```
