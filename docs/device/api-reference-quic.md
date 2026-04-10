# Device QUIC API Reference

Endpoint: `localhost:9444` (UDP)

## Overview

The Device API over QUIC provides low-latency, multiplexed access to device and profile operations. QUIC transport is ideal for mobile clients and high-frequency attestation requests.

## Connection

```go
import (
    "context"
    "crypto/tls"

    "github.com/quic-go/quic-go"
)

tlsConf := &tls.Config{
    RootCAs:    caCertPool,
    NextProtos: []string{"device-api"},
}

conn, _ := quic.DialAddr(context.Background(), "localhost:9444", tlsConf, nil)
stream, _ := conn.OpenStreamSync(context.Background())
```

## Message Format

QUIC messages use length-prefixed protobuf encoding:

```
+----------------+------------------+
| Length (4B BE) | Protobuf Payload |
+----------------+------------------+
```

Request header:
```protobuf
message RequestHeader {
  string method = 1;      // e.g., "RegisterDevice"
  string request_id = 2;  // Correlation ID
}
```

## Device Operations

### RegisterDevice

```protobuf
// Request
message RegisterDeviceRequest {
  string serial = 1;
  string model = 2;
  string ek_cert = 3;
  string attest_pub = 4;
  string signing_pub = 5;
  uint32 hash_algo_id = 6;
}

// Response
message RegisterDeviceResponse {
  Device device = 1;
}
```

### GetDevice

```protobuf
message GetDeviceRequest {
  uint64 id = 1;
}

message GetDeviceResponse {
  Device device = 1;
}
```

### UpdateDevice

```protobuf
message UpdateDeviceRequest {
  Device device = 1;
}

message UpdateDeviceResponse {
  Device device = 1;
}
```

### DeleteDevice

```protobuf
message DeleteDeviceRequest {
  uint64 id = 1;
}

message DeleteDeviceResponse {
  bool success = 1;
}
```

### ListDevices

```protobuf
message ListDevicesRequest {
  int32 page = 1;
  int32 page_size = 2;
  string sort_order = 3;
}

message ListDevicesResponse {
  repeated Device devices = 1;
  int32 total_count = 2;
  int32 total_pages = 3;
}
```

### FindBySerial

```protobuf
message FindDeviceBySerialRequest {
  string serial = 1;
}

message FindDeviceBySerialResponse {
  Device device = 1;
}
```

### AttestDevice

```protobuf
message AttestDeviceRequest {
  uint64 device_id = 1;
  bytes nonce = 2;
  bytes quote = 3;
  bytes signature = 4;
  map<uint32, bytes> pcrs = 5;
}

message AttestDeviceResponse {
  bool verified = 1;
  uint64 device_id = 2;
  int64 attestation_time = 3;
}
```

## Profile Operations

### CreateProfile

```protobuf
message CreateProfileRequest {
  string name = 1;
  string model = 2;
  string role = 3;
  ProfileMatchRules match_rules = 4;
  NetworkPhaseConfig provisioning_network = 5;
  NetworkPhaseConfig production_network = 6;
  NetworkPhaseConfig quarantine_network = 7;
}

message CreateProfileResponse {
  DeviceProfile profile = 1;
}
```

### GetProfile

```protobuf
message GetProfileRequest {
  uint64 id = 1;
}

message GetProfileResponse {
  DeviceProfile profile = 1;
}
```

### FindMatchingProfile

```protobuf
message FindMatchingProfileRequest {
  string mac_address = 1;
  string serial = 2;
  string model = 3;
}

message FindMatchingProfileResponse {
  DeviceProfile profile = 1;
}
```

### FindProfileByMACAddress

```protobuf
message FindProfileByMACRequest {
  string mac_prefix = 1;
}

message FindProfileByMACResponse {
  DeviceProfile profile = 1;
}
```

### FindProfileBySerial

```protobuf
message FindProfileBySerialRequest {
  string serial_prefix = 1;
}

message FindProfileBySerialResponse {
  DeviceProfile profile = 1;
}
```

## Go Client Example

```go
package main

import (
    "context"
    "crypto/tls"
    "encoding/binary"

    "github.com/quic-go/quic-go"
    "google.golang.org/protobuf/proto"
)

func main() {
    tlsConf := &tls.Config{
        RootCAs:    loadCACertPool(),
        NextProtos: []string{"device-api"},
    }

    conn, _ := quic.DialAddr(context.Background(), "localhost:9444", tlsConf, nil)
    defer conn.CloseWithError(0, "")

    stream, _ := conn.OpenStreamSync(context.Background())

    // Build request
    req := &RegisterDeviceRequest{
        Serial: "SRV-2024-001",
        Model:  "TrustedServer-v2",
    }
    data, _ := proto.Marshal(req)

    // Send length-prefixed message
    length := make([]byte, 4)
    binary.BigEndian.PutUint32(length, uint32(len(data)))
    stream.Write(length)
    stream.Write(data)

    // Read response
    stream.Read(length)
    respLen := binary.BigEndian.Uint32(length)
    respData := make([]byte, respLen)
    stream.Read(respData)

    var resp RegisterDeviceResponse
    proto.Unmarshal(respData, &resp)
}
```

## Stream Multiplexing

QUIC allows multiple concurrent streams per connection:

```go
// Parallel device lookups
for _, serial := range serials {
    go func(s string) {
        stream, _ := conn.OpenStreamSync(ctx)
        defer stream.Close()
        // Send FindBySerial request
    }(serial)
}
```

## Connection Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| MaxIdleTimeout | 30s | Connection idle timeout |
| MaxIncomingStreams | 100 | Max concurrent streams |
| MaxIncomingUniStreams | 100 | Max unidirectional streams |
| InitialStreamReceiveWindow | 512KB | Initial flow control |

## Error Handling

QUIC uses application error codes:

| Code | Description |
|------|-------------|
| 0x00 | No error |
| 0x01 | Protocol error |
| 0x02 | Internal error |
| 0x03 | Not found |
| 0x04 | Invalid argument |
| 0x05 | Already exists |

See [api-reference.md](api-reference.md) for complete error code mapping.
