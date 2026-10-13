# gRPC API Reference

gRPC API documentation for the Trusted Platform daemon.

## Connection

```
localhost:9443 (TCP)
/run/platformd.sock (Unix Socket)
```

## Service Definition

```protobuf
service PlatformDaemon {
  rpc GetHealth(GetHealthRequest) returns (GetHealthResponse);
  rpc GetStatus(GetStatusRequest) returns (GetStatusResponse);
  rpc ListServices(ListServicesRequest) returns (ListServicesResponse);
  rpc StartService(StartServiceRequest) returns (StartServiceResponse);
  rpc StopService(StopServiceRequest) returns (StopServiceResponse);
  rpc Shutdown(ShutdownRequest) returns (ShutdownResponse);
}
```

## Methods

### GetHealth

Returns system health status.

**Request:**
```protobuf
message GetHealthRequest {}
```

**Response:**
```protobuf
message GetHealthResponse {
  HealthStatus status = 1;
  repeated ComponentHealth components = 2;
  google.protobuf.Timestamp timestamp = 3;
}

enum HealthStatus {
  HEALTH_STATUS_UNSPECIFIED = 0;
  HEALTH_STATUS_HEALTHY = 1;
  HEALTH_STATUS_UNHEALTHY = 2;
  HEALTH_STATUS_DEGRADED = 3;
}

message ComponentHealth {
  string name = 1;
  HealthStatus status = 2;
  string message = 3;
  google.protobuf.Timestamp last_checked = 4;
}
```

---

### GetStatus

Returns detailed daemon status.

**Request:**
```protobuf
message GetStatusRequest {}
```

**Response:**
```protobuf
message GetStatusResponse {
  string status = 1;
  string version = 2;
  string build_time = 3;
  string git_commit = 4;
  SystemInfo system = 5;
  google.protobuf.Timestamp timestamp = 6;
}

message SystemInfo {
  string os = 1;
  string arch = 2;
  int32 num_cpus = 3;
  uint64 total_memory_mb = 4;
  uint64 available_memory_mb = 5;
  string uptime = 6;
}
```

---

### ListServices

Lists all managed services.

**Request:**
```protobuf
message ListServicesRequest {}
```

**Response:**
```protobuf
message ListServicesResponse {
  repeated ServiceInfo services = 1;
  int32 count = 2;
}

message ServiceInfo {
  string name = 1;
  ServiceStatus status = 2;
  google.protobuf.Timestamp started_at = 3;
  string uptime = 4;
  uint64 start_count = 5;
  uint64 stop_count = 6;
  string last_error = 7;
}

enum ServiceStatus {
  SERVICE_STATUS_UNSPECIFIED = 0;
  SERVICE_STATUS_STOPPED = 1;
  SERVICE_STATUS_STARTING = 2;
  SERVICE_STATUS_RUNNING = 3;
  SERVICE_STATUS_STOPPING = 4;
  SERVICE_STATUS_ERROR = 5;
}
```

---

### StartService

Starts a stopped service.

**Request:**
```protobuf
message StartServiceRequest {
  ServiceType service = 1;
}

enum ServiceType {
  SERVICE_TYPE_UNSPECIFIED = 0;
  SERVICE_TYPE_TPM = 1;
  SERVICE_TYPE_SDN = 2;
  SERVICE_TYPE_COMPUTE = 3;
  SERVICE_TYPE_DNS = 4;
  SERVICE_TYPE_ACME = 5;
  SERVICE_TYPE_WEBSERVICE = 6;
  SERVICE_TYPE_ATTESTATION = 7;
  SERVICE_TYPE_KMS = 8;
  SERVICE_TYPE_VTPM = 9;
  SERVICE_TYPE_CA = 10;
  SERVICE_TYPE_MCP = 11;
}
```

**Response:**
```protobuf
message StartServiceResponse {
  bool success = 1;
  string message = 2;
}
```

---

### StopService

Stops a running service.

**Request:**
```protobuf
message StopServiceRequest {
  ServiceType service = 1;
}
```

**Response:**
```protobuf
message StopServiceResponse {
  bool success = 1;
  string message = 2;
}
```

---

### Shutdown

Initiates daemon shutdown.

**Request:**
```protobuf
message ShutdownRequest {
  bool graceful = 1;
  uint32 timeout_seconds = 2;
}
```

**Response:**
```protobuf
message ShutdownResponse {
  bool success = 1;
  string message = 2;
}
```

## Additional Services

When enabled, the daemon also exposes:

### CA Service

```protobuf
service CAService {
  rpc GetCAInfo(GetCAInfoRequest) returns (GetCAInfoResponse);
  rpc IssueCertificate(IssueCertificateRequest) returns (IssueCertificateResponse);
  rpc GetCertificate(GetCertificateRequest) returns (GetCertificateResponse);
  rpc ListCertificates(ListCertificatesRequest) returns (ListCertificatesResponse);
  rpc RevokeCertificate(RevokeCertificateRequest) returns (RevokeCertificateResponse);
  rpc RenewCertificate(RenewCertificateRequest) returns (RenewCertificateResponse);
  rpc VerifyCertificate(VerifyCertificateRequest) returns (VerifyCertificateResponse);
  rpc GetCRL(GetCRLRequest) returns (GetCRLResponse);
  rpc GetCABundle(GetCABundleRequest) returns (GetCABundleResponse);
}
```

### vTPM Service

```protobuf
service VTPMService {
  rpc CreateBundle(CreateBundleRequest) returns (CreateBundleResponse);
  rpc GetBundle(GetBundleRequest) returns (GetBundleResponse);
  rpc ListBundles(ListBundlesRequest) returns (ListBundlesResponse);
  rpc DeleteBundle(DeleteBundleRequest) returns (DeleteBundleResponse);
}
```

### Device Service

```protobuf
service DeviceService {
  rpc RegisterDevice(RegisterDeviceRequest) returns (RegisterDeviceResponse);
  rpc GetDevice(GetDeviceRequest) returns (GetDeviceResponse);
  rpc ListDevices(ListDevicesRequest) returns (ListDevicesResponse);
  rpc DeleteDevice(DeleteDeviceRequest) returns (DeleteDeviceResponse);
  rpc UpdateDevice(UpdateDeviceRequest) returns (UpdateDeviceResponse);
}
```

## Error Handling

gRPC errors use standard status codes:

| Code | Status | Description |
|------|--------|-------------|
| 0 | OK | Success |
| 3 | INVALID_ARGUMENT | Invalid request parameters |
| 5 | NOT_FOUND | Resource not found |
| 6 | ALREADY_EXISTS | Resource already exists |
| 7 | PERMISSION_DENIED | Access denied |
| 13 | INTERNAL | Internal error |
| 14 | UNAVAILABLE | Service unavailable |
| 16 | UNAUTHENTICATED | Authentication required |

## Examples

### grpcurl

The TCP listener always serves TLS (#32 — plaintext gRPC is refused at
startup), so TCP examples pass the platform CA bundle. Only the Unix socket
accepts `-plaintext`.

```bash
# List methods
grpcurl -cacert /etc/trusted-platform/certs/ca-bundle.pem localhost:9443 list

# Health probe (the only RPC served without a token)
grpcurl -cacert /etc/trusted-platform/certs/ca-bundle.pem localhost:9443 \
  grpc.health.v1.Health/Check

# Component health: needs a token holding platform:read. Every TCP call
# below needs the same authorization header.
grpcurl -cacert /etc/trusted-platform/certs/ca-bundle.pem \
  -H "authorization: Bearer $TOKEN" localhost:9443 \
  platform.v1.PlatformDaemon/GetHealth

# Get status
grpcurl -cacert /etc/trusted-platform/certs/ca-bundle.pem localhost:9443 \
  platform.v1.PlatformDaemon/GetStatus

# List services
grpcurl -cacert /etc/trusted-platform/certs/ca-bundle.pem localhost:9443 \
  platform.v1.PlatformDaemon/ListServices

# Start service
grpcurl -cacert /etc/trusted-platform/certs/ca-bundle.pem \
  -d '{"service": "SERVICE_TYPE_DNS"}' \
  localhost:9443 platform.v1.PlatformDaemon/StartService

# Stop service
grpcurl -cacert /etc/trusted-platform/certs/ca-bundle.pem \
  -d '{"service": "SERVICE_TYPE_DNS"}' \
  localhost:9443 platform.v1.PlatformDaemon/StopService

# Via Unix socket (the sanctioned non-TLS carve-out)
grpcurl -plaintext -unix /run/platformd.sock \
  platform.v1.PlatformDaemon/GetHealth
```

### Go Client

```go
package main

import (
    "context"
    "log"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"

    platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func main() {
    // TCP connection — the listener always serves TLS (#32), so the
    // client verifies against the platform CA bundle. Plaintext
    // credentials are accepted only on the Unix socket (see below).
    creds, err := credentials.NewClientTLSFromFile(
        "/etc/trusted-platform/certs/ca-bundle.pem", "")
    if err != nil {
        log.Fatal(err)
    }
    conn, err := grpc.Dial("localhost:9443",
        grpc.WithTransportCredentials(creds))
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    client := platformv1.NewPlatformDaemonClient(conn)

    // Health check
    health, err := client.GetHealth(context.Background(),
        &platformv1.GetHealthRequest{})
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Health: %v", health.Status)

    // List services
    services, err := client.ListServices(context.Background(),
        &platformv1.ListServicesRequest{})
    if err != nil {
        log.Fatal(err)
    }
    for _, svc := range services.Services {
        log.Printf("Service: %s, Status: %v", svc.Name, svc.Status)
    }
}
```

### Unix Socket Connection

```go
import (
    "context"
    "net"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
)

func connectUnix() (*grpc.ClientConn, error) {
    return grpc.Dial(
        "unix:///run/platformd.sock",
        grpc.WithTransportCredentials(insecure.NewCredentials()),
        grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
            return net.Dial("unix", "/run/platformd.sock")
        }),
    )
}
```

### Python Client

```python
import grpc
import platform_pb2
import platform_pb2_grpc

# Create channel — the TCP listener always serves TLS (#32)
with open('/etc/trusted-platform/certs/ca-bundle.pem', 'rb') as f:
    creds = grpc.ssl_channel_credentials(root_certificates=f.read())
channel = grpc.secure_channel('localhost:9443', creds)
stub = platform_pb2_grpc.PlatformDaemonStub(channel)

# Health check
response = stub.GetHealth(platform_pb2.GetHealthRequest())
print(f"Health: {response.status}")

# List services
response = stub.ListServices(platform_pb2.ListServicesRequest())
for svc in response.services:
    print(f"Service: {svc.name}, Status: {svc.status}")
```

## TLS Configuration

For secure connections:

```go
import (
    "crypto/tls"
    "google.golang.org/grpc/credentials"
)

// Client with TLS
creds := credentials.NewTLS(&tls.Config{
    // Configure TLS
})

conn, err := grpc.Dial("localhost:9443",
    grpc.WithTransportCredentials(creds))
```

Or with mTLS:

```go
cert, _ := tls.LoadX509KeyPair("client.crt", "client.key")
caCert, _ := os.ReadFile("ca.crt")

certPool := x509.NewCertPool()
certPool.AppendCertsFromPEM(caCert)

creds := credentials.NewTLS(&tls.Config{
    Certificates: []tls.Certificate{cert},
    RootCAs:      certPool,
})
```

## See Also

- [API Reference](api-reference.md)
- [Configuration](configuration.md)
- [Architecture](architecture.md)
