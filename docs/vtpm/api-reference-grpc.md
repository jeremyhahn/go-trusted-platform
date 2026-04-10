# vTPM gRPC API Reference

Package: `platform.v1`
Service: `VTPMService`
Port: `9443`

## Service Definition

```protobuf
service VTPMService {
  // Bundle CRUD
  rpc CreateBundle(CreateBundleRequest) returns (CreateBundleResponse);
  rpc GetBundle(GetBundleRequest) returns (GetBundleResponse);
  rpc DeleteBundle(DeleteBundleRequest) returns (DeleteBundleResponse);
  rpc ListBundles(ListBundlesRequest) returns (ListBundlesResponse);

  // Template operations
  rpc CreateTemplate(CreateTemplateRequest) returns (CreateTemplateResponse);
  rpc GetTemplate(GetTemplateRequest) returns (GetTemplateResponse);
  rpc DeleteTemplate(DeleteTemplateRequest) returns (DeleteTemplateResponse);
  rpc ListTemplates(ListTemplatesRequest) returns (ListTemplatesResponse);
  rpc CloneTemplate(CloneTemplateRequest) returns (CloneTemplateResponse);

  // Export/Import (streaming)
  rpc ExportBundle(ExportBundleRequest) returns (stream ExportBundleResponse);
  rpc ImportBundle(stream ImportBundleRequest) returns (ImportBundleResponse);

  // Validation
  rpc ValidateBundle(ValidateBundleRequest) returns (ValidateBundleResponse);

  // Path getters
  rpc GetBundlePath(GetBundlePathRequest) returns (GetBundlePathResponse);
  rpc GetTPMSocketPath(GetTPMSocketPathRequest) returns (GetTPMSocketPathResponse);
  rpc GetNVRAMPath(GetNVRAMPathRequest) returns (GetNVRAMPathResponse);
}
```

## Enums

```protobuf
enum BundleMode {
  BUNDLE_MODE_UNSPECIFIED = 0;
  BUNDLE_MODE_TEMPLATE = 1;
  BUNDLE_MODE_PRE_ASSIGNED = 2;
}

enum EKAlgorithm {
  EK_ALGORITHM_UNSPECIFIED = 0;
  EK_ALGORITHM_RSA = 1;
  EK_ALGORITHM_ECC = 2;
}
```

## Bundle Methods

### CreateBundle

```protobuf
message CreateBundleRequest {
  CreateBundleOptions options = 1;
}

message CreateBundleOptions {
  BundleMode mode = 1;
  string hostname = 2;
  EKAlgorithm ek_algorithm = 3;
  bool secure_boot_enabled = 4;
  map<string, string> labels = 5;
  string template_id = 6;
}

message CreateBundleResponse {
  Status status = 1;
  Bundle bundle = 2;
}
```

**Go Example:**
```go
client := platformv1.NewVTPMServiceClient(conn)

resp, err := client.CreateBundle(ctx, &platformv1.CreateBundleRequest{
    Options: &platformv1.CreateBundleOptions{
        Mode:              platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED,
        Hostname:          "vm001.example.com",
        EkAlgorithm:       platformv1.EKAlgorithm_EK_ALGORITHM_RSA,
        SecureBootEnabled: true,
        Labels:            map[string]string{"env": "prod"},
    },
})
```

### GetBundle

```protobuf
message GetBundleRequest {
  string id = 1;
}

message GetBundleResponse {
  Bundle bundle = 1;
}
```

### DeleteBundle

```protobuf
message DeleteBundleRequest {
  string id = 1;
}

message DeleteBundleResponse {
  Status status = 1;
}
```

### ListBundles

```protobuf
message ListBundlesRequest {
  ListBundleOptions options = 1;
}

message ListBundleOptions {
  BundleMode mode = 1;
  map<string, string> labels = 2;
  int32 limit = 3;
  int32 offset = 4;
}

message ListBundlesResponse {
  repeated Bundle bundles = 1;
  int32 total = 2;
}
```

## Template Methods

### CreateTemplate

```protobuf
message CreateTemplateRequest {
  CreateTemplateOptions options = 1;
}

message CreateTemplateOptions {
  string id = 1;
  string description = 2;
  EKAlgorithm ek_algorithm = 3;
  bool secure_boot_enabled = 4;
}

message CreateTemplateResponse {
  Status status = 1;
  Template template = 2;
}
```

### CloneTemplate

```protobuf
message CloneTemplateRequest {
  CloneOptions options = 1;
}

message CloneOptions {
  string template_id = 1;
  string hostname = 2;
  map<string, string> labels = 3;
}

message CloneTemplateResponse {
  Status status = 1;
  Bundle bundle = 2;
}
```

## Export/Import (Streaming)

### ExportBundle

Server streams tar.gz chunks to client.

```protobuf
message ExportBundleRequest {
  string id = 1;
}

message ExportBundleResponse {
  bytes data = 1;  // Chunk of tar.gz archive
}
```

**Go Example:**
```go
stream, err := client.ExportBundle(ctx, &platformv1.ExportBundleRequest{Id: bundleID})
if err != nil {
    return err
}

file, _ := os.Create("bundle.tar.gz")
defer file.Close()

for {
    resp, err := stream.Recv()
    if err == io.EOF {
        break
    }
    if err != nil {
        return err
    }
    file.Write(resp.Data)
}
```

### ImportBundle

Client streams tar.gz chunks to server.

```protobuf
message ImportBundleRequest {
  bytes data = 1;  // Chunk of tar.gz archive
}

message ImportBundleResponse {
  Status status = 1;
  Bundle bundle = 2;
}
```

## Validation

```protobuf
message ValidateBundleRequest {
  string id = 1;
}

message ValidateBundleResponse {
  Status status = 1;
  bool valid = 2;
  repeated string errors = 3;
}
```

## Path Getters

```protobuf
message GetBundlePathRequest {
  string id = 1;
}
message GetBundlePathResponse {
  string path = 1;
}

message GetTPMSocketPathRequest {
  string id = 1;
}
message GetTPMSocketPathResponse {
  string path = 1;
}

message GetNVRAMPathRequest {
  string id = 1;
}
message GetNVRAMPathResponse {
  string path = 1;
}
```

## Connection Example

```go
import (
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
    platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen/platform/v1"
)

// TLS connection
creds, err := credentials.NewClientTLSFromFile("ca.crt", "")
if err != nil {
    return err
}

conn, err := grpc.Dial("localhost:9443", grpc.WithTransportCredentials(creds))
if err != nil {
    return err
}
defer conn.Close()

client := platformv1.NewVTPMServiceClient(conn)
```

## Error Handling

gRPC status codes:

| Code | Description |
|------|-------------|
| `NOT_FOUND` | Bundle or template not found |
| `ALREADY_EXISTS` | Bundle or template already exists |
| `INVALID_ARGUMENT` | Invalid request parameters |
| `INTERNAL` | Server error |

```go
resp, err := client.GetBundle(ctx, &platformv1.GetBundleRequest{Id: id})
if err != nil {
    if st, ok := status.FromError(err); ok {
        if st.Code() == codes.NotFound {
            // Handle not found
        }
    }
    return err
}
```
