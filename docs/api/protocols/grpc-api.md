# gRPC API Reference

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [daemon/api.md](../../daemon/api.md) and each feature's `api.md`.

The gRPC API provides high-performance, strongly-typed access to all platform services with support for bidirectional streaming.

## Connection Configuration

### Server Address

```
{host}:{port}
```

Default port: **10443**

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PLATFORM_GRPC_ADDR` | Full address | `localhost:10443` |
| `PLATFORM_GRPC_PORT` | Port number | `10443` |
| `PLATFORM_GRPC_TLS` | Enable TLS | `true` |

### Go SDK Configuration

```go
import _ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/grpc"

client, err := platform.NewClient(ctx,
    platform.WithGRPCAddr("platform.example.com:10443"),
    platform.WithTLSConfig(&tls.Config{
        MinVersion: tls.VersionTLS13,
        RootCAs:    certPool,
    }),
    platform.WithOnlyProtocol(platform.ProtocolGRPC),
    platform.WithTimeout(10*time.Second),
    platform.WithMaxMessageSize(8*1024*1024),
)
```

### Direct gRPC Connection

```go
import (
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
    platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

conn, err := grpc.DialContext(ctx, "platform.example.com:10443",
    grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
    grpc.WithDefaultCallOptions(
        grpc.MaxCallRecvMsgSize(4*1024*1024),
        grpc.MaxCallSendMsgSize(4*1024*1024),
    ),
)
defer conn.Close()

caClient := platformv1.NewCAServiceClient(conn)
```

## Authentication

### Token Metadata

```go
import "google.golang.org/grpc/metadata"

// Add token to outgoing context
ctx := metadata.AppendToOutgoingContext(ctx,
    "authorization", "Bearer "+token,
)

// Make authenticated call
response, err := client.CA().GetInfo(ctx, request)
```

### mTLS Authentication

```go
// Load client certificate
cert, _ := tls.LoadX509KeyPair("client.crt", "client.key")

// Load CA certificate
caCert, _ := os.ReadFile("ca.crt")
certPool := x509.NewCertPool()
certPool.AppendCertsFromPEM(caCert)

// Configure mTLS
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
    RootCAs:      certPool,
    MinVersion:   tls.VersionTLS13,
}

client, err := platform.NewClient(ctx,
    platform.WithGRPCAddr("platform.example.com:10443"),
    platform.WithTLSConfig(tlsConfig),
)
```

### Per-RPC Credentials

```go
type tokenAuth struct {
    token string
}

func (t tokenAuth) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
    return map[string]string{
        "authorization": "Bearer " + t.token,
    }, nil
}

func (t tokenAuth) RequireTransportSecurity() bool {
    return true
}

conn, err := grpc.DialContext(ctx, addr,
    grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
    grpc.WithPerRPCCredentials(tokenAuth{token: myToken}),
)
```

## Service Definitions

### Platform Daemon Service

```protobuf
service PlatformDaemon {
    // Get platform version
    rpc GetVersion(GetVersionRequest) returns (GetVersionResponse);

    // Get platform status
    rpc GetStatus(GetStatusRequest) returns (GetStatusResponse);

    // Health checks
    rpc Health(HealthRequest) returns (HealthResponse);
    rpc Liveness(LivenessRequest) returns (LivenessResponse);
    rpc Readiness(ReadinessRequest) returns (ReadinessResponse);
}
```

### CA Service

```protobuf
service CAService {
    // Certificate lifecycle
    rpc GetInfo(GetCAInfoRequest) returns (GetCAInfoResponse);
    rpc Issue(IssueCertificateRequest) returns (IssueCertificateResponse);
    rpc Get(GetCertificateRequest) returns (GetCertificateResponse);
    rpc List(ListCertificatesRequest) returns (ListCertificatesResponse);
    rpc Revoke(RevokeCertificateRequest) returns (RevokeCertificateResponse);
    rpc Renew(RenewCertificateRequest) returns (RenewCertificateResponse);
    rpc Verify(VerifyCertificateRequest) returns (VerifyCertificateResponse);

    // CA distribution
    rpc GetCRL(GetCRLRequest) returns (GetCRLResponse);
    rpc GetBundle(GetBundleRequest) returns (GetBundleResponse);
    rpc GetTrustRoot(GetTrustRootRequest) returns (GetTrustRootResponse);
}
```

### IAM Service

```protobuf
service PlatformIAMService {
    // User management
    rpc CreateUser(CreateUserRequest) returns (CreateUserResponse);
    rpc GetUser(GetUserRequest) returns (GetUserResponse);
    rpc ListUsers(ListUsersRequest) returns (ListUsersResponse);
    rpc DeleteUser(DeleteUserRequest) returns (DeleteUserResponse);
    rpc GetCurrentUser(GetCurrentUserRequest) returns (GetCurrentUserResponse);

    // Role management
    rpc CreateRole(CreateRoleRequest) returns (CreateRoleResponse);
    rpc GetRole(GetRoleRequest) returns (GetRoleResponse);
    rpc ListRoles(ListRolesRequest) returns (ListRolesResponse);
    rpc DeleteRole(DeleteRoleRequest) returns (DeleteRoleResponse);
    rpc AssignRole(AssignRoleRequest) returns (AssignRoleResponse);
    rpc RevokeRole(RevokeRoleRequest) returns (RevokeRoleResponse);

    // Authentication
    rpc Authenticate(AuthenticateRequest) returns (AuthenticateResponse);
    rpc CreateToken(CreateTokenRequest) returns (CreateTokenResponse);
    rpc VerifyToken(VerifyTokenRequest) returns (VerifyTokenResponse);
    rpc RefreshToken(RefreshTokenRequest) returns (RefreshTokenResponse);
    rpc RevokeToken(RevokeTokenRequest) returns (RevokeTokenResponse);

    // Authorization
    rpc CheckPermission(CheckPermissionRequest) returns (CheckPermissionResponse);

    // MFA
    rpc SetupTOTP(SetupTOTPRequest) returns (SetupTOTPResponse);
    rpc VerifyTOTP(VerifyTOTPRequest) returns (VerifyTOTPResponse);
    rpc DisableTOTP(DisableTOTPRequest) returns (DisableTOTPResponse);
}
```

### KMS Service

```protobuf
service KeyManagementService {
    // Key lifecycle
    rpc CreateKey(CreateKeyRequest) returns (CreateKeyResponse);
    rpc GetKey(GetKeyRequest) returns (GetKeyResponse);
    rpc ListKeys(ListKeysRequest) returns (ListKeysResponse);
    rpc DeleteKey(DeleteKeyRequest) returns (DeleteKeyResponse);
    rpc RotateKey(RotateKeyRequest) returns (RotateKeyResponse);

    // Cryptographic operations
    rpc Encrypt(EncryptRequest) returns (EncryptResponse);
    rpc Decrypt(DecryptRequest) returns (DecryptResponse);
    rpc Sign(SignRequest) returns (SignResponse);
    rpc Verify(VerifyRequest) returns (VerifyResponse);

    // Key derivation
    rpc GenerateRandom(GenerateRandomRequest) returns (GenerateRandomResponse);
    rpc GenerateDataKey(GenerateDataKeyRequest) returns (GenerateDataKeyResponse);
    rpc GenerateWrappedDataKey(GenerateWrappedDataKeyRequest) returns (GenerateWrappedDataKeyResponse);
}
```

### vTPM Service

```protobuf
service VTPMService {
    // Lifecycle management
    rpc Create(CreateVTPMRequest) returns (CreateVTPMResponse);
    rpc Delete(DeleteVTPMRequest) returns (DeleteVTPMResponse);
    rpc Start(StartVTPMRequest) returns (StartVTPMResponse);
    rpc Stop(StopVTPMRequest) returns (StopVTPMResponse);
    rpc List(ListVTPMRequest) returns (ListVTPMResponse);
    rpc GetState(GetVTPMStateRequest) returns (GetVTPMStateResponse);

    // TPM operations
    rpc Quote(VTPMQuoteRequest) returns (VTPMQuoteResponse);
    rpc Seal(VTPMSealRequest) returns (VTPMSealResponse);
    rpc Unseal(VTPMUnsealRequest) returns (VTPMUnsealResponse);
    rpc ExtendPCR(ExtendPCRRequest) returns (ExtendPCRResponse);
    rpc ReadPCR(ReadPCRRequest) returns (ReadPCRResponse);
}
```

### Attestation Service

```protobuf
service AttestationService {
    // Quote operations
    rpc GetQuote(GetQuoteRequest) returns (GetQuoteResponse);
    rpc VerifyQuote(VerifyQuoteRequest) returns (VerifyQuoteResponse);

    // Key retrieval
    rpc GetEK(GetEKRequest) returns (GetEKResponse);
    rpc GetAK(GetAKRequest) returns (GetAKResponse);
    rpc CreateAK(CreateAKRequest) returns (CreateAKResponse);

    // Challenge-response
    rpc ChallengeAK(ChallengeAKRequest) returns (ChallengeAKResponse);
    rpc VerifyChallenge(VerifyChallengeRequest) returns (VerifyChallengeResponse);
}
```

## Streaming Operations

### Server Streaming Example

```go
// Stream certificate events
stream, err := client.CA().WatchCertificates(ctx, &platformv1.WatchCertificatesRequest{
    Filter: "status=revoked",
})
if err != nil {
    log.Fatal(err)
}

for {
    event, err := stream.Recv()
    if err == io.EOF {
        break
    }
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Certificate event: %s %s", event.Type, event.Serial)
}
```

### Client Streaming Example

```go
// Batch certificate verification
stream, err := client.CA().VerifyBatch(ctx)
if err != nil {
    log.Fatal(err)
}

for _, cert := range certificates {
    if err := stream.Send(&platformv1.VerifyCertificateRequest{
        Certificate: cert,
    }); err != nil {
        log.Fatal(err)
    }
}

response, err := stream.CloseAndRecv()
if err != nil {
    log.Fatal(err)
}
log.Printf("Verified %d certificates", response.ValidCount)
```

### Bidirectional Streaming Example

```go
// Interactive attestation session
stream, err := client.Attestation().InteractiveAttest(ctx)
if err != nil {
    log.Fatal(err)
}

// Send initial request
stream.Send(&platformv1.AttestRequest{
    Phase: platformv1.Phase_INIT,
})

// Process challenge-response
for {
    response, err := stream.Recv()
    if err == io.EOF {
        break
    }
    if err != nil {
        log.Fatal(err)
    }

    if response.Phase == platformv1.Phase_COMPLETE {
        log.Printf("Attestation successful: %v", response.Result)
        break
    }

    // Send challenge response
    stream.Send(&platformv1.AttestRequest{
        Phase:    response.Phase,
        Response: computeResponse(response.Challenge),
    })
}
```

## Error Codes Mapping

### gRPC Status Codes

| gRPC Code | HTTP Equivalent | Description |
|-----------|-----------------|-------------|
| `OK` (0) | 200 | Success |
| `CANCELLED` (1) | 499 | Request cancelled |
| `UNKNOWN` (2) | 500 | Unknown error |
| `INVALID_ARGUMENT` (3) | 400 | Invalid request |
| `DEADLINE_EXCEEDED` (4) | 504 | Timeout |
| `NOT_FOUND` (5) | 404 | Resource not found |
| `ALREADY_EXISTS` (6) | 409 | Resource exists |
| `PERMISSION_DENIED` (7) | 403 | Access denied |
| `RESOURCE_EXHAUSTED` (8) | 429 | Rate limited |
| `FAILED_PRECONDITION` (9) | 400 | State error |
| `ABORTED` (10) | 409 | Operation aborted |
| `OUT_OF_RANGE` (11) | 400 | Out of range |
| `UNIMPLEMENTED` (12) | 501 | Not implemented |
| `INTERNAL` (13) | 500 | Internal error |
| `UNAVAILABLE` (14) | 503 | Service unavailable |
| `DATA_LOSS` (15) | 500 | Data loss |
| `UNAUTHENTICATED` (16) | 401 | Not authenticated |

### Error Handling

```go
import (
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/status"
)

response, err := client.CA().Issue(ctx, request)
if err != nil {
    st, ok := status.FromError(err)
    if !ok {
        log.Fatalf("Non-gRPC error: %v", err)
    }

    switch st.Code() {
    case codes.InvalidArgument:
        log.Printf("Invalid request: %s", st.Message())
        // Parse details for field-level errors
        for _, detail := range st.Details() {
            if br, ok := detail.(*errdetails.BadRequest); ok {
                for _, violation := range br.FieldViolations {
                    log.Printf("Field %s: %s", violation.Field, violation.Description)
                }
            }
        }
    case codes.PermissionDenied:
        log.Printf("Access denied: %s", st.Message())
    case codes.Unavailable:
        log.Printf("Service unavailable, retrying...")
        // Implement retry logic
    default:
        log.Printf("Error: %s", st.Message())
    }
}
```

## Connection Management

### Connection Pooling

```go
// Create connection pool with round-robin load balancing
conn, err := grpc.DialContext(ctx, "dns:///platform.example.com:10443",
    grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
    grpc.WithDefaultServiceConfig(`{
        "loadBalancingPolicy": "round_robin",
        "healthCheckConfig": {"serviceName": ""}
    }`),
)
```

### Keepalive Configuration

```go
import "google.golang.org/grpc/keepalive"

conn, err := grpc.DialContext(ctx, addr,
    grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
    grpc.WithKeepaliveParams(keepalive.ClientParameters{
        Time:                10 * time.Second,
        Timeout:             5 * time.Second,
        PermitWithoutStream: true,
    }),
)
```

### Retry Configuration

```go
retryPolicy := `{
    "methodConfig": [{
        "name": [{"service": "platformv1.CAService"}],
        "retryPolicy": {
            "maxAttempts": 5,
            "initialBackoff": "0.1s",
            "maxBackoff": "5s",
            "backoffMultiplier": 2,
            "retryableStatusCodes": ["UNAVAILABLE", "RESOURCE_EXHAUSTED"]
        }
    }]
}`

conn, err := grpc.DialContext(ctx, addr,
    grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
    grpc.WithDefaultServiceConfig(retryPolicy),
)
```

## Interceptors

### Unary Client Interceptor

```go
func loggingInterceptor(
    ctx context.Context,
    method string,
    req, reply interface{},
    cc *grpc.ClientConn,
    invoker grpc.UnaryInvoker,
    opts ...grpc.CallOption,
) error {
    start := time.Now()
    err := invoker(ctx, method, req, reply, cc, opts...)
    duration := time.Since(start)

    log.Printf("[gRPC] %s duration=%v error=%v", method, duration, err)
    return err
}

conn, err := grpc.DialContext(ctx, addr,
    grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
    grpc.WithUnaryInterceptor(loggingInterceptor),
)
```

### Stream Client Interceptor

```go
func streamLoggingInterceptor(
    ctx context.Context,
    desc *grpc.StreamDesc,
    cc *grpc.ClientConn,
    method string,
    streamer grpc.Streamer,
    opts ...grpc.CallOption,
) (grpc.ClientStream, error) {
    log.Printf("[gRPC Stream] Opening %s", method)
    stream, err := streamer(ctx, desc, cc, method, opts...)
    return stream, err
}
```

## Protocol Buffers

### Generating Clients

```bash
# Install protoc plugins
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Generate Go code
protoc \
    --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative \
    pkg/api/grpc/proto/*.proto
```

### Proto Files Location

```
pkg/api/grpc/proto/
  platform.proto      # Platform daemon service
  ca.proto           # Certificate Authority service
  iam.proto          # IAM service
  kms.proto          # Key Management service
  vtpm.proto         # Virtual TPM service
  device.proto       # Device service
  attestation.proto  # Attestation service
  sdn.proto          # SDN service
  dns.proto          # DNS service
  ...
```
