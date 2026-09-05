# Integration Testing Strategy

Integration tests validate the full stack through public protocols only. Unit tests cover service layer logic; integration tests verify that all protocols expose consistent behavior to users.

## Core Principles

1. **Public Protocols Only** - Never call service layers directly in integration tests
2. **Full Stack Testing** - CLI to platformd to service layer to database
3. **Protocol Parity** - Same test scenarios run against ALL protocols
4. **Real Services** - Run in devcontainer with actual infrastructure

## Why Test Public Protocols (Not Service Layers)

```
Unit Tests:           Service Layer (direct calls)
Integration Tests:    Public APIs (CLI, REST, gRPC, QUIC, MCP, Socket)
```

**Rationale:**
- Unit tests already cover service layer logic with high coverage
- Public APIs call service layers internally, so testing APIs tests the full stack
- Avoids duplicate test coverage
- Tests what users actually interact with
- Validates serialization, transport, and protocol handling

## Public APIs

| Protocol | Transport | Use Case |
|----------|-----------|----------|
| **CLI** | platformctl -> platformd | Human operators, scripts |
| **REST** | HTTP/JSON via platform-api | External systems, web clients |
| **gRPC** | Protocol buffers via platformd | High-performance internal services |
| **QUIC** | UDP low-latency | Real-time, mobile clients |
| **MCP** | Model Context Protocol | AI/LLM integration |
| **Unix Socket** | Local IPC | Same-host services |

## Architecture

### Command Set Interface Pattern

Every package defines a central interface matching its operations:

```go
// kmsProtocol defines all KMS operations testable across protocols.
type kmsProtocol interface {
    // Lifecycle
    Name() string
    Setup(t *testing.T, ctx context.Context) error
    Teardown(t *testing.T) error

    // Key Management
    GenerateKey(ctx context.Context, req *GenerateKeyRequest) (*GenerateKeyResponse, error)
    GetKey(ctx context.Context, req *GetKeyRequest) (*GetKeyResponse, error)
    ListKeys(ctx context.Context, req *ListKeysRequest) (*ListKeysResponse, error)
    RotateKey(ctx context.Context, req *RotateKeyRequest) (*RotateKeyResponse, error)
    DeleteKey(ctx context.Context, req *DeleteKeyRequest) (*DeleteKeyResponse, error)

    // Cryptographic Operations
    Encrypt(ctx context.Context, req *EncryptRequest) (*EncryptResponse, error)
    Decrypt(ctx context.Context, req *DecryptRequest) (*DecryptResponse, error)
    Sign(ctx context.Context, req *SignRequest) (*SignResponse, error)
    Verify(ctx context.Context, req *VerifyRequest) (*VerifyResponse, error)
}
```

### Protocol Adapters

Each adapter implements the interface for its protocol:

```go
// CLI Adapter - executes platformctl commands
type cliAdapter struct {
    binaryPath string
    configPath string
}

func (c *cliAdapter) Name() string { return "CLI" }

func (c *cliAdapter) GenerateKey(ctx context.Context, req *GenerateKeyRequest) (*GenerateKeyResponse, error) {
    args := []string{"kms", "key", "generate",
        "--name", req.Name,
        "--algorithm", req.Algorithm,
        "--output", "json",
    }
    output, err := c.exec(ctx, args...)
    if err != nil {
        return nil, err
    }
    var resp GenerateKeyResponse
    if err := json.Unmarshal(output, &resp); err != nil {
        return nil, err
    }
    return &resp, nil
}

// REST Adapter - calls platform-api HTTP endpoints
type restAdapter struct {
    baseURL    string
    httpClient *http.Client
}

func (r *restAdapter) Name() string { return "REST" }

func (r *restAdapter) GenerateKey(ctx context.Context, req *GenerateKeyRequest) (*GenerateKeyResponse, error) {
    body, _ := json.Marshal(req)
    httpReq, _ := http.NewRequestWithContext(ctx, "POST", r.baseURL+"/api/v1/kms/keys", bytes.NewReader(body))
    httpReq.Header.Set("Content-Type", "application/json")

    httpResp, err := r.httpClient.Do(httpReq)
    if err != nil {
        return nil, err
    }
    defer httpResp.Body.Close()

    var resp GenerateKeyResponse
    if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
        return nil, err
    }
    return &resp, nil
}

// gRPC Adapter - calls platformd gRPC services
type grpcAdapter struct {
    conn   *grpc.ClientConn
    client pb.KMSServiceClient
}

func (g *grpcAdapter) Name() string { return "gRPC" }

func (g *grpcAdapter) GenerateKey(ctx context.Context, req *GenerateKeyRequest) (*GenerateKeyResponse, error) {
    pbReq := &pb.GenerateKeyRequest{
        Name:      req.Name,
        Algorithm: req.Algorithm,
    }
    pbResp, err := g.client.GenerateKey(ctx, pbReq)
    if err != nil {
        return nil, err
    }
    return &GenerateKeyResponse{
        KeyID:   pbResp.KeyId,
        Version: pbResp.Version,
    }, nil
}
```

### Multi-Protocol Test Runner

```go
func TestKMSMultiProtocol(t *testing.T) {
    if os.Getenv("INTEGRATION_TEST") == "" {
        t.Skip("Set INTEGRATION_TEST=1 to run")
    }

    protocols := []kmsProtocol{
        &cliAdapter{binaryPath: "/usr/local/bin/platformctl"},
        &restAdapter{baseURL: "https://localhost:8443"},
        &grpcAdapter{endpoint: "localhost:8444"},
        &quicAdapter{endpoint: "localhost:8445"},
        &mcpAdapter{endpoint: "localhost:8446"},
        &socketAdapter{path: "/run/platformd/platformd.sock"},
    }

    for _, protocol := range protocols {
        protocol := protocol
        t.Run(protocol.Name(), func(t *testing.T) {
            runKMSTests(t, protocol)
        })
    }
}

func runKMSTests(t *testing.T, p kmsProtocol) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
    defer cancel()

    require.NoError(t, p.Setup(t, ctx))
    defer p.Teardown(t)

    prefix := p.Name() + "-" + time.Now().Format("20060102150405")

    t.Run("GenerateKey", func(t *testing.T) { testGenerateKey(t, ctx, p, prefix) })
    t.Run("GetKey", func(t *testing.T) { testGetKey(t, ctx, p, prefix) })
    t.Run("EncryptDecrypt", func(t *testing.T) { testEncryptDecrypt(t, ctx, p, prefix) })
    t.Run("SignVerify", func(t *testing.T) { testSignVerify(t, ctx, p, prefix) })
}
```

### Shared Test Scenarios

```go
func testGenerateKey(t *testing.T, ctx context.Context, p kmsProtocol, prefix string) {
    t.Run("AES256GCM", func(t *testing.T) {
        req := &GenerateKeyRequest{
            Name:      prefix + "-aes256",
            Algorithm: "AES-256-GCM",
        }
        resp, err := p.GenerateKey(ctx, req)
        require.NoError(t, err)
        assert.NotEmpty(t, resp.KeyID)
    })

    t.Run("EmptyNameReturnsError", func(t *testing.T) {
        req := &GenerateKeyRequest{Name: "", Algorithm: "AES-256-GCM"}
        _, err := p.GenerateKey(ctx, req)
        require.Error(t, err)
    })
}

func testEncryptDecrypt(t *testing.T, ctx context.Context, p kmsProtocol, prefix string) {
    // Setup: create key
    keyResp, err := p.GenerateKey(ctx, &GenerateKeyRequest{
        Name:      prefix + "-enc-test",
        Algorithm: "AES-256-GCM",
    })
    require.NoError(t, err)

    t.Run("RoundTrip", func(t *testing.T) {
        plaintext := []byte("test data for encryption")

        encResp, err := p.Encrypt(ctx, &EncryptRequest{
            KeyID:     keyResp.KeyID,
            Plaintext: plaintext,
        })
        require.NoError(t, err)
        require.NotEqual(t, plaintext, encResp.Ciphertext)

        decResp, err := p.Decrypt(ctx, &DecryptRequest{
            KeyID:      keyResp.KeyID,
            Ciphertext: encResp.Ciphertext,
            Nonce:      encResp.Nonce,
        })
        require.NoError(t, err)
        assert.Equal(t, plaintext, decResp.Plaintext)
    })

    t.Run("TamperedCiphertextFails", func(t *testing.T) {
        encResp, _ := p.Encrypt(ctx, &EncryptRequest{
            KeyID:     keyResp.KeyID,
            Plaintext: []byte("tamper test"),
        })

        tampered := make([]byte, len(encResp.Ciphertext))
        copy(tampered, encResp.Ciphertext)
        tampered[0] ^= 0xFF

        _, err := p.Decrypt(ctx, &DecryptRequest{
            KeyID:      keyResp.KeyID,
            Ciphertext: tampered,
            Nonce:      encResp.Nonce,
        })
        require.Error(t, err)
    })
}
```

## Protocol Adapter Coverage

The following test packages have multi-protocol adapters implemented:

| Package | CLI | REST | gRPC | QUIC | MCP | Unix |
|---------|-----|------|------|------|-----|------|
| `daemon` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `ca` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `vtpm` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `tpm` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `kms` | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ |
| `secrets` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `iam` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `sdn` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `dns` | ✓ | ✓ | ✗ | ✓ | ✓ | ✗ |
| `attestation` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `pxe` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `tenant` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `device` | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |

Packages without full protocol coverage are still being implemented. Pull requests welcome for missing adapters.

## Directory Structure

```
test/integration/
├── PACKAGE_X/
│   ├── commands.go           # Central command set interface
│   ├── helpers.go            # Shared test utilities
│   ├── cli_adapter.go        # CLI protocol adapter
│   ├── rest_adapter.go       # REST protocol adapter
│   ├── grpc_adapter.go       # gRPC protocol adapter
│   ├── quic_adapter.go       # QUIC protocol adapter
│   ├── mcp_adapter.go        # MCP protocol adapter
│   ├── unix_adapter.go       # Unix socket adapter (gRPC over UDS)
│   ├── multiprotocol_test.go # Protocol parity tests
│   └── PACKAGE_X_test.go     # Package-specific edge cases
├── e2e/
│   ├── config.go             # E2E test configuration
│   ├── setup.go              # Environment setup
│   ├── cleanup.go            # Resource cleanup
│   └── e2e_provisioning_test.go
└── testenv/
    └── docker-compose.yml    # Test infrastructure
```

## Test Execution

### Build Tags

Integration tests require codec support for QUIC protocol testing. Always include the following build tags:

```
-tags 'integration codec_msgpack codec_json codec_cbor'
```

These tags enable:
- `integration` - Marks tests requiring infrastructure (skipped without flag)
- `codec_msgpack` - MessagePack codec for QUIC wire protocol
- `codec_json` - JSON codec for REST/MCP testing
- `codec_cbor` - CBOR codec for compact encoding

### Makefile Targets

```makefile
# Run all integration tests
make integration-test

# Run package-specific integration tests
make integration-test-ca
make integration-test-vtpm
make integration-test-daemon
make integration-test-secrets
make integration-test-iam
make integration-test-sdn
```

These targets automatically include the required build tags and environment variables.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `INTEGRATION_TEST` | - | Must be set to `1` to run |
| `PLATFORMD_GRPC_ENDPOINT` | `127.0.0.1:10443` | platformd gRPC endpoint |
| `PLATFORMD_REST_ENDPOINT` | `127.0.0.1:8443` | REST API endpoint |
| `PLATFORMD_QUIC_ENDPOINT` | `127.0.0.1:9444` | QUIC protocol endpoint |
| `PLATFORMD_MCP_ENDPOINT` | `127.0.0.1:9445` | MCP protocol endpoint |
| `PLATFORMD_UNIX_SOCKET` | `/tmp/platformd.sock` | Unix socket path for local IPC |
| `PLATFORMCTL_PATH` | `/usr/local/bin/platformctl` | CLI binary path |
| `PLATFORMD_CONFIG` | `test/integration/config.yaml` | Configuration file path |
| `SKIP_IAM_VALIDATION` | (unset) | Set to `1` to skip IAM token validation in tests |
| `RAFT_CLUSTER_TEST` | (unset) | Set to `1` to enable cluster replication tests |

### Running in DevContainer

The integration tests run in a Docker devcontainer with all required infrastructure.

```bash
# Run all integration tests (including infrastructure setup)
make integration-test

# Run specific package tests
make integration-test-ca
make integration-test-daemon
make integration-test-vtpm

# Run with additional output
make integration-test VERBOSE=1

# Run specific test within a package
make integration-test-ca TEST=TestCAMultiProtocol
```

The Makefile automatically handles:
- Building the platformd binary
- Building the platformctl CLI
- Starting required services (OVS, swtpm, etc.)
- Running platformd with test configuration
- Cleaning up test artifacts

**Test Configuration:**
- Config file: `test/integration/config.yaml`
- Script: `build/docker/devcontainer/run-integration-tests.sh`
- Test cleanup: `/tmp/platformd-integration` directory removed before each run to avoid key/cert mismatches

**Every per-package target goes through one canned recipe.** The Makefile's
`run-integration-suite` holds the single `docker run` invocation; a target is

```make
integration-test-<name>: build-devcontainer
	$(call run-integration-suite,<name>)
```

where `<name>` is a keyword in the runner's `TARGET_PACKAGES` map. **Add a new
target that way rather than calling the runner script directly.** A bare script
call runs the suite on the invoking workstation, and the runner is not a
passive thing to host: it `chmod 666`s `/dev/net/tun` and `/dev/kvm`,
`modprobe`s `tun` and `openvswitch`, and `pkill -9`s any running `swtpm socket`
and `ovsdb-server` — including ones it did not start. Fifteen targets did
exactly that until #492.

## Protocol Parity Assertions

Integration tests must verify identical behavior across all protocols:

```go
func TestProtocolParity(t *testing.T) {
    protocols := getAllProtocols()

    // Generate key via each protocol
    results := make(map[string]*GenerateKeyResponse)
    for _, p := range protocols {
        resp, err := p.GenerateKey(ctx, &GenerateKeyRequest{
            Name:      "parity-test",
            Algorithm: "AES-256-GCM",
        })
        require.NoError(t, err, "Protocol: %s", p.Name())
        results[p.Name()] = resp
    }

    // Verify all responses have same structure
    var reference *GenerateKeyResponse
    for name, resp := range results {
        if reference == nil {
            reference = resp
            continue
        }
        assert.NotEmpty(t, resp.KeyID, "Protocol %s: KeyID empty", name)
        assert.NotZero(t, resp.Version, "Protocol %s: Version zero", name)
    }
}
```

## Error Handling Consistency

Each protocol adapter must translate errors to typed errors:

```go
// Typed errors for consistent handling
type ErrKeyNotFound struct{ KeyID string }
func (e ErrKeyNotFound) Error() string { return "key not found: " + e.KeyID }

type ErrInvalidInput struct{ Field, Message string }
func (e ErrInvalidInput) Error() string { return e.Field + ": " + e.Message }

type ErrPermissionDenied struct{ Operation string }
func (e ErrPermissionDenied) Error() string { return "permission denied: " + e.Operation }

// REST adapter error translation
func (r *restAdapter) translateError(resp *http.Response) error {
    var apiErr struct {
        Code    int    `json:"code"`
        Message string `json:"message"`
    }
    json.NewDecoder(resp.Body).Decode(&apiErr)

    switch resp.StatusCode {
    case 404:
        return ErrKeyNotFound{KeyID: apiErr.Message}
    case 400:
        return ErrInvalidInput{Message: apiErr.Message}
    case 403:
        return ErrPermissionDenied{Operation: apiErr.Message}
    default:
        return fmt.Errorf("api error: %d %s", resp.StatusCode, apiErr.Message)
    }
}

// gRPC adapter error translation
func (g *grpcAdapter) translateError(err error) error {
    st, ok := status.FromError(err)
    if !ok {
        return err
    }
    switch st.Code() {
    case codes.NotFound:
        return ErrKeyNotFound{KeyID: st.Message()}
    case codes.InvalidArgument:
        return ErrInvalidInput{Message: st.Message()}
    case codes.PermissionDenied:
        return ErrPermissionDenied{Operation: st.Message()}
    default:
        return err
    }
}
```

## Test Categories

### Happy Path Tests
- CRUD operations succeed with valid input
- Round-trip data integrity (encrypt/decrypt, sign/verify)
- Pagination and filtering work correctly

### Error Handling Tests
- Invalid input returns appropriate errors
- Missing resources return not-found errors
- Permission failures are caught and reported

### Edge Case Tests
- Empty strings, nil inputs
- Maximum size limits
- Unicode and special characters
- Concurrent operations

### Protocol-Specific Tests
- CLI output formatting
- REST status codes and headers
- gRPC metadata and streaming
- QUIC connection handling

## Coverage Requirements

| Category | Target |
|----------|--------|
| Protocol adapters | 90%+ |
| Command interface | 100% |
| Error translation | 100% |
| Happy path scenarios | 100% |
| Error scenarios | 90%+ |

## Best Practices

1. **Unique Test Data** - Use timestamp prefixes to avoid collisions
2. **Cleanup After Tests** - Delete created resources in teardown
3. **Context Timeouts** - Always use contexts with deadlines
4. **Parallel Safety** - Use unique names for parallel test runs
5. **Skip Gracefully** - Skip if infrastructure unavailable, dont fail
6. **Assert Behavior, Not Implementation** - Test outcomes, not internals
