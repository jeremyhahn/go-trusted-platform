# Integration Testing Strategy

> **Status: REFERENCE** · Last verified: 2026-10-13
> How the multi-protocol suites in `test/integration/` are built and run: the Makefile's `run-integration-suite` and `build/docker/devcontainer/run-integration-tests.sh`.

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
| **REST** | HTTP/JSON via platformd | External systems, web clients |
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

// REST Adapter - calls platformd REST endpoints
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
    protocols := []kmsProtocol{
        &cliAdapter{binaryPath: "/usr/local/bin/platformctl"},
        &restAdapter{baseURL: "https://localhost:8443"},
        &grpcAdapter{endpoint: "localhost:10443"},
        &quicAdapter{endpoint: "localhost:9444"},
        &mcpAdapter{endpoint: "https://localhost:9445"},
        &socketAdapter{path: "/run/platformd.sock"},
    }

    gate := helpers.NewAdapterGate(t, "kms", helpers.AdapterNames(protocols)...)
    for _, protocol := range protocols {
        protocol := protocol
        t.Run(protocol.Name(), func(t *testing.T) {
            gate.RequireSetup(t, protocol.Name(), protocol.Setup(t, ctx))
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
| `kms` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `secrets` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `iam` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `sdn` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `dns` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `attestation` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `pxe` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `tenant` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `device` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `objectstorage` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

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
└── e2e/
    ├── config.go             # E2E test configuration
    ├── setup.go              # Environment setup
    ├── cleanup.go            # Resource cleanup
    └── e2e_provisioning_test.go
```

## Test Execution

### Build Tags

The targets build with `TEST_BUILD_TAGS` (Makefile:365): `integration`,
`INTEGRATION_CODEC_TAGS` (`codec_msgpack codec_json codec_cbor`),
`INTEGRATION_VECTOR_TAGS` (`vector qrdb_vector`, the `WITH_VECTOR=1` tags) and
the full `BUILD_TAGS` list, which includes any `GO_BUILD_TAGS` passed to `make`
([build-tags.md](../configuration/build-tags.md#go_build_tags)).
`integration` marks a file as needing the devcontainer; the codecs carry the
QUIC wire protocol and the REST/MCP bodies; the vector tags let the embedded
`quicbaas.TestConfig` serve the Vector service that the quicbaas and sdk suites
assert against.

Never type the tag list by hand. Outside `make`, derive it:

```bash
go vet -tags "integration $(make -s print-build-tags)" ./test/integration/...
```

A hand-written list drops codecs, and the suite then fails with
`no codec available for encoding`.

### Makefile Targets

```makefile
# Run every devcontainer-runnable suite (the runner's `all` keyword)
make integration-test

# Run one suite: integration-test-<key>, where <key> is a TARGET_PACKAGES key
make integration-test-ca
make integration-test-compute
make integration-test-vtpm
make integration-test-daemon
make integration-test-root          # test/integration itself, not its subdirectories
```

Every directory under `test/integration` that holds a Go suite has a key in
the runner's `TARGET_PACKAGES` map and an `integration-test-<key>` target.
`make help` lists them. The suites a container cannot run are the exceptions,
listed below.

`make integration-test` runs the runner's `ALL_TARGETS` list in order:
every key except `cold-start` and `barrier-gate` (each needs the shared
`platformd` not running), `bmc` (needs the vBMC config), `diskimage`,
`netboot`, `nat64` and `ipsec` (each needs inputs built on the host first),
`pxe` (platformd has no PXE backend), `bootstrap` (the shared platformd
publishes no DANE records) and `secureboot` (needs prebuilt FIPS-kernel
artifacts), all three in the table below, and the keys that
only run part of a suite already in the list (`lb`, `ipxe-dhcp`, `ipxe-tftp`,
`ipxe-http`, `testenv-enrollment`).

The keys in the runner's `TARGET_NO_DAEMON` map skip the shared `platformd`:
their suites start their own daemon or cluster, or test something that needs
none (`datastore`, `quicbaas`, `sdk`, `cluster`, `cmd`, `installer`, `lb`,
`e2e`, `ipxe` and its slices, `testenv-enrollment`, `helpers`). `helpers` runs
the integration-tagged tests of the harness library itself; its untagged
tests run in `make test`.

Under `make integration-test` the daemon-free keys of `ALL_TARGETS` (`helpers`,
`datastore`, `quicbaas`, `sdk`, `cluster`, `cmd`, `ipxe`, `installer`, `e2e`)
run concurrently. Each writes its own log under `/tmp/integration-logs/`, and
the runner prints that log whole when the suite ends, so the `-v` output of two
suites never interleaves. The daemon-backed keys then run one at a time, in
list order, on the one shared `platformd`. The run fails if any suite fails,
and the closing summary lists every key with its `PASS` or `FAIL`.

The runner does not pre-compile the whole of `./test/integration/...`. Each
suite's package is checked with `go vet` under the run's tags, which compiles
it without running a `TestMain`. A single key is checked before Open vSwitch,
the software TPM or `platformd` starts, so a compile error ends the run with
its `file:line` first. Under `make integration-test` each package is checked
just before its own run. A compile error fails that suite, and the others
still run. The check compiles the package's dependencies into the build cache
that the suite's `go test` then reuses.

Kept out of the runner, or out of its default set:

| Directory | Why | How it runs |
|-----------|-----|-------------|
| `pxe` | platformd constructs its PXE service with a nil backend (`pkg/api/daemon/daemon.go:979`), and nothing outside tests calls `SetPXEService` or `pkg/compute/pxe.NewService`, so every transport answers `SERVICE_NOT_CONFIGURED` and the suite fails at adapter setup. Its six adapters are real; it rejoins `ALL_TARGETS` when platformd has a PXE backend | `make integration-test-pxe` |
| `bootstrap` | `TestDANERecords_Published`, `TestDANEBootstrap_EndToEnd` and `TestTrustResolver_DANE` need DANE-TA records at `_8443._tcp.localhost.` (`test/integration/bootstrap/bootstrap_test.go:212`, `helpers_test.go:49-52`), and the shared platformd publishes none. TLSA publication runs only when a `webservices:` certificate is issued (`pkg/app/app.go:4077`) with `dns.dane.enabled` and `auto-generate` set (`app.go:4271-4276`); `test/integration/config.yaml` has no `webservices:` section (`:5`, so `InitWebServer` returns at `app.go:3601`) and DANE off. Even with one, `resolveDANEZone` finds no zone for `localhost.` (`app.go:4355`), and the internal DNS listens on 9053 (`config.yaml:212`), not the tests' default 8053. Its five REST bootstrap-endpoint tests run with it | `make integration-test-bootstrap` |
| `secureboot` | `TestFIPSKernelModuleSignatureEnforcement` fails without a prebuilt FIPS kernel, its modules tarball and the module-signing key it was built with (`test/integration/secureboot/fipskernel_test.go:210-212`, `helpers.go:61-71`), which only the caller supplies through `FIPS_KERNEL_IMAGE`, `FIPS_MODULES_TAR` and `FIPS_MODULE_SIGNING_KEY`; the runner sets none of them. `docs/firmware/secure-boot.md:513-514` already keeps the target out of the `all` sweep | `make integration-test-secureboot` with the three variables set |
| `secureboot/hardware` | Real TPM and efivarfs on the node; disabled unless `TP_HW_TPM`/`TP_HW_EFIVARS` is `1` | `make integration-test-secureboot-hw` on the node |
| `sdn/topology` | The multi-node topology tests start their nodes with docker-compose (`test/integration/sdn/topology/docker-compose.tmpl`), and the devcontainer has neither docker-compose nor a Docker daemon. The `topology` build tag keeps them out of the `sdn` key's `./test/integration/sdn/...`; run anywhere else, they fail with `ErrDockerComposeMissing` | `make integration-test-sdn-topology` on a host with docker-compose |
| `compute-aws` | A Floci emulator compose file, not a suite; the tests are in `pkg/compute/aws` | `make integration-test-compute-aws` on the host |
| `diskimage/userspace` | An arm64 userspace container | `make integration-test-diskimage-userspace` |
| `web` | Playwright (TypeScript), not Go | `npx playwright test --config ../test/integration/web/playwright.config.ts` from `web/` |

These targets automatically include the required build tags and environment variables.

The runner's `TARGET_ENV` map sets `IPXE_DHCP_ENABLED=1` for `ipxe` and
`ipxe-dhcp`; with it, the suite's `TestMain` starts the platform DHCP server on
loopback at a free UDP port, and the DHCP tests exchange real DISCOVER/OFFER
and REQUEST/ACK with it. Without the variable those tests fail rather than
skip; `ipxe-http` and `ipxe-tftp` keep them out with their `-run` patterns.
The iPXE suite has no skips at all: its firmware upstream and HTTPS proxy
upstream are local fixture servers, so it needs no outside network.
`integration-test-testenv-enrollment` and `integration-test-e2e` pass
`INTEGRATION_TEST_SERVER_ISO` and `INTEGRATION_TEST_CLIENT_ISO` through when
they are set. Without them the enrollment test runs its framework VM only, and
`TestE2EDeviceProvisioning` validates its infrastructure and stops before
provisioning.

A per-package target must drive
`build/docker/devcontainer/run-integration-tests.sh`, which brings up Open
vSwitch, a software TPM and a real `platformd` before the suite starts. A bare
`go test` cannot satisfy the first of the core principles above, whether it runs
on the host or inside a container with no daemon: either way the suite has no
real services to talk to. So a new suite gets a keyword in the runner's
`TARGET_PACKAGES` map and a target that calls `run-integration-suite`.

The `-local` variants (`integration-test-iam-local` and its siblings) are the
deliberate exception. They run on the host against services the caller has
already started, they say so in their help text, and they are not what CI or a
lane runs.

CI runs `make integration-test` in its full tier (see CI below). The other
workflow that touches tests is `.github/workflows/batch.yml` (#860): a `workflow_dispatch`-only workflow, dispatched on
`main` and never part of a merge gate, that runs on the self-hosted `batch`
runners. It fuzzes every `Fuzz*` target, runs the `make test-race` package set
with `-count=3`, soaks by looping `make test-race` (not these suites), and
benchmarks the same package set. It reads its tags and packages from the
Makefile (`print-build-tags`, `print-race-pkgs`, `print-test-skip`). Each
finding is a log line that starts with `BATCH-FINDING`.

The runner hands back anything it created in the bind-mounted source tree
before it exits. The container runs as root, so without that step a run leaves
root-owned paths behind, `git status` reports a permission error on every
invocation afterwards, and `git worktree remove` fails on the offending path.
The owning user comes from `HOST_UID`/`HOST_GID` when the target passes them,
and otherwise from the mount point's own ownership.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PLATFORM_REST_ENDPOINT` | `https://localhost:8443` | REST API endpoint |
| `PLATFORM_GRPC_ENDPOINT` | `localhost:10443` | platformd gRPC endpoint |
| `PLATFORM_QUIC_ENDPOINT` | `localhost:9444` | QUIC protocol endpoint |
| `PLATFORM_MCP_ENDPOINT` | `https://localhost:9445` | MCP protocol endpoint (TLS 1.3 only, #844) |
| `PLATFORM_SOCKET_PATH` | `/run/platformd.sock` | Unix socket path for local IPC |
| `PLATFORMCTL_PATH` | `platformctl` (on `PATH`) | CLI binary path |
| `PLATFORM_CLIENT_CERT`, `PLATFORM_CLIENT_KEY` | `client-bundle.pem` | Harness admin credential, subject `O=system` (`helpers.HarnessTenantID`) |
| `PLATFORM_TENANT_CLIENT_CERT`, `PLATFORM_TENANT_CLIENT_KEY` | `tenant-client-bundle.pem` | Harness credential bound to the non-system tenant `harness-tenant` (`helpers.ForeignTenantID`) |
| `PLATFORM_CA_CERT` | `ca-bundle.crt` | CA both client credentials chain to |

The two client bundles live in `/tmp/platformd-integration/tls/`. platformd
writes both on first start (`pkg/daemon/commands/harness_admin_bundle_integration.go`,
`integration` build only), from the same root admin request through the same
issuer; the tenant bundle differs only in its subject `O`, and it is written
first, so a run that has `client-bundle.pem` always has both. The mTLS
transports bind a caller to the tenant its subject names, so a suite proves a
cross-tenant refusal by dialing with `helpers.TenantTLSConfig()` instead of
`helpers.TLSConfigOrInsecure()`.

The endpoint variables are the ones the shared helpers in
`test/integration/helpers/endpoints.go` read. Suites with a private namespace
(`VTPM_*`, `TENANT_*`, `IAM_*`, `ATTESTATION_*`, `AUTH_*`) read
their own name first and otherwise use the shared helper. The defaults are
there only for running a suite by hand against a platformd on its standard
ports.

`run-integration-tests.sh` sets each listener port once
(`PLATFORMD_{REST,GRPC,QUIC,MCP}_PORT`). It passes that port to
`platformd serve` and builds every exported endpoint from it, so the daemon and
the suites cannot drift apart: to move a port, change that one variable.
`TestRunnerExportsEveryEndpointFromThePortItGivesPlatformd`, part of the unit
suite, fails if a flag goes back to a literal port or if an endpoint the helpers
read is no longer exported from the same variable (#502).

### Running in DevContainer

The integration tests run in a Docker devcontainer with all required infrastructure.

```bash
# Run all integration tests (including infrastructure setup)
make integration-test

# Run specific package tests
make integration-test-ca
make integration-test-daemon
make integration-test-vtpm
```

The Makefile reads no `VERBOSE` or `TEST` variable. The runner chooses the
`-run` filter per target from its `TARGET_RUN` map.

The Makefile automatically handles:
- Building the platformd binary
- Building the platformctl CLI
- Starting required services (OVS, swtpm, etc.)
- Running platformd with test configuration
- Cleaning up test artifacts

**Test Configuration:**
- Config file: `test/integration/config.yaml`. Its `dns:` section gives
  platformd an internal CoreDNS server on port 9053 seeded with zone
  `integration.internal.`, so the daemon builds a DNS backend and the dns
  suite reaches real zone storage. DNSSEC and DANE stay off, so the
  `bootstrap` suite's DANE tests have no records to find and the suite is kept
  out of `ALL_TARGETS` (see the kept-out table above).
  `TestIntegrationConfig_LoadsWithDNSServer` (`pkg/app`) loads the file the way
  platformd does and checks the `dns:` keys strictly. The file has no `pxe:`
  section: platformd has no reader for one, because PXE is a gateway-role
  service. Its `PXEGRPCService` therefore has no backend, so the `pxe` suite is
  kept out of `ALL_TARGETS` (see the kept-out table above).
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

`integration-test-webservice` and `integration-test-ca-quicbaas-adapter` do
not follow this: they test packages under `pkg/`, not a suite under
`test/integration`, so the runner has no key for them.

No target hand-writes its own `docker run` of the runner either. A
hand-written block drifts: `integration-test`, `-sdn` and `-barrier-gate` lost
the define's module-cache mount and `GOWORK=off`, so the container resolved
every module over the network and the SDN suite never got past building
`platformd` (#539). `pkg/arch/integrationsuite_test.go` fails `make test` on
any recipe that names the runner outside the define, and on a define that
drops either flag.

`make integration-test` is the one target that does not use the define. It is
the CI standard's integration stage, so it builds the `integration` stage of
`build/docker/devcontainer/Dockerfile` as `IT_IMAGE` and runs
`build/docker/devcontainer/compose.yaml`'s `integration` service under the
compose project `IT_PROJECT`. The service's entrypoint is the runner, so the
Makefile passes it only `all` and the tags; the service carries the define's
flags (privileged, `/dev/net/tun`, an exec `/tmp`, `GOWORK=off`). The image
bakes the source and the module cache with `GOPROXY=off`, so nothing is
bind-mounted and nothing is fetched. The target tears the stack down on every
exit and exits with the suites' status.

### CI

`.github/workflows/ci.yml` is the canonical CI (handbook `ci-standard.md`,
ci-template). Its five stages are Makefile targets, `make build`, `make test`,
`make integration-test`, `make security` and `make deps-check`, and run in the
devcontainer image so a developer and CI run the same thing:

| Job | Tier | What it runs |
|-----|------|--------------|
| `image` | PR | `make docker-build` (toolchain and integration images), then `make build`, `make test`, `make security` and `make deps-check` in the toolchain image through `scripts/in-toolchain-image.sh`, and `trivy image` on the integration image |
| `integration` | full | `make integration-test` under a per-run `IT_PROJECT` and `IT_IMAGE`, torn down on every exit |
| `lint`, `sdkjs`, `security`, `build`, `test` | PR | Native-runner checks: format, vet, lint, `check-insecure-tls`; the JS SDK; gosec with its SARIF upload (GitHub only), govulncheck, module verification; `go build ./...` (root and `sdk/go`), `build-no-web`, the Pi binaries and the `sdk/go` consumer check; `make test` and `make test-sdk-go` |
| `race`, `web` | full | `make test-race`; the web console's tests, typecheck and build |
| `fips` | main only | `make test-fips`; outside the gate |

The full tier runs on every push to `main`, on `workflow_dispatch`, and on a PR
labelled `ci:full`. `CI Gate` passes when every PR-tier job passed and every
full-tier job passed or was not selected.

The `image` job's `trivy image` step fails on any CRITICAL or HIGH finding in
the integration image that has a fix (`--severity CRITICAL,HIGH --exit-code 1
--ignore-unfixed`, handbook `devops.md` §8). It skips `/gomodcache`, the baked
third-party module cache, whose test-fixture keys are not credentials; module
vulnerabilities stay gated by govulncheck and `trivy fs` in `make security`.
Its suppressions are `build/docker/devcontainer/trivyignore-image.yaml`, not
the root `.trivyignore`: each entry is scoped by path to one package copy and
carries its reason and an `expired_at` date, after which the finding fails the
gate again. Today it holds only advisories in the dependencies npm itself
bundles, which no Node or npm release fixes yet.

The images come from one Dockerfile, `build/docker/devcontainer/Dockerfile`,
built from the repository root. `scripts/tool-pins.sh` holds the base image and
the pins for govulncheck, trivy and Node.js (the integration image's official
Node release archive, digest-checked per architecture in place of nvm), and the
Makefile includes it;
golangci-lint, actionlint, gosec and swag stay pinned in their
`build/tools-src` modules, so each links the dependency versions its module
names rather than the tool's own (#933). The integration stage installs only
the packages a suite, the runner or a Makefile target run there calls; the
CanoKey QEMU build, autotools, tpm2-abrmd, yubikey-manager, the Secure Boot
signing tools, the X server and the legacy network tools were dropped because
nothing called them, and the `trivy image` step scans every package left. The toolchain image is tagged with a hash of its inputs
(`make -s toolchain-image`). Forge credentials reach the build only as the
`gomodauth` BuildKit secret, from `MODULE_ENV_FILE`. Every job that starts
containers first runs `scripts/reap-stale-ci-stacks.sh go-trusted-platform-ci-`,
which removes the stacks a runner that died mid-job left behind.

The toolchain container writes in four places: the checkout at `/src`, the
build cache at `/gocache` (a named volume under compose, the container's own
disk-backed layer under `scripts/in-toolchain-image.sh`), `/var/tmp` (likewise
a named volume or the container's layer), which is `TMPDIR`, and a 3 GB tmpfs
at `/tmp`, which is `HOME`. The image sets `GOTMPDIR=/gocache`, so the go
command's work directory, every compiled package and linked test binary of a
run, sits on disk beside the cache. `make test` over the whole tree needs more
than `/tmp` holds: on a cold cache at `-p 8` its work directory peaked at
4.2 GB and the build cache ended at 3.5 GB, and the peak grows with the
runner's CPU count.

The linker does not follow `GOTMPDIR`. An external (cgo) link writes its
objects under `os.MkdirTemp("", "go-link-")` (`hostlinksetup` in
`cmd/link/internal/ld/lib.go`), which follows `TMPDIR`, and `make test` links
one test binary per CPU at once; with `TMPDIR=/tmp` those links failed with
`no space left on device`. `/var/tmp` is on disk, and like `/tmp` it is sticky
under root-owned ancestors, so a 0700 directory made under `os.TempDir()`
still passes `cmd/deployer-pin`'s ancestor check, and its path is short
enough for the Unix sockets the tests bind there. `t.TempDir()` follows
`GOTMPDIR` and lands in `/gocache`.

The stages that get a network (`make security`, `make deps-check` and CI's
`trivy image`, with `IN_IMAGE_NETWORK=bridge`) keep their downloads off `/tmp`
as well. `scripts/in-toolchain-image.sh` points their writable module cache at
`/gocache/mod`: it starts empty, so the stage downloads its whole module graph
(about 2.3 GB unpacked for the root module). The image sets
`TRIVY_CACHE_DIR=/gocache/trivy`, so trivy's vulnerability DB (1.6 GB
unpacked) is not written to `$HOME/.cache/trivy`. With both in `/tmp`,
`make security` failed writing `trivy.db` with `no space left on device`.

To run a stage locally as CI does: `make docker-build`, then
`make docker-run CMD='make test'`.

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

## An Unreachable Transport Is a Failure, Not a Skip

A multi-protocol suite exists to prove that every transport reaches the same
service and gets the same answer. A `Setup` that fails has proved nothing about
that transport, so it must not be reported as a skip: a skipped subtest does not
fail its parent, which made a daemon that never started and a transport that
passed produce the same summary line (issue #523).

Two helpers in `test/integration/helpers` carry this:

- `helpers.RequireAdapterSetup(t, suite, transport, err)` fails the test when a
  single adapter's `Setup` returns an error, naming the transport and the
  endpoint it dialled so a reader can tell a broken adapter from a broken
  product.
- `helpers.NewAdapterGate(t, suite, transports...)` returns a gate whose
  `RequireSetup` does the same inside a loop and additionally counts the
  transports that executed. The gate fails the suite from the parent test's
  cleanup if **no** transport ran, so a suite cannot degrade to zero adapters
  and still report success.

Environment guards fail as well. A suite whose prerequisite (a TPM, OVS,
swtpm, a configured daemon section) is missing fails; where a suite checks the
prerequisite itself, the failure is a typed error naming it and how to provide
it. Nothing in `test/integration` skips (#260). The runner starts OVS and swtpm for every target, so in a `make`
run such a failure means that bring-up failed, and the runner has already
printed a warning saying so. For
`integration-test-vtpm` a swtpm that does not start ends the run.

That swtpm is the daemon's TPM: `test/integration/config.yaml` and
`test/integration/barrier_gate/config.yaml` set `tpm.device` to
`/tmp/swtpm/swtpm.sock`, the socket `start_swtpm` serves, with only the SHA-256
PCR bank active. The integration container is privileged and sees the host's
`/dev/tpmrm0`, so a config naming that device runs `platformd` on the CI host's
own TPM; on a host whose TPM has no active SHA-256 bank the daemon stops at
`PCR 23 is not present in bank 0x000b`. `TestIntegrationConfig_TPMIsHarnessSwtpm`
in `pkg/app` holds both configs to the runner's socket. It also holds the
embedded quicbaas server's `seal.tpm2.device` to that socket. platformd copies
`tpm.device` into that setting, so the server's hardware probe never opens the
host's `/dev/tpmrm0` ([daemon configuration](../daemon/configuration.md)).

The harness swtpm is provisioned like shipped hardware: it has an endorsement
key and an EK certificate before `platformd` first opens it. `start_swtpm`
calls `provision_swtpm_state` (`build/docker/devcontainer/swtpm-provision.sh`),
which runs `swtpm_setup --createek --create-ek-cert`: the RSA 2048 EK is
persisted at `0x81010001`, the `tpm.ek.handle` both configs name, and its
certificate, issued by a `swtpm_localca` CA created under `/tmp/swtpm/localca`,
is written to NV index `0x01C00002`. `platformd` therefore opens a TPM it
recognises as initialized and does not take its recovery path, which no
shipped TPM needs. If `swtpm_setup` or `swtpm_localca` is missing, or
provisioning fails, the runner stops with a `FATAL` message instead of starting
the daemons on a TPM without an EK.

A bring-up failure ends the run for the same reason. When `platformd` does not
start, `build/docker/devcontainer/run-integration-tests.sh` aborts before any
suite runs rather than handing the suites endpoints nothing is listening on.

## A Missing Surface Is Declared by Type, Never by Error Text

A subtest whose operation has no endpoint on a transport fails with the
declared gap's own text, naming the transport and operation; it is never
skipped (#260). The gap must be *declared*. Suites used to skip whenever the error text
contained one of a dozen phrases ("not implemented", "unavailable", "501",
"404", "unknown flag", ...), so a 404, a mistyped CLI flag, a timeout or a
failed handshake read as "not built yet" (issue #487). Error text is never
matched now.

`test/integration/helpers/surface` is the one place that decision is made:

- An adapter whose transport has no endpoint for an operation returns
  `surface.ErrNoSurface{Transport, Operation, Reason}`. `Reason` optionally
  names where the gap is recorded.
- `surface.IsNotImplemented(err)` is true only for an `ErrNoSurface` anywhere in
  the chain (`errors.As`) or a gRPC status with `codes.Unimplemented`.
- `surface.RequireImplemented(t, err)` fails the test on exactly that, with the
  gap's text, and leaves every other error to the caller, which fails with its text or asserts it as an
  expected refusal.
- `surface.IsDeclaredRefusal(err, sentinels...)` recognises a deployment gap
  the daemon declares with a sentinel (for example
  `daemon.ErrFIDO2NotConfigured`), either in the chain or carried across the
  wire as that sentinel's exact text. The match comes from the sentinel value,
  so renaming or retiring a sentinel breaks the build rather than widening the
  match. The fido2, piv and luks suites assert their backend sentinels as the
  expected refusal this way.

Do not add a phrase list to a suite. If a transport lacks an operation, make
its adapter return `ErrNoSurface`. If the server refuses for a deployment
reason, match its sentinel with `IsDeclaredRefusal`.

## Best Practices

1. **Unique Test Data** - Use timestamp prefixes to avoid collisions
2. **Cleanup After Tests** - Delete created resources in teardown
3. **Context Timeouts** - Always use contexts with deadlines
4. **Parallel Safety** - Use unique names for parallel test runs
5. **Never Skip an Unreachable Transport** - A transport whose `Setup` fails has
   not been tested. Fail with `helpers.RequireAdapterSetup` or
   `AdapterGate.RequireSetup`, never `t.Skip` (see the section above)
6. **Recognise a Gap Only by Its Typed Declaration** - `surface.RequireImplemented`
   or a server sentinel through `surface.IsDeclaredRefusal`, never a match on
   error text (see the section above)
7. **Assert Behavior, Not Implementation** - Test outcomes, not internals
