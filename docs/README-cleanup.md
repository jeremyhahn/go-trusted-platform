# TODO/FIXME Cleanup Checklist

This document tracks the cleanup of TODO/FIXME comments throughout the codebase.

**Total Items: ~124**
- **Completed: 24**
- **False Positives: 3**
- **Remaining: 97**

---

## Completed Items

| File | Description | Status |
|------|-------------|--------|
| `pkg/cli/commands/version.go:118` | Import version from app.Version | **DONE** |
| `pkg/store/datastore/entities/user.go:69` | Use DisplayName field | **DONE** |
| `pkg/cli/commands/kms/crypto_batch.go:201` | Implement batch encrypt | **DONE** |
| `pkg/cli/commands/kms/crypto_batch.go:207` | Implement batch decrypt | **DONE** |
| `pkg/cli/commands/kms/crypto_rewrap.go:89` | Implement rewrap | **DONE** |
| `pkg/cli/commands/registry/inspect.go:135` | Implement registry client call | **DONE** |
| `pkg/cli/commands/registry/delete.go:122` | Implement registry client call | **DONE** |
| `pkg/cli/commands/registry/push.go:101` | Implement registry client call | **DONE** |
| `pkg/cli/commands/registry/list.go:116` | Implement registry client call | **DONE** |
| `pkg/cli/commands/registry/status.go:135` | Implement registry client call | **DONE** |
| `pkg/cli/commands/registry/pull.go:93` | Implement registry client call | **DONE** |
| `pkg/cli/commands/cluster/leave.go:76` | Call cluster service | **DONE** |
| `pkg/cli/commands/cluster/join.go:123` | Call cluster service | **DONE** |
| `pkg/cli/commands/cluster/nodes.go:69` | Call cluster service | **DONE** |
| `pkg/cli/commands/cluster/status.go:67` | Call cluster service | **DONE** |
| `pkg/cli/commands/cluster/bootstrap.go:107` | Call cluster service | **DONE** |
| `pkg/api/grpc/kms_service.go` | BatchEncrypt gRPC handler | **DONE** |
| `pkg/api/grpc/kms_service.go` | BatchDecrypt gRPC handler | **DONE** |
| `pkg/api/grpc/kms_service.go` | Rewrap gRPC handler | **DONE** |
| `pkg/api/grpc/registry_service.go` | Registry gRPC service | **DONE** |
| `pkg/api/grpc/cluster_service.go` | Cluster gRPC service | **DONE** |
| `sdk/go/platform/client.go` | Registry/Cluster clients | **DONE** |
| `pkg/api/daemon/config.go` | Add RegistryService config field | **DONE** |
| `pkg/api/daemon/daemon.go` | Register Registry gRPC service | **DONE** |

## False Positives (Not TODOs)

These items were identified as false positives - they contain "XXXX" patterns used for format descriptions, not actual TODO comments:

| File | Reason |
|------|--------|
| `pkg/uefi/guid.go:115` | Format description comment |
| `pkg/qemu/ovs_network.go:204` | Format description comment |
| `pkg/installer/installer.go:1401` | Format description comment |

---

## Remaining Blocked Items

These items are waiting for external services or infrastructure to be implemented first.

### Blocked by CA Dual-Mode Support (3 items)

CA CLI commands require dual-mode (embedded/remote) support.

| File | Description |
|------|-------------|
| `pkg/cli/commands/ca/install.go:55` | Implement dual-mode support |
| `pkg/cli/commands/ca/init.go:53` | Implement dual-mode support |
| `pkg/cli/commands/ca/uninstall.go:56` | Implement dual-mode support |

### Blocked by KMS Secrets Service (1 item)

| File | Description |
|------|-------------|
| `pkg/cli/commands/bootstrap/secrets_migrate.go:86` | Implement secrets migrate |

### Blocked by Device Service (6 items)

Device handlers require device lifecycle management to be implemented.

| File | Description |
|------|-------------|
| `pkg/api/rest/device_handlers.go:714` | Implement actual activation logic |
| `pkg/api/rest/device_handlers.go:767` | Implement actual TPM attestation verification |
| `pkg/api/rest/device_handlers.go:815` | Implement actual state tracking |
| `pkg/api/quic/device_handlers.go:773` | Implement actual activation logic |
| `pkg/api/quic/device_handlers.go:816` | Implement actual TPM attestation verification |
| `pkg/api/quic/device_handlers.go:863` | Implement actual state tracking |

### Blocked by Remote go-xkms Server (5 items)

Secureboot XKMS operations require the remote go-xkms server.

| File | Description |
|------|-------------|
| `pkg/secureboot/keychain.go:113` | Remove once remote go-xkms server is available |
| `pkg/secureboot/keychain.go:231` | Remove once remote go-xkms server is available |
| `pkg/secureboot/keychain.go:370` | Use remote go-xkms server once available |
| `pkg/secureboot/keychain.go:415` | Refactor to use remote go-xkms server for signing |
| `pkg/secureboot/keychain.go:469` | Remove once remote go-xkms server is available |

### Blocked by QuicBaaS SDK (2 items)

QuicBaaS operations require SDK query interface updates.

| File | Description |
|------|-------------|
| `pkg/storage/quicbaas/client.go:359` | Use proper SDK query interface when available |
| `pkg/storage/quicbaas/client.go:387` | Add SDK support for ListEntityTypes when available |

### Blocked by IAM Service (2 items)

Operations requiring authorization/IAM support.

| File | Description |
|------|-------------|
| `pkg/api/daemon/daemon.go:758` | Wire in PEP client when IAM is available |
| `pkg/dns/service.go:430` | Complete DNS service domain ownership verification |

### Other Deferred Items (5 items)

Items requiring significant infrastructure or external dependencies.

| File | Description | Dependency |
|------|-------------|------------|
| `pkg/authenticode/pe.go:790` | Implement RFC3161 timestamp request/response | Timestamp authority |
| `pkg/vtpm/service.go:720` | Start swtpm, inject EK certificate, stop swtpm | vTPM lifecycle |
| `pkg/initrd/strategy_fido2.go:220` | Implement metadata storage via LUKS2 tokens | LUKS2 token support |
| `pkg/app/app.go:2195` | Re-seal the CA, run intrusion detection handlers | Intrusion detection |
| `pkg/iso/customize.go:804` | Add IMA config to SecurityConfig if needed | IMA configuration |
| `pkg/sdn/gateway/commands/serve.go:143` | Create gateway node integration | SDN gateway |
| `pkg/webservice/v1/router/acme.go:45` | Make rate limits configurable | Configuration |

---

## Integration Test Adapters (79 items)

All integration test adapter TODOs are blocked waiting for SDK and protocol support. These will be implemented as each protocol becomes available in the SDK.

### Summary by Protocol

| Protocol | Adapter Files | TODO Count |
|----------|---------------|------------|
| MCP | `test/integration/pxe/mcp_adapter.go` | 15 |
| QUIC | `test/integration/pxe/quic_adapter.go` | 15 |
| gRPC | `test/integration/pxe/grpc_adapter.go` | 18 |
| Container | `test/integration/container/` | 11 |
| Invitation | `test/integration/invitation/` | 8 |
| User Registration | `test/integration/user_registration/` | 4 |
| TPM | `test/integration/tpm/` | 4 |
| Registry | `test/integration/registry/` | 2 |
| Tenant | `test/integration/tenant/` | 1 |
| SDN | `test/integration/sdn/` | 1 |

---

## Progress Summary

| Category | Total | Completed | False Positive | Blocked | Actionable |
|----------|-------|-----------|----------------|---------|------------|
| CLI Commands | 19 | 17 | 0 | 2 | 0 |
| API Handlers | 7 | 2 | 0 | 5 | 0 |
| Core Services | 19 | 5 | 3 | 11 | 0 |
| Integration Adapters | 79 | 0 | 0 | 79 | 0 |
| **Total** | **124** | **24** | **3** | **97** | **0** |

---

## New Services Implemented

### KMS Service Extensions
- **BatchEncrypt** - Encrypt multiple items in a single request
- **BatchDecrypt** - Decrypt multiple items in a single request
- **Rewrap** - Re-encrypt ciphertext with latest key version without exposing plaintext

### Registry Service (New)
Full container/artifact registry service with:
- Push (streaming)
- Pull (streaming)
- List (paginated)
- Inspect
- Delete
- Status

### Cluster Service (New)
Full cluster management service with:
- Bootstrap - Initialize a new cluster
- Join - Join an existing cluster
- Leave - Leave gracefully
- GetStatus - Get cluster status
- ListNodes - List all cluster nodes

### Daemon Integration
Registry service is now integrated into the daemon:
- Added `RegistryService` config field to `pkg/api/daemon/config.go`
- Added registry gRPC service registration in `pkg/api/daemon/daemon.go`
- Registry service can be enabled by providing a `RegistryService` implementation

---

## Test Coverage

| Package | Coverage | Status |
|---------|----------|--------|
| `pkg/api/grpc` | 86.0% | Needs ~4% more |
| `pkg/api/rest` | 81.8% | Needs ~8% more |
| `pkg/api/daemon` | ~85% | Pre-existing QUIC failures |
| `pkg/cli/commands/kms` | 33.3% | Run funcs need integration tests |
| `pkg/cli/commands/registry` | 69.5% | Run funcs need integration tests |
| `pkg/cli/commands/cluster` | 92.4% | **DONE** |

---

## Notes

- Most remaining TODO items are blocked by external service dependencies
- Integration adapters will be implemented as SDK protocol support becomes available
- Items marked "blocked" are intentional placeholders, not technical debt
- False positives are format description comments containing "XXXX" patterns
- The codebase follows a pattern of creating command stubs that return "not implemented" errors until backend services are ready
