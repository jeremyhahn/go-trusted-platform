# Build Tags Reference

> **Status: REFERENCE** · Last verified: 2026-10-18
> The `WITH_*` Makefile variables and the Go build tags each one adds to `BUILD_TAGS`.

This document describes all build tags used in go-trusted-platform for conditional compilation and feature selection.

## Overview

go-trusted-platform uses build tags to control which features are included in the compiled binary. This allows:

- Optimizing binary size by excluding unused features
- Building for specific deployment scenarios (edge, cloud, enterprise)
- Including optional integrations (cloud providers, HSM, post-quantum crypto)

The `WITH_*` names below are **Makefile variables**, not Go build tags. The
Makefile turns them into the Go tags in `BUILD_TAGS`. Set them on the `make`
command line, and print the resulting list with `make -s print-build-tags`.
The default list is:

```
iam rest quic mcp cluster gms_pure_go raft timeseries qrdb_ts pkcs8 frost local objstore codec_json codec_msgpack codec_cbor
```

### `GO_BUILD_TAGS`

ci-template v1.21 passes the repository's tag set to `make lint`, `build`,
`coverage`, `security` and `integration-test` as `GO_BUILD_TAGS`, space
separated (handbook `software/conventions/devcontainer.md` §6). The Makefile
appends it to `BUILD_TAGS` after every `WITH_*` append, so every `go build`,
`go test`, `go vet`, `TEST_BUILD_TAGS`, the integration runner and
`print-build-tags` see it. golangci-lint, gosec and govulncheck, which do not
read `BUILD_TAGS`, receive `GO_BUILD_TAGS` alone as `--build-tags`/`-tags`,
comma separated. Empty or unset, it changes nothing.

```
make -s print-build-tags GO_BUILD_TAGS='probe_a probe_b'
# ... codec_cbor probe_a probe_b
```

`make check-go-build-tags`, a prerequisite of `make test`, dry-runs (`make -n`)
each of those targets plus `test` with a probe tag and fails if the tag does
not reach a command.

**Important**: Native go-trusted-platform services (TPM, vTPM, attestation, device, SDN, DNS, etc.) have NO build tags. They are CORE features and are ALWAYS compiled into every build.

## Always-On Tags

`iam rest quic mcp cluster gms_pure_go` are in `BUILD_TAGS` unconditionally.
The platform needs them at runtime: a build without `iam` fails at startup with
"IAM service not enabled". `gms_pure_go` keeps go-mysql-server CGO-free.

`WITH_REST`, `WITH_QUIC`, `WITH_MCP` and `WITH_IAM` are still declared (default
1), but nothing reads them, so setting them to 0 changes nothing. Dropping one
of these tags means building with `-tags` directly.

## Feature Tags

Feature tags control which go-quicbaas services are included. A
quicbaas feature that rides on a qrdb engine also enables the matching
qrdb tag (qrdb's own tag names), so the engine is compiled in rather
than qrdb's feature-disabled stub: `WITH_TIMESERIES` adds
`timeseries qrdb_ts`, `WITH_VECTOR` adds `vector qrdb_vector`, and
`WITH_RAG` adds `rag qrdb_vector`.

| Variable | Default | Effect |
|-----------|---------|--------|
| `WITH_RAFT` | 1 | Raft consensus for clustering (`raft`) |
| `WITH_TIMESERIES` | 1 | TimeSeries service (`timeseries` + `qrdb_ts`) |
| `WITH_VECTOR` | 0 | Vector database service (`vector` + `qrdb_vector`) |
| `WITH_RAG` | 0 | RAG service (`rag` + `qrdb_vector`; requires `WITH_VECTOR=1`, or make stops with an error) |

A build with the vector tags also needs `quicbaas.vector.enabled: true` before
the embedded server serves the Vector service. Validate refuses that setting in
a build without the tags. Without the service, every call on the platform's SDK
client `Vector()` fails at once with `ErrVectorUnavailable`, whose reason names
the missing build or the disabled setting.

Integration builds (`TEST_BUILD_TAGS`, used by `make integration-test` and every
`make integration-test-<suite>`) always carry `vector qrdb_vector`, and
`quicbaas.TestConfig` enables the service in such a build. The factory's
Vector assertion (`TestFactory_SDKClient_VectorOperations` in
`pkg/storage/quicbaas`) is a unit test: `make test` runs it without the service
and asserts `ErrVectorUnavailable`; `make test-pkg PKG=./pkg/storage/quicbaas/
GO_BUILD_TAGS='vector qrdb_vector'` runs it against a real vector store.

## qrdb Optional Feature Tags

qrdb's optional engines and protocol frontends, OFF by default for the
platform (lean build — the default platform binary contains no SQL
engine, no MySQL/PostgreSQL/etcd wire frontends). The MySQL and
PostgreSQL frontends are engines over qrdb's SQL layer, so enabling
either implies `qrdb_sql`. SQL builds stay CGO-free via the always-on
`gms_pure_go` tag.

| Variable | Default | Effect |
|-----------|---------|--------|
| `WITH_QRDB_SQL` | 0 | qrdb SQL query engine (`qrdb_sql`; pkg/sql over go-mysql-server) |
| `WITH_QRDB_MYSQL` | 0 | MySQL wire frontend (`qrdb_mysql`, implies `qrdb_sql`) |
| `WITH_QRDB_PGSQL` | 0 | PostgreSQL wire frontend (`qrdb_pgsql`, implies `qrdb_sql`) |
| `WITH_QRDB_ETCD` | 0 | etcd v3 gRPC frontend (`qrdb_etcd`) |

## Cloud Provider Tags

Cloud provider tags enable integration with external cloud services. Disabled by default to minimize dependencies.

The three group variables switch on every per-service variable for their cloud:

| Variable | Default | Turns on |
|-----------|---------|--------|
| `WITH_AWS` | 0 | `WITH_AWS_KMS` (`awskms`), `WITH_OBJSTORE_S3` (`awss3`), `WITH_AWS_COMPUTE` (`awscompute`) |
| `WITH_GCP` | 0 | `WITH_GCP_KMS` (`gcpkms`), `WITH_OBJSTORE_GCS` (`gcpstorage`), `WITH_GCP_COMPUTE` (`gcpcompute`) |
| `WITH_AZURE` | 0 | `WITH_AZURE_KV` (`azurekv`), `WITH_OBJSTORE_AZURE` (`azureblob`), `WITH_AZURE_COMPUTE` (`azurecompute`) |
| `WITH_VAULT` | 0 | HashiCorp Vault (`vault`) |

Each per-service variable defaults to 0 and can be set on its own.
`WITH_OBJSTORE_MINIO` (`minio`) is the one storage backend outside the groups.
`WITH_OBJSTORE_LOCAL` defaults to 1 (`local`), and `objstore` is added whenever
any storage backend is on.

## Security/Crypto Tags

Security tags enable advanced cryptographic features.

| Variable | Default | Effect |
|-----------|---------|--------|
| `WITH_PKCS8` | 1 | PKCS#8 software key storage (`pkcs8`) |
| `WITH_TPM2` | 0 | TPM 2.0 key support (`tpm2`) |
| `WITH_PKCS11` | 0 | PKCS#11 HSM support (`pkcs11`, requires CGO) |
| `WITH_QUANTUM` | 0 | Post-quantum cryptography algorithms (`quantum`) |
| `WITH_FROST` | 1 | FROST threshold signatures, RFC 9591 (`frost`) |
| `WITH_FIPS` | 0 | FIPS 140-3 crypto implementations (`fips`; pair with `GODEBUG=fips140=only`). See [FIPS mode](../fips/engineering.md) |

## Messaging Protocol Tags

Messaging tags control which message broker protocols are included.

| Variable | Default | Effect |
|-----------|---------|--------|
| `WITH_MQTT` | 0 | MQTT over WebSocket (`quicbaas_mqtt`) |
| `WITH_AMQP` | 0 | AMQP over WebSocket (`quicbaas_amqp`) |
| `WITH_STOMP` | 0 | STOMP over WebSocket (`quicbaas_stomp`) |

## Service Embedding

There are no `WITH_QUICBAAS_EMBEDDED` or `WITH_XKMS_EMBEDDED` variables.
Nothing in the Makefile selects embedded or remote services.

## Codec Tags

Codec tags control which serialization formats are included.

| Variable | Default | Effect |
|-----------|---------|--------|
| `WITH_CODEC_JSON` | 1 | JSON codec (`codec_json`) |
| `WITH_CODEC_MSGPACK` | 1 | MessagePack codec (`codec_msgpack`) |
| `WITH_CODEC_CBOR` | 1 | CBOR codec (`codec_cbor`) |
| `WITH_CODEC_YAML` | 0 | YAML codec (`codec_yaml`) |
| `WITH_CODEC_TOML` | 0 | TOML codec (`codec_toml`) |
| `WITH_CODEC_BSON` | 0 | BSON codec (`codec_bson`) |
| `WITH_CODEC_PROTOBUF` | 0 | Protocol Buffers codec (`codec_protobuf`) |

## Cache Tags

Cache tags control additional caching layers.

| Variable | Default | Effect |
|-----------|---------|--------|
| `WITH_L2_REDIS` | 0 | Redis L2 cache (`l2_redis`) |

## Platform-Specific Tags

Platform-specific build tags used by the Makefile.

| Build Tag | Usage | Effect |
|-----------|-------|--------|
| `platform_web` | `WITH_WEB=1` | Embed web frontend into binary |
| `desktop` | `WITH_DESKTOP=1` | Build the desktop GUI into `platformctl` (requires Wails v2); only `cmd/platformctl` reads it |
| `platform_p2p` | `WITH_P2P=1` | Include P2P/libp2p networking support |
| `key_safety` | **Unavailable** | Would add the `platformctl kms` key-safety command (`pkg/cli/commands/kms/key_safety.go`), but a build with it fails: that file calls `SetKeySafety`, `GetKeySafety`, `ClearKeySafety`, `SafetyCheck` and `SafetyReport` (`key_safety.go:343,381,457,490,545`) on `platformv1.KeyManagementServiceClient` (`sdk/go/client.go:508`), and that interface (`sdk/go/gen/kms_grpc.pb.go:54`) declares none of them. Do not pass `GO_BUILD_TAGS=key_safety` until the platform KMS client supports those calls; no `WITH_*` variable sets it |

Some files are selected by the **absence** of a tag (`!iam`, `!cluster`,
`!fips`, `!awscompute`, `!azurecompute`, `!gcpcompute`, `!key_safety`,
`!platform_p2p`, `!platform_web`, `!desktop`). The tagged build never sees
them; the compile-everything target runs a second, untagged pass so they are
still compiled (see the comment above it in the `Makefile`).

## Build Examples

### Default Build (Development)

```bash
make build
# Or, outside make, with the same tag list:
go build -tags "$(make -s print-build-tags)" ./cmd/platformd
```

Never type the tag list by hand: a hand-written list drops the codec tags, and
the binary then fails with `no codec available for encoding`.

### Minimal Build

Turn off the optional features that are on by default:

```bash
make build WITH_RAFT=0 WITH_TIMESERIES=0 WITH_FROST=0
```

`WITH_RAFT=0` drops the embedded QuicBaaS: the Makefile marks raft "required
for embedded QuicBaaS". The test files tagged `//go:build raft` (for example
`pkg/storage/quicbaas/factory_test.go` and
`pkg/api/daemon/app_services_embedded_test.go`) are also left out of a
raft-free build.

### Cloud Deployment (AWS Backend)

```bash
make build WITH_AWS=1
```

### Enterprise Build

Build with all enterprise features including cloud providers and HSM support:

```bash
make build WITH_AWS=1 WITH_GCP=1 WITH_AZURE=1 WITH_VAULT=1 WITH_PKCS11=1 WITH_QUANTUM=1 WITH_L2_REDIS=1
```

### Without MCP (Non-AI Deployments)

The Makefile cannot drop MCP: `mcp` is an always-on tag (see Always-On Tags).

### With Embedded Web Frontend

Build with the web dashboard embedded in the binary:

```bash
WITH_WEB=1 make build
```

### With P2P Support

Build the gateway daemon with P2P/libp2p networking:

```bash
make build-gatewayd WITH_P2P=1
```

## Docker Build Arguments

The builder images in `build/docker/trusted-platform-builder/` take `WITH_WEB`
as a build argument:

```dockerfile
ARG WITH_WEB=false
```

Usage:

```bash
docker build --build-arg WITH_WEB=true -f build/docker/trusted-platform-builder/Dockerfile-alpine -t trusted-platform-builder:latest .
```

These images are build environments: they do not compile go-trusted-platform
(the Dockerfile's own note says so). `WITH_WEB=true` only copies the built web
frontend into `pkg/webserver/embed/dist`; nothing is compiled with
`platform_web` inside the image. Unlike the Makefile variable, which takes
`1`/`0`, the Docker argument takes `true`/`false`.

## Related Documentation

- [Service Endpoints Configuration](../daemon/configuration.md) - Configure service connections
- [Deployment Modes](../cluster/user.md) - Standalone, cluster, and mixed deployments
- [SDK Integration](../sdk/architecture.md) - Multi-transport support
