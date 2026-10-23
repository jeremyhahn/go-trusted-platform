# Trusted Registry — API

> **Status: NORMATIVE** · Scope: registry routes on every transport · Last verified: 2026-10-16
> Conflicts with this document are defects. Fix them here first.
> One row per capability, showing its form on each of the six transports. A
> transport that does not carry a capability is written `MISSING`, never
> omitted — omitting it hides the gap.

---

## 1. The six transports

The SDK declares exactly six protocols (`sdk/go/protocol.go`):

| Transport | Constant | How it reaches the daemon |
|---|---|---|
| Embedded | `ProtocolEmbedded` | In-process; gRPC method strings dispatched straight to service implementations (`sdk/go/transport/embedded/`) |
| Unix | `ProtocolUnix` | **gRPC over a Unix domain socket** (`sdk/go/transport/unix/adapter.go`) |
| gRPC | `ProtocolGRPC` | gRPC over TCP |
| REST | `ProtocolREST` | HTTP/HTTPS under `/api/v1` |
| QUIC | `ProtocolQUIC` | Binary opcode protocol over QUIC, MessagePack payloads |
| MCP | `ProtocolMCP` | JSON-RPC tools for AI/LLM clients |

**Unix is not a separate surface.** It is the same gRPC service set over a
socket instead of a TCP port, so any RPC in the gRPC column is available on Unix
with the same name and message types. Rows below therefore give gRPC and Unix
one column.

`ServiceRegistry.Registry` (`sdk/go/transport/embedded/adapter.go:50`) holds a
`platformv1.RegistryServiceServer`, so the embedded transport carries the whole
gRPC service.

---

## 2. Capability matrix

`RegistryService` is defined in `pkg/api/grpc/proto/registry.proto`. REST routes
are registered in `pkg/webservice/v1/rest/registry/router.go`; MCP tools in
`pkg/api/mcp/registry_tools.go`.

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| List images | `GET /api/v1/compute/images` | `RegistryService.List` | `MISSING — docs/13 G7` | `platform_registry_list` | `ServiceRegistry.Registry` |
| Inspect image | `GET /api/v1/compute/images/{repository}` (`Accept: application/json`) | `RegistryService.Inspect` | `MISSING — docs/13 G7` | `platform_registry_inspect` | `ServiceRegistry.Registry` |
| Pull image | `GET /api/v1/compute/images/{repository}` (`Accept: application/vnd.oci.image.layer.v1.tar` or `application/x-trusted-platform-image`) | `RegistryService.Pull` (server stream) | `MISSING — docs/13 G7` | **deliberately absent** (§4) | `ServiceRegistry.Registry` |
| Push image | `POST /api/v1/compute/images` (JSON envelope) | `RegistryService.Push` (client stream) | `MISSING — docs/13 G7` | **deliberately absent** (§4) | `ServiceRegistry.Registry` |
| Delete image | `DELETE /api/v1/compute/images/{repository}` | `RegistryService.Delete` | `MISSING — docs/13 G7` | `platform_registry_delete` | `ServiceRegistry.Registry` |
| Registry status | `GET /api/v1/compute/images/status` | `RegistryService.Status` | `MISSING — docs/13 G7` | `platform_registry_status` | `ServiceRegistry.Registry` |

`{repository}` is matched as `{repository:.+}` because OCI references contain
slashes (`registry.example.com/library/alpine:3.20`). The matched segment
includes any trailing `:tag`; the handler splits it.

`ListImages` and `PushImage` are each registered on both `""` and `"/"` so a
trailing slash does not 404.

**QUIC carries no registry opcode.** Grepped `pkg/api/quic/` on 2026-08-18: no
`Op*Registry*` or `Op*Image*` constant exists. Registry is a Tier 1 platform
capability, so this is a real six-transport hole and belongs in the gap register
as G7 (the platform re-export gap), not in a backlog nobody reads.

---

## 3. OCI Distribution v2 API

The registry also serves the standard OCI distribution API so unmodified
container tooling works against it. These routes are **REST only** — that is the
specification, not a gap. Registered in
`pkg/webservice/v1/rest/registry/ocidist.go`:

| Method | Path | Purpose |
|---|---|---|
| GET | `/v2` and `/v2/` | Version check |
| GET | `/v2/_catalog` | Repository catalog |
| GET | `/v2/{name}/tags/list` | Tag list for a repository |
| HEAD | `/v2/{name}/manifests/{reference}` | Manifest existence and digest |
| GET | `/v2/{name}/manifests/{reference}` | Fetch manifest |
| PUT | `/v2/{name}/manifests/{reference}` | Publish manifest |
| DELETE | `/v2/{name}/manifests/{reference}` | Delete manifest |
| POST | `/v2/{name}/blobs/uploads/` | Begin a blob upload |
| PATCH | `/v2/{name}/blobs/uploads/{uuid}` | Append to an upload |
| PUT | `/v2/{name}/blobs/uploads/{uuid}` | Complete an upload |
| DELETE | `/v2/{name}/blobs/uploads/{uuid}` | Cancel an upload |
| HEAD | `/v2/{name}/blobs/{digest}` | Blob existence |
| GET | `/v2/{name}/blobs/{digest}` | Fetch blob |

`{name}` is `{name:.+}` for the same slash reason. The distribution spec's
upload-cancel route (`DELETE /v2/{name}/blobs/uploads/{uuid}`) is also served,
so a client can release a session it abandons.

### Who may call `/v2` (#549)

Every `/v2` route is mounted behind a gate; nothing at the host root is public.
Two principals are admitted, the same two the attestation quote routes take
(`Router.RegisterRootRoutes`, `pkg/webservice/v1/router.go`):

- **A machine caller** presenting an mTLS identity chained to the platform
  anchors and admitted by the node's caller-admission policy
  (`pkg/attestation/calleradmission`). A refused machine caller is refused — it
  is not offered the operator path as a second chance. With no policy
  configured, no machine caller is admitted.
- **An operator** through the admin chain (`admin` role) when no client
  certificate is presented.

Reads (version check, catalog, tags, manifest and blob `GET`/`HEAD`) and writes
(manifest `PUT`/`DELETE`, uploads and cancels) are gated separately
(`OCIDistGates`), so the read policy can widen without widening writes. Today
both take the same principals.

`GET /v2/` answering `401` to an anonymous client is the spec's own signal that
the registry requires authentication; `docker login` and `crane auth` expect it.

### Upload bounds

Uploads are buffered in memory until committed, so they are capped
(`OCIDistLimits`, defaults in `DefaultOCIDistLimits`): manifest body 4 MiB, one
chunk 256 MiB, one blob 4 GiB, 8 GiB in flight across all sessions, and a
15-minute idle window after which a session is evicted and its bytes released.
A body over its cap answers `413`; a table at its in-flight cap answers `429`
with the spec's `TOOMANYREQUESTS` code; a digest mismatch on commit releases the
session, so a client restarts rather than keeping a rejected buffer pinned.

---

## 4. Deliberate omissions

`Push` and `Pull` are **not** exposed as MCP tools, and that is a decision, not
an oversight (`pkg/api/mcp/registry_tools.go`): binary blob transfer over
JSON-RPC is a poor fit, and both are already served by gRPC and REST. An LLM
client that needs image bytes calls those transports. Do not "complete" the MCP
surface by adding them. The SDK MCP transport follows suit: it maps the four
unary methods onto the four tools and no tool for `Push` or `Pull`
(`sdk/go/transport/mcp/registry.go`).

---

## 5. Authorization

Platform tokens carry an `scp` claim in the qrdb-canonical
`"<resource>:<action>"` form (e.g. `dns:write`), minted by the broker from the
subject's resolved permissions. Each transport enforces it per operation: gRPC
through the interceptor's `RequireScope`, QUIC through `AuthorizeRequest`, MCP
through `AuthorizeTool`.

Both catalogs are **default-deny**
([`docs/auth/architecture.md`](../auth/architecture.md)). **Every
`RegistryService` RPC carries a required scope** in the gRPC catalog
(`pkg/api/grpc/method_permissions.go`): `Inspect`, `List`, `Status` and `Pull`
need `registry:read`, `Push` needs `registry:write`, and `Delete` needs
`registry:delete`. The four `platform_registry_*` MCP tools carry their gRPC
twin's scope (#304, `pkg/api/mcp/authz.go`): `platform_registry_status`,
`platform_registry_list` and `platform_registry_inspect` need `registry:read`,
`platform_registry_delete` needs `registry:delete`. A caller without the scope
gets `PermissionDenied` (`-32003`) and the tool never runs. Registry artifacts
are platform-level: no transport scopes them to a tenant.

`VerifyClient` ([engineering.md](engineering.md) §2) is the platform-curated
API's attestation control. It does **not** run on the `/v2` path: the
distribution backend (`pkg/registry/ocidist_backend.go`) is storage plus state
checks, and until #549 nothing on that path verified anything — the earlier
revision of this section, which said `/v2` "authenticates by TPM attestation",
was wrong. Scope-based authorization and attestation are different controls,
and a reader must not assume the `scp` claim constrains what an attested client
may do to the registry.

### The two surfaces are gated differently, and deliberately (#165, #549)

`/api/v1/compute/images/**` — the platform-curated image surface: list, push,
delete and status — requires an authenticated caller holding `admin`. It is a
console surface and had no authentication at all before #165.

`/v2` — the machine protocol — takes the caller gate described in §3: an
attested machine identity, or an operator through the admin chain. It was
mounted bare on the root router until #549 on the false premise above.

The distinction to hold on to: `/compute/images` is a human-operated management
view of the registry, `/v2` is the machine protocol. They share a backend and
nothing else. The paragraph above about the `scp` catalog is unchanged by this
and remains an open question for the owner.

---

## 6. Status and error mapping

QUIC status bytes (`sdk/go/wire/quicwire/protocol.go`) are the platform's canonical
status vocabulary and the other transports map onto the same set:

| Byte | Name | REST | Registry cause |
|---|---|---|---|
| `0x00` | `StatusOK` | 200 | — |
| `0x01` | `StatusInvalidRequest` | 400 | `ErrInvalidImageRef`, `ErrInvalidManifest` |
| `0x02` | `StatusNotFound` | 404 | `ErrImageNotFound`, `ErrManifestNotFound`, `ErrBlobNotFound` |
| `0x03` | `StatusUnauthorized` | 401 | `ErrAttestationRequired`, `ErrInvalidSession` |
| `0x04` | `StatusInternalError` | 500 | Unclassified failure |
| `0x05` | `StatusTimeout` | 504 | `ErrOperationTimeout` |
| `0x06` | `StatusAlreadyExists` | 409 | `ErrImageExists` |
| `0x07` | `StatusPermissionDenied` | 403 | `ErrAccessDenied`, `ErrPCRMismatch`, `ErrAIKNotAllowed` |
| `0x08` | `StatusResourceExhausted` | 429 | Concurrency limits exceeded |
| `0x09` | `StatusInvalidArgument` | 400 | `ErrInvalidDigest` |
| `0x0A` | `StatusUnavailable` | 503 | Registry service not wired into the daemon |
| `0x0B` | `StatusNotImplemented` | 501 | — |

Payloads are capped at `MaxPayloadSize` (16 MiB) and auth tokens at
`MaxTokenSize` (8 KiB) on QUIC.

**503 is meaningful.** When the daemon starts without a registry service, every
REST route returns 503 with a structured "not configured" envelope rather than
404 or 500, so an operator can distinguish a disabled feature from a broken one.

**MCP answers with the REST and QUIC classes** (`pkg/api/daemon/mcp_registry.go`,
#304): an unwired registry is `Unavailable` (`ErrRegistryNotConfigured`; gRPC
says `FailedPrecondition`), a missing `repository` or `reference` is
`InvalidArgument`, and a service error, wrapped in `ErrRegistryServiceFailed`,
takes the code `grpcapi.RegistryErrorStatus` gives it on gRPC — an unknown
artifact is `NotFound`, and a reference outside the OCI distribution-spec
grammar (`ErrInvalidImageRef`, carried across the adapter as
`grpcapi.ErrInvalidArtifactReference`) is `InvalidArgument` on gRPC, Unix and
MCP (JSON-RPC invalid params) and 400 on REST.

**A `/v2` path no route claims returns a JSON 404, not the web console.** The
SPA catch-all declines the whole `/v2/` namespace along with the other API
namespaces (`webserver_v1.go` `apiPathPrefixes`; see
[`docs/bootstrap/api.md`](../bootstrap/api.md) §2). The body is the platform's
`{error, path, message}` envelope rather than the OCI `errors` array — a
spec-shaped registry 404 for unmounted paths would be a separate change.

---

## 7. Pagination

`List` is the only unbounded result set. It is cursor-paginated: the SDK client
signature is
`List(ctx, repository string, limit int32, cursor, sortBy string, ascending bool)`
(`sdk/go/services/registry/client.go:64`), and the CLI surfaces the same
parameters as `--repository`, `--cursor`, `--sort-by` and `--sort-desc`.

`platform_registry_list` carries the whole `ListArtifactsRequest`:
`repository`, `artifact_type`, `limit`, `offset`, `cursor`, `sort_by`,
`ascending`, and the label selector as `match_labels` (object) and
`match_expressions` (array). The SDK MCP transport sends each of them, so a
cursor page over MCP is the same page as over gRPC.

The OCI `_catalog` and `tags/list` routes follow the distribution spec's own
`n`/`last` pagination, which is a different scheme; do not conflate them.

---

## 8. Versioning

Platform routes are under `/api/v1` and the gRPC package is `platform.v1`. The
OCI routes are under `/v2`, which is the **distribution specification's**
version, unrelated to the platform's. Nothing in the registry surface is
deprecated as of 2026-08-18.

---

## 9. SDK client

`sdk/go/services/registry` exposes `Status`, `List`, `Inspect` and `Delete`
directly, plus `GRPCClient()` for the generated client. `Push` and `Pull` are
reachable only through `GRPCClient()` because they are streaming RPCs — a
convenience wrapper for streaming has not been written. That is a smaller,
separate gap from the QUIC hole in §2 and should not be conflated with it.
