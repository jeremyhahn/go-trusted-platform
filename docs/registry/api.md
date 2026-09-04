# Trusted Registry — API

> **Status: NORMATIVE** · Scope: registry routes on every transport · Last verified: 2026-08-18
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
| HEAD | `/v2/{name}/blobs/{digest}` | Blob existence |
| GET | `/v2/{name}/blobs/{digest}` | Fetch blob |

`{name}` is `{name:.+}` for the same slash reason. The attestation gate applies
to these routes exactly as it does to the `/api/v1` routes — an unattested
`docker pull` fails.

---

## 4. Deliberate omissions

`Push` and `Pull` are **not** exposed as MCP tools, and that is a decision, not
an oversight (`pkg/api/mcp/registry_tools.go`): binary blob transfer over
JSON-RPC is a poor fit, and both are already served by gRPC and REST. An LLM
client that needs image bytes calls those transports. Do not "complete" the MCP
surface by adding them.

---

## 5. Authorization

Platform tokens carry an `scp` claim in the qrdb-canonical
`"<resource>:<action>"` form (e.g. `dns:write`), minted by the broker from the
subject's resolved permissions. Each transport enforces it per operation: gRPC
through the interceptor's `RequireScope`, QUIC through `AuthorizeRequest`, MCP
through `AuthorizeTool`.

**No registry method carries a required scope.** The gRPC catalog
(`pkg/api/grpc/method_permissions.go`) maps 185 methods across 11 services —
`CAService`, `DeviceService`, `DNSService`, `GatewayService`,
`KeyManagementService`, `NTPService`, `PlatformIAMService`, `ProxyService`,
`SDNService`, `VTPMService` and one daemon method. `RegistryService` is not
among them, and the catalog's own doc comment states that **a method absent from
the map carries no required scope**: the interceptor allows it once the token is
validated.

In practice the registry is not unguarded — TPM attestation is its
authentication method and `VerifyClient` runs ahead of every path (see
[engineering.md](engineering.md) §2). But scope-based authorization and
attestation are different controls, and a reader must not assume the `scp` claim
constrains what an attested client may do to the registry. **Whether
`RegistryService` should join the scope catalog is an open question for the
owner**, recorded in the migration report; it is not decided here.

### The two surfaces are gated differently, and deliberately (#165)

`/api/v1/compute/images/**` — the platform-curated image surface: list, push,
delete and status — requires an authenticated caller holding `admin`. It is a
console surface and had no authentication at all before #165.

**`/v2` is not gated by that change and must not be.** The OCI Distribution
surface is mounted at the host root by `pkg/webservice/webserver_v1.go` and
authenticates by **TPM attestation** (`VerifyClient`, [engineering.md](engineering.md)
§2), which is the registry's own auth method and this platform's whole point.
Putting a role gate in front of it would demand a bearer token from a client
whose credential is a quote.

The distinction to hold on to: `/compute/images` is a human-operated management
view of the registry, `/v2` is the machine protocol. They share a backend and
nothing else. The paragraph above about the `scp` catalog is unchanged by this
and remains an open question for the owner.

---

## 6. Status and error mapping

QUIC status bytes (`pkg/api/quic/protocol.go`) are the platform's canonical
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
