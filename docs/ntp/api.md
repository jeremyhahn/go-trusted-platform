# Time Synchronization — API

> **Status: NORMATIVE** · Scope: NTP capabilities on every transport · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING — docs/13 G7`, never omitted.

---

## 1. The six transports

The transport model, the QUIC frame format, the canonical status bytes and the
platform-wide authorization picture live in
[`docs/daemon/api.md`](../daemon/api.md) and are not repeated here.
`sdk/go/protocol.go` declares `ProtocolEmbedded`, `ProtocolUnix`,
`ProtocolGRPC`, `ProtocolREST`, `ProtocolQUIC`, `ProtocolMCP`, and **Unix is
gRPC over a Unix domain socket**, so gRPC and Unix share a column.

For NTP:

- **gRPC**: `platform.v1.NTPService`, **3 RPCs**
  (`pkg/api/grpc/proto/ntp.proto`, implemented by
  `pkg/api/daemon/ntp_grpc_service.go`).
- **REST**: base path `/api/v1/ntp`, served by **two independent routers** —
  see §2.
- **QUIC**: `OpNTPCategory` (`0x50`) with the sub-operation in `payload[0]`,
  dispatched by `handleNTPCategory` (`pkg/api/daemon/quic_ntp.go`).
- **MCP**: `ntp_status`, `ntp_sources`, `ntp_step`
  (`pkg/api/mcp/ntp_tools.go`).
- **Embedded**: **no route.** `ServiceRegistry`
  (`sdk/go/transport/embedded/adapter.go`) has no `NTP` field.

**One implementation backs all of them.** `NTPGRPCService` is registered on the
TCP gRPC server and the Unix-socket gRPC server, handed to the QUIC handler and
both REST routers, and reached by the MCP tools — so semantics and error
mapping are identical everywhere by construction, not by convention.

## 2. Two REST routers serve the same three paths

| Router | File | Mounted on |
|---|---|---|
| `restntp.NTPRouter` | `pkg/webservice/v1/rest/ntp/router.go` | the webservice listener, via `pkg/webservice/v1/router.go` |
| `rest.NTPHandlers` | `pkg/api/rest/ntp_handlers.go` | the daemon's own REST listener |

Both expose `GET /api/v1/ntp/status`, `GET /api/v1/ntp/sources` and
`POST /api/v1/ntp/step`, both call the same `NTPServiceServer`, and both encode
the message with `protojson` under identical options
(`UseProtoNames: false`, `EmitUnpopulated: true`). The paths match by design —
`ntpBasePath` is hard-coded to `/api/v1/ntp` in the daemon handler
*"so a client sees the same URLs regardless of which listener it reaches"* —
and the status mapping is duplicated to match: `ntpGRPCToHTTPStatus` in the
daemon handler mirrors `protorest`'s switch.

**The envelopes differ, and this is the one place the two listeners are not
interchangeable.** The daemon listener writes the protojson document as the
whole body:

```json
{ "status": { "synced": true, "stratum": 3, ... } }
```

The webservice listener wraps it in the standard `WebServiceResponse` envelope
(`sdk/go/wire/restwire/envelope.go`, written by `pkg/webservice/v1/response`):

```json
{ "code": 200, "error": "", "success": true, "payload": { "status": { "synced": true, ... } } }
```

A client that hard-codes one shape breaks against the other. The comment in
`pkg/api/rest/ntp_handlers.go` claiming both listeners *"emit byte-identical
payloads"* is true of the marshalled message and not of the response body.

When the backing server is nil, both answer **503**:
`protorest.ErrServiceUnavailable{Service: "ntp"}` on the webservice side,
`ErrNTPUnavailable{}` (`"ntp service is not configured on this node"`) on the
daemon side.

## 3. Capabilities

| Capability | Embedded (Go) | Unix | REST | gRPC | QUIC | MCP |
|---|---|---|---|---|---|---|
| **Get sync status** | `MISSING — docs/13 G7` (no `ServiceRegistry.NTP`); in-process `ntp.Service.Status(ctx)` | `platform.v1.NTPService/GetStatus` | `GET /api/v1/ntp/status` | `platform.v1.NTPService/GetStatus` | `OpNTPCategory` `0x50` + `NTPSubGetStatus` `0x01` | `ntp_status` |
| **List time sources** | `MISSING — docs/13 G7`; in-process `ntp.Service.Sources(ctx)` | `platform.v1.NTPService/ListSources` | `GET /api/v1/ntp/sources` | `platform.v1.NTPService/ListSources` | `0x50` + `NTPSubListSources` `0x02` | `ntp_sources` |
| **Step the clock** | `MISSING — docs/13 G7`; in-process `ntp.Service.Step(ctx)` | `platform.v1.NTPService/Step` | `POST /api/v1/ntp/step` | `platform.v1.NTPService/Step` | `0x50` + `NTPSubStep` `0x03` | `ntp_step` |
| **Apply configuration** (render `chrony.conf`, enable and restart chronyd) | `ntp.Service.Apply(ctx)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| **Wait for the startup gate** | `ntp.Service.WaitForSync(ctx)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| **Read the cached last status** (no poll) | `ntp.Service.LastStatus()` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| **Clock trustworthiness as a health component** | via `pkg/health` | see [`docs/health/api.md`](../health/api.md) | ditto | ditto | ditto | ditto |

Two gaps worth naming:

**NTP is absent from the embedded transport.** `ServiceRegistry` has no `NTP`
field, so `platformctl --transport embedded ntp status` cannot reach the
service, and an in-process SDK consumer has no NTP client. The in-process route
that exists is a direct `*ntp.Service` call, which is not the SDK boundary.

**Configuration application has no remote surface at all.** `Apply` and
`WaitForSync` are bring-up-only Go calls. Changing a node's time configuration
means editing the `ntp:` section and restarting platformd — there is no
"reload NTP" verb on any transport, and no `chrony.conf` render preview.

## 4. Request and response schemas

All three requests are **empty messages**: `GetNTPStatusRequest`,
`ListNTPSourcesRequest`, `StepNTPClockRequest`. There are no parameters, no
filters and no pagination anywhere in this surface — the source list is bounded
by the configuration.

Because the requests are empty, **the SDK's QUIC adapter sends only the
sub-opcode byte** and `handleNTPCategory` tolerates a zero-length sub-payload.

### `platform.v1.NTPStatus`

Returned inside `GetNTPStatusResponse.status` and `StepNTPClockResponse.status`.

| Field | Type | From `ntp.Status` |
|---|---|---|
| `synced` | bool | `Synced` |
| `stratum` | uint32 | `Stratum` |
| `leap_status` | string | `LeapStatus` |
| `offset_seconds` | double | `OffsetSeconds` |
| `root_dispersion` | double | `RootDispersion` |
| `root_delay` | double | `RootDelay` |
| `last_sync_unix` | int64 | `LastSync.Unix()`, **`0` when never** |
| `mode` | string | `Mode` |
| `reference_id` | string | `ReferenceID` |
| `reference_name` | string | `ReferenceName` |
| `sources_reachable` | uint32 | `SourcesReachable` |
| `sources_total` | uint32 | `SourcesTotal` |
| `anomaly` | bool | `Anomaly` |
| `anomaly_reason` | string | `AnomalyReason` |
| `serve_name_findings` | repeated `NTSServeNameFinding` | `ServeNameFindings`; **absent** when there is no mismatch |

**`last_sync_unix` is seconds, not RFC 3339, and `0` means "never".** That is
the one field clients get wrong.

### `platform.v1.NTSServeNameFinding`

One advertised NTS-KE server name clients cannot usefully dial (#509). It is
a serving-side misconfiguration, **not** a statement about this node's own
clock — `synced` can be true beside it.

| Field | Type | Meaning |
|---|---|---|
| `kind` | string | `nts-name-unreachable` or `nts-name-unresolvable`; the stable marker monitoring keys on |
| `name` | string | the `serve.nts.server-names` entry |
| `address` | string | where the name resolved. **Empty** for `nts-name-unresolvable` |
| `listen_networks` | repeated string | the allow list as rendered. **Empty** for `nts-name-unresolvable` |
| `error` | string | the resolver's own words, for `nts-name-unresolvable` |

The two kinds are different claims and are never collapsed:

- `nts-name-unreachable` — the name resolved and this node's allow list
  refuses the address; the client completes the NTS-KE handshake and is then
  refused time.
- `nts-name-unresolvable` — the name did not resolve here at all. Nodes
  forward the internal zone through the control plane, so a name it cannot
  resolve is one no client can reach. It has no address, so it is never
  reported as an allow-list refusal.

Populated at NTP bring-up and at each NTS certificate renewal, never on a
status poll.

### `platform.v1.NTPSource`

Returned as a repeated field in `ListNTPSourcesResponse.sources`.

| Field | Type | Notes |
|---|---|---|
| `address` | string | |
| `mode` | string | `server`, `peer`, `refclock`, `unknown` |
| `state` | string | `selected`, `combined`, `excluded`, `unreachable`, `falseticker`, `jittery`, `unknown` |
| `stratum` | uint32 | |
| `poll_seconds` | uint32 | Already decoded from chrony's log2 form |
| `reach` | uint32 | The 8-bit reachability register; `255` = last eight polls succeeded |
| `last_rx_seconds` | int64 | |
| `offset_seconds` | double | |
| `reachable` | bool | `reach != 0` |

### REST bodies

`protojson` with `EmitUnpopulated: true` and **lowerCamelCase** field names
(`UseProtoNames: false`) on both listeners, so absent values appear as zeros
rather than being omitted, and the proto field `last_sync_unix` appears on the
wire as `lastSyncUnix`.

| Route | Marshalled message |
|---|---|
| `GET /api/v1/ntp/status` | `{"status": {…NTPStatus…}}` |
| `GET /api/v1/ntp/sources` | `{"sources": [{…NTPSource…}, …]}` |
| `POST /api/v1/ntp/step` | `{"status": {…NTPStatus…}}` |

Wrapped in the `WebServiceResponse` envelope on the webservice listener; raw on
the daemon listener — see §2.

`POST /api/v1/ntp/step` takes **no request body**.

### QUIC frames

Request: opcode `0x50`, `payload[0]` = sub-opcode, `payload[1:]` = the
MessagePack-encoded `platform.v1` request (empty for all three).
Response: the MessagePack-encoded `platform.v1` response message.

**The protobuf messages are the wire contract**, and MessagePack keys on Go
**field names**, which is what keeps client and server in lockstep.

## 5. Status and error mapping

One domain error set, mapped once (`ntpErrToGRPC`), projected onto each
transport:

| Domain error | gRPC | REST | QUIC |
|---|---|---|---|
| `ntp.ErrDisabled`, `daemon.ErrNTPNotConfigured` | `Unavailable` | **503** | `StatusUnavailable` (`0x0A`) |
| `ntp.ErrControlUnavailable` (chronyd unreachable) | `Unavailable` | **503** | `StatusUnavailable` (`0x0A`) |
| `ntp.ErrNoReachableSource` (from `Step`) | `Aborted` | **409** | `StatusAlreadyExists` (`0x06`) |
| `ntp.ErrSyncTimeout` | `DeadlineExceeded` | **504** | `StatusTimeout` (`0x05`) |
| `ntp.ErrMalformedControlOutput` | `Internal` | **500** | `StatusInternalError` (`0x04`) |
| anything else | `Internal` | **500** | `StatusInternalError` (`0x04`) |
| unknown sub-opcode | — | — | `StatusNotImplemented` (`0x0B`) |
| empty QUIC payload (no sub-opcode) | — | — | `StatusInvalidRequest` (`0x01`) |
| NTP service not wired into the QUIC handler | — | — | `StatusUnavailable` (`0x0A`) |

`ntpQUICStatus` also maps `InvalidArgument` → `StatusInvalidArgument`,
`NotFound` → `StatusNotFound`, `PermissionDenied` → `StatusPermissionDenied`,
`Unimplemented` → `StatusNotImplemented`, `ResourceExhausted` →
`StatusResourceExhausted`, with `StatusInternalError` as the fallback for any
code not in the map.

Two things to read out of that table:

**503 means "not configured" or "chronyd is not answering", never
"unimplemented".** A node with no `ntp:` section returns a typed `Unavailable`
error with the message `ntp service is not configured on this node` — it never
returns `Unimplemented`, and it never panics.

**409 on `step` is the documented contract for "nothing to step towards."**
`Aborted` is chosen specifically because it maps to Conflict in both REST
listeners. Note that `pkg/webservice/v1/rest/ntp/router.go`'s doc comment says
`FailedPrecondition` here; that is wrong — see
[engineering.md](engineering.md) §7.

## 6. Authorization

**NTPService is fully scoped in the default-deny gRPC scope catalog**
(`pkg/api/grpc/method_permissions.go`) — all three RPCs are mapped:

| Method | Scope |
|---|---|
| `/platform.v1.NTPService/GetStatus` | `ntp:read` |
| `/platform.v1.NTPService/ListSources` | `ntp:read` |
| `/platform.v1.NTPService/Step` | **`ntp:write`** |

**MCP coverage is likewise complete** (`pkg/api/mcp/authz.go`):

| Tool | Scope |
|---|---|
| `ntp_status` | `ntp:read` |
| `ntp_sources` | `ntp:read` |
| `ntp_step` | **`ntp:write`** |

Both catalogs are default-deny ([`docs/daemon/api.md`](../daemon/api.md) §5),
and both cover every NTP operation, so no NTP call is refused for want of a
classification.

QUIC enforcement goes through `AuthorizeRequest` on the same `scp` claims. The
daemon REST listener checks the same scope per route through
`restapi.ScopeGuard` (#584): `ntp:read` on status and sources, `ntp:write` on
step, from a platform token's `scp` or from the verified mTLS client
certificate admitted as the operator (`*:*`). No credential is 401, a missing
scope 403, and handlers built without a guard refuse every route
([`docs/daemon/api.md`](../daemon/api.md)). The webservice applies its own
middleware chain to `/api/v1`, below.

`ntp:write` gates exactly one operation — `Step` — because it is the only one
that mutates the system clock. The scope split is the reason `Step` is a
separate RPC rather than a flag on `GetStatus`.

### REST is gated on the `admin` role (#165)

`/api/v1/ntp/**` requires an authenticated caller holding `admin`, including
`POST /ntp/step`.

The reason `step` matters more than its size suggests is stated in
[user.md](user.md): a node whose clock is wrong fails attestation, ACME
issuance and token validation **without any of those failures naming the
clock**. An anonymous caller able to step the clock therefore has a
denial-of-service primitive whose symptoms point everywhere except at the
cause.

This changes the REST position only. The gRPC, Unix, MCP and embedded
positions described above are unchanged. See
[`docs/auth/architecture.md`](../auth/architecture.md) §6c.

## 7. Versioning and deprecation

REST under `/api/v1`; gRPC package `platform.v1`; QUIC `ProtocolVersion`
`0x01`. Nothing in this surface is deprecated.

**Opcode note.** `OpNTPCategory` = `0x50` reclaims the head of the
never-implemented `OpProv*` range (the provisioning surface actually ships under
`OpProvisioningCategory`, `0xCF`). `0x51` is `OpIAMCategory` (IAM tenant records, #767); `0x52`–`0x55` are
reserved for NTP growth.
The same reclamation precedent applies to `OpAttestCollectHost` and
`OpVMExtendedCategory` — see [`docs/daemon/api.md`](../daemon/api.md) §4 for why
opcode values repeat across categories.

## 8. Related

- [`docs/health/api.md`](../health/api.md) — the `ntp` health component, and the
  only NTP signal that reaches an unauthenticated probe
- [`docs/daemon/api.md`](../daemon/api.md) — transports, QUIC frame format,
  status bytes, platform-wide authorization
- The legacy per-transport files in this folder — `api-reference.md`,
  `api-reference-rest.md`, `api-reference-grpc.md`, `api-reference-quic.md`,
  `api-reference-mcp.md`, `api-reference-unix.md` — predate this convention.
  **This file supersedes them**; where they disagree, this file is verified
  against code and they are not.
