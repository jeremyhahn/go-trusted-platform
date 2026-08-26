# Platform Daemon — API

> **Status: NORMATIVE** · Scope: daemon routes on every transport; the platform's transport model · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
>
> **This file carries the canonical QUIC category-opcode table (§4).** Other
> feature folders link here rather than repeating it.

---

## 1. The six transports

`sdk/go/protocol.go` declares exactly six protocol constants:

| Transport | Constant | Mechanism |
|---|---|---|
| Embedded | `ProtocolEmbedded` | In-process; gRPC method strings dispatched straight to service implementations via an O(1) map (`sdk/go/transport/embedded/`) |
| Unix | `ProtocolUnix` | **gRPC over a Unix domain socket** (`sdk/go/transport/unix/adapter.go`) |
| gRPC | `ProtocolGRPC` | gRPC over TCP |
| REST | `ProtocolREST` | HTTP/HTTPS under `/api/v1` |
| QUIC | `ProtocolQUIC` | Binary opcode protocol over QUIC, MessagePack payloads |
| MCP | `ProtocolMCP` | JSON-RPC tools over stdio or HTTP |

**Unix is not a separate service surface** — it is the same gRPC service set over
a socket. Any gRPC RPC is available on Unix under the same name.

**The embedded transport's reach is bounded by `ServiceRegistry`**
(`sdk/go/transport/embedded/adapter.go:32`), which has **22 fields**: Daemon, CA,
TPM, VTPM, Device, IAM, KMS, SDN, Compute, IDevID, Attestation, Tenant, PXE,
DNS, Gateway, Proxy, Overlay, Registry, Cluster, EAB, Invitation and
ConfigDelivery. Anything not in that list has **no embedded route** —
`SwitchService` is the notable absentee ([`docs/sdn/api.md`](../sdn/api.md) §7).

`/api/v1/platform/protocols` reports which transports are actually serving.

---

## 2. Daemon capabilities

gRPC: `PlatformDaemon`, 17 RPCs (`pkg/api/grpc/proto/daemon.proto`).
REST: `/api/v1/platform` (`pkg/webservice/v1/rest/platform/router.go`).
MCP: eleven tools.

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Status | `GET /api/v1/platform/status` | `GetStatus` | `MISSING — docs/13 G7` | `platform_daemon_status` | ✅ |
| Health | `GET /api/v1/platform/health` | `GetHealth` | `OpHealth` (`0x00`) | `platform_health` | ✅ |
| Liveness | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpLiveness` (`0x01`) | `platform_liveness` | — |
| Readiness | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpReadiness` (`0x02`) | `platform_readiness` | — |
| Version | `GET /api/v1/platform/version` | `GetVersion` | `MISSING — docs/13 G7` | `platform_daemon_version` | ✅ |
| System info | `GET /api/v1/platform/system` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | — |
| **Shutdown** | `MISSING — docs/13 G7` | `Shutdown` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| Get config | `GET /api/v1/platform/config` | `GetConfig` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| Update config | `MISSING — docs/13 G7` | `UpdateConfig` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| Reload config | `POST /api/v1/platform/config/reload` | `ReloadConfig` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| **Validate config** | `POST /api/v1/platform/config/validate` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | — |
| List services | `GET /api/v1/platform/services` | `ListServices` | `MISSING — docs/13 G7` | `platform_daemon_list_services` | ✅ |
| Get service | `GET /api/v1/platform/services/{service}` | `GetServiceStatus` | `MISSING — docs/13 G7` | `platform_daemon_get_service` | ✅ |
| Start service | `POST /api/v1/platform/services/{service}/start` | `StartService` | `MISSING — docs/13 G7` | `platform_daemon_start_service` | ✅ |
| Stop service | `POST /api/v1/platform/services/{service}/stop` | `StopService` | `MISSING — docs/13 G7` | `platform_daemon_stop_service` | ✅ |
| Restart service | `POST /api/v1/platform/services/{service}/restart` | `RestartService` | `MISSING — docs/13 G7` | `platform_daemon_restart_service` | ✅ |
| List protocols | `GET /api/v1/platform/protocols` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `platform_daemon_list_protocols` | — |
| Metrics | `GET /api/v1/platform/metrics` | `StreamMetrics` (stream) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| Query logs | `GET /api/v1/platform/logs` | `StreamLogs` (stream) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| List log services | `GET /api/v1/platform/logs/services` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | — |
| Stream logs | `GET /api/v1/platform/logs/stream` | `StreamLogs` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| Stream events | `MISSING — docs/13 G7` | `StreamEvents` (stream) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| List entity types | `MISSING — docs/13 G7` | `ListEntityTypes` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| Dump entity type | `MISSING — docs/13 G7` | `DumpEntityType` (stream) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |

**QUIC carries only three daemon opcodes** — health, liveness and readiness at
`0x00`–`0x02`. Everything else about running the daemon is REST, gRPC, MCP or
embedded.

---

## 3. Configuration snapshots — REST only

| Method | Path |
|---|---|
| GET | `/api/v1/platform/config/snapshots` |
| POST | `/api/v1/platform/config/snapshots` |
| GET | `/api/v1/platform/config/snapshots/{id}` |
| DELETE | `/api/v1/platform/config/snapshots/{id}` |
| POST | `/api/v1/platform/config/snapshots/{id}/rollback` |

Plus `POST /api/v1/platform/config/validate`.

**This is the platform's configuration undo, and it exists on REST alone.** On a
system that programs a datapath and enforces attestation policy, a bad
configuration change is the most likely way to lose access — snapshot before
changing, validate before applying, roll back if wrong.

---

## 4. The QUIC protocol — canonical reference

### Frame constants (`pkg/api/quic/protocol.go`)

| Constant | Value |
|---|---|
| `ProtocolVersion` | `0x01` |
| `MaxPayloadSize` | 16 MiB |
| `MaxTokenSize` | 8 KiB |

### Status bytes — the platform's canonical status vocabulary

| Byte | Name | REST |
|---|---|---|
| `0x00` | `StatusOK` | 200 |
| `0x01` | `StatusInvalidRequest` | 400 |
| `0x02` | `StatusNotFound` | 404 |
| `0x03` | `StatusUnauthorized` | 401 |
| `0x04` | `StatusInternalError` | 500 |
| `0x05` | `StatusTimeout` | 504 |
| `0x06` | `StatusAlreadyExists` | 409 |
| `0x07` | `StatusPermissionDenied` | 403 |
| `0x08` | `StatusResourceExhausted` | 429 |
| `0x09` | `StatusInvalidArgument` | 400 |
| `0x0A` | `StatusUnavailable` | 503 |
| `0x0B` | `StatusNotImplemented` | 501 |

### Category opcodes — read this before writing any QUIC client

The opcode is a **single byte** with a **two-level extension**: certain values
are *category* opcodes whose sub-opcode is carried in the payload, and the daemon
routes them to a dedicated handler (`pkg/api/daemon/quic_service.go`). Sixteen
distinct values, seventeen names:

| Opcode | Category | Notes |
|---|---|---|
| `0x2E` | `OpOverlayCategory` | VXLAN/EVPN overlay |
| `0x2F` | `OpGatewayCategory` | Edge gateway. **Sub-opcodes `0x20`–`0x2D` route to the proxy handler**; zone ops at `0x10`–`0x14`; perf at `0x36`–`0x38` |
| `0x2F` | `OpProxyCategory` | **An alias of `OpGatewayCategory`**, not a separate value |
| `0x3F` | `OpIPAMCategory` | IPAM |
| `0x50` | `OpNTPCategory` | Time synchronisation |
| `0x69` | `OpVMExtendedCategory` | VM operational sub-opcodes (`0xCC`–`0xD0`) |
| `0x99` | `OpTPM2Category` | Physical TPM |
| `0x9A` | `OpCeremonyCategory` | Phase 3.5 |
| `0x9B` | `OpPIVCategory` | Phase 3.5 |
| `0x9C` | `OpLUKSCategory` | Phase 3.5 |
| `0x9D` | `OpFIDO2Category` | Phase 3.5 |
| `0x9E` | `OpTenantBarrierCategory` | Per-tenant barrier |
| `0x9F` | `OpBMCCategory` | BMC enrollment |
| `0xCC` | `OpSwitchCategory` | Physical switch; sub-opcodes `SwitchSub*` `0x01`–`0x05` |
| `0xCD` | `OpKMSExtendedCategory` | KMS key-lifecycle verbs |
| `0xCE` | `OpSecretsCategory` | Secrets |
| `0xCF` | `OpProvisioningCategory` | Provisioning / config delivery |

**This is why opcode values repeat.** `OpOverlayStatus`, `OpGatewayStatus` and
`OpLiveness` are all `0x01`: the first two are sub-opcodes inside their category,
the third is a top-level opcode. A client sending `0x01` at top level gets a
liveness check. Likewise `OpVMMetrics` (`0xCC` under `0x69`) and
`OpSwitchCategory` (`0xCC` at top level) are unrelated.

`pkg/api/quic/vm_ops_opcodes.go` documents the rule for its own range: values
*"live in the 0x69 sub-opcode namespace and only need to be unique among the
sub-opcodes routed under that category"*.

### Two dead opcode names

`OpAttestGetReport` (`0x76`) and `OpAttestGetPCRs` (`0x77`) are shadowed by
`OpAttestGetManifest` and `OpAttestGetReportByID` at the same values, and the
handler dispatches on the latter pair. **Both dead names are still in the
`OpcodeNames` table**, so logs mislabel those two operations. See
[`docs/attestation/api.md`](../attestation/api.md) §4.

### Panics do not drop connections

`pkg/api/quic/server.go` recovers a panicking handler into
`StatusInternalError` and logs the stack, *"so the client never sees a bare EOF
from a panicking handler."* gRPC has the equivalent in
`pkg/api/daemon/recovery_interceptor.go`.

---

## 5. Authorization — the platform-wide picture

Platform tokens carry an `scp` claim in the qrdb-canonical
`"<resource>:<action>"` form, minted by the broker from the subject's resolved
permissions. Enforcement is per operation: gRPC `RequireScope`, QUIC
`AuthorizeRequest`, MCP `AuthorizeTool`.

Two catalogs, both **default-allow**:

| Catalog | Coverage | Default for an unlisted entry |
|---|---|---|
| gRPC (`pkg/api/grpc/method_permissions.go`) | **185 of 461 RPCs**, across 11 of 31 services | *"carries no required scope: the interceptor allows it once the token is validated"* |
| MCP (`pkg/api/mcp/authz.go`) | **71 of 449 declared tool names** | `AuthorizeTool` returns no error — *"Unknown tool - let the tool registry handle the error"* |

Services **in** the gRPC catalog: `CAService` (12), `DeviceService` (21),
`DNSService` (13), `GatewayService` (9 of 24), `KeyManagementService` (23),
`NTPService` (3), `PlatformIAMService` (41), `ProxyService` (14),
`SDNService` (25), `VTPMService` (23), and one daemon method.

Services **not** in it include `PlatformDaemon` (16 of 17 RPCs, among them
`Shutdown`, `UpdateConfig` and `StopService`), `ComputeService`,
`AttestationService`, `RegistryService`, `TenantService`, `ClusterService`,
`PXEService`, `ConfigDeliveryService`, `BMCService`, `OverlayService`,
`SwitchService`, `TPMService`, `IDevIDService`, `EABService` and
`InvitationService`.

MCP's 71 covered tools are the vtpm, dns, device, profile, gateway-lb,
gateway-perf, sdn, proxy and ntp families only. Not covered: **ca, kms, secrets,
iam, compute, attestation, registry, tenant, pxe, provision, bmc, tpm, cluster,
eab, invitation, ceremony, piv, luks, fido2, daemon** — and, where a capability
has two tool names, frequently the newer one
([`docs/dns/api.md`](../dns/api.md) §3, [`docs/vtpm/api.md`](../vtpm/api.md) §5).

**Whether both catalogs should default to deny is the single largest question
this documentation migration surfaced.** It is raised for the owner in the
migration report and is not decided anywhere in these documents.

### Certificate-bound routes

A few REST routes authorize on the **mTLS client certificate** rather than on a
token scope, because their caller is a machine whose identity *is* its
certificate. The webservice listener therefore requests a client certificate
optionally — `tls.VerifyClientCertIfGiven`, set in
`pkg/webservice/webserver_v1.go` — so a presented certificate is chained to the
configured `ClientCAs` by the TLS stack before any handler runs, while clients
that present none (the WebUI, token-authenticated API callers) are unaffected.
Handlers on these routes read identity from the connection's `VerifiedChains`,
never from `PeerCertificates`.

| Route | Bound to | Refusal |
|---|---|---|
| `POST /api/v1/gateway/telemetry` | body `gateway_id` == client certificate CN | 401 unverified · 403 mismatch |
| `GET /api/v1/gateway/desired-config/{id}` | `{id}` == client certificate CN | 401 unverified · 403 mismatch |
| device enrollment routes (`pkg/webservice/v1/router/device.go`) | `MTLSMiddleware` chain verification | 401 |

The Subject Common Name is the platform's machine-principal field throughout —
the trusted reverse proxy keys attestation manifests by the IDevID CN, and the
daemon's gRPC mTLS interceptor reads the same field. See
[`docs/gateway/api.md`](../gateway/api.md) §8.

---

## 6. Versioning

REST under `/api/v1`; gRPC package `platform.v1`; QUIC `ProtocolVersion`
`0x01`. The OCI distribution `/v2` routes
([`docs/registry/api.md`](../registry/api.md) §3) are the distribution
specification's version, not the platform's.
