# Go SDK — API

> **Status: NORMATIVE** · Scope: what `sdk/go` carries, per service and per transport · Last verified: 2026-10-15
> Conflicts with this document are defects. Fix them here first.
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING`, never omitted.

---

## 1. The six transports

`sdk/go/protocol.go` declares six: `ProtocolUnix`, `ProtocolGRPC`,
`ProtocolREST`, `ProtocolQUIC`, `ProtocolMCP`, `ProtocolEmbedded`. **Unix is
gRPC over a Unix domain socket**, so gRPC and Unix share a column: both carry
every generated method, streaming included. The other four carry a method only
when their adapter maps it:

| Transport | Where the mapping lives |
|---|---|
| REST | `transport/rest/adapter.go` (`grpcMethodToRESTMap`, `templatedRouteTable`), plus `ldevid.go`, `provisioning.go`, `attestation_reports.go`, `app_services.go`, `iam.go` (single IAM resources onto the reply's resource field) |
| QUIC | `transport/quic/adapter.go` (`grpcMethodToOpcodeMap`, `categorySubOpcodeMap`), plus `aaa_ldevid.go`, `aab_bmc.go`, `aab_cluster.go`, `aab_invitation.go`, `aab_ntp.go`, `aab_pxe.go`, `aac_app_services.go`, `ceremony.go`, `device.go`, `dns.go`, `fido2.go`, `gateway_nat64.go`, `luks.go`, `piv.go`, `provisioning.go`, `tpm_quote.go` |
| MCP | `transport/mcp/adapter.go` (`grpcMethodToMCPToolMap`), plus `app_services.go`, `attestation_reports.go`, `bmc.go`, `cluster.go`, `eab.go`, `invitation.go`, `ldevid.go`, `phase35.go`, `provisioning.go`, `pxe.go`, `switch.go`, `tpm_quote.go` |
| Embedded | `transport/embedded/adapter.go` (`ServiceRegistry`), `dispatch.go` (`register<Service>Handlers`) |

The server side of each transport, with ports, opcodes and authorization, is
[../daemon/api.md](../daemon/api.md).

## 2. Platform services by transport

✅ means the adapter maps the service; per-method coverage lives in the feature
folder's own `api.md`. Streaming RPCs are ✅ only on gRPC / Unix.

| Service (`platform.v1`) | `Client` accessor | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|---|
| `PlatformDaemon` | `Daemon()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `TPMService` | `TPM()` | ✅ | ✅ | `Quote`, `VerifyQuote` only ([tpm/api.md §5](../tpm/api.md#5-sealing-pcrs-attestation-entropy)); the rest `MISSING — docs/13 G7` | `Quote` (refused: no TLS to bind), `VerifyQuote` only; the rest `MISSING — docs/13 G7` | ✅ |
| `CAService` | `CA()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `DeviceService` | `Device()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `VTPMService` | `VTPM()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `SDNService` | `SDN()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `ComputeService` | `Compute()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `BMCService` | `BMC()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `IDevIDService` | `IDevID()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `AttestationService` | `Attestation()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `TenantService` | `Tenant()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `PXEService` | `PXE()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `DNSService` | `DNS()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `NTPService` | `NTP()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `GatewayService` | `Gateway()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `ProxyService` | `Proxy()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `OverlayService` | `Overlay()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `RegistryService` | `Registry()` | `MISSING — docs/13 G7` | ✅ | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| `ClusterService` | `Cluster()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `ConfigDeliveryService` | `ConfigDelivery()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `PlatformIAMService` | `IAM()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `KeyManagementService` | `KMS()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `BarrierService` | `Barrier()` | `MISSING — docs/13 G7` | ✅ | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| `EABService` | `EAB()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `InvitationService` | `Invitation()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `CacheService` (§3.5) | `Cache()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `SchedulerService` (§3.5) | `Scheduler()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `MessagingService` (§3.5) | `Messaging()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `SwitchService` | `Switch()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `ProvisioningGateway` | `MISSING — docs/13 G7` | ✅ | ✅ | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| `CeremonyService` | `Ceremony()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `FIDO2Service` | `FIDO2()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `PIVService` | `PIV()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `LUKSService` | `LUKS()` | ✅ | ✅ | ✅ | ✅ | ✅ |

A service with no `Client` accessor is reached through its `sdk/go/services/*`
wrapper (see [engineering.md §2](engineering.md#service-wrapper-constructors)).

## 3. go-quicbaas re-export surface

`Client.QuicBaaS()` returns the raw `quicbaas.Client`, so every go-quicbaas
group is callable through it. A group counts as **re-exported** when
`sdk/go/services/quicbaas.Client` gives it a typed accessor. That is the frontage
platform code and SDK consumers program against.

| go-quicbaas group | Accessor | `services/quicbaas.Client` |
|---|---|---|
| `CoreData()` | `KV()`, `Batch()`, `Transaction()`, `Query()` | ✅ each |
| `ClusterMgmt()` | `Cluster()`, `Health()`, `Operations()`, `Cache()` | ✅ each |
| `Security()` | `Auth()`, `Seal()`, `KMS()`, `Secrets()`, `Crypto()`, `Certificate()`, `DEK()`, `DynamicSecrets()`, `RBAC()` | ✅ each |
| `Security()` | `CertificateExt()`, `ACME()`, `Trust()`, `Attestation()`, `SSH()` | ✅ each |
| `Security()` | `Barrier()`, `Ceremony()`, `Credentials()`, `SealStore()` | ✅ each; an upstream failure is `ErrServiceUnavailable` |
| `Security()` | `SecretResolver()` | ✅; nil on a client built without a secret registry |
| `Identity()` | `IAM()` | ✅ |
| `Search()` | `Vector()`, `TimeSeries()` | ✅ each |
| `Storage()` | `Backup()`, `ObjectStorage()`, `ObjectStorageAdmin()`, `ObjectTransfer()`, `ParameterStore()` | ✅ each |
| `Async()` | `Scheduler()`, `Messaging()` | ✅ each |
| `ClusterMgmt()`, `Search()`, `Storage()`, `Async()` | request / response types of `client/cache`, `client/vector`, `client/timeseries`, `client/objectstorage`, `client/scheduler`, `client/messaging` | ✅ `sdk/go/services/{cache,vector,timeseries,objectstorage,scheduler,messaging}` (§3.4) |
| `AI()` | `Embedding()`, `Ollama()` | ✅ each |
| `AI()` | `RAG()` | ✅ |
| `BarrierCeremonyMgmt()` | `Ceremony()`, `CustodianGroup()`, `Share()` | ✅ each; `Ceremony()` is the `Security()` accessor, since go-quicbaas routes both to the same QRDB ceremony client; an upstream failure is `ErrServiceUnavailable` |
| `TenantMgmtService()` | `Tenant()` | ✅; an upstream failure is `ErrServiceUnavailable` |
| agentic | `Orchestrator()`, `Project()`, `Account()`, `SDLC()` | ✅ each |
| agentic | container-trust types from `go-quicbaas/sdk/go/orchestration` | ✅ `sdk/go/services/orchestration` (§3.1) |
| agentic | request / response types of `client/orchestrator`, `client/project`, `client/account`, `client/sdlc` | ✅ `sdk/go/services/{orchestrator,project,account,sdlc}` (§3.2) |
| agentic | a platform container attestor registered into `WithContainerAttestor`: this host, device registry lookup, golden PCRs from the device profile, quarantine and re-attestation on drift | ✅ `container.FleetContainerAttestor` in the embedded server (§3.3) |
| agentic | container attestation of a remote device, a recorded verdict on a pass, TOFU capture of a missing baseline | `MISSING — docs/13 G7` |
| service registry | `Registry()`, `DataStore()` | ✅ each; a `DataStore()` upstream failure is `ErrServiceUnavailable` |
| connection | `Transport()` | ✅ |
| qrdb surface go-quicbaas does not route | `SQL()`, `Collections()`, `Lock()`, `Lease()` and the rest | `MISSING — docs/13 G1` |

A re-exported accessor rides the side-client's transport (`QuicBaaSTransport`:
unix, grpc, rest, quic or mcp) to quicbaasd, so its transport coverage is
go-quicbaas's own. platformd itself serves only `Cache()`, `Scheduler()` and
`Messaging()` of these groups (§3.5).

### 3.1 Container-trust types

`sdk/go/services/orchestration` re-exports the trust axis as aliases and
thin functions. Values are the upstream ones, so `errors.As` matches across the
boundary.

| Identifier | Kind |
|---|---|
| `TrustLevel`: `TrustLevelDefault`, `TrustLevelNone`, `TrustLevelPinned`, `TrustLevelAttested`, `TrustLevelMeasured` | type alias, constants |
| `TrustPolicy`: `TrustPolicyOptIn`, `TrustPolicyPinned`, `TrustPolicyAttested`, `TrustPolicyMeasured` | type alias, constants |
| `TrustCapabilities` (`DigestPinning`, `HostTPM`, `MeasuredLaunch`) | type alias |
| `ResolveTrustLevel(requested, serverPolicy, tenantOverride, caps) (TrustLevel, error)` | function |
| `ParseTrustLevel(string)`, `ParseTrustPolicy(string)` | function |
| `TrustLevelViolationError` (`Requested`, `Policy`, `Reason`) | error type alias, from `ResolveTrustLevel` |
| `InputValidationError` (`Field`, `Message`), `ErrInvalidInput` | error type alias and sentinel, from the `Parse*` functions |

`ResolveTrustLevel` is deny-by-default: a tenant override may only tighten the
server policy, and a level below the floor or one the host cannot prove is a
`*TrustLevelViolationError`, never a downgrade.

### 3.2 Agentic client types

Each agentic accessor has a sibling package that re-exports the request,
response and record types of its go-quicbaas client, so a caller never imports
go-quicbaas. Every identifier is a type alias or a constant bound to the
upstream value.

| Accessor | Package | Replaces | Constants |
|---|---|---|---|
| `Orchestrator()` | `sdk/go/services/orchestrator` | `go-quicbaas/sdk/go/client/orchestrator` | `SandboxMode*`, `SessionTurnRole*`, `SpendLevel*`, `SpendPolicy*`, `WorkflowMode*`, `TurnStatusAccepted`, `SpendUnattributed` |
| `Project()` | `sdk/go/services/project` | `go-quicbaas/sdk/go/client/project` | `ProjectRole*` |
| `Account()` | `sdk/go/services/account` | `go-quicbaas/sdk/go/client/account` | `CredentialHealth*`, `Provider*`, `Refresh*`, `Status*` |
| `SDLC()` | `sdk/go/services/sdlc` | `go-quicbaas/sdk/go/client/sdlc` | none |

Each package also aliases the upstream `Client` interface, so a caller can name
the accessor's return type. `orchestrator` re-exports the two prompt errors,
`EmptyTurnError` and `MissingTurnIDError`, and `errors.As` matches them across
the boundary. The packages leave out what only a transport implementer needs:
the `NewClient` constructors, the orchestrator `*Wire` envelopes and the
`NewPromptSession*` response builders, and `sdlc.SDLCCapableTransport`.

`sdk/go/services/auth` is a second, purpose-built adapter over
`Security().Auth()` for `platformctl auth`: `Login`, `AddFactor`,
`ListFactors`, `RemoveFactor`, `RotateFactor`, `RelabelFactor`. `platformctl barrier` uses
`QuicBaaS().Security().Barrier()` directly; `Client.Barrier()` remains for
callers of the platform `BarrierService`.

### 3.3 Platform container attestor

The embedded QuicBaaS server registers
`pkg/storage/quicbaas.ContainerAttestorAdapter` through `WithContainerAttestor`
when it starts. `platformd` then installs `container.FleetContainerAttestor` into
it, so `Security().Attestation().AttestContainer` on the embedded transport is
answered by the platform. The attestor is not installed on a node without:

- `attestation.reporting.enabled`, which provides the control plane's own
  device record;
- a host TPM;
- a container runtime binary.

On such a node the call returns `ErrContainerAttestorNotAvailable`.

Only this host can be attested; a request naming another device is refused.
The fail-closed rules are in
[`docs/compute/engineering.md`](../compute/engineering.md) §5, invariant 8.

### 3.4 Application and search client types

The application, search and data-service accessors follow §3.2: each has a
sibling package that re-exports the request, response and value types of its
go-quicbaas client, plus its `Client` interface. Every identifier is a type alias or a
constant bound to the upstream value.

| Accessor | Package | Replaces | Constants |
|---|---|---|---|
| `Cache()` | `sdk/go/services/cache` | `go-quicbaas/sdk/go/client/cache` | none |
| `Vector()` | `sdk/go/services/vector` | `go-quicbaas/sdk/go/client/vector` | `FilterOperator*`, `IndexType*` |
| `TimeSeries()` | `sdk/go/services/timeseries` | `go-quicbaas/sdk/go/client/timeseries` | `Aggregate*` |
| `ObjectStorage()` | `sdk/go/services/objectstorage` | `go-quicbaas/sdk/go/client/objectstorage` | `ReplicationMode*` |
| `Scheduler()` | `sdk/go/services/scheduler` | `go-quicbaas/sdk/go/client/scheduler` | `JobStatus*`, `JobType*`, `OwnerType*` |
| `Messaging()` | `sdk/go/services/messaging` | `go-quicbaas/sdk/go/client/messaging` | `Codec*`, `MessageType*`, `EventType*`, `Op*` |
| `Backup()` | `sdk/go/services/backup` | `go-quicbaas/sdk/go/client/backup` | none |
| `ParameterStore()` | `sdk/go/services/parameterstore` | `go-quicbaas/sdk/go/client/parameterstore` | none |
| `Operations()` | `sdk/go/services/operations` | `go-quicbaas/sdk/go/client/operations` | none |
| `ObjectStorageAdmin()` | `sdk/go/services/objectstorageadmin` | `go-quicbaas/sdk/go/client/objectstorageadmin` | `BackendType*`, `StorageTier*`, `GCStatus*` |
| `ObjectTransfer()` | `sdk/go/services/objecttransfer` | `go-quicbaas/sdk/go/client/objecttransfer` | `Compression*` |
| `Embedding()` | `sdk/go/services/embedding` | `go-quicbaas/sdk/go/client/embedding` | `Provider*`, `InputType*`, `Status*` |
| `Ollama()` | `sdk/go/services/ollama` | `go-quicbaas/sdk/go/client/ollama` | none |
| `RAG()` | `sdk/go/services/rag` | `go-quicbaas/sdk/go/client/rag` | none |

#704 added the eight packages from `backup` to `rag`, so their consumers no
longer import go-quicbaas. None of their upstream packages exports a
sentinel error.

`messaging` also forwards `NewDeltaBuilder()` and `NewDeltaApplier[E]()`,
because the upstream `DeltaBuilder` and `DeltaApplier[E]` keep their state
unexported and cannot be built any other way. The packages leave out the
`NewClient` constructors, which take a raw go-quicbaas transport.

An accessor returns nil when the SDK does not serve the service, and
`NewClientFromSDK(nil)` fails with `ErrNilSDKClient`.

platformd serves Cache, Scheduler and Messaging itself (§3.5). Every other
accessor in the table is reached only through the side-client (§3), and
`platformctl` has no command group for it.

### 3.5 Cache, Scheduler and Messaging on platformd

platformd serves `platform.v1.CacheService`, `SchedulerService` and
`MessagingService` (`pkg/api/grpc/proto/{cache,scheduler,messaging}.proto`)
over the composed go-quicbaas SDK its quicbaas DAO factory holds. Each
transport calls one gRPC service instance, and that instance calls the service
layer in `pkg/appservices`. The service layer validates the request and is the
only code that calls the SDK client.

On REST (`pkg/api/rest/app_service_handlers.go`) each RPC is one route. An item
route names its job or channel in the path. A GET or DELETE route takes its
filters from the query string, named after the proto field: an enum by name or
number, and a map field such as `tags` as repeated `key=value` parameters. Any
other route takes the rest of the request as a protojson body. A body field
that disagrees with the path is `400`. A gRPC status becomes its HTTP twin:
`UNAVAILABLE` `503`, `INVALID_ARGUMENT` `400`, `NOT_FOUND` `404`, and anything
unmapped `500`. Errors use the `{error, code, timestamp}` envelope.

Both REST listeners serve this route table, and both call the server instances
the other transports call. The daemon REST listener checks each route's scope
with `restapi.ScopeGuard` ([docs/daemon/api.md](../daemon/api.md)). The
platformd HTTPS listener in webservice mode mounts the same table through
`appServiceRoutes` (`pkg/webservice/v1/router.go`). There each route sits
behind the admin role gate. When the auth middleware is the IAM
`PlatformTokenMiddleware`, the route's scope is checked as well. A daemon
without these services mounts none of the routes.

| Route | RPC |
|---|---|
| `GET /api/v1/cache/stats?entity_type=` | `CacheService/GetStats` |
| `GET`, `PATCH /api/v1/cache/config` | `GetConfig`, `UpdateConfig` |
| `DELETE /api/v1/cache/entries?entity_type=&all=` | `Clear` |
| `POST /api/v1/scheduler/jobs` | `SchedulerService/CreateJob` (`201`) |
| `GET /api/v1/scheduler/jobs?owner_type=&owner_id=&status=&job_type=&tags=&limit=&offset=` | `ListJobs` |
| `GET`, `PATCH`, `DELETE /api/v1/scheduler/jobs/{job_id}` | `GetJob`, `UpdateJob`, `DeleteJob` |
| `POST /api/v1/scheduler/jobs/{job_id}/{trigger,pause,resume,cancel}` | `TriggerJob`, `PauseJob`, `ResumeJob`, `CancelJob` |
| `GET /api/v1/scheduler/jobs/{job_id}/history?limit=&offset=&start_time_unix_ms=&end_time_unix_ms=&status=` | `GetJobHistory` |
| `GET /api/v1/scheduler/status` | `GetStatus` |
| `POST`, `GET /api/v1/messaging/channels` | `MessagingService/CreateChannel` (`201`), `ListChannels` |
| `GET`, `DELETE /api/v1/messaging/channels/{name}` | `GetChannel`, `DeleteChannel` |
| `POST /api/v1/messaging/channels/{channel}/messages` | `Publish` |
| `GET /api/v1/messaging/channels/{channel}/stats` | `GetChannelStats` |
| `GET /api/v1/messaging/stats`, `/dedup-stats` | `GetStats`, `GetDedupStats` |

On QUIC each service is a category opcode, `0x53` cache, `0x54` scheduler and
`0x55` messaging ([../daemon/api.md](../daemon/api.md) §4). `payload[0]` is the
`CacheSub*`, `SchedulerSub*` or `MessagingSub*` sub-opcode from
`sdk/go/wire/quicwire/appservice_opcodes.go`, and `payload[1:]` is the
MessagePack-encoded `platform.v1` request. Every request carries a body, even
an empty message. The status mapping follows the gRPC errors below:
`UNAVAILABLE` becomes `StatusUnavailable` naming the service,
`INVALID_ARGUMENT` becomes `StatusInvalidArgument`, an undecodable body is
`StatusInvalidRequest` and an unknown sub-opcode is `StatusPermissionDenied`
from the authorization guard.

On MCP (`pkg/api/mcp/app_service_tools.go`) each RPC is one tool. Arguments and
results use the proto3 JSON mapping with proto field names: an enum travels by
name, a 64-bit integer as a string and bytes as base64. Each tool's input
schema lists its request's fields. An argument the request does not have is
refused as invalid. A gRPC status becomes the JSON-RPC error code of its class
(`sdk/go/wire/mcpwire`), and the SDK maps it back. A daemon whose MCP provider
has no server for the service answers `UNAVAILABLE`.

| Tool | RPC |
|---|---|
| `cache_stats`, `cache_config_get`, `cache_config_update`, `cache_clear` | `CacheService/GetStats`, `GetConfig`, `UpdateConfig`, `Clear` |
| `scheduler_job_create`, `scheduler_job_list`, `scheduler_job_get`, `scheduler_job_update`, `scheduler_job_delete` | `SchedulerService/CreateJob`, `ListJobs`, `GetJob`, `UpdateJob`, `DeleteJob` |
| `scheduler_job_trigger`, `scheduler_job_pause`, `scheduler_job_resume`, `scheduler_job_cancel` | `TriggerJob`, `PauseJob`, `ResumeJob`, `CancelJob` |
| `scheduler_job_history`, `scheduler_status` | `GetJobHistory`, `GetStatus` |
| `messaging_channel_create`, `messaging_channel_list`, `messaging_channel_get`, `messaging_channel_delete` | `MessagingService/CreateChannel`, `ListChannels`, `GetChannel`, `DeleteChannel` |
| `messaging_publish`, `messaging_channel_stats`, `messaging_stats`, `messaging_dedup_stats` | `Publish`, `GetChannelStats`, `GetStats`, `GetDedupStats` |

Every route, opcode and tool requires the scope of its RPC:

| RPC | Scope |
|---|---|
| `CacheService/GetStats`, `GetConfig` | `cache:read` |
| `CacheService/UpdateConfig` | `cache:write` |
| `CacheService/Clear` | `cache:delete` |
| `SchedulerService/GetJob`, `ListJobs`, `GetJobHistory`, `GetStatus` | `scheduler:read` |
| `SchedulerService/CreateJob`, `UpdateJob`, `TriggerJob`, `PauseJob`, `ResumeJob`, `CancelJob` | `scheduler:write` |
| `SchedulerService/DeleteJob` | `scheduler:delete` |
| `MessagingService/GetChannel`, `ListChannels`, `GetStats`, `GetDedupStats`, `GetChannelStats` | `messaging:read` |
| `MessagingService/CreateChannel`, `Publish` | `messaging:write` |
| `MessagingService/DeleteChannel` | `messaging:delete` |

Wire rules:

- Times are Unix milliseconds and durations are milliseconds; `0` means unset.
- Scheduler job and execution IDs are decimal strings, because a JSON number
  cannot carry a 64-bit ID exactly. A missing or non-decimal `job_id` is
  `InvalidArgument`.
- An `UNSPECIFIED` scheduler enum is no filter in `ListJobs` and
  `GetJobHistory`. In `CreateJob` it is refused for `job_type` and means
  `SYSTEM` for `owner_type`.
- `CacheService/UpdateConfig` changes only the fields that are set; a request
  with none set is `InvalidArgument`. `Clear` takes exactly one of
  `entity_type` and `all`.

Errors:

| Cause | Status |
|---|---|
| The node's DAO factory has no SDK, or the SDK does not serve the service (the embedded transport answers `UnknownMethodError`) | `UNAVAILABLE`, `ErrorInfo` reason `SERVICE_NOT_CONFIGURED`, metadata `service` = `cache`, `scheduler` or `messaging` |
| The request fails validation | `INVALID_ARGUMENT`, naming the field |
| The SDK answers with a typed error (`QBError`) | its code's gRPC twin, as `barrier.SDKCode` maps it: `NotFound` `NOT_FOUND`, `AlreadyExists` and `Conflict` `ALREADY_EXISTS`, `InvalidInput` `INVALID_ARGUMENT`, `Unavailable` `UNAVAILABLE`, and so on |
| The SDK answers with a gRPC status | that status code |
| Any other SDK failure | `INTERNAL` |

The embedded transport of the pinned go-quicbaas `sdk/go v0.12.0-alpha` serves
none of the three. It has no `quicbaas.Scheduler` or `quicbaas.Messaging`
handlers, and its `quicbaas.Cache` handlers are keyed `GetStats`, `Clear`,
`GetConfig` and `UpdateConfig`, while the SDK's cache client sends
`GetCacheStats`, `ClearCache`, `GetCacheConfig` and `UpdateCacheConfig`. On a
node that runs the embedded SDK, every call therefore answers
`SERVICE_NOT_CONFIGURED`.

Messaging leaves out `Subscribe`, `Unsubscribe`, `WatchChannel` and
`PublishDelta`. A subscription delivers to the SDK session that opened it, and
a delta is computed from values held in the caller's process, so none of the
four has a meaning when platformd makes the call for a remote caller. A caller
that needs them uses the side-client.
