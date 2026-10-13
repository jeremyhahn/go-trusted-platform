# Go SDK — API

> **Status: NORMATIVE** · Scope: what `sdk/go` carries, per service and per transport · Last verified: 2026-10-13
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
| REST | `transport/rest/adapter.go` (`grpcMethodToRESTMap`, `templatedRouteTable`), plus `ldevid.go`, `provisioning.go`, `attestation_reports.go`, `iam.go` (single IAM resources onto the reply's resource field) |
| QUIC | `transport/quic/adapter.go` (`grpcMethodToOpcodeMap`, `categorySubOpcodeMap`), plus `aaa_ldevid.go`, `aab_ntp.go`, `device.go`, `dns.go`, `gateway_nat64.go`, `provisioning.go` |
| MCP | `transport/mcp/adapter.go` (`grpcMethodToMCPToolMap`), plus `attestation_reports.go`, `eab.go`, `ldevid.go`, `provisioning.go` |
| Embedded | `transport/embedded/adapter.go` (`ServiceRegistry`), `dispatch.go` (`register<Service>Handlers`) |

The server side of each transport, with ports, opcodes and authorization, is
[../daemon/api.md](../daemon/api.md).

## 2. Platform services by transport

✅ means the adapter maps the service; per-method coverage lives in the feature
folder's own `api.md`. Streaming RPCs are ✅ only on gRPC / Unix.

| Service (`platform.v1`) | `Client` accessor | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|---|
| `PlatformDaemon` | `Daemon()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `TPMService` | `TPM()` | ✅ | ✅ | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| `CAService` | `CA()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `DeviceService` | `Device()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `VTPMService` | `VTPM()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `SDNService` | `SDN()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `ComputeService` | `Compute()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `BMCService` | `BMC()` | ✅ | ✅ | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| `IDevIDService` | `IDevID()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `AttestationService` | `Attestation()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `TenantService` | `Tenant()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `PXEService` | `PXE()` | ✅ | ✅ | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| `DNSService` | `DNS()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `NTPService` | `NTP()` | ✅ | ✅ | ✅ | ✅ | `MISSING — docs/13 G7` |
| `GatewayService` | `Gateway()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `ProxyService` | `Proxy()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `OverlayService` | `Overlay()` | ✅ | ✅ | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| `RegistryService` | `Registry()` | `MISSING — docs/13 G7` | ✅ | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| `ClusterService` | `Cluster()` | ✅ | ✅ | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| `ConfigDeliveryService` | `ConfigDelivery()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `PlatformIAMService` | `IAM()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `KeyManagementService` | `KMS()` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `BarrierService` | `Barrier()` | `MISSING — docs/13 G7` | ✅ | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| `EABService` | `MISSING — docs/13 G7` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `InvitationService` | `MISSING — docs/13 G7` | ✅ | ✅ | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| `SwitchService` | `MISSING — docs/13 G7` | ✅ | ✅ | ✅ | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| `ProvisioningGateway` | `MISSING — docs/13 G7` | ✅ | ✅ | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| `CeremonyService` | `MISSING — docs/13 G7` | ✅ | ✅ | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| `FIDO2Service` | `MISSING — docs/13 G7` | ✅ | ✅ | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| `PIVService` | `MISSING — docs/13 G7` | ✅ | ✅ | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| `LUKSService` | `MISSING — docs/13 G7` | ✅ | ✅ | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |

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
| `Security()` | `CertificateExt()`, `ACME()`, `Trust()`, `Attestation()`, `SSH()` | `MISSING — docs/13 G7` |
| `Security()` | `Barrier()`, `Ceremony()`, `Credentials()`, `SealStore()`, `SecretResolver()` | `MISSING — docs/13 G7` |
| `Identity()` | `IAM()` | ✅ |
| `Search()` | `Vector()`, `TimeSeries()` | ✅ each |
| `Storage()` | `Backup()`, `ObjectStorage()`, `ObjectStorageAdmin()`, `ObjectTransfer()`, `ParameterStore()` | ✅ each |
| `Async()` | `Scheduler()`, `Messaging()` | ✅ each |
| `AI()` | `Embedding()`, `Ollama()` | ✅ each |
| `AI()` | `RAG()` | `MISSING — docs/13 G7` |
| `BarrierCeremonyMgmt()` | `Ceremony()`, `CustodianGroup()`, `Share()` | `MISSING — docs/13 G7` |
| `TenantMgmtService()` | `Tenant()` | `MISSING — docs/13 G7` |
| agentic | `Orchestrator()`, `Project()`, `Account()` | ✅ each |
| agentic | `SDLC()` | `MISSING — docs/13 G7` |
| agentic | container-trust types from `go-quicbaas/sdk/go/orchestration` | ✅ `sdk/go/services/orchestration` (§3.1) |
| agentic | request / response types of `client/orchestrator`, `client/project`, `client/account` | `MISSING — docs/13 G7` |
| agentic | a platform container attestor registered into `WithContainerAttestor` | `MISSING — docs/13 G7` |
| service registry | `Discovery()`, `DataStore()` | `MISSING — docs/13 G7` |
| connection | `Transport()` | ✅ |
| qrdb surface go-quicbaas does not route | `SQL()`, `Collections()`, `Lock()`, `Lease()` and the rest | `MISSING — docs/13 G1` |

A re-exported accessor rides the side-client's transport (`QuicBaaSTransport`:
unix, grpc, rest, quic or mcp) to quicbaasd, so its transport coverage is
go-quicbaas's own. platformd serves none of these groups and `platformctl` has
no command group for them.

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

`sdk/go/services/auth` is a second, purpose-built adapter over
`Security().Auth()` for `platformctl auth`: `Login`, `AddFactor`,
`ListFactors`, `RemoveFactor`, `RotateFactor`, `RelabelFactor`. `platformctl barrier` uses
`QuicBaaS().Security().Barrier()` directly; `Client.Barrier()` remains for
callers of the platform `BarrierService`.
