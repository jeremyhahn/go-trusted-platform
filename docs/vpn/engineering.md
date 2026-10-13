# Remote-Access VPN — Engineering Contract

> **Status: PARTIAL — the core (#584 PR 1), both data planes (#584 PR 2), the gateway service and the operator control plane (#584 PR 3) exist; left for PR 4: the web page, the JS SDK and `platformctl vpn connect`. The admission listener and the gatewayd runtime assembly are planned (§1).** · Scope: `pkg/sdn/gateway/services/vpn`, `pkg/sdn/tunnel`, `pkg/vpn` · Last verified: 2026-10-13
> Identifiers below are either real today (grepped) or marked *(planned)*. A
> planned name is a requirement for the implementing PR, not a claim.
> Feature folder: [architecture.md](architecture.md) · engineering (this file) ·
> [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

## 1. Exported surface

### Exists today and is consumed as-is

| Identifier | Package | Role here |
|---|---|---|
| `Policy`, `New(Config) (*Policy, error)`, `(*Policy).Evaluate(ctx, *Peer) Decision`, `PeerFromTLS`, `Decision`, `Reason`, `Strategy`, `AttestedPeers`, `Auditor` | `pkg/attestation/calleradmission` | Device identity and the audit sink |
| `Service.VerifyQuote`, `Service.GetQuote`, `Service.CollectHostAttestation`, `Service.VerifyManifest` | `pkg/attestation/service` | Quote verification |
| `DeviceVerdict{DeviceID, HostID, Serial, Passed, Cryptographic, Reason, ProfileID, …}`, `Sink.RecordDeviceVerdict` | `pkg/attestation/verdict` | The verdict the lease depends on |
| `Collector`, `NewCollector(Config)`, `(*Collector).Enqueue(deviceID)`, `Cache`, `NewCache(ttl)` | `pkg/attestation/reporting` | Scheduled re-attestation inside the lease |
| `HostManifest`, `HostAttestation{PCRs, AKPublicKey, IDevIDCertificate, Nonce, …}` | `pkg/attestation/manifest` | What the agent submits |
| `OPAEngine`, `NewOPAEngine()`, `(*OPAEngine).LoadPolicy`, `(*OPAEngine).Evaluate(ctx, name, input) (*EvaluationResult, error)`, `Violation` | `pkg/policy/opa` | Posture evaluation |
| `ReadSecureBootStatus() (*SecureBootStatus, error)`, `SecureBootEnabled() (bool, error)` | `pkg/uefi` | Posture fact: Secure Boot |
| `NewReader`, `NewVerifier`, `Status{Available, Enabled, PolicyLoaded}`, `EventLog` | `pkg/ima` | Posture fact: IMA |
| `Allocator` (`Allocate`, `AllocateSpecific`, `Release`, `ReleaseByDeviceID`, `ListPoolsByZone`) | `pkg/sdn/ipam` | Address lease |
| `ManagementVPNConfig{Enabled, Type, AllowTo}` | `pkg/sdn/config.go` | Zone reachability of admitted clients |
| `Security().Auth().FIDO2()` → `FIDO2Client`; `.PIV()` → `XKMSPIVService`; `.Factors()` → `AuthFactorsClient`; `Security().KMS()` → `KMSClient` | quicbaas SDK (`services_security.go`) | Person factor, keys |
| `AuthFactorEnrollRequest` (= `qrdbtransport.EnrollFactorRequest{FactorName, Subject, TenantID, MethodParams}`) | quicbaas SDK | Factor enrollment |
| `quic-go` (`github.com/quic-go/quic-go`, already in `go.mod`), `pkg/api/quic` | this repo | MASQUE transport base |

### Core — exists since #584 PR 1 (`pkg/sdn/gateway/services/vpn`)

| Identifier | Contract |
|---|---|
| `Service`, `New(deps Deps, cfg Config) (*Service, error)`, `Start/Stop/Active/Health`, `Config()` | Same lifecycle shape as `services/firewall`; `New` refuses an invalid config or a missing dependency before anything runs |
| `Deps{Identity IdentityPolicy, Verifier, Posture PostureEvaluator, Factors FactorVerifier, IPAM ipam.Allocator, DataPlanes map[DataPlaneKind]DataPlane, Leases LeaseStore, Audit calleradmission.Auditor, Clock, Logger}` | Every dependency is an interface; `calleradmission.Policy` and `opa.OPAEngine` satisfy theirs directly; the daemon adapts the attestation service to `Verifier` and the SDK's FIDO2/PIV clients to `FactorVerifier` |
| `(*Service).Challenge() ([]byte, error)`, `Admit(ctx, *AdmissionRequest) (*Lease, error)`, `Renew(ctx, LeaseID, *Evidence) (*Lease, error)`, `Revoke(ctx, LeaseID, RevokeReason) error`, `Leases(ctx)`, `Lease(ctx, id)`, `Sweep(ctx)`, `ZonesAllowed([]string) bool` | The five-step pipeline; nonces are single-use with `NonceTTL`; `Sweep` runs from the clock's ticker and is callable directly |
| `AdmissionRequest{Peer, DeviceID, TenantID, Nonce, Attestation *manifest.HostAttestation, Posture, PersonFactor, DataPlane, Keys PeerKeys, RequestedZones}`, `Evidence{Nonce, Attestation, Posture, PersonFactor}` | Wire form in [api.md](api.md) |
| `PeerKeys{WireGuardPublicKey, ClientCertificateSHA256}` | The client-side material a lease carries: the peer key the WireGuard plane programs, and the fingerprint of the admitted mTLS client certificate the MASQUE plane binds a session by. Admission fills the fingerprint in; a request cannot assert it |
| `Lease{ID, DeviceID, TenantID, Address netip.Prefix, Zones, DataPlane, Keys, IssuedAt, ExpiresAt, Renewals, Verdict VerdictSummary}`, `LeaseID`, `RevokeReason` (`expired`, `operator`, `client`, `replaced`, `attestation-failed`, `posture-violation`) | Tenant-scoped; `MemoryLeaseStore` is the gateway projection and the test store; the control-plane-backed `LeaseStore` is *(planned)* |
| `PostureReport{SecureBoot, IMA, FDE, AgentVersion, OSRelease, KernelRelease, CollectedAt}`, `VerdictSummary{Passed, Cryptographic, ProfileID}` | The OPA input is `{"posture": report, "verdict": summary}` |
| `DataPlane` interface — `Kind()`, `InstallPeer(ctx, *Lease) error`, `RemovePeer(ctx, LeaseID) error`; `ManagedDataPlane` adds `Start(ctx)`/`Stop(ctx)` | Both shipped planes are managed: the gateway starts them before the service admits leases and stops them after |
| `Config{Listener{BindHost, Port}, DataPlanes, Pool, LeaseTTL, RenewWindow, RequirePersonFactor{OnAdmit, OnRenew}, PosturePolicy, AllowTo, NonceTTL}`, `WithDefaults`, `Validate`, `Offers` | §5; `Validate` is the startup refusal |
| `DataPlaneMASQUE` (every build), `DataPlaneWireGuard` (`//go:build !fips` file) | Under `fips` the WireGuard symbol does not exist and `Validate` refuses `data-planes: [wireguard]` as a kind this build does not offer |
| `Enrolment{TenantID, DeviceID, Zones}`, `(*Service).SetEnrolments(ctx, []Enrolment) error`, `Enrolments()` | A peer is an operator enrolment delivered by the control plane. Admission checks it right after identity: no enrolment → `ErrPeerNotEnrolled`; a requested zone outside a non-empty `Zones` → `ErrZoneNotAllowed`. Before the first delivery nothing is enrolled. A new set revokes (`operator`) every lease it no longer covers. Admission checks the enrolment again after the person factor and keeps it from that check to the lease write under `enrolGate`, which `SetEnrolments` holds exclusively while it publishes and sweeps: a peer withdrawn while its attestation runs is refused (`ErrPeerNotEnrolled`) and holds no lease, and a lease committed just before a withdrawal is in the sweep. Peers are keyed by the (tenant, device) pair, never a joined string, so `("a/b", "c")` and `("a", "b/c")` are two peers. A structurally malformed set (empty tenant or device, a duplicate) is refused whole (`ErrInvalidEnrolment`) and the previous one stays. A peer asking for a zone outside `allow-to` is refused alone, fail closed: it is not enrolled, its leases are revoked, the rest of the set applies, and `RejectedEnrolments()` reports it with the `ErrZoneNotAllowed` text until a later set no longer carries it. Renewal re-checks the enrolment |
| `PosturePolicy{TenantID, Name, Module}`, `CompilePosturePolicy(ctx, PosturePolicy) (*opa.OPAEngine, error)`, `(*Service).SetPosturePolicies(ctx, []PosturePolicy) error`, `PosturePackage` | A tenant policy compiles in an engine of its own, replacing the embedded default, so it must declare `package vpn.posture` and cannot merge with another tenant's rules. The service judges a tenant by its policy named after `posture-policy`, else by the gateway default. A delivered policy that does not compile refuses its tenant (`ErrPostureUnavailable`), never falls back |
| `pkg/policy/opa/policies/vpn_posture.rego` (package `vpn.posture`) | Embedded; rules `verdict-required`, `verdict-passed`, `verdict-cryptographic`, `posture-required`, `secure-boot-enabled`, `secure-boot-setup-mode`, `fde-root-encrypted`, `ima-enabled`, `ima-policy-loaded`, `agent-version` |

### Data planes — exist since #584 PR 2

| Identifier | Package | Contract |
|---|---|---|
| `NewWireGuardPlane(hub WireGuardHub, logger) (ManagedDataPlane, error)` (`//go:build !fips`) | `pkg/sdn/gateway/services/vpn` | One kernel peer per lease, whose only allowed address is the lease address. `Start` brings the hub up, `Stop` removes it with every peer |
| `WireGuardHub` interface — `Up`, `Down`, `SetPeer(ctx, publicKey, allowed)`, `RemovePeer(ctx, publicKey)`, `PublicKey()`, `ListenPort()` | same | `*tunnel.WireGuardHub` satisfies it; the plane never sees the server private key |
| `NewMASQUEPlane(cfg MASQUEConfig, dev PacketDevice, logger) (ManagedDataPlane, error)` | same | CONNECT-IP over HTTP/3; a lease binds an address to the client certificate it was admitted under, and the session presenting that certificate is assigned that address |
| `MASQUEConfig{BindHost, Port, Template, TLS, Routes}`, `PacketDevice` | same | `Validate` refuses a listener without a server certificate, without verified client certificates, or with no advertised route. `Stop` is terminal — it closes the host device, which cannot be reopened, so a restart builds a new plane |
| `tunnel.WireGuardHub`, `NewWireGuardHub(logger, WireGuardHubConfig{Name, KeyRef, ListenPort, Addresses, MTU}, KeyProvider)` (`!fips`) | `pkg/sdn/tunnel` | The hub device: many roaming peers on one interface, keyed once from the `KeyProvider` and zeroized |
| `tunnel.TUN`, `OpenTUN(TUNConfig{Name, Addresses, MTU})` | `pkg/sdn/tunnel` | The MASQUE plane's host-side layer-3 device |

### Gateway service — exists since #584 PR 3 (`pkg/sdn/gateway`, `pkg/sdn/gateway/state`)

| Identifier | Contract |
|---|---|
| `ManagementVPNServiceConfig{Enabled, vpn.Config}` (`management_vpn`) | The core `Config` inlined beside `enabled` (§5); `Validate` applies `WithDefaults` and the core's `Validate` when enabled, so a bad section stops gatewayd at load |
| `VPNRuntime{Identity, Verifier, Posture, Factors, IPAM, DataPlanes map[DataPlaneKind]VPNDataPlaneFactory, Leases, Audit}`, `GatewayRuntime.VPN` | What the assembly hands the service. Planes are factories: every start builds them afresh, because a stopped MASQUE plane has closed its device. A nil `VPN` refuses the service with `ErrRuntimeMissing`; a configured kind without a factory refuses it with `ErrServiceStartFailed` wrapping `ErrDepsMissing`. A nil `Leases` keeps leases in memory |
| `serviceBuilders["management-vpn"]` → `buildManagementVPN` | Builds the planes, then `vpn.New`; a refusal stops the planes already built. `Start` starts the planes in order, then the service, rolling back on the first failure; `Stop` revokes every lease (`operator`) so the addresses return to the pool, stops the service, then the planes in reverse |
| `DesiredConfig.VPN` → `DesiredVPN{Peers []DesiredVPNPeer{TenantID, DeviceID, Zones}, PosturePolicies []DesiredVPNPosturePolicy{TenantID, Name, Module}}`, `SectionVPN` | The control plane's enrolment set and tenant posture policies. `Gateway.Apply` validates it (tenant and device required, no duplicate (tenant, device) peer or (tenant, name) policy, compared field by field), records it and hands it to the running service: policies first, then enrolments. A section that arrives before the service starts is applied as it starts. A gateway that does not run the VPN ignores the section. A supervised VPN refuses it (`ErrDesiredApplyFailed{Section: "vpn"}`): the supervisor forwards the document to the datapath child only |
| `Snapshot.VPN` → `VPNState{Running, Admissions, Refusals, LastRefusal, EnrolledPeers, LeasesByDataPlane, Leases []VPNLeaseState, PosturePolicyErrors, RejectedPeers []VPNRejectedPeer}`, `(*Service).PosturePolicyErrors()`, `(*Service).RejectedEnrolments()` | The telemetry section; absent while the service is not running here. A tenant whose delivered policy is refused is listed with the reason, and so is every peer refused from the last enrolment set (`rejected_peers` in the API) |

### Control plane — exists since #584 PR 3 (`pkg/vpn`, `pkg/api/daemon`)

| Identifier | Contract |
|---|---|
| `NewService(quicbaas.Storage, *logging.Logger)`, `(*Service).EnrolPeer`, `ListPeers`, `RevokePeer`, `GetPosturePolicy`, `SetPosturePolicy`, `DeletePosturePolicy`, `ListPosturePolicies` | Peers and posture policies are platform-store records (§6). `EnrolPeer` is an upsert that keeps the first enrolment time. `SetPosturePolicy` compiles the module before storing it (`ErrInvalidPosturePolicy`); policy names are letters, digits, `_`, `-`, `.` |
| `(*Service).SetGatewaySnapshotStore`, `Status(ctx, gatewayID)` | Status reads the gateways' telemetry snapshots (`Snapshot.VPN`). Without a store it is `ErrStatusUnavailable`; an unknown gateway is `ErrGatewayNotFound` |
| `(*Service).DesiredVPN(ctx)` | The `vpn` section the daemon overlays on every gateway's desired config ([docs/gateway/engineering.md](../gateway/engineering.md)) |
| `VPNGRPCService`, `vpnErrToGRPC` | The one service every transport calls. Errors map as [api.md](api.md) §3; a daemon without the service refuses every RPC `Unavailable` |
| `sdk/go/services/vpn.Client`, `NewClientFromGRPC` | The Go client the CLI and the integration suite use, over any transport |

### Planned (still to be created — names are the requirement)

| Identifier | Package | Contract |
|---|---|---|
| The admission listener (mTLS-only, `Config.Listener`) and the datapath process client | `pkg/sdn/gateway/services/vpn` | The gateway process model (#557) |
| The gatewayd assembly of `VPNRuntime`: the planes from `masque.*` / `wireguard.*` keys and a `FactorVerifier` over the SDK | `pkg/sdn/gateway/commands` | Blocked on the SDK: no quicbaas verb verifies a FIDO2 or PIV assertion over a caller nonce |
| The control-plane `LeaseStore` | daemon | §6 |
| The operator web page and the JS SDK client for `VPNService` | web UI, JS SDK | #584 PR 4 |
| `platformctl vpn connect` and the other client-agent verbs ([cli.md](cli.md)) | `pkg/cli/commands/vpn` | #584 PR 4; needs the admission listener |

## 2. Invariants

- **Every step fails closed.** An unreachable verifier, an unloaded posture
  policy, an SDK error listing factors, a full pool — each is a refusal with its
  own typed error, never an admission with a warning.
- **No lease without all five steps** on a fresh session; renewal repeats
  attestation and posture, and repeats the person factor when
  `RequirePersonFactor.OnRenew` is set.
- **No credential in the clear**: the admission listener is mTLS-only; the
  person factor is a signature over the session nonce, never a shared secret in
  a request body.
- **Lease bounds**: `LeaseTTL` ∈ [5m, 24h], `RenewWindow` < `LeaseTTL`; a renewal
  before `ExpiresAt − RenewWindow` is refused with `ErrRenewalNotOpen` (the window is
  enforced at runtime, not only validated); a lease
  past `ExpiresAt` is revoked by the service's own ticker even if the datapath
  process is unreachable (the peer removal is retried, the lease is already
  dead).
- **One lease per device per tenant**; a second admission for the same device
  revokes the first (a lost laptop that comes back online cannot keep a session
  open beside the replacement).
- **Zones are the zone matrix's**: the lease's `Zones` ⊆ `ManagementVPNConfig.AllowTo`
  ∩ the person's IAM entitlement; the datapath enforces them through the
  compiled zone matrix, the same object the OVS flows and the trusted proxy use.
- **Idempotent revoke**; concurrent renew/revoke resolve to revoked. Every multi-step lease operation for one (tenant, device) — admit's find/replace/allocate/install/put, renew's get/verify/put, revoke and the expiry sweep — runs under a per-device lock (`keyLock`), so concurrent admissions cannot both see "no lease" and orphan a peer. Lock order is `enrolGate` before a device lock, never the reverse.
- **Ordering**: the address is allocated before the peer is installed and
  released after the peer is removed; a failed install releases the address.
- **FIPS**: `DataPlaneWireGuard` and `wireguardPlane` live in `//go:build !fips`
  files; the `fips` build has no WireGuard symbol at all.

## 3. Error semantics (planned vocabulary, typed, never `fmt.Errorf`)

| Error | When | Wire mapping |
|---|---|---|
| `ErrPeerRefused{Reason}` | `calleradmission.Decision.Admitted == false` | 401 (`ReasonUntrustedIssuer`, `ReasonNoIdentity`) / 403 otherwise; gRPC `Unauthenticated`/`PermissionDenied` |
| `ErrAttestationFailed{DeviceID, Reason}` | `DeviceVerdict.Passed` or `.Cryptographic` false, or `VerifyQuote` error | 403 / `PermissionDenied` |
| `ErrPostureViolation{Violations}` | any `opa.Violation` | 403 / `PermissionDenied`, violations listed by rule name only |
| `ErrPostureUnavailable{Cause}` | `ErrPolicyNotFound`, `ErrEvaluationFailed`, `ErrEngineNotInitialized` from OPA | 503 / `Unavailable` — refusal, not bypass |
| `ErrPersonFactorRequired` | no factor presented and policy requires one | 401 / `Unauthenticated` |
| `ErrPersonFactorInvalid{FactorName}` | assertion/signature failed | 401 / `Unauthenticated` |
| `ErrPoolExhausted{Pool}` | `Allocator.Allocate` returns no address | 503 / `ResourceExhausted` |
| `ErrDataPlaneUnavailable{Kind}` | datapath process unreachable, or kind absent in this build | 503 / `Unavailable` |
| `ErrLeaseStoreUnavailable{Cause}` | the lease store could not be read or written | 503 / `Unavailable` — refusal |
| `ErrLeaseExpired{LeaseID}` | renew after `ExpiresAt` | 410 / `NotFound` |
| `ErrLeaseNotFound{LeaseID}` | unknown or already revoked | 404 / `NotFound` |
| `ErrPeerNotEnrolled{TenantID, DeviceID}` | the identity passed but the control plane has not enrolled the device | 403 / `PermissionDenied` |
| `ErrInvalidEnrolment{Index, Reason}` | a delivered enrolment set is malformed (empty tenant or device, a duplicate) | desired-config apply failure |
| `ErrPosturePolicyInvalid{TenantID, Name, Reason}` | a tenant module does not parse, compile, or declare `vpn.posture` | 400 / `InvalidArgument` on the control plane; on the gateway the tenant is refused |
| `ErrInvalidConfig{Field, Reason}` | at load: TTL bounds, WireGuard in FIPS, empty pool, unknown zone | startup refusal |

## 4. Posture

The report is what the client agent can collect **from this repository's code
today**; anything else is future and must not be assumed by a policy:

| Fact | Source | Status |
|---|---|---|
| Secure Boot enabled, setup mode, efivars availability | `pkg/uefi.ReadSecureBootStatus` | collectable |
| IMA available / enabled / policy loaded; measurement log digest | `pkg/ima.Status`, `pkg/ima.NewReader` | collectable |
| Full-disk encryption present on the root volume | LUKS2 state via `go-quicbaas/sdk/go/xkms/luks` | collectable |
| Agent version, OS release, kernel release | the agent binary and `/etc/os-release`, `uname` | collectable |
| Patch level, EDR presence, screen-lock policy | — | **future**; a policy referencing them fails closed with `ErrPostureUnavailable` |

The OPA input is the JSON form of `PostureReport` plus the `DeviceVerdict`;
the policy lives beside `pkg/policy/opa/policies/host.rego` as
`vpn_posture.rego` and is tenant-overridable through the posture-policy CRUD in
[api.md](api.md). The engine's `Violation` list is the refusal reason;
`EvaluationResult` without violations admits.

## 5. Configuration

Gateway config, `gateway.management_vpn`: `enabled` beside the core
`vpn.Config` keys, inlined. Key names are hyphenated like the rest of the
gateway section. The `wireguard.*` and `masque.*` keys are *(planned)*: the
gateway does not parse them yet, and the assembly that will build the planes
from them is the planned `VPNRuntime` row in §1.

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `false` | |
| `listener` | `{bind-host, port}` | `""`, `4433` | admission listener, mTLS-only; the host-filter inventory learns it from here |
| `data-planes` | list of `wireguard \| masque` | `[masque]` | `wireguard` refused under `fips` |
| `wireguard.listen-port` *(planned)* | int | `51820` | `!fips` only |
| `masque.template` *(planned)* | string | `https://{host}:{port}/.well-known/masque/ip/` | RFC 9484 URI template. IP flow forwarding (`{target}`/`{ipproto}` variables) is not offered: the proxy carries whole IP packets, so the template takes no variables |
| `masque.routes` *(planned)* | prefixes | from the zone matrix | Advertised to an admitted client as RFC 9484 address ranges. At least one is required — a session with no route can carry nothing |
| `pool` | IPAM pool name | required | `Allocator.GetPoolByName` |
| `lease-ttl` | duration | `8h` | [5m, 24h] |
| `renew-window` | duration | `30m` | < `lease-ttl` |
| `require-person-factor` | `{on-admit, on-renew}` | `{true, false}` | |
| `posture-policy` | name | `vpn_posture` | tenant override via API |
| `allow-to` | zone names | existing `ManagementVPNConfig.AllowTo` | |

Secrets are references, never values: the WireGuard server key and the MASQUE
TLS identity are `kms://` references resolved through `Security().KMS()`. The
WireGuard hub resolves its key reference through `tunnel.KeyProvider` once at
`Up`, hands the material to the kernel and zeroizes it; only the derived
public key stays in memory, and it is what an admission response advertises.

## 6. Persistence

Enrolled peers and posture policies exist today: `pkg/vpn` stores them as
`VPNPeer` and `VPNPosturePolicy` records in the platform store, keyed by
`<tenant>/<device>` and `<tenant>/<name>`. Two keys that hash to the same
record ID are refused (`ErrKeyCollision`) rather than overwriting each other.

Leases and posture policies are tenant-scoped entities on the control plane,
reached through the quicbaas SDK's entity/DAO seam (the data-access convention:
entity interfaces over raw KV), keyed `tenant/<id>/vpn/lease/<lease-id>` and
`tenant/<id>/vpn/posture-policy/<name>`; the gateway keeps only an in-memory
projection it rebuilds from the control plane on start (desired-config pull).
No client secret is ever persisted. The lease stores the client's WireGuard
public key and the SHA-256 fingerprint of the mTLS client certificate the
admission ran under; the MASQUE plane binds a session to a lease by
reproducing that fingerprint, so no session identifier has to be issued,
carried or revoked separately.

## 7. Test strategy

- **Unit** (`pkg/sdn/gateway/services/vpn`): every pipeline step with fakes —
  refused peer, failed verdict, posture violation, posture engine unavailable,
  missing/invalid factor, pool exhausted, datapath failure releases the address,
  lease expiry revokes, second admission revokes the first, FIPS config refusal
  (both tag variants compile). Injected clock; no `time.Sleep`.
- **Golden**: the OPA input JSON for a fixture report; the rendered peer
  configuration for each data plane.
- **Data planes** (unit, no `CAP_NET_ADMIN`): the WireGuard plane against a
  hub fake — the peer's allowed address is exactly the lease address, a
  kernel refusal is reported, a removal the kernel refused keeps the lease
  mapped; the MASQUE plane against a real in-process CONNECT-IP round trip
  over loopback QUIC with a throwaway mTLS CA — the assigned address and
  advertised routes a client sees, a packet each way, a session refused for a
  certificate no lease was admitted under, a packet sourced from another
  address dropped, revocation and reconnection closing the previous session.
  The tunnel package tests the hub and the TUN device against netlink and
  wgctrl fakes.
- **Control plane**: `pkg/vpn` against an in-memory store; each transport's
  route, opcode and tool table pinned against `VPNService_ServiceDesc`; one
  error table (`vpnServiceErrorCases`) pins the gRPC code and the QUIC status of
  every `pkg/vpn` error, so the transports cannot drift apart. `make test-vpn`
  runs these, `make coverage-vpn` reports their coverage.
- **Benchmarks** (`make bench-vpn`): the two steps every desired-config pull
  repeats per gateway — `BenchmarkDesiredVPN` renders the `vpn` section from
  the store, `BenchmarkSetEnrolments` applies the enrolment set on the gateway
  (validation, per-peer zone refusal, the lease sweep) — each at 100 and 1000
  peers.
- **Integration, control plane** (`test/integration/vpn/`, `make
  integration-test-vpn`): the CLI and the REST, gRPC, QUIC, MCP and Unix SDK
  adapters run the same peer and posture-policy lifecycle against platformd;
  a node without the control plane must refuse every verb.
- **Integration, admission** *(planned, with the listener)*: a real
  admission over mTLS with the devcontainer's TPM (swtpm) and a fixture posture,
  the peer visible in the kernel (WireGuard, `!fips`) or a MASQUE session
  carrying an ICMP echo, revocation removing it; the same verbs over REST,
  gRPC, QUIC, MCP, Unix and the CLI per the multi-protocol adapter pattern.
- **Fault injection seams**: `Deps` interfaces; the datapath fake can refuse,
  hang (context-bounded) or succeed.

## 8. Observability

Log events (structured): `vpn.admit`, `vpn.refuse` (with `reason` class, never
the policy's identity list), `vpn.renew`, `vpn.revoke`, `vpn.lease.expire`.
The planes add `vpn.wireguard.peer.{install,remove}`,
`vpn.masque.{start,stop}`, `vpn.masque.peer.{install,remove}`,
`vpn.masque.session.{open,close,refused}` and `vpn.masque.packet.dropped`.
Metrics: `vpn_leases_active`, `vpn_admissions_total{outcome}`,
`vpn_revocations_total{reason}`, `vpn_posture_violations_total{rule}`,
`vpn_reattest_duration_seconds`. Audit: every decision through the
`calleradmission.Auditor` sink and the SDK audit record, carrying device id,
tenant, lease id and outcome. The gateway telemetry snapshot carries a `vpn`
section (`VPNState`, §1): admission and refusal counts, the last refusal
reason, enrolled peers, leases per data plane, every lease, the tenants
whose posture policy is refused, and the peers refused from the enrolment set
(each also logged once per set as `vpn.enrolment: peer refused`).

## 9. Replacing the interim endpoint

The interim administrative VPN terminates on the site firewall today. Cutover
order: (1) this service carries administrative sessions in parallel for a
burn-in period with the interim endpoint still up; (2) the management VLAN's
platform endpoints are reachable only through leases (`allow-to`); (3) the
interim endpoint is removed. The interim endpoint is the rollback for the whole
period.
