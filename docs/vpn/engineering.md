# Remote-Access VPN — Engineering Contract

> **Status: PARTIAL — §1 "core" identifiers exist (#584 PR 1); data planes, listener, transports and client are planned.** · Scope: `pkg/sdn/gateway/services/vpn` · Last verified: 2026-09-08
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
| `ManagementVPNServiceConfig{Enabled}` (`management_vpn`) | `pkg/sdn/gateway/types.go` | Service section, to be extended |
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
| `Lease{ID, DeviceID, TenantID, Address netip.Prefix, Zones, DataPlane, Keys, IssuedAt, ExpiresAt, Renewals, Verdict VerdictSummary}`, `LeaseID`, `RevokeReason` (`expired`, `operator`, `client`, `replaced`, `attestation-failed`, `posture-violation`) | Tenant-scoped; `MemoryLeaseStore` is the gateway projection and the test store; the control-plane-backed `LeaseStore` is *(planned)* |
| `PostureReport{SecureBoot, IMA, FDE, AgentVersion, OSRelease, KernelRelease, CollectedAt}`, `VerdictSummary{Passed, Cryptographic, ProfileID}` | The OPA input is `{"posture": report, "verdict": summary}` |
| `DataPlane` interface — `Kind()`, `InstallPeer(ctx, *Lease) error`, `RemovePeer(ctx, LeaseID) error` | Implementations *(planned)*: the WireGuard plane (`!fips`) and the MASQUE plane |
| `Config{Listener{BindHost, Port}, DataPlanes, Pool, LeaseTTL, RenewWindow, RequirePersonFactor{OnAdmit, OnRenew}, PosturePolicy, AllowTo, NonceTTL}`, `WithDefaults`, `Validate`, `Offers` | §5; `Validate` is the startup refusal |
| `DataPlaneMASQUE` (every build), `DataPlaneWireGuard` (`//go:build !fips` file) | Under `fips` the WireGuard symbol does not exist and `Validate` refuses `data-planes: [wireguard]` as a kind this build does not offer |
| `pkg/policy/opa/policies/vpn_posture.rego` (package `vpn.posture`) | Embedded; rules `verdict-required`, `verdict-passed`, `verdict-cryptographic`, `posture-required`, `secure-boot-enabled`, `secure-boot-setup-mode`, `fde-root-encrypted`, `ima-enabled`, `ima-policy-loaded`, `agent-version` |

### Planned (still to be created — names are the requirement)

| Identifier | Package | Contract |
|---|---|---|
| `wireguardPlane` (`!fips`), `masquePlane` | `pkg/sdn/gateway/services/vpn` | The two `DataPlane` implementations; the WireGuard one through `pkg/sdn/tunnel`'s wgctrl seam |
| The admission listener (mTLS-only, `Config.Listener`) and the datapath process client | same | The gateway process model (#557) |
| The control-plane `LeaseStore` and posture-policy CRUD | daemon | §6 |

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
- **Idempotent revoke**; concurrent renew/revoke resolve to revoked. Every multi-step lease operation for one (tenant, device) — admit's find/replace/allocate/install/put, renew's get/verify/put, revoke and the expiry sweep — runs under a per-device lock (`keyLock`), so concurrent admissions cannot both see "no lease" and orphan a peer.
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

Gateway config, `gateway.management_vpn` (extends today's `{enabled}`;
key names hyphenated like the rest of the gateway section; every value also
settable by env and flag per the configuration convention):

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `false` | exists today |
| `listener` | `{bind-host, port}` | `""`, `4433` | admission listener, mTLS-only; the host-filter inventory learns it from here |
| `data-planes` | list of `wireguard \| masque` | `[masque]` | `wireguard` refused under `fips` |
| `wireguard.listen-port` | int | `51820` | `!fips` only |
| `masque.template` | string | `https://{host}:{port}/.well-known/masque/ip/{target}/{ipproto}/` | RFC 9484 URI template |
| `pool` | IPAM pool name | required | `Allocator.GetPoolByName` |
| `lease-ttl` | duration | `8h` | [5m, 24h] |
| `renew-window` | duration | `30m` | < `lease-ttl` |
| `require-person-factor` | `{on-admit, on-renew}` | `{true, false}` | |
| `posture-policy` | name | `vpn_posture` | tenant override via API |
| `allow-to` | zone names | existing `ManagementVPNConfig.AllowTo` | |

Secrets are references, never values: the WireGuard server key and the MASQUE
TLS identity are `kms://` references resolved through `Security().KMS()`.

## 6. Persistence

Leases and posture policies are tenant-scoped entities on the control plane,
reached through the quicbaas SDK's entity/DAO seam (the data-access convention:
entity interfaces over raw KV), keyed `tenant/<id>/vpn/lease/<lease-id>` and
`tenant/<id>/vpn/posture-policy/<name>`; the gateway keeps only an in-memory
projection it rebuilds from the control plane on start (desired-config pull).
No client secret is ever persisted; the WireGuard peer public key and the
MASQUE session id are the only client-side material stored, both in the lease.

## 7. Test strategy

- **Unit** (`pkg/sdn/gateway/services/vpn`): every pipeline step with fakes —
  refused peer, failed verdict, posture violation, posture engine unavailable,
  missing/invalid factor, pool exhausted, datapath failure releases the address,
  lease expiry revokes, second admission revokes the first, FIPS config refusal
  (both tag variants compile). Injected clock; no `time.Sleep`.
- **Golden**: the OPA input JSON for a fixture report; the rendered peer
  configuration for each data plane.
- **Integration** (`test/integration/vpn/`, devcontainer, `NET_ADMIN`): a real
  admission over mTLS with the devcontainer's TPM (swtpm) and a fixture posture,
  the peer visible in the kernel (WireGuard, `!fips`) or a MASQUE session
  carrying an ICMP echo, revocation removing it; the same verbs over REST,
  gRPC, QUIC, MCP, Unix and the CLI per the multi-protocol adapter pattern.
- **Fault injection seams**: `Deps` interfaces; the datapath fake can refuse,
  hang (context-bounded) or succeed.

## 8. Observability

Log events (structured): `vpn.admit`, `vpn.refuse` (with `reason` class, never
the policy's identity list), `vpn.renew`, `vpn.revoke`, `vpn.lease.expire`.
Metrics: `vpn_leases_active`, `vpn_admissions_total{outcome}`,
`vpn_revocations_total{reason}`, `vpn_posture_violations_total{rule}`,
`vpn_reattest_duration_seconds`. Audit: every decision through the
`calleradmission.Auditor` sink and the SDK audit record, carrying device id,
tenant, lease id and outcome. The gateway telemetry snapshot gains a `vpn`
section (active leases per data plane, last refusal reason).

## 9. Replacing the interim endpoint

The interim administrative VPN terminates on the site firewall today. Cutover
order: (1) this service carries administrative sessions in parallel for a
burn-in period with the interim endpoint still up; (2) the management VLAN's
platform endpoints are reachable only through leases (`allow-to`); (3) the
interim endpoint is removed. The interim endpoint is the rollback for the whole
period.
