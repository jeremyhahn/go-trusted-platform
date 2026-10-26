# Remote-Access VPN — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/sdn/gateway/services/vpn`, `pkg/sdn/gateway/ipc`, `pkg/sdn/tunnel`, `pkg/vpn` · Last verified: 2026-10-16
> Conflicts with this document are defects. Fix them here first.
> Partial today: the core (#584 PR 1), both data planes (#584 PR 2), the gateway service and the operator control plane (#584 PR 3) exist; the control-plane lease record and the gateway's projection of it exist (§6); the admission listener (#557), its wire contract and the client agent core (`pkg/vpn/agent`) exist; the JS SDK client and the web page (#584 PR 4) exist, and so do `platformctl vpn connect [--foreground]|disconnect|lease|posture|renew` and their exit codes; the client presents the host's TPM device identity (`TPMDevice`, `OpenHostDevice`), renews its lease with fresh evidence (`Agent.Renew`, `Agent.KeepAlive`) and brings up the leased data plane, WireGuard (`!fips`) or MASQUE CONNECT-IP; the client signs the fido2 person factor (`FIDO2Signer`), while the PIV signer waits on the SDK (§1). The datapath child's peer RPCs, its plane host and the process client that reaches it exist (#584); the gatewayd runtime assembly that wires them is planned (§1).
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
| `Lease{ID, DeviceID, TenantID, Address netip.Prefix, Zones, DataPlane, Keys, IssuedAt, ExpiresAt, Renewals, Verdict VerdictSummary}`, `LeaseID`, `RevokeReason` (`expired`, `operator`, `client`, `replaced`, `attestation-failed`, `posture-violation`) | Tenant-scoped; `MemoryLeaseStore` holds the gateway's leases (on its own, or as the local half of the control-plane projection, §1 Gateway service) and is the test store |
| `(*Service).Restore(ctx) error`, `ErrLeaseNotRestored{LeaseID, Reason, Cause}` | Reinstates the leases the store holds after a restart: each takes its address back (an allocation its device still holds is kept) and has its peer installed. A lease that expired, or whose data plane, zones or address this gateway can no longer give it, is dropped from the store, its address released only if its device holds it, and reported; the reports are joined. Not started is `ErrNotStarted`; an unreadable store `ErrLeaseStoreUnavailable`. Called after `Start` and before the enrolment set, whose sweep then revokes the restored leases of withdrawn peers |
| `PostureReport{SecureBoot, IMA, FDE, AgentVersion, OSRelease, KernelRelease, CollectedAt}`, `VerdictSummary{Passed, Cryptographic, ProfileID}` | The OPA input is `{"posture": report, "verdict": summary}` |
| `DataPlane` interface — `Kind()`, `InstallPeer(ctx, *Lease) error`, `RemovePeer(ctx, LeaseID) error`; `ManagedDataPlane` adds `Start(ctx)`/`Stop(ctx)` | Both shipped planes are managed: the gateway starts them before the service admits leases and stops them after |
| `Config{Listener{BindHost, Port}, DataPlanes, Pool, LeaseTTL, RenewWindow, RequirePersonFactor{OnAdmit, OnRenew}, PosturePolicy, AllowTo, NonceTTL}`, `WithDefaults`, `Validate`, `Offers` | §5; `Validate` is the startup refusal |
| `DataPlaneMASQUE` (every build), `DataPlaneWireGuard` (`//go:build !fips` file) | Under `fips` the WireGuard symbol does not exist and `Validate` refuses `data-planes: [wireguard]` as a kind this build does not offer |
| `Enrolment{TenantID, DeviceID, Zones}`, `(*Service).SetEnrolments(ctx, []Enrolment) error`, `Enrolments()` | A peer is an operator enrolment delivered by the control plane. Admission checks it right after identity: no enrolment → `ErrPeerNotEnrolled`; a requested zone outside a non-empty `Zones` → `ErrZoneNotAllowed`. Before the first delivery nothing is enrolled. A new set revokes (`operator`) every lease it no longer covers. Admission checks the enrolment again after the person factor and keeps it from that check to the lease write under `enrolGate`, which `SetEnrolments` holds exclusively while it publishes and sweeps: a peer withdrawn while its attestation runs is refused (`ErrPeerNotEnrolled`) and holds no lease, and a lease committed just before a withdrawal is in the sweep. Peers are keyed by the (tenant, device) pair, never a joined string, so `("a/b", "c")` and `("a", "b/c")` are two peers. A structurally malformed set (empty tenant or device, a duplicate) is refused whole (`ErrInvalidEnrolment`) and the previous one stays. A peer asking for a zone outside `allow-to` is refused alone, fail closed: it is not enrolled, its leases are revoked, the rest of the set applies, and `RejectedEnrolments()` reports it with the `ErrZoneNotAllowed` text until a later set no longer carries it. Renewal re-checks the enrolment |
| `PosturePolicy{TenantID, Name, Module}`, `CompilePosturePolicy(ctx, PosturePolicy) (*opa.OPAEngine, error)`, `(*Service).SetPosturePolicies(ctx, []PosturePolicy) error`, `PosturePackage` | A tenant policy compiles in an engine of its own, replacing the embedded default, so it must declare `package vpn.posture` and cannot merge with another tenant's rules. The service judges a tenant by its policy named after `posture-policy`, else by the gateway default. A delivered policy that does not compile refuses its tenant (`ErrPostureUnavailable`), never falls back |
| `pkg/policy/opa/policies/vpn_posture.rego` (package `vpn.posture`) | Embedded; rules `verdict-required`, `verdict-passed`, `verdict-cryptographic`, `posture-required`, `secure-boot-enabled`, `secure-boot-setup-mode`, `fde-root-encrypted`, `ima-enabled`, `ima-policy-loaded`, `agent-version` |

### Admission listener — exists since #557 (`pkg/sdn/gateway/services/vpn`)

| Identifier | Contract |
|---|---|
| `NewAdmissionListener(svc *Service, ListenerDeps{Certificate tls.Certificate, ClientCAs ClientCASource, Logger}) (*AdmissionListener, error)` | Binds to `Config.Listener`. A missing service, certificate or CA source is `ErrDepsMissing` |
| `ClientCASource` — `CAPool(ctx) (*x509.CertPool, error)` | The device-identity anchor; `*trust.Anchor` satisfies it. It is read on every handshake, so a rotated anchor applies to the next connection. An error or a nil pool fails the handshake (`ErrListenerTrust`) and never falls back to the system roots |
| `(*AdmissionListener).Start(ctx)`, `Done()`, `Addr()` | `Start` binds (`ErrListenerBind`) and serves TLS 1.3 with `RequireAndVerifyClientCert` until `ctx` is cancelled. It then shuts down, gives in-flight calls a 10 s grace, releases the port and closes `Done`. A listener starts once (`ErrAlreadyStarted`) |
| The routes and bodies of `wire.go` (Control plane, below); `(*AdmissionRequestWire).request`, `(*RenewalRequestWire).evidence` | [api.md](api.md) §5. A handler decodes a wire body, converts it (a PCR value that is not hex is `ErrInvalidRequest`), calls the `Service` and encodes the lease with `LeaseToWire` and `Config.RenewWindow`; every admission decision is the service's. The challenge offers `Config.DataPlanes` in order. The lease's `endpoint` is empty until a plane exposes one |
| `(*Service).OwnLease(ctx, LeaseID, *calleradmission.Peer) (*Lease, error)` | Renew and disconnect act only on the lease whose `ClientCertificateSHA256` matches the presented certificate (constant-time compare); anything else is `ErrLeaseNotFound` |
| `RefusalOf(err)` → `RefusalWire{Reason, Rules}` | Every refusal goes through `RefusalOf` (§3); an unmatched error is `internal` (500) and only the class reaches the client. The client's exit code is `pkg/vpn/agent`'s `ExitCode` |

### Data planes — exist since #584 PR 2

| Identifier | Package | Contract |
|---|---|---|
| `NewWireGuardPlane(hub WireGuardHub, logger) (ManagedDataPlane, error)` (`//go:build !fips`) | `pkg/sdn/gateway/services/vpn` | One kernel peer per lease, whose only allowed address is the lease address. `Start` brings the hub up, `Stop` removes it with every peer |
| `WireGuardHub` interface — `Up`, `Down`, `SetPeer(ctx, publicKey, allowed)`, `RemovePeer(ctx, publicKey)`, `PublicKey()`, `ListenPort()` | same | `*tunnel.WireGuardHub` satisfies it; the plane never sees the server private key |
| `NewMASQUEPlane(cfg MASQUEConfig, dev PacketDevice, logger) (ManagedDataPlane, error)` | same | CONNECT-IP over HTTP/3; a lease binds an address to the client certificate it was admitted under, and the session presenting that certificate is assigned that address |
| `MASQUEConfig{BindHost, Port, Template, TLS, Routes}`, `PacketDevice` | same | `Validate` refuses a listener without a server certificate, without verified client certificates, or with no advertised route. `Stop` is terminal — it closes the host device, which cannot be reopened, so a restart builds a new plane |
| `tunnel.WireGuardHub`, `NewWireGuardHub(logger, WireGuardHubConfig{Name, KeyRef, ListenPort, Addresses, MTU}, KeyProvider)` (`!fips`) | `pkg/sdn/tunnel` | The hub device: many roaming peers on one interface, keyed once from the `KeyProvider` and zeroized |
| `tunnel.TUN`, `OpenTUN(TUNConfig{Name, Addresses, MTU, Routes})` | `pkg/sdn/tunnel` | The MASQUE planes' host-side layer-3 device. `Routes` are installed as link routes through it; a route that fails removes the device |
| `tunnel.WireGuardClient`, `NewWireGuardClient`, `Up(WireGuardClientConfig)`, `Down(name)`, `GenerateWireGuardKey` (`!fips`) | `pkg/sdn/tunnel` | The client WireGuard link: one peer (the gateway), its address, and a route per lease route through it |

### Datapath process — exists since #584 (gateway process model #557)

| Identifier | Package | Contract |
|---|---|---|
| `DatapathService.InstallVPNPeer`, `RemoveVPNPeer`; `VPNPeer{lease_id, data_plane, address, wireguard_public_key, client_certificate_sha256}`, `VPNPeerRefusal{class, field, reason, existing_lease_id}`, `VPNPeerRefusalClass` | `pkg/sdn/gateway/ipc` (`proto/ipc.proto`) | The `DataPlane` seam across the gateway socket, under the datapath UID policy. A plane's refusal travels in the response with the class of its typed error (`INVALID_REQUEST`, `PEER_KEY_INVALID`, `PEER_CONFLICT`, `NOT_STARTED`, `LEASE_NOT_FOUND`, `UNAVAILABLE`); an RPC error means the child never answered. A process hosting no planes refuses `UNAVAILABLE` |
| `(*ipc.Server).SetVPNPlanes(VPNPlanes)`, `ipc.VPNPlanes`; `(*ipc.Client).InstallVPNPeer`, `RemoveVPNPeer` | `pkg/sdn/gateway/ipc` | The child publishes its planes on its server (nil withdraws them); the client is the one channel, shared with `ApplyDesired` |
| `PlaneHost`, `NewPlaneHost(...ManagedDataPlane) (*PlaneHost, error)`, `Start`, `Stop`, `InstallVPNPeer`, `RemoveVPNPeer` | `pkg/sdn/gateway/services/vpn` | The child's side: it owns the planes (and `CAP_NET_ADMIN`), one per kind this build offers. `NewPlaneHost` refuses no planes, a nil plane (`ErrDepsMissing`), a kind the build lacks or a kind twice (`ErrInvalidConfig`), so a FIPS child cannot host WireGuard. `Start` starts them in order and stops the started ones when one fails; `Stop` stops them in reverse. A request it cannot parse is `ErrInvalidRequest` (`peer`, `lease_id`, `address`); a plane it does not host is `ErrDataPlaneUnavailable`; any untyped plane error is `UNAVAILABLE` with its text |
| `DatapathPlane`, `NewDatapathPlane(kind, DatapathPeers) (*DatapathPlane, error)`, `DatapathPeers` | `pkg/sdn/gateway/services/vpn` | The `DataPlane` of a process that does not own the plane; `*ipc.Client` is its `DatapathPeers`. A kind this build does not offer is `ErrDataPlaneUnavailable` (WireGuard under `fips`); no peers is `ErrDepsMissing`. It fails closed: an RPC that gets no answer (child down, socket gone, caller not admitted) is `ErrDataPlaneUnavailable` wrapping the RPC error, and a refusal is rebuilt as the same typed error, an unknown class as `ErrDataPlaneUnavailable` |

### Gateway service — exists since #584 PR 3 (`pkg/sdn/gateway`, `pkg/sdn/gateway/state`)

| Identifier | Contract |
|---|---|
| `ManagementVPNServiceConfig{Enabled, vpn.Config}` (`management_vpn`) | The core `Config` inlined beside `enabled` (§5); `Validate` applies `WithDefaults` and the core's `Validate` when enabled, so a bad section stops gatewayd at load |
| `VPNRuntime{Identity, Verifier, Posture, Factors, IPAM, DataPlanes map[DataPlaneKind]VPNDataPlaneFactory, Leases, Audit, Listener vpn.ListenerDeps}`, `GatewayRuntime.VPN` | What the assembly hands the service. `Listener` is the admission listener's server certificate and device-identity anchor; without them the service refuses to build (`ErrServiceStartFailed` wrapping `ErrDepsMissing`). Planes are factories: every start builds them afresh, because a stopped MASQUE plane has closed its device. A nil `VPN` refuses the service with `ErrRuntimeMissing`; a configured kind without a factory refuses it with `ErrServiceStartFailed` wrapping `ErrDepsMissing`. A nil `Leases` is a `MemoryLeaseStore`; with a lease control plane set it becomes the local half of the projection (below) |
| `serviceBuilders["management-vpn"]` → `buildManagementVPN` | Builds the planes, then `vpn.New`, then the admission listener; a refusal stops the planes already built. `Start` rebuilds the projected leases (below), starts the planes in order, then the service, rolling back on the first failure; with a projection it then calls `Restore` (a dropped lease is logged, not fatal) before applying the enrolment set, and it opens the listener last (a port that will not bind stops the service and the planes). `Stop` cancels the listener's context and waits for its port, then stops the service, then the planes in reverse; without a projection it first revokes every lease (`operator`) so the addresses return to the pool, with one it keeps them, because a stop is not a revocation and the next start reinstates them. The listener therefore runs wherever the service runs: today inside `gatewayd serve` |
| `VPNLeaseControl` (`FetchDesiredConfig`, `PutVPNLease`, `DeleteVPNLease`), `(*Gateway).SetVPNLeaseControl(control, journal)`, `RevocationJournal`, `NewRevocationJournal`, `ErrRevocationJournal{Path, Op, Cause}`, `projectedLeaseStore` | The control plane as the record of the gateway's leases; `controlplane.Reporter` implements it and `gatewayd serve` sets it whenever the reporter runs, with the revocation journal at `<--data-dir>/vpn/pending-revocations.json`. Under the process model the gatewayd supervisor creates `<--data-dir>/vpn` before every launch of the unprivileged `vpn` child, mode `0700` and owned by the child's uid and gid, so the child can write its journal there (`process.Definition.StateDir`, `ErrStateDir`); a relaunched child keeps the leases it admitted and the revocations it journaled (`TestSupervisedRelaunch_AKilledVPNChildKeepsItsLeasesAndPendingRevocations`). The `vpn` child itself (`serveProcess`) does not yet call `SetVPNLeaseControl`; that is part of the VPNRuntime assembly in #584. A control plane set without a journal refuses the service (`ErrServiceUnavailable`). On start the service pulls the desired config once — the same pull, no second channel — loads its `vpn.leases` into the local store and keeps its `vpn` section for the apply. An unreachable control plane refuses the start (`ErrLeaseStoreUnavailable`) before any plane starts, rather than running on an empty projection; a recorded lease that does not parse refuses it (`ErrDesiredConfigInvalid{Field: "vpn.leases[i].address"}`). `Put` goes to the control plane first. A renewal it refuses is `ErrLeaseStoreUnavailable` and leaves the projection unchanged. An admission (a lease the projection does not hold) is journaled before its PUT is sent and cleared once the control plane and the projection both hold it; a journal that cannot be written refuses the admission before anything is sent. A PUT that fails — including one the control plane committed while its answer was lost — or a projection that refuses the lease after the control plane took it fails the admission (`ErrLeaseStoreUnavailable`) and withdraws it: the entry becomes a pending revocation and its DELETE is sent at once, so no failed admission is left recorded for a restart to reinstate. `Delete` (revoke, sweep) journals the revocation as pending, drops the lease from the projection, then sends the control-plane DELETE; a refused DELETE is `ErrLeaseStoreUnavailable` and stays pending, one that lands clears the entry. If the journal cannot be written, the revocation is durable only through the DELETE: one that lands drops the lease; one that is refused too keeps the lease and is `ErrLeaseStoreUnavailable` wrapping `ErrRevocationNotRecorded{LeaseID, Cause}`, and the service then refuses the revocation whole — the peer and the address stay, so the running gateway and a restarted one, which rebuilds the lease from the control plane, agree — until a retry (the caller's, or the next sweep's for an expired lease) is recorded. The service therefore revokes in the order record, peer, address, and `Restore` deletes a dropped lease before releasing its address. Every sweep retries the pending DELETEs alone (`RetryPendingDeletes`, the optional `vpn.PendingDeleteStore`), never the peer removal or address release, so an address handed to another device meanwhile is left intact. A start loads the journal and leaves every lease it names out of the rebuilt projection — a pending revocation, or an admission a previous process journaled and never cleared, whose DELETE becomes pending — so neither survives a process restart and the device must be admitted afresh; a journal that cannot be read or parsed refuses the start (`ErrLeaseStoreUnavailable` wrapping `ErrRevocationJournal`). The journal is the pending revocations and the admissions in flight as JSON, replaced whole through a synced temporary file and a rename; a journal write that fails is `ErrLeaseStoreUnavailable` wrapping `ErrRevocationJournal`. Reads are local |
| `DesiredConfig.VPN` → `DesiredVPN{Peers []DesiredVPNPeer{TenantID, DeviceID, Zones}, PosturePolicies []DesiredVPNPosturePolicy{TenantID, Name, Module}, Leases []DesiredVPNLease}`, `DesiredVPNVerdict`, `SectionVPN` | The control plane's enrolment set and tenant posture policies, and the leases this gateway recorded (read only on start, above; each needs an ID, tenant, device, data plane, a prefix address and an expiry after its issue time, and no (tenant, ID) repeats; not part of the content version). `Gateway.Apply` validates it (tenant and device required, no duplicate (tenant, device) peer or (tenant, name) policy, compared field by field), records it and hands it to the running service: policies first, then enrolments. A section that arrives before the service starts is applied as it starts. A gateway that does not run the VPN ignores the section. A supervised VPN applies it in the `vpn` child: the supervisor sends that child the whole document on every apply and at each launch, and the child applies only the sections of the services it hosts |
| `Snapshot.VPN` → `VPNState{Running, Admissions, Refusals, LastRefusal, EnrolledPeers, LeasesByDataPlane, Leases []VPNLeaseState, PosturePolicyErrors, RejectedPeers []VPNRejectedPeer, Revocations, PostureViolations, Reattest *DurationHistogram}`, `(*Service).PosturePolicyErrors()`, `(*Service).RejectedEnrolments()` | The telemetry section; absent while the service is not running here. A tenant whose delivered policy is refused is listed with the reason, and so is every peer refused from the last enrolment set (`rejected_peers` in the API) |

### Control plane — exists since #584 PR 3 (`pkg/vpn`, `pkg/api/daemon`)

| Identifier | Contract |
|---|---|
| `NewService(quicbaas.Storage, *logging.Logger)`, `(*Service).EnrolPeer`, `ListPeers`, `RevokePeer`, `GetPosturePolicy`, `SetPosturePolicy`, `DeletePosturePolicy`, `ListPosturePolicies` | Peers and posture policies are platform-store records (§6). `EnrolPeer` is an upsert that keeps the first enrolment time. `SetPosturePolicy` compiles the module before storing it (`ErrInvalidPosturePolicy`); policy names are letters, digits, `_`, `-`, `.` |
| `(*Service).SetGatewaySnapshotStore`, `Status(ctx, gatewayID)` | Status reads the gateways' telemetry snapshots (`Snapshot.VPN`). Without a store it is `ErrStatusUnavailable`; an unknown gateway is `ErrGatewayNotFound` |
| `Lease{LeaseID, GatewayID, TenantID, DeviceID, Address, Zones, DataPlane, WireGuardPublicKey, ClientCertificateSHA256, IssuedAt, ExpiresAt, Renewals, Verdict}`, `NewLeaseStore(quicbaas.Storage, *logging.Logger)`, `(*LeaseStore).Put`, `Get`, `Delete`, `List(ctx, tenantID)`, `ListByGateway`, `Sweep` | The control-plane lease store (§6). A lease is written and deleted only by the gateway that issued it (`ErrLeaseOwnedByOtherGateway`); a malformed lease is `ErrInvalidArgument`; an unknown one is the core's `ErrLeaseNotFound`; every read or write the store cannot complete is the core's `ErrLeaseStoreUnavailable`. `List` orders by issue time, as `MemoryLeaseStore` does. `Sweep` removes the leases expired by the core's rule (`ExpiresAt` reached), re-reading each one under the lock `Put` and `Delete` take, so a renewal saved after the sweep listed it survives — the platform store has no conditional delete |
| `(*Service).DesiredVPN(ctx, gatewayID)` | The `vpn` section the daemon overlays on a gateway's desired config ([docs/gateway/engineering.md](../gateway/engineering.md)): the enrolled peers and policies, and the leases that gateway recorded. It sweeps the expired leases first |
| `(*Service).RecordGatewayLease(ctx, gatewayID, *DesiredVPNLease)`, `ReleaseGatewayLease(ctx, gatewayID, tenantID, leaseID)`, `restgateway.VPNLeaseSink` | The gateway's write-through of each admission, renewal and revocation, over the gateway-facing lease routes ([api.md](api.md) §6). Releasing a lease the store no longer holds succeeds |
| `VPNGRPCService`, `vpnErrToGRPC` | The one service every transport calls. Errors map as [api.md](api.md) §3; a daemon without the service refuses every RPC `Unavailable` |
| `sdk/go/services/vpn.Client`, `NewClientFromGRPC` | The Go client the CLI and the integration suite use, over any transport |
| `PathChallenges`, `PathAdmissions`, `LeasePath`, `LeaseRenewPath`; `ChallengeWire`, `AdmissionRequestWire`, `RenewalRequestWire`, `AttestationWire`, `PersonFactorWire`, `PeerWire`, `LeaseWire`, `EndpointWire`; `RefusalClass`, `RefusalWire`, `RefusalOf(err)`; `DecodeRequest(r, into)` (`pkg/sdn/gateway/services/vpn/wire.go`) | The admission listener's wire contract ([api.md](api.md) §5), shared by the listener and the client so the two cannot drift. `RefusalOf` is the one place a typed admission error becomes a reason class and an HTTP status. `DecodeRequest` is the listener's body rule — an unknown field or trailing data is `ErrInvalidRequest{Field: "body"}` — and the client's tests decode every body they send with it |
| `pkg/vpn/agent`: `Agent` (`New(Deps)`, `Connect`, `Disconnect`, `Lease`, `Posture`, `Renew`, `KeepAlive`), the `Device` / `PostureSource` / `FactorSigner` / `DataPlane` / `Gateway` / `StateStore` seams | The client admission: dial with the device certificate, fetch the challenge, pick a plane, bind the quote and the factor to the nonce, admit under `ConnectOptions.TenantID` (required: an empty tenant is `ErrInvalidOptions{Field: "tenant"}` before anything is dialled), bring the plane up, record the lease. A plane that fails to come up, or a lease that cannot be recorded, is torn down and revoked (`ErrRollback` when the cleanup itself fails). The undo runs on its own context, bounded at 10 s from the moment the cleanup begins and detached from the connect's cancellation, so a connect cancelled or timed out after admission still releases the peer and its address. `Disconnect` revokes and tears down; a lease the gateway no longer holds counts as gone |
| `(*Agent).Renew(ctx)`, `(*Agent).KeepAlive(ctx)`, `Deps.After`, `State.Factor`, `ErrLeaseLapsed` | Renewal over a fresh challenge: a `RenewalRequestWire` with the same quote, posture and person-factor evidence as an admission (the factor `connect` presented, kept in `State.Factor`). It names no device, plane, zones or peer; the gateway keeps the held lease's. A refusal ends the lease (revoke, plane down, state removed; `ErrRollback` when that fails) unless it is `renewal-not-open`, `nonce-unknown` or a 503, which keep it. A renewal answered with another lease or plane is `ErrInvalidResponse` and keeps the held lease. `KeepAlive` waits on `Deps.After` (default `time.After`) until each `RenewAtUnix`, retries any other failure every 30 s capped at expiry, ends an expired lease with `ErrLeaseLapsed` (which unwraps to the last failure), and returns nil when its context ends |
| `HTTPGateway`, `NewHTTPGateway`, `DialHTTPGateway` | The admission client (`Challenge`, `Admit`, `Renew` to `LeaseRenewPath`, `Revoke`): TLS 1.3, the device certificate as the client certificate, the gateway verified against the given roots. A non-2xx answer decodes as `RefusedError{Status, Class, Rules}`; anything that is not the contract is `ErrInvalidResponse` |
| `TPMDevice`, `NewTPMDevice(TPMDeviceConfig)`; `HostDevice`, `OpenHostDevice(HostDeviceOptions)` | The TPM-backed `Device`. `OpenHostDevice` opens the TPM from the platform configuration's `tpm` section through the SDK's `xkms.NewTPM2` (no key, blob or certificate store), names unnamed IAK/IDevID keys `<hostname>-iak` / `<hostname>-idevid` as platformd does, and signs the mTLS handshake with the IDevID key (`platform.NewTPMSigner`). The certificate chain comes from `--idevid-cert`, else the TPM's NV index. `Quote` is `attestation/service.CollectHostAttestation` over the nonce, carrying the IDevID certificate. A missing configuration, TPM, IDevID key or certificate is `ErrNoDevice` / `ErrIDevIDCertificate` (exit 1) |
| `HostPosture`, `NewHostPosture` | The posture collector (§4) |
| `FIDO2Signer`, `NewFIDO2Signer(FIDO2SignerOptions{RPID, CredentialID})` (`factor_fido2.go`) | The `FactorSigner` for the fido2 person factor, over the SDK's FIDO2 handler (`quicbaas/sdk/go/xkms/fido2`, `AssertWithOptions`) on the first authenticator attached to the host. It asks for a WebAuthn assertion whose challenge is the session nonce, under `RPID`, for `CredentialID` (unpadded base64url; empty lets the authenticator pick a discoverable credential), with `userVerification: discouraged` — a touch, no PIN (the SDK's PIN-carrying `Assert` is not re-exported). The factor's `Assertion` is the PublicKeyCredential JSON (`id`, `rawId`, `type`, `response{authenticatorData, clientDataJSON, signature, userHandle}`), its `CredentialID` the credential that asserted. A missing RP ID or a credential ID that is not unpadded base64url is `ErrInvalidOptions`; another factor kind is `ErrFactorUnsupported`; no authenticator, no touch or a failed close is `ErrAuthenticator`; an answer without a credential id is `ErrInvalidAssertion` (all exit 1) |
| `FileStateStore` (`/run/platformctl/vpn.json`, 0600 in a 0700 directory, atomic rename) | The held lease and the local session; no secrets |
| `ExitCode(err)`: 0, 4 refused, 5 posture violation, 6 not connected, 1 otherwise | The exit codes of [cli.md](cli.md). A refusal met while rolling back never decides the code |
| `VPNService` (`sdk/javascript/src/services/vpn-service.ts`), `PlatformClient.vpn`, `useVPN` | The JS client over the REST routes: the same eight operations, with the protojson field names and string 64-bit integers ([api.md](api.md) §2) |
| `web/src/app/(dashboard)/networking/vpn/page.tsx` (Networking → VPN) | The operator page over `useVPN`: gateway status and sessions, enrolled peers with enrol (`enrolPeer`; the zone field is comma-separated, empty for every allowed zone) and revoke, posture policies listed, viewed, edited and deleted after a confirmation (`deletePosturePolicy`). A refused enrolment, revoke, save or delete keeps its dialog open. A node without the control plane shows the not-available state; a daemon without gateway telemetry still lists peers and policies |
| `New` without a `Device` or `DataPlanes`; `ErrNoDevice` | Posture, state store and dialer are required; the device and the planes are not, so a host without them still reads its lease. `Connect` and `Disconnect` then fail with `ErrNoDevice` before any gateway is dialled (exit 1) |
| `platformctl vpn connect`, `disconnect`, `lease`, `posture`, `renew` (`pkg/cli/commands/vpn/client.go`) | The client verbs over `pkg/vpn/agent` ([cli.md](cli.md)). `--ca-file` gives the gateway's roots. `connect`, `renew` and `disconnect` open the host's `TPMDevice` (`OpenHostDevice`; `--device-id`, `--idevid-cert`) and close it on return; a host without one exits 1 with `ErrNoDevice`, and `disconnect` still tears down and forgets the local lease. `connect --foreground` runs `KeepAlive` under a SIGINT/SIGTERM context and disconnects when it ends. `clientDataPlanes` gives the agent WireGuard (absent under `fips`) on every verb that brings a plane up or down, and MASQUE only where its TUN can be held or ended: `connect --foreground`, `renew` and `disconnect` (in a process that holds no tunnel its `Down` is a no-op; the gateway's revoke ends the session). `connect --data-plane masque` without `--foreground` is `ErrForegroundRequired` (exit 1) before the TPM is opened. `connect` and `renew` build a `FIDO2Signer` from `--fido2-rp-id` / `--fido2-credential-id` before the TPM is opened (a bad flag exits 1 there); without them the agent has no signer and refuses a person factor, so `renew` of a fido2 lease takes the same flags, since the state records only the factor kind. `lease` and `posture` get no plane. The verbs are tested against an `httptest` server standing in for the admission listener |
| `NewWireGuardPlane(logger)`, `WireGuardInterface` (`vpn-wg0`) (`!fips`) | The client WireGuard plane over `tunnel.WireGuardClient`. `Prepare` makes a fresh key pair per admission and sends the public half; `Up` keys `vpn-wg0` with it (the key is zeroized whether or not the bring-up succeeds and never used twice), peers it with the lease's gateway key and endpoint (a host name is resolved), addresses it with the lease address and routes the lease's routes. The link is a kernel object, so it outlives the command and `disconnect` removes it by name. A lease it cannot use is `ErrLeaseUnusable`; `Up` without a prepared key is `ErrNotPrepared` |
| `NewMASQUEPlane(certificate, roots, logger)`, `MASQUEInterface` (`vpn-masque0`) | The client MASQUE CONNECT-IP plane (RFC 9484, `connect-ip-go` over quic-go). `Up` dials the lease's template authority over HTTP/3 with the device certificate (TLS 1.3, the gateway verified against `roots`), opens the CONNECT-IP session, requires the gateway to assign the lease address (`ErrAddressNotAssigned`) and waits for its routes, then opens `vpn-masque0` with the lease address and routes and pumps packets both ways. A non-2xx answer is `ErrSessionRefused{Status}`; a gateway that cannot be reached, or that ends the session during setup, is `ErrGatewayUnreachable`; a template with variables, a non-https template or a bad address or route is `ErrLeaseUnusable`; a second `Up` while a tunnel is held is `ErrAlreadyConnected`. The TUN dies with the process, so the tunnel lives only in the process that connected; a session the gateway ends closes the TUN (`vpn.masque.session.ended`) |
| `cli.ExitError{Code, Err}`, `cli.ExitCode(err)` (`pkg/cli/exitcode.go`) | The exit-code plumbing: `cmd/platformctl` exits with the code of an `ExitError` in the error chain and 1 for every other failure |

### Planned (still to be created — names are the requirement)

| Identifier | Package | Contract |
|---|---|---|
| The gatewayd assembly of `VPNRuntime`: the planes from `masque.*` / `wireguard.*` keys, the listener's TLS, and a `FactorVerifier` over the SDK | `pkg/sdn/gateway/commands` | Blocked on the SDK: no quicbaas verb verifies a FIDO2 or PIV assertion over a caller nonce. Until then gatewayd refuses a configured `management_vpn` with `ErrRuntimeMissing` |
| The PIV `FactorSigner` over the SDK | `pkg/vpn/agent` | Blocked on the SDK: the quicbaas re-exports give a client no way to sign with a PIV card's key (no PKCS#11 or PC/SC `PIVKeyGenerator`, and `XKMSPIVService` has no sign verb). Until then `--factor piv` is refused before the gateway is dialled |

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
| `ErrListenerBind{Address, Cause}` | the admission listener cannot bind `Config.Listener` | service start failure; the gateway rolls the service and planes back |
| `ErrListenerTrust{Cause}` | the device-identity anchor yields an error or no pool | the handshake fails; no handler runs |

On the admission listener each of these reaches the client as a `RefusalClass`
(`RefusalOf`, [api.md](api.md) §5, which has the full class and status table):
the `calleradmission` reason for `ErrPeerRefused`, otherwise the error's
kebab-case name (`posture-violation`, `pool-exhausted`, `peer-conflict`, …).
`ErrDataPlaneNotStarted` shares `data-plane-unavailable` and `ErrPeerKeyInvalid`
shares `invalid-request`. The client turns the class back into `RefusedError`
and its exit code.

## 4. Posture

The report is what the client agent can collect **from this repository's code
today**; anything else is future and must not be assumed by a policy:

| Fact | Source | Status |
|---|---|---|
| Secure Boot enabled, setup mode, efivars availability | `pkg/uefi.ReadSecureBootStatus` | collectable |
| IMA available / enabled / policy loaded; measurement log digest | `pkg/ima.Status`, `pkg/ima.NewReader` | collectable |
| Full-disk encryption present on the root volume | sysfs: the root mount's block device (`/proc/self/mountinfo`; the source device for an anonymous device number; for btrfs, every member device the filesystem lists under `/sys/fs/btrfs/<fsid>/devices/`, since the mount names only one) is a device-mapper target whose `dm/uuid` starts `CRYPT-LUKS`, directly or under other layers through `slaves/` (LVM on LUKS, RAID on LUKS). Every path down to the physical devices must pass through a LUKS mapping: one plain member of an LVM group, RAID array or btrfs filesystem makes the root unencrypted, and so does a btrfs root whose filesystem is not found in sysfs or a part of the device tree that cannot be read (fail closed). The `sdk/go/xkms/luks` re-export opens and seals volumes but has no probe for the mounted root | collected (`HostPosture`) |
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
gateway section. The `wireguard.*` and `masque.*` keys are parsed and
validated per offered plane (`Config.Validate`); the assembly that builds the
planes from them is the planned `VPNRuntime` row in §1.

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `false` | |
| `listener` | `{bind-host, port}` | `""`, `4433` | admission listener, mTLS-only; the host-filter inventory learns it from here |
| `data-planes` | list of `wireguard \| masque` | `[masque]` | `wireguard` refused under `fips` |
| `wireguard.listen-port` | int | `51820` when `wireguard` is offered | 1-65535. `!fips` only: set without `wireguard` in `data-planes` (always so under `fips`) it is refused |
| `masque.template` | string | required when `masque` is offered | RFC 9484 §3 URI template: an absolute `https` URL with a host and a path. IP flow forwarding (`{target}`/`{ipproto}` variables) is not offered: the proxy carries whole IP packets, so the template takes no variables |
| `masque.routes` | prefixes | required when `masque` is offered | Advertised to an admitted client as RFC 9484 §4.6 address ranges. At least one is required — a client may send only to an advertised range, so a session with no route can carry nothing |
| `pool` | IPAM pool name | required | `Allocator.GetPoolByName` |
| `lease-ttl` | duration | `8h` | [5m, 24h] |
| `renew-window` | duration | `30m` | < `lease-ttl` |
| `require-person-factor` | `{on-admit, on-renew}` | `{true, false}` | |
| `posture-policy` | name | `vpn_posture` | tenant override via API |
| `allow-to` | zone names | existing `ManagementVPNConfig.AllowTo` | |

`masque` is the default plane, so a section that names no data planes still
needs `masque.template` and `masque.routes`. Each plane's keys are refused when
that plane is not in `data-planes`, rather than silently ignored. Every refusal
is an `*ErrInvalidConfig` naming the key:

| `Field` | Cause |
|---|---|
| `wireguard.listen-port` | set while `wireguard` is not offered (every `fips` build), or outside 1-65535 |
| `masque` | `masque.template` or `masque.routes` set while `masque` is not offered |
| `masque.template` | missing; not a URI template; has variables; not an absolute `https` URL with a host; no path (RFC 9484 §3) |
| `masque.routes` | empty, or a prefix that is not valid (RFC 9484 §4.6) |

Secrets are references, never values: the WireGuard server key and the MASQUE
TLS identity are `kms://` references resolved through `Security().KMS()`. The
WireGuard hub resolves its key reference through `tunnel.KeyProvider` once at
`Up`, hands the material to the kernel and zeroizes it; only the derived
public key stays in memory, and it is what an admission response advertises.

## 6. Persistence

Enrolled peers, posture policies and leases exist today: `pkg/vpn` stores them
as `VPNPeer`, `VPNPosturePolicy` and `VPNLease` records in the platform store,
keyed by `<tenant>/<device>`, `<tenant>/<name>` and
`tenant/<id>/vpn/lease/<lease-id>`. Two keys that hash to the same record ID
are refused (`ErrKeyCollision`) rather than overwriting each other. A lease
record also names the gateway that issued it, which is the only gateway that
may rewrite or delete it.

Leases and posture policies are tenant-scoped entities on the control plane,
reached through the quicbaas SDK's entity/DAO seam (the data-access convention:
entity interfaces over raw KV), keyed `tenant/<id>/vpn/lease/<lease-id>` and
`tenant/<id>/vpn/posture-policy/<name>`; the gateway keeps only an in-memory
projection it rebuilds from the control plane on start (desired-config pull),
and a journal of the revocations the control plane has not yet taken and the
admissions whose PUT may have landed without an answer, which keeps both out
of that rebuild.
Every admission, renewal and revocation is written to the control plane before
the projection, so a write the control plane refuses fails the operation; a
failed admission is deleted from the control plane again. A revocation that
neither the journal nor the control plane can record is refused and leaves
the session in place, so a restart cannot reinstate a session the gateway had
torn down. A gateway that cannot reach the control plane
at start refuses to start rather than run on an empty projection, and stopping
keeps the records, so the next start reinstates the sessions that have not
expired. No client secret is ever persisted. The lease stores the client's WireGuard
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
- **Unit, admission listener**: a real TLS 1.3 listener on `127.0.0.1:0`
  with a throwaway CA — each verb for a valid device certificate, another
  device's lease answering not found, a handshake refused for no certificate,
  a foreign CA, an expired certificate, or an anchor that fails or yields no
  pool; a malformed body as a typed 400; shutdown releasing the port with no
  serving goroutine left. The gateway tests open the listener with the
  service, release its port on stop, and roll back on a port already taken.
- **Control plane**: `pkg/vpn` against an in-memory store; each transport's
  route, opcode and tool table pinned against `VPNService_ServiceDesc`; one
  error table (`vpnServiceErrorCases`) pins the gRPC code and the QUIC status of
  every `pkg/vpn` error, so the transports cannot drift apart. `make test-vpn`
  runs these, `make coverage-vpn` reports their coverage.
- **Lease record** (unit, in memory): `pkg/vpn` records, releases and sweeps
  a gateway's leases and serves them in that gateway's section only;
  `Restore` reinstates a recorded lease and drops one it can no longer give
  (expired, data plane, zones, address, data-plane refusal); the gateway
  rebuilds its projection from a seeded control plane, revokes a restored
  lease whose peer was withdrawn, writes every change through, refuses to
  start when the control plane is unreachable and keeps the records on stop;
  a revocation the control plane refused stays out of a second gateway
  started over the same journal, and an unreadable journal refuses the start;
  a revocation that neither the journal nor the control plane records keeps
  the lease, its peer and its address, and a restart agrees with it; an
  admission whose PUT committed but failed, or whose projection refused it
  after the PUT, is deleted again and stays out of a restart's rebuild;
  the gateway-facing lease routes refuse another gateway's record.
- **Benchmarks** (`make bench-vpn`): the two steps every desired-config pull
  repeats per gateway — `BenchmarkDesiredVPN` renders the `vpn` section from
  the store, `BenchmarkSetEnrolments` applies the enrolment set on the gateway
  (validation, per-peer zone refusal, the lease sweep) — each at 100 and 1000
  peers.
- **Integration, control plane** (`test/integration/vpn/`, `make
  integration-test-vpn`): the CLI and the REST, gRPC, QUIC, MCP and Unix SDK
  adapters run the same peer and posture-policy lifecycle against platformd;
  a node without the control plane must refuse every verb.
- **Integration, admission** *(planned, with the gatewayd assembly)*: a real
  admission over mTLS with the devcontainer's TPM (swtpm) and a fixture posture,
  the peer visible in the kernel (WireGuard, `!fips`) or a MASQUE session
  carrying an ICMP echo, revocation removing it; the same verbs over REST,
  gRPC, QUIC, MCP, Unix and the CLI per the multi-protocol adapter pattern.
- **Fault injection seams**: `Deps` interfaces; the datapath fake can refuse,
  hang (context-bounded) or succeed. `DatapathPeers` stands in for the child:
  the tests answer with every refusal class, an unknown class and an RPC
  error, and `pkg/sdn/gateway/ipc` runs `DatapathPlane` over a real socket to
  a `PlaneHost`, to a missing socket and as a caller the policy refuses.

## 8. Observability

Log events (structured): `vpn.admit`, `vpn.refuse`, `vpn.renew`, `vpn.revoke`
and `vpn.lease.expire`. `vpn.refuse` carries `device`, the refusal `reason`
class (`RefusalOf`, [api.md](api.md) §5) and, for a posture violation, the violated `rules`. It never
carries a policy refusal's error text, which can hold the policy's identity
list. Only a refusal the gateway caused (a 5xx class: the lease store, a data
plane or the posture engine is down) adds `error`, naming the failing
dependency. `Sweep` logs `vpn.lease.expire` (`lease`, `device`, `expired_at`)
before the `vpn.revoke` with reason `expired`.
The planes add `vpn.wireguard.peer.{install,remove}`,
`vpn.masque.{start,stop}`, `vpn.masque.peer.{install,remove}`,
`vpn.masque.session.{open,close,refused}` and `vpn.masque.packet.dropped`.
Metrics come from the `vpn` telemetry section through the gatewayd collector
(`pkg/sdn/gateway/metrics.go`), so they and the control plane's
`GetStatus` always agree. Each carries the `gateway` label and is absent
while the service is not running on the gateway:

| Series | Type | Counts |
|---|---|---|
| `gatewayd_vpn_leases_active{data_plane}` | gauge | active leases per data plane |
| `gatewayd_vpn_admissions_total{outcome}` | counter | `admitted` and `refused` decisions |
| `gatewayd_vpn_revocations_total{reason}` | counter | revoked leases by `RevokeReason` (`expired`, `operator`, `attestation-failed`, …); a revoke the journal did not record is not counted |
| `gatewayd_vpn_posture_violations_total{rule}` | counter | each posture rule that refused an admission or a renewal (`posture-missing` and `denied` included); past 64 distinct rule names the rest count as `other`, so a tenant policy cannot grow the label set; an engine failure is a refusal, not a violation |
| `gatewayd_vpn_reattest_duration_seconds` | histogram | how long a renewal's re-attestation took to verify, passed or failed (buckets 5ms–10s); the admission attestation is not a re-attestation |

`vpn.Health()` carries the same counts (`Revocations`, `PostureViolations`,
`Reattest DurationHistogram`), counted lock-free in
`services/vpn/meters.go`. Audit: every decision through the
`calleradmission.Auditor` sink and the SDK audit record, carrying device id,
tenant, lease id and outcome. The gateway telemetry snapshot carries a `vpn`
section (`VPNState`, §1): admission and refusal counts, the last refusal
reason, enrolled peers, leases per data plane, every lease, the tenants
whose posture policy is refused, the peers refused from the enrolment set
(each also logged once per set as `vpn.enrolment: peer refused`), and the
revocation, posture-violation and re-attestation counts above
(`revocations`, `posture_violations`, `reattest` in the API).

## 9. Replacing the interim endpoint

The interim administrative VPN terminates on the site firewall today. Cutover
order: (1) this service carries administrative sessions in parallel for a
burn-in period with the interim endpoint still up; (2) the management VLAN's
platform endpoints are reachable only through leases (`allow-to`); (3) the
interim endpoint is removed. The interim endpoint is the rollback for the whole
period.
