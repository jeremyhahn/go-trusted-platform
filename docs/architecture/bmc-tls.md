# BMC TLS Certificate Management -- Architecture

End-to-end automated TLS certificate issuance, deployment, and
renewal for each node's own baseboard management controller (BMC).
Each platformd instance manages only its own BMC's cert; renewal is
driven by the embedded quicbaas scheduler with node-affine job
dispatch so a cluster-wide raft deployment still produces exactly
one renewal per node per tick.

## Components at a glance

```
 +----------------------------+
 | platform config YAML       |
 |   bmc:                     |
 |     certificate: {...}     |
 |     key: {...}             |
 |     backend: auto          |
 +-------------+--------------+
               |
               v
 +----------------------------+
 | app.InitBMCCertManagement  |  orchestrator -- called once at boot
 +-------------+--------------+
               |
     +---------+----------+-----------------+
     |                    |                 |
     v                    v                 v
 +-------+     +--------------------+   +------------------+
 | issue |     | CertTargetRegistry |   | RegisterCert-    |
 | BMCCert     |  .Register(target) |   | Renewal(...)     |
 | Core  |     +--------------------+   +--------+---------+
 +---+---+                                       |
     |                                           v
     | generate ECDSA                 +------------------------+
     | build CSR                      | quicbaas scheduler     |
     | ACME (dns-01) or local CA      |  .RegisterHandler(     |
     | deploy via AutoCertManager     |    "platform.cert-     |
     |                                |     renewal",          |
     v                                |    certRenewalHandler) |
 +-------+                            |  .ScheduleJob(         |
 | BMC   | <------ Redfish           |    NodeAffinity:<N>,    |
 | vendor|   or    SMC CGI           |    Recurring,           |
 | probe |                            |    "0 2 * * *")        |
 +-------+                            +-----------+------------+
                                                  |
                                     (every tick, on owner node only)
                                                  |
                                                  v
                                      +-------------------------+
                                      | certRenewalHandler:     |
                                      |   for each target:      |
                                      |     if due:             |
                                      |       target.Reissue()  |
                                      |       -> issueBMCCertCore
                                      |          -> deploy      |
                                      +-------------------------+
```

## Why dns-01, not http-01

BMCs sit on isolated management VLANs unreachable from ACME servers.
http-01 requires the validator to reach the authorizing host on
TCP/80 -- impossible across VLAN boundaries. dns-01 places a TXT
record at `_acme-challenge.<fqdn>` that the ACME server queries
instead, which works because the platform DNS is authoritative for
the internal zone.

Enforcement:
- `pkg/bmc/config.go` `Config.Validate` rejects any
  `Certificate.ACME.Challenge != "dns-01"` with an
  operator-facing error explaining why.
- `pkg/app/bmc_cert.go` `buildBMCACMERequest` re-validates as
  defense-in-depth.

## DNS-01 challenge handling

DNS-01 challenge setup and cleanup are implemented as inline
closures in `pkg/app/bmc_cert.go:buildBMCACMERequest`. These
closures wrap the platform DNS service (`pkg/dns`) to create and
remove `_acme-challenge` TXT records.

The go-xkms ACME client (pkg/acme, formerly go-trusted-ca, consumed via go-quicbaas SDK)
provides the ACME challenge integration. The platform passes its
setup/cleanup closures to the ACME request, which invokes them
during the dns-01 challenge flow.

During setup the closure performs the RFC 8555 8.4 transformation
`TXT = base64url(SHA-256(keyAuth))` before writing the record,
because the ACME client passes HTTP-01-format keyAuth to setup
callbacks regardless of challenge type.

## Backend selection -- AutoCertManager

`pkg/bmc/auto_cert.go` `AutoCertManager` dispatches to a backend
based on vendor probe + config:

| Backend setting | Dispatch |
|---|---|
| `""` / `auto` | Probe `/redfish/v1/`; use `RecommendCertBackend(vendor)`. Supermicro -> SMC-CGI; others -> Redfish CertificateService. |
| `redfish` | Force `redfishCertManager`. |
| `smc-cgi` | Force Supermicro CGI (bypasses hardware-validation gate). |

Factory registry pattern resolves the import-cycle concern between
`pkg/bmc` and `pkg/bmc/smc`. Smc registers itself via `init()` on
side-effect import; parent `pkg/bmc` has the interface + registry.

### X10 ATEN CGI fallback gate

The `allow_cgi_fallback` config field (default `false`) gates
auto-mode selection of `smc-cgi` until real X10 hardware validates
the CGI wire protocol. Explicit `backend: smc-cgi` pinning bypasses
the gate -- operators who know their hardware works can opt in
before the blanket clearance.

## Cluster scheduling (the exactly-once trick)

The cert-renewal job is created with `NodeAffinity: <nodeID>`.
The go-quicbaas scheduler engine (P1 patch) consults a per-job
`shouldExecute` gate before executing:

| Gate | NodeAffinity setting | Dispatch decision |
|---|---|---|
| Scheduler without `LeaderChecker` (single-node, test mode) | any | execute |
| Scheduler WITH `LeaderChecker` | `""` (cluster-wide) | execute iff `IsLeader() == true` |
| Scheduler WITH `nodeID` + `LeaderChecker` | non-empty | execute iff `NodeAffinity == s.nodeID` -- **leader status irrelevant for affine jobs** |

The affinity path correctly handles node-local work (BMC cert
renewal depends on local secret store + local TLS config + a BMC
only this node can reach); the leader path correctly handles
cluster-wide work (audit cleanup, KMS grace period) that must fire
once across the cluster regardless of which node ends up doing it.

## Credentials -- memguard end-to-end

Private keys and passwords live in `*memguard.MemoryEnclave`
(memguard-backed locked memory) from the service/manager boundary inward.
The config, CLI-prompt and credential-record boundaries ahead of it still
materialise a plain string first — see
[protected memory](../security/protected-memory.md) for the type, its
vocabulary, and the known gaps. Brief unlocked `[]byte` appears
only when PEM is serialized into an HTTP body; those buffers are
scrubbed immediately after `httpClient.Do` returns. No
`KeyStore`/`KMS` persistence for BMC TLS private keys -- each
renewal generates a fresh ephemeral ECDSA P-256 keypair in-process,
ships cert+key to the BMC, scrubs, and forgets. The BMC owns its
own key; the platform just signs fresh CSRs.

## Node ownership model

Each platformd has its own BMC config:

```yaml
bmc:
  address: bmc-node-17.internal
  port:    443
  username: admin
  password: "..."
  certificate:
    subject: { cn: bmc-node-17.internal }
    sans: { dns: [bmc-node-17.internal] }
    acme:
      request: { authz_type: dns, challenge_type: dns-01 }
  key:
    algorithm: ECDSA
    cn: bmc-node-17.internal
  backend: auto
  allow_cgi_fallback: false
```

Each platformd node independently:
1. Issues its own BMC's initial cert at boot
2. Registers a `CertTarget` in its local `CertTargetRegistry`
3. Creates a `platform.cert-renewal.<nodeID>` job pinned via
   `NodeAffinity` to itself

In a 3-node raft cluster the scheduler store is replicated on
PlatformShardID=1 -- three jobs exist (one per node, distinct
names), and each fires only on its owning node via the affinity
gate. No two nodes ever race on the same cert.

## Renewal cadence

Schedule: `"0 2 * * *"` (02:00 daily) by default. Threshold: 30
days -- certs within 30 days of `NotAfter` get reissued. Both are
configurable on `CertRenewalRegistration`. The handler snapshots
the registry, evaluates each target, and records per-target outcome
in the JobResult.Payload (JSON array of `renewalResult`) for
`GetJobHistory` audit.

Partial failure does not abort the sweep: if BMC-A's renewal fails
(ACME rate limit, BMC unreachable, etc.), BMC-B and BMC-C still get
their turn. The job surfaces `Success=false` so operators can query
history and re-run failed targets via manual `TriggerJob`.

## Boot wiring

Platformd adds one call near the end of `App.Init*`:

```go
if err := app.InitBMCCertManagement(ctx, InitBMCCertManagementOptions{
    BMCConfig:     app.BMCConfig,
    NodeID:        app.NodeID,        // e.g., raft node ID
    ACMEIssuer:    app.ACMEClient,
    LocalCAIssuer: app.CA,
    DNSUpdater:    app.DNSService,
    Hostmaster:    app.Hostmaster,
    Scheduler:     app.Scheduler,     // *scheduler.SchedulerEngine
    Registry:      app.CertTargets,   // *CertTargetRegistry
    Logger:        app.Logger,
}); err != nil {
    app.Logger.Error("BMC cert init failed", "err", err)
    // fatal or non-fatal per deployment policy
}
```

`InitBMCCertManagement` short-circuits if `BMCConfig == nil || BMCConfig.Certificate == nil`, so callers can invoke unconditionally. Validation errors surface immediately; an
unreachable BMC at boot surfaces an `ErrInitBMCCertIssue` the
caller can log-and-continue, letting the next tick retry.

## Integration testing

Real-services only -- no mocks in integration tests per the project
rule. `test/integration/bmc/vbmc` ships a containerized responder
that speaks the Redfish + SMC-CGI surface platformd exercises,
running alongside the devcontainer via docker-compose. Two flavors
(`vbmc-supermicro`, `vbmc-dell`) cover both vendor branches of the
AutoCertManager probe.

Test harness at `test/integration/bmc/harness.go` (integration
build tag) provides:
- `ConfigFor(ctx, flavor)` -- pre-populated `*bmc.Config` with a
  SPKI-pin `TLSProvider` derived from capturing the vBMC's self-signed
  cert (capture-then-verify pattern; no `InsecureSkipVerify` in the
  resulting client)
- `WithDNSCert(cfg, cn)` -- fills the dns-01 Identity block
- `WaitForReady(ctx, flavor)` -- barriers on vBMC startup
- `GetStats(ctx, flavor)` -- reads the vBMC's `/debug/stats` for
  before/after counter diffs

See `docs/bmc/testing.md` for runbook.

## File map

| Path | Purpose |
|---|---|
| `pkg/memguard/memory_enclave.go` | `MemoryEnclave` locked-memory primitive (slice 1) |
| `pkg/bmc/user.go`, `ipmi_user.go`, `redfish_user.go` | User CRUD (slices 2-3) |
| `pkg/bmc/cert.go`, `redfish_cert.go` | Cert interface + Redfish backend (slice 3) |
| `pkg/bmc/smc/cgi_cert.go` | Supermicro ATEN CGI backend (slice 4) |
| `pkg/bmc/credentials.go` | `CredentialStore` interface + MemoryStore (slice 5) |
| `pkg/bmc/credentials/quicbaas_store.go` | QuicBaaS-backed credential adapter (slice 5) |
| `pkg/bmc/rotation.go` | Password rotation engine (slice 7) |
| `pkg/bmc/auto_cert.go` | Vendor-dispatch `AutoCertManager` (P3) |
| `pkg/bmc/config.go` | Config + validator (P2) |
| `pkg/app/bmc_cert.go` | `issueBMCCertificateCore` + dns-01 closures (P4) |
| `pkg/app/cert_targets.go` | `CertTargetRegistry` (P4) |
| `pkg/app/cert_renewal_handler.go` | Scheduler handler + job registration (P5) |
| `pkg/app/bmc_cert_init.go` | `InitBMCCertManagement` orchestrator (this slice) |
| `go-quicbaas/pkg/scheduler/{types,scheduler}.go` | `LeaderChecker` + `NodeAffinity` + dispatch gate (P1) |
| `test/integration/bmc/vbmc/` | Integration test vBMC responder (P6) |
| `test/integration/bmc/harness.go` | Integration test helpers (P6) |

## Deferred / follow-up

| # | Item |
|---|---|
| #7 | Consolidate `redfishClient` + `redfishTransport` HTTP plumbing duplication |
| #9 | Hardware-validate SMC CGI on real X10 to unlock `allow_cgi_fallback` in auto mode |
| #20 | Productionize `rmcp_sim_test.go` into the vBMC binary for IPMI integration tests |
| -- | Wire `InitBMCCertManagement` into `App.Init*` boot path |
| -- | Register webservice TLS as a `CertTarget` alongside BMC so the same renewal sweep covers it |
| -- | Wire-protocol `NodeAffinity` field exposure in gRPC/REST/MCP scheduler handlers (only needed if remote clients create node-affine jobs) |
