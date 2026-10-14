# Certificate Lifecycle -- Operator Runbook

> **Status: REFERENCE** · Last verified: 2026-10-13
> How platformd issues, registers and renews its managed TLS certificates (`pkg/app` cert targets and the renewal job).

How the platform issues, deploys, and renews TLS certificates for
its managed identities (webservices + BMCs), and how operators
intervene when the automatic flow needs a nudge.

## TL;DR

1. Platform config declares cert-managed identities (webservice
   `Certificate:` blocks; BMC `certificate:` block).
2. At platformd boot, each identity is issued an initial cert via
   the embedded ACME client (dns-01 for BMC; any challenge type
   for webservice) and deployed to its endpoint.
3. Each managed cert is registered as a `CertTarget` in
   `app.CertTargets`.
4. A single scheduler job `platform.cert-renewal.<nodeID>` fires
   daily at 02:00 (configurable), sweeps the registry, and
   re-issues anything within 30 days of expiry (configurable).
5. The job is pinned to its owning node via `NodeAffinity` so
   a 3-node cluster renews each node's own certs independently.

## Identities managed today

| Kind | Where configured | Issuance trigger |
|---|---|---|
| `CertKindWebservice` | `WebServices` list in platform YAML | `App.InitWebServer()` at boot |
| `CertKindBMC` | `bmc:` block in platform YAML | `initBMCCertManagement`, called from `App.InitCertManagement()` at boot |
| `CertKindNTS` | `ntp.serve.nts` in platform YAML | `App.RegisterNTSCertTarget()` at boot (`pkg/daemon/commands/cert_renewal_wiring.go`) |
| `CertKindDaemon` | Always, when a TLS transport is enabled (target `daemon.platformd`) | `applyDaemonTLSIdentity` via `App.RegisterCertTarget()` at boot (`pkg/daemon/commands/serve.go`); see [`../daemon/architecture.md`](../daemon/architecture.md) §Daemon TLS identity renewal while running |

A new kind is added to `validCertKinds` in `pkg/app/cert_targets.go`;
the sweep itself treats every kind the same.

## The renewal job

Created once per node by `RegisterCertRenewal` during
`App.InitCertManagement`:

```
Name:         platform.cert-renewal.<nodeID>
Handler:      platform.cert-renewal
JobType:      Recurring
Schedule:     "0 2 * * *"       (02:00 daily, configurable)
NodeAffinity: <nodeID>          (P1 scheduler gate)
OwnerType:    System
Timeout:      30m
MaxRetries:   3
```

**`NodeAffinity` is mandatory** for correctness. Without it, in a
3-node cluster the scheduler would fire the job on all three nodes
simultaneously (see `docs/architecture/bmc-tls.md`
Cluster scheduling).

## Boot wiring

`App.InitCertManagement` is called from **both** platformd boot paths in
`pkg/daemon/commands/serve.go` — `runWithWebservices` and `runDaemonOnly`. A node
with a `bmc:` block but no `webservices` takes the daemon-only path, and its BMC
certificate still needs renewing.

Both call sites sit **after** `App.ServiceRegistry()`, and that ordering is
load-bearing in two directions:

- after `InitWebServer` / `LoadCA`, so webservice targets are already registered
  and there is a CA to reissue with;
- after `App.ServiceRegistry()`, which is what lazily materializes the DAO factory
  — and therefore the scheduler engine — and assigns `App.DNSService`. BMC cert
  init passes `App.DNSService` as its dns-01 updater, so scheduling any earlier
  either finds no scheduler and skips renewal outright, or hands BMC ACME
  issuance a nil DNS updater. Both failures are silent.

`pkg/arch/cert_renewal_wiring_test.go` fails the build if either call site moves
ahead of the registry.

Webservice targets register themselves in `initWebServiceKeyAttributes` on the
`certLoaded` tail, which every path reaches — including the `goto certLoaded`
jumps taken on an ordinary restart, when the CA already holds the certificate.
Registration must stay on that tail: if it moves back under the issuance branch,
restarted nodes register nothing and the sweep silently renews nothing.

Scheduling failure is **warn-and-continue**, not fatal: a node that cannot
schedule renewal is degraded, not broken, and refusing to boot would take a
serving node down over a future problem. The failure is otherwise invisible, so
the warnings name the consequence outright. Grep the boot log for these:

```
certificate renewal NOT scheduled: ...    # no sweep at all on this node
cert renewal: cannot ... cert target ...  # one identity excluded from the sweep
```

Either line means certificates will run to expiry with nothing renewing them.
The healthy boot line is `certificate renewal scheduled`.

## What the sweep verifies against

A webservice target's `Current` dials loopback but sets `ServerName` to the
service's configured DNS identity — certificates are issued for that name, never
for `127.0.0.1`, so an unset `ServerName` fails hostname verification before
`NotAfter` is read and the target is recorded failed forever.

The verification roots follow the **issuance mode**. A webservice that opts in to
a public ACME directory serves a certificate signed by that public CA, so the
sweep verifies it against the system pool (with the platform root still included,
for a service that has not completed its first ACME order yet). Locally-issued
webservices verify against the platform pool. One predicate,
`webServiceUsesPublicACME`, decides both issuance and verification so the two
cannot drift apart.

## When a target is due

Expiry is the default trigger: a certificate within `Threshold` of `NotAfter` is
reissued. It is not the only one.

`CertTarget.DueOverride` lets a target report itself due for reasons expiry
cannot express, and it is consulted on **both** outcomes of `Current`:

| `Current` returns | Sweep behaviour |
|---|---|
| a certificate, not near expiry | `DueOverride(cert, nil)` decides; BMC targets say "due" when the certificate does not chain to the configured issuer or does not match the configured identity |
| a certificate, near expiry | reissued on expiry; no override consulted |
| an error, or no certificate | `DueOverride(nil, err)` decides; BMC targets say "due", because an endpoint serving nothing readable is the one that most needs issuing |
| an error, no `DueOverride` | recorded `failed` — webservice targets take this path, since an unreachable service is not fixed by reissuing its certificate |

The last two rows are what let a BMC **converge**. Boot-time provisioning is
non-fatal, so something has to recover a device that was unreachable or whose
deploy failed at startup. Without the override on the error path, the sweep would
re-read and re-fail that target every day for the life of the process.

Renewals not explained by expiry carry a `due_reason` in the job's result
payload, so the audit trail never shows a rotation with no stated cause.

## Renewal vs rotation: putting the new certificate into service

Issuing a replacement into the CA is **not** enough. `ca.ServerTLSConfig` returns
`Certificates: []tls.Certificate{...}` — a static snapshot taken when the
listener starts — so a certificate replaced in the CA is not the certificate
clients receive.

`issueWebServiceCertificate` therefore calls `App.installWebServiceCert`, which
invokes the installer the running server registered at startup
(`WebServerV1.ReloadCertificate` via `App.RegisterWebServiceCertInstaller`). That
rebuilds the certificate from the CA and hands it to the listener's
`CertReloader`, so it is served on the next handshake with no restart and no
dropped connections.

Without that step renewal degrades into a **daily re-issue loop**: the sweep
issues a certificate, the endpoint keeps serving the previous one, so the next
sweep reads the same near-expiry certificate and issues again — every day, until
the served certificate expires and TLS breaks. Both ends of the seam are guarded
by `pkg/arch/cert_renewal_wiring_test.go`.

The two issuance paths treat installation failure differently, and the split is
the whole point:

| Path | Policy | Why |
|---|---|---|
| Boot (`InitWebServer`) | `installOptional` | The listener does not exist yet, so there is no installer to call and none is expected. Failing here would stop a node booting over a listener that has not started. |
| Renewal (`Reissue`) | `installRequired` | The sweep records the target's outcome from this return value. Reporting success while the endpoint still serves the expiring certificate is a renewal that did not happen, logged as one that did. |

Under `installRequired` a missing or failing installer returns
`ErrCertInstallerMissing` / `ErrCertInstallFailed`, so the target is recorded
`failed` and retried on the next sweep rather than marked renewed.

The reload rebuilds through the **same** `buildTLSConfig` the listener started
with, so a service configured with `certificate.acme.cross_sign` keeps its
cross-signed chain. Building the replacement separately would swap it for an
ordinary chain on the first rotation and break every client relying on that trust
path — silently, and only after the first renewal.

BMC targets do not need this. Their `Reissue` deploys to the device itself
(`ReplaceWebCertificate`), so issuance and installation are the same step.

## Sweep robustness

One target cannot take down the rest, and the sweep is honest about why it
stopped. Both properties matter because this runs unattended, once a day.

- **A panicking target is isolated.** `Current` and `Reissue` call out to
  deployers, ACME clients and BMC transports; a panic in any of them is recovered
  per target, recorded as `failed` with the panic text, and the remaining targets
  are still swept. It is recorded rather than swallowed so it stays visible in the
  job history.
- **Cancellation stops the sweep without slandering the targets — and without
  claiming success.** The job carries a timeout and the daemon can shut down
  mid-sweep. Remaining targets are left unevaluated rather than recorded
  `failed`, so a cancellation cannot read as a fleet-wide certificate outage.
  But the sweep also returns `ErrCertRenewalSweepIncomplete`, and the handler
  fails the job with it, because those certificates were never checked. Both
  halves matter: recording them `failed` invents an outage, while returning
  silently reports a clean tick over work that never ran — and the scheduler
  would not retry it.
- Targets are read from a registry `Snapshot`, so registration during a sweep
  cannot race it, and results are sorted by name for a stable audit trail.

## Tuning knobs

| Knob | Default | Where |
|---|---|---|
| Cron schedule | `0 2 * * *` | `DefaultCertRenewalSchedule` or `CertRenewalRegistration.Schedule` |
| Renewal threshold | 30 days | `DefaultCertRenewalThreshold` or `CertRenewalRegistration.Threshold` |
| Job timeout | 30m | `DefaultCertRenewalTimeout` or `CertRenewalRegistration.Timeout` |
| Max retries | 3 | `CertRenewalRegistration.MaxRetries` |

Override at boot via the `CertRenewalRegistration` passed to
`RegisterCertRenewal`. Platform config hooks for these are
follow-up wiring.

⚠️ **The stored job is preserved, not reconciled.** The renewal *threshold* lives
in the handler closure, which is rebuilt every boot, so changing it takes effect
on restart. The **schedule, timeout and max-retries** are baked into the
scheduler job when it is first created, and a later boot leaves that job alone —
so editing them and restarting has no effect. Boot now logs a WARN naming both
the stored and the configured value when they differ; until then this was
entirely silent.

Updating the stored job in place needs the scheduler's `UpdateJob`, whose
`JobUpdateParams` type is not re-exported through `go-quicbaas/sdk/go`, and the
platform may only import `sdk/go`. Filed upstream. The operator workaround is to
delete the job so it is recreated from current configuration.

## Operator workflows

### Trigger an immediate renewal (no wait for the cron tick)

The scheduler CLI commands (`platformctl schedule list`,
`platformctl schedule trigger`, `platformctl schedule history`)
are planned but not yet implemented. Monitor renewal outcomes
via the platformd logs until the scheduler CLI is available.

The handler's JSON payload (in `JobResult.Output`) lists per-target
outcomes:

```json
[
  {"name":"webservice.admin",     "kind":"webservice", "action":"skipped",  "days_left":72.4},
  {"name":"bmc.bmc-node-17.int",  "kind":"bmc",        "action":"renewed",  "days_left":12.1},
  {"name":"webservice.tenant-7",  "kind":"webservice", "action":"failed",   "error":"reissue: ACME rate limit"}
]
```

### Pause renewals on a specific node (maintenance)

Not yet exposed via CLI. Each node's renewal job is identified by
its nodeID in the scheduler. Pausing and resuming will be available
once the scheduler CLI is implemented.

### Force a specific cert to renew (bypass threshold)

No direct CLI yet -- workaround: set the threshold temporarily on a
one-shot run. Or: trigger the job after artificially aging the cert
in the registry (future: `platformctl cert target renew <name>`).

For BMC certs specifically:

```bash
# Explicit platformctl bmc cert replace bypasses the registry /
# scheduler and just runs the issuance flow once.
platformctl bmc cert replace \
    --profile-id <id> \
    --cert <path> --key <path>
```

### Rotate all certs on a node

Kill the platformd process -- on next boot `InitWebServer` +
`InitCertManagement` re-issue every managed cert from scratch.
Existing certs with time remaining aren't touched, but any near-
expiry certs will be renewed.

Not a routine procedure. Prefer triggering the renewal job once
the scheduler CLI is available.

## Troubleshooting

### `ErrAutoCertCGIGated` on Supermicro BMC

The platform detected a Supermicro BMC and `auto` mode resolved to
the SMC-CGI backend, but `allow_cgi_fallback` is disabled (default).

Fix: either

1. Pin the backend explicitly via `bmc.backend: redfish` (works on
   X11+ where Redfish CertificateService is reliable), or
2. Pin to `bmc.backend: smc-cgi` (opt into the CGI path for this
   BMC; bypasses the gate), or
3. Run the X10 hardware validation procedure at
   `docs/operations/x10-smc-cgi-validation.md` and set
   `bmc.allow_cgi_fallback: true` for the validated BMC.

### `ErrRotationReverted` / `ErrRotationCatastrophic` in logs

Password rotation (different codepath from cert rotation; see
`pkg/bmc/rotation.go`) failed. `Reverted` = rollback succeeded,
store reflects prior password. `Catastrophic` = rollback failed,
store reflects attempted new password, BMC state ambiguous.
Operator intervention required for catastrophic case.

### `cert-renewal sweep: N failed` in job history

Inspect the JSON payload for per-target errors. Common causes:

- ACME rate limit hit -- wait, then trigger manually
- BMC unreachable -- network issue; next tick will retry
- Local CA unavailable -- platform CA service not ready; check
  `platformctl ca info`

### Renewal job exists but never fires

- Check `allow_cgi_fallback` if BMCs are involved
- Check that `NodeAffinity` matches the node's current ID
  (hostname change after boot would leave an orphaned job)
- Verify the node is reachable by the scheduler (not a leader gap
  -- node-affine jobs bypass the leader check)

### Job fires but all targets report "skipped: not due"

Working as intended -- all managed certs have more than
`Threshold` time left.

## Under the hood

Code paths:

| Step | File |
|---|---|
| Initial issuance (webservice) | `pkg/app/app.go:issueWebServiceCertificate` |
| Initial issuance (BMC) | `pkg/app/bmc_cert.go:issueBMCCertificateCore` |
| Target registration | `pkg/app/cert_targets.go:CertTargetRegistry.Replace` |
| Scheduler handler | `pkg/app/cert_renewal_handler.go:buildCertRenewalHandler` |
| Per-target evaluation | `pkg/app/cert_renewal_handler.go:evaluateAndReissue` |
| BMC deploy | `pkg/bmc/auto_cert.go:AutoCertManager.ReplaceWebCertificate` |
| DNS-01 challenge | go-xkms ACME (pkg/acme, via go-quicbaas SDK) |
| DNS-01 closures (BMC) | `pkg/app/bmc_cert.go:buildBMCACMERequest` (inline setup/cleanup) |
| Scheduler engine | `go-quicbaas/pkg/scheduler/scheduler.go` |

## Related docs

- `docs/architecture/bmc-tls.md` -- overall architecture
- `docs/architecture/bmc-tls.md` Cluster scheduling -- scheduler clustering semantics
- `docs/bmc/engineering.md` §3 -- BMC YAML schema
- `docs/bmc/user.md` -- BMC admin tasks
- `docs/operations/x10-smc-cgi-validation.md` -- X10 hardware cert path runbook
