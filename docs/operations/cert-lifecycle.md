# Certificate Lifecycle -- Operator Runbook

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
| `CertKindBMC` | `bmc:` block in platform YAML | `App.InitBMCCertManagement()` at boot |

Future kinds: Kubernetes ingress, SDN switch mgmt, etc. The
registry is kind-agnostic.

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
simultaneously (see `docs/architecture/quicbaas-integration.md`
Scheduler Clustering).

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
`InitBMCCertManagement` re-issue every managed cert from scratch.
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
   `docs/operations/x10-smc-cgi-validation.md` and flip the gate
   platform-wide.

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
  `platformctl ca status`

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
| DNS-01 challenge | `go-trusted-ca/pkg/acme/challenges/dns-01` (upstream) |
| DNS-01 closures (BMC) | `pkg/app/bmc_cert.go:buildBMCACMERequest` (inline setup/cleanup) |
| Scheduler engine | `go-quicbaas/pkg/scheduler/scheduler.go` |

## Related docs

- `docs/architecture/bmc-tls.md` -- overall architecture
- `docs/architecture/quicbaas-integration.md` -- scheduler clustering semantics
- `docs/bmc/configuration.md` -- BMC YAML schema
- `docs/bmc/operations.md` -- BMC admin tasks
- `docs/operations/x10-smc-cgi-validation.md` -- X10 hardware cert path runbook
