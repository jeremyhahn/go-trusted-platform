# Time Synchronization — Architecture

> **Status: NORMATIVE** · Scope: `pkg/ntp/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## 1. The problem

**Time is a trust primitive on this platform.** Four separate mechanisms are
silently wrong on a node whose clock is wrong, and none of them reports the
clock as the cause:

- **TPM attestation freshness.** A quote is evidence about a moment. A verifier
  that cannot place that moment cannot bound replay.
- **ACME (RFC 8555) issuance.** Order and authorization windows, and the
  `notBefore`/`notAfter` of everything issued.
- **DANE / DNSSEC signature windows.** RRSIG inception and expiration are
  absolute timestamps; a skewed validator rejects good signatures or accepts
  expired ones.
- **JWT `exp` / `nbf`.** A token that expired an hour ago still validates on a
  node running an hour slow.

The observed failure that motivated this feature was a lab node that booted
**two years slow with no time daemon running at all**. Nothing in the platform
noticed. Every downstream trust decision on that node was being made against a
clock that was wrong by a factor no policy anywhere accounted for.

The requirement that follows: a node that cannot prove its clock is disciplined
must **say so**, loudly, in a place fleet monitoring already reads.

## 2. The shape chosen

**The platform does not implement NTP.** chrony runs as a packaged OpenRC
service. `pkg/ntp` does four things around it:

1. **Renders** `chrony.conf` from the `ntp:` configuration section.
2. **Manages** the OpenRC service lifecycle — enable in the default runlevel,
   restart when the rendered configuration changed.
3. **Polls** chronyd's local Unix control socket (through `chronyc -c -n`) for
   tracking and source state.
4. **Publishes** that state to the multi-protocol API and to the `ntp` health
   component.

Two design commitments follow from "we do not implement NTP":

- **The control plane is read-mostly.** The only mutation the platform offers is
  `Step`, an explicit operator recovery action. Everything else is observation.
- **Configuration is explicit.** An absent or disabled `ntp:` section means
  platformd **never touches chrony**. It does not install a default, does not
  render a file, does not restart anything. `Config.Active()` gates the whole
  subsystem, and every service method returns `ErrDisabled` when it is false.

### The startup gate

`App.StartNTP` runs **after network bring-up (`initSDN`) and before TPM/CA
initialization**. That position is the whole point: TPM and CA initialization
make trust decisions, so they must not run against a bogus clock.

When `consume.startup-gate.block-until-synced` is set, bring-up polls chronyd
until the clock converges or the timeout expires. What happens then is policy:

| `on-timeout` | Behaviour |
|---|---|
| `warn-and-continue` (default) | The node boots. The `ntp` health component reports `time-unsynced`, so fleet monitoring surfaces it |
| `fail-startup` | Bring-up aborts with `app.ErrNTPStartupGate` wrapping `ntp.ErrSyncTimeout` |

The default is deliberately not `fail-startup`: a node that refuses to boot
because a time server was unreachable is worse than a node that boots and says
its clock is untrusted. Making the degraded state **visible** is the control;
refusing to boot is an option, not the default.

Visible in three places, and #509 is what happens when only the first exists:

| Surface | What it shows |
|---|---|
| The `ntp` health component | `degraded`, message `time-unsynced`. `platformctl health` names every non-healthy component in its DEFAULT view, not only under `--detailed`, and the console's health page renders `degraded` as degraded rather than collapsing it to down |
| The attestation report | `time_synced` beside each verdict, recorded by the collector at collection time. Three states: true, false, and ABSENT when the device did not answer — an unreadable clock is not a wrong clock |
| The startup log | the gate's warning line, once per boot |

### Alternatives rejected

| Alternative | Why it was rejected |
|---|---|
| **Implement NTP (or SNTP) in Go inside the platform** | Clock discipline is a control-loop problem with decades of accumulated correctness in chrony — slew rates, step thresholds, dispersion accounting, falseticker rejection, leap handling. Reimplementing it would be a large surface with subtle failure modes in the one subsystem whose failures are invisible. |
| **Speak chrony's command protocol natively over the socket** | The protocol is chrony's private interface with no compatibility promise. `chronyc -c` (CSV) is the supported surface, is stable, and is shipped with the daemon. The platform shells out to it rather than reimplementing the wire format. |
| **Trust the RTC and skip NTP entirely** | The motivating failure was exactly this: a node whose RTC was two years wrong and nothing to correct it. |
| **Boot regardless, without a gate** | TPM and CA initialization would run against an unknown clock. The gate exists so that the ordering — network, then time, then trust — is enforced rather than hoped for. |
| **Fail startup by default when the clock does not converge** | A transient upstream outage would take a fleet offline. Warn-and-continue plus a health component that names the condition gives operators the signal without the outage. `fail-startup` remains available for deployments that want it. |
| **Always allow chronyd to step the clock** | A large jump *after* convergence means either a failing oscillator or a hostile time source. The rendered config allows steps for the first three updates only (`makestep 1.0 3`) so a years-wrong RTC converges immediately; a large correction after that is flagged as an **anomaly**, not silently absorbed. |
| **Default `serve.listen-networks` to `0.0.0.0/0`** | An open NTP server is a reflection-amplification source. `ErrUnrestrictedListenNetwork` rejects `0.0.0.0/0` and `::/0` outright, and any prefix of length 0, at configuration validation — not at runtime, and not as a warning. |
| **Leave chrony's UDP command port enabled** | Remote command access to the clock daemon is an attack surface with no platform use. The rendered config sets `cmdport 0` and binds the command socket to a local Unix path. |
| **Let consume-only nodes listen on port 123 anyway** | A client has no reason to be a server. `renderServer` emits `port 0` for a consume-only node so it never listens. |
| **Fall back to unauthenticated time when NTS material is unresolved** | That is a silent security downgrade at exactly the moment the operator asked for authenticated time. `ErrUnresolvedNTSMaterial` is fatal for the service instead. |
| **Cache the last known status and serve it** | An operator asking about the clock needs the clock's current state, not a memory of it. Every `Status` call polls. `LastStatus()` exists for callers that explicitly want the cached value and returns nil before the first poll. |
| **Expose chrony's full command set (`burst`, `add server`, `offline`, …)** | The platform owns the configuration; a runtime mutation the platform does not know about would be silently overwritten at the next `Apply`. Only `Step` is exposed, and only as recovery. |

## 3. Component boundaries

| Piece | Package | Owner |
|---|---|---|
| `ntp:` configuration schema, validation | `pkg/ntp/config.go` | this repo |
| `chrony.conf` rendering, filesystem layout | `pkg/ntp/chronyconf.go` | this repo |
| Service lifecycle, startup gate, RTC write-back, anomaly detection | `pkg/ntp/service.go` | this repo |
| Control-socket client (`chronyc` CSV parsing) | `pkg/ntp/control.go` | this repo |
| Advertised-name / allow-list reconciliation | `pkg/ntp/servename.go`, driven from `pkg/app/ntp.go` and `pkg/app/nts_provision.go` | this repo |
| Domain status and source types | `pkg/ntp/types.go` | this repo |
| Typed errors | `pkg/ntp/errors.go` | this repo |
| Bring-up policy (`StartNTP`, gate timeout handling) | `pkg/app/ntp.go` | this repo |
| `NTPBackend`, proto projection, gRPC→wire error mapping | `pkg/api/daemon/ntp_service.go` | this repo |
| gRPC `platform.v1.NTPService` | `pkg/api/daemon/ntp_grpc_service.go` | this repo |
| QUIC category dispatch | `pkg/api/daemon/quic_ntp.go`, `sdk/go/wire/quicwire/ntp_opcodes.go` | this repo |
| MCP tools | `pkg/api/mcp/ntp_tools.go` | this repo |
| REST routers (two listeners) | `pkg/webservice/v1/rest/ntp/router.go`, `pkg/api/rest/ntp_handlers.go` | this repo |
| CLI | `pkg/cli/commands/ntp/` | this repo |
| SDK client and QUIC wire mapping | `sdk/go/services/ntp/`, `sdk/go/transport/quic/aab_ntp.go` | this repo |
| **The NTP protocol, clock discipline, NTS-KE** | **chrony**, a packaged OpenRC service | **not this repo, not this stack** |
| **The `ntp` health component** | `pkg/api/daemon/ntp_health_checker.go`, registered into `pkg/health` | this repo — see [`docs/health/`](../health/) |
| The node clock state served to the attestation collector (`GET /api/v1/attestation/clock`) | `pkg/webservice/v1/rest/attestation/clock_router.go`, adapter in `pkg/daemon/commands/attestation_clock.go` | the attestation feature — see [`docs/attestation/api.md`](../attestation/api.md) §2. It is a READ-ONLY projection of `Status`; the privileged clock verbs stay on this feature's operator-gated routes |
| **NTS certificate and key issuance** | first boot: `App.ProvisionNTSKeys` (pkg/app) generates a self-signed NTS-KE server certificate + key into the KMS before the fail-closed secret walk, because the `kms://` references are keypair material nothing else creates (#55); it also snapshots the `kms://` object paths before the secrets engine resolves the config in place, and the `nts-server` renewal target registers from that snapshot. The target's authority is the certificate chronyd actually serves on the NTS-KE port (loopback inspection dial): a self-signed served certificate is due immediately (upgraded to platform-CA-issued on the first sweep), an unreadable endpoint is due for redeploy, and expiry renews thereafter. Reissue writes the new pair to the KMS key-first, then deploys through `Service.RotateNTSMaterial` — a serialized, service-locked rotation that BORROWS the material for exactly one deployment (the shared config is never mutated at runtime, and no plaintext copy of the renewed key outlives the call — the service keeps only SHA-256 digests to verify the published store on later applies, never regressing it), publishes the pair atomically through the versioned material store (`nts.d/<version>` + `current` symlink swap), and restarts chronyd — deployment failure is renewal failure, so the sweep converges | **provisioning: pkg/app; consumption: this feature** |

**One backend instance serves every transport.** `NTPBackend` is held by the
daemon and shared by the gRPC service, both REST routers, the QUIC category
handler, the MCP tools, and the Unix-socket gRPC server. `*ntp.Service`
satisfies it (`var _ NTPBackend = (*ntp.Service)(nil)`). This is why every
protocol reports the same clock and maps errors identically — there is no second
implementation to drift.

## 4. Data flow

### Bring-up

```
initSDN (network up)
    │
    ▼
App.StartNTP
    │  Config.Active() == false ──▶ return nil, chrony untouched
    │
    ├─ ntp.NewService(cfg)          ── Validate() fails ──▶ FATAL: refuse to start
    ├─ Service.Apply(ctx)
    │     ├─ writeNTSMaterial   (NTS serving only; unresolved kms:// URI ⇒ hard error)
    │     ├─ Render(cfg, paths) ⇒ chrony.conf text
    │     ├─ writeConfigFile    ⇒ changed? (byte comparison against the existing file)
    │     ├─ rc-update add chronyd default
    │     └─ unchanged && running ⇒ no-op;  otherwise rc-service chronyd restart
    │        (Apply failure is logged and bring-up continues)
    │
    └─ Service.WaitForSync(ctx)   ── gate disabled ⇒ returns immediately
          ├─ poll Status every DefaultPollInterval (2 s) until GateTimeout (120 s)
          ├─ synced ⇒ log, optional hwclock --systohc --utc, return
          └─ timeout ⇒ ErrSyncTimeout ⇒ warn-and-continue | ErrNTPStartupGate
    │
    ▼
TPM / CA initialization  (now running against a clock the platform vouched for)
```

`Apply` is **idempotent**: an unchanged configuration on a running daemon is a
no-op, so a platformd restart never disturbs a converged clock.

### A status query

```
any transport ──▶ NTPGRPCService.GetStatus ──▶ NTPBackend.Status(ctx)
                                                    │
                                                    ├─ chronyc -c -n -h <socket> tracking  ⇒ Tracking
                                                    ├─ chronyc -c -n -h <socket> sources   ⇒ []Source  (best effort)
                                                    ├─ detectAnomaly(tracking)
                                                    └─ store in lastStatus, return *Status
```

Source enumeration is **informational**: a control socket that answers
`tracking` but not `sources` still yields a usable status with zero counts and a
debug log line. A failure there does not fail the status call.

### What is persisted, and where

| Artefact | Path (default, overridable in tests only) | Written by |
|---|---|---|
| `chrony.conf` | `/etc/chrony/chrony.conf`, mode `0644` | `Service.Apply` |
| Drift file | `/var/lib/chrony/chrony.drift` | chronyd |
| NTS server certificate | `/etc/chrony/nts.d/current/nts-server.crt`, mode `0644` | `Service.deployNTSMaterial` |
| NTS server key | `/etc/chrony/nts.d/current/nts-server.key`, mode `0600` | `Service.deployNTSMaterial` |
| NTS-KE key cache | `/var/lib/chrony/` | chronyd |
| Control socket | `/run/chrony/chronyd.sock` | chronyd |
| Hardware clock | the RTC | `hwclock --systohc --utc`, only when `rtc.write-back` |

`Paths` are **not part of the YAML schema** — they are platform layout constants
overridable only through the `WithPaths` test option.

The rendered `chrony.conf` carries a `ManagedHeader` marking it platform-owned.
Hand edits are overwritten on the next `Apply`.

### What crosses a boundary

- **Process boundary, every time**: `chronyc` is executed through
  `CommandRunner`; `rc-update`, `rc-service` and `hwclock` likewise. Every host
  interaction in the package goes through that one interface, which is what
  keeps unit tests off the real clock.
- **Host boundary, continuously**: chronyd polls upstream sources over NTP/NTS.
  The platform never speaks NTP itself.
- **Host boundary, on a serving node**: chronyd answers NTP on port 123 for the
  CIDRs in `serve.listen-networks`, and NTS-KE when configured.

## 5. Trust boundaries

**This is the section that explains why an NTP feature is a security feature.**

1. **Upstream time source → this node.** An attacker who controls the time a
   node accepts controls certificate validity windows, attestation freshness,
   DANE signature windows and token expiry on that node. Three controls apply:
   - **NTS (RFC 8915)** authenticates the source. Internal control-plane
     sources set `nts: true`. Most public upstreams and nearly every router
     cannot do NTS, so it is best-effort there — which is precisely why a node
     that consumes only public time is trusting the network.

     **An NTS client is a TLS client, so the upstream is NAMED, not
     addressed.** chronyd verifies the NTS-KE certificate against the name in
     its own `server` directive, and platform certificates carry DNS SANs
     only. An IP address in `consume.upstream[].address` with `nts: true`
     therefore fails the handshake forever: the node never synchronises and
     spends the whole startup gate at every boot, while the configuration
     reads as if authenticated time were in force. #509 is that state,
     measured on the fleet. The two halves of the fix are configuration:
     the consuming node names the control plane
     (`cp.<internal-domain>`, resolved through the platform DNS the same way
     the ACME directory URL already is), and the serving node lists that name
     in `serve.nts.server-names` so its certificate is issued with it.

     **A valid certificate is necessary and not sufficient.** `serve` decides
     who it answers by SOURCE ADDRESS (`serve.listen-networks`), and nothing
     in the protocol ties that to the name it was issued for. A control plane
     can therefore hold a correct certificate for `cp.<domain>`, complete the
     handshake, and then refuse the client's NTP packets because the name
     resolves onto a segment no `allow` directive covers — a configuration
     that looks right from every angle except the clock. That is the measured
     fleet state: the internal zone published `cp` at the MANAGEMENT address
     while chrony.conf allowed only the trusted and provisioning `/24`s.
     `Service.CheckServeNames` closes it (§"Advertised names versus the allow
     list" below).
   - **Step limiting.** `makestep 1.0 3` confines steps to the first three
     updates. Afterwards chronyd slews, and a large correction is treated as
     evidence, not as a correction.
   - **Anomaly detection.** `Service.detectAnomaly` flags any post-convergence
     correction larger than `LargeStepThreshold` (1 s), latches it, and drives
     the `ntp` health component to degraded with an operator-readable reason.
     On a trusted platform that condition means a failing oscillator **or a
     hostile time source**, and the platform will not decide which.

2. **This node → its NTP clients.** A serving node is authoritative time for the
   CIDRs it allows, so the allow-list is a trust boundary in the outbound
   direction. `serve.listen-networks` is mandatory for a serving node
   (`ErrNoListenNetworks`), must be explicit CIDRs, and cannot be
   `0.0.0.0/0`, `::/0`, or any zero-length prefix
   (`ErrUnrestrictedListenNetwork`). Consume-only nodes render `port 0` and
   never listen.

3. **NTS key material and the served identity.** The NTS-KE server key is platform-CA-issued and
   referenced as a `kms://` URI resolved by the secrets engine before chronyd
   starts. If a value still looks like a secret reference (`kms://`,
   `secret://`, `file://`) when chronyd needs it on disk,
   `ErrUnresolvedNTSMaterial` **fails the NTP service** rather than serving
   unauthenticated time. The key is written mode `0600`; the certificate `0644`.
   Both files are staged as a fresh temp file in the destination directory
   and renamed into place, rather than written to the path directly:
   `os.WriteFile` applies its permission argument only when it CREATES the
   file and follows a symlink sitting at the path, so a stale or planted
   entry could otherwise make the key inherit a wider mode or land
   somewhere an attacker chose. Staging makes both impossible — the chmod
   precedes the write, and the rename replaces the name rather than
   following it — and makes each write atomic.
   A renewal's private key travels from generation to disk inside a
   `memguard.MemoryEnclave` and is materialized only for the write itself;
   what remains unprotected, and why, is registered in
   [protected-memory.md](../security/protected-memory.md).

   The renewal sweep's NTS-KE inspection dial (`ntsServedCertificate`) is
   the one `InsecureSkipVerify` in this feature and is on the Makefile's
   `check-insecure-tls` allowlist. It is the same **capture-only** pattern
   the platform already permits for `captureAndConfirmSPKI` and
   `fetchControlPlaneCABundle`: it connects to loopback on `ntp.serve.nts.port`
   (default `4460`, the same port rendered into chrony.conf as `ntsport`), exchanges
   **no application data**, and exists solely to read the leaf chronyd is
   serving. Verification cannot run at handshake time precisely because
   the served certificate may still legitimately be the self-signed
   bootstrap one — detecting that is the sweep's whole job. The real trust
   decision happens immediately afterwards in `ntsServedCertInvalid`,
   which verifies the captured certificate against the platform CA roots
   (server-auth EKU, NTS hostname) and marks anything else due for
   reissue.

   **Every name a client dials is verified, not just one.** The served
   certificate must be valid for this node's FQDN AND for every
   `serve.nts.server-names` entry. A certificate satisfying only some of
   them is one some client rejects, and would otherwise sit "healthy" until
   expiry while the nodes that dial the missing name never synchronise. The
   bare hostname is issued into the SANs but is deliberately NOT verified:
   nothing dials it, and requiring it would put the target permanently due
   against a CA that normalises SANs.

4. **chronyd's control surface.** The rendered configuration disables the UDP
   command port (`cmdport 0`) and binds the command socket to a local Unix path.
   Local socket access is therefore equivalent to control of the node's clock —
   which makes filesystem permissions on `/run/chrony/` part of this boundary.

5. **`chrony.conf` injection.** chrony's configuration is line-oriented and
   whitespace-delimited, so an upstream address containing whitespace or `#`
   could inject additional directives. `validateConsume` rejects any address
   containing ` `, `\t`, `\r`, `\n` or `#` (`ErrInvalidUpstreamAddress`).
   Configuration is operator-supplied, but it may arrive through a template or
   a provisioning path, so this is validated rather than trusted.

6. **`Step` is a privileged mutation.** It moves the system clock, and every
   validity decision on the node moves with it. It requires `ntp:write` on every
   transport, and refuses when no source is reachable (`ErrNoReachableSource`)
   rather than stepping toward stale data.

7. **The health surface is public.** `ntp` component details — stratum, offset,
   reachable source counts, anomaly reason, and any serve-name finding — reach
   unauthenticated health probes. That is intentional and none of it is
   secret: a serve-name finding names a DNS name, an address and the allow
   list, all of which the node already publishes by answering (or refusing) on
   them. See [`docs/health/architecture.md`](../health/architecture.md) §5.

### Advertised names versus the allow list

A serving node makes two independent statements that nothing in chrony or in
RFC 8915 reconciles:

| Statement | Configuration | Enforced against |
|---|---|---|
| "I am `cp.example.internal`" | `serve.nts.server-names` → the certificate SANs | the name the client wrote |
| "I answer 10.4.6.0/24 and 192.0.2.0/24" | `serve.listen-networks` → `allow` directives | the packet's source address |

When the name resolves outside the allow list, the handshake succeeds and the
time is refused. The failure is worse than a handshake failure precisely
because it is quieter: the certificate is valid, the source shows as
unreachable, and nothing names the cause.

`Service.CheckServeNames` reconciles the two. It runs where the served
identity is established or replaced — `App.StartNTP` immediately after
`Apply` (the allow list has just been rendered) and
`App.reissueNTSCertificate` after a successful deploy — resolves each
advertised name, and latches the ones clients cannot usefully dial. `Status`
carries the latched findings and the `ntp` health component reports them as
degraded under the finding's own marker, naming the name and either the
address and allow list or the resolver's error.

A name can fail in two ways, and they are reported as two kinds because they
are two different claims with two different fixes:

| Kind | Means | Fix |
|---|---|---|
| `nts-name-unreachable` | the name resolved, and this node's allow list refuses the address | reconcile the allow list and the zone |
| `nts-name-unresolvable` | the name did not resolve on this node at all, with the resolver's own error | publish the record, or repair the resolver |

Both are findings because both leave clients unable to dial the name: nodes
forward the internal zone through the control plane, so a name the control
plane cannot resolve is one no node can reach either — the same silent
failure in a different coat.

Three rules keep the check honest:

- **It resolves at provisioning and renewal, never on a status poll.** A DNS
  lookup per health probe would put the resolver in the health path for an
  answer that only changes when the configuration or the zone does.
- **An unresolvable name is never reported as a refused one.** It has no
  address, so the allow-list claim would have nothing behind it. That is the
  same absence-of-evidence discipline the collector applies to `time_synced`,
  and it is why the kinds exist rather than one flat marker.
- **It does not choose a side.** Widening the allow list and republishing the
  name on an already-allowed segment are both valid, and which is right
  depends on fleet addressing the platform does not own. It reports the
  mismatch and names both halves.

It also does not make the CLOCK unhealthy: `Status.Healthy()` is untouched by
a finding, because the node's own time may be perfectly disciplined. It is a
serving-side misconfiguration and reads as its own degraded reason.

## 6. What this feature deliberately does not do

- **It does not implement NTP, SNTP, PTP or NTS.** chrony does. This is a
  configuration, lifecycle and observation layer.
- **It does not manage the hardware clock beyond one call.** `rtc.write-back`
  runs `hwclock --systohc --utc` once, after the gate confirms sync. There is
  no RTC drift correction, no periodic write-back. A failure there is logged,
  not fatal — the system clock is already right.
- **It does not issue the NTS certificate.** First boot self-sign-provisions
  it (`App.ProvisionNTSKeys`, pkg/app — see the ownership table above) and
  renewal replaces it with CA-issued material; the secrets engine resolves
  the reference; this feature writes the resolved material to disk and
  restarts chronyd when it changes (`Service.Apply` — the renewal deploy
  path).
- **It does not touch chrony when the section is absent or disabled.** No
  default configuration is installed, nothing is restarted, and every service
  method returns `ErrDisabled`.
- **It does not expose chrony's runtime command set.** Only `Step`.
- **It does not decide whether an anomaly is hardware or attack.** It reports
  the correction and its magnitude and marks the node degraded.
- **It does not gate other subsystems at runtime.** The startup gate applies to
  bring-up only. Once the node is up, an unsynchronised clock is a *health*
  signal — it does not stop ACME issuance or attestation. Deciding whether it
  should is an owner question, not something this feature has settled.
- **It does not run outside OpenRC.** `rc-update` and `rc-service` are the
  service manager; there is no systemd path.
