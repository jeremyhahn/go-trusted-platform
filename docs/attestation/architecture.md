# Attestation Architecture

> **Status: NORMATIVE** · Scope: `pkg/attestation/`, `pkg/ima/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: architecture (this file) · [engineering.md](engineering.md) ·
> [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> **Verification scope.** The package boundaries, configuration keys, error
> names and transport tables were re-checked against code on 2026-08-18. The
> narrative and diagram sections below predate the feature-folder migration and
> were carried over rather than re-derived; treat them as orientation.

## The problem

Every other control on the platform reduces to "is this machine what we think it
is". Certificates prove key possession, tokens prove a prior authentication, and
both survive the machine being compromised. Attestation is the only control that
asks the hardware what the software actually is, at the moment of asking.

## The shape chosen

A **three-level chain**, verified in order:

1. **Host** — measured boot captured in a host manifest, rooted in the physical
   TPM.
2. **VM** — attested against its own virtual TPM, bound to an attested host.
3. **Container** — measured into a platform PCR at start, bound to an attested
   host.

Each level is only meaningful because the level below it verified. The binding
is enforced in code (`ErrHostNotAttested`, `ErrHostBindingInvalid`), not by
convention.

Two independent measurement sources feed it: the **TPM event log** (firmware and
bootloader, early PCRs) and **Linux IMA** (files the kernel opened, PCR 10),
plus the platform's own **workload chain** (default PCR 14), which is a Merkle
structure so tampering with the log is detectable rather than merely
implausible.

### Alternatives rejected

| Alternative | Why it was rejected |
|---|---|
| **Agent self-report — the host tells the control plane what it is running** | A compromised host lies. The whole premise is that the report must come from hardware the host cannot forge. |
| **A single flat measurement per host, no VM/container levels** | Nodes host multi-tenant workloads. Without per-workload measurement, one tenant's container changing invalidates the host's attestation for everyone, and no workload can be attested independently. |
| **Reusing the IMA PCR (10) for platform workload measurements** | PCR 10 belongs to the kernel; the platform extending it would interleave with kernel measurements and make both logs unverifiable. A separate, configurable workload PCR (default 14) keeps the two logs independent. |
| **Overwriting a workload measurement when a workload restarts** | PCRs cannot be overwritten, and a log that could be would not be evidence. The chain is append-only with a Merkle root. |
| **`allow` as the default policy action** | A policy engine that admits anything it has no rule for is not a policy engine. The default is `deny` (`DefaultPolicyAction = DefaultActionDeny`) and inverting it is not a tuning knob. |
| **Verifying quotes without a freshness bound** | A signature-valid quote replayed later proves only what the machine looked like once. Nonce plus `ErrQuoteExpired` bound both replay and staleness. |

## Component boundaries

| Piece | Package | Owner |
|---|---|---|
| Manifest build / sign / verify | `pkg/attestation/manifest` | this repo |
| VM attestation | `pkg/attestation/vm` | this repo |
| Workload chain and lifecycle | `pkg/attestation/workload` | this repo |
| Scheduled push to remote verifiers | `pkg/attestation/push` | this repo |
| Manifest persistence | `pkg/attestation/store` | this repo |
| Service façade and events | `pkg/attestation/service` | this repo |
| IMA log reading and PCR 10 verification | `pkg/ima` | this repo |
| Virtual TPM provisioning | `pkg/vtpm`, `pkg/swtpm` — [`docs/vtpm/`](../vtpm/) | this repo |
| Physical TPM operations, key hierarchy | `pkg/api`/TPM surface — [`docs/tpm/`](../tpm/) | this repo |
| **Certificates and CA** | consumed through the quicbaas SDK | **not this repo** |
| **Key management** | consumed through the quicbaas SDK | **not this repo** |
| **Policy evaluation engine (OPA)** | `pkg/policy/opa/` | this repo — workload admission and attestation-evidence policy is legitimately ours; *token* authorization is not |

The capability row is *"TPM attestation of nodes and workloads (host manifests,
VM, container, push/verify)"*, Tier 1, reached through `services/attestation`,
`services/tpm` and `services/vtpm` in the platform SDK.

## Data flow — a container attestation

1. A verifier (or the CLI) issues a **nonce**.
2. The workload chain produces the container's **measurement**, extended into
   the configured workload PCR at container start by a `LifecycleHook`.
3. The TPM produces a **quote** over the requested PCR set, covering the nonce.
4. The verifier checks, in order: signature against the attestation key, nonce
   equality, quote age against its expiry, then **every** PCR named by policy.
5. The policy engine evaluates the evidence; the default action on no match is
   **deny**.
6. The result is recorded and observable through `AttestationObserver` and
   `GET /api/v1/attestation/events`.

Any failure in step 4 or 5 denies. There is no partial result.

## Trust boundaries

1. **Attesting node → verifier.** Crossed by the quote and manifest. Everything
   on the node side is untrusted until the quote verifies.
2. **Platform → TPM.** The TPM is the root of trust. A software TPM
   (`SoftwareTPM`) satisfies the same interface for tests and **is not a trust
   root** — a deployment running against it has no attestation guarantee.
3. **Manifest store.** Stored manifests are evidence. Their integrity is what
   `ErrMerkleRootMismatch` protects.
4. **Push targets.** Manifests pushed to remote verifiers leave the node.
   `attestation.allowed-verifiers` is the allowlist; an empty list is not a
   safe default in a hostile network.

## What this feature deliberately does not do

- **It does not issue certificates or manage keys.** Those come from the stack
  through the quicbaas SDK and are never reimplemented here.
- **It does not decide token authorization.** The platform is a broker-token
  validator, not a token-authorization decision point. The OPA engine here
  decides *workload admission* and *attestation evidence*, which is a different
  question.
- **It does not measure what the kernel already measures.** IMA owns PCR 10;
  the platform reads and verifies that log rather than duplicating it.
- **Its CLI is `container attest` plus the reporting verbs**
  (`platformctl attestation reports|callers`, #429). Manifests, quotes and
  policies still have no verb; that is a gap, recorded in [cli.md](cli.md)
  §1, not a decision.

## The attestation reporting service (design of record, owner-ruled 2026-09-03)

> **Status: DESIGN.** Tracked as #226. Sequenced behind go-xkms#274 → go-xkms#273
> → go-qrdb#278. Nothing below is implemented yet; where this section and the
> code disagree, this section is the requirement and the code is the defect.

### The problem it solves

The console offers **Run Attestation** on a device. Until #227 that control
called `collectHostAttestation`, which attests *the control plane's own TPM*,
discarded the device id, and reported success for the selected device — a green
result for a machine that was never attested. The control is now disabled,
because the platform has the **verifier** half of device attestation and no
**collector**: nothing asks a node for a quote.

### Shape

A reporting service collects attestation evidence from enrolled nodes on a
schedule, verifies it, and serves the **cached** result. It runs either
in-process in the control plane or **standalone on another node**, so that
potentially untrusted nodes never connect to the control plane directly.

```
  operator ──▶ console ──▶ reporting service ──(mTLS, IDevID)──▶ node
                              │      ▲                            │
                          cache│      └── collector loop (15 min) ─┘
                              ▼
                      verified report + verdict + age
```

**The reporting service dials the node.** Nodes accept no inbound connection
from the control plane.

### The invariant: a request never reaches a TPM

**No inbound request may cause a TPM quote.** The collector is the only
component that ever contacts a node's TPM; request handlers read the cache.
This is what stops repeated requests from exhausting a device's TPM, and it is
structural, not a tuning parameter: there must be no code path from a handler to
a quote.

An operator action **may** trigger fresh collection — it enqueues work with the
collector, which applies the same cache TTL, de-duplication and per-device
serialization it applies to scheduled work, so concurrent requests coalesce into
at most one in-flight collection per device. What is forbidden is a handler
talking to a TPM directly. A test asserts the separation; a comment does not.

### Mutual attestation, and why it is the detection mechanism

The node verifies the reporting service exactly as the reporting service
verifies nodes: fresh nonce, quote, verification against a provisioned policy. A
valid mTLS certificate proves *identity*; it does not prove *state*, and a
compromised reporting service still holds its key.

Because **every node independently verifies the reporting service**, a
compromise that changes measured state is rejected fleet-wide with no central
detector to subvert and nothing to broadcast. Two properties make this real
rather than decorative:

- **Channel binding.** A quote proves state at quote time, not request time. The
  TLS channel binding goes in the quote's qualifying data, so a valid quote
  cannot be replayed onto another connection (go-xkms#273). This is built
  for every quote a node produces over TLS: the node derives the binding of
  the connection the request arrived on and quotes it with the caller's
  nonce, so neither the reporting collector nor a direct caller can be fed a
  quote a relay obtained over its own connection (#482, §The collector, as
  built; [api.md](api.md) §5.1a).
- **Measured userspace is mandatory here.** A firmware/bootchain PCR set does
  not detect a swapped userspace daemon — precisely the threat when the peer is
  a reporting service. Policy for this use **must** include PCR 10 / the IMA log
  ([ima/architecture.md](../ima/architecture.md) is NORMATIVE).

Provisioning is the one thing that cannot be peer-to-peer: a node cannot verify
the reporting service without already holding its AK anchor and an acceptable
policy. That distribution is the control plane's job at enrollment. Trust cannot
be bootstrapped from nothing — but nothing at *request* time needs the CP.

### Device identity

Device mTLS authenticates with the **IDevID**, per TCG: IAK and LAK are
`Restricted`; the IDevID key is `Unrestricted`, precisely so it can authenticate
(TCG *TPM 2.0 Keys for Device Identity and Attestation* v1.10 r9). No device
private key exists outside a TPM.

This depends on go-xkms#274: the IDevID sign path currently routes through the
restricted hash-ticket flow and signs `H(digest)` instead of `digest`, which no
TLS `CertificateVerify` can satisfy. The file-based client certificates
introduced in #147 are a **workaround for that defect**, not the design, and are
retired when #274 lands.

### Baselines: signed manifest, TOFU fallback per profile

A profile with a signed reference manifest from the build pipeline verifies
against it. A profile without one falls back to TOFU. Two trust levels therefore
coexist, and the weaker one must never be invisible:

- `baseline_source: signed | tofu` is a field on the report **and** the device,
  not an inference.
- The console renders it beside every verdict. A TOFU pass must not look
  identical to a signed-manifest pass.
- A profile that later gains a signed manifest **re-baselines** and flags devices
  whose TOFU baseline disagrees — otherwise a TOFU baseline silently outranks a
  real manifest and enshrines whatever the node booted first.
- TOFU baselining is recorded as a **security event**: it is the moment trust was
  conferred without evidence.

### Failure: deny service, then quarantine — and what must NOT trigger it

A failed node is denied at every gated surface and moved to a restricted SDN
zone.

**"No evidence" is not "failed attestation."** An unreachable node, a collector
error, an expired cache or a network blip must **never** quarantine anything.
Only a cryptographically failed verification does — bad AK signature, nonce
mismatch, or PCR divergence from a *known* baseline.

This is the most important safety property in the feature. The platform has
already shipped this exact conflation as a real bug: #197, where a monitoring
outage was reported as "the host never read the media." Reporting absence of
evidence as evidence of compromise would here take a healthy node off the
network.

- Quarantine requires a configurable **consecutive-failure threshold** (default
  greater than one), so a single sample cannot isolate a node.
- Quarantine is reversible, manually overridable, and every action is audited.

### Who may challenge a node — a strategy, not a rule

Node-side admission is a named, config-selected authorization strategy, so an
operator can restrict challenges to their own reporting servers or open them to
any attested node:

| strategy | admits |
|---|---|
| `reporting-servers` | identities carrying the reporting-server role (**default**) |
| `any-attested` | any peer passing the attestation gate |
| `allowlist` | an explicitly provisioned set of peer identities |

The attestation gate runs **first and always**; the strategy authorizes only
after state is proven, keeping identity and state as separate claims. Strategies
are pluggable, and the selected strategy is exposed in the node's config surface
so it is auditable rather than guessed.

**What is built (PR a of #226), and what is not.** `pkg/attestation/calleradmission`
implements the *identity* claim and the strategy: the peer's client certificate
must chain to the node's configured anchors with the client-auth key usage, its
identity is its DNS SANs (the Common Name only when there are none — a CN that
disagrees with the SANs is not a second way to match), and the strategy then
decides. The *state* claim — "this peer is itself currently attested" — is the
upstream attested-caller middleware (go-qrdb#278 over go-xkms#273) and is not
built here. Until it lands, `any-attested` is honoured only where the node holds
attested-peer evidence locally (a control plane running the reporting cache) and
**refuses everyone elsewhere**, with an audited `attestation-gate-unavailable`
reason; it never degrades to "any valid certificate".

Everything fails closed: no anchors configured, a certificate from another
issuer, a certificate with no name, a name not on the list, an empty or
unparseable list, or an attestation source that cannot answer — each refuses,
each with a distinct `Reason` in the event log (`caller_admitted` /
`caller_refused` in `pkg/attestation/store`). "Not on the list" and "measured
state unacceptable" are different events; only the second is flagged
`security_relevant`.

The default `reporting-servers` set is **derived** from the control plane the
node enrolled against (the host of `acme.client.directory`) and logged at
startup as the effective identity set. An operator-set list **replaces** the
derived one; it never unions with it. Anchors come, in order, from
`attestation.reporting.callers.ca-file`, else `heartbeat.ca-file`, else the
[platform anchor](../trust/architecture.md#21-platform-anchor) — the root of the chain that issued this node's IDevID, which
on an enrolled node is the control plane's CA because enrollment imports that
chain (#653). The anchor source reported for the last is `platform-anchor`.
`GET /api/v1/attestation/callers`
reports the compiled policy — strategy, effective identities and their source,
anchor source, and whether it can admit anyone at all.

The quote-producing routes carry two principals: an operator through the admin
chain, or an admitted machine caller. A refused machine caller is refused; it is
not handed to the operator chain for a second attempt.

### The collector, as built (PR b of #226)

`pkg/attestation/reporting` gained the pieces slice A left as seams, and the
control plane composes them in `pkg/daemon/commands/attestation_reporting.go`:

- **`NodeQuoteSource`** is the platform's one `QuoteSource`: the reporting
  server dials `POST /api/v1/attestation/host` on the node with a fresh
  32-byte nonce, presents the webservice identity named by
  `attestation.reporting.collector.identity` (with the platform intermediate
  in the chain), verifies the node against an operator bundle
  (`attestation.reporting.collector.ca-file`) when one is set, else the trust
  resolver's `internal` class — the precedence the gateway reporter already
  uses for the control plane — with `ServerName` pinned, refuses a dialer with
  verification disabled,
  follows no redirects, bounds the response at 1 MiB, and refuses a response
  whose echo is not bound to its connection before anything reaches the
  verifier.
  **Every quote is bound to its connection, by both ends (#482).** The
  collector sends the node the **bare** nonce. The node derives the channel
  binding of the connection the request arrived on — 32 bytes of TLS
  exporter output under the upstream label `EXPORTER-attested-peer`
  (`xkms.PeerChannelBinding`) — and its TPM quotes
  `QualifyingData(nonce, binding)` = SHA-256(nonce ‖ binding)
  (`xkms.PeerQualifyingData`), which it echoes
  (`pkg/attestation/channelbind`, [api.md](api.md) §5.1a). The collector
  derives the binding from its own end of the same connection and accepts
  the echo only when it equals `QualifyingData(nonce, its binding)`;
  otherwise the attempt fails with `ErrQuoteNotBound`. The request is pinned
  to the dialled connection and a redial is refused (`ErrConnectionSpent`).
  The evidence carries the bare nonce and the binding beside the quote, and
  the reporting verifier requires both. A connection that cannot export
  keying material (TLS 1.2 without the extended master secret) is refused on
  either end — `ErrChannelBinding` on the collector,
  `ErrChannelBindingRequired` on the node, which also refuses the Unix
  socket, the embedded transport and plain HTTP; neither falls back to an
  unbound nonce.
  **Why the node must derive it.** When the collector sent the bound value
  and the node quoted it as received, any endpoint holding a valid
  certificate could relay that value unchanged to a healthy node over a
  second connection and return a quote that passed. Now the relay's forward
  is bound by the node to the relay's connection (B), the collector holds
  connection A, and the quote is refused: the attested state is accepted
  only from whoever terminates the collector's own TLS connection
  (`TestCollectHost_RelayedQuoteIsRejected`). A non-200
  from the node — including the node's own caller policy refusing this
  reporting server — is a collection failure, never a verdict.
- **Address provenance (#377).** `DeviceAddressResolver` dials only what the
  platform learned from an authenticated connection: the platform DNS A/AAAA
  record for `<hostname>.<internal zone>` (registered at enrollment from the
  enrolling connection), then the transport peer address of the device's last
  mTLS-verified heartbeat (`last_heartbeat_addr`, recorded from the
  connection, never the body). A device with neither fails closed with
  `ErrNoDialableAddress`; nothing is guessed. The expected certificate name is
  the device FQDN unless the device **profile** sets `tls-server-name`, for
  fleets whose node certificates carry a role name
  (`platformctl device profile update <id> --tls-server-name <name>`; the
  field is on every profile transport since #448, survives an update that
  omits it, and is removed only by an explicit clear such as
  `--clear-tls-server-name`, `docs/device/api.md` §3.2).
- **Profile resolution has one implementation and one precedence (#463).**
  `ProfileService.FindProfileForDevice` is the only device → profile lookup
  the attestation path uses — the collector for the node's TLS server name,
  the quote verifier for the PCR baseline — so both always land on the same
  profile: (1) the profile **bound** to the device, whose `ek_serial` equals
  the serial of the device's stored EK certificate (what
  `AssignProfileToDevice` records; a device record carries no MAC); (2) else
  a profile whose **match rules** cover the device's serial and model; (3)
  else `ErrNoProfileForDevice`, which the collector reports as "no
  tls-server-name" and the verifier as an absence. Any other error is a store
  that could not answer, not "no profile": the verifier fails closed with
  `ErrDeviceProfileLookupFailed` (cause attached) and records no verdict,
  because a lookup that decided nothing must not be read as an absence.
  Installer-created profiles
  carry neither rules nor a binding, so the operator binds each enrolled
  device once (`platformctl device profile assign <profile-id> --device
  <device-id>`); the EK serial is derived on the control plane from the
  device's stored certificate, never by a client.
- **Verdicts persist.** The cache writes through to `<attestation>/reports/`
  and warms from it at start, keeping each report's original `CollectedAt`,
  so a restarted control plane shows the last verdict as old rather than every
  device as never collected.
- **The trigger is an enqueue.** `POST /attestation/reports/{id}/refresh`,
  `RefreshDeviceReport` and `attestation_device_refresh` call
  `Collector.Refresh`, which applies the same per-device serialization and
  coalescing as the schedule. They answer 202 / `enqueued: true` immediately;
  the verdict is read back with its age.
- **Every transport renders the same `View`:** verdict, each check, baseline
  source and capture flag, `attested_at`, `collected_at`, `fresh`,
  `age_seconds`, `as_of`, `time_synced`. Never collected is a 404 /
  `NotFound` / `ErrNoDeviceReport`, never a synthesised failed verdict.
- **The device's clock state travels with the verdict (#509).** In the same
  collection that produces the quote, the collector reads the node's clock
  route (`GET /attestation/clock`, on the same caller gate as the quote
  routes) and records `time_synced` on the report. It is a three-state field —
  true, false, ABSENT — and the collector records ABSENT whenever the read
  failed. Recording `false` because a node was unreachable would convert a
  network problem into a claim about that machine's clock, which is the same
  conflation the "absence of evidence is not failed attestation" rule above
  exists to prevent. The `ClockSource` seam is optional and separate from
  `QuoteSource` for that reason: a collector wired without one produces
  reports that say nothing about clocks rather than reports that say the wrong
  thing.
- **`any-attested` on the control plane** consults this cache: a peer whose
  certificate names a device with a verified, fresh report is attested.

Standalone reporting-server mode (slice D) is **not** built: a node that is
not the control plane holds no device records, profiles or CA anchor to verify
against, so the collector there would need the CP as a data source at request
time — which is the coupling requirement 3 exists to avoid. The service is a
platformd component enabled by `attestation.reporting.enabled`; the standalone
topology needs a ruling on where a reporting server gets device records and is
filed as a follow-up rather than shipped as a stub.

### Every node is its own root CA — measured 2026-09-05

Do not design against "the platform CA" as if there were one. On the live fleet
every node stands up its **own** root and issuing CA (`root-ca.<role>.<domain>`
/ `ca01.<role>.<domain>`), and a node's webservice certificate is issued by that
local CA, not by the control plane. Two consequences the reporting service had
to be built around:

- A node's listener trusted only its own CA for client certificates, so a
  control-plane client certificate — issued by the CP CA that enrolled the node —
  failed the TLS handshake on every node (HTTP 000 from node-05 to node-01 and
  to itself; 200 to the CP). The listener now also requests certificates from
  the caller-admission anchors, and the policy re-verifies the chain itself.
- The control plane cannot verify a node's server certificate with its own CA.
  The collector verifies against the platform CA only (then the unconfigured
  [platform anchor](../trust/architecture.md#21-platform-anchor)), so the collector (PR b)
  requires node webservice certificates to chain to the platform CA and carry
  the device's name; that is a deploy step, recorded in the collector PR.

Recorded on #377 as well, so the next design starts from the measured shape.

### The control plane is a device in its own registry (#472, owner-ruled 2026-09-06)

The collector iterates device records. A control plane with no record is never
collected, so the one machine that decides every other machine's verdict was
the one machine nothing could attest — measured on the live fleet on
2026-09-05, where `device list` returned two nodes and no control plane
despite a fully provisioned control-plane TPM.

The ruling is that **the control plane is enrolled as a device like any node**,
and nodes verify it with the attested-peer primitive at connection time. There
is no self-report path: a parallel "the control plane reports on itself" code
path would be a second implementation of verification whose divergence from the
real one nobody would notice until it mattered.

**Registration reuses the enrollment path, not the enrollment ceremony.**
`device.Register` is the one find-or-create implementation; the ACME
order-finalize hook fills its `Registration` from the CA's `TCGEnrollmentData`
and the control plane fills the identical structure from its own TPM
(`device.ControlPlaneRegistrar`) — EK certificate, IAK certificate as
`attest_cert`, the IAK and IDevID `TPMT_PUBLIC` public areas, the boot event
log, and the IDevID Common Name as the hostname. The control plane does not
drive ACME at itself: its own CA already issued those certificates from its own
TPM at platform identity completion, and the listener ACME would target is not
up at that point in the boot.

**Fail closed on the anchor.** A control plane whose TPM holds no attestation
public area is refused (`ErrControlPlaneNoAttestationKey`) rather than
registered. A record the collector dials and can never verdict reports "no
evidence" for ever while looking configured, which is worse than no record.
Every other piece of material is best-effort: a TPM with no manufacturer EK
certificate, a platform whose IDevID has not been issued, and a kernel that
exposes no measurement log are all real, and none of them stops the machine
being attestable.

**An unverifiable attestation certificate is never recorded — recording one
would quarantine the machine.** This is the one place where writing *less* to
the device record is the safe direction, and the asymmetry is in the verifier:

| what the record holds | the verifier's check | consequence |
|---|---|---|
| no attestation certificate | **absent** | denied service; nothing quarantined |
| a certificate that fails verification | **failed**, and therefore **cryptographic** | dispatched to the quarantine observers |

So a CA that does not stamp `tcg-cap-verifiedTPMRestricted` would, by
recording what it issued, convert every device it enrolls from "cannot be
attested" into "attestation failed" — and on a control plane registering
itself, that machine is the control plane. The live fleet's IAK certificates
were issued by a pre-0.9.4 CA and carry no policy, so this is the ordinary
case today.

`device.Register` therefore records an attestation certificate only when
`vm.CarriesVerifiedTPMRestricted` holds, dropping a non-compliant or
unparseable one, preserving whatever was already recorded, and returning the
reason for the caller to log. It emits no verdict and notifies no observer:
registration is a registry write, never a second verification path. The gate
is narrower than `device attest-cert record` (#485) — no chain check, no
key-match check — because both of those hold by construction at enrollment
while the policy attribute does not. Once the CA stamps the policy the
operator runs `platformctl device attest-cert record <id> --reissue`, which
applies the full fail-closed preflight.

**Phase.** Self-registration runs in the serve path, immediately before the
collector is built, gated on `attestation.reporting.enabled` — the setting that
makes a node a reporting server. It is a **reconcile on every start**, not a
one-shot at install: the device registry does not exist at platform identity
completion, and every control plane already deployed was provisioned before
this existed, so a first-boot-only registration would leave those machines
permanently unattestable. `device.Register` is find-or-create by product
serial, so repeating it is a no-op.

**Address provenance for a machine dialling itself.** The resolver accepts a
platform DNS record registered at enrollment or the peer address of an
authenticated heartbeat, and a machine has neither for itself. The third
provenance, used for exactly one device id, is the control plane's own
loopback endpoint (`reporting.SourceControlPlaneLoopback`): it is not learned
from a record and not something a device claimed, it is a property of the
process doing the dialling — the strongest provenance in the resolver, not a
weakening of it. The port and certificate name come from this control plane's
own webservice configuration, specifically the listener whose identity the
collector presents (`attestation.reporting.collector.identity`). A profile
bound to the device with `tls-server-name` still wins, exactly as for a node.

**Admission is the same policy, not a bypass.** The control plane's collector
reaches its own quote route through the same `pkg/attestation/calleradmission`
gate that admits it on every node: the collector presents the webservice
identity certificate, the policy verifies the chain against the control plane's
own anchors, and the `reporting-servers` set — derived from the
self-referential `acme.client.directory` — must name it. There is no loopback
exemption; a mutation adding one is killed by
`TestControlPlaneAsDevice_EndToEnd`. A refusal is a collection failure, never a
verdict, so an operator who narrows the identity list sees an unattested
control plane rather than a quarantined one.

**Profile binding is an operator step**, the same one every enrolled device
needs (`platformctl device profile assign <profile-id> --device <device-id>`),
because the PCR baseline and network policy a profile carries are operator
decisions. Collection works without one: the control plane's own certificate
name comes from its own configuration.

**What is not in this half.** Nodes verifying the control plane — the mutual
half. #482 put the device quote verifier on the attested-peer primitive and
bound the collector's quotes to their connection, but a node verifying the
control plane must derive the binding on its own end of the connection, and
go-quicbaas does not yet re-export the node-side helpers
(`QualifyingDataFromTLS`, `EvidenceFromTLS`). Until then the control plane is
collected and verdicted like a node, and nodes still take its identity on its
certificate alone.

### Transports

The verifier is **one implementation** (go-xkms#273) consumed by every
transport. REST, gRPC, MCP and Unix are registered through the `apimodule`
seam. **QUIC is a gap to fill, not a handler to retain** (#386): the
`OpAttestDeviceWorkload` handler exists as code but is never constructed in
production — `WithQUICAttestationService` has no production caller — so it
answers `ErrAttestationServiceNotAvailable`. An earlier revision of this
section said all five transports carried the capability; that was written on
a false premise and is corrected here rather than left contradicting the code.

### Backend wiring on both run paths (#544)

`platformd serve` has two run paths: with a `webservices:` section
(`runWithWebservices`) and without one (`runDaemonOnly`). Both build the
attestation backend through the one helper, `wireAttestationOnConfig`
(`pkg/daemon/commands/attestation_init.go`): the manifest store and service
under `<platform-dir>/attestation`, the quarantine observer, the caller
policy and the reporting collector. It sets `daemon.Config.AttestationService`
and `AttestationReporting` before `daemon.New`, so a daemon-only node serves
the same gRPC, Unix and MCP attestation surface as one with webservices. The
webservices path adds only its REST consumers (the enrollment capture hook,
the event reader, the SDN enrollment hook) on top.

When the backend is absent the RPCs are still registered and answer
`FailedPrecondition` ("attestation service backend is not configured"); that
happens only when the store cannot be opened (`ErrAttestationStoreUnavailable`,
logged, startup continues). A node with no TPM still gets the backend: manifest
operations work, and quote production answers `ErrTPMSessionNotConfigured`.
Before #544 the daemon-only path never built the backend, so every attestation
RPC on it answered `FailedPrecondition`.

### Quote production (#387)

`CollectHostAttestation` and `GetQuote` produce real quotes once the daemon
hands the attestation service the node's TPM (`attestation_init.go`). The
quote is signed by the **IAK** — the Restricted attestation key TCG assigns to
attestation. `CollectHostAttestation` quotes the caller's nonce bound to the
connection the request arrived on, `QualifyingData(nonce, binding)` (#482,
§The collector, as built), and refuses a request whose connection carries no
binding. `GetQuote` does the same and returns the binding so a direct
caller can check the echo against its own connection
([engineering.md](engineering.md) §3 invariant 11). Before returning, the
node checks that the PCR values it is about to report hash to the digest its
TPM signed, and refuses to emit evidence its own verifier would reject. The
REST routes that expose this are gated ([api.md](api.md) §5.1) in the same
change; quote production never reaches a node ungated.

### Revocation

Preferred: **attestation-gated short-lived credentials** — renewed only while
attestation passes, so quarantine is fail-closed by expiry with nothing to
distribute and no delivery guarantee to depend on. A pushed denylist shortens
the revocation window but **fails open** when a node misses the message; add one
only if the credential lifetime cannot be made short enough.

### The residual limit, stated plainly

None of this detects a compromise that changes no measured state and occurs
after the last quote. Channel binding shrinks that window to a single
connection; short credential lifetimes and the refresh interval shrink the rest.
It cannot be closed by attestation, and the console must not imply continuous
proof — it shows a verdict **and** the evidence age.

### Implementation status of the reporting service (#226)

The design above is the contract; this records what exists in code, so the
section is not read as describing a shipped feature.

| slice | state |
|---|---|
| **A — collector, cache, the never-quote invariant** | `pkg/attestation/reporting`; PR b adds `NodeQuoteSource`, `DeviceAddressResolver`, persistence, `View` |
| B — node-side attestation endpoint | quote production: #388. Caller admission (identity + strategy, anchors on the listener, audit events): `pkg/attestation/calleradmission`, PR a of #226. The collector that dials it: PR b. The state gate is upstream (go-qrdb#278 / go-xkms#273) |
| C — `AttestDevice` on all transports | PR #316 (transports) + #373/#374 (the verifier contract below) — the **verifier** half only |
| D — standalone reporting-server mode | not built; needs a ruling on the reporting server's device-record source (follow-up filed from PR b) |
| E — console verdict + evidence age | server side built (PR b): reports on REST, gRPC/Unix and MCP with `fresh`, `age_seconds`, `pcr_baseline_source`, `ak_certificate_verified`. Console built: the Devices pages render each verdict beside its age (#428); the Attestation page summarises the fleet from the same reports and raises stale, unverdicted, failed, none-at-all and not-configured as problems (#643). Manifests and quotes are labelled signed/unsigned, never as verdicts |

`pkg/attestation/reporting` implements the invariant structurally rather than
by convention:

- `Reader` — the read-only view a request handler is given — has exactly two
  methods, neither taking a `context.Context`. A context is the signature of
  an operation that blocks on something external, which a cache read never
  does and a device round-trip always does. `TestInvariant_ReaderCannotReachADevice`
  enumerates the methods by reflection, so **adding** one fails the test.
- `Cache` holds no `QuoteSource` and no `Verifier`, asserted by reflection over
  its fields. `Reader` constrains what a handler may *call*; this constrains
  what the concrete type can *reach*.
- `Collector` is the only holder of a `QuoteSource`. An operator refresh goes
  through `Collector.Enqueue`, which applies the same per-device serialization
  and coalescing as scheduled work — so an operator cannot generate more TPM
  load than the schedule would.

Two rules the code enforces that are easy to get backwards:

- **Absence of evidence is not failed attestation.** A device that could not be
  reached, or evidence that could not be evaluated, leaves the previous report
  **and its timestamp** untouched. Writing a failed verdict there would convert a
  network problem into an attestation result — the conflation #197 shipped once.
  A verification that *ran* and said no is a real result and does replace the
  cached one.
- **A stale report is retained, not discarded.** Expiry means the evidence is
  old, not that the device has none; deleting it makes an overdue device
  indistinguishable from one never collected. Consumers read `Fresh` alongside
  the report. `DefaultTTL` is deliberately longer than `DefaultInterval` — a TTL
  shorter than the refresh cycle marks every report stale before its replacement
  is due, a budget no correct behaviour can satisfy.

### Device quote verification — the contract as built (#373, #374)

`pkg/api/daemon.DeviceQuoteVerifier` is the one implementation behind every
transport's `AttestDevice`. It exists because the previous verifier had two
spec defects: it took the expected PCR state **from the attester** and passed
when none was supplied (an attacker chose what "good" meant), and it never
checked `tcg-cap-verifiedTPMRestricted`, the check TCG DevID v1 r12 §8.2 makes
a MUST before trusting a quote.

- **The checks are upstream's (#482).** Certificate chain and Restricted,
  quote signature, nonce, PCR digest and baseline comparison are the go-xkms
  attested-peer verifier, reached through the go-quicbaas re-export
  `xkms.NewPeerAttestationVerifier`. The platform keeps only what it alone
  knows: which profile holds the baseline, trust-on-first-use capture into it,
  the verdict sink, and the transports. There is no local copy of any check.
- **Trust anchor** is the device's enrolled attestation **certificate**,
  chained to the platform CA (root + intermediate) and required to carry
  2.23.133.11.1.3. A bare public key is not accepted.
- **Expected state** is the `PCRBaseline` on the device's `DeviceProfile`
  (`source` = `signed` | `tofu`). Reported values must hash to the signed
  digest before they are compared. A profile without a baseline captures one
  from the first quote whose every other check held (owner ruling: signed
  manifest, TOFU fallback per profile); only the values the verifier proved
  are captured, and the capture is a `pcr_baseline_captured` event.
- **Channel binding is required on the collector's verifier, ignored on the
  transports (#482).** `DeviceQuoteVerifierForReporting` refuses evidence
  without a `channel_binding` (`ErrInvalidAttestationEvidence`, no verdict)
  and hands the binding to the peer policy, which requires the quote's
  extraData to equal SHA-256(nonce ‖ binding). A quote over the bare nonce
  is a cryptographic failure. The transports verify evidence a caller
  submits, where a binding names no session the verifier saw, so they ignore
  the field rather than honour it.
- **Verdict classes** are carried by `pkg/attestation/verdict.DeviceVerdict`
  and recorded by the attestation service (`RecordDeviceVerdict`): a
  cryptographic failure reaches the quarantine observers (deny + SDN
  quarantine, the #226 ruling); an absence of evidence is denied but never
  quarantined. Which class a failure falls in is the peer verdict's
  `Failure`, mapped onto `DeviceVerdict.Cryptographic` and nowhere else
  decided. A quoted PCR **selection** that differs from the baseline's
  register set is an absence — nothing the TPM signed was wrong, the quote
  just does not cover what the profile accepts — while a **value** that
  diverges on a covered register is cryptographic. A missing certificate,
  CA, profile or baseline, or a stored baseline the verifier refuses as
  unusable, is an absence.
- **Enrollment records the anchor (#404).** The ACME finalize for a
  TCG-CSR-IDEVID order issues the IAK certificate together with the IDevID
  and hands it to the platform's device registration hook as DER; the hook
  stores it PEM-encoded in `Device.AttestCert` on first enrollment and
  re-enrollment, and every device transport carries it as `attest_cert`
  beside `attest_pub`. Recording is not verifying: the certificate passes
  `ak_certificate_verified` only if the issuing CA stamped
  `tcg-cap-verifiedTPMRestricted`, which the `tcg-iak` profile does from
  go-xkms v0.9.3-alpha; the go-xkms reachable through the current quicbaas
  pin stamps residency and fixed only, so devices enrolled against it are
  recorded correctly and still denied until the pin moves.
- **The console shows the baseline's provenance.** The device profiles page
  renders each profile's `pcr_baseline` — source, age, covered registers and
  the seeding device — and the JS SDK `DeviceAttestResponse` carries
  `ak_certificate_verified`, `pcr_baseline_source` and
  `pcr_baseline_recorded_at` for the per-device verdict view #428 renders.
- **The baseline is readable on every transport, and writable on none**
  (#448): the pb `DeviceProfile.pcr_baseline` (`PCRBaseline` message) on
  gRPC / Unix / live QUIC, the dark REST/QUIC profile responses, the MCP
  profile results and `platformctl device profile` all report it; every
  create/update path ignores a supplied one, and `ProfileService.Update`
  keeps the stored baseline (and `tls_server_name`, unless the update
  clears it explicitly, `docs/device/api.md` §3.2) when an update carries
  none.
- What is **not** in this slice: the dark REST/QUIC device handlers that
  still carry a stub verifier (#403) and the signed-manifest baseline writer
  (the `signed` source exists in the entity; nothing produces it yet).

## Overview

The Trusted Platform Attestation architecture provides hierarchical trust verification using TPM 2.0 hardware roots of trust. The system enables cryptographic proof of platform integrity through TPM quotes, event log analysis, and policy-based verification. Attestation extends from physical hosts through virtual machines to individual containers, creating a complete chain of trust for all workloads.

## System Architecture

```
+------------------------------------------------------------------------------+
|                        Trusted Platform Attestation                           |
+------------------------------------------------------------------------------+
|                                                                              |
|  +------------------------------------------------------------------------+  |
|  |                      Attestation Manager                               |  |
|  |                   (pkg/attestation/manager.go)                         |  |
|  |                                                                        |  |
|  |  +---------------+  +---------------+  +---------------+               |  |
|  |  |    Quote      |  |    Verify     |  |   Manifest    |               |  |
|  |  |  Generator    |  |    Engine     |  |   Builder     |               |  |
|  |  |               |  |               |  |               |               |  |
|  |  | * Nonce gen   |  | * Quote check |  | * Host info   |               |  |
|  |  | * PCR select  |  | * PCR compare |  | * VM enum     |               |  |
|  |  | * AK signing  |  | * Event parse |  | * Container   |               |  |
|  |  +---------------+  +---------------+  +---------------+               |  |
|  |                                                                        |  |
|  |  +--------------------------------------------------------------------+|  |
|  |  |                  Workload Chain Manager                            ||  |
|  |  |               PCR 14 Extension Tracking                            ||  |
|  |  +--------------------------------------------------------------------+|  |
|  +------------------------------------------------------------------------+  |
|                                      |                                       |
|                                      | uses                                  |
|                                      v                                       |
|  +------------------------------------------------------------------------+  |
|  |                         TPM Layer                                      |  |
|  |                      (go-tpm library)                                  |  |
|  |                                                                        |  |
|  |  +---------------+  +---------------+  +---------------+               |  |
|  |  |    Quote      |  |     PCR       |  |   Event Log   |               |  |
|  |  |  Generation   |  |    Reading    |  |    Parser     |               |  |
|  |  |               |  |               |  |               |               |  |
|  |  | * TPM2_Quote  |  | * PCR banks   |  | * TCG2 format |               |  |
|  |  | * AK handle   |  | * SHA-256/384 |  | * Replay      |               |  |
|  |  | * Signature   |  | * Selection   |  | * Verify      |               |  |
|  |  +---------------+  +---------------+  +---------------+               |  |
|  +------------------------------------------------------------------------+  |
|                                      |                                       |
|         +----------------------------+----------------------------+          |
|         |                            |                            |          |
|         v                            v                            v          |
|  +----------------+         +----------------+         +----------------+    |
|  | Certificate    |         |  Policy Engine |         | Workload Mgr   |    |
|  | Authority      |         |     (OPA)      |         |                |    |
|  |                |         |                |         |                |    |
|  | * IDevID/IAK   |         | * Rego rules   |         | * Podman       |    |
|  | * Attest store |         | * PCR policy   |         | * QEMU/libvirt |    |
|  | * ACME enroll  |         | * Evaluation   |         | * swtpm        |    |
|  +----------------+         +----------------+         +----------------+    |
|                                                                              |
+------------------------------------------------------------------------------+
                                      |
              +-----------------------+-----------------------+
              |                       |                       |
              v                       v                       v
       +-------------+         +-------------+         +-------------+
       |  platformd  |         |     CA      |         |    OPA      |
       |  (daemon)   |         |  (go-ca)    |         |  (policy)   |
       +-------------+         +-------------+         +-------------+
```

## Component Overview

### Attestation Manager

The central coordinator for all attestation operations. Orchestrates quote generation, verification workflows, and manifest creation.

Responsibilities:
- Coordinate attestation requests across components
- Manage attestation state and caching
- Route verification requests to appropriate handlers
- Aggregate results from multiple attestation sources

### TPM Interface

Hardware interaction layer using go-tpm for TPM 2.0 communication.

Capabilities:
- TPM device discovery and initialization
- Session management for authorized operations
- Error handling and retry logic
- Support for both hardware TPM and swtpm

### Quote Generator

Creates TPM quotes with cryptographic proof of platform state.

Operations:
- Generate cryptographic nonces for freshness
- Select appropriate PCR banks (SHA-256, SHA-384)
- Request TPM2_Quote with Attestation Key (AK)
- Package quote with signature and certificate chain

### Quote Verifier

Validates TPM quotes against known-good PCR values and policies.

Verification steps:
- Validate quote signature against AK certificate
- Verify nonce freshness and uniqueness
- Compare PCR values against expected baselines
- Check event log consistency with PCR values

### Event Log Analyzer

Parses and replays TCG2 event logs to verify measurement integrity.

Functions:
- Parse TCG2 event log binary format
- Replay measurements to verify PCR values
- Extract event metadata for policy evaluation
- Identify unexpected or malicious measurements

### Manifest Builder

Creates hierarchical attestation reports encompassing hosts and workloads.

Report contents:
- Host platform attestation summary
- Virtual machine attestation for each VM
- Container attestation for each container
- Cryptographic binding between layers

### Workload Chain Manager

Tracks PCR 14 extensions as workloads start and stop.

Tracking:
- Record workload lifecycle events
- Maintain extension chain integrity
- Support workload enumeration for attestation
- Provide tamper-evident workload history

### Policy Engine

OPA-based policy evaluation for attestation decisions.

Policy features:
- Rego policy language for flexible rules
- PCR value baseline comparisons
- Event log content validation
- Custom attestation requirements per workload type

## Data Model

All attestation data uses structured storage paths within the CA:

```
Attestation Storage (CA):
attestation/{akCN}/quote/data          -> TPM quote blob
attestation/{akCN}/quote/signature     -> Quote signature
attestation/{akCN}/quote/nonce         -> Challenge nonce
attestation/{akCN}/quote/timestamp     -> Quote creation time

attestation/{akCN}/eventlog/data       -> TCG2 event log binary
attestation/{akCN}/eventlog/parsed     -> Parsed event entries (JSON)
attestation/{akCN}/eventlog/hash       -> Event log integrity hash

attestation/{akCN}/pcrs/data           -> PCR values snapshot
attestation/{akCN}/pcrs/bank           -> PCR bank identifier
attestation/{akCN}/pcrs/selection      -> Selected PCR indices

Device Profiles:
profiles/{profileName}/pcrs/expected   -> Expected PCR values
profiles/{profileName}/events/allowed  -> Allowed event patterns
profiles/{profileName}/policy/rego     -> OPA policy for profile

Workload Chains:
workloads/{hostID}/chain/current       -> Current PCR 14 value
workloads/{hostID}/chain/entries       -> Extension history
workloads/{hostID}/chain/manifest      -> Active workload manifest
```

## Attestation Flows

### Device Enrollment Flow

```
Device                platformd               TPM                    CA
   |                     |                     |                     |
   | 1. Enrollment req   |                     |                     |
   |-------------------->|                     |                     |
   |                     |                     |                     |
   |                     | 2. Create EK        |                     |
   |                     |-------------------->|                     |
   |                     |                     |                     |
   |                     |    EK handle        |                     |
   |                     |<--------------------|                     |
   |                     |                     |                     |
   |                     | 3. Create AK        |                     |
   |                     |-------------------->|                     |
   |                     |                     |                     |
   |                     |    AK handle + pub  |                     |
   |                     |<--------------------|                     |
   |                     |                     |                     |
   |                     | 4. ACME enroll-01   |                     |
   |                     |-------------------------------------------->|
   |                     |                     |                     |
   |                     |                     |    Challenge        |
   |                     |<--------------------------------------------|
   |                     |                     |                     |
   |                     | 5. Prove possession |                     |
   |                     |-------------------->|                     |
   |                     |                     |                     |
   |                     |    Signed response  |                     |
   |                     |<--------------------|                     |
   |                     |                     |                     |
   |                     | 6. Submit proof     |                     |
   |                     |-------------------------------------------->|
   |                     |                     |                     |
   |                     |                     |    IDevID cert      |
   |                     |<--------------------------------------------|
   |                     |                     |                     |
   | 7. Enrollment done  |                     |                     |
   |<--------------------|                     |                     |
```

### Quote Verification Flow

```
Verifier             Device              TPM                 Policy Engine
   |                   |                   |                       |
   | 1. Request quote  |                   |                       |
   |   (with nonce)    |                   |                       |
   |------------------>|                   |                       |
   |                   |                   |                       |
   |                   | 2. TPM2_Quote     |                       |
   |                   |------------------>|                       |
   |                   |                   |                       |
   |                   |    Quote + sig    |                       |
   |                   |<------------------|                       |
   |                   |                   |                       |
   |                   | 3. Read event log |                       |
   |                   |------------------>|                       |
   |                   |                   |                       |
   |                   |    Event log      |                       |
   |                   |<------------------|                       |
   |                   |                   |                       |
   |    Quote bundle   |                   |                       |
   |<------------------|                   |                       |
   |                   |                   |                       |
   | 4. Verify quote signature             |                       |
   |                   |                   |                       |
   | 5. Replay event log                   |                       |
   |                   |                   |                       |
   | 6. Evaluate policy|                   |                       |
   |------------------------------------------------------>|       |
   |                   |                   |                       |
   |                   |                   |    Policy decision    |
   |<------------------------------------------------------|       |
   |                   |                   |                       |
   | 7. Return result  |                   |                       |
   |------------------>|                   |                       |
```

### Manifest Generation Flow

```
Request              Attestation Mgr          Host TPM           VM/Container
   |                       |                     |                     |
   | 1. Generate manifest  |                     |                     |
   |---------------------->|                     |                     |
   |                       |                     |                     |
   |                       | 2. Collect host     |                     |
   |                       |    attestation      |                     |
   |                       |-------------------->|                     |
   |                       |                     |                     |
   |                       |    Host quote       |                     |
   |                       |<--------------------|                     |
   |                       |                     |                     |
   |                       | 3. Enumerate VMs    |                     |
   |                       |-------------------------------------------->|
   |                       |                     |                     |
   |                       |                     |    VM list          |
   |                       |<--------------------------------------------|
   |                       |                     |                     |
   |                       | 4. For each VM:     |                     |
   |                       |    Get swtpm quote  |                     |
   |                       |-------------------------------------------->|
   |                       |                     |                     |
   |                       |                     |    VM quotes        |
   |                       |<--------------------------------------------|
   |                       |                     |                     |
   |                       | 5. Enumerate        |                     |
   |                       |    containers       |                     |
   |                       |-------------------------------------------->|
   |                       |                     |                     |
   |                       |                     |    Container list   |
   |                       |<--------------------------------------------|
   |                       |                     |                     |
   |                       | 6. Sign manifest    |                     |
   |                       |-------------------->|                     |
   |                       |                     |                     |
   |    Signed manifest    |    Signature        |                     |
   |<----------------------|<--------------------|                     |
```

### Workload Attestation Flow

```
Workload Mgr         platformd               TPM                    CA
   |                     |                     |                     |
   | 1. Container start  |                     |                     |
   |-------------------->|                     |                     |
   |                     |                     |                     |
   |                     | 2. Compute digest   |                     |
   |                     | H(type||id||image)  |                     |
   |                     |                     |                     |
   |                     | 3. Extend PCR 14    |                     |
   |                     |-------------------->|                     |
   |                     |                     |                     |
   |                     |    New PCR value    |                     |
   |                     |<--------------------|                     |
   |                     |                     |                     |
   |                     | 4. Record extension |                     |
   |                     |-------------------------------------------->|
   |                     |                     |                     |
   |                     |                     |    Stored           |
   |                     |<--------------------------------------------|
   |                     |                     |                     |
   | 5. Start confirmed  |                     |                     |
   |<--------------------|                     |                     |
   |                     |                     |                     |
   | (Later: Container stop)                   |                     |
   |                     |                     |                     |
   | 6. Container stop   |                     |                     |
   |-------------------->|                     |                     |
   |                     |                     |                     |
   |                     | 7. Record stop      |                     |
   |                     |-------------------------------------------->|
   |                     |                     |                     |
```

## Hierarchical Trust Model

```
+---------------------------------------------+
|           Host Attestation                  |
|  TPM 2.0 (PCRs 0-10, 14, 23)               |
|                                             |
|  * Hardware root of trust                   |
|  * Platform firmware measurements           |
|  * OS boot measurements                     |
|  * Workload chain in PCR 14                 |
+-------------+---------------+---------------+
              |               |               |
              v               v               v
       +-------------+ +-------------+ +-------------+
       |    VM 1     | |    VM 2     | |    VM N     |
       |   swtpm     | |   swtpm     | |   swtpm     |
       |             | |             | |             |
       | * vTPM 2.0  | | * vTPM 2.0  | | * vTPM 2.0  |
       | * VM boot   | | * VM boot   | | * VM boot   |
       | * Guest OS  | | * Guest OS  | | * Guest OS  |
       +------+------+ +------+------+ +------+------+
              |               |               |
       +------+------+ +------+------+ +------+------+
       |  C1  |  C2  | |  C3  |  C4  | |  C5  |  C6  |
       +------+------+ +------+------+ +------+------+

Trust Propagation:
  Host TPM ---[quote]---> Verifier
       |
       +---> swtpm (VM 1) ---[quote]---> Verifier
       |          |
       |          +---> Container C1 ---[manifest]---> Verifier
       |          +---> Container C2 ---[manifest]---> Verifier
       |
       +---> swtpm (VM 2) ---[quote]---> Verifier
                  |
                  +---> Container C3 ---[manifest]---> Verifier
                  +---> Container C4 ---[manifest]---> Verifier
```

## PCR Extension Chain

Workloads are tracked through sequential PCR 14 extensions:

```
PCR 14 Extension Chain
+------------------------------------------------------------------------------+
|                                                                              |
|  Initial State (boot):                                                       |
|  PCR[14] = 0x0000...0000 (all zeros)                                        |
|                                                                              |
|  Extension 1 (Container A starts):                                           |
|  digest_1 = H("container" || "container-a-id" || "sha256:abc123...")        |
|  PCR[14] = H(PCR[14] || digest_1)                                           |
|          = 0x3a7b...c4e2                                                    |
|                                                                              |
|  Extension 2 (VM B starts):                                                  |
|  digest_2 = H("vm" || "vm-b-id" || "sha256:def456...")                      |
|  PCR[14] = H(PCR[14] || digest_2)                                           |
|          = 0x8f12...9d3a                                                    |
|                                                                              |
|  Extension 3 (Container C starts):                                           |
|  digest_3 = H("container" || "container-c-id" || "sha256:ghi789...")        |
|  PCR[14] = H(PCR[14] || digest_3)                                           |
|          = 0x2c5e...a1b7                                                    |
|                                                                              |
+------------------------------------------------------------------------------+

Chain Properties:
  * Order-dependent: Same workloads in different order = different PCR
  * Tamper-evident: Cannot remove or reorder entries
  * Verifiable: Can replay chain to verify current PCR value
  * Auditable: Complete history of workload lifecycle
```

## Security Model

### Hardware Root of Trust

| Component | Security Property |
|-----------|-------------------|
| TPM 2.0 | Tamper-resistant hardware security module |
| EK | Manufacturer-provisioned, unique identity |
| SRK | Storage hierarchy root, platform-bound |
| AK | Attestation signing key, non-migratable |

### Quote Freshness

```
Freshness Verification:
+-------------------------------------------------------------------+
|                                                                   |
|  1. Verifier generates nonce: N = random(256 bits)               |
|                                                                   |
|  2. Quote includes nonce: Quote = Sign_AK(PCRs || N)             |
|                                                                   |
|  3. Verification:                                                 |
|     - Check signature with AK public key                          |
|     - Verify N matches original challenge                         |
|     - Confirm quote timestamp within acceptable window            |
|                                                                   |
|  Protection against:                                              |
|     * Replay attacks (nonce uniqueness)                           |
|     * Stale quotes (timestamp check)                              |
|     * Quote forgery (AK signature)                                |
|                                                                   |
+-------------------------------------------------------------------+
```

### Policy-Based Verification

| Policy Type | Description |
|-------------|-------------|
| PCR Baseline | Expected PCR values for known-good state |
| Event Allowlist | Permitted measurement events |
| Workload Rules | Required attestation for workload types |
| Time Bounds | Maximum age for valid attestation |

### Tamper-Evident Event Logs

```
Event Log Integrity:
+-------------------------------------------------------------------+
|                                                                   |
|  TCG2 Event Log Format:                                           |
|  +----------------+----------------+----------------+              |
|  | Event Header   | Digest         | Event Data    |              |
|  | (PCR, type)    | (SHA-256/384)  | (variable)    |              |
|  +----------------+----------------+----------------+              |
|                                                                   |
|  Replay Verification:                                             |
|  1. Start with known-good initial PCR values                      |
|  2. For each event: PCR' = H(PCR || event_digest)                 |
|  3. Compare final PCR values with quoted values                   |
|  4. Any mismatch indicates tampering                              |
|                                                                   |
+-------------------------------------------------------------------+
```

### Hierarchical Trust Propagation

| Level | Trust Anchor | Verification Method |
|-------|--------------|---------------------|
| Host | Hardware TPM | TPM quote with EK/AK chain |
| VM | Host attestation | swtpm quote bound to host |
| Container | VM/Host attestation | PCR 14 extension chain |

## Performance Characteristics

| Operation | Typical Latency | Notes |
|-----------|-----------------|-------|
| Quote generation | ~100ms | TPM 2.0 hardware operation |
| Quote verification | ~50ms | Signature verification + PCR compare |
| Event log replay | ~20ms per 1000 events | Linear in event count |
| Manifest generation | ~500ms per 100 workloads | Includes enumeration overhead |
| Policy evaluation | ~10ms | OPA Rego evaluation |
| PCR extension | ~5ms | Single TPM operation |
| Nonce generation | ~1ms | Cryptographic random |

### Scaling Considerations

```
Throughput Limits:
+-------------------------------------------------------------------+
|                                                                   |
|  TPM Operations:                                                  |
|  * Hardware TPM: ~10 quotes/second (hardware bound)               |
|  * swtpm: ~100 quotes/second (software emulation)                 |
|                                                                   |
|  Verification:                                                    |
|  * Single core: ~200 verifications/second                         |
|  * Multi-core: Linear scaling with worker count                   |
|                                                                   |
|  Manifest Generation:                                             |
|  * Small deployment (<10 workloads): <100ms                       |
|  * Medium deployment (10-100 workloads): <500ms                   |
|  * Large deployment (100-1000 workloads): ~5s                     |
|                                                                   |
+-------------------------------------------------------------------+
```

## Container Attestation

Container attestation uses an event-log based approach where PCR 14 holds an aggregate hash while a measurement log tracks individual container measurements.

### Why Event-Log Based Attestation

PCR registers can only be extended, never reset (except debug PCR 16). With multiple containers starting and stopping, direct PCR-per-container allocation is impossible. The event-log approach solves this by:

- Using PCR 14 as the **aggregate** hash of all container measurements
- Maintaining a **measurement log** that tracks individual container entries
- Enabling verification by replaying the log to reconstruct the expected PCR value

This follows the TCG (Trusted Computing Group) standard approach used by measured boot.

### Container Measurement Flow

```
Container Orchestrator        Measurement Log         TPM
        |                           |                  |
        | 1. Container Create       |                  |
        |-------------------------->|                  |
        |                           |                  |
        | 2. Compute measurements   |                  |
        |   - Hash image layers     |                  |
        |   - Hash container config |                  |
        |                           |                  |
        | 3. Append log entry       |                  |
        |-------------------------->|                  |
        |                           |                  |
        |                           | 4. Extend PCR 14 |
        |                           |----------------->|
        |                           |                  |
        |                           |   New PCR value  |
        |                           |<-----------------|
        |                           |                  |
        | 5. Return with entry      |                  |
        |<--------------------------|                  |
```

### Measurement Entry Types

| Event Type | Description |
|------------|-------------|
| CREATE | Container created with image and config hashes |
| START | Container execution started |
| STOP | Container execution stopped |
| REMOVE | Container removed from system |

### Integration with Container Orchestrator

The Container Orchestrator (`pkg/compute/container/`) integrates with the attestation system through:

1. **attestation.go** - TPM PCR 14 extension operations
2. **measurement_log.go** - Per-container measurement tracking

When the orchestrator creates, starts, stops, or removes a container:
- The appropriate measurement is computed
- PCR 14 is extended with the measurement hash
- The measurement log records the entry for verification

### Verification Process

Remote verifiers can validate container attestation by:

1. Requesting a TPM quote over PCR 14
2. Receiving the measurement log alongside the quote
3. Replaying the log to compute the expected PCR 14 value
4. Comparing the computed value with the quoted value
5. Extracting individual container measurements from the log

### Benefits

| Benefit | Description |
|---------|-------------|
| Unlimited containers | Single PCR supports any number of containers |
| Individual tracking | Each container measurement recoverable from log |
| Standard approach | Follows TCG measured boot patterns |
| Audit capability | Log can be persisted and audited |
| Remote verification | Verifier can validate any container in the log |

## Related Documentation

- [TPM Integration](../tpm/README.md) - TPM 2.0 device interaction and key management
- [Certificate Authority](../ca/README.md) - IDevID/IAK certificate issuance
- [Policy Engine](../policy/README.md) - OPA-based attestation policies
- [Workload Management](../workloads/README.md) - Container and VM lifecycle
- [Workload Attestation](workload-attestation.md) - Container measurement log details
- [Security Model](../security/README.md) - Platform security architecture
- [API Reference](../api/attestation.md) - Attestation API endpoints
