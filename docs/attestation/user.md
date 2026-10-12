# Attestation — Using It

> **Status: REFERENCE** · Last verified: 2026-08-18
> What an operator does with attestation, in the order they do it. Package names
> and internals are in [engineering.md](engineering.md).

---

## What this is

Attestation is how the platform answers "is this machine still the machine we
enrolled, running what we expect?" — with evidence from a TPM rather than with
an assertion from the machine itself.

Three things get attested, in a strict order:

1. **The host.** Its measured boot chain, captured as a *host manifest*.
2. **VMs on that host**, each against its own virtual TPM.
3. **Containers on that host**, measured into a platform PCR as they start.

The ordering is enforced, not conventional: a host that has not attested cannot
vouch for anything running on it.

The result is used elsewhere — it is the only way to authenticate to the
container registry, and it gates whether a workload is admitted at all.

---

## Prerequisites

1. **A TPM, provisioned.** `platformctl tpm status` should report a present,
   provisioned device. Without one there is nothing to attest with.
2. **Attestation configured and enabled** in the platform config. The keys are
   listed in [engineering.md](engineering.md) §5; the two that decide whether
   anything happens are `attestation.workload.enabled` and
   `attestation.policy.policy-dir`.
3. **A policy directory.** If `attestation.policy.engine` is set but
   `policy-dir` is empty, the platform refuses to start — deliberately, because
   a policy engine with no policies would evaluate everything against nothing.
4. **Synchronised time.** Quotes expire. Clock drift shows up as attestation
   failures that look like tampering.

---

## Understanding the default posture

Before trusting a deployment, confirm three settings:

- **`attestation.policy.default-action`** should be `deny`. That is the built-in
  default and it is what makes the system fail closed. If it reads `allow`,
  every workload that no policy matches is admitted.
- **`attestation.allow-open-enrollment`** should be `false`. True means devices
  can enroll without prior authorisation.
- **`attestation.allow-attestor-self-ca`** should be `false`. True lets an
  attestor vouch for its own identity, which removes the point of an external
  CA.

All three default to the safe value. Any of them flipped is a deliberate choice
someone made, and worth understanding before you rely on the deployment.

---

## Attesting a container

The one thing you can do from a shell:

```bash
platformctl container attest 7f3a9c21b804 --output json
```

The CLI generates a fresh nonce each time. Supply `--nonce` only when a remote
verifier issued one and expects it echoed back:

```bash
platformctl container attest 7f3a9c21b804 \
    --nonce 9f86d081884c7d659a2feaa0c55ad015 \
    --pcrs 0,1,7,14
```

Everything else — host manifests, quotes, VM attestation, policies, reports —
is API-only today. [cli.md](cli.md) §5 lists which transport carries what.

---

## Working with manifests over the API

A host manifest is the record of what a host measured. The normal cycle:

1. **Build** it: `POST /api/v1/attestation/manifests/build`
2. **Verify** it: `POST /api/v1/attestation/manifests/verify`
3. **List** what is stored: `GET /api/v1/attestation/manifests`
4. **Fetch** one: `GET /api/v1/attestation/manifests/{id}`

Manifests can be pushed to remote verifiers on a schedule rather than pulled.
That is `attestation.manifest.push-enabled`, with `push-interval` and
`push-targets`. Use it when verifiers should learn about drift without polling
every host.

---

## Reading an attestation failure

The error tells you which control tripped. Work through them in this order:

**"PCR mismatch", with indices and values.**
A measurement changed. Something in the boot chain or the workload is not what
policy expects. The failure carries the expected and actual value **per PCR
index** — read which index moved before doing anything else. A firmware update,
a kernel change or a bootloader change moves early PCRs legitimately; a changed
workload moves the workload PCR (default **14**).

Do not widen the policy to make the error go away until you know which of those
happened. Widening a golden-PCR policy to accommodate an unexplained change is
how attestation stops meaning anything.

**"Quote expired" or "nonce mismatch".**
Freshness, not integrity. Almost always clock drift, occasionally a nonce being
reused across calls. Check time synchronisation first.

**"Host not attested" or "host binding invalid".**
You tried to attest a VM or container before its host attested. Attest the host
first.

**"Merkle root mismatch".**
The workload measurement chain does not hash to the recorded root. This is the
serious one: it means the log was modified, not that a measurement is
unexpected. Treat it as an incident, not a configuration problem.

**"Chain not initialised".**
Workload attestation was enabled but the chain was never started — usually a
daemon that came up before workload attestation was configured. Restart with the
configuration in place.

**"AK not found" / "AIK not found".**
No attestation identity key. The node was never enrolled, or it was
re-provisioned and lost its key. Both spellings appear, for the same concept.

**Everything returns 503.**
The attestation service is not wired into the daemon. Configuration, not a
crash.

---

## IMA, and the two PCRs

Linux IMA measures files as the kernel opens them, extending **PCR 10**. The
platform reads and verifies that log separately from its own workload
measurements, which extend a **configurable** PCR (default **14**).

These get confused constantly. If you are reading kernel file measurements, that
is PCR 10 and it is fixed. If you are reading platform workload measurements,
that is `attestation.workload.pcr` and you can change it. Changing the workload
PCR invalidates every golden policy that named the old one.

---

## Reading a device's attestation report

The control plane's collector dials every enrolled device on a schedule
(`attestation.reporting.interval`, 15 minutes by default), verifies the quote
it gets back, and serves the **cached** verdict. Read it from a shell on the
control plane (Unix socket as root) or with a context that carries the admin
role:

```bash
platformctl attestation reports list          # the fleet, one row per device
platformctl attestation reports get <device-id>   # one device's full report
```

Both verbs sit on `GET /api/v1/attestation/reports[/{device_id}]` and the
matching gRPC/Unix and MCP routes ([api.md](api.md) §5.3); `-o json` prints
the wire shape unchanged.

Read three things together, never one alone — the table prints them on one
line for exactly that reason (`Verdict: verified (fresh, age 42s)`):

- **`verified`** — the verdict, with `signature_valid`, `nonce_valid`,
  `pcrs_valid` and `ak_certificate_verified` saying which check failed, and
  `cryptographic_failure` saying whether a check ran and failed (the only kind
  that quarantines; the table says `failed`) or could not run (`not verified`).
- **`fresh` and `age_seconds`** — how old the evidence is. A report past its
  TTL is kept and served as `stale`; expiry means the evidence is old, not that
  the device has none.
- **`pcr_baseline_source`** — `signed` or `tofu`. A TOFU pass is a weaker
  claim than a signed-manifest pass and must not be read the same way.
- **`time_synced`** — whether that node can place itself in time. A verified
  quote from a node whose clock is wrong is still a weaker statement than the
  same quote from a node whose clock is right: the node's own certificate
  windows, DANE signature windows and token checks all run on its clock. The
  table prints `synced`, `UNSYNCED` or `unknown`, and `unknown` means the
  collector could not read the state — it is not a claim about the clock. In
  JSON the field is absent in that case. An `UNSYNCED` node is a
  time-synchronization problem, not an attestation one; see
  [`docs/ntp/user.md`](../ntp/user.md).

`reports get` on a device the collector has **never collected** prints no
report and exits non-zero saying so (the API answers `404`). That is not a
failed attestation — check the device has a dialable address (a platform DNS
record or an authenticated heartbeat) and that the node admits this control
plane (next section).

To refresh out of cycle:

```bash
platformctl attestation reports refresh <device-id>   # prints "Enqueued: yes"
platformctl attestation reports get <device-id>       # then read the new age
```

The refresh enqueues collection with the collector (`POST
…/reports/{device_id}/refresh`, `202`); it does not wait for, or return, a
quote. Read the report again for the new verdict and its age. Repeated
refreshes coalesce into one collection per device, so pressing the button
twice cannot put two quote requests on one TPM.

### In the console

The Devices page shows every device's verdict **beside its age** in an
Attestation column — `Verified`, `Failed` (a check ran and failed) or
`Not verified` (a check could not run), with `stale` marked when the evidence
is past the collector TTL. A device the collector has never reached shows
`Never collected`, which is neither green nor red; a node without the
reporting service says `Reporting not configured` instead of showing every
device as never collected. The row menu's **Refresh attestation** is the
`POST …/refresh` above: it enqueues, the console re-reads the fleet, and the
age moves when the collector has been.

The device detail page carries the full report: the four checks, whether a
failure was cryptographic or a check that could not run, the baseline source
(`Signed baseline` and `TOFU baseline` render differently) with its age, the
verifier's and collector's timestamps, and the same Refresh control. It also
shows **Last heartbeat from** — the `last_heartbeat_addr` the collector will
dial when platform DNS has no record for the device. The JS SDK exposes the
routes as `AttestationService.listDeviceReports / getDeviceReport /
refreshDeviceReport / describeCallers`, and `classifyDeviceReport()` turns a
report response into the four states above so no page decides on its own
what a 404 means.

## The control plane appears in its own fleet

The control plane registers itself as a device in its own registry on every
start where `attestation.reporting.enabled` is true (#472), reading its own
EK, IAK and IDevID material out of its own TPM. It then appears in
`platformctl device list`, in the console's Devices page, and in
`attestation reports list` exactly like a node — same columns, same verdict,
same age. There is no separate "control plane health" view, deliberately: a
verdict the control plane produced about itself through a different code path
would be a different claim.

Find it by the hostname its IDevID certificate carries:

```bash
platformctl device list                 # the control plane is one of the rows
platformctl attestation reports get <control-plane-device-id>
```

Two things to know when reading it:

- **The collector reaches the control plane over loopback.** It does not need
  a platform DNS record or a heartbeat for itself, and the certificate it
  verifies is its own webservice certificate — the listener named by
  `attestation.reporting.collector.identity`, or the primary webservice.
- **The control plane must admit itself.** The collector goes through the same
  caller-admission policy as on any node, so the derived or configured
  `reporting-servers` identity set has to name the control plane's own
  certificate name. `platformctl attestation callers` prints the effective
  policy; if you replaced the derived list, the control plane's own name has
  to be on the replacement, or its own report reads `Never collected` while
  every node's is fine.

Bind a profile to it once, the same step every enrolled device needs, so the
verifier has a PCR baseline and the collector a `tls-server-name` if the
control plane's certificate carries a role name rather than its FQDN:

```bash
platformctl device profile assign <profile-id> --device <control-plane-device-id>
```

Nodes do **not** yet verify the control plane in return. That is the mutual
half of the design and lands with the channel-bound attested-peer primitive
(#482); until then a node takes the control plane's identity on its
certificate and its state on nothing.

## After the CA upgrade: record the certificate, then read the next verdict

A device enrolled before the control plane recorded attestation certificates
at enrollment has no `attest_cert` on its record. Its report says
`ak_certificate_verified: false` with `cryptographic_failure: false` — the
check could not run — and the console shows **no AK certificate**. The device
is denied, not quarantined, and nothing changes on its own.

The certificates the fleet's CA issued at enrollment (2026-08-31) chain to
the CA but do **not** carry `tcg-cap-verifiedTPMRestricted`
(2.23.133.11.1.3). Do not try to backfill one of those by hand: the verifier
classifies a chained certificate without the attribute as a *cryptographic*
failure, which quarantines. The control plane refuses to record such a
certificate for exactly that reason.

Once the platform CA stamps the attribute (go-xkms ≥ 0.9.3 reached through
go-quicbaas), record each device's certificate without re-enrolling it:

```bash
# record what the CA holds for the device; refused unless it chains, carries
# .3 and certifies the device's enrolled attestation key
platformctl device attest-cert record <device-id>

# the CA lost the enrollment-time IAK record (go-xkms#371): let it issue a
# fresh certificate over the device's enrolled attestation public key
platformctl device attest-cert record <device-id> --reissue
```

A device that already holds a certificate without `.3` (for example, one
recorded before the preflight existed) is quarantined by every quote. If no
compliant certificate can be recorded yet, clear the refused one:

```bash
# when every candidate is refused, clear the stored certificate instead of
# keeping it; the next quote is then an absence (denied), not a
# cryptographic failure (quarantine)
platformctl device attest-cert record <device-id> --clear-on-refusal
```

The flag is off by default, never clears a compliant certificate, and clears
nothing on any other error. Record a compliant certificate later the usual
way.

Then either wait for the collector's next sweep or enqueue one with
`platformctl attestation reports refresh <device-id>`, and read the report
again with `platformctl attestation reports get <device-id>`:
`ak_certificate_verified` turns true and, with a good quote, the verdict
passes. The record itself is audited as `device_attest_cert_recorded`
(or `device_attest_cert_refused`, with the reason, or
`device_attest_cert_cleared`, with the refusal that caused the clear) in the
attestation event log; it is never a verdict, so it never quarantines or
releases a device by itself. After a clear, the collector's next sweep
reports the device as having no certificate (denied) instead of a
cryptographic failure. Full semantics and the transport surface:
[device/api.md §4.5](../device/api.md#45-recording-the-attestation-certificate-without-re-enrolling-473).

## Naming the certificate the collector verifies

The collector verifies each node's webservice certificate against the
device's own FQDN (`<hostname>.<internal zone>`). Fleets built from the
shipped templates serve a **role** name instead — every worker presents
`CN=compute.<domain>.internal` — so the collector cannot match and refuses
to dial:

```
device has no hostname and its profile sets no tls-server-name; there is no name to verify the node's certificate against
```

Put the name the nodes actually serve on the device **profile**, and make
sure the collector can find that profile from the device. The collector and
the quote verifier share one resolver (`FindProfileForDevice`): the profile
**bound** to the device's EK identity first, else a profile whose **match
rules** cover the device's serial and model, else nothing — and nothing means
no server name and no PCR baseline. Installer-created profiles carry no match
rules and no binding, so bind each enrolled device to its profile explicitly.
From the control plane over the Unix socket:

```bash
# find the profile and device ids
platformctl --transport unix --server /run/platformd.sock device profile list
platformctl --transport unix --server /run/platformd.sock device list

# bind each enrolled device to its profile: the control plane derives the EK
# serial from the device's stored EK certificate and prestages it
platformctl --transport unix --server /run/platformd.sock \
    device profile assign <compute-profile-id> --device <node-05-device-id>
platformctl --transport unix --server /run/platformd.sock \
    device profile assign <gateway-profile-id> --device <gw-01-device-id>

platformctl --transport unix --server /run/platformd.sock \
    device profile update <compute-profile-id> \
    --tls-server-name compute.example.internal

platformctl --transport unix --server /run/platformd.sock \
    device profile update <gateway-profile-id> \
    --tls-server-name gw.example.internal

# confirm: EK Serial / Assigned = true and the TLS Server Name row
# (ek_serial, assigned, tls_server_name in --output json)
platformctl --transport unix --server /run/platformd.sock device profile get <compute-profile-id>
```

A device whose record carries no EK certificate cannot be bound this way; give
`assign` an explicit `--ek-serial` or `--mac` instead. The `--tls-server-name`
flag also exists on `device profile create`. The setting is per profile,
applies at the next collection, and survives later profile edits that do not
name it — the server keeps the stored value when an update omits it. Leave it
unset for profiles whose nodes are issued their own device name. The
collector's log names the failure when resolution still finds nothing:
`no device profile is bound to or matches this device`.

## Who may ask this node for a quote

A TPM quote is expensive and its PCR values are a description of the machine, so
the two routes that produce one (`POST /api/v1/attestation/host` and
`/attestation/quote`) admit exactly two kinds of caller: an operator with the
admin role, or a machine whose client certificate chains to this node's
configured anchors and whose name the node's **caller policy** accepts.

The policy is `attestation.reporting.callers` in the node's config:

```yaml
attestation:
  reporting:
    callers:
      strategy: reporting-servers        # default; or any-attested, allowlist
      # reporting-servers:               # replaces the derived default
      #   - cp.example.internal
      # allowlist:                       # for strategy: allowlist
      #   - reporting-01.example.internal
      # ca-file: /etc/trusted-platform/heartbeat/cp-ca.pem
```

With nothing set, the node admits the control plane it enrolled against (the
host of `acme.client.directory`) and trusts the CA in `heartbeat.ca-file`, or
failing that the platform anchor — the root that issued its IDevID, reported as
anchor source `platform-anchor`. Check what is actually enforced
on the node:

```bash
platformctl attestation callers          # GET /api/v1/attestation/callers
```

which reports the strategy, the effective identity list and where it came
from, the anchor source, and `admits_nobody` — true whenever the compiled
policy cannot admit any caller (no anchors, an empty or unparseable list, or
`any-attested` on a node with no attested-peer evidence). Every admission and
every refusal is in the attestation event log as `caller_admitted` or
`caller_refused`; a refusal whose `security_relevant` metadata is `true` means a
peer proved its identity and was refused on its measured state.

## Where to go next

- [cli.md](cli.md) — what the CLI can and cannot do
- [api.md](api.md) — every capability on every transport, including the gaps
- [architecture.md](architecture.md) — how host, VM and container attestation compose
- [`docs/registry/`](../registry/) — the feature that consumes attestation as authentication
- [`docs/tpm/`](../tpm/), [`docs/vtpm/`](../vtpm/), [`docs/ima/`](../ima/)
