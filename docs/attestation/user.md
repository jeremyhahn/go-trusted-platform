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
      #   - cp.trusted-platform.internal
      # allowlist:                       # for strategy: allowlist
      #   - reporting-01.trusted-platform.internal
      # ca-file: /etc/trusted-platform/heartbeat/cp-ca.pem
```

With nothing set, the node admits the control plane it enrolled against (the
host of `acme.client.directory`) and trusts the CA in `heartbeat.ca-file`, or
failing that the root that issued its IDevID. Check what is actually enforced
with:

```
GET /api/v1/attestation/callers
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
