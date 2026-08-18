# Linux IMA — API

> **Status: NORMATIVE** · Scope: IMA capabilities on every transport · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING — docs/13 G7`, never omitted.

---

## 1. The one-line summary

**IMA has no service surface. Every capability is embedded-only.** Verified
2026-08-18: no REST route, no gRPC service or RPC, no QUIC opcode, no MCP tool,
and no `ServiceRegistry` field mentions IMA. Nothing in this repository even
imports `pkg/ima`.

That makes every non-embedded cell in every table below `MISSING`. The tables
exist anyway, because a capability documented on one transport tells the reader
nothing about whether the others exist — and because a recorded gap is a tracked
debt with an owner, while an omitted row is invisible work.

The six transports and the transport model itself are documented in
[`docs/daemon/api.md`](../daemon/api.md); the frame constants, status-byte
vocabulary and canonical QUIC opcode table live there and are not repeated.

---

## 2. Status and availability

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Report whether IMA is available on this system | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Reader).IsAvailable()` |
| Report whether securityfs is mounted | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Reader).IsSecurityFSMounted()` |
| Report IMA status | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Reader).GetStatus()` — **partial**, see below |
| Report the integrity-violation count | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Reader).ReadViolations()` |

`GetStatus` populates `Available`, `Enabled`, `PolicyLoaded`, `HashAlgorithm`,
`MeasurementCount` and `ViolationCount` (which is always 0). The other seven
`Status` fields are declared and never set —
[engineering.md](engineering.md) §2.5. Any future service that returns `Status`
verbatim would be publishing seven fields of misinformation; the gap must be
closed in `GetStatus` before it is exposed on a transport.

---

## 3. Measurement log

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Read and parse the ASCII measurement log | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Reader).ReadEventLog()` |
| Read the log from an explicit path | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Reader).ReadEventLogFromFile(path)` |
| Parse a log from an `io.Reader` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Reader).ParseEventLog(r)` |
| Parse a single event line | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Reader).ParseEvent(line)` |
| Find events by file path | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Reader).FindEventByPath(log, path)` |
| Find events by file hash | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Reader).FindEventByHash(log, hash)` |
| Compute measurement statistics | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Reader).GetStatistics(log)` |
| Read the **binary** measurement log | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | **PLANNED** — `ima.EventPaths.BinaryRuntime` names the path; nothing reads it |

**Pagination matters here and does not exist.** A measurement log on a busy node
is unbounded — tens of thousands of events, several megabytes. `ReadEventLog`
returns the whole thing in one slice. Any transport exposure of this capability
needs a cursor, and QUIC in particular caps payloads at `MaxPayloadSize`
(16 MiB), which a long-running node's log can exceed. Recorded now so it is a
design input rather than a production incident.

---

## 4. Policy

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Read the loaded IMA policy | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Reader).ReadPolicy()` |
| Read a policy from an explicit path | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Reader).ReadPolicyFromFile(path)` |
| Parse a policy from an `io.Reader` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Reader).ParsePolicy(r)` |
| Parse a single policy rule | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Reader).ParsePolicyRule(line)` |
| **Write / load an IMA policy** | `MISSING` | `MISSING` | `MISSING` | `MISSING` | **Deliberately absent** |

The last row is the one exception to "everything missing here is a gap". A
policy that can be replaced at runtime over the network invalidates every
measurement taken under it. The policy is generated at install time and its
selection lives in the signed UKI's kernel command line
([architecture.md](architecture.md) §6.2). `pkg/ima` writes nothing, and a
policy-write RPC would be a defect, not a feature.

---

## 5. Verification

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Verify a whole event log against an allowlist | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Verifier).VerifyEventLog(log)` |
| Verify one file's current hash against its measurement | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Verifier).VerifyFile(event)` |
| Verify an IMA file signature | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | **PLANNED** — `VerifySignature` is a presence check only ([engineering.md](engineering.md) §4.10) |
| Find files measured more than once | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Verifier).FindDuplicateMeasurements(log)` |
| Find files whose hash changed between measurements | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Verifier).FindModifiedFiles(log)` |
| Detect time gaps between measurements | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Verifier).DetectMeasurementGaps(log, maxGap)` — **always returns nil**; the ASCII log carries no timestamps |
| Hash a file | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Verifier).HashFile(path, alg)` / `HashFileToHex(path, alg)` |

---

## 6. Allowlists

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Set an allowlist at construction | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `ima.NewVerifier(ima.WithAllowlist(m))` |
| Add an entry | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Verifier).AddToAllowlist(path, hash)` |
| Add an algorithm-scoped entry | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Verifier).AddToAllowlistWithAlg(alg, path, hash)` — **stored and never read** |
| Remove an entry | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Verifier).RemoveFromAllowlist(path)` |
| Clear the allowlist | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Verifier).ClearAllowlist()` |
| Read the allowlist | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Verifier).GetAllowlist()` — returns a deep copy |
| Build an allowlist from a log | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Verifier).BuildAllowlistFromLog(log)` |

Allowlists are **in-memory per `Verifier` instance**. There is no persistence,
no distribution mechanism and no golden-allowlist store — an allowlist does not
survive the process that built it. That is the single largest thing standing
between this library and useful fleet-wide attestation.

---

## 7. PCR 10

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Compute the expected PCR 10 from a log | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Verifier).ComputePCR10(log, alg)` |
| Compare a computed PCR 10 to a supplied value | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Verifier).VerifyPCR10(log, expected, alg)` |
| Read PCR 10 from the TPM (sysfs) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Verifier).ReadPCR10FromTPM(bank)` / `…WithPath(tpmPath, bank)` |
| Verify a log against the TPM's PCR 10 | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Verifier).VerifyPCR10AgainstTPM(log, bank)` / `…WithPath(...)` |
| Report whether PCR 10 is readable | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Verifier).IsPCR10Available(bank)` / `…WithPath(...)` |
| Report whether a TPM is present | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Verifier).IsTPMAvailable()` / `…WithPath(...)` |
| List available PCR banks | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*ima.Verifier).GetAvailablePCRBanks()` / `…WithPath(...)` |
| **Produce a signed quote over PCR 10** | see below | see below | see below | see below | **not this feature** |

The last row is the important one. A sysfs PCR read is not attestation
([architecture.md](architecture.md) §6.5). Quotes are produced and verified by
[`docs/attestation/`](../attestation/), which **does** have a transport surface —
and which today has no IMA-specific field in its manifest and does not consume
`pkg/ima`. That integration is **PLANNED**.

---

## 8. Provisioning

Configuring IMA is not an API call. It is a declarative `os.ima.*` block in the
installer config, consumed once at install time
([engineering.md](engineering.md) §6). It reaches a node through the same
config-delivery path as everything else in the installer config — which *is* on
all six transports, documented in [`docs/provisioning/`](../provisioning/) — but
there is no IMA-shaped capability there, only "deliver this device's config".

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Change a node's IMA policy or appraise mode at runtime | `MISSING` | `MISSING` | `MISSING` | `MISSING` | **Deliberately absent** — the setting lives in the signed UKI's kernel command line and changing it means re-signing the boot image |

---

## 9. Authorization

There is nothing to authorize: no route, no RPC, no tool name, therefore no
`scp` permission and no MCP authorization-map entry.

When this surface is built, the scoping question to settle first is that a
measurement log is a **complete inventory of every binary the node has
executed**. It is not secret, but it is high-value reconnaissance, and reading
it should require an explicit read permission rather than falling through
`AuthorizeTool`'s allow-if-absent default on MCP.

---

## 10. Versioning and deprecation

Nothing to version — the feature has no routes. `pkg/ima`'s exported Go surface
is the only contract, and no part of it is deprecated. The fields marked
"NEVER SET" in [engineering.md](engineering.md) §2.5 are latent breaking changes
in waiting: populating them is a behaviour change for any caller that has
learned to treat them as zero.

---

## 11. Related

- [architecture.md](architecture.md) — trust boundaries and the PCR-replay caveat
- [engineering.md](engineering.md) — the exported surface in full
- [cli.md](cli.md) — why there are no verbs, and what to run instead
- [`docs/daemon/api.md`](../daemon/api.md) — the transport model
- [`docs/attestation/`](../attestation/) — the consumer this feature is not yet
  wired to
- [`docs/firmware/api.md`](../firmware/api.md) — the boot-time half, which has
  exactly one capability on all six transports
