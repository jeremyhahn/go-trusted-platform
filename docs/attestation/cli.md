# Attestation — CLI

> **Status: NORMATIVE** · Scope: attestation verbs in `platformctl` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.

---

## 1. There is no `platformctl attestation` command group

Read that before looking for one. `pkg/cli/commands/` has no `attestation`
directory, and `pkg/cli/commands/root.go` registers no attestation group among
its 41 top-level commands (verified 2026-08-18).

Attestation reaches the CLI through exactly **one** verb —
`platformctl container attest` — plus the TPM primitives the attestation stack
sits on. Everything else in the feature (manifests, quotes, host attestation, VM
attestation, reports, policies) is reachable only through the SDK, REST, gRPC,
QUIC or MCP. See [api.md](api.md) for what each transport carries.

**This is a gap, not a design decision.** Attestation is a Tier 1 platform
capability; a capability with no CLI cannot be exercised or debugged by an
operator at a shell. It is raised in the migration report as an owner question:
whether to build `platformctl attestation` or to record the omission
deliberately.

---

## 2. Global flags

`platformctl` persistent flags (`pkg/cli/commands/root.go:125`) apply to every
verb below. Precedence is **flag > environment > config file > built-in
default**.

| Flag | Short | Default | Environment |
|---|---|---|---|
| `--config` | `-c` | platform default | `PLATFORMCTL_CONFIG` |
| `--context` | | current-context | `PLATFORMCTL_CONTEXT` |
| `--transport` | | from context | `PLATFORMCTL_TRANSPORT` (`unix`, `grpc`, `rest`, `quic`, `mcp`, `embedded`) |
| `--server` | | from context | `PLATFORMCTL_SERVER` |
| `--server-name` | | | `PLATFORMCTL_SERVER_NAME` |
| `--output` | `-o` | `table` | `PLATFORMCTL_OUTPUT` (`table`, `json`, `yaml`) |
| `--verbose` | `-v` | `false` | |
| `--no-color` | | `false` | `NO_COLOR` |

---

## 3. `platformctl container attest <container-id>`

Attest container integrity. This is the whole attestation CLI surface.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--nonce` | string | generated | Hex-encoded nonce for anti-replay. Generated if not provided. |
| `--pcrs` | string | all configured | Comma-separated PCR indices to include |

```bash
# Let the CLI generate the nonce — the normal case.
platformctl container attest 7f3a9c21b804 --output json

# Supply your own nonce when a remote verifier issued it.
platformctl container attest 7f3a9c21b804 \
    --nonce 9f86d081884c7d659a2feaa0c55ad015 \
    --pcrs 0,1,7,14
```

**Supply `--nonce` only when something else issued it.** The generated nonce is
fresh per invocation, which is what you want for a local check. Reusing a nonce
across invocations defeats the replay control the attestation depends on
(`ErrNonceMismatch`, [engineering.md](engineering.md) §3).

`--pcrs` narrows the quote. Omit it to get the platform's configured
`attestation.quote-pcrs` set. PCR **14** is the platform's default workload PCR;
PCR **10** is the kernel IMA log PCR. They are different things — see
[engineering.md](engineering.md) §8.

Requires a reachable daemon on the selected transport. `--transport embedded`
runs the services in-process.

---

## 4. TPM primitives the attestation stack sits on

These belong to the TPM feature ([`docs/tpm/`](../tpm/)), not to attestation,
but they are what you reach for when an attestation result needs explaining:

| Verb | Why it matters here |
|---|---|
| `platformctl tpm eventlog` | The measured-boot event log behind a host manifest |
| `platformctl tpm extend` | Extends a PCR — the operation workload measurement performs |
| `platformctl tpm seal` / `unseal` | PCR-bound sealing; the same PCR policy attestation checks |
| `platformctl tpm status` / `info` | Whether the TPM is present and provisioned at all |
| `platformctl tpm ek` / `srk` / `iak` / `idevid` | The key hierarchy an attestation identity is rooted in |

When a quote fails to verify, the ordering to work through is: `tpm status`
(is there a TPM), `tpm eventlog` (what did it measure), then re-run the attest.

---

## 5. What has no CLI

Recorded explicitly so the next agent does not go looking:

| Capability | Reachable via |
|---|---|
| Build / verify / list / delete manifests | REST, gRPC, QUIC, MCP, SDK |
| Get / verify a quote | REST, gRPC, QUIC, SDK |
| Collect host attestation | REST, gRPC, QUIC, SDK |
| Collect VM attestation | REST, gRPC, QUIC, SDK |
| Attestation reports (workload) | QUIC, MCP |
| Device attestation reports, refresh trigger, caller policy (#226) | REST, gRPC, Unix, MCP — no `platformctl` verb; follow-up filed from PR b |
| Attestation policies | QUIC, MCP |
| Attestation events | REST |

---

## 6. Parity gap

`conventions/feature-docs.md` §4 requires every verb here to have a
`CommandDefinition` in the integration parity suite. **This repository defines no
`CommandDefinition` type** (grepped repo-wide, 2026-08-18), so the requirement is
unmet repo-wide. Raised as an owner question in the migration report rather than
marked satisfied.
