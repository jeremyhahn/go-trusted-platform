# Attestation — CLI

> **Status: NORMATIVE** · Scope: attestation verbs in `platformctl` · Last verified: 2026-09-05
> Conflicts with this document are defects. Fix them here first.

---

## 1. What `platformctl attestation` covers

`platformctl attestation` (`pkg/cli/commands/attestation/`, registered in
`pkg/cli/commands/root.go`) is the **reporting** surface only: the control
plane's cached device verdicts, the out-of-cycle refresh trigger, and a node's
caller-admission policy (#226, #429). None of its verbs reaches a device; they
read the reporting cache or enqueue work with the collector, exactly like the
REST, gRPC/Unix and MCP routes they sit on ([api.md](api.md) §5.3).

Everything else in the feature (manifests, quotes, host and VM attestation,
workload reports, policies, events) still has no verb beyond
`platformctl container attest` (§4). That remains a gap, not a design decision:
attestation is a Tier 1 capability, and a capability with no CLI cannot be
exercised or debugged by an operator at a shell. §6 lists what is missing.

---

## 2. Global flags

`platformctl` persistent flags (`pkg/cli/commands/root.go`) apply to every
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

The reporting verbs work over the Unix socket as root on a node (no token; the
socket is the credential) and over REST or gRPC with a context whose token
carries the admin role (REST) or `attestation:read` / `attestation:write`
(MCP). **QUIC does not carry them** (#386): `--transport quic` fails with
`Unimplemented` rather than pretending.

---

## 3. Reporting verbs

### 3.1 `platformctl attestation reports list`

Every cached device report, ordered by device id. One row per device:

```
DEVICE   SERIAL   VERDICT        FRESH   AGE      BASELINE   COLLECTED
9        SN-9     verified       fresh   42s      signed     2026-09-05T12:00:01Z
12       SN-12    failed         stale   1h2m5s   tofu       2026-09-05T12:00:01Z
15       SN-15    not verified   fresh   42s      -          2026-09-05T12:00:01Z
```

`VERDICT` is never printed without `FRESH` and `AGE` beside it: a verified
report that is hours old says less than it appears to. The three labels are the
console's — `verified`; `failed` when a check ran and failed (`cryptographic_failure`,
the only kind that quarantines); `not verified` when a check could not run
(no AK certificate on record, for instance). `BASELINE` is the PCR baseline
the verdict rests on, `signed` or `tofu`; a TOFU pass is a weaker claim than a
signed-manifest pass and must not be read the same way. `-` means no baseline
was evaluated.

`-o json` prints `{"reports": [...], "count": n}` with each report in the
wire shape (`reporting.View`, [api.md](api.md) §5.3) unchanged; `-o yaml` the
same. An empty cache prints an informational line in table mode and
`{"reports": [], "count": 0}` otherwise.

### 3.2 `platformctl attestation reports get <device-id>`

One device's full report. `<device-id>` is the platform's numeric device id;
anything that is not a positive decimal integer is refused with
`ErrInvalidDeviceID` **before** any connection is made.

```
Device: 12
Serial: SN-12
Model: X10SDV-TLN4F
Verdict: failed (stale, age 1h2m5s)
AK certificate verified: yes
Signature valid: yes
Nonce valid: yes
PCRs valid: no
Cryptographic failure: yes
PCR baseline: tofu, captured on this collection
Device clock: UNSYNCED
Status: failed
Message: PCR 7 does not match the baseline
Attested at: 2026-09-05T12:00:00Z
Collected at: 2026-09-05T12:00:01Z
As of: 2026-09-05T12:00:43Z
```

The `Verdict` line is the only place a verdict appears, and it always carries
the freshness and age. `Attested at` is the verifier's timestamp, `Collected at`
the collector's, `As of` the instant the age was computed. `-o json|yaml` print
the wire shape unchanged, with `verified`, `fresh`, `age_seconds` and
`cryptographic_failure` present even when false or zero.

`Device clock` is that node's own clock trust state at collection, and it has
three values, never two: `synced`, `UNSYNCED`, and `unknown` when the device
did not report one. `unknown` is not an accusation — the collector could not
read the state, which says nothing about the clock. In `-o json|yaml` the
field is `time_synced` and it is **omitted entirely** in the unknown case, so
a script must test for presence rather than truthiness. The fleet table
carries the same value in a `CLOCK` column (#509).

**Never collected is its own state.** A device the collector has never reached
has no report. The verb prints nothing on stdout in any format and exits
non-zero with `ErrNeverCollected`:

```
device 9 has never been collected: no attestation report exists yet. This is
not a negative verdict; check that the device has a dialable address (a
platform DNS record or an authenticated heartbeat) and that the node admits
this control plane (platformctl attestation callers)
```

It is never rendered as `failed` or `not verified`, and `-o json` never
fabricates a report with `verified: false`. The transports signal the state as
`404` / `NotFound`; over MCP, whose server collapses every tool error to
`InternalError`, the Go SDK recognises it by the server's message
(`no report has been collected for device`) — see [api.md](api.md) §5.3.

### 3.3 `platformctl attestation reports refresh <device-id>`

Enqueue an out-of-cycle collection. The command returns as soon as the
collector has accepted the request and prints only that:

```
Device: 9
Enqueued: yes
Note: collection enqueued with the collector; read the report for the verdict and its age
```

It never waits for, and never prints, a quote or a verdict. The collector
applies its own TTL, coalescing and per-device serialization, so pressing this
twice cannot put two quote requests on one TPM. Read the report again
(`reports get`) for the new verdict and its age. `-o json` prints
`{"device_id": "9", "enqueued": true, "note": "..."}`. A refresh the collector
did not accept (collector stopped, device unknown, reporting not configured on
this node) is `ErrRefreshFailed` with the server's reason.

### 3.4 `platformctl attestation callers`

The node's compiled caller-admission policy: which callers this node lets
collect its quotes through `POST /api/v1/attestation/host`.

```
Strategy: identity-list
Admits nobody: no
Identities: cp.trusted-platform.internal
Identities source: attestation.callers.identities
Identity list valid: yes
Trust anchors configured: yes
Anchor source: platform-anchor
Attested peers available: no
```

Run it on a node whose report the control plane cannot collect. `Admits nobody:
yes` is the usual reason a device is never collected: an unparseable identity
list (`Invalid entries` names the offenders), no trust anchors, or
`any-attested` on a node with no attested-peer evidence. `-o json|yaml` print
the wire shape (`calleradmission.Description`) unchanged.

### 3.5 Errors

Every failure is a typed error in `pkg/cli/commands/attestation/errors.go`:

| Error | When |
|---|---|
| `ErrInvalidDeviceID` | the argument is not a positive decimal integer; raised before connecting |
| `ErrNeverCollected` | `reports get` on a device with no report (`NotFound`); not a verdict |
| `ErrListReportsFailed`, `ErrGetReportFailed`, `ErrRefreshFailed`, `ErrDescribeCallersFailed` | the transport or server refused; the message carries the server's reason (admin role required, reporting not configured on this node, collector stopped, …) |

Nothing is printed on stdout when a verb fails, so `-o json` output is either
the wire shape or absent.

### 3.6 Go SDK

The verbs are thin: `sdk/go/services/attestation.Client` gained
`ListDeviceReports`, `GetDeviceReport`, `RefreshDeviceReport` and
`DescribeCallerPolicy` (#429), returning the pb messages from
`pkg/api/grpc/proto/attestation.proto`. `GetDeviceReport` returns
`*ErrNoDeviceReport` for the never-collected state on every transport. The
REST adapter (`sdk/go/transport/rest/attestation_reports.go`) routes the four
methods to their `/api/v1/attestation/...` paths and decodes the webservice's
bare `reporting.View` / `Description` payloads onto the pb replies; the MCP
adapter (`sdk/go/transport/mcp/attestation_reports.go`) maps them to the four
`attestation_*` tools and does the same. Consumers that want the wire shape as
a Go value convert with the CLI's `viewFromProto` pattern (the inverse of the
daemon's `viewToProto`).

---

## 4. `platformctl container attest <container-id>`

Attest container integrity. This is the whole non-reporting attestation CLI
surface.

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

## 5. TPM primitives the attestation stack sits on

These belong to the TPM feature ([`docs/tpm/`](../tpm/)), not to attestation,
but they are what you reach for when an attestation result needs explaining:

| Verb | Why it matters here |
|---|---|
| `platformctl tpm eventlog` | The measured-boot event log behind a host manifest |
| `platformctl tpm extend` | Extends a PCR — the operation workload measurement performs |
| `platformctl tpm seal` / `unseal` | PCR-bound sealing; the same PCR policy attestation checks |
| `platformctl tpm status` / `info` | Whether the TPM is present and provisioned at all |
| `platformctl tpm ek` / `srk` / `iak` / `idevid` | The key hierarchy an attestation identity is rooted in |
| `platformctl device attest-cert record` | Records the AK certificate a device's verdict is verified against ([device/cli.md](../device/cli.md)) |

When a device's verdict fails to verify, the ordering to work through is:
`attestation reports get` (which check failed, and was it cryptographic),
`attestation callers` on the node (does it admit this control plane), then on
the node `tpm status` (is there a TPM) and `tpm eventlog` (what did it
measure), then `attestation reports refresh` and read again.

---

## 6. What has no CLI

Recorded explicitly so the next agent does not go looking:

| Capability | Reachable via |
|---|---|
| Build / verify / list / delete manifests | REST, gRPC, QUIC, MCP, SDK |
| Get / verify a quote | REST, gRPC, QUIC, SDK |
| Collect host attestation | REST, gRPC, QUIC, SDK |
| Collect VM attestation | REST, gRPC, QUIC, SDK |
| Attestation reports (workload) | QUIC, MCP |
| Attestation policies | QUIC, MCP |
| Attestation events | REST |

Device attestation reports, the refresh trigger and the caller policy (#226)
left this table with #429 (§3).

---

## 7. Parity gap

`conventions/feature-docs.md` §4 requires every verb here to have a
`CommandDefinition` in the integration parity suite. **This repository defines no
`CommandDefinition` type** (grepped repo-wide, 2026-08-18), so the requirement is
unmet repo-wide. Raised as an owner question in the migration report rather than
marked satisfied. The reporting verbs' behaviour is pinned by the unit suite in
`pkg/cli/commands/attestation/` (success and failure per verb against a fake SDK
client, table goldens under `testdata/`, and the never-collected mutation check);
the multi-protocol integration exercise in `test/integration/attestation/` is
#429's remaining verification item.
