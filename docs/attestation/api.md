# Attestation — API

> **Status: NORMATIVE** · Scope: attestation routes on every transport · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING`, never omitted.

---

## 1. The six transports

`sdk/go/protocol.go` declares exactly six: `ProtocolEmbedded`, `ProtocolUnix`,
`ProtocolGRPC`, `ProtocolREST`, `ProtocolQUIC`, `ProtocolMCP`.

**Unix is gRPC over a Unix domain socket** (`sdk/go/transport/unix/adapter.go`),
so every RPC in the gRPC column is available on Unix under the same name; the
two share a column below. `ServiceRegistry.Attestation`
(`sdk/go/transport/embedded/adapter.go:43`) holds a
`platformv1.AttestationServiceServer`, so embedded carries the whole service.

---

## 2. Capability matrix

gRPC: `AttestationService` in `pkg/api/grpc/proto/attestation.proto` — ten RPCs.
REST: `pkg/webservice/v1/rest/attestation/` (`server_router.go`,
`events_router.go`, and a second legacy router — see §3).
QUIC: `pkg/api/quic/attestation_handlers.go` plus the base range in
`sdk/go/wire/quicwire/protocol.go`, routed by the daemon for opcodes `0x70`–`0x77`
(`pkg/api/daemon/quic_service.go:522`).
MCP: fifteen `attestation_*` tools.

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| List manifests | `GET /api/v1/attestation/manifests` | `ListManifests` | `MISSING — docs/13 G7` | `attestation_list_manifests` | ✅ |
| Get manifest | `GET /api/v1/attestation/manifests/{id}` | `GetManifest` | `OpAttestGetManifest` (`0x76`) | `attestation_get_manifest` | ✅ |
| Build manifest | `POST /api/v1/attestation/manifests/build` | `BuildManifest` | `OpAttestBuildManifest` (`0x7C`) | `attestation_create_manifest` | ✅ |
| Verify manifest | `POST /api/v1/attestation/manifests/verify` | `VerifyManifest` | `OpAttestVerifyManifest` (`0x7D`) | `attestation_verify_manifest` | ✅ |
| Delete manifest | `DELETE /api/v1/attestation/manifests/{id}` | `DeleteManifest` | `MISSING — docs/13 G7` | `attestation_delete_manifest` | ✅ |
| Get quote | `POST /api/v1/attestation/quote` | `GetAttestationQuote` | `OpAttestQuote` (`0x70`) | `MISSING — docs/13 G7` | ✅ |
| Verify quote | `POST /api/v1/attestation/quote/verify` | `VerifyAttestationQuote` | `OpAttestVerify` (`0x71`) | `MISSING — docs/13 G7` | ✅ |
| Collect host attestation | `POST /api/v1/attestation/host` | `CollectHostAttestation` | `OpAttestHost` (`0x7E`), `OpAttestCollectHost` (`0x72`) | `MISSING — docs/13 G7` | ✅ |
| Collect VM attestation | `POST /api/v1/attestation/vm/{id}` | `CollectVMAttestation` | `OpAttestVMWorkload` (`0x7F`) | `MISSING — docs/13 G7` | ✅ |
| Collect container attestation | `POST /api/v1/attestation/container/{id}` | `CollectContainerAttestation` | `OpAttestContainerWorkload` (`0xED`) | `MISSING — docs/13 G7` | ✅ |
| Attest a workload | `MISSING — docs/13 G7` | (covered by the two Collect RPCs) | `OpAttestDeviceWorkload` (`0xEE`) | `attestation_attest_workload` | — |
| Verify a workload | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `attestation_verify_workload` | — |
| Attestation reports (create / get / list) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpAttestGetReportByID` (`0x77`), `OpAttestListReports` (`0xEF`) | `attestation_create_report`, `attestation_get_report`, `attestation_list_reports` | — |
| Attestation policies (create / get / list / delete / evaluate) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpAttestCreatePolicy` (`0xAA`), `OpAttestListPolicies` (`0xAB`) | `attestation_create_policy`, `attestation_get_policy`, `attestation_list_policies`, `attestation_delete_policy`, `attestation_evaluate_policy` | — |
| Attestation events | `GET /api/v1/attestation/events` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | — |
| Caller-admission policy (effective) | `GET /api/v1/attestation/callers` | `DescribeCallerPolicy` | `MISSING — #386` | `attestation_caller_policy` | ✅ |
| Node clock state (collector-facing) | `GET /api/v1/attestation/clock` | REST-only by design — see §5.2a | REST-only by design | REST-only by design | — |
| Device report (cached verdict + age) | `GET /api/v1/attestation/reports/{device_id}` | `GetDeviceReport` | `MISSING — #386` | `attestation_device_report` | ✅ |
| Device reports (fleet) | `GET /api/v1/attestation/reports` | `ListDeviceReports` | `MISSING — #386` | `attestation_device_reports` | ✅ |
| Refresh a device report (enqueue) | `POST /api/v1/attestation/reports/{device_id}/refresh` | `RefreshDeviceReport` | `MISSING — #386` | `attestation_device_refresh` | ✅ |
| Challenge / response | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpAttestChallenge` (`0x74`), `OpAttestResponse` (`0x75`) | `MISSING — docs/13 G7` | — |
| Get AK | `MISSING` — served by the TPM surface, [`docs/tpm/`](../tpm/) | — | `OpAttestGetAK` (`0x73`) | — | — |

**Reading the gaps.** The rows are lopsided in a consistent direction: manifests
and quotes are complete on gRPC and REST, while **reports and policies exist only
on QUIC and MCP**. That is not a documentation artefact — it is the actual
shape, and it means an operator using REST cannot manage attestation policy at
all. This is the single largest attestation surface hole and belongs in the gap
register as G7.

---

## 3. Two REST attestation routers

There are two, mounted on the same `/api/v1/attestation` prefix:

- **`server_router.go`** — the current surface, listed above: `/manifests`,
  `/manifests/build`, `/manifests/verify`, `/manifests/{id}`, `/quote`,
  `/quote/verify`, `/host`, `/vm/{id}`, `/container/{id}`.
- **A second, older router** registering `/manifest` (singular),
  `/manifest/build`, `/verify`, and `GET /quote`.

The old paths differ from the new by more than a plural: the old `/verify`
became `/manifests/verify`, and the old **`GET`** `/quote` became **`POST`**
`/quote` (a quote request carries a nonce, which does not belong in a query
string). New clients use the `server_router.go` forms. **Which of the two is
canonical, and whether the older one should be removed or kept as a compatibility
alias, is an open question for the owner** — recorded in the migration report,
not decided here.

---

## 4. QUIC opcode hazards

Two pairs of constants share a value in the same flat opcode space:

| Value | Names | Which one the dispatcher uses |
|---|---|---|
| `0x76` | `OpAttestGetReport` (`protocol.go:226`), `OpAttestGetManifest` (`attestation_handlers.go:29`) | **`OpAttestGetManifest`** — the handler switches on it |
| `0x77` | `OpAttestGetPCRs` (`protocol.go:227`), `OpAttestGetReportByID` (`attestation_handlers.go:55`) | **`OpAttestGetReportByID`** |

`OpAttestGetReport` and `OpAttestGetPCRs` are therefore dead names, but both are
still in the `OpcodeNames` table (`protocol.go:898-899`), so **logs will label a
manifest fetch `AttestGetReport` and a report fetch `AttestGetPCRs`**. When
debugging a QUIC attestation call, trust the handler, not the log label.

`OpAttestCollectHost` (`0x72`) carries a comment saying it was "repurposed from
the never-implemented OpAttestGetEK" — the EK opcode never shipped and the value
was reused. Nothing depends on the old meaning.

---

## 5. Authorization

Platform tokens carry an `scp` claim in the qrdb-canonical
`"<resource>:<action>"` form. Enforcement is per operation: gRPC through
`RequireScope`, QUIC through `AuthorizeRequest`, MCP through `AuthorizeTool`.

**`AttestationService` is not in the gRPC scope catalog.**
`pkg/api/grpc/method_permissions.go` maps 185 methods across eleven services —
`CAService`, `DeviceService`, `DNSService`, `GatewayService`,
`KeyManagementService`, `NTPService`, `PlatformIAMService`, `ProxyService`,
`SDNService`, `VTPMService`, and one daemon method. Attestation is absent, and
the catalog's own doc comment states that a method absent from the map carries
no required scope: the interceptor allows it once the token is validated.

That means **any validated token can build, verify and delete attestation
manifests over gRPC.** Given that attestation is the authentication method for
the OCI registry ([`docs/registry/`](../registry/)) and gates workload
admission, whether `AttestationService` should join the scope catalog is a
security question for the owner. It is raised in the migration report and is not
decided here.

### 5.1 REST `/api/v1/attestation/*` requires the admin role (#387)

Every route the attestation REST routers register — the manifest verbs, the
quote verbs, `POST /attestation/host`, `/vm/{id}`, `/container/{id}`, the
`/events` timeline and `/callers` — is mounted behind the platform's admin-role
gate, the same seam #165 put in front of the credential-bearing routers.

**Why it is gated now.** Until #387 every quote-producing operation answered
`ErrTPMSessionNotConfigured`, so the open routes were inert. #387 hands the
attestation service the node's TPM: `POST /attestation/host` makes the TPM
quote the caller's nonce on demand and returns the PCR values that quote
covers. Ungated, that is a TPM-DoS and a measured-state disclosure surface open
to any host on the network — precisely what the reporting service's
cache-and-gate design ([architecture.md](architecture.md), design of record)
exists to prevent.

**Request contract.** `POST /attestation/host` decodes a protobuf-JSON
`CollectHostAttestationRequest`: `nonce` (base64, **required** — the TPM signs
it and the caller checks the echo) and `config` (`AttestationQuoteConfig`,
**optional**). An absent or empty `config` asks for the node's default PCR
selection (`DefaultPCRIndices`, 0–7 and 14); `config.pcrIndices` narrows it. The
collector always sends a `config` object, empty when it has no selection —
measured 2026-09-05, the handler had required the field and every collection
on the fleet answered `400 quote config is required` while the service would
have defaulted it.

### 5.2 The two quote-producing routes carry a second principal (#226)

`POST /attestation/host` and `POST /attestation/quote` are what the reporting
collector dials. The collector is a machine and holds no operator session, so
those two routes — and only those two — admit a second principal:

1. **No client certificate presented** → the operator chain decides (JWT plus
   the admin role), exactly as in §5.1.
2. **A client certificate presented** → the node's caller-admission policy
   decides (`pkg/attestation/calleradmission`): the chain must reach the
   configured anchors with the client-auth key usage, the identity is the
   certificate's DNS SANs, and the configured strategy (`reporting-servers`,
   default; `any-attested`; `allowlist`) authorizes. Its decision is final for
   the request: a refused machine caller answers `403` (`401` when the chain
   or the name is unusable) and is **not** handed to the operator chain for a
   second attempt.

Every decision is an attestation event (`caller_admitted`, `caller_refused`)
carrying the strategy, the identity, the transport address and a `reason`
that distinguishes a configuration refusal (`not-listed`, `list-empty`,
`list-invalid`, `no-trust-anchors`, `untrusted-issuer`, `no-identity`,
`attestation-gate-unavailable`) from a security-relevant one (`not-attested`,
`attestation-stale`).

With no policy configured — no `attestation.reporting.callers` section and
nothing to derive one from — the two routes are operator-only, which is the
pre-#226 behaviour. The policy can only narrow who else gets in; it never
loosens the operator gate. `GET /attestation/callers` reports the compiled
policy so an operator can see what is enforced.

**A certificate that does not chain at all fails the TLS handshake**, before
any handler or audit event. The listener requests client certificates from the
union of its own CA and the policy anchors (`tls.VerifyClientCertIfGiven`), so
a browser with no certificate is unaffected while a certificate from an unknown
issuer never reaches HTTP. Such a peer is visible in the TLS error log, not in
the attestation event log.

### 5.2a The node clock route (#509)

`GET /api/v1/attestation/clock` sits on the SAME caller gate as the two
quote-producing routes above, for the same principal and by the same rules.
It answers one question: can the machine the collector is about to quote
place itself in time?

```json
{
  "synced": true,
  "stratum": 3,
  "leap_status": "Normal",
  "offset_seconds": -0.000012,
  "sources_reachable": 1,
  "sources_total": 2,
  "anomaly": false
}
```

It is a read-only projection of the node's time-synchronization status
([`docs/ntp/`](../ntp/)). The privileged clock verbs — `GET /api/v1/ntp/status`,
`/sources`, and above all `POST /api/v1/ntp/step`, which moves the system
clock — stay on the operator-gated NTP surface. A read-only machine principal
must not reach a mutation that moves every validity window on the node, so the
route is a projection here rather than an admission to that surface.

**A clock that cannot be read answers `503`, never `"synced": false`.** The
collector records the first as unknown and the second as a wrong clock, and a
control-socket failure must never be able to produce the second. A node with
no `ntp:` section answers `503` for the same reason: nothing was asked to
manage time here, which is not a claim about the clock.

Why on the attestation surface and not the NTP one: the answer is recorded
beside an attestation verdict, and its principal is the collector's mTLS
identity. A verdict from a machine that cannot place itself in time is a
weaker verdict — that node's ACME renewals, DANE signature windows and token
checks all run on its own clock, not the verifier's.

**REST-only is deliberate, and is not a `docs/13` gap.** This route is not a
service; it is one narrow projection of state that IS already carried on all
five transports, by the NTP surface's `GetStatus` ([`docs/ntp/api.md`](../ntp/api.md)).
What differs here is the authorization, not the data: the collector is a
machine principal on the caller gate, and it speaks REST. Adding gRPC, QUIC
and MCP copies would widen a machine-caller surface for no caller that
exists. An operator wanting the clock on another transport asks the NTP
service, which answers on all of them with more detail.

### 5.3 Device reports (#226)

The four report capabilities above read the reporting cache or enqueue work
with the collector; none reaches a device. They are admin-gated on REST, and
their MCP tools are permission-mapped (`attestation:read`; the refresh is
`attestation:write` because it spends a node's TPM time). QUIC does not carry
them: the attestation QUIC handlers are never constructed in production
(#386), so the column is recorded as a gap rather than a handler.

Every transport returns the same shape — `reporting.View`: `device_id`,
`serial`, `model`, `verified`, `ak_certificate_verified`, `signature_valid`,
`nonce_valid`, `pcrs_valid`, `cryptographic_failure`, `pcr_baseline_source`,
`pcr_baseline_recorded_at`, `pcr_baseline_captured`, `status`, `message`,
`attested_at`, `collected_at`, `fresh`, `age_seconds`, `as_of`, and
`time_synced`. A consumer that renders `verified` without `fresh` and
`age_seconds` is misrepresenting the report.

`time_synced` is the DEVICE's own clock trust state at collection, read from
that node's clock route (§5.2a) in the same collection that produced the
quote. It has **three** states and a consumer must render three: `true`,
`false`, and **absent** — the key is omitted entirely, and the proto field is
`optional`, when the device did not answer. A machine whose clock could not be
read is not a machine with a wrong clock, and collapsing the two would repeat
the reachability-as-verdict conflation #197 shipped once already. A collector
wired with no clock source produces reports with the key absent throughout.
`platformctl attestation reports` renders the three as `synced`, `UNSYNCED`
and `unknown`; the console renders them as a badge, and flags only `false` in
the fleet table. **Never collected** is `404` / `NotFound` / `ErrNoDeviceReport`;
a **failed** verdict is a `200` whose `verified` is false. The refresh
answers `202` with `enqueued: true` and never a quote; `503` when the
reporting service is not configured on this node.

The Go SDK carries the four on `sdk/go/services/attestation.Client` as
`ListDeviceReports`, `GetDeviceReport`, `RefreshDeviceReport` and
`DescribeCallerPolicy` (#429), with `GetDeviceReport` returning
`*ErrNoDeviceReport` for the never-collected state. The REST adapter routes them to the paths above and
decodes the webservice's bare `reporting.View` / `Description` payloads onto
the pb replies; the MCP adapter maps them to the four tools. One transport
caveat: the MCP server collapses every tool error to `InternalError`, so over
MCP the SDK recognises never-collected by the server's message (`no report
has been collected for device`), the text all three servers share. `platformctl
attestation reports list|get|refresh` and `platformctl attestation callers`
([cli.md](cli.md) §3) are thin over this client.

The JS SDK re-exports the four routes (`AttestationService.listDeviceReports`,
`getDeviceReport`, `refreshDeviceReport`, `describeCallers`) with `View` typed
as `DeviceReport`, and `classifyDeviceReport()` maps a report response onto
`report` / `never-collected` (404) / `not-configured` (503) / `error` in one
place, so the console's Devices pages (#428) branch on what the server
answered rather than on `success` alone.

**What this does not close.** The gRPC scope-catalog gap above stands. The
state half of admission — proving the caller is itself currently attested — is
go-qrdb#278 over go-xkms#273 and composes in front of this policy when it
lands; `any-attested` refuses everyone on a node with no attested-peer
evidence until then.

### 5.4 Workload verdicts on the collect routes (#483)

`POST /api/v1/attestation/vm/{id}` and `.../container/{id}` — and their QUIC
opcodes `0x7F` / `0xED` — return `verified` alongside two fields that say how
that answer was reached:

| Field | Meaning |
|---|---|
| `verification_status` | `verified`, `failed`, or `not_evaluated` |
| `verification_error` | why, when the status is not `verified`; omitted when it is |

The status is three-valued on purpose. `failed` means a check ran and rejected
the evidence; `not_evaluated` means no check could run — the evidence, or the
material needed to judge it, was absent. **A consumer that renders `verified`
alone cannot tell a passed check from a check that never happened**, which is
what these routes reported before #483: both response builders set
`verified: true` from a literal, on every response, for any evidence.

VM evidence carries a quote, an AIK and a signature, so it is verified for
real: the quote's `ExtraData` must equal the nonce the caller supplied
(anti-replay) and the signature must check out against the AIK. Container
evidence carries a digest and a PCR value and **no signature**, so no
cryptographic verification is defined for it; those responses are always
`not_evaluated`, never a pass. Both transports call one implementation
(`pkg/attestation/verdict`), so they cannot drift.

---

## 6. Status and error mapping

| QUIC byte | Name | REST | Attestation cause |
|---|---|---|---|
| `0x00` | `StatusOK` | 200 | — |
| `0x01` | `StatusInvalidRequest` | 400 | `ErrInvalidManifest`, `ErrEmptyManifest`, `ErrInvalidVMIdentity` |
| `0x02` | `StatusNotFound` | 404 | `ErrManifestNotFound`, `ErrAKNotFound`, `ErrAIKNotFound` |
| `0x03` | `StatusUnauthorized` | 401 | `ErrAuthFailed` |
| `0x04` | `StatusInternalError` | 500 | `ErrQuoteGenerationFailed`, `ErrSerializationFailed` |
| `0x05` | `StatusTimeout` | 504 | `ErrContextCanceled`, `ErrRetryExhausted` |
| `0x07` | `StatusPermissionDenied` | 403 | `ErrAttestationFailed`, `ErrPCRMismatch`, `ErrQuoteVerificationFailed`, `ErrQuoteExpired`, `ErrNonceMismatch`, `ErrMerkleRootMismatch`, `ErrHostNotAttested` |
| `0x09` | `StatusInvalidArgument` | 400 | `ErrInvalidWorkloadType`, `ErrInvalidHashAlgorithm` |
| `0x0A` | `StatusUnavailable` | 503 | Attestation service not wired into the daemon |
| `0x0B` | `StatusNotImplemented` | 501 | An opcode in range with no handler |

Every row mapping to 403 is a **fail-closed** path. There is no attestation
error that yields a partially trusted result.

Payloads are bounded at `MaxPayloadSize` (16 MiB) on QUIC — relevant here
because an IMA event log can be large. A host with a very long measurement log
must page it rather than pushing it in one frame.

---

## 7. Versioning

REST is under `/api/v1`; gRPC is package `platform.v1`. The older REST router in
§3 is not version-tagged and is not a `/api/v0` — both routers serve under `v1`,
which is precisely why the duplication needs an owner ruling.
