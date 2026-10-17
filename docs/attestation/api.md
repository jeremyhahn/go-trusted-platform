# Attestation — API

> **Status: NORMATIVE** · Scope: attestation routes on every transport · Last verified: 2026-10-12
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

gRPC: `AttestationService` in `pkg/api/grpc/proto/attestation.proto` — sixteen RPCs.
REST: `pkg/webservice/v1/rest/attestation/` (`server_router.go`,
`events_router.go`, `reports_router.go`, `clock_router.go`, `verdicts_router.go`
— see §3).
QUIC: `pkg/api/quic/attestation_handlers.go` plus the base range in
`sdk/go/wire/quicwire/protocol.go`, routed by the daemon for opcodes `0x6A`, `0x70`–`0x77`
and `0x7C`–`0x7F` (`pkg/api/daemon/quic_attestation.go`). The manifest and
collection opcodes call the same gRPC servicer through
`pkg/api/daemon/quic_attestation_adapter.go`, so each answers with its gRPC
twin's result and error class; `0x77` has no report store behind any transport
and answers `StatusNotImplemented`. `0x73` calls the TPM gRPC servicer's
`GetAK`. `0x74` is unassigned: no transport serves challenge / response, so
QUIC carries no opcode for it. The authorization catalog does not classify the
byte either, so the daemon refuses it before dispatch with `StatusPermissionDenied`
("QUIC operation not classified for authorization: opcode 0x74"), the answer
every reserved byte gets.
MCP: the `attestation_*` tools. The five manifest tools call the gRPC
`AttestationService` methods (`pkg/api/daemon/mcp_attestation_manifests.go`), so
each answers with its gRPC twin's result and error class. The five quote and
collection tools (`pkg/api/mcp/attestation_quote_tools.go`) take the gRPC
request in protojson form and call the same servicer; the two that quote a
caller's nonce bind it to the HTTPS connection and are refused over stdio
(§5.1a). A tool marked
"refused" is registered but has no backend and no scope, so every call is
refused (§5).

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| List manifests | `GET /api/v1/attestation/manifests` | `ListManifests` | `MISSING — docs/13 G7` | `attestation_list_manifests` | ✅ |
| Get manifest | `GET /api/v1/attestation/manifests/{id}` | `GetManifest` | `OpAttestGetManifest` (`0x76`) | `attestation_get_manifest` | ✅ |
| Build manifest | `POST /api/v1/attestation/manifests/build` | `BuildManifest` | `OpAttestBuildManifest` (`0x7C`) | `attestation_create_manifest` | ✅ |
| Verify manifest | `POST /api/v1/attestation/manifests/verify` | `VerifyManifest` | `OpAttestVerifyManifest` (`0x7D`) | `attestation_verify_manifest` | ✅ |
| Delete manifest | `DELETE /api/v1/attestation/manifests/{id}` | `DeleteManifest` | `MISSING — docs/13 G7` | `attestation_delete_manifest` | ✅ |
| Get quote (TLS only — §5.1a) | `POST /api/v1/attestation/quote` | `GetAttestationQuote` (refused over Unix) | `OpAttestQuote` (`0x70`) | `attestation_get_quote` (HTTPS only) | refused — no TLS (§5.1a) |
| Verify quote | `POST /api/v1/attestation/quote/verify` | `VerifyAttestationQuote` | `OpAttestVerify` (`0x71`) | `attestation_verify_quote` | ✅ |
| Collect host attestation (TLS only — §5.1a) | `POST /api/v1/attestation/host` | `CollectHostAttestation` (refused over Unix) | `OpAttestHost` (`0x7E`), `OpAttestCollectHost` (`0x72`) | `attestation_collect_host` (HTTPS only) | refused — no TLS (§5.1a) |
| Collect VM attestation | `POST /api/v1/attestation/vm/{id}` | `CollectVMAttestation` | `OpAttestVMWorkload` (`0x7F`) — without a TPM session it carries `ErrTPMSessionNotConfigured` as the other transports do (gRPC `Internal`, QUIC `StatusInternalError`) | `attestation_collect_vm` | ✅ |
| Collect container attestation | `POST /api/v1/attestation/container/{id}` | `CollectContainerAttestation` | `OpAttestContainerWorkload` (`0x6A`) — moved off `0xED`, which PXE owns (#949); calls `CollectContainerAttestation` and answers its gRPC twin's result and error class | `attestation_collect_container` | ✅ |
| Attest a workload | `MISSING — docs/13 G7` | (covered by the two Collect RPCs) | `MISSING` — `OpAttestDeviceWorkload` (`0xEE`) is shadowed by the PXE family | `MISSING — docs/13 G7` | — |
| Verify a workload | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | — |
| Attestation reports (create / get / list) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING` — `OpAttestGetReportByID` (`0x77`) answers `StatusNotImplemented` (no report store on any transport); `OpAttestListReports` (`0xEF`) is shadowed by the PXE family | `MISSING — docs/13 G7` | — |
| Attestation policies (create / get / list / delete / evaluate) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING` — `OpAttestCreatePolicy` (`0xAA`) and `OpAttestListPolicies` (`0xAB`) are shadowed by the IAM family | `MISSING — docs/13 G7` | — |
| Attestation events | `GET /api/v1/attestation/events` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | — |
| Caller-admission policy (effective) | `GET /api/v1/attestation/callers` | `DescribeCallerPolicy` | `MISSING — #386` | `attestation_caller_policy` | ✅ |
| Node clock state (collector-facing) | `GET /api/v1/attestation/clock` | REST-only by design — see §5.2a | REST-only by design | REST-only by design | — |
| Device report (cached verdict + age) | `GET /api/v1/attestation/reports/{device_id}` | `GetDeviceReport` | `MISSING — #386` | `attestation_device_report` | ✅ |
| Device reports (fleet) | `GET /api/v1/attestation/reports` | `ListDeviceReports` | `MISSING — #386` | `attestation_device_reports` | ✅ |
| Refresh a device report (enqueue) | `POST /api/v1/attestation/reports/{device_id}/refresh` | `RefreshDeviceReport` | `MISSING — #386` | `attestation_device_refresh` | ✅ |
| Device verdict feed (`attestation:read`, tenant-filtered — §5.5, [engineering §9](engineering.md#device-verdict-events)) | `GET /api/v1/attestation/verdicts?cursor=&wait_ms=` (long-poll) | `StreamDeviceVerdicts` (server stream), `PollDeviceVerdicts` | `OpAttestPollVerdicts` (`0x75`, long-poll) | `attestation_device_verdicts_poll` (long-poll) | ✅ (long-poll) |
| Challenge / response | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` — `0x74` is unassigned; the never-implemented `OpAttestResponse` value `0x75` now carries `OpAttestPollVerdicts` | `MISSING — docs/13 G7` | — |
| Get AK | `MISSING` — served by the TPM surface, [`docs/tpm/`](../tpm/) | `TPMService.GetAK` ([`docs/tpm/`](../tpm/)) | `OpAttestGetAK` (`0x73`) — calls the TPM gRPC servicer's `GetAK`, so it answers its gRPC twin's result and error class | — | — |

**Reading the gaps.** The rows are lopsided in a consistent direction: manifests
and quotes are complete on gRPC and REST, while **reports and policies exist on
no transport**: QUIC defines opcodes for them, but `0x77` answers
`StatusNotImplemented` and the others are shadowed by the IAM and PXE families
(their MCP tools are registered but refused). That is not a documentation artefact — it is the actual
shape, and it means an operator using REST cannot manage attestation policy at
all. This is the single largest attestation surface hole and belongs in the gap
register as G7.

---

## 3. One REST attestation surface

The REST rows above are the whole surface: every route is registered under
`/api/v1/attestation` by `server_router.go` (`/manifests`, `/manifests/build`,
`/manifests/verify`, `/manifests/{id}`, `/quote`, `/quote/verify`, `/host`,
`/vm/{id}`, `/container/{id}`) or by the events, reports and clock routers.
`pkg/webservice/v1/testdata/routes.golden` is the authority. The older router
that registered `/manifest` (singular), `/manifest/build`, `/verify` and
`GET /quote` no longer exists, and the daemon answers those paths `404`.

The REST adapter in `test/integration/attestation/rest_adapter.go` calls only
these routes. The suite verbs no route serves — VM identity, a separate
manifest-signing step, push, and the workload chain — return `ErrRESTNoRoute`
instead of calling a path the daemon never registered (#546).
`BuildManifest` signs as it builds, and `VerifyManifest` fetches the stored
manifest and posts it to `/manifests/verify`, which takes the manifest itself.

`VerifyManifest` does not check a manifest signature. A request that carries a
public key is refused `FailedPrecondition`
(`ErrAttestationManifestSignatureUnchecked`) on every transport, rather than
answered with the signature reported valid unchecked (#304).

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
`RequireScope`, QUIC through `AuthMiddleware.GuardRequest`, MCP through
`AuthorizeTool`.

**QUIC checks a scope on every attestation opcode (#767).** The catalog
(`pkg/api/quic/opcode_permissions.go`, [`docs/daemon/api.md`](../daemon/api.md)
§5) asks `attestation:read` for the reads (verify a quote, get the AK, reports,
manifest verification) and `attestation:write` for every opcode that collects
fresh evidence: `OpAttestQuote` (`0x70`) and `OpAttestCollectHost` (`0x72`),
which make the node's TPM sign the caller's nonce and return the PCR values the
quote covers, plus challenge/response, manifest build, host attestation, VM
workload attestation and container workload attestation (`0x6A`). A quote is the TPM-DoS and measured-state disclosure
surface §5.1 describes, so an `attestation:read` token is refused it with
`StatusPermissionDenied`.

Both catalogs are **default-deny**
([`docs/auth/architecture.md`](../auth/architecture.md)).

**`AttestationService` is fully scoped on gRPC** (`pkg/api/grpc/method_permissions.go`):

| Permission | RPCs |
|---|---|
| `attestation:read` | `GetDeviceReport`, `ListDeviceReports`, `DescribeCallerPolicy`, `GetAttestationQuote`, `VerifyAttestationQuote`, `GetManifest`, `ListManifests`, `VerifyManifest` |
| `attestation:write` | `RefreshDeviceReport`, `BuildManifest`, `CollectHostAttestation`, `CollectVMAttestation`, `CollectContainerAttestation` |
| `attestation:delete` | `DeleteManifest` |

Attestation gates workload admission and the OCI registry
([`docs/registry/`](../registry/)), so `attestation:write` and
`attestation:delete` — building and deleting manifests — are the grants to
guard.

On MCP (`pkg/api/mcp/authz.go`), each classified tool asks the scope of its
gRPC twin:

| Permission | MCP tools |
|---|---|
| `attestation:read` | `attestation_device_report`, `attestation_device_reports`, `attestation_caller_policy`, `attestation_device_verdicts_poll`, `attestation_get_manifest`, `attestation_list_manifests`, `attestation_verify_manifest`, `attestation_get_quote`, `attestation_verify_quote` |
| `attestation:write` | `attestation_device_refresh`, `attestation_create_manifest`, `attestation_collect_host`, `attestation_collect_vm`, `attestation_collect_container` |
| `attestation:delete` | `attestation_delete_manifest` |

#304 deleted ten tools that no backend served: no gRPC method, and no REST
route the daemon mounts. They were `attestation_attest_workload` and
`attestation_verify_workload` (the real workload paths are `container_attest`
and `vm_attest`), the three report tools (`attestation_create_report`,
`attestation_get_report`, `attestation_list_reports`) and the five policy tools
(`attestation_create_policy`, `attestation_get_policy`,
`attestation_list_policies`, `attestation_delete_policy`,
`attestation_evaluate_policy`).

Manifests have no tenant: the gRPC manifest methods do not filter by tenant,
and the MCP tools answer exactly as they do.

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
`CollectHostAttestationRequest`: `nonce` (base64, **required** — the bare
challenge; the node binds it to the connection before quoting, §5.1a) and
`config` (`AttestationQuoteConfig`, **optional**). An absent or empty `config` asks for the node's default PCR
selection (`DefaultPCRIndices`, 0–7 and 14); `config.pcrIndices` narrows it. The
collector always sends a `config` object, empty when it has no selection —
measured 2026-09-05, the handler had required the field and every collection
on the fleet answered `400 quote config is required` while the service would
have defaulted it.

QUIC `0x7E` (`pkg/api/quic`) decodes the QUIC `CollectHostAttestationRequest`
under the same contract. `nonce` is **required**: an empty one is refused
`StatusInvalidArgument` (`ErrAttestationNonceRequired`), as gRPC refuses it
`InvalidArgument` (`nonce is required`), before the TPM is reached — a quote
over no nonce proves no freshness (RFC 9334 §10). A nonce shorter than 16 bytes
is refused the same way (`ErrAttestationInvalidNonce`). An absent
`hash_algorithm` is SHA-256 and absent `pcr_indices` the default selection.

### 5.1a Every node quote is bound to the connection it arrives on (#482)

The node, not the caller, binds the quote. On every transport that serves a
quote, the node derives the channel binding from **its own end of the
connection the request arrived on** — 32 bytes of TLS exporter output under
`xkms.PeerChannelBindingExporterLabel` (`xkms.PeerChannelBinding`) — and the
TPM quotes `QualifyingData(nonce, binding)` = SHA-256(nonce ‖ binding)
(`xkms.PeerQualifyingData`), never the nonce as sent. The rule covers every
operation that has the node's TPM sign a caller's nonce:

| Operation | Endpoints | The node returns |
|---|---|---|
| Collect host attestation | REST `POST /api/v1/attestation/host`; gRPC `CollectHostAttestation`; QUIC `0x72` (daemon), `0x7E` (`pkg/api/quic`); MCP `attestation_collect_host` | `attestation.nonce` = the value quoted |
| Get quote | REST `POST /api/v1/attestation/quote`; gRPC and Unix `GetAttestationQuote`; QUIC `0x70`; MCP `attestation_get_quote` | `channel_binding` beside the quote |
| TPM quote | REST `POST /api/v1/tpm/quote` (webservice and daemon REST); gRPC and Unix `TPMService.Quote`; QUIC `0x99`·`0x0F`; MCP `platform_tpm_quote` | `channel_binding` beside the quote |
| TPM certify with a nonce | daemon REST `POST /api/v1/tpm/certify` | `channel_binding` beside the certify structure |

The caller derives the binding from its own end of the same connection and
accepts the quote only when its qualifying data (the TPMS_ATTEST `extraData`)
equals `QualifyingData(nonce, its binding)`. The collector reports anything else
as `reporting.ErrQuoteNotBound`, the cause of `ErrNodeUnreachable`; the Go SDK
as `quotebind.ErrQuoteNotBound`, wrapped in the client's `ErrGetQuoteFailed` /
`ErrQuoteFailed` / `ErrCollectHostAttestationFailed`. The echoed `channel_binding` is only
compared against the caller's own, never trusted: a relay can rewrite it.

**Why the node derives it.** Were the caller to send the bound value, or were
the node to quote the nonce as sent, a relay — any endpoint with a valid
certificate — could forward the caller's nonce unchanged to a healthy node over
a second connection and hand back a quote that passes. With the node deriving,
the relay's forward lands on connection B and the quote is bound to B; the
caller holds A, so the relay cannot pass off another node's attested state as
its own (`TestCollectHost_RelayedQuoteIsRejected`,
`TestGetAttestationQuote_RelayedQuoteIsRejected`).

| Transport | Binding taken from | No binding available |
|---|---|---|
| REST | the request's `http.Request.TLS` | plain HTTP, or an exporter that refuses → `400` |
| gRPC | the peer's `credentials.TLSInfo` | exporter refuses → `FailedPrecondition` |
| QUIC | the QUIC connection's TLS state | exporter refuses → `StatusInvalidRequest` |
| MCP over HTTPS | the request's `http.Request.TLS` | plain HTTP → tool error |
| MCP over stdio | — (no TLS) | always refused (tool error) |
| Unix socket, embedded | — (no TLS) | always refused (`FailedPrecondition`) |

A request with no binding is refused with
`channelbind.ErrChannelBindingRequired` (it names the transport) before the
TPM is touched; the node never falls back to quoting the bare nonce, since a
bare quote is exactly what a relay needs. The SDK refuses the same calls on
its side before sending them: over Unix, MCP and embedded it returns
`transport.ErrChannelBindingUnavailable`, since it has no connection of its own
to check the echo against.

**Verifying a bound quote.** `VerifyAttestationQuote` and `TPMService.VerifyQuote`
take an optional `channel_binding`. With it, the expected qualifying data is
`QualifyingData(expected_nonce, channel_binding)`; without it, the bare nonce.
`channel_binding` without a nonce is `InvalidArgument`. A verify request is a
signature check, not channel proof: the verifier that accepts a quote as
evidence of a peer — the reporting collector — derives the binding itself.

**Signature scheme.** `AttestationQuote.signature_algorithm` names the scheme
the AK signed under, as `x509.SignatureAlgorithm` names it (`SHA256-RSA`,
`SHA256-RSAPSS`, `ECDSA-SHA256`, and their SHA-384/512 forms).
`GetAttestationQuote` fills it from the IAK; pass the returned quote to
`VerifyAttestationQuote` unchanged (`platformctl`'s binding takes it as an
argument). The signature is checked under that scheme only. A quote that
declares no scheme or an unknown one is refused as
`vm.ErrUnsupportedSignatureAlgorithm`; one whose scheme the AK key cannot
carry, as `vm.ErrSignatureSchemeMismatch` — never retried under another
scheme. See [engineering.md](engineering.md) §3 invariant 12.

**Browsers.** A browser cannot read the TLS exporter of its own connection. The
JavaScript SDK's `checkQuoteBinding` (and the web console's quote page, which
runs it) proves the quote is bound to the `channelBinding` the node returned —
never a quote of the bare nonce — but not that the binding is the page's own
connection. See [engineering.md](engineering.md) §3 invariant 10.

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
them: the daemon serves the attestation QUIC handler (§1), but it has no
device-report opcode (#386), so the column is recorded as a gap rather than a
handler.

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
the pb replies; the MCP adapter maps them to the four tools. Never-collected
is `NotFound` on every transport: the MCP server answers `ErrNoDeviceReport`
with `-32005`, and the SDK decodes it to `codes.NotFound`
([`docs/daemon/api.md`](../daemon/api.md) §1, #505). `platformctl
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
opcodes `0x7F` / `0x6A` — return `verified` alongside two fields that say how
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

VM evidence carries a quote, an AIK, a signature and the scheme it was signed
under (`signature_algorithm`), so it is verified for real: the quote's
`ExtraData` must equal the nonce the caller supplied (anti-replay) and the
signature must check out against the AIK under the declared scheme (#482).
Evidence that names no scheme is `not_evaluated` — no scheme is guessed from
the key type — and a scheme the signature was not made under is `failed`. That is the
rule for evidence a caller submits on a transport. A device quote the
collector fetches on the reporting path is bound to the TLS connection it was
collected over, so its `ExtraData` is
`QualifyingData(nonce, binding)` = SHA-256(nonce ‖ binding)
(`xkms.PeerQualifyingData`), and the reporting verifier refuses a quote of the
bare nonce ([engineering §3, invariant 10](engineering.md#3-invariants)). Container
evidence carries a digest and a PCR value and **no signature**, so no
cryptographic verification is defined for it; those responses are always
`not_evaluated`, never a pass. Both transports call one implementation
(`pkg/attestation/verdict`), so they cannot drift.

### 5.5 Device verdict feed (#709)

Every transport follows the same feed of recorded device verdicts
([engineering §9](engineering.md#device-verdict-events)): the last 256, from a
cursor. gRPC and Unix carry `StreamDeviceVerdicts` as a server stream. The
others carry no server stream, so they long-poll one RPC,
`PollDeviceVerdicts(cursor, wait_ms) → (cursor, verdicts)`:

| Transport | Poll | Who it admits |
|---|---|---|
| REST | `GET /api/v1/attestation/verdicts?cursor=&wait_ms=`, behind the admin-role gate (§5.1) | the verified session's tenant; `system` sees every tenant; no tenant → `403` |
| gRPC / Unix | `PollDeviceVerdicts` | the stream's rules (engineering §9 table) |
| QUIC | `OpAttestPollVerdicts` (`0x75`), a `PollDeviceVerdictsRequest` in the connection's codec | a platform token with `attestation:read`; none → `StatusPermissionDenied` |
| MCP | tool `attestation_device_verdicts_poll` (`cursor`, `wait_ms`), permission `attestation:read` | a platform token with `attestation:read`; none → refused |
| Embedded | `PollDeviceVerdicts` in process | the local caller, every tenant |

An empty cursor answers at once with the current position and no verdicts —
that is how a follow starts "from now on". Each later poll passes the cursor the
previous reply returned and waits up to `wait_ms` (clamped to 20 s) for a
verdict it may see before answering an empty page. Always pass the returned
cursor on: it moves past verdicts of tenants the caller may not see, even on
an empty page. The reply is the
pb `PollDeviceVerdictsResponse` on every transport: protojson in the REST
envelope's `payload`, proto field names over MCP.

| Condition | gRPC | REST | QUIC |
|---|---|---|---|
| Fell behind the ring, or a cursor from an earlier platformd run | `RESOURCE_EXHAUSTED` | `429` | `StatusResourceExhausted` |
| Cursor the feed never issued; malformed `wait_ms` | `INVALID_ARGUMENT` | `400` | `StatusInvalidArgument` |
| Caller not admitted | `PERMISSION_DENIED` | `403` | `StatusPermissionDenied` |
| platformd shutting down | `UNAVAILABLE` | `503` | `StatusUnavailable` |
| No feed on this node (attestation service cannot hand out verdicts) | `FAILED_PRECONDITION` | `400`; `503` when the route has no poller at all | `StatusInvalidRequest`; `StatusUnavailable` with no attestation service |

The Go SDK (`sdk/go/transport/pollstream`) answers `StreamDeviceVerdicts` on
the REST, QUIC, MCP and embedded connections by running these polls: one head
poll with an empty cursor, then polls that each wait half the transport
timeout (at most 20 s; the full 20 s embedded, where no timeout applies),
handing the verdicts to `Recv` in order and ending the stream with the first
poll error. A caller therefore writes one follow loop for every transport.
**Two MCP caveats:** MCP carries the other conditions above with their gRPC
code, but JSON-RPC has no code for `RESOURCE_EXHAUSTED`, so over MCP a stream
that fell behind ends `Internal` carrying the daemon's message; and the MCP
client retries a failed call (three times, one
second apart) before the stream sees the error. `platformctl attestation
verdicts follow` ([cli.md](cli.md) §3.5) is thin over this call.

---

## 6. Status and error mapping

| QUIC byte | Name | REST | Attestation cause |
|---|---|---|---|
| `0x00` | `StatusOK` | 200 | — |
| `0x01` | `StatusInvalidRequest` | 400 | `ErrInvalidManifest`, `ErrEmptyManifest`, `ErrInvalidVMIdentity`, `ErrChannelBindingRequired` (gRPC `FailedPrecondition`, §5.1a) |
| `0x02` | `StatusNotFound` | 404 | `ErrManifestNotFound`, `ErrAKNotFound`, `ErrAIKNotFound` |
| `0x03` | `StatusUnauthorized` | 401 | `ErrAuthFailed` |
| `0x04` | `StatusInternalError` | 500 | `ErrQuoteGenerationFailed`, `ErrSerializationFailed` |
| `0x05` | `StatusTimeout` | 504 | `ErrContextCanceled`, `ErrRetryExhausted` |
| `0x07` | `StatusPermissionDenied` | 403 | `ErrAttestationFailed`, `ErrPCRMismatch`, `ErrQuoteVerificationFailed`, `ErrQuoteExpired`, `ErrNonceMismatch`, `ErrMerkleRootMismatch`, `ErrHostNotAttested` |
| `0x09` | `StatusInvalidArgument` | 400 | `ErrInvalidWorkloadType`, `ErrInvalidHashAlgorithm`, `ErrAttestationNonceRequired` and `ErrAttestationInvalidNonce` (QUIC `0x7E`, §5.1) |
| `0x0A` | `StatusUnavailable` | 503 | Attestation service not wired into the daemon |
| `0x0B` | `StatusNotImplemented` | 501 | An opcode in range with no handler; `0x77` (`ErrQUICAttestationNoService`: no report store behind any transport) |

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
