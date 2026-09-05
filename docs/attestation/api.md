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
`protocol.go`, routed by the daemon for opcodes `0x70`–`0x77`
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
quote verbs, `POST /attestation/host`, `/vm/{id}`, `/container/{id}`, and the
`/events` timeline — is mounted behind the platform's admin-role gate, the same
seam #165 put in front of the credential-bearing routers.

**Why it is gated now.** Until #387 every quote-producing operation answered
`ErrTPMSessionNotConfigured`, so the open routes were inert. #387 hands the
attestation service the node's TPM: `POST /attestation/host` makes the TPM
quote the caller's nonce on demand and returns the PCR values that quote
covers. Ungated, that is a TPM-DoS and a measured-state disclosure surface open
to any host on the network — precisely what the reporting service's
cache-and-gate design ([architecture.md](architecture.md), design of record)
exists to prevent.

**Why the admin role.** The #165 hold was waiting on a "node-push credential
ruling". The #226 ruling settled the model as **pull**: the reporting server
dials a node's quote endpoint with its own nonce. The caller of every
quote-producing route is therefore the platform's own component holding an
admin credential, not an anonymous node. The admin role is the strictest gate
that exists today; the attested-caller gate and the operator-configurable
allowlist (#226) compose **on top of** it when they land — they do not replace
it.

**What this does not close.** The gRPC scope-catalog gap above stands: over
gRPC, attestation methods still carry no required scope. The REST gate is a
different seam and must not be read as resolving it.

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
