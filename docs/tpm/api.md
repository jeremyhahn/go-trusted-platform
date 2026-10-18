# Physical TPM 2.0 — API

> **Status: NORMATIVE** · Scope: TPM and device-identity routes on every transport · Last verified: 2026-10-14
> Conflicts with this document are defects. Fix them here first.
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING — docs/13 G7`, never omitted.

---

## 1. The six transports

`sdk/go/protocol.go` declares six: `ProtocolEmbedded`, `ProtocolUnix`,
`ProtocolGRPC`, `ProtocolREST`, `ProtocolQUIC`, `ProtocolMCP`. **Unix is gRPC
over a Unix domain socket**, so gRPC and Unix share a column. Framing, status
bytes and the category-opcode rule are in
[`docs/daemon/api.md`](../daemon/api.md) §4 and are not repeated here.

| Surface | Where |
|---|---|
| gRPC | `TPMService`, **28 RPCs** (`pkg/api/grpc/proto/tpm.proto`); `IDevIDService`, **20 RPCs** (`idevid.proto`) |
| Embedded | `ServiceRegistry.TPM` (`platformv1.TPMServiceServer`) and `ServiceRegistry.IDevID` — the embedded adapter dispatches gRPC method strings, so **embedded coverage equals gRPC coverage exactly** |
| REST | web service: `/api/v1/tpm` (`pkg/webservice/v1/rest/tpm/router.go`) and `/api/v1/idevid` (`pkg/webservice/v1/rest/idevid/router.go`); daemon REST listener: `/api/v1/tpm` (`pkg/api/rest/tpm_handlers.go`, mounted by `RESTServer.SetTPMHandlers`) and `POST /api/v1/idevid/ldevid` (`pkg/api/daemon/rest_idevid_ldevid.go`) |
| QUIC | category opcode `OpTPM2Category` = **`0x99`**, sub-opcode in `payload[0]` (`pkg/api/quic/tpm_handlers.go`); device identity uses **top-level** opcodes `0x56`–`0x5F`, `0x6B`–`0x6E`, `0x78`–`0x7B` |
| MCP | 31 `platform_tpm_*` tools (`pkg/api/mcp/tpm_tools.go`) plus 17 `idevid_*` / `iak_*` tools (`idevid_tools.go`, `ldevid_tools.go`) |

**Two REST servers serve `/api/v1/tpm`.** The web service mounts its router;
platformd's own REST listener mounts `restapi.TPMHandlers`. On the daemon
listener every route needs a platform bearer token granting the scope in §9.
**Every daemon-listener route calls one RPC of the daemon's `TPMService`** —
the same `TPMGRPCService` that gRPC, Unix and embedded call, with no TPM logic
of its own — and speaks the SDK wire contract, so both SDK REST adapters work
against it (`TestTPMRoutesServeTheSDKContract`,
`pkg/api/rest/tpm_handlers_test.go`; `TestTPMQuoteParity_*`,
`pkg/api/daemon/tpm_quote_transport_parity_test.go`):

- The request is the RPC's request message. The body is protojson, with either
  the camelCase JSON name (the JavaScript SDK) or the proto name (the Go SDK)
  of each field, and enums given by name or number. An empty body is the empty
  request.
- Query parameters and path parameters set fields of the same message, by
  either name: a `uint32` handle or index in decimal or `0x` hex, an enum by
  name or number, a bool, a string, and one parameter per element of a
  repeated field (`?indices=0&indices=7`). A path parameter wins over a query
  parameter of the same name. A field of a nested message takes a dotted path
  (`a.b`); bytes and whole messages travel only in the body.
- **A field the message does not have is `400`, never a silent default** — in
  the body (`ErrInvalidRequestBody`, `unknown field "x"`) or as a parameter
  (`ErrInvalidQueryParameter`). So is a parameter that does not parse, or a
  single-valued field given twice. The TPM service is not called.
- The reply is the bare protojson response message, with camelCase keys and
  every field present. An RPC error is the standard error envelope, its status
  mapped from the gRPC code.

The path-parameter forms the JavaScript SDK calls are
`DELETE /tpm/{ek,srk,ak}/{handle}` and `GET`/`PUT`/`DELETE /tpm/nvram/{index}`;
the Go SDK sends the key deletes to `DELETE /tpm/{ek,srk,ak}` with the
fields in the body, and the NV reads, writes and undefines to the same
`/tpm/nvram/{index}` routes, the other fields (password, offset, size, data)
in the body. `POST /tpm/nvram` defines an index. `GET /tpm/pcrs` (parameters) and `POST /tpm/pcrs`
(body) both call `GetPCRs`. `POST /tpm/activate-credential` calls
`TPMService.ActivateCredential` (`credentialBlob`, `encryptedSecret` →
`secret`) under `tpm:write`, its gRPC twin's scope; the IDevID-shaped body it
used to take (`credential_blob`, `secret` → `decrypted`) is now a `400`.
`POST /tpm/certify` calls `TPMService.Certify` under `tpm:read`. The routes
with no `TPMService` RPC behind them — `capabilities`, `platform`,
`pcrs/extend`, `csr/idevid` and `POST /tpm/iak` — are not served by the daemon
listener. The daemon listener's
`/tpm/idevid*`, `/tpm/iak*` and `/tpm/device/attributes`
routes are its device-identity routes (`pkg/api/daemon/rest_idevid.go`), not
`TPMHandlers`, and carry no TPM scope. The cells in §3–§8 name the web service
routes.

---

## 2. Sub-opcode reference for the `0x99` category

The first payload byte selects the operation. Full constant list in
[engineering.md](engineering.md) §7.

| Sub-op | Constant | Sub-op | Constant |
|---|---|---|---|
| `0x01` | `SubOpTPM2Info` | `0x12` | `SubOpTPM2ExtendPCR` |
| `0x02` | `SubOpTPM2Provision` | `0x13` | `SubOpTPM2EventLog` |
| `0x03` | `SubOpTPM2Clear` | `0x14` | `SubOpTPM2Random` |
| `0x04` | `SubOpTPM2GetEK` | `0x15` | `SubOpTPM2Seal` |
| `0x05` | `SubOpTPM2CreateEK` | `0x16` | `SubOpTPM2Unseal` |
| `0x06` | `SubOpTPM2DeleteEK` | `0x17` | `SubOpTPM2Capabilities` |
| `0x07` | `SubOpTPM2GetEKCert` | `0x18` | `SubOpTPM2NVRead` |
| `0x08` | `SubOpTPM2ImportEKCert` | `0x19` | `SubOpTPM2NVWrite` |
| `0x09` | `SubOpTPM2GetSRK` | `0x1A` | `SubOpTPM2NVDelete` |
| `0x0A` | `SubOpTPM2CreateSRK` | `0x1B` | `SubOpTPM2NVList` |
| `0x0B` | `SubOpTPM2DeleteSRK` | `0x1C` | `SubOpTPM2IDevIDCSR` |
| `0x0C` | `SubOpTPM2GetIAK` | `0x1D` | `SubOpTPM2LDevIDCSR` |
| `0x0D` | `SubOpTPM2CreateIAK` | `0x1E` | `SubOpTPM2PlatformAttrs` |
| `0x0E` | `SubOpTPM2DeleteIAK` | `0x1F` | `SubOpTPM2GetIDevID` |
| `0x0F` | `SubOpTPM2Quote` | `0x20` | `SubOpTPM2MakeCred` |
| `0x10` | `SubOpTPM2VerifyQuote` | `0x21` | `SubOpTPM2ActivateCred` |
| `0x11` | `SubOpTPM2ReadPCRs` | `0x22` | `SubOpTPM2Certify` |

`0x1D` never reaches the TPM2 handler: `QUICServiceHandler.handleTPM2Category`
intercepts it and routes to the IDevID service, because LDevID issuance is
CA-backed.

---

## 3. Device and lifecycle

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| TPM info | `GET /api/v1/tpm/info` | `Info` | `0x99` · `0x01` | `platform_tpm_info` | ✅ |
| Provision | `POST /api/v1/tpm/provision` | `Provision` | `0x99` · `0x02` | `platform_tpm_provision` | ✅ |
| Clear | `POST /api/v1/tpm/clear` | `Clear` | `0x99` · `0x03` | `platform_tpm_clear` | ✅ |
| Capabilities | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `0x99` · `0x17` | `platform_tpm_capabilities` | `MISSING — docs/13 G7` |
| Platform attributes | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `0x99` · `0x1E` | `platform_tpm_platform` | `MISSING — docs/13 G7` |

**`Info` returns two views of the same thing.** `Properties["info"]` is
go-xkms's verbatim multi-line report; `Manufacturer`, `MaxNvramSize`,
`FipsMode`, `Capabilities` and the NV index list are the structured, canonical
fields. Parse the structured fields. If the underlying `FixedProperties` read
fails the call still succeeds with the text fallback and empty structured
fields — check for an empty `Manufacturer` before trusting them.

**`Info` also publishes the configured SRK handles**, so a client probes the real
handle instead of assuming the default. Every transport carries the same two
keys, as `0x%08X` strings, built by `tpmsrk.InfoProperties`: `platform_srk_handle`
(`tpm.platform-srk.srk-handle`, default `0x81000002`) and `ssrk_handle`
(`tpm.ssrk.handle`, default `0x81000001`). They are in `Properties` on gRPC/Unix,
REST (`properties`) and QUIC, and top-level keys of the MCP `platform_tpm_info`
result. A daemon that predates them omits the keys; clients fall back to the
default. `platformctl tpm status` uses `platform_srk_handle` for its PlatformSRK
row.

Request/response schemas: `TPMInfoRequest`/`TPMInfoResponse`,
`TPMProvisionRequest` (`owner_password`, `endorsement_password`, `create_ek`,
`create_srk`, `create_ak`, plus optional `KeyAttributes` for each) /
`TPMProvisionResponse` (`status`, `ek_public`, `srk_public`, `ak_public`,
`ek_certificate`), `TPMClearRequest` (`owner_password`, `confirm`) /
`TPMClearResponse`.

---

## 4. Keys

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Get EK | `GET /api/v1/tpm/ek` | `GetEK` | `0x99` · `0x04` | `platform_tpm_ek` | ✅ |
| Create EK | `POST /api/v1/tpm/ek` | `CreateEK` | `0x99` · `0x05` | `platform_tpm_ek_create` | ✅ |
| Delete EK | `DELETE /api/v1/tpm/ek` | `DeleteEK` | `0x99` · `0x06` | `platform_tpm_ek_delete` | ✅ |
| Get EK certificate | `GET /api/v1/tpm/ek/certificate` | `GetEKCertificate` | `0x99` · `0x07` | `platform_tpm_ek_cert` | ✅ |
| Import EK certificate | `POST /api/v1/tpm/ek/certificate` | `ImportEKCertificate` | `0x99` · `0x08` | `platform_tpm_ek_import_cert` | ✅ |
| Get SRK | `GET /api/v1/tpm/srk?handle=` | `GetSRK` | `0x99` · `0x09` | `platform_tpm_srk` (`handle` arg) | ✅ |
| Create SRK | `POST /api/v1/tpm/srk` | `CreateSRK` | `0x99` · `0x0A` | `platform_tpm_srk_create` | ✅ |
| Delete SRK | `DELETE /api/v1/tpm/srk` | `DeleteSRK` | `0x99` · `0x0B` | `platform_tpm_srk_delete` | ✅ |
| Get AK / IAK | `GET /api/v1/tpm/ak` | `GetAK` | `0x99` · `0x0C` (`GetIAK`) | `platform_tpm_iak` | ✅ |
| Create AK / IAK | `POST /api/v1/tpm/ak` | `CreateAK` | `0x99` · `0x0D` (`CreateIAK`) | `platform_tpm_iak_create` | ✅ |
| Delete AK / IAK | `DELETE /api/v1/tpm/ak` | `DeleteAK` | `0x99` · `0x0E` (`DeleteIAK`) | `platform_tpm_iak_delete` | ✅ |

**AK and IAK are the same key under two names.** gRPC and REST say `ak`; QUIC
and MCP say `iak`. A client author who learns one transport will not find the
capability on the other by name. Recorded in [engineering.md](engineering.md)
§13.

**`GetSRK` dispatches on the requested persistent handle, on every transport.**
The platform has two storage root keys and they are different keys: the
storage-hierarchy SSRK and the platform-hierarchy PlatformSRK that parents the
Platform KeyStore. All five transports resolve a handle identically, through the
single dispatch in `pkg/api/tpmsrk`:

| requested handle | resolves to |
|---|---|
| absent, or `0` | SSRK |
| `0x81000001` | SSRK |
| `0x81000002` | PlatformSRK |
| the configured `tpm.platform-srk.srk-handle` | PlatformSRK |
| the configured `tpm.ssrk.handle` | SSRK |
| anything else | **not found** — never a fall-through to the SSRK |

Each transport carries the handle in its own idiom: REST as the `?handle=`
query parameter (hex or decimal), gRPC/Unix in `GetSRKRequest.handle`, QUIC in
the `0x99` · `0x09` payload, MCP as the `handle` tool argument. A malformed
handle is rejected rather than defaulted, because `0` is itself a meaningful
handle: defaulting it would answer with the SSRK, which is a key the caller did
not ask for.

**This was not true before #475.** The REST, QUIC and MCP handlers took no
handle at all and answered every call from `SSRKAttributes`, so a request for
the PlatformSRK returned the SSRK with a success status, and the PlatformSRK
was unreachable on three of the five transports. Only gRPC, Unix and embedded
dispatched correctly.

**The default handles and the configured handles both resolve.** The dispatch
matches the defaults `0x81000001` / `0x81000002` and the handles the daemon is
configured with, which `Info` publishes (above). A request for any other handle is
not found even when that key exists. The response carries the handle the key
actually occupies (the configured one), so a caller that compares it against
the default it requested will misfire on any deployment that overrides it —
read the handle from `Info` instead.

Key algorithms across all transports: `RSA-2048`, `RSA-3072`, `RSA-4096`,
`ECDSA-P256`, `ECDSA-P384`, `ECDSA-P521` (`KeyAlgorithm` in
`sdk/go/services/tpm/types.go`).

---

## 5. Sealing, PCRs, attestation, entropy

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Seal | `POST /api/v1/tpm/seal` | `Seal` | `0x99` · `0x15` | `platform_tpm_seal` | ✅ |
| Unseal | `POST /api/v1/tpm/unseal` | `Unseal` | `0x99` · `0x16` | `platform_tpm_unseal` | ✅ |
| Read PCRs | `GET /api/v1/tpm/pcrs`, `POST /api/v1/tpm/pcrs` | `GetPCRs` | `0x99` · `0x11` | `platform_tpm_pcrs` | ✅ |
| **Extend PCR** | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `0x99` · `0x12` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Quote (TLS only — bound, see below) | `POST /api/v1/tpm/quote` | `Quote` (refused over Unix) | `0x99` · `0x0F` | `platform_tpm_quote` (refused over stdio) | refused — no TLS |
| Verify quote | `POST /api/v1/tpm/quote/verify` | `VerifyQuote` | `0x99` · `0x10` | `platform_tpm_verify_quote` | ✅ |
| Certify | `POST /api/v1/tpm/certify` | `Certify` | `0x99` · `0x22` | `platform_tpm_certify` | ✅ |
| Event log | `GET /api/v1/tpm/eventlog` | `GetEventLog` | `0x99` · `0x13` | `platform_tpm_eventlog` | ✅ |
| Get random | `POST /api/v1/tpm/random` | `GetRandom` | `0x99` · `0x14` | `platform_tpm_random` | ✅ |

`POST /api/v1/tpm/pcrs` is a deliberate alias of the `GET` handler, added
because the JavaScript SDK sends the index list and bank selection in a body.
Both dispatch to the same handler.

**Certify has one implementation (`pkg/api/tpmcertify`).** gRPC, Unix,
embedded and both REST servers reach it through `TPMService.Certify`; QUIC
`0x22` and MCP `platform_tpm_certify` call `tpmcertify.Certify` directly. It
calls the SDK's `TrustedPlatformModule.CertifyKey` (re-exported in
`sdk/go/xkms`), so the IAK signs a `TPMS_ATTEST` naming the key. The request
is `key_handle`, `key_password` (the key's authValue, empty for none) and
`nonce`. The handle must be persistent (`0x81000000`–`0x81FFFFFF`) and the
nonce at most 64 bytes: a zero handle, a transient handle or a longer nonce
is `InvalidArgument` and the TPM is not called. A handle the TPM does not
hold is `NotFound`, a daemon without a TPM is `Unavailable`, and any other
TPM failure is `Internal`. The configured IDevID is certified under its admin
policy. The reply carries `certify_info` (the `TPMS_ATTEST` bytes),
`signature`, `signature_algorithm` (its x509 name), `certify_info_signature`
(the marshalled `TPMT_SIGNATURE`), `attesting_key_public` and
`attested_key_public` (PKIX DER), the TPM public areas of both keys, and the
`nonce`. Every transport returns the same attestation and the same refusals
(`TestTPMCertifyParity_*`, `pkg/api/daemon/tpm_certify_parity_test.go`).

**PCR extend has one validator (`pkg/api/tpmpcr`).** QUIC `0x12` and MCP
`platform_tpm_pcr_extend` both call `tpmpcr.Extend`: the index must be 0–23
and the data non-empty (both `InvalidArgument`), and the bank defaults to
`sha256`. MCP takes the bank as `hash_alg`, QUIC as
`TPM2ExtendPCRRequest.hash_alg`.

**Extend PCR has no gRPC method behind it.** `TPMService` (`tpm.proto`) has
no extend RPC, so gRPC, REST and Unix cannot extend a PCR; QUIC `0x12` and
MCP `platform_tpm_pcr_extend` are the two transports that do. The MCP tool is
scoped `tpm:write`, the scope of the QUIC sub-op.

**A quote is bound to the connection it is requested over (#482).** The node
never quotes the nonce as sent: it derives the TLS exporter binding of the
connection the request arrived on, quotes `SHA-256(nonce ‖ channel_binding)`
and returns `channel_binding` so the caller can check the echo against its own
connection. A request with no TLS state (Unix, embedded, MCP over stdio, plain
HTTP) is refused with `ErrChannelBindingRequired` before the TPM is touched.
The SDK `tpm` client checks the echo with `sdk/go/quotebind` and refuses a
quote bound elsewhere (`quotebind.ErrQuoteNotBound` inside `ErrQuoteFailed`).
`VerifyQuote` takes the same optional `channel_binding` to recompute the
qualifying data; a passing verify is not channel proof. The contract and its
tests are in [attestation/api.md](../attestation/api.md) §5.1a.

**A quote is verified under the scheme it declares (#482).** `Quote` returns
`signature_algorithm`, the IAK's TPMT_SIGNATURE scheme as an
`x509.SignatureAlgorithm` name (`SHA256-RSAPSS`, `SHA256-RSA`,
`ECDSA-SHA256`), read from the IAK key attributes with
`vm.QuoteSignatureAlgorithm` before the TPM is asked to sign. An IAK that
declares no scheme is refused (gRPC `FailedPrecondition`) and no quote is
taken. `VerifyQuote` takes `signature_algorithm` back on every transport —
REST and gRPC/Unix through the proto field (`signatureAlgorithm` in the REST
protojson body), QUIC `TPM2VerifyQuoteRequest.signature_algorithm`, MCP
`platform_tpm_verify_quote` argument `signature_algorithm` — and checks the
signature with `vm.VerifyQuoteSignatureWithAlgorithm`. A missing, unknown or
mismatched scheme returns `verified: false` with
`signature_verification_failed: …`; nothing infers PKCS#1 v1.5 from an RSA
key any more, so an RSA-PSS IAK's quotes verify.

Schemas: `SealRequest` (`data`, `cn`, `parent_handle`, `parent_password`,
`password`, `pcr_indices`, `pcr_bank`, `overwrite`) / `SealResponse`
(`status`, `sealed_data`, `public_key`, `private_key`); `UnsealRequest`
(`cn`, `parent_handle`, `parent_password`, `password`, `pcr_indices`,
`pcr_bank`) / `UnsealResponse` (`status`, `data`); `QuoteRequest`
(`ak_handle`, `ak_password`, `pcr_indices`, `pcr_bank`, `nonce`) /
`QuoteResponse` (`status`, `quote`, `signature`, `pcr_values`, `event_log`,
`channel_binding`, `signature_algorithm`); `VerifyQuoteRequest` carries the
required `signature_algorithm` and an optional `channel_binding`.

**`ak_public` names the key that signed the quote, on every transport.** It is
the attestation key's PKIX DER — the `ak_public` proto field on REST and
gRPC/Unix (`akPublic` in the protojson body), raw bytes in QUIC
`TPM2VerifyQuoteRequest.ak_public`, and the base64 `platform_tpm_verify_quote`
argument `ak_public` on MCP. Left empty, the platform IAK verifies. The MCP
service provider (`MCPServiceProvider`) serves
the quote tools on the same `TPMGRPCService` as gRPC, so there is one quote
path and one verifier (`pkg/api/daemon/tpm_quote_tools.go`).

**The SDK `tpm` client reaches `Quote` and `VerifyQuote` on every transport.**
The SDK QUIC adapter routes both onto `0x99` · `0x0F` / `0x10`
(`sdk/go/transport/quic/tpm_quote.go`), encoding the `quicwire.TPM2Quote*`
bodies the server decodes, so `ak_public`, `channel_binding` and
`signature_algorithm` arrive on QUIC as they do on gRPC. The SDK MCP adapter
routes both onto `platform_tpm_quote` / `platform_tpm_verify_quote`
(`sdk/go/transport/mcp/tpm_quote.go`); the verify arguments are the proto's own
JSON names. Over Unix, MCP and embedded the SDK refuses `Quote` with
`transport.ErrChannelBindingUnavailable` inside `ErrQuoteFailed` and the TPM is
not touched; `VerifyQuote` works there. The
cross-transport tests are `pkg/api/daemon/tpm_quote_transport_parity_test.go`.

**Seal refuses `pcr_indices` on REST, gRPC, Unix and MCP.** PCR-bound sealing is
unavailable until go-quicbaas re-exports the TPM PolicyPCR primitives
(go-quicbaas #1171). Without them go-xkms would seal an object the PCRs do not
protect, so `Seal` returns `FailedPrecondition`. Unseal is unchanged. The
contract is in [engineering.md](engineering.md) §6.

**There is no `platform_policy` field on `SealRequest` on any transport.**
Sealing under the platform PCR policy is a server-side property of how the
parent key was created, not a per-request option. The CLI's `--policy` flag has
nowhere to go (see [cli.md](cli.md) §6).

**QUIC bounds:** random requests are capped at 1024 bytes
(`ErrTPM2InvalidNumBytes`); PCR indices must be 0–23
(`ErrTPM2InvalidPCRIndex`). Payloads are capped at `MaxPayloadSize` (16 MiB) —
see [`docs/daemon/api.md`](../daemon/api.md) §4.

---

## 6. NVRAM

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| **Define NV index** | `POST /api/v1/tpm/nvram` | `DefineNVRAM` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| Read NV index | `GET /api/v1/tpm/nvram/{index}` | `ReadNVRAM` | `0x99` · `0x18` | `platform_tpm_nv_read` | ✅ |
| Write NV index | `PUT /api/v1/tpm/nvram/{index}` | `WriteNVRAM` | `0x99` · `0x19` | `platform_tpm_nv_write` | ✅ |
| Undefine NV index | `DELETE /api/v1/tpm/nvram/{index}` | `UndefineNVRAM` | `0x99` · `0x1A` | `platform_tpm_nv_delete` | ✅ |
| **List NV indexes** | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `0x99` · `0x1B` | `platform_tpm_nv_list` | `MISSING — docs/13 G7` |

**Neither QUIC nor MCP can define an NV index.** Both can read, write and delete
one but cannot create it; a QUIC- or MCP-only client must have the index defined
for it through REST, gRPC or embedded. Conversely **only QUIC and MCP can list**
the defined indexes — though `Info`'s structured `NVIndex` list gives gRPC/REST
callers the same information indirectly.

Read, write and undefine share one implementation (`pkg/api/tpmnv`) on gRPC,
REST (through the gRPC service), QUIC and MCP, so validation and the
auth-hierarchy behaviour are identical on every transport: the index's own
public attributes select AUTHREAD / OWNERREAD / PPREAD. Index 0 and empty
write data are `InvalidArgument`, a TPM with no transport is `Unavailable`,
a read `size` of 0 reads the whole index, and a `size` past the end of the
index stops at the end. Offsets are 16-bit: gRPC and REST refuse an `offset`
above 65535 with `InvalidArgument` (`ErrNVOffsetOutOfRange`).
The MCP tools take `index`, `size`, `offset` and `password` (read), `index`,
`data`, `offset` and `password` (write), and `index` and `parent_password`
(delete) — the same fields as the proto and the QUIC structs.

**NV bounds.** `pkg/api/tpmnv` also refuses, with `InvalidArgument` and before
the TPM is touched, an index outside the NV handle range
`0x01000000`–`0x01FFFFFF` (`tpmnv.CheckIndex`) on read, write and undefine, and
a write whose offset plus data length runs past the 65535-byte NV offset space
(`tpmnv.CheckSpan`), so no chunk of it is written. A read needs no span check:
it is clamped to the index. gRPC `DefineNVRAM` applies the same index check
and refuses a `size` above 65535.

**REST NV routes.** The web service serves read, write and undefine only on
`/api/v1/tpm/nvram/{index}`, behind the admin gate like every `/tpm` route. The
index comes from the path (decimal or `0x` hex; one that does not parse is
`400`) and wins over any `index` in the body; the optional JSON body carries
the rest of the request — `password`, `offset`, `size` for a read, `data`,
`offset`, `password` for a write, `password`, `parentPassword` for an
undefine. A malformed body
is `400`.

---

## 7. Credential activation

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| MakeCredential | `MISSING — docs/13 G7` | `MakeCredential` | `0x99` · `0x20` | `platform_tpm_make_credential` | ✅ |
| ActivateCredential (TPMService) | `MISSING — docs/13 G7` | `ActivateCredential` | `0x99` · `0x21` | `platform_tpm_activate_credential` | ✅ |
| ActivateCredential (IDevIDService) | `POST /api/v1/idevid/activate-credential` | `IDevIDService.ActivateCredential` | `0x6E` (`OpActivateCredential`) | `MISSING — docs/13 G7` | ✅ |

**The MakeCredential/ActivateCredential pair is the proof-of-possession step in
device enrollment**. On REST the TPMService pair is served only by the daemon
listener (`POST /api/v1/tpm/make-credential` and
`POST /api/v1/tpm/activate-credential`, §1); the web service has neither. The
IDevID surface carries its own ActivateCredential, the one the web service
serves. Neither SDK has a REST client path for the TPMService pair: the
JavaScript SDK reaches only the IDevID one, and the Go SDK's REST adapter maps
neither RPC.

`TPM2MakeCredentialRequest` (QUIC) takes `ak_name`, `secret`, `ek_cert`,
`iak_pub`: with `ek_cert` and `iak_pub` present the **verifier** path runs;
otherwise the local EK is used with `ak_name`.

---

## 8. Device identity — IDevID, IAK, LDevID

REST base path `/api/v1/idevid`. QUIC uses **top-level** opcodes here, not the
`0x99` category.

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Generate IDevID | `POST /api/v1/idevid/generate` | `GenerateIDevID` | `0x56` | `idevid_generate` | ✅ |
| IDevID info | `GET /api/v1/idevid`, `GET /api/v1/idevid/info` | `GetIDevIDInfo` | `0x57` | `idevid_info` | ✅ |
| IDevID exists | `GET /api/v1/idevid/exists` | `HasIDevID` | `0x78` | `idevid_exists` | ✅ |
| Delete IDevID (refused, below) | `DELETE /api/v1/idevid`, `DELETE /api/v1/tpm/idevid` | `DeleteIDevID` | `0x58` | `idevid_delete` | ✅ |
| IDevID CSR | `POST /api/v1/idevid/csr` | `CreateIDevIDCSR` | `0x59`, also `0x99` · `0x1C` | `idevid_csr` | ✅ |
| Install IDevID certificate | `POST /api/v1/idevid/certificate` | `InstallIDevIDCertificate` | `0x5A` | `idevid_install_cert` | ✅ |
| Get IDevID certificate | `GET /api/v1/idevid/certificate` | `GetIDevIDCertificate` | `0x5B` | `idevid_get_cert` | ✅ |
| Delete IDevID certificate | `DELETE /api/v1/idevid/certificate` | `DeleteIDevIDCertificate` | `0x7A` | `idevid_delete_cert` | ✅ |
| Get IDevID public key | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `0x99` · `0x1F` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| **List expiring IDevIDs** | `GET /api/v1/idevid/expiring` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Generate IAK | `POST /api/v1/idevid/iak/generate` | `GenerateIAK` | `0x5C` | `iak_generate` | ✅ |
| IAK info | `GET /api/v1/idevid/iak` | `GetIAKInfo` | `0x5D` | `iak_info` | ✅ |
| IAK exists | `GET /api/v1/idevid/iak/exists` | `HasIAK` | `0x79` | `iak_exists` | ✅ |
| Delete IAK (refused, below) | `DELETE /api/v1/idevid/iak`, `DELETE /api/v1/tpm/iak` | `DeleteIAK` | `0x5E` | `iak_delete` | ✅ |
| IAK CSR | `POST /api/v1/idevid/iak/csr` | `CreateIAKCSR` | `0x5F` | `iak_csr` | ✅ |
| Install IAK certificate | `POST /api/v1/idevid/iak/certificate` | `InstallIAKCertificate` | `0x6B` | `iak_install_cert` | ✅ |
| Get IAK certificate | `GET /api/v1/idevid/iak/certificate` | `GetIAKCertificate` | `0x6C` | `iak_get_cert` | ✅ |
| Delete IAK certificate | `DELETE /api/v1/idevid/iak/certificate` | `DeleteIAKCertificate` | `0x7B` | `iak_delete_cert` | ✅ |
| Create LDevID | `POST /api/v1/idevid/ldevid` | `CreateLDevID` | `0x99` · `0x1D` | `idevid_create_ldevid` | ✅ |
| Device attributes | `GET /api/v1/idevid/attributes` | `GetDeviceAttributes` | `0x6D` | `MISSING — docs/13 G7` | ✅ |
| Flush transient contexts | `POST /api/v1/idevid/flush` | `FlushTransientContexts` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |

**`GET /api/v1/idevid/expiring` is REST-only and has no gRPC method behind
it.** It is the only certificate-expiry surface in the feature, and the only
way to reach it is HTTP.

**The Go SDK's REST adapter maps every `IDevIDService` RPC to the web
service's route above** (`sdk/go/transport/rest/adapter.go`; `CreateLDevID` in
`ldevid.go`) except `DeleteIDevID` and `DeleteIAK`, which go to the daemon
listener's `DELETE /api/v1/tpm/idevid` / `/api/v1/tpm/iak` so the refusal
below arrives as `412` and keeps its class. For every other RPC, `platformv1.NewIDevIDServiceClient` over
REST reaches the same
handlers a browser does (`TestSDKREST_*`,
`pkg/webservice/v1/rest/idevid/ldevid_test.go`). Until #452 the table named
seven RPCs that do not exist, and every real call except `CreateLDevID` fell
through to a derived path that answered `404`. `POST /api/v1/idevid/ldevid` is served by both the
web service and the daemon listener (`pkg/api/daemon/rest_idevid_ldevid.go`).

**Delete IDevID and Delete IAK are refused until the owner rules on
eviction.** No transport evicts the key, and none reports a deletion that did
not happen. gRPC and Unix `DeleteIDevID` / `DeleteIAK`, QUIC `0x58` / `0x5E`,
the MCP `idevid_delete` / `iak_delete` tools and REST
`DELETE /api/v1/tpm/idevid` / `DELETE /api/v1/tpm/iak` all refuse with
`FailedPrecondition` (`ErrDeviceIdentityKeyNotDeletable`) and change nothing —
no key, no certificate, no state (#304). Both REST servers serve those two
paths: the daemon listener and the web service, which also keeps its own
`DELETE /api/v1/idevid` / `DELETE /api/v1/idevid/iak` on the same handlers,
behind the admin role gate. On the wire the class is QUIC status `0x0C`
(`StatusFailedPrecondition`) and HTTP `412` on both REST servers: the daemon
listener's IDevID-family mapping, shared with LDevID, and on the web service
the key-delete handlers' own mapping, because `protorest`'s shared `400`
(#665) reaches the SDK as `InvalidArgument`, not the refusal. The SDK returns
`*idevid.ErrIdentityKeyNotDeletable`, and `platformctl tpm idevid delete` /
`platformctl tpm iak delete` exit `1` with the refusal. The certificate
deletes are real on every transport.

---

## 9. Authorization

Platform tokens carry an `scp` claim in the qrdb-canonical
`"<resource>:<action>"` form. Enforcement is per operation — gRPC
`RequireScope`, QUIC `AuthorizeRequest`, MCP `AuthorizeTool` — and **all three
catalogs are default-deny** ([`docs/daemon/api.md`](../daemon/api.md) §5).

| Surface | Coverage |
|---|---|
| gRPC `TPMService` | **every RPC scoped** in `pkg/api/grpc/method_permissions.go`: `tpm:read` for the observers plus `Quote`, `VerifyQuote`, `Certify`, `ReadNVRAM`, `Unseal` and `MakeCredential`; `tpm:write` for `ActivateCredential`, the `Create*` calls, `DefineNVRAM`, `WriteNVRAM`, `ImportEKCertificate`, `Provision` and `Seal`; `tpm:delete` for `DeleteAK`, `DeleteEK`, `DeleteSRK`, `UndefineNVRAM` and `Clear` |
| gRPC `IDevIDService` | **every RPC scoped**: `idevid:read` for the `Get*` / `Has*` calls; `idevid:write` for CSR, generate, install, `CreateLDevID`, `ActivateCredential` and `FlushTransientContexts`; `idevid:delete` for the four `Delete*` calls |
| MCP — `platform_tpm_quote`, `platform_tpm_verify_quote`, `platform_tpm_certify` | **scoped `tpm:read`** in `pkg/api/mcp/authz.go`, the scope of their gRPC twins |
| MCP — `platform_tpm_nv_*` tools | **scoped** in `pkg/api/mcp/authz.go` on their gRPC twins' tiers: `tpm:read` for `nv_list` (`Info`) and `nv_read`, `tpm:write` for `nv_write`, `tpm:delete` for `nv_delete` |
| MCP — `platform_tpm_pcr_extend` | **scoped `tpm:write`** in `pkg/api/mcp/authz.go`, the scope of QUIC's `SubOpTPM2ExtendPCR` (it has no gRPC twin) |
| MCP — `platform_tpm_*` tools with a gRPC twin | **scoped** in `pkg/api/mcp/authz.go` on the gRPC tiers (#304), except `platform_tpm_unseal`, which needs `tpm:write`; the table is in [api-reference-mcp.md](api-reference-mcp.md) |
| MCP — `platform_tpm_capabilities`, `platform_tpm_platform` | **scoped** `tpm:read` (#304): each answers a subset of gRPC `Info` (the fixed properties; the config and the EK/SRK/IAK attributes), and their QUIC twins `0x17` and `0x1E` are `tpm:read` |
| MCP — `platform_tpm_{ek,srk,iak}_delete` | **refused**: not in `pkg/api/mcp/authz.go`, so `AuthorizeTool` answers `AuthErrorToolNotClassified` for every caller. The deletes flush a persistent handle, which deletes nothing |
| MCP — `idevid_*` / `iak_*` tools | **scoped** in `pkg/api/mcp/authz.go` with their gRPC twins' scopes, IAK tools included: `idevid:read` for info, exists and get-cert; `idevid:write` for generate, CSR, install-cert and `idevid_create_ldevid`; `idevid:delete` for the deletes. The tools call the shared `IDevIDGRPCService`, so each answers with its gRPC message and error class (#304) |
| MCP — `device_attributes`, `activate_credential` | **scoped** `idevid:read` and `idevid:write`, the scopes of gRPC `GetDeviceAttributes` and `IDevIDService/ActivateCredential` (#304). They make the same TPM calls as those methods but answer with the MCP provider's errors, not the gRPC status |
| QUIC `0x99` category | **every sub-opcode scoped** in `pkg/api/quic/opcode_permissions.go`, which is fail-closed: `tpm:read` for the observers plus `Quote`, `VerifyQuote`, `Certify`, `Unseal`, `MakeCred` and the NV reads; `tpm:write` for `Provision`, the `Create*` calls, `ImportEKCert`, `ExtendPCR`, `Seal`, `NVWrite`, the IDevID CSR and `ActivateCred`; `tpm:delete` for `Clear`, the `Delete*` calls and `NVDelete`. The exception is `LDevIDCSR` (`0x1D`): the daemon serves it with `IDevIDService.CreateLDevID`, so it takes `idevid:write` |
| QUIC device-identity opcodes | **scoped** with their gRPC `IDevIDService` twins' scopes (#304): `idevid:read` for info, has, get-cert and device attributes; `idevid:write` for generate, CSR, install-cert and activate-credential; `idevid:delete` for the deletes. One `idevid:*` grant covers the same operation on gRPC, QUIC and MCP |
| REST — web service | route-level middleware only; no per-operation TPM scope (below) |
| REST — daemon listener, `TPMHandlers` | **every route scoped** in `TPMHandlers.routes` (`pkg/api/rest/tpm_handlers.go`), on the gRPC tiers: `tpm:read` for the `GET` routes plus `POST pcrs`, `quote`, `quote/verify`, `certify`, `make-credential`, `random` and `unseal`; `tpm:write` for `provision`, `POST ek`, `POST ek/certificate`, `POST srk`, `POST ak`, `POST`/`PUT nvram`, `seal` and `activate-credential`; `tpm:delete` for `clear` and every `DELETE` (`ek`, `srk`, `ak`, `nvram`, with or without the path parameter). The bearer token is checked by the shared platform-token validator: no token is `401` (`ErrTPMTokenRequired`), a token without the scope or no validator configured is `403` (`ErrTPMForbidden`) |
| REST — daemon listener, `rest_idevid.go` | no per-operation scope; mTLS only |

**Concretely: on gRPC, `Clear` and `DeleteEK` need `tpm:delete`, `Unseal`
needs `tpm:read`, and `DeleteIDevID` needs `idevid:delete`.** Note that
`Unseal` sits in the read tier. On MCP `platform_tpm_unseal` needs `tpm:write`,
and `idevid_delete` needs `idevid:delete` as on gRPC. On QUIC, `SubOpTPM2Clear` needs
`tpm:delete` and `SubOpTPM2Unseal` `tpm:read`, matching gRPC.

### Web service REST is gated on the `admin` role (#165)

`/api/v1/tpm/**` requires an authenticated caller holding `admin` — including
`POST /tpm/clear`, `POST /tpm/provision`, EK/SRK/AK create and delete,
seal/unseal and the NVRAM define/write/undefine routes. Reads are gated with
the writes: the event log, the PCR banks and NVRAM contents describe the
platform's measured state, which is what an attacker preparing to forge a
quote reads first.

`/api/v1/idevid/**` — the node's own IDevID and IAK, their CSRs and
certificate install/delete, LDevID issuance, and `activate-credential` — is gated the same
way. It is the identity every other node authenticates this one by.

Until #165 both surfaces answered callers with no token at all. See
[`docs/auth/architecture.md`](../auth/architecture.md) §6c. **This does not
change the gRPC or MCP positions above.**

---

## 10. Status and error mapping

QUIC status bytes are the platform-wide vocabulary
([`docs/daemon/api.md`](../daemon/api.md) §4). TPM-specific causes:

| QUIC byte | Name | REST | gRPC | TPM cause |
|---|---|---|---|---|
| `0x00` | `StatusOK` | 200 | `OK` | — |
| `0x01` | `StatusInvalidRequest` | 400 | `InvalidArgument` | `ErrTPM2MissingSubOpcode`, `ErrTPM2MissingData`, `ErrTPM2MissingCN`, `ErrTPM2MissingCertificate`, `ErrTPM2MissingCredentialBlob`, `ErrTPM2MissingEncryptedSecret`, `ErrTPM2DecodingFailed`, `ErrTPM2InvalidNumBytes`, `ErrTPM2InvalidPCRIndex` |
| `0x02` | `StatusNotFound` | 404 | `NotFound` | upstream error text matching `not found` / `does not exist` / `no such` |
| `0x03` | `StatusUnauthorized` | 401 | `Unauthenticated` | Token invalid |
| `0x04` | `StatusInternalError` | 500 | `Internal` | `ErrTPM2OperationFailed`, `ErrTPM2EncodingFailed`, anything unclassified |
| `0x06` | `StatusAlreadyExists` | 409 | `AlreadyExists` | upstream text matching `already exists` / `duplicate` |
| `0x07` | `StatusPermissionDenied` | 403 | `PermissionDenied` | upstream text matching `permission` / `denied` / `unauthorized` / `forbidden` / `authorization` |
| `0x0A` | `StatusUnavailable` | 503 | `Unavailable` | `ErrTPM2ServiceNotAvailable` — **the daemon has no TPM handle** |
| `0x0B` | `StatusNotImplemented` | 501 | `Unimplemented` | `ErrTPM2UnknownSubOpcode` |
| — | — | — | `FailedPrecondition` | upstream text matching `TPM` / `tpm` / `handle` |

**503 on any TPM operation means the daemon has no TPM**, not that the operation
failed. Check `platformctl tpm status` and the `"TPM target resolved"` log line
before looking at anything else.

**gRPC status codes are derived by substring matching on the upstream error
message** (`TPMGRPCService.mapError`, [engineering.md](engineering.md) §6). They
are advisory. Do not build client control flow on the difference between
`FailedPrecondition` and `Internal`.

Panics in a QUIC handler are recovered into `StatusInternalError`; gRPC has the
equivalent in `pkg/api/daemon/recovery_interceptor.go`.

---

## 11. Versioning

REST under `/api/v1`; gRPC package `platform.v1`; QUIC `ProtocolVersion` `0x01`.
Nothing in this feature is deprecated.

## 12. Related

- [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [user.md](user.md)
- [`docs/daemon/api.md`](../daemon/api.md) — transports, framing, opcodes, the
  authorization picture
- [`docs/vtpm/api.md`](../vtpm/api.md) — the virtual-TPM transport matrix
- [`docs/attestation/api.md`](../attestation/api.md) — what consumes a quote
