# Physical TPM 2.0 — API

> **Status: NORMATIVE** · Scope: TPM and device-identity routes on every transport · Last verified: 2026-08-18
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
| gRPC | `TPMService`, **27 RPCs** (`pkg/api/grpc/proto/tpm.proto`); `IDevIDService`, **20 RPCs** (`idevid.proto`) |
| Embedded | `ServiceRegistry.TPM` (`platformv1.TPMServiceServer`) and `ServiceRegistry.IDevID` — the embedded adapter dispatches gRPC method strings, so **embedded coverage equals gRPC coverage exactly** |
| REST | `/api/v1/tpm` (`pkg/webservice/v1/rest/tpm/router.go`) and `/api/v1/idevid` (`pkg/webservice/v1/rest/idevid/router.go`) |
| QUIC | category opcode `OpTPM2Category` = **`0x99`**, sub-opcode in `payload[0]` (`pkg/api/quic/tpm_handlers.go`); device identity uses **top-level** opcodes `0x56`–`0x5F`, `0x6B`–`0x6E`, `0x78`–`0x7B` |
| MCP | 31 `platform_tpm_*` tools (`pkg/api/mcp/tpm_tools.go`) plus 17 `idevid_*` / `iak_*` tools (`idevid_tools.go`, `ldevid_tools.go`) |

**A second REST surface exists and is not served.** `pkg/api/rest/tpm_handlers.go`
registers `/api/v1/tpm/make-credential`, `/activate-credential`, `/certify`,
`/capabilities`, `/pcrs/extend`, `/nv/read`, `/nv/write`, `/nv/define`, `/nv`,
`/csr/idevid`, `/csr/ldevid`, `/platform` and `/idevid`. `NewTPMHandlers` is
constructed only in its own tests. **Do not document, call, or build against
those paths.** Only the routes in §3–§8 below are reachable.

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
| `0x11` | `SubOpTPM2ReadPCRs` | | |

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
| **Extend PCR** | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `0x99` · `0x12` | `platform_tpm_pcr_extend` | `MISSING — docs/13 G7` |
| Quote | `POST /api/v1/tpm/quote` | `Quote` | `0x99` · `0x0F` | `platform_tpm_quote` | ✅ |
| Verify quote | `POST /api/v1/tpm/quote/verify` | `VerifyQuote` | `0x99` · `0x10` | `platform_tpm_verify_quote` | ✅ |
| **Certify** | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `platform_tpm_certify` | `MISSING — docs/13 G7` |
| Event log | `GET /api/v1/tpm/eventlog` | `GetEventLog` | `0x99` · `0x13` | `platform_tpm_eventlog` | ✅ |
| Get random | `POST /api/v1/tpm/random` | `GetRandom` | `0x99` · `0x14` | `platform_tpm_random` | ✅ |

`POST /api/v1/tpm/pcrs` is a deliberate alias of the `GET` handler, added
because the JavaScript SDK sends the index list and bank selection in a body.
Both dispatch to the same handler.

**Certify exists on MCP alone.** One transport out of six, with no gRPC method
behind it to grow into.

Schemas: `SealRequest` (`data`, `cn`, `parent_handle`, `parent_password`,
`password`, `pcr_indices`, `pcr_bank`, `overwrite`) / `SealResponse`
(`status`, `sealed_data`, `public_key`, `private_key`); `UnsealRequest`
(`cn`, `parent_handle`, `parent_password`, `password`, `pcr_indices`,
`pcr_bank`) / `UnsealResponse` (`status`, `data`); `QuoteRequest`
(`ak_handle`, `ak_password`, `pcr_indices`, `pcr_bank`, `nonce`) /
`QuoteResponse` (`status`, `quote`, `signature`, `pcr_values`, `event_log`).

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

All four NV operations share one wire implementation (`pkg/api/tpmnv`), so the
auth-hierarchy behaviour is identical on every transport: the index's own public
attributes select AUTHREAD / OWNERREAD / PPREAD.

---

## 7. Credential activation

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| MakeCredential | `MISSING — docs/13 G7` | `MakeCredential` | `0x99` · `0x20` | `platform_tpm_make_credential` | ✅ |
| ActivateCredential (TPMService) | `MISSING — docs/13 G7` | `ActivateCredential` | `0x99` · `0x21` | `platform_tpm_activate_credential` | ✅ |
| ActivateCredential (IDevIDService) | `POST /api/v1/idevid/activate-credential` | `IDevIDService.ActivateCredential` | `0x6E` (`OpActivateCredential`) | `MISSING — docs/13 G7` | ✅ |

**The MakeCredential/ActivateCredential pair is the proof-of-possession step in
device enrollment**, and it is **absent from REST on the TPMService surface**.
The IDevID surface carries its own ActivateCredential, which is the one REST
clients can reach.

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
| Delete IDevID | `DELETE /api/v1/idevid` | `DeleteIDevID` | `0x58` | `idevid_delete` | ✅ |
| IDevID CSR | `POST /api/v1/idevid/csr` | `CreateIDevIDCSR` | `0x59`, also `0x99` · `0x1C` | `idevid_csr` | ✅ |
| Install IDevID certificate | `POST /api/v1/idevid/certificate` | `InstallIDevIDCertificate` | `0x5A` | `idevid_install_cert` | ✅ |
| Get IDevID certificate | `GET /api/v1/idevid/certificate` | `GetIDevIDCertificate` | `0x5B` | `idevid_get_cert` | ✅ |
| Delete IDevID certificate | `DELETE /api/v1/idevid/certificate` | `DeleteIDevIDCertificate` | `0x7A` | `idevid_delete_cert` | ✅ |
| Get IDevID public key | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `0x99` · `0x1F` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| **List expiring IDevIDs** | `GET /api/v1/idevid/expiring` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Generate IAK | `POST /api/v1/idevid/iak/generate` | `GenerateIAK` | `0x5C` | `iak_generate` | ✅ |
| IAK info | `GET /api/v1/idevid/iak` | `GetIAKInfo` | `0x5D` | `iak_info` | ✅ |
| IAK exists | `GET /api/v1/idevid/iak/exists` | `HasIAK` | `0x79` | `iak_exists` | ✅ |
| Delete IAK | `DELETE /api/v1/idevid/iak` | `DeleteIAK` | `0x5E` | `iak_delete` | ✅ |
| IAK CSR | `POST /api/v1/idevid/iak/csr` | `CreateIAKCSR` | `0x5F` | `iak_csr` | ✅ |
| Install IAK certificate | `POST /api/v1/idevid/iak/certificate` | `InstallIAKCertificate` | `0x6B` | `iak_install_cert` | ✅ |
| Get IAK certificate | `GET /api/v1/idevid/iak/certificate` | `GetIAKCertificate` | `0x6C` | `iak_get_cert` | ✅ |
| Delete IAK certificate | `DELETE /api/v1/idevid/iak/certificate` | `DeleteIAKCertificate` | `0x7B` | `iak_delete_cert` | ✅ |
| **Create LDevID** | `MISSING — docs/13 G7` | `CreateLDevID` | `0x99` · `0x1D` | `idevid_create_ldevid` | ✅ |
| Device attributes | `GET /api/v1/idevid/attributes` | `GetDeviceAttributes` | `0x6D` | `MISSING — docs/13 G7` | ✅ |
| Flush transient contexts | `POST /api/v1/idevid/flush` | `FlushTransientContexts` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |

Two asymmetries worth naming:

- **`GET /api/v1/idevid/expiring` is REST-only and has no gRPC method behind
  it.** It is the only certificate-expiry surface in the feature, and the only
  way to reach it is HTTP.
- **LDevID has no REST route.** It is the newest identity verb and the one
  operators are most likely to want from a browser or a script.

---

## 9. Authorization

Platform tokens carry an `scp` claim in the qrdb-canonical
`"<resource>:<action>"` form. Enforcement is per operation — gRPC
`RequireScope`, QUIC `AuthorizeRequest`, MCP `AuthorizeTool` — and **all three
catalogs are default-deny** ([`docs/daemon/api.md`](../daemon/api.md) §5).

| Surface | Coverage |
|---|---|
| gRPC `TPMService` | **every RPC scoped** in `pkg/api/grpc/method_permissions.go`: `tpm:read` for the observers plus `Quote`, `VerifyQuote`, `ReadNVRAM`, `Unseal` and `MakeCredential`; `tpm:write` for `ActivateCredential`, the `Create*` calls, `DefineNVRAM`, `WriteNVRAM`, `ImportEKCertificate`, `Provision` and `Seal`; `tpm:delete` for `DeleteAK`, `DeleteEK`, `DeleteSRK`, `UndefineNVRAM` and `Clear` |
| gRPC `IDevIDService` | **every RPC scoped**: `idevid:read` for the `Get*` / `Has*` calls; `idevid:write` for CSR, generate, install, `CreateLDevID`, `ActivateCredential` and `FlushTransientContexts`; `idevid:delete` for the four `Delete*` calls |
| MCP — `platform_tpm_*` tools | **refused**: not in `pkg/api/mcp/authz.go`, so `AuthorizeTool` answers `AuthErrorToolNotClassified` for every caller |
| MCP — `idevid_*` / `iak_*` tools | **refused**, likewise |
| QUIC `0x99` category | **every sub-opcode scoped** in `pkg/api/quic/opcode_permissions.go`, which is fail-closed: `tpm:read` for the observers plus `Quote`, `VerifyQuote`, `Unseal`, `MakeCred` and the NV reads; `tpm:write` for `Provision`, the `Create*` calls, `ImportEKCert`, `ExtendPCR`, `Seal`, `NVWrite`, the IDevID / LDevID CSRs and `ActivateCred`; `tpm:delete` for `Clear`, the `Delete*` calls and `NVDelete` |
| QUIC device-identity opcodes | **scoped under `tpm:*`**, not `idevid:*` as on gRPC: `tpm:read` for info and get-cert, `tpm:write` for generate, CSR and install-cert, `tpm:delete` for the deletes ([engineering.md](engineering.md) §13) |
| REST | route-level middleware only; no per-operation TPM scope |

**Concretely: on gRPC, `Clear` and `DeleteEK` need `tpm:delete`, `Unseal`
needs `tpm:read`, and `DeleteIDevID` needs `idevid:delete`.** Note that
`Unseal` sits in the read tier. On MCP none of the TPM or device-identity tools
can be called until they are classified. On QUIC, `SubOpTPM2Clear` needs
`tpm:delete` and `SubOpTPM2Unseal` `tpm:read`, matching gRPC.

### REST is gated on the `admin` role (#165)

`/api/v1/tpm/**` requires an authenticated caller holding `admin` — including
`POST /tpm/clear`, `POST /tpm/provision`, EK/SRK/AK create and delete,
seal/unseal and the NVRAM define/write/undefine routes. Reads are gated with
the writes: the event log, the PCR banks and NVRAM contents describe the
platform's measured state, which is what an attacker preparing to forge a
quote reads first.

`/api/v1/idevid/**` — the node's own IDevID and IAK, their CSRs and
certificate install/delete, and `activate-credential` — is gated the same
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
Nothing in this feature is deprecated. The unserved routes in
`pkg/api/rest/tpm_handlers.go` (§1) are not a deprecated version of anything —
they were never wired.

## 12. Related

- [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [user.md](user.md)
- [`docs/daemon/api.md`](../daemon/api.md) — transports, framing, opcodes, the
  authorization picture
- [`docs/vtpm/api.md`](../vtpm/api.md) — the virtual-TPM transport matrix
- [`docs/attestation/api.md`](../attestation/api.md) — what consumes a quote
