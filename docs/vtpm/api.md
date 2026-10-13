# Virtual TPM — API

> **Status: NORMATIVE** · Scope: vTPM routes on every transport · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING`, never omitted.

---

## 1. The six transports

`sdk/go/protocol.go` declares six: `ProtocolEmbedded`, `ProtocolUnix`,
`ProtocolGRPC`, `ProtocolREST`, `ProtocolQUIC`, `ProtocolMCP`. **Unix is gRPC
over a Unix domain socket**, so gRPC and Unix share a column.
`ServiceRegistry.VTPM` carries the service in-process.

gRPC: `VTPMService`, 23 RPCs (`pkg/api/grpc/proto/vtpm.proto`).
REST: base path `/api/v1/vtpm` (`pkg/webservice/v1/rest/vtpm/router.go`).
QUIC: **two top-level ranges** — `0x03`–`0x0F` for templates and bundles,
`0x10`–`0x1F` for runtime operations (`sdk/go/wire/quicwire/protocol.go`).

---

## 2. Templates

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Create template | `POST /api/v1/vtpm/templates` | `CreateTemplate` | `OpVTPMCreateTemplate` (`0x03`) | `vtpm_template_create` | ✅ |
| Get template | `GET /api/v1/vtpm/templates/{id}` | `GetTemplate` | `OpVTPMGetTemplate` (`0x04`) | `vtpm_template_get` | ✅ |
| Delete template | `DELETE /api/v1/vtpm/templates/{id}` | `DeleteTemplate` | `OpVTPMDeleteTemplate` (`0x05`) | `vtpm_template_delete` | ✅ |
| List templates | `GET /api/v1/vtpm/templates` | `ListTemplates` | `OpVTPMListTemplates` (`0x06`) | `vtpm_template_list` | ✅ |
| Clone template → bundle | `POST /api/v1/vtpm/templates/{id}/clone` | `CloneTemplate` | `OpVTPMCloneTemplate` (`0x07`) | `vtpm_template_clone` | ✅ |

Complete on all five reachable transports.

---

## 3. Bundles

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Create bundle | `POST /api/v1/vtpm/bundles` | `CreateBundle` | `OpVTPMCreate` (`0x10`) | `vtpm_bundle_create`, `vtpm_create` | ✅ |
| Get bundle | `GET /api/v1/vtpm/bundles/{id}` | `GetBundle` | `OpVTPMGetBundle` (`0x0E`) | `vtpm_bundle_get`, `vtpm_get` | ✅ |
| List bundles | `GET /api/v1/vtpm/bundles` | `ListBundles` | `OpVTPMList` (`0x15`) | `vtpm_bundle_list`, `vtpm_list` | ✅ |
| Delete bundle | `DELETE /api/v1/vtpm/bundles/{id}` | `DeleteBundle` | `OpVTPMDelete` (`0x11`) | `vtpm_bundle_delete`, `vtpm_delete` | ✅ |
| Export bundle | `GET /api/v1/vtpm/bundles/{id}/export` | `ExportBundle` (server stream) | `OpVTPMExportBundle` (`0x08`) | `vtpm_export` | ✅ |
| Import bundle | `POST /api/v1/vtpm/bundles/import` | `ImportBundle` (client stream) | `OpVTPMImportBundle` (`0x09`) | `vtpm_import` | ✅ |
| Validate bundle | `POST /api/v1/vtpm/bundles/{id}/validate` | `ValidateBundle` | `OpVTPMValidateBundle` (`0x0A`) | `vtpm_validate` | ✅ |
| Bundle path | `GET /api/v1/vtpm/bundles/{id}/path` | `GetBundlePath` | `OpVTPMGetBundlePath` (`0x0B`) | `vtpm_get_bundle_path` | ✅ |
| TPM socket path | `GET /api/v1/vtpm/bundles/{id}/tpm-socket` | `GetTPMSocketPath` | `OpVTPMGetSocketPath` (`0x0C`) | `vtpm_get_tpm_socket_path` | ✅ |
| NVRAM path | `GET /api/v1/vtpm/bundles/{id}/nvram` | `GetNVRAMPath` | `OpVTPMGetNVRAMPath` (`0x0D`) | `vtpm_get_nvram_path` | ✅ |

Note the REST import route is `POST /api/v1/vtpm/bundles/import` and is
registered **before** the `{id}` routes, so `import` is not swallowed as a
bundle id.

---

## 4. Runtime operations

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Start vTPM | `MISSING — docs/13 G7` | `StartVTPM` | `OpVTPMStart` (`0x12`) | `vtpm_start` | ✅ |
| Stop vTPM | `MISSING — docs/13 G7` | `StopVTPM` | `OpVTPMStop` (`0x13`) | `vtpm_stop` | ✅ |
| Is running | `MISSING — docs/13 G7` | `IsVTPMRunning` | `OpVTPMIsRunning` (`0x0F`) | `vtpm_is_running` | ✅ |
| Get state | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpVTPMGetState` (`0x14`) | `MISSING — docs/13 G7` | — |
| Quote | `MISSING — docs/13 G7` | `QuoteVTPM` | `OpVTPMQuote` (`0x19`) | `vtpm_bundle_quote`, `vtpm_quote` | ✅ |
| Verify quote | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpVTPMVerifyQuote` (`0x1A`) | `MISSING — docs/13 G7` | — |
| Seal | `MISSING — docs/13 G7` | `SealVTPM` | `OpVTPMSeal` (`0x1D`) | `vtpm_bundle_seal`, `vtpm_seal` | ✅ |
| Unseal | `MISSING — docs/13 G7` | `UnsealVTPM` | `OpVTPMUnseal` (`0x1E`) | `vtpm_bundle_unseal`, `vtpm_unseal` | ✅ |
| Extend PCR | `MISSING — docs/13 G7` | `ExtendVTPMPCR` | `OpVTPMExtendPCR` (`0x1B`) | `vtpm_bundle_pcr_extend`, `vtpm_extend_pcr` | ✅ |
| Read PCR | `MISSING — docs/13 G7` | `ReadVTPMPCR` | `OpVTPMReadPCR` (`0x1C`) | `vtpm_bundle_pcr_read`, `vtpm_read_pcr` | ✅ |
| Get EK | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpVTPMGetEK` (`0x16`) | `MISSING — docs/13 G7` | — |
| Get AK | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpVTPMGetAK` (`0x17`) | `MISSING — docs/13 G7` | — |
| Create AK | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpVTPMCreateAK` (`0x18`) | `MISSING — docs/13 G7` | — |
| Get random | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpVTPMGetRandom` (`0x1F`) | `MISSING — docs/13 G7` | — |

**Not one runtime operation is on REST.** REST carries the whole
template/bundle *management* surface and none of the *runtime* surface — no
start, no stop, no quote, no seal, no PCR. An operator on REST can create a
vTPM bundle and cannot start it.

Five operations (get state, verify quote, get EK, get AK, create AK, get random)
are **QUIC-only** — no gRPC, no REST, no MCP.

---

## 5. The MCP surface is duplicated, and the two halves authorize differently

Same pattern as DNS ([`docs/dns/api.md`](../dns/api.md) §3), and here it lands on
key operations.

| Older family (in the authorization map) | Newer family (**not** in the map) |
|---|---|
| `vtpm_create` → `vtpm:write` | `vtpm_bundle_create` |
| `vtpm_delete` → `vtpm:delete` | `vtpm_bundle_delete` |
| `vtpm_list` → `vtpm:read` | `vtpm_bundle_list` |
| `vtpm_quote` → `vtpm:read` | `vtpm_bundle_quote` |
| `vtpm_seal` → `vtpm:write` | `vtpm_bundle_seal` |
| `vtpm_unseal` → `vtpm:read` | `vtpm_bundle_unseal` |
| `vtpm_extend_pcr` → `vtpm:write` | `vtpm_bundle_pcr_extend` |
| `vtpm_read_pcr` → `vtpm:read` | `vtpm_bundle_pcr_read` |
| `vtpm_start` → `vtpm:write`, `vtpm_stop` → `vtpm:write` | — |
| — | all `vtpm_template_*`, `vtpm_export`, `vtpm_import`, `vtpm_validate`, `vtpm_get*`, `vtpm_is_running` |

`AuthorizeTool` (`pkg/api/mcp/authz.go`) is default-deny (#300): a tool absent
from the map is refused with `AuthErrorToolNotClassified` whatever scopes the
token holds. **`vtpm_seal` requires `vtpm:write`; `vtpm_bundle_seal` is refused
for every caller. `vtpm_unseal` requires `vtpm:read`; `vtpm_bundle_unseal` is
refused likewise.**

The newer names do not work over MCP until they are classified. Which family is
canonical is the same open question as DNS.

---

## 6. Authorization

Both catalogs are **default-deny**
([`docs/auth/architecture.md`](../auth/architecture.md)).

**`VTPMService` is fully scoped on gRPC** with 23 methods mapped — resource
`vtpm`, actions `read`/`write`/`delete`. `UnsealVTPM` sits in the read tier.

On MCP, ten vTPM tool names carry a permission; the rest are refused. See §5.

### REST is gated on the `admin` role (#165)

`/api/v1/vtpm/**` requires an authenticated caller holding `admin`. A vTPM
bundle carries the sealed state of a guest's virtual TPM, so create, import,
export, validate and delete are all privileged, as are the NVRAM and
tpm-socket reads on a bundle.

Until #165 the surface answered callers with no token at all. See
[`docs/auth/architecture.md`](../auth/architecture.md) §6c. **This does not
change the gRPC or MCP positions above.**

---

## 7. Status and error mapping

| QUIC byte | Name | REST | vTPM cause |
|---|---|---|---|
| `0x00` | `StatusOK` | 200 | — |
| `0x01` | `StatusInvalidRequest` | 400 | `ErrInvalidManifest`, `ErrMissingHostname` |
| `0x02` | `StatusNotFound` | 404 | `ErrVTPMNotFound`, `ErrBundleNotFound`, `ErrTemplateNotFound` |
| `0x03` | `StatusUnauthorized` | 401 | Token invalid |
| `0x04` | `StatusInternalError` | 500 | `ErrGenerationFailed`, `ErrEKGenerationFailed`, `ErrSRKGenerationFailed`, `ErrEKCertInjectionFailed`, `ErrSecureBootEnrollmentFailed`, `ErrSWTPMOperationFailed` |
| `0x06` | `StatusAlreadyExists` | 409 | `ErrVTPMAlreadyExists`, `ErrBundleAlreadyExists`, `ErrTemplateAlreadyExists` |
| `0x07` | `StatusPermissionDenied` | 403 | Missing `vtpm:*` scope; `ErrTPMDeviceOpenFailed` on permissions |
| `0x09` | `StatusInvalidArgument` | 400 | `ErrInvalidEKAlgorithm`, `ErrUnknownTPMTarget`, `ErrNotCharDevice`, `ErrNotUnixSocket`, `ErrNilTPMConfig` |
| `0x0A` | `StatusUnavailable` | 503 | `ErrSwtpmSocketUnavailable`, `ErrHardwareTPMUnavailable`, `ErrNoTPMDetected` |

**The EK algorithm is `RSA` or `ECC`, in any letter case, and nothing else.**
Bundle and template creation parse `ek_algorithm` (`algorithm` on the MCP
`vtpm_create` and `vtpm_template_create` tools) the same way on every
transport. An omitted or empty value, or `EK_ALGORITHM_UNSPECIFIED` on gRPC,
takes the daemon's configured `ek-algorithm`. Any other value — `ECDSA`
included, which is not an alias — is `ErrInvalidEKAlgorithm`: 400 on REST,
`StatusInvalidArgument` on QUIC, `InvalidArgument` on gRPC and MCP. Before #460
an unrecognized value silently became RSA.

**503 on a runtime operation usually means the swtpm daemon is not running**
(`ErrSwtpmSocketUnavailable`) — start the bundle before quoting it.

QUIC payloads are capped at `MaxPayloadSize` (16 MiB), which is why bundle
export and import are streaming on gRPC.

---

## 8. Versioning

REST under `/api/v1`; gRPC package `platform.v1`. Nothing deprecated. The
duplicated MCP families in §5 await an owner ruling.
