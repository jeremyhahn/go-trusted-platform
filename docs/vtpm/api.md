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

`GET /api/v1/vtpm/bundles` filters on the query parameters `mode`, `labels`
(repeated, each `key=value`), `limit`, `offset` and `device_profile_id`. `mode`
takes `template` or `pre-assigned`, or the gRPC enum names
`BUNDLE_MODE_TEMPLATE` and `BUNDLE_MODE_PRE_ASSIGNED` that the SDK sends; the
create body's `mode` accepts the same. A `labels` value without `=` or an
empty key, or a `device_profile_id` that is not an unsigned integer, is 400.
Create takes `device_profile_id`, and every manifest returns it.

---

## 4. Runtime operations

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Start vTPM | `POST /api/v1/vtpm/bundles/{id}/start` | `StartVTPM` | `OpVTPMStart` (`0x12`) | `vtpm_start` | ✅ |
| Stop vTPM | `POST /api/v1/vtpm/bundles/{id}/stop` | `StopVTPM` | `OpVTPMStop` (`0x13`) | `vtpm_stop` | ✅ |
| Is running | `GET /api/v1/vtpm/bundles/{id}/state` | `IsVTPMRunning` | `OpVTPMIsRunning` (`0x0F`) | `vtpm_is_running` | ✅ |
| Get state | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpVTPMGetState` (`0x14`) | `MISSING — docs/13 G7` | — |
| Quote | `POST /api/v1/vtpm/bundles/{id}/quote` | `QuoteVTPM` | `OpVTPMQuote` (`0x19`) | `vtpm_bundle_quote`, `vtpm_quote` | ✅ |
| Verify quote | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpVTPMVerifyQuote` (`0x1A`) | `MISSING — docs/13 G7` | — |
| Seal | `POST /api/v1/vtpm/bundles/{id}/seal` | `SealVTPM` | `OpVTPMSeal` (`0x1D`) | `vtpm_bundle_seal`, `vtpm_seal` | ✅ |
| Unseal | `POST /api/v1/vtpm/bundles/{id}/unseal` | `UnsealVTPM` | `OpVTPMUnseal` (`0x1E`) | `vtpm_bundle_unseal`, `vtpm_unseal` | ✅ |
| Extend PCR | `POST /api/v1/vtpm/bundles/{id}/pcrs/extend` | `ExtendVTPMPCR` | `OpVTPMExtendPCR` (`0x1B`) | `vtpm_bundle_pcr_extend`, `vtpm_extend_pcr` | ✅ |
| Read PCR | `GET /api/v1/vtpm/bundles/{id}/pcrs?pcr_index=N` | `ReadVTPMPCR` | `OpVTPMReadPCR` (`0x1C`) | `vtpm_bundle_pcr_read`, `vtpm_read_pcr` | ✅ |
| Get EK | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpVTPMGetEK` (`0x16`) | `MISSING — docs/13 G7` | — |
| Get AK | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpVTPMGetAK` (`0x17`) | `MISSING — docs/13 G7` | — |
| Create AK | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpVTPMCreateAK` (`0x18`) | `MISSING — docs/13 G7` | — |
| Get random | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `OpVTPMGetRandom` (`0x1F`) | `MISSING — docs/13 G7` | — |

**REST carries every runtime operation gRPC carries.** The bundle id is the
`{id}` path segment and never appears in the body. Request and reply bodies use
the gRPC message field names in snake_case, with bytes base64-encoded, so the
SDK REST transport sends and decodes the `platform.v1` messages unchanged:

| Route | Body | Reply payload |
|---|---|---|
| `POST …/{id}/start` | — | `status`, `bundle_id`, `running`, `socket_path` |
| `POST …/{id}/stop` | — | `status`, `bundle_id`, `stopped` |
| `GET …/{id}/state` | — | `bundle_id`, `running`, `socket_path`; 404 for an unknown bundle |
| `POST …/{id}/quote` | `nonce`, `pcrs` | `status`, `bundle_id`, `quote`, `signature`, `pcr_values`, `hash_algorithm` |
| `POST …/{id}/seal` | `data`, `pcrs`, `auth_value` | `status`, `bundle_id`, `sealed_data` |
| `POST …/{id}/unseal` | `sealed_data`, `auth_value` | `status`, `bundle_id`, `data` |
| `POST …/{id}/pcrs/extend` | `pcr_index`, `data` | `status`, `bundle_id`, `pcr_index`, `extended` |
| `GET …/{id}/pcrs?pcr_index=N` | — | `status`, `bundle_id`, `pcr_index`, `value` |

Read PCR names the index in the query, not the path, because PCR 0 is a valid
index and the SDK leaves a zero value out of the request; an absent
`pcr_index` reads PCR 0. The handlers are in
`pkg/webservice/v1/rest/vtpm/runtime.go` and call the same `vtpm.VTPMService`
as gRPC and QUIC.

Six operations (get state, verify quote, get EK, get AK, create AK, get random)
are **QUIC-only** — no gRPC, no REST, no MCP.

---

## 5. The MCP surface is duplicated; each `vtpm_bundle_*` tool runs its `vtpm_*` twin

Nine bundle operations have two MCP names. The `vtpm_bundle_*` name keeps its
documented argument names, and the dispatcher renames them to the twin's
(`vtpmBundleAliases`, `pkg/api/mcp/vtpm_tools_exec.go`). The call then runs the
twin's executor against the same `vtpm.VTPMService` backend, and it carries
the twin's scope in `toolPermissionCatalog` (`pkg/api/mcp/authz.go`):

| `vtpm_bundle_*` tool | Twin | gRPC method | Scope | Arguments renamed for the twin |
|---|---|---|---|---|
| `vtpm_bundle_create` | `vtpm_create` | `CreateBundle` | `vtpm:write` | `hostname` → `name`, `ek_algorithm` → `algorithm` |
| `vtpm_bundle_get` | `vtpm_get` | `GetBundle` | `vtpm:read` | `bundle_id` → `name` |
| `vtpm_bundle_list` | `vtpm_list` | `ListBundles` | `vtpm:read` | none |
| `vtpm_bundle_delete` | `vtpm_delete` | `DeleteBundle` | `vtpm:delete` | `bundle_id` → `name` |
| `vtpm_bundle_quote` | `vtpm_quote` | `QuoteVTPM` | `vtpm:read` | `bundle_id` → `name` |
| `vtpm_bundle_seal` | `vtpm_seal` | `SealVTPM` | `vtpm:write` | `bundle_id` → `name` |
| `vtpm_bundle_unseal` | `vtpm_unseal` | `UnsealVTPM` | `vtpm:read` | `bundle_id` → `name`, `sealed_data` → `sealed` |
| `vtpm_bundle_pcr_extend` | `vtpm_extend_pcr` | `ExtendVTPMPCR` | `vtpm:write` | `bundle_id` → `name`, `pcr_index` → `pcr` |
| `vtpm_bundle_pcr_read` | `vtpm_read_pcr` | `ReadVTPMPCR` | `vtpm:read` | `bundle_id` → `name`, `pcr_index` → `pcr` |

`vtpm_start` and `vtpm_stop` (`vtpm:write`) have no `vtpm_bundle_*` twin.

The alias and its twin give the same result and the same error for the same
request, because they run the same code. Only the documented name selects the
bundle: a twin-named argument sent to an alias (`name` to `vtpm_bundle_get`)
is dropped, not used. Bad input is `InvalidArgument` before the backend runs.
That covers an unknown EK algorithm, an unknown list `mode`, a negative `limit`
or `offset`, and a nonce, data or sealed blob that is not base64. An unknown
bundle is the backend's `ErrBundleNotFound`. A daemon with no vTPM service
answers `ErrServiceNotAvailable` (`Unavailable`), never success; gRPC leaves
`VTPMService` unregistered then, so it answers `Unimplemented`.

Both names take the options gRPC carries: `secure_boot_enabled` and `labels` on
create, and `mode`, `labels`, `limit` and `offset` on list. Seal and unseal take
`auth_value`. An absent `limit` lists every bundle, as gRPC does.

The tools with no duplicate carry the scope of their gRPC method (#304), and
fail with the same gRPC class as that method:

| Tools | Scope |
|---|---|
| `vtpm_validate`, `vtpm_export`, `vtpm_get_bundle_path`, `vtpm_get_tpm_socket_path`, `vtpm_get_nvram_path`, `vtpm_is_running`, `vtpm_template_get`, `vtpm_template_list` | `vtpm:read` |
| `vtpm_import`, `vtpm_template_create`, `vtpm_template_clone` | `vtpm:write` |
| `vtpm_template_delete` | `vtpm:delete` |

`vtpm_export` sits in the read tier because gRPC `ExportBundle` does, although
the archive is key material ([user.md](user.md), "Moving a vTPM"). `vtpm_validate` answers
`valid: false` for an absent bundle, as gRPC `ValidateBundle` does.

---

## 6. Authorization

Both catalogs are **default-deny**
([`docs/auth/architecture.md`](../auth/architecture.md)).

**`VTPMService` is fully scoped on gRPC** with 23 methods mapped — resource
`vtpm`, actions `read`/`write`/`delete`. `UnsealVTPM` sits in the read tier.

On MCP, all 32 vTPM tool names carry a permission. Each of the nine
`vtpm_bundle_*` names carries the scope of its `vtpm_*` twin. See §5.

### REST is gated on the `admin` role (#165)

`/api/v1/vtpm/**` requires an authenticated caller holding `admin`. A vTPM
bundle carries the sealed state of a guest's virtual TPM, so create, import,
export, validate and delete are all privileged, as are the NVRAM and
tpm-socket reads on a bundle. The runtime routes in §4 sit behind the same
gate: no vTPM route is reachable without `admin`.

**REST has no read/write tiers.** The gRPC and MCP tiers (unseal in `read`,
seal in `write`) do not apply on REST. `admin` is the only gate, so reading a
PCR and sealing under a bundle need the same role.

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

The REST runtime routes (§4) also return:

- 404 for `ErrBundleNotFound`.
- 409 for `ErrVTPMNotRunning` or `ErrVTPMAlreadyRunning`: the bundle is not in
  the state the operation needs. gRPC answers `FailedPrecondition` for both,
  never `Internal`.
- 400 for `ErrInvalidNonce`, `ErrInvalidPCRIndex`, or a `pcr_index` query value
  that is not an integer.

QUIC payloads are capped at `MaxPayloadSize` (16 MiB), which is why bundle
export and import are streaming on gRPC.

---

## 8. Versioning

REST under `/api/v1`; gRPC package `platform.v1`. Nothing deprecated. Both MCP
families in §5 are served; which one is canonical awaits an owner ruling.
