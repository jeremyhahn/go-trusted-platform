# TPM REST API Reference

> **Status: REFERENCE** · Last verified: 2026-10-15
> The `/api/v1/tpm` routes of platformd's REST listener. The cross-transport
> contract is [api.md](api.md).

Base URL: `https://localhost:8443/api/v1/tpm`

These are the routes platformd's own REST listener serves through
`restapi.TPMHandlers` (`pkg/api/rest/tpm_handlers.go`). The web service's
`/api/v1/tpm` router is described in [api.md](api.md) §3–§8.

Every route needs the mTLS client certificate the listener asks for **and** a
platform bearer token (`Authorization: Bearer <token>`) granting the route's
scope ([api.md](api.md) §9):

| Scope | Routes |
|-------|--------|
| `tpm:read` | every `GET`, plus `POST pcrs`, `quote`, `quote/verify`, `certify`, `make-credential`, `random`, `unseal` |
| `tpm:write` | `POST provision`, `ek`, `ek/certificate`, `srk`, `ak`, `activate-credential`, `nvram`, `pcrs/extend`, `seal`; `PUT nvram` |
| `tpm:delete` | `POST clear`, every `DELETE` |

`GET`/`DELETE /iak`, `GET`/`DELETE /idevid` and `GET /device/attributes` are
the listener's device-identity routes (`pkg/api/daemon/rest_idevid.go`); they
take no token and are not described here, except for one rule: `DELETE /idevid`
and `DELETE /iak` are refused until the owner rules on eviction. They answer
`412 Precondition Failed` — the listener's status for the gRPC class
`FailedPrecondition`, the class every other transport returns — and change
nothing: no key, no certificate, no state (#304). The certificates have their
own `DELETE /idevid/cert` and `DELETE /iak/cert`, which do delete and answer
in gRPC's classes (#704): no TPM is `412`, a missing certificate `404`, any
other TPM failure `500` (api.md §8). The web
service serves the same two `DELETE` paths, behind its admin role gate, with
the same `412` and the same error message
(`pkg/webservice/v1/rest/idevid/router.go`).

The listener also serves `POST /api/v1/idevid/ldevid` (`CreateLDevID`,
`rest_idevid_ldevid.go`), the same path the web service serves. The web
service's `/api/v1/idevid` routes — the ones the Go SDK's REST adapter maps for
every `IDevIDService` RPC except `DeleteIDevID` and `DeleteIAK`, which it sends
to the listener's `DELETE /api/v1/tpm/idevid` and `/api/v1/tpm/iak` so the
refusal keeps its class — are in [api.md](api.md) §8.

## Wire contract

Every route calls one RPC of the daemon's `TPMService` — the service gRPC,
Unix and embedded call — and speaks that RPC's messages
(`pkg/api/grpc/proto/tpm.proto`):

- **Request.** The body is the RPC's request message as protojson. Each field
  may be spelled with its camelCase JSON name (`pcrIndices`, what the
  JavaScript SDK sends) or its proto name (`pcr_indices`, what the Go SDK
  sends); enums by name (`PCR_BANK_SHA256`) or number (`2`); bytes as base64.
  An empty body is the empty request.
- **Parameters.** Query and path parameters set fields of the same message, by
  either name. A `uint32` takes decimal or `0x` hex (`0x81000002`), an enum its
  name or number, a bool `true`/`false`, and a repeated field one parameter per
  element (`?indices=0&indices=7`). A path parameter wins over a query
  parameter of the same name. Bytes and message fields travel only in the body.
- **Refusals.** A field the message does not have is `400`, in the body
  (`unknown field "x"`) or as a parameter (`ErrInvalidQueryParameter`), and
  so is a parameter that does not parse or a single-valued field given twice.
  The TPM is not touched.
- **Response.** The bare protojson response message, camelCase keys, every
  field present (empty lists `[]`, empty maps `{}`, unset messages `null`).

## Routes

| Route | RPC | Request fields (body, or parameters where shown) |
|-------|-----|------|
| `GET /info` | `Info` | none |
| `GET /capabilities` | `GetCapabilities` | none |
| `GET /platform` | `GetPlatformAttributes` | none |
| `POST /provision` | `Provision` | `ownerPassword`, `endorsementPassword`, `createEk`, `createSrk`, `createAk`, `ekAttributes`, `srkAttributes`, `akAttributes` |
| `POST /clear` | `Clear` | `ownerPassword`, `confirm` |
| `GET /ek` | `GetEK` | `?algorithm=&handle=` |
| `POST /ek` | `CreateEK` | `attributes`, `persistent` |
| `DELETE /ek`, `DELETE /ek/{handle}` | `DeleteEK` | `handle`, `algorithm`, `password` |
| `GET /ek/certificate` | `GetEKCertificate` | `?algorithm=&handle=` |
| `POST /ek/certificate` | `ImportEKCertificate` | `certificate` (DER, base64), `format`, `nvramIndex` |
| `GET /srk` | `GetSRK` | `?algorithm=&handle=` |
| `POST /srk` | `CreateSRK` | `attributes`, `persistent`, `parentHandle`, `parentPassword` |
| `DELETE /srk`, `DELETE /srk/{handle}` | `DeleteSRK` | `handle`, `algorithm`, `password` |
| `GET /ak` | `GetAK` | `?algorithm=&handle=` |
| `POST /ak` | `CreateAK` | `attributes`, `persistent`, `parentHandle`, `parentPassword` |
| `DELETE /ak`, `DELETE /ak/{handle}` | `DeleteAK` (refused, `412`) | `handle`, `algorithm`, `password` (ignored) |
| `POST /make-credential` | `MakeCredential` | `akName`, `secret`, `ekCert`, `iakPub` |
| `POST /activate-credential` | `ActivateCredential` | `credentialBlob`, `encryptedSecret` |
| `POST /quote` | `Quote` | `akHandle`, `akPassword`, `pcrIndices`, `pcrBank`, `nonce` |
| `POST /quote/verify` | `VerifyQuote` | `quote`, `signature`, `signatureAlgorithm`, `akPublic`, `nonce`, `expectedPcrs`, `channelBinding`, … |
| `POST /certify` | `Certify` | `keyHandle`, `keyPassword`, `nonce` |
| `GET /pcrs`, `POST /pcrs` | `GetPCRs` | `indices`, `bank` (`GET`: `?indices=0&indices=7&bank=PCR_BANK_SHA256`) |
| `POST /pcrs/extend` | `ExtendPCR` | `index` (0-23), `hashAlg` (default `sha256`), `data` (base64, not empty) |
| `GET /eventlog` | `GetEventLog` | `?format=` |
| `POST /nvram` | `DefineNVRAM` | `index`, `size`, `password`, `attributes`, `parentPassword` |
| `GET /nvram`, `GET /nvram/{index}` | `ReadNVRAM` | `index`, `password`, `offset`, `size` (`?offset=&size=` on the path form) |
| `PUT /nvram`, `PUT /nvram/{index}` | `WriteNVRAM` | `index`, `data`, `password`, `offset` |
| `DELETE /nvram`, `DELETE /nvram/{index}` | `UndefineNVRAM` | `index`, `parentPassword`, `password` |
| `POST /random` | `GetRandom` | `numBytes` |
| `POST /seal` | `Seal` | `data`, `cn`, `parentHandle`, … |
| `POST /unseal` | `Unseal` | `cn`, `parentHandle`, `parentPassword`, `password`, `pcrIndices`, `pcrBank` |

The path forms (`/ek/{handle}`, `/nvram/{index}`) are what the JavaScript SDK
calls. The Go SDK sends `DeleteEK`, `DeleteSRK` and `DeleteAK` to the bare
route with the fields in the body, and `ReadNVRAM`, `WriteNVRAM` and
`UndefineNVRAM` to `/nvram/{index}` with the index in the path and the other
fields in the body — the web service serves only that form.

`DELETE /ak` and `DELETE /ak/{handle}` are refused: `DeleteAK` names the IAK,
which is not evicted, so it answers `FailedPrecondition` as `DELETE
/api/v1/tpm/iak` does, and both REST servers send it as `412` with the typed
error's message rather than the shared `400` (#704). Any other `DeleteAK`
failure takes the shared mapping. The TPM is not touched.

### Info

`Info` reports the TPM's identity and the configured SRK handles
([api.md](api.md) §3). `manufacturer` is `null` when the fixed properties
could not be read; the text report in `properties.info` is still returned.

```json
{
  "version": "TPM_VERSION_2_0",
  "manufacturer": { "name": "Infineon", "id": 1229346816, "model": "SLB9670", "firmwareVersion": "7.85" },
  "capabilities": [{ "name": "SHA256", "supported": true, "value": "supported" }],
  "pcrBanks": ["PCR_BANK_SHA256"],
  "maxNvramSize": 2048,
  "isSimulator": false,
  "fipsMode": true,
  "properties": { "info": "...", "platform_srk_handle": "0x81000002", "ssrk_handle": "0x81000001" },
  "nvIndexes": [{ "handle": 29360130, "type": "ordinary", "size": 1024, "authRead": true, "authWrite": false }]
}
```

There is no availability flag. A TPM is available exactly when this call
succeeds; without one the daemon answers `503 Service Unavailable`.

### Quote and verify

```json
POST /api/v1/tpm/quote
{ "nonce": "dGVzdG5vbmNl", "pcrIndices": [0, 7], "pcrBank": "PCR_BANK_SHA256" }

200 OK
{
  "quote": "…", "signature": "…", "signatureAlgorithm": "SHA256-RSAPSS",
  "pcrValues": [], "eventLog": "…", "channelBinding": "…"
}
```

The quote covers `SHA-256(nonce ‖ channel_binding)`, where `channel_binding` is
the TLS exporter of the connection the request arrived on; a request over
plain HTTP is refused. `POST /quote/verify` takes the quote, the
`signatureAlgorithm` the quote declared, `akPublic` and the same `nonce` and
`channelBinding`. A quote that does not verify is still `200 OK`, with
`verified: false` and the reason in `message`. See [api.md](api.md) §5.

## Error responses

A refused request, or an RPC error, is the standard error body:

```json
{ "error": "invalid query parameter handle=\"persistent\": not a valid uint32", "code": 400, "timestamp": "2026-10-13T10:30:00Z" }
```

| Status | Cause |
|--------|-------|
| `400 Bad Request` | A malformed or unknown body field (`ErrInvalidRequestBody`) or URL parameter (`ErrInvalidQueryParameter`); the RPC's `InvalidArgument` or `FailedPrecondition` |
| `401 Unauthorized` | No bearer token (`ErrTPMTokenRequired`); the RPC's `Unauthenticated` |
| `403 Forbidden` | The token is rejected or lacks the route's scope, or no token validator is configured (`ErrTPMForbidden`); the RPC's `PermissionDenied` |
| `404 Not Found` | The RPC's `NotFound` |
| `409 Conflict` | The RPC's `AlreadyExists` or `Aborted` |
| `412 Precondition Failed` | `DELETE /ak` and `DELETE /ak/{handle}`: the RPC's `FailedPrecondition` |
| `500 Internal Server Error` | Any other RPC error, or a response that cannot be encoded |
| `501 Not Implemented` | The RPC's `Unimplemented` |
| `503 Service Unavailable` | No TPM service (`ErrTPMServiceNotAvailable`), or the RPC's `Unavailable` |
| `504 Gateway Timeout` | The RPC's `DeadlineExceeded` |

## cURL examples

```bash
AUTH=(--cacert ca.crt --cert client.crt --key client.key -H "Authorization: Bearer $TOKEN")

# TPM info
curl "${AUTH[@]}" https://localhost:8443/api/v1/tpm/info

# The SRK at a given handle
curl "${AUTH[@]}" "https://localhost:8443/api/v1/tpm/srk?handle=0x81000002"

# Read PCRs 0 and 7 from the SHA-256 bank
curl "${AUTH[@]}" "https://localhost:8443/api/v1/tpm/pcrs?indices=0&indices=7&bank=PCR_BANK_SHA256"

# Quote
curl "${AUTH[@]}" -H "Content-Type: application/json" \
  -d '{"nonce":"dGVzdG5vbmNl","pcrIndices":[0,7]}' \
  https://localhost:8443/api/v1/tpm/quote

# Read 32 bytes of an NV index
curl "${AUTH[@]}" "https://localhost:8443/api/v1/tpm/nvram/0x1c00002?size=32"

# Random bytes
curl "${AUTH[@]}" -H "Content-Type: application/json" \
  -d '{"numBytes":32}' https://localhost:8443/api/v1/tpm/random
```
