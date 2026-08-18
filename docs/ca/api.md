# Certificate Authority — API

> **Status: NORMATIVE** · Scope: CA and ACME routes on every transport · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING`, never omitted.

---

## 1. The six transports

`sdk/go/protocol.go` declares six: `ProtocolEmbedded`, `ProtocolUnix`,
`ProtocolGRPC`, `ProtocolREST`, `ProtocolQUIC`, `ProtocolMCP`. **Unix is gRPC
over a Unix domain socket**, so gRPC and Unix share a column.
`ServiceRegistry.CA` carries the service in-process.

gRPC: `CAService`, 12 RPCs (`pkg/api/grpc/proto/ca.proto`).
REST: base path `/api/v1/ca` (`pkg/webservice/v1/rest/ca/router.go`), plus the
ACME protocol routes (§3).
QUIC: nine top-level opcodes, `0xA0`–`0xA8`.
MCP: nine `ca_*` tools.

---

## 2. Capability matrix

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| CA info | `GET /api/v1/ca/info` | `GetCAInfo` | `OpCAInfo` (`0xA0`) | `ca_info` | ✅ |
| Initialise the CA | `MISSING — docs/13 G7` | `InitCA` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| Install CA certificates | `MISSING — docs/13 G7` | `InstallCACertificates` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| Uninstall CA certificates | `MISSING — docs/13 G7` | `UninstallCACertificates` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| Issue certificate | `POST /api/v1/ca/certificates` | `IssueCertificate` | `OpCAIssue` (`0xA1`) | `ca_issue` | ✅ |
| List certificates | `GET /api/v1/ca/certificates` | `ListCertificates` | `OpCAList` (`0xA5`) | `ca_list` | ✅ |
| Get certificate | `GET /api/v1/ca/certificates/{serial}` | `GetCertificate` | `OpCAGet` (`0xA4`) | `ca_get` | ✅ |
| Revoke certificate | `DELETE /api/v1/ca/certificates/{serial}` | `RevokeCertificate` | `OpCARevoke` (`0xA2`) | `ca_revoke` | ✅ |
| Renew certificate | `MISSING — docs/13 G7` | `RenewCertificate` | `OpCARenew` (`0xA3`) | `ca_renew` | ✅ |
| Verify certificate | `MISSING — docs/13 G7` | `VerifyCertificate` | `OpCAVerify` (`0xA6`) | `ca_verify` | ✅ |
| Get CRL | `GET /api/v1/ca/crl` | `GetCRL` | `OpCACRL` (`0xA7`) | `ca_crl` | ✅ |
| Get CA bundle | `GET /api/v1/ca/bundle` | `GetCABundle` | `OpCABundle` (`0xA8`) | `ca_bundle` | ✅ |
| Get bootstrap bundle | `GET /api/v1/ca/bootstrap` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | — |
| Get root certificate | `GET /api/v1/ca/root` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | — |
| Get intermediate certificate | `GET /api/v1/ca/intermediate` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | — |

Two shapes:

- **Renew and verify are missing from REST** while present on gRPC, QUIC, MCP
  and embedded. So is the whole CA administration set (`InitCA`,
  `InstallCACertificates`, `UninstallCACertificates`), which is gRPC and
  embedded only.
- **Three REST routes have no counterpart anywhere else**: `/ca/root`,
  `/ca/intermediate`, `/ca/bootstrap`. They serve raw trust material to clients
  that have none yet, which is why they are HTTP-only — a client that cannot
  establish trust cannot use a mutually authenticated transport.

**Revocation is `DELETE .../{serial}`, not `POST .../{serial}/revoke`.** An
earlier planning document specified the `POST` form; the code registers `DELETE`.

---

## 3. ACME (RFC 8555)

`pkg/webservice/v1/router/acme.go` implements the protocol server. **REST only —
by specification, not as a gap.** ACME clients speak HTTP.

| Route group | Purpose |
|---|---|
| `directory` | Service directory |
| `newNonce` | Anti-replay nonce |
| `newAccount` | Account registration |
| `accounts` | Account management |
| `newOrder` | New certificate order |
| `listOrders` / `getOrder` | Order state |
| `finalizeOrder` | CSR submission |
| `authorization` | Authorization state |
| `challenge` | Challenge response |
| `certificate` | Certificate download |
| `revokeCert` | Revocation |
| `keyChange` | Account key rollover |
| `bundle` | CA bundle |

**Every route above is rate-limited**, threading a
`*trustedca.ACMERateLimiter`; `newAccount` has its own separate limiter. The one
exception is `bundle`, which publishes public trust material.

The challenge types this platform's device enrollment relies on — `endorse-01`,
`enroll-01`, `device-attest-01` — are **go-xkms's** to implement; this repository
hosts the server.

---

## 4. Authorization

**`CAService` is in the gRPC scope catalog** with all 12 methods mapped —
resource `ca`, actions `read`/`write`/`delete`. It is one of only eleven services
in the catalog, and one of the few with complete coverage.

**None of the nine `ca_*` MCP tools is in the MCP authorization map.** Of 449
declared tool names, 71 carry a permission; the CA tools are not among them, and
`AuthorizeTool` allows a tool absent from the map once the token validates.

So `IssueCertificate` over gRPC requires `ca:write`, while `ca_issue` over MCP
requires nothing beyond a valid token. **Certificate issuance is the highest-value
operation in the platform.** Raised as an owner question in the migration report.

ACME authenticates by its own protocol mechanisms (account keys, EAB) rather
than by platform tokens.

---

## 5. Status and error mapping

| QUIC byte | Name | REST | CA cause |
|---|---|---|---|
| `0x00` | `StatusOK` | 200 | — |
| `0x01` | `StatusInvalidRequest` | 400 | Malformed CSR or serial |
| `0x02` | `StatusNotFound` | 404 | Unknown serial |
| `0x03` | `StatusUnauthorized` | 401 | Token invalid; ACME account unknown |
| `0x04` | `StatusInternalError` | 500 | Signing or keystore failure |
| `0x06` | `StatusAlreadyExists` | 409 | CA already initialised |
| `0x07` | `StatusPermissionDenied` | 403 | Missing `ca:*` scope |
| `0x08` | `StatusResourceExhausted` | 429 | **ACME rate limit** |
| `0x0A` | `StatusUnavailable` | 503 | CA not wired into the daemon |

429 on an ACME route is the rate limiter doing its job, not a fault.

---

## 6. Known defect

`pkg/webservice/v1/rest/ca/handlers.go:715` records that the proto
`IssueCertificateRequest` carries **no explicit field** for something the REST
handler needs. The REST issuance path and the gRPC message are therefore not
fully aligned. Check the code before assuming a field exists on either side.

---

## 7. Versioning

Platform routes under `/api/v1`; gRPC package `platform.v1`. ACME routes follow
RFC 8555's own directory-driven shape and are not versioned by the platform.
Nothing deprecated.
