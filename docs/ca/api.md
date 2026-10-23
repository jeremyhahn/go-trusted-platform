# Certificate Authority — API

> **Status: NORMATIVE** · Scope: CA and ACME routes on every transport · Last verified: 2026-10-09
> Conflicts with this document are defects. Fix them here first.
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING`, never omitted.

---

## 1. The six transports

`sdk/go/protocol.go` declares six: `ProtocolEmbedded`, `ProtocolUnix`,
`ProtocolGRPC`, `ProtocolREST`, `ProtocolQUIC`, `ProtocolMCP`. **Unix is gRPC
over a Unix domain socket**, so gRPC and Unix share a column.
`ServiceRegistry.CA` carries the service in-process.

gRPC: `CAService`, 13 RPCs (`pkg/api/grpc/proto/ca.proto`).
REST: base path `/api/v1/ca` (`pkg/webservice/v1/rest/ca/router.go`), plus the
ACME protocol routes (§3).
QUIC: nine top-level opcodes, `0xA0`–`0xA8`, plus Sign CSR under the KMS
extended category (`0xCD`, sub-opcode `0x07`).
MCP: ten `ca_*` tools.

---

## 2. Capability matrix

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| CA info | `GET /api/v1/ca/info` | `GetCAInfo` | `OpCAInfo` (`0xA0`) | `ca_info` | ✅ |
| Initialise the CA | `MISSING — docs/13 G7` | `InitCA` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| Install CA certificates | `MISSING — docs/13 G7` | `InstallCACertificates` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| Uninstall CA certificates | `MISSING — docs/13 G7` | `UninstallCACertificates` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ |
| Issue certificate | `POST /api/v1/ca/certificates` | `IssueCertificate` | `OpCAIssue` (`0xA1`) | `ca_issue` | ✅ |
| Sign CSR (certify a KMS key for code signing) | `POST /api/v1/ca/sign-csr` | `SignCSR` | `OpKMSExtendedCategory` (`0xCD`) sub `KMSSubSignCSR` (`0x07`) | `ca_sign_csr` | ✅ |
| List certificates | `GET /api/v1/ca/certificates` | `ListCertificates` | `OpCAList` (`0xA5`) | `ca_list` | ✅ |
| Get certificate | `GET /api/v1/ca/certificates/{serial}` | `GetCertificate` | `OpCAGet` (`0xA4`) | `ca_get` | ✅ |
| Revoke certificate | `DELETE /api/v1/ca/certificates/{serial}` | `RevokeCertificate` | `OpCARevoke` (`0xA2`) | `ca_revoke` | ✅ |
| Renew certificate | `POST /api/v1/ca/certificates/{serial}/renew` | `RenewCertificate` | `OpCARenew` (`0xA3`) | `ca_renew` | ✅ |
| Verify certificate | `POST /api/v1/ca/certificates/verify` | `VerifyCertificate` | `OpCAVerify` (`0xA6`) | `ca_verify` | ✅ |
| Get CRL | `GET /api/v1/ca/crl` | `GetCRL` | `OpCACRL` (`0xA7`) | `ca_crl` | ✅ |
| Get CA bundle | `GET /api/v1/ca/bundle` | `GetCABundle` | `OpCABundle` (`0xA8`) | `ca_bundle` | ✅ |
| Get bootstrap bundle | `GET /api/v1/ca/bootstrap` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | — |
| Get root certificate | `GET /api/v1/ca/root` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | — |
| Get intermediate certificate | `GET /api/v1/ca/intermediate` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | — |

Two shapes:

- **The CA administration set is missing from REST, QUIC and MCP**:
  `InitCA`, `InstallCACertificates` and `UninstallCACertificates` are gRPC
  and embedded only. Renew and verify reached REST in #452: the web service
  serves them through the same `CAService` implementation gRPC serves.
- **Three REST routes have no counterpart anywhere else**: `/ca/root`,
  `/ca/intermediate`, `/ca/bootstrap`. They serve raw trust material to clients
  that have none yet, which is why they are HTTP-only — a client that cannot
  establish trust cannot use a mutually authenticated transport.

### One certificate on every transport

The gRPC service is the reference shape for a certificate. Its `Certificate`
carries the subject, SANs (only when the certificate has any), validity,
status, key family, signature algorithm, `is_ca`, `max_path_len`, key usages,
extended key usages, the SHA-256 fingerprint, PEM, and DER when
`include_der` asks for it.

The daemon's QUIC handler speaks its own wire structs: a flat
`CAIssueRequest` with a string `key_algorithm`, and a `Certificate` with
unix-second times and string enums. That `Certificate` carries
`max_path_len`, `key_usage`, `ext_key_usage`, `fingerprint_sha256` and
`der`, and `CAGetRequest` takes `include_der`. The SDK's QUIC adapter
translates both directions for `IssueCertificate`, `GetCertificate` and
`SignCSR` (`sdk/go/transport/quic/ca_sign_csr.go`, value maps in
`sdk/go/transport/internal/cawire`). A key algorithm the gRPC service
refuses is refused by the SDK before anything is sent.

REST has one wire format for issue, sign-csr and get: the gRPC messages as
proto-JSON. `POST /api/v1/ca/certificates` takes an `IssueCertificateRequest`
(`{"request": {"subject": {...}, "sans": {...}, "key_algorithm":
"KEY_ALGORITHM_ECDSA_P256", ...}}`), `POST /api/v1/ca/sign-csr` takes a
`SignCSRRequest`, and both answer an `IssueCertificateResponse`.
`GET /api/v1/ca/certificates/{serial}` takes `include_pem` and `include_der`
as query parameters and answers a `GetCertificateResponse`. Field names may be
snake_case or camelCase.

Two servers serve these routes, and they differ only in framing:

| Server | Code | Reply |
|--------|------|-------|
| CA webservice | `pkg/webservice/v1/rest/ca` | the message inside the `{code, success, payload}` envelope |
| Daemon REST listener | `pkg/api/rest` | the message bare |

The SDK's REST adapter sends the message as it is and unwraps the envelope
when one is present, so the same client works against either server.
`TestCARESTWire_*` (`pkg/api/daemon/ca_rest_wire_parity_test.go`) drives
the SDK against both real handlers over one CA for issue, get and sign-csr,
including the refusals, and against the web service for revoke, renew and
verify, scopes included.

Revoke, renew and verify are proto-JSON on the web service too. Revoke and
renew are item operations: the serial travels in the path and only in the
path, and the body carries the rest of the request (`reason`, `delete_keys`;
`valid_days`, `preserve_sans`, `new_sans`). A serial that is not 1–40 hex
digits is refused with 400 before the CA is asked. Verify takes a
`VerifyCertificateRequest` (`certificate_pem` or `certificate_der`, both
base64 in proto-JSON) and answers a `VerifyCertificateResponse`.

The daemon REST listener still answers list, revoke, renew and verify with
its own flat JSON, and it revokes with `POST .../{serial}/revoke`. The SDK's
revoke, renew and verify claims follow the web service.

The MCP `ca_issue` tool takes the request flat — subject fields including
`address` and `postal_code`, SANs as `dns_names` / `ip_addresses` /
`email_addresses` / `uris`, and the key algorithm as a string under
`algorithm` — and `ca_get` takes `include_pem` and `include_der`. Both answer
with the gRPC service's own reply. The SDK's MCP adapter flattens
`IssueCertificate` (`sdk/go/transport/mcp/ca.go`). An `algorithm` the tool
does not know is refused, never issued as the default. One difference
remains: `ca_issue` defaults an unset `valid_days` to 365 where gRPC passes
0 (the CA's default). Both tools need the scope gRPC needs, from the `certs`
family (§4).

`TestCACertificateParity` (`pkg/api/daemon/ca_transport_parity_test.go`)
issues and reads one fully populated certificate over every transport. It
requires each transport to return the gRPC service's certificate and to ask
the CA for the same certificate.

**Revocation is `DELETE .../{serial}`, not `POST .../{serial}/revoke`.** An
earlier planning document specified the `POST` form; the web service
registers `DELETE`, and the SDK sends it.

### Issuing from a CSR

Issue certificate always generates the key: the CA creates a new key in
`store_type` and certifies it. `store_type` must name a real store —
`software` / `pkcs8` / empty, `tpm2` / `tpm`, `pkcs11`, `awskms`, `gcpkms`,
`azurekv`, `vault`, `quantum`, `frost`. Any other name is an invalid request;
it never falls back to a new software key. It takes no CSR: `csr_pem` is a
reserved field of `CertificateRequest`.

**Sign CSR** is the separate operation that certifies a key that already
exists — a key that never leaves a KMS or HSM. It takes only `csr_pem` and
`valid_days`, and every transport applies the same policy
(`issuance.SignCSR` in `pkg/ca/issuance`) before the CA is reached:

- The CSR's self-signature must verify.
- Its subject must be **one common name and nothing else**. `O`, `OU`, `C`,
  `serialNumber` or any other attribute is refused, and so is any SAN (DNS,
  IP, URI or email). The CA copies the subject and SANs into the
  certificate, and the platform's mTLS reads an identity from CN and a
  tenant from O.
- The common name must be the ID of a key the platform KMS holds, and the
  CSR's public key must equal that key's public key, read through the SDK
  KMS. A CSR for any other key, or one naming no KMS key, is refused.
- The usages are fixed, not requested: key usage `digitalSignature`, extended
  key usage **`codeSigning` only**. The certificate can never act as a TLS
  server or client identity.

A refused CSR is the caller's error: `InvalidArgument` / 400 /
`StatusInvalidRequest`. The flow is `platformctl kms key csr` then
`platformctl ca sign-csr` (see `cli.md`); the netboot fleet key is certified
this way.

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

**`CAService` is in the gRPC scope catalog** with all 13 methods mapped onto
permissions go-qrdb registers (#768). A permission outside go-qrdb's registry
cannot be held by any role, so these are the only names that can authorize:

| Methods | Permission |
|---------|------------|
| `InitCA` | `ca:create` |
| `SignCSR` | `ca:sign-csr` (wildcard-only: no role holds it by name, so only `ca:*` or `*:*` covers it) |
| `GetCAInfo`, `GetCABundle`, `GetCRL` | `ca:read` |
| `IssueCertificate`, `RenewCertificate` | `certs:generate` |
| `RevokeCertificate` | `certs:revoke` |
| `GetCertificate`, `VerifyCertificate` | `certs:read` |
| `ListCertificates` | `certs:list` |
| `InstallCACertificates`, `UninstallCACertificates` | `trust:write` (they change the system trust store) |

**Every `ca_*` MCP tool needs the scope of its gRPC twin** (#304):

| MCP tool | Scope | gRPC twin |
|---|---|---|
| `ca_issue`, `ca_renew` | `certs:generate` | `IssueCertificate`, `RenewCertificate` |
| `ca_revoke` | `certs:revoke` | `RevokeCertificate` |
| `ca_get`, `ca_verify` | `certs:read` | `GetCertificate`, `VerifyCertificate` |
| `ca_list` | `certs:list` | `ListCertificates` |
| `ca_info`, `ca_crl`, `ca_bundle` | `ca:read` | `GetCAInfo`, `GetCRL`, `GetCABundle` |
| `ca_sign_csr` | `ca:sign-csr` | `SignCSR` (below) |

QUIC's operation catalog (`pkg/api/quic/opcode_permissions.go`) requires the
same scopes for the operations it maps, and
`TestQUICAuthzContract_ScopesMatchGRPC` pins the parity. No transport uses
`ca:write`: go-qrdb does not register it, so no role could hold it. A token without the scope is refused with
`AuthErrorPermissionDenied`. The map is in `AuthorizationChecker`
(`pkg/api/mcp/authz.go`); a tool absent from it is denied
(`AuthErrorToolNotClassified`, since #300).

The REST split below is by role and by public route, not by scope, so MCP
does not copy it: `ca_info`, `ca_crl` and `ca_bundle` need `ca:read` over MCP
although their REST routes are public.

ACME authenticates by its own protocol mechanisms (account keys, EAB) rather
than by platform tokens.

### Sign CSR needs `ca:sign-csr`, granted only to the platform admin (#691)

A code-signing certificate for a KMS key is what every netbooted device's
boot chain trusts, so Sign CSR has an admin-level scope of its own,
`ca:sign-csr`. **`certs:generate` does not grant it, and neither does `*:generate`**;
`ca:sign-csr`, `ca:*` and `*:*` do. Grant it to the platform admin only —
and remember that `ca:*` and `*:*` carry it.

Each transport's handler checks it itself and fails closed, so a transport
that authenticates without scopes cannot reach it:

| Transport | Allowed caller | Refused |
|---|---|---|
| REST, platformd listener (`/api/v1/ca/sign-csr`) | Platform token granting `ca:sign-csr`, through the listener's shared `ScopeGuard` (`RequireToken`) | No token, a token the validator rejects, or an operator client certificate alone → 401 (`ErrRouteUnauthenticated`); token without the scope, or no guard → 403 (`ErrRouteForbidden`) |
| REST, web service (`/api/v1/ca/sign-csr`) | Platform token granting `ca:sign-csr` | No token → 401; token without the scope → 403 (`ErrSignCSRScopeRequired`) |
| gRPC (TCP) | Platform token granting `ca:sign-csr` | mTLS or a legacy token alone → `PermissionDenied` |
| Unix (gRPC over the socket) | Root (uid 0), by peer credentials, or a platform token granting `ca:sign-csr` | Any other uid → `PermissionDenied` |
| QUIC | Platform token granting `ca:sign-csr` | Anything else, including an operator client certificate alone → `StatusPermissionDenied` |
| MCP (`ca_sign_csr`) | Platform token granting `ca:sign-csr` | Anything else, including an operator client certificate alone → refused |
| Embedded | Root, by the identity the embedder attaches through `ServiceRegistry.CallerContext`, or a context carrying a `ca:sign-csr` platform token | Any other uid, or no identity attached → `PermissionDenied` |

On QUIC and MCP an operator client certificate presented with no token
authenticates with `*:*`, which opens every other tool; sign-csr does not
count that grant (`tokenAuthorizedContext` in `pkg/api/quic`, the token
check in `MCPServiceProvider.CASignCSR`), so only a token's grant reaches
`issuance.AuthorizeSignCSR`, the one rule every transport shares.

`platformctl ca sign-csr` run as root on the platformd host therefore works
with no token configured; from anywhere else it needs a `ca:sign-csr` token.

The embedded transport runs no interceptors, so it cannot learn who is
calling; the embedder says so. platformctl's embedded host
(`pkg/api/daemon/embedded_host.go`), which serves both the desktop GUI's
standalone mode and a CLI context whose transport is `embedded`, attaches its
own process's credentials (`peercred.ContextWithProcessCredentials`, the PID
and effective UID and GID) to every call. In-process callers then hold exactly
what that process would hold as a Unix socket peer: a GUI or CLI running as
root may sign, and any other uid is refused. A registry with no `CallerContext` attaches
nothing, and sign-csr refuses every call that brings no token. None of this
reaches the network transports, which never use the embedded connection.

The embedded host brings up the node's CA the way `platformd serve` does,
through the same two functions: `App.LoadOrInitCA` loads it from storage, or
initializes it when there is none yet. `daemon.AttachNodeCA` then sets it as
the daemon's CA service. A node with no CA configured, or whose CA can be
neither loaded nor initialized, still hosts everything else. Its embedded
registry still carries the CA service, so every CA call, `ca sign-csr`
included, answers `FailedPrecondition` with `ErrCANotInitialized`
("certificate authority not initialized"), not an unregistered method.
Authorization runs first, so a non-root caller is still refused sign-csr with
`PermissionDenied`.

### REST is split, and the privileged half is gated on `admin` (#165)

`POST/GET /api/v1/ca/certificates` and `GET/DELETE
/api/v1/ca/certificates/{serial}` require an authenticated caller holding
`admin`. Issuance and revocation are privileged, and the list of
certificates this CA has issued is an inventory of every identity on the
platform. `POST /api/v1/ca/sign-csr` is in the same gated half and in
addition requires `ca:sign-csr` (above).

Renew, revoke and verify are in the gated half and each also takes the scope
of its gRPC twin:

| Route | Scope |
|---|---|
| `POST /api/v1/ca/certificates/{serial}/renew` | `certs:generate` |
| `DELETE /api/v1/ca/certificates/{serial}` | `certs:revoke` |
| `POST /api/v1/ca/certificates/verify` | `certs:read` |

Under platform-token auth a request with no token is refused with 401 and a
token without the scope with 403, before the handler runs. Under the legacy
JWT handler the role gate alone applies, because its sessions carry roles,
not scopes. Devices, VPN and the provisioning gateway are scoped the same
way. Sign CSR differs: its handler checks its scope itself and fails closed.

`GET /api/v1/ca/bootstrap`, `/ca/crl`, `/ca/bundle`, `/ca/root`,
`/ca/intermediate` and `/ca/info` stay **public**, and must: the
trust-bootstrap fetch exists to serve a client that does not trust this
platform yet, RFC 5280 relying parties retrieve a CRL anonymously, and the
rest is the CA's own chain — already presented on every TLS handshake.

The split is `CARouter.RegisterRoutes` (gated) versus
`CARouter.RegisterPublicRoutes` (ungated), asserted exactly in both
directions by `pkg/webservice/v1/rest/ca/router_test.go`. Nothing that
mutates CA state and nothing that enumerates issued certificates may join
the public half. **This does not change the gRPC or MCP positions above.**

---

## 5. Status and error mapping

| QUIC byte | Name | REST | CA cause |
|---|---|---|---|
| `0x00` | `StatusOK` | 200 | — |
| `0x01` | `StatusInvalidRequest` | 400 | Malformed CSR, a CSR naming more than a KMS key or a key the KMS does not hold, unknown store type, malformed serial |
| `0x02` | `StatusNotFound` | 404 | Unknown serial |
| `0x03` | `StatusUnauthorized` | 401 | Token invalid; ACME account unknown |
| `0x04` | `StatusInternalError` | 500 | Signing or keystore failure |
| `0x06` | `StatusAlreadyExists` | 409 | CA already initialised |
| `0x07` | `StatusPermissionDenied` | 403 | Missing `ca:*` scope; Sign CSR without `ca:sign-csr` |
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
