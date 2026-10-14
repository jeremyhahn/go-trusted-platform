# Certificate Authority (re-export frontage) — Engineering Contract

> **Status: NORMATIVE** · Scope: `pkg/ca/`, `pkg/acme/`, the CA transport layer · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> Design and boundaries: [architecture.md](architecture.md). Transport matrix:
> [api.md](api.md).

---

## 1. This repository does not implement a CA

That is the first thing to know, and the package tree says it plainly.
`pkg/ca/` contains exactly four things (verified 2026-10-12):

```
pkg/ca/
    AGENTS.md          (symlinked mirror of CLAUDE.md)
    CLAUDE.md
    issuance/          (Sign CSR policy, see the gap below)
    quicbaas/
        errors.go
        keystore_adapter.go
        kms_adapter.go
```

`pkg/acme/` contains one directory: `storage/quicbaas/`.

There is no CA implementation, no ACME server, no certificate issuance logic. The
whole feature is **adapters plus transport frontage**: the CA and ACME
implementation is go-xkms's `TrustedCA`, consumed through
`go-quicbaas/sdk/go`, and this repo re-exports it as the platform product's
CA surface (docs/00 L5).

**One gap, not a decision: Sign CSR's checks in `pkg/ca/issuance`.** Sign CSR
certifies a KMS key for code signing. Before `issuance.SignCSR` calls the CA's
`SignCSR`, it parses the CSR and verifies its self-signature (`parseCSR`),
refuses any subject attribute but the common name and any subject alternative
name (`checkNamesOnlyTheKey`), and requires the CSR's key to be the KMS key the
common name names (`checkKMSKey`). The parse is CSR processing, which belongs
to the CA. It stays here only because the pinned stack has no seam for the
policy: go-xkms v0.17.0-alpha (behind go-quicbaas `sdk/go` v0.12.0-alpha)
copies the CSR's subject and names into the template and has no
`TemplateValidator`, and go-quicbaas v0.12.0-alpha re-exports no profile type
or registry, so the platform cannot give its CA a profile. go-xkms v0.49.0-alpha has that hook, the profile
`TemplateValidator`, which `Issuer.Template` calls last on every issuance path
with `template.PublicKey` set. go-quicbaas `sdk/go` v0.14.0-alpha re-exports
it with `ProfileProvider`, `ProfileRegistry` and `NewDefaultProfileRegistry`.
Once the platform is on that SDK (#720), the CA factory registers a
code-signing profile in `Params.Profiles`, and that profile's
`ValidateTemplate` refuses extra names and any key that is not the named KMS
key. `issuance.SignCSR` then only calls `SignCSR` with the profile, and
`parseCSR` is deleted. The KMS lookup stays in the platform, because the KMS
key names are the platform's. `CallerSANProfile` does not fit this case: it
requires caller-supplied names (`ErrCallerSANsRequired`), and this
certificate carries none.

The two adapters are the whole local surface:

| File | Role |
|---|---|
| `pkg/ca/quicbaas/keystore_adapter.go` | Adapts the stack's keystore to the CA's expectations |
| `pkg/ca/quicbaas/kms_adapter.go` | Adapts the stack's KMS |
| `pkg/acme/storage/quicbaas/` | ACME storage over the stack |

`pkg/store/certstore/adapter.go` and `pkg/store/object/objstore_adapter.go` are
the other two adapter sites.

**Never add certificate logic here.** If something is missing, it is missing in
go-xkms or in the quicbaas SDK, and the fix belongs there — that is docs/00 L8,
and the local `pkg/ca/CLAUDE.md` says the same thing in stronger terms.

## 2. A stale instruction file — read before trusting `pkg/ca/CLAUDE.md`

`pkg/ca/CLAUDE.md` carries a responsibility table naming **`go-trusted-ca`** as
the owner of "all CA operations, ACME server/client, certificate management".

**`go-trusted-ca` was decommissioned on 2026-08-19** — the standalone CA was
rolled into go-xkms (`TrustedCA` + ACME), and its repository archived. An agent
following that table would go looking for a repository that is no longer a live
dependency.

The identifier `go-trusted-ca` still appears in ten tracked files
(`pkg/store/certstore/adapter.go`, `pkg/ca/quicbaas/keystore_adapter.go`,
`pkg/ca/quicbaas/kms_adapter.go`, `pkg/api/quic/ca_handlers.go`,
`pkg/api/grpc/ca_service.go`, `pkg/api/rest/ca_handlers.go`,
`pkg/api/daemon/ca_grpc_service.go`, `pkg/store/object/objstore_adapter.go`,
`pkg/webservice/v1/registry.go`, and `pkg/ca/CLAUDE.md`).

That file is an **agent instruction file with an `AGENTS.md` mirror**, not
feature documentation, so it is reported here rather than edited in a
documentation migration. It needs its own change: the responsibility table
retargeted at go-xkms, and the mirror updated in the same commit.

## 3. Exported surface

There is no CA type exported from this repository. The surface is:

- **gRPC** `CAService` — 13 RPCs (`pkg/api/grpc/proto/ca.proto`), implemented by
  `pkg/api/grpc/ca_service.go` and `pkg/api/daemon/ca_grpc_service.go`.
- **REST** — `pkg/webservice/v1/rest/ca/` plus the ACME router
  `pkg/webservice/v1/router/acme.go`.
- **QUIC** — nine opcodes, `0xA0`–`0xA8`, plus Sign CSR at `0xCD`/`0x07`.
- **MCP** — ten `ca_*` tools.

Sign CSR's policy and its `ca:sign-csr` check live once, in
`pkg/ca/issuance` (`SignCSR`, `AuthorizeSignCSR`); every transport's handler
calls them rather than restating them. gRPC adds the one transport-specific
grant, root on the Unix socket (`grpc.AuthorizeSignCSR`).
- **SDK** — `sdk/go/services/ca`.

## 4. ACME is a protocol server, not a management API

`pkg/webservice/v1/router/acme.go` implements RFC 8555 endpoint-for-endpoint:
directory, new-nonce, new-account, new-order, list-orders, get-order,
finalize-order, authorization, challenge, certificate, revoke-cert, key-change,
plus a `bundle` route.

Two structural facts:

1. **Every ACME route is rate-limited.** The router threads a
   `*trustedca.ACMERateLimiter` through each registration function, and
   `newAccount` gets its own separate limiter. That is not incidental — an
   unlimited ACME endpoint is an unlimited certificate-issuance endpoint.
2. **`bundle` is the one route with no rate limiter** — it publishes the CA
   bundle, which is public information by design.

`trustedca` is the go-xkms type; the platform hosts the server and does not
implement the protocol.

## 5. Certificate lifecycle asymmetry

The 13 gRPC RPCs are `GetCAInfo`, `InitCA`, `InstallCACertificates`,
`UninstallCACertificates`, `IssueCertificate`, `SignCSR`, `GetCertificate`,
`ListCertificates`, `RevokeCertificate`, `RenewCertificate`,
`VerifyCertificate`, `GetCRL`, `GetCABundle`.

**REST carries eight of them.** `RenewCertificate` and `VerifyCertificate` have
no REST route, and neither do `InitCA`, `InstallCACertificates` or
`UninstallCACertificates` — see [api.md](api.md). Revocation over REST is
`DELETE /api/v1/ca/certificates/{serial}`, not a `POST .../revoke`.

## 6. Known defect

`pkg/webservice/v1/rest/ca/handlers.go:715` carries a `TODO` recording that the
proto `IssueCertificateRequest` **has no explicit field** for something the REST
handler needs. Until that is resolved, the REST issuance path and the gRPC
message are not fully aligned. Verify against the code before assuming a field
exists.

## 7. Invariants

1. **The CA's keys live in the stack's KMS, not here.** The adapters exist so
   that stays true.
2. **`InitCA` is not idempotent in the useful sense** — initialising an already
   initialised CA is an error, not a re-key.
3. **`GetCABundle` is public.** It is the route a client uses to establish trust
   before it has any; it must remain reachable without credentials.
4. **Revocation is durable and one-way.** There is no unrevoke RPC.
5. **ACME rate limiting is a security control**, not a courtesy.

## 8. Test strategy

| Layer | Location | Covers |
|---|---|---|
| Unit | `pkg/webservice/v1/router/acme_test.go`, `pkg/webservice/v1/rest/ca/*_test.go` | Route registration, handler behaviour |
| Integration | `test/integration/ca/`, `test/integration/acme/` | End-to-end issuance |
| ACME enrollment | `test/integration/acme_enrollment_integration_test.go`, `acme_enrollment_mock_server_test.go` | Enrollment against a mock ACME server |
| Transport parity | `pkg/api/daemon/ca_transport_parity_test.go` | Issue and get through the SDK on every transport return the gRPC service's certificate and send the CA the same request ([api.md](api.md) §2) |

`test/integration/ACME_ENROLLMENT_TESTS_README.md` documents that suite.

**Known repo-wide gap:** no `CommandDefinition` type exists in this repository
(grepped 2026-08-18), so the CLI parity requirement in
`conventions/feature-docs.md` §4 is unmet repo-wide.

## 9. Observability

Certificate issuance and revocation are audit events by nature. Private key
material must never reach a log; the adapters exist so that the platform layer
never holds it.

## 10. Related

- [architecture.md](architecture.md) · [api.md](api.md) · [cli.md](cli.md) · [user.md](user.md)
- [`docs/kms/`](../kms/) — the other half of the stack re-export frontage
- [`docs/device/`](../device/) — IDevID enrollment, which consumes issuance
- [`docs/eab/`](../eab/) — ACME External Account Binding credentials
- [`docs/dns/`](../dns/) — DNS-01 challenge records
- Deep dives carried over and not re-verified in this pass:
  [acme.md](acme.md), [asn1.md](asn1.md), [configuration.md](configuration.md).
  The legacy overview.md is deleted; these five files hold its content.
