# `platformctl ceremony`

> **Status: REFERENCE** · Last verified: 2026-10-13
> The `platformctl ceremony` command reference, wire mapping and scopes.

Ceremony operations for barrier initialization and officer enrollment.

Routes through `platform.Client.Ceremony()` and the platform SDK ceremony
service adapter, which terminates at the canonical ceremony backend. The
platform repo provides the CLI binding and a thin server-side backend
(`CeremonyBackend`, `pkg/app/backends/ceremony.go`) that delegates every call
to the SDK's barrier ceremony service and mints the admin bundle on Init.

`platformd serve` wires the production ceremony backend (the QuicBaaS SDK
ceremony service, plus the platform CA as the admin bundle issuer) into
every transport once the barrier is unsealed. A daemon that reaches that
point without an SDK client refuses to start (`ErrServeStartup{Phase: "SDK
backends"}`), so `ceremony: backend not configured` is never the answer of a
running platformd. platformctl's desktop embedded daemon wires the same
backend and likewise refuses to start without an SDK client.

The subcommands honor the global flags `--config`, `--context`,
`--transport`, `--server`, `--output`.

## Subcommands

### `ceremony init` (removed)

`platformctl ceremony init` exits non-zero with `CanonicalRedirectError`. Use
the root `platformctl init` ([`docs/bootstrap/cli.md`](../bootstrap/cli.md) §1a),
which drives the pre-unseal `POST /init` — the only init surface that exists
before unseal ([`docs/daemon/api.md`](../daemon/api.md) §1). The
`CeremonyService.Init` RPC below remains for SDK callers that hold
`ceremony:write` on an already-unsealed daemon.

The Init reply carries `ceremony_id`, `state`, `initialized_at`, `spki_pin`,
`admin_cert_pem` and `admin_key_pem` on every transport (gRPC `AdminCertPem` /
`AdminKeyPem` / `SpkiPin`). The daemon mints the admin client certificate from
the platform CA **before** it touches the ceremony, so a minting failure leaves
the platform uninitialized and retryable. The admin key is not stored anywhere:
the Init reply is its only copy, and the only admin credential the platform
issues ([`docs/bootstrap/cli.md`](../bootstrap/cli.md) §1a).

### `ceremony status`

Print the current ceremony state.

```
platformctl ceremony status
```

### `ceremony claim-cert begin`

Start an officer cert-claim challenge. The server issues a nonce that the
officer must sign with their authenticator.

```
# PIV
platformctl ceremony claim-cert begin \
    --username alice \
    --authenticator-type piv \
    --slot 9a

# FIDO2
platformctl ceremony claim-cert begin \
    --username alice \
    --authenticator-type fido2 \
    --credential-id <base64url credID>
```

### `ceremony claim-cert complete`

Submit the signature over the nonce; receive the issued officer certificate
and intermediate chain.

```
platformctl ceremony claim-cert complete \
    --username alice \
    --nonce <nonce> \
    --signature <base64 signature>
```

### `ceremony claim-share begin`

Request a share-claim challenge nonce. The officer signs the nonce with the
private key matching their claimed certificate.

```
platformctl ceremony claim-share begin --username alice
```

### `ceremony claim-share complete`

Submit the signature over the nonce; receive the caller's Shamir share.
Only returned once.

```
platformctl ceremony claim-share complete \
    --username alice \
    --nonce <nonce> \
    --signature <base64 signature>
```

### `ceremony sign-csr`

Sign a CSR with the ceremony CA.

```
platformctl ceremony sign-csr \
    --username alice \
    --so-pin 123456 \
    --csr-file ./alice.csr \
    --role admin
```

## Exit codes

`platformctl ceremony` returns non-zero on any SDK error. Typed command-surface
errors live in `sdk/go/services/ceremony/errors.go`; backend errors propagate
through the selected platform SDK transport.

## Wire surface

Every CLI subcommand maps 1:1 to a REST endpoint, gRPC RPC, QUIC opcode,
and MCP tool. The CLI opens the selected platform SDK transport and dispatches
through the ceremony service client exposed by `platform.Client.Ceremony()`;
there is no transport-local placeholder for ceremony verbs.

| Subcommand | REST (POST unless noted) | MCP tool |
|------------|--------------------------|----------|
| `ceremony init` | `POST /api/v1/ceremony/init` | `platform_ceremony_init` |
| `ceremony status` | `GET /api/v1/ceremony/status` | `platform_ceremony_status` |
| `ceremony claim-cert begin` | `POST /api/v1/ceremony/claim-cert/begin` | `platform_ceremony_claim_cert_begin` |
| `ceremony claim-cert complete` | `POST /api/v1/ceremony/claim-cert/complete` | `platform_ceremony_claim_cert_complete` |
| `ceremony claim-share begin` | `POST /api/v1/ceremony/claim-share/begin` | `platform_ceremony_claim_share_begin` |
| `ceremony claim-share complete` | `POST /api/v1/ceremony/claim-share/complete` | `platform_ceremony_claim_share_complete` |
| `ceremony sign-csr` | `POST /api/v1/ceremony/sign-csr` | `platform_ceremony_sign_csr` |

REST responses use snake_case JSON. MCP tool names follow the
`platform_{module}_{verb}` convention. gRPC service names and QUIC opcodes
are in `pkg/api/grpc/proto/ceremony.proto` and `sdk/go/wire/quicwire/phase35_opcodes.go`
respectively.

### Transports and scopes

The SDK client for each transport is tested against the daemon's real handlers.
QUIC uses category opcode `0x9A` with the sub-opcode in `payload[0]`.
The embedded transport dispatches every RPC in-process through
`ServiceRegistry.Ceremony`.

| Subcommand | gRPC method (`platform.v1.CeremonyService`) | QUIC sub-opcode | Scope |
|------------|---------------------------------------------|-----------------|-------|
| `ceremony init` | `Init` | `0x01` | `ceremony:write` |
| `ceremony status` | `Status` | `0x02` | `ceremony:read` |
| `ceremony claim-cert begin` | `ClaimCertBegin` | `0x03` | `ceremony:write` |
| `ceremony claim-cert complete` | `ClaimCertComplete` | `0x04` | `ceremony:write` |
| `ceremony claim-share begin` | `ClaimShareBegin` | `0x05` | `ceremony:write` |
| `ceremony claim-share complete` | `ClaimShareComplete` | `0x07` | `ceremony:write` |
| `ceremony sign-csr` | `SignCSR` | `0x06` | `ceremony:write` |

`init` and `status` are scoped, not pre-auth. First boot has no token to present,
so it runs over the Unix socket (local, not token-gated) or the pre-auth
`POST /init` REST route. On gRPC (TCP), QUIC and MCP an unauthenticated `init`
would let a remote caller seize an uninitialized platform, so those transports
require `ceremony:write`. A token without the scope is refused
(`PermissionDenied` / `StatusPermissionDenied`), and so is a QUIC caller with no
principal; under mTLS the client certificate is the principal and holds every
scope ([`docs/daemon/api.md`](../daemon/api.md) §5). Scopes are minted by the broker
from the subject's IAM permissions, so a role gains `ceremony:read` /
`ceremony:write` by being granted those permissions; the admin role needs both.
