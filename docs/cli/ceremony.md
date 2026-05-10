# `platformctl ceremony`

Ceremony operations for barrier initialization and officer enrollment.

The `ceremony` command tree mirrors `qrdb ceremony` and drives the n-of-m
barrier bootstrap flow: initial setup, officer claim-cert challenge /
response, Shamir share distribution, and Security Officer CSR signing.

All subcommands connect to `platformd` via the SDK and therefore honor the
global flags `--config`, `--context`, `--transport`, `--server`, `--output`.

> Phase 3 status: CLI + SDK scaffolding is complete. Server-side handlers
> land in Phase 3.5. The SDK currently returns `ErrNotYetWired` for every
> method.

## Subcommands

### `ceremony init`

Initialize a fresh ceremony.

```
platformctl ceremony init \
    --so-pin 123456 \
    --user-pin 654321 \
    --threshold 3-of-5 \
    --hostname cp-01 \
    --sans "cp-01.example.com,10.0.0.10" \
    --credential-seal-strategy shamir
```

| Flag | Description |
|------|-------------|
| `--so-pin` | Security Officer PIN |
| `--user-pin` | User PIN |
| `--threshold` | Shamir threshold descriptor (e.g. `3-of-5`) |
| `--hostname` | Initial node hostname |
| `--sans` | Subject alternative names (comma-separated) |
| `--credential-seal-strategy` | Seal strategy (`shamir`, `tpm`, `fido2`, ...) |

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

### `ceremony claim-share`

Retrieve the caller's Shamir share. Only returned once.

```
platformctl ceremony claim-share --username alice
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

`platformctl ceremony` returns non-zero on any SDK error, including the
Phase 3 `ErrNotYetWired` placeholder. Once the server-side handlers are
wired, real errors surface via the `*Failed` wrappers defined in
`sdk/go/services/ceremony/errors.go`.

## Wire surface

Every CLI subcommand above maps 1:1 to a REST endpoint, gRPC RPC, QUIC
opcode, and MCP tool. Callers that want to bypass `platformctl` can invoke
the backend directly. Phase 3.5 + task #88 wire these live at platformd
startup.

| Subcommand | REST (POST unless noted) | MCP tool |
|------------|--------------------------|----------|
| `ceremony init` | `POST /api/v1/ceremony/init` | `platform_ceremony_init` |
| `ceremony status` | `GET /api/v1/ceremony/status` | `platform_ceremony_status` |
| `ceremony claim-cert begin` | `POST /api/v1/ceremony/claim-cert/begin` | `platform_ceremony_claim_cert_begin` |
| `ceremony claim-cert complete` | `POST /api/v1/ceremony/claim-cert/complete` | `platform_ceremony_claim_cert_complete` |
| `ceremony claim-share` | `POST /api/v1/ceremony/claim-share` | `platform_ceremony_claim_share` |
| `ceremony sign-csr` | `POST /api/v1/ceremony/sign-csr` | `platform_ceremony_sign_csr` |

REST responses use snake_case JSON. MCP tool names follow the
`platform_{module}_{verb}` convention. gRPC service names and QUIC opcodes
are in `pkg/api/grpc/proto/ceremony.proto` and `pkg/api/quic/protocol.go`
respectively.
