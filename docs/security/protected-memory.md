# Protected Memory

Every key, password, passphrase, token, share, private key and credential
this process holds in memory lives in protected storage for its whole
lifetime and is zeroized on release — never a plain `[]byte` or `string`.

The platform's primitive is **`MemoryEnclave`** in
[`pkg/memguard`](../../pkg/memguard): an `mlock`'d, guard-paged region
backed by `awnumar/memguard` that is wiped on `Destroy`, renders as
`[REDACTED]` in every `String`/JSON/YAML path, and compares in constant
time.

## Vocabulary

The type is named for its mechanism — a region of locked, zeroized memory.

```go
type MemoryEnclave                                            // the locked region
func NewMemoryEnclave(b []byte) *MemoryEnclave                // wraps and wipes b
func NewMemoryEnclaveFromString(s string) *MemoryEnclave      // for config/flags/decoded bodies
func NewRandomMemoryEnclave(size int) (*MemoryEnclave, error) // CSPRNG fill
func (e *MemoryEnclave) Open(fn func([]byte) error) error     // scoped borrow — preferred
func (e *MemoryEnclave) Bytes() []byte                        // escape hatch; do not retain
func (e *MemoryEnclave) Size() int
func (e *MemoryEnclave) IsAlive() bool
func (e *MemoryEnclave) Equal(other *MemoryEnclave) bool      // constant time
func (e *MemoryEnclave) EqualBytes(b []byte) bool             // constant time
func (e *MemoryEnclave) Destroy()                             // zeroize and release
```

**"Secret" is banned as the name of this type.** It is ambiguous across
this codebase: it already denotes a config value, a secret *reference* URI
(`kms://`, `env://`, `file://`, `idevid://`, `xkms://`), an ACME account
secret and a Shamir share — none of which are a buffer of locked memory. Do
not introduce `Secret`, `SecureString`, `SecureBytes`, `ProtectedBuffer` or
any repo-local synonym. One vocabulary across the portfolio is the point:
the follow-on audit is done by grep.

### Empty is a value, not a failure

`NewMemoryEnclave(nil)` returns a **live, zero-length** enclave. Callers
model "no password supplied" that way and the callee validates it at the
point of use with `Size() == 0` (see `pkg/bmc/credentials.go`,
`pkg/bmc/ipmi_user.go`). Construction never fails on empty input, so that
contract stays where the validation is.

## Rules

1. Sensitive material goes into an enclave at the boundary where it first
   enters the process (decoded request body, config load, flag parse) and
   is released with `Destroy` — typically `defer`red by the handler that
   built it.
2. Prefer `Open` over `Bytes`. The slice is borrowed from locked memory:
   never retain it, never modify it.
3. When an upstream API takes a plain `string` or `[]byte`, materialize it
   *inside* the `Open`/`With*` callback so the copy's lifetime is the call,
   not the request. A Go string cannot be zeroized; this narrows the
   exposure window rather than closing it, and the enclave remains the
   durable custodian.
4. Never log an enclave's contents. `String`, `MarshalJSON` and
   `MarshalYAML` already emit `[REDACTED]`; do not defeat them.

## Deprecated names

`Secret`, `New`, `NewFromString`, `NewRandom` and `MemoryEnclave.WithBytes`
remain as aliases in [`pkg/memguard/deprecated.go`](../../pkg/memguard/deprecated.go)
so no caller breaks. No new code may use them. They are removed in the
coordinated, bottom-up portfolio-wide protected-memory wave, which is
sequenced deliberately: these are Layer 0/1 APIs and a breaking change
cascades through go-quicraft → go-qrdb → go-xkms → go-quicbaas →
go-trusted-platform.

The same additive-then-deprecate rule governs the PIV service-layer
requests in `pkg/api/daemon/piv_service.go`:
`PIVGenerateRequest.PIN`, `PIVSignRequest.PIN`, `PIVImportRequest.PIN` and
`PIVImportRequest.PrivateKeyPEM` are deprecated in favour of `PINEnclave`
and `PrivateKey`, and are read through `WithPIN` / `WithPrivateKeyPEM` /
`HasPrivateKey`, which prefer the enclave and fall back to the plain field.
All five transports populate the enclave — REST (`piv_rest.go`), gRPC
(`piv_grpc_service.go`), QUIC (`phase35_quic.go`), MCP (`mcp_phase35.go`),
and Unix, which serves the same gRPC PIV service over a UDS listener
(`daemon.go`, `EnableGRPCUDS`). The wire contract is unchanged.

## Audit register

State of the protected-memory audit (2026-08-18). "Deferred" means the fix
is a breaking change to a published signature and belongs to the
coordinated wave, not that the site is acceptable.

| Area | State |
|---|---|
| `pkg/memguard` — the primitive itself | **`MemoryEnclave`**; old names deprecated |
| BMC credentials, passwords, TLS private keys (`pkg/bmc/**`, `pkg/app/bmc_cert.go`, `pkg/cli/commands/bmc/`) | Enclave end-to-end |
| PIV PIN + private key material (`pkg/api/daemon/piv_*.go`, `pkg/app/backends/piv.go`) | Enclave; plain fields deprecated |
| ~57 `secret:"true"`-tagged DTO fields across 19 packages | **Deferred** — see below |
| Untagged plaintext credentials on service-layer and config types | **Deferred** — see below |

### The `secret:"true"` tag delivers nothing today

`SecretStructTag` (`pkg/bootstrap/secrets.go:46`) marks fields whose value
may be a secret *reference URI* for the bootstrap secret resolver. It is
**declared and never read** — there is no `Tag.Get("secret")` call site in
the repo. So the tag is purely documentary: it provides neither redaction
nor locked memory. Reading it as a redaction marker overstates it.

Giving the tag real enforcement — a reflective redactor on log/marshal
paths, and/or enclave typing for the fields — is a platform-wide API change
across ~57 DTOs on shipped REST/gRPC/QUIC/MCP/Unix surfaces. That is an
owner decision and part of the coordinated wave.

### Untagged plaintext credentials found by this audit

Sites that hold credential material in a plain `string` / `[]byte` and
carry no `secret:"true"` tag at all, so they do not even show up in a tag
sweep:

| Site | Material |
|---|---|
| `pkg/dns/config.go:275` | TSIG shared HMAC secret |
| `pkg/storage/luks/types.go:272` | LUKS format passphrase |
| `pkg/api/daemon/ceremony_service.go:166` | Shamir share (claim-share result) |
| `pkg/api/quic/phase35_types.go:99` | Shamir share (QUIC wire) |
| `pkg/api/rest/init_handlers.go:120,122` | barrier root secret + Shamir share |
| `pkg/api/rest/tpm_handlers.go:161,171,185` | TPM auth secrets |
| `pkg/api/quic/tpm_handlers.go:246,255,267` | TPM auth secrets |
| `pkg/api/rest/tenant_handlers.go:173` | tenant key material |
| `pkg/api/rest/dns_handlers.go:250`, `pkg/api/quic/dns_handlers.go:265` | TSIG key |
| `pkg/api/grpc/iam_types.go:331,336` | IAM tokens |
| `pkg/attestation/push/types.go:117,123` | push token + password |
| `pkg/sdn/bgp/types.go:587` | BGP MD5 session password |

All are wire DTOs or service-layer request/result types whose signatures
ship to consumers, so each is a breaking change and belongs to the
coordinated wave.
