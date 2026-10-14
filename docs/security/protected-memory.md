# Protected Memory

> **Status: REFERENCE** · Last verified: 2026-10-13
> The protected-memory mandate, the `MemoryEnclave` primitive in `pkg/memguard`, and the register of paths that do not yet meet it.

**The mandate.** Every key, password, passphrase, token, share, private key
and credential this process holds in memory lives in protected storage for
its whole lifetime and is zeroized on release — never a plain `[]byte` or
`string`.

This document states that mandate, the primitive that implements it, and —
in [Known gaps](#known-gaps) — the places the platform does not yet meet it.
Read the register before assuming any given path is covered end to end.

The platform's primitive is **`MemoryEnclave`** in
[`pkg/memguard`](../../pkg/memguard): an `mlock`'d, guard-paged region that
is wiped on `Destroy`, renders as `[REDACTED]` in every `String`/JSON/YAML
path, and compares in constant time.

## Layering — the locked region belongs to the stack

`MemoryEnclave` does not allocate locked memory itself. It holds a
`secure.Buffer` obtained from
`github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/secure` — the sanctioned SDK
re-export, which aliases go-xkms's alias of the canonical go-qrdb
implementation. **No file in this module imports `awnumar/memguard`**, and
`pkg/arch/layerguard_test.go` fails the build with a `file:line` report if
one ever does.

What `pkg/memguard` adds is the platform API the re-export does not carry:
the live zero-length enclave, the scoped `Open` borrow, `IsAlive`,
constant-time comparison, and the redacting marshalers. Those belong
upstream — see [Known gaps](#the-sanctioned-sdk-enclave-re-export-lacks-the-enclave-api)
— and the shape is held here so callers do not change when the SDK grows
them.

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
and `PrivateKey`, and are read through `WithPIN` / `WithPrivateKeyPEM`, which read the plain
field only when no enclave was supplied at all. An enclave that was supplied
and then destroyed is a lifecycle error and surfaces `memguard.ErrDestroyed`
— it never falls back, because that would turn a use-after-destroy into a
PIV operation with a stale or empty PIN.
`PIVImportRequest` is currently validated but never stored: PIV `Import`
fails closed with `ErrPIVKeyImportUnsupported` until the go-quicbaas SDK
re-exports go-xkms `ImportPIVKey` (see [piv CLI](../cli/piv.md)).
All five transports populate the enclave — REST (`piv_rest.go`), gRPC
(`piv_grpc_service.go`), QUIC (`phase35_quic.go`), MCP (`mcp_phase35.go`),
and Unix, which serves the same gRPC PIV service over a UDS listener
(`daemon.go`, `EnableGRPCUDS`). The wire contract is unchanged.

## Known gaps

These are recorded, not accepted. Each needs an upstream or wire change and
belongs to the coordinated wave.

### The transport decode boundary is not protected

Every transport materializes a request field before the platform can take
custody of it: `encoding/json` produces a `string` in the REST handler's
anonymous struct, protobuf produces one in the generated gRPC message, the
QUIC codec produces one in the DTO, and MCP produces one in the `args` map.
`NewMemoryEnclaveFromString` then *copies* that value into locked memory —
it cannot erase the original, because a Go string is immutable and the
decoder owns the backing array.

So for PIV, `Destroy` wipes the enclave while the decoded PIN or PEM string
remains readable in the process image until the collector reuses that
memory. The enclave is the durable custodian from the service layer inward;
the decode buffer ahead of it is not covered.

Closing this needs the wire and SDK layers to hand over mutable, wipeable
storage rather than a `string` — coordinated wire and SDK changes, not
something a platform-side wrapper can reach. Filed upstream:
go-quicbaas#29.

### JSON decoding materialises a string

`MemoryEnclave.UnmarshalJSON` decodes through `encoding/json` so escape
sequences yield the value the sender meant. `encoding/json` hands back a Go
string, which cannot be wiped — the same decode-boundary gap as above,
unavoidable for a JSON string field.

### The BMC config, CLI and credential-record boundaries are not protected

Same shape as the PIV decode boundary, at four BMC entry points. Each takes
custody *after* the value already exists in an immutable Go string, so the
enclave is a copy and the original cannot be scrubbed:

| Site | Plaintext holder |
|---|---|
| `pkg/bmc/service_user.go:49,73` | `CreateUser` / `SetUserPassword` take `password string` |
| `pkg/cli/commands/bmc/user.go:585,670` | `passwordStr` from the terminal prompt, enclaved at 593 / 683 |
| `pkg/bmc/config.go:26` | `cfg.Password` decoded from YAML/JSON |
| `pkg/bmc/credentials.go:156,168,196` | `credentialRecord.Password` on both the marshal and unmarshal side |

Converting one of those strings to `[]byte` creates a wipeable *copy*; it
cannot scrub the string's backing array. Protection therefore begins at the
service/manager boundary, and `Credentials` is the durable custodian from
there inward.

Closing these needs the same coordinated change as PIV: signature changes on
`Service.CreateUser` / `SetUserPassword`, a wipeable prompt reader, and a
credential record that serializes from the enclave without an intermediate
string.

### Secret resolution and deployment hand back plaintext, not handles

Two ends of the NTS key's life are outside the enclave, and both are the
same upstream shape — the SDK exposes plaintext where it should expose a
handle. Filed as
go-quicbaas#136,
tracked here as
#60.

- **Generation.** The key is generated at Layer 5 as an ordinary
  `*ecdsa.PrivateKey` because the SDK offers no non-exportable KMS key
  handle to generate into. `enclaveNTSKey` takes custody as early as the
  language allows — the first thing it does with the marshalled key is
  copy it into locked memory and clear the buffers it copied from — but
  the generated key itself **cannot be scrubbed at all** from here: as of
  Go 1.26 `crypto/ecdsa` keeps the scalar in an internal FIPS
  representation behind a package-level cache, `PrivateKey.D` is a
  deprecated legacy view of it (staticcheck SA1019), and the package
  exposes no zeroization API. Wiping `D` would clear one copy, leave the
  cached one, and read as a stronger guarantee than it is — so the code
  deliberately does not do it. This is the single strongest argument for
  moving generation behind the upstream handle.
- **Resolution.** `ProcessSecrets` substitutes `kms://` references into
  the configuration as plain Go strings before the NTP service starts, so
  the startup material reaches `writeConfiguredNTSMaterial` as a string
  that cannot be wiped. The copy taken there IS wiped after the write,
  which narrows the window; closing it needs handle-preserving resolution
  below Layer 5. The same pipeline feeds the secure-boot provisioner, so
  this is a platform-wide gap, not an NTS one.

The store write in between is bounded rather than protected: the SDK
request field is a plain `[]byte` whose retention the platform cannot
assume, so it receives an ordinary copy (rule 3) — the enclave stays the
durable custodian, and the copy is deliberately NOT wiped afterwards
because the store may still hold it.

### The upstream PIV API takes a plain string

`xkmssdk.SignPIV` takes `PIN string`, so the platform must materialize a
string at that call (see rule 3). The enclave bounds the copy's lifetime to
the call; it does not remove it. Same upstream issue
(go-quicbaas#29).

### The sanctioned SDK enclave re-export lacks the enclave API

`quicbaas/sdk/go/xkms/secure` (at the pinned `sdk/go` v0.12.0-alpha) exposes
`Buffer`, `NewBuffer`, `NewBufferFromBytes`, `Secret`, `Wipe`, `Purge` and
the passphrase providers. `pkg/memguard` uses only `Buffer` and
`NewBufferFromBytes`. Even the full upstream `go-qrdb/pkg/secure` surface lacks
the scoped borrow, the liveness check, constant-time comparison, and the
empty-value contract that this repo's callers depend on. The locked region
comes from that re-export either way, but `MemoryEnclave` cannot become a
plain type alias for `secure.Buffer` until those exist: aliasing today would
change BMC credential-validation semantics, because `NewBufferFromBytes(nil)`
fails construction where callers require a live, zero-length value. Filed
upstream
(go-quicbaas#29).

`NewBufferFromBytes`, the constructor `pkg/memguard` uses, is structurally
incapable of allocate-then-fill. It calls memguard's
`NewBuffer`, moves the source in, and then **`Freeze()`s** the region
(`awnumar/memguard@v0.23.0/buffer.go:48`), so the returned buffer is
read-only: writing into `Buffer.Bytes()` faults with `SEGV_ACCERR`. The
mutable allocator is `secure.NewBuffer(size)`, which the go-quicbaas
re-export now carries; `pkg/memguard` does not use it yet. Seeding a
zero-filled buffer from `NewBufferFromBytes` and filling it in place does
not work — it was tried and segfaults.

Two consequences are visible today:

- `NewRandomMemoryEnclave` draws into an ordinary heap slice and wipes it as
  `NewBufferFromBytes` copies it into the locked region. The draw is briefly
  unlocked, and its failure paths clear the slice with the `clear` builtin
  rather than an optimization-resistant wipe; the re-export now carries
  `secure.Wipe`, which this package does not call yet. Nothing outside this package's own tests calls it.
- `NewMemoryEnclaveFromFile` — the protected read path for credential files
  on disk — passes the content through exactly ONE ordinary heap slice,
  allocated at the file's measured size so the read never reallocates, and
  wiped on every path. It is strictly better than `os.ReadFile`, which grows
  by append (a file whose size changes leaves earlier copies of the secret
  unreachable and unwiped) and leaves the whole plaintext behind when a
  downstream construction fails. It is not zero copies, and cannot be until
  it moves to the re-exported `NewBuffer`.

Callers **must** use `NewMemoryEnclaveFromFile` rather than
`os.ReadFile` + `NewMemoryEnclave` for private keys, passphrases and tokens.

## Audit register

State of the protected-memory audit (2026-08-18). "Deferred" means the fix
is a breaking change to a published signature and belongs to the
coordinated wave, not that the site is acceptable.

| Area | State |
|---|---|
| `pkg/memguard` — the primitive itself | **`MemoryEnclave`**, backed by the SDK `secure.Buffer`; no direct `awnumar/memguard` import remains, and the layer guard enforces it. Old names deprecated. `NewMemoryEnclaveFromFile` is the protected read path for credential files |
| Firstboot admin bundle in the claim CLI (`pkg/cli/commands/admin/client.go`) | Key read via `NewMemoryEnclaveFromFile` and borrowed with `Open`; the certificate is public and read normally. **Not end to end** — the one transfer copy and the parsed stdlib key remain, both upstream (see above) |
| BMC credentials, passwords, TLS private keys (`pkg/bmc/**`, `pkg/app/bmc_cert.go`, `pkg/cli/commands/bmc/`) | Enclave from the service/manager boundary inward. **Not end to end** — see [Known gaps](#known-gaps) |
| PIV PIN + private key material (`pkg/api/daemon/piv_*.go`, `pkg/app/backends/piv.go`) | Enclave from the service layer inward; plain fields deprecated. **Not end to end** — see [Known gaps](#known-gaps) |
| Daemon mTLS server private key (`pkg/daemon/commands/provision_identity.go`) | **Keystore-held (#33).** Generated and kept in the platform CA keystore; the listeners hold only its `crypto.Signer`. No key bytes are marshalled or written, and the daemon writes no admin key either (the one-shot `/init` reply is the admin credential) — see [`docs/daemon/architecture.md`](../daemon/architecture.md) §Daemon TLS identity and key custody |
| NTS server private key — provisioning and renewal (`pkg/app/nts_provision.go`, `pkg/ntp/service.go`) | Enclave from marshalling inward: `enclaveNTSKey` marshals straight into the enclave and clears the intermediate DER and PEM, and rotation carries the enclave rather than a plain field. **Not end to end** — generation, the startup path and the KMS write are covered below |
| 61 `secret:"true"`-tagged fields across 25 packages | **Deferred** — see below |
| Untagged plaintext credentials on service-layer and config types | **Deferred** — see below |

### The `secret:"true"` tag delivers no protection today

`SecretStructTag` (`pkg/bootstrap/secrets.go:47`) marks fields whose value
may be a secret *reference URI* for the bootstrap secret resolver. Its one
reader is `bootstrap.PlaintextSecretFields`, which the diskless image build
uses to refuse a platform config holding a tagged field as plaintext
(`pkg/diskimage/diskless_config.go`). Nothing reads it on a log, marshal or
memory path, so it provides neither redaction nor locked memory. Reading it
as a redaction marker overstates it.

Giving the tag real enforcement — a reflective redactor on log/marshal
paths, and/or enclave typing for the fields — is a platform-wide API change
across 61 fields on shipped REST/gRPC/QUIC/MCP/Unix surfaces. That is an
owner decision and part of the coordinated wave.

### Untagged plaintext credentials found by this audit

Sites that hold credential material in a plain `string` / `[]byte` and
carry no `secret:"true"` tag at all, so they do not even show up in a tag
sweep:

| Site | Material |
|---|---|
| `pkg/storage/luks/types.go:271` | LUKS format passphrase |
| `pkg/api/daemon/ceremony_service.go:182` | Shamir share (claim-share result) |
| `sdk/go/wire/quicwire/phase35_types.go:101` | Shamir share (QUIC wire) |
| `pkg/api/rest/init_handlers.go:145,147` | barrier root secret + Shamir share |
| `pkg/api/rest/tpm_handlers.go:176,186,200` | TPM auth secrets |
| `pkg/api/quic/tpm_handlers.go:218,227,239` | TPM auth secrets |
| `pkg/api/rest/tenant_handlers.go:160` | tenant key material |
| `pkg/api/grpc/iam_types.go:330,335` | IAM tokens |
| `pkg/attestation/push/types.go:116,122` | push token + password |
| `pkg/sdn/bgp/types.go:735` | BGP MD5 session secret (`AuthKey`, resolved at runtime) |

All are wire DTOs or service-layer request/result types whose signatures
ship to consumers, so each is a breaking change and belongs to the
coordinated wave.
