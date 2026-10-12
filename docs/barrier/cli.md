# Barrier CLI

> **Status: NORMATIVE** · Scope: `platformctl barrier` (`pkg/cli/commands/barrier/`) · Last verified: 2026-10-11
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) ·
> cli (this file) · [api.md](api.md) · [user.md](user.md).
>
> **Derivation.** Verbs, flags and validation rules were read from the cobra
> declarations and validators in `pkg/cli/commands/barrier/*.go`. They were
> not taken from `--help` output.

Nine verbs. `platformctl tenant barrier` is a different capability,
documented in [`docs/tenant/cli.md`](../tenant/cli.md#5-platformctl-tenant-barrier).

## 1. Verb tree

```
platformctl barrier status
platformctl barrier init            --barrier-strategy <none|passphrase|shamir>
                                    [--passphrase <pp>] [--so-pin <pin> --user-pin <pin>]
platformctl barrier init-shamir     --passphrase <pp> --threshold <M> --total <N>
                                    [--so-pin <pin> --user-pin <pin>]
platformctl barrier unseal          --passphrase <pp>
platformctl barrier unseal-shares   --share <s> [--share <s> ...] | --shares-file <path|->
platformctl barrier seal            [-y|--assume-yes]
platformctl barrier rekey           [--so-pin <pin>] [--threshold <M> --total <N>]
platformctl barrier recovery generate --threshold <M> --total <N> [--so-pin <pin>]
platformctl barrier recovery recover  --share <s> [--share <s> ...]
```

No flag is marked required in cobra. "Required" below means the verb's
validator rejects the call before any connection is opened.

| Verb | Flags | Upstream call |
|---|---|---|
| `status` | none | `BarrierStatus` |
| `init` | `--barrier-strategy` (required: `none`, `passphrase`, `shamir`); `--passphrase` (required unless `none`, rejected with `none`); `--so-pin`, `--user-pin` (both or neither; rejected with `none`) | `BarrierInitialize` |
| `init-shamir` | `--passphrase` (required); `--threshold`, `--total` (`2 ≤ M ≤ N`); `--so-pin`, `--user-pin` (both or neither) | `BarrierInitializeShamir` |
| `unseal` | `--passphrase` (required) | `BarrierUnseal` |
| `unseal-shares` | `--share` (repeatable) **or** `--shares-file` (newline-delimited, blank lines skipped, `-` reads stdin) | `BarrierUnsealWithShares` |
| `seal` | `-y`/`--assume-yes` skips the prompt. No PIN: `BarrierSeal` takes no request, so `--so-pin` is rejected as an unknown flag. | `BarrierSeal` |
| `rekey` | `--so-pin`; `--threshold`, `--total` (paired; when set, `2 ≤ M ≤ N`; omitted keeps the current layout). No `--user-pin`. | `BarrierRekey` |
| `recovery generate` | `--threshold`, `--total` (required, `2 ≤ M ≤ N`); `--so-pin` | `BarrierGenerateRecoveryKeys` |
| `recovery recover` | `--share` (repeatable, at least one) | `BarrierRecoverWithKeys` |

**`--passphrase` is not a PIN.** The two kinds of secret do different jobs:

| Flag | Job |
|---|---|
| `--passphrase` | The seal strategy's wrapping secret. `passphrase` derives the wrapping key from it, `shamir` uses it as the strategy seal, and `none` takes none. |
| `--so-pin`, `--user-pin` | The two-PIN dual-control pair, set at init and checked by the upstream PIN backend on rekey and recovery generation. The CLI enforces "both or neither" before anything is sent. |

`seal` asks `Sealing the barrier will block all data-plane access until unsealed.
Proceed? [y/N]:` and proceeds only on `y` or `yes`.

## 2. Where the verbs go

**Every verb goes to quicbaasd, not to platformd.** The command opens the CLI's
platform SDK client, takes its quicbaas client (`Client.QuicBaaS()`) and calls
`Security().Barrier()` on it. platformd's `BarrierService` is not involved.

**The root `--transport` flag does not select this connection.** It selects the
platformd connection. The quicbaasd connection is resolved separately:

| Setting | Source, highest priority first | Default |
|---|---|---|
| Address | `PLATFORMCTL_QUICBAAS_ADDR`; the context's `quicbaas_addr` | Local context: `/run/quicbaas.sock`. Remote context: the context's `server` |
| Transport | `PLATFORMCTL_QUICBAAS_TRANSPORT`; the context's `quicbaas_transport` | Local context: `unix`. Remote context: the context's platformd protocol |

Transport values are `unix`, `grpc`, `rest`, `quic` and `mcp`. Empty, `grpc` or
an unknown value lets the quicbaas SDK auto-detect from the address: an HTTP URL
means REST, a `.sock` path means Unix, and anything else means gRPC. `embedded`
is listed as accepted in the code comments but is treated as unknown.

With no resolvable address, every verb fails with `ErrQuicBaaSNotConfigured`.

## 3. Output

`-o json` and `-o yaml` print the upstream response, or `{ok, ...}` for verbs
whose upstream call returns nothing. The default table output prints:

| Verb | Table output |
|---|---|
| `status` | Sealed, Strategy, Hardware Backed, Initialized At |
| `init` | "Barrier initialized successfully", Strategy |
| `init-shamir` | Threshold, Total Shares, Shares Sealed |
| `rekey` | Threshold, Total Shares, Shares Sealed |
| `recovery generate` | Threshold, Total, Shares Sealed |
| `unseal`, `unseal-shares`, `seal`, `recovery recover` | A success line |

`unseal-shares` and `recovery recover` add `shares_submitted` in JSON and YAML.
No verb prints share material: upstream returns none. `init-shamir`, `rekey`
and `recovery generate` report how many shares were sealed to officers, and
their help says so.

| Shares from | Claimed with |
|---|---|
| `init-shamir`, `rekey` | `platformctl ceremony claim-share begin`, then `complete` (the ceremony's officer share claim) |
| `recovery generate` | The upstream recovery share claim. platformctl has no verb for it. |

Any other `-o` value fails with `ErrInvalidOutputFormat`.

## 4. Validation

Typed errors are in `pkg/cli/commands/barrier/errors.go`.

| Rule | Verb(s) | Error |
|---|---|---|
| `--barrier-strategy` not `none`, `passphrase` or `shamir` | `init` | `ErrInvalidBarrierStrategy` |
| `--passphrase` given with `none` | `init` | `ErrSecretNotAllowed` |
| `--so-pin` or `--user-pin` given with `none` | `init` | `PINsNotAllowedError{Flag}` |
| `--passphrase` empty | `init` | `ErrSecretRequired` |
| `--passphrase` empty | `init-shamir`, `unseal` | `ErrMissingSecret` |
| `--user-pin` without `--so-pin` | `init`, `init-shamir` | `ErrUserPinRequiresSOPin` |
| `--so-pin` without `--user-pin` | `init`, `init-shamir` | `ErrSOPinRequiresUserPin` |
| `--total` below 2 | `init-shamir`, `recovery generate`, `rekey` when set | `ErrInvalidTotal` |
| `--threshold` below 2 or above `--total` | `init-shamir`, `recovery generate`, `rekey` when set | `ErrInvalidThreshold` |
| Only one of `--threshold`, `--total` | `rekey` | `ErrRekeyPartialFlags` |
| Both `--share` and `--shares-file` | `unseal-shares` | `ErrShareSourcesConflict` |
| Neither source, or an empty shares file | `unseal-shares` | `ErrMissingShares` |
| No `--share` | `recovery recover` | `ErrMissingShares` |
| Shares file unreadable | `unseal-shares` | `ErrSharesFileReadFailed` |
| Prompt answered other than `y`/`yes` | `seal` | `ErrSealCancelled` |

Upstream failures are wrapped per verb: `ErrBarrierInitFailed`,
`ErrBarrierInitShamirFailed`, `ErrBarrierStatusFailed`,
`ErrBarrierUnsealFailed`, `ErrBarrierUnsealSharesFailed`,
`ErrBarrierSealFailed`, `ErrBarrierRekeyFailed`,
`ErrBarrierRecoveryGenerateFailed`, `ErrBarrierRecoveryRecoverFailed`.

## 5. Help text

The help is held to this file by tests in `barrier_test.go`: no share-creating
verb promises shares on stdout, and `rekey` names the claim verb that exists.

## 6. Not on the CLI

- The platform gate routes (`/healthz`, `/init`, `/unseal`) — use `curl`; see
  [user.md](user.md#first-start-on-a-new-node).
- platformd's `BarrierService` — reachable through the platform SDK; see
  [api.md](api.md).
- Officer enrollment and share claims — under `platformctl ceremony`, not
  `barrier`; recovery share claims are upstream only (§3). See
  [`docs/bootstrap/`](../bootstrap/).

## 7. Examples

Passphrase strategy with the PIN pair:

```sh
platformctl barrier init --barrier-strategy passphrase \
  --passphrase '<wrapping-passphrase>' --so-pin '<so-pin>' --user-pin '<user-pin>'
platformctl barrier status
platformctl barrier seal -y
platformctl barrier unseal --passphrase '<wrapping-passphrase>'
```

Shamir 3-of-5, with shares read from stdin at unseal:

```sh
platformctl barrier init-shamir --passphrase '<seed>' --threshold 3 --total 5 \
  --so-pin '<so-pin>' --user-pin '<user-pin>'
platformctl barrier unseal-shares --shares-file - < <shares-file>
```

Rekey to a new layout, then generate and use recovery shares:

```sh
platformctl barrier rekey --so-pin '<so-pin>' --threshold 3 --total 7
platformctl barrier recovery generate --threshold 3 --total 5 --so-pin '<so-pin>'
platformctl barrier recovery recover --share '<r1>' --share '<r2>' --share '<r3>'
```

## Related

- [`docs/daemon/cli.md`](../daemon/cli.md) §2 — root flags and CLI contexts
- [`docs/tenant/cli.md`](../tenant/cli.md) — `platformctl tenant barrier`
