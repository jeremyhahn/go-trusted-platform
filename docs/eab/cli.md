# ACME External Account Binding — CLI

> **Status: NORMATIVE** · Scope: `pkg/eab/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## 1. There is no `platformctl eab` command group

Verified against `pkg/cli/commands/root.go` on 2026-08-18: the 42 command
groups registered there do not include `eab`. **EAB credentials cannot be
created, listed, revoked, validated, exported or cleaned up from the CLI.**

That is a gap, not a design decision — the API carries all eleven capabilities
on five transports ([api.md](api.md)). It is recorded in §4.

What the CLI *does* have is the **consuming** side: three verbs take an
already-issued credential as flags.

---

## 2. `platformctl provision fetch-config`

Fetch this device's platform configuration from a provisioning server. Used
during ISO boot by `autoinstall.sh`.

| Flag | Type | Default | Required | Meaning |
|---|---|---|---|---|
| `--server-url` | string | `""` | yes | Provisioning server URL |
| `--ek-serial` | string | `""` | one of `--ek-serial` / `--mac` | Device EK serial number |
| `--mac` | string | `""` | one of `--ek-serial` / `--mac` | Device MAC address |
| `--eab-kid` | string | `""` | **yes** | EAB key ID |
| `--eab-hmac` | string | `""` | **yes** | EAB HMAC key, `base64url` without padding |
| `--output` | string | `""` | yes | Path to write the config YAML |

```bash
platformctl provision fetch-config \
    --server-url https://platform.example.com:8443 \
    --ek-serial ABC123 \
    --mac 00:11:22:33:44:55 \
    --eab-kid REPLACE_WITH_KEY_ID \
    --eab-hmac REPLACE_WITH_BASE64URL_HMAC \
    --output /tmp/platform-config.yaml
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Config fetched and written to `--output` |
| `1` | Error — including EAB validation failure |
| `2` | Server returned `pending`: the device awaits approval, try `provision interactive` |

Exit code `2` is the contract with `autoinstall.sh`. Do not treat it as failure.

**`--eab-hmac` is a secret on the command line.** It appears in the process
table and, on an interactive shell, in history. It is acceptable inside an
installer's non-interactive boot script; it is not acceptable typed by hand on a
shared machine.

---

## 3. `platformctl provision interactive`

QR-code-driven provisioning for a device the server has not yet approved. Run
after `fetch-config` exits `2`.

Same flags as `fetch-config`, plus:

| Flag | Type | Default | Required | Meaning |
|---|---|---|---|---|
| `--timeout` | int | `600` | no | Seconds to poll before giving up |

```bash
platformctl provision interactive \
    --server-url https://platform.example.com:8443 \
    --ek-serial ABC123 \
    --mac 00:11:22:33:44:55 \
    --eab-kid REPLACE_WITH_KEY_ID \
    --eab-hmac REPLACE_WITH_BASE64URL_HMAC \
    --output /tmp/platform-config.yaml \
    --timeout 300
```

Polls every 5 seconds (`pollIntervalSeconds`) until the operator approves the
device or the timeout expires. `--timeout 0` or negative is rejected with
`ErrInvalidTimeout`.

---

## 4. `platformctl install system`

Installs the platform onto local disk. Two of its flags carry an EAB credential,
used only when the installer needs the control plane to sign a Secure Boot DB
digest remotely (`--resign-mode remote` plus a provisioning server URL).

| Flag | Type | Default | Required | Meaning |
|---|---|---|---|---|
| `--eab-kid` | string | `""` | for remote signing | EAB key ID for remote provisioning auth |
| `--eab-hmac` | string | `""` | for remote signing | EAB HMAC for remote provisioning auth |

```bash
platformctl install system \
    --eab-kid REPLACE_WITH_KEY_ID \
    --eab-hmac REPLACE_WITH_BASE64URL_HMAC
```

The remote-signing path posts to `/api/v1/provisioning/sign` after fetching a
nonce from `/api/v1/provisioning/config/nonce`, authenticating with the EAB pair
plus the device's EK identity. See [`docs/provisioning/`](../provisioning/).

---

## 5. Errors

| Error | Message | Cause |
|---|---|---|
| `ErrEABKIDRequired` | `provision: --eab-kid is required` | `--eab-kid` empty |
| `ErrEABHMACRequired` | `provision: --eab-hmac is required` | `--eab-hmac` empty |
| `ErrInvalidTimeout` | — | `--timeout <= 0` on `provision interactive` |

A server-side EAB rejection surfaces as `ErrEABValidationFailed` wrapping the
`pkg/eab` error, rendered as a non-zero exit with the server's message.

---

## 6. Recorded gaps

1. **No `platformctl eab` group.** Eleven capabilities exist on gRPC, Unix,
   REST, QUIC, MCP and embedded, and none on the CLI. An operator issuing a
   credential today uses `curl`, the Go SDK (`sdk/go/services/eab`), the
   JavaScript SDK (`sdk/javascript/src/services/eab-service.ts`), or an MCP
   client. Raised for the owner; not resolved here.

2. **CLI parity suite.** `conventions/feature-docs.md` §4 requires every verb
   here to have a matching `CommandDefinition`. **This repository defines no
   `CommandDefinition` type** (grepped repo-wide, 2026-08-18), so the
   requirement is unmet repo-wide. The three verbs above belong to
   [`docs/provisioning/`](../provisioning/) and
   [`docs/installer/`](../installer/) respectively; they are documented here
   because their EAB flags are this feature's only CLI presence.

---

## 7. Related

- [architecture.md](architecture.md) · [engineering.md](engineering.md) · [api.md](api.md) · [user.md](user.md)
- [`docs/daemon/cli.md`](../daemon/cli.md) §2 — persistent `platformctl` flags
