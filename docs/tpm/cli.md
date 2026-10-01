# Physical TPM 2.0 — CLI

> **Status: NORMATIVE** · Scope: `platformctl tpm` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> Every verb and every flag below was read out of `pkg/cli/commands/tpm/` on
> 2026-08-18. Flags mentioned only in a command's help text but never registered
> are listed in §6 as defects, not documented as if they worked.

---

## 1. Command group

```
platformctl tpm            TPM device identity operations
platformctl tpm idevid     Manage IDevID (Initial Device Identifier) keys
platformctl tpm idevid ldevid
                           Manage LDevID (IEEE 802.1AR) keys
platformctl tpm iak        Manage IAK (Initial Attestation Key) keys
platformctl tpm ek         Endorsement Key operations
platformctl tpm srk        Storage Root Key operations
platformctl tpm nvram      NVRAM operations
platformctl tpm device     TPM device information
```

Registered at `pkg/cli/commands/root.go` alongside `platformctl vtpm`.

**`platformctl tpm` is not part of the locked CLI surface.** `docs/11-cli-surface`
defines no `tpm` group for `platformctl`, so there is no cross-binary contract
to mirror here. Treat this document as the definition until one exists.

### Global flags

`platformctl` persistent flags (`pkg/cli/commands/root.go:125`). Precedence is
**flag > environment > config file > built-in default**.

| Flag | Short | Default | Environment | Meaning |
|---|---|---|---|---|
| `--config` | `-c` | platform default | `PLATFORMCTL_CONFIG` | Config file |
| `--context` | | current-context | `PLATFORMCTL_CONTEXT` | Named context |
| `--transport` | | from context | `PLATFORMCTL_TRANSPORT` | `unix`, `grpc`, `rest`, `quic`, `mcp`, `embedded` |
| `--server` | | from context | `PLATFORMCTL_SERVER` | Server address |
| `--server-name` | | | `PLATFORMCTL_SERVER_NAME` | TLS SNI / verification hostname |
| `--output` | `-o` | `table` | `PLATFORMCTL_OUTPUT` | `table`, `json`, `yaml` |
| `--verbose` | `-v` | `false` | | Verbose output |
| `--no-color` | | `false` | `NO_COLOR` | Disable colour |

**Which verbs work without a server.** Exactly one: `tpm clear --force`. It
opens the TPM directly through go-xkms, schedules a UEFI PPI clear and reboots
(§5). Every other working verb is a client verb and needs a reachable
`platformd` on the selected transport; `--transport embedded` runs the services
in-process.

**`tpm eventlog --format` is not `--output`.** `--format` selects `json`, `text`
or `binary` for the event-log payload; `-o`/`--output` still selects the
rendering of the surrounding response. They are independent.

---

## 2. Device and status

| Verb | Flags | Purpose |
|---|---|---|
| `info` | — | Full TPM information report |
| `status` | `--platform-srk-handle` | Provisioning state of the platform-defined objects |
| `device attributes` | — | Manufacturer, model, firmware version |
| `flush` | — | Flush transient contexts (handles `0x80000000`–`0x80FFFFFF`) |

```bash
platformctl tpm info -o json
platformctl tpm status
platformctl tpm device attributes
platformctl tpm flush
```

**`status` is the "is this node ready?" verb.** It reports, per object (EK,
SSRK, PlatformSRK, IAK, IDevID), whether the persistent handle is present and
whether a certificate is installed, plus PCR 23 in the SHA-256 bank and whether
it has been extended. Every row is backed by the SDK call its dedicated verb
uses — `tpm ek certificate`, `tpm srk info --handle`, `tpm iak info`,
`tpm idevid info` — so `status` cannot disagree with them (#471).

```
OBJECT         HANDLE         CERTIFICATE                                NOTES
----------------------------------------------------------------------------------------------------
EK             present        present (PEM)
SSRK           present        n/a                                        0x81000001
PlatformSRK    present        n/a                                        0x81000002; default handle assumed (daemon config not exposed); override with --platform-srk-handle
IAK            present        present (cert lacks verifiedTPMRestricted) 0x81010002; issuer ca01.cp.example.com
IDevID         present        present                                    0x81020000; issuer ca01.cp.example.com
```

How to read a row:

- **`HANDLE`** is `present`, `absent` or `error`. `absent` is printed **only**
  when the daemon positively reports the object missing (`HasIAK`/`HasIDevID`
  false, or a `NotFound` from the SRK/EK lookup). Any other failure prints
  `error` with `error: <reason>` in `NOTES` — an unreachable daemon never
  looks like an unprovisioned node.
- **`CERTIFICATE`** is `present` or `n/a`. On the IAK row it is annotated
  `present (cert lacks verifiedTPMRestricted)` when the certificate does not
  carry the TCG policy `2.23.133.11.1.3` (tcg-cap-verifiedTPMRestricted). The
  attestation verifier requires that policy on the attestation key, so such a
  node is provisioned but will not pass attestation until the IAK certificate
  is re-issued by a CA that stamps it. The verdict is the verifier's own
  predicate (`vm.CarriesVerifiedTPMRestricted`); it is not evaluated for the
  IDevID, which is not an attestation key.
- **`NOTES`** carries the handle, the certificate issuer CN and
  `verifiedTPMRestricted` when present; the remedy (`tpm iak generate` …) when
  absent.
- **`PlatformSRK`** is probed at `0x81000002`, platformd's default for
  `tpm.platform-srk.handle`, because the daemon does not expose the configured
  value over the API. A node configured with a different handle must be probed
  with `--platform-srk-handle 0x8100XXXX`; the row says which handle it used.

`-o json` / `-o yaml` keep the pre-#471 keys (`name`, `role`, `handle_present`,
`cert_present`, `cert_format`, `error`) and add, when known, `handle`,
`issuer`, `cert_policies` (every certificatePolicies OID), `note`, and on the
IAK row `verified_tpm_restricted`.

**`flush` is the fix for `TPM_RC_OBJECT_MEMORY`.** Reach for it when operations
start failing after a long-running session, not as routine hygiene.

---

## 3. Provisioning and clearing

**`provision`**

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--create-ek` | bool | **`true`** | Create the Endorsement Key |
| `--create-srk` | bool | **`true`** | Create the Storage Root Key |
| `--create-ak` | bool | **`true`** | Create the Attestation Key |
| `--owner-password` | string | `""` | Owner hierarchy password |
| `--endorsement-password` | string | `""` | Endorsement hierarchy password |

All three `--create-*` default to **true**, so a bare `platformctl tpm provision`
creates all three keys. To create only one, disable the others explicitly
(`--create-srk=false --create-ak=false`).

**`clear`**

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--confirm` | bool | `false` | **Required.** Without it the command prints a warning and exits 0 |
| `--owner-password` | string | `""` | Owner/lockout hierarchy password |
| `--force` | bool | `false` | Clear via UEFI PPI on next boot, then reboot immediately |
| `--device` | string | `/dev/tpm0` | TPM device path — **`--force` only** |

```bash
platformctl tpm provision --owner-password "$OWNER_PW"
platformctl tpm clear --confirm
platformctl tpm clear --force --confirm            # reboots the machine
```

**Without `--confirm`, `clear` does nothing and still exits 0.** It prints
`Use --confirm to proceed.` Scripts that check only the exit status will believe
the TPM was cleared.

**`--force` is a different code path, not a stronger flag.** It bypasses the
daemon entirely, opens the TPM at `--device` (default `/dev/tpm0`, *not*
`/dev/tpmrm0`), schedules a Physical Presence Interface clear that firmware
services on the next boot, then writes `b` to `/proc/sysrq-trigger` to reboot
immediately. Use it when the TPM is in DA lockout or its hierarchy auth is
unknown — the two cases where `TPM2_Clear` cannot work. If the auto-reboot
fails it tells you to reboot manually; the clear is already scheduled either way.

---

## 4. Keys

### `platformctl tpm ek`

| Verb | Flags |
|---|---|
| `create` | `--algorithm` (default `RSA-2048`), `--persistent` (default **`true`**) |
| `info` | `--handle` (uint32, default `0x81010001`) |
| `certificate` | — |
| `delete` | `--handle` (default `0x81010001`), `--password` |

`--algorithm` accepts `RSA-2048`, `RSA-3072`, `ECDSA-P256`, `ECDSA-P384`. An
unrecognised value fails locally with `ErrInvalidKeyAlgorithm` before any RPC.

```bash
platformctl tpm ek info
platformctl tpm ek create --algorithm ECDSA-P256
platformctl tpm ek certificate > ek.pem
```

**`ek certificate` prints PEM, never raw DER.** The code converts before
printing because raw DER contains bytes (`ESC`, `Shift-Out`) that corrupt a
terminal — a real incident on a serial console. JSON and YAML output get the
same PEM-safe string.

### `platformctl tpm srk`

| Verb | Flags |
|---|---|
| `create` | `--algorithm` (default `RSA-2048`), `--persistent` (default **`true`**), `--parent` (uint32, default `0x81010001`), `--parent-password` |
| `info` | `--handle` (uint32, default `0x81000001`) |
| `delete` | `--handle` (default `0x81000001`), `--password` |

**`srk create --parent` defaults to the EK handle** (`0x81010001`), and
`srk info --handle` defaults to the **SSRK** handle (`0x81000001`). The
PlatformSRK at `0x81000002` is a different key and must be named explicitly.

**`--handle` now works on every transport.** Before #475 the REST, QUIC and MCP
handlers ignored it and answered from the SSRK, so `srk info --handle
0x81000002` returned the *storage* key with a success status unless the CLI
happened to be talking gRPC or the Unix socket. A handle naming neither key is
now an error on all five rather than a silent fall-through.

```bash
platformctl tpm srk create --algorithm ECDSA-P256 --parent 0x81010001
platformctl tpm srk info --handle 0x81000002        # the PlatformSRK
```

---

## 5. Sealing, NVRAM and the event log

**`seal`**

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--cn` | string | | Common name for the sealed object (**required**) |
| `--data` | string | `""` | Data to seal — **a raw string, not base64** |
| `--password` | string | `""` | Authorization for the sealed object |
| `--parent` | uint32 | `0x81000001` | Parent SRK handle |
| `--parent-password` | string | `""` | Parent key password |
| `--pcrs` | int slice | none | PCR indices to bind to, comma-separated |
| `--pcr-bank` | string | `sha256` | `sha1`, `sha256`, `sha384`, `sha512` |
| `--overwrite` | bool | `false` | Replace existing sealed data with this CN |
| `--policy` | bool | `true` | **Parsed and discarded — see §6** |

**`unseal`**

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--cn` | string | | Common name of the sealed object (**required**) |
| `--password` | string | `""` | Authorization |
| `--parent` | uint32 | `0x81000001` | Parent SRK handle |
| `--parent-password` | string | `""` | Parent key password |
| `--pcrs` | int slice | none | PCR indices |
| `--pcr-bank` | string | `sha256` | Bank |

```bash
platformctl tpm seal   --cn db-master --data "$SECRET" --pcrs 7,9 --password "$PW"
platformctl tpm unseal --cn db-master --password "$PW"
```

**Encoding differs from `platformctl vtpm`.** `vtpm seal --data` is base64;
`tpm seal --data` is a raw string, passed through as `[]byte(opts.Data)`. Binary
secrets need a shell that can pass the bytes intact.

**`unseal` writes the secret to stdout** in `table` mode with no trailing
newline, and into a `data` field in `json`/`yaml` mode. Redirect it; do not let
it land in a terminal scrollback.

**`--pcrs` binds the object to those PCR values.** It unseals only while they
still match — that is the point, and it is also why an unseal that worked
yesterday fails after a firmware or bootloader change.

**`nvram`**

| Verb | Flags |
|---|---|
| `define` | `--index` (**required**), `--size` (**required**), `--password`, `--attributes` (string slice, e.g. `AUTHWRITE`, `AUTHREAD`) |
| `write` | `--index` (**required**), `--data` (**required**), `--password`, `--offset` (default `0`) |
| `read` | `--index` (**required**), `--password`, `--offset` (default `0`), `--size` (default `0` = all), `--hex` |
| `delete` | `--index` (**required**), `--password` |

```bash
platformctl tpm nvram define --index 0x01000001 --size 256 --attributes AUTHWRITE,AUTHREAD
platformctl tpm nvram write  --index 0x01000001 --data "hello"
platformctl tpm nvram read   --index 0x01000001 --hex
platformctl tpm nvram delete --index 0x01000001
```

`--index` is a `uint32` flag, so hex literals (`0x01000001`) work. Index ranges,
from the command's own help: `0x01000000`–`0x01FFFFFF` owner-defined,
`0x01400000`–`0x017FFFFF` platform, `0x01800000`–`0x01BFFFFF` endorsement,
`0x01C00000`–`0x01FFFFFF` TCG-defined.

**`eventlog`**

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--format` | string | `text` | `json`, `text`, `binary` |

With `--format binary` the log is hex-encoded into the response rather than
written as raw bytes.

---

## 6. Verbs that exist and do nothing

Six verbs are registered, appear in `--help`, and return
`ErrDaemonConnectionRequired` **unconditionally** — before any connection is
attempted. They are not "broken when the daemon is down"; they are unwired.

| Verb | Error operation string | Long help advertises (none registered) |
|---|---|---|
| `tpm install` | `install` | `--so-pin` |
| `tpm destroy` | `destroy` | `--lockout-password`, `--confirm` |
| `tpm policy` | `policy` | positional `create` / `session` |
| `tpm extend` | `extend` | (none) |
| `tpm enroll` | `enroll` | `--acme-server`, `--cn`, `--ip`, `--force` |
| `tpm xkms` | `xkms` | `--parent`, `--parent-password`, `--parent-policy`, `--password`, `--ca`, `--tls`, `--hmac`, `--policy`, and positional `generate` / `delete` / `info` |

The message is `daemon connection required: operation '<op>' not yet supported`.

Two consequences worth stating plainly:

- **The platform PCR cannot be extended from the CLI.** `tpm extend` is the verb
  for it and it does not work. The extension happens automatically in
  `App.OpenTPM` on every boot; on QUIC it is `SubOpTPM2ExtendPCR`, and on MCP it
  is `platform_tpm_pcr_extend`.
- **ACME device enrollment cannot be driven from `platformctl tpm`.** Build the
  CSR with `tpm idevid csr` / `tpm iak csr` and complete enrollment through the
  CA surface.

`tpm seal --policy` used to be a seventh case of the same class — registered,
parsed, never carried by any request — and was removed in #681 rather than
wired: PCR binding is `--pcrs`, and the sealed object's auth is `--password`.

---

## 7. Device identity

### `platformctl tpm idevid`

| Verb | Flags |
|---|---|
| `generate` | `--algorithm` (default `ECDSA-P256`), `--overwrite` |
| `info` | — |
| `delete` | — |
| `csr` | `--common-name`, `--organization`, `--country`, `--state`, `--locality`, `--organizational-unit` |
| `install` | `--cert-file` (**required** — `MarkFlagRequired`, PEM) |
| `certificate` (alias `cert`) | — |

**`--common-name` on `csr` is described as required in its help text but is not
marked required by the parser.** Omitting it produces a server-side failure, not
a usage error. `--cert-file` on `install` *is* enforced locally.

### `platformctl tpm iak`

Identical shape: `generate`, `info`, `delete`, `csr`, `install`,
`certificate` (alias `cert`), with the same flags.

`--algorithm` on both accepts `ECDSA-P256` (default, TCG-preferred),
`ECDSA-P384`, `RSA-2048`, `RSA-3072`.

### `platformctl tpm idevid ldevid create`

An LDevID (IEEE 802.1AR) is a locally significant, CA-issued **operational**
identity layered on the permanent IDevID **birth** identity. Issuance is refused
unless the device has a proven, currently valid IDevID certificate installed.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--common-name` | string | the IDevID CN | Subject CN |
| `--organization` | string | `""` | Subject O |
| `--organizational-unit` | string | `""` | Subject OU |
| `--country` | string | `""` | Subject C (2 letters) |
| `--state` | string | `""` | Subject ST |
| `--locality` | string | `""` | Subject L |
| `--algorithm` | string | `ECDSA-P256` | `ECDSA-P256`, `ECDSA-P384`, `RSA-2048`, `RSA-3072` |
| `--handle` | string | `0x81010102` | Persistent handle; hex `0x…` or decimal |
| `--profile` | string | `""` | Platform CA certificate profile used for issuance |
| `--validity-days` | uint32 | `0` | `0` = CA/profile default |
| `--overwrite` | bool | `false` | Replace an existing LDevID key at the handle |
| `--out` | string | `""` | Write the issued certificate PEM here; the CSR goes to `<out>.csr` |

```bash
platformctl tpm idevid generate --algorithm ECDSA-P256
platformctl tpm idevid csr --common-name node-01.example.com --organization "Example Inc"
platformctl tpm idevid install --cert-file ./node-01-idevid.pem
platformctl tpm idevid certificate

platformctl tpm iak generate
platformctl tpm iak csr --common-name node-01.example.com
platformctl tpm iak install --cert-file ./node-01-iak.pem

platformctl tpm idevid ldevid create \
    --common-name node-01.example.com \
    --algorithm ECDSA-P256 \
    --out ./node-01-ldevid.pem
```

**`--handle` on `ldevid create` is a string, not a uint32 flag**, unlike
`--handle` on `ek info` / `srk info`. It parses both hex and decimal.

**There is no `ldevid info`, `ldevid delete` or `ldevid certificate`.** `create`
is the only LDevID verb.

---

## 8. What the CLI does not cover

| Capability | Reach it with |
|---|---|
| Quote the physical TPM | **No CLI verb anywhere.** There is no `platformctl attestation` group; the only attest verb is `platformctl container attest`, which quotes a container's measurement ([`docs/attestation/cli.md`](../attestation/cli.md) §1). Direct quoting is gRPC `Quote`, REST `POST /api/v1/tpm/quote`, QUIC `0x0F`, MCP `platform_tpm_quote` |
| Verify a quote | gRPC `VerifyQuote`, REST `POST /api/v1/tpm/quote/verify`, QUIC `0x10`, MCP `platform_tpm_verify_quote` |
| Read or extend physical PCRs | REST `GET /api/v1/tpm/pcrs` (read); extend is QUIC `0x12` or MCP `platform_tpm_pcr_extend` only |
| Attestation key (AK/IAK) create, get, delete on the *TPMService* surface | gRPC `CreateAK`/`GetAK`/`DeleteAK`, REST `/api/v1/tpm/ak`, QUIC `0x0C`–`0x0E` (named IAK), MCP `platform_tpm_iak*` |
| Import an EK certificate | gRPC `ImportEKCertificate`, REST `POST /api/v1/tpm/ek/certificate`, QUIC `0x08`, MCP `platform_tpm_ek_import_cert` |
| Get random bytes from the TPM | gRPC `GetRandom`, REST `POST /api/v1/tpm/random`, QUIC `0x14`, MCP `platform_tpm_random` |
| MakeCredential / ActivateCredential | gRPC, QUIC `0x20`/`0x21`, MCP — **not REST** |
| TPM capabilities, NV index listing, platform attributes, certify | QUIC and MCP only |
| Virtual TPMs | `platformctl vtpm` — [`docs/vtpm/cli.md`](../vtpm/cli.md) |

---

## 9. Exit codes and output

`0` on success, non-zero on failure, with the structured error rendered in the
selected `--output` format. `--output json` is the form to parse; the `table`
renderer is for humans and its columns are not a stable interface. An
unsupported `--output` value fails with `cli.ErrInvalidOutputFormat`.

The exception is `tpm clear` without `--confirm`, which prints a warning and
exits `0` (§3).

---

## 10. Parity

`conventions/feature-docs.md` §4 requires every verb here to have a matching
entry in the integration parity suite. **This repository defines no
`CommandDefinition` type** (grepped 2026-08-18). The TPM feature uses a
different mechanism that satisfies the intent: `test/integration/tpm/commands.go`
declares a `TPMCommands` interface implemented by six protocol adapters, and
`TestTPMMultiProtocol` runs one suite across all of them
(`make integration-test-tpm`).

Coverage is partial. `TPMCommands` covers `Info`, `Provision`, `Clear`, EK
create/info/certificate/delete, SRK create/info/delete, `Seal`, `Unseal` and
`EventLog`. **NVRAM, device identity (IDevID/IAK/LDevID), `flush`, `status` and
`device attributes` have no parity coverage.** The naming mismatch against the
convention, and the gap, are raised for the owner rather than marked satisfied.
