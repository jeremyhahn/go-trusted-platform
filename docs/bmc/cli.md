# BMC — CLI

> **Status: NORMATIVE** · Scope: `platformctl bmc` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> Every verb and every flag below was read out of `pkg/cli/commands/bmc/` on
> 2026-08-18. All hosts in examples are placeholders.

---

## 1. Command group

```
platformctl bmc          Baseboard Management Controller operations
platformctl bmc cert     Manage BMC web server certificates
platformctl bmc user     Manage BMC user accounts
```

Eighteen entries registered in `NewCommand` (`bmc.go`): fifteen leaf verbs plus
the `cert` and `user` groups.

| Verb | Group | Reaches the BMC via |
|---|---|---|
| `power-on`, `power-off`, `power-reset`, `power-cycle`, `power-status` | — | daemon REST **or** standalone |
| `set-boot-device`, `get-boot-device` | — | daemon REST **or** standalone |
| `mount-iso`, `unmount-iso`, `media-status` | — | daemon REST **or** standalone |
| `sensors`, `system-info` | — | daemon REST **or** standalone |
| `provision` | — | daemon REST only |
| `mac` | — | **standalone only** |
| `console` | — | **standalone only** |
| `cert get`, `cert status`, `cert replace` | `cert` | daemon **gRPC SDK** or standalone |
| `cert restore` | `cert` | daemon gRPC SDK only |
| `enroll` | — | daemon gRPC SDK only |
| `user list`, `user create`, `user delete`, `user update-password`, `user update-access` | `user` | daemon gRPC SDK or standalone |

## 2. Three client paths, not one

This group does **not** use a single transport, and knowing which path a verb
takes is what makes its flags make sense.

| Path | Verbs | Flags it needs |
|---|---|---|
| **Raw HTTP to platformd** — builds its own `*http.Client` and calls `/api/v1/bmc/...` | power, boot device, virtual media, sensors, system-info, provision | `--server-url`, `--profile-id`, `--ca-cert`, `--client-cert`, `--client-key` |
| **gRPC SDK to platformd** — `cli.NewBaseCommand` → `base.Client().BMC()` → `sdk/go/services/bmc` | `cert get`/`status`/`replace`/`restore`, `enroll`, `user *` | `--profile-id` plus the `platformctl` persistent transport flags |
| **Standalone** — direct IPMI/Redfish, no daemon | everything except `provision`, `enroll`, `cert restore` | `--bmc-host` and the `--bmc-*` set |

`--server-url` is **not** a `platformctl` persistent flag; it is registered
per-verb only on the raw-HTTP path. The SDK-path verbs use the persistent
`--server` / `--transport` / `--context` flags instead. Passing `--server-url`
to `bmc enroll` does nothing.

### Global (`platformctl` persistent) flags

`pkg/cli/commands/root.go`. Precedence is **flag > environment > config file >
built-in default**.

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

**`--transport embedded` cannot reach any BMC verb.** The embedded
`ServiceRegistry` has no `BMC` field ([api.md](api.md) §2). Use `--bmc-host`
standalone mode when there is no daemon.

### Daemon-mode flags (raw-HTTP path)

Registered individually on power, boot, media, sensor, system-info and
provision verbs.

| Flag | Type | Default | Environment | Meaning |
|---|---|---|---|---|
| `--server-url` | string | `""` | | platformd URL (**required** in daemon mode) |
| `--profile-id` | string | `""` | | Device profile ID (**required** in daemon mode) |
| `--ca-cert` | string | `""` | `PLATFORM_CA_CERT` | CA bundle verifying the platformd certificate |
| `--client-cert` | string | `""` | `PLATFORM_CLIENT_CERT` | Client certificate for mutual TLS |
| `--client-key` | string | `""` | `PLATFORM_CLIENT_KEY` | Client key |

`InsecureSkipVerify` is never set on this client. With no CA bundle the system
trust store is used.

### Standalone flags

Registered by `addStandaloneFlags` on every verb that supports the direct path.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--bmc-host` | string | `""` | BMC IP or hostname. **Setting it selects standalone mode** |
| `--bmc-port` | int | `0` | `0` → 443 for Redfish, 623 for IPMI |
| `--bmc-user` | string | `""` | BMC username (**required** in standalone mode) |
| `--bmc-pass` | string | `""` | BMC password. Prefer `--bmc-pass-file` |
| `--bmc-pass-file` | string | `""` | Path to a password file; mode must be `0600` or stricter |
| `--bmc-protocol` | string | `auto` | `redfish`, `ipmi`, or `auto` (probe) |
| `--bmc-pin` | string | `""` | Hex SHA-256 SPKI fingerprint of the BMC TLS leaf |
| `--bmc-ca-file` | string | `""` | PEM CA bundle for the BMC. Mutually exclusive with `--bmc-pin` |

**Mode selection is explicit and enforced.** `checkModeConflict` rejects both
flag sets together (`ErrBMCFlagConflict`) and rejects neither
(`ErrBMCNoMode`). Nothing is guessed.

**`--bmc-pass` and `--bmc-pass-file` are mutually exclusive.** A password file
whose permission bits allow group or other access is refused outright with
`ErrBMCInsecurePasswordFile` — it is not read and then warned about.

**Standalone Redfish with neither `--bmc-pin` nor `--bmc-ca-file`:**

- On an interactive terminal, `platformctl` dials once with verification off to
  capture the peer certificate — exchanging no application data — prints the
  subject, issuer, expiry and SPKI pin to stderr, and requires you to type
  `yes`. It then reconnects *pinned*, and tells you the `--bmc-pin` value to
  use next time.
- Non-interactively it fails with `ErrBMCNoPinOrCAFile`. Scripts must pin.

---

## 3. Power

| Verb | Purpose |
|---|---|
| `power-on` | Power on |
| `power-off` | Power off (hard) |
| `power-reset` | Hard reset |
| `power-cycle` | Off then on |
| `power-status` | Query state |

Flags: the daemon-mode set and the standalone set (§2). No verb-specific flags.

```bash
platformctl bmc power-on \
    --server-url https://platform.example.com:8443 \
    --profile-id 42

platformctl bmc power-status \
    --bmc-host bmc.example.com \
    --bmc-user admin \
    --bmc-pass-file "$XDG_CONFIG_HOME/platform/bmc.pass" \
    --bmc-protocol ipmi \
    --bmc-pin 3f2a...c91d
```

Daemon mode POSTs `{"action":"on"|"off"|"reset"|"cycle"}` to
`/api/v1/bmc/{profileID}/power`. `power-status` GETs the same path.

---

## 4. Boot device

**`set-boot-device`**

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--device` | string | `""` | **Required.** `pxe`, `disk`, `cdrom`, `bios` |
| `--persistent` | bool | `false` | Survive reboots |

**`get-boot-device`** takes no verb-specific flags.

```bash
platformctl bmc set-boot-device \
    --server-url https://platform.example.com:8443 \
    --profile-id 42 --device pxe --persistent
```

**The CLI's accepted device set is not the API's.** `validBootDevices` in
`pkg/cli/commands/bmc/helpers.go` accepts `pxe`, `disk`, `cdrom`, `bios`, while
`bmc.BootDevice` defines `pxe`, `disk`, `cdrom`, `virtual_media`, `none`.
So `--device virtual_media` and `--device none` are rejected by the CLI even
though the API accepts them, and `--device bios` is accepted by the CLI with no
matching `BootDevice` constant. Use REST, gRPC or MCP to select
`virtual_media` or to clear an override with `none`.

**`--persistent` does not always mean what it says.** On boards whose quirk sets
`BootOverrideContinuous` (all Supermicro entries, and the VeloCloud EDGE840),
the Redfish path always requests `Continuous` regardless of this flag, because
X10 ATEN firmware erases a `Once` override before BIOS POST reads it. Clear it
afterwards with a `none` override through a non-CLI transport.

---

## 5. Virtual media

**`mount-iso`**

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--iso-url` | string | `""` | **Required.** URL of the ISO |

**`unmount-iso`**, **`media-status`**: no verb-specific flags.

```bash
platformctl bmc mount-iso \
    --server-url https://platform.example.com:8443 \
    --profile-id 42 \
    --iso-url https://images.example.com/installer.iso

platformctl bmc media-status --server-url https://platform.example.com:8443 --profile-id 42
platformctl bmc unmount-iso  --server-url https://platform.example.com:8443 --profile-id 42
```

Virtual media is a Redfish operation. On a `protocol: ipmi` profile the IPMI
client opens an embedded Redfish connection on port 443 with the same
credentials — so the BMC's HTTPS port must be reachable even when the profile
says IPMI.

`mount-iso` only takes a URL. The richer `bmc.MediaSpec` form — explicit
`Protocol` (`http`, `https`, `cifs`, `nfs`), share `Username`/`Password`,
`WriteProtected` — has no CLI surface; reach it in-process through `pkg/bmc`.

---

## 6. Sensors and system info

`sensors` and `system-info` take no verb-specific flags.

```bash
platformctl bmc sensors     --server-url https://platform.example.com:8443 --profile-id 42
platformctl bmc system-info --bmc-host bmc.example.com --bmc-user admin \
    --bmc-pass-file /etc/platform/bmc.pass --bmc-protocol ipmi
```

On IPMI, sensors come from SDR repository parsing and system info from FRU
data; on Redfish, from the Thermal/Power and System resources.

---

## 7. `platformctl bmc provision`

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--iso-url` | string | `""` | ISO for provisioning (optional) |

Daemon-only. `POST /api/v1/bmc/{profileID}/provision`. The standalone flags are
registered on the command but passing `--bmc-host` returns
`ErrBMCRequiresDaemon{Subcommand: "provision"}` — BMC profile persistence
requires `platformd`.

```bash
platformctl bmc provision \
    --server-url https://platform.example.com:8443 \
    --profile-id 42 --iso-url https://images.example.com/installer.iso
```

**This returns an error on a stock daemon.** `pkg/api/daemon/daemon.go`
constructs the BMC gRPC service with a nil baremetal orchestrator, so
`Provision` and `ProvisionStatus` return `FailedPrecondition` until one is
wired via `SetBaremetalService`.

---

## 8. `platformctl bmc mac`

Standalone only — it takes the standalone flag set and nothing else, and errors
if `--bmc-host` is absent.

```bash
platformctl bmc mac \
    --bmc-host bmc.example.com \
    --bmc-user ADMIN \
    --bmc-pass-file "$XDG_CONFIG_HOME/platform/bmc.pass" \
    --bmc-protocol ipmi
```

`--output json` prints `{"host": "...", "macs": ["..."]}`, primary MAC first.

Two discovery paths, chosen automatically:

- **Redfish** walks the system's `EthernetInterfaces` collection and returns
  every valid unicast MAC.
- **IPMI (Supermicro OEM)** issues NetFn `0x30` / Cmd `0x21` over the RMCP+
  session. This is the only out-of-band path on X10 ATEN firmware, whose
  Redfish `EthernetInterfaces` collection is empty. The OEM command is gated on
  the IANA enterprise number from Get Device ID — a model-independent check, so
  rebadged Supermicro boards with an empty SMBIOS model string still take it.
  Other vendors fall through to a Redfish probe.

The same dispatch backs `platformctl bootstrap discover`, so IPMI-only fleets
need no operator-supplied MAC list.

---

## 9. `platformctl bmc console`

Standalone only. There is no `platformd` proxy: SOL is a long-lived
bidirectional stream with no request/response shape.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--log-file` | string | `""` | Capture output to a file instead of an interactive terminal |
| `--send-break` | bool | `false` | Send one serial break and exit |
| `--send` | string array | `nil` | Send a literal string, then continue. Repeatable |
| `--send-delay` | duration | `500ms` | Delay between consecutive `--send` strings |
| `--sol-instance` | uint8 | `0` | IPMI 2.0 SOL payload instance (Table 24-2). `0` consults the quirk registry, falling back to `0x01` |

Plus the standalone flag set. Requires `--bmc-protocol ipmi`, or auto-detection
landing on IPMI — Redfish exposes no SOL transport.

```bash
# Interactive; Ctrl+] disconnects, stdin is in raw mode for the session
platformctl bmc console \
    --bmc-host bmc.example.com --bmc-user admin \
    --bmc-pass-file /etc/platform/bmc.pass --bmc-protocol ipmi

# Capture without a TTY
platformctl bmc console \
    --bmc-host bmc.example.com --bmc-user admin \
    --bmc-pass-file /etc/platform/bmc.pass --bmc-protocol ipmi \
    --log-file /var/log/sol-node-01.log

# Drive a recovery non-interactively
platformctl bmc console \
    --bmc-host bmc.example.com --bmc-user admin \
    --bmc-pass-file /etc/platform/bmc.pass --bmc-protocol ipmi \
    --log-file recovery.log --send 'reset\r' --send 'boot\r'

# Kick a stuck firmware menu
platformctl bmc console --bmc-host bmc.example.com --bmc-user admin \
    --bmc-pass-file /etc/platform/bmc.pass --bmc-protocol ipmi --send-break
```

Recognized escapes in `--send`: `\r`, `\n`, `\t`, `\\`, `\e` (ESC, `0x1b`),
`\xNN`. **Unknown escapes are rejected**, so a typo cannot silently become a
literal backslash sequence on the console.

**A zero-byte SOL log is almost always the wrong payload instance.** Activating
instance `0x01` against a board wired to `0x02` succeeds at the protocol level
and streams nothing. `--sol-instance 2` is the diagnostic; a quirk entry is the
fix.

---

## 10. `platformctl bmc cert`

Four verbs: `get`, `status`, `replace`, `restore`.

| Verb | Flags |
|---|---|
| `get` | `--profile-id` (daemon mode) + standalone set |
| `status` | `--profile-id` (daemon mode) + standalone set |
| `replace` | `--profile-id`, `--cert` (path, required), `--key` (path, required) + standalone set |
| `restore` | `--profile-id` (required), `--factory` (bool, **required**) |

`get` and `status` run the **same code path** and print the same fields:
subject, issuer, serial, not-before, not-after, days remaining, SANs,
fingerprint. `status` exists as a name for renewal monitoring.

```bash
platformctl bmc cert get --profile-id 42
platformctl bmc cert get --profile-id 42 --output json

# Capture a pin for later scripted use — this is how you obtain --bmc-pin
platformctl bmc cert get --bmc-host bmc.example.com --bmc-user admin \
    --bmc-pass-file /etc/platform/bmc.pass

platformctl bmc cert replace --profile-id 42 \
    --cert <install-dir>/certs/bmc.pem --key <install-dir>/certs/bmc-key.pem

platformctl bmc cert restore --profile-id 42 --factory
```

**`cert get` works against any BMC**, including one whose firmware supports no
certificate management: it reads the live TLS handshake peer certificate rather
than asking a backend.

**`--factory` on `restore` is required and has no default.** It exists only to
make accidental invocation impossible. Restore removes the platform-issued
certificate and cannot be undone without re-enrolling. It also does **not**
re-upload your backup — the platform never held that key; the BMC regenerates
its own self-signed certificate.

`cert restore` has **no standalone mode**: the ceremony deletes the platform's
SPKI pin, removes DANE TLSA records and clears `Device.BMCEnrollment`, none of
which exist without a daemon.

---

## 11. `platformctl bmc user`

Five verbs. All accept `--profile-id` (daemon) or the standalone flag set.

| Verb | Verb-specific flags |
|---|---|
| `list` | — |
| `create` | `--username` (required), `--role` (required), `--slot` uint32 default `0` (auto-assign), `--channel` uint32 default `1` |
| `delete` | `--username` (required) |
| `update-password` | `--username` (required) |
| `update-access` | `--username` (required), `--role` (required), `--channel` uint32 default `1` |

Valid `--role` values: `administrator`, `operator`, `user`, `callback`,
`no-access`.

```bash
platformctl bmc user list --profile-id 42
platformctl bmc user list --profile-id 42 --output json

platformctl bmc user create --profile-id 42 --username operator1 --role operator
platformctl bmc user update-password --profile-id 42 --username operator1
platformctl bmc user update-access  --profile-id 42 --username operator1 --role administrator
platformctl bmc user delete --profile-id 42 --username operator1
```

**Passwords are never flags.** `create` and `update-password` prompt on stderr;
there is no `--password`. That is deliberate — a password in `argv` is visible
in `ps` and in shell history.

`delete`, `update-password` and `update-access` take a `--username` and resolve
the slot by listing accounts first. `--slot` on `create` exists for hardware
that requires an explicit slot; `0` auto-assigns.

---

## 12. `platformctl bmc enroll`

| Flag | Type | Default | Environment | Meaning |
|---|---|---|---|---|
| `--profile-id` | string | `""` | | **Required** |
| `--backups-dir` | string | `""` | `PLATFORMCTL_BACKUPS_DIR` | Persist the factory certificate and full result client-side |
| `--replace-certificate` | bool | tri-state | | Override the profile's `replace-certificate` |
| `--rotate-password` | bool | tri-state | | Override `rotate-password` |
| `--dns-register` | bool | tri-state | | Override `dns-register` |
| `--dane-publish` | bool | tri-state | | Override `dane-publish` |

**The four override flags are tri-state, not booleans with a `false` default.**
The command inspects `cmd.Flags().Changed(name)`: a flag you did not pass sends
a nil pointer and the profile's stored value is used unchanged. Passing
`--rotate-password=false` is therefore meaningfully different from omitting it.
The cobra default of `false` shown above is the *variable's* zero value, not the
effective behavior.

```bash
# Use the profile's stored enrollment policy
platformctl bmc enroll --profile-id 7

# Override individual steps for this invocation only
platformctl bmc enroll --profile-id 7 \
    --replace-certificate --rotate-password --dns-register --dane-publish

# Keep the factory-certificate evidence
platformctl bmc enroll --profile-id 7 --backups-dir <install-dir>/backups
```

With `--backups-dir` (or `PLATFORMCTL_BACKUPS_DIR`) set and a factory
certificate returned, three files are written under `<dir>/<hostname>/bmc/`,
directory mode `0700`, files `0600`:

| File | Contents |
|---|---|
| `factory-cert.pem` | PEM factory TLS certificate |
| `factory-cert.json` | Subject, issuer, serial, validity, SPKI SHA-256, DER SHA-256, capture time |
| `enrollment.json` | The full enrollment result, all steps |

With neither set, a notice goes to stderr and no backup is written. The backup
is **identity evidence only** — the platform never holds the factory key and can
never re-deploy it.

The result lists every ceremony step — `trust`, `factory-cert`, `credentials`,
`replace-certificate`, `dns-register`, `dane-publish`, `device-stamp` — with an
outcome each, including skipped ones and why. A failure still prints the partial
result.

---

## 13. Exit codes and output

`0` on success, non-zero on failure. `--output json` is the parseable form;
the `table` renderer is for humans and its columns are not a stable interface.
Interactive prompts (password entry, SPKI confirmation) go to **stderr**, so
`--output json` piped to a parser stays clean.

The daemon REST path unwraps the platform envelope
(`{"code","success","error","payload"}`) transparently; a non-zero `code` with
an `error` string becomes `ErrUnexpectedStatus`.

---

## 14. Parity gap

`conventions/feature-docs.md` §4 requires every verb here to have a matching
`CommandDefinition` in the integration parity suite. **This repository defines
no `CommandDefinition` type** — grepped repo-wide on 2026-08-18, it appears only
in documentation. The requirement is unmet repo-wide, not only for BMC, and is
recorded here rather than quietly marked satisfied.
