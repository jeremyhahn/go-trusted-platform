# Firmware Trust — CLI

> **Status: NORMATIVE** · Scope: `platformctl secure-boot`, `platformctl authenticode`, `platformctl install uki`, `platformctl install uki-rebuild`, `platformctl iso module-signing-key` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> Every verb and every flag below was read out of `pkg/cli/commands/secureboot/`,
> `pkg/cli/commands/authenticode/`, `pkg/cli/commands/install/` and
> `pkg/cli/commands/iso/` on 2026-08-18.

---

## 1. The command groups

```
platformctl secure-boot            Bare-metal UEFI Secure Boot operations (efivarfs)
                                   aliases: secureboot, sb
platformctl authenticode           Authenticode signing and verification
platformctl install uki            Build a Unified Kernel Image
platformctl install uki-rebuild    Rebuild and re-sign the UKI after a kernel update
platformctl iso module-signing-key Generate the stable kernel module-signing key
```

There is **no `platformctl firmware` command group** and **no `platformctl ota`
command group** (grepped 2026-08-18). Everything the legacy
[README.md](README.md) shows under those names is PLANNED — see
[architecture.md](architecture.md) §9.

**Every verb here runs locally.** None of them talks to a daemon on a chosen
transport, with one exception: `install uki-rebuild` opens a platform SDK client
when — and only when — `secure-boot.resign-mode` is `remote` and the DB key URI
is not a `file://` reference, in order to hash-sign the digest against the
control-plane KMS. Everything else works with no server at all, including
`secure-boot status`, `secure-boot enroll --commit` and `authenticode sign`.

### Global flags

`platformctl` persistent flags (`pkg/cli/commands/root.go`). Precedence is
**flag > environment > config file > built-in default**.

| Flag | Short | Default | Environment | Meaning |
|---|---|---|---|---|
| `--config` | `-c` | platform default config path | `PLATFORMCTL_CONFIG` | Config file |
| `--context` | | current-context | `PLATFORMCTL_CONTEXT` | Named context to use |
| `--transport` | | from context | `PLATFORMCTL_TRANSPORT` | `unix`, `grpc`, `rest`, `quic`, `mcp`, `embedded` |
| `--server` | | from context | `PLATFORMCTL_SERVER` | Server address; implies a remote context |
| `--server-name` | | | `PLATFORMCTL_SERVER_NAME` | TLS SNI / certificate verification hostname |
| `--output` | `-o` | `table` | `PLATFORMCTL_OUTPUT` | `table`, `json`, `yaml` |
| `--verbose` | `-v` | `false` | | Verbose output |
| `--no-color` | | `false` | `NO_COLOR` | Disable coloured output |

**`-v` collides in two places.** The root binds `-v` to `--verbose`;
`install uki` and `install uki-rebuild` each bind their own local `-v/--verbose`.
Cobra resolves the local flag first. Prefer long forms in scripts.

---

## 2. `platformctl secure-boot`

Operates on the **running firmware** through `/sys/firmware/efi/efivars`. This
is the bare-metal counterpart to OVMF NVRAM-file enrollment for virtual
machines.

Safety model, enforced identically by every verb:

- `status` is strictly read-only.
- `enroll` and `enforce` **default to dry-run**; nothing is written without
  `--commit`.
- Enrollment requires the firmware to be in Setup Mode.
- The signed UKI is Authenticode-verified against the `db` certificate **before**
  any variable is written.
- Keys are written `db` → `KEK` → `PK`, PK **last**.

### 2.1 `secure-boot status`

Report firmware Secure Boot state. Performs no writes.

| Flag | Type | Default | Required | Meaning |
|---|---|---|---|---|
| `--efivars` | string | `/sys/firmware/efi/efivars` | no | efivarfs directory to read; override for rehearsal against a fixture directory |

Prints `SetupMode`, `SecureBoot`, `UserMode` (each rendered `enabled`/`disabled`
in table output) and a one-line summary of each of `PK`, `KEK`, `db`, `dbx`:
certificate count, hash count, other-entry count, and the X.509 subjects. A
database that is not present prints `absent`.

```bash
platformctl secure-boot status
platformctl secure-boot status -o json
```

### 2.2 `secure-boot enroll`

Enroll the platform PK, KEK and DB certificates into the running firmware.

| Flag | Type | Default | Required | Meaning |
|---|---|---|---|---|
| `--efivars` | string | `/sys/firmware/efi/efivars` | no | efivarfs directory |
| `--keys-dir` | string | `/etc/trusted-platform/secure-boot` | no | Directory holding `PK.crt`, `KEK.crt`, `DB.crt` |
| `--pk-cert` | string | `""` | no | Explicit PK certificate path; overrides `--keys-dir` |
| `--kek-cert` | string | `""` | no | Explicit KEK certificate path; overrides `--keys-dir` |
| `--db-cert` | string | `""` | no | Explicit DB certificate path; overrides `--keys-dir` |
| `--uki` | string | `/boot/efi/EFI/BOOT/BOOTX64.EFI` | no | Path to the signed unified kernel image |
| `--commit` | bool | `false` | no | **Actually write the variables.** Default is dry-run |

Four gates run on **both** the dry run and the commit:

1. efivarfs must be readable — else `ErrEfivarsUnavailable`.
2. The firmware must be in Setup Mode — else `ErrNotSetupMode`.
3. All three certificates must load and parse as PEM — else
   `ErrCertificateLoad{Role, Path, Cause}` or `ErrNotPEMCertificate{Path}`.
4. The signed UKI must exist (`ErrUKINotFound{Path}`), must Authenticode-verify,
   and its embedded certificate must equal the DB certificate — else
   `ErrUKIVerify`.

A dry run that passes is a commit that will work, minus the writes. On commit
the firmware state is read back and reported as `PostSetupMode`,
`PostSecureBoot`, `PostPKPresent`.

```bash
# Rehearse: every guard runs, nothing is written
platformctl secure-boot enroll

# Commit, using the default key directory
platformctl secure-boot enroll --commit

# Commit with explicit certificate paths
platformctl secure-boot enroll --commit \
    --pk-cert <install-dir>/keys/PK.crt \
    --kek-cert <install-dir>/keys/KEK.crt \
    --db-cert <install-dir>/keys/DB.crt

# Rehearse against a fixture directory instead of live firmware
platformctl secure-boot enroll --efivars ./testdata/efivars --uki ./out/BOOTX64.EFI
```

### 2.3 `secure-boot enforce`

Transition the firmware into enforced Secure Boot, but only when it is provably
safe. Same flags as `enroll` (they share `addEnrollFlags`).

Behaviour:

- If Secure Boot is already enforced (`SecureBoot` set and not Setup Mode), the
  command reports success and writes nothing — `AlreadyEnforced: true`.
- Otherwise it runs the full `enroll` pipeline.
- After a **committed** enrollment the firmware state is read back and a
  Platform Key must be present; if it is not, the command fails with
  `ErrEnforceIncomplete{Reason}`.

Enforcement becomes active on the next boot.

```bash
platformctl secure-boot enforce
platformctl secure-boot enforce --commit
```

### 2.4 What `secure-boot` does not cover

| Capability | Reach it with |
|---|---|
| Generate PK/KEK/DB | The installer (`secure-boot:` config), or `platformctl iso create`, which stages keys onto the ISO |
| Enroll into an OVMF `OVMF_VARS.fd` file | The installer / ISO / VM paths; there is no CLI verb for the NVRAM-file enroller |
| Delete or roll back an enrolled PK | **Firmware setup menu only** (physical or BMC access). Deliberately not a CLI verb |
| Read or write an arbitrary EFI variable | Go API only (`pkg/uefi/firmware`) |
| Set or read `TRUSTED_PLATFORM` | Go API only |

---

## 3. `platformctl authenticode`

Sign and verify PE/COFF executables (EFI binaries, Windows executables) with
Authenticode/PKCS#7. Native Go — no `sbsign`/`sbverify` required.

### 3.1 `authenticode sign`

| Flag | Type | Default | Required | Meaning |
|---|---|---|---|---|
| `--key` | string | `""` | **yes** | Path to the signing private key (PEM; PKCS#1 or PKCS#8) |
| `--cert` | string | `""` | **yes** | Path to the signing certificate (PEM) |
| `--input` | string | `""` | **yes** | Path to the input PE/COFF file |
| `--output` | string | `""` | **yes** | Path to write the signed file |

The output file is created fresh and chmodded `0755`; it is removed if signing
fails. Table output prints a success line; `-o json` / `-o yaml` print
`{input, output, success, message}`.

```bash
platformctl authenticode sign \
    --key <install-dir>/secure-boot/DB.key \
    --cert <install-dir>/secure-boot/DB.crt \
    --input ./out/BOOTX64.EFI.unsigned \
    --output ./out/BOOTX64.EFI
```

**This verb takes a file key.** It is the offline/development path. The
production signing paths (`install uki-rebuild`, the installer) reach a
KMS-resident key instead and never write a private key to disk.

### 3.2 `authenticode verify`

| Flag | Type | Default | Required | Meaning |
|---|---|---|---|---|
| `--cert` | string | `""` | no | Certificate (PEM or DER) the file must be signed by |
| `--input` | string | `""` | **yes** | Path to the signed PE/COFF file |

```bash
platformctl authenticode verify \
    --cert <install-dir>/secure-boot/DB.crt \
    --input ./out/BOOTX64.EFI
```

Verification needs no key (`authenticode.NewVerifier`): the signature is
checked against the certificate **embedded in it**. Without `--cert` that is
all it proves — the file is intact and self-consistently signed. With `--cert`
the embedded signer must also be exactly that certificate, otherwise the
command fails naming both subjects; this is the same binding `uefi.VerifySignedUKI`
enforces for `secure-boot enroll`. No chain is built and no trust anchor is
consulted.

---

## 4. `platformctl install uki`

Build a Unified Kernel Image. The output is **unsigned**; sign it with
`platformctl authenticode sign`.

| Flag | Short | Type | Default | Required | Meaning |
|---|---|---|---|---|---|
| `--kernel` | | string | `""` | **yes** | Path to the kernel image (vmlinuz) |
| `--initramfs` | | string | `""` | **yes** | Path to the initramfs |
| `--cmdline` | | string | `""` | **yes** | Kernel command line |
| `--output` | | string | `""` | **yes** | Output path for the UKI |
| `--osrelease` | | string | `""` | no | Path to an os-release file; a read failure warns and is skipped |
| `--stub` | | string | `""` | no | Path to the EFI stub; defaults to `/usr/lib/systemd/boot/efi/linuxx64.efi.stub` |
| `--use-objcopy` | | bool | `false` | no | Use the objcopy-based builder instead of the native Go PE patcher |
| `--verbose` | `-v` | bool | `false` | no | Verbose logging |
| `--debug` | | bool | `false` | no | Debug logging (implies verbose) |

```bash
platformctl install uki \
    --kernel /boot/vmlinuz-6.6.64-0-lts \
    --initramfs /boot/initramfs-6.6.64-0-lts \
    --cmdline "root=/dev/mapper/cryptroot ro quiet" \
    --output /boot/efi/EFI/BOOT/BOOTX64.EFI

# objcopy builder, custom stub and os-release
platformctl install uki \
    --kernel /boot/vmlinuz \
    --initramfs /boot/initramfs \
    --cmdline "root=/dev/mapper/cryptroot ro" \
    --output /boot/efi/EFI/Linux/linux.efi \
    --use-objcopy \
    --stub /usr/lib/systemd/boot/efi/linuxx64.efi.stub \
    --osrelease /etc/os-release
```

The default builder patches PE headers in Go and needs no external tools. The
objcopy builder prefers `llvm-objcopy`, falls back to `objcopy`, then to
`/usr/bin/llvm-objcopy` and `/usr/bin/objcopy`, and warns at construction time
if none is found — the failure then surfaces during the build, not at flag
parsing.

**`--stub` is not architecture-aware.** Both builders read the same default stub
path regardless of the architecture recorded by `SetArchitecture`; a non-x86_64
UKI needs an explicit `--stub`.

---

## 5. `platformctl install uki-rebuild`

Rebuild and re-sign the UKI on an installed, booted node. Normally invoked
automatically by the kernel-update hook
(`/etc/kernel/install.d/90-trusted-platform-uki.install`) when a kernel package
changes. Without it, a kernel upgrade leaves a stale UKI and a node enforcing
Secure Boot will not boot.

| Flag | Short | Type | Default | Required | Meaning |
|---|---|---|---|---|---|
| `--kver` | | string | `""` | no | Kernel version to rebuild for; default is the newest under `/lib/modules` |
| `--config` | | string | `""` | no | Platform config path; falls back to `/etc/platformd/config.yaml` then `/etc/platformd/install.yaml` |
| `--uki` | | string | `""` | no | Live UKI path to replace; default `/boot/efi/EFI/BOOT/BOOTX64.EFI` |
| `--verbose` | `-v` | bool | `false` | no | Verbose logging |
| `--debug` | | bool | `false` | no | Debug logging (implies verbose) |

Note that `--config` here is the **local** platform config path and is a
different flag from the root's `-c/--config`.

Pipeline — never-brick, in this order:

1. Resolve the kernel version.
2. Rebuild the UKI with the persisted kernel cmdline (`/etc/kernel/cmdline`).
3. Resolve the DB signer exactly as the installer does — `file://` locally, or
   remote hash-signing through the platform SDK. **It never generates a new DB
   key.**
4. Sign, verify the result against the DB certificate, and spot-check the
   freshly installed modules for signature trailers (a bounded sample, 16 files).
5. Only then swap atomically over the live UKI, keeping the previous image as
   `BOOTX64.EFI.prev`.

Any failure aborts the swap, leaves the working UKI in place, and exits
non-zero so the kernel hook logs it. If `secure-boot.enabled` is false the
command logs "nothing to re-sign" and exits `0`.

```bash
# As the kernel hook invokes it
platformctl install uki-rebuild --kver 6.6.67-0-lts

# Newest installed kernel
platformctl install uki-rebuild
```

---

## 6. `platformctl iso module-signing-key`

Generate the stable platform kernel module-signing key consumed by the FIPS
kernel build via `CONFIG_MODULE_SIG_KEY`. This is a **separate trust root** from
UEFI Secure Boot.

| Flag | Type | Default | Required | Meaning |
|---|---|---|---|---|
| `--out` | string | `$HOME/.trusted-platform/secure-boot/module-signing-key.pem` | no | Output path for the key+certificate PEM bundle |
| `--key-bits` | int | `4096` | no | RSA modulus size; below 2048 is rejected |
| `--common-name` | string | `Trusted Platform Module Signing Key` | no | Certificate CommonName |
| `--organization` | string | `Trusted Platform` | no | Certificate Organization |
| `--country` | string | `US` | no | Certificate Country |
| `--valid-years` | int | `10` | no | Certificate validity in years |
| `--force` | bool | `false` | no | **Dangerous.** Overwrite an existing key |

```bash
# One-time, at the default operator location
platformctl iso module-signing-key

# At an explicit path on a build server
platformctl iso module-signing-key --out /secure/keys/module-signing-key.pem
```

The command prints the path, the certificate subject, the not-after date and
the SHA-256 fingerprint of the certificate.

**Back this key up.** Regenerating it orphans every module signed with the
previous key on already-built kernels, which is why an existing key is never
overwritten without `--force` (`ErrModuleKeyExists`). Keep it outside the
repository and outside any Docker build context; the builder mounts it
read-only. The bundle is written `0600`, its parent directory `0700`.

**This verb ignores `-o/--output` format.** It writes coloured lines directly to
stdout rather than going through the `platformctl` printer, so `-o json`
produces the same human text. Treat its output as human-only.

---

## 7. Verbs that do not exist

Listed because the legacy documents in this folder show them and an agent will
otherwise go looking.

| Legacy verb | Status |
|---|---|
| `platformctl firmware sign\|flash\|attest\|test` | Does not exist — PLANNED |
| `platformctl firmware android build-grapheneos\|flash-grapheneos` | Does not exist — PLANNED |
| `platformctl firmware ota configure`, `platformctl ota update\|status\|rollback` | Does not exist — PLANNED |
| `platformctl firmware rpi test-qemu` | Does not exist — PLANNED |
| `platformctl vtpm install-swtpm\|create-bundle\|deploy-bundle` | Does not exist; the real vTPM verbs are in [`docs/vtpm/cli.md`](../vtpm/cli.md) |
| A CLI verb that signs an out-of-tree kernel module | Does not exist. `pkg/modulesign` is a library; its only callers today are the integration tests |

---

## 8. Exit codes and output

All verbs follow the `platformctl` convention: `0` on success, non-zero on
failure, with the structured error rendered in the selected `--output` format.
`--output json` is the form to parse; the `table` renderer is for humans and its
columns are not a stable interface. The exception is
`iso module-signing-key` (§6), which does not honour `--output` at all.

---

## 9. Parity gap

`conventions/feature-docs.md` §4 requires every verb here to have a matching
`CommandDefinition` in the integration parity suite. **This repository defines no
`CommandDefinition` type** (grepped repo-wide, 2026-08-18), so the requirement is
unmet repo-wide, not only for this feature. It is raised as an owner question
rather than quietly marked satisfied.
