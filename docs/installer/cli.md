# Installer — CLI

> **Status: NORMATIVE** · Scope: `platformctl install`, `platformctl iso`, `platformctl wipe`, `platform-initrd` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> Every verb and flag below was read out of `pkg/cli/commands/install/`,
> `pkg/cli/commands/iso/`, `pkg/cli/commands/wipe.go` and
> `pkg/boot/commands/` on 2026-08-18.

---

## 1. Command groups

```
platformctl install    System installation operations
platformctl iso        ISO image management operations
platformctl wipe       Securely wipe a LUKS container or device
platform-initrd        Initramfs boot operations (NOT user-facing)
```

`platformctl firstboot` and `platformctl provision` are adjacent and documented
in [`docs/provisioning/cli.md`](../provisioning/cli.md).

### Global flags

`platformctl` persistent flags (`pkg/cli/commands/root.go`). Precedence is
**flag > environment > config file > built-in default**.

| Flag | Short | Default | Environment | Meaning |
|---|---|---|---|---|
| `--config` | `-c` | platform default config path | `PLATFORMCTL_CONFIG` | Config file |
| `--context` | | current-context | `PLATFORMCTL_CONTEXT` | Named context |
| `--transport` | | from context | `PLATFORMCTL_TRANSPORT` | `unix`, `grpc`, `rest`, `quic`, `mcp`, `embedded` |
| `--server` | | from context | `PLATFORMCTL_SERVER` | Server address |
| `--server-name` | | | `PLATFORMCTL_SERVER_NAME` | TLS SNI / verification hostname |
| `--output` | `-o` | `table` | `PLATFORMCTL_OUTPUT` | `table`, `json`, `yaml` |
| `--verbose` | `-v` | `false` | | Verbose output |
| `--no-color` | | `false` | `NO_COLOR` | Disable coloured output |

**All three `install` verbs rebind `-v` to their own `--verbose`,** and
`install`, `iso` and `wipe` each define a local `--config` or `--debug` that
shadows nothing at the root but reads differently. `wipe` binds `-V` (capital)
to `--verbose` and `-p` to `--path`. **Use long forms in scripts.**

### Which verbs need a running daemon

| Verb | Needs `platformd`? |
|---|---|
| `install system`, `install uki`, `install uki-rebuild` | **No.** They run entirely locally — on install media, or on the node itself. |
| `wipe` | **No.** |
| `iso create`, `iso test *`, `iso module-signing-key` | **No.** They run locally. |
| `iso download`, `iso extract`, `iso customize`, `iso build`, `iso profile *` | **No.** They run locally through `pkg/iso` and `pkg/installer`. See §4. |
| `platform-initrd boot`, `platform-initrd recovery` | **No.** They run before userspace exists. |

---

## 2. `platformctl install`

```
platformctl install system        Install complete operating system
platformctl install uki           Build a Unified Kernel Image
platformctl install uki-rebuild   Rebuild and re-sign the UKI after a kernel update
```

### 2.1 `platformctl install system`

Runs the whole of Phase A ([architecture.md](architecture.md) §5). **Only ever
run this from live install media.** It repartitions the target disk.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--config` | string | `""` → `/etc/platformd/install.yaml` | Installer config file |
| `--os` | string | `alpine` | `alpine`, `debian`, `fedora`, `ubuntu` |
| `--os-version` | string | `""` | OS version; empty = latest stable |
| `--disk` | string | `""` | Target disk device, e.g. `/dev/sda` |
| `--efi-size` | int | `538` | EFI partition size in MB |
| `--partition-table` | string | `gpt` | `gpt` or `mbr` |
| `--filesystem` | string | `lvm` | `lvm` or `ext4` |
| `--lvm-vg` | string | `vg0` | LVM volume group name |
| `--lvm-lv` | string | `root` | LVM logical volume name |
| `--password` | string | `""` | LUKS encryption passphrase |
| `--root-password` | string | `""` | Root user password |
| `--hostname` | string | `trusted-platform` | System hostname |
| `--mirror` | string | `""` | Alpine mirror URL |
| `--automated` | bool | `false` | No interactive prompts |
| `--fips` | bool | `false` | FIPS mode (forces PBKDF2 over Argon2id) |
| `--lockdown` | bool | **`true`** | Kernel lockdown |
| `--lockdown-mode` | string | `confidentiality` | `integrity` or `confidentiality` |
| `--tpm-auto-upgrade-seal` | bool | **`true`** | Written to `/etc/alpine-tpm.conf` (`pkg/installer/alpine.go:601`) and read by nothing; no automatic reseal exists ([engineering.md §5](engineering.md#5-unlock-strategy-table--as-the-code-registers-it)) |
| `--platformd-binary` | string | `""` | Path to the platformd binary to install |
| `--verbose` / `-v` | bool | `false` | Verbose logging |
| `--debug` | bool | `false` | Debug logging (implies verbose) |

Install-time **remote Secure Boot DB signing** (`resign-mode: remote`). Set
`--provision-server-url` to wire the remote signer; leave it empty for airgapped
or local installs and the installer falls through to on-node key generation.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--provision-server-url` | string | `""` | Control-plane URL, e.g. `https://platform.example.com:8443` |
| `--eab-kid` | string | `""` | EAB key ID |
| `--eab-hmac` | string | `""` | EAB HMAC — **a secret** |
| `--ek-serial` | string | `""` | TPM EK serial presented for auth |
| `--mac` | string | `""` | Booting NIC MAC presented for auth |
| `--ek-cert` | string | `""` | Path to the EK certificate (DER or PEM) |
| `--ca-bundle` | string | `""` | PEM bundle used to verify the control plane's TLS certificate |

```bash
# From a config file — the normal path
platformctl install system --config /etc/platformd/install.yaml

# Flags only, fully unattended
platformctl install system --os alpine --disk /dev/sda \
    --password "$LUKS_PASSPHRASE" --hostname node-01 --automated

# Remote Secure Boot DB signing: only the digest leaves the node
platformctl install system --config /etc/platformd/install.yaml \
    --provision-server-url https://platform.example.com:8443 \
    --eab-kid "$EAB_KID" --eab-hmac "$EAB_HMAC" \
    --ek-serial "$EK_SERIAL" --mac aa:bb:cc:dd:ee:ff \
    --ca-bundle /media/cdrom/ca-bundle.pem
```

**`--automated` requires a LUKS password.** With `--automated` and no
`disk.encryption.password` / `passphrase` in the config and no `--password`, the
command fails with `ErrPasswordRequired` before touching the disk.

**Secrets on the command line are visible.** `--password`, `--root-password` and
`--eab-hmac` land in the process table and in shell history. Put them in the
config file (mode 0600) or an environment variable expanded by the shell, and
prefer a config file for anything unattended.

### 2.2 `platformctl install uki`

Build a Unified Kernel Image.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--kernel` | string | `""` | Path to the kernel image (vmlinuz) |
| `--initramfs` | string | `""` | Path to the initramfs |
| `--cmdline` | string | `""` | Kernel command line |
| `--output` | string | `""` | Output path for the UKI |
| `--osrelease` | string | `""` | Path to an os-release file |
| `--stub` | string | `""` | EFI stub; defaults to `/usr/lib/systemd/boot/efi/linuxx64.efi.stub` |
| `--use-objcopy` | bool | `false` | Use the objcopy-based builder |
| `--verbose` / `-v` | bool | `false` | Verbose logging |
| `--debug` | bool | `false` | Debug logging |

```bash
platformctl install uki \
    --kernel /boot/vmlinuz-lts --initramfs /boot/initramfs-lts \
    --cmdline "root=/dev/mapper/vg0-root ro" \
    --output /boot/efi/EFI/BOOT/BOOTX64.EFI
```

### 2.3 `platformctl install uki-rebuild`

Rebuild and re-sign the UKI after a kernel update, so the node stays bootable
under enforced Secure Boot with `CONFIG_MODULE_SIG_FORCE`.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--kver` | string | `""` | Kernel version; empty = newest under `/lib/modules` |
| `--config` | string | `""` | Platform config; defaults to `/etc/platformd/config.yaml`, then `/etc/platformd/install.yaml` |
| `--uki` | string | `""` | Live UKI to replace; defaults to `/boot/efi/EFI/BOOT/BOOTX64.EFI` |
| `--verbose` / `-v` | bool | `false` | Verbose logging |
| `--debug` | bool | `false` | Debug logging |

```bash
platformctl install uki-rebuild --kver 6.12.8-lts
```

**A rebuilt UKI changes what the machine measures.** New PCR values invalidate
anything sealed to them — the LUKS key, vTPM-sealed secrets, golden-PCR
attestation policy. Plan the reseal in the same maintenance window: nothing
re-seals automatically, so the next boot ends at the LUKS passphrase prompt
([architecture.md](architecture.md) trust boundary 4). The install
also writes a kernel-update hook so an ordinary `apk upgrade linux-lts` triggers
this automatically; `uki-rebuild` is the manual path when that hook failed to
install.

---

## 3. `platformctl iso`

```
platformctl iso create               All-in-one ISO creation
platformctl iso download             Download the Alpine base ISO
platformctl iso extract              Extract ISO contents
platformctl iso customize            Apply platform components and overlays
platformctl iso build                Build the final bootable ISO
platformctl iso profile              Manage installation profiles
platformctl iso test                 Test ISO images in QEMU
platformctl iso module-signing-key   Generate the kernel module-signing key
```

### 3.1 `platformctl iso create`

The only ISO-production verb that is implemented end to end. It runs download →
extract → generate Secure Boot keys → customise → build in sequence. The running
`platformd` binary copies **itself** into the ISO, so no binary path is needed.

Alpine:

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--alpine-version` | string | `3.22.2` | Alpine Linux version |
| `--mirror` | string | `http://mirror.cs.odu.edu/alpine` | **Build-time** pre-fetch source |
| `--apk-mirror` | string | `""` | **Install-time** APK repository base, baked into the cmdline as `platform_apk_mirror=`; empty falls back to the public Alpine mirror |
| `--arch` | string | `x86_64` | `x86_64` or `aarch64` |

`--diskless` netboot media is supported only for media sets that include a diskless root, currently the arm64 QEMU `virt` and Raspberry Pi sets; an x86_64-only set is rejected instead of silently falling back to a disk-backed install.

Platform:

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--platform-version` | string | `""` | From the `VERSION` file when empty |
| `--platform-config` | string | `""` | `platformd.yaml`; auto-detected from `--platform-type` |
| `--platform-type` | string | `server` | `server` or `client` |
| `--overrides` | string | `""` | Config deep-merged onto `--platform-config` |

Security:

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--secure-boot` | bool | **`true`** | Secure Boot support |
| `--tpm-unseal` | bool | **`true`** | TPM auto-unseal |
| `--luks` | bool | **`true`** | LUKS encryption |
| `--fips` | bool | `false` | FIPS mode |
| `--fido2` | bool | `false` | FIDO2 support (installs `libfido2` and friends) |

Build:

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--overlay` | string | `""` | Overlay directory to include |
| `--output` | string | `""` | Output filename; auto-generated when empty |
| `--keys-dir` | string | `""` | Secure Boot keys directory |
| `--generate-keys` | bool | **`true`** | Generate Secure Boot keys if absent |
| `--key-backend` | string | `file` | `file`, `software`, `pkcs11`, `tpm2`, `awskms`, `azurekv`, `gcpkms`, `vault` |
| `--force` | bool | `false` | Rebuild even if files exist |
| `--webui` | string | `""` | `public_html` directory or tarball |
| `--config` | string | `""` | ISO build configuration file |
| `--work-dir` | string | `work` | Working directory |
| `--debug` / `--verbose` | bool | `false` | Output verbosity |
| `--pre-fetch` | bool | **`true`** | Pre-download all packages into the ISO for offline install. **Unavailable in a `fips`-tagged build** — see the note below |
| `--platform-apk-dir` | string | `""` | strongSwan builder output (`make strongswan-build`; one `x86_64/` and `aarch64/` directory each) whose apks go into the offline repository and are installed for the overlay's IPsec transport. Requires `--pre-fetch` and an embedded platform config; empty = the media carry none of them. See below |

Dynamic configuration and trust bootstrap:

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--config-server` | string | `""` | Server URL for dynamic config fetch at boot |
| `--bootstrap-strategy` | string | `auto` | `dane`, `noise`, `spki`, `auto` |
| `--bootstrap-dns` | string | `""` | DNS server for DANE TLSA lookups |
| `--bootstrap-noise-key` | string | `""` | Noise server public key, hex |
| `--bootstrap-spki-pin` | string | `""` | SPKI SHA-256 pin |
| `--ca-bundle` | string | `""` | CA bundle PEM embedded into the ISO trust store |
| `--ca-key-algorithm` | string | `""` | Filter the bundle: `rsa`, `ecdsa`, `ed25519`; empty = all |

```bash
platformctl iso create
platformctl iso create --fips --secure-boot --output trusted-fips.iso
platformctl iso create --platform-config base.yaml --overrides node-01.yaml
platformctl iso create --pre-fetch=false        # smaller ISO, needs a mirror at install time
```

### Pre-fetch is unavailable in a FIPS build

A binary built with the `fips` tag **cannot** pre-fetch an offline APK
repository. Attempting it fails closed with `ErrFIPSAPKChecksumUnavailable`
rather than producing an ISO that silently fails at install time.

The reason is the format, not a policy choice we could relax: Alpine's
`APKINDEX` defines a package checksum as `Q1` + base64 of the **SHA-1** digest,
and `apk` rejects an index whose checksums are anything else. A FIPS build will
not compute SHA-1, so the index cannot be produced at all. There is no approved
substitute, unlike the other FIPS gates in this platform.

Two ways to proceed:

- build the ISO with `--pre-fetch=false` and provide a mirror reachable at
  install time; or
- assemble the image with a **non-FIPS** build of `platformctl`. Image assembly
  is a build-host operation — it does not determine whether the *installed
  system* runs in FIPS mode, which is selected by the `ProfileFIPS` install
  profile and the FIPS kernel.

```text
```

**`--pre-fetch` defaults to `true` and should stay that way** for BMC virtual
media, air-gapped and PXE installs. `--pre-fetch=false` is only safe when the
install network is known to permit outbound HTTPS to the Alpine CDN.

**`--platform-apk-dir`** adds `trusted-platform-strongswan`,
`trusted-platform-strongswan-openrc`, `trusted-platform-p11-host`,
`trusted-platform-p11-host-openrc` (from the directory, signed by the builder's
key) and `p11-kit-server` (from the Alpine mirror) to the offline repository.
The build fails with `ErrPlatformAPKMissing` when the directory lacks one of
them or its index does not list it, and with `ErrPlatformAPKInvalid` when an
apk is not the one its index entry describes (size, gzip CRCs, or the `C:`
checksum of its control segment) or the media's APKINDEX cannot list it. The
apks are copied on every build, replacing the file of the same name a reused
work directory holds from an earlier build (a rebuild keeps its version and
pkgrel), and the copy is checked against the index entry again. The
flag is refused with `ErrPlatformAPKDirUnusable` together with
`--pre-fetch=false` (the packages are in no Alpine mirror) and with
`--config-server` when no `--platform-config` is embedded (the node then
installs what the server's configuration names, not these packages). A
`--config` file's value is used unless the flag is given.
`platformctl diskimage create` takes the same flag, with the same
`--pre-fetch` rule; the factory image and the netboot sets carry the same
packages. The
services they install are described in
[`docs/sdn/engineering.md`](../sdn/engineering.md) §9.6.

**`--overrides` requires `--platform-config`** — it is a merge onto a template,
so without a template it fails with `ErrOverridesWithoutTemplate`.

There is **no `--debug-sink` flag**. The forensic sink is set through the ISO
build config (`platform.debug_sink`); when it is unset, the install script
derives the sink from the DHCP server. See [engineering.md](engineering.md) §10.

### 3.2 `platformctl iso test`

Runs the built image under QEMU with a software TPM and OVMF. Six verbs:
`install`, `firstboot`, `boot`, `all`, `pxe`, `client-server`.

Flags shared by `install`, `firstboot`, `boot` and `all`:

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--disk` | string | `alpine-platform-installed.qcow2` | qcow2 disk image |
| `--disk-size` | string | `10G` | Disk size |
| `--disk-cache` | string | `writethrough` | QEMU disk cache mode (`writethrough`, `writeback`, `none`, `unsafe`, `directsync`). Nested-virt hosts should use `unsafe` or `writeback` — see docs/installer/qemu-testing.md |
| `--memory` | int | `8192` | RAM in MB |
| `--cpus` | int | host CPU count | CPU cores |
| `--work-dir` | string | `work` | VM artefacts |
| `--secure-boot` | bool | **`true`** | UEFI Secure Boot |
| `--debug` | bool | `false` | Debug output |
| `--fido2` | bool | `false` | FIDO2/CanoKey emulation |
| `--fido2-mode` | string | `canokey` | `canokey`, `u2f-emulated`, `u2f-passthru` |
| `--canokey-file` | string | `""` | CanoKey state file |
| `--canokey-pcap` | string | `""` | USB packet capture |
| `--u2f-device` | string | `""` | Host hidraw device for U2F passthrough |
| `--qemu-binary` | string | `""` | Custom QEMU binary |
| `--network` | string | `""` | `user`, `bridge`, `none`; empty auto-detects |
| `--timeout` | duration | `0` (none) | Bound on each VM run (e.g. `45m`); see below |

`--work-dir` holds the artefacts (disk, NVRAM, TPM state, logs) and may be as
deep as you like. The VM's runtime unix sockets (QMP, console) do **not** live
there: a unix socket path is capped at 107 bytes, which a deep work dir
exceeds. Each run creates a short `tp-vm-*` directory under `$TMPDIR` for its
sockets and removes it when the VM stops. The software TPM already relocates
its own socket the same way. A socket path that is still over the limit (a long
`$TMPDIR`, or a path set explicitly) fails before QEMU starts with
`ErrSocketPathTooLong`, naming the path and the limit.

`install` and `all` additionally take `--iso` (default: resolved as
`trusted-alpine-<VERSION>-x86_64.iso`, then the `-fips` variant).

```bash
platformctl iso test install --iso trusted-alpine-1.0.0-x86_64.iso
platformctl iso test firstboot --disk alpine-platform-installed.qcow2
platformctl iso test all
```

**`iso test install` succeeds when the VM exits after a reboot.** The autoinstall
script reboots, QEMU exits non-zero, and the harness treats that as success if
the disk exists and exceeds 100 MB.

**A VM test waits until the guest powers off.** Interactively you end it with
Ctrl+C. A headless run (CI) passes `--timeout`: when it expires the verb kills
QEMU, stops the software TPM and fails with `ErrVMTimeout`, naming the
timeout. A run cut off this way never counts as an install, whatever the disk
size. A guest with no autoinstaller (a stock Alpine ISO) sits at its login
prompt and never powers off, so it always ends at the timeout.

**`iso test firstboot` and `iso test boot` are the same code path**
(`runTestBootCommon`). The distinction is the state of the disk you point them
at, not the verb.

`iso test pxe` — **requires root** for bridge/TAP setup:

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--iso` | string | `""` | ISO; kernel/initrd extracted automatically |
| `--kernel` / `--initrd` | string | `""` | Override ISO extraction |
| `--args` | string | `""` | Kernel boot arguments |
| `--memory` | int | `4096` | RAM in MB |
| `--cpus` | int | host CPU count | CPU cores |
| `--work-dir` | string | `work-pxe` | VM and PXE server artefacts |
| `--disk` / `--disk-size` | string | `<work-dir>/pxe-client.qcow2` / `10G` | The client's disk, created when missing |
| `--secure-boot` | bool | `false` | UEFI Secure Boot (x86_64) |
| `--architecture` | string | `x86_64` | `x86_64` or `aarch64` (QEMU `virt` from the platform's U-Boot) |
| `--uboot` / `--ipxe` / `--keys-dir` | string | `make uboot-build` output / `make ipxe-build` output / `~/.trusted-platform/secure-boot` | aarch64: the firmware, the platform-built arm64 iPXE, and the db key that signs what U-Boot loads |
| `--serial-log` / `--expect` | string | `""` | Unattended run: capture the console, stop at a milestone |
| `--debug` | bool | `false` | Debug output |

```bash
sudo platformctl iso test pxe --iso trusted-alpine-1.0.0-x86_64.iso
```

`iso test client-server` — two VMs on an isolated network, exercising ACME
`enroll-01` TPM enrolment end to end. Selected flags: `--iso`, `--server-disk`
(`server-installed.qcow2`), `--client-disk` (`client-installed.qcow2`),
`--server-work-dir` (`work-server`), `--client-work-dir` (`work-client`),
`--disk-size` (`10G`), `--memory` (`8192`), `--cpus` (`min(host, 8)`),
`--secure-boot` (**`false`** — disabled by default because of KVM SMM emulation
bugs), `--skip-install`, `--server-only`, `--client-only`, `--user-network`
(no root required, `--server-only` only), `--server-host-port` (`8443`),
`--dns-host-port` (`8053`), `--use-ovs`, `--server-config`, `--client-config`,
`--server-profile`, `--client-profile`, `--dynamic-network`, `--enable-dhcp`,
`--server-timeout` (`600`), `--bootstrap-strategy` (`dane`),
`--bootstrap-noise-key`, `--bootstrap-spki-pin`, `--platformd-binary`,
`--webui`, `--console` (**`true`**), `--fido2`, `--fido2-mode`, `--debug`.

```bash
sudo platformctl iso test client-server --iso trusted-alpine-1.0.0-x86_64.iso
platformctl iso test client-server --server-only --user-network   # no root
```

### 3.3 `platformctl iso module-signing-key`

Generates the stable kernel module-signing key the FIPS kernel build embeds via
`CONFIG_MODULE_SIG_KEY`. Written as one PEM bundle: PKCS#8 private key followed
by a self-signed certificate.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--out` | string | `$HOME/.trusted-platform/secure-boot/module-signing-key.pem` | Output path |
| `--key-bits` | int | `secureboot.DefaultModuleKeyBits` | RSA key size, minimum 2048 |
| `--common-name` | string | `secureboot.DefaultModuleKeyCN` | Certificate CN |
| `--organization` | string | `Trusted Platform` | Certificate O |
| `--country` | string | `US` | Certificate C |
| `--valid-years` | int | `secureboot.DefaultModuleKeyValidYears` | Validity |
| `--force` | bool | `false` | Overwrite an existing key |

```bash
platformctl iso module-signing-key
platformctl iso module-signing-key --out /secure/keys/module-signing-key.pem
```

**`--force` orphans every module already signed with the previous key** on
kernels that were already built. The key lives outside the repository and
outside any build context; back it up.

### 3.4 The step verbs

`download`, `extract`, `customize` and `build` are the four steps `iso create`
runs, exposed one at a time; the four `profile` verbs read and render the
built-in installation profiles. All eight run locally — no daemon, no
network beyond the Alpine mirror `download` fetches from. Their flags and
output are in §4.

---

## 4. Step and profile verbs

Each verb prints one result object in the selected `--output` format and exits
non-zero on failure (§7). Stdout carries only that object: progress lines and
the output of the tools a verb runs (`7z`, `bsdtar`, `xorriso`, the build
container) go to stderr.

**`--output` is shadowed on three verbs.** `iso create --output` and
`iso build --output` (the ISO path) and `iso profile generate --output` / `-o`
(the config file) replace the global `--output` / `-o`, so those verbs always
print in the default format — `table`, which renders a result object as YAML.
Parse their output as YAML. `iso create` prints `success`, `output_iso`,
`sha256`, `size_bytes` and `message`.

**`iso download`** — `--url` (`""`; must name an ISO file and overrides
`--version`/`--mirror`/`--arch`), `--version` (`3.22.2`), `--mirror`
(`http://mirror.cs.odu.edu/alpine`), `--arch` (`x86_64` or `aarch64`),
`--force` (`false`; removes the existing ISO first), `--verify` (**`true`**),
`--resume` (**`true`**), `--work-dir` (`work`; the ISO lands here), `--debug`.
Prints `success`, `iso_path`, `sha256`, `size_bytes`, `verified`, `message`.

**`iso extract`** — `--iso` (**required**), `--output-dir` (`""` →
`<work-dir>/iso`), `--force` (`false`; without it a non-empty output directory
is refused), `--work-dir` (`work`), `--debug`. Prints `success`, `output_dir`,
`file_count`, `message`.

**`iso customize`** — `--iso-dir` (**required**), `--overlay`, `--keys-dir`,
`--platformd-binary` (`""` → `platformd` beside `platformctl`),
`--platform-config` (platform config baked into the ISO; **required** unless
the `--config` file names a config server), `--config` (ISO build
configuration file), `--work-dir` (`work`), `--debug`. `platform-initrd` and
`gatewayd` are taken from beside `platformd`; `gatewayd` is required when the
platform config enables the gateway role, as
`configs/platform/templates/single-node/default.yaml` does. Prints `success`,
`iso_dir`, `message`.

**`iso build`** — `--iso-dir` (**required**), `--output` (**required**),
`--label` (`TRUSTED_PLATFORM`; longer than 32 characters is refused),
`--checksum` (**`true`**; writes `<output>.sha256`), `--debug`. Prints
`success`, `output_iso`, `sha256`, `size_bytes`, `checksum_file` (omitted
without `--checksum`), `message`.

**`iso profile`** — verbs `list` (alias `ls`), `show <profile-name>`,
`validate <config-file>`, `generate`. The four built-in profile names are
`dev`, `production`, `production-hs`, `fips` ([engineering.md](engineering.md)
§2); every Secure Boot profile carries the canonical platform PK/KEK/DB key
URIs (`kms://platform/secureboot/{pk,kek,db}`,
[docs/firmware/secure-boot.md](../firmware/secure-boot.md)), so a generated
config validates as-is.

- `list` prints `success`, `profiles` (each `name`, `description`,
  `secure_boot`, `tpm_unseal`, `luks`, `fips`, `lockdown`), `message`.
- `show` prints `success`, `profile` (the same summary), `yaml` (the rendered
  install config), `message`. An unknown name fails.
- `validate` loads the file as an install config and prints `success`,
  `valid`, `errors`, `message`. An invalid config prints `valid: false` with
  its errors **and** exits non-zero; a missing file fails without a result.
- `generate` takes `--profile` / `-p` (**required**), `--output` / `-o`
  (`""`: the YAML is printed only) and `--device` (overrides the disk device).
  It prints `success`, `output_file`, `yaml`, `message`.

---

## 5. `platformctl wipe`

Securely wipe a LUKS container or device. This is what the dracut hook calls
after a successful firstboot to destroy `installer.luks`.

| Flag | Short | Type | Default | Meaning |
|---|---|---|---|---|
| `--path` | `-p` | string | — (**required**) | Device or container file |
| `--passes` | | int | `1` | Overwrite passes |
| `--random` | | bool | `false` | Random data instead of zeros |
| `--trim` | | bool | **`true`** | Issue TRIM/DISCARD after wiping |
| `--verbose` | `-V` | bool | `false` | Verbose output |

```bash
platformctl wipe --path /boot/efi/tpm2/installer.luks --trim
platformctl wipe --path /dev/sda2 --passes 3 --random --trim
```

**`--trim` is the part that matters on an SSD.** Overwriting a file does not
reach the spare blocks the controller has already remapped; the `BLKDISCARD`
ioctl is what tells the firmware to release them. Leave it on.

---

## 6. `platform-initrd`

**Not user-facing.** Called by dracut hooks during early boot. Everything after
`switch_root` is `platformctl`.

```
platform-initrd boot        Unlock the encrypted root filesystem
platform-initrd recovery    Recovery mode with fallback unlock
platform-initrd version     Print version information
```

### 6.1 `platform-initrd boot`

| Flag | Short | Type | Default | Meaning |
|---|---|---|---|---|
| `--device` | `-d` | string | — (**required** without `--diskless`) | LUKS device path |
| `--name` | `-n` | string | `cryptroot` | LUKS mapping name |
| `--diskless` | | bool | `false` | Mount the diskless dm-verity root the signed command line describes instead of unlocking `--device`; the two are mutually exclusive. The dracut hook passes it only when the signed command line carries `platform_boot_model=diskless` |
| `--root-mount` | | string | `/sysroot` | Where `--diskless` mounts the overlay root |
| `--diskless-work-dir` | | string | `/run/platform/diskless-root` | Tmpfs directory for the fetched image and hash tree |
| `--timeout` | | int | `30` | Unlock timeout in seconds |
| `--pcrs` | | []uint | unset | PCR selection; falls back to the `pcr-banks` file, then `config.yaml` |
| `--fallback` | | bool | **`true`** | Enable fallback unlock methods |
| `--emergency` | | bool | `false` | Drop to an emergency shell on failure |
| `--tpm-path` | | string | `/dev/tpmrm0` | TPM device |
| `--efi-path` | | string | `/boot/efi` | EFI mount point |
| `--xkms-dir` | | string | `/etc/trusted-platform/xkms` | XKMS storage directory |
| `--verbose` | `-v` | bool | `false` | Verbose logging |
| `--debug` | | bool | `false` | Debug logging |
| `--fips` | | bool | `false` | Recorded but not read; the kernel's FIPS mode selects the keyslot KDF ([FIPS mode](../fips/cli.md)) |

```bash
platform-initrd boot --device /dev/sda2
platform-initrd boot --device /dev/sda2 --timeout 60 --pcrs 0,7,9
platform-initrd boot --diskless --root-mount /sysroot
```

### 6.2 `platform-initrd recovery`

| Flag | Short | Type | Default | Meaning |
|---|---|---|---|---|
| `--device` | `-d` | string | — (**required**) | LUKS device path |
| `--name` | `-n` | string | `cryptroot` | LUKS mapping name |
| `--reseal-pcrs` | | bool | `true` | Recorded but not read; recovery does not reseal (below) |
| `--fido2` | | bool | **`true`** | Enable FIDO2 authenticator unlock |
| `--interactive` | | bool | `false` | Interactive recovery menu |
| `--tpm-path` | | string | `/dev/tpmrm0` | TPM device |
| `--efi-path` | | string | `/boot/efi` | EFI mount point |
| `--xkms-dir` | | string | `/etc/trusted-platform/xkms` | XKMS storage directory |
| `--verbose` | `-v` | bool | `false` | Verbose logging |
| `--debug` | | bool | `false` | Debug logging |
| `--fips` | | bool | `false` | Recorded but not read; the kernel's FIPS mode selects the keyslot KDF ([FIPS mode](../fips/cli.md)) |

```bash
platform-initrd recovery --device /dev/sda2
platform-initrd recovery --device /dev/sda2 --interactive
```

**Recovery hard-codes its PCR selection to `0,1,2,3,7`** and its timeout to 300
seconds with 5 retries (`pkg/boot/commands/recovery.go`). It does **not** honour
a `--pcrs` flag — there isn't one.

**Recovery does not reseal.** The TPM-PCR unlock reads its seal from
`tpm2/seal-platform.pub` / `.priv` on the ESP, which only first boot writes; the
initrd has no writer for them. Option 4 of the `--interactive` menu ("Attempt to
reseal TPM keys") therefore refuses with *"the resealed data cannot be stored"*,
naming the TPM-PCR slot, before it unseals anything. It never reports success.
Unlock, boot, and reseal from the running system.

---

## 7. Exit codes and output

`platformctl` verbs return `0` on success and non-zero on failure, with the
structured error rendered in the selected `--output` format. Parse
`--output json`; the `table` renderer is for humans and its columns are not a
stable interface.

`platform-initrd` returns `0` or `1` — `main` calls `os.Exit(1)` on any error
from `commands.Execute()`. There are no finer-grained codes. Diagnose from
`/run/platform-initrd-boot.log` and the serial console, not the exit code.

---

## 8. Parity gap

`conventions/feature-docs.md` §4 requires every verb here to have a matching
`CommandDefinition` in the integration parity suite. **This repository defines
no `CommandDefinition` type** (grepped repo-wide, 2026-08-18), so the
requirement is unmet repo-wide, not only for the installer.
