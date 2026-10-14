# Trusted Platform ISO

> **Status: REFERENCE** · Last verified: 2026-10-13
> Building the installer ISO with `platformctl iso create`; the full flag reference is [cli.md](cli.md) §3.

The Trusted Platform ISO is built using the `platformctl iso` command, which provides a complete CLI for downloading, customizing, and building bootable Alpine Linux ISO images with platform-specific components.


> The Raspberry Pi is not installed from an ISO. Its factory SD-card image
> reuses this pipeline's media staging and the installer, run on the build
> host: see [docs/factory-image/](../factory-image/) and `make image-rpi`.

## Building the ISO

The `platformctl iso create` command performs all build steps in sequence:

1. Download Alpine Linux ISO with SHA256 verification
2. Extract ISO contents for customization
3. Generate Secure Boot keys (if enabled)
4. Customize with platform components (platformd copies itself into the ISO).
   This step has two halves: `Customizer.StageMedia` lays down everything the
   installer reads from the media root (installer/initrd configuration, the
   pre-fetched apk repository for the target architecture, the platform
   binaries, platform configuration and CA bundle, dracut module, Secure Boot
   keys, FIPS artifacts, web UI), and the live-ISO half rewrites Alpine's
   initramfs and GRUB so the ISO boots straight into the autoinstaller. A disk
   image builder reuses `StageMedia` alone and supplies its own boot chain.
5. Build final bootable ISO

The resulting install is an Alpine Linux operating system configured for Secure and Measured Boot using custom keys. The kernel is built with [EFI Stub](https://docs.kernel.org/admin-guide/efi-stub.html) which supports being booted directly from your system's UEFI.

Booting the kernel directly from UEFI bypasses the usual Shim and 2nd stage bootloader such as Grub or systemd-boot. This configuration reduces potential attack vectors during the boot process and quickly boots the operating system.


### Quick Start

```bash
# Create ISO with all defaults (uses VERSION file for version)
platformctl iso create

# Create ISO with custom work directory
platformctl iso create --work-dir /tmp/build

# Create FIPS-enabled ISO
platformctl iso create --fips

# Create ISO without Secure Boot
platformctl iso create --secure-boot=false
```


### Secure Boot on the installer media

**What is signed.** With `--secure-boot` and media signing, the ISO's EFI
bootloader (`efi/boot/bootx64.efi`, and the copy inside the El Torito
`efi.img` that firmware actually loads) is signed with the staged DB key. This
is what lets firmware in enforcing mode boot the installer at all.

**What is not.** The kernel and initrd on the ISO are **not** signed, and there
is no shim in the chain, so nothing verifies them once GRUB is running.
Firmware verifies the loader, not the system. Tracked in
issue #354 — do not read a successful enforcing boot of the
installer as end-to-end verification of the installer's payload.

**Failure is fatal, deliberately.** A media-signing build whose bootloader
cannot be signed fails the build. Emitting the ISO instead would produce media
that firmware silently rejects at boot, which is the failure this signing
exists to remove.

**Firmware that ships enforcing with vendor keys.** If the target's firmware
enforces Secure Boot with keys you do not control, the platform's DB key is not
trusted by it and signing with that key does not help. The supported sequence
is:

1. put the firmware in Setup Mode (or disable Secure Boot) for the install;
2. boot the installer and let it stage the keys and sign the installed UKI;
3. enroll PK/KEK/DB and re-enable enforcement after the install.

Every subsequent boot is then a signed chain verified against keys the platform
owns. This is ordinary UEFI practice rather than a workaround, and it is an
explicit deployment step rather than something the ISO can do for you.

### Command Flags

Selected flags; [cli.md](cli.md) §3.1 lists them all.

| Flag | Default | Description |
|------|---------|-------------|
| `--alpine-version` | 3.22.2 | Alpine Linux version to download |
| `--mirror` | http://mirror.cs.odu.edu/alpine | Alpine Linux mirror URL |
| `--arch` | x86_64 | Target architecture, `x86_64` or `aarch64` (GOARCH aliases accepted). Selects the Alpine ISO and apk repository, the minirootfs, and the ELF machine every bundled binary must have — an `x86_64` `platformd` next to an `aarch64` build fails with `BinaryArchMismatchError`. FIPS builds are x86_64 only (the FIPS kernel and OpenSSL provider are container-built for that architecture). |
| `--platform-type` | server | Platform type: 'server' or 'client' |
| `--platform-config` | single-node/default | Path to platformd.yaml template (baked into ISO). Default: `configs/platform/templates/single-node/default.yaml` |
| `--overrides` | (none) | Path to override YAML (deep-merged onto `--platform-config` template before baking) |
| `--config-server` | (none) | Base URL for dynamic config fetch at install time. Bakes `platform_config=<URL>` into kernel cmdline. See §Config Delivery Modes below |
| `--secure-boot` | true | Enable Secure Boot support. SINGLE SOURCE OF TRUTH for the baked config: the customize step forces `secure-boot.enabled` in the baked platform config to match this flag (adding a media-staged DB signing reference when the config carries none — an existing `db` ref and `resign-mode`, e.g. remote/KMS signing, are preserved untouched), so the ISO can never generate-and-enroll keys while shipping an unsigned UKI, or the reverse. A baked `secure-boot.enforce: true` additionally makes the build fail-closed on enrollment material: the staged media must carry the PK/KEK enrollment certificates the installer will enroll (validated as X.509, named by the baked `pk`/`kek` media cert-uris or the `PK.crt`/`KEK.crt` convention) — the installer warns past their absence at install time, so the build is the only gate against an enforce-requested node without enforcement. The override pass also mirrors `SecureBootConfig.Validate` for enforcing configs — `pk`/`kek` `key-uri` present with a `kms://` or `file://` scheme — so a config the target would deterministically reject fails the build instead; staged enrollment certificates may be PEM or DER (the installer parses both). Staging always REPLACES the ISO's `secure-boot-keys` directory (a stale private key from a previous build can never survive a switch to remote signing; a `--keys-dir` overlapping the staging directory is rejected before anything is removed), a media-signing build validates the staged DB pair as usable signing material — parseable key + certificate with matching public keys (`authenticode.LoadSigningPair`, the same loader the installer uses), not merely present files — and a remote/KMS-signing build never runs local key generation — neither in staging nor in the `iso create` Step-3 orchestration, which classifies the platform config's db reference first (`SecureBootRemoteSigning`): no local private signing key is needed or produced. A media-signing build also **signs the ISO's own EFI bootloader** with the staged DB key, so firmware already enforcing Secure Boot will load the installer instead of refusing it with `Access Denied` — see *Secure Boot on the installer media* below |
| `--tpm-unseal` | true | Enable TPM auto-unseal |
| `--luks` | true | Enable LUKS encryption |
| `--fips` | false | Enable FIPS mode |
| `--fido2` | false | Enable FIDO2 security key support |
| `--keys-dir` | work/secure-boot-keys | Secure Boot keys directory |
| `--generate-keys` | true | Generate Secure Boot keys if they don't exist |
| `--key-backend` | file | Key backend: file, software, pkcs11, tpm2, awskms, azurekv, gcpkms, vault |
| `--output` | auto-generated | Output ISO filename |
| `--webui` | auto-detected | Path to WebUI directory or tarball |
| `--work-dir` | work | Working directory for ISO operations |
| `--force` | false | Force rebuild even if files exist |
| `--debug` | false | Enable debug output |

The output filename defaults to: `trusted-alpine-<version>-<arch>.iso` (or with `-fips` suffix if FIPS is enabled).


## Individual Commands

**These verbs are stubs.** `download`, `extract`, `customize` and `build`
parse their flags and return `ErrDaemonConnectionRequired`
([cli.md](cli.md) §3.4); use `iso create`. Their intended usage:

```bash
# Download Alpine ISO
platformctl iso download --version 3.22.2

# Extract ISO contents
platformctl iso extract --iso work/alpine-standard-3.22.2-x86_64.iso

# Customize ISO (integrates platform binaries and configuration)
platformctl iso customize --iso-dir work/iso \
  --platformd-binary ./platformd-static \
  --keys-dir secure-boot-keys

# Build final bootable ISO
platformctl iso build --iso-dir work/iso --output trusted-platform.iso
```


### Download Command

Downloads Alpine Linux ISO with SHA256 checksum verification and resume support:

```bash
# Download default version
platformctl iso download

# Download specific version
platformctl iso download --version 3.21.0

# Download from specific mirror
platformctl iso download --mirror http://dl-cdn.alpinelinux.org/alpine

# Force re-download
platformctl iso download --force
```


### Build Command

Builds a UEFI-only bootable ISO image using xorriso:

```bash
# Build with default settings
platformctl iso build --iso-dir work/iso --output platform.iso

# Build with custom volume label
platformctl iso build --iso-dir work/iso --output platform.iso --label MY_PLATFORM
```

The ISO boots through UEFI only (the El Torito `boot/grub/efi.img`); there
is no legacy BIOS path. It is a GPT hybrid (`-isohybrid-gpt-basdat`), so the
same file boots from USB.


## Installation Profiles

The `platformctl iso profile` verbs are stubs too ([cli.md](cli.md) §3.4).
Their intended usage:

```bash
# List available profiles
platformctl iso profile list

# Show profile details
platformctl iso profile show production

# Generate configuration from profile
platformctl iso profile generate --profile production --output prod.yaml

# Validate a configuration file
platformctl iso profile validate myconfig.yaml
```

### Built-in Profiles

| Profile | Description |
|---------|-------------|
| `dev` | Development workstation with debug enabled and relaxed security |
| `production` | Production server with balanced security and integrity lockdown |
| `fips` | FIPS 140-3 compliant with FIPS mode and integrity lockdown |
| `production-hs` | High-security production with FIPS and confidentiality lockdown |


## Testing the ISO

The `platformctl iso test` command provides QEMU-based testing with software TPM support.


### QEMU / KVM

```bash
# Test ISO installation
platformctl iso test install --iso trusted-alpine-1.0.0-x86_64.iso

# Test first boot after installation
platformctl iso test firstboot --disk alpine-platform-installed.qcow2

# Test normal boot
platformctl iso test boot --disk alpine-platform-installed.qcow2

# Run all tests sequentially
platformctl iso test all --iso trusted-alpine-1.0.0-x86_64.iso
```

### Test Command Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--disk` | alpine-platform-installed.qcow2 | Path to qcow2 disk image |
| `--disk-size` | 10G | Disk size (e.g., 2G, 10G, 20G) |
| `--disk-cache` | writethrough | QEMU disk cache mode (`writethrough`, `writeback`, `none`, `unsafe`, `directsync`); nested-virt hosts should use `unsafe` or `writeback` |
| `--memory` | 8192 | RAM in MB |
| `--cpus` | auto | Number of CPU cores |
| `--secure-boot` | true | Enable UEFI Secure Boot |
| `--fido2` | false | Enable FIDO2/CanoKey device emulation |
| `--fido2-mode` | canokey | FIDO2 mode: canokey, u2f-emulated, or u2f-passthru |
| `--network` | auto | Network mode: user, bridge, or none |


### UEFI / OVMF

Secure Boot keys are enrolled into the OVMF_VARS UEFI NVRAM file using native Go code in the `pkg/uefi` and `pkg/qemu` packages. This replaces external tools and provides a pure Go implementation.


## Booting the OS

The installer writes the signed UKI (kernel with EFI stub, initramfs and cmdline) to the default EFI location `/EFI/BOOT/BOOTX64.EFI` (`BOOTAA64.EFI` on arm64) and registers it as a UEFI boot entry. Firmware that honors the default path boots it without that entry.


### Bare Metal

If your UEFI system does not automatically load the default bootx64.efi path, you will need to set the path manually. Refer to your motherboard documentation on how to access your UEFI firmware interface to set the boot entry.


### Direct Kernel Boot

QEMU supports [Direct Kernel Boot](https://qemu-project.gitlab.io/qemu/system/linuxboot.html) which is very useful for fast Linux kernel testing.


## Config Delivery Modes

`platformctl iso create` supports four config-delivery modes. Pick based
on your deployment topology. What the orchestrator publishes per MAC is
`docs/bootstrap/architecture.md` (Phase 3 · Control plane).

### 1. Default baked (no flags)

```
platformctl iso create
```

Template: `configs/platform/templates/single-node/default.yaml`
(CP + GW collocated, reference-architecture defaults).
Merged config is written to `/media/cdrom/configs/installer.yaml`
inside the ISO. Installer reads it at PRIO 2 of the autoinstall
priority chain. Good for single-node deploys.

### 2. Custom baked

```
platformctl iso create \
  --platform-config <template> \
  [--overrides <site.yaml>]
```

Same as default but uses the specified template, optionally
deep-merged with an override file. Produces a role-specific ISO
for multi-node deployments that pre-build one ISO per role.

### 3. Dynamic fetch

```
platformctl iso create \
  --config-server http://deployer.lan:8080/config/mac
```

Bakes `platform_config=<URL>` into the kernel cmdline. No config
baked into ISO. At install time, `autoinstall.sh` discovers the
local MAC and fetches `<URL>/<mac-dashed>/installer.yaml` from the
bootstrap orchestrator's pxeboot HTTP server. A single ISO installs
CP, GW, and compute correctly — role selection is MAC-keyed.

### 4. Hybrid (dynamic + baked fallback)

```
platformctl iso create \
  --config-server http://deployer.lan:8080/config/mac \
  --platform-config <template> \
  [--overrides <site.yaml>]
```

Both mechanisms enabled. Install-time PRIO 1 tries dynamic fetch
first; any failure falls through to PRIO 2 and uses the baked config.

### Install-time priority chain

```
Kernel cmdline has platform_config=<URL>?
  yes → PRIO 1: GET <URL>/<mac>/installer.yaml
         200 → use fetched config
         fail → fall through to PRIO 2
  no  → skip PRIO 1

PRIO 2: /media/cdrom/configs/installer.yaml exists? → use it
PRIO 3: Fatal, drop to /bin/sh
```

See `docs/installer/autoinstall.md` for implementation detail.

---

## Network Zone Identity

**No build path calls this today.** `Customizer.EmbedDeviceProfileNetworkConfig`
has no caller outside its tests, so neither `iso create` nor the `iso
customize` stub writes the artifacts below. When it is called with a device
profile, the ISO customizer bakes the SDN zone name into every
network artifact so the installed OS knows its zone at firstboot without
querying an external API.

### Zone sources

Each `NetworkPhaseConfig` in the device profile's `networks:` map carries an
optional `zone:` field. For the trusted (post-enrollment) phase,
`GetPostEnrollmentNetworkConfig()` applies the profile-level `zone:` field as
a fallback when the per-network `zone:` is absent.

### Baked artifacts

`EmbedDeviceProfileNetworkConfig` (`pkg/iso/customize_profile.go`)
writes the following zone-aware artifacts into the ISO overlay
(`<overlay>/etc/platformd/network/`):

| File | Content |
|------|---------|
| `provisioning.yaml` | `NetworkPhaseConfig` YAML; includes `zone:` when non-empty |
| `admitted.yaml` | `NetworkPhaseConfig` YAML of the post-enrollment phase; includes `zone:` when non-empty |
| `quarantine.yaml` | `NetworkPhaseConfig` YAML; includes `zone:` when non-empty |
| `network.env` | Shell-sourceable env file; always declares `TP_NETWORK_ZONE` |

The systemd-networkd stubs at `<overlay>/etc/systemd/network/10-eth0-<phase>.network`
carry a comment header `# trusted-platform-zone: <zone>` when the zone is
known (systemd-networkd has no native zone concept; the comment is the
correct vehicle).

### `TP_NETWORK_ZONE`

`TP_NETWORK_ZONE` is set to the admitted phase's zone name in
`/etc/platformd/network/network.env`. `configs/os/trusted-platform-network.sh`
(run by `trusted-platform-network.service`) sources it as the fallback when
the API is unreachable. The value is the SDN zone
the device operates in after successful enrollment (e.g. `"control-plane"`).

`TP_NETWORK_ZONE` is NOT a kernel cmdline parameter — it does not appear
in the kernel cmdline and is not listed in `docs/reference/kernel-cmdline.md`.
It reaches the running OS exclusively through the baked artifact and through
the live API response (`zone` field in the `admittedNetwork` object of
`GET /api/v1/device/profile`) fetched
by `configs/os/trusted-platform-network.sh`.

### Missing zone semantics

When neither the `NetworkPhaseConfig.Zone` field nor the profile-level
`DeviceProfile.Zone` carries a value, the baked `network.env` declares
`TP_NETWORK_ZONE=""` (empty string). This is consistent with how missing VLAN
IDs are emitted as `0` rather than treated as an error — no error is returned
and the artifact is still written.

---

## Makefile Integration

One Makefile target wraps the CLI:

| Makefile Target | CLI Command |
|-----------------|-------------|
| `make isos` | `bin/platformctl iso create --output bin/$(ISO_NAME)` |
