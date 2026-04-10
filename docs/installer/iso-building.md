# Trusted Platform ISO

The Trusted Platform ISO is built using the `platformctl iso` command, which provides a complete CLI for downloading, customizing, and building bootable Alpine Linux ISO images with platform-specific components.


## Building the ISO

The `platformctl iso create` command performs all build steps in sequence:

1. Download Alpine Linux ISO with SHA256 verification
2. Extract ISO contents for customization
3. Generate Secure Boot keys (if enabled)
4. Customize with platform components (platformd copies itself into the ISO)
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


### Command Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--alpine-version` | 3.22.2 | Alpine Linux version to download |
| `--mirror` | http://mirror.cs.odu.edu/alpine | Alpine Linux mirror URL |
| `--arch` | x86_64 | Architecture (x86_64 or aarch64) |
| `--platform-type` | server | Platform type: 'server' or 'client' |
| `--platform-config` | auto-detected | Path to platformd.yaml config file |
| `--installer-config` | configs/installer/default.yaml | Path to installer config file |
| `--secure-boot` | true | Enable Secure Boot support |
| `--tpm-unseal` | true | Enable TPM auto-unseal |
| `--luks` | true | Enable LUKS encryption |
| `--fips` | false | Enable FIPS mode |
| `--fido2` | false | Enable FIDO2 security key support |
| `--keys-dir` | work/secure-boot-keys | Secure Boot keys directory |
| `--generate-keys` | true | Generate Secure Boot keys if they don't exist |
| `--key-backend` | file | Key backend: file, software, pkcs11, tpm2, yubikey, awskms, azurekv, gcpkms, vault |
| `--output` | auto-generated | Output ISO filename |
| `--webui` | auto-detected | Path to WebUI directory or tarball |
| `--work-dir` | work | Working directory for ISO operations |
| `--force` | false | Force rebuild even if files exist |
| `--debug` | false | Enable debug output |

The output filename defaults to: `trusted-alpine-<version>-<arch>.iso` (or with `-fips` suffix if FIPS is enabled).


## Individual Commands

For more control over the build process, each step can be executed individually:

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

Builds a hybrid BIOS/UEFI bootable ISO image using xorriso:

```bash
# Build with default settings
platformctl iso build --iso-dir work/iso --output platform.iso

# Build with custom volume label
platformctl iso build --iso-dir work/iso --output platform.iso --label MY_PLATFORM
```

The resulting ISO can boot via:
- Legacy BIOS (using isolinux/syslinux)
- UEFI (using grub EFI bootloader)
- USB/HDD (via isohybrid MBR)


## Installation Profiles

The `platformctl iso profile` command manages installation configuration profiles:

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
| `--memory` | 8192 | RAM in MB |
| `--cpus` | auto | Number of CPU cores |
| `--secure-boot` | true | Enable UEFI Secure Boot |
| `--fido2` | false | Enable FIDO2/CanoKey device emulation |
| `--fido2-mode` | canokey | FIDO2 mode: canokey, u2f-emulated, or u2f-passthru |
| `--network` | auto | Network mode: user, bridge, or none |


### UEFI / OVMF

Secure Boot keys are enrolled into the OVMF_VARS UEFI NVRAM file using native Go code in the `pkg/uefi` and `pkg/qemu` packages. This replaces external tools and provides a pure Go implementation.


## Booting the OS

The installed Operating System writes a custom compiled and signed kernel with EFI stub support to `/EFI/debian/kernel.efi` and copies it to the default EFI location `EFI/Boot/bootx64.efi`. This allows default systems that honor the default path to boot without any custom UEFI boot entries.


### Bare Metal

If your UEFI system does not automatically load the default bootx64.efi path, you will need to set the path manually. Refer to your motherboard documentation on how to access your UEFI firmware interface to set the boot entry.


### Direct Kernel Boot

QEMU supports [Direct Kernel Boot](https://qemu-project.gitlab.io/qemu/system/linuxboot.html) which is very useful for fast Linux kernel testing.


## Makefile Integration

For convenience, Makefile targets wrap the CLI commands:

| Makefile Target | CLI Command |
|-----------------|-------------|
| `make download-iso` | `platformctl iso download` |
| `make extract-iso` | `platformctl iso extract` |
| `make customize-iso` | `platformctl iso customize` |
| `make build-iso` | `platformctl iso build` |
| `make iso` | `platformctl iso create` |
| `make test-install` | `platformctl iso test install` |
