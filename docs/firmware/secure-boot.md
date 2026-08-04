# Secure Boot Configuration and Management

## Overview

The Trusted Platform provides **URI-driven Secure Boot key management** with support for both **TPM-resident keys** (PK/KEK) and **remote KMS-backed keys** (DB). Keys are referenced by URI (`kms://` or `file://`) rather than filesystem paths, enabling flexible deployment from ISO media, remote KMS backends, or airgap-mode file storage.

The implementation includes:

- **URI-driven key references** - `kms://` (remote KMS) or `file://` (airgap/dev)
- **Hybrid default placement** - PK/KEK on TPM (never leave silicon), DB in CP-KMS
- **Remote signing** - DB key stays server-side; only 64-byte digests sent for signing
- **Kernel module signing** - Compile-time `CONFIG_MODULE_SIG_FORCE` enforcement (separate from UKI signing)
- **Install-time enforcement** - Verify-before-enforce model with Setup Mode verification
- **Native implementation** - Pure Go Authenticode signing, no external tools required

## Configuration Model

### Key Structure

Each Secure Boot key (PK, KEK, DB) is a reference with the following structure:

```yaml
pk:  { cn: "Trusted Platform Secure Boot PK",  store: tpm2,     key-uri: kms://platform/secureboot/pk,  cert-uri: kms://platform/secureboot/pk-cert }
kek: { cn: "Trusted Platform Secure Boot KEK", store: tpm2,     key-uri: kms://platform/secureboot/kek, cert-uri: kms://platform/secureboot/kek-cert }
db:  { cn: "Trusted Platform Secure Boot DB",  store: software, key-uri: kms://platform/secureboot/db,  cert-uri: kms://platform/secureboot/db-cert }
```

Each key reference contains:

| Field | Description |
|-------|-------------|
| `cn` | Common Name for the certificate |
| `store` | Backend that holds the key material (`tpm2`, `software`, etc.). The KMS uses this to route key operations. |
| `key-uri` | URI pointing to the private key: `kms://<path>` (remote KMS) or `file://<path>` (airgap/dev) |
| `cert-uri` | URI pointing to the companion certificate (usually `kms://`) |

### URI Scheme Reference

| Scheme | Example | Purpose | Key Residency |
|--------|---------|---------|----------------|
| `kms://` | `kms://platform/secureboot/db` | Remote KMS backend (canonical for production). The `store` field picks the backend. | Server-side (never leaves KMS during signing) |
| `file://` | `file:///etc/secureboot/db.key` | Airgap/dev mode: key material on disk. Use only in isolated environments. | On-disk (dev/recovery only) |
| `idevid:` | `idevid://base64data` | Inline secret: base64-encoded ciphertext decrypted by device IDevID cert. Used for device-specific provisioning. | Inline in config |

### Backend Selection

Backend selection is **not** controlled by the URI scheme. Instead, the inlined `store` field determines how the KMS backend routes key operations:

- `store: tpm2` → TPM 2.0 backend (key never leaves silicon)
- `store: software` → Software backend (in-memory or KMS persisted)
- `store: hsm` → Hardware Security Module (future)

The URI scheme (`kms://` vs `file://`) only distinguishes **remote KMS resolution** from **on-disk key material**. The `store` field is what the backend looks at to choose the actual key provider.

### Resign Mode

The `resign-mode` field controls how database key signing is performed:

| Mode | Behavior | When to use |
|------|----------|-------------|
| `remote` (default) | DB key stays server-side. Only the module/UKI hash digest is sent to the KMS for signing. | Production: DB key never leaves the KMS server. |
| `local` | Key material is resolved on-node. Full key material may be downloaded and used locally. | Development, airgap nodes, or when KMS is not accessible. |

In `remote` mode the node sends only the digest to the control plane's
`POST /api/v1/provisioning/sign` endpoint, which signs it with the CP-KMS DB key
and returns the signature plus the DB certificate. That request is authenticated
with EAB credentials, a single-use nonce, and the device's EK certificate — the
same pre-enrollment authentication as config delivery — so it works before the
node has an IDevID. See
[Config Delivery](../provisioning/config-delivery.md#sign-digest-remote-secure-boot-resign).

## Complete Example Configuration

```yaml
secure-boot:
  enabled: true
  enforce: false
  resign-mode: remote
  pk:  { cn: "Trusted Platform Secure Boot PK",  store: tpm2,     key-uri: kms://platform/secureboot/pk,  cert-uri: kms://platform/secureboot/pk-cert }
  kek: { cn: "Trusted Platform Secure Boot KEK", store: tpm2,     key-uri: kms://platform/secureboot/kek, cert-uri: kms://platform/secureboot/kek-cert }
  db:  { cn: "Trusted Platform Secure Boot DB",  store: software, key-uri: kms://platform/secureboot/db,  cert-uri: kms://platform/secureboot/db-cert }
```

### Field Descriptions

- **`enabled`** (bool, optional) - Enables Secure Boot support. If false, UKI signing and enforcement are skipped. Default: false.
- **`enforce`** (bool, optional) - Attempt to transition firmware into enforced Secure Boot mode. Default: false. SAFETY: enforcement only proceeds if the signed UKI verifies against the db certificate AND the firmware is in Setup Mode. Failures are logged as warnings and never abort the install.
- **`resign-mode`** (string, optional) - `remote` (default) or `local`. Controls whether DB signing uses remote KMS (digest only) or local key material.
- **`pk`, `kek`, `db`** - Key reference blocks. Each requires `cn`, `store`, `key-uri`, and `cert-uri`.

## Kernel Module Signing

### Overview

Kernel module signing enforces a **separate trust root** from UEFI Secure Boot. The kernel maintains its own keyring (`.builtin_trusted_keys` / `.secondary_keys` / `.machine`); a module must be signed by a key present in that keyring to load.

### Compile-Time Enforcement

The production FIPS kernel applies compile-time configuration to enforce module signatures:

| Config Option | Purpose |
|---------------|---------|
| `CONFIG_MODULE_SIG` | Enable kernel module signature support |
| `CONFIG_MODULE_SIG_ALL` | Auto-sign all in-tree modules at build time |
| `CONFIG_MODULE_SIG_SHA256` | Use SHA-256 for module digests |
| `CONFIG_MODULE_SIG_FORCE` | **ENFORCE**: reject any unsigned or untrusted-signed modules at load time |
| `CONFIG_MODULE_SIG_KEY` | Path to the stable module-signing key+cert (production builds only) |

When `CONFIG_MODULE_SIG_FORCE=y`, the kernel **silently rejects** any module that is:

1. Unsigned (no appended signature)
2. Signed with a key not in the kernel's trusted keyring

This enforcement happens **at load time**, before the module code executes. Combined with `CONFIG_MODULE_SIG_ALL`, every in-tree module in the production kernel is signed at build time with a stable platform key, making the module set fully enforced.

### Production vs. Development Builds

**Production builds** (e.g., CI/CD):
- Set `MODULE_SIGNING_KEY=/path/to/stable-key+cert.pem`
- The kernel embeds the public key in `.builtin_trusted_keys`
- Modules signed with this key load anywhere
- Out-of-tree modules can be signed with the same key via `pkg/modulesign`

**Development builds** (e.g., local `make fips-kernel`):
- `MODULE_SIGNING_KEY` unset
- Kernel auto-generates an ephemeral per-build key
- All in-tree modules signed with the ephemeral key
- Development modules load because they're signed with the build's own key
- NOT suitable for multi-build deployments (modules from different builds won't cross-load)

### Stable Module-Signing Key Provisioning

The stable platform module-signing key is generated ONCE per platform by the
operator, stored **outside the repository**, and consumed by the FIPS kernel
build via `CONFIG_MODULE_SIG_KEY`:

```bash
# One-time: generate the key (default: ~/.trusted-platform/secure-boot/module-signing-key.pem)
platformctl iso module-signing-key
# or, from the kernel builder directory:
make -C build/docker/fips-kernel-builder module-key

# Every production kernel build: mount the key read-only into the builder
make -C build/docker/fips-kernel-builder build \
  MODULE_SIGNING_KEY=$HOME/.trusted-platform/secure-boot/module-signing-key.pem
```

The generator (`pkg/secureboot.GenerateModuleSigningKey`) writes a single PEM
bundle — PKCS#8 private key followed by a self-signed certificate carrying the
kernel-required extensions (`CA:FALSE`, `keyUsage=digitalSignature`, SKID/AKID)
— exactly the layout of the kernel's autogenerated `certs/signing_key.pem`.
The builder Makefile mounts the key read-only into the container; the key
never enters the build context or an image layer.

Rules:

- **Back the key up.** Regenerating it orphans every module signed with the
  old key on already-built kernels; `platformctl iso module-signing-key`
  refuses to overwrite an existing key without `--force`.
- **Never commit the key** or copy it into a Docker build context.
- The same key is the signer for out-of-tree modules via `pkg/modulesign`
  (`pkg/secureboot.LoadModuleSigningKey` loads it back as a `crypto.Signer`).

KMS-residency note: the kernel build itself signs thousands of in-tree
modules (`CONFIG_MODULE_SIG_ALL`) inside a standalone Docker container that
runs before/independently of any platform deployment, so build-time
remote-KMS hash-signing is not applicable here. The honest production pattern
is this operator-provisioned key file with restricted permissions (0600);
KMS-backed signing remains the model for the UKI DB key (resign-mode
`remote`), which is a per-node, install/update-time operation.

### Out-of-Tree Module Signing

The `pkg/modulesign` package signs out-of-tree kernel modules (`.ko` files) with a detached CMS (PKCS#7) signature in the exact format the kernel's module verifier accepts. The signed module layout is:

```
original_module_bytes || cms_der || module_signature(12B) || magic(28B)
```

Where:
- `cms_der` - Detached CMS SignedData envelope (no embedded certificates)
- `module_signature` - 12-byte `struct module_signature` trailer
- `magic` - 28-byte marker: `"~Module signature appended~\n"`

The kernel's module verifier:
1. Extracts the CMS signature from the file tail
2. Verifies the signature against the module bytes using CMS digest verification
3. Matches the signer (issuer + serial) against the kernel's trusted keyring
4. Rejects the module if the signer is not in the keyring

No per-node re-signing is required for in-tree modules; only out-of-tree `.ko` files need signing via `pkg/modulesign`.

### Kernel Command-Line Note

The kernel does NOT provide a command-line parameter to override `CONFIG_MODULE_SIG_FORCE` at boot. Module signature enforcement is a compile-time decision only. All production boots enforce module signatures; there is no runtime opt-out.

## UEFI Secure Boot

### Signature Chain

```
Firmware (OVMF/UEFI) with Secure Boot enabled
    ↓ verifies UKI signature against enrolled DB certificate
UKI (Unified Kernel Image, signed with DB key)
    ↓ is a single PE/COFF executable containing:
        - Linux kernel
        - Initramfs
        - Kernel command line (embedded, cannot be modified at boot)
        - Other boot components (optional)
```

When Secure Boot is enabled in firmware:

1. Firmware loads the UKI from disk
2. Firmware verifies the Authenticode signature against the enrolled DB certificate
3. Firmware executes the UKI if the signature verifies
4. Firmware halts if the signature is invalid or missing

The kernel and initramfs cannot be modified at boot because they are embedded in the UKI; the command line is also embedded.

### Signing Implementation

The platform uses native Go Authenticode signing via `pkg/authenticode`. The UKI is signed with the DB key during installation:

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/authenticode"

signer, err := authenticode.NewSigner(&authenticode.SignerOptions{
    KeyStore:      keyBackend,      // SDK-backed key provider
    Certificate:   dbCert,           // DB certificate (embedded in UKI signature)
    Logger:        logger,
})

// Sign the UKI in place
err = signer.SignFile(ukiPath)
```

### Install-Media Key Staging (ISO builds)

ISO builds stage the Secure Boot material in ONE canonical location:
`<iso-root>/secure-boot-keys/` (PK/KEK/DB certificates plus the DB keypair for
offline `local` resign-mode). During installation the Alpine live environment
mounts the install media at `/media/cdrom`, so the generated installer config
references the DB keypair as:

```yaml
secure-boot:
  enabled: true
  resign-mode: local
  db:
    key-uri: file:///media/cdrom/secure-boot-keys/DB.key
    cert-uri: file:///media/cdrom/secure-boot-keys/DB.crt
```

`pkg/iso` exposes this contract as `SecureBootKeysISODirName` /
`SecureBootKeysMediaDir`; the staging path and the generated URIs are pinned
together by unit tests. If the media is mounted elsewhere (USB installs), the
installer's documented resolver chain warns and falls through to on-node DB
key generation — the install never strands.

## Install-Time Secure Boot Enforcement

### Overview

When `secure-boot.enforce: true`, the installer attempts to enroll the Secure Boot keys into the firmware and activate Secure Boot enforcement. This is a **safety-gated operation** with multiple guards:

1. **Verify-before-enforce** - The signed UKI must prove to verify against the DB certificate being enrolled
2. **Setup Mode verification** - The firmware must be in Setup Mode (unauthenticated key enrollment allowed)
3. **Ordered enrollment** - Keys are enrolled as `db` → `KEK` → `PK` (PK enrollment activates enforcement)
4. **Foreseeable failures are non-fatal** - Any expected failure (missing key material, firmware not Setup Mode, signature verification failure) logs a warning and skips enforcement; the system still boots unsigned

### Safe-by-Default Behavior

The enforcement gate is specifically ordered to guarantee a failed enrollment **cannot strand the node**:

1. **DB enrollment** - If db enrollment fails, KEK and PK are never written; firmware remains in Setup Mode
2. **KEK enrollment** - If KEK enrollment fails, PK is never written; firmware remains in Setup Mode
3. **PK enrollment** (activates enforcement) - Only written if db + KEK succeeded and the signed UKI verified

If **any step before PK fails**, the firmware is left in Setup Mode and the node still boots unsigned. The physical operator can delete the firmware keys in Setup Mode to recover.

### Recovery and Rollback

- **Rollback to unsigned** - Delete PK from firmware setup mode (requires physical or BMC access)
- **Re-provision node** - Reboot from install media, leave `enforce: false` in config

### When to Enable Enforcement

`enforce: true` should only be enabled after:

1. Validating Secure Boot enrollment works on **OVMF/QEMU** (test environment)
2. Validating Secure Boot enrollment works on **production firmware** (e.g., Supermicro X10, Dell R640)
3. Verifying the operating procedure for key recovery (deleting PK, re-running installer)

Hardware validation is critical: different firmware vendors have different Setup Mode implementations. The `pkg/uefi/efivars_enroll.go` package implements the standard UEFI approach, but firmware quirks may require adjustments.

## Dual-Target Model: Virtual and Real Hardware

Secure Boot enrollment and TPM attestation are first-class on BOTH targets:

| Concern | Virtual (OVMF / swtpm) | Real hardware (e.g. Supermicro X10) |
|---------|------------------------|--------------------------------------|
| Key enrollment | OVMF NVRAM-file enroller (`pkg/uefi/enrollment.go`), exercised by the OVMF integration suite | efivarfs authenticated writes (`pkg/uefi/efivars_enroll.go`) via `platformctl secure-boot enroll/enforce` and the installer gate |
| Firmware state | OVMF `EnrollmentStatus` | `uefi.ReadSecureBootStatus()` — efivarfs read side (`SetupMode`, `SecureBoot`, `UserMode`, PK/KEK/db/dbx summaries) |
| TPM | swtpm Unix socket or in-process simulator | `/dev/tpmrm0` (or `/dev/tpm0`) character device |
| TPM selection | `tpm.device: /path/to/swtpm.sock` or `tpm.simulator: true` | `tpm.device: /dev/tpmrm0` |

### TPM Target Selection (single resolver)

The hardware-vs-swtpm-vs-simulator decision is made in exactly one place —
`vtpm.ResolveTPMTarget` — consumed by `pkg/app` `OpenTPM()` (the platform TPM),
`vtpm.TPMProvider.GetTPMForTarget` (attestation providers), and the hardware
integration tier. The `tpm:` config section expresses the target explicitly:

```yaml
tpm:
  device: /dev/tpmrm0     # REAL HARDWARE (fails closed if the device is absent)
  # device: /var/lib/swtpm/swtpm.sock   # swtpm socket (virtual hosts)
  # device: auto          # runtime detection: swtpm socket, then /dev/tpmrm0, then /dev/tpm0
  simulator: false        # true = in-process simulator (dev only; takes precedence over device)
```

Explicit configuration always wins and never silently degrades:

- A hardware device path that does not exist fails with `ErrHardwareTPMUnavailable`.
- A swtpm `.sock` path that does not exist fails with `ErrSwtpmSocketUnavailable`.
- `auto` that detects nothing fails with `ErrNoTPMDetected`.

### Bare-Metal CLI Verbs

`platformctl secure-boot` operates on the running firmware via efivarfs:

```bash
# Read-only firmware state: SetupMode / SecureBoot / UserMode + PK/KEK/db/dbx contents
platformctl secure-boot status

# Dry-run (default): runs EVERY guard — efivarfs present, Setup Mode, certificates
# load, signed UKI Authenticode-verifies against the DB cert — and writes NOTHING
platformctl secure-boot enroll

# Commit: write db -> KEK -> PK (PK LAST; enrollment requires Setup Mode)
platformctl secure-boot enroll --commit

# Enforcement gate: no-op if already enforced, otherwise enroll + confirm PK present
platformctl secure-boot enforce --commit
```

Key material defaults to `/etc/trusted-platform/secure-boot/{PK,KEK,DB}.crt`
(`--keys-dir`, or per-role `--pk-cert/--kek-cert/--db-cert`); the signed UKI
defaults to `/boot/efi/EFI/BOOT/BOOTX64.EFI` (`--uki`). All safety gates from
the installer apply identically: Setup Mode required, verify-before-enforce,
PK written last, typed errors on every failure.

### Operator Workflow on Real Hardware (X10)

1. Boot the node in UEFI mode and clear the Secure Boot keys in firmware setup
   (this puts the firmware in Setup Mode).
2. `platformctl secure-boot status` — confirm `SetupMode: enabled`.
3. `platformctl secure-boot enroll` — dry-run; every guard must pass.
4. `platformctl secure-boot enroll --commit` — writes db → KEK → PK.
5. `platformctl secure-boot status` — confirm PK/KEK/db present and Setup Mode left.
6. Reboot; Secure Boot is enforced. Recovery: delete PK in firmware setup.

### Hardware Integration Tier

`test/integration/secureboot/hardware/` is the opt-in REAL-HARDWARE tier of the
Secure Boot suite. Run it **on the target node**, never in the devcontainer:

```bash
make integration-test-secureboot-hw          # sets TP_HW_TPM=1 TP_HW_EFIVARS=1
```

| Env var | Effect |
|---------|--------|
| `TP_HW_TPM=1` | Full attestation cycle against the hardware TPM: resolver → provider dispatch → PCR 0/7 read → IAK quote with fresh nonce → TPMS_ATTEST magic/nonce check → signature verification against the IAK public key. Requires a **provisioned** platform TPM (IAK); an unprovisioned TPM fails with a typed error. |
| `TP_HW_TPM_DEVICE` | Override the TPM device (default `/dev/tpmrm0`). |
| `TP_HW_EFIVARS=1` | **Read-only** efivarfs checks: SetupMode/SecureBoot parse plus state invariants (enforced ⇒ PK+db present, not Setup Mode). |

Gating is skip-free and honest: with a tier variable set but the hardware
precondition missing, the test FAILS with a typed error (`ErrHardwareTPMUnavailable`,
`ErrHardwareTPMNotProvisioned`, `ErrEfivarsRequired`) — it never `t.Skip()`s and
never fakes success. With the variables unset (the CI default) the tier is
disabled and the virtual OVMF tier remains authoritative.

The tier NEVER writes an EFI variable: committing PK from CI would take the
node out of Setup Mode and can strand its boot chain. The efivars WRITE path is
validated by the operator through the CLI dry-run/commit workflow above.

## Key Components

### Native UEFI NVRAM Manipulation

**Package**: `pkg/uefi`

Provides pure Go implementation of UEFI variable operations.

**Variable-store format contract**: the variable-header layout is a property
of the STORE, not of an individual variable's attributes. OVMF's
`OVMF_VARS*.fd` uses the AUTHENTICATED variable store
(`gEfiAuthenticatedVariableGuid`), in which **every** variable carries the
60-byte `AUTHENTICATED_VARIABLE_HEADER` — including variables that have no
`TIME_BASED_AUTHENTICATED_WRITE_ACCESS` attribute. Emitting a 32-byte header
for such a variable produces a store the firmware cannot walk; EDK2's variable
driver faults with `#UD - Invalid Opcode` on the next boot.

**Firmware-derived variables**: `SetupMode` and `SecureBoot` are *not*
persisted by enrollment. EDK2's `AuthVariableLib` recomputes them from PK
presence at every boot (PK present ⇒ User Mode ⇒ Secure Boot active) and
publishes them as volatile variables, then creates the non-volatile
`SecureBootEnable` knob itself. `EnrollKeys` therefore writes only
`db` → `KEK` → `PK`; enrolling PK last is what activates Secure Boot.
`GetEnrollmentStatus()` mirrors the firmware rule, deriving mode from PK
presence when the volatile variables are absent from an offline store.

Both behaviors are proven end to end by `TestOVMFSecureBootEnforcement` and
pinned by unit regression tests in `pkg/uefi`.

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/uefi"

// Check if firmware is in Setup Mode
isSetup, err := uefi.IsSetupMode()

// Read/write EFI variables
nvram, err := uefi.ReadVariable("SetupMode", uefi.EFIGlobalVariable)
err = uefi.WriteVariable("db", uefi.EFIImageSecurityDatabase, eslBytes)
```

### Authenticode Signing

**Package**: `pkg/authenticode`

Signs and verifies PE/COFF files (bootloaders, UKIs) without external tools.

### Module Signing

**Package**: `pkg/modulesign`

Signs out-of-tree kernel modules with detached CMS signatures in kernel-verifier format.

## Troubleshooting

### "Secure Boot enforcement failed" warning

This is expected if:
- Firmware is not in Setup Mode (requires manual key deletion in firmware setup)
- DB key material is unavailable (check KMS connectivity during install)
- The signed UKI failed to verify against the db certificate (check key-uri / cert-uri)

The system still boots. Check the full installation log to determine which condition triggered the warning.

### "UKI verification failed"

The Authenticode signature on the UKI does not match the DB certificate being enrolled. Check:

1. DB key-uri and cert-uri are correctly configured
2. The signing key and certificate are properly resolved from the KMS
3. The UKI was successfully signed (check install logs)

### Bare-metal firmware doesn't support efivarfs

Some firmware images do not expose the `efivarfs` pseudo-filesystem. Enforcement will be skipped with a warning; the system still boots. Enroll keys manually in the firmware setup menu if Secure Boot is required.

## Security Considerations

### Key Storage

**CRITICAL**: Secure Boot keys are the root of trust for firmware signature verification.

- **PK/KEK (TPM-resident)** - Keys never leave the TPM; the TPM itself is the trusted storage
- **DB (KMS-backed)** - In production, DB keys are stored in the CP-KMS and never leave the server for `remote` resign-mode
- **File-backed keys** (dev only) - Keep encrypted; never commit to version control

### Recovery After Key Loss

If the DB key is lost but PK/KEK are still enrolled:

1. The system cannot re-sign new UKIs
2. Boot is still possible with the current signed UKI
3. To recover:
   - Delete PK from firmware setup (physical or BMC access)
   - Regenerate the key material in the KMS
   - Re-provision the node with a newly signed UKI

### Hardware Validation

Secure Boot enrollment is firmware-specific. Before deploying `enforce: true` to production:

1. Validate on OVMF/QEMU (development environment)
2. Validate on each production hardware model (e.g., Supermicro X10, Dell R640)
3. Document the recovery procedure for your site
4. Test rollback (delete PK, re-run installer with `enforce: false`)

## Integration Testing

`test/integration/secureboot/` proves the chain against real external
verifiers and real firmware. Run with:

```bash
make integration-test-secureboot
```

| Test | Proves |
|------|--------|
| `TestModuleSignOpenSSLInterop` | `pkg/modulesign` output is a valid detached CMS over the exact module bytes (verified by OpenSSL, an independent implementation) and follows the kernel appended-signature contract (trailer + magic). |
| `TestModuleSignCorruptedSignatureFailsVerify` / `TestModuleSignTamperedContentFailsVerify` | Signature and content binding: any modification fails verification. |
| `TestUnsignedModuleLacksTrailer` | Unsigned modules carry no trailer — the condition `CONFIG_MODULE_SIG_FORCE` rejects. |
| `TestOVMFSecureBootEnforcement` | Full enforce cycle on real OVMF firmware: platform-generated PK/KEK/DB enrolled into the variable store via `pkg/uefi`, a DB-signed EFI payload (platform Authenticode signer, cross-checked with `sbverify`) **boots**, while unsigned and wrongly-signed payloads are **rejected** by the firmware with `Access Denied`. |
| `TestFIPSKernelModuleSignatureEnforcement` | The real FIPS kernel rejects an unsigned module at insmod with `ENOKEY` ("Required key not available"), loads the build-signed module, and loads the same module re-signed by `pkg/modulesign` with the stable platform key. |

The FIPS-kernel test consumes **prebuilt artifacts** (the kernel takes hours
to build) via environment variables and FAILS with a typed setup error when
they are absent — the `secureboot` target is therefore excluded from the
`all` integration sweep:

```bash
# Build once (out of band):
make -C build/docker/fips-kernel-builder module-key
make -C build/docker/fips-kernel-builder build \
  MODULE_SIGNING_KEY=$HOME/.trusted-platform/secure-boot/module-signing-key.pem

# Then run the suite:
export FIPS_KERNEL_IMAGE=build/docker/fips-kernel-builder/output/vmlinuz-fips
export FIPS_MODULES_TAR=build/docker/fips-kernel-builder/output/modules-fips-<kver>.tar.gz
export FIPS_MODULE_SIGNING_KEY=$HOME/.trusted-platform/secure-boot/module-signing-key.pem
make integration-test-secureboot
```

The devcontainer provides `qemu-system-x86`, `ovmf` (the
`OVMF_CODE_4M.secboot.fd` Secure Boot build), `sbsigntool`, `openssl` and
`busybox-static` (for the test initramfs).

## References

- [UEFI Secure Boot Specification](https://uefi.org/specs/UEFI/2.10/32_Secure_Boot_and_Driver_Signing.html)
- [Microsoft Authenticode Specification](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/authenticode)
- [Linux Kernel Module Signing](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)

## Summary

The Secure Boot implementation provides:

1. **URI-driven configuration** - Flexible key referencing (kms://, file://, idevid://)
2. **Hybrid key placement** - PK/KEK on TPM, DB in KMS by default
3. **Remote signing** - DB key stays server-side during production deployments
4. **Separate module signing** - Compile-time enforcement via CONFIG_MODULE_SIG_FORCE
5. **Safe installation** - Verify-before-enforce gate with Setup Mode verification
6. **Production-ready** - Enforce cycle and module-signature rejection proven against real OVMF firmware and the real FIPS kernel in `test/integration/secureboot/`; hardware-specific validation still required before bare-metal `enforce: true` (Supermicro X10 / Dell R640).
