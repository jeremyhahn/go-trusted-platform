# TPM Configuration

> **Status: REFERENCE** · Last verified: 2026-10-15
> The `tpm:` configuration section and its flags.

This document describes the configuration options for the TPM 2.0 integration in go-trusted-platform.

## Configuration Overview

TPM configuration is specified in the platform configuration file (YAML format). The shipped block is
`configs/platform/templates/single-node/default.yaml` (`tpm:`). There are no global TPM flags or
environment variables; the `platformctl tpm` commands take the per-command flags listed below.

## Configuration File

### Basic TPM Configuration

The `device` and `simulator` keys express the TPM target explicitly and are
resolved by a single platform-wide resolver (`vtpm.ResolveTPMTarget`):

| Configuration | Target | Failure mode |
|---------------|--------|--------------|
| `device: /dev/tpmrm0` (or `/dev/tpm0`) | Real hardware TPM character device | `ErrHardwareTPMUnavailable` if the device is absent — never silently downgrades to a software TPM |
| `device: /path/to/swtpm.sock` | swtpm software TPM over a Unix socket | `ErrSwtpmSocketUnavailable` if the socket is absent — never silently opens a hardware device |
| `device: auto` (or empty) | Runtime detection: swtpm socket, then `/dev/tpmrm0`, then `/dev/tpm0` | `ErrNoTPMDetected` when nothing is found |
| `simulator: true` | In-process TPM simulator (development only) | Takes precedence over `device` |

```yaml
tpm:
  # TPM target: /dev/tpmrm0 (hardware), /path/to/swtpm.sock (swtpm), or auto (detect)
  device: /dev/tpmrm0

  # Use the in-process TPM simulator (development only; takes precedence over device)
  simulator: false

  # Encrypt TPM command sessions
  encrypt-sessions: false

  # Use TPM as entropy source
  entropy: false

  # Default hash algorithm
  hash: SHA-256
```

### Key Handle Configuration

Each key type is configured in its own nested section:

```yaml
tpm:
  # Endorsement Key (EK) - manufacturer-certified identity key
  ek:
    handle: 0x81010001
    hash: SHA-256
    rsa:
      size: 2048

  # Shared Storage Root Key (SSRK) - protects storage hierarchy
  ssrk:
    handle: 0x81000001
    platform-policy: false
    rsa:
      size: 2048

  # Initial Attestation Key (IAK) - for remote attestation
  iak:
    handle: 0x81010002
    hash: SHA-256
    signature-algorithm: SHA256-RSA
    rsa:
      size: 2048

  # Initial Device ID (IDevID) - device identity certificate
  idevid:
    handle: 0x81020000
    cert-handle: 0x01C90000   # currently IGNORED - see "Certificate handles" below
    model: edge
    serial: device-serial-001
    hash: SHA-256
    signature-algorithm: SHA256-RSA
    rsa:
      size: 2048
```

#### Certificate handles

**`iak.cert-handle` and `idevid.cert-handle` are currently IGNORED.** Both are
cleared at startup (`applyCertHandleNVInterim`, `pkg/app/tpm_cert_nv.go`), and the IAK and IDevID certificates are kept in the platform
certificate store instead of TPM NVRAM. A warning naming the ignored handle is
logged at boot.

This is temporary. go-xkms defines the NV index as a *counter*, which the TPM
accepts only at 8 bytes, so every certificate-sized NV write is rejected with
`TPM_RC_SIZE` and the daemon does not start — see go-xkms#138, tracked here as
issue #81 and documented in [engineering.md](engineering.md) item 9. Setting
either field is harmless; it simply has no effect until that fix is adopted.

Two consequences worth knowing while this stands:

- A verifier must **not** assume an identity certificate is in NVRAM merely
  because a handle is configured.
- The certificate store has no `TPM_PT_NV_INDEX_MAX` ceiling (2048 bytes on the
  reference simulator), so certificates too large for an NV index persist fine
  today.

### PCR Configuration

```yaml
tpm:
  # Platform PCR for measurements
  platform-pcr: 23

  # PCR bank to use
  platform-pcr-bank: sha256

  # PCRs for sealing (Secure Boot + kernel cmdline)
  golden-pcrs: [7, 9]
```

### Platform SRK Configuration

```yaml
tpm:
  # Platform storage root key for application keys
  platform-srk:
    srk-handle: 0x81000002
    # SRK authorization, generated and kept in the platform KMS
    srk-auth: "kms://tpm/platform-srk/srk-auth?ensure=true&len=32&enc=raw"
    platform-policy: true       # Bind to platform PCR state
```

## Full Configuration Example

```yaml
# Platform TPM configuration
tpm:
  # Device configuration
  device: /dev/tpmrm0
  simulator: false
  encrypt-sessions: false
  entropy: false
  hash: SHA-256

  # Endorsement Key (EK) - manufacturer-certified identity key
  ek:
    handle: 0x81010001
    hash: SHA-256
    rsa:
      size: 2048

  # Shared Storage Root Key (SSRK) - protects storage hierarchy
  ssrk:
    handle: 0x81000001
    platform-policy: false
    rsa:
      size: 2048

  # Initial Attestation Key (IAK) - for remote attestation
  iak:
    handle: 0x81010002
    hash: SHA-256
    signature-algorithm: SHA256-RSA
    rsa:
      size: 2048

  # Initial Device ID (IDevID) - device identity certificate
  idevid:
    handle: 0x81020000
    cert-handle: 0x01C90000   # currently IGNORED - see "Certificate handles" below
    model: edge
    serial: device-serial-001
    hash: SHA-256
    signature-algorithm: SHA256-RSA
    rsa:
      size: 2048

  # PCR configuration
  platform-pcr: 23
  platform-pcr-bank: sha256
  golden-pcrs: [7, 9]

  # Platform storage root key for application keys
  platform-srk:
    srk-handle: 0x81000002
    srk-auth: "kms://tpm/platform-srk/srk-auth?ensure=true&len=32&enc=raw"
    platform-policy: true
```

## Command-Line Flags

From `pkg/cli/commands/tpm/`.

### `tpm provision`

| Flag | Description | Default |
|------|-------------|---------|
| `--create-ek` | Create the EK | `true` |
| `--create-srk` | Create the SRK | `true` |
| `--create-ak` | Create the AK | `true` |
| `--owner-password` | Owner hierarchy password | - |
| `--endorsement-password` | Endorsement hierarchy password | - |

### `tpm ek create` / `tpm srk create`

| Flag | Description | Default |
|------|-------------|---------|
| `--algorithm` | `RSA-2048`, `RSA-3072`, `ECDSA-P256` or `ECDSA-P384` | `RSA-2048` |
| `--persistent` | Make the key persistent at the configured `tpm.ek.handle` / `tpm.ssrk.handle` | `true` |
| `--parent` | (`srk create` only) parent handle | `0x81010001` |
| `--parent-password` | (`srk create` only) parent password | - |

### `tpm seal` / `tpm unseal`

| Flag | Description | Default |
|------|-------------|---------|
| `--cn` | Common name of the sealed object (required) | - |
| `--data` | (`seal` only) data to seal | - |
| `--password` | Sealed object password | - |
| `--parent` | Parent key handle | `0x81000001` |
| `--parent-password` | Parent key password | - |
| `--pcrs` | PCR indices to bind to (comma-separated) | - |
| `--pcr-bank` | `sha1`, `sha256`, `sha384` or `sha512` | `sha256` |
| `--overwrite` | (`seal` only) overwrite existing sealed data | `false` |

### `tpm clear`

| Flag | Description | Default |
|------|-------------|---------|
| `--owner-password` | Owner (lockout) authorization | - |
| `--confirm` | Required; without it the command only warns | `false` |
| `--force` | Clear through UEFI PPI (bypasses DA lockout, reboots) | `false` |
| `--device` | TPM device path | `/dev/tpm0` |

## PCR Reference

### PCR Index Assignments

| PCR | Measured By | Contents |
|-----|-------------|----------|
| 0 | Firmware | Core UEFI code |
| 1 | Firmware | UEFI configuration |
| 2 | Firmware | Option ROM code |
| 3 | Firmware | Option ROM configuration |
| 4 | Firmware | MBR/Boot loader |
| 5 | Firmware | GPT/Partition table |
| 6 | Firmware | Resume from S4/S5 |
| 7 | Firmware | Secure Boot state |
| 8 | GRUB | Kernel command line |
| 9 | GRUB/Kernel | Kernel and initrd |
| 10 | IMA | Runtime file measurements |
| 11 | systemd-stub | UKI components |
| 12 | systemd-stub | Kernel parameters |
| 13 | systemd-stub | System extensions |
| 14 | shim | MOK certificates |
| 15 | systemd | Root FS encryption key |

### Recommended PCR Policies

| Use Case | PCRs | Description |
|----------|------|-------------|
| Boot Integrity | 0, 1, 2, 3, 7 | Firmware and Secure Boot |
| Kernel Integrity | 7, 8, 9 | Secure Boot + Kernel |
| UKI Integrity | 7, 11 | Unified Kernel Image |
| Full Integrity | 0-3, 7-9, 11 | Complete boot chain |

## Handle Allocation

### TCG Recommended Handles

| Handle | Key Type | Description |
|--------|----------|-------------|
| 0x81010001 | EK | Endorsement Key (RSA) |
| 0x81010002 | AK/IAK | Attestation Key |
| 0x81000001 | SSRK | Shared Storage Root Key (`tpm.ssrk.handle`) |
| 0x81000002 | Platform SRK | Application key parent (`tpm.platform-srk.srk-handle`) |
| 0x81020000 | IDevID | Device Identity Key |
| 0x81000100+ | App Keys | Application keys |

### Handle Ranges

| Range | Purpose |
|-------|---------|
| 0x81000000-0x8100FFFF | Owner hierarchy persistent |
| 0x81010000-0x8101FFFF | Endorsement hierarchy persistent |
| 0x81020000-0x8102FFFF | Platform hierarchy persistent |

## Software TPM Configuration

### swtpm for Development

```yaml
tpm:
  # A socket path selects swtpm; simulator: true would take precedence
  simulator: false
  device: /tmp/swtpm-sock
```

swtpm itself is started outside the platform; there is no `tpm.swtpm` key.

### Starting swtpm

```bash
# Create state directory
mkdir -p /var/lib/swtpm

# Start swtpm
swtpm socket \
  --tpmstate dir=/var/lib/swtpm \
  --ctrl type=unixio,path=/tmp/swtpm-sock \
  --tpm2 \
  --log level=3
```

### QEMU Integration

```bash
# Start QEMU with vTPM
qemu-system-x86_64 \
  -chardev socket,id=chrtpm,path=/tmp/swtpm-sock \
  -tpmdev emulator,id=tpm0,chardev=chrtpm \
  -device tpm-tis,tpmdev=tpm0 \
  ...
```

## Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| "TPM not found" | No TPM device | Check /dev/tpmrm0 exists |
| "Permission denied" | Insufficient permissions | Add user to tss group |
| "TPM in lockout" | Too many auth failures | Wait or clear lockout |
| "Handle exists" | Key already provisioned | Use `--overwrite` (seal, iak, idevid, ldevid) or a different handle |

### Verify TPM Access

```bash
# Check TPM device
ls -la /dev/tpmrm0

# Check TPM group membership
groups $(whoami)

# Add user to tss group
sudo usermod -aG tss $(whoami)
```

### Reset TPM Lockout

```bash
# Clear the TPM (requires owner authorization)
platformctl tpm clear --owner-password <password> --confirm

# Force UEFI clear (requires reboot)
platformctl tpm clear --force --confirm
```

## Security Recommendations

### Production Configuration

```yaml
tpm:
  # Use hardware TPM
  device: /dev/tpmrm0
  simulator: false

  # Encrypt TPM command sessions
  encrypt-sessions: true

  # Use TPM as entropy source
  entropy: true

  # PCR configuration - bind to Secure Boot and kernel
  platform-pcr: 23
  platform-pcr-bank: sha256
  golden-pcrs: [0, 1, 2, 3, 7, 8, 9, 11]

  # Platform SRK with platform policy
  platform-srk:
    srk-handle: 0x81000002
    srk-auth: "kms://tpm/platform-srk/srk-auth?ensure=true&len=32&enc=raw"
    platform-policy: true
```

### Key Storage

- Store EK and SRK as persistent keys
- Use PCR policies for sealed objects
- Rotate application keys periodically
- Back up TPM-sealed recovery keys

### Access Control

- Restrict /dev/tpmrm0 access via udev rules
- Use hierarchy passwords
- Implement lockout policies
- Audit TPM operations

## Provisioning

This section describes the provisioning approach used by the Trusted Platform.

### Authorization Implementation

The Trusted Platform uses the "less complex" implementation mentioned in Section 7.2.2 - Implementation Options - from the TCG TPM 2.0 Keys for Device Identity and Attestation specification.

This approach provides a balance between security and operational complexity suitable for most deployments.

### Alternative Implementations

**Most Complex Implementation:**
An enterprise may safely configure the TPM per the "most complex" implementation option using a Delegation Policy following provisioning. This can be done using the TSS command line tools.

**Simplest Implementation:**
The "simplest implementation" may also be safely implemented by the Platform Administrator or Owner following provisioning using the same TSS command line tools.

### Provisioning Steps

1. **Check TPM Availability**
   ```bash
   platformctl tpm info
   ```

2. **Provision TPM with Platform Keys**
   ```bash
   platformctl tpm provision
   ```

3. **Verify Key Hierarchy**
   ```bash
   platformctl tpm ek info
   platformctl tpm srk info
   ```

## Related Documentation

- [README](README.md) - TPM module overview
- [Architecture](architecture.md) - TPM integration architecture
- [CLI Usage](cli-usage.md) - Command-line reference
- [Sealing](sealing.md) - PCR-based data protection
- [Attestation](attestation.md) - Quote operations
- [PCRs](pcrs.md) - Platform Configuration Register reference
- [Security](security.md) - Security considerations and CVEs

## References

### TCG Specifications

- [TCG TPM 2.0 Provisioning Guidance](https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf)
- [TPM 2.0 Keys for Device Identity and Attestation](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf)
- [TCG OID Registry](https://trustedcomputinggroup.org/wp-content/uploads/TCG-OID-Registry-Version-1.00-Revision-0.74_10July24.pdf)

### Standards

- [OPC UA Device Onboarding](https://reference.opcfoundation.org/Onboarding/v105/docs/5.1)
- [ACME Device Attestation Draft](https://datatracker.ietf.org/doc/html/draft-acme-device-attest-03)
