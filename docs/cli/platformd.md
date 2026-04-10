# platformd Reference

`platformd` is the Trusted Platform daemon providing TPM, Certificate Authority, and platform services. It uses a Trusted Platform Module, Secure Boot, and Certificate Authority to establish a Platform Root of Trust.

## Synopsis

```
platformd [command] [options]
```

## Commands

### serve

Start the platform daemon with all configured services. Web services (REST API, ACME, etc.) are automatically started if the `webservices:` section is defined in the configuration file.

```bash
# Start with default config
platformd serve

# Initialize and start
platformd serve --init

# Start with PINs
platformd serve --so-pin --pin

# Debug mode
platformd serve --debug
```

When web services are configured, the server provides:
- REST API endpoints
- Swagger/OpenAPI documentation at `/swagger`
- ACME server (RFC 8555) for certificate management
- Static file hosting

### api

Start the REST API gateway server. Runs as non-root and communicates with platformd via Unix socket.

```bash
# Start with defaults
platformd api

# Custom port and TLS
platformd api --port 8443 --tls-cert /path/to/cert --tls-key /path/to/key

# Enable mTLS
platformd api --mtls --tls-ca /path/to/ca.crt
```

| Option | Description |
|--------|-------------|
| `--host` | Listen address (default: 0.0.0.0) |
| `--port` | Listen port (default: 8443) |
| `--socket` | Path to platformd Unix socket |
| `--tls` | Enable HTTPS/TLS (default: true) |
| `--tls-cert` | TLS certificate file |
| `--tls-key` | TLS private key file |
| `--tls-ca` | CA certificate for client verification |
| `--tls-min-version` | Minimum TLS version (default: 1.3) |
| `--mtls` | Enable mutual TLS |
| `--mtls-verify` | Verify client certificates (default: true) |
| `--base-path` | API base path (default: /api/v1) |
| `--cors` | Enable CORS support |
| `--log-requests` | Log HTTP requests (default: true) |

### status

Display Trusted Platform status including TPM keys, certificates, and services.

```bash
platformd status
```

Shows:
- TPM information
- Endorsement Key (EK)
- EK Certificate
- Shared Storage Root Key (SSRK)
- Initial Attestation Key (IAK)
- Initial Device ID (IDevID)

### config

Platform configuration management.

#### config gen

Generate platform configuration file.

```bash
# Generate server config
platformd config gen --type server --hostname myhost --public-domain example.com

# Generate client config
platformd config gen --type client

# Dry run (print to stdout)
platformd config gen --dry-run
```

| Option | Description |
|--------|-------------|
| `--type` | Configuration type: server or client |
| `--hostname` | Hostname (auto-detected if not set) |
| `--public-domain` | Public domain name |
| `--internal-domain` | Internal domain (default: internal) |
| `--platform-dir` | Platform data directory |
| `--config-dir` | Configuration directory |
| `--ca-dir` | CA data directory |
| `--log-dir` | Log directory |
| `--fips` | Enable FIPS mode (default: true) |
| `--dry-run` | Print config instead of writing |
| `--output` | Output file path |

### ca

Certificate Authority operations.

#### ca init

Initialize the Certificate Authority.

```bash
platformd ca init --so-pin --pin
```

#### ca info

Display CA information.

```bash
platformd ca info
```

#### ca issue

Issue a new certificate.

```bash
platformd ca issue --cn example.com --sans-dns www.example.com
```

| Option | Description |
|--------|-------------|
| `--sans-dns` | Comma-separated DNS SANs |
| `--sans-ips` | Comma-separated IP SANs |
| `--sans-emails` | Comma-separated email SANs |
| `--key-size` | RSA key size in bits |
| `--ecc-curve` | ECC curve: P-256, P-384, P-521 |

#### ca revoke

Revoke a certificate.

```bash
platformd ca revoke --serial 12345
```

#### ca certificate

Display certificate details.

```bash
platformd ca certificate --serial 12345
```

#### ca export-bundle

Export CA certificate bundle.

```bash
platformd ca export-bundle --output ca-bundle.pem
```

#### ca install

Install CA certificates to system trust store.

```bash
platformd ca install
```

#### ca uninstall

Remove CA certificates from system trust store.

```bash
platformd ca uninstall
```

### tpm

Trusted Platform Module operations.

#### tpm info

Display TPM information.

```bash
platformd tpm info
```

#### tpm provision

Provision the TPM according to TCG guidance.

```bash
platformd tpm provision --init
```

#### tpm ek

Manage Endorsement Key.

```bash
platformd tpm ek
```

#### tpm srk

Manage Storage Root Key.

```bash
platformd tpm srk
```

#### tpm seal

Seal data to TPM.

```bash
platformd tpm seal --data "secret" --pcrs 0,1,2,3
```

#### tpm unseal

Unseal data from TPM.

```bash
platformd tpm unseal --handle 0x81000001
```

#### tpm clear

Clear TPM (requires platform authorization).

```bash
platformd tpm clear --so-pin
```

#### tpm eventlog

Display TPM event log.

```bash
platformd tpm eventlog
```

### platform

Platform administration operations.

#### platform provision

Provision a new platform.

```bash
platformd platform provision --init --so-pin --pin
```

#### platform install

Install platform components.

```bash
platformd platform install
```

#### platform destroy

Destroy platform data.

```bash
platformd platform destroy --confirm
```

#### platform extend

Extend PCR values.

```bash
platformd platform extend --pcr 14 --data "measurement"
```

#### platform xkms

Manage platform XKMS.

```bash
platformd platform xkms
```

#### platform policy

Manage platform policies.

```bash
platformd platform policy
```

### vtpm

Virtual TPM bundle management for VM deployment.

#### vtpm create

Create a pre-provisioned vTPM bundle.

```bash
platformd vtpm create --hostname vm001.example.com
```

#### vtpm template

Manage vTPM templates.

```bash
# Create template
platformd vtpm template create --id base-vtpm

# List templates
platformd vtpm template list

# Delete template
platformd vtpm template delete --id base-vtpm
```

#### vtpm clone

Clone a vTPM from template.

```bash
platformd vtpm clone --template base-vtpm --hostname vm002.example.com
```

#### vtpm list

List all vTPM bundles.

```bash
platformd vtpm list
```

#### vtpm info

Show vTPM bundle details.

```bash
platformd vtpm info --id bundle-123
```

#### vtpm export

Export vTPM bundle.

```bash
platformd vtpm export bundle-123 -o bundle.vtpm.tar.gz
```

#### vtpm import

Import vTPM bundle.

```bash
platformd vtpm import bundle.vtpm.tar.gz
```

#### vtpm delete

Delete vTPM bundle.

```bash
platformd vtpm delete --id bundle-123
```

### iso (MOVED)

**Note**: ISO commands have been moved to `platformctl`:

| Old Command | New Location |
|-------------|-------------|
| `platformd iso download` | `platformctl iso download` |
| `platformd iso extract` | `platformctl iso extract` |
| `platformd iso customize` | `platformctl iso customize` |
| `platformd iso build` | `platformctl iso build` |
| `platformd iso create` | `platformctl iso create` |
| `platformd iso profile` | `platformctl iso profile` |
| `platformd iso test` | `platformctl iso test` |

See [platformctl.md](platformctl.md) for ISO command documentation.

### initrd (MOVED)

**Note**: Initramfs commands have been moved to dedicated binaries:

| Old Command | New Location | Binary |
|-------------|-------------|--------|
| `platformd initrd boot` | `platform-initrd boot` | platform-initrd |
| `platformd initrd recovery` | `platform-initrd recovery` | platform-initrd |
| `platformd initrd firstboot` | `platformctl firstboot` | platformctl |
| `platformd initrd system-install` | `platformctl install system` | platformctl |
| `platformd initrd build-uki` | `platformctl install uki` | platformctl |
| `platformd initrd wipe` | `platformctl wipe` | platformctl |

See [platform-initrd.md](platform-initrd.md) for initrd boot commands and [platformctl.md](platformctl.md) for firstboot and installation commands.

### fido2

FIDO2 security key operations for LUKS.

#### fido2 enroll

Enroll a FIDO2 key for LUKS unlock.

```bash
platformd fido2 enroll --device /dev/sda2
```

#### fido2 test

Test FIDO2 unlock.

```bash
platformd fido2 test --device /dev/sda2
```

#### fido2 list

List enrolled FIDO2 tokens.

```bash
platformd fido2 list --device /dev/sda2
```

#### fido2 info

Show FIDO2 and LUKS information.

```bash
platformd fido2 info --device /dev/sda2
```

#### fido2 remove

Remove FIDO2 token.

```bash
platformd fido2 remove --device /dev/sda2 --slot 1
```

### authenticode

Authenticode PE/COFF signing for UEFI Secure Boot.

#### authenticode sign

Sign a PE/COFF file.

```bash
platformd authenticode sign \
  --key db.key \
  --cert db.crt \
  --input boot.efi \
  --output boot-signed.efi
```

#### authenticode verify

Verify an Authenticode signature.

```bash
platformd authenticode verify --input boot-signed.efi
```

### pkcs11

PKCS#11 token operations (requires pkcs11 build tag).

```bash
# Use YubiKey
platformd pkcs11 --ykcs11 --so-pin --pin

# Use SoftHSM2
platformd pkcs11 --softhsm2 --slot 0 --label mytoken

# Use OpenSC
platformd pkcs11 --opensc --module /path/to/module.so
```

| Option | Description |
|--------|-------------|
| `--module`, `-m` | PKCS#11 module path |
| `--label`, `-l` | Token label |
| `--slot`, `-s` | Token slot |
| `--ykcs11` | Use YubiKey PKCS#11 module |
| `--softhsm2` | Use SoftHSM2 module |
| `--opensc` | Use OpenSC module |

### ovmf

OVMF/UEFI variable management (requires libvirt build tag).

#### ovmf parse

Parse OVMF variables file.

```bash
platformd ovmf parse /usr/share/OVMF/OVMF_VARS_4M.fd
platformd ovmf parse --json
```

## Global Options

| Option | Short | Description |
|--------|-------|-------------|
| `--help` | `-h` | Display help |
| `--debug` | `-d` | Enable debug mode |
| `--debug-secrets` | | Include secrets in logs |
| `--env` | `-e` | Environment (dev, staging, prod) |
| `--platform-dir` | | Platform data directory |
| `--config-dir` | | Configuration directory |
| `--config` | `-c` | Path to specific config file |
| `--log-dir` | | Log files directory |
| `--ca-dir` | | CA data directory |
| `--setuid` | | Run as specified user |
| `--intermediate` | | Target CA index (default: 1) |
| `--so-pin` | | Prompt for Security Officer PIN |
| `--pin` | | Prompt for user PIN |
| `--raw-so-pin` | | Plain-text SO PIN (automation) |
| `--raw-pin` | | Plain-text user PIN (automation) |
| `--init` | | Initialize platform on startup |

## Environment Variables

Configuration can also be set via environment variables (uppercase with underscores):

```bash
export PLATFORMD_DEBUG=true
export PLATFORMD_PLATFORM_DIR=/var/lib/platformd
export PLATFORMD_CONFIG_DIR=/etc/platformd
```

## Examples

### Initial Platform Setup

```bash
# Generate configuration
platformd config gen \
  --type server \
  --hostname server01 \
  --public-domain example.com \
  --output /etc/platformd/config.yaml

# Provision TPM and CA
platformd platform provision --init --so-pin --pin

# Start the platform
platformd serve --so-pin --pin
```

### Certificate Management

```bash
# Issue certificate
platformd ca issue \
  --cn app.example.com \
  --sans-dns app.example.com,www.app.example.com \
  --sans-ips 192.168.1.100

# View certificate
platformd ca certificate --serial 12345

# Revoke certificate
platformd ca revoke --serial 12345
```

### Create Installation ISO

```bash
# Build static binary
make build-static

# Create ISO (using platformctl)
platformctl iso create \
  --platformd-binary ./platformd-static \
  --output platform-installer.iso

# Test in QEMU
platformctl iso test install --iso platform-installer.iso
```

### Virtual TPM Provisioning

```bash
# Create template
platformd vtpm template create --id production-base

# Clone for VM
platformd vtpm clone \
  --template production-base \
  --hostname vm-web-01.example.com

# Export for distribution
platformd vtpm export vm-web-01 -o vm-web-01.vtpm.tar.gz
```

## See Also

- [platformctl Reference](platformctl.md)
- [CLI Overview](README.md)
- [Man Pages](../man/)
