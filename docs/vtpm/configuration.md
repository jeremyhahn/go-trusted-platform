# vTPM Configuration

## Configuration File

Add the `vtpm` section to your platform configuration file:

```yaml
# config.yaml
vtpm:
  base-dir: /var/lib/trusted-platform/vtpm
  ovmf-code: /usr/share/OVMF/OVMF_CODE_4M.fd
  ovmf-code-secure: /usr/share/OVMF/OVMF_CODE_4M.secboot.fd
  ovmf-vars: /usr/share/OVMF/OVMF_VARS_4M.fd
  pcr-banks:
    - sha256
  secure-boot-key-size: 2048
  secure-boot-valid-years: 10
  secure-boot-common-name: "Trusted Platform"
  secure-boot-organization: "Trusted Platform"
  ek-algorithm: RSA
  debug: false
```

## Configuration Options

### Base Directory

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `base-dir` | string | `/var/lib/trusted-platform/vtpm` | Base directory for bundles and templates |

Directory structure:
```
{base-dir}/
├── bundles/      # Pre-assigned bundles
└── templates/    # Template images
```

### OVMF Firmware

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `ovmf-code` | string | `/usr/share/OVMF/OVMF_CODE_4M.fd` | UEFI firmware code |
| `ovmf-code-secure` | string | `/usr/share/OVMF/OVMF_CODE_4M.secboot.fd` | Secure Boot firmware |
| `ovmf-vars` | string | `/usr/share/OVMF/OVMF_VARS_4M.fd` | NVRAM template |

**Notes:**
- `ovmf-code` is used when Secure Boot is disabled
- `ovmf-code-secure` is used when Secure Boot is enabled
- `ovmf-vars` is copied for each bundle's NVRAM

### PCR Banks

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `pcr-banks` | []string | `["sha256"]` | PCR hash algorithms |

Supported values:
- `sha1` - SHA-1 (legacy, not recommended)
- `sha256` - SHA-256 (recommended)
- `sha384` - SHA-384
- `sha512` - SHA-512

### Secure Boot Keys

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `secure-boot-keys-dir` | string | (none) | Existing keys directory |
| `secure-boot-key-size` | int | `2048` | RSA key size in bits |
| `secure-boot-valid-years` | int | `10` | Certificate validity |
| `secure-boot-common-name` | string | `"Trusted Platform"` | Certificate CN prefix |
| `secure-boot-organization` | string | `"Trusted Platform"` | Certificate organization |

**Key Size Requirements:**
- Minimum: 2048 bits
- Recommended: 2048 or 4096 bits

**Using Existing Keys:**

If `secure-boot-keys-dir` is specified, the service uses existing keys instead of generating new ones:

```
{secure-boot-keys-dir}/
├── PK.key
├── PK.crt
├── KEK.key
├── KEK.crt
├── DB.key
└── DB.crt
```

### EK Algorithm

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `ek-algorithm` | string | `RSA` | Default EK key algorithm |

Values:
- `RSA` - RSA 2048-bit (widest compatibility)
- `ECC` - ECC P-256 (smaller certificates)

### Debug Mode

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `debug` | bool | `false` | Enable debug output |

## Environment Variables

Configuration can be overridden with environment variables:

| Variable | Configuration Option |
|----------|---------------------|
| `VTPM_BASE_DIR` | `base-dir` |
| `VTPM_OVMF_CODE` | `ovmf-code` |
| `VTPM_OVMF_CODE_SECURE` | `ovmf-code-secure` |
| `VTPM_OVMF_VARS` | `ovmf-vars` |
| `VTPM_EK_ALGORITHM` | `ek-algorithm` |
| `VTPM_DEBUG` | `debug` |

## Example Configurations

### Development

```yaml
vtpm:
  base-dir: ./trusted-data/vtpm
  ovmf-code: /usr/share/OVMF/OVMF_CODE_4M.fd
  ovmf-vars: /usr/share/OVMF/OVMF_VARS_4M.fd
  pcr-banks:
    - sha256
  ek-algorithm: RSA
  debug: true
```

### Production

```yaml
vtpm:
  base-dir: /var/lib/trusted-platform/vtpm
  ovmf-code: /usr/share/OVMF/OVMF_CODE_4M.fd
  ovmf-code-secure: /usr/share/OVMF/OVMF_CODE_4M.secboot.fd
  ovmf-vars: /usr/share/OVMF/OVMF_VARS_4M.fd
  pcr-banks:
    - sha256
    - sha384
  secure-boot-key-size: 4096
  secure-boot-valid-years: 5
  secure-boot-common-name: "ACME Corp"
  secure-boot-organization: "ACME Corporation"
  ek-algorithm: RSA
  debug: false
```

### Shared Secure Boot Keys

```yaml
vtpm:
  base-dir: /var/lib/trusted-platform/vtpm
  ovmf-code: /usr/share/OVMF/OVMF_CODE_4M.fd
  ovmf-code-secure: /usr/share/OVMF/OVMF_CODE_4M.secboot.fd
  ovmf-vars: /usr/share/OVMF/OVMF_VARS_4M.fd
  secure-boot-keys-dir: /etc/trusted-platform/secureboot
  ek-algorithm: RSA
```

## Programmatic Configuration

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"

// Start with defaults
config := vtpm.DefaultConfig()

// Customize
config.BaseDir = "/opt/vtpm"
config.SecureBootKeySize = 4096
config.EKAlgorithm = vtpm.EKAlgorithmECC

// Apply remaining defaults
config.ApplyDefaults()

// Validate
if err := config.Validate(); err != nil {
    log.Fatal(err)
}
```

## Default Configuration

```go
func DefaultConfig() *Config {
    return &Config{
        BaseDir:                "/var/lib/trusted-platform/vtpm",
        OVMFCode:               "/usr/share/OVMF/OVMF_CODE_4M.fd",
        OVMFCodeSecure:         "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
        OVMFVars:               "/usr/share/OVMF/OVMF_VARS_4M.fd",
        PCRBanks:               []string{"sha256"},
        SecureBootKeySize:      2048,
        SecureBootValidYears:   10,
        SecureBootCommonName:   "Trusted Platform",
        SecureBootOrganization: "Trusted Platform",
        EKAlgorithm:            EKAlgorithmRSA,
        Debug:                  false,
    }
}
```

## Validation Rules

The configuration is validated before service initialization:

| Field | Requirement |
|-------|-------------|
| `BaseDir` | Cannot be empty |
| `OVMFCode` | Cannot be empty, file must exist |
| `OVMFVars` | Cannot be empty, file must exist |
| `OVMFCodeSecure` | If specified, file must exist |
| `PCRBanks` | At least one valid bank required |
| `SecureBootKeySize` | Must be at least 2048 |
| `EKAlgorithm` | Must be "RSA" or "ECC"; a request may use any case, anything else is `ErrInvalidEKAlgorithm` |
| `SecureBootKeysDir` | If specified, directory must exist |

## Dependencies

Ensure the following packages are installed:

### Debian/Ubuntu

```bash
apt install ovmf swtpm swtpm-tools
```

### RHEL/CentOS

```bash
dnf install edk2-ovmf swtpm swtpm-tools
```

### Alpine

```bash
apk add ovmf swtpm
```

## Directory Permissions

```bash
# Create base directory
mkdir -p /var/lib/trusted-platform/vtpm
chown platformd:platformd /var/lib/trusted-platform/vtpm
chmod 750 /var/lib/trusted-platform/vtpm
```
