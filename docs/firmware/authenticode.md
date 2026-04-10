# Authenticode Signing Package

## Overview

The Authenticode package (`pkg/authenticode`) provides native Go implementation of Microsoft Authenticode signing for PE/COFF (Portable Executable) files. This is primarily used for signing EFI binaries to enable UEFI Secure Boot verification.

### What is Authenticode?

Authenticode is Microsoft's code signing technology that embeds PKCS#7/CMS digital signatures directly into PE/COFF executables. For UEFI Secure Boot, the firmware verifies these signatures against enrolled keys before executing bootloaders, drivers, and other EFI applications.

### PE/COFF Signing

PE/COFF (Portable Executable / Common Object File Format) is the executable format used by:

- Windows executables (.exe, .dll)
- UEFI applications (.efi)
- Unified Kernel Images (UKIs)
- UEFI drivers and bootloaders

The signing process:

1. Compute Authenticode digest (hash excluding signature area and checksum)
2. Build SPC_INDIRECT_DATA_CONTENT structure with PE digest
3. Create PKCS#7 SignedData with authenticated attributes
4. Sign the authenticated attributes digest
5. Embed WIN_CERTIFICATE structure in PE security directory

## Features

| Feature | Description |
|---------|-------------|
| Native Go Implementation | No external tool dependencies (sbsigntool, osslsigncode) |
| Hardware Key Support | TPM 2.0, PKCS#11 (HSM), and software keystores |
| RSA and ECDSA | Supports both signature algorithms |
| Full PKCS#7 Compliance | Compatible with sbverify, osslsigncode verification |
| Certificate Chain | Embeds full certificate chain in signature |
| PE32/PE32+ Support | Both 32-bit and 64-bit PE formats |
| Signature Verification | Verify existing Authenticode signatures |
| Certificate Extraction | Extract signing certificate from signed binaries |
| RFC3161 Timestamps | Optional timestamping support (placeholder) |

## Architecture

```
+------------------+     +-------------------+     +------------------+
|   Application    |     |   Authenticode    |     |    Keystore      |
|   (platformd)    |---->|      Signer       |---->|   (Backend)      |
+------------------+     +-------------------+     +------------------+
                                |                         |
                                v                         v
                         +-------------+           +--------------+
                         |  PE Parser  |           |   TPM 2.0    |
                         +-------------+           +--------------+
                                |                         |
                                v                         v
                         +-------------+           +--------------+
                         | PKCS#7/ASN1 |           |  PKCS#11     |
                         |   Builder   |           |   (HSM)      |
                         +-------------+           +--------------+
                                |                         |
                                v                         v
                         +-------------+           +--------------+
                         |  Signed PE  |           |   PKCS#8     |
                         |   Output    |           |  (Software)  |
                         +-------------+           +--------------+
```

### Signing Flow

```
Input PE File
     |
     v
+--------------------+
| 1. Parse PE/COFF   |  <- Extract headers, locate security directory
+--------------------+
     |
     v
+--------------------+
| 2. Compute         |  <- SHA-256 hash excluding checksum and
|    Authenticode    |     security directory sections
|    Digest          |
+--------------------+
     |
     v
+--------------------+
| 3. Build SPC       |  <- Create SpcIndirectDataContent with
|    Content         |     PE digest and algorithm OID
+--------------------+
     |
     v
+--------------------+
| 4. Build Auth      |  <- contentType, signingTime, messageDigest
|    Attributes      |
+--------------------+
     |
     v
+--------------------+
| 5. Sign with       |  <- TPM, HSM, or software key via keystore
|    Keystore        |
+--------------------+
     |
     v
+--------------------+
| 6. Build PKCS#7    |  <- SignedData with certs, signature, content
|    Structure       |
+--------------------+
     |
     v
+--------------------+
| 7. Embed in PE     |  <- WIN_CERTIFICATE in security directory
+--------------------+
     |
     v
Signed PE File
```

## API Reference

### Interface

```go
// Authenticode provides PE/COFF (Windows Authenticode) signing functionality
type Authenticode interface {
    // Sign signs a PE/COFF file with Authenticode signature
    Sign(input io.Reader, output io.Writer) error

    // SignFile signs a PE/COFF file and writes the signed output
    SignFile(inputPath, outputPath string) error

    // Verify verifies an Authenticode signature on a PE/COFF file
    Verify(input io.Reader) error

    // VerifyFile verifies an Authenticode signature on a file
    VerifyFile(path string) error

    // ExtractCertificate extracts the signing certificate from a signed PE/COFF file
    ExtractCertificate(input io.Reader) (*x509.Certificate, error)

    // ExtractCertificateFile extracts the signing certificate from a signed file
    ExtractCertificateFile(path string) (*x509.Certificate, error)
}
```

### SignerOptions

```go
type SignerOptions struct {
    // KeyStore is the keystore backend (TPM, PKCS#11, or PKCS8)
    KeyStore types.Backend

    // KeyAttributes identifies which key to use for signing
    KeyAttributes *types.KeyAttributes

    // Certificate is the code signing certificate
    Certificate *x509.Certificate

    // CertChain is the certificate chain (optional)
    CertChain []*x509.Certificate

    // TimestampURL is the RFC3161 timestamp server URL (optional)
    TimestampURL string

    // Logger for diagnostic output
    Logger *logging.Logger
}
```

### Constructor

```go
func NewSigner(opts *SignerOptions) (Authenticode, error)
```

Creates a new Authenticode signer. Returns an error if:
- KeyStore is nil
- KeyAttributes is nil
- Certificate is nil
- Logger is nil
- Key does not exist in keystore

### Utility Functions

```go
// SigningTime extracts the signing time from a signed PE file
func SigningTime(input io.Reader) (time.Time, error)
```

## Usage Examples

### Basic Signing with Software Key

```go
import (
    "github.com/jeremyhahn/go-trusted-platform/pkg/authenticode"
    xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// Create signer with PKCS#8 software keystore
signer, err := authenticode.NewSigner(&authenticode.SignerOptions{
    KeyStore:      pkcs8Backend,
    KeyAttributes: &xkmssdk.KeyAttributes{CN: "secure-boot-db"},
    Certificate:   dbCert,
    CertChain:     []*x509.Certificate{intermediateCert, rootCert},
    Logger:        logger,
})
if err != nil {
    log.Fatal(err)
}

// Sign an EFI binary
err = signer.SignFile("bootx64.efi", "bootx64-signed.efi")
if err != nil {
    log.Fatal(err)
}
```

### Signing with TPM-Backed Key

```go
import (
    "github.com/jeremyhahn/go-trusted-platform/pkg/authenticode"
    xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// Create TPM backend using SDK
tpmBackend, err := xkmssdk.NewTPM2Backend(&xkmssdk.TPMConfig{
    DevicePath: "/dev/tpmrm0",
})
if err != nil {
    log.Fatal(err)
}

// Create signer with TPM keystore
signer, err := authenticode.NewSigner(&authenticode.SignerOptions{
    KeyStore:      tpmBackend,
    KeyAttributes: &xkmssdk.KeyAttributes{
        CN:          "secure-boot-db",
        KeyType:     xkmssdk.KeyTypeRSA,
        KeySize:     2048,
        StoreType:   xkmssdk.StoreTypeTPM2,
    },
    Certificate:   dbCert,
    Logger:        logger,
})
if err != nil {
    log.Fatal(err)
}

// Sign EFI binary with hardware-protected key
err = signer.SignFile("grubx64.efi", "grubx64-signed.efi")
```

### Signing with PKCS#11 HSM

```go
import (
    "github.com/jeremyhahn/go-trusted-platform/pkg/authenticode"
    xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// Create PKCS#11 backend using SDK
hsmBackend, err := xkmssdk.NewPKCS11Backend(&xkmssdk.PKCS11Config{
    Library: "/usr/lib/softhsm/libsofthsm2.so",
    Slot:    0,
    PIN:     "1234",
})
if err != nil {
    log.Fatal(err)
}

// Create signer with HSM keystore
signer, err := authenticode.NewSigner(&authenticode.SignerOptions{
    KeyStore:      hsmBackend,
    KeyAttributes: &xkmssdk.KeyAttributes{
        CN:        "code-signing-key",
        StoreType: xkmssdk.StoreTypePKCS11,
    },
    Certificate:   signingCert,
    CertChain:     certChain,
    Logger:        logger,
})
if err != nil {
    log.Fatal(err)
}

err = signer.SignFile("shimx64.efi", "shimx64-signed.efi")
```

### Verifying Signatures

```go
// Verify a signed EFI binary
err := signer.VerifyFile("bootx64-signed.efi")
if err != nil {
    log.Printf("Signature verification failed: %v", err)
} else {
    log.Println("Signature verified successfully")
}

// Using io.Reader
file, _ := os.Open("signed.efi")
defer file.Close()

err = signer.Verify(file)
```

### Extracting Certificates

```go
// Extract signing certificate from signed binary
cert, err := signer.ExtractCertificateFile("bootx64-signed.efi")
if err != nil {
    log.Fatal(err)
}

log.Printf("Signed by: %s", cert.Subject.CommonName)
log.Printf("Issuer: %s", cert.Issuer.CommonName)
log.Printf("Valid until: %s", cert.NotAfter)

// Get signing time
file, _ := os.Open("signed.efi")
sigTime, err := authenticode.SigningTime(file)
if err == nil {
    log.Printf("Signed at: %s", sigTime)
}
```

### CLI Usage

```bash
# Sign an EFI binary
platformd authenticode sign \
    --key /path/to/DB.key \
    --cert /path/to/DB.crt \
    --input bootx64.efi \
    --output bootx64-signed.efi

# Verify a signature
platformd authenticode verify \
    --cert /path/to/DB.crt \
    --input bootx64-signed.efi

# Sign with TPM key
platformd authenticode sign \
    --keystore tpm \
    --key-cn secure-boot-db \
    --cert /path/to/DB.crt \
    --input kernel.efi \
    --output kernel-signed.efi
```

## Integration with TPM/HSM Key Stores

The Authenticode package integrates with the go-xkms library to support hardware-backed signing operations. The key never leaves the secure hardware.

### Supported Backends

| Backend | Type | Use Case |
|---------|------|----------|
| TPM 2.0 | Hardware | Server/workstation secure boot signing |
| PKCS#11 | Hardware | HSM-based enterprise signing |
| PKCS#8 | Software | Development and testing |

### Key Management Flow

```
+-------------------+
| Generate Key Pair |  <- In TPM/HSM or import to software store
+-------------------+
         |
         v
+-------------------+
| Issue Certificate |  <- Platform CA issues code signing cert
+-------------------+
         |
         v
+-------------------+
| Configure Signer  |  <- KeyStore + KeyAttributes + Certificate
+-------------------+
         |
         v
+-------------------+
| Sign EFI Binaries |  <- Signing ops use hardware key
+-------------------+
```

### Security Considerations

1. **TPM Keys**: Signing key never leaves TPM; only signature is returned
2. **HSM Keys**: Enterprise-grade hardware security for high-value keys
3. **Key Attestation**: TPM can provide attestation of key properties
4. **Audit Logging**: All signing operations can be logged for compliance

## Verification Compatibility

Signed binaries are compatible with standard verification tools:

```bash
# Verify with sbverify (sbsigntool)
sbverify --cert DB.crt bootx64-signed.efi

# Verify with osslsigncode
osslsigncode verify -CAfile ca-bundle.crt bootx64-signed.efi

# UEFI firmware verification
# Happens automatically during Secure Boot
```

## Error Handling

The package returns typed errors for proper error handling:

```go
err := signer.SignFile(input, output)
if err != nil {
    switch {
    case strings.Contains(err.Error(), "keystore is required"):
        // Missing keystore configuration
    case strings.Contains(err.Error(), "failed to get signer"):
        // Key not found or access denied
    case strings.Contains(err.Error(), "failed to parse PE"):
        // Invalid PE file format
    case strings.Contains(err.Error(), "signature verification failed"):
        // Signature mismatch or corruption
    default:
        // Other error
    }
}
```

## Related Documentation

- [Secure Boot Implementation](secure-boot.md) - Automated Secure Boot with custom keys
- [UEFI Secure Boot](uefi-secure-boot.md) - UEFI Secure Boot concepts
- [Firmware Architecture](architecture.md) - Overall firmware architecture
- [API Reference](api-reference.md) - Firmware CLI commands
- [KMS API Reference](/docs/kms/api-reference.md) - Key management integration
- [TPM CLI Usage](/docs/tpm/cli-usage.md) - TPM key operations
