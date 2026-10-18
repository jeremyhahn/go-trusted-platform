# Authenticode Signing Package

> **Status: REFERENCE** · Last verified: 2026-10-15
> The Authenticode signer in `pkg/authenticode`.

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
| PKCS#7 SignedData | `sbverify` accepts the signatures (`test/integration/secureboot/ovmf_test.go`) |
| Certificate Chain | Embeds full certificate chain in signature |
| PE32/PE32+ Support | Both 32-bit and 64-bit PE formats |
| Signature Verification | Verify existing Authenticode signatures |
| Certificate Extraction | Extract signing certificate from signed binaries |
| RFC3161 Timestamps | Optional TSA countersignature, embedded and verified; a failed stamp fails signing |

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

    // SignFile signs a PE/COFF file and writes the signed output. The output
    // is replaced atomically, so outputPath may equal inputPath.
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
    KeyStore xkmssdk.KeyProvider

    // KeyAttributes identifies which key to use for signing
    KeyAttributes *xkmssdk.KeyAttributes

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

`xkmssdk` is `github.com/jeremyhahn/go-quicbaas/sdk/go/xkms`.

A non-empty `TimestampURL` makes `Sign` request an RFC 3161 countersignature
over the signature from that time-stamp authority. The token must verify and
carry the request's nonce; it is embedded as an unauthenticated attribute, and
`Verify` checks every embedded timestamp. A TSA that cannot stamp returns a
`*TimestampError` and fails the signing.

### Constructor

```go
func NewSigner(ctx context.Context, opts *SignerOptions) (Authenticode, error)
func NewFileSigner(ctx context.Context, keyPath, certPath string, logger *logging.Logger) (Authenticode, error)
func NewCryptoSigner(ctx context.Context, signer crypto.Signer, cert *x509.Certificate, logger *logging.Logger) (Authenticode, error)
func NewVerifier(ctx context.Context, logger *logging.Logger) Authenticode
```

`NewFileSigner` signs with a PEM key and certificate; `NewCryptoSigner` with
any `crypto.Signer`; `NewVerifier` returns a value that only verifies and
extracts. `NewSigner` returns an error if:
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

### Signing with a PEM Key File

```go
import (
    "github.com/jeremyhahn/go-trusted-platform/pkg/authenticode"
)

signer, err := authenticode.NewFileSigner(ctx, "DB.key", "DB.crt", logger)
if err != nil {
    log.Fatal(err)
}

// Sign an EFI binary
err = signer.SignFile("bootx64.efi", "bootx64-signed.efi")
if err != nil {
    log.Fatal(err)
}
```

### Signing with a Keystore Key

```go
import (
    xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
    "github.com/jeremyhahn/go-trusted-platform/pkg/authenticode"
)

// keyStore is any xkmssdk.KeyProvider: a TPM 2.0, PKCS#11 or software
// backend built through the go-quicbaas SDK re-exports.
signer, err := authenticode.NewSigner(ctx, &authenticode.SignerOptions{
    KeyStore:      keyStore,
    KeyAttributes: &xkmssdk.KeyAttributes{CN: "secure-boot-db"},
    Certificate:   dbCert,
    CertChain:     []*x509.Certificate{intermediateCert, rootCert},
    Logger:        logger,
})
if err != nil {
    log.Fatal(err)
}

err = signer.SignFile("grubx64.efi", "grubx64-signed.efi")
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
platformctl authenticode sign \
    --key /path/to/DB.key \
    --cert /path/to/DB.crt \
    --input bootx64.efi \
    --output bootx64-signed.efi

# Verify a signature (--cert is optional)
platformctl authenticode verify \
    --cert /path/to/DB.crt \
    --input bootx64-signed.efi
```

The CLI signs with a PEM key file only (`pkg/cli/commands/authenticode`); it
has no keystore or TPM option.

## Integration with TPM/HSM Key Stores

`NewSigner` signs through any `xkmssdk.KeyProvider`, the go-xkms keystore
surface re-exported by the go-quicbaas SDK, so a hardware-backed key never
leaves the hardware.

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

# UEFI firmware verification
# Happens automatically during Secure Boot
```

## Error Handling

Errors are `*MessageError` and `*WrappedError` (`pkg/authenticode/errors.go`)
carrying the messages below; `NewSigner` returns the keystore ones:

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
- [KMS API Reference](../kms/api.md) - Key management integration
- [TPM CLI Usage](../tpm/cli-usage.md) - TPM key operations
