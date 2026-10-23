# UEFI Package Documentation

> **Status: REFERENCE** · Last verified: 2026-10-15
> The UEFI NVRAM and key-enrollment package `pkg/uefi`.

Native Go implementation for UEFI firmware operations including NVRAM manipulation, Secure Boot key enrollment, and EFI Signature List (ESL) encoding.

## Overview

The `pkg/uefi` package provides pure Go support for UEFI data structures and operations. It enables native enrollment of Secure Boot keys into OVMF NVRAM files without external dependencies like `virt-fw-vars` or `efitools`.

**Key Capabilities:**
- UEFI GUID handling with well-known GUIDs
- EFI Signature List (ESL) encoding and decoding
- Firmware Volume parsing (OVMF_VARS.fd)
- Variable Store manipulation
- Secure Boot key enrollment (PK, KEK, db, dbx)
- Platform information storage

## Features

| Feature | Description |
|---------|-------------|
| **GUID Management** | Parse, generate, and serialize 128-bit UUIDs in UEFI format |
| **ESL Encoding** | Create signature lists from X.509 certificates or hashes |
| **ESL Decoding** | Parse existing signature lists from binary data |
| **NVRAM Parsing** | Read OVMF firmware volume and variable store structures |
| **Variable Access** | Get, set, list, and delete UEFI variables |
| **Key Enrollment** | Automated Secure Boot key enrollment (PK, KEK, db) |
| **Platform Info** | Store/retrieve platform identification in NVRAM |
| **Status Checking** | Query Secure Boot and Setup Mode status |

## Key Hierarchy

UEFI Secure Boot uses a hierarchical trust model where each key authorizes the next level:

```
                    +------------------+
                    |  Platform Key    |
                    |      (PK)        |
                    +--------+---------+
                             |
                             | Authorizes updates to
                             v
                    +------------------+
                    | Key Exchange Key |
                    |      (KEK)       |
                    +--------+---------+
                             |
                             | Authorizes updates to
                             v
              +------------------------------+
              |                              |
              v                              v
     +----------------+            +------------------+
     | Signature DB   |            | Forbidden Sig DB |
     |     (db)       |            |      (dbx)       |
     +-------+--------+            +------------------+
             |                              |
             | Contains trusted             | Contains revoked
             | certificates/hashes          | certificates/hashes
             v                              v
     +----------------+            +------------------+
     | Signed EFI     |            | Blocked EFI      |
     | Binaries       |            | Binaries         |
     +----------------+            +------------------+
```

**Key Descriptions:**

| Key | GUID | Purpose |
|-----|------|---------|
| **PK** | EFI Global Variable | Root of trust, controls KEK updates |
| **KEK** | EFI Global Variable | Controls db/dbx updates |
| **db** | Image Security Database | Trusted signing certificates/hashes |
| **dbx** | Image Security Database | Revoked/forbidden certificates/hashes |

## EFI Signature List (ESL) Format

The ESL format is used to store collections of signatures (certificates or hashes) in UEFI variables.

### ESL Structure

```
+---------------------------+
| EFI_SIGNATURE_LIST Header |  28 bytes
+---------------------------+
| SignatureType    (GUID)   |  16 bytes - Type of signatures
| SignatureListSize (u32)   |   4 bytes - Total list size
| SignatureHeaderSize (u32) |   4 bytes - Optional header size
| SignatureSize     (u32)   |   4 bytes - Size of each signature
+---------------------------+
| Optional Header           |  SignatureHeaderSize bytes
+---------------------------+
| EFI_SIGNATURE_DATA[]      |  Variable (repeated)
+---------------------------+

EFI_SIGNATURE_DATA:
+---------------------------+
| SignatureOwner (GUID)     |  16 bytes - Owner identifier
| SignatureData  (bytes)    |  Variable - Certificate or hash
+---------------------------+
```

### Signature Type GUIDs

| Type | GUID | Data Size |
|------|------|-----------|
| X.509 Certificate | `A5C059A1-94E4-4AA7-87B5-AB155C2BF072` | Variable |
| X.509 SHA-256 (`EFIX509SHA256`) | `3BD2A492-96C0-4079-B420-FCF98EF103ED` | 48 bytes |
| SHA-256 Hash | `C1C41626-504C-4092-ACA9-41F936934328` | 32 bytes |
| SHA-384 Hash | `FF3E5307-9FD0-48C9-85F1-8AD56C701E01` | 48 bytes |
| SHA-512 Hash | `093E0FAE-A6C4-4F50-9F1B-D41E2B89C19A` | 64 bytes |
| RSA-2048 | `3C5766E8-269C-4E34-AA14-ED776E85B3B6` | 256 bytes |
| PKCS#7 | `4AAFD29D-68DF-49EE-8AA9-347D375665A7` | Variable |

### Creating Signature Lists

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/uefi"

// Create ESL from X.509 certificate (DER-encoded)
certDER, _ := os.ReadFile("cert.der")
ownerGUID := uefi.NewGUID()
esl := uefi.NewSignatureListFromCert(certDER, ownerGUID)

// Create ESL from SHA-256 hash
hash := sha256.Sum256(data)
hashESL := uefi.NewSignatureListFromHash(hash[:], uefi.EFISHA256, ownerGUID)

// Serialize to binary
eslBytes := esl.Bytes()

// Concatenate multiple lists into one []byte
combined := uefi.ConcatSignatureLists(esl1, esl2, esl3)
```

### Parsing Signature Lists

```go
// Parse single signature list
esl, bytesRead, err := uefi.ParseSignatureList(data)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Type: %s\n", esl.SignatureType.String())
fmt.Printf("Signatures: %d\n", esl.SignatureCount())
fmt.Printf("Is X.509: %v\n", esl.IsX509())

// Parse concatenated lists
lists, err := uefi.ParseSignatureLists(data)
for _, list := range lists {
    fmt.Printf("List with %d signatures\n", list.SignatureCount())
}
```

## NVRAM Manipulation

The NVRAM component provides read/write access to OVMF firmware variable stores.

### Opening NVRAM Files

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/uefi"

// Open existing NVRAM file
nvram, err := uefi.OpenNVRAM("/path/to/OVMF_VARS.fd")
if err != nil {
    log.Fatal(err)
}

// Parse from byte slice
data, _ := os.ReadFile("/path/to/OVMF_VARS.fd")
nvram, err := uefi.ParseNVRAM(data, "/path/to/OVMF_VARS.fd")
```

### Variable Operations

```go
// List all variables
vars := nvram.ListVariables()
for _, v := range vars {
    fmt.Printf("Name: %s, GUID: %s, Size: %d\n",
        v.Name, v.GUID.String(), len(v.Data))
}

// Get specific variable
pk, err := nvram.GetVariable("PK", uefi.EFIGlobalVariable)
if err == uefi.ErrVariableNotFound {
    fmt.Println("PK not enrolled")
}

// Set variable
attrs := uefi.AttrNonVolatile |
         uefi.AttrBootserviceAccess |
         uefi.AttrRuntimeAccess
err = nvram.SetVariable("MyVar", uefi.TrustedPlatformGUID, attrs, data)

// Delete variable
err = nvram.DeleteVariable("MyVar", uefi.TrustedPlatformGUID)

// Save changes
err = nvram.Save()          // Save to original path
err = nvram.SaveTo(newPath) // Save to new path
```

### Variable Attributes

| Constant | Value | Description |
|----------|-------|-------------|
| `AttrNonVolatile` | 0x01 | Persists across power cycles |
| `AttrBootserviceAccess` | 0x02 | Accessible during boot services |
| `AttrRuntimeAccess` | 0x04 | Accessible during runtime |
| `AttrHardwareErrorRecord` | 0x08 | Hardware error record |
| `AttrAuthenticatedWriteAccess` | 0x10 | Count-based authentication (deprecated in UEFI) |
| `AttrTimeBasedAuthWriteAccess` | 0x20 | Time-based authentication |
| `AttrAppendWrite` | 0x40 | Append to existing data |

**Standard combinations:**
```go
// Secure Boot variables (PK, KEK, db, dbx)
uefi.SecureBootAttributes // NV | BS | RT | TIME_BASED_AUTH

// Runtime-accessible variables
attrs := uefi.AttrNonVolatile |
         uefi.AttrBootserviceAccess |
         uefi.AttrRuntimeAccess
```

## Secure Boot Key Enrollment

The `SecureBootEnroller` provides high-level API for automated key enrollment.

### Configuration

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/uefi"

config := &uefi.SecureBootEnrollerConfig{
    // Path to NVRAM file (will be created if needed)
    NVRAMPath: "/path/to/OVMF_VARS.fd",

    // Directory containing PK.crt, KEK.crt, DB.crt
    KeysDir: "/path/to/keys",

    // Optional: template NVRAM file; when empty, the common OVMF
    // locations under /usr/share are tried
    TemplatePath: "/usr/share/OVMF/OVMF_VARS_4M.fd",

    // Optional: owner GUID (auto-generated if nil)
    OwnerGUID: nil,
}

enroller, err := uefi.NewSecureBootEnroller(config, logger)
```

### Key Enrollment

```go
// Enroll all Secure Boot keys
err := enroller.EnrollKeys(ctx)
if err != nil {
    log.Fatalf("Failed to enroll keys: %v", err)
}

// This performs:
// 1. Initialize NVRAM from template (if needed)
// 2. Load PK.crt, KEK.crt, DB.crt from KeysDir (PEM or DER)
// 3. Create ESL structures for each certificate
// 4. Set PK, KEK, db variables (SecureBootAttributes)
// 5. Save NVRAM
```

`SecureBoot` and `SetupMode` are not written. The firmware derives them at
every boot from PK presence (PK present means User Mode with Secure Boot on),
so enrolling PK is what turns Secure Boot on (`pkg/uefi/enrollment.go`).
`GetEnrollmentStatus` applies the same rule and prefers a stored value only
when the store has one.

### Checking Enrollment Status

```go
status, err := enroller.GetEnrollmentStatus()
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Secure Boot: %v\n", status.SecureBootEnabled)
fmt.Printf("Setup Mode: %v\n", status.SetupMode)
fmt.Printf("PK enrolled: %v\n", status.HasPK)
fmt.Printf("KEK enrolled: %v\n", status.HasKEK)
fmt.Printf("db enrolled: %v\n", status.HasDB)
fmt.Printf("dbx enrolled: %v\n", status.HasDBX)
fmt.Printf("All keys enrolled: %v\n", status.KeysEnrolled)

// Human-readable status
fmt.Println(status.String())
// Output: SecureBoot: enabled, Mode: User Mode, PK: true, KEK: true, db: true, dbx: false
```

## Platform Information Storage

Store platform identification data in NVRAM for boot-time verification.

### Setting Platform Info

```go
info := &uefi.PlatformInfo{
    Version:   "1.0.0",
    BuildDate: "2025-01-15T12:00:00Z",
    GitCommit: "abc123def",
}

err := enroller.SetPlatformInfo(ctx, info) // Version is required
// Stores: "1.0.0|2025-01-15T12:00:00Z|abc123def"
// Variable: TRUSTED_PLATFORM
// GUID: F47E4B3D-8C21-4A9F-B6E5-1D2C3E4F5A6B
```

### Reading Platform Info

```go
info, err := enroller.GetPlatformInfo()
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Version: %s\n", info.Version)
fmt.Printf("Build: %s\n", info.BuildDate)
fmt.Printf("Commit: %s\n", info.GitCommit)
```

### Combined Enrollment with Platform Info

```go
info := &uefi.PlatformInfo{Version: "1.0.0"}
err := enroller.EnrollKeysWithPlatformInfo(ctx, info)
// Enrolls keys AND sets platform info in one operation
```

## Usage Examples

### Complete Key Enrollment Workflow

```go
package main

import (
    "context"
    "log"

    "github.com/jeremyhahn/go-trusted-platform/pkg/logging"
    "github.com/jeremyhahn/go-trusted-platform/pkg/uefi"
)

func main() {
    ctx := context.Background()
    logger := logging.DefaultLogger()

    // Configure enroller
    config := &uefi.SecureBootEnrollerConfig{
        NVRAMPath:    "./work/nvram/OVMF_VARS.fd",
        KeysDir:      "./work/secure-boot-keys",
        TemplatePath: "/usr/share/OVMF/OVMF_VARS_4M.fd",
    }

    enroller, err := uefi.NewSecureBootEnroller(config, logger)
    if err != nil {
        log.Fatal(err)
    }

    // Enroll keys with platform info
    info := &uefi.PlatformInfo{
        Version:   "1.0.0",
        BuildDate: "2025-01-15",
        GitCommit: "abc123",
    }

    if err := enroller.EnrollKeysWithPlatformInfo(ctx, info); err != nil {
        log.Fatal(err)
    }

    // Verify enrollment
    status, _ := enroller.GetEnrollmentStatus()
    log.Printf("Enrollment status: %s", status.String())
}
```

### Manual NVRAM Manipulation

```go
package main

import (
    "crypto/x509"
    "log"
    "os"

    "github.com/jeremyhahn/go-trusted-platform/pkg/uefi"
)

func main() {
    // Open NVRAM
    nvram, err := uefi.OpenNVRAM("./OVMF_VARS.fd")
    if err != nil {
        log.Fatal(err)
    }

    // Load certificate (DER)
    certData, _ := os.ReadFile("./DB.crt")
    cert, _ := x509.ParseCertificate(certData)

    // Create signature list
    ownerGUID := uefi.NewGUID()
    esl := uefi.NewSignatureListFromCert(cert.Raw, ownerGUID)

    // Set db variable
    err = nvram.SetVariable("db",
        uefi.EFIImageSecurityDatabase,
        uefi.SecureBootAttributes,
        esl.Bytes())
    if err != nil {
        log.Fatal(err)
    }

    // Save
    if err := nvram.Save(); err != nil {
        log.Fatal(err)
    }
}
```

### GUID Operations

```go
// Generate random GUID
guid := uefi.NewGUID()
fmt.Println(guid.String()) // upper-case 8-4-4-4-12 form

// Parse GUID from string
guid, err := uefi.ParseGUID("8BE4DF61-93CA-11D2-AA0D-00E098032B8C")

// Parse with braces
guid, _ = uefi.ParseGUID("{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}")

// Convert to bytes (mixed-endian UEFI format)
bytes := guid.Bytes() // 16 bytes

// Create from bytes
guid, err = uefi.GUIDFromBytes(bytes)

// Compare GUIDs
if guid.Equal(uefi.EFIGlobalVariable) {
    fmt.Println("Is EFI Global Variable GUID")
}

// Check if zero
if guid.IsZero() {
    fmt.Println("GUID is all zeros")
}
```

## Live System (efivarfs)

On a running UEFI system the package reads and writes the firmware variables
through efivarfs (`EfivarsPath`, default `/sys/firmware/efi/efivars`):

| Function | Purpose |
|----------|---------|
| `EfivarsAvailable`, `IsSetupMode`, `SecureBootEnabled` | Firmware state checks |
| `ReadSecureBootStatus`, `ReadDBCertificates` | Read the Secure Boot state and the db certificates |
| `EnrollKeysToEfivars(ctx, pk, kek, db, ts)` | Enroll in the order db, KEK, PK (PK last); refuses with `ErrEfivarsUnavailable` or `ErrNotSetupMode` |
| `VerifySignedUKI(verifier, ukiPath, dbCert, logger)` | Check the UKI is signed by exactly `dbCert` before PK is enrolled |

The `...FromDir` / `...Dir` variants take the efivars directory as an argument.

## Error Handling

The package defines typed errors for robust error handling:

```go
var (
    uefi.ErrInvalidFormat     // Invalid data format
    uefi.ErrInvalidGUID       // Invalid GUID
    uefi.ErrInvalidSignature  // Invalid signature in header
    uefi.ErrInvalidChecksum   // Checksum mismatch
    uefi.ErrVariableNotFound  // Variable not found
    uefi.ErrInsufficientSpace // Insufficient space in variable store
    uefi.ErrReadOnly          // Attempt to modify read-only value
)

// Example usage
v, err := nvram.GetVariable("PK", uefi.EFIGlobalVariable)
if errors.Is(err, uefi.ErrVariableNotFound) {
    fmt.Println("Platform Key not enrolled")
}
```

## Well-Known GUIDs

| Variable | GUID | Constant |
|----------|------|----------|
| EFI Global Variable | `8BE4DF61-93CA-11D2-AA0D-00E098032B8C` | `EFIGlobalVariable` |
| Image Security Database | `D719B2CB-3D3A-4596-A3BC-DAD00E67656F` | `EFIImageSecurityDatabase` |
| X.509 Certificate | `A5C059A1-94E4-4AA7-87B5-AB155C2BF072` | `EFIX509Cert` |
| SHA-256 Hash | `C1C41626-504C-4092-ACA9-41F936934328` | `EFISHA256` |
| Trusted Platform | `F47E4B3D-8C21-4A9F-B6E5-1D2C3E4F5A6B` | `TrustedPlatformGUID` |
| FFS2 | `8C8CE578-8A3D-4F1C-9935-896185C32DD3` | `FFS2GUID` |
| FFS3 | `5473C07A-3DCB-4DCA-BD6F-1E9689E7349A` | `FFS3GUID` |
| NVRAM Variable Store | `DDCF3616-3275-4164-98B6-FE85707FFE7D` | `NVRAMVariableStoreGUID` |
| Authenticated Variable | `AAF32C78-947B-439A-A180-2E144EC37792` | `AuthenticatedVariableGUID` |

## Related Documentation

- [Secure Boot](secure-boot.md) - Automated Secure Boot implementation
- [UEFI Secure Boot](uefi-secure-boot.md) - Detailed Secure Boot specification
- [Architecture](architecture.md) - Firmware architecture overview
- [API Reference](api-reference.md) - CLI and API commands
- [Configuration](configuration.md) - Configuration examples

## References

- [UEFI Specification 2.10](https://uefi.org/specs/UEFI/2.10/)
- [UEFI Platform Initialization Specification 1.8](https://uefi.org/specs/PI/1.8/)
- [EDK2 MdeModulePkg](https://github.com/tianocore/edk2/tree/master/MdeModulePkg)
