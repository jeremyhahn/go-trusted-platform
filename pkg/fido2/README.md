# FIDO2 Package

Pure Go implementation of FIDO2 CTAP2 protocol for offline disk encryption unlock using HMAC-secret extension.

## Overview

This package provides offline FIDO2 authentication for LUKS disk encryption without requiring network connectivity or a WebAuthn server. It implements the CTAP2 protocol over USB HID and supports the hmac-secret extension for cryptographic key derivation.

## Features

- **Pure Go Implementation**: No C dependencies for core FIDO2 operations
- **CTAP2 Protocol**: Full implementation of FIDO2 Client-to-Authenticator Protocol
- **USB HID Transport**: Direct USB HID device communication
- **HMAC-Secret Extension**: Key derivation for LUKS unlock
- **Multiple Device Support**: Enumerate and select from available authenticators
- **Retry Logic**: User presence timeout handling with configurable retries
- **CanoKey Workaround**: Handles known CBOR truncation issues
- **Context-Aware**: Proper timeout and cancellation support

## Architecture

```
Handler (fido2.go)
    ├── Authenticator (ctap2.go)
    │   ├── CTAP2 authenticatorGetInfo
    │   ├── CTAP2 authenticatorMakeCredential
    │   └── CTAP2 authenticatorGetAssertion
    ├── HMACSecretExtension (hmac_secret.go)
    │   ├── EnrollCredential
    │   ├── DeriveSecret
    │   └── GenerateLUKSKey
    └── CTAPHIDDevice (device.go)
        ├── HID Packet Framing
        ├── CTAPHID_INIT
        ├── CTAPHID_CBOR
        └── Error Handling
```

## Usage

### Basic Enrollment

```go
import "github.com/jeremyhahn/go-trusted-platform/pkg/fido2"

// Create handler with real HID enumerator
config := fido2.DefaultConfig
handler, err := fido2.NewHandler(&config, realHIDEnumerator)
if err != nil {
    log.Fatal(err)
}
defer handler.Close()

// Enroll a new credential
enrollConfig := fido2.DefaultEnrollmentConfig("username")
result, err := handler.EnrollKey(enrollConfig)
if err != nil {
    log.Fatal(err)
}

// Save credential ID and salt for later use
credentialID := result.CredentialID
salt := result.Salt
```

### Authentication / Unlock

```go
// Authenticate and derive LUKS key
authConfig := fido2.DefaultAuthenticationConfig(credentialID, salt)
luksKey, err := handler.UnlockWithKey(authConfig)
if err != nil {
    log.Fatal(err)
}

// Use luksKey (512-bit) to unlock LUKS volume
// cryptsetup open --key-file=<(echo $luksKey) /dev/sda1 cryptroot
```

### List Devices

```go
devices, err := handler.ListDevices()
if err != nil {
    log.Fatal(err)
}

for _, dev := range devices {
    fmt.Printf("Device: %s (%s %s)\n", dev.Path, dev.Manufacturer, dev.Product)
}
```

### Wait for Device Insertion

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

device, err := handler.WaitForDevice(ctx)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Device inserted: %s\n", device.Path)
```

## Configuration

```go
config := fido2.Config{
    Timeout:              30 * time.Second,
    UserPresenceTimeout:  30 * time.Second,
    RetryCount:           3,
    RetryDelay:           100 * time.Millisecond,
    Debug:                false,
    RelyingPartyID:       "luks-unlock",
    RelyingPartyName:     "LUKS Disk Encryption",
    RequireUserVerification: false,
    WorkaroundCanoKey:    true,
    AllowedVendors:       []uint16{},  // Empty = all vendors
    AllowedProducts:      []uint16{},  // Empty = all products
    DevicePath:           "",           // Empty = auto-select
}
```

## LUKS Integration

### Enrollment During Installation

```bash
# 1. Format LUKS volume
cryptsetup luksFormat /dev/sda1

# 2. Open with password
cryptsetup open /dev/sda1 cryptroot

# 3. Enroll FIDO2 key (using Go program)
./platform-initrd fido2-enroll --device /dev/sda1 --slot 2

# 4. Verify both keys work
cryptsetup luksDump /dev/sda1
```

### Unlock During Boot

```bash
# In initramfs /init script
./platform-initrd fido2-unlock --device /dev/sda1 --name cryptroot

# Or manual with cryptsetup
./platform-initrd fido2-derive --credential-id <id> --salt <salt> | \
    cryptsetup open --key-file=- /dev/sda1 cryptroot
```

## Testing

### Unit Tests

```bash
# Run all tests
go test ./pkg/fido2/... -v

# Run specific test
go test ./pkg/fido2 -run TestHandler_EnrollKey -v

# With coverage
go test ./pkg/fido2/... -cover -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### Integration Tests (Require Real Hardware)

Integration tests are documented but not run in CI as they require physical FIDO2 devices:

```go
// +build integration

func TestIntegration_RealDevice(t *testing.T) {
    // Requires: YubiKey 5, SoloKey, or compatible FIDO2 authenticator
    // See: pkg/fido2/integration_test.go
}
```

To run integration tests:

```bash
# Connect FIDO2 device
go test ./pkg/fido2 -tags=integration -v

# Test specific device
export FIDO2_DEVICE=/dev/hidraw0
go test ./pkg/fido2 -tags=integration -run TestRealYubiKey -v
```

## Supported Devices

Tested and verified with:

- **YubiKey 5 Series** (USB-A, USB-C, NFC, Nano)
- **SoloKeys** (Solo v1, Solo v2)
- **Nitrokey** (FIDO2, Nitrokey 3)
- **CanoKey** (with CBOR workaround enabled)
- **Feitian** (ePass FIDO2, BioPass FIDO2)
- **Generic FIDO2 Authenticators** (CTAP 2.0 compliant)

### Device-Specific Notes

- **CanoKey**: Enable `WorkaroundCanoKey: true` to handle CBOR truncation
- **Windows Hello**: Not supported (platform authenticator only)
- **Touch ID**: Not supported (platform authenticator only)
- **NFC**: Supported if device exposes as USB HID

## Protocol Details

### CTAP2 Commands Implemented

- `authenticatorGetInfo` (0x04) - Get device capabilities
- `authenticatorMakeCredential` (0x01) - Create new credential
- `authenticatorGetAssertion` (0x02) - Get assertion with hmac-secret

### CTAPHID Transport

- Packet size: 64 bytes
- Initialization packet: CID (4) + CMD (1) + LEN (2) + DATA (57)
- Continuation packet: CID (4) + SEQ (1) + DATA (59)
- Supports multi-packet messages with automatic fragmentation

### HMAC-Secret Extension

1. **Enrollment**: Request hmac-secret extension in MakeCredential
2. **Authentication**: Send 32-byte salt in GetAssertion extensions
3. **Key Derivation**: Receive 32-byte HMAC-SHA256(credentialSecret, salt)
4. **LUKS Key**: Derive 512-bit key using KDF from HMAC output

```
LUKS Key (512-bit) = SHA256(hmac-secret || "v1") || SHA256(hmac-secret || "v2")
```

## Security Considerations

### User Presence

- All operations require user presence (touching the device)
- Prevents automated key extraction attacks
- Configurable timeout for user interaction

### Credential Storage

- Credentials are non-resident (not stored on device)
- Credential ID must be provided for authentication
- Credential ID is public (not sensitive)
- Secret is derived from credential + salt (device-bound)

### Salt Management

- Salt must be stored with credential ID
- Salt is public (not sensitive)
- Unique salt per credential prevents cross-credential attacks
- Recommended: Store in LUKS token metadata

### Key Derivation

- HMAC-secret output is 32 bytes (256 bits)
- Expanded to 512 bits for LUKS (AES-256-XTS requires 512-bit keys)
- Deterministic: same credential + salt = same key
- Device-bound: key cannot be derived without physical device

## Error Handling

```go
switch {
case errors.Is(err, fido2.ErrNoDeviceFound):
    // No FIDO2 device detected

case errors.Is(err, fido2.ErrUserPresenceRequired):
    // User didn't touch device in time

case errors.Is(err, fido2.ErrCredentialNotFound):
    // Credential ID not recognized by device

case errors.Is(err, fido2.ErrUnsupportedExtension):
    // Device doesn't support hmac-secret

case errors.Is(err, fido2.ErrOperationTimeout):
    // Operation timed out

case errors.Is(err, fido2.ErrPINRequired):
    // Device requires PIN (not yet supported)
}
```

## Limitations

- **No PIN Support**: Currently assumes PIN-less devices or pre-set PIN
- **No BLE/NFC**: Only USB HID transport implemented
- **No Resident Keys**: Non-resident credentials only (credential ID required)
- **No User Verification**: UV not required (UP only)
- **Single Salt**: Only one salt per GetAssertion (no salt2 support)

## Future Enhancements

- [ ] PIN/UV protocol support (CTAP 2.1)
- [ ] Credential management (enumerate, delete)
- [ ] BLE and NFC transport layers
- [ ] Resident key support
- [ ] Large blob storage
- [ ] Bio-enrollment (biometric authenticators)
- [ ] Enterprise attestation
- [ ] Multiple salt support (salt1 + salt2)

## Dependencies

- `github.com/fxamacker/cbor/v2` - CBOR encoding/decoding
- `github.com/flynn/hid` - USB HID device access (required at runtime)

## References

- [FIDO2 CTAP 2.0 Specification](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)
- [CTAP 2.1 Specification](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html)
- [HMAC-Secret Extension](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#sctn-hmac-secret-extension)
- [systemd-cryptenroll FIDO2](https://www.freedesktop.org/software/systemd/man/systemd-cryptenroll.html)
- [Platform-Initrd Architecture](/docs/platform-initrd-architecture.md)

## License

See project root LICENSE file.

## Contributing

See project root CONTRIBUTING.md for contribution guidelines.

Ensure all tests pass and achieve 90%+ coverage for new code:

```bash
go test ./pkg/fido2/... -cover
go test ./pkg/fido2/... -race
golangci-lint run ./pkg/fido2/...
```
