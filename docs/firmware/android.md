# Android/GrapheneOS Secure Mobile Implementation

> Part of the go-trusted-platform trusted firmware architecture

## Overview

This document details the Android-specific implementation for trusted firmware capabilities, supporting GrapheneOS and other security-focused Android distributions with native fastboot integration, hardware attestation, and A/B seamless updates.

## Supported Platforms

### GrapheneOS (Primary Target)

**GrapheneOS** is a privacy and security-focused mobile OS based on AOSP (Android Open Source Project).

**Features**:
- Hardware-backed attestation
- Verified boot with rollback protection
- A/B seamless system updates
- MAC randomization
- Sandboxed Google Play (optional)
- No Google services by default

**Supported Devices**:
- Pixel 9a (tegu)
- Pixel 9 Pro Fold (comet)
- Pixel 9 Pro XL (komodo)
- Pixel 9 Pro (caiman)
- Pixel 9 (tokay)
- Pixel 8a (akita)
- Pixel 8 Pro (husky)
- Pixel 8 (shiba)
- Pixel Fold (felix)
- Pixel Tablet (tangorpro)
- Pixel 7a (lynx)
- Pixel 7 Pro (cheetah)
- Pixel 7 (panther)
- Pixel 6a (bluejay)
- Pixel 6 Pro (raven)
- Pixel 6 (oriole)

GrapheneOS has experimental support for the following devices:

- Pixel 10 Pro Fold (rango)
- Pixel 10 Pro XL (mustang)
- Pixel 10 Pro (blazer)
- Pixel 10 (frankel)


## Android Verified Boot 2.0 (AVB)

### Boot Chain

```
┌─────────────────────────────────────────────────────────┐
│              Android Verified Boot Flow                 │
└─────────────────────────────────────────────────────────┘

1. Bootloader (Locked)
   ↓ verify boot.img signature

2. boot.img (Kernel + Ramdisk)
   ↓ verify vbmeta partition

3. vbmeta (Verification Metadata)
   ↓ contains hashes of all verified partitions
   ↓ signed by OEM key

4. system.img (Android System)
   ↓ dm-verity verification

5. vendor.img (Vendor Binaries)
   ↓ dm-verity verification

6. Android Runtime
```

### Verified Boot States

| State | Bootloader | Verity | Custom Key | Risk |
|-------|------------|--------|------------|------|
| **GREEN** | Locked | Enabled | OEM Key | ✅ Secure |
| **YELLOW** | Locked | Enabled | Custom Key | ⚠️ Custom OS |
| **ORANGE** | Unlocked | Disabled | Any | ❌ Insecure |
| **RED** | Locked | Failed | - | ❌ Corrupted |

**go-trusted-platform targets**: GREEN and YELLOW states

## Native Fastboot Implementation

### Why Native Go Implementation?

**gofastboot Analysis**:
- Only 500 lines of code
- Trivial USB protocol wrapper
- Limited error handling
- No advanced features

**Decision**: Implement native fastboot in Go for:
- Full control over protocol
- Better error handling
- Custom security features
- Integration with signing infrastructure
- No external dependencies

### Fastboot Protocol

**Location**: `pkg/firmware/android/fastboot/protocol.go`

```go
package fastboot

import (
    "github.com/google/gousb"
)

type FastbootDevice struct {
    usb      *gousb.Device
    endpoint *gousb.InEndpoint
    logger   *logging.Logger
}

// Fastboot command format:
// Command: ASCII string, max 64 bytes
// Response: "OKAY", "FAIL", "INFO", "DATA"

func (f *FastbootDevice) SendCommand(cmd string) (string, error) {
    // 1. Send command (max 64 bytes)
    if len(cmd) > 64 {
        return "", fmt.Errorf("command too long: %d bytes", len(cmd))
    }

    if _, err := f.endpoint.Write([]byte(cmd)); err != nil {
        return "", err
    }

    // 2. Read response
    resp := make([]byte, 64)
    n, err := f.endpoint.Read(resp)
    if err != nil {
        return "", err
    }

    response := string(resp[:n])

    // 3. Parse response status
    if strings.HasPrefix(response, "OKAY") {
        return response[4:], nil
    } else if strings.HasPrefix(response, "FAIL") {
        return "", fmt.Errorf("fastboot error: %s", response[4:])
    } else if strings.HasPrefix(response, "INFO") {
        // Informational message, read next response
        log.Info(response[4:])
        return f.readNextResponse()
    } else if strings.HasPrefix(response, "DATA") {
        // Data transfer required
        size := parseHexSize(response[4:])
        return f.receiveData(size)
    }

    return "", fmt.Errorf("unknown response: %s", response)
}

func (f *FastbootDevice) Flash(partition string, image []byte) error {
    // 1. Send flash command
    cmd := fmt.Sprintf("flash:%s", partition)
    if _, err := f.SendCommand(cmd); err != nil {
        return err
    }

    // 2. Device responds with DATA command requesting image
    // 3. Send image size
    sizeCmd := fmt.Sprintf("download:%08x", len(image))
    if _, err := f.SendCommand(sizeCmd); err != nil {
        return err
    }

    // 4. Send image data in chunks
    chunkSize := 1024 * 1024  // 1MB chunks
    for offset := 0; offset < len(image); offset += chunkSize {
        end := offset + chunkSize
        if end > len(image) {
            end = len(image)
        }

        if _, err := f.endpoint.Write(image[offset:end]); err != nil {
            return err
        }
    }

    // 5. Wait for OKAY
    resp := make([]byte, 64)
    n, err := f.endpoint.Read(resp)
    if err != nil {
        return err
    }

    if !strings.HasPrefix(string(resp[:n]), "OKAY") {
        return fmt.Errorf("flash failed: %s", string(resp[:n]))
    }

    return nil
}

func (f *FastbootDevice) GetVar(variable string) (string, error) {
    cmd := fmt.Sprintf("getvar:%s", variable)
    return f.SendCommand(cmd)
}

func (f *FastbootDevice) Reboot() error {
    _, err := f.SendCommand("reboot")
    return err
}

func (f *FastbootDevice) RebootBootloader() error {
    _, err := f.SendCommand("reboot-bootloader")
    return err
}

func (f *FastbootDevice) LockBootloader() error {
    // Lock bootloader (moves to GREEN or YELLOW state)
    _, err := f.SendCommand("flashing lock")
    return err
}

func (f *FastbootDevice) UnlockBootloader() error {
    // Unlock bootloader (WARNING: wipes data!)
    _, err := f.SendCommand("flashing unlock")
    return err
}
```

### USB Device Detection

**Location**: `pkg/firmware/android/fastboot/detect.go`

```go
func DetectFastbootDevices() ([]*FastbootDevice, error) {
    // Android fastboot USB IDs
    // Google: 0x18d1
    // Various manufacturers use different IDs

    ctx := gousb.NewContext()
    defer ctx.Close()

    devices := []*FastbootDevice{}

    // Enumerate USB devices
    devs, err := ctx.OpenDevices(func(desc *gousb.DeviceDesc) bool {
        // Match known fastboot vendor IDs
        return desc.Vendor == gousb.ID(0x18d1) ||  // Google
               desc.Vendor == gousb.ID(0x0bb4)     // HTC (example)
    })

    if err != nil {
        return nil, err
    }

    for _, dev := range devs {
        // Check if device is in fastboot mode
        if isFastbootDevice(dev) {
            devices = append(devices, &FastbootDevice{usb: dev})
        }
    }

    return devices, nil
}

func isFastbootDevice(dev *gousb.Device) bool {
    // Fastboot interface class: 0xFF (vendor-specific)
    // Check interface descriptors
    for _, cfg := range dev.Desc.Configs {
        for _, intf := range cfg.Interfaces {
            for _, alt := range intf.AltSettings {
                if alt.Class == gousb.ClassVendorSpec {
                    return true
                }
            }
        }
    }
    return false
}
```

## GrapheneOS Integration

### Building GrapheneOS

**Location**: `pkg/firmware/android/grapheneos/builder.go`

```go
package grapheneos

type GrapheneOSBuilder struct {
    sourceDir string
    xkmsBackend  *xkms.Backend
    logger    *logging.Logger
}

func NewGrapheneOSBuilder(sourceDir string) *GrapheneOSBuilder {
    return &GrapheneOSBuilder{
        sourceDir: sourceDir,
    }
}

func (b *GrapheneOSBuilder) Build(device string) (*BuildArtifacts, error) {
    // 1. Initialize build environment
    if err := b.initBuildEnv(); err != nil {
        return nil, err
    }

    // 2. Set device target
    if err := b.setTarget(device); err != nil {
        return nil, err
    }

    // 3. Build system images
    log.Info("Building GrapheneOS system images...")
    if err := b.buildSystemImages(); err != nil {
        return nil, err
    }

    // 4. Build vendor images
    if err := b.buildVendorImages(); err != nil {
        return nil, err
    }

    // 5. Build boot image (kernel + ramdisk)
    if err := b.buildBootImage(); err != nil {
        return nil, err
    }

    // 6. Sign all images with platform keys
    artifacts, err := b.signImages()
    if err != nil {
        return nil, err
    }

    return artifacts, nil
}

func (b *GrapheneOSBuilder) initBuildEnv() error {
    // Source build/envsetup.sh
    cmd := exec.Command("bash", "-c", "source build/envsetup.sh")
    cmd.Dir = b.sourceDir
    return cmd.Run()
}

func (b *GrapheneOSBuilder) setTarget(device string) error {
    // Run lunch command
    cmd := exec.Command("bash", "-c", fmt.Sprintf("lunch %s-user", device))
    cmd.Dir = b.sourceDir
    return cmd.Run()
}

func (b *GrapheneOSBuilder) buildSystemImages() error {
    // Build with make
    cmd := exec.Command("make", "-j$(nproc)", "systemimage")
    cmd.Dir = b.sourceDir
    return cmd.Run()
}

func (b *GrapheneOSBuilder) signImages() (*BuildArtifacts, error) {
    // Sign boot.img, system.img, vendor.img
    // Use platform signing keys from go-trusted-platform

    artifacts := &BuildArtifacts{}

    // Sign boot image
    bootImg := filepath.Join(b.sourceDir, "out/target/product/*/boot.img")
    signedBoot, err := b.signBootImage(bootImg)
    if err != nil {
        return nil, err
    }
    artifacts.Boot = signedBoot

    // Sign system image
    systemImg := filepath.Join(b.sourceDir, "out/target/product/*/system.img")
    signedSystem, err := b.signSystemImage(systemImg)
    if err != nil {
        return nil, err
    }
    artifacts.System = signedSystem

    return artifacts, nil
}
```

### Signing Keys

**Location**: `pkg/firmware/android/signing/keys.go`

```go
package signing

// Android signing keys (AVB 2.0)
type AndroidKeyset struct {
    Platform    *rsa.PrivateKey  // Platform key (system signing)
    Media       *rsa.PrivateKey  // Media key
    Shared      *rsa.PrivateKey  // Shared key
    Release     *rsa.PrivateKey  // Release key
    AVBKey      *rsa.PrivateKey  // AVB signing key (vbmeta)
}

func (k *AndroidKeyset) GenerateAVBKeys() error {
    // Generate RSA-4096 key for AVB signing
    key, err := rsa.GenerateKey(rand.Reader, 4096)
    if err != nil {
        return err
    }

    k.AVBKey = key

    // Export public key for bootloader
    pubkeyPath := "/path/to/avb_pubkey.bin"
    if err := exportAVBPublicKey(key, pubkeyPath); err != nil {
        return err
    }

    return nil
}

func SignVBMeta(vbmetaImg string, key *rsa.PrivateKey) error {
    // Sign vbmeta partition with AVB key
    cmd := exec.Command("avbtool",
        "add_hash_footer",
        "--image", vbmetaImg,
        "--partition_name", "vbmeta",
        "--key", keyPath(key),
        "--algorithm", "SHA256_RSA4096",
    )

    return cmd.Run()
}
```

## A/B Seamless Updates

### A/B Partition Layout

```
┌─────────────────────────────────────────────┐
│  Android A/B Partition Scheme               │
├─────────────────────────────────────────────┤
│  bootloader_a       bootloader_b            │
│  boot_a             boot_b                  │
│  system_a           system_b                │
│  vendor_a           vendor_b                │
│  vbmeta_a           vbmeta_b                │
│  dtbo_a             dtbo_b (device tree)    │
├─────────────────────────────────────────────┤
│  userdata (shared, not duplicated)          │
└─────────────────────────────────────────────┘
```

### OTA Update Implementation

**Location**: `pkg/ota/android.go`

```go
package ota

type AndroidOTAUpdater struct {
    fastboot      *fastboot.FastbootDevice
    currentSlot   string  // "a" or "b"
    logger        *logging.Logger
}

func (u *AndroidOTAUpdater) Update(manifestURL string) error {
    // 1. Download OTA manifest
    manifest := downloadManifest(manifestURL)

    // 2. Verify manifest signature
    if !verifyManifestSignature(manifest) {
        return errors.New("invalid manifest signature")
    }

    // 3. Determine inactive slot
    inactive := u.getInactiveSlot()

    // 4. Download update images
    log.Infof("Downloading update to slot %s", inactive)

    images, err := u.downloadImages(manifest)
    if err != nil {
        return err
    }

    // 5. Verify all image signatures
    if err := u.verifyImages(images); err != nil {
        return err
    }

    // 6. Reboot to bootloader
    if err := u.fastboot.RebootBootloader(); err != nil {
        return err
    }

    // 7. Flash images to inactive slot
    if err := u.flashSlot(inactive, images); err != nil {
        return err
    }

    // 8. Set inactive slot as active
    if err := u.setActiveSlot(inactive); err != nil {
        return err
    }

    // 9. Reboot
    return u.fastboot.Reboot()
}

func (u *AndroidOTAUpdater) flashSlot(slot string, images *OTAImages) error {
    // Flash boot image
    partition := fmt.Sprintf("boot_%s", slot)
    if err := u.fastboot.Flash(partition, images.Boot); err != nil {
        return fmt.Errorf("failed to flash boot_%s: %w", slot, err)
    }

    // Flash system image
    partition = fmt.Sprintf("system_%s", slot)
    if err := u.fastboot.Flash(partition, images.System); err != nil {
        return fmt.Errorf("failed to flash system_%s: %w", slot, err)
    }

    // Flash vendor image
    partition = fmt.Sprintf("vendor_%s", slot)
    if err := u.fastboot.Flash(partition, images.Vendor); err != nil {
        return fmt.Errorf("failed to flash vendor_%s: %w", slot, err)
    }

    // Flash vbmeta
    partition = fmt.Sprintf("vbmeta_%s", slot)
    if err := u.fastboot.Flash(partition, images.VBMeta); err != nil {
        return fmt.Errorf("failed to flash vbmeta_%s: %w", slot, err)
    }

    return nil
}

func (u *AndroidOTAUpdater) setActiveSlot(slot string) error {
    cmd := fmt.Sprintf("set_active:%s", slot)
    _, err := u.fastboot.SendCommand(cmd)
    return err
}

func (u *AndroidOTAUpdater) getInactiveSlot() string {
    current, _ := u.fastboot.GetVar("current-slot")

    if current == "a" {
        return "b"
    }
    return "a"
}
```

### Rollback Protection

**Location**: `pkg/firmware/android/rollback/`

```go
package rollback

// Android uses rollback index in vbmeta
type RollbackProtection struct {
    fastboot *fastboot.FastbootDevice
    logger   *logging.Logger
}

func (r *RollbackProtection) GetRollbackIndex() (uint64, error) {
    // Read rollback index from device
    index, err := r.fastboot.GetVar("rollback-index")
    if err != nil {
        return 0, err
    }

    return strconv.ParseUint(index, 10, 64)
}

func (r *RollbackProtection) VerifyVersion(newVersion uint64) error {
    current, err := r.GetRollbackIndex()
    if err != nil {
        return err
    }

    if newVersion <= current {
        return fmt.Errorf("rollback detected: current=%d, new=%d", current, newVersion)
    }

    return nil
}

func (r *RollbackProtection) IncrementRollbackIndex() error {
    // Increment rollback index (done automatically by bootloader after successful boot)
    // This is just for verification
    current, err := r.GetRollbackIndex()
    if err != nil {
        return err
    }

    log.Infof("Current rollback index: %d", current)
    return nil
}
```

## Hardware Attestation

### Android Key Attestation API

**Location**: `pkg/firmware/android/attestation/hardware.go`

```go
package attestation

// Android hardware attestation uses Keystore API
// This verifies that keys are stored in hardware-backed keystore (TEE or StrongBox)

type HardwareAttestor struct {
    adb    *adb.Client
    logger *logging.Logger
}

func (h *HardwareAttestor) Attest(nonce []byte) (*Attestation, error) {
    // 1. Generate attestation key in hardware keystore
    keyAlias := "attestation-key"
    if err := h.generateAttestationKey(keyAlias, nonce); err != nil {
        return nil, err
    }

    // 2. Request attestation certificate chain
    certChain, err := h.getAttestationCerts(keyAlias)
    if err != nil {
        return nil, err
    }

    // 3. Parse attestation extension
    attestExt, err := parseAttestationExtension(certChain[0])
    if err != nil {
        return nil, err
    }

    // 4. Verify attestation properties
    attestation := &Attestation{
        Nonce:              nonce,
        Certificates:       certChain,
        SecurityLevel:      attestExt.SecurityLevel,  // TEE or StrongBox
        VerifiedBootState:  attestExt.VerifiedBootState,
        VerifiedBootHash:   attestExt.VerifiedBootHash,
        OSVersion:          attestExt.OSVersion,
        PatchLevel:         attestExt.PatchLevel,
    }

    return attestation, nil
}

func (h *HardwareAttestor) generateAttestationKey(alias string, nonce []byte) error {
    // Use ADB to execute keystore command on device
    cmd := fmt.Sprintf(
        "am broadcast -a com.android.keystore.ATTEST " +
        "--es alias %s " +
        "--es challenge %x",
        alias,
        nonce,
    )

    _, err := h.adb.Shell(cmd)
    return err
}

func (h *HardwareAttestor) getAttestationCerts(alias string) ([]*x509.Certificate, error) {
    // Retrieve certificate chain from keystore
    cmd := fmt.Sprintf("keystore list -alias %s", alias)
    output, err := h.adb.Shell(cmd)
    if err != nil {
        return nil, err
    }

    return parseCertChain(output)
}

type AttestationExtension struct {
    SecurityLevel      string  // "TrustedEnvironment" or "StrongBox"
    VerifiedBootState  string  // "Verified", "SelfSigned", "Unverified", "Failed"
    VerifiedBootHash   []byte  // Hash of verified boot key
    OSVersion          int
    PatchLevel         int
}
```

### Attestation Verification

**Location**: `pkg/firmware/android/attestation/verifier.go`

```go
func VerifyHardwareAttestation(attestation *Attestation) error {
    // 1. Verify certificate chain roots to Google attestation root
    if err := verifyCertChain(attestation.Certificates); err != nil {
        return err
    }

    // 2. Verify attestation extension signature
    if err := verifyAttestationExtension(attestation.Certificates[0]); err != nil {
        return err
    }

    // 3. Check security level (must be TEE or StrongBox)
    if attestation.SecurityLevel != "TrustedEnvironment" &&
       attestation.SecurityLevel != "StrongBox" {
        return fmt.Errorf("invalid security level: %s", attestation.SecurityLevel)
    }

    // 4. Check verified boot state (must be Verified or SelfSigned)
    if attestation.VerifiedBootState != "Verified" &&
       attestation.VerifiedBootState != "SelfSigned" {
        return fmt.Errorf("unverified boot state: %s", attestation.VerifiedBootState)
    }

    // 5. Verify OS version and patch level
    if attestation.PatchLevel < MINIMUM_PATCH_LEVEL {
        return fmt.Errorf("patch level too old: %d", attestation.PatchLevel)
    }

    return nil
}
```

## ADB Integration

### ADB for Remote Operations

**Location**: `pkg/firmware/android/adb/client.go`

```go
package adb

type Client struct {
    host   string  // localhost:5037 (default ADB server)
    logger *logging.Logger
}

func NewClient() *Client {
    return &Client{host: "localhost:5037"}
}

func (c *Client) Shell(cmd string) (string, error) {
    // Execute shell command via ADB
    adbCmd := exec.Command("adb", "shell", cmd)
    output, err := adbCmd.Output()
    return string(output), err
}

func (c *Client) Push(local, remote string) error {
    cmd := exec.Command("adb", "push", local, remote)
    return cmd.Run()
}

func (c *Client) Pull(remote, local string) error {
    cmd := exec.Command("adb", "pull", remote, local)
    return cmd.Run()
}

func (c *Client) Install(apk string) error {
    cmd := exec.Command("adb", "install", apk)
    return cmd.Run()
}

func (c *Client) Reboot(mode string) error {
    // mode: "", "bootloader", "recovery"
    cmd := exec.Command("adb", "reboot", mode)
    return cmd.Run()
}
```

## Device Flashing

### Complete Flash Workflow

**Location**: `pkg/firmware/android/flasher/flasher.go`

```go
package flasher

type AndroidFlasher struct {
    fastboot  *fastboot.FastbootDevice
    signer    *signing.AndroidSigner
    logger    *logging.Logger
}

func (f *AndroidFlasher) FlashGrapheneOS(images *BuildArtifacts) error {
    // 1. Verify device is in fastboot mode
    if !f.fastboot.IsConnected() {
        return errors.New("device not in fastboot mode")
    }

    // 2. Unlock bootloader (if needed, WARNING: wipes data!)
    if locked, _ := f.isBootloaderLocked(); locked {
        log.Warn("Unlocking bootloader will WIPE ALL DATA!")
        if err := f.fastboot.UnlockBootloader(); err != nil {
            return err
        }
    }

    // 3. Flash bootloader
    if err := f.flashBootloader(images.Bootloader); err != nil {
        return err
    }

    // 4. Flash radio (baseband)
    if err := f.flashRadio(images.Radio); err != nil {
        return err
    }

    // 5. Flash boot images to both slots
    for _, slot := range []string{"a", "b"} {
        if err := f.flashBootSlot(slot, images); err != nil {
            return err
        }
    }

    // 6. Flash userdata (optional, for clean install)
    if images.Userdata != nil {
        if err := f.fastboot.Flash("userdata", images.Userdata); err != nil {
            return err
        }
    }

    // 7. Set active slot
    if err := f.fastboot.SetActiveSlot("a"); err != nil {
        return err
    }

    // 8. Lock bootloader (moves to YELLOW or GREEN state)
    log.Info("Locking bootloader with custom key...")
    if err := f.fastboot.LockBootloader(); err != nil {
        return err
    }

    // 9. Reboot
    log.Info("Flashing complete, rebooting...")
    return f.fastboot.Reboot()
}

func (f *AndroidFlasher) flashBootSlot(slot string, images *BuildArtifacts) error {
    partitions := map[string][]byte{
        fmt.Sprintf("boot_%s", slot):   images.Boot,
        fmt.Sprintf("system_%s", slot): images.System,
        fmt.Sprintf("vendor_%s", slot): images.Vendor,
        fmt.Sprintf("vbmeta_%s", slot):  images.VBMeta,
        fmt.Sprintf("dtbo_%s", slot):    images.DTBO,
    }

    for partition, data := range partitions {
        log.Infof("Flashing %s...", partition)
        if err := f.fastboot.Flash(partition, data); err != nil {
            return fmt.Errorf("failed to flash %s: %w", partition, err)
        }
    }

    return nil
}

func (f *AndroidFlasher) isBootloaderLocked() (bool, error) {
    unlocked, err := f.fastboot.GetVar("unlocked")
    if err != nil {
        return false, err
    }

    return unlocked != "yes", nil
}
```

## Testing

### Emulator Testing

**Location**: `pkg/firmware/testing/android_emulator.go`

```go
type AndroidEmulator struct {
    avdName  string
    logger   *logging.Logger
}

func (e *AndroidEmulator) Start() error {
    // Start Android emulator
    cmd := exec.Command("emulator",
        "-avd", e.avdName,
        "-no-snapshot",
        "-wipe-data",
    )

    return cmd.Start()
}

func (e *AndroidEmulator) WaitForBoot() error {
    // Wait for boot animation to complete
    for i := 0; i < 120; i++ {
        output, _ := exec.Command("adb", "shell", "getprop", "sys.boot_completed").Output()
        if strings.TrimSpace(string(output)) == "1" {
            return nil
        }
        time.Sleep(1 * time.Second)
    }

    return errors.New("emulator boot timeout")
}
```

## CLI Commands

```bash
# Detect fastboot devices
platformctl firmware android detect

# Flash GrapheneOS
platformctl firmware android flash-grapheneos \
    --images grapheneos-build.tar \
    --device <serial> \
    --lock-bootloader

# OTA update
platformctl ota update --device android-pixel7 --version 2024-01-01

# Attest device
platformctl firmware attest \
    --device android-pixel7 \
    --protocol android-hardware \
    --verify-trust

# Check bootloader status
platformctl firmware android bootloader-status --device <serial>

# Lock bootloader (WARNING: wipes data)
platformctl firmware android lock-bootloader --device <serial> --confirm

# Unlock bootloader (WARNING: wipes data)
platformctl firmware android unlock-bootloader --device <serial> --confirm

# Flash specific partition
platformctl firmware android flash-partition \
    --partition boot_a \
    --image boot.img \
    --device <serial>

# Set active slot
platformctl firmware android set-active-slot --slot a --device <serial>

# Get device info
platformctl firmware android info --device <serial>

# Test in emulator
platformctl firmware android test-emulator --avd pixel_7_api_33
```

## Implementation Files

### Core Android Files

1. **pkg/firmware/android/fastboot/** - Native fastboot implementation
   - protocol.go - Fastboot protocol (USB communication)
   - detect.go - USB device detection
   - commands.go - Fastboot commands (flash, reboot, etc.)

2. **pkg/firmware/android/grapheneos/** - GrapheneOS integration
   - builder.go - Build GrapheneOS from source
   - installer.go - Install GrapheneOS to device

3. **pkg/firmware/android/signing/** - Image signing
   - keys.go - Android signing keys (platform, AVB)
   - signer.go - Sign boot/system/vendor images
   - avb.go - AVB 2.0 signing

4. **pkg/firmware/android/flasher/** - Device flashing
   - flasher.go - Complete flash workflow
   - verify.go - Post-flash verification

5. **pkg/firmware/android/attestation/** - Hardware attestation
   - hardware.go - Android keystore attestation
   - verifier.go - Attestation verification

6. **pkg/firmware/android/adb/** - ADB integration
   - client.go - ADB client for remote operations

7. **pkg/ota/** - Universal OTA system
   - android.go - Android OTA updater (A/B seamless)

8. **pkg/firmware/android/rollback/** - Rollback protection
   - vbmeta.go - vbmeta rollback index

## Security Considerations

### Threat Model

**Protected Against**:
- ✅ Unsigned system images (AVB signature verification)
- ✅ Bootloader tampering (verified boot)
- ✅ Rollback attacks (rollback index in vbmeta)
- ✅ Runtime tampering (dm-verity)
- ✅ Key compromise (hardware-backed keystore)

**NOT Protected Against**:
- ❌ Bootloader unlock with physical access (wipes data)
- ❌ Hardware-level attacks on TEE/StrongBox

### Best Practices

1. **Development**: Use emulator, don't lock bootloader
2. **Testing**: Test on real device with unlocked bootloader
3. **Staging**: Test with locked bootloader (YELLOW state)
4. **Production**: Lock bootloader with platform keys (GREEN/YELLOW state)

### Bootloader Lock Checklist

- [ ] System images tested in emulator
- [ ] Images flashed and tested on real device (unlocked)
- [ ] A/B OTA tested
- [ ] Attestation verified
- [ ] Rollback protection tested
- [ ] **ALL TESTS PASSING**
- [ ] ⚠️ **FINAL STEP**: Lock bootloader (wipes data!)

## GrapheneOS vs CalyxOS vs LineageOS

| Feature | GrapheneOS | CalyxOS | LineageOS |
|---------|------------|---------|-----------|
| Hardware Attestation | ✅ Full | ✅ Full | ⚠️ Limited |
| Verified Boot | ✅ Yes | ✅ Yes | ✅ Yes |
| A/B Updates | ✅ Yes | ✅ Yes | ✅ Yes |
| Google Services | ❌ None | ⚠️ microG | ❌ None |
| Privacy Focus | 🔥 Extreme | 💚 High | ⚠️ Medium |
| Device Support | Limited (Pixels) | Medium | Extensive |

**Recommendation**: GrapheneOS for maximum security and attestation support

## References

- GrapheneOS: https://grapheneos.org/
- Android Verified Boot: https://source.android.com/security/verifiedboot
- Hardware Attestation: https://developer.android.com/training/articles/security-key-attestation
- Fastboot Protocol: https://android.googlesource.com/platform/system/core/+/master/fastboot/
- AVB 2.0: https://android.googlesource.com/platform/external/avb/
