# Trusted Platform Firmware Support

Enterprise-grade firmware signing, attestation, and OTA updates for embedded devices and mobile platforms.

## Overview

Trusted Platform Firmware provides comprehensive firmware lifecycle management integrated with the Trusted Platform. It supports AVR microcontrollers, Raspberry Pi, and Android devices with language-agnostic compilation, secure boot, attestation, and over-the-air updates.

## Key Features

| Feature | Description |
|---------|-------------|
| **Language-Agnostic** | Compile firmware with any toolchain (avr-gcc, Rust, Arduino IDE, etc.) |
| **Universal OTA** | Single OTA system works across AVR, RPi, ARM64, AMD64, Android |
| **Universal Attestation** | One attestation service supporting serial, TPM, BLE, LoRa, WiFi |
| **Secure Boot** | Bootloader signature verification with hardware root of trust |
| **Firmware Encryption** | AES-128-CTR encryption for IP protection and anti-cloning |
| **Native ISP** | No avrdude dependency - pure Go ISP implementation |
| **Native Fastboot** | Pure Go fastboot for Android/GrapheneOS |
| **Virtual Testing** | Test in simavr/QEMU before flashing real hardware |
| **Supply Chain Security** | SLSA provenance and SBOM generation |
| **QuicBaaS Integration** | Audit logging, RBAC/ABAC, fleet management |

## Architecture Decision

**Single Trusted Platform binary with integrated firmware module** - NOT a separate project.

| Aspect | Decision |
|--------|----------|
| Architecture | Firmware built into `pkg/firmware` as integrated module |
| Binary | Single `platformctl` binary for all operations |
| OTA System | Extends existing `pkg/ota` for universal OTA |
| Attestation | Extends existing `pkg/attestation` service |
| Device Config | Extends existing `pkg/device` schemas |

**Rationale:**
- One binary is simpler to deploy and maintain
- Firmware reuses platform CA infrastructure
- Universal OTA/attestation across all device types
- Single documentation set and unified CLI

## Supported Platforms

### AVR Microcontrollers

**Families**: ATmega (328p, 2560), ATtiny (85, 45), AVR-DA/DB

**Flash Constraints** (Arduino Nano - ATmega328P):
- Total Flash: 32KB
- Bootloader: 4-6KB
- Optional Library: 1-3KB
- **User Application: 24KB+** ✅

**Features**:
- C bootloader with Ed25519 signature verification
- Pseudo-OTP root of trust (EEPROM + lock bits)
- Native ISP flashing (no avrdude)
- Optional libtrusted-avr.a library
- Serial and wireless attestation
- Golden image + staging OTA strategy
- **ATECC608A/ATECC508A support** (deferred pending hardware)

### Raspberry Pi

**Models**: All models (Pi 4, Pi 3, Pi Zero 2 W, Compute Module 4)

**Features**:
- OTP-based secure boot
- Signed boot chain (bootcode.bin → start4.elf → kernel → initramfs)
- **TPM2_Quote attestation** (physical TPM or swtpm)
- A/B partition OTA updates
- Alpine Linux integration
- USB recovery mode (unbrick support)
- SD card image flashing

**TPM Support**:
- Physical TPM: Uses /dev/tpmrm0
- Virtual TPM: Uses swtpm (software TPM emulation)
- **No software fallback** - always TPM2_Quote

### Android/GrapheneOS

**Devices**: Google Pixel series and compatible devices

**Features**:
- Native Go fastboot implementation
- Android Verified Boot 2.0 (AVB)
- A/B seamless updates
- Hardware attestation API
- GrapheneOS building and signing
- Bootloader lock/unlock management

## Quick Start

### Flash AVR Firmware

```bash
# User compiles firmware with any toolchain
avr-gcc -mmcu=atmega328p -o firmware.elf main.c
avr-objcopy -O ihex firmware.elf firmware.hex

# Sign with platform CA
platformctl firmware sign firmware.hex --device arduino-001

# Flash to device
platformctl firmware flash firmware.hex --port /dev/ttyUSB0 --verify

# Attest device
platformctl firmware attest --device-id arduino-001 --port /dev/ttyUSB0
```

### Configure Raspberry Pi

> **NOTE: PROPOSED CONFIGURATION - Not yet implemented**
>
> The `firmware:` configuration section shown below is a **planned feature** for Phase O.
> This schema is proposed and subject to change. The current platform configuration
> does not include a `firmware:` section.

```yaml
# PROPOSED config.yaml (flat YAML format) - NOT YET IMPLEMENTED
debug: true
platform-dir: /var/lib/trusted-platform

# TPM configuration (physical or swtpm)
tpm:
  device: /dev/tpmrm0        # Physical TPM
  # device: /var/run/swtpm-socket  # OR swtpm virtual TPM
  simulator: false
  hash: SHA-256

# PROPOSED: Firmware settings (Phase O - not yet implemented)
firmware:
  platform: raspberry-pi
  model: rpi4b

  # OTP configuration
  otp:
    programmed: true
    pubkey-hash: sha256:abcdef1234...

  # A/B partitions
  ota:
    enabled: true
    partitioning: ab
    active-partition: a

  # Attestation via TPM2_Quote
  attestation:
    protocol: tpm
    pcr-selection: "0,1,2,3,4,5,6,7"
```

### Flash GrapheneOS

```bash
# Build GrapheneOS
platformctl firmware android build-grapheneos --device pixel-7

# Flash to device
platformctl firmware android flash-grapheneos \
  --images grapheneos-build.tar \
  --device <serial> \
  --lock-bootloader

# Attest device
platformctl firmware attest \
  --device pixel-7 \
  --protocol android-hardware
```

## OTA Updates

```bash
# Configure OTA server
platformctl firmware ota configure \
  --url https://updates.example.com \
  --device atmega328p

# Trigger update
platformctl ota update --device-id arduino-001 --version 1.2.3

# Check status
platformctl ota status --device-id arduino-001

# Rollback if needed
platformctl ota rollback --device-id arduino-001
```

## Attestation

```bash
# Attest AVR device (serial)
platformctl firmware attest --device-id arduino-001 --port /dev/ttyUSB0

# Attest RPi (TPM2_Quote)
platformctl firmware attest --device-id rpi-001 --protocol tpm

# Attest via BLE (wireless)
platformctl firmware attest --device-id sensor-001 --protocol ble

# Attest Android (hardware attestation)
platformctl firmware attest --device-id pixel-7 --protocol android-hardware
```

## swtpm Virtual TPM (Raspberry Pi)

For Raspberry Pi devices without physical TPM:

```bash
# Install swtpm on target
platformctl vtpm install-swtpm --target rpi-001

# Create pre-made vtpm bundle
platformctl vtpm create-bundle --output vtpm-bundle.tar.gz

# Deploy to device
platformctl vtpm deploy-bundle \
  --bundle vtpm-bundle.tar.gz \
  --device rpi-001

# Device now has virtual TPM for TPM2_Quote attestation
```

## Configuration

> **NOTE: PROPOSED CONFIGURATION - Not yet implemented**
>
> The firmware device configuration schema shown below is a **planned feature** for Phase O.
> This schema is proposed and subject to change.

Device configurations use **flat YAML format** (matches existing go-trusted-platform configs):

```yaml
# PROPOSED: AVR device config (Phase O - not yet implemented)
device-id: arduino-uno-001
model: atmega328p
role: iot

platform:
  type: avr
  target: atmega328p
  programmer: usbasp
  serial-port: /dev/ttyUSB0

firmware:
  bootloader-size: 4096
  flash-size: 32768
  eeprom-size: 1024

security:
  lock-bits: 0xFC
  fuses:
    low: 0xFF
    high: 0xDE

attestation:
  protocol: serial
  baud-rate: 115200

ota:
  enabled: true
  update-url: https://firmware.example.com/updates
  partitioning: golden-staging
```

See [configuration.md](configuration.md) for complete examples.

## QuicBaaS Integration

Firmware operations integrate with QuicBaaS for:

- **Audit Logging**: Immutable log of all flash, attest, OTA operations
- **RBAC/ABAC**: Fine-grained permissions (firmware-admin, firmware-operator, firmware-viewer)
- **Fleet Management**: Track device inventory, firmware versions, attestation status
- **Compliance**: SOC 2, ISO 27001 reporting

```yaml
# ABAC policy (uses apiVersion/kind/metadata/spec format)
apiVersion: abac.trustedplatform.io/v1
kind: Policy
metadata:
  name: firmware-operator
  tenant: platform

spec:
  subjects:
    roles: [firmware-operator]
  rules:
    - name: flash-and-attest
      effect: allow
      actions: [execute]
      resources: [firmware:flash, firmware:attest, firmware:ota]
```

## Documentation

### Platform & Architecture
- [Architecture](architecture.md) - System design and architecture decisions
- [Configuration](configuration.md) - Configuration reference and examples
- [Roadmap](../../ROADMAP.md) - Development roadmap and progress tracker
- [API Reference](api-reference.md) - CLI commands and API documentation

### Secure Boot Pipeline
- [Authenticode](authenticode.md) - PE/COFF code signing for EFI binaries
- [UKI](uki.md) - Unified Kernel Image building
- [UEFI](uefi.md) - UEFI NVRAM and Secure Boot key enrollment

### Device Support
- [AVR Support](avr-attestation.md) - AVR microcontroller implementation details
- [AVR Attestation](avr-attestation.md) - `pkg/firmware/avr/attestation`, the AVR attestation provider
- [Raspberry Pi](rpi.md) - Raspberry Pi secure boot and swtpm
- [Android](android.md) - Android/GrapheneOS support

## Key Concepts

### Language-Agnostic Firmware

Users compile firmware with **any toolchain**:
- avr-gcc (standard C)
- Rust (via avr-rust)
- Arduino IDE
- PlatformIO

go-trusted-platform handles signing and flashing.

### Universal OTA

**One OTA system** for all platforms:
- **AVR**: Golden image + staging
- **RPi**: A/B partitions
- **Android**: A/B seamless updates
- **ARM64/AMD64**: Existing mechanisms

All use the same `pkg/ota` service.

### Universal Attestation

**One attestation service** with multiple transports:
- **Serial**: AVR devices
- **TPM2_Quote**: RPi (physical TPM or swtpm), ARM64, AMD64
- **BLE/LoRa/WiFi**: Wireless devices
- **Android Hardware**: Pixel devices

All use the same `pkg/attestation` service.

### Secure Boot

- **AVR**: Bootloader verifies Ed25519 signature before execution
- **RPi**: OTP-backed boot chain with signature verification
- **Android**: AVB 2.0 with vbmeta signing

### Firmware Encryption

- **AES-128-CTR** encryption for IP protection
- **Device-specific keys** prevent firmware cloning
- **ATECC608A support** (when hardware available)
- Bootloader decrypts and verifies before execution

## Security Model

### Threat Protection

| Threat | AVR | RPi | Android |
|--------|-----|-----|---------|
| Unsigned firmware | ✅ Bootloader verifies | ✅ OTP + signatures | ✅ AVB 2.0 |
| Firmware tampering | ✅ Ed25519 signatures | ✅ Signature chain | ✅ vbmeta |
| Rollback attacks | ✅ EEPROM counter | ✅ TPM NV counter | ✅ Rollback index |
| Firmware extraction | ✅ Lock bits 0xFC | ✅ Encrypted rootfs | ✅ FDE |
| Runtime tampering | ✅ Lock bits | ✅ dm-verity | ✅ dm-verity |

### Trust Chain

```
Platform CA (TPM-backed root)
  ├─ Firmware Signing CA (intermediate)
  │   ├─ AVR Firmware Signing Cert
  │   ├─ RPi Bootloader Signing Cert
  │   └─ Android System Signing Cert
  └─ Device Identity CA (intermediate)
      ├─ AVR Device Cert (arduino-001)
      ├─ RPi Device Cert (rpi-001)
      └─ Android Device Cert (pixel-7)
```

## Virtual Testing

Test firmware safely before flashing real hardware:

```bash
# Test AVR in simavr
platformctl firmware test \
  --input firmware.hex \
  --simulator simavr \
  --bootloader bootloader.hex

# Test RPi in QEMU
platformctl firmware rpi test-qemu \
  --boot-chain boot.img
```

**Benefits**:
- Zero risk of bricking hardware
- Fast iteration during development
- Verify signature verification logic
- Test attestation protocol

## Supply Chain Security

- **SLSA** provenance generation
- **SBOM** (CycloneDX/SPDX)
- Reproducible builds (Docker)
- Signed manifests

## Enterprise Features

- **Fleet Management WebUI**: Real-time device status, firmware versions
- **Metrics & Telemetry**: Prometheus/Grafana integration
- **Compliance**: Audit logs for SOC 2, ISO 27001
- **RBAC/ABAC**: Multi-user access control
- **HSM Integration**: YubiHSM, cloud HSM support (future)

## Next Steps

1. **Set up development environment**: Install Docker for firmware builds
2. **Read architecture**: See [architecture.md](architecture.md)
3. **Try examples**: Start with AVR hello-world firmware
4. **Configure devices**: See [configuration.md](configuration.md)
5. **Deploy**: Flash your first signed firmware

## Contributing

See [Roadmap](../../ROADMAP.md) for current status and development progress.

## Related Documentation

- [BIOS](bios.md) - BIOS standards and security guidelines
- [Secure Boot](secure-boot.md) - Automated Secure Boot implementation with native Go
- [UEFI Secure Boot](uefi-secure-boot.md) - UEFI Secure Boot concepts and key management
- [Authenticode](authenticode.md) - PE/COFF Authenticode code signing
- [UKI](uki.md) - Unified Kernel Image building and signing
- [UEFI](uefi.md) - UEFI firmware variables and key enrollment

## License

Dual-licensed under AGPL-3.0 and commercial license.
