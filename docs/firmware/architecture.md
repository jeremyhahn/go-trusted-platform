# Firmware Architecture

Comprehensive architecture for Trusted Platform Firmware support.

## Architecture Overview

Firmware support is **integrated into go-trusted-platform** as `pkg/firmware`, extending existing `pkg/ota`, `pkg/attestation`, and `pkg/device` packages rather than creating parallel systems.

## Key Decisions

| Decision | Rationale |
|----------|-----------|
| **Monorepo** | Avoids circular dependencies, unified signing/CA |
| **Extend existing packages** | Reuses pkg/ota, pkg/attestation, pkg/device |
| **Language-agnostic** | Users compile with any toolchain (avr-gcc, Rust, etc.) |
| **C bootloader** | Production C code from day 1, no TinyGo prototyping |
| **Universal OTA** | Single pkg/ota for AVR, RPi, Android, ARM64, AMD64 |
| **Universal Attestation** | Single pkg/attestation with multiple transports |
| **Flat YAML config** | Matches existing go-trusted-platform format |
| **TPM2_Quote only (RPi)** | Physical TPM or swtpm, no software fallback |

## Package Structure

```
pkg/firmware/
├── avr/              # AVR implementations
├── rpi/              # Raspberry Pi
├── android/          # Android/GrapheneOS  
├── signing/          # Firmware signing
├── trust/            # Trust management
├── encryption/       # Firmware encryption
└── testing/          # simavr/QEMU

pkg/ota/              # Extended for firmware
├── avr.go
├── rpi.go
└── android.go

pkg/attestation/      # Extended for firmware
├── avr.go
├── rpi.go
└── android.go

pkg/vtpm/             # Extended for swtpm
├── swtpm.go
├── bundle.go
└── installer.go
```

## Trust Model

```
Platform CA (TPM-backed root)
  ├─ Firmware Signing CA
  │   ├─ AVR Firmware Cert
  │   ├─ RPi Bootloader Cert
  │   └─ Android System Cert
  └─ Device Identity CA
      ├─ AVR Device Cert
      ├─ RPi Device Cert
      └─ Android Device Cert
```

## Platform-Specific Designs

### AVR
- C bootloader (4-6KB)
- Pseudo-OTP (EEPROM + EESAVE + lock bits)
- Ed25519 signature verification
- Golden image + staging OTA
- ATECC608A support (deferred)

### Raspberry Pi
- OTP-based secure boot
- Signed boot chain
- TPM2_Quote attestation (physical TPM or swtpm)
- A/B partition OTA
- Alpine Linux integration

### Android
- Native Go fastboot
- AVB 2.0 verification
- Hardware attestation API
- A/B seamless updates

See [ROADMAP.md](ROADMAP.md) for complete architecture details and development status.
