# Trusted Firmware Roadmap

```
STATUS: Phase 0 - Planned
Last Updated: 2026-01-02
```

## Executive Summary

Trusted Firmware extends go-trusted-platform with enterprise-grade firmware signing, attestation, and OTA updates for embedded devices. The implementation would integrate as `pkg/firmware` and extend the existing `pkg/attestation` and `pkg/device` packages. It would also have to create `pkg/ota` from scratch: despite the wording of earlier drafts, no OTA framework exists in this repo today.

**Supported Platforms:**
- AVR microcontrollers (ATmega, ATtiny, AVR-DA/DB)
- Raspberry Pi (all models with OTP-based secure boot)
- Android/GrapheneOS (native fastboot, AVB 2.0)

**Key Capabilities:**
- Language-agnostic firmware (compile with any toolchain)
- Universal OTA system across all platforms
- Universal attestation service (serial, TPM, BLE, LoRa, WiFi)
- Firmware encryption (AES-128-CTR) for IP protection
- Supply chain security (SLSA/SBOM)
- QuicBaaS integration (audit logging, RBAC/ABAC)

## Dependencies

| Dependency | Package | Status |
|------------|---------|--------|
| Certificate Authority | `pkg/ca` | Available |
| Code Signing | `pkg/authenticode` | Available |
| TPM Support | `pkg/vtpm` | Available |
| Device Profiles | `pkg/device` | Available |
| OTA Framework | `pkg/ota` | **Not started** - the package does not exist, and there is no OTA implementation anywhere in the tree. This roadmap has to build it, not extend it |
| Attestation Framework | `pkg/attestation` | Available |
| QuicBaaS | via `go-quicbaas/sdk/go` | Available - there is no `pkg/quicbaas`. The SDK is consumed directly, with local adapters at `pkg/storage/quicbaas`, `pkg/ca/quicbaas` and `pkg/acme/storage/quicbaas` |
| Alpine Installer | `pkg/installer` | Available |

---

## Milestone 1: Core Infrastructure

**Goal:** Package structure, device profiles, and universal service foundations

### Deliverables
- [ ] Working device profile system for firmware devices
- [ ] Universal OTA service skeleton
- [ ] Universal attestation service skeleton
- [ ] Virtual testing environment (simavr, QEMU)

### Tasks

**Package Structure**
- [ ] Create `pkg/firmware/` directory structure
- [ ] Create `docker/` directory for dev environments
- [ ] Create core interfaces (`types.go`, `signer.go`, `flasher.go`)

**Device Profile Extensions**
- [ ] Extend `pkg/device` with firmware-specific YAML schema
- [ ] Create device profile loader
- [ ] Add example profiles (AVR, RPi, Android)

**Universal Services**
- [ ] Define `OTAUpdater` interface in `pkg/ota`
- [ ] Create universal OTA orchestrator
- [ ] Define attestation transport interface in `pkg/attestation`
- [ ] Create universal attestation service
- [ ] Stub platform implementations (AVR, RPi, Android)

**Infrastructure**
- [ ] QuicBaaS schema: `firmware_devices` collection
- [ ] QuicBaaS schema: `firmware_audit` collection
- [ ] QuicBaaS schema: `firmware_versions` collection
- [ ] Extend `pkg/authenticode` for firmware signing (detached/embedded)
- [ ] simavr integration for AVR testing
- [ ] QEMU integration for RPi testing
- [ ] Mock ISP for unit testing

### Acceptance Criteria
- [ ] Device profiles load and validate correctly
- [ ] OTA interface compiles with stub implementations
- [ ] Attestation service skeleton passes unit tests
- [ ] simavr runs test firmware without errors

---

## Milestone 2: AVR Bootloader and Crypto

**Goal:** Production C bootloader with crypto auto-detection

### Deliverables
- [ ] Production C bootloader (4-6KB)
- [ ] Optional C library libtrusted-avr.a (1-3KB)
- [ ] Crypto auto-detection (Software/TPM/ATECC608A)
- [ ] 24KB+ user space verified on Arduino Nano

### Tasks

**C Bootloader**
- [ ] Create `pkg/firmware/avr/bootloader/` structure
- [ ] Implement Ed25519 signature verification
- [ ] Implement SHA256 hashing
- [ ] Implement boot logic and application jump
- [ ] Implement pseudo-OTP (EEPROM + EESAVE + lock bits)
- [ ] Implement OTA coordinator logic
- [ ] Implement AES-128-CTR decryption (optional)
- [ ] Build system (Makefile with Docker)
- [ ] Test in simavr

**Optional C Library**
- [ ] Create `pkg/firmware/avr/library/`
- [ ] Implement attestation helpers (~1KB)
- [ ] Implement ATECC608A helpers (~2KB)
- [ ] Implement crypto helpers (software fallback)
- [ ] Implement OTA helpers
- [ ] Build system and distribution

**Crypto Provider**
- [ ] Create `pkg/firmware/avr/crypto/` structure
- [ ] Define `CryptoProvider` interface
- [ ] Implement software crypto (Cgo wrappers: ed25519-donna, tinycrypt)
- [ ] Implement TPM support (reuse `pkg/vtpm`)
- [ ] Implement ATECC608A driver (I2C, auto-detection, key ops)
- [ ] Implement provisioning workflow
- [ ] Implement auto-detection logic (Software -> TPM -> ATECC608A)

**Target Definitions**
- [ ] Create `pkg/firmware/avr/targets/`
- [ ] Define ATmega targets (328p, 2560, 1280)
- [ ] Define ATtiny targets (85, 45)
- [ ] Define AVR-DA/DB targets
- [ ] Implement auto-detection via ISP

### Acceptance Criteria
- [ ] Bootloader compiles to under 6KB
- [ ] Ed25519 signature verification passes test vectors
- [ ] ATECC608A detected and operational (when present)
- [ ] Software fallback works on boards without secure element
- [ ] User application has 24KB+ available on ATmega328p

---

## Milestone 3: AVR ISP Flashing and Device Management

**Goal:** Native Go ISP implementation and firmware signing/flashing

### Deliverables
- [ ] Native Go ISP flashing (no avrdude dependency)
- [ ] Language-agnostic firmware support
- [ ] Integrated with universal OTA/attestation

### Tasks

**Native ISP Implementation**
- [ ] Create `pkg/firmware/avr/flasher/` structure
- [ ] Implement SPI-based ISP protocol
- [ ] Implement programming enable sequence
- [ ] Implement chip erase
- [ ] Implement page programming
- [ ] Implement readback verification
- [ ] Implement device signature reading
- [ ] Create lock bit manager (`pkg/firmware/avr/lockbits/`)
- [ ] Create fuse manager (`pkg/firmware/avr/fuses/`)
- [ ] Test with mock ISP
- [ ] Test with real hardware (dev boards)

**OTA Integration**
- [ ] Implement `pkg/ota/avr.go`
- [ ] Golden image + staging layout
- [ ] Download, verification, and promotion logic
- [ ] Rollback support
- [ ] Bootloader OTA coordination
- [ ] Test in simavr

**Attestation Integration**
- [ ] Implement `pkg/attestation/avr.go`
- [ ] Serial protocol implementation
- [ ] Lightweight attestation format (164 bytes)
- [ ] Signature generation and response handling
- [ ] Verification logic
- [ ] Test with mock device

**Enrollment**
- [ ] ACME enrollment (reuse device-attest-01)
- [ ] Firmware hash verification in challenge
- [ ] Device certificate issuance

**Rollback Protection**
- [ ] Create `pkg/firmware/avr/rollback/`
- [ ] EEPROM monotonic counter
- [ ] Version verification
- [ ] Integration with OTA

### Acceptance Criteria
- [ ] Flash signed firmware via native ISP
- [ ] Device responds to attestation requests
- [ ] Rollback protection rejects older firmware
- [ ] OTA update cycle completes successfully

---

## Milestone 4: Firmware Encryption and Supply Chain

**Goal:** IP protection and supply chain security

### Deliverables
- [ ] Encrypted firmware support
- [ ] Supply chain security (SLSA/SBOM)
- [ ] Delta updates working

### Tasks

**Firmware Encryption**
- [ ] Create `pkg/firmware/encryption/` structure
- [ ] Implement AES-128-CTR encryption
- [ ] Implement key derivation (device-specific)
- [ ] Implement IV generation
- [ ] Define encrypted firmware format
- [ ] Implement bootloader decryption (ATECC608A key unwrap, software fallback)
- [ ] Integrate with OTA
- [ ] Test in simavr

**Supply Chain Security**
- [ ] Create `pkg/firmware/supplychain/` structure
- [ ] Implement SLSA provenance generation
- [ ] Implement SBOM generation (CycloneDX, SPDX)
- [ ] Integrate with build process

**Delta Updates**
- [ ] Create `pkg/ota/delta/`
- [ ] Implement binary diff generation
- [ ] Implement patch application
- [ ] Verification logic
- [ ] Bandwidth testing

### Acceptance Criteria
- [ ] Encrypted firmware decrypts and boots correctly
- [ ] SLSA provenance validates against build
- [ ] SBOM contains accurate dependency information
- [ ] Delta updates reduce transfer size by 50%+

---

## Milestone 5: Raspberry Pi Support

**Goal:** RPi secure boot, OTP, recovery, and Alpine integration

### Deliverables
- [ ] RPi secure boot with OTP
- [ ] Alpine Linux integration
- [ ] Universal OTA for RPi
- [ ] USB recovery mode

### Tasks

**RPi Boot Chain**
- [ ] Create `pkg/firmware/rpi/` structure
- [ ] Implement boot chain builder
- [ ] Sign bootcode.bin, start4.elf, kernel8.img, initramfs
- [ ] Generate config.txt
- [ ] SD card image builder
- [ ] Test in QEMU

**OTP Programming**
- [ ] Create rpiboot Go wrapper
- [ ] Interface definition and implementation
- [ ] Config generation
- [ ] OTP programming
- [ ] Recovery mode support
- [ ] Document usage and warnings (irreversible operation)

**Alpine Linux Integration**
- [ ] Create `pkg/installer/alpine_rpi.go`
- [ ] RPi-specific image building
- [ ] Boot partition setup
- [ ] Rootfs creation
- [ ] Package installation
- [ ] Keep `pkg/installer/alpine.go` unchanged

**OTA Integration**
- [ ] Implement `pkg/ota/rpi.go`
- [ ] A/B partition layout
- [ ] Partition management
- [ ] Boot config switching
- [ ] Rollback support

**Attestation Integration**
- [ ] Implement `pkg/attestation/rpi.go`
- [ ] TPM2_Quote attestation (physical TPM or swtpm)
- [ ] Quote generation and verification

**Rollback Protection**
- [ ] TPM NV counter implementation
- [ ] Version verification
- [ ] Integration with OTA

### Acceptance Criteria
- [ ] Signed boot chain boots in QEMU
- [ ] OTP programming workflow documented
- [ ] USB recovery mode can unbrick device
- [ ] A/B OTA update completes successfully
- [ ] TPM2_Quote attestation verifies correctly

---

## Milestone 6: Android Support

**Goal:** Android device flashing, attestation, and OTA

### Deliverables
- [ ] Native fastboot implementation
- [ ] GrapheneOS support
- [ ] Android hardware attestation
- [ ] Universal OTA for Android

### Tasks

**Fastboot Implementation**
- [ ] Create `pkg/firmware/android/fastboot/` structure
- [ ] Implement native Go fastboot protocol
- [ ] USB communication (github.com/google/gousb)
- [ ] Command/response protocol
- [ ] Download, flash, getvar commands
- [ ] Lock/unlock bootloader
- [ ] Test with device

**GrapheneOS Integration**
- [ ] Create `pkg/firmware/android/grapheneos/` structure
- [ ] Boot image signing
- [ ] System image signing
- [ ] Vendor image signing
- [ ] Factory image building
- [ ] Documentation

**Android Attestation**
- [ ] Implement `pkg/attestation/android.go`
- [ ] Android hardware attestation API integration
- [ ] Certificate chain extraction
- [ ] Verification

**OTA Integration**
- [ ] Implement `pkg/ota/android.go`
- [ ] A/B seamless update support
- [ ] OTA package generation
- [ ] Update application
- [ ] Rollback support

### Acceptance Criteria
- [ ] Native fastboot flashes device
- [ ] GrapheneOS installation succeeds
- [ ] Android hardware attestation verifies
- [ ] A/B OTA updates work

---

## Milestone 7: Wireless Protocols and CLI

**Goal:** Wireless attestation transports and complete platformctl integration

### Deliverables
- [ ] Wireless attestation transports (BLE, LoRa, WiFi)
- [ ] Complete platformctl CLI
- [ ] QuicBaaS integration

### Tasks

**Wireless Transports**
- [ ] Create `pkg/attestation/wireless/` structure
- [ ] Implement BLE transport (GATT service, pairing)
- [ ] Implement LoRaWAN transport (downlink/uplink, gateway)
- [ ] Implement WiFi transport (HTTPS, certificate pinning)
- [ ] Integrate with universal attestation service

**QuicBaaS Integration**
- [ ] Complete schema extensions
- [ ] Audit logging (flash, attest, OTA, enroll events)
- [ ] RBAC/ABAC policies (firmware-admin, firmware-operator, firmware-viewer, device-owner)
- [ ] GraphQL API extensions

**platformctl Commands**
- [ ] `platformctl firmware sign`
- [ ] `platformctl firmware flash`
- [ ] `platformctl firmware attest`
- [ ] `platformctl firmware enroll`
- [ ] `platformctl firmware devices`
- [ ] `platformctl firmware test`
- [ ] `platformctl firmware encrypt`
- [ ] `platformctl ota update`
- [ ] `platformctl ota rollback`
- [ ] `platformctl ota status`
- [ ] `platformctl firmware atecc608a provision`
- [ ] `platformctl firmware atecc608a export-pubkey`
- [ ] `platformctl firmware atecc608a lock`
- [ ] `platformctl firmware rpi build-bootchain`
- [ ] `platformctl firmware rpi program-otp`
- [ ] `platformctl firmware rpi recovery`
- [ ] `platformctl firmware rpi flash-sdcard`

### Acceptance Criteria
- [ ] BLE attestation works within 30m range
- [ ] LoRaWAN attestation succeeds over gateway
- [ ] All CLI commands functional
- [ ] Audit events recorded in QuicBaaS

---

## Milestone 8: Examples, Documentation, and Fleet UI

**Goal:** Working examples, comprehensive documentation, fleet management

### Deliverables
- [ ] Working examples (AVR, RPi, Android)
- [ ] Comprehensive documentation
- [ ] Fleet management WebUI

### Tasks

**Examples**
- [ ] Hello World AVR (C firmware with README)
- [ ] IoT Sensor (AVR with attestation and OTA)
- [ ] Hello World RPi (Alpine Linux with TPM attestation)
- [ ] Secure bootloader reference implementation

**Documentation**
- [ ] Getting started guide
- [ ] Platform-specific guides (AVR, RPi, Android)
- [ ] Troubleshooting and FAQ
- [ ] Architecture overview
- [ ] API reference
- [ ] Security documentation (threat model, best practices)

**Fleet Management WebUI**
- [ ] Device list view
- [ ] Real-time attestation status
- [ ] Firmware version tracking
- [ ] OTA update management
- [ ] Audit log viewer
- [ ] RBAC configuration UI

**Trust Management**
- [ ] Firmware hash database
- [ ] Trusted firmware list management
- [ ] Trust verification logic
- [ ] Certificate management

### Acceptance Criteria
- [ ] Examples compile and run successfully
- [ ] Documentation covers all features
- [ ] WebUI displays device fleet status
- [ ] User satisfaction > 90%

---

## Milestone 9: Testing and Hardening

**Goal:** Security audit, performance optimization, production readiness

### Deliverables
- [ ] Security audit complete
- [ ] Performance targets met
- [ ] Production deployment ready

### Tasks

**Simulated Testing**
- [ ] simavr: bootloader, attestation, OTA, signature tests
- [ ] QEMU: RPi boot chain, Android boot, full system tests

**Virtual Hardware Testing**
- [ ] Test on cheap ATmega328p boards
- [ ] Test ISP programming
- [ ] Test EEPROM operations
- [ ] Test bootloader (without locking)
- [ ] Test attestation and OTA

**Physical Testing**
- [ ] Test on production Arduino boards (set EESAVE, lock bits LAST)
- [ ] Test on Raspberry Pi (OTP LAST - irreversible)
- [ ] Test on Android devices (fastboot, GrapheneOS, attestation)

**Security Hardening**
- [ ] Security audit of bootloader
- [ ] Constant-time crypto verification
- [ ] Side-channel analysis
- [ ] Fuzzing ISP protocol
- [ ] Fuzzing attestation protocol
- [ ] Penetration testing

**Performance Optimization**
- [ ] Bootloader size optimization
- [ ] ISP flashing speed
- [ ] OTA download optimization
- [ ] Delta update efficiency
- [ ] Attestation latency

**Production Readiness**
- [ ] Error handling review
- [ ] Logging improvements
- [ ] Metrics collection
- [ ] Alert system
- [ ] Monitoring dashboards
- [ ] Backup/recovery procedures

### Acceptance Criteria
- [ ] Security audit passes with no critical findings
- [ ] Bootloader fits in 4KB on ATmega328p
- [ ] Attestation latency < 100ms
- [ ] All integration tests pass
- [ ] Documentation complete

---

## Docker Development Environments

| Container | Purpose | Status |
|-----------|---------|--------|
| `docker/avr-dev.Dockerfile` | avr-gcc, avr-libc, simavr, Make | [ ] Not started |
| `docker/rpi-dev.Dockerfile` | ARM cross-compilation, QEMU, rpiboot | [ ] Not started |
| `docker/android-dev.Dockerfile` | Android SDK/NDK, fastboot tools | [ ] Not started |
| `docker/docker-compose.yml` | Dev environment orchestration | [ ] Not started |

---

## Success Criteria Summary

### AVR
- [ ] Compile firmware with any toolchain
- [ ] Sign firmware with platform CA
- [ ] Test bootloader in simavr
- [ ] Flash signed firmware via native ISP
- [ ] Bootloader verifies signatures
- [ ] Device responds to attestation (serial)
- [ ] Platform verifies attestation
- [ ] Rollback protection works
- [ ] OTA updates work
- [ ] 24KB+ available for user code
- [ ] Crypto auto-detection works

### Raspberry Pi
- [ ] Build signed boot chain
- [ ] Test in QEMU
- [ ] Program OTP
- [ ] USB recovery mode works
- [ ] Flash to SD card
- [ ] Boot with signed chain
- [ ] Attestation via TPM
- [ ] A/B OTA updates work
- [ ] Alpine Linux integration clean

### Android
- [ ] Native fastboot implementation works
- [ ] Flash GrapheneOS
- [ ] Android hardware attestation works
- [ ] A/B OTA updates work
- [ ] Boot image signing works

### Universal
- [ ] Single OTA system for all platforms
- [ ] Single attestation service for all platforms
- [ ] Unified device profiles
- [ ] Unified CLI (platformctl)
- [ ] All platforms use platform CA
- [ ] QuicBaaS integration complete
- [ ] WebUI fleet management working

---

## Notes

**Irreversible Operations:**
- AVR lock bits (Mode 3: 0xFC) - test thoroughly before setting
- RPi OTP programming - one-time only, cannot be undone

**Hardware for Testing:**
- Order cheap ATmega328p dev boards before using production hardware
- Test all operations in simavr/QEMU first

**Security:**
- Complete security audit before production deployment
- Document threat model and security guarantees

---

## Related Documentation

- [README.md](README.md) - Overview and quick start
- [architecture.md](architecture.md) - System design
- [configuration.md](configuration.md) - Configuration reference
- [avr.md](avr.md) - AVR implementation details
- [rpi.md](rpi.md) - Raspberry Pi details
- [android.md](android.md) - Android/GrapheneOS support
