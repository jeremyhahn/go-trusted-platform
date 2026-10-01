# AVR Microcontroller Implementation

> Part of the go-trusted-platform trusted firmware architecture

## Overview

This document details the AVR-specific implementation for trusted firmware capabilities, supporting all AVR families (ATmega, ATtiny, AVR-DA/DB) with language-agnostic compilation, secure boot, and hardware/software attestation.

## Supported Hardware

### ATmega Family
- **ATmega328P** (Arduino Uno/Nano): 32KB flash, 2KB SRAM, 1KB EEPROM
- **ATmega2560** (Arduino Mega): 256KB flash, 8KB SRAM, 4KB EEPROM
- **ATmega1280**: 128KB flash, 8KB SRAM, 4KB EEPROM

### ATtiny Family
- **ATtiny85**: 8KB flash (no bootloader section, signature-only)
- **ATtiny45**: 4KB flash (signature-only)

### AVR-DA/DB Family
- Modern AVR with enhanced security features
- More flash, better crypto performance

## Flash Memory Layout (ATmega328P Example)

```
┌─────────────────────────────┐ 0x0000
│   Application Area          │ User firmware
│   (28KB)                    │ 0x0000 - 0x6FFF
│                             │
├─────────────────────────────┤ 0x7000
│   Bootloader Section        │ Signature verification
│   (4KB)                     │ OTA coordinator
│                             │ Boot logic
└─────────────────────────────┘ 0x8000 (32KB)

EEPROM Layout (1KB):
┌─────────────────────────────┐ 0x000
│   Pubkey Hash (32 bytes)    │ SHA256 of bootloader public key
├─────────────────────────────┤ 0x020
│   Device Serial (16 bytes)  │ Device identifier
├─────────────────────────────┤ 0x030
│   Boot Counter (4 bytes)    │ Monotonic counter
├─────────────────────────────┤ 0x034
│   FW Version (4 bytes)      │ Current firmware version
├─────────────────────────────┤ 0x038
│   Active Slot (1 byte)      │ 0=Golden, 1=Active
├─────────────────────────────┤ 0x039
│   Update Flags (1 byte)     │ OTA state machine
├─────────────────────────────┤ 0x03A
│   Reserved (86 bytes)       │ Platform use
├─────────────────────────────┤ 0x080 (128 bytes used)
│   User Area (896 bytes)     │ Available for application
└─────────────────────────────┘ 0x400 (1KB)
```

## Flash Constraints & Budget

### Arduino Nano (ATmega328P - 32KB Flash)

> **CORRECTED 2026-09-23 against a measured implementation.** Every figure in
> the original breakdown was an estimate; `jeremyhahn/arduino-generic` has since
> built this bootloader and measured it with avr-gcc 14.2 at `-Os -flto
> --gc-sections`. Two of the estimates were not close, and one of them decided
> an architectural choice this document then recommended. Reproduce with
> `make bootloader-budget` and `make boot-core-size` in that repository.

**Breakdown**:
- **Bootloader**: it does not fit in 4-6KB in the form this document describes.
  The ATmega328P's boot section is **4096 bytes and that is `BOOTSZ`'s largest
  setting** — there is no 6KB option to select.
  - ~~Ed25519 verification: ~2KB~~ → **72,930 bytes measured** for
    ed25519-donna's verify path with nothing reachable but `ed25519_sign_open`.
    That is 17.8x the whole boot section and 2.2x the part's entire flash, and
    its single largest stack frame (2,950 bytes) exceeds the part's total SRAM.
    A single rodata table, `ge25519_niels_sliding_multiples`, is 3,840 bytes —
    94% of the boot section before one instruction of code. donna also assumes
    a 32-bit `int`, so it is *wrong* on this target before it is too big for it.
  - SHA256 hashing: ~1KB → **4,052 bytes measured**, rolled loops, `-Os`.
  - Boot logic: ~0.5KB → **1,238 bytes** for measure, compare, pin and rollback.
  - OTA coordinator: ~0.5KB → **2,220 bytes** with its framing.
  - CDI handoff: **802 bytes** (absent from the original breakdown).

  **Totals, measured:** the core with *no signature backend at all* is 7,908
  bytes — 3,812 over the section before a primitive is chosen. So the finding is
  not that Ed25519 is too big; it is that a 4KB AVR boot section cannot hold a
  hash, a boot decision and an update path together.

  **What fits:** put both the hash and the signature check in the ATECC608A and
  the boot section holds no cryptography at all — **2,368 bytes of 4,096** on an
  ATmega328P, 2,436 on a 32U4, 2,542 on a 2560. `Verify` runs in **stored mode**
  against a locked element slot rather than external mode, so an attacker who
  rewrites every byte of flash cannot substitute the signing key. The costs are
  real and stated: the element hashes 64 bytes per command, so a 28KB image is
  ~450 round trips and seconds of boot; and OTA leaves the boot section, so
  recovery on a 4KB part needs a programmer.

  **Secure boot on AVR therefore requires an element.** A board without one gets
  measured boot — the platform refuses to trust a device whose `FWHash` does not
  match the golden build — but a tampered image still runs locally until the
  next attestation. See `docs/security/bootloader.md` in arduino-generic.
- **Optional libtrusted-avr.a**: 1-3KB (if user links it)
  - Attestation helpers: ~1KB
  - ATECC608A helpers: ~2KB
- **User Application**: **24-26KB** ✅

**SRAM**: 2KB (bootloader runs separately, doesn't affect application SRAM)

**EEPROM**: 1KB (128 bytes reserved, 896 bytes free for user)

### OTA Flash Layout (Advanced)

For devices with OTA support, flash can be partitioned:

> **CORRECTED 2026-09-23.** This layout is not buildable on an ATmega328P and
> two of its errors would not surface until someone flashed a part.
>
> **The boot section is not at 0x0000.** On every classic AVR it is at the TOP
> of flash — `BOOTRST` vectors reset to `BOOTSZ` bytes below the end, which is
> 0x7000 on a 328P with a 4KB section. The correct map is the one in "Flash
> Memory Layout" above, which this diagram contradicts.
>
> **And the partitions do not fit.** 4-6KB + 12KB + 12KB + 2KB is 30-32KB of a
> 32KB part with the interrupt vectors, the application and the bootloader all
> still to place.
>
> A/B slots are not available on this part at all: 28KB of application plus 28KB
> of staging does not fit 32KB of flash. arduino-generic updates **in place**
> and keeps a `STAGED` marker in reserved EEPROM, so an interrupted update
> leaves the device in the bootloader rather than bricked — the recovery is the
> bootloader. A part with external flash or a larger device can have A/B; a bare
> 328P cannot, and pretending otherwise produces a layout that is only
> discovered to be impossible during bring-up.

## Language-Agnostic Compilation

### Supported Toolchains

Users can compile firmware with **any toolchain**:
- **avr-gcc** (standard C compiler)
- **Rust** (via avr-rust)
- **Arduino IDE** (C++ with Arduino framework)
- **PlatformIO** (multiple frameworks)

### Optional C Library

**libtrusted-avr.a** (~1-3KB) provides optional helpers:

```c
// Attestation API
void attestation_init(const char* device_id);
int attestation_respond(uint8_t* nonce, uint8_t* response);

// Crypto API (if not using ATECC608A)
void sha256(uint8_t* data, size_t len, uint8_t* hash);

// ATECC608A API (if hardware present)
int atecc608a_sign(uint8_t* hash, uint8_t* signature);
int atecc608a_verify(uint8_t* hash, uint8_t* sig, uint8_t* pubkey);
int atecc608a_random(uint8_t* output);

// OTA API
void ota_check_update(void);
bool ota_pending(void);
```

### Compilation Workflow

```bash
# 1. User compiles firmware with their preferred toolchain
avr-gcc -mmcu=atmega328p -o firmware.elf main.c -ltrusted-avr  # Optional lib
avr-objcopy -O ihex firmware.elf firmware.hex

# 2. go-trusted-platform signs the firmware
platformctl firmware sign firmware.hex --device arduino-001

# 3. Flash to device
platformctl firmware flash firmware.hex --device arduino-001 --verify
```

## Secure Bootloader

### Pseudo-OTP Root of Trust

The bootloader implements a **pseudo-OTP** (One-Time Programmable) root of trust using:

**Hardware Mechanisms**:
1. **EEPROM Storage**: Store SHA256 hash of bootloader public key (32 bytes)
2. **EESAVE Fuse = 0**: EEPROM survives chip erase (pseudo-permanent)
3. **Lock Bits = 0xFC** (Mode 3): Prevents external read/write of flash/EEPROM
4. **JTAG Fuse = 1**: Disables hardware debugger access
5. **BLB Bits**: Prevent application from modifying bootloader

**Security Guarantees**:
- ✅ Runtime tamper protection (lock bits prevent ISP write)
- ✅ Bootloader verifies application signature before execution
- ✅ Boot counter detects unexpected resets
- ✅ Public key hash provides root of trust
- ❌ NOT protected against physical chip erase + reprogram (acceptable)

### Bootloader Implementation

**Location**: `pkg/firmware/avr/bootloader/`

**main.c** - Core bootloader logic:
```c
void bootloader_main() {
    // 1. Increment boot counter
    uint32_t boot_count = eeprom_read_dword(BOOT_COUNTER_ADDR);
    eeprom_write_dword(BOOT_COUNTER_ADDR, boot_count + 1);

    // 2. Check for OTA update pending
    uint8_t flags = eeprom_read_byte(UPDATE_FLAGS_ADDR);

    if (flags & FLAG_UPDATE_PENDING) {
        // OTA update mode
        if (verify_signature(ACTIVE_SLOT)) {
            // Update successful
            eeprom_write_byte(UPDATE_FLAGS_ADDR, FLAG_UPDATE_SUCCESS);
            jump_to_application(ACTIVE_SLOT);
        } else {
            // Signature failed, rollback to golden image
            eeprom_write_byte(UPDATE_FLAGS_ADDR, FLAG_UPDATE_FAILED);
            jump_to_application(GOLDEN_SLOT);
        }
    } else {
        // Normal boot
        if (verify_signature(APPLICATION_START)) {
            jump_to_application(APPLICATION_START);
        } else {
            // Signature invalid, halt with error LED
            error_halt();
        }
    }
}

bool verify_signature(uint16_t app_addr) {
    // 1. Read public key hash from EEPROM
    uint8_t stored_hash[32];
    eeprom_read_block(stored_hash, PUBKEY_HASH_ADDR, 32);

    // 2. Compute hash of embedded public key
    uint8_t computed_hash[32];
    sha256(EMBEDDED_PUBKEY, 32, computed_hash);

    // 3. Verify hashes match (root of trust)
    if (memcmp(stored_hash, computed_hash, 32) != 0) {
        return false;
    }

    // 4. Compute application firmware hash
    uint8_t fw_hash[32];
    hash_flash_range(app_addr, APP_SIZE, fw_hash);

    // 5. Read signature from flash metadata
    uint8_t signature[64];
    read_flash_metadata(app_addr, SIG_OFFSET, signature, 64);

    // 6. Verify signature
    return ed25519_verify(signature, fw_hash, EMBEDDED_PUBKEY);
}
```

**verify.c** - Ed25519 signature verification:
```c
#include "ed25519-donna/ed25519.h"

bool ed25519_verify(const uint8_t* sig, const uint8_t* msg,
                    const uint8_t* pubkey) {
    return ed25519_sign_open(msg, 32, pubkey, sig) == 0;
}
```

**otp.c** - EEPROM pseudo-OTP manager:
```c
void otp_write_pubkey_hash(const uint8_t* hash) {
    // Write hash to EEPROM (only done once during provisioning)
    eeprom_write_block(hash, PUBKEY_HASH_ADDR, 32);
}

bool otp_verify_pubkey_hash(const uint8_t* pubkey) {
    uint8_t stored_hash[32];
    uint8_t computed_hash[32];

    eeprom_read_block(stored_hash, PUBKEY_HASH_ADDR, 32);
    sha256(pubkey, 32, computed_hash);

    return memcmp(stored_hash, computed_hash, 32) == 0;
}
```

### Build System

**Makefile** (in pkg/firmware/avr/bootloader/):
```makefile
MCU = atmega328p
F_CPU = 16000000UL
BOOTLOADER_START = 0x7000

CC = avr-gcc
OBJCOPY = avr-objcopy
SIZE = avr-size

CFLAGS = -mmcu=$(MCU) -DF_CPU=$(F_CPU) -Os -Wall
CFLAGS += -DBOOTLOADER_START=$(BOOTLOADER_START)
LDFLAGS = -Wl,--section-start=.text=$(BOOTLOADER_START)

SOURCES = main.c verify.c otp.c sha256.c
OBJECTS = $(SOURCES:.c=.o)

bootloader.hex: bootloader.elf
	$(OBJCOPY) -O ihex -R .eeprom $< $@
	$(SIZE) bootloader.elf

bootloader.elf: $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJECTS) bootloader.elf bootloader.hex
```

## Native ISP Protocol Implementation

### ISP Overview

**ISP (In-System Programming)** is the SPI-based protocol for programming AVR chips.

**Physical Interface**:
- **SCK** (Clock): SPI clock line
- **MISO** (Master In, Slave Out): Data from AVR
- **MOSI** (Master Out, Slave In): Data to AVR
- **RESET**: Active-low reset (must be asserted for programming)
- **VCC/GND**: Power

### Hardware Options

1. **Raspberry Pi GPIO**
   - Use SPI peripheral + GPIO for RESET
   - Cost: $0 (if you have a Pi)
   - Speed: Fast (hardware SPI)

2. **USB-to-SPI Adapters**
   - FT232H (~$15)
   - CH341A (~$5)
   - Bus Pirate (~$30)

3. **Arduino as ISP**
   - Use another Arduino as programmer
   - Cost: ~$3 (Arduino Nano clone)

### Go Implementation

**Location**: `pkg/firmware/avr/flasher/isp.go`

```go
package flasher

import (
    "periph.io/x/conn/v3/gpio"
    "periph.io/x/conn/v3/spi"
)

type ISPFlasher struct {
    spi    spi.Conn
    reset  gpio.PinOut
    target *Target
    logger *logging.Logger
}

func NewISPFlasher(spiConn spi.Conn, resetPin gpio.PinOut) *ISPFlasher {
    return &ISPFlasher{
        spi:   spiConn,
        reset: resetPin,
    }
}

func (f *ISPFlasher) Flash(firmware *SignedFirmware) error {
    // 1. Verify signature BEFORE flashing (supply chain integrity)
    if err := firmware.VerifySignature(); err != nil {
        return fmt.Errorf("signature verification failed: %w", err)
    }

    // 2. Enter programming mode
    if err := f.enterProgrammingMode(); err != nil {
        return err
    }
    defer f.exitProgrammingMode()

    // 3. Read device signature (verify correct chip)
    sig, err := f.readDeviceSignature()
    if err != nil {
        return err
    }

    target, err := DetectTarget(sig)
    if err != nil {
        return fmt.Errorf("unknown device: %w", err)
    }
    f.target = target

    // 4. Erase chip (preserves EEPROM if EESAVE fuse set)
    if err := f.eraseChip(); err != nil {
        return err
    }

    // 5. Program flash memory page by page
    if err := f.programFlash(firmware.Data); err != nil {
        return err
    }

    // 6. Verify programming via readback
    if err := f.verifyFlash(firmware.Data); err != nil {
        return err
    }

    // 7. Set fuses (EESAVE, disable JTAG)
    if err := f.setFuses(); err != nil {
        return err
    }

    // 8. Set lock bits (mode 3: 0xFC for production)
    if err := f.setLockBits(0xFC); err != nil {
        return err
    }

    return nil
}

func (f *ISPFlasher) enterProgrammingMode() error {
    // 1. Assert RESET (low)
    f.reset.Out(gpio.Low)
    time.Sleep(20 * time.Millisecond)

    // 2. Send Programming Enable command
    cmd := []byte{0xAC, 0x53, 0x00, 0x00}
    resp := make([]byte, 4)

    if err := f.spi.Tx(cmd, resp); err != nil {
        return err
    }

    // 3. Check response (should be 0x53 echoed back)
    if resp[2] != 0x53 {
        return fmt.Errorf("programming enable failed")
    }

    return nil
}

func (f *ISPFlasher) programFlash(data []byte) error {
    pageSize := f.target.PageSize
    numPages := (len(data) + pageSize - 1) / pageSize

    for page := 0; page < numPages; page++ {
        start := page * pageSize
        end := start + pageSize
        if end > len(data) {
            end = len(data)
        }

        if err := f.programPage(page, data[start:end]); err != nil {
            return fmt.Errorf("programming page %d failed: %w", page, err)
        }
    }

    return nil
}

func (f *ISPFlasher) programPage(pageNum int, data []byte) error {
    // 1. Load page buffer
    for i, b := range data {
        addr := uint16(i)

        // Load low byte
        cmd := []byte{
            0x40,
            byte(addr >> 8),
            byte(addr),
            b,
        }
        if err := f.spi.Tx(cmd, nil); err != nil {
            return err
        }
    }

    // 2. Write page to flash
    pageAddr := uint16(pageNum) * f.target.PageSize
    cmd := []byte{
        0x4C,
        byte(pageAddr >> 8),
        byte(pageAddr),
        0x00,
    }

    if err := f.spi.Tx(cmd, nil); err != nil {
        return err
    }

    // 3. Wait for write to complete
    time.Sleep(5 * time.Millisecond)

    return nil
}

func (f *ISPFlasher) setLockBits(bits byte) error {
    cmd := []byte{0xAC, 0xE0, 0x00, bits}
    return f.spi.Tx(cmd, nil)
}
```

### Lock Bits Management

**Location**: `pkg/firmware/avr/lockbits/manager.go`

**Lock Bit Modes**:
- **0xFF**: No protection (default, development)
- **0xFE**: Mode 2 (partial protection, testing)
- **0xFC**: Mode 3 (full protection, production)

**Effects of Mode 3 (0xFC)**:
- External ISP cannot read flash
- External ISP cannot write flash
- External ISP cannot read EEPROM
- External ISP cannot write EEPROM
- Application cannot write to boot section
- **Only chip erase can clear** (destructive)

```go
package lockbits

const (
    LockModeNone    = 0xFF  // No protection
    LockModePartial = 0xFE  // Mode 2
    LockModeFull    = 0xFC  // Mode 3 (production)
)

type LockManager struct {
    flasher *ISPFlasher
}

func (lm *LockManager) SetLockBits(mode byte) error {
    // Warn user if setting full protection
    if mode == LockModeFull {
        log.Warn("Setting lock bits to mode 3 (0xFC) - only chip erase can reverse this!")
    }

    return lm.flasher.setLockBits(mode)
}

func (lm *LockManager) ReadLockBits() (byte, error) {
    cmd := []byte{0x58, 0x00, 0x00, 0x00}
    resp := make([]byte, 4)

    if err := lm.flasher.spi.Tx(cmd, resp); err != nil {
        return 0, err
    }

    return resp[3], nil
}
```

## Hardware Security: ATECC608A

### Overview

**ATECC608A** is a $0.60 secure element providing hardware crypto and key storage.

**Features**:
- Private keys never leave chip
- Hardware ECDSA (P-256)
- ~~Ed25519~~ — **CORRECTED 2026-09-23: the ATECC608A has no hardware Ed25519.**
  Its asymmetric primitives are P-256 only (`Sign`, `Verify`, `GenKey`, `ECDH`).
  This claim is why the original document reached for Ed25519 in the bootloader;
  element signing and element image verification are both ECDSA P-256.
- Hardware SHA256, AES-128
- 16 key slots
- OTP zones for permanent data
- I2C interface (easy AVR integration)
- Common Criteria EAL6+, FIPS 140-2 Level 2

### Auto-Detection

**Location**: `pkg/firmware/avr/crypto/atecc608a/detect.go`

```go
func DetectATECC608A() (*ATECC608A, error) {
    // 1. Scan I2C bus for device at 0x60
    bus, err := i2c.New(i2c.Address(0x60))
    if err != nil {
        return nil, err
    }

    // 2. Wake device (toggle SCL for 60us)
    if err := wakeDevice(bus); err != nil {
        return nil, err
    }

    // 3. Read device revision
    rev, err := readRevision(bus)
    if err != nil {
        return nil, err
    }

    // 4. Verify it's ATECC608A (rev 0x6000 or 0x6002)
    if rev != 0x6000 && rev != 0x6002 {
        return nil, fmt.Errorf("not an ATECC608A (rev: 0x%04x)", rev)
    }

    return &ATECC608A{i2c: bus}, nil
}
```

### Unified Crypto Provider

**Location**: `pkg/firmware/avr/crypto/crypto.go`

```go
type CryptoProvider interface {
    Sign(data [32]byte) ([64]byte, error)
    Verify(hash [32]byte, sig [64]byte, pubkey [64]byte) (bool, error)
    Hash(data []byte) ([32]byte, error)
    Random() ([32]byte, error)
}

func NewCryptoProvider() CryptoProvider {
    // Try ATECC608A first
    if chip, err := atecc608a.DetectATECC608A(); err == nil {
        log.Info("Using ATECC608A hardware crypto")
        return &HardwareCrypto{chip: chip}
    }

    // Try TPM (if available)
    if tpm, err := vtpm.Open(); err == nil {
        log.Info("Using TPM hardware crypto")
        return &TPMCrypto{tpm: tpm}
    }

    // Fall back to software crypto
    log.Warn("No hardware crypto detected, using software implementation")
    return &SoftwareCrypto{}
}
```

### ATECC608A Driver

**Location**: `pkg/firmware/avr/crypto/atecc608a/device.go`

```go
type ATECC608A struct {
    i2c     *i2c.Device
    address byte
}

func (a *ATECC608A) Sign(hash [32]byte, slotID int) ([64]byte, error) {
    // Build ECDSA sign command
    cmd := buildCommand(CMD_SIGN, slotID, hash[:])

    // Execute command
    resp, err := a.executeCommand(cmd)
    if err != nil {
        return [64]byte{}, err
    }

    // Return signature
    var sig [64]byte
    copy(sig[:], resp)
    return sig, nil
}

func (a *ATECC608A) GenKey(slotID int) ([64]byte, error) {
    // Generate key pair in slot
    cmd := buildCommand(CMD_GENKEY, slotID, nil)

    resp, err := a.executeCommand(cmd)
    if err != nil {
        return [64]byte{}, err
    }

    // Return public key
    var pubkey [64]byte
    copy(pubkey[:], resp)
    return pubkey, nil
}

func (a *ATECC608A) Lock() error {
    // Lock configuration (one-time, irreversible)
    cmd := buildCommand(CMD_LOCK, 0, nil)
    _, err := a.executeCommand(cmd)
    return err
}
```

### Provisioning Workflow

> **AMENDED 2026-09-23. This flow produces signed-measurement attestation, not
> DICE, and the difference is the whole point of the feature.**
>
> `GenKey` → `export-pubkey` → `lock-data` gives the device a **static random
> key**. It proves the device holds a key the factory recorded. It does not bind
> the device's identity to what the device is *running*, which is what DICE is
> for and what makes a measurement worth attesting to — with a static key, a
> device whose firmware was replaced signs with exactly the same key as before.
>
> DICE derives the identity from `CDI = HMAC(UDS, H(firmware))`, so changing the
> firmware changes the identity. The ATECC608A cannot derive a P-256 key from a
> CDI — there is no such command — so the implementation follows DICE's own
> layering instead: the DeviceID key is element-resident and acts as the ECA
> (Layering Architecture §8.1.1.5), and the measurement binding lives in the CDI,
> computed by the element's own HMAC so the UDS never crosses the bus.
>
> Three profiles, in `docs/attestation/dice-profiles.md` in arduino-generic:
> **DICE-TPM** (discrete TPM), **DICE-HW** (ATECC608A), **DICE-SW** (neither,
> and it reports `notSecure` and means it).
>
> Two further corrections to the steps below. **The UDS must not come from the
> host** — step 1 as written has the platform generate and see key material; the
> implementation seeds it from the element's own TRNG so a compromised
> provisioning station learns nothing. And **`Lock` must carry its summary CRC**:
> the element accepts a no-CRC form that locks without checking the zone holds
> what you believe it holds, and on a part with no erase and no reset that turns
> one transcription error into scrap.
>
> See `docs/security/provisioning.md` in arduino-generic for the corrected
> sequence and its failure modes.

```bash
# 1. Generate device key pair in slot 0
platformctl firmware atecc608a provision --slot 0 --generate-key

# 2. Export public key
platformctl firmware atecc608a export-pubkey --slot 0 --output device-pubkey.pem

# 3. Create CSR and sign with platform CA
platformctl ca sign-csr --csr device.csr --output device.crt

# 4. Write device serial to OTP zone
platformctl firmware atecc608a write-otp --serial-number "AVR-001-2025"

# 5. Lock configuration (irreversible!)
platformctl firmware atecc608a lock-config

# 6. Lock data zone (irreversible!)
platformctl firmware atecc608a lock-data
```

## Attestation Protocol

### Lightweight Attestation Format

**Size**: 164 bytes (optimized for low bandwidth)

> **AMENDED 2026-09-23.** Two changes, both from implementing it.
>
> **`Timestamp` → `UptimeMs`.** No AVR in scope has a real-time clock. A device
> cannot report a wall-clock time it does not have, and a verifier must never
> take freshness from one it could: freshness is *always* the verifier's nonce.
> The gateway stamps `CreatedAt` when it relays.
>
> **An `AlgID` byte**, taken from `Reserved`. The evidence now says which
> primitive signed it rather than the verifier knowing out of band. Both ECDSA
> P-256 `r‖s` and Ed25519 `R‖S` are exactly 64 raw bytes, so the frame size is
> unchanged and only the interpretation differs.

```
[Version:1][Nonce:16][DeviceID:16][FWHash:32][BootCount:4][UptimeMs:4][AlgID:1][Signature:64][Reserved:26]
```

### Serial Attestation

**Location**: `pkg/firmware/avr/attestation/serial.go`

```go
type SerialAttestor struct {
    port      *serial.Port
    crypto    CryptoProvider
    deviceID  string
}

func (a *SerialAttestor) RequestAttestation(nonce [16]byte) (*Attestation, error) {
    // 1. Send attestation request
    req := &AttestationRequest{
        Version: 1,
        Nonce:   nonce,
    }

    if err := a.port.Write(req.Marshal()); err != nil {
        return nil, err
    }

    // 2. Read attestation response
    resp := make([]byte, 164)
    if _, err := io.ReadFull(a.port, resp); err != nil {
        return nil, err
    }

    // 3. Parse attestation
    return ParseAttestation(resp)
}
```

### Device-Side Implementation (C)

**Firmware code** (linked with libtrusted-avr.a):

```c
#include <trusted-avr.h>

void handle_attestation_request() {
    AttestationRequest req;

    // 1. Read request from serial
    serial_read(&req, sizeof(req));

    // 2. Build attestation data
    AttestationData data = {
        .version = 1,
        .nonce = req.nonce,
        .device_id = DEVICE_ID,
        .fw_hash = get_firmware_hash(),
        .boot_count = eeprom_read_dword(BOOT_COUNTER_ADDR),
        .timestamp = get_timestamp(),
    };

    // 3. Sign with device key (ATECC608A or software)
    uint8_t signature[64];
    crypto_sign(hash(&data), signature);

    // 4. Build attestation
    Attestation attest = {
        .data = data,
        .signature = signature,
    };

    // 5. Send response
    serial_write(&attest, sizeof(attest));
}
```

## OTA Updates

### AVR OTA Strategy

**Golden Image + Staging**:

```
Bootloader (0x7000-0x7FFF)
  ↓ coordinates updates
Golden Image (0x0000-0x3FFF)  ← Fallback (never overwritten)
Staging Area (0x4000-0x6FFF)  ← Download new firmware here
```

### OTA Update Flow

**Location**: `pkg/ota/avr.go`

```go
type AVROTAUpdater struct {
    flasher *ISPFlasher
    crypto  CryptoProvider
}

func (u *AVROTAUpdater) Update(manifestURL string) error {
    // 1. Download manifest
    manifest := downloadManifest(manifestURL)

    // 2. Verify manifest signature
    if !verifyManifest(manifest) {
        return errors.New("invalid manifest signature")
    }

    // 3. Check version (rollback protection)
    currentVersion := readCurrentVersion()
    if manifest.Version <= currentVersion {
        return errors.New("rollback detected")
    }

    // 4. Download encrypted firmware to staging
    downloadToStaging(manifest.FirmwareURL)

    // 5. Verify firmware hash
    if !verifyHash(manifest.Hash) {
        return errors.New("hash mismatch")
    }

    // 6. Set OTA pending flag
    setOTAPending()

    // 7. Reboot (bootloader will verify and activate)
    reboot()

    return nil
}
```

### Bootloader OTA Logic

```c
void bootloader_ota_check() {
    if (eeprom_read_byte(UPDATE_FLAGS_ADDR) & FLAG_UPDATE_PENDING) {
        // Decrypt staging firmware (if encrypted)
        decrypt_staging();

        // Verify signature
        if (verify_signature(STAGING_AREA)) {
            // Copy staging to active
            copy_flash(STAGING_AREA, ACTIVE_AREA, APP_SIZE);

            // Update version counter
            uint32_t version = read_staging_version();
            eeprom_write_dword(FW_VERSION_ADDR, version);

            // Clear pending flag
            eeprom_write_byte(UPDATE_FLAGS_ADDR, FLAG_UPDATE_SUCCESS);

            jump_to_application(ACTIVE_AREA);
        } else {
            // Signature failed, rollback to golden
            eeprom_write_byte(UPDATE_FLAGS_ADDR, FLAG_UPDATE_FAILED);
            jump_to_application(GOLDEN_AREA);
        }
    }
}
```

## Firmware Encryption

### AES-128-CTR Encryption

**Purpose**: Protect IP, prevent firmware cloning

**Key Management**:
1. **ATECC608A**: FEK stored in slot 1, decrypted by bootloader
2. **Software**: FEK derived from device serial + platform secret

### Encryption Flow

**Location**: `pkg/firmware/encryption/encryptor.go`

```go
func (e *Encryptor) Encrypt(firmware []byte, deviceID string) (*EncryptedFirmware, error) {
    // 1. Generate random IV
    iv := make([]byte, 16)
    rand.Read(iv)

    // 2. Derive device-specific key
    fek := deriveDeviceKey(deviceID, e.platformSecret)

    // 3. Encrypt with AES-128-CTR
    block, _ := aes.NewCipher(fek)
    stream := cipher.NewCTR(block, iv)
    ciphertext := make([]byte, len(firmware))
    stream.XORKeyStream(ciphertext, firmware)

    // 4. For ATECC608A: wrap FEK with device public key
    wrappedKey := wrapKeyForDevice(fek, deviceID)

    return &EncryptedFirmware{
        Ciphertext: ciphertext,
        IV:         iv,
        WrappedKey: wrappedKey,
    }, nil
}
```

### Bootloader Decryption

```c
void decrypt_firmware() {
    // 1. Read IV from metadata
    uint8_t iv[16];
    read_metadata(IV_OFFSET, iv, 16);

    // 2. Get FEK from ATECC608A or derive from serial
    uint8_t fek[16];
    #ifdef ATECC608A
        atecc608a_unwrap_key(SLOT_1, wrapped_key, fek);
    #else
        derive_key_from_serial(device_serial, fek);
    #endif

    // 3. Decrypt firmware page by page
    for (uint16_t page = 0; page < num_pages; page++) {
        // Read encrypted page
        read_flash_page(STAGING_AREA + page * PAGE_SIZE, buffer);

        // Decrypt
        aes128_ctr_decrypt(buffer, PAGE_SIZE, fek, iv, page);

        // Write decrypted page
        write_flash_page(ACTIVE_AREA + page * PAGE_SIZE, buffer);
    }
}
```

## Testing

### simavr Integration

**Location**: `pkg/firmware/testing/simavr.go`

```go
type SimAVR struct {
    binary    string
    firmware  string
    logger    *logging.Logger
}

func (s *SimAVR) Run() error {
    cmd := exec.Command("simavr",
        "-m", "atmega328p",
        "-f", "16000000",
        s.firmware,
    )

    return cmd.Run()
}
```

### Testing Workflow

```bash
# 1. Build bootloader
cd pkg/firmware/avr/bootloader
make

# 2. Build test firmware
avr-gcc -mmcu=atmega328p test.c -o test.elf
avr-objcopy -O ihex test.elf test.hex

# 3. Test in simavr
platformctl firmware test --input test.hex --simulator simavr --bootloader bootloader.hex

# 4. Only after simulation passes: test on real hardware
platformctl firmware flash test.hex --port /dev/ttyUSB0 --verify
```

## CLI Commands

```bash
# Build firmware (if using TinyGo, optional)
platformctl firmware build --source ./src --target atmega328p --output firmware.hex

# Sign firmware
platformctl firmware sign --input firmware.hex --device arduino-001

# Flash to device
platformctl firmware flash --input firmware.hex --port /dev/ttyUSB0 --verify

# Flash with lock bits (production)
platformctl firmware flash --input firmware.hex --port /dev/ttyUSB0 --verify --lock --production

# Attest device
platformctl firmware attest --device-id arduino-001 --port /dev/ttyUSB0

# Test in simulator
platformctl firmware test --input firmware.hex --simulator simavr

# OTA update
platformctl ota update --device-id arduino-001 --version 1.2.3

# ATECC608A provisioning
platformctl firmware atecc608a provision --slot 0 --generate-key
platformctl firmware atecc608a export-pubkey --slot 0 --output pubkey.pem
platformctl firmware atecc608a lock-config
```

## Implementation Files

### Core AVR Files

1. **pkg/firmware/avr/bootloader/** - C bootloader implementation
   - main.c - Boot logic
   - verify.c - Ed25519 verification
   - otp.c - EEPROM pseudo-OTP
   - decrypt.c - Firmware decryption
   - Makefile - Build system

2. **pkg/firmware/avr/flasher/** - Native ISP
   - isp.go - ISP protocol implementation
   - spi.go - SPI communication layer
   - verify.go - Post-flash verification

3. **pkg/firmware/avr/crypto/** - Crypto providers
   - crypto.go - Unified interface with auto-detection
   - software.go - Software crypto (Cgo)
   - atecc608a/ - Hardware secure element driver

4. **pkg/firmware/avr/lockbits/** - Lock bit management
   - manager.go - Lock bit operations

5. **pkg/firmware/avr/fuses/** - Fuse bit management
   - manager.go - Fuse operations (EESAVE, JTAG)

6. **pkg/firmware/avr/targets/** - Target definitions
   - targets.go - ATmega/ATtiny/AVR-DA definitions
   - detection.go - Auto-detect connected device

7. **pkg/firmware/avr/attestation/** - Attestation
   - serial.go - Serial attestation protocol

8. **pkg/firmware/avr/rollback/** - Rollback protection
   - counter.go - EEPROM monotonic counter

9. **pkg/firmware/avr/library/** - Optional C library
   - libtrusted-avr/ - Source for libtrusted-avr.a
   - Makefile - Build library

## Security Considerations

### Threat Model

**Protected Against**:
- ✅ Firmware tampering (signature verification)
- ✅ Unauthorized firmware updates (CA-signed only)
- ✅ Rollback attacks (monotonic counter)
- ✅ Runtime modification (lock bits prevent ISP write)
- ✅ Firmware extraction (lock bits mode 3)
- ✅ Debugger access (JTAG disabled)

**NOT Protected Against**:
- ❌ Physical chip erase + reprogram (acceptable, requires physical access)
- ❌ Chip decapping / invasive attacks (nation-state level)
- ❌ Power analysis / fault injection (lab equipment required)

### Best Practices

1. **Development**: Lock bits = 0xFF, JTAG enabled
2. **Testing**: Lock bits = 0xFE, JTAG disabled
3. **Production**: Lock bits = 0xFC, JTAG disabled, EESAVE set

## References

- ATmega328P Datasheet: https://ww1.microchip.com/downloads/en/DeviceDoc/Atmel-7810-Automotive-Microcontrollers-ATmega328P_Datasheet.pdf
- AVR ISP Protocol: https://www.microchip.com/en-us/application-notes/an2596
- ATECC608A Datasheet: https://ww1.microchip.com/downloads/en/DeviceDoc/ATECC608A-CryptoAuthentication-Device-Summary-Data-Sheet-DS40001977B.pdf
- Ed25519-donna: https://github.com/floodyberry/ed25519-donna
