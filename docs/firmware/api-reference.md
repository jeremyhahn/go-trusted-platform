# Firmware API Reference

CLI commands and API for Trusted Platform Firmware.

## platformctl firmware Commands

### Signing

```bash
platformctl firmware sign \
  --input firmware.hex \
  --output signed.hex \
  --device arduino-001

platformctl firmware sign \
  --input firmware.hex \
  --key firmware-signing \
  --cert /path/to/cert.crt
```

### Flashing

```bash
# Flash AVR
platformctl firmware flash \
  --input signed.hex \
  --port /dev/ttyUSB0 \
  --programmer usbasp \
  --verify \
  --lock

# Flash with device profile
platformctl firmware flash \
  --input firmware.hex \
  --device-profile arduino-001.yaml
```

### Attestation

```bash
# AVR (serial)
platformctl firmware attest \
  --device-id arduino-001 \
  --port /dev/ttyUSB0 \
  --verify-trust

# RPi (TPM)
platformctl firmware attest \
  --device-id rpi-001 \
  --protocol tpm

# Android (hardware)
platformctl firmware attest \
  --device-id pixel-7 \
  --protocol android-hardware

# Wireless (BLE)
platformctl firmware attest \
  --device-id sensor-001 \
  --protocol ble
```

### OTA Updates

```bash
# Configure OTA
platformctl firmware ota configure \
  --url https://updates.example.com \
  --device atmega328p

# Trigger update
platformctl ota update \
  --device-id arduino-001 \
  --version 1.2.3

# Check status
platformctl ota status --device-id arduino-001

# Rollback
platformctl ota rollback --device-id arduino-001
```

### RPi Commands

```bash
# Build boot chain
platformctl firmware rpi build-bootchain \
  --kernel kernel8.img \
  --initramfs initramfs.img \
  --output boot-chain.tar

# Program OTP (IRREVERSIBLE!)
platformctl firmware rpi program-otp \
  --pubkey-hash <hash> \
  --confirm-irreversible

# USB recovery
platformctl firmware rpi recovery \
  --boot-chain boot.img

# Flash SD card
platformctl firmware rpi flash-sdcard \
  --boot-chain boot.img \
  --device /dev/sdb

# Test in QEMU
platformctl firmware rpi test-qemu \
  --boot-chain boot.img
```

### Android Commands

```bash
# Flash GrapheneOS
platformctl firmware android flash-grapheneos \
  --images grapheneos-build.tar \
  --device <serial> \
  --lock-bootloader

# Bootloader status
platformctl firmware android bootloader-status \
  --device <serial>

# Lock bootloader
platformctl firmware android lock-bootloader \
  --device <serial> \
  --confirm
```

### Virtual TPM (swtpm)

```bash
# Install swtpm
platformctl vtpm install-swtpm --target rpi-001

# Create bundle
platformctl vtpm create-bundle \
  --output vtpm-bundle.tar.gz

# Deploy bundle
platformctl vtpm deploy-bundle \
  --bundle vtpm-bundle.tar.gz \
  --device rpi-001
```

### Testing

```bash
# Test in simavr
platformctl firmware test \
  --input firmware.hex \
  --simulator simavr \
  --bootloader bootloader.hex

# Test in QEMU
platformctl firmware test \
  --input boot.img \
  --simulator qemu \
  --machine raspi3b
```

## See Also

- [README.md](README.md) - Overview
- [Configuration](configuration.md) - Config examples
- [Roadmap](../../ROADMAP.md) - Development roadmap
