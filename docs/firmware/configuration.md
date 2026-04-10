# Firmware Configuration Reference

> **NOTE: PROPOSED CONFIGURATION - Not yet implemented**
>
> The firmware configuration schemas documented on this page are **planned features** for Phase O.
> These schemas are proposed and subject to change. The current platform configuration
> does not include a `firmware:` section. All configuration examples below represent the
> intended design for future implementation.

Configuration examples for Trusted Platform Firmware support across AVR, Raspberry Pi, and Android platforms.

## Configuration Format

**IMPORTANT**: Device configurations use **flat YAML format** with kebab-case keys, matching existing go-trusted-platform configs.

**✅ CORRECT Format** (flat YAML):
```yaml
device-id: arduino-001
model: atmega328p
firmware:
  bootloader-size: 4096
```

**❌ WRONG Format** (do NOT use Kubernetes-style):
```yaml
# DO NOT USE THIS FORMAT
apiVersion: v1
kind: Device
metadata:
  name: arduino-001
spec:
  firmware:
    bootloader-size: 4096
```

**Exception**: ABAC policies DO use apiVersion/kind/metadata/spec format (see [RBAC/ABAC Policies](#rbacabac-policies)).

---

## AVR Microcontroller Configuration

> **PROPOSED** - All AVR configurations below are planned for Phase O implementation.

### Basic AVR Device

```yaml
# PROPOSED: AVR device configuration (Arduino Uno example)
debug: true
platform-dir: /var/lib/trusted-platform
device-id: arduino-uno-001
model: atmega328p
role: iot

# Platform settings
platform:
  type: avr
  target: atmega328p
  programmer: usbasp
  serial-port: /dev/ttyUSB0

# Firmware settings
firmware:
  bootloader-size: 4096  # 4KB boot section
  flash-size: 32768      # 32KB total flash
  eeprom-size: 1024      # 1KB EEPROM
  sram-size: 2048        # 2KB SRAM

# Security
security:
  lock-bits: 0xFC        # Mode 3 (production)
  fuses:
    low: 0xFF
    high: 0xDE           # EESAVE=0, JTAG disabled
    extended: 0xFD

# Attestation
attestation:
  protocol: serial
  baud-rate: 115200
  timeout: 5s

# OTA
ota:
  enabled: true
  update-url: https://firmware.example.com/updates
  check-interval: 1h
  partitioning: golden-staging
  max-retries: 3

# Rollback protection
rollback:
  enabled: true
  storage: eeprom
  address: 0x00

# Identity
identity:
  device-certificate: /etc/platform/certs/arduino-uno-001.crt
  private-key: /etc/platform/keys/arduino-uno-001.key
  ca-certificate: /etc/platform/certs/ca.crt
  acme-url: https://ca.example.com/acme/directory
```

### AVR with ATECC608A (Deferred)

```yaml
# PROPOSED: AVR with secure element (pending hardware availability)
device-id: arduino-secure-001
model: atmega328p

platform:
  type: avr
  target: atmega328p
  serial-port: /dev/ttyUSB0

firmware:
  bootloader-size: 4096
  flash-size: 32768

# Hardware security (DEFERRED - pending dev board)
security:
  lock-bits: 0xFC
  secure-element:
    enabled: true
    type: atecc608a
    i2c-address: 0x60
    key-slots:
      signing: 0           # Slot 0 for device signing
      encryption: 1        # Slot 1 for firmware decryption

attestation:
  protocol: serial
  hardware-backed: true    # Use ATECC608A

identity:
  private-key: atecc608a:slot0  # Key in secure element
```

### AVR with Wireless Attestation

```yaml
# PROPOSED: AVR with wireless attestation
device-id: iot-sensor-001
model: atmega328p

platform:
  type: avr
  target: atmega328p

firmware:
  bootloader-size: 4096
  flash-size: 32768

# Wireless attestation
attestation:
  protocol: serial
  baud-rate: 115200
  wireless:
    - type: ble
      enabled: true
      service-uuid: "0000180a-0000-1000-8000-00805f9b34fb"
      device-name: "IoT-Sensor-001"
    - type: lora
      enabled: false
      frequency: 915000000
    - type: wifi
      enabled: false

ota:
  enabled: true
  update-url: https://iot.example.com/updates
  protocols:
    - https
    - mqtt
    - ble
```

---

## Raspberry Pi Configuration

> **PROPOSED** - All Raspberry Pi configurations below are planned for Phase O implementation.

### Basic Raspberry Pi with Physical TPM

```yaml
# PROPOSED: Raspberry Pi with physical TPM
debug: true
platform-dir: /var/lib/trusted-platform
device-id: rpi-edge-001
model: rpi4b
role: edge

# Platform settings
platform:
  type: raspberry-pi
  model: rpi4b
  architecture: aarch64

# TPM configuration (physical TPM)
tpm:
  device: /dev/tpmrm0
  simulator: false
  hash: SHA-256
  encrypt-sessions: false

  # TPM keys
  ek:
    handle: 0x81010001
    hash: SHA-256
    rsa:
      size: 2048

  iak:
    handle: 0x81010002
    hash: SHA-256
    rsa:
      size: 2048
    signature-algorithm: SHA256-RSAPSS

  platform-pcr: 23
  platform-pcr-bank: sha256
  golden-pcrs: [0, 7, 9]

# Firmware settings
firmware:
  platform: raspberry-pi

  # OTP configuration
  otp:
    programmed: true
    pubkey-hash: sha256:abcdef1234567890...
    revision-code: 0xc03111

  # Boot chain
  boot-chain:
    bootloader: /boot/bootcode.bin
    firmware: /boot/start4.elf
    kernel: /boot/kernel8.img
    initramfs: /boot/initramfs.img
    rootfs: /dev/mmcblk0p2

  # Security
  security:
    secure-boot-enabled: true
    tpm-enabled: true
    pcr-banks: [sha256]

  # Attestation via TPM2_Quote
  attestation:
    protocol: tpm
    pcr-selection: "0,1,2,3,4,5,6,7"
    wireless:
      - type: wifi
        enabled: true
        ssid: edge-network

  # OTA (A/B partitions)
  ota:
    enabled: true
    update-url: https://firmware.example.com/rpi-updates
    check-interval: 6h
    partitioning: ab
    active-partition: a
    max-retries: 3

  # Rollback protection (TPM NV)
  rollback:
    enabled: true
    storage: tpm-nv
    nv-index: 0x1500000

# Alpine Linux
os:
  distribution: alpine
  version: edge
  architecture: aarch64
  packages:
    - go-trusted-platform-agent
    - tpm2-tools
    - attestation-client

# Identity
identity:
  device-certificate: /etc/platform/certs/rpi-edge-001.crt
  private-key: tpm:0x81000001  # TPM-backed key
  ca-certificate: /etc/platform/certs/ca.crt
  acme-url: https://ca.example.com/acme/directory
```

### Raspberry Pi with swtpm (Virtual TPM)

```yaml
# PROPOSED: Raspberry Pi WITHOUT physical TPM - uses swtpm
debug: true
platform-dir: /var/lib/trusted-platform
device-id: rpi-dev-001
model: rpi4b
role: edge

platform:
  type: raspberry-pi
  model: rpi4b
  architecture: aarch64

# swtpm configuration (software TPM)
tpm:
  device: /var/run/swtpm-socket  # swtpm socket instead of /dev/tpmrm0
  simulator: false                # Not a simulator, real swtpm
  hash: SHA-256

  # swtpm-specific settings
  swtpm:
    enabled: true
    bundle: /var/lib/trusted-platform/swtpm/
    socket-path: /var/run/swtpm-socket
    state-dir: /var/lib/trusted-platform/swtpm/state

  # Same TPM key configuration as physical TPM
  ek:
    handle: 0x81010001
    hash: SHA-256
    rsa:
      size: 2048

  iak:
    handle: 0x81010002
    hash: SHA-256
    rsa:
      size: 2048

  platform-pcr: 23
  golden-pcrs: [0, 7, 9]

firmware:
  platform: raspberry-pi

  # Attestation via TPM2_Quote (using swtpm)
  attestation:
    protocol: tpm
    pcr-selection: "0,1,2,3,4,5,6,7"

  # OTA and other settings same as physical TPM
  ota:
    enabled: true
    update-url: https://firmware.example.com/rpi-updates
    partitioning: ab
    active-partition: a

  rollback:
    enabled: true
    storage: tpm-nv
    nv-index: 0x1500000
```

---

## Android/GrapheneOS Configuration

> **PROPOSED** - All Android/GrapheneOS configurations below are planned for Phase O implementation.

### Google Pixel Device

```yaml
# PROPOSED: Android device configuration (Google Pixel example)
debug: true
platform-dir: /var/lib/trusted-platform
device-id: pixel-7-001
model: pixel-7
role: mobile

# Platform settings
platform:
  type: android
  manufacturer: google
  model: pixel-7
  architecture: aarch64

# Firmware settings
firmware:
  platform: android

  # Android Verified Boot
  avb:
    enabled: true
    version: 2.0
    algorithm: SHA256-RSA4096
    rollback-index: 0

  # Bootloader
  bootloader:
    locked: true
    state: yellow  # Custom key (GrapheneOS)
    # States: green (OEM key), yellow (custom key), orange (unlocked), red (failed)

  # Attestation via Android Hardware Attestation API
  attestation:
    protocol: android-hardware
    security-level: StrongBox  # or TrustedEnvironment
    verified-boot-state: SelfSigned
    patch-level: 2025-01

  # OTA (A/B seamless updates)
  ota:
    enabled: true
    update-url: https://grapheneos.example.com/updates
    partitioning: ab
    active-slot: a
    max-retries: 3

  # Rollback protection
  rollback:
    enabled: true
    storage: vbmeta
    index: 0

# GrapheneOS settings
os:
  distribution: grapheneos
  version: 2025010200
  build-variant: user

# Identity
identity:
  device-certificate: /data/platform/certs/pixel-7-001.crt
  private-key: keystore:attestation-key  # Android Keystore
  ca-certificate: /data/platform/certs/ca.crt
```

---

## Firmware Update Server Configuration

> **PROPOSED** - OTA update manifest format is planned for Phase O implementation.

### OTA Update Manifest

```json
{
  "version": "1.2.3",
  "device-type": "atmega328p",
  "firmware-url": "https://updates.example.com/firmware-1.2.3.hex.enc",
  "hash": "sha256:abcdef1234567890...",
  "signature": "base64-encoded-ed25519-signature",
  "encryption-key": "encrypted-with-device-pubkey",
  "release-notes": "Bug fixes and security improvements",
  "min-bootloader-version": "1.0.0",
  "is-security-update": true,
  "timestamp": "2025-01-15T10:00:00Z",
  "rollback-index": 5
}
```

---

## QuicBaaS Integration

> **PROPOSED** - QuicBaaS firmware device entries are planned for Phase O implementation.

### Firmware Device Entry

```yaml
# PROPOSED: QuicBaaS firmware device entry (flat YAML)
device-id: arduino-001
type: avr
model: atmega328p
serial-number: AVR-2025-001
role: iot

# Current state
current-version: 1.2.3
firmware-hash: sha256:abcdef...
boot-count: 42
last-attestation: 2025-01-15T14:30:00Z
attestation-status: trusted

# Hardware
secure-element:
  type: none  # or atecc608a (when available)
  enabled: false

capabilities:
  - ota
  - wireless
  - attestation

# Enrollment
enrolled-at: 2025-01-10T09:00:00Z
certificate-id: cert-arduino-001

# Metadata
labels:
  environment: production
  location: warehouse-A
  owner: iot-team
```

### RBAC/ABAC Policies

**Note**: ABAC policies DO use apiVersion/kind/metadata/spec format:

```yaml
# Firmware RBAC policy (YAML with apiVersion/kind/metadata/spec)
apiVersion: abac.trustedplatform.io/v1
kind: Policy
metadata:
  name: firmware-operator
  tenant: platform
  description: Can flash and attest devices
  priority: 100

spec:
  subjects:
    roles:
      - firmware-operator
    authenticated: true

  rules:
    - name: flash-permission
      effect: allow
      actions:
        - execute
      resources:
        - firmware:flash
        - firmware:attest
        - firmware:ota
      conditions:
        environment:
          - development
          - staging
          - production

    - name: read-firmware-data
      effect: allow
      actions:
        - read
      resources:
        - firmware:*
```

```yaml
# Firmware admin policy
apiVersion: abac.trustedplatform.io/v1
kind: Policy
metadata:
  name: firmware-admin
  tenant: platform
  description: Full firmware management access

spec:
  subjects:
    roles:
      - firmware-admin

  rules:
    - name: full-access
      effect: allow
      actions:
        - "*"
      resources:
        - firmware:*
```

```yaml
# Device owner policy (manage own devices only)
apiVersion: abac.trustedplatform.io/v1
kind: Policy
metadata:
  name: device-owner
  tenant: platform

spec:
  subjects:
    authenticated: true

  rules:
    - name: manage-owned-devices
      effect: allow
      actions:
        - read
        - attest
        - ota
      resources:
        - firmware:device:${subject.id}:*
```

---

## Virtual TPM Bundle Configuration

> **PROPOSED** - swtpm bundle configuration is planned for Phase O implementation.

### swtpm Bundle

```yaml
# PROPOSED: swtpm bundle configuration
swtpm:
  version: 0.8.0
  state-dir: /var/lib/trusted-platform/swtpm/state
  socket-path: /var/run/swtpm-socket
  ctrl-socket: /var/run/swtpm-ctrl

  # TPM configuration
  tpm-version: 2.0
  platform-auth: ""
  owner-auth: ""
  endorsement-auth: ""

  # Pre-generated keys
  ek:
    public-key: /var/lib/trusted-platform/swtpm/ek.pub
    certificate: /var/lib/trusted-platform/swtpm/ek.crt
    handle: 0x81010001

  # NV storage
  nvram:
    path: /var/lib/trusted-platform/swtpm/nvram/
    size: 524288  # 512KB
```

---

## Fuse and Lock Bit Configuration

> **PROPOSED** - Fuse configuration format is planned for Phase O implementation.

### AVR Fuse Settings

```yaml
# PROPOSED: Fuse configuration (AVR)
fuses:
  # Low fuse (clock settings)
  low: 0xFF
    # CKDIV8=1 (no division)
    # CKOUT=1 (no clock output)
    # SUT=11 (startup time)
    # CKSEL=1111 (full swing crystal)

  # High fuse (bootloader, EEPROM, JTAG)
  high: 0xDE
    # RSTDISBL=1 (RESET enabled)
    # DWEN=1 (debugWIRE disabled)
    # SPIEN=0 (SPI programming enabled)
    # WDTON=1 (watchdog not always on)
    # EESAVE=0 (EEPROM preserved on chip erase)
    # BOOTSZ=01 (4KB boot section)
    # BOOTRST=0 (boot to bootloader)

  # Extended fuse (brown-out)
  extended: 0xFD
    # BODLEVEL=101 (2.7V brown-out)

# Lock bits
lock-bits: 0xFC  # Mode 3 (production)
  # LB=00 (no memory lock)
  # BLB0=11 (no restrictions on app section)
  # BLB1=11 (bootloader protection)
```

---

## Configuration Files Location

> **PROPOSED** - Firmware device configuration file structure is planned for Phase O implementation.

**Remote Development Host**:
```
sftp://jhahn@198.51.100.51/home/jhahn/sources/go-trusted-platform/
├── configs/
│   └── firmware/              # PROPOSED - not yet created
│       ├── arduino-uno-001.yaml
│       ├── rpi-edge-001.yaml
│       ├── pixel-7-001.yaml
│       └── ...
```

**Local Installation**:
```
/etc/trusted-platform/
├── config.yaml           # Main platform config
└── devices/              # PROPOSED - not yet created
    ├── arduino-001.yaml
    ├── rpi-001.yaml
    └── pixel-7.yaml
```

---

## Environment Variables

```bash
# Platform configuration
PLATFORM_DIR=/var/lib/trusted-platform
PLATFORM_CONFIG=/etc/trusted-platform/config.yaml

# Firmware-specific
FIRMWARE_CA_CERT=/etc/platform/certs/firmware-ca.crt
FIRMWARE_UPDATE_URL=https://firmware.example.com/updates

# swtpm (if using virtual TPM)
SWTPM_STATE_DIR=/var/lib/trusted-platform/swtpm/state
SWTPM_SOCKET=/var/run/swtpm-socket

# QuicBaaS
QUICBAAS_ENDPOINT=https://quicbaas.example.com
QUICBAAS_COLLECTION=firmware_devices
```

---

## Best Practices

1. **Use flat YAML format** for device configs (NOT apiVersion/kind)
2. **ABAC policies** DO use apiVersion/kind/metadata/spec
3. **Store secrets securely** (use TPM, ATECC608A, or encrypted storage)
4. **Test in simulator first** (simavr for AVR, QEMU for RPi)
5. **Don't lock bootloader/lock bits** until fully tested
6. **Program OTP last** on RPi (irreversible)
7. **Use swtpm** for RPi without physical TPM
8. **Always verify signatures** before flashing
9. **Enable rollback protection** in production
10. **Use QuicBaaS** for audit logging and RBAC

---

## See Also

- [README.md](README.md) - Overview and quick start
- [Architecture](architecture.md) - System design
- [API Reference](api-reference.md) - CLI commands
- [AVR Details](avr.md) - AVR-specific information
- [RPi Details](rpi.md) - Raspberry Pi and swtpm
- [Android Details](android.md) - GrapheneOS support
