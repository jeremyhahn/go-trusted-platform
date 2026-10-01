# Raspberry Pi Secure Boot Implementation

> Part of the go-trusted-platform trusted firmware architecture
>
> **Status: PLANNED (this document); the SD-card image SHIPPED.** What is
> implemented today is the factory image in [docs/factory-image/](../factory-image/):
> Alpine aarch64 on an MBR SD card, U-Boot loaded by the Pi firmware as
> `kernel8.img` with the platform's PK/KEK/db preseeded and EFI TCG2 measured
> boot, a signed UKI at `EFI/BOOT/BOOTAA64.EFI`, and the unchanged
> platform-initrd / firstboot / platformd first boot with the LUKS key sealed
> to the Infineon SLB9670 on SPI. The root of trust of that image is the
> U-Boot binary on the unauthenticated FAT partition. Everything below —
> OTP-based root of trust, `boot.sig` signed firmware, A/B slots, OTA — is
> the design that has not been built, and nothing here should be read as a
> description of the shipped image.

## Overview

This document details the Raspberry Pi-specific implementation for trusted firmware capabilities, including OTP-based root of trust, signed boot chain, Alpine Linux integration, and TPM attestation.

## Supported Hardware

### All Raspberry Pi Models

- **Raspberry Pi 4B**: 4GB/8GB RAM, dual 4K display, USB 3.0
- **Raspberry Pi 3B+**: 1GB RAM, quad-core ARM Cortex-A53
- **Raspberry Pi Zero 2 W**: Compact, wireless
- **Raspberry Pi Compute Module 4**: Industrial applications

### Features by Model

| Model | OTP Support | TPM Support | Secure Boot |
|-------|-------------|-------------|-------------|
| Pi 4  | ✅ Yes      | ✅ Optional | ✅ Yes      |
| Pi 3  | ✅ Yes      | ✅ Optional | ✅ Yes      |
| Pi Zero 2W | ✅ Yes   | ❌ No       | ✅ Yes      |
| CM4   | ✅ Yes      | ✅ Optional | ✅ Yes      |

## Boot Architecture

### Boot Chain

```
┌─────────────────────────────────────────────────────────────┐
│                     Raspberry Pi Boot Flow                  │
└─────────────────────────────────────────────────────────────┘

1. GPU ROM Bootloader (immutable, on-die)
   ↓ verify pubkey hash (OTP)

2. bootcode.bin (first stage bootloader)
   ↓ verify signature

3. start4.elf (second stage, GPU firmware)
   ↓ verify signature

4. config.txt (boot configuration)
   ↓ specifies kernel

5. kernel8.img (Linux kernel)
   ↓ verify signature

6. initramfs.img (initial ramdisk)
   ↓ verify signature

7. rootfs (Alpine Linux)
   ↓ dm-verity verification
```

### Secure Boot Flow

```
Power On
  ↓
GPU ROM (OTP-backed)
  ├─ Read OTP rows 45-52 (pubkey hash)
  ├─ Compute hash of bootcode.bin pubkey
  ├─ Compare hashes
  └─ If match: load bootcode.bin
     If mismatch: halt (red LED blink)
  ↓
bootcode.bin (First Stage)
  ├─ Verify start4.elf signature
  └─ Load start4.elf
  ↓
start4.elf (GPU Firmware)
  ├─ Parse config.txt
  ├─ Verify kernel8.img signature
  └─ Load kernel8.img
  ↓
kernel8.img (Linux Kernel)
  ├─ Verify initramfs.img signature
  └─ Load initramfs.img
  ↓
initramfs.img (Alpine Linux)
  ├─ Verify rootfs with dm-verity
  └─ Mount rootfs and boot
```

## OTP (One-Time Programmable) Memory

### OTP Layout

Raspberry Pi has 66 rows of 32-bit OTP memory:

```
Rows 0-31:  Customer programmable
Rows 32-35: Serial number (factory programmed)
Rows 36-43: Revision code (factory programmed)
Rows 45-52: Secure boot public key hash (customer programmable)
Rows 53-65: Reserved
```

### Programming OTP

**⚠️ WARNING**: OTP is **one-time programmable**. Once written, values CANNOT be changed.

**Location**: `pkg/firmware/rpi/otp/`

```go
package otp

type OTPProgrammer struct {
    rpiboot RPiBoot  // Wrapper for official rpiboot tool
    logger  *logging.Logger
}

type OTPConfig struct {
    PublicKeyHash [32]byte  // SHA256 hash of signing public key
    SerialNumber  string     // Device serial (read-only if factory programmed)
}

func (o *OTPProgrammer) ProgramOTP(config *OTPConfig) error {
    // 1. Generate rpiboot config directory
    configDir, err := o.generateRPIBootConfig(config)
    if err != nil {
        return err
    }

    // 2. Execute rpiboot to program OTP
    // WARNING: This is irreversible!
    log.Warn("Programming OTP - this is IRREVERSIBLE!")
    log.Warn("Rows 45-52 will be permanently written")

    cmd := exec.Command("rpiboot",
        "-d", configDir,  // Config directory
        "-o", "otp",      // OTP mode
    )

    if err := cmd.Run(); err != nil {
        return fmt.Errorf("rpiboot failed: %w", err)
    }

    // 3. Verify OTP was programmed correctly
    return o.verifyOTP(config.PublicKeyHash)
}

func (o *OTPProgrammer) ReadOTP() (*OTPConfig, error) {
    // Read current OTP values
    cmd := exec.Command("vcgencmd", "otp_dump")
    output, err := cmd.Output()
    if err != nil {
        return nil, err
    }

    // Parse OTP dump
    return parseOTPDump(string(output))
}
```

### rpiboot Integration

**Phase 1: Wrapper Approach** (MVP - Fast to Market)

**Location**: `pkg/firmware/rpi/rpiboot/wrapper.go`

```go
package rpiboot

type RPiBootWrapper struct {
    rpibootPath string
    logger      *logging.Logger
}

func NewRPIBootWrapper() (*RPiBootWrapper, error) {
    // Find rpiboot binary
    path, err := exec.LookPath("rpiboot")
    if err != nil {
        return nil, fmt.Errorf("rpiboot not found: %w", err)
    }

    return &RPiBootWrapper{rpibootPath: path}, nil
}

func (r *RPiBootWrapper) ProgramOTP(config *OTPConfig) error {
    // 1. Create config directory structure
    tmpDir := createTempDir()
    defer os.RemoveAll(tmpDir)

    // 2. Write bootcode.bin with embedded pubkey
    bootcode := buildBootcodeWithPubkey(config.PublicKey)
    ioutil.WriteFile(filepath.Join(tmpDir, "bootcode.bin"), bootcode, 0644)

    // 3. Write boot.conf
    bootConf := fmt.Sprintf("otp_program=1\notp_hash=%x\n", config.PublicKeyHash)
    ioutil.WriteFile(filepath.Join(tmpDir, "boot.conf"), []byte(bootConf), 0644)

    // 4. Execute rpiboot
    cmd := exec.Command(r.rpibootPath, "-d", tmpDir)
    return cmd.Run()
}

func (r *RPiBootWrapper) RecoveryBoot(firmware *SignedFirmware) error {
    // USB recovery mode - boot without SD card
    tmpDir := createTempDir()
    defer os.RemoveAll(tmpDir)

    // Write recovery firmware
    ioutil.WriteFile(filepath.Join(tmpDir, "bootcode.bin"), firmware.Bootcode, 0644)
    ioutil.WriteFile(filepath.Join(tmpDir, "start4.elf"), firmware.Start, 0644)
    ioutil.WriteFile(filepath.Join(tmpDir, "kernel8.img"), firmware.Kernel, 0644)

    // Boot via USB
    cmd := exec.Command(r.rpibootPath, "-d", tmpDir)
    return cmd.Run()
}
```

**Phase 2+: Native Go Implementation** (Future Enhancement)

**Location**: `pkg/firmware/rpi/rpiboot/native.go`

```go
// Future: Native Go implementation of rpiboot protocol
// Requires reverse-engineering USB protocol
type NativeRPiBoot struct {
    usbDevice *usb.Device
    logger    *logging.Logger
}

// TODO: Implement native USB protocol
// This is a future enhancement, not needed for MVP
```

**Interface Abstraction**:

**Location**: `pkg/firmware/rpi/rpiboot/interface.go`

```go
package rpiboot

// RPiBoot interface allows switching between wrapper and native implementations
type RPiBoot interface {
    ProgramOTP(config *OTPConfig) error
    RecoveryBoot(firmware *SignedFirmware) error
    FlashBootloader(bootloader []byte) error
}

// Factory function (use wrapper for now, native later)
func NewRPIBoot() (RPiBoot, error) {
    // Phase 1: Use wrapper
    return NewRPIBootWrapper()

    // Phase 2+: Use native implementation
    // return NewNativeRPIBoot()
}
```

## Recovery Mode

### USB Recovery (Unbrick Support)

**Purpose**: Recover devices with corrupted bootloader or SD card

**Location**: `pkg/firmware/rpi/rpiboot/recovery.go`

```go
type RecoveryMode struct {
    rpiboot RPiBoot
    logger  *logging.Logger
}

func (r *RecoveryMode) Unbrick(signedBootChain *BootChain) error {
    log.Info("Entering USB recovery mode")
    log.Info("1. Power off Raspberry Pi")
    log.Info("2. Remove SD card")
    log.Info("3. Connect Pi to computer via USB")
    log.Info("4. Power on Pi (will enter USB boot mode)")
    log.Info("Waiting for device...")

    // Boot via USB using rpiboot
    if err := r.rpiboot.RecoveryBoot(signedBootChain); err != nil {
        return fmt.Errorf("recovery boot failed: %w", err)
    }

    log.Info("Recovery successful!")
    log.Info("1. Power off Pi")
    log.Info("2. Insert SD card")
    log.Info("3. Power on Pi")

    return nil
}
```

**CLI**:
```bash
# Unbrick device via USB recovery
platformctl firmware rpi recovery --boot-chain boot.img

# Flash bootloader via USB
platformctl firmware rpi recovery-flash-bootloader --bootloader bootcode.bin
```

## Boot Chain Builder

### Signed Boot Chain

**Location**: `pkg/firmware/rpi/bootchain/builder.go`

```go
package bootchain

type BootChainBuilder struct {
    signer    *firmware.Signer
    logger    *logging.Logger
}

type BootChain struct {
    Bootcode  []byte  // bootcode.bin (first stage)
    Start     []byte  // start4.elf (GPU firmware)
    Kernel    []byte  // kernel8.img (Linux kernel)
    Initramfs []byte  // initramfs.img (initial ramdisk)
    Config    []byte  // config.txt (boot config)
    DTB       []byte  // Device tree blob
}

func (b *BootChainBuilder) Build(config *BootChainConfig) (*BootChain, error) {
    chain := &BootChain{}

    // 1. Build bootcode.bin (embed signing public key)
    chain.Bootcode = b.buildBootcode(config.PublicKey)

    // 2. Sign bootcode.bin
    bootcodeSig, err := b.signer.Sign(chain.Bootcode)
    if err != nil {
        return nil, err
    }

    // 3. Build start4.elf with embedded bootcode signature
    chain.Start = b.buildStart4(bootcodeSig)

    // 4. Sign start4.elf
    startSig, err := b.signer.Sign(chain.Start)
    if err != nil {
        return nil, err
    }

    // 5. Build kernel with embedded start4 signature
    chain.Kernel = b.buildKernel(config.KernelPath, startSig)

    // 6. Sign kernel
    kernelSig, err := b.signer.Sign(chain.Kernel)
    if err != nil {
        return nil, err
    }

    // 7. Build initramfs with embedded kernel signature
    chain.Initramfs = b.buildInitramfs(config.InitramfsPath, kernelSig)

    // 8. Generate config.txt
    chain.Config = b.generateConfig(config)

    return chain, nil
}

func (b *BootChainBuilder) buildBootcode(pubkey []byte) []byte {
    // Load base bootcode.bin
    base := loadBaseBootcode()

    // Inject public key at known offset
    // GPU ROM will hash this pubkey and compare with OTP
    copy(base[PUBKEY_OFFSET:], pubkey)

    return base
}

func (b *BootChainBuilder) generateConfig(config *BootChainConfig) []byte {
    // config.txt for secure boot
    return []byte(fmt.Sprintf(`
# Raspberry Pi Secure Boot Configuration

# Kernel
kernel=kernel8.img
initramfs initramfs.img followkernel

# Device Tree
dtoverlay=miniuart-bt
enable_uart=1

# Security
disable_splash=1
boot_delay=0

# Secure Boot
secure_boot=1
signing_key=%s

# Performance
arm_64bit=1
arm_freq=1500
gpu_mem=256

# Partition Selection (A/B)
active_partition=%s
`,
        config.PublicKeyPath,
        config.ActivePartition,
    ))
}
```

## A/B Partition Strategy

### Partition Layout

```
┌─────────────────────────────────────────────┐
│  SD Card Layout (16GB example)              │
├─────────────────────────────────────────────┤
│  Boot Partition (256MB, FAT32)              │
│  - bootcode.bin                             │
│  - start4.elf                               │
│  - config.txt (specifies active partition)  │
├─────────────────────────────────────────────┤
│  Partition A (7GB, ext4)                    │
│  - kernel8.img                              │
│  - initramfs.img                            │
│  - rootfs/ (Alpine Linux)                   │
├─────────────────────────────────────────────┤
│  Partition B (7GB, ext4)                    │
│  - kernel8.img                              │
│  - initramfs.img                            │
│  - rootfs/ (Alpine Linux)                   │
├─────────────────────────────────────────────┤
│  Data Partition (remaining, ext4)           │
│  - User data (persists across updates)      │
└─────────────────────────────────────────────┘
```

### OTA Update with A/B

**Location**: `pkg/ota/rpi.go`

```go
package ota

type RPiOTAUpdater struct {
    currentPartition string  // "a" or "b"
    mountPoint       string
    logger           *logging.Logger
}

func (u *RPiOTAUpdater) Update(manifestURL string) error {
    // 1. Download manifest
    manifest := downloadManifest(manifestURL)

    // 2. Verify manifest signature
    if !verifyManifest(manifest) {
        return errors.New("invalid manifest")
    }

    // 3. Determine inactive partition
    inactive := u.getInactivePartition()

    // 4. Download signed boot chain to inactive partition
    log.Infof("Downloading update to partition %s", inactive)
    if err := u.downloadToPartition(manifest, inactive); err != nil {
        return err
    }

    // 5. Verify signatures of all boot chain components
    if err := u.verifyBootChain(inactive); err != nil {
        return err
    }

    // 6. Update config.txt to use inactive partition
    if err := u.updateBootConfig(inactive); err != nil {
        return err
    }

    // 7. Reboot into new partition
    log.Info("Update downloaded and verified, rebooting...")
    return u.reboot()
}

func (u *RPiOTAUpdater) getInactivePartition() string {
    if u.currentPartition == "a" {
        return "b"
    }
    return "a"
}

func (u *RPiOTAUpdater) updateBootConfig(newPartition string) error {
    config := readBootConfig("/boot/config.txt")

    // Update active partition
    config.Set("active_partition", newPartition)

    return writeBootConfig("/boot/config.txt", config)
}

func (u *RPiOTAUpdater) verifyBootChain(partition string) error {
    // Mount partition
    mountPoint := fmt.Sprintf("/mnt/%s", partition)
    if err := mount(partition, mountPoint); err != nil {
        return err
    }
    defer unmount(mountPoint)

    // Verify kernel signature
    kernelPath := filepath.Join(mountPoint, "kernel8.img")
    if err := verifySignature(kernelPath); err != nil {
        return fmt.Errorf("kernel signature invalid: %w", err)
    }

    // Verify initramfs signature
    initramfsPath := filepath.Join(mountPoint, "initramfs.img")
    if err := verifySignature(initramfsPath); err != nil {
        return fmt.Errorf("initramfs signature invalid: %w", err)
    }

    // Verify rootfs with dm-verity
    rootfsPath := filepath.Join(mountPoint, "rootfs.img")
    if err := verifyDMVerity(rootfsPath); err != nil {
        return fmt.Errorf("rootfs verification failed: %w", err)
    }

    return nil
}
```

## Alpine Linux Integration

### Why Alpine Linux?

- **Small**: ~130MB base system
- **Secure**: Minimal attack surface
- **Fast**: Quick boot times
- **Modern**: Up-to-date packages
- **Go-friendly**: Easy to integrate go-trusted-platform agent

### Dedicated RPi Installer

**Location**: `pkg/installer/alpine_rpi.go`

**Purpose**: Keep RPi-specific Alpine code separate from existing alpine.go

```go
package installer

type AlpineRPiInstaller struct {
    baseInstaller *AlpineInstaller  // Reuse common Alpine logic
    bootchain     *bootchain.Builder
    logger        *logging.Logger
}

func NewAlpineRPiInstaller() *AlpineRPiInstaller {
    return &AlpineRPiInstaller{
        baseInstaller: NewAlpineInstaller(),
        bootchain:     bootchain.NewBuilder(),
    }
}

func (a *AlpineRPiInstaller) Install(device string, config *RPiConfig) error {
    // 1. Partition SD card (boot + A + B + data)
    if err := a.partitionSDCard(device); err != nil {
        return err
    }

    // 2. Install Alpine base to both A and B partitions
    log.Info("Installing Alpine to partition A")
    if err := a.baseInstaller.InstallToPartition(device, "a"); err != nil {
        return err
    }

    log.Info("Installing Alpine to partition B")
    if err := a.baseInstaller.InstallToPartition(device, "b"); err != nil {
        return err
    }

    // 3. Build signed boot chain
    chain, err := a.bootchain.Build(config.BootChainConfig)
    if err != nil {
        return err
    }

    // 4. Write boot partition
    if err := a.writeBootPartition(device, chain); err != nil {
        return err
    }

    // 5. Install go-trusted-platform agent
    if err := a.installAgent(device); err != nil {
        return err
    }

    // 6. Configure dm-verity for rootfs
    if err := a.configureDMVerity(device); err != nil {
        return err
    }

    return nil
}

func (a *AlpineRPiInstaller) partitionSDCard(device string) error {
    // Use sgdisk to partition
    // Partition 1: 256MB FAT32 (boot)
    // Partition 2: 7GB ext4 (A)
    // Partition 3: 7GB ext4 (B)
    // Partition 4: Remaining ext4 (data)

    commands := [][]string{
        {"sgdisk", "-Z", device},  // Zap existing partitions
        {"sgdisk", "-n", "1:0:+256M", "-t", "1:0700", device},  // Boot
        {"sgdisk", "-n", "2:0:+7G", "-t", "2:8300", device},    // A
        {"sgdisk", "-n", "3:0:+7G", "-t", "3:8300", device},    // B
        {"sgdisk", "-n", "4:0:0", "-t", "4:8300", device},      // Data
    }

    for _, cmd := range commands {
        if err := exec.Command(cmd[0], cmd[1:]...).Run(); err != nil {
            return err
        }
    }

    // Format partitions
    exec.Command("mkfs.vfat", "-F", "32", device+"1").Run()  // Boot
    exec.Command("mkfs.ext4", device+"2").Run()              // A
    exec.Command("mkfs.ext4", device+"3").Run()              // B
    exec.Command("mkfs.ext4", device+"4").Run()              // Data

    return nil
}

func (a *AlpineRPiInstaller) installAgent(device string) error {
    // Mount partition A
    mountPoint := "/mnt/rpi-install"
    exec.Command("mount", device+"2", mountPoint).Run()
    defer exec.Command("umount", mountPoint).Run()

    // Install go-trusted-platform-agent binary
    agentPath := filepath.Join(mountPoint, "usr/local/bin/platform-agent")
    if err := copyFile("/usr/local/bin/platform-agent", agentPath); err != nil {
        return err
    }

    // Install systemd service
    servicePath := filepath.Join(mountPoint, "etc/systemd/system/platform-agent.service")
    service := `[Unit]
Description=go-trusted-platform Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/platform-agent --config /etc/platform/agent.conf
Restart=always

[Install]
WantedBy=multi-user.target
`
    return ioutil.WriteFile(servicePath, []byte(service), 0644)
}
```

**Existing alpine.go stays clean**:
```go
// pkg/installer/alpine.go (UNCHANGED)

// This file handles x86/ARM64 Alpine installation
// NO Raspberry Pi-specific code here
```

## TPM Integration

### Optional TPM Support

**Location**: `pkg/firmware/rpi/attestation/tpm.go`

```go
package attestation

import (
    "github.com/google/go-tpm/tpm2"
    "github.com/google/go-tpm/tpmutil"
)

type TPMAttestor struct {
    tpm    *tpm2.TPM
    logger *logging.Logger
}

func NewTPMAttestor() (*TPMAttestor, error) {
    // Open TPM device
    tpm, err := tpm2.OpenTPM("/dev/tpmrm0")
    if err != nil {
        return nil, err
    }

    return &TPMAttestor{tpm: tpm}, nil
}

func (t *TPMAttestor) Attest(nonce []byte) (*Attestation, error) {
    // 1. Select PCRs to quote
    pcrSelection := tpm2.PCRSelection{
        Hash: tpm2.AlgSHA256,
        PCRs: []int{0, 1, 2, 3, 4, 5, 6, 7},
    }

    // 2. Generate TPM2_Quote
    quote, sig, err := tpm2.Quote(
        t.tpm,
        tpmutil.Handle(0x81000001),  // AIK handle
        "",                          // Password
        "",                          // Qualifier
        nonce,
        pcrSelection,
        tpm2.AlgNull,
    )
    if err != nil {
        return nil, err
    }

    // 3. Return attestation
    return &Attestation{
        Quote:     quote,
        Signature: sig,
        PCRs:      t.readPCRs(pcrSelection),
    }, nil
}

func (t *TPMAttestor) readPCRs(selection tpm2.PCRSelection) [][]byte {
    pcrs := make([][]byte, len(selection.PCRs))

    for i, pcrIndex := range selection.PCRs {
        pcrValue, err := tpm2.ReadPCR(t.tpm, pcrIndex, selection.Hash)
        if err != nil {
            log.Errorf("Failed to read PCR %d: %v", pcrIndex, err)
            continue
        }
        pcrs[i] = pcrValue
    }

    return pcrs
}
```

### Software Attestation Fallback

**Location**: `pkg/firmware/rpi/attestation/software.go`

```go
// If no TPM available, use software attestation
type SoftwareAttestor struct {
    privateKey ed25519.PrivateKey
    logger     *logging.Logger
}

func (s *SoftwareAttestor) Attest(nonce []byte) (*Attestation, error) {
    // 1. Build attestation data
    data := &AttestationData{
        Nonce:       nonce,
        DeviceID:    getDeviceID(),
        OSHash:      getOSHash(),
        KernelHash:  getKernelHash(),
        BootCount:   getBootCount(),
        Timestamp:   time.Now().Unix(),
    }

    // 2. Sign with device private key
    signature := ed25519.Sign(s.privateKey, data.Marshal())

    return &Attestation{
        Data:      data,
        Signature: signature,
    }, nil
}
```

## Rollback Protection

### TPM NV Counter

**Location**: `pkg/firmware/rpi/rollback/tpm_counter.go`

```go
package rollback

type TPMCounter struct {
    tpm     *tpm2.TPM
    nvIndex uint32
    logger  *logging.Logger
}

const FIRMWARE_VERSION_NV_INDEX = 0x1500000

func NewTPMCounter() (*TPMCounter, error) {
    tpm, err := tpm2.OpenTPM("/dev/tpmrm0")
    if err != nil {
        return nil, err
    }

    return &TPMCounter{
        tpm:     tpm,
        nvIndex: FIRMWARE_VERSION_NV_INDEX,
    }, nil
}

func (t *TPMCounter) Increment() error {
    // Increment TPM NV counter (monotonic)
    return tpm2.NVIncrement(
        t.tpm,
        tpmutil.Handle(t.nvIndex),
        tpmutil.Handle(t.nvIndex),
        "",  // Password
    )
}

func (t *TPMCounter) Read() (uint64, error) {
    // Read current counter value
    data, err := tpm2.NVRead(
        t.tpm,
        tpmutil.Handle(t.nvIndex),
    )
    if err != nil {
        return 0, err
    }

    return binary.BigEndian.Uint64(data), nil
}

func (t *TPMCounter) VerifyVersion(version uint64) error {
    current, err := t.Read()
    if err != nil {
        return err
    }

    if version <= current {
        return fmt.Errorf("rollback detected: current=%d, new=%d", current, version)
    }

    return nil
}
```

## SD Card Flasher

### Writing Boot Images

**Location**: `pkg/firmware/rpi/flasher/sdcard.go`

```go
package flasher

type SDCardFlasher struct {
    logger *logging.Logger
}

func (f *SDCardFlasher) Flash(device string, bootChain *BootChain) error {
    // 1. Verify device is valid
    if !f.isValidDevice(device) {
        return fmt.Errorf("invalid device: %s", device)
    }

    // 2. Partition SD card
    if err := f.partition(device); err != nil {
        return err
    }

    // 3. Mount boot partition
    mountPoint := "/mnt/rpi-boot"
    if err := mount(device+"1", mountPoint); err != nil {
        return err
    }
    defer unmount(mountPoint)

    // 4. Write boot files
    files := map[string][]byte{
        "bootcode.bin":   bootChain.Bootcode,
        "start4.elf":     bootChain.Start,
        "kernel8.img":    bootChain.Kernel,
        "initramfs.img":  bootChain.Initramfs,
        "config.txt":     bootChain.Config,
    }

    for filename, data := range files {
        path := filepath.Join(mountPoint, filename)
        if err := ioutil.WriteFile(path, data, 0644); err != nil {
            return fmt.Errorf("failed to write %s: %w", filename, err)
        }
    }

    // 5. Sync and unmount
    exec.Command("sync").Run()

    log.Info("SD card flashed successfully!")
    log.Info("You can now insert the SD card into your Raspberry Pi")

    return nil
}
```

## Testing with QEMU

### QEMU Integration

**Location**: `pkg/firmware/testing/qemu.go`

```go
type QEMURPi struct {
    machine   string  // "raspi3b" or "raspi4b"
    kernel    string
    initramfs string
    logger    *logging.Logger
}

func (q *QEMURPi) Run() error {
    cmd := exec.Command("qemu-system-aarch64",
        "-M", q.machine,
        "-cpu", "cortex-a72",
        "-m", "1G",
        "-kernel", q.kernel,
        "-initrd", q.initramfs,
        "-append", "console=ttyAMA0",
        "-nographic",
    )

    return cmd.Run()
}
```

### Testing Workflow

```bash
# 1. Build boot chain
platformctl firmware rpi build-bootchain \
    --kernel kernel8.img \
    --initramfs initramfs.img \
    --output boot-chain.tar

# 2. Test in QEMU first (safe)
platformctl firmware rpi test-qemu --boot-chain boot-chain.tar

# 3. Only after QEMU passes: flash to SD card
platformctl firmware rpi flash-sdcard \
    --boot-chain boot-chain.tar \
    --device /dev/sdb \
    --verify

# 4. Test on real Pi (don't program OTP yet)
# Insert SD card, boot Pi, verify everything works

# 5. ONLY after full confirmation: program OTP (irreversible!)
platformctl firmware rpi program-otp \
    --pubkey-hash <hash> \
    --confirm-irreversible
```

## CLI Commands

```bash
# Build signed boot chain
platformctl firmware rpi build-bootchain \
    --kernel kernel8.img \
    --initramfs initramfs.img \
    --dtb bcm2711-rpi-4-b.dtb \
    --output boot-chain.tar

# Test in QEMU (safe, no hardware risk)
platformctl firmware rpi test-qemu --boot-chain boot-chain.tar

# Flash to SD card
platformctl firmware rpi flash-sdcard \
    --boot-chain boot-chain.tar \
    --device /dev/sdb \
    --verify

# Program OTP (irreversible, do LAST)
platformctl firmware rpi program-otp \
    --pubkey-hash <sha256-hash> \
    --confirm-irreversible

# USB recovery mode (unbrick)
platformctl firmware rpi recovery --boot-chain boot-chain.tar

# Install Alpine Linux
platformctl firmware rpi install-alpine \
    --device /dev/sdb \
    --boot-chain boot-chain.tar \
    --packages "go-trusted-platform-agent,tpm2-tools"

# OTA update
platformctl ota update --device-id rpi-001 --version 2.0.0

# Attest device
platformctl firmware attest --device-id rpi-001 --protocol tpm
```

## Implementation Files

### Core RPi Files

1. **pkg/firmware/rpi/rpiboot/** - rpiboot wrapper/native
   - wrapper.go - Go wrapper for official rpiboot tool (Phase 1)
   - native.go - Native Go implementation (Phase 2+, future)
   - interface.go - RPiBoot interface abstraction
   - config.go - Generate rpiboot config files
   - recovery.go - USB recovery mode

2. **pkg/firmware/rpi/otp/** - OTP programming
   - programmer.go - OTP programming via rpiboot
   - reader.go - Read current OTP values

3. **pkg/firmware/rpi/bootchain/** - Boot chain builder
   - builder.go - Build signed boot chain
   - signer.go - Sign boot components

4. **pkg/firmware/rpi/flasher/** - SD card flasher
   - sdcard.go - Write boot images to SD card
   - verify.go - Verify SD card contents

5. **pkg/firmware/rpi/attestation/** - Attestation
   - tpm.go - TPM-based attestation
   - software.go - Software fallback attestation

6. **pkg/firmware/rpi/rollback/** - Rollback protection
   - tpm_counter.go - TPM NV counter

7. **pkg/installer/** - Alpine Linux installer
   - alpine_rpi.go - RPi-specific Alpine installer (NEW, dedicated)
   - alpine.go - Existing x86/ARM64 installer (UNCHANGED)

8. **pkg/ota/** - Universal OTA system
   - rpi.go - RPi OTA updater (A/B partitions)

## Security Considerations

### Threat Model

**Protected Against**:
- ✅ Unauthorized bootloader modification (OTP-backed pubkey hash)
- ✅ Unsigned kernel execution (signature verification)
- ✅ Rootfs tampering (dm-verity)
- ✅ Rollback attacks (TPM NV counter or software counter)
- ✅ Runtime attestation compromise (TPM quote or signed attestation)

**NOT Protected Against**:
- ❌ Physical TPM reset (acceptable, requires physical access)
- ❌ OTP already programmed incorrectly (one-time only)

### Best Practices

1. **Development**: Test in QEMU, don't program OTP
2. **Testing**: Test on real Pi with SD card, don't program OTP
3. **Staging**: Test full boot chain with test OTP values
4. **Production**: Program OTP LAST, after complete validation

### OTP Programming Checklist

- [ ] Boot chain tested in QEMU
- [ ] Boot chain tested on real Pi (no OTP)
- [ ] Signatures verified
- [ ] Rollback protection tested
- [ ] Recovery mode tested
- [ ] A/B partition OTA tested
- [ ] **ALL TESTS PASSING**
- [ ] ⚠️ **FINAL STEP**: Program OTP (irreversible!)

## References

- Raspberry Pi Boot Process: https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#raspberry-pi-4-boot-flow
- rpiboot Tool: https://github.com/raspberrypi/usbboot
- TPM2 Tools: https://github.com/tpm2-software/tpm2-tools
- Alpine Linux: https://alpinelinux.org/
- dm-verity: https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/verity.html
