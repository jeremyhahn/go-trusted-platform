// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package installer

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/fips"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// sysBlockDir is the sysfs directory holding one entry per block device.
const sysBlockDir = "/sys/block"

// diskManager implements the DiskManager interface
type diskManager struct {
	config   *DiskConfig
	logger   *logging.Logger
	diskInfo *DiskInfo
}

// NewDiskManager creates a new disk manager
func NewDiskManager(logger *logging.Logger, config *DiskConfig) (DiskManager, error) {
	if config == nil {
		return nil, ErrInvalidConfig("disk config is required")
	}

	return &diskManager{
		config: config,
		logger: logger,
		diskInfo: &DiskInfo{
			Device:         config.Device,
			PartitionTable: config.PartitionTable,
		},
	}, nil
}

// CreatePartitionTable creates a new GPT or MBR partition table
func (dm *diskManager) CreatePartitionTable(ctx context.Context, table PartitionTable) error {
	dm.logger.Info("[DISK] Creating partition table", "type", table, "device", dm.config.Device)

	// Determine parted label type
	var labelType string
	switch table {
	case PartitionTableGPT:
		labelType = "gpt"
	case PartitionTableMBR:
		labelType = "msdos"
	default:
		return ErrInvalidConfig(fmt.Sprintf("unsupported partition table: %s", table))
	}

	// Zero the first 10MB of the disk to wipe any stale ESP/GPT data.
	// Supermicro UEFI firmware caches old partition tables and boot
	// entries in NVRAM; zeroing ensures the firmware sees the new
	// partition table on the next boot instead of a stale ESP from a
	// prior install.
	dm.logger.Info("[DISK] Wiping old partition data", "device", dm.config.Device)
	wipeCmd := exec.CommandContext(ctx, "dd", "if=/dev/zero", "of="+dm.config.Device, "bs=1M", "count=10", "conv=notrunc")
	if wipeOut, wipeErr := wipeCmd.CombinedOutput(); wipeErr != nil {
		dm.logger.Warn("[DISK] dd wipe failed (continuing)", "output", strings.TrimSpace(string(wipeOut)), "error", wipeErr)
	}
	// Also wipe the backup GPT header at the end of disk (if wipefs is available)
	wipeEndCmd := exec.CommandContext(ctx, "wipefs", "--all", "--force", dm.config.Device)
	if wipeEndOut, wipeEndErr := wipeEndCmd.CombinedOutput(); wipeEndErr != nil {
		dm.logger.Warn("[DISK] wipefs failed (continuing)", "output", strings.TrimSpace(string(wipeEndOut)), "error", wipeEndErr)
	}

	// Create partition table using parted
	dm.logger.Debug("[DISK] Creating partition table using parted", "label", labelType)
	cmd := exec.CommandContext(ctx, "parted", "-s", dm.config.Device, "mklabel", labelType)
	output, err := cmd.CombinedOutput()
	if err != nil {
		dm.logger.Warn("[DISK] Failed to create partition table", "output", strings.TrimSpace(string(output)), "error", err)
		return ErrDiskOperation("parted mklabel failed", err)
	}

	dm.logger.Info("[DISK] Partition table created successfully")
	return nil
}

// CreateEFIPartition creates and formats the EFI system partition
func (dm *diskManager) CreateEFIPartition(ctx context.Context, sizeMB int) error {
	dm.logger.Info("[DISK] Creating EFI partition", "size_mb", sizeMB)

	// Default EFI size (538MB)
	if sizeMB == 0 {
		sizeMB = 538
	}

	// Use parted to create EFI partition
	// Start at 1MiB, end at (1 + sizeMB)MiB
	dm.logger.Debug("[DISK] Creating EFI partition using parted")

	// The ESP is FAT32 under both partition tables; only the partition name
	// parted is given differs between GPT and MBR.
	partType := "fat32"

	// parted mkpart args: partition-type fs-type start end
	// For GPT: parted -s /dev/vda mkpart ESP fat32 1MiB 539MiB
	// For MBR: parted -s /dev/vda mkpart primary fat32 1MiB 539MiB
	var mkpartArgs []string
	if dm.config.PartitionTable == PartitionTableGPT {
		mkpartArgs = []string{
			"-s", dm.config.Device,
			"mkpart", "ESP", partType,
			"1MiB", fmt.Sprintf("%dMiB", 1+sizeMB),
		}
	} else {
		mkpartArgs = []string{
			"-s", dm.config.Device,
			"mkpart", "primary", partType,
			"1MiB", fmt.Sprintf("%dMiB", 1+sizeMB),
		}
	}

	dm.logger.Debug("[DISK] Running parted mkpart", "args", mkpartArgs)
	cmd := exec.CommandContext(ctx, "parted", mkpartArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		dm.logger.Warn("[DISK] Failed to create EFI partition", "output", strings.TrimSpace(string(output)), "error", err)
		return ErrDiskOperation("parted mkpart failed", err)
	}
	dm.logger.Debug("[DISK] parted mkpart completed", "output", strings.TrimSpace(string(output)))

	// Set boot flag for GPT (ESP type)
	if dm.config.PartitionTable == PartitionTableGPT {
		cmd = exec.CommandContext(ctx, "parted", "-s", dm.config.Device, "set", "1", "esp", "on")
		output, err = cmd.CombinedOutput()
		if err != nil {
			dm.logger.Warn("[DISK] Failed to set ESP flag", "output", strings.TrimSpace(string(output)))
			// Non-fatal, continue
		}
	} else {
		// Set boot flag for MBR
		cmd = exec.CommandContext(ctx, "parted", "-s", dm.config.Device, "set", "1", "boot", "on")
		output, err = cmd.CombinedOutput()
		if err != nil {
			dm.logger.Warn("[DISK] Failed to set boot flag", "output", strings.TrimSpace(string(output)))
			// Non-fatal, continue
		}
	}

	dm.diskInfo.EFIPartition = fmt.Sprintf("%s1", dm.config.Device)

	// List partitions for debugging
	dm.logger.Debug("[DISK] Listing partitions after creation")
	listCmd := exec.CommandContext(ctx, "parted", "-s", dm.config.Device, "print")
	if listOutput, err := listCmd.CombinedOutput(); err == nil {
		dm.logMultilineOutput("partition_table", string(listOutput))
	}

	// Also check /proc/partitions
	if procData, err := os.ReadFile("/proc/partitions"); err == nil {
		dm.logPartitions(procData)
	}

	// Probe partitions to create device nodes
	if err := dm.probePartitions(ctx); err != nil {
		return err
	}

	// Try udevadm settle to ensure device nodes are created
	if err := dm.settleDevices(ctx); err != nil {
		dm.logger.Infof("[DISK] udevadm settle not available or failed: %v", err)
	}

	// Check /proc/partitions again after probe
	if procData, err := os.ReadFile("/proc/partitions"); err == nil {
		dm.logPartitions(procData)
	}

	// List /dev to see what device nodes exist
	if devEntries, err := os.ReadDir("/dev"); err == nil {
		vdaDevices := []string{}
		for _, entry := range devEntries {
			if strings.HasPrefix(entry.Name(), "vda") {
				vdaDevices = append(vdaDevices, entry.Name())
			}
		}
		dm.logger.Infof("[DISK] /dev/vda* devices: %v", vdaDevices)
	}

	// Wait for device node to appear (up to 15 seconds)
	if err := dm.waitForDevice(ctx, dm.diskInfo.EFIPartition, 15*time.Second); err != nil {
		return ErrDiskOperation("EFI partition device node not found", err)
	}

	// Format EFI partition as FAT32
	if err := dm.formatFAT32(dm.diskInfo.EFIPartition, "EFI"); err != nil {
		return ErrDiskOperation("failed to format EFI partition", err)
	}

	// Sync filesystem writes and wait for device to be ready
	dm.logger.Debug("[DISK] Syncing filesystem writes", "partition", dm.diskInfo.EFIPartition)
	syncCmd := exec.CommandContext(ctx, "sync")
	if err := syncCmd.Run(); err != nil {
		dm.logger.Warn("[DISK] sync command failed", "error", err)
	}

	// Wait for filesystem to be fully ready after formatting
	time.Sleep(1 * time.Second)

	// Verify device is readable before proceeding
	if f, err := os.Open(dm.diskInfo.EFIPartition); err == nil {
		if closeErr := f.Close(); closeErr != nil {
			dm.logger.Warn("[DISK] Failed to close EFI partition device", "error", closeErr)
		}
		dm.logger.Debug("[DISK] EFI partition device verified readable")
	} else {
		dm.logger.Warn("[DISK] EFI partition device not immediately readable", "error", err)
		time.Sleep(1 * time.Second) // Additional wait
	}

	dm.logger.Info("[DISK] EFI partition created", "device", dm.diskInfo.EFIPartition)
	return nil
}

// CreateRootPartition creates the root partition
func (dm *diskManager) CreateRootPartition(ctx context.Context) error {
	dm.logger.Info("[DISK] Creating root partition")

	// Get EFI partition size (default to 538MB if not set)
	efiSizeMB := dm.config.EFIPartitionSize
	if efiSizeMB == 0 {
		efiSizeMB = 538
	}

	// Calculate start position (after EFI partition + 1MiB alignment)
	startMiB := 1 + efiSizeMB

	// Use parted to create root partition using remaining space
	dm.logger.Debug("[DISK] Creating root partition using parted")

	// parted mkpart args: partition-type fs-type start end
	// For GPT: parted -s /dev/vda mkpart root ext4 539MiB 100%
	// For MBR: parted -s /dev/vda mkpart primary ext4 539MiB 100%
	var mkpartArgs []string
	if dm.config.PartitionTable == PartitionTableGPT {
		mkpartArgs = []string{
			"-s", dm.config.Device,
			"mkpart", "root", "ext4",
			fmt.Sprintf("%dMiB", startMiB), "100%",
		}
	} else {
		mkpartArgs = []string{
			"-s", dm.config.Device,
			"mkpart", "primary", "ext4",
			fmt.Sprintf("%dMiB", startMiB), "100%",
		}
	}

	dm.logger.Debug("[DISK] Running parted mkpart", "args", mkpartArgs)
	cmd := exec.CommandContext(ctx, "parted", mkpartArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		dm.logger.Warn("[DISK] Failed to create root partition", "output", strings.TrimSpace(string(output)), "error", err)
		return ErrDiskOperation("parted mkpart failed", err)
	}
	dm.logger.Debug("[DISK] parted mkpart completed", "output", strings.TrimSpace(string(output)))

	dm.diskInfo.RootPartition = fmt.Sprintf("%s2", dm.config.Device)

	// List partitions for debugging
	dm.logger.Debug("[DISK] Listing partitions after root creation")
	listCmd := exec.CommandContext(ctx, "parted", "-s", dm.config.Device, "print")
	if listOutput, err := listCmd.CombinedOutput(); err == nil {
		dm.logMultilineOutput("partition_table", string(listOutput))
	}

	// Check /proc/partitions before probe
	if procData, err := os.ReadFile("/proc/partitions"); err == nil {
		dm.logPartitions(procData)
	}

	// Probe partitions to create device nodes
	if err := dm.probePartitions(ctx); err != nil {
		return err
	}

	// Try udevadm settle to ensure device nodes are created
	if err := dm.settleDevices(ctx); err != nil {
		dm.logger.Debug("[DISK] udevadm settle not available or failed", "error", err)
	}

	// Check /proc/partitions after probe
	if procData, err := os.ReadFile("/proc/partitions"); err == nil {
		dm.logPartitions(procData)
	}

	// List /dev to see what device nodes exist
	if devEntries, err := os.ReadDir("/dev"); err == nil {
		vdaDevices := []string{}
		for _, entry := range devEntries {
			if strings.HasPrefix(entry.Name(), "vda") {
				vdaDevices = append(vdaDevices, entry.Name())
			}
		}
		dm.logger.Debug("[DISK] Device nodes found", "devices", vdaDevices)
	}

	// Wait for device node to appear (up to 15 seconds)
	if err := dm.waitForDevice(ctx, dm.diskInfo.RootPartition, 15*time.Second); err != nil {
		return ErrDiskOperation("root partition device node not found", err)
	}

	dm.logger.Info("[DISK] Root partition created", "device", dm.diskInfo.RootPartition)
	return nil
}

// SetupLUKS creates and opens a LUKS container
func (dm *diskManager) SetupLUKS(ctx context.Context, partition string, config *EncryptionConfig) (string, error) {
	dm.logger.Info("[DISK] Setting up LUKS encryption")

	// Use root partition if not specified
	if partition == "" {
		partition = dm.diskInfo.RootPartition
	}

	if config == nil {
		return "", ErrEncryption("encryption config is required", nil)
	}

	// Parse cipher (format: "aes-xts-plain64" -> cipher="aes", mode="xts-plain64")
	cipherFull := "aes-xts-plain64"
	if config.Cipher != "" {
		cipherFull = config.Cipher
	}
	cipherParts := strings.SplitN(cipherFull, "-", 2)
	cipher := cipherParts[0]
	cipherMode := "xts-plain64"
	if len(cipherParts) > 1 {
		cipherMode = cipherParts[1]
	}

	// Determine key size in bits
	keySize := 512
	if config.KeySize > 0 {
		keySize = config.KeySize
	}

	// Determine hash algorithm
	hash := "sha256"
	if config.Hash != "" {
		hash = config.Hash
	}

	// Determine KDF algorithm
	// FIPS 140-3 does not approve Argon2id, so PBKDF2-SHA256 must be used in FIPS mode
	kdfType := config.PBKDF
	if kdfType == "" {
		// Check config FIPS flag first (for installer), then runtime kernel state
		if config.FIPS || fips.IsEnabled() {
			kdfType = fips.KDFPBKDF2
		} else {
			kdfType = fips.DefaultKDF // argon2id
		}
	}

	// Get passphrase (use Passphrase field, fall back to Password)
	passphrase := config.Passphrase
	if passphrase == "" {
		passphrase = config.Password
	}

	dm.logger.Info("[DISK] LUKS parameters",
		"cipher", cipherFull,
		"keySize", keySize,
		"hash", hash,
		"kdf", kdfType,
		"fips_config", config.FIPS)

	// Format LUKS container using pure Go luks2 library
	dm.logger.Info("[DISK] Formatting LUKS container", "partition", partition)

	// Use pbkdf2 during installation to avoid OOM in low-memory install environments.
	// The installed system can re-key with argon2id on first boot if desired.
	installKDF := "pbkdf2"
	dm.logger.Info("[DISK] Using PBKDF2 for installation (low-memory safe)", "requested_kdf", kdfType)

	formatOpts := luks2.FormatOptions{
		Device:     partition,
		Passphrase: []byte(passphrase),
		Cipher:     cipher,
		CipherMode: cipherMode,
		KeySize:    keySize,
		HashAlgo:   hash,
		KDFType:    installKDF,
	}

	if err := luks2.Format(formatOpts); err != nil {
		return "", ErrEncryption("LUKS format failed", err)
	}

	dm.logger.Info("[DISK] LUKS container formatted successfully")

	// Get LUKS UUID using pure Go luks2 library
	volumeInfo, err := luks2.GetVolumeInfo(partition)
	if err != nil {
		dm.logger.Warn("[DISK] Failed to get LUKS UUID", "error", err)
	} else {
		dm.diskInfo.LUKSUUID = volumeInfo.UUID
		dm.logger.Info("[DISK] LUKS UUID", "uuid", volumeInfo.UUID)
	}

	// Open LUKS container using pure Go luks2 library
	mappedName := "cryptroot"
	if config.MappedName != "" {
		mappedName = config.MappedName
	}

	dm.logger.Info("[DISK] Opening LUKS container", "mapped_name", mappedName)

	if err := luks2.Unlock(partition, []byte(passphrase), mappedName); err != nil {
		return "", ErrEncryption("LUKS unlock failed", err)
	}

	mappedDevice := fmt.Sprintf("/dev/mapper/%s", mappedName)
	dm.logger.Info("[DISK] LUKS container opened", "mapped_device", mappedDevice)
	dm.diskInfo.MappedDevice = mappedDevice

	return mappedDevice, nil
}

// FormatFilesystem creates a filesystem on the given device
func (dm *diskManager) FormatFilesystem(ctx context.Context, device, fsType, label string) error {
	dm.logger.Info("[DISK] Formatting filesystem", "device", device, "type", fsType, "label", label)

	switch fsType {
	case "vfat", "fat32":
		return dm.formatFAT32(device, label)
	case "ext4":
		return dm.formatExt4(device, label)
	default:
		return ErrDiskOperation(fmt.Sprintf("unsupported filesystem: %s", fsType), nil)
	}
}

// formatFAT32 formats a partition as FAT32
func (dm *diskManager) formatFAT32(device, label string) error {
	dm.logger.Debug("[DISK] Formatting as FAT32", "device", device, "label", label)

	args := []string{"-F", "32"}
	if label != "" {
		args = append(args, "-n", label)
	}
	args = append(args, device)

	cmd := exec.Command("mkfs.vfat", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		dm.logger.Warn("[DISK] FAT32 formatting failed", "output", strings.TrimSpace(string(output)), "error", err)
		return ErrDiskOperation("mkfs.vfat failed", err)
	}

	dm.logger.Debug("[DISK] FAT32 formatting successful")
	return nil
}

// formatExt4 formats a partition as ext4
func (dm *diskManager) formatExt4(device, label string) error {
	dm.logger.Debug("[DISK] Formatting as ext4", "device", device, "label", label)

	args := []string{"-F"}
	if label != "" {
		args = append(args, "-L", label)
	}
	args = append(args, device)

	cmd := exec.Command("mkfs.ext4", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		dm.logger.Warn("[DISK] ext4 formatting failed", "output", strings.TrimSpace(string(output)), "error", err)
		return ErrDiskOperation("mkfs.ext4 failed", err)
	}

	dm.logger.Debug("[DISK] ext4 formatting successful")
	return nil
}

// Mount mounts a filesystem
func (dm *diskManager) Mount(ctx context.Context, device, mountpoint, fsType string, flags uintptr) error {
	dm.logger.Info("[DISK] Mounting filesystem", "device", device, "mountpoint", mountpoint, "type", fsType)

	// Create mountpoint if it doesn't exist
	if err := os.MkdirAll(mountpoint, 0755); err != nil {
		return ErrDiskOperation("failed to create mountpoint", err)
	}

	// Mount using syscall
	if err := syscall.Mount(device, mountpoint, fsType, flags, ""); err != nil {
		return ErrDiskOperation("failed to mount filesystem", err)
	}

	dm.logger.Debug("[DISK] Filesystem mounted successfully")
	return nil
}

// Unmount unmounts a filesystem
func (dm *diskManager) Unmount(ctx context.Context, mountpoint string) error {
	dm.logger.Info("[DISK] Unmounting filesystem", "mountpoint", mountpoint)

	if err := syscall.Unmount(mountpoint, 0); err != nil {
		return ErrDiskOperation("failed to unmount filesystem", err)
	}

	dm.logger.Debug("[DISK] Filesystem unmounted successfully")
	return nil
}

// CreateLVMPhysicalVolume creates an LVM physical volume
func (dm *diskManager) CreateLVMPhysicalVolume(ctx context.Context, device string) error {
	dm.logger.Info("[DISK] Creating LVM physical volume", "device", device)

	cmd := exec.CommandContext(ctx, "pvcreate", "-ff", "-y", device)
	output, err := cmd.CombinedOutput()
	if err != nil {
		dm.logger.Warn("[DISK] pvcreate failed", "output", strings.TrimSpace(string(output)), "error", err)
		return ErrDiskOperation("pvcreate failed", err)
	}

	dm.logger.Info("[DISK] LVM physical volume created successfully")

	// DEBUG: Verify LVM signature was written immediately after pvcreate
	if f, err := os.Open(device); err == nil {
		buf := make([]byte, 1024)
		if _, err := f.Read(buf); err == nil {
			dm.logger.Info("[DISK] DEBUG: After pvcreate - checking DECRYPTED LVM signature",
				"device", device,
				"offset_0", fmt.Sprintf("%x", buf[:32]),
				"offset_512", fmt.Sprintf("%x", buf[512:544]))
			if string(buf[512:520]) == "LABELONE" {
				dm.logger.Info("[DISK] DEBUG: LVM signature FOUND after pvcreate!")
			} else {
				dm.logger.Warn("[DISK] DEBUG: NO LVM signature after pvcreate!", "got", fmt.Sprintf("%q", string(buf[512:520])))
			}
		}
		if closeErr := f.Close(); closeErr != nil {
			dm.logger.Warn("[DISK] DEBUG: Failed to close device file", "error", closeErr)
		}
	}

	// DEBUG: Also check the ENCRYPTED backend device to verify encryption is working
	// The backend device should have encrypted data at LUKS data offset (290816 bytes)
	if dm.config.Device != "" {
		backendDev := fmt.Sprintf("%s2", dm.config.Device) // Root partition (e.g., /dev/vda2)
		if f, err := os.Open(backendDev); err == nil {
			buf := make([]byte, 1024)
			luksDataOffset := int64(290816) // Standard LUKS2 data offset
			if _, err := f.ReadAt(buf, luksDataOffset); err == nil {
				dm.logger.Info("[DISK] DEBUG: After pvcreate - checking ENCRYPTED backend data",
					"device", backendDev,
					"luks_offset", luksDataOffset,
					"encrypted_sector0", fmt.Sprintf("%x", buf[:32]),
					"encrypted_sector1", fmt.Sprintf("%x", buf[512:544]))
				// Check if all zeros (data not encrypted/written yet)
				allZeros := true
				for _, b := range buf[:64] {
					if b != 0 {
						allZeros = false
						break
					}
				}
				if allZeros {
					dm.logger.Warn("[DISK] DEBUG: Backend device has ALL ZEROS at LUKS offset - encryption may not be working!")
				} else {
					dm.logger.Info("[DISK] DEBUG: Backend device has encrypted data - encryption is working")
				}
			} else {
				dm.logger.Warn("[DISK] DEBUG: Failed to read backend device", "device", backendDev, "error", err)
			}
			if closeErr := f.Close(); closeErr != nil {
				dm.logger.Warn("[DISK] DEBUG: Failed to close backend device", "error", closeErr)
			}
		} else {
			dm.logger.Warn("[DISK] DEBUG: Failed to open backend device", "device", backendDev, "error", err)
		}
	}

	return nil
}

// CreateLVMVolumeGroup creates an LVM volume group
func (dm *diskManager) CreateLVMVolumeGroup(ctx context.Context, vgName string, pvDevices []string) error {
	dm.logger.Info("[DISK] Creating LVM volume group", "vg", vgName, "pvs", pvDevices)

	if len(pvDevices) == 0 {
		return ErrInvalidConfig("at least one physical volume required")
	}

	args := append([]string{vgName}, pvDevices...)
	cmd := exec.CommandContext(ctx, "vgcreate", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		dm.logger.Warn("[DISK] vgcreate failed", "output", strings.TrimSpace(string(output)), "error", err)
		return ErrDiskOperation("vgcreate failed", err)
	}

	dm.logger.Info("[DISK] LVM volume group created successfully")

	// DEBUG: Check if LVM signature still exists after vgcreate
	if len(pvDevices) > 0 {
		if f, err := os.Open(pvDevices[0]); err == nil {
			buf := make([]byte, 1024)
			if _, err := f.Read(buf); err == nil {
				dm.logger.Info("[DISK] DEBUG: After vgcreate - checking LVM signature",
					"device", pvDevices[0],
					"offset_512", fmt.Sprintf("%x", buf[512:528]))
				if string(buf[512:520]) == "LABELONE" {
					dm.logger.Info("[DISK] DEBUG: LVM signature still present after vgcreate")
				} else {
					dm.logger.Warn("[DISK] DEBUG: LVM signature GONE after vgcreate!", "got", fmt.Sprintf("%q", string(buf[512:520])))
				}
			}
			if closeErr := f.Close(); closeErr != nil {
				dm.logger.Warn("[DISK] failed to close file", "error", closeErr)
			}
		}
	}

	return nil
}

// CreateLVMLogicalVolume creates an LVM logical volume
func (dm *diskManager) CreateLVMLogicalVolume(ctx context.Context, vgName, lvName string, size string) (string, error) {
	dm.logger.Info("[DISK] Creating LVM logical volume", "vg", vgName, "lv", lvName, "size", size)

	// Build lvcreate command
	// lvcreate -l 100%FREE -n root vg0
	var args []string
	if size == "100%FREE" || size == "100%VG" {
		args = []string{"-l", size, "-n", lvName, vgName}
	} else {
		// Assume size is specified (e.g., "10G", "500M")
		args = []string{"-L", size, "-n", lvName, vgName}
	}

	cmd := exec.CommandContext(ctx, "lvcreate", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		dm.logger.Warn("[DISK] lvcreate failed", "output", strings.TrimSpace(string(output)), "error", err)
		return "", ErrDiskOperation("lvcreate failed", err)
	}

	// LV device path
	lvDevice := fmt.Sprintf("/dev/mapper/%s-%s", vgName, lvName)

	// DEBUG: Check if LVM signature still exists after lvcreate
	cryptrootPath := "/dev/mapper/cryptroot"
	if f, err := os.Open(cryptrootPath); err == nil {
		buf := make([]byte, 1024)
		if _, err := f.Read(buf); err == nil {
			dm.logger.Info("[DISK] DEBUG: After lvcreate - checking LVM signature",
				"device", cryptrootPath,
				"offset_512", fmt.Sprintf("%x", buf[512:528]))
			if string(buf[512:520]) == "LABELONE" {
				dm.logger.Info("[DISK] DEBUG: LVM signature still present after lvcreate")
			} else {
				dm.logger.Warn("[DISK] DEBUG: LVM signature GONE after lvcreate!", "got", fmt.Sprintf("%q", string(buf[512:520])))
			}
		}
		if closeErr := f.Close(); closeErr != nil {
			dm.logger.Warn("[DISK] failed to close file", "error", closeErr)
		}
	}

	// Also check for /dev/vgName/lvName format
	altPath := fmt.Sprintf("/dev/%s/%s", vgName, lvName)

	// Wait for device to appear
	dm.logger.Debug("[DISK] Waiting for LV device to appear...")
	time.Sleep(1 * time.Second)

	// Check which path exists
	if _, err := os.Stat(lvDevice); err == nil {
		dm.logger.Info("[DISK] LVM logical volume created", "device", lvDevice)
		return lvDevice, nil
	}

	if _, err := os.Stat(altPath); err == nil {
		dm.logger.Info("[DISK] LVM logical volume created", "device", altPath)
		return altPath, nil
	}

	// If neither exists, return the mapper path anyway (it should appear)
	dm.logger.Info("[DISK] LVM logical volume created", "device", lvDevice)
	return lvDevice, nil
}

// Close releases resources
func (dm *diskManager) Close() error {
	// Nothing to close for now
	return nil
}

// probePartitions tells the kernel to re-scan partitions
func (dm *diskManager) probePartitions(ctx context.Context) error {
	dm.logger.Debug("[DISK] Re-scanning partitions", "device", dm.config.Device)

	// First, use blockdev to force kernel to re-read partition table
	// This is more reliable than partprobe alone
	dm.logger.Debug("[DISK] Using blockdev --rereadpt")
	cmd := exec.CommandContext(ctx, "blockdev", "--rereadpt", dm.config.Device)
	output, err := cmd.CombinedOutput()
	if err != nil {
		dm.logger.Warn("[DISK] blockdev --rereadpt failed", "output", strings.TrimSpace(string(output)))
		// Try partprobe as fallback
		dm.logger.Debug("[DISK] Trying partprobe as fallback")
		cmd = exec.CommandContext(ctx, "partprobe", dm.config.Device)
		output, err = cmd.CombinedOutput()
		if err != nil {
			dm.logger.Warn("[DISK] partprobe also failed", "output", strings.TrimSpace(string(output)))
		}
	}

	// Trigger mdev to create device nodes (Alpine Linux uses mdev instead of udev)
	dm.logger.Debug("[DISK] Triggering mdev to create device nodes")
	cmd = exec.CommandContext(ctx, "mdev", "-s")
	output, err = cmd.CombinedOutput()
	if err != nil {
		dm.logger.Warn("[DISK] mdev -s failed", "output", strings.TrimSpace(string(output)))
	}

	// Also trigger uevent for the disk to force device node creation
	deviceName := filepath.Base(dm.config.Device) // Extract "vda" from "/dev/vda"
	ueventPath := filepath.Join(sysBlockDir, deviceName, "uevent")
	if err := os.WriteFile(ueventPath, []byte("add\n"), 0644); err == nil {
		dm.logger.Debug("[DISK] Triggered uevent", "device", deviceName)
		// Small delay for uevent to propagate
		time.Sleep(500 * time.Millisecond)
	} else {
		dm.logger.Warn("[DISK] Failed to trigger uevent", "error", err)
	}

	// Give kernel and mdev time to create device nodes
	dm.logger.Debug("[DISK] Waiting for partition device nodes")
	time.Sleep(2 * time.Second)

	dm.logger.Debug("[DISK] Partition re-scan complete")
	return nil
}

// settleDevices waits for udev to process all events and create device nodes
func (dm *diskManager) settleDevices(ctx context.Context) error {
	dm.logger.Debug("[DISK] Running udevadm settle to ensure device nodes are created")

	cmd := exec.CommandContext(ctx, "udevadm", "settle", "--timeout=10")
	output, err := cmd.CombinedOutput()
	if err != nil {
		dm.logger.Debug("[DISK] udevadm settle failed", "output", string(output), "error", err)
		return err
	}

	dm.logger.Debug("[DISK] udevadm settle completed")
	return nil
}

// waitForDevice waits for a device node to appear with retries
func (dm *diskManager) waitForDevice(ctx context.Context, device string, maxWait time.Duration) error {
	dm.logger.Debug("[DISK] Waiting for device node", "device", device, "max_wait", maxWait)

	deadline := time.Now().Add(maxWait)
	checkInterval := 100 * time.Millisecond
	attempts := 0

	for time.Now().Before(deadline) {
		attempts++

		// Check if context is cancelled
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Check if device exists
		if _, err := os.Stat(device); err == nil {
			dm.logger.Debug("[DISK] Device node ready", "device", device, "attempts", attempts)
			return nil
		}

		// Wait before next check
		time.Sleep(checkInterval)
	}

	// Last resort: try to manually create the device node using mknod
	dm.logger.Warn("[DISK] Device node not found after waiting, attempting manual creation", "device", device)
	if err := dm.createDeviceNode(ctx, device); err == nil {
		// Check if it exists now
		if _, err := os.Stat(device); err == nil {
			dm.logger.Debug("[DISK] Device node manually created successfully", "device", device)
			return nil
		}
	}

	dm.logger.Warn("[DISK] Device node not found", "device", device, "attempts", attempts, "wait_seconds", maxWait.Seconds())
	return &MessageError{Msg: fmt.Sprintf("timeout waiting for device node: %s", device)}
}

// createDeviceNode manually creates a device node using mknod
func (dm *diskManager) createDeviceNode(ctx context.Context, device string) error {
	// Read /proc/partitions to get major/minor numbers
	procData, err := os.ReadFile("/proc/partitions")
	if err != nil {
		return &WrappedError{Msg: "failed to read /proc/partitions", Err: err}
	}

	// Parse partition table to find major/minor for this device
	deviceName := filepath.Base(device)
	var major, minor int
	found := false

	lines := strings.Split(string(procData), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[3] == deviceName {
			if maj, err := strconv.Atoi(fields[0]); err == nil {
				if min, err := strconv.Atoi(fields[1]); err == nil {
					major = maj
					minor = min
					found = true
					break
				}
			}
		}
	}

	if !found {
		return &MessageError{Msg: fmt.Sprintf("device %s not found in /proc/partitions", deviceName)}
	}

	dm.logger.Debug("[DISK] Creating device node manually", "device", device, "major", major, "minor", minor)

	// Use mknod to create the block device node
	cmd := exec.CommandContext(ctx, "mknod", device, "b", fmt.Sprintf("%d", major), fmt.Sprintf("%d", minor))
	output, err := cmd.CombinedOutput()
	if err != nil {
		dm.logger.Warn("[DISK] mknod failed", "device", device, "output", strings.TrimSpace(string(output)), "error", err)
		return err
	}

	dm.logger.Debug("[DISK] mknod completed successfully", "device", device)
	return nil
}

// EnsureDeviceNode ensures a device node exists, creating it if necessary
func (dm *diskManager) EnsureDeviceNode(ctx context.Context, device string, maxWait time.Duration) error {
	dm.logger.Debug("[DISK] Ensuring device node exists", "device", device)

	// Check if device already exists
	if _, err := os.Stat(device); err == nil {
		dm.logger.Debug("[DISK] Device node already exists", "device", device)
		return nil
	}

	// Device doesn't exist - try to create it
	dm.logger.Debug("[DISK] Device node missing, attempting to create", "device", device)

	// First try mdev scan to see if it appears
	cmd := exec.CommandContext(ctx, "mdev", "-s")
	if output, err := cmd.CombinedOutput(); err != nil {
		dm.logger.Warn("[DISK] mdev -s failed", "output", strings.TrimSpace(string(output)))
	}

	time.Sleep(500 * time.Millisecond)

	// Check again
	if _, err := os.Stat(device); err == nil {
		dm.logger.Debug("[DISK] Device node created via mdev", "device", device)
		return nil
	}

	// Still doesn't exist - create manually with mknod
	if err := dm.createDeviceNode(ctx, device); err != nil {
		return &WrappedError{Msg: "failed to create device node", Err: err}
	}

	// Final verification
	if _, err := os.Stat(device); err != nil {
		return &MessageError{Msg: fmt.Sprintf("device node still not available after creation attempt: %s", device)}
	}

	dm.logger.Debug("[DISK] Device node ensured", "device", device)
	return nil
}

// logMultilineOutput logs multi-line command output in a structured way.
// For log aggregators, this logs a summary at INFO level and individual
// non-empty lines at DEBUG level.
func (dm *diskManager) logMultilineOutput(context string, output string) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	nonEmptyLines := 0
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			nonEmptyLines++
		}
	}

	dm.logger.Debug("[DISK] Command output",
		"context", context,
		"line_count", nonEmptyLines)

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			dm.logger.Debug("[DISK] Output line",
				"context", context,
				"line_num", i+1,
				"content", trimmed)
		}
	}
}

// logPartitions parses /proc/partitions and logs each partition as a structured entry.
func (dm *diskManager) logPartitions(data []byte) {
	lines := strings.Split(string(data), "\n")

	// Parse partitions (skip header lines)
	partitions := []string{}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			// Skip header line
			if fields[0] == "major" {
				continue
			}
			// fields: major minor blocks name
			name := fields[3]
			blocks := fields[2]
			partitions = append(partitions, fmt.Sprintf("%s:%sKB", name, blocks))
		}
	}

	if len(partitions) > 0 {
		dm.logger.Debug("[DISK] Partitions detected",
			"count", len(partitions),
			"partitions", partitions)
	}
}
