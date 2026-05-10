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

package drive

import (
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// FilesystemType represents supported filesystem types
type FilesystemType string

const (
	// FilesystemExt4 is the ext4 filesystem
	FilesystemExt4 FilesystemType = "ext4"

	// FilesystemXFS is the XFS filesystem
	FilesystemXFS FilesystemType = "xfs"

	// FilesystemZFS is the ZFS filesystem
	FilesystemZFS FilesystemType = "zfs"

	// FilesystemFAT32 is the FAT32 filesystem (for EFI partitions)
	FilesystemFAT32 FilesystemType = "vfat"
)

// DriveRole defines the purpose of a drive
type DriveRole string

const (
	// DriveRoleSystem contains the root filesystem
	DriveRoleSystem DriveRole = "system"

	// DriveRoleData is for data storage
	DriveRoleData DriveRole = "data"

	// DriveRoleBackup is for backup storage
	DriveRoleBackup DriveRole = "backup"

	// DriveRoleSwap is for swap space
	DriveRoleSwap DriveRole = "swap"
)

// RecoveryKeyFormat specifies the output format for recovery keys
type RecoveryKeyFormat string

const (
	// RecoveryKeyFormatHex outputs the key as hexadecimal
	RecoveryKeyFormatHex RecoveryKeyFormat = "hex"

	// RecoveryKeyFormatBase64 outputs the key as base64
	RecoveryKeyFormatBase64 RecoveryKeyFormat = "base64"

	// RecoveryKeyFormatDashed outputs as dash-separated hex groups
	RecoveryKeyFormatDashed RecoveryKeyFormat = "dashed"
)

// DriveConfig represents a physical or virtual drive configuration
type DriveConfig struct {
	// ID is a unique identifier for this drive configuration
	ID string `yaml:"id" json:"id" mapstructure:"id"`

	// Device is the block device path (e.g., /dev/sda, /dev/nvme0n1)
	Device string `yaml:"device" json:"device" mapstructure:"device"`

	// Role defines the drive's purpose
	Role DriveRole `yaml:"role" json:"role" mapstructure:"role"`

	// PartitionTable type (gpt or mbr)
	PartitionTable string `yaml:"partition-table" json:"partition_table" mapstructure:"partition-table"`

	// Partitions defines the partition layout
	Partitions []PartitionConfig `yaml:"partitions" json:"partitions" mapstructure:"partitions"`

	// WipeOnInstall wipes the drive before partitioning
	WipeOnInstall bool `yaml:"wipe-on-install,omitempty" json:"wipe_on_install,omitempty" mapstructure:"wipe-on-install"`
}

// PartitionConfig represents a partition on a drive
type PartitionConfig struct {
	// ID is a unique identifier for this partition
	ID string `yaml:"id" json:"id" mapstructure:"id"`

	// Number is the partition number (1, 2, 3, etc.)
	Number int `yaml:"number" json:"number" mapstructure:"number"`

	// Label is the partition label
	Label string `yaml:"label,omitempty" json:"label,omitempty" mapstructure:"label"`

	// Size is the partition size (e.g., "512M", "100G", "100%" for remaining)
	Size string `yaml:"size" json:"size" mapstructure:"size"`

	// Type specifies GPT partition type GUID or MBR type code
	Type string `yaml:"type,omitempty" json:"type,omitempty" mapstructure:"type"`

	// Filesystem configuration
	Filesystem *FilesystemConfig `yaml:"filesystem,omitempty" json:"filesystem,omitempty" mapstructure:"filesystem"`

	// Encryption configuration (nil = no encryption)
	Encryption *EncryptionConfig `yaml:"encryption,omitempty" json:"encryption,omitempty" mapstructure:"encryption"`

	// Mount defines how this partition should be mounted
	Mount *MountConfig `yaml:"mount,omitempty" json:"mount,omitempty" mapstructure:"mount"`

	// Flags contains partition flags (esp, boot, lvm, etc.)
	Flags []string `yaml:"flags,omitempty" json:"flags,omitempty" mapstructure:"flags"`
}

// FilesystemConfig defines filesystem settings for a partition
type FilesystemConfig struct {
	// Type of filesystem (ext4, xfs, zfs, vfat)
	Type FilesystemType `yaml:"type" json:"type" mapstructure:"type"`

	// Label for the filesystem
	Label string `yaml:"label,omitempty" json:"label,omitempty" mapstructure:"label"`

	// BlockSize for the filesystem (0 = default)
	BlockSize int `yaml:"block-size,omitempty" json:"block_size,omitempty" mapstructure:"block-size"`

	// Force formatting even if existing filesystem detected
	Force bool `yaml:"force,omitempty" json:"force,omitempty" mapstructure:"force"`

	// Ext4Options contains ext4-specific options
	Ext4Options *Ext4Options `yaml:"ext4,omitempty" json:"ext4,omitempty" mapstructure:"ext4"`

	// XFSOptions contains XFS-specific options
	XFSOptions *XFSOptions `yaml:"xfs,omitempty" json:"xfs,omitempty" mapstructure:"xfs"`

	// ZFSOptions contains ZFS-specific options
	ZFSOptions *ZFSOptions `yaml:"zfs,omitempty" json:"zfs,omitempty" mapstructure:"zfs"`
}

// Ext4Options contains ext4-specific formatting options
type Ext4Options struct {
	// JournalSize in MB (0 = auto)
	JournalSize int `yaml:"journal-size,omitempty" json:"journal_size,omitempty" mapstructure:"journal-size"`

	// InodeSize (128, 256, 512) - default 256
	InodeSize int `yaml:"inode-size,omitempty" json:"inode_size,omitempty" mapstructure:"inode-size"`

	// ReservedBlocksPercent percentage (default 5%)
	ReservedBlocksPercent float64 `yaml:"reserved-blocks-percent,omitempty" json:"reserved_blocks_percent,omitempty" mapstructure:"reserved-blocks-percent"`

	// StrideSize for RAID arrays (0 = none)
	StrideSize int `yaml:"stride-size,omitempty" json:"stride_size,omitempty" mapstructure:"stride-size"`

	// StripeWidth for RAID arrays (0 = none)
	StripeWidth int `yaml:"stripe-width,omitempty" json:"stripe_width,omitempty" mapstructure:"stripe-width"`

	// Enable64bit enables 64-bit block numbers
	Enable64bit bool `yaml:"enable-64bit,omitempty" json:"enable_64bit,omitempty" mapstructure:"enable-64bit"`
}

// XFSOptions contains XFS-specific formatting options
type XFSOptions struct {
	// AgCount is the number of allocation groups (0 = auto)
	AgCount int `yaml:"ag-count,omitempty" json:"ag_count,omitempty" mapstructure:"ag-count"`

	// BlockSize (512, 1024, 2048, 4096) - default 4096
	BlockSize int `yaml:"block-size,omitempty" json:"block_size,omitempty" mapstructure:"block-size"`

	// InodeSize (256, 512, 1024, 2048) - default 512
	InodeSize int `yaml:"inode-size,omitempty" json:"inode_size,omitempty" mapstructure:"inode-size"`

	// SectorSize (512, 4096) - default 512
	SectorSize int `yaml:"sector-size,omitempty" json:"sector_size,omitempty" mapstructure:"sector-size"`

	// LogSize in MB (0 = auto)
	LogSize int `yaml:"log-size,omitempty" json:"log_size,omitempty" mapstructure:"log-size"`

	// RefLink enables reflink support (CoW)
	RefLink bool `yaml:"reflink,omitempty" json:"reflink,omitempty" mapstructure:"reflink"`

	// BigTime enables timestamps beyond 2038
	BigTime bool `yaml:"bigtime,omitempty" json:"bigtime,omitempty" mapstructure:"bigtime"`
}

// ZFSOptions contains ZFS-specific options
type ZFSOptions struct {
	// PoolName is the name of the ZFS pool to create
	PoolName string `yaml:"pool-name" json:"pool_name" mapstructure:"pool-name"`

	// DatasetName is the name of the dataset (default: root)
	DatasetName string `yaml:"dataset-name,omitempty" json:"dataset_name,omitempty" mapstructure:"dataset-name"`

	// Compression algorithm (lz4, zstd, gzip, off)
	Compression string `yaml:"compression,omitempty" json:"compression,omitempty" mapstructure:"compression"`

	// Ashift value for alignment (9=512, 12=4K, 13=8K)
	Ashift int `yaml:"ashift,omitempty" json:"ashift,omitempty" mapstructure:"ashift"`

	// RecordSize (128K default)
	RecordSize string `yaml:"record-size,omitempty" json:"record_size,omitempty" mapstructure:"record-size"`

	// EnableDedup enables deduplication
	EnableDedup bool `yaml:"enable-dedup,omitempty" json:"enable_dedup,omitempty" mapstructure:"enable-dedup"`

	// MountPoint for the pool
	MountPoint string `yaml:"mount-point,omitempty" json:"mount_point,omitempty" mapstructure:"mount-point"`

	// Properties to set on the pool
	Properties map[string]string `yaml:"properties,omitempty" json:"properties,omitempty" mapstructure:"properties"`
}

// EncryptionConfig defines LUKS encryption settings for a partition
type EncryptionConfig struct {
	// Enabled enables LUKS encryption
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// MappingName is the device mapper name (e.g., "cryptroot", "cryptdata")
	MappingName string `yaml:"mapping-name" json:"mapping_name" mapstructure:"mapping-name"`

	// LUKS contains LUKS-specific settings
	LUKS *LUKSConfig `yaml:"luks,omitempty" json:"luks,omitempty" mapstructure:"luks"`

	// TPMSealing configuration for this volume
	TPMSealing *TPMSealingConfig `yaml:"tpm-sealing,omitempty" json:"tpm_sealing,omitempty" mapstructure:"tpm-sealing"`

	// RecoveryKey configuration
	RecoveryKey *RecoveryKeyConfig `yaml:"recovery-key,omitempty" json:"recovery_key,omitempty" mapstructure:"recovery-key"`
}

// LUKSConfig contains LUKS-specific settings
type LUKSConfig struct {
	// Version is LUKS version (always "luks2")
	Version string `yaml:"version,omitempty" json:"version,omitempty" mapstructure:"version"`

	// Cipher algorithm (default: aes-xts-plain64)
	Cipher string `yaml:"cipher,omitempty" json:"cipher,omitempty" mapstructure:"cipher"`

	// KeySize in bits (default: 512)
	KeySize int `yaml:"key-size,omitempty" json:"key_size,omitempty" mapstructure:"key-size"`

	// Hash algorithm (default: sha256)
	Hash string `yaml:"hash,omitempty" json:"hash,omitempty" mapstructure:"hash"`

	// PBKDF algorithm (default: argon2id)
	PBKDF string `yaml:"pbkdf,omitempty" json:"pbkdf,omitempty" mapstructure:"pbkdf"`

	// Argon2Memory in KB (default: 1048576 = 1GB)
	Argon2Memory int `yaml:"argon2-memory,omitempty" json:"argon2_memory,omitempty" mapstructure:"argon2-memory"`

	// Argon2Time iterations (default: 4)
	Argon2Time int `yaml:"argon2-time,omitempty" json:"argon2_time,omitempty" mapstructure:"argon2-time"`

	// Argon2Parallel threads (default: 4)
	Argon2Parallel int `yaml:"argon2-parallel,omitempty" json:"argon2_parallel,omitempty" mapstructure:"argon2-parallel"`

	// AllowDiscards enables TRIM/discard for SSDs
	AllowDiscards bool `yaml:"allow-discards,omitempty" json:"allow_discards,omitempty" mapstructure:"allow-discards"`
}

// TPMSealingConfig defines TPM sealing options per-volume
type TPMSealingConfig struct {
	// Enabled enables TPM sealing for this volume
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// KeySlot is the LUKS keyslot to use for TPM-sealed key (default: 1)
	KeySlot int `yaml:"key-slot,omitempty" json:"key_slot,omitempty" mapstructure:"key-slot"`

	// PCRPolicy enables PCR-based policy
	PCRPolicy bool `yaml:"pcr-policy" json:"pcr_policy" mapstructure:"pcr-policy"`

	// PCRSelection defines which PCRs to seal against
	PCRSelection []uint `yaml:"pcr-selection,omitempty" json:"pcr_selection,omitempty" mapstructure:"pcr-selection"`

	// PCRBanks defines which PCR banks to use (sha256, sha384, etc.)
	PCRBanks []string `yaml:"pcr-banks,omitempty" json:"pcr_banks,omitempty" mapstructure:"pcr-banks"`

	// KeyName is the identifier for this sealed key in XKMS
	KeyName string `yaml:"key-name,omitempty" json:"key_name,omitempty" mapstructure:"key-name"`

	// KeyAttributes for the sealed key (populated at runtime)
	KeyAttributes *xkmssdk.KeyAttributes `yaml:"-" json:"-" mapstructure:"-"`

	// SealedData contains the sealed key data from TPM (populated at runtime)
	SealedData *xkmssdk.SealedData `yaml:"-" json:"-" mapstructure:"-"`
}

// RecoveryKeyConfig defines recovery key options
type RecoveryKeyConfig struct {
	// Generate enables generation of a recovery key
	Generate bool `yaml:"generate" json:"generate" mapstructure:"generate"`

	// KeySlot is the LUKS keyslot to use for recovery key (default: 2)
	KeySlot int `yaml:"key-slot,omitempty" json:"key_slot,omitempty" mapstructure:"key-slot"`

	// OutputPath is where to store the recovery key file
	OutputPath string `yaml:"output-path,omitempty" json:"output_path,omitempty" mapstructure:"output-path"`

	// Format specifies output format (hex, base64, dashed)
	Format RecoveryKeyFormat `yaml:"format,omitempty" json:"format,omitempty" mapstructure:"format"`

	// Length is the key length in bytes (default: 32)
	Length int `yaml:"length,omitempty" json:"length,omitempty" mapstructure:"length"`
}

// MountConfig defines mount configuration
type MountConfig struct {
	// Mountpoint is the target mount path
	Mountpoint string `yaml:"mountpoint" json:"mountpoint" mapstructure:"mountpoint"`

	// ReadOnly mounts filesystem read-only
	ReadOnly bool `yaml:"read-only,omitempty" json:"read_only,omitempty" mapstructure:"read-only"`

	// NoExec disables execution
	NoExec bool `yaml:"noexec,omitempty" json:"noexec,omitempty" mapstructure:"noexec"`

	// NoSUID disables suid bits
	NoSUID bool `yaml:"nosuid,omitempty" json:"nosuid,omitempty" mapstructure:"nosuid"`

	// NoDev disables device files
	NoDev bool `yaml:"nodev,omitempty" json:"nodev,omitempty" mapstructure:"nodev"`

	// Options is a comma-separated string of additional mount options
	Options string `yaml:"options,omitempty" json:"options,omitempty" mapstructure:"options"`

	// AutoMount enables automatic mounting
	AutoMount bool `yaml:"auto-mount,omitempty" json:"auto_mount,omitempty" mapstructure:"auto-mount"`

	// MountOrder is the order for mounting (lower = earlier)
	MountOrder int `yaml:"mount-order,omitempty" json:"mount_order,omitempty" mapstructure:"mount-order"`

	// Dependencies lists partition IDs that must be mounted first
	Dependencies []string `yaml:"dependencies,omitempty" json:"dependencies,omitempty" mapstructure:"dependencies"`
}

// StorageConfig represents the complete multi-drive storage configuration
type StorageConfig struct {
	// Drives is the list of drive configurations
	Drives []DriveConfig `yaml:"drives" json:"drives" mapstructure:"drives"`

	// DefaultFilesystem is the default filesystem type for new partitions
	DefaultFilesystem FilesystemType `yaml:"default-filesystem,omitempty" json:"default_filesystem,omitempty" mapstructure:"default-filesystem"`

	// DefaultLUKSConfig is the default LUKS configuration
	DefaultLUKS *LUKSConfig `yaml:"default-luks,omitempty" json:"default_luks,omitempty" mapstructure:"default-luks"`

	// RequireRootEncryption ensures root partition is always encrypted
	RequireRootEncryption bool `yaml:"require-root-encryption,omitempty" json:"require_root_encryption,omitempty" mapstructure:"require-root-encryption"`
}

// VolumeUnlockConfig represents a volume to unlock during boot
type VolumeUnlockConfig struct {
	// PartitionID references the partition ID from drive configuration
	PartitionID string `yaml:"partition-id" json:"partition_id" mapstructure:"partition-id"`

	// DevicePath is the block device path
	DevicePath string `yaml:"device-path" json:"device_path" mapstructure:"device-path"`

	// MappingName for device mapper
	MappingName string `yaml:"mapping-name" json:"mapping_name" mapstructure:"mapping-name"`

	// Mountpoint for this volume
	Mountpoint string `yaml:"mountpoint,omitempty" json:"mountpoint,omitempty" mapstructure:"mountpoint"`

	// IsRoot indicates this is the root filesystem
	IsRoot bool `yaml:"is-root,omitempty" json:"is_root,omitempty" mapstructure:"is-root"`

	// FilesystemType for mounting
	FilesystemType FilesystemType `yaml:"filesystem-type,omitempty" json:"filesystem_type,omitempty" mapstructure:"filesystem-type"`

	// UnlockMethods in priority order
	UnlockMethods []UnlockMethod `yaml:"unlock-methods,omitempty" json:"unlock_methods,omitempty" mapstructure:"unlock-methods"`

	// TPMKeyName is the name of the TPM-sealed key for this volume
	TPMKeyName string `yaml:"tpm-key-name,omitempty" json:"tpm_key_name,omitempty" mapstructure:"tpm-key-name"`

	// Dependencies lists volume IDs that must be unlocked first
	Dependencies []string `yaml:"dependencies,omitempty" json:"dependencies,omitempty" mapstructure:"dependencies"`

	// MountOrder determines mount sequence (lower = earlier)
	MountOrder int `yaml:"mount-order,omitempty" json:"mount_order,omitempty" mapstructure:"mount-order"`

	// TPMSealing configuration reference
	TPMSealing *TPMSealingConfig `yaml:"tpm-sealing,omitempty" json:"tpm_sealing,omitempty" mapstructure:"tpm-sealing"`

	// KeyAttributes for unsealing (populated at runtime)
	KeyAttributes *xkmssdk.KeyAttributes `yaml:"-" json:"-" mapstructure:"-"`
}

// UnlockMethod defines how to unlock an encrypted volume
type UnlockMethod string

const (
	// UnlockTPMPCR uses TPM with PCR-based policy
	UnlockTPMPCR UnlockMethod = "tpm-pcr"

	// UnlockTPMNoPCR uses TPM without PCR policy (for upgrades)
	UnlockTPMNoPCR UnlockMethod = "tpm-nopcr"

	// UnlockFIDO2 uses FIDO2 hardware authenticator
	UnlockFIDO2 UnlockMethod = "fido2"

	// UnlockPassword uses interactive password prompt
	UnlockPassword UnlockMethod = "password"

	// UnlockKeyfile uses a key file
	UnlockKeyfile UnlockMethod = "keyfile"

	// UnlockRecovery uses recovery key
	UnlockRecovery UnlockMethod = "recovery"
)

// DefaultStorageConfig returns a StorageConfig with sensible defaults
func DefaultStorageConfig() *StorageConfig {
	return &StorageConfig{
		DefaultFilesystem:     FilesystemExt4,
		RequireRootEncryption: true,
		DefaultLUKS: &LUKSConfig{
			Version:        "luks2",
			Cipher:         "aes-xts-plain64",
			KeySize:        512,
			Hash:           "sha256",
			PBKDF:          "argon2id",
			Argon2Memory:   1048576, // 1GB
			Argon2Time:     4,
			Argon2Parallel: 4,
			AllowDiscards:  true,
		},
	}
}

// DefaultTPMSealingConfig returns default TPM sealing configuration
func DefaultTPMSealingConfig() *TPMSealingConfig {
	return &TPMSealingConfig{
		Enabled:      true,
		KeySlot:      1,
		PCRPolicy:    true,
		PCRSelection: []uint{0, 1, 2, 3, 7, 9},
		PCRBanks:     []string{"sha256"},
	}
}

// DefaultRecoveryKeyConfig returns default recovery key configuration
func DefaultRecoveryKeyConfig() *RecoveryKeyConfig {
	return &RecoveryKeyConfig{
		Generate: true,
		KeySlot:  2,
		Format:   RecoveryKeyFormatDashed,
		Length:   32,
	}
}

// Validate validates the storage configuration
func (c *StorageConfig) Validate() error {
	if len(c.Drives) == 0 {
		return ErrNoDrivesConfigured
	}

	// Check for system drive
	hasSystemDrive := false
	for _, drive := range c.Drives {
		if drive.Role == DriveRoleSystem {
			hasSystemDrive = true
			break
		}
	}
	if !hasSystemDrive {
		return ErrNoSystemDrive
	}

	// Validate each drive
	for _, drive := range c.Drives {
		if err := drive.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// Validate validates a drive configuration
func (d *DriveConfig) Validate() error {
	if d.ID == "" {
		return ErrDriveIDRequired
	}
	if d.Device == "" {
		return ErrDevicePathRequired
	}
	if len(d.Partitions) == 0 {
		return ErrNoPartitions
	}

	for _, part := range d.Partitions {
		if err := part.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// Validate validates a partition configuration
func (p *PartitionConfig) Validate() error {
	if p.ID == "" {
		return ErrPartitionIDRequired
	}
	if p.Number < 1 {
		return ErrInvalidPartitionNumber
	}
	if p.Size == "" {
		return ErrPartitionSizeRequired
	}
	return nil
}

// GetSystemDrive returns the system drive configuration
func (c *StorageConfig) GetSystemDrive() *DriveConfig {
	for i := range c.Drives {
		if c.Drives[i].Role == DriveRoleSystem {
			return &c.Drives[i]
		}
	}
	return nil
}

// GetRootPartition returns the root partition from the system drive
func (c *StorageConfig) GetRootPartition() *PartitionConfig {
	systemDrive := c.GetSystemDrive()
	if systemDrive == nil {
		return nil
	}

	for i := range systemDrive.Partitions {
		part := &systemDrive.Partitions[i]
		if part.Mount != nil && part.Mount.Mountpoint == "/" {
			return part
		}
	}
	return nil
}

// GetEFIPartition returns the EFI partition from the system drive
func (c *StorageConfig) GetEFIPartition() *PartitionConfig {
	systemDrive := c.GetSystemDrive()
	if systemDrive == nil {
		return nil
	}

	for i := range systemDrive.Partitions {
		part := &systemDrive.Partitions[i]
		// Check for EFI flags or mount point
		for _, flag := range part.Flags {
			if flag == "esp" || flag == "boot" {
				return part
			}
		}
		if part.Mount != nil && (part.Mount.Mountpoint == "/boot/efi" || part.Mount.Mountpoint == "/boot") {
			return part
		}
	}
	return nil
}

// GetEncryptedPartitions returns all partitions with encryption enabled
func (c *StorageConfig) GetEncryptedPartitions() []*PartitionConfig {
	var encrypted []*PartitionConfig
	for i := range c.Drives {
		for j := range c.Drives[i].Partitions {
			part := &c.Drives[i].Partitions[j]
			if part.Encryption != nil && part.Encryption.Enabled {
				encrypted = append(encrypted, part)
			}
		}
	}
	return encrypted
}
