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

package luks

import (
	"context"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// UnlockMethod represents a method for unlocking LUKS volumes
type UnlockMethod string

const (
	// UnlockTPMPCR uses TPM with PCR-based policy + PIN
	// Platform KeyStore SRK (0x81000002) with PCR auth policy
	UnlockTPMPCR UnlockMethod = "tpm-pcr"

	// UnlockTPMNoPCR uses TPM without PCR verification
	UnlockTPMNoPCR UnlockMethod = "tpm-nopcr"

	// UnlockTPMUpgrade uses TPM upgrade key for system updates
	// No policy at all - only for one-time use during kernel upgrades
	UnlockTPMUpgrade UnlockMethod = "tpm-upgrade"

	// UnlockPassword uses password-based unlock (LUKS passphrase)
	UnlockPassword UnlockMethod = "password"

	// UnlockKeyfile uses keyfile-based unlock
	UnlockKeyfile UnlockMethod = "keyfile"

	// UnlockFIDO2 uses FIDO2 device for unlock
	UnlockFIDO2 UnlockMethod = "fido2"
)

// LUKS version constants
const (
	LUKS1 LUKSVersion = 1
	LUKS2 LUKSVersion = 2
)

// VolumeConfig represents configuration for a LUKS volume
type VolumeConfig struct {
	// DevicePath is the path to the block device
	DevicePath string

	// MappingName is the device mapper name (e.g., "cryptroot")
	MappingName string

	// Cipher is the encryption cipher (e.g., "aes-xts-plain64")
	Cipher string

	// KeySize is the encryption key size in bits
	KeySize int

	// Hash is the hash algorithm for key derivation
	Hash string

	// KeySlots contains information about configured key slots
	KeySlots []KeySlot

	// MountPoint is the intended mount point
	MountPoint string

	// Filesystem is the filesystem type (e.g., "ext4", "btrfs")
	Filesystem string

	// Label is the volume label
	Label string

	// UUID is the LUKS volume UUID
	UUID string

	// PCRSelection for TPM sealing
	PCRSelection []uint

	// PCRBanks for TPM sealing
	PCRBanks []string

	// XKMSPath for sealed keys
	XKMSPath string

	// LUKSVersion is the LUKS format version
	LUKSVersion LUKSVersion

	// AllowDiscards enables TRIM/discard passthrough
	AllowDiscards bool

	// Timeout is the unlock timeout in seconds
	Timeout int

	// HashAlgorithm is the hash algorithm for key derivation (e.g., "sha256")
	HashAlgorithm string

	// PBKDFType is the key derivation function type (e.g., "argon2id", "pbkdf2")
	PBKDFType string
}

// KeySlot contains information about a LUKS key slot
type KeySlot struct {
	// Index is the slot index number
	Index int

	// Type is the unlock method type for this slot
	Type UnlockMethod

	// Priority is the slot priority (lower = higher priority)
	Priority int

	// Enabled indicates if the slot is active
	Enabled bool

	// Attrs contains key attributes for this slot
	Attrs *xkmssdk.KeyAttributes

	// SealedData contains TPM-sealed key data for this slot
	SealedData *xkmssdk.SealedData
}

// KeySlotInfo is an alias for backward compatibility
type KeySlotInfo = KeySlot

// Handler defines the interface for LUKS operations
type Handler interface {
	// IsLUKS checks if a device is a LUKS volume
	IsLUKS(ctx context.Context, devicePath string) (bool, error)

	// Format formats a device with LUKS encryption
	Format(ctx context.Context, devicePath string, password []byte, opts *FormatOptions) error

	// AddKey adds a new key to a LUKS volume
	AddKey(ctx context.Context, devicePath string, existingPassword, newPassword []byte, opts *AddKeyOptions) error

	// Open opens (unlocks) a LUKS volume
	Open(ctx context.Context, devicePath, mappingName string, password []byte, opts *OpenOptions) error

	// IsOpen checks if a LUKS volume is already unlocked (device-mapper mapping exists)
	IsOpen(ctx context.Context, mappingName string) bool

	// Close closes (locks) a LUKS volume
	Close(ctx context.Context, mappingName string) error

	// Status returns status information about a LUKS volume
	Status(ctx context.Context, devicePath string) (*VolumeStatus, error)

	// Version returns the LUKS version of a device
	Version(ctx context.Context, devicePath string) (LUKSVersion, error)

	// RemoveKey removes a key from a specific slot
	RemoveKey(ctx context.Context, devicePath string, slot int) error

	// KillSlot kills (disables) a key slot
	KillSlot(ctx context.Context, devicePath string, slot int) error

	// ChangeKey changes the key in a specific slot
	ChangeKey(ctx context.Context, devicePath string, slot int, oldPassword, newPassword []byte) error

	// UUID returns the UUID of a LUKS volume
	UUID(ctx context.Context, devicePath string) (string, error)

	// DumpHeader dumps the LUKS header information
	DumpHeader(ctx context.Context, devicePath string) (map[string]interface{}, error)

	// TestKey tests if a password is valid for a LUKS volume
	TestKey(ctx context.Context, devicePath string, password []byte, slot *int) error

	// Resize resizes an open LUKS volume
	Resize(ctx context.Context, mappingName string, newSize *uint64) error

	// Suspend suspends an open LUKS volume (dm-crypt suspend)
	Suspend(ctx context.Context, mappingName string) error

	// Resume resumes a suspended LUKS volume
	Resume(ctx context.Context, mappingName string, password []byte) error
}

// HandlerWithTokens extends Handler with LUKS2 token metadata operations.
// Use this interface when you need both basic LUKS operations and token management.
type HandlerWithTokens interface {
	Handler
	TokenHandler
}

// OpenOptions contains options for opening a LUKS volume
type OpenOptions struct {
	// ReadOnly opens the volume in read-only mode
	ReadOnly bool

	// AllowDiscards enables TRIM/discard passthrough
	AllowDiscards bool

	// NoReadWorkqueue disables read workqueue
	NoReadWorkqueue bool

	// NoWriteWorkqueue disables write workqueue
	NoWriteWorkqueue bool

	// SubmitFromCryptCPUs submits IO from crypt CPUs
	SubmitFromCryptCPUs bool

	// Timeout is the unlock timeout in seconds
	Timeout int

	// KeySlot specifies which key slot to use (nil means any)
	KeySlot *int
}

// VolumeStatus contains status information about a LUKS volume
type VolumeStatus struct {
	// Active indicates if the volume is active (unlocked)
	Active bool

	// DevicePath is the underlying device path
	DevicePath string

	// MappingPath is the device mapper path
	MappingPath string

	// Cipher is the encryption cipher
	Cipher string

	// KeySize is the key size in bits
	KeySize int

	// Mode is the cipher mode
	Mode string

	// Offset is the data offset
	Offset uint64

	// Size is the volume size
	Size uint64

	// Version is the LUKS version
	Version LUKSVersion

	// UUID is the volume UUID
	UUID string

	// ActiveSlots contains indices of active (occupied) key slots
	ActiveSlots []int
}

// LUKSVersion represents the LUKS format version
type LUKSVersion int

const (
	// LUKSVersion1 represents LUKS version 1
	LUKSVersion1 LUKSVersion = 1

	// LUKSVersion2 represents LUKS version 2
	LUKSVersion2 LUKSVersion = 2
)

// FormatOptions contains options for formatting a LUKS volume
type FormatOptions struct {
	// Device is the path to the device/file
	Device string

	// Passphrase is the initial passphrase
	Passphrase []byte

	// Label is the volume label
	Label string

	// Subsystem is the subsystem label
	Subsystem string

	// Cipher is the cipher algorithm (default: "aes")
	Cipher string

	// CipherMode is the cipher mode (default: "xts-plain64")
	CipherMode string

	// KeySize is the key size in bits (default: 512)
	KeySize int

	// HashAlgo is the hash algorithm (default: "sha256")
	HashAlgo string

	// HashAlgorithm is the hash algorithm (alias for HashAlgo)
	HashAlgorithm string

	// SectorSize is the sector size (default: 512)
	SectorSize int

	// KDFType is the KDF type: "pbkdf2", "argon2i", "argon2id"
	KDFType string

	// PBKDFType is the PBKDF type (alias for KDFType)
	PBKDFType string

	// PBKDFIterTime is the target time for PBKDF2 in ms
	PBKDFIterTime int

	// Argon2Time is the Argon2 time cost
	Argon2Time int

	// Argon2Memory is the Argon2 memory cost in KB
	Argon2Memory int

	// Argon2Parallel is the Argon2 parallelism
	Argon2Parallel int
}

// AddKeyOptions contains options for adding a key to a LUKS volume
type AddKeyOptions struct {
	// KeySlot specifies which key slot to use
	KeySlot *int

	// Keyslot is an alias for KeySlot for compatibility
	Keyslot *int

	// Force allows adding key even if slot is occupied
	Force bool

	// KDFType specifies the password-based key derivation function (e.g., "pbkdf2", "argon2id")
	// If empty, defaults to argon2id
	KDFType string

	// Hash specifies the hash algorithm for PBKDF (e.g., "sha256", "sha512")
	// Only used when KDFType is "pbkdf2"
	Hash string
}

// NewCryptsetupHandler creates a new LUKS handler using go-luks2
func NewCryptsetupHandler(config *Config, logger interface{}) (Handler, error) {
	return NewCryptsetupHandlerImpl(config, logger)
}

// NewCryptsetupHandlerWithTokens creates a new LUKS handler with token support using go-luks2
func NewCryptsetupHandlerWithTokens(config *Config, logger interface{}) (HandlerWithTokens, error) {
	return NewCryptsetupHandlerImpl(config, logger)
}
