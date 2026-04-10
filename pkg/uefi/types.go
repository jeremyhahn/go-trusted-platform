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

package uefi

import "errors"

// Error definitions
var (
	// ErrInvalidFormat indicates invalid data format
	ErrInvalidFormat = errors.New("invalid format")
	// ErrInvalidGUID indicates an invalid GUID
	ErrInvalidGUID = errors.New("invalid GUID")
	// ErrInvalidSignature indicates an invalid signature in a header
	ErrInvalidSignature = errors.New("invalid signature")
	// ErrInvalidChecksum indicates a checksum mismatch
	ErrInvalidChecksum = errors.New("invalid checksum")
	// ErrVariableNotFound indicates a variable was not found
	ErrVariableNotFound = errors.New("variable not found")
	// ErrInsufficientSpace indicates insufficient space in variable store
	ErrInsufficientSpace = errors.New("insufficient space")
	// ErrReadOnly indicates an attempt to modify a read-only value
	ErrReadOnly = errors.New("read-only")
)

// Variable Attributes (EFI_VARIABLE_* from UEFI spec)
const (
	// EFI_VARIABLE_NON_VOLATILE - Variable persists across power cycles
	AttrNonVolatile uint32 = 0x00000001

	// EFI_VARIABLE_BOOTSERVICE_ACCESS - Variable accessible during boot services
	AttrBootserviceAccess uint32 = 0x00000002

	// EFI_VARIABLE_RUNTIME_ACCESS - Variable accessible during runtime
	AttrRuntimeAccess uint32 = 0x00000004

	// EFI_VARIABLE_HARDWARE_ERROR_RECORD - Variable is a hardware error record
	AttrHardwareErrorRecord uint32 = 0x00000008

	// EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS - Deprecated, use TIME_BASED
	AttrAuthenticatedWriteAccess uint32 = 0x00000010

	// EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS - Variable uses time-based authentication
	AttrTimeBasedAuthWriteAccess uint32 = 0x00000020

	// EFI_VARIABLE_APPEND_WRITE - Data is appended to existing value
	AttrAppendWrite uint32 = 0x00000040
)

// SecureBootAttributes is the standard attribute set for Secure Boot variables
const SecureBootAttributes = AttrNonVolatile |
	AttrBootserviceAccess |
	AttrRuntimeAccess |
	AttrTimeBasedAuthWriteAccess

// Variable State values
const (
	// VAR_IN_DELETED_TRANSITION - Variable is being deleted
	VarStateDeletedTransition uint8 = 0xFE

	// VAR_DELETED - Variable has been deleted
	VarStateDeleted uint8 = 0xFD

	// VAR_ADDED - Variable is valid and active
	VarStateAdded uint8 = 0x3F

	// VAR_HEADER_VALID_ONLY - Only header is valid (data may be corrupt)
	VarStateHeaderValidOnly uint8 = 0x7F
)

// Variable Store State values
const (
	// VARIABLE_STORE_HEALTHY - Variable store is healthy
	VarStoreHealthy uint8 = 0xFE

	// VARIABLE_STORE_FORMATTED - Variable store is formatted but empty
	VarStoreFormatted uint8 = 0x5A
)

// Firmware Volume Attributes
const (
	// EFI_FVB2_READ_DISABLED_CAP - Read disable capability
	FvbReadDisabledCap uint32 = 0x00000001

	// EFI_FVB2_READ_ENABLED_CAP - Read enable capability
	FvbReadEnabledCap uint32 = 0x00000002

	// EFI_FVB2_READ_STATUS - Current read status
	FvbReadStatus uint32 = 0x00000004

	// EFI_FVB2_WRITE_DISABLED_CAP - Write disable capability
	FvbWriteDisabledCap uint32 = 0x00000008

	// EFI_FVB2_WRITE_ENABLED_CAP - Write enable capability
	FvbWriteEnabledCap uint32 = 0x00000010

	// EFI_FVB2_WRITE_STATUS - Current write status
	FvbWriteStatus uint32 = 0x00000020

	// EFI_FVB2_LOCK_CAP - Locking capability
	FvbLockCap uint32 = 0x00000040

	// EFI_FVB2_LOCK_STATUS - Current lock status
	FvbLockStatus uint32 = 0x00000080

	// EFI_FVB2_STICKY_WRITE - Sticky write (persists)
	FvbStickyWrite uint32 = 0x00000200

	// EFI_FVB2_MEMORY_MAPPED - Memory mapped access
	FvbMemoryMapped uint32 = 0x00000400

	// EFI_FVB2_ERASE_POLARITY - Erased state polarity
	FvbErasePolarity uint32 = 0x00000800

	// EFI_FVB2_READ_LOCK_CAP - Read lock capability
	FvbReadLockCap uint32 = 0x00001000

	// EFI_FVB2_READ_LOCK_STATUS - Read lock status
	FvbReadLockStatus uint32 = 0x00002000

	// EFI_FVB2_WRITE_LOCK_CAP - Write lock capability
	FvbWriteLockCap uint32 = 0x00004000

	// EFI_FVB2_WRITE_LOCK_STATUS - Write lock status
	FvbWriteLockStatus uint32 = 0x00008000

	// EFI_FVB2_ALIGNMENT - Alignment mask (bits 16-31)
	FvbAlignment uint32 = 0x001F0000

	// EFI_FVB2_WEAK_ALIGNMENT - Allow weak alignment
	FvbWeakAlignment uint32 = 0x80000000
)

// Firmware Volume signatures
var (
	// FirmwareVolumeSignature is the '_FVH' signature in FV headers
	FirmwareVolumeSignature = [4]byte{'_', 'F', 'V', 'H'}

	// VariableHeaderStartID is the 0x55AA marker at start of each variable
	VariableHeaderStartID uint16 = 0x55AA
)

// Size constants
const (
	// FirmwareVolumeHeaderMinSize is the minimum FV header size (without block map)
	FirmwareVolumeHeaderMinSize = 56

	// VariableStoreHeaderSize is the size of the variable store header
	VariableStoreHeaderSize = 28

	// VariableHeaderSize is the size of a standard variable header (without name/data)
	VariableHeaderSize = 32

	// AuthVariableHeaderSize is the size of an authenticated variable header
	AuthVariableHeaderSize = 60

	// SignatureListHeaderSize is the size of an ESL header
	SignatureListHeaderSize = 28

	// SignatureDataHeaderSize is the size of an EFI_SIGNATURE_DATA header (just the GUID)
	SignatureDataHeaderSize = 16
)

// EFITime represents an EFI_TIME structure (16 bytes)
type EFITime struct {
	Year       uint16
	Month      uint8
	Day        uint8
	Hour       uint8
	Minute     uint8
	Second     uint8
	Pad1       uint8
	Nanosecond uint32
	TimeZone   int16
	Daylight   uint8
	Pad2       uint8
}

// EFITimeSize is the size of an EFI_TIME structure
const EFITimeSize = 16

// FirmwareVolumeHeader represents an EFI_FIRMWARE_VOLUME_HEADER
type FirmwareVolumeHeader struct {
	ZeroVector      [16]byte
	FileSystemGUID  GUID
	FvLength        uint64
	Signature       [4]byte
	Attributes      uint32
	HeaderLength    uint16
	Checksum        uint16
	ExtHeaderOffset uint16
	Reserved        uint8
	Revision        uint8
}

// FvBlockMapEntry represents a block map entry
type FvBlockMapEntry struct {
	NumBlocks uint32
	Length    uint32
}

// VariableStoreHeader represents a VARIABLE_STORE_HEADER
type VariableStoreHeader struct {
	Signature GUID
	Size      uint32
	Format    uint8
	State     uint8
	Reserved  uint16
	Reserved1 uint32
}

// Variable represents an EFI variable (name, GUID, attributes, and data)
type Variable struct {
	Name       string
	GUID       GUID
	Attributes uint32
	Data       []byte
}

// SignatureList represents an EFI_SIGNATURE_LIST
type SignatureList struct {
	SignatureType       GUID
	SignatureListSize   uint32
	SignatureHeaderSize uint32
	SignatureSize       uint32
	Header              []byte          // Optional signature header
	Signatures          []SignatureData // Array of signatures
}

// SignatureData represents an EFI_SIGNATURE_DATA
type SignatureData struct {
	Owner GUID
	Data  []byte // Signature data (certificate, hash, etc.)
}
