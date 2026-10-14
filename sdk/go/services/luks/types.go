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

// Package luks provides SDK types and a client for the platform LUKS2 volume
// management service.
package luks

// KeyType enumerates the keyslot backends the service supports.
type KeyType string

const (
	// KeyTypeUnspecified indicates the key type was not provided.
	KeyTypeUnspecified KeyType = ""
	// KeyTypePassphrase is a passphrase keyslot.
	KeyTypePassphrase KeyType = "passphrase"
	// KeyTypeFIDO2 is a FIDO2 keyslot.
	KeyTypeFIDO2 KeyType = "fido2"
	// KeyTypeTPM is a TPM2-sealed keyslot.
	KeyTypeTPM KeyType = "tpm"
	// KeyTypeRecovery is a recovery-key keyslot.
	KeyTypeRecovery KeyType = "recovery"
)

// Keyslot describes a single LUKS2 keyslot.
type Keyslot struct {
	// Slot is the 0-based keyslot index.
	Slot int32 `json:"slot" yaml:"slot"`
	// Type is the keyslot backend type.
	Type KeyType `json:"type,omitempty" yaml:"type,omitempty"`
	// KeySize is the master-key size in bytes.
	KeySize int32 `json:"key_size,omitempty" yaml:"key_size,omitempty"`
	// Priority is the LUKS2 slot priority.
	Priority int32 `json:"priority,omitempty" yaml:"priority,omitempty"`
}

// StatusRequest requests the status of a LUKS device.
type StatusRequest struct {
	// Device is the block device path (empty means auto-detect).
	Device string `json:"device,omitempty" yaml:"device,omitempty"`
}

// StatusResponse describes the device header status.
type StatusResponse struct {
	// Device is the resolved device path.
	Device string `json:"device" yaml:"device"`
	// IsLUKS indicates whether the device carries a LUKS header.
	IsLUKS bool `json:"is_luks" yaml:"is_luks"`
	// Version is the LUKS header version (1 or 2).
	Version int32 `json:"version,omitempty" yaml:"version,omitempty"`
	// UUID is the volume UUID.
	UUID string `json:"uuid,omitempty" yaml:"uuid,omitempty"`
	// Label is the volume label, if any.
	Label string `json:"label,omitempty" yaml:"label,omitempty"`
	// Cipher is the volume cipher (for example "aes-xts-plain64").
	Cipher string `json:"cipher,omitempty" yaml:"cipher,omitempty"`
	// ActiveSlots lists the active keyslot indices.
	ActiveSlots []int32 `json:"active_slots,omitempty" yaml:"active_slots,omitempty"`
}

// ListSlotsRequest requests the keyslot listing for a device.
type ListSlotsRequest struct {
	// Device is the block device path (empty means auto-detect).
	Device string `json:"device,omitempty" yaml:"device,omitempty"`
}

// ListSlotsResponse lists the active keyslots.
type ListSlotsResponse struct {
	// Device is the resolved device path.
	Device string `json:"device" yaml:"device"`
	// Slots are the active keyslots.
	Slots []Keyslot `json:"slots,omitempty" yaml:"slots,omitempty"`
}

// InfoRequest requests a detailed info dump for a device.
type InfoRequest struct {
	// Device is the block device path (empty means auto-detect).
	Device string `json:"device,omitempty" yaml:"device,omitempty"`
}

// InfoResponse returns the full LUKS2 header / metadata.
type InfoResponse struct {
	// Device is the resolved device path.
	Device string `json:"device" yaml:"device"`
	// UUID is the volume UUID.
	UUID string `json:"uuid,omitempty" yaml:"uuid,omitempty"`
	// Label is the volume label, if any.
	Label string `json:"label,omitempty" yaml:"label,omitempty"`
	// Version is the LUKS header version.
	Version int32 `json:"version,omitempty" yaml:"version,omitempty"`
	// Cipher is the volume cipher.
	Cipher string `json:"cipher,omitempty" yaml:"cipher,omitempty"`
	// KeySize is the master-key size in bits.
	KeySize int32 `json:"key_size,omitempty" yaml:"key_size,omitempty"`
	// SectorSize is the volume sector size in bytes.
	SectorSize int32 `json:"sector_size,omitempty" yaml:"sector_size,omitempty"`
	// Slots are the active keyslots.
	Slots []Keyslot `json:"slots,omitempty" yaml:"slots,omitempty"`
	// MetadataJSON is the raw JSON metadata payload (for operators who want it).
	MetadataJSON string `json:"metadata_json,omitempty" yaml:"metadata_json,omitempty"`
}

// EnrollPassphraseRequest asks the service to add a passphrase keyslot.
type EnrollPassphraseRequest struct {
	// Device is the block device path.
	Device string `json:"device" yaml:"device"`
	// ExistingPassphrase is an existing passphrase for the device.
	ExistingPassphrase string `json:"existing_passphrase" yaml:"existing_passphrase"`
	// NewPassphrase is the passphrase to enroll.
	NewPassphrase string `json:"new_passphrase" yaml:"new_passphrase"`
}

// EnrollPassphraseResponse returns the enrolled slot index.
type EnrollPassphraseResponse struct {
	// Slot is the 0-based keyslot index of the new slot.
	Slot int32 `json:"slot" yaml:"slot"`
}

// EnrollFIDO2Request asks the service to add a FIDO2 keyslot.
type EnrollFIDO2Request struct {
	// Device is the block device path.
	Device string `json:"device" yaml:"device"`
	// ExistingPassphrase is an existing passphrase for the device.
	ExistingPassphrase string `json:"existing_passphrase" yaml:"existing_passphrase"`
	// CredentialID is the FIDO2 credential id (base64url).
	CredentialID string `json:"credential_id" yaml:"credential_id"`
	// RequirePIN requires user PIN for the FIDO2 ceremony.
	RequirePIN bool `json:"require_pin" yaml:"require_pin"`
	// RequireUV requires user verification (biometric / PIN).
	RequireUV bool `json:"require_uv" yaml:"require_uv"`
}

// EnrollFIDO2Response returns the enrolled slot index.
type EnrollFIDO2Response struct {
	// Slot is the 0-based keyslot index of the new slot.
	Slot int32 `json:"slot" yaml:"slot"`
	// TokenID is the LUKS2 token id attached to the slot.
	TokenID string `json:"token_id,omitempty" yaml:"token_id,omitempty"`
}

// EnrollTPMRequest asks the service to add a TPM2-sealed keyslot.
type EnrollTPMRequest struct {
	// Device is the block device path.
	Device string `json:"device" yaml:"device"`
	// ExistingPassphrase is an existing passphrase for the device.
	ExistingPassphrase string `json:"existing_passphrase" yaml:"existing_passphrase"`
	// PCRs are the PCR indices to bind to.
	PCRs []int32 `json:"pcrs,omitempty" yaml:"pcrs,omitempty"`
	// Handle is the persistent NV handle (for example 0x81000003).
	Handle string `json:"handle,omitempty" yaml:"handle,omitempty"`
}

// EnrollTPMResponse returns the enrolled slot index.
type EnrollTPMResponse struct {
	// Slot is the 0-based keyslot index of the new slot.
	Slot int32 `json:"slot" yaml:"slot"`
	// TokenID is the LUKS2 token id attached to the slot.
	TokenID string `json:"token_id,omitempty" yaml:"token_id,omitempty"`
}

// EnrollRecoveryRequest asks the service to add a recovery-key keyslot.
type EnrollRecoveryRequest struct {
	// Device is the block device path.
	Device string `json:"device" yaml:"device"`
	// ExistingPassphrase is an existing passphrase for the device.
	ExistingPassphrase string `json:"existing_passphrase" yaml:"existing_passphrase"`
}

// EnrollRecoveryResponse returns the enrolled slot index and the recovery key.
// The recovery key is only returned once; callers must persist it.
type EnrollRecoveryResponse struct {
	// Slot is the 0-based keyslot index of the new slot.
	Slot int32 `json:"slot" yaml:"slot"`
	// RecoveryKey is the generated recovery key (only returned on enrollment).
	RecoveryKey string `json:"recovery_key,omitempty" yaml:"recovery_key,omitempty"`
}

// RemoveKeyRequest asks the service to remove a keyslot.
type RemoveKeyRequest struct {
	// Device is the block device path.
	Device string `json:"device" yaml:"device"`
	// Slot is the 0-based keyslot index to remove.
	Slot int32 `json:"slot" yaml:"slot"`
}

// RemoveKeyResponse returns the outcome of a slot removal.
type RemoveKeyResponse struct {
	// Removed is true when the slot was removed.
	Removed bool `json:"removed" yaml:"removed"`
}

// TestUnlockRequest asks the service to verify a keyslot can unlock a device.
type TestUnlockRequest struct {
	// Device is the block device path.
	Device string `json:"device" yaml:"device"`
	// Slot is the 0-based keyslot index to test.
	Slot int32 `json:"slot" yaml:"slot"`
}

// TestUnlockResponse returns the outcome of an unlock test.
type TestUnlockResponse struct {
	// Unlocked is true when the slot successfully unlocked the master key.
	Unlocked bool `json:"unlocked" yaml:"unlocked"`
}

// ChangePassphraseRequest asks the service to change a passphrase slot.
type ChangePassphraseRequest struct {
	// Device is the block device path.
	Device string `json:"device" yaml:"device"`
	// Slot is the 0-based keyslot index to update.
	Slot int32 `json:"slot" yaml:"slot"`
	// OldPassphrase is the current passphrase for the slot.
	OldPassphrase string `json:"old_passphrase" yaml:"old_passphrase"`
	// NewPassphrase is the replacement passphrase.
	NewPassphrase string `json:"new_passphrase" yaml:"new_passphrase"`
}

// ChangePassphraseResponse returns the outcome of a passphrase change.
type ChangePassphraseResponse struct {
	// Changed is true when the passphrase was changed.
	Changed bool `json:"changed" yaml:"changed"`
}
