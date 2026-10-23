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

// Package luks provides integration between go-luks2 and go-xkms for
// TPM-sealed LUKS encryption management. This package serves as the
// composition layer that combines pure LUKS2 operations from go-luks2
// with TPM sealing/unsealing from go-xkms.
package luks

import (
	"context"
	"fmt"
	"path/filepath"

	goluks "github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/drive"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// Manager provides high-level LUKS operations with TPM integration
type Manager struct {
	logger     *logging.Logger
	tpm        xkmssdk.TrustedPlatformModule
	keyBackend xkmssdk.TPMKeyBackend
	config     *Config
	volumes    map[string]*VolumeState
}

// Config contains manager configuration
type Config struct {
	// XKMSPath is the path to store sealed keys
	XKMSPath string

	// DefaultPCRSelection for TPM sealing
	DefaultPCRSelection []uint

	// DefaultPCRBanks for TPM sealing
	DefaultPCRBanks []string

	// Debug enables debug logging
	Debug bool
}

// VolumeState tracks the state of a LUKS volume
type VolumeState struct {
	// Config is the partition configuration
	Config *drive.PartitionConfig

	// DevicePath is the block device path
	DevicePath string

	// MappingName is the device mapper name
	MappingName string

	// IsUnlocked indicates if the volume is currently unlocked
	IsUnlocked bool

	// IsMounted indicates if the volume is currently mounted
	IsMounted bool

	// MountPoint is the current mount point
	MountPoint string

	// SealedKeyPath is the path to the TPM-sealed key
	SealedKeyPath string
}

// NewManager creates a new LUKS manager
func NewManager(
	logger *logging.Logger,
	tpm xkmssdk.TrustedPlatformModule,
	keyBackend xkmssdk.TPMKeyBackend,
	config *Config,
) (*Manager, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if logger == nil {
		logger = logging.DefaultLogger()
	}

	return &Manager{
		logger:     logger,
		tpm:        tpm,
		keyBackend: keyBackend,
		config:     config,
		volumes:    make(map[string]*VolumeState),
	}, nil
}

// DefaultConfig returns default manager configuration
func DefaultConfig() *Config {
	return &Config{
		XKMSPath:            "/var/lib/trusted-platform/luks",
		DefaultPCRSelection: []uint{0, 1, 2, 3, 7, 9},
		DefaultPCRBanks:     []string{"sha256"},
		Debug:               false,
	}
}

// FormatVolume formats a partition with LUKS encryption and optional filesystem
func (m *Manager) FormatVolume(ctx context.Context, part *drive.PartitionConfig, passphrase []byte) error {
	if part.Encryption == nil || !part.Encryption.Enabled {
		return &MessageError{Msg: fmt.Sprintf("encryption not enabled for partition %s", part.ID)}
	}

	devicePath := m.getDevicePath(part)
	m.logger.Infof("Formatting LUKS volume: %s", devicePath)

	// Build LUKS format options
	opts := m.buildFormatOptions(part, passphrase, devicePath)

	// Same keyslot policy as the handler: resolve before go-luks2 sees it, or
	// an empty KDF becomes argon2id on a FIPS-activated host.
	if err := applyFIPSFormatPolicy(&opts.KDFType, &opts.HashAlgo); err != nil {
		return &WrappedError{Msg: "LUKS keyslot policy rejected the format options", Err: err}
	}

	// Format the LUKS volume using go-luks2
	if err := goluks.Format(opts); err != nil {
		return &WrappedError{Msg: "failed to format LUKS volume", Err: err}
	}

	m.logger.Infof("LUKS volume formatted: %s", devicePath)

	// Add TPM-sealed key if configured
	if part.Encryption.TPMSealing != nil && part.Encryption.TPMSealing.Enabled {
		if err := m.AddTPMSealedKey(ctx, part, passphrase); err != nil {
			return &WrappedError{Msg: "failed to add TPM-sealed key", Err: err}
		}
	}

	// Add recovery key if configured
	if part.Encryption.RecoveryKey != nil && part.Encryption.RecoveryKey.Generate {
		if err := m.AddRecoveryKey(ctx, part, passphrase); err != nil {
			return &WrappedError{Msg: "failed to add recovery key", Err: err}
		}
	}

	return nil
}

// AddTPMSealedKey generates a random LUKS key and seals it to the TPM
func (m *Manager) AddTPMSealedKey(ctx context.Context, part *drive.PartitionConfig, existingPassphrase []byte) error {
	if m.tpm == nil {
		return &MessageError{Msg: "TPM not available"}
	}

	tpmConfig := part.Encryption.TPMSealing
	devicePath := m.getDevicePath(part)

	m.logger.Infof("Adding TPM-sealed key to %s (keyslot %d)", devicePath, tpmConfig.KeySlot)

	// Generate a random LUKS key
	luksKey, err := m.tpm.RandomBytes(32)
	if err != nil {
		return &WrappedError{Msg: "failed to generate random key", Err: err}
	}
	defer clearBytes(luksKey)

	// Build key attributes for TPM sealing
	keyName := tpmConfig.KeyName
	if keyName == "" {
		keyName = fmt.Sprintf("luks-%s", part.ID)
	}

	attrs := &xkmssdk.KeyAttributes{
		CN:             keyName,
		KeyType:        xkmssdk.KeyTypeHMAC,
		PlatformPolicy: tpmConfig.PCRPolicy,
		TPMAttributes:  &xkmssdk.TPMAttributes{},
	}

	// Set parent to SRK
	srkAttrs, err := m.tpm.SSRKAttributes()
	if err != nil {
		return &WrappedError{Msg: "failed to get SRK attributes", Err: err}
	}
	attrs.Parent = srkAttrs

	// Seal the key to TPM
	m.logger.Debugf("Sealing key to TPM (PCR policy: %v)", tpmConfig.PCRPolicy)
	sealOpts := &xkmssdk.SealOptions{
		KeyAttributes: attrs,
	}
	sealedData, err := m.tpm.Seal(ctx, luksKey, sealOpts)
	if err != nil {
		return &WrappedError{Msg: "failed to seal key to TPM", Err: err}
	}

	// Add the key to LUKS
	keyslot := tpmConfig.KeySlot
	addOpts := &goluks.AddKeyOptions{
		Keyslot: &keyslot,
	}

	if err := applyFIPSKeyslotPolicy(&addOpts.KDFType, &addOpts.Hash); err != nil {
		return &WrappedError{Msg: "LUKS keyslot policy rejected the add-key options", Err: err}
	}

	if err := goluks.AddKey(devicePath, existingPassphrase, luksKey, addOpts); err != nil {
		return &WrappedError{Msg: "failed to add key to LUKS", Err: err}
	}

	// Store key attributes and sealed data for later unsealing
	tpmConfig.KeyAttributes = attrs
	tpmConfig.SealedData = sealedData

	m.logger.Infof("TPM-sealed key added to keyslot %d", keyslot)
	return nil
}

// AddRecoveryKey generates and adds a recovery key to the volume
func (m *Manager) AddRecoveryKey(ctx context.Context, part *drive.PartitionConfig, existingPassphrase []byte) error {
	recoveryConfig := part.Encryption.RecoveryKey
	devicePath := m.getDevicePath(part)

	m.logger.Infof("Adding recovery key to %s", devicePath)

	// Map format
	var format goluks.RecoveryKeyFormat
	switch recoveryConfig.Format {
	case drive.RecoveryKeyFormatHex:
		format = goluks.RecoveryKeyFormatHex
	case drive.RecoveryKeyFormatBase64:
		format = goluks.RecoveryKeyFormatBase64
	default:
		format = goluks.RecoveryKeyFormatDashed
	}

	// Build options
	length := recoveryConfig.Length
	if length <= 0 {
		length = 32
	}

	keyslot := recoveryConfig.KeySlot
	opts := &goluks.RecoveryKeyOptions{
		Length:     length,
		Format:     format,
		Keyslot:    &keyslot,
		OutputPath: recoveryConfig.OutputPath,
	}

	// A recovery key is a keyslot too, so it gets the same policy. Only the KDF
	// is resolved — RecoveryKeyOptions has no hash field.
	var noHash string
	if err := applyFIPSKeyslotPolicy(&opts.KDFType, &noHash); err != nil {
		return &WrappedError{Msg: "LUKS keyslot policy rejected the recovery-key options", Err: err}
	}

	// Generate and add recovery key using go-luks2
	recoveryKey, err := goluks.AddRecoveryKey(devicePath, existingPassphrase, opts)
	if err != nil {
		return &WrappedError{Msg: "failed to add recovery key", Err: err}
	}
	defer recoveryKey.Clear()

	m.logger.Infof("Recovery key added to keyslot %d", keyslot)
	if recoveryConfig.OutputPath != "" {
		m.logger.Infof("Recovery key saved to: %s", recoveryConfig.OutputPath)
	}

	return nil
}

// UnlockWithTPM unlocks a LUKS volume using TPM-sealed key
func (m *Manager) UnlockWithTPM(ctx context.Context, part *drive.PartitionConfig) error {
	if m.tpm == nil {
		return &MessageError{Msg: "TPM not available"}
	}

	tpmConfig := part.Encryption.TPMSealing
	if tpmConfig == nil || !tpmConfig.Enabled {
		return &MessageError{Msg: fmt.Sprintf("TPM sealing not configured for partition %s", part.ID)}
	}

	devicePath := m.getDevicePath(part)
	mappingName := part.Encryption.MappingName

	m.logger.Infof("Unlocking %s with TPM-sealed key", devicePath)

	// Build key attributes for unsealing
	keyName := tpmConfig.KeyName
	if keyName == "" {
		keyName = fmt.Sprintf("luks-%s", part.ID)
	}

	// Check if we have sealed data
	if tpmConfig.SealedData == nil {
		return &MessageError{Msg: fmt.Sprintf("no sealed data available for partition %s", part.ID)}
	}

	attrs := &xkmssdk.KeyAttributes{
		CN:             keyName,
		KeyType:        xkmssdk.KeyTypeHMAC,
		PlatformPolicy: tpmConfig.PCRPolicy,
	}

	// Set parent to SRK
	srkAttrs, err := m.tpm.SSRKAttributes()
	if err != nil {
		return &WrappedError{Msg: "failed to get SRK attributes", Err: err}
	}
	srkAttrs.Password = nil
	if srkAttrs.TPMAttributes != nil {
		srkAttrs.TPMAttributes.HierarchyAuth = nil
	}
	attrs.Parent = srkAttrs

	// Unseal the key from TPM
	unsealOpts := &xkmssdk.UnsealOptions{
		KeyAttributes: attrs,
	}
	key, err := m.tpm.Unseal(ctx, tpmConfig.SealedData, unsealOpts)
	if err != nil {
		return &WrappedError{Msg: "failed to unseal key from TPM", Err: err}
	}
	defer clearBytes(key)

	// Unlock the LUKS volume using go-luks2
	if err := goluks.Unlock(devicePath, key, mappingName); err != nil {
		return &WrappedError{Msg: "failed to unlock LUKS volume", Err: err}
	}

	// Track volume state
	m.volumes[part.ID] = &VolumeState{
		Config:      part,
		DevicePath:  devicePath,
		MappingName: mappingName,
		IsUnlocked:  true,
	}

	m.logger.Infof("Volume %s unlocked as %s", devicePath, mappingName)
	return nil
}

// UnlockWithPassphrase unlocks a LUKS volume using a passphrase
func (m *Manager) UnlockWithPassphrase(ctx context.Context, part *drive.PartitionConfig, passphrase []byte) error {
	devicePath := m.getDevicePath(part)
	mappingName := part.Encryption.MappingName

	m.logger.Infof("Unlocking %s with passphrase", devicePath)

	// Unlock using go-luks2
	if err := goluks.Unlock(devicePath, passphrase, mappingName); err != nil {
		return &WrappedError{Msg: "failed to unlock LUKS volume", Err: err}
	}

	// Track volume state
	m.volumes[part.ID] = &VolumeState{
		Config:      part,
		DevicePath:  devicePath,
		MappingName: mappingName,
		IsUnlocked:  true,
	}

	m.logger.Infof("Volume %s unlocked as %s", devicePath, mappingName)
	return nil
}

// UnlockWithRecoveryKey unlocks a LUKS volume using a recovery key
func (m *Manager) UnlockWithRecoveryKey(ctx context.Context, part *drive.PartitionConfig, recoveryKey string) error {
	devicePath := m.getDevicePath(part)
	mappingName := part.Encryption.MappingName

	m.logger.Infof("Unlocking %s with recovery key", devicePath)

	// Parse the recovery key
	key, err := goluks.ParseRecoveryKey(recoveryKey)
	if err != nil {
		return &WrappedError{Msg: "failed to parse recovery key", Err: err}
	}
	defer key.Destroy()

	// Unlock using go-luks2. ParseRecoveryKey returns the key in an enclave's
	// locked memory; WithBytes lends it for the duration of the call and holds
	// a read lock across it, so the key is never copied onto the Go heap and a
	// concurrent Destroy cannot unmap the pages Unlock is reading.
	if err := key.WithBytes(func(recovery []byte) error {
		return goluks.Unlock(devicePath, recovery, mappingName)
	}); err != nil {
		return &WrappedError{Msg: "failed to unlock LUKS volume", Err: err}
	}

	// Track volume state
	m.volumes[part.ID] = &VolumeState{
		Config:      part,
		DevicePath:  devicePath,
		MappingName: mappingName,
		IsUnlocked:  true,
	}

	m.logger.Infof("Volume %s unlocked as %s", devicePath, mappingName)
	return nil
}

// Lock closes an unlocked LUKS volume
func (m *Manager) Lock(ctx context.Context, part *drive.PartitionConfig) error {
	mappingName := part.Encryption.MappingName

	m.logger.Infof("Locking volume: %s", mappingName)

	// Lock using go-luks2
	if err := goluks.Lock(mappingName); err != nil {
		return &WrappedError{Msg: "failed to lock LUKS volume", Err: err}
	}

	// Update volume state
	if state, ok := m.volumes[part.ID]; ok {
		state.IsUnlocked = false
	}

	m.logger.Infof("Volume %s locked", mappingName)
	return nil
}

// MakeFilesystem creates a filesystem on an unlocked LUKS volume
func (m *Manager) MakeFilesystem(ctx context.Context, part *drive.PartitionConfig) error {
	if part.Filesystem == nil {
		return &MessageError{Msg: fmt.Sprintf("no filesystem configured for partition %s", part.ID)}
	}

	mappingName := part.Encryption.MappingName
	fsType := string(part.Filesystem.Type)
	label := part.Filesystem.Label

	m.logger.Infof("Creating %s filesystem on %s (label: %s)", fsType, mappingName, label)

	// Create filesystem using go-luks2
	if err := goluks.MakeFilesystem(mappingName, fsType, label); err != nil {
		return &WrappedError{Msg: "failed to create filesystem", Err: err}
	}

	m.logger.Infof("Filesystem created on %s", mappingName)
	return nil
}

// Mount mounts an unlocked LUKS volume
func (m *Manager) Mount(ctx context.Context, part *drive.PartitionConfig) error {
	if part.Mount == nil {
		return &MessageError{Msg: fmt.Sprintf("no mount configuration for partition %s", part.ID)}
	}

	mappingName := part.Encryption.MappingName
	mountPoint := part.Mount.Mountpoint

	m.logger.Infof("Mounting %s at %s", mappingName, mountPoint)

	// Build mount options
	opts := goluks.MountOptions{
		Device:     mappingName,
		MountPoint: mountPoint,
	}

	if part.Filesystem != nil {
		opts.FSType = string(part.Filesystem.Type)
	}

	// Mount using go-luks2
	if err := goluks.Mount(opts); err != nil {
		return &WrappedError{Msg: "failed to mount", Err: err}
	}

	// Update volume state
	if state, ok := m.volumes[part.ID]; ok {
		state.IsMounted = true
		state.MountPoint = mountPoint
	}

	m.logger.Infof("Volume mounted at %s", mountPoint)
	return nil
}

// Unmount unmounts a LUKS volume
func (m *Manager) Unmount(ctx context.Context, part *drive.PartitionConfig) error {
	if part.Mount == nil {
		return &MessageError{Msg: fmt.Sprintf("no mount configuration for partition %s", part.ID)}
	}

	mountPoint := part.Mount.Mountpoint

	m.logger.Infof("Unmounting %s", mountPoint)

	// Unmount using go-luks2
	if err := goluks.Unmount(mountPoint, 0); err != nil {
		return &WrappedError{Msg: "failed to unmount", Err: err}
	}

	// Update volume state
	if state, ok := m.volumes[part.ID]; ok {
		state.IsMounted = false
		state.MountPoint = ""
	}

	m.logger.Infof("Volume unmounted from %s", mountPoint)
	return nil
}

// GetVolumeInfo returns information about a LUKS volume
func (m *Manager) GetVolumeInfo(part *drive.PartitionConfig) (*goluks.VolumeInfo, error) {
	devicePath := m.getDevicePath(part)
	return goluks.GetVolumeInfo(devicePath)
}

// ListKeyslots returns keyslot information for a volume
func (m *Manager) ListKeyslots(part *drive.PartitionConfig) ([]goluks.KeyslotInfo, error) {
	devicePath := m.getDevicePath(part)
	return goluks.ListKeyslots(devicePath)
}

// IsUnlocked checks if a volume is currently unlocked
func (m *Manager) IsUnlocked(part *drive.PartitionConfig) bool {
	return goluks.IsUnlocked(part.Encryption.MappingName)
}

// getDevicePath constructs the device path for a partition
func (m *Manager) getDevicePath(part *drive.PartitionConfig) string {
	// This would typically be set by the drive manager based on the parent drive
	// For now, assume it's stored in the partition config or use a placeholder
	// In practice, this would be something like /dev/sda2 or /dev/nvme0n1p2
	return fmt.Sprintf("/dev/disk/by-partlabel/%s", part.Label)
}

// buildFormatOptions creates LUKS format options from partition config
func (m *Manager) buildFormatOptions(part *drive.PartitionConfig, passphrase []byte, devicePath string) goluks.FormatOptions {
	opts := goluks.FormatOptions{
		Device:     devicePath,
		Passphrase: passphrase,
		Label:      part.Label,
	}

	if part.Encryption != nil && part.Encryption.LUKS != nil {
		luks := part.Encryption.LUKS
		if luks.Cipher != "" {
			// Parse cipher string like "aes-xts-plain64" -> cipher="aes", mode="xts-plain64"
			opts.Cipher = "aes"
			opts.CipherMode = "xts-plain64"
		}
		if luks.KeySize > 0 {
			opts.KeySize = luks.KeySize
		}
		if luks.Hash != "" {
			opts.HashAlgo = luks.Hash
		}
		if luks.PBKDF != "" {
			opts.KDFType = luks.PBKDF
		}
		if luks.Argon2Memory > 0 {
			opts.Argon2Memory = luks.Argon2Memory
		}
		if luks.Argon2Time > 0 {
			opts.Argon2Time = luks.Argon2Time
		}
		if luks.Argon2Parallel > 0 {
			opts.Argon2Parallel = luks.Argon2Parallel
		}
	}

	return opts
}

// getSealedKeyPath returns the path for storing a sealed key
func (m *Manager) getSealedKeyPath(partID string) string {
	return filepath.Join(m.config.XKMSPath, partID)
}

// clearBytes securely zeros a byte slice
func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
