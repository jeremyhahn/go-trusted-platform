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

package initrd

import (
	"context"
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/drive"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// MultiDriveManager handles unlocking multiple encrypted drives
type MultiDriveManager struct {
	logger        *logging.Logger
	tpm           xkmssdk.TrustedPlatformModule
	keyBackend    xkmssdk.TPMKeyBackend
	luksHandler   luks.Handler
	storageConfig *drive.StorageConfig
	luksManager   *luks.Manager
	chain         *StrategyChain
	platform      *Platform
}

// MultiDriveConfig contains configuration for multi-drive operations
type MultiDriveConfig struct {
	// StorageConfig is the multi-drive storage configuration
	StorageConfig *drive.StorageConfig

	// XKMSPath is the path to store sealed keys
	XKMSPath string

	// DefaultPCRSelection for TPM sealing
	DefaultPCRSelection []uint

	// DefaultPCRBanks for TPM sealing
	DefaultPCRBanks []string
}

// NewMultiDriveManager creates a new multi-drive manager
func NewMultiDriveManager(
	platform *Platform,
	storageConfig *drive.StorageConfig,
	logger *logging.Logger,
) (*MultiDriveManager, error) {
	if platform == nil {
		return nil, fmt.Errorf("platform is required")
	}
	if storageConfig == nil {
		return nil, fmt.Errorf("storage config is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	// Validate storage config
	if err := storageConfig.Validate(); err != nil {
		return nil, fmt.Errorf("invalid storage config: %w", err)
	}

	// Create LUKS manager for TPM integration
	luksManagerConfig := &luks.Config{
		XKMSPath:            platform.Config.XKMSPath,
		DefaultPCRSelection: platform.Config.PCRSelection,
		DefaultPCRBanks:     platform.Config.PCRBanks,
	}

	luksManager, err := luks.NewManager(
		logger,
		platform.TPM,
		platform.Backend,
		luksManagerConfig,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create LUKS manager: %w", err)
	}

	mgr := &MultiDriveManager{
		logger:        logger,
		tpm:           platform.TPM,
		keyBackend:    platform.Backend,
		luksHandler:   platform.LUKS,
		storageConfig: storageConfig,
		luksManager:   luksManager,
		chain:         NewStrategyChain(logger),
		platform:      platform,
	}

	return mgr, nil
}

// UnlockAllVolumes unlocks all encrypted volumes in the storage configuration
func (m *MultiDriveManager) UnlockAllVolumes(ctx context.Context) error {
	m.logger.Info("Unlocking all encrypted volumes")

	// Get all encrypted partitions
	encryptedPartitions := m.storageConfig.GetEncryptedPartitions()
	if len(encryptedPartitions) == 0 {
		m.logger.Info("No encrypted partitions configured")
		return nil
	}

	m.logger.Infof("Found %d encrypted partitions", len(encryptedPartitions))

	// Unlock root partition first if present
	rootPartition := m.storageConfig.GetRootPartition()
	if rootPartition != nil && rootPartition.Encryption != nil && rootPartition.Encryption.Enabled {
		m.logger.Info("Unlocking root partition first", "id", rootPartition.ID)
		if err := m.unlockPartition(ctx, rootPartition); err != nil {
			return fmt.Errorf("failed to unlock root partition: %w", err)
		}
	}

	// Unlock remaining partitions
	for _, part := range encryptedPartitions {
		// Skip root partition (already unlocked)
		if rootPartition != nil && part.ID == rootPartition.ID {
			continue
		}

		m.logger.Infof("Unlocking partition: %s", part.ID)
		if err := m.unlockPartition(ctx, part); err != nil {
			m.logger.Errorf("Failed to unlock partition %s: %v", part.ID, err)
			// Continue with other partitions - don't fail entire boot for data partitions
			if !m.isRootPartition(part) {
				continue
			}
			return err
		}
	}

	m.logger.Info("All encrypted volumes unlocked successfully")
	return nil
}

// unlockPartition attempts to unlock a single encrypted partition
func (m *MultiDriveManager) unlockPartition(ctx context.Context, part *drive.PartitionConfig) error {
	m.logger.Infof("Attempting to unlock partition %s", part.ID)

	// Try TPM-sealed key first if configured
	if part.Encryption.TPMSealing != nil && part.Encryption.TPMSealing.Enabled {
		m.logger.Info("Trying TPM-sealed key unlock", "partition", part.ID)
		if err := m.luksManager.UnlockWithTPM(ctx, part); err == nil {
			m.logger.Infof("Successfully unlocked %s with TPM-sealed key", part.ID)
			return nil
		} else {
			m.logger.Warnf("TPM unlock failed for %s: %v", part.ID, err)
		}
	}

	// Convert to luks.VolumeConfig for strategy chain
	volume := m.partitionToVolumeConfig(part)

	// Fall back to strategy chain
	return m.chain.Execute(ctx, volume)
}

// partitionToVolumeConfig converts drive.PartitionConfig to luks.VolumeConfig
func (m *MultiDriveManager) partitionToVolumeConfig(part *drive.PartitionConfig) *luks.VolumeConfig {
	volume := &luks.VolumeConfig{
		DevicePath:    m.getDevicePath(part),
		MappingName:   part.Encryption.MappingName,
		LUKSVersion:   luks.LUKS2,
		AllowDiscards: true,
		KeySlots:      make([]luks.KeySlot, 0),
	}

	if part.Encryption.LUKS != nil {
		volume.Cipher = part.Encryption.LUKS.Cipher
		volume.KeySize = part.Encryption.LUKS.KeySize
		volume.HashAlgorithm = part.Encryption.LUKS.Hash
		volume.PBKDFType = part.Encryption.LUKS.PBKDF
	}

	return volume
}

// getDevicePath constructs the device path for a partition
func (m *MultiDriveManager) getDevicePath(part *drive.PartitionConfig) string {
	// Use by-partlabel if label is available
	if part.Label != "" {
		return fmt.Sprintf("/dev/disk/by-partlabel/%s", part.Label)
	}
	// Fall back to device path construction from parent drive
	// This would typically be set by the drive manager
	return fmt.Sprintf("/dev/disk/by-partlabel/%s", part.ID)
}

// isRootPartition checks if the partition is the root partition
func (m *MultiDriveManager) isRootPartition(part *drive.PartitionConfig) bool {
	if part.Mount == nil {
		return false
	}
	return part.Mount.Mountpoint == "/"
}

// InstallAllVolumes performs initial setup for all encrypted volumes
func (m *MultiDriveManager) InstallAllVolumes(ctx context.Context, passphrase []byte) error {
	m.logger.Info("Installing all encrypted volumes")

	encryptedPartitions := m.storageConfig.GetEncryptedPartitions()
	if len(encryptedPartitions) == 0 {
		m.logger.Info("No encrypted partitions to install")
		return nil
	}

	for _, part := range encryptedPartitions {
		m.logger.Infof("Installing partition: %s", part.ID)
		if err := m.installPartition(ctx, part, passphrase); err != nil {
			return fmt.Errorf("failed to install partition %s: %w", part.ID, err)
		}
	}

	m.logger.Info("All encrypted volumes installed successfully")
	return nil
}

// installPartition performs initial setup for a single encrypted partition
func (m *MultiDriveManager) installPartition(ctx context.Context, part *drive.PartitionConfig, passphrase []byte) error {
	m.logger.Infof("Formatting LUKS volume for partition %s", part.ID)

	// Format the volume with LUKS
	if err := m.luksManager.FormatVolume(ctx, part, passphrase); err != nil {
		return fmt.Errorf("failed to format LUKS volume: %w", err)
	}

	// Create filesystem if configured
	if part.Filesystem != nil {
		// First unlock the volume
		if err := m.luksManager.UnlockWithPassphrase(ctx, part, passphrase); err != nil {
			return fmt.Errorf("failed to unlock for filesystem creation: %w", err)
		}
		defer m.luksManager.Lock(ctx, part) //nolint:errcheck

		// Create filesystem
		if err := m.luksManager.MakeFilesystem(ctx, part); err != nil {
			return fmt.Errorf("failed to create filesystem: %w", err)
		}
	}

	return nil
}

// MountAllVolumes mounts all unlocked encrypted volumes
func (m *MultiDriveManager) MountAllVolumes(ctx context.Context) error {
	m.logger.Info("Mounting all encrypted volumes")

	// Get mount order from storage config
	mountOrder := m.getMountOrder()

	for _, part := range mountOrder {
		if part.Mount == nil {
			continue
		}

		// Only mount if partition is encrypted and has a mount config
		if part.Encryption != nil && part.Encryption.Enabled {
			if !m.luksManager.IsUnlocked(part) {
				m.logger.Warnf("Skipping mount of %s - volume not unlocked", part.ID)
				continue
			}

			m.logger.Infof("Mounting partition %s at %s", part.ID, part.Mount.Mountpoint)
			if err := m.luksManager.Mount(ctx, part); err != nil {
				return fmt.Errorf("failed to mount %s: %w", part.ID, err)
			}
		}
	}

	m.logger.Info("All volumes mounted successfully")
	return nil
}

// UnmountAllVolumes unmounts all mounted encrypted volumes
func (m *MultiDriveManager) UnmountAllVolumes(ctx context.Context) error {
	m.logger.Info("Unmounting all encrypted volumes")

	// Get mount order and reverse it for unmount
	mountOrder := m.getMountOrder()
	for i := len(mountOrder) - 1; i >= 0; i-- {
		part := mountOrder[i]
		if part.Mount == nil || part.Encryption == nil || !part.Encryption.Enabled {
			continue
		}

		m.logger.Infof("Unmounting partition %s from %s", part.ID, part.Mount.Mountpoint)
		if err := m.luksManager.Unmount(ctx, part); err != nil {
			m.logger.Warnf("Failed to unmount %s: %v", part.ID, err)
		}
	}

	return nil
}

// LockAllVolumes locks all unlocked encrypted volumes
func (m *MultiDriveManager) LockAllVolumes(ctx context.Context) error {
	m.logger.Info("Locking all encrypted volumes")

	encryptedPartitions := m.storageConfig.GetEncryptedPartitions()
	for _, part := range encryptedPartitions {
		if m.luksManager.IsUnlocked(part) {
			m.logger.Infof("Locking partition %s", part.ID)
			if err := m.luksManager.Lock(ctx, part); err != nil {
				m.logger.Warnf("Failed to lock %s: %v", part.ID, err)
			}
		}
	}

	return nil
}

// getMountOrder returns partitions in mount order (sorted by mountpoint depth)
func (m *MultiDriveManager) getMountOrder() []*drive.PartitionConfig {
	var result []*drive.PartitionConfig

	// Collect all partitions with mount configs
	for i := range m.storageConfig.Drives {
		drv := &m.storageConfig.Drives[i]
		for j := range drv.Partitions {
			part := &drv.Partitions[j]
			if part.Mount != nil {
				result = append(result, part)
			}
		}
	}

	// Sort by mountpoint depth (fewer slashes = shallower = mount first)
	// Using a simple bubble sort for small arrays
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			depthI := countSlashes(result[i].Mount.Mountpoint)
			depthJ := countSlashes(result[j].Mount.Mountpoint)
			if depthJ < depthI {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	return result
}

// countSlashes counts the number of slashes in a path
func countSlashes(path string) int {
	count := 0
	for _, c := range path {
		if c == '/' {
			count++
		}
	}
	return count
}

// RegisterStrategy registers an unlock strategy for fallback.
// Nil strategies are ignored to support conditional compilation (minimal builds).
func (m *MultiDriveManager) RegisterStrategy(strategy UnlockStrategy) {
	if strategy == nil {
		return
	}
	m.chain.Add(strategy)
}

// GetStorageConfig returns the storage configuration
func (m *MultiDriveManager) GetStorageConfig() *drive.StorageConfig {
	return m.storageConfig
}

// GetLUKSManager returns the LUKS manager for direct access
func (m *MultiDriveManager) GetLUKSManager() *luks.Manager {
	return m.luksManager
}
