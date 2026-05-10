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
	"os"
	"path/filepath"
	"syscall"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

const (
	// EFI partition mount point during boot
	efiMountPoint = "/boot/efi"

	// TPM upgrade seal file paths on EFI partition (relative to EFI mount)
	// These are non-PCR sealed objects created by firstboot for upgrade scenarios
	// Note: Presence of these files indicates re-seal is needed (no separate flag)
	upgradePublicFile  = "tpm2/seal-upgrade.pub"
	upgradePrivateFile = "tpm2/seal-upgrade.priv"
)

// TPMUpgradeStrategy unlocks using TPM without PCR policy for kernel upgrades
// This strategy uses non-PCR sealed objects stored temporarily on the EFI partition.
// After successful unlock, the upgrade seal files are KEPT for re-sealing.
// The presence of upgrade seals signals that re-seal is needed.
// After successful re-seal and PCR-unlock verification, upgrade seals are deleted.
//
// Workflow:
//  1. Check for upgrade seal files on EFI partition
//  2. If found, load and unseal WITHOUT PCR policy verification
//  3. Unlock LUKS volume with unsealed key
//  4. KEEP upgrade seal files (needed for re-seal process)
//  5. Firstboot detects upgrade seals, re-seals with current PCRs
//  6. After TPM-PCR unlock succeeds, upgrade seals are deleted
//
// Priority: 2 (between TPM-PCR [1] and FIDO2 [3])
type TPMUpgradeStrategy struct {
	platform *Platform
	logger   *logging.Logger
	priority int
}

// NewTPMUpgradeStrategy creates a new TPM upgrade unlock strategy
func NewTPMUpgradeStrategy(platform *Platform, logger *logging.Logger) *TPMUpgradeStrategy {
	return &TPMUpgradeStrategy{
		platform: platform,
		logger:   logger,
		priority: 2, // Second priority - between TPM-PCR (1) and FIDO2 (3)
	}
}

// Name returns the strategy name
func (s *TPMUpgradeStrategy) Name() string {
	return "TPM-Upgrade"
}

// Priority returns the execution priority
func (s *TPMUpgradeStrategy) Priority() int {
	return s.priority
}

// CanUnlock checks if this strategy can unlock the volume
// It checks for the presence of upgrade seal files on the EFI partition
func (s *TPMUpgradeStrategy) CanUnlock(ctx context.Context, volume *luks.VolumeConfig) bool {
	// Check if TPM is available
	if s.platform.TPM == nil {
		s.logger.Debug("TPM-Upgrade: TPM not available")
		return false
	}

	// Check if upgrade seal files exist on EFI partition
	efiPath := s.getEFIPath()
	publicPath := filepath.Join(efiPath, upgradePublicFile)
	privatePath := filepath.Join(efiPath, upgradePrivateFile)

	// Need to mount EFI to check - do a quick stat check
	// If EFI is not mounted, try to mount it temporarily
	mounted, err := s.ensureEFIMounted()
	if err != nil {
		s.logger.Debugf("TPM-Upgrade: Cannot check EFI partition: %v", err)
		return false
	}
	defer func() {
		if !mounted {
			// Only unmount if we mounted it
			s.unmountEFI()
		}
	}()

	_, err1 := os.Stat(publicPath)
	_, err2 := os.Stat(privatePath)

	if err1 == nil && err2 == nil {
		s.logger.Info("TPM-Upgrade: Found upgrade seal files (no PCR policy) on EFI partition")
		s.logger.Info("TPM-Upgrade: Attempting automated kernel upgrade boot")
		return true
	}

	s.logger.Debug("TPM-Upgrade: No upgrade seal files found")
	return false
}

// Unlock attempts to unlock the volume using TPM upgrade seal without PCR policy
// This follows the Alpine dracut-module-tpm2 workflow:
//  1. Mount EFI partition
//  2. Load upgrade seal object from EFI
//  3. Unseal WITHOUT PCR verification
//  4. Unlock LUKS volume
//  5. Delete upgrade seal files immediately
func (s *TPMUpgradeStrategy) Unlock(ctx context.Context, volume *luks.VolumeConfig) error {
	s.logger.Infof("Attempting TPM-Upgrade unlock for %s (no PCR verification)", volume.DevicePath)
	s.logger.Info("This system will boot with the new kernel and re-seal with new PCRs")

	// Ensure EFI partition is mounted READ-WRITE
	// We need write access to delete upgrade seals and write reseal flag after unlock
	wasMounted, err := s.ensureEFIMountedRW()
	if err != nil {
		return fmt.Errorf("failed to mount EFI partition: %w", err)
	}
	defer func() {
		if !wasMounted {
			s.unmountEFI()
		}
	}()

	efiPath := s.getEFIPath()
	publicPath := filepath.Join(efiPath, upgradePublicFile)
	privatePath := filepath.Join(efiPath, upgradePrivateFile)

	// Verify upgrade seal files exist
	if _, err := os.Stat(publicPath); err != nil {
		return fmt.Errorf("upgrade public seal file not found: %w", err)
	}
	if _, err := os.Stat(privatePath); err != nil {
		return fmt.Errorf("upgrade private seal file not found: %w", err)
	}

	s.logger.Info("Loading upgrade seal object from EFI partition...")

	// Upgrade seals use SSRK which has NO PCR policy
	// This is required because Platform KeyStore SRK has PCR auth policy
	// which would prevent unseal after kernel upgrades when PCRs change
	ssrkHandle := s.getSSRKHandle()

	s.logger.Infof("Using SSRK for upgrade unseal (no PCR policy), handle=0x%08x", ssrkHandle)

	// Get SSRK attributes as parent
	srkAttrs, err := s.platform.TPM.KeyAttributes(ssrkHandle)
	if err != nil {
		return fmt.Errorf("failed to get SSRK attributes: %w", err)
	}

	// SSRK has NO platform policy - this allows unseal without PCR verification
	srkAttrs.PlatformPolicy = false

	// Create key attributes for upgrade seal
	// Both parent SRK and sealed object have NO PCR policy
	upgradeAttrs := &xkmssdk.KeyAttributes{
		CN:             "luks-upgrade-seal",
		KeyType:        xkmssdk.KeyTypeHMAC,
		PlatformPolicy: false, // No PCR policy
		Parent:         srkAttrs,
		StoreType:      xkmssdk.StoreSoftware,
	}

	// Load sealed data from EFI partition files
	pubBlob, err := os.ReadFile(publicPath)
	if err != nil {
		return fmt.Errorf("failed to read upgrade seal public: %w", err)
	}
	privBlob, err := os.ReadFile(privatePath)
	if err != nil {
		return fmt.Errorf("failed to read upgrade seal private: %w", err)
	}

	sealedData := &xkmssdk.SealedData{
		Backend:    xkmssdk.BackendTypeTPM2, // Required for proper unsealing
		TPMPublic:  pubBlob,
		TPMPrivate: privBlob,
	}

	// Get the backend for retrieving sealed data
	var backend interface{}
	if s.platform.XKMS != nil {
		backend = s.platform.XKMS.Backend()
	} else if s.platform.Backend != nil {
		backend = s.platform.Backend
	}

	// Unseal the key using TPM (no PCR verification)
	s.logger.Info("Unsealing LUKS key using upgrade seal (no PCR verification)...")
	unsealOpts := &xkmssdk.UnsealOptions{
		KeyAttributes: upgradeAttrs,
		Backend:       backend,
	}
	key, err := s.platform.TPM.Unseal(ctx, sealedData, unsealOpts)
	if err != nil {
		s.logger.Errorf("Failed to unseal upgrade seal - error: %v", err)
		s.logger.Info("Falling back to next unlock strategy...")
		return fmt.Errorf("failed to unseal upgrade key: %w", err)
	}

	s.logger.Info("Successfully unsealed LUKS key using upgrade seal from EFI")

	// Attempt LUKS unlock
	openOpts := &luks.OpenOptions{
		AllowDiscards: volume.AllowDiscards,
		Timeout:       volume.Timeout,
	}

	err = s.platform.LUKS.Open(ctx, volume.DevicePath, volume.MappingName, key, openOpts)
	if err != nil {
		return fmt.Errorf("LUKS unlock failed with upgrade seal: %w", err)
	}

	s.logger.Infof("Successfully unlocked %s with TPM upgrade seal", volume.DevicePath)

	// IMPORTANT: Do NOT delete upgrade seal files here!
	// The re-seal process needs them to read the LUKS key for re-sealing with new PCR values.
	//
	// Flow:
	// 1. TPM-Upgrade unlocks disk using upgrade seals (no PCR policy)
	// 2. TPM-Upgrade sets .reseal-needed flag (keeps upgrade seals intact)
	// 3. System boots with new kernel
	// 4. On next boot, firstboot strategy detects .reseal-needed flag
	// 5. firstboot reads key from upgrade seals, re-seals with current PCR values
	// 6. firstboot THEN deletes upgrade seals
	//
	// This ensures the LUKS key is available for re-sealing.
	// The upgrade seals are only deleted AFTER successful re-seal with PCR policy.
	// Upgrade seals are kept for re-seal process
	// The presence of seal-upgrade.pub/priv indicates re-seal is needed
	// No separate flag file required - upgrade seals themselves are the signal
	s.logger.Info("SECURITY: Upgrade seals kept for re-seal process")
	s.logger.Info("Presence of upgrade seals will trigger re-seal on next firstboot run")

	// Sync to ensure deletion and re-seal flag are persisted
	syscall.Sync()

	return nil
}

// Install performs installation-time setup for TPM-Upgrade strategy
// This creates the initial directory structure on the EFI partition
// but doesn't create upgrade seals (those are created on-demand before kernel upgrades)
func (s *TPMUpgradeStrategy) Install(ctx context.Context, volume *luks.VolumeConfig, password []byte) error {
	s.logger.Infof("Installing TPM-Upgrade strategy for %s", volume.DevicePath)

	// Ensure EFI partition is mounted
	wasMounted, err := s.ensureEFIMounted()
	if err != nil {
		return fmt.Errorf("failed to mount EFI partition: %w", err)
	}
	defer func() {
		if !wasMounted {
			s.unmountEFI()
		}
	}()

	// Create tpm2 directory on EFI partition if it doesn't exist
	efiPath := s.getEFIPath()
	tpm2Dir := filepath.Join(efiPath, "tpm2")
	if err := os.MkdirAll(tpm2Dir, 0700); err != nil {
		return fmt.Errorf("failed to create tpm2 directory: %w", err)
	}

	s.logger.Info("Created tpm2 directory on EFI partition")
	s.logger.Info("TPM-Upgrade strategy ready - upgrade seals can be created before kernel updates")
	s.logger.Info("Use CreateUpgradeSeal() before kernel upgrade to enable one-time boot")
	return nil
}

// CreateUpgradeSeal creates non-PCR sealed objects for kernel upgrades
// This should be called before a kernel upgrade to allow the next boot to succeed
// The upgrade seal allows one-time boot with the new kernel before PCRs are updated
//
// Parameters:
//
//	key: The LUKS key to seal (typically retrieved from a PCR-sealed slot)
//
// This function:
//  1. Creates key attributes WITHOUT PCR policy
//  2. Seals the key to TPM (bound to SRK but no PCRs)
//  3. Stores sealed blobs on EFI partition as seal-upgrade.pub/priv
//  4. These files will be deleted after first successful boot
func (s *TPMUpgradeStrategy) CreateUpgradeSeal(key []byte) error {
	s.logger.Info("Creating upgrade seal for kernel upgrade")

	if len(key) == 0 {
		return fmt.Errorf("key cannot be empty")
	}

	// Ensure EFI partition is mounted (read-write for seal creation)
	wasMounted, err := s.ensureEFIMountedRW()
	if err != nil {
		return fmt.Errorf("failed to mount EFI partition: %w", err)
	}
	defer func() {
		if !wasMounted {
			s.unmountEFI()
		}
	}()

	// Upgrade seals use SSRK which has NO PCR policy
	// This is required because Platform KeyStore SRK has PCR auth policy
	// which would prevent unseal after kernel upgrades when PCRs change
	ssrkHandle := s.getSSRKHandle()

	s.logger.Infof("Using SSRK for upgrade seal (no PCR policy), handle=0x%08x", ssrkHandle)

	// Get SSRK attributes as parent
	srkAttrs, err := s.platform.TPM.KeyAttributes(ssrkHandle)
	if err != nil {
		return fmt.Errorf("failed to get SSRK attributes: %w", err)
	}

	// SSRK has NO platform policy - this allows unseal without PCR verification
	srkAttrs.PlatformPolicy = false

	// Create key attributes for upgrade seal without PCR policy
	upgradeAttrs := &xkmssdk.KeyAttributes{
		CN:             "luks-upgrade-seal",
		KeyType:        xkmssdk.KeyTypeHMAC,
		PlatformPolicy: false, // No PCR policy
		Parent:         srkAttrs,
		StoreType:      xkmssdk.StoreSoftware,
	}

	// Get the backend for storing sealed data
	var backend interface{}
	if s.platform.XKMS != nil {
		backend = s.platform.XKMS.Backend()
	} else if s.platform.Backend != nil {
		backend = s.platform.Backend
	}

	// Seal the key to TPM without PCR policy
	s.logger.Info("Sealing upgrade key to TPM (no PCR binding)...")
	sealOpts := &xkmssdk.SealOptions{
		KeyAttributes: upgradeAttrs,
		Backend:       backend,
	}
	sealedData, err := s.platform.TPM.Seal(context.Background(), key, sealOpts)
	if err != nil {
		return fmt.Errorf("failed to seal upgrade key: %w", err)
	}

	// Write sealed data to EFI partition
	publicPath := filepath.Join(s.getEFIPath(), upgradePublicFile)
	privatePath := filepath.Join(s.getEFIPath(), upgradePrivateFile)

	if err := os.WriteFile(publicPath, sealedData.TPMPublic, 0600); err != nil {
		return fmt.Errorf("failed to write upgrade seal public: %w", err)
	}
	if err := os.WriteFile(privatePath, sealedData.TPMPrivate, 0600); err != nil {
		return fmt.Errorf("failed to write upgrade seal private: %w", err)
	}

	s.logger.Info("✓ Upgrade seal created successfully on EFI partition")
	s.logger.Info("System will boot once with new kernel, then re-seal with new PCRs")

	return nil
}

// getEFIPath returns the EFI partition path
// This can be overridden in tests
func (s *TPMUpgradeStrategy) getEFIPath() string {
	return efiMountPoint
}

// ensureEFIMounted checks if EFI is mounted and mounts it if needed (read-only)
// Returns true if it was already mounted, false if we mounted it
func (s *TPMUpgradeStrategy) ensureEFIMounted() (bool, error) {
	return s.mountEFI(syscall.MS_RDONLY)
}

// ensureEFIMountedRW checks if EFI is mounted and mounts it if needed (read-write)
// Returns true if it was already mounted, false if we mounted it
func (s *TPMUpgradeStrategy) ensureEFIMountedRW() (bool, error) {
	return s.mountEFI(0)
}

// mountEFI mounts the EFI partition with the specified flags
func (s *TPMUpgradeStrategy) mountEFI(flags uintptr) (bool, error) {
	// Check if already mounted by looking for EFI directory
	efiDir := filepath.Join(efiMountPoint, "EFI")
	if stat, err := os.Stat(efiDir); err == nil && stat.IsDir() {
		s.logger.Debug("EFI partition already mounted")
		return true, nil
	}

	// Auto-detect EFI partition device if not configured or if configured as mount point
	bootDevice := s.platform.Config.BootDevice
	if bootDevice == "" || bootDevice == "/boot/efi" {
		s.logger.Debug("Auto-detecting EFI partition device...")
		detected, err := s.detectEFIDevice()
		if err != nil {
			return false, fmt.Errorf("failed to detect EFI partition: %w", err)
		}
		bootDevice = detected
		s.logger.Debugf("Detected EFI partition: %s", bootDevice)
	}

	// Create mount point if it doesn't exist
	if err := os.MkdirAll(efiMountPoint, 0755); err != nil {
		return false, fmt.Errorf("failed to create mount point: %w", err)
	}

	// Mount the EFI partition
	err := syscall.Mount(
		bootDevice,
		efiMountPoint,
		"vfat",
		flags,
		"",
	)
	if err != nil {
		return false, fmt.Errorf("failed to mount EFI partition %s: %w", bootDevice, err)
	}

	if flags&syscall.MS_RDONLY != 0 {
		s.logger.Debugf("Mounted EFI partition %s at %s (read-only)", bootDevice, efiMountPoint)
	} else {
		s.logger.Debugf("Mounted EFI partition %s at %s (read-write)", bootDevice, efiMountPoint)
	}
	return false, nil
}

// detectEFIDevice attempts to auto-detect the EFI partition device
// It looks for FAT-formatted partitions in common locations
func (s *TPMUpgradeStrategy) detectEFIDevice() (string, error) {
	// Common EFI partition locations (typically first partition)
	candidates := []string{
		"/dev/vda1",      // VirtIO disk (QEMU/KVM)
		"/dev/sda1",      // SCSI/SATA disk
		"/dev/nvme0n1p1", // NVMe disk
	}

	for _, device := range candidates {
		// Check if device exists
		if _, err := os.Stat(device); err != nil {
			continue
		}

		// Check if it's a block device
		stat, err := os.Stat(device)
		if err != nil || stat.Mode()&os.ModeDevice == 0 {
			continue
		}

		// Try to determine if it's a FAT filesystem
		// We can't use blkid in initramfs, so we'll just try to mount it
		s.logger.Debugf("Trying EFI partition candidate: %s", device)
		return device, nil
	}

	return "", fmt.Errorf("no EFI partition found in candidates: %v", candidates)
}

// unmountEFI unmounts the EFI partition
func (s *TPMUpgradeStrategy) unmountEFI() {
	if err := syscall.Unmount(efiMountPoint, 0); err != nil {
		s.logger.Debugf("Failed to unmount EFI partition: %v", err)
	} else {
		s.logger.Debug("Unmounted EFI partition")
	}
}

// getSSRKHandle returns the Shared SRK handle from TPM config.
// The SSRK (default 0x81000001) has NO platform policy and is used for
// temporary upgrade seals that need to survive kernel/PCR changes.
func (s *TPMUpgradeStrategy) getSSRKHandle() xkmssdk.TPMHandle {
	if s.platform.TPM != nil {
		config := s.platform.TPM.Config()
		if config != nil && config.SSRK != nil && config.SSRK.Handle != 0 {
			return xkmssdk.TPMHandle(config.SSRK.Handle)
		}
	}
	// Default SSRK handle
	return xkmssdk.TPMHandle(0x81000001)
}
