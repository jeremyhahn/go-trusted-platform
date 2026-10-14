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

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/fips"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/partition"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

const (
	// EFI partition mount point during boot
	pcrEfiMountPoint = "/boot/efi"

	// Platform KeyStore seal file paths on EFI partition (relative to EFI mount)
	// These are sealed under Platform KeyStore SRK with platform policy
	pcrPublicFile  = "tpm2/seal-platform.pub"
	pcrPrivateFile = "tpm2/seal-platform.priv"
	pcrBanksFile   = "tpm2/pcr-banks"

	// Upgrade seal file paths (TEMPORARY - for kernel upgrades only)
	// Sealed under SSRK for one-time recovery boot during system upgrades
	// Note: Presence of these files indicates re-seal is needed (no separate flag)
	pcrUpgradePublicFile  = "tpm2/seal-upgrade.pub"
	pcrUpgradePrivateFile = "tpm2/seal-upgrade.priv"
)

// TPMPCRStrategy unlocks using TPM with Platform KeyStore SRK.
// This strategy reads sealed objects from the EFI partition and attempts
// to unseal using the Platform KeyStore SRK configured in the TPM config.
//
// All handle values and PCR settings come from the configuration file.
// No hardcoded handles or PCR indices.
//
// SECURITY: Platform KeyStore SRK has:
//   - Platform PCR auth policy (requires golden measurement extension)
//   - Password protection
//
// Workflow:
//  1. Check for seal files on EFI partition
//  2. Extend platform PCR with golden measurement (satisfies SRK auth policy)
//  3. Load sealed blobs from EFI partition
//  4. Unseal using Platform KeyStore SRK (handle from config)
//  5. Unlock LUKS volume with unsealed key
//
// Priority: 1 (Highest priority - secure boot with Platform KeyStore)
type TPMPCRStrategy struct {
	platform *Platform
	logger   *logging.Logger
	priority int
}

// NewTPMPCRStrategy creates a new TPM PCR unlock strategy
func NewTPMPCRStrategy(platform *Platform, logger *logging.Logger) *TPMPCRStrategy {
	return &TPMPCRStrategy{
		platform: platform,
		logger:   logger,
		priority: 1, // Highest priority - secure boot with Platform KeyStore
	}
}

// StrategyNameTPMPCR is the TPM-PCR strategy's Name(): the only strategy
// whose success proves the firstboot seal, which is what platform-initrd
// tests for before it destroys the installer container.
const StrategyNameTPMPCR = "TPM-PCR"

// Name returns the strategy name
func (s *TPMPCRStrategy) Name() string {
	return StrategyNameTPMPCR
}

// Priority returns the execution priority
func (s *TPMPCRStrategy) Priority() int {
	return s.priority
}

// getPlatformKeystoreSRKHandle returns the Platform KeyStore SRK handle from config.
// Falls back to default if not configured.
func (s *TPMPCRStrategy) getPlatformKeystoreSRKHandle() xkmssdk.TPMHandle {
	if s.platform.TPM != nil {
		config := s.platform.TPM.Config()
		if config != nil && config.PlatformSRK != nil && config.PlatformSRK.SRKHandle != 0 {
			return xkmssdk.TPMHandle(config.PlatformSRK.SRKHandle)
		}
	}
	// Fallback to conventional Platform KeyStore SRK handle
	return xkmssdk.TPMHandle(0x81000002)
}

// getPlatformPolicy returns whether platform policy is enabled from config.
func (s *TPMPCRStrategy) getPlatformPolicy() bool {
	if s.platform.TPM != nil {
		config := s.platform.TPM.Config()
		if config != nil && config.PlatformSRK != nil {
			return config.PlatformSRK.PlatformPolicy
		}
	}
	return true // Default to enabled for security
}

// CanUnlock checks if this strategy can unlock the volume
// It checks for the presence of Platform KeyStore seal files on the EFI partition
func (s *TPMPCRStrategy) CanUnlock(ctx context.Context, volume *luks.VolumeConfig) bool {
	// Check if TPM is available
	if s.platform.TPM == nil {
		s.logger.Debug("TPM-PCR: TPM not available")
		return false
	}

	efiPath := s.getEFIPath()

	// Need to mount EFI to check
	mounted, err := s.ensureEFIMounted()
	if err != nil {
		s.logger.Debugf("TPM-PCR: Cannot check EFI partition: %v", err)
		return false
	}
	defer func() {
		if !mounted {
			s.unmountEFI()
		}
	}()

	// Check for Platform KeyStore seals
	platformPubPath := filepath.Join(efiPath, pcrPublicFile)
	platformPrivPath := filepath.Join(efiPath, pcrPrivateFile)
	_, err1 := os.Stat(platformPubPath)
	_, err2 := os.Stat(platformPrivPath)

	if err1 == nil && err2 == nil {
		srkHandle := s.getPlatformKeystoreSRKHandle()
		s.logger.Infof("TPM-PCR: Found Platform KeyStore seals, SRK handle=0x%08x", srkHandle)
		return true
	}

	s.logger.Debug("TPM-PCR: No Platform KeyStore seal files found on EFI partition")
	return false
}

// Unlock attempts to unlock the volume using TPM PCR-sealed keys.
// Uses Platform KeyStore SRK with platform policy (PCR 23 auth).
//
// Flow:
//  1. Extend platform PCR with golden measurement (required for Platform SRK auth)
//  2. Load Platform KeyStore seals (seal-platform.pub/priv)
//  3. Unseal using Platform SRK
//  4. Unlock LUKS with unsealed key
func (s *TPMPCRStrategy) Unlock(ctx context.Context, volume *luks.VolumeConfig) error {
	s.logger.Infof("Attempting TPM-PCR unlock for %s", volume.DevicePath)

	// Ensure EFI partition is mounted
	wasMounted, err := s.ensureEFIMounted()
	if err != nil {
		return &WrappedError{Msg: "failed to mount EFI partition", Err: err}
	}
	defer func() {
		if !wasMounted {
			s.unmountEFI()
		}
	}()

	efiPath := s.getEFIPath()

	// Extend the platform PCR with the golden measurement BEFORE
	// unsealing. The extension satisfies the SEALED OBJECT's PCR-bound
	// auth policy — the child is always PCR-bound — so it runs
	// unconditionally. keystore-platform-policy governs a different
	// axis: how the PARENT SRK is authorized during load (#52).
	s.logger.Info("Extending platform PCR with golden measurement...")
	if err := s.extendPlatformPCR(ctx); err != nil {
		s.logger.Errorf("Failed to extend platform PCR: %v", err)
		return &WrappedError{Msg: "failed to extend platform PCR", Err: err}
	}
	s.logger.Info("Platform PCR extended - sealed object policy satisfiable")

	// Get the backend
	var backend interface{}
	if s.platform.XKMS != nil {
		backend = s.platform.XKMS.Backend()
	} else if s.platform.Backend != nil {
		backend = s.platform.Backend
	}

	// Load Platform KeyStore seals
	platformPubPath := filepath.Join(efiPath, pcrPublicFile)
	platformPrivPath := filepath.Join(efiPath, pcrPrivateFile)

	if _, err := os.Stat(platformPubPath); err != nil {
		return &MessageError{Msg: fmt.Sprintf("Platform KeyStore seal not found: %s", platformPubPath)}
	}
	if _, err := os.Stat(platformPrivPath); err != nil {
		return &MessageError{Msg: fmt.Sprintf("Platform KeyStore seal not found: %s", platformPrivPath)}
	}

	s.logger.Info("Loading Platform KeyStore sealed objects...")
	key, err := s.unsealPlatformKeyStore(ctx, platformPubPath, platformPrivPath, backend)
	if err != nil {
		return &WrappedError{Msg: "Platform KeyStore unseal failed", Err: err}
	}

	// Unlock LUKS with unsealed key
	if err := s.unlockLUKS(ctx, volume, key); err != nil {
		return err
	}

	s.logger.Infof("Successfully unlocked %s with Platform KeyStore", volume.DevicePath)
	// Delete upgrade seals since Platform KeyStore seals work
	s.deleteInsecureUpgradeSeals(efiPath)
	return nil
}

// sealedObjectAttrs builds the attributes of a sealed object under the
// platform-keystore SRK. The CHILD axis (PlatformPolicy on the sealed
// object) is ALWAYS true: it attaches the PCR-bound auth policy that is
// this strategy's security property. The PARENT axis — how the SRK itself
// is authorized (password vs platform-policy session, recorded as
// keystore-platform-policy in pcr-banks) — travels on parent.PlatformPolicy
// alone. Both the seal (Install) and unseal (unsealPlatformKeyStore) sides
// build their attributes here so the two can never disagree (#52).
func sealedObjectAttrs(cn string, parent *xkmssdk.KeyAttributes) *xkmssdk.KeyAttributes {
	return &xkmssdk.KeyAttributes{
		CN:        cn,
		KeyType:   xkmssdk.KeyTypeHMAC,
		TPMPolicy: common.TPMPolicyPlatform,
		Parent:    parent,
	}
}

// unsealPlatformKeyStore unseals using Platform KeyStore SRK (0x81000002)
func (s *TPMPCRStrategy) unsealPlatformKeyStore(ctx context.Context, pubPath, privPath string, backend interface{}) ([]byte, error) {
	pkSrkHandle := s.getPlatformKeystoreSRKHandle()
	s.logger.Infof("Using Platform KeyStore SRK, handle=0x%08x", pkSrkHandle)

	// Get Platform KeyStore SRK attributes as parent
	srkAttrs, err := s.platform.TPM.KeyAttributes(pkSrkHandle)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to get Platform KeyStore SRK attributes", Err: err}
	}

	// PARENT authorization mode: how the SRK is authorized during load —
	// password or platform-policy session. Recorded at seal time as
	// keystore-platform-policy in pcr-banks and replayed here; assuming
	// the wrong mode is TPM_RC_POLICY_FAIL on every load (#52).
	srkAttrs.TPMPolicy = common.PlatformTPMPolicy(s.getPlatformPolicy())

	// CHILD attributes: the sealed object is ALWAYS PCR-bound —
	// PlatformPolicy here attaches the PCR-based auth policy the
	// platform-PCR extension above satisfies. Independent of the
	// parent's authorization mode.
	pcrAttrs := sealedObjectAttrs("luks-root", srkAttrs)
	pcrAttrs.StoreType = xkmssdk.StoreSoftware

	// Load sealed data from EFI partition files
	pubBlob, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to read seal public", Err: err}
	}
	privBlob, err := os.ReadFile(privPath)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to read seal private", Err: err}
	}

	sealedData := &xkmssdk.SealedData{
		Backend:    xkmssdk.BackendTypeTPM2,
		TPMPublic:  pubBlob,
		TPMPrivate: privBlob,
	}

	// Unseal the key using Platform KeyStore SRK
	s.logger.Info("Unsealing LUKS key from Platform KeyStore...")
	unsealOpts := &xkmssdk.UnsealOptions{
		KeyAttributes: pcrAttrs,
		Backend:       backend,
	}
	return s.platform.TPM.Unseal(ctx, sealedData, unsealOpts)
}

// unlockLUKS attempts to unlock the LUKS volume with the given key
func (s *TPMPCRStrategy) unlockLUKS(ctx context.Context, volume *luks.VolumeConfig, key []byte) error {
	openOpts := &luks.OpenOptions{
		AllowDiscards: volume.AllowDiscards,
		Timeout:       volume.Timeout,
	}

	if err := s.platform.LUKS.Open(ctx, volume.DevicePath, volume.MappingName, key, openOpts); err != nil {
		return &WrappedError{Msg: "LUKS unlock failed", Err: err}
	}

	return nil
}

// deleteInsecureUpgradeSeals removes the upgrade seal files from EFI partition
// This MUST be called after Platform KeyStore seals are verified to work
func (s *TPMPCRStrategy) deleteInsecureUpgradeSeals(efiPath string) {
	s.logger.Info("Platform KeyStore seals verified - deleting temporary upgrade seals")

	upgradePubPath := filepath.Join(efiPath, pcrUpgradePublicFile)
	upgradePrivPath := filepath.Join(efiPath, pcrUpgradePrivateFile)

	// Check if any files need to be deleted
	pubExists := false
	privExists := false

	if _, err := os.Stat(upgradePubPath); err == nil {
		pubExists = true
	}
	if _, err := os.Stat(upgradePrivPath); err == nil {
		privExists = true
	}

	if !pubExists && !privExists {
		s.logger.Debug("No upgrade seals to delete")
		return
	}

	// Remount EFI as read-write for deletion
	s.logger.Debug("Remounting EFI partition as read-write for cleanup...")
	if err := syscall.Mount("", efiPath, "", syscall.MS_REMOUNT, ""); err != nil {
		s.logger.Warnf("Failed to remount EFI as read-write: %v", err)
		s.logger.Warn("Upgrade seals may persist until next reboot")
		return
	}

	// Delete upgrade public seal
	if pubExists {
		if err := os.Remove(upgradePubPath); err != nil {
			s.logger.Warnf("Failed to delete upgrade public seal: %v", err)
		} else {
			s.logger.Info("Deleted temporary seal-upgrade.pub")
		}
	}

	// Delete upgrade private seal
	if privExists {
		if err := os.Remove(upgradePrivPath); err != nil {
			s.logger.Warnf("Failed to delete upgrade private seal: %v", err)
		} else {
			s.logger.Info("Deleted temporary seal-upgrade.priv")
		}
	}

	syscall.Sync()
	s.logger.Info("Upgrade seals deleted - system in secure state")
}

// Install performs installation-time setup for TPM-PCR strategy
func (s *TPMPCRStrategy) Install(ctx context.Context, volume *luks.VolumeConfig, password []byte) error {
	s.logger.Infof("Installing TPM-PCR strategy for %s", volume.DevicePath)

	// Generate a new random key for LUKS
	key, err := s.platform.TPM.RandomBytes(32)
	if err != nil {
		return &WrappedError{Msg: "failed to generate random key", Err: err}
	}

	// Get Platform KeyStore SRK handle from config
	pkSrkHandle := s.getPlatformKeystoreSRKHandle()
	s.logger.Infof("Using Platform KeyStore SRK, handle=0x%08x", pkSrkHandle)

	// Get Platform KeyStore SRK attributes as parent
	srkAttrs, err := s.platform.TPM.KeyAttributes(pkSrkHandle)
	if err != nil {
		return &WrappedError{Msg: "failed to get Platform KeyStore SRK attributes", Err: err}
	}

	// PARENT axis: how the SRK itself is authorized (password vs
	// platform-policy session) — the configured mode from pcr-banks.
	srkAttrs.TPMPolicy = common.PlatformTPMPolicy(s.getPlatformPolicy())

	// CHILD axis: the sealed object is ALWAYS PCR-bound, regardless of how
	// the parent SRK is authorized — the same unconditional choice
	// unsealPlatformKeyStore makes. Coupling this to the parent mode would
	// seal without an AuthPolicy under keystore-platform-policy=false while
	// unseal demands a PCR policy, and the two sides could never agree.
	attrs := sealedObjectAttrs(fmt.Sprintf("luks-root-platform-%s", volume.MappingName), srkAttrs)

	// Get the backend
	var backend interface{}
	if s.platform.XKMS != nil {
		backend = s.platform.XKMS.Backend()
	} else if s.platform.Backend != nil {
		backend = s.platform.Backend
	}

	// Seal the key under Platform KeyStore SRK
	s.logger.Infof("Sealing key under Platform KeyStore SRK with PCRs: %v", s.platform.Config.PCRSelection)
	sealOpts := &xkmssdk.SealOptions{
		KeyAttributes: attrs,
		Backend:       backend,
	}
	sealedData, err := s.platform.TPM.Seal(ctx, key, sealOpts)
	if err != nil {
		return &WrappedError{Msg: "failed to seal key", Err: err}
	}

	// Find the first available TPM-PCR slot
	var targetSlot *luks.KeySlot
	for i := range volume.KeySlots {
		if volume.KeySlots[i].Type == luks.UnlockTPMPCR {
			targetSlot = &volume.KeySlots[i]
			break
		}
	}

	if targetSlot == nil {
		return &MessageError{Msg: "no TPM-PCR key slot configured"}
	}

	// Add the key to the LUKS key slot
	addOpts := &luks.AddKeyOptions{
		KeySlot: &targetSlot.Index,
		KDFType: fips.GetKDF(),
		Hash:    fips.GetHash(),
	}

	s.logger.Info("Adding Platform KeyStore key to LUKS", "slot", targetSlot.Index, "fips", fips.IsEnabled(), "kdf", addOpts.KDFType)
	err = s.platform.LUKS.AddKey(ctx, volume.DevicePath, password, key, addOpts)
	if err != nil {
		return &WrappedError{Msg: fmt.Sprintf("failed to add key to LUKS slot %d", targetSlot.Index), Err: err}
	}

	// Store the key attributes and sealed data in the slot configuration
	targetSlot.Attrs = attrs
	targetSlot.SealedData = sealedData

	s.logger.Infof("Successfully installed Platform KeyStore seal in slot %d", targetSlot.Index)
	return nil
}

// getEFIPath returns the EFI partition path
func (s *TPMPCRStrategy) getEFIPath() string {
	return pcrEfiMountPoint
}

// ensureEFIMounted checks if EFI is mounted and mounts it if needed (read-only)
func (s *TPMPCRStrategy) ensureEFIMounted() (bool, error) {
	return s.mountEFI(syscall.MS_RDONLY)
}

// mountEFI mounts the EFI partition with the specified flags
func (s *TPMPCRStrategy) mountEFI(flags uintptr) (bool, error) {
	// Check if already mounted by looking for EFI directory
	efiDir := filepath.Join(pcrEfiMountPoint, "EFI")
	if stat, err := os.Stat(efiDir); err == nil && stat.IsDir() {
		s.logger.Debug("EFI partition already mounted")
		return true, nil
	}

	// Auto-detect EFI partition device if not configured
	bootDevice := s.platform.Config.BootDevice
	if bootDevice == "" || bootDevice == "/boot/efi" {
		s.logger.Debug("Auto-detecting EFI partition device...")
		detected, err := s.detectEFIDevice()
		if err != nil {
			return false, &WrappedError{Msg: "failed to detect EFI partition", Err: err}
		}
		bootDevice = detected
		s.logger.Debugf("Detected EFI partition: %s", bootDevice)
	}

	// Create mount point if it doesn't exist
	if err := os.MkdirAll(pcrEfiMountPoint, 0755); err != nil {
		return false, &WrappedError{Msg: "failed to create mount point", Err: err}
	}

	// Mount the EFI partition
	err := syscall.Mount(
		bootDevice,
		pcrEfiMountPoint,
		"vfat",
		flags,
		"",
	)
	if err != nil {
		return false, &WrappedError{Msg: fmt.Sprintf("failed to mount EFI partition %s", bootDevice), Err: err}
	}

	if flags&syscall.MS_RDONLY != 0 {
		s.logger.Debugf("Mounted EFI partition %s at %s (read-only)", bootDevice, pcrEfiMountPoint)
	} else {
		s.logger.Debugf("Mounted EFI partition %s at %s (read-write)", bootDevice, pcrEfiMountPoint)
	}
	return false, nil
}

// detectEFIDevice locates the EFI partition that belongs to the configured
// root device (sibling partition, then the EFI label, then the well-known
// first-partition names, see pkg/partition).
func (s *TPMPCRStrategy) detectEFIDevice() (string, error) {
	device, err := partition.FindESP(s.platform.rootDevice())
	if err != nil {
		return "", &WrappedError{Msg: "no EFI partition found", Err: err}
	}
	s.logger.Debugf("Detected EFI partition: %s", device)
	return device, nil
}

// unmountEFI unmounts the EFI partition
func (s *TPMPCRStrategy) unmountEFI() {
	if err := syscall.Unmount(pcrEfiMountPoint, 0); err != nil {
		s.logger.Debugf("Failed to unmount EFI partition: %v", err)
	} else {
		s.logger.Debug("Unmounted EFI partition")
	}
}

// extendPlatformPCR extends the platform PCR with golden measurement in-process.
// This MUST be called BEFORE any operations that require Platform KeyStore SRK.
//
// Uses the TPM connection already established in the platform to extend PCR 23
// (or configured platform PCR) with the golden measurement hash.
func (s *TPMPCRStrategy) extendPlatformPCR(ctx context.Context) error {
	if s.platform.TPM == nil {
		return &MessageError{Msg: "TPM not available for PCR extension"}
	}

	// Check if platform PCR is already extended
	extended, err := s.platform.TPM.IsPlatformPCRExtended()
	if err != nil {
		s.logger.Warnf("Failed to check platform PCR state: %v", err)
		// Continue anyway - CreatePlatformPolicy will fail if there's a real problem
	} else if extended {
		s.logger.Info("Platform PCR already extended, skipping")
		return nil
	}

	// Extend platform PCR with golden measurement
	s.logger.Info("Extending platform PCR with golden measurement (in-process)...")
	if err := s.platform.TPM.CreatePlatformPolicy(); err != nil {
		return &WrappedError{Msg: "failed to extend platform PCR", Err: err}
	}

	s.logger.Info("Platform PCR extended successfully")
	return nil
}
