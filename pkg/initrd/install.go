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
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/fips"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// Install performs the installation workflow
// This sets up LUKS encryption and provisions all unlock strategies
// It also prepares a bootable disk with proper partitioning and filesystems
func (m *initrdManager) Install(ctx context.Context, password []byte) error {
	m.logger.Info("[PLATFORM-INITRD] Starting installation workflow",
		"device", m.platform.Config.RootDevice,
		"xkms_path", m.platform.Config.XKMSPath)

	startTime := time.Now()

	// Validate configuration
	m.logger.Info("[PLATFORM-INITRD] Validating configuration")
	if err := m.platform.Config.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	m.logger.Info("[PLATFORM-INITRD] Configuration validated successfully")

	// Ensure xkms directory exists
	m.logger.Info("[PLATFORM-INITRD] Creating xkms directory", "path", m.platform.Config.XKMSPath)
	if err := os.MkdirAll(m.platform.Config.XKMSPath, 0700); err != nil {
		return fmt.Errorf("failed to create xkms directory: %w", err)
	}
	m.logger.Info("[PLATFORM-INITRD] XKMS directory created")

	// Initialize platform components
	m.logger.Info("[PLATFORM-INITRD] Initializing platform components")
	if err := m.initializePlatform(ctx); err != nil {
		return fmt.Errorf("failed to initialize platform: %w", err)
	}
	m.logger.Info("[PLATFORM-INITRD] Platform components initialized")

	// Minimal TPM setup - creates EK and SRK if they don't exist
	m.logger.Info("[PLATFORM-INITRD] Provisioning TPM (creating EK and SRK)")
	if err := m.platform.TPM.Install(nil, nil); err != nil {
		// Software TPMs (swtpm) don't have EK certificates - expected
		if !errors.Is(err, xkmssdk.ErrTPMEndorsementCertNotFound) {
			return fmt.Errorf("failed to initialize TPM: %w", err)
		}
		m.logger.Info("[PLATFORM-INITRD] No EK certificate found (expected for software TPM)")
	}
	m.logger.Info("[PLATFORM-INITRD] TPM provisioned successfully")

	// Step 1: Partition the disk (EFI + LUKS root)
	m.logger.Info("[PLATFORM-INITRD] Partitioning disk")
	diskPreparer := NewDiskPreparer(m.platform.Config.RootDevice, "/mnt", m.logger)
	if err := diskPreparer.PartitionDisk(ctx); err != nil {
		return fmt.Errorf("failed to partition disk: %w", err)
	}
	scheme := diskPreparer.GetScheme()

	// Step 2: Format EFI partition
	if err := diskPreparer.FormatEFIPartition(ctx); err != nil {
		return fmt.Errorf("failed to format EFI partition: %w", err)
	}

	// Step 3: Setup LUKS on root partition
	m.logger.Info("[PLATFORM-INITRD] Setting up LUKS encryption on root partition", "partition", scheme.RootPartition)

	// Update config to use the root partition (not the whole disk)
	originalDevice := m.platform.Config.RootDevice
	m.platform.Config.RootDevice = scheme.RootPartition

	// Check if partition is already LUKS formatted
	isLUKS, err := m.platform.LUKS.IsLUKS(ctx, scheme.RootPartition)
	if err != nil {
		return fmt.Errorf("failed to check LUKS status: %w", err)
	}

	// Format partition if not already LUKS
	if !isLUKS {
		if err := m.formatLUKSVolume(ctx, password); err != nil {
			m.platform.Config.RootDevice = originalDevice // Restore original
			return fmt.Errorf("failed to format LUKS volume: %w", err)
		}
	} else {
		m.logger.Info("[PLATFORM-INITRD] Partition is already LUKS formatted, skipping format")
	}

	// Build volume configuration
	m.logger.Info("[PLATFORM-INITRD] Building volume configuration")
	volume, err := m.buildVolumeConfig()
	if err != nil {
		m.platform.Config.RootDevice = originalDevice // Restore original
		return fmt.Errorf("failed to build volume config: %w", err)
	}
	m.logger.Info("[PLATFORM-INITRD] Volume configuration built")

	// Install unlock strategies (seals key to TPM)
	if err := m.installUnlockStrategies(ctx, volume, password); err != nil {
		m.platform.Config.RootDevice = originalDevice // Restore original
		return fmt.Errorf("failed to install unlock strategies: %w", err)
	}

	// Step 4: Open the LUKS volume
	mappingName := volume.MappingName // Use the mapping name from volume config
	m.logger.Info("[PLATFORM-INITRD] Opening LUKS volume", "mapping", mappingName)
	if err := m.platform.LUKS.Open(ctx, scheme.RootPartition, mappingName, password, nil); err != nil {
		m.platform.Config.RootDevice = originalDevice // Restore original
		return fmt.Errorf("failed to open LUKS volume: %w", err)
	}
	luksDevicePath := "/dev/mapper/" + mappingName

	// Step 5: Format root filesystem
	if err := diskPreparer.FormatRootFilesystem(ctx, luksDevicePath); err != nil {
		m.platform.LUKS.Close(ctx, mappingName)
		m.platform.Config.RootDevice = originalDevice // Restore original
		return fmt.Errorf("failed to format root filesystem: %w", err)
	}

	// Step 6: Mount filesystems
	if err := diskPreparer.MountFilesystems(ctx, luksDevicePath); err != nil {
		m.platform.LUKS.Close(ctx, mappingName)
		m.platform.Config.RootDevice = originalDevice // Restore original
		return fmt.Errorf("failed to mount filesystems: %w", err)
	}

	// Restore original device path
	m.platform.Config.RootDevice = originalDevice

	duration := time.Since(startTime)
	m.logger.Info("[PLATFORM-INITRD] Installation completed successfully", "duration", duration)
	m.logger.Info("[PLATFORM-INITRD] Encrypted disk prepared and ready for OS installation",
		"root_mount", "/mnt",
		"boot_mount", "/mnt/boot")

	return nil
}

// formatLUKSVolume formats the device as a LUKS2 volume
func (m *initrdManager) formatLUKSVolume(ctx context.Context, password []byte) error {
	// Use FIPS-appropriate KDF (auto-detected from kernel)
	// FIPS 140-3 does not approve Argon2id, so PBKDF2-SHA256 must be used
	kdfType := fips.GetKDF()
	isFIPS := fips.IsEnabled()

	m.logger.Info("[PLATFORM-INITRD] Formatting device as LUKS2 volume",
		"device", m.platform.Config.RootDevice,
		"cipher", "aes-xts-plain64",
		"key_size", 512,
		"hash", "sha256",
		"kdf", kdfType,
		"fips", isFIPS)

	formatOpts := &luks.FormatOptions{
		Cipher:        "aes-xts-plain64",
		KeySize:       512, // 512 bits for XTS = 256-bit effective
		HashAlgorithm: "sha256",
		KDFType:       kdfType,
		Label:         "cryptroot",
		SectorSize:    512,
	}

	err := m.platform.LUKS.Format(ctx, m.platform.Config.RootDevice, password, formatOpts)
	if err != nil {
		return fmt.Errorf("LUKS format failed: %w", err)
	}

	m.logger.Info("[PLATFORM-INITRD] LUKS volume formatted successfully")
	return nil
}

// installUnlockStrategies installs all configured unlock strategies
// During installation, we use TPM-NoPCR strategy to create initial sealed keys
func (m *initrdManager) installUnlockStrategies(ctx context.Context, volume *luks.VolumeConfig, password []byte) error {
	m.logger.Info("[PLATFORM-INITRD] Installing unlock strategies for installation mode")

	// For installation, we use TPM-NoPCR strategy
	// This creates a TPM-sealed key WITHOUT PCR policy to allow first boot to succeed
	// The system should re-seal with PCR policy on first boot for enhanced security
	noPCRStrategy := NewTPMNoPCRStrategy(m.platform, m.logger)

	m.logger.Info("[PLATFORM-INITRD] Installing strategy", "strategy", noPCRStrategy.Name())
	err := noPCRStrategy.Install(ctx, volume, password)
	if err != nil {
		return fmt.Errorf("failed to install TPM-NoPCR strategy: %w", err)
	}

	m.logger.Info("[PLATFORM-INITRD] Successfully installed TPM-NoPCR strategy")
	m.logger.Info("Note: The system should re-seal keys with PCR policy on first boot")

	return nil
}

// VerifyInstallation verifies that the installation was successful
func (m *initrdManager) VerifyInstallation(ctx context.Context) error {
	m.logger.Info("Verifying installation")

	// Check LUKS status
	status, err := m.platform.LUKS.Status(ctx, m.platform.Config.RootDevice)
	if err != nil {
		return fmt.Errorf("failed to get LUKS status: %w", err)
	}

	if status.Version != luks.LUKS2 {
		return fmt.Errorf("expected LUKS2, got %d", status.Version)
	}

	m.logger.Infof("LUKS verification passed:")
	m.logger.Infof("  Version: %d", status.Version)
	m.logger.Infof("  UUID: %s", status.UUID)
	m.logger.Infof("  Cipher: %s", status.Cipher)
	m.logger.Infof("  Key Size: %d bits", status.KeySize)
	m.logger.Infof("  Active Slots: %v", status.ActiveSlots)

	return nil
}
