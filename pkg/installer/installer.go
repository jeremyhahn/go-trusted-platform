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
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/anatol/devmapper.go"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/authenticode"
	"github.com/jeremyhahn/go-trusted-platform/pkg/fips"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/quirks"
	"github.com/jeremyhahn/go-trusted-platform/pkg/secureboot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uefi"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uki"
	"golang.org/x/sys/unix"

	// Import Alpine package to register FIPS installer
	_ "github.com/jeremyhahn/go-trusted-platform/pkg/installer/alpine"
)

// targetMountPoint is where the installer mounts the target root filesystem.
const targetMountPoint = "/mnt"

// installer implements the Installer interface
type installer struct {
	config      *Config
	logger      *logging.Logger
	diskManager DiskManager
	osInstaller OSInstaller
	ukiBuilder  UKIBuilder

	// resolveRemoteSigner is the remote hash-signing seam consumed by
	// resolveSecureBootSigner branch (b). It is nil unless wired: NewInstaller
	// populates it for resign-mode remote when a complete RemoteSignContext is
	// supplied (install-time DB signing over /api/v1/provisioning/sign); the
	// Phase 5a kernel-update path and tests populate it directly.
	resolveRemoteSigner remoteSignerResolver

	// remoteSignCtx carries the pre-IDevID provisioning identity (EAB + EK + CP
	// URL) used to populate resolveRemoteSigner for install-time remote DB
	// signing. It is supplied via WithRemoteSignContext and is nil for airgapped
	// or local installs, in which case the remote seam stays nil.
	remoteSignCtx *RemoteSignContext
}

// InstallerOption customises a newly constructed installer. The primary use is
// WithRemoteSignContext, which threads the boot/provisioning identity needed for
// install-time remote Secure Boot DB signing (resign-mode: remote) into the
// constructor so it can wire the remote signer seam.
type InstallerOption func(*installer)

// WithRemoteSignContext supplies the pre-IDevID provisioning identity (EAB
// credentials, TPM EK serial/cert, NIC MAC, and the control-plane URL) used for
// install-time remote Secure Boot DB signing. When present and Secure Boot is in
// resign-mode remote, NewInstaller wires the remote signer seam; otherwise the
// seam stays nil and resolveSecureBootSigner falls through to on-node generation.
func WithRemoteSignContext(rsc *RemoteSignContext) InstallerOption {
	return func(i *installer) { i.remoteSignCtx = rsc }
}

// NewInstaller creates a new system installer. Optional InstallerOptions thread
// extra construction-time context; WithRemoteSignContext enables install-time
// remote Secure Boot DB signing (resign-mode: remote).
func NewInstaller(
	logger *logging.Logger,
	config *Config,
	opts ...InstallerOption,
) (Installer, error) {

	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Propagate FIPS flag from OS config to encryption config
	// This ensures LUKS uses PBKDF2 instead of Argon2id in FIPS mode
	if config.OS != nil && config.OS.FIPS && config.Disk != nil && config.Disk.Encryption != nil {
		config.Disk.Encryption.FIPS = true
	}

	// Propagate Debug flag to OS config for debug mode features
	// This enables SSH installation and root login configuration
	if config.OS != nil && config.Debug {
		config.OS.Debug = true
	}

	// Propagate hardware identity fields into OSConfig so that OS-specific
	// installers (e.g. alpineInstaller) can resolve pkg/quirks entries for
	// vendor-specific console wiring, kernel modules, and Samba settings
	// without needing access to the outer Config struct.
	if config.OS != nil {
		hw := config.HardwareIdentity()
		config.OS.HardwareManufacturer = hw.Manufacturer
		config.OS.HardwareModel = hw.Model
		config.OS.HardwarePartNumber = hw.PartNumber
	}

	// Create disk manager
	diskManager, err := NewDiskManager(logger, config.Disk)
	if err != nil {
		return nil, ErrDiskOperation("failed to create disk manager", err)
	}

	// Ensure OS filesystem type is synced with disk config
	if config.OS != nil && config.OS.FilesystemType == "" {
		if config.Disk != nil && config.Disk.RootFilesystem != "" {
			config.OS.FilesystemType = config.Disk.RootFilesystem
		} else {
			config.OS.FilesystemType = FilesystemLVM
		}
	}

	// Create OS-specific installer
	osInstaller, err := NewOSInstaller(logger, config.OS)
	if err != nil {
		return nil, ErrOSInstall("failed to create OS installer", err)
	}

	// Create UKI builder
	ukiBuilder := NewUKIBuilderAdapter(logger)

	// Check for TPM device if sealing is enabled
	// NOTE: We intentionally do NOT initialize the TPM here.
	// Creating a tpm2.NewTPM2() would provision the EK, which would then
	// conflict with firstboot provisioning (--init flag).
	// The installer only needs to verify TPM device exists.
	// Full TPM provisioning (EK, SRK, etc.) happens during firstboot.
	if config.EnableTPMSealing {
		if _, err := os.Stat("/dev/tpmrm0"); err == nil {
			logger.Info("TPM device found (/dev/tpmrm0) - provisioning will happen during firstboot")
		} else if _, err := os.Stat("/dev/tpm0"); err == nil {
			logger.Info("TPM device found (/dev/tpm0) - provisioning will happen during firstboot")
		} else {
			logger.Warn("TPM sealing enabled but no TPM device found, continuing without TPM")
			config.EnableTPMSealing = false
		}
	}

	inst := &installer{
		config:      config,
		logger:      logger,
		diskManager: diskManager,
		osInstaller: osInstaller,
		ukiBuilder:  ukiBuilder,
	}
	for _, opt := range opts {
		opt(inst)
	}

	// Wire the install-time remote DB signer seam when Secure Boot is in
	// resign-mode remote AND a complete provisioning context was supplied. The
	// DB private key stays in the control-plane KMS; only the digest is
	// round-tripped over /api/v1/provisioning/sign. When the context is absent
	// or incomplete (airgap / local installs) the seam stays nil and
	// resolveSecureBootSigner falls through to on-node key generation.
	if config.SecureBoot != nil && config.SecureBoot.Enabled &&
		config.SecureBoot.ResignMode == SecureBootResignModeRemote && inst.remoteSignCtx.ready() {
		logger.Info("[SECUREBOOT] resign-mode remote with a provisioning context — wiring install-time remote DB signer",
			"server_url", inst.remoteSignCtx.ServerURL)
		inst.resolveRemoteSigner = installRemoteSignerResolver(inst.remoteSignCtx, logger)
	}

	return inst, nil
}

// Install performs the complete system installation
func (i *installer) Install(ctx context.Context) error {
	i.logger.Info("[INSTALLER] Starting system installation")

	// Step 1: Clear TPM state before provisioning.
	//
	// Always attempt TPM2_Clear, independent of EnableTPMSealing. On re-install
	// stale TPM state (keys, PCR policies, ownership) from the previous
	// installation causes PCR_POLICY_FAIL / TPM_RC_POLICY errors at first
	// boot when platformd tries to seal against the current PCR values. A
	// clear-on-install always leaves the TPM ready for a fresh hierarchy.
	//
	// Failure is non-fatal: when no TPM is present at all (VM, hardware
	// without a TPM chip) the install must still proceed. clearTPM itself
	// attempts modprobe(tpm_tis/tpm_crb) so the live ISO doesn't need the
	// modules preloaded.
	if err := i.clearTPM(); err != nil {
		i.logger.Warn("[INSTALLER] TPM clear skipped or failed (continuing)", "error", err)
	} else {
		i.logger.Info("[INSTALLER] TPM cleared successfully - ready for fresh provisioning")
	}

	// Step 2: Disk partitioning and LUKS setup
	diskInfo, err := i.setupDisk(ctx)
	if err != nil {
		return &WrappedError{Msg: "disk setup failed", Err: err}
	}
	i.logger.Info("[INSTALLER] Disk setup complete", "device", diskInfo.Device)

	// Step 2: Install base operating system
	if err := i.installOS(ctx, diskInfo); err != nil {
		return &WrappedError{Msg: "os installation failed", Err: err}
	}
	i.logger.Info("[INSTALLER] OS installation complete")

	// Step 3: Install FIPS kernel (if FIPS enabled)
	// Note: FIPS kernel must be installed BEFORE building UKI, but OpenSSL config must be AFTER signing
	var fipsInstaller fips.Installer
	if i.config.OS.FIPS {
		i.logger.Info("[INSTALLER] FIPS is enabled, installing FIPS kernel (phase 1)")
		var err error
		fipsInstaller, err = i.createFIPSInstaller()
		if err != nil {
			return &WrappedError{Msg: "failed to create FIPS installer", Err: err}
		}
		if err := fipsInstaller.InstallKernel(ctx); err != nil {
			return &WrappedError{Msg: "fips kernel installation failed", Err: err}
		}
		i.logger.Info("[INSTALLER] FIPS kernel installed")
	}

	// Step 4: Install platformd binary and dracut module BEFORE UKI build
	// This must happen BEFORE buildUKI() because dracut needs the binary in initramfs
	// This is CRITICAL - if platform-initrd isn't in the initramfs, the system won't boot
	if err := i.installPlatformInitrdForDracut(ctx); err != nil {
		return &WrappedError{Msg: "[INSTALLER] CRITICAL: failed to install platform-initrd for dracut", Err: err}
	}
	i.logger.Info("[INSTALLER] Platform-initrd installed for dracut")

	// Step 4b: gatewayd for gateway-role nodes (#66). Required when the
	// platform configuration enables the gateway role; a gateway image
	// without its edge daemon fails here rather than booting as a worker.
	if err := i.installGatewaydBinary(ctx, "/mnt", i.gatewayRoleFromConfig()); err != nil {
		return &WrappedError{Msg: "[INSTALLER] CRITICAL: failed to install gatewayd", Err: err}
	}

	// NOTE: LUKS keys are ONLY stored in the encrypted installer.luks container
	// NEVER write plaintext keys to the raw EFI partition!

	// Step 5: Build and install UKI
	// Note: Kernel must be available (either standard or FIPS) before this step
	// Note: platformd must be installed before this step for dracut to include it
	// Note: Firstboot keyfile must be created before this step for dracut to embed it
	if err := i.buildUKI(ctx, diskInfo); err != nil {
		return &WrappedError{Msg: "uki building failed", Err: err}
	}
	i.logger.Info("[INSTALLER] UKI built and installed")

	// Step 6: Sign UKI with Secure Boot keys (if available)
	// Note: Must be done BEFORE FIPS OpenSSL configuration because FIPS mode breaks signing
	// signUKI will gracefully skip if keys or sbsign are not available
	if err := i.signUKI(ctx, diskInfo); err != nil {
		return &WrappedError{Msg: "secure boot signing failed", Err: err}
	}

	// Step 6b: Configure UEFI boot entry
	// Create a proper boot entry pointing to the UKI at the standard UEFI path
	if err := i.configureUEFIBoot(ctx, diskInfo); err != nil {
		i.logger.Warnf("[INSTALLER] UEFI boot configuration failed: %v (system will boot via standard UEFI path)", err)
	}

	// Step 6c: OPTIONALLY enforce UEFI Secure Boot (db -> KEK -> PK LAST).
	// MUST run BEFORE FIPS OpenSSL configuration, which breaks signing/verify.
	// Safe-by-default: keys are enrolled only when the signed UKI provably
	// verifies against the db cert AND the firmware is in Setup Mode, and PK is
	// written last so a failed/misconfigured enable can never strand the node.
	// Best-effort — a failure is logged but never aborts an otherwise-bootable
	// install.
	if err := i.enforceSecureBoot(ctx, diskInfo); err != nil {
		i.logger.Warnf("[INSTALLER] Secure Boot enforcement failed: %v (system will boot unsigned)", err)
	}

	// Step 6d: install the kernel-update UKI rebuild hook so a future
	// `apk upgrade linux-lts` re-builds and re-signs the UKI and the node stays
	// bootable under enforced Secure Boot + CONFIG_MODULE_SIG_FORCE. Guarded on
	// secure-boot.enabled inside the step; best-effort — a failure here does not
	// break THIS install, only future kernel upgrades (which would then need a
	// manual `platformctl install uki-rebuild`).
	if err := i.installKernelUpdateHook(); err != nil {
		i.logger.Warnf("[INSTALLER] Failed to install kernel-update UKI rebuild hook: %v (kernel upgrades will need a manual re-sign)", err)
	}

	// Step 7: Configure OpenSSL for FIPS (if FIPS enabled)
	// Note: MUST be done AFTER signing to avoid breaking OpenSSL operations
	if i.config.OS.FIPS && fipsInstaller != nil {
		i.logger.Info("[INSTALLER] Configuring OpenSSL for FIPS mode (phase 2)")
		if err := fipsInstaller.ConfigureOpenSSL(ctx); err != nil {
			return &WrappedError{Msg: "fips openssl configuration failed", Err: err}
		}
		// Verify FIPS installation
		if err := fipsInstaller.Verify(); err != nil {
			return &WrappedError{Msg: "fips verification failed", Err: err}
		}
		i.logger.Info("[INSTALLER] FIPS configuration complete and verified")
	}

	// CRITICAL: Sync EFI partition before writing the installer container.
	// The UKI (74MB) and signed version must be fully committed to the FAT32
	// partition before we allocate 100MB for installer.luks. Without this sync,
	// the FAT32 cluster allocation for installer.luks can overwrite the UKI data.
	i.logger.Info("[INSTALLER] Syncing EFI partition before installer container creation")
	efiSyncDir, err := os.Open("/mnt/boot/efi")
	if err == nil {
		if syncErr := efiSyncDir.Sync(); syncErr != nil {
			i.logger.Warnf("[INSTALLER] Failed to sync EFI partition: %v", syncErr)
		}
		efiSyncDir.Close()
	}
	// unix.Sync() is sync(2), which on Linux returns only once writeback has
	// completed. The second that used to follow it waited for work already done.
	unix.Sync()

	// Verify UKI still exists before creating installer container
	ukiVerify := "/mnt/boot/efi/EFI/BOOT/BOOTX64.EFI"
	if info, verifyErr := os.Stat(ukiVerify); verifyErr != nil {
		i.logger.Warnf("[INSTALLER] WARNING: UKI file missing before installer creation: %v", verifyErr)
	} else {
		i.logger.Info("[INSTALLER] UKI verified present before installer creation", "size", info.Size())
	}

	// Step 8: Prepare LUKS key for TPM sealing
	// Create an encrypted installer container on the EFI partition containing the LUKS key.
	//
	// SECURITY: The LUKS key is NEVER stored in plaintext on the EFI partition!
	// It is only stored inside the encrypted installer.luks container.
	//
	// The flow is:
	//   1. This step creates /boot/efi/tpm2/installer.luks (encrypted container with luks-key.bin inside)
	//   2. First boot: platform-initrd mounts installer.luks, reads key, unlocks LUKS
	//   3. After switch_root: platformctl firstboot provisions platform, seals key to TPM
	//   4. Firstboot securely wipes installer.luks - forensic protection achieved
	//
	// We DO NOT seal during installation because the ISO kernel is measured, not installed kernel.
	if i.config.Disk.Encryption != nil {
		if err := i.prepareLUKSKeyForTPM(ctx, diskInfo); err != nil {
			// Don't fail installation if key preparation fails
			// User can still unlock with password
			i.logger.Warn("[INSTALLER] Failed to prepare LUKS key for TPM", "error", err)
		} else {
			i.logger.Info("[INSTALLER] LUKS key prepared for initramfs firstboot sealing")
		}
	}

	// Step 10: Install firstboot service (fallback/cleanup only)
	// NOTE: Primary sealing now happens in INITRAMFS via FirstbootSealStrategy.
	// This service is kept as a fallback in case initramfs sealing fails.
	// The platformd binary was already installed in Step 4 for dracut.
	if err := i.installFirstbootService(ctx); err != nil {
		i.logger.Warn("[INSTALLER] Failed to install firstboot service (fallback)", "error", err)
		// Don't fail - primary sealing is in initramfs
	} else {
		i.logger.Info("[INSTALLER] Firstboot service installed as fallback")
	}

	// Step 10: Enable essential OpenRC services in the default runlevel
	// (Note: Console configuration is now handled by OS-specific installer)
	if err := i.osInstaller.EnableServices(ctx, "/mnt"); err != nil {
		i.logger.Warn("[INSTALLER] Failed to enable OpenRC services", "error", err)
		// Don't fail installation if service enablement fails
	}

	// Step 11: FIDO2 enrollment (automatic detection or explicit configuration)
	// Note: FIDO2 enrollment must be done AFTER LUKS setup and with physical device access
	if i.config.EnableFIDO2Enrollment {
		// Explicitly enabled
		if err := i.enrollFIDO2(ctx, diskInfo); err != nil {
			i.logger.Warn("[INSTALLER] FIDO2 enrollment failed", "error", err)
			// Don't fail installation if FIDO2 enrollment fails
			// User can enroll FIDO2 key manually after boot
		} else {
			i.logger.Info("[INSTALLER] FIDO2 enrollment complete")
		}
	} else if i.config.Disk.Encryption != nil {
		// Auto-detect FIDO2 device if LUKS encryption is enabled
		i.logger.Info("[INSTALLER] Checking for FIDO2 security key...")
		if IsFIDO2Available() {
			i.logger.Info("[INSTALLER] FIDO2 device detected! Automatically enrolling for LUKS unlock")
			if err := i.enrollFIDO2(ctx, diskInfo); err != nil {
				i.logger.Warn("[INSTALLER] Automatic FIDO2 enrollment failed", "error", err)
				i.logger.Info("[INSTALLER] You can manually enroll later with: platformd fido2 enroll")
			} else {
				i.logger.Info("[INSTALLER] FIDO2 security key enrolled automatically")
			}
		} else {
			i.logger.Info("[INSTALLER] No FIDO2 device detected, skipping FIDO2 enrollment")
		}
	}

	// Step 12: Clean shutdown of disk resources - CRITICAL for data integrity
	// Without proper cleanup, encrypted data may not be flushed to disk before reboot
	i.logger.Info("[INSTALLER] Cleaning up disk resources before completion")

	// Sync all pending writes first. sync(2) blocks until writeback completes,
	// so there is nothing left to wait for afterwards.
	unix.Sync()

	// First unmount any chroot pseudo-filesystems that might still be mounted
	chrootMounts := []string{"/mnt/dev", "/mnt/sys", "/mnt/proc"}
	for _, mount := range chrootMounts {
		if err := unix.Unmount(mount, unix.MNT_DETACH); err == nil {
			i.logger.Info("[INSTALLER] Unmounted chroot mount", "path", mount)
		}
	}

	// CRITICAL: Flush ALL pending writes to the EFI partition before unmount.
	// FAT32 on real SATA SSDs can lose data without proper fsync.
	i.logger.Info("[INSTALLER] Syncing EFI partition before unmount")

	// System-wide sync as belt-and-suspenders.
	//
	// The two seconds that used to follow this were labelled "allow disk
	// controller to flush write-back cache", which reads as the durability step
	// itself. It was not: sync(2) blocks until writeback completes, and the
	// controller flush is covered by the blockdev --flushbufs calls below. The
	// sleep was redundancy stacked on calls that already wait (#260).
	//
	// The fsync of the EFI MOUNT POINT that used to sit above this is gone for
	// a different reason. /mnt/boot/efi is a directory, so fsyncing it flushed
	// the name entry and not BOOTX64.EFI's contents — which is not what a
	// reader would take that call to mean. syncUKIOnESP below fsyncs the file
	// and then its parent directory, matching uki_rebuild.go.
	//
	// And what #260 correctly recorded as unhandled here — every flush and
	// unmount below logging a warning and continuing to reboot, including the
	// UKI-missing check — is what this change fixes (#287).
	unix.Sync()

	// Make the unified kernel image durable and prove it is there. A failure
	// here means the installed system will not boot, so it ends the install
	// rather than being logged and stepped over.
	if err := i.syncUKIOnESP(); err != nil {
		return err
	}

	// Unmount filesystems in reverse order - use lazy unmount if regular fails
	for _, mountPoint := range []string{espMountPoint, "/mnt"} {
		if err := i.unmountOrFail(mountPoint, unix.Unmount); err != nil {
			return err
		}
	}

	// Sync, then flush the device buffers explicitly with blockdev --flushbufs
	// below. Both block; neither needs to be waited on afterwards.
	unix.Sync()

	// Flush dm-crypt device buffers explicitly
	if diskInfo.MappedDevice != "" {
		if err := i.flushBuffers(ctx, "/dev/mapper/cryptroot", runCommand); err != nil {
			return err
		}
	}

	// Flush backend device buffers
	backendDev := fmt.Sprintf("%s2", i.config.Disk.Device)
	if err := i.flushBuffers(ctx, backendDev, runCommand); err != nil {
		return err
	}

	// Another sync after flush
	unix.Sync()

	// DEBUG: Verify LVM data exists before cleanup
	if diskInfo.MappedDevice != "" {
		// Check decrypted view
		cryptrootPath := "/dev/mapper/cryptroot"
		if f, err := os.Open(cryptrootPath); err == nil {
			buf := make([]byte, 1024)
			if _, err := f.Read(buf); err == nil {
				i.logger.Info("[INSTALLER] DEBUG: cryptroot DECRYPTED before cleanup",
					"offset_0", fmt.Sprintf("%x", buf[:32]),
					"offset_512", fmt.Sprintf("%x", buf[512:544]))
				if string(buf[512:520]) == "LABELONE" {
					i.logger.Info("[INSTALLER] DEBUG: LVM signature FOUND at offset 512!")
				} else {
					i.logger.Warn("[INSTALLER] DEBUG: NO LVM signature at offset 512!", "got", fmt.Sprintf("%q", string(buf[512:520])))
				}
			}
			if closeErr := f.Close(); closeErr != nil {
				i.logger.Warn("[INSTALLER] failed to close file", "error", closeErr)
			}
		}

		// Check raw encrypted data on backend device - drop caches first to ensure fresh read from disk
		if output, err := exec.CommandContext(ctx, "sh", "-c", "echo 3 > /proc/sys/vm/drop_caches").CombinedOutput(); err != nil {
			i.logger.Warn("[INSTALLER] drop_caches failed", "error", err, "output", string(output))
		}

		if f, err := os.Open(backendDev); err == nil {
			buf := make([]byte, 1024)
			// Read at LUKS data offset (290816 bytes)
			if _, err := f.ReadAt(buf, 290816); err == nil {
				i.logger.Info("[INSTALLER] DEBUG: backend ENCRYPTED at offset 290816 (after cache drop)",
					"offset_0", fmt.Sprintf("%x", buf[:32]),
					"offset_512", fmt.Sprintf("%x", buf[512:544]))
				// Check if it's all zeros (means nothing was written)
				allZeros := true
				for _, b := range buf[:64] {
					if b != 0 {
						allZeros = false
						break
					}
				}
				if allZeros {
					i.logger.Warn("[INSTALLER] DEBUG: Backend device has ALL ZEROS - data NOT encrypted/written!")
				} else {
					i.logger.Info("[INSTALLER] DEBUG: Backend device has encrypted data")
				}
			}
			if err := f.Close(); err != nil {
				i.logger.Warn("[INSTALLER] DEBUG: Failed to close backend device", "error", err)
			}
		}
	}

	// Deactivate LVM if used - use devmapper directly (dmsetup may not be installed)
	if diskInfo.LVMDevice != "" {
		i.logger.Info("[INSTALLER] Deactivating LVM devices using devmapper")

		// Remove LVM devices in order: LV first, then VG internal devices
		lvmDevices := []string{"vg0-root"}
		for _, dev := range lvmDevices {
			i.logger.Info("[INSTALLER] Removing device-mapper device", "name", dev)
			if err := devmapper.Remove(dev); err != nil {
				i.logger.Warn("[INSTALLER] devmapper.Remove failed", "device", dev, "error", err)
			} else {
				i.logger.Info("[INSTALLER] Device removed successfully", "name", dev)
			}
		}

		// Wait for the mappings to actually disappear rather than sleeping and
		// assuming. devmapper.Remove can return before the node is gone, and the
		// LUKS close below fails confusingly if a mapping is still held.
		for _, dev := range lvmDevices {
			// Concatenated, not filepath.Join: /dev/mapper is a kernel-fixed
			// location rather than a composed path, and gocritic's filepathJoin
			// rightly objects to handing Join an argument that already contains
			// a separator. It also matches how the rest of the repo names these
			// nodes (pkg/firstboot/strategy.go).
			node := "/dev/mapper/" + dev
			if err := pollUntil(ctx, 10*time.Second, 100*time.Millisecond, func() bool {
				_, statErr := os.Stat(node)
				return os.IsNotExist(statErr)
			}); err != nil {
				i.logger.Warn("[INSTALLER] device-mapper node still present after removal", "node", node, "error", err)
			}
		}
		unix.Sync()
	}

	// Close the main LUKS device - CRITICAL for flushing encrypted data
	if diskInfo.MappedDevice != "" {
		mappedName := "cryptroot"
		if i.config.Disk.Encryption != nil && i.config.Disk.Encryption.MappedName != "" {
			mappedName = i.config.Disk.Encryption.MappedName
		}

		// Try up to 3 times with increasing delays
		luksClosed := false
		for attempt := 1; attempt <= 3; attempt++ {
			i.logger.Info("[INSTALLER] Closing LUKS device", "name", mappedName, "attempt", attempt)
			if err := luks2.Lock(mappedName); err != nil {
				i.logger.Warn("[INSTALLER] Failed to close LUKS device", "error", err, "attempt", attempt)
				if attempt < 3 {
					// Cancellable backoff. This is a DIFFERENT change from
					// removing a guess: the wait itself is legitimate — the
					// device is genuinely busy and retrying immediately would
					// fail the same way. What was wrong is that it could not be
					// interrupted, so a cancelled install kept going for the
					// remainder of the interval while writing to disks.
					select {
					case <-ctx.Done():
						i.logger.Warn("[INSTALLER] cancelled while waiting to retry LUKS close", "error", ctx.Err())
						return ctx.Err()
					case <-time.After(time.Duration(attempt) * time.Second):
					}
					unix.Sync()
				}
			} else {
				i.logger.Info("[INSTALLER] LUKS device closed successfully", "name", mappedName)
				luksClosed = true
				break
			}
		}

		// If still not closed, try devmapper.Remove directly
		if !luksClosed {
			i.logger.Warn("[INSTALLER] LUKS close failed after 3 attempts, trying devmapper.Remove directly")
			// Sync first to flush dm-crypt buffers
			unix.Sync()

			if err := devmapper.Remove(mappedName); err != nil {
				i.logger.Warn("[INSTALLER] devmapper.Remove failed - DATA MAY NOT BE PERSISTED!", "device", mappedName, "error", err)
			} else {
				i.logger.Info("[INSTALLER] devmapper.Remove succeeded", "name", mappedName)
			}
		}
	}

	// Sync the backend device directly to ensure encrypted blocks are written
	if i.config.Disk.Device != "" {
		backendDev := fmt.Sprintf("%s2", i.config.Disk.Device) // Root partition
		if f, err := os.OpenFile(backendDev, os.O_RDWR|os.O_SYNC, 0); err == nil {
			if syncErr := f.Sync(); syncErr != nil {
				i.logger.Warn("[INSTALLER] Failed to sync backend device", "error", syncErr)
			}
			if closeErr := f.Close(); closeErr != nil {
				i.logger.Warn("[INSTALLER] Failed to close backend device", "error", closeErr)
			}
			i.logger.Info("[INSTALLER] Synced backend device", "device", backendDev)
		}
	}

	// Final sync to ensure all encrypted data is written to disk
	unix.Sync()
	unix.Sync()

	// DEBUG: Verify LUKS header magic is still intact after cleanup
	if i.config.Disk.Device != "" {
		backendDev := fmt.Sprintf("%s2", i.config.Disk.Device) // Root partition
		if f, err := os.Open(backendDev); err == nil {
			magic := make([]byte, 6)
			if _, err := f.Read(magic); err == nil {
				if string(magic[:4]) == "LUKS" && magic[4] == 0xba && magic[5] == 0xbe {
					i.logger.Info("[INSTALLER] DEBUG: LUKS header magic VALID after cleanup", "magic", fmt.Sprintf("%x", magic))
				} else {
					i.logger.Warn("[INSTALLER] DEBUG: LUKS header magic CORRUPTED!", "expected", "4c554b53babe", "got", fmt.Sprintf("%x", magic))
				}
			} else {
				i.logger.Warn("[INSTALLER] DEBUG: Failed to read LUKS header magic", "error", err)
			}
			if err := f.Close(); err != nil {
				i.logger.Warn("[INSTALLER] DEBUG: Failed to close backend device", "error", err)
			}
		} else {
			i.logger.Warn("[INSTALLER] DEBUG: Failed to open backend device", "device", backendDev, "error", err)
		}
	}

	i.logger.Info("[INSTALLER] Disk cleanup complete - data synced to disk")

	i.logger.Info("[INSTALLER] System installation completed successfully")
	return nil
}

// clearTPM resets the TPM to a clean state by sending the TPM2_Clear command
// via the lockout hierarchy with empty authorization. This removes all
// persistent keys, resets owner/endorsement/lockout auth to empty, and
// changes the storage primary seed so fresh keys can be provisioned against
// the current PCR values. On a first install this is a no-op (the TPM is
// already clear). On re-install this prevents PCR mismatch errors caused by
// stale TPM state from the previous installation.
func (i *installer) clearTPM() error {
	device := i.resolveTPMDevice()
	if device == "" {
		// Try loading TPM kernel modules as a safety net in case the ISO
		// environment didn't autoload them.
		i.loadTPMModules()
		device = i.resolveTPMDevice()
		if device == "" {
			return ErrTPM("no TPM device found after modprobe tpm_tis/tpm_crb", nil)
		}
	}

	i.logger.Info("[TPM] Clearing TPM state", "device", device)

	params := &xkmssdk.TPMParams{
		Config: &xkmssdk.TPMConfig{
			Device: device,
		},
	}

	tpm, err := xkmssdk.NewTPM2(params)
	if err != nil {
		return ErrTPM("failed to open TPM device", err)
	}
	defer tpm.Close()

	// Clear with empty lockout auth (default on fresh or previously-cleared TPM)
	if err := tpm.Clear(nil); err != nil {
		// DA lockout recovery: if LOCKOUT hierarchy refuses the clear
		// because of accumulated bad-auth counter from prior failed
		// provisioning runs, fall back to the UEFI Physical Presence
		// Interface. PPI-scheduled clears bypass DA lockout because
		// they're executed by firmware during POST with physical
		// presence asserted. The installer triggers a reboot after
		// scheduling so firmware services the clear on the next boot.
		if strings.Contains(err.Error(), "TPM_RC_LOCKOUT") {
			i.logger.Warn("[TPM] TPM2_Clear blocked by DA lockout; scheduling UEFI PPI ForceClear (reboot required)")
			if fcErr := tpm.ForceClear(); fcErr != nil {
				return ErrTPM("TPM2_Clear failed (lockout) and ForceClear via PPI also failed", fcErr)
			}
			i.logger.Info("[TPM] UEFI PPI ForceClear scheduled; issuing warm reset via SysRq-b so firmware services the clear at next POST")
			// Use the SysRq-based HardReset helper rather than
			// `reboot -f`. On Supermicro X10, the busybox reboot gets
			// translated into an ACPI S5 shutdown, which leaves the
			// system off and the PPI request unserviced until the next
			// manual power-on. SysRq-b forces the CPU reset vector
			// directly, skipping init/ACPI and guaranteeing a warm
			// reboot into POST where PPI is processed.
			HardReset()
			return ErrTPM("TPM2_Clear failed (lockout) — scheduled PPI ForceClear; reboot initiated", err)
		}
		return ErrTPM("TPM2_Clear failed", err)
	}

	i.logger.Info("[TPM] TPM2_Clear completed - all hierarchies reset")
	return nil
}

// tpmDeviceCandidates lists the TPM character devices, preferred first.
// Package variable so tests can override it to point at tmpdir fakes;
// production code never mutates this.
var tpmDeviceCandidates = []string{"/dev/tpmrm0", "/dev/tpm0"}

// resolveTPMDevice returns the preferred TPM character device if present.
// The resource-manager device /dev/tpmrm0 is preferred; /dev/tpm0 is the
// fallback for kernels without in-kernel RM support.
func (i *installer) resolveTPMDevice() string {
	for _, path := range tpmDeviceCandidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

// tpmModprobe runs modprobe for a single module; overridable for tests so
// unit tests never mutate the host's kernel module state.
var tpmModprobe = func(module string) (string, error) {
	cmd := exec.Command("modprobe", module)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// tpmDeviceWaitTimeout bounds how long loadTPMModules polls for a TPM
// character device to appear after modprobe. udev/mdev create the node
// asynchronously; a short poll loop is the deterministic alternative to a
// fixed Sleep. Exported via var so tests can shrink it.
var tpmDeviceWaitTimeout = 2 * time.Second

// loadTPMModules attempts to modprobe the standard TPM drivers so that
// /dev/tpm0 appears in environments (live ISO) that don't autoload them.
// Errors from modprobe are logged and ignored — the caller re-checks for
// the device. After modprobe we poll (not sleep) for up to
// tpmDeviceWaitTimeout so udev/mdev has time to create the node.
func (i *installer) loadTPMModules() {
	modules := []string{"tpm", "tpm_tis_core", "tpm_tis", "tpm_crb"}
	for _, m := range modules {
		out, err := tpmModprobe(m)
		if err != nil {
			i.logger.Debug("[TPM] modprobe failed", "module", m, "error", err, "output", out)
			continue
		}
		i.logger.Info("[TPM] loaded kernel module", "module", m)
	}
	// Poll for device node creation rather than sleeping a fixed interval.
	deadline := time.Now().Add(tpmDeviceWaitTimeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for time.Now().Before(deadline) {
		if i.resolveTPMDevice() != "" {
			return
		}
		<-ticker.C
	}
}

// setupDisk handles disk partitioning, LUKS encryption, and mounting
func (i *installer) setupDisk(ctx context.Context) (*DiskInfo, error) {
	i.logger.Info("[DISK] Setting up disk", "device", i.config.Disk.Device)

	// Create partition table
	if err := i.diskManager.CreatePartitionTable(ctx, i.config.Disk.PartitionTable); err != nil {
		return nil, ErrDiskOperation("failed to create partition table", err)
	}

	// Create EFI partition
	if err := i.diskManager.CreateEFIPartition(ctx, i.config.Disk.EFIPartitionSize); err != nil {
		return nil, ErrDiskOperation("failed to create EFI partition", err)
	}

	// Create root partition
	if err := i.diskManager.CreateRootPartition(ctx); err != nil {
		return nil, ErrDiskOperation("failed to create root partition", err)
	}

	// Setup LUKS encryption (if configured)
	var mappedDevice string
	var baseDevice string
	if i.config.Disk.Encryption != nil {
		device, err := i.diskManager.SetupLUKS(ctx, "", i.config.Disk.Encryption)
		if err != nil {
			return nil, ErrEncryption("failed to setup LUKS", err)
		}
		mappedDevice = device
		baseDevice = device
	} else {
		baseDevice = fmt.Sprintf("%s2", i.config.Disk.Device)
	}

	// Determine filesystem type (default to LVM if not specified)
	fsType := i.config.Disk.RootFilesystem
	if fsType == "" {
		fsType = FilesystemLVM
	}

	var rootDevice string
	var lvmVG, lvmLV, lvmDevice string

	// Setup filesystem based on type
	switch fsType {
	case FilesystemLVM:
		i.logger.Info("[DISK] Setting up LVM on", "device", baseDevice)

		// Create LVM Physical Volume
		if err := i.diskManager.CreateLVMPhysicalVolume(ctx, baseDevice); err != nil {
			return nil, ErrDiskOperation("failed to create LVM physical volume", err)
		}

		// Determine volume group name (default: vg0)
		lvmVG = i.config.Disk.LVMVolumeGroup
		if lvmVG == "" {
			lvmVG = "vg0"
		}

		// Create LVM Volume Group
		if err := i.diskManager.CreateLVMVolumeGroup(ctx, lvmVG, []string{baseDevice}); err != nil {
			return nil, ErrDiskOperation("failed to create LVM volume group", err)
		}

		// Determine logical volume name (default: root)
		lvmLV = i.config.Disk.LVMLogicalVolume
		if lvmLV == "" {
			lvmLV = "root"
		}

		// Create LVM Logical Volume using 100% of free space
		lvPath, err := i.diskManager.CreateLVMLogicalVolume(ctx, lvmVG, lvmLV, "100%FREE")
		if err != nil {
			return nil, ErrDiskOperation("failed to create LVM logical volume", err)
		}
		lvmDevice = lvPath
		rootDevice = lvPath

		// Format the LV as ext4
		i.logger.Info("[DISK] Formatting LVM logical volume", "device", rootDevice)
		if err := i.diskManager.FormatFilesystem(ctx, rootDevice, "ext4", "root"); err != nil {
			return nil, ErrDiskOperation("failed to format LVM logical volume", err)
		}

	case FilesystemExt4:
		i.logger.Info("[DISK] Setting up ext4 filesystem on", "device", baseDevice)
		rootDevice = baseDevice

		// Format root filesystem as ext4
		i.logger.Info("[DISK] Formatting root filesystem", "device", rootDevice)
		if err := i.diskManager.FormatFilesystem(ctx, rootDevice, "ext4", "root"); err != nil {
			return nil, ErrDiskOperation("failed to format root filesystem", err)
		}

	default:
		return nil, ErrInvalidConfig(fmt.Sprintf("unsupported filesystem type: %s", fsType))
	}

	// Mount root filesystem to /mnt
	mountPoint := "/mnt"
	i.logger.Info("[DISK] Mounting root filesystem", "device", rootDevice, "mountpoint", mountPoint)
	if err := i.diskManager.Mount(ctx, rootDevice, mountPoint, "ext4", 0); err != nil {
		return nil, ErrDiskOperation("failed to mount root filesystem", err)
	}

	// Mount EFI partition to /mnt/boot/efi (matching reference Alpine architecture)
	efiPartition := fmt.Sprintf("%s1", i.config.Disk.Device)
	efiMountPoint := fmt.Sprintf("%s/boot/efi", mountPoint)

	// Ensure EFI partition device node exists before mounting
	// (it may have disappeared when vda2 was created)
	if err := i.diskManager.EnsureDeviceNode(ctx, efiPartition, 10*time.Second); err != nil {
		return nil, ErrDiskOperation("EFI partition device node not available", err)
	}

	i.logger.Info("[DISK] Mounting EFI partition", "device", efiPartition, "mountpoint", efiMountPoint)
	if err := i.diskManager.Mount(ctx, efiPartition, efiMountPoint, "vfat", 0); err != nil {
		return nil, ErrDiskOperation("failed to mount EFI partition", err)
	}

	// Get LUKS UUID from volume if LUKS encryption is enabled
	var luksUUID string
	if mappedDevice != "" {
		// Get LUKS UUID using pure Go luks2 library
		rootPartition := fmt.Sprintf("%s2", i.config.Disk.Device)
		volumeInfo, err := luks2.GetVolumeInfo(rootPartition)
		if err == nil {
			luksUUID = volumeInfo.UUID
			i.logger.Debug("[DISK] Retrieved LUKS UUID for diskInfo", "uuid", luksUUID)
		} else {
			i.logger.Warn("[DISK] Failed to get LUKS UUID", "error", err)
		}
	}

	diskInfo := &DiskInfo{
		Device:           i.config.Disk.Device,
		EFIPartition:     efiPartition,
		RootPartition:    fmt.Sprintf("%s2", i.config.Disk.Device),
		MappedDevice:     mappedDevice,
		LUKSUUID:         luksUUID,
		PartitionTable:   i.config.Disk.PartitionTable,
		FilesystemType:   fsType,
		LVMVolumeGroup:   lvmVG,
		LVMLogicalVolume: lvmLV,
		LVMDevice:        lvmDevice,
	}

	return diskInfo, nil
}

// installOS handles OS installation
func (i *installer) installOS(ctx context.Context, diskInfo *DiskInfo) error {
	i.logger.Info("[OS] Installing base system", "os", i.config.OS.OS)

	// Mount root filesystem
	mountPoint := "/mnt"

	// Install base packages
	if err := i.osInstaller.InstallBase(ctx, mountPoint); err != nil {
		return ErrOSInstall("failed to install base system", err)
	}

	// Configure system files (fstab, crypttab, etc.)
	if err := i.osInstaller.ConfigureSystem(ctx, mountPoint, diskInfo); err != nil {
		return ErrOSInstall("failed to configure system", err)
	}

	// Install kernel and initramfs
	if err := i.osInstaller.InstallKernel(ctx, mountPoint); err != nil {
		return ErrOSInstall("failed to install kernel", err)
	}

	// Set root password. Config value is authoritative; default to
	// "password" only when the config doesn't specify one.
	rootPassword := i.config.OS.RootPassword
	if rootPassword == "" {
		rootPassword = "password"
		i.logger.Info("[INSTALLER] No root password in config, using default")
	}
	if err := i.osInstaller.SetRootPassword(ctx, mountPoint, rootPassword); err != nil {
		return ErrOSInstall("failed to set root password", err)
	}

	// Install additional packages from configuration BEFORE network config
	// This ensures packages can be installed while public DNS (8.8.8.8) is still configured
	// ConfigureNetwork may change resolv.conf to use local dnsmasq which isn't running during install
	if err := i.osInstaller.InstallPackages(ctx, mountPoint); err != nil {
		i.logger.Warn("[INSTALLER] Failed to install additional packages", "error", err)
		// Don't fail installation if package installation fails
	} else {
		i.logger.Info("[INSTALLER] Additional packages installed successfully")
	}

	// Install and configure SSH for debug mode (if enabled)
	// This must be done after package installation while DNS is still available
	if i.config.Debug {
		i.logger.Info("[INSTALLER] Debug mode enabled - installing SSH for remote access")
		if alpineInst, ok := i.osInstaller.(*alpineInstaller); ok {
			if err := alpineInst.InstallDebugSSH(ctx, mountPoint); err != nil {
				i.logger.Warn("[INSTALLER] Failed to install debug SSH", "error", err)
				// Don't fail installation if SSH setup fails
			} else {
				i.logger.Info("[INSTALLER] Debug SSH installed and configured (root login enabled)")
			}
		}
	}

	// Configure network (DNS, interfaces, bridges, bonds, VLANs)
	// This is done AFTER package installation so dnsmasq config doesn't break package fetching
	if i.config.Network != nil {
		if err := i.osInstaller.ConfigureNetwork(ctx, mountPoint, i.config.Network); err != nil {
			// Network configuration failure is not fatal - continue with installation
			i.logger.Warn("[OS] Failed to configure network", "error", err)
		} else {
			i.logger.Info("[OS] Network configuration complete")
		}
	}

	// Execute post-install scripts. A failure here is FATAL: the
	// post-install script typically provisions SSH keys, serial
	// console getty, sshd_config overrides, and other operator
	// access surfaces. Silently ignoring a failure ships a node
	// that looks "installed" but has no way for an operator to
	// reach it — exactly the state the 2026-04-08 lab-node-2 install
	// hit when an inline-script path bug caused the script to fail
	// with exit 2 and the installer logged a warning then continued
	// with an unreachable OS. If a deployment really wants to tolerate
	// post-install failures, the post-install script itself should
	// trap errors and exit 0 — the installer gives the operator no
	// way to distinguish "cosmetic tweak failed" from "operator
	// access never configured".
	if err := i.osInstaller.ExecutePostInstall(ctx, mountPoint); err != nil {
		i.logger.Error(err, "[INSTALLER] Post-install scripts failed")
		return &WrappedError{Msg: "post-install scripts failed", Err: err}
	}
	i.logger.Info("[INSTALLER] Post-install scripts executed successfully")

	return nil
}

// installFIPS handles FIPS component installation
// createFIPSInstaller creates the FIPS installer for the target OS
func (i *installer) createFIPSInstaller() (fips.Installer, error) {
	mountPoint := "/mnt"

	// Determine work directory (use /tmp if not specified)
	workDir := "/tmp/fips"
	if err := os.MkdirAll(workDir, 0755); err != nil {
		return nil, ErrOSInstall("failed to create FIPS work directory", err)
	}

	// Create FIPS installer based on OS
	fipsConfig := &fips.Config{
		OS:         string(i.config.OS.OS),
		Version:    i.config.OS.Version,
		Arch:       i.config.OS.Architecture,
		Mirror:     i.config.OS.Mirror,
		WorkDir:    workDir,
		MountPoint: mountPoint,
		Debug:      i.config.Debug,
		Logger:     slog.Default(),
	}

	return fips.NewInstaller(fipsConfig)
}

// resolveHardwareQuirk resolves the vendor-specific quirks for this host
// from the same identity the BMC clients use (Redfish System.Manufacturer /
// Model / PartNumber, carried on the installer Config), so the installed OS
// and the BMC side select the same registry entry. When no field is set the
// generic cross-vendor defaults are used (see pkg/quirks.Default).
func (i *installer) resolveHardwareQuirk() quirks.Quirk {
	hwQuirk := quirks.ResolveIdentity(i.config.OS.hardwareIdentity())
	i.logger.Info("[UKI] Resolved hardware quirks",
		"quirk", hwQuirk.Key,
		"manufacturer", i.config.HardwareManufacturer,
		"model", i.config.HardwareModel,
		"part_number", i.config.HardwarePartNumber,
		"sol_port", hwQuirk.SOLPort,
		"earlycon", hwQuirk.EarlyconSpec)
	return hwQuirk
}

// buildUKI handles UKI building using dracut
func (i *installer) buildUKI(ctx context.Context, diskInfo *DiskInfo) error {
	i.logger.Info("[UKI] Building Unified Kernel Image using dracut")

	mountPoint := "/mnt"

	// Detect kernel version from /mnt/lib/modules/
	modulesPath := filepath.Join(mountPoint, "lib", "modules")
	entries, err := os.ReadDir(modulesPath)
	if err != nil {
		return ErrUKIBuild("failed to read kernel modules directory", err)
	}

	if len(entries) == 0 {
		return ErrUKIBuild("no kernel modules found", nil)
	}

	kernelVersion := entries[0].Name()
	i.logger.Debug("[UKI] Detected kernel version", "version", kernelVersion)

	// Determine kernel path - prioritize FIPS kernel if FIPS mode is enabled
	var kernelPath string
	if i.config.OS != nil && i.config.OS.FIPS {
		// FIPS mode: use the FIPS-capable kernel
		kernelPath = filepath.Join(mountPoint, "boot", "vmlinuz-fips")
		if _, err := os.Stat(kernelPath); err != nil {
			return ErrUKIBuild("FIPS kernel not found (expected at /boot/vmlinuz-fips). FIPS mode is enabled but FIPS kernel was not installed.", err)
		}
		i.logger.Info("[UKI] Using FIPS-capable kernel", "path", kernelPath)
	} else {
		// Non-FIPS mode: use standard LTS kernel
		kernelPath = filepath.Join(mountPoint, "boot", fmt.Sprintf("vmlinuz-%s", kernelVersion))
		if _, err := os.Stat(kernelPath); err != nil {
			// Try alternate path
			kernelPath = filepath.Join(mountPoint, "boot", "vmlinuz-lts")
			if _, err := os.Stat(kernelPath); err != nil {
				return ErrUKIBuild(fmt.Sprintf("kernel not found: %s", kernelPath), err)
			}
		}
		i.logger.Debug("[UKI] Using kernel", "path", kernelPath)
	}

	// Build kernel command line
	var cmdlineParts []string

	// Add root device
	rootDevice := diskInfo.RootPartition
	if diskInfo.LVMDevice != "" {
		rootDevice = diskInfo.LVMDevice
	} else if diskInfo.MappedDevice != "" {
		rootDevice = diskInfo.MappedDevice
	}
	cmdlineParts = append(cmdlineParts, fmt.Sprintf("root=%s", rootDevice))

	// Add LUKS parameters if encryption is enabled
	if diskInfo.MappedDevice != "" {
		luksName := "cryptroot"
		if i.config.Disk != nil && i.config.Disk.Encryption != nil && i.config.Disk.Encryption.MappedName != "" {
			luksName = i.config.Disk.Encryption.MappedName
		}
		if diskInfo.LUKSUUID != "" {
			cmdlineParts = append(cmdlineParts,
				fmt.Sprintf("rd.luks.uuid=%s", diskInfo.LUKSUUID),
				fmt.Sprintf("rd.luks.name=%s=%s", diskInfo.LUKSUUID, luksName),
			)
		} else {
			i.logger.Warn("[UKI] LUKS UUID not available, using device path")
			cmdlineParts = append(cmdlineParts, fmt.Sprintf("rd.luks.name=%s", luksName))
		}
	}

	// Add LVM parameters if using LVM
	if diskInfo.LVMDevice != "" {
		cmdlineParts = append(cmdlineParts, "rd.lvm=1")
		if diskInfo.LVMVolumeGroup != "" {
			cmdlineParts = append(cmdlineParts, fmt.Sprintf("rd.lvm.vg=%s", diskInfo.LVMVolumeGroup))
		}
	}

	hwQuirk := i.resolveHardwareQuirk()

	// Add standard boot parameters
	cmdlineParts = append(cmdlineParts,
		"rootfstype=ext4",
		"ro",
	)
	// Append vendor-specific console/earlycon parameters from the quirk
	// table.  These cover SOL UART wiring, early console binding, and VGA
	// mirroring for the resolved hardware platform.
	cmdlineParts = append(cmdlineParts, hwQuirk.KernelCmdline...)

	// Add security parameters based on configuration
	if i.config.OS != nil {
		// Add kernel lockdown mode if enabled
		if i.config.OS.Lockdown {
			// Determine lockdown mode: integrity or confidentiality
			// - integrity: allows loading of signed modules, firmware
			// - confidentiality: prevents loading of any modules, firmware, kexec (strongest)
			lockdownMode := i.config.OS.LockdownMode
			if lockdownMode == "" {
				lockdownMode = "confidentiality" // Default to strongest mode
			}
			// Validate mode
			if lockdownMode != "integrity" && lockdownMode != "confidentiality" {
				i.logger.Warn("[UKI] Invalid lockdown mode, using confidentiality", "mode", lockdownMode)
				lockdownMode = "confidentiality"
			}
			cmdlineParts = append(cmdlineParts, fmt.Sprintf("lockdown=%s", lockdownMode))
			i.logger.Info("[UKI] Kernel lockdown enabled", "mode", lockdownMode)
		}

		// Add FIPS mode if enabled
		if i.config.OS.FIPS {
			cmdlineParts = append(cmdlineParts, "fips=1")
			i.logger.Info("[UKI] FIPS mode enabled")
		}

		// Add IMA (Integrity Measurement Architecture) parameters if enabled
		if i.config.OS.IMA != nil && i.config.OS.IMA.Enabled {
			// Enable IMA
			cmdlineParts = append(cmdlineParts, "ima=on")

			// Set IMA policy (tcb is the standard Trusted Computing Base policy)
			imaPolicy := i.config.OS.IMA.Policy
			if imaPolicy == "" {
				imaPolicy = "tcb"
			}
			cmdlineParts = append(cmdlineParts, fmt.Sprintf("ima_policy=%s", imaPolicy))

			// Set IMA hash algorithm
			imaHash := i.config.OS.IMA.HashAlgorithm
			if imaHash == "" {
				imaHash = "sha256"
			}
			cmdlineParts = append(cmdlineParts, fmt.Sprintf("ima_hash=%s", imaHash))

			// Enable IMA audit if configured
			if i.config.OS.IMA.AuditEnabled {
				cmdlineParts = append(cmdlineParts, "ima_audit=1")
			}

			// Set IMA appraisal mode if not "off"
			if i.config.OS.IMA.AppraiseMode != "" && i.config.OS.IMA.AppraiseMode != "off" {
				cmdlineParts = append(cmdlineParts, fmt.Sprintf("ima_appraise=%s", i.config.OS.IMA.AppraiseMode))
			}

			// Enable EVM if configured
			if i.config.OS.IMA.EVM {
				cmdlineParts = append(cmdlineParts, "evm=fix")
			}

			i.logger.Info("[UKI] IMA enabled", "policy", imaPolicy, "hash", imaHash)
		}
	}

	// In debug mode, propagate debug params from the installer's kernel
	// cmdline into the UKI cmdline so firstboot-log-upload and platformd
	// self-registration can reach the bootstrap server after disk reboot.
	if i.config.Debug {
		cmdlineParts = append(cmdlineParts, "platform_debug=1")
		// Read the bootstrap server address from the installer's live env cmdline
		if liveCmdline, readErr := os.ReadFile("/proc/cmdline"); readErr == nil {
			for _, param := range strings.Fields(string(liveCmdline)) {
				if strings.HasPrefix(param, "platform_debug_sink=") {
					cmdlineParts = append(cmdlineParts, param)
					i.logger.Info("[UKI] Propagating debug sink to UKI cmdline", "param", param)
				}
			}
		}
		i.logger.Info("[UKI] Debug mode: baked platform_debug params into UKI cmdline")
	}

	cmdline := strings.Join(cmdlineParts, " ")
	i.logger.Debug("[UKI] Kernel command line", "cmdline", cmdline)

	// Write kernel cmdline to /etc/kernel/cmdline in chroot
	// This is embedded in the initramfs by the platformd dracut module and parsed
	// by our cmdline hook as a fallback when getarg fails.
	kernelCmdlineDir := filepath.Join(mountPoint, "etc", "kernel")
	if err := os.MkdirAll(kernelCmdlineDir, 0755); err != nil {
		return ErrUKIBuild("failed to create /etc/kernel directory", err)
	}
	kernelCmdlinePath := filepath.Join(kernelCmdlineDir, "cmdline")
	if err := os.WriteFile(kernelCmdlinePath, []byte(cmdline+"\n"), 0644); err != nil {
		return ErrUKIBuild("failed to write /etc/kernel/cmdline", err)
	}
	i.logger.Info("[UKI] Wrote kernel cmdline to chroot", "path", kernelCmdlinePath, "cmdline", cmdline)

	// Write dracut.conf.d config to force kernel_cmdline in the UKI .cmdline section.
	// Alpine's dracut ignores the --kernel-cmdline CLI flag and falls back to
	// /proc/cmdline from the bind-mounted host, embedding the wrong root= UUID.
	// The kernel_cmdline conf variable cannot be ignored — dracut always reads it.
	dracutConfDir := filepath.Join(mountPoint, "etc", "dracut.conf.d")
	if err := os.MkdirAll(dracutConfDir, 0755); err != nil {
		return ErrUKIBuild("failed to create /etc/dracut.conf.d directory", err)
	}
	dracutConfPath := filepath.Join(dracutConfDir, "99-platformd-cmdline.conf")
	dracutConfContent := fmt.Sprintf("kernel_cmdline=%q\n", cmdline)
	if err := os.WriteFile(dracutConfPath, []byte(dracutConfContent), 0644); err != nil {
		return ErrUKIBuild("failed to write dracut.conf.d/99-platformd-cmdline.conf", err)
	}
	i.logger.Info("[UKI] Wrote dracut kernel_cmdline config", "path", dracutConfPath)

	// Create output directory for UKI at the UEFI spec removable media boot path.
	// \EFI\BOOT\BOOTX64.EFI is the standard path that ALL UEFI firmware discovers
	// automatically — works on VMs, bare metal, and removable media without needing
	// EFI Shell or efibootmgr.
	ukiDir := filepath.Join(mountPoint, "boot", "efi", "EFI", "BOOT")
	if err := os.MkdirAll(ukiDir, 0755); err != nil {
		return ErrUKIBuild("failed to create UKI directory", err)
	}

	ukiPath := filepath.Join(ukiDir, "BOOTX64.EFI")
	i.logger.Info("[UKI] Building UKI", "output", ukiPath)

	// Build UKI using two-step approach: dracut (initramfs) + objcopy (UKI assembly)
	// dracut must be run in chroot to use the target system's configuration
	i.logger.Info("[UKI] Running dracut in chroot to build initramfs")

	// Mount required filesystems for dracut to work in chroot
	i.logger.Debug("[UKI] Mounting /proc, /sys, /dev in chroot")

	// Create mount points
	mountDirs := []string{
		filepath.Join(mountPoint, "proc"),
		filepath.Join(mountPoint, "sys"),
		filepath.Join(mountPoint, "dev"),
	}

	for _, dir := range mountDirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return ErrUKIBuild(fmt.Sprintf("failed to create mount point %s", dir), err)
		}
	}

	// Load required kernel modules for dracut
	i.logger.Debug("[UKI] Loading kernel modules for dracut")
	modules := []string{"dm_mod", "dm_crypt"}
	for _, mod := range modules {
		modprobeCmd := exec.CommandContext(ctx, "modprobe", mod)
		if err := modprobeCmd.Run(); err != nil {
			i.logger.Warnf("[UKI] Failed to load module %s: %v (may already be loaded)", mod, err)
		}
	}

	// Mount filesystems (proc and sys need proper mounts, not bind mounts)
	mounts := []struct{ fstype, source, target, options string }{
		{"proc", "proc", filepath.Join(mountPoint, "proc"), ""},
		{"sysfs", "sysfs", filepath.Join(mountPoint, "sys"), ""},
		{"", "/dev", filepath.Join(mountPoint, "dev"), "bind"},
	}

	for _, m := range mounts {
		var mountCmd *exec.Cmd
		if m.options == "bind" {
			mountCmd = exec.CommandContext(ctx, "mount", "--bind", m.source, m.target)
		} else {
			mountCmd = exec.CommandContext(ctx, "mount", "-t", m.fstype, m.source, m.target)
		}
		if err := mountCmd.Run(); err != nil {
			i.logger.Warnf("[UKI] Failed to mount %s: %v", m.target, err)
		}
	}

	// Ensure umount happens even if dracut fails
	defer func() {
		// Unmount in reverse order
		for i := len(mounts) - 1; i >= 0; i-- {
			umountCmd := exec.Command("umount", mounts[i].target)
			_ = umountCmd.Run() // Ignore errors during cleanup
		}
	}()

	// Create symlinks for Alpine-specific binary paths
	// On Alpine, some binaries are in /bin instead of /usr/bin, but dracut
	// modules (like 95ima) expect them in /usr/bin.
	alpineSymlinks := []struct {
		src, dst string
	}{
		{"/bin/keyctl", filepath.Join(mountPoint, "usr", "bin", "keyctl")},
	}
	for _, link := range alpineSymlinks {
		srcInChroot := filepath.Join(mountPoint, link.src)
		if _, err := os.Stat(srcInChroot); err == nil {
			// Source exists in chroot, check if symlink destination exists
			if _, err := os.Lstat(link.dst); err != nil {
				// Destination doesn't exist, create symlink
				if err := os.Symlink(link.src, link.dst); err != nil {
					i.logger.Warnf("[UKI] Failed to create symlink %s -> %s: %v", link.dst, link.src, err)
				} else {
					i.logger.Debug("[UKI] Created symlink for Alpine compatibility", "symlink", link.dst, "target", link.src)
				}
			}
		}
	}

	// Step 1: Build initramfs with dracut (WITHOUT --uefi)
	// Alpine's dracut ignores --kernel-cmdline and kernel_cmdline conf when building
	// UKI, always reading /proc/cmdline from the bind-mounted host instead.
	// Solution: build initramfs separately, then assemble UKI manually with objcopy.
	initramfsPath := filepath.Join(mountPoint, "boot", fmt.Sprintf("initramfs-%s", kernelVersion))
	initramfsRelPath := strings.TrimPrefix(initramfsPath, mountPoint)

	dracutArgs := []string{
		"chroot", mountPoint,
		"dracut",
		"--force",
		"--no-hostonly",
		"--kver", kernelVersion,
		"--add", "platformd lvm dm",
		"--install", "modprobe insmod",
		"--add-drivers", "igb ixgbe e1000e i40e ice mlx5_core bnxt_en dm_mod dm_crypt vfat fat nls_cp437 nls_iso8859_1",
		"--omit", "crypt network network-legacy nbd nfs",
		// CRITICAL: dracut by default prepends an early-microcode cpio
		// archive (uncompressed AuthenticAMD.bin / GenuineIntel.bin) to
		// the main initramfs. The kernel decoder concatenates them at
		// boot time, but our injectPlatformInitrdIntoInitramfs step has
		// to extract / modify / repack the initramfs and the standard
		// `cat | cpio -idm` only consumes the FIRST archive (microcode),
		// missing the actual rootfs initramfs entirely. With
		// --no-early-microcode dracut produces a SINGLE-archive initramfs
		// our shell-based extract+repack pipeline can handle. The
		// downside is the CPU loads its microcode from disk later in
		// boot rather than during the EFI handover, which is fine for
		// our deployment because we're running production-built systems
		// where late microcode updates are acceptable.
		"--no-early-microcode",
		initramfsRelPath,
	}

	i.logger.Debug("[UKI] Dracut command (initramfs only)", "args", strings.Join(dracutArgs, " "))

	cmd := exec.CommandContext(ctx, dracutArgs[0], dracutArgs[1:]...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return ErrUKIBuild(fmt.Sprintf("dracut failed: %v", err), err)
	}

	// Verify initramfs was created
	initramfsInfo, err := os.Stat(initramfsPath)
	if err != nil {
		return ErrUKIBuild("initramfs not found after dracut", err)
	}
	if initramfsInfo.Size() == 0 {
		return ErrUKIBuild("dracut produced empty initramfs", nil)
	}
	i.logger.Info("[UKI] Initramfs built", "path", initramfsPath, "size", initramfsInfo.Size())

	// CRITICAL: Inject platform-initrd binary directly into the initramfs.
	// Dracut's inst_binary/inst_simple silently fails for statically linked Go binaries.
	// We work around this by appending a cpio archive containing platform-initrd
	// to the gzipped initramfs. The Linux kernel concatenates multiple cpio archives
	// during decompression, so this adds the binary without rebuilding the whole thing.
	if err := i.injectPlatformInitrdIntoInitramfs(ctx, mountPoint, initramfsPath); err != nil {
		return ErrUKIBuild("failed to inject platform-initrd into initramfs", err)
	}
	i.logger.Info("[UKI] platform-initrd injected into initramfs")

	// Build UKI as BOOTX64.EFI for direct UEFI boot
	i.logger.Info("[UKI] Assembling UKI with native PE builder (correct cmdline)")

	ukiConfig, err := uki.FromFiles(kernelPath, initramfsPath, cmdline)
	if err != nil {
		return ErrUKIBuild(fmt.Sprintf("failed to create UKI config: %v", err), err)
	}
	defer ukiConfig.Close()

	// Load the systemd-stub from the chroot — systemd-efistub is installed
	// in the target system, so the stub lives under mountPoint.
	stubPath := filepath.Join(mountPoint, uki.DefaultStubPath)
	stubFile, err := os.Open(stubPath)
	if err != nil {
		return ErrUKIBuild(fmt.Sprintf("failed to open EFI stub at %s (is systemd-efistub installed?)", stubPath), err)
	}
	ukiConfig.Stub = stubFile
	i.logger.Info("[UKI] Using systemd-stub as PE base", "path", stubPath)

	if i.config.OS != nil {
		ukiConfig.OSRelease = generateOSRelease(i.config.OS)
	}

	ukiBuilder := uki.NewBuilder(i.logger)
	if err := ukiBuilder.BuildFile(ukiConfig, ukiPath); err != nil {
		return ErrUKIBuild(fmt.Sprintf("native UKI builder failed: %v", err), err)
	}

	// Clean up the chroot initramfs (copies on EFI partition remain)
	os.Remove(initramfsPath)

	ukiInfo, err := os.Stat(ukiPath)
	if err != nil {
		return ErrUKIBuild("UKI file not found after build", err)
	}
	if ukiInfo.Size() == 0 {
		return ErrUKIBuild("UKI builder produced empty file", nil)
	}

	// CRITICAL: fsync the UKI file to ensure it's flushed to the physical disk.
	// FAT32 on real SATA SSDs with write-back cache can lose data if fsync is
	// not called before unmount. This is not an issue in QEMU with virtio.
	i.logger.Info("[UKI] Syncing UKI file to disk", "path", ukiPath, "size", ukiInfo.Size())
	ukiFile, err := os.OpenFile(ukiPath, os.O_RDONLY, 0)
	if err == nil {
		if syncErr := ukiFile.Sync(); syncErr != nil {
			i.logger.Warn("[UKI] fsync on UKI file failed", "error", syncErr)
		}
		ukiFile.Close()
	}

	// Also sync the parent directory to flush FAT32 directory entries
	ukiDirFile, err := os.Open(filepath.Dir(ukiPath))
	if err == nil {
		if syncErr := ukiDirFile.Sync(); syncErr != nil {
			i.logger.Warn("[UKI] fsync on UKI directory failed", "error", syncErr)
		}
		ukiDirFile.Close()
	}

	// Sync the entire EFI mount point
	unix.Sync()

	// Verify the file is readable and correct size after sync
	verifyInfo, err := os.Stat(ukiPath)
	if err != nil {
		return ErrUKIBuild("UKI file not found after sync", err)
	}
	if verifyInfo.Size() != ukiInfo.Size() {
		return ErrUKIBuild(fmt.Sprintf("UKI file size mismatch after sync: expected %d, got %d", ukiInfo.Size(), verifyInfo.Size()), nil)
	}

	i.logger.Info("[UKI] UKI built and synced successfully", "path", ukiPath, "size", ukiInfo.Size(), "cmdline", cmdline)
	return nil
}

// generateOSRelease creates an os-release string
func generateOSRelease(config *OSConfig) string {
	parts := []string{
		fmt.Sprintf("NAME=%q", config.OS),
		fmt.Sprintf("VERSION=%q", config.Version),
		fmt.Sprintf("ID=%s", config.OS),
		fmt.Sprintf("VERSION_ID=%q", config.Version),
		"PRETTY_NAME=\"Trusted Platform\"",
	}
	return strings.Join(parts, "\n") + "\n"
}

// signUKI signs the UKI with the Secure Boot DB key using native authenticode.
// It is a no-op unless Secure Boot is enabled in the config, so the Enabled flag
// governs both signing and (via enforceSecureBoot) enrollment. The DB key is
// resolved by resolveSecureBootSigner: keys pre-baked on the install media take
// priority (offline / virtual-media back-compat); otherwise the DB key is
// GENERATED on the node via the configured go-xkms backend so no private signing
// key is ever shipped over the network.
func (i *installer) signUKI(ctx context.Context, diskInfo *DiskInfo) error {
	if i.config.SecureBoot == nil || !i.config.SecureBoot.Enabled {
		i.logger.Info("[SECUREBOOT] Secure Boot disabled in config — skipping UKI signing")
		return nil
	}

	i.logger.Info("[SECUREBOOT] Signing UKI with native authenticode")

	mountPoint := "/mnt"

	signingKey, cert, err := i.resolveSecureBootSigner(ctx)
	if err != nil {
		// A UEFI system without Secure Boot enrollment still boots fine, so a
		// signing-material failure must not strand an otherwise-bootable
		// install — warn and continue rather than aborting the deploy.
		i.logger.Warn("[SECUREBOOT] No usable Secure Boot signing key — UKI will not be signed",
			"error", err)
		return nil
	}
	if signingKey == nil {
		i.logger.Warn("[SECUREBOOT] Secure Boot signing key unavailable — UKI will not be signed")
		return nil
	}

	// Create a simple keystore backend for signing
	signingBackend := &secureBootKeyBackend{
		privateKey: signingKey,
		logger:     i.logger,
	}

	// Create authenticode signer
	signer, err := authenticode.NewSigner(ctx, &authenticode.SignerOptions{
		KeyStore:      signingBackend,
		KeyAttributes: &xkmssdk.KeyAttributes{CN: "secure-boot"},
		Certificate:   cert,
		Logger:        i.logger,
	})
	if err != nil {
		return &WrappedError{Msg: "failed to create authenticode signer", Err: err}
	}

	// Path to UKI at the UEFI spec removable media boot path
	ukiPath := filepath.Join(mountPoint, "boot", "efi", "EFI", "BOOT", "BOOTX64.EFI")

	// Check if UKI exists
	if _, err := os.Stat(ukiPath); err != nil {
		i.logger.Warn("[SECUREBOOT] UKI not found, skipping signing", "path", ukiPath)
		return nil
	}

	// Sign in-place
	i.logger.Info("[SECUREBOOT] Signing UKI", "path", ukiPath)

	// Create temporary file for signed output
	signedPath := ukiPath + ".signed"
	if err := signer.SignFile(ukiPath, signedPath); err != nil {
		return &WrappedError{Msg: "failed to sign UKI", Err: err}
	}

	// Replace original with signed
	if err := os.Rename(signedPath, ukiPath); err != nil {
		if removeErr := os.Remove(signedPath); removeErr != nil {
			i.logger.Warn("[SECUREBOOT] failed to remove signed file", "error", removeErr)
		}
		return &WrappedError{Msg: "failed to replace UKI with signed version", Err: err}
	}

	i.logger.Info("[SECUREBOOT] UKI signed successfully with native authenticode")
	return nil
}

// enforceSecureBoot OPTIONALLY transitions the firmware into enforced UEFI
// Secure Boot, but only when it is provably safe. It is a no-op unless both
// secure-boot.enabled and secure-boot.enforce are set (enforce defaults to
// false). The enrollment order (db -> KEK -> PK LAST) plus a verify-before-
// enforce gate guarantee a failed or misconfigured enable can never strand the
// node: Secure Boot activates only when PK is written, and PK is written only
// after the signed UKI is confirmed to verify against the db certificate being
// enrolled. Foreseeable failures warn-and-skip (return nil); only an unexpected
// failure after every guard returns an error, which the caller logs without
// aborting the install.
func (i *installer) enforceSecureBoot(ctx context.Context, diskInfo *DiskInfo) error {
	if i.config.SecureBoot == nil || !i.config.SecureBoot.Enabled || !i.config.SecureBoot.Enforce {
		return nil
	}
	i.logger.Info("[SECUREBOOT] Enforcement requested — running verify-before-enforce gate")

	// Step 2: resolve the DB signer + certificate exactly as signUKI did. The
	// private key is needed only to build the Authenticode verifier; the
	// certificate is what gets enrolled into db and what the UKI must verify
	// against. Unavailable DB material is a warn-and-skip, never a failed install.
	signingKey, dbCert, err := i.resolveSecureBootSigner(ctx)
	if err != nil || signingKey == nil || dbCert == nil {
		i.logger.Warn("[SECUREBOOT] DB signing material unavailable — skipping Secure Boot enforcement", "error", err)
		return nil
	}

	// Step 3: BRICK GUARD. Build an Authenticode verifier from the resolved DB
	// key (the same keystore backend signUKI uses) and confirm the signed UKI
	// verifies against dbCert. If it does not, enrolling PK would produce a node
	// the firmware refuses to boot, so skip enforcement.
	verifier, err := authenticode.NewSigner(ctx, &authenticode.SignerOptions{
		KeyStore:      &secureBootKeyBackend{privateKey: signingKey, logger: i.logger},
		KeyAttributes: &xkmssdk.KeyAttributes{CN: "secure-boot"},
		Certificate:   dbCert,
		Logger:        i.logger,
	})
	if err != nil {
		i.logger.Warn("[SECUREBOOT] could not build UKI verifier — skipping Secure Boot enforcement", "error", err)
		return nil
	}
	ukiPath := filepath.Join(targetMountPoint, "boot", "efi", "EFI", "BOOT", "BOOTX64.EFI")
	if vErr := uefi.VerifySignedUKI(verifier, ukiPath, dbCert, i.logger); vErr != nil {
		i.logger.Warn("[SECUREBOOT] signed UKI did not verify; skipping Secure Boot enforcement to avoid an unbootable node",
			"uki", ukiPath, "error", vErr)
		return nil
	}

	// Step 4: keys can only be enrolled when efivarfs is mounted and the
	// firmware is in Setup Mode (no active PK). Otherwise warn-and-skip.
	if !uefi.EfivarsAvailable() {
		i.logger.Warn("[SECUREBOOT] efivarfs not present; cannot enroll Secure Boot keys " +
			"(operator must boot the target in UEFI mode and clear Secure Boot keys in firmware setup first)")
		return nil
	}
	setupMode, err := uefi.IsSetupMode()
	if err != nil {
		i.logger.Warn("[SECUREBOOT] could not read SetupMode; skipping Secure Boot enforcement", "error", err)
		return nil
	}
	if !setupMode {
		i.logger.Warn("[SECUREBOOT] firmware not in Setup Mode; cannot enroll Secure Boot keys " +
			"(operator must clear Secure Boot keys in firmware setup first)")
		return nil
	}

	// Step 5: resolve PK + KEK certificates and enroll db -> KEK -> PK (PK LAST).
	pkCert, kekCert, err := i.resolveSecureBootEnrollCerts()
	if err != nil {
		i.logger.Warn("[SECUREBOOT] could not resolve PK/KEK certificates; skipping Secure Boot enforcement", "error", err)
		return nil
	}
	if enrollErr := uefi.EnrollKeysToEfivars(ctx, pkCert, kekCert, dbCert, uefi.NewEFITime(time.Now())); enrollErr != nil {
		// This is after every foreseeable guard. Because PK is written LAST, a
		// db/KEK-only partial state never enforces Secure Boot, so the node still
		// boots. Surface the error loudly; the caller logs it without aborting.
		return ErrSecureBoot("enroll secure boot keys into efivars", enrollErr)
	}

	// Step 6: re-read and log the resulting firmware state.
	sbEnabled, sbErr := uefi.SecureBootEnabled()
	setupAfter, smErr := uefi.IsSetupMode()
	i.logger.Info("[SECUREBOOT] Secure Boot keys enrolled",
		"secure_boot_enabled", sbEnabled,
		"secure_boot_read_error", sbErr,
		"setup_mode", setupAfter,
		"setup_mode_read_error", smErr)
	return nil
}

// resolveSecureBootEnrollCerts resolves the PK and KEK certificates to enroll
// into firmware when enforcing Secure Boot. It mirrors resolveSecureBootSigner's
// precedence: a cert-uri file:// reference wins, otherwise the PK.crt / KEK.crt
// that XKMSManager.GenerateAll co-locates with the DB cert (on the install
// media, or in the on-node generated keys directory) is used.
func (i *installer) resolveSecureBootEnrollCerts() (*x509.Certificate, *x509.Certificate, error) {
	dir := i.secureBootKeysDir()
	pkCert, err := i.resolveEnrollCert(i.config.SecureBoot.PK.CertURI, dir, "PK.crt")
	if err != nil {
		return nil, nil, ErrSecureBoot("resolve PK certificate", err)
	}
	kekCert, err := i.resolveEnrollCert(i.config.SecureBoot.KEK.CertURI, dir, "KEK.crt")
	if err != nil {
		return nil, nil, ErrSecureBoot("resolve KEK certificate", err)
	}
	return pkCert, kekCert, nil
}

// resolveEnrollCert loads an X.509 certificate from a file:// cert-uri when one
// is configured, otherwise from dir/filename (where GenerateAll wrote it).
func (i *installer) resolveEnrollCert(certURI, dir, filename string) (*x509.Certificate, error) {
	if p := fileURIPath(certURI); p != "" {
		return parsePEMCertificate(p)
	}
	return parsePEMCertificate(filepath.Join(dir, filename))
}

// secureBootKeysDir returns the directory that holds the PK/KEK/DB certificates,
// mirroring resolveSecureBootSigner's precedence: install-media keys win,
// otherwise the on-node generated keys directory on the target root (/mnt).
func (i *installer) secureBootKeysDir() string {
	for _, isoMount := range []string{"/media/cdrom", "/media/usb", "/mnt/cdrom"} {
		d := filepath.Join(isoMount, "secure-boot-keys")
		if _, err := os.Stat(filepath.Join(d, "DB.crt")); err == nil {
			return d
		}
	}
	keysDir := "/etc/trusted-platform/secure-boot"
	if i.config.SecureBoot != nil && strings.HasPrefix(i.config.SecureBoot.DB.KeyURI, "file://") {
		keysDir = filepath.Dir(strings.TrimPrefix(i.config.SecureBoot.DB.KeyURI, "file://"))
	}
	return filepath.Join(targetMountPoint, keysDir)
}

// fileURIPath returns the filesystem path of a file:// URI (case-insensitive
// scheme), or "" if uri is not a file:// reference.
func fileURIPath(uri string) string {
	const scheme = "file://"
	if len(uri) >= len(scheme) && strings.EqualFold(uri[:len(scheme)], scheme) {
		return uri[len(scheme):]
	}
	return ""
}

// remoteSignerResolver constructs the remote Secure Boot DB signer + its
// public certificate for ResignMode=="remote" via KMS hash-signing (see
// secureboot.NewRemoteSigner). It is the install-time seam for branch (b) of
// resolveSecureBootSigner: at install the SDK client is normally absent so the
// installer's resolveRemoteSigner field is nil and the branch is skipped
// (Phase 2 EK-bootstrap delivers the key instead); the Phase 5a kernel-update
// path and tests populate it.
type remoteSignerResolver func(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.Signer, *x509.Certificate, error)

// resolveSecureBootSigner returns the DB signing key + certificate used to sign
// the UKI. It resolves the DB SecureBootKeyRef in a DETERMINISTIC, documented
// order — each branch is an explicit mode, NOT a silent fallback chain:
//
//	(a) DB.KeyURI is a file:// reference  -> read the PEM keypair locally
//	    (subsumes the legacy install-media loader, which now runs only as the
//	    back-compat path when DB.KeyURI is empty).
//	(b) ResignMode == "remote" AND a remote signer is constructible
//	    -> remote KMS hash-signing (see secureboot.NewRemoteSigner): the private
//	    key stays in the KMS and only the digest is round-tripped. At install the
//	    SDK client is normally absent (i.resolveRemoteSigner == nil) so this
//	    branch is skipped and Phase 2 EK-bootstrap delivers the key; the Phase 5a
//	    kernel-update path and tests populate the seam.
//	(c) otherwise (standalone / "local" / no URI) -> GENERATE the DB keypair on
//	    the node via the configured go-xkms backend. This is the legitimate
//	    standalone generator; the private key is created locally and never
//	    traverses the network.
//
// A file:// or remote branch that does not resolve warns and continues to the
// next mode rather than stranding an otherwise-bootable install.
func (i *installer) resolveSecureBootSigner(ctx context.Context) (crypto.PrivateKey, *x509.Certificate, error) {
	sb := i.config.SecureBoot

	// (a) Explicit file:// DB key URI; or, for back-compat only, keys pre-baked
	// on the install media when no DB.KeyURI is configured.
	if sb != nil && fileURIPath(sb.DB.KeyURI) != "" {
		if key, cert, err := i.loadFileURISecureBootKeys(); err != nil {
			i.logger.Warn("[SECUREBOOT] file:// DB key URI did not resolve — continuing", "key_uri", sb.DB.KeyURI, "error", err)
		} else if key != nil {
			i.logger.Info("[SECUREBOOT] Using Secure Boot DB keypair from file:// URI", "key_uri", sb.DB.KeyURI)
			return key, cert, nil
		}
	} else if sb == nil || sb.DB.KeyURI == "" {
		if key, cert := i.loadISOSecureBootKeys(); key != nil {
			i.logger.Info("[SECUREBOOT] Using Secure Boot keys from install media")
			return key, cert, nil
		}
	}

	// (b) Remote hash-signing: only when explicitly requested and the seam is
	// wired (an SDK client is reachable to construct the remote signer).
	if sb != nil && sb.ResignMode == SecureBootResignModeRemote {
		if i.resolveRemoteSigner == nil {
			i.logger.Info("[SECUREBOOT] resign-mode remote requested but no SDK client at install — deferring DB key to on-node generation (Phase 2 EK-bootstrap)")
		} else if attrs, err := sb.DB.ToKeyAttributes(); err != nil {
			i.logger.Warn("[SECUREBOOT] invalid DB key attributes for remote signing — continuing", "error", err)
		} else if signer, cert, err := i.resolveRemoteSigner(ctx, attrs); err != nil {
			i.logger.Warn("[SECUREBOOT] remote signer unavailable — continuing", "error", err)
		} else if signer != nil {
			i.logger.Info("[SECUREBOOT] Using remote KMS hash-signing for the Secure Boot DB key")
			return signer, cert, nil
		}
	}

	// (c) Standalone on-node generation (the legitimate standalone generator).
	return i.generateSecureBootKey(ctx)
}

// loadFileURISecureBootKeys reads the DB keypair referenced by a file:// DB
// KeyURI plus its companion certificate (the file:// CertURI, or the sibling
// DB.crt next to the key when CertURI is empty). It reuses parsePEMPrivateKey /
// parsePEMCertificate and returns a typed error on any failure so the caller
// can fall through to the next mode rather than aborting the deploy.
func (i *installer) loadFileURISecureBootKeys() (crypto.PrivateKey, *x509.Certificate, error) {
	// Shared with the Phase 5a kernel-update re-sign path (resolveRebuildSigner)
	// via loadFileURISecureBootSigner so both resolve file:// DB material identically.
	return loadFileURISecureBootSigner(i.config.SecureBoot)
}

// loadISOSecureBootKeys looks for a pre-baked DB key+cert on the install media
// (offline / virtual-media back-compat). Any read/decode/parse failure returns
// (nil, nil) so the caller falls through to on-node generation rather than
// hard-failing — a stale or malformed DB.key on the media must not abort the
// deploy.
func (i *installer) loadISOSecureBootKeys() (crypto.PrivateKey, *x509.Certificate) {
	var keyPath, certPath string
	for _, isoMount := range []string{"/media/cdrom", "/media/usb", "/mnt/cdrom"} {
		k := filepath.Join(isoMount, "secure-boot-keys", "DB.key")
		c := filepath.Join(isoMount, "secure-boot-keys", "DB.crt")
		if _, err := os.Stat(k); err != nil {
			continue
		}
		if _, err := os.Stat(c); err != nil {
			continue
		}
		keyPath, certPath = k, c
		break
	}
	if keyPath == "" {
		return nil, nil
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		i.logger.Warn("[SECUREBOOT] Failed to read install-media Secure Boot key", "path", keyPath, "error", err)
		return nil, nil
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		i.logger.Warn("[SECUREBOOT] Failed to decode install-media Secure Boot key PEM", "path", keyPath)
		return nil, nil
	}
	var privateKey crypto.PrivateKey
	if keyBlock.Type == "RSA PRIVATE KEY" {
		privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	} else {
		privateKey, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	}
	if err != nil {
		i.logger.Warn("[SECUREBOOT] Failed to parse install-media Secure Boot key", "path", keyPath, "type", keyBlock.Type, "error", err)
		return nil, nil
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		i.logger.Warn("[SECUREBOOT] Failed to read install-media Secure Boot cert", "path", certPath, "error", err)
		return nil, nil
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		i.logger.Warn("[SECUREBOOT] Failed to decode install-media Secure Boot cert PEM", "path", certPath)
		return nil, nil
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		i.logger.Warn("[SECUREBOOT] Failed to parse install-media Secure Boot cert", "path", certPath, "error", err)
		return nil, nil
	}
	return privateKey, cert
}

// generateSecureBootKey generates the Secure Boot DB keypair on the node via
// the configured go-xkms backend (default "software") and returns a signer +
// certificate. The keypair is written to the LUKS-encrypted target root (off
// the ESP) so it persists on the installed system and never leaves the node.
// Reuses the same secureboot.XKMSManager flow as build-time generation
// (pkg/cli/commands/iso/create.go:generateSecureBootKeys).
func (i *installer) generateSecureBootKey(ctx context.Context) (crypto.PrivateKey, *x509.Certificate, error) {
	const mountPoint = "/mnt"

	backend := "software"
	keysDir := "/etc/trusted-platform/secure-boot"
	// NOTE: on-node generation here is the local/file path; routing kms:// DB URIs through the SDK ResolverRegistry + remote ServiceKey hash-signing is the follow-up signing-consolidation step (secure-boot task #3, "3b").
	if i.config.SecureBoot != nil {
		if i.config.SecureBoot.DB.StoreType != "" {
			backend = i.config.SecureBoot.DB.StoreType
		}
		if strings.HasPrefix(i.config.SecureBoot.DB.KeyURI, "file://") {
			keysDir = filepath.Dir(strings.TrimPrefix(i.config.SecureBoot.DB.KeyURI, "file://"))
		}
	}
	// Generate onto the LUKS-encrypted target root so the private key persists
	// there (NOT the ESP) and never leaves the node.
	targetKeysDir := filepath.Join(mountPoint, keysDir)

	cn := "Trusted Platform Secure Boot DB"
	if i.config.OS.Hostname != "" {
		cn = cn + " - " + i.config.OS.Hostname
	}

	return generateSecureBootSigner(ctx, i.logger, backend, targetKeysDir, cn)
}

// generateSecureBootSigner generates (or reuses) the Secure Boot DB keypair in
// keysDir via the given go-xkms backend and returns a crypto.Signer + the DB
// certificate. keysDir is an absolute path on the target root. Factored out of
// generateSecureBootKey so it is unit-testable against a temp dir without
// touching /mnt. Mirrors pkg/cli/commands/iso/create.go:generateSecureBootKeys.
func generateSecureBootSigner(ctx context.Context, logger *logging.Logger, backend, keysDir, commonName string) (crypto.PrivateKey, *x509.Certificate, error) {
	km, err := secureboot.NewXKMSManager(&secureboot.XKMSConfig{
		KeysDir:      keysDir,
		Backend:      secureboot.BackendType(backend),
		CommonName:   commonName,
		Country:      "US",
		Organization: "Trusted Platform",
		KeySize:      2048,
		ValidYears:   10,
		ExportKeys:   true,
	}, logger)
	if err != nil {
		return nil, nil, ErrSecureBoot(fmt.Sprintf("init secure boot key manager (backend=%s)", backend), err)
	}
	defer func() {
		if cerr := km.Close(); cerr != nil {
			logger.Warn("[SECUREBOOT] failed to close key manager", "error", cerr)
		}
	}()

	if !km.KeysExist() {
		logger.Info("[SECUREBOOT] Generating Secure Boot DB key on node",
			"backend", backend, "keys_dir", keysDir)
		if err := km.GenerateAll(ctx); err != nil {
			return nil, nil, ErrSecureBoot("generate secure boot keys", err)
		}
		logger.Info("[SECUREBOOT] Generated Secure Boot DB key", "backend", backend)
	} else {
		logger.Info("[SECUREBOOT] Reusing existing Secure Boot DB key", "keys_dir", keysDir)
	}

	// Load the signer + cert from the EXPORTED PEM files (ExportKeys: true)
	// rather than km.GetSigner — the manager's lazy signer is backed by storage
	// that km.Close() tears down before the caller signs the UKI. The exported
	// DB.key is a standalone private key independent of the manager.
	paths := km.GetKeyPaths()
	privateKey, err := parsePEMPrivateKey(paths.DBKey)
	if err != nil {
		return nil, nil, ErrSecureBoot("read secure boot DB key", err)
	}
	cert, err := parsePEMCertificate(paths.DBCert)
	if err != nil {
		return nil, nil, ErrSecureBoot("read secure boot DB cert", err)
	}
	return privateKey, cert, nil
}

// ValidateSecureBootSigningPair verifies that keyPath and certPath hold
// exactly the material the installer's file:// signing path
// (loadFileURISecureBootSigner) will accept at install time: a parseable
// PEM private key, a parseable certificate, and matching public keys. The
// ISO build's staging gate calls this so a build can never succeed with
// signing material the target then rejects — a malformed or mismatched
// pair would otherwise surface only as a failed UKI sign or verify on the
// node (#50, round-11 review).
func ValidateSecureBootSigningPair(keyPath, certPath string) error {
	_, _, err := LoadSecureBootSigningPair(keyPath, certPath)
	return err
}

// LoadSecureBootSigningPair parses and validates the DB signing pair at
// keyPath/certPath and returns it ready for use.
//
// ValidateSecureBootSigningPair is this function with the values discarded,
// so a caller that needs the material and a caller that only needs the
// verdict cannot disagree about what "usable" means.
func LoadSecureBootSigningPair(keyPath, certPath string) (crypto.Signer, *x509.Certificate, error) {
	key, err := parsePEMPrivateKey(keyPath)
	if err != nil {
		return nil, nil, ErrSecureBoot("parse secure boot DB key", err)
	}
	cert, err := parsePEMCertificate(certPath)
	if err != nil {
		return nil, nil, ErrSecureBoot("parse secure boot DB cert", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, nil, ErrSecureBoot("secure boot DB key type", &MessageError{Msg: fmt.Sprintf("%T cannot sign", key)})
	}
	pub, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(cert.PublicKey) {
		return nil, nil, ErrSecureBoot("secure boot DB pair", &MessageError{
			Msg: "certificate public key does not match the private key"})
	}
	return signer, cert, nil
}

// NewSecureBootFileSigner returns an authenticode signer for the DB pair at
// keyPath/certPath, for callers that need to sign a PE binary on disk.
//
// The key parsing, the usability check and the KeyStore shim all live here so
// there is one implementation of "sign a PE with the platform's DB key" rather
// than one per package that needs it.
func NewSecureBootFileSigner(ctx context.Context, keyPath, certPath string, logger *logging.Logger) (authenticode.Authenticode, error) {
	signingKey, cert, err := LoadSecureBootSigningPair(keyPath, certPath)
	if err != nil {
		return nil, err
	}
	return authenticode.NewSigner(ctx, &authenticode.SignerOptions{
		KeyStore:      &secureBootKeyBackend{privateKey: signingKey, logger: logger},
		KeyAttributes: &xkmssdk.KeyAttributes{CN: "secure-boot"},
		Certificate:   cert,
		Logger:        logger,
	})
}

// parsePEMPrivateKey reads a PEM private key file (PKCS#1 or PKCS#8).
func parsePEMPrivateKey(path string) (crypto.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, &MessageError{Msg: fmt.Sprintf("failed to decode private key PEM at %s", path)}
	}
	if block.Type == "RSA PRIVATE KEY" {
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	return x509.ParsePKCS8PrivateKey(block.Bytes)
}

// parsePEMCertificate reads an X.509 certificate file, PEM or raw DER. The
// ISO build's enforcement gate stages any artifact that positively parses
// as certificate material (PEM or DER), so the installer must accept both —
// a DER PK/KEK cert that passed the build but failed here would make
// enforceSecureBoot warn-and-skip, shipping a node with enforce requested
// and no enforcement (#50, round-10 review).
func parsePEMCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(data); block != nil {
		return x509.ParseCertificate(block.Bytes)
	}
	cert, derErr := x509.ParseCertificate(data)
	if derErr != nil {
		return nil, &MessageError{Msg: fmt.Sprintf("failed to decode certificate (PEM or DER) at %s: %v", path, derErr)}
	}
	return cert, nil
}

// secureBootKeyBackend is a minimal Backend implementation for Secure Boot signing
type secureBootKeyBackend struct {
	privateKey crypto.PrivateKey
	logger     *logging.Logger
}

func (b *secureBootKeyBackend) Type() xkmssdk.BackendType {
	return "secure-boot"
}

func (b *secureBootKeyBackend) Capabilities() xkmssdk.Capabilities {
	return xkmssdk.Capabilities{
		Keys:           true,
		HardwareBacked: false,
		Signing:        true,
		Decryption:     false,
		KeyRotation:    false,
	}
}

func (b *secureBootKeyBackend) Signer(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.Signer, error) {
	signer, ok := b.privateKey.(crypto.Signer)
	if !ok {
		return nil, &MessageError{Msg: "private key does not implement crypto.Signer"}
	}
	return signer, nil
}

func (b *secureBootKeyBackend) GenerateKey(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, &MessageError{Msg: "not implemented"}
}

func (b *secureBootKeyBackend) GetKey(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.PrivateKey, error) {
	return b.privateKey, nil
}

func (b *secureBootKeyBackend) DeleteKey(ctx context.Context, attrs *xkmssdk.KeyAttributes) error {
	return &MessageError{Msg: "not implemented"}
}

func (b *secureBootKeyBackend) ListKeys(ctx context.Context) ([]*xkmssdk.KeyAttributes, error) {
	return nil, nil
}

func (b *secureBootKeyBackend) Decrypter(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.Decrypter, error) {
	return nil, &MessageError{Msg: "not implemented"}
}

func (b *secureBootKeyBackend) RotateKey(ctx context.Context, attrs *xkmssdk.KeyAttributes) error {
	return &MessageError{Msg: "not implemented"}
}

func (b *secureBootKeyBackend) Close() error {
	return nil
}

// InstallerPassword is a well-known password for the installer container.
// This provides forensic protection (encrypted data defeats recovery from SSD spare blocks)
// but is not intended as access control since the install environment is trusted.
// IMPORTANT: This constant is used across multiple packages:
//   - pkg/installer/installer.go (creating installer.luks)
//   - pkg/initrd/firstboot.go (unlocking installer.luks)
//   - pkg/initrd/strategy_firstboot_seal.go (unlocking installer.luks)
//   - pkg/cmd/initrd/boot.go (unlocking installer.luks)
//   - pkg/iso/customize.go (generating dracut unlock script)
//
// configureUEFIBoot creates a UEFI boot entry and startup.nsh fallback
// so the firmware can find the UKI on the ESP. It also writes the
// TRUSTED_PLATFORM=1 custom EFI variable that marks this ESP as having
// been provisioned by go-trusted-platform.
//
// go-trusted-platform is UEFI-only by policy — see the comment on
// pkg/iso/build.go runXorriso. If /sys/firmware/efi/efivars is not
// mounted (i.e. the installer is running in a legacy-BIOS-booted live
// environment) this function RETURNS AN ERROR rather than silently
// continuing with only a fallback path. An installed system without a
// UEFI boot entry is a broken system and the installer must refuse to
// mark such an install as successful.
func (i *installer) configureUEFIBoot(ctx context.Context, diskInfo *DiskInfo) error {
	i.logger.Info("[UEFI] Configuring UEFI boot entry")

	mountPoint := "/mnt"
	espDir := filepath.Join(mountPoint, "boot", "efi")

	// Read kernel cmdline from /etc/kernel/cmdline (written by buildUKI step)
	kernelCmdlinePath := filepath.Join(mountPoint, "etc", "kernel", "cmdline")
	cmdlineBytes, err := os.ReadFile(kernelCmdlinePath)
	if err != nil {
		i.logger.Warnf("[UEFI] Failed to read kernel cmdline: %v, startup.nsh will have no arguments", err)
		cmdlineBytes = nil
	}
	cmdline := strings.TrimSpace(string(cmdlineBytes))

	// Write startup.nsh as a fallback for systems with EFI Shell.
	// Points to the standard UEFI removable media path where the UKI lives.
	startupPath := filepath.Join(espDir, "startup.nsh")
	var startupContent string
	if cmdline != "" {
		startupContent = fmt.Sprintf("\\EFI\\BOOT\\BOOTX64.EFI %s\n", cmdline)
	} else {
		startupContent = "\\EFI\\BOOT\\BOOTX64.EFI\n"
	}

	if err := os.WriteFile(startupPath, []byte(startupContent), 0644); err != nil {
		i.logger.Warnf("[UEFI] Failed to write startup.nsh: %v", err)
	} else {
		i.logger.Info("[UEFI] Wrote startup.nsh fallback to ESP")
	}

	// Write the Trusted Platform provisioning sentinel to the ESP.
	// This is a plain file marker that ALWAYS ships as a first-class
	// part of the install, regardless of whether efivarfs is available.
	// It's how operators, recovery tools, and platformd itself can
	// answer "was this disk provisioned by go-trusted-platform?" by
	// inspecting the ESP without needing to boot the full OS or trust
	// any runtime state. Reading back the Trusted Platform EFI
	// variable gives the same answer cryptographically via firmware;
	// this sentinel is the file-system equivalent.
	sentinelDir := filepath.Join(espDir, "EFI", "TRUSTED_PLATFORM")
	if err := os.MkdirAll(sentinelDir, 0755); err != nil {
		return &WrappedError{Msg: "create TRUSTED_PLATFORM sentinel dir", Err: err}
	}
	sentinelPath := filepath.Join(sentinelDir, "PROVISIONED")
	sentinel := "TRUSTED_PLATFORM=1\n"
	if err := os.WriteFile(sentinelPath, []byte(sentinel), 0644); err != nil {
		return &WrappedError{Msg: "write TRUSTED_PLATFORM sentinel", Err: err}
	}
	i.logger.Info("[UEFI] Wrote TRUSTED_PLATFORM sentinel to ESP", "path", sentinelPath)

	// UEFI-only policy: the EFI runtime services directory MUST exist,
	// which proves the kernel was loaded by UEFI firmware (not Legacy/CSM).
	if _, err := os.Stat("/sys/firmware/efi"); err != nil {
		return &WrappedError{Msg: "[UEFI] /sys/firmware/efi not present: " +
			"the Trusted Platform installer is UEFI-only; ensure the target " +
			"firmware is set to UEFI boot (not Legacy/CSM) and that the " +
			"installer ISO was booted via its EFI bootloader", Err: err}
	}

	// Ensure efivarfs is mounted. The Alpine live environment may not
	// auto-mount it even when booted via UEFI. Without efivarfs,
	// efibootmgr cannot create NVRAM boot entries and the firmware
	// won't find the installed UKI on reboot.
	efiVarsDir := "/sys/firmware/efi/efivars"
	if _, statErr := os.Stat(efiVarsDir); statErr != nil {
		if mkErr := os.MkdirAll(efiVarsDir, 0755); mkErr != nil {
			i.logger.Warnf("[UEFI] Failed to create efivars mountpoint: %v", mkErr)
		}
	}
	// Try mounting efivarfs — harmless if already mounted.
	mountCmd := exec.CommandContext(ctx, "mount", "-t", "efivarfs", "efivarfs", efiVarsDir)
	if mountOut, mountErr := mountCmd.CombinedOutput(); mountErr != nil {
		i.logger.Warnf("[UEFI] Failed to mount efivarfs at %s: %v (%s)", efiVarsDir, mountErr, string(mountOut))
	} else {
		i.logger.Info("[UEFI] Mounted efivarfs", "path", efiVarsDir)
	}

	// Install efibootmgr if not available. --allow-untrusted is required
	// because the offline prefetch repo's APKINDEX is unsigned (the package
	// files themselves are byte-identical to the official Alpine mirror,
	// but apk has no key for our locally-regenerated index). Without this
	// flag apk silently treats prefetched packages as unselectable, which
	// surfaces as `efibootmgr (no such package)` even when the .apk file
	// is sitting in /media/cdrom/apks-prefetch/.
	efibootmgrPath, err := exec.LookPath("efibootmgr")
	if err != nil {
		i.logger.Info("[UEFI] Installing efibootmgr...")
		installCmd := exec.CommandContext(ctx, "apk", "add", "--no-cache",
			"--allow-untrusted", "efibootmgr")
		installCmd.Stdout = os.Stderr
		installCmd.Stderr = os.Stderr
		if err := installCmd.Run(); err != nil {
			return &WrappedError{Msg: "[UEFI] failed to install efibootmgr", Err: err}
		}
		efibootmgrPath, _ = exec.LookPath("efibootmgr")
	}
	if efibootmgrPath == "" {
		return &MessageError{Msg: "[UEFI] efibootmgr binary not found after install"}
	}

	// Delete stale boot entries from prior installs. On re-installs,
	// old "Trusted Platform" entries point to GRUB (from the ISO's
	// efi.img El Torito boot image) instead of the UKI. If these
	// stale entries remain in the BootOrder, the firmware loads GRUB
	// (which fails with "blind mode") instead of the UKI.
	i.logger.Info("[UEFI] Cleaning stale boot entries")
	listCmd := exec.CommandContext(ctx, efibootmgrPath)
	listOut, listErr := listCmd.Output()
	if listErr == nil {
		for _, line := range strings.Split(string(listOut), "\n") {
			// Match lines like "Boot0000* Trusted Platform" or "Boot0004* Trusted Platform"
			if strings.Contains(line, "Trusted Platform") && strings.HasPrefix(strings.TrimSpace(line), "Boot") {
				// Extract boot number: "Boot0000*" → "0000"
				parts := strings.Fields(strings.TrimSpace(line))
				if len(parts) >= 1 {
					bootID := strings.TrimPrefix(parts[0], "Boot")
					bootID = strings.TrimSuffix(bootID, "*")
					bootID = strings.TrimSuffix(bootID, " ")
					if len(bootID) == 4 {
						i.logger.Info("[UEFI] Deleting stale boot entry", "id", bootID, "label", "Trusted Platform")
						delCmd := exec.CommandContext(ctx, efibootmgrPath, "--delete-bootnum", "--bootnum", bootID)
						if delOut, delErr := delCmd.CombinedOutput(); delErr != nil {
							i.logger.Warnf("[UEFI] Failed to delete Boot%s: %v (%s)", bootID, delErr, string(delOut))
						}
					}
				}
			}
		}
	} else {
		i.logger.Warnf("[UEFI] Failed to list boot entries: %v", listErr)
	}

	// Create a `Trusted Platform` UEFI NVRAM entry pointing at the UKI
	// at /EFI/BOOT/BOOTX64.EFI on the ESP. This is necessary on platforms
	// whose firmware does NOT implement the UEFI removable-media fallback
	// correctly — notably Supermicro X10SDV-class boards, where the
	// default boot order is `PXE → HDD/efi/boot/bootx64.efi`. PXE always
	// fails (`PXE-E79: NBP is too big to fit in free base memory`) and
	// the firmware halts at "Reboot and Select proper Boot device"
	// instead of falling through to the disk ESP. With an explicit
	// NVRAM entry the firmware respects it ahead of PXE.
	//
	// Re-installs are still safe: the BMC's
	// `BootSourceOverrideTarget=Cd / BootSourceOverrideEnabled=Once|Continuous`
	// is consumed by firmware BEFORE the NVRAM BootOrder, so the virtual
	// CD wins on bootstrap-orchestrator runs.
	if diskInfo != nil && diskInfo.Device != "" {
		espDevice := diskInfo.Device + "1"
		espPart := "1"
		i.logger.Info("[UEFI] Creating NVRAM boot entry",
			"label", "Trusted Platform", "disk", diskInfo.Device,
			"part", espPart, "loader", "\\EFI\\BOOT\\BOOTX64.EFI")
		createCmd := exec.CommandContext(ctx, efibootmgrPath,
			"--create",
			"--disk", diskInfo.Device,
			"--part", espPart,
			"--label", "Trusted Platform",
			"--loader", `\EFI\BOOT\BOOTX64.EFI`)
		// Discard the verbose efibootmgr output (full BootOrder with
		// PCI device paths can contain bytes that confuse log encoders
		// and have caused silent process exits in earlier runs). The
		// presence/absence of the new entry is verified by listing
		// boot entries downstream.
		createCmd.Stdout = io.Discard
		createCmd.Stderr = io.Discard
		if createErr := createCmd.Run(); createErr != nil {
			i.logger.Warnf("[UEFI] efibootmgr --create failed (continuing with fallback path): %v",
				createErr)
		} else {
			i.logger.Info("[UEFI] NVRAM boot entry registered",
				"esp_device", espDevice, "label", "Trusted Platform")
		}
	} else {
		i.logger.Warn("[UEFI] No disk info available, skipping NVRAM entry creation")
	}

	// Write the TRUSTED_PLATFORM=1 custom EFI variable.
	//
	// GUID is a custom namespace unique to go-trusted-platform:
	//   7a7c0000-7fa1-4db5-9f4e-74757374706c (fictional but stable).
	// Format: efivarfs binary path
	//   /sys/firmware/efi/efivars/TRUSTED_PLATFORM-<guid>
	// Content: 4 bytes of EFI attributes + variable data.
	// Attributes: NonVolatile(0x01) | BootServiceAccess(0x02) |
	//             RuntimeAccess(0x04) = 0x07
	//
	// The EFI variable is a second, independent signal alongside the
	// on-disk sentinel file. An attacker swapping the ESP cannot
	// forge it without access to the firmware NVRAM; firmware that
	// doesn't support NVRAM writes will refuse gracefully.
	if err := writeTrustedPlatformEFIVar(); err != nil {
		return &WrappedError{Msg: "[UEFI] writing TRUSTED_PLATFORM EFI variable", Err: err}
	}
	i.logger.Info("[UEFI] Wrote TRUSTED_PLATFORM EFI variable")

	return nil
}

// trustedPlatformEFIVarName is the name of the custom EFI variable
// go-trusted-platform writes on every successful install. Operators
// and platformd can read this back to verify a given target was
// provisioned by this project.
const trustedPlatformEFIVarName = "TRUSTED_PLATFORM"

// trustedPlatformEFIVarGUID is the GUID for the variable's vendor
// namespace. Chosen at random and stable across all installs so the
// variable path in efivarfs is deterministic:
//
//	/sys/firmware/efi/efivars/TRUSTED_PLATFORM-7a7c0000-7fa1-4db5-9f4e-74757374706c
const trustedPlatformEFIVarGUID = "7a7c0000-7fa1-4db5-9f4e-74757374706c"

// writeTrustedPlatformEFIVar writes the TRUSTED_PLATFORM=1 custom EFI
// variable via the efivarfs binary interface. The variable is
// NonVolatile + BootServiceAccess + RuntimeAccess so it persists
// across reboots AND is readable at both UEFI boot time and from
// userspace at runtime.
//
// efivarfs format: the file content is [4 bytes attributes (little-
// endian)] + [variable data]. We make the variable file writable,
// rewrite it, then drop write bits again. On some firmware the
// variable creation triggers a SetVariable runtime-service call that
// can fail (read-only NVRAM, secure-variable auth required, etc.);
// in that case the error bubbles up to the caller.
func writeTrustedPlatformEFIVar() error {
	varPath := fmt.Sprintf("/sys/firmware/efi/efivars/%s-%s",
		trustedPlatformEFIVarName, trustedPlatformEFIVarGUID)

	// NonVolatile(0x01) | BootServiceAccess(0x02) | RuntimeAccess(0x04)
	const attrs uint32 = 0x07

	body := []byte("1")
	buf := make([]byte, 4+len(body))
	buf[0] = byte(attrs)
	buf[1] = byte(attrs >> 8)
	buf[2] = byte(attrs >> 16)
	buf[3] = byte(attrs >> 24)
	copy(buf[4:], body)

	// If the variable already exists from a prior install, the file
	// is immutable by default on efivarfs — clear the immutable bit
	// with chattr before overwriting. Best-effort; if chattr is
	// missing, try the write anyway and let the error speak.
	_ = exec.Command("chattr", "-i", varPath).Run()

	if err := os.WriteFile(varPath, buf, 0644); err != nil {
		return err
	}
	// Reassert immutable bit so nothing accidentally clobbers it.
	_ = exec.Command("chattr", "+i", varPath).Run()
	return nil
}

const InstallerPassword = "forensic-protection-only"

// prepareLUKSKeyForTPM prepares LUKS keys and creates an encrypted installer container
//
// SECURITY MODEL:
//   - LUKS key and recovery key are NEVER written as plaintext to unencrypted storage
//   - Keys are stored in an encrypted LUKS container (installer.luks, 100MB) on EFI partition
//   - The installer uses a well-known password for forensic protection, not access control
//   - On firstboot, initramfs provisions platform INSIDE the container, seals keys to TPM, then wipes
//
// This protects against forensic recovery of wiped data from SSD spare blocks.
// NOTE: EFI partition must be at least 200MB to accommodate the installer container.
func (i *installer) prepareLUKSKeyForTPM(ctx context.Context, diskInfo *DiskInfo) error {
	i.logger.Info("[TPM] Preparing encrypted installer container for TPM sealing on first boot")

	if i.config.Disk.Encryption == nil {
		return &MessageError{Msg: "encryption not configured"}
	}

	// Get LUKS passphrase (needed to add keys to keyslots)
	passphrase := i.config.Disk.Encryption.Passphrase
	if passphrase == "" {
		passphrase = i.config.Disk.Encryption.Password
	}
	if passphrase == "" {
		return &MessageError{Msg: "LUKS passphrase not configured"}
	}

	// Generate random 32-byte LUKS key
	i.logger.Info("[TPM] Generating random 32-byte LUKS key")
	luksKey := make([]byte, 32)
	if _, err := rand.Read(luksKey); err != nil {
		return &WrappedError{Msg: "failed to generate LUKS key", Err: err}
	}
	defer clearBytes(luksKey)

	// DEBUG: Log key hash for verification against firstboot
	keyHash := sha256.Sum256(luksKey)
	i.logger.Info("[TPM] DEBUG: LUKS key hash (first 8 bytes)", "hash", fmt.Sprintf("%x", keyHash[:8]))

	// Generate recovery key (dashed hex format)
	i.logger.Info("[TPM] Generating recovery key")
	recoveryKey := generateRecoveryKey()

	keyslot1 := 1
	addKeyOpts := &luks2.AddKeyOptions{
		Keyslot: &keyslot1,
		KDFType: "pbkdf2", // Use PBKDF2 during install to avoid OOM in low-memory environments
		Hash:    "sha256",
	}

	// Add LUKS key as keyslot 1 using pure Go luks2 library
	i.logger.Info("[TPM] Adding LUKS key as keyslot 1", "device", diskInfo.RootPartition)
	if err := luks2.AddKey(diskInfo.RootPartition, []byte(passphrase), luksKey, addKeyOpts); err != nil {
		return &WrappedError{Msg: "failed to add LUKS key", Err: err}
	}
	i.logger.Info("[TPM] LUKS key added as keyslot 1")

	// Add recovery key as keyslot 2 using pure Go luks2 library
	i.logger.Info("[TPM] Adding recovery key as keyslot 2")
	keyslot2 := 2
	recoveryKeyOpts := &luks2.AddKeyOptions{
		Keyslot: &keyslot2,
		KDFType: "pbkdf2", // Use PBKDF2 during install to avoid OOM
		Hash:    "sha256",
	}
	if err := luks2.AddKey(diskInfo.RootPartition, []byte(passphrase), []byte(recoveryKey), recoveryKeyOpts); err != nil {
		return &WrappedError{Msg: "failed to add recovery key", Err: err}
	}
	i.logger.Info("[TPM] Recovery key added as keyslot 2")

	// Find platform config from ISO - REQUIRED for firstboot
	configData, err := i.findPlatformConfig()
	if err != nil {
		return &WrappedError{Msg: "[TPM] FATAL: platform config not found on ISO - firstboot will fail without config. " +
			"Ensure the ISO was built with a platform config file at /configs/installer.yaml", Err: err}
	}

	// Create encrypted installer container on EFI partition
	efiDir := "/mnt/boot/efi/tpm2"
	if err := os.MkdirAll(efiDir, 0700); err != nil {
		return &WrappedError{Msg: "failed to create /boot/efi/tpm2 directory", Err: err}
	}

	// Write network config to EFI partition for firstboot networking
	// This file is outside installer.luks so it's accessible during early boot
	if err := i.writeFirstbootNetworkConfig(efiDir); err != nil {
		i.logger.Warn("[TPM] Failed to write firstboot network config; the initramfs falls back to DHCP and the firstboot hostname is not set", "error", err)
	}

	// Write a minimal pcr-banks file to EFI at install time so the dracut
	// unlock hook can pass --pcrs to platform-initrd on the very first
	// boot — before firstboot writes the full pcr-banks. Without this,
	// platform-initrd falls through to searching config.yaml inside
	// installer.luks, which is unreachable if the EFI mount itself
	// failed. firstboot will overwrite this file with the authoritative
	// values (platform-pcr, keystore-srk-handle, etc) after provisioning.
	if err := i.writeInitialPCRBanks(efiDir); err != nil {
		i.logger.Warn("[TPM] Failed to write initial pcr-banks file", "error", err)
	}

	installerPath := filepath.Join(efiDir, "installer.luks")
	if err := i.createInstallerContainer(ctx, installerPath, luksKey, recoveryKey, configData); err != nil {
		return &WrappedError{Msg: "failed to create installer container", Err: err}
	}

	i.logger.Info("[TPM] Encrypted installer container created", "path", installerPath)
	i.logger.Info("[TPM] On first boot, initramfs will provision platform inside container, seal to TPM, and wipe")

	return nil
}

// generateRecoveryKey generates a recovery key in dashed hex format (XXXX-XXXX-...)
func generateRecoveryKey() string {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(fmt.Sprintf("failed to generate random key: %v", err))
	}

	hexStr := strings.ToUpper(fmt.Sprintf("%x", key))
	var parts []string
	for j := 0; j < len(hexStr); j += 4 {
		end := j + 4
		if end > len(hexStr) {
			end = len(hexStr)
		}
		parts = append(parts, hexStr[j:end])
	}
	return strings.Join(parts, "-")
}

// findPlatformConfig searches for the platform config file on the ISO
// IMPORTANT: Config MUST have seal-pcrs at root level for LUKS TPM sealing
func (i *installer) findPlatformConfig() ([]byte, error) {
	// Priority 1: dynamically-fetched merged config written by autoinstall.sh
	// (customize.go Priority 1). This carries the orchestrator-published
	// template+overrides merge, including per-node `debug:`, `domain:`,
	// and static IP fields. Without this path the installer falls back to
	// the ISO-baked default (single-node/default.yaml), which has
	// debug:false and a generic hostname — wiping out the override file
	// contents the operator put in bootstrap.yaml.
	//
	// See docs/bootstrap/config-delivery.md §3 (dynamic mode) and
	// docs/installer/autoinstall.md for the fetch flow that writes
	// /tmp/platform-config.yaml.
	for _, dynPath := range []string{"/tmp/platform-config.yaml"} {
		if data, err := os.ReadFile(dynPath); err == nil {
			i.logger.Info("[TPM] Found platform config (dynamic fetch)", "path", dynPath, "size", len(data))
			if !bytes.Contains(data, []byte("seal-pcrs:")) {
				i.logger.Warn("[TPM] Dynamic config missing seal-pcrs, falling back to baked",
					"path", dynPath)
			} else {
				i.logger.Info("[TPM] Config validated - has seal-pcrs", "path", dynPath)
				return data, nil
			}
		}
	}

	// Priority 2: ISO-baked config. Used when --config-server was not
	// specified at iso create time, or when dynamic fetch failed.
	for _, isoMount := range []string{"/media/cdrom", "/media/usb", "/mnt/cdrom"} {
		for _, configName := range []string{
			"installer.yaml",
			"platformd.yaml",
			"platform.yaml",
			"config.yaml",
		} {
			testPath := filepath.Join(isoMount, "configs", configName)
			if data, err := os.ReadFile(testPath); err == nil {
				i.logger.Info("[TPM] Found platform config (baked)", "path", testPath, "size", len(data))

				// Validate config has seal-pcrs before returning
				if !bytes.Contains(data, []byte("seal-pcrs:")) {
					i.logger.Warn("[TPM] Config found but missing seal-pcrs",
						"path", testPath,
						"HINT", "Config MUST have 'seal-pcrs: [7, 9]' at root level for TPM sealing")
					continue // Try next config file
				}

				i.logger.Info("[TPM] Config validated - has seal-pcrs", "path", testPath)
				return data, nil
			}
		}
	}
	return nil, &MessageError{Msg: "platform config not found on ISO or at /tmp/platform-config.yaml (or all found configs missing seal-pcrs)"}
}

// createInstallerContainer creates a LUKS-encrypted container with keys and config
// The container is 100MB to hold all provisioning output (CA keys, platform state, etc.)
func (i *installer) createInstallerContainer(ctx context.Context, path string, luksKey []byte, recoveryKey string, configData []byte) error {
	// Create 100MB file for installer container
	// NOTE: FAT32 doesn't support sparse files, so we must write actual zeros
	installerSize := int64(100 * 1024 * 1024)
	if err := createAllocatedFile(path, installerSize); err != nil {
		return &WrappedError{Msg: "failed to create installer file", Err: err}
	}

	// Format directly to the FILE (not loop device) - go-luks2 works correctly on files
	// Loop devices have caching issues that cause header corruption on FAT32
	i.logger.Info("[TPM] Formatting installer container as LUKS2", "file", path)
	formatOpts := luks2.FormatOptions{
		Device:     path, // Format the FILE directly, not a loop device
		Passphrase: []byte(InstallerPassword),
		Label:      "installer",
		KDFType:    "pbkdf2", // Use PBKDF2 during install to avoid OOM in low-memory environments
	}
	if err := luks2.Format(formatOpts); err != nil {
		if removeErr := os.Remove(path); removeErr != nil {
			return &WrappedError{Msg: "failed to remove container file", Err: removeErr}
		}
		return &WrappedError{Msg: "failed to format installer container", Err: err}
	}
	i.logger.Info("[TPM] LUKS2 format complete")

	// Now setup loop device for unlock/mount operations
	loopDev, err := luks2.SetupLoopDevice(path)
	if err != nil {
		if removeErr := os.Remove(path); removeErr != nil {
			return &WrappedError{Msg: "failed to remove container file", Err: removeErr}
		}
		return &WrappedError{Msg: "failed to setup loop device", Err: err}
	}

	// Unlock installer using loop device
	i.logger.Info("[TPM] Opening installer container...", "device", loopDev)
	if err := luks2.Unlock(loopDev, []byte(InstallerPassword), "installer"); err != nil {
		if detachErr := luks2.DetachLoopDevice(loopDev); detachErr != nil {
			i.logger.Warn("[TPM] Failed to detach loop device", "error", detachErr)
		}
		if removeErr := os.Remove(path); removeErr != nil {
			return &WrappedError{Msg: "failed to remove container file", Err: removeErr}
		}
		return &WrappedError{Msg: "failed to unlock installer container", Err: err}
	}

	// Get the actual device path (handles udev symlink vs dm-X fallback)
	installerDevPath, err := luks2.GetMappedDevicePath("installer")
	if err != nil {
		i.logger.Warn("[TPM] GetMappedDevicePath failed, using default path", "error", err)
		installerDevPath = "/dev/mapper/installer"
	}
	i.logger.Info("[TPM] Installer container unlocked", "device", installerDevPath)

	// Create ext4 filesystem
	i.logger.Info("[TPM] Creating ext4 filesystem in installer container")
	mkfsCmd := exec.CommandContext(ctx, "mkfs.ext4", "-q", installerDevPath)
	if output, err := mkfsCmd.CombinedOutput(); err != nil {
		if lockErr := luks2.Lock("installer"); lockErr != nil {
			i.logger.Warn("[TPM] Failed to lock installer container", "error", lockErr)
		}
		if detachErr := luks2.DetachLoopDevice(loopDev); detachErr != nil {
			i.logger.Warn("[TPM] Failed to detach loop device", "error", detachErr)
		}
		if removeErr := os.Remove(path); removeErr != nil {
			return &WrappedError{Msg: "failed to remove container file", Err: removeErr}
		}
		return &CommandOutputError{Msg: "failed to create filesystem", Err: err, Detail: fmt.Sprintf(" (output: %s)", string(output))}
	}

	// Mount installer container
	mountPoint := "/tmp/installer-mount"
	if err := os.MkdirAll(mountPoint, 0700); err != nil {
		if lockErr := luks2.Lock("installer"); lockErr != nil {
			i.logger.Warn("[TPM] Failed to lock installer container", "error", lockErr)
		}
		if detachErr := luks2.DetachLoopDevice(loopDev); detachErr != nil {
			i.logger.Warn("[TPM] Failed to detach loop device", "error", detachErr)
		}
		if removeErr := os.Remove(path); removeErr != nil {
			return &WrappedError{Msg: "failed to remove container file", Err: removeErr}
		}
		return &WrappedError{Msg: "failed to create mount point", Err: err}
	}

	if err := unix.Mount(installerDevPath, mountPoint, "ext4", 0, ""); err != nil {
		if lockErr := luks2.Lock("installer"); lockErr != nil {
			i.logger.Warn("[TPM] Failed to lock installer container", "error", lockErr)
		}
		if detachErr := luks2.DetachLoopDevice(loopDev); detachErr != nil {
			i.logger.Warn("[TPM] Failed to detach loop device", "error", detachErr)
		}
		if removeErr := os.Remove(path); removeErr != nil {
			return &WrappedError{Msg: "failed to remove container file", Err: removeErr}
		}
		return &WrappedError{Msg: "failed to mount installer container", Err: err}
	}

	// Write files to installer container
	i.logger.Info("[TPM] Writing keys and config to encrypted installer container")

	// Write LUKS key at root
	if err := os.WriteFile(filepath.Join(mountPoint, "luks-key.bin"), luksKey, 0600); err != nil {
		if umountErr := unix.Unmount(mountPoint, 0); umountErr != nil {
			i.logger.Warn("[TPM] Failed to unmount installer container", "error", umountErr)
		}
		if lockErr := luks2.Lock("installer"); lockErr != nil {
			i.logger.Warn("[TPM] Failed to lock installer container", "error", lockErr)
		}
		if detachErr := luks2.DetachLoopDevice(loopDev); detachErr != nil {
			i.logger.Warn("[TPM] Failed to detach loop device", "error", detachErr)
		}
		if removeErr := os.Remove(path); removeErr != nil {
			return &WrappedError{Msg: "failed to remove container file", Err: removeErr}
		}
		return &WrappedError{Msg: "failed to write LUKS key to installer", Err: err}
	}

	// Write recovery key at root
	if err := os.WriteFile(filepath.Join(mountPoint, "recovery-key.txt"), []byte(recoveryKey), 0600); err != nil {
		if umountErr := unix.Unmount(mountPoint, 0); umountErr != nil {
			i.logger.Warn("[TPM] Failed to unmount installer container", "error", umountErr)
		}
		if lockErr := luks2.Lock("installer"); lockErr != nil {
			i.logger.Warn("[TPM] Failed to lock installer container", "error", lockErr)
		}
		if detachErr := luks2.DetachLoopDevice(loopDev); detachErr != nil {
			i.logger.Warn("[TPM] Failed to detach loop device", "error", detachErr)
		}
		if removeErr := os.Remove(path); removeErr != nil {
			return &WrappedError{Msg: "failed to remove container file", Err: removeErr}
		}
		return &WrappedError{Msg: "failed to write recovery key to installer", Err: err}
	}

	// Write config at /etc/trusted-platform/config.yaml (mirrors production path)
	if configData != nil {
		configDir := filepath.Join(mountPoint, "etc", "trusted-platform")
		if err := os.MkdirAll(configDir, 0755); err != nil {
			if umountErr := unix.Unmount(mountPoint, 0); umountErr != nil {
				i.logger.Warn("[TPM] Failed to unmount installer container", "error", umountErr)
			}
			if lockErr := luks2.Lock("installer"); lockErr != nil {
				i.logger.Warn("[TPM] Failed to lock installer container", "error", lockErr)
			}
			if detachErr := luks2.DetachLoopDevice(loopDev); detachErr != nil {
				i.logger.Warn("[TPM] Failed to detach loop device", "error", detachErr)
			}
			if removeErr := os.Remove(path); removeErr != nil {
				i.logger.Warn("[TPM] failed to remove container file", "error", removeErr)
			}
			return &WrappedError{Msg: "failed to create config directory", Err: err}
		}
		if err := os.WriteFile(filepath.Join(configDir, "config.yaml"), configData, 0600); err != nil {
			if umountErr := unix.Unmount(mountPoint, 0); umountErr != nil {
				i.logger.Warn("[TPM] Failed to unmount installer container", "error", umountErr)
			}
			if lockErr := luks2.Lock("installer"); lockErr != nil {
				i.logger.Warn("[TPM] Failed to lock installer container", "error", lockErr)
			}
			if detachErr := luks2.DetachLoopDevice(loopDev); detachErr != nil {
				i.logger.Warn("[TPM] Failed to detach loop device", "error", detachErr)
			}
			if removeErr := os.Remove(path); removeErr != nil {
				i.logger.Warn("[TPM] failed to remove container file", "error", removeErr)
			}
			return &WrappedError{Msg: "failed to write config to installer", Err: err}
		}
		i.logger.Info("[TPM] Platform config written to installer at /etc/trusted-platform/config.yaml")
	}

	// Unmount and close - CRITICAL: sync at each step to ensure data
	// reaches the FAT filesystem backing file before loop device detach
	if err := unix.Unmount(mountPoint, 0); err != nil {
		i.logger.Warn("[TPM] Failed to unmount installer container", "error", err)
	}
	os.Remove(mountPoint)

	// Sync after unmount to flush ext4 data to dm-crypt device
	unix.Sync()

	if err := luks2.Lock("installer"); err != nil {
		i.logger.Warn("[TPM] Failed to close installer container", "error", err)
	}

	// Sync after LUKS close to flush encrypted data to loop device
	unix.Sync()

	if err := luks2.DetachLoopDevice(loopDev); err != nil {
		i.logger.Warn("[TPM] Failed to detach loop device", "error", err)
	}

	// Final sync to flush loop device data to FAT filesystem backing file
	unix.Sync()
	i.logger.Info("[TPM] Installer container data synced to disk")

	// Final verification: read header using go-luks2 to ensure it's valid
	i.logger.Info("[TPM] Final verification: checking LUKS header integrity...")
	if _, _, err := luks2.ReadHeader(path); err != nil {
		i.logger.Error(&WrappedError{Msg: "[TPM] FINAL VERIFICATION FAILED", Err: err})
		if removeErr := os.Remove(path); removeErr != nil {
			return &WrappedError{Msg: "failed to remove container file", Err: removeErr}
		}
		return &WrappedError{Msg: "final LUKS header verification failed", Err: err}
	}
	i.logger.Info("[TPM] FINAL VERIFICATION PASSED: LUKS header intact")

	return nil
}

// createAllocatedFile creates a file with actual allocated blocks
// FAT32 does not support sparse files, so we must write actual data
// to ensure the filesystem allocates real disk blocks for the loop device
func createAllocatedFile(path string, size int64) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	// Write zeros in 1MB chunks to allocate real disk blocks on FAT32
	const chunkSize = 1024 * 1024 // 1MB
	zeros := make([]byte, chunkSize)

	remaining := size
	for remaining > 0 {
		writeSize := chunkSize
		if remaining < int64(chunkSize) {
			writeSize = int(remaining)
		}

		n, err := f.Write(zeros[:writeSize])
		if err != nil {
			if removeErr := os.Remove(path); removeErr != nil {
				return &WrappedError{Msg: "failed to remove container file", Err: removeErr}
			}
			return &WrappedError{Msg: "failed to allocate file blocks", Err: err}
		}
		remaining -= int64(n)
	}

	// Sync to ensure data is written to disk
	if err := f.Sync(); err != nil {
		if removeErr := os.Remove(path); removeErr != nil {
			return &WrappedError{Msg: "failed to remove container file", Err: removeErr}
		}
		return &WrappedError{Msg: "failed to sync file", Err: err}
	}

	return nil
}

// clearBytes securely zeros a byte slice
func clearBytes(b []byte) {
	for j := range b {
		b[j] = 0
	}
}

// copyBinaryWithVerification copies a binary file from src to dst with verification.
// It ensures the target directory exists, copies the binary with executable permissions (0755),
// and verifies the file was written correctly by checking size and permissions.
func copyBinaryWithVerification(src, dst string) error {
	// Read source binary
	data, err := os.ReadFile(src)
	if err != nil {
		return &WrappedError{Msg: fmt.Sprintf("failed to read binary from %s", src), Err: err}
	}

	// Create target directory if needed
	targetDir := filepath.Dir(dst)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("failed to create directory %s", targetDir), Err: err}
	}

	// Write binary
	if err := os.WriteFile(dst, data, 0755); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("failed to write binary to %s", dst), Err: err}
	}

	// Ensure permissions are set correctly (WriteFile may not update perms on existing files)
	if err := os.Chmod(dst, 0755); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("failed to set permissions on %s", dst), Err: err}
	}

	// Verify the write
	stat, err := os.Stat(dst)
	if err != nil {
		return &WrappedError{Msg: "binary verification failed - file not found after write", Err: err}
	}
	if stat.Size() != int64(len(data)) {
		return &MessageError{Msg: fmt.Sprintf("binary verification failed - size mismatch: got %d, expected %d", stat.Size(), len(data))}
	}
	if stat.Mode().Perm() != 0755 {
		return &MessageError{Msg: fmt.Sprintf("binary verification failed - wrong permissions: got %o, expected 0755", stat.Mode().Perm())}
	}

	return nil
}

// injectPlatformInitrdIntoInitramfs unpacks the dracut-generated initramfs,
// adds /usr/bin/platform-initrd to it, and repacks it as a single cpio archive.
// This ensures the binary is extracted by userspace tools (like cpio -i) when
// debugging, in addition to being available at boot via the Linux kernel.
//
// This works around dracut's inst_binary/inst_simple limitations with statically
// linked Go binaries, which are silently dropped during normal dracut processing.
func (i *installer) injectPlatformInitrdIntoInitramfs(ctx context.Context, mountPoint, initramfsPath string) error {
	srcBinary := filepath.Join(mountPoint, "usr", "bin", "platform-initrd")
	if _, err := os.Stat(srcBinary); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("platform-initrd not found at %s", srcBinary), Err: err}
	}

	// Create a work directory to extract + modify + repack
	workDir, err := os.MkdirTemp("", "initrd-rebuild-*")
	if err != nil {
		return &WrappedError{Msg: "failed to create work dir", Err: err}
	}
	defer os.RemoveAll(workDir)

	extractDir := filepath.Join(workDir, "extract")
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create extract dir", Err: err}
	}

	i.logger.Info("[UKI] Extracting initramfs for modification", "path", initramfsPath)

	// Extract the cpio initramfs into extractDir.
	//
	// Compression detection: dracut on modern kernels can produce zstd,
	// xz, gzip, lz4, lzma, lzop, bzip2, or even uncompressed initramfs
	// images depending on dracut.conf and kernel CONFIG_RD_*. We MUST
	// detect the format from the magic bytes rather than assume gzip,
	// otherwise zcat fails with "no gzip/bzip2/xz magic" on a zstd
	// initramfs (the actual default on Alpine 3.22 + dracut 105).
	//
	// Tool flags: Alpine's busybox cpio only accepts short flags. We
	// previously passed --no-absolute-filenames which is a GNU cpio long
	// option busybox doesn't recognize ("cpio: unrecognized option").
	// `cpio -idm` (short form) extracts with leading slashes already
	// stripped — busybox refuses absolute paths by default, so the GNU
	// safety flag isn't needed here.
	decompressor, err := detectInitramfsDecompressor(initramfsPath)
	if err != nil {
		return &WrappedError{Msg: "failed to detect initramfs compression", Err: err}
	}
	i.logger.Info("[UKI] Detected initramfs format", "decompressor", decompressor)

	extractCmd := fmt.Sprintf("cd %s && %s %s | cpio -idm 2>&1",
		extractDir, decompressor, initramfsPath)
	cmd := exec.CommandContext(ctx, "sh", "-c", extractCmd)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stderr
	if err := cmd.Run(); err != nil {
		return &CommandOutputError{Msg: "failed to extract initramfs", Err: err, Detail: fmt.Sprintf(" (output: %s)", stderr.String())}
	}
	i.logger.Info("[UKI] Initramfs extracted", "output", stderr.String())

	// Verify extraction worked — we should see common dirs like /bin, /etc
	if _, err := os.Stat(filepath.Join(extractDir, "bin")); err != nil {
		return &MessageError{Msg: "initramfs extraction incomplete — /bin not found"}
	}

	// Copy platform-initrd into the extracted directory
	binData, err := os.ReadFile(srcBinary)
	if err != nil {
		return &WrappedError{Msg: "failed to read platform-initrd", Err: err}
	}
	extractedBinDir := filepath.Join(extractDir, "usr", "bin")
	if err := os.MkdirAll(extractedBinDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create usr/bin in extract dir", Err: err}
	}
	extractedBinPath := filepath.Join(extractedBinDir, "platform-initrd")
	if err := os.WriteFile(extractedBinPath, binData, 0755); err != nil {
		return &WrappedError{Msg: "failed to write platform-initrd to extract dir", Err: err}
	}
	i.logger.Info("[UKI] Added platform-initrd to initramfs contents",
		"path", extractedBinPath,
		"size", len(binData))

	// Repack as a cpio archive with the SAME compression the original
	// used. The Linux kernel decoder picks up whichever format the magic
	// bytes indicate, but we want to match the original so the resulting
	// initramfs size is comparable and we don't pull in compressors the
	// install env doesn't have.
	compressor := decompressorToCompressor(decompressor)
	i.logger.Info("[UKI] Repacking initramfs", "compressor", compressor)
	newInitramfsPath := initramfsPath + ".new"
	repackCmd := fmt.Sprintf("cd %s && find . | cpio -o -H newc 2>/dev/null | %s > %s",
		extractDir, compressor, newInitramfsPath)
	cmd = exec.CommandContext(ctx, "sh", "-c", repackCmd)
	stderr.Reset()
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return &CommandOutputError{Msg: "failed to repack initramfs", Err: err, Detail: fmt.Sprintf(" (stderr: %s)", stderr.String())}
	}

	// Verify new initramfs
	newInfo, err := os.Stat(newInitramfsPath)
	if err != nil {
		return &WrappedError{Msg: "repacked initramfs not found", Err: err}
	}
	if newInfo.Size() == 0 {
		return &MessageError{Msg: "repacked initramfs is empty"}
	}
	i.logger.Info("[UKI] Repacked initramfs", "size", newInfo.Size())

	// Atomically replace the original initramfs
	if err := os.Rename(newInitramfsPath, initramfsPath); err != nil {
		return &WrappedError{Msg: "failed to replace initramfs", Err: err}
	}

	// Final stat
	finalInfo, err := os.Stat(initramfsPath)
	if err != nil {
		return &WrappedError{Msg: "failed to stat final initramfs", Err: err}
	}
	i.logger.Info("[UKI] Final initramfs with platform-initrd",
		"path", initramfsPath,
		"size", finalInfo.Size(),
		"binary_size", len(binData))
	return nil
}

// detectInitramfsDecompressor reads the first few bytes of an initramfs file
// and returns the shell command that streams its contents to stdout. dracut
// can produce gzip, xz, zstd, lz4, lzma, lzop, bzip2, or uncompressed
// archives depending on the kernel's CONFIG_RD_* and the dracut.conf
// `compress=` setting. Picking the wrong decompressor (or assuming gzip)
// causes the cpio extraction step to fail with "no magic" errors that look
// like the install succeeded.
//
// Magic bytes per the Linux kernel's lib/decompress_*:
//
//	gzip   1f 8b
//	bzip2  42 5a 68
//	xz     fd 37 7a 58 5a 00
//	lzma   5d 00 00
//	lzop   89 4c 5a 4f
//	lz4    02 21 4c 18  (legacy frame)  OR  04 22 4d 18  (frame format)
//	zstd   28 b5 2f fd
//	cpio   30 37 30 37  ("0707" — uncompressed newc format)
func detectInitramfsDecompressor(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	hdr := make([]byte, 8)
	if _, err := io.ReadFull(f, hdr); err != nil {
		return "", &WrappedError{Msg: "read magic bytes", Err: err}
	}

	switch {
	case hdr[0] == 0x1f && hdr[1] == 0x8b:
		return "zcat", nil
	case hdr[0] == 0x42 && hdr[1] == 0x5a && hdr[2] == 0x68:
		return "bzcat", nil
	case hdr[0] == 0xfd && hdr[1] == 0x37 && hdr[2] == 0x7a && hdr[3] == 0x58 && hdr[4] == 0x5a:
		return "xzcat", nil
	case hdr[0] == 0x5d && hdr[1] == 0x00 && hdr[2] == 0x00:
		return "lzcat", nil
	case hdr[0] == 0x89 && hdr[1] == 0x4c && hdr[2] == 0x5a && hdr[3] == 0x4f:
		return "lzop -d", nil
	case (hdr[0] == 0x02 && hdr[1] == 0x21 && hdr[2] == 0x4c && hdr[3] == 0x18) ||
		(hdr[0] == 0x04 && hdr[1] == 0x22 && hdr[2] == 0x4d && hdr[3] == 0x18):
		return "lz4cat", nil
	case hdr[0] == 0x28 && hdr[1] == 0xb5 && hdr[2] == 0x2f && hdr[3] == 0xfd:
		return "zstdcat", nil
	case hdr[0] == 0x30 && hdr[1] == 0x37 && hdr[2] == 0x30 && hdr[3] == 0x37:
		return "cat", nil // uncompressed cpio newc
	default:
		return "", &MessageError{Msg: fmt.Sprintf("unrecognised initramfs magic bytes: %x", hdr[:8])}
	}
}

// decompressorToCompressor maps the decoder used to extract an initramfs
// to the matching encoder we use when repacking. We always pick the
// streaming form (writes to stdout) so the cpio | <encoder> > new pipeline
// works without temporary files.
func decompressorToCompressor(decoder string) string {
	switch decoder {
	case "zcat":
		return "gzip -n"
	case "bzcat":
		return "bzip2"
	case "xzcat":
		return "xz --check=crc32 -z"
	case "lzcat":
		return "lzma"
	case "lzop -d":
		return "lzop"
	case "lz4cat":
		return "lz4 -l"
	case "zstdcat":
		return "zstd"
	case "cat":
		return "cat"
	default:
		return "gzip -n"
	}
}

// installPlatformInitrdForDracut installs platformd binary and dracut module BEFORE UKI build
// This must be called BEFORE buildUKI() so dracut can include the binary in initramfs
func (i *installer) installPlatformInitrdForDracut(ctx context.Context) error {
	i.logger.Info("[DRACUT] Installing platformd binary and module for dracut")

	mountPoint := "/mnt"

	// 1. Copy platformd binary from ISO to target system (single consolidated binary)
	var platformdSrc string
	for _, isoMount := range []string{"/media/cdrom", "/media/usb", "/mnt/cdrom"} {
		// Prefer platformd (consolidated binary)
		testPath := filepath.Join(isoMount, "platformd-bin", "platformd")
		if _, err := os.Stat(testPath); err == nil {
			platformdSrc = testPath
			break
		}
	}

	if platformdSrc == "" {
		return &MessageError{Msg: "platformd binary not found on ISO"}
	}

	// Create /usr/bin directory in target
	// NOTE: We use /usr/bin because the dracut module (module-setup.sh) and
	// unlock script (platformd-unlock.sh) expect platformd at /usr/bin/platformd
	targetBinDir := filepath.Join(mountPoint, "usr", "bin")
	if err := os.MkdirAll(targetBinDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create /usr/bin directory", Err: err}
	}

	// Copy platformd binary (consolidated binary for boot, firstboot, install)
	platformdData, err := os.ReadFile(platformdSrc)
	if err != nil {
		return &WrappedError{Msg: "failed to read platformd binary", Err: err}
	}

	targetPlatformd := filepath.Join(targetBinDir, "platformd")
	if err := os.WriteFile(targetPlatformd, platformdData, 0755); err != nil {
		return &WrappedError{Msg: "failed to write platformd binary", Err: err}
	}

	// Explicitly sync to ensure file is written to disk
	syncCmd := exec.CommandContext(ctx, "sync")
	if err := syncCmd.Run(); err != nil {
		i.logger.Warn("[DRACUT] Failed to sync filesystem", "error", err)
	}

	// Verify the file was written correctly
	if stat, err := os.Stat(targetPlatformd); err != nil {
		return &WrappedError{Msg: "platformd binary verification failed - file not found after write", Err: err}
	} else if stat.Size() != int64(len(platformdData)) {
		return &MessageError{Msg: fmt.Sprintf("platformd binary verification failed - size mismatch: got %d, expected %d", stat.Size(), len(platformdData))}
	} else if stat.Mode().Perm() != 0755 {
		return &MessageError{Msg: fmt.Sprintf("platformd binary verification failed - wrong permissions: got %o, expected 0755", stat.Mode().Perm())}
	}

	i.logger.Info("[DRACUT] Installed platformd binary", "path", targetPlatformd, "size", len(platformdData))

	// Create symlink at /usr/sbin/platformd -> /usr/bin/platformd
	// Some OpenRC services and firstboot scripts expect platformd at /usr/sbin
	targetSbinDir := filepath.Join(mountPoint, "usr", "sbin")
	if err := os.MkdirAll(targetSbinDir, 0755); err != nil {
		i.logger.Warn("[DRACUT] Failed to create /usr/sbin directory", "error", err)
	} else {
		symlinkPath := filepath.Join(targetSbinDir, "platformd")
		os.Remove(symlinkPath) // Remove if exists
		if err := os.Symlink("/usr/bin/platformd", symlinkPath); err != nil {
			i.logger.Warn("[DRACUT] Failed to create /usr/sbin/platformd symlink", "error", err)
		} else {
			i.logger.Info("[DRACUT] Created symlink /usr/sbin/platformd -> /usr/bin/platformd")
		}
	}

	// Also install platformctl if available on ISO (derive path from platformd location)
	platformctlSrc := filepath.Join(filepath.Dir(platformdSrc), "platformctl")
	i.logger.Debug("[DRACUT] Checking for platformctl binary", "path", platformctlSrc)
	if _, err := os.Stat(platformctlSrc); err == nil {
		i.logger.Debug("[DRACUT] Found platformctl, starting copy")
		targetPlatformctl := filepath.Join(targetBinDir, "platformctl")
		if err := copyBinaryWithVerification(platformctlSrc, targetPlatformctl); err != nil {
			i.logger.Warn("[DRACUT] Failed to install platformctl binary", "error", err)
		} else {
			stat, _ := os.Stat(targetPlatformctl)
			i.logger.Info("[DRACUT] Installed platformctl binary", "path", targetPlatformctl, "size", stat.Size())
		}
	} else {
		i.logger.Debug("[DRACUT] platformctl binary not found on ISO, skipping")
	}

	// CRITICAL: Install platform-initrd binary for dracut initramfs boot operations
	// This is the minimal binary called by the dracut hook during boot to unlock LUKS
	// Without this binary, the system will not boot!
	platformInitrdSrc := filepath.Join(filepath.Dir(platformdSrc), "platform-initrd")
	i.logger.Info("[DRACUT] Installing platform-initrd binary (CRITICAL for boot)", "path", platformInitrdSrc)
	if _, err := os.Stat(platformInitrdSrc); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("[DRACUT] platform-initrd binary not found on ISO at %s", platformInitrdSrc), Err: err}
	}
	targetPlatformInitrd := filepath.Join(targetBinDir, "platform-initrd")
	if err := copyBinaryWithVerification(platformInitrdSrc, targetPlatformInitrd); err != nil {
		return &WrappedError{Msg: "[DRACUT] failed to install platform-initrd binary", Err: err}
	}
	stat, _ := os.Stat(targetPlatformInitrd)
	i.logger.Info("[DRACUT] Successfully installed platform-initrd binary", "path", targetPlatformInitrd, "size", stat.Size())

	// Verify the file is actually executable and present
	if _, err := os.Stat(targetPlatformInitrd); err != nil {
		return &WrappedError{Msg: "[DRACUT] platform-initrd verification failed after copy", Err: err}
	}

	// 2. Copy platformd config file (for platformd binary)
	// Both binaries use the same config file for TPM configuration (including types.srk-handle)
	// Search for platform type-specific config files (server/client) as well as generic configs
	i.logger.Debug("[DRACUT] Searching for platform config on ISO")
	var platformConfigSrc string
	for _, isoMount := range []string{"/media/cdrom", "/media/usb", "/mnt/cdrom"} {
		for _, configName := range []string{
			"installer.yaml",
			"platformd.yaml",
			"platform.yaml",
			"config.yaml",
		} {
			testPath := filepath.Join(isoMount, "configs", configName)
			if _, err := os.Stat(testPath); err == nil {
				platformConfigSrc = testPath
				i.logger.Debug("[DRACUT] Found platform config", "path", testPath)
				break
			}
		}
		if platformConfigSrc != "" {
			break
		}
	}

	if platformConfigSrc != "" {
		// Read config file once
		configData, err := os.ReadFile(platformConfigSrc)
		if err != nil {
			i.logger.Warn("[DRACUT] Failed to read platform config", "error", err)
		} else {
			// 1. Copy to root filesystem (/etc/trusted-platform/config.yaml)
			// Available after switch_root when root is mounted
			targetConfigDir := filepath.Join(mountPoint, "etc", "trusted-platform")
			if err := os.MkdirAll(targetConfigDir, 0755); err != nil {
				i.logger.Warn("[DRACUT] Failed to create config directory", "error", err)
			} else {
				targetConfig := filepath.Join(targetConfigDir, "config.yaml")
				if err := os.WriteFile(targetConfig, configData, 0644); err != nil {
					i.logger.Warn("[DRACUT] Failed to write platform config to root", "error", err)
				} else {
					i.logger.Info("[DRACUT] Installed platform config to root filesystem", "path", targetConfig)
				}
			}

			// NOTE: Config is NOT written to EFI partition here.
			// It's stored in the encrypted installer container (installer.luks)
			// created by prepareLUKSKeyForTPM(). The firstboot strategy will
			// read config from the installer and provision platform inside it.
			// This ensures no sensitive data is ever on the unencrypted EFI partition.
		}
	} else {
		i.logger.Warn("[DRACUT] Platform config not found on ISO, platformd will use defaults")
	}

	// 3. Copy platformd dracut module
	i.logger.Debug("[DRACUT] Searching for platformd dracut module on ISO")
	dracutModuleFound := false
	for _, isoMount := range []string{"/media/cdrom", "/media/usb", "/mnt/cdrom"} {
		dracutModuleSrc := filepath.Join(isoMount, "dracut-platformd", "90platformd")
		if _, err := os.Stat(dracutModuleSrc); err == nil {
			i.logger.Debug("[DRACUT] Found dracut module", "path", dracutModuleSrc)
			dracutModuleDir := filepath.Join(mountPoint, "usr", "lib", "dracut", "modules.d", "90platformd")
			if err := os.MkdirAll(dracutModuleDir, 0755); err != nil {
				return &WrappedError{Msg: "failed to create dracut module directory", Err: err}
			}

			// Copy the dracut module directory using cp -r
			i.logger.Debug("[DRACUT] Copying dracut module", "src", dracutModuleSrc, "dest", dracutModuleDir)
			cpCmd := exec.CommandContext(ctx, "cp", "-r", dracutModuleSrc+"/.", dracutModuleDir)
			if output, err := cpCmd.CombinedOutput(); err != nil {
				return &CommandOutputError{Msg: "failed to copy dracut module", Err: err, Detail: fmt.Sprintf(" (output: %s)", string(output))}
			}
			i.logger.Info("[DRACUT] Installed platformd dracut module")
			dracutModuleFound = true
			break
		}
	}
	if !dracutModuleFound {
		i.logger.Warn("[DRACUT] dracut module not found on ISO")
	}

	i.logger.Debug("[DRACUT] installPlatformInitrdForDracut completed successfully")
	return nil
}

// installFirstbootService installs the firstboot TPM sealing service
// Note: The platformd binary is already installed by installPlatformInitrdForDracut()
// This function only creates the OpenRC service for first-boot TPM sealing
func (i *installer) installFirstbootService(ctx context.Context) error {
	i.logger.Info("[FIRSTBOOT] Installing TPM firstboot sealing service")

	mountPoint := "/mnt"

	// 1. Create tpm-firstboot-seal OpenRC service script
	// This matches the reference at build/iso/alpine/amd64/scripts/install/tpm-firstboot-seal.sh
	initdDir := filepath.Join(mountPoint, "etc", "init.d")
	if err := os.MkdirAll(initdDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create /etc/init.d directory", Err: err}
	}

	firstbootService := `#!/sbin/openrc-run

description="First-boot TPM sealing and re-sealing after kernel upgrades"

depend() {
    need localmount networking
    after bootmisc
    keyword -shutdown
}

start() {
    ebegin "Running platformd TPM sealing"

    RESEAL_MODE=false

    # Check if re-seal is needed (upgrade seals exist on EFI partition)
    # Upgrade seals indicate TPM-Upgrade was used because PCR seals failed
    # This happens after kernel upgrades when PCR values change
    if [ -f /boot/efi/tpm2/seal-upgrade.pub ] && [ -f /boot/efi/tpm2/seal-upgrade.priv ]; then
        einfo "Upgrade seals found - re-seal required (PCR values changed)"
        RESEAL_MODE=true
        # Remove the flag to allow re-sealing
        rm -f /var/lib/tpm2/platform-sealed.flag
    elif [ -f /var/lib/tpm2/platform-sealed.flag ]; then
        # Already sealed and no upgrade seals - nothing to do
        einfo "Platform already sealed, no re-seal needed"
        # Ensure the initialized flag exists so platformd doesn't try to reinitialize
        if [ ! -f /var/lib/trusted-platform/.initialized ]; then
            mkdir -p /var/lib/trusted-platform
            touch /var/lib/trusted-platform/.initialized || ewarn "Failed to create init flag"
            einfo "Platform marked as initialized (sealed during installation)"
        fi
        eend 0
        return 0
    fi

    # Check if platformctl is available (CLI binary with firstboot command)
    # NOTE: platform-initrd is for boot/recovery only, platformctl has firstboot and all user commands
    if [ ! -x /usr/bin/platformctl ]; then
        eerror "platformctl binary not found at /usr/bin/platformctl"
        eend 1
        return 1
    fi

    # Apply network configuration from EFI partition
    if [ -f /boot/efi/tpm2/network.conf ]; then
        einfo "Loading network configuration from EFI partition"
        . /boot/efi/tpm2/network.conf

        # Set hostname if provided
        if [ -n "$HOSTNAME" ]; then
            hostname "$HOSTNAME" 2>/dev/null || true
            einfo "Hostname set to: $HOSTNAME"
        fi
    fi

    # Wait a moment for network to fully stabilize
    sleep 2

    # Cleanup any leftover installer device mapper from initramfs failures
    # This can happen if initramfs provisioning failed and fell back to key-only unlock
    if [ -e /dev/mapper/installer ]; then
        ewarn "Found leftover installer device mapper, cleaning up..."
        # Try to unmount any mount points
        umount /mnt/installer 2>/dev/null || true
        umount -l /mnt/installer 2>/dev/null || true
        # Close the LUKS container using dmsetup (no cryptsetup dependency)
        dmsetup remove installer 2>/dev/null || dmsetup remove --force installer 2>/dev/null || true
        # Find and detach any loop devices for installer.luks
        for loopdev in /dev/loop*; do
            if [ -b "$loopdev" ] && losetup "$loopdev" 2>/dev/null | grep -q installer.luks; then
                losetup -d "$loopdev" 2>/dev/null || true
                einfo "Detached loop device $loopdev"
            fi
        done
        # Verify cleanup
        if [ -e /dev/mapper/installer ]; then
            ewarn "Could not fully clean up installer device mapper - continuing anyway"
        else
            einfo "Installer device mapper cleaned up successfully"
        fi
    fi

    # Extract LUKS UUID from kernel command line
    LUKS_UUID=$(cat /proc/cmdline | grep -o 'rd\.luks\.uuid=[^ ]*' | head -n1 | cut -d'=' -f2)
    if [ -z "$LUKS_UUID" ]; then
        eerror "Could not find LUKS UUID in kernel command line"
        eend 1
        return 1
    fi

    LUKS_DEVICE="/dev/disk/by-uuid/$LUKS_UUID"
    einfo "Found LUKS UUID: $LUKS_UUID"
    einfo "Using device path: $LUKS_DEVICE"

    mkdir -p /var/lib/tpm2
    einfo "Created /var/lib/tpm2/ directory for marker file"

    # Run firstboot - this will provision (if needed) and seal/re-seal the LUKS key
    if [ "$RESEAL_MODE" = "true" ]; then
        einfo "Running TPM re-sealing with current PCR values..."
    else
        einfo "Running firstboot provisioning and TPM sealing..."
    fi

    if /usr/bin/platformctl firstboot --luks-device "$LUKS_DEVICE" --debug 2>&1; then
        mkdir -p /var/lib/tpm2
        touch /var/lib/tpm2/platform-sealed.flag || ewarn "Failed to create seal flag"
        einfo "TPM sealing completed successfully"

        # Create the platform initialized flag so platformd service doesn't use --init
        # when TPM is already provisioned (which would fail with "EK already exists" error)
        mkdir -p /var/lib/trusted-platform
        touch /var/lib/trusted-platform/.initialized || ewarn "Failed to create init flag"
        einfo "Platform marked as initialized"

        # IMPORTANT: do NOT auto-reboot here. The seal is already in place
        # on the EFI partition; the LUKS root is already unlocked via
        # the keyfile fallback path; platformd starts cleanly on this
        # very boot. The next *natural* reboot will exercise the
        # TPM-PCR unseal — if PCRs match, the system switches to
        # TPM-only unlock; if not, the keyfile fallback continues to
        # cover us with no operational impact.
        #
        # Auto-rebooting here was a self-defeating loop on hardware
        # where PCR 9 differs between the installer initramfs and the
        # production initramfs (a known X10/SLB9665 reality): every
        # "verify" reboot would fall through to keyfile, then we'd
        # auto-reboot again, forever. The keyfile-fallback path is
        # the validation — it ran successfully *this* boot, that is
        # the proof we need. Defer seal-confirmation to the natural
        # next boot.
        einfo "Seal staged on EFI partition. TPM-PCR unlock will be"
        einfo "attempted on the next natural reboot; keyfile fallback"
        einfo "guarantees the system remains operational either way."
    else
        eerror "Platform sealing failed"
        eend 1
        return 1
    fi

    eend 0
}

stop() {
    return 0
}
`

	firstbootServicePath := filepath.Join(initdDir, "tpm-firstboot-seal")
	if err := os.WriteFile(firstbootServicePath, []byte(firstbootService), 0755); err != nil {
		return &WrappedError{Msg: "failed to write tpm-firstboot-seal service", Err: err}
	}
	i.logger.Info("[FIRSTBOOT] Created tpm-firstboot-seal OpenRC service")

	// 4. Enable tpm-firstboot-seal service in default runlevel
	rcUpdateCmd := exec.CommandContext(ctx, "chroot", mountPoint, "rc-update", "add", "tpm-firstboot-seal", "default")
	if output, err := rcUpdateCmd.CombinedOutput(); err != nil {
		i.logger.Warn("[FIRSTBOOT] Failed to enable tpm-firstboot-seal service", "error", err, "output", string(output))
		// Don't fail, service can be enabled manually
	} else {
		i.logger.Info("[FIRSTBOOT] Enabled tpm-firstboot-seal service in default runlevel")
	}

	i.logger.Info("[FIRSTBOOT] First-boot TPM sealing service installation complete")
	i.logger.Info("[FIRSTBOOT] On first boot, system will seal LUKS key to TPM with PCR policy")

	// Install firstboot log upload service (debug mode only)
	if err := i.installFirstbootLogUploadService(ctx); err != nil {
		i.logger.Warn("[FIRSTBOOT] Failed to install firstboot-log-upload service", "error", err)
		// Don't fail - debug log upload is best-effort
	}

	// Install platformd OpenRC service
	if err := i.installPlatformdService(ctx); err != nil {
		i.logger.Warn("[FIRSTBOOT] Failed to install platformd service", "error", err)
		// Don't fail - service can be installed manually
	}

	return nil
}

// installPlatformdService installs the platformd OpenRC service
// This service starts the platform daemon (web services auto-start if configured)
func (i *installer) installPlatformdService(ctx context.Context) error {
	i.logger.Info("[PLATFORMD] Installing platformd OpenRC service")

	mountPoint := "/mnt"
	initdDir := filepath.Join(mountPoint, "etc", "init.d")

	// Build base command args
	baseArgs := "--platform-dir=/var/lib/trusted-platform --config-dir=/etc/trusted-platform --log-dir=/var/log/trusted-platform"
	if i.config.Environment != "" {
		baseArgs += " --env " + i.config.Environment
		i.logger.Info("[PLATFORMD] Using environment", "env", i.config.Environment)
	}

	// Create platformd OpenRC service script
	// platformd auto-detects initialization state and self-provisions when needed
	platformdService := fmt.Sprintf(`#!/sbin/openrc-run

description="Trusted Platform daemon"

command="/usr/sbin/platformd"
command_background=true
pidfile="/run/platformd.pid"
output_log="/var/log/trusted-platform/platformd.log"
error_log="/var/log/trusted-platform/platformd.log"

BASE_ARGS="%s"

depend() {
    need localmount networking ovsdb-server ovs-vswitchd
    after tpm-firstboot-seal
    keyword -shutdown
}

start_pre() {
    mkdir -p /var/lib/trusted-platform
    mkdir -p /var/log/trusted-platform
    mkdir -p /etc/trusted-platform
    command_args="serve $BASE_ARGS"

    # Wait for ovs-vswitchd to populate the Open_vSwitch root row in
    # OVSDB before platformd tries to create bridges. On cold boots
    # (especially fresh installs), ovs-vswitchd can take 60-180s to
    # finish its startup dance; without this gate, platformd's own
    # retry window exhausts and SDN init gets deferred permanently.
    einfo "Waiting for ovs-vswitchd to populate Open_vSwitch root row..."
    local deadline=$(( $(date +%%s) + 300 ))
    while [ $(date +%%s) -lt $deadline ]; do
        if ovs-vsctl --timeout=3 list Open_vSwitch 2>/dev/null | grep -q '^_uuid'; then
            einfo "OVS root row populated"
            return 0
        fi
        sleep 2
    done
    ewarn "OVS root row never appeared within 300s — platformd will retry, SDN may defer"
}

start() {
    ebegin "Starting platformd"
    start-stop-daemon --start --background \
        --make-pidfile --pidfile "$pidfile" \
        --stdout "$output_log" --stderr "$error_log" \
        --exec $command -- $command_args
    eend $?
}

stop() {
    ebegin "Stopping platformd"
    start-stop-daemon --stop --pidfile "$pidfile"
    eend $?
}
`, baseArgs)

	platformdServicePath := filepath.Join(initdDir, "platformd")
	if err := os.WriteFile(platformdServicePath, []byte(platformdService), 0755); err != nil {
		return &WrappedError{Msg: "failed to write platformd service", Err: err}
	}
	i.logger.Info("[PLATFORMD] Created platformd OpenRC service")

	// Enable platformd service in default runlevel
	rcUpdateCmd := exec.CommandContext(ctx, "chroot", mountPoint, "rc-update", "add", "platformd", "default")
	if output, err := rcUpdateCmd.CombinedOutput(); err != nil {
		i.logger.Warn("[PLATFORMD] Failed to enable platformd service", "error", err, "output", string(output))
		// Don't fail, service can be enabled manually
	} else {
		i.logger.Info("[PLATFORMD] Enabled platformd service in default runlevel")
	}

	i.logger.Info("[PLATFORMD] Platformd installation complete")
	return nil
}

// installFirstbootLogUploadService installs an OpenRC service that uploads
// diagnostic logs to the bootstrap server on first boot. The service only
// activates when platform_debug=1 is present on the kernel command line and
// disables itself after a successful upload.
func (i *installer) installFirstbootLogUploadService(ctx context.Context) error {
	i.logger.Info("[LOG-UPLOAD] Installing firstboot-log-upload OpenRC service")

	mountPoint := "/mnt"
	initdDir := filepath.Join(mountPoint, "etc", "init.d")
	if err := os.MkdirAll(initdDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create /etc/init.d directory", Err: err}
	}

	logUploadService := `#!/sbin/openrc-run

description="First-boot diagnostic log upload to bootstrap server"

depend() {
    need localmount networking
    after platformd
    keyword -shutdown
}

start() {
    ebegin "First-boot log upload"

    # Only run in debug mode
    if ! grep -q 'platform_debug=1' /proc/cmdline 2>/dev/null; then
        einfo "platform_debug=1 not set on kernel cmdline, skipping log upload"
        eend 0
        return 0
    fi

    # Extract debug sink from kernel cmdline
    SINK=$(cat /proc/cmdline 2>/dev/null | tr ' ' '\n' | grep '^platform_debug_sink=' | cut -d= -f2- | tail -1)
    if [ -z "$SINK" ]; then
        ewarn "platform_debug_sink not found on kernel cmdline, cannot upload logs"
        eend 1
        return 1
    fi

    # Resolve hostname
    HOSTNAME_VAL=$(hostname 2>/dev/null | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9.\-]/-/g')
    case "$HOSTNAME_VAL" in
        ""|"-none-"|"none"|"localhost"|"alpine"|"alpinelinux") HOSTNAME_VAL="unknown" ;;
    esac

    LOGFILE="/tmp/firstboot-diagnostics.log"

    # Collect diagnostics
    {
        echo "=== FIRSTBOOT DIAGNOSTICS ==="
        echo "timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)"
        echo "hostname: ${HOSTNAME_VAL}"
        echo "kernel_cmdline: $(cat /proc/cmdline 2>/dev/null)"
        echo ""
        echo "--- hostname ---"
        hostname 2>&1 || true
        echo ""
        echo "--- ip addr ---"
        ip addr 2>&1 || true
        echo ""
        echo "--- rc-status ---"
        rc-status 2>&1 || true
        echo ""
        echo "--- dmesg ---"
        dmesg 2>&1 || true
        echo ""
        echo "--- platformd.log ---"
        if [ -f /var/log/trusted-platform/platformd.log ]; then
            cat /var/log/trusted-platform/platformd.log 2>&1 || true
        else
            echo "(not found)"
        fi
        echo ""
        echo "=== END FIRSTBOOT DIAGNOSTICS ==="
    } > "$LOGFILE" 2>/dev/null || true

    URL="http://${SINK}/installs/${HOSTNAME_VAL}/firstboot.log"
    einfo "Uploading firstboot diagnostics to ${URL}"

    UPLOAD_OK=false
    if command -v curl >/dev/null 2>&1; then
        if curl --silent --show-error --max-time 30 \
             --request PUT --upload-file "$LOGFILE" "${URL}" 2>&1; then
            UPLOAD_OK=true
        fi
    elif command -v wget >/dev/null 2>&1; then
        if wget --quiet --timeout=30 --method=PUT \
             --body-file="$LOGFILE" "${URL}" -O /dev/null 2>&1; then
            UPLOAD_OK=true
        fi
    else
        eerror "Neither curl nor wget available for log upload"
        eend 1
        return 1
    fi

    rm -f "$LOGFILE"

    if [ "$UPLOAD_OK" = "true" ]; then
        einfo "Firstboot log upload succeeded"
        # Disable this service so it does not run again
        rc-update del firstboot-log-upload default 2>/dev/null || true
        eend 0
        return 0
    else
        ewarn "Firstboot log upload failed"
        eend 1
        return 1
    fi
}

stop() {
    return 0
}
`

	servicePath := filepath.Join(initdDir, "firstboot-log-upload")
	if err := os.WriteFile(servicePath, []byte(logUploadService), 0755); err != nil {
		return &WrappedError{Msg: "failed to write firstboot-log-upload service", Err: err}
	}
	i.logger.Info("[LOG-UPLOAD] Created firstboot-log-upload OpenRC service")

	// Enable firstboot-log-upload service in default runlevel
	rcUpdateCmd := exec.CommandContext(ctx, "chroot", mountPoint, "rc-update", "add", "firstboot-log-upload", "default")
	if output, err := rcUpdateCmd.CombinedOutput(); err != nil {
		i.logger.Warn("[LOG-UPLOAD] Failed to enable firstboot-log-upload service", "error", err, "output", string(output))
		// Don't fail, service can be enabled manually
	} else {
		i.logger.Info("[LOG-UPLOAD] Enabled firstboot-log-upload service in default runlevel")
	}

	return nil
}

// enrollFIDO2 enrolls a FIDO2 security key for LUKS unlock
// This follows the reference at build/iso/alpine/amd64/scripts/host/fido2-enroll.sh
func (i *installer) enrollFIDO2(ctx context.Context, diskInfo *DiskInfo) error {
	i.logger.Info("[FIDO2] Starting FIDO2 security key enrollment")

	if i.config.Disk.Encryption == nil {
		return &MessageError{Msg: "FIDO2 enrollment requires LUKS encryption"}
	}

	// Get LUKS passphrase
	passphrase := i.config.Disk.Encryption.Passphrase
	if passphrase == "" {
		passphrase = i.config.Disk.Encryption.Password
	}
	if passphrase == "" {
		return &MessageError{Msg: "LUKS passphrase required for FIDO2 enrollment"}
	}

	// Configure FIDO2 enrollment
	fido2Config := &FIDO2EnrollmentConfig{
		LUKSDevice:     diskInfo.RootPartition,
		LUKSPassphrase: passphrase,
		FIPSMode:       i.config.OS != nil && i.config.OS.FIPS,
		Debug:          i.config.Debug,
	}

	// Apply user configuration if provided
	if i.config.FIDO2 != nil {
		if i.config.FIDO2.RelyingPartyID != "" {
			fido2Config.RelyingPartyID = i.config.FIDO2.RelyingPartyID
		}
		if i.config.FIDO2.Keyslot != 0 {
			fido2Config.TargetKeyslot = i.config.FIDO2.Keyslot
		}
	}

	// Create enrollment handler
	enrollment, err := NewFIDO2Enrollment(fido2Config)
	if err != nil {
		return &WrappedError{Msg: "failed to create FIDO2 enrollment handler", Err: err}
	}

	// Perform enrollment
	if err := enrollment.Enroll(ctx); err != nil {
		return &WrappedError{Msg: "FIDO2 enrollment failed", Err: err}
	}

	i.logger.Info("[FIDO2] Security key enrolled successfully",
		"device", diskInfo.RootPartition,
		"keyslot", fido2Config.TargetKeyslot,
		"rp", fido2Config.RelyingPartyID)

	return nil
}

// Close releases resources
func (i *installer) Close() error {
	if i.diskManager != nil {
		if err := i.diskManager.Close(); err != nil {
			return err
		}
	}
	return nil
}

// writeFirstbootNetworkConfig writes a simple network config file to the EFI partition
// This file is used by the initramfs/dracut hook to configure networking before ACME enrollment
// The file format is simple key=value pairs that are easy to parse in shell scripts
func (i *installer) writeFirstbootNetworkConfig(efiDir string) error {
	if i.config.Network == nil || len(i.config.Network.Interfaces) == 0 {
		i.logger.Info("[TPM] No network configuration found, skipping firstboot network config")
		return nil
	}

	// Find the first static interface configuration
	var networkConfig strings.Builder
	networkConfig.WriteString("# Firstboot network configuration\n")
	networkConfig.WriteString("# Generated by installer for initramfs network setup\n\n")

	for _, iface := range i.config.Network.Interfaces {
		if iface.Type == "static" && iface.IPv4Address != "" {
			// IPV4_ADDRESS is written bare and the prefix separately: the
			// dracut hook joins them itself, so a CIDR suffix here would be
			// applied twice ("a.b.c.d/24/24") and the interface would get
			// no address at all.
			bare, prefix, err := firstbootStaticAddress(iface.IPv4Address, iface.IPv4Netmask)
			if err != nil {
				return err
			}
			fmt.Fprintf(&networkConfig, "INTERFACE=%s\n", iface.Name)
			fmt.Fprintf(&networkConfig, "TYPE=%s\n", iface.Type)
			fmt.Fprintf(&networkConfig, "IPV4_ADDRESS=%s\n", bare)
			fmt.Fprintf(&networkConfig, "IPV4_PREFIX=%d\n", prefix)
			fmt.Fprintf(&networkConfig, "IPV4_NETMASK=%s\n", iface.IPv4Netmask)
			fmt.Fprintf(&networkConfig, "IPV4_GATEWAY=%s\n", iface.IPv4Gateway)
			break // Only configure first static interface
		} else if iface.Type == "dhcp" {
			fmt.Fprintf(&networkConfig, "INTERFACE=%s\n", iface.Name)
			networkConfig.WriteString("TYPE=dhcp\n")
			break
		}
	}

	// Add DNS configuration if available
	// Quote the value to handle multiple DNS servers separated by spaces
	if i.config.Network.DNS != nil && len(i.config.Network.DNS.Nameservers) > 0 {
		fmt.Fprintf(&networkConfig, "DNS=\"%s\"\n", strings.Join(i.config.Network.DNS.Nameservers, " "))
	}

	// Add hostname from OS config - critical for IAK/IDevID certificate naming
	// This must be set before App.Init() during firstboot to avoid "(none)" hostnames
	if i.config.OS != nil && i.config.OS.Hostname != "" {
		fmt.Fprintf(&networkConfig, "HOSTNAME=%s\n", i.config.OS.Hostname)
	}

	networkConfigPath := filepath.Join(efiDir, "network.conf")
	if err := os.WriteFile(networkConfigPath, []byte(networkConfig.String()), 0644); err != nil {
		return &WrappedError{Msg: "failed to write network config", Err: err}
	}

	i.logger.Info("[TPM] Firstboot network config written", "path", networkConfigPath)

	return nil
}

// writeInitialPCRBanks writes a minimal pcr-banks file containing only the
// seal-pcrs line, before firstboot has had a chance to write the full
// authoritative version. It lets the dracut unlock hook (which reads
// /boot/efi/tpm2/pcr-banks to decide the --pcrs flag for platform-initrd)
// work correctly on the very first boot. firstboot overwrites this file
// with the full set of fields (platform-pcr, keystore-srk-handle,
// ssrk-handle, etc) once TPM provisioning has populated them.
func (i *installer) writeInitialPCRBanks(efiDir string) error {
	if len(i.config.PCRs) == 0 {
		i.logger.Info("[TPM] No seal-pcrs configured, skipping initial pcr-banks write")
		return nil
	}

	// Format PCRs as comma-separated decimal (matches firstboot's output).
	pcrStrs := make([]string, 0, len(i.config.PCRs))
	for _, p := range i.config.PCRs {
		pcrStrs = append(pcrStrs, fmt.Sprintf("%d", p))
	}
	pcrLine := fmt.Sprintf("seal-pcrs=%s\n", strings.Join(pcrStrs, ","))

	pcrBanksPath := filepath.Join(efiDir, "pcr-banks")
	if err := os.WriteFile(pcrBanksPath, []byte(pcrLine), 0644); err != nil {
		return &WrappedError{Msg: "failed to write initial pcr-banks", Err: err}
	}

	i.logger.Info("[TPM] Initial pcr-banks written",
		"path", pcrBanksPath,
		"seal-pcrs", strings.Join(pcrStrs, ","))

	return nil
}
