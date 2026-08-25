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

package firstboot

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platform "github.com/jeremyhahn/go-trusted-platform/pkg/platform"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uefi/firmware"
)

const (
	// Encrypted installer container on EFI partition (100MB)
	// Presence indicates first boot - contains everything needed for provisioning
	//
	// INSTALLER creates this with:
	//   /luks-key.bin                      - 32-byte LUKS encryption key
	//   /recovery-key.txt                  - Human-readable recovery key
	//   /etc/trusted-platform/config.yaml  - Platform configuration
	//
	// FIRSTBOOT adds during provisioning:
	//   /var/lib/trusted-platform/...      - Full platform state (CA, keys, etc.)
	//   /var/log/trusted-platform/...      - Logs
	//
	// After LUKS unlock, contents are copied to root filesystem, then container
	// is securely wiped. EFI partition must be at least 200MB to hold this.
	strategyInstallerContainerFile = "tpm2/installer.luks"

	// Installer container mount point during firstboot
	strategyInstallerMountPoint = "/mnt/installer"

	// Platform SRK sealed blob files on EFI - created after first boot sealing
	// These are sealed under Platform KeyStore SRK with platform policy
	strategySealPub  = "tpm2/seal-platform.pub"
	strategySealPriv = "tpm2/seal-platform.priv"
	strategyPCRBanks = "tpm2/pcr-banks"

	// Upgrade seal files (no PCR policy) - fallback for kernel upgrades
	strategyUpgradePub  = "tpm2/seal-upgrade.pub"
	strategyUpgradePriv = "tpm2/seal-upgrade.priv"

	// EFI mount point
	strategyEFIMountPoint = "/boot/efi"

	// Marker directory for post-switch_root file copying
	strategyMarkerDir = "/run/initramfs/firstboot"

	// Marker file for copy operation
	strategyCopyMarker = "tpm2/.copy-platform-state"

	// Device-node directories the root volume is resolved against
	strategyDevDir       = "/dev"
	strategyDevMapperDir = "/dev/mapper"
)

// FirstbootSealStrategy handles first boot TPM sealing using the ENCRYPTED INSTALLER approach.
//
// SECURITY MODEL:
// All provisioning happens INSIDE the encrypted installer container. This ensures:
//   - All sensitive data (CA keys, platform state) stays encrypted until copied to root
//   - Single secure wipe destroys all provisioning artifacts
//   - No plaintext secrets ever written to unencrypted storage
//
// FLOW:
//  1. Open encrypted installer.luks container (contains LUKS key, recovery key, config)
//  2. Create directory structure inside installer for provisioning
//  3. Run platform provisioning INTO the installer (all output encrypted)
//  4. Seal LUKS key to TPM with PCR policy
//  5. Unlock LUKS root partition
//  6. Copy installer contents to root filesystem
//  7. Secure wipe installer container
//
// Priority: 0 (highest) - must run before TPM-PCR to handle first boot
type FirstbootSealStrategy struct {
	executor *Executor
	logger   *logging.Logger
	priority int
	luks     luks.Handler
}

// NewFirstbootSealStrategy creates a new first boot sealing strategy
func NewFirstbootSealStrategy(executor *Executor, luksHandler luks.Handler, logger *logging.Logger) *FirstbootSealStrategy {
	return &FirstbootSealStrategy{
		executor: executor,
		logger:   logger,
		priority: 0,
		luks:     luksHandler,
	}
}

// Name returns the strategy name
func (s *FirstbootSealStrategy) Name() string {
	return "Firstboot-Seal"
}

// Priority returns the execution priority (0 = highest)
func (s *FirstbootSealStrategy) Priority() int {
	return s.priority
}

// CanUnlock checks if this is first boot (installer.luks exists, no sealed blobs)
func (s *FirstbootSealStrategy) CanUnlock(ctx context.Context, volume *luks.VolumeConfig) bool {
	efiPath := s.getEFIPath()
	mounted, err := s.ensureEFIMounted()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Cannot check EFI partition: %v\n", err)
		return false
	}
	defer func() {
		if !mounted {
			s.unmountEFI()
		}
	}()

	installerPath := filepath.Join(efiPath, strategyInstallerContainerFile)
	sealPubPath := filepath.Join(efiPath, strategySealPub)

	// Check if encrypted installer exists (first boot indicator)
	if _, err := os.Stat(installerPath); err != nil {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] No installer.luks found - not first boot\n")
		return false
	}

	// Check if sealed blobs already exist (shouldn't on first boot)
	if _, err := os.Stat(sealPubPath); err == nil {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Sealed blobs exist - not first boot\n")
		return false
	}

	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] First boot detected - installer.luks exists, no sealed blobs\n")
	return true
}

// Unlock performs first boot using ENCRYPTED INSTALLER approach:
//  1. Open installer container and mount read-write
//  2. Read LUKS key and recovery key from installer
//  3. Provision platform INSIDE installer (everything encrypted)
//  4. Seal LUKS key to TPM
//  5. Unlock LUKS root partition
//  6. Copy installer contents to root (platform state, config, recovery key)
//  7. Close installer (unmount, lock LUKS, secure wipe)
//
// After this function completes, the initrd performs switch_root and the
// system boots with all platform state already copied to the root filesystem.
func (s *FirstbootSealStrategy) Unlock(ctx context.Context, volume *luks.VolumeConfig) error {
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] ========================================\n")
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] FIRST BOOT - ENCRYPTED INSTALLER APPROACH\n")
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] All provisioning happens inside encrypted container\n")
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] ========================================\n")

	// Ensure EFI is mounted read-write
	efiPath := s.getEFIPath()
	wasMounted, err := s.ensureEFIMountedRW()
	if err != nil {
		return &WrappedError{Msg: "failed to mount EFI partition", Err: err}
	}
	defer func() {
		if !wasMounted {
			s.unmountEFI()
		}
	}()

	installerPath := filepath.Join(efiPath, strategyInstallerContainerFile)

	// STEP 1: Open and mount installer container
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] ----------------------------------------\n")
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] STEP 1: Opening encrypted installer container\n")
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] ----------------------------------------\n")

	loopDev, err := s.openInstaller(installerPath)
	if err != nil {
		return &WrappedError{Msg: "failed to open installer", Err: err}
	}
	// Forensic dump: every entry into Unlock() leaves a snapshot of the
	// kernel ring buffer, block-device topology, and LUKS state inside the
	// (still mounted) installer container. The container is preserved on
	// seal-retry, so an operator can read these from a rescue boot or via
	// platformctl after the system comes up. This is the firstboot
	// equivalent of pkg/iso/customize.go's autoinstall upload_install_log
	// pipeline, but file-based instead of HTTP-based — initrd networking
	// is fragile and we can't depend on it being up at the moment of
	// failure.
	defer s.dumpFirstbootForensics()
	// Track whether we should wipe the installer on cleanup
	// Only wipe after successful sealing - NOT on fallback to plain key
	sealingSucceeded := false
	wipePasses := s.getSecureWipePasses()
	if wipePasses <= 0 {
		wipePasses = 1 // Default to NIST SP 800-88
	}
	defer func() {
		s.closeInstaller(loopDev, installerPath, wipePasses, sealingSucceeded)
	}()

	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Installer mounted at %s\n", strategyInstallerMountPoint)

	// STEP 2: Read LUKS key and recovery key
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] ----------------------------------------\n")
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] STEP 2: Reading keys from installer\n")
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] ----------------------------------------\n")

	luksKeyPath := filepath.Join(strategyInstallerMountPoint, "luks-key.bin")
	recoveryKeyPath := filepath.Join(strategyInstallerMountPoint, "recovery-key.txt")

	luksKey, err := os.ReadFile(luksKeyPath)
	if err != nil {
		return &WrappedError{Msg: "failed to read LUKS key", Err: err}
	}
	defer clearBytes(luksKey)

	if len(luksKey) != 32 {
		return &MessageError{Msg: fmt.Sprintf("invalid LUKS key size: expected 32, got %d", len(luksKey))}
	}
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] LUKS key read (32 bytes)\n")

	// DEBUG: Log key hash for verification against installer
	keyHash := sha256.Sum256(luksKey)
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] DEBUG: LUKS key hash (first 8 bytes): %x\n", keyHash[:8])

	var recoveryKey string
	if data, err := os.ReadFile(recoveryKeyPath); err == nil {
		recoveryKey = string(data)
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Recovery key read\n")
	}

	// STEP 3: Provision platform INTO the installer
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] ----------------------------------------\n")
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] STEP 3: Provisioning platform inside installer\n")
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] All output encrypted - maximum security\n")
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] ----------------------------------------\n")

	// Mount securityfs if not already mounted - required for TPM event log access
	// The binary_bios_measurements file is at /sys/kernel/security/tpm0/binary_bios_measurements
	securityfsPath := "/sys/kernel/security"
	if _, err := os.Stat(filepath.Join(securityfsPath, "tpm0")); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Mounting securityfs for TPM event log access...\n")
		if err := os.MkdirAll(securityfsPath, 0755); err == nil {
			if err := syscall.Mount("securityfs", securityfsPath, "securityfs", 0, ""); err != nil {
				fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] WARNING: Failed to mount securityfs: %v\n", err)
				fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] TPM event log may not be available\n")
			} else {
				fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Securityfs mounted successfully\n")
			}
		}
	} else {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Securityfs already mounted (tpm0 exists)\n")
	}

	// Check TPM event log availability for attestation
	// Wait for the file to have content (kernel may need time to process ACPI event log)
	eventLogPath := filepath.Join(securityfsPath, "tpm0", "binary_bios_measurements")
	var eventLogSize int64
	for i := 0; i < 10; i++ {
		if fileInfo, err := os.Stat(eventLogPath); err == nil {
			eventLogSize = fileInfo.Size()
			if eventLogSize > 0 {
				fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] TPM event log available: %s (%d bytes)\n", eventLogPath, eventLogSize)
				break
			}
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] TPM event log file exists but empty (%d/10)...\n", i+1)
		} else {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Waiting for TPM event log (%d/10): %v\n", i+1, err)
		}
		// Try to trigger TPM driver to process ACPI event log by reading from TPM device
		if f, err := os.Open("/dev/tpm0"); err == nil {
			f.Close()
		}
		time.Sleep(time.Second)
	}
	if eventLogSize == 0 {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] WARNING: TPM event log NOT available or empty\n")
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Attestation data will be incomplete\n")
	}

	// sealRetryNeeded is set when provisioning OR sealing fails. The boot
	// continues — LUKS gets unlocked with the plain key from the installer,
	// the installer container is preserved (NOT wiped) so next boot can
	// retry, and a marker file is dropped on the rootfs so platformd can
	// surface the degraded state in the admin panel.
	sealRetryNeeded := false
	sealRetryReason := ""

	// IDEMPOTENCY GUARD: detect prior provisioning. If a previous boot
	// already ran TPM Install, the OWNER hierarchy auth has been set to
	// some TPM-derived value that we don't know how to reproduce on
	// subsequent boots without a stored secret. Re-running Install with
	// nil hierarchy auth fails with TPM_RC_BAD_AUTH and aborts the entire
	// firstboot flow — the failure mode observed on lab-node-2 second boot
	// 2026-04-08 (rc=1, manual entry fallback).
	//
	// The fix: skip TPM provisioning AND sealing entirely if a sealed
	// platform key has already been written to the EFI partition. The
	// matching executor.go path (line 185) uses the same artifact
	// (`seal-platform.pub`) as its sealed-state probe, so the two code
	// paths agree on what "previously provisioned" means.
	//
	// IMPORTANT: do NOT use pcr-banks as a marker. pcr-banks is written
	// pre-pivot by the installer to tell platform-initrd which PCR
	// algorithms to extend; it exists on EVERY successful install boot,
	// regardless of whether sealing has actually completed. Treating it
	// as a "prior provisioning" signal silently skips TPM provisioning
	// (and therefore the IAK/IDevID enrollment ceremony that gates ACME
	// enroll-01) on every fresh first boot — leaving each freshly-
	// installed node enrolled against its own local CA forever. That
	// false-positive bit a 2026-05-02 GW reflash where enroll-01 against
	// the CP never fired and no DNS records got registered.
	priorProvisioning := false
	for _, marker := range []string{
		filepath.Join(efiPath, "tpm2", "seal-platform.pub"),
		filepath.Join(efiPath, strategySealPub),
	} {
		if _, err := os.Stat(marker); err == nil {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] PRIOR-PROVISIONING DETECTED: %s exists — skipping TPM provisioning + sealing\n", marker)
			priorProvisioning = true
			break
		}
	}

	if priorProvisioning {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Idempotent path: skipping provisionInsideInstaller and sealKeyToTPM\n")
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Will unlock LUKS with plain key from installer container only\n")
		sealRetryNeeded = true
		sealRetryReason = "idempotent skip: prior provisioning artifacts present"
	} else if err := s.provisionInsideInstaller(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] ERROR: Provisioning failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Marking seal-retry-needed and continuing with plain-key boot\n")
		sealRetryNeeded = true
		sealRetryReason = fmt.Sprintf("provisionInsideInstaller: %v", err)
	} else {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Platform provisioned inside encrypted installer\n")

		// STEP 4: Seal LUKS key to TPM
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] ----------------------------------------\n")
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] STEP 4: Sealing LUKS key to TPM\n")
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] ----------------------------------------\n")

		if err := s.sealKeyToTPM(ctx, luksKey, efiPath); err != nil {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] ERROR: TPM sealing failed: %v\n", err)
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Marking seal-retry-needed and continuing with plain-key boot\n")
			sealRetryNeeded = true
			sealRetryReason = fmt.Sprintf("sealKeyToTPM: %v", err)
		} else {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] LUKS key sealed to TPM with PCR policy\n")
			// IMPORTANT: do NOT set sealingSucceeded=true yet. Seal must
			// be validated by a subsequent unseal before we wipe. See
			// next-boot validation TODO.
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] NOTE: installer container preserved pending next-boot unseal validation\n")
		}
	}

	// Set TRUSTED_PLATFORM EFI variable to indicate successful provisioning.
	// Only set this when sealing actually succeeded — if we're in retry
	// mode, the system is NOT fully provisioned and the variable would lie.
	if !sealRetryNeeded {
		if firmware.IsAvailable() {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Setting TRUSTED_PLATFORM EFI variable...\n")
			if err := firmware.SetTrustedPlatform(); err != nil {
				fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] WARNING: Failed to set TRUSTED_PLATFORM EFI variable: %v\n", err)
				// This is not a fatal error - the system is still provisioned
			} else {
				fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] TRUSTED_PLATFORM EFI variable set to 'true'\n")
			}
		} else {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] efivarfs not available - skipping TRUSTED_PLATFORM EFI variable (VM environment)\n")
		}
	} else {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Skipping TRUSTED_PLATFORM EFI variable — sealing did not complete (seal-retry mode)\n")
	}

	// STEP 5: Unlock LUKS root partition
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] ----------------------------------------\n")
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] STEP 5: Unlocking LUKS root partition\n")
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] ----------------------------------------\n")

	// Check if LUKS root partition is already unlocked (e.g., by dracut during boot)
	if s.luks.IsOpen(ctx, volume.MappingName) {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] LUKS root partition already unlocked (mapping %s exists)\n", volume.MappingName)
	} else {
		openOpts := &luks.OpenOptions{
			AllowDiscards: volume.AllowDiscards,
			Timeout:       volume.Timeout,
		}
		if err := s.luks.Open(ctx, volume.DevicePath, volume.MappingName, luksKey, openOpts); err != nil {
			return &WrappedError{Msg: "luks unlock failed", Err: err}
		}
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] LUKS root partition unlocked\n")
	}

	// DEBUG: Check device node state after LUKS unlock
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] DEBUG: Checking device nodes after unlock...\n")
	if output, err := exec.Command("ls", "-la", "/dev/mapper/").CombinedOutput(); err == nil {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] DEBUG: /dev/mapper/ contents:\n%s\n", string(output))
	} else {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] DEBUG: Failed to list /dev/mapper/: %v\n", err)
	}
	if output, err := exec.Command("ls", "-la", "/dev/dm-*").CombinedOutput(); err == nil {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] DEBUG: /dev/dm-* devices:\n%s\n", string(output))
	} else {
		// Try with shell expansion
		if output2, err2 := exec.Command("sh", "-c", "ls -la /dev/dm-* 2>/dev/null || echo 'No dm-* devices'").CombinedOutput(); err2 == nil {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] DEBUG: /dev/dm-* devices:\n%s\n", string(output2))
		}
	}
	// Check cryptroot specifically
	mapperPath := fmt.Sprintf("/dev/mapper/%s", volume.MappingName)
	if fi, err := os.Lstat(mapperPath); err == nil {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] DEBUG: %s exists, mode=%v\n", mapperPath, fi.Mode())
		if fi.Mode()&os.ModeSymlink != 0 {
			if target, err := os.Readlink(mapperPath); err == nil {
				fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] DEBUG: %s -> %s\n", mapperPath, target)
				if targetFi, err := os.Stat(target); err == nil {
					fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] DEBUG: Target %s exists, mode=%v\n", target, targetFi.Mode())
				} else {
					fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] DEBUG: Target %s does NOT exist: %v\n", target, err)
				}
			}
		}
	} else {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] DEBUG: %s does NOT exist: %v\n", mapperPath, err)
	}
	// Check if we can actually read from the device
	if f, err := os.Open(mapperPath); err == nil {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] DEBUG: %s is readable\n", mapperPath)
		// Read first 512 bytes to check for LVM PV signature
		buf := make([]byte, 512)
		if n, readErr := f.Read(buf); readErr == nil && n >= 512 {
			// LVM PV signature is "LABELONE" at offset 0 or 512 or 1024
			// Check for signature
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] DEBUG: First 64 bytes of decrypted device:\n")
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] DEBUG: %x\n", buf[:64])
			// Check for LABELONE signature (ASCII: 4c 41 42 45 4c 4f 4e 45)
			if buf[0] == 'L' && buf[1] == 'A' && buf[2] == 'B' && buf[3] == 'E' && buf[4] == 'L' {
				fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] DEBUG: Found LVM LABELONE signature at offset 0!\n")
			} else {
				fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] DEBUG: NO LVM signature at offset 0 (expected LABELONE)\n")
			}
		} else {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] DEBUG: Failed to read first sector: %v\n", readErr)
		}
		f.Close()
	} else {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] DEBUG: %s is NOT readable: %v\n", mapperPath, err)
	}
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] DEBUG: Device node check complete\n")

	// STEP 6: Copy installer contents to root filesystem BEFORE switch_root
	// This must happen now while installer is still mounted
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] ----------------------------------------\n")
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] STEP 6: Copying installer contents to root filesystem\n")
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] ----------------------------------------\n")

	if err := s.copyInstallerToRoot(volume.MappingName, recoveryKey, sealRetryReason); err != nil {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] WARNING: Failed to copy installer contents: %v\n", err)
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Platform state may not be available after boot\n")
	} else {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Installer contents copied to root filesystem\n")
	}

	// Preserve luks-key.bin ALWAYS (until a future seal-validation
	// handshake proves the TPM unseal works on a clean reboot). Deleting
	// the keyfile now leaves the system with no fallback when the next
	// boot's TPM unseal fails — exactly the failure mode that left lab-node-2
	// stuck on 2026-04-08: post-pivot firstboot sealed successfully,
	// deleted the keyfile, then the next boot's TPM-PCR strategy failed
	// (848ms FAILED) and the Keyfile strategy had nothing to read.
	//
	// Cost: the LUKS key plaintext lives in the LUKS-encrypted installer
	// container indefinitely. The installer container is itself encrypted
	// at rest and is mounted only inside initrd, so the exposure is the
	// same as it was during the first boot. The eventual fix is a
	// .tpm-seal-confirmed handshake that performs a real unseal test
	// before authorizing deletion.
	_ = luksKeyPath
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] luks-key.bin preserved (deletion deferred to seal-confirmation handshake)\n")

	// (seal-retry marker is dropped inside copyInstallerToRoot while the
	// rootfs is still mounted — see that function for the write path)

	// STEP 7: Apply recovery-key strategy (destroy | escrow)
	// This decides what happens to the LUKS recovery passphrase that the
	// installer wrote to slot 2 of the root device. The operator chooses
	// the disposition via installer config:
	//   - destroy: kill slot 2, shred the plaintext, no leftover
	//   - escrow:  keep slot 2, stage plaintext at tmpfs handoff path for
	//              platformd to push into the tenant secret store on
	//              first run, then shred the tmpfs copy.
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] ----------------------------------------\n")
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] STEP 7: Applying recovery-key strategy\n")
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] ----------------------------------------\n")
	strategyApplied, strategyErr := s.applyRecoveryKeyStrategy(volume.DevicePath, recoveryKey)
	if strategyErr != nil {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] WARNING: Recovery-key strategy failed: %v\n", strategyErr)
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Continuing — the system will still boot, operator can reconcile later\n")
	}
	// Scrub the in-memory copy of the recovery passphrase now that the
	// strategy has either destroyed it or handed it off to tmpfs.
	clearString(&recoveryKey)

	syscall.Sync()

	// Resolve the seal parent handle for the summary message
	sealParentHandle := s.getLUKSSealParentHandle()

	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] ========================================\n")
	if sealRetryNeeded {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] FIRST BOOT COMPLETE — DEGRADED (seal retry needed)\n")
	} else {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] FIRST BOOT COMPLETE\n")
	}
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] ========================================\n")
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] - Platform provisioned inside encrypted installer: %v\n", !sealRetryNeeded)
	if sealRetryNeeded {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] - SEAL-RETRY REASON: %s\n", sealRetryReason)
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] - Installer container PRESERVED for next-boot retry\n")
	} else {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] - LUKS key sealed to TPM SSRK (handle 0x%08x)\n", sealParentHandle)
	}
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] - Root partition unlocked\n")
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] - Installer contents copied to root filesystem\n")
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] - Recovery-key strategy: %s\n", strategyApplied)
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] ========================================\n")

	// SECURITY: the root filesystem is unlocked, but when sealing did not
	// complete the unlock came from the plain key. Report that as an error
	// so the caller's exit code is non-zero, the OpenRC tpm-firstboot-seal
	// service does not mark itself started, and firstboot re-runs on the
	// next boot. Returning nil here is what silently downgraded security
	// and reported "Installation completed successfully" while platformd
	// crashed at startup with TPM_RC_POLICY_FAIL (lab-node-2, 2026-04-07).
	if sealRetryNeeded {
		return ErrSealingFallbackUsed
	}

	return nil
}

// openInstaller opens and mounts the encrypted installer container
// If the installer is already mounted (by dracut hook), returns empty loopDev and skips opening
func (s *FirstbootSealStrategy) openInstaller(installerPath string) (string, error) {
	// Check if installer is already mounted by dracut hook
	// The dracut hook mounts it at /mnt/installer before calling platformd
	testFile := filepath.Join(strategyInstallerMountPoint, "luks-key.bin")
	if _, err := os.Stat(testFile); err == nil {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Installer already mounted at %s (by dracut hook)\n", strategyInstallerMountPoint)
		// Return empty loopDev to indicate we didn't open it
		return "", nil
	}

	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Setting up loop device for installer...\n")

	// Setup loop device
	loopDev, err := luks2.SetupLoopDevice(installerPath)
	if err != nil {
		return "", &WrappedError{Msg: "failed to setup loop device", Err: err}
	}

	// Unlock with well-known password
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Unlocking installer (forensic protection password)...\n")
	if err := luks2.Unlock(loopDev, []byte(installer.InstallerPassword), "installer"); err != nil {
		luks2.DetachLoopDevice(loopDev)
		return "", &WrappedError{Msg: "failed to unlock installer", Err: err}
	}

	// Get mapped device path
	installerDevPath, err := luks2.GetMappedDevicePath("installer")
	if err != nil {
		installerDevPath = "/dev/mapper/installer"
	}

	// Create and mount
	if err := os.MkdirAll(strategyInstallerMountPoint, 0700); err != nil {
		luks2.Lock("installer")
		luks2.DetachLoopDevice(loopDev)
		return "", &WrappedError{Msg: "failed to create mount point", Err: err}
	}

	// Mount read-write for provisioning
	if err := syscall.Mount(installerDevPath, strategyInstallerMountPoint, "ext4", 0, ""); err != nil {
		luks2.Lock("installer")
		luks2.DetachLoopDevice(loopDev)
		return "", &WrappedError{Msg: "failed to mount installer", Err: err}
	}

	return loopDev, nil
}

// closeInstaller unmounts and closes the installer, optionally wiping it
// Only wipes the installer.luks file if sealing succeeded - preserves it on fallback
// so the tpm-firstboot-seal service can retry sealing after boot
// passes: number of wipe passes (1=NIST, 3=DoD, 7=DoD-ECE)
// sealingSucceeded: if true, securely wipe the installer; if false, preserve it for retry
func (s *FirstbootSealStrategy) closeInstaller(loopDev, installerPath string, passes int, sealingSucceeded bool) {
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Closing installer...\n")

	// Stop DNS service first to release log file handles and prevent
	// file descriptor leaks that can block LUKS container closure
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Stopping DNS service...\n")
	if err := dns.Stop(); err != nil {
		// Not an error if DNS wasn't running
		if err != dns.ErrDNSNotRunning {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] WARNING: Failed to stop DNS service: %v\n", err)
		}
	} else {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] DNS service stopped\n")
	}

	// Give DNS goroutines time to clean up
	time.Sleep(200 * time.Millisecond)

	// Sync filesystem before any cleanup
	syscall.Sync()

	// Check if any processes are using the installer mount
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Checking for processes using installer mount...\n")
	var procs string
	if output, err := exec.Command("fuser", "-m", strategyInstallerMountPoint).CombinedOutput(); err == nil {
		procs = strings.TrimSpace(string(output))
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Processes using mount: %s\n", procs)
	}

	// Use lazy unmount (MNT_DETACH) which allows processes to continue using
	// their open file handles until they naturally close. This prevents the
	// firstboot process from being killed during cleanup.
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Unmounting installer (lazy)...\n")
	if err := syscall.Unmount(strategyInstallerMountPoint, syscall.MNT_DETACH); err != nil {
		// Try normal unmount as fallback
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Lazy unmount failed: %v, trying normal unmount...\n", err)
		if err := syscall.Unmount(strategyInstallerMountPoint, 0); err != nil {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] WARNING: Normal unmount also failed: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Normal unmount succeeded\n")
		}
	} else {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Lazy unmount succeeded\n")
	}
	_ = os.Remove(strategyInstallerMountPoint)

	// Wait for lazy unmount to complete and file handles to be released
	// Give services more time to shut down (the App.Close() was called earlier)
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Waiting for file handles to be released...\n")
	time.Sleep(500 * time.Millisecond)
	syscall.Sync()

	// If processes were found earlier, wait a bit more and check again
	if procs != "" {
		time.Sleep(500 * time.Millisecond)
	}

	// Close LUKS container with retries and increasing delays
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Closing LUKS container...\n")
	var luksErr error
	for i := 0; i < 10; i++ {
		if luksErr = luks2.Lock("installer"); luksErr == nil {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] LUKS container closed\n")
			break
		}
		if i < 9 {
			delay := time.Duration((i+1)*200) * time.Millisecond
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] LUKS close attempt %d failed: %v, retrying in %v...\n", i+1, luksErr, delay)
			// Try force-closing any remaining users of the device
			if i >= 3 {
				// After several attempts, try dmsetup remove --force
				if output, dmErr := exec.Command("dmsetup", "remove", "--force", "installer").CombinedOutput(); dmErr != nil {
					fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] dmsetup remove --force failed: %s\n", strings.TrimSpace(string(output)))
				}
			}
			time.Sleep(delay)
		}
	}
	if luksErr != nil {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] WARNING: Failed to close LUKS container: %v\n", luksErr)
		// Final attempt: dmsetup remove with deferred option
		if output, err := exec.Command("dmsetup", "remove", "--deferred", "installer").CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] dmsetup remove --deferred also failed: %s\n", strings.TrimSpace(string(output)))
		} else {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] LUKS container scheduled for deferred removal\n")
		}
	}

	// Detach loop device if we created it
	if loopDev != "" {
		if err := luks2.DetachLoopDevice(loopDev); err != nil {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] WARNING: Failed to detach loop device: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Loop device detached\n")
		}
	}

	// Only wipe if sealing succeeded - preserve installer for retry on fallback
	if !sealingSucceeded {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] ----------------------------------------\n")
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] PRESERVING installer.luks for retry\n")
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Sealing failed - tpm-firstboot-seal service will retry after boot\n")
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] ----------------------------------------\n")
		syscall.Sync()
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Installer cleanup complete (preserved)\n")
		return
	}

	// SECURE WIPE installer.luks - CRITICAL SECURITY STEP
	// The installer container has the plaintext LUKS key - must be destroyed
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] ----------------------------------------\n")
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] SECURE WIPE: Destroying installer.luks (%d passes)\n", passes)
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] ----------------------------------------\n")

	if err := secureWipeFile(installerPath, passes); err != nil {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] WARNING: Secure wipe failed: %v\n", err)
		// Try simple delete as fallback
		if err := os.Remove(installerPath); err != nil {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] WARNING: Failed to delete installer.luks: %v\n", err)
		}
	} else {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] installer.luks securely wiped\n")
	}

	syscall.Sync()
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Installer cleanup complete\n")
}

// provisionInsideInstaller runs minimal TPM provisioning (EK + SSRK only).
// PlatformSRK is NOT created here because PCR 9 differs between the installer
// initramfs and the production boot initramfs, so any PCR 23 policy bound to
// PlatformSRK would fail on subsequent boots. PlatformSRK creation is deferred
// to platformd on the first stable boot.
//
// TPM persistent handles survive OS reinstalls. To ensure a clean slate on
// firstboot, FactoryReset is called first to evict stale platform handles
// while preserving EK certificates provisioned by the manufacturer.
func (s *FirstbootSealStrategy) provisionInsideInstaller(ctx context.Context) error {
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Running minimal TPM provisioning (EK + SSRK only)...\n")

	if s.executor.TPM() == nil {
		return ErrTPMNotAvailable
	}

	// We DO NOT generate a hierarchy auth PIN here. firstboot used to
	// generate a random soPIN and pass it to FactoryReset+Install, which
	// caused TPM_RC_BAD_AUTH at platformd startup because the random PIN
	// was discarded when firstboot exited and platformd's autogen-derived
	// auth didn't match. Hierarchy auth is left empty after the (clear or
	// non-clear) reset pass, and the per-key SRK auth that platformd
	// resolves from autogen:// is set on the SRK object itself by
	// platformd at PlatformSRK creation time. See the long comment around
	// the Install() call below for the full chain.

	// Factory reset to clear stale persistent handles from previous installs.
	// TPM persistent handles survive OS reinstalls, so we must evict them
	// before creating new EK + SSRK.
	//
	// Two modes, both preserve manufacturer EK certificates:
	//
	//   1. Plain FactoryReset (default): EvictControl on each persistent
	//      handle using the supplied owner auth. Fails with TPM_RC_BAD_AUTH
	//      if a previous failed run set the owner hierarchy auth to a
	//      value we don't know.
	//
	//   2. FactoryResetWithClear (opt-in via installer config
	//      encryption.tpm.factory-reset-on-firstboot=true): TPM2_Clear via
	//      LOCKOUT hierarchy with empty auth FIRST, then EvictControl.
	//      Resets owner/endorsement/lockout auths and wipes all persistent
	//      objects in those hierarchies in one shot. Required for
	//      first-time provisioning of fresh hardware where the TPM may have
	//      been touched by a previous owner. **DESTRUCTIVE — opt-in only.**
	//
	// The Go default is mode 1 (safe). Reference templates default the
	// installer config flag to true so first-time provisioning Just Works
	// on fresh hardware. Operators reinstalling on hardware with a
	// known-good TPM state should set the flag to false.
	// Pass nil for ownerAuth: when we follow up with FactoryResetWithClear,
	// the TPM2_Clear pre-pass leaves OWNER auth empty so empty is correct.
	// When we follow up with plain FactoryReset on a clean-or-fresh TPM,
	// empty is also correct. The previous code passed firstboot's random
	// soPIN here which would have been wrong AFTER the Clear pass anyway.
	wantClear := s.shouldFactoryResetWithClear()
	if wantClear {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Clearing TPM via FactoryResetWithClear (DESTRUCTIVE — opt-in via installer config)...\n")
		if err := s.executor.TPM().FactoryResetWithClear(nil); err != nil {
			// Not fatal - may be a clean TPM with no handles to evict
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] FactoryResetWithClear: %v (may be clean TPM)\n", err)
			// When the software clear fails with an auth/lockout error the TPM
			// has BOTH owner and lockout auths stale (a prior failed run) —
			// TPM2_Clear via empty lockout can't recover it. Escalate to a
			// UEFI PPI ForceClear so the firmware clears it at next POST,
			// when the operator opted in. Loop-guarded; reboots at most once.
			if s.shouldForceClearViaPPI() && isTPMAuthError(err) {
				s.escalateToPPIForceClear(err)
			}
		} else {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] FactoryResetWithClear complete - TPM hierarchies cleared\n")
			// Software clear succeeded (e.g. the post-PPI-clear boot with a
			// now-clean TPM). Drop any stale PPI-escalation marker so a future
			// re-install can escalate again if needed.
			_ = os.Remove(filepath.Join(s.getEFIPath(), "tpm2", "ppi-clear-attempted"))
		}
	} else {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Clearing stale platform handles (preserving EK certs, no TPM2_Clear)...\n")
		if err := s.executor.TPM().FactoryReset(nil); err != nil {
			// Not fatal - may be a clean TPM with no handles to evict
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Factory reset: %v (may be clean TPM)\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Factory reset complete - stale handles cleared\n")
		}
	}

	// FULL install: EK + SSRK + platform policy + IAK + IDevID (#61).
	// Firstboot runs from the installed system, so PCR 7/9 already hold
	// their production values — the platform policy and golden
	// measurements captured here are the ones every subsequent boot
	// reproduces. Provisioning everything now means platformd finds a
	// fully-provisioned TPM at startup (IAK present, Platform SRK
	// present, policy digest matching) and ADOPTS it instead of running
	// its destructive re-provisioning (TPM2_Clear), which regenerated the
	// storage seed and invalidated the LUKS seal written moments earlier.
	// (IDevID creation warn-continues without an EK certificate — swtpm.)
	//
	// CRITICAL: pass nil for soPIN, NOT a freshly-generated random PIN.
	//
	// xkms.Install() interprets a non-nil soPIN as "set the OWNER /
	// ENDORSEMENT / LOCKOUT hierarchy auths to this value" and writes
	// them via TPM2_HierarchyChangeAuth. firstboot's random soPIN is
	// generated locally, used only to seed the call, and DISCARDED when
	// firstboot returns. platformd then starts with NO knowledge of that
	// PIN, reads its own autogen://-resolved srk-auth from config, and
	// every subsequent TPM operation that needs OWNER hierarchy auth
	// fails with TPM_RC_BAD_AUTH because firstboot's PIN ≠ platformd's
	// autogen output.
	//
	// Passing nil here makes Install skip the SetHierarchyAuth pass
	// entirely (see go-xkms/pkg/tpm2/provision.go — `if soPIN != nil`),
	// leaving OWNER / ENDORSEMENT / LOCKOUT auths as their post-Clear
	// state (empty). The per-key SRK auth (the platformctl autogen value)
	// is set on the key object itself, not on the hierarchy. The SRK auth
	// is the protection boundary; hierarchy auth is irrelevant once root
	// has the TPM device anyway.
	//
	// This was the second bug uncovered after the FactoryResetWithClear
	// pre-pass got lab-node-2 past the original BAD_AUTH on the eviction
	// loop. See docs/installer/factory-reset.md for the full chain.
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Installing EK + SSRK + platform policy + IAK + IDevID...\n")
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Hierarchy auth left EMPTY so platformd can re-open OWNER hierarchy\n")
	if err := s.executor.TPM().Install(
		nil, // see comment above — DO NOT set hierarchy auth here
		&xkmssdk.InstallOptions{
			EK:             true,
			SSRK:           true,
			PlatformPolicy: true,
			IAK:            true,
			IDevID:         true,
		},
	); err != nil {
		// ErrTPMEndorsementCertNotFound is expected for swtpm
		if !errors.Is(err, xkmssdk.ErrTPMEndorsementCertNotFound) {
			return &WrappedError{Msg: "TPM install failed", Err: err}
		}
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] WARNING: EK cert not found (expected for swtpm)\n")
	}

	// Create the Platform KeyStore SRK (0x81000002) — the LUKS seal
	// parent (#61). Created through the SAME pkg/platform keychain code
	// platformd uses, so the template (and therefore the derived primary
	// key) is identical by construction: platformd's keystore bring-up
	// probes the handle, finds this SRK, and adopts it as-is.
	if err := s.ensurePlatformSRK(); err != nil {
		return &WrappedError{Msg: "Platform KeyStore SRK creation failed", Err: err}
	}

	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Provisioning complete (EK + SSRK + Platform SRK + IAK)\n")
	return nil
}

// ensurePlatformSRK creates the Platform KeyStore SRK at its configured
// handle when it does not exist yet, via the same pkg/platform keychain path
// platformd uses at startup. The SRK is created with empty auth values
// (InitializeWithDefaults) — firstboot leaves the owner hierarchy
// unauthenticated, and an empty SRK password keeps unseal sessions on the
// PCR-policy branch, which is how the initrd authorizes the parent.
func (s *FirstbootSealStrategy) ensurePlatformSRK() error {
	if s.executor.TPM() == nil {
		return ErrTPMNotAvailable
	}
	tpmConfig := s.executor.TPM().Config()
	if tpmConfig == nil || tpmConfig.PlatformSRK == nil {
		return &MessageError{Msg: "tpm.keystore (platform-srk) configuration missing — cannot create the LUKS seal parent"}
	}
	if tpmConfig.PlatformSRK.CN == "" {
		// Same default platformd applies before its keystore bring-up.
		tpmConfig.PlatformSRK.CN = "platform"
	}

	ks, err := platform.NewPlatformKeyStore(s.executor.TPM(), s.executor.Backend(), tpmConfig.PlatformSRK)
	if err != nil {
		if !errors.Is(err, platform.ErrXKMSNotInitialized) {
			return &WrappedError{Msg: "platform keystore probe failed", Err: err}
		}
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Creating Platform KeyStore SRK at 0x%08x (platform-policy=%v)...\n",
			tpmConfig.PlatformSRK.SRKHandle, tpmConfig.PlatformSRK.PlatformPolicy)
		if err := ks.InitializeWithDefaults(); err != nil {
			return &WrappedError{Msg: "platform keystore SRK initialization failed", Err: err}
		}
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Platform KeyStore SRK created\n")
		return nil
	}

	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Platform KeyStore SRK already present at 0x%08x\n",
		tpmConfig.PlatformSRK.SRKHandle)
	return nil
}

// strategyRootMountPoint is the temporary mount point used by
// copyInstallerToRoot and writeSealRetryMarker for the unlocked root
// filesystem during firstboot. Defined as a package constant so the
// retry-marker writer can target the same mount that copyInstallerToRoot
// established.
const strategyRootMountPoint = "/mnt/root-tmp"

// copyInstallerToRoot mounts the unlocked root and copies installer contents to it.
// This must be called while the installer is still mounted and the root is unlocked.
//
// sealRetryReason, when non-empty, also drops a /var/lib/trusted-platform/.seal-retry-needed
// marker on the rootfs (while it's still mounted) so platformd's startup
// checks can pick it up and surface the degraded state.
func (s *FirstbootSealStrategy) copyInstallerToRoot(mappingName, recoveryKey, sealRetryReason string) error {
	// Temporary mount point for root filesystem
	rootMountPoint := strategyRootMountPoint

	// Load installer config to check if LVM is used
	// Default to LVM with vg0/root if config can't be read
	useLVM := true
	vgName := "vg0"
	lvName := "root"

	configPath := filepath.Join(strategyInstallerMountPoint, "etc", "trusted-platform", "config.yaml")
	if cfg, err := installer.LoadConfig(configPath); err == nil {
		useLVM = cfg.Disk.RootFilesystem == installer.FilesystemLVM
		if cfg.Disk.LVMVolumeGroup != "" {
			vgName = cfg.Disk.LVMVolumeGroup
		}
		if cfg.Disk.LVMLogicalVolume != "" {
			lvName = cfg.Disk.LVMLogicalVolume
		}
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Loaded config: useLVM=%v vg=%s lv=%s\n", useLVM, vgName, lvName)
	} else {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Config not found, assuming LVM with vg0/root\n")
	}

	// Determine root device path based on filesystem type
	var rootDevPath string
	if useLVM {
		// For LVM, we need to activate the volume group first
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Activating LVM volumes...\n")

		// DEBUG: Show PV scan devices before LVM commands
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] DEBUG: Checking devices before LVM activation...\n")
		if output, err := exec.Command("/sbin/lvm", "pvs", "--all", "-v").CombinedOutput(); err == nil {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] DEBUG: pvs --all output:\n%s\n", string(output))
		} else {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] DEBUG: pvs --all failed: %v\nOutput: %s\n", err, string(output))
		}
		if output, err := exec.Command("/sbin/lvm", "lvmdiskscan").CombinedOutput(); err == nil {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] DEBUG: lvmdiskscan output:\n%s\n", string(output))
		}

		// Run pvscan to find physical volumes
		if err := s.runCommand("/sbin/lvm", "pvscan", "--cache"); err != nil {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] WARNING: lvm pvscan failed: %v\n", err)
		}
		// Show PVs found after pvscan
		if output, err := exec.Command("/sbin/lvm", "pvs").CombinedOutput(); err == nil {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] DEBUG: pvs after pvscan:\n%s\n", string(output))
		}

		// Run lvm vgscan to scan for volume groups
		// Use /sbin/lvm which is the path in dracut initrd
		if err := s.runCommand("/sbin/lvm", "vgscan", "--mknodes"); err != nil {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] WARNING: lvm vgscan failed: %v\n", err)
		}

		// Activate all volume groups
		if err := s.runCommand("/sbin/lvm", "vgchange", "-ay"); err != nil {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] WARNING: lvm vgchange failed: %v\n", err)
		}

		// Explicitly activate the specific LV we need
		lvPath := fmt.Sprintf("%s/%s", vgName, lvName)
		if err := s.runCommand("/sbin/lvm", "lvchange", "-ay", lvPath); err != nil {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] WARNING: lvm lvchange failed for %s: %v\n", lvPath, err)
		}

		// Create device nodes explicitly
		if err := s.runCommand("/sbin/lvm", "vgmknodes", vgName); err != nil {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] WARNING: lvm vgmknodes failed: %v\n", err)
		}

		// Trigger udev to create device nodes
		_ = s.runCommand("udevadm", "trigger", "--type=devices")
		_ = s.runCommand("udevadm", "settle", "--timeout=5")

		// LVM root device: /dev/mapper/vg0-root
		rootDevPath = filepath.Join(strategyDevMapperDir, vgName+"-"+lvName)
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Using LVM root device: %s\n", rootDevPath)

		// Wait up to 5 seconds for device node to appear
		deviceFound := false
		for i := 0; i < 50; i++ {
			if _, err := os.Stat(rootDevPath); err == nil {
				deviceFound = true
				break
			}
			// Also check /dev/vgName/lvName format
			altPath := filepath.Join(strategyDevDir, vgName, lvName)
			if _, err := os.Stat(altPath); err == nil {
				rootDevPath = altPath
				deviceFound = true
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		if !deviceFound {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] WARNING: LVM device not found after activation, attempting dmsetup...\n")
			// Try to list dm devices for debugging
			if output, err := exec.Command("dmsetup", "ls").CombinedOutput(); err == nil {
				fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] dmsetup ls output: %s\n", string(output))
			}
		}
	} else {
		// Non-LVM: use the LUKS mapping directly
		rootDevPath = filepath.Join(strategyDevMapperDir, mappingName)
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Using direct root device: %s\n", rootDevPath)
	}

	// Verify the root device exists
	if _, err := os.Stat(rootDevPath); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("root device not found at %s", rootDevPath), Err: err}
	}

	// Create temporary mount point
	if err := os.MkdirAll(rootMountPoint, 0755); err != nil {
		return &WrappedError{Msg: "failed to create root mount point", Err: err}
	}
	defer os.Remove(rootMountPoint)

	// Mount the root filesystem
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Mounting root at %s...\n", rootMountPoint)
	if err := syscall.Mount(rootDevPath, rootMountPoint, "ext4", 0, ""); err != nil {
		// Try xfs if ext4 fails
		if err := syscall.Mount(rootDevPath, rootMountPoint, "xfs", 0, ""); err != nil {
			// Try btrfs as last resort
			if err := syscall.Mount(rootDevPath, rootMountPoint, "btrfs", 0, ""); err != nil {
				return &WrappedError{Msg: "failed to mount root filesystem", Err: err}
			}
		}
	}
	defer func() {
		syscall.Sync()
		syscall.Unmount(rootMountPoint, 0)
	}()
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Root filesystem mounted\n")

	// Copy directories from installer to root
	dirsToSync := []struct {
		src  string
		dest string
	}{
		{filepath.Join(strategyInstallerMountPoint, "var", "lib", "trusted-platform"), filepath.Join(rootMountPoint, "var", "lib", "trusted-platform")},
		{filepath.Join(strategyInstallerMountPoint, "var", "log", "trusted-platform"), filepath.Join(rootMountPoint, "var", "log", "trusted-platform")},
		{filepath.Join(strategyInstallerMountPoint, "etc", "trusted-platform"), filepath.Join(rootMountPoint, "etc", "trusted-platform")},
	}

	for _, sync := range dirsToSync {
		if _, err := os.Stat(sync.src); err != nil {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Source %s does not exist, skipping\n", sync.src)
			continue
		}

		// Create parent directories
		if err := os.MkdirAll(filepath.Dir(sync.dest), 0755); err != nil {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] WARNING: Failed to create parent for %s: %v\n", sync.dest, err)
			continue
		}

		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Copying %s -> %s\n", sync.src, sync.dest)
		if err := copyDirRecursive(sync.src, sync.dest); err != nil {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] WARNING: Failed to copy %s: %v\n", sync.src, err)
		}
	}

	// Recovery key disposition is handled by applyRecoveryKeyStrategy()
	// after copyInstallerToRoot returns. DO NOT write the recovery key
	// unconditionally to /root/luks-recovery.txt — that would leak the
	// plaintext passphrase to the rootfs regardless of the operator's
	// chosen strategy (destroy|escrow). See strategy.go applyRecoveryKeyStrategy.
	_ = recoveryKey

	// Create TPM sealed marker — only when sealing actually completed.
	if sealRetryReason == "" {
		sealedMarkerPath := filepath.Join(rootMountPoint, "var", "lib", "tpm2", ".tpm-sealed")
		if err := os.MkdirAll(filepath.Dir(sealedMarkerPath), 0755); err == nil {
			if err := os.WriteFile(sealedMarkerPath, []byte("sealed-by-initrd\n"), 0644); err != nil {
				fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] WARNING: Failed to create .tpm-sealed: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Created .tpm-sealed marker\n")
			}
		}
	}

	// Drop the seal-retry marker when we booted in degraded mode. The
	// rootfs is still mounted at this point — once this function returns,
	// the deferred unmount fires and the marker becomes part of the rootfs
	// platformd will see when it starts up post-pivot.
	if sealRetryReason != "" {
		retryDir := filepath.Join(rootMountPoint, "var", "lib", "trusted-platform")
		if err := os.MkdirAll(retryDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] WARNING: Failed to create %s: %v\n", retryDir, err)
		} else {
			retryPath := filepath.Join(retryDir, ".seal-retry-needed")
			body := fmt.Sprintf("reason=%s\nwritten_at=%s\nmapping=%s\n",
				sealRetryReason, time.Now().UTC().Format(time.RFC3339), mappingName)
			if err := os.WriteFile(retryPath, []byte(body), 0600); err != nil {
				fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] WARNING: Failed to write seal-retry marker: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Wrote seal-retry marker at %s\n", retryPath)
			}
		}
	}

	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Installer contents copied to root filesystem\n")
	return nil
}

// runCommand executes a command and returns any error
func (s *FirstbootSealStrategy) runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return &CommandOutputError{Msg: fmt.Sprintf("%s %v failed", name, args), Err: err, Detail: fmt.Sprintf(" (output: %s)", string(output))}
	}
	return nil
}

// sealKeyToTPM seals the LUKS key under the Platform KeyStore SRK with PCR
// policy. provisionInsideInstaller creates the Platform SRK before this runs
// (firstboot executes from the installed system, so PCR 7/9 already hold
// their production values and the platform policy captured here matches
// every subsequent boot). The sealed object itself has PCR policy for
// tamper detection (the CHILD axis, always on), and the parent Platform SRK
// carries the platform policy too — the initrd satisfies both by extending
// the platform PCR with the golden measurement before unsealing.
//
// The parent handle is resolved by getLUKSSealParentHandle (installer
// override → tpm.keystore.srk-handle → 0x81000002).
func (s *FirstbootSealStrategy) sealKeyToTPM(ctx context.Context, key []byte, efiPath string) error {
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Opening TPM for sealing...\n")

	if s.executor.TPM() == nil {
		return ErrTPMNotAvailable
	}

	// Resolve the LUKS seal parent handle from installer config or TPM config
	sealParentHandle := s.getLUKSSealParentHandle()
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Using LUKS seal parent handle: 0x%08x\n", sealParentHandle)

	// Load installer config to check for TPM seal config overrides
	installerCfg := s.loadInstallerConfig()
	var tpmSealCfg *installer.TPMSealConfig
	if installerCfg != nil && installerCfg.Disk != nil &&
		installerCfg.Disk.Encryption != nil && installerCfg.Disk.Encryption.TPM != nil {
		tpmSealCfg = installerCfg.Disk.Encryption.TPM
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Installer TPM seal config: handle=0x%08x platform-policy=%v\n",
			tpmSealCfg.Handle, tpmSealCfg.PlatformPolicy)
	}

	// Get parent key attributes
	srkAttrs, err := s.executor.TPM().KeyAttributes(xkmssdk.TPMHandle(sealParentHandle))
	if err != nil {
		return &WrappedError{Msg: fmt.Sprintf("seal parent key not available at 0x%08x", sealParentHandle), Err: err}
	}

	// PARENT authorization mode: the Platform KeyStore SRK is created with
	// the platform policy (tpm.keystore.platform-policy), so its use is
	// authorized by a PCR policy session — which the initrd can satisfy
	// because it extends the platform PCR with the golden measurement
	// BEFORE unsealing (the old "initrd unseals before the platform policy
	// extension exists" concern predates that and is no longer true). An
	// explicit installer override still wins for operators sealing under
	// an alternative parent — but only when they actually redirected the
	// parent (handle set): TPMSealConfig.PlatformPolicy is a plain bool,
	// so an untouched section would otherwise read as "explicitly false"
	// and silently downgrade the default Platform SRK to password auth.
	platformPolicy := s.getPlatformPolicy()
	if tpmSealCfg != nil && tpmSealCfg.Handle != 0 {
		platformPolicy = tpmSealCfg.PlatformPolicy
	}
	srkAttrs.PlatformPolicy = platformPolicy

	// PCR selection for sealed object - resolve from installer TPM seal config first,
	// then fall back to the firstboot executor config (single source of truth)
	var pcrSelection []uint
	if tpmSealCfg != nil && len(tpmSealCfg.SealPCRs) > 0 {
		pcrSelection = tpmSealCfg.SealPCRs
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Using seal-pcrs from installer TPM config: %v\n", pcrSelection)
	} else if s.executor.Config() != nil && len(s.executor.Config().PCRSelection) > 0 {
		pcrSelection = s.executor.Config().PCRSelection
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Using seal-pcrs from firstboot config: %v\n", pcrSelection)
	}
	if len(pcrSelection) == 0 {
		return &MessageError{Msg: "seal-pcrs not configured, cannot seal LUKS key"}
	}
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] PCR selection: %v\n", pcrSelection)

	// The CHILD is always PCR-bound: PlatformPolicy on the sealed object
	// attaches the PCR-based auth policy — the security property TPM-PCR
	// sealing exists for. platformPolicy above governs only how the
	// PARENT SRK is authorized (recorded in pcr-banks, replayed by the
	// initrd) — the two axes are independent (#52).
	pcrAttrs := &xkmssdk.KeyAttributes{
		CN:             "luks-root",
		KeyType:        xkmssdk.KeyTypeHMAC,
		PlatformPolicy: true,
		Parent:         srkAttrs,
	}

	// Seal with PCR policy on the object
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Sealing key to TPM with PCR policy...\n")
	sealOpts := &xkmssdk.SealOptions{
		KeyAttributes: pcrAttrs,
		Backend:       nil, // Use default backend
	}
	sealedData, err := s.executor.TPM().Seal(ctx, key, sealOpts)
	if err != nil {
		return &WrappedError{Msg: "failed to seal key", Err: err}
	}

	// Write sealed blobs to EFI
	sealPubPath := filepath.Join(efiPath, strategySealPub)
	sealPrivPath := filepath.Join(efiPath, strategySealPriv)
	pcrBanksPath := filepath.Join(efiPath, strategyPCRBanks)

	if err := os.WriteFile(sealPubPath, sealedData.TPMPublic, 0600); err != nil {
		return &WrappedError{Msg: "failed to write seal-platform.pub", Err: err}
	}
	if err := os.WriteFile(sealPrivPath, sealedData.TPMPrivate, 0600); err != nil {
		return &WrappedError{Msg: "failed to write seal-platform.priv", Err: err}
	}

	// Write pcr-banks file with platform config
	// This is the ONLY config stored on EFI - needed for boot to know platform PCR
	// IMPORTANT: All values MUST come from the installer config (single source of truth)
	tpmConfig := s.executor.TPM().Config()

	// Format seal-pcrs as comma-separated list
	sealPCRsStr := s.formatPCRList(pcrSelection)

	// Format golden-pcrs as comma-separated list
	goldenPCRsStr := ""
	if len(tpmConfig.GoldenPCRs) > 0 {
		goldenPCRsStr = s.formatPCRList(tpmConfig.GoldenPCRs)
	}

	// keystore-srk-handle: the parent handle used for sealing the LUKS key.
	// The initrd reads this to know which handle to use for unseal.
	// During firstboot, this is typically SSRK (0x81000001) since PlatformSRK
	// does not exist yet.
	keystoreSRKHandle := sealParentHandle

	pcrBanksContent := formatPCRBanksContent(sealPCRsStr, goldenPCRsStr,
		tpmConfig.PlatformPCR, tpmConfig.PlatformPCRBank,
		uint32(keystoreSRKHandle), platformPolicy, uint32(tpmConfig.SSRK.Handle))
	if err := os.WriteFile(pcrBanksPath, []byte(pcrBanksContent), 0644); err != nil {
		return &WrappedError{Msg: "failed to write pcr-banks", Err: err}
	}

	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Sealed blobs written to EFI\n")
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Platform config in pcr-banks: platform-pcr=%d, keystore-srk-handle=0x%08x\n",
		tpmConfig.PlatformPCR, keystoreSRKHandle)

	// Delete any upgrade seals (security)
	s.deleteUpgradeSeals(efiPath)

	return nil
}

// formatPCRBanksContent renders the authoritative pcr-banks file. The
// keystore-platform-policy line records HOW the seal authorized the parent
// SRK, so the unseal side replays the same authorization instead of
// assuming: sealing with password auth while unsealing with a
// platform-policy session yields TPM_RC_POLICY_FAIL on every boot, the
// keyfile fallback carries the system forever, and the seal is never
// proven (#52).
func formatPCRBanksContent(sealPCRs, goldenPCRs string, platformPCR uint, platformPCRBank string,
	keystoreSRKHandle uint32, keystorePlatformPolicy bool, ssrkHandle uint32) string {
	return fmt.Sprintf(`seal-pcrs=%s
platform-pcr=%d
platform-pcr-bank=%s
golden-pcrs=%s
keystore-srk-handle=0x%08x
keystore-platform-policy=%t
ssrk-handle=0x%08x
`,
		sealPCRs, platformPCR, platformPCRBank, goldenPCRs,
		keystoreSRKHandle, keystorePlatformPolicy, ssrkHandle)
}

// formatPCRList formats a PCR selection as a comma-separated string.
func (s *FirstbootSealStrategy) formatPCRList(pcrs []uint) string {
	parts := make([]string, len(pcrs))
	for i, pcr := range pcrs {
		parts[i] = fmt.Sprintf("%d", pcr)
	}
	return strings.Join(parts, ",")
}

// deleteUpgradeSeals removes upgrade seal files (security measure)
func (s *FirstbootSealStrategy) deleteUpgradeSeals(efiPath string) {
	upgradePubPath := filepath.Join(efiPath, strategyUpgradePub)
	upgradePrivPath := filepath.Join(efiPath, strategyUpgradePriv)

	os.Remove(upgradePubPath)
	os.Remove(upgradePrivPath)
}

// getPlatformKeystoreSRKHandle returns the Platform KeyStore SRK handle
func (s *FirstbootSealStrategy) getPlatformKeystoreSRKHandle() uint32 {
	if s.executor.TPM() != nil {
		config := s.executor.TPM().Config()
		if config != nil && config.PlatformSRK != nil && config.PlatformSRK.SRKHandle != 0 {
			return config.PlatformSRK.SRKHandle
		}
	}
	return 0x81000002
}

// getPlatformPolicy returns the platform-policy setting
func (s *FirstbootSealStrategy) getPlatformPolicy() bool {
	if s.executor.TPM() != nil {
		config := s.executor.TPM().Config()
		if config != nil && config.PlatformSRK != nil {
			return config.PlatformSRK.PlatformPolicy
		}
	}
	return true
}

// getSSRKHandle returns the SSRK handle from TPM config.
func (s *FirstbootSealStrategy) getSSRKHandle() uint32 {
	if s.executor.TPM() != nil {
		config := s.executor.TPM().Config()
		if config != nil && config.SSRK != nil && config.SSRK.Handle != 0 {
			return config.SSRK.Handle
		}
	}
	return 0x81000001
}

// getLUKSSealParentHandle resolves the parent handle for LUKS key sealing.
// Priority order:
//  1. disk.encryption.tpm.handle from installer config (explicit operator override)
//  2. Platform KeyStore SRK handle from TPM config (tpm.keystore.srk-handle)
//  3. Conventional Platform KeyStore SRK handle (0x81000002)
//
// The seal parent is the PLATFORM KEYSTORE SRK, never the SSRK (#61, owner
// ruling 2026-08-24, matching the reference platform design): the SSRK is
// the general-purpose storage parent with no platform binding, while the
// Platform SRK carries the PCR-bound platform policy. Just as important,
// platformd ADOPTS an existing Platform SRK at startup instead of declaring
// the TPM unprovisioned — sealing under the SSRK left platformd to
// re-provision with a destructive TPM2_Clear that regenerated the storage
// seed and invalidated the seal minutes after it was written.
func (s *FirstbootSealStrategy) getLUKSSealParentHandle() uint32 {
	// Check installer config for explicit LUKS TPM seal handle
	if cfg := s.loadInstallerConfig(); cfg != nil {
		if cfg.Disk != nil && cfg.Disk.Encryption != nil && cfg.Disk.Encryption.TPM != nil {
			if cfg.Disk.Encryption.TPM.Handle != 0 {
				return cfg.Disk.Encryption.TPM.Handle
			}
		}
	}

	// Fall back to the Platform KeyStore SRK handle from TPM config
	return s.getPlatformKeystoreSRKHandle()
}

// loadInstallerConfig loads the installer configuration from the mounted
// installer container. Returns nil if the config cannot be loaded.
func (s *FirstbootSealStrategy) loadInstallerConfig() *installer.Config {
	configPath := filepath.Join(strategyInstallerMountPoint, "etc", "trusted-platform", "config.yaml")
	cfg, err := installer.LoadConfig(configPath)
	if err != nil {
		return nil
	}
	return cfg
}

// shouldFactoryResetWithClear returns true when the operator has explicitly
// opted into the destructive TPM2_Clear pre-pass via the installer config
// disk.encryption.tpm.factory-reset-on-firstboot flag. Default is false:
// the Go library never destroys TPM state without explicit operator
// consent. Reference architecture templates default the YAML flag to true
// for first-time provisioning of fresh hardware.
//
// See: docs/installer/factory-reset.md and pkg/installer/types.go
// (TPMSealConfig.FactoryResetOnFirstBoot).
func (s *FirstbootSealStrategy) shouldFactoryResetWithClear() bool {
	cfg := s.loadInstallerConfig()
	if cfg == nil {
		return false
	}
	if cfg.Disk == nil || cfg.Disk.Encryption == nil || cfg.Disk.Encryption.TPM == nil {
		return false
	}
	return cfg.Disk.Encryption.TPM.FactoryResetOnFirstBoot
}

// shouldForceClearViaPPI reports whether firstboot may escalate to a UEFI PPI
// ForceClear when the software TPM2_Clear cannot recover a stale-auth TPM.
// Gated by disk.encryption.tpm.force-clear-via-ppi (default false).
func (s *FirstbootSealStrategy) shouldForceClearViaPPI() bool {
	cfg := s.loadInstallerConfig()
	if cfg == nil || cfg.Disk == nil || cfg.Disk.Encryption == nil || cfg.Disk.Encryption.TPM == nil {
		return false
	}
	return cfg.Disk.Encryption.TPM.ForceClearViaPPI
}

// isTPMAuthError reports whether err is a TPM authorization failure that a
// software clear cannot recover from (owner and/or lockout auth stale). These
// are the cases where only a firmware PPI ForceClear can recover the TPM.
func isTPMAuthError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "TPM_RC_BAD_AUTH") ||
		strings.Contains(msg, "TPM_RC_AUTH_FAIL") ||
		strings.Contains(msg, "TPM_RC_LOCKOUT")
}

// escalateToPPIForceClear schedules a firmware TPM clear via the UEFI Physical
// Presence Interface and reboots so the firmware performs it at next POST. It
// is loop-guarded by an ESP marker: if a PPI clear was already scheduled on a
// prior boot yet the TPM is still locked, the firmware ignored the request (it
// needs a one-time BIOS "Pending Operation: TPM Clear" / "PPI Bypass for
// Clear"), so we do NOT reboot again — we log the remediation and continue with
// a degraded TPM.
func (s *FirstbootSealStrategy) escalateToPPIForceClear(cause error) {
	marker := filepath.Join(s.getEFIPath(), "tpm2", "ppi-clear-attempted")

	// Marker lives on the ESP; ensure it is writable.
	if _, err := s.ensureEFIMountedRW(); err != nil {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] WARNING: could not mount ESP read-write for PPI marker: %v\n", err)
	}

	if _, statErr := os.Stat(marker); statErr == nil {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] PPI ForceClear was already scheduled on a prior boot, but the TPM is still locked (%v).\n", cause)
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] The firmware did not perform the clear. One-time fix: BIOS > Security > TPM > Pending Operation: TPM Clear (or enable 'PPI Bypass for Clear'), then re-provision. Continuing with a degraded TPM.\n")
		return
	}

	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Software TPM clear could not recover the TPM (%v) — escalating to UEFI PPI ForceClear.\n", cause)

	if err := os.MkdirAll(filepath.Dir(marker), 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] WARNING: could not create PPI marker directory: %v\n", err)
	}
	if err := os.WriteFile(marker, []byte("1\n"), 0o600); err != nil {
		// Without a durable marker we risk a reboot loop, so refuse to escalate.
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] WARNING: could not write PPI marker (%v) — skipping PPI escalation to avoid a reboot loop.\n", err)
		return
	}
	syscall.Sync()

	if err := s.executor.TPM().ForceClear(); err != nil {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] PPI ForceClear scheduling failed: %v — continuing with a degraded TPM.\n", err)
		return
	}

	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] UEFI PPI ForceClear scheduled — rebooting so the firmware clears the TPM at POST...\n")
	exec.Command("sync").Run()
	syscall.Sync()

	// Immediate reboot so no provisioning runs on the still-dirty TPM. On the
	// next boot the firmware has cleared it and FactoryResetWithClear succeeds.
	if err := syscall.Reboot(syscall.LINUX_REBOOT_CMD_RESTART); err != nil {
		// Lockdown/capability fallbacks.
		if werr := os.WriteFile("/proc/sysrq-trigger", []byte("b"), 0o200); werr != nil {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] WARNING: reboot syscall (%v) and sysrq (%v) both failed; using executor reboot.\n", err, werr)
			s.executor.triggerReboot()
		}
	}

	// Block so provisioning does not continue while the reboot is pending.
	select {}
}

// getSecureWipePasses returns the number of secure wipe passes from config
func (s *FirstbootSealStrategy) getSecureWipePasses() int {
	// Default to 1 (NIST SP 800-88)
	return 1
}

// LUKS keyslot convention (must match pkg/installer/installer.go
// prepareLUKSKeyForTPM):
//
//	slot 0 — installer passphrase (removed during installer cleanup)
//	slot 1 — TPM-sealed LUKS key (used by steady-state unseal path)
//	slot 2 — recovery passphrase (disposition controlled by the
//	         recovery-key-strategy field of TPMSealConfig)
const (
	luksSlotTPMKey   = 1
	luksSlotRecovery = 2
)

// firstbootHandoffDir is a tmpfs directory in which platform-initrd stages
// secrets that need to survive the switch_root into the production rootfs
// for exactly one consumer: platformd on first run. It is NEVER written to
// persistent storage. Platform-initrd creates it read/write owner-only, and
// platformd shreds and unlinks the files after consuming them.
const firstbootHandoffDir = "/run/platform/firstboot-handoff"

// firstbootHandoffRecoveryKey is the single-consumer handoff path for the
// LUKS recovery passphrase when recovery-key-strategy=escrow. platformd's
// first-run escrow consumer reads it, pushes the value to
// tenants/{tenant}/nodes/{node}/secrets/luks/recovery in the secret store,
// then shreds and unlinks the file.
const firstbootHandoffRecoveryKey = firstbootHandoffDir + "/recovery.key"

// recoveryKeyStrategy reads the resolved recovery-key strategy from the
// installer config. Returns the default ("escrow") when no config is
// available so we never leave a node in an undefined state.
func (s *FirstbootSealStrategy) recoveryKeyStrategy() string {
	cfg := s.loadInstallerConfig()
	if cfg == nil || cfg.Disk == nil || cfg.Disk.Encryption == nil || cfg.Disk.Encryption.TPM == nil {
		return installer.RecoveryKeyStrategyEscrow
	}
	return cfg.Disk.Encryption.TPM.ResolvedRecoveryKeyStrategy()
}

// applyRecoveryKeyStrategy disposes of the LUKS recovery passphrase
// according to the operator's chosen strategy.
//
//   - destroy: luksKillSlot(slot 2) — the recovery passphrase is
//     permanently removed from the LUKS header. The only remaining
//     unlock path is the TPM-sealed key in slot 1.
//
//   - escrow: keep slot 2 and stage the plaintext recovery passphrase
//     at firstbootHandoffRecoveryKey (tmpfs, root-owned, 0600) for
//     platformd to push into the tenant secret store on first run.
//
// Returns the strategy string that was actually applied (useful for the
// summary log line) and any error encountered. Errors are non-fatal at the
// caller — the system still boots and operators can reconcile manually.
func (s *FirstbootSealStrategy) applyRecoveryKeyStrategy(devicePath, recoveryKey string) (string, error) {
	strategy := s.recoveryKeyStrategy()

	if recoveryKey == "" {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] No recovery key present in installer — strategy=%s is a no-op\n", strategy)
		return strategy, nil
	}

	switch strategy {
	case installer.RecoveryKeyStrategyDestroy:
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] recovery-key-strategy=destroy: killing LUKS slot %d on %s\n", luksSlotRecovery, devicePath)
		if err := luks2.KillSlot(devicePath, []byte(recoveryKey), luksSlotRecovery); err != nil {
			return strategy, &WrappedError{Msg: fmt.Sprintf("luks2.KillSlot(slot=%d)", luksSlotRecovery), Err: err}
		}
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Recovery keyslot %d killed — recovery passphrase is unrecoverable\n", luksSlotRecovery)
		return strategy, nil

	case installer.RecoveryKeyStrategyEscrow:
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] recovery-key-strategy=escrow: staging passphrase at %s for platformd pickup\n", firstbootHandoffRecoveryKey)
		if err := os.MkdirAll(firstbootHandoffDir, 0700); err != nil {
			return strategy, &WrappedError{Msg: fmt.Sprintf("mkdir %s", firstbootHandoffDir), Err: err}
		}
		// Write atomically: O_EXCL refuses to clobber any pre-existing
		// handoff file so a stale consumer cannot silently overwrite a
		// still-unconsumed key.
		f, err := os.OpenFile(firstbootHandoffRecoveryKey, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_EXCL, 0600)
		if err != nil {
			return strategy, &WrappedError{Msg: fmt.Sprintf("open %s", firstbootHandoffRecoveryKey), Err: err}
		}
		if _, err := f.Write([]byte(recoveryKey)); err != nil {
			f.Close()
			_ = os.Remove(firstbootHandoffRecoveryKey)
			return strategy, &WrappedError{Msg: fmt.Sprintf("write %s", firstbootHandoffRecoveryKey), Err: err}
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return strategy, &WrappedError{Msg: fmt.Sprintf("sync %s", firstbootHandoffRecoveryKey), Err: err}
		}
		if err := f.Close(); err != nil {
			return strategy, &WrappedError{Msg: fmt.Sprintf("close %s", firstbootHandoffRecoveryKey), Err: err}
		}
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Recovery passphrase staged for platformd escrow consumer\n")
		return strategy, nil

	default:
		return strategy, &MessageError{Msg: fmt.Sprintf("unknown recovery-key-strategy %q (expected %q or %q)", strategy, installer.RecoveryKeyStrategyDestroy, installer.RecoveryKeyStrategyEscrow)}
	}
}

// dumpFirstbootForensics writes a forensic snapshot of the system state at
// the moment Unlock() returns. It runs unconditionally — success and
// failure both produce a dump — because a "successful" boot that needs
// retry mode is just as worth investigating as an outright failure.
//
// The snapshot is written to a timestamped subdirectory inside the
// installer container at strategyInstallerMountPoint/firstboot-runs/.
// The container is encrypted at rest and is preserved on seal-retry, so
// the dump survives across reboots until the operator either fixes the
// node (and the next successful firstboot wipes the installer) or pulls
// the dump out via platformctl / a rescue boot.
//
// We do NOT depend on networking. dhcpcd in initrd is brittle and the
// failure modes we want to capture often happen before any NIC is up.
// Writing to the local encrypted volume is reliable in every state where
// the installer container is open — which is true throughout Unlock().
//
// Errors are deliberately swallowed (best-effort): if dumping fails we do
// not want to mask the original Unlock() return path. We just print a
// warning and continue.
func (s *FirstbootSealStrategy) dumpFirstbootForensics() {
	// Bail out quietly if the installer is not mounted (we never got past
	// step 1) — there is nowhere to write to.
	probe := filepath.Join(strategyInstallerMountPoint, "luks-key.bin")
	if _, err := os.Stat(probe); err != nil {
		altProbe := filepath.Join(strategyInstallerMountPoint, "etc", "trusted-platform", "config.yaml")
		if _, altErr := os.Stat(altProbe); altErr != nil {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-FORENSICS] installer not mounted — skipping dump\n")
			return
		}
	}

	stamp := time.Now().UTC().Format("20060102T150405Z")
	dumpDir := filepath.Join(strategyInstallerMountPoint, "firstboot-runs", stamp)
	if err := os.MkdirAll(dumpDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-FORENSICS] mkdir %s: %v\n", dumpDir, err)
		return
	}

	// Always-on diagnostics — every command runs, output is captured even
	// when the command fails (so we keep the stderr).
	commands := []struct {
		name string
		argv []string
	}{
		{"dmesg.txt", []string{"dmesg"}},
		{"lsblk.txt", []string{"lsblk", "-O"}},
		{"blkid.txt", []string{"blkid"}},
		{"dmsetup-status.txt", []string{"dmsetup", "status"}},
		{"dmsetup-info.txt", []string{"dmsetup", "info"}},
		{"mount.txt", []string{"mount"}},
		{"proc-mounts.txt", []string{"cat", "/proc/mounts"}},
		{"proc-cmdline.txt", []string{"cat", "/proc/cmdline"}},
		{"sys-class-tpm.txt", []string{"sh", "-c", "ls -la /sys/class/tpm/ 2>&1; echo ---; ls -la /dev/tpm* 2>&1"}},
		{"ip-addr.txt", []string{"ip", "-br", "addr"}},
		{"ip-link.txt", []string{"ip", "-br", "link"}},
		{"date.txt", []string{"date", "-u", "+%Y-%m-%dT%H:%M:%SZ"}},
	}
	for _, cmd := range commands {
		out, _ := exec.Command(cmd.argv[0], cmd.argv[1:]...).CombinedOutput()
		path := filepath.Join(dumpDir, cmd.name)
		if err := os.WriteFile(path, out, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-FORENSICS] write %s: %v\n", path, err)
		}
	}

	// Marker so the operator knows where the latest dump lives.
	latest := filepath.Join(strategyInstallerMountPoint, "firstboot-runs", "latest")
	_ = os.Remove(latest)
	_ = os.Symlink(stamp, latest)

	// Sync so the writes hit the encrypted device before the eventual
	// closeInstaller path locks the LUKS volume.
	syscall.Sync()

	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-FORENSICS] forensic dump written to %s (preserved in installer container)\n", dumpDir)
}

// clearString best-effort overwrites the backing bytes of a string to zero.
// Go strings are immutable at the language level, so this reaches through a
// byte-slice alias. It is NOT a guarantee the value has been scrubbed from
// memory — that depends on the runtime keeping no copies — but it removes
// the obvious plaintext from the stack frame for callers that care.
func clearString(s *string) {
	if s == nil || *s == "" {
		return
	}
	b := []byte(*s)
	for i := range b {
		b[i] = 0
	}
	*s = ""
}

// Install is not used - installer writes to installer container directly
func (s *FirstbootSealStrategy) Install(ctx context.Context, volume *luks.VolumeConfig, password []byte) error {
	return nil
}

// getEFIPath returns the EFI partition path
func (s *FirstbootSealStrategy) getEFIPath() string {
	return strategyEFIMountPoint
}

// ensureEFIMounted mounts EFI read-only
func (s *FirstbootSealStrategy) ensureEFIMounted() (bool, error) {
	return s.mountEFI(syscall.MS_RDONLY)
}

// ensureEFIMountedRW mounts EFI read-write
func (s *FirstbootSealStrategy) ensureEFIMountedRW() (bool, error) {
	return s.mountEFI(0)
}

// mountEFI mounts the EFI partition
func (s *FirstbootSealStrategy) mountEFI(flags uintptr) (bool, error) {
	efiDir := filepath.Join(strategyEFIMountPoint, "EFI")
	if stat, err := os.Stat(efiDir); err == nil && stat.IsDir() {
		return true, nil
	}

	bootDevice := s.detectEFIDevice()
	if bootDevice == "" {
		return false, &MessageError{Msg: "no EFI partition found"}
	}

	if err := os.MkdirAll(strategyEFIMountPoint, 0755); err != nil {
		return false, &WrappedError{Msg: "failed to create mount point", Err: err}
	}

	if err := syscall.Mount(bootDevice, strategyEFIMountPoint, "vfat", flags, ""); err != nil {
		return false, &WrappedError{Msg: fmt.Sprintf("failed to mount %s", bootDevice), Err: err}
	}

	return false, nil
}

// detectEFIDevice finds the EFI partition
func (s *FirstbootSealStrategy) detectEFIDevice() string {
	candidates := []string{"/dev/vda1", "/dev/sda1", "/dev/nvme0n1p1"}
	for _, device := range candidates {
		if _, err := os.Stat(device); err == nil {
			return device
		}
	}
	return ""
}

// unmountEFI unmounts the EFI partition
func (s *FirstbootSealStrategy) unmountEFI() {
	syscall.Unmount(strategyEFIMountPoint, 0)
}

// ProcessFirstbootMarkers processes markers after switch_root
// Copies installer contents to root and securely wipes installer
func ProcessFirstbootMarkers(efiPath string) error {
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Processing firstboot markers...\n")

	markerPath := filepath.Join(efiPath, strategyCopyMarker)
	if _, err := os.Stat(markerPath); err != nil {
		// No marker - not first boot
		return nil
	}

	// Copy recovery key to /root/
	processRecoveryKey()

	// Copy installer contents to root filesystem
	if err := copyInstallerToRootFS(); err != nil {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] WARNING: Failed to copy installer: %v\n", err)
	}

	// Secure wipe installer (default to NIST single-pass for post-switch_root)
	installerPath := filepath.Join(efiPath, strategyInstallerContainerFile)
	if err := secureWipeFile(installerPath, 1); err != nil {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] WARNING: Secure wipe failed: %v\n", err)
		os.Remove(installerPath)
	}

	// Remove markers
	os.Remove(markerPath)
	os.RemoveAll(strategyMarkerDir)

	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Firstboot markers processed\n")
	return nil
}

// processRecoveryKey copies recovery key from marker to /root/
func processRecoveryKey() {
	recoveryPath := filepath.Join(strategyMarkerDir, "luks-recovery.txt")
	data, err := os.ReadFile(recoveryPath)
	if err != nil {
		return
	}

	destPath := RecoveryKeyPath
	if err := os.WriteFile(destPath, data, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] WARNING: Failed to write recovery key: %v\n", err)
		return
	}

	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Recovery key written to %s\n", destPath)
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] IMPORTANT: Back up this key securely!\n")
	os.Remove(recoveryPath)
}

// copyInstallerToRootFS copies installer contents to root filesystem
func copyInstallerToRootFS() error {
	// The installer should still be mounted from the initramfs phase
	// Copy var/ and etc/ directories
	dirs := []string{"var", "etc"}
	for _, dir := range dirs {
		src := filepath.Join(strategyInstallerMountPoint, dir)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if err := copyDirRecursive(src, "/"+dir); err != nil {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] WARNING: Failed to copy %s: %v\n", dir, err)
		}
	}
	return nil
}

// copyDirRecursive copies a directory recursively
func copyDirRecursive(src, dest string) error {
	return filepath.Walk(src, func(srcPath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}

		relPath, err := filepath.Rel(src, srcPath)
		if err != nil {
			return nil
		}
		if relPath == "." {
			return nil
		}

		destPath := filepath.Join(dest, relPath)

		if info.IsDir() {
			os.MkdirAll(destPath, info.Mode())
		} else {
			os.MkdirAll(filepath.Dir(destPath), 0755)
			data, err := os.ReadFile(srcPath)
			if err != nil {
				return nil
			}
			os.WriteFile(destPath, data, info.Mode())
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Copied: %s\n", destPath)
		}
		return nil
	})
}

// secureWipeFile overwrites a file before deleting
// passes: 1 = NIST SP 800-88 (SSD), 3 = DoD 5220.22-M, 7 = DoD ECE
func secureWipeFile(path string, passes int) error {
	if passes <= 0 {
		passes = 1 // Default to NIST single-pass
	}

	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Secure wipe: %d passes\n", passes)

	// For DoD 5220.22-M (3+ passes), do pattern-based wipes first
	if passes >= 3 {
		// Pass 1: All zeros
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Pass 1/%d: zeros (0x00)\n", passes)
		if err := luks2.Wipe(luks2.WipeOptions{
			Device: path, Passes: 1, Random: false, HeaderOnly: false, Trim: false,
		}); err != nil {
			return &WrappedError{Msg: "zeros pass failed", Err: err}
		}

		// Pass 2: All ones
		fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Pass 2/%d: ones (0xFF)\n", passes)
		if err := wipeWithPattern(path, 0xFF); err != nil {
			return &WrappedError{Msg: "ones pass failed", Err: err}
		}

		// Additional passes for DoD ECE (7-pass)
		for i := 3; i < passes; i++ {
			fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Pass %d/%d: random\n", i, passes)
			if err := luks2.Wipe(luks2.WipeOptions{
				Device: path, Passes: 1, Random: true, HeaderOnly: false, Trim: false,
			}); err != nil {
				return &WrappedError{Msg: fmt.Sprintf("random pass %d failed", i), Err: err}
			}
		}
	}

	// Final pass: random + TRIM
	fmt.Fprintf(os.Stderr, "[FIRSTBOOT-SEAL] Final pass %d/%d: random + TRIM\n", passes, passes)
	if err := luks2.Wipe(luks2.WipeOptions{
		Device: path, Passes: 1, Random: true, HeaderOnly: false, Trim: true,
	}); err != nil {
		return &WrappedError{Msg: "final wipe failed", Err: err}
	}

	return os.Remove(path)
}

// wipeWithPattern overwrites a file with a specific byte pattern
func wipeWithPattern(path string, pattern byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	// Write in 1MB chunks
	chunkSize := 1024 * 1024
	chunk := make([]byte, chunkSize)
	for i := range chunk {
		chunk[i] = pattern
	}

	remaining := info.Size()
	for remaining > 0 {
		writeSize := int64(chunkSize)
		if remaining < writeSize {
			writeSize = remaining
		}
		if _, err := f.Write(chunk[:writeSize]); err != nil {
			return err
		}
		remaining -= writeSize
	}

	return f.Sync()
}

// clearBytes securely zeros a byte slice
func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// CopyTmpfsToRoot is deprecated - use ProcessFirstbootMarkers
func CopyTmpfsToRoot(efiPath string) error {
	return ProcessFirstbootMarkers(efiPath)
}
