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

import "errors"

// Typed errors for firstboot package
var (
	// ErrNoTPMDevice is returned when no TPM device can be found
	ErrNoTPMDevice = errors.New("no TPM device found at /dev/tpmrm0 or /dev/tpm0")

	// ErrNoTPMConfig is returned when no TPM configuration can be found
	ErrNoTPMConfig = errors.New("no TPM configuration found: required pcr-banks at /boot/efi/tpm2/pcr-banks OR config at /mnt/installer/etc/trusted-platform/config.yaml (firstboot) OR /etc/trusted-platform/config.yaml (after decryption)")

	// ErrAlreadySealed is returned when TPM sealing has already been completed
	ErrAlreadySealed = errors.New("TPM already sealed (marker file exists)")

	// ErrSealingFallbackUsed is returned when firstboot completed by falling
	// back to plain-key LUKS unlock instead of sealing the key to the TPM.
	// This is a SECURITY DOWNGRADE: subsequent boots will not be cryptographically
	// bound to the platform's PCR state, the pcr-banks file is not written,
	// platformd cannot recover sealed secrets, and the system is effectively
	// running unprotected. The OpenRC tpm-firstboot-seal service must NOT
	// touch /var/lib/tpm2/platform-sealed.flag or /var/lib/trusted-platform/.initialized
	// when this error is returned, so it retries on the next boot.
	//
	// Most common cause: stale TPM owner-hierarchy auth from a previous
	// failed install run that we don't have the password for. The fix is
	// either TPM2_Clear via lockout (try this first) or PPI clear via the
	// UEFI firmware (requires reboot and may need physical confirmation).
	ErrSealingFallbackUsed = errors.New("firstboot fell back to plain-key unlock — TPM sealing did not complete; pcr-banks not written; platformd will fail to recover sealed secrets; clear the TPM and retry")

	// ErrNoLUKSKey is returned when no LUKS key can be found
	ErrNoLUKSKey = errors.New("no LUKS key found - neither installer container nor plain key file exist")

	// ErrInvalidKeySize is returned when the LUKS key has an unexpected size
	ErrInvalidKeySize = errors.New("invalid LUKS key size: expected 32 bytes")

	// ErrTPMNotAvailable is returned when TPM operations are attempted without TPM
	ErrTPMNotAvailable = errors.New("TPM not available")

	// ErrSSRKNotAccessible is returned when the SSRK handle cannot be accessed
	ErrSSRKNotAccessible = errors.New("SSRK not accessible")

	// ErrPlatformSRKNotAccessible is returned when the Platform KeyStore SRK cannot be accessed
	ErrPlatformSRKNotAccessible = errors.New("platform keystore SRK not accessible, was platform provisioned")
)

const (
	// Marker file indicating platform is initialized (used by OpenRC/systemd service)
	// Note: TPM sealed state is detected by presence of EFISealPlatformPub/Priv files
	PlatformInitializedMarker = "/var/lib/trusted-platform/.initialized"

	// Encrypted installer container written by installer (to be used by firstboot)
	// Contains: luks-key.bin, recovery-key.txt, /etc/trusted-platform/config.yaml
	// Password: installer.InstallerPassword (well-known - forensic protection, not access control)
	// Size: 100MB (holds full provisioning output)
	// SECURITY: The LUKS key is ONLY stored inside this encrypted container, never in plaintext
	EFIInstallerFile = "/boot/efi/tpm2/installer.luks"

	// Recovery key destination after firstboot (written after switch_root completes)
	RecoveryKeyPath = "/root/luks-recovery.txt"

	// EFI partition paths
	EFITPMDir        = "/boot/efi/tpm2"
	EFIPCRBanks      = "/boot/efi/tpm2/pcr-banks"
	EFIPCRValues     = "/boot/efi/tpm2/pcr-seal-values.txt"
	EFISwtpmStateDir = "/boot/efi/tpm2/swtpm-state"

	// EFI partition paths for Platform KeyStore sealed objects (SECURE production seals)
	// These are sealed under Platform SRK with platform policy (PCR 23 auth)
	EFISealPlatformPub  = "/boot/efi/tpm2/seal-platform.pub"
	EFISealPlatformPriv = "/boot/efi/tpm2/seal-platform.priv"

	// EFI partition paths for upgrade seals (TEMPORARY - kernel upgrades only)
	// Sealed under SSRK for one-time recovery boot during system upgrades
	EFISealUpgradePub  = "/boot/efi/tpm2/seal-upgrade.pub"
	EFISealUpgradePriv = "/boot/efi/tpm2/seal-upgrade.priv"

	// Note: Re-seal is detected by presence of upgrade seals (seal-upgrade.pub/priv)
	// No separate flag file needed - the upgrade seals themselves signal re-seal is required

	// Default swtpm state directory
	DefaultSwtpmStateDir = "/var/lib/swtpm"

	// Note: SRK handles are NOT hardcoded here.
	// They come from the TPM configuration file:
	//   - tpm.ssrk.handle: Shared SRK (default 0x81000001) - NO auth policy, for upgrades
	//   - tpm.keystore.srk-handle: Platform KeyStore SRK (default 0x81000002) - has platform policy
)

// Config contains configuration for firstboot sealing
type Config struct {
	// PCRSelection specifies which PCRs to seal against
	PCRSelection []uint

	// TPMAutoUnseal enables/disables TPM auto-unseal
	TPMAutoUnseal bool

	// LuksTPMOnly removes password keyslot if true
	LuksTPMOnly bool

	// LuksDevice is the LUKS encrypted device path
	LuksDevice string

	// SwtpmStateDir is the directory for swtpm state files
	SwtpmStateDir string

	// EFIMountPoint is the EFI partition mount point
	EFIMountPoint string

	// ConfigPath is the path to the platform configuration file to copy to /etc/trusted-platform/config.yaml
	// If empty, auto-detects from /media/cdrom/configs/ (looks for installer.yaml,
	// platformd.yaml, platform.yaml, or config.yaml)
	ConfigPath string

	// Debug enables debug logging and saves additional diagnostic info
	Debug bool
}

// DefaultConfig returns default firstboot configuration
// NOTE: PCRSelection is nil - MUST be set from installer config (single source of truth)
func DefaultConfig() *Config {
	return &Config{
		// PCRSelection must come from installer config - no hardcoded defaults
		PCRSelection:  nil,
		TPMAutoUnseal: true,
		LuksTPMOnly:   false,
		LuksDevice:    "", // Auto-detect
		SwtpmStateDir: DefaultSwtpmStateDir,
		EFIMountPoint: "/boot/efi",
		Debug:         false,
	}
}
