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
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
)

// OperatingSystem represents the target OS to install
type OperatingSystem string

const (
	OSAlpine OperatingSystem = "alpine"
	OSDebian OperatingSystem = "debian"
	OSFedora OperatingSystem = "fedora"
	OSUbuntu OperatingSystem = "ubuntu"
)

// FilesystemType represents the root filesystem type
type FilesystemType string

const (
	FilesystemLVM  FilesystemType = "lvm"
	FilesystemExt4 FilesystemType = "ext4"
)

// DefaultLUKSTPMHandle is the default persistent handle for the LUKS seal
// parent key. During firstboot, the LUKS key is sealed under the SSRK at
// this handle. The sealed blob is written to the EFI partition as files,
// not persisted inside the TPM itself.
const DefaultLUKSTPMHandle = uint32(0x81000001)

// DiskConfig defines disk partitioning and filesystem configuration
type DiskConfig struct {
	// Target disk device (e.g., /dev/sda, /dev/vda)
	Device string `yaml:"device" json:"device"`

	// Partition scheme
	PartitionTable PartitionTable `yaml:"partition-table" json:"partition_table"`

	// EFI partition size in MB (default: 538)
	EFIPartitionSize int `yaml:"efi-partition-size" json:"efi_partition_size"`

	// Filesystem type for root (default: lvm)
	RootFilesystem FilesystemType `yaml:"root-filesystem" json:"root_filesystem"`

	// LVM volume group name (used when RootFilesystem is lvm)
	LVMVolumeGroup string `yaml:"lvm-volume-group" json:"lvm_volume_group"`

	// LVM logical volume name (used when RootFilesystem is lvm)
	LVMLogicalVolume string `yaml:"lvm-logical-volume" json:"lvm_logical_volume"`

	// LUKS encryption settings
	Encryption *EncryptionConfig `yaml:"encryption" json:"encryption"`
}

// PartitionTable represents the partition scheme
type PartitionTable string

const (
	PartitionTableGPT PartitionTable = "gpt"
	PartitionTableMBR PartitionTable = "mbr"
)

// TPMSealConfig configures TPM-based LUKS key sealing with a dedicated parent key handle.
// The Handle field specifies which persistent TPM key is used as the PARENT
// for sealing the LUKS encryption key. The sealed blob is stored as files
// on the EFI partition (seal-platform.pub/priv), not as a persistent TPM object.
type TPMSealConfig struct {
	// Enabled controls whether LUKS key sealing via TPM is active.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Handle is the persistent TPM handle of the PARENT key used for sealing.
	// Default: 0x81000001 (SSRK). The SSRK has no platform policy, making it
	// suitable for LUKS unseal during early boot before PlatformSRK exists.
	Handle uint32 `yaml:"handle" json:"handle"`

	// Password is the auth value for the parent key handle (if any).
	Password string `yaml:"password,omitempty" json:"password,omitempty" secret:"true"`

	// SealPCRs specifies which PCRs to include in the seal policy.
	// If empty, falls back to the top-level installer Config.PCRs.
	SealPCRs []uint `yaml:"seal-pcrs" json:"seal_pcrs"`

	// PCRBanks specifies the PCR hash algorithm banks (e.g., "sha256").
	// If empty, defaults to the TPM configuration value.
	PCRBanks []string `yaml:"pcr-banks,omitempty" json:"pcr_banks,omitempty"`

	// PlatformPolicy controls whether the parent key requires platform policy
	// (PCR 23 authorization). Should be false for LUKS sealing since the
	// initrd must unseal before platformd creates the platform policy.
	PlatformPolicy bool `yaml:"platform-policy" json:"platform_policy"`

	// RecoveryKey configures LUKS recovery key generation.
	RecoveryKey *RecoveryKeyConfig `yaml:"recovery-key,omitempty" json:"recovery_key,omitempty"`

	// FactoryResetOnFirstBoot, when true, instructs firstboot to call
	// FactoryResetWithClear before provisioning the TPM. This issues a
	// TPM2_Clear via the LOCKOUT hierarchy with empty auth, which on most
	// fresh-or-platform-reset TPMs resets owner/endorsement/lockout auths
	// and wipes all persistent objects in those hierarchies (manufacturer
	// EK certs in the Platform hierarchy are preserved).
	//
	// **DESTRUCTIVE — opt-in only.** Enable this in:
	//
	//   - Reference architecture templates that ship a fresh image to a
	//     fresh node (templates default it to true)
	//   - First-time provisioning of newly-purchased hardware
	//   - Recovery from a previous failed install run that left stale
	//     owner-hierarchy auth on the TPM
	//
	// Disable in:
	//   - Re-imaging a node that already has a known-good TPM state you
	//     intend to preserve
	//   - Multi-tenant or shared-TPM scenarios where another component
	//     owns the TPM hierarchy auths
	//
	// The Go default is FALSE (safe). Reference templates set it true.
	// See: docs/installer/factory-reset.md
	FactoryResetOnFirstBoot bool `yaml:"factory-reset-on-firstboot,omitempty" json:"factory_reset_on_firstboot,omitempty"`

	// ForceClearViaPPI, when true, escalates to a UEFI Physical Presence
	// Interface (PPI) ForceClear + reboot when the software TPM2_Clear
	// (FactoryResetWithClear) cannot recover a TPM whose owner AND lockout
	// auths are both stale/unknown (fails with TPM_RC_BAD_AUTH /
	// TPM_RC_AUTH_FAIL / TPM_RC_LOCKOUT). The firmware performs the clear at
	// next POST with physical presence asserted, bypassing DA lockout — the
	// only path that recovers a doubly-locked TPM left by a prior failed
	// provisioning run.
	//
	// Loop-guarded via an ESP marker (tpm2/ppi-clear-attempted): if the
	// firmware ignores the request or requires an un-bypassed physical-
	// presence confirmation, firstboot reboots at most once, then continues
	// with a degraded TPM and logs the one-time BIOS remediation instead of
	// reboot-looping. Only meaningful alongside FactoryResetOnFirstBoot.
	//
	// The Go default is FALSE. Reference X10 templates set it true because
	// that hardware's DA lockout routinely blocks the software clear.
	ForceClearViaPPI bool `yaml:"force-clear-via-ppi,omitempty" json:"force_clear_via_ppi,omitempty"`

	// RecoveryKeyStrategy controls what happens to the LUKS recovery
	// passphrase after first-production-boot reseal.
	//
	// Background: the installer LUKS-formats the target root with a
	// randomly-generated TPM key (slot 1) AND a recovery passphrase
	// (slot 2). Because the installer cannot seal against production
	// PCR values (it runs in a different measured environment), the
	// actual TPM sealing is deferred to the very first production boot.
	// On that first boot, platform-initrd unlocks the root with the
	// recovery passphrase, reseals a NEW TPM key slot against LIVE
	// PCRs, and then applies this strategy to the recovery passphrase:
	//
	//   "destroy" — permanently remove the recovery keyslot via
	//               luksKillSlot. The passphrase is unrecoverable after
	//               first boot. Suitable for kiosk / single-purpose /
	//               fully-unattended deployments where recovery is not
	//               expected and the TPM sealed slot is the only unlock
	//               path.
	//
	//   "escrow"  — keep the recovery keyslot AND push the passphrase
	//               to the secret store at:
	//                 tenants/{tenant}/nodes/{node}/secrets/luks/recovery
	//               An authorized operator can later retrieve it via the
	//               secret store for manual recovery. This is the default
	//               because a fully auto-destroyed recovery slot is a
	//               hard operational edge case and most operators want
	//               a break-glass path.
	//
	// Default (zero value and unset): "escrow".
	RecoveryKeyStrategy string `yaml:"recovery-key-strategy,omitempty" json:"recovery_key_strategy,omitempty"`
}

// Recovery key strategies for RecoveryKeyStrategy.
const (
	// RecoveryKeyStrategyDestroy removes the LUKS recovery keyslot after
	// first-production-boot reseal. Unrecoverable.
	RecoveryKeyStrategyDestroy = "destroy"

	// RecoveryKeyStrategyEscrow keeps the LUKS recovery keyslot and
	// escrows the passphrase to the tenant secret store under
	// tenants/{tenant}/nodes/{node}/secrets/luks/recovery.
	RecoveryKeyStrategyEscrow = "escrow"
)

// ResolvedRecoveryKeyStrategy returns the effective strategy with the
// default ("escrow") applied when the field is empty.
func (t *TPMSealConfig) ResolvedRecoveryKeyStrategy() string {
	if t == nil || t.RecoveryKeyStrategy == "" {
		return RecoveryKeyStrategyEscrow
	}
	return t.RecoveryKeyStrategy
}

// RecoveryKeyConfig configures LUKS recovery key generation.
type RecoveryKeyConfig struct {
	// Enabled controls whether a recovery key is generated.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Method specifies how the recovery key is generated. Currently
	// only "autogen" is supported (cryptographically random generation).
	Method string `yaml:"method,omitempty" json:"method,omitempty"`
}

// EncryptionConfig defines LUKS encryption settings
type EncryptionConfig struct {
	// LUKS version (default: luks2)
	Version string `yaml:"version" json:"version"`

	// Cipher (default: aes-xts-plain64)
	Cipher string `yaml:"cipher" json:"cipher"`

	// Key size in bits (default: 512)
	KeySize int `yaml:"key-size" json:"key_size"`

	// Hash algorithm (default: sha256)
	Hash string `yaml:"hash" json:"hash"`

	// PBKDF algorithm (auto-detected: pbkdf2 for FIPS, argon2id otherwise)
	PBKDF string `yaml:"pbkdf" json:"pbkdf"`

	// Password for initial LUKS keyslot
	Password string `yaml:"password,omitempty" json:"password,omitempty" secret:"true"`

	// Passphrase for initial LUKS keyslot (alias for Password for backwards compatibility)
	Passphrase string `yaml:"passphrase,omitempty" json:"passphrase,omitempty" secret:"true"`

	// MappedName for the LUKS device mapper name (default: cryptroot)
	MappedName string `yaml:"mapped-name" json:"mapped_name"`

	// TPM configures TPM-based LUKS key sealing. When set, the LUKS key is
	// sealed to the TPM using the specified parent handle and PCR policy.
	TPM *TPMSealConfig `yaml:"tpm,omitempty" json:"tpm,omitempty"`

	// FIPS mode - if true, forces PBKDF2 instead of Argon2id
	// This is set from OS config during installation (not from YAML)
	FIPS bool `yaml:"-" json:"-"`
}

// IMAConfig defines Linux Integrity Measurement Architecture configuration
type IMAConfig struct {
	// Enable IMA (Integrity Measurement Architecture)
	Enabled bool `yaml:"enabled" json:"enabled"`

	// IMA policy: "tcb" (Trusted Computing Base), "appraise_tcb", "secure_boot", or "critical_data"
	// - tcb: Measures all executables, libraries, and kernel modules
	// - appraise_tcb: Measures and appraises (verifies signatures) for TCB
	// - secure_boot: Minimal policy for secure boot environments
	// - critical_data: Measures critical kernel data
	Policy string `yaml:"policy" json:"policy"`

	// Enable EVM (Extended Verification Module) for file metadata protection
	EVM bool `yaml:"evm" json:"evm"`

	// Hash algorithm for IMA measurements (sha256, sha1, sha512)
	HashAlgorithm string `yaml:"hash-algorithm" json:"hash_algorithm"`

	// Additional files/directories to monitor beyond default policy
	// These are added to the IMA policy for measurement
	MonitorPaths []string `yaml:"monitor-paths" json:"monitor_paths"`

	// Appraise mode: "off", "log", "enforce", "fix"
	// - off: No appraisal
	// - log: Log appraisal failures but allow execution
	// - enforce: Block execution on appraisal failure
	// - fix: Fix missing/invalid signatures (requires EVM key)
	AppraiseMode string `yaml:"appraise-mode" json:"appraise_mode"`

	// Path to IMA signing key (for appraise mode)
	SigningKeyPath string `yaml:"signing-key-path,omitempty" json:"signing_key_path,omitempty"`

	// Path to IMA public key certificate (for signature verification)
	PublicKeyPath string `yaml:"public-key-path,omitempty" json:"public_key_path,omitempty"`

	// Audit mode - log IMA events to audit subsystem
	AuditEnabled bool `yaml:"audit-enabled" json:"audit_enabled"`
}

// DefaultIMAMonitorPaths returns common Linux paths for rootkit/intrusion detection
func DefaultIMAMonitorPaths() []string {
	return []string{
		// System binaries
		"/bin",
		"/sbin",
		"/usr/bin",
		"/usr/sbin",
		"/usr/local/bin",
		"/usr/local/sbin",
		// Libraries
		"/lib",
		"/lib64",
		"/usr/lib",
		"/usr/lib64",
		// Kernel modules
		"/lib/modules",
		// Boot files
		"/boot",
		// System configuration
		"/etc/passwd",
		"/etc/shadow",
		"/etc/group",
		"/etc/sudoers",
		"/etc/sudoers.d",
		"/etc/ssh/sshd_config",
		"/etc/pam.d",
		"/etc/security",
		"/etc/ld.so.conf",
		"/etc/ld.so.conf.d",
		// Cron and scheduled tasks
		"/etc/crontab",
		"/etc/cron.d",
		"/etc/cron.daily",
		"/etc/cron.hourly",
		"/etc/cron.weekly",
		"/etc/cron.monthly",
		"/var/spool/cron",
		// Init system
		"/etc/init.d",
		"/etc/rc.d",
		"/etc/systemd",
		"/usr/lib/systemd",
		// Kernel parameters
		"/etc/sysctl.conf",
		"/etc/sysctl.d",
		// Network configuration
		"/etc/hosts",
		"/etc/hosts.allow",
		"/etc/hosts.deny",
		"/etc/resolv.conf",
		// Package management
		"/etc/apk",
		"/etc/apt",
		"/etc/yum.repos.d",
		"/etc/dnf",
	}
}

// OSConfig defines OS-specific installation configuration
type OSConfig struct {
	// Operating system to install
	OS OperatingSystem `yaml:"os" json:"os"`

	// OS version (e.g., "3.22" for Alpine, "bookworm" for Debian)
	Version string `yaml:"version" json:"version"`

	// Architecture (e.g., "x86_64", "aarch64")
	Architecture string `yaml:"architecture" json:"architecture"`

	// Hostname for the installed system
	Hostname string `yaml:"hostname" json:"hostname"`

	// Mirror URL
	Mirror string `yaml:"mirror" json:"mirror"`

	// Additional packages to install
	Packages []string `yaml:"packages" json:"packages"`

	// Inline post-install script (embedded in YAML as multiline string)
	PostInstall string `yaml:"post-install,omitempty" json:"post_install,omitempty"`

	// Path to post-install script file (local path or HTTP URL)
	// For HTTP URLs, a .sha256 file must exist alongside for checksum validation
	PostInstallScript string `yaml:"post-install-script,omitempty" json:"post_install_script,omitempty"`

	// Root password
	RootPassword string `yaml:"root-password,omitempty" json:"root_password,omitempty" secret:"true"`

	// Filesystem type (lvm or ext4) - used to determine packages to install
	FilesystemType FilesystemType `yaml:"filesystem-type" json:"filesystem_type"`

	// FIPS mode enabled
	FIPS bool `yaml:"fips" json:"fips"`

	// Kernel lockdown enabled
	Lockdown bool `yaml:"lockdown" json:"lockdown"`

	// Kernel lockdown mode: "integrity" or "confidentiality"
	LockdownMode string `yaml:"lockdown-mode" json:"lockdown_mode"`

	// Automatic TPM resealing on kernel upgrade
	TPMAutoUpgradeSeal bool `yaml:"tpm-auto-upgrade-seal" json:"tpm_auto_upgrade_seal"`

	// Path to platformd binary to install (consolidated binary includes all initrd commands)
	PlatformdBinary string `yaml:"platformd-binary" json:"platformd_binary"`

	// WebUI installation directory (where public_html should be installed)
	WebUIInstallPath string `yaml:"webui-install-path" json:"webui_install_path"`

	// Enable FIDO2 support (installs libfido2, fido2, coreutils packages)
	EnableFIDO2 bool `yaml:"enable-fido2" json:"enable_fido2"`

	// KernelModules is a list of kernel modules to load at boot.
	// These are written to /etc/modules on the installed system.
	// Required for bare metal deployments where NIC drivers are not
	// built into the kernel (e.g., igb, ixgbe for Intel NICs).
	KernelModules []string `yaml:"kernel-modules,omitempty" json:"kernel_modules,omitempty"`

	// IMA (Integrity Measurement Architecture) configuration
	IMA *IMAConfig `yaml:"ima,omitempty" json:"ima,omitempty"`

	// Debug mode - when enabled, installs and configures SSH for debug access
	Debug bool `yaml:"-" json:"-"`

	// HardwareManufacturer is the Redfish System.Manufacturer string for the
	// target host (e.g. "Supermicro", "Dell Inc.", "HPE"). Propagated from
	// Config at construction time. OS installers use this together with
	// HardwareModel to resolve pkg/quirks entries for vendor-specific behaviour
	// (serial console device, kernel modules, Samba protocol).
	HardwareManufacturer string `yaml:"-" json:"-"`

	// HardwareModel is the Redfish System.Model string (e.g. "X10SDV-TP8F",
	// "PowerEdge R640"). Propagated from Config at construction time.
	HardwareModel string `yaml:"-" json:"-"`
}

// UKIConfig defines Unified Kernel Image configuration
type UKIConfig struct {
	// Kernel command line
	Cmdline string `yaml:"cmdline" json:"cmdline"`

	// Path to kernel on installed system (e.g., /boot/vmlinuz-lts)
	KernelPath string `yaml:"kernel-path" json:"kernel_path"`

	// Path to initramfs on installed system (e.g., /boot/initramfs-lts)
	InitramfsPath string `yaml:"initramfs-path" json:"initramfs_path"`

	// OS release string (optional)
	OSRelease string `yaml:"os-release" json:"os_release"`

	// Path to microcode (optional)
	MicrocodePath string `yaml:"microcode-path" json:"microcode_path"`
}

// Secure Boot re-sign modes. "remote" sends only a digest to the CP-KMS
// (the DB key never leaves the server); "local" resolves key material on-node.
const (
	SecureBootResignModeRemote = "remote"
	SecureBootResignModeLocal  = "local"
)

// SecureBootKeyRef references one Secure Boot key (PK, KEK, or DB). Backend
// selection is the KMS's job: the inlined KeyConfig.StoreType (tpm2|software|
// hsm|...) drives routing inside the KMS, never the URI scheme.
type SecureBootKeyRef struct {
	common.KeyConfig `yaml:",inline" mapstructure:",squash"`
	// KeyURI references the private key: kms://<path> or file://<path>.
	KeyURI string `yaml:"key-uri,omitempty" json:"key_uri,omitempty" mapstructure:"key-uri"`
	// CertURI references the companion certificate (usually kms://).
	CertURI string `yaml:"cert-uri,omitempty" json:"cert_uri,omitempty" mapstructure:"cert-uri"`
}

// SecureBootConfig defines Secure Boot key management. PK/KEK are normally
// TPM-resident (store: tpm2); DB is normally CP-KMS software-backed and signs
// the UKI + every kernel module via remote hash-signing (resign-mode: remote).
type SecureBootConfig struct {
	Enabled    bool             `yaml:"enabled,omitempty" json:"enabled,omitempty" mapstructure:"enabled"`
	Enforce    bool             `yaml:"enforce,omitempty" json:"enforce,omitempty" mapstructure:"enforce"`
	ResignMode string           `yaml:"resign-mode,omitempty" json:"resign_mode,omitempty" mapstructure:"resign-mode"`
	PK         SecureBootKeyRef `yaml:"pk,omitempty" json:"pk,omitempty" mapstructure:"pk"`
	KEK        SecureBootKeyRef `yaml:"kek,omitempty" json:"kek,omitempty" mapstructure:"kek"`
	DB         SecureBootKeyRef `yaml:"db,omitempty" json:"db,omitempty" mapstructure:"db"`
}

// validSecureBootURI reports whether s uses a supported Secure Boot URI scheme
// (kms:// or file://, case-insensitive). Backend selection is the KMS's job, so
// the scheme only distinguishes KMS-resolved from on-media key material.
func validSecureBootURI(s string) bool {
	lower := strings.ToLower(s)
	return strings.HasPrefix(lower, "kms://") || strings.HasPrefix(lower, "file://")
}

// Validate checks the Secure Boot config when enabled. It defaults ResignMode,
// requires a DB key URI (needed to sign the UKI), requires PK+KEK URIs when
// Enforce is set, and rejects any URI whose scheme is not kms:// or file://.
func (c *SecureBootConfig) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}
	if c.ResignMode == "" {
		c.ResignMode = SecureBootResignModeRemote
	}
	if c.ResignMode != SecureBootResignModeRemote && c.ResignMode != SecureBootResignModeLocal {
		return &ErrSecureBootConfig{
			Field:  "resign-mode",
			Reason: fmt.Sprintf("must be %q or %q", SecureBootResignModeRemote, SecureBootResignModeLocal),
		}
	}
	if c.DB.KeyURI == "" {
		return &ErrSecureBootConfig{Field: "db.key-uri", Reason: "required to sign the UKI"}
	}
	if c.Enforce {
		if c.PK.KeyURI == "" {
			return &ErrSecureBootConfig{Field: "pk.key-uri", Reason: "required when enforce is set"}
		}
		if c.KEK.KeyURI == "" {
			return &ErrSecureBootConfig{Field: "kek.key-uri", Reason: "required when enforce is set"}
		}
	}
	for _, ref := range []struct {
		field string
		uri   string
	}{
		{"pk.key-uri", c.PK.KeyURI},
		{"pk.cert-uri", c.PK.CertURI},
		{"kek.key-uri", c.KEK.KeyURI},
		{"kek.cert-uri", c.KEK.CertURI},
		{"db.key-uri", c.DB.KeyURI},
		{"db.cert-uri", c.DB.CertURI},
	} {
		if ref.uri == "" {
			continue
		}
		if !validSecureBootURI(ref.uri) {
			return &ErrSecureBootConfig{Field: ref.field, Reason: "scheme must be kms:// or file://"}
		}
	}
	return nil
}

// Config is the complete system installation configuration
type Config struct {
	// Disk configuration
	Disk *DiskConfig `yaml:"disk" json:"disk"`

	// OS configuration
	OS *OSConfig `yaml:"os" json:"os"`

	// Network configuration
	Network *NetworkConfig `yaml:"network,omitempty" json:"network,omitempty"`

	// UKI configuration
	UKI *UKIConfig `yaml:"uki,omitempty" json:"uki,omitempty"`

	// Secure Boot configuration
	SecureBoot *SecureBootConfig `yaml:"secure-boot,omitempty" json:"secure_boot,omitempty"`

	// Enable TPM sealing
	EnableTPMSealing bool `yaml:"enable-tpm-sealing" json:"enable_tpm_sealing"`

	// PCRs to seal against
	PCRs []uint `yaml:"pcrs,omitempty" json:"pcrs,omitempty"`

	// Enable FIDO2 enrollment
	EnableFIDO2Enrollment bool `yaml:"enable-fido2-enrollment" json:"enable_fido2_enrollment"`

	// FIDO2 configuration
	FIDO2 *FIDO2Config `yaml:"fido2,omitempty" json:"fido2,omitempty"`

	// Debug mode
	Debug bool `yaml:"debug" json:"debug"`

	// Environment specifies the platform environment (dev, preprod, prod, test)
	// When set to "test", platformd skips external service checks like public IP detection
	Environment string `yaml:"environment,omitempty" json:"environment,omitempty"`

	// HardwareManufacturer is the Redfish System.Manufacturer string for the
	// target host (e.g. "Supermicro", "Dell Inc.", "HPE"). When set, the
	// installer resolves vendor-specific quirks (kernel cmdline, Samba
	// protocol) via pkg/quirks.Resolve. An empty string causes the generic
	// cross-vendor defaults to be used.
	HardwareManufacturer string `yaml:"hardware-manufacturer,omitempty" json:"hardware_manufacturer,omitempty"`

	// HardwareModel is the Redfish System.Model string for the target host
	// (e.g. "X10SDV-TP8F", "PowerEdge R640"). Used together with
	// HardwareManufacturer to select board-specific quirks.
	HardwareModel string `yaml:"hardware-model,omitempty" json:"hardware_model,omitempty"`
}

// FIDO2Config holds FIDO2 enrollment configuration
type FIDO2Config struct {
	// Relying Party ID for FIDO2 credentials
	RelyingPartyID string `yaml:"relying-party-id" json:"relying_party_id"`

	// LUKS keyslot to use for FIDO2 (default: 3)
	Keyslot int `yaml:"keyslot" json:"keyslot"`

	// User presence required for unlock
	UserPresenceRequired bool `yaml:"user-presence-required" json:"user_presence_required"`

	// Timeout for device operations in seconds
	Timeout int `yaml:"timeout" json:"timeout"`
}

// InterfaceType represents the network interface addressing type
type InterfaceType string

const (
	// InterfaceTypeDHCP uses DHCP for address configuration
	InterfaceTypeDHCP InterfaceType = "dhcp"
	// InterfaceTypeStatic uses static IP address configuration
	InterfaceTypeStatic InterfaceType = "static"
	// InterfaceTypeManual marks interface as manually configured
	InterfaceTypeManual InterfaceType = "manual"
	// InterfaceTypeDisabled marks interface as disabled
	InterfaceTypeDisabled InterfaceType = "disabled"
)

// BridgeType represents the type of network bridge
type BridgeType string

const (
	// BridgeTypeLinux uses the Linux kernel bridge
	BridgeTypeLinux BridgeType = "linux"
	// BridgeTypeOVS uses Open vSwitch
	BridgeTypeOVS BridgeType = "ovs"
)

// BondType represents how the bond is realised: via the Linux kernel
// `bonding` driver (ifenslave-style netdev, requires the kernel module
// loaded) or as an OVS bond (a port group on an OVS bridge with LACP
// handled by ovs-vswitchd, no kernel bonding module required).
type BondType string

const (
	// BondTypeLinux uses the Linux kernel `bonding` driver and creates
	// a bondN netdev that member NICs are enslaved to via
	// `ip link set <member> master bond0`. The bond netdev is then added
	// as a port on whatever bridge consumes it.
	BondTypeLinux BondType = "linux"
	// BondTypeOVS creates the bond natively in Open vSwitch: a single
	// port on the bridge owns multiple member NICs and OVS handles LACP
	// (`ovs-vsctl add-bond <bridge> <bond> <if1> <if2> ...`). No Linux
	// `bonding` kernel module is required. This is the default for new
	// deployments because it collocates the data-plane bonding state
	// with OVS flow rules and plays better with SDN controllers.
	BondTypeOVS BondType = "ovs"
)

// SubnetScope classifies the purpose and ownership of a subnet.
type SubnetScope string

const (
	// SubnetScopeInternal represents SDN-managed internal segments.
	SubnetScopeInternal SubnetScope = "internal"
	// SubnetScopePublic represents ARIN-assigned, BGP-announced subnets.
	SubnetScopePublic SubnetScope = "public"
	// SubnetScopeTransit represents GRE tunnel point-to-point subnets.
	SubnetScopeTransit SubnetScope = "transit"
	// SubnetScopeISP represents ISP-assigned subnets that are not owned.
	SubnetScopeISP SubnetScope = "isp"
)

// SubnetRole identifies a special operational role for a subnet.
type SubnetRole string

const (
	// SubnetRoleProvisioning marks the subnet used for PXE/provisioning.
	SubnetRoleProvisioning SubnetRole = "provisioning"
	// SubnetRoleQuarantine marks the subnet used for quarantined nodes.
	SubnetRoleQuarantine SubnetRole = "quarantine"
)

// DHCPScopeConfig defines DHCP serving parameters for a subnet.
type DHCPScopeConfig struct {
	// Enabled controls whether DHCP is served on this subnet.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// RangeStart is the first allocatable DHCP address.
	RangeStart string `yaml:"range-start" json:"range_start"`

	// RangeEnd is the last allocatable DHCP address.
	RangeEnd string `yaml:"range-end" json:"range_end"`

	// LeaseDuration is the DHCP lease duration (e.g., "1h", "24h").
	LeaseDuration string `yaml:"lease-duration,omitempty" json:"lease_duration,omitempty"`
}

// SubnetConfig defines a named subnet with scope, VLAN binding, and optional
// DHCP serving parameters. Subnets are the single source of truth for IP
// addressing; IPAM pools and SDN networks are derived from them.
type SubnetConfig struct {
	// Name is the unique identifier for this subnet.
	Name string `yaml:"name" json:"name"`

	// Scope classifies the subnet (internal, public, transit, isp).
	Scope SubnetScope `yaml:"scope,omitempty" json:"scope,omitempty"`

	// VLANID is the IEEE 802.1Q VLAN identifier (1-4094). Zero means untagged.
	VLANID uint16 `yaml:"vlan-id,omitempty" json:"vlan_id,omitempty"`

	// CIDR is the network prefix in CIDR notation (e.g., "10.200.0.0/24").
	CIDR string `yaml:"cidr" json:"cidr"`

	// Gateway is the default gateway address for this subnet.
	Gateway string `yaml:"gateway,omitempty" json:"gateway,omitempty"`

	// DNS is the list of DNS server addresses for this subnet.
	DNS []string `yaml:"dns,omitempty" json:"dns,omitempty"`

	// DHCP configures DHCP serving parameters for this subnet.
	DHCP *DHCPScopeConfig `yaml:"dhcp,omitempty" json:"dhcp,omitempty"`

	// Role identifies a special operational role (provisioning, quarantine).
	Role SubnetRole `yaml:"role,omitempty" json:"role,omitempty"`
}

// BondVLANConfig defines a VLAN sub-interface on a bond. The VLAN ID is
// resolved from the referenced SubnetConfig by name.
type BondVLANConfig struct {
	// Subnet is the name of the SubnetConfig to bind this sub-interface to.
	Subnet string `yaml:"subnet" json:"subnet" mapstructure:"subnet"`

	// IPv4Address is the static IPv4 address for this sub-interface.
	IPv4Address string `yaml:"ipv4-address" json:"ipv4_address" mapstructure:"ipv4-address"`

	// AutoStart controls whether this sub-interface starts on boot.
	AutoStart bool `yaml:"auto-start" json:"auto_start" mapstructure:"auto-start"`
}

// NetworkConfig defines network configuration for the installed system
type NetworkConfig struct {
	// DNS configuration
	DNS *DNSConfig `yaml:"dns,omitempty" json:"dns,omitempty"`

	// DNSMasq configures the local dnsmasq forwarder. When Enabled, the
	// installer installs the dnsmasq package, writes /etc/dnsmasq.conf,
	// enables the OpenRC service, and points /etc/resolv.conf at
	// 127.0.0.1 so all DNS queries flow through the local cache before
	// being forwarded to UpstreamServers.
	DNSMasq *DNSMasqConfig `yaml:"dnsmasq,omitempty" json:"dnsmasq,omitempty"`

	// Network interfaces configuration
	Interfaces []InterfaceConfig `yaml:"interfaces,omitempty" json:"interfaces,omitempty"`

	// Bridge configurations
	Bridges []BridgeConfig `yaml:"bridges,omitempty" json:"bridges,omitempty"`

	// Bond configurations
	Bonds []BondConfig `yaml:"bonds,omitempty" json:"bonds,omitempty"`

	// VLAN configurations
	VLANs []VLANConfig `yaml:"vlans,omitempty" json:"vlans,omitempty"`

	// Subnets defines named subnet configurations with scope, VLAN, and DHCP.
	Subnets []SubnetConfig `yaml:"subnets,omitempty" json:"subnets,omitempty"`

	// Wait for network before completing boot (useful for TPM sealing)
	WaitOnline bool `yaml:"wait-online" json:"wait_online"`

	// Timeout in seconds to wait for network (default: 30)
	WaitTimeout int `yaml:"wait-timeout" json:"wait_timeout"`
}

// DNSConfig defines DNS resolver configuration
type DNSConfig struct {
	// DNS nameservers (e.g., ["8.8.8.8", "8.8.4.4"])
	Nameservers []string `yaml:"nameservers" json:"nameservers"`

	// DNS search domains (e.g., ["example.com", "internal.example.com"])
	SearchDomains []string `yaml:"search-domains" json:"search_domains"`

	// DNS options (e.g., ["timeout:2", "attempts:3"])
	Options []string `yaml:"options,omitempty" json:"options,omitempty"`

	// UpstreamDNS specifies a DNS server with non-standard port for dnsmasq forwarding.
	// Format: "ip#port" (e.g., "10.99.99.2#8053")
	// When set, dnsmasq is installed and configured to forward to this server,
	// and resolv.conf points to localhost.
	UpstreamDNS string `yaml:"upstream-dns,omitempty" json:"upstream_dns,omitempty"`
}

// DNSMasqConfig configures the local dnsmasq DNS forwarder.
type DNSMasqConfig struct {
	// Enabled toggles dnsmasq install + configure.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// UpstreamServers are forwarded to as `server=...` lines. Each
	// entry may be a plain IP, an IP with `#port`, or a domain-scoped
	// `/example.com/IP#port` form. Multiple entries become multiple
	// `server=` lines so dnsmasq does round-robin / split-horizon.
	UpstreamServers []string `yaml:"upstream-servers,omitempty" json:"upstream_servers,omitempty"`

	// LocalDomain populates `local=/<domain>/` and `domain=<domain>`
	// directives so unqualified names resolve under this suffix without
	// forwarding upstream.
	LocalDomain string `yaml:"local-domain,omitempty" json:"local_domain,omitempty"`
}

// InterfaceConfig defines configuration for a network interface
type InterfaceConfig struct {
	// Interface name (e.g., "eth0", "enp0s3")
	Name string `yaml:"name" json:"name"`

	// Interface type: dhcp, static, manual, disabled
	Type InterfaceType `yaml:"type" json:"type"`

	// IPv4 address with CIDR notation (e.g., "192.168.1.10/24")
	// For backwards compatibility, can also be just IP and use Netmask
	IPv4Address string `yaml:"ipv4-address,omitempty" json:"ipv4_address,omitempty"`

	// IPv4 netmask (e.g., "255.255.255.0") - used if IPv4Address doesn't include CIDR
	IPv4Netmask string `yaml:"ipv4-netmask,omitempty" json:"ipv4_netmask,omitempty"`

	// IPv4 default gateway
	IPv4Gateway string `yaml:"ipv4-gateway,omitempty" json:"ipv4_gateway,omitempty"`

	// IPv6 address with prefix (e.g., "2001:db8::1/64")
	IPv6Address string `yaml:"ipv6-address,omitempty" json:"ipv6_address,omitempty"`

	// IPv6 default gateway
	IPv6Gateway string `yaml:"ipv6-gateway,omitempty" json:"ipv6_gateway,omitempty"`

	// MTU (Maximum Transmission Unit)
	MTU int `yaml:"mtu,omitempty" json:"mtu,omitempty"`

	// MAC address override
	MACAddress string `yaml:"mac-address,omitempty" json:"mac_address,omitempty"`

	// Auto-start interface on boot
	AutoStart bool `yaml:"auto-start" json:"auto_start"`

	// Enable IPv6 auto-configuration (SLAAC)
	IPv6AutoConf bool `yaml:"ipv6-autoconf,omitempty" json:"ipv6_autoconf,omitempty"`

	// Additional routes
	Routes []RouteConfig `yaml:"routes,omitempty" json:"routes,omitempty"`

	// Interface-specific DNS servers (overrides global DNS)
	DNS []string `yaml:"dns,omitempty" json:"dns,omitempty"`
}

// RouteConfig defines a static route
type RouteConfig struct {
	// Destination network (e.g., "10.0.0.0/8")
	Destination string `yaml:"destination" json:"destination"`

	// Gateway address
	Gateway string `yaml:"gateway" json:"gateway"`

	// Metric (lower = higher priority)
	Metric int `yaml:"metric,omitempty" json:"metric,omitempty"`
}

// BridgeConfig defines a network bridge configuration
type BridgeConfig struct {
	// Bridge name (e.g., "br0", "trusted0")
	Name string `yaml:"name" json:"name"`

	// Bridge type: linux or ovs
	Type BridgeType `yaml:"type" json:"type"`

	// Member interfaces to add to the bridge
	Interfaces []string `yaml:"interfaces" json:"interfaces"`

	// IP configuration for the bridge (same as InterfaceConfig)
	IPv4Address string `yaml:"ipv4-address,omitempty" json:"ipv4_address,omitempty"`
	IPv4Netmask string `yaml:"ipv4-netmask,omitempty" json:"ipv4_netmask,omitempty"`
	IPv4Gateway string `yaml:"ipv4-gateway,omitempty" json:"ipv4_gateway,omitempty"`

	// Use DHCP for the bridge
	DHCP bool `yaml:"dhcp,omitempty" json:"dhcp,omitempty"`

	// STP (Spanning Tree Protocol) enabled
	STP bool `yaml:"stp,omitempty" json:"stp,omitempty"`

	// Forward delay in seconds (for STP)
	ForwardDelay int `yaml:"forward-delay,omitempty" json:"forward_delay,omitempty"`

	// Auto-start bridge on boot
	AutoStart bool `yaml:"auto-start" json:"auto_start"`
}

// BondConfig defines a network bond (link aggregation) configuration
type BondConfig struct {
	// Bond name (e.g., "bond0")
	Name string `yaml:"name" json:"name"`

	// Type chooses the bonding implementation. "ovs" creates the bond
	// as an OVS port (default), "linux" uses the kernel bonding driver.
	// Empty defaults to "ovs".
	Type BondType `yaml:"type,omitempty" json:"type,omitempty"`

	// Bridge names the OVS bridge this bond attaches to when Type=ovs.
	// Ignored for Type=linux. Must match a `network.bridges[].name`
	// entry with type=ovs. Defaults to the first OVS bridge if unset.
	Bridge string `yaml:"bridge,omitempty" json:"bridge,omitempty"`

	// Bond mode.
	//   Linux: balance-rr, active-backup, balance-xor, broadcast,
	//          802.3ad, balance-tlb, balance-alb (raw kernel driver values)
	//   OVS:   active-backup, balance-slb, balance-tcp (OVS port
	//          bond_mode values — 802.3ad is implicit when LACP is
	//          enabled on balance-tcp)
	Mode string `yaml:"mode" json:"mode"`

	// LACP controls OVS LACP negotiation when Type=ovs.
	// Values: "active", "passive", "off". Ignored for Type=linux
	// (kernel 802.3ad is controlled via Mode instead).
	LACP string `yaml:"lacp,omitempty" json:"lacp,omitempty"`

	// Interfaces lists the member interfaces for this bond.
	Interfaces []string `yaml:"interfaces" json:"interfaces"`

	// VLANs defines VLAN sub-interfaces on this bond. Each entry references
	// a SubnetConfig by name to resolve the VLAN ID.
	VLANs []BondVLANConfig `yaml:"vlans,omitempty" json:"vlans,omitempty"`

	// IP configuration
	IPv4Address string `yaml:"ipv4-address,omitempty" json:"ipv4_address,omitempty"`
	IPv4Netmask string `yaml:"ipv4-netmask,omitempty" json:"ipv4_netmask,omitempty"`
	IPv4Gateway string `yaml:"ipv4-gateway,omitempty" json:"ipv4_gateway,omitempty"`

	// Use DHCP
	DHCP bool `yaml:"dhcp,omitempty" json:"dhcp,omitempty"`

	// Primary interface (for active-backup mode)
	Primary string `yaml:"primary,omitempty" json:"primary,omitempty"`

	// MII monitoring interval in ms
	MIIMon int `yaml:"miimon,omitempty" json:"miimon,omitempty"`

	// Auto-start on boot
	AutoStart bool `yaml:"auto-start" json:"auto_start"`
}

// VLANConfig defines a VLAN interface configuration
type VLANConfig struct {
	// VLAN interface name (e.g., "eth0.100", "vlan100")
	Name string `yaml:"name" json:"name"`

	// Parent interface
	Parent string `yaml:"parent" json:"parent"`

	// VLAN ID (1-4094)
	ID int `yaml:"id" json:"id"`

	// IP configuration
	IPv4Address string `yaml:"ipv4-address,omitempty" json:"ipv4_address,omitempty"`
	IPv4Netmask string `yaml:"ipv4-netmask,omitempty" json:"ipv4_netmask,omitempty"`
	IPv4Gateway string `yaml:"ipv4-gateway,omitempty" json:"ipv4_gateway,omitempty"`

	// Use DHCP
	DHCP bool `yaml:"dhcp,omitempty" json:"dhcp,omitempty"`

	// Auto-start on boot
	AutoStart bool `yaml:"auto-start" json:"auto_start"`
}

// Validate validates the network configuration
func (nc *NetworkConfig) Validate() error {
	// Validate interfaces
	for i, iface := range nc.Interfaces {
		if iface.Name == "" {
			return ErrInvalidConfig(fmt.Sprintf("interface %d: name is required", i))
		}
		if iface.Type == InterfaceTypeStatic {
			if iface.IPv4Address == "" && iface.IPv6Address == "" {
				return ErrInvalidConfig(fmt.Sprintf("interface %s: static type requires IPv4 or IPv6 address", iface.Name))
			}
		}
	}

	// Validate VLANs
	for i, vlan := range nc.VLANs {
		if vlan.Name == "" {
			return ErrInvalidConfig(fmt.Sprintf("vlan %d: name is required", i))
		}
		if vlan.Parent == "" {
			return ErrInvalidConfig(fmt.Sprintf("vlan %s: parent interface is required", vlan.Name))
		}
		if vlan.ID < 1 || vlan.ID > 4094 {
			return ErrInvalidConfig(fmt.Sprintf("vlan %s: ID must be between 1 and 4094", vlan.Name))
		}
	}

	// Validate bridges. A bridge with no interfaces is legal — it's a
	// host-local bridge (typical for OVS bridges that only carry
	// VM/container traffic and don't need an uplink port). Bonds that
	// declare `bridge: <name>` attach themselves later via OVSDB.
	for i, br := range nc.Bridges {
		if br.Name == "" {
			return ErrInvalidConfig(fmt.Sprintf("bridge %d: name is required", i))
		}
	}

	// Validate bonds
	for i, bond := range nc.Bonds {
		if bond.Name == "" {
			return ErrInvalidConfig(fmt.Sprintf("bond %d: name is required", i))
		}
		if len(bond.Interfaces) < 2 {
			return ErrInvalidConfig(fmt.Sprintf("bond %s: at least two member interfaces are required", bond.Name))
		}
		if bond.Mode == "" {
			return ErrInvalidConfig(fmt.Sprintf("bond %s: mode is required", bond.Name))
		}
	}

	return nil
}

// SubnetByName returns the SubnetConfig with the given name, or nil if not found.
func (nc *NetworkConfig) SubnetByName(name string) *SubnetConfig {
	for i := range nc.Subnets {
		if nc.Subnets[i].Name == name {
			return &nc.Subnets[i]
		}
	}
	return nil
}

// ProvisioningSubnet returns the first subnet with role "provisioning", or nil.
func (nc *NetworkConfig) ProvisioningSubnet() *SubnetConfig {
	for i := range nc.Subnets {
		if nc.Subnets[i].Role == SubnetRoleProvisioning {
			return &nc.Subnets[i]
		}
	}
	return nil
}

// QuarantineSubnet returns the first subnet with role "quarantine", or nil.
func (nc *NetworkConfig) QuarantineSubnet() *SubnetConfig {
	for i := range nc.Subnets {
		if nc.Subnets[i].Role == SubnetRoleQuarantine {
			return &nc.Subnets[i]
		}
	}
	return nil
}

// InternalSubnets returns all subnets with scope "internal".
func (nc *NetworkConfig) InternalSubnets() []SubnetConfig {
	var result []SubnetConfig
	for _, s := range nc.Subnets {
		if s.Scope == SubnetScopeInternal {
			result = append(result, s)
		}
	}
	return result
}

// PublicSubnets returns all subnets with scope "public".
func (nc *NetworkConfig) PublicSubnets() []SubnetConfig {
	var result []SubnetConfig
	for _, s := range nc.Subnets {
		if s.Scope == SubnetScopePublic {
			result = append(result, s)
		}
	}
	return result
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Disk == nil {
		return ErrInvalidConfig("disk configuration is required")
	}
	if c.Disk.Device == "" {
		return ErrInvalidConfig("disk device is required")
	}
	if c.OS == nil {
		return ErrInvalidConfig("OS configuration is required")
	}
	// Validate network configuration if present
	if c.Network != nil {
		if err := c.Network.Validate(); err != nil {
			return err
		}
	}
	// Validate Secure Boot configuration if present
	if c.SecureBoot != nil {
		if err := c.SecureBoot.Validate(); err != nil {
			return err
		}
	}
	// UKI configuration is optional - it can be handled externally
	return nil
}

// Installer is the main interface for system installation
type Installer interface {
	// Install performs the complete system installation
	Install(ctx context.Context) error

	// Close releases resources
	Close() error
}

// DiskManager handles disk partitioning and filesystem operations
type DiskManager interface {
	// CreatePartitionTable creates a new GPT or MBR partition table
	CreatePartitionTable(ctx context.Context, table PartitionTable) error

	// CreateEFIPartition creates and formats the EFI system partition
	CreateEFIPartition(ctx context.Context, sizeMB int) error

	// CreateRootPartition creates the root partition
	CreateRootPartition(ctx context.Context) error

	// SetupLUKS creates and opens a LUKS container
	SetupLUKS(ctx context.Context, partition string, config *EncryptionConfig) (string, error)

	// CreateLVMPhysicalVolume creates an LVM physical volume
	CreateLVMPhysicalVolume(ctx context.Context, device string) error

	// CreateLVMVolumeGroup creates an LVM volume group
	CreateLVMVolumeGroup(ctx context.Context, vgName string, pvDevices []string) error

	// CreateLVMLogicalVolume creates an LVM logical volume
	CreateLVMLogicalVolume(ctx context.Context, vgName, lvName string, size string) (string, error)

	// FormatFilesystem creates a filesystem on the given device
	FormatFilesystem(ctx context.Context, device, fsType, label string) error

	// Mount mounts a filesystem
	Mount(ctx context.Context, device, mountpoint, fsType string, flags uintptr) error

	// Unmount unmounts a filesystem
	Unmount(ctx context.Context, mountpoint string) error

	// EnsureDeviceNode ensures a device node exists, creating it if necessary
	EnsureDeviceNode(ctx context.Context, device string, maxWait time.Duration) error

	// Close releases resources
	Close() error
}

// OSInstaller handles OS-specific installation logic
type OSInstaller interface {
	// InstallBase installs the base operating system
	InstallBase(ctx context.Context, rootPath string) error

	// ConfigureSystem configures system files (fstab, crypttab, etc.)
	ConfigureSystem(ctx context.Context, rootPath string, diskInfo *DiskInfo) error

	// ConfigureNetwork configures network interfaces, DNS, bridges, bonds, and VLANs
	ConfigureNetwork(ctx context.Context, rootPath string, netConfig *NetworkConfig) error

	// InstallKernel installs kernel and initramfs
	InstallKernel(ctx context.Context, rootPath string) error

	// SetRootPassword sets the root password
	SetRootPassword(ctx context.Context, rootPath, password string) error

	// EnableServices enables essential system services in the default runlevel
	EnableServices(ctx context.Context, rootPath string) error

	// InstallPackages installs additional packages from configuration
	InstallPackages(ctx context.Context, rootPath string) error

	// ExecutePostInstall executes post-install scripts from configuration
	ExecutePostInstall(ctx context.Context, rootPath string) error

	// Name returns the OS name
	Name() OperatingSystem
}

// UKIBuilder handles Unified Kernel Image building
type UKIBuilder interface {
	// BuildUKI builds a Unified Kernel Image
	BuildUKI(ctx context.Context, config *UKIConfig, output io.Writer) error
}

// DiskInfo contains information about the disk configuration
type DiskInfo struct {
	Device           string
	EFIPartition     string
	RootPartition    string
	LUKSPartition    string
	MappedDevice     string
	EFIUUID          string
	RootUUID         string
	LUKSUUID         string
	PartitionTable   PartitionTable
	FilesystemType   FilesystemType
	LVMVolumeGroup   string
	LVMLogicalVolume string
	LVMDevice        string // /dev/mapper/vg-lv
}
