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

package iso

import (
	"context"
	"fmt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uki"
	"io"
	"path/filepath"
)

// ISOBuilder handles ISO image creation
type ISOBuilder interface {
	// BuildISO creates a bootable ISO image
	BuildISO(ctx context.Context, config *ISOConfig) error

	// ValidateISO verifies the created ISO
	ValidateISO(ctx context.Context, isoPath string) error
}

// ISOExtractor handles ISO extraction operations
type ISOExtractor interface {
	// ExtractISO extracts ISO contents to the configured directory
	ExtractISO(ctx context.Context, config *ISOConfig) error
}

// BootConfig defines boot loader configuration
type BootConfig struct {
	// BIOS boot loader path (isolinux)
	BIOSBootPath string

	// UEFI boot image path
	UEFIBootImage string

	// Boot catalog path
	BootCatalog string

	// Boot load size (typically 4)
	BootLoadSize int
}

// ISOResult contains information about the created ISO
type ISOResult struct {
	// Path to the created ISO file
	Path string

	// Size in bytes
	Size int64

	// VolumeID is the volume identifier
	VolumeID string

	// Whether the ISO is bootable
	Bootable bool

	// Supported boot methods
	BootMethods []string
}

// XorrisoRunner executes xorriso commands
type XorrisoRunner interface {
	// Run executes xorriso with the given arguments
	Run(ctx context.Context, args []string, stdout, stderr io.Writer) error

	// Version returns the xorriso version
	Version(ctx context.Context) (string, error)
}

// PlatformISOConfig defines comprehensive configuration for platform ISO building
type PlatformISOConfig struct {
	// Alpine configuration
	Alpine AlpineConfig `yaml:"alpine" json:"alpine"`

	// Working directories
	Directories DirectoryConfig `yaml:"directories" json:"directories"`

	// Platform configuration
	Platform PlatformConfig `yaml:"platform" json:"platform"`

	// Security configuration
	Security SecurityConfig `yaml:"security" json:"security"`

	// LUKS encryption configuration
	LUKS LUKSConfig `yaml:"luks" json:"luks"`

	// Root filesystem configuration
	RootFS RootFSConfig `yaml:"root_fs" json:"root_fs"`

	// Build configuration
	Build BuildOptions `yaml:"build" json:"build"`

	// Output configuration
	Output OutputConfig `yaml:"output" json:"output"`

	// Installer overrides applied to the generated installer configuration
	// (every field is optional; the zero value keeps the x86_64 ISO defaults)
	Installer InstallerOverrides `yaml:"installer" json:"installer"`
}

// InstallerOverrides carries the per-target adjustments to the installer
// configuration the media generator embeds. The ISO leaves every field
// empty; an image target (an SD card for a Raspberry Pi) sets the ones its
// hardware needs.
type InstallerOverrides struct {
	// Device is the install target block device (default /dev/sda).
	Device string `yaml:"device,omitempty" json:"device,omitempty"`
	// PartitionTable is "gpt" (default) or "mbr".
	PartitionTable string `yaml:"partition_table,omitempty" json:"partition_table,omitempty"`
	// KernelPackage is the apk kernel package to install and prefetch
	// (default linux-lts; linux-rpi for a Raspberry Pi).
	KernelPackage string `yaml:"kernel_package,omitempty" json:"kernel_package,omitempty"`
	// ExtraPackages are additional apk packages to prefetch and install.
	ExtraPackages []string `yaml:"extra_packages,omitempty" json:"extra_packages,omitempty"`
	// HardwareManufacturer and HardwareModel select the pkg/quirks entry
	// whose kernel command line and console wiring the target needs. Empty
	// means the generic default quirk.
	HardwareManufacturer string `yaml:"hardware_manufacturer,omitempty" json:"hardware_manufacturer,omitempty"`
	HardwareModel        string `yaml:"hardware_model,omitempty" json:"hardware_model,omitempty"`
	// Target is the installer target: disk (default) or image (a
	// loop-mounted disk image on a build host).
	Target string `yaml:"target,omitempty" json:"target,omitempty"`
	// BootFirmware is the firmware the installed system boots under: uefi
	// (default) or uboot.
	BootFirmware string `yaml:"boot_firmware,omitempty" json:"boot_firmware,omitempty"`
	// KernelArtifactsDir, when set, is where on the mounted media the
	// installer finds a platform-built kernel for KernelPackage's flavour
	// (installer.OSConfig.KernelArtifactsDir); the kernel package is then
	// neither prefetched nor installed from apk.
	KernelArtifactsDir string `yaml:"kernel_artifacts_dir,omitempty" json:"kernel_artifacts_dir,omitempty"`
}

// AlpineConfig holds Alpine Linux ISO configuration
type AlpineConfig struct {
	Version string `yaml:"version" json:"version"`
	Mirror  string `yaml:"mirror" json:"mirror"`
	// Architecture is the target CPU architecture in Alpine spelling
	// (x86_64, the default, or aarch64; GOARCH aliases are accepted). It
	// selects the apk repository, the minirootfs and the ELF machine the
	// bundled binaries must have.
	Architecture string `yaml:"architecture" json:"architecture"`
	// APKMirror is the INSTALL-time APK repository base URL (e.g.
	// "http://198.51.100.11:8080"). It is distinct from Mirror, which is
	// the BUILD-time pre-fetch source: APKMirror is baked into the kernel
	// cmdline (platform_apk_mirror=) so a node that has no /media/cdrom —
	// the PXE case, where only vmlinuz+initramfs are fetched over the
	// network — can still resolve packages at install time. When empty the
	// autoinstall repo setup falls back to the public Alpine mirror.
	APKMirror string `yaml:"apk_mirror" json:"apk_mirror"`
	ISO       string `yaml:"iso" json:"iso"`
	URL       string `yaml:"url" json:"url"`
	Packages  string `yaml:"packages" json:"packages"`
}

// DirectoryConfig holds directory paths for the build process
type DirectoryConfig struct {
	Work       string `yaml:"work" json:"work"`
	ISO        string `yaml:"iso" json:"iso"`
	Overlay    string `yaml:"overlay" json:"overlay"`
	Keys       string `yaml:"keys" json:"keys"`
	NVRAM      string `yaml:"nvram" json:"nvram"`
	ConfigsDir string `yaml:"configs_dir" json:"configs_dir"` // Base directory for configs/os files
}

// PlatformConfig holds platform binary and version configuration
type PlatformConfig struct {
	Version            string       `yaml:"version" json:"version"`
	PlatformdBinary    string       `yaml:"platformd_binary" json:"platformd_binary"`
	PlatformctlBinary  string       `yaml:"platformctl_binary" json:"platformctl_binary"` // Optional CLI binary
	ObjcopyBinary      string       `yaml:"objcopy_binary" json:"objcopy_binary"`
	ConfigFile         string       `yaml:"config_file" json:"config_file"`           // platformd.yaml config file path
	CABundlePath       string       `yaml:"ca_bundle_path" json:"ca_bundle_path"`     // CA bundle to embed in ISO for client trust store
	CAKeyAlgorithm     string       `yaml:"ca_key_algorithm" json:"ca_key_algorithm"` // Filter CA bundle by key algorithm (e.g., rsa, ecdsa, ed25519)
	AfterInstallAction string       `yaml:"after_install_action" json:"after_install_action"`
	WebUIPath          string       `yaml:"webui_path" json:"webui_path"`       // Path to public_html directory or tarball
	PlatformType       PlatformType `yaml:"platform_type" json:"platform_type"` // Platform type: client or server

	// Dynamic configuration for server-based config fetch at boot time
	ConfigServerURL   string `yaml:"config_server_url" json:"config_server_url"`
	BootstrapStrategy string `yaml:"bootstrap_strategy" json:"bootstrap_strategy"`
	BootstrapDNS      string `yaml:"bootstrap_dns" json:"bootstrap_dns"`
	BootstrapNoiseKey string `yaml:"bootstrap_noise_key" json:"bootstrap_noise_key"`
	BootstrapSPKIPin  string `yaml:"bootstrap_spki_pin" json:"bootstrap_spki_pin"`

	// DebugSink is the host:port of the bootstrap container's HTTP forensic
	// sink. Baked into the kernel cmdline as platform_debug_sink=<value>.
	// The autoinstall.sh upload_install_log function reads this and PUTs
	// /tmp/install.log there on every exit path. Defaults to
	// 198.18.1.91:8080 (our reference deployment) when unset; override
	// per-deployment via the iso create CLI flag --debug-sink.
	DebugSink string `yaml:"debug_sink,omitempty" json:"debug_sink,omitempty"`
}

// SecurityConfig holds security-related configuration
type SecurityConfig struct {
	// TPM configuration
	TPM TPMConfig `yaml:"tpm" json:"tpm"`

	// Secure Boot configuration
	SecureBoot bool   `yaml:"secure_boot" json:"secure_boot"`
	OVMFCode   string `yaml:"ovmf_code" json:"ovmf_code"`
	OVMFVars   string `yaml:"ovmf_vars" json:"ovmf_vars"`

	// System lockdown
	Lockdown     bool   `yaml:"lockdown" json:"lockdown"`
	LockdownMode string `yaml:"lockdown_mode" json:"lockdown_mode"`

	// FIPS mode
	FIPS       bool       `yaml:"fips" json:"fips"`
	FIPSConfig FIPSConfig `yaml:"fips_config" json:"fips_config"`

	// FIDO2 security key support
	EnableFIDO2 bool `yaml:"enable_fido2" json:"enable_fido2"`
}

// FIPSConfig holds FIPS artifact container configuration
type FIPSConfig struct {
	// Container runtime: "docker" or "podman" (default: "docker")
	ContainerRuntime string `yaml:"container_runtime" json:"container_runtime"`

	// OpenSSL FIPS provider container name (default: "openssl-fips-provider-builder")
	OpenSSLContainer string `yaml:"openssl_container" json:"openssl_container"`

	// FIPS kernel builder container name (default: "fips-kernel-builder")
	KernelContainer string `yaml:"kernel_container" json:"kernel_container"`
}

// TPMConfig holds TPM-related configuration
type TPMConfig struct {
	AutoUnseal      bool   `yaml:"auto_unseal" json:"auto_unseal"`
	SealPCR         string `yaml:"seal_pcr" json:"seal_pcr"`
	Device          string `yaml:"device" json:"device"`
	AutoUpgradeSeal bool   `yaml:"auto_upgrade_seal" json:"auto_upgrade_seal"`
	SWTPMStateDir   string `yaml:"swtpm_state_dir" json:"swtpm_state_dir"`
	SWTPMCtrlSocket string `yaml:"swtpm_ctrl_socket" json:"swtpm_ctrl_socket"`
	SWTPMSocket     string `yaml:"swtpm_socket" json:"swtpm_socket"`
}

// LUKSConfig holds LUKS encryption configuration
type LUKSConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	TPMOnly bool `yaml:"tpm_only" json:"tpm_only"`
}

// RootFSConfig holds root filesystem configuration
type RootFSConfig struct {
	Type string `yaml:"type" json:"type"` // "lvm" or "ext4"
}

// BuildOptions holds build-specific configuration
type BuildOptions struct {
	Debug        bool   `yaml:"debug" json:"debug"`
	QEMUDisk     string `yaml:"qemu_disk" json:"qemu_disk"`
	QEMUDiskSize string `yaml:"qemu_disk_size" json:"qemu_disk_size"`
	PreFetch     bool   `yaml:"pre_fetch" json:"pre_fetch"` // Pre-fetch packages for offline installation
}

// OutputConfig holds output configuration
type OutputConfig struct {
	ISO       string `yaml:"iso" json:"iso"`
	Directory string `yaml:"directory" json:"directory"`
	Checksum  bool   `yaml:"checksum" json:"checksum"`
	Label     string `yaml:"label" json:"label"` // ISO volume label (max 32 chars)
}

// Validate validates the PlatformISOConfig
func (c *PlatformISOConfig) Validate() error {
	if c.Alpine.Version == "" {
		return &MessageError{Msg: "alpine version is required"}
	}
	if c.Alpine.Mirror == "" {
		return &MessageError{Msg: "alpine mirror is required"}
	}
	if c.Directories.Work == "" {
		return &MessageError{Msg: "work directory is required"}
	}
	if c.Platform.Version == "" {
		return &MessageError{Msg: "platform version is required"}
	}

	// Validate security settings
	if c.Security.Lockdown && c.Security.LockdownMode != "integrity" && c.Security.LockdownMode != "confidentiality" {
		return &MessageError{Msg: "lockdown_mode must be either 'integrity' or 'confidentiality'"}
	}

	// Validate root filesystem type
	if c.RootFS.Type != "lvm" && c.RootFS.Type != "ext4" {
		return &MessageError{Msg: "root_fs type must be either 'lvm' or 'ext4'"}
	}

	// Validate TPM PCR values if auto-unseal is enabled
	if c.Security.TPM.AutoUnseal && c.Security.TPM.SealPCR == "" {
		return &MessageError{Msg: "tpm seal_pcr is required when auto_unseal is enabled"}
	}

	arch, err := uki.ParseArchitecture(c.Alpine.Architecture)
	if err != nil {
		return &UnsupportedArchitectureError{Arch: c.Alpine.Architecture}
	}
	// The FIPS kernel and OpenSSL provider are container-built for x86_64
	// only (build/docker/fips-kernel-builder).
	if c.Security.FIPS && arch != uki.ArchX86_64 {
		return &FIPSUnsupportedArchitectureError{Arch: string(arch)}
	}
	switch c.Installer.PartitionTable {
	case "", string(installer.PartitionTableGPT), string(installer.PartitionTableMBR):
	default:
		return &MessageError{Msg: "installer partition_table must be either 'gpt' or 'mbr'"}
	}
	switch c.Installer.Target {
	case "", string(installer.InstallTargetDisk), string(installer.InstallTargetImage):
	default:
		return &MessageError{Msg: "installer target must be either 'disk' or 'image'"}
	}
	switch c.Installer.BootFirmware {
	case "", string(installer.BootFirmwareUEFI), string(installer.BootFirmwareUBoot):
	default:
		return &MessageError{Msg: "installer boot_firmware must be either 'uefi' or 'uboot'"}
	}

	return nil
}

// architecture returns the canonical target architecture, x86_64 when the
// configuration does not name one. Validate has already rejected anything
// pkg/uki does not model, so an unparsable value here is treated as the
// historical default rather than a second error path.
func (c *PlatformISOConfig) architecture() uki.Architecture {
	arch, err := uki.ParseArchitecture(c.Alpine.Architecture)
	if err != nil {
		return uki.ArchX86_64
	}
	return arch
}

// SetDefaults sets default values for empty configuration fields
func (c *PlatformISOConfig) SetDefaults() {
	if c.Directories.Work == "" {
		c.Directories.Work = "work"
	}

	// Set derived directory paths
	if c.Directories.ISO == "" {
		c.Directories.ISO = filepath.Join(c.Directories.Work, "iso")
	}
	if c.Directories.Overlay == "" {
		c.Directories.Overlay = filepath.Join(c.Directories.Work, "overlay")
	}
	if c.Directories.Keys == "" {
		c.Directories.Keys = filepath.Join(c.Directories.Work, "secure-boot-keys")
	}
	if c.Directories.NVRAM == "" {
		c.Directories.NVRAM = filepath.Join(c.Directories.Work, "nvram")
	}

	// Alpine defaults
	if c.Alpine.Mirror == "" {
		c.Alpine.Mirror = "http://mirror.cs.odu.edu/alpine"
	}
	// Canonicalise the architecture spelling ("arm64" -> "aarch64") so the
	// apk repository directory and the ELF check agree; an unknown value is
	// left for Validate to reject.
	if arch, err := uki.ParseArchitecture(c.Alpine.Architecture); err == nil {
		c.Alpine.Architecture = string(arch)
	}

	// Platform defaults
	if c.Platform.ObjcopyBinary == "" {
		c.Platform.ObjcopyBinary = "objcopy"
	}
	if c.Platform.AfterInstallAction == "" {
		c.Platform.AfterInstallAction = "poweroff"
	}

	// Security defaults
	if c.Security.TPM.Device == "" {
		c.Security.TPM.Device = "/dev/tpm0"
	}
	if c.Security.TPM.SealPCR == "" {
		c.Security.TPM.SealPCR = "0,7,9"
	}
	if c.Security.TPM.SWTPMStateDir == "" {
		c.Security.TPM.SWTPMStateDir = filepath.Join(c.Directories.Work, "tpm")
	}
	if c.Security.TPM.SWTPMCtrlSocket == "" {
		c.Security.TPM.SWTPMCtrlSocket = filepath.Join(c.Security.TPM.SWTPMStateDir, "swtpm-ctrl")
	}
	if c.Security.TPM.SWTPMSocket == "" {
		c.Security.TPM.SWTPMSocket = filepath.Join(c.Security.TPM.SWTPMStateDir, "swtpm-sock")
	}
	if c.Security.LockdownMode == "" {
		c.Security.LockdownMode = "confidentiality"
	}

	// OVMF defaults
	if c.Security.OVMFCode == "" {
		if c.Security.SecureBoot {
			c.Security.OVMFCode = "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd"
		} else {
			c.Security.OVMFCode = "/usr/share/OVMF/OVMF_CODE_4M.fd"
		}
	}
	if c.Security.OVMFVars == "" {
		c.Security.OVMFVars = "/usr/share/OVMF/OVMF_VARS_4M.fd"
	}

	// FIPS defaults
	if c.Security.FIPSConfig.ContainerRuntime == "" {
		c.Security.FIPSConfig.ContainerRuntime = "docker"
	}
	if c.Security.FIPSConfig.OpenSSLContainer == "" {
		c.Security.FIPSConfig.OpenSSLContainer = "openssl-fips-provider-builder"
	}
	if c.Security.FIPSConfig.KernelContainer == "" {
		c.Security.FIPSConfig.KernelContainer = "fips-kernel-builder"
	}

	// Root filesystem default
	if c.RootFS.Type == "" {
		c.RootFS.Type = "lvm"
	}

	// Build defaults
	if c.Build.QEMUDisk == "" {
		c.Build.QEMUDisk = "alpine-platform-installed.qcow2"
	}
	if c.Build.QEMUDiskSize == "" {
		c.Build.QEMUDiskSize = "10G"
	}

	// Output ISO name
	if c.Output.ISO == "" {
		suffix := ""
		if c.Security.FIPS {
			suffix = "-fips"
		}
		c.Output.ISO = fmt.Sprintf("trusted-platform-alpine%s-%s.iso", suffix, c.Platform.Version)
	}

	if c.Output.Directory == "" {
		c.Output.Directory = "."
	}
}

// String returns a human-readable representation of the configuration
func (c *PlatformISOConfig) String() string {
	return fmt.Sprintf("PlatformISOConfig{Alpine: %s, Platform: %s, SecureBoot: %v, TPM: %v, LUKS: %v, FIPS: %v}",
		c.Alpine.Version,
		c.Platform.Version,
		c.Security.SecureBoot,
		c.Security.TPM.AutoUnseal,
		c.LUKS.Enabled,
		c.Security.FIPS)
}
