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
}

// AlpineConfig holds Alpine Linux ISO configuration
type AlpineConfig struct {
	Version  string `yaml:"version" json:"version"`
	Mirror   string `yaml:"mirror" json:"mirror"`
	ISO      string `yaml:"iso" json:"iso"`
	URL      string `yaml:"url" json:"url"`
	Packages string `yaml:"packages" json:"packages"`
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
	ConfigFile         string       `yaml:"config_file" json:"config_file"`       // platformd.yaml config file path
	CABundlePath       string       `yaml:"ca_bundle_path" json:"ca_bundle_path"` // CA bundle to embed in ISO for client trust store
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
		return fmt.Errorf("alpine version is required")
	}
	if c.Alpine.Mirror == "" {
		return fmt.Errorf("alpine mirror is required")
	}
	if c.Directories.Work == "" {
		return fmt.Errorf("work directory is required")
	}
	if c.Platform.Version == "" {
		return fmt.Errorf("platform version is required")
	}

	// Validate security settings
	if c.Security.Lockdown && c.Security.LockdownMode != "integrity" && c.Security.LockdownMode != "confidentiality" {
		return fmt.Errorf("lockdown_mode must be either 'integrity' or 'confidentiality'")
	}

	// Validate root filesystem type
	if c.RootFS.Type != "lvm" && c.RootFS.Type != "ext4" {
		return fmt.Errorf("root_fs type must be either 'lvm' or 'ext4'")
	}

	// Validate TPM PCR values if auto-unseal is enabled
	if c.Security.TPM.AutoUnseal && c.Security.TPM.SealPCR == "" {
		return fmt.Errorf("tpm seal_pcr is required when auto_unseal is enabled")
	}

	return nil
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
