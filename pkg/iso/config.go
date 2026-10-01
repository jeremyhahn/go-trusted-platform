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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uki"
	"gopkg.in/yaml.v2"
)

// PlatformType defines the type of platform (client or server)
type PlatformType string

const (
	// PlatformTypeServer is for server deployments (default)
	PlatformTypeServer PlatformType = "server"
	// PlatformTypeClient is for client deployments
	PlatformTypeClient PlatformType = "client"
)

// String returns the string representation of PlatformType
func (p PlatformType) String() string {
	return string(p)
}

// IsValid checks if the platform type is valid
func (p PlatformType) IsValid() bool {
	return p == PlatformTypeServer || p == PlatformTypeClient
}

// ISOBuildConfig defines complete ISO build configuration
type ISOBuildConfig struct {
	// Alpine configuration
	AlpineVersion string `yaml:"alpine-version" json:"alpine_version"`
	AlpineMirror  string `yaml:"alpine-mirror" json:"alpine_mirror"`
	Architecture  string `yaml:"architecture" json:"architecture"`

	// PlatformVersion is the platform release baked into the media
	// (PlatformConfig.Version); the CLI reads it from the VERSION file.
	PlatformVersion string `yaml:"platform-version,omitempty" json:"platform_version,omitempty"`

	// Platform type (client or server)
	PlatformType PlatformType `yaml:"platform-type" json:"platform_type"`

	// Output configuration
	OutputISO   string `yaml:"output-iso" json:"output_iso"`
	OutputLabel string `yaml:"output-label" json:"output_label"`
	WorkDir     string `yaml:"work-dir" json:"work_dir"`

	// Binary path (auto-detected via os.Executable() - binary copies itself)
	PlatformdBinary string `yaml:"platformd-binary" json:"platformd_binary"`

	// Platform configuration file (platformd.yaml for TPM provisioning)
	PlatformConfigFile string `yaml:"platform-config-file" json:"platform_config_file"`

	// CA bundle path - the CA certificate chain to embed in the ISO for client trust
	// This is exported from the server's CA and installed to the client's OS trust store
	CABundlePath string `yaml:"ca-bundle-path" json:"ca_bundle_path"`

	// CA key algorithm filter - when set, only include certs for this key algorithm
	// Maps to the CA bundle endpoint: /api/v1/acme/ca-bundle/{storeType}/{keyAlgo}
	// Empty means include all algorithms (default bundle)
	CAKeyAlgorithm string `yaml:"ca-key-algorithm" json:"ca_key_algorithm"`

	// Installer configuration file (disk layout, LUKS, TPM settings)

	// WebUI path (public_html directory or tarball)
	WebUIPath string `yaml:"webui-path" json:"webui_path"`

	// Installation configuration
	InstallConfig *installer.Config `yaml:"install-config,omitempty" json:"install_config,omitempty"`
	ConfigFile    string            `yaml:"config-file,omitempty" json:"config_file,omitempty"`
	Profile       string            `yaml:"profile,omitempty" json:"profile,omitempty"`

	// Device profile configuration for network provisioning
	// DeviceProfile is an inline device profile for network configuration
	DeviceProfile *entities.DeviceProfile `yaml:"device-profile,omitempty" json:"device_profile,omitempty"`
	// DeviceProfilePath is a path to a device profile YAML file
	DeviceProfilePath string `yaml:"device-profile-path,omitempty" json:"device_profile_path,omitempty"`
	// PlatformAPIEndpoint is the platform API URL for device profile fetching
	PlatformAPIEndpoint string `yaml:"platform-api-endpoint,omitempty" json:"platform_api_endpoint,omitempty"`

	// Secure Boot
	KeysDir      string `yaml:"keys-dir" json:"keys_dir"`
	GenerateKeys bool   `yaml:"generate-keys" json:"generate_keys"`
	KeyBackend   string `yaml:"key-backend" json:"key_backend"` // Key backend: file, software, pkcs11, tpm2, awskms, azurekv, gcpkms, vault

	// TPM configuration
	TPMAutoUnseal      bool   `yaml:"tpm-auto-unseal" json:"tpm_auto_unseal"`
	TPMSealPCR         []uint `yaml:"tpm-seal-pcr" json:"tpm_seal_pcr"`
	TPMAutoUpgradeSeal bool   `yaml:"tpm-auto-upgrade-seal" json:"tpm_auto_upgrade_seal"`
	LUKSTPMOnly        bool   `yaml:"luks-tpm-only" json:"luks_tpm_only"`

	// System configuration
	RootFS       string `yaml:"root-fs" json:"root_fs"`
	Lockdown     bool   `yaml:"lockdown" json:"lockdown"`
	LockdownMode string `yaml:"lockdown-mode" json:"lockdown_mode"`
	FIPS         bool   `yaml:"fips" json:"fips"`
	// NetworkServed marks media served over the network (a netboot media
	// set) rather than written to a disc or card: it must never carry
	// private key material, whatever the Secure Boot setting.
	NetworkServed bool   `yaml:"network-served" json:"network_served"`
	SecureBoot    bool   `yaml:"secure-boot" json:"secure_boot"`
	EnableFIDO2   bool   `yaml:"enable-fido2" json:"enable_fido2"`
	AfterInstall  string `yaml:"after-install" json:"after_install"`

	// Additional packages
	Packages []string `yaml:"packages" json:"packages"`

	// Build options
	Force bool `yaml:"force" json:"force"`
	Debug bool `yaml:"debug" json:"debug"`

	// Pre-fetch packages for offline installation
	PreFetch bool `yaml:"pre-fetch" json:"pre_fetch"`

	// Dynamic configuration: when ConfigServerURL is set and no config file is
	// provided, the ISO injects kernel cmdline params so the device fetches its
	// config from the server at boot time.

	// ConfigServerURL is the server URL for dynamic config fetch at boot time.
	ConfigServerURL string `yaml:"config-server-url,omitempty" json:"config_server_url,omitempty"`

	// BootstrapStrategy is the trust bootstrap strategy (dane, noise, spki, auto).
	// Used when ConfigServerURL is set. Default: "auto"
	BootstrapStrategy string `yaml:"bootstrap-strategy,omitempty" json:"bootstrap_strategy,omitempty"`

	// BootstrapDNS is the DNS server for DANE TLSA lookups.
	BootstrapDNS string `yaml:"bootstrap-dns,omitempty" json:"bootstrap_dns,omitempty"`

	// BootstrapNoiseKey is the Noise server public key (hex-encoded).
	BootstrapNoiseKey string `yaml:"bootstrap-noise-key,omitempty" json:"bootstrap_noise_key,omitempty"`

	// BootstrapSPKIPin is the SPKI pin SHA-256 hash for certificate pinning.
	BootstrapSPKIPin string `yaml:"bootstrap-spki-pin,omitempty" json:"bootstrap_spki_pin,omitempty"`

	// APKMirror is the INSTALL-time APK repository base URL baked into the
	// kernel cmdline as platform_apk_mirror=. It is distinct from
	// AlpineMirror (the BUILD-time pre-fetch source). PXE-booted nodes have
	// no /media/cdrom, so without an install mirror their post-switch-root
	// apk repos would be empty; this URL gives them a working repository.
	// Empty means the autoinstall repo setup falls back to the public
	// Alpine mirror (dl-cdn) at install time.
	APKMirror string `yaml:"apk-mirror,omitempty" json:"apk_mirror,omitempty"`
}

// IsDynamicConfigMode returns true when the ISO should fetch config from a
// server at boot time rather than embedding a config file.
func (c *ISOBuildConfig) IsDynamicConfigMode() bool {
	return c.ConfigServerURL != "" && c.PlatformConfigFile == "" &&
		c.InstallConfig == nil && c.ConfigFile == "" && c.Profile == ""
}

// DefaultISOBuildConfig returns default configuration
func DefaultISOBuildConfig() *ISOBuildConfig {
	return &ISOBuildConfig{
		AlpineVersion:      "3.22.2",
		AlpineMirror:       "https://dl-cdn.alpinelinux.org/alpine",
		Architecture:       "x86_64",
		PlatformType:       PlatformTypeServer, // Default to server
		OutputLabel:        "TRUSTED_PLATFORM",
		WorkDir:            "work",
		RootFS:             "lvm",
		LockdownMode:       "confidentiality",
		AfterInstall:       "poweroff",
		TPMAutoUpgradeSeal: true,
		TPMSealPCR:         []uint{0, 7, 9},
		GenerateKeys:       true,
	}
}

// Validate validates the configuration
func (c *ISOBuildConfig) Validate() error {
	if c.AlpineVersion == "" {
		return &MessageError{Msg: "alpine version is required"}
	}

	if c.AlpineMirror == "" {
		return &MessageError{Msg: "alpine mirror is required"}
	}

	if c.Architecture == "" {
		return &MessageError{Msg: "architecture is required"}
	}

	// Validate architecture is supported
	validArch := map[string]bool{
		"x86_64":  true,
		"aarch64": true,
	}
	if !validArch[c.Architecture] {
		return &MessageError{Msg: fmt.Sprintf("unsupported architecture: %s (supported: x86_64, aarch64)", c.Architecture)}
	}

	// Validate platform type
	if c.PlatformType != "" && !c.PlatformType.IsValid() {
		return &MessageError{Msg: fmt.Sprintf("unsupported platform type: %s (supported: server, client)", c.PlatformType)}
	}
	// Set default if empty
	if c.PlatformType == "" {
		c.PlatformType = PlatformTypeServer
	}

	if c.WorkDir == "" {
		return &MessageError{Msg: "work directory is required"}
	}

	// Validate root filesystem type
	if c.RootFS != "" && c.RootFS != "lvm" && c.RootFS != "ext4" {
		return &MessageError{Msg: fmt.Sprintf("root-fs must be 'lvm' or 'ext4', got: %s", c.RootFS)}
	}

	// Validate lockdown mode
	if c.Lockdown && c.LockdownMode != "" {
		if c.LockdownMode != "integrity" && c.LockdownMode != "confidentiality" {
			return &MessageError{Msg: fmt.Sprintf("lockdown-mode must be 'integrity' or 'confidentiality', got: %s", c.LockdownMode)}
		}
	}

	// Validate after-install action
	if c.AfterInstall != "" && c.AfterInstall != "reboot" && c.AfterInstall != "poweroff" {
		return &MessageError{Msg: fmt.Sprintf("after-install must be 'reboot' or 'poweroff', got: %s", c.AfterInstall)}
	}

	// Validate mutually exclusive config sources
	configSources := 0
	if c.InstallConfig != nil {
		configSources++
	}
	if c.ConfigFile != "" {
		configSources++
	}
	if c.Profile != "" {
		configSources++
	}
	if configSources > 1 {
		return &MessageError{Msg: "only one of install-config, config-file, or profile can be specified"}
	}

	// Validate config file exists if specified
	if c.ConfigFile != "" {
		if _, err := os.Stat(c.ConfigFile); os.IsNotExist(err) {
			return &MessageError{Msg: fmt.Sprintf("config file not found: %s", c.ConfigFile)}
		}
	}

	// Validate profile name if specified
	if c.Profile != "" {
		if err := installer.ValidateProfileName(c.Profile); err != nil {
			return &WrappedError{Msg: "invalid profile", Err: err}
		}
	}

	// Validate binary path exists if specified
	if c.PlatformdBinary != "" {
		if _, err := os.Stat(c.PlatformdBinary); os.IsNotExist(err) {
			return &MessageError{Msg: fmt.Sprintf("platformd binary not found: %s", c.PlatformdBinary)}
		}
	}

	// Validate keys directory exists if specified and not generating
	if c.KeysDir != "" && !c.GenerateKeys {
		if _, err := os.Stat(c.KeysDir); os.IsNotExist(err) {
			return &MessageError{Msg: fmt.Sprintf("keys directory not found: %s", c.KeysDir)}
		}
	}

	return nil
}

// GetInstallConfig returns or generates install config
func (c *ISOBuildConfig) GetInstallConfig() (*installer.Config, error) {
	// If InstallConfig is already provided, use it
	if c.InstallConfig != nil {
		return c.InstallConfig, nil
	}

	// If ConfigFile is provided, load it
	if c.ConfigFile != "" {
		config, err := installer.LoadConfig(c.ConfigFile)
		if err != nil {
			return nil, &WrappedError{Msg: "failed to load config file", Err: err}
		}
		return config, nil
	}

	// If Profile is provided, load it
	if c.Profile != "" {
		config, err := LoadProfile(c.Profile)
		if err != nil {
			return nil, &WrappedError{Msg: "failed to load profile", Err: err}
		}
		// Apply build config overrides to profile
		c.applyOverrides(config)
		return config, nil
	}

	// Generate config from build config
	config := c.generateInstallConfig()
	return config, nil
}

// generateInstallConfig creates an installer.Config from ISOBuildConfig
func (c *ISOBuildConfig) generateInstallConfig() *installer.Config {
	config := installer.DefaultConfig()

	// Set OS configuration
	if config.OS == nil {
		config.OS = &installer.OSConfig{}
	}
	config.OS.OS = installer.OSAlpine
	config.OS.Version = c.AlpineVersion
	config.OS.Architecture = c.Architecture
	config.OS.Mirror = c.AlpineMirror
	config.OS.Packages = c.Packages
	config.OS.FIPS = c.FIPS
	config.OS.Lockdown = c.Lockdown
	config.OS.LockdownMode = c.LockdownMode
	config.OS.TPMAutoUpgradeSeal = c.TPMAutoUpgradeSeal
	config.OS.PlatformdBinary = c.PlatformdBinary

	// Set root filesystem
	if c.RootFS != "" {
		if config.Disk == nil {
			config.Disk = &installer.DiskConfig{}
		}
		config.Disk.RootFilesystem = installer.FilesystemType(c.RootFS)
		config.OS.FilesystemType = installer.FilesystemType(c.RootFS)
	}

	// Set TPM configuration
	config.EnableTPMSealing = c.TPMAutoUnseal
	if len(c.TPMSealPCR) > 0 {
		config.PCRs = c.TPMSealPCR
	}

	// Set Secure Boot. Mirror customize.go's buildInstallerConfig: the DB
	// keypair is staged on the install media (ISO root secure-boot-keys/,
	// mounted at SecureBootKeysMediaDir during installation) and referenced
	// via file:// so offline ISO signing resolves it locally (ResignMode
	// local).
	if c.SecureBoot {
		config.SecureBoot = &installer.SecureBootConfig{
			Enabled:    true,
			ResignMode: installer.SecureBootResignModeLocal,
			DB: installer.SecureBootKeyRef{
				KeyURI:  "file://" + SecureBootKeysMediaDir + "/DB.key",
				CertURI: "file://" + SecureBootKeysMediaDir + "/DB.crt",
			},
		}
	}

	// Set debug mode
	config.Debug = c.Debug

	return config
}

// applyOverrides applies build config overrides to a loaded config
func (c *ISOBuildConfig) applyOverrides(config *installer.Config) {
	if config.OS != nil {
		// Override version if specified
		if c.AlpineVersion != "" {
			config.OS.Version = c.AlpineVersion
		}
		// Override mirror if specified
		if c.AlpineMirror != "" {
			config.OS.Mirror = c.AlpineMirror
		}
		// Override architecture if specified
		if c.Architecture != "" {
			config.OS.Architecture = c.Architecture
		}
		// Override packages if specified
		if len(c.Packages) > 0 {
			config.OS.Packages = c.Packages
		}
		// Override binary path if specified
		if c.PlatformdBinary != "" {
			config.OS.PlatformdBinary = c.PlatformdBinary
		}
	}

	// Override debug mode
	if c.Debug {
		config.Debug = true
	}
}

// LoadProfile loads a built-in profile
func LoadProfile(name string) (*installer.Config, error) {
	return installer.GetProfile(name)
}

// ResolveWorkDir creates and returns work directory
func (c *ISOBuildConfig) ResolveWorkDir() (string, error) {
	if c.WorkDir == "" {
		c.WorkDir = "work"
	}

	// Convert to absolute path
	workDir, err := filepath.Abs(c.WorkDir)
	if err != nil {
		return "", &WrappedError{Msg: "failed to resolve work directory", Err: err}
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(workDir, 0755); err != nil {
		return "", &WrappedError{Msg: "failed to create work directory", Err: err}
	}

	c.WorkDir = workDir
	return workDir, nil
}

// ErrPlatformdBinaryName is returned when the resolved binary cannot be
// recognized as platformd. The Name and Path fields preserve the rejected
// input for diagnostics; the Reason explains which check failed.
type ErrPlatformdBinaryName struct {
	Name   string
	Path   string
	Reason string
}

// Error implements the error interface.
func (e *ErrPlatformdBinaryName) Error() string {
	return "iso: " + e.Reason + " (got " + e.Name + " at " + e.Path + ")"
}

// ValidatePlatformdBinaryName checks that the resolved binary is platformd.
// It accepts any basename whose lowercase form contains the substring
// "platformd" so that prefixed builds (e.g. "my-platformd",
// "platformd-fips") still validate. The companion CLI binary "platformctl"
// is explicitly rejected with a typed error mentioning "platformctl" to give
// callers a clear remediation hint regardless of case.
func ValidatePlatformdBinaryName(path string) error {
	name := filepath.Base(path)
	lower := strings.ToLower(name)

	// Reject the companion CLI explicitly first so a binary named
	// "PlatformCtl" or "platformctl-debug" doesn't slip through the
	// "contains platformd" check (it doesn't, but be explicit).
	if strings.Contains(lower, "platformctl") {
		return &ErrPlatformdBinaryName{
			Name:   name,
			Path:   path,
			Reason: "binary appears to be platformctl, not platformd",
		}
	}

	if !strings.Contains(lower, "platformd") {
		return &ErrPlatformdBinaryName{
			Name:   name,
			Path:   path,
			Reason: "binary does not appear to be platformd",
		}
	}

	return nil
}

// ResolveBinaries validates the platformd binary path
// The binary is auto-detected using os.Executable() in the command layer
func (c *ISOBuildConfig) ResolveBinaries() error {
	// Validate platformd binary exists (should be auto-detected via os.Executable())
	if c.PlatformdBinary == "" {
		return &MessageError{Msg: "platformd binary path not set (should be auto-detected)"}
	}

	if _, err := os.Stat(c.PlatformdBinary); os.IsNotExist(err) {
		return &MessageError{Msg: fmt.Sprintf("platformd binary not found: %s", c.PlatformdBinary)}
	}

	// Validate the binary is actually platformd, not platformctl
	if err := ValidatePlatformdBinaryName(c.PlatformdBinary); err != nil {
		return err
	}

	return nil
}

// GetAlpineISOURL returns the download URL
func (c *ISOBuildConfig) GetAlpineISOURL() string {
	majorVersion := getMajorVersion(c.AlpineVersion)
	filename := c.GetAlpineISOFilename()
	return fmt.Sprintf("%s/v%s/releases/%s/%s",
		c.AlpineMirror, majorVersion, c.Architecture, filename)
}

// GetAlpineISOFilename returns the ISO filename
func (c *ISOBuildConfig) GetAlpineISOFilename() string {
	return fmt.Sprintf("alpine-standard-%s-%s.iso", c.AlpineVersion, c.Architecture)
}

// ISOConfig defines configuration for ISO operations (download, extract, build)
type ISOConfig struct {
	// Version is the Alpine version to download (e.g., "3.22.2")
	Version string

	// ISO is the ISO filename (e.g., "alpine-standard-3.22.2-x86_64.iso")
	// If empty, it will be auto-generated from Version
	ISO string

	// URL is the full download URL for the ISO
	// If empty, it will be auto-generated from MirrorURL and Version
	URL string

	// MirrorURL is the base mirror URL (e.g., "http://mirror.cs.odu.edu/alpine")
	MirrorURL string

	// Architecture is the Alpine architecture of the ISO to download
	// (x86_64, the default, or aarch64); it selects the release directory and
	// the ISO file name.
	Architecture string

	// WorkDir is the directory where the ISO will be downloaded
	WorkDir string

	// ISODir is the directory where ISO contents will be extracted
	// Default: WorkDir/iso
	ISODir string

	// VerifyChecksum enables SHA256 checksum verification against the
	// mirror's .sha256 file.
	VerifyChecksum bool

	// SHA256, when set, pins the file's hex SHA-256. It replaces the
	// mirror's checksum — a pin is part of the build, the mirror's file is
	// not — and a cached download is re-verified against it on every run.
	SHA256 string

	// ResumeDownload enables resuming partial downloads
	ResumeDownload bool

	// ProgressCallback is called with download progress updates
	// Receives: bytesDownloaded, totalBytes, percentComplete
	ProgressCallback func(int64, int64, float64)

	// OutputISO is the path for the output ISO when building
	OutputISO string

	// KeysDir is the secure boot keys directory (optional)
	KeysDir string

	// VolumeID is the volume ID for the ISO (max 32 chars)
	VolumeID string

	// ApplicationID is the application ID (optional)
	ApplicationID string

	// PublisherID is the publisher ID (optional)
	PublisherID string

	// Debug enables debug output
	Debug bool
}

// DefaultISOConfig returns a configuration with sensible defaults
func DefaultISOConfig() *ISOConfig {
	return &ISOConfig{
		Version:        "3.22.2",
		MirrorURL:      "http://mirror.cs.odu.edu/alpine",
		Architecture:   "x86_64",
		WorkDir:        "work",
		VerifyChecksum: true,
		ResumeDownload: true,
		VolumeID:       "ALPINE",
	}
}

// Validate checks the configuration and auto-populates derived fields
func (c *ISOConfig) Validate() error {
	if c.Version == "" {
		return &MessageError{Msg: "version is required"}
	}

	if c.WorkDir == "" {
		return &MessageError{Msg: "work directory is required"}
	}

	if c.MirrorURL == "" {
		return &MessageError{Msg: "mirror URL is required"}
	}

	if c.SHA256 != "" {
		if _, err := hex.DecodeString(c.SHA256); err != nil || len(c.SHA256) != sha256.Size*2 {
			return &MessageError{Msg: "pinned SHA256 " + c.SHA256 + " is not a hex SHA-256 digest"}
		}
	}

	arch, err := uki.ParseArchitecture(c.Architecture)
	if err != nil {
		return &UnsupportedArchitectureError{Arch: c.Architecture}
	}
	c.Architecture = string(arch)

	// Auto-generate ISO filename if not provided
	if c.ISO == "" {
		c.ISO = fmt.Sprintf("alpine-standard-%s-%s.iso", c.Version, c.Architecture)
	}

	// Auto-generate download URL if not provided
	if c.URL == "" {
		majorVersion := getMajorVersion(c.Version)
		c.URL = fmt.Sprintf("%s/v%s/releases/%s/%s",
			c.MirrorURL, majorVersion, c.Architecture, c.ISO)
	}

	// Auto-generate ISODir if not provided
	if c.ISODir == "" {
		c.ISODir = filepath.Join(c.WorkDir, "iso")
	}

	return nil
}

// ChecksumURL returns the URL for the ISO checksum file
func (c *ISOConfig) ChecksumURL() string {
	return c.URL + ".sha256"
}

// ISOPath returns the full path to the downloaded ISO
func (c *ISOConfig) ISOPath() string {
	return filepath.Join(c.WorkDir, c.ISO)
}

// ChecksumPath returns the full path to the checksum file
func (c *ISOConfig) ChecksumPath() string {
	return c.ISOPath() + ".sha256"
}

// VerifiedMarkerPath returns the path to the verification marker file
func (c *ISOConfig) VerifiedMarkerPath() string {
	return c.ISOPath() + ".verified"
}

// TempPath returns the temporary download path
func (c *ISOConfig) TempPath() string {
	return c.ISOPath() + ".tmp"
}

// DownloadConfig holds Alpine ISO download configuration
type DownloadConfig struct {
	Version      string `yaml:"version" json:"version"`
	Mirror       string `yaml:"mirror" json:"mirror"`
	Architecture string `yaml:"architecture" json:"architecture"`
	OutputDir    string `yaml:"output-dir" json:"output_dir"`
	Force        bool   `yaml:"force" json:"force"`
	Debug        bool   `yaml:"debug" json:"debug"`
}

// Validate validates the download configuration
func (c *DownloadConfig) Validate() error {
	if c.Version == "" {
		return &MessageError{Msg: "version is required"}
	}
	if c.Mirror == "" {
		return &MessageError{Msg: "mirror is required"}
	}
	if c.Architecture == "" {
		return &MessageError{Msg: "architecture is required"}
	}
	if c.OutputDir == "" {
		return &MessageError{Msg: "output directory is required"}
	}

	// Validate architecture
	validArch := map[string]bool{
		"x86_64":  true,
		"aarch64": true,
	}
	if !validArch[c.Architecture] {
		return &MessageError{Msg: fmt.Sprintf("unsupported architecture: %s (supported: x86_64, aarch64)", c.Architecture)}
	}

	return nil
}

// GetISOURL returns the download URL
func (c *DownloadConfig) GetISOURL() string {
	majorVersion := getMajorVersion(c.Version)
	filename := c.GetISOFilename()
	return fmt.Sprintf("%s/v%s/releases/%s/%s",
		c.Mirror, majorVersion, c.Architecture, filename)
}

// GetISOFilename returns the ISO filename
func (c *DownloadConfig) GetISOFilename() string {
	return fmt.Sprintf("alpine-standard-%s-%s.iso", c.Version, c.Architecture)
}

// GetChecksumURL returns the checksum URL
func (c *DownloadConfig) GetChecksumURL() string {
	return c.GetISOURL() + ".sha256"
}

// GetISOPath returns the full path to the downloaded ISO
func (c *DownloadConfig) GetISOPath() string {
	return filepath.Join(c.OutputDir, c.GetISOFilename())
}

// ExtractConfig holds ISO extraction configuration
type ExtractConfig struct {
	ISOPath   string `yaml:"iso-path" json:"iso_path"`
	OutputDir string `yaml:"output-dir" json:"output_dir"`
	Force     bool   `yaml:"force" json:"force"`
	Debug     bool   `yaml:"debug" json:"debug"`
}

// Validate validates the extract configuration
func (c *ExtractConfig) Validate() error {
	if c.ISOPath == "" {
		return &MessageError{Msg: "iso path is required"}
	}
	if c.OutputDir == "" {
		return &MessageError{Msg: "output directory is required"}
	}

	// Check if ISO exists
	if _, err := os.Stat(c.ISOPath); os.IsNotExist(err) {
		return &MessageError{Msg: fmt.Sprintf("iso file not found: %s", c.ISOPath)}
	}

	return nil
}

// CustomizeConfig holds ISO customization configuration
type CustomizeConfig struct {
	ISODir          string            `yaml:"iso-dir" json:"iso_dir"`
	PlatformdBinary string            `yaml:"platformd-binary" json:"platformd_binary"`
	InstallConfig   *installer.Config `yaml:"install-config,omitempty" json:"install_config,omitempty"`
	KeysDir         string            `yaml:"keys-dir" json:"keys_dir"`
	WorkDir         string            `yaml:"work-dir" json:"work_dir"`
	GenerateKeys    bool              `yaml:"generate-keys" json:"generate_keys"`
	Debug           bool              `yaml:"debug" json:"debug"`
}

// Validate validates the customize configuration
func (c *CustomizeConfig) Validate() error {
	if c.ISODir == "" {
		return &MessageError{Msg: "iso directory is required"}
	}
	if c.PlatformdBinary == "" {
		return &MessageError{Msg: "platformd binary is required"}
	}
	if c.WorkDir == "" {
		return &MessageError{Msg: "work directory is required"}
	}

	// Check if ISO directory exists
	if _, err := os.Stat(c.ISODir); os.IsNotExist(err) {
		return &MessageError{Msg: fmt.Sprintf("iso directory not found: %s", c.ISODir)}
	}

	// Check if platformd binary exists
	if _, err := os.Stat(c.PlatformdBinary); os.IsNotExist(err) {
		return &MessageError{Msg: fmt.Sprintf("platformd binary not found: %s", c.PlatformdBinary)}
	}

	// Check if keys directory exists if not generating
	if c.KeysDir != "" && !c.GenerateKeys {
		if _, err := os.Stat(c.KeysDir); os.IsNotExist(err) {
			return &MessageError{Msg: fmt.Sprintf("keys directory not found: %s", c.KeysDir)}
		}
	}

	return nil
}

// BuildConfig holds final ISO build configuration
type BuildConfig struct {
	ISODir    string `yaml:"iso-dir" json:"iso_dir"`
	OutputISO string `yaml:"output-iso" json:"output_iso"`
	Label     string `yaml:"label" json:"label"`
	Debug     bool   `yaml:"debug" json:"debug"`
}

// Validate validates the build configuration
func (c *BuildConfig) Validate() error {
	if c.ISODir == "" {
		return &MessageError{Msg: "iso directory is required"}
	}
	if c.OutputISO == "" {
		return &MessageError{Msg: "output iso path is required"}
	}
	if c.Label == "" {
		return &MessageError{Msg: "volume label is required"}
	}

	// Check if ISO directory exists
	if _, err := os.Stat(c.ISODir); os.IsNotExist(err) {
		return &MessageError{Msg: fmt.Sprintf("iso directory not found: %s", c.ISODir)}
	}

	// Validate label length (ISO9660 limit is 32 characters)
	if len(c.Label) > 32 {
		return &MessageError{Msg: fmt.Sprintf("volume label must be 32 characters or less, got %d", len(c.Label))}
	}

	return nil
}

// LoadISOBuildConfig loads ISO build configuration from a YAML file
func LoadISOBuildConfig(path string) (*ISOBuildConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to read config file", Err: err}
	}

	config := DefaultISOBuildConfig()
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, &WrappedError{Msg: "failed to parse config file", Err: err}
	}

	if err := config.Validate(); err != nil {
		return nil, &WrappedError{Msg: "invalid configuration", Err: err}
	}

	return config, nil
}

// SaveISOBuildConfig saves ISO build configuration to a YAML file
func SaveISOBuildConfig(config *ISOBuildConfig, path string) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return &WrappedError{Msg: "failed to marshal config", Err: err}
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return &WrappedError{Msg: "failed to write config file", Err: err}
	}

	return nil
}

// getMajorVersion extracts the major.minor version from a full version string
// Example: "3.22.2" -> "3.22"
func getMajorVersion(version string) string {
	parts := strings.Split(version, ".")
	if len(parts) >= 2 {
		return fmt.Sprintf("%s.%s", parts[0], parts[1])
	}
	return version
}

// PublicAlpineMirror is the last-resort APK repository base used when no
// install mirror is configured and the node has no local CD repo. It keeps
// internet-connected installs working out of the box.
const PublicAlpineMirror = "https://dl-cdn.alpinelinux.org/alpine"

// alpineReleaseBranch converts a full Alpine version like "3.22.2" into the
// release-branch path component "v3.22" used in Alpine repository URLs
// (e.g. https://dl-cdn.alpinelinux.org/alpine/v3.22/main). An empty version
// yields an empty branch so callers can fall back to a runtime derivation
// from /etc/alpine-release.
func alpineReleaseBranch(version string) string {
	mm := getMajorVersion(version)
	if mm == "" {
		return ""
	}
	return "v" + mm
}

// apkRepositoryLines returns the /etc/apk/repositories content the
// autoinstall script writes for a given boot scenario. It encodes the same
// three-way auto-detect that buildAutoinstallScript bakes into the installer
// so the branch logic is unit-testable without booting a node:
//
//  1. cdromPresent — vmedia/CD boot: the local pre-fetched repos (OFFLINE).
//     PXE has no /media/cdrom, which is exactly why this branch is first.
//  2. mirror != "" — a configured install mirror (platform_apk_mirror=).
//  3. otherwise    — the public Alpine mirror fallback.
//
// branch is the release-branch component (e.g. "v3.22"); mirror is trimmed
// of any trailing slash so the joined URLs are well-formed.
func apkRepositoryLines(cdromPresent bool, mirror, branch string) []string {
	switch {
	case cdromPresent:
		return []string{"/media/cdrom/apks", "/media/cdrom/apks-prefetch"}
	case mirror != "":
		base := strings.TrimRight(mirror, "/")
		return []string{base + "/" + branch + "/main", base + "/" + branch + "/community"}
	default:
		return []string{
			PublicAlpineMirror + "/" + branch + "/main",
			PublicAlpineMirror + "/" + branch + "/community",
		}
	}
}

// GetDeviceProfile returns the device profile from various sources
func (c *ISOBuildConfig) GetDeviceProfile() (*entities.DeviceProfile, error) {
	// If DeviceProfile is already provided inline, use it
	if c.DeviceProfile != nil {
		return c.DeviceProfile, nil
	}

	// If DeviceProfilePath is provided, load from file
	if c.DeviceProfilePath != "" {
		profile, err := LoadDeviceProfileFromFile(c.DeviceProfilePath)
		if err != nil {
			return nil, &WrappedError{Msg: fmt.Sprintf("failed to load device profile from %s", c.DeviceProfilePath), Err: err}
		}
		return profile, nil
	}

	// No device profile configured
	return nil, nil
}

// LoadDeviceProfileFromFile loads a device profile from a YAML file
func LoadDeviceProfileFromFile(path string) (*entities.DeviceProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to read device profile file", Err: err}
	}

	var profile entities.DeviceProfile
	if err := yaml.Unmarshal(data, &profile); err != nil {
		return nil, &WrappedError{Msg: "failed to parse device profile YAML", Err: err}
	}

	return &profile, nil
}

// SaveDeviceProfileToFile saves a device profile to a YAML file
func SaveDeviceProfileToFile(profile *entities.DeviceProfile, path string) error {
	data, err := yaml.Marshal(profile)
	if err != nil {
		return &WrappedError{Msg: "failed to marshal device profile", Err: err}
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return &WrappedError{Msg: "failed to write device profile file", Err: err}
	}

	return nil
}
