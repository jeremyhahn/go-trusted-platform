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
	"bytes"
	"context"
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/jeremyhahn/go-trusted-platform/pkg/initrd"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/secureboot"
	storageluks "github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

// Customizer handles ISO customization operations
type Customizer struct {
	config     *PlatformISOConfig
	overlayDir string
	logger     *logging.Logger
}

// NewCustomizer creates a new ISO customizer
func NewCustomizer(config *PlatformISOConfig, logger *logging.Logger) *Customizer {
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	return &Customizer{
		config:     config,
		overlayDir: config.Directories.Overlay,
		logger:     logger,
	}
}

// CustomizeAll runs all customization steps in the correct order
func (c *Customizer) CustomizeAll(ctx context.Context) error {
	c.logger.Info("Starting complete ISO customization")

	// Check prerequisites
	if err := c.checkPrerequisites(); err != nil {
		return fmt.Errorf("prerequisites check failed: %w", err)
	}

	// Generate configuration files
	c.logger.Info("Generating installation configuration")
	if err := c.GenerateInstallConfig(); err != nil {
		return fmt.Errorf("failed to generate install config: %w", err)
	}

	// Pre-fetch APK packages for offline installation (if enabled)
	if c.config.Build.PreFetch {
		c.logger.Info("Pre-fetching APK packages for offline installation")
		if err := c.BuildPreFetchRepository(ctx); err != nil {
			return fmt.Errorf("failed to pre-fetch packages: %w", err)
		}
	}

	// Copy platformd binary (single binary for all operations including boot, firstboot, install)
	if c.config.Platform.PlatformdBinary != "" {
		c.logger.Info("Copying platformd binary")
		if err := c.CopyPlatformdBinary(ctx, c.config.Platform.PlatformdBinary); err != nil {
			return fmt.Errorf("failed to copy platformd binary: %w", err)
		}
	}

	// Copy platformctl CLI binaries (optional - for system administration)
	// If not explicitly specified, look for them alongside platformd
	// Copy both regular and static versions for compatibility with Alpine/musl
	platformctlBinary := c.config.Platform.PlatformctlBinary
	if platformctlBinary == "" && c.config.Platform.PlatformdBinary != "" {
		// Auto-detect platformctl alongside platformd
		platformctlBinary = filepath.Join(filepath.Dir(c.config.Platform.PlatformdBinary), "platformctl")
	}
	if platformctlBinary != "" {
		c.logger.Info("Copying platformctl binary", "path", platformctlBinary)
		if err := c.CopyPlatformctlBinary(ctx, platformctlBinary); err != nil {
			// platformctl is optional, just warn on failure
			c.logger.Warn("Failed to copy platformctl binary", "error", err)
		}
	}

	// Copy static platformctl binary for Alpine/musl compatibility (REQUIRED for ISO installation)
	// The static binary is needed because Alpine uses musl libc which is incompatible with glibc
	platformctlStaticBinary := ""
	if c.config.Platform.PlatformdBinary != "" {
		platformctlStaticBinary = filepath.Join(filepath.Dir(c.config.Platform.PlatformdBinary), "platformctl-static")
	}
	if platformctlStaticBinary != "" {
		c.logger.Info("Copying platformctl-static binary", "path", platformctlStaticBinary)
		if err := c.CopyPlatformctlStaticBinary(ctx, platformctlStaticBinary); err != nil {
			// Log but continue - we may still have the regular binary
			c.logger.Warn("Failed to copy platformctl-static binary", "error", err)
		}
	}

	// Copy platform-initrd binary for boot operations in initramfs (CRITICAL)
	// This binary is called by the dracut hook during boot to unlock LUKS
	platformInitrdBinary := ""
	if c.config.Platform.PlatformdBinary != "" {
		platformInitrdBinary = filepath.Join(filepath.Dir(c.config.Platform.PlatformdBinary), "platform-initrd")
	}
	if platformInitrdBinary != "" {
		c.logger.Info("Copying platform-initrd binary", "path", platformInitrdBinary)
		if err := c.CopyPlatformInitrdBinary(ctx, platformInitrdBinary); err != nil {
			// This is critical for boot - log the error but try to continue
			c.logger.Warn("Failed to copy platform-initrd binary", "error", err)
		}
	}

	// Copy platform configuration file (for TPM keystore SRK handle 0x81000002)
	// Platform config is REQUIRED - it must contain seal-pcrs for TPM sealing
	c.logger.Info("Bundling platform configuration")
	if err := c.CopyPlatformConfig(ctx, c.config.Platform.ConfigFile); err != nil {
		return fmt.Errorf("failed to bundle platform config: %w", err)
	}

	// Copy CA bundle for client trust store (secure delivery via ISO)
	if c.config.Platform.CABundlePath != "" {
		c.logger.Info("Bundling CA certificate bundle")
		if err := c.CopyCABundle(ctx, c.config.Platform.CABundlePath); err != nil {
			c.logger.Warn("Failed to bundle CA certificate", "error", err)
		}
	}

	// Copy objcopy binary if specified
	if c.config.Platform.ObjcopyBinary != "" && c.config.Platform.ObjcopyBinary != "objcopy" {
		c.logger.Info("Copying objcopy binary")
		if err := c.copyObjcopyBinary(ctx, c.config.Platform.ObjcopyBinary); err != nil {
			// Log warning but don't fail - objcopy is optional
			c.logger.Warn("Failed to copy objcopy binary", "error", err)
		}
	}

	// Copy dracut module to ISO for installation
	c.logger.Info("Copying dracut module to ISO")
	if err := c.CopyDracutModule(ctx); err != nil {
		return fmt.Errorf("failed to copy dracut module: %w", err)
	}

	// Copy Secure Boot keys to ISO overlay
	c.logger.Info("Copying Secure Boot keys to ISO overlay")
	if err := c.CopySecureBootKeys(ctx); err != nil {
		return fmt.Errorf("failed to copy Secure Boot keys: %w", err)
	}

	// Copy pre-built FIPS artifacts to ISO
	if c.config.Security.FIPS {
		c.logger.Info("Copying pre-built FIPS artifacts to ISO")
		if err := c.CopyFIPSArtifacts(ctx); err != nil {
			return fmt.Errorf("failed to copy FIPS artifacts: %w", err)
		}
	}

	// Copy WebUI to ISO for installation
	if c.config.Platform.WebUIPath != "" {
		c.logger.Info("Copying WebUI to ISO")
		if err := c.CopyWebUI(ctx, c.config.Platform.WebUIPath); err != nil {
			return fmt.Errorf("failed to copy WebUI: %w", err)
		}
	}

	// Copy network setup script and service file to overlay
	c.logger.Info("Copying network setup script to overlay")
	if err := c.CopyNetworkSetupFiles(ctx); err != nil {
		return fmt.Errorf("failed to copy network setup files: %w", err)
	}

	// Modify initramfs
	c.logger.Info("Modifying initramfs")
	if err := c.ModifyInitramfs(ctx); err != nil {
		return fmt.Errorf("failed to modify initramfs: %w", err)
	}

	// Generate autoinstall script
	c.logger.Info("Generating autoinstall script")
	if err := c.GenerateAutoinstallScript(ctx); err != nil {
		return fmt.Errorf("failed to generate autoinstall script: %w", err)
	}

	// Configure bootloader
	c.logger.Info("Configuring bootloader")
	if err := c.ConfigureBootloader(ctx); err != nil {
		return fmt.Errorf("failed to configure bootloader: %w", err)
	}

	// Clean up temporary files
	c.logger.Info("Cleaning up temporary files")
	if err := c.cleanup(); err != nil {
		c.logger.Warn("Failed to clean up temporary files", "error", err)
	}

	c.logger.Info("ISO customization completed successfully")
	return nil
}

// ModifyInitramfs extracts, modifies, and repacks the initramfs with platformd
func (c *Customizer) ModifyInitramfs(ctx context.Context) error {
	c.logger.Info("Modifying initramfs with platformd dracut module")

	// Find initramfs in ISO
	initramfsPath, err := c.findInitramfs()
	if err != nil {
		return fmt.Errorf("failed to find initramfs: %w", err)
	}
	c.logger.Debug("Found initramfs", "path", initramfsPath)

	// Create temporary directory for extraction
	tmpDir := filepath.Join(c.config.Directories.Work, "initramfs-tmp")
	if err := os.RemoveAll(tmpDir); err != nil {
		return fmt.Errorf("failed to remove old initramfs temp dir: %w", err)
	}
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return fmt.Errorf("failed to create initramfs temp dir: %w", err)
	}

	// Extract initramfs
	c.logger.Info("Extracting initramfs")
	if err := extractInitramfs(initramfsPath, tmpDir); err != nil {
		return fmt.Errorf("failed to extract initramfs: %w", err)
	}

	// Create dracut module structure
	c.logger.Info("Creating dracut module structure")
	if err := c.createDracutModule(tmpDir); err != nil {
		return fmt.Errorf("failed to create dracut module: %w", err)
	}

	// Create autoinstall overlay
	c.logger.Info("Creating autoinstall overlay")
	if err := c.createAutoinstallOverlay(tmpDir); err != nil {
		return fmt.Errorf("failed to create autoinstall overlay: %w", err)
	}

	// Patch init script
	c.logger.Info("Patching init script")
	if err := c.patchInitScript(tmpDir); err != nil {
		return fmt.Errorf("failed to patch init script: %w", err)
	}

	// Repack initramfs
	c.logger.Info("Repacking initramfs")
	if err := repackInitramfs(tmpDir, initramfsPath); err != nil {
		return fmt.Errorf("failed to repack initramfs: %w", err)
	}

	// Verify repacked initramfs
	c.logger.Info("Verifying repacked initramfs")
	if err := c.verifyInitramfs(initramfsPath); err != nil {
		return fmt.Errorf("failed to verify initramfs: %w", err)
	}

	c.logger.Info("Initramfs modification completed successfully")
	return nil
}

// CopyPlatformBinary copies the platformd binary to the ISO
func (c *Customizer) CopyPlatformBinary(ctx context.Context, binaryPath string) error {
	c.logger.Info("Copying platformd binary", "source", binaryPath)

	// Validate binary
	if err := validateBinary(binaryPath); err != nil {
		return fmt.Errorf("binary validation failed: %w", err)
	}

	// Create destination directory
	destDir := filepath.Join(c.config.Directories.ISO, "platformd-bin")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Copy binary
	destPath := filepath.Join(destDir, "platformd")
	if err := copyFile(binaryPath, destPath); err != nil {
		return fmt.Errorf("failed to copy binary: %w", err)
	}

	// Set executable permissions
	if err := os.Chmod(destPath, 0755); err != nil {
		return fmt.Errorf("failed to set executable permissions: %w", err)
	}

	// Calculate and log checksum
	checksum, err := calculateSHA256(destPath)
	if err != nil {
		c.logger.Warn("Failed to calculate checksum", "error", err)
	} else {
		c.logger.Info("Binary copied successfully",
			"destination", destPath,
			"sha256", checksum)
	}

	// Also copy to overlay for installed system
	overlayBinDir := filepath.Join(c.overlayDir, "usr", "bin")
	if err := os.MkdirAll(overlayBinDir, 0755); err != nil {
		return fmt.Errorf("failed to create overlay bin directory: %w", err)
	}

	overlayPath := filepath.Join(overlayBinDir, "platformd")
	if err := copyFile(binaryPath, overlayPath); err != nil {
		return fmt.Errorf("failed to copy binary to overlay: %w", err)
	}

	if err := os.Chmod(overlayPath, 0755); err != nil {
		return fmt.Errorf("failed to set overlay binary permissions: %w", err)
	}

	c.logger.Debug("Binary also copied to overlay", "path", overlayPath)
	return nil
}

// CopyPlatformdBinary copies the platformd binary to the ISO for installation
func (c *Customizer) CopyPlatformdBinary(ctx context.Context, binaryPath string) error {
	c.logger.Info("Copying platformd binary", "source", binaryPath)

	// Validate binary
	if err := validateBinary(binaryPath); err != nil {
		return fmt.Errorf("binary validation failed: %w", err)
	}

	// Create destination directory
	destDir := filepath.Join(c.config.Directories.ISO, "platformd-bin")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Copy binary
	destPath := filepath.Join(destDir, "platformd")
	if err := copyFile(binaryPath, destPath); err != nil {
		return fmt.Errorf("failed to copy binary: %w", err)
	}

	// Set executable permissions
	if err := os.Chmod(destPath, 0755); err != nil {
		return fmt.Errorf("failed to set executable permissions: %w", err)
	}

	// Calculate and log checksum
	checksum, err := calculateSHA256(destPath)
	if err != nil {
		c.logger.Warn("Failed to calculate checksum", "error", err)
	} else {
		c.logger.Info("Platformd binary copied successfully",
			"destination", destPath,
			"sha256", checksum)
	}

	return nil
}

// CopyPlatformctlBinary copies the platformctl CLI binary to the ISO for installation.
// This is optional - if not provided, only platformd will be installed.
func (c *Customizer) CopyPlatformctlBinary(ctx context.Context, binaryPath string) error {
	if binaryPath == "" {
		c.logger.Debug("No platformctl binary specified, skipping")
		return nil
	}

	c.logger.Info("Copying platformctl binary", "source", binaryPath)

	// Validate binary exists
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		c.logger.Warn("platformctl binary not found, skipping", "path", binaryPath)
		return nil
	}

	// Validate binary
	if err := validateBinary(binaryPath); err != nil {
		return fmt.Errorf("platformctl binary validation failed: %w", err)
	}

	// Create destination directory
	destDir := filepath.Join(c.config.Directories.ISO, "platformd-bin")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Copy binary
	destPath := filepath.Join(destDir, "platformctl")
	if err := copyFile(binaryPath, destPath); err != nil {
		return fmt.Errorf("failed to copy platformctl binary: %w", err)
	}

	// Set executable permissions
	if err := os.Chmod(destPath, 0755); err != nil {
		return fmt.Errorf("failed to set executable permissions: %w", err)
	}

	// Calculate and log checksum
	checksum, err := calculateSHA256(destPath)
	if err != nil {
		c.logger.Warn("Failed to calculate checksum", "error", err)
	} else {
		c.logger.Info("Platformctl binary copied successfully",
			"destination", destPath,
			"sha256", checksum)
	}

	return nil
}

// CopyPlatformctlStaticBinary copies the static platformctl CLI binary to the ISO for installation.
// The static binary is required for Alpine Linux which uses musl libc (incompatible with glibc).
func (c *Customizer) CopyPlatformctlStaticBinary(ctx context.Context, binaryPath string) error {
	if binaryPath == "" {
		c.logger.Debug("No platformctl-static binary specified, skipping")
		return nil
	}

	c.logger.Info("Copying platformctl-static binary", "source", binaryPath)

	// Validate binary exists
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		c.logger.Warn("platformctl-static binary not found, skipping", "path", binaryPath)
		return nil
	}

	// Validate binary
	if err := validateBinary(binaryPath); err != nil {
		return fmt.Errorf("platformctl-static binary validation failed: %w", err)
	}

	// Create destination directory
	destDir := filepath.Join(c.config.Directories.ISO, "platformd-bin")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Copy binary
	destPath := filepath.Join(destDir, "platformctl-static")
	if err := copyFile(binaryPath, destPath); err != nil {
		return fmt.Errorf("failed to copy platformctl-static binary: %w", err)
	}

	// Set executable permissions
	if err := os.Chmod(destPath, 0755); err != nil {
		return fmt.Errorf("failed to set executable permissions: %w", err)
	}

	// Calculate and log checksum
	checksum, err := calculateSHA256(destPath)
	if err != nil {
		c.logger.Warn("Failed to calculate checksum", "error", err)
	} else {
		c.logger.Info("Platformctl-static binary copied successfully",
			"destination", destPath,
			"sha256", checksum)
	}

	return nil
}

// CopyPlatformInitrdBinary copies the platform-initrd binary to the ISO and overlay.
// This binary is CRITICAL for boot - it's called by dracut hooks to unlock LUKS.
// The binary must be in /usr/bin/platform-initrd in the initramfs.
func (c *Customizer) CopyPlatformInitrdBinary(ctx context.Context, binaryPath string) error {
	if binaryPath == "" {
		c.logger.Debug("No platform-initrd binary specified, skipping")
		return nil
	}

	c.logger.Info("Copying platform-initrd binary", "source", binaryPath)

	// Validate binary exists
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		c.logger.Warn("platform-initrd binary not found, skipping", "path", binaryPath)
		return nil
	}

	// Validate binary
	if err := validateBinary(binaryPath); err != nil {
		return fmt.Errorf("platform-initrd binary validation failed: %w", err)
	}

	// Create destination directory on ISO
	destDir := filepath.Join(c.config.Directories.ISO, "platformd-bin")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Copy binary to ISO
	destPath := filepath.Join(destDir, "platform-initrd")
	if err := copyFile(binaryPath, destPath); err != nil {
		return fmt.Errorf("failed to copy platform-initrd binary: %w", err)
	}

	// Set executable permissions
	if err := os.Chmod(destPath, 0755); err != nil {
		return fmt.Errorf("failed to set executable permissions: %w", err)
	}

	c.logger.Debug("Platform-initrd binary copied to ISO", "path", destPath)

	// CRITICAL: Also copy to overlay for installed system
	// This ensures the binary is available in /usr/bin/platform-initrd after installation
	// The dracut hook calls /usr/bin/platform-initrd during boot
	overlayBinDir := filepath.Join(c.overlayDir, "usr", "bin")
	if err := os.MkdirAll(overlayBinDir, 0755); err != nil {
		return fmt.Errorf("failed to create overlay bin directory: %w", err)
	}

	overlayPath := filepath.Join(overlayBinDir, "platform-initrd")
	if err := copyFile(binaryPath, overlayPath); err != nil {
		return fmt.Errorf("failed to copy platform-initrd binary to overlay: %w", err)
	}

	if err := os.Chmod(overlayPath, 0755); err != nil {
		return fmt.Errorf("failed to set overlay binary permissions: %w", err)
	}

	c.logger.Debug("Platform-initrd binary also copied to overlay", "path", overlayPath)

	// Calculate and log checksum
	checksum, err := calculateSHA256(destPath)
	if err != nil {
		c.logger.Warn("Failed to calculate checksum", "error", err)
	} else {
		c.logger.Info("Platform-initrd binary copied successfully",
			"destination", destPath,
			"sha256", checksum)
	}

	return nil
}

// CopyPlatformConfig copies the platformd.yaml configuration file to the ISO
// This config file is used by platformd binaries for consistent TPM configuration.
// The config MUST exist and MUST contain seal-pcrs for TPM sealing.
func (c *Customizer) CopyPlatformConfig(ctx context.Context, configPath string) error {
	c.logger.Info("Copying platform configuration file", "source", configPath)

	// In dynamic config mode, skip embedding config - the device will fetch
	// its config from the server at boot time via kernel cmdline params.
	if configPath == "" && c.config.Platform.ConfigServerURL != "" {
		c.logger.Info("Dynamic config mode: skipping config embed, device will fetch from server",
			"server", c.config.Platform.ConfigServerURL)
		return nil
	}

	// Platform config is REQUIRED when not in dynamic config mode
	if configPath == "" {
		return ErrPlatformConfigRequired()
	}

	// Validate config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return ErrPlatformConfigNotFound(configPath)
	}

	// Read config file
	srcData, err := os.ReadFile(configPath)
	if err != nil {
		return ErrPlatformConfigRead(configPath, err)
	}

	// Validate config contains seal-pcrs (required for TPM sealing)
	if !bytes.Contains(srcData, []byte("seal-pcrs:")) {
		return ErrPlatformConfigMissingSealPCRs(configPath)
	}

	// Create configs directory in ISO
	destDir := filepath.Join(c.config.Directories.ISO, "configs")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return ErrConfigDirCreate(destDir, err)
	}
	// Apply runtime security flag overrides (FIPS, FIDO2, lockdown)
	// These come from ISO build flags and may override what's in the config file
	modifiedData, err := c.applySecurityOverrides(srcData)
	if err != nil {
		c.logger.Warn("Failed to apply security overrides, using original config", "error", err)
		modifiedData = srcData
	}

	// Use installer.yaml as the single source of truth for autoinstall.sh
	configFilename := "installer.yaml"

	// Copy config file to ISO
	destPath := filepath.Join(destDir, configFilename)
	if err := os.WriteFile(destPath, modifiedData, 0644); err != nil {
		return ErrPlatformConfigWrite(destPath, err)
	}

	c.logger.Info("Platform config copied successfully",
		"source", configPath,
		"destination", destPath,
		"size", len(srcData))

	return nil
}

// CopyCABundle copies the CA certificate bundle to the ISO for installation
// into the client's OS trust store. This is the secure way to establish trust
// between client and server - the CA cert is delivered via the same trusted
// channel as the installer itself (the ISO).
func (c *Customizer) CopyCABundle(ctx context.Context, bundlePath string) error {
	if bundlePath == "" {
		c.logger.Debug("No CA bundle path specified, skipping")
		return nil
	}

	c.logger.Info("Copying CA bundle to ISO", "source", bundlePath)

	// Validate bundle file exists
	if _, err := os.Stat(bundlePath); os.IsNotExist(err) {
		return fmt.Errorf("CA bundle not found: %s", bundlePath)
	}

	// Create configs directory in ISO
	destDir := filepath.Join(c.config.Directories.ISO, "configs")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create configs directory: %w", err)
	}

	// Copy bundle file
	destPath := filepath.Join(destDir, "ca-bundle.pem")
	srcData, err := os.ReadFile(bundlePath)
	if err != nil {
		return fmt.Errorf("failed to read CA bundle: %w", err)
	}

	if err := os.WriteFile(destPath, srcData, 0644); err != nil {
		return fmt.Errorf("failed to write CA bundle: %w", err)
	}

	c.logger.Info("CA bundle copied successfully",
		"source", bundlePath,
		"destination", destPath)

	return nil
}

// applySecurityOverrides applies runtime flag overrides to the platform config YAML.
// This handles ISO build flags (--fips, --fido2, --lockdown) that may override
// values in the platform config file.
func (c *Customizer) applySecurityOverrides(data []byte) ([]byte, error) {
	// Parse YAML into a generic map to preserve all fields
	var config map[string]interface{}
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse installer config YAML: %w", err)
	}

	// Apply FIDO2 override from runtime flag
	if osConfig, ok := config["os"].(map[interface{}]interface{}); ok {
		osConfig["enable-fido2"] = c.config.Security.EnableFIDO2
		c.logger.Debug("Applied enable-fido2 override", "value", c.config.Security.EnableFIDO2)
	}

	// Apply other security overrides if set
	if osConfig, ok := config["os"].(map[interface{}]interface{}); ok {
		// FIPS override
		if c.config.Security.FIPS {
			osConfig["fips"] = true
			c.logger.Debug("Applied fips override", "value", true)
		}
		// Lockdown override
		if c.config.Security.Lockdown {
			osConfig["lockdown"] = true
			if c.config.Security.LockdownMode != "" {
				osConfig["lockdown-mode"] = c.config.Security.LockdownMode
			}
			c.logger.Debug("Applied lockdown override", "value", true, "mode", c.config.Security.LockdownMode)
		}
	}

	// Apply FIPS PBKDF override to disk encryption config
	// FIPS 140-3 does not approve Argon2id, so PBKDF2 must be used
	if c.config.Security.FIPS {
		if diskConfig, ok := config["disk"].(map[interface{}]interface{}); ok {
			if encConfig, ok := diskConfig["encryption"].(map[interface{}]interface{}); ok {
				encConfig["pbkdf"] = "pbkdf2"
				c.logger.Debug("Applied FIPS pbkdf override", "value", "pbkdf2")
			}
		}
	}

	// Apply TPM sealing override
	if c.config.Security.TPM.AutoUnseal {
		config["enable-tpm-sealing"] = true
		c.logger.Debug("Applied enable-tpm-sealing override", "value", true)
	}

	// Marshal back to YAML
	modifiedData, err := yaml.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal modified config: %w", err)
	}

	return modifiedData, nil
}

// BuildPreFetchRepository downloads all required packages and creates a local APK repository
func (c *Customizer) BuildPreFetchRepository(ctx context.Context) error {
	// Extract Alpine version major.minor (e.g., "3.22.2" -> "3.22")
	version := c.config.Alpine.Version
	versionParts := strings.Split(version, ".")
	majorMinor := version
	if len(versionParts) >= 2 {
		majorMinor = fmt.Sprintf("%s.%s", versionParts[0], versionParts[1])
	}

	// Determine architecture - default to x86_64
	arch := "x86_64"
	// Try to detect from Alpine config or use default

	// Create PreFetchConfig from our PlatformISOConfig
	prefetchConfig := &PreFetchConfig{
		Mirror:        c.config.Alpine.Mirror,
		Version:       majorMinor, // Use major.minor for APK repos
		Architecture:  arch,
		WorkDir:       c.config.Directories.Work,
		ISODir:        c.config.Directories.ISO,
		FIPS:          c.config.Security.FIPS,
		EnableFIDO2:   c.config.Security.EnableFIDO2,
		FilesystemLVM: c.config.RootFS.Type == "lvm",
		IMAEnabled:    false,
		ExtraPackages: []string{},
	}

	// Check if mirror is empty and set default
	if prefetchConfig.Mirror == "" {
		prefetchConfig.Mirror = "https://dl-cdn.alpinelinux.org/alpine"
	}

	// Create pre-fetch builder
	builder := NewPreFetchBuilder(prefetchConfig, c.logger)

	// Build the local repository
	if err := builder.BuildLocalRepository(ctx); err != nil {
		return err
	}

	c.logger.Info("Pre-fetch repository created successfully",
		"location", filepath.Join(c.config.Directories.ISO, "apks"))

	return nil
}

// CopySecureBootKeys copies Secure Boot keys to the ISO for installation.
// If keys don't exist, they are automatically generated.
// Keys are always embedded in the ISO regardless of the SecureBoot setting,
// making the ISO "Secure Boot ready" even when SecureBoot is not explicitly enabled.
func (c *Customizer) CopySecureBootKeys(ctx context.Context) error {
	c.logger.Info("Preparing Secure Boot keys for ISO")

	// Source keys directory
	keysDir := c.config.Directories.Keys
	if keysDir == "" {
		keysDir = filepath.Join(c.config.Directories.Work, "secure-boot-keys")
		c.config.Directories.Keys = keysDir
	}

	// Check if keys exist, generate if not
	if err := c.ensureSecureBootKeysExist(ctx, keysDir); err != nil {
		c.logger.Warn("Failed to ensure Secure Boot keys exist", "error", err)
		// Continue without keys - the ISO will still be bootable without Secure Boot
		return nil
	}

	// Verify keys directory exists after generation
	if _, err := os.Stat(keysDir); os.IsNotExist(err) {
		c.logger.Warn("Secure Boot keys directory not found after generation attempt", "path", keysDir)
		return nil
	}

	// Destination in ISO directory (will be accessible at /media/cdrom/secure-boot-keys during installation)
	destDir := filepath.Join(c.config.Directories.ISO, "secure-boot-keys")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create secure-boot-keys directory in ISO: %w", err)
	}

	// Copy all files from keys directory
	entries, err := os.ReadDir(keysDir)
	if err != nil {
		return fmt.Errorf("failed to read keys directory: %w", err)
	}

	if len(entries) == 0 {
		c.logger.Warn("Secure Boot keys directory is empty", "path", keysDir)
		return nil
	}

	filesCopied := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		srcPath := filepath.Join(keysDir, entry.Name())
		destPath := filepath.Join(destDir, entry.Name())

		if err := copyFile(srcPath, destPath); err != nil {
			c.logger.Warn("Failed to copy key file", "file", entry.Name(), "error", err)
			continue
		}

		c.logger.Debug("Copied key file", "file", entry.Name())
		filesCopied++
	}

	if filesCopied > 0 {
		c.logger.Info("Secure Boot keys copied successfully to ISO",
			"count", filesCopied,
			"destination", destDir)
	}
	return nil
}

// ensureSecureBootKeysExist checks if Secure Boot keys exist and generates them if not.
// This ensures the ISO is always "Secure Boot ready" regardless of the SecureBoot flag.
func (c *Customizer) ensureSecureBootKeysExist(ctx context.Context, keysDir string) error {
	// Check if required key files exist
	dbKeyPath := filepath.Join(keysDir, "DB.key")
	dbCertPath := filepath.Join(keysDir, "DB.crt")

	dbKeyExists := false
	dbCertExists := false
	if _, err := os.Stat(dbKeyPath); err == nil {
		dbKeyExists = true
	}
	if _, err := os.Stat(dbCertPath); err == nil {
		dbCertExists = true
	}

	// If both key and cert exist, we're good
	if dbKeyExists && dbCertExists {
		c.logger.Debug("Secure Boot keys already exist", "path", keysDir)
		return nil
	}

	// Generate keys if they don't exist
	c.logger.Info("Secure Boot keys not found, generating automatically", "path", keysDir)

	xkmsConfig := &secureboot.XKMSConfig{
		KeysDir:      keysDir,
		Backend:      secureboot.BackendFile,
		CommonName:   "Trusted Platform",
		Country:      "US",
		Organization: "Trusted Platform",
		KeySize:      2048,
		ValidYears:   10,
		ExportKeys:   true, // Always export for Secure Boot enrollment
	}

	km, err := secureboot.NewXKMSManager(xkmsConfig, c.logger)
	if err != nil {
		return fmt.Errorf("failed to create key manager: %w", err)
	}
	defer km.Close()

	// Generate all keys (PK, KEK, DB)
	if err := km.GenerateAll(ctx); err != nil {
		return fmt.Errorf("failed to generate Secure Boot keys: %w", err)
	}

	c.logger.Info("Secure Boot keys generated successfully", "path", keysDir)
	return nil
}

// CopyNetworkSetupFiles copies the network setup script and systemd service file to the overlay
// for the installed system. This enables client-side network configuration on boot.
func (c *Customizer) CopyNetworkSetupFiles(ctx context.Context) error {
	c.logger.Info("Copying network setup files to overlay for installed system")

	// Determine base directory (configs/os should be in project root or current working directory)
	configsDir := c.config.Directories.ConfigsDir
	if configsDir == "" {
		// Fallback to configs/os relative to project root or CWD
		configsDir = "configs/os"
	}

	// Network setup script
	scriptSrc := filepath.Join(configsDir, "trusted-platform-network.sh")
	if _, err := os.Stat(scriptSrc); os.IsNotExist(err) {
		c.logger.Warn("Network setup script not found, skipping", "path", scriptSrc)
		return nil
	}

	// Destination for script in overlay (usr/local/bin)
	overlayBinDir := filepath.Join(c.overlayDir, "usr", "local", "bin")
	if err := os.MkdirAll(overlayBinDir, 0755); err != nil {
		return fmt.Errorf("failed to create overlay bin directory: %w", err)
	}

	// Copy script to overlay
	scriptDest := filepath.Join(overlayBinDir, "trusted-platform-network.sh")
	if err := copyFile(scriptSrc, scriptDest); err != nil {
		return fmt.Errorf("failed to copy network setup script: %w", err)
	}

	// Make script executable
	if err := os.Chmod(scriptDest, 0755); err != nil {
		return fmt.Errorf("failed to set executable permissions on script: %w", err)
	}

	c.logger.Debug("Network setup script copied to overlay", "destination", scriptDest)

	// Systemd service file
	serviceSrc := filepath.Join(configsDir, "trusted-platform-network.service")
	if _, err := os.Stat(serviceSrc); os.IsNotExist(err) {
		c.logger.Warn("Network service file not found, skipping", "path", serviceSrc)
		return nil
	}

	// Destination for service in overlay (lib/systemd/system)
	overlayServiceDir := filepath.Join(c.overlayDir, "lib", "systemd", "system")
	if err := os.MkdirAll(overlayServiceDir, 0755); err != nil {
		return fmt.Errorf("failed to create overlay systemd directory: %w", err)
	}

	// Copy service file to overlay
	serviceDest := filepath.Join(overlayServiceDir, "trusted-platform-network.service")
	if err := copyFile(serviceSrc, serviceDest); err != nil {
		return fmt.Errorf("failed to copy network service file: %w", err)
	}

	// Set restrictive permissions on service file
	if err := os.Chmod(serviceDest, 0644); err != nil {
		return fmt.Errorf("failed to set permissions on service file: %w", err)
	}

	c.logger.Debug("Network service file copied to overlay", "destination", serviceDest)

	c.logger.Info("Network setup files copied successfully to overlay")
	return nil
}

// CopyFIPSArtifacts builds FIPS artifacts by running containers and copies them to the ISO
func (c *Customizer) CopyFIPSArtifacts(ctx context.Context) error {
	runtime := c.config.Security.FIPSConfig.ContainerRuntime
	opensslContainer := c.config.Security.FIPSConfig.OpenSSLContainer
	kernelContainer := c.config.Security.FIPSConfig.KernelContainer

	c.logger.Info("Building FIPS artifacts using containers",
		"runtime", runtime,
		"openssl_container", opensslContainer,
		"kernel_container", kernelContainer)

	// Create work directory for build artifacts
	artifactsWorkDir := filepath.Join(c.config.Directories.Work, "fips-artifacts")
	if err := os.MkdirAll(artifactsWorkDir, 0755); err != nil {
		return fmt.Errorf("failed to create artifacts work directory: %w", err)
	}

	// Create subdirectories for each artifact type
	opensslOutputDir := filepath.Join(artifactsWorkDir, "openssl-output")
	kernelOutputDir := filepath.Join(artifactsWorkDir, "kernel-output")

	if err := os.MkdirAll(opensslOutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create OpenSSL output directory: %w", err)
	}
	if err := os.MkdirAll(kernelOutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create kernel output directory: %w", err)
	}

	// Create FIPS artifacts directory in ISO
	destDir := filepath.Join(c.config.Directories.ISO, "fips-artifacts")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create FIPS artifacts directory in ISO: %w", err)
	}

	// 1. Build complete FIPS-validated OpenSSL by running the container
	c.logger.Info("Building complete FIPS-validated OpenSSL (OpenSSL 3.1.2, Certificate #4985)", "container", opensslContainer)

	// Get absolute path for volume mount
	absOpensslOutputDir, err := filepath.Abs(opensslOutputDir)
	if err != nil {
		return fmt.Errorf("failed to get absolute path for OpenSSL output: %w", err)
	}

	runOpensslCmd := exec.CommandContext(ctx, runtime, "run", "--rm",
		"-v", fmt.Sprintf("%s:/output", absOpensslOutputDir),
		opensslContainer)

	// Show Docker output in debug mode
	if c.config.Build.Debug {
		runOpensslCmd.Stdout = os.Stdout
		runOpensslCmd.Stderr = os.Stderr
		if err := runOpensslCmd.Run(); err != nil {
			return fmt.Errorf("failed to build OpenSSL FIPS module using container %s: %w\nHint: Build the container image first with: cd build/docker/openssl-fips-provider && make build",
				opensslContainer, err)
		}
	} else {
		if output, err := runOpensslCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to build OpenSSL FIPS module using container %s: %w\nOutput: %s\nHint: Build the container image first with: cd build/docker/openssl-fips-provider && make build",
				opensslContainer, err, string(output))
		}
	}

	// Copy complete FIPS OpenSSL installation to ISO
	// According to official OpenSSL FIPS documentation and the reference project:
	//   - We MUST install the ENTIRE OpenSSL from a FIPS 140-3 validated version
	//   - OpenSSL 3.1.2 is FIPS 140-3 validated (Certificate #4985, valid until March 10, 2030)
	//   - The complete validated OpenSSL installation (binaries, libraries, FIPS module)
	//     must be installed as a unit - we cannot mix validated components with unvalidated ones
	//
	// The container outputs to /output which contains:
	//  - /output/usr/bin/openssl (OpenSSL binary)
	//  - /output/usr/lib/libssl.so.3, /output/usr/lib/libcrypto.so.3 (libraries)
	//  - /output/usr/lib/ossl-modules/fips.so (FIPS provider module)
	//  - /output/etc/ssl/* (configuration files)

	// 1. Copy usr/ directory (binaries, libraries, FIPS module)
	usrSrc := filepath.Join(opensslOutputDir, "usr")
	usrDest := filepath.Join(destDir, "usr")

	if _, err := os.Stat(usrSrc); err != nil {
		return fmt.Errorf("complete OpenSSL installation not found in output at %s: %w", usrSrc, err)
	}

	cpUsrCmd := exec.CommandContext(ctx, "cp", "-a", usrSrc, destDir)
	if output, err := cpUsrCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to copy OpenSSL usr directory: %w\nOutput: %s", err, string(output))
	}

	// 2. Copy etc/ directory (SSL configuration)
	etcSrc := filepath.Join(opensslOutputDir, "etc")

	if _, err := os.Stat(etcSrc); err == nil {
		cpEtcCmd := exec.CommandContext(ctx, "cp", "-a", etcSrc, destDir)
		if output, err := cpEtcCmd.CombinedOutput(); err != nil {
			c.logger.Warn("Failed to copy SSL configuration (may not be critical)",
				"output", string(output),
				"error", err)
		}
	}

	// 3. Verify the complete OpenSSL installation
	fipsModulePath := filepath.Join(usrDest, "lib", "ossl-modules", "fips.so")
	opensslBinPath := filepath.Join(usrDest, "bin", "openssl")
	libsslPath := filepath.Join(usrDest, "lib", "libssl.so.3")
	libcryptoPath := filepath.Join(usrDest, "lib", "libcrypto.so.3")

	for _, path := range []string{fipsModulePath, opensslBinPath, libsslPath, libcryptoPath} {
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("FIPS OpenSSL installation incomplete - missing: %s", path)
		}
	}

	checksum, err := calculateSHA256(fipsModulePath)
	if err != nil {
		c.logger.Warn("Failed to calculate FIPS module checksum", "error", err)
	} else {
		c.logger.Info("FIPS provider module built and copied",
			"container", opensslContainer,
			"destination", fipsModulePath,
			"sha256", checksum)
	}

	// 2. Build FIPS kernel by running the container
	c.logger.Info("Building FIPS-capable kernel (this may take 15-30 minutes)", "container", kernelContainer)

	// Get absolute path for volume mount
	absKernelOutputDir, err := filepath.Abs(kernelOutputDir)
	if err != nil {
		return fmt.Errorf("failed to get absolute path for kernel output: %w", err)
	}

	runKernelCmd := exec.CommandContext(ctx, runtime, "run", "--rm",
		"-v", fmt.Sprintf("%s:/output", absKernelOutputDir),
		kernelContainer)

	// Show Docker output in debug mode
	if c.config.Build.Debug {
		runKernelCmd.Stdout = os.Stdout
		runKernelCmd.Stderr = os.Stderr
		if err := runKernelCmd.Run(); err != nil {
			return fmt.Errorf("failed to build FIPS kernel using container %s: %w\nHint: Build the container image first with: cd build/docker/fips-kernel-builder && make build",
				kernelContainer, err)
		}
	} else {
		if output, err := runKernelCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to build FIPS kernel using container %s: %w\nOutput: %s\nHint: Build the container image first with: cd build/docker/fips-kernel-builder && make build",
				kernelContainer, err, string(output))
		}
	}

	// Copy kernel to ISO
	kernelSrc := filepath.Join(kernelOutputDir, "vmlinuz-fips")
	kernelDest := filepath.Join(destDir, "vmlinuz-fips")

	if _, err := os.Stat(kernelSrc); err != nil {
		return fmt.Errorf("FIPS kernel not found in output: %w", err)
	}

	if err := copyFile(kernelSrc, kernelDest); err != nil {
		return fmt.Errorf("failed to copy FIPS kernel to ISO: %w", err)
	}

	kernelChecksum, err := calculateSHA256(kernelDest)
	if err != nil {
		c.logger.Warn("Failed to calculate kernel checksum", "error", err)
	} else {
		c.logger.Info("FIPS kernel built and copied",
			"container", kernelContainer,
			"destination", kernelDest,
			"sha256", kernelChecksum)
	}

	// 3. Copy kernel modules tarball
	c.logger.Info("Copying FIPS kernel modules")

	// Find the modules tarball in the output directory
	pattern := filepath.Join(kernelOutputDir, "modules-fips-*.tar.gz")
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return fmt.Errorf("kernel modules tarball not found in %s", kernelOutputDir)
	}

	modulesSrc := matches[0]
	modulesDest := filepath.Join(destDir, "modules-fips.tar.gz")

	if err := copyFile(modulesSrc, modulesDest); err != nil {
		return fmt.Errorf("failed to copy kernel modules to ISO: %w", err)
	}

	modulesChecksum, err := calculateSHA256(modulesDest)
	if err != nil {
		c.logger.Warn("Failed to calculate modules checksum", "error", err)
	} else {
		c.logger.Info("FIPS kernel modules copied",
			"source", filepath.Base(modulesSrc),
			"destination", modulesDest,
			"sha256", modulesChecksum)
	}

	// Write checksums file
	checksumsPath := filepath.Join(destDir, "SHA256SUMS")
	checksumsContent := fmt.Sprintf("%s  fips.so\n%s  vmlinuz-fips\n%s  modules-fips.tar.gz\n",
		checksum, kernelChecksum, modulesChecksum)
	if err := os.WriteFile(checksumsPath, []byte(checksumsContent), 0644); err != nil {
		c.logger.Warn("Failed to write checksums file", "error", err)
	} else {
		c.logger.Debug("Checksums file created", "path", checksumsPath)
	}

	c.logger.Info("FIPS artifacts built and copied successfully",
		"runtime", runtime,
		"openssl_container", opensslContainer,
		"kernel_container", kernelContainer,
		"fips_module", "fips.so",
		"kernel", "vmlinuz-fips",
		"modules", "modules-fips.tar.gz")

	return nil
}

// GenerateAutoinstallScript generates the automated installation script
func (c *Customizer) GenerateAutoinstallScript(ctx context.Context) error {
	c.logger.Info("Generating autoinstall script")

	// This is handled by createAutoinstallOverlay in ModifyInitramfs
	// But we provide this method for API completeness and flexibility
	scriptPath := filepath.Join(c.config.Directories.Work, "autoinstall.sh")

	script := c.buildAutoinstallScript()

	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		return fmt.Errorf("failed to write autoinstall script: %w", err)
	}

	c.logger.Info("Autoinstall script generated", "path", scriptPath)
	return nil
}

// ConfigureBootloader configures GRUB for automated installation
func (c *Customizer) ConfigureBootloader(ctx context.Context) error {
	c.logger.Info("Configuring GRUB bootloader")

	// Find GRUB config
	grubPath := filepath.Join(c.config.Directories.ISO, "boot", "grub", "grub.cfg")
	if _, err := os.Stat(grubPath); os.IsNotExist(err) {
		return fmt.Errorf("GRUB config not found: %s", grubPath)
	}

	// Read existing config
	content, err := os.ReadFile(grubPath)
	if err != nil {
		return fmt.Errorf("failed to read GRUB config: %w", err)
	}

	// Modify config for autoinstall
	modified := string(content)

	// Force serial + text console for BMC SOL visibility.
	// Aggressively strip ALL video/graphics-related lines from the stock
	// Alpine grub.cfg. On headless servers (e.g. Supermicro X10SDV-TP8F)
	// these cause "error: no suitable video mode found. Booting in blind
	// mode" because GRUB tries to initialize a graphical framebuffer that
	// does not exist. Our embedded EFI config already sets gfxpayload=text
	// and gfxmode=text, so none of these are needed.
	videoStripKeywords := []string{
		"gfxmode",
		"gfxterm",
		"all_video",
		"loadfont",
		"gfxpayload",
	}
	{
		lines := strings.Split(modified, "\n")
		filtered := make([]string, 0, len(lines))
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			strip := false
			for _, kw := range videoStripKeywords {
				if strings.Contains(trimmed, kw) {
					strip = true
					break
				}
			}
			if !strip {
				filtered = append(filtered, line)
			}
		}
		modified = strings.Join(filtered, "\n")
	}
	// Inject serial console config before the first menuentry if not
	// already present.
	if !strings.Contains(modified, "terminal_output") {
		lines := strings.Split(modified, "\n")
		for i, line := range lines {
			if strings.Contains(line, "menuentry") {
				serialCfg := []string{
					"serial --unit=0 --speed=115200",
					"serial --unit=1 --speed=115200",
					"terminal_input serial console",
					"terminal_output serial console",
				}
				lines = append(lines[:i], append(serialCfg, lines[i:]...)...)
				break
			}
		}
		modified = strings.Join(lines, "\n")
	}

	// Remove 'quiet' parameter to see boot messages
	modified = strings.ReplaceAll(modified, " quiet", "")
	modified = strings.ReplaceAll(modified, "quiet ", "")

	// Rename menu entry from "Linux lts" to "Trusted Alpine LTS"
	modified = strings.ReplaceAll(modified, `menuentry "Linux lts"`, `menuentry "Trusted Alpine LTS"`)
	modified = strings.ReplaceAll(modified, `menuentry 'Linux lts'`, `menuentry 'Trusted Alpine LTS'`)

	// Add console and autoinstall parameters
	// Look for kernel command lines and add our parameters
	lines := strings.Split(modified, "\n")
	for i, line := range lines {
		// Match "linux" followed by whitespace (space or tab) and contains vmlinuz
		if (strings.Contains(line, "linux\t") || strings.Contains(line, "linux ")) && strings.Contains(line, "/boot/vmlinuz") {
			// Add our parameters after the kernel line
			// Kernel console — kitchen sink for cross-vendor BMC SOL coverage.
			//
			//   earlycon                 — auto-discover the serial console from
			//                              the ACPI SPCR table the firmware
			//                              published. This is the canonical
			//                              Linux mechanism for "find the BMC
			//                              SOL UART from firmware metadata"
			//                              and works on all SPCR-publishing
			//                              BMCs (Supermicro X10+, Dell, HPE,
			//                              Lenovo, Cisco). DO NOT remove.
			//   console=ttyS0,115200n8   — COM1 (Linux ttyS0)
			//   console=ttyS1,115200n8   — COM2 (Linux ttyS1). Many Supermicro
			//                              boards route SOL to COM2.
			//   console=tty1             — VGA text mode for SMM snooping
			//                              ("Console Redirection After POST"
			//                              BIOS setting).
			//
			// Last `console=` wins as the kmsg primary; we put ttyS1 last
			// because Supermicro X10SDV-TP8F is the deployment target.
			if !strings.Contains(line, "console=ttyS0") {
				// earlyprintk=efi,keep — use UEFI ConOut (already routed to
				// SOL by BIOS Console Redirection) for output BEFORE the
				// regular kernel serial driver loads. The "keep" suffix
				// preserves the binding past ExitBootServices so the same
				// channel keeps working until the regular console takes over.
				// This eliminates the gap between "EFI stub: measured initrd"
				// and the first kernel-driven serial output, which is what we
				// were seeing on the Supermicro X10SDV-TP8F.
				line += " earlyprintk=efi,keep earlycon console=tty1 console=ttyS0,115200n8 console=ttyS1,115200n8"
			}
			if !strings.Contains(line, "alpine_start=autoinstall") {
				line += " alpine_start=autoinstall"
			}
			// Append dynamic config params when in server-fetch mode
			dynamicParams := c.buildDynamicConfigParams()
			if dynamicParams != "" && !strings.Contains(line, "platform_config=") {
				line += " " + dynamicParams
			}
			// Always enable debug mode + forensic upload sink for the
			// install. The autoinstall.sh upload_install_log function reads
			// platform_debug_sink from /proc/cmdline and PUTs install.log
			// there on every exit path. We bake the bootstrap host into
			// the kernel cmdline at ISO build time because the live env's
			// udhcpc doesn't write the dhclient lease format the script
			// would otherwise probe.
			if !strings.Contains(line, "platform_debug=") {
				line += " platform_debug=1"
			}
			if !strings.Contains(line, "platform_debug_sink=") {
				sink := c.config.Platform.DebugSink
				if sink == "" {
					sink = "198.18.1.91:8080"
				}
				line += " platform_debug_sink=" + sink
			}
			lines[i] = line
		}
	}
	modified = strings.Join(lines, "\n")

	// Write back modified config
	if err := os.WriteFile(grubPath, []byte(modified), 0644); err != nil {
		return fmt.Errorf("failed to write GRUB config: %w", err)
	}

	c.logger.Info("GRUB bootloader configured for autoinstall")

	// Update EFI bootloader with correct volume label
	if err := c.UpdateEFIBootloader(ctx); err != nil {
		c.logger.Warn("Failed to update EFI bootloader, UEFI boot may fail", "error", err)
	}

	return nil
}

// UpdateEFIBootloader updates the EFI bootloader to use the correct volume label.
// This is necessary because the Alpine ISO's bootx64.efi has a hardcoded search
// directive for the original Alpine volume label.
// The EFI bootloader is located at /efi/boot/bootx64.efi in the ISO directory.
// Requires grub-mkstandalone to be installed.
func (c *Customizer) UpdateEFIBootloader(ctx context.Context) error {
	c.logger.Info("Updating EFI bootloader with correct volume label")

	// The actual EFI bootloader is at /efi/boot/bootx64.efi, not inside efi.img
	efiBootDir := filepath.Join(c.config.Directories.ISO, "efi", "boot")
	bootx64Path := filepath.Join(efiBootDir, "bootx64.efi")

	if _, err := os.Stat(bootx64Path); os.IsNotExist(err) {
		return fmt.Errorf("EFI bootloader not found: %s", bootx64Path)
	}

	// Find grub-mkstandalone
	grubMkstandalone := "grub-mkstandalone"
	if _, err := exec.LookPath(grubMkstandalone); err != nil {
		grubMkstandalone = "grub2-mkstandalone"
		if _, err := exec.LookPath(grubMkstandalone); err != nil {
			return fmt.Errorf("grub-mkstandalone not found: install grub2-common or grub-common package")
		}
	}

	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "efi-update-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Get the volume label from config
	volumeLabel := c.config.Output.Label
	if volumeLabel == "" {
		volumeLabel = "TRUSTED_PLATFORM"
	}

	// Read the ISO grub.cfg to get the full boot menu config
	isoGrubCfg := filepath.Join(c.config.Directories.ISO, "boot", "grub", "grub.cfg")
	grubCfgBytes, err := os.ReadFile(isoGrubCfg)
	if err != nil {
		return fmt.Errorf("failed to read ISO grub.cfg: %w", err)
	}

	// Create embedded GRUB config that searches for the ISO volume by label,
	// then includes the full boot menu inline as a fallback. The iso9660 and
	// search_label modules are included explicitly via --install-modules.
	grubCfgContent := fmt.Sprintf(`insmod iso9660
insmod search_label
insmod part_gpt
insmod part_msdos
insmod serial
# Serial console for BMC SOL — COM1 (unit=0) and COM2 (unit=1)
# for cross-vendor coverage. Output to both serial and text console.
serial --unit=0 --speed=115200
serial --unit=1 --speed=115200
set gfxmode=text
set gfxpayload=text
terminal_input serial console
terminal_output serial console
search --no-floppy --set=root --label "%s"

%s`, volumeLabel, string(grubCfgBytes))

	grubCfgPath := filepath.Join(tmpDir, "grub.cfg")
	if err := os.WriteFile(grubCfgPath, []byte(grubCfgContent), 0644); err != nil {
		return fmt.Errorf("failed to write GRUB config: %w", err)
	}

	// Create new bootx64.efi with grub-mkstandalone, including modules needed
	// to read ISO9660 filesystems and search by volume label.
	newEFIPath := filepath.Join(tmpDir, "bootx64.efi")
	mkstandaloneCmd := exec.CommandContext(ctx, grubMkstandalone,
		"--format=x86_64-efi",
		"--output="+newEFIPath,
		"--locales=",
		"--fonts=",
		"--install-modules=iso9660 search search_label part_gpt part_msdos fat linux normal configfile echo test serial",
		"boot/grub/grub.cfg="+grubCfgPath,
	)

	if output, err := mkstandaloneCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("grub-mkstandalone failed: %w, output: %s", err, string(output))
	}

	// Check generated file size
	newInfo, err := os.Stat(newEFIPath)
	if err != nil {
		return fmt.Errorf("failed to stat new bootx64.efi: %w", err)
	}
	c.logger.Debug("Generated new bootx64.efi", "size", newInfo.Size())

	// Replace the original bootx64.efi with the new one
	if err := copyFile(newEFIPath, bootx64Path); err != nil {
		return fmt.Errorf("failed to replace bootx64.efi: %w", err)
	}

	c.logger.Info("EFI bootloader updated with volume label", "label", volumeLabel, "path", bootx64Path)

	// Regenerate efi.img (El Torito UEFI boot image) with the new bootx64.efi.
	// UEFI firmware boots from the El Torito catalog which points to efi.img,
	// not from the ISO filesystem's /efi/boot/bootx64.efi directly.
	efiImgPath := filepath.Join(c.config.Directories.ISO, "boot", "grub", "efi.img")
	if err := c.regenerateEFIImage(newEFIPath, efiImgPath); err != nil {
		return fmt.Errorf("failed to regenerate efi.img: %w", err)
	}

	return nil
}

// regenerateEFIImage creates a new FAT filesystem image containing the
// bootx64.efi at /efi/boot/bootx64.efi, suitable for use as an El Torito
// UEFI boot image in the ISO.
func (c *Customizer) regenerateEFIImage(bootx64Src, efiImgDst string) error {
	c.logger.Info("Regenerating efi.img with custom bootloader")

	// Get the size of the new bootx64.efi to calculate image size
	info, err := os.Stat(bootx64Src)
	if err != nil {
		return fmt.Errorf("failed to stat bootx64.efi: %w", err)
	}

	// Calculate image size: bootx64.efi size + overhead for FAT filesystem structures.
	// Round up to nearest MB, minimum 4MB to ensure FAT12/16 compatibility.
	imgSizeBytes := info.Size() + 512*1024 // 512KB overhead for FAT metadata
	imgSizeMB := (imgSizeBytes / (1024 * 1024)) + 1
	if imgSizeMB < 4 {
		imgSizeMB = 4
	}

	// Create a new empty image file
	truncateCmd := exec.Command("truncate", "-s", fmt.Sprintf("%dM", imgSizeMB), efiImgDst)
	if output, err := truncateCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create efi.img: %w, output: %s", err, string(output))
	}

	// Format as FAT filesystem
	mkfsCmd := exec.Command("mkfs.vfat", "-F", "12", efiImgDst)
	if output, err := mkfsCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to format efi.img: %w, output: %s", err, string(output))
	}

	// Use mtools to copy files into the FAT image without mounting
	// Create directory structure: /efi/boot/
	mmd := exec.Command("mmd", "-i", efiImgDst, "::efi", "::efi/boot")
	if output, err := mmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create directories in efi.img: %w, output: %s", err, string(output))
	}

	// Copy bootx64.efi into the image
	mcopy := exec.Command("mcopy", "-i", efiImgDst, bootx64Src, "::efi/boot/bootx64.efi")
	if output, err := mcopy.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to copy bootx64.efi into efi.img: %w, output: %s", err, string(output))
	}

	newInfo, err := os.Stat(efiImgDst)
	if err != nil {
		return fmt.Errorf("failed to stat new efi.img: %w", err)
	}
	c.logger.Info("efi.img regenerated", "size", newInfo.Size(), "path", efiImgDst)
	return nil
}

// Helper functions

// checkPrerequisites verifies that all required resources are available
func (c *Customizer) checkPrerequisites() error {
	// Check ISO directory exists
	if _, err := os.Stat(c.config.Directories.ISO); os.IsNotExist(err) {
		return fmt.Errorf("ISO directory not found: %s", c.config.Directories.ISO)
	}

	// Check required binaries
	requiredCommands := []string{"cpio", "gzip", "file", "awk"}
	for _, cmd := range requiredCommands {
		if _, err := exec.LookPath(cmd); err != nil {
			return fmt.Errorf("required command not found: %s", cmd)
		}
	}

	// Check platformd binary if specified
	if c.config.Platform.PlatformdBinary != "" {
		if _, err := os.Stat(c.config.Platform.PlatformdBinary); os.IsNotExist(err) {
			return fmt.Errorf("platformd binary not found: %s", c.config.Platform.PlatformdBinary)
		}
	}

	// Check secure boot keys if enabled
	if c.config.Security.SecureBoot {
		keyPath := filepath.Join(c.config.Directories.Keys, "DB.key")
		certPath := filepath.Join(c.config.Directories.Keys, "DB.crt")
		if _, err := os.Stat(keyPath); os.IsNotExist(err) {
			c.logger.Warn("Secure boot key not found", "path", keyPath)
		}
		if _, err := os.Stat(certPath); os.IsNotExist(err) {
			c.logger.Warn("Secure boot certificate not found", "path", certPath)
		}
	}

	return nil
}

// findInitramfs locates the initramfs file in the extracted ISO
func (c *Customizer) findInitramfs() (string, error) {
	// Common locations for Alpine initramfs
	patterns := []string{
		filepath.Join(c.config.Directories.ISO, "boot", "initramfs-*"),
		filepath.Join(c.config.Directories.ISO, "boot", "initrd*"),
	}

	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		if len(matches) > 0 {
			return matches[0], nil
		}
	}

	return "", fmt.Errorf("initramfs not found in ISO directory")
}

// createDracutModule creates dracut module structure in the initramfs
func (c *Customizer) createDracutModule(initramfsDir string) error {
	moduleDir := filepath.Join(initramfsDir, "usr", "lib", "dracut", "modules.d", "90platformd")
	if err := os.MkdirAll(moduleDir, 0755); err != nil {
		return fmt.Errorf("failed to create module directory: %w", err)
	}

	// Create module-setup.sh
	moduleSetup := `#!/bin/bash
# Dracut module for platform-initrd (boot-only binary)
# NOTE: platform-initrd is the minimal binary for initramfs boot operations
#       platformd is the daemon-only binary, platformctl is the CLI

check() {
    return 0
}

depends() {
    # No crypt module needed - platform-initrd uses go-luks2 for all LUKS operations
    echo systemd
}

install() {
    inst_binary /usr/bin/platform-initrd
    inst_simple "$moddir/platform-initrd-boot.sh" /usr/bin/platform-initrd-boot.sh

    # Install configuration files
    if [ -f /etc/trusted-platform/platformd.yaml ]; then
        inst_simple /etc/trusted-platform/platformd.yaml
    fi
    if [ -f /etc/platformd/install.yaml ]; then
        inst_simple /etc/platformd/install.yaml
    fi
    if [ -f /etc/platformd/initrd.yaml ]; then
        inst_simple /etc/platformd/initrd.yaml
    fi
}
`
	moduleSetupPath := filepath.Join(moduleDir, "module-setup.sh")
	if err := os.WriteFile(moduleSetupPath, []byte(moduleSetup), 0755); err != nil {
		return fmt.Errorf("failed to write module-setup.sh: %w", err)
	}

	// Create platform-initrd-boot.sh wrapper script for dracut
	wrapperScript := `#!/bin/bash
# Platform-initrd boot wrapper for dracut (calls platform-initrd boot)

platform-initrd boot "$@"
`
	wrapperPath := filepath.Join(moduleDir, "platform-initrd-boot.sh")
	if err := os.WriteFile(wrapperPath, []byte(wrapperScript), 0755); err != nil {
		return fmt.Errorf("failed to write wrapper script: %w", err)
	}

	c.logger.Debug("Dracut module created", "path", moduleDir)
	return nil
}

// createAutoinstallOverlay creates the overlay directory structure for autoinstall
func (c *Customizer) createAutoinstallOverlay(initramfsDir string) error {
	overlayDir := filepath.Join(initramfsDir, "overlay")
	if err := os.MkdirAll(filepath.Join(overlayDir, "etc"), 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(overlayDir, "root"), 0755); err != nil {
		return err
	}

	// Create inittab for autoinstall
	// Skip OpenRC entirely — it hangs in the live ISO environment because
	// services expect a fully configured system. The run-autoinstall.sh wrapper
	// already mounts /dev, /proc, /sys, modloop, starts mdev, loads modules,
	// and configures networking manually. BusyBox init just needs to launch it.
	inittab := `::sysinit:/root/run-autoinstall.sh
::sysinit:/sbin/poweroff -f
::ctrlaltdel:/sbin/reboot
`
	inittabPath := filepath.Join(overlayDir, "etc", "inittab")
	if err := os.WriteFile(inittabPath, []byte(inittab), 0644); err != nil {
		return fmt.Errorf("failed to write inittab: %w", err)
	}

	// Create autoinstall script
	autoinstallScript := c.buildAutoinstallScript()
	autoinstallPath := filepath.Join(overlayDir, "root", "autoinstall.sh")
	if err := os.WriteFile(autoinstallPath, []byte(autoinstallScript), 0755); err != nil {
		return fmt.Errorf("failed to write autoinstall.sh: %w", err)
	}

	// Create wrapper script
	// Detect the active console from the kernel (last entry in
	// /sys/class/tty/console/active is the primary console).
	// Falls back to /dev/console which always routes to the active console.
	wrapperScript := `#!/bin/sh
# Autoinstall wrapper - launched by BusyBox init after switch_root
# Redirect all output to serial console for visibility in logs
exec > /dev/ttyS0 2>&1 || exec > /dev/console 2>&1 || true

echo "[autoinstall] run-autoinstall.sh starting (PID $$)"
echo "[autoinstall] run-autoinstall.sh starting (PID $$)" > /dev/kmsg 2>/dev/null

# Mount essential filesystems if not already mounted
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mkdir -p /dev/pts /dev/shm /run 2>/dev/null || true
mount -t devpts devpts /dev/pts 2>/dev/null || true
mount -t tmpfs tmpfs /dev/shm 2>/dev/null || true
mount -t tmpfs tmpfs /run 2>/dev/null || true

# Mount the modloop (kernel modules squashfs) - required for AF_PACKET, dm_crypt, etc.
# Alpine's init adds modloop as an OpenRC service; since we bypass OpenRC, mount it manually.
echo "[autoinstall] Mounting modloop..." > /dev/kmsg 2>/dev/null
KVER=$(uname -r)
if [ ! -d "/lib/modules/$KVER/kernel" ]; then
    # Mount the ISO/CD if not already mounted
    mkdir -p /media/cdrom
    mountpoint -q /media/cdrom 2>/dev/null || \
        mount -t iso9660 /dev/sr0 /media/cdrom 2>/dev/null || \
        mount -t iso9660 /dev/cdrom /media/cdrom 2>/dev/null || true

    MODLOOP=""
    for f in /media/cdrom/boot/modloop-lts /media/*/boot/modloop-lts; do
        [ -f "$f" ] && MODLOOP="$f" && break
    done
    if [ -n "$MODLOOP" ]; then
        mkdir -p /.modloop
        mount -t squashfs -o loop,ro "$MODLOOP" /.modloop 2>/dev/null
        if [ -d "/.modloop/modules" ]; then
            # Link modules directory so modprobe finds them
            rm -rf /lib/modules 2>/dev/null
            ln -sf /.modloop/modules /lib/modules
            echo "[autoinstall] modloop mounted: $(ls /lib/modules/)" > /dev/kmsg 2>/dev/null
        else
            echo "[autoinstall] WARNING: modloop has no modules dir" > /dev/kmsg 2>/dev/null
        fi
    else
        echo "[autoinstall] WARNING: modloop not found on ISO" > /dev/kmsg 2>/dev/null
    fi
else
    echo "[autoinstall] Kernel modules already available" > /dev/kmsg 2>/dev/null
fi

# Start mdev for device hotplug (BusyBox device manager)
echo "[autoinstall] Starting mdev..." > /dev/kmsg 2>/dev/null
echo /sbin/mdev > /proc/sys/kernel/hotplug 2>/dev/null || true
mdev -s 2>/dev/null || true

# Load essential kernel modules
echo "[autoinstall] Loading kernel modules..." > /dev/kmsg 2>/dev/null
modprobe af_packet 2>/dev/null || true
modprobe virtio_net 2>/dev/null || true
modprobe virtio_blk 2>/dev/null || true
modprobe virtio_pci 2>/dev/null || true
modprobe e1000 2>/dev/null || true
modprobe e1000e 2>/dev/null || true
modprobe igb 2>/dev/null || true
modprobe dm_mod 2>/dev/null || true
modprobe dm_crypt 2>/dev/null || true
sleep 1

# Re-scan devices after module loading
mdev -s 2>/dev/null || true

# Bring up networking manually (no OpenRC available)
echo "[autoinstall] Bringing up network..." > /dev/kmsg 2>/dev/null
ip link set lo up 2>/dev/null || true

# Find first ethernet interface
ETH_IF=""
for iface in /sys/class/net/eth* /sys/class/net/en*; do
    [ -e "$iface" ] || continue
    ETH_IF=$(basename "$iface")
    break
done

if [ -n "$ETH_IF" ]; then
    echo "[autoinstall] Configuring interface: $ETH_IF" > /dev/kmsg 2>/dev/null
    ip link set "$ETH_IF" up
    echo "[autoinstall] Link state: $(cat /sys/class/net/$ETH_IF/operstate 2>/dev/null)" > /dev/kmsg 2>/dev/null
    echo "[autoinstall] MAC: $(cat /sys/class/net/$ETH_IF/address 2>/dev/null)" > /dev/kmsg 2>/dev/null

    # Ensure ISO is mounted (may have been skipped if modules were in initramfs)
    mkdir -p /media/cdrom 2>/dev/null || true
    mountpoint -q /media/cdrom 2>/dev/null || \
        mount -t iso9660 /dev/sr0 /media/cdrom 2>/dev/null || \
        mount -t iso9660 /dev/cdrom /media/cdrom 2>/dev/null || true

    # Check for static IP configuration in installer.yaml on the ISO
    STATIC_CONFIGURED=false
    INSTALLER_YAML="/media/cdrom/configs/installer.yaml"
    if [ -f "$INSTALLER_YAML" ]; then
        IFACE_TYPE=$(grep -A10 "interfaces:" "$INSTALLER_YAML" 2>/dev/null | grep "type:" | head -1 | sed 's/.*type:\s*//' | tr -d ' "')
        if [ "$IFACE_TYPE" = "static" ]; then
            echo "[autoinstall] Static IP configuration detected in installer.yaml" > /dev/kmsg 2>/dev/null

            IPV4_ADDR=$(grep -A10 "interfaces:" "$INSTALLER_YAML" | grep "ipv4-address:" | head -1 | sed 's/.*ipv4-address:\s*//' | tr -d ' "')
            IPV4_MASK=$(grep -A10 "interfaces:" "$INSTALLER_YAML" | grep "ipv4-netmask:" | head -1 | sed 's/.*ipv4-netmask:\s*//' | tr -d ' "')
            IPV4_GW=$(grep -A10 "interfaces:" "$INSTALLER_YAML" | grep "ipv4-gateway:" | head -1 | sed 's/.*ipv4-gateway:\s*//' | tr -d ' "')
            DNS_SERVERS=$(grep -A5 "dns:" "$INSTALLER_YAML" 2>/dev/null | grep -A3 "nameservers:" | grep "^\s*-" | sed 's/.*-\s*//' | tr -d ' "' | tr '\n' ' ')

            if [ -n "$IPV4_ADDR" ] && [ -n "$IPV4_GW" ]; then
                # Calculate CIDR prefix from netmask
                case "$IPV4_MASK" in
                    255.255.255.0)   CIDR="24" ;;
                    255.255.255.128) CIDR="25" ;;
                    255.255.255.192) CIDR="26" ;;
                    255.255.255.224) CIDR="27" ;;
                    255.255.255.240) CIDR="28" ;;
                    255.255.255.248) CIDR="29" ;;
                    255.255.255.252) CIDR="30" ;;
                    255.255.0.0)     CIDR="16" ;;
                    255.0.0.0)       CIDR="8" ;;
                    *)               CIDR="24" ;;
                esac

                echo "[autoinstall] Configuring $ETH_IF: ${IPV4_ADDR}/${CIDR} gw ${IPV4_GW}" > /dev/kmsg 2>/dev/null
                ip addr add "${IPV4_ADDR}/${CIDR}" dev "$ETH_IF" 2>/dev/null || true
                ip route add default via "$IPV4_GW" 2>/dev/null || true

                if [ -n "$DNS_SERVERS" ]; then
                    : > /etc/resolv.conf
                    for dns in $DNS_SERVERS; do
                        echo "nameserver $dns" >> /etc/resolv.conf
                    done
                    echo "[autoinstall] DNS configured: $DNS_SERVERS" > /dev/kmsg 2>/dev/null
                fi

                STATIC_CONFIGURED=true
                echo "[autoinstall] Static network configured successfully" > /dev/kmsg 2>/dev/null
            fi
        fi
    fi

    # Fall back to DHCP only if static config was not applied
    if [ "$STATIC_CONFIGURED" = "false" ]; then
        echo "[autoinstall] No static config, falling back to DHCP" > /dev/kmsg 2>/dev/null
        if command -v udhcpc >/dev/null 2>&1; then
            UDHCPC_SCRIPT=""
            for s in /usr/share/udhcpc/default.script /etc/udhcpc/default.script; do
                [ -x "$s" ] && UDHCPC_SCRIPT="$s" && break
            done
            if [ -n "$UDHCPC_SCRIPT" ]; then
                echo "[autoinstall] Running udhcpc with script: $UDHCPC_SCRIPT" > /dev/kmsg 2>/dev/null
                udhcpc -i "$ETH_IF" -n -t 5 -T 3 -A 3 -s "$UDHCPC_SCRIPT" -v 2>&1 | while read line; do
                    echo "[autoinstall] udhcpc: $line" > /dev/kmsg 2>/dev/null
                done
            else
                echo "[autoinstall] No udhcpc script found, running without script" > /dev/kmsg 2>/dev/null
                udhcpc -i "$ETH_IF" -n -t 5 -T 3 -A 3 -v 2>&1 | while read line; do
                    echo "[autoinstall] udhcpc: $line" > /dev/kmsg 2>/dev/null
                done
            fi
        elif command -v dhcpcd >/dev/null 2>&1; then
            echo "[autoinstall] Running dhcpcd on $ETH_IF..." > /dev/kmsg 2>/dev/null
            dhcpcd -w --timeout 30 "$ETH_IF" 2>/dev/null || true
        fi
    fi

    # Log IP address
    IP_ADDR=$(ip -4 addr show "$ETH_IF" 2>/dev/null | grep -o 'inet [^ ]*' | head -1)
    echo "[autoinstall] Network: $ETH_IF $IP_ADDR" > /dev/kmsg 2>/dev/null
else
    echo "[autoinstall] WARNING: No ethernet interface found" > /dev/kmsg 2>/dev/null
fi

/bin/sh /root/autoinstall.sh
RESULT=$?
echo "[autoinstall] autoinstall.sh exited with code: ${RESULT}" > /dev/kmsg 2>/dev/null
echo "[autoinstall] autoinstall.sh exited with code: ${RESULT}"

# If running as PID 1, poweroff directly since there's no init to return to
if [ $$ -eq 1 ]; then
    echo "[autoinstall] running as PID 1, calling poweroff" > /dev/kmsg 2>/dev/null
    exec poweroff -f
fi
`
	wrapperPath := filepath.Join(overlayDir, "root", "run-autoinstall.sh")
	if err := os.WriteFile(wrapperPath, []byte(wrapperScript), 0755); err != nil {
		return fmt.Errorf("failed to write wrapper script: %w", err)
	}

	c.logger.Debug("Autoinstall overlay created", "path", overlayDir)
	return nil
}

// patchInitScript patches Alpine's init script to copy overlay to sysroot
func (c *Customizer) patchInitScript(initramfsDir string) error {
	initPath := filepath.Join(initramfsDir, "init")
	if _, err := os.Stat(initPath); os.IsNotExist(err) {
		return fmt.Errorf("init script not found: %s", initPath)
	}

	patchContent := `
# Autoinstall injection - copy overlay to sysroot and use BusyBox init with custom inittab
if grep -q alpine_start=autoinstall /proc/cmdline 2>/dev/null; then
  echo "Applying autoinstall configuration..." > /dev/kmsg
  mkdir -p "$sysroot"/root "$sysroot"/etc
  if [ -f /overlay/root/autoinstall.sh ]; then
    cp -f /overlay/root/autoinstall.sh "$sysroot"/root/autoinstall.sh && echo "autoinstall.sh copied" > /dev/kmsg || echo "autoinstall.sh copy failed" > /dev/kmsg
    chmod +x "$sysroot"/root/autoinstall.sh
  fi
  if [ -f /overlay/root/run-autoinstall.sh ]; then
    cp -f /overlay/root/run-autoinstall.sh "$sysroot"/root/run-autoinstall.sh && echo "run-autoinstall.sh copied" > /dev/kmsg || echo "run-autoinstall.sh copy failed" > /dev/kmsg
    chmod +x "$sysroot"/root/run-autoinstall.sh
  fi
  # Install custom inittab that runs OpenRC sysinit/boot then autoinstall
  # Using BusyBox init ensures /dev, /proc, /sys are properly set up
  if [ -f /overlay/etc/inittab ]; then
    cp -f /overlay/etc/inittab "$sysroot"/etc/inittab && echo "inittab installed" > /dev/kmsg || echo "inittab copy failed" > /dev/kmsg
  fi
  echo "autoinstall configured via inittab" > /dev/kmsg
fi
`

	// Write patch content to temporary file
	patchPath := filepath.Join(initramfsDir, "patch.txt")
	if err := os.WriteFile(patchPath, []byte(strings.TrimSpace(patchContent)), 0644); err != nil {
		return fmt.Errorf("failed to write patch content: %w", err)
	}
	defer os.Remove(patchPath)

	// Use awk to inject patch after setup_inittab_console function
	// Read patch content from file to avoid quoting issues
	awkScript := `
/^setup_inittab_console$/ && !injected {
    print;
    print "";
    while ((getline line < "` + patchPath + `") > 0) {
        print line;
    }
    close("` + patchPath + `");
    print "";
    injected=1;
    next;
}
{ print }
`

	// Create temporary awk script
	awkScriptPath := filepath.Join(initramfsDir, "patch.awk")
	if err := os.WriteFile(awkScriptPath, []byte(awkScript), 0644); err != nil {
		return fmt.Errorf("failed to write awk script: %w", err)
	}
	defer os.Remove(awkScriptPath)

	// Apply patch using awk
	cmd := exec.Command("awk", "-f", awkScriptPath, initPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to patch init script: %w\nOutput: %s", err, string(output))
	}

	// Write patched init
	if err := os.WriteFile(initPath, output, 0755); err != nil {
		return fmt.Errorf("failed to write patched init: %w", err)
	}

	c.logger.Debug("Init script patched successfully")
	return nil
}

// verifyInitramfs verifies that the repacked initramfs contains expected files
func (c *Customizer) verifyInitramfs(initramfsPath string) error {
	// Create temporary directory for verification
	verifyDir := filepath.Join(c.config.Directories.Work, "verify-initramfs")
	if err := os.RemoveAll(verifyDir); err != nil {
		return fmt.Errorf("failed to remove old verify dir: %w", err)
	}
	if err := os.MkdirAll(verifyDir, 0755); err != nil {
		return fmt.Errorf("failed to create verify dir: %w", err)
	}
	defer os.RemoveAll(verifyDir)

	// Extract initramfs
	if err := extractInitramfs(initramfsPath, verifyDir); err != nil {
		return fmt.Errorf("failed to extract for verification: %w", err)
	}

	// Check for expected files
	expectedFiles := []string{
		"overlay/etc/inittab",
		"overlay/root/autoinstall.sh",
		"overlay/root/run-autoinstall.sh",
	}

	for _, file := range expectedFiles {
		path := filepath.Join(verifyDir, file)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return fmt.Errorf("verification failed: %s not found in initramfs", file)
		}
	}

	c.logger.Debug("Initramfs verification passed")
	return nil
}

// buildAutoinstallScript generates the autoinstall script content
func (c *Customizer) buildAutoinstallScript() string {
	var sb strings.Builder

	sb.WriteString(`#!/bin/sh
# Automated installation script with platformd integration
set -e

log() {
    echo "[autoinstall] $1"
    echo "[autoinstall] $1" > /dev/kmsg 2>/dev/null || true
    sync
}

error() {
    echo "[autoinstall] ERROR: $1" >&2
    echo "[autoinstall] ERROR: $1" > /dev/kmsg 2>/dev/null || true
    sync
    exit 1
}

# resolve_platform_hostname extracts os.hostname from the embedded
# platformd config file. The config is the single source of truth for
# every node-specific field; the installer reads it from the ISO at
# /etc/platformd/config.yaml (copied in by the iso customizer) or from
# the fetch cache in dynamic-config mode (/etc/platformd/config.yaml
# written by the dynamic-config fetcher before autoinstall runs).
#
# Returns the hostname string on stdout, empty string if not set.
# Falls back to the Alpine live env's hostname command only when the
# config file is missing entirely — which only happens in development
# or misconfigured builds.
#
# Shell-native YAML scan: looks for the first indented "hostname:" key
# inside the top-level "os:" block. Handles quoted and unquoted values.
# Avoids python/yq dependencies because the live installer environment
# has neither.
resolve_platform_hostname() {
    # Candidate paths, in preference order:
    # 1. The installer.Config yaml in the overlay — populated by
    #    buildInstallerConfig with hostname sourced from the merged
    #    platformd config. This is the canonical runtime path under
    #    the live Alpine environment.
    # 2. The merged platformd config on the CD mount (legacy/fallback).
    CFG="/etc/platformd/install.yaml"
    [ ! -f "$CFG" ] && CFG="/etc/platformd/config.yaml"
    [ ! -f "$CFG" ] && CFG="/media/cdrom/configs/installer.yaml"
    [ ! -f "$CFG" ] && CFG="/mnt/cdrom/configs/installer.yaml"
    if [ -f "$CFG" ]; then
        # awk scan: track when we enter the "os:" block at indent 0,
        # then emit the first indented "hostname:" value we see before
        # we hit another top-level key.
        HN=$(awk '
            /^os:[[:space:]]*$/ { inos = 1; next }
            /^[a-zA-Z]/        { if (inos) { inos = 0 } }
            inos && /^[[:space:]]+hostname:/ {
                sub(/^[[:space:]]+hostname:[[:space:]]*/, "")
                gsub(/["'"'"']/, "")
                sub(/[[:space:]]+$/, "")
                print
                exit
            }
        ' "$CFG" 2>/dev/null)
        if [ -n "$HN" ]; then
            echo "$HN"
            return 0
        fi
    fi
    # Final fallback: Alpine live env hostname command. Usually returns
    # (none) or localhost; the caller normalizes those to "unknown".
    hostname 2>/dev/null
}

# upload_install_log uploads /tmp/install.log to the bootstrap container's
# HTTP forensic sink. Resolves the sink in this order:
#   1. Kernel cmdline platform_debug_sink=host:port
#   2. The DHCP server IP from the dhclient lease (the bootstrap container
#      IS the DHCP server in our deployment, so this is always reachable)
#   3. The default gateway as a last resort
# Best-effort: a failed upload logs a warning and returns 0 so the
# surrounding cleanup continues unchanged.
upload_install_log() {
    upload_install_log_with_code "$?"
}

# upload_install_log_with_code is the implementation. The trap calls this
# directly with the exit code captured BEFORE upload_checkpoint runs, so we
# don't lose the original install exit code in the postmortem.
upload_install_log_with_code() {
    INSTALL_EXIT_CODE="$1"
    [ -z "$INSTALL_EXIT_CODE" ] && INSTALL_EXIT_CODE=0
    set +e

    SINK=$(cat /proc/cmdline 2>/dev/null | tr ' ' '\n' | grep '^platform_debug_sink=' | cut -d= -f2- | tail -1)
    if [ -z "$SINK" ]; then
        DHCP_SERVER=$(grep -h '^server-identifier\|^dhcp-server-identifier' /var/lib/dhcp/*.leases /var/lib/dhcpcd/*.lease* 2>/dev/null | tail -1 | sed 's/.*identifier //; s/[ ;].*//')
        if [ -z "$DHCP_SERVER" ]; then
            DHCP_SERVER=$(ip route show default 2>/dev/null | head -1 | awk '{print $3}')
        fi
        if [ -n "$DHCP_SERVER" ]; then
            SINK="${DHCP_SERVER}:8080"
        fi
    fi

    if [ -z "$SINK" ]; then
        echo "[autoinstall] no upload sink resolved - install.log will NOT be uploaded" > /dev/kmsg 2>/dev/null || true
        set -e
        return $INSTALL_EXIT_CODE
    fi

    # Hostname for the upload path. Single source of truth is the
    # embedded platformd config at /etc/platformd/config.yaml (copied
    # into the ISO by CopyPlatformConfig) or, in dynamic config mode,
    # the config fetched at boot and written to the same path. We do a
    # minimal shell-native YAML scan for the os.hostname field rather
    # than pulling in a YAML parser. Fall back to the Alpine live env
    # hostname command and then to "unknown" if both sources are empty.
    HOSTNAME_LC=$(resolve_platform_hostname)
    HOSTNAME_LC=$(echo "$HOSTNAME_LC" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9.\-]/-/g')
    case "$HOSTNAME_LC" in
        ""|"-none-"|"none"|"localhost"|"alpine"|"alpinelinux") HOSTNAME_LC="unknown" ;;
    esac

    URL="http://${SINK}/installs/${HOSTNAME_LC}/install.log"
    echo "[autoinstall] uploading install.log to ${URL} (exit=${INSTALL_EXIT_CODE})" > /dev/kmsg 2>/dev/null || true

    # Append a postmortem manifest with hardware/system context. Invaluable
    # for diagnosing install failures after the live env is gone.
    {
        echo ""
        echo "=== POSTMORTEM MANIFEST ==="
        echo "exit_code: ${INSTALL_EXIT_CODE}"
        echo "timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)"
        echo "hostname: ${HOSTNAME_LC}"
        echo "kernel_cmdline: $(cat /proc/cmdline 2>/dev/null)"
        echo ""
        echo "--- lsblk ---"
        lsblk 2>&1 || true
        echo ""
        echo "--- ip addr ---"
        ip addr 2>&1 || true
        echo ""
        echo "--- mount ---"
        mount 2>&1 || true
        echo ""
        echo "--- dmesg tail ---"
        dmesg 2>&1 | tail -200 || true
        echo ""
        echo "=== END POSTMORTEM ==="
    } >> /tmp/install.log 2>/dev/null || true

    if command -v curl >/dev/null 2>&1; then
        curl --silent --show-error --max-time 30 \
             --request PUT --upload-file /tmp/install.log "${URL}" \
             > /dev/kmsg 2>&1 || \
            echo "[autoinstall] curl PUT failed (continuing)" > /dev/kmsg 2>/dev/null || true
    else
        BODY_LEN=$(wc -c < /tmp/install.log 2>/dev/null || echo 0)
        HOST_PART="${SINK%:*}"
        PORT_PART="${SINK##*:}"
        {
            printf 'PUT /installs/%s/install.log HTTP/1.1\r\n' "${HOSTNAME_LC}"
            printf 'Host: %s\r\n' "${SINK}"
            printf 'Content-Length: %s\r\n' "${BODY_LEN}"
            printf 'Connection: close\r\n'
            printf 'Content-Type: text/plain\r\n'
            printf '\r\n'
            cat /tmp/install.log 2>/dev/null
        } | nc -w 30 "${HOST_PART}" "${PORT_PART}" > /dev/kmsg 2>&1 || \
            echo "[autoinstall] nc PUT failed (continuing)" > /dev/kmsg 2>/dev/null || true
    fi

    echo "[autoinstall] upload attempt complete" > /dev/kmsg 2>/dev/null || true
    set -e
    return $INSTALL_EXIT_CODE
}

# upload_checkpoint uploads a tiny heartbeat file to mark that the script
# reached this stage. Used at multiple points (script-start, pre-install,
# post-install, success, failure) so we can pinpoint which stage the install
# is dying at when the full install.log doesn't make it off the box.
upload_checkpoint() {
    CHECKPOINT_NAME="$1"
    set +e

    SINK=$(cat /proc/cmdline 2>/dev/null | tr ' ' '\n' | grep '^platform_debug_sink=' | cut -d= -f2- | tail -1)
    if [ -z "$SINK" ]; then
        DHCP_SERVER=$(grep -h '^server-identifier\|^dhcp-server-identifier' /var/lib/dhcp/*.leases /var/lib/dhcpcd/*.lease* 2>/dev/null | tail -1 | sed 's/.*identifier //; s/[ ;].*//')
        [ -z "$DHCP_SERVER" ] && DHCP_SERVER=$(ip route show default 2>/dev/null | head -1 | awk '{print $3}')
        [ -n "$DHCP_SERVER" ] && SINK="${DHCP_SERVER}:8080"
    fi
    if [ -z "$SINK" ]; then
        echo "[checkpoint:$CHECKPOINT_NAME] no sink resolved" > /dev/kmsg 2>/dev/null || true
        set -e
        return
    fi

    HOSTNAME_LC=$(resolve_platform_hostname)
    HOSTNAME_LC=$(echo "$HOSTNAME_LC" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9.\-]/-/g')
    case "$HOSTNAME_LC" in
        ""|"-none-"|"none"|"localhost"|"alpine"|"alpinelinux") HOSTNAME_LC="unknown" ;;
    esac

    PAYLOAD="checkpoint=$CHECKPOINT_NAME timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date) sink=$SINK"
    URL="http://${SINK}/installs/${HOSTNAME_LC}/checkpoint-${CHECKPOINT_NAME}.txt"
    echo "[checkpoint:$CHECKPOINT_NAME] PUT $URL" > /dev/kmsg 2>/dev/null || true

    if command -v curl >/dev/null 2>&1; then
        printf '%s\n' "$PAYLOAD" | curl --silent --show-error --max-time 10 \
             --request PUT --data-binary @- "${URL}" > /dev/kmsg 2>&1 || \
            echo "[checkpoint:$CHECKPOINT_NAME] curl failed" > /dev/kmsg 2>/dev/null || true
    else
        BODY_LEN=$(printf '%s\n' "$PAYLOAD" | wc -c)
        HOST_PART="${SINK%:*}"
        PORT_PART="${SINK##*:}"
        {
            printf 'PUT /installs/%s/checkpoint-%s.txt HTTP/1.1\r\n' "${HOSTNAME_LC}" "${CHECKPOINT_NAME}"
            printf 'Host: %s\r\n' "${SINK}"
            printf 'Content-Length: %s\r\n' "${BODY_LEN}"
            printf 'Connection: close\r\n'
            printf '\r\n'
            printf '%s\n' "$PAYLOAD"
        } | nc -w 10 "${HOST_PART}" "${PORT_PART}" > /dev/kmsg 2>&1 || \
            echo "[checkpoint:$CHECKPOINT_NAME] nc failed" > /dev/kmsg 2>/dev/null || true
    fi
    set -e
}

# Trap upload + log exit on EVERY exit path. CRITICAL: capture $? FIRST
# and pass it explicitly to upload_install_log, otherwise running
# upload_checkpoint first clobbers $? to its own success exit code (0)
# and the postmortem reports exit_code:0 even when the install actually
# failed. This is exactly the bug that masked the original UKI build
# failure as "successful install" — every checkpoint says success because
# the original install error was overwritten before the trap reached the
# upload step.
trap 'TRAP_RC=$?; upload_checkpoint exit-trap; upload_install_log_with_code "$TRAP_RC"; echo "[autoinstall] script exiting with status $TRAP_RC" > /dev/kmsg 2>/dev/null' EXIT INT TERM

# CHECKPOINT 1: script started. If this never lands on the bootstrap host,
# the autoinstall.sh isn't running at all (init/inittab problem).
upload_checkpoint script-start

log "Starting platformd system installation..."

# Load common bare metal NIC drivers before configuring network
log "Loading kernel modules for bare metal NICs..."
for mod in igb ixgbe e1000e i40e ice; do
    modprobe "$mod" 2>/dev/null && log "  Loaded: $mod" || true
done
sleep 2

# Configure networking from installer.yaml if available
log "Configuring network..."
INSTALLER_YAML="/media/cdrom/configs/installer.yaml"
if [ -f "$INSTALLER_YAML" ]; then
    log "Reading network configuration from installer.yaml..."

    # Extract network interface configuration using grep/sed
    # Check if static IP is configured
    IFACE_TYPE=$(grep -A10 "interfaces:" "$INSTALLER_YAML" | grep "type:" | head -1 | sed 's/.*type:\s*//' | tr -d ' "')

    if [ "$IFACE_TYPE" = "static" ]; then
        log "Static IP configuration detected"

        # Extract network settings
        IFACE_NAME=$(grep -A10 "interfaces:" "$INSTALLER_YAML" | grep "name:" | head -1 | sed 's/.*name:\s*//' | tr -d ' "')
        IPV4_ADDR=$(grep -A10 "interfaces:" "$INSTALLER_YAML" | grep "ipv4-address:" | head -1 | sed 's/.*ipv4-address:\s*//' | tr -d ' "')
        IPV4_MASK=$(grep -A10 "interfaces:" "$INSTALLER_YAML" | grep "ipv4-netmask:" | head -1 | sed 's/.*ipv4-netmask:\s*//' | tr -d ' "')
        IPV4_GW=$(grep -A10 "interfaces:" "$INSTALLER_YAML" | grep "ipv4-gateway:" | head -1 | sed 's/.*ipv4-gateway:\s*//' | tr -d ' "')

        # Extract DNS servers
        DNS_SERVERS=$(grep -A5 "dns:" "$INSTALLER_YAML" | grep -A3 "nameservers:" | grep "^\s*-" | sed 's/.*-\s*//' | tr -d ' "' | tr '\n' ' ')

        # Default interface name if not specified
        [ -z "$IFACE_NAME" ] && IFACE_NAME="eth0"

        if [ -n "$IPV4_ADDR" ] && [ -n "$IPV4_GW" ]; then
            log "Configuring $IFACE_NAME with IP: $IPV4_ADDR, Gateway: $IPV4_GW"

            # Bring up interface
            ip link set "$IFACE_NAME" up 2>/dev/null || true

            # Calculate CIDR prefix from netmask
            # Common netmasks: 255.255.255.0 = /24, 255.255.255.240 = /28
            case "$IPV4_MASK" in
                255.255.255.0)   CIDR="24" ;;
                255.255.255.128) CIDR="25" ;;
                255.255.255.192) CIDR="26" ;;
                255.255.255.224) CIDR="27" ;;
                255.255.255.240) CIDR="28" ;;
                255.255.255.248) CIDR="29" ;;
                255.255.255.252) CIDR="30" ;;
                255.255.254.0)   CIDR="23" ;;
                255.255.252.0)   CIDR="22" ;;
                255.255.248.0)   CIDR="21" ;;
                255.255.240.0)   CIDR="20" ;;
                255.255.0.0)     CIDR="16" ;;
                255.0.0.0)       CIDR="8" ;;
                *)               CIDR="24" ;;  # Default to /24
            esac

            # Configure IP address
            ip addr add "${IPV4_ADDR}/${CIDR}" dev "$IFACE_NAME" 2>/dev/null || true

            # Add default route
            ip route add default via "$IPV4_GW" 2>/dev/null || true

            # Configure DNS
            if [ -n "$DNS_SERVERS" ]; then
                log "Configuring DNS: $DNS_SERVERS"
                : > /etc/resolv.conf
                for dns in $DNS_SERVERS; do
                    echo "nameserver $dns" >> /etc/resolv.conf
                done
            fi

            log "Static network configuration complete"
            ip addr show "$IFACE_NAME"
            ip route show
        else
            log "Incomplete static config, falling back to DHCP"
            setup-interfaces -a 2>&1 || true
            rc-service networking start 2>&1 || true
        fi
    else
        log "DHCP or no network type specified, using auto-configuration"
        setup-interfaces -a 2>&1 || true
        rc-service networking start 2>&1 || true
    fi
else
    log "No installer.yaml found, using DHCP"
    setup-interfaces -a 2>&1 || true
    rc-service networking start 2>&1 || true
fi
sleep 2

# Mount the ISO/CD-ROM if not already mounted
log "Mounting boot media..."
mkdir -p /media/cdrom
if ! mountpoint -q /media/cdrom 2>/dev/null; then
    mount -t iso9660 /dev/sr0 /media/cdrom 2>/dev/null || \
    mount -t iso9660 /dev/cdrom /media/cdrom 2>/dev/null || \
    log "Warning: Could not mount CD-ROM, packages may not be available offline"
fi

# Setup repositories - use local ISO packages first, network as fallback
log "Setting up repositories..."
cat > /etc/apk/repositories << 'REPOEOF'
/media/cdrom/apks
`)

	// Add network repository URLs as fallback
	majorVersion := getMajorVersion(c.config.Alpine.Version)
	fmt.Fprintf(&sb, "%s/v%s/main\n", c.config.Alpine.Mirror, majorVersion)
	fmt.Fprintf(&sb, "%s/v%s/community\n", c.config.Alpine.Mirror, majorVersion)

	sb.WriteString(`REPOEOF

# Wait for network to come up (DHCP may take a few seconds)
log "Waiting for network connectivity..."
NETWORK_READY=false
for i in $(seq 1 10); do
    if apk update --allow-untrusted 2>/dev/null; then
        NETWORK_READY=true
        log "Package index updated successfully"
        break
    fi
    log "Waiting for network... attempt $i/10"
    sleep 2
done
if [ "$NETWORK_READY" = "false" ]; then
    log "Warning: Network not available, using local packages from ISO only"
    # Use pre-fetched packages repo for offline installation
    # --allow-untrusted is needed because the pre-fetch APKINDEX is unsigned
    printf "/media/cdrom/apks\n/media/cdrom/apks-prefetch\n" > /etc/apk/repositories
fi

# Install required packages (--no-network forces local repo only if network unavailable)
log "Installing disk management tools..."
apk add --no-cache --allow-untrusted \
    parted \
    e2fsprogs \
    e2fsprogs-extra \
    lvm2 \
    dosfstools \
    util-linux \
    kmod \
    device-mapper \
    eudev || error "Failed to install required packages"

# Decompression/compression tooling for the initramfs rebuild step. dracut
# can produce gzip, xz, or zstd initramfs depending on kernel CONFIG_RD_*
# and dracut.conf. The Go installer auto-detects the format from magic
# bytes (pkg/installer/installer.go:detectInitramfsDecompressor) and
# shells out to the matching streaming tool. The full set must be
# available in the live env, otherwise the install dies in the UKI
# extract-modify-repack pipeline with an obscure "command not found".
log "Installing initramfs codec tools (gzip/xz/zstd/lz4/lzop)..."
apk add --no-cache --allow-untrusted \
    gzip \
    xz \
    zstd \
    lz4 \
    lzop \
    bzip2 || log "Warning: some initramfs codecs may not be available; install will fail if dracut uses them"

# cpio binary in busybox accepts only short options. The Go installer's
# inject step uses cpio -idm (short form), which IS busybox-compatible.
# Future maintainers: do NOT reintroduce GNU long options like
# --no-absolute-filenames which silently break in busybox.

# Install glibc compatibility layer for platformd binary
log "Installing glibc compatibility layer..."
apk add --no-cache --allow-untrusted gcompat libc6-compat || log "Warning: glibc compatibility packages may not be fully available"

# Install OpenSSL libraries needed by platformd
log "Installing OpenSSL libraries..."
apk add --no-cache --allow-untrusted openssl-dev || log "Warning: OpenSSL dev package not available"

# Install SoftHSM if the platform config references it
if grep -q "libsofthsm" /media/cdrom/configs/*.yaml 2>/dev/null; then
    log "Platform config references SoftHSM, installing softhsm package..."
    apk add --no-cache --allow-untrusted softhsm || log "Warning: SoftHSM package not available"
else
    log "SoftHSM not referenced in config, skipping installation"
fi

log "Required packages installed successfully"
sync
sleep 1

# Load required kernel modules for device-mapper and LUKS
log "Loading kernel modules..."
modprobe dm_mod 2>/dev/null || log "Warning: dm_mod may already be loaded"
modprobe dm_crypt 2>/dev/null || log "Warning: dm_crypt may already be loaded"
modprobe loop 2>/dev/null || log "Warning: loop may already be loaded"

# Trigger udev to create device nodes (including /dev/mapper/control)
log "Triggering udev to create device nodes..."
if command -v udevadm >/dev/null 2>&1; then
    udevadm trigger --type=devices 2>/dev/null || true
    udevadm settle --timeout=10 2>/dev/null || true
fi

# Verify /dev/mapper/control exists
if [ -e /dev/mapper/control ]; then
    log "Device-mapper control node ready: /dev/mapper/control"
else
    # Manually create dm control node if udev didn't
    log "Creating device-mapper control node manually..."
    mkdir -p /dev/mapper
    if [ ! -e /dev/mapper/control ]; then
        # Get dm control major/minor from /proc/misc
        DM_MINOR=$(grep -w "device-mapper" /proc/misc 2>/dev/null | awk '{print $1}')
        if [ -n "$DM_MINOR" ]; then
            mknod /dev/mapper/control c 10 "$DM_MINOR" 2>/dev/null || log "Warning: Could not create control node"
        fi
    fi
fi

# Verify device-mapper is working
if [ -e /dev/mapper/control ]; then
    log "Device-mapper ready"
else
    error "Device-mapper control node not available - LUKS will fail"
fi

# Find platformctl binary (CLI binary for installation operations)
# Prefer static binary for Alpine/musl compatibility
PLATFORM_BIN=""
if [ -x /usr/bin/platformctl-static ]; then
    PLATFORM_BIN="/usr/bin/platformctl-static"
    log "Found platformctl-static in /usr/bin"
elif [ -x /usr/bin/platformctl ]; then
    PLATFORM_BIN="/usr/bin/platformctl"
    log "Found platformctl in /usr/bin"
elif [ -x /media/cdrom/platformd-bin/platformctl-static ]; then
    PLATFORM_BIN="/media/cdrom/platformd-bin/platformctl-static"
    log "Found platformctl-static on CD-ROM"
elif [ -x /media/cdrom/platformd-bin/platformctl ]; then
    PLATFORM_BIN="/media/cdrom/platformd-bin/platformctl"
    log "Found platformctl on CD-ROM"
else
    error "platformctl binary not found"
fi

# Find installer configuration file
INSTALLER_CONFIG=""
if [ -f /media/cdrom/configs/installer.yaml ]; then
    INSTALLER_CONFIG="/media/cdrom/configs/installer.yaml"
    log "Found installer configuration: $INSTALLER_CONFIG"
else
    log "No installer configuration found, using defaults"
fi

# Detect target installation disk
# Skip removable devices (BMC virtual CD-ROM) and small devices (< 8GB)
INSTALL_DISK=""
log "Auto-detecting installation disk..."
lsblk -d -o NAME,SIZE,TYPE,TRAN,RO,RM 2>/dev/null | while read line; do log "  $line"; done

for disk in /dev/sda /dev/sdb /dev/sdc /dev/nvme0n1 /dev/vda; do
    [ -b "$disk" ] || continue
    DEVNAME=$(basename $disk)
    REMOVABLE=$(cat /sys/block/$DEVNAME/removable 2>/dev/null || echo "1")
    if [ "$REMOVABLE" = "1" ]; then
        log "  Skipping $disk (removable - likely virtual CD)"
        continue
    fi
    READONLY=$(cat /sys/block/$DEVNAME/ro 2>/dev/null || echo "1")
    if [ "$READONLY" = "1" ]; then
        log "  Skipping $disk (read-only)"
        continue
    fi
    SIZE_SECTORS=$(cat /sys/block/$DEVNAME/size 2>/dev/null || echo "0")
    SIZE_GB=$((SIZE_SECTORS * 512 / 1024 / 1024 / 1024))
    if [ "$SIZE_GB" -lt 8 ]; then
        log "  Skipping $disk (${SIZE_GB}GB - too small)"
        continue
    fi
    INSTALL_DISK="$disk"
    log "Found installation target: $INSTALL_DISK (${SIZE_GB}GB)"
    break
done

if [ -z "$INSTALL_DISK" ]; then
    error "No suitable installation disk found (need non-removable disk >= 8GB)"
fi

log "Installing Alpine Linux with TPM-based disk encryption"
log "Target disk: $INSTALL_DISK"

# Resolve hostname from embedded platform config (same function used for
# install log upload path). Falls back to "trusted-platform" if unset.
PLATFORM_HOSTNAME=$(resolve_platform_hostname)
PLATFORM_HOSTNAME=$(echo "$PLATFORM_HOSTNAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9.\-]/-/g')
case "$PLATFORM_HOSTNAME" in
    ""|"-none-"|"none"|"localhost"|"alpine"|"alpinelinux"|"unknown") PLATFORM_HOSTNAME="trusted-platform" ;;
esac
log "Resolved platform hostname: $PLATFORM_HOSTNAME"

# Build installation command (using platformctl CLI binary)
# If installer config exists, use it; otherwise use command-line flags.
# When --config is provided, the config file is the single source of
# truth for hostname, root-password, and encryption password. CLI
# flags are only used to override when absolutely needed. The install
# command only applies flag overrides when the flag is explicitly
# provided (cobra Changed check), so omitting them lets the config
# file values take effect.
if [ -n "$INSTALLER_CONFIG" ]; then
    log "Using installer configuration file: $INSTALLER_CONFIG"
    sleep 1
    log "Building installation command..."
    # Config file provides hostname, root-password, encryption settings.
    # Only pass --password in debug mode as a known dev passphrase;
    # in production the config's encryption settings are authoritative.
    INSTALL_CMD="$PLATFORM_BIN install system \
        --config \"$INSTALLER_CONFIG\" \
        --os alpine \
        --disk \"$INSTALL_DISK\" \
        --automated \
        --verbose \
        --debug"
    # In debug mode, force a known LUKS passphrase for dev convenience
    if grep -q 'platform_debug=1' /proc/cmdline 2>/dev/null; then
        INSTALL_CMD="$INSTALL_CMD --password \"password\""
        log "Debug mode: using known LUKS passphrase"
    fi
    log "Installation command built successfully"
else
    # No config file — fallback to CLI flags with defaults.
    # This is the degraded/test path.
    INSTALL_CMD="$PLATFORM_BIN install system \
        --os alpine \
        --disk \"$INSTALL_DISK\" \
        --password \"password\" \
        --root-password \"password\" \
        --hostname \"$PLATFORM_HOSTNAME\" \
        --automated \
        --verbose \
        --debug"
`)

	// Add optional flags based on configuration (only when no config file is used)
	sb.WriteString(`
fi

# Add additional flags if not using config file
if [ -z "$INSTALLER_CONFIG" ]; then
`)

	if c.config.Security.FIPS {
		sb.WriteString(`    INSTALL_CMD="$INSTALL_CMD --fips"
    log "FIPS mode: enabled"
`)
	}

	if c.config.Security.Lockdown {
		sb.WriteString(`    INSTALL_CMD="$INSTALL_CMD --lockdown"
`)
		if c.config.Security.LockdownMode != "" {
			fmt.Fprintf(&sb, `    INSTALL_CMD="$INSTALL_CMD --lockdown-mode \"%s\""
    log "Kernel lockdown: enabled (mode: %s)"
`, c.config.Security.LockdownMode, c.config.Security.LockdownMode)
		} else {
			sb.WriteString(`    log "Kernel lockdown: enabled (mode: confidentiality)"
`)
		}
	}

	if c.config.Security.TPM.AutoUpgradeSeal {
		sb.WriteString(`    INSTALL_CMD="$INSTALL_CMD --tpm-auto-upgrade-seal"
    log "TPM auto-upgrade seal: enabled"
`)
	}

	sb.WriteString(`fi
`)

	// Add platformd binary if configured
	if c.config.Platform.PlatformdBinary != "" {
		sb.WriteString(`
# Add platformd binary if it exists on the ISO
PLATFORMD_PATH="/media/cdrom/platformd-bin/platformd"
if [ -f "$PLATFORMD_PATH" ]; then
    INSTALL_CMD="$INSTALL_CMD --platformd-binary \"$PLATFORMD_PATH\""
    log "Platformd binary: $PLATFORMD_PATH"
fi
`)
	}

	// Execute installation and handle result
	afterAction := c.config.Platform.AfterInstallAction
	if afterAction == "" {
		afterAction = "poweroff"
	}

	sb.WriteString(`
# Execute the installation command
log "About to execute installation command..."
sleep 1
log "Command: $INSTALL_CMD"
sleep 1
log "Starting installation now..."
set +e
eval "$INSTALL_CMD" > /tmp/install.log 2>&1
INSTALL_RESULT=$?
set -e
# Log the install output to kernel log for serial capture
while IFS= read -r line; do
    echo "[autoinstall] install: $line" > /dev/kmsg 2>/dev/null
done < /tmp/install.log
log "Installation command exited with code: $INSTALL_RESULT"
sleep 1

if [ $INSTALL_RESULT -eq 0 ]; then
    log "Installation completed successfully"

    # Persist kernel modules to installed system's /etc/modules
    # The Go installer unmounts /mnt before returning, so we re-open LUKS/LVM
    set +e
    log "Persisting kernel modules to installed system..."
    LVM_DEV="/dev/mapper/vg0-root"
    MODULES_WRITTEN=false

    if [ -n "$INSTALL_DISK" ]; then
        LUKS_PART="${INSTALL_DISK}2"
        if echo "$INSTALL_DISK" | grep -q "nvme"; then
            LUKS_PART="${INSTALL_DISK}p2"
        fi

        log "  Re-opening LUKS on $LUKS_PART..."
        echo -n "password" | cryptsetup luksOpen "$LUKS_PART" cryptroot --key-file=- 2>/dev/null
        if [ $? -eq 0 ]; then
            log "  LUKS opened"
            vgchange -ay vg0 2>/dev/null
            sleep 1
            if [ -b "$LVM_DEV" ]; then
                mount "$LVM_DEV" /mnt 2>/dev/null
                if [ -d /mnt/etc ]; then
                    log "  Rootfs mounted at /mnt"

                    # Add detected NIC modules
                    for mod in igb ixgbe e1000e i40e ice; do
                        if lsmod 2>/dev/null | grep -q "^${mod} "; then
                            if ! grep -q "^${mod}$" /mnt/etc/modules 2>/dev/null; then
                                echo "$mod" >> /mnt/etc/modules
                                log "  Added module: $mod"
                                MODULES_WRITTEN=true
                            fi
                        fi
                    done

                    if [ "$MODULES_WRITTEN" = "true" ]; then
                        log "  Modules persisted to /mnt/etc/modules"
                    else
                        log "  No additional modules needed"
                    fi

                    sync
                    umount /mnt 2>/dev/null || true
                fi
            fi
            vgchange -an vg0 2>/dev/null || true
            cryptsetup luksClose cryptroot 2>/dev/null || true
            log "  LUKS closed after module persistence"
        else
            log "  WARNING: Could not re-open LUKS for module persistence"
        fi
    fi
    set -e
`)

	if afterAction == "poweroff" {
		sb.WriteString(`    log "System will poweroff..."
    # CRITICAL: Properly unmount filesystems and sync before poweroff
    # to ensure all data (especially installer.luks on EFI) is written to disk
    log "Syncing filesystems before unmount..."
    sync

    # DEBUG: Verify LUKS header exists before unmount
    if [ -f /mnt/boot/efi/tpm2/installer.luks ]; then
        MAGIC=$(head -c 6 /mnt/boot/efi/tpm2/installer.luks | xxd -p)
        log "DEBUG: installer.luks magic bytes before unmount: $MAGIC"
        if [ "$MAGIC" = "4c554b53babe" ]; then
            log "DEBUG: LUKS header VALID before unmount"
        else
            log "DEBUG: LUKS header MISSING before unmount!"
        fi
    else
        log "DEBUG: installer.luks NOT FOUND before unmount!"
    fi

    # DEBUG: Verify main LUKS partition header (${INSTALL_DISK}2)
    if [ -b ${INSTALL_DISK}2 ]; then
        VDAMAG=$(head -c 6 ${INSTALL_DISK}2 | xxd -p)
        log "DEBUG: ${INSTALL_DISK}2 LUKS header magic bytes: $VDAMAG"
        if [ "$VDAMAG" = "4c554b53babe" ]; then
            log "DEBUG: ${INSTALL_DISK}2 LUKS header VALID!"
        else
            log "DEBUG: ${INSTALL_DISK}2 LUKS header CORRUPTED! Expected 4c554b53babe, got $VDAMAG"
        fi
    else
        log "DEBUG: ${INSTALL_DISK}2 does not exist as block device!"
    fi

    log "Unmounting EFI partition..."
    umount /mnt/boot/efi 2>/dev/null || true
    sync

    # DEBUG: Remount and verify again to ensure write went through
    mount ${INSTALL_DISK}1 /mnt/boot/efi 2>/dev/null || true
    if [ -f /mnt/boot/efi/tpm2/installer.luks ]; then
        MAGIC=$(head -c 6 /mnt/boot/efi/tpm2/installer.luks | xxd -p)
        log "DEBUG: installer.luks magic bytes after remount: $MAGIC"
        if [ "$MAGIC" = "4c554b53babe" ]; then
            log "DEBUG: LUKS header VALID after remount - data persisted!"
        else
            log "DEBUG: LUKS header MISSING after remount! Write did NOT persist!"
        fi
    fi
    umount /mnt/boot/efi 2>/dev/null || true

    log "Unmounting remaining filesystems..."
    umount /mnt/proc 2>/dev/null || true
    umount /mnt/sys 2>/dev/null || true
    umount /mnt/dev 2>/dev/null || true
    umount /mnt 2>/dev/null || true
    sync
    sleep 3

    # Upload the install.log BEFORE poweroff. The EXIT trap will not fire
    # because poweroff halts the system before the script reaches its
    # natural exit point. Calling upload_install_log_with_code explicitly
    # here with the captured $INSTALL_RESULT is the only way to guarantee
    # the postmortem makes it off the box on the success path.
    log "Uploading install.log forensic capture before poweroff..."
    upload_checkpoint pre-poweroff || true
    upload_install_log_with_code "$INSTALL_RESULT" || true

    log "Powering off..."
    poweroff
`)
	} else {
		sb.WriteString(`    log "System will reboot..."
    # CRITICAL: Properly unmount filesystems and sync before reboot
    log "Syncing and unmounting filesystems..."
    sync
    umount /mnt/boot/efi 2>/dev/null || true
    umount /mnt/proc 2>/dev/null || true
    umount /mnt/sys 2>/dev/null || true
    umount /mnt/dev 2>/dev/null || true
    umount /mnt 2>/dev/null || true
    sync
    sleep 3

    # Upload the install.log BEFORE reboot. The EXIT trap will not fire
    # because reboot halts the system before the script reaches its
    # natural exit point. See poweroff branch above for rationale.
    log "Uploading install.log forensic capture before reboot..."
    upload_checkpoint pre-reboot || true
    upload_install_log_with_code "$INSTALL_RESULT" || true

    reboot
`)
	}

	sb.WriteString(`else
    log "INSTALLATION FAILED — install.log dump follows"
    cat /tmp/install.log 2>&1 || true
    log "Uploading install.log forensic capture after install failure (exit_code=$INSTALL_RESULT)..."
    upload_checkpoint install-failed || true
    upload_install_log_with_code "$INSTALL_RESULT" || true
    error "Installation failed"
fi
`)

	return sb.String()
}

// copyObjcopyBinary copies the objcopy binary to ISO (for UKI building during installation)
func (c *Customizer) copyObjcopyBinary(ctx context.Context, binaryPath string) error {
	c.logger.Info("Copying objcopy binary", "source", binaryPath)

	// Validate binary exists
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		return fmt.Errorf("objcopy binary not found: %s", binaryPath)
	}

	// Create destination directory
	destDir := filepath.Join(c.config.Directories.ISO, "platformd-bin")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Copy binary
	destPath := filepath.Join(destDir, "objcopy")
	if err := copyFile(binaryPath, destPath); err != nil {
		return fmt.Errorf("failed to copy binary: %w", err)
	}

	// Set executable permissions
	if err := os.Chmod(destPath, 0755); err != nil {
		return fmt.Errorf("failed to set executable permissions: %w", err)
	}

	// Create llvm-objcopy symlink for compatibility
	symlinkPath := filepath.Join(destDir, "llvm-objcopy")
	os.Remove(symlinkPath) // Remove if exists
	if err := os.Symlink("objcopy", symlinkPath); err != nil {
		c.logger.Warn("Failed to create llvm-objcopy symlink", "error", err)
	}

	c.logger.Info("Objcopy binary copied successfully", "destination", destPath)
	return nil
}

// CopyDracutModule generates and copies the dracut module files to the ISO for use during installation
func (c *Customizer) CopyDracutModule(ctx context.Context) error {
	c.logger.Info("Generating dracut module files for ISO")

	// Create destination directory on ISO
	// The installer looks for /media/cdrom/dracut-platformd/90platformd
	destDir := filepath.Join(c.config.Directories.ISO, "dracut-platformd", "90platformd")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create dracut module destination directory: %w", err)
	}

	// Generate module-setup.sh
	moduleSetupPath := filepath.Join(destDir, "module-setup.sh")
	moduleSetupContent := `#!/bin/bash
# Dracut module for platformd TPM-based LUKS unlock
# This module integrates platformd into the initramfs for automatic disk decryption

check() {
    # Don't use require_binaries during chroot build - it can fail
    # The binary will be available when the module is installed
    return 0
}

depends() {
    # No crypt module needed - platform-initrd uses go-luks2 for all LUKS operations
    # This removes the cryptsetup binary dependency entirely
    return 0
}

install() {
    # Install platform-initrd binary for boot operations (CRITICAL)
    # This is the minimal binary with boot, firstboot, recovery commands
    # NOTE: platformd is the daemon-only binary, platformctl is the CLI
    # We use inst_simple instead of inst_binary because platform-initrd is a
    # statically linked Go binary with no dynamic library dependencies.
    # inst_binary uses ldd and can fail for static binaries; inst_simple just copies.
    if [ ! -e /usr/bin/platform-initrd ]; then
        derror "PLATFORMD: /usr/bin/platform-initrd not found - boot WILL fail!"
        ls -la /usr/bin/platform-initrd 2>&1 | while read line; do derror "PLATFORMD: $line"; done
        return 1
    fi
    if ! inst_simple /usr/bin/platform-initrd /usr/bin/platform-initrd; then
        derror "PLATFORMD: inst_simple failed for /usr/bin/platform-initrd"
        return 1
    fi
    # Ensure executable permissions on the copied file
    chmod +x "${initdir}/usr/bin/platform-initrd" 2>/dev/null || true
    dinfo "PLATFORMD: Installed /usr/bin/platform-initrd via inst_simple"

    # Install required system utilities individually to avoid silent failures.
    # NOTE: No cryptsetup needed - platform-initrd uses go-luks2 for all LUKS operations
    for _bin in dd cat rm mkdir mount umount findmnt grep awk sleep head tee basename cp chmod \
                modprobe lsmod blkid losetup stat dmsetup; do
        inst_multiple "$_bin" 2>/dev/null || dinfo "PLATFORMD: binary $_bin not found, skipping"
    done

    # LVM binary: try multiple paths (Alpine uses /sbin/lvm, others use /usr/sbin/lvm)
    if [ -x /sbin/lvm ]; then
        inst_binary /sbin/lvm
        dinfo "PLATFORMD: Installed /sbin/lvm"
    elif [ -x /usr/sbin/lvm ]; then
        inst_binary /usr/sbin/lvm
        dinfo "PLATFORMD: Installed /usr/sbin/lvm"
    else
        inst_multiple lvm 2>/dev/null || dwarn "PLATFORMD: lvm binary not found!"
    fi

    # Install libraries needed for device mapper and LVM
    # NOTE: No libcryptsetup needed - go-luks2 is pure Go
    inst_libdir_file "libdevmapper.so*" 2>/dev/null || true
    inst_libdir_file "liblvm2*.so*" 2>/dev/null || true
    inst_libdir_file "libdevmapper-event*.so*" 2>/dev/null || true

    # Install firstboot keyfile if it exists (for automated firstboot unlock)
    # The installer creates this keyfile on the EFI partition during installation
    # It's embedded in the initramfs for firstboot, then deleted after TPM provisioning
    if [ -f /boot/efi/tpm2/luks-firstboot.key ]; then
        inst_simple /boot/efi/tpm2/luks-firstboot.key /etc/luks-firstboot.key
        dinfo "PLATFORMD: Embedded firstboot keyfile in initramfs"
    fi

    # Embed kernel cmdline into initramfs for root device detection
    # The installer writes /etc/kernel/cmdline with all params built from config:
    #   root=, rd.luks.uuid=, rd.luks.name=, rd.lvm=1, rd.lvm.vg=, rootfstype=
    # Our hooks parse this as the single source of truth for boot configuration.
    if [ -f /etc/kernel/cmdline ]; then
        inst_simple /etc/kernel/cmdline /etc/kernel/cmdline
        dinfo "PLATFORMD: Embedded /etc/kernel/cmdline in initramfs"

        # Install as cmdline.d override so dracut's getarg returns our values
        # for ALL modules. Dracut reads /proc/cmdline first, then /etc/cmdline.d/*.conf.
        # Last occurrence wins, so our values override the (possibly wrong) UKI cmdline.
        mkdir -p "${initdir}/etc/cmdline.d"
        cp /etc/kernel/cmdline "${initdir}/etc/cmdline.d/99-platformd.conf"
        dinfo "PLATFORMD: Installed cmdline.d override for dracut getarg"
    fi

    # Install cmdline hook to set root device from embedded /etc/kernel/cmdline
    # This also sets the root/rootok shell variables for dracut's internal state
    inst_hook cmdline 99 "${moddir}/platformd-root.sh"

    # Install hook for platform-initrd LUKS unlock - priority 10 runs early in settled phase
    inst_hook initqueue/settled 10 "${moddir}/platformd-unlock.sh"

    # Install initqueue/finished hook to tell dracut root device is available
    # This prevents dracut from waiting 200+ seconds for a wrong UUID device
    inst_hook initqueue/finished 99 "${moddir}/platformd-finished.sh"

    # Install mount hook to explicitly mount root if dracut's standard handler fails
    inst_hook mount 99 "${moddir}/platformd-mount.sh"

    dinfo "PLATFORMD: Module installed successfully"
    return 0
}

installkernel() {
    # Install TPM kernel modules
    instmods tpm tpm_tis tpm_crb tpm_vtpm_proxy 2>/dev/null || true

    # Install device mapper module
    instmods dm_mod dm_crypt 2>/dev/null || true

    # Install loop device module (required for installer.luks container)
    instmods loop 2>/dev/null || true

    # Install filesystem modules for EFI partition
    instmods vfat fat nls_cp437 nls_iso8859_1 2>/dev/null || true

    # Install ext4 module for installer container filesystem
    instmods ext4 2>/dev/null || true

    # Install storage controller modules for hardware and QEMU testing
    # ahci: SATA/AHCI controller (required - CONFIG_SATA_AHCI=m in Alpine kernel)
    # nvme: NVMe storage (common on modern hardware)
    instmods ahci libahci virtio_pci virtio_blk ata_piix nvme 2>/dev/null || true
}
`
	if err := os.WriteFile(moduleSetupPath, []byte(moduleSetupContent), 0755); err != nil {
		return fmt.Errorf("failed to write module-setup.sh: %w", err)
	}
	c.logger.Debug("Generated module-setup.sh")

	// Generate platformd-unlock.sh (the main unlock hook)
	// NOTE: All LUKS operations use platformd with go-luks2 - NO cryptsetup calls!
	unlockScriptPath := filepath.Join(destDir, "platformd-unlock.sh")
	wrapperScript := `#!/bin/sh
# Platformd unlock hook for dracut
# All config values come from kernel cmdline params (built from installer config).
# Params: root=, rd.luks.uuid=, rd.luks.name=<uuid>=<name>, rd.lvm=1, rd.lvm.vg=
# Fallback: parse /etc/kernel/cmdline embedded in initramfs.

# Load dracut library for proper integration
type getarg >/dev/null 2>&1 || . /lib/dracut-lib.sh

# Helper: parse a param from the embedded /etc/kernel/cmdline
# Used as fallback when getarg fails (UKI cmdline may be wrong)
kcarg() {
    if [ -f /etc/kernel/cmdline ]; then
        _val=$(grep -o "$1=[^ ]*" /etc/kernel/cmdline | head -1)
        if [ -n "$_val" ]; then
            echo "${_val#*=}"
            return
        fi
    fi
}

# Parse config from kernel cmdline with /etc/kernel/cmdline fallback
# rd.luks.name format: <uuid>=<name>
_luks_name_param="$(getarg rd.luks.name=)"
if [ -z "$_luks_name_param" ]; then
    _luks_name_param="$(kcarg rd.luks.name)"
fi

LUKS_UUID=""
LUKS_NAME=""
if [ -n "$_luks_name_param" ]; then
    LUKS_UUID="${_luks_name_param%%=*}"
    LUKS_NAME="${_luks_name_param#*=}"
fi

# Fallback UUID from rd.luks.uuid
if [ -z "$LUKS_UUID" ]; then
    LUKS_UUID="$(getarg rd.luks.uuid=)"
    [ -z "$LUKS_UUID" ] && LUKS_UUID="$(kcarg rd.luks.uuid)"
    LUKS_UUID="${LUKS_UUID#luks-}"
fi

# LVM volume group from rd.lvm.vg
LVM_VG="$(getarg rd.lvm.vg=)"
[ -z "$LVM_VG" ] && LVM_VG="$(kcarg rd.lvm.vg)"

# Root device from root=
ROOT_DEV="$(getarg root=)"
[ -z "$ROOT_DEV" ] && ROOT_DEV="$(kcarg root)"

# Check for completion marker to prevent re-execution in initqueue loop
if [ -f /tmp/platformd-unlock-done ]; then
    return 0
fi

# Check for failure marker to prevent infinite loops
if [ -f /tmp/platformd-unlock-failed ]; then
    return 0
fi

# Check if LUKS device is already open
if [ -n "$LUKS_NAME" ] && [ -e "/dev/mapper/$LUKS_NAME" ]; then
    info "PLATFORMD: LUKS already unlocked ($LUKS_NAME)"
    # Activate LVM if configured
    if [ -n "$LVM_VG" ]; then
        if [ -z "$ROOT_DEV" ] || [ ! -e "$ROOT_DEV" ]; then
            info "PLATFORMD: Activating LVM (VG=$LVM_VG)..."
            /sbin/lvm vgscan 2>&1 || warn "PLATFORMD: vgscan failed"
            /sbin/lvm vgchange -ay "$LVM_VG" 2>&1 || warn "PLATFORMD: vgchange failed"
        fi
    fi
    # Create /dev/root symlink so dracut can find root device
    if [ -n "$ROOT_DEV" ] && [ -e "$ROOT_DEV" ]; then
        ln -sf "$ROOT_DEV" /dev/root 2>/dev/null || true
        info "PLATFORMD: Root device ready: $ROOT_DEV"
    else
        warn "PLATFORMD: Root device $ROOT_DEV not found after activation"
    fi
    touch /tmp/platformd-unlock-done
    return 0
fi

info "PLATFORMD: Starting unlock process..."
info "PLATFORMD: rd.luks.name: UUID=$LUKS_UUID NAME=$LUKS_NAME"

# Find LUKS device by UUID
LUKS_DEV=""
if [ -n "$LUKS_UUID" ]; then
    LUKS_DEV="/dev/disk/by-uuid/$LUKS_UUID"
    if [ ! -b "$LUKS_DEV" ]; then
        LUKS_DEV="/dev/disk/by-uuid/luks-$LUKS_UUID"
    fi
fi

# Fallback: scan common partitions for LUKS magic bytes
if [ -z "$LUKS_DEV" ] || [ ! -b "$LUKS_DEV" ]; then
    info "PLATFORMD: Scanning for LUKS device..."
    for dev in ${INSTALL_DISK}2 /dev/sda2 /dev/nvme0n1p2 /dev/vda3 /dev/sda3; do
        if [ -b "$dev" ]; then
            MAGIC=$(dd if="$dev" bs=6 count=1 2>/dev/null | od -A n -t x1 | tr -d ' ' | head -c 12)
            if [ "$MAGIC" = "4c554b53babe" ]; then
                LUKS_DEV="$dev"
                info "PLATFORMD: Found LUKS device: $LUKS_DEV"
                break
            fi
        fi
    done
fi

if [ -z "$LUKS_DEV" ] || [ ! -b "$LUKS_DEV" ]; then
    warn "PLATFORMD: No LUKS device found, skipping unlock"
    touch /tmp/platformd-unlock-failed
    return 0
fi

info "PLATFORMD: Target device: $LUKS_DEV -> $LUKS_NAME"

# Find EFI partition by scanning for FAT32/EFI partitions
# Can't rely on a specific device path since BMC virtual media may shift disk numbering
EFI_PART=""
# First try by LUKS device: if LUKS is on sdX2, EFI is on sdX1
LUKS_DISK=$(echo "$LUKS_DEV" | sed 's/[0-9]*$//' | sed 's/p$//')
if [ -n "$LUKS_DISK" ] && [ -b "${LUKS_DISK}1" ]; then
    EFI_PART="${LUKS_DISK}1"
elif [ -n "$LUKS_DISK" ] && [ -b "${LUKS_DISK}p1" ]; then
    EFI_PART="${LUKS_DISK}p1"
fi
# Fallback: scan all partitions for EFI system partition
if [ -z "$EFI_PART" ]; then
    for part in /dev/sda1 /dev/sdb1 /dev/sdc1 /dev/nvme0n1p1 /dev/vda1; do
        if [ -b "$part" ]; then
            # Check if it's a FAT/EFI partition by trying to mount it
            mkdir -p /tmp/efi-probe
            if mount -t vfat "$part" /tmp/efi-probe 2>/dev/null; then
                if [ -d /tmp/efi-probe/EFI ] || [ -f /tmp/efi-probe/tpm2/installer.luks ]; then
                    EFI_PART="$part"
                    umount /tmp/efi-probe 2>/dev/null
                    break
                fi
                umount /tmp/efi-probe 2>/dev/null
            fi
        fi
    done
fi

UNLOCK_SUCCESS=0
BOOT_MODE=""

# Mount EFI partition and detect boot mode
if [ -n "$EFI_PART" ]; then
    info "PLATFORMD: Checking boot mode on $EFI_PART..."
    mkdir -p /boot/efi
    if mount -t vfat "$EFI_PART" /boot/efi 2>/dev/null; then
        if [ -f /boot/efi/tpm2/installer.luks ]; then
            BOOT_MODE="firstboot"
            info "PLATFORMD: Detected FIRSTBOOT mode (installer.luks exists)"
        elif [ -f /boot/efi/tpm2/pcr-banks ]; then
            BOOT_MODE="boot"
            info "PLATFORMD: Detected BOOT mode (pcr-banks exists)"
        else
            warn "PLATFORMD: No installer.luks or pcr-banks found - cannot determine boot mode"
        fi
    else
        warn "PLATFORMD: Failed to mount EFI partition"
    fi
fi

# For FIRSTBOOT mode, bring up networking for ACME enrollment
# Network config is stored in /boot/efi/tpm2/network.conf (written by installer)
if [ "$BOOT_MODE" = "firstboot" ]; then
    info "PLATFORMD: Bringing up network for ACME enrollment..."

    # Load all common NIC drivers (virtual and bare metal)
    for drv in virtio_net e1000 e1000e igb ixgbe i40e ice; do
        modprobe "$drv" 2>/dev/null || true
    done
    modprobe e1000e 2>/dev/null || true

    NETWORK_CONF="/boot/efi/tpm2/network.conf"
    NET_IFACE=""
    NET_TYPE=""
    NET_IP=""
    NET_MASK=""
    NET_GW=""

    if [ -f "$NETWORK_CONF" ]; then
        info "PLATFORMD: Reading network config from $NETWORK_CONF"
        . "$NETWORK_CONF"
        NET_IFACE="${INTERFACE:-eth0}"
        NET_TYPE="${TYPE:-dhcp}"
        NET_IP="${IPV4_ADDRESS:-}"
        NET_MASK="${IPV4_NETMASK:-255.255.255.0}"
        NET_GW="${IPV4_GATEWAY:-}"
        NET_DNS="${DNS:-8.8.8.8}"
        NET_HOSTNAME="${HOSTNAME:-}"
        info "PLATFORMD: Network config: iface=$NET_IFACE type=$NET_TYPE ip=$NET_IP gw=$NET_GW dns=$NET_DNS hostname=$NET_HOSTNAME"

        if [ -n "$NET_HOSTNAME" ]; then
            info "PLATFORMD: Setting hostname to $NET_HOSTNAME"
            echo "$NET_HOSTNAME" > /etc/hostname
            hostname "$NET_HOSTNAME" 2>/dev/null || true
        fi
    else
        info "PLATFORMD: No network.conf found, will try DHCP"
        NET_IFACE="eth0"
        NET_TYPE="dhcp"
        NET_DNS="8.8.8.8"
    fi

    for i in 1 2 3 4 5; do
        if ip link show "$NET_IFACE" >/dev/null 2>&1; then
            break
        fi
        info "PLATFORMD: Waiting for network interface $NET_IFACE... ($i/5)"
        sleep 1
    done

    if ip link show "$NET_IFACE" >/dev/null 2>&1; then
        info "PLATFORMD: Configuring network interface $NET_IFACE..."
        ip link set "$NET_IFACE" up

        if [ "$NET_TYPE" = "static" ] && [ -n "$NET_IP" ] && [ -n "$NET_GW" ]; then
            case "$NET_MASK" in
                255.255.255.0)   PREFIX="24" ;;
                255.255.255.128) PREFIX="25" ;;
                255.255.255.192) PREFIX="26" ;;
                255.255.255.224) PREFIX="27" ;;
                255.255.255.240) PREFIX="28" ;;
                255.255.255.248) PREFIX="29" ;;
                255.255.255.252) PREFIX="30" ;;
                255.255.254.0)   PREFIX="23" ;;
                255.255.252.0)   PREFIX="22" ;;
                255.255.248.0)   PREFIX="21" ;;
                255.255.240.0)   PREFIX="20" ;;
                255.255.0.0)     PREFIX="16" ;;
                255.0.0.0)       PREFIX="8" ;;
                *)               PREFIX="24" ;;
            esac
            info "PLATFORMD: Configuring static IP: $NET_IP/$PREFIX gateway: $NET_GW"
            ip addr add "$NET_IP/$PREFIX" dev "$NET_IFACE" 2>/dev/null || true
            ip route add default via "$NET_GW" 2>/dev/null || true

            info "PLATFORMD: Configuring DNS: $NET_DNS"
            : > /etc/resolv.conf
            for dns_server in $NET_DNS; do
                echo "nameserver $dns_server" >> /etc/resolv.conf
            done
        else
            info "PLATFORMD: Configuring DHCP on $NET_IFACE..."
            udhcpc -i "$NET_IFACE" -n -q -t 5 2>/dev/null || true
            if [ ! -s /etc/resolv.conf ]; then
                info "PLATFORMD: DHCP did not configure DNS, using fallback"
                echo "nameserver 8.8.8.8" > /etc/resolv.conf
            fi
        fi

        ip addr show "$NET_IFACE" 2>/dev/null | grep inet || warn "PLATFORMD: No IP address on $NET_IFACE"
        info "PLATFORMD: DNS configuration:"
        cat /etc/resolv.conf 2>/dev/null || warn "PLATFORMD: No resolv.conf"

        if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
            info "PLATFORMD: Network connectivity confirmed"
        else
            warn "PLATFORMD: No network connectivity - ACME enrollment may fail"
        fi
    else
        warn "PLATFORMD: Network interface $NET_IFACE not found"
    fi
fi

modprobe loop 2>/dev/null || true

info "PLATFORMD: Loading TPM kernel modules..."
modprobe tpm 2>/dev/null || true
modprobe tpm_tis 2>/dev/null || true
modprobe tpm_crb 2>/dev/null || true
modprobe tpm_vtpm_proxy 2>/dev/null || true

sleep 1

if [ -c /dev/tpm0 ]; then
    info "PLATFORMD: Triggering TPM driver initialization..."
    dd if=/dev/tpm0 bs=1 count=1 2>/dev/null || true
fi

if ! mountpoint -q /sys/kernel/security 2>/dev/null; then
    info "PLATFORMD: Mounting securityfs for TPM event log..."
    mkdir -p /sys/kernel/security 2>/dev/null || true
    mount -t securityfs securityfs /sys/kernel/security 2>/dev/null || true
fi

TPM_EVENTLOG="/sys/kernel/security/tpm0/binary_bios_measurements"
EVENTLOG_SIZE=0
for i in 1 2 3 4 5 6 7 8 9 10; do
    if [ -f "$TPM_EVENTLOG" ]; then
        EVENTLOG_SIZE=$(stat -c%s "$TPM_EVENTLOG" 2>/dev/null || echo "0")
        if [ "$EVENTLOG_SIZE" -gt 0 ]; then
            info "PLATFORMD: TPM event log available: $TPM_EVENTLOG ($EVENTLOG_SIZE bytes)"
            break
        fi
        info "PLATFORMD: TPM event log file exists but empty, waiting... ($i/10)"
    else
        info "PLATFORMD: Waiting for TPM event log file... ($i/10)"
    fi
    cat /dev/tpm0 >/dev/null 2>&1 || true
    sleep 1
done
if [ ! -f "$TPM_EVENTLOG" ] || [ "$EVENTLOG_SIZE" -eq 0 ]; then
    warn "PLATFORMD: TPM event log not available or empty - attestation data will be incomplete"
fi

# DIAGNOSTIC: Show what's actually in /usr/bin to debug platform-initrd availability
warn "PLATFORMD: DIAGNOSTIC - listing /usr/bin contents:"
ls -la /usr/bin/ 2>&1 | head -20 | while read line; do warn "PLATFORMD: $line"; done
warn "PLATFORMD: DIAGNOSTIC - searching for platform-initrd anywhere in initramfs:"
find / -name "platform-initrd*" 2>/dev/null | while read line; do warn "PLATFORMD: FOUND: $line"; done
warn "PLATFORMD: DIAGNOSTIC - stat /usr/bin/platform-initrd:"
stat /usr/bin/platform-initrd 2>&1 | while read line; do warn "PLATFORMD: $line"; done

if [ -x /usr/bin/platform-initrd ]; then
    info "PLATFORMD: Running platform-initrd boot (mode: $BOOT_MODE)..."
    info "PLATFORMD: invoking platform-initrd boot --device=$LUKS_DEV --name=$LUKS_NAME"
    # Capture all output to a tmpfs file so we can replay it through dracut's
    # info/warn helpers regardless of where /dev/console actually points. This
    # gives us reliable visibility on every BMC SOL channel, every kernel
    # console redirect setting, and every dracut version. The cost is one
    # tmpfs file (cleaned up on switch_root).
    : > /run/platformd-initrd.log
    /usr/bin/platform-initrd boot --device "$LUKS_DEV" --name "$LUKS_NAME" --verbose < /dev/null > /run/platformd-initrd.log 2>&1
    rc=$?
    info "PLATFORMD: platform-initrd boot exited rc=$rc — log follows:"
    if [ -s /run/platformd-initrd.log ]; then
        # Replay through dracut's info helper so every line lands on the
        # console regardless of redirection. Truncate per-line to keep the
        # log readable on slow SOL channels.
        while IFS= read -r line; do
            info "PLATFORMD-LOG: $line"
        done < /run/platformd-initrd.log
    else
        warn "PLATFORMD-LOG: (empty — binary produced no output)"
    fi
    if [ $rc -eq 0 ]; then
        info "PLATFORMD: Boot successful"
        UNLOCK_SUCCESS=1
    else
        warn "PLATFORMD: Boot failed (rc=$rc)"
    fi
else
    warn "PLATFORMD: platform-initrd not found at /usr/bin/platform-initrd"
fi

umount /boot/efi 2>/dev/null || true

# If unlock succeeded, activate LVM and create root device symlink
if [ $UNLOCK_SUCCESS -eq 1 ]; then
    if [ -e "/dev/mapper/$LUKS_NAME" ]; then
        # Activate LVM if VG specified in kernel cmdline
        if [ -n "$LVM_VG" ]; then
            info "PLATFORMD: Activating LVM (VG=$LVM_VG)..."
            /sbin/lvm vgscan 2>&1 || warn "PLATFORMD: vgscan failed"
            /sbin/lvm vgchange -ay "$LVM_VG" 2>&1 || warn "PLATFORMD: vgchange failed"
        fi

        # Create root symlink from kernel cmdline root= param
        if [ -n "$ROOT_DEV" ] && [ -e "$ROOT_DEV" ]; then
            info "PLATFORMD: Root device ready: $ROOT_DEV"
            ln -sf "$ROOT_DEV" /dev/root 2>/dev/null || true
        else
            warn "PLATFORMD: Root device $ROOT_DEV not found after activation"
        fi
    fi
    touch /tmp/platformd-unlock-done
else
    warn "PLATFORMD: Unlock failed, falling back to manual entry"
    touch /tmp/platformd-unlock-failed
fi

return 0
`
	if err := os.WriteFile(unlockScriptPath, []byte(wrapperScript), 0755); err != nil {
		return fmt.Errorf("failed to write platformd-unlock.sh: %w", err)
	}
	c.logger.Debug("Generated platformd-unlock.sh")

	// Generate platformd-root.sh (cmdline hook to set root device)
	// This reads root= from /etc/kernel/cmdline embedded in the initramfs,
	// overriding any incorrect cmdline that dracut may have embedded in the UKI.
	rootScriptPath := filepath.Join(destDir, "platformd-root.sh")
	rootScript := `#!/bin/sh
# Platformd root detection hook for dracut (cmdline phase)
# Reads root= and rootfstype= from the embedded /etc/kernel/cmdline.
# The installer builds this cmdline from config (root device, fstype, LUKS, LVM params).
# This overrides any incorrect cmdline that dracut may embed in the UKI .cmdline section.

type getarg >/dev/null 2>&1 || . /lib/dracut-lib.sh

# Parse root device and filesystem type from embedded kernel cmdline
if [ -f /etc/kernel/cmdline ]; then
    _root=$(grep -o 'root=[^ ]*' /etc/kernel/cmdline | head -1)
    if [ -n "$_root" ]; then
        root="${_root#root=}"
        rootok=1
        info "PLATFORMD: Root device from /etc/kernel/cmdline: $root"
    fi
    _fstype=$(grep -o 'rootfstype=[^ ]*' /etc/kernel/cmdline | head -1)
    if [ -n "$_fstype" ]; then
        rootfstype="${_fstype#rootfstype=}"
        info "PLATFORMD: Root fstype: $rootfstype"
    fi
fi
`
	if err := os.WriteFile(rootScriptPath, []byte(rootScript), 0755); err != nil {
		return fmt.Errorf("failed to write platformd-root.sh: %w", err)
	}
	c.logger.Debug("Generated platformd-root.sh")

	// Generate platformd-finished.sh (initqueue/finished hook)
	// This tells dracut the root device is ready so it stops waiting.
	// dracut's initqueue loop runs finished hooks to check if it should proceed.
	// Return 0 = root is ready, return 1 = keep waiting.
	finishedScriptPath := filepath.Join(destDir, "platformd-finished.sh")
	finishedScript := `#!/bin/sh
# Tell dracut root device is available (initqueue/finished hook)
# Returns 0 when root is ready, 1 to keep waiting.

# Check if the root device (set by cmdline hook from /etc/kernel/cmdline) exists
if [ -n "$root" ] && [ -e "$root" ]; then
    return 0
fi

# Check /dev/root symlink (created by unlock hook after LVM activation)
if [ -e /dev/root ]; then
    return 0
fi

return 1
`
	if err := os.WriteFile(finishedScriptPath, []byte(finishedScript), 0755); err != nil {
		return fmt.Errorf("failed to write platformd-finished.sh: %w", err)
	}
	c.logger.Debug("Generated platformd-finished.sh")

	// Generate platformd-mount.sh (mount hook to mount root filesystem)
	// This is a fallback in case dracut's standard mount handler fails.
	mountScriptPath := filepath.Join(destDir, "platformd-mount.sh")
	mountScript := `#!/bin/sh
# Platformd mount hook for dracut
# Mounts root filesystem if dracut's standard handler hasn't done it yet.
# All values come from dracut variables (set by cmdline hooks parsing /etc/kernel/cmdline).

type getarg >/dev/null 2>&1 || . /lib/dracut-lib.sh

# Skip if already mounted
if mountpoint -q "$NEWROOT" 2>/dev/null; then
    return 0
fi

_root="$root"
_fstype="${rootfstype:-ext4}"

# Try /dev/root symlink if root variable is empty
if [ -z "$_root" ] && [ -e /dev/root ]; then
    _root="/dev/root"
fi

if [ -z "$_root" ]; then
    warn "PLATFORMD: No root device set, cannot mount"
    return 1
fi

if [ ! -e "$_root" ]; then
    info "PLATFORMD: Waiting for root device $_root..."
    udevadm settle 2>/dev/null || true
fi

if [ -e "$_root" ]; then
    info "PLATFORMD: Mounting root filesystem $_root (type=$_fstype) at $NEWROOT"
    mount -t "$_fstype" -o ro "$_root" "$NEWROOT"
    if [ $? -eq 0 ]; then
        info "PLATFORMD: Root filesystem mounted successfully"
    else
        warn "PLATFORMD: Failed to mount root filesystem"
        return 1
    fi
else
    warn "PLATFORMD: Root device $_root does not exist"
    return 1
fi
return 0
`
	if err := os.WriteFile(mountScriptPath, []byte(mountScript), 0755); err != nil {
		return fmt.Errorf("failed to write platformd-mount.sh: %w", err)
	}
	c.logger.Debug("Generated platformd-mount.sh")

	c.logger.Info("Dracut module generated successfully", "destination", destDir)
	return nil
}

// CopyWebUI copies the WebUI (public_html) directory or tarball to the ISO
// The WebUI can be provided as a directory path or as a .tar.gz file
func (c *Customizer) CopyWebUI(ctx context.Context, webUIPath string) error {
	c.logger.Info("Copying WebUI to ISO", "source", webUIPath)

	// Validate path exists
	info, err := os.Stat(webUIPath)
	if err != nil {
		return fmt.Errorf("WebUI path not found: %w", err)
	}

	if info.IsDir() {
		// Copy directory contents to webui/ directory on ISO
		destDir := filepath.Join(c.config.Directories.ISO, "webui")
		if err := os.MkdirAll(destDir, 0755); err != nil {
			return fmt.Errorf("failed to create webui directory: %w", err)
		}

		c.logger.Debug("Copying WebUI directory", "source", webUIPath, "destination", destDir)

		// Use cp -a to preserve permissions and structure
		cpCmd := exec.CommandContext(ctx, "cp", "-a", webUIPath+"/.", destDir)
		if output, err := cpCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to copy WebUI directory: %w\nOutput: %s", err, string(output))
		}
	} else if strings.HasSuffix(webUIPath, ".tar.gz") || strings.HasSuffix(webUIPath, ".tgz") {
		// Copy tarball directly to ISO (no directory created - installer will extract from tarball)
		destFile := filepath.Join(c.config.Directories.ISO, "webui.tar.gz")
		if err := copyFile(webUIPath, destFile); err != nil {
			return fmt.Errorf("failed to copy WebUI tarball: %w", err)
		}
		c.logger.Debug("Copied WebUI tarball", "destination", destFile)
	} else {
		return fmt.Errorf("WebUI path must be a directory or .tar.gz file: %s", webUIPath)
	}

	// Log success
	if info.IsDir() {
		c.logger.Info("WebUI directory copied successfully",
			"destination", filepath.Join(c.config.Directories.ISO, "webui"))
	} else {
		checksum, err := calculateSHA256(filepath.Join(c.config.Directories.ISO, "webui.tar.gz"))
		if err != nil {
			c.logger.Warn("Failed to calculate WebUI checksum", "error", err)
		} else {
			c.logger.Info("WebUI tarball copied successfully",
				"sha256", checksum)
		}
	}

	return nil
}

// cleanup removes temporary files created during customization
func (c *Customizer) cleanup() error {
	// Remove initramfs temp directory
	tmpDir := filepath.Join(c.config.Directories.Work, "initramfs-tmp")
	if err := os.RemoveAll(tmpDir); err != nil {
		return fmt.Errorf("failed to remove initramfs temp dir: %w", err)
	}

	// Remove verify directory
	verifyDir := filepath.Join(c.config.Directories.Work, "verify-initramfs")
	if err := os.RemoveAll(verifyDir); err != nil {
		return fmt.Errorf("failed to remove verify dir: %w", err)
	}

	return nil
}

// Helper utility functions

// extractInitramfs extracts initramfs to the specified directory
func extractInitramfs(initramfsPath, outputDir string) error {
	// Detect compression type
	fileCmd := exec.Command("file", initramfsPath)
	output, err := fileCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to detect file type: %w", err)
	}

	fileType := string(output)

	// Change to output directory for extraction
	oldDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}
	defer os.Chdir(oldDir)

	if err := os.Chdir(outputDir); err != nil {
		return fmt.Errorf("failed to change to output directory: %w", err)
	}

	var decompressCmd *exec.Cmd

	if strings.Contains(fileType, "gzip") {
		decompressCmd = exec.Command("gunzip", "-c", initramfsPath)
	} else if strings.Contains(fileType, "XZ") || strings.Contains(fileType, "xz") {
		decompressCmd = exec.Command("xz", "-dc", initramfsPath)
	} else if strings.Contains(fileType, "Zstandard") || strings.Contains(fileType, "zstd") {
		decompressCmd = exec.Command("zstd", "-dc", initramfsPath)
	} else {
		// Try as uncompressed cpio
		cpioCmd := exec.Command("cpio", "-idm")
		cpioCmd.Stdin, err = os.Open(initramfsPath)
		if err != nil {
			return fmt.Errorf("failed to open initramfs: %w", err)
		}
		if err := cpioCmd.Run(); err != nil {
			return fmt.Errorf("failed to extract initramfs: %w", err)
		}
		return nil
	}

	// Pipe decompressor to cpio
	cpioCmd := exec.Command("cpio", "-idm")
	cpioCmd.Stdin, err = decompressCmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create pipe: %w", err)
	}

	if err := cpioCmd.Start(); err != nil {
		return fmt.Errorf("failed to start cpio: %w", err)
	}

	if err := decompressCmd.Start(); err != nil {
		return fmt.Errorf("failed to start decompressor: %w", err)
	}

	if err := cpioCmd.Wait(); err != nil {
		return fmt.Errorf("cpio extraction failed: %w", err)
	}

	if err := decompressCmd.Wait(); err != nil {
		return fmt.Errorf("decompression failed: %w", err)
	}

	return nil
}

// repackInitramfs repacks the modified initramfs
func repackInitramfs(initramfsDir, outputPath string) error {
	// Change to initramfs directory
	oldDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}
	defer os.Chdir(oldDir)

	if err := os.Chdir(initramfsDir); err != nil {
		return fmt.Errorf("failed to change to initramfs directory: %w", err)
	}

	// Create temporary file for new initramfs
	tmpFile := outputPath + ".new"

	// Create cpio archive and compress with zstd
	findCmd := exec.Command("find", ".")
	cpioCmd := exec.Command("cpio", "-o", "-H", "newc")
	zstdCmd := exec.Command("zstd", "-19", "-T0")

	// Setup pipes
	cpioCmd.Stdin, err = findCmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create find->cpio pipe: %w", err)
	}

	zstdCmd.Stdin, err = cpioCmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create cpio->zstd pipe: %w", err)
	}

	// Create output file
	outFile, err := os.Create(tmpFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	zstdCmd.Stdout = outFile

	// Start commands in order
	if err := zstdCmd.Start(); err != nil {
		return fmt.Errorf("failed to start zstd: %w", err)
	}

	if err := cpioCmd.Start(); err != nil {
		return fmt.Errorf("failed to start cpio: %w", err)
	}

	if err := findCmd.Start(); err != nil {
		return fmt.Errorf("failed to start find: %w", err)
	}

	// Wait for completion
	if err := findCmd.Wait(); err != nil {
		return fmt.Errorf("find failed: %w", err)
	}

	if err := cpioCmd.Wait(); err != nil {
		return fmt.Errorf("cpio failed: %w", err)
	}

	if err := zstdCmd.Wait(); err != nil {
		return fmt.Errorf("zstd failed: %w", err)
	}

	// Replace original with new file
	if err := os.Rename(tmpFile, outputPath); err != nil {
		return fmt.Errorf("failed to replace initramfs: %w", err)
	}

	return nil
}

// validateBinary validates that the file is a valid ELF 64-bit binary
func validateBinary(path string) error {
	// Check file exists
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("binary not found: %w", err)
	}

	// Check it's a regular file
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular file: %s", path)
	}

	// Open and parse as ELF
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open binary: %w", err)
	}
	defer file.Close()

	elfFile, err := elf.Open(path)
	if err != nil {
		return fmt.Errorf("not a valid ELF binary: %w", err)
	}
	defer elfFile.Close()

	// Check it's 64-bit
	if elfFile.Class != elf.ELFCLASS64 {
		return fmt.Errorf("binary is not 64-bit (ELF class: %v)", elfFile.Class)
	}

	// Check architecture
	if elfFile.Machine != elf.EM_X86_64 {
		return fmt.Errorf("binary is not x86_64 (machine type: %v)", elfFile.Machine)
	}

	return nil
}

// GenerateInstallConfig generates installation configuration from ISO build config
// and writes it to the overlay directory for embedding in the initrd.
func (c *Customizer) GenerateInstallConfig() error {
	// In dynamic config mode, skip generating install config - the device will
	// fetch its configuration from the server at boot time.
	if c.config.Platform.ConfigServerURL != "" && c.config.Platform.ConfigFile == "" {
		c.logger.Info("Dynamic config mode: skipping install config generation",
			"server", c.config.Platform.ConfigServerURL)
		return nil
	}

	c.logger.Info("Generating installation configuration from ISO build config")

	// Create installer.Config from PlatformISOConfig
	installConfig, err := c.buildInstallerConfig()
	if err != nil {
		return fmt.Errorf("failed to build installer config: %w", err)
	}

	// Generate initrd.Config for boot-time use
	initrdConfig := c.buildInitrdConfig()

	// Create directory structure in overlay
	configDir := filepath.Join(c.overlayDir, "etc", "platformd")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Write installer configuration
	installConfigPath := filepath.Join(configDir, "install.yaml")
	if err := c.writeInstallerConfig(installConfig, installConfigPath); err != nil {
		return fmt.Errorf("failed to write installer config: %w", err)
	}

	// Write initrd configuration
	initrdConfigPath := filepath.Join(configDir, "initrd.yaml")
	if err := c.writeInitrdConfig(initrdConfig, initrdConfigPath); err != nil {
		return fmt.Errorf("failed to write initrd config: %w", err)
	}

	c.logger.Info("Installation configuration generated successfully",
		"installer_config", installConfigPath,
		"initrd_config", initrdConfigPath)

	return nil
}

// buildInstallerConfig converts PlatformISOConfig to installer.Config
func (c *Customizer) buildInstallerConfig() (*installer.Config, error) {
	config := &installer.Config{
		Debug: c.config.Build.Debug,
	}

	// Build disk configuration
	config.Disk = &installer.DiskConfig{
		Device:           "/dev/sda", // Default device, can be overridden at install time
		PartitionTable:   installer.PartitionTableGPT,
		EFIPartitionSize: 538, // Standard EFI partition size
	}

	// Set root filesystem type
	switch c.config.RootFS.Type {
	case "lvm":
		config.Disk.RootFilesystem = installer.FilesystemLVM
		config.Disk.LVMVolumeGroup = "vg0"
		config.Disk.LVMLogicalVolume = "root"
	case "ext4":
		config.Disk.RootFilesystem = installer.FilesystemExt4
	default:
		return nil, fmt.Errorf("unsupported root filesystem type: %s", c.config.RootFS.Type)
	}

	// Configure LUKS encryption if enabled
	if c.config.LUKS.Enabled {
		// Use PBKDF2 for FIPS mode (Argon2id is not FIPS-approved)
		pbkdf := "argon2id"
		if c.config.Security.FIPS {
			pbkdf = "pbkdf2"
		}
		config.Disk.Encryption = &installer.EncryptionConfig{
			Version:    "luks2",
			Cipher:     "aes-xts-plain64",
			KeySize:    512,
			Hash:       "sha256",
			PBKDF:      pbkdf,
			MappedName: "cryptroot",
			// Password will be set interactively during installation
			// or can be provided via kernel command line parameter
		}
	}

	// Build OS configuration. The hostname is sourced from the merged
	// platformd config file (which honors --overrides) instead of
	// being hardcoded — see readOSHostnameFromConfig. Falls back to
	// the historical "trusted-platform" default only when no config
	// file is supplied or the config doesn't set os.hostname. This
	// is the single source of truth that feeds:
	//
	//   - installer.Config.OS.Hostname → /etc/hostname on the installed
	//     system
	//   - autoinstall.sh resolve_platform_hostname → install-log upload
	//     path /installs/{hostname}/install.log
	//   - orchestrator bootstrap run → install-log polling URL
	//
	// One hostname, one place, no parallel cmdline plumbing.
	hostname := readOSHostnameFromConfig(c.config.Platform.ConfigFile)
	if hostname == "" {
		hostname = "trusted-platform"
	}
	config.OS = &installer.OSConfig{
		OS:                 installer.OSAlpine,
		Version:            c.config.Alpine.Version,
		Architecture:       "x86_64",
		Hostname:           hostname,
		Mirror:             c.config.Alpine.Mirror,
		FilesystemType:     config.Disk.RootFilesystem,
		FIPS:               c.config.Security.FIPS,
		Lockdown:           c.config.Security.Lockdown,
		LockdownMode:       c.config.Security.LockdownMode,
		TPMAutoUpgradeSeal: c.config.Security.TPM.AutoUpgradeSeal,
		// PlatformdBinary intentionally empty - installer finds binary on ISO at /media/cdrom/platformd-bin/platformd
		EnableFIDO2: c.config.Security.EnableFIDO2,
	}

	// Build UKI configuration (if platformd binary is available)
	if c.config.Platform.PlatformdBinary != "" {
		config.UKI = &installer.UKIConfig{
			Cmdline: c.buildKernelCmdline(),
		}
	}

	// Configure Secure Boot if enabled
	if c.config.Security.SecureBoot {
		// Secure Boot keys will be available on the ISO in /secure-boot-keys
		// The installer will look for them at runtime
		config.SecureBoot = &installer.SecureBootConfig{
			KeyPath:  "/tmp/secureboot-keys/DB.key",
			CertPath: "/tmp/secureboot-keys/DB.crt",
		}
	}

	// Configure TPM sealing
	config.EnableTPMSealing = c.config.Security.TPM.AutoUnseal
	if config.EnableTPMSealing {
		// Parse PCR selection from string (e.g., "0,7,9" -> []uint{0, 7, 9})
		pcrs, err := parsePCRSelection(c.config.Security.TPM.SealPCR)
		if err != nil {
			c.logger.Warn("Invalid PCR selection, using defaults", "error", err)
			pcrs = []uint{0, 7, 9}
		}
		config.PCRs = pcrs
	}

	// Enable FIDO2 enrollment if FIDO2 support is enabled and LUKS is active
	if c.config.Security.EnableFIDO2 && c.config.LUKS.Enabled {
		config.EnableFIDO2Enrollment = true
	}

	return config, nil
}

// buildInitrdConfig generates initrd configuration for boot-time use
func (c *Customizer) buildInitrdConfig() *initrd.Config {
	config := initrd.DefaultConfig()

	// Set mode based on ISO configuration
	config.Mode = initrd.ModeInstall

	// Configure PCR banks and selection
	config.PCRBanks = []string{"sha256"}

	// Parse PCR selection for sealing
	if c.config.Security.TPM.SealPCR != "" {
		pcrs, err := parsePCRSelection(c.config.Security.TPM.SealPCR)
		if err != nil {
			c.logger.Warn("Invalid PCR selection, using defaults", "error", err)
		} else {
			config.PCRSelection = pcrs
		}
	}

	// Configure upgrade PCRs (typically a subset of PCRSelection)
	// Usually PCRs 0, 1, 2, 3 are used for upgrade strategy
	config.UpgradePCRSelection = []uint{0, 1, 2, 3}

	// Configure unlock methods based on LUKS settings
	config.FallbackMethods = []storageluks.UnlockMethod{}

	if c.config.LUKS.Enabled {
		if c.config.Security.TPM.AutoUnseal {
			// Add TPM unlock methods
			config.FallbackMethods = append(config.FallbackMethods,
				storageluks.UnlockTPMPCR,
				storageluks.UnlockTPMUpgrade,
			)
		}

		if !c.config.LUKS.TPMOnly {
			// Add password fallback
			config.FallbackMethods = append(config.FallbackMethods,
				storageluks.UnlockPassword,
			)
		}
	}

	// Set reasonable defaults
	config.UnlockTimeout = 30
	config.RetryCount = 3
	config.EnableAuditLog = true
	config.AuditLogPath = "/var/log/initrd-unlock.log"

	// Set FIPS mode (affects PBKDF algorithm selection - PBKDF2 vs Argon2id)
	config.FIPS = c.config.Security.FIPS

	return config
}

// buildKernelCmdline builds kernel command line parameters from config
func (c *Customizer) buildKernelCmdline() string {
	var parts []string

	// Root device will be set during installation
	parts = append(parts, "root=/dev/mapper/cryptroot")

	// LUKS configuration
	if c.config.LUKS.Enabled {
		parts = append(parts, "rd.luks.name=cryptroot")
	}

	// LVM configuration
	if c.config.RootFS.Type == "lvm" {
		parts = append(parts, "rd.lvm=1")
	}

	// Basic boot parameters
	parts = append(parts,
		"rootfstype=ext4",
		"ro",
		"console=tty0",
		"console=ttyS0,115200n8",
		"loglevel=7",
	)

	// Security parameters
	if c.config.Security.Lockdown {
		lockdownMode := c.config.Security.LockdownMode
		if lockdownMode == "" {
			lockdownMode = "confidentiality"
		}
		parts = append(parts, fmt.Sprintf("lockdown=%s", lockdownMode))
	}

	if c.config.Security.FIPS {
		parts = append(parts, "fips=1")
	}

	return strings.Join(parts, " ")
}

// writeInstallerConfig writes installer configuration to YAML file
func (c *Customizer) writeInstallerConfig(config *installer.Config, path string) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	c.logger.Debug("Wrote installer configuration", "path", path, "size", len(data))
	return nil
}

// writeInitrdConfig writes initrd configuration to YAML file
func (c *Customizer) writeInitrdConfig(config *initrd.Config, path string) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	c.logger.Debug("Wrote initrd configuration", "path", path, "size", len(data))
	return nil
}

// parsePCRSelection parses PCR selection string (e.g., "0,7,9") to slice of uints
func parsePCRSelection(selection string) ([]uint, error) {
	if selection == "" {
		return nil, fmt.Errorf("empty PCR selection")
	}

	var pcrs []uint
	for _, s := range strings.Split(selection, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}

		var pcr uint
		if _, err := fmt.Sscanf(s, "%d", &pcr); err != nil {
			return nil, fmt.Errorf("invalid PCR value: %s", s)
		}
		if pcr > 23 {
			return nil, fmt.Errorf("PCR value out of range (0-23): %d", pcr)
		}
		pcrs = append(pcrs, pcr)
	}

	if len(pcrs) == 0 {
		return nil, fmt.Errorf("no valid PCRs found")
	}

	return pcrs, nil
}

// buildDynamicConfigParams builds kernel cmdline parameters for dynamic
// configuration mode. Returns an empty string when not in dynamic config mode.
func (c *Customizer) buildDynamicConfigParams() string {
	url := c.config.Platform.ConfigServerURL
	if url == "" {
		return ""
	}

	var params []string
	params = append(params, "platform_config="+url)

	if s := c.config.Platform.BootstrapStrategy; s != "" {
		params = append(params, "bootstrap_strategy="+s)
	}
	if s := c.config.Platform.BootstrapDNS; s != "" {
		params = append(params, "bootstrap_dns="+s)
	}
	if s := c.config.Platform.BootstrapNoiseKey; s != "" {
		params = append(params, "bootstrap_noise_key="+s)
	}
	if s := c.config.Platform.BootstrapSPKIPin; s != "" {
		params = append(params, "bootstrap_spki_pin="+s)
	}

	return strings.Join(params, " ")
}

// readOSHostnameFromConfig extracts the os.hostname field from a merged
// platformd config yaml file. Returns the raw string on success or an
// empty string on any failure (missing file, unreadable, no os block,
// no hostname key, blank value).
//
// This is used by buildInstallerConfig as the single source of truth
// for the installed-system hostname; autoinstall.sh reads the same
// value at install time via its shell-native resolve_platform_hostname
// helper. Keeping the logic simple and dependency-free (no full YAML
// unmarshaller) because it's invoked very early in ISO customization
// and the field we want is trivial to find with a line scan.
//
// NOTE: earlier drafts of this file carried a buildHostnameParam
// helper that baked a platform_hostname=X kernel cmdline parameter
// into the bootloader configs. That indirection was removed because
// we already have the merged config file to read from.
func readOSHostnameFromConfig(path string) string {
	if path == "" {
		return ""
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(raw), "\n")
	inOSBlock := false
	for _, rawLine := range lines {
		line := strings.TrimRight(rawLine, "\r")
		// Detect start of "os:" top-level key (no leading whitespace).
		if strings.HasPrefix(line, "os:") && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			inOSBlock = true
			continue
		}
		if inOSBlock {
			// Any other top-level key ends the os block.
			if len(line) > 0 && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, "#") {
				inOSBlock = false
				continue
			}
			stripped := strings.TrimSpace(line)
			if strings.HasPrefix(stripped, "hostname:") {
				val := strings.TrimSpace(strings.TrimPrefix(stripped, "hostname:"))
				val = strings.Trim(val, `"'`)
				return val
			}
		}
	}
	return ""
}
