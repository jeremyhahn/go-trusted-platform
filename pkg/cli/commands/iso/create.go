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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	pkgiso "github.com/jeremyhahn/go-trusted-platform/pkg/iso"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/secureboot"
)

// createFlags holds flags for the create command
type createFlags struct {
	alpineVersion   string
	mirror          string
	arch            string
	platformVersion string
	platformConfig  string
	platformType    string
	secureBoot      bool
	tpmUnseal       bool
	luks            bool
	fips            bool
	fido2           bool
	overlay         string
	output          string
	keysDir         string
	generateKeys    bool
	keyBackend      string
	force           bool
	webUI           string
	configFile      string
	workDir         string
	debug           bool
	verbose         bool
	preFetch        bool
	overrides       string

	// Dynamic configuration
	configServer      string
	bootstrapStrategy string
	bootstrapDNS      string
	bootstrapNoiseKey string
	bootstrapSPKIPin  string
}

// newCreateCommand creates the create subcommand for all-in-one ISO creation
func newCreateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	flags := &createFlags{}

	cmd := &cobra.Command{
		Use:   "create",
		Short: "All-in-one ISO creation",
		Long: `Create a complete custom platform ISO in one command.

This command performs all steps in sequence:
1. Download Alpine ISO
2. Extract ISO contents
3. Generate Secure Boot keys (if needed)
4. Customize with platform components (binary copies itself into ISO)
5. Build final bootable ISO

This is equivalent to running download, extract, customize, and build commands
in sequence, but with automatic coordination and sensible defaults.

The platformd binary automatically copies itself into the ISO, so no separate
binary path needs to be specified. The output filename defaults to:
  trusted-<os>-<version>-<arch>.iso

Examples:
  # Create ISO with all defaults (uses VERSION file for version)
  platformctl iso create

  # Create ISO with custom work directory
  platformctl iso create --work-dir /tmp/build

  # Create FIPS-enabled ISO
  platformctl iso create --fips

  # Create ISO without Secure Boot
  platformctl iso create --secure-boot=false

  # Create ISO with overrides merged onto a template config
  platformctl iso create --platform-config base.yaml --overrides node-specific.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCreate(getFlags(), flags)
		},
	}

	// Alpine flags
	cmd.Flags().StringVar(&flags.alpineVersion, "alpine-version", "3.22.2", "Alpine Linux version")
	cmd.Flags().StringVar(&flags.mirror, "mirror", "http://mirror.cs.odu.edu/alpine", "Alpine Linux mirror URL")
	cmd.Flags().StringVar(&flags.arch, "arch", "x86_64", "Architecture (x86_64 or aarch64)")

	// Platform flags
	cmd.Flags().StringVar(&flags.platformVersion, "platform-version", "", "Platform version (from VERSION file if not specified)")
	cmd.Flags().StringVar(&flags.platformConfig, "platform-config", "", "Path to platformd.yaml config file (auto-detected based on platform-type)")
	cmd.Flags().StringVar(&flags.platformType, "platform-type", "server", "Platform type: 'server' or 'client' (determines config file and defaults)")
	cmd.Flags().StringVar(&flags.overrides, "overrides", "", "Path to override config (deep-merged onto --platform-config template)")

	// Security flags
	cmd.Flags().BoolVar(&flags.secureBoot, "secure-boot", true, "Enable Secure Boot support")
	cmd.Flags().BoolVar(&flags.tpmUnseal, "tpm-unseal", true, "Enable TPM auto-unseal")
	cmd.Flags().BoolVar(&flags.luks, "luks", true, "Enable LUKS encryption")
	cmd.Flags().BoolVar(&flags.fips, "fips", false, "Enable FIPS mode")
	cmd.Flags().BoolVar(&flags.fido2, "fido2", false, "Enable FIDO2 security key support (installs libfido2 packages)")

	// Build flags
	cmd.Flags().StringVar(&flags.overlay, "overlay", "", "Overlay directory to include")
	cmd.Flags().StringVar(&flags.output, "output", "", "Output ISO filename (auto-generated if not specified)")
	cmd.Flags().StringVar(&flags.keysDir, "keys-dir", "", "Secure Boot keys directory")
	cmd.Flags().BoolVar(&flags.generateKeys, "generate-keys", true, "Generate Secure Boot keys if they don't exist")
	cmd.Flags().StringVar(&flags.keyBackend, "key-backend", "file", "Secure Boot key backend: file, software, pkcs11, tpm2, awskms, azurekv, gcpkms, vault")
	cmd.Flags().BoolVar(&flags.force, "force", false, "Force rebuild even if files exist")
	cmd.Flags().StringVar(&flags.webUI, "webui", "", "Path to WebUI directory or tarball (public_html or public_html.tar.gz)")

	// Common flags
	cmd.Flags().StringVar(&flags.configFile, "config", "", "Path to ISO build configuration file")
	cmd.Flags().StringVar(&flags.workDir, "work-dir", "work", "Working directory for ISO operations")
	cmd.Flags().BoolVar(&flags.debug, "debug", false, "Enable debug output")
	cmd.Flags().BoolVar(&flags.verbose, "verbose", false, "Enable verbose output")
	cmd.Flags().BoolVar(&flags.preFetch, "pre-fetch", false,
		"Pre-download all packages into the ISO for offline installation")

	// Dynamic configuration flags
	cmd.Flags().StringVar(&flags.configServer, "config-server", "", "Server URL for dynamic config fetch at boot time")
	cmd.Flags().StringVar(&flags.bootstrapStrategy, "bootstrap-strategy", "auto", "Trust bootstrap strategy (dane, noise, spki, auto)")
	cmd.Flags().StringVar(&flags.bootstrapDNS, "bootstrap-dns", "", "DNS server for DANE TLSA lookups")
	cmd.Flags().StringVar(&flags.bootstrapNoiseKey, "bootstrap-noise-key", "", "Noise server public key (hex-encoded)")
	cmd.Flags().StringVar(&flags.bootstrapSPKIPin, "bootstrap-spki-pin", "", "SPKI pin SHA-256 hash for certificate pinning")

	return cmd
}

// runCreate executes the all-in-one ISO creation command
func runCreate(commonFlags *cli.CommonFlags, flags *createFlags) error {
	ctx := context.Background()

	// Setup logger
	logger := getCreateLogger(flags)

	printHeader("Creating Trusted Platform ISO")

	// Validate architecture
	if flags.arch != "x86_64" && flags.arch != "aarch64" {
		return ErrInvalidArchitecture{
			Architecture: flags.arch,
			Valid:        []string{"x86_64", "aarch64"},
		}
	}

	// Validate platform type
	if flags.platformType != "server" && flags.platformType != "client" {
		return ErrInvalidPlatformType{
			PlatformType: flags.platformType,
			Valid:        []string{"server", "client"},
		}
	}

	// Merge overrides onto platform config template if requested
	if err := applyOverrides(flags); err != nil {
		return err
	}

	// Build complete ISO build configuration
	buildConfig, err := buildISOBuildConfig(flags)
	if err != nil {
		return ErrConfigValidationFailed{Reason: err.Error()}
	}

	// Validate configuration
	printInfo("Validating configuration...")
	if err := buildConfig.Validate(); err != nil {
		return ErrConfigValidationFailed{Reason: err.Error()}
	}

	// Find/build platform binaries if not specified
	printInfo("Resolving platform binaries...")
	if err := buildConfig.ResolveBinaries(); err != nil {
		return ErrBuildFailed{Reason: fmt.Sprintf("failed to resolve binaries: %v", err)}
	}

	// Create work directory
	workDirPath, err := buildConfig.ResolveWorkDir()
	if err != nil {
		return ErrBuildFailed{Reason: fmt.Sprintf("failed to create work directory: %v", err)}
	}

	printInfo(fmt.Sprintf("Work directory: %s", workDirPath))
	printInfo(fmt.Sprintf("Alpine version: %s", buildConfig.AlpineVersion))
	printInfo(fmt.Sprintf("Architecture: %s", buildConfig.Architecture))
	printInfo(fmt.Sprintf("Platform type: %s", buildConfig.PlatformType))
	printInfo(fmt.Sprintf("Platformd binary: %s (self)", buildConfig.PlatformdBinary))
	printInfo(fmt.Sprintf("Secure Boot: %v", buildConfig.SecureBoot))
	printInfo(fmt.Sprintf("TPM auto-unseal: %v", buildConfig.TPMAutoUnseal))
	printInfo(fmt.Sprintf("LUKS encryption: %v", buildConfig.LUKSTPMOnly))
	printInfo(fmt.Sprintf("FIPS mode: %v", buildConfig.FIPS))
	printInfo(fmt.Sprintf("FIDO2 support: %v", buildConfig.EnableFIDO2))
	printInfo(fmt.Sprintf("Pre-fetch packages: %v", buildConfig.PreFetch))

	// Step 1: Download Alpine ISO
	printHeader("Step 1/5: Downloading Alpine ISO")
	isoPath, err := downloadAlpineISO(ctx, logger, buildConfig, workDirPath)
	if err != nil {
		return ErrDownloadFailed{Reason: err.Error()}
	}
	printSuccess(fmt.Sprintf("Alpine ISO downloaded: %s", isoPath))

	// Step 2: Extract ISO
	printHeader("Step 2/5: Extracting ISO")
	if err := extractAlpineISO(ctx, logger, buildConfig, isoPath, workDirPath); err != nil {
		return ErrExtractionFailed{Reason: err.Error()}
	}
	printSuccess("ISO extracted successfully")

	// Step 3: Generate Secure Boot keys if needed
	if buildConfig.SecureBoot && buildConfig.GenerateKeys {
		printHeader("Step 3/5: Generating Secure Boot Keys")
		if err := generateSecureBootKeys(ctx, logger, buildConfig); err != nil {
			return ErrBuildFailed{Reason: fmt.Sprintf("failed to generate Secure Boot keys: %v", err)}
		}
		printSuccess("Secure Boot keys ready")
	} else {
		printHeader("Step 3/5: Secure Boot Keys")
		if buildConfig.SecureBoot {
			printInfo("Using existing Secure Boot keys")
		} else {
			printInfo("Secure Boot disabled - skipping key generation")
		}
	}

	// Step 4: Customize ISO
	printHeader("Step 4/5: Customizing ISO")
	if err := customizeISO(ctx, logger, buildConfig, workDirPath); err != nil {
		return ErrCustomizationFailed{Reason: err.Error()}
	}
	printSuccess("ISO customization complete")

	// Step 5: Build final ISO
	printHeader("Step 5/5: Building Final ISO")
	outputISO, err := buildFinalISO(ctx, logger, buildConfig, workDirPath)
	if err != nil {
		return ErrBuildFailed{Reason: err.Error()}
	}

	// Calculate and display SHA256
	printInfo("Calculating SHA256 checksum...")
	checksum, err := calculateFileSHA256(outputISO)
	if err != nil {
		printWarn(fmt.Sprintf("Failed to calculate checksum: %v", err))
	} else {
		printInfo(fmt.Sprintf("SHA256: %s", checksum))
	}

	printHeader("ISO Creation Complete")
	printSuccess(fmt.Sprintf("Output ISO: %s", outputISO))

	// Get file size
	if info, err := os.Stat(outputISO); err == nil {
		printInfo(fmt.Sprintf("Size: %d MB", info.Size()/(1024*1024)))
	}

	return nil
}

// applyOverrides merges the overrides file onto the platform config template
// and updates flags.platformConfig to point to the merged temp file.
func applyOverrides(flags *createFlags) error {
	if flags.overrides == "" {
		return nil
	}
	if flags.platformConfig == "" {
		return ErrOverridesWithoutTemplate{}
	}

	printInfo("Merging overrides onto template")

	merged, err := config.DeepMergeYAMLFiles(flags.platformConfig, flags.overrides)
	if err != nil {
		return ErrOverridesMergeFailed{Reason: err.Error()}
	}

	tmpFile, err := os.CreateTemp("", "platformd-merged-*.yaml")
	if err != nil {
		return ErrOverridesTempFile{Reason: err.Error()}
	}

	if _, err := tmpFile.Write(merged); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return ErrOverridesTempFileWrite{Path: tmpFile.Name(), Reason: err.Error()}
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpFile.Name())
		return ErrOverridesTempFileWrite{Path: tmpFile.Name(), Reason: err.Error()}
	}

	flags.platformConfig = tmpFile.Name()
	return nil
}

// buildISOBuildConfig constructs the ISO build configuration from flags
func buildISOBuildConfig(flags *createFlags) (*pkgiso.ISOBuildConfig, error) {
	config := pkgiso.DefaultISOBuildConfig()

	// Resolve platformd binary path from the same directory as the running binary.
	// platformd and platformctl are separate binaries built from separate cmd/ directories.
	selfPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %w", err)
	}
	selfPath, err = filepath.EvalSymlinks(selfPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve executable path: %w", err)
	}
	binDir := filepath.Dir(selfPath)
	platformdPath := filepath.Join(binDir, "platformd")
	if _, err := os.Stat(platformdPath); err != nil {
		return nil, fmt.Errorf("platformd binary not found at %s (build with 'make build')", platformdPath)
	}
	config.PlatformdBinary = platformdPath

	// Override from flags
	if flags.alpineVersion != "" {
		config.AlpineVersion = flags.alpineVersion
	}
	if flags.mirror != "" {
		config.AlpineMirror = flags.mirror
	}
	if flags.arch != "" {
		config.Architecture = flags.arch
	}

	// Set platform type
	config.PlatformType = pkgiso.PlatformType(flags.platformType)

	// Set platform config file (for TPM provisioning)
	if flags.platformConfig != "" {
		config.PlatformConfigFile = flags.platformConfig
	} else {
		// Auto-detect config file based on platform type
		var defaultConfigPaths []string
		if flags.platformType == "server" {
			defaultConfigPaths = []string{
				"configs/platform/standalone/qemu.server.example.com.yaml",
			}
		} else {
			defaultConfigPaths = []string{
				"configs/platform/standalone/qemu.node0.example.com.yaml",
				"configs/platform/standalone/qemu.client.example.com.yaml",
			}
		}
		for _, p := range defaultConfigPaths {
			if _, err := os.Stat(p); err == nil {
				config.PlatformConfigFile = p
				break
			}
		}
	}

	if flags.workDir != "" {
		config.WorkDir = flags.workDir
	}
	if flags.keysDir != "" {
		config.KeysDir = flags.keysDir
	}
	if flags.output != "" {
		config.OutputISO = flags.output
	}
	if flags.webUI != "" {
		config.WebUIPath = flags.webUI
	} else {
		// Auto-detect public_html.tar.gz or public_html/ in current directory
		// Prefer tarball first (more reliable, avoids empty directory issues)
		if _, err := os.Stat("public_html.tar.gz"); err == nil {
			config.WebUIPath = "public_html.tar.gz"
		} else if info, err := os.Stat("public_html"); err == nil && info.IsDir() {
			// Verify directory is not empty
			entries, err := os.ReadDir("public_html")
			if err == nil && len(entries) > 0 {
				config.WebUIPath = "public_html"
			}
		}
	}

	// Boolean flags
	config.SecureBoot = flags.secureBoot
	config.GenerateKeys = flags.generateKeys
	config.KeyBackend = flags.keyBackend
	config.TPMAutoUnseal = flags.tpmUnseal
	config.LUKSTPMOnly = flags.luks
	config.FIPS = flags.fips
	config.EnableFIDO2 = flags.fido2
	config.Force = flags.force
	config.Debug = flags.debug
	config.PreFetch = flags.preFetch

	// Dynamic configuration
	if flags.configServer != "" {
		config.ConfigServerURL = flags.configServer
	}
	if flags.bootstrapStrategy != "" && flags.bootstrapStrategy != "auto" {
		config.BootstrapStrategy = flags.bootstrapStrategy
	}
	if flags.bootstrapDNS != "" {
		config.BootstrapDNS = flags.bootstrapDNS
	}
	if flags.bootstrapNoiseKey != "" {
		config.BootstrapNoiseKey = flags.bootstrapNoiseKey
	}
	if flags.bootstrapSPKIPin != "" {
		config.BootstrapSPKIPin = flags.bootstrapSPKIPin
	}

	// Load config file if specified
	if flags.configFile != "" {
		loadedConfig, err := pkgiso.LoadISOBuildConfig(flags.configFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load config file: %w", err)
		}
		// Merge loaded config with flag overrides
		config = mergeConfigs(loadedConfig, config)
	}

	// Read platform version from VERSION file if not specified
	platformVersion := flags.platformVersion
	if platformVersion == "" {
		if version, err := readVersionFile(); err == nil {
			platformVersion = version
		} else {
			platformVersion = "dev"
		}
	}

	// Generate output ISO name if not specified
	// Format: trusted-$OS_NAME-$TRUSTED_PLATFORM_VERSION-$ARCHITECTURE.iso
	if config.OutputISO == "" {
		osName := "alpine"
		fipsSuffix := ""
		if config.FIPS {
			fipsSuffix = "-fips"
		}
		config.OutputISO = fmt.Sprintf("trusted-%s-%s-%s%s.iso",
			osName, platformVersion, config.Architecture, fipsSuffix)
	}

	return config, nil
}

// downloadAlpineISO downloads the Alpine Linux ISO
func downloadAlpineISO(ctx context.Context, logger *logging.Logger, config *pkgiso.ISOBuildConfig, workDir string) (string, error) {
	// Build ISOConfig for download
	isoConfig := pkgiso.DefaultISOConfig()
	isoConfig.Version = config.AlpineVersion
	isoConfig.MirrorURL = config.AlpineMirror
	isoConfig.WorkDir = workDir
	isoConfig.VerifyChecksum = true
	isoConfig.ResumeDownload = true
	isoConfig.Debug = config.Debug

	// Customize ISO filename for architecture
	if config.Architecture != "x86_64" {
		isoConfig.ISO = fmt.Sprintf("alpine-standard-%s-%s.iso", config.AlpineVersion, config.Architecture)
	}

	if err := isoConfig.Validate(); err != nil {
		return "", fmt.Errorf("invalid ISO configuration: %w", err)
	}

	printInfo(fmt.Sprintf("Downloading from: %s", isoConfig.URL))
	printInfo(fmt.Sprintf("Output: %s", isoConfig.ISOPath()))

	// Remove existing files if force flag is set
	if config.Force {
		removeExistingISOFiles(isoConfig)
	}

	if err := pkgiso.DownloadISO(ctx, isoConfig); err != nil {
		return "", err
	}

	return isoConfig.ISOPath(), nil
}

// extractAlpineISO extracts the ISO contents
func extractAlpineISO(ctx context.Context, logger *logging.Logger, config *pkgiso.ISOBuildConfig, isoPath, workDir string) error {
	// Build ISOConfig for extraction
	isoConfig := &pkgiso.ISOConfig{
		Version:   config.AlpineVersion,
		MirrorURL: config.AlpineMirror,
		WorkDir:   workDir,
		ISODir:    filepath.Join(workDir, "iso"),
		Debug:     config.Debug,
	}

	// Set the ISO path manually since we already have it
	isoConfig.ISO = filepath.Base(isoPath)

	if err := isoConfig.Validate(); err != nil {
		return fmt.Errorf("invalid ISO configuration: %w", err)
	}

	printInfo(fmt.Sprintf("Extracting to: %s", isoConfig.ISODir))

	if err := pkgiso.ExtractISO(ctx, isoConfig); err != nil {
		return err
	}

	return nil
}

// generateSecureBootKeys generates Secure Boot keys if needed
func generateSecureBootKeys(ctx context.Context, logger *logging.Logger, config *pkgiso.ISOBuildConfig) error {
	keysDir := config.KeysDir
	if keysDir == "" {
		keysDir = filepath.Join(config.WorkDir, "secure-boot-keys")
	}

	// Determine backend type
	backend := secureboot.BackendType(config.KeyBackend)
	if config.KeyBackend == "" {
		backend = secureboot.BackendFile
	}

	// Use XKMSManager for all backends (including file)
	xkmsConfig := &secureboot.XKMSConfig{
		KeysDir:      keysDir,
		Backend:      backend,
		CommonName:   "Trusted Platform",
		Country:      "US",
		Organization: "Trusted Platform",
		KeySize:      2048,
		ValidYears:   10,
		ExportKeys:   true, // Always export for Secure Boot enrollment
	}

	km, err := secureboot.NewXKMSManager(xkmsConfig, logger)
	if err != nil {
		return fmt.Errorf("failed to create key manager: %w", err)
	}
	defer km.Close()

	// Check if keys exist
	if km.KeysExist() {
		printInfo(fmt.Sprintf("Secure Boot keys already exist - skipping generation (backend: %s)", backend))
		return nil
	}

	printInfo(fmt.Sprintf("Generating Secure Boot keys in: %s (backend: %s)", keysDir, backend))
	if err := km.GenerateAll(ctx); err != nil {
		return fmt.Errorf("failed to generate keys: %w", err)
	}

	// Update config with keys directory
	config.KeysDir = keysDir

	return nil
}

// customizeISO customizes the extracted ISO with platform components
func customizeISO(ctx context.Context, logger *logging.Logger, config *pkgiso.ISOBuildConfig, workDir string) error {

	printInfo("Integrating platform components...")

	// Create PlatformISOConfig from the build config
	platformConfig := &pkgiso.PlatformISOConfig{
		Alpine: pkgiso.AlpineConfig{
			Version: config.AlpineVersion,
			Mirror:  config.AlpineMirror,
		},
		Directories: pkgiso.DirectoryConfig{
			Work:    workDir,
			ISO:     filepath.Join(workDir, "iso"),
			Overlay: filepath.Join(workDir, "overlay"),
			Keys:    config.KeysDir,
		},
		Platform: pkgiso.PlatformConfig{
			PlatformdBinary:   config.PlatformdBinary,
			ConfigFile:        config.PlatformConfigFile,
			CABundlePath:      config.CABundlePath,
			WebUIPath:         config.WebUIPath,
			PlatformType:      config.PlatformType,
			ConfigServerURL:   config.ConfigServerURL,
			BootstrapStrategy: config.BootstrapStrategy,
			BootstrapDNS:      config.BootstrapDNS,
			BootstrapNoiseKey: config.BootstrapNoiseKey,
			BootstrapSPKIPin:  config.BootstrapSPKIPin,
		},
		Security: pkgiso.SecurityConfig{
			SecureBoot: config.SecureBoot,
			TPM: pkgiso.TPMConfig{
				AutoUnseal:      config.TPMAutoUnseal,
				AutoUpgradeSeal: config.TPMAutoUpgradeSeal,
			},
			FIPS:        config.FIPS,
			Lockdown:    config.Lockdown,
			EnableFIDO2: config.EnableFIDO2,
		},
		LUKS: pkgiso.LUKSConfig{
			Enabled: config.LUKSTPMOnly,
			TPMOnly: config.LUKSTPMOnly,
		},
		RootFS: pkgiso.RootFSConfig{
			Type: config.RootFS,
		},
		Build: pkgiso.BuildOptions{
			Debug:    config.Debug,
			PreFetch: config.PreFetch,
		},
		Output: pkgiso.OutputConfig{
			Label: config.OutputLabel,
		},
	}

	// Set defaults
	platformConfig.SetDefaults()

	customizer := pkgiso.NewCustomizer(platformConfig, logger)
	if err := customizer.CustomizeAll(ctx); err != nil {
		return err
	}

	return nil
}

// buildFinalISO builds the final bootable ISO
func buildFinalISO(ctx context.Context, logger *logging.Logger, config *pkgiso.ISOBuildConfig, workDir string) (string, error) {
	printInfo(fmt.Sprintf("Building ISO: %s", config.OutputISO))
	printInfo(fmt.Sprintf("Volume label: %s", config.OutputLabel))

	builder := pkgiso.NewBuilder(logger)

	// Convert to ISOConfig for BuildISO
	isoConfig := &pkgiso.ISOConfig{
		ISODir:    filepath.Join(workDir, "iso"),
		OutputISO: config.OutputISO,
		VolumeID:  config.OutputLabel,
		KeysDir:   config.KeysDir,
		Debug:     config.Debug,
	}

	if err := builder.BuildISO(ctx, isoConfig); err != nil {
		return "", err
	}

	return config.OutputISO, nil
}

// getCreateLogger creates a logger with appropriate log level
func getCreateLogger(flags *createFlags) *logging.Logger {
	level := slog.LevelInfo
	if flags.debug {
		level = slog.LevelDebug
	}
	return logging.NewLogger(level, nil)
}

// mergeConfigs merges two configurations, with override taking precedence
func mergeConfigs(base, override *pkgiso.ISOBuildConfig) *pkgiso.ISOBuildConfig {
	result := *base

	// Override only non-default values
	if override.AlpineVersion != "" && override.AlpineVersion != "3.22.2" {
		result.AlpineVersion = override.AlpineVersion
	}
	if override.AlpineMirror != "" && override.AlpineMirror != "https://dl-cdn.alpinelinux.org/alpine" {
		result.AlpineMirror = override.AlpineMirror
	}
	if override.Architecture != "" && override.Architecture != "x86_64" {
		result.Architecture = override.Architecture
	}
	if override.OutputISO != "" {
		result.OutputISO = override.OutputISO
	}
	if override.OutputLabel != "" {
		result.OutputLabel = override.OutputLabel
	}
	if override.WorkDir != "" && override.WorkDir != "work" {
		result.WorkDir = override.WorkDir
	}
	// Always use the current binary (self-copy) - don't override from config file
	// The PlatformdBinary is auto-detected using os.Executable()
	if override.KeysDir != "" {
		result.KeysDir = override.KeysDir
	}

	// Always override boolean flags
	result.SecureBoot = override.SecureBoot
	result.GenerateKeys = override.GenerateKeys
	result.TPMAutoUnseal = override.TPMAutoUnseal
	result.LUKSTPMOnly = override.LUKSTPMOnly
	result.FIPS = override.FIPS
	result.EnableFIDO2 = override.EnableFIDO2
	result.Force = override.Force
	result.Debug = override.Debug

	return &result
}

// readVersionFile reads the VERSION file
func readVersionFile() (string, error) {
	versionFile := "VERSION"
	if _, err := os.Stat(versionFile); os.IsNotExist(err) {
		// Try parent directory
		versionFile = "../VERSION"
		if _, err := os.Stat(versionFile); os.IsNotExist(err) {
			return "", fmt.Errorf("VERSION file not found")
		}
	}

	data, err := os.ReadFile(versionFile)
	if err != nil {
		return "", err
	}

	version := string(data)
	// Trim whitespace
	version = strings.TrimSpace(version)

	return version, nil
}

// calculateFileSHA256 calculates the SHA256 hash of a file
func calculateFileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("failed to hash file: %w", err)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// removeExistingISOFiles removes existing ISO and related files
func removeExistingISOFiles(cfg *pkgiso.ISOConfig) {
	files := []string{
		cfg.ISOPath(),
		cfg.ChecksumPath(),
		cfg.VerifiedMarkerPath(),
		cfg.TempPath(),
	}

	for _, file := range files {
		_ = removeFileIfExists(file)
	}
}
