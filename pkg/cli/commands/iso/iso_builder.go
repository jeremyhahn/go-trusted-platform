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
	"os"
	"os/exec"
	"path/filepath"

	pkgiso "github.com/jeremyhahn/go-trusted-platform/pkg/iso"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// ISOBuilderConfig holds configuration for building a custom ISO
type ISOBuilderConfig struct {
	// OutputPath is the path for the output ISO file
	OutputPath string

	// WorkDir is the working directory for ISO building
	WorkDir string

	// PlatformConfigPath is the path to the platform config file to embed
	PlatformConfigPath string

	// PlatformType is "server" or "client"
	PlatformType string

	// SecureBoot enables Secure Boot support (default: true)
	SecureBoot bool

	// KeysDir is the directory containing Secure Boot keys (optional)
	// If not set, keys will be generated in WorkDir/secure-boot-keys
	KeysDir string

	// EnableFIDO2 enables FIDO2 support in the ISO
	EnableFIDO2 bool

	// Debug enables debug output
	Debug bool

	// PlatformdBinary is the path to the platformd binary to embed in the ISO
	// If empty, uses the current executable (os.Executable())
	PlatformdBinary string

	// PlatformctlBinary is the platformctl installed on the target. If empty,
	// uses the running platformctl.
	PlatformctlBinary string

	// PlatformctlStaticBinary is the static platformctl the Alpine installer
	// runs. If empty, none is installed and PlatformctlBinary must be static.
	PlatformctlStaticBinary string

	// CABundlePath is the path to the CA certificate bundle to embed in the ISO
	// This allows clients to trust the server's CA without insecure network fetch
	CABundlePath string

	// WebUIPath is the path to the WebUI directory or tarball to embed in the ISO
	// This gets extracted to /var/lib/trusted-platform/public_html during installation
	WebUIPath string

	// PreFetch downloads all required packages into the ISO for offline installation
	PreFetch bool
}

// BuildCustomISO creates a custom ISO with the specified installer config embedded.
// This allows creating separate ISOs for server and client VMs with their own
// network configurations.
func BuildCustomISO(ctx context.Context, logger *logging.Logger, cfg *ISOBuilderConfig) error {
	// Create work directory
	if err := os.MkdirAll(cfg.WorkDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create work directory", Err: err}
	}

	// Determine platformd binary path
	var platformdPath string
	if cfg.PlatformdBinary != "" {
		// Use explicitly provided binary path
		platformdPath = cfg.PlatformdBinary
		// Resolve to absolute path if relative
		if !filepath.IsAbs(platformdPath) {
			absPath, err := filepath.Abs(platformdPath)
			if err != nil {
				return &WrappedError{Msg: "failed to resolve platformd binary path", Err: err}
			}
			platformdPath = absPath
		}
		// Verify binary exists
		if _, err := os.Stat(platformdPath); err != nil {
			return &MessageError{Msg: fmt.Sprintf("platformd binary not found: %s", platformdPath)}
		}
		logger.Infof("Using specified platformd binary: %s", platformdPath)
	} else {
		// Get the current executable path (platformd binary)
		selfPath, err := os.Executable()
		if err != nil {
			return &WrappedError{Msg: "failed to get executable path", Err: err}
		}
		selfPath, err = filepath.EvalSymlinks(selfPath)
		if err != nil {
			return &WrappedError{Msg: "failed to resolve executable path", Err: err}
		}

		// Prefer static binary for Alpine/musl compatibility
		// The static binary doesn't depend on glibc and works with musl
		selfDir := filepath.Dir(selfPath)
		staticPath := filepath.Join(selfDir, "platformd-static")
		if _, err := os.Stat(staticPath); err == nil {
			platformdPath = staticPath
			logger.Infof("Using static platformd binary for Alpine compatibility: %s", platformdPath)
		} else {
			platformdPath = selfPath
			logger.Warnf("Static binary not found at %s, using dynamic binary: %s (may not work on Alpine/musl)", staticPath, platformdPath)
		}
	}

	// Validate the resolved binary is actually platformd, not platformctl
	if err := pkgiso.ValidatePlatformdBinaryName(platformdPath); err != nil {
		return err
	}

	// Build ISO configuration
	buildConfig, err := newBuilderISOBuildConfig(cfg, platformdPath)
	if err != nil {
		return err
	}

	// Set platform config if provided
	if cfg.PlatformConfigPath != "" {
		buildConfig.PlatformConfigFile = cfg.PlatformConfigPath
	} else {
		// Auto-detect platform config based on type
		// Auto-detect platform config based on type
		var defaultConfigPaths []string
		if cfg.PlatformType == "server" {
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
				buildConfig.PlatformConfigFile = p
				break
			}
		}
	}

	// Set CA bundle path if provided (for client ISOs to trust the server CA)
	if cfg.CABundlePath != "" {
		buildConfig.CABundlePath = cfg.CABundlePath
		logger.Infof("CA bundle path: %s", cfg.CABundlePath)
	}

	// Set WebUI path - auto-detect or auto-build if not provided
	webUIPath, err := resolveWebUIPath(ctx, logger, cfg.WebUIPath)
	if err != nil {
		return &WrappedError{Msg: "failed to resolve WebUI", Err: err}
	}
	if webUIPath != "" {
		buildConfig.WebUIPath = webUIPath
		logger.Infof("WebUI path: %s", webUIPath)
	}

	// Validate configuration
	if err := buildConfig.Validate(); err != nil {
		return &WrappedError{Msg: "configuration validation failed", Err: err}
	}

	// Resolve binaries
	if err := buildConfig.ResolveBinaries(); err != nil {
		return &WrappedError{Msg: "failed to resolve binaries", Err: err}
	}

	// Resolve work directory
	workDirPath, err := buildConfig.ResolveWorkDir()
	if err != nil {
		return &WrappedError{Msg: "failed to resolve work directory", Err: err}
	}

	logger.Infof("Building custom ISO: %s", cfg.OutputPath)
	logger.Infof("Work directory: %s", workDirPath)

	// Step 1: Download Alpine ISO
	logger.Info("Downloading Alpine ISO...")
	isoPath, err := downloadAlpineISO(ctx, logger, buildConfig, workDirPath)
	if err != nil {
		return &WrappedError{Msg: "failed to download Alpine ISO", Err: err}
	}
	logger.Infof("Alpine ISO: %s", isoPath)

	// Step 2: Extract ISO
	logger.Info("Extracting ISO...")
	if err := extractAlpineISO(ctx, logger, buildConfig, isoPath, workDirPath); err != nil {
		return &WrappedError{Msg: "failed to extract ISO", Err: err}
	}

	// Step 3: Generate Secure Boot keys if needed — never for a platform
	// config carrying a remote/KMS db signing reference (round-16 review).
	decision, err := pkgiso.EnsureSecureBootKeys(ctx, logger, buildConfig)
	if err != nil {
		return &WrappedError{Msg: "failed to generate Secure Boot keys", Err: err}
	}
	switch decision {
	case pkgiso.SecureBootKeysGenerated:
		logger.Info("Generated Secure Boot keys", "dir", buildConfig.KeysDir)
	case pkgiso.SecureBootKeysRemote:
		logger.Info("Remote/KMS signing configured - skipping local key generation")
	}

	// Step 4: Customize ISO (includes copying installer config and Secure Boot keys)
	logger.Info("Customizing ISO...")
	if err := customizeISO(ctx, logger, buildConfig, workDirPath); err != nil {
		return &WrappedError{Msg: "failed to customize ISO", Err: err}
	}

	// Step 5: Build final ISO
	logger.Info("Building final ISO...")
	outputISO, err := buildFinalISO(ctx, logger, buildConfig, workDirPath)
	if err != nil {
		return &WrappedError{Msg: "failed to build final ISO", Err: err}
	}

	logger.Infof("ISO created: %s", outputISO)

	return nil
}

// newBuilderISOBuildConfig maps the builder inputs onto a pkg/iso build
// config. platformctl and platformctl-static follow the same rules as
// `iso create` (namePlatformctlBinaries): a dynamically linked platformctl
// needs a platformctl-static beside it, or staging rejects it.
func newBuilderISOBuildConfig(cfg *ISOBuilderConfig, platformdPath string) (*pkgiso.ISOBuildConfig, error) {
	buildConfig := pkgiso.DefaultISOBuildConfig()
	buildConfig.PlatformdBinary = platformdPath
	if err := namePlatformctlBinaries(buildConfig, cfg.PlatformctlBinary, cfg.PlatformctlStaticBinary); err != nil {
		return nil, err
	}
	buildConfig.WorkDir = cfg.WorkDir
	buildConfig.OutputISO = cfg.OutputPath
	buildConfig.EnableFIDO2 = cfg.EnableFIDO2
	buildConfig.Debug = cfg.Debug
	buildConfig.SecureBoot = cfg.SecureBoot
	buildConfig.GenerateKeys = cfg.SecureBoot // Generate keys if SecureBoot is enabled
	buildConfig.PreFetch = cfg.PreFetch

	// Set keys directory if provided
	if cfg.KeysDir != "" {
		buildConfig.KeysDir = cfg.KeysDir
	}

	// Set platform type
	if cfg.PlatformType != "" {
		buildConfig.PlatformType = pkgiso.PlatformType(cfg.PlatformType)
	}
	return buildConfig, nil
}

// resolveWebUIPath determines the WebUI path to use for the ISO.
// Priority:
//  1. Explicitly provided path (--webui flag)
//  2. public_html.tar.gz in current working directory
//  3. public_html/ directory in current working directory
//  4. Auto-build using `make build-public-html` if none found
func resolveWebUIPath(ctx context.Context, logger *logging.Logger, explicitPath string) (string, error) {
	logger.Info("Resolving WebUI path", "explicitPath", explicitPath)

	// If explicitly provided, validate and return
	if explicitPath != "" {
		if _, err := os.Stat(explicitPath); err != nil {
			return "", &MessageError{Msg: fmt.Sprintf("specified WebUI path not found: %s", explicitPath)}
		}
		logger.Debug("Using explicitly specified WebUI path", "path", explicitPath)
		return explicitPath, nil
	}

	// Check for public_html.tar.gz in current directory
	tarballPath := "public_html.tar.gz"
	cwd, _ := os.Getwd()
	logger.Debug("Checking for WebUI tarball", "path", tarballPath, "cwd", cwd)
	if _, err := os.Stat(tarballPath); err == nil {
		absPath, _ := filepath.Abs(tarballPath)
		logger.Info("Found WebUI tarball in current directory", "path", absPath)
		return absPath, nil
	} else {
		logger.Debug("WebUI tarball not found", "error", err.Error())
	}

	// Check for public_html/ directory in current directory
	dirPath := "public_html"
	if info, err := os.Stat(dirPath); err == nil && info.IsDir() {
		// Verify it has content (not empty)
		entries, err := os.ReadDir(dirPath)
		if err == nil && len(entries) > 0 {
			absPath, _ := filepath.Abs(dirPath)
			logger.Info("Found WebUI directory in current directory", "path", absPath)
			return absPath, nil
		}
	}

	// Auto-build WebUI using make build-public-html
	logger.Info("No WebUI found, auto-building using 'make build-public-html'...")
	logger.Info("This may take a few minutes on first run (building devcontainer and cloning web project)...")

	buildCmd := exec.CommandContext(ctx, "make", "build-public-html")
	buildCmd.Stdout = os.Stderr // build chatter is progress; stdout carries the verb's result
	buildCmd.Stderr = os.Stderr

	if err := buildCmd.Run(); err != nil {
		return "", &CommandOutputError{Msg: "failed to auto-build WebUI", Err: err, Detail: "\nRun 'make build-public-html' manually to diagnose"}
	}

	// Verify tarball was created
	if _, err := os.Stat(tarballPath); err == nil {
		absPath, _ := filepath.Abs(tarballPath)
		logger.Info("WebUI auto-build successful", "path", absPath)
		return absPath, nil
	}

	// Check for directory if tarball wasn't created
	if info, err := os.Stat(dirPath); err == nil && info.IsDir() {
		absPath, _ := filepath.Abs(dirPath)
		logger.Info("WebUI auto-build successful (directory)", "path", absPath)
		return absPath, nil
	}

	logger.Warn("WebUI auto-build completed but no output found - continuing without WebUI")
	return "", nil
}
