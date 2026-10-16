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

package alpine

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/fips"
)

func init() {
	// Register the Alpine FIPS installer factory
	fips.RegisterInstaller("alpine", NewFIPSInstaller)
}

// fipsArtifactsDir is where an ISO built with --fips carries the pre-built
// FIPS kernel, kernel modules and OpenSSL FIPS provider.
const fipsArtifactsDir = "/media/cdrom/fips-artifacts"

// FIPSInstaller implements FIPS installation for Alpine Linux
type FIPSInstaller struct {
	config       *fips.Config
	logger       *slog.Logger
	apkManager   *APKManager
	artifactsDir string
}

// NewFIPSInstaller creates a new Alpine FIPS installer
func NewFIPSInstaller(config *fips.Config) (fips.Installer, error) {
	if config == nil {
		return nil, &MessageError{Msg: "config is required"}
	}

	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	// Create APK manager for package installation
	apkManager := NewAPKManager(config.Mirror, config.Version, config.Arch, config.WorkDir, config.Logger)

	return &FIPSInstaller{
		config:       config,
		logger:       config.Logger,
		apkManager:   apkManager,
		artifactsDir: fipsArtifactsDir,
	}, nil
}

// Install performs complete FIPS installation for Alpine Linux
func (i *FIPSInstaller) Install(ctx context.Context) error {
	i.logger.Info("Installing FIPS components for Alpine Linux")

	// Note: Alpine Linux repository kernels do NOT have built-in FIPS support.
	// We must compile a FIPS-capable kernel from Linux kernel source.
	// Steps:
	// 1. Install FIPS-capable kernel from source
	// 2. Install OpenSSL FIPS module from source
	// 3. Configure OpenSSL for FIPS mode
	// 4. Add fips=1 to kernel command line (done by buildUKI)
	// 5. Verify the configuration

	i.logger.Info("Installing FIPS-capable kernel from source")
	if err := i.installFIPSKernel(ctx); err != nil {
		return &WrappedError{Msg: "failed to install FIPS kernel", Err: err}
	}

	// 1. Install OpenSSL FIPS module
	if err := i.installOpenSSLFIPS(ctx); err != nil {
		return &WrappedError{Msg: "failed to install OpenSSL FIPS", Err: err}
	}

	// 2. Configure OpenSSL for FIPS
	if err := i.configureOpenSSLFIPS(); err != nil {
		return &WrappedError{Msg: "failed to configure OpenSSL FIPS", Err: err}
	}

	// 3. Verify FIPS installation
	if err := i.Verify(); err != nil {
		return &WrappedError{Msg: "FIPS verification failed", Err: err}
	}

	i.logger.Info("FIPS installation completed successfully for Alpine Linux")
	return nil
}

// Verify checks if FIPS is properly installed and configured
func (i *FIPSInstaller) Verify() error {
	i.logger.Info("Verifying FIPS installation")

	// Check for FIPS kernel module
	fipsModulePath := filepath.Join(i.config.MountPoint, "usr", "lib", "ossl-modules", "fips.so")
	if _, err := os.Stat(fipsModulePath); err != nil {
		return &SentinelCauseError{Sentinel: fips.ErrVerificationFailed, Cause: err}
	}

	// Check for FIPS configuration
	fipsConfigPath := filepath.Join(i.config.MountPoint, "etc", "ssl", "fipsmodule.cnf")
	if _, err := os.Stat(fipsConfigPath); err != nil {
		return &SentinelCauseError{Sentinel: fips.ErrVerificationFailed, Cause: &MessageError{Msg: "FIPS config not found"}}
	}

	// Check OpenSSL configuration
	opensslConfigPath := filepath.Join(i.config.MountPoint, "etc", "ssl", "openssl.cnf")
	content, err := os.ReadFile(opensslConfigPath)
	if err != nil {
		return &WrappedError{Msg: "failed to read openssl.cnf", Err: err}
	}

	if !strings.Contains(string(content), "fips_sect") {
		return &SentinelCauseError{Sentinel: fips.ErrOpenSSLNotConfigured, Cause: &MessageError{Msg: "OpenSSL config does not include FIPS section"}}
	}

	i.logger.Info("FIPS verification passed")
	return nil
}

// GetKernelCommandLine returns the required kernel command line parameters for FIPS mode
func (i *FIPSInstaller) GetKernelCommandLine() string {
	return "fips=1"
}

// InstallKernel installs ONLY the FIPS kernel and modules
// This must be called BEFORE building UKI, as the kernel is required for dracut
func (i *FIPSInstaller) InstallKernel(ctx context.Context) error {
	i.logger.Info("Installing FIPS kernel and modules (phase 1 - before UKI build)")
	return i.installFIPSKernel(ctx)
}

// ConfigureOpenSSL installs and configures OpenSSL for FIPS mode
// This must be called AFTER signing UKI, as FIPS mode breaks OpenSSL signing operations
func (i *FIPSInstaller) ConfigureOpenSSL(ctx context.Context) error {
	i.logger.Info("Configuring OpenSSL for FIPS mode (phase 2 - after signing)")

	// Install OpenSSL FIPS module
	if err := i.installOpenSSLFIPS(ctx); err != nil {
		return &WrappedError{Msg: "failed to install OpenSSL FIPS", Err: err}
	}

	// Configure OpenSSL for FIPS
	if err := i.configureOpenSSLFIPS(); err != nil {
		return &WrappedError{Msg: "failed to configure OpenSSL FIPS", Err: err}
	}

	// Final verification: ensure all required files exist
	fipsModulePath := filepath.Join(i.config.MountPoint, "usr", "lib", "ossl-modules", "fips.so")
	fipsConfigPath := filepath.Join(i.config.MountPoint, "etc", "ssl", "fipsmodule.cnf")
	opensslConfigPath := filepath.Join(i.config.MountPoint, "etc", "ssl", "openssl.cnf")

	i.logger.Info("Verifying FIPS OpenSSL configuration files")

	if _, err := os.Stat(fipsModulePath); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("FIPS module not found at %s", fipsModulePath), Err: err}
	}
	i.logger.Info("✓ FIPS module present", "path", fipsModulePath)

	if _, err := os.Stat(fipsConfigPath); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("fipsmodule.cnf not found at %s", fipsConfigPath), Err: err}
	}
	i.logger.Info("✓ FIPS module config present", "path", fipsConfigPath)

	if _, err := os.Stat(opensslConfigPath); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("openssl.cnf not found at %s", opensslConfigPath), Err: err}
	}

	// Check that openssl.cnf contains FIPS configuration
	content, err := os.ReadFile(opensslConfigPath)
	if err != nil {
		return &WrappedError{Msg: "failed to read openssl.cnf", Err: err}
	}

	if !strings.Contains(string(content), "fips_sect") {
		return &MessageError{Msg: "openssl.cnf does not contain FIPS configuration"}
	}
	i.logger.Info("✓ OpenSSL config contains FIPS settings", "path", opensslConfigPath)

	i.logger.Info("OpenSSL FIPS configuration completed successfully")
	return nil
}

// installFIPSKernel installs the pre-built FIPS kernel from ISO
func (i *FIPSInstaller) installFIPSKernel(ctx context.Context) error {
	i.logger.Info("Installing pre-built FIPS-capable kernel from ISO")

	// Check if FIPS artifacts are available on the ISO
	artifactsDir := i.artifactsDir
	if _, err := os.Stat(artifactsDir); os.IsNotExist(err) {
		return &MessageError{Msg: fmt.Sprintf("FIPS artifacts not found on ISO at %s. Was the ISO built with --fips flag?", artifactsDir)}
	}

	// 1. Copy pre-built FIPS kernel
	kernelSrc := filepath.Join(artifactsDir, "vmlinuz-fips")
	if _, err := os.Stat(kernelSrc); os.IsNotExist(err) {
		return &MessageError{Msg: fmt.Sprintf("FIPS kernel not found on ISO: %s", kernelSrc)}
	}

	// Ensure boot directory exists
	bootDir := filepath.Join(i.config.MountPoint, "boot")
	if err := os.MkdirAll(bootDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create boot directory", Err: err}
	}

	kernelDest := filepath.Join(bootDir, "vmlinuz-fips")
	i.logger.Info("Copying FIPS kernel", "source", kernelSrc, "destination", kernelDest)

	// Read and write kernel file
	kernelData, err := os.ReadFile(kernelSrc)
	if err != nil {
		return &WrappedError{Msg: "failed to read FIPS kernel", Err: err}
	}

	if err := os.WriteFile(kernelDest, kernelData, 0644); err != nil {
		return &WrappedError{Msg: "failed to write FIPS kernel", Err: err}
	}

	// 2. Extract pre-built kernel modules
	modulesSrc := filepath.Join(artifactsDir, "modules-fips.tar.gz")
	if _, err := os.Stat(modulesSrc); os.IsNotExist(err) {
		return &MessageError{Msg: fmt.Sprintf("FIPS kernel modules not found on ISO: %s", modulesSrc)}
	}

	i.logger.Info("Extracting FIPS kernel modules", "source", modulesSrc)
	extractCmd := exec.CommandContext(ctx, "tar", "-xzf", modulesSrc, "-C", i.config.MountPoint)
	if output, err := extractCmd.CombinedOutput(); err != nil {
		i.logger.Error("Failed to extract kernel modules",
			"output", string(output),
			"error", err)
		return &WrappedError{Msg: "failed to extract kernel modules", Err: err}
	}

	// 3. Run depmod to update module dependencies
	// First, we need to find the kernel version from the modules directory
	libModulesDir := filepath.Join(i.config.MountPoint, "lib", "modules")
	entries, err := os.ReadDir(libModulesDir)
	if err != nil {
		i.logger.Warn("Could not read modules directory to run depmod", "error", err)
	} else {
		// Find the FIPS kernel version directory
		for _, entry := range entries {
			if entry.IsDir() && strings.Contains(entry.Name(), "fips") {
				i.logger.Info("Running depmod for FIPS kernel", "version", entry.Name())
				depmodCmd := exec.CommandContext(ctx, "chroot", i.config.MountPoint,
					"depmod", "-a", entry.Name())
				if output, err := depmodCmd.CombinedOutput(); err != nil {
					i.logger.Warn("depmod failed (may not be critical)",
						"output", string(output),
						"error", err)
				}
				break
			}
		}
	}

	i.logger.Info("Pre-built FIPS kernel and modules installed successfully")
	return nil
}

// installOpenSSLFIPS installs the complete FIPS-validated OpenSSL from the ISO
func (i *FIPSInstaller) installOpenSSLFIPS(ctx context.Context) error {
	i.logger.Info("Installing FIPS provider module with system OpenSSL")

	// According to official OpenSSL FIPS documentation:
	//   - The FIPS provider module (fips.so) from OpenSSL 3.1.2 is FIPS 140-3 validated (Certificate #4985)
	//   - This module is COMPATIBLE with ANY OpenSSL 3.x version (3.0 - 3.5+)
	//   - We should NOT replace system OpenSSL libraries
	//   - Instead, copy ONLY the validated fips.so to the system
	//
	// This approach:
	//   - Maintains FIPS compliance (using validated FIPS provider from 3.1.2)
	//   - Ensures symbol compatibility (using Alpine's system OpenSSL 3.5.4 libraries)
	//   - Is officially supported per OpenSSL documentation
	//
	// References:
	//   - https://github.com/openssl/openssl/blob/master/README-FIPS.md
	//   - "The OpenSSL 3.1.2 FIPS module is compatible with any version of OpenSSL 3.0-3.5+"
	//   - Web search confirms OSSL_get_max_threads/OSSL_set_max_threads added in 3.2

	// Step 1: Install Alpine's system OpenSSL package
	i.logger.Info("Installing Alpine's system OpenSSL package")
	apkCmd := exec.CommandContext(ctx, "chroot", i.config.MountPoint, "apk", "add", "openssl")
	if output, err := apkCmd.CombinedOutput(); err != nil {
		i.logger.Error("Failed to install OpenSSL package",
			"output", string(output),
			"error", err)
		return &WrappedError{Msg: "failed to install OpenSSL package", Err: err}
	}
	i.logger.Info("Alpine's system OpenSSL installed successfully")

	// Step 2: Copy ONLY the FIPS provider module from ISO
	artifactsDir := i.artifactsDir
	fipsModuleSrc := filepath.Join(artifactsDir, "usr", "lib", "ossl-modules", "fips.so")

	// Verify the FIPS module exists on the ISO
	if _, err := os.Stat(fipsModuleSrc); os.IsNotExist(err) {
		return &MessageError{Msg: fmt.Sprintf("FIPS provider module not found on ISO at %s. Was the ISO built with --fips flag?", fipsModuleSrc)}
	}

	i.logger.Info("Found FIPS provider module on ISO", "source", fipsModuleSrc)

	// Create the modules directory
	modulesDir := filepath.Join(i.config.MountPoint, "usr", "lib", "ossl-modules")
	if err := os.MkdirAll(modulesDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create modules directory", Err: err}
	}

	// Copy the FIPS provider module
	fipsModuleDest := filepath.Join(modulesDir, "fips.so")
	fipsData, err := os.ReadFile(fipsModuleSrc)
	if err != nil {
		return &WrappedError{Msg: "failed to read FIPS module", Err: err}
	}

	if err := os.WriteFile(fipsModuleDest, fipsData, 0644); err != nil {
		return &WrappedError{Msg: "failed to write FIPS module", Err: err}
	}

	// Verify the FIPS module was copied
	if _, err := os.Stat(fipsModuleDest); err != nil {
		return &WrappedError{Msg: "FIPS module not found after copy", Err: err}
	}

	i.logger.Info("FIPS provider module installed successfully",
		"module", "/usr/lib/ossl-modules/fips.so",
		"note", "Using Alpine's system OpenSSL 3.5.4 libraries for compatibility")

	return nil
}

// configureOpenSSLFIPS configures OpenSSL to use FIPS mode
func (i *FIPSInstaller) configureOpenSSLFIPS() error {
	i.logger.Info("Configuring OpenSSL for FIPS mode")

	// Generate FIPS module configuration
	if err := i.generateFIPSModuleConfig(); err != nil {
		return &WrappedError{Msg: "failed to generate FIPS module config", Err: err}
	}

	// Update OpenSSL configuration
	if err := i.updateOpenSSLConfig(); err != nil {
		return &WrappedError{Msg: "failed to update OpenSSL config", Err: err}
	}

	return nil
}

// generateFIPSModuleConfig runs openssl fipsinstall to generate fipsmodule.cnf
func (i *FIPSInstaller) generateFIPSModuleConfig() error {
	fipsConfigPath := filepath.Join(i.config.MountPoint, "etc", "ssl", "fipsmodule.cnf")

	i.logger.Info("Generating FIPS module configuration",
		"config", fipsConfigPath)

	// Ensure /etc/ssl directory exists
	sslDir := filepath.Join(i.config.MountPoint, "etc", "ssl")
	if err := os.MkdirAll(sslDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create /etc/ssl directory", Err: err}
	}

	// FIPS module was installed to /usr/lib/ossl-modules/fips.so by installOpenSSLFIPS
	fipsModulePath := "/usr/lib/ossl-modules/fips.so"

	// Verify the module exists
	fullPath := filepath.Join(i.config.MountPoint, fipsModulePath[1:]) // Remove leading /
	if _, err := os.Stat(fullPath); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("FIPS module not found at %s", fipsModulePath), Err: err}
	}

	i.logger.Info("Found FIPS module", "path", fipsModulePath)

	// Check if openssl is available in chroot
	opensslPath := filepath.Join(i.config.MountPoint, "usr", "bin", "openssl")
	if _, err := os.Stat(opensslPath); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("openssl binary not found in chroot at %s", opensslPath), Err: err}
	}
	i.logger.Info("OpenSSL binary found in chroot", "path", opensslPath)

	// Run openssl fipsinstall in chroot to generate the FIPS module configuration
	// Note: openssl fipsinstall computes the module's checksum and creates config
	i.logger.Info("Running openssl fipsinstall in chroot",
		"module", fipsModulePath,
		"output", "/etc/ssl/fipsmodule.cnf")

	cmd := exec.Command("chroot", i.config.MountPoint,
		"openssl", "fipsinstall",
		"-out", "/etc/ssl/fipsmodule.cnf",
		"-module", fipsModulePath)

	output, err := cmd.CombinedOutput()
	if err != nil {
		i.logger.Error("Failed to run openssl fipsinstall",
			"output", string(output),
			"error", err)
		return &CommandOutputError{Msg: "failed to run openssl fipsinstall", Err: err, Detail: fmt.Sprintf("\nOutput: %s", string(output))}
	}

	// Verify the config was created
	if _, err := os.Stat(fipsConfigPath); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("fipsmodule.cnf was not created at %s", fipsConfigPath), Err: err}
	}

	i.logger.Info("FIPS module configuration generated successfully",
		"config", fipsConfigPath)

	return nil
}

// updateOpenSSLConfig updates /etc/ssl/openssl.cnf to enable FIPS
// Following the reference project at build/iso/alpine/amd64/scripts/host/upgrade-kernel.sh
func (i *FIPSInstaller) updateOpenSSLConfig() error {
	opensslConfigPath := filepath.Join(i.config.MountPoint, "etc", "ssl", "openssl.cnf")

	i.logger.Info("Replacing OpenSSL configuration with FIPS-enabled config", "path", opensslConfigPath)

	// Backup existing config if it exists
	if _, err := os.Stat(opensslConfigPath); err == nil {
		backupPath := opensslConfigPath + ".backup"
		content, err := os.ReadFile(opensslConfigPath)
		if err == nil {
			_ = os.WriteFile(backupPath, content, 0644)
			i.logger.Info("Backed up original openssl.cnf", "backup", backupPath)
		}
	}

	// REPLACE entire openssl.cnf with minimal FIPS configuration
	// This matches EXACTLY what the reference project does in upgrade-kernel.sh:175-197
	fipsConfig := `config_diagnostics = 1
openssl_conf = openssl_init

.include /etc/ssl/fipsmodule.cnf

[openssl_init]
providers = provider_sect
alg_section = algorithm_sect

[provider_sect]
fips = fips_sect
base = base_sect

[base_sect]
activate = 1

[fips_sect]
activate = 1

[algorithm_sect]
default_properties = fips=yes
`

	if err := os.WriteFile(opensslConfigPath, []byte(fipsConfig), 0644); err != nil {
		return &WrappedError{Msg: "failed to write openssl.cnf", Err: err}
	}

	i.logger.Info("OpenSSL configuration replaced with FIPS settings",
		"path", opensslConfigPath)

	return nil
}

// installPackage downloads and installs an Alpine package
func (i *FIPSInstaller) installPackage(ctx context.Context, pkgName string) error {
	i.logger.Info("Installing package", "package", pkgName)

	// Use APK manager to download and install the package
	if err := i.apkManager.DownloadAndInstall(ctx, pkgName, i.config.MountPoint); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("failed to install %s", pkgName), Err: err}
	}

	return nil
}
