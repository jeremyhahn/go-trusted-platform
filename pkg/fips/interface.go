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

package fips

import (
	"context"
	"log/slog"
)

// Installer is the generic interface for FIPS installation across different operating systems
type Installer interface {
	// Install performs complete FIPS installation including:
	// - FIPS-enabled kernel installation
	// - OpenSSL FIPS module installation
	// - FIPS configuration
	// - Verification
	Install(ctx context.Context) error

	// InstallKernel installs ONLY the FIPS kernel and modules
	// This must be called BEFORE building UKI, as the kernel is required for dracut
	InstallKernel(ctx context.Context) error

	// ConfigureOpenSSL installs and configures OpenSSL for FIPS mode
	// This must be called AFTER signing UKI, as FIPS mode breaks OpenSSL signing operations
	ConfigureOpenSSL(ctx context.Context) error

	// Verify checks if FIPS is properly installed and configured
	Verify() error

	// GetKernelCommandLine returns the required kernel command line parameters for FIPS mode
	GetKernelCommandLine() string
}

// Config holds common FIPS configuration options
type Config struct {
	// OS name (alpine, ubuntu, debian, etc.)
	OS string

	// OS version
	Version string

	// Architecture (x86_64, aarch64)
	Arch string

	// Mirror URL for package downloads
	Mirror string

	// Work directory for downloads and temporary files
	WorkDir string

	// Mount point of target system
	MountPoint string

	// Enable debug output
	Debug bool

	// Logger instance
	Logger *slog.Logger
}

// InstallerFactory is a function that creates a FIPS installer
type InstallerFactory func(*Config) (Installer, error)

var installerRegistry = make(map[string]InstallerFactory)

// RegisterInstaller registers a FIPS installer factory for a specific OS
func RegisterInstaller(os string, factory InstallerFactory) {
	installerRegistry[os] = factory
}

// NewInstaller creates the appropriate FIPS installer for the given OS
func NewInstaller(config *Config) (Installer, error) {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	// Look up registered installer factory
	factory, ok := installerRegistry[config.OS]
	if !ok {
		return nil, ErrUnsupportedOS
	}

	return factory(config)
}
