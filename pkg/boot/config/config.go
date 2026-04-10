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

// Package config provides minimal configuration types for boot commands.
// This package is intentionally kept lightweight to minimize dependencies
// in the platform-initrd binary. It avoids importing heavy packages like
// pkg/app and pkg/installer which pull in QuicBaaS, DNS services, etc.
package config

// InstallerPassword is a well-known password for the installer container.
// Used to unlock installer.luks during boot to access TPM seal objects.
//
// Security consideration: This password provides forensic protection only.
// The installer container is mounted read-only and contains no sensitive data
// other than the initial seal objects which are protected by the TPM.
const InstallerPassword = "forensic-protection-only"

// BootConfig represents the minimal config fields needed for boot operations.
// This is a lightweight alternative to pkg/app.App for parsing config.yaml
// during boot without pulling in heavy dependencies.
type BootConfig struct {
	// SealPCRs specifies the PCR registers to seal LUKS keys against.
	// Example: [0, 7, 9] for firmware, secure boot, and kernel measurements.
	SealPCRs []uint `yaml:"seal-pcrs,omitempty" json:"seal_pcrs,omitempty" mapstructure:"seal-pcrs"`

	// SecureWipePasses specifies the number of secure wipe passes.
	// Default is 1 (NIST SP 800-88 compliant).
	SecureWipePasses int `yaml:"secure-wipe-passes,omitempty" json:"secure_wipe_passes,omitempty" mapstructure:"secure-wipe-passes"`
}
