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

package vtpm

import (
	"fmt"
	"os"
	"path/filepath"
)

// Config holds the configuration for the vTPM service.
type Config struct {
	// BaseDir is the base directory for vTPM bundles and templates.
	// Bundles are stored in BaseDir/bundles/{id}/
	// Templates are stored in BaseDir/templates/{id}/
	BaseDir string `yaml:"base-dir" json:"base_dir"`

	// OVMFCode is the path to OVMF firmware code.
	OVMFCode string `yaml:"ovmf-code" json:"ovmf_code"`

	// OVMFCodeSecure is the path to OVMF firmware code with Secure Boot.
	OVMFCodeSecure string `yaml:"ovmf-code-secure" json:"ovmf_code_secure"`

	// OVMFVars is the path to OVMF NVRAM template.
	OVMFVars string `yaml:"ovmf-vars" json:"ovmf_vars"`

	// PCRBanks specifies the PCR banks for swtpm initialization.
	// Default: ["sha256"]
	PCRBanks []string `yaml:"pcr-banks" json:"pcr_banks"`

	// SecureBootKeysDir is the optional path to existing Secure Boot keys.
	// If not set, keys will be generated for each bundle/template.
	SecureBootKeysDir string `yaml:"secure-boot-keys-dir" json:"secure_boot_keys_dir"`

	// SecureBootKeySize is the RSA key size for Secure Boot keys.
	// Default: 2048
	SecureBootKeySize int `yaml:"secure-boot-key-size" json:"secure_boot_key_size"`

	// SecureBootValidYears is the certificate validity in years.
	// Default: 10
	SecureBootValidYears int `yaml:"secure-boot-valid-years" json:"secure_boot_valid_years"`

	// SecureBootCommonName is the CN prefix for Secure Boot certificates.
	// Default: "Trusted Platform"
	SecureBootCommonName string `yaml:"secure-boot-common-name" json:"secure_boot_common_name"`

	// SecureBootOrganization is the organization for Secure Boot certificates.
	// Default: "Trusted Platform"
	SecureBootOrganization string `yaml:"secure-boot-organization" json:"secure_boot_organization"`

	// EKAlgorithm is the default EK key algorithm.
	// Default: "RSA"
	EKAlgorithm EKAlgorithm `yaml:"ek-algorithm" json:"ek_algorithm"`

	// Debug enables debug output.
	Debug bool `yaml:"debug" json:"debug"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		BaseDir:                "/var/lib/trusted-platform/vtpm",
		OVMFCode:               "/usr/share/OVMF/OVMF_CODE_4M.fd",
		OVMFCodeSecure:         "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
		OVMFVars:               "/usr/share/OVMF/OVMF_VARS_4M.fd",
		PCRBanks:               []string{"sha256"},
		SecureBootKeySize:      2048,
		SecureBootValidYears:   10,
		SecureBootCommonName:   "Trusted Platform",
		SecureBootOrganization: "Trusted Platform",
		EKAlgorithm:            EKAlgorithmRSA,
		Debug:                  false,
	}
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	if c.BaseDir == "" {
		return ErrInvalidConfig{Field: "BaseDir", Reason: "cannot be empty"}
	}

	if c.OVMFCode == "" {
		return ErrInvalidConfig{Field: "OVMFCode", Reason: "cannot be empty"}
	}

	if c.OVMFVars == "" {
		return ErrInvalidConfig{Field: "OVMFVars", Reason: "cannot be empty"}
	}

	// Check OVMF files exist
	if _, err := os.Stat(c.OVMFCode); err != nil {
		return ErrOVMFNotFound{Path: c.OVMFCode}
	}

	if _, err := os.Stat(c.OVMFVars); err != nil {
		return ErrOVMFNotFound{Path: c.OVMFVars}
	}

	// OVMFCodeSecure is optional, only validate if specified
	if c.OVMFCodeSecure != "" {
		if _, err := os.Stat(c.OVMFCodeSecure); err != nil {
			return ErrOVMFNotFound{Path: c.OVMFCodeSecure}
		}
	}

	// Validate PCR banks
	if len(c.PCRBanks) == 0 {
		return ErrInvalidConfig{Field: "PCRBanks", Reason: "at least one PCR bank is required"}
	}

	validBanks := map[string]bool{"sha1": true, "sha256": true, "sha384": true, "sha512": true}
	for _, bank := range c.PCRBanks {
		if !validBanks[bank] {
			return ErrInvalidConfig{Field: "PCRBanks", Reason: fmt.Sprintf("invalid PCR bank: %s", bank)}
		}
	}

	// Validate Secure Boot key size
	if c.SecureBootKeySize < 2048 {
		return ErrInvalidConfig{Field: "SecureBootKeySize", Reason: "must be at least 2048"}
	}

	// Validate EK algorithm
	if c.EKAlgorithm != "" && !c.EKAlgorithm.IsValid() {
		return ErrInvalidConfig{Field: "EKAlgorithm", Reason: fmt.Sprintf("invalid algorithm: %s", c.EKAlgorithm)}
	}

	// Validate Secure Boot keys directory if specified
	if c.SecureBootKeysDir != "" {
		if _, err := os.Stat(c.SecureBootKeysDir); err != nil {
			return ErrInvalidConfig{Field: "SecureBootKeysDir", Reason: fmt.Sprintf("directory not found: %s", c.SecureBootKeysDir)}
		}
	}

	return nil
}

// BundlesDir returns the path to the bundles directory.
func (c *Config) BundlesDir() string {
	return filepath.Join(c.BaseDir, "bundles")
}

// TemplatesDir returns the path to the templates directory.
func (c *Config) TemplatesDir() string {
	return filepath.Join(c.BaseDir, "templates")
}

// BundlePath returns the path to a specific bundle.
func (c *Config) BundlePath(id string) string {
	return filepath.Join(c.BundlesDir(), id)
}

// TemplatePath returns the path to a specific template.
func (c *Config) TemplatePath(id string) string {
	return filepath.Join(c.TemplatesDir(), id)
}

// GetOVMFCodePath returns the appropriate OVMF code path based on Secure Boot setting.
func (c *Config) GetOVMFCodePath(secureBoot bool) string {
	if secureBoot && c.OVMFCodeSecure != "" {
		return c.OVMFCodeSecure
	}
	return c.OVMFCode
}

// ApplyDefaults applies default values to empty fields.
func (c *Config) ApplyDefaults() {
	defaults := DefaultConfig()

	if c.BaseDir == "" {
		c.BaseDir = defaults.BaseDir
	}
	if c.OVMFCode == "" {
		c.OVMFCode = defaults.OVMFCode
	}
	if c.OVMFCodeSecure == "" {
		c.OVMFCodeSecure = defaults.OVMFCodeSecure
	}
	if c.OVMFVars == "" {
		c.OVMFVars = defaults.OVMFVars
	}
	if len(c.PCRBanks) == 0 {
		c.PCRBanks = defaults.PCRBanks
	}
	if c.SecureBootKeySize == 0 {
		c.SecureBootKeySize = defaults.SecureBootKeySize
	}
	if c.SecureBootValidYears == 0 {
		c.SecureBootValidYears = defaults.SecureBootValidYears
	}
	if c.SecureBootCommonName == "" {
		c.SecureBootCommonName = defaults.SecureBootCommonName
	}
	if c.SecureBootOrganization == "" {
		c.SecureBootOrganization = defaults.SecureBootOrganization
	}
	if c.EKAlgorithm == "" {
		c.EKAlgorithm = defaults.EKAlgorithm
	}
}
