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
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.BaseDir != "/var/lib/trusted-platform/vtpm" {
		t.Errorf("DefaultConfig().BaseDir = %v, want /var/lib/trusted-platform/vtpm", config.BaseDir)
	}

	if len(config.PCRBanks) == 0 {
		t.Error("DefaultConfig().PCRBanks should not be empty")
	}

	if config.PCRBanks[0] != "sha256" {
		t.Errorf("DefaultConfig().PCRBanks[0] = %v, want sha256", config.PCRBanks[0])
	}

	if config.SecureBootKeySize != 2048 {
		t.Errorf("DefaultConfig().SecureBootKeySize = %v, want 2048", config.SecureBootKeySize)
	}

	if config.EKAlgorithm != EKAlgorithmRSA {
		t.Errorf("DefaultConfig().EKAlgorithm = %v, want RSA", config.EKAlgorithm)
	}
}

func TestConfig_Validate_EmptyBaseDir(t *testing.T) {
	config := DefaultConfig()
	config.BaseDir = ""

	err := config.Validate()
	if err == nil {
		t.Error("Validate() should return error for empty BaseDir")
	}

	if _, ok := err.(ErrInvalidConfig); !ok {
		t.Errorf("Validate() error type = %T, want ErrInvalidConfig", err)
	}
}

func TestConfig_Validate_EmptyOVMFCode(t *testing.T) {
	config := DefaultConfig()
	config.OVMFCode = ""

	err := config.Validate()
	if err == nil {
		t.Error("Validate() should return error for empty OVMFCode")
	}
}

func TestConfig_Validate_EmptyOVMFVars(t *testing.T) {
	config := DefaultConfig()
	config.OVMFVars = ""

	err := config.Validate()
	if err == nil {
		t.Error("Validate() should return error for empty OVMFVars")
	}
}

func TestConfig_Validate_EmptyPCRBanks(t *testing.T) {
	config := DefaultConfig()
	config.PCRBanks = nil

	// Create temp OVMF files to pass file existence check
	tmpDir := t.TempDir()
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")
	os.WriteFile(ovmfCode, []byte("test"), 0644)
	os.WriteFile(ovmfVars, []byte("test"), 0644)
	config.OVMFCode = ovmfCode
	config.OVMFVars = ovmfVars

	err := config.Validate()
	if err == nil {
		t.Error("Validate() should return error for empty PCRBanks")
	}
}

func TestConfig_Validate_InvalidPCRBank(t *testing.T) {
	config := DefaultConfig()
	config.PCRBanks = []string{"sha256", "invalid-bank"}

	// Create temp OVMF files
	tmpDir := t.TempDir()
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")
	os.WriteFile(ovmfCode, []byte("test"), 0644)
	os.WriteFile(ovmfVars, []byte("test"), 0644)
	config.OVMFCode = ovmfCode
	config.OVMFVars = ovmfVars

	err := config.Validate()
	if err == nil {
		t.Error("Validate() should return error for invalid PCR bank")
	}
}

func TestConfig_Validate_SmallKeySize(t *testing.T) {
	config := DefaultConfig()
	config.SecureBootKeySize = 1024

	// Create temp OVMF files
	tmpDir := t.TempDir()
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")
	os.WriteFile(ovmfCode, []byte("test"), 0644)
	os.WriteFile(ovmfVars, []byte("test"), 0644)
	config.OVMFCode = ovmfCode
	config.OVMFVars = ovmfVars

	err := config.Validate()
	if err == nil {
		t.Error("Validate() should return error for key size < 2048")
	}
}

func TestConfig_Validate_InvalidEKAlgorithm(t *testing.T) {
	config := DefaultConfig()
	config.EKAlgorithm = EKAlgorithm("INVALID")

	// Create temp OVMF files
	tmpDir := t.TempDir()
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")
	os.WriteFile(ovmfCode, []byte("test"), 0644)
	os.WriteFile(ovmfVars, []byte("test"), 0644)
	config.OVMFCode = ovmfCode
	config.OVMFVars = ovmfVars

	err := config.Validate()
	if err == nil {
		t.Error("Validate() should return error for invalid EK algorithm")
	}
}

func TestConfig_Validate_NonexistentSecureBootKeysDir(t *testing.T) {
	config := DefaultConfig()
	config.SecureBootKeysDir = "/nonexistent/path"

	// Create temp OVMF files
	tmpDir := t.TempDir()
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")
	os.WriteFile(ovmfCode, []byte("test"), 0644)
	os.WriteFile(ovmfVars, []byte("test"), 0644)
	config.OVMFCode = ovmfCode
	config.OVMFVars = ovmfVars

	err := config.Validate()
	if err == nil {
		t.Error("Validate() should return error for nonexistent SecureBootKeysDir")
	}
}

func TestConfig_BundlesDir(t *testing.T) {
	config := &Config{BaseDir: "/var/lib/vtpm"}
	expected := "/var/lib/vtpm/bundles"

	if got := config.BundlesDir(); got != expected {
		t.Errorf("BundlesDir() = %v, want %v", got, expected)
	}
}

func TestConfig_TemplatesDir(t *testing.T) {
	config := &Config{BaseDir: "/var/lib/vtpm"}
	expected := "/var/lib/vtpm/templates"

	if got := config.TemplatesDir(); got != expected {
		t.Errorf("TemplatesDir() = %v, want %v", got, expected)
	}
}

func TestConfig_BundlePath(t *testing.T) {
	config := &Config{BaseDir: "/var/lib/vtpm"}
	expected := "/var/lib/vtpm/bundles/test-bundle"

	if got := config.BundlePath("test-bundle"); got != expected {
		t.Errorf("BundlePath() = %v, want %v", got, expected)
	}
}

func TestConfig_TemplatePath(t *testing.T) {
	config := &Config{BaseDir: "/var/lib/vtpm"}
	expected := "/var/lib/vtpm/templates/base-template"

	if got := config.TemplatePath("base-template"); got != expected {
		t.Errorf("TemplatePath() = %v, want %v", got, expected)
	}
}

func TestConfig_GetOVMFCodePath(t *testing.T) {
	config := &Config{
		OVMFCode:       "/usr/share/OVMF/OVMF_CODE.fd",
		OVMFCodeSecure: "/usr/share/OVMF/OVMF_CODE.secboot.fd",
	}

	// Without Secure Boot
	if got := config.GetOVMFCodePath(false); got != config.OVMFCode {
		t.Errorf("GetOVMFCodePath(false) = %v, want %v", got, config.OVMFCode)
	}

	// With Secure Boot
	if got := config.GetOVMFCodePath(true); got != config.OVMFCodeSecure {
		t.Errorf("GetOVMFCodePath(true) = %v, want %v", got, config.OVMFCodeSecure)
	}

	// With Secure Boot but no secure path configured
	config.OVMFCodeSecure = ""
	if got := config.GetOVMFCodePath(true); got != config.OVMFCode {
		t.Errorf("GetOVMFCodePath(true) with empty OVMFCodeSecure = %v, want %v", got, config.OVMFCode)
	}
}

func TestConfig_ApplyDefaults(t *testing.T) {
	config := &Config{}
	config.ApplyDefaults()

	defaults := DefaultConfig()

	if config.BaseDir != defaults.BaseDir {
		t.Errorf("ApplyDefaults() BaseDir = %v, want %v", config.BaseDir, defaults.BaseDir)
	}

	if config.OVMFCode != defaults.OVMFCode {
		t.Errorf("ApplyDefaults() OVMFCode = %v, want %v", config.OVMFCode, defaults.OVMFCode)
	}

	if config.EKAlgorithm != defaults.EKAlgorithm {
		t.Errorf("ApplyDefaults() EKAlgorithm = %v, want %v", config.EKAlgorithm, defaults.EKAlgorithm)
	}

	if config.SecureBootKeySize != defaults.SecureBootKeySize {
		t.Errorf("ApplyDefaults() SecureBootKeySize = %v, want %v", config.SecureBootKeySize, defaults.SecureBootKeySize)
	}
}

func TestConfig_ApplyDefaults_PreservesExisting(t *testing.T) {
	config := &Config{
		BaseDir:           "/custom/path",
		EKAlgorithm:       EKAlgorithmECC,
		SecureBootKeySize: 4096,
	}
	config.ApplyDefaults()

	if config.BaseDir != "/custom/path" {
		t.Errorf("ApplyDefaults() overwrote BaseDir = %v, want /custom/path", config.BaseDir)
	}

	if config.EKAlgorithm != EKAlgorithmECC {
		t.Errorf("ApplyDefaults() overwrote EKAlgorithm = %v, want ECC", config.EKAlgorithm)
	}

	if config.SecureBootKeySize != 4096 {
		t.Errorf("ApplyDefaults() overwrote SecureBootKeySize = %v, want 4096", config.SecureBootKeySize)
	}
}

// =============================================================================
// Additional Config Tests for Coverage
// =============================================================================

func TestConfig_ApplyDefaults_AllFields(t *testing.T) {
	config := &Config{}
	config.ApplyDefaults()

	defaults := DefaultConfig()

	if config.OVMFCodeSecure != defaults.OVMFCodeSecure {
		t.Errorf("OVMFCodeSecure = %v, want %v", config.OVMFCodeSecure, defaults.OVMFCodeSecure)
	}
	if config.SecureBootValidYears != defaults.SecureBootValidYears {
		t.Errorf("SecureBootValidYears = %v, want %v", config.SecureBootValidYears, defaults.SecureBootValidYears)
	}
	if config.SecureBootCommonName != defaults.SecureBootCommonName {
		t.Errorf("SecureBootCommonName = %v, want %v", config.SecureBootCommonName, defaults.SecureBootCommonName)
	}
	if config.SecureBootOrganization != defaults.SecureBootOrganization {
		t.Errorf("SecureBootOrganization = %v, want %v", config.SecureBootOrganization, defaults.SecureBootOrganization)
	}
}

func TestDefaultConfig_AllFields(t *testing.T) {
	config := DefaultConfig()

	// Test all default values
	if config.OVMFCodeSecure == "" {
		t.Error("DefaultConfig should set OVMFCodeSecure")
	}
	if config.SecureBootValidYears != 10 {
		t.Errorf("SecureBootValidYears = %d, want 10", config.SecureBootValidYears)
	}
	if config.SecureBootCommonName != "Trusted Platform" {
		t.Errorf("SecureBootCommonName = %v, want 'Trusted Platform'", config.SecureBootCommonName)
	}
	if config.SecureBootOrganization != "Trusted Platform" {
		t.Errorf("SecureBootOrganization = %v, want 'Trusted Platform'", config.SecureBootOrganization)
	}
	if config.Debug != false {
		t.Error("DefaultConfig.Debug should be false")
	}
}

func TestConfig_Validate_AllValidPCRBanks(t *testing.T) {
	tmpDir := t.TempDir()
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")
	os.WriteFile(ovmfCode, []byte("test"), 0644)
	os.WriteFile(ovmfVars, []byte("test"), 0644)

	// Test with all valid banks at once
	config := &Config{
		BaseDir:           tmpDir,
		OVMFCode:          ovmfCode,
		OVMFVars:          ovmfVars,
		PCRBanks:          []string{"sha1", "sha256", "sha384", "sha512"},
		SecureBootKeySize: 2048,
	}

	err := config.Validate()
	if err != nil {
		t.Errorf("Validate should pass for all valid PCR banks: %v", err)
	}
}

func TestConfig_Validate_SecureBootKeySize_Boundary(t *testing.T) {
	tmpDir := t.TempDir()
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")
	os.WriteFile(ovmfCode, []byte("test"), 0644)
	os.WriteFile(ovmfVars, []byte("test"), 0644)

	// Test exactly 2048 - should pass
	config := &Config{
		BaseDir:           tmpDir,
		OVMFCode:          ovmfCode,
		OVMFVars:          ovmfVars,
		PCRBanks:          []string{"sha256"},
		SecureBootKeySize: 2048,
	}

	err := config.Validate()
	if err != nil {
		t.Errorf("Validate should pass for SecureBootKeySize=2048: %v", err)
	}

	// Test 2047 - should fail
	config.SecureBootKeySize = 2047
	err = config.Validate()
	if err == nil {
		t.Error("Validate should fail for SecureBootKeySize=2047")
	}
}

func TestConfig_Validate_EKAlgorithm_ECC(t *testing.T) {
	tmpDir := t.TempDir()
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")
	os.WriteFile(ovmfCode, []byte("test"), 0644)
	os.WriteFile(ovmfVars, []byte("test"), 0644)

	config := &Config{
		BaseDir:           tmpDir,
		OVMFCode:          ovmfCode,
		OVMFVars:          ovmfVars,
		PCRBanks:          []string{"sha256"},
		EKAlgorithm:       EKAlgorithmECC,
		SecureBootKeySize: 2048,
	}

	err := config.Validate()
	if err != nil {
		t.Errorf("Validate should pass for EKAlgorithmECC: %v", err)
	}
}

func TestConfig_Validate_EKAlgorithm_RSA(t *testing.T) {
	tmpDir := t.TempDir()
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")
	os.WriteFile(ovmfCode, []byte("test"), 0644)
	os.WriteFile(ovmfVars, []byte("test"), 0644)

	config := &Config{
		BaseDir:           tmpDir,
		OVMFCode:          ovmfCode,
		OVMFVars:          ovmfVars,
		PCRBanks:          []string{"sha256"},
		EKAlgorithm:       EKAlgorithmRSA,
		SecureBootKeySize: 2048,
	}

	err := config.Validate()
	if err != nil {
		t.Errorf("Validate should pass for EKAlgorithmRSA: %v", err)
	}
}
