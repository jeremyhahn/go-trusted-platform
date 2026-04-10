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

package qemu

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uefi"
)

// SecureBootEnroller handles Secure Boot key enrollment operations for QEMU/OVMF
type SecureBootEnroller struct {
	keysDir      string
	nvramDir     string
	ovmfVarsPath string
	logger       *logging.Logger
	debug        bool
	ownerGUID    uefi.GUID
}

// SecureBootEnrollerConfig contains configuration for the SecureBootEnroller
type SecureBootEnrollerConfig struct {
	// KeysDir is the directory containing Secure Boot keys (PK.crt, KEK.crt, DB.crt)
	KeysDir string

	// NVRAMDir is the directory where NVRAM files will be stored
	NVRAMDir string

	// OVMFVarsPath is the path to the OVMF_VARS template file
	OVMFVarsPath string

	// OwnerGUID is the GUID to use as the key owner (optional)
	// If not specified, a new GUID will be generated
	OwnerGUID *uefi.GUID

	// Debug enables debug output
	Debug bool
}

// NewSecureBootEnroller creates a new Secure Boot key enroller
func NewSecureBootEnroller(config *SecureBootEnrollerConfig, logger *logging.Logger) (*SecureBootEnroller, error) {
	if config == nil {
		return nil, fmt.Errorf("%w: config cannot be nil", ErrInvalidConfiguration)
	}

	if logger == nil {
		logger = logging.DefaultLogger()
	}

	// Validate keys directory
	if config.KeysDir == "" {
		return nil, fmt.Errorf("%w: keys directory not specified", ErrInvalidConfiguration)
	}

	if _, err := os.Stat(config.KeysDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("%w: keys directory does not exist: %s", ErrKeysNotFound, config.KeysDir)
	}

	// Validate required key files exist
	requiredKeys := []string{"PK.crt", "KEK.crt", "DB.crt"}
	for _, keyFile := range requiredKeys {
		keyPath := filepath.Join(config.KeysDir, keyFile)
		if _, err := os.Stat(keyPath); os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: required key file missing: %s", ErrKeysNotFound, keyPath)
		}
	}

	// Validate OVMF VARS template
	if config.OVMFVarsPath == "" {
		return nil, fmt.Errorf("%w: OVMF VARS path not specified", ErrInvalidConfiguration)
	}

	if _, err := os.Stat(config.OVMFVarsPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("%w: OVMF VARS template not found: %s", ErrNVRAMNotFound, config.OVMFVarsPath)
	}

	// Validate NVRAM directory
	if config.NVRAMDir == "" {
		return nil, fmt.Errorf("%w: NVRAM directory not specified", ErrInvalidConfiguration)
	}

	// Set owner GUID
	ownerGUID := uefi.NewGUID()
	if config.OwnerGUID != nil {
		ownerGUID = *config.OwnerGUID
	}

	logger.Debug("SecureBootEnroller initialized",
		"keys_dir", config.KeysDir,
		"nvram_dir", config.NVRAMDir,
		"ovmf_vars", config.OVMFVarsPath,
		"owner_guid", ownerGUID.String())

	return &SecureBootEnroller{
		keysDir:      config.KeysDir,
		nvramDir:     config.NVRAMDir,
		ovmfVarsPath: config.OVMFVarsPath,
		logger:       logger,
		debug:        config.Debug,
		ownerGUID:    ownerGUID,
	}, nil
}

// IsEnrolled checks if Secure Boot keys are already enrolled
// Returns true if the enrollment flag exists, NVRAM file exists, and
// the keys haven't been regenerated since enrollment (flag is newer than keys)
func (e *SecureBootEnroller) IsEnrolled() bool {
	flagPath := filepath.Join(e.nvramDir, "OVMF_VARS_ENROLLED.flag")
	nvramPath := filepath.Join(e.nvramDir, "OVMF_VARS.fd")

	flagExists := fileExists(flagPath)
	nvramExists := fileExists(nvramPath)

	if !flagExists || !nvramExists {
		e.logger.Debug("Enrollment check: missing files",
			"flag_exists", flagExists,
			"nvram_exists", nvramExists)
		return false
	}

	// Check if any key files are newer than the enrollment flag
	// This handles the case where keys were regenerated after enrollment
	flagInfo, err := os.Stat(flagPath)
	if err != nil {
		e.logger.Debug("Cannot stat enrollment flag", "error", err)
		return false
	}

	keyFiles := []string{"PK.crt", "KEK.crt", "DB.crt"}
	for _, keyFile := range keyFiles {
		keyPath := filepath.Join(e.keysDir, keyFile)
		keyInfo, err := os.Stat(keyPath)
		if err != nil {
			// Key file doesn't exist or can't be read
			e.logger.Debug("Cannot stat key file", "file", keyFile, "error", err)
			continue
		}

		if keyInfo.ModTime().After(flagInfo.ModTime()) {
			e.logger.Info("Keys regenerated since last enrollment, re-enrollment required",
				"key_file", keyFile,
				"key_time", keyInfo.ModTime(),
				"flag_time", flagInfo.ModTime())
			return false
		}
	}

	e.logger.Debug("Enrollment status: keys enrolled and up-to-date",
		"flag_exists", flagExists,
		"nvram_exists", nvramExists)

	return true
}

// InitializeNVRAM initializes NVRAM from template if needed
// This creates OVMF_VARS_INSTALL.fd for install (no Secure Boot)
// and prepares the environment for enrollment
func (e *SecureBootEnroller) InitializeNVRAM(nvramFile string) error {
	// Create NVRAM directory if it doesn't exist
	if err := os.MkdirAll(e.nvramDir, 0755); err != nil {
		return fmt.Errorf("failed to create NVRAM directory: %w", err)
	}

	nvramPath := filepath.Join(e.nvramDir, nvramFile)

	// Check if NVRAM file already exists
	if fileExists(nvramPath) {
		e.logger.Debug("NVRAM file already exists",
			"path", nvramPath)
		return nil
	}

	e.logger.Info("Initializing NVRAM from template",
		"template", e.ovmfVarsPath,
		"target", nvramPath)

	// Copy OVMF VARS template
	if err := copyFile(e.ovmfVarsPath, nvramPath); err != nil {
		return fmt.Errorf("failed to copy OVMF VARS template: %w", err)
	}

	// Set permissions
	if err := os.Chmod(nvramPath, 0644); err != nil {
		return fmt.Errorf("failed to set NVRAM file permissions: %w", err)
	}

	e.logger.Debug("NVRAM file initialized successfully",
		"path", nvramPath)

	return nil
}

// EnrollKeys enrolls Secure Boot keys into OVMF NVRAM using native Go implementation
// This enrolls the Platform Key (PK), Key Exchange Key (KEK), and Database (DB)
func (e *SecureBootEnroller) EnrollKeys(ctx context.Context) error {
	// Check if already enrolled with current keys
	if e.IsEnrolled() {
		e.logger.Info("Secure Boot keys already enrolled")
		return nil
	}

	e.logger.Info("Enrolling Secure Boot keys into NVRAM",
		"keys_dir", e.keysDir,
		"nvram_dir", e.nvramDir)

	// Create NVRAM directory if it doesn't exist
	if err := os.MkdirAll(e.nvramDir, 0755); err != nil {
		return fmt.Errorf("failed to create NVRAM directory: %w", err)
	}

	// Reset NVRAM for fresh enrollment
	// This is necessary when keys have been regenerated since last enrollment
	nvramPath := filepath.Join(e.nvramDir, "OVMF_VARS.fd")
	flagPath := filepath.Join(e.nvramDir, "OVMF_VARS_ENROLLED.flag")

	// Remove existing NVRAM and flag to ensure clean enrollment
	if fileExists(nvramPath) {
		e.logger.Debug("Removing existing NVRAM for re-enrollment", "path", nvramPath)
		if err := os.Remove(nvramPath); err != nil {
			return fmt.Errorf("failed to remove existing NVRAM: %w", err)
		}
	}
	if fileExists(flagPath) {
		e.logger.Debug("Removing existing enrollment flag", "path", flagPath)
		if err := os.Remove(flagPath); err != nil {
			return fmt.Errorf("failed to remove existing enrollment flag: %w", err)
		}
	}

	// Initialize fresh NVRAM from template
	e.logger.Debug("Initializing NVRAM from template", "path", nvramPath)
	if err := e.InitializeNVRAM("OVMF_VARS.fd"); err != nil {
		return fmt.Errorf("failed to initialize NVRAM: %w", err)
	}

	// Perform native enrollment
	if err := e.enrollKeysNative(ctx, nvramPath); err != nil {
		return fmt.Errorf("%w: %v", ErrEnrollmentFailed, err)
	}

	// Create enrollment flag file
	if err := createFlagFile(flagPath); err != nil {
		return fmt.Errorf("failed to create enrollment flag file: %w", err)
	}

	e.logger.Info("Secure Boot keys enrolled successfully")

	return nil
}

// enrollKeysNative performs Secure Boot key enrollment using the native UEFI package
func (e *SecureBootEnroller) enrollKeysNative(ctx context.Context, nvramPath string) error {
	e.logger.Debug("Using native UEFI enrollment", "nvram", nvramPath)

	// Create native enroller config
	enrollerConfig := &uefi.SecureBootEnrollerConfig{
		NVRAMPath:    nvramPath,
		KeysDir:      e.keysDir,
		TemplatePath: e.ovmfVarsPath,
		OwnerGUID:    &e.ownerGUID,
	}

	// Create native enroller
	enroller, err := uefi.NewSecureBootEnroller(enrollerConfig, e.logger)
	if err != nil {
		return fmt.Errorf("failed to create native enroller: %w", err)
	}

	// Enroll keys using native implementation
	if err := enroller.EnrollKeys(ctx); err != nil {
		return fmt.Errorf("native enrollment failed: %w", err)
	}

	e.logger.Info("Secure Boot keys enrolled successfully",
		"nvram", nvramPath,
		"owner_guid", e.ownerGUID.String())

	return nil
}

// loadCertificate loads a certificate from the keys directory
func (e *SecureBootEnroller) loadCertificate(filename string) (*x509.Certificate, error) {
	certPath := filepath.Join(e.keysDir, filename)

	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}

	// Try PEM first
	block, _ := pem.Decode(certData)
	if block != nil {
		certData = block.Bytes
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// ValidateEnrollment validates that the enrollment was successful
// by reading the NVRAM and checking that all required key variables exist
//
// Note: The SecureBoot runtime variable is not checked here because it's only
// created when OVMF firmware actually boots. virt-fw-vars only enrolls keys,
// it doesn't create runtime variables.
func (e *SecureBootEnroller) ValidateEnrollment(ctx context.Context) error {
	if !e.IsEnrolled() {
		return fmt.Errorf("enrollment validation failed: keys not enrolled")
	}

	nvramPath := filepath.Join(e.nvramDir, "OVMF_VARS.fd")

	// Open NVRAM and check variables
	nvram, err := uefi.OpenNVRAM(nvramPath)
	if err != nil {
		return fmt.Errorf("failed to open NVRAM for validation: %w", err)
	}

	// Check for required key variables
	// Note: SecureBoot and SetupMode are runtime variables created by firmware
	// and won't exist in the NVRAM file created by virt-fw-vars
	requiredVars := []struct {
		name string
		guid uefi.GUID
	}{
		{"PK", uefi.EFIGlobalVariable},
		{"KEK", uefi.EFIGlobalVariable},
		{"db", uefi.EFIImageSecurityDatabase},
	}

	for _, v := range requiredVars {
		variable, err := nvram.GetVariable(v.name, v.guid)
		if err != nil {
			return fmt.Errorf("enrollment validation failed: variable %s not found", v.name)
		}
		if len(variable.Data) == 0 {
			return fmt.Errorf("enrollment validation failed: variable %s has no data", v.name)
		}
		e.logger.Debug("Variable validated",
			"name", v.name,
			"size", len(variable.Data))
	}

	e.logger.Debug("Enrollment validated successfully")

	return nil
}

// GetEnrollmentStatus returns the current enrollment status
//
// Note: SecureBoot and SetupMode are runtime-only variables that are created
// by OVMF firmware when it boots. When checking NVRAM files prepared with
// virt-fw-vars, these variables won't exist. The status is inferred from the
// presence of key variables (PK, KEK, DB).
func (e *SecureBootEnroller) GetEnrollmentStatus() (*uefi.EnrollmentStatus, error) {
	nvramPath := filepath.Join(e.nvramDir, "OVMF_VARS.fd")

	if !fileExists(nvramPath) {
		return &uefi.EnrollmentStatus{}, nil
	}

	nvram, err := uefi.OpenNVRAM(nvramPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open NVRAM: %w", err)
	}

	status := &uefi.EnrollmentStatus{}

	// Check SecureBoot variable (runtime-only, might not exist)
	if sb, err := nvram.GetVariable("SecureBoot", uefi.EFIGlobalVariable); err == nil && len(sb.Data) > 0 {
		status.SecureBootEnabled = sb.Data[0] == 0x01
	}

	// Check SetupMode variable (runtime-only, might not exist)
	if sm, err := nvram.GetVariable("SetupMode", uefi.EFIGlobalVariable); err == nil && len(sm.Data) > 0 {
		status.SetupMode = sm.Data[0] == 0x01
	}

	// Check for key variables
	if _, err := nvram.GetVariable("PK", uefi.EFIGlobalVariable); err == nil {
		status.HasPK = true
	}
	if _, err := nvram.GetVariable("KEK", uefi.EFIGlobalVariable); err == nil {
		status.HasKEK = true
	}
	if _, err := nvram.GetVariable("db", uefi.EFIImageSecurityDatabase); err == nil {
		status.HasDB = true
	}
	if _, err := nvram.GetVariable("dbx", uefi.EFIImageSecurityDatabase); err == nil {
		status.HasDBX = true
	}

	status.KeysEnrolled = status.HasPK && status.HasKEK && status.HasDB

	// If keys are enrolled but SecureBoot variable doesn't exist (expected when
	// using virt-fw-vars), we infer that Secure Boot is enabled based on key presence
	if status.KeysEnrolled && !status.SecureBootEnabled {
		// Check if SecureBoot variable actually exists but is disabled
		if _, err := nvram.GetVariable("SecureBoot", uefi.EFIGlobalVariable); err != nil {
			// Variable doesn't exist - this is expected with virt-fw-vars
			// Infer SecureBoot is enabled based on enrolled keys
			status.SecureBootEnabled = true
			// SetupMode should be false when keys are enrolled
			status.SetupMode = false
		}
	}

	return status, nil
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer func() { _ = srcFile.Close() }()

	dstFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer func() { _ = dstFile.Close() }()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return fmt.Errorf("failed to copy file contents: %w", err)
	}

	if err := dstFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync destination file: %w", err)
	}

	return nil
}

// createFlagFile creates an empty flag file
func createFlagFile(path string) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create flag file: %w", err)
	}
	defer func() { _ = file.Close() }()

	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to sync flag file: %w", err)
	}

	return nil
}
