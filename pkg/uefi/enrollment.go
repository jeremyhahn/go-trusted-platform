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

package uefi

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// SecureBootEnroller handles native Secure Boot key enrollment into NVRAM
type SecureBootEnroller struct {
	nvramPath    string
	keysDir      string
	templatePath string
	logger       *logging.Logger
	ownerGUID    GUID
}

// SecureBootEnrollerConfig contains configuration for the enroller
type SecureBootEnrollerConfig struct {
	// NVRAMPath is the path to the NVRAM file to modify
	NVRAMPath string

	// KeysDir is the directory containing PK.crt, KEK.crt, DB.crt
	KeysDir string

	// TemplatePath is the path to the OVMF_VARS template (optional)
	// If NVRAMPath doesn't exist, it will be copied from here
	TemplatePath string

	// OwnerGUID is the GUID to use as the key owner (optional)
	// If not specified, a new GUID will be generated
	OwnerGUID *GUID
}

// NewSecureBootEnroller creates a new Secure Boot enroller
func NewSecureBootEnroller(config *SecureBootEnrollerConfig, logger *logging.Logger) (*SecureBootEnroller, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	if config.NVRAMPath == "" {
		return nil, fmt.Errorf("NVRAM path not specified")
	}

	if config.KeysDir == "" {
		return nil, fmt.Errorf("keys directory not specified")
	}

	if logger == nil {
		logger = logging.DefaultLogger()
	}

	ownerGUID := NewGUID()
	if config.OwnerGUID != nil {
		ownerGUID = *config.OwnerGUID
	}

	return &SecureBootEnroller{
		nvramPath:    config.NVRAMPath,
		keysDir:      config.KeysDir,
		templatePath: config.TemplatePath,
		logger:       logger,
		ownerGUID:    ownerGUID,
	}, nil
}

// EnrollKeys enrolls PK, KEK, and DB keys into the NVRAM
func (e *SecureBootEnroller) EnrollKeys(ctx context.Context) error {
	e.logger.Info("Enrolling Secure Boot keys",
		"nvram", e.nvramPath,
		"keys_dir", e.keysDir)

	// Initialize NVRAM if needed
	if err := e.initializeNVRAM(); err != nil {
		return fmt.Errorf("failed to initialize NVRAM: %w", err)
	}

	// Load certificates
	pkCert, err := e.loadCertificate("PK.crt")
	if err != nil {
		return fmt.Errorf("failed to load Platform Key: %w", err)
	}

	kekCert, err := e.loadCertificate("KEK.crt")
	if err != nil {
		return fmt.Errorf("failed to load Key Exchange Key: %w", err)
	}

	dbCert, err := e.loadCertificate("DB.crt")
	if err != nil {
		return fmt.Errorf("failed to load Database Key: %w", err)
	}

	// Open NVRAM
	nvram, err := OpenNVRAM(e.nvramPath)
	if err != nil {
		return fmt.Errorf("failed to open NVRAM: %w", err)
	}

	// Create ESL structures for each key
	pkESL := NewSignatureListFromCert(pkCert.Raw, e.ownerGUID)
	kekESL := NewSignatureListFromCert(kekCert.Raw, e.ownerGUID)
	dbESL := NewSignatureListFromCert(dbCert.Raw, e.ownerGUID)

	e.logger.Debug("Created signature lists",
		"pk_size", pkESL.SignatureListSize,
		"kek_size", kekESL.SignatureListSize,
		"db_size", dbESL.SignatureListSize)

	// Set Platform Key (PK)
	if err := nvram.SetVariable("PK", EFIGlobalVariable, SecureBootAttributes, pkESL.Bytes()); err != nil {
		return fmt.Errorf("failed to set PK: %w", err)
	}
	e.logger.Debug("Set Platform Key (PK)")

	// Set Key Exchange Key (KEK)
	if err := nvram.SetVariable("KEK", EFIGlobalVariable, SecureBootAttributes, kekESL.Bytes()); err != nil {
		return fmt.Errorf("failed to set KEK: %w", err)
	}
	e.logger.Debug("Set Key Exchange Key (KEK)")

	// Set Signature Database (db)
	if err := nvram.SetVariable("db", EFIImageSecurityDatabase, SecureBootAttributes, dbESL.Bytes()); err != nil {
		return fmt.Errorf("failed to set db: %w", err)
	}
	e.logger.Debug("Set Signature Database (db)")

	// Set SecureBoot to enabled (0x01)
	secureBootValue := []byte{0x01}
	secureBootAttrs := AttrNonVolatile | AttrBootserviceAccess | AttrRuntimeAccess
	if err := nvram.SetVariable("SecureBoot", EFIGlobalVariable, secureBootAttrs, secureBootValue); err != nil {
		return fmt.Errorf("failed to set SecureBoot: %w", err)
	}
	e.logger.Debug("Set SecureBoot=1")

	// Set SetupMode to disabled (0x00) - keys are enrolled
	setupModeValue := []byte{0x00}
	if err := nvram.SetVariable("SetupMode", EFIGlobalVariable, secureBootAttrs, setupModeValue); err != nil {
		return fmt.Errorf("failed to set SetupMode: %w", err)
	}
	e.logger.Debug("Set SetupMode=0")

	// Save NVRAM
	if err := nvram.Save(); err != nil {
		return fmt.Errorf("failed to save NVRAM: %w", err)
	}

	e.logger.Info("Secure Boot keys enrolled successfully",
		"nvram", e.nvramPath,
		"owner_guid", e.ownerGUID.String())

	return nil
}

// initializeNVRAM initializes the NVRAM file from template if it doesn't exist
func (e *SecureBootEnroller) initializeNVRAM() error {
	// Check if NVRAM already exists
	if _, err := os.Stat(e.nvramPath); err == nil {
		return nil
	}

	// Need template to initialize
	if e.templatePath == "" {
		// Try common OVMF locations
		commonPaths := []string{
			"/usr/share/OVMF/OVMF_VARS_4M.fd",
			"/usr/share/OVMF/OVMF_VARS.fd",
			"/usr/share/edk2/ovmf/OVMF_VARS.fd",
			"/usr/share/qemu/OVMF_VARS.fd",
		}
		for _, p := range commonPaths {
			if _, err := os.Stat(p); err == nil {
				e.templatePath = p
				break
			}
		}
	}

	if e.templatePath == "" {
		return fmt.Errorf("NVRAM template not found and no template path specified")
	}

	// Create directory if needed
	dir := filepath.Dir(e.nvramPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create NVRAM directory: %w", err)
	}

	// Copy template
	e.logger.Info("Initializing NVRAM from template",
		"template", e.templatePath,
		"target", e.nvramPath)

	templateData, err := os.ReadFile(e.templatePath)
	if err != nil {
		return fmt.Errorf("failed to read NVRAM template: %w", err)
	}

	if err := os.WriteFile(e.nvramPath, templateData, 0644); err != nil {
		return fmt.Errorf("failed to write NVRAM: %w", err)
	}

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

// GetEnrollmentStatus checks the current Secure Boot enrollment status
func (e *SecureBootEnroller) GetEnrollmentStatus() (*EnrollmentStatus, error) {
	nvram, err := OpenNVRAM(e.nvramPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open NVRAM: %w", err)
	}

	status := &EnrollmentStatus{}

	// Check SecureBoot variable
	if sb, err := nvram.GetVariable("SecureBoot", EFIGlobalVariable); err == nil && len(sb.Data) > 0 {
		status.SecureBootEnabled = sb.Data[0] == 0x01
	}

	// Check SetupMode variable
	if sm, err := nvram.GetVariable("SetupMode", EFIGlobalVariable); err == nil && len(sm.Data) > 0 {
		status.SetupMode = sm.Data[0] == 0x01
	}

	// Check for key variables
	if _, err := nvram.GetVariable("PK", EFIGlobalVariable); err == nil {
		status.HasPK = true
	}
	if _, err := nvram.GetVariable("KEK", EFIGlobalVariable); err == nil {
		status.HasKEK = true
	}
	if _, err := nvram.GetVariable("db", EFIImageSecurityDatabase); err == nil {
		status.HasDB = true
	}
	if _, err := nvram.GetVariable("dbx", EFIImageSecurityDatabase); err == nil {
		status.HasDBX = true
	}

	status.KeysEnrolled = status.HasPK && status.HasKEK && status.HasDB

	return status, nil
}

// EnrollmentStatus represents the current Secure Boot enrollment state
type EnrollmentStatus struct {
	SecureBootEnabled bool
	SetupMode         bool
	HasPK             bool
	HasKEK            bool
	HasDB             bool
	HasDBX            bool
	KeysEnrolled      bool
}

// String returns a human-readable status
func (s *EnrollmentStatus) String() string {
	sbState := "disabled"
	if s.SecureBootEnabled {
		sbState = "enabled"
	}

	setupState := "User Mode"
	if s.SetupMode {
		setupState = "Setup Mode"
	}

	return fmt.Sprintf("SecureBoot: %s, Mode: %s, PK: %v, KEK: %v, db: %v, dbx: %v",
		sbState, setupState, s.HasPK, s.HasKEK, s.HasDB, s.HasDBX)
}

// PlatformInfo contains platform identification information
// stored in UEFI NVRAM for boot-time verification
type PlatformInfo struct {
	// Version is the platform software version (from VERSION file)
	Version string
	// BuildDate is the build date/time (optional)
	BuildDate string
	// GitCommit is the git commit hash (optional)
	GitCommit string
}

// SetPlatformInfo sets the TRUSTED_PLATFORM variable in NVRAM
// This allows the platform to identify itself during UEFI boot
// and enables boot-time verification of platform integrity
func (e *SecureBootEnroller) SetPlatformInfo(ctx context.Context, info *PlatformInfo) error {
	if info == nil {
		return fmt.Errorf("platform info cannot be nil")
	}

	if info.Version == "" {
		return fmt.Errorf("platform version is required")
	}

	e.logger.Info("Setting TRUSTED_PLATFORM variable",
		"version", info.Version,
		"nvram", e.nvramPath)

	// Open NVRAM
	nvram, err := OpenNVRAM(e.nvramPath)
	if err != nil {
		return fmt.Errorf("failed to open NVRAM: %w", err)
	}

	// Format: VERSION|BUILD_DATE|GIT_COMMIT
	// Example: "1.0.0|2024-01-15T12:00:00Z|abc123"
	data := info.Version
	if info.BuildDate != "" {
		data += "|" + info.BuildDate
	}
	if info.GitCommit != "" {
		if info.BuildDate == "" {
			data += "|"
		}
		data += "|" + info.GitCommit
	}

	// Set variable with runtime access (readable from OS)
	attrs := AttrNonVolatile | AttrBootserviceAccess | AttrRuntimeAccess
	if err := nvram.SetVariable("TRUSTED_PLATFORM", TrustedPlatformGUID, attrs, []byte(data)); err != nil {
		return fmt.Errorf("failed to set TRUSTED_PLATFORM: %w", err)
	}

	// Save NVRAM
	if err := nvram.Save(); err != nil {
		return fmt.Errorf("failed to save NVRAM: %w", err)
	}

	e.logger.Info("TRUSTED_PLATFORM variable set successfully",
		"value", data,
		"guid", TrustedPlatformGUID.String())

	return nil
}

// GetPlatformInfo reads the TRUSTED_PLATFORM variable from NVRAM
func (e *SecureBootEnroller) GetPlatformInfo() (*PlatformInfo, error) {
	nvram, err := OpenNVRAM(e.nvramPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open NVRAM: %w", err)
	}

	v, err := nvram.GetVariable("TRUSTED_PLATFORM", TrustedPlatformGUID)
	if err != nil {
		return nil, fmt.Errorf("failed to get TRUSTED_PLATFORM: %w", err)
	}

	info := &PlatformInfo{}

	// Parse: VERSION|BUILD_DATE|GIT_COMMIT
	data := string(v.Data)
	parts := make([]string, 3)
	idx := 0
	for i := 0; i < len(data) && idx < 3; i++ {
		if data[i] == '|' {
			idx++
		} else {
			parts[idx] += string(data[i])
		}
	}

	info.Version = parts[0]
	info.BuildDate = parts[1]
	info.GitCommit = parts[2]

	return info, nil
}

// EnrollKeysWithPlatformInfo enrolls Secure Boot keys and sets platform info
// This is a convenience method that combines EnrollKeys and SetPlatformInfo
func (e *SecureBootEnroller) EnrollKeysWithPlatformInfo(ctx context.Context, info *PlatformInfo) error {
	if err := e.EnrollKeys(ctx); err != nil {
		return err
	}

	if info != nil && info.Version != "" {
		if err := e.SetPlatformInfo(ctx, info); err != nil {
			return err
		}
	}

	return nil
}
