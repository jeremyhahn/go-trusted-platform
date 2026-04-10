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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uefi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCertificate creates a self-signed certificate for testing
func generateTestCertificate(t *testing.T, cn string) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	// Return PEM encoded certificate
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}

	return pem.EncodeToMemory(pemBlock)
}

// createMockOVMFVars creates a mock OVMF VARS file with valid structure
// This creates a proper firmware volume with variable store header that virt-fw-vars can parse
func createMockOVMFVars(t *testing.T, path string) {
	t.Helper()

	// Create minimal OVMF VARS structure (4MB file)
	data := make([]byte, 4*1024*1024) // 4MB

	// Fill with 0xFF (erased flash state)
	for i := range data {
		data[i] = 0xFF
	}

	// Set up firmware volume header at offset 0
	// Zero vector (16 bytes)
	for i := 0; i < 16; i++ {
		data[i] = 0x00
	}

	// FileSystemGUID (16 bytes) - EFI_FIRMWARE_FILE_SYSTEM2_GUID
	copy(data[16:32], uefi.FFS2GUID.Bytes())

	// FvLength (8 bytes) - little endian
	volumeLen := uint64(len(data))
	binary.LittleEndian.PutUint64(data[32:40], volumeLen)

	// Signature "_FVH" (4 bytes)
	copy(data[40:44], uefi.FirmwareVolumeSignature[:])

	// Attributes (4 bytes) - little endian
	// EFI_FVB2_ERASE_POLARITY | EFI_FVB2_MEMORY_MAPPED
	binary.LittleEndian.PutUint32(data[44:48], 0x000F0800)

	// HeaderLength (2 bytes) - 72 bytes
	binary.LittleEndian.PutUint16(data[48:50], 72)

	// Checksum (2 bytes) - set to 0 for now
	binary.LittleEndian.PutUint16(data[50:52], 0)

	// ExtHeaderOffset (2 bytes)
	binary.LittleEndian.PutUint16(data[52:54], 0)

	// Reserved (1 byte)
	data[54] = 0

	// Revision (1 byte)
	data[55] = 2

	// Block map (2 entries, 8 bytes each = 16 bytes)
	// Entry 1: NumBlocks=size/0x1000, Length=0x1000
	numBlocks := uint32(len(data) / 0x1000)
	binary.LittleEndian.PutUint32(data[56:60], numBlocks)
	binary.LittleEndian.PutUint32(data[60:64], 0x1000)
	// Entry 2: NumBlocks=0, Length=0 (terminator)
	binary.LittleEndian.PutUint32(data[64:68], 0)
	binary.LittleEndian.PutUint32(data[68:72], 0)

	// Now add variable store header after FV header (at offset 72)
	vsOffset := 72

	// Variable Store Signature GUID - EFI_AUTHENTICATED_VARIABLE_GUID
	copy(data[vsOffset:vsOffset+16], uefi.AuthenticatedVariableGUID.Bytes())

	// Variable Store Size (4 bytes) - rest of volume
	vsSize := uint32(len(data) - vsOffset)
	binary.LittleEndian.PutUint32(data[vsOffset+16:vsOffset+20], vsSize)

	// Format (1 byte) - VARIABLE_STORE_FORMATTED
	data[vsOffset+20] = 0x5a

	// State (1 byte) - VARIABLE_STORE_HEALTHY
	data[vsOffset+21] = 0xfe

	// Reserved (2 bytes)
	binary.LittleEndian.PutUint16(data[vsOffset+22:vsOffset+24], 0)

	// Reserved1 (4 bytes)
	binary.LittleEndian.PutUint32(data[vsOffset+24:vsOffset+28], 0)

	require.NoError(t, os.WriteFile(path, data, 0644))
}

// trySystemOVMFVars attempts to find and use a real OVMF_VARS file from the system
func trySystemOVMFVars(t *testing.T) (string, bool) {
	t.Helper()

	commonPaths := []string{
		"/usr/share/OVMF/OVMF_VARS_4M.fd",
		"/usr/share/OVMF/OVMF_VARS.fd",
		"/usr/share/edk2/ovmf/OVMF_VARS.fd",
		"/usr/share/qemu/OVMF_VARS.fd",
	}

	for _, path := range commonPaths {
		if _, err := os.Stat(path); err == nil {
			return path, true
		}
	}

	return "", false
}

// setupTestEnv creates a temporary test environment
func setupTestEnv(t *testing.T) (string, *SecureBootEnrollerConfig, func()) {
	t.Helper()

	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "secureboot-test-*")
	require.NoError(t, err)

	// Create keys directory
	keysDir := filepath.Join(tmpDir, "keys")
	require.NoError(t, os.MkdirAll(keysDir, 0755))

	// Create valid certificate files
	keyFiles := []struct {
		name string
		cn   string
	}{
		{"PK.crt", "Platform Key"},
		{"KEK.crt", "Key Exchange Key"},
		{"DB.crt", "Database Key"},
	}
	for _, kf := range keyFiles {
		certData := generateTestCertificate(t, kf.cn)
		keyPath := filepath.Join(keysDir, kf.name)
		require.NoError(t, os.WriteFile(keyPath, certData, 0644))
	}

	// Create NVRAM directory
	nvramDir := filepath.Join(tmpDir, "nvram")
	require.NoError(t, os.MkdirAll(nvramDir, 0755))

	// Try to use a real OVMF VARS file from the system, otherwise create mock
	ovmfVarsPath := filepath.Join(tmpDir, "OVMF_VARS.fd")
	if systemOVMF, found := trySystemOVMFVars(t); found {
		// Copy system OVMF VARS to temp location
		systemData, err := os.ReadFile(systemOVMF)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(ovmfVarsPath, systemData, 0644))
	} else {
		// Create mock OVMF VARS with proper structure
		createMockOVMFVars(t, ovmfVarsPath)
	}

	config := &SecureBootEnrollerConfig{
		KeysDir:      keysDir,
		NVRAMDir:     nvramDir,
		OVMFVarsPath: ovmfVarsPath,
		Debug:        false,
	}

	cleanup := func() {
		_ = os.RemoveAll(tmpDir)
	}

	return tmpDir, config, cleanup
}

// setupTestEnvWithMockCerts creates test env with mock (invalid) certificates
// for tests that don't need valid certs
func setupTestEnvWithMockCerts(t *testing.T) (string, *SecureBootEnrollerConfig, func()) {
	t.Helper()

	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "secureboot-test-*")
	require.NoError(t, err)

	// Create keys directory
	keysDir := filepath.Join(tmpDir, "keys")
	require.NoError(t, os.MkdirAll(keysDir, 0755))

	// Create mock key files (not valid certificates)
	keyFiles := []string{"PK.crt", "KEK.crt", "DB.crt"}
	for _, keyFile := range keyFiles {
		keyPath := filepath.Join(keysDir, keyFile)
		require.NoError(t, os.WriteFile(keyPath, []byte("mock-key-data"), 0644))
	}

	// Create NVRAM directory
	nvramDir := filepath.Join(tmpDir, "nvram")
	require.NoError(t, os.MkdirAll(nvramDir, 0755))

	// Create mock OVMF VARS template (minimal valid size)
	ovmfVarsPath := filepath.Join(tmpDir, "OVMF_VARS.fd")
	require.NoError(t, os.WriteFile(ovmfVarsPath, []byte("mock-ovmf-vars"), 0644))

	config := &SecureBootEnrollerConfig{
		KeysDir:      keysDir,
		NVRAMDir:     nvramDir,
		OVMFVarsPath: ovmfVarsPath,
		Debug:        false,
	}

	cleanup := func() {
		_ = os.RemoveAll(tmpDir)
	}

	return tmpDir, config, cleanup
}

func TestNewSecureBootEnroller_Success(t *testing.T) {
	_, config, cleanup := setupTestEnvWithMockCerts(t)
	defer cleanup()

	logger := logging.DefaultLogger()

	enroller, err := NewSecureBootEnroller(config, logger)
	require.NoError(t, err)
	assert.NotNil(t, enroller)
	assert.Equal(t, config.KeysDir, enroller.keysDir)
	assert.Equal(t, config.NVRAMDir, enroller.nvramDir)
	assert.Equal(t, config.OVMFVarsPath, enroller.ovmfVarsPath)
}

func TestNewSecureBootEnroller_NilConfig(t *testing.T) {
	logger := logging.DefaultLogger()

	enroller, err := NewSecureBootEnroller(nil, logger)
	assert.Nil(t, enroller)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidConfiguration))
}

func TestNewSecureBootEnroller_MissingKeysDir(t *testing.T) {
	_, config, cleanup := setupTestEnvWithMockCerts(t)
	defer cleanup()

	// Remove keys directory
	_ = os.RemoveAll(config.KeysDir)

	logger := logging.DefaultLogger()
	enroller, err := NewSecureBootEnroller(config, logger)
	assert.Nil(t, enroller)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrKeysNotFound))
}

func TestNewSecureBootEnroller_MissingKeyFile(t *testing.T) {
	_, config, cleanup := setupTestEnvWithMockCerts(t)
	defer cleanup()

	// Remove one required key file
	pkPath := filepath.Join(config.KeysDir, "PK.crt")
	require.NoError(t, os.Remove(pkPath))

	logger := logging.DefaultLogger()
	enroller, err := NewSecureBootEnroller(config, logger)
	assert.Nil(t, enroller)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrKeysNotFound))
}

func TestNewSecureBootEnroller_MissingOVMFVars(t *testing.T) {
	_, config, cleanup := setupTestEnvWithMockCerts(t)
	defer cleanup()

	// Remove OVMF VARS template
	require.NoError(t, os.Remove(config.OVMFVarsPath))

	logger := logging.DefaultLogger()
	enroller, err := NewSecureBootEnroller(config, logger)
	assert.Nil(t, enroller)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrNVRAMNotFound))
}

func TestNewSecureBootEnroller_WithOwnerGUID(t *testing.T) {
	_, config, cleanup := setupTestEnvWithMockCerts(t)
	defer cleanup()

	// Set a specific owner GUID
	ownerGUID := uefi.MustParseGUID("12345678-1234-1234-1234-123456789ABC")
	config.OwnerGUID = &ownerGUID

	logger := logging.DefaultLogger()
	enroller, err := NewSecureBootEnroller(config, logger)
	require.NoError(t, err)
	assert.NotNil(t, enroller)
	assert.Equal(t, ownerGUID, enroller.ownerGUID)
}

func TestIsEnrolled_NotEnrolled(t *testing.T) {
	_, config, cleanup := setupTestEnvWithMockCerts(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	enroller, err := NewSecureBootEnroller(config, logger)
	require.NoError(t, err)

	enrolled := enroller.IsEnrolled()
	assert.False(t, enrolled)
}

func TestIsEnrolled_FlagOnly(t *testing.T) {
	_, config, cleanup := setupTestEnvWithMockCerts(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	enroller, err := NewSecureBootEnroller(config, logger)
	require.NoError(t, err)

	// Create only flag file
	flagPath := filepath.Join(config.NVRAMDir, "OVMF_VARS_ENROLLED.flag")
	require.NoError(t, os.WriteFile(flagPath, []byte(""), 0644))

	enrolled := enroller.IsEnrolled()
	assert.False(t, enrolled, "should not be enrolled with only flag file")
}

func TestIsEnrolled_NVRAMOnly(t *testing.T) {
	_, config, cleanup := setupTestEnvWithMockCerts(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	enroller, err := NewSecureBootEnroller(config, logger)
	require.NoError(t, err)

	// Create only NVRAM file
	nvramPath := filepath.Join(config.NVRAMDir, "OVMF_VARS.fd")
	require.NoError(t, os.WriteFile(nvramPath, []byte("mock-nvram"), 0644))

	enrolled := enroller.IsEnrolled()
	assert.False(t, enrolled, "should not be enrolled with only NVRAM file")
}

func TestIsEnrolled_BothExist(t *testing.T) {
	_, config, cleanup := setupTestEnvWithMockCerts(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	enroller, err := NewSecureBootEnroller(config, logger)
	require.NoError(t, err)

	// Create both flag and NVRAM files
	flagPath := filepath.Join(config.NVRAMDir, "OVMF_VARS_ENROLLED.flag")
	require.NoError(t, os.WriteFile(flagPath, []byte(""), 0644))

	nvramPath := filepath.Join(config.NVRAMDir, "OVMF_VARS.fd")
	require.NoError(t, os.WriteFile(nvramPath, []byte("mock-nvram"), 0644))

	enrolled := enroller.IsEnrolled()
	assert.True(t, enrolled)
}

func TestIsEnrolled_KeysRegeneratedAfterEnrollment(t *testing.T) {
	_, config, cleanup := setupTestEnvWithMockCerts(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	enroller, err := NewSecureBootEnroller(config, logger)
	require.NoError(t, err)

	// Create enrollment files
	nvramPath := filepath.Join(config.NVRAMDir, "OVMF_VARS.fd")
	require.NoError(t, os.WriteFile(nvramPath, []byte("mock-nvram"), 0644))

	flagPath := filepath.Join(config.NVRAMDir, "OVMF_VARS_ENROLLED.flag")
	require.NoError(t, os.WriteFile(flagPath, []byte(""), 0644))

	// Wait a bit then update a key file (simulates key regeneration)
	time.Sleep(10 * time.Millisecond)
	pkPath := filepath.Join(config.KeysDir, "PK.crt")
	require.NoError(t, os.WriteFile(pkPath, []byte("regenerated-key"), 0644))

	enrolled := enroller.IsEnrolled()
	assert.False(t, enrolled, "should not be enrolled when keys are newer than flag")
}

func TestInitializeNVRAM_Success(t *testing.T) {
	_, config, cleanup := setupTestEnvWithMockCerts(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	enroller, err := NewSecureBootEnroller(config, logger)
	require.NoError(t, err)

	err = enroller.InitializeNVRAM("OVMF_VARS_INSTALL.fd")
	require.NoError(t, err)

	// Check that NVRAM file was created
	nvramPath := filepath.Join(config.NVRAMDir, "OVMF_VARS_INSTALL.fd")
	assert.FileExists(t, nvramPath)

	// Verify content was copied
	content, err := os.ReadFile(nvramPath)
	require.NoError(t, err)
	expected, _ := os.ReadFile(config.OVMFVarsPath)
	assert.Equal(t, expected, content)
}

func TestInitializeNVRAM_AlreadyExists(t *testing.T) {
	_, config, cleanup := setupTestEnvWithMockCerts(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	enroller, err := NewSecureBootEnroller(config, logger)
	require.NoError(t, err)

	// Create NVRAM file with existing content
	nvramPath := filepath.Join(config.NVRAMDir, "OVMF_VARS_INSTALL.fd")
	existingContent := []byte("existing-content")
	require.NoError(t, os.WriteFile(nvramPath, existingContent, 0644))

	err = enroller.InitializeNVRAM("OVMF_VARS_INSTALL.fd")
	require.NoError(t, err)

	// Verify content was not overwritten
	content, err := os.ReadFile(nvramPath)
	require.NoError(t, err)
	assert.Equal(t, "existing-content", string(content))
}

func TestInitializeNVRAM_CreateDirectory(t *testing.T) {
	tmpDir, config, cleanup := setupTestEnvWithMockCerts(t)
	defer cleanup()

	// Remove NVRAM directory
	require.NoError(t, os.RemoveAll(config.NVRAMDir))

	// Update config with new NVRAM dir path
	config.NVRAMDir = filepath.Join(tmpDir, "new-nvram")

	logger := logging.DefaultLogger()
	enroller, err := NewSecureBootEnroller(config, logger)
	require.NoError(t, err)

	// Update enroller's nvramDir (since config was modified after creation)
	enroller.nvramDir = config.NVRAMDir

	err = enroller.InitializeNVRAM("OVMF_VARS.fd")
	require.NoError(t, err)

	// Check that directory and file were created
	assert.DirExists(t, config.NVRAMDir)
	nvramPath := filepath.Join(config.NVRAMDir, "OVMF_VARS.fd")
	assert.FileExists(t, nvramPath)
}

func TestEnrollKeys_Success(t *testing.T) {
	// Use full test environment with valid certificates
	_, config, cleanup := setupTestEnv(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	enroller, err := NewSecureBootEnroller(config, logger)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = enroller.EnrollKeys(ctx)
	require.NoError(t, err)

	// Verify enrollment
	assert.True(t, enroller.IsEnrolled())

	// Check that NVRAM file was created
	nvramPath := filepath.Join(config.NVRAMDir, "OVMF_VARS.fd")
	assert.FileExists(t, nvramPath)

	// Check that flag file was created
	flagPath := filepath.Join(config.NVRAMDir, "OVMF_VARS_ENROLLED.flag")
	assert.FileExists(t, flagPath)
}

func TestEnrollKeys_AlreadyEnrolled(t *testing.T) {
	_, config, cleanup := setupTestEnvWithMockCerts(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	enroller, err := NewSecureBootEnroller(config, logger)
	require.NoError(t, err)

	// Create enrollment files manually
	nvramPath := filepath.Join(config.NVRAMDir, "OVMF_VARS.fd")
	require.NoError(t, os.WriteFile(nvramPath, []byte("mock-nvram"), 0644))

	flagPath := filepath.Join(config.NVRAMDir, "OVMF_VARS_ENROLLED.flag")
	require.NoError(t, os.WriteFile(flagPath, []byte(""), 0644))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Should succeed without re-enrolling
	err = enroller.EnrollKeys(ctx)
	require.NoError(t, err)
}

func TestEnrollKeys_InvalidCertificate(t *testing.T) {
	// Use test environment with mock (invalid) certificates
	_, config, cleanup := setupTestEnvWithMockCerts(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	enroller, err := NewSecureBootEnroller(config, logger)
	require.NoError(t, err)

	// Force re-enrollment by ensuring no flag exists
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = enroller.EnrollKeys(ctx)
	// Should fail because certificates are invalid
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrEnrollmentFailed))
}

// TestEnrollKeys_VirtFwVarsNotFound was removed because the code now uses
// a native Go UEFI implementation and no longer depends on external tools
// like virt-fw-vars. See pkg/uefi for the native implementation.

func TestFileExists(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "fileexists-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	existingFile := filepath.Join(tmpDir, "exists.txt")
	require.NoError(t, os.WriteFile(existingFile, []byte("test"), 0644))

	nonExistingFile := filepath.Join(tmpDir, "does-not-exist.txt")

	assert.True(t, fileExists(existingFile))
	assert.False(t, fileExists(nonExistingFile))
}

func TestCopyFile_Success(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "copyfile-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	srcPath := filepath.Join(tmpDir, "source.txt")
	srcContent := []byte("test content")
	require.NoError(t, os.WriteFile(srcPath, srcContent, 0644))

	dstPath := filepath.Join(tmpDir, "dest.txt")

	err = copyFile(srcPath, dstPath)
	require.NoError(t, err)

	// Verify destination file exists and has correct content
	assert.FileExists(t, dstPath)
	dstContent, err := os.ReadFile(dstPath)
	require.NoError(t, err)
	assert.Equal(t, srcContent, dstContent)
}

func TestCopyFile_SourceNotFound(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "copyfile-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	srcPath := filepath.Join(tmpDir, "nonexistent.txt")
	dstPath := filepath.Join(tmpDir, "dest.txt")

	err = copyFile(srcPath, dstPath)
	assert.Error(t, err)
}

func TestCreateFlagFile_Success(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "flagfile-test-*")
	require.NoError(t, err)
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	flagPath := filepath.Join(tmpDir, "test.flag")

	err = createFlagFile(flagPath)
	require.NoError(t, err)

	assert.FileExists(t, flagPath)
}

func TestValidateEnrollment_NotEnrolled(t *testing.T) {
	_, config, cleanup := setupTestEnvWithMockCerts(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	enroller, err := NewSecureBootEnroller(config, logger)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = enroller.ValidateEnrollment(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "keys not enrolled")
}

func TestValidateEnrollment_Success(t *testing.T) {
	// Use full test environment with valid certificates
	_, config, cleanup := setupTestEnv(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	enroller, err := NewSecureBootEnroller(config, logger)
	require.NoError(t, err)

	// First, enroll keys
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = enroller.EnrollKeys(ctx)
	require.NoError(t, err)

	// Now validate
	err = enroller.ValidateEnrollment(ctx)
	require.NoError(t, err)
}

func TestGetEnrollmentStatus_NoNVRAM(t *testing.T) {
	_, config, cleanup := setupTestEnvWithMockCerts(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	enroller, err := NewSecureBootEnroller(config, logger)
	require.NoError(t, err)

	status, err := enroller.GetEnrollmentStatus()
	require.NoError(t, err)
	assert.NotNil(t, status)
	assert.False(t, status.SecureBootEnabled)
	assert.False(t, status.KeysEnrolled)
}

func TestGetEnrollmentStatus_AfterEnrollment(t *testing.T) {
	// Use full test environment with valid certificates and real/proper OVMF
	_, config, cleanup := setupTestEnv(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	enroller, err := NewSecureBootEnroller(config, logger)
	require.NoError(t, err)

	// Enroll keys
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = enroller.EnrollKeys(ctx)
	require.NoError(t, err)

	// Get status
	status, err := enroller.GetEnrollmentStatus()
	require.NoError(t, err)
	assert.NotNil(t, status)
	assert.True(t, status.SecureBootEnabled)
	assert.True(t, status.HasPK)
	assert.True(t, status.HasKEK)
	assert.True(t, status.HasDB)
	assert.True(t, status.KeysEnrolled)
	assert.False(t, status.SetupMode) // Should be in user mode after enrollment
}

func TestNewSecureBootEnroller_NilLogger(t *testing.T) {
	_, config, cleanup := setupTestEnvWithMockCerts(t)
	defer cleanup()

	// Should use default logger if nil is provided
	enroller, err := NewSecureBootEnroller(config, nil)
	require.NoError(t, err)
	assert.NotNil(t, enroller)
	assert.NotNil(t, enroller.logger)
}

func TestNewSecureBootEnroller_DebugMode(t *testing.T) {
	_, config, cleanup := setupTestEnvWithMockCerts(t)
	defer cleanup()

	config.Debug = true

	logger := logging.DefaultLogger()
	enroller, err := NewSecureBootEnroller(config, logger)
	require.NoError(t, err)
	assert.NotNil(t, enroller)
	assert.True(t, enroller.debug)
}

func TestLoadCertificate_PEM(t *testing.T) {
	_, config, cleanup := setupTestEnv(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	enroller, err := NewSecureBootEnroller(config, logger)
	require.NoError(t, err)

	cert, err := enroller.loadCertificate("PK.crt")
	require.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Equal(t, "Platform Key", cert.Subject.CommonName)
}

func TestLoadCertificate_DER(t *testing.T) {
	tmpDir, config, cleanup := setupTestEnv(t)
	defer cleanup()

	// Create a DER-encoded certificate
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "DER Test",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	// Write DER directly (no PEM encoding)
	derPath := filepath.Join(tmpDir, "keys", "DER.crt")
	require.NoError(t, os.WriteFile(derPath, certDER, 0644))

	logger := logging.DefaultLogger()
	enroller, err := NewSecureBootEnroller(config, logger)
	require.NoError(t, err)

	cert, err := enroller.loadCertificate("DER.crt")
	require.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Equal(t, "DER Test", cert.Subject.CommonName)
}

func TestLoadCertificate_Invalid(t *testing.T) {
	_, config, cleanup := setupTestEnvWithMockCerts(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	enroller, err := NewSecureBootEnroller(config, logger)
	require.NoError(t, err)

	_, err = enroller.loadCertificate("PK.crt")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse certificate")
}

func TestLoadCertificate_FileNotFound(t *testing.T) {
	_, config, cleanup := setupTestEnvWithMockCerts(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	enroller, err := NewSecureBootEnroller(config, logger)
	require.NoError(t, err)

	_, err = enroller.loadCertificate("NONEXISTENT.crt")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read certificate")
}

func TestSecureBootEnrollerConfig_EmptyKeysDir(t *testing.T) {
	config := &SecureBootEnrollerConfig{
		KeysDir:      "",
		NVRAMDir:     "/tmp/nvram",
		OVMFVarsPath: "/tmp/ovmf.fd",
	}

	enroller, err := NewSecureBootEnroller(config, nil)
	assert.Nil(t, enroller)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "keys directory not specified")
}

func TestSecureBootEnrollerConfig_EmptyNVRAMDir(t *testing.T) {
	tmpDir := t.TempDir()
	keysDir := filepath.Join(tmpDir, "keys")
	require.NoError(t, os.MkdirAll(keysDir, 0755))

	// Create required key files
	for _, keyFile := range []string{"PK.crt", "KEK.crt", "DB.crt"} {
		require.NoError(t, os.WriteFile(filepath.Join(keysDir, keyFile), []byte("mock"), 0644))
	}

	ovmfPath := filepath.Join(tmpDir, "OVMF_VARS.fd")
	require.NoError(t, os.WriteFile(ovmfPath, []byte("mock"), 0644))

	config := &SecureBootEnrollerConfig{
		KeysDir:      keysDir,
		NVRAMDir:     "",
		OVMFVarsPath: ovmfPath,
	}

	enroller, err := NewSecureBootEnroller(config, nil)
	assert.Nil(t, enroller)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "NVRAM directory not specified")
}

func TestSecureBootEnrollerConfig_EmptyOVMFVarsPath(t *testing.T) {
	tmpDir := t.TempDir()
	keysDir := filepath.Join(tmpDir, "keys")
	require.NoError(t, os.MkdirAll(keysDir, 0755))

	// Create required key files
	for _, keyFile := range []string{"PK.crt", "KEK.crt", "DB.crt"} {
		require.NoError(t, os.WriteFile(filepath.Join(keysDir, keyFile), []byte("mock"), 0644))
	}

	config := &SecureBootEnrollerConfig{
		KeysDir:      keysDir,
		NVRAMDir:     filepath.Join(tmpDir, "nvram"),
		OVMFVarsPath: "",
	}

	enroller, err := NewSecureBootEnroller(config, nil)
	assert.Nil(t, enroller)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "OVMF VARS path not specified")
}
