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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create a test certificate
func createTestCertificate(t *testing.T, commonName string) (*x509.Certificate, []byte) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, certDER
}

// Helper function to create a test NVRAM file
func createTestNVRAM(t *testing.T, path string) {
	t.Helper()

	// Create minimal valid NVRAM structure
	data := make([]byte, 512*1024) // 512KB typical size

	// Fill with erased state
	for i := range data {
		data[i] = 0xFF
	}

	// Write firmware volume header
	// Zero vector (16 bytes)
	for i := 0; i < 16; i++ {
		data[i] = 0
	}

	// FileSystem GUID (16 bytes) - use FFS2
	copy(data[16:32], FFS2GUID.Bytes())

	// FvLength (8 bytes)
	fvLen := uint64(len(data))
	data[32] = byte(fvLen)
	data[33] = byte(fvLen >> 8)
	data[34] = byte(fvLen >> 16)
	data[35] = byte(fvLen >> 24)
	data[36] = byte(fvLen >> 32)
	data[37] = byte(fvLen >> 40)
	data[38] = byte(fvLen >> 48)
	data[39] = byte(fvLen >> 56)

	// Signature "_FVH" (4 bytes)
	copy(data[40:44], FirmwareVolumeSignature[:])

	// Attributes (4 bytes)
	data[44] = 0x00
	data[45] = 0x04
	data[46] = 0x0F
	data[47] = 0x00

	// HeaderLength (2 bytes) - 0x48 = 72 bytes
	data[48] = 0x48
	data[49] = 0x00

	// Checksum (2 bytes) - skip for test
	data[50] = 0x00
	data[51] = 0x00

	// ExtHeaderOffset (2 bytes)
	data[52] = 0x00
	data[53] = 0x00

	// Reserved (1 byte)
	data[54] = 0x00

	// Revision (1 byte)
	data[55] = 0x02

	// Variable store header at offset 72 (0x48)
	// GUID - use NVRAMVariableStoreGUID
	copy(data[72:88], NVRAMVariableStoreGUID.Bytes())

	// Size (4 bytes) - rest of file
	vsSize := uint32(len(data) - 72)
	data[88] = byte(vsSize)
	data[89] = byte(vsSize >> 8)
	data[90] = byte(vsSize >> 16)
	data[91] = byte(vsSize >> 24)

	// Format (1 byte)
	data[92] = VarStoreFormatted

	// State (1 byte)
	data[93] = VarStoreHealthy

	// Reserved (2 bytes)
	data[94] = 0
	data[95] = 0

	// Reserved1 (4 bytes)
	data[96] = 0
	data[97] = 0
	data[98] = 0
	data[99] = 0

	err := os.WriteFile(path, data, 0644)
	require.NoError(t, err)
}

func TestNewSecureBootEnroller_Success(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "enroller-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	config := &SecureBootEnrollerConfig{
		NVRAMPath: filepath.Join(tmpDir, "OVMF_VARS.fd"),
		KeysDir:   tmpDir,
	}

	logger := logging.DefaultLogger()
	enroller, err := NewSecureBootEnroller(config, logger)
	require.NoError(t, err)
	assert.NotNil(t, enroller)
	assert.Equal(t, config.NVRAMPath, enroller.nvramPath)
	assert.Equal(t, config.KeysDir, enroller.keysDir)
	assert.False(t, enroller.ownerGUID.IsZero())
}

func TestNewSecureBootEnroller_WithOwnerGUID(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "enroller-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	ownerGUID := NewGUID()
	config := &SecureBootEnrollerConfig{
		NVRAMPath: filepath.Join(tmpDir, "OVMF_VARS.fd"),
		KeysDir:   tmpDir,
		OwnerGUID: &ownerGUID,
	}

	enroller, err := NewSecureBootEnroller(config, nil)
	require.NoError(t, err)
	assert.Equal(t, ownerGUID, enroller.ownerGUID)
}

func TestNewSecureBootEnroller_NilConfig(t *testing.T) {
	enroller, err := NewSecureBootEnroller(nil, nil)
	assert.Error(t, err)
	assert.Nil(t, enroller)
	assert.Contains(t, err.Error(), "config cannot be nil")
}

func TestNewSecureBootEnroller_EmptyNVRAMPath(t *testing.T) {
	config := &SecureBootEnrollerConfig{
		NVRAMPath: "",
		KeysDir:   "/tmp/keys",
	}

	enroller, err := NewSecureBootEnroller(config, nil)
	assert.Error(t, err)
	assert.Nil(t, enroller)
	assert.Contains(t, err.Error(), "NVRAM path not specified")
}

func TestNewSecureBootEnroller_EmptyKeysDir(t *testing.T) {
	config := &SecureBootEnrollerConfig{
		NVRAMPath: "/tmp/OVMF_VARS.fd",
		KeysDir:   "",
	}

	enroller, err := NewSecureBootEnroller(config, nil)
	assert.Error(t, err)
	assert.Nil(t, enroller)
	assert.Contains(t, err.Error(), "keys directory not specified")
}

func TestEnrollKeys_Success(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "enroller-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create test certificates
	_, pkDER := createTestCertificate(t, "Platform Key")
	_, kekDER := createTestCertificate(t, "Key Exchange Key")
	_, dbDER := createTestCertificate(t, "Database Key")

	// Write certificates as PEM files
	pkPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pkDER})
	kekPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: kekDER})
	dbPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: dbDER})

	err = os.WriteFile(filepath.Join(tmpDir, "PK.crt"), pkPEM, 0644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tmpDir, "KEK.crt"), kekPEM, 0644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tmpDir, "DB.crt"), dbPEM, 0644)
	require.NoError(t, err)

	// Create test NVRAM template
	templatePath := filepath.Join(tmpDir, "OVMF_VARS_template.fd")
	createTestNVRAM(t, templatePath)

	config := &SecureBootEnrollerConfig{
		NVRAMPath:    filepath.Join(tmpDir, "OVMF_VARS.fd"),
		KeysDir:      tmpDir,
		TemplatePath: templatePath,
	}

	enroller, err := NewSecureBootEnroller(config, nil)
	require.NoError(t, err)

	ctx := context.Background()
	err = enroller.EnrollKeys(ctx)
	require.NoError(t, err)

	// Verify NVRAM file was created
	_, err = os.Stat(config.NVRAMPath)
	assert.NoError(t, err)
}

func TestEnrollKeys_MissingPK(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "enroller-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	templatePath := filepath.Join(tmpDir, "OVMF_VARS_template.fd")
	createTestNVRAM(t, templatePath)

	config := &SecureBootEnrollerConfig{
		NVRAMPath:    filepath.Join(tmpDir, "OVMF_VARS.fd"),
		KeysDir:      tmpDir,
		TemplatePath: templatePath,
	}

	enroller, err := NewSecureBootEnroller(config, nil)
	require.NoError(t, err)

	ctx := context.Background()
	err = enroller.EnrollKeys(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load Platform Key")
}

func TestInitializeNVRAM_ExistingFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "enroller-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	nvramPath := filepath.Join(tmpDir, "OVMF_VARS.fd")
	createTestNVRAM(t, nvramPath)

	config := &SecureBootEnrollerConfig{
		NVRAMPath: nvramPath,
		KeysDir:   tmpDir,
	}

	enroller, err := NewSecureBootEnroller(config, nil)
	require.NoError(t, err)

	err = enroller.initializeNVRAM()
	assert.NoError(t, err)
}

func TestInitializeNVRAM_CopyTemplate(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "enroller-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	templatePath := filepath.Join(tmpDir, "OVMF_VARS_template.fd")
	createTestNVRAM(t, templatePath)

	nvramPath := filepath.Join(tmpDir, "OVMF_VARS.fd")

	config := &SecureBootEnrollerConfig{
		NVRAMPath:    nvramPath,
		KeysDir:      tmpDir,
		TemplatePath: templatePath,
	}

	enroller, err := NewSecureBootEnroller(config, nil)
	require.NoError(t, err)

	err = enroller.initializeNVRAM()
	assert.NoError(t, err)

	// Verify file was copied
	_, err = os.Stat(nvramPath)
	assert.NoError(t, err)
}

func TestInitializeNVRAM_NoTemplate(t *testing.T) {
	// This test verifies that when no template is provided and no common OVMF paths
	// exist, the initialization fails with an appropriate error.
	// We use a completely isolated temp directory to ensure no system OVMF files interfere.

	tmpDir, err := os.MkdirTemp("", "enroller-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	nvramPath := filepath.Join(tmpDir, "OVMF_VARS.fd")

	config := &SecureBootEnrollerConfig{
		NVRAMPath: nvramPath,
		KeysDir:   tmpDir,
		// No TemplatePath specified - enroller will try common paths
	}

	enroller, err := NewSecureBootEnroller(config, nil)
	require.NoError(t, err)

	// The initializeNVRAM function checks common OVMF paths and uses them if found.
	// This is expected behavior - it provides sensible defaults.
	// We need to verify that:
	// 1. If OVMF is installed, template is found and used (success)
	// 2. If OVMF is NOT installed, error is returned
	err = enroller.initializeNVRAM()

	// Check if any common OVMF paths exist on this system
	commonPaths := []string{
		"/usr/share/OVMF/OVMF_VARS_4M.fd",
		"/usr/share/OVMF/OVMF_VARS.fd",
		"/usr/share/edk2/ovmf/OVMF_VARS.fd",
		"/usr/share/qemu/OVMF_VARS.fd",
	}
	ovmfExists := false
	for _, p := range commonPaths {
		if _, statErr := os.Stat(p); statErr == nil {
			ovmfExists = true
			break
		}
	}

	if ovmfExists {
		// OVMF is installed on this system - initialization should succeed
		// by using the system template
		assert.NoError(t, err, "initialization should succeed when OVMF is installed")
		// Verify the NVRAM file was created
		_, statErr := os.Stat(nvramPath)
		assert.NoError(t, statErr, "NVRAM file should be created from system template")
	} else {
		// OVMF is not installed - we expect the error
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "NVRAM template not found")
	}
}

func TestLoadCertificate_PEM(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "enroller-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	_, certDER := createTestCertificate(t, "Test Certificate")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	certPath := filepath.Join(tmpDir, "test.crt")
	err = os.WriteFile(certPath, certPEM, 0644)
	require.NoError(t, err)

	config := &SecureBootEnrollerConfig{
		NVRAMPath: filepath.Join(tmpDir, "OVMF_VARS.fd"),
		KeysDir:   tmpDir,
	}

	enroller, err := NewSecureBootEnroller(config, nil)
	require.NoError(t, err)

	cert, err := enroller.loadCertificate("test.crt")
	require.NoError(t, err)
	assert.Equal(t, "Test Certificate", cert.Subject.CommonName)
}

func TestLoadCertificate_DER(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "enroller-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	_, certDER := createTestCertificate(t, "Test Certificate")

	certPath := filepath.Join(tmpDir, "test.crt")
	err = os.WriteFile(certPath, certDER, 0644)
	require.NoError(t, err)

	config := &SecureBootEnrollerConfig{
		NVRAMPath: filepath.Join(tmpDir, "OVMF_VARS.fd"),
		KeysDir:   tmpDir,
	}

	enroller, err := NewSecureBootEnroller(config, nil)
	require.NoError(t, err)

	cert, err := enroller.loadCertificate("test.crt")
	require.NoError(t, err)
	assert.Equal(t, "Test Certificate", cert.Subject.CommonName)
}

func TestLoadCertificate_NotFound(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "enroller-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	config := &SecureBootEnrollerConfig{
		NVRAMPath: filepath.Join(tmpDir, "OVMF_VARS.fd"),
		KeysDir:   tmpDir,
	}

	enroller, err := NewSecureBootEnroller(config, nil)
	require.NoError(t, err)

	_, err = enroller.loadCertificate("nonexistent.crt")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read certificate")
}

func TestLoadCertificate_Invalid(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "enroller-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	certPath := filepath.Join(tmpDir, "invalid.crt")
	err = os.WriteFile(certPath, []byte("invalid certificate data"), 0644)
	require.NoError(t, err)

	config := &SecureBootEnrollerConfig{
		NVRAMPath: filepath.Join(tmpDir, "OVMF_VARS.fd"),
		KeysDir:   tmpDir,
	}

	enroller, err := NewSecureBootEnroller(config, nil)
	require.NoError(t, err)

	_, err = enroller.loadCertificate("invalid.crt")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse certificate")
}

func TestGetEnrollmentStatus(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "enroller-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	nvramPath := filepath.Join(tmpDir, "OVMF_VARS.fd")
	createTestNVRAM(t, nvramPath)

	// Open NVRAM and set some variables
	nvram, err := OpenNVRAM(nvramPath)
	require.NoError(t, err)

	// Set SecureBoot enabled
	_ = nvram.SetVariable("SecureBoot", EFIGlobalVariable, AttrNonVolatile|AttrBootserviceAccess|AttrRuntimeAccess, []byte{0x01})

	// Set SetupMode disabled
	_ = nvram.SetVariable("SetupMode", EFIGlobalVariable, AttrNonVolatile|AttrBootserviceAccess|AttrRuntimeAccess, []byte{0x00})

	// Set PK, KEK, db
	_, pkDER := createTestCertificate(t, "PK")
	pkESL := NewSignatureListFromCert(pkDER, NewGUID())
	_ = nvram.SetVariable("PK", EFIGlobalVariable, SecureBootAttributes, pkESL.Bytes())

	_, kekDER := createTestCertificate(t, "KEK")
	kekESL := NewSignatureListFromCert(kekDER, NewGUID())
	_ = nvram.SetVariable("KEK", EFIGlobalVariable, SecureBootAttributes, kekESL.Bytes())

	_, dbDER := createTestCertificate(t, "DB")
	dbESL := NewSignatureListFromCert(dbDER, NewGUID())
	_ = nvram.SetVariable("db", EFIImageSecurityDatabase, SecureBootAttributes, dbESL.Bytes())

	err = nvram.Save()
	require.NoError(t, err)

	config := &SecureBootEnrollerConfig{
		NVRAMPath: nvramPath,
		KeysDir:   tmpDir,
	}

	enroller, err := NewSecureBootEnroller(config, nil)
	require.NoError(t, err)

	status, err := enroller.GetEnrollmentStatus()
	require.NoError(t, err)
	assert.True(t, status.SecureBootEnabled)
	assert.False(t, status.SetupMode)
	assert.True(t, status.HasPK)
	assert.True(t, status.HasKEK)
	assert.True(t, status.HasDB)
	assert.True(t, status.KeysEnrolled)
}

func TestGetEnrollmentStatus_EmptyNVRAM(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "enroller-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	nvramPath := filepath.Join(tmpDir, "OVMF_VARS.fd")
	createTestNVRAM(t, nvramPath)

	config := &SecureBootEnrollerConfig{
		NVRAMPath: nvramPath,
		KeysDir:   tmpDir,
	}

	enroller, err := NewSecureBootEnroller(config, nil)
	require.NoError(t, err)

	status, err := enroller.GetEnrollmentStatus()
	require.NoError(t, err)
	assert.False(t, status.SecureBootEnabled)
	assert.False(t, status.HasPK)
	assert.False(t, status.HasKEK)
	assert.False(t, status.HasDB)
	assert.False(t, status.KeysEnrolled)
}

func TestEnrollmentStatus_String(t *testing.T) {
	status := &EnrollmentStatus{
		SecureBootEnabled: true,
		SetupMode:         false,
		HasPK:             true,
		HasKEK:            true,
		HasDB:             true,
		HasDBX:            true,
		KeysEnrolled:      true,
	}

	str := status.String()
	assert.Contains(t, str, "SecureBoot: enabled")
	assert.Contains(t, str, "Mode: User Mode")
	assert.Contains(t, str, "PK: true")
	assert.Contains(t, str, "KEK: true")
	assert.Contains(t, str, "db: true")
	assert.Contains(t, str, "dbx: true")
}

func TestEnrollmentStatus_String_Disabled(t *testing.T) {
	status := &EnrollmentStatus{
		SecureBootEnabled: false,
		SetupMode:         true,
		HasPK:             false,
		HasKEK:            false,
		HasDB:             false,
		HasDBX:            false,
		KeysEnrolled:      false,
	}

	str := status.String()
	assert.Contains(t, str, "SecureBoot: disabled")
	assert.Contains(t, str, "Mode: Setup Mode")
	assert.Contains(t, str, "PK: false")
	assert.Contains(t, str, "KEK: false")
	assert.Contains(t, str, "db: false")
	assert.Contains(t, str, "dbx: false")
}

func TestSetPlatformInfo_Success(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "enroller-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	nvramPath := filepath.Join(tmpDir, "OVMF_VARS.fd")
	createTestNVRAM(t, nvramPath)

	config := &SecureBootEnrollerConfig{
		NVRAMPath: nvramPath,
		KeysDir:   tmpDir,
	}

	enroller, err := NewSecureBootEnroller(config, nil)
	require.NoError(t, err)

	info := &PlatformInfo{
		Version:   "1.0.0",
		BuildDate: "2024-01-15T12:00:00Z",
		GitCommit: "abc123",
	}

	ctx := context.Background()
	err = enroller.SetPlatformInfo(ctx, info)
	require.NoError(t, err)

	// Verify it was saved
	nvram, err := OpenNVRAM(nvramPath)
	require.NoError(t, err)

	v, err := nvram.GetVariable("TRUSTED_PLATFORM", TrustedPlatformGUID)
	require.NoError(t, err)
	assert.Equal(t, "1.0.0|2024-01-15T12:00:00Z|abc123", string(v.Data))
}

func TestSetPlatformInfo_NilInfo(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "enroller-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	nvramPath := filepath.Join(tmpDir, "OVMF_VARS.fd")
	createTestNVRAM(t, nvramPath)

	config := &SecureBootEnrollerConfig{
		NVRAMPath: nvramPath,
		KeysDir:   tmpDir,
	}

	enroller, err := NewSecureBootEnroller(config, nil)
	require.NoError(t, err)

	ctx := context.Background()
	err = enroller.SetPlatformInfo(ctx, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "platform info cannot be nil")
}

func TestSetPlatformInfo_EmptyVersion(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "enroller-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	nvramPath := filepath.Join(tmpDir, "OVMF_VARS.fd")
	createTestNVRAM(t, nvramPath)

	config := &SecureBootEnrollerConfig{
		NVRAMPath: nvramPath,
		KeysDir:   tmpDir,
	}

	enroller, err := NewSecureBootEnroller(config, nil)
	require.NoError(t, err)

	info := &PlatformInfo{
		Version: "",
	}

	ctx := context.Background()
	err = enroller.SetPlatformInfo(ctx, info)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "platform version is required")
}

func TestSetPlatformInfo_VersionOnly(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "enroller-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	nvramPath := filepath.Join(tmpDir, "OVMF_VARS.fd")
	createTestNVRAM(t, nvramPath)

	config := &SecureBootEnrollerConfig{
		NVRAMPath: nvramPath,
		KeysDir:   tmpDir,
	}

	enroller, err := NewSecureBootEnroller(config, nil)
	require.NoError(t, err)

	info := &PlatformInfo{
		Version: "1.0.0",
	}

	ctx := context.Background()
	err = enroller.SetPlatformInfo(ctx, info)
	require.NoError(t, err)

	nvram, err := OpenNVRAM(nvramPath)
	require.NoError(t, err)

	v, err := nvram.GetVariable("TRUSTED_PLATFORM", TrustedPlatformGUID)
	require.NoError(t, err)
	assert.Equal(t, "1.0.0", string(v.Data))
}

func TestGetPlatformInfo_Success(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "enroller-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	nvramPath := filepath.Join(tmpDir, "OVMF_VARS.fd")
	createTestNVRAM(t, nvramPath)

	config := &SecureBootEnrollerConfig{
		NVRAMPath: nvramPath,
		KeysDir:   tmpDir,
	}

	enroller, err := NewSecureBootEnroller(config, nil)
	require.NoError(t, err)

	// Set platform info
	info := &PlatformInfo{
		Version:   "1.0.0",
		BuildDate: "2024-01-15T12:00:00Z",
		GitCommit: "abc123",
	}

	ctx := context.Background()
	err = enroller.SetPlatformInfo(ctx, info)
	require.NoError(t, err)

	// Get it back
	retrieved, err := enroller.GetPlatformInfo()
	require.NoError(t, err)
	assert.Equal(t, "1.0.0", retrieved.Version)
	assert.Equal(t, "2024-01-15T12:00:00Z", retrieved.BuildDate)
	assert.Equal(t, "abc123", retrieved.GitCommit)
}

func TestGetPlatformInfo_NotFound(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "enroller-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	nvramPath := filepath.Join(tmpDir, "OVMF_VARS.fd")
	createTestNVRAM(t, nvramPath)

	config := &SecureBootEnrollerConfig{
		NVRAMPath: nvramPath,
		KeysDir:   tmpDir,
	}

	enroller, err := NewSecureBootEnroller(config, nil)
	require.NoError(t, err)

	_, err = enroller.GetPlatformInfo()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get TRUSTED_PLATFORM")
}

func TestEnrollKeysWithPlatformInfo_Success(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "enroller-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create test certificates
	_, pkDER := createTestCertificate(t, "Platform Key")
	_, kekDER := createTestCertificate(t, "Key Exchange Key")
	_, dbDER := createTestCertificate(t, "Database Key")

	// Write certificates as PEM files
	pkPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pkDER})
	kekPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: kekDER})
	dbPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: dbDER})

	err = os.WriteFile(filepath.Join(tmpDir, "PK.crt"), pkPEM, 0644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tmpDir, "KEK.crt"), kekPEM, 0644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tmpDir, "DB.crt"), dbPEM, 0644)
	require.NoError(t, err)

	// Create test NVRAM template
	templatePath := filepath.Join(tmpDir, "OVMF_VARS_template.fd")
	createTestNVRAM(t, templatePath)

	config := &SecureBootEnrollerConfig{
		NVRAMPath:    filepath.Join(tmpDir, "OVMF_VARS.fd"),
		KeysDir:      tmpDir,
		TemplatePath: templatePath,
	}

	enroller, err := NewSecureBootEnroller(config, nil)
	require.NoError(t, err)

	info := &PlatformInfo{
		Version:   "1.0.0",
		BuildDate: "2024-01-15T12:00:00Z",
		GitCommit: "abc123",
	}

	ctx := context.Background()
	err = enroller.EnrollKeysWithPlatformInfo(ctx, info)
	require.NoError(t, err)

	// Verify platform info was set
	retrieved, err := enroller.GetPlatformInfo()
	require.NoError(t, err)
	assert.Equal(t, "1.0.0", retrieved.Version)
}

func TestEnrollKeysWithPlatformInfo_NilInfo(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "enroller-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create test certificates
	_, pkDER := createTestCertificate(t, "Platform Key")
	_, kekDER := createTestCertificate(t, "Key Exchange Key")
	_, dbDER := createTestCertificate(t, "Database Key")

	pkPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pkDER})
	kekPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: kekDER})
	dbPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: dbDER})

	err = os.WriteFile(filepath.Join(tmpDir, "PK.crt"), pkPEM, 0644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tmpDir, "KEK.crt"), kekPEM, 0644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tmpDir, "DB.crt"), dbPEM, 0644)
	require.NoError(t, err)

	templatePath := filepath.Join(tmpDir, "OVMF_VARS_template.fd")
	createTestNVRAM(t, templatePath)

	config := &SecureBootEnrollerConfig{
		NVRAMPath:    filepath.Join(tmpDir, "OVMF_VARS.fd"),
		KeysDir:      tmpDir,
		TemplatePath: templatePath,
	}

	enroller, err := NewSecureBootEnroller(config, nil)
	require.NoError(t, err)

	ctx := context.Background()
	err = enroller.EnrollKeysWithPlatformInfo(ctx, nil)
	require.NoError(t, err)
}

func TestEnrollKeysWithPlatformInfo_EmptyVersion(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "enroller-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create test certificates
	_, pkDER := createTestCertificate(t, "Platform Key")
	_, kekDER := createTestCertificate(t, "Key Exchange Key")
	_, dbDER := createTestCertificate(t, "Database Key")

	pkPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pkDER})
	kekPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: kekDER})
	dbPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: dbDER})

	err = os.WriteFile(filepath.Join(tmpDir, "PK.crt"), pkPEM, 0644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tmpDir, "KEK.crt"), kekPEM, 0644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tmpDir, "DB.crt"), dbPEM, 0644)
	require.NoError(t, err)

	templatePath := filepath.Join(tmpDir, "OVMF_VARS_template.fd")
	createTestNVRAM(t, templatePath)

	config := &SecureBootEnrollerConfig{
		NVRAMPath:    filepath.Join(tmpDir, "OVMF_VARS.fd"),
		KeysDir:      tmpDir,
		TemplatePath: templatePath,
	}

	enroller, err := NewSecureBootEnroller(config, nil)
	require.NoError(t, err)

	info := &PlatformInfo{
		Version: "", // Empty version
	}

	ctx := context.Background()
	err = enroller.EnrollKeysWithPlatformInfo(ctx, info)
	require.NoError(t, err) // Should succeed, platform info just won't be set
}

func TestSetPlatformInfo_WithBuildDateOnly(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "enroller-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	nvramPath := filepath.Join(tmpDir, "OVMF_VARS.fd")
	createTestNVRAM(t, nvramPath)

	config := &SecureBootEnrollerConfig{
		NVRAMPath: nvramPath,
		KeysDir:   tmpDir,
	}

	enroller, err := NewSecureBootEnroller(config, nil)
	require.NoError(t, err)

	info := &PlatformInfo{
		Version:   "1.0.0",
		BuildDate: "2024-01-15T12:00:00Z",
	}

	ctx := context.Background()
	err = enroller.SetPlatformInfo(ctx, info)
	require.NoError(t, err)

	nvram, err := OpenNVRAM(nvramPath)
	require.NoError(t, err)

	v, err := nvram.GetVariable("TRUSTED_PLATFORM", TrustedPlatformGUID)
	require.NoError(t, err)
	assert.Equal(t, "1.0.0|2024-01-15T12:00:00Z", string(v.Data))
}

func TestSetPlatformInfo_WithGitCommitOnly(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "enroller-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	nvramPath := filepath.Join(tmpDir, "OVMF_VARS.fd")
	createTestNVRAM(t, nvramPath)

	config := &SecureBootEnrollerConfig{
		NVRAMPath: nvramPath,
		KeysDir:   tmpDir,
	}

	enroller, err := NewSecureBootEnroller(config, nil)
	require.NoError(t, err)

	info := &PlatformInfo{
		Version:   "1.0.0",
		GitCommit: "abc123",
	}

	ctx := context.Background()
	err = enroller.SetPlatformInfo(ctx, info)
	require.NoError(t, err)

	nvram, err := OpenNVRAM(nvramPath)
	require.NoError(t, err)

	v, err := nvram.GetVariable("TRUSTED_PLATFORM", TrustedPlatformGUID)
	require.NoError(t, err)
	assert.Equal(t, "1.0.0||abc123", string(v.Data))
}

func TestParseVariableStore_TooSmallForHeader(t *testing.T) {
	data := make([]byte, 100)
	for i := range data {
		data[i] = 0xFF
	}

	copy(data[16:32], FFS2GUID.Bytes())
	copy(data[40:44], FirmwareVolumeSignature[:])
	data[48] = 0x48
	data[49] = 0x00

	nvram := &NVRAM{data: data}
	err := nvram.parseFirmwareVolumeHeader()
	require.NoError(t, err)

	err = nvram.parseVariableStore()
	require.NoError(t, err)
}

func TestGetEnrollmentStatus_PartialVariables(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "enroller-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	nvramPath := filepath.Join(tmpDir, "OVMF_VARS.fd")
	createTestNVRAM(t, nvramPath)

	nvram, err := OpenNVRAM(nvramPath)
	require.NoError(t, err)

	// Only set PK, not KEK or db
	_, pkDER := createTestCertificate(t, "PK")
	pkESL := NewSignatureListFromCert(pkDER, NewGUID())
	err = nvram.SetVariable("PK", EFIGlobalVariable, SecureBootAttributes, pkESL.Bytes())
	require.NoError(t, err)

	err = nvram.Save()
	require.NoError(t, err)

	config := &SecureBootEnrollerConfig{
		NVRAMPath: nvramPath,
		KeysDir:   tmpDir,
	}

	enroller, err := NewSecureBootEnroller(config, nil)
	require.NoError(t, err)

	status, err := enroller.GetEnrollmentStatus()
	require.NoError(t, err)
	assert.True(t, status.HasPK)
	assert.False(t, status.HasKEK)
	assert.False(t, status.HasDB)
	assert.False(t, status.KeysEnrolled) // Not all keys present
}

func TestInitializeNVRAM_InvalidTemplate(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "enroller-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create an invalid template (directory instead of file)
	templatePath := filepath.Join(tmpDir, "invalid_template")
	err = os.Mkdir(templatePath, 0755)
	require.NoError(t, err)

	nvramPath := filepath.Join(tmpDir, "OVMF_VARS.fd")

	config := &SecureBootEnrollerConfig{
		NVRAMPath:    nvramPath,
		KeysDir:      tmpDir,
		TemplatePath: templatePath,
	}

	enroller, err := NewSecureBootEnroller(config, nil)
	require.NoError(t, err)

	err = enroller.initializeNVRAM()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read NVRAM template")
}

func TestInitializeNVRAM_WriteError(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "enroller-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	templatePath := filepath.Join(tmpDir, "OVMF_VARS_template.fd")
	createTestNVRAM(t, templatePath)

	// Use a path in a non-existent directory that can't be created
	nvramPath := "/proc/nonexistent/OVMF_VARS.fd" // /proc is read-only

	config := &SecureBootEnrollerConfig{
		NVRAMPath:    nvramPath,
		KeysDir:      tmpDir,
		TemplatePath: templatePath,
	}

	enroller, err := NewSecureBootEnroller(config, nil)
	require.NoError(t, err)

	err = enroller.initializeNVRAM()
	assert.Error(t, err)
}

// TestEnrollKeysDoesNotPersistDerivedVariables pins the corrected enrollment
// contract: SetupMode and SecureBoot are firmware-DERIVED (EDK2 recomputes
// them from PK presence every boot and publishes them as volatile variables),
// so EnrollKeys must not persist them into the variable store. Writing them
// previously corrupted authenticated stores and faulted the firmware variable
// driver on the next boot.
func TestEnrollKeysDoesNotPersistDerivedVariables(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "enroller-derived-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	for name, cn := range map[string]string{"PK.crt": "PK", "KEK.crt": "KEK", "DB.crt": "DB"} {
		_, der := createTestCertificate(t, cn)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, name), certPEM, 0644))
	}

	templatePath := filepath.Join(tmpDir, "OVMF_VARS_template.fd")
	createTestNVRAM(t, templatePath)

	nvramPath := filepath.Join(tmpDir, "OVMF_VARS.fd")
	enroller, err := NewSecureBootEnroller(&SecureBootEnrollerConfig{
		NVRAMPath:    nvramPath,
		KeysDir:      tmpDir,
		TemplatePath: templatePath,
	}, nil)
	require.NoError(t, err)
	require.NoError(t, enroller.EnrollKeys(context.Background()))

	nvram, err := OpenNVRAM(nvramPath)
	require.NoError(t, err)

	for _, derived := range []string{"SetupMode", "SecureBoot"} {
		_, err := nvram.GetVariable(derived, EFIGlobalVariable)
		assert.ErrorIs(t, err, ErrVariableNotFound,
			"%s must not be persisted into the variable store (it is firmware-derived)", derived)
	}

	// The key variables ARE persisted.
	for _, key := range []string{"PK", "KEK"} {
		_, err := nvram.GetVariable(key, EFIGlobalVariable)
		assert.NoError(t, err, "%s must be enrolled", key)
	}
	_, err = nvram.GetVariable("db", EFIImageSecurityDatabase)
	assert.NoError(t, err, "db must be enrolled")
}

// TestGetEnrollmentStatusDerivesFromPK proves the status reader mirrors the
// firmware rule when the derived variables are absent: PK present means User
// Mode with Secure Boot active; no PK means Setup Mode.
func TestGetEnrollmentStatusDerivesFromPK(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "enroller-derive-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	nvramPath := filepath.Join(tmpDir, "OVMF_VARS.fd")
	createTestNVRAM(t, nvramPath)

	enroller, err := NewSecureBootEnroller(&SecureBootEnrollerConfig{
		NVRAMPath: nvramPath,
		KeysDir:   tmpDir,
	}, nil)
	require.NoError(t, err)

	// No PK yet: Setup Mode, Secure Boot inactive.
	status, err := enroller.GetEnrollmentStatus()
	require.NoError(t, err)
	assert.True(t, status.SetupMode, "no PK must report Setup Mode")
	assert.False(t, status.SecureBootEnabled)

	// Enroll only PK.
	nvram, err := OpenNVRAM(nvramPath)
	require.NoError(t, err)
	_, pkDER := createTestCertificate(t, "PK")
	pkESL := NewSignatureListFromCert(pkDER, NewGUID())
	require.NoError(t, nvram.SetVariable("PK", EFIGlobalVariable, SecureBootAttributes, pkESL.Bytes()))
	require.NoError(t, nvram.Save())

	status, err = enroller.GetEnrollmentStatus()
	require.NoError(t, err)
	assert.False(t, status.SetupMode, "PK present must report User Mode")
	assert.True(t, status.SecureBootEnabled, "PK present must report Secure Boot active")
}
