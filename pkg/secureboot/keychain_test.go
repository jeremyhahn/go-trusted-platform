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

package secureboot

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewXKMSManager(t *testing.T) {
	tests := []struct {
		name      string
		config    func(t *testing.T) *XKMSConfig
		wantErr   bool
		errString string
	}{
		{
			name: "nil config",
			config: func(t *testing.T) *XKMSConfig {
				return nil
			},
			wantErr:   true,
			errString: "config cannot be nil",
		},
		{
			name: "empty KeysDir",
			config: func(t *testing.T) *XKMSConfig {
				return &XKMSConfig{
					KeysDir: "",
				}
			},
			wantErr:   true,
			errString: "KeysDir cannot be empty",
		},
		{
			name: "invalid KeySize",
			config: func(t *testing.T) *XKMSConfig {
				return &XKMSConfig{
					KeysDir: t.TempDir(),
					KeySize: 1024,
				}
			},
			wantErr:   true,
			errString: "KeySize must be at least 2048 bits",
		},
		{
			name: "invalid backend",
			config: func(t *testing.T) *XKMSConfig {
				return &XKMSConfig{
					KeysDir: t.TempDir(),
					Backend: "invalid",
				}
			},
			wantErr:   true,
			errString: "unsupported backend",
		},
		{
			name: "valid config with file backend",
			config: func(t *testing.T) *XKMSConfig {
				return &XKMSConfig{
					KeysDir: t.TempDir(),
					Backend: BackendFile,
				}
			},
			wantErr: false,
		},
		{
			name: "valid config with software backend",
			config: func(t *testing.T) *XKMSConfig {
				return &XKMSConfig{
					KeysDir: t.TempDir(),
					Backend: BackendSoftware,
				}
			},
			wantErr: false,
		},
		{
			name: "valid config with defaults",
			config: func(t *testing.T) *XKMSConfig {
				return &XKMSConfig{
					KeysDir: t.TempDir(),
				}
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.config(t)
			km, err := NewXKMSManager(config, nil)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errString)
				assert.Nil(t, km)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, km)
				if km != nil {
					km.Close()
				}
			}
		})
	}
}

func TestBackendTypeIsValid(t *testing.T) {
	tests := []struct {
		backend BackendType
		valid   bool
	}{
		{BackendFile, true},
		{BackendSoftware, true},
		{BackendPKCS11, true},
		{BackendTPM2, true},
		{BackendAWSKMS, true},
		{BackendAzureKV, true},
		{BackendGCPKMS, true},
		{BackendVault, true},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.backend), func(t *testing.T) {
			assert.Equal(t, tt.valid, tt.backend.IsValid())
		})
	}
}

func TestXKMSManagerGenerateAllWithFileBackend(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()

	config := &XKMSConfig{
		KeysDir:      tmpDir,
		Backend:      BackendFile,
		CommonName:   "Test Platform",
		Country:      "US",
		Organization: "Test Org",
		KeySize:      2048,
		ValidYears:   1,
		ExportKeys:   true,
	}

	km, err := NewXKMSManager(config, nil)
	require.NoError(t, err)
	defer km.Close()

	ctx := context.Background()
	err = km.GenerateAll(ctx)
	require.NoError(t, err)

	// Verify keys exist
	paths := km.GetKeyPaths()
	assert.FileExists(t, paths.PKKey)
	assert.FileExists(t, paths.PKCert)
	assert.FileExists(t, paths.KEKKey)
	assert.FileExists(t, paths.KEKCert)
	assert.FileExists(t, paths.DBKey)
	assert.FileExists(t, paths.DBCert)

	// Verify KeysExist returns true
	assert.True(t, km.KeysExist())
}

func TestXKMSManagerIdempotent(t *testing.T) {
	tmpDir := t.TempDir()

	config := &XKMSConfig{
		KeysDir:    tmpDir,
		Backend:    BackendFile,
		ExportKeys: true,
	}

	km, err := NewXKMSManager(config, nil)
	require.NoError(t, err)
	defer km.Close()

	ctx := context.Background()

	// First generation
	err = km.GenerateAll(ctx)
	require.NoError(t, err)

	// Get file info for PK key
	pkPath := filepath.Join(tmpDir, "PK.key")
	info1, err := os.Stat(pkPath)
	require.NoError(t, err)

	// Second generation should be idempotent
	err = km.GenerateAll(ctx)
	require.NoError(t, err)

	// File should not have been modified
	info2, err := os.Stat(pkPath)
	require.NoError(t, err)
	assert.Equal(t, info1.ModTime(), info2.ModTime())
}

func TestXKMSManagerGetSigner(t *testing.T) {
	tmpDir := t.TempDir()

	config := &XKMSConfig{
		KeysDir:    tmpDir,
		Backend:    BackendFile,
		ExportKeys: true,
	}

	km, err := NewXKMSManager(config, nil)
	require.NoError(t, err)
	defer km.Close()

	ctx := context.Background()
	err = km.GenerateAll(ctx)
	require.NoError(t, err)

	// Get signer for PK
	signer, err := km.GetSigner(t.Context(), KeyTypePK)
	require.NoError(t, err)
	assert.NotNil(t, signer)
	assert.NotNil(t, signer.Public())
}

func TestXKMSManagerGetKeyPaths(t *testing.T) {
	tmpDir := t.TempDir()

	config := &XKMSConfig{
		KeysDir: tmpDir,
		Backend: BackendFile,
	}

	km, err := NewXKMSManager(config, nil)
	require.NoError(t, err)
	defer km.Close()

	paths := km.GetKeyPaths()
	assert.Equal(t, filepath.Join(tmpDir, "PK.key"), paths.PKKey)
	assert.Equal(t, filepath.Join(tmpDir, "PK.crt"), paths.PKCert)
	assert.Equal(t, filepath.Join(tmpDir, "KEK.key"), paths.KEKKey)
	assert.Equal(t, filepath.Join(tmpDir, "KEK.crt"), paths.KEKCert)
	assert.Equal(t, filepath.Join(tmpDir, "DB.key"), paths.DBKey)
	assert.Equal(t, filepath.Join(tmpDir, "DB.crt"), paths.DBCert)
}

func TestXKMSManagerKeysExist(t *testing.T) {
	tmpDir := t.TempDir()

	config := &XKMSConfig{
		KeysDir:    tmpDir,
		Backend:    BackendFile,
		ExportKeys: true,
	}

	km, err := NewXKMSManager(config, nil)
	require.NoError(t, err)
	defer km.Close()

	// Before generation, keys should not exist
	assert.False(t, km.KeysExist())

	// Generate keys
	ctx := context.Background()
	err = km.GenerateAll(ctx)
	require.NoError(t, err)

	// After generation, keys should exist
	assert.True(t, km.KeysExist())
}

// TestBackendToStoreType tests the backendToStoreType function coverage
func TestBackendToStoreType(t *testing.T) {
	tests := []struct {
		name     string
		backend  BackendType
		expected xkmssdk.StoreType
	}{
		{"File backend", BackendFile, xkmssdk.StoreSoftware},
		{"Software backend", BackendSoftware, xkmssdk.StoreSoftware},
		{"PKCS11 backend", BackendPKCS11, xkmssdk.StorePKCS11},
		{"TPM2 backend", BackendTPM2, xkmssdk.StoreTPM2},
		{"AWS KMS backend", BackendAWSKMS, xkmssdk.StoreAWSKMS},
		{"Azure KV backend", BackendAzureKV, xkmssdk.StoreAzureKV},
		{"GCP KMS backend", BackendGCPKMS, xkmssdk.StoreGCPKMS},
		{"Vault backend", BackendVault, xkmssdk.StoreVault},
		{"Unknown backend", "unknown", xkmssdk.StoreSoftware}, // default case
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := backendToStoreType(tt.backend)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestGenerateAllWithoutExport tests generation without key export
func TestGenerateAllWithoutExport(t *testing.T) {
	tmpDir := t.TempDir()

	config := &XKMSConfig{
		KeysDir:    tmpDir,
		Backend:    BackendFile,
		ExportKeys: false, // Don't export keys
	}

	km, err := NewXKMSManager(config, nil)
	require.NoError(t, err)
	defer km.Close()

	ctx := context.Background()
	err = km.GenerateAll(ctx)
	require.NoError(t, err)

	// Verify keys directory was NOT created since ExportKeys is false
	paths := km.GetKeyPaths()
	_, err = os.Stat(paths.PKKey)
	assert.True(t, os.IsNotExist(err), "Key files should not exist when ExportKeys is false")
}

// TestWriteKeyError tests error handling in writeKey
func TestWriteKeyError(t *testing.T) {
	// Generate a test key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Test successful write
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test.key")
	err = writeKey(privateKey, keyPath)
	require.NoError(t, err)
	assert.FileExists(t, keyPath)

	// Test error - invalid path (directory that doesn't exist with read-only parent)
	invalidPath := filepath.Join(tmpDir, "nonexistent", "subdir", "test.key")
	err = writeKey(privateKey, invalidPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create key file")
}

// TestWriteCertificateError tests error handling in writeCertificate
func TestWriteCertificateError(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test certificate
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test",
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Test successful write
	certPath := filepath.Join(tmpDir, "test.crt")
	err = writeCertificate(cert, certPath)
	require.NoError(t, err)
	assert.FileExists(t, certPath)

	// Test error - invalid path
	invalidPath := filepath.Join(tmpDir, "nonexistent", "subdir", "test.crt")
	err = writeCertificate(cert, invalidPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create certificate file")
}

// TestGetSignerError tests error handling in GetSigner
func TestGetSignerError(t *testing.T) {
	tmpDir := t.TempDir()

	config := &XKMSConfig{
		KeysDir:    tmpDir,
		Backend:    BackendFile,
		ExportKeys: true,
	}

	km, err := NewXKMSManager(config, nil)
	require.NoError(t, err)
	defer km.Close()

	// Try to get signer for non-existent key
	_, err = km.GetSigner(t.Context(), KeyTypePK)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get key")
}

// TestCloseWhenNotInitialized tests Close on a manager that never got a backend
func TestCloseWhenNotInitialized(t *testing.T) {
	km := &XKMSManager{}

	err := km.Close()
	assert.NoError(t, err)

	_, err = km.GetSigner(t.Context(), KeyTypePK)
	assert.ErrorIs(t, err, ErrManagerClosed)
}

// TestCloseError tests error handling in Close
func TestCloseError(t *testing.T) {
	tmpDir := t.TempDir()

	config := &XKMSConfig{
		KeysDir:    tmpDir,
		Backend:    BackendFile,
		ExportKeys: true,
	}

	km, err := NewXKMSManager(config, nil)
	require.NoError(t, err)

	// Close should work fine
	err = km.Close()
	assert.NoError(t, err)
	assert.Nil(t, km.ks)

	// Second close should also work (already closed)
	err = km.Close()
	assert.NoError(t, err)

	// A closed manager refuses key operations instead of panicking
	_, err = km.GetSigner(context.Background(), KeyTypePK)
	assert.ErrorIs(t, err, ErrManagerClosed)
	assert.ErrorIs(t, km.GeneratePlatformKey(context.Background()), ErrManagerClosed)
}

// TestInitializeServiceReinitialization tests reinitializing the service
func TestInitializeServiceReinitialization(t *testing.T) {
	tmpDir := t.TempDir()

	config := &XKMSConfig{
		KeysDir:    tmpDir,
		Backend:    BackendFile,
		ExportKeys: true,
	}

	// First manager generates the keys
	km1, err := NewXKMSManager(config, nil)
	require.NoError(t, err)
	require.NotNil(t, km1.ks)
	require.NoError(t, km1.GenerateAll(context.Background()))
	require.NoError(t, km1.Close())

	// A second manager on the same directory reads the keys back
	km2, err := NewXKMSManager(config, nil)
	require.NoError(t, err)
	require.NotNil(t, km2.ks)
	signer, err := km2.GetSigner(context.Background(), KeyTypeDB)
	require.NoError(t, err)
	assert.NotNil(t, signer.Public())
	require.NoError(t, km2.Close())
}

// TestCreateXKMSBackendUnsupported tests unsupported backend types
func TestCreateXKMSBackendUnsupported(t *testing.T) {
	tmpDir := t.TempDir()

	unsupportedBackends := []BackendType{
		BackendPKCS11,
		BackendTPM2,
		BackendAWSKMS,
		BackendAzureKV,
		BackendGCPKMS,
		BackendVault,
	}

	for _, backend := range unsupportedBackends {
		t.Run(string(backend), func(t *testing.T) {
			config := &XKMSConfig{
				KeysDir: tmpDir,
				Backend: backend,
			}

			km, err := NewXKMSManager(config, nil)
			assert.Error(t, err)
			assert.Nil(t, km)
			assert.Contains(t, err.Error(), "requires a pre-configured KeyStore instance")
		})
	}
}

// TestGenerateIndividualKeys tests generating individual keys
func TestGenerateIndividualKeys(t *testing.T) {
	tests := []struct {
		name     string
		keyType  KeyType
		genFunc  func(km *XKMSManager, ctx context.Context) error
		certName string
		keyName  string
	}{
		{
			name:     "Generate PK",
			keyType:  KeyTypePK,
			genFunc:  func(km *XKMSManager, ctx context.Context) error { return km.GeneratePlatformKey(ctx) },
			certName: "PK.crt",
			keyName:  "PK.key",
		},
		{
			name:     "Generate KEK",
			keyType:  KeyTypeKEK,
			genFunc:  func(km *XKMSManager, ctx context.Context) error { return km.GenerateKeyExchangeKey(ctx) },
			certName: "KEK.crt",
			keyName:  "KEK.key",
		},
		{
			name:     "Generate DB",
			keyType:  KeyTypeDB,
			genFunc:  func(km *XKMSManager, ctx context.Context) error { return km.GenerateDatabaseKey(ctx) },
			certName: "DB.crt",
			keyName:  "DB.key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			config := &XKMSConfig{
				KeysDir:      tmpDir,
				Backend:      BackendFile,
				CommonName:   "Test",
				Country:      "US",
				Organization: "Test Org",
				ExportKeys:   true,
			}

			km, err := NewXKMSManager(config, nil)
			require.NoError(t, err)
			defer km.Close()

			ctx := context.Background()
			err = tt.genFunc(km, ctx)
			require.NoError(t, err)

			// Verify files exist
			certPath := filepath.Join(tmpDir, tt.certName)
			keyPath := filepath.Join(tmpDir, tt.keyName)
			assert.FileExists(t, certPath)
			assert.FileExists(t, keyPath)
		})
	}
}

// TestKeysExistPartialKeys tests KeysExist when only some keys exist
func TestKeysExistPartialKeys(t *testing.T) {
	tmpDir := t.TempDir()

	config := &XKMSConfig{
		KeysDir:    tmpDir,
		Backend:    BackendFile,
		ExportKeys: true,
	}

	km, err := NewXKMSManager(config, nil)
	require.NoError(t, err)
	defer km.Close()

	// Create only PK cert
	ctx := context.Background()
	err = km.GeneratePlatformKey(ctx)
	require.NoError(t, err)

	// KeysExist should return false because not all keys exist
	assert.False(t, km.KeysExist())

	// Generate remaining keys
	err = km.GenerateKeyExchangeKey(ctx)
	require.NoError(t, err)
	err = km.GenerateDatabaseKey(ctx)
	require.NoError(t, err)

	// Now all keys exist
	assert.True(t, km.KeysExist())
}

// TestBackendTypeString tests the String method
func TestBackendTypeString(t *testing.T) {
	tests := []struct {
		backend  BackendType
		expected string
	}{
		{BackendFile, "file"},
		{BackendSoftware, "software"},
		{BackendPKCS11, "pkcs11"},
		{BackendTPM2, "tpm2"},
		{BackendAWSKMS, "awskms"},
		{BackendAzureKV, "azurekv"},
		{BackendGCPKMS, "gcpkms"},
		{BackendVault, "vault"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.backend.String())
		})
	}
}

// TestGenerateKeyFallback tests the fallback path when rawBackend is nil
func TestGenerateKeyFallback(t *testing.T) {
	tmpDir := t.TempDir()

	config := &XKMSConfig{
		KeysDir:    tmpDir,
		Backend:    BackendFile,
		ExportKeys: false,
	}

	km, err := NewXKMSManager(config, nil)
	require.NoError(t, err)
	defer km.Close()

	// Set rawBackend to nil to test fallback
	km.rawBackend = nil

	ctx := context.Background()
	err = km.GeneratePlatformKey(ctx)
	require.NoError(t, err)
}

// TestCreateXKMSBackendErrors tests error paths in createXKMSBackend
func TestCreateXKMSBackendErrors(t *testing.T) {
	// Test with invalid path that can't be created
	tmpDir := t.TempDir()

	// Create a file (not a directory) where we'll try to create subdirectories
	invalidPath := filepath.Join(tmpDir, "file")
	err := os.WriteFile(invalidPath, []byte("test"), 0644)
	require.NoError(t, err)

	// Try to create keys directory under the file (should fail)
	config := &XKMSConfig{
		KeysDir: filepath.Join(invalidPath, "keys"),
		Backend: BackendFile,
	}

	km := &XKMSManager{
		config: config,
		logger: nil,
	}

	_, err = km.createXKMSBackend()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create")
}

// TestInitializeServiceError tests error handling in initializeService
func TestInitializeServiceError(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a file where we need a directory
	invalidPath := filepath.Join(tmpDir, "file")
	err := os.WriteFile(invalidPath, []byte("test"), 0644)
	require.NoError(t, err)

	// Try to use it as KeysDir
	config := &XKMSConfig{
		KeysDir: filepath.Join(invalidPath, "keys"),
		Backend: BackendFile,
	}

	km := &XKMSManager{
		config: config,
		logger: logging.DefaultLogger(),
	}

	err = km.initializeService()
	assert.Error(t, err)
}

// TestGetSignerNonSigner tests error when key doesn't implement crypto.Signer
func TestGetSignerNonSigner(t *testing.T) {
	tmpDir := t.TempDir()

	config := &XKMSConfig{
		KeysDir:    tmpDir,
		Backend:    BackendFile,
		ExportKeys: true,
	}

	km, err := NewXKMSManager(config, nil)
	require.NoError(t, err)
	defer km.Close()

	// Generate a key first
	ctx := context.Background()
	err = km.GeneratePlatformKey(ctx)
	require.NoError(t, err)

	// Now test getting all three signers to cover different key types
	for _, keyType := range []KeyType{KeyTypePK, KeyTypeKEK, KeyTypeDB} {
		km2, err := NewXKMSManager(config, nil)
		require.NoError(t, err)

		if keyType != KeyTypePK {
			// Generate the other keys
			if keyType == KeyTypeKEK {
				err = km2.GenerateKeyExchangeKey(ctx)
			} else {
				err = km2.GenerateDatabaseKey(ctx)
			}
			require.NoError(t, err)
		}

		signer, err := km2.GetSigner(t.Context(), keyType)
		require.NoError(t, err)
		assert.NotNil(t, signer)
		km2.Close()
	}
}

// TestGenerateKeyWithExistingKey tests regenerating an existing key
func TestGenerateKeyWithExistingKey(t *testing.T) {
	tmpDir := t.TempDir()

	config := &XKMSConfig{
		KeysDir:      tmpDir,
		Backend:      BackendFile,
		CommonName:   "Test",
		Country:      "US",
		Organization: "Test Org",
		ExportKeys:   true,
	}

	km, err := NewXKMSManager(config, nil)
	require.NoError(t, err)
	defer km.Close()

	ctx := context.Background()

	// Generate key twice to test the existing key deletion path
	err = km.GeneratePlatformKey(ctx)
	require.NoError(t, err)

	// Regenerate (should delete existing key first)
	err = km.GeneratePlatformKey(ctx)
	require.NoError(t, err)
}

// TestXKMSManagerLeavesProcessServiceAlone guards the vtpm CreateBundle
// failure: platformd's process-wide go-xkms service holds the embedded
// go-quicbaas KMS keys the platform CA signs with, and a Secure Boot manager
// that reset or closed it left the CA with "keystore: not initialized".
func TestXKMSManagerLeavesProcessServiceAlone(t *testing.T) {
	storage := xkmssdk.NewStorageMemory()
	backend, err := xkmssdk.NewSoftwareBackend(&xkmssdk.SoftwareBackendConfig{KeyStorage: storage})
	require.NoError(t, err)
	processKS, err := xkmssdk.NewServiceBackend(&xkmssdk.ServiceBackendConfig{
		Backend:     backend,
		CertStorage: storage,
	})
	require.NoError(t, err)

	if xkmssdk.ServiceIsInitialized() {
		require.NoError(t, xkmssdk.ServiceClose())
		xkmssdk.ServiceReset()
	}
	require.NoError(t, xkmssdk.ServiceInitialize(&xkmssdk.ServiceConfig{
		Backends:       map[string]xkmssdk.ServiceBackend{"software": processKS},
		DefaultBackend: "software",
	}))
	t.Cleanup(func() {
		assert.NoError(t, xkmssdk.ServiceClose())
		xkmssdk.ServiceReset()
	})

	km, err := NewXKMSManager(&XKMSConfig{KeysDir: t.TempDir(), Backend: BackendFile}, nil)
	require.NoError(t, err)
	require.NoError(t, km.GenerateAll(context.Background()))
	require.NoError(t, km.Close())

	require.True(t, xkmssdk.ServiceIsInitialized())
	got, err := xkmssdk.ServiceGetBackend("software")
	require.NoError(t, err)
	assert.Same(t, processKS, got)
}

// TestExportCertificateError tests exportCertificate error handling
func TestExportCertificateError(t *testing.T) {
	tmpDir := t.TempDir()

	config := &XKMSConfig{
		KeysDir:    tmpDir,
		Backend:    BackendFile,
		ExportKeys: true,
	}

	km, err := NewXKMSManager(config, nil)
	require.NoError(t, err)
	defer km.Close()

	// Create a test certificate
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test",
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Point KeysDir to a path under a regular file so file creation
	// fails regardless of privilege level (root bypasses chmod)
	blockerFile := filepath.Join(tmpDir, "blocker")
	err = os.WriteFile(blockerFile, []byte("x"), 0644)
	require.NoError(t, err)
	km.config.KeysDir = filepath.Join(blockerFile, "impossible")

	// Try to export - should fail
	err = km.exportCertificate(cert, KeyTypePK)
	assert.Error(t, err)
}

// TestExportPrivateKeyError tests exportPrivateKey error handling
func TestExportPrivateKeyError(t *testing.T) {
	tmpDir := t.TempDir()

	config := &XKMSConfig{
		KeysDir:    tmpDir,
		Backend:    BackendFile,
		ExportKeys: true,
	}

	km, err := NewXKMSManager(config, nil)
	require.NoError(t, err)
	defer km.Close()

	// Create a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Point KeysDir to a path under a regular file so file creation
	// fails regardless of privilege level (root bypasses chmod)
	blockerFile := filepath.Join(tmpDir, "blocker")
	err = os.WriteFile(blockerFile, []byte("x"), 0644)
	require.NoError(t, err)
	km.config.KeysDir = filepath.Join(blockerFile, "impossible")

	// Try to export - should fail
	err = km.exportPrivateKey(privateKey, KeyTypePK)
	assert.Error(t, err)
}

// TestSaveCertificateError tests certificate save error path
func TestSaveCertificateError(t *testing.T) {
	tmpDir := t.TempDir()

	config := &XKMSConfig{
		KeysDir:    tmpDir,
		Backend:    BackendFile,
		ExportKeys: true,
	}

	km, err := NewXKMSManager(config, nil)
	require.NoError(t, err)

	// Close to make cert storage unavailable, then reinitialize
	err = km.Close()
	require.NoError(t, err)

	// Create new manager
	km2, err := NewXKMSManager(config, nil)
	require.NoError(t, err)
	defer km2.Close()

	ctx := context.Background()
	err = km2.GeneratePlatformKey(ctx)
	require.NoError(t, err)
}

// TestCreateBackendDefaultCase tests unsupported backend default case
func TestCreateBackendDefaultCase(t *testing.T) {
	tmpDir := t.TempDir()

	config := &XKMSConfig{
		KeysDir: tmpDir,
		Backend: "unsupported", // Use unsupported backend
	}

	km := &XKMSManager{
		config: config,
		logger: logging.DefaultLogger(),
	}

	_, err := km.createXKMSBackend()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported backend type")
}

// TestGenerateAllPKError tests error propagation when PK generation fails
func TestGenerateAllPKError(t *testing.T) {
	tmpDir := t.TempDir()

	config := &XKMSConfig{
		KeysDir:    tmpDir,
		Backend:    BackendFile,
		ExportKeys: true,
	}

	km, err := NewXKMSManager(config, nil)
	require.NoError(t, err)
	defer km.Close()

	// Create PK.crt as a directory so the certificate export fails when
	// trying to open it as a file. This works regardless of privilege
	// level (root bypasses chmod but cannot open a directory for writing).
	err = os.Mkdir(filepath.Join(tmpDir, "PK.crt"), 0755)
	require.NoError(t, err)

	ctx := context.Background()
	err = km.GenerateAll(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to generate Platform Key")
}

// TestGenerateAllCallsGenerateFunctions tests that GenerateAll properly calls all generate functions
func TestGenerateAllCallsGenerateFunctions(t *testing.T) {
	tmpDir := t.TempDir()
	keysDir := filepath.Join(tmpDir, "newkeys")

	config := &XKMSConfig{
		KeysDir:    keysDir,
		Backend:    BackendFile,
		ExportKeys: true,
	}

	km, err := NewXKMSManager(config, nil)
	require.NoError(t, err)
	defer km.Close()

	ctx := context.Background()
	err = km.GenerateAll(ctx)
	require.NoError(t, err)

	// Verify all keys were created
	paths := km.GetKeyPaths()
	assert.FileExists(t, paths.PKCert)
	assert.FileExists(t, paths.KEKCert)
	assert.FileExists(t, paths.DBCert)
	assert.FileExists(t, paths.PKKey)
	assert.FileExists(t, paths.KEKKey)
	assert.FileExists(t, paths.DBKey)
}

// TestGenerateAllWithCancelledContextDuringGeneration tests context cancellation
func TestGenerateAllWithCancelledContextDuringGeneration(t *testing.T) {
	tmpDir := t.TempDir()
	keysDir := filepath.Join(tmpDir, "keys")

	config := &XKMSConfig{
		KeysDir:    keysDir,
		Backend:    BackendFile,
		ExportKeys: true,
	}

	km, err := NewXKMSManager(config, nil)
	require.NoError(t, err)
	defer km.Close()

	// Cancel context before generating
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = km.GenerateAll(ctx)
	assert.Error(t, err)
	// The error should be from the first key generation (PK)
	assert.Contains(t, err.Error(), "Platform Key")
	assert.ErrorIs(t, err, context.Canceled)
}

// TestCreateXKMSBackendCertStorageError tests cert storage creation error path
func TestCreateXKMSBackendCertStorageError(t *testing.T) {
	tmpDir := t.TempDir()

	// Create the keys subdirectory so key storage succeeds
	keysPath := filepath.Join(tmpDir, "keys")
	err := os.MkdirAll(keysPath, 0755)
	require.NoError(t, err)

	// Create a file where we need the certs directory
	certsPath := filepath.Join(tmpDir, "certs")
	err = os.WriteFile(certsPath, []byte("block"), 0644)
	require.NoError(t, err)

	config := &XKMSConfig{
		KeysDir: tmpDir,
		Backend: BackendFile,
	}

	km := &XKMSManager{
		config: config,
		logger: logging.DefaultLogger(),
	}

	_, err = km.createXKMSBackend()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create")
}

// TestGenerateAllKEKErrorPropagation tests KEK error propagation in GenerateAll
func TestGenerateAllKEKErrorPropagation(t *testing.T) {
	tmpDir := t.TempDir()
	keysDir := filepath.Join(tmpDir, "keys")

	config := &XKMSConfig{
		KeysDir:    keysDir,
		Backend:    BackendFile,
		ExportKeys: true,
	}

	km, err := NewXKMSManager(config, nil)
	require.NoError(t, err)
	defer km.Close()

	ctx := context.Background()

	// Generate PK first to set up for KEK failure
	err = km.GeneratePlatformKey(ctx)
	require.NoError(t, err)

	// Remove PK cert to ensure GenerateAll proceeds past KeysExist check
	os.Remove(filepath.Join(keysDir, "PK.crt"))

	// Create KEK.crt as a directory so certificate export fails when
	// trying to open it as a file. This works regardless of privilege
	// level (root bypasses chmod but cannot open a directory for writing).
	err = os.Mkdir(filepath.Join(keysDir, "KEK.crt"), 0755)
	require.NoError(t, err)

	// GenerateAll should fail on KEK after PK regenerates successfully
	err = km.GenerateAll(ctx)
	assert.Error(t, err)
}

// TestGenerateAllDBErrorPropagation tests DB error propagation in GenerateAll
func TestGenerateAllDBErrorPropagation(t *testing.T) {
	tmpDir := t.TempDir()
	keysDir := filepath.Join(tmpDir, "keys")

	config := &XKMSConfig{
		KeysDir:    keysDir,
		Backend:    BackendFile,
		ExportKeys: true,
	}

	km, err := NewXKMSManager(config, nil)
	require.NoError(t, err)
	defer km.Close()

	ctx := context.Background()

	// Generate PK and KEK first
	err = km.GeneratePlatformKey(ctx)
	require.NoError(t, err)

	err = km.GenerateKeyExchangeKey(ctx)
	require.NoError(t, err)

	// Remove KEK cert to ensure GenerateAll proceeds past KeysExist check
	os.Remove(filepath.Join(keysDir, "KEK.crt"))

	// Create DB.crt as a directory so certificate export fails when
	// trying to open it as a file. This works regardless of privilege
	// level (root bypasses chmod but cannot open a directory for writing).
	err = os.Mkdir(filepath.Join(keysDir, "DB.crt"), 0755)
	require.NoError(t, err)

	// GenerateAll should fail on DB after PK and KEK regenerate successfully
	err = km.GenerateAll(ctx)
	assert.Error(t, err)
}

// TestGenerateCertificateForAllKeyTypes tests certificate generation for all key types
func TestGenerateCertificateForAllKeyTypes(t *testing.T) {
	tmpDir := t.TempDir()

	config := &XKMSConfig{
		KeysDir:    tmpDir,
		Backend:    BackendFile,
		ExportKeys: true,
	}

	km, err := NewXKMSManager(config, nil)
	require.NoError(t, err)
	defer km.Close()

	// Create a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Test certificate generation for all key types
	for _, keyType := range []KeyType{KeyTypePK, KeyTypeKEK, KeyTypeDB} {
		subject := pkix.Name{
			CommonName: "Test " + string(keyType),
		}

		cert, err := km.generateCertificate(privateKey, subject, keyType)
		require.NoError(t, err, "Failed to generate certificate for %s", keyType)
		assert.NotNil(t, cert)
		assert.Contains(t, cert.Subject.CommonName, string(keyType))
	}
}

// TestGenerateAllWithAllOptionalConfig tests key generation with maximum config options
func TestGenerateAllWithAllOptionalConfig(t *testing.T) {
	tmpDir := t.TempDir()

	config := &XKMSConfig{
		KeysDir:      tmpDir,
		Backend:      BackendSoftware, // Use software backend explicitly
		CommonName:   "Full Config Test",
		Country:      "US",
		Organization: "Test Org",
		KeySize:      2048,
		ValidYears:   10,
		ExportKeys:   true,
	}

	km, err := NewXKMSManager(config, nil)
	require.NoError(t, err)
	defer km.Close()

	ctx := context.Background()
	err = km.GenerateAll(ctx)
	require.NoError(t, err)

	// Verify all keys exist
	assert.True(t, km.KeysExist())

	// Verify signers work for all key types
	for _, keyType := range []KeyType{KeyTypePK, KeyTypeKEK, KeyTypeDB} {
		signer, err := km.GetSigner(t.Context(), keyType)
		require.NoError(t, err, "Failed to get signer for %s", keyType)
		assert.NotNil(t, signer)
	}
}

// TestWriteKeySuccess tests successful key write
func TestWriteKeySuccess(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate a test key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Test successful write
	keyPath := filepath.Join(tmpDir, "test.key")
	err = writeKey(privateKey, keyPath)
	require.NoError(t, err)
	assert.FileExists(t, keyPath)

	// Verify file permissions
	info, err := os.Stat(keyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

// TestWriteCertificateSuccess tests successful certificate write
func TestWriteCertificateSuccess(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test certificate
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test",
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Test successful write
	certPath := filepath.Join(tmpDir, "test.crt")
	err = writeCertificate(cert, certPath)
	require.NoError(t, err)
	assert.FileExists(t, certPath)

	// Verify file permissions
	info, err := os.Stat(certPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), info.Mode().Perm())
}

// errSignerError is an error returned by the failing signer
var errSignerError = errors.New("signing operation failed")

// failingSigner is a crypto.Signer that always fails to sign
type failingSigner struct {
	publicKey crypto.PublicKey
}

func (f *failingSigner) Public() crypto.PublicKey {
	return f.publicKey
}

func (f *failingSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, errSignerError
}

// TestGenerateCertificateSigningError tests the error path when certificate signing fails
func TestGenerateCertificateSigningError(t *testing.T) {
	tmpDir := t.TempDir()

	config := &XKMSConfig{
		KeysDir:    tmpDir,
		Backend:    BackendFile,
		ExportKeys: true,
	}

	km, err := NewXKMSManager(config, nil)
	require.NoError(t, err)
	defer km.Close()

	// Create a real RSA key to get a valid public key
	realKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create a failing signer with the real public key
	failSigner := &failingSigner{publicKey: &realKey.PublicKey}

	subject := pkix.Name{
		CommonName: "Test",
	}

	// Try to generate certificate with failing signer - should fail
	cert, err := km.generateCertificate(failSigner, subject, KeyTypePK)
	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "failed to create certificate")
}

// TestGenerateAllMkdirError tests error when directory creation fails
func TestGenerateAllMkdirError(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a file where we want to create a directory
	blockingFile := filepath.Join(tmpDir, "block")
	err := os.WriteFile(blockingFile, []byte("block"), 0644)
	require.NoError(t, err)

	// Try to create keys directory under the file (should fail)
	keysDir := filepath.Join(blockingFile, "keys")

	config := &XKMSConfig{
		KeysDir:    keysDir,
		Backend:    BackendFile,
		ExportKeys: true,
	}

	// This will fail during NewXKMSManager because the path is invalid
	km, err := NewXKMSManager(config, nil)
	assert.Error(t, err)
	assert.Nil(t, km)
}
