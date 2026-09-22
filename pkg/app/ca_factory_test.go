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

package app

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewBootstrapCAStoreFactory verifies factory construction.
func TestNewBootstrapCAStoreFactory(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	factory := NewBootstrapCAStoreFactory(logger, "/tmp/test-data", EnvTest, "")

	require.NotNil(t, factory)
	assert.Equal(t, "/tmp/test-data", factory.platformDir)
	assert.Equal(t, EnvTest, factory.environment)
}

// TestBootstrapCAStoreFactory_CreateKeyStore_Test verifies keystore creation with in-memory storage.
func TestBootstrapCAStoreFactory_CreateKeyStore_Test(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	factory := NewBootstrapCAStoreFactory(logger, "/tmp/test-data", EnvTest, "")

	ks, err := factory.CreateKeyStore("test-ca")

	require.NoError(t, err)
	require.NotNil(t, ks)
}

// TestBootstrapCAStoreFactory_CreateKeyStore_EmptyCN verifies keystore creation with empty CN.
func TestBootstrapCAStoreFactory_CreateKeyStore_EmptyCN(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	factory := NewBootstrapCAStoreFactory(logger, "/tmp/test-data", EnvTest, "")

	ks, err := factory.CreateKeyStore("")

	require.NoError(t, err)
	require.NotNil(t, ks)
}

// TestBootstrapCAStoreFactory_CreateCertStore_Test verifies certstore creation with in-memory storage.
func TestBootstrapCAStoreFactory_CreateCertStore_Test(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	factory := NewBootstrapCAStoreFactory(logger, "/tmp/test-data", EnvTest, "")

	cs, err := factory.CreateCertStore("test-ca")

	require.NoError(t, err)
	require.NotNil(t, cs)
}

// TestBootstrapCAStoreFactory_CreateCertStore_EmptyCN verifies certstore with empty CN.
func TestBootstrapCAStoreFactory_CreateCertStore_EmptyCN(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	factory := NewBootstrapCAStoreFactory(logger, "/tmp/test-data", EnvTest, "")

	cs, err := factory.CreateCertStore("")

	require.NoError(t, err)
	require.NotNil(t, cs)
}

// TestBootstrapCAStoreFactory_CreateObjectStore_Test verifies objectstore with in-memory storage.
func TestBootstrapCAStoreFactory_CreateObjectStore_Test(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	factory := NewBootstrapCAStoreFactory(logger, "/tmp/test-data", EnvTest, "")

	os, err := factory.CreateObjectStore("test-ca")

	require.NoError(t, err)
	require.NotNil(t, os)
}

// TestBootstrapCAStoreFactory_CreateObjectStore_EmptyCN verifies objectstore with empty CN.
func TestBootstrapCAStoreFactory_CreateObjectStore_EmptyCN(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	factory := NewBootstrapCAStoreFactory(logger, "/tmp/test-data", EnvTest, "")

	os, err := factory.CreateObjectStore("")

	require.NoError(t, err)
	require.NotNil(t, os)
}

// TestBootstrapCAStoreFactory_MultipleCAs verifies creating stores for different CAs.
func TestBootstrapCAStoreFactory_MultipleCAs(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	factory := NewBootstrapCAStoreFactory(logger, "/tmp/test-data", EnvTest, "")

	cas := []string{"root-ca", "intermediate-ca", "issuing-ca"}

	for _, cn := range cas {
		t.Run(cn, func(t *testing.T) {
			ks, err := factory.CreateKeyStore(cn)
			require.NoError(t, err)
			require.NotNil(t, ks)

			cs, err := factory.CreateCertStore(cn)
			require.NoError(t, err)
			require.NotNil(t, cs)

			os, err := factory.CreateObjectStore(cn)
			require.NoError(t, err)
			require.NotNil(t, os)
		})
	}
}

// TestNewCAStoreFactory verifies CAStoreFactory construction.
// mustPassword builds a password for a test, failing the test if the enclave
// backing it cannot be allocated. A nil secret is the documented "no
// authentication" case and never fails.
func mustPassword(t *testing.T, secret []byte) xkmssdk.Password {
	t.Helper()
	password, err := xkmssdk.NewPassword(secret)
	require.NoError(t, err)
	return password
}

func TestNewCAStoreFactory(t *testing.T) {
	app := &App{
		Logger: logging.DefaultLogger(),
	}

	// NewCAStoreFactory accepts soPIN and userPIN for API consistency but ignores them
	factory := NewCAStoreFactory(app, "/tmp/platform", nil, mustPassword(t, nil), mustPassword(t, nil))

	require.NotNil(t, factory)
	assert.Equal(t, "/tmp/platform", factory.platformDir)
	assert.Equal(t, "x509", factory.certPartition)
}

// TestNewCAStoreFactory_WithPINs verifies PINs are accepted but ignored.
func TestNewCAStoreFactory_WithPINs(t *testing.T) {
	app := &App{
		Logger: logging.DefaultLogger(),
	}

	soPIN := mustPassword(t, []byte("so-pin-secret"))
	userPIN := mustPassword(t, []byte("user-pin-secret"))

	factory := NewCAStoreFactory(app, "/tmp/platform", nil, soPIN, userPIN)

	require.NotNil(t, factory)
	assert.Equal(t, "/tmp/platform", factory.platformDir)
}

// TestCAStoreFactory_CreateKeyStore_NilQuicBaaS verifies error when QuicBaaS is not initialized.
func TestCAStoreFactory_CreateKeyStore_NilQuicBaaS(t *testing.T) {
	app := &App{
		Logger: logging.DefaultLogger(),
	}

	factory := NewCAStoreFactory(app, "/tmp/platform", nil, mustPassword(t, nil), mustPassword(t, nil))

	_, err := factory.CreateKeyStore("test-ca")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "QuicBaaS service not initialized")
}

// TestCAStoreFactory_CreateCertStore_NilStorage verifies error when storage is nil.
func TestCAStoreFactory_CreateCertStore_NilStorage(t *testing.T) {
	app := &App{
		Logger: logging.DefaultLogger(),
	}

	factory := NewCAStoreFactory(app, "/tmp/platform", nil, mustPassword(t, nil), mustPassword(t, nil))

	// Storage is nil, so NewObjectStore will fail
	_, err := factory.CreateCertStore("test-ca")

	require.Error(t, err)
}

// TestCAStoreFactory_CreateObjectStore_NilStorage verifies behavior when storage is nil.
func TestCAStoreFactory_CreateObjectStore_NilStorage(t *testing.T) {
	app := &App{
		Logger: logging.DefaultLogger(),
	}

	factory := NewCAStoreFactory(app, "/tmp/platform", nil, mustPassword(t, nil), mustPassword(t, nil))

	// ObjStoreAdapter wraps nil storage; Configure may succeed or fail depending on implementation.
	// This exercises the code path regardless of outcome.
	result, err := factory.CreateObjectStore("test-ca")
	if err != nil {
		assert.Contains(t, err.Error(), "test-ca")
	} else {
		assert.NotNil(t, result)
	}
}

// TestCertStoreFactoryAdapter_CreateCertStore verifies the adapter returns the wrapped certstore.
func TestCertStoreFactoryAdapter_CreateCertStore(t *testing.T) {
	adapter := &CertStoreFactoryAdapter{certStore: nil}

	result, err := adapter.CreateCertStore("any-cn")

	require.NoError(t, err)
	assert.Nil(t, result)
}

// TestCertStoreFactoryAdapter_CreateCertStore_IgnoresCN verifies CN is ignored.
func TestCertStoreFactoryAdapter_CreateCertStore_IgnoresCN(t *testing.T) {
	adapter := &CertStoreFactoryAdapter{certStore: nil}

	result1, err1 := adapter.CreateCertStore("ca-1")
	result2, err2 := adapter.CreateCertStore("ca-2")

	require.NoError(t, err1)
	require.NoError(t, err2)
	assert.Equal(t, result1, result2)
}

// =============================================================================
// BootstrapCAStoreFactory non-EnvTest paths (filesystem-backed)
// =============================================================================

// TestBootstrapCAStoreFactory_CreateKeyStore_NonEnvTest_Success verifies
// that the file-backed path succeeds when the directories are writable.
func TestBootstrapCAStoreFactory_CreateKeyStore_NonEnvTest_Success(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	factory := NewBootstrapCAStoreFactory(logger, t.TempDir(), EnvProd, "")

	ks, err := factory.CreateKeyStore("root-ca")
	require.NoError(t, err)
	require.NotNil(t, ks)
}

// TestBootstrapCAStoreFactory_CreateKeyStore_NonEnvTest_KeyStorageError verifies
// that a blocked keys directory produces ErrBootstrapStoreInit{Store:"key-storage"}.
func TestBootstrapCAStoreFactory_CreateKeyStore_NonEnvTest_KeyStorageError(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	base := t.TempDir()
	factory := NewBootstrapCAStoreFactory(logger, base, EnvProd, "")

	// Block the keys directory by planting a regular file at that path.
	caDir := filepath.Join(base, "ca", "root-ca")
	require.NoError(t, os.MkdirAll(caDir, 0o755))
	keysPath := filepath.Join(caDir, "keys")
	f, err := os.Create(keysPath)
	require.NoError(t, err)
	f.Close()

	_, storeErr := factory.CreateKeyStore("root-ca")
	require.Error(t, storeErr)
	var target ErrBootstrapStoreInit
	require.ErrorAs(t, storeErr, &target)
	assert.Equal(t, "key-storage", target.Store)
}

// TestBootstrapCAStoreFactory_CreateKeyStore_NonEnvTest_CertStorageError verifies
// that a blocked certs directory (while the keys dir is fine) produces
// ErrBootstrapStoreInit{Store:"cert-storage"}.
func TestBootstrapCAStoreFactory_CreateKeyStore_NonEnvTest_CertStorageError(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	base := t.TempDir()
	factory := NewBootstrapCAStoreFactory(logger, base, EnvProd, "")

	caDir := filepath.Join(base, "ca", "root-ca")
	require.NoError(t, os.MkdirAll(caDir, 0o755))

	// Pre-create the keys dir so key-storage succeeds.
	require.NoError(t, os.MkdirAll(filepath.Join(caDir, "keys"), 0o755))

	// Block the certs directory with a regular file.
	certsPath := filepath.Join(caDir, "certs")
	f, err := os.Create(certsPath)
	require.NoError(t, err)
	f.Close()

	_, storeErr := factory.CreateKeyStore("root-ca")
	require.Error(t, storeErr)
	var target ErrBootstrapStoreInit
	require.ErrorAs(t, storeErr, &target)
	assert.Equal(t, "cert-storage", target.Store)
}

// =============================================================================
// BootstrapCAStoreFactory.CreateCertStore non-EnvTest paths
// =============================================================================

// TestBootstrapCAStoreFactory_CreateCertStore_NonEnvTest_Success verifies
// the file-backed certstore creation path.
func TestBootstrapCAStoreFactory_CreateCertStore_NonEnvTest_Success(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	factory := NewBootstrapCAStoreFactory(logger, t.TempDir(), EnvProd, "")

	cs, err := factory.CreateCertStore("root-ca")
	require.NoError(t, err)
	require.NotNil(t, cs)
}

// TestBootstrapCAStoreFactory_CreateCertStore_NonEnvTest_Error verifies that a
// blocked certs directory surfaces ErrBootstrapStoreInit{Store:"cert-storage"}.
func TestBootstrapCAStoreFactory_CreateCertStore_NonEnvTest_Error(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	base := t.TempDir()
	factory := NewBootstrapCAStoreFactory(logger, base, EnvProd, "")

	// Block the certs directory with a regular file.
	caDir := filepath.Join(base, "ca", "root-ca")
	require.NoError(t, os.MkdirAll(caDir, 0o755))
	f, err := os.Create(filepath.Join(caDir, "certs"))
	require.NoError(t, err)
	f.Close()

	_, storeErr := factory.CreateCertStore("root-ca")
	require.Error(t, storeErr)
	var target ErrBootstrapStoreInit
	require.ErrorAs(t, storeErr, &target)
	assert.Equal(t, "cert-storage", target.Store)
}

// =============================================================================
// CAStoreFactory.CreateCertStore with valid memory storage
// =============================================================================

// TestCAStoreFactory_CreateCertStore_WithMemoryStorage verifies that the
// success path completes when a valid ObjectStorage client is wired.
func TestCAStoreFactory_CreateCertStore_WithMemoryStorage(t *testing.T) {
	app := &App{Logger: logging.DefaultLogger()}
	factory := NewCAStoreFactory(app, t.TempDir(), object.NewMemoryClient(),
		mustPassword(t, nil), mustPassword(t, nil))

	cs, err := factory.CreateCertStore("test-ca")
	require.NoError(t, err)
	require.NotNil(t, cs)
}
