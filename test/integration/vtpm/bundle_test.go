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

//go:build integration

package vtpm_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/swtpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSWTPM_Lifecycle tests the swtpm lifecycle operations
func TestSWTPM_Lifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	stateDir := t.TempDir()
	socketPath := filepath.Join(stateDir, "swtpm.sock")

	// Create swtpm
	config := &swtpm.Config{
		StateDir:   stateDir,
		SocketPath: socketPath,
		PCRBanks:   []string{"sha256"},
	}

	sw, err := swtpm.NewSWTPM(config, nil)
	require.NoError(t, err, "Failed to create SWTPM instance")

	// Initialize
	err = sw.Initialize(ctx)
	require.NoError(t, err, "Failed to initialize SWTPM")

	// Start
	err = sw.Start(ctx)
	require.NoError(t, err, "Failed to start SWTPM")

	// Wait for socket
	waitForSocket(t, socketPath)

	// Verify socket exists
	_, err = os.Stat(socketPath)
	require.NoError(t, err, "SWTPM socket not created")

	// Check running
	assert.True(t, sw.IsRunning(), "SWTPM should be running")

	// Stop
	err = sw.Stop()
	require.NoError(t, err, "Failed to stop SWTPM")

	// Verify stopped
	assert.False(t, sw.IsRunning(), "SWTPM should not be running after stop")
}

// TestSWTPM_MultipleInstances tests running multiple swtpm instances
func TestSWTPM_MultipleInstances(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	instances := make([]*swtpm.SWTPM, 3)

	// Create and start multiple instances
	for i := 0; i < 3; i++ {
		stateDir := t.TempDir()
		socketPath := filepath.Join(stateDir, "swtpm.sock")

		config := &swtpm.Config{
			StateDir:   stateDir,
			SocketPath: socketPath,
			PCRBanks:   []string{"sha256"},
		}

		sw, err := swtpm.NewSWTPM(config, nil)
		require.NoError(t, err, "Failed to create SWTPM instance %d", i)

		err = sw.Initialize(ctx)
		require.NoError(t, err, "Failed to initialize SWTPM instance %d", i)

		err = sw.Start(ctx)
		require.NoError(t, err, "Failed to start SWTPM instance %d", i)

		instances[i] = sw
	}

	// Verify all are running
	for i, sw := range instances {
		assert.True(t, sw.IsRunning(), "SWTPM instance %d should be running", i)
	}

	// Stop all
	for i, sw := range instances {
		err := sw.Stop()
		require.NoError(t, err, "Failed to stop SWTPM instance %d", i)
	}
}

// TestEKCertInjection_FullWorkflow tests the complete EK certificate injection workflow
func TestEKCertInjection_FullWorkflow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	stateDir := t.TempDir()
	socketPath := filepath.Join(stateDir, "swtpm.sock")

	// Start swtpm
	sw := setupSWTPM(t, ctx, stateDir, socketPath)
	defer cleanupSWTPM(t, sw)

	// Generate test EK certificate
	cert := generateTestCert(t, "EK Certificate Test")

	// Create injector
	injector := vtpm.NewEKCertInjector(socketPath, nil)

	// Test RSA injection
	t.Run("RSA", func(t *testing.T) {
		err := injector.InjectCertificate(ctx, cert, vtpm.EKAlgorithmRSA)
		require.NoError(t, err, "Failed to inject RSA EK certificate")

		// Read back and verify
		readCert, err := injector.ReadCertificate(ctx, vtpm.EKAlgorithmRSA)
		require.NoError(t, err, "Failed to read RSA EK certificate")
		assert.True(t, cert.Equal(readCert), "Certificates should match")
	})

	// Test ECC injection
	t.Run("ECC", func(t *testing.T) {
		eccCert := generateTestCert(t, "ECC EK Certificate Test")
		err := injector.InjectCertificate(ctx, eccCert, vtpm.EKAlgorithmECC)
		require.NoError(t, err, "Failed to inject ECC EK certificate")

		readCert, err := injector.ReadCertificate(ctx, vtpm.EKAlgorithmECC)
		require.NoError(t, err, "Failed to read ECC EK certificate")
		assert.True(t, eccCert.Equal(readCert), "Certificates should match")
	})
}

// TestEKCertInjection_ChunkedWrite tests injection of certificates larger than NV buffer
func TestEKCertInjection_ChunkedWrite(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	stateDir := t.TempDir()
	socketPath := filepath.Join(stateDir, "swtpm.sock")

	sw := setupSWTPM(t, ctx, stateDir, socketPath)
	defer cleanupSWTPM(t, sw)

	// Generate a certificate with extensions to make it larger
	cert := generateTestCertWithExtensions(t, "Large Certificate Test")
	certSize := len(cert.Raw)
	t.Logf("Certificate size: %d bytes", certSize)

	injector := vtpm.NewEKCertInjector(socketPath, nil)

	// Set a small buffer size to force chunked writes
	injector.SetNVBufferMax(256)

	err := injector.InjectCertificate(ctx, cert, vtpm.EKAlgorithmRSA)
	require.NoError(t, err, "Failed to inject large certificate with chunked writes")

	readCert, err := injector.ReadCertificate(ctx, vtpm.EKAlgorithmRSA)
	require.NoError(t, err, "Failed to read large certificate")

	assert.True(t, cert.Equal(readCert), "Certificates should match after chunked write/read")
}

// TestEKCertInjection_Overwrite tests overwriting an existing certificate
func TestEKCertInjection_Overwrite(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	stateDir := t.TempDir()
	socketPath := filepath.Join(stateDir, "swtpm.sock")

	sw := setupSWTPM(t, ctx, stateDir, socketPath)
	defer cleanupSWTPM(t, sw)

	cert1 := generateTestCert(t, "First Certificate")
	cert2 := generateTestCert(t, "Second Certificate")

	injector := vtpm.NewEKCertInjector(socketPath, nil)

	// Inject first
	err := injector.InjectCertificate(ctx, cert1, vtpm.EKAlgorithmRSA)
	require.NoError(t, err)

	// Verify first
	readCert, err := injector.ReadCertificate(ctx, vtpm.EKAlgorithmRSA)
	require.NoError(t, err)
	assert.True(t, cert1.Equal(readCert))

	// Overwrite with second
	err = injector.InjectCertificate(ctx, cert2, vtpm.EKAlgorithmRSA)
	require.NoError(t, err, "Should be able to overwrite existing certificate")

	// Verify second
	readCert, err = injector.ReadCertificate(ctx, vtpm.EKAlgorithmRSA)
	require.NoError(t, err)
	assert.True(t, cert2.Equal(readCert), "Should read the second certificate")
}

// TestEKCertInjection_ErrorCases tests error handling
func TestEKCertInjection_ErrorCases(t *testing.T) {
	t.Run("NilCertificate", func(t *testing.T) {
		injector := vtpm.NewEKCertInjector("/tmp/nonexistent.sock", nil)
		err := injector.InjectCertificate(context.Background(), nil, vtpm.EKAlgorithmRSA)
		assert.Error(t, err, "Should fail with nil certificate")
	})

	t.Run("InvalidSocket", func(t *testing.T) {
		cert := generateTestCert(t, "Test")
		injector := vtpm.NewEKCertInjector("/tmp/nonexistent.sock", nil)
		err := injector.InjectCertificate(context.Background(), cert, vtpm.EKAlgorithmRSA)
		assert.Error(t, err, "Should fail with invalid socket")
	})
}

// TestSWTPM_RestartWithState tests that TPM state persists across restarts
func TestSWTPM_RestartWithState(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	stateDir := t.TempDir()
	socketPath := filepath.Join(stateDir, "swtpm.sock")

	// First session: inject certificate
	config := &swtpm.Config{
		StateDir:   stateDir,
		SocketPath: socketPath,
		PCRBanks:   []string{"sha256"},
	}

	sw, err := swtpm.NewSWTPM(config, nil)
	require.NoError(t, err)

	err = sw.Initialize(ctx)
	require.NoError(t, err)

	err = sw.Start(ctx)
	require.NoError(t, err)

	// Wait for socket
	waitForSocket(t, socketPath)

	cert := generateTestCert(t, "Persistent Certificate")
	injector := vtpm.NewEKCertInjector(socketPath, nil)

	err = injector.InjectCertificate(ctx, cert, vtpm.EKAlgorithmRSA)
	require.NoError(t, err)

	err = sw.Stop()
	require.NoError(t, err)

	// Second session: verify certificate persisted
	sw2, err := swtpm.NewSWTPM(config, nil)
	require.NoError(t, err)

	// Don't re-initialize - use existing state
	err = sw2.Start(ctx)
	require.NoError(t, err)
	defer sw2.Stop()

	// Wait for socket
	waitForSocket(t, socketPath)

	injector2 := vtpm.NewEKCertInjector(socketPath, nil)
	readCert, err := injector2.ReadCertificate(ctx, vtpm.EKAlgorithmRSA)
	require.NoError(t, err, "Should be able to read certificate after restart")

	assert.True(t, cert.Equal(readCert), "Certificate should persist across restarts")
}

// Helper function already defined in nvram_test.go, but we need them here too
// since this is a separate test file

func setupSWTPMBundle(t *testing.T, ctx context.Context, stateDir, socketPath string) *swtpm.SWTPM {
	t.Helper()

	config := &swtpm.Config{
		StateDir:   stateDir,
		SocketPath: socketPath,
		PCRBanks:   []string{"sha256"},
	}

	sw, err := swtpm.NewSWTPM(config, nil)
	require.NoError(t, err, "Failed to create SWTPM instance")

	err = sw.Initialize(ctx)
	require.NoError(t, err, "Failed to initialize SWTPM")

	err = sw.Start(ctx)
	require.NoError(t, err, "Failed to start SWTPM")

	// Wait for socket to be ready
	waitForSocket(t, socketPath)

	_, err = os.Stat(socketPath)
	require.NoError(t, err, "SWTPM socket not created")

	return sw
}

func generateTestCertBundle(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Integration Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}
