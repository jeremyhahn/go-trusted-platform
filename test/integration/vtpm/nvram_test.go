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

// TestEKCertInjection_RSA tests EK certificate injection for RSA algorithm
func TestEKCertInjection_RSA(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Create temp directory for swtpm state
	stateDir := t.TempDir()
	socketPath := filepath.Join(stateDir, "swtpm.sock")

	// Initialize and start swtpm
	sw := setupSWTPM(t, ctx, stateDir, socketPath)
	defer cleanupSWTPM(t, sw)

	// Generate test EK certificate
	cert := generateTestCert(t, "RSA EK Test")

	// Create injector
	injector := vtpm.NewEKCertInjector(socketPath, nil)

	// Inject certificate
	err := injector.InjectCertificate(ctx, cert, vtpm.EKAlgorithmRSA)
	require.NoError(t, err, "Failed to inject RSA EK certificate")

	// Read back and verify
	readCert, err := injector.ReadCertificate(ctx, vtpm.EKAlgorithmRSA)
	require.NoError(t, err, "Failed to read RSA EK certificate")

	assert.True(t, cert.Equal(readCert), "Read certificate should match injected certificate")
}

// TestEKCertInjection_ECC tests EK certificate injection for ECC algorithm
func TestEKCertInjection_ECC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	stateDir := t.TempDir()
	socketPath := filepath.Join(stateDir, "swtpm.sock")

	sw := setupSWTPM(t, ctx, stateDir, socketPath)
	defer cleanupSWTPM(t, sw)

	cert := generateTestCert(t, "ECC EK Test")
	injector := vtpm.NewEKCertInjector(socketPath, nil)

	err := injector.InjectCertificate(ctx, cert, vtpm.EKAlgorithmECC)
	require.NoError(t, err, "Failed to inject ECC EK certificate")

	readCert, err := injector.ReadCertificate(ctx, vtpm.EKAlgorithmECC)
	require.NoError(t, err, "Failed to read ECC EK certificate")

	assert.True(t, cert.Equal(readCert), "Read certificate should match injected certificate")
}

// TestEKCertInjection_VerifyCertificate tests the verification function
func TestEKCertInjection_VerifyCertificate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	stateDir := t.TempDir()
	socketPath := filepath.Join(stateDir, "swtpm.sock")

	sw := setupSWTPM(t, ctx, stateDir, socketPath)
	defer cleanupSWTPM(t, sw)

	cert := generateTestCert(t, "Verify Test")
	injector := vtpm.NewEKCertInjector(socketPath, nil)

	err := injector.InjectCertificate(ctx, cert, vtpm.EKAlgorithmRSA)
	require.NoError(t, err)

	// Verify should succeed with matching certificate
	err = injector.VerifyCertificate(ctx, cert, vtpm.EKAlgorithmRSA)
	require.NoError(t, err, "Verification should succeed for matching certificate")
}

// TestEKCertInjection_VerifyCertificate_Mismatch tests verification with wrong certificate
func TestEKCertInjection_VerifyCertificate_Mismatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	stateDir := t.TempDir()
	socketPath := filepath.Join(stateDir, "swtpm.sock")

	sw := setupSWTPM(t, ctx, stateDir, socketPath)
	defer cleanupSWTPM(t, sw)

	cert1 := generateTestCert(t, "Original Cert")
	cert2 := generateTestCert(t, "Different Cert")

	injector := vtpm.NewEKCertInjector(socketPath, nil)

	err := injector.InjectCertificate(ctx, cert1, vtpm.EKAlgorithmRSA)
	require.NoError(t, err)

	// Verify should fail with different certificate
	err = injector.VerifyCertificate(ctx, cert2, vtpm.EKAlgorithmRSA)
	assert.Error(t, err, "Verification should fail for mismatched certificate")
}

// TestEKCertInjection_Reinjection tests overwriting an existing certificate
func TestEKCertInjection_Reinjection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	stateDir := t.TempDir()
	socketPath := filepath.Join(stateDir, "swtpm.sock")

	sw := setupSWTPM(t, ctx, stateDir, socketPath)
	defer cleanupSWTPM(t, sw)

	cert1 := generateTestCert(t, "First Cert")
	cert2 := generateTestCert(t, "Second Cert")

	injector := vtpm.NewEKCertInjector(socketPath, nil)

	// Inject first certificate
	err := injector.InjectCertificate(ctx, cert1, vtpm.EKAlgorithmRSA)
	require.NoError(t, err)

	// Inject second certificate (should overwrite)
	err = injector.InjectCertificate(ctx, cert2, vtpm.EKAlgorithmRSA)
	require.NoError(t, err, "Should be able to overwrite existing certificate")

	// Verify second certificate is now stored
	readCert, err := injector.ReadCertificate(ctx, vtpm.EKAlgorithmRSA)
	require.NoError(t, err)

	assert.True(t, cert2.Equal(readCert), "Read certificate should match second injected certificate")
}

// TestEKCertInjection_LargeCertificate tests injection of a larger certificate
func TestEKCertInjection_LargeCertificate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	stateDir := t.TempDir()
	socketPath := filepath.Join(stateDir, "swtpm.sock")

	sw := setupSWTPM(t, ctx, stateDir, socketPath)
	defer cleanupSWTPM(t, sw)

	// Generate a certificate with extensions to make it larger
	cert := generateTestCertWithExtensions(t, "Large Cert Test")
	injector := vtpm.NewEKCertInjector(socketPath, nil)

	// Set a smaller buffer to test chunking
	injector.SetNVBufferMax(256)

	err := injector.InjectCertificate(ctx, cert, vtpm.EKAlgorithmRSA)
	require.NoError(t, err, "Failed to inject large certificate")

	readCert, err := injector.ReadCertificate(ctx, vtpm.EKAlgorithmRSA)
	require.NoError(t, err, "Failed to read large certificate")

	assert.True(t, cert.Equal(readCert), "Read certificate should match injected certificate")
}

// TestEKCertInjection_NilCertificate tests error handling for nil certificate
func TestEKCertInjection_NilCertificate(t *testing.T) {
	injector := vtpm.NewEKCertInjector("/tmp/nonexistent.sock", nil)

	ctx := context.Background()
	err := injector.InjectCertificate(ctx, nil, vtpm.EKAlgorithmRSA)
	assert.Error(t, err, "Should fail with nil certificate")
}

// TestEKCertInjection_InvalidSocket tests error handling for invalid socket
func TestEKCertInjection_InvalidSocket(t *testing.T) {
	cert := generateTestCert(t, "Invalid Socket Test")
	injector := vtpm.NewEKCertInjector("/tmp/nonexistent.sock", nil)

	ctx := context.Background()
	err := injector.InjectCertificate(ctx, cert, vtpm.EKAlgorithmRSA)
	assert.Error(t, err, "Should fail with invalid socket")
}

// TestEKCertInjection_BothAlgorithms tests injecting certificates for both RSA and ECC
func TestEKCertInjection_BothAlgorithms(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	stateDir := t.TempDir()
	socketPath := filepath.Join(stateDir, "swtpm.sock")

	sw := setupSWTPM(t, ctx, stateDir, socketPath)
	defer cleanupSWTPM(t, sw)

	rsaCert := generateTestCert(t, "RSA EK Cert")
	eccCert := generateTestCert(t, "ECC EK Cert")

	injector := vtpm.NewEKCertInjector(socketPath, nil)

	// Inject both certificates
	err := injector.InjectCertificate(ctx, rsaCert, vtpm.EKAlgorithmRSA)
	require.NoError(t, err)

	err = injector.InjectCertificate(ctx, eccCert, vtpm.EKAlgorithmECC)
	require.NoError(t, err)

	// Read back both and verify they're independent
	readRSA, err := injector.ReadCertificate(ctx, vtpm.EKAlgorithmRSA)
	require.NoError(t, err)

	readECC, err := injector.ReadCertificate(ctx, vtpm.EKAlgorithmECC)
	require.NoError(t, err)

	assert.True(t, rsaCert.Equal(readRSA), "RSA certificate should match")
	assert.True(t, eccCert.Equal(readECC), "ECC certificate should match")
	assert.False(t, readRSA.Equal(readECC), "RSA and ECC certificates should be different")
}

// Helper functions

func setupSWTPM(t *testing.T, ctx context.Context, stateDir, socketPath string) *swtpm.SWTPM {
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

	// Verify socket exists
	_, err = os.Stat(socketPath)
	require.NoError(t, err, "SWTPM socket not created")

	return sw
}

func cleanupSWTPM(t *testing.T, sw *swtpm.SWTPM) {
	t.Helper()
	if sw != nil {
		sw.Stop()
	}
}

func generateTestCert(t *testing.T, cn string) *x509.Certificate {
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

func generateTestCertWithExtensions(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:         cn,
			Organization:       []string{"Integration Test Org"},
			OrganizationalUnit: []string{"Integration Test Unit"},
			Country:            []string{"US"},
			Province:           []string{"California"},
			Locality:           []string{"San Francisco"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"test.example.com", "localhost"},
		EmailAddresses:        []string{"test@example.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}
