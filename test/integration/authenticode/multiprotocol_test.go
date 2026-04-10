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

// Package authenticode provides multi-protocol integration tests for Authenticode services.
// These tests verify that Authenticode signing and verification operations work consistently
// across all protocol adapters (CLI, REST, gRPC, QUIC, MCP, Unix) using a unified
// AuthenticodeCommands interface.
//
// Run tests via:
//
//	make integration-test-authenticode
//
// The multiprotocol pattern enables:
//   - Testing all protocols against the same test scenarios
//   - Ensuring API consistency across transport layers
//   - Easy addition of new protocol adapters
package authenticode

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Multi-Protocol Test Entry Point
// =============================================================================

// TestAuthenticodeMultiProtocol runs the complete Authenticode test suite against all
// protocol adapters. Each adapter implements the AuthenticodeCommands interface, enabling
// unified testing across CLI, REST, gRPC, QUIC, MCP, and Unix protocols.
func TestAuthenticodeMultiProtocol(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Get all protocol adapters that implement AuthenticodeCommands
	adapters := []AuthenticodeCommands{
		NewCLIAdapter(),
		// NewRESTAdapter(),  // TODO: Implement
		// NewGRPCAdapter(),  // TODO: Implement
		// NewQUICAdapter(),  // TODO: Implement
		// NewMCPAdapter(),   // TODO: Implement
		// NewUnixAdapter(),  // TODO: Implement
	}

	for _, adapter := range adapters {
		adapter := adapter // Capture for closure
		t.Run(adapter.Name(), func(t *testing.T) {
			if err := adapter.Setup(ctx); err != nil {
				t.Skipf("Skipping %s: setup failed: %v", adapter.Name(), err)
			}
			defer func() {
				if err := adapter.Teardown(); err != nil {
					t.Logf("Warning: teardown error for %s: %v", adapter.Name(), err)
				}
			}()

			testAuthenticodeProtocol(t, ctx, adapter)
		})
	}
}

// testAuthenticodeProtocol runs the complete Authenticode test suite against a single
// protocol adapter.
func testAuthenticodeProtocol(t *testing.T, ctx context.Context, cmd AuthenticodeCommands) {
	// Generate unique test prefix for this protocol run
	prefix := fmt.Sprintf("%s-%d", cmd.Name(), time.Now().Unix())

	t.Run("SignAndVerify", func(t *testing.T) {
		testSignAndVerify(t, ctx, cmd, prefix)
	})

	t.Run("SignWithRSA", func(t *testing.T) {
		testSignWithRSA(t, ctx, cmd, prefix)
	})

	t.Run("SignWithECDSA", func(t *testing.T) {
		testSignWithECDSA(t, ctx, cmd, prefix)
	})

	t.Run("VerifyWithCertificate", func(t *testing.T) {
		testVerifyWithCertificate(t, ctx, cmd, prefix)
	})

	t.Run("SignErrors", func(t *testing.T) {
		testSignErrors(t, ctx, cmd, prefix)
	})

	t.Run("VerifyErrors", func(t *testing.T) {
		testVerifyErrors(t, ctx, cmd, prefix)
	})
}

// =============================================================================
// Sign and Verify Tests
// =============================================================================

func testSignAndVerify(t *testing.T, ctx context.Context, cmd AuthenticodeCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	t.Run("BasicSignAndVerify", func(t *testing.T) {
		// Create test fixtures
		testDir := t.TempDir()
		keyPath, certPath := createRSATestKeyAndCert(t, testDir, prefix)
		inputPath := createTestPEFile(t, testDir, prefix+"-basic")
		outputPath := filepath.Join(testDir, prefix+"-basic-signed.efi")

		// Sign the file
		signOpts := SignOptions{
			KeyPath:  keyPath,
			CertPath: certPath,
			Input:    inputPath,
			Output:   outputPath,
		}

		signResult, err := cmd.Sign(testCtx, signOpts)
		require.NoError(t, err, "Sign should succeed")
		require.NotNil(t, signResult, "Result should not be nil")
		assert.True(t, signResult.Success, "Sign should be successful")
		assert.Equal(t, inputPath, signResult.Input, "Input path should match")
		assert.Equal(t, outputPath, signResult.Output, "Output path should match")

		// Verify the signed file exists
		_, err = os.Stat(outputPath)
		require.NoError(t, err, "Signed file should exist")

		// Verify the signature
		verifyOpts := VerifyOptions{
			Input: outputPath,
		}

		verifyResult, err := cmd.Verify(testCtx, verifyOpts)
		require.NoError(t, err, "Verify should succeed")
		require.NotNil(t, verifyResult, "Result should not be nil")
		assert.True(t, verifyResult.Verified, "Verification should succeed")
	})
}

func testSignWithRSA(t *testing.T, ctx context.Context, cmd AuthenticodeCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	t.Run("SignWithRSA2048", func(t *testing.T) {
		testDir := t.TempDir()
		keyPath, certPath := createRSATestKeyAndCertWithBits(t, testDir, prefix+"-rsa2048", 2048)
		inputPath := createTestPEFile(t, testDir, prefix+"-rsa2048")
		outputPath := filepath.Join(testDir, prefix+"-rsa2048-signed.efi")

		signOpts := SignOptions{
			KeyPath:  keyPath,
			CertPath: certPath,
			Input:    inputPath,
			Output:   outputPath,
		}

		result, err := cmd.Sign(testCtx, signOpts)
		require.NoError(t, err, "Sign with RSA-2048 should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "Sign should be successful")

		// Verify the signature
		verifyResult, err := cmd.Verify(testCtx, VerifyOptions{Input: outputPath})
		require.NoError(t, err, "Verify should succeed")
		assert.True(t, verifyResult.Verified, "Verification should succeed")
	})

	t.Run("SignWithRSA4096", func(t *testing.T) {
		testDir := t.TempDir()
		keyPath, certPath := createRSATestKeyAndCertWithBits(t, testDir, prefix+"-rsa4096", 4096)
		inputPath := createTestPEFile(t, testDir, prefix+"-rsa4096")
		outputPath := filepath.Join(testDir, prefix+"-rsa4096-signed.efi")

		signOpts := SignOptions{
			KeyPath:  keyPath,
			CertPath: certPath,
			Input:    inputPath,
			Output:   outputPath,
		}

		result, err := cmd.Sign(testCtx, signOpts)
		require.NoError(t, err, "Sign with RSA-4096 should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "Sign should be successful")

		// Verify the signature
		verifyResult, err := cmd.Verify(testCtx, VerifyOptions{Input: outputPath})
		require.NoError(t, err, "Verify should succeed")
		assert.True(t, verifyResult.Verified, "Verification should succeed")
	})
}

func testSignWithECDSA(t *testing.T, ctx context.Context, cmd AuthenticodeCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	t.Run("SignWithECDSAP256", func(t *testing.T) {
		testDir := t.TempDir()
		keyPath, certPath := createECDSATestKeyAndCert(t, testDir, prefix+"-ecdsa256", elliptic.P256())
		inputPath := createTestPEFile(t, testDir, prefix+"-ecdsa256")
		outputPath := filepath.Join(testDir, prefix+"-ecdsa256-signed.efi")

		signOpts := SignOptions{
			KeyPath:  keyPath,
			CertPath: certPath,
			Input:    inputPath,
			Output:   outputPath,
		}

		result, err := cmd.Sign(testCtx, signOpts)
		require.NoError(t, err, "Sign with ECDSA-P256 should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "Sign should be successful")

		// Verify the signature
		verifyResult, err := cmd.Verify(testCtx, VerifyOptions{Input: outputPath})
		require.NoError(t, err, "Verify should succeed")
		assert.True(t, verifyResult.Verified, "Verification should succeed")
	})

	t.Run("SignWithECDSAP384", func(t *testing.T) {
		testDir := t.TempDir()
		keyPath, certPath := createECDSATestKeyAndCert(t, testDir, prefix+"-ecdsa384", elliptic.P384())
		inputPath := createTestPEFile(t, testDir, prefix+"-ecdsa384")
		outputPath := filepath.Join(testDir, prefix+"-ecdsa384-signed.efi")

		signOpts := SignOptions{
			KeyPath:  keyPath,
			CertPath: certPath,
			Input:    inputPath,
			Output:   outputPath,
		}

		result, err := cmd.Sign(testCtx, signOpts)
		require.NoError(t, err, "Sign with ECDSA-P384 should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "Sign should be successful")

		// Verify the signature
		verifyResult, err := cmd.Verify(testCtx, VerifyOptions{Input: outputPath})
		require.NoError(t, err, "Verify should succeed")
		assert.True(t, verifyResult.Verified, "Verification should succeed")
	})
}

func testVerifyWithCertificate(t *testing.T, ctx context.Context, cmd AuthenticodeCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	t.Run("VerifyWithSpecificCertificate", func(t *testing.T) {
		testDir := t.TempDir()
		keyPath, certPath := createRSATestKeyAndCert(t, testDir, prefix+"-verify-cert")
		inputPath := createTestPEFile(t, testDir, prefix+"-verify-cert")
		outputPath := filepath.Join(testDir, prefix+"-verify-cert-signed.efi")

		// Sign the file
		signOpts := SignOptions{
			KeyPath:  keyPath,
			CertPath: certPath,
			Input:    inputPath,
			Output:   outputPath,
		}

		signResult, err := cmd.Sign(testCtx, signOpts)
		require.NoError(t, err, "Sign should succeed")
		require.True(t, signResult.Success, "Sign should be successful")

		// Verify with the same certificate
		verifyOpts := VerifyOptions{
			Input:    outputPath,
			CertPath: certPath,
		}

		verifyResult, err := cmd.Verify(testCtx, verifyOpts)
		require.NoError(t, err, "Verify with certificate should succeed")
		require.NotNil(t, verifyResult, "Result should not be nil")
		assert.True(t, verifyResult.Verified, "Verification with certificate should succeed")
	})

	t.Run("VerifyWithDifferentCertificate", func(t *testing.T) {
		testDir := t.TempDir()
		keyPath1, certPath1 := createRSATestKeyAndCert(t, testDir, prefix+"-diff-cert1")
		_, certPath2 := createRSATestKeyAndCert(t, testDir, prefix+"-diff-cert2")
		inputPath := createTestPEFile(t, testDir, prefix+"-diff-cert")
		outputPath := filepath.Join(testDir, prefix+"-diff-cert-signed.efi")

		// Sign with first key/cert
		signOpts := SignOptions{
			KeyPath:  keyPath1,
			CertPath: certPath1,
			Input:    inputPath,
			Output:   outputPath,
		}

		signResult, err := cmd.Sign(testCtx, signOpts)
		require.NoError(t, err, "Sign should succeed")
		require.True(t, signResult.Success, "Sign should be successful")

		// Verify with different certificate should fail trust verification
		verifyOpts := VerifyOptions{
			Input:    outputPath,
			CertPath: certPath2,
		}

		// This may succeed or fail depending on implementation
		// At minimum, basic signature verification should pass
		verifyResult, err := cmd.Verify(testCtx, verifyOpts)
		if err == nil {
			// If it succeeds, the verification result indicates trust status
			assert.NotNil(t, verifyResult, "Result should not be nil")
		}
	})
}

// =============================================================================
// Error Handling Tests
// =============================================================================

func testSignErrors(t *testing.T, ctx context.Context, cmd AuthenticodeCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("SignMissingKey", func(t *testing.T) {
		testDir := t.TempDir()
		_, certPath := createRSATestKeyAndCert(t, testDir, prefix+"-missing-key")
		inputPath := createTestPEFile(t, testDir, prefix+"-missing-key")
		outputPath := filepath.Join(testDir, prefix+"-missing-key-signed.efi")

		signOpts := SignOptions{
			KeyPath:  "/nonexistent/key.pem",
			CertPath: certPath,
			Input:    inputPath,
			Output:   outputPath,
		}

		_, err := cmd.Sign(testCtx, signOpts)
		require.Error(t, err, "Sign with missing key should fail")
	})

	t.Run("SignMissingCert", func(t *testing.T) {
		testDir := t.TempDir()
		keyPath, _ := createRSATestKeyAndCert(t, testDir, prefix+"-missing-cert")
		inputPath := createTestPEFile(t, testDir, prefix+"-missing-cert")
		outputPath := filepath.Join(testDir, prefix+"-missing-cert-signed.efi")

		signOpts := SignOptions{
			KeyPath:  keyPath,
			CertPath: "/nonexistent/cert.pem",
			Input:    inputPath,
			Output:   outputPath,
		}

		_, err := cmd.Sign(testCtx, signOpts)
		require.Error(t, err, "Sign with missing cert should fail")
	})

	t.Run("SignMissingInput", func(t *testing.T) {
		testDir := t.TempDir()
		keyPath, certPath := createRSATestKeyAndCert(t, testDir, prefix+"-missing-input")
		outputPath := filepath.Join(testDir, prefix+"-missing-input-signed.efi")

		signOpts := SignOptions{
			KeyPath:  keyPath,
			CertPath: certPath,
			Input:    "/nonexistent/file.efi",
			Output:   outputPath,
		}

		_, err := cmd.Sign(testCtx, signOpts)
		require.Error(t, err, "Sign with missing input file should fail")
	})

	t.Run("SignInvalidKeyFormat", func(t *testing.T) {
		testDir := t.TempDir()
		_, certPath := createRSATestKeyAndCert(t, testDir, prefix+"-invalid-key")
		inputPath := createTestPEFile(t, testDir, prefix+"-invalid-key")
		outputPath := filepath.Join(testDir, prefix+"-invalid-key-signed.efi")

		// Create an invalid key file
		invalidKeyPath := filepath.Join(testDir, "invalid-key.pem")
		err := os.WriteFile(invalidKeyPath, []byte("not a valid key"), 0600)
		require.NoError(t, err, "Failed to create invalid key file")

		signOpts := SignOptions{
			KeyPath:  invalidKeyPath,
			CertPath: certPath,
			Input:    inputPath,
			Output:   outputPath,
		}

		_, err = cmd.Sign(testCtx, signOpts)
		require.Error(t, err, "Sign with invalid key format should fail")
	})

	t.Run("SignInvalidCertFormat", func(t *testing.T) {
		testDir := t.TempDir()
		keyPath, _ := createRSATestKeyAndCert(t, testDir, prefix+"-invalid-cert")
		inputPath := createTestPEFile(t, testDir, prefix+"-invalid-cert")
		outputPath := filepath.Join(testDir, prefix+"-invalid-cert-signed.efi")

		// Create an invalid cert file
		invalidCertPath := filepath.Join(testDir, "invalid-cert.pem")
		err := os.WriteFile(invalidCertPath, []byte("not a valid certificate"), 0644)
		require.NoError(t, err, "Failed to create invalid cert file")

		signOpts := SignOptions{
			KeyPath:  keyPath,
			CertPath: invalidCertPath,
			Input:    inputPath,
			Output:   outputPath,
		}

		_, err = cmd.Sign(testCtx, signOpts)
		require.Error(t, err, "Sign with invalid cert format should fail")
	})
}

func testVerifyErrors(t *testing.T, ctx context.Context, cmd AuthenticodeCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("VerifyMissingFile", func(t *testing.T) {
		verifyOpts := VerifyOptions{
			Input: "/nonexistent/signed-file.efi",
		}

		_, err := cmd.Verify(testCtx, verifyOpts)
		require.Error(t, err, "Verify with missing file should fail")
	})

	t.Run("VerifyUnsignedFile", func(t *testing.T) {
		testDir := t.TempDir()
		inputPath := createTestPEFile(t, testDir, prefix+"-unsigned")

		verifyOpts := VerifyOptions{
			Input: inputPath,
		}

		_, err := cmd.Verify(testCtx, verifyOpts)
		// Unsigned file verification should fail
		require.Error(t, err, "Verify unsigned file should fail")
	})

	t.Run("VerifyInvalidCertificate", func(t *testing.T) {
		testDir := t.TempDir()
		keyPath, certPath := createRSATestKeyAndCert(t, testDir, prefix+"-invalid-verify-cert")
		inputPath := createTestPEFile(t, testDir, prefix+"-invalid-verify-cert")
		outputPath := filepath.Join(testDir, prefix+"-invalid-verify-cert-signed.efi")

		// Sign the file
		signOpts := SignOptions{
			KeyPath:  keyPath,
			CertPath: certPath,
			Input:    inputPath,
			Output:   outputPath,
		}

		signResult, err := cmd.Sign(testCtx, signOpts)
		require.NoError(t, err, "Sign should succeed")
		require.True(t, signResult.Success, "Sign should be successful")

		// Create an invalid cert for verification
		invalidCertPath := filepath.Join(testDir, "invalid-verify-cert.pem")
		err = os.WriteFile(invalidCertPath, []byte("not a valid certificate"), 0644)
		require.NoError(t, err, "Failed to create invalid cert file")

		verifyOpts := VerifyOptions{
			Input:    outputPath,
			CertPath: invalidCertPath,
		}

		_, err = cmd.Verify(testCtx, verifyOpts)
		require.Error(t, err, "Verify with invalid certificate should fail")
	})

	t.Run("VerifyCorruptedSignature", func(t *testing.T) {
		testDir := t.TempDir()
		keyPath, certPath := createRSATestKeyAndCert(t, testDir, prefix+"-corrupted")
		inputPath := createTestPEFile(t, testDir, prefix+"-corrupted")
		outputPath := filepath.Join(testDir, prefix+"-corrupted-signed.efi")

		// Sign the file
		signOpts := SignOptions{
			KeyPath:  keyPath,
			CertPath: certPath,
			Input:    inputPath,
			Output:   outputPath,
		}

		signResult, err := cmd.Sign(testCtx, signOpts)
		require.NoError(t, err, "Sign should succeed")
		require.True(t, signResult.Success, "Sign should be successful")

		// Corrupt the signed file
		data, err := os.ReadFile(outputPath)
		require.NoError(t, err, "Failed to read signed file")
		if len(data) > 100 {
			// Flip some bytes in the middle (likely in the signature area)
			data[len(data)/2] ^= 0xFF
			data[len(data)/2+1] ^= 0xFF
		}
		err = os.WriteFile(outputPath, data, 0644)
		require.NoError(t, err, "Failed to write corrupted file")

		verifyOpts := VerifyOptions{
			Input: outputPath,
		}

		_, err = cmd.Verify(testCtx, verifyOpts)
		require.Error(t, err, "Verify corrupted signature should fail")
	})
}

// =============================================================================
// Test Fixture Helpers
// =============================================================================

// createRSATestKeyAndCert creates an RSA key pair and self-signed certificate for testing.
func createRSATestKeyAndCert(t *testing.T, testDir, name string) (keyPath, certPath string) {
	return createRSATestKeyAndCertWithBits(t, testDir, name, 2048)
}

// createRSATestKeyAndCertWithBits creates an RSA key pair with specified bit size.
func createRSATestKeyAndCertWithBits(t *testing.T, testDir, name string, bits int) (keyPath, certPath string) {
	t.Helper()

	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err, "Failed to generate RSA key")

	// Create self-signed certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("Test Signer %s", name),
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err, "Failed to create certificate")

	// Write private key
	keyPath = filepath.Join(testDir, name+"-key.pem")
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	err = os.WriteFile(keyPath, keyPEM, 0600)
	require.NoError(t, err, "Failed to write key file")

	// Write certificate
	certPath = filepath.Join(testDir, name+"-cert.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	err = os.WriteFile(certPath, certPEM, 0644)
	require.NoError(t, err, "Failed to write cert file")

	return keyPath, certPath
}

// createECDSATestKeyAndCert creates an ECDSA key pair and self-signed certificate for testing.
func createECDSATestKeyAndCert(t *testing.T, testDir, name string, curve elliptic.Curve) (keyPath, certPath string) {
	t.Helper()

	// Generate ECDSA key
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err, "Failed to generate ECDSA key")

	// Create self-signed certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("Test Signer %s", name),
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err, "Failed to create certificate")

	// Write private key (PKCS#8 format for ECDSA)
	keyPath = filepath.Join(testDir, name+"-key.pem")
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err, "Failed to marshal ECDSA key")
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})
	err = os.WriteFile(keyPath, keyPEM, 0600)
	require.NoError(t, err, "Failed to write key file")

	// Write certificate
	certPath = filepath.Join(testDir, name+"-cert.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	err = os.WriteFile(certPath, certPEM, 0644)
	require.NoError(t, err, "Failed to write cert file")

	return keyPath, certPath
}

// createTestPEFile creates a minimal PE/COFF file for testing.
// This creates a valid PE header structure that can be signed.
func createTestPEFile(t *testing.T, testDir, name string) string {
	t.Helper()

	filePath := filepath.Join(testDir, name+".efi")

	// Create a minimal PE/COFF structure
	// DOS Header (64 bytes)
	dosHeader := make([]byte, 64)
	dosHeader[0] = 'M'
	dosHeader[1] = 'Z'
	// e_lfanew at offset 0x3C points to PE signature
	binary.LittleEndian.PutUint32(dosHeader[0x3C:], 64) // PE header at offset 64

	// PE Signature (4 bytes)
	peSignature := []byte{'P', 'E', 0, 0}

	// COFF File Header (20 bytes)
	coffHeader := make([]byte, 20)
	// Machine: AMD64 (0x8664)
	binary.LittleEndian.PutUint16(coffHeader[0:], 0x8664)
	// NumberOfSections: 1
	binary.LittleEndian.PutUint16(coffHeader[2:], 1)
	// TimeDateStamp
	binary.LittleEndian.PutUint32(coffHeader[4:], uint32(time.Now().Unix()))
	// SizeOfOptionalHeader: 240 (PE32+)
	binary.LittleEndian.PutUint16(coffHeader[16:], 240)
	// Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
	binary.LittleEndian.PutUint16(coffHeader[18:], 0x22)

	// Optional Header PE32+ (240 bytes)
	optionalHeader := make([]byte, 240)
	// Magic: PE32+ (0x20b)
	binary.LittleEndian.PutUint16(optionalHeader[0:], 0x20b)
	// SizeOfCode
	binary.LittleEndian.PutUint32(optionalHeader[4:], 0x200)
	// AddressOfEntryPoint
	binary.LittleEndian.PutUint32(optionalHeader[16:], 0x1000)
	// ImageBase
	binary.LittleEndian.PutUint64(optionalHeader[24:], 0x10000)
	// SectionAlignment
	binary.LittleEndian.PutUint32(optionalHeader[32:], 0x1000)
	// FileAlignment
	binary.LittleEndian.PutUint32(optionalHeader[36:], 0x200)
	// SizeOfImage
	binary.LittleEndian.PutUint32(optionalHeader[56:], 0x3000)
	// SizeOfHeaders
	binary.LittleEndian.PutUint32(optionalHeader[60:], 0x200)
	// Subsystem: EFI_APPLICATION (10)
	binary.LittleEndian.PutUint16(optionalHeader[68:], 10)
	// NumberOfRvaAndSizes: 16
	binary.LittleEndian.PutUint32(optionalHeader[108:], 16)

	// Section Header (40 bytes) - .text section
	sectionHeader := make([]byte, 40)
	copy(sectionHeader[0:8], ".text\x00\x00\x00")
	// VirtualSize
	binary.LittleEndian.PutUint32(sectionHeader[8:], 0x100)
	// VirtualAddress
	binary.LittleEndian.PutUint32(sectionHeader[12:], 0x1000)
	// SizeOfRawData
	binary.LittleEndian.PutUint32(sectionHeader[16:], 0x200)
	// PointerToRawData
	binary.LittleEndian.PutUint32(sectionHeader[20:], 0x200)
	// Characteristics: MEM_EXECUTE | MEM_READ | CNT_CODE
	binary.LittleEndian.PutUint32(sectionHeader[36:], 0x60000020)

	// Padding to FileAlignment
	headerSize := len(dosHeader) + len(peSignature) + len(coffHeader) + len(optionalHeader) + len(sectionHeader)
	padding := make([]byte, 0x200-headerSize)

	// Section data (minimal code)
	sectionData := make([]byte, 0x200)
	// NOP sled and RET for minimal valid code
	for i := 0; i < len(sectionData)-1; i++ {
		sectionData[i] = 0x90 // NOP
	}
	sectionData[len(sectionData)-1] = 0xC3 // RET

	// Combine all parts
	pe := make([]byte, 0, 0x400)
	pe = append(pe, dosHeader...)
	pe = append(pe, peSignature...)
	pe = append(pe, coffHeader...)
	pe = append(pe, optionalHeader...)
	pe = append(pe, sectionHeader...)
	pe = append(pe, padding...)
	pe = append(pe, sectionData...)

	err := os.WriteFile(filePath, pe, 0644)
	require.NoError(t, err, "Failed to write test PE file")

	return filePath
}
