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

// Package ca provides multi-protocol integration tests for Certificate Authority services.
// These tests verify that CA operations work consistently across all protocol adapters
// (CLI, REST, gRPC, QUIC, MCP, Unix) using a unified CACommands interface.
//
// Run tests via:
//
//	make integration-test-ca
//
// The multiprotocol pattern enables:
//   - Testing all protocols against the same test scenarios
//   - Ensuring API consistency across transport layers
//   - Easy addition of new protocol adapters
package ca

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// =============================================================================
// Multi-Protocol Test Entry Point
// =============================================================================

// TestCAMultiProtocol runs the complete CA test suite against all protocol adapters.
// Each adapter implements the CACommands interface, enabling unified testing across
// CLI, REST, gRPC, QUIC, MCP, and Unix protocols.
func TestCAMultiProtocol(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// All protocol adapters that implement CACommands
	adapters := []CACommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}

	gate := helpers.NewAdapterGate(t, "ca", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter // Capture for closure
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			defer func() {
				if err := adapter.Teardown(); err != nil {
					t.Logf("Warning: teardown error for %s: %v", adapter.Name(), err)
				}
			}()

			testCAProtocol(t, ctx, adapter)
		})
	}
}

// testCAProtocol runs the complete CA test suite against a single protocol adapter.
func testCAProtocol(t *testing.T, ctx context.Context, cmd CACommands) {
	// Generate unique test prefix for this protocol run
	prefix := fmt.Sprintf("%s-%d", cmd.Name(), time.Now().Unix())

	t.Run("Info", func(t *testing.T) {
		testCAInfo(t, ctx, cmd)
	})

	t.Run("IssueCertificate", func(t *testing.T) {
		testIssueCertificate(t, ctx, cmd, prefix)
	})

	t.Run("GetCertificate", func(t *testing.T) {
		testGetCertificate(t, ctx, cmd, prefix)
	})

	t.Run("ListCertificates", func(t *testing.T) {
		testListCertificates(t, ctx, cmd)
	})

	t.Run("VerifyCertificate", func(t *testing.T) {
		testVerifyCertificate(t, ctx, cmd, prefix)
	})

	t.Run("RenewCertificate", func(t *testing.T) {
		testRenewCertificate(t, ctx, cmd, prefix)
	})

	t.Run("RevokeCertificate", func(t *testing.T) {
		testRevokeCertificate(t, ctx, cmd, prefix)
	})

	t.Run("CRL", func(t *testing.T) {
		testCRL(t, ctx, cmd)
	})

	t.Run("ExportBundle", func(t *testing.T) {
		testExportBundle(t, ctx, cmd)
	})
}

// =============================================================================
// CA Info Tests
// =============================================================================

func testCAInfo(t *testing.T, ctx context.Context, cmd CACommands) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("GetCAInfo", func(t *testing.T) {
		result, err := cmd.Info(testCtx)
		skipIfNotImplemented(t, err)
		require.NoError(t, err, "Info should succeed")
		require.NotNil(t, result, "Result should not be nil")

		// CA should be initialized
		assert.True(t, result.IsInitialized, "CA should be initialized")

		// Common name should be present
		assert.NotEmpty(t, result.CommonName, "Common name should not be empty")

		// Root certificate should be present
		assert.NotNil(t, result.RootCertificate, "Root certificate should be present")
	})
}

// =============================================================================
// Certificate Issue Tests
// =============================================================================

func testIssueCertificate(t *testing.T, ctx context.Context, cmd CACommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	t.Run("IssueECDSACertificate", func(t *testing.T) {
		opts := IssueCertificateOptions{
			CommonName: fmt.Sprintf("%s-ecdsa.example.com", prefix),
			StoreType:  "pkcs8",
			Algorithm:  "ECDSA-P256",
			ValidDays:  365,
		}

		result, err := cmd.IssueCertificate(testCtx, opts)
		skipIfNotImplemented(t, err)
		require.NoError(t, err, "Issue certificate should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "Issue should be successful")
		assert.NotNil(t, result.Certificate, "Certificate should be present")
		assert.NotEmpty(t, result.Certificate.Serial, "Serial should not be empty")
	})

	t.Run("IssueRSACertificate", func(t *testing.T) {
		opts := IssueCertificateOptions{
			CommonName: fmt.Sprintf("%s-rsa.example.com", prefix),
			StoreType:  "pkcs8",
			Algorithm:  "RSA-2048",
			ValidDays:  365,
		}

		result, err := cmd.IssueCertificate(testCtx, opts)
		require.NoError(t, err, "Issue RSA certificate should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "Issue should be successful")
	})

	t.Run("IssueCertificateWithSANs", func(t *testing.T) {
		opts := IssueCertificateOptions{
			CommonName: fmt.Sprintf("%s-sans.example.com", prefix),
			StoreType:  "pkcs8",
			Algorithm:  "ECDSA-P256",
			ValidDays:  365,
			SANsDNS:    []string{"www.example.com", "api.example.com"},
			SANsIPs:    []string{"192.168.1.1", "10.0.0.1"},
		}

		result, err := cmd.IssueCertificate(testCtx, opts)
		require.NoError(t, err, "Issue certificate with SANs should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "Issue should be successful")

		if result.Certificate != nil {
			assert.NotEmpty(t, result.Certificate.SANsDNS, "DNS SANs should be present")
		}
	})
}

// =============================================================================
// Certificate Get Tests
// =============================================================================

func testGetCertificate(t *testing.T, ctx context.Context, cmd CACommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	// First issue a certificate to retrieve
	cn := fmt.Sprintf("%s-get.example.com", prefix)
	issueOpts := IssueCertificateOptions{
		CommonName: cn,
		StoreType:  "pkcs8",
		Algorithm:  "ECDSA-P256",
		ValidDays:  365,
	}

	issueResult, err := cmd.IssueCertificate(testCtx, issueOpts)
	skipIfNotImplemented(t, err)
	require.NoError(t, err, "Issue certificate should succeed")
	require.True(t, issueResult.Success, "Issue should be successful")
	require.NotNil(t, issueResult.Certificate, "Certificate should be present")

	t.Run("GetBySerial", func(t *testing.T) {
		opts := GetCertificateOptions{
			Serial:     issueResult.Certificate.Serial,
			IncludePEM: true,
		}

		result, err := cmd.GetCertificate(testCtx, opts)
		skipIfNotImplemented(t, err)
		require.NoError(t, err, "Get certificate should succeed")
		require.NotNil(t, result, "Result should not be nil")
		require.NotNil(t, result.Certificate, "Certificate should be present")
		assert.Equal(t, issueResult.Certificate.Serial, result.Certificate.Serial, "Serial should match")
	})

	t.Run("GetByCommonName", func(t *testing.T) {
		opts := GetCertificateOptions{
			CommonName: cn,
			StoreType:  "pkcs8",
			Algorithm:  "ECDSA-P256",
			IncludePEM: true,
		}

		result, err := cmd.GetCertificate(testCtx, opts)
		require.NoError(t, err, "Get certificate by CN should succeed")
		require.NotNil(t, result, "Result should not be nil")
		require.NotNil(t, result.Certificate, "Certificate should be present")
	})

	t.Run("GetNonExistent", func(t *testing.T) {
		opts := GetCertificateOptions{
			Serial: "nonexistent-serial-12345",
		}

		_, err := cmd.GetCertificate(testCtx, opts)
		require.Error(t, err, "Get nonexistent certificate should fail")
	})
}

// =============================================================================
// Certificate List Tests
// =============================================================================

func testListCertificates(t *testing.T, ctx context.Context, cmd CACommands) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("ListAll", func(t *testing.T) {
		opts := ListCertificatesOptions{
			Status: "all",
		}

		result, err := cmd.ListCertificates(testCtx, opts)
		skipIfNotImplemented(t, err)
		require.NoError(t, err, "List certificates should succeed")
		require.NotNil(t, result, "Result should not be nil")

		// Should have at least the CA certificates
		assert.NotEmpty(t, result.Certificates, "Should have at least some certificates")
	})

	t.Run("ListActive", func(t *testing.T) {
		opts := ListCertificatesOptions{
			Status: "active",
		}

		result, err := cmd.ListCertificates(testCtx, opts)
		require.NoError(t, err, "List active certificates should succeed")
		require.NotNil(t, result, "Result should not be nil")

		// All returned certificates should be valid
		for _, cert := range result.Certificates {
			assert.Equal(t, CertificateStatusValid, cert.Status, "All should be valid")
		}
	})

	t.Run("ListWithLimit", func(t *testing.T) {
		opts := ListCertificatesOptions{
			Status: "all",
			Limit:  5,
		}

		result, err := cmd.ListCertificates(testCtx, opts)
		require.NoError(t, err, "List certificates with limit should succeed")
		require.NotNil(t, result, "Result should not be nil")

		assert.LessOrEqual(t, len(result.Certificates), 5, "Should respect limit")
	})
}

// =============================================================================
// Certificate Verify Tests
// =============================================================================

func testVerifyCertificate(t *testing.T, ctx context.Context, cmd CACommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	// First issue a certificate to verify
	cn := fmt.Sprintf("%s-verify.example.com", prefix)
	issueOpts := IssueCertificateOptions{
		CommonName: cn,
		StoreType:  "pkcs8",
		Algorithm:  "ECDSA-P256",
		ValidDays:  365,
	}

	issueResult, err := cmd.IssueCertificate(testCtx, issueOpts)
	skipIfNotImplemented(t, err)
	require.NoError(t, err, "Issue certificate should succeed")
	require.True(t, issueResult.Success, "Issue should be successful")
	require.NotNil(t, issueResult.Certificate, "Certificate should be present")

	// Retrieve the certificate with PEM data for verification tests.
	// The VerifyCertificate API across all protocols (gRPC, REST, QUIC, MCP)
	// requires the actual PEM data, not just a serial number. The CLI adapter
	// handles serial-to-PEM conversion internally, but other adapters need
	// the PEM to be provided explicitly.
	certPEM := issueResult.Certificate.PEM
	if len(certPEM) == 0 {
		// If the issue response didn't include PEM, fetch it via GetCertificate
		getResult, getErr := cmd.GetCertificate(testCtx, GetCertificateOptions{
			Serial:     issueResult.Certificate.Serial,
			IncludePEM: true,
		})
		if getErr == nil && getResult.Certificate != nil {
			certPEM = getResult.Certificate.PEM
		}
	}

	t.Run("VerifyValidCertificate", func(t *testing.T) {
		if len(certPEM) == 0 {
			t.Skip("PEM not available for verification")
		}

		opts := VerifyCertificateOptions{
			Serial:          issueResult.Certificate.Serial,
			CertificatePEM:  certPEM,
			CheckCRL:        true,
			CheckExpiration: true,
		}

		result, err := cmd.VerifyCertificate(testCtx, opts)
		require.NoError(t, err, "Verify certificate should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Valid, "Certificate should be valid")
		assert.False(t, result.Expired, "Certificate should not be expired")
		assert.False(t, result.Revoked, "Certificate should not be revoked")
	})

	t.Run("VerifyWithPEM", func(t *testing.T) {
		if len(certPEM) == 0 {
			t.Skip("PEM not available in issued certificate")
		}

		opts := VerifyCertificateOptions{
			CertificatePEM:  certPEM,
			CheckCRL:        true,
			CheckExpiration: true,
		}

		result, err := cmd.VerifyCertificate(testCtx, opts)
		require.NoError(t, err, "Verify certificate with PEM should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Valid, "Certificate should be valid")
	})
}

// =============================================================================
// Certificate Renew Tests
// =============================================================================

func testRenewCertificate(t *testing.T, ctx context.Context, cmd CACommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	// First issue a certificate to renew
	cn := fmt.Sprintf("%s-renew.example.com", prefix)
	issueOpts := IssueCertificateOptions{
		CommonName: cn,
		StoreType:  "pkcs8",
		Algorithm:  "ECDSA-P256",
		ValidDays:  30, // Short validity to simulate expiring soon
	}

	issueResult, err := cmd.IssueCertificate(testCtx, issueOpts)
	skipIfNotImplemented(t, err)
	require.NoError(t, err, "Issue certificate should succeed")
	require.True(t, issueResult.Success, "Issue should be successful")
	require.NotNil(t, issueResult.Certificate, "Certificate should be present")

	t.Run("RenewCertificate", func(t *testing.T) {
		opts := RenewCertificateOptions{
			Serial:       issueResult.Certificate.Serial,
			ValidDays:    365,
			PreserveSANs: true,
		}

		result, err := cmd.RenewCertificate(testCtx, opts)
		skipIfNotImplemented(t, err)
		require.NoError(t, err, "Renew certificate should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "Renew should be successful")
		assert.NotNil(t, result.NewCertificate, "New certificate should be present")

		if result.NewCertificate != nil && issueResult.Certificate != nil {
			assert.NotEqual(t, issueResult.Certificate.Serial, result.NewCertificate.Serial, "New serial should be different")
		}
	})
}

// =============================================================================
// Certificate Revoke Tests
// =============================================================================

func testRevokeCertificate(t *testing.T, ctx context.Context, cmd CACommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	// First issue a certificate to revoke
	cn := fmt.Sprintf("%s-revoke.example.com", prefix)
	issueOpts := IssueCertificateOptions{
		CommonName: cn,
		StoreType:  "pkcs8",
		Algorithm:  "ECDSA-P256",
		ValidDays:  365,
	}

	issueResult, err := cmd.IssueCertificate(testCtx, issueOpts)
	skipIfNotImplemented(t, err)
	require.NoError(t, err, "Issue certificate should succeed")
	require.True(t, issueResult.Success, "Issue should be successful")
	require.NotNil(t, issueResult.Certificate, "Certificate should be present")

	// Retrieve PEM data for the revoked certificate verification test
	certPEM := issueResult.Certificate.PEM
	if len(certPEM) == 0 {
		getResult, getErr := cmd.GetCertificate(testCtx, GetCertificateOptions{
			Serial:     issueResult.Certificate.Serial,
			IncludePEM: true,
		})
		if getErr == nil && getResult.Certificate != nil {
			certPEM = getResult.Certificate.PEM
		}
	}

	t.Run("RevokeCertificate", func(t *testing.T) {
		opts := RevokeCertificateOptions{
			Serial:     issueResult.Certificate.Serial,
			Reason:     RevocationReasonSuperseded,
			DeleteKeys: true,
		}

		result, err := cmd.RevokeCertificate(testCtx, opts)
		require.NoError(t, err, "Revoke certificate should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "Revoke should be successful")
		assert.Equal(t, CertificateStatusRevoked, result.Status, "Status should be revoked")
	})

	t.Run("VerifyRevokedCertificate", func(t *testing.T) {
		if len(certPEM) == 0 {
			t.Skip("PEM not available for revocation verification")
		}

		opts := VerifyCertificateOptions{
			Serial:         issueResult.Certificate.Serial,
			CertificatePEM: certPEM,
			CheckCRL:       true,
		}

		result, err := cmd.VerifyCertificate(testCtx, opts)
		require.NoError(t, err, "Verify revoked certificate should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.False(t, result.Valid, "Revoked certificate should not be valid")
		assert.True(t, result.Revoked, "Certificate should be marked as revoked")
	})
}

// =============================================================================
// CRL Tests
// =============================================================================

func testCRL(t *testing.T, ctx context.Context, cmd CACommands) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("GetCRL", func(t *testing.T) {
		opts := GetCRLOptions{
			IncludeEntries: true,
		}

		result, err := cmd.GetCRL(testCtx, opts)
		skipIfNotImplemented(t, err)
		require.NoError(t, err, "Get CRL should succeed")
		require.NotNil(t, result, "Result should not be nil")

		// CRL should have valid timestamps
		assert.False(t, result.ThisUpdate.IsZero(), "ThisUpdate should be set")
		assert.False(t, result.NextUpdate.IsZero(), "NextUpdate should be set")
		assert.True(t, result.NextUpdate.After(result.ThisUpdate), "NextUpdate should be after ThisUpdate")
	})

	t.Run("GenerateCRL", func(t *testing.T) {
		result, err := cmd.GenerateCRL(testCtx)
		if err != nil {
			// Some adapters may not support CRL generation
			if _, ok := err.(ErrNotImplemented); ok {
				t.Skipf("CRL generate not implemented for this adapter")
			}
			require.Fail(t, "Generate CRL failed", err.Error())
		}

		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "Generate CRL should be successful")
	})
}

// =============================================================================
// Export Bundle Tests
// =============================================================================

func testExportBundle(t *testing.T, ctx context.Context, cmd CACommands) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("ExportCABundle", func(t *testing.T) {
		result, err := cmd.ExportBundle(testCtx, "")
		skipIfNotImplemented(t, err)
		require.NoError(t, err, "Export bundle should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "Export should be successful")
		assert.Greater(t, result.CertCount, int32(0), "Should have at least one certificate")
	})

	t.Run("ExportCABundleToFile", func(t *testing.T) {
		tmpFile := fmt.Sprintf("/tmp/ca-bundle-test-%d.pem", time.Now().UnixNano())

		result, err := cmd.ExportBundle(testCtx, tmpFile)
		require.NoError(t, err, "Export bundle to file should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "Export should be successful")
		assert.Equal(t, tmpFile, result.FilePath, "File path should match")
		assert.Greater(t, result.Size, int64(0), "File size should be positive")
	})
}
