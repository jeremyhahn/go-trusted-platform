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

// Package network provides integration tests for network authentication services.
// These tests coordinate test environment setup and teardown for OVS-based
// network authentication flows.
//
// Run tests via:
//
//	make integration-test-network
package network

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"
)

// =============================================================================
// Global Test State
// =============================================================================

var (
	// testBridgeName is the OVS bridge name used for network auth tests.
	testBridgeName = "test-network-auth"

	// testCACert is the test CA certificate in PEM format.
	testCACert []byte

	// testCAKey is the test CA private key in PEM format.
	testCAKey []byte

	// testCAPrivateKey is the parsed CA private key for signing.
	testCAPrivateKey *ecdsa.PrivateKey

	// testCACertParsed is the parsed CA certificate for signing.
	testCACertParsed *x509.Certificate

	// ovsAvailable indicates whether OVS is available in the test environment.
	ovsAvailable bool

	// opaAvailable indicates whether OPA is available in the test environment.
	opaAvailable bool
)

// =============================================================================
// TestMain
// =============================================================================

// TestMain coordinates integration test setup and teardown.
// It checks for the INTEGRATION_TEST environment variable and sets up
// the test environment including OVS bridges and test certificates.
func TestMain(m *testing.M) {
	// Check for integration test environment
	if os.Getenv("INTEGRATION_TEST") == "" {
		fmt.Println("Skipping integration tests. Set INTEGRATION_TEST=1 to run.")
		os.Exit(0)
	}

	// Setup test environment
	code := setupTestEnvironment()
	if code != 0 {
		os.Exit(code)
	}

	// Run tests
	result := m.Run()

	// Cleanup
	cleanupTestEnvironment()

	os.Exit(result)
}

// =============================================================================
// Setup Functions
// =============================================================================

// setupTestEnvironment initializes the test environment.
// It checks for OVS and OPA availability, sets up test certificates,
// and creates test bridges if OVS is available.
func setupTestEnvironment() int {
	fmt.Println("Setting up network integration test environment...")

	// Check OVS availability
	ovsAvailable = CheckOVSAvailable()
	if ovsAvailable {
		fmt.Println("  - OVS: available")
	} else {
		fmt.Println("  - OVS: not available (some tests will be skipped)")
	}

	// Check OPA availability
	endpoints := GetServiceEndpoints()
	opaAvailable = CheckOPAAvailable(endpoints.OPA)
	if opaAvailable {
		fmt.Println("  - OPA: available at", endpoints.OPA)
	} else {
		fmt.Println("  - OPA: not available (some tests will be skipped)")
	}

	// Setup test CA
	if err := setupTestCA(); err != nil {
		fmt.Printf("Failed to setup test CA: %v\n", err)
		return 1
	}
	fmt.Println("  - Test CA: created")

	// Create test bridge if OVS is available
	if ovsAvailable {
		if err := CreateTestBridge(testBridgeName); err != nil {
			fmt.Printf("Failed to create test bridge: %v\n", err)
			return 1
		}
		fmt.Println("  - Test bridge:", testBridgeName, "created")
	}

	fmt.Println("Test environment setup complete.")
	return 0
}

// cleanupTestEnvironment tears down the test environment.
// It removes test bridges and cleans up any temporary files.
func cleanupTestEnvironment() {
	fmt.Println("Cleaning up network integration test environment...")

	// Delete test bridge if OVS was available
	if ovsAvailable {
		if err := DeleteTestBridge(testBridgeName); err != nil {
			fmt.Printf("Warning: failed to delete test bridge %s: %v\n", testBridgeName, err)
		} else {
			fmt.Println("  - Test bridge:", testBridgeName, "deleted")
		}
	}

	// Clear test certificates (memory cleanup)
	testCACert = nil
	testCAKey = nil
	testCAPrivateKey = nil
	testCACertParsed = nil

	fmt.Println("Test environment cleanup complete.")
}

// =============================================================================
// Certificate Authority Setup
// =============================================================================

// setupTestCA generates a test Certificate Authority for signing test certificates.
// The CA uses ECDSA P-256 and is valid for 24 hours.
func setupTestCA() error {
	// Generate ECDSA private key for CA
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate CA private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate CA serial number: %w", err)
	}

	// Create CA certificate template
	now := time.Now()
	caTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         "Test Network Auth CA",
			Organization:       []string{"go-trusted-platform Test"},
			OrganizationalUnit: []string{"Integration Tests"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	// Create self-signed CA certificate
	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Encode CA certificate to PEM
	certBuf := new(bytes.Buffer)
	if err := pem.Encode(certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: caCertDER}); err != nil {
		return fmt.Errorf("failed to encode CA certificate PEM: %w", err)
	}
	testCACert = certBuf.Bytes()

	// Encode CA private key to PEM
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal CA private key: %w", err)
	}

	keyBuf := new(bytes.Buffer)
	if err := pem.Encode(keyBuf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		return fmt.Errorf("failed to encode CA key PEM: %w", err)
	}
	testCAKey = keyBuf.Bytes()

	// Parse and store for later use
	testCAPrivateKey = privateKey
	testCACertParsed, err = x509.ParseCertificate(caCertDER)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	return nil
}

// =============================================================================
// Certificate Signing Helpers
// =============================================================================

// SignCertificateWithTestCA signs a certificate using the test CA.
// This is useful for creating client certificates that chain to the test CA.
func SignCertificateWithTestCA(template *x509.Certificate, publicKey interface{}) ([]byte, error) {
	if testCACertParsed == nil || testCAPrivateKey == nil {
		return nil, fmt.Errorf("test CA not initialized")
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, testCACertParsed, publicKey, testCAPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	certBuf := new(bytes.Buffer)
	if err := pem.Encode(certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return nil, fmt.Errorf("failed to encode certificate PEM: %w", err)
	}

	return certBuf.Bytes(), nil
}

// GenerateClientCertificate generates a client certificate signed by the test CA.
// The certificate is valid for 24 hours and uses ECDSA P-256.
func GenerateClientCertificate(cn string) (certPEM, keyPEM []byte, err error) {
	if testCACertParsed == nil || testCAPrivateKey == nil {
		return nil, nil, fmt.Errorf("test CA not initialized")
	}

	// Generate ECDSA private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create certificate template
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"go-trusted-platform Test"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Sign with test CA
	certPEM, err = SignCertificateWithTestCA(&template, &privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	// Encode private key to PEM
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyBuf := new(bytes.Buffer)
	if err := pem.Encode(keyBuf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		return nil, nil, fmt.Errorf("failed to encode key PEM: %w", err)
	}

	return certPEM, keyBuf.Bytes(), nil
}

// =============================================================================
// Environment Check Helpers
// =============================================================================

// IsOVSAvailable returns true if OVS is available in the test environment.
func IsOVSAvailable() bool {
	return ovsAvailable
}

// IsOPAAvailable returns true if OPA is available in the test environment.
func IsOPAAvailable() bool {
	return opaAvailable
}

// GetTestBridgeName returns the name of the test OVS bridge.
func GetTestBridgeName() string {
	return testBridgeName
}

// GetTestCACert returns the test CA certificate in PEM format.
func GetTestCACert() []byte {
	return testCACert
}

// GetTestCAKey returns the test CA private key in PEM format.
func GetTestCAKey() []byte {
	return testCAKey
}
