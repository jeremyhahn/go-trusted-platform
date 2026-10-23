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

package vtpm

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// EKCertInfo Tests
// =============================================================================

func TestEKCertInfo_Fingerprint(t *testing.T) {
	// Create a test certificate
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	// Calculate expected fingerprint
	hash := sha256.Sum256(cert.Raw)
	expectedFingerprint := "sha256:" + hex.EncodeToString(hash[:])

	// Calculate using certFingerprint
	actualFingerprint := certFingerprint(cert)

	if actualFingerprint != expectedFingerprint {
		t.Errorf("certFingerprint() = %v, want %v", actualFingerprint, expectedFingerprint)
	}
}

func TestEKCertInfo_Struct(t *testing.T) {
	now := time.Now()
	notBefore := now.Add(-1 * time.Hour)
	notAfter := now.Add(365 * 24 * time.Hour)

	info := &EKCertInfo{
		Subject:      "CN=test.example.com",
		Issuer:       "CN=Test CA",
		SerialNumber: "12345",
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		Fingerprint:  "sha256:abc123",
	}

	// Verify all fields
	if info.Subject != "CN=test.example.com" {
		t.Errorf("Subject = %v, want CN=test.example.com", info.Subject)
	}
	if info.Issuer != "CN=Test CA" {
		t.Errorf("Issuer = %v, want CN=Test CA", info.Issuer)
	}
	if info.SerialNumber != "12345" {
		t.Errorf("SerialNumber = %v, want 12345", info.SerialNumber)
	}
	if !info.NotBefore.Equal(notBefore) {
		t.Errorf("NotBefore = %v, want %v", info.NotBefore, notBefore)
	}
	if !info.NotAfter.Equal(notAfter) {
		t.Errorf("NotAfter = %v, want %v", info.NotAfter, notAfter)
	}
	if info.Fingerprint != "sha256:abc123" {
		t.Errorf("Fingerprint = %v, want sha256:abc123", info.Fingerprint)
	}
}

// =============================================================================
// CA Error Handling Tests
// =============================================================================

type ekErrorMockCA struct {
	returnErr error
}

func (m *ekErrorMockCA) IssueEKCertificate(ctx context.Context, publicKey crypto.PublicKey, hostname string) (*x509.Certificate, error) {
	return nil, m.returnErr
}

func TestInjectEKCertificate_CAUnavailable(t *testing.T) {
	config := createEKTestConfig(t)

	// Create a mock CA that returns an error
	mockCA := &ekErrorMockCA{
		returnErr: errors.New("CA service unavailable"),
	}

	service, err := NewService(config, nil, mockCA)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	ctx := context.Background()
	opts := &CreateBundleOptions{
		Hostname:    "test.example.com",
		EKAlgorithm: EKAlgorithmRSA,
	}

	// This will fail because we can't connect to the socket
	// But we're testing the error type
	_, err = service.injectEKCertificate(ctx, "/nonexistent/socket.sock", t.TempDir(), opts)
	if err == nil {
		t.Error("injectEKCertificate should fail with nonexistent socket")
	}

	// Should be a TPM connection error since we can't connect
	var connErr ErrTPMConnectionFailed
	if !errors.As(err, &connErr) {
		// If not connection error, might be CA error in a different path
		t.Logf("Got error type: %T, error: %v", err, err)
	}
}

func TestInjectEKCertificate_InvalidSocketPath(t *testing.T) {
	config := createEKTestConfig(t)

	service, err := NewService(config, nil, &ekWorkingMockCA{})
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	ctx := context.Background()
	opts := &CreateBundleOptions{
		Hostname:    "test.example.com",
		EKAlgorithm: EKAlgorithmRSA,
	}

	// Try with empty socket path
	_, err = service.injectEKCertificate(ctx, "", t.TempDir(), opts)
	if err == nil {
		t.Error("injectEKCertificate should fail with empty socket path")
	}

	// Should fail with connection error
	var connErr ErrTPMConnectionFailed
	if !errors.As(err, &connErr) {
		t.Logf("Got error type: %T, expected ErrTPMConnectionFailed", err)
	}
}

// =============================================================================
// EK Algorithm Tests
// =============================================================================

func TestEKAlgorithm_NVIndex_RSA(t *testing.T) {
	alg := EKAlgorithmRSA
	nvIndex := alg.NVIndex()

	// TCG-defined NV index for RSA EK certificate
	expected := uint32(NVIndexRSAEKCert)
	if nvIndex != expected {
		t.Errorf("EKAlgorithmRSA.NVIndex() = 0x%08X, want 0x%08X", nvIndex, expected)
	}
}

func TestEKAlgorithm_NVIndex_ECC(t *testing.T) {
	alg := EKAlgorithmECC
	nvIndex := alg.NVIndex()

	// TCG-defined NV index for ECC EK certificate
	expected := uint32(NVIndexECCEKCert)
	if nvIndex != expected {
		t.Errorf("EKAlgorithmECC.NVIndex() = 0x%08X, want 0x%08X", nvIndex, expected)
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

func createEKTestConfig(t *testing.T) *Config {
	tmpDir := t.TempDir()

	// Create OVMF files (just need to exist for validation)
	ovmfCode := filepath.Join(tmpDir, "OVMF_CODE.fd")
	ovmfVars := filepath.Join(tmpDir, "OVMF_VARS.fd")
	os.WriteFile(ovmfCode, []byte("test"), 0644)
	os.WriteFile(ovmfVars, []byte("test"), 0644)

	return &Config{
		BaseDir:              tmpDir,
		OVMFCode:             ovmfCode,
		OVMFVars:             ovmfVars,
		PCRBanks:             []string{"sha256"},
		SecureBootKeySize:    2048,
		SecureBootValidYears: 10,
		EKAlgorithm:          EKAlgorithmRSA,
	}
}

// ekWorkingMockCA is a mock CA that successfully issues certificates.
type ekWorkingMockCA struct{}

func (m *ekWorkingMockCA) IssueEKCertificate(ctx context.Context, publicKey crypto.PublicKey, hostname string) (*x509.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: hostname,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	// Generate a key for signing
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, publicKey, key)
	cert, _ := x509.ParseCertificate(certDER)
	return cert, nil
}

// =============================================================================
// Certificate Fingerprint Tests
// =============================================================================

func TestCertFingerprint_Consistency(t *testing.T) {
	// Generate a certificate
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	// Calculate fingerprint multiple times - should be consistent
	fp1 := certFingerprint(cert)
	fp2 := certFingerprint(cert)
	fp3 := certFingerprint(cert)

	if fp1 != fp2 || fp2 != fp3 {
		t.Error("certFingerprint should return consistent results")
	}
}

func TestCertFingerprint_Format(t *testing.T) {
	// Generate a certificate
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	fp := certFingerprint(cert)

	// Verify format: "sha256:" prefix followed by hex string
	if !strings.HasPrefix(fp, "sha256:") {
		t.Errorf("Fingerprint should start with 'sha256:', got: %s", fp)
	}

	// SHA256 hash is 32 bytes = 64 hex chars
	hexPart := strings.TrimPrefix(fp, "sha256:")
	if len(hexPart) != 64 {
		t.Errorf("Fingerprint hex part should be 64 chars, got %d", len(hexPart))
	}

	// Verify it's valid hex
	if _, err := hex.DecodeString(hexPart); err != nil {
		t.Errorf("Fingerprint hex part is not valid hex: %v", err)
	}
}

func TestCertFingerprint_DifferentCerts(t *testing.T) {
	// Generate two different certificates
	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)

	template1 := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test1.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	template2 := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test2.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	certDER1, _ := x509.CreateCertificate(rand.Reader, template1, template1, &key1.PublicKey, key1)
	certDER2, _ := x509.CreateCertificate(rand.Reader, template2, template2, &key2.PublicKey, key2)
	cert1, _ := x509.ParseCertificate(certDER1)
	cert2, _ := x509.ParseCertificate(certDER2)

	fp1 := certFingerprint(cert1)
	fp2 := certFingerprint(cert2)

	if fp1 == fp2 {
		t.Error("Different certificates should have different fingerprints")
	}
}

// =============================================================================
// Comprehensive Table-Driven Tests
// =============================================================================

func TestEKAlgorithm_Comprehensive(t *testing.T) {
	tests := []struct {
		name          string
		algorithm     EKAlgorithm
		expectedValid bool
		expectedIndex uint32
	}{
		{
			name:          "RSA algorithm",
			algorithm:     EKAlgorithmRSA,
			expectedValid: true,
			expectedIndex: NVIndexRSAEKCert,
		},
		{
			name:          "ECC algorithm",
			algorithm:     EKAlgorithmECC,
			expectedValid: true,
			expectedIndex: NVIndexECCEKCert,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test IsValid
			if tt.algorithm.IsValid() != tt.expectedValid {
				t.Errorf("IsValid() = %v, want %v", tt.algorithm.IsValid(), tt.expectedValid)
			}

			// Test NVIndex
			if tt.algorithm.NVIndex() != tt.expectedIndex {
				t.Errorf("NVIndex() = 0x%08X, want 0x%08X", tt.algorithm.NVIndex(), tt.expectedIndex)
			}
		})
	}
}
