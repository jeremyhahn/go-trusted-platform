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

package vm

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"testing"
	"time"
)

// testCAKeyPair holds a CA certificate and private key for testing.
type testCAKeyPair struct {
	cert    *x509.Certificate
	privKey *rsa.PrivateKey
}

// newTestCA creates a new test CA certificate and key pair.
func newTestCA() *testCAKeyPair {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Platform CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	cert, _ := x509.ParseCertificate(certBytes)

	return &testCAKeyPair{
		cert:    cert,
		privKey: privKey,
	}
}

// issueEKCertificate issues an EK certificate signed by this CA.
func (ca *testCAKeyPair) issueEKCertificate(vmID, hostID string, pubKey *rsa.PublicKey) (*x509.Certificate, []byte) {
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: "vm:" + vmID + "@host:" + hostID,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:    x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	certBytes, _ := x509.CreateCertificate(rand.Reader, &template, ca.cert, pubKey, ca.privKey)
	cert, _ := x509.ParseCertificate(certBytes)

	return cert, certBytes
}

// createTestQuote creates a test quote with valid signature.
func createTestQuote(privKey *rsa.PrivateKey, nonce []byte, pcrs []PCRValue) *VMQuote {
	// Create quote data
	quoteData := make([]byte, 64)
	rand.Read(quoteData)

	// Sign the quote
	hashed := sha256.Sum256(quoteData)
	signature, _ := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashed[:])

	// Marshal public key
	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(&privKey.PublicKey)

	return &VMQuote{
		QuoteData:          quoteData,
		Signature:          signature,
		SignatureAlgorithm: x509.SHA256WithRSA.String(),
		PCRs:               pcrs,
		PCRDigest:          make([]byte, 32),
		Nonce:              nonce,
		Timestamp:          time.Now().UTC(),
		AIKPublicKey:       pubKeyBytes,
		HashAlgorithm:      HashAlgorithmSHA256,
	}
}

func TestNewVMVerifier(t *testing.T) {
	t.Run("with defaults", func(t *testing.T) {
		verifier := NewVMVerifier()
		if verifier == nil {
			t.Error("Expected non-nil verifier")
		}
	})

	t.Run("with logger", func(t *testing.T) {
		logger := slog.Default()
		verifier := NewVMVerifier(WithVerifierLogger(logger))
		if verifier == nil {
			t.Error("Expected non-nil verifier")
		}
	})
}

func TestVMVerifier_Initialize(t *testing.T) {
	ctx := context.Background()
	ca := newTestCA()

	t.Run("successful initialization", func(t *testing.T) {
		verifier := NewVMVerifier()

		config := &VerifierConfig{
			PlatformCACert:     ca.cert,
			MaxQuoteAge:        300,
			RequireHostBinding: true,
			AllowedHostIDs:     []string{"host-1", "host-2"},
		}

		err := verifier.Initialize(ctx, config)
		if err != nil {
			t.Errorf("Initialize() unexpected error: %v", err)
		}
	})

	t.Run("nil config", func(t *testing.T) {
		verifier := NewVMVerifier()

		err := verifier.Initialize(ctx, nil)
		if err == nil {
			t.Error("Expected error for nil config")
		}
		var configErr ErrInvalidConfig
		if !errors.As(err, &configErr) {
			t.Errorf("Expected ErrInvalidConfig, got %T", err)
		}
	})

	t.Run("nil platform CA cert", func(t *testing.T) {
		verifier := NewVMVerifier()

		config := &VerifierConfig{
			PlatformCACert: nil,
		}

		err := verifier.Initialize(ctx, config)
		if err == nil {
			t.Error("Expected error for nil platform CA cert")
		}
	})

	t.Run("already initialized", func(t *testing.T) {
		verifier := NewVMVerifier()

		config := &VerifierConfig{
			PlatformCACert: ca.cert,
		}

		err := verifier.Initialize(ctx, config)
		if err != nil {
			t.Errorf("First Initialize() unexpected error: %v", err)
		}

		err = verifier.Initialize(ctx, config)
		if err == nil {
			t.Error("Expected error for already initialized")
		}
	})

	t.Run("context canceled", func(t *testing.T) {
		verifier := NewVMVerifier()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		config := &VerifierConfig{
			PlatformCACert: ca.cert,
		}

		err := verifier.Initialize(ctx, config)
		if err == nil {
			t.Error("Expected error for canceled context")
		}
	})
}

func TestVMVerifier_VerifyQuote(t *testing.T) {
	ctx := context.Background()
	ca := newTestCA()

	setupVerifier := func() VMVerifier {
		verifier := NewVMVerifier()

		config := &VerifierConfig{
			PlatformCACert:     ca.cert,
			MaxQuoteAge:        300,
			RequireHostBinding: false,
		}

		if err := verifier.Initialize(ctx, config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}
		return verifier
	}

	t.Run("successful verification", func(t *testing.T) {
		verifier := setupVerifier()

		// Create test keys and certificate
		aikPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		ekCert, _ := ca.issueEKCertificate("vm-123", "host-456", &aikPrivKey.PublicKey)

		nonce := []byte{0x01, 0x02, 0x03, 0x04}
		pcrs := []PCRValue{
			{Index: 0, Value: make([]byte, 32), Algorithm: HashAlgorithmSHA256},
			{Index: 14, Value: make([]byte, 32), Algorithm: HashAlgorithmSHA256},
		}

		quote := createTestQuote(aikPrivKey, nonce, pcrs)

		identity := &VMIdentity{
			VMID:          "vm-123",
			HostID:        "host-456",
			EKCertificate: ekCert,
		}

		expectedPCRs := map[int][]byte{
			0:  make([]byte, 32),
			14: make([]byte, 32),
		}

		request := &VerifyRequest{
			Quote:          quote,
			Identity:       identity,
			ExpectedNonce:  nonce,
			ExpectedPCRs:   expectedPCRs,
			PlatformCACert: ca.cert,
			MaxQuoteAge:    300,
		}

		result, err := verifier.VerifyQuote(ctx, request)
		if err != nil {
			t.Errorf("VerifyQuote() unexpected error: %v", err)
		}
		if result == nil {
			t.Error("Expected non-nil result")
			return
		}

		if result.Status != VerificationStatusVerified {
			t.Errorf("Expected verified status, got %s", result.Status)
		}
		if !result.SignatureValid {
			t.Error("Expected valid signature")
		}
		if !result.CertificateChainValid {
			t.Error("Expected valid certificate chain")
		}
		if !result.NonceValid {
			t.Error("Expected valid nonce")
		}
		if !result.PCRsValid {
			t.Error("Expected valid PCRs")
		}
	})

	t.Run("not initialized", func(t *testing.T) {
		verifier := NewVMVerifier()

		request := &VerifyRequest{
			Quote:          &VMQuote{},
			Identity:       &VMIdentity{VMID: "vm", HostID: "host"},
			ExpectedNonce:  []byte{0x01},
			PlatformCACert: ca.cert,
		}

		_, err := verifier.VerifyQuote(ctx, request)
		if err == nil {
			t.Error("Expected error for not initialized")
		}
		var initErr ErrVerifierNotInitialized
		if !errors.As(err, &initErr) {
			t.Errorf("Expected ErrVerifierNotInitialized, got %T", err)
		}
	})

	t.Run("nil request", func(t *testing.T) {
		verifier := setupVerifier()

		_, err := verifier.VerifyQuote(ctx, nil)
		if err == nil {
			t.Error("Expected error for nil request")
		}
	})

	t.Run("nonce mismatch", func(t *testing.T) {
		verifier := setupVerifier()

		aikPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		ekCert, _ := ca.issueEKCertificate("vm-123", "host-456", &aikPrivKey.PublicKey)

		nonce := []byte{0x01, 0x02, 0x03, 0x04}
		quote := createTestQuote(aikPrivKey, nonce, []PCRValue{
			{Index: 0, Value: make([]byte, 32), Algorithm: HashAlgorithmSHA256},
		})

		identity := &VMIdentity{
			VMID:          "vm-123",
			HostID:        "host-456",
			EKCertificate: ekCert,
		}

		request := &VerifyRequest{
			Quote:          quote,
			Identity:       identity,
			ExpectedNonce:  []byte{0x05, 0x06, 0x07, 0x08}, // Different nonce
			PlatformCACert: ca.cert,
		}

		result, err := verifier.VerifyQuote(ctx, request)
		if err != nil {
			t.Errorf("VerifyQuote() unexpected error: %v", err)
		}

		if result.Status != VerificationStatusFailed {
			t.Errorf("Expected failed status, got %s", result.Status)
		}
		if result.NonceValid {
			t.Error("Expected invalid nonce")
		}
	})

	t.Run("PCR mismatch", func(t *testing.T) {
		verifier := setupVerifier()

		aikPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		ekCert, _ := ca.issueEKCertificate("vm-123", "host-456", &aikPrivKey.PublicKey)

		nonce := []byte{0x01, 0x02, 0x03, 0x04}
		actualPCR := make([]byte, 32)
		actualPCR[0] = 0x01
		quote := createTestQuote(aikPrivKey, nonce, []PCRValue{
			{Index: 0, Value: actualPCR, Algorithm: HashAlgorithmSHA256},
		})

		identity := &VMIdentity{
			VMID:          "vm-123",
			HostID:        "host-456",
			EKCertificate: ekCert,
		}

		expectedPCR := make([]byte, 32)
		expectedPCR[0] = 0x02 // Different value
		request := &VerifyRequest{
			Quote:         quote,
			Identity:      identity,
			ExpectedNonce: nonce,
			ExpectedPCRs: map[int][]byte{
				0: expectedPCR,
			},
			PlatformCACert: ca.cert,
		}

		result, err := verifier.VerifyQuote(ctx, request)
		if err != nil {
			t.Errorf("VerifyQuote() unexpected error: %v", err)
		}

		if result.Status != VerificationStatusFailed {
			t.Errorf("Expected failed status, got %s", result.Status)
		}
		if result.PCRsValid {
			t.Error("Expected invalid PCRs")
		}
		if len(result.PCRMismatches) != 1 {
			t.Errorf("Expected 1 PCR mismatch, got %d", len(result.PCRMismatches))
		}
	})

	t.Run("invalid signature", func(t *testing.T) {
		verifier := setupVerifier()

		aikPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		ekCert, _ := ca.issueEKCertificate("vm-123", "host-456", &aikPrivKey.PublicKey)

		nonce := []byte{0x01, 0x02, 0x03, 0x04}
		quote := createTestQuote(aikPrivKey, nonce, []PCRValue{
			{Index: 0, Value: make([]byte, 32), Algorithm: HashAlgorithmSHA256},
		})
		// Corrupt signature
		quote.Signature[0] ^= 0xFF

		identity := &VMIdentity{
			VMID:          "vm-123",
			HostID:        "host-456",
			EKCertificate: ekCert,
		}

		request := &VerifyRequest{
			Quote:          quote,
			Identity:       identity,
			ExpectedNonce:  nonce,
			PlatformCACert: ca.cert,
		}

		result, err := verifier.VerifyQuote(ctx, request)
		if err != nil {
			t.Errorf("VerifyQuote() unexpected error: %v", err)
		}

		if result.Status != VerificationStatusFailed {
			t.Errorf("Expected failed status, got %s", result.Status)
		}
		if result.SignatureValid {
			t.Error("Expected invalid signature")
		}
	})

	// verifyDeclaredScheme verifies a quote the AIK signed with RSA-PSS after
	// declare rewrites the scheme the quote names.
	verifyDeclaredScheme := func(t *testing.T, declare func(*VMQuote)) *VerificationResult {
		t.Helper()
		verifier := setupVerifier()

		aikPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		ekCert, _ := ca.issueEKCertificate("vm-123", "host-456", &aikPrivKey.PublicKey)

		nonce := []byte{0x01, 0x02, 0x03, 0x04}
		quote := createTestQuote(aikPrivKey, nonce, nil)
		hashed := sha256.Sum256(quote.QuoteData)
		quote.Signature, err = rsa.SignPSS(rand.Reader, aikPrivKey, crypto.SHA256, hashed[:],
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		if err != nil {
			t.Fatalf("SignPSS: %v", err)
		}
		declare(quote)

		result, err := verifier.VerifyQuote(ctx, &VerifyRequest{
			Quote:          quote,
			Identity:       &VMIdentity{VMID: "vm-123", HostID: "host-456", EKCertificate: ekCert},
			ExpectedNonce:  nonce,
			PlatformCACert: ca.cert,
		})
		if err != nil {
			t.Fatalf("VerifyQuote() unexpected error: %v", err)
		}
		return result
	}

	t.Run("RSA-PSS quote verifies under its declared scheme", func(t *testing.T) {
		result := verifyDeclaredScheme(t, func(q *VMQuote) {
			q.SignatureAlgorithm = x509.SHA256WithRSAPSS.String()
		})
		if !result.SignatureValid || result.Status != VerificationStatusVerified {
			t.Errorf("Expected a verified PSS quote, got %s: %v", result.Status, result.Errors)
		}
	})

	t.Run("undeclared or mismatched scheme is refused", func(t *testing.T) {
		for name, scheme := range map[string]string{
			"undeclared": "",
			"PKCS#1 v1.5 declared for a PSS signature": x509.SHA256WithRSA.String(),
			"ECDSA declared for an RSA AIK":            x509.ECDSAWithSHA256.String(),
		} {
			t.Run(name, func(t *testing.T) {
				result := verifyDeclaredScheme(t, func(q *VMQuote) { q.SignatureAlgorithm = scheme })
				if result.SignatureValid || result.Status != VerificationStatusFailed {
					t.Errorf("Expected the signature refused, got %s", result.Status)
				}
			})
		}
	})

	t.Run("context canceled", func(t *testing.T) {
		verifier := setupVerifier()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		aikPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		nonce := []byte{0x01, 0x02}
		quote := createTestQuote(aikPrivKey, nonce, []PCRValue{
			{Index: 0, Value: make([]byte, 32), Algorithm: HashAlgorithmSHA256},
		})

		request := &VerifyRequest{
			Quote:          quote,
			Identity:       &VMIdentity{VMID: "vm", HostID: "host"},
			ExpectedNonce:  nonce,
			PlatformCACert: ca.cert,
		}

		_, err := verifier.VerifyQuote(ctx, request)
		if err == nil {
			t.Error("Expected error for canceled context")
		}
	})
}

func TestVMVerifier_VerifyAttestation(t *testing.T) {
	ctx := context.Background()
	ca := newTestCA()

	setupVerifier := func() VMVerifier {
		verifier := NewVMVerifier()

		config := &VerifierConfig{
			PlatformCACert:     ca.cert,
			MaxQuoteAge:        300,
			RequireHostBinding: false,
		}

		if err := verifier.Initialize(ctx, config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}
		return verifier
	}

	t.Run("successful attestation verification", func(t *testing.T) {
		verifier := setupVerifier()

		aikPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		ekCert, _ := ca.issueEKCertificate("vm-123", "host-456", &aikPrivKey.PublicKey)

		nonce := []byte{0x01, 0x02, 0x03, 0x04}
		pcrs := []PCRValue{
			{Index: 0, Value: make([]byte, 32), Algorithm: HashAlgorithmSHA256},
			{Index: 14, Value: make([]byte, 32), Algorithm: HashAlgorithmSHA256},
		}

		quote := createTestQuote(aikPrivKey, nonce, pcrs)

		identity := &VMIdentity{
			VMID:          "vm-123",
			HostID:        "host-456",
			EKCertificate: ekCert,
		}

		attestation := &VMAttestation{
			Identity:  identity,
			Quote:     quote,
			Timestamp: time.Now().UTC(),
		}

		expectedPCRs := map[int][]byte{
			0:  make([]byte, 32),
			14: make([]byte, 32),
		}

		result, err := verifier.VerifyAttestation(ctx, attestation, expectedPCRs, nonce)
		if err != nil {
			t.Errorf("VerifyAttestation() unexpected error: %v", err)
		}
		if result == nil {
			t.Error("Expected non-nil result")
			return
		}

		if result.Status != VerificationStatusVerified {
			t.Errorf("Expected verified status, got %s", result.Status)
		}

		// Check attestation was updated with result
		if attestation.VerificationResult == nil {
			t.Error("Expected attestation to be updated with verification result")
		}
		if !attestation.IsVerified() {
			t.Error("Expected attestation.IsVerified() to return true")
		}
	})

	t.Run("not initialized", func(t *testing.T) {
		verifier := NewVMVerifier()

		attestation := &VMAttestation{
			Identity: &VMIdentity{VMID: "vm", HostID: "host"},
			Quote: &VMQuote{
				QuoteData:     []byte{0x01},
				Signature:     []byte{0x02},
				PCRs:          []PCRValue{{Index: 0, Value: make([]byte, 32), Algorithm: HashAlgorithmSHA256}},
				Nonce:         []byte{0x03},
				HashAlgorithm: HashAlgorithmSHA256,
			},
		}

		_, err := verifier.VerifyAttestation(ctx, attestation, nil, []byte{0x03})
		if err == nil {
			t.Error("Expected error for not initialized")
		}
	})

	t.Run("nil attestation", func(t *testing.T) {
		verifier := setupVerifier()

		_, err := verifier.VerifyAttestation(ctx, nil, nil, []byte{0x01})
		if err == nil {
			t.Error("Expected error for nil attestation")
		}
	})

	t.Run("invalid attestation", func(t *testing.T) {
		verifier := setupVerifier()

		attestation := &VMAttestation{
			Identity: nil, // Invalid
			Quote: &VMQuote{
				QuoteData:     []byte{0x01},
				Signature:     []byte{0x02},
				PCRs:          []PCRValue{{Index: 0, Value: make([]byte, 32), Algorithm: HashAlgorithmSHA256}},
				Nonce:         []byte{0x03},
				HashAlgorithm: HashAlgorithmSHA256,
			},
		}

		_, err := verifier.VerifyAttestation(ctx, attestation, nil, []byte{0x03})
		if err == nil {
			t.Error("Expected error for invalid attestation")
		}
	})
}

func TestVMVerifier_VerifyEKCertificate(t *testing.T) {
	ctx := context.Background()
	ca := newTestCA()

	setupVerifier := func() VMVerifier {
		verifier := NewVMVerifier()

		config := &VerifierConfig{
			PlatformCACert:     ca.cert,
			RequireHostBinding: false,
		}

		if err := verifier.Initialize(ctx, config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}
		return verifier
	}

	t.Run("valid certificate", func(t *testing.T) {
		verifier := setupVerifier()

		privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		ekCert, _ := ca.issueEKCertificate("vm-123", "host-456", &privKey.PublicKey)

		identity := &VMIdentity{
			VMID:          "vm-123",
			HostID:        "host-456",
			EKCertificate: ekCert,
		}

		err := verifier.VerifyEKCertificate(ctx, identity)
		if err != nil {
			t.Errorf("VerifyEKCertificate() unexpected error: %v", err)
		}
	})

	t.Run("not initialized", func(t *testing.T) {
		verifier := NewVMVerifier()

		identity := &VMIdentity{
			VMID:   "vm-123",
			HostID: "host-456",
		}

		err := verifier.VerifyEKCertificate(ctx, identity)
		if err == nil {
			t.Error("Expected error for not initialized")
		}
	})

	t.Run("nil identity", func(t *testing.T) {
		verifier := setupVerifier()

		err := verifier.VerifyEKCertificate(ctx, nil)
		if err == nil {
			t.Error("Expected error for nil identity")
		}
	})

	t.Run("nil EK certificate", func(t *testing.T) {
		verifier := setupVerifier()

		identity := &VMIdentity{
			VMID:          "vm-123",
			HostID:        "host-456",
			EKCertificate: nil,
		}

		err := verifier.VerifyEKCertificate(ctx, identity)
		if err == nil {
			t.Error("Expected error for nil EK certificate")
		}
	})

	t.Run("certificate not signed by CA", func(t *testing.T) {
		verifier := setupVerifier()

		// Create self-signed certificate (not signed by CA)
		privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		template := x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "vm:vm-123@host:host-456"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Hour),
		}
		certBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
		cert, _ := x509.ParseCertificate(certBytes)

		identity := &VMIdentity{
			VMID:          "vm-123",
			HostID:        "host-456",
			EKCertificate: cert,
		}

		err := verifier.VerifyEKCertificate(ctx, identity)
		if err == nil {
			t.Error("Expected error for certificate not signed by CA")
		}
	})

	t.Run("identity mismatch", func(t *testing.T) {
		verifier := setupVerifier()

		privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		ekCert, _ := ca.issueEKCertificate("vm-different", "host-different", &privKey.PublicKey)

		identity := &VMIdentity{
			VMID:          "vm-123",
			HostID:        "host-456",
			EKCertificate: ekCert, // Certificate has different identity
		}

		err := verifier.VerifyEKCertificate(ctx, identity)
		if err == nil {
			t.Error("Expected error for identity mismatch")
		}
	})
}

func TestVMVerifier_HostBindingValidation(t *testing.T) {
	ctx := context.Background()
	ca := newTestCA()

	t.Run("allowed host", func(t *testing.T) {
		verifier := NewVMVerifier()

		config := &VerifierConfig{
			PlatformCACert:     ca.cert,
			RequireHostBinding: true,
			AllowedHostIDs:     []string{"host-allowed-1", "host-allowed-2"},
		}

		if err := verifier.Initialize(ctx, config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		aikPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		ekCert, _ := ca.issueEKCertificate("vm-123", "host-allowed-1", &aikPrivKey.PublicKey)

		identity := &VMIdentity{
			VMID:          "vm-123",
			HostID:        "host-allowed-1",
			EKCertificate: ekCert,
		}

		err := verifier.VerifyEKCertificate(ctx, identity)
		if err != nil {
			t.Errorf("VerifyEKCertificate() unexpected error: %v", err)
		}
	})

	t.Run("disallowed host", func(t *testing.T) {
		verifier := NewVMVerifier()

		config := &VerifierConfig{
			PlatformCACert:     ca.cert,
			RequireHostBinding: true,
			AllowedHostIDs:     []string{"host-allowed-1", "host-allowed-2"},
		}

		if err := verifier.Initialize(ctx, config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		aikPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		ekCert, _ := ca.issueEKCertificate("vm-123", "host-not-allowed", &aikPrivKey.PublicKey)

		identity := &VMIdentity{
			VMID:          "vm-123",
			HostID:        "host-not-allowed",
			EKCertificate: ekCert,
		}

		err := verifier.VerifyEKCertificate(ctx, identity)
		if err == nil {
			t.Error("Expected error for disallowed host")
		}
		var hostErr ErrHostBindingInvalid
		if !errors.As(err, &hostErr) {
			t.Errorf("Expected ErrHostBindingInvalid, got %T", err)
		}
	})
}

func TestVMVerifier_Close(t *testing.T) {
	ctx := context.Background()
	ca := newTestCA()

	t.Run("successful close", func(t *testing.T) {
		verifier := NewVMVerifier()

		config := &VerifierConfig{
			PlatformCACert: ca.cert,
		}

		if err := verifier.Initialize(ctx, config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		err := verifier.Close()
		if err != nil {
			t.Errorf("Close() unexpected error: %v", err)
		}
	})

	t.Run("double close", func(t *testing.T) {
		verifier := NewVMVerifier()

		config := &VerifierConfig{
			PlatformCACert: ca.cert,
		}

		if err := verifier.Initialize(ctx, config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		err := verifier.Close()
		if err != nil {
			t.Errorf("First Close() unexpected error: %v", err)
		}

		err = verifier.Close()
		if err != nil {
			t.Errorf("Second Close() unexpected error: %v", err)
		}
	})

	t.Run("operations after close", func(t *testing.T) {
		verifier := NewVMVerifier()

		config := &VerifierConfig{
			PlatformCACert: ca.cert,
		}

		if err := verifier.Initialize(ctx, config); err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}
		if err := verifier.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}

		identity := &VMIdentity{
			VMID:   "vm-123",
			HostID: "host-456",
		}

		err := verifier.VerifyEKCertificate(ctx, identity)
		if err == nil {
			t.Error("Expected error for operation after close")
		}
	})
}

func TestParsePublicKey(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pkixDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}

	tests := []struct {
		name string
		data []byte
	}{
		{name: "PKIX DER", data: pkixDER},
		{name: "PKIX PEM", data: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkixDER})},
		{name: "PKCS#1 DER", data: x509.MarshalPKCS1PublicKey(&privKey.PublicKey)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pubKey, err := parsePublicKey(tt.data)
			if err != nil {
				t.Fatalf("parsePublicKey() unexpected error: %v", err)
			}
			rsaKey, ok := pubKey.(*rsa.PublicKey)
			if !ok || !rsaKey.Equal(&privKey.PublicKey) {
				t.Errorf("parsePublicKey() = %T, want the generated RSA public key", pubKey)
			}
		})
	}

	refusals := []struct {
		name string
		data []byte
	}{
		{name: "garbage", data: []byte{0x00, 0x01, 0x02}},
		{name: "PEM with a non-key body", data: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{0x30, 0x00}})},
	}
	for _, tt := range refusals {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parsePublicKey(tt.data)
			var sigErr ErrSignatureInvalid
			if !errors.As(err, &sigErr) {
				t.Fatalf("want ErrSignatureInvalid, got %v", err)
			}
		})
	}
}

func TestParseEKCertificate(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "vm:vm-1@host:host-1"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	tests := []struct {
		name string
		data []byte
	}{
		{name: "DER", data: certDER},
		{name: "PEM", data: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := parseEKCertificate(tt.data)
			if err != nil {
				t.Fatalf("parseEKCertificate() unexpected error: %v", err)
			}
			if !bytes.Equal(cert.Raw, certDER) {
				t.Error("parseEKCertificate() returned a different certificate")
			}
		})
	}

	refusals := []struct {
		name string
		data []byte
	}{
		{name: "garbage", data: []byte{0x00, 0x01, 0x02}},
		{name: "PEM of another type", data: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: certDER})},
		{name: "PEM certificate with a corrupt body", data: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER[:len(certDER)/2]})},
	}
	for _, tt := range refusals {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseEKCertificate(tt.data)
			var ekErr ErrEKCertificateInvalid
			if !errors.As(err, &ekErr) {
				t.Fatalf("want ErrEKCertificateInvalid, got %v", err)
			}
			if ekErr.Cause == nil {
				t.Error("ErrEKCertificateInvalid should carry the x509 parse cause")
			}
		})
	}
}
