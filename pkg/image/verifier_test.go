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

package image

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCAAndCert generates a CA certificate and a signing certificate.
func generateTestCAAndCert(t *testing.T) (*x509.Certificate, *rsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	// Generate CA key
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caCertBytes)
	require.NoError(t, err)

	// Generate signing key
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signingTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "Test Signer",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	signingCertBytes, err := x509.CreateCertificate(rand.Reader, signingTemplate, caCert, &signingKey.PublicKey, caKey)
	require.NoError(t, err)

	signingCert, err := x509.ParseCertificate(signingCertBytes)
	require.NoError(t, err)

	return caCert, signingKey, signingCert
}

// generateExpiredCert generates an expired certificate for testing.
func generateExpiredCert(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Expired Cert",
		},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour), // Expired
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)

	return key, cert
}

func TestNewVerifier(t *testing.T) {
	tests := []struct {
		name      string
		opts      *VerifierOptions
		expectErr bool
	}{
		{
			name:      "nil options",
			opts:      nil,
			expectErr: true,
		},
		{
			name:      "empty options",
			opts:      &VerifierOptions{},
			expectErr: false,
		},
		{
			name: "with config",
			opts: &VerifierOptions{
				Config: &VerifierConfig{
					AllowExpired: true,
				},
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier, err := NewVerifier(tt.opts)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, verifier)
			}
		})
	}
}

func TestVerifier_VerifySignature_RSA(t *testing.T) {
	caCert, signingKey, signingCert := generateTestCAAndCert(t)

	// Create a signer
	signer, err := NewSigner(&SignerOptions{
		Config: &SignerConfig{
			PrivateKey:      signingKey,
			Certificate:     signingCert,
			HashAlgorithm:   crypto.SHA256,
			SignatureFormat: FormatCosign,
		},
	})
	require.NoError(t, err)

	// Sign a manifest
	manifest := []byte(`{"schemaVersion": 2}`)
	sig, err := signer.SignManifest(context.Background(), manifest, nil)
	require.NoError(t, err)

	// Create a verifier with the CA as trust anchor
	verifier, err := NewVerifier(&VerifierOptions{
		Config: &VerifierConfig{
			TrustAnchors: []*x509.Certificate{caCert},
		},
	})
	require.NoError(t, err)

	// Verify the signature
	result, err := verifier.VerifySignature(context.Background(), sig, nil)
	require.NoError(t, err)

	assert.True(t, result.Verified)
	assert.Equal(t, sig.ImageDigest, result.ImageDigest)
	assert.Contains(t, result.SignerIdentity, "Test Signer")
	assert.Equal(t, FormatCosign, result.SignatureFormat)
	assert.Equal(t, AlgorithmRSA256, result.SignatureAlgorithm)
	assert.NotEmpty(t, result.CertChain)
}

func TestVerifier_VerifySignature_ECDSA(t *testing.T) {
	// Generate ECDSA CA and signing cert
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ECDSA CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	caCertBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caCertBytes)
	require.NoError(t, err)

	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signingTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "ECDSA Signer"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}

	signingCertBytes, err := x509.CreateCertificate(rand.Reader, signingTemplate, caCert, &signingKey.PublicKey, caKey)
	require.NoError(t, err)
	signingCert, err := x509.ParseCertificate(signingCertBytes)
	require.NoError(t, err)

	// Create signer and verifier
	signer, err := NewSigner(&SignerOptions{
		Config: &SignerConfig{
			PrivateKey:  signingKey,
			Certificate: signingCert,
		},
	})
	require.NoError(t, err)

	manifest := []byte(`{"schemaVersion": 2}`)
	sig, err := signer.SignManifest(context.Background(), manifest, nil)
	require.NoError(t, err)

	verifier, err := NewVerifier(&VerifierOptions{
		Config: &VerifierConfig{
			TrustAnchors: []*x509.Certificate{caCert},
		},
	})
	require.NoError(t, err)

	result, err := verifier.VerifySignature(context.Background(), sig, nil)
	require.NoError(t, err)

	assert.True(t, result.Verified)
	assert.Equal(t, AlgorithmECDSA256, result.SignatureAlgorithm)
}

func TestVerifier_VerifySignature_NilSignature(t *testing.T) {
	verifier, err := NewVerifier(&VerifierOptions{})
	require.NoError(t, err)

	_, err = verifier.VerifySignature(context.Background(), nil, nil)
	assert.Error(t, err)
}

func TestVerifier_VerifySignature_NoCertificate(t *testing.T) {
	verifier, err := NewVerifier(&VerifierOptions{})
	require.NoError(t, err)

	sig := &ImageSignature{
		ImageDigest: "sha256:abc123",
		Signature:   []byte("signature"),
	}

	result, err := verifier.VerifySignature(context.Background(), sig, nil)
	assert.Error(t, err)
	assert.False(t, result.Verified)
}

func TestVerifier_VerifySignature_ExpiredCert(t *testing.T) {
	expiredKey, expiredCert := generateExpiredCert(t)

	// Create a self-signed signature with expired cert
	signer, err := NewSigner(&SignerOptions{
		Config: &SignerConfig{
			PrivateKey:  expiredKey,
			Certificate: expiredCert,
		},
	})
	require.NoError(t, err)

	manifest := []byte(`{"schemaVersion": 2}`)
	sig, err := signer.SignManifest(context.Background(), manifest, nil)
	require.NoError(t, err)

	// Try to verify without allowing expired
	verifier, err := NewVerifier(&VerifierOptions{
		Config: &VerifierConfig{
			TrustAnchors: []*x509.Certificate{expiredCert},
		},
	})
	require.NoError(t, err)

	result, err := verifier.VerifySignature(context.Background(), sig, nil)
	assert.Error(t, err)
	assert.False(t, result.Verified)
	assert.IsType(t, ErrCertificateExpired{}, err)
}

func TestVerifier_VerifySignature_AllowExpired(t *testing.T) {
	expiredKey, expiredCert := generateExpiredCert(t)

	signer, err := NewSigner(&SignerOptions{
		Config: &SignerConfig{
			PrivateKey:  expiredKey,
			Certificate: expiredCert,
		},
	})
	require.NoError(t, err)

	manifest := []byte(`{"schemaVersion": 2}`)
	sig, err := signer.SignManifest(context.Background(), manifest, nil)
	require.NoError(t, err)

	// Allow expired certificates
	verifier, err := NewVerifier(&VerifierOptions{
		Config: &VerifierConfig{
			TrustAnchors: []*x509.Certificate{expiredCert},
			AllowExpired: true,
		},
	})
	require.NoError(t, err)

	result, err := verifier.VerifySignature(context.Background(), sig, nil)
	require.NoError(t, err)
	assert.True(t, result.Verified)
}

func TestVerifier_VerifySignature_UntrustedSigner(t *testing.T) {
	// Create a signing cert
	rsaKey, rsaCert := generateTestRSAKeyPair(t)

	signer, err := NewSigner(&SignerOptions{
		Config: &SignerConfig{
			PrivateKey:  rsaKey,
			Certificate: rsaCert,
		},
	})
	require.NoError(t, err)

	manifest := []byte(`{"schemaVersion": 2}`)
	sig, err := signer.SignManifest(context.Background(), manifest, nil)
	require.NoError(t, err)

	// Create a different CA
	differentKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	differentCA := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "Different CA"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign,
		IsCA:         true,
	}

	differentCABytes, err := x509.CreateCertificate(rand.Reader, differentCA, differentCA, &differentKey.PublicKey, differentKey)
	require.NoError(t, err)
	differentCACert, err := x509.ParseCertificate(differentCABytes)
	require.NoError(t, err)

	// Verify with different CA - should fail
	verifier, err := NewVerifier(&VerifierOptions{
		Config: &VerifierConfig{
			TrustAnchors: []*x509.Certificate{differentCACert},
		},
	})
	require.NoError(t, err)

	result, err := verifier.VerifySignature(context.Background(), sig, nil)
	assert.Error(t, err)
	assert.False(t, result.Verified)
}

func TestVerifier_VerifySignature_WithAnnotations(t *testing.T) {
	caCert, signingKey, signingCert := generateTestCAAndCert(t)

	signer, err := NewSigner(&SignerOptions{
		Config: &SignerConfig{
			PrivateKey:  signingKey,
			Certificate: signingCert,
		},
	})
	require.NoError(t, err)

	manifest := []byte(`{"schemaVersion": 2}`)
	sig, err := signer.SignManifest(context.Background(), manifest, &SigningOptions{
		Annotations: map[string]string{
			"author":  "test",
			"version": "1.0.0",
		},
	})
	require.NoError(t, err)

	verifier, err := NewVerifier(&VerifierOptions{
		Config: &VerifierConfig{
			TrustAnchors: []*x509.Certificate{caCert},
		},
	})
	require.NoError(t, err)

	// Verify with matching annotations
	result, err := verifier.VerifySignature(context.Background(), sig, &VerificationOptions{
		VerifyAnnotations: map[string]string{
			"author": "test",
		},
	})
	require.NoError(t, err)
	assert.True(t, result.Verified)

	// Verify with mismatched annotations
	result, err = verifier.VerifySignature(context.Background(), sig, &VerificationOptions{
		VerifyAnnotations: map[string]string{
			"author": "wrong",
		},
	})
	assert.Error(t, err)
	assert.False(t, result.Verified)
}

func TestVerifier_VerifySignature_RequiredSignerIdentity(t *testing.T) {
	caCert, signingKey, signingCert := generateTestCAAndCert(t)

	signer, err := NewSigner(&SignerOptions{
		Config: &SignerConfig{
			PrivateKey:  signingKey,
			Certificate: signingCert,
		},
	})
	require.NoError(t, err)

	manifest := []byte(`{"schemaVersion": 2}`)
	sig, err := signer.SignManifest(context.Background(), manifest, nil)
	require.NoError(t, err)

	verifier, err := NewVerifier(&VerifierOptions{
		Config: &VerifierConfig{
			TrustAnchors: []*x509.Certificate{caCert},
		},
	})
	require.NoError(t, err)

	// Verify with matching identity
	result, err := verifier.VerifySignature(context.Background(), sig, &VerificationOptions{
		RequiredSignerIdentity: signingCert.Subject.String(),
	})
	require.NoError(t, err)
	assert.True(t, result.Verified)

	// Verify with wrong identity
	result, err = verifier.VerifySignature(context.Background(), sig, &VerificationOptions{
		RequiredSignerIdentity: "CN=Wrong Signer",
	})
	assert.Error(t, err)
	assert.False(t, result.Verified)
}

func TestVerifier_VerifyPayload(t *testing.T) {
	caCert, signingKey, signingCert := generateTestCAAndCert(t)

	// Create signature
	payload := []byte("test payload")
	digest := sha256.Sum256(payload)
	signature, err := rsa.SignPKCS1v15(rand.Reader, signingKey, crypto.SHA256, digest[:])
	require.NoError(t, err)

	verifier, err := NewVerifier(&VerifierOptions{
		Config: &VerifierConfig{
			TrustAnchors: []*x509.Certificate{caCert},
		},
	})
	require.NoError(t, err)

	result, err := verifier.VerifyPayload(context.Background(), payload, signature, signingCert, nil)
	require.NoError(t, err)
	assert.True(t, result.Verified)
}

func TestVerifier_VerifyPayload_NilParams(t *testing.T) {
	rsaKey, rsaCert := generateTestRSAKeyPair(t)

	verifier, err := NewVerifier(&VerifierOptions{
		Config: &VerifierConfig{
			TrustAnchors: []*x509.Certificate{rsaCert},
		},
	})
	require.NoError(t, err)

	// Nil payload
	_, err = verifier.VerifyPayload(context.Background(), nil, []byte("sig"), rsaCert, nil)
	assert.Error(t, err)

	// Empty payload
	_, err = verifier.VerifyPayload(context.Background(), []byte{}, []byte("sig"), rsaCert, nil)
	assert.Error(t, err)

	// Nil signature
	_, err = verifier.VerifyPayload(context.Background(), []byte("payload"), nil, rsaCert, nil)
	assert.Error(t, err)

	// Empty signature
	_, err = verifier.VerifyPayload(context.Background(), []byte("payload"), []byte{}, rsaCert, nil)
	assert.Error(t, err)

	// Nil cert
	payload := []byte("test payload")
	digest := sha256.Sum256(payload)
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest[:])
	require.NoError(t, err)
	_, err = verifier.VerifyPayload(context.Background(), payload, signature, nil, nil)
	assert.Error(t, err)
}

func TestVerifier_VerifyImage_NoRegistryClient(t *testing.T) {
	verifier, err := NewVerifier(&VerifierOptions{})
	require.NoError(t, err)

	ref := &ImageReference{
		Registry:   "docker.io",
		Repository: "library/nginx",
		Tag:        "latest",
	}

	_, err = verifier.VerifyImage(context.Background(), ref, nil)
	assert.Error(t, err)
}

func TestVerifier_VerifyImage_NilRef(t *testing.T) {
	verifier, err := NewVerifier(&VerifierOptions{})
	require.NoError(t, err)

	_, err = verifier.VerifyImage(context.Background(), nil, nil)
	assert.Error(t, err)
}

func TestVerifier_VerifyImage_InvalidRef(t *testing.T) {
	verifier, err := NewVerifier(&VerifierOptions{})
	require.NoError(t, err)

	ref := &ImageReference{
		Registry: "docker.io",
		// Empty repository
	}

	_, err = verifier.VerifyImage(context.Background(), ref, nil)
	assert.Error(t, err)
}

func TestParseTrustAnchorsFromPEM(t *testing.T) {
	_, cert1 := generateTestRSAKeyPair(t)
	_, cert2 := generateTestRSAKeyPair(t)

	pemData := encodeCertificateChainPEM([]*x509.Certificate{cert1, cert2})

	certs, err := ParseTrustAnchorsFromPEM(pemData)
	require.NoError(t, err)
	assert.Len(t, certs, 2)
}

func TestParseTrustAnchorsFromPEM_Empty(t *testing.T) {
	_, err := ParseTrustAnchorsFromPEM([]byte{})
	assert.Error(t, err)

	_, err = ParseTrustAnchorsFromPEM([]byte("not pem data"))
	assert.Error(t, err)
}

func TestDigestMatches(t *testing.T) {
	data := []byte("test data")
	digest := ComputeDigest(data, DigestSHA256)

	assert.True(t, DigestMatches(data, digest))
	assert.False(t, DigestMatches([]byte("different data"), digest))
	assert.False(t, DigestMatches(data, "invalid:digest"))
}

func TestComputeDigest(t *testing.T) {
	data := []byte("test data")

	sha256Digest := ComputeDigest(data, DigestSHA256)
	assert.True(t, isValidDigest(sha256Digest))
	assert.Contains(t, sha256Digest, "sha256:")

	sha384Digest := ComputeDigest(data, DigestSHA384)
	assert.True(t, isValidDigest(sha384Digest))
	assert.Contains(t, sha384Digest, "sha384:")

	sha512Digest := ComputeDigest(data, DigestSHA512)
	assert.True(t, isValidDigest(sha512Digest))
	assert.Contains(t, sha512Digest, "sha512:")
}

func TestComparesEqual(t *testing.T) {
	a := []byte("test")
	b := []byte("test")
	c := []byte("different")

	assert.True(t, ComparesEqual(a, b))
	assert.False(t, ComparesEqual(a, c))
	assert.True(t, ComparesEqual(nil, nil))
	assert.False(t, ComparesEqual(a, nil))
}

func TestVerifier_MergeOptions(t *testing.T) {
	caCert, _, _ := generateTestCAAndCert(t)

	verifier, err := NewVerifier(&VerifierOptions{
		Config: &VerifierConfig{
			TrustAnchors:     []*x509.Certificate{caCert},
			AllowExpired:     true,
			RequireTimestamp: true,
			CheckRevocation:  true,
		},
	})
	require.NoError(t, err)

	// Test with nil options
	merged := verifier.mergeOptions(nil)
	assert.NotNil(t, merged)
	assert.Equal(t, []*x509.Certificate{caCert}, merged.TrustAnchors)
	assert.True(t, merged.AllowExpired)
	assert.True(t, merged.RequireTimestamp)
	assert.True(t, merged.CheckRevocation)

	// Test with empty options
	merged = verifier.mergeOptions(&VerificationOptions{})
	assert.Equal(t, []*x509.Certificate{caCert}, merged.TrustAnchors)

	// Test with override
	differentCA, _, _ := generateTestCAAndCert(t)
	merged = verifier.mergeOptions(&VerificationOptions{
		TrustAnchors: []*x509.Certificate{differentCA},
	})
	assert.Equal(t, []*x509.Certificate{differentCA}, merged.TrustAnchors)
}

func TestVerifier_GetHasherForAlgorithm(t *testing.T) {
	verifier, err := NewVerifier(&VerifierOptions{})
	require.NoError(t, err)

	// Test all algorithms
	tests := []struct {
		algorithm SignatureAlgorithm
	}{
		{AlgorithmRSA256},
		{AlgorithmRSA384},
		{AlgorithmRSA512},
		{AlgorithmECDSA256},
		{AlgorithmECDSA384},
		{AlgorithmECDSA512},
		{"unknown"},
	}

	for _, tt := range tests {
		t.Run(string(tt.algorithm), func(t *testing.T) {
			hasher := verifier.getHasherForAlgorithm(tt.algorithm)
			assert.NotNil(t, hasher)
		})
	}
}

func TestVerifier_GetHashTypeForAlgorithm(t *testing.T) {
	verifier, err := NewVerifier(&VerifierOptions{})
	require.NoError(t, err)

	tests := []struct {
		algorithm SignatureAlgorithm
		expected  crypto.Hash
	}{
		{AlgorithmRSA256, crypto.SHA256},
		{AlgorithmRSA384, crypto.SHA384},
		{AlgorithmRSA512, crypto.SHA512},
		{AlgorithmECDSA256, crypto.SHA256},
		{AlgorithmECDSA384, crypto.SHA384},
		{AlgorithmECDSA512, crypto.SHA512},
		{"unknown", crypto.SHA256},
	}

	for _, tt := range tests {
		t.Run(string(tt.algorithm), func(t *testing.T) {
			hashType := verifier.getHashTypeForAlgorithm(tt.algorithm)
			assert.Equal(t, tt.expected, hashType)
		})
	}
}

func TestVerifier_DetermineAlgorithmFromCert(t *testing.T) {
	verifier, err := NewVerifier(&VerifierOptions{})
	require.NoError(t, err)

	// RSA cert
	_, rsaCert := generateTestRSAKeyPair(t)
	assert.Equal(t, AlgorithmRSA256, verifier.determineAlgorithmFromCert(rsaCert))

	// ECDSA cert
	_, ecdsaCert := generateTestECDSAKeyPair(t)
	assert.Equal(t, AlgorithmECDSA256, verifier.determineAlgorithmFromCert(ecdsaCert))
}

func TestNewVerifierFromFiles(t *testing.T) {
	// Create a temp file with a certificate
	_, cert := generateTestRSAKeyPair(t)
	pemData := encodeCertificatePEM(cert)

	tmpFile, err := os.CreateTemp("", "test-cert-*.pem")
	require.NoError(t, err)
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	_, err = tmpFile.Write(pemData)
	require.NoError(t, err)
	_ = tmpFile.Close()

	verifier, err := NewVerifierFromFiles(tmpFile.Name())
	require.NoError(t, err)
	assert.NotNil(t, verifier)
	assert.Len(t, verifier.config.TrustAnchors, 1)
}

func TestNewVerifierFromFiles_FileNotFound(t *testing.T) {
	_, err := NewVerifierFromFiles("/nonexistent/path/cert.pem")
	assert.Error(t, err)
	assert.IsType(t, ErrCertificateNotFound{}, err)
}

func TestNewVerifierFromFiles_InvalidCert(t *testing.T) {
	// Create a temp file with invalid data
	tmpFile, err := os.CreateTemp("", "invalid-cert-*.pem")
	require.NoError(t, err)
	t.Cleanup(func() {
		if rerr := os.Remove(tmpFile.Name()); rerr != nil {
			t.Logf("cleanup: %v", rerr)
		}
	})

	_, err = tmpFile.WriteString("not a valid certificate")
	require.NoError(t, err)
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("failed to close temp file: %v", err)
	}

	_, err = NewVerifierFromFiles(tmpFile.Name())
	assert.Error(t, err)
}

func TestDigestMatches_AllAlgorithms(t *testing.T) {
	data := []byte("test data for digest matching")

	// Test SHA-256
	sha256Digest := ComputeDigest(data, DigestSHA256)
	assert.True(t, DigestMatches(data, sha256Digest))

	// Test SHA-384
	sha384Digest := ComputeDigest(data, DigestSHA384)
	assert.True(t, DigestMatches(data, sha384Digest))

	// Test SHA-512
	sha512Digest := ComputeDigest(data, DigestSHA512)
	assert.True(t, DigestMatches(data, sha512Digest))

	// Test unknown algorithm
	assert.False(t, DigestMatches(data, "unknown:abc123"))
}

func TestVerifier_VerifySignature_WithTimestamp(t *testing.T) {
	caCert, signingKey, signingCert := generateTestCAAndCert(t)

	signer, err := NewSigner(&SignerOptions{
		Config: &SignerConfig{
			PrivateKey:  signingKey,
			Certificate: signingCert,
		},
	})
	require.NoError(t, err)

	manifest := []byte(`{"schemaVersion": 2}`)
	sig, err := signer.SignManifest(context.Background(), manifest, nil)
	require.NoError(t, err)

	// Add a mock timestamp token
	sig.TimestampToken = []byte{0x30, 0x00}

	verifier, err := NewVerifier(&VerifierOptions{
		Config: &VerifierConfig{
			TrustAnchors: []*x509.Certificate{caCert},
		},
	})
	require.NoError(t, err)

	result, err := verifier.VerifySignature(context.Background(), sig, nil)
	require.NoError(t, err)
	assert.True(t, result.Verified)
	assert.True(t, result.TimestampVerified)
}

func TestVerifier_VerifySignature_RequireTimestamp(t *testing.T) {
	caCert, signingKey, signingCert := generateTestCAAndCert(t)

	signer, err := NewSigner(&SignerOptions{
		Config: &SignerConfig{
			PrivateKey:  signingKey,
			Certificate: signingCert,
		},
	})
	require.NoError(t, err)

	manifest := []byte(`{"schemaVersion": 2}`)
	sig, err := signer.SignManifest(context.Background(), manifest, nil)
	require.NoError(t, err)

	// No timestamp token

	verifier, err := NewVerifier(&VerifierOptions{
		Config: &VerifierConfig{
			TrustAnchors: []*x509.Certificate{caCert},
		},
	})
	require.NoError(t, err)

	// Should fail when timestamp is required but not present
	result, err := verifier.VerifySignature(context.Background(), sig, &VerificationOptions{
		RequireTimestamp: true,
	})
	assert.Error(t, err)
	assert.False(t, result.Verified)
}

func TestVerifier_VerifySignature_MissingAnnotation(t *testing.T) {
	caCert, signingKey, signingCert := generateTestCAAndCert(t)

	signer, err := NewSigner(&SignerOptions{
		Config: &SignerConfig{
			PrivateKey:  signingKey,
			Certificate: signingCert,
		},
	})
	require.NoError(t, err)

	manifest := []byte(`{"schemaVersion": 2}`)
	sig, err := signer.SignManifest(context.Background(), manifest, nil)
	require.NoError(t, err)

	verifier, err := NewVerifier(&VerifierOptions{
		Config: &VerifierConfig{
			TrustAnchors: []*x509.Certificate{caCert},
		},
	})
	require.NoError(t, err)

	// Require an annotation that is not present
	result, err := verifier.VerifySignature(context.Background(), sig, &VerificationOptions{
		VerifyAnnotations: map[string]string{
			"required_key": "required_value",
		},
	})
	assert.Error(t, err)
	assert.False(t, result.Verified)
}

func TestVerifier_VerifySignature_FromPEM(t *testing.T) {
	caCert, signingKey, signingCert := generateTestCAAndCert(t)

	signer, err := NewSigner(&SignerOptions{
		Config: &SignerConfig{
			PrivateKey:  signingKey,
			Certificate: signingCert,
		},
	})
	require.NoError(t, err)

	manifest := []byte(`{"schemaVersion": 2}`)
	sig, err := signer.SignManifest(context.Background(), manifest, nil)
	require.NoError(t, err)

	// Clear the certificate and only use PEM
	sigWithPEM := &ImageSignature{
		ImageDigest:        sig.ImageDigest,
		SignerCertPEM:      sig.SignerCertPEM,
		Timestamp:          sig.Timestamp,
		Signature:          sig.Signature,
		SignatureFormat:    sig.SignatureFormat,
		SignatureAlgorithm: sig.SignatureAlgorithm,
		Payload:            sig.Payload,
		PayloadDigest:      sig.PayloadDigest,
	}

	verifier, err := NewVerifier(&VerifierOptions{
		Config: &VerifierConfig{
			TrustAnchors: []*x509.Certificate{caCert},
		},
	})
	require.NoError(t, err)

	result, err := verifier.VerifySignature(context.Background(), sigWithPEM, nil)
	require.NoError(t, err)
	assert.True(t, result.Verified)
}

func TestVerifier_VerifySignature_InvalidCertPEM(t *testing.T) {
	verifier, err := NewVerifier(&VerifierOptions{})
	require.NoError(t, err)

	sig := &ImageSignature{
		ImageDigest:   "sha256:abc123",
		SignerCertPEM: []byte("invalid pem data"),
		Signature:     []byte("signature"),
	}

	result, err := verifier.VerifySignature(context.Background(), sig, nil)
	assert.Error(t, err)
	assert.False(t, result.Verified)
}

func TestVerifier_VerifySignature_WithIntermediateCerts(t *testing.T) {
	caCert, signingKey, signingCert := generateTestCAAndCert(t)

	signer, err := NewSigner(&SignerOptions{
		Config: &SignerConfig{
			PrivateKey:  signingKey,
			Certificate: signingCert,
		},
	})
	require.NoError(t, err)

	manifest := []byte(`{"schemaVersion": 2}`)
	sig, err := signer.SignManifest(context.Background(), manifest, nil)
	require.NoError(t, err)

	// Create a verifier with intermediate certs configured
	verifier, err := NewVerifier(&VerifierOptions{
		Config: &VerifierConfig{
			TrustAnchors:      []*x509.Certificate{caCert},
			IntermediateCerts: []*x509.Certificate{},
		},
	})
	require.NoError(t, err)

	result, err := verifier.VerifySignature(context.Background(), sig, &VerificationOptions{
		IntermediateCerts: []*x509.Certificate{},
	})
	require.NoError(t, err)
	assert.True(t, result.Verified)
}

func TestVerifier_VerifyPayload_ECDSA(t *testing.T) {
	// Generate ECDSA CA and signing cert
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ECDSA CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	caCertBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caCertBytes)
	require.NoError(t, err)

	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signingTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "ECDSA Signer"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}

	signingCertBytes, err := x509.CreateCertificate(rand.Reader, signingTemplate, caCert, &signingKey.PublicKey, caKey)
	require.NoError(t, err)
	signingCert, err := x509.ParseCertificate(signingCertBytes)
	require.NoError(t, err)

	// Create signature
	payload := []byte("test payload for ECDSA")
	digest := sha256.Sum256(payload)
	signature, err := ecdsa.SignASN1(rand.Reader, signingKey, digest[:])
	require.NoError(t, err)

	verifier, err := NewVerifier(&VerifierOptions{
		Config: &VerifierConfig{
			TrustAnchors: []*x509.Certificate{caCert},
		},
	})
	require.NoError(t, err)

	result, err := verifier.VerifyPayload(context.Background(), payload, signature, signingCert, nil)
	require.NoError(t, err)
	assert.True(t, result.Verified)
}

func TestVerifier_VerifyImage_WithMockRegistry(t *testing.T) {
	caCert, signingKey, signingCert := generateTestCAAndCert(t)

	// Create a signature
	signer, err := NewSigner(&SignerOptions{
		Config: &SignerConfig{
			PrivateKey:  signingKey,
			Certificate: signingCert,
		},
	})
	require.NoError(t, err)

	manifest := []byte(`{"schemaVersion": 2}`)
	sig, err := signer.SignManifest(context.Background(), manifest, nil)
	require.NoError(t, err)

	// Mock server that returns the signature
	server, caPool := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.dev.cosign.simplesigning.v1+json")
		if err := json.NewEncoder(w).Encode(sig); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	defer server.Close()

	registryClient, err := NewRegistryClient(&RegistryOptions{
		CACertPool: caPool,
	})
	require.NoError(t, err)

	verifier, err := NewVerifier(&VerifierOptions{
		Config: &VerifierConfig{
			TrustAnchors: []*x509.Certificate{caCert},
		},
		RegistryClient: registryClient,
	})
	require.NoError(t, err)

	ref := &ImageReference{
		Registry:   server.Listener.Addr().String(),
		Repository: "myimage",
		Tag:        "latest",
	}

	result, err := verifier.VerifyImage(context.Background(), ref, nil)
	require.NoError(t, err)
	assert.True(t, result.Verified)
}

func TestVerifier_VerifyImage_SignatureNotFound(t *testing.T) {
	caCert, _, _ := generateTestCAAndCert(t)

	server, caPool := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	registryClient, err := NewRegistryClient(&RegistryOptions{
		CACertPool: caPool,
	})
	require.NoError(t, err)

	verifier, err := NewVerifier(&VerifierOptions{
		Config: &VerifierConfig{
			TrustAnchors: []*x509.Certificate{caCert},
		},
		RegistryClient: registryClient,
	})
	require.NoError(t, err)

	ref := &ImageReference{
		Registry:   server.Listener.Addr().String(),
		Repository: "myimage",
		Tag:        "latest",
	}

	_, err = verifier.VerifyImage(context.Background(), ref, nil)
	assert.Error(t, err)
	assert.IsType(t, ErrSignatureNotFound{}, err)
}

func TestVerifier_VerifyPayload_InvalidSignature(t *testing.T) {
	caCert, _, signingCert := generateTestCAAndCert(t)

	verifier, err := NewVerifier(&VerifierOptions{
		Config: &VerifierConfig{
			TrustAnchors: []*x509.Certificate{caCert},
		},
	})
	require.NoError(t, err)

	payload := []byte("test payload")
	invalidSignature := []byte("invalid signature")

	result, err := verifier.VerifyPayload(context.Background(), payload, invalidSignature, signingCert, nil)
	assert.Error(t, err)
	assert.False(t, result.Verified)
}

func TestVerifier_VerifySignatureBytes_ECDSAInvalidSignature(t *testing.T) {
	verifier, err := NewVerifier(&VerifierOptions{})
	require.NoError(t, err)

	_, ecdsaCert := generateTestECDSAKeyPair(t)

	// Invalid ECDSA signature should return error
	err = verifier.verifySignatureBytes([]byte("data"), []byte("bad sig"), ecdsaCert, AlgorithmECDSA256)
	assert.Error(t, err)
	assert.IsType(t, ErrInvalidSignature{}, err)
}

func TestVerifier_VerifyCertificateChain_NotYetValid(t *testing.T) {
	// Generate a cert that's not yet valid
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Future Cert",
		},
		NotBefore:             time.Now().Add(24 * time.Hour), // In the future
		NotAfter:              time.Now().Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)

	verifier, err := NewVerifier(&VerifierOptions{
		Config: &VerifierConfig{
			TrustAnchors: []*x509.Certificate{cert},
		},
	})
	require.NoError(t, err)

	err = verifier.verifyCertificateChain(cert, nil, &VerificationOptions{})
	assert.Error(t, err)
	assert.IsType(t, ErrCertificateExpired{}, err)
}

func TestVerifier_VerifyCertificateChain_WithVerificationTime(t *testing.T) {
	caCert, _, signingCert := generateTestCAAndCert(t)

	verifier, err := NewVerifier(&VerifierOptions{
		Config: &VerifierConfig{
			TrustAnchors: []*x509.Certificate{caCert},
		},
	})
	require.NoError(t, err)

	// Use a verification time in the past (within cert validity)
	pastTime := time.Now().Add(-30 * time.Minute)
	err = verifier.verifyCertificateChain(signingCert, nil, &VerificationOptions{
		VerificationTime: &pastTime,
	})
	require.NoError(t, err)
}

func TestVerifier_MergeOptions_IntermediateCerts(t *testing.T) {
	_, cert1 := generateTestRSAKeyPair(t)
	_, cert2 := generateTestRSAKeyPair(t)

	verifier, err := NewVerifier(&VerifierOptions{
		Config: &VerifierConfig{
			IntermediateCerts: []*x509.Certificate{cert1},
		},
	})
	require.NoError(t, err)

	// Should use config intermediates when options is empty
	merged := verifier.mergeOptions(&VerificationOptions{})
	assert.Equal(t, []*x509.Certificate{cert1}, merged.IntermediateCerts)

	// Should use options intermediates when provided
	merged = verifier.mergeOptions(&VerificationOptions{
		IntermediateCerts: []*x509.Certificate{cert2},
	})
	assert.Equal(t, []*x509.Certificate{cert2}, merged.IntermediateCerts)
}

func TestComputeDigest_DefaultAlgorithm(t *testing.T) {
	data := []byte("test data")

	// Empty algorithm should default to SHA256
	digest := ComputeDigest(data, "")
	assert.Contains(t, digest, "sha256:")
}

func TestParseTrustAnchorsFromPEM_SkipsNonCertBlocks(t *testing.T) {
	_, cert := generateTestRSAKeyPair(t)

	// Create PEM with mixed block types
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: []byte("key data"),
	})
	pemData = append(pemData, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})...)

	certs, err := ParseTrustAnchorsFromPEM(pemData)
	require.NoError(t, err)
	assert.Len(t, certs, 1)
}

func TestParseTrustAnchorsFromPEM_InvalidCertData(t *testing.T) {
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("invalid cert data"),
	})

	_, err := ParseTrustAnchorsFromPEM(pemData)
	assert.Error(t, err)
}
