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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestRSAKeyPair generates an RSA key pair for testing.
func generateTestRSAKeyPair(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cert := generateTestCertificate(t, &privateKey.PublicKey, privateKey)
	return privateKey, cert
}

// generateTestECDSAKeyPair generates an ECDSA key pair for testing.
func generateTestECDSAKeyPair(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cert := generateTestCertificate(t, &privateKey.PublicKey, privateKey)
	return privateKey, cert
}

// generateTestCertificate generates a self-signed certificate for testing.
func generateTestCertificate(t *testing.T, pubKey crypto.PublicKey, privKey crypto.PrivateKey) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
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

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)

	return cert
}

func TestNewSigner(t *testing.T) {
	rsaKey, rsaCert := generateTestRSAKeyPair(t)

	tests := []struct {
		name      string
		opts      *SignerOptions
		expectErr bool
		errType   error
	}{
		{
			name:      "nil options",
			opts:      nil,
			expectErr: true,
		},
		{
			name:      "nil config",
			opts:      &SignerOptions{},
			expectErr: true,
		},
		{
			name: "nil private key",
			opts: &SignerOptions{
				Config: &SignerConfig{
					Certificate: rsaCert,
				},
			},
			expectErr: true,
		},
		{
			name: "nil certificate",
			opts: &SignerOptions{
				Config: &SignerConfig{
					PrivateKey: rsaKey,
				},
			},
			expectErr: true,
		},
		{
			name: "valid RSA config",
			opts: &SignerOptions{
				Config: &SignerConfig{
					PrivateKey:  rsaKey,
					Certificate: rsaCert,
				},
			},
			expectErr: false,
		},
		{
			name: "valid config with all options",
			opts: &SignerOptions{
				Config: &SignerConfig{
					PrivateKey:      rsaKey,
					Certificate:     rsaCert,
					HashAlgorithm:   crypto.SHA256,
					SignatureFormat: FormatCosign,
				},
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := NewSigner(tt.opts)
			if tt.expectErr {
				assert.Error(t, err)
				assert.Nil(t, signer)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, signer)
			}
		})
	}
}

func TestNewSigner_ECDSA(t *testing.T) {
	ecKey, ecCert := generateTestECDSAKeyPair(t)

	signer, err := NewSigner(&SignerOptions{
		Config: &SignerConfig{
			PrivateKey:  ecKey,
			Certificate: ecCert,
		},
	})

	assert.NoError(t, err)
	assert.NotNil(t, signer)
}

func TestSigner_SignManifest_RSA(t *testing.T) {
	rsaKey, rsaCert := generateTestRSAKeyPair(t)

	signer, err := NewSigner(&SignerOptions{
		Config: &SignerConfig{
			PrivateKey:      rsaKey,
			Certificate:     rsaCert,
			HashAlgorithm:   crypto.SHA256,
			SignatureFormat: FormatCosign,
		},
	})
	require.NoError(t, err)

	manifest := []byte(`{"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json"}`)

	sig, err := signer.SignManifest(context.Background(), manifest, nil)
	require.NoError(t, err)

	assert.NotEmpty(t, sig.ImageDigest)
	assert.Equal(t, rsaCert, sig.SignerCert)
	assert.NotEmpty(t, sig.Signature)
	assert.Equal(t, FormatCosign, sig.SignatureFormat)
	assert.Equal(t, AlgorithmRSA256, sig.SignatureAlgorithm)
	assert.NotEmpty(t, sig.SignerCertPEM)
	assert.NotZero(t, sig.Timestamp)
}

func TestSigner_SignManifest_ECDSA(t *testing.T) {
	ecKey, ecCert := generateTestECDSAKeyPair(t)

	signer, err := NewSigner(&SignerOptions{
		Config: &SignerConfig{
			PrivateKey:      ecKey,
			Certificate:     ecCert,
			HashAlgorithm:   crypto.SHA256,
			SignatureFormat: FormatCosign,
		},
	})
	require.NoError(t, err)

	manifest := []byte(`{"schemaVersion": 2}`)

	sig, err := signer.SignManifest(context.Background(), manifest, nil)
	require.NoError(t, err)

	assert.NotEmpty(t, sig.ImageDigest)
	assert.Equal(t, ecCert, sig.SignerCert)
	assert.NotEmpty(t, sig.Signature)
	assert.Equal(t, AlgorithmECDSA256, sig.SignatureAlgorithm)
}

func TestSigner_SignManifest_WithAnnotations(t *testing.T) {
	rsaKey, rsaCert := generateTestRSAKeyPair(t)

	signer, err := NewSigner(&SignerOptions{
		Config: &SignerConfig{
			PrivateKey:  rsaKey,
			Certificate: rsaCert,
		},
	})
	require.NoError(t, err)

	manifest := []byte(`{"schemaVersion": 2}`)
	opts := &SigningOptions{
		Annotations: map[string]string{
			"author":  "test",
			"version": "1.0.0",
		},
	}

	sig, err := signer.SignManifest(context.Background(), manifest, opts)
	require.NoError(t, err)

	assert.Equal(t, "test", sig.Annotations["author"])
	assert.Equal(t, "1.0.0", sig.Annotations["version"])
}

func TestSigner_SignManifest_EmptyManifest(t *testing.T) {
	rsaKey, rsaCert := generateTestRSAKeyPair(t)

	signer, err := NewSigner(&SignerOptions{
		Config: &SignerConfig{
			PrivateKey:  rsaKey,
			Certificate: rsaCert,
		},
	})
	require.NoError(t, err)

	_, err = signer.SignManifest(context.Background(), nil, nil)
	assert.Error(t, err)

	_, err = signer.SignManifest(context.Background(), []byte{}, nil)
	assert.Error(t, err)
}

func TestSigner_SignPayload(t *testing.T) {
	rsaKey, rsaCert := generateTestRSAKeyPair(t)

	signer, err := NewSigner(&SignerOptions{
		Config: &SignerConfig{
			PrivateKey:  rsaKey,
			Certificate: rsaCert,
		},
	})
	require.NoError(t, err)

	payload := []byte("test payload data")

	signature, err := signer.SignPayload(context.Background(), payload, nil)
	require.NoError(t, err)

	assert.NotEmpty(t, signature)
}

func TestSigner_SignPayload_Empty(t *testing.T) {
	rsaKey, rsaCert := generateTestRSAKeyPair(t)

	signer, err := NewSigner(&SignerOptions{
		Config: &SignerConfig{
			PrivateKey:  rsaKey,
			Certificate: rsaCert,
		},
	})
	require.NoError(t, err)

	_, err = signer.SignPayload(context.Background(), nil, nil)
	assert.Error(t, err)

	_, err = signer.SignPayload(context.Background(), []byte{}, nil)
	assert.Error(t, err)
}

func TestSigner_SignImage_NoRegistryClient(t *testing.T) {
	rsaKey, rsaCert := generateTestRSAKeyPair(t)

	signer, err := NewSigner(&SignerOptions{
		Config: &SignerConfig{
			PrivateKey:  rsaKey,
			Certificate: rsaCert,
		},
	})
	require.NoError(t, err)

	ref := &ImageReference{
		Registry:   "docker.io",
		Repository: "library/nginx",
		Tag:        "latest",
	}

	_, err = signer.SignImage(context.Background(), ref, nil)
	assert.Error(t, err)
}

func TestSigner_SignImage_NilRef(t *testing.T) {
	rsaKey, rsaCert := generateTestRSAKeyPair(t)

	signer, err := NewSigner(&SignerOptions{
		Config: &SignerConfig{
			PrivateKey:  rsaKey,
			Certificate: rsaCert,
		},
	})
	require.NoError(t, err)

	_, err = signer.SignImage(context.Background(), nil, nil)
	assert.Error(t, err)
}

func TestSigner_SignImage_InvalidRef(t *testing.T) {
	rsaKey, rsaCert := generateTestRSAKeyPair(t)

	signer, err := NewSigner(&SignerOptions{
		Config: &SignerConfig{
			PrivateKey:  rsaKey,
			Certificate: rsaCert,
		},
	})
	require.NoError(t, err)

	ref := &ImageReference{
		// Empty repository is invalid
		Registry: "docker.io",
		Tag:      "latest",
	}

	_, err = signer.SignImage(context.Background(), ref, nil)
	assert.Error(t, err)
}

func TestSigner_DetermineAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		keyType  string
		hashAlgo crypto.Hash
		expected SignatureAlgorithm
	}{
		{"RSA SHA256", "RSA", crypto.SHA256, AlgorithmRSA256},
		{"RSA SHA384", "RSA", crypto.SHA384, AlgorithmRSA384},
		{"RSA SHA512", "RSA", crypto.SHA512, AlgorithmRSA512},
		{"ECDSA SHA256", "ECDSA", crypto.SHA256, AlgorithmECDSA256},
		{"ECDSA SHA384", "ECDSA", crypto.SHA384, AlgorithmECDSA384},
		{"ECDSA SHA512", "ECDSA", crypto.SHA512, AlgorithmECDSA512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var key crypto.PrivateKey
			var cert *x509.Certificate

			if tt.keyType == "RSA" {
				key, cert = generateTestRSAKeyPair(t)
			} else {
				key, cert = generateTestECDSAKeyPair(t)
			}

			signer, err := NewSigner(&SignerOptions{
				Config: &SignerConfig{
					PrivateKey:    key,
					Certificate:   cert,
					HashAlgorithm: tt.hashAlgo,
				},
			})
			require.NoError(t, err)

			assert.Equal(t, tt.expected, signer.determineAlgorithm())
		})
	}
}

func TestParsePrivateKey_RSA(t *testing.T) {
	rsaKey, _ := generateTestRSAKeyPair(t)

	// Encode as PKCS1
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
	})

	parsed, err := parsePrivateKey(keyPEM)
	require.NoError(t, err)
	assert.IsType(t, &rsa.PrivateKey{}, parsed)
}

func TestParsePrivateKey_ECDSA(t *testing.T) {
	ecKey, _ := generateTestECDSAKeyPair(t)

	// Encode as EC
	keyBytes, err := x509.MarshalECPrivateKey(ecKey)
	require.NoError(t, err)

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	parsed, err := parsePrivateKey(keyPEM)
	require.NoError(t, err)
	assert.IsType(t, &ecdsa.PrivateKey{}, parsed)
}

func TestParsePrivateKey_PKCS8(t *testing.T) {
	rsaKey, _ := generateTestRSAKeyPair(t)

	keyBytes, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	require.NoError(t, err)

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})

	parsed, err := parsePrivateKey(keyPEM)
	require.NoError(t, err)
	assert.IsType(t, &rsa.PrivateKey{}, parsed)
}

func TestParsePrivateKey_Invalid(t *testing.T) {
	// Not PEM data
	_, err := parsePrivateKey([]byte("not pem"))
	assert.Error(t, err)

	// Wrong PEM type
	invalidPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "UNKNOWN KEY TYPE",
		Bytes: []byte("invalid"),
	})
	_, err = parsePrivateKey(invalidPEM)
	assert.Error(t, err)
}

func TestParseCertificate(t *testing.T) {
	_, cert := generateTestRSAKeyPair(t)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	parsed, err := parseCertificate(certPEM)
	require.NoError(t, err)
	assert.Equal(t, cert.Subject.CommonName, parsed.Subject.CommonName)
}

func TestParseCertificate_Invalid(t *testing.T) {
	// Not PEM data
	_, err := parseCertificate([]byte("not pem"))
	assert.Error(t, err)

	// Invalid certificate data
	invalidPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("invalid"),
	})
	_, err = parseCertificate(invalidPEM)
	assert.Error(t, err)
}

func TestParseCertificateChain(t *testing.T) {
	_, cert1 := generateTestRSAKeyPair(t)
	_, cert2 := generateTestRSAKeyPair(t)

	chainPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert1.Raw,
	})
	chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert2.Raw,
	})...)

	chain, err := parseCertificateChain(chainPEM)
	require.NoError(t, err)
	assert.Len(t, chain, 2)
}

func TestParseCertificateChain_Empty(t *testing.T) {
	chain, err := parseCertificateChain([]byte(""))
	require.NoError(t, err)
	assert.Empty(t, chain)
}

func TestEncodeCertificatePEM(t *testing.T) {
	_, cert := generateTestRSAKeyPair(t)

	pem := encodeCertificatePEM(cert)
	assert.NotEmpty(t, pem)
	assert.Contains(t, string(pem), "BEGIN CERTIFICATE")
	assert.Contains(t, string(pem), "END CERTIFICATE")
}

func TestEncodeCertificateChainPEM(t *testing.T) {
	_, cert1 := generateTestRSAKeyPair(t)
	_, cert2 := generateTestRSAKeyPair(t)

	chain := []*x509.Certificate{cert1, cert2}
	pem := encodeCertificateChainPEM(chain)

	assert.NotEmpty(t, pem)
	// Should contain two certificate blocks
	assert.Contains(t, string(pem), "BEGIN CERTIFICATE")
}

func TestEncodeHex(t *testing.T) {
	data := []byte{0xab, 0xcd, 0xef, 0x12, 0x34}
	result := encodeHex(data)
	assert.Equal(t, "abcdef1234", result)
}

func TestEncodeDecodeSignatureBase64(t *testing.T) {
	original := []byte("test signature data")

	encoded := EncodeSignatureBase64(original)
	assert.NotEmpty(t, encoded)

	decoded, err := DecodeSignatureBase64(encoded)
	require.NoError(t, err)
	assert.Equal(t, original, decoded)
}

func TestDecodeSignatureBase64_Invalid(t *testing.T) {
	_, err := DecodeSignatureBase64("not valid base64!!!")
	assert.Error(t, err)
}

func TestSigner_CreatePayload(t *testing.T) {
	rsaKey, rsaCert := generateTestRSAKeyPair(t)

	signer, err := NewSigner(&SignerOptions{
		Config: &SignerConfig{
			PrivateKey:  rsaKey,
			Certificate: rsaCert,
		},
	})
	require.NoError(t, err)

	// Test without annotations
	payload := signer.createPayload("sha256:abc123", nil)
	assert.Equal(t, "atomic container signature", payload.Critical.Type)
	assert.Equal(t, "sha256:abc123", payload.Critical.Image.DockerReference)
	assert.Nil(t, payload.Optional)

	// Test with annotations
	opts := &SigningOptions{
		Annotations: map[string]string{
			"key": "value",
		},
	}
	payloadWithAnnotations := signer.createPayload("sha256:def456", opts)
	assert.NotNil(t, payloadWithAnnotations.Optional)
	assert.Equal(t, "value", payloadWithAnnotations.Optional["key"])
}

// New tests for improved coverage

func TestNewSignerFromFiles(t *testing.T) {
	// Create temp directory
	tempDir := t.TempDir()

	// Generate test key pair
	rsaKey, rsaCert := generateTestRSAKeyPair(t)

	// Write key file
	keyPath := filepath.Join(tempDir, "key.pem")
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
	})
	err := os.WriteFile(keyPath, keyPEM, 0600)
	require.NoError(t, err)

	// Write cert file
	certPath := filepath.Join(tempDir, "cert.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rsaCert.Raw,
	})
	err = os.WriteFile(certPath, certPEM, 0600)
	require.NoError(t, err)

	t.Run("valid key and cert files", func(t *testing.T) {
		signer, err := NewSignerFromFiles(keyPath, certPath, "")
		require.NoError(t, err)
		assert.NotNil(t, signer)
	})

	t.Run("with certificate chain", func(t *testing.T) {
		// Generate chain cert
		_, chainCert := generateTestRSAKeyPair(t)
		chainPath := filepath.Join(tempDir, "chain.pem")
		chainPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: chainCert.Raw,
		})
		err := os.WriteFile(chainPath, chainPEM, 0600)
		require.NoError(t, err)

		signer, err := NewSignerFromFiles(keyPath, certPath, chainPath)
		require.NoError(t, err)
		assert.NotNil(t, signer)
	})

	t.Run("key file not found", func(t *testing.T) {
		_, err := NewSignerFromFiles("/nonexistent/key.pem", certPath, "")
		assert.Error(t, err)
		assert.IsType(t, ErrKeyNotFound{}, err)
	})

	t.Run("cert file not found", func(t *testing.T) {
		_, err := NewSignerFromFiles(keyPath, "/nonexistent/cert.pem", "")
		assert.Error(t, err)
		assert.IsType(t, ErrCertificateNotFound{}, err)
	})

	t.Run("chain file not found", func(t *testing.T) {
		_, err := NewSignerFromFiles(keyPath, certPath, "/nonexistent/chain.pem")
		assert.Error(t, err)
		assert.IsType(t, ErrCertificateNotFound{}, err)
	})

	t.Run("invalid key file", func(t *testing.T) {
		badKeyPath := filepath.Join(tempDir, "bad_key.pem")
		err := os.WriteFile(badKeyPath, []byte("not a pem key"), 0600)
		require.NoError(t, err)

		_, err = NewSignerFromFiles(badKeyPath, certPath, "")
		assert.Error(t, err)
	})

	t.Run("invalid cert file", func(t *testing.T) {
		badCertPath := filepath.Join(tempDir, "bad_cert.pem")
		err := os.WriteFile(badCertPath, []byte("not a pem cert"), 0600)
		require.NoError(t, err)

		_, err = NewSignerFromFiles(keyPath, badCertPath, "")
		assert.Error(t, err)
	})

	t.Run("invalid chain file", func(t *testing.T) {
		badChainPath := filepath.Join(tempDir, "bad_chain.pem")
		// Write a non-certificate PEM block
		badPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: []byte("invalid cert data"),
		})
		err := os.WriteFile(badChainPath, badPEM, 0600)
		require.NoError(t, err)

		_, err = NewSignerFromFiles(keyPath, certPath, badChainPath)
		assert.Error(t, err)
	})
}

func TestSigner_SignImage_WithMockRegistry(t *testing.T) {
	manifest := `{"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json"}`

	server, caPool := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Docker-Content-Digest", "sha256:abc123def456")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(manifest)); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	defer server.Close()

	rsaKey, rsaCert := generateTestRSAKeyPair(t)

	registryClient, err := NewRegistryClient(&RegistryOptions{
		CACertPool: caPool,
	})
	require.NoError(t, err)

	signer, err := NewSigner(&SignerOptions{
		Config: &SignerConfig{
			PrivateKey:  rsaKey,
			Certificate: rsaCert,
		},
		RegistryClient: registryClient,
	})
	require.NoError(t, err)

	ref := &ImageReference{
		Registry:   server.Listener.Addr().String(),
		Repository: "myimage",
		Tag:        "latest",
	}

	sig, err := signer.SignImage(context.Background(), ref, nil)
	require.NoError(t, err)
	assert.NotNil(t, sig)
	assert.NotEmpty(t, sig.ImageDigest)
	assert.NotEmpty(t, sig.Signature)
}

func TestSigner_SignImage_RegistryError(t *testing.T) {
	server, caPool := tlsTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		if _, err := w.Write([]byte("internal server error")); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	defer server.Close()

	rsaKey, rsaCert := generateTestRSAKeyPair(t)

	registryClient, err := NewRegistryClient(&RegistryOptions{
		MaxRetries: 0, // No retries for faster test
		CACertPool: caPool,
	})
	require.NoError(t, err)

	signer, err := NewSigner(&SignerOptions{
		Config: &SignerConfig{
			PrivateKey:  rsaKey,
			Certificate: rsaCert,
		},
		RegistryClient: registryClient,
	})
	require.NoError(t, err)

	ref := &ImageReference{
		Registry:   server.Listener.Addr().String(),
		Repository: "myimage",
		Tag:        "latest",
	}

	_, err = signer.SignImage(context.Background(), ref, nil)
	assert.Error(t, err)
}

func TestSigner_SignManifest_WithCertChain(t *testing.T) {
	// Generate CA
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	caCertBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caCertBytes)
	require.NoError(t, err)

	// Generate signing key and cert
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signingTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Signing Cert"},
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

	signer, err := NewSigner(&SignerOptions{
		Config: &SignerConfig{
			PrivateKey:  signingKey,
			Certificate: signingCert,
			CertChain:   []*x509.Certificate{caCert},
		},
	})
	require.NoError(t, err)

	manifest := []byte(`{"schemaVersion": 2}`)
	sig, err := signer.SignManifest(context.Background(), manifest, nil)
	require.NoError(t, err)

	assert.NotEmpty(t, sig.CertChainPEM)
	assert.Len(t, sig.CertChain, 1)
}

func TestSigner_SignManifest_WithTimestampClient(t *testing.T) {
	rsaKey, rsaCert := generateTestRSAKeyPair(t)

	// Use no-op timestamp client for test
	tsClient := NewNoOpTimestampClient()

	signer, err := NewSigner(&SignerOptions{
		Config: &SignerConfig{
			PrivateKey:  rsaKey,
			Certificate: rsaCert,
		},
		TimestampClient: tsClient,
	})
	require.NoError(t, err)

	manifest := []byte(`{"schemaVersion": 2}`)
	sig, err := signer.SignManifest(context.Background(), manifest, nil)
	require.NoError(t, err)

	// No-op returns nil, so timestamp token should be empty
	assert.Empty(t, sig.TimestampToken)
}

func TestSigner_GetHasher_AllAlgorithms(t *testing.T) {
	rsaKey, rsaCert := generateTestRSAKeyPair(t)

	tests := []struct {
		name         string
		hashAlgo     crypto.Hash
		expectedSize int
	}{
		{"SHA256", crypto.SHA256, 32},
		{"SHA384", crypto.SHA384, 48},
		{"SHA512", crypto.SHA512, 64},
		{"Default (SHA1)", crypto.SHA1, 32}, // defaults to SHA256
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := NewSigner(&SignerOptions{
				Config: &SignerConfig{
					PrivateKey:    rsaKey,
					Certificate:   rsaCert,
					HashAlgorithm: tt.hashAlgo,
				},
			})
			require.NoError(t, err)

			hasher := signer.getHasher()
			assert.NotNil(t, hasher)
			hasher.Write([]byte("test"))
			sum := hasher.Sum(nil)
			assert.Equal(t, tt.expectedSize, len(sum))
		})
	}
}

func TestSigner_DetermineAlgorithm_UnknownKeyType(t *testing.T) {
	rsaKey, rsaCert := generateTestRSAKeyPair(t)

	signer, err := NewSigner(&SignerOptions{
		Config: &SignerConfig{
			PrivateKey:  rsaKey,
			Certificate: rsaCert,
		},
	})
	require.NoError(t, err)

	// Replace with unsupported key type
	signer.config.PrivateKey = "not a real key"

	algo := signer.determineAlgorithm()
	assert.Equal(t, SignatureAlgorithm(""), algo)
}

func TestSigner_SignData_UnsupportedKeyType(t *testing.T) {
	rsaKey, rsaCert := generateTestRSAKeyPair(t)

	signer, err := NewSigner(&SignerOptions{
		Config: &SignerConfig{
			PrivateKey:  rsaKey,
			Certificate: rsaCert,
		},
	})
	require.NoError(t, err)

	// Replace with unsupported key type
	signer.config.PrivateKey = "not a real key"

	_, err = signer.signData([]byte("test data"))
	assert.Error(t, err)
	assert.IsType(t, ErrInvalidKeyType{}, err)
}

func TestParseCertificateChain_SkipsNonCertBlocks(t *testing.T) {
	_, cert := generateTestRSAKeyPair(t)

	// Create PEM with mixed block types
	chainPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY", // Should be skipped
		Bytes: []byte("key data"),
	})
	chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})...)
	chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY", // Should be skipped
		Bytes: []byte("public key data"),
	})...)

	chain, err := parseCertificateChain(chainPEM)
	require.NoError(t, err)
	assert.Len(t, chain, 1)
}

func TestSignaturePayload_JSON_Marshaling(t *testing.T) {
	payload := &SignaturePayload{
		Critical: CriticalData{
			Type: "atomic container signature",
			Image: ImageIdentity{
				DockerReference: "sha256:abc123",
			},
			Identity: SignerIdentity{},
		},
		Optional: map[string]interface{}{
			"key1": "value1",
			"key2": 123,
		},
	}

	data, err := json.Marshal(payload)
	require.NoError(t, err)
	assert.Contains(t, string(data), "atomic container signature")
	assert.Contains(t, string(data), "sha256:abc123")

	var parsed SignaturePayload
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)
	assert.Equal(t, payload.Critical.Type, parsed.Critical.Type)
}

func TestSigner_SignPayload_ECDSA(t *testing.T) {
	ecKey, ecCert := generateTestECDSAKeyPair(t)

	signer, err := NewSigner(&SignerOptions{
		Config: &SignerConfig{
			PrivateKey:  ecKey,
			Certificate: ecCert,
		},
	})
	require.NoError(t, err)

	payload := []byte("test payload data for ECDSA")

	signature, err := signer.SignPayload(context.Background(), payload, nil)
	require.NoError(t, err)
	assert.NotEmpty(t, signature)
}

func TestParsePrivateKey_PKCS8_ECDSA(t *testing.T) {
	ecKey, _ := generateTestECDSAKeyPair(t)

	keyBytes, err := x509.MarshalPKCS8PrivateKey(ecKey)
	require.NoError(t, err)

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})

	parsed, err := parsePrivateKey(keyPEM)
	require.NoError(t, err)
	assert.IsType(t, &ecdsa.PrivateKey{}, parsed)
}
