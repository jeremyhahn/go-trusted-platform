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

package webservice

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCertificate creates a self-signed test certificate
func generateTestCertificate(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "test-cert",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, privateKey
}

func TestNewSigner(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	cert, _ := generateTestCertificate(t)

	t.Run("creates signer with all fields", func(t *testing.T) {
		signer := NewSigner(context.Background(), logger, nil, cert, "test-cn", []byte("password"))

		assert.NotNil(t, signer)
		assert.Equal(t, logger, signer.logger)
		assert.Nil(t, signer.ca) // CA is nil in this test
		assert.Equal(t, cert, signer.cert)
		assert.Equal(t, "test-cn", signer.cn)
		assert.Equal(t, []byte("password"), signer.password)
	})

	t.Run("creates signer with nil password", func(t *testing.T) {
		signer := NewSigner(context.Background(), logger, nil, cert, "test-cn", nil)

		assert.NotNil(t, signer)
		assert.Nil(t, signer.password)
	})

	t.Run("creates signer with empty cn", func(t *testing.T) {
		signer := NewSigner(context.Background(), logger, nil, cert, "", []byte("password"))

		assert.NotNil(t, signer)
		assert.Equal(t, "", signer.cn)
	})

	t.Run("creates signer with nil cert", func(t *testing.T) {
		signer := NewSigner(context.Background(), logger, nil, nil, "test-cn", nil)

		assert.NotNil(t, signer)
		assert.Nil(t, signer.cert)
	})
}

func TestSignerPublic(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	cert, _ := generateTestCertificate(t)

	t.Run("returns certificate public key", func(t *testing.T) {
		signer := NewSigner(context.Background(), logger, nil, cert, "test-cn", nil)

		publicKey := signer.Public()

		assert.NotNil(t, publicKey)
		assert.Equal(t, cert.PublicKey, publicKey)
	})

	t.Run("returns ECDSA public key type", func(t *testing.T) {
		signer := NewSigner(context.Background(), logger, nil, cert, "test-cn", nil)

		publicKey := signer.Public()

		_, ok := publicKey.(*ecdsa.PublicKey)
		assert.True(t, ok, "expected *ecdsa.PublicKey")
	})
}

func TestSignerImplementsCryptoSigner(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	cert, _ := generateTestCertificate(t)

	t.Run("implements crypto.Signer interface", func(t *testing.T) {
		signer := NewSigner(context.Background(), logger, nil, cert, "test-cn", nil)

		// Verify that Signer implements crypto.Signer
		var _ crypto.Signer = signer
	})
}

func TestSignerStruct(t *testing.T) {
	t.Run("struct fields are accessible", func(t *testing.T) {
		signer := &Signer{
			cn:       "test-cn",
			password: []byte("test-password"),
		}

		assert.Equal(t, "test-cn", signer.cn)
		assert.Equal(t, []byte("test-password"), signer.password)
	})

	t.Run("struct can be created with zero values", func(t *testing.T) {
		signer := &Signer{}

		assert.Empty(t, signer.cn)
		assert.Nil(t, signer.password)
		assert.Nil(t, signer.cert)
		assert.Nil(t, signer.ca)
		assert.Nil(t, signer.logger)
	})
}

func TestSignerPublic_DifferentKeyTypes(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)

	t.Run("ECDSA P-256 public key", func(t *testing.T) {
		cert, _ := generateTestCertificate(t)
		signer := NewSigner(context.Background(), logger, nil, cert, "test-cn", nil)

		publicKey := signer.Public()

		ecdsaPubKey, ok := publicKey.(*ecdsa.PublicKey)
		require.True(t, ok)
		assert.Equal(t, elliptic.P256(), ecdsaPubKey.Curve)
	})
}

func TestSignerFieldValues(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	cert, _ := generateTestCertificate(t)

	t.Run("password is stored correctly", func(t *testing.T) {
		password := []byte("secret-password-123")
		signer := NewSigner(context.Background(), logger, nil, cert, "test-cn", password)

		assert.Equal(t, password, signer.password)
	})

	t.Run("cn is stored correctly", func(t *testing.T) {
		cn := "unique-common-name.example.com"
		signer := NewSigner(context.Background(), logger, nil, cert, cn, nil)

		assert.Equal(t, cn, signer.cn)
	})

	t.Run("logger is stored correctly", func(t *testing.T) {
		signer := NewSigner(context.Background(), logger, nil, cert, "test-cn", nil)

		assert.Same(t, logger, signer.logger)
	})
}
