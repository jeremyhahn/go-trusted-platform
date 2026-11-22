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

package iam

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"testing"
	"time"

	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// createTestLogger creates a logger for testing.
func createTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelDebug, nil)
}

// createTestCertificate creates a self-signed client certificate for testing.
func createTestCertificate(opts ...func(*x509.Certificate)) (*x509.Certificate, *rsa.PrivateKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         "Test User",
			Organization:       []string{"Test Org"},
			OrganizationalUnit: []string{"Test OU"},
		},
		EmailAddresses: []string{"test@example.com"},
		DNSNames:       []string{"example.com"},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	for _, opt := range opts {
		opt(template)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		panic(err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		panic(err)
	}

	return cert, privateKey
}

func TestGetSetSessionInContext(t *testing.T) {
	t.Parallel()
	t.Run("sets_and_gets_session_from_context", func(t *testing.T) {
		session := NewIAMSession(&sdkiam.User{
			ID:       "user-123",
			TenantID: "tenant-456",
		})

		ctx := context.Background()
		ctx = SetSessionInContext(ctx, session)

		retrieved, ok := GetSessionFromContext(ctx)

		if !ok {
			t.Error("expected session to be found in context")
		}
		if retrieved != session {
			t.Error("expected retrieved session to match original")
		}
	})

	t.Run("returns_false_when_session_not_in_context", func(t *testing.T) {
		ctx := context.Background()

		_, ok := GetSessionFromContext(ctx)

		if ok {
			t.Error("expected session not to be found in context")
		}
	})

	t.Run("returns_false_for_wrong_type_in_context", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), SessionContextKey, "not a session")

		_, ok := GetSessionFromContext(ctx)

		if ok {
			t.Error("expected session not to be found for wrong type")
		}
	})
}
