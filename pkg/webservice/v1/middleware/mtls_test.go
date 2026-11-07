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

package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCertAuthority generates a self-signed CA certificate
// Indexes into testKeys, one per role in a certificate chain.
const (
	rootKeyIndex = iota
	intermediateKeyIndex
	leafKeyIndex
)

// testKeys generates one RSA key per chain role, once for the whole package:
// key generation dominated this package's test time, and no test needs a
// fresh key.
var testKeys = sync.OnceValues(func() ([]*rsa.PrivateKey, error) {
	keys := make([]*rsa.PrivateKey, leafKeyIndex+1)
	for i := range keys {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		keys[i] = key
	}
	return keys, nil
})

// testKey returns the shared key for a chain role.
func testKey(t *testing.T, index int) *rsa.PrivateKey {
	t.Helper()
	keys, err := testKeys()
	require.NoError(t, err)
	return keys[index]
}

func testCertAuthority(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	caKey := testKey(t, rootKeyIndex)

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	return caCert, caKey
}

// testClientCert generates a client certificate signed by the CA
func testClientCert(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey, cn string, dnsNames []string, serialNumber string) *x509.Certificate {
	t.Helper()

	clientKey := testKey(t, leafKeyIndex)

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   cn,
			SerialNumber: serialNumber,
		},
		DNSNames:    dnsNames,
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	require.NoError(t, err)

	clientCert, err := x509.ParseCertificate(clientCertDER)
	require.NoError(t, err)

	return clientCert
}

// testSelfSignedClientCert generates a self-signed client certificate (not signed by the CA)
func testSelfSignedClientCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	clientKey := testKey(t, leafKeyIndex)

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, clientTemplate, &clientKey.PublicKey, clientKey)
	require.NoError(t, err)

	clientCert, err := x509.ParseCertificate(clientCertDER)
	require.NoError(t, err)

	return clientCert
}

func testLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelDebug, io.Discard)
}

func testResponseWriter() response.HttpWriter {
	return response.NewResponseWriter(testLogger(), nil)
}

func TestNewMTLSMiddleware(t *testing.T) {
	t.Run("creates middleware with valid parameters", func(t *testing.T) {
		logger := testLogger()
		writer := testResponseWriter()
		roots := x509.NewCertPool()

		middleware := NewMTLSMiddleware(logger, writer, roots)

		assert.NotNil(t, middleware)
	})

	t.Run("creates middleware with nil trusted roots", func(t *testing.T) {
		logger := testLogger()
		writer := testResponseWriter()

		middleware := NewMTLSMiddleware(logger, writer, nil)

		assert.NotNil(t, middleware)
	})
}

func TestMTLSMiddleware_Verify(t *testing.T) {
	caCert, caKey := testCertAuthority(t)

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	t.Run("rejects request without TLS", func(t *testing.T) {
		logger := testLogger()
		writer := testResponseWriter()
		middleware := NewMTLSMiddleware(logger, writer, roots)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		// req.TLS is nil by default
		rec := httptest.NewRecorder()

		nextCalled := false
		next := func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		}

		middleware.Verify(rec, req, next)

		assert.False(t, nextCalled)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("rejects request without peer certificates", func(t *testing.T) {
		logger := testLogger()
		writer := testResponseWriter()
		middleware := NewMTLSMiddleware(logger, writer, roots)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{},
		}
		rec := httptest.NewRecorder()

		nextCalled := false
		next := func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		}

		middleware.Verify(rec, req, next)

		assert.False(t, nextCalled)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("rejects invalid client certificate", func(t *testing.T) {
		logger := testLogger()
		writer := testResponseWriter()
		middleware := NewMTLSMiddleware(logger, writer, roots)

		// Create a self-signed certificate not signed by the CA
		invalidCert := testSelfSignedClientCert(t, "invalid-client")

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{invalidCert},
		}
		rec := httptest.NewRecorder()

		nextCalled := false
		next := func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		}

		middleware.Verify(rec, req, next)

		assert.False(t, nextCalled)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("accepts valid client certificate with CN serial", func(t *testing.T) {
		logger := testLogger()
		writer := testResponseWriter()
		middleware := NewMTLSMiddleware(logger, writer, roots)

		clientCert := testClientCert(t, caCert, caKey, "device-serial-123", nil, "")

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{clientCert},
		}
		rec := httptest.NewRecorder()

		var capturedSerial string
		nextCalled := false
		next := func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			capturedSerial = r.Context().Value(ContextKeyDeviceSerial).(string)
		}

		middleware.Verify(rec, req, next)

		assert.True(t, nextCalled)
		assert.Equal(t, "device-serial-123", capturedSerial)
	})

	t.Run("accepts valid client certificate with DNS SAN serial", func(t *testing.T) {
		logger := testLogger()
		writer := testResponseWriter()
		middleware := NewMTLSMiddleware(logger, writer, roots)

		// Certificate with empty CN but DNS SAN
		clientCert := testClientCert(t, caCert, caKey, "", []string{"device-from-dns.local"}, "")

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{clientCert},
		}
		rec := httptest.NewRecorder()

		var capturedSerial string
		nextCalled := false
		next := func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			capturedSerial = r.Context().Value(ContextKeyDeviceSerial).(string)
		}

		middleware.Verify(rec, req, next)

		assert.True(t, nextCalled)
		assert.Equal(t, "device-from-dns.local", capturedSerial)
	})

	t.Run("accepts valid client certificate with subject serial number", func(t *testing.T) {
		logger := testLogger()
		writer := testResponseWriter()
		middleware := NewMTLSMiddleware(logger, writer, roots)

		// Certificate with empty CN, no DNS SAN, but subject serial number
		clientCert := testClientCert(t, caCert, caKey, "", nil, "SN12345678")

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{clientCert},
		}
		rec := httptest.NewRecorder()

		var capturedSerial string
		nextCalled := false
		next := func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			capturedSerial = r.Context().Value(ContextKeyDeviceSerial).(string)
		}

		middleware.Verify(rec, req, next)

		assert.True(t, nextCalled)
		assert.Equal(t, "SN12345678", capturedSerial)
	})

	t.Run("rejects certificate without serial identifier", func(t *testing.T) {
		logger := testLogger()
		writer := testResponseWriter()
		middleware := NewMTLSMiddleware(logger, writer, roots)

		// Certificate with empty CN, no DNS SANs, no serial number
		clientCert := testClientCert(t, caCert, caKey, "", nil, "")

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{clientCert},
		}
		rec := httptest.NewRecorder()

		nextCalled := false
		next := func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		}

		middleware.Verify(rec, req, next)

		assert.False(t, nextCalled)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("adds intermediate certificates to verification chain", func(t *testing.T) {
		logger := testLogger()
		writer := testResponseWriter()

		// Create root CA
		rootKey := testKey(t, rootKeyIndex)

		rootTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: "Root CA",
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}

		rootCertDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
		require.NoError(t, err)

		rootCert, err := x509.ParseCertificate(rootCertDER)
		require.NoError(t, err)

		// Create intermediate CA
		intermediateKey := testKey(t, intermediateKeyIndex)

		intermediateTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject: pkix.Name{
				CommonName: "Intermediate CA",
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}

		intermediateCertDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, rootCert, &intermediateKey.PublicKey, rootKey)
		require.NoError(t, err)

		intermediateCert, err := x509.ParseCertificate(intermediateCertDER)
		require.NoError(t, err)

		// Create client cert signed by intermediate
		clientKey := testKey(t, leafKeyIndex)

		clientTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(3),
			Subject: pkix.Name{
				CommonName: "device-with-chain",
			},
			NotBefore:   time.Now(),
			NotAfter:    time.Now().Add(24 * time.Hour),
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}

		clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, intermediateCert, &clientKey.PublicKey, intermediateKey)
		require.NoError(t, err)

		clientCert, err := x509.ParseCertificate(clientCertDER)
		require.NoError(t, err)

		// Only add root to trusted roots
		chainRoots := x509.NewCertPool()
		chainRoots.AddCert(rootCert)

		middleware := NewMTLSMiddleware(logger, writer, chainRoots)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{clientCert, intermediateCert},
		}
		rec := httptest.NewRecorder()

		var capturedSerial string
		nextCalled := false
		next := func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			capturedSerial = r.Context().Value(ContextKeyDeviceSerial).(string)
		}

		middleware.Verify(rec, req, next)

		assert.True(t, nextCalled)
		assert.Equal(t, "device-with-chain", capturedSerial)
	})
}

func TestExtractSerialFromCert(t *testing.T) {
	t.Run("extracts from Common Name first", func(t *testing.T) {
		cert := &x509.Certificate{
			Subject: pkix.Name{
				CommonName:   "device-cn",
				SerialNumber: "device-serial",
			},
			DNSNames: []string{"device-dns.local"},
		}

		result := DeviceSerialFromCert(cert)

		assert.Equal(t, "device-cn", result)
	})

	t.Run("extracts from DNS SAN when CN is empty", func(t *testing.T) {
		cert := &x509.Certificate{
			Subject: pkix.Name{
				CommonName:   "",
				SerialNumber: "device-serial",
			},
			DNSNames: []string{"device-dns.local", "device-dns2.local"},
		}

		result := DeviceSerialFromCert(cert)

		assert.Equal(t, "device-dns.local", result)
	})

	t.Run("extracts from Subject SerialNumber when CN and DNS are empty", func(t *testing.T) {
		cert := &x509.Certificate{
			Subject: pkix.Name{
				CommonName:   "",
				SerialNumber: "device-serial",
			},
			DNSNames: nil,
		}

		result := DeviceSerialFromCert(cert)

		assert.Equal(t, "device-serial", result)
	})

	t.Run("returns empty string when no identifiers", func(t *testing.T) {
		cert := &x509.Certificate{
			Subject: pkix.Name{
				CommonName:   "",
				SerialNumber: "",
			},
			DNSNames: nil,
		}

		result := DeviceSerialFromCert(cert)

		assert.Equal(t, "", result)
	})
}

func TestMTLSErrors(t *testing.T) {
	t.Run("ErrTLSRequired has correct message", func(t *testing.T) {
		assert.Equal(t, "TLS connection required", ErrTLSRequired.Error())
	})

	t.Run("ErrClientCertRequired has correct message", func(t *testing.T) {
		assert.Equal(t, "client certificate required", ErrClientCertRequired.Error())
	})

	t.Run("ErrCertVerifyFailed has correct message", func(t *testing.T) {
		assert.Equal(t, "client certificate verification failed", ErrCertVerifyFailed.Error())
	})

	t.Run("ErrNoDeviceSerial has correct message", func(t *testing.T) {
		assert.Equal(t, "no device serial in certificate", ErrNoDeviceSerial.Error())
	})
}
