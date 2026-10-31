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
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance"
)

// testInstallerCert mints a client certificate signed the way the issuer
// signs a PXE installer leaf: the critical extended key usage extension
// carrying id-kp-clientAuth and tp-pxeInstaller.
func testInstallerCert(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey, cn string) *x509.Certificate {
	t.Helper()

	marker, err := issuance.InstallerMarkerExtension()
	require.NoError(t, err)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(3),
		Subject:         pkix.Name{CommonName: cn},
		NotBefore:       time.Now(),
		NotAfter:        time.Now().Add(24 * time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{marker},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	require.True(t, issuance.HasInstallerMarker(cert), "test certificate must carry the installer marker")
	return cert
}

// devicePaths are the machine-facing device routes the mTLS middleware guards.
var devicePaths = []struct {
	method string
	path   string
}{
	{http.MethodGet, "/device/profile"},
	{http.MethodPost, "/device/heartbeat"},
	{http.MethodPost, "/device/activate"},
}

func TestMTLSMiddleware_RefusesInstallerCertificate(t *testing.T) {
	caCert, caKey := testCertAuthority(t)
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	installer := testInstallerCert(t, caCert, caKey, "device-serial-123")

	for _, route := range devicePaths {
		t.Run(route.path, func(t *testing.T) {
			middleware := NewMTLSMiddleware(testLogger(), testResponseWriter(), roots)

			req := httptest.NewRequest(route.method, route.path, nil)
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{installer}}
			rec := httptest.NewRecorder()

			nextCalled := false
			middleware.Verify(rec, req, func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
			})

			assert.False(t, nextCalled, "an installer certificate must not reach the device handler")
			assert.Equal(t, http.StatusForbidden, rec.Code)
		})
	}
}

func TestMTLSMiddleware_AdmitsUnmarkedDeviceWithTheSameCN(t *testing.T) {
	caCert, caKey := testCertAuthority(t)
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	device := testClientCert(t, caCert, caKey, "device-serial-123", nil, "")

	for _, route := range devicePaths {
		t.Run(route.path, func(t *testing.T) {
			middleware := NewMTLSMiddleware(testLogger(), testResponseWriter(), roots)

			req := httptest.NewRequest(route.method, route.path, nil)
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{device}}
			rec := httptest.NewRecorder()

			var serial string
			middleware.Verify(rec, req, func(w http.ResponseWriter, r *http.Request) {
				serial, _ = r.Context().Value(ContextKeyDeviceSerial).(string)
			})

			assert.Equal(t, "device-serial-123", serial)
		})
	}
}

func TestErrInstallerNotDevice(t *testing.T) {
	err := error(ErrInstallerNotDevice{CommonName: "device-serial-123"})

	msg := err.Error()
	for _, want := range []string{`"device-serial-123"`, "tp-pxeInstaller", "not a device identity"} {
		assert.True(t, strings.Contains(msg, want), "Error() = %q, missing %q", msg, want)
	}

	assert.True(t, errors.Is(err, ErrInstallerNotDevice{}), "Is must match any Common Name")
	assert.False(t, errors.Is(err, ErrCertVerifyFailed), "must not match ErrCertVerifyFailed")
	assert.False(t, errors.Is(ErrNoDeviceSerial, ErrInstallerNotDevice{}), "ErrNoDeviceSerial must not match")
}
