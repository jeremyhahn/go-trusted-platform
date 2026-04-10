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
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// tlsTestServer creates an httptest TLS server and returns the server along
// with an x509.CertPool that trusts the server's certificate. This allows
// the RegistryClient (which always uses HTTPS with full certificate
// verification) to connect to the test server without InsecureSkipVerify.
func tlsTestServer(t *testing.T, handler http.Handler) (*httptest.Server, *x509.CertPool) {
	t.Helper()

	server := httptest.NewTLSServer(handler)

	// Extract the test server's CA certificate into a cert pool.
	// httptest.NewTLSServer uses a self-signed certificate from
	// net/http/internal/testcert, which is the leaf and root in one.
	certPool := x509.NewCertPool()
	for _, cert := range server.TLS.Certificates {
		for _, certDER := range cert.Certificate {
			parsed, err := x509.ParseCertificate(certDER)
			require.NoError(t, err)
			certPool.AddCert(parsed)
		}
	}

	return server, certPool
}
