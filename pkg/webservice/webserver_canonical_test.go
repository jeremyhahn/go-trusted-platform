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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// mockCAForBundle is a minimal mock that only implements CABundle(), which is
// all the trust-bootstrap handler calls for an unfiltered fetch.
type mockCAForBundle struct {
	trustedca.CACertificateAuthority
	bundle []byte
}

func (m *mockCAForBundle) CABundle() ([]byte, error) { return m.bundle, nil }

// TestRegisterCanonicalRoutes_WiresServerCA verifies the web server mounts the
// trust-bootstrap fetch at the canonical host-root path, served by the CA the
// server itself was built with. This is the route
// `xkey trust import-platform <host:port>` fetches (issue #201): before this
// wiring the platform served the bundle only under /api/v1, and the request
// fell through to the SPA catch-all.
func TestRegisterCanonicalRoutes_WiresServerCA(t *testing.T) {
	pem := []byte("-----BEGIN CERTIFICATE-----\nSERVERCA\n-----END CERTIFICATE-----")
	logger := logging.NewLogger(slog.LevelDebug, io.Discard)

	server := &WebServerV1{
		logger:      logger,
		ca:          &mockCAForBundle{bundle: pem},
		router:      mux.NewRouter(),
		routerMutex: &sync.Mutex{},
	}

	router := mux.NewRouter()
	server.registerCanonicalRoutes(router, response.NewResponseWriter(logger, nil))

	req := httptest.NewRequest(http.MethodGet, "/v1/ca/bootstrap", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/pem-certificate-chain", w.Header().Get("Content-Type"))
	assert.Equal(t, string(pem), w.Body.String())
}
