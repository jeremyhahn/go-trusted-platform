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

package ca

import (
	"crypto/x509"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gorilla/mux"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// canonicalTestRouter mounts the canonical trust-bootstrap route on a bare
// ROOT router — no /api/v1 prefix — exactly as webserver_v1.buildRoutes does,
// and returns it alongside the PEM the mock CA will serve.
func canonicalTestRouter(t *testing.T) (*mux.Router, []byte) {
	t.Helper()

	pem := []byte("-----BEGIN CERTIFICATE-----\nCANONICAL\n-----END CERTIFICATE-----")
	mockCA := &mockCertificateAuthority{
		initialized: true,
		caBundleFn: func(_ xkmssdk.StoreType, _ x509.PublicKeyAlgorithm) ([]byte, error) {
			return pem, nil
		},
	}
	caRouter := NewCARouter(
		logging.NewLogger(slog.LevelDebug, os.Stdout), mockCA, &mockHttpWriter{})

	router := mux.NewRouter()
	caRouter.RegisterCanonicalRoutes(router)
	return router, pem
}

// TestRegisterCanonicalRoutes_ServesBundle pins the wire contract the go-xkms
// trust fetcher depends on: GET /v1/ca/bootstrap at the HOST ROOT returns the
// raw PEM bundle. `xkey trust import-platform <host:port>` fetches exactly
// this path, so the literal here is the contract, not a detail.
func TestRegisterCanonicalRoutes_ServesBundle(t *testing.T) {
	router, pem := canonicalTestRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/ca/bootstrap", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, contentTypePEM, rec.Header().Get("Content-Type"))
	assert.Equal(t, string(pem), rec.Body.String())
}

// TestRegisterCanonicalRoutes_PassesQueryFilters verifies the canonical path
// is the same handler as the prefixed one, filters included — the two paths
// must not drift into serving different bundles.
func TestRegisterCanonicalRoutes_PassesQueryFilters(t *testing.T) {
	var capturedStoreType xkmssdk.StoreType
	var capturedAlg x509.PublicKeyAlgorithm

	mockCA := &mockCertificateAuthority{
		initialized: true,
		caBundleFn: func(storeType xkmssdk.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) ([]byte, error) {
			capturedStoreType = storeType
			capturedAlg = keyAlgorithm
			return []byte("PEM"), nil
		},
	}
	caRouter := NewCARouter(
		logging.NewLogger(slog.LevelDebug, os.Stdout), mockCA, &mockHttpWriter{})
	router := mux.NewRouter()
	caRouter.RegisterCanonicalRoutes(router)

	req := httptest.NewRequest(http.MethodGet,
		"/v1/ca/bootstrap?store_type=software&algorithm=ECDSA", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, xkmssdk.StoreSoftware, capturedStoreType)
	assert.Equal(t, x509.ECDSA, capturedAlg)
}

// TestRegisterCanonicalRoutes_GETOnly verifies the canonical route accepts
// only GET; the bundle fetch is a read and nothing else may reach it here,
// since this route is mounted UNGATED at the host root.
func TestRegisterCanonicalRoutes_GETOnly(t *testing.T) {
	router, _ := canonicalTestRouter(t)

	for _, method := range []string{
		http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch,
	} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/v1/ca/bootstrap", nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
		})
	}
}

// TestRegisterCanonicalRoutes_OnlyBootstrap verifies the canonical mount
// publishes the trust-bootstrap fetch and nothing else. It is ungated, so an
// accidental addition here would publish a CA route to anonymous callers.
func TestRegisterCanonicalRoutes_OnlyBootstrap(t *testing.T) {
	router, _ := canonicalTestRouter(t)

	paths := map[string]bool{}
	require.NoError(t, router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		template, err := route.GetPathTemplate()
		if err != nil {
			return err
		}
		paths[template] = true
		return nil
	}))

	assert.Equal(t, map[string]bool{CanonicalBootstrapPath: true}, paths)
}

// TestRegisterPublicRoutes_KeepsPrefixedBootstrap verifies the canonical path
// is an ADDITION: the platform-prefixed /api/v1/ca/bootstrap that installers,
// the ISO test client and docs already use must keep working.
func TestRegisterPublicRoutes_KeepsPrefixedBootstrap(t *testing.T) {
	pem := []byte("-----BEGIN CERTIFICATE-----\nPREFIXED\n-----END CERTIFICATE-----")
	mockCA := &mockCertificateAuthority{
		initialized: true,
		caBundleFn: func(_ xkmssdk.StoreType, _ x509.PublicKeyAlgorithm) ([]byte, error) {
			return pem, nil
		},
	}
	caRouter := NewCARouter(
		logging.NewLogger(slog.LevelDebug, os.Stdout), mockCA, &mockHttpWriter{})

	router := mux.NewRouter()
	caRouter.RegisterPublicRoutes(router.PathPrefix("/api/v1").Subrouter())
	caRouter.RegisterCanonicalRoutes(router)

	for _, path := range []string{"/api/v1/ca/bootstrap", "/v1/ca/bootstrap"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			require.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, string(pem), rec.Body.String())
		})
	}
}
