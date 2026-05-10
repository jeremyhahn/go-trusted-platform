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

//go:build codec_msgpack

package daemon

import (
	"crypto/x509"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	pkgca "github.com/jeremyhahn/go-xkms/pkg/ca"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	goca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mock CA exposing the goca.CACertificateAuthority surface SetCAHandlers needs.
// =============================================================================

type fakeRESTCA struct {
	goca.CACertificateAuthority // embed for any methods we don't override
}

func (f *fakeRESTCA) Identity() string                                { return "Test CA" }
func (f *fakeRESTCA) IsInitialized() bool                             { return true }
func (f *fakeRESTCA) DefaultKeyAlgorithm() x509.PublicKeyAlgorithm    { return x509.ECDSA }
func (f *fakeRESTCA) DefaultValidityPeriod() int                      { return 365 }
func (f *fakeRESTCA) TrustedRoot() (*x509.Certificate, error)         { return nil, nil }
func (f *fakeRESTCA) TrustedIntermediate() (*x509.Certificate, error) { return nil, nil }
func (f *fakeRESTCA) IssueCertificate(req *goca.CACertificateRequest) (*pkgca.IssuedCertificate, error) {
	return nil, nil
}
func (f *fakeRESTCA) RevokeCert(*x509.Certificate, pkgca.RevokeOptions) error { return nil }
func (f *fakeRESTCA) CABundle() ([]byte, error)                               { return []byte{}, nil }
func (f *fakeRESTCA) CABundleFiltered(xkmssdk.StoreType, x509.PublicKeyAlgorithm) ([]byte, error) {
	return []byte{}, nil
}
func (f *fakeRESTCA) ParseBundle([]byte) ([]*x509.Certificate, error) { return nil, nil }
func (f *fakeRESTCA) CertStore() xkmssdk.CertStore                    { return nil }

// =============================================================================
// Tests
// =============================================================================

func TestRESTServer_SetCAHandlers_Nil(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()
	service, err := NewService(config)
	require.NoError(t, err)

	server, err := NewRESTServer(config, service, slog.Default())
	require.NoError(t, err)

	// Calling SetCAHandlers with nil should be a no-op (must not panic).
	server.SetCAHandlers(nil)

	// /api/v1/ca/info should NOT be registered when CA is nil.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/info", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code, "CA routes should not be registered when CA is nil")
}

func TestRESTServer_SetCAHandlers_RegistersRoutes(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()
	service, err := NewService(config)
	require.NoError(t, err)

	server, err := NewRESTServer(config, service, slog.Default())
	require.NoError(t, err)

	server.SetCAHandlers(&fakeRESTCA{})

	// /api/v1/ca/info should now be registered. The handler will respond
	// (status will be 200 because the fake CA reports IsInitialized=true).
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/info", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.NotEqual(t, http.StatusNotFound, w.Code, "CA routes should be registered after SetCAHandlers")
}

func TestRESTServer_SetCAHandlers_AllRoutesRegistered(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()
	service, err := NewService(config)
	require.NoError(t, err)

	server, err := NewRESTServer(config, service, slog.Default())
	require.NoError(t, err)

	server.SetCAHandlers(&fakeRESTCA{})

	// Walk the router and verify every CA route is present. We can't
	// distinguish handler-returned 404 from router 404 by status code, so
	// inspect the route table directly. Each route is identified by its
	// (method, path-template) tuple.
	expected := map[string]string{
		"GET /api/v1/ca/info":                                 "",
		"GET /api/v1/ca/certificates":                         "",
		"POST /api/v1/ca/certificates":                        "",
		"GET /api/v1/ca/certificates/{serial}":                "",
		"POST /api/v1/ca/certificates/{serial}/revoke":        "",
		"POST /api/v1/ca/certificates/{serial}/renew":         "",
		"POST /api/v1/ca/certificates/verify":                 "",
		"GET /api/v1/ca/crl":                                  "",
		"GET /api/v1/ca/bundle":                               "",
	}
	found := map[string]bool{}
	walkErr := server.router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		tmpl, _ := route.GetPathTemplate()
		methods, _ := route.GetMethods()
		for _, m := range methods {
			key := m + " " + tmpl
			if _, ok := expected[key]; ok {
				found[key] = true
			}
		}
		return nil
	})
	require.NoError(t, walkErr)

	for key := range expected {
		assert.Truef(t, found[key], "route %q must be registered", key)
	}
}
