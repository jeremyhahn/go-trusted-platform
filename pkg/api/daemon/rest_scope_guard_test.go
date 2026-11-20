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

package daemon

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
)

// guardedVPNRouter mounts the VPN and NTP REST routes behind guard with no
// service, so a request the guard admits answers 503.
func guardedVPNRouter(guard *restapi.ScopeGuard) *mux.Router {
	router := mux.NewRouter()
	restapi.NewVPNHandlers(nil, guard, nil).RegisterRoutes(router)
	restapi.NewNTPHandlers(nil, guard, nil).RegisterRoutes(router)
	return router
}

// serveWithChain sends a request whose TLS handshake verified chain (none
// when chain is nil).
func serveWithChain(router http.Handler, method, target string, chain []*x509.Certificate) int {
	req := httptest.NewRequest(method, target, nil)
	if chain != nil {
		req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{chain}}
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder.Code
}

// Under mTLS the daemon REST listener admits its trusted client certificate
// as the operator on every VPN and NTP route, and nothing else.
func TestNewRESTScopeGuard_MTLS_AdmitsTheOperatorCertificate(t *testing.T) {
	t.Parallel()
	trusted := testutil.GenerateTestTLSBundle(t)
	foreign := testutil.GenerateTestTLSBundle(t)
	config := failClosedConfig()
	config.EnableMTLS = true
	config.MTLSPrincipals = operatorPrincipals()
	config.MTLSClientCAPool = trusted.CAPool

	guard, err := newRESTScopeGuard(config, nil, logging.DefaultLogger())
	require.NoError(t, err)
	router := guardedVPNRouter(guard)

	operator := []*x509.Certificate{leafOf(t, trusted.ClientCert), trusted.CACert}
	for _, route := range [][2]string{
		{http.MethodPost, "/api/v1/vpn/peers"},
		{http.MethodGet, "/api/v1/vpn/status"},
		{http.MethodPut, "/api/v1/vpn/posture-policies/corp"},
		{http.MethodPost, "/api/v1/ntp/step"},
	} {
		assert.Equal(t, http.StatusServiceUnavailable, serveWithChain(router, route[0], route[1], operator),
			"%s %s: the operator certificate holds every scope", route[0], route[1])
	}

	assert.Equal(t, http.StatusUnauthorized,
		serveWithChain(router, http.MethodGet, "/api/v1/vpn/status", []*x509.Certificate{leafOf(t, foreign.ClientCert)}),
		"a certificate from another CA is not the operator")
	assert.Equal(t, http.StatusUnauthorized, serveWithChain(router, http.MethodGet, "/api/v1/vpn/status", nil))
}

// Without mTLS there is no certificate verifier: a certificate is not a
// credential, and the guard still refuses rather than admitting.
func TestNewRESTScopeGuard_NoMTLS_RefusesCertificates(t *testing.T) {
	t.Parallel()
	bundle := testutil.GenerateTestTLSBundle(t)

	guard, err := newRESTScopeGuard(failClosedConfig(), nil, logging.DefaultLogger())
	require.NoError(t, err)

	code := serveWithChain(guardedVPNRouter(guard), http.MethodGet, "/api/v1/ntp/status",
		[]*x509.Certificate{leafOf(t, bundle.ClientCert), bundle.CACert})
	assert.Equal(t, http.StatusUnauthorized, code)
}

func TestNewRESTScopeGuard_MTLSWithoutClientCAPool_ReturnsTypedError(t *testing.T) {
	t.Parallel()
	config := failClosedConfig()
	config.EnableMTLS = true

	guard, err := newRESTScopeGuard(config, nil, logging.DefaultLogger())
	require.Error(t, err)
	assert.Nil(t, guard)
	var want ErrTransportAuthRequired
	require.True(t, errors.As(err, &want), "error is %T, want ErrTransportAuthRequired", err)
	assert.Equal(t, transportREST, want.Transport)
}
