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
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/pxe"
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
	trusted := newWebhookIssuer(t, "admin CA")
	foreign := testutil.GenerateTestTLSBundle(t)
	config := failClosedConfig()
	config.EnableMTLS = true
	config.MTLSClientCAPool = trusted.pool()
	config.MTLSOperatorTrustDomain = testOperatorTrustDomain

	guard, err := newRESTScopeGuard(config, nil, nil, logging.DefaultLogger())
	require.NoError(t, err)
	router := guardedVPNRouter(guard)

	operator := []*x509.Certificate{trusted.issueOperator(t, 100), trusted.cert}
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

// guardedCARouter serves the REST CA routes behind the guard newRESTScopeGuard
// builds, as rest_service.go registers them.
func guardedCARouter(t *testing.T, clientCAs *x509.CertPool, installs installCertificateBindings) *mux.Router {
	t.Helper()
	config := failClosedConfig()
	config.EnableMTLS = true
	config.MTLSClientCAPool = clientCAs
	guard, err := newRESTScopeGuard(config, nil, installs, logging.DefaultLogger())
	require.NoError(t, err)
	router := mux.NewRouter()
	restapi.NewCAHandlers(restapi.NewCAAuthorityAdapter(&configurableMockCA{}), nil, nil).
		WithScopeGuard(guard).RegisterRoutes(router)
	return router
}

// pxeBindingsFor binds leaf's SHA-256 as the install certificate of a device
// in installing, through the PXE store the PXE handlers use.
func pxeBindingsFor(leaf *x509.Certificate) pxeInstallBindings {
	store := newMockPXEService()
	store.devices["installer-node"] = &pxe.DeviceInfo{
		ID:                       "installer-node",
		State:                    pxe.StateInstalling,
		InstallCertificateSHA256: pxe.CertificateSHA256(leaf.Raw),
	}
	store.installerCerts[pxe.CertificateSHA256(leaf.Raw)] = struct{}{}
	service := NewPXEGRPCService(logging.DefaultLogger(), nil)
	service.SetPXEService(store)
	return pxeInstallBindings{service: service}
}

// The REST listener trusts the installer's certificate so the installer can
// report its result. That certificate holds only pxe:write: it is refused
// issuance and renewal through the production authenticator (Codex 8646).
func TestNewRESTScopeGuard_MTLS_InstallerCertificateReachesNoCAIssuance(t *testing.T) {
	t.Parallel()
	trusted := testutil.GenerateTestTLSBundle(t)
	installer := leafOf(t, trusted.ClientCert)
	router := guardedCARouter(t, trusted.CAPool, pxeBindingsFor(installer))
	chain := []*x509.Certificate{installer, trusted.CACert}

	assert.Equal(t, http.StatusForbidden, serveWithChain(router, http.MethodPost, "/api/v1/ca/certificates", chain),
		"an installer certificate holds no certs:generate")
	assert.Equal(t, http.StatusForbidden, serveWithChain(router, http.MethodPost, "/api/v1/ca/certificates/01/renew", chain),
		"renewal issues a certificate, so an installer certificate is refused it")
}

// A trusted certificate no installation binds is the operator's and still
// reaches CA issuance and renewal.
func TestNewRESTScopeGuard_MTLS_OperatorCertificateStillReachesCAIssuance(t *testing.T) {
	t.Parallel()
	trusted := testutil.GenerateTestTLSBundle(t)
	other := testutil.GenerateTestTLSBundle(t)
	router := guardedCARouter(t, trusted.CAPool, pxeBindingsFor(leafOf(t, other.ClientCert)))
	chain := []*x509.Certificate{leafOf(t, trusted.ClientCert), trusted.CACert}

	for _, target := range []string{"/api/v1/ca/certificates", "/api/v1/ca/certificates/01/renew"} {
		code := serveWithChain(router, http.MethodPost, target, chain)
		assert.NotEqual(t, http.StatusForbidden, code, "%s: the operator holds every scope", target)
		assert.NotEqual(t, http.StatusUnauthorized, code, "%s: the operator certificate authenticates", target)
	}
}

// A certificate whose install binding cannot be read is refused, never
// treated as the operator.
func TestNewRESTScopeGuard_MTLS_UnreadableInstallBindingIsRefused(t *testing.T) {
	t.Parallel()
	store := newMockPXEService()
	store.installerErr = errors.New("pxe store offline")
	service := NewPXEGRPCService(logging.DefaultLogger(), nil)
	service.SetPXEService(store)
	trusted := testutil.GenerateTestTLSBundle(t)
	router := guardedCARouter(t, trusted.CAPool, pxeInstallBindings{service: service})
	chain := []*x509.Certificate{leafOf(t, trusted.ClientCert), trusted.CACert}

	assert.Equal(t, http.StatusUnauthorized, serveWithChain(router, http.MethodPost, "/api/v1/ca/certificates", chain))
}

// Without mTLS there is no certificate verifier: a certificate is not a
// credential, and the guard still refuses rather than admitting.
func TestNewRESTScopeGuard_NoMTLS_RefusesCertificates(t *testing.T) {
	t.Parallel()
	bundle := testutil.GenerateTestTLSBundle(t)

	guard, err := newRESTScopeGuard(failClosedConfig(), nil, nil, logging.DefaultLogger())
	require.NoError(t, err)

	code := serveWithChain(guardedVPNRouter(guard), http.MethodGet, "/api/v1/ntp/status",
		[]*x509.Certificate{leafOf(t, bundle.ClientCert), bundle.CACert})
	assert.Equal(t, http.StatusUnauthorized, code)
}

func TestNewRESTScopeGuard_MTLSWithoutClientCAPool_ReturnsTypedError(t *testing.T) {
	t.Parallel()
	config := failClosedConfig()
	config.EnableMTLS = true

	guard, err := newRESTScopeGuard(config, nil, nil, logging.DefaultLogger())
	require.Error(t, err)
	assert.Nil(t, guard)
	var want ErrTransportAuthRequired
	require.True(t, errors.As(err, &want), "error is %T, want ErrTransportAuthRequired", err)
	assert.Equal(t, transportREST, want.Transport)
}
