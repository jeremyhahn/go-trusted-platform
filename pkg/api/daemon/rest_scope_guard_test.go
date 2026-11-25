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
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/gorilla/mux"
	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restiam "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/iam"
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

// certificateOperatorRole is the stored role of the testutil client
// certificate's IAM user in these tests.
const certificateOperatorRole = "operator"

// iamStoringOperator holds the testutil client certificate's user with
// certificateOperatorRole.
func iamStoringOperator() *storedUsersIAM {
	iam := iamStoringAnyUser()
	iam.users[0].Roles = []string{certificateOperatorRole}
	return iam
}

// pepGrantingRolePermissions is a PEP that allows a "resource:action" in
// permissions only when the Check carries role; it records each question as
// "subject resource:action".
func pepGrantingRolePermissions(role string, permissions []string, asked *[]string) *mockSDKPEPClient {
	return &mockSDKPEPClient{checkFunc: func(_ context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
		permission := req.Resource + ":" + req.Action
		*asked = append(*asked, req.Subject.ID+" "+permission)
		if !slices.Contains(permissions, permission) || !slices.Contains(req.Subject.Roles, role) {
			return &sdkiam.CheckResponse{Allowed: false}, nil
		}
		return &sdkiam.CheckResponse{Allowed: true}, nil
	}}
}

// pepGrantingRoleEverything is a PEP that allows every permission to a
// Check carrying role, and nothing to any other.
func pepGrantingRoleEverything(role string) *mockSDKPEPClient {
	return &mockSDKPEPClient{checkFunc: func(_ context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
		return &sdkiam.CheckResponse{Allowed: slices.Contains(req.Subject.Roles, role)}, nil
	}}
}

// Under mTLS the daemon REST listener admits its trusted client certificate
// on every VPN and NTP route the IAM PEP grants its stored user, and nothing
// else.
func TestNewRESTScopeGuard_MTLS_AdmitsTheOperatorCertificate(t *testing.T) {
	t.Parallel()
	trusted := testutil.GenerateTestTLSBundle(t)
	foreign := testutil.GenerateTestTLSBundle(t)
	config := failClosedConfig()
	config.EnableMTLS = true
	config.MTLSClientCAPool = trusted.CAPool

	var asked []string
	pep := pepGrantingRolePermissions(certificateOperatorRole, []string{"vpn:write", "vpn:read", "vpn:admin", "ntp:write"}, &asked)
	guard, err := newRESTScopeGuard(config, nil, pep, iamStoringOperator(), logging.DefaultLogger())
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
			"%s %s: the PEP grants the certificate's stored user the route", route[0], route[1])
	}
	assert.Contains(t, asked, "1001 ntp:write", "the PEP decides on the stored user ID")
	assert.Equal(t, http.StatusForbidden, serveWithChain(router, http.MethodGet, "/api/v1/ntp/status", operator),
		"ntp:read is not granted")

	assert.Equal(t, http.StatusUnauthorized,
		serveWithChain(router, http.MethodGet, "/api/v1/vpn/status", []*x509.Certificate{leafOf(t, foreign.ClientCert)}),
		"a certificate from another CA is not the operator")
	assert.Equal(t, http.StatusUnauthorized, serveWithChain(router, http.MethodGet, "/api/v1/vpn/status", nil))
}

// Under mTLS a certificate caller is refused when the PEP denies it, or when
// no PEP or no IAM client is wired; the guard is still built, so bearer
// tokens keep working.
func TestNewRESTScopeGuard_MTLS_RefusesTheCertificateWithoutAPEPGrant(t *testing.T) {
	t.Parallel()
	trusted := testutil.GenerateTestTLSBundle(t)
	config := failClosedConfig()
	config.EnableMTLS = true
	config.MTLSClientCAPool = trusted.CAPool
	operator := []*x509.Certificate{leafOf(t, trusted.ClientCert), trusted.CACert}

	var asked []string
	denying := pepGrantingRolePermissions(certificateOperatorRole, nil, &asked)
	granting := pepGrantingRolePermissions(certificateOperatorRole, []string{"ntp:write"}, &asked)
	cases := []struct {
		name string
		pep  quicbaassdk.IAMPEPClient
		iam  quicbaassdk.IAMClient
	}{
		{"the PEP denies", denying, iamStoringOperator()},
		{"the stored user lacks the role", granting, iamStoringAnyUser()},
		{"no PEP", nil, iamStoringOperator()},
		{"no IAM client", granting, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			guard, err := newRESTScopeGuard(config, nil, tc.pep, tc.iam, logging.DefaultLogger())
			require.NoError(t, err)
			require.NotNil(t, guard)
			assert.Equal(t, http.StatusForbidden, serveWithChain(guardedVPNRouter(guard), http.MethodPost, "/api/v1/ntp/step", operator))
		})
	}
}

// The daemon's IAM and device routers make their own per-route decision on
// the caller; a certificate caller there is decided by the IAM PEP too.
func TestNewRESTScopeGuard_MTLS_IAMAndDeviceRoutersAskThePEP(t *testing.T) {
	t.Parallel()
	trusted := testutil.GenerateTestTLSBundle(t)
	config := failClosedConfig()
	config.EnableMTLS = true
	config.MTLSClientCAPool = trusted.CAPool
	operator := []*x509.Certificate{leafOf(t, trusted.ClientCert), trusted.CACert}

	guardGranting := func(t *testing.T, permissions ...string) *restapi.ScopeGuard {
		t.Helper()
		var asked []string
		guard, err := newRESTScopeGuard(config, nil, pepGrantingRolePermissions(certificateOperatorRole, permissions, &asked), iamStoringOperator(), logging.DefaultLogger())
		require.NoError(t, err)
		return guard
	}

	t.Run("IAM router", func(t *testing.T) {
		serve := func(guard *restapi.ScopeGuard) int {
			iam := newMemIAM()
			s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
			require.NoError(t, s.SetIAMHandlers(logging.DefaultLogger(), restiam.NewQuicBaaSIAMAdapter(iam), restiam.NewQuicBaaSPEPAdapter(iam.PEP()), guard, iamRESTSystemTenant))
			// The flat users route names the caller's own tenant (the
			// certificate's "Test Platform Client"), so requireOwnTenant
			// admits it and the PEP alone decides.
			return serveWithChain(s.router, http.MethodGet, "/api/v1/iam/users?tenant_id=Test+Platform+Client", operator)
		}
		assert.Equal(t, http.StatusForbidden, serve(guardGranting(t)), "the PEP grants nothing")
		code := serve(guardGranting(t, iamScopeResource+":read"))
		assert.NotEqual(t, http.StatusForbidden, code, "the PEP grants iam:read")
		assert.NotEqual(t, http.StatusUnauthorized, code)
	})

	t.Run("device router", func(t *testing.T) {
		serve := func(guard *restapi.ScopeGuard) (int, int) {
			reached := 0
			authorizer := restScopeAuthorizer{guard: guard, respWriter: response.NewResponseWriter(logging.DefaultLogger(), nil)}
			handler := authorizer.RequireScope("device:write")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached++
				w.WriteHeader(http.StatusNoContent)
			}))
			router := guard.Authenticate(func(w http.ResponseWriter, r *http.Request, caller *platformtoken.AuthorizedContext) {
				handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), restCallerKey{}, caller)))
			})
			return serveWithChain(router, http.MethodPost, "/api/v1/devices/7/disable", operator), reached
		}
		code, reached := serve(guardGranting(t))
		assert.Equal(t, http.StatusForbidden, code, "the PEP grants nothing")
		assert.Zero(t, reached)
		code, reached = serve(guardGranting(t, "device:write"))
		assert.Equal(t, http.StatusNoContent, code, "the PEP grants device:write")
		assert.Equal(t, 1, reached)
	})
}

// Without mTLS there is no certificate verifier: a certificate is not a
// credential, and the guard still refuses rather than admitting.
func TestNewRESTScopeGuard_NoMTLS_RefusesCertificates(t *testing.T) {
	t.Parallel()
	bundle := testutil.GenerateTestTLSBundle(t)

	guard, err := newRESTScopeGuard(failClosedConfig(), nil, pepGrantingRoleEverything(certificateOperatorRole), iamStoringOperator(), logging.DefaultLogger())
	require.NoError(t, err)

	code := serveWithChain(guardedVPNRouter(guard), http.MethodGet, "/api/v1/ntp/status",
		[]*x509.Certificate{leafOf(t, bundle.ClientCert), bundle.CACert})
	assert.Equal(t, http.StatusUnauthorized, code)
}

func TestNewRESTScopeGuard_MTLSWithoutClientCAPool_ReturnsTypedError(t *testing.T) {
	t.Parallel()
	config := failClosedConfig()
	config.EnableMTLS = true

	guard, err := newRESTScopeGuard(config, nil, nil, nil, logging.DefaultLogger())
	require.Error(t, err)
	assert.Nil(t, guard)
	var want ErrTransportAuthRequired
	require.True(t, errors.As(err, &want), "error is %T, want ErrTransportAuthRequired", err)
	assert.Equal(t, transportREST, want.Transport)
}
