// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// gatewaydSPIFFEID is gatewayd's service SPIFFE ID in trustDomain.
func gatewaydSPIFFEID(trustDomain string) *url.URL {
	return &url.URL{Scheme: "spiffe", Host: trustDomain, Path: "/tenant/" + app.SystemTenantID + "/svc/gatewayd"}
}

// issueGatewayd signs a certificate in gatewayd's node certificate shape: the
// gateway ID as CN, the system tenant as organization and gatewayd's service
// SPIFFE ID.
func (f *installerScopeFixture) issueGatewayd(t *testing.T, serial int64) *x509.Certificate {
	t.Helper()
	return f.issuerA.issueClient(t, serial,
		pkix.Name{CommonName: "gw-01", Organization: []string{app.SystemTenantID}},
		[]*url.URL{gatewaydSPIFFEID(testOperatorTrustDomain)})
}

// callUnary sends one unary call for method through the production gRPC
// interceptor as leaf and reports whether the handler ran.
func (f *installerScopeFixture) callUnary(t *testing.T, leaf *x509.Certificate, method string) (bool, error) {
	t.Helper()
	reached := false
	_, err := f.unary(t)(grpcContext(verifiedState(leaf)), struct{}{},
		&grpc.UnaryServerInfo{FullMethod: method},
		func(context.Context, interface{}) (interface{}, error) {
			reached = true
			return nil, nil
		})
	return reached, err
}

// The proxy sync methods gatewayd calls must pass the gRPC interceptor with
// its certificate (Codex 8537 P1-1).
func TestMTLSServicePrincipal_GatewaydReachesProxySync(t *testing.T) {
	f := newInstallerScopeFixture(t)
	gatewayd := f.issueGatewayd(t, 400)

	for _, method := range []string{
		platformv1.ProxyService_GetProxyConfig_FullMethodName,
		platformv1.ProxyService_GetZoneMatrix_FullMethodName,
	} {
		reached, err := f.callUnary(t, gatewayd, method)
		require.NoError(t, err, method)
		assert.True(t, reached, "gatewayd must reach %s", method)
	}
}

func TestMTLSServicePrincipal_GatewaydIsRefusedMethodsOutsideItsRole(t *testing.T) {
	f := newInstallerScopeFixture(t)
	gatewayd := f.issueGatewayd(t, 401)

	for _, method := range []string{
		platformv1.PXEService_UpdateState_FullMethodName,
		platformv1.ProxyService_ReloadProxyConfig_FullMethodName,
	} {
		reached, err := f.callUnary(t, gatewayd, method)
		assert.Equal(t, codes.PermissionDenied, status.Code(err), method)
		assert.Contains(t, status.Convert(err).Message(),
			ErrMTLSServiceMethodDenied{Service: "gatewayd", Method: method}.Error())
		assert.False(t, reached, "gatewayd must not reach %s", method)
	}
}

func TestMTLSServicePrincipal_GatewaydStreamOutsideItsRoleIsRefused(t *testing.T) {
	f := newInstallerScopeFixture(t)
	reached := false

	err := f.stream(t)(nil, &mockServerStream{ctx: grpcContext(verifiedState(f.issueGatewayd(t, 402)))},
		&grpc.StreamServerInfo{FullMethod: "/platform.v1.PlatformDaemon/StreamEvents"},
		func(interface{}, grpc.ServerStream) error {
			reached = true
			return nil
		})

	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.False(t, reached)
}

// An installer certificate keeps today's limits: the proxy sync methods are
// refused as installer methods.
func TestMTLSServicePrincipal_InstallerIsStillRefusedProxySync(t *testing.T) {
	f := newInstallerScopeFixture(t)

	for _, method := range []string{
		platformv1.ProxyService_GetProxyConfig_FullMethodName,
		platformv1.ProxyService_GetZoneMatrix_FullMethodName,
	} {
		reached, err := f.callUnary(t, f.installer, method)
		assert.Equal(t, codes.PermissionDenied, status.Code(err), method)
		assert.Contains(t, status.Convert(err).Message(), ErrMTLSInstallerMethodDenied{Method: method}.Error())
		assert.False(t, reached, "an installer must not reach %s", method)
	}
}

func TestMTLSServicePrincipal_Classification(t *testing.T) {
	f := newInstallerScopeFixture(t)
	td := testOperatorTrustDomain
	system := pkix.Name{CommonName: "gw-01", Organization: []string{app.SystemTenantID}}
	spiffeID := func(raw string) *url.URL {
		uri, err := url.Parse(raw)
		require.NoError(t, err)
		return uri
	}
	rows := []struct {
		name    string
		subject pkix.Name
		uris    []*url.URL
		td      string
		want    bool
	}{
		{"gatewayd", system, []*url.URL{gatewaydSPIFFEID(td)}, td, true},
		{"gatewayd, SPIFFE in caps", system, []*url.URL{spiffeID("SPIFFE://platform.test/tenant/system/svc/gatewayd")}, td, true},
		{"unknown service", system, []*url.URL{spiffeID("spiffe://platform.test/tenant/system/svc/other")}, td, false},
		{"other trust domain", system, []*url.URL{gatewaydSPIFFEID("other.test")}, td, false},
		{"tenant organization", pkix.Name{CommonName: "gw-01", Organization: []string{"acme"}}, []*url.URL{gatewaydSPIFFEID(td)}, td, false},
		{"two organizations", pkix.Name{CommonName: "gw-01", Organization: []string{app.SystemTenantID, "acme"}}, []*url.URL{gatewaydSPIFFEID(td)}, td, false},
		{"no URI SAN", system, nil, td, false},
		{"query", system, []*url.URL{spiffeID("spiffe://platform.test/tenant/system/svc/gatewayd?x=1")}, td, false},
		{"nested name", system, []*url.URL{spiffeID("spiffe://platform.test/tenant/system/svc/gatewayd/x")}, td, false},
		{"empty trust domain", system, []*url.URL{gatewaydSPIFFEID(td)}, "", false},
		{"no tenant segment", system, []*url.URL{spiffeID("spiffe://platform.test/service/gatewayd")}, td, false},
		{"other tenant's service", system, []*url.URL{spiffeID("spiffe://platform.test/tenant/acme/svc/gatewayd")}, td, false},
		{"other tenant's service, tenant organization", pkix.Name{CommonName: "gw-01", Organization: []string{"acme"}}, []*url.URL{spiffeID("spiffe://platform.test/tenant/acme/svc/gatewayd")}, td, false},
		{"empty name", system, []*url.URL{spiffeID("spiffe://platform.test/tenant/system/svc/")}, td, false},
	}
	for i, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			leaf := f.issuerA.issueClient(t, int64(410+i), row.subject, row.uris)
			service, ok := mtlsServicePrincipal(leaf, row.td)
			assert.Equal(t, row.want, ok)
			if row.want {
				assert.Equal(t, "gatewayd", service)
			}
			assert.False(t, isMTLSPrincipal(leaf, row.td), "a service principal gets no platform grant")
		})
	}
	t.Run("user kind", func(t *testing.T) {
		leaf := f.issuerA.issueClient(t, 440, system, []*url.URL{spiffeID("spiffe://platform.test/tenant/system/user/gatewayd")})
		_, ok := mtlsServicePrincipal(leaf, td)
		assert.False(t, ok)
	})
	t.Run("nil certificate", func(t *testing.T) {
		_, ok := mtlsServicePrincipal(nil, td)
		assert.False(t, ok)
	})
}

func TestMTLSServiceAdmitsMethod(t *testing.T) {
	assert.True(t, mtlsServiceAdmitsMethod("gatewayd", platformv1.ProxyService_GetZoneMatrix_FullMethodName))
	assert.False(t, mtlsServiceAdmitsMethod("gatewayd", platformv1.ProxyService_ReloadProxyConfig_FullMethodName))
	assert.False(t, mtlsServiceAdmitsMethod("gatewayd", "/platform.v1.Unknown/Method"))
	assert.False(t, mtlsServiceAdmitsMethod("other", platformv1.ProxyService_GetZoneMatrix_FullMethodName))
}
