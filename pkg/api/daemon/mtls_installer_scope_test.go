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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/auth"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/pxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// testOperatorTrustDomain is the SPIFFE trust domain the tests' daemon names
// its operator in.
const testOperatorTrustDomain = "platform.test"

// installerMAC is the device the installer certificate is bound to.
const installerMAC = "00:11:22:33:44:c3"

// operatorSPIFFEID is the platform admin's SPIFFE ID in trustDomain.
func operatorSPIFFEID(trustDomain string) *url.URL {
	return &url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
		Path:   "/tenant/" + app.SystemTenantID + "/user/" + common.AdminUsername,
	}
}

// nameOperator gives cert the subject organization and SPIFFE ID of the
// operator's admin certificate in trustDomain.
func nameOperator(cert *x509.Certificate, trustDomain string) {
	cert.Subject.Organization = []string{app.SystemTenantID}
	cert.URIs = []*url.URL{operatorSPIFFEID(trustDomain)}
}

// issueOperator signs the operator's admin certificate: the platform admin's
// SPIFFE ID in testOperatorTrustDomain and the system tenant as organization.
func (i *webhookIssuer) issueOperator(t *testing.T, serial int64) *x509.Certificate {
	t.Helper()
	return i.issueClient(t, serial,
		pkix.Name{CommonName: common.AdminUsername, Organization: []string{app.SystemTenantID}},
		[]*url.URL{operatorSPIFFEID(testOperatorTrustDomain)})
}

// issueClient issues a client certificate from issuer with subject and URI
// SANs.
func (i *webhookIssuer) issueClient(t *testing.T, serial int64, subject pkix.Name, uris []*url.URL) *x509.Certificate {
	t.Helper()
	return i.issueClientTLS(t, serial, subject, uris).Leaf
}

// issueClientTLS signs a client certificate and returns it with its key, as a
// TLS client presents it.
func (i *webhookIssuer) issueClientTLS(t *testing.T, serial int64, subject pkix.Name, uris []*url.URL) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      subject,
		URIs:         uris,
		NotBefore:    i.cert.NotBefore,
		NotAfter:     i.cert.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, i.cert, &key.PublicKey, i.key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}
}

// operatorTLSBundle is a test TLS bundle whose client certificate is the
// operator's admin certificate, issued by a second CA its pool also trusts:
// a daemon whose operator trust domain is testOperatorTrustDomain grants it
// every scope, as it does the admin bundle /init issues.
func operatorTLSBundle(t *testing.T) *testutil.TestTLSBundle {
	t.Helper()
	bundle := testutil.GenerateTestTLSBundle(t)
	issuer := newWebhookIssuer(t, "admin CA")
	bundle.CAPool.AddCert(issuer.cert)
	bundle.ClientCert = issuer.issueClientTLS(t, 100,
		pkix.Name{CommonName: common.AdminUsername, Organization: []string{app.SystemTenantID}},
		[]*url.URL{operatorSPIFFEID(testOperatorTrustDomain)})
	return bundle
}

func (i *webhookIssuer) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(i.cert)
	return pool
}

// installerScopeFixture is a PXE service with an operator certificate and an
// installer certificate bound to installerMAC, both issued by the CA the
// daemon's client CA pool trusts.
type installerScopeFixture struct {
	*webhookFixture
	operator  *x509.Certificate
	installer *x509.Certificate
	config    *Config
}

func newInstallerScopeFixture(t *testing.T) *installerScopeFixture {
	t.Helper()
	f := newWebhookFixture(t)
	operator := f.issuerA.issueOperator(t, 100)
	installer := f.issuerA.issueClient(t, 101,
		pkix.Name{CommonName: "installer", Organization: []string{"installer"}}, nil)
	f.install(t, installerMAC, installer)

	config := failClosedConfig()
	config.EnableMTLS = true
	config.MTLSClientCAPool = f.issuerA.pool()
	config.MTLSOperatorTrustDomain = testOperatorTrustDomain
	return &installerScopeFixture{webhookFixture: f, operator: operator, installer: installer, config: config}
}

func (f *installerScopeFixture) deviceID(t *testing.T, mac string) string {
	t.Helper()
	device, err := f.backend.GetDeviceByMAC(context.Background(), mac)
	require.NoError(t, err)
	return device.ID
}

// unary is the production gRPC mTLS interceptor over the fixture's client CA.
func (f *installerScopeFixture) unary(t *testing.T) grpc.UnaryServerInterceptor {
	t.Helper()
	adapter, err := auth.NewMTLSAdapterFromRoots(logging.DefaultLogger(), f.config.MTLSClientCAPool)
	require.NoError(t, err)
	return MTLSUnaryInterceptor(&MTLSInterceptorConfig{
		Authenticator:       adapter,
		Logger:              logging.DefaultLogger(),
		OperatorTrustDomain: f.config.MTLSOperatorTrustDomain,
	})
}

func (f *installerScopeFixture) stream(t *testing.T) grpc.StreamServerInterceptor {
	t.Helper()
	adapter, err := auth.NewMTLSAdapterFromRoots(logging.DefaultLogger(), f.config.MTLSClientCAPool)
	require.NoError(t, err)
	return MTLSStreamInterceptor(&MTLSInterceptorConfig{
		Authenticator:       adapter,
		Logger:              logging.DefaultLogger(),
		OperatorTrustDomain: f.config.MTLSOperatorTrustDomain,
	})
}

// updateState calls PXE UpdateState through the gRPC interceptor as leaf,
// moving the device at mac to FAILED. It reports whether the handler ran.
func (f *installerScopeFixture) updateState(t *testing.T, leaf *x509.Certificate, mac string) (bool, error) {
	t.Helper()
	req := &platformv1.UpdatePXEStateRequest{
		DeviceId: f.deviceID(t, mac),
		State:    platformv1.ProvisioningState_PROVISIONING_STATE_FAILED,
	}
	reached := false
	_, err := f.unary(t)(grpcContext(verifiedState(leaf)), req,
		&grpc.UnaryServerInfo{FullMethod: platformv1.PXEService_UpdateState_FullMethodName},
		func(ctx context.Context, req interface{}) (interface{}, error) {
			reached = true
			return f.svc.UpdateState(ctx, req.(*platformv1.UpdatePXEStateRequest))
		})
	return reached, err
}

func TestMTLSInstallerScope_OperatorReachesGRPCUpdateState(t *testing.T) {
	f := newInstallerScopeFixture(t)

	reached, err := f.updateState(t, f.operator, webhookOtherMAC)

	require.NoError(t, err)
	assert.True(t, reached)
	assert.Equal(t, pxe.StateFailed, f.state(t, webhookOtherMAC))
}

func TestMTLSInstallerScope_InstallerIsRefusedGRPCUpdateStateOfAnotherDevice(t *testing.T) {
	f := newInstallerScopeFixture(t)

	reached, err := f.updateState(t, f.installer, webhookOtherMAC)

	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), ErrMTLSInstallerMethodDenied{Method: platformv1.PXEService_UpdateState_FullMethodName}.Error())
	assert.False(t, reached, "the handler must not run for a refused installer")
	assert.Equal(t, pxe.StateInstalling, f.state(t, webhookOtherMAC))
}

func TestMTLSInstallerScope_InstallerIsRefusedGRPCStreams(t *testing.T) {
	f := newInstallerScopeFixture(t)
	reached := false

	err := f.stream(t)(nil, &mockServerStream{ctx: grpcContext(verifiedState(f.installer))},
		&grpc.StreamServerInfo{FullMethod: "/platform.v1.PlatformDaemon/StreamEvents"},
		func(interface{}, grpc.ServerStream) error {
			reached = true
			return nil
		})

	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.False(t, reached)
}

func TestMTLSInstallerScope_InstallerCompletesItsOwnDeviceThroughGRPCWebhook(t *testing.T) {
	f := newInstallerScopeFixture(t)
	req := &platformv1.PXEWebhookCompleteRequest{MacAddress: installerMAC, Success: true}

	_, err := f.unary(t)(grpcContext(verifiedState(f.installer)), req,
		&grpc.UnaryServerInfo{FullMethod: platformv1.PXEService_WebhookComplete_FullMethodName},
		func(ctx context.Context, req interface{}) (interface{}, error) {
			return f.svc.WebhookComplete(ctx, req.(*platformv1.PXEWebhookCompleteRequest))
		})

	require.NoError(t, err)
	assert.Equal(t, pxe.StateInstallComplete, f.state(t, installerMAC))
	assert.Equal(t, pxe.StateInstalling, f.state(t, webhookOtherMAC))
}

func TestMTLSInstallerScope_QUICGrantsOnlyTheOperator(t *testing.T) {
	f := newInstallerScopeFixture(t)
	mw, _, err := selectQUICAuth(f.config, nil, f.config.MTLSClientCAPool, logging.DefaultLogger())
	require.NoError(t, err)
	call := func(leaf *x509.Certificate) *quicwire.Response {
		_, resp := mw.GuardRequest(quicContext(verifiedState(leaf)), &quicwire.Request{Opcode: quicwire.OpKMSDeleteKey})
		return resp
	}

	assert.Nil(t, call(f.operator))
	resp := call(f.installer)
	require.NotNil(t, resp)
	assert.Equal(t, quicwire.StatusPermissionDenied, resp.Status)
}

func TestMTLSInstallerScope_RESTScopeGuardGrantsOnlyTheOperator(t *testing.T) {
	f := newInstallerScopeFixture(t)
	guard, err := newRESTScopeGuard(f.config, nil, logging.DefaultLogger())
	require.NoError(t, err)
	call := func(leaf *x509.Certificate) (int, bool) {
		reached := false
		handler := guard.Require("pxe:write", func(w http.ResponseWriter, _ *http.Request) {
			reached = true
			w.WriteHeader(http.StatusOK)
		})
		r := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/devices/x/state", nil)
		r.TLS = verifiedState(leaf)
		w := httptest.NewRecorder()
		handler(w, r)
		return w.Code, reached
	}

	code, reached := call(f.operator)
	assert.Equal(t, http.StatusOK, code)
	assert.True(t, reached)

	code, reached = call(f.installer)
	assert.Equal(t, http.StatusForbidden, code)
	assert.False(t, reached)
}

// An installer certificate must not issue or renew a certificate on the
// daemon's REST CA routes, registered as rest_service.go registers them
// (Codex 8238); the operator certificate passes the guard.
func TestMTLSInstallerScope_RESTCAIssueAndRenewRefuseTheInstaller(t *testing.T) {
	f := newInstallerScopeFixture(t)
	guard, err := newRESTScopeGuard(f.config, nil, logging.DefaultLogger())
	require.NoError(t, err)

	config := DefaultConfig()
	config.MTLSOperatorTrustDomain = testOperatorTrustDomain
	service, err := NewService(config)
	require.NoError(t, err)
	server, err := NewRESTServer(config, service, slog.Default())
	require.NoError(t, err)
	server.SetCAHandlers(&fakeRESTCA{}, guard)

	for _, path := range []string{"/api/v1/ca/certificates", "/api/v1/ca/certificates/0a1b/renew"} {
		call := func(leaf *x509.Certificate) int {
			r := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
			r.TLS = verifiedState(leaf)
			w := httptest.NewRecorder()
			server.router.ServeHTTP(w, r)
			return w.Code
		}

		assert.Equal(t, http.StatusForbidden, call(f.installer), "the installer must be refused POST %s", path)

		operator := call(f.operator)
		assert.NotEqual(t, http.StatusUnauthorized, operator, "the operator must pass the guard on POST %s", path)
		assert.NotEqual(t, http.StatusForbidden, operator, "the operator must pass the guard on POST %s", path)
	}
}

// boundaryKMS records the keys the REST KMS routes asked it to delete, so a
// test can prove a refused request never reached the key service.
type boundaryKMS struct {
	restapi.KMSService
	deleted []string
}

func (k *boundaryKMS) DeleteKey(_ context.Context, req *restapi.KMSDeleteKeyServiceRequest) (*restapi.KMSDeleteKeyServiceResponse, error) {
	k.deleted = append(k.deleted, req.KeyID)
	return &restapi.KMSDeleteKeyServiceResponse{KeyID: req.KeyID}, nil
}

// newInstallerBoundaryServer builds a REST server that knows the operator's
// trust domain, with one running managed service and a recording KMS.
func newInstallerBoundaryServer(t *testing.T, f *installerScopeFixture) (*RESTServer, *mockManagedService, *boundaryKMS) {
	t.Helper()
	config := DefaultConfig()
	config.MTLSOperatorTrustDomain = testOperatorTrustDomain
	service, err := NewService(config)
	require.NoError(t, err)
	managed := newMockService("boundary-svc")
	require.NoError(t, service.RegisterService(managed))
	server, err := NewRESTServer(config, service, slog.Default())
	require.NoError(t, err)
	kms := &boundaryKMS{}
	server.SetKMSHandlers(kms)
	server.SetCAHandlers(&fakeRESTCA{}, nil)

	start := serveAs(server, f.operator, http.MethodPost, "/api/v1/services/boundary-svc/start")
	require.Equal(t, http.StatusOK, start.Code, "the operator starts the service: %s", start.Body.String())
	return server, managed, kms
}

// serveAs sends one request through the REST router with leaf as the verified
// client certificate.
func serveAs(server *RESTServer, leaf *x509.Certificate, method, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader("{}"))
	r.TLS = verifiedState(leaf)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, r)
	return w
}

func TestMTLSInstallerScope_RESTPrivilegedRoutesRefuseTheInstaller(t *testing.T) {
	f := newInstallerScopeFixture(t)
	server, managed, kms := newInstallerBoundaryServer(t, f)

	stop := serveAs(server, f.installer, http.MethodPost, "/api/v1/services/boundary-svc/stop")
	assert.Equal(t, http.StatusForbidden, stop.Code, "the installer must not stop a service")
	assert.Zero(t, managed.stopCount.Load(), "a refused stop must leave the service running")

	del := serveAs(server, f.installer, http.MethodDelete, "/api/v1/kms/keys/k1")
	assert.Equal(t, http.StatusForbidden, del.Code, "the installer must not delete a key")
	assert.Empty(t, kms.deleted, "a refused delete must leave the key in place")
}

func TestMTLSInstallerScope_OperatorReachesRESTPrivilegedRoutes(t *testing.T) {
	f := newInstallerScopeFixture(t)
	server, managed, kms := newInstallerBoundaryServer(t, f)

	stop := serveAs(server, f.operator, http.MethodPost, "/api/v1/services/boundary-svc/stop")
	assert.Equal(t, http.StatusOK, stop.Code, "the operator stops the service: %s", stop.Body.String())
	assert.Equal(t, int32(1), managed.stopCount.Load())

	del := serveAs(server, f.operator, http.MethodDelete, "/api/v1/kms/keys/k1")
	assert.NotEqual(t, http.StatusForbidden, del.Code, "the operator deletes the key: %s", del.Body.String())
	assert.Equal(t, []string{"k1"}, kms.deleted)
}

func TestMTLSInstallerScope_RESTMachineFacingRoutesAdmitTheInstaller(t *testing.T) {
	f := newInstallerScopeFixture(t)
	server, _, _ := newInstallerBoundaryServer(t, f)

	for _, path := range []string{"/api/v1/health", "/api/v1/ca/info", "/api/v1/ca/crl", "/api/v1/ca/bundle"} {
		w, _ := serveRecovering(server, f.installer, http.MethodGet, path)
		refusal := ErrInstallerRouteForbidden{Method: http.MethodGet, Path: path}.Error()
		assert.NotContains(t, w.Body.String(), refusal, "the installer must reach GET %s", path)
	}
}

// routeVariable matches one gorilla/mux path variable, with or without a
// pattern, so a template can be turned into a concrete request path.
var routeVariable = regexp.MustCompile(`\{[^{}]*(\{[^{}]*\}[^{}]*)*\}`)

// TestMTLSInstallerScope_EveryRESTRouteIsAllowlistedOrRefused walks every
// route the daemon REST listener registers. A route that is not a named
// machine-facing route must refuse the installer, so a new route added
// without a decision fails here.
func TestMTLSInstallerScope_EveryRESTRouteIsAllowlistedOrRefused(t *testing.T) {
	f := newInstallerScopeFixture(t)
	server, _ := daemonRouteTable(t)
	cp, _ := newGatewayControlPlane(t)
	server.SetGatewayControlPlane(cp)
	routes := servedRoutes(t, server.Router())

	registered := make(map[string]bool, len(routes))
	for _, route := range routes {
		registered[route] = true
		method, template, _ := strings.Cut(route, " ")
		path := routeVariable.ReplaceAllString(template, "1")
		refusal := ErrInstallerRouteForbidden{Method: method, Path: path}.Error()

		w, reachedHandler := serveRecovering(server, f.installer, method, path)
		if installerMachineRoutes[route] {
			assert.NotContains(t, w.Body.String(), refusal, "machine-facing %s must admit the installer", route)
			continue
		}
		assert.False(t, reachedHandler, "%s reached its handler for the installer", route)
		assert.Equal(t, http.StatusForbidden, w.Code, "%s must refuse the installer", route)
		assert.Contains(t, w.Body.String(), refusal, "%s must refuse at the listener boundary", route)
	}
	for route := range installerMachineRoutes {
		assert.True(t, registered[route], "allowlisted %s is not a registered route", route)
	}
}

// serveRecovering is serveAs for route-table fakes whose handlers may panic on
// an unset dependency; a panic means the request got past the boundary.
// servedRoutes lists every "METHOD template" with a handler. Subrouter
// prefixes have none and answer 404 themselves, so they are left out.
func servedRoutes(t *testing.T, router *mux.Router) []string {
	t.Helper()
	var out []string
	err := router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		template, err := route.GetPathTemplate()
		if err != nil || route.GetHandler() == nil {
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil || len(methods) == 0 {
			methods = []string{http.MethodGet}
		}
		for _, method := range methods {
			out = append(out, method+" "+template)
		}
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, out)
	return out
}

func serveRecovering(server *RESTServer, leaf *x509.Certificate, method, path string) (w *httptest.ResponseRecorder, reachedHandler bool) {
	w = httptest.NewRecorder()
	defer func() {
		if recover() != nil {
			reachedHandler = true
		}
	}()
	r := httptest.NewRequest(method, path, strings.NewReader("{}"))
	r.TLS = verifiedState(leaf)
	server.router.ServeHTTP(w, r)
	return w, false
}

func TestMTLSInstallerScope_MCPGrantsOnlyTheOperator(t *testing.T) {
	f := newInstallerScopeFixture(t)
	peers, err := newMCPPeerAuthenticator(f.config, logging.DefaultLogger())
	require.NoError(t, err)
	checker := mcp.NewAuthorizationChecker(nil, nil, mcp.WithPeerAuthenticator(peers))
	call := func(leaf *x509.Certificate) *mcp.AuthorizationError {
		_, authErr := checker.AuthorizeTool(mcpContext(verifiedState(leaf)), "pxe_update_state", "")
		return authErr
	}

	assert.Nil(t, call(f.operator))
	authErr := call(f.installer)
	require.NotNil(t, authErr)
	assert.Equal(t, mcp.AuthErrorPermissionDenied, authErr.Type)
}

// completeInstall runs the PXE WebhookComplete servicer for installerMAC in
// the context a transport guard admitted, as that transport's handler does.
func (f *installerScopeFixture) completeInstall(t *testing.T, ctx context.Context) {
	t.Helper()
	_, err := f.svc.WebhookComplete(ctx, &platformv1.PXEWebhookCompleteRequest{MacAddress: installerMAC, Success: true})
	require.NoError(t, err)
	assert.Equal(t, pxe.StateInstallComplete, f.state(t, installerMAC))
	assert.Equal(t, pxe.StateInstalling, f.state(t, webhookOtherMAC))
}

// quicGuard is the production QUIC guard for the fixture's daemon. guard
// sends one provisioning-category operation as leaf.
func (f *installerScopeFixture) quicGuard(t *testing.T) func(leaf *x509.Certificate, sub byte) (context.Context, *quicwire.Response) {
	t.Helper()
	mw, _, err := selectQUICAuth(f.config, nil, f.config.MTLSClientCAPool, logging.DefaultLogger())
	require.NoError(t, err)
	return func(leaf *x509.Certificate, sub byte) (context.Context, *quicwire.Response) {
		return mw.GuardRequest(quicContext(verifiedState(leaf)),
			&quicwire.Request{Opcode: quicwire.OpProvisioningCategory, Payload: []byte{sub}})
	}
}

// mcpChecker is the production MCP authorization checker for the fixture's
// daemon, authorizing one tool as leaf.
func (f *installerScopeFixture) mcpChecker(t *testing.T) func(leaf *x509.Certificate, tool string) (context.Context, *mcp.AuthorizationError) {
	t.Helper()
	peers, err := newMCPPeerAuthenticator(f.config, logging.DefaultLogger())
	require.NoError(t, err)
	checker := mcp.NewAuthorizationChecker(nil, nil, mcp.WithPeerAuthenticator(peers))
	return func(leaf *x509.Certificate, tool string) (context.Context, *mcp.AuthorizationError) {
		return checker.AuthorizeTool(mcpContext(verifiedState(leaf)), tool, "")
	}
}

func TestMTLSInstallerScope_InstallerCompletesItsOwnDeviceThroughQUICWebhook(t *testing.T) {
	f := newInstallerScopeFixture(t)

	ctx, resp := f.quicGuard(t)(f.installer, quicwire.PXESubWebhookComplete)

	require.Nil(t, resp, "the QUIC guard must admit the installer to WebhookComplete")
	f.completeInstall(t, ctx)
}

func TestMTLSInstallerScope_InstallerIsRefusedOtherQUICPXEWrites(t *testing.T) {
	f := newInstallerScopeFixture(t)

	_, resp := f.quicGuard(t)(f.installer, quicwire.PXESubStopService)

	require.NotNil(t, resp, "the installer must not stop the PXE service over QUIC")
	assert.Equal(t, quicwire.StatusPermissionDenied, resp.Status)
}

func TestMTLSInstallerScope_OperatorReachesQUICPXEWrites(t *testing.T) {
	f := newInstallerScopeFixture(t)
	guard := f.quicGuard(t)

	for _, sub := range []byte{quicwire.PXESubWebhookComplete, quicwire.PXESubStopService} {
		_, resp := guard(f.operator, sub)
		assert.Nil(t, resp, "the operator must pass the QUIC guard on PXE sub-opcode %d", sub)
	}
}

func TestMTLSInstallerScope_InstallerCompletesItsOwnDeviceThroughMCPWebhook(t *testing.T) {
	f := newInstallerScopeFixture(t)

	ctx, authErr := f.mcpChecker(t)(f.installer, "pxe_webhook_complete")

	require.Nil(t, authErr, "the MCP checker must admit the installer to pxe_webhook_complete")
	f.completeInstall(t, ctx)
}

func TestMTLSInstallerScope_InstallerIsRefusedOtherMCPPXEWrites(t *testing.T) {
	f := newInstallerScopeFixture(t)

	_, authErr := f.mcpChecker(t)(f.installer, "pxe_stop_service")

	require.NotNil(t, authErr, "the installer must not stop the PXE service over MCP")
	assert.Equal(t, mcp.AuthErrorPermissionDenied, authErr.Type)
}

func TestMTLSInstallerScope_OperatorReachesMCPPXEWrites(t *testing.T) {
	f := newInstallerScopeFixture(t)
	authorize := f.mcpChecker(t)

	for _, tool := range []string{"pxe_webhook_complete", "pxe_stop_service"} {
		_, authErr := authorize(f.operator, tool)
		assert.Nil(t, authErr, "the operator must pass the MCP checker on %s", tool)
	}
}

func TestMTLSInstallerScope_RightNameWithoutSPIFFEIDIsNotTheOperator(t *testing.T) {
	f := newInstallerScopeFixture(t)
	impostor := f.issuerA.issueClient(t, 102,
		pkix.Name{CommonName: common.AdminUsername, Organization: []string{app.SystemTenantID}}, nil)

	reached, err := f.updateState(t, impostor, webhookOtherMAC)

	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.False(t, reached)
	assert.Nil(t, mtlsGrantFor(impostor, testOperatorTrustDomain))
}

func TestMTLSInstallerScope_EmptyTrustDomainMakesNoCertificateTheOperator(t *testing.T) {
	f := newInstallerScopeFixture(t)
	f.config.MTLSOperatorTrustDomain = ""

	reached, err := f.updateState(t, f.operator, webhookOtherMAC)

	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.False(t, reached)
	assert.Nil(t, mtlsGrantFor(f.operator, ""))
}

func TestIsMTLSOperator(t *testing.T) {
	operator := func(edit func(cert *x509.Certificate)) *x509.Certificate {
		cert := &x509.Certificate{}
		nameOperator(cert, testOperatorTrustDomain)
		edit(cert)
		return cert
	}
	withURI := func(raw string) func(cert *x509.Certificate) {
		return func(cert *x509.Certificate) {
			uri, err := url.Parse(raw)
			require.NoError(t, err)
			cert.URIs = []*url.URL{uri}
		}
	}
	cases := map[string]struct {
		leaf        *x509.Certificate
		trustDomain string
		want        bool
	}{
		"operator":                  {leaf: operator(func(*x509.Certificate) {}), trustDomain: testOperatorTrustDomain, want: true},
		"operator, SPIFFE in caps":  {leaf: operator(withURI("SPIFFE://platform.test/tenant/system/user/admin")), trustDomain: testOperatorTrustDomain, want: true},
		"nil certificate":           {leaf: nil, trustDomain: testOperatorTrustDomain},
		"empty trust domain":        {leaf: operator(func(*x509.Certificate) {}), trustDomain: ""},
		"other trust domain":        {leaf: operator(func(*x509.Certificate) {}), trustDomain: "other.test"},
		"other user":                {leaf: operator(withURI("spiffe://platform.test/tenant/system/user/alice"))},
		"other tenant":              {leaf: operator(withURI("spiffe://platform.test/tenant/acme/user/admin"))},
		"longer path":               {leaf: operator(withURI("spiffe://platform.test/tenant/system/user/admin/x"))},
		"query":                     {leaf: operator(withURI("spiffe://platform.test/tenant/system/user/admin?x=1"))},
		"https scheme":              {leaf: operator(withURI("https://platform.test/tenant/system/user/admin"))},
		"no URI SAN":                {leaf: operator(func(cert *x509.Certificate) { cert.URIs = nil })},
		"other organization":        {leaf: operator(func(cert *x509.Certificate) { cert.Subject.Organization = []string{"acme"} })},
		"second organization":       {leaf: operator(func(cert *x509.Certificate) { cert.Subject.Organization = append(cert.Subject.Organization, "acme") })},
		"no organization":           {leaf: operator(func(cert *x509.Certificate) { cert.Subject.Organization = nil })},
		"operator among other URIs": {leaf: operator(func(cert *x509.Certificate) { cert.URIs = append([]*url.URL{{Scheme: "urn"}}, cert.URIs...) }), trustDomain: testOperatorTrustDomain, want: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			trustDomain := tc.trustDomain
			if trustDomain == "" && name != "empty trust domain" && name != "nil certificate" {
				trustDomain = testOperatorTrustDomain
			}
			assert.Equal(t, tc.want, isMTLSOperator(tc.leaf, trustDomain))
			if tc.want {
				assert.Equal(t, []string{mtlsOperatorScope}, mtlsGrantFor(tc.leaf, trustDomain))
			} else {
				assert.Nil(t, mtlsGrantFor(tc.leaf, trustDomain))
			}
		})
	}
}
