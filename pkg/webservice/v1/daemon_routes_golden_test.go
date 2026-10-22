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

package v1_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
	bmcwebsvc "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// daemonRouteGoldenPath holds every "METHOD /template" the webservice
// listener mounts for the daemon-owned groups.
const daemonRouteGoldenPath = "testdata/daemon_routes.golden"

// updateDaemonRouteGolden rewrites daemonRouteGoldenPath from the routes
// the webservice mounts, instead of only comparing against it.
var updateDaemonRouteGolden = flag.Bool("update", false, "rewrite "+daemonRouteGoldenPath+" from the mounted daemon routes")

// pathVariable matches one gorilla/mux template variable, with or without
// a pattern ({slot}, {profileID:[0-9]+}).
var pathVariable = regexp.MustCompile(`\{[^}]+\}`)

// goldenBMC is a BMC handler whose methods are never called: the route table
// only takes their method values, and every request below stops at the gate.
type goldenBMC struct{ bmcwebsvc.RestHandler }

// goldenDevices, goldenProfiles, goldenKMS and goldenOverlay are services
// whose methods are never called, for the same reason.
type (
	goldenDevices  struct{ restapi.DeviceServiceInterface }
	goldenProfiles struct {
		restapi.ProfileServiceInterface
	}
	goldenKMS     struct{ restapi.KMSService }
	goldenOverlay struct {
		restapi.OverlayServiceInterface
	}
	goldenProxy   struct{ restapi.ProxyServiceBackend }
	goldenTenants struct {
		restapi.TenantManagerInterface
	}
	goldenCA struct {
		quicbaasca.CACertificateAuthority
	}
	goldenVTPM struct{ vtpm.VTPMService }
)

// goldenConfigDelivery answers every config-delivery route with 204. The
// machine half of the group stays on the certificate gate, so a request
// from a verified certificate reaches these handlers.
type goldenConfigDelivery struct{}

func (goldenConfigDelivery) GetNonce(w http.ResponseWriter, _ *http.Request) { noContent(w) }
func (goldenConfigDelivery) FetchConfig(w http.ResponseWriter, _ *http.Request) {
	noContent(w)
}
func (goldenConfigDelivery) SignDigest(w http.ResponseWriter, _ *http.Request) { noContent(w) }
func (goldenConfigDelivery) ListSessions(w http.ResponseWriter, _ *http.Request) {
	noContent(w)
}
func (goldenConfigDelivery) GetSession(w http.ResponseWriter, _ *http.Request) { noContent(w) }
func (goldenConfigDelivery) PollSession(w http.ResponseWriter, _ *http.Request) {
	noContent(w)
}
func (goldenConfigDelivery) FulfillSession(w http.ResponseWriter, _ *http.Request) {
	noContent(w)
}

func noContent(w http.ResponseWriter) { w.WriteHeader(http.StatusNoContent) }

// errGoldenCANotInitialized is the error the golden CA answers a bundle
// read with.
type errGoldenCANotInitialized struct{}

func (errGoldenCANotInitialized) Error() string { return "golden CA is not initialized" }

// The CA's public material stays on the certificate gate, so a request from
// a verified certificate reaches these: the golden CA is uninitialized.
func (goldenCA) IsInitialized() bool { return false }

func (goldenCA) CABundle() ([]byte, error) { return nil, errGoldenCANotInitialized{} }

func (goldenCA) TrustedRootCertPool(*x509.Certificate) (*x509.CertPool, error) {
	return nil, errGoldenCANotInitialized{}
}

func (goldenCA) GenerateCRL(context.Context) ([]byte, error) {
	return nil, errGoldenCANotInitialized{}
}

// ownedRoutes adapts the daemon REST server's owned groups to the
// v1.DaemonRESTRoutes table the webservice router mounts.
type ownedRoutes struct {
	server *daemon.RESTServer
	roots  *x509.CertPool
}

func (o ownedRoutes) ClientCAs() *x509.CertPool { return o.roots }

func (o ownedRoutes) MountRESTRoutes(api *mux.Router) error {
	return o.server.MountOwnedRoutes(api)
}

// daemonRoutesOnWebservice builds the daemon REST server with every
// daemon-owned group registered through its setters and mounts the groups
// the way the webservice router does: v1.MountDaemonRESTRoutes on /api/v1.
// Its client pool is empty, so no request gets past the certificate gate,
// and every privileged route passes the webservice gate.
func daemonRoutesOnWebservice(t *testing.T) *mux.Router {
	t.Helper()
	return mountDaemonRoutes(t, x509.NewCertPool(), passThrough, passCaller)
}

// mountDaemonRoutes is daemonRoutesOnWebservice over the client roots and
// the webservice and session gates given.
func mountDaemonRoutes(t *testing.T, roots *x509.CertPool, authorize v1.DaemonRouteAuthorizer, caller v1.DaemonCallerAuthenticator) *mux.Router {
	t.Helper()

	config := daemon.DefaultConfig()
	config.RESTListenAddr = "127.0.0.1:0"
	service, err := daemon.NewService(config)
	require.NoError(t, err)
	server, err := daemon.NewRESTServer(config, service, slog.Default())
	require.NoError(t, err)

	logger := logging.DefaultLogger()
	server.SetBMCHandler(goldenBMC{})
	server.SetCeremonyService(daemon.NewCeremonyService(logger, nil))
	server.SetPIVService(daemon.NewPIVService(logger, nil))
	server.SetLUKSService(daemon.NewLUKSService(logger, nil, nil))
	server.SetFIDO2Service(daemon.NewFIDO2Service(logger, nil))
	server.SetClusterService(platformv1.UnimplementedClusterServiceServer{})
	server.SetDeviceHandlers(goldenDevices{}, goldenProfiles{}, platformv1.UnimplementedDeviceServiceServer{})
	server.SetKMSHandlers(goldenKMS{})
	server.SetOverlayHandlers(goldenOverlay{})
	server.SetConfigDeliveryHandler(goldenConfigDelivery{})
	server.SetSDNService(nil)
	server.SetGatewayIPAMService(nil, nil)
	server.SetProxyService(goldenProxy{})
	server.SetNTPHandlers(platformv1.UnimplementedNTPServiceServer{}, nil)
	server.SetVPNHandlers(platformv1.UnimplementedVPNServiceServer{}, nil)
	server.SetAppServiceHandlers(restapi.AppServiceServers{}, nil)
	server.SetTenantHandlers(goldenTenants{}, nil, "")
	server.SetComputeHandlers(platformv1.UnimplementedComputeServiceServer{}, nil)
	server.SetCAHandlers(goldenCA{}, nil)
	server.SetTPMHandlers(platformv1.UnimplementedTPMServiceServer{}, nil)
	server.SetVTPMService(goldenVTPM{})

	root := mux.NewRouter()
	api := root.PathPrefix("/api/v1").Subrouter()
	writer := response.NewResponseWriter(logger, nil)
	require.NoError(t, v1.MountDaemonRESTRoutes(api, ownedRoutes{server: server, roots: roots}, writer, authorize, caller))
	return root
}

// passThrough authorizes every privileged route, so these tests see the
// client-certificate gate alone.
func passThrough(string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler { return next }
}

// passCaller lets every caller through the login-checked routes.
func passCaller(next http.Handler) http.Handler { return next }

// TestMountDaemonRESTRoutes_EveryDaemonRouteStillExists compares the
// daemon-owned groups the webservice listener mounts against the checked-in
// golden. A setter that stops registering a group, or a group that moves out
// of the owned set, removes lines here, which the router's own walk cannot
// see (docs/daemon/architecture.md). Regenerate the golden with
//
//	go test -tags "$(make -s print-build-tags)" \
//	    -run TestMountDaemonRESTRoutes_EveryDaemonRouteStillExists ./pkg/webservice/v1/ -update
//
// (-update follows the package: go test hands it and every later argument
// to the test binary, so it cannot ride in TESTFLAGS) and review the diff: every added line is a route the guard must classify.
func TestMountDaemonRESTRoutes_EveryDaemonRouteStillExists(t *testing.T) {
	built := testutil.WalkRoutes(t, daemonRoutesOnWebservice(t))
	if *updateDaemonRouteGolden {
		require.NoError(t, os.WriteFile(daemonRouteGoldenPath, []byte(strings.Join(built, "\n")+"\n"), 0o600))
	}

	data, err := os.ReadFile(daemonRouteGoldenPath)
	require.NoError(t, err, "missing %s -- it is the assertion, not a cache", daemonRouteGoldenPath)
	assert.Equal(t, goldenLines(string(data)), built,
		"the daemon-owned routes mounted on the webservice listener differ from %s", daemonRouteGoldenPath)
}

// TestMountDaemonRESTRoutes_EveryDaemonRouteRequiresClientCert sends every
// daemon-owned endpoint a request with no TLS state: each must answer the
// gate's 401, so no daemon-owned route is reachable on the webservice
// listener without a verified client certificate. The golden also lists the
// group subrouter prefixes (GET /api/v1/fido2, ...), which carry no handler
// and answer 404; the sweep probes every route that does carry one.
func TestMountDaemonRESTRoutes_EveryDaemonRouteRequiresClientCert(t *testing.T) {
	root := daemonRoutesOnWebservice(t)

	data, err := os.ReadFile(daemonRouteGoldenPath)
	require.NoError(t, err)
	golden := goldenLines(string(data))

	endpoints := endpointRoutes(t, root)
	require.NotEmpty(t, endpoints, "the webservice router mounts no daemon-owned endpoint")

	for _, route := range endpoints {
		assert.Contains(t, golden, route, "endpoint missing from %s", daemonRouteGoldenPath)

		method, template, found := strings.Cut(route, " ")
		require.True(t, found, "route %q is not \"METHOD /template\"", route)
		path := pathVariable.ReplaceAllString(template, "1")

		rec := httptest.NewRecorder()
		root.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		assert.Equal(t, http.StatusUnauthorized, rec.Code, "%s %s without a client certificate", method, path)
	}
}

// publicDaemonEndpoints are the replayed daemon endpoints that keep the
// client-certificate gate alone (docs/daemon/architecture.md): the CA's
// public material, the machine half of config delivery, which authenticates
// inside the request, and the four reads made before a session exists
// (ceremony status, tenant MFA policy, AAGUID lookup, mTLS probe). Every
// other endpoint takes the admin gate and its scope or an authenticated
// session (#983); adding one here is a reviewed change.
var publicDaemonEndpoints = []string{
	"GET /api/v1/auth/factors/aaguid-lookup",
	"GET /api/v1/ca/bundle",
	"GET /api/v1/ca/crl",
	"GET /api/v1/ca/info",
	"GET /api/v1/ceremony/status",
	"GET /api/v1/provisioning/config/nonce",
	"GET /api/v1/provisioning/sessions/{sessionID}/poll",
	"GET /api/v1/tenants/{id}/security/mfa-policy",
	"HEAD /api/v1/auth/mtls/probe",
	"POST /api/v1/provisioning/config",
	"POST /api/v1/provisioning/sign",
}

// refusedScopeHeader is the response header refuseWithScope names the
// guarding scope in.
const refusedScopeHeader = "X-Refused-Scope"

// refuseWithScope is a webservice gate that refuses every privileged route
// with 403 and names the scope the route was guarded with.
func refuseWithScope(scope string) func(http.Handler) http.Handler {
	return func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set(refusedScopeHeader, scope)
			w.WriteHeader(http.StatusForbidden)
		})
	}
}

// refusedSessionHeader is the response header refuseSession marks its
// refusal with.
const refusedSessionHeader = "X-Refused-Session"

// refuseSession is a session gate that refuses every session-gated route
// with 401 and marks the refusal.
func refuseSession(http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(refusedSessionHeader, "session")
		w.WriteHeader(http.StatusUnauthorized)
	})
}

// TestMountDaemonRESTRoutes_EveryDaemonEndpointIsGatedOrPublic sends every
// replayed daemon endpoint a request from a verified client certificate and
// checks it against the production classification (classifyDaemonRoute):
// an operator endpoint must stop at the webservice gate with its scope, a
// session endpoint at the session gate, and a certificate-only endpoint
// must be one of publicDaemonEndpoints and reach its handler. A daemon
// route added without a classification fails here.
func TestMountDaemonRESTRoutes_EveryDaemonEndpointIsGatedOrPublic(t *testing.T) {
	platform := testutil.GenerateTestTLSBundle(t)
	root := mountDaemonRoutes(t, platform.CAPool, refuseWithScope, refuseSession)
	state := verifiedState(t, platform)

	endpoints := endpointRoutes(t, root)
	public := make([]string, 0)
	for _, route := range endpoints {
		method, template, _ := strings.Cut(route, " ")
		gate, scope := v1.ClassifyDaemonRoute(method, template)
		if gate == v1.DaemonRouteCertificate {
			public = append(public, route)
		}
		t.Run(route, func(t *testing.T) {
			req := httptest.NewRequest(method, pathVariable.ReplaceAllString(template, "1"), nil)
			req.TLS = state
			rec := httptest.NewRecorder()
			root.ServeHTTP(rec, req)

			switch gate {
			case v1.DaemonRouteOperator:
				assert.Equal(t, http.StatusForbidden, rec.Code, "the endpoint passed the webservice gate")
				assert.Equal(t, []string{scope}, rec.Header().Values(refusedScopeHeader), "the endpoint took the wrong scope")
			case v1.DaemonRouteSession:
				assert.Equal(t, http.StatusUnauthorized, rec.Code, "the endpoint passed the session gate")
				assert.Equal(t, []string{"session"}, rec.Header().Values(refusedSessionHeader), "the endpoint did not take the session gate")
			case v1.DaemonRouteCertificate:
				assert.NotEqual(t, http.StatusForbidden, rec.Code, "a public endpoint reached the webservice gate")
				assert.Empty(t, rec.Header().Values(refusedScopeHeader), "a public endpoint reached the webservice gate")
				assert.Empty(t, rec.Header().Values(refusedSessionHeader), "a public endpoint reached the session gate")
			default:
				assert.Failf(t, "unclassified daemon endpoint", "%s has no authorization classification and is denied", route)
			}
		})
	}

	assert.ElementsMatch(t, publicDaemonEndpoints, public, "the certificate-only daemon endpoints changed")
}

// TestPrivilegedDaemonMethodRoutes_NameDaemonRoutes keeps the gate table
// free of entries that guard nothing: each one is a replayed daemon
// endpoint or a daemon auth-factor route.
func TestPrivilegedDaemonMethodRoutes_NameDaemonRoutes(t *testing.T) {
	registered := map[string]bool{}
	for _, route := range endpointRoutes(t, daemonRoutesOnWebservice(t)) {
		registered[route] = true
	}
	authFactors := mux.NewRouter()
	restapi.NewAuthFactorHandlers(nil, slog.Default()).RegisterRoutes(authFactors)
	for _, route := range endpointRoutes(t, authFactors) {
		registered[route] = true
	}

	require.NotEmpty(t, v1.PrivilegedDaemonMethodRoutes)
	for key := range v1.PrivilegedDaemonMethodRoutes {
		assert.Truef(t, registered[key], "gate entry %s names no daemon route", key)
	}
	require.NotEmpty(t, v1.CallerCheckedDaemonMethodRoutes)
	for key := range v1.CallerCheckedDaemonMethodRoutes {
		assert.Truef(t, registered[key], "login-checked entry %s names no daemon route", key)
		_, gated := v1.PrivilegedDaemonMethodRoutes[key]
		assert.Falsef(t, gated, "login-checked entry %s is also in the admin gate table", key)
	}
}

// verifiedState is the TLS state of a connection whose client certificate
// chained to bundle's CA.
func verifiedState(t *testing.T, bundle *testutil.TestTLSBundle) *tls.ConnectionState {
	t.Helper()
	leaf, err := x509.ParseCertificate(bundle.ClientCert.Certificate[0])
	require.NoError(t, err)
	return &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf, bundle.CACert}},
	}
}

// endpointRoutes returns "METHOD /template" for every route on router that
// carries a handler, in the form testutil.WalkRoutes uses.
func endpointRoutes(t *testing.T, router *mux.Router) []string {
	t.Helper()

	endpoints := make([]string, 0)
	err := router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		if route.GetHandler() == nil {
			return nil
		}
		template, err := route.GetPathTemplate()
		if err != nil {
			return err
		}
		methods, err := route.GetMethods()
		if err != nil {
			methods = []string{http.MethodGet}
		}
		for _, method := range methods {
			endpoints = append(endpoints, method+" "+template)
		}
		return nil
	})
	require.NoError(t, err)
	return endpoints
}

// goldenLines returns the non-blank lines of a golden file, trimmed.
func goldenLines(data string) []string {
	lines := make([]string, 0)
	for _, line := range strings.Split(data, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
