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

package v1

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cryptoclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/crypto"
	dekclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/dek"
	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	kmsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	secretsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/jwt"
	iammw "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// =============================================================================
// Test doubles
//
// The audit below never reaches a handler on a gated route, so the service
// doubles only have to make their routers register. Each embeds the
// interface it stands in for: a call that does slip through panics loudly
// instead of returning a plausible zero value.
// =============================================================================

// anonymousAuth models the inbound seam's response to a request carrying no
// credential, which is what jwt.RestHandler.Verify does: write 401 and stop.
// It publishes no session, so a guard mounted without it would be reached
// with an empty context and must still deny.
type anonymousAuth struct{ mockTokenHandler }

func (a *anonymousAuth) Verify(w http.ResponseWriter, r *http.Request, _ http.HandlerFunc) {
	w.WriteHeader(http.StatusUnauthorized)
}

// sessionAuth models a request carrying a VERIFIED credential: it publishes
// an IAMSession with the given roles, exactly as jwt.RestHandler.Verify does
// after it has checked the signature. It is how the role half of the gate is
// exercised independently of the authentication half.
type sessionAuth struct {
	mockTokenHandler
	roles    []string
	tenantID string
}

func (s *sessionAuth) Verify(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	session := iammw.NewIAMSession(&iamsdk.User{
		ID:       "probe-user",
		TenantID: s.tenantID,
		Email:    "probe@example.test",
		Roles:    s.roles,
	})
	next(w, r.WithContext(iammw.SetSessionInContext(r.Context(), session)))
}

type stubCA struct {
	trustedca.CACertificateAuthority
}

func (s *stubCA) IsInitialized() bool { return false }

type stubVTPMService struct{ vtpm.VTPMService }

type stubKMSClient struct{ kmsclient.Client }
type stubCryptoClient struct{ cryptoclient.Client }
type stubDEKClient struct{ dekclient.Client }
type stubSecretsClient struct{ secretsclient.Client }

type stubTPMServer struct {
	platformv1.UnimplementedTPMServiceServer
}
type stubTenantServer struct {
	platformv1.UnimplementedTenantServiceServer
}
type stubIDevIDServer struct {
	platformv1.UnimplementedIDevIDServiceServer
}

// newGatedTestRouter builds the full v1 route table with every service the
// slice-1 gate covers wired, mounted under /api/v1 exactly as
// webserver_v1.buildRoutes does. The caller supplies the registry carrying
// the inbound authentication seam under test; everything else is filled in
// here so each test differs only in the credential it models.
func newGatedTestRouter(t *testing.T, registry *testHandlerRegistry) *mux.Router {
	t.Helper()

	logger := testLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	registry.responseWriter = respWriter
	registry.tpmService = &stubTPMServer{}
	registry.tenantService = &stubTenantServer{}
	registry.idevidService = &stubIDevIDServer{}
	registry.vtpmService = &stubVTPMService{}
	registry.kmsKeyMgmt = &stubKMSClient{}
	registry.kmsCrypto = &stubCryptoClient{}
	registry.kmsDEK = &stubDEKClient{}
	registry.kmsSecrets = &stubSecretsClient{}
	registry.tenantID = "system"

	v1Router := NewRouter(logger, &stubCA{}, nil, nil, registry, respWriter)

	root := mux.NewRouter()
	v1Router.RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())
	return root
}

var pathVariable = regexp.MustCompile(`\{[^}]*\}`)

// probe issues one credential-free request against a route template and
// reports the status code the wire saw.
//
// A handler that panics is reported as probeHandlerReached rather than
// failing the test, and that is a deliberate signal, not leniency: reaching
// a handler at all proves the request was NOT denied, which is precisely
// what the audit asks. Several ungated handlers panic on the interface-
// embedding doubles above, and every one of those panics is evidence for
// the assertion rather than noise obscuring it.
const probeHandlerReached = 599

func probe(router *mux.Router, method, template string) int {
	return serve(router,
		httptest.NewRequest(method, pathVariable.ReplaceAllString(template, "probe"), nil))
}

// serve runs one request through the router and reports the status the wire
// saw, mapping a handler panic to probeHandlerReached. Every probe in this
// file goes through it so "the handler ran" is reported identically however
// the request was built.
func serve(router *mux.Router, req *http.Request) (code int) {
	defer func() {
		if recovered := recover(); recovered != nil {
			code = probeHandlerReached
		}
	}()
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder.Code
}

// denied reports whether a status code means the request was refused
// without a credential.
//
// 404 counts. mux's Walk reports a subrouter's own PathPrefix route
// alongside the endpoints registered under it, and those prefix entries
// address no handler: a request against one is answered by mux itself and
// discloses nothing. A handler that chose to answer 404 would also have
// disclosed nothing.
func denied(code int) bool {
	return code == http.StatusUnauthorized ||
		code == http.StatusForbidden ||
		code == http.StatusNotFound
}

// publicRoutes is the complete set of v1 routes that answer a caller
// holding no credential, WITH the reason each one must. It is the
// artifact #165 asks for: an unexplained public route is the defect, so a
// route may only leave the gate by acquiring a line here.
//
// Everything in this map is either (a) material already published in every
// TLS handshake this platform performs, (b) an endpoint whose entire
// purpose is to serve a client that cannot yet have a credential, or (c) a
// report of wire state that names no secret.
var publicRoutes = map[string]string{
	// It must stay public: pkg/bootstrap/orchestrator.go's httpHealthChecker
	// probes https://<node>:{8443,9443,443}/api/v1/status to decide a node
	// has finished booting, from a machine that has no credential yet and may
	// not trust the node's CA yet. Gating it would break node bootstrap.
	//
	// It ALSO over-discloses for that purpose — the handler returns SMBIOS
	// product/board/chassis (including serials), kernel version, hostname,
	// network interfaces and addresses, and TPM and CA status. A liveness
	// probe reads only the status code. That is an information-disclosure
	// defect, not an authorization one, and it is tracked on #236: the fix
	// is to narrow the body, not to gate the route.
	"GET /api/v1/status": "bootstrap liveness. The bootstrap orchestrator probes it " +
		"before any credential exists; see #236 for what it over-discloses.",
	"GET /api/v1/pubkey": "the server's own public key, which it presents on every TLS handshake.",
	"GET /api/v1/certificate": "the server's own certificate, likewise presented on every " +
		"TLS handshake and readable by anyone who can connect.",

	// Registered with no method matcher, so they answer every verb; the
	// walk reports them under GET.
	"GET /api/v1/login":         "credential issuance. Gating the endpoint that mints the credential is a deadlock.",
	"GET /api/v1/login/refresh": "same ceremony; the caller presents a refresh credential to the handler, not to a gate.",

	"GET /api/v1/ca/bootstrap": "the trust-bootstrap fetch. Its purpose is to serve the CA bundle to a " +
		"client that does not trust this platform yet and therefore cannot have authenticated to it.",
	"GET /api/v1/ca/crl": "CRL distribution. RFC 5280 relying parties retrieve a CRL anonymously; a gated " +
		"CRL cannot be consumed by the verifiers it exists for.",
	"GET /api/v1/ca/bundle":       "the CA's own chain — a strict subset of what /ca/bootstrap already publishes.",
	"GET /api/v1/ca/root":         "the root CA certificate, present in every chain this platform issues.",
	"GET /api/v1/ca/intermediate": "the intermediate CA certificate, likewise.",
	"GET /api/v1/ca/info": "CA identity, default algorithm and validity, plus summaries of the two " +
		"certificates above. No issued-certificate inventory, no key material.",

	"GET /api/v1/platform/service-registry": "wire state only — which REST surfaces are configured. " +
		"Deliberately public so the console can show dark surfaces before login; predates this change.",
}

// pendingRoutes is the rest of #165: routes still reachable without a
// credential because their tranche has not landed. It exists so the audit
// can be exact today — a NEW ungated route fails the test immediately —
// while the known remainder shrinks visibly, one slice at a time, until
// this map is empty and only publicRoutes is left.
//
// Slice 2 (platform, compute, registry, sdn, switch, overlay, gateway, dns,
// eab, attestation, ntp) and slice 3 (pxe, invitation, devices seeder, /v2,
// the account-factor and quicbaas stubs) empty it.
var pendingRoutes = map[string]string{
	"GET /api/v1/compute/images/": "#165 slice 2 — service-registry 503 stub for the unconfigured registry.",
	"GET /api/v1/compute/images":  "#165 slice 2 — as above.",
	"GET /api/v1/compute/":        "#165 slice 2 — service-registry 503 stub for unconfigured compute.",
	"GET /api/v1/compute":         "#165 slice 2 — as above.",
	"GET /api/v1/dns/":            "#165 slice 2 — service-registry 503 stub for unconfigured dns.",
	"GET /api/v1/dns":             "#165 slice 2 — as above.",
	"GET /api/v1/sdn/":            "#165 slice 2 — service-registry 503 stub for unconfigured sdn.",
	"GET /api/v1/sdn":             "#165 slice 2 — as above.",
	"GET /api/v1/switches/":       "#165 slice 2 — service-registry 503 stub for unconfigured switch.",
	"GET /api/v1/switches":        "#165 slice 2 — as above.",

	"GET /api/v1/users/{id}/factors": "#165 slice 3 — auth-factor stub registered directly on the v1 router.",

	"GET /api/v1/quicbaas/storage/buckets":                               "#165 slice 3 — quicbaas UI stub.",
	"POST /api/v1/quicbaas/storage/buckets":                              "#165 slice 3 — quicbaas UI stub.",
	"DELETE /api/v1/quicbaas/storage/buckets/{name}":                     "#165 slice 3 — quicbaas UI stub.",
	"GET /api/v1/quicbaas/storage/buckets/{name}/objects":                "#165 slice 3 — quicbaas UI stub.",
	"DELETE /api/v1/quicbaas/storage/buckets/{name}/objects/{object:.*}": "#165 slice 3 — quicbaas UI stub.",
	"GET /api/v1/quicbaas/kv":                                            "#165 slice 3 — quicbaas UI stub.",
	"POST /api/v1/quicbaas/kv":                                           "#165 slice 3 — quicbaas UI stub.",
	"DELETE /api/v1/quicbaas/kv/{key}":                                   "#165 slice 3 — quicbaas UI stub.",
	"GET /api/v1/quicbaas/timeseries/metrics":                            "#165 slice 3 — quicbaas UI stub.",
	"POST /api/v1/quicbaas/timeseries/metrics":                           "#165 slice 3 — quicbaas UI stub.",
	"GET /api/v1/quicbaas/vector/collections":                            "#165 slice 3 — quicbaas UI stub.",
	"POST /api/v1/quicbaas/vector/collections":                           "#165 slice 3 — quicbaas UI stub.",
	"GET /api/v1/quicbaas/vector/namespaces":                             "#165 slice 3 — quicbaas UI stub.",
	"POST /api/v1/quicbaas/vector/namespaces":                            "#165 slice 3 — quicbaas UI stub.",
	"GET /api/v1/quicbaas/backup/snapshots":                              "#165 slice 3 — quicbaas UI stub.",
	"POST /api/v1/quicbaas/backup/snapshots":                             "#165 slice 3 — quicbaas UI stub.",
	"GET /api/v1/quicbaas/backups":                                       "#165 slice 3 — quicbaas UI stub.",
	"POST /api/v1/quicbaas/backups":                                      "#165 slice 3 — quicbaas UI stub.",
}

// walkRoutes returns every "METHOD /template" the finished table exposes.
func walkRoutes(t *testing.T, router *mux.Router) []string {
	t.Helper()

	seen := map[string]bool{}
	require.NoError(t, router.Walk(
		func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
			template, err := route.GetPathTemplate()
			if err != nil {
				return nil
			}
			methods, err := route.GetMethods()
			if err != nil || len(methods) == 0 {
				// A route with no method matcher answers all of them;
				// GET is enough to establish whether it is gated.
				methods = []string{http.MethodGet}
			}
			for _, method := range methods {
				seen[method+" "+template] = true
			}
			return nil
		}))

	out := make([]string, 0, len(seen))
	for route := range seen {
		out = append(out, route)
	}
	sort.Strings(out)
	return out
}

// =============================================================================
// The audit
// =============================================================================

// TestRegisterRoutes_EveryRouteDeniesWithoutCredential is the default-deny
// assertion for the whole REST surface, and the reason #165's gate is
// declared in router.go rather than copied into each rest router: it walks
// the FINISHED route table rather than a hand-written list, so a router
// mounted on the ungated parent by mistake — or one added later that never
// calls gated() — fails the build gate instead of shipping open.
//
// Its reach is bounded by newGatedTestRouter's wiring, and deliberately
// stated rather than implied: a router whose backing service is nil never
// registers, so it is neither asserted nor excused here. The fixture wires
// every service #165 slice 1 gates; the surfaces still to be gated — and
// the ones a later slice must add to this fixture to bring under the
// assertion, among them /bmc, /provisioning and the /v2 OCI mount at the
// host root — are named in pendingRoutes and in docs/auth/architecture.md
// §6c.
func TestRegisterRoutes_EveryRouteDeniesWithoutCredential(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: &anonymousAuth{}})

	for _, route := range walkRoutes(t, router) {
		method, template := splitRoute(route)
		if _, ok := publicRoutes[route]; ok {
			continue
		}
		if _, ok := pendingRoutes[route]; ok {
			continue
		}
		code := probe(router, method, template)
		assert.True(t, denied(code),
			"%s answered %d to a request carrying no credential. Gate it with "+
				"v1Router.gated(...), or add it to publicRoutes with the reason it must stay open.",
			route, code)
	}
}

// TestRegisterRoutes_EveryDeclaredOpenRouteIsActuallyOpen is the other
// direction, and it is what stops the two maps above from decaying into
// documentation. A route listed as public or pending that has since been
// gated would otherwise sit there forever, quietly excusing a gate nobody
// needs and hiding the fact that the remaining work has shrunk.
func TestRegisterRoutes_EveryDeclaredOpenRouteIsActuallyOpen(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: &anonymousAuth{}})

	registered := map[string]bool{}
	for _, route := range walkRoutes(t, router) {
		registered[route] = true
	}

	for _, declared := range []map[string]string{publicRoutes, pendingRoutes} {
		for route, reason := range declared {
			if !registered[route] {
				// The route's service is not wired in this fixture, so it
				// never registered. Nothing to prove either way.
				continue
			}
			method, template := splitRoute(route)
			code := probe(router, method, template)
			assert.False(t, code == http.StatusUnauthorized || code == http.StatusForbidden,
				"%s is declared open (%s) but answered %d — remove it from the list; it is gated now.",
				route, reason, code)
		}
	}
}

// TestRegisterRoutes_EveryOpenRouteCarriesAReason keeps the two maps
// disjoint and non-empty of justification. A route with a blank reason is
// the "unexplained public route" this issue is about.
func TestRegisterRoutes_EveryOpenRouteCarriesAReason(t *testing.T) {
	for route, reason := range publicRoutes {
		assert.NotEmpty(t, reason, "public route %s carries no justification", route)
		_, alsoPending := pendingRoutes[route]
		assert.False(t, alsoPending,
			"%s is declared both permanently public and pending; decide which", route)
	}
	for route, reason := range pendingRoutes {
		assert.NotEmpty(t, reason, "pending route %s carries no justification", route)
	}
}

// gatedProbes are one representative route from each router slice 1 gates,
// chosen for blast radius: the operation whose unauthenticated reachability
// #165 calls out by name.
var gatedProbes = []struct {
	name   string
	method string
	path   string
}{
	{"tpm clear", http.MethodPost, "/api/v1/tpm/clear"},
	{"tpm nvram write", http.MethodPut, "/api/v1/tpm/nvram/0x1c00002"},
	{"tenant barrier unseal", http.MethodPost, "/api/v1/tenants/t1/barrier/unseal"},
	{"tenant barrier init", http.MethodPost, "/api/v1/tenants/t1/barrier/init"},
	{"tenant DEK rotate", http.MethodPost, "/api/v1/tenants/t1/dek/rotate"},
	{"tenant delete", http.MethodDelete, "/api/v1/tenants/t1"},
	{"kms decrypt", http.MethodPost, "/api/v1/kms/decrypt/k1"},
	{"kms sign", http.MethodPost, "/api/v1/kms/sign/k1"},
	{"kms secret read", http.MethodGet, "/api/v1/kms/secrets/s1"},
	{"kms key delete", http.MethodDelete, "/api/v1/kms/keys/k1"},
	{"ca issue certificate", http.MethodPost, "/api/v1/ca/certificates"},
	{"ca revoke certificate", http.MethodDelete, "/api/v1/ca/certificates/abc"},
	{"idevid generate", http.MethodPost, "/api/v1/idevid/generate"},
	{"idevid delete", http.MethodDelete, "/api/v1/idevid"},
	{"vtpm bundle export", http.MethodGet, "/api/v1/vtpm/bundles/b1/export"},
	{"vtpm bundle delete", http.MethodDelete, "/api/v1/vtpm/bundles/b1"},
}

// TestGatedRoutes_RejectAnonymousCallers is the authentication half of the
// gate on the routes that matter most.
func TestGatedRoutes_RejectAnonymousCallers(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: &anonymousAuth{}})

	for _, tc := range gatedProbes {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, http.StatusUnauthorized, probe(router, tc.method, tc.path))
		})
	}
}

// TestGatedRoutes_RejectAuthenticatedCallersWithoutTheAdminRole is the
// authorization half, and it is the assertion that a passing
// authentication test cannot stand in for: a caller who holds a perfectly
// valid credential for an ordinary account must still be refused.
func TestGatedRoutes_RejectAuthenticatedCallersWithoutTheAdminRole(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{
		tokenHandler: &sessionAuth{roles: []string{"user"}, tenantID: "system"},
	})

	for _, tc := range gatedProbes {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, http.StatusForbidden, probe(router, tc.method, tc.path))
		})
	}
}

// TestGatedRoutes_AdmitTheAdminRole proves the gate is a gate and not a
// wall: the same requests reach their handlers once the session carries
// admin. Without this the suite would pass just as well against a
// deny-everything middleware.
func TestGatedRoutes_AdmitTheAdminRole(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{
		tokenHandler: &sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: "system"},
	})

	for _, tc := range gatedProbes {
		t.Run(tc.name, func(t *testing.T) {
			code := probe(router, tc.method, tc.path)
			assert.NotEqual(t, http.StatusUnauthorized, code, "admin was refused authentication")
			assert.NotEqual(t, http.StatusForbidden, code, "admin was refused authorization")
		})
	}
}

// TestCARoutes_PublicHalfStaysReachableWithoutACredential pins the carve-out
// in the other direction: gating the CA must not take the trust-bootstrap
// fetch or the CRL with it, or clients that do not trust the platform yet
// can never come to.
func TestCARoutes_PublicHalfStaysReachableWithoutACredential(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: &anonymousAuth{}})

	for _, path := range []string{
		"/api/v1/ca/bootstrap",
		"/api/v1/ca/crl",
		"/api/v1/ca/bundle",
		"/api/v1/ca/root",
		"/api/v1/ca/intermediate",
		"/api/v1/ca/info",
	} {
		t.Run(path, func(t *testing.T) {
			code := probe(router, http.MethodGet, path)
			assert.NotEqual(t, http.StatusUnauthorized, code)
			assert.NotEqual(t, http.StatusForbidden, code)
		})
	}
}

// TestRoleGate_DeniesEveryRequestWhenTheAuthSeamIsUnavailable covers the
// fail-closed branch. A node that could not build an authenticator must
// refuse the protected surface, not publish it.
func TestRoleGate_DeniesEveryRequestWhenTheAuthSeamIsUnavailable(t *testing.T) {
	logger := testLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	// A registry with no token handler and no broker middleware: authMiddleware
	// resolves to nil, so no authenticator can be adapted.
	v1Router := NewRouter(logger, nil, nil, nil, &testHandlerRegistry{
		responseWriter: respWriter,
	}, respWriter).(*Router)

	root := mux.NewRouter()
	v1Router.router = root.PathPrefix("/api/v1").Subrouter()
	v1Router.gatedGroups = make(map[string]*mux.Router)

	reached := false
	v1Router.gated(common.ROLE_ADMIN).
		HandleFunc("/probe", func(http.ResponseWriter, *http.Request) { reached = true }).
		Methods(http.MethodPost)

	assert.Equal(t, http.StatusUnauthorized, probe(root, http.MethodPost, "/api/v1/probe"))
	assert.False(t, reached, "a group that could not acquire a gate must not reach its handler")
}

// refusingWriter is an http.ResponseWriter whose body write always fails,
// the way a client that hung up mid-response makes it fail.
type refusingWriter struct {
	header http.Header
	status int
}

func (w *refusingWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}

func (w *refusingWriter) WriteHeader(status int) { w.status = status }

func (w *refusingWriter) Write([]byte) (int, error) {
	return 0, &MessageError{Msg: "connection reset by peer"}
}

// TestRoleGate_StillRefusesWhenTheDenialBodyCannotBeWritten pins the error
// path of the deny-all: losing the connection while explaining the refusal
// must not turn the refusal into a panic, and the 401 status must already be
// on the wire before the body is attempted.
func TestRoleGate_StillRefusesWhenTheDenialBodyCannotBeWritten(t *testing.T) {
	logger := testLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	v1Router := NewRouter(logger, nil, nil, nil, &testHandlerRegistry{
		responseWriter: respWriter,
	}, respWriter).(*Router)

	root := mux.NewRouter()
	v1Router.router = root.PathPrefix("/api/v1").Subrouter()
	v1Router.gatedGroups = make(map[string]*mux.Router)

	reached := false
	v1Router.gated(common.ROLE_ADMIN).
		HandleFunc("/probe", func(http.ResponseWriter, *http.Request) { reached = true }).
		Methods(http.MethodPost)

	writer := &refusingWriter{}
	require.NotPanics(t, func() {
		root.ServeHTTP(writer, httptest.NewRequest(http.MethodPost, "/api/v1/probe", nil))
	})
	assert.Equal(t, http.StatusUnauthorized, writer.status)
	assert.False(t, reached)
}

// TestRoleGate_DeniesWhenTheGuardCannotBeBuilt covers the other fail-closed
// branch: an authenticator exists but the SessionGuard refuses to build
// (NewSessionGuard requires a response writer, because a guard that cannot
// write a 403 cannot deny).
func TestRoleGate_DeniesWhenTheGuardCannotBeBuilt(t *testing.T) {
	logger := testLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	v1Router := NewRouter(logger, nil, nil, nil, &testHandlerRegistry{
		tokenHandler:   &sessionAuth{roles: []string{common.ROLE_ADMIN}},
		responseWriter: respWriter,
	}, respWriter).(*Router)

	root := mux.NewRouter()
	v1Router.router = root.PathPrefix("/api/v1").Subrouter()
	v1Router.gatedGroups = make(map[string]*mux.Router)
	// NewSessionGuard rejects a nil response writer.
	v1Router.responseWriter = nil

	reached := false
	v1Router.gated(common.ROLE_ADMIN).
		HandleFunc("/probe", func(http.ResponseWriter, *http.Request) { reached = true }).
		Methods(http.MethodPost)

	// denyAll writes the refusal itself rather than through the response
	// writer, which is the very component missing here — so the denial
	// survives the failure it is reporting.
	assert.Equal(t, http.StatusUnauthorized, probe(root, http.MethodPost, "/api/v1/probe"))
	assert.False(t, reached, "a group whose guard could not be built must not reach its handler")
}

// TestGated_MemoisesOneGroupPerRoleSet pins the grouping behaviour the
// route table depends on: routers sharing a role set share one group, so
// their registration order — which the /compute/images-before-/compute
// carve-out relies on — is the order they were registered in.
func TestGated_MemoisesOneGroupPerRoleSet(t *testing.T) {
	logger := testLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	v1Router := NewRouter(logger, nil, nil, nil, &testHandlerRegistry{
		tokenHandler:   &anonymousAuth{},
		responseWriter: respWriter,
	}, respWriter).(*Router)

	v1Router.router = mux.NewRouter()
	v1Router.gatedGroups = make(map[string]*mux.Router)

	admin := v1Router.gated(common.ROLE_ADMIN)
	assert.Same(t, admin, v1Router.gated(common.ROLE_ADMIN))
	assert.NotSame(t, admin, v1Router.gated(common.ROLE_SO))
	assert.Len(t, v1Router.gatedGroups, 2)
}

// TestRegisterRoutes_RebuildsGatedGroupsPerMux guards a stale-group bug:
// buildRoutes may re-register onto a fresh mux at runtime, and reusing the
// previous mux's groups would attach the new routes to a router nothing
// serves.
func TestRegisterRoutes_RebuildsGatedGroupsPerMux(t *testing.T) {
	logger := testLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	registry := &testHandlerRegistry{
		tokenHandler:   &anonymousAuth{},
		responseWriter: respWriter,
		tpmService:     &stubTPMServer{},
	}
	v1Router := NewRouter(logger, nil, nil, nil, registry, respWriter)

	first := mux.NewRouter()
	v1Router.RegisterRoutes(first.PathPrefix("/api/v1").Subrouter())
	firstGroup := v1Router.(*Router).gatedGroups[common.ROLE_ADMIN]

	second := mux.NewRouter()
	v1Router.RegisterRoutes(second.PathPrefix("/api/v1").Subrouter())
	secondGroup := v1Router.(*Router).gatedGroups[common.ROLE_ADMIN]

	require.NotNil(t, firstGroup)
	require.NotNil(t, secondGroup)
	assert.NotSame(t, firstGroup, secondGroup)
	assert.Equal(t, http.StatusUnauthorized, probe(second, http.MethodPost, "/api/v1/tpm/clear"))
}

// splitRoute splits a "METHOD /path" key back into its parts.
func splitRoute(route string) (method, template string) {
	for i := 0; i < len(route); i++ {
		if route[i] == ' ' {
			return route[:i], route[i+1:]
		}
	}
	return http.MethodGet, route
}

// =============================================================================
// The console's carrier, end to end through the gate
//
// The console's SDK client sends the platform JWT in the `jwt` cookie, not in
// an Authorization header. Two things were separately proven and never joined:
// jwt.Service.ParseToken accepts the cookie
// (TestParseToken_AcceptsTheConsoleCookie), and jwt.RestHandler.Verify
// publishes a session for a BEARER-carried token
// (TestHandlerVerify_PublishesSession). Neither crosses the carrier and the
// gate together, so "the console keeps working once logged in" was reasoning,
// not an assertion. These tests make it one, against the REAL verifier —
// a real signing key, a real signed token — rather than a seam double.
// =============================================================================

// consoleAuthSeam builds the production jwt.RestHandler over a real software
// keystore, and returns it with a signed token for a system-tenant admin.
func consoleAuthSeam(t *testing.T) (jwt.TokenHandler, string) {
	t.Helper()

	logger := testLogger()
	dir := t.TempDir()

	storage, err := xkmssdk.NewFileStorageBackend(dir)
	require.NoError(t, err)

	xkms, err := platform.NewXKMS(
		logger.Slog(),
		&platform.XKMSConfig{
			CN:             "gate-test",
			SoftwareConfig: &xkmssdk.SoftwareBackendConfig{KeyStorage: storage},
		},
		xkmssdk.NewFileBackend(logger.Slog(), storage),
		storage,
		storage,
		nil, // no TPM in a unit test
		nil, // no platform key store
	)
	require.NoError(t, err)

	// ECDSA P-256 rather than RSA: this is a unit test, and the assertion is
	// about the carrier, not the algorithm.
	keyAttrs, err := xkmssdk.KeyAttributesFromConfig(&xkmssdk.KeyConfig{
		CN:                 "gate-test",
		Hash:               "SHA256",
		KeyAlgorithm:       xkmssdk.KeyAlgorithmString(x509.ECDSA.String()),
		SignatureAlgorithm: xkmssdk.SignatureAlgorithmName(x509.ECDSAWithSHA256.String()),
		StoreType:          xkmssdk.StoreSoftware,
	})
	require.NoError(t, err)
	keyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err = xkms.GenerateKey(context.Background(), keyAttrs)
	require.NoError(t, err)

	jwtService, err := jwt.NewService(context.Background(), jwt.ServiceParams{
		Audience:   "localhost",
		Issuer:     "localhost",
		Expiration: 3600,
		KeyAttrs:   keyAttrs,
		XKMS:       xkms,
	})
	require.NoError(t, err)

	handler, err := jwt.NewRestHandler(
		logger, response.NewResponseWriter(logger, nil), jwtService, nil)
	require.NoError(t, err)

	user := entities.NewUser("admin")
	user.TenantID = "system"
	user.AddRole(&entities.Role{Name: common.ROLE_ADMIN})

	token, err := jwtService.GenerateToken(user)
	require.NoError(t, err)

	return handler, token
}

// probeWithCookie issues a request carrying the platform JWT the way the
// console does — in the `jwt` cookie, with no Authorization header.
func probeWithCookie(router *mux.Router, method, path, token string) int {
	req := httptest.NewRequest(method, path, nil)
	req.AddCookie(&http.Cookie{Name: "jwt", Value: token})
	req.Header.Set("Accept", "application/json")

	return serve(router, req)
}

// TestGatedRoutes_AdmitTheConsoleCookie proves the console's credential
// carrier survives the gate: a request with only the `jwt` cookie reaches the
// handler on every route slice 1 gates.
func TestGatedRoutes_AdmitTheConsoleCookie(t *testing.T) {
	handler, token := consoleAuthSeam(t)
	router := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: handler})

	for _, tc := range gatedProbes {
		t.Run(tc.name, func(t *testing.T) {
			code := probeWithCookie(router, tc.method, tc.path, token)
			assert.NotEqual(t, http.StatusUnauthorized, code,
				"the console's cookie was refused authentication")
			assert.NotEqual(t, http.StatusForbidden, code,
				"the console's cookie was refused authorization")
		})
	}
}

// TestGatedRoutes_RefuseTheSameRequestWithoutTheCookie is the control. Same
// router, same real verifier, same routes — only the cookie removed. Without
// it the test above would pass against a gate that admits everyone.
func TestGatedRoutes_RefuseTheSameRequestWithoutTheCookie(t *testing.T) {
	handler, _ := consoleAuthSeam(t)
	router := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: handler})

	for _, tc := range gatedProbes {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, http.StatusUnauthorized, probe(router, tc.method, tc.path))
		})
	}
}

// TestGatedRoutes_RefuseAForgedCookie closes the obvious way the two tests
// above could both pass while the gate checked nothing: a cookie this signer
// did not produce must be refused.
func TestGatedRoutes_RefuseAForgedCookie(t *testing.T) {
	handler, _ := consoleAuthSeam(t)
	router := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: handler})

	forged := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJlbWFpbCI6ImFkbWluIiwidGVuYW50X2lkIjoic3lzdGVtIiwicm9sZXMiOlsiYWRtaW4iXX0." +
		"not-a-signature"

	for _, tc := range gatedProbes {
		t.Run(tc.name, func(t *testing.T) {
			code := probeWithCookie(router, tc.method, tc.path, forged)
			assert.Contains(t,
				[]int{http.StatusUnauthorized, http.StatusBadRequest}, code,
				"a cookie this signer did not produce must not pass the gate")
		})
	}
}

// TestPublicRoutes_NeedNoCookie is the counterpart on the other side of the
// split: the trust-bootstrap fetch and the CRL must answer a client that has
// no cookie, because a client that does not trust the platform yet cannot
// have one.
func TestPublicRoutes_NeedNoCookie(t *testing.T) {
	handler, _ := consoleAuthSeam(t)
	router := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: handler})

	for _, path := range []string{"/api/v1/ca/bootstrap", "/api/v1/ca/crl"} {
		t.Run(path, func(t *testing.T) {
			code := probe(router, http.MethodGet, path)
			assert.NotEqual(t, http.StatusUnauthorized, code)
			assert.NotEqual(t, http.StatusForbidden, code)
		})
	}
}
