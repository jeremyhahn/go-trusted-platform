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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	devicepkg "github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning/configdelivery"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	webdevice "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/jwt"
	iammw "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restgateway "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/gateway"
	restplatform "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/platform"
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

type stubComputeServer struct {
	platformv1.UnimplementedComputeServiceServer
}

type stubRegistryService struct{ grpcapi.RegistryService }

type stubDNSService struct{ dns.DNSService }
type stubSwitchService struct {
	webdevice.SwitchServiceProvider
}

type stubEABServer struct {
	platformv1.UnimplementedEABServiceServer
}

type stubNTPServer struct {
	platformv1.UnimplementedNTPServiceServer
}

type stubOverlayServer struct {
	platformv1.UnimplementedOverlayServiceServer
}

type stubSDNServer struct {
	platformv1.UnimplementedSDNServiceServer
}

type stubGatewayServer struct {
	platformv1.UnimplementedGatewayServiceServer
}

type stubGatewayStore struct{ restgateway.GatewayStateStore }

// stubConfigDelivery makes the device router register /provisioning/**, which
// closes the audit blind spot that slice 1 recorded for that prefix.
type stubConfigDelivery struct{ configdelivery.RestHandler }

type stubPXEServer struct {
	platformv1.UnimplementedPXEServiceServer
}

// stubAttestationServer brings /attestation under the audit. Its routes are
// NOT gated — see pendingRoutes — but wiring it means the remaining work is
// enumerated by the test rather than described in prose.
type stubAttestationServer struct {
	platformv1.UnimplementedAttestationServiceServer
}

// stubDeviceGRPCServer brings POST /devices/{id}/attest under the audit.
//
// Wiring it is the point, not a formality: the route registers only when a
// DeviceServiceServer is present, so a fixture that left this nil would omit
// the route from the walk entirely and the audit would report a clean run
// over a surface it never saw. That is exactly the blind spot #121 recorded
// for the seeder router — a gate claim is only as wide as the fixture behind
// it.
type stubDeviceGRPCServer struct {
	platformv1.UnimplementedDeviceServiceServer
}

// The bootstrap seeder router (pkg/webservice/v1/rest/device) registers only
// when BOTH of these are wired. Without them its three routes were invisible
// to the audit — a blind spot in the coverage claim, not a gap in the gate.
type stubDeviceTemplateService struct {
	devicepkg.DeviceTemplateService
}
type stubDeviceProfileService struct{ devicepkg.DeviceProfileService }

type stubInvitationServer struct {
	platformv1.UnimplementedInvitationServiceServer
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
	registry.platformRouter = restplatform.NewPlatformRouter(logger, respWriter)
	registry.computeService = &stubComputeServer{}
	registry.registryService = &stubRegistryService{}
	registry.dnsService = &stubDNSService{}
	registry.eabService = &stubEABServer{}
	registry.ntpService = &stubNTPServer{}
	registry.overlayService = &stubOverlayServer{}
	registry.switchService = &stubSwitchService{}
	registry.sdnService = &stubSDNServer{}
	registry.gatewayService = &stubGatewayServer{}
	registry.gatewayStore = &stubGatewayStore{}
	registry.configDelivery = &stubConfigDelivery{}
	registry.pxeService = &stubPXEServer{}
	registry.attestationService = &stubAttestationServer{}
	registry.deviceGRPCService = &stubDeviceGRPCServer{}
	registry.deviceTemplateService = &stubDeviceTemplateService{}
	registry.deviceProfileService = &stubDeviceProfileService{}
	registry.invitationService = &stubInvitationServer{}
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

	// The invitee-facing half of /invitations (#165 slice 3, #171). The
	// invitation token IS the credential: both handlers take it from the URL
	// or the body and hand it to the service. An invitee has no platform
	// session by construction — that is what an invitation is for — so a
	// role guard here would not deny requests, it would make invitations
	// unacceptable.
	"GET /api/v1/invitations/token/{token}": "the invitation token is the credential; the invitee has no session yet.",
	"POST /api/v1/invitations/accept":       "same ceremony — accepting is how the invitee first gets a session.",
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

	// /attestation is held ENTIRELY, console-shaped routes included, and
	// that is deliberate rather than an oversight. The router is mixed —
	// manifest reads and the build/verify verbs are operator work, while
	// POST /attestation/{host,vm/{id},container/{id}} are node pushes — but
	// the split axis depends on what a node presents, which could not be
	// established: pkg/attestation/push/client.go supports per-target
	// Bearer/Basic credentials yet posts to an arbitrary configured
	// endpoint, so it is unproven that these routes are its target or what
	// role a node token would carry. Gating the operator half alone would
	// bake in a boundary the ruling may move. Escalated on #165.
	"GET /api/v1/attestation/manifests":         "#165 — awaiting the node-push credential ruling.",
	"POST /api/v1/attestation/manifests/build":  "#165 — awaiting the node-push credential ruling.",
	"POST /api/v1/attestation/manifests/verify": "#165 — awaiting the node-push credential ruling.",
	"GET /api/v1/attestation/manifests/{id}":    "#165 — awaiting the node-push credential ruling.",
	"DELETE /api/v1/attestation/manifests/{id}": "#165 — awaiting the node-push credential ruling.",
	"POST /api/v1/attestation/quote":            "#165 — awaiting the node-push credential ruling.",
	"POST /api/v1/attestation/quote/verify":     "#165 — awaiting the node-push credential ruling.",
	"POST /api/v1/attestation/host":             "#165 — node push; credential unestablished.",
	"POST /api/v1/attestation/vm/{id}":          "#165 — node push; credential unestablished.",
	"POST /api/v1/attestation/container/{id}":   "#165 — node push; credential unestablished.",

	// The bootstrap seeder (pkg/webservice/v1/rest/device). ALWAYS live in a
	// running platformd — the services it registers behind are constructed
	// unconditionally (#121) — so these are reachable, unauthenticated
	// routes today, not a conditional surface. Its caller is the seeder
	// running during node bring-up, and the owner ruled on 2026-09-02
	// (#121/#176) that it presents `admin@system` over **mTLS**.
	// That is a different seam from this campaign's role guard: mounting
	// gated() in front of it would demand a bearer token or cookie from a
	// caller whose credential is a client certificate. Recorded here rather
	// than gated, because implementing the ruled seam is that issue's work,
	// not #165's.
	//
	// The third route, POST /devices/templates/{id}/create-profile, does not
	// appear because the walk only reports routes a request can reach; it
	// shares the /devices/templates prefix with the gated CRUD aliases.
	"GET /api/v1/devices/config":     "#121/#176 — bootstrap seeder; ruled to present admin@system over mTLS.",
	"POST /api/v1/devices/templates": "#121/#176 — bootstrap seeder; ruled to present admin@system over mTLS.",

	// NOT justified — an open defect, listed here rather than in
	// publicRoutes precisely because it is not defensible. Its caller is a
	// booting node, but unlike every other machine-facing route this
	// campaign left open it presents NO credential and the server checks
	// none: the device is identified by a MAC address taken from the request
	// body. Choosing what a booting node should present is an architecture
	// decision, so #165 could not close it. See #238.
	"POST /api/v1/pxe/webhook/complete": "#238 — authenticates nobody; identifies the device by an attacker-supplied MAC.",

	// /provisioning was split by principal in slice 3: the session views and
	// fulfilment took the admin gate, and these stay open because a machine at
	// boot has no client certificate — the router says so in terms — and the
	// handlers authenticate it by EAB, plus the EK for signing. They are listed
	// here rather than in publicRoutes because "authenticates by EAB" is a claim
	// about the HANDLER that this audit cannot observe: it sees a refusal, not
	// who refused. Verifying that claim is its own work.
	"POST /api/v1/provisioning/config":                   "device-facing, EAB-authenticated in the handler.",
	"GET /api/v1/provisioning/config/nonce":              "replay nonce for the EAB exchange above.",
	"POST /api/v1/provisioning/sign":                     "device-facing Secure Boot DB signing, EAB+EK authenticated in the handler.",
	"GET /api/v1/provisioning/sessions/{sessionID}/poll": "device-facing: polled by the provisioning client while it waits for an operator to fulfil its session.",
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
// # What a green run here does NOT prove
//
// This test observes a REFUSAL. It cannot distinguish
//
//	gated                     — refused by #165's role guard
//	self-authenticating       — refused by the route's own check, e.g.
//	                            /gateway/telemetry's mTLS client certificate
//	would-be-gated-if-gated   — refused for an unrelated reason
//
// so it would stay green through a regression that deleted a
// self-authenticating route's own check entirely. Every such route needs a
// direct assertion of its own — see
// TestGatewayFacingRoutes_RefuseACallerWithNoClientCertificate and
// TestGatewayFacingRoutes_AreNotBehindTheRoleGate, which exist for exactly
// that reason. An audit whose blind spots are written down can be trusted
// within them; one whose blind spots are unknown cannot be trusted at all.
//
// Its reach is bounded by newGatedTestRouter's wiring, and deliberately
// stated rather than implied: a router whose backing service is nil never
// registers, so it is neither asserted nor excused here.
//
// The fixture now wires every service slices 1 and 2 gate, plus the config
// delivery handler, which brings /provisioning under the assertion. What
// remains outside it is the /v2 OCI mount, which webserver_v1 registers on
// the ROOT router rather than under /api/v1 — this walk cannot see it, and
// it is deliberately never role-gated because it authenticates by TPM
// attestation.
//
// Slice 3 additionally wired the bootstrap seeder's template and profile
// services, which brings /devices/{config,templates} under the assertion.
// Those are ungated by ruling rather than by omission — see pendingRoutes.
//
// The guard those routes register behind — `templateService != nil &&
// profileService != nil` in v1Router.deviceRoutes — reads like a real
// condition and is not one: pkg/app/app.go:909-915 constructs both
// unconditionally and calls FatalError on failure, so BOTH are always
// non-nil in a running platformd (#121). The guard is only ever false in a
// fixture. So these routes were not "maybe live and invisible" — they were
// always live, always unauthenticated, and invisible purely because this
// fixture did not build the services. That is the sharpest form of the rule
// below: a nil in a fixture can hide a route that production always serves.
//
// Slice 1 also named /bmc here. That was wrong: the webservice serves no
// /bmc route. pkg/webservice/v1/router/bmc.go exists but NewBMCRouter has
// no non-test caller, and the live BMC surface belongs to the second REST
// server tracked on #232. It is not this audit's blind spot, and the
// unreferenced router is filed separately.
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

// =============================================================================
// Slice 2 — /platform
// =============================================================================

// platformProbes are the /platform routes chosen for blast radius: the ones
// whose unauthenticated reachability #165 calls out by name.
var platformProbes = []struct {
	name   string
	method string
	path   string
}{
	{"config read", http.MethodGet, "/api/v1/platform/config"},
	{"config reload", http.MethodPost, "/api/v1/platform/config/reload"},
	{"snapshot rollback", http.MethodPost, "/api/v1/platform/config/snapshots/s1/rollback"},
	{"snapshot delete", http.MethodDelete, "/api/v1/platform/config/snapshots/s1"},
	{"service stop", http.MethodPost, "/api/v1/platform/services/tpm/stop"},
	{"service restart", http.MethodPost, "/api/v1/platform/services/tpm/restart"},
	{"log query", http.MethodGet, "/api/v1/platform/logs"},
	{"log stream", http.MethodGet, "/api/v1/platform/logs/stream"},
	{"health detail", http.MethodGet, "/api/v1/platform/health"},
	{"metrics", http.MethodGet, "/api/v1/platform/metrics"},
}

// TestPlatformRoutes_AreRegisteredAndGated is the guard against a vacuous
// pass: if the platform router failed to register, every probe below would
// answer 404, `denied` would call that a refusal, and the audit would be
// green while asserting nothing. So the route table is checked for the
// routes first, and only then are they required to deny.
func TestPlatformRoutes_AreRegisteredAndGated(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: &anonymousAuth{}})

	registered := map[string]bool{}
	for _, route := range walkRoutes(t, router) {
		registered[route] = true
	}
	for _, want := range []string{
		"GET /api/v1/platform/config",
		"POST /api/v1/platform/config/reload",
		"POST /api/v1/platform/config/snapshots/{id}/rollback",
		"POST /api/v1/platform/services/{service}/stop",
		"GET /api/v1/platform/logs/stream",
		"GET /api/v1/platform/health",
	} {
		require.True(t, registered[want],
			"%s did not register; the gate assertion below would be vacuous", want)
	}

	for _, tc := range platformProbes {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, http.StatusUnauthorized, probe(router, tc.method, tc.path))
		})
	}
}

// TestPlatformRoutes_RejectAuthenticatedCallersWithoutTheAdminRole is the
// authorization half for /platform.
func TestPlatformRoutes_RejectAuthenticatedCallersWithoutTheAdminRole(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{
		tokenHandler: &sessionAuth{roles: []string{"user"}, tenantID: "system"},
	})

	for _, tc := range platformProbes {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, http.StatusForbidden, probe(router, tc.method, tc.path))
		})
	}
}

// TestPlatformRoutes_AdmitTheConsoleCookie proves the console still reaches
// its own Platform pages — config, logs, health and metrics are all read by
// the dashboard, so this is the surface most likely to break on a gate.
func TestPlatformRoutes_AdmitTheConsoleCookie(t *testing.T) {
	handler, token := consoleAuthSeam(t)
	router := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: handler})

	for _, tc := range platformProbes {
		t.Run(tc.name, func(t *testing.T) {
			code := probeWithCookie(router, tc.method, tc.path, token)
			assert.NotEqual(t, http.StatusUnauthorized, code)
			assert.NotEqual(t, http.StatusForbidden, code)
		})
	}
}

// TestServiceRegistryEndpoint_SurvivesTheGatedPlatformSubtree is the
// fallthrough regression this slice most plausibly breaks.
//
// /platform/service-registry is registered on the UNGATED router while the
// rest of /platform now lives behind the gate, so a request for it is first
// offered to the gated group's /platform subrouter, finds no match there,
// and must fall through to the public route rather than being answered 401
// by the group it merely passed through. That behaviour is a property of
// gorilla/mux's matcher chain, not of anything this repo controls, so it is
// asserted rather than assumed.
func TestServiceRegistryEndpoint_SurvivesTheGatedPlatformSubtree(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: &anonymousAuth{}})

	code := probe(router, http.MethodGet, "/api/v1/platform/service-registry")
	assert.NotEqual(t, http.StatusUnauthorized, code,
		"the deliberately public service registry was swallowed by the gated /platform subtree")
	assert.NotEqual(t, http.StatusNotFound, code,
		"the service registry stopped resolving once /platform moved behind the gate")
	assert.Equal(t, http.StatusOK, code)
}

// computeProbes are the compute and curated-image routes chosen for blast
// radius. `container exec` is arbitrary code execution inside a workload;
// `vm migrate` moves a workload to another host.
var computeProbes = []struct {
	name   string
	method string
	path   string
}{
	{"vm create", http.MethodPost, "/api/v1/compute/vms"},
	{"vm delete", http.MethodDelete, "/api/v1/compute/vms/v1"},
	{"vm migrate", http.MethodPost, "/api/v1/compute/vms/v1/migrate"},
	{"vm snapshot restore", http.MethodPost, "/api/v1/compute/vms/v1/snapshots/s1/restore"},
	{"vm disk detach", http.MethodDelete, "/api/v1/compute/vms/v1/disks/d1"},
	{"vm list", http.MethodGet, "/api/v1/compute/vms"},
	{"container exec", http.MethodPost, "/api/v1/compute/containers/c1/exec"},
	{"container delete", http.MethodDelete, "/api/v1/compute/containers/c1"},
	{"image push", http.MethodPost, "/api/v1/compute/images"},
	{"image delete", http.MethodDelete, "/api/v1/compute/images/repo/name"},
	{"image list", http.MethodGet, "/api/v1/compute/images"},
}

// TestComputeRoutes_AreRegisteredAndGated guards against a vacuous pass the
// same way the platform test does: prove the routes exist before requiring
// them to deny, since an unregistered route answers 404 and 404 counts as a
// refusal.
func TestComputeRoutes_AreRegisteredAndGated(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: &anonymousAuth{}})

	registered := map[string]bool{}
	for _, route := range walkRoutes(t, router) {
		registered[route] = true
	}
	for _, want := range []string{
		"POST /api/v1/compute/vms",
		"POST /api/v1/compute/vms/{id}/migrate",
		"POST /api/v1/compute/containers/{id}/exec",
		"POST /api/v1/compute/images",
		"DELETE /api/v1/compute/images/{repository:.+}",
	} {
		require.True(t, registered[want],
			"%s did not register; the gate assertion below would be vacuous", want)
	}

	for _, tc := range computeProbes {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, http.StatusUnauthorized, probe(router, tc.method, tc.path))
		})
	}
}

// TestComputeRoutes_RejectAuthenticatedCallersWithoutTheAdminRole is the
// authorization half.
func TestComputeRoutes_RejectAuthenticatedCallersWithoutTheAdminRole(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{
		tokenHandler: &sessionAuth{roles: []string{"user"}, tenantID: "system"},
	})

	for _, tc := range computeProbes {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, http.StatusForbidden, probe(router, tc.method, tc.path))
		})
	}
}

// TestComputeImagesRoutesStillPrecedeTheComputeStub pins the ordering the
// two surfaces depend on. /compute/images belongs to the registry and
// /compute to the orchestrator; mux matches in registration order, so
// computeImagesRoutes must register first or an unconfigured compute
// service's catch-all 503 would shadow the live image surface. Moving both
// behind one memoised gated group preserves that order — this asserts it
// rather than trusting that it did.
func TestComputeImagesRoutesStillPrecedeTheComputeStub(t *testing.T) {
	handler, token := consoleAuthSeam(t)
	router := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: handler})

	// A GET that only the registry router declares. If the compute stub or
	// the compute router shadowed it, this would not reach the registry.
	code := probeWithCookie(router, http.MethodGet, "/api/v1/compute/images/status", token)
	assert.NotEqual(t, http.StatusUnauthorized, code)
	assert.NotEqual(t, http.StatusForbidden, code)
	assert.NotEqual(t, http.StatusNotFound, code,
		"/compute/images/status stopped resolving once both surfaces moved behind the gate")
}

// networkProbes are the network-fabric routes. Flow rules ARE the policy
// this platform enforces, a VLAN move relocates a machine between network
// zones, and a VNI is a tenant's layer-2 isolation boundary.
var networkProbes = []struct {
	name   string
	method string
	path   string
}{
	{"sdn add flow", http.MethodPost, "/api/v1/sdn/bridges/br0/flows"},
	{"sdn delete bridge", http.MethodDelete, "/api/v1/sdn/bridges/br0"},
	{"sdn delete port", http.MethodDelete, "/api/v1/sdn/bridges/br0/ports/p1"},
	{"switch set port vlan", http.MethodPost, "/api/v1/switches/sw1/ports/1/vlan"},
	{"switch disable port", http.MethodPost, "/api/v1/switches/sw1/ports/1/disable"},
	{"overlay create vni", http.MethodPost, "/api/v1/overlay/vnis"},
	{"overlay delete vni", http.MethodDelete, "/api/v1/overlay/vnis/100"},
	{"dns zone list", http.MethodGet, "/api/v1/dns/zones"},
	{"eab create", http.MethodPost, "/api/v1/eab/credentials"},
	{"ntp step", http.MethodPost, "/api/v1/ntp/step"},
}

// TestNetworkRoutes_AreRegisteredAndGated covers the sdn / switch / overlay /
// dns / eab / ntp group. None of these has a machine caller: the only
// in-repo consumers are the console and the SDK REST adapter, which attaches
// a bearer token when its context carries one.
func TestNetworkRoutes_AreRegisteredAndGated(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: &anonymousAuth{}})

	registered := map[string]bool{}
	for _, route := range walkRoutes(t, router) {
		registered[route] = true
	}
	for _, want := range []string{
		"DELETE /api/v1/sdn/bridges/{name}",
		"POST /api/v1/switches/{switch}/ports/{port}/vlan",
		"POST /api/v1/overlay/vnis",
		"POST /api/v1/ntp/step",
	} {
		require.True(t, registered[want],
			"%s did not register; the gate assertion below would be vacuous", want)
	}

	for _, tc := range networkProbes {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, http.StatusUnauthorized, probe(router, tc.method, tc.path))
		})
	}
}

// TestNetworkRoutes_RejectAuthenticatedCallersWithoutTheAdminRole is the
// authorization half for the network group.
func TestNetworkRoutes_RejectAuthenticatedCallersWithoutTheAdminRole(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{
		tokenHandler: &sessionAuth{roles: []string{"user"}, tenantID: "system"},
	})

	for _, tc := range networkProbes {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, http.StatusForbidden, probe(router, tc.method, tc.path))
		})
	}
}

// =============================================================================
// Gateway — split by principal, not by verb
// =============================================================================

// TestGatewayOperatorRoutes_AreRegisteredAndGated covers the operator half:
// the GatewayService controls and the fleet-wide /gateway/state surface.
func TestGatewayOperatorRoutes_AreRegisteredAndGated(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: &anonymousAuth{}})

	registered := map[string]bool{}
	for _, route := range walkRoutes(t, router) {
		registered[route] = true
	}
	for _, want := range []string{
		"POST /api/v1/gateway/bgp/prefixes",
		"DELETE /api/v1/gateway/bgp/prefixes",
		"POST /api/v1/gateway/ipam/allocations",
		"GET /api/v1/gateway/state",
		"DELETE /api/v1/gateway/state/{id}",
	} {
		require.True(t, registered[want],
			"%s did not register; the gate assertion below would be vacuous", want)
	}

	for _, tc := range []struct{ name, method, path string }{
		{"bgp announce", http.MethodPost, "/api/v1/gateway/bgp/prefixes"},
		{"bgp withdraw", http.MethodDelete, "/api/v1/gateway/bgp/prefixes"},
		{"ipam allocate", http.MethodPost, "/api/v1/gateway/ipam/allocations"},
		{"set gateway mode", http.MethodPost, "/api/v1/gateway/mode"},
		{"fleet state list", http.MethodGet, "/api/v1/gateway/state"},
		{"clear gateway record", http.MethodDelete, "/api/v1/gateway/state/g1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, http.StatusUnauthorized, probe(router, tc.method, tc.path))
		})
	}
}

// TestGatewayFacingRoutes_RefuseACallerWithNoClientCertificate is the
// assertion that keeps the audit's green from being accidental.
//
// /gateway/telemetry and /gateway/desired-config/{id} are NOT behind the
// role gate — they authenticate themselves with a verified mTLS client
// certificate, because their caller is gatewayd and its credential is a
// certificate, not a bearer token. The default-deny audit therefore passes
// them for a reason unrelated to #165's gate, and a regression that removed
// their own authentication would keep the audit green while opening the
// fleet's telemetry and desired-config surface to anyone.
//
// So the refusal is asserted here directly, against the routes as the v1
// router actually mounts them.
func TestGatewayFacingRoutes_RefuseACallerWithNoClientCertificate(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: &anonymousAuth{}})

	registered := map[string]bool{}
	for _, route := range walkRoutes(t, router) {
		registered[route] = true
	}
	require.True(t, registered["POST /api/v1/gateway/telemetry"])
	require.True(t, registered["GET /api/v1/gateway/desired-config/{id}"])

	assert.Equal(t, http.StatusUnauthorized,
		probe(router, http.MethodPost, "/api/v1/gateway/telemetry"),
		"telemetry accepted a caller presenting no client certificate")
	assert.Equal(t, http.StatusUnauthorized,
		probe(router, http.MethodGet, "/api/v1/gateway/desired-config/g1"),
		"desired-config served a caller presenting no client certificate")
}

// TestGatewayFacingRoutes_AreNotBehindTheRoleGate is the converse, and it
// is the one that would catch the tempting mistake: sweeping the whole
// /gateway prefix behind the admin gate for tidiness. A gateway presenting
// a valid client certificate and no bearer token must still be served, or
// every gateway in the fleet stops reporting.
func TestGatewayFacingRoutes_AreNotBehindTheRoleGate(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: &anonymousAuth{}})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/desired-config/gw-1", nil)
	req.TLS = &tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{
			{Subject: pkix.Name{CommonName: "gw-1"}},
		}},
	}

	code := serve(router, req)
	assert.NotEqual(t, http.StatusUnauthorized, code,
		"a gateway with a verified client certificate was refused authentication; "+
			"the role gate has been mounted in front of the gatewayd-facing half")
	assert.NotEqual(t, http.StatusForbidden, code,
		"a gateway with a verified client certificate naming its own id was refused authorization")
}

// =============================================================================
// #234 — the within-tenant boundary, end to end
//
// #165 gated /api/v1/tenants on the admin role. That says the CALLER is an
// administrator; it cannot say they administer the tenant they named, and
// every route under /{id} takes its target tenant from the URL. These assert
// the boundary through the v1 router as production mounts it.
// =============================================================================

// tenantScopedProbes are the routes whose target tenant comes from the path.
var tenantScopedProbes = []struct{ name, method, path string }{
	{"read another tenant", http.MethodGet, "/api/v1/tenants/tenant-b"},
	{"delete another tenant", http.MethodDelete, "/api/v1/tenants/tenant-b"},
	{"suspend another tenant", http.MethodPost, "/api/v1/tenants/tenant-b/suspend"},
	{"rewrite another tenant's quotas", http.MethodPut, "/api/v1/tenants/tenant-b/quotas"},
	{"rotate another tenant's DEK", http.MethodPost, "/api/v1/tenants/tenant-b/dek/rotate"},
	{"unseal another tenant's barrier", http.MethodPost, "/api/v1/tenants/tenant-b/barrier/unseal"},
	{"read another tenant's barrier", http.MethodGet, "/api/v1/tenants/tenant-b/barrier"},
}

// TestTenantRoutes_DenyAnAdminOfAnotherTenant is #234. The caller holds
// "admin" — a perfectly valid credential — inside tenant-a, and names
// tenant-b in the path.
func TestTenantRoutes_DenyAnAdminOfAnotherTenant(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{
		tokenHandler: &sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: "tenant-a"},
	})

	for _, tc := range tenantScopedProbes {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, http.StatusForbidden, probe(router, tc.method, tc.path),
				"an admin of tenant-a reached tenant-b")
		})
	}
}

// TestTenantRoutes_AdmitTheSystemTenant is the control that keeps the guard
// from being a wall. platformctl drives this surface as a system admin naming
// a tenant, so denying it would break the only caller it has — and the naive
// RequireOwnTenant would have done exactly that.
func TestTenantRoutes_AdmitTheSystemTenant(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{
		tokenHandler: &sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: "system"},
	})

	for _, tc := range tenantScopedProbes {
		t.Run(tc.name, func(t *testing.T) {
			code := probe(router, tc.method, tc.path)
			assert.NotEqual(t, http.StatusForbidden, code,
				"the system tenant was denied its own control-plane surface")
			assert.NotEqual(t, http.StatusUnauthorized, code)
		})
	}
}

// TestTenantRoutes_AdmitATenantReadingItself is the other half of the
// disjunction, and the sentence in docs/auth/architecture.md §6c that says
// what this surface is for: "A tenant admin reads their own tenant through
// /api/v1/tenants".
func TestTenantRoutes_AdmitATenantReadingItself(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{
		tokenHandler: &sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: "tenant-a"},
	})

	code := probe(router, http.MethodGet, "/api/v1/tenants/tenant-a")
	assert.NotEqual(t, http.StatusForbidden, code, "a tenant was denied a read of itself")
	assert.NotEqual(t, http.StatusUnauthorized, code)
}

// TestTenantRoutes_CrossTenantOperationsAreSystemOnly covers the routes that
// name no single tenant and therefore act across all of them. A tenant admin
// holds "admin" inside their own tenant and must not enumerate or create
// tenants with it — the decision #159 already made for /api/v1/iam/tenants.
//
// by-name is in this set for an additional reason it cannot escape: tenant
// ids are UUIDs, so comparing the NAME in the path against the session's
// tenant id would deny every caller including a tenant's own.
func TestTenantRoutes_CrossTenantOperationsAreSystemOnly(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{
		tokenHandler: &sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: "tenant-a"},
	})

	for _, tc := range []struct{ name, method, path string }{
		{"list every tenant", http.MethodGet, "/api/v1/tenants"},
		{"create a tenant", http.MethodPost, "/api/v1/tenants"},
		{"sync tenants", http.MethodPost, "/api/v1/tenants/sync"},
		{"look a tenant up by name", http.MethodGet, "/api/v1/tenants/by-name/victim"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, http.StatusForbidden, probe(router, tc.method, tc.path),
				"a tenant-scoped admin reached a cross-tenant operation")
		})
	}
}

// TestRegisterRoutes_DeviceAttestIsRegisteredAndGated asserts the device
// attestation route both EXISTS in the finished route table and sits behind
// the admin gate.
//
// The existence half is the one that matters. POST /devices/{id}/attest
// registers only when a DeviceServiceServer is wired, so a fixture that left
// it nil would produce a route table without the route — and the default-deny
// walk would then pass by never seeing it. That is precisely the blind spot
// #121 recorded for the bootstrap seeder router, where a guard requiring two
// services made three reachable routes invisible to the audit. Asserting the
// route is present converts "the walk found nothing wrong" into "the walk
// looked at this".
func TestRegisterRoutes_DeviceAttestIsRegisteredAndGated(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: &anonymousAuth{}})

	const route = "POST /api/v1/devices/{id}/attest"

	var found bool
	for _, r := range walkRoutes(t, router) {
		if r == route {
			found = true
			break
		}
	}
	require.True(t, found,
		"%s must be in the route table; if it is absent the default-deny walk "+
			"passes over a surface it never saw", route)

	// And it must be gated: attestation reads a device's enrolled key and
	// reports a security verdict about that machine.
	_, open := publicRoutes[route]
	assert.False(t, open, "%s must not be declared a public route", route)
	_, pending := pendingRoutes[route]
	assert.False(t, pending, "%s must not be parked as pending; it is gated today", route)
}
