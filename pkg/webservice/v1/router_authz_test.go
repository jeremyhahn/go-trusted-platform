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
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
	restattestation "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/attestation"
	restregistry "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/registry"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cryptoclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/crypto"
	dekclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/dek"
	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	kmsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	secretsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/healthprobe"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	devicepkg "github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	dnsentities "github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning/configdelivery"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/adminclaim"
	webdevice "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/jwt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	iammw "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restgateway "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/gateway"
	restiam "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/iam"
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

// Zone serves no zone, so an admitted DNS probe answers from its handler
// instead of reaching the nil embedded service.
func (s *stubDNSService) Zone(context.Context, string) (*dnsentities.Zone, error) {
	return nil, dns.ErrZoneNotFound
}

type stubSwitchService struct {
	webdevice.SwitchServiceProvider
}

type stubEABServer struct {
	platformv1.UnimplementedEABServiceServer
}

type stubNTPServer struct {
	platformv1.UnimplementedNTPServiceServer
}

type stubVPNServer struct {
	platformv1.UnimplementedVPNServiceServer
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

// probeIAM and probePEP bring the IAM surface under the audit (#400).
//
// Router.iamRoutes registers the IAM router only when IAMClients() yields a
// non-nil IAM client. Until these existed the fixture yielded nil, the router
// returned early, and the built table carried zero /api/v1/iam routes -- so
// every route-table test in this package was blind to the platform's
// administration surface (70 routes: each capability registers unscoped and
// tenant-scoped, docs/iam/api.md §2).
//
// They embed the interface with no bodies, deliberately. iamRoutes reads only
// whether the client is non-nil, and the route-table tests never reach a
// handler body, so no method should ever be called here. If one is, the nil
// embedded interface panics, and serve() reports that as probeHandlerReached
// -- which is the CORRECT failure for a registration fixture: an ungated route
// that reaches its handler fails loudly instead of answering 200 with a
// plausible zero value, which is what a hand-written 43-method mock would do.
// A live quicbaas IAM service standing inside a fast in-process suite to
// satisfy a predicate that is `iamClient == nil` would buy no property this
// does not (ruling on #400; precedent: rest/iam/router_test.go's
// &mockIAMClient{}).
type probeIAM struct{ restiam.IAMClient }
type probePEP struct{ restiam.PEPClient }

// The four surfaces the fixture left unbuilt until #420. Each is served in
// production and had zero lines in the golden, so no route test could see
// it -- the #400 shape again. Same embedded-interface probe: no bodies, a
// reached handler nil-panics and serve() reports probeHandlerReached, which
// is the correct signal for a registration audit.
//
//   - probeACME registers /acme/** (router/acme.go). RFC 8555: the directory,
//     new-nonce and CA-bundle routes are public by protocol; every other route
//     is JWS-authenticated inside the xkms ACME server (docs/ca/api.md §5).
//   - probeDeviceHandler registers the mTLS-verified /device/{profile,
//     activate,heartbeat} (router/device.go RegisterMachineFacingRoutes);
//     probeBootHandler adds the diskless per-boot POST /device/boot behind
//     the same middleware (#690).
//     The middleware in front of it is the REAL middleware.NewMTLSMiddleware
//     over an empty pool, not a double: a plain-HTTP probe is refused 401 by
//     the same code path production runs, so the refusal under test is
//     production's. The pass-through mockMTLSMiddleware would certify the
//     wrong thing.
//   - the admin-claim ceremony (adminclaim.RestHandler) is built from
//     probe doubles of its four interface dependencies and an empty trust
//     anchor pool; its routes are pre-auth by design and protected by the
//     firstboot certificate proof in the handler (docs/auth/architecture.md
//     §6b).
//   - webauthn uses the existing mockWebAuthnHandler: its handlers are
//     no-ops that answer 200, which is exactly the property publicRoutes
//     asserts for a ceremony route.
type probeACME struct{ trustedca.ACMERestServicer }
type probeDeviceHandler struct{ webdevice.RestHandler }
type probeBootHandler struct{ webdevice.BootHandler }
type probeClaimCeremony struct{ adminclaim.FIDO2Ceremony }
type probeClaimFactors struct{ adminclaim.FactorLister }
type probeClaimUsers struct{ service.UserServicer }
type probeClaimIssuer struct{ adminclaim.TokenIssuer }

// adminClaimFixture builds the admin-claim REST handler the way
// HandlerRegistry.AdminClaimRestHandler does, over probe doubles. It fails
// the test rather than returning nil: a nil here would silently drop the
// five claim routes from the walk, which is the blind spot being closed.
func adminClaimFixture(t *testing.T, logger *logging.Logger, respWriter response.HttpWriter) *adminclaim.RestHandler {
	t.Helper()
	svc, err := adminclaim.NewService(adminclaim.ServiceParams{
		Logger:        logger,
		Ceremony:      &probeClaimCeremony{},
		Factors:       &probeClaimFactors{},
		Users:         &probeClaimUsers{},
		TokenIssuer:   &probeClaimIssuer{},
		TrustAnchors:  x509.NewCertPool(),
		TenantID:      "system",
		AdminUsername: common.AdminUsername,
		AdminEmail:    "admin@test.invalid",
	})
	require.NoError(t, err, "the admin-claim service must build in the fixture, or its routes vanish from the audit")
	handler, err := adminclaim.NewRestHandler(logger, respWriter, svc)
	require.NoError(t, err)
	return handler
}

// newGatedTestRouter builds the full v1 route table with every service the
// slice-1 gate covers wired, mounted under /api/v1 exactly as
// webserver_v1.buildRoutes does. The caller supplies the registry carrying
// the inbound authentication seam under test; everything else is filled in
// here so each test differs only in the credential it models.
func newGatedTestRouter(t *testing.T, registry *testHandlerRegistry) *mux.Router {
	t.Helper()

	v1Router := newGatedV1Router(t, registry)

	// Both halves, as webserver_v1.go mounts them: the root carries the
	// health probes the SDK's PlatformDaemon claims resolve to.
	root := mux.NewRouter()
	require.NoError(t, v1Router.RegisterRootRoutes(root))
	v1Router.RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())
	return root
}

// newGatedV1Router builds the v1 Router over registry with every service
// stubbed, before any route is registered.
func newGatedV1Router(t *testing.T, registry *testHandlerRegistry) *Router {
	t.Helper()

	logger := testLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	registry.responseWriter = respWriter
	registry.tpmService = &stubTPMServer{}
	if registry.tenantService == nil {
		registry.tenantService = &stubTenantServer{}
	}
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
	registry.vpnService = &stubVPNServer{}
	if registry.appServices == (restapi.AppServiceServers{}) {
		registry.appServices = restapi.AppServiceServers{
			Cache:     &countingCacheServer{},
			Scheduler: &countingSchedulerServer{},
			Messaging: &countingMessagingServer{},
		}
	}
	registry.overlayService = &stubOverlayServer{}
	registry.switchService = &stubSwitchService{}
	registry.sdnService = &stubSDNServer{}
	registry.gatewayService = &stubGatewayServer{}
	registry.gatewayStore = &stubGatewayStore{}
	registry.configDelivery = &stubConfigDelivery{}
	registry.pxeService = &stubPXEServer{}
	// The audit covers every route the platform can serve, so it mounts
	// the install-completion webhook too; operators turn it on (#238).
	registry.pxeWebhookEnabled = true
	registry.attestationService = &stubAttestationServer{}
	registry.deviceGRPCService = &stubDeviceGRPCServer{}
	registry.deviceTemplateService = &stubDeviceTemplateService{}
	registry.deviceProfileService = &stubDeviceProfileService{}
	registry.invitationService = &stubInvitationServer{}
	registry.iamClient = &probeIAM{}
	registry.pepClient = &probePEP{}
	registry.webauthn = &mockWebAuthnHandler{}
	registry.acmeService = &probeACME{}
	registry.deviceHandler = &probeDeviceHandler{}
	registry.bootHandler = &probeBootHandler{}
	registry.mtls = middleware.NewMTLSMiddleware(logger, respWriter, x509.NewCertPool())
	registry.adminClaim = adminClaimFixture(t, logger, respWriter)
	registry.tenantID = "system"

	v1Router, ok := NewRouter(logger, &stubCA{}, nil, nil, registry, respWriter).(*Router)
	require.True(t, ok, "NewRouter must build a *Router")
	return v1Router
}

// probe issues one credential-free request against a route template and
// reports the status code the wire saw.
//
// The concrete path comes from concreteFor (route_coverage_test.go), which
// gives a pattern-constrained placeholder a value its pattern ACCEPTS. The
// earlier substitution of the literal "probe" for every variable made 31
// numeric-pattern routes ({id:[0-9]+}) unreachable: mux matched nothing,
// answered 404, and denied() read that as a refusal -- a green produced by
// never reaching the route (#420). Positive control: with the EAB router
// ungated, the old probe flagged 5 of its 12 routes and stayed silent on
// the 7 with {id:[0-9]+}.
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
		httptest.NewRequest(method, testutil.ConcreteFor(template), nil))
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

// publicRoutes is the complete set of v1 and root routes that answer a caller
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

	// The WebAuthn ceremony (router/webauthn.go; docs/auth/api.md §3 and
	// §"WebAuthn REST browser contract"). Registration and login are how a
	// browser first obtains a session, so like /login they cannot sit behind
	// the credential they issue. Registration without an invitation token is
	// refused by the handler when self-service registration is off
	// (iam.self_service_registration, default false) -- a refusal the audit
	// cannot see, so it is recorded here rather than relied on. The walk
	// reports these as GET because the router registers them method-less.
	"GET /api/v1/webauthn/registration/begin":  "WebAuthn ceremony: begins registration; the credential is what the ceremony issues.",
	"GET /api/v1/webauthn/registration/finish": "WebAuthn ceremony: completes registration.",
	"GET /api/v1/webauthn/registration/status": "WebAuthn ceremony: whether a registration is complete; no session exists yet.",
	"GET /api/v1/webauthn/login/begin":         "WebAuthn ceremony: begins login; credential issuance, like /login.",
	"GET /api/v1/webauthn/login/finish":        "WebAuthn ceremony: completes login and issues the session.",

	// ACME, the public half (router/acme.go; docs/ca/api.md §5: "ACME
	// authenticates by its own protocol mechanisms (account keys, EAB) rather
	// than by platform tokens"). RFC 8555 §7.1.1 directory and §7.2 new-nonce
	// are the protocol's unauthenticated entry points, and the CA bundle is
	// the CA's own chain -- the same material /ca/bundle already publishes.
	"GET /api/v1/acme/directory":                       "RFC 8555 §7.1.1 directory; the unauthenticated entry point of the protocol.",
	"GET /api/v1/acme/new-nonce":                       "RFC 8555 §7.2 nonce; issued before any JWS can be signed.",
	"HEAD /api/v1/acme/new-nonce":                      "RFC 8555 §7.2 nonce, the HEAD form the RFC prescribes.",
	"GET /api/v1/acme/ca-bundle":                       "the CA's own chain, already published by /ca/bundle.",
	"GET /api/v1/acme/ca-bundle/{storeType}":           "the CA's own chain for one key store.",
	"GET /api/v1/acme/ca-bundle/{storeType}/{keyAlgo}": "the CA's own chain for one key store and algorithm.",

	// The admin-claim ceremony's status probe (adminclaim/handler.go;
	// docs/auth/api.md §2b: "Discloses no secret -- only whether the one-time
	// flow is still open, so the console can route a fresh node to its setup
	// page").
	"GET /api/v1/admin/claim/status": "admin-claim status: whether the one-time claim is still open; no secret disclosed (docs/auth/api.md §2b).",

	// A diskless node's IDevID chain (#690; docs/device/api.md). The node
	// keeps no disk, so it fetches its own chain before it can present it in
	// the mTLS handshake that POST /device/boot demands. It authenticates in
	// the request instead: a signature by the TPM-resident IDevID key over
	// the connection, checked against the recorded chain. Every other
	// request is refused alike, so a name alone learns nothing.
	"POST /api/v1/device/boot/certificate": "a diskless node's IDevID chain, released for proof of its TPM-resident key over the connection, needed before it can present that chain over mTLS (docs/device/api.md).",

	// The health probes at the host root (docs/health/api.md §7). Load
	// balancers, orchestrators and the SDK's Connect probe reach them before
	// any credential exists. The bodies carry the verdict only; the
	// component breakdown stays behind the admin chain at
	// /api/v1/platform/health.
	"GET /health":       "aggregate health for load balancers and the SDK's GetHealth; status only, 503 unless healthy.",
	"GET /health/live":  "liveness for orchestrators and the SDK's Connect probe; answers whenever the process does.",
	"GET /health/ready": "readiness for orchestrators; status only, 503 while a checker is unhealthy.",
}

// pendingRoutes is the rest of #165: routes still reachable without a
// credential because their tranche has not landed. It exists so the audit
// can be exact today — a NEW ungated route fails the test immediately —
// while the known remainder shrinks visibly, one slice at a time, until
// this map is empty and only publicRoutes is left.
//
// Slice 2 (platform, compute, registry, sdn, switch, overlay, gateway, dns,
// eab, attestation, ntp) and slice 3 (pxe, invitation, devices seeder, the
// account-factor and quicbaas stubs) empty it. /v2 was booked here as
// resolved by attestation; it was gated for real by #549 and is asserted
// by the root-router walk.
var pendingRoutes = map[string]string{

	// /attestation is GATED (#387), resolving the #165 hold. The ruling it
	// was waiting for landed with the #226 design: attestation is PULL —
	// the reporting server dials a node's POST /attestation/host with its
	// own nonce — so the caller of every quote-producing route is the
	// platform's own component holding an admin credential, not an
	// anonymous node push. Ungated, that route makes the TPM quote on
	// demand and returns PCR values to any host on the network.

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
	// The second route, POST /devices/templates/{id:[0-9]+}/create-profile,
	// was believed not to appear in the walk. It does -- it is in the golden
	// -- and the audit passed it only because the old probe could not reach
	// a numeric-pattern route (#420). It is reachable, unauthenticated, and
	// carries the same ruling as the first.
	//
	// The seeder's GET /devices/config is not in this table: it is mounted
	// only on the provisioning surface, never on the full one (#177).
	"POST /api/v1/devices/templates":                            "#121/#176 — bootstrap seeder; ruled to present admin@system over mTLS.",
	"POST /api/v1/devices/templates/{id:[0-9]+}/create-profile": "#121/#176 — bootstrap seeder; ruled to present admin@system over mTLS. Hidden from the audit until #420 made the probe pattern-aware.",

	// NOT justified — an open defect, listed here rather than in
	// publicRoutes precisely because it is not defensible. Its caller is a
	// booting node, but unlike every other machine-facing route this
	// campaign left open it presents NO credential and the server checks
	// none: the device is identified by a MAC address taken from the request
	// body. Choosing what a booting node should present is an architecture
	// decision, so #165 could not close it. See #238. Until then it is
	// mounted only when the operator sets pxe.ServiceConfig.WebhookEnabled.
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

	// ACME, the JWS-authenticated half (router/acme.go). Every one of these
	// is authenticated inside the xkms ACME server by the RFC 8555 §6.2 JWS
	// (account key or EAB) -- go-xkms pkg/acme/server/handlers/service.go --
	// and docs/ca/api.md §5 records that ACME does not use platform tokens.
	// Listed here rather than in publicRoutes for the same reason as the
	// provisioning routes: "authenticated by JWS" is a claim about the
	// handler that this audit cannot observe, and until #420's direct
	// assertion exists it is recorded, not proven.
	"POST /api/v1/acme/new-account":  "ACME: JWS-authenticated in the xkms server (RFC 8555 §7.3).",
	"POST /api/v1/acme/new-order":    "ACME: JWS-authenticated (RFC 8555 §7.4).",
	"POST /api/v1/acme/account/{id}": "ACME: JWS-authenticated account update (RFC 8555 §7.3.2).",
	"POST /api/v1/acme/authz/{id}":   "ACME: JWS-authenticated authorization (RFC 8555 §7.5).",
	// The GET form is registered alongside POST (router/acme.go) and is
	// authenticated the same way: the xkms handler parses the account JWS
	// before it dispatches on method (handlers/authorization.go), so a bare
	// GET fails at the account-key parse. RFC 8555 §6.3 prescribes
	// POST-as-GET for this resource; the GET registration is an upstream
	// shape, recorded here rather than judged.
	"GET /api/v1/acme/authz/{id}":           "ACME: JWS-authenticated authorization fetch; the handler parses the account JWS before dispatching on method.",
	"POST /api/v1/acme/challenge/{id}":      "ACME: JWS-authenticated challenge response (RFC 8555 §7.5.1).",
	"POST /api/v1/acme/order/{id}":          "ACME: JWS-authenticated order status (POST-as-GET, RFC 8555 §6.3).",
	"POST /api/v1/acme/order/{id}/finalize": "ACME: JWS-authenticated finalize (RFC 8555 §7.4).",
	"POST /api/v1/acme/orders":              "ACME: JWS-authenticated orders list (RFC 8555 §7.1.2.1).",
	"POST /api/v1/acme/cert/{id}":           "ACME: JWS-authenticated certificate download (POST-as-GET, RFC 8555 §7.4.2).",
	"POST /api/v1/acme/revoke-cert":         "ACME: JWS-authenticated revocation (RFC 8555 §7.6).",
	"POST /api/v1/acme/key-change":          "ACME: JWS-authenticated key rollover (RFC 8555 §7.3.5).",

	// The admin-claim ceremony's pre-auth steps (docs/auth/architecture.md
	// §6b). No session can exist before the system admin has been claimed, so
	// these run before any credential; the handler binds the challenge to a
	// possession proof against the firstboot admin certificate, chained to
	// the trust anchor. The passkey steps are not listed: they require the
	// claim token the verify step issues, and the walk sees them refuse.
	"POST /api/v1/admin/claim/challenge": "admin claim: issues a possession nonce; pre-auth by necessity (docs/auth/architecture.md §6b).",
	"POST /api/v1/admin/claim/verify":    "admin claim: exchanges the certificate proof for a claim token; the proof is the credential.",
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
// delivery handler, which brings /provisioning under the assertion. The
// /v2 OCI mount lives on the ROOT router rather than under /api/v1, so
// this walk cannot see it; TestRegisterRootRoutes_EveryRouteDeniesWithoutCredential
// walks that router. Until #549 the excuse written here was that /v2
// "authenticates by TPM attestation" — it did not: its backend is storage
// plus state checks and nothing on the path verified anything. A root
// mount is now gated like everything else, and the root walk is what
// stops the next one hiding behind the same assumption.
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

	for _, route := range testutil.WalkRoutes(t, router) {
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

// TestRegisterRootRoutes_EveryRouteDeniesWithoutCredential is the root-router
// half of the audit. Surfaces the platform must serve at the host root —
// today the OCI Distribution protocol at /v2 — are mounted by
// RegisterRootRoutes rather than under /api/v1, so the /api/v1 walk above
// never sees them. That blind spot is exactly where /v2 shipped
// unauthenticated (#549): a comment excused it as attestation-gated and no
// test could contradict the comment. This walk can. Every route the root
// router carries must refuse a credential-free request except the health
// probes declared in publicRoutes, which carry a verdict and nothing else — a
// registry client that reaches an ungated /v2/ is a client that could push.
func TestRegisterRootRoutes_EveryRouteDeniesWithoutCredential(t *testing.T) {
	root := newRootTestRouter(t, &testHandlerRegistry{
		tokenHandler:   &anonymousAuth{},
		ociDistBackend: &stubOCIDistBackend{},
	})

	routes := testutil.WalkRoutes(t, root)
	require.NotEmpty(t, routes, "the root fixture mounted nothing, so it proves nothing")
	for _, route := range routes {
		if _, ok := publicRoutes[route]; ok {
			continue
		}
		method, template := splitRoute(route)
		code := probe(root, method, template)
		// Stricter than denied(): every root route addresses a handler, so
		// a 404 here would mean the mount vanished, not that it refused.
		assert.True(t, code == http.StatusUnauthorized || code == http.StatusForbidden,
			"%s answered %d to a request carrying no credential. Root mounts go through "+
				"RegisterRootRoutes behind the caller gate and admin chain; only publicRoutes is public.",
			route, code)
	}
}

// TestRegisterRootRoutes_NilBackendMountsOnlyTheProbes pins the other half of
// the contract: with no distribution backend the registry is not configured
// on this node, and the root carries no /v2 at all — not an ungated one —
// only the health probes.
func TestRegisterRootRoutes_NilBackendMountsOnlyTheProbes(t *testing.T) {
	root := newRootTestRouter(t, &testHandlerRegistry{tokenHandler: &anonymousAuth{}})
	assert.ElementsMatch(t, probeRoutes, testutil.WalkRoutes(t, root))
}

// newRootTestRouter builds the v1 router on the same fixture as
// newGatedTestRouter and mounts only its root surfaces.
func newRootTestRouter(t *testing.T, registry *testHandlerRegistry) *mux.Router {
	t.Helper()
	logger := testLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	registry.responseWriter = respWriter
	registry.iamClient = &probeIAM{}
	registry.pepClient = &probePEP{}
	registry.tenantID = "system"

	v1Router := NewRouter(logger, &stubCA{}, nil, nil, registry, respWriter)
	root := mux.NewRouter()
	require.NoError(t, v1Router.RegisterRootRoutes(root))
	return root
}

// probeRoutes are the health probes RegisterRootRoutes mounts whether or not
// a distribution backend is configured.
var probeRoutes = []string{
	"GET " + healthprobe.HealthPath,
	"GET " + healthprobe.LivenessPath,
	"GET " + healthprobe.ReadinessPath,
}

// fixedHealthChecker reports a fixed status under a name, message and detail
// no probe body may carry.
type fixedHealthChecker struct {
	name   string
	status health.HealthStatus
}

func (c *fixedHealthChecker) Name() string { return c.name }

func (c *fixedHealthChecker) Check(ctx context.Context) health.ComponentHealth {
	return health.ComponentHealth{
		Name:    c.name,
		Status:  c.status,
		Message: "secret-message-" + c.name,
		Details: map[string]interface{}{"address": "10.9.8.7"},
	}
}

// The probes the webservice listener mounts at the root answer a caller with
// no credential, 503 when the probe fails, and name no component.
func TestRegisterRootRoutes_HealthProbesAnswerWithoutCredential(t *testing.T) {
	cases := map[health.HealthStatus]map[string]int{
		health.StatusHealthy: {
			healthprobe.HealthPath: http.StatusOK, healthprobe.LivenessPath: http.StatusOK, healthprobe.ReadinessPath: http.StatusOK},
		health.StatusDegraded: {
			healthprobe.HealthPath: http.StatusServiceUnavailable, healthprobe.LivenessPath: http.StatusOK, healthprobe.ReadinessPath: http.StatusOK},
		health.StatusUnhealthy: {
			healthprobe.HealthPath: http.StatusServiceUnavailable, healthprobe.LivenessPath: http.StatusOK, healthprobe.ReadinessPath: http.StatusServiceUnavailable},
	}
	for status, want := range cases {
		t.Run(string(status), func(t *testing.T) {
			registry := health.NewRegistry()
			t.Cleanup(func() {
				if err := registry.Close(); err != nil {
					t.Errorf("Close: %v", err)
				}
			})
			require.NoError(t, registry.Register(&fixedHealthChecker{name: "component-ca", status: health.StatusHealthy}))
			require.NoError(t, registry.Register(&fixedHealthChecker{name: "component-kms", status: status}))
			root := newRootTestRouter(t, &testHandlerRegistry{
				tokenHandler:   &anonymousAuth{},
				healthRegistry: registry,
			})

			for path, code := range want {
				recorder := httptest.NewRecorder()
				root.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
				assert.Equal(t, code, recorder.Code, "GET %s", path)
				for _, leak := range []string{"component-", "secret-message", "10.9.8.7"} {
					assert.NotContains(t, recorder.Body.String(), leak, "GET %s leaks %q", path, leak)
				}
			}
		})
	}
}

// stubOCIDistBackend mounts /v2 in the root fixture. Its methods are never
// reached by a credential-free probe; a probe that reaches one has already
// failed the audit, and the panic is reported as probeHandlerReached.
type stubOCIDistBackend struct{ restregistry.OCIDistBackend }

// TestRegisterRoutes_EveryDeclaredOpenRouteIsActuallyOpen is the other
// direction, and it is what stops the two maps above from decaying into
// documentation. A route listed as public or pending that has since been
// gated would otherwise sit there forever, quietly excusing a gate nobody
// needs and hiding the fact that the remaining work has shrunk.
func TestRegisterRoutes_EveryDeclaredOpenRouteIsActuallyOpen(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: &anonymousAuth{}})

	registered := map[string]bool{}
	for _, route := range testutil.WalkRoutes(t, router) {
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
	{"attestation host quote", http.MethodPost, "/api/v1/attestation/host"},
	{"attestation quote", http.MethodPost, "/api/v1/attestation/quote"},
	{"attestation manifests list", http.MethodGet, "/api/v1/attestation/manifests"},
	{"attestation manifest build", http.MethodPost, "/api/v1/attestation/manifests/build"},
	{"attestation events", http.MethodGet, "/api/v1/attestation/events"},
	{"tpm nvram read", http.MethodGet, "/api/v1/tpm/nvram/0x1c00002"},
	{"tpm nvram write", http.MethodPut, "/api/v1/tpm/nvram/0x1c00002"},
	{"tpm nvram undefine", http.MethodDelete, "/api/v1/tpm/nvram/0x1c00002"},
	{"tenant barrier unseal", http.MethodPost, "/api/v1/tenants/t1/barrier/unseal"},
	{"tenant barrier init", http.MethodPost, "/api/v1/tenants/t1/barrier/init"},
	{"tenant DEK rotate", http.MethodPost, "/api/v1/tenants/t1/dek/rotate"},
	{"tenant delete", http.MethodDelete, "/api/v1/tenants/t1"},
	{"kms decrypt", http.MethodPost, "/api/v1/kms/decrypt/k1"},
	{"kms sign", http.MethodPost, "/api/v1/kms/sign/k1"},
	{"kms secret read", http.MethodGet, "/api/v1/kms/secrets/s1"},
	{"kms key delete", http.MethodDelete, "/api/v1/kms/keys/k1"},
	{"kms generate data key", http.MethodPost, "/api/v1/kms/data-keys"},
	{"kms generate wrapped data key", http.MethodPost, "/api/v1/kms/data-keys/wrapped"},
	{"ca issue certificate", http.MethodPost, "/api/v1/ca/certificates"},
	{"ca revoke certificate", http.MethodDelete, "/api/v1/ca/certificates/abc"},
	{"idevid generate", http.MethodPost, "/api/v1/idevid/generate"},
	{"idevid delete", http.MethodDelete, "/api/v1/idevid"},
	{"idevid install certificate", http.MethodPost, "/api/v1/idevid/certificate"},
	{"idevid create ldevid", http.MethodPost, "/api/v1/idevid/ldevid"},
	{"idevid key delete, daemon path", http.MethodDelete, "/api/v1/tpm/idevid"},
	{"iak key delete, daemon path", http.MethodDelete, "/api/v1/tpm/iak"},
	{"vtpm bundle export", http.MethodGet, "/api/v1/vtpm/bundles/b1/export"},
	{"vtpm bundle delete", http.MethodDelete, "/api/v1/vtpm/bundles/b1"},
	{"vtpm start", http.MethodPost, "/api/v1/vtpm/bundles/b1/start"},
	{"vtpm stop", http.MethodPost, "/api/v1/vtpm/bundles/b1/stop"},
	{"vtpm state", http.MethodGet, "/api/v1/vtpm/bundles/b1/state"},
	{"vtpm quote", http.MethodPost, "/api/v1/vtpm/bundles/b1/quote"},
	{"vtpm seal", http.MethodPost, "/api/v1/vtpm/bundles/b1/seal"},
	{"vtpm unseal", http.MethodPost, "/api/v1/vtpm/bundles/b1/unseal"},
	{"vtpm pcr read", http.MethodGet, "/api/v1/vtpm/bundles/b1/pcrs"},
	{"vtpm pcr extend", http.MethodPost, "/api/v1/vtpm/bundles/b1/pcrs/extend"},
	{"dns record get", http.MethodGet, "/api/v1/dns/zones/example.com./records/A/www"},
	{"dns resolve", http.MethodGet, "/api/v1/dns/resolve?fqdn=www.example.com.&type=A"},
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
	for _, route := range testutil.WalkRoutes(t, router) {
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
// `vm migrate` moves a workload to another host, and `migration prepare`
// and `migration finalize` land one on this host.
var computeProbes = []struct {
	name   string
	method string
	path   string
}{
	{"vm create", http.MethodPost, "/api/v1/compute/vms"},
	{"vm delete", http.MethodDelete, "/api/v1/compute/vms/v1"},
	{"vm migrate", http.MethodPost, "/api/v1/compute/vms/v1/migrate"},
	{"migration prepare", http.MethodPost, "/api/v1/compute/migrations/prepare"},
	{"migration finalize", http.MethodPost, "/api/v1/compute/migrations/r1/finalize"},
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
	for _, route := range testutil.WalkRoutes(t, router) {
		registered[route] = true
	}
	for _, want := range []string{
		"POST /api/v1/compute/vms",
		"POST /api/v1/compute/vms/{id}/migrate",
		"POST /api/v1/compute/migrations/prepare",
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
	{"sdn add port", http.MethodPost, "/api/v1/sdn/bridges/br0/ports"},
	{"sdn authenticate port", http.MethodPost, "/api/v1/sdn/bridges/br0/ports/p1/auth"},
	{"sdn revoke port auth", http.MethodDelete, "/api/v1/sdn/bridges/br0/ports/p1/auth"},
	{"switch list ports", http.MethodGet, "/api/v1/switches/sw1/ports"},
	{"switch get port status", http.MethodGet, "/api/v1/switches/sw1/ports/1"},
	{"switch set port vlan", http.MethodPost, "/api/v1/switches/sw1/ports/1/vlan"},
	{"switch enable port", http.MethodPost, "/api/v1/switches/sw1/ports/1/enable"},
	{"switch disable port", http.MethodPost, "/api/v1/switches/sw1/ports/1/disable"},
	// Authorizing or quarantining a PXE device moves it between VLANs too.
	{"pxe update state", http.MethodPut, "/api/v1/pxe/devices/d1/state"},
	{"pxe authorize", http.MethodPost, "/api/v1/pxe/devices/d1/authorize"},
	{"pxe quarantine", http.MethodPost, "/api/v1/pxe/devices/d1/quarantine"},
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
	for _, route := range testutil.WalkRoutes(t, router) {
		registered[route] = true
	}
	for _, want := range []string{
		"DELETE /api/v1/sdn/bridges/{name}",
		"POST /api/v1/sdn/bridges/{name}/ports/{port}/auth",
		"DELETE /api/v1/sdn/bridges/{name}/ports/{port}/auth",
		"POST /api/v1/switches/{switch}/ports/{port}/vlan",
		"POST /api/v1/pxe/devices/{id}/authorize",
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
	for _, route := range testutil.WalkRoutes(t, router) {
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
	for _, route := range testutil.WalkRoutes(t, router) {
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
// #458 — the caller gate on the quote-producing routes must be REACHABLE
//
// #423 mounted /attestation/{host,quote} twice: once through RegisterRoutes
// on the admin-gated subrouter (no gate) and once on the bare router with the
// caller gate. mux dispatches to the first match, so the gated registration
// was dead code and every machine caller on the fleet got 401 from the
// operator chain. These drive the production Router with a client
// certificate on the connection and assert the gate's verdict is what the
// wire sees.
// =============================================================================

// authzStubPolicy is a CallerPolicy that returns one fixed decision and
// records that it was consulted.
type authzStubPolicy struct {
	decision  calleradmission.Decision
	evaluated int
}

func (p *authzStubPolicy) Evaluate(context.Context, *calleradmission.Peer) calleradmission.Decision {
	p.evaluated++
	return p.decision
}

func (p *authzStubPolicy) Describe() calleradmission.Description {
	return calleradmission.Description{Strategy: p.decision.Strategy}
}

func (p *authzStubPolicy) Anchors() []*x509.Certificate { return nil }

// machineCallerRequest is a credential-free POST whose TLS connection carries
// a peer certificate — what a reporting collector's dial looks like to the
// node. No bearer token: a machine caller never has one.
func machineCallerRequest(path string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: "node-05-compute-01"}}},
	}
	req.RemoteAddr = "10.4.2.143:41000"
	return req
}

func TestQuoteRoutes_RefusedMachineCallerGets403FromTheGate(t *testing.T) {
	for _, path := range []string{"/api/v1/attestation/host", "/api/v1/attestation/quote"} {
		t.Run(path, func(t *testing.T) {
			policy := &authzStubPolicy{decision: calleradmission.Decision{
				Admitted: false,
				Identity: "node-05-compute-01",
				Strategy: calleradmission.StrategyReportingServers,
				Reason:   calleradmission.ReasonNotListed,
			}}
			router := newGatedTestRouter(t, &testHandlerRegistry{
				tokenHandler:         &anonymousAuth{},
				attestationReporting: &restattestation.Reporting{Policy: policy},
			})

			code := serve(router, machineCallerRequest(path))

			assert.Equal(t, 1, policy.evaluated,
				"the caller-admission policy was never consulted: the gated registration is shadowed")
			assert.Equal(t, http.StatusForbidden, code,
				"a refused machine caller must see the gate's 403, not the operator chain's 401")
		})
	}
}

func TestQuoteRoutes_AdmittedMachineCallerBypassesTheOperatorChain(t *testing.T) {
	policy := &authzStubPolicy{decision: calleradmission.Decision{
		Admitted: true,
		Identity: "cp.example.internal",
		Strategy: calleradmission.StrategyReportingServers,
		Reason:   calleradmission.ReasonAdmitted,
	}}
	router := newGatedTestRouter(t, &testHandlerRegistry{
		tokenHandler:         &anonymousAuth{},
		attestationReporting: &restattestation.Reporting{Policy: policy},
	})

	code := serve(router, machineCallerRequest("/api/v1/attestation/host"))

	assert.Equal(t, 1, policy.evaluated)
	assert.NotEqual(t, http.StatusUnauthorized, code,
		"an admitted machine caller was handed to the operator chain")
	assert.NotEqual(t, http.StatusForbidden, code,
		"an admitted machine caller was refused")
}

func TestQuoteRoutes_WithoutAPolicyTheOperatorChainStillGates(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: &anonymousAuth{}})

	assert.Equal(t, http.StatusUnauthorized, serve(router, machineCallerRequest("/api/v1/attestation/host")),
		"with no caller policy a certificate alone must not open the quote route")
	assert.Equal(t, http.StatusUnauthorized, probe(router, http.MethodPost, "/api/v1/attestation/host"),
		"an operator without a token must still be refused")
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
		// The lookup by name is not system-only: a tenant resolves its own
		// name (router_tenant_byname_test.go).
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
	for _, r := range testutil.WalkRoutes(t, router) {
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

// scopedSessionAuth is a session carrying roles AND scopes. Like the
// platform-token middleware it is also the router's ScopeAuthorizer, so the
// routes that take a scope check it; the legacy sessionAuth does not.
type scopedSessionAuth struct {
	sessionAuth
	scopes []string
}

// Verify publishes the session and, as PlatformTokenMiddleware.Verify does
// for a platform token, the AuthorizedContext carrying the token's scopes.
func (s *scopedSessionAuth) Verify(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	ctx := iammw.SetAuthorizedContext(r.Context(), &platformtoken.AuthorizedContext{
		Subject:  "probe-user",
		TenantID: s.tenantID,
		Roles:    s.roles,
		Scopes:   s.scopes,
	})
	s.sessionAuth.Verify(w, r.WithContext(ctx), next)
}

func (s *scopedSessionAuth) RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !slices.Contains(s.scopes, scope) {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// pxeOperatorProbes is every PXE operator route and the PXEService RPC it
// stands for. The route must take the scope the gRPC catalog gives the RPC.
var pxeOperatorProbes = []struct{ method, path, rpc string }{
	{http.MethodGet, "/api/v1/pxe/status", "GetStatus"},
	{http.MethodPost, "/api/v1/pxe/start", "StartService"},
	{http.MethodPost, "/api/v1/pxe/stop", "StopService"},
	{http.MethodGet, "/api/v1/pxe/devices", "ListDevices"},
	{http.MethodPost, "/api/v1/pxe/devices", "RegisterDevice"},
	{http.MethodGet, "/api/v1/pxe/devices/mac/{mac}", "GetDeviceByMAC"},
	{http.MethodGet, "/api/v1/pxe/devices/{id}", "GetDevice"},
	{http.MethodDelete, "/api/v1/pxe/devices/{id}", "RemoveDevice"},
	{http.MethodPut, "/api/v1/pxe/devices/{id}/state", "UpdateState"},
	{http.MethodPost, "/api/v1/pxe/devices/{id}/enrolled", "SetDeviceEnrolled"},
	{http.MethodPost, "/api/v1/pxe/devices/{id}/authorize", "Authorize"},
	{http.MethodPost, "/api/v1/pxe/devices/{id}/quarantine", "Quarantine"},
	{http.MethodPost, "/api/v1/pxe/devices/{id}/retry", "Retry"},
	{http.MethodGet, "/api/v1/pxe/devices/{id}/events", "GetEvents"},
}

// pxeScopedAdmin builds the gated router for an admin session holding scopes.
func pxeScopedAdmin(t *testing.T, scopes ...string) *mux.Router {
	return newGatedTestRouter(t, &testHandlerRegistry{
		tokenHandler: &scopedSessionAuth{
			sessionAuth: sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: "system"},
			scopes:      scopes,
		},
	})
}

// TestPXEOperatorRoutes_RefuseTheAdminRoleWithoutTheRPCScope closes the gap
// where REST was wider than gRPC: an admin token holding every pxe scope but
// the one the route's RPC needs is refused, as gRPC refuses the RPC.
func TestPXEOperatorRoutes_RefuseTheAdminRoleWithoutTheRPCScope(t *testing.T) {
	pxeScopes := []string{"pxe:read", "pxe:write", "pxe:delete"}
	for _, tc := range pxeOperatorProbes {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			scope := grpcapi.ScopeForMethod("/platform.v1.PXEService/" + tc.rpc)
			require.NotEmpty(t, scope, "%s is not in the gRPC catalog", tc.rpc)
			others := slices.DeleteFunc(slices.Clone(pxeScopes), func(s string) bool { return s == scope })

			assert.Equal(t, http.StatusForbidden, probe(pxeScopedAdmin(t, others...), tc.method, tc.path))
		})
	}
}

// TestPXEOperatorRoutes_AdmitTheAdminRoleWithTheRPCScope: the role and the
// RPC's scope together reach the service. The stub service implements no
// RPC, so reaching it answers 501.
func TestPXEOperatorRoutes_AdmitTheAdminRoleWithTheRPCScope(t *testing.T) {
	for _, tc := range pxeOperatorProbes {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			scope := grpcapi.ScopeForMethod("/platform.v1.PXEService/" + tc.rpc)
			require.NotEmpty(t, scope, "%s is not in the gRPC catalog", tc.rpc)

			assert.Equal(t, http.StatusNotImplemented, probe(pxeScopedAdmin(t, scope), tc.method, tc.path))
		})
	}
}

// TestPXEOperatorRoutes_ScopeAloneDoesNotPassTheRoleGate: the scope is on top
// of the admin gate, not instead of it.
func TestPXEOperatorRoutes_ScopeAloneDoesNotPassTheRoleGate(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{
		tokenHandler: &scopedSessionAuth{
			sessionAuth: sessionAuth{roles: []string{"user"}, tenantID: "system"},
			scopes:      []string{"pxe:read", "pxe:write", "pxe:delete"},
		},
	})
	for _, tc := range pxeOperatorProbes {
		assert.Equal(t, http.StatusForbidden, probe(router, tc.method, tc.path), "%s %s", tc.method, tc.path)
	}
}

// =============================================================================
// IAM (#400)
// =============================================================================

// iamRoutesUnderAudit returns every IAM handler route the fixture built,
// i.e. every walked route under /api/v1/iam/ except the bare prefix entry
// the PathPrefix subrouter itself contributes (it has no handler; a request
// matching only it answers 404).
//
// It requires the count rather than merely the presence: rest/iam/router.go
// registers each capability twice (docs/iam/api.md §2) — 33 flat routes and
// 38 tenant-scoped ones — and a fixture that silently lost one tree would
// otherwise pass the per-route assertions over the other.
func iamRoutesUnderAudit(t *testing.T, router *mux.Router) []string {
	t.Helper()

	const wantIAMRoutes = 71
	var routes []string
	for _, route := range testutil.WalkRoutes(t, router) {
		_, template := splitRoute(route)
		if strings.HasPrefix(template, "/api/v1/iam/") {
			routes = append(routes, route)
		}
	}
	require.Lenf(t, routes, wantIAMRoutes,
		"the fixture built %d IAM handler routes, not %d. iamRoutes() registers "+
			"the surface only when IAMClients() yields a non-nil client; if this is 0 "+
			"the probe is unwired and every route test in this package is blind to "+
			"IAM again (#400)", len(routes), wantIAMRoutes)
	return routes
}

// TestIAMRoutes_AreRegisteredAndGated asserts, per route, what
// TestRegisterRoutes_EveryRouteDeniesWithoutCredential asserts in aggregate:
// every IAM route the platform builds refuses a caller with no credential.
// The aggregate test cannot notice the IAM tree going missing — it would
// iterate a smaller set and pass — so the count check in
// iamRoutesUnderAudit is the half this test adds.
func TestIAMRoutes_AreRegisteredAndGated(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: &anonymousAuth{}})

	for _, route := range iamRoutesUnderAudit(t, router) {
		method, template := splitRoute(route)
		assert.Equalf(t, http.StatusUnauthorized, probe(router, method, template),
			"%s did not answer 401 to a request carrying no credential", route)
	}
}

// TestIAMRoutes_RejectAuthenticatedCallersWithoutTheAdminRole exercises the
// role half of the IAM gate through the platform's own authorization()
// wiring: a verified session that lacks the admin role is refused on every
// IAM route, flat and tenant-scoped alike (docs/iam/api.md §8).
func TestIAMRoutes_RejectAuthenticatedCallersWithoutTheAdminRole(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{
		tokenHandler: &sessionAuth{roles: []string{"user"}, tenantID: "system"},
	})

	for _, route := range iamRoutesUnderAudit(t, router) {
		method, template := splitRoute(route)
		assert.Equalf(t, http.StatusForbidden, probe(router, method, template),
			"%s did not answer 403 to an authenticated caller without the admin role", route)
	}
}

// TestIAMPermissionCheckRoutes_AreGated pins the gate on the permission-check
// routes #452 registered for the SDK's CheckPermission claim. The check is a
// read-tier decision, but it sits behind the same admin gate as every other
// /api/v1/iam route (docs/iam/api.md §8): no credential is 401 and a
// non-admin session is 403, on the flat route and its tenant-scoped twin.
// Requiring the routes in the audited set first keeps a 401 from an
// unregistered path from passing for the gate.
func TestIAMPermissionCheckRoutes_AreGated(t *testing.T) {
	anonymous := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: &anonymousAuth{}})
	underPrivileged := newGatedTestRouter(t, &testHandlerRegistry{
		tokenHandler: &sessionAuth{roles: []string{"user"}, tenantID: "system"},
	})
	built := iamRoutesUnderAudit(t, anonymous)

	for _, template := range []string{
		"/api/v1/iam/permissions/check",
		"/api/v1/iam/tenants/{tenant}/permissions/check",
	} {
		require.Containsf(t, built, http.MethodPost+" "+template, "%s is not registered", template)
		assert.Equalf(t, http.StatusUnauthorized, probe(anonymous, http.MethodPost, template),
			"POST %s did not answer 401 to a request carrying no credential", template)
		assert.Equalf(t, http.StatusForbidden, probe(underPrivileged, http.MethodPost, template),
			"POST %s did not answer 403 to an authenticated caller without the admin role", template)
	}
}

// TestIAMRoutes_TenantGuardsAreWiredToThePlatformSession asserts the two
// guards Router.iamRoutes builds from the platform's own state, which
// rest/iam's tests cannot see because they inject their own:
//
//   - RequireSystemTenant is bound to restHandlerRegistry.TenantID() (the
//     fixture's "system"), so an admin in any other tenant is refused on the
//     tenant-record routes;
//   - RequireOwnTenant reads mux.Vars(r)["tenant"], so the same admin is
//     refused on every tenant-scoped route that names a tenant other than
//     their own (probe() substitutes "probe" for {tenant}).
//
// The flat routes carry neither guard: the same admin is admitted to them,
// which is the positive control that the 403s above come from the tenant
// guards and not from the role gate.
func TestIAMRoutes_TenantGuardsAreWiredToThePlatformSession(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{
		tokenHandler: &sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: "acme"},
	})

	var tenantGuarded, flat int
	for _, route := range iamRoutesUnderAudit(t, router) {
		method, template := splitRoute(route)
		code := probe(router, method, template)
		if strings.HasPrefix(template, "/api/v1/iam/tenants") {
			tenantGuarded++
			assert.Equalf(t, http.StatusForbidden, code,
				"%s admitted an admin from tenant acme; the system-tenant or own-tenant guard is not wired", route)
			continue
		}
		flat++
		assert.NotEqualf(t, http.StatusUnauthorized, code, "%s refused the admin authentication", route)
		assert.NotEqualf(t, http.StatusForbidden, code, "%s refused the admin authorization", route)
	}
	require.Equal(t, 38, tenantGuarded, "tenant-record plus tenant-scoped routes")
	require.Equal(t, 33, flat, "flat routes")
}

// TestIAMRoutes_SystemTenantAdminReachesTenantLifecycle is the other half of
// the RequireSystemTenant wiring: the guard admits the tenant it is bound to.
// A guard that refused everyone would pass the test above and still be a
// fault (an unreachable admin surface, per rest/iam.Authorization).
func TestIAMRoutes_SystemTenantAdminReachesTenantLifecycle(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{
		tokenHandler: &sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: "system"},
	})

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/iam/tenants"},
		{http.MethodPost, "/api/v1/iam/tenants"},
		{http.MethodGet, "/api/v1/iam/tenants/{tenant}"},
		{http.MethodPut, "/api/v1/iam/tenants/{tenant}"},
		{http.MethodDelete, "/api/v1/iam/tenants/{tenant}"},
	} {
		code := probe(router, tc.method, tc.path)
		assert.NotEqualf(t, http.StatusUnauthorized, code, "%s %s refused the system admin authentication", tc.method, tc.path)
		assert.NotEqualf(t, http.StatusForbidden, code, "%s %s refused the system admin authorization", tc.method, tc.path)
	}
}
