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
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/healthprobe"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restattestation "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/attestation"
	restca "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/ca"
	restcompute "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/compute"
	restdevice "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/device"
	restdns "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/dns"
	resteab "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/eab"
	restgateway "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/gateway"
	restiam "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/iam"
	restidevid "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/idevid"
	restinvitation "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/invitation"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/kms"
	restntp "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/ntp"
	restoverlay "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/overlay"
	restpxe "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/pxe"
	restregistry "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/registry"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/sdn"
	switchapi "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/switch"
	resttenant "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/tenant"
	resttpm "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/tpm"
	restvpn "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/vpn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
)

// Router mounts the versioned API and the host-root surfaces.
var _ router.RootRouter = (*Router)(nil)

type Router struct {
	baseURI             string
	baseServiceURI      string
	ca                  trustedca.CACertificateAuthority
	caConfig            *trustedca.CAConfig
	restHandlerRegistry RestHandlerRegistry
	logger              *logging.Logger
	router              *mux.Router
	responseWriter      response.HttpWriter
	serverKeyAttributes *xkmssdk.KeyAttributes
	serviceRegistry     *ServiceRegistry
	// gatedGroups memoises one protected route group per role set. See
	// gated() in authz.go.
	gatedGroups map[string]*mux.Router
	router.WebServiceRouter
}

func NewRouter(
	logger *logging.Logger,
	ca trustedca.CACertificateAuthority,
	caConfig *trustedca.CAConfig,
	serverKeyAttribtues *xkmssdk.KeyAttributes,
	restHandlerRegistry RestHandlerRegistry,
	responseWriter response.HttpWriter) router.RootRouter {

	return &Router{
		ca:                  ca,
		caConfig:            caConfig,
		logger:              logger,
		restHandlerRegistry: restHandlerRegistry,
		serverKeyAttributes: serverKeyAttribtues,
		responseWriter:      responseWriter,
		serviceRegistry:     NewServiceRegistry(logger, responseWriter),
		gatedGroups:         make(map[string]*mux.Router),
	}
}

// Registers all websocket and REST services
// RegisterRootRoutes mounts the surfaces the platform serves at the host
// root rather than under /api/v1: the health probes and the OCI
// Distribution protocol, which its spec fixes at /v2/ (#549).
//
// The probes — GET /health, /health/live and /health/ready — are
// unauthenticated so load balancers and orchestrators can reach them; their
// bodies carry the verdict only, never a component (docs/health/api.md §4).
// The component breakdown stays admin-gated at /api/v1/platform/health.
//
// The registry's authentication method is TPM attestation, so /v2 takes
// the two principals the attestation quote routes take: a machine caller
// admitted by the node's caller-admission policy (mTLS identity chained to
// the platform anchors, then the configured strategy), or an operator
// through the admin chain when no machine identity is presented. A refused
// machine caller is refused, not offered the operator path. Reads and
// writes are gated separately so the read policy can widen on its own.
//
// A nil distribution backend means the registry is not configured on this
// node, and nothing is mounted — the same rule every service router
// applies to a nil service. Anything else that stops the mount is an
// error, never a silent skip.
func (v1Router *Router) RegisterRootRoutes(root *mux.Router) error {
	healthprobe.NewHandlers(v1Router.restHandlerRegistry.HealthRegistry).RegisterRoutes(root)

	backend := v1Router.restHandlerRegistry.OCIDistBackend()
	if backend == nil {
		v1Router.logger.Debug("OCI distribution backend is nil - /v2 not registered")
		return nil
	}
	gate := v1Router.callerGate()
	operator := v1Router.operatorChain(common.ROLE_ADMIN)
	gates := restregistry.OCIDistGates{
		Read:  func(next http.Handler) http.Handler { return gate.Wrap(next, operator) },
		Write: func(next http.Handler) http.Handler { return gate.Wrap(next, operator) },
	}
	return restregistry.RegisterOCIDistRoutes(root, v1Router.logger, backend, gates,
		restregistry.DefaultOCIDistLimits())
}

// RegisterEdgeRoutes mounts on root the one API group a public edge
// listener may carry: the ACME server under the versioned prefix, so
// `/api/v1/acme/directory` is the same URL on every surface (#571).
// Nothing else — no console, no other API group, no registry — is
// mounted; the edge surface's remaining routes are the web server's
// virtual hosts and its TLS redirect. It reports whether ACME was
// mounted: a gateway node has no ACME server (the control plane does),
// and its edge is a pure reverse-proxy listener.
func (v1Router *Router) RegisterEdgeRoutes(root *mux.Router, baseURI string) bool {
	if v1Router.restHandlerRegistry.ACMERestService() == nil {
		v1Router.logger.Debug("ACME service is nil - edge surface carries no API route")
		return false
	}
	v1Router.router = root.PathPrefix(baseURI).Subrouter()
	v1Router.gatedGroups = make(map[string]*mux.Router)
	v1Router.acmeRoutes()
	return true
}

// RegisterProvisioningRoutes mounts on root the one route a provisioning
// listener carries: GET {baseURI}/devices/config, the boot-time config fetch
// (#177). The route is unauthenticated by design — its caller is a machine
// still booting with no credential — so it is served only from a listener
// bound inside the isolated provisioning zone, and no other surface mounts
// it. It reports whether the route was mounted: without the device profile
// service there is nothing to deliver.
func (v1Router *Router) RegisterProvisioningRoutes(root *mux.Router, baseURI string) bool {
	profileService := v1Router.restHandlerRegistry.DeviceProfileService()
	if profileService == nil {
		v1Router.logger.Debug("Device profile service is nil - provisioning surface carries no route")
		return false
	}
	restdevice.NewDeviceRouter(
		v1Router.logger,
		v1Router.restHandlerRegistry.ResponseWriter(),
		nil,
		profileService,
	).RegisterConfigRoute(root.PathPrefix(baseURI).Subrouter())
	return true
}

// callerGate builds the machine-caller gate from the node's caller-admission
// policy. With no policy configured the gate hands every request to the
// operator chain; the policy can only narrow who else gets in.
func (v1Router *Router) callerGate() *restattestation.CallerGate {
	rep := v1Router.restHandlerRegistry.AttestationReporting()
	var policy restattestation.CallerPolicy
	if rep != nil && rep.Policy != nil {
		policy = rep.Policy
	}
	return restattestation.NewCallerGate(v1Router.logger, policy, v1Router.responseWriter)
}

func (v1Router *Router) RegisterRoutes(router *mux.Router) {
	v1Router.router = router
	// Protected route groups are per-mux; a router rebuilt onto a fresh
	// mux must not reuse the previous mux's groups.
	v1Router.gatedGroups = make(map[string]*mux.Router)
	v1Router.platformRoutes()
	v1Router.systemRoutes()
	v1Router.authenticationRoutes()
	v1Router.adminClaimRoutes()
	v1Router.webAuthnRoutes()
	v1Router.acmeRoutes()
	v1Router.attestationRoutes()
	v1Router.bmcRoutes()
	v1Router.caRoutes()
	// computeImagesRoutes MUST register before computeRoutes: mux matches
	// in registration order, and when compute is unconfigured its
	// catch-all 503 stub on /compute would otherwise shadow the
	// registry-backed /compute/images surface.
	v1Router.computeImagesRoutes()
	v1Router.computeRoutes()
	v1Router.deviceRoutes()
	v1Router.dnsRoutes()
	v1Router.eabRoutes()
	v1Router.gatewayRoutes()
	v1Router.iamRoutes()
	v1Router.idevidRoutes()
	v1Router.invitationRoutes()
	v1Router.kmsRoutes()
	v1Router.overlayRoutes()
	v1Router.ntpRoutes()
	v1Router.vpnRoutes()
	v1Router.appServiceRoutes()
	v1Router.pxeRoutes()
	v1Router.sdnRoutes()
	v1Router.switchRoutes()
	v1Router.tenantRoutes()
	v1Router.tpmRoutes()
	v1Router.vtpmRoutes()
	v1Router.quicbaasStubRoutes()

	// Always mount /platform/service-registry last so it observes the
	// full set of *Routes() outcomes recorded above. The endpoint is
	// public-but-useful even without auth — it only reports wire state,
	// never sensitive config — so the platform Services tab can show
	// dark surfaces without a token.
	if v1Router.serviceRegistry != nil {
		v1Router.serviceRegistry.RegisterStatusEndpoint(v1Router.router)
	}
}

// quicbaasStubRoutes registers placeholder GET handlers for QuicBaaS
// surfaces the dashboard probes (Storage Objects, KV, etc.) so the UI
// renders the empty state instead of a "the requested API endpoint
// does not exist" 404 banner. Real QuicBaaS REST surface mounting is
// tracked separately; until then these stubs return empty collections.
// quicbaasStubRoutes mounts the placeholder surfaces the dashboard probes.
// They are gated with the rest of the console's API: a stub that echoes a
// caller's JSON back as a created object is not sensitive today, but these
// are placeholders for real QuicBaaS storage, KV, time-series, vector and
// backup surfaces, and the route table is where the gate is decided. Wiring
// a real backend behind an already-gated route is safe; behind an ungated
// one it publishes the backend.
//
// #165's own table names these and /users/{id}/factors as the ungated set
// registered directly on the v1 router, so gating them is what closes that
// row rather than an expansion of it.
func (v1Router *Router) quicbaasStubRoutes() {
	stub := func(payload map[string]any) func(w http.ResponseWriter, r *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			v1Router.restHandlerRegistry.ResponseWriter().Success200(w, r, payload)
		}
	}
	// `mutationStub` echoes whatever JSON body the client sent back as
	// the payload (with a generated identifier when one isn't already
	// supplied) so the WebUI's optimistic mutations land on a 200/201
	// rather than a 404. Real QuicBaaS POST/PUT/DELETE wiring is
	// tracked separately; until then this lets the user complete the
	// full create flow with the dialog closing and the table
	// refreshing.
	mutationStub := func(idField string) func(w http.ResponseWriter, r *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			body := map[string]any{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if idField != "" {
				if _, ok := body[idField]; !ok {
					body[idField] = fmt.Sprintf("stub-%d", time.Now().UnixNano())
				}
			}
			body["created_at"] = time.Now().UTC().Format(time.RFC3339)
			v1Router.restHandlerRegistry.ResponseWriter().Success200(w, r, body)
		}
	}
	deleteStub := func() func(w http.ResponseWriter, r *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			v1Router.restHandlerRegistry.ResponseWriter().Success200(w, r, map[string]any{"deleted": true})
		}
	}

	// Auth-factor endpoints used by /account/security. The full
	// implementation lives in the IAM service; until that's wired up
	// return an empty factor list so the page can render its empty
	// state instead of an inline 404 alert.
	gated := v1Router.gated(common.ROLE_ADMIN)

	gated.HandleFunc("/users/{id}/factors",
		stub(map[string]any{"factors": []any{}, "total": 0})).Methods("GET")

	gated.HandleFunc("/quicbaas/storage/buckets",
		stub(map[string]any{"buckets": []any{}, "total": 0})).Methods("GET")
	gated.HandleFunc("/quicbaas/storage/buckets",
		mutationStub("name")).Methods("POST")
	gated.HandleFunc("/quicbaas/storage/buckets/{name}",
		deleteStub()).Methods("DELETE")
	gated.HandleFunc("/quicbaas/storage/buckets/{name}/objects",
		stub(map[string]any{"objects": []any{}, "total": 0})).Methods("GET")
	gated.HandleFunc("/quicbaas/storage/buckets/{name}/objects/{object:.*}",
		deleteStub()).Methods("DELETE")

	gated.HandleFunc("/quicbaas/kv",
		stub(map[string]any{"entries": []any{}, "total": 0})).Methods("GET")
	gated.HandleFunc("/quicbaas/kv",
		mutationStub("key")).Methods("POST")
	gated.HandleFunc("/quicbaas/kv/{key}",
		deleteStub()).Methods("DELETE")

	gated.HandleFunc("/quicbaas/timeseries/metrics",
		stub(map[string]any{"metrics": []any{}, "total": 0})).Methods("GET")
	gated.HandleFunc("/quicbaas/timeseries/metrics",
		mutationStub("name")).Methods("POST")

	gated.HandleFunc("/quicbaas/vector/collections",
		stub(map[string]any{"collections": []any{}, "total": 0})).Methods("GET")
	gated.HandleFunc("/quicbaas/vector/collections",
		mutationStub("name")).Methods("POST")
	gated.HandleFunc("/quicbaas/vector/namespaces",
		stub(map[string]any{"namespaces": []any{}, "total": 0})).Methods("GET")
	gated.HandleFunc("/quicbaas/vector/namespaces",
		mutationStub("name")).Methods("POST")

	gated.HandleFunc("/quicbaas/backup/snapshots",
		stub(map[string]any{"snapshots": []any{}, "total": 0})).Methods("GET")
	gated.HandleFunc("/quicbaas/backup/snapshots",
		mutationStub("id")).Methods("POST")
	gated.HandleFunc("/quicbaas/backups",
		stub(map[string]any{"backups": []any{}, "total": 0})).Methods("GET")
	gated.HandleFunc("/quicbaas/backups",
		mutationStub("id")).Methods("POST")
}

// authMiddleware resolves the single inbound authentication seam every
// protected route shares. Precedence:
//  1. Broker platform-token validator (pure-validator inbound path) when
//     JWT.PlatformToken.Enabled — validates broker-issued, JWKS-published,
//     DPoP-bound tokens (iss/aud/exp + cnf.jkt) and maps scp -> RBAC +
//     tenant_id -> RLS.
//  2. Legacy locally minted JWT handler.
//
// Both publish the verified identity as an iam.IAMSession in the request
// context, which is what the RBAC route guards read. The WebAuthn handler
// is deliberately NOT a candidate: its Verify is a pass-through that
// authenticates nothing (see webauthn.WebAuthnRestHandler.Verify).
func (v1Router *Router) authMiddleware() middleware.AuthMiddleware {
	if platformToken := v1Router.restHandlerRegistry.PlatformTokenMiddleware(); platformToken != nil {
		return platformToken
	}
	return v1Router.restHandlerRegistry.JSONWebTokenHandler()
}

func (v1Router *Router) systemRoutes() {
	authMiddleware := v1Router.authMiddleware()
	systemRouter := router.NewSystemRouter(
		v1Router.logger,
		v1Router.ca,
		v1Router.caConfig,
		v1Router.serverKeyAttributes,
		v1Router.restHandlerRegistry.JSONWebTokenHandler(),
		authMiddleware,
		v1Router.router,
		v1Router.responseWriter,
		v1Router.restHandlerRegistry.TPM())
	systemRouter.RegisterRoutes(v1Router.router)
}

// adminClaimRoutes mounts the one-time platform-admin claim ceremony. Its
// routes are pre-auth by necessity — no session can exist before the
// system admin has been claimed — and are protected instead by the
// firstboot certificate proof (docs/auth/architecture.md §Admin claim).
func (v1Router *Router) adminClaimRoutes() {
	handler := v1Router.restHandlerRegistry.AdminClaimRestHandler()
	if handler == nil {
		v1Router.logger.Debug("Admin claim handler is nil - admin claim routes not registered")
		return
	}
	handler.RegisterRoutes(v1Router.router)
}

func (v1Router *Router) authenticationRoutes() {
	registrationRouter := router.NewAuthenticationRouter(
		v1Router.restHandlerRegistry.JSONWebTokenHandler())
	registrationRouter.RegisterRoutes(v1Router.router)
}

func (v1Router *Router) webAuthnRoutes() {
	webAuthnService := v1Router.restHandlerRegistry.WebAuthnRestService()
	if webAuthnService == nil {
		v1Router.logger.Debug("WebAuthn not configured - WebAuthn routes not registered")
		return
	}
	webAuthnRouter := router.NewWebAuthnRouter(
		v1Router.restHandlerRegistry.JSONWebTokenHandler(),
		webAuthnService)
	webAuthnRouter.RegisterRoutes(v1Router.router)
}

func (v1Router *Router) acmeRoutes() {
	if v1Router.restHandlerRegistry.ACMERestService() == nil {
		return
	}
	acmeRouter := router.NewACMERouter(
		v1Router.restHandlerRegistry.ACMERestService())
	acmeRouter.RegisterRoutes(v1Router.router)
}

// caRoutes mounts the CA surface in two halves. Certificate issuance,
// revocation and the issued-certificate inventory require an authenticated
// admin; the CA's own chain, its CRL and the trust-bootstrap fetch stay
// public because the clients that need them have no credential yet, or
// because the material is already published in every TLS handshake. The
// division and its justification live on the two RegisterRoutes methods.
//
// The service-registry 503 stub for an unconfigured CA stays on the
// ungated router: it reports only that the surface is dark, which is
// exactly what the deliberately public /platform/service-registry already
// reports.
func (v1Router *Router) caRoutes() {
	v1Router.serviceRegistry.requireService(
		v1Router.router, "ca", "/ca", v1Router.ca,
		func() {
			kmsClient, _, _, _ := v1Router.restHandlerRegistry.KMSSDKClients()
			caRouter := restca.NewCARouter(
				v1Router.logger,
				v1Router.ca,
				v1Router.responseWriter).WithKMS(issuance.ClientKMS(kmsClient))
			// Renew and verify are served by the same CA service gRPC
			// serves; without it they answer 503.
			if server := v1Router.restHandlerRegistry.CAServiceServer(); server != nil {
				caRouter.WithService(server)
			}
			if scoped, ok := v1Router.authMiddleware().(middleware.ScopeAuthorizer); ok {
				caRouter.SetScopeAuthorizer(scoped)
			}
			caRouter.RegisterPublicRoutes(v1Router.router)
			caRouter.RegisterRoutes(v1Router.gated(common.ROLE_ADMIN))
		},
	)
}

func (v1Router *Router) deviceRoutes() {
	deviceHandler := v1Router.restHandlerRegistry.DeviceRestHandler()
	configDeliveryHandler := v1Router.restHandlerRegistry.ConfigDeliveryHandler()

	// Wire the TemplateCRUDHandler for the legacy /device/templates routes
	// if both template and profile services are available.
	var templateHandler device.TemplateCRUDHandler
	templateService := v1Router.restHandlerRegistry.DeviceTemplateService()
	profileService := v1Router.restHandlerRegistry.DeviceProfileService()
	deviceService := v1Router.restHandlerRegistry.DeviceService()
	if templateService != nil && profileService != nil {
		templateHandler = device.NewTemplateHandler(
			v1Router.logger,
			v1Router.restHandlerRegistry.ResponseWriter(),
			templateService,
			profileService,
			deviceService,
		)
	}

	// Wire the DeviceCRUDHandler for device profile CRUD endpoints.
	var crudHandler device.DeviceCRUDHandler
	if profileService != nil || deviceService != nil {
		crudHandler = device.NewCRUDHandler(
			v1Router.logger,
			v1Router.restHandlerRegistry.ResponseWriter(),
			deviceService,
			profileService,
		)
	}

	// Device attestation verification delegates to the in-process
	// DeviceService gRPC implementation, so REST, gRPC, Unix, QUIC and MCP
	// all answer from one verifier (#226). A nil service yields a nil
	// handler and the route is simply not registered — an absent capability
	// should not look like a broken one.
	attestHandler := device.NewAttestHandler(
		v1Router.logger,
		v1Router.restHandlerRegistry.ResponseWriter(),
		v1Router.restHandlerRegistry.DeviceServiceServer(),
	)

	// The attestation-certificate record verb (#473) delegates to the same
	// in-process DeviceService so every transport runs one fail-closed
	// preflight.
	attestCertHandler := device.NewAttestCertHandler(
		v1Router.logger,
		v1Router.restHandlerRegistry.ResponseWriter(),
		v1Router.restHandlerRegistry.DeviceServiceServer(),
	)
	// Operator Enable/Disable Device (#250) delegates to the same in-process
	// DeviceService, so REST enforces what every other transport enforces.
	lifecycleHandler := device.NewLifecycleHandler(
		v1Router.logger,
		v1Router.restHandlerRegistry.ResponseWriter(),
		v1Router.restHandlerRegistry.DeviceServiceServer(),
	)

	// A diskless node's per-boot delivery (#690) runs the same verifier as
	// attestHandler, behind the node's IDevID instead of an operator role.
	bootHandler := v1Router.restHandlerRegistry.DeviceBootHandler()

	if deviceHandler == nil && configDeliveryHandler == nil && templateHandler == nil && crudHandler == nil && attestHandler == nil && bootHandler == nil {
		v1Router.logger.Debug("Device, config delivery, template, and CRUD handlers are nil - device routes not registered")
		return
	}

	deviceRouter, err := router.NewDeviceRouter(
		v1Router.restHandlerRegistry.MTLSMiddleware(),
		deviceHandler,
		crudHandler,
		templateHandler,
		configDeliveryHandler,
		attestHandler,
	)
	if err != nil {
		// Routes without a handler would nil-dereference on first request
		// (#320); register none rather than a broken half.
		v1Router.logger.Error(err, "Device routes not registered: the device, profile and template services are required")
		return
	}
	deviceRouter.SetAttestCertHandler(attestCertHandler)
	deviceRouter.SetLifecycleHandler(lifecycleHandler)
	deviceRouter.SetBootHandler(bootHandler)
	if scoped, ok := v1Router.authMiddleware().(middleware.ScopeAuthorizer); ok {
		deviceRouter.SetScopeAuthorizer(scoped)
	}
	// Split by principal. Device and profile CRUD, templates, profile
	// assignment and the provisioning SESSION surface are operator work and
	// take the admin gate. The machine-facing half — the mTLS-verified
	// /device/{profile,activate,heartbeat,boot} and the EAB-authenticated
	// /provisioning/{config,config/nonce,sign} plus the client's session
	// poll — stays off it: a machine at boot has no operator session, and
	// several of those routes run before it holds any platform credential.
	deviceRouter.RegisterMachineFacingRoutes(v1Router.router)
	deviceRouter.RegisterRoutes(v1Router.gated(common.ROLE_ADMIN))

	// Register bootstrap seeder routes at /devices/templates.
	// These use a simplified request format consumed by the bootstrap seeder.
	// Its GET /devices/config is not mounted here: only the provisioning
	// surface carries it (RegisterProvisioningRoutes, #177).
	if templateService != nil && profileService != nil {
		seederRouter := restdevice.NewDeviceRouter(
			v1Router.logger,
			v1Router.restHandlerRegistry.ResponseWriter(),
			templateService,
			profileService,
		)
		seederRouter.RegisterRoutes(v1Router.router)
	}
}

// dnsRoutes mounts /dns when a DNS backend is configured. The routes call
// the DNSService gRPC server, so REST and gRPC share one service path and one
// wire shape.
func (v1Router *Router) dnsRoutes() {
	dnsService := v1Router.restHandlerRegistry.DNSService()
	v1Router.serviceRegistry.requireService(
		v1Router.router, "dns", "/dns", dnsService,
		func() {
			dnsRouter := restdns.NewDNSRouter(
				v1Router.logger,
				v1Router.restHandlerRegistry.DNSServiceServer(),
				v1Router.responseWriter)
			// Authoritative zone and record CRUD plus DNSSEC signing.
			// Zone contents are the platform's internal name map, so the
			// reads are gated with the writes.
			dnsRouter.RegisterRoutes(v1Router.gated(common.ROLE_ADMIN))
		},
	)
}

func (v1Router *Router) attestationRoutes() {
	server := v1Router.restHandlerRegistry.AttestationServiceServer()
	if server == nil {
		v1Router.logger.Debug("Attestation service server is nil - attestation routes not registered")
		return
	}
	r := restattestation.NewAttestationServerRouter(
		v1Router.logger,
		server,
		v1Router.responseWriter)
	// Gated (#387): the manifest, verify and workload-collect routes take
	// the admin gate. The two QUOTE-PRODUCING routes (/host, /quote) make
	// this node's TPM sign the caller's nonce; they are what the reporting
	// collector dials (#226), so they carry two principals: an operator
	// through the same admin chain, or a machine caller admitted by the
	// node's caller-admission policy (mTLS identity chained to the platform
	// anchors, then the configured strategy). A refused machine caller is
	// refused — it is not offered the operator path as a second chance.
	// With no policy configured the routes are operator-only, exactly as
	// before #226; the policy can only narrow who else gets in.
	r.RegisterRoutes(v1Router.gated(common.ROLE_ADMIN))
	rep := v1Router.restHandlerRegistry.AttestationReporting()
	gate := v1Router.callerGate()
	r.RegisterQuoteRoutes(v1Router.router, gate, v1Router.operatorChain(common.ROLE_ADMIN))

	// The node's own clock trust state (#509), on the same gate and for
	// the same principal: the collector records it beside the verdict, so
	// a report from a machine that cannot place itself in time says so.
	// It is a read of state the health surface already publishes — no
	// secret, and no mutation; the privileged clock verbs stay on the
	// operator-gated NTP surface.
	var clock restattestation.ClockReader
	if rep != nil && rep.Clock != nil {
		clock = rep.Clock
	}
	restattestation.NewClockRouter(clock, v1Router.responseWriter).
		RegisterRoutes(v1Router.router, gate, v1Router.operatorChain(common.ROLE_ADMIN))

	// The effective caller policy, so an operator sees what is enforced.
	restattestation.NewCallersRouter(rep, v1Router.responseWriter).
		RegisterRoutes(v1Router.gated(common.ROLE_ADMIN))

	// Reports (#226 slices B/E): cached verdicts with their age and the
	// operator "attest now" trigger, which enqueues collection with the
	// collector and never quotes. Admin-gated: a report is a security
	// verdict about a machine and the trigger spends TPM time.
	restattestation.NewReportsRouter(v1Router.logger, rep, v1Router.responseWriter).
		RegisterRoutes(v1Router.gated(common.ROLE_ADMIN))

	// Device verdicts (#709): the long-poll StreamDeviceVerdicts rides on
	// over HTTP. Admin-gated like the reports; the session's tenant decides
	// which devices' verdicts the caller sees.
	restattestation.NewVerdictsRouter(v1Router.restHandlerRegistry.AttestationVerdicts(), v1Router.responseWriter).
		RegisterRoutes(v1Router.gated(common.ROLE_ADMIN))

	// Events surface — distinct from the proto-defined manifest /
	// quote / collect surfaces. Wired from the platform attestation
	// store so the WebUI's /attestation/eventlogs page renders the
	// enrollment timeline.
	if reader := v1Router.restHandlerRegistry.AttestationEventReader(); reader != nil {
		eventsRouter := restattestation.NewEventsRouter(
			v1Router.logger,
			reader,
			v1Router.responseWriter)
		eventsRouter.RegisterRoutes(v1Router.gated(common.ROLE_ADMIN))
	}
}

// computeRoutes mounts /api/v1/compute/{vms,containers,...} backed by
// the in-process ComputeService gRPC server. On nodes where the compute
// orchestrator is not configured (e.g. a control plane without a
// container runtime) the surface answers a structured 503 through the
// service registry — per the loud-failure policy and the documented
// contract in docs/compute/api.md — instead of a raw 404.
// computeImagesRoutes registers before this one (mux matches in
// registration order) AND /compute/images is carved out of the 503
// stub, so the registry-owned surface is never shadowed — not even for
// methods its routes don't declare, which mux would otherwise let fall
// through to the method-agnostic stub.
func (v1Router *Router) computeRoutes() {
	server := v1Router.restHandlerRegistry.ComputeServiceServer()
	v1Router.serviceRegistry.requireService(
		v1Router.router,
		"compute",
		"/compute",
		server,
		func() {
			r := restcompute.NewComputeRouter(
				v1Router.logger,
				server,
				v1Router.responseWriter)
			if scoped, ok := v1Router.authMiddleware().(middleware.ScopeAuthorizer); ok {
				r.SetScopeAuthorizer(scoped)
			}
			// VM and container lifecycle: create, delete, start, stop,
			// reboot, migrate, snapshot and restore, disk attach/detach,
			// container exec and attestation. Reads are gated with the
			// writes — the VM and container inventory is the tenant
			// workload map.
			r.RegisterRoutes(v1Router.gated(common.ROLE_ADMIN))
		},
		"/compute/images",
	)
}

// computeImagesRoutes mounts /api/v1/compute/images backed by the
// OCI artifact registry adapter. The registry is wired by the daemon
// boot path; here we just look it up and either install handlers or
// register a structured-503 stub via the service registry so callers
// see "registry not configured" instead of a 404.
func (v1Router *Router) computeImagesRoutes() {
	svc := v1Router.restHandlerRegistry.RegistryService()
	v1Router.serviceRegistry.requireService(
		v1Router.router,
		"registry",
		"/compute/images",
		svc,
		func() {
			r := restregistry.NewRouter(
				v1Router.logger,
				svc,
				v1Router.responseWriter)
			// The platform-curated image surface: push, delete and the
			// image inventory. This is NOT the OCI Distribution surface —
			// /v2 is mounted at the host root by webserver_v1 and carries
			// its own attestation-based authentication, which is why it is
			// not gated here.
			r.RegisterRoutes(v1Router.gated(common.ROLE_ADMIN))
		},
	)
}

func (v1Router *Router) bmcRoutes() {
	h := v1Router.restHandlerRegistry.BMCRestHandler()
	if h == nil {
		v1Router.logger.Debug("BMC REST handler is nil - BMC routes not registered")
		return
	}
	// Remote power, boot and media control of the host: admin only.
	router.NewBMCRouter(h).RegisterRoutes(v1Router.gated(common.ROLE_ADMIN))
}

func (v1Router *Router) eabRoutes() {
	server := v1Router.restHandlerRegistry.EABServiceServer()
	if server == nil {
		v1Router.logger.Debug("EAB service server is nil - EAB routes not registered")
		return
	}
	r := resteab.NewEABRouter(
		v1Router.logger,
		server,
		v1Router.responseWriter)
	// ACME External Account Binding credentials: create, revoke, delete.
	// An EAB credential is a bearer secret that authorises certificate
	// issuance, so the whole surface is credential-bearing.
	r.RegisterRoutes(v1Router.gated(common.ROLE_ADMIN))
}

func (v1Router *Router) gatewayRoutes() {
	server := v1Router.restHandlerRegistry.GatewayServiceServer()
	if server != nil {
		r := restgateway.NewGatewayRouter(
			v1Router.logger,
			server,
			v1Router.responseWriter)
		// BGP announce and withdraw, IPAM allocate and release, gateway
		// mode. These are operator controls over routing and addressing;
		// an anonymous announce is a route hijack.
		r.RegisterRoutes(v1Router.gated(common.ROLE_ADMIN))

		// Full IPAM pool CRUD under /sdn/gateway/ipam — the WebUI's
		// Networking → IPAM contract (docs/sdn/ipam). Registered here,
		// before sdnRoutes, so an unconfigured-SDN 503 stub on /sdn can
		// never shadow it (gated() is a path-matcher-less subrouter of
		// v1Router.router, so registration order on the parent is
		// preserved and mux still matches in that order).
		//
		// Pool create, update and delete are operator controls over the
		// address plan, so the surface carries the same admin gate as the
		// rest of the gateway routes.
		ipamRouter := restgateway.NewIPAMRouter(
			v1Router.logger,
			server,
			v1Router.responseWriter)
		ipamRouter.RegisterRoutes(v1Router.gated(common.ROLE_ADMIN))
	} else {
		v1Router.logger.Debug("Gateway service server is nil - gateway service routes not registered")
	}

	// Control-plane endpoints (state cache + telemetry ingestion +
	// desired-config pull) are independent of the in-process
	// GatewayService gRPC implementation — they let a separate
	// gatewayd process report into the CP. Wired unconditionally so
	// the structured loud-failure envelope surfaces when the store
	// isn't configured.
	store, cfgSource := v1Router.restHandlerRegistry.GatewayControlPlane()
	if store != nil || cfgSource != nil {
		cp := restgateway.NewControlPlane(
			v1Router.logger,
			store,
			cfgSource,
			v1Router.responseWriter)
		cp.SetVPNLeaseSink(v1Router.restHandlerRegistry.GatewayVPNLeases())
		// The control plane is split by PRINCIPAL, not by verb. The
		// operator half (the fleet-wide /gateway/state surface) takes the
		// admin gate; the gatewayd-facing half authenticates itself with a
		// verified mTLS client certificate and binds the request's
		// gateway_id to that certificate, so it must stay off the role
		// gate or every gateway in the fleet stops reporting. See the two
		// methods' own documentation.
		cp.RegisterGatewayFacingRoutes(v1Router.router)
		cp.RegisterRoutes(v1Router.gated(common.ROLE_ADMIN))
	}
}

func (v1Router *Router) idevidRoutes() {
	server := v1Router.restHandlerRegistry.IDevIDServiceServer()
	if server == nil {
		v1Router.logger.Debug("IDevID service server is nil - IDevID routes not registered")
		return
	}
	r := restidevid.NewIDevIDRouter(
		v1Router.logger,
		server,
		v1Router.responseWriter)
	// The node's own IDevID and IAK: generate, delete, CSR, certificate
	// install and delete, and activate-credential. This is the identity
	// every other node authenticates this one by.
	r.RegisterRoutes(v1Router.gated(common.ROLE_ADMIN))
}

func (v1Router *Router) invitationRoutes() {
	server := v1Router.restHandlerRegistry.InvitationServiceServer()
	if server == nil {
		v1Router.logger.Debug("Invitation service server is nil - invitation routes not registered")
		return
	}
	r := restinvitation.NewInvitationRouter(
		v1Router.logger,
		server,
		v1Router.responseWriter)
	// Split by principal. The five tenant-admin routes resolve their tenant
	// and inviter from the verified session and take the admin gate; the two
	// invitee-facing routes authenticate by the invitation token itself and
	// must stay off it, because an invitee has no platform session by
	// construction. See the two methods' own documentation, and #171 for the
	// unverified decoders the gated half used to rely on.
	r.RegisterInviteeRoutes(v1Router.router)
	r.RegisterRoutes(v1Router.gated(common.ROLE_ADMIN))
}

func (v1Router *Router) overlayRoutes() {
	server := v1Router.restHandlerRegistry.OverlayServiceServer()
	if server == nil {
		v1Router.logger.Debug("Overlay service server is nil - overlay routes not registered")
		return
	}
	r := restoverlay.NewOverlayRouter(
		v1Router.logger,
		server,
		v1Router.responseWriter)
	// VXLAN overlay: VNI create and delete, VTEP and tunnel inventory.
	// A VNI is a tenant's layer-2 isolation boundary.
	r.RegisterRoutes(v1Router.gated(common.ROLE_ADMIN))
}

func (v1Router *Router) ntpRoutes() {
	server := v1Router.restHandlerRegistry.NTPServiceServer()
	if server == nil {
		v1Router.logger.Debug("NTP service server is nil - NTP routes not registered")
		return
	}
	r := restntp.NewNTPRouter(
		v1Router.logger,
		server,
		v1Router.responseWriter)
	// POST /ntp/step forces a clock correction. A node whose clock is
	// wrong fails attestation, ACME issuance and token validation without
	// any of those failures naming the clock (docs/ntp/user.md), which
	// makes an anonymous stepper a denial-of-service primitive.
	r.RegisterRoutes(v1Router.gated(common.ROLE_ADMIN))
}

func (v1Router *Router) vpnRoutes() {
	server := v1Router.restHandlerRegistry.VPNServiceServer()
	if server == nil {
		v1Router.logger.Debug("VPN service server is nil - VPN routes not registered")
		return
	}
	r := restvpn.NewVPNRouter(
		v1Router.logger,
		server,
		v1Router.responseWriter)
	if scoped, ok := v1Router.authMiddleware().(middleware.ScopeAuthorizer); ok {
		r.SetScopeAuthorizer(scoped)
	}
	// Enrolling or revoking a peer decides which devices reach the
	// management network, and a posture policy decides which of them stay
	// there: operator work behind the admin gate, then vpn:read, vpn:write
	// or vpn:admin per route, as on gRPC, QUIC and MCP.
	r.RegisterRoutes(v1Router.gated(common.ROLE_ADMIN))
}

// appServiceRoutes mounts /cache, /scheduler, /messaging and /object-storage
// over the daemon's Cache, Scheduler, Messaging and ObjectStorage servers,
// with the route table the daemon REST listener serves. Like the VPN routes
// they are operator work behind the admin gate, then each route's cache:,
// scheduler:, messaging: or objectstorage: scope, as on gRPC, QUIC and MCP.
func (v1Router *Router) appServiceRoutes() {
	servers := v1Router.restHandlerRegistry.AppServiceServers()
	if servers.Cache == nil && servers.Scheduler == nil && servers.Messaging == nil && servers.ObjectStorage == nil {
		v1Router.logger.Debug("Application service servers are nil - cache, scheduler, messaging and object storage routes not registered")
		return
	}
	guard := scopeRouteGuard{}
	if scoped, ok := v1Router.authMiddleware().(middleware.ScopeAuthorizer); ok {
		guard.authorizer = scoped
	}
	restapi.NewAppServiceHandlers(servers, guard, v1Router.logger.Slog()).
		RegisterVersionedRoutes(v1Router.gated(common.ROLE_ADMIN))
}

// scopeRouteGuard checks an application service route's scope with the
// platform token middleware. Without one the routes stay on the role gate
// alone, as the VPN routes do under the legacy JWT handler: its sessions
// carry roles, not scopes.
type scopeRouteGuard struct {
	authorizer middleware.ScopeAuthorizer
}

func (g scopeRouteGuard) Require(scope string, next http.HandlerFunc) http.HandlerFunc {
	if g.authorizer == nil {
		return next
	}
	return g.authorizer.RequireScope(scope)(next).ServeHTTP
}

func (v1Router *Router) pxeRoutes() {
	server := v1Router.restHandlerRegistry.PXEServiceServer()
	if server == nil {
		v1Router.logger.Debug("PXE service server is nil - PXE routes not registered")
		return
	}
	r := restpxe.NewPXERouter(
		v1Router.logger,
		server,
		v1Router.responseWriter,
		v1Router.restHandlerRegistry.PXEWebhookEnabled())
	// Split by principal. Service controls and the device lifecycle —
	// authorize, quarantine, retry, state — are operator work and take the
	// admin gate, then per route the pxe:* scope its RPC takes on gRPC. The
	// install-completion webhook stays off both because its caller is a
	// booting node; it presents and checks no credential at all (#238), so
	// it is mounted only when the operator enabled it.
	//
	// The provisioning gateway's device reports (register, state, install
	// complete) under /provisioning/devices/{mac}: the admin gate, then
	// provisioning:write per route, as on gRPC. The install-complete report
	// is the webhook's operation behind a credential, so it does not widen
	// #238.
	//
	// Under the legacy JWT handler, which carries roles and no scopes, the
	// role gate alone applies (docs/ipxe/api.md §5).
	if scoped, ok := v1Router.authMiddleware().(middleware.ScopeAuthorizer); ok {
		r.SetScopeAuthorizer(scoped)
	}
	r.RegisterMachineFacingRoutes(v1Router.router)
	r.RegisterRoutes(v1Router.gated(common.ROLE_ADMIN))
	r.RegisterGatewayRoutes(v1Router.gated(common.ROLE_ADMIN))
}

func (v1Router *Router) tenantRoutes() {
	server := v1Router.restHandlerRegistry.TenantServiceServer()
	if server == nil {
		v1Router.logger.Debug("Tenant service server is nil - tenant routes not registered")
		return
	}
	// The admin gate #165 mounted says the CALLER is an administrator. It
	// cannot say they administer the tenant they named, and every route under
	// /{id} takes its target tenant from the URL — so a tenant-scoped admin
	// would reach any other tenant's quotas, DEK and barrier by changing a
	// path segment (#234). These guards close that.
	_, guard, err := v1Router.authorization()
	if err != nil {
		v1Router.logger.Error(err,
			"Tenant routes not registered: the RBAC guard could not be built")
		return
	}
	r, err := resttenant.NewTenantRouter(
		v1Router.logger,
		server,
		v1Router.responseWriter,
		resttenant.Authorization{
			// The caller's own tenant, or the system tenant acting as the
			// control plane. Both are legitimate here and neither existing
			// guard expresses the disjunction: RequireOwnTenant alone would
			// deny the system admin that platformctl drives this surface as,
			// and RequireTenant(system) alone would deny a tenant reading
			// itself, which docs/auth/architecture.md §6c says this surface
			// is for.
			RequireOwnTenantOrSystem: guard.RequireOwnTenantOrSystem(
				v1Router.restHandlerRegistry.TenantID(),
				func(r *http.Request) string { return mux.Vars(r)["id"] }),
			// Listing, creating and syncing are inherently cross-tenant; a
			// tenant admin must not enumerate or create tenants with the
			// role they hold inside their own.
			RequireSystemTenant: guard.RequireTenant(
				v1Router.restHandlerRegistry.TenantID()),
			// The lookup by name applies the rule every other transport
			// applies (#304): the session's tenant resolves its own name,
			// the system tenant any.
			RequireOwnTenantNameOrSystem: guard.RequireOwnTenantNameOrSystem(
				v1Router.restHandlerRegistry.TenantID(),
				resttenant.NameResolver(server)),
		})
	if err != nil {
		v1Router.logger.Error(err, "Tenant routes not registered")
		return
	}
	// Tenant lifecycle, quotas, the per-tenant DEK and the per-tenant
	// barrier. Every route is an administrative operation on tenancy state,
	// so the whole subtree keeps the admin gate as well.
	r.RegisterRoutes(v1Router.gated(common.ROLE_ADMIN))
}

func (v1Router *Router) tpmRoutes() {
	server := v1Router.restHandlerRegistry.TPMServiceServer()
	if server == nil {
		v1Router.logger.Debug("TPM service server is nil - TPM routes not registered")
		return
	}
	r := resttpm.NewTPMRouter(
		v1Router.logger,
		server,
		v1Router.responseWriter)
	// The host TPM: provision and clear, EK/SRK/AK creation and deletion,
	// seal/unseal, NVRAM definition and writes. Reads are gated with the
	// writes — the event log, PCR banks and NVRAM contents describe the
	// platform's measured state, which is exactly what an attacker
	// preparing to forge a quote wants.
	r.RegisterRoutes(v1Router.gated(common.ROLE_ADMIN))
}

func (v1Router *Router) iamRoutes() {
	iamClient, pepClient := v1Router.restHandlerRegistry.IAMClients()
	if iamClient == nil {
		v1Router.logger.Debug("IAM service client is nil - IAM routes not registered")
		return
	}
	// IAM is the platform's administration surface. It is registered only
	// when the authentication seam and the RBAC guards are both available;
	// otherwise the routes stay unregistered rather than being published
	// without a gate.
	authenticate, guard, err := v1Router.authorization()
	if err != nil {
		v1Router.logger.Error(err,
			"IAM routes not registered: the authentication seam or RBAC guard could not be built")
		return
	}
	iamRouter, err := restiam.NewIAMRouter(
		v1Router.logger,
		iamClient,
		pepClient,
		v1Router.responseWriter,
		restiam.Authorization{
			Authenticate: authenticate,
			RequireAdmin: guard.RequireRoles(common.ROLE_ADMIN),
			// The platform's operating tenant IS the firstboot system
			// tenant (pkg/app adopts it), so it is the control-plane
			// tenant this guard admits.
			RequireSystemTenant: guard.RequireTenant(v1Router.restHandlerRegistry.TenantID()),
			// The IAM handlers give the URL's {tenant} precedence over the
			// session's, and a flat route names its tenant in the
			// tenant_id query, so the tenant a request NAMES has to be
			// the caller's own.
			RequireOwnTenant: guard.RequireOwnTenant(restiam.RequestedTenant),
		})
	if err != nil {
		v1Router.logger.Error(err, "IAM routes not registered")
		return
	}
	iamRouter.RegisterRoutes(v1Router.router)
}

func (v1Router *Router) kmsRoutes() {
	keyMgmt, crypto, dek, secrets := v1Router.restHandlerRegistry.KMSSDKClients()
	if keyMgmt == nil && crypto == nil && dek == nil && secrets == nil {
		v1Router.logger.Debug("KMS SDK clients are nil - KMS routes not registered")
		return
	}
	kmsRouter := kms.NewKMSRouter(
		v1Router.logger,
		keyMgmt,
		crypto,
		dek,
		secrets,
		v1Router.responseWriter)
	// Keys, DEKs, secrets, and the crypto operations that use them —
	// encrypt, decrypt, sign. The whole surface is credential-bearing.
	kmsRouter.RegisterRoutes(v1Router.gated(common.ROLE_ADMIN))
}

func (v1Router *Router) sdnRoutes() {
	sdnService := v1Router.restHandlerRegistry.SDNService()
	v1Router.serviceRegistry.requireService(
		v1Router.router, "sdn", "/sdn", sdnService,
		func() {
			sdnRouter := sdn.NewSDNRouter(
				v1Router.logger,
				sdnService,
				v1Router.restHandlerRegistry.ResponseWriter())
			// Bridge, port, flow and VLAN mutation. Flow rules ARE the
			// network policy this platform enforces; an anonymous caller
			// that can add one can route around every other control.
			sdnRouter.RegisterRoutes(v1Router.gated(common.ROLE_ADMIN))
		},
	)
}

func (v1Router *Router) switchRoutes() {
	switchService := v1Router.restHandlerRegistry.SwitchService()
	v1Router.serviceRegistry.requireService(
		v1Router.router, "switch", "/switches", switchService,
		func() {
			switchRouter := switchapi.NewSwitchRouter(
				v1Router.logger,
				switchService,
				v1Router.restHandlerRegistry.ResponseWriter())
			// Physical switch port control: VLAN assignment, enable and
			// disable. Moving a port between VLANs moves a machine between
			// network zones.
			switchRouter.RegisterRoutes(v1Router.gated(common.ROLE_ADMIN))
		},
	)
}

func (v1Router *Router) vtpmRoutes() {
	vtpmService := v1Router.restHandlerRegistry.VTPMService()
	v1Router.serviceRegistry.requireService(
		v1Router.router, "vtpm", "/vtpm", vtpmService,
		func() {
			vtpmRouter := vtpm.NewVTPMRouter(
				v1Router.logger,
				vtpmService,
				v1Router.restHandlerRegistry.ResponseWriter())
			// vTPM bundles carry the sealed state of a guest's virtual
			// TPM; create, import, export and delete are all privileged.
			vtpmRouter.RegisterRoutes(v1Router.gated(common.ROLE_ADMIN))
		},
	)
}

func (v1Router *Router) platformRoutes() {
	// The platform service surface owns /platform/service-registry —
	// the very endpoint operators consult to see this status. Don't
	// register the catch-all 503 stub for it; otherwise an
	// unconfigured platform router would mask the status endpoint.
	platformRouter := v1Router.restHandlerRegistry.PlatformRestRouter()
	if platformRouter == nil {
		if v1Router.serviceRegistry != nil {
			v1Router.serviceRegistry.markUnconfigured("platform", "/platform",
				"platform service not configured by daemon — /platform/service-registry remains available; other /platform/* routes are dark")
		}
		v1Router.logger.Warnf("Platform router is nil - /platform routes not registered (but /platform/service-registry is still wired)")
		return
	}
	// The whole /platform subtree requires an authenticated admin: config
	// read and reload, snapshot capture and rollback, service start/stop/
	// restart, and the structured log query and live stream. Unlike /ca
	// this needs no public half — every /platform caller in the tree is the
	// console, which authenticates, and the health feature's documented
	// load-balancer integration uses the unversioned /health on the
	// daemon's own listener rather than anything under /api/v1/platform.
	//
	// The component-by-component health breakdown is gated with the rest
	// deliberately: which subsystem is degraded is useful to an attacker
	// choosing where to push, and an anonymous caller that only needs
	// liveness has /api/v1/status.
	//
	// /platform/service-registry is NOT part of this: it is registered
	// separately on the ungated router (RegisterRoutes, below) under its
	// own pre-existing decision, so the console can show dark surfaces
	// before login.
	platformRouter.RegisterRoutes(v1Router.gated(common.ROLE_ADMIN))
	if v1Router.serviceRegistry != nil {
		v1Router.serviceRegistry.markConfigured("platform", "/platform")
	}
}
