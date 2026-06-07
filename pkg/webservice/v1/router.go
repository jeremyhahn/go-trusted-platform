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
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
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
	restoverlay "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/overlay"
	restpxe "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/pxe"
	restregistry "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/registry"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/sdn"
	switchapi "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/switch"
	resttenant "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/tenant"
	resttpm "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/tpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

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
	router.WebServiceRouter
}

func NewRouter(
	logger *logging.Logger,
	ca trustedca.CACertificateAuthority,
	caConfig *trustedca.CAConfig,
	serverKeyAttribtues *xkmssdk.KeyAttributes,
	restHandlerRegistry RestHandlerRegistry,
	responseWriter response.HttpWriter) router.WebServiceRouter {

	return &Router{
		ca:                  ca,
		caConfig:            caConfig,
		logger:              logger,
		restHandlerRegistry: restHandlerRegistry,
		serverKeyAttributes: serverKeyAttribtues,
		responseWriter:      responseWriter,
		serviceRegistry:     NewServiceRegistry(logger, responseWriter),
	}
}

// Registers all websocket and REST services
func (v1Router *Router) RegisterRoutes(router *mux.Router) {
	v1Router.router = router
	v1Router.platformRoutes()
	v1Router.systemRoutes()
	v1Router.authenticationRoutes()
	v1Router.webAuthnRoutes()
	v1Router.acmeRoutes()
	v1Router.attestationRoutes()
	v1Router.caRoutes()
	v1Router.computeRoutes()
	v1Router.computeImagesRoutes()
	v1Router.deviceRoutes()
	v1Router.dnsRoutes()
	v1Router.eabRoutes()
	v1Router.gatewayRoutes()
	v1Router.iamRoutes()
	v1Router.idevidRoutes()
	v1Router.invitationRoutes()
	v1Router.kmsRoutes()
	v1Router.overlayRoutes()
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
	v1Router.router.HandleFunc("/users/{id}/factors",
		stub(map[string]any{"factors": []any{}, "total": 0})).Methods("GET")

	v1Router.router.HandleFunc("/quicbaas/storage/buckets",
		stub(map[string]any{"buckets": []any{}, "total": 0})).Methods("GET")
	v1Router.router.HandleFunc("/quicbaas/storage/buckets",
		mutationStub("name")).Methods("POST")
	v1Router.router.HandleFunc("/quicbaas/storage/buckets/{name}",
		deleteStub()).Methods("DELETE")
	v1Router.router.HandleFunc("/quicbaas/storage/buckets/{name}/objects",
		stub(map[string]any{"objects": []any{}, "total": 0})).Methods("GET")
	v1Router.router.HandleFunc("/quicbaas/storage/buckets/{name}/objects/{object:.*}",
		deleteStub()).Methods("DELETE")

	v1Router.router.HandleFunc("/quicbaas/kv",
		stub(map[string]any{"entries": []any{}, "total": 0})).Methods("GET")
	v1Router.router.HandleFunc("/quicbaas/kv",
		mutationStub("key")).Methods("POST")
	v1Router.router.HandleFunc("/quicbaas/kv/{key}",
		deleteStub()).Methods("DELETE")

	v1Router.router.HandleFunc("/quicbaas/timeseries/metrics",
		stub(map[string]any{"metrics": []any{}, "total": 0})).Methods("GET")
	v1Router.router.HandleFunc("/quicbaas/timeseries/metrics",
		mutationStub("name")).Methods("POST")

	v1Router.router.HandleFunc("/quicbaas/vector/collections",
		stub(map[string]any{"collections": []any{}, "total": 0})).Methods("GET")
	v1Router.router.HandleFunc("/quicbaas/vector/collections",
		mutationStub("name")).Methods("POST")
	v1Router.router.HandleFunc("/quicbaas/vector/namespaces",
		stub(map[string]any{"namespaces": []any{}, "total": 0})).Methods("GET")
	v1Router.router.HandleFunc("/quicbaas/vector/namespaces",
		mutationStub("name")).Methods("POST")

	v1Router.router.HandleFunc("/quicbaas/backup/snapshots",
		stub(map[string]any{"snapshots": []any{}, "total": 0})).Methods("GET")
	v1Router.router.HandleFunc("/quicbaas/backup/snapshots",
		mutationStub("id")).Methods("POST")
	v1Router.router.HandleFunc("/quicbaas/backups",
		stub(map[string]any{"backups": []any{}, "total": 0})).Methods("GET")
	v1Router.router.HandleFunc("/quicbaas/backups",
		mutationStub("id")).Methods("POST")
}

func (v1Router *Router) systemRoutes() {
	// Use WebAuthn as auth middleware if configured, otherwise fall back to JWT.
	var authMiddleware middleware.AuthMiddleware
	webAuthnHandler := v1Router.restHandlerRegistry.WebAuthnRestService()
	if webAuthnHandler != nil {
		authMiddleware = webAuthnHandler
	} else {
		authMiddleware = v1Router.restHandlerRegistry.JSONWebTokenHandler()
	}
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

func (v1Router *Router) caRoutes() {
	v1Router.serviceRegistry.requireService(
		v1Router.router, "ca", "/ca", v1Router.ca,
		func() {
			caRouter := restca.NewCARouter(
				v1Router.logger,
				v1Router.ca,
				v1Router.responseWriter)
			caRouter.RegisterRoutes(v1Router.router)
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
	if templateService != nil && profileService != nil {
		templateHandler = device.NewTemplateHandler(
			v1Router.logger,
			v1Router.restHandlerRegistry.ResponseWriter(),
			templateService,
			profileService,
		)
	}

	// Wire the DeviceCRUDHandler for device profile CRUD endpoints.
	deviceService := v1Router.restHandlerRegistry.DeviceService()
	var crudHandler device.DeviceCRUDHandler
	if profileService != nil || deviceService != nil {
		crudHandler = device.NewCRUDHandler(
			v1Router.logger,
			v1Router.restHandlerRegistry.ResponseWriter(),
			deviceService,
			profileService,
		)
	}

	if deviceHandler == nil && configDeliveryHandler == nil && templateHandler == nil && crudHandler == nil {
		v1Router.logger.Debug("Device, config delivery, template, and CRUD handlers are nil - device routes not registered")
		return
	}

	deviceRouter := router.NewDeviceRouter(
		v1Router.restHandlerRegistry.MTLSMiddleware(),
		deviceHandler,
		crudHandler,
		templateHandler,
		configDeliveryHandler,
	)
	deviceRouter.RegisterRoutes(v1Router.router)

	// Register bootstrap seeder routes at /devices/templates.
	// These use a simplified request format consumed by the bootstrap seeder.
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

func (v1Router *Router) dnsRoutes() {
	dnsService := v1Router.restHandlerRegistry.DNSService()
	v1Router.serviceRegistry.requireService(
		v1Router.router, "dns", "/dns", dnsService,
		func() {
			dnsRouter := restdns.NewDNSRouter(
				v1Router.logger,
				dnsService,
				v1Router.responseWriter)
			dnsRouter.RegisterRoutes(v1Router.router)
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
	r.RegisterRoutes(v1Router.router)

	// Events surface — distinct from the proto-defined manifest /
	// quote / collect surfaces. Wired from the platform attestation
	// store so the WebUI's /attestation/eventlogs page renders the
	// enrollment timeline.
	if reader := v1Router.restHandlerRegistry.AttestationEventReader(); reader != nil {
		eventsRouter := restattestation.NewEventsRouter(
			v1Router.logger,
			reader,
			v1Router.responseWriter)
		eventsRouter.RegisterRoutes(v1Router.router)
	}
}

func (v1Router *Router) computeRoutes() {
	server := v1Router.restHandlerRegistry.ComputeServiceServer()
	if server == nil {
		v1Router.logger.Debug("Compute service server is nil - compute routes not registered")
		return
	}
	r := restcompute.NewComputeRouter(
		v1Router.logger,
		server,
		v1Router.responseWriter)
	r.RegisterRoutes(v1Router.router)
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
			r.RegisterRoutes(v1Router.router)
		},
	)
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
	r.RegisterRoutes(v1Router.router)
}

func (v1Router *Router) gatewayRoutes() {
	server := v1Router.restHandlerRegistry.GatewayServiceServer()
	if server != nil {
		r := restgateway.NewGatewayRouter(
			v1Router.logger,
			server,
			v1Router.responseWriter)
		r.RegisterRoutes(v1Router.router)
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
		cp.RegisterRoutes(v1Router.router)
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
	r.RegisterRoutes(v1Router.router)
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
	r.RegisterRoutes(v1Router.router)
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
	r.RegisterRoutes(v1Router.router)
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
		v1Router.responseWriter)
	r.RegisterRoutes(v1Router.router)
}

func (v1Router *Router) tenantRoutes() {
	server := v1Router.restHandlerRegistry.TenantServiceServer()
	if server == nil {
		v1Router.logger.Debug("Tenant service server is nil - tenant routes not registered")
		return
	}
	r := resttenant.NewTenantRouter(
		v1Router.logger,
		server,
		v1Router.responseWriter)
	r.RegisterRoutes(v1Router.router)
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
	r.RegisterRoutes(v1Router.router)
}

func (v1Router *Router) iamRoutes() {
	iamClient, pepClient := v1Router.restHandlerRegistry.IAMClients()
	if iamClient == nil {
		v1Router.logger.Debug("IAM service client is nil - IAM routes not registered")
		return
	}
	iamRouter := restiam.NewIAMRouter(
		v1Router.logger,
		iamClient,
		pepClient,
		v1Router.responseWriter)
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
	kmsRouter.RegisterRoutes(v1Router.router)
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
			sdnRouter.RegisterRoutes(v1Router.router)
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
			switchRouter.RegisterRoutes(v1Router.router)
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
			vtpmRouter.RegisterRoutes(v1Router.router)
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
	platformRouter.RegisterRoutes(v1Router.router)
	if v1Router.serviceRegistry != nil {
		v1Router.serviceRegistry.markConfigured("platform", "/platform")
	}
}
