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
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/objectstorage"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/healthprobe"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning/configdelivery"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	bmcwebsvc "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/bmc"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const (
	restAPIVersion = "v1"
	restBasePath   = "/api/" + restAPIVersion
)

// serviceStatusStringMap provides O(1) lookup from protobuf ServiceStatus to
// human-readable REST API string representations.
var serviceStatusStringMap = map[platformv1.ServiceStatus]string{
	platformv1.ServiceStatus_SERVICE_STATUS_UNSPECIFIED: "unspecified",
	platformv1.ServiceStatus_SERVICE_STATUS_STOPPED:     "stopped",
	platformv1.ServiceStatus_SERVICE_STATUS_STARTING:    "starting",
	platformv1.ServiceStatus_SERVICE_STATUS_RUNNING:     "running",
	platformv1.ServiceStatus_SERVICE_STATUS_STOPPING:    "stopping",
	platformv1.ServiceStatus_SERVICE_STATUS_ERROR:       "error",
}

// serviceStatusToString converts an atomic int32 service status value to
// a human-readable string using the protobuf ServiceStatus enum.
// restServiceRefusalStatus answers ErrServiceNotControllable. The refusal is
// FailedPrecondition, which the platform webservice REST mapper
// (protorest.WriteError) sends as 400; this server matches it so both REST
// surfaces answer the same refusal the same way.
const restServiceRefusalStatus = http.StatusBadRequest

func serviceStatusToString(rawStatus int32) string {
	s, ok := serviceStatusStringMap[platformv1.ServiceStatus(rawStatus)]
	if !ok {
		return "unknown"
	}
	return s
}

// RESTServer wraps the http.Server with daemon-specific functionality
type RESTServer struct {
	server                *http.Server
	router                *mux.Router
	service               *Service
	logger                *slog.Logger
	config                *Config
	running               atomic.Bool
	tpm2Service           xkmssdk.TrustedPlatformModule
	vtpmService           vtpm.VTPMService
	configDeliveryHandler configdelivery.RestHandler
	bmcHandler            bmcwebsvc.RestHandler
	sdnHandlers           *restapi.SDNHandlers
	gatewayHandlers       *restapi.GatewayHandlers
	gatewayService        *gatewayRESTService
	idevidService         *IDevIDGRPCService
}

// NewRESTServer creates a new REST server for the daemon
// newRESTServer is the constructor New uses for the built-in REST server. It
// is a variable so a test can force a construction failure and assert that
// New refuses to run without an enabled transport (#444).
var newRESTServer = NewRESTServer

func NewRESTServer(config *Config, service *Service, logger *slog.Logger) (*RESTServer, error) {
	if logger == nil {
		logger = slog.Default()
	}

	router := mux.NewRouter()
	restServer := &RESTServer{
		router:  router,
		service: service,
		logger:  logger,
		config:  config,
	}

	// Register daemon-level REST endpoints
	restServer.registerRoutes()

	// Apply middleware
	handler := restServer.applyMiddleware(router)

	// Create HTTP server
	restServer.server = &http.Server{
		Addr:           config.RESTListenAddr,
		Handler:        handler,
		ReadTimeout:    config.RESTConfig.ReadTimeout,
		WriteTimeout:   config.RESTConfig.WriteTimeout,
		IdleTimeout:    config.RESTConfig.IdleTimeout,
		MaxHeaderBytes: config.RESTConfig.MaxHeaderBytes,
	}

	return restServer, nil
}

// Start starts the REST server
func (s *RESTServer) Start() error {
	if s.running.Load() {
		return ErrRESTServerAlreadyRunning{}
	}

	// Fail closed (#550, #312): mTLS at the TLS layer is this server's only
	// authentication, so without it the listener would serve BMC power
	// control and the rest of the daemon API anonymously. SkipIAMValidation
	// (testing only) is the explicit opt-out.
	if !s.config.SkipIAMValidation && !s.config.EnableMTLS {
		return ErrTransportAuthRequired{
			Transport: transportREST,
			Reason:    "the daemon REST server authenticates by mTLS only and mTLS is disabled",
		}
	}

	s.running.Store(true)

	// Configure TLS: prefer a USABLE in-memory certificate, fall back to
	// files. tlsCertificateUsable treats a structurally empty certificate
	// as absent (#32): binding with it would report a healthy TLS
	// transport whose every handshake fails.
	inMemory := s.config.inMemoryCertificate()
	if tlsCertificateUsable(inMemory) || (s.config.RESTTLSCertFile != "" && s.config.RESTTLSKeyFile != "") {
		var cert tls.Certificate
		if tlsCertificateUsable(inMemory) {
			cert = *inMemory
		} else {
			var err error
			cert, err = tls.LoadX509KeyPair(s.config.RESTTLSCertFile, s.config.RESTTLSKeyFile)
			if err != nil {
				s.running.Store(false)
				return ErrRESTServerStartFailed{Reason: "failed to load TLS certificates: " + err.Error()}
			}
		}
		// Enable mutual TLS if configured. Fails closed: mTLS with no
		// resolvable client CA pool is a typed error, never a listener that
		// merely does not ask for a client certificate (#550).
		tlsConfig, tlsErr := newServerTLSConfig(s.config, transportREST, cert)
		if tlsErr != nil {
			s.running.Store(false)
			return tlsErr
		}
		if tlsConfig.ClientCAs != nil {
			s.logger.Info("REST server mTLS enabled", "addr", s.config.RESTListenAddr)
		}

		s.server.TLSConfig = tlsConfig

		// Bind synchronously so listener failures (address in use, bad
		// address) surface as the typed startup error instead of being
		// logged from a goroutine after Start has already reported
		// success (#32). ServeTLS on the bound listener keeps the
		// net/http HTTP/2 setup that ListenAndServeTLS provided.
		listener, lnErr := net.Listen("tcp", s.config.RESTListenAddr)
		if lnErr != nil {
			s.running.Store(false)
			return ErrRESTServerStartFailed{Reason: "failed to bind " + s.config.RESTListenAddr + ": " + lnErr.Error()}
		}

		s.logger.Info("REST server starting with TLS", "addr", s.config.RESTListenAddr)
		go func() {
			if err := s.server.ServeTLS(listener, "", ""); err != nil && err != http.ErrServerClosed {
				s.logger.Error("REST server error", "error", err)
				s.running.Store(false)
			}
		}()
	} else {
		// Fail closed (#32): the REST listener carries platform credentials
		// on the canonical TLS port, so absent TLS material means refusing
		// to serve — never a plaintext listener. The Unix-domain-socket
		// transport is the single sanctioned non-TLS carve-out.
		s.running.Store(false)
		return ErrRESTServerStartFailed{
			Reason: "TLS material absent (no in-memory certificate and no cert/key files): refusing to start a plaintext listener on " + s.config.RESTListenAddr,
		}
	}

	return nil
}

// Stop gracefully stops the REST server
func (s *RESTServer) Stop(ctx context.Context) error {
	if !s.running.Load() {
		return ErrRESTServerNotRunning{}
	}

	s.logger.Info("Stopping REST server...")
	if err := s.server.Shutdown(ctx); err != nil {
		s.logger.Error("REST server shutdown error", "error", err)
		return ErrRESTServerStopFailed{Reason: err.Error()}
	}

	s.running.Store(false)
	s.logger.Info("REST server stopped")
	return nil
}

// ForceStop immediately stops the REST server
func (s *RESTServer) ForceStop() error {
	if !s.running.Load() {
		return ErrRESTServerNotRunning{}
	}

	s.logger.Info("Force stopping REST server...")
	if err := s.server.Close(); err != nil {
		return ErrRESTServerStopFailed{Reason: err.Error()}
	}

	s.running.Store(false)
	return nil
}

// IsRunning returns whether the REST server is running
func (s *RESTServer) IsRunning() bool {
	return s.running.Load()
}

// Router returns the underlying mux router for external route registration
func (s *RESTServer) Router() *mux.Router {
	return s.router
}

// registerRoutes registers all daemon-level REST endpoints
func (s *RESTServer) registerRoutes() {
	// Root-level probes for service discovery and load balancers: GET /health,
	// /health/live and /health/ready, status only, the answers the webservice
	// listener and every other transport give (docs/health/api.md §4).
	healthprobe.NewHandlers(s.service.currentHealthRegistry).RegisterRoutes(s.router)

	api := s.router.PathPrefix(restBasePath).Subrouter()

	// Health and status endpoints (also available under /api/v1 for consistency)
	api.HandleFunc("/health", s.handleHealth).Methods(http.MethodGet)
	api.HandleFunc("/status", s.handleStatus).Methods(http.MethodGet)
	api.HandleFunc("/version", s.handleVersion).Methods(http.MethodGet)

	// Service management endpoints
	api.HandleFunc("/services", s.handleListServices).Methods(http.MethodGet)
	api.HandleFunc("/services/{service}", s.handleGetService).Methods(http.MethodGet)
	api.HandleFunc("/services/{service}/start", s.handleStartService).Methods(http.MethodPost)
	api.HandleFunc("/services/{service}/stop", s.handleStopService).Methods(http.MethodPost)
	api.HandleFunc("/services/{service}/restart", s.handleRestartService).Methods(http.MethodPost)

	// Protocol status endpoint
	api.HandleFunc("/protocols", s.handleProtocols).Methods(http.MethodGet)

	// Register IDevID/IAK routes
	s.registerIDevIDRoutes()

	s.logger.Info("REST routes registered", "basePath", restBasePath)
}

// SetTPM2Service sets the TPM2 service for REST handlers.
// This allows IDevID/IAK operations via REST API using go-xkms's TPM2 directly.
func (s *RESTServer) SetTPM2Service(svc xkmssdk.TrustedPlatformModule) {
	s.tpm2Service = svc
}

// SetIDevIDService injects the shared IDevID gRPC service used for LDevID
// (802.1AR) issuance over REST.
func (s *RESTServer) SetIDevIDService(svc *IDevIDGRPCService) {
	s.idevidService = svc
}

// SetConfigDeliveryHandler sets the config delivery handler and registers
// provisioning routes on the daemon's REST API. These routes are unprotected
// (no mTLS) since devices at boot time have no client certificate.
func (s *RESTServer) SetConfigDeliveryHandler(handler configdelivery.RestHandler) {
	if handler == nil {
		return
	}
	s.configDeliveryHandler = handler

	api := s.router.PathPrefix(restBasePath).Subrouter()
	api.HandleFunc("/provisioning/config", handler.FetchConfig).Methods(http.MethodPost)
	api.HandleFunc("/provisioning/config/nonce", handler.GetNonce).Methods(http.MethodGet)
	api.HandleFunc("/provisioning/sign", handler.SignDigest).Methods(http.MethodPost)
	api.HandleFunc("/provisioning/sessions", handler.ListSessions).Methods(http.MethodGet)
	api.HandleFunc("/provisioning/sessions/{sessionID}", handler.GetSession).Methods(http.MethodGet)
	api.HandleFunc("/provisioning/sessions/{sessionID}/poll", handler.PollSession).Methods(http.MethodGet)
	api.HandleFunc("/provisioning/sessions/{sessionID}/fulfill", handler.FulfillSession).Methods(http.MethodPost)

	s.logger.Info("Provisioning config delivery routes registered")
}

// SetBMCHandler sets the BMC handler and registers bare metal management
// routes on the daemon's REST API.
func (s *RESTServer) SetBMCHandler(handler bmcwebsvc.RestHandler) {
	if handler == nil {
		return
	}
	s.bmcHandler = handler

	api := s.router.PathPrefix(restBasePath).Subrouter()
	api.HandleFunc("/bmc/{profileID:[0-9]+}/power", handler.PowerAction).Methods(http.MethodPost)
	api.HandleFunc("/bmc/{profileID:[0-9]+}/power", handler.PowerStatus).Methods(http.MethodGet)
	api.HandleFunc("/bmc/{profileID:[0-9]+}/boot-device", handler.SetBootDevice).Methods(http.MethodPost)
	api.HandleFunc("/bmc/{profileID:[0-9]+}/boot-device", handler.GetBootDevice).Methods(http.MethodGet)
	api.HandleFunc("/bmc/{profileID:[0-9]+}/virtual-media", handler.MountISO).Methods(http.MethodPost)
	api.HandleFunc("/bmc/{profileID:[0-9]+}/virtual-media", handler.UnmountISO).Methods(http.MethodDelete)
	api.HandleFunc("/bmc/{profileID:[0-9]+}/virtual-media", handler.VirtualMediaStatus).Methods(http.MethodGet)
	api.HandleFunc("/bmc/{profileID:[0-9]+}/sensors", handler.GetSensors).Methods(http.MethodGet)
	api.HandleFunc("/bmc/{profileID:[0-9]+}/system-info", handler.GetSystemInfo).Methods(http.MethodGet)
	api.HandleFunc("/bmc/{profileID:[0-9]+}/provision", handler.Provision).Methods(http.MethodPost)
	api.HandleFunc("/bmc/{profileID:[0-9]+}/provision", handler.ProvisionStatus).Methods(http.MethodGet)
	api.HandleFunc("/bmc/{profileID:[0-9]+}/enroll", handler.EnrollBMC).Methods(http.MethodPost)
	api.HandleFunc("/bmc/{profileID:[0-9]+}/cert/restore", handler.RestoreBMC).Methods(http.MethodPost)
	api.HandleFunc("/bmc/{profileID:[0-9]+}/cert", handler.GetWebCertificate).Methods(http.MethodGet)
	api.HandleFunc("/bmc/{profileID:[0-9]+}/cert", handler.ReplaceWebCertificate).Methods(http.MethodPut)
	api.HandleFunc("/bmc/{profileID:[0-9]+}/users", handler.ListUsers).Methods(http.MethodGet)
	api.HandleFunc("/bmc/{profileID:[0-9]+}/users", handler.CreateUser).Methods(http.MethodPost)
	api.HandleFunc("/bmc/{profileID:[0-9]+}/users/{slot:[0-9]+}", handler.DeleteUser).Methods(http.MethodDelete)
	api.HandleFunc("/bmc/{profileID:[0-9]+}/users/{slot:[0-9]+}/password", handler.SetUserPassword).Methods(http.MethodPut)
	api.HandleFunc("/bmc/{profileID:[0-9]+}/users/{slot:[0-9]+}/privilege", handler.SetUserPrivilege).Methods(http.MethodPut)

	s.logger.Info("BMC management routes registered")
}

// SetNTPHandlers wires the time-synchronization REST handlers onto the
// daemon's REST router so /api/v1/ntp/* is served. The handlers delegate to
// the same in-process NTPServiceServer that backs gRPC, QUIC, MCP, and the
// Unix socket, so every transport reports one clock. A nil server leaves the
// routes unmounted, which is the correct signal on a node with no `ntp:`
// section. guard checks each route's ntp:* scope; nil refuses every route.
func (s *RESTServer) SetNTPHandlers(server platformv1.NTPServiceServer, guard *restapi.ScopeGuard) {
	if server == nil {
		return
	}
	handlers := restapi.NewNTPHandlers(server, guard, s.logger)
	handlers.RegisterRoutes(s.router)
	s.logger.Info("NTP REST routes registered")
}

// SetVPNHandlers wires the VPN control-plane REST handlers onto the daemon's
// REST router so /api/v1/vpn/* is served. The handlers delegate to the same
// in-process VPNServiceServer that backs gRPC, QUIC, MCP, and the Unix
// socket. A nil server leaves the routes unmounted. guard checks each route's
// vpn:* scope; nil refuses every route.
func (s *RESTServer) SetVPNHandlers(server platformv1.VPNServiceServer, guard *restapi.ScopeGuard) {
	if server == nil {
		return
	}
	handlers := restapi.NewVPNHandlers(server, guard, s.logger)
	handlers.RegisterRoutes(s.router)
	s.logger.Info("VPN REST routes registered")
}

// SetAppServiceHandlers wires the Cache, Scheduler and Messaging REST
// handlers onto the daemon's REST router so /api/v1/cache/*,
// /api/v1/scheduler/* and /api/v1/messaging/* are served by the same
// in-process servers that back gRPC, QUIC, MCP, and the Unix socket. A nil
// server answers its routes with 503. guard checks each route's scope; nil
// refuses every route.
func (s *RESTServer) SetAppServiceHandlers(servers restapi.AppServiceServers, guard *restapi.ScopeGuard) {
	handlers := restapi.NewAppServiceHandlers(servers, guard, s.logger)
	handlers.RegisterRoutes(s.router)
	s.logger.Info("Application service REST routes registered")
}

// SetDeviceHandlers wires the device REST handlers (CRUD + profiles) onto
// the daemon's REST router. The handlers reuse the device service +
// profile service that the gRPC and QUIC adapters share, so REST clients
// see the same data as every other transport.
//
// attestSvc is the in-process DeviceService gRPC implementation, which owns
// the platform's single DeviceQuoteVerifier. Passing it is what makes
// POST /api/v1/devices/{id}/attest verify a quote; without it the route is
// not registered at all. Before #403 the REST package carried its own
// "verifier" that returned true for any input, so this route reported every
// device attested.
func (s *RESTServer) SetDeviceHandlers(
	deviceSvc restapi.DeviceServiceInterface,
	profileSvc restapi.ProfileServiceInterface,
	attestSvc platformv1.DeviceServiceServer,
) {
	if deviceSvc == nil && profileSvc == nil {
		return
	}
	opts := []restapi.DeviceHandlerOption{}
	if attestSvc != nil {
		opts = append(opts, restapi.WithDeviceAttestService(attestSvc))
	}
	handlers := restapi.NewDeviceHandlers(deviceSvc, profileSvc, s.logger, opts...)
	handlers.RegisterRoutes(s.router)
	s.logger.Info("Device REST routes registered", "attestation", attestSvc != nil)
}

// SetTenantHandlers wires the tenant REST handlers onto the daemon's REST
// router so /api/v1/tenants/* endpoints are served. The handlers delegate to
// the platform's tenant.Manager — the same instance used by the gRPC, QUIC,
// MCP, and Unix-socket adapters — so per-tenant state (CRUD, quotas, VLAN,
// barrier lifecycle) is identical across every transport.
//
// Without this wiring /api/v1/tenants/* would 404 even though the gRPC
// TenantService is registered. Mirrors SetDeviceHandlers / SetCAHandlers.
//
// Every route runs behind guard and authorizes the caller it verified as the
// tenant gRPC server does, with systemTenantID as the one tenant allowed to
// act on every other (restapi.TenantHandlers). A nil guard answers 403.
func (s *RESTServer) SetTenantHandlers(manager restapi.TenantManagerInterface, guard *restapi.ScopeGuard, systemTenantID string) {
	if manager == nil {
		return
	}
	handlers := restapi.NewTenantHandlers(
		restapi.WithTenantManager(manager),
		restapi.WithTenantLogger(s.logger),
		restapi.WithTenantGuard(guard),
		restapi.WithTenantSystemTenant(systemTenantID),
	)
	handlers.RegisterRoutes(s.router)
	s.logger.Info("Tenant REST routes registered")
}

// SetKMSHandlers wires the KMS REST handlers onto the daemon's REST router so
// /api/v1/kms/* endpoints are served. The service delegates to the same
// QuicBaaS SDK KMS and Crypto clients used by the gRPC, QUIC, MCP, and
// embedded transports, so keys created via REST are visible everywhere else
// and vice-versa. Mirrors SetDeviceHandlers / SetTenantHandlers.
func (s *RESTServer) SetKMSHandlers(service restapi.KMSService) {
	if service == nil {
		return
	}
	handlers := restapi.NewKMSHandlers(service, s.logger)
	handlers.RegisterRoutes(s.router)
	s.logger.Info("KMS REST routes registered")
}

// SetComputeHandlers wires the compute (VM and container) REST handlers onto
// the daemon's REST router. Every /api/v1/compute/* route runs the same
// ComputeService RPC gRPC serves, over protobuf JSON, behind the scope that
// RPC requires on gRPC, checked by guard.
func (s *RESTServer) SetComputeHandlers(compute platformv1.ComputeServiceServer, guard *restapi.ScopeGuard) {
	if compute == nil {
		return
	}
	restapi.NewComputeHandlers(compute, guard, s.logger).RegisterRoutes(s.router)
}

// SetOverlayHandlers wires the overlay REST handlers onto the daemon's REST
// router so /api/v1/sdn/overlay/* endpoints are served. When svc is nil the
// method is a no-op — routes are not mounted, so callers that 404 get a clear
// signal that the overlay feature is disabled rather than an internal error.
// Mirrors SetDeviceHandlers / SetTenantHandlers.
func (s *RESTServer) SetOverlayHandlers(svc restapi.OverlayServiceInterface) {
	if svc == nil {
		return
	}
	handlers := restapi.NewOverlayHandlers(svc, s.logger)
	handlers.RegisterRoutes(s.router)
	s.logger.Info("Overlay REST routes registered")
}

// SetCAHandlers wires the CA REST handlers onto the daemon's REST router so
// /api/v1/ca/* endpoints are served. The handlers wrap the production CA
// (quicbaasca.CACertificateAuthority) via CAAuthorityAdapter, which delegates to
// the same CA instance used by the gRPC, QUIC, MCP and Unix-socket adapters.
// All transports therefore share state — certificates issued via gRPC are
// visible via REST and vice-versa.
//
// guard authorizes POST /api/v1/ca/sign-csr, which needs a platform token
// granting ca:sign-csr (a client certificate alone is refused); when it is
// nil, sign-csr refuses every request.
func (s *RESTServer) SetCAHandlers(ca quicbaasca.CACertificateAuthority, guard *restapi.ScopeGuard) {
	if ca == nil {
		return
	}
	adapter := restapi.NewCAAuthorityAdapter(ca)
	if adapter == nil {
		return
	}
	var caObjStorage objectstorage.Client
	var caKMS issuance.KMS
	if s.config != nil {
		caKMS = s.config.csrKMS()
		if s.config.App != nil {
			caObjStorage = s.config.App.Storage
		}
	}
	handlers := restapi.NewCAHandlers(adapter, s.logger, caObjStorage).WithKMS(caKMS).WithScopeGuard(guard)
	handlers.RegisterRoutes(s.router)
	s.logger.Info("CA REST routes registered")

	// Wire auth factor endpoints (AAGUID lookup, mTLS probe, cert issuance,
	// MFA policy). These share the same CA instance as the CA handlers so
	// certificate issuance goes through the live platform CA.
	authFactorHandlers := restapi.NewAuthFactorHandlers(ca, s.logger)
	authFactorHandlers.RegisterRoutes(s.router)
	s.logger.Info("Auth factor REST routes registered")
}

// SetTPMHandlers mounts the physical TPM routes (/api/v1/tpm/...). Every
// route runs on tpm, the daemon's TPM service, with the protobuf JSON request
// and response the SDK speaks, so a REST call is the one gRPC, QUIC, MCP and
// Unix serve. Every route requires tpm:read, tpm:write or tpm:delete, checked
// by guard (a platform token, else the verified client certificate); with no
// guard every route refuses. A nil TPM service mounts nothing.
func (s *RESTServer) SetTPMHandlers(tpm platformv1.TPMServiceServer, guard *restapi.ScopeGuard) {
	if tpm == nil {
		return
	}
	restapi.NewTPMHandlers(s.logger).WithTPMService(tpm).WithScopeGuard(guard).RegisterRoutes(s.router)
}

// applyMiddleware wraps the router with middleware handlers
func (s *RESTServer) applyMiddleware(handler http.Handler) http.Handler {
	// Apply CORS middleware if enabled
	if s.config.RESTConfig.EnableCORS {
		handler = s.corsMiddleware(handler)
	}

	// Apply compression middleware if enabled
	if s.config.RESTConfig.EnableCompression {
		handler = s.compressionMiddleware(handler)
	}

	// Apply request logging middleware
	handler = s.loggingMiddleware(handler)

	// Apply request ID middleware
	handler = s.requestIDMiddleware(handler)

	return handler
}

// corsMiddleware handles CORS headers
func (s *RESTServer) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			allowed := false
			for _, o := range s.config.RESTConfig.AllowedOrigins {
				if o == "*" || o == origin {
					allowed = true
					break
				}
			}
			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", strings.Join(s.config.RESTConfig.AllowedMethods, ", "))
				w.Header().Set("Access-Control-Allow-Headers", strings.Join(s.config.RESTConfig.AllowedHeaders, ", "))
				w.Header().Set("Access-Control-Max-Age", "86400")
			}
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// compressionMiddleware handles gzip compression for responses
func (s *RESTServer) compressionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}

		gz := gzip.NewWriter(w)
		defer gz.Close()

		w.Header().Set("Content-Encoding", "gzip")
		gzw := &gzipResponseWriter{Writer: gz, ResponseWriter: w}
		next.ServeHTTP(gzw, r)
	})
}

// loggingMiddleware logs HTTP requests
func (s *RESTServer) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(sw, r)

		s.logger.Debug("HTTP request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"duration", time.Since(start),
			"remote", r.RemoteAddr,
		)
	})
}

// requestIDMiddleware adds a request ID to each request
func (s *RESTServer) requestIDMiddleware(next http.Handler) http.Handler {
	var requestCounter atomic.Uint64
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID(requestCounter.Add(1))
		}
		w.Header().Set("X-Request-ID", requestID)
		next.ServeHTTP(w, r)
	})
}

// Handler implementations

// handleHealth handles GET /api/v1/health
func (s *RESTServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	healthResp := HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now().UTC(),
	}

	// Check if health registry is available for detailed health
	if s.service.healthRegistry != nil {
		systemHealth := s.service.healthRegistry.Check(ctx)
		healthResp.Status = string(systemHealth.Status)
		healthResp.Components = make([]ComponentHealthResponse, 0, len(systemHealth.Components))
		for _, comp := range systemHealth.Components {
			healthResp.Components = append(healthResp.Components, ComponentHealthResponse{
				Name:      comp.Name,
				Status:    string(comp.Status),
				Message:   comp.Message,
				LastCheck: comp.LastChecked,
			})
		}
	}

	s.writeJSON(w, http.StatusOK, healthResp)
}

// handleStatus handles GET /api/v1/status
func (s *RESTServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	appVersion := app.GetVersion()

	statusResp := StatusResponse{
		Status:    "ready",
		Version:   appVersion.Version,
		BuildTime: appVersion.BuildDate,
		GitCommit: appVersion.GitHash,
		GoVersion: runtime.Version(),
		System: SystemInfoResponse{
			OS:                runtime.GOOS,
			Arch:              runtime.GOARCH,
			NumCPUs:           runtime.NumCPU(),
			TotalMemoryMB:     memStats.Sys / 1024 / 1024,
			AvailableMemoryMB: (memStats.Sys - memStats.Alloc) / 1024 / 1024,
			Uptime:            time.Since(s.service.startTime).String(),
		},
		Timestamp: time.Now().UTC(),
	}

	s.writeJSON(w, http.StatusOK, statusResp)
}

// handleVersion handles GET /api/v1/version
func (s *RESTServer) handleVersion(w http.ResponseWriter, r *http.Request) {
	appVersion := app.GetVersion()

	versionResp := VersionResponse{
		Version:   appVersion.Version,
		BuildTime: appVersion.BuildDate,
		GitCommit: appVersion.GitHash,
		GoVersion: runtime.Version(),
	}

	s.writeJSON(w, http.StatusOK, versionResp)
}

// handleListServices handles GET /api/v1/services
func (s *RESTServer) handleListServices(w http.ResponseWriter, r *http.Request) {
	s.service.mu.RLock()
	defer s.service.mu.RUnlock()

	services := make([]ServiceInfoResponse, 0, len(s.service.services))
	for name, state := range s.service.services {
		state.mu.RLock()
		status := serviceStatusToString(int32(state.observedStatus()))

		var uptime string
		if !state.startedAt.IsZero() {
			uptime = time.Since(state.startedAt).String()
		}

		svcInfo := ServiceInfoResponse{
			Name:       name,
			Status:     status,
			StartedAt:  state.startedAt,
			Uptime:     uptime,
			StartCount: state.startCount.Load(),
			StopCount:  state.stopCount.Load(),
			LastError:  state.lastError,
		}
		state.mu.RUnlock()
		services = append(services, svcInfo)
	}

	s.writeJSON(w, http.StatusOK, ServicesListResponse{
		Services:  services,
		Count:     len(services),
		Timestamp: time.Now().UTC(),
	})
}

// handleGetService handles GET /api/v1/services/{service}
func (s *RESTServer) handleGetService(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serviceName := vars["service"]

	s.service.mu.RLock()
	state, exists := s.service.services[serviceName]
	s.service.mu.RUnlock()

	if !exists {
		s.writeError(w, http.StatusNotFound, ErrServiceNotFound{ServiceName: serviceName})
		return
	}

	state.mu.RLock()
	status := serviceStatusToString(int32(state.observedStatus()))

	var uptime string
	if !state.startedAt.IsZero() {
		uptime = time.Since(state.startedAt).String()
	}

	svcInfo := ServiceInfoResponse{
		Name:       serviceName,
		Status:     status,
		StartedAt:  state.startedAt,
		Uptime:     uptime,
		StartCount: state.startCount.Load(),
		StopCount:  state.stopCount.Load(),
		LastError:  state.lastError,
	}
	state.mu.RUnlock()

	s.writeJSON(w, http.StatusOK, svcInfo)
}

// handleStartService handles POST /api/v1/services/{service}/start
func (s *RESTServer) handleStartService(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serviceName := vars["service"]

	s.service.mu.RLock()
	state, exists := s.service.services[serviceName]
	s.service.mu.RUnlock()

	if !exists {
		s.writeError(w, http.StatusNotFound, ErrServiceNotFound{ServiceName: serviceName})
		return
	}
	if refusal, owned := processOwned(state.service); owned {
		s.writeError(w, restServiceRefusalStatus, refusal)
		return
	}

	state.mu.Lock()
	if state.observedStatus() == platformv1.ServiceStatus_SERVICE_STATUS_RUNNING {
		state.mu.Unlock()
		s.writeError(w, http.StatusConflict, ErrServiceAlreadyRunning{ServiceName: serviceName})
		return
	}

	state.status.Store(int32(platformv1.ServiceStatus_SERVICE_STATUS_STARTING))
	state.lastError = ""

	if err := state.service.Start(r.Context()); err != nil {
		state.status.Store(int32(platformv1.ServiceStatus_SERVICE_STATUS_ERROR))
		state.lastError = err.Error()
		state.mu.Unlock()
		s.writeError(w, http.StatusInternalServerError, ErrServiceStartFailed{ServiceName: serviceName, Reason: err.Error()})
		return
	}

	state.status.Store(int32(platformv1.ServiceStatus_SERVICE_STATUS_RUNNING))
	state.startedAt = time.Now()
	state.startCount.Add(1)
	state.mu.Unlock()

	s.writeJSON(w, http.StatusOK, ServiceActionResponse{
		Service: serviceName,
		Action:  "start",
		Success: true,
		Message: "service started successfully",
	})
}

// handleStopService handles POST /api/v1/services/{service}/stop
func (s *RESTServer) handleStopService(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serviceName := vars["service"]

	s.service.mu.RLock()
	state, exists := s.service.services[serviceName]
	s.service.mu.RUnlock()

	if !exists {
		s.writeError(w, http.StatusNotFound, ErrServiceNotFound{ServiceName: serviceName})
		return
	}
	if refusal, owned := processOwned(state.service); owned {
		s.writeError(w, restServiceRefusalStatus, refusal)
		return
	}

	state.mu.Lock()
	if state.observedStatus() == platformv1.ServiceStatus_SERVICE_STATUS_STOPPED {
		state.mu.Unlock()
		s.writeError(w, http.StatusConflict, ErrServiceNotRunning{ServiceName: serviceName})
		return
	}

	state.status.Store(int32(platformv1.ServiceStatus_SERVICE_STATUS_STOPPING))

	if err := state.service.Stop(r.Context()); err != nil {
		state.status.Store(int32(platformv1.ServiceStatus_SERVICE_STATUS_ERROR))
		state.lastError = err.Error()
		state.mu.Unlock()
		s.writeError(w, http.StatusInternalServerError, ErrServiceStopFailed{ServiceName: serviceName, Reason: err.Error()})
		return
	}

	state.status.Store(int32(platformv1.ServiceStatus_SERVICE_STATUS_STOPPED))
	state.stopCount.Add(1)
	state.mu.Unlock()

	s.writeJSON(w, http.StatusOK, ServiceActionResponse{
		Service: serviceName,
		Action:  "stop",
		Success: true,
		Message: "service stopped successfully",
	})
}

// handleRestartService handles POST /api/v1/services/{service}/restart
func (s *RESTServer) handleRestartService(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serviceName := vars["service"]

	s.service.mu.RLock()
	state, exists := s.service.services[serviceName]
	s.service.mu.RUnlock()

	if !exists {
		s.writeError(w, http.StatusNotFound, ErrServiceNotFound{ServiceName: serviceName})
		return
	}
	if refusal, owned := processOwned(state.service); owned {
		s.writeError(w, restServiceRefusalStatus, refusal)
		return
	}

	ctx := r.Context()

	state.mu.Lock()
	// Stop if running
	if state.observedStatus() == platformv1.ServiceStatus_SERVICE_STATUS_RUNNING {
		state.status.Store(int32(platformv1.ServiceStatus_SERVICE_STATUS_STOPPING))
		if err := state.service.Stop(ctx); err != nil {
			state.status.Store(int32(platformv1.ServiceStatus_SERVICE_STATUS_ERROR))
			state.lastError = err.Error()
			state.mu.Unlock()
			s.writeError(w, http.StatusInternalServerError, ErrServiceStopFailed{ServiceName: serviceName, Reason: err.Error()})
			return
		}
		state.stopCount.Add(1)
	}

	// Start
	state.status.Store(int32(platformv1.ServiceStatus_SERVICE_STATUS_STARTING))
	state.lastError = ""
	if err := state.service.Start(ctx); err != nil {
		state.status.Store(int32(platformv1.ServiceStatus_SERVICE_STATUS_ERROR))
		state.lastError = err.Error()
		state.mu.Unlock()
		s.writeError(w, http.StatusInternalServerError, ErrServiceStartFailed{ServiceName: serviceName, Reason: err.Error()})
		return
	}

	state.status.Store(int32(platformv1.ServiceStatus_SERVICE_STATUS_RUNNING))
	state.startedAt = time.Now()
	state.startCount.Add(1)
	state.mu.Unlock()

	s.writeJSON(w, http.StatusOK, ServiceActionResponse{
		Service: serviceName,
		Action:  "restart",
		Success: true,
		Message: "service restarted successfully",
	})
}

// handleProtocols handles GET /api/v1/protocols
func (s *RESTServer) handleProtocols(w http.ResponseWriter, r *http.Request) {
	protocols := []ProtocolStatusResponse{
		{
			Name:    "REST",
			Enabled: s.config.EnableREST,
			Address: s.config.RESTListenAddr,
			Port:    extractPort(s.config.RESTListenAddr),
			Status:  boolToStatus(s.running.Load()),
			TLS:     s.config.RESTTLSCertFile != "",
		},
		{
			Name:    "gRPC",
			Enabled: s.config.EnableGRPCTCP,
			Address: s.config.GRPCListenAddr,
			Port:    extractPort(s.config.GRPCListenAddr),
			Status:  "unknown", // Would need reference to gRPC server
			TLS:     s.config.GRPCTLSCertFile != "",
		},
		{
			Name:    "Unix Socket",
			Enabled: true,
			Address: s.config.SocketPath,
			Port:    0,
			Status:  "running",
			TLS:     false,
		},
		{
			Name:    "QUIC",
			Enabled: s.config.EnableQUIC,
			Address: s.config.QUICListenAddr,
			Port:    extractPort(s.config.QUICListenAddr),
			Status:  boolToStatus(s.config.EnableQUIC),
			TLS:     true, // QUIC always uses TLS
		},
		{
			Name:    "MCP",
			Enabled: s.config.EnableMCP,
			Address: getMCPAddress(s.config),
			Port:    extractPort(getMCPAddress(s.config)),
			Status:  boolToStatus(s.config.EnableMCP),
			TLS:     s.config.MCPServesHTTP(),
		},
	}

	s.writeJSON(w, http.StatusOK, ProtocolsResponse{
		Protocols: protocols,
		Timestamp: time.Now().UTC(),
	})
}

// Helper methods

func (s *RESTServer) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		s.logger.Error("Failed to encode JSON response", "error", err)
	}
}

func (s *RESTServer) writeError(w http.ResponseWriter, status int, err error) {
	s.writeJSON(w, status, ErrorResponse{
		Error:     err.Error(),
		Code:      status,
		Timestamp: time.Now().UTC(),
	})
}

// Response types

// HealthResponse represents the health check response
type HealthResponse struct {
	Status     string                    `json:"status"`
	Components []ComponentHealthResponse `json:"components,omitempty"`
	Timestamp  time.Time                 `json:"timestamp"`
}

// ComponentHealthResponse represents individual component health
type ComponentHealthResponse struct {
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	Message   string    `json:"message,omitempty"`
	LastCheck time.Time `json:"last_check"`
}

// StatusResponse represents the daemon status response
type StatusResponse struct {
	Status    string             `json:"status"`
	Version   string             `json:"version"`
	BuildTime string             `json:"build_time"`
	GitCommit string             `json:"git_commit"`
	GoVersion string             `json:"go_version"`
	System    SystemInfoResponse `json:"system"`
	Timestamp time.Time          `json:"timestamp"`
}

// SystemInfoResponse represents system information
type SystemInfoResponse struct {
	OS                string `json:"os"`
	Arch              string `json:"arch"`
	NumCPUs           int    `json:"num_cpus"`
	TotalMemoryMB     uint64 `json:"total_memory_mb"`
	AvailableMemoryMB uint64 `json:"available_memory_mb"`
	Uptime            string `json:"uptime"`
}

// VersionResponse represents the version response
type VersionResponse struct {
	Version   string `json:"version"`
	BuildTime string `json:"build_time"`
	GitCommit string `json:"git_commit"`
	GoVersion string `json:"go_version"`
}

// ServiceInfoResponse represents service information
type ServiceInfoResponse struct {
	Name       string    `json:"name"`
	Status     string    `json:"status"`
	StartedAt  time.Time `json:"started_at,omitempty"`
	Uptime     string    `json:"uptime,omitempty"`
	StartCount uint64    `json:"start_count"`
	StopCount  uint64    `json:"stop_count"`
	LastError  string    `json:"last_error,omitempty"`
}

// ServicesListResponse represents the list of services
type ServicesListResponse struct {
	Services  []ServiceInfoResponse `json:"services"`
	Count     int                   `json:"count"`
	Timestamp time.Time             `json:"timestamp"`
}

// ServiceActionResponse represents a service action result
type ServiceActionResponse struct {
	Service string `json:"service"`
	Action  string `json:"action"`
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// ProtocolStatusResponse represents a protocol's status
type ProtocolStatusResponse struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Address string `json:"address"`
	Port    int    `json:"port"`
	Status  string `json:"status"`
	TLS     bool   `json:"tls"`
}

// ProtocolsResponse represents all protocol statuses
type ProtocolsResponse struct {
	Protocols []ProtocolStatusResponse `json:"protocols"`
	Timestamp time.Time                `json:"timestamp"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error     string    `json:"error"`
	Code      int       `json:"code"`
	Timestamp time.Time `json:"timestamp"`
}

// Helper types for middleware

type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

// Unwrap returns the wrapped writer, so http.ResponseController reaches the
// connection through the middleware (a stop route moves its write deadline).
func (w *gzipResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// Unwrap returns the wrapped writer, so http.ResponseController reaches the
// connection through the middleware (a stop route moves its write deadline).
func (w *statusWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// Utility functions

func generateRequestID(counter uint64) string {
	return time.Now().Format("20060102150405") + "-" + strconv.FormatUint(counter, 10)
}

func extractPort(addr string) int {
	parts := strings.Split(addr, ":")
	if len(parts) < 2 {
		return 0
	}
	port := 0
	for _, c := range parts[len(parts)-1] {
		if c >= '0' && c <= '9' {
			port = port*10 + int(c-'0')
		} else {
			return 0
		}
	}
	return port
}

func boolToStatus(running bool) string {
	if running {
		return "running"
	}
	return "stopped"
}

func getMCPAddress(config *Config) string {
	if config.MCPConfig != nil {
		return config.MCPConfig.HTTPAddr
	}
	return ""
}

// SetCeremonyService wires the ceremony service into the REST server and
// registers its routes.
func (s *RESTServer) SetCeremonyService(svc *CeremonyService) {
	if svc == nil {
		return
	}
	h := newCeremonyRESTHandlers(svc)
	api := s.router.PathPrefix(restBasePath).Subrouter()
	h.registerCeremonyRoutes(api)
	s.logger.Info("Ceremony REST routes registered")
}

// SetPIVService wires the PIV service into the REST server and registers its routes.
func (s *RESTServer) SetPIVService(svc *PIVService) {
	if svc == nil {
		return
	}
	h := newPIVRESTHandlers(svc)
	api := s.router.PathPrefix(restBasePath).Subrouter()
	h.registerPIVRoutes(api)
	s.logger.Info("PIV REST routes registered")
}

// SetLUKSService wires the LUKS service into the REST server and registers its routes.
func (s *RESTServer) SetLUKSService(svc *LUKSService) {
	if svc == nil {
		return
	}
	h := newLUKSRESTHandlers(svc)
	api := s.router.PathPrefix(restBasePath).Subrouter()
	h.registerLUKSRoutes(api)
	s.logger.Info("LUKS REST routes registered")
}

// SetFIDO2Service wires the FIDO2 service into the REST server and registers its routes.
func (s *RESTServer) SetFIDO2Service(svc *FIDO2Service) {
	if svc == nil {
		return
	}
	h := newFIDO2RESTHandlers(svc)
	api := s.router.PathPrefix(restBasePath).Subrouter()
	h.registerFIDO2Routes(api)
	s.logger.Info("FIDO2 REST routes registered")
}

// SetClusterService wires the Cluster gRPC service into the REST server
// and mounts /api/v1/cluster routes. The handlers fall through to the
// gRPC implementation, so REST and gRPC report identical state when the
// underlying coordinator is missing (HTTP 503 + Unavailable code).
func (s *RESTServer) SetClusterService(svc platformv1.ClusterServiceServer) {
	h := newClusterRESTHandlers(svc)
	api := s.router.PathPrefix(restBasePath).Subrouter()
	h.registerClusterRoutes(api)
	if svc == nil {
		s.logger.Info("Cluster REST routes registered (no backend; will return 503)")
		return
	}
	s.logger.Info("Cluster REST routes registered")
}
