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
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning/configdelivery"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	bmcwebsvc "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/bmc"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
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
}

// NewRESTServer creates a new REST server for the daemon
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

	s.running.Store(true)

	// Configure TLS: prefer in-memory certificate, fall back to files
	if s.config.TLSCertificate != nil || (s.config.RESTTLSCertFile != "" && s.config.RESTTLSKeyFile != "") {
		var cert tls.Certificate
		if s.config.TLSCertificate != nil {
			cert = *s.config.TLSCertificate
		} else {
			var err error
			cert, err = tls.LoadX509KeyPair(s.config.RESTTLSCertFile, s.config.RESTTLSKeyFile)
			if err != nil {
				s.running.Store(false)
				return ErrRESTServerStartFailed{Reason: "failed to load TLS certificates: " + err.Error()}
			}
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}

		// Enable mutual TLS if configured
		if s.config.EnableMTLS {
			clientCAPool := s.config.MTLSClientCAPool
			if clientCAPool == nil && s.config.MTLSClientCAFile != "" {
				caCert, readErr := os.ReadFile(s.config.MTLSClientCAFile)
				if readErr != nil {
					s.running.Store(false)
					return ErrRESTServerStartFailed{Reason: "failed to read mTLS client CA file: " + readErr.Error()}
				}
				clientCAPool = x509.NewCertPool()
				if !clientCAPool.AppendCertsFromPEM(caCert) {
					s.running.Store(false)
					return ErrRESTServerStartFailed{Reason: "failed to parse mTLS client CA certificates"}
				}
			}
			if clientCAPool != nil {
				tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
				tlsConfig.ClientCAs = clientCAPool
				s.logger.Info("REST server mTLS enabled", "addr", s.config.RESTListenAddr)
			}
		}

		s.server.TLSConfig = tlsConfig
		s.logger.Info("REST server starting with TLS", "addr", s.config.RESTListenAddr)
		go func() {
			if err := s.server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				s.logger.Error("REST server error", "error", err)
				s.running.Store(false)
			}
		}()
	} else {
		s.logger.Info("REST server starting without TLS", "addr", s.config.RESTListenAddr)
		go func() {
			if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				s.logger.Error("REST server error", "error", err)
				s.running.Store(false)
			}
		}()
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
	// Root-level health endpoint for service discovery and load balancers
	s.router.HandleFunc("/health", s.handleHealth).Methods(http.MethodGet)

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

	s.logger.Info("BMC management routes registered")
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
		status := serviceStatusToString(state.status.Load())

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
	status := serviceStatusToString(state.status.Load())

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

	state.mu.Lock()
	if platformv1.ServiceStatus(state.status.Load()) == platformv1.ServiceStatus_SERVICE_STATUS_RUNNING {
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

	state.mu.Lock()
	if platformv1.ServiceStatus(state.status.Load()) == platformv1.ServiceStatus_SERVICE_STATUS_STOPPED {
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

	ctx := r.Context()

	state.mu.Lock()
	// Stop if running
	if platformv1.ServiceStatus(state.status.Load()) == platformv1.ServiceStatus_SERVICE_STATUS_RUNNING {
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
			TLS:     false,
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

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
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
