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

package platform

import (
	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

const (
	// basePath is the platform route prefix relative to the parent API
	// subrouter. The parent already mounts at /api/v1, so routes resolve
	// to /api/v1/platform/... at runtime.
	basePath = "/platform"
)

// PlatformRouter provides REST routing for platform daemon operations
type PlatformRouter struct {
	handlers *PlatformHandlers
}

// NewPlatformRouter creates a new PlatformRouter instance
func NewPlatformRouter(
	logger *logging.Logger,
	respWriter response.HttpWriter,
) *PlatformRouter {
	return &PlatformRouter{
		handlers: NewPlatformHandlers(logger, respWriter),
	}
}

// SetHealthRegistry sets the health registry for health checks
func (r *PlatformRouter) SetHealthRegistry(registry health.Registry) {
	r.handlers.SetHealthRegistry(registry)
}

// SetServicesManager sets the services manager for service management
func (r *PlatformRouter) SetServicesManager(manager ServicesManager) {
	r.handlers.SetServicesManager(manager)
}

// SetProtocolConfig sets the protocol config for protocol status
func (r *PlatformRouter) SetProtocolConfig(config *ProtocolConfig) {
	r.handlers.SetProtocolConfig(config)
}

// SetRESTServerRunningFunc sets the function to check if REST server is running
func (r *PlatformRouter) SetRESTServerRunningFunc(fn func() bool) {
	r.handlers.SetRESTServerRunningFunc(fn)
}

// SetVersionInfo sets the version info for status and version endpoints
func (r *PlatformRouter) SetVersionInfo(info *VersionInfo) {
	r.handlers.SetVersionInfo(info)
}

// SetConfigReloader wires the daemon's config-reload surface into the
// /platform/config/reload handler. Routes are always registered; if
// the reloader is unset, the handler returns 503 with a structured
// body so the surface is honest about being dark.
func (r *PlatformRouter) SetConfigReloader(rl ConfigReloader) {
	r.handlers.SetConfigReloader(rl)
}

// SetLogQuerier wires the daemon's log surface into /platform/logs.
func (r *PlatformRouter) SetLogQuerier(q LogQuerier) {
	r.handlers.SetLogQuerier(q)
}

// Handlers returns the underlying handlers for direct access if needed
func (r *PlatformRouter) Handlers() *PlatformHandlers {
	return r.handlers
}

// RegisterRoutes registers all platform REST routes on the provided router.
// The router parameter is expected to be the /api/v1 subrouter, so routes
// are registered under /platform relative to that prefix.
func (r *PlatformRouter) RegisterRoutes(router *mux.Router) {
	// Create subrouter for platform endpoints
	platformRouter := router.PathPrefix(basePath).Subrouter()

	// Register all route groups
	r.registerHealthRoutes(platformRouter)
	r.registerStatusRoutes(platformRouter)
	r.registerServiceRoutes(platformRouter)
	r.registerProtocolRoutes(platformRouter)
	r.registerMetricsRoutes(platformRouter)
	r.registerConfigRoutes(platformRouter)
	r.registerLogRoutes(platformRouter)
}

// registerConfigRoutes registers platform configuration endpoints.
// GET    /api/v1/platform/config                              - Full merged config (redacted by default)
// POST   /api/v1/platform/config/reload                       - Re-read config file (captures pre-reload snapshot)
// POST   /api/v1/platform/config/validate                     - Dry-run validate proposed YAML
// GET    /api/v1/platform/config/snapshots                    - List snapshot history
// POST   /api/v1/platform/config/snapshots                    - Capture current state as a snapshot
// GET    /api/v1/platform/config/snapshots/{id}               - Get a snapshot (full tree)
// DELETE /api/v1/platform/config/snapshots/{id}               - Delete a snapshot
// POST   /api/v1/platform/config/snapshots/{id}/rollback      - Roll back to a snapshot
func (r *PlatformRouter) registerConfigRoutes(router *mux.Router) {
	router.HandleFunc("/config", r.handlers.GetConfig).Methods("GET")
	router.HandleFunc("/config/reload", r.handlers.ReloadConfig).Methods("POST")
	router.HandleFunc("/config/validate", r.handlers.ValidateConfig).Methods("POST")
	router.HandleFunc("/config/snapshots", r.handlers.ListSnapshots).Methods("GET")
	router.HandleFunc("/config/snapshots", r.handlers.CreateSnapshot).Methods("POST")
	router.HandleFunc("/config/snapshots/{id}", r.handlers.GetSnapshot).Methods("GET")
	router.HandleFunc("/config/snapshots/{id}", r.handlers.DeleteSnapshot).Methods("DELETE")
	router.HandleFunc("/config/snapshots/{id}/rollback", r.handlers.Rollback).Methods("POST")
}

// registerLogRoutes registers structured log query / stream endpoints.
// GET    /api/v1/platform/logs              - Paginated query
// GET    /api/v1/platform/logs/services     - Service-selector list
// GET    /api/v1/platform/logs/stream       - SSE live tail
func (r *PlatformRouter) registerLogRoutes(router *mux.Router) {
	router.HandleFunc("/logs", r.handlers.QueryLogs).Methods("GET")
	router.HandleFunc("/logs/services", r.handlers.ListLogServices).Methods("GET")
	router.HandleFunc("/logs/stream", r.handlers.StreamLogs).Methods("GET")
}

// registerHealthRoutes registers health check endpoints
// GET    /api/v1/platform/health                - Get platform health status
func (r *PlatformRouter) registerHealthRoutes(router *mux.Router) {
	router.HandleFunc("/health", r.handlers.GetHealth).Methods("GET")
}

// registerStatusRoutes registers status and version endpoints
// GET    /api/v1/platform/status                - Get platform status
// GET    /api/v1/platform/version               - Get platform version
// GET    /api/v1/platform/system                - Get system info (SDK alias)
func (r *PlatformRouter) registerStatusRoutes(router *mux.Router) {
	router.HandleFunc("/status", r.handlers.GetStatus).Methods("GET")
	router.HandleFunc("/version", r.handlers.GetVersion).Methods("GET")
	// /system mirrors what the JS SDK calls (`platform.getSystemInfo()`),
	// which expects `{system: {...}}`. We re-use the status response's
	// system block so the same handler covers both shapes.
	router.HandleFunc("/system", r.handlers.GetSystem).Methods("GET")
}

// registerServiceRoutes registers service management endpoints
// GET    /api/v1/platform/services              - List all services
// GET    /api/v1/platform/services/{service}    - Get service status
// POST   /api/v1/platform/services/{service}/start   - Start a service
// POST   /api/v1/platform/services/{service}/stop    - Stop a service
// POST   /api/v1/platform/services/{service}/restart - Restart a service
func (r *PlatformRouter) registerServiceRoutes(router *mux.Router) {
	// Service collection routes
	router.HandleFunc("/services", r.handlers.ListServices).Methods("GET")

	// Service instance routes
	router.HandleFunc("/services/{service}", r.handlers.GetService).Methods("GET")
	router.HandleFunc("/services/{service}/start", r.handlers.StartService).Methods("POST")
	router.HandleFunc("/services/{service}/stop", r.handlers.StopService).Methods("POST")
	router.HandleFunc("/services/{service}/restart", r.handlers.RestartService).Methods("POST")
}

// registerProtocolRoutes registers protocol status endpoints
// GET    /api/v1/platform/protocols             - Get protocol status
func (r *PlatformRouter) registerProtocolRoutes(router *mux.Router) {
	router.HandleFunc("/protocols", r.handlers.GetProtocols).Methods("GET")
}

// registerMetricsRoutes registers the platform metrics aggregator used
// by the dashboard. Returns aggregated service health + system snapshot.
//
// GET    /api/v1/platform/metrics              - Get platform metrics
func (r *PlatformRouter) registerMetricsRoutes(router *mux.Router) {
	router.HandleFunc("/metrics", r.handlers.GetMetrics).Methods("GET")
}
