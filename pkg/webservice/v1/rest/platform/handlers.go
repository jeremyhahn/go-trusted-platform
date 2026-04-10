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
	"net/http"
	"runtime"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// PlatformHandlers provides REST handlers for platform daemon operations
type PlatformHandlers struct {
	logger          *logging.Logger
	respWriter      response.HttpWriter
	healthRegistry  health.Registry
	servicesManager ServicesManager
	protocolConfig  *ProtocolConfig
	versionInfo     *VersionInfo
	startTime       time.Time
	restServerRunFn func() bool
}

// NewPlatformHandlers creates a new PlatformHandlers instance
func NewPlatformHandlers(
	logger *logging.Logger,
	respWriter response.HttpWriter,
) *PlatformHandlers {
	return &PlatformHandlers{
		logger:     logger,
		respWriter: respWriter,
		startTime:  time.Now(),
	}
}

// SetHealthRegistry sets the health registry for health checks
func (h *PlatformHandlers) SetHealthRegistry(registry health.Registry) {
	h.healthRegistry = registry
}

// SetServicesManager sets the services manager for service management
func (h *PlatformHandlers) SetServicesManager(manager ServicesManager) {
	h.servicesManager = manager
}

// SetProtocolConfig sets the protocol config for protocol status
func (h *PlatformHandlers) SetProtocolConfig(config *ProtocolConfig) {
	h.protocolConfig = config
}

// SetRESTServerRunningFunc sets the function to check if REST server is running
func (h *PlatformHandlers) SetRESTServerRunningFunc(fn func() bool) {
	h.restServerRunFn = fn
}

// SetVersionInfo sets the version info for status and version endpoints
func (h *PlatformHandlers) SetVersionInfo(info *VersionInfo) {
	h.versionInfo = info
}

// GetHealth handles GET /api/v1/platform/health
func (h *PlatformHandlers) GetHealth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	healthResp := HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now().Unix(),
	}

	// Check if health registry is available for detailed health
	if h.healthRegistry != nil {
		systemHealth := h.healthRegistry.Check(ctx)
		healthResp.Status = string(systemHealth.Status)
		healthResp.Components = make([]ComponentHealthResponse, 0, len(systemHealth.Components))
		for _, comp := range systemHealth.Components {
			healthResp.Components = append(healthResp.Components, ComponentHealthResponse{
				Name:      comp.Name,
				Status:    string(comp.Status),
				Message:   comp.Message,
				LastCheck: comp.LastChecked.Unix(),
			})
		}
	}

	h.respWriter.Success200(w, r, healthResp)
}

// GetStatus handles GET /api/v1/platform/status
func (h *PlatformHandlers) GetStatus(w http.ResponseWriter, r *http.Request) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	version := ""
	buildTime := ""
	gitCommit := ""
	if h.versionInfo != nil {
		version = h.versionInfo.Version
		buildTime = h.versionInfo.BuildDate
		gitCommit = h.versionInfo.GitHash
	}

	statusResp := StatusResponse{
		Status:    "ready",
		Version:   version,
		BuildTime: buildTime,
		GitCommit: gitCommit,
		GoVersion: runtime.Version(),
		System: SystemInfoResponse{
			OS:                runtime.GOOS,
			Arch:              runtime.GOARCH,
			NumCPUs:           runtime.NumCPU(),
			TotalMemoryMB:     memStats.Sys / 1024 / 1024,
			AvailableMemoryMB: (memStats.Sys - memStats.Alloc) / 1024 / 1024,
			Uptime:            time.Since(h.startTime).String(),
		},
		Timestamp: time.Now().Unix(),
	}

	h.respWriter.Success200(w, r, statusResp)
}

// GetVersion handles GET /api/v1/platform/version
func (h *PlatformHandlers) GetVersion(w http.ResponseWriter, r *http.Request) {
	version := ""
	buildTime := ""
	gitCommit := ""
	if h.versionInfo != nil {
		version = h.versionInfo.Version
		buildTime = h.versionInfo.BuildDate
		gitCommit = h.versionInfo.GitHash
	}

	versionResp := VersionResponse{
		Version:   version,
		BuildTime: buildTime,
		GitCommit: gitCommit,
		GoVersion: runtime.Version(),
	}

	h.respWriter.Success200(w, r, versionResp)
}
