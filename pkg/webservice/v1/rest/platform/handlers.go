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
	"github.com/jeremyhahn/go-trusted-platform/pkg/sysstats"
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
	sysSampler      *sysstats.Sampler
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
		sysSampler: sysstats.NewSampler(""),
	}
}

// SetDiskPath overrides the filesystem path the metrics handler uses
// when reporting disk usage. Defaults to "/" if never called.
func (h *PlatformHandlers) SetDiskPath(path string) {
	h.sysSampler = sysstats.NewSampler(path)
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

// GetHealth handles GET /api/v1/platform/health. The body is shaped to
// match the JS SDK's GetHealthResponse so the WebUI dashboard reads
// `response.data.health.healthy` etc. directly.
func (h *PlatformHandlers) GetHealth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := time.Now().UTC().Format(time.RFC3339Nano)

	ph := PlatformHealth{
		Healthy:   true,
		Status:    "healthy",
		Services:  []ServiceHealth{},
		Timestamp: now,
	}

	if h.healthRegistry != nil {
		systemHealth := h.healthRegistry.Check(ctx)
		ph.Status = string(systemHealth.Status)
		ph.Healthy = systemHealth.Status == health.StatusHealthy
		if !ph.Healthy && systemHealth.Status == health.StatusDegraded {
			ph.Message = "one or more components are degraded"
		} else if systemHealth.Status == health.StatusUnhealthy {
			ph.Message = "one or more components are unhealthy"
		}
		ph.Services = make([]ServiceHealth, 0, len(systemHealth.Components))
		for _, comp := range systemHealth.Components {
			ph.Services = append(ph.Services, ServiceHealth{
				Name:      comp.Name,
				Healthy:   comp.Status == health.StatusHealthy,
				Status:    string(comp.Status),
				Message:   comp.Message,
				LastCheck: comp.LastChecked.UTC().Format(time.RFC3339Nano),
			})
		}
	}

	h.respWriter.Success200(w, r, HealthResponse{Health: ph})
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

// GetSystem handles GET /api/v1/platform/system. The JS SDK calls this
// to populate platform/health and platform/metrics dashboard widgets,
// expecting `{system: {...}}`.
func (h *PlatformHandlers) GetSystem(w http.ResponseWriter, r *http.Request) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	resp := struct {
		System SystemInfoResponse `json:"system"`
	}{
		System: SystemInfoResponse{
			OS:                runtime.GOOS,
			Arch:              runtime.GOARCH,
			NumCPUs:           runtime.NumCPU(),
			TotalMemoryMB:     memStats.Sys / 1024 / 1024,
			AvailableMemoryMB: (memStats.Sys - memStats.Alloc) / 1024 / 1024,
			Uptime:            time.Since(h.startTime).String(),
		},
	}
	h.respWriter.Success200(w, r, resp)
}

// GetMetrics handles GET /api/v1/platform/metrics. Returns aggregated
// system + service health for the dashboard's CPU/Memory/Storage tiles.
// The body matches the JS SDK GetMetricsResponse contract so the WebUI
// reads `response.data.metrics.cpuUsagePercent` directly.
func (h *PlatformHandlers) GetMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := time.Now().UTC().Format(time.RFC3339Nano)

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	pm := PlatformMetrics{
		OverallStatus: "healthy",
		Services:      []ServiceMetricResponse{},
		System: SystemInfoResponse{
			OS:                runtime.GOOS,
			Arch:              runtime.GOARCH,
			NumCPUs:           runtime.NumCPU(),
			TotalMemoryMB:     memStats.Sys / 1024 / 1024,
			AvailableMemoryMB: (memStats.Sys - memStats.Alloc) / 1024 / 1024,
			Uptime:            time.Since(h.startTime).String(),
		},
		Timestamp: now,
	}

	if h.sysSampler != nil {
		if snap, err := h.sysSampler.Snapshot(); err == nil {
			pm.CPUUsagePercent = snap.CPUPercent
			pm.MemoryUsagePercent = snap.MemoryPercent
			pm.DiskUsagePercent = snap.DiskPercent
		} else {
			h.logger.Warnf("sysstats snapshot failed: %v", err)
		}
	}

	if h.healthRegistry != nil {
		sys := h.healthRegistry.Check(ctx)
		pm.OverallStatus = string(sys.Status)
		for _, comp := range sys.Components {
			pm.Services = append(pm.Services, ServiceMetricResponse{
				Name:        comp.Name,
				DisplayName: comp.Name,
				Status:      string(comp.Status),
				Healthy:     comp.Status == health.StatusHealthy,
				LastCheck:   comp.LastChecked.UTC().Format(time.RFC3339Nano),
				Message:     comp.Message,
			})
		}
	}

	h.respWriter.Success200(w, r, MetricsResponse{Metrics: pm})
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
