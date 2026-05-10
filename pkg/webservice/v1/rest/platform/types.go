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
	"context"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
)

// ServicesManager provides service management operations
type ServicesManager interface {
	ListServices(ctx context.Context, req *platformv1.ListServicesRequest) (*platformv1.ListServicesResponse, error)
	GetServiceStatus(ctx context.Context, req *platformv1.GetServiceStatusRequest) (*platformv1.GetServiceStatusResponse, error)
	StartService(ctx context.Context, req *platformv1.StartServiceRequest) (*platformv1.StartServiceResponse, error)
	StopService(ctx context.Context, req *platformv1.StopServiceRequest) (*platformv1.StopServiceResponse, error)
	RestartService(ctx context.Context, req *platformv1.RestartServiceRequest) (*platformv1.RestartServiceResponse, error)
}

// ProtocolConfig provides protocol configuration information
type ProtocolConfig struct {
	EnableREST     bool
	RESTListenAddr string
	RESTTLSEnabled bool
	EnableGRPCTCP  bool
	GRPCListenAddr string
	GRPCTLSEnabled bool
	SocketPath     string
	EnableQUIC     bool
	QUICListenAddr string
	EnableMCP      bool
	MCPHTTPAddr    string
}

// VersionInfo provides application version information
type VersionInfo struct {
	Version   string
	BuildDate string
	GitHash   string
}

// HealthResponse mirrors the JS SDK's GetHealthResponse, wrapping a
// PlatformHealth payload so dashboard code can read
// `response.data.health.healthy` directly.
type HealthResponse struct {
	Health PlatformHealth `json:"health"`
}

// PlatformHealth is the dashboard-shaped platform health summary.
// camelCase tags match sdk/javascript/src/types/platform.ts
// PlatformHealth.
type PlatformHealth struct {
	Healthy   bool            `json:"healthy"`
	Message   string          `json:"message,omitempty"`
	Status    string          `json:"status"`
	Services  []ServiceHealth `json:"services"`
	Timestamp string          `json:"timestamp"`
}

// ServiceHealth is one service's contribution to PlatformHealth.
type ServiceHealth struct {
	Name      string  `json:"name"`
	Healthy   bool    `json:"healthy"`
	Status    string  `json:"status,omitempty"`
	Message   string  `json:"message,omitempty"`
	LastCheck string  `json:"lastCheck,omitempty"`
	LatencyMs float64 `json:"latencyMs,omitempty"`
}

// ComponentHealthResponse is retained for callers that still consume
// the legacy flat shape (status/message/last_check). New callers should
// use PlatformHealth.
type ComponentHealthResponse struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	Message   string `json:"message,omitempty"`
	LastCheck int64  `json:"last_check"`
}

// MetricsResponse mirrors the JS SDK's GetMetricsResponse and is served
// at GET /api/v1/platform/metrics. The dashboard's CPU/Memory/Storage
// tiles read these fields directly (`response.data.metrics.cpuUsagePercent`).
type MetricsResponse struct {
	Metrics PlatformMetrics `json:"metrics"`
	History []PlatformMetrics `json:"history,omitempty"`
}

// PlatformMetrics is a single instantaneous OS+platform health snapshot.
type PlatformMetrics struct {
	CPUUsagePercent    float64                 `json:"cpuUsagePercent"`
	MemoryUsagePercent float64                 `json:"memoryUsagePercent"`
	DiskUsagePercent   float64                 `json:"diskUsagePercent"`
	ActiveConnections  uint64                  `json:"activeConnections,omitempty"`
	RequestsPerSecond  float64                 `json:"requestsPerSecond,omitempty"`
	ErrorRate          float64                 `json:"errorRate,omitempty"`
	OverallStatus      string                  `json:"overallStatus"`
	System             SystemInfoResponse      `json:"system"`
	Services           []ServiceMetricResponse `json:"services"`
	Timestamp          string                  `json:"timestamp"`
}

// ServiceMetricResponse is a single service's metric snapshot.
type ServiceMetricResponse struct {
	Name        string  `json:"name"`
	DisplayName string  `json:"displayName"`
	Status      string  `json:"status"`
	Healthy     bool    `json:"healthy"`
	LatencyMs   float64 `json:"latencyMs,omitempty"`
	LastCheck   string  `json:"lastCheck"`
	Message     string  `json:"message,omitempty"`
}

// StatusResponse represents the daemon status response
type StatusResponse struct {
	Status    string             `json:"status"`
	Version   string             `json:"version"`
	BuildTime string             `json:"build_time"`
	GitCommit string             `json:"git_commit"`
	GoVersion string             `json:"go_version"`
	System    SystemInfoResponse `json:"system"`
	Timestamp int64              `json:"timestamp"`
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
	Timestamp int64                 `json:"timestamp"`
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
	Timestamp int64                    `json:"timestamp"`
}
