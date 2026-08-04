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

// SystemStatus represents the overall system status.
type SystemStatus string

const (
	SystemStatusUnspecified  SystemStatus = "UNKNOWN"
	SystemStatusReady        SystemStatus = "READY"
	SystemStatusInitializing SystemStatus = "INITIALIZING"
	SystemStatusDegraded     SystemStatus = "DEGRADED"
	SystemStatusUnavailable  SystemStatus = "UNAVAILABLE"
	SystemStatusShuttingDown SystemStatus = "SHUTTING_DOWN"
)

// HealthStatus represents the health of a component.
type HealthStatus string

const (
	HealthStatusUnspecified HealthStatus = "UNKNOWN"
	HealthStatusHealthy     HealthStatus = "HEALTHY"
	HealthStatusDegraded    HealthStatus = "DEGRADED"
	HealthStatusUnhealthy   HealthStatus = "UNHEALTHY"
)

// ServiceType represents a platform service type.
type ServiceType string

const (
	ServiceTypeUnspecified ServiceType = "Unspecified"
	ServiceTypeTPM         ServiceType = "TPM"
	ServiceTypeSDN         ServiceType = "SDN"
	ServiceTypeCompute     ServiceType = "Compute"
	ServiceTypeDNS         ServiceType = "DNS"
	ServiceTypeACME        ServiceType = "ACME"
	ServiceTypeWebService  ServiceType = "WebService"
	ServiceTypeAttestation ServiceType = "Attestation"
)

// ServiceStatus represents the status of a service.
type ServiceStatus string

const (
	ServiceStatusUnspecified ServiceStatus = "UNKNOWN"
	ServiceStatusRunning     ServiceStatus = "RUNNING"
	ServiceStatusStopped     ServiceStatus = "STOPPED"
	ServiceStatusStarting    ServiceStatus = "STARTING"
	ServiceStatusStopping    ServiceStatus = "STOPPING"
	ServiceStatusError       ServiceStatus = "ERROR"
)

// TPMVersion represents the TPM specification version.
type TPMVersion string

const (
	TPMVersionUnspecified TPMVersion = "Unknown"
	TPMVersion12          TPMVersion = "1.2"
	TPMVersion20          TPMVersion = "2.0"
)

// VersionInfo contains version information about the platform daemon.
type VersionInfo struct {
	Version    string            `json:"version" yaml:"version"`
	BuildTime  string            `json:"build_time" yaml:"build_time"`
	GitCommit  string            `json:"git_commit" yaml:"git_commit"`
	GoVersion  string            `json:"go_version" yaml:"go_version"`
	Components map[string]string `json:"components,omitempty" yaml:"components,omitempty"`
}

// StatusInfo contains the overall platform status.
type StatusInfo struct {
	Status   SystemStatus   `json:"status" yaml:"status"`
	Info     *PlatformInfo  `json:"info,omitempty" yaml:"info,omitempty"`
	Services []*ServiceInfo `json:"services,omitempty" yaml:"services,omitempty"`
}

// PlatformInfo contains platform identification and system information.
type PlatformInfo struct {
	Hostname   string      `json:"hostname" yaml:"hostname"`
	PlatformID string      `json:"platform_id" yaml:"platform_id"`
	Version    string      `json:"version" yaml:"version"`
	BuildTime  string      `json:"build_time" yaml:"build_time"`
	GitCommit  string      `json:"git_commit" yaml:"git_commit"`
	FIPSMode   bool        `json:"fips_mode" yaml:"fips_mode"`
	SystemInfo *SystemInfo `json:"system_info,omitempty" yaml:"system_info,omitempty"`
	TPMInfo    *TPMInfo    `json:"tpm_info,omitempty" yaml:"tpm_info,omitempty"`
}

// SystemInfo contains operating system and hardware information.
type SystemInfo struct {
	OS                string `json:"os" yaml:"os"`
	Arch              string `json:"arch" yaml:"arch"`
	KernelVersion     string `json:"kernel_version" yaml:"kernel_version"`
	NumCPUs           uint32 `json:"num_cpus" yaml:"num_cpus"`
	TotalMemoryMB     uint64 `json:"total_memory_mb" yaml:"total_memory_mb"`
	AvailableMemoryMB uint64 `json:"available_memory_mb" yaml:"available_memory_mb"`
	UptimeSeconds     uint64 `json:"uptime_seconds" yaml:"uptime_seconds"`
}

// TPMInfo contains TPM hardware information.
type TPMInfo struct {
	Version         TPMVersion `json:"version" yaml:"version"`
	Manufacturer    string     `json:"manufacturer" yaml:"manufacturer"`
	FirmwareVersion string     `json:"firmware_version" yaml:"firmware_version"`
	IsSimulator     bool       `json:"is_simulator" yaml:"is_simulator"`
	FIPSMode        bool       `json:"fips_mode" yaml:"fips_mode"`
}

// HealthInfo contains the health status of the platform.
type HealthInfo struct {
	Status     HealthStatus       `json:"status" yaml:"status"`
	Components []*ComponentHealth `json:"components,omitempty" yaml:"components,omitempty"`
}

// ComponentHealth contains the health of an individual component.
type ComponentHealth struct {
	Name    string       `json:"name" yaml:"name"`
	Status  HealthStatus `json:"status" yaml:"status"`
	Message string       `json:"message,omitempty" yaml:"message,omitempty"`
}

// ServiceInfo contains information about a platform service.
type ServiceInfo struct {
	Name          string        `json:"name" yaml:"name"`
	Type          ServiceType   `json:"type" yaml:"type"`
	Status        ServiceStatus `json:"status" yaml:"status"`
	Health        HealthStatus  `json:"health" yaml:"health"`
	UptimeSeconds uint64        `json:"uptime_seconds" yaml:"uptime_seconds"`
	Version       string        `json:"version" yaml:"version"`
}

// ConfigSection contains a configuration section.
type ConfigSection struct {
	Section string            `json:"section" yaml:"section"`
	Values  map[string]string `json:"values" yaml:"values"`
}
