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

//go:build integration

package cli

import (
	"context"
	"time"
)

// CLICommands defines the central command set for root-level CLI integration testing.
// Each protocol adapter (CLI, REST, gRPC, QUIC, MCP, Unix) implements this interface.
// Tests are written once against this interface and run against all protocols.
type CLICommands interface {
	// Protocol identification and lifecycle
	Name() string
	Setup(ctx context.Context) error
	Teardown() error

	// Version commands (platformctl version)
	Version(ctx context.Context, opts VersionOptions) (*VersionResult, error)

	// Status commands (platformctl status)
	Status(ctx context.Context) (*StatusResult, error)

	// Health commands (platformctl health)
	Health(ctx context.Context, opts HealthOptions) (*HealthResult, error)

	// Config commands (platformctl config ...)
	ConfigGet(ctx context.Context, section string) (*ConfigGetResult, error)
	ConfigSet(ctx context.Context, section string, values map[string]string, persist bool) (*ConfigSetResult, error)
	ConfigReload(ctx context.Context) (*ConfigReloadResult, error)

	// Context commands (platformctl context ...)
	ContextList(ctx context.Context) (*ContextListResult, error)
	ContextCurrent(ctx context.Context) (*ContextCurrentResult, error)
	ContextUse(ctx context.Context, name string) (*ContextUseResult, error)
	ContextAdd(ctx context.Context, opts ContextAddOptions) (*ContextAddResult, error)
	ContextDelete(ctx context.Context, name string) (*ContextDeleteResult, error)

	// Service commands (platformctl service ...)
	ServiceList(ctx context.Context) (*ServiceListResult, error)
	ServiceStatus(ctx context.Context, serviceType string) (*ServiceStatusResult, error)
	ServiceStart(ctx context.Context, serviceType string) (*ServiceStartResult, error)
	ServiceStop(ctx context.Context, serviceType string, opts ServiceStopOptions) (*ServiceStopResult, error)
	ServiceRestart(ctx context.Context, serviceType string, timeout uint32) (*ServiceRestartResult, error)

	// Completion commands (platformctl completion)
	Completion(ctx context.Context, shell string) (*CompletionResult, error)
}

// =============================================================================
// Version Types
// =============================================================================

// VersionOptions contains options for the version command.
type VersionOptions struct {
	ClientOnly bool
}

// VersionResult contains the result of a version query.
type VersionResult struct {
	ClientVersion string
	ServerVersion *ServerVersionInfo
}

// ServerVersionInfo contains server version details.
type ServerVersionInfo struct {
	Version    string
	BuildTime  string
	GitCommit  string
	GoVersion  string
	Components map[string]string
}

// =============================================================================
// Status Types
// =============================================================================

// StatusResult contains the result of a status query.
type StatusResult struct {
	SystemStatus string
	Info         *PlatformInfo
	Services     []ServiceInfo
}

// PlatformInfo contains platform information.
type PlatformInfo struct {
	Hostname   string
	PlatformID string
	Version    string
	BuildTime  string
	GitCommit  string
	FIPSMode   bool
	SystemInfo *SystemInfo
	TPMInfo    *TPMInfo
}

// SystemInfo contains system information.
type SystemInfo struct {
	OS                string
	Arch              string
	KernelVersion     string
	NumCPUs           int32
	TotalMemoryMB     int64
	AvailableMemoryMB int64
	UptimeSeconds     int64
}

// TPMInfo contains TPM information.
type TPMInfo struct {
	Version         string
	Manufacturer    string
	FirmwareVersion string
	IsSimulator     bool
	FIPSMode        bool
}

// ServiceInfo contains service information.
type ServiceInfo struct {
	Name          string
	Type          string
	Status        string
	Health        string
	UptimeSeconds int64
	Version       string
}

// =============================================================================
// Health Types
// =============================================================================

// HealthOptions contains options for the health command.
type HealthOptions struct {
	Detailed bool
}

// HealthResult contains the result of a health query.
type HealthResult struct {
	Status     string
	Components []ComponentHealth
}

// ComponentHealth contains component health information.
type ComponentHealth struct {
	Name    string
	Status  string
	Message string
}

// =============================================================================
// Config Types
// =============================================================================

// ConfigGetResult contains the result of a config get operation.
type ConfigGetResult struct {
	Sections []ConfigSection
}

// ConfigSection contains a configuration section.
type ConfigSection struct {
	Section string
	Values  map[string]string
}

// ConfigSetResult contains the result of a config set operation.
type ConfigSetResult struct {
	Success bool
	Message string
}

// ConfigReloadResult contains the result of a config reload operation.
type ConfigReloadResult struct {
	Success          bool
	ReloadedSections []string
	Message          string
}

// =============================================================================
// Context Types
// =============================================================================

// ContextListResult contains the result of a context list operation.
type ContextListResult struct {
	Contexts       []ContextInfo
	CurrentContext string
}

// ContextInfo contains context information.
type ContextInfo struct {
	Name   string
	Type   string
	Target string
}

// ContextCurrentResult contains the current context information.
type ContextCurrentResult struct {
	Name       string
	Type       string
	SocketPath string
	Server     string
	CACert     string
	ClientCert string
}

// ContextUseResult contains the result of a context use operation.
type ContextUseResult struct {
	Success bool
	Message string
}

// ContextAddOptions contains options for adding a context.
type ContextAddOptions struct {
	Name       string
	Type       string
	SocketPath string
	Server     string
	CACert     string
	ClientCert string
	ClientKey  string
}

// ContextAddResult contains the result of a context add operation.
type ContextAddResult struct {
	Success bool
	Message string
}

// ContextDeleteResult contains the result of a context delete operation.
type ContextDeleteResult struct {
	Success bool
	Message string
}

// =============================================================================
// Service Types
// =============================================================================

// ServiceListResult contains the result of a service list operation.
type ServiceListResult struct {
	Services []ServiceInfo
}

// ServiceStatusResult contains the result of a service status operation.
type ServiceStatusResult struct {
	Service *ServiceInfo
}

// ServiceStartResult contains the result of a service start operation.
type ServiceStartResult struct {
	Success bool
	Message string
}

// ServiceStopOptions contains options for stopping a service.
type ServiceStopOptions struct {
	Force   bool
	Timeout uint32
}

// ServiceStopResult contains the result of a service stop operation.
type ServiceStopResult struct {
	Success bool
	Message string
}

// ServiceRestartResult contains the result of a service restart operation.
type ServiceRestartResult struct {
	Success bool
	Message string
}

// =============================================================================
// Completion Types
// =============================================================================

// CompletionResult contains the result of a completion generation.
type CompletionResult struct {
	Script string
}

// =============================================================================
// Wipe Types (Note: Wipe is a local operation, not tested via multi-protocol)
// =============================================================================

// WipeOptions contains options for the wipe command.
type WipeOptions struct {
	Path    string
	Passes  int
	Random  bool
	Trim    bool
	Verbose bool
}

// WipeResult contains the result of a wipe operation.
type WipeResult struct {
	Success  bool
	Duration time.Duration
	Message  string
}
