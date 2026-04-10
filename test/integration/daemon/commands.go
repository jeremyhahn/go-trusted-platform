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

package daemon

import (
	"context"
	"time"
)

// DaemonCommands defines the central command set for daemon integration testing.
// Each protocol adapter (CLI, REST, gRPC, QUIC, MCP, Socket) implements this interface.
// Tests are written once against this interface and run against all protocols.
type DaemonCommands interface {
	// Protocol identification and lifecycle
	Name() string
	Setup(ctx context.Context) error
	Teardown() error

	// Health check operations
	Health(ctx context.Context) (*HealthResult, error)

	// Status operations
	Status(ctx context.Context) (*StatusResult, error)

	// Version information
	Version(ctx context.Context) (*VersionResult, error)

	// Service management
	ListServices(ctx context.Context) (*ListServicesResult, error)
	GetService(ctx context.Context, serviceName string) (*ServiceInfoResult, error)
	StartService(ctx context.Context, serviceName string) (*ServiceActionResult, error)
	StopService(ctx context.Context, serviceName string) (*ServiceActionResult, error)
	RestartService(ctx context.Context, serviceName string) (*ServiceActionResult, error)

	// Protocol listing
	ListProtocols(ctx context.Context) (*ListProtocolsResult, error)
}

// =============================================================================
// Health Check Types
// =============================================================================

// HealthResult contains the result of a health check operation.
type HealthResult struct {
	Status     string
	Components []ComponentHealth
	Timestamp  time.Time
}

// ComponentHealth contains health information for a single component.
type ComponentHealth struct {
	Name      string
	Status    string
	Message   string
	LastCheck time.Time
}

// =============================================================================
// Status Types
// =============================================================================

// StatusResult contains the daemon status information.
type StatusResult struct {
	Status    string
	Version   string
	BuildTime string
	GitCommit string
	GoVersion string
	System    SystemInfo
	Timestamp time.Time
}

// SystemInfo contains system information.
type SystemInfo struct {
	OS                string
	Arch              string
	NumCPUs           int
	TotalMemoryMB     uint64
	AvailableMemoryMB uint64
	Uptime            string
}

// =============================================================================
// Version Types
// =============================================================================

// VersionResult contains version information.
type VersionResult struct {
	Version   string
	BuildTime string
	GitCommit string
	GoVersion string
}

// =============================================================================
// Service Types
// =============================================================================

// ListServicesResult contains the result of listing services.
type ListServicesResult struct {
	Services  []ServiceInfoResult
	Count     int
	Timestamp time.Time
}

// ServiceInfoResult contains information about a single service.
type ServiceInfoResult struct {
	Name       string
	Status     string
	StartedAt  time.Time
	Uptime     string
	StartCount uint64
	StopCount  uint64
	LastError  string
}

// ServiceActionResult contains the result of a service action.
type ServiceActionResult struct {
	Service string
	Action  string
	Success bool
	Message string
}

// =============================================================================
// Protocol Types
// =============================================================================

// ListProtocolsResult contains information about all supported protocols.
type ListProtocolsResult struct {
	Protocols []ProtocolInfo
	Timestamp time.Time
}

// ProtocolInfo contains information about a single protocol.
type ProtocolInfo struct {
	Name    string
	Enabled bool
	Address string
	Port    int
	Status  string
	TLS     bool
}
