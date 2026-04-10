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

// Package daemon provides integration test adapters for daemon services.
// This file implements the DaemonCommands interface using gRPC calls.

//go:build integration

package daemon

import (
	"context"
	"fmt"
	"os"
	"time"

	pb "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
)

// =============================================================================
// gRPC Protocol Adapter
// =============================================================================

// GRPCAdapter implements DaemonCommands using gRPC calls to platformd.
type GRPCAdapter struct {
	conn   *grpc.ClientConn
	daemon pb.PlatformDaemonClient
}

// NewGRPCAdapter creates a new gRPC protocol adapter instance.
func NewGRPCAdapter() *GRPCAdapter {
	return &GRPCAdapter{}
}

// Name returns the protocol adapter identifier.
func (g *GRPCAdapter) Name() string {
	return "gRPC"
}

// Setup initializes the gRPC connection to platformd.
func (g *GRPCAdapter) Setup(ctx context.Context) error {
	endpoint := os.Getenv(EnvPlatformGRPCEndpoint)
	if endpoint == "" {
		endpoint = GetServiceEndpoints().PlatformGRPC
	}

	conn, err := grpc.NewClient(endpoint,
		helpers.GRPCTransportCredentials(),
	)
	if err != nil {
		return ErrGRPCConnectionFailed{Endpoint: endpoint, Err: err}
	}

	g.conn = conn
	g.daemon = pb.NewPlatformDaemonClient(conn)

	// Verify connectivity by calling health
	_, err = g.daemon.GetHealth(ctx, &pb.GetHealthRequest{})
	if err != nil {
		conn.Close()
		return ErrGRPCConnectionFailed{Endpoint: endpoint, Err: err}
	}

	return nil
}

// Teardown closes the gRPC connection.
func (g *GRPCAdapter) Teardown() error {
	if g.conn != nil {
		return g.conn.Close()
	}
	return nil
}

// =============================================================================
// Health Operations
// =============================================================================

// Health retrieves health status via gRPC.
func (g *GRPCAdapter) Health(ctx context.Context) (*HealthResult, error) {
	resp, err := g.daemon.GetHealth(ctx, &pb.GetHealthRequest{})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetHealth", Err: err}
	}

	result := &HealthResult{
		Status:    normalizeHealthStatus(resp.Status.String()),
		Timestamp: time.Now(),
	}

	if resp.Timestamp != nil {
		result.Timestamp = resp.Timestamp.AsTime()
	}

	for _, c := range resp.Components {
		ch := ComponentHealth{
			Name:    c.Name,
			Status:  normalizeHealthStatus(c.Status.String()),
			Message: c.Message,
		}
		if c.LastCheck != nil {
			ch.LastCheck = c.LastCheck.AsTime()
		}
		result.Components = append(result.Components, ch)
	}

	return result, nil
}

// =============================================================================
// Status Operations
// =============================================================================

// Status retrieves daemon status via gRPC.
func (g *GRPCAdapter) Status(ctx context.Context) (*StatusResult, error) {
	resp, err := g.daemon.GetStatus(ctx, &pb.GetStatusRequest{})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetStatus", Err: err}
	}

	result := &StatusResult{
		Status:    normalizeSystemStatus(resp.Status.String()),
		Timestamp: time.Now(),
	}

	if resp.Timestamp != nil {
		result.Timestamp = resp.Timestamp.AsTime()
	}

	if resp.Info != nil {
		if resp.Info.SystemInfo != nil {
			result.System = SystemInfo{
				OS:                resp.Info.SystemInfo.Os,
				Arch:              resp.Info.SystemInfo.Arch,
				NumCPUs:           int(resp.Info.SystemInfo.NumCpus),
				TotalMemoryMB:     resp.Info.SystemInfo.TotalMemoryMb,
				AvailableMemoryMB: resp.Info.SystemInfo.AvailableMemoryMb,
				Uptime:            fmt.Sprintf("%ds", resp.Info.SystemInfo.UptimeSeconds),
			}
		}
		result.Version = resp.Info.Version
		result.BuildTime = resp.Info.BuildTime
		result.GitCommit = resp.Info.GitCommit
	}

	// Get version info separately for additional fields
	versionResp, err := g.daemon.GetVersion(ctx, &pb.GetVersionRequest{})
	if err == nil {
		if result.Version == "" {
			result.Version = versionResp.Version
		}
		if result.BuildTime == "" {
			result.BuildTime = versionResp.BuildTime
		}
		if result.GitCommit == "" {
			result.GitCommit = versionResp.GitCommit
		}
		result.GoVersion = versionResp.GoVersion
	}

	return result, nil
}

// =============================================================================
// Version Operations
// =============================================================================

// Version retrieves version information via gRPC.
func (g *GRPCAdapter) Version(ctx context.Context) (*VersionResult, error) {
	resp, err := g.daemon.GetVersion(ctx, &pb.GetVersionRequest{})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetVersion", Err: err}
	}

	return &VersionResult{
		Version:   resp.Version,
		BuildTime: resp.BuildTime,
		GitCommit: resp.GitCommit,
		GoVersion: resp.GoVersion,
	}, nil
}

// =============================================================================
// Service Operations
// =============================================================================

// ListServices lists all services via gRPC.
func (g *GRPCAdapter) ListServices(ctx context.Context) (*ListServicesResult, error) {
	resp, err := g.daemon.ListServices(ctx, &pb.ListServicesRequest{})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ListServices", Err: err}
	}

	result := &ListServicesResult{
		Count:     len(resp.Services),
		Timestamp: time.Now(),
	}

	for _, s := range resp.Services {
		info := ServiceInfoResult{
			Name:   s.Name,
			Status: normalizeServiceStatus(s.Status.String()),
		}
		if s.StartedAt != nil {
			info.StartedAt = s.StartedAt.AsTime()
		}
		if s.UptimeSeconds > 0 {
			info.Uptime = fmt.Sprintf("%ds", s.UptimeSeconds)
		}
		result.Services = append(result.Services, info)
	}

	return result, nil
}

// GetService retrieves a single service's information via gRPC.
func (g *GRPCAdapter) GetService(ctx context.Context, serviceName string) (*ServiceInfoResult, error) {
	resp, err := g.daemon.GetServiceStatus(ctx, &pb.GetServiceStatusRequest{
		Service: serviceNameToType(serviceName),
	})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetServiceStatus", Err: err}
	}

	if resp.Service == nil {
		return nil, ErrServiceNotFound{ServiceName: serviceName}
	}

	result := &ServiceInfoResult{
		Name:   resp.Service.Name,
		Status: normalizeServiceStatus(resp.Service.Status.String()),
	}

	if resp.Service.StartedAt != nil {
		result.StartedAt = resp.Service.StartedAt.AsTime()
	}
	if resp.Service.UptimeSeconds > 0 {
		result.Uptime = fmt.Sprintf("%ds", resp.Service.UptimeSeconds)
	}

	return result, nil
}

// StartService starts a service via gRPC.
func (g *GRPCAdapter) StartService(ctx context.Context, serviceName string) (*ServiceActionResult, error) {
	resp, err := g.daemon.StartService(ctx, &pb.StartServiceRequest{
		Service: serviceNameToType(serviceName),
	})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "StartService", Err: err}
	}

	return &ServiceActionResult{
		Service: serviceName,
		Action:  "start",
		Success: resp.Status != nil && resp.Status.Success,
		Message: getStatusMessage(resp.Status),
	}, nil
}

// StopService stops a service via gRPC.
func (g *GRPCAdapter) StopService(ctx context.Context, serviceName string) (*ServiceActionResult, error) {
	resp, err := g.daemon.StopService(ctx, &pb.StopServiceRequest{
		Service: serviceNameToType(serviceName),
	})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "StopService", Err: err}
	}

	return &ServiceActionResult{
		Service: serviceName,
		Action:  "stop",
		Success: resp.Status != nil && resp.Status.Success,
		Message: getStatusMessage(resp.Status),
	}, nil
}

// RestartService restarts a service via gRPC.
func (g *GRPCAdapter) RestartService(ctx context.Context, serviceName string) (*ServiceActionResult, error) {
	resp, err := g.daemon.RestartService(ctx, &pb.RestartServiceRequest{
		Service: serviceNameToType(serviceName),
	})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "RestartService", Err: err}
	}

	return &ServiceActionResult{
		Service: serviceName,
		Action:  "restart",
		Success: resp.Status != nil && resp.Status.Success,
		Message: getStatusMessage(resp.Status),
	}, nil
}

// =============================================================================
// Protocol Operations
// =============================================================================

// ListProtocols lists all protocols via gRPC.
// Note: The PlatformDaemon service doesn't have a ListProtocols method,
// so we return a fixed list based on the expected protocols.
func (g *GRPCAdapter) ListProtocols(ctx context.Context) (*ListProtocolsResult, error) {
	// The daemon API doesn't expose a ListProtocols endpoint directly.
	// Return the known protocols with their default configuration.
	endpoints := GetServiceEndpoints()

	result := &ListProtocolsResult{
		Timestamp: time.Now(),
		Protocols: []ProtocolInfo{
			{Name: "REST", Enabled: true, Address: endpoints.PlatformAPI, Port: 8443, Status: "running", TLS: true},
			{Name: "gRPC", Enabled: true, Address: endpoints.PlatformGRPC, Port: 10443, Status: "running", TLS: false},
			{Name: "QUIC", Enabled: true, Address: endpoints.PlatformQUIC, Port: 9444, Status: "running", TLS: true},
			{Name: "MCP", Enabled: true, Address: endpoints.PlatformMCP, Port: 9445, Status: "running", TLS: false},
			{Name: "Unix Socket", Enabled: true, Address: endpoints.PlatformdSocket, Port: 0, Status: "running", TLS: false},
		},
	}

	return result, nil
}

// =============================================================================
// Helper Functions
// =============================================================================

// serviceNameToType converts a service name string to the protobuf ServiceType enum.
func serviceNameToType(name string) pb.ServiceType {
	switch name {
	case "tpm", "TPM":
		return pb.ServiceType_SERVICE_TYPE_TPM
	case "sdn", "SDN":
		return pb.ServiceType_SERVICE_TYPE_SDN
	case "compute", "COMPUTE":
		return pb.ServiceType_SERVICE_TYPE_COMPUTE
	case "dns", "DNS":
		return pb.ServiceType_SERVICE_TYPE_DNS
	case "acme", "ACME":
		return pb.ServiceType_SERVICE_TYPE_ACME
	case "webservice", "WEBSERVICE":
		return pb.ServiceType_SERVICE_TYPE_WEBSERVICE
	case "attestation", "ATTESTATION":
		return pb.ServiceType_SERVICE_TYPE_ATTESTATION
	default:
		return pb.ServiceType_SERVICE_TYPE_UNSPECIFIED
	}
}

// getStatusMessage extracts the message from a Status response.
func getStatusMessage(status *pb.Status) string {
	if status == nil {
		return ""
	}
	return status.Message
}

// Ensure GRPCAdapter implements DaemonCommands interface.
var _ DaemonCommands = (*GRPCAdapter)(nil)
