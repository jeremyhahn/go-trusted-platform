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
// This file implements the DaemonCommands interface using gRPC over Unix socket.

//go:build integration

package daemon

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
)

// =============================================================================
// Unix Socket Adapter Constants
// =============================================================================

const (
	// unixDialTimeout is the timeout for establishing Unix socket connection.
	unixDialTimeout = 10 * time.Second
)

// =============================================================================
// Unix Protocol Adapter
// =============================================================================

// UnixAdapter implements the DaemonCommands interface using gRPC over Unix socket
// to communicate with platformd.
type UnixAdapter struct {
	socketPath string
	conn       *grpc.ClientConn
	daemon     pb.PlatformDaemonClient
}

// NewUnixAdapter creates a new UnixAdapter instance.
func NewUnixAdapter() *UnixAdapter {
	return &UnixAdapter{}
}

// Name returns the protocol adapter identifier.
func (u *UnixAdapter) Name() string {
	return "Unix"
}

// Setup initializes the gRPC connection over Unix socket.
// Unix domain sockets use insecure transport credentials because TLS is not
// needed for local IPC -- the kernel enforces access control via file permissions.
func (u *UnixAdapter) Setup(ctx context.Context) error {
	u.socketPath = os.Getenv(EnvPlatformdSocket)
	if u.socketPath == "" {
		u.socketPath = DefaultPlatformdSocket
	}

	conn, err := grpc.DialContext(ctx, "unix://"+u.socketPath,
		helpers.GRPCUnixCredentials(),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			socketAddr := strings.TrimPrefix(addr, "unix://")
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketAddr)
		}),
		grpc.WithBlock(),
	)
	if err != nil {
		return ErrUnixConnectionFailed{Path: u.socketPath, Err: err}
	}

	u.conn = conn
	u.daemon = pb.NewPlatformDaemonClient(conn)

	// Verify connectivity with a health call
	_, err = u.daemon.GetHealth(ctx, &pb.GetHealthRequest{})
	if err != nil {
		u.conn.Close()
		return ErrUnixBackendUnavailable{Err: err}
	}

	return nil
}

// Teardown closes the gRPC connection.
func (u *UnixAdapter) Teardown() error {
	if u.conn != nil {
		return u.conn.Close()
	}
	return nil
}

// =============================================================================
// Health Operations
// =============================================================================

// Health retrieves health status via Unix socket.
func (u *UnixAdapter) Health(ctx context.Context) (*HealthResult, error) {
	resp, err := u.daemon.GetHealth(ctx, &pb.GetHealthRequest{})
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetHealth", Err: err}
	}
	return healthResultFromProto(resp), nil
}

// =============================================================================
// Status Operations
// =============================================================================

// Status retrieves daemon status via Unix socket.
func (u *UnixAdapter) Status(ctx context.Context) (*StatusResult, error) {
	resp, err := u.daemon.GetStatus(ctx, &pb.GetStatusRequest{})
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetStatus", Err: err}
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
	versionResp, err := u.daemon.GetVersion(ctx, &pb.GetVersionRequest{})
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

// Version retrieves version information via Unix socket.
func (u *UnixAdapter) Version(ctx context.Context) (*VersionResult, error) {
	resp, err := u.daemon.GetVersion(ctx, &pb.GetVersionRequest{})
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetVersion", Err: err}
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

// ListServices lists all services via Unix socket.
func (u *UnixAdapter) ListServices(ctx context.Context) (*ListServicesResult, error) {
	resp, err := u.daemon.ListServices(ctx, &pb.ListServicesRequest{})
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "ListServices", Err: err}
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

// GetService retrieves a single service's information via Unix socket.
func (u *UnixAdapter) GetService(ctx context.Context, serviceName string) (*ServiceInfoResult, error) {
	resp, err := u.daemon.GetServiceStatus(ctx, &pb.GetServiceStatusRequest{
		Service: serviceNameToType(serviceName),
	})
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetServiceStatus", Err: err}
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

// StartService starts a service via Unix socket.
func (u *UnixAdapter) StartService(ctx context.Context, serviceName string) (*ServiceActionResult, error) {
	resp, err := u.daemon.StartService(ctx, &pb.StartServiceRequest{
		Service: serviceNameToType(serviceName),
	})
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "StartService", Err: err}
	}

	return &ServiceActionResult{
		Service: serviceName,
		Action:  "start",
		Success: resp.Status != nil && resp.Status.Success,
		Message: getStatusMessage(resp.Status),
	}, nil
}

// StopService stops a service via Unix socket.
func (u *UnixAdapter) StopService(ctx context.Context, serviceName string) (*ServiceActionResult, error) {
	resp, err := u.daemon.StopService(ctx, &pb.StopServiceRequest{
		Service: serviceNameToType(serviceName),
	})
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "StopService", Err: err}
	}

	return &ServiceActionResult{
		Service: serviceName,
		Action:  "stop",
		Success: resp.Status != nil && resp.Status.Success,
		Message: getStatusMessage(resp.Status),
	}, nil
}

// RestartService restarts a service via Unix socket.
func (u *UnixAdapter) RestartService(ctx context.Context, serviceName string) (*ServiceActionResult, error) {
	resp, err := u.daemon.RestartService(ctx, &pb.RestartServiceRequest{
		Service: serviceNameToType(serviceName),
	})
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "RestartService", Err: err}
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

// ListProtocols lists all protocols via Unix socket.
func (u *UnixAdapter) ListProtocols(ctx context.Context) (*ListProtocolsResult, error) {
	// The daemon API doesn't expose a ListProtocols endpoint directly.
	// Return the known protocols with their default configuration.
	endpoints := GetServiceEndpoints()

	result := &ListProtocolsResult{
		Timestamp: time.Now(),
		Protocols: []ProtocolInfo{
			{Name: "REST", Enabled: true, Address: endpoints.PlatformAPI, Port: 8443, Status: "running", TLS: true},
			{Name: "gRPC", Enabled: true, Address: endpoints.PlatformGRPC, Port: 10443, Status: "running", TLS: false},
			{Name: "QUIC", Enabled: true, Address: endpoints.PlatformQUIC, Port: 9444, Status: "running", TLS: true},
			{Name: "MCP", Enabled: true, Address: endpoints.PlatformMCP, Port: 9445, Status: "running", TLS: true},
			{Name: "Unix Socket", Enabled: true, Address: endpoints.PlatformdSocket, Port: 0, Status: "running", TLS: false},
		},
	}

	return result, nil
}

// Ensure UnixAdapter implements DaemonCommands interface.
var _ DaemonCommands = (*UnixAdapter)(nil)
