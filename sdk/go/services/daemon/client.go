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

// Package daemon provides a client for platform daemon service operations.
// It supports both gRPC and REST transports, matching the JavaScript SDK's
// Platform service functionality.
package daemon

import (
	"context"
	"io"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// PlatformClient defines the interface for platform daemon operations.
// This interface matches the JavaScript SDK's Platform service functionality.
type PlatformClient interface {
	// Information Operations
	GetVersion(ctx context.Context) (*platformv1.GetVersionResponse, error)
	GetStatus(ctx context.Context) (*platformv1.GetStatusResponse, error)
	GetSystemInfo(ctx context.Context) (*platformv1.SystemInfo, error)
	GetTPMInfo(ctx context.Context) (*platformv1.TPMInfo, error)

	// Health Operations
	GetHealth(ctx context.Context, detailed bool) (*platformv1.GetHealthResponse, error)

	// Configuration Operations
	GetConfig(ctx context.Context, section string) ([]*platformv1.ConfigSection, error)
	UpdateConfig(ctx context.Context, section *platformv1.ConfigSection, persist bool) error
	ReloadConfig(ctx context.Context) ([]string, error)

	// Lifecycle Operations
	Provision(ctx context.Context, req *platformv1.ProvisionRequest) (*platformv1.ProvisionResponse, error)
	Shutdown(ctx context.Context, graceful bool, timeoutSeconds uint32) error
	Restart(ctx context.Context, timeoutSeconds uint32) error

	// Service Management
	StartService(ctx context.Context, service platformv1.ServiceType, options map[string]string) (*platformv1.ServiceInfo, error)
	StopService(ctx context.Context, service platformv1.ServiceType, force bool, timeoutSeconds uint32) error
	RestartService(ctx context.Context, service platformv1.ServiceType, timeoutSeconds uint32) (*platformv1.ServiceInfo, error)
	GetServiceStatus(ctx context.Context, service platformv1.ServiceType) (*platformv1.ServiceInfo, error)
	ListServices(ctx context.Context, types []platformv1.ServiceType, statuses []platformv1.ServiceStatus) ([]*platformv1.ServiceInfo, error)

	// Streaming Operations
	StreamEvents(ctx context.Context, req *platformv1.StreamEventsRequest) (EventStream, error)
	StreamLogs(ctx context.Context, req *platformv1.StreamLogsRequest) (LogStream, error)
	StreamMetrics(ctx context.Context, req *platformv1.StreamMetricsRequest) (MetricStream, error)

	// Database Operations
	ListEntityTypes(ctx context.Context) (*platformv1.ListEntityTypesResponse, error)
	DumpEntityType(ctx context.Context, entityType, format string, pretty bool) (EntityDumpStream, error)
}

// EventStream provides an interface for consuming event streams.
type EventStream interface {
	// Recv receives the next event from the stream.
	// Returns io.EOF when the stream is closed.
	Recv() (*platformv1.Event, error)
	// CloseSend closes the send direction of the stream.
	CloseSend() error
}

// LogStream provides an interface for consuming log streams.
type LogStream interface {
	// Recv receives the next log entry from the stream.
	// Returns io.EOF when the stream is closed.
	Recv() (*platformv1.LogEntry, error)
	// CloseSend closes the send direction of the stream.
	CloseSend() error
}

// MetricStream provides an interface for consuming metric streams.
type MetricStream interface {
	// Recv receives the next metric data from the stream.
	// Returns io.EOF when the stream is closed.
	Recv() (*platformv1.MetricData, error)
	// CloseSend closes the send direction of the stream.
	CloseSend() error
}

// EntityDumpStream provides an interface for consuming entity dump streams.
type EntityDumpStream interface {
	// Recv receives the next entity dump response from the stream.
	// Returns io.EOF when the stream is closed.
	Recv() (*platformv1.DumpEntityTypeResponse, error)
	// CloseSend closes the send direction of the stream.
	CloseSend() error
}

// Client provides access to platform daemon service operations.
type Client struct {
	grpc platformv1.PlatformDaemonClient
}

// NewClient creates a new daemon service client from a transport adapter.
func NewClient(conn transport.Adapter) (*Client, error) {
	if conn == nil {
		return nil, common.ErrNilConnection
	}
	grpcConn := conn.Connection()
	if grpcConn == nil {
		return nil, common.ErrNilConnection
	}
	return &Client{
		grpc: platformv1.NewPlatformDaemonClient(grpcConn),
	}, nil
}

// NewClientFromGRPC creates a new daemon service client from a gRPC client.
// This is useful when you already have a gRPC client from the platform.Client.
func NewClientFromGRPC(grpcClient platformv1.PlatformDaemonClient) *Client {
	return &Client{
		grpc: grpcClient,
	}
}

// GetVersion returns version information about the platform daemon.
func (c *Client) GetVersion(ctx context.Context) (*platformv1.GetVersionResponse, error) {
	resp, err := c.grpc.GetVersion(ctx, &platformv1.GetVersionRequest{})
	if err != nil {
		return nil, &ErrGetVersionFailed{Cause: err}
	}
	return resp, nil
}

// GetStatus returns the current status of the platform daemon.
func (c *Client) GetStatus(ctx context.Context) (*platformv1.GetStatusResponse, error) {
	resp, err := c.grpc.GetStatus(ctx, &platformv1.GetStatusRequest{})
	if err != nil {
		return nil, &ErrGetStatusFailed{Cause: err}
	}
	return resp, nil
}

// GetSystemInfo returns system information about the platform.
// This is a convenience method that extracts SystemInfo from GetStatus.
func (c *Client) GetSystemInfo(ctx context.Context) (*platformv1.SystemInfo, error) {
	status, err := c.GetStatus(ctx)
	if err != nil {
		return nil, err
	}
	if status.Info == nil {
		return nil, &ErrGetSystemInfoFailed{Cause: ErrSystemInfoNotAvailable}
	}
	if status.Info.SystemInfo == nil {
		return nil, &ErrGetSystemInfoFailed{Cause: ErrSystemInfoNotAvailable}
	}
	return status.Info.SystemInfo, nil
}

// GetTPMInfo returns TPM information about the platform.
// This is a convenience method that extracts TPMInfo from GetStatus.
func (c *Client) GetTPMInfo(ctx context.Context) (*platformv1.TPMInfo, error) {
	status, err := c.GetStatus(ctx)
	if err != nil {
		return nil, err
	}
	if status.Info == nil {
		return nil, &ErrGetTPMInfoFailed{Cause: ErrTPMInfoNotAvailable}
	}
	if status.Info.TpmInfo == nil {
		return nil, &ErrGetTPMInfoFailed{Cause: ErrTPMInfoNotAvailable}
	}
	return status.Info.TpmInfo, nil
}

// GetHealth returns the health status of the platform daemon.
func (c *Client) GetHealth(ctx context.Context, detailed bool) (*platformv1.GetHealthResponse, error) {
	resp, err := c.grpc.GetHealth(ctx, &platformv1.GetHealthRequest{Detailed: detailed})
	if err != nil {
		return nil, &ErrGetHealthFailed{Cause: err}
	}
	return resp, nil
}

// GetConfig returns the current configuration.
// If section is empty, all sections are returned.
func (c *Client) GetConfig(ctx context.Context, section string) ([]*platformv1.ConfigSection, error) {
	resp, err := c.grpc.GetConfig(ctx, &platformv1.GetConfigRequest{Section: section})
	if err != nil {
		return nil, &ErrGetConfigFailed{Cause: err}
	}
	return resp.Sections, nil
}

// UpdateConfig updates a configuration section.
func (c *Client) UpdateConfig(ctx context.Context, section *platformv1.ConfigSection, persist bool) error {
	if section == nil {
		return &ErrUpdateConfigFailed{Section: "", Cause: ErrNilConfigSection}
	}
	_, err := c.grpc.UpdateConfig(ctx, &platformv1.UpdateConfigRequest{
		Section: section,
		Persist: persist,
	})
	if err != nil {
		return &ErrUpdateConfigFailed{Section: section.Section, Cause: err}
	}
	return nil
}

// ReloadConfig reloads the configuration from disk.
func (c *Client) ReloadConfig(ctx context.Context) ([]string, error) {
	resp, err := c.grpc.ReloadConfig(ctx, &platformv1.ReloadConfigRequest{})
	if err != nil {
		return nil, &ErrReloadConfigFailed{Cause: err}
	}
	return resp.ReloadedSections, nil
}

// Provision initializes the platform with the specified options.
func (c *Client) Provision(ctx context.Context, req *platformv1.ProvisionRequest) (*platformv1.ProvisionResponse, error) {
	if req == nil {
		return nil, &ErrProvisionFailed{Cause: ErrNilRequest}
	}
	resp, err := c.grpc.Provision(ctx, req)
	if err != nil {
		return nil, &ErrProvisionFailed{Cause: err}
	}
	return resp, nil
}

// Shutdown initiates a graceful shutdown of the platform daemon.
func (c *Client) Shutdown(ctx context.Context, graceful bool, timeoutSeconds uint32) error {
	_, err := c.grpc.Shutdown(ctx, &platformv1.ShutdownRequest{
		Graceful:       graceful,
		TimeoutSeconds: timeoutSeconds,
	})
	if err != nil {
		return &ErrShutdownFailed{Cause: err}
	}
	return nil
}

// Restart initiates a restart of the platform daemon by stopping and starting all services.
// This is implemented by stopping all services and then starting them again.
func (c *Client) Restart(ctx context.Context, timeoutSeconds uint32) error {
	// Get list of running services
	services, err := c.ListServices(ctx, nil, []platformv1.ServiceStatus{platformv1.ServiceStatus_SERVICE_STATUS_RUNNING})
	if err != nil {
		return &ErrRestartFailed{Cause: err}
	}

	// Restart each running service
	for _, svc := range services {
		_, restartErr := c.RestartService(ctx, svc.Type, timeoutSeconds)
		if restartErr != nil {
			return &ErrRestartFailed{Cause: restartErr}
		}
	}

	return nil
}

// StartService starts a specific service.
func (c *Client) StartService(ctx context.Context, service platformv1.ServiceType, options map[string]string) (*platformv1.ServiceInfo, error) {
	resp, err := c.grpc.StartService(ctx, &platformv1.StartServiceRequest{
		Service: service,
		Options: options,
	})
	if err != nil {
		return nil, &ErrStartServiceFailed{Service: service.String(), Cause: err}
	}
	return resp.Service, nil
}

// StopService stops a specific service.
func (c *Client) StopService(ctx context.Context, service platformv1.ServiceType, force bool, timeoutSeconds uint32) error {
	_, err := c.grpc.StopService(ctx, &platformv1.StopServiceRequest{
		Service:        service,
		Force:          force,
		TimeoutSeconds: timeoutSeconds,
	})
	if err != nil {
		return &ErrStopServiceFailed{Service: service.String(), Cause: err}
	}
	return nil
}

// RestartService restarts a specific service.
func (c *Client) RestartService(ctx context.Context, service platformv1.ServiceType, timeoutSeconds uint32) (*platformv1.ServiceInfo, error) {
	resp, err := c.grpc.RestartService(ctx, &platformv1.RestartServiceRequest{
		Service:        service,
		TimeoutSeconds: timeoutSeconds,
	})
	if err != nil {
		return nil, &ErrRestartServiceFailed{Service: service.String(), Cause: err}
	}
	return resp.Service, nil
}

// GetServiceStatus returns the status of a specific service.
func (c *Client) GetServiceStatus(ctx context.Context, service platformv1.ServiceType) (*platformv1.ServiceInfo, error) {
	resp, err := c.grpc.GetServiceStatus(ctx, &platformv1.GetServiceStatusRequest{Service: service})
	if err != nil {
		return nil, &ErrGetServiceStatusFailed{Service: service.String(), Cause: err}
	}
	return resp.Service, nil
}

// ListServices returns a list of services.
// If types is nil or empty, all service types are returned.
// If statuses is nil or empty, services in all statuses are returned.
func (c *Client) ListServices(ctx context.Context, types []platformv1.ServiceType, statuses []platformv1.ServiceStatus) ([]*platformv1.ServiceInfo, error) {
	resp, err := c.grpc.ListServices(ctx, &platformv1.ListServicesRequest{
		Types:    types,
		Statuses: statuses,
	})
	if err != nil {
		return nil, &ErrListServicesFailed{Cause: err}
	}
	return resp.Services, nil
}

// StreamEvents opens a stream to receive platform events.
func (c *Client) StreamEvents(ctx context.Context, req *platformv1.StreamEventsRequest) (EventStream, error) {
	if req == nil {
		req = &platformv1.StreamEventsRequest{}
	}
	stream, err := c.grpc.StreamEvents(ctx, req)
	if err != nil {
		return nil, &ErrStreamEventsFailed{Cause: err}
	}
	return &eventStreamAdapter{stream: stream}, nil
}

// StreamLogs opens a stream to receive service logs.
func (c *Client) StreamLogs(ctx context.Context, req *platformv1.StreamLogsRequest) (LogStream, error) {
	if req == nil {
		req = &platformv1.StreamLogsRequest{}
	}
	stream, err := c.grpc.StreamLogs(ctx, req)
	if err != nil {
		return nil, &ErrStreamLogsFailed{Cause: err}
	}
	return &logStreamAdapter{stream: stream}, nil
}

// StreamMetrics opens a stream to receive platform metrics.
func (c *Client) StreamMetrics(ctx context.Context, req *platformv1.StreamMetricsRequest) (MetricStream, error) {
	if req == nil {
		req = &platformv1.StreamMetricsRequest{}
	}
	stream, err := c.grpc.StreamMetrics(ctx, req)
	if err != nil {
		return nil, &ErrStreamMetricsFailed{Cause: err}
	}
	return &metricStreamAdapter{stream: stream}, nil
}

// ListEntityTypes returns a list of database entity types.
func (c *Client) ListEntityTypes(ctx context.Context) (*platformv1.ListEntityTypesResponse, error) {
	resp, err := c.grpc.ListEntityTypes(ctx, &platformv1.ListEntityTypesRequest{})
	if err != nil {
		return nil, &ErrListEntityTypesFailed{Cause: err}
	}
	return resp, nil
}

// DumpEntityType opens a stream to dump entities of a specific type.
// If entityType is empty, all entity types are dumped.
// Format can be "json" or "yaml".
func (c *Client) DumpEntityType(ctx context.Context, entityType, format string, pretty bool) (EntityDumpStream, error) {
	stream, err := c.grpc.DumpEntityType(ctx, &platformv1.DumpEntityTypeRequest{
		EntityType: entityType,
		Format:     format,
		Pretty:     pretty,
	})
	if err != nil {
		return nil, &ErrDumpEntityTypeFailed{EntityType: entityType, Cause: err}
	}
	return &entityDumpStreamAdapter{stream: stream}, nil
}

// eventStreamAdapter wraps gRPC event stream to implement EventStream interface.
type eventStreamAdapter struct {
	stream platformv1.PlatformDaemon_StreamEventsClient
}

func (a *eventStreamAdapter) Recv() (*platformv1.Event, error) {
	event, err := a.stream.Recv()
	if err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, &ErrStreamRecvFailed{StreamType: "events", Cause: err}
	}
	return event, nil
}

func (a *eventStreamAdapter) CloseSend() error {
	return a.stream.CloseSend()
}

// logStreamAdapter wraps gRPC log stream to implement LogStream interface.
type logStreamAdapter struct {
	stream platformv1.PlatformDaemon_StreamLogsClient
}

func (a *logStreamAdapter) Recv() (*platformv1.LogEntry, error) {
	entry, err := a.stream.Recv()
	if err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, &ErrStreamRecvFailed{StreamType: "logs", Cause: err}
	}
	return entry, nil
}

func (a *logStreamAdapter) CloseSend() error {
	return a.stream.CloseSend()
}

// metricStreamAdapter wraps gRPC metric stream to implement MetricStream interface.
type metricStreamAdapter struct {
	stream platformv1.PlatformDaemon_StreamMetricsClient
}

func (a *metricStreamAdapter) Recv() (*platformv1.MetricData, error) {
	data, err := a.stream.Recv()
	if err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, &ErrStreamRecvFailed{StreamType: "metrics", Cause: err}
	}
	return data, nil
}

func (a *metricStreamAdapter) CloseSend() error {
	return a.stream.CloseSend()
}

// entityDumpStreamAdapter wraps gRPC entity dump stream to implement EntityDumpStream interface.
type entityDumpStreamAdapter struct {
	stream platformv1.PlatformDaemon_DumpEntityTypeClient
}

func (a *entityDumpStreamAdapter) Recv() (*platformv1.DumpEntityTypeResponse, error) {
	resp, err := a.stream.Recv()
	if err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, &ErrStreamRecvFailed{StreamType: "entity_dump", Cause: err}
	}
	return resp, nil
}

func (a *entityDumpStreamAdapter) CloseSend() error {
	return a.stream.CloseSend()
}

// Ensure Client implements PlatformClient interface.
var _ PlatformClient = (*Client)(nil)
