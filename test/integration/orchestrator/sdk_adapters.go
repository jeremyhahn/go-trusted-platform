// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package orchestrator

import (
	"context"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"

	// Register every sdk/go transport so the adapter can select any of
	// them by protocol.
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/grpc"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/mcp"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/quic"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/unix"
)

// SDKAdapter drives OrchestratorCommands through the platform SDK over one
// selected transport, exercising the exact adapter tables (REST route map,
// QUIC category 0x66 sub-opcode map, MCP tool map) the production clients
// use.
type SDKAdapter struct {
	name         string
	endpoint     string
	options      func() *platform.Options
	client       platform.Client
	orchestrator platformv1.OrchestratorServiceClient
}

// NewGRPCAdapter drives the orchestrator service over TLS gRPC.
func NewGRPCAdapter() *SDKAdapter {
	endpoints := GetServiceEndpoints()
	return &SDKAdapter{
		name:     "gRPC",
		endpoint: endpoints.PlatformGRPC,
		options: func() *platform.Options {
			return platform.NewOptions(
				platform.WithOnlyProtocol(platform.ProtocolGRPC),
				platform.WithGRPCAddr(endpoints.PlatformGRPC),
				platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
			)
		},
	}
}

// NewRESTAdapter drives the orchestrator service over HTTPS REST.
func NewRESTAdapter() *SDKAdapter {
	endpoints := GetServiceEndpoints()
	return &SDKAdapter{
		name:     "REST",
		endpoint: endpoints.PlatformREST,
		options: func() *platform.Options {
			return platform.NewOptions(
				platform.WithOnlyProtocol(platform.ProtocolREST),
				platform.WithRESTAddr(endpoints.PlatformREST),
				platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
			)
		},
	}
}

// NewQUICAdapter drives the orchestrator service over QUIC.
func NewQUICAdapter() *SDKAdapter {
	endpoints := GetServiceEndpoints()
	return &SDKAdapter{
		name:     "QUIC",
		endpoint: endpoints.PlatformQUIC,
		options: func() *platform.Options {
			return platform.NewOptions(
				platform.WithOnlyProtocol(platform.ProtocolQUIC),
				platform.WithQUICAddr(endpoints.PlatformQUIC),
				platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
			)
		},
	}
}

// NewMCPAdapter drives the orchestrator service over MCP.
func NewMCPAdapter() *SDKAdapter {
	endpoints := GetServiceEndpoints()
	return &SDKAdapter{
		name:     "MCP",
		endpoint: endpoints.PlatformMCP,
		options: func() *platform.Options {
			return platform.NewOptions(
				platform.WithOnlyProtocol(platform.ProtocolMCP),
				platform.WithMCPAddr(endpoints.PlatformMCP),
				platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
			)
		},
	}
}

// NewUnixAdapter drives the orchestrator service over gRPC-over-UDS, the CLI
// default.
func NewUnixAdapter() *SDKAdapter {
	endpoints := GetServiceEndpoints()
	return &SDKAdapter{
		name:     "Unix",
		endpoint: endpoints.PlatformUnix,
		options: func() *platform.Options {
			return platform.NewOptions(
				platform.WithOnlyProtocol(platform.ProtocolUnix),
				platform.WithUnixSocket(endpoints.PlatformUnix),
			)
		},
	}
}

// Name returns the transport name.
func (a *SDKAdapter) Name() string { return a.name }

// Setup connects the platform SDK client over the selected transport.
func (a *SDKAdapter) Setup(ctx context.Context) error {
	client, err := platform.Connect(ctx, a.options())
	if err != nil {
		return ErrConnectionFailed{Protocol: a.name, Endpoint: a.endpoint, Err: err}
	}
	a.client = client
	a.orchestrator = client.Orchestrator()
	return nil
}

// Teardown closes the SDK client.
func (a *SDKAdapter) Teardown() error {
	if a.client != nil {
		return a.client.Close()
	}
	return nil
}

// Health implements OrchestratorCommands.
func (a *SDKAdapter) Health(ctx context.Context) (*platformv1.OrchestratorHealthResponse, error) {
	return a.orchestrator.Health(ctx, &platformv1.OrchestratorHealthRequest{})
}

// ListAgents implements OrchestratorCommands.
func (a *SDKAdapter) ListAgents(ctx context.Context, req *platformv1.ListOrchestratorAgentsRequest) (*platformv1.ListOrchestratorAgentsResponse, error) {
	return a.orchestrator.ListAgents(ctx, req)
}

// GetAgent implements OrchestratorCommands.
func (a *SDKAdapter) GetAgent(ctx context.Context, req *platformv1.GetOrchestratorAgentRequest) (*platformv1.GetOrchestratorAgentResponse, error) {
	return a.orchestrator.GetAgent(ctx, req)
}

// DisableAgent implements OrchestratorCommands.
func (a *SDKAdapter) DisableAgent(ctx context.Context, req *platformv1.DisableOrchestratorAgentRequest) (*platformv1.DisableOrchestratorAgentResponse, error) {
	return a.orchestrator.DisableAgent(ctx, req)
}

// EnableAgent implements OrchestratorCommands.
func (a *SDKAdapter) EnableAgent(ctx context.Context, req *platformv1.EnableOrchestratorAgentRequest) (*platformv1.EnableOrchestratorAgentResponse, error) {
	return a.orchestrator.EnableAgent(ctx, req)
}

// ListSessions implements OrchestratorCommands.
func (a *SDKAdapter) ListSessions(ctx context.Context, req *platformv1.ListOrchestratorSessionsRequest) (*platformv1.ListOrchestratorSessionsResponse, error) {
	return a.orchestrator.ListSessions(ctx, req)
}

// CloseSession implements OrchestratorCommands.
func (a *SDKAdapter) CloseSession(ctx context.Context, req *platformv1.CloseOrchestratorSessionRequest) (*platformv1.CloseOrchestratorSessionResponse, error) {
	return a.orchestrator.CloseSession(ctx, req)
}

// ListJobs implements OrchestratorCommands.
func (a *SDKAdapter) ListJobs(ctx context.Context, req *platformv1.ListOrchestratorJobsRequest) (*platformv1.ListOrchestratorJobsResponse, error) {
	return a.orchestrator.ListJobs(ctx, req)
}

// GetJob implements OrchestratorCommands.
func (a *SDKAdapter) GetJob(ctx context.Context, req *platformv1.GetOrchestratorJobRequest) (*platformv1.GetOrchestratorJobResponse, error) {
	return a.orchestrator.GetJob(ctx, req)
}

// CancelJob implements OrchestratorCommands.
func (a *SDKAdapter) CancelJob(ctx context.Context, req *platformv1.CancelOrchestratorJobRequest) (*platformv1.CancelOrchestratorJobResponse, error) {
	return a.orchestrator.CancelJob(ctx, req)
}

// Compile-time check: the SDK adapter satisfies the shared surface.
var _ OrchestratorCommands = (*SDKAdapter)(nil)
