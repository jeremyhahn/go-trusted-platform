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

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// SetOrchestratorService wires the orchestrator backend into the MCP service
// provider. A nil server leaves every orchestrator_* tool returning the typed
// service-unavailable error.
func (m *MCPServiceProvider) SetOrchestratorService(server platformv1.OrchestratorServiceServer) {
	m.orchestratorService = server
}

// orchestratorMCPCall forwards one orchestrator tool to its
// OrchestratorService RPC, so the tool answers what the RPC answers: the
// same response message and the same gRPC status class on failure.
func orchestratorMCPCall[Req any, Resp any](ctx context.Context, m *MCPServiceProvider, req *Req,
	method func(platformv1.OrchestratorServiceServer, context.Context, *Req) (Resp, error)) (interface{}, error) {
	if m.orchestratorService == nil {
		return nil, ErrServiceNotAvailable{Service: orchestratorServiceName}
	}
	resp, err := method(m.orchestratorService, ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// OrchestratorHealth returns the orchestrator's health report.
func (m *MCPServiceProvider) OrchestratorHealth(ctx context.Context) (interface{}, error) {
	return orchestratorMCPCall(ctx, m, &platformv1.OrchestratorHealthRequest{}, platformv1.OrchestratorServiceServer.Health)
}

// OrchestratorListAgents returns one page of a tenant's fleet agents.
func (m *MCPServiceProvider) OrchestratorListAgents(ctx context.Context, req *platformv1.ListOrchestratorAgentsRequest) (interface{}, error) {
	return orchestratorMCPCall(ctx, m, req, platformv1.OrchestratorServiceServer.ListAgents)
}

// OrchestratorGetAgent returns one fleet agent.
func (m *MCPServiceProvider) OrchestratorGetAgent(ctx context.Context, req *platformv1.GetOrchestratorAgentRequest) (interface{}, error) {
	return orchestratorMCPCall(ctx, m, req, platformv1.OrchestratorServiceServer.GetAgent)
}

// OrchestratorDisableAgent disables a fleet agent and revokes its credentials.
func (m *MCPServiceProvider) OrchestratorDisableAgent(ctx context.Context, req *platformv1.DisableOrchestratorAgentRequest) (interface{}, error) {
	return orchestratorMCPCall(ctx, m, req, platformv1.OrchestratorServiceServer.DisableAgent)
}

// OrchestratorEnableAgent re-activates a disabled fleet agent.
func (m *MCPServiceProvider) OrchestratorEnableAgent(ctx context.Context, req *platformv1.EnableOrchestratorAgentRequest) (interface{}, error) {
	return orchestratorMCPCall(ctx, m, req, platformv1.OrchestratorServiceServer.EnableAgent)
}

// OrchestratorListSessions returns one page of agent sessions.
func (m *MCPServiceProvider) OrchestratorListSessions(ctx context.Context, req *platformv1.ListOrchestratorSessionsRequest) (interface{}, error) {
	return orchestratorMCPCall(ctx, m, req, platformv1.OrchestratorServiceServer.ListSessions)
}

// OrchestratorCloseSession terminates an agent session.
func (m *MCPServiceProvider) OrchestratorCloseSession(ctx context.Context, req *platformv1.CloseOrchestratorSessionRequest) (interface{}, error) {
	return orchestratorMCPCall(ctx, m, req, platformv1.OrchestratorServiceServer.CloseSession)
}

// OrchestratorListJobs returns one page of a tenant's orchestration jobs.
func (m *MCPServiceProvider) OrchestratorListJobs(ctx context.Context, req *platformv1.ListOrchestratorJobsRequest) (interface{}, error) {
	return orchestratorMCPCall(ctx, m, req, platformv1.OrchestratorServiceServer.ListJobs)
}

// OrchestratorGetJob returns the current status of one orchestration job.
func (m *MCPServiceProvider) OrchestratorGetJob(ctx context.Context, req *platformv1.GetOrchestratorJobRequest) (interface{}, error) {
	return orchestratorMCPCall(ctx, m, req, platformv1.OrchestratorServiceServer.GetJob)
}

// OrchestratorCancelJob cancels a running orchestration job.
func (m *MCPServiceProvider) OrchestratorCancelJob(ctx context.Context, req *platformv1.CancelOrchestratorJobRequest) (interface{}, error) {
	return orchestratorMCPCall(ctx, m, req, platformv1.OrchestratorServiceServer.CancelJob)
}
