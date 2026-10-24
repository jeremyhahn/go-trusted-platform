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

// Package orchestrator is the platform service layer over the go-quicbaas
// orchestrator client (quicbaas.Client.Orchestrator()). Every platform
// transport — gRPC, REST, QUIC, MCP and the Unix socket — calls this layer;
// none calls the SDK client directly. The layer validates requests, calls the
// SDK and converts its records to the platform.v1 OrchestratorService
// messages. It keeps no orchestrator state of its own.
package orchestrator

import (
	"context"

	sdktransport "github.com/jeremyhahn/go-quicbaas/sdk/go/transport"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkorch "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/orchestrator"
)

// ClientResolver returns the SDK orchestrator client, or nil while the
// embedded SDK is not running. The daemon resolves it on every call because
// its quicbaas factory comes up after the transports are wired.
type ClientResolver func() sdkorch.Client

// Service answers OrchestratorService operations from the SDK client.
type Service struct {
	resolve ClientResolver
}

// NewService returns a Service over resolve. A nil resolver, or one that
// returns nil, makes every operation fail with ErrNotConfigured.
func NewService(resolve ClientResolver) *Service {
	return &Service{resolve: resolve}
}

func (s *Service) sdk() (sdkorch.Client, error) {
	if s == nil || s.resolve == nil {
		return nil, ErrNotConfigured{}
	}
	client := s.resolve()
	if client == nil {
		return nil, ErrNotConfigured{}
	}
	return client, nil
}

func required(field, value string) error {
	if value == "" {
		return &ErrMissingField{Field: field}
	}
	return nil
}

// Health returns the orchestrator's health check report.
func (s *Service) Health(ctx context.Context, _ *platformv1.OrchestratorHealthRequest) (*platformv1.OrchestratorHealthResponse, error) {
	client, err := s.sdk()
	if err != nil {
		return nil, err
	}
	report, err := client.Health(ctx)
	if err != nil {
		return nil, &OperationError{Op: "Health", Err: err}
	}
	return &platformv1.OrchestratorHealthResponse{
		Healthy:    report.Healthy,
		Status:     report.Status,
		Components: report.Components,
		Timestamp:  report.Timestamp,
	}, nil
}

// ListAgents returns one page of the tenant's registered agents.
func (s *Service) ListAgents(ctx context.Context, req *platformv1.ListOrchestratorAgentsRequest) (*platformv1.ListOrchestratorAgentsResponse, error) {
	client, err := s.sdk()
	if err != nil {
		return nil, err
	}
	if err := required("tenant_id", req.GetTenantId()); err != nil {
		return nil, err
	}
	sdkReq := &sdkorch.ListAgentsRequest{
		TenantID: req.GetTenantId(),
		Status:   req.GetStatus(),
		Host:     req.GetHost(),
		Backend:  req.GetBackend(),
	}
	if sdkReq.Limit, sdkReq.Offset, err = pageParams(req.GetPage()); err != nil {
		return nil, err
	}
	resp, err := client.ListAgents(tenantContext(ctx, req.GetTenantId()), sdkReq)
	if err != nil {
		return nil, &OperationError{Op: "ListAgents", Err: err}
	}
	agents := make([]*platformv1.OrchestratorAgent, 0, len(resp.Agents))
	for _, agent := range resp.Agents {
		agents = append(agents, agentToPb(agent))
	}
	return &platformv1.ListOrchestratorAgentsResponse{
		Agents: agents,
		Page:   pageInfo(resp.Total, resp.Limit, resp.Offset),
	}, nil
}

// GetAgent returns one registered agent.
func (s *Service) GetAgent(ctx context.Context, req *platformv1.GetOrchestratorAgentRequest) (*platformv1.GetOrchestratorAgentResponse, error) {
	client, err := s.sdk()
	if err != nil {
		return nil, err
	}
	if err := tenantAndID(req.GetTenantId(), "agent_id", req.GetAgentId()); err != nil {
		return nil, err
	}
	agent, err := client.GetAgent(tenantContext(ctx, req.GetTenantId()), &sdkorch.GetAgentRequest{TenantID: req.GetTenantId(), AgentID: req.GetAgentId()})
	if err != nil {
		return nil, &OperationError{Op: "GetAgent", Err: err}
	}
	return &platformv1.GetOrchestratorAgentResponse{Agent: agentToPb(agent)}, nil
}

// DisableAgent administratively disables an agent.
func (s *Service) DisableAgent(ctx context.Context, req *platformv1.DisableOrchestratorAgentRequest) (*platformv1.DisableOrchestratorAgentResponse, error) {
	client, err := s.sdk()
	if err != nil {
		return nil, err
	}
	if err := tenantAndID(req.GetTenantId(), "agent_id", req.GetAgentId()); err != nil {
		return nil, err
	}
	resp, err := client.DisableAgent(tenantContext(ctx, req.GetTenantId()), &sdkorch.DisableAgentRequest{TenantID: req.GetTenantId(), AgentID: req.GetAgentId()})
	if err != nil {
		return nil, &OperationError{Op: "DisableAgent", Err: err}
	}
	return &platformv1.DisableOrchestratorAgentResponse{
		AgentId:    resp.AgentID,
		Disabled:   resp.Disabled,
		DisabledAt: resp.DisabledAt.Unix(),
	}, nil
}

// EnableAgent re-activates a disabled agent.
func (s *Service) EnableAgent(ctx context.Context, req *platformv1.EnableOrchestratorAgentRequest) (*platformv1.EnableOrchestratorAgentResponse, error) {
	client, err := s.sdk()
	if err != nil {
		return nil, err
	}
	if err := tenantAndID(req.GetTenantId(), "agent_id", req.GetAgentId()); err != nil {
		return nil, err
	}
	resp, err := client.EnableAgent(tenantContext(ctx, req.GetTenantId()), &sdkorch.EnableAgentRequest{TenantID: req.GetTenantId(), AgentID: req.GetAgentId()})
	if err != nil {
		return nil, &OperationError{Op: "EnableAgent", Err: err}
	}
	return &platformv1.EnableOrchestratorAgentResponse{AgentId: resp.AgentID, Enabled: resp.Enabled}, nil
}

// ListSessions returns one page of agent sessions.
func (s *Service) ListSessions(ctx context.Context, req *platformv1.ListOrchestratorSessionsRequest) (*platformv1.ListOrchestratorSessionsResponse, error) {
	client, err := s.sdk()
	if err != nil {
		return nil, err
	}
	sdkReq := &sdkorch.ListSessionsRequest{
		Status:  req.GetStatus(),
		JobID:   req.GetJobId(),
		AgentID: req.GetAgentId(),
	}
	if sdkReq.Limit, sdkReq.Offset, err = pageParams(req.GetPage()); err != nil {
		return nil, err
	}
	resp, err := client.ListSessions(ctx, sdkReq)
	if err != nil {
		return nil, &OperationError{Op: "ListSessions", Err: err}
	}
	sessions := make([]*platformv1.OrchestratorSession, 0, len(resp.Sessions))
	for _, session := range resp.Sessions {
		sessions = append(sessions, sessionToPb(session))
	}
	return &platformv1.ListOrchestratorSessionsResponse{
		Sessions: sessions,
		Page:     pageInfo(resp.Total, resp.Limit, resp.Offset),
	}, nil
}

// CloseSession terminates an agent session.
func (s *Service) CloseSession(ctx context.Context, req *platformv1.CloseOrchestratorSessionRequest) (*platformv1.CloseOrchestratorSessionResponse, error) {
	client, err := s.sdk()
	if err != nil {
		return nil, err
	}
	if err := required("session_id", req.GetSessionId()); err != nil {
		return nil, err
	}
	resp, err := client.CloseSession(ctx, &sdkorch.CloseSessionRequest{SessionID: req.GetSessionId()})
	if err != nil {
		return nil, &OperationError{Op: "CloseSession", Err: err}
	}
	return &platformv1.CloseOrchestratorSessionResponse{SessionId: resp.SessionID, Closed: resp.Closed}, nil
}

// ListJobs returns one page of the tenant's orchestration jobs.
func (s *Service) ListJobs(ctx context.Context, req *platformv1.ListOrchestratorJobsRequest) (*platformv1.ListOrchestratorJobsResponse, error) {
	client, err := s.sdk()
	if err != nil {
		return nil, err
	}
	if err := required("tenant_id", req.GetTenantId()); err != nil {
		return nil, err
	}
	sdkReq := &sdkorch.ListJobsRequest{TenantID: req.GetTenantId(), Statuses: req.GetStatuses()}
	if sdkReq.Limit, sdkReq.Offset, err = pageParams(req.GetPage()); err != nil {
		return nil, err
	}
	resp, err := client.ListJobs(tenantContext(ctx, req.GetTenantId()), sdkReq)
	if err != nil {
		return nil, &OperationError{Op: "ListJobs", Err: err}
	}
	jobs := make([]*platformv1.OrchestratorJob, 0, len(resp.Jobs))
	for i := range resp.Jobs {
		jobs = append(jobs, jobSummaryToPb(&resp.Jobs[i]))
	}
	return &platformv1.ListOrchestratorJobsResponse{
		Jobs: jobs,
		Page: pageInfo(resp.Total, resp.Limit, resp.Offset),
	}, nil
}

// GetJob returns the current status of one orchestration job.
func (s *Service) GetJob(ctx context.Context, req *platformv1.GetOrchestratorJobRequest) (*platformv1.GetOrchestratorJobResponse, error) {
	client, err := s.sdk()
	if err != nil {
		return nil, err
	}
	if err := tenantAndID(req.GetTenantId(), "job_id", req.GetJobId()); err != nil {
		return nil, err
	}
	job, err := client.GetJobStatus(tenantContext(ctx, req.GetTenantId()), &sdkorch.GetJobStatusRequest{TenantID: req.GetTenantId(), JobID: req.GetJobId()})
	if err != nil {
		return nil, &OperationError{Op: "GetJob", Err: err}
	}
	return &platformv1.GetOrchestratorJobResponse{Job: jobStatusToPb(job)}, nil
}

// CancelJob cancels a running orchestration job.
func (s *Service) CancelJob(ctx context.Context, req *platformv1.CancelOrchestratorJobRequest) (*platformv1.CancelOrchestratorJobResponse, error) {
	client, err := s.sdk()
	if err != nil {
		return nil, err
	}
	if err := tenantAndID(req.GetTenantId(), "job_id", req.GetJobId()); err != nil {
		return nil, err
	}
	resp, err := client.CancelJob(tenantContext(ctx, req.GetTenantId()), &sdkorch.CancelJobRequest{TenantID: req.GetTenantId(), JobID: req.GetJobId()})
	if err != nil {
		return nil, &OperationError{Op: "CancelJob", Err: err}
	}
	return &platformv1.CancelOrchestratorJobResponse{JobId: resp.JobID, Cancelled: resp.Cancelled}, nil
}

func tenantAndID(tenantID, idField, id string) error {
	if err := required("tenant_id", tenantID); err != nil {
		return err
	}
	return required(idField, id)
}

// tenantContext names tenantID on ctx for the SDK call, the way every
// tenant-scoped SDK route does (pkg/webservice/v1/webauthn/webauthn.go,
// fido2Context): the go-quicbaas orchestration service checks the context's
// tenant, not only the request body's, and refuses an unscoped call.
func tenantContext(ctx context.Context, tenantID string) context.Context {
	return sdktransport.ContextWithTenant(ctx, tenantID)
}
