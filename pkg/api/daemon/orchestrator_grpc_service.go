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

	"github.com/jeremyhahn/go-trusted-platform/pkg/orchestrator"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkorch "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/orchestrator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// OrchestratorGRPCService implements platform.v1 OrchestratorService over the
// pkg/orchestrator service layer. The same instance is registered on the TCP
// gRPC server and the Unix-socket gRPC server, and the REST, QUIC and MCP
// transports call it, so every transport answers with the same status codes.
type OrchestratorGRPCService struct {
	platformv1.UnimplementedOrchestratorServiceServer

	service *orchestrator.Service
}

// NewOrchestratorGRPCService returns the gRPC service over service. A nil
// service answers every RPC with codes.Unavailable.
func NewOrchestratorGRPCService(service *orchestrator.Service) *OrchestratorGRPCService {
	return &OrchestratorGRPCService{service: service}
}

// orchestratorClientResolver resolves quicbaas.Client.Orchestrator() from the
// daemon's quicbaas DAO factory on every call; it returns nil while the
// factory has no SDK client.
func orchestratorClientResolver(config *Config) orchestrator.ClientResolver {
	return func() sdkorch.Client {
		sdkClient := platformSDK(config)
		if sdkClient == nil {
			return nil
		}
		return sdkClient.Orchestrator()
	}
}

// orchestratorCodes maps a service error kind to its gRPC code.
var orchestratorCodes = map[orchestrator.ErrorKind]codes.Code{
	orchestrator.KindInvalidArgument:  codes.InvalidArgument,
	orchestrator.KindNotFound:         codes.NotFound,
	orchestrator.KindConflict:         codes.FailedPrecondition,
	orchestrator.KindPermissionDenied: codes.PermissionDenied,
	orchestrator.KindUnauthenticated:  codes.Unauthenticated,
	orchestrator.KindUnavailable:      codes.Unavailable,
}

func orchestratorErrToGRPC(err error) error {
	code, ok := orchestratorCodes[orchestrator.Classify(err)]
	if !ok {
		code = codes.Internal
	}
	return status.Error(code, err.Error())
}

// orchestratorCall runs one service operation and converts its error.
func orchestratorCall[Req, Resp any](ctx context.Context, req Req, op func(context.Context, Req) (Resp, error)) (Resp, error) {
	if err := authorizeOrchestratorTenant(ctx, req); err != nil {
		var zero Resp
		return zero, err
	}
	resp, err := op(ctx, req)
	if err != nil {
		var zero Resp
		return zero, orchestratorErrToGRPC(err)
	}
	return resp, nil
}

// tenantScopedRequest is every OrchestratorService request that names the
// tenant it acts on.
type tenantScopedRequest interface {
	GetTenantId() string
}

// authorizeOrchestratorTenant refuses a tenant-scoped request that names a
// tenant other than the authenticated caller's own, with
// codes.PermissionDenied, as authorizeIAMTenant does for IAM. A caller with
// no tenant-bound identity (the Unix-socket operator, the in-process
// webservice, which applies its own tenant rule) is admitted, as
// callerTenant documents.
func authorizeOrchestratorTenant(ctx context.Context, req any) error {
	scoped, ok := req.(tenantScopedRequest)
	if !ok {
		return nil
	}
	caller, bound := callerTenant(ctx)
	if !bound || caller == scoped.GetTenantId() {
		return nil
	}
	return status.Error(codes.PermissionDenied, ErrOrchestratorTenantForbidden{Requested: scoped.GetTenantId()}.Error())
}

// Health implements OrchestratorService.Health.
func (s *OrchestratorGRPCService) Health(ctx context.Context, req *platformv1.OrchestratorHealthRequest) (*platformv1.OrchestratorHealthResponse, error) {
	return orchestratorCall(ctx, req, s.service.Health)
}

// ListAgents implements OrchestratorService.ListAgents.
func (s *OrchestratorGRPCService) ListAgents(ctx context.Context, req *platformv1.ListOrchestratorAgentsRequest) (*platformv1.ListOrchestratorAgentsResponse, error) {
	return orchestratorCall(ctx, req, s.service.ListAgents)
}

// GetAgent implements OrchestratorService.GetAgent.
func (s *OrchestratorGRPCService) GetAgent(ctx context.Context, req *platformv1.GetOrchestratorAgentRequest) (*platformv1.GetOrchestratorAgentResponse, error) {
	return orchestratorCall(ctx, req, s.service.GetAgent)
}

// DisableAgent implements OrchestratorService.DisableAgent.
func (s *OrchestratorGRPCService) DisableAgent(ctx context.Context, req *platformv1.DisableOrchestratorAgentRequest) (*platformv1.DisableOrchestratorAgentResponse, error) {
	return orchestratorCall(ctx, req, s.service.DisableAgent)
}

// EnableAgent implements OrchestratorService.EnableAgent.
func (s *OrchestratorGRPCService) EnableAgent(ctx context.Context, req *platformv1.EnableOrchestratorAgentRequest) (*platformv1.EnableOrchestratorAgentResponse, error) {
	return orchestratorCall(ctx, req, s.service.EnableAgent)
}

// ListSessions implements OrchestratorService.ListSessions.
func (s *OrchestratorGRPCService) ListSessions(ctx context.Context, req *platformv1.ListOrchestratorSessionsRequest) (*platformv1.ListOrchestratorSessionsResponse, error) {
	return orchestratorCall(ctx, req, s.service.ListSessions)
}

// CloseSession implements OrchestratorService.CloseSession.
func (s *OrchestratorGRPCService) CloseSession(ctx context.Context, req *platformv1.CloseOrchestratorSessionRequest) (*platformv1.CloseOrchestratorSessionResponse, error) {
	return orchestratorCall(ctx, req, s.service.CloseSession)
}

// ListJobs implements OrchestratorService.ListJobs.
func (s *OrchestratorGRPCService) ListJobs(ctx context.Context, req *platformv1.ListOrchestratorJobsRequest) (*platformv1.ListOrchestratorJobsResponse, error) {
	return orchestratorCall(ctx, req, s.service.ListJobs)
}

// GetJob implements OrchestratorService.GetJob.
func (s *OrchestratorGRPCService) GetJob(ctx context.Context, req *platformv1.GetOrchestratorJobRequest) (*platformv1.GetOrchestratorJobResponse, error) {
	return orchestratorCall(ctx, req, s.service.GetJob)
}

// CancelJob implements OrchestratorService.CancelJob.
func (s *OrchestratorGRPCService) CancelJob(ctx context.Context, req *platformv1.CancelOrchestratorJobRequest) (*platformv1.CancelOrchestratorJobResponse, error) {
	return orchestratorCall(ctx, req, s.service.CancelJob)
}
