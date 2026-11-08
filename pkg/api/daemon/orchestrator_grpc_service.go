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
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
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

	// systemTenantID is the platform's system tenant, which may name any
	// tenant; "" admits no caller as system (tenant.IsSystemTenant).
	systemTenantID string
}

// SetSystemTenant sets the platform's system tenant, as
// TenantGRPCServer.SetSystemTenant does. Call it before serving.
func (s *OrchestratorGRPCService) SetSystemTenant(tenantID string) {
	s.systemTenantID = tenantID
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
func orchestratorCall[Req, Resp any](ctx context.Context, s *OrchestratorGRPCService, req Req, op func(context.Context, Req) (Resp, error)) (Resp, error) {
	if err := s.authorizeSystemOnly(ctx, req); err != nil {
		var zero Resp
		return zero, err
	}
	if err := s.authorizeTenant(ctx, req); err != nil {
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

// authorizeSystemOnly refuses the session RPCs to every caller but the system
// tenant. The SDK cannot carry the caller's tenant into the embedded
// orchestrator, which then lists and closes sessions across all tenants.
func (s *OrchestratorGRPCService) authorizeSystemOnly(ctx context.Context, req any) error {
	switch req.(type) {
	case *platformv1.ListOrchestratorSessionsRequest, *platformv1.CloseOrchestratorSessionRequest:
	default:
		return nil
	}
	if caller, bound := callerTenant(ctx); bound && tenant.IsSystemTenant(s.systemTenantID, caller) {
		return nil
	}
	return status.Error(codes.PermissionDenied, "orchestrator sessions are served to the system tenant only")
}

// tenantScopedRequest is every OrchestratorService request that names the
// tenant it acts on.
type tenantScopedRequest interface {
	GetTenantId() string
}

// authorizeTenant applies the platform tenant rule, tenant.AuthorizeTenantAccess,
// the one REST applies too: the system tenant may name any tenant, any other
// caller its own tenant only, and a request naming another tenant is refused
// with codes.PermissionDenied, as authorizeIAMTenant does for IAM. A caller with
// no tenant-bound identity (the Unix-socket operator, the in-process
// webservice, which applies its own tenant rule) is admitted, as
// callerTenant documents.
func (s *OrchestratorGRPCService) authorizeTenant(ctx context.Context, req any) error {
	scoped, ok := req.(tenantScopedRequest)
	if !ok {
		return nil
	}
	caller, bound := callerTenant(ctx)
	if !bound {
		return nil
	}
	isSystem := tenant.IsSystemTenant(s.systemTenantID, caller)
	if err := tenant.AuthorizeTenantAccess(caller, isSystem, scoped.GetTenantId()); err != nil {
		return status.Error(codes.PermissionDenied, ErrOrchestratorTenantForbidden{Requested: scoped.GetTenantId()}.Error())
	}
	return nil
}

// Health implements OrchestratorService.Health.
func (s *OrchestratorGRPCService) Health(ctx context.Context, req *platformv1.OrchestratorHealthRequest) (*platformv1.OrchestratorHealthResponse, error) {
	return orchestratorCall(ctx, s, req, s.service.Health)
}

// ListAgents implements OrchestratorService.ListAgents.
func (s *OrchestratorGRPCService) ListAgents(ctx context.Context, req *platformv1.ListOrchestratorAgentsRequest) (*platformv1.ListOrchestratorAgentsResponse, error) {
	return orchestratorCall(ctx, s, req, s.service.ListAgents)
}

// GetAgent implements OrchestratorService.GetAgent.
func (s *OrchestratorGRPCService) GetAgent(ctx context.Context, req *platformv1.GetOrchestratorAgentRequest) (*platformv1.GetOrchestratorAgentResponse, error) {
	return orchestratorCall(ctx, s, req, s.service.GetAgent)
}

// DisableAgent implements OrchestratorService.DisableAgent.
func (s *OrchestratorGRPCService) DisableAgent(ctx context.Context, req *platformv1.DisableOrchestratorAgentRequest) (*platformv1.DisableOrchestratorAgentResponse, error) {
	return orchestratorCall(ctx, s, req, s.service.DisableAgent)
}

// EnableAgent implements OrchestratorService.EnableAgent.
func (s *OrchestratorGRPCService) EnableAgent(ctx context.Context, req *platformv1.EnableOrchestratorAgentRequest) (*platformv1.EnableOrchestratorAgentResponse, error) {
	return orchestratorCall(ctx, s, req, s.service.EnableAgent)
}

// ListSessions implements OrchestratorService.ListSessions.
func (s *OrchestratorGRPCService) ListSessions(ctx context.Context, req *platformv1.ListOrchestratorSessionsRequest) (*platformv1.ListOrchestratorSessionsResponse, error) {
	return orchestratorCall(ctx, s, req, s.service.ListSessions)
}

// CloseSession implements OrchestratorService.CloseSession.
func (s *OrchestratorGRPCService) CloseSession(ctx context.Context, req *platformv1.CloseOrchestratorSessionRequest) (*platformv1.CloseOrchestratorSessionResponse, error) {
	return orchestratorCall(ctx, s, req, s.service.CloseSession)
}

// ListJobs implements OrchestratorService.ListJobs.
func (s *OrchestratorGRPCService) ListJobs(ctx context.Context, req *platformv1.ListOrchestratorJobsRequest) (*platformv1.ListOrchestratorJobsResponse, error) {
	return orchestratorCall(ctx, s, req, s.service.ListJobs)
}

// GetJob implements OrchestratorService.GetJob.
func (s *OrchestratorGRPCService) GetJob(ctx context.Context, req *platformv1.GetOrchestratorJobRequest) (*platformv1.GetOrchestratorJobResponse, error) {
	return orchestratorCall(ctx, s, req, s.service.GetJob)
}

// CancelJob implements OrchestratorService.CancelJob.
func (s *OrchestratorGRPCService) CancelJob(ctx context.Context, req *platformv1.CancelOrchestratorJobRequest) (*platformv1.CancelOrchestratorJobResponse, error) {
	return orchestratorCall(ctx, s, req, s.service.CancelJob)
}
