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
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// orchestratorMCPTestServer answers every OrchestratorService RPC with a
// fixed response, or with err when it is set, and records the last request.
type orchestratorMCPTestServer struct {
	platformv1.UnimplementedOrchestratorServiceServer

	err     error
	request proto.Message
}

func (s *orchestratorMCPTestServer) answer(req proto.Message, resp proto.Message) (proto.Message, error) {
	s.request = req
	if s.err != nil {
		return nil, s.err
	}
	return resp, nil
}

func (s *orchestratorMCPTestServer) Health(_ context.Context, req *platformv1.OrchestratorHealthRequest) (*platformv1.OrchestratorHealthResponse, error) {
	resp, err := s.answer(req, &platformv1.OrchestratorHealthResponse{Healthy: true})
	return asOrchestratorResponse[platformv1.OrchestratorHealthResponse](resp, err)
}

func (s *orchestratorMCPTestServer) ListAgents(_ context.Context, req *platformv1.ListOrchestratorAgentsRequest) (*platformv1.ListOrchestratorAgentsResponse, error) {
	resp, err := s.answer(req, &platformv1.ListOrchestratorAgentsResponse{Agents: []*platformv1.OrchestratorAgent{{Id: "a1"}}})
	return asOrchestratorResponse[platformv1.ListOrchestratorAgentsResponse](resp, err)
}

func (s *orchestratorMCPTestServer) GetAgent(_ context.Context, req *platformv1.GetOrchestratorAgentRequest) (*platformv1.GetOrchestratorAgentResponse, error) {
	resp, err := s.answer(req, &platformv1.GetOrchestratorAgentResponse{Agent: &platformv1.OrchestratorAgent{Id: "a1"}})
	return asOrchestratorResponse[platformv1.GetOrchestratorAgentResponse](resp, err)
}

func (s *orchestratorMCPTestServer) DisableAgent(_ context.Context, req *platformv1.DisableOrchestratorAgentRequest) (*platformv1.DisableOrchestratorAgentResponse, error) {
	resp, err := s.answer(req, &platformv1.DisableOrchestratorAgentResponse{AgentId: "a1", Disabled: true})
	return asOrchestratorResponse[platformv1.DisableOrchestratorAgentResponse](resp, err)
}

func (s *orchestratorMCPTestServer) EnableAgent(_ context.Context, req *platformv1.EnableOrchestratorAgentRequest) (*platformv1.EnableOrchestratorAgentResponse, error) {
	resp, err := s.answer(req, &platformv1.EnableOrchestratorAgentResponse{AgentId: "a1", Enabled: true})
	return asOrchestratorResponse[platformv1.EnableOrchestratorAgentResponse](resp, err)
}

func (s *orchestratorMCPTestServer) ListSessions(_ context.Context, req *platformv1.ListOrchestratorSessionsRequest) (*platformv1.ListOrchestratorSessionsResponse, error) {
	resp, err := s.answer(req, &platformv1.ListOrchestratorSessionsResponse{Sessions: []*platformv1.OrchestratorSession{{SessionId: "s1"}}})
	return asOrchestratorResponse[platformv1.ListOrchestratorSessionsResponse](resp, err)
}

func (s *orchestratorMCPTestServer) CloseSession(_ context.Context, req *platformv1.CloseOrchestratorSessionRequest) (*platformv1.CloseOrchestratorSessionResponse, error) {
	resp, err := s.answer(req, &platformv1.CloseOrchestratorSessionResponse{SessionId: "s1", Closed: true})
	return asOrchestratorResponse[platformv1.CloseOrchestratorSessionResponse](resp, err)
}

func (s *orchestratorMCPTestServer) ListJobs(_ context.Context, req *platformv1.ListOrchestratorJobsRequest) (*platformv1.ListOrchestratorJobsResponse, error) {
	resp, err := s.answer(req, &platformv1.ListOrchestratorJobsResponse{Jobs: []*platformv1.OrchestratorJob{{JobId: "j1"}}})
	return asOrchestratorResponse[platformv1.ListOrchestratorJobsResponse](resp, err)
}

func (s *orchestratorMCPTestServer) GetJob(_ context.Context, req *platformv1.GetOrchestratorJobRequest) (*platformv1.GetOrchestratorJobResponse, error) {
	resp, err := s.answer(req, &platformv1.GetOrchestratorJobResponse{Job: &platformv1.OrchestratorJob{JobId: "j1"}})
	return asOrchestratorResponse[platformv1.GetOrchestratorJobResponse](resp, err)
}

func (s *orchestratorMCPTestServer) CancelJob(_ context.Context, req *platformv1.CancelOrchestratorJobRequest) (*platformv1.CancelOrchestratorJobResponse, error) {
	resp, err := s.answer(req, &platformv1.CancelOrchestratorJobResponse{JobId: "j1", Cancelled: true})
	return asOrchestratorResponse[platformv1.CancelOrchestratorJobResponse](resp, err)
}

// asOrchestratorResponse narrows answer's message back to the RPC's
// response type.
func asOrchestratorResponse[T any](resp proto.Message, err error) (*T, error) {
	if err != nil {
		return nil, err
	}
	return any(resp).(*T), nil
}

// orchestratorMCPCase is one provider method: how to call it, the request
// the RPC must receive, and the response message it must return.
type orchestratorMCPCase struct {
	call     func(*MCPServiceProvider) (interface{}, error)
	request  proto.Message
	response proto.Message
}

func orchestratorMCPCases() map[string]orchestratorMCPCase {
	ctx := context.Background()
	agentList := &platformv1.ListOrchestratorAgentsRequest{TenantId: "acme", Page: &platformv1.OrchestratorPage{Limit: 5}}
	agentGet := &platformv1.GetOrchestratorAgentRequest{TenantId: "acme", AgentId: "a1"}
	agentDisable := &platformv1.DisableOrchestratorAgentRequest{TenantId: "acme", AgentId: "a1"}
	agentEnable := &platformv1.EnableOrchestratorAgentRequest{TenantId: "acme", AgentId: "a1"}
	sessionList := &platformv1.ListOrchestratorSessionsRequest{AgentId: "a1"}
	sessionClose := &platformv1.CloseOrchestratorSessionRequest{SessionId: "s1"}
	jobList := &platformv1.ListOrchestratorJobsRequest{TenantId: "acme", Statuses: []string{"running"}}
	jobGet := &platformv1.GetOrchestratorJobRequest{TenantId: "acme", JobId: "j1"}
	jobCancel := &platformv1.CancelOrchestratorJobRequest{TenantId: "acme", JobId: "j1"}

	return map[string]orchestratorMCPCase{
		"OrchestratorHealth": {
			call:     func(m *MCPServiceProvider) (interface{}, error) { return m.OrchestratorHealth(ctx) },
			request:  &platformv1.OrchestratorHealthRequest{},
			response: &platformv1.OrchestratorHealthResponse{Healthy: true},
		},
		"OrchestratorListAgents": {
			call:     func(m *MCPServiceProvider) (interface{}, error) { return m.OrchestratorListAgents(ctx, agentList) },
			request:  agentList,
			response: &platformv1.ListOrchestratorAgentsResponse{Agents: []*platformv1.OrchestratorAgent{{Id: "a1"}}},
		},
		"OrchestratorGetAgent": {
			call:     func(m *MCPServiceProvider) (interface{}, error) { return m.OrchestratorGetAgent(ctx, agentGet) },
			request:  agentGet,
			response: &platformv1.GetOrchestratorAgentResponse{Agent: &platformv1.OrchestratorAgent{Id: "a1"}},
		},
		"OrchestratorDisableAgent": {
			call:     func(m *MCPServiceProvider) (interface{}, error) { return m.OrchestratorDisableAgent(ctx, agentDisable) },
			request:  agentDisable,
			response: &platformv1.DisableOrchestratorAgentResponse{AgentId: "a1", Disabled: true},
		},
		"OrchestratorEnableAgent": {
			call:     func(m *MCPServiceProvider) (interface{}, error) { return m.OrchestratorEnableAgent(ctx, agentEnable) },
			request:  agentEnable,
			response: &platformv1.EnableOrchestratorAgentResponse{AgentId: "a1", Enabled: true},
		},
		"OrchestratorListSessions": {
			call:     func(m *MCPServiceProvider) (interface{}, error) { return m.OrchestratorListSessions(ctx, sessionList) },
			request:  sessionList,
			response: &platformv1.ListOrchestratorSessionsResponse{Sessions: []*platformv1.OrchestratorSession{{SessionId: "s1"}}},
		},
		"OrchestratorCloseSession": {
			call:     func(m *MCPServiceProvider) (interface{}, error) { return m.OrchestratorCloseSession(ctx, sessionClose) },
			request:  sessionClose,
			response: &platformv1.CloseOrchestratorSessionResponse{SessionId: "s1", Closed: true},
		},
		"OrchestratorListJobs": {
			call:     func(m *MCPServiceProvider) (interface{}, error) { return m.OrchestratorListJobs(ctx, jobList) },
			request:  jobList,
			response: &platformv1.ListOrchestratorJobsResponse{Jobs: []*platformv1.OrchestratorJob{{JobId: "j1"}}},
		},
		"OrchestratorGetJob": {
			call:     func(m *MCPServiceProvider) (interface{}, error) { return m.OrchestratorGetJob(ctx, jobGet) },
			request:  jobGet,
			response: &platformv1.GetOrchestratorJobResponse{Job: &platformv1.OrchestratorJob{JobId: "j1"}},
		},
		"OrchestratorCancelJob": {
			call:     func(m *MCPServiceProvider) (interface{}, error) { return m.OrchestratorCancelJob(ctx, jobCancel) },
			request:  jobCancel,
			response: &platformv1.CancelOrchestratorJobResponse{JobId: "j1", Cancelled: true},
		},
	}
}

func TestMCPOrchestratorProviderForwardsToTheRPC(t *testing.T) {
	for name, tc := range orchestratorMCPCases() {
		t.Run(name, func(t *testing.T) {
			server := &orchestratorMCPTestServer{}
			provider := &MCPServiceProvider{}
			provider.SetOrchestratorService(server)

			result, err := tc.call(provider)
			if err != nil {
				t.Fatalf("%s() error = %v", name, err)
			}
			if !proto.Equal(server.request, tc.request) {
				t.Fatalf("RPC received %v, want %v", server.request, tc.request)
			}
			got, ok := result.(proto.Message)
			if !ok || !proto.Equal(got, tc.response) {
				t.Fatalf("%s() = %v, want %v", name, result, tc.response)
			}
		})
	}
}

func TestMCPOrchestratorProviderReportsUnavailableWithoutABackend(t *testing.T) {
	for name, tc := range orchestratorMCPCases() {
		t.Run(name, func(t *testing.T) {
			var unavailable ErrServiceNotAvailable
			result, err := tc.call(&MCPServiceProvider{})
			if !errors.As(err, &unavailable) {
				t.Fatalf("%s() error = %v, want ErrServiceNotAvailable", name, err)
			}
			if unavailable.Service != "orchestrator" {
				t.Fatalf("Service = %q, want orchestrator", unavailable.Service)
			}
			if result != nil {
				t.Fatalf("%s() result = %v, want nil", name, result)
			}
		})
	}
}

func TestMCPOrchestratorProviderPropagatesRPCFailures(t *testing.T) {
	failure := status.Error(codes.NotFound, "agent not found")

	for name, tc := range orchestratorMCPCases() {
		t.Run(name, func(t *testing.T) {
			provider := &MCPServiceProvider{}
			provider.SetOrchestratorService(&orchestratorMCPTestServer{err: failure})

			result, err := tc.call(provider)
			if status.Code(err) != codes.NotFound {
				t.Fatalf("%s() error = %v, want the RPC's NotFound status", name, err)
			}
			if result != nil {
				t.Fatalf("%s() result = %v, want nil on failure", name, result)
			}
		})
	}
}
