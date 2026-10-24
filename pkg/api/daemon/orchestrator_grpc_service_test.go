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
	"testing"

	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
	"github.com/jeremyhahn/go-trusted-platform/pkg/orchestrator"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkorch "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/orchestrator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// orchestratorTestClient answers GetAgent and CancelJob; every other SDK
// method is the embedded nil interface and is never called by these tests.
type orchestratorTestClient struct {
	sdkorch.Client

	agent     *sdkorch.AgentRegistration
	cancelErr error
}

func (c *orchestratorTestClient) GetAgent(_ context.Context, req *sdkorch.GetAgentRequest) (*sdkorch.AgentRegistration, error) {
	if req.AgentID != c.agent.ID {
		return nil, sdkerrors.NewNotFound("GetAgent", "no agent "+req.AgentID)
	}
	return c.agent, nil
}

func (c *orchestratorTestClient) CancelJob(_ context.Context, req *sdkorch.CancelJobRequest) (*sdkorch.CancelJobResponse, error) {
	if c.cancelErr != nil {
		return nil, c.cancelErr
	}
	return &sdkorch.CancelJobResponse{JobID: req.JobID, Cancelled: true}, nil
}

func orchestratorGRPCOver(client sdkorch.Client) *OrchestratorGRPCService {
	return NewOrchestratorGRPCService(orchestrator.NewService(func() sdkorch.Client { return client }))
}

func TestOrchestratorGRPC_GetAgentReturnsTheSDKAgent(t *testing.T) {
	svc := orchestratorGRPCOver(&orchestratorTestClient{agent: &sdkorch.AgentRegistration{ID: "a1", TenantID: "t1", Name: "builder"}})

	resp, err := svc.GetAgent(context.Background(), &platformv1.GetOrchestratorAgentRequest{TenantId: "t1", AgentId: "a1"})
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if resp.GetAgent().GetId() != "a1" || resp.GetAgent().GetName() != "builder" {
		t.Fatalf("GetAgent returned %+v, want agent a1 named builder", resp.GetAgent())
	}
}

func TestOrchestratorGRPC_CancelJob(t *testing.T) {
	svc := orchestratorGRPCOver(&orchestratorTestClient{})

	resp, err := svc.CancelJob(context.Background(), &platformv1.CancelOrchestratorJobRequest{TenantId: "t1", JobId: "j1"})
	if err != nil {
		t.Fatalf("CancelJob: %v", err)
	}
	if resp.GetJobId() != "j1" || !resp.GetCancelled() {
		t.Fatalf("CancelJob returned %+v, want j1 cancelled", resp)
	}
}

// TestOrchestratorGRPC_TenantRule pins the caller-tenant rule every
// non-REST orchestrator transport shares: a caller bound to one tenant
// may not name another, while its own tenant and an unbound caller pass.
func TestOrchestratorGRPC_TenantRule(t *testing.T) {
	svc := orchestratorGRPCOver(&orchestratorTestClient{})
	req := &platformv1.CancelOrchestratorJobRequest{TenantId: "t1", JobId: "j1"}

	_, err := svc.CancelJob(tokenCallerContext("t2"), req)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("other tenant: code = %v (%v), want PermissionDenied", status.Code(err), err)
	}

	admitted := map[string]context.Context{
		"own tenant":     tokenCallerContext("t1"),
		"unbound caller": context.Background(),
	}
	for name, ctx := range admitted {
		t.Run(name, func(t *testing.T) {
			if _, err := svc.CancelJob(ctx, req); err != nil {
				t.Fatalf("CancelJob: %v", err)
			}
		})
	}

	if err := authorizeOrchestratorTenant(tokenCallerContext("t2"), &platformv1.OrchestratorHealthRequest{}); err != nil {
		t.Fatalf("Health names no tenant and must pass: %v", err)
	}
}

func TestOrchestratorGRPC_ErrorCodes(t *testing.T) {
	client := &orchestratorTestClient{agent: &sdkorch.AgentRegistration{ID: "a1"}}
	tests := []struct {
		name string
		svc  *OrchestratorGRPCService
		call func(*OrchestratorGRPCService) error
		want codes.Code
	}{
		{
			name: "no SDK client is Unavailable",
			svc:  NewOrchestratorGRPCService(orchestrator.NewService(nil)),
			call: func(s *OrchestratorGRPCService) error {
				_, err := s.Health(context.Background(), &platformv1.OrchestratorHealthRequest{})
				return err
			},
			want: codes.Unavailable,
		},
		{
			name: "missing tenant is InvalidArgument",
			svc:  orchestratorGRPCOver(client),
			call: func(s *OrchestratorGRPCService) error {
				_, err := s.GetAgent(context.Background(), &platformv1.GetOrchestratorAgentRequest{AgentId: "a1"})
				return err
			},
			want: codes.InvalidArgument,
		},
		{
			name: "unknown agent is NotFound",
			svc:  orchestratorGRPCOver(client),
			call: func(s *OrchestratorGRPCService) error {
				_, err := s.GetAgent(context.Background(), &platformv1.GetOrchestratorAgentRequest{TenantId: "t1", AgentId: "missing"})
				return err
			},
			want: codes.NotFound,
		},
		{
			name: "SDK conflict is FailedPrecondition",
			svc:  orchestratorGRPCOver(&orchestratorTestClient{cancelErr: sdkerrors.NewConflict("CancelJob", "job already finished")}),
			call: func(s *OrchestratorGRPCService) error {
				_, err := s.CancelJob(context.Background(), &platformv1.CancelOrchestratorJobRequest{TenantId: "t1", JobId: "j1"})
				return err
			},
			want: codes.FailedPrecondition,
		},
		{
			name: "unclassified SDK error is Internal",
			svc:  orchestratorGRPCOver(&orchestratorTestClient{cancelErr: context.DeadlineExceeded}),
			call: func(s *OrchestratorGRPCService) error {
				_, err := s.CancelJob(context.Background(), &platformv1.CancelOrchestratorJobRequest{TenantId: "t1", JobId: "j1"})
				return err
			},
			want: codes.Internal,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call(tt.svc)
			if got := status.Code(err); got != tt.want {
				t.Fatalf("code = %v (%v), want %v", got, err, tt.want)
			}
		})
	}
}
