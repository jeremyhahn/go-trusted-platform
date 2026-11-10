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
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gorilla/mux"
	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/orchestrator"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util/peercred"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkorch "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/orchestrator"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/local"
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

func (c *orchestratorTestClient) ListSessions(_ context.Context, _ *sdkorch.ListSessionsRequest) (*sdkorch.ListSessionsResponse, error) {
	return &sdkorch.ListSessionsResponse{Sessions: []*sdkorch.SessionStatusResponse{{SessionID: "s1", Status: "active"}}}, nil
}

func (c *orchestratorTestClient) CloseSession(_ context.Context, req *sdkorch.CloseSessionRequest) (*sdkorch.CloseSessionResponse, error) {
	return &sdkorch.CloseSessionResponse{SessionID: req.SessionID, Closed: true}, nil
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
	svc.SetSystemTenant("sys")
	req := &platformv1.CancelOrchestratorJobRequest{TenantId: "t1", JobId: "j1"}

	_, err := svc.CancelJob(tokenCallerContext("t2"), req)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("other tenant: code = %v (%v), want PermissionDenied", status.Code(err), err)
	}

	admitted := map[string]context.Context{
		"own tenant":     tokenCallerContext("t1"),
		"system tenant":  tokenCallerContext("sys"),
		"unbound caller": context.Background(),
	}
	for name, ctx := range admitted {
		t.Run(name, func(t *testing.T) {
			if _, err := svc.CancelJob(ctx, req); err != nil {
				t.Fatalf("CancelJob: %v", err)
			}
		})
	}

	if err := svc.authorizeTenant(tokenCallerContext("t2"), &platformv1.OrchestratorHealthRequest{}); err != nil {
		t.Fatalf("Health names no tenant and must pass: %v", err)
	}
}

// The SDK cannot carry the caller's tenant into the embedded orchestrator,
// which lists every tenant's sessions, so the session RPCs serve only the
// system tenant.
func TestOrchestratorGRPC_SessionsServeOnlySystemTenant(t *testing.T) {
	svc := orchestratorGRPCOver(&orchestratorTestClient{})
	svc.SetSystemTenant("sys")
	listReq := &platformv1.ListOrchestratorSessionsRequest{}
	closeReq := &platformv1.CloseOrchestratorSessionRequest{SessionId: "s1"}

	refused := map[string]context.Context{
		"tenant caller":  tokenCallerContext("t1"),
		"unbound caller": context.Background(),
	}
	for name, ctx := range refused {
		t.Run(name, func(t *testing.T) {
			if _, err := svc.ListSessions(ctx, listReq); status.Code(err) != codes.PermissionDenied {
				t.Fatalf("ListSessions: code = %v (%v), want PermissionDenied", status.Code(err), err)
			}
			if _, err := svc.CloseSession(ctx, closeReq); status.Code(err) != codes.PermissionDenied {
				t.Fatalf("CloseSession: code = %v (%v), want PermissionDenied", status.Code(err), err)
			}
		})
	}

	sys := tokenCallerContext("sys")
	list, err := svc.ListSessions(sys, listReq)
	if err != nil {
		t.Fatalf("system ListSessions: %v", err)
	}
	if len(list.GetSessions()) != 1 || list.GetSessions()[0].GetSessionId() != "s1" {
		t.Fatalf("system ListSessions = %v, want session s1", list.GetSessions())
	}
	closed, err := svc.CloseSession(sys, closeReq)
	if err != nil {
		t.Fatalf("system CloseSession: %v", err)
	}
	if !closed.GetClosed() || closed.GetSessionId() != "s1" {
		t.Fatalf("system CloseSession = %v, want s1 closed", closed)
	}
}

// The Unix socket's operator carries peer credentials, not a tenant-bound
// identity: it is the trusted local operator, so a session listing or close
// over the socket reaches the service with no token.
func TestOrchestratorGRPC_UnixOperatorReachesSessions(t *testing.T) {
	svc := orchestratorGRPCOver(&orchestratorTestClient{})
	svc.SetSystemTenant("sys")

	dir, err := os.MkdirTemp("", "orch")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "platformd.sock")
	lis, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := grpc.NewServer(
		grpc.Creds(peercred.NewUnixTransportCredentials()),
		grpc.UnaryInterceptor(peercred.UnixCredentialsUnaryInterceptor()),
		grpc.StreamInterceptor(peercred.UnixCredentialsStreamInterceptor()),
	)
	platformv1.RegisterOrchestratorServiceServer(server, svc)
	go server.Serve(lis)
	t.Cleanup(server.Stop)

	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(local.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	client := platformv1.NewOrchestratorServiceClient(conn)

	list, err := client.ListSessions(context.Background(), &platformv1.ListOrchestratorSessionsRequest{})
	if err != nil {
		t.Fatalf("Unix ListSessions: %v", err)
	}
	if len(list.GetSessions()) != 1 || list.GetSessions()[0].GetSessionId() != "s1" {
		t.Fatalf("Unix ListSessions = %v, want session s1", list.GetSessions())
	}
	closed, err := client.CloseSession(context.Background(), &platformv1.CloseOrchestratorSessionRequest{SessionId: "s1"})
	if err != nil {
		t.Fatalf("Unix CloseSession: %v", err)
	}
	if !closed.GetClosed() || closed.GetSessionId() != "s1" {
		t.Fatalf("Unix CloseSession = %v, want s1 closed", closed)
	}
}

// restCallerAuthorizer admits each token as the caller it names.
type restCallerAuthorizer map[string]*platformtoken.AuthorizedContext

func (a restCallerAuthorizer) AuthorizeToken(_ context.Context, token, _, _, _, _ string) (*platformtoken.AuthorizedContext, error) {
	if caller, ok := a[token]; ok {
		return caller, nil
	}
	return nil, errors.New("unknown token")
}

// TestOrchestratorREST_SessionsReachTheSharedService: the REST session
// routes hand the caller they verified to the shared service, whose own
// system-tenant check then admits the system tenant and refuses any other.
func TestOrchestratorREST_SessionsReachTheSharedService(t *testing.T) {
	svc := orchestratorGRPCOver(&orchestratorTestClient{})
	svc.SetSystemTenant("sys")
	guard := rest.NewScopeGuard(restCallerAuthorizer{
		"sys-read":     {Subject: "sys-read", TenantID: "sys", Scopes: []string{"orchestrator:read"}},
		"sys-write":    {Subject: "sys-write", TenantID: "sys", Scopes: []string{"orchestrator:write"}},
		"tenant-read":  {Subject: "tenant-read", TenantID: "t1", Scopes: []string{"orchestrator:read"}},
		"tenant-write": {Subject: "tenant-write", TenantID: "t1", Scopes: []string{"orchestrator:write"}},
	}, nil, nil)
	router := mux.NewRouter()
	rest.NewOrchestratorHandlers(svc, guard, "sys", nil).RegisterRoutes(router)

	serve := func(method, target, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, http.NoBody)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}
	const sessions = "/api/v1/orchestrator/sessions"

	tests := []struct {
		name, method, target, token string
		want                        int
	}{
		{"system list", http.MethodGet, sessions, "sys-read", http.StatusOK},
		{"system close", http.MethodDelete, sessions + "/s1", "sys-write", http.StatusOK},
		{"tenant list", http.MethodGet, sessions, "tenant-read", http.StatusForbidden},
		{"tenant close", http.MethodDelete, sessions + "/s1", "tenant-write", http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if rec := serve(tt.method, tt.target, tt.token); rec.Code != tt.want {
				t.Fatalf("status = %d (%s), want %d", rec.Code, rec.Body, tt.want)
			}
		})
	}
}

// TestOrchestratorGRPC_TenantRuleWithoutSystemTenant proves the fail-closed
// reading: with no system tenant set, a caller named "sys" is an ordinary
// tenant and is refused another tenant's request.
func TestOrchestratorGRPC_TenantRuleWithoutSystemTenant(t *testing.T) {
	svc := orchestratorGRPCOver(&orchestratorTestClient{})
	req := &platformv1.CancelOrchestratorJobRequest{TenantId: "t1", JobId: "j1"}

	_, err := svc.CancelJob(tokenCallerContext("sys"), req)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v (%v), want PermissionDenied", status.Code(err), err)
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
