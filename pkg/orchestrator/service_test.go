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

package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/pkg/orchestration"
	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
	sdktransport "github.com/jeremyhahn/go-quicbaas/sdk/go/transport"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkorch "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/orchestrator"
)

// fakeClient answers the ten operations the Service calls; the embedded
// interface is nil, so any other call panics and fails the test.
type fakeClient struct {
	sdkorch.Client
	err error

	listAgentsReq   *sdkorch.ListAgentsRequest
	listSessionsReq *sdkorch.ListSessionsRequest
	listJobsReq     *sdkorch.ListJobsRequest

	// ctxTenant is the tenant the last tenant-scoped call carried on its
	// context, where the go-quicbaas transport reads it.
	ctxTenant string
	// orchTenant is the tenant the last call carried under the embedded
	// orchestrator's own context key, which its TenantGuard reads.
	orchTenant string
}

var disabledAt = time.Unix(1700000000, 0)

func serviceOver(client sdkorch.Client) *Service {
	return NewService(func() sdkorch.Client { return client })
}

func (f *fakeClient) Health(context.Context) (*sdkorch.HealthCheckReport, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &sdkorch.HealthCheckReport{Healthy: true, Status: "ok", Components: map[string]string{"raft": "ok"}, Timestamp: 42}, nil
}

func (f *fakeClient) ListAgents(ctx context.Context, req *sdkorch.ListAgentsRequest) (*sdkorch.ListAgentsResponse, error) {
	f.ctxTenant = sdktransport.TenantFromContext(ctx)
	f.orchTenant = orchestration.TenantFromContext(ctx)
	f.listAgentsReq = req
	if f.err != nil {
		return nil, f.err
	}
	resp := &sdkorch.ListAgentsResponse{Agents: []*sdkorch.AgentRegistration{{ID: "a1", TenantID: req.TenantID, Status: "online"}}, Count: 1}
	resp.Total, resp.Limit, resp.Offset = 7, req.Limit, req.Offset
	return resp, nil
}

func (f *fakeClient) GetAgent(ctx context.Context, req *sdkorch.GetAgentRequest) (*sdkorch.AgentRegistration, error) {
	f.ctxTenant = sdktransport.TenantFromContext(ctx)
	f.orchTenant = orchestration.TenantFromContext(ctx)
	if f.err != nil {
		return nil, f.err
	}
	return &sdkorch.AgentRegistration{ID: req.AgentID, TenantID: req.TenantID, Name: "builder", Metadata: map[string]string{"k": "v"}}, nil
}

func (f *fakeClient) DisableAgent(ctx context.Context, req *sdkorch.DisableAgentRequest) (*sdkorch.DisableAgentResponse, error) {
	f.ctxTenant = sdktransport.TenantFromContext(ctx)
	f.orchTenant = orchestration.TenantFromContext(ctx)
	if f.err != nil {
		return nil, f.err
	}
	return &sdkorch.DisableAgentResponse{AgentID: req.AgentID, Disabled: true, DisabledAt: disabledAt}, nil
}

func (f *fakeClient) EnableAgent(ctx context.Context, req *sdkorch.EnableAgentRequest) (*sdkorch.EnableAgentResponse, error) {
	f.ctxTenant = sdktransport.TenantFromContext(ctx)
	f.orchTenant = orchestration.TenantFromContext(ctx)
	if f.err != nil {
		return nil, f.err
	}
	return &sdkorch.EnableAgentResponse{AgentID: req.AgentID, Enabled: true}, nil
}

func (f *fakeClient) ListSessions(_ context.Context, req *sdkorch.ListSessionsRequest) (*sdkorch.ListSessionsResponse, error) {
	f.listSessionsReq = req
	if f.err != nil {
		return nil, f.err
	}
	resp := &sdkorch.ListSessionsResponse{Sessions: []*sdkorch.SessionStatusResponse{{SessionID: "s1", JobID: req.JobID, Status: "active"}}}
	resp.Total = 1
	return resp, nil
}

func (f *fakeClient) CloseSession(ctx context.Context, req *sdkorch.CloseSessionRequest) (*sdkorch.CloseSessionResponse, error) {
	f.ctxTenant = sdktransport.TenantFromContext(ctx)
	f.orchTenant = orchestration.TenantFromContext(ctx)
	if f.err != nil {
		return nil, f.err
	}
	return &sdkorch.CloseSessionResponse{SessionID: req.SessionID, Closed: true}, nil
}

func (f *fakeClient) ListJobs(ctx context.Context, req *sdkorch.ListJobsRequest) (*sdkorch.ListJobsResponse, error) {
	f.ctxTenant = sdktransport.TenantFromContext(ctx)
	f.orchTenant = orchestration.TenantFromContext(ctx)
	f.listJobsReq = req
	if f.err != nil {
		return nil, f.err
	}
	resp := &sdkorch.ListJobsResponse{Jobs: []sdkorch.JobSummary{{JobID: "j1", State: "running", TaskCount: 3, Completed: 1}}}
	resp.Total = 1
	return resp, nil
}

func (f *fakeClient) GetJobStatus(ctx context.Context, req *sdkorch.GetJobStatusRequest) (*sdkorch.JobStatus, error) {
	f.ctxTenant = sdktransport.TenantFromContext(ctx)
	f.orchTenant = orchestration.TenantFromContext(ctx)
	if f.err != nil {
		return nil, f.err
	}
	return &sdkorch.JobStatus{JobID: req.JobID, State: "running", Runner: "sdlc", Failed: 2}, nil
}

func (f *fakeClient) CancelJob(ctx context.Context, req *sdkorch.CancelJobRequest) (*sdkorch.CancelJobResponse, error) {
	f.ctxTenant = sdktransport.TenantFromContext(ctx)
	f.orchTenant = orchestration.TenantFromContext(ctx)
	if f.err != nil {
		return nil, f.err
	}
	return &sdkorch.CancelJobResponse{JobID: req.JobID, Cancelled: true}, nil
}

// call runs one Service operation with a valid request.
type call func(ctx context.Context, s *Service) error

var validCalls = map[string]call{
	"Health": func(ctx context.Context, s *Service) error {
		_, err := s.Health(ctx, &platformv1.OrchestratorHealthRequest{})
		return err
	},
	"ListAgents": func(ctx context.Context, s *Service) error {
		_, err := s.ListAgents(ctx, &platformv1.ListOrchestratorAgentsRequest{TenantId: "t1"})
		return err
	},
	"GetAgent": func(ctx context.Context, s *Service) error {
		_, err := s.GetAgent(ctx, &platformv1.GetOrchestratorAgentRequest{TenantId: "t1", AgentId: "a1"})
		return err
	},
	"DisableAgent": func(ctx context.Context, s *Service) error {
		_, err := s.DisableAgent(ctx, &platformv1.DisableOrchestratorAgentRequest{TenantId: "t1", AgentId: "a1"})
		return err
	},
	"EnableAgent": func(ctx context.Context, s *Service) error {
		_, err := s.EnableAgent(ctx, &platformv1.EnableOrchestratorAgentRequest{TenantId: "t1", AgentId: "a1"})
		return err
	},
	"ListSessions": func(ctx context.Context, s *Service) error {
		_, err := s.ListSessions(ctx, &platformv1.ListOrchestratorSessionsRequest{})
		return err
	},
	"CloseSession": func(ctx context.Context, s *Service) error {
		_, err := s.CloseSession(ctx, &platformv1.CloseOrchestratorSessionRequest{SessionId: "s1"})
		return err
	},
	"ListJobs": func(ctx context.Context, s *Service) error {
		_, err := s.ListJobs(ctx, &platformv1.ListOrchestratorJobsRequest{TenantId: "t1"})
		return err
	},
	"GetJob": func(ctx context.Context, s *Service) error {
		_, err := s.GetJob(ctx, &platformv1.GetOrchestratorJobRequest{TenantId: "t1", JobId: "j1"})
		return err
	},
	"CancelJob": func(ctx context.Context, s *Service) error {
		_, err := s.CancelJob(ctx, &platformv1.CancelOrchestratorJobRequest{TenantId: "t1", JobId: "j1"})
		return err
	},
}

func TestService_EveryOperationRefusesWithoutClient(t *testing.T) {
	for name, run := range validCalls {
		t.Run(name, func(t *testing.T) {
			err := run(context.Background(), NewService(nil))
			if !errors.Is(err, ErrNotConfigured{}) {
				t.Fatalf("nil resolver: err = %v, want ErrNotConfigured", err)
			}
			err = run(context.Background(), NewService(func() sdkorch.Client { return nil }))
			if !errors.Is(err, ErrNotConfigured{}) {
				t.Fatalf("resolver without a client: err = %v, want ErrNotConfigured", err)
			}
			if Classify(err) != KindUnavailable {
				t.Fatalf("Classify = %v, want KindUnavailable", Classify(err))
			}
		})
	}
}

func TestService_EveryOperationWrapsSDKError(t *testing.T) {
	sdkErr := sdkerrors.NewNotFound("orchestrator", "no such record")
	for name, run := range validCalls {
		t.Run(name, func(t *testing.T) {
			err := run(context.Background(), serviceOver(&fakeClient{err: sdkErr}))
			var opErr *OperationError
			if !errors.As(err, &opErr) || opErr.Op != name {
				t.Fatalf("err = %v, want OperationError for %s", err, name)
			}
			if Classify(err) != KindNotFound {
				t.Fatalf("Classify = %v, want KindNotFound", Classify(err))
			}
		})
	}
}

func TestService_MissingFields(t *testing.T) {
	ctx := context.Background()
	fake := &fakeClient{}
	s := serviceOver(fake)
	cases := map[string]struct {
		run   func() error
		field string
	}{
		"ListAgents tenant": {func() error {
			_, err := s.ListAgents(ctx, &platformv1.ListOrchestratorAgentsRequest{})
			return err
		}, "tenant_id"},
		"GetAgent agent": {func() error {
			_, err := s.GetAgent(ctx, &platformv1.GetOrchestratorAgentRequest{TenantId: "t1"})
			return err
		}, "agent_id"},
		"DisableAgent tenant": {func() error {
			_, err := s.DisableAgent(ctx, &platformv1.DisableOrchestratorAgentRequest{AgentId: "a1"})
			return err
		}, "tenant_id"},
		"EnableAgent agent": {func() error {
			_, err := s.EnableAgent(ctx, &platformv1.EnableOrchestratorAgentRequest{TenantId: "t1"})
			return err
		}, "agent_id"},
		"CloseSession session": {func() error {
			_, err := s.CloseSession(ctx, &platformv1.CloseOrchestratorSessionRequest{})
			return err
		}, "session_id"},
		"ListJobs tenant": {func() error {
			_, err := s.ListJobs(ctx, &platformv1.ListOrchestratorJobsRequest{})
			return err
		}, "tenant_id"},
		"GetJob job": {func() error {
			_, err := s.GetJob(ctx, &platformv1.GetOrchestratorJobRequest{TenantId: "t1"})
			return err
		}, "job_id"},
		"CancelJob tenant": {func() error {
			_, err := s.CancelJob(ctx, &platformv1.CancelOrchestratorJobRequest{JobId: "j1"})
			return err
		}, "tenant_id"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := tc.run()
			var missing *ErrMissingField
			if !errors.As(err, &missing) || missing.Field != tc.field {
				t.Fatalf("err = %v, want ErrMissingField{%s}", err, tc.field)
			}
			if Classify(err) != KindInvalidArgument {
				t.Fatalf("Classify = %v, want KindInvalidArgument", Classify(err))
			}
			if fake.ctxTenant != "" {
				t.Fatalf("refused request reached the SDK with tenant %q", fake.ctxTenant)
			}
		})
	}
}

// TestService_TenantScopedCallsCarryTheTenant pins the fix for the
// "orchestration: tenant ID required" refusal: every tenant-scoped call
// hands the SDK a context that names the request's tenant, not only the
// request field.
func TestService_TenantScopedCallsCarryTheTenant(t *testing.T) {
	scoped := []string{"ListAgents", "GetAgent", "DisableAgent", "EnableAgent", "ListJobs", "GetJob", "CancelJob"}
	for _, name := range scoped {
		t.Run(name, func(t *testing.T) {
			fake := &fakeClient{}
			if err := validCalls[name](context.Background(), serviceOver(fake)); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if fake.ctxTenant != "t1" {
				t.Fatalf("SDK context tenant = %q, want t1", fake.ctxTenant)
			}
		})
	}
}

// TestService_TenantScopedCallsAlsoSetOrchestrationTenant pins the bridge to
// the embedded backend: its TenantGuard reads the orchestration package's
// context key, not the SDK transport's.
func TestService_TenantScopedCallsAlsoSetOrchestrationTenant(t *testing.T) {
	scoped := []string{"ListAgents", "GetAgent", "DisableAgent", "EnableAgent", "ListJobs", "GetJob", "CancelJob"}
	for _, name := range scoped {
		t.Run(name, func(t *testing.T) {
			fake := &fakeClient{}
			if err := validCalls[name](context.Background(), serviceOver(fake)); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if fake.orchTenant != "t1" {
				t.Fatalf("orchestration context tenant = %q, want t1", fake.orchTenant)
			}
		})
	}
}

// TestService_CloseSessionCarriesSystemTenant: every session route is
// system-only, so CloseSession must reach the backend as the system tenant
// on both context keys.
func TestService_CloseSessionCarriesSystemTenant(t *testing.T) {
	fake := &fakeClient{}
	if err := validCalls["CloseSession"](context.Background(), serviceOver(fake)); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}
	if fake.orchTenant != orchestration.SystemTenantID {
		t.Fatalf("orchestration context tenant = %q, want %q", fake.orchTenant, orchestration.SystemTenantID)
	}
	if fake.ctxTenant != orchestration.SystemTenantID {
		t.Fatalf("SDK context tenant = %q, want %q", fake.ctxTenant, orchestration.SystemTenantID)
	}
}

func TestService_NegativePageRefused(t *testing.T) {
	ctx := context.Background()
	fake := &fakeClient{}
	s := serviceOver(fake)
	bad := &platformv1.OrchestratorPage{Limit: -1}
	_, agentsErr := s.ListAgents(ctx, &platformv1.ListOrchestratorAgentsRequest{TenantId: "t1", Page: bad})
	_, sessionsErr := s.ListSessions(ctx, &platformv1.ListOrchestratorSessionsRequest{Page: &platformv1.OrchestratorPage{Offset: -2}})
	_, jobsErr := s.ListJobs(ctx, &platformv1.ListOrchestratorJobsRequest{TenantId: "t1", Page: bad})
	for _, err := range []error{agentsErr, sessionsErr, jobsErr} {
		if !errors.Is(err, ErrInvalidPage{}) {
			t.Fatalf("err = %v, want ErrInvalidPage", err)
		}
	}
	if fake.listAgentsReq != nil || fake.listSessionsReq != nil || fake.listJobsReq != nil {
		t.Fatal("a refused page reached the SDK")
	}
}

func TestService_Health(t *testing.T) {
	resp, err := serviceOver(&fakeClient{}).Health(context.Background(), &platformv1.OrchestratorHealthRequest{})
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if !resp.GetHealthy() || resp.GetStatus() != "ok" || resp.GetComponents()["raft"] != "ok" || resp.GetTimestamp() != 42 {
		t.Fatalf("Health = %+v", resp)
	}
}

func TestService_ListAgentsPassesFiltersAndPage(t *testing.T) {
	fake := &fakeClient{}
	resp, err := serviceOver(fake).ListAgents(context.Background(), &platformv1.ListOrchestratorAgentsRequest{
		TenantId: "t1", Status: "online", Host: "h1", Backend: "claude",
		Page: &platformv1.OrchestratorPage{Limit: 10, Offset: 20},
	})
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	got := fake.listAgentsReq
	if got.TenantID != "t1" || got.Status != "online" || got.Host != "h1" || got.Backend != "claude" || got.Limit != 10 || got.Offset != 20 {
		t.Fatalf("SDK request = %+v", got)
	}
	if len(resp.GetAgents()) != 1 || resp.GetAgents()[0].GetId() != "a1" || resp.GetAgents()[0].GetTenantId() != "t1" {
		t.Fatalf("agents = %+v", resp.GetAgents())
	}
	if page := resp.GetPage(); page.GetTotal() != 7 || page.GetLimit() != 10 || page.GetOffset() != 20 {
		t.Fatalf("page = %+v", page)
	}
}

func TestService_GetAgent(t *testing.T) {
	resp, err := serviceOver(&fakeClient{}).GetAgent(context.Background(), &platformv1.GetOrchestratorAgentRequest{TenantId: "t1", AgentId: "a9"})
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if agent := resp.GetAgent(); agent.GetId() != "a9" || agent.GetName() != "builder" || agent.GetMetadata()["k"] != "v" {
		t.Fatalf("agent = %+v", agent)
	}
}

func TestService_DisableAndEnableAgent(t *testing.T) {
	ctx := context.Background()
	s := serviceOver(&fakeClient{})
	disabled, err := s.DisableAgent(ctx, &platformv1.DisableOrchestratorAgentRequest{TenantId: "t1", AgentId: "a1"})
	if err != nil {
		t.Fatalf("DisableAgent: %v", err)
	}
	if disabled.GetAgentId() != "a1" || !disabled.GetDisabled() || disabled.GetDisabledAt() != disabledAt.Unix() {
		t.Fatalf("DisableAgent = %+v", disabled)
	}
	enabled, err := s.EnableAgent(ctx, &platformv1.EnableOrchestratorAgentRequest{TenantId: "t1", AgentId: "a1"})
	if err != nil {
		t.Fatalf("EnableAgent: %v", err)
	}
	if enabled.GetAgentId() != "a1" || !enabled.GetEnabled() {
		t.Fatalf("EnableAgent = %+v", enabled)
	}
}

func TestService_ListSessionsAndClose(t *testing.T) {
	ctx := context.Background()
	fake := &fakeClient{}
	s := serviceOver(fake)
	list, err := s.ListSessions(ctx, &platformv1.ListOrchestratorSessionsRequest{JobId: "j1", Status: "active", AgentId: "a1"})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if got := fake.listSessionsReq; got.JobID != "j1" || got.Status != "active" || got.AgentID != "a1" {
		t.Fatalf("SDK request = %+v", got)
	}
	if len(list.GetSessions()) != 1 || list.GetSessions()[0].GetJobId() != "j1" || list.GetPage().GetTotal() != 1 {
		t.Fatalf("ListSessions = %+v", list)
	}
	closed, err := s.CloseSession(ctx, &platformv1.CloseOrchestratorSessionRequest{SessionId: "s1"})
	if err != nil {
		t.Fatalf("CloseSession: %v", err)
	}
	if closed.GetSessionId() != "s1" || !closed.GetClosed() {
		t.Fatalf("CloseSession = %+v", closed)
	}
}

func TestService_Jobs(t *testing.T) {
	ctx := context.Background()
	fake := &fakeClient{}
	s := serviceOver(fake)
	list, err := s.ListJobs(ctx, &platformv1.ListOrchestratorJobsRequest{TenantId: "t1", Statuses: []string{"running"}})
	if err != nil {
		t.Fatalf("ListJobs: %v", err)
	}
	if got := fake.listJobsReq; got.TenantID != "t1" || len(got.Statuses) != 1 || got.Statuses[0] != "running" {
		t.Fatalf("SDK request = %+v", got)
	}
	if jobs := list.GetJobs(); len(jobs) != 1 || jobs[0].GetJobId() != "j1" || jobs[0].GetTaskCount() != 3 || jobs[0].GetCompleted() != 1 {
		t.Fatalf("jobs = %+v", jobs)
	}
	job, err := s.GetJob(ctx, &platformv1.GetOrchestratorJobRequest{TenantId: "t1", JobId: "j2"})
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if got := job.GetJob(); got.GetJobId() != "j2" || got.GetRunner() != "sdlc" || got.GetFailed() != 2 {
		t.Fatalf("GetJob = %+v", got)
	}
	cancelled, err := s.CancelJob(ctx, &platformv1.CancelOrchestratorJobRequest{TenantId: "t1", JobId: "j2"})
	if err != nil {
		t.Fatalf("CancelJob: %v", err)
	}
	if cancelled.GetJobId() != "j2" || !cancelled.GetCancelled() {
		t.Fatalf("CancelJob = %+v", cancelled)
	}
}

func TestClassify(t *testing.T) {
	cases := map[string]struct {
		err  error
		want ErrorKind
	}{
		"invalid input": {sdkerrors.NewInvalidInput("op", "bad"), KindInvalidArgument},
		"conflict":      {sdkerrors.NewConflict("op", "pinned"), KindConflict},
		"already":       {sdkerrors.NewAlreadyExists("op", "dup"), KindConflict},
		"forbidden":     {sdkerrors.NewForbidden("op", "no"), KindPermissionDenied},
		"internal":      {sdkerrors.NewInternal("op", "boom"), KindInternal},
		"plain":         {errors.New("plain"), KindInternal},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			wrapped := &OperationError{Op: "X", Err: tc.err}
			if got := Classify(wrapped); got != tc.want {
				t.Fatalf("Classify(%v) = %v, want %v", wrapped, got, tc.want)
			}
		})
	}
}
