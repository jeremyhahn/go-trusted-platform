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

package tenant

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// inProcTenantServer is an in-memory TenantService served over a Unix
// socket in the test's temp directory, so the CLI run functions exercise the
// real SDK client and gRPC transport without a daemon.
type inProcTenantServer struct {
	platformv1.UnimplementedTenantServiceServer
	mu      sync.Mutex
	tenants map[string]*platformv1.Tenant // by id
	fail    error
}

func (s *inProcTenantServer) byName(name string) (*platformv1.Tenant, error) {
	for _, t := range s.tenants {
		if t.GetName() == name {
			return t, nil
		}
	}
	return nil, status.Error(codes.NotFound, "tenant not found")
}

func (s *inProcTenantServer) ListTenants(context.Context, *platformv1.ListTenantsRequest) (*platformv1.ListTenantsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return nil, s.fail
	}
	out := &platformv1.ListTenantsResponse{}
	for _, t := range s.tenants {
		out.Tenants = append(out.Tenants, t)
	}
	out.Total = int32(len(out.Tenants))
	return out, nil
}

func (s *inProcTenantServer) GetTenant(_ context.Context, r *platformv1.GetTenantRequest) (*platformv1.GetTenantResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tenants[r.GetTenantId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "tenant not found")
	}
	return &platformv1.GetTenantResponse{Tenant: t}, nil
}

func (s *inProcTenantServer) GetTenantByName(_ context.Context, r *platformv1.GetTenantByNameRequest) (*platformv1.GetTenantByNameResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.byName(r.GetName())
	if err != nil {
		return nil, err
	}
	return &platformv1.GetTenantByNameResponse{Tenant: t}, nil
}

func (s *inProcTenantServer) CreateTenant(_ context.Context, r *platformv1.CreateTenantRequest) (*platformv1.CreateTenantResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return nil, s.fail
	}
	t := &platformv1.Tenant{
		Id: "id-" + r.GetName(), Name: r.GetName(), DisplayName: r.GetDisplayName(),
		State: platformv1.TenantState_TENANT_STATE_ACTIVE, ComputeQuota: r.GetComputeQuota(),
		NetworkQuota: r.GetNetworkQuota(), StorageQuota: r.GetStorageQuota(),
	}
	s.tenants[t.Id] = t
	return &platformv1.CreateTenantResponse{Tenant: t}, nil
}

func (s *inProcTenantServer) DeleteTenant(_ context.Context, r *platformv1.DeleteTenantRequest) (*platformv1.DeleteTenantResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return nil, s.fail
	}
	delete(s.tenants, r.GetTenantId())
	return &platformv1.DeleteTenantResponse{}, nil
}

func (s *inProcTenantServer) setState(id string, st platformv1.TenantState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return s.fail
	}
	t, ok := s.tenants[id]
	if !ok {
		return status.Error(codes.NotFound, "tenant not found")
	}
	t.State = st
	return nil
}

func (s *inProcTenantServer) SuspendTenant(_ context.Context, r *platformv1.SuspendTenantRequest) (*platformv1.SuspendTenantResponse, error) {
	return &platformv1.SuspendTenantResponse{}, s.setState(r.GetTenantId(), platformv1.TenantState_TENANT_STATE_SUSPENDED)
}

func (s *inProcTenantServer) ResumeTenant(_ context.Context, r *platformv1.ResumeTenantRequest) (*platformv1.ResumeTenantResponse, error) {
	return &platformv1.ResumeTenantResponse{}, s.setState(r.GetTenantId(), platformv1.TenantState_TENANT_STATE_ACTIVE)
}

func (s *inProcTenantServer) UpdateQuotas(_ context.Context, r *platformv1.UpdateQuotasRequest) (*platformv1.UpdateQuotasResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return nil, s.fail
	}
	t := s.tenants[r.GetTenantId()]
	t.ComputeQuota, t.NetworkQuota, t.StorageQuota = r.GetCompute(), r.GetNetwork(), r.GetStorage()
	return &platformv1.UpdateQuotasResponse{}, nil
}

func (s *inProcTenantServer) barrierErr() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fail
}

func (s *inProcTenantServer) InitTenantBarrier(_ context.Context, _ *platformv1.InitTenantBarrierRequest) (*platformv1.InitTenantBarrierResponse, error) {
	return &platformv1.InitTenantBarrierResponse{Status: &platformv1.Status{Success: true}}, s.barrierErr()
}

func (s *inProcTenantServer) UnsealTenantBarrier(_ context.Context, _ *platformv1.UnsealTenantBarrierRequest) (*platformv1.UnsealTenantBarrierResponse, error) {
	return &platformv1.UnsealTenantBarrierResponse{Status: &platformv1.Status{Success: true}}, s.barrierErr()
}

func (s *inProcTenantServer) SealTenantBarrier(_ context.Context, _ *platformv1.SealTenantBarrierRequest) (*platformv1.SealTenantBarrierResponse, error) {
	return &platformv1.SealTenantBarrierResponse{Status: &platformv1.Status{Success: true}}, s.barrierErr()
}

func (s *inProcTenantServer) GetTenantBarrierStatus(_ context.Context, r *platformv1.GetTenantBarrierStatusRequest) (*platformv1.GetTenantBarrierStatusResponse, error) {
	return &platformv1.GetTenantBarrierStatusResponse{BarrierStatus: &platformv1.TenantBarrierStatus{TenantId: r.GetTenantId(), Initialized: true}}, s.barrierErr()
}

// startTenantServer serves an inProcTenantServer on a Unix socket and
// returns it with CLI flags for each output format pointing at it.
func startTenantServer(t *testing.T) (*inProcTenantServer, func(cli.OutputFormat) *cli.CommonFlags) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "platformd.sock")
	lis, err := net.Listen("unix", sock)
	require.NoError(t, err)
	srv := &inProcTenantServer{tenants: map[string]*platformv1.Tenant{}}
	gs := grpc.NewServer()
	platformv1.RegisterTenantServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	flags := func(format cli.OutputFormat) *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: format,
			NoColor:      true,
			GetContext: func() (*cli.Context, error) {
				return &cli.Context{Name: "test", Type: cli.ContextTypeLocal, Local: &cli.LocalContext{SocketPath: sock}}, nil
			},
		}
	}
	return srv, flags
}

// TestRunCommands_InProcess drives every CLI run function end to end against
// the in-process server, in table and JSON output.
func TestRunCommands_InProcess(t *testing.T) {
	_, flags := startTenantServer(t)

	for _, format := range []cli.OutputFormat{cli.OutputFormatTable, cli.OutputFormatJSON} {
		name := "acme-" + string(format)
		f := flags(format)
		require.NoError(t, runTenantCreate(f, &createTenantOptions{
			Name: name, MaxVMs: 5, MaxBridges: 1, MaxVolumesGB: 10,
		}))
		require.NoError(t, runTenantList(f, 10, 0))
		require.NoError(t, runTenantShow(f, name))
		require.NoError(t, runTenantUsage(f, name))
		require.NoError(t, runQuotasGet(f, name))
		require.NoError(t, runQuotasSet(f, name, &quotasSetOptions{MaxVMs: 7, setMaxVMs: true}))
		require.NoError(t, runTenantSuspend(f, name))
		require.NoError(t, runTenantResume(f, name))
		require.NoError(t, runBarrierInit(f, name, 2, 3))
		require.NoError(t, runBarrierUnseal(f, name, "00112233", ""))
		require.NoError(t, runBarrierSeal(f, name))
		require.NoError(t, runBarrierStatus(f, name))
		require.NoError(t, runTenantDelete(f, name, true))
	}
}

// TestRunCommands_UnknownTenant refuses every name-keyed verb for a tenant
// that does not exist.
func TestRunCommands_UnknownTenant(t *testing.T) {
	_, flags := startTenantServer(t)
	f := flags(cli.OutputFormatTable)
	for name, run := range map[string]func() error{
		"show":    func() error { return runTenantShow(f, "ghost") },
		"usage":   func() error { return runTenantUsage(f, "ghost") },
		"quotas":  func() error { return runQuotasGet(f, "ghost") },
		"set":     func() error { return runQuotasSet(f, "ghost", &quotasSetOptions{}) },
		"suspend": func() error { return runTenantSuspend(f, "ghost") },
		"resume":  func() error { return runTenantResume(f, "ghost") },
		"delete":  func() error { return runTenantDelete(f, "ghost", true) },
		"init":    func() error { return runBarrierInit(f, "ghost", 2, 3) },
		"unseal":  func() error { return runBarrierUnseal(f, "ghost", "00", "") },
		"seal":    func() error { return runBarrierSeal(f, "ghost") },
		"status":  func() error { return runBarrierStatus(f, "ghost") },
	} {
		assert.Error(t, run(), name)
	}
}

// TestRunCommands_ServerFailure surfaces a server failure from the verbs that
// reach the server after the lookup.
func TestRunCommands_ServerFailure(t *testing.T) {
	srv, flags := startTenantServer(t)
	f := flags(cli.OutputFormatTable)
	require.NoError(t, runTenantCreate(f, &createTenantOptions{Name: "acme"}))

	srv.mu.Lock()
	srv.fail = status.Error(codes.Internal, "backend down")
	srv.mu.Unlock()

	var opErr ErrOperationFailed
	assert.True(t, errors.As(runTenantCreate(f, &createTenantOptions{Name: "other"}), &opErr))
	assert.Error(t, runTenantList(f, 10, 0))
	assert.Error(t, runTenantSuspend(f, "acme"))
	assert.Error(t, runTenantResume(f, "acme"))
	assert.Error(t, runTenantDelete(f, "acme", true))
	assert.Error(t, runQuotasSet(f, "acme", &quotasSetOptions{MaxVMs: 1, setMaxVMs: true}))
	assert.Error(t, runBarrierInit(f, "acme", 2, 3))
	assert.Error(t, runBarrierSeal(f, "acme"))
	assert.Error(t, runBarrierStatus(f, "acme"))
}

// TestRunCommands_NoContext refuses to run without a CLI context.
func TestRunCommands_NoContext(t *testing.T) {
	var noCtx cli.ErrNoContextSet
	assert.True(t, errors.As(runTenantCreate(&cli.CommonFlags{}, &createTenantOptions{Name: "x"}), &noCtx))
	assert.True(t, errors.As(runTenantList(&cli.CommonFlags{}, 10, 0), &noCtx))
}
