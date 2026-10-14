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

package mcp

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// recordingTenantServer is a TenantService that records each request it is
// sent, under its method name, and answers a fixed response or err.
type recordingTenantServer struct {
	platformv1.UnimplementedTenantServiceServer

	requests map[string]interface{}
	calls    []string
	err      error
	quotas   *platformv1.GetQuotasResponse
}

func newRecordingTenantServer() *recordingTenantServer {
	return &recordingTenantServer{requests: make(map[string]interface{})}
}

func (s *recordingTenantServer) record(method string, req interface{}) error {
	s.calls = append(s.calls, method)
	s.requests[method] = req
	return s.err
}

func okStatus() *platformv1.Status {
	return &platformv1.Status{Success: true, Message: "ok"}
}

func testTenant(id string) *platformv1.Tenant {
	return &platformv1.Tenant{Id: id, Name: id + "-name", State: platformv1.TenantState_TENANT_STATE_ACTIVE}
}

func (s *recordingTenantServer) ListTenants(_ context.Context, req *platformv1.ListTenantsRequest) (*platformv1.ListTenantsResponse, error) {
	if err := s.record("ListTenants", req); err != nil {
		return nil, err
	}
	return &platformv1.ListTenantsResponse{Tenants: []*platformv1.Tenant{testTenant("t1")}, Total: 1}, nil
}

func (s *recordingTenantServer) GetTenant(_ context.Context, req *platformv1.GetTenantRequest) (*platformv1.GetTenantResponse, error) {
	if err := s.record("GetTenant", req); err != nil {
		return nil, err
	}
	return &platformv1.GetTenantResponse{Tenant: testTenant(req.GetTenantId())}, nil
}

func (s *recordingTenantServer) GetTenantByName(_ context.Context, req *platformv1.GetTenantByNameRequest) (*platformv1.GetTenantByNameResponse, error) {
	if err := s.record("GetTenantByName", req); err != nil {
		return nil, err
	}
	return &platformv1.GetTenantByNameResponse{Tenant: testTenant("t1")}, nil
}

func (s *recordingTenantServer) CreateTenant(_ context.Context, req *platformv1.CreateTenantRequest) (*platformv1.CreateTenantResponse, error) {
	if err := s.record("CreateTenant", req); err != nil {
		return nil, err
	}
	return &platformv1.CreateTenantResponse{Status: okStatus(), Tenant: testTenant("t1")}, nil
}

func (s *recordingTenantServer) UpdateTenant(_ context.Context, req *platformv1.UpdateTenantRequest) (*platformv1.UpdateTenantResponse, error) {
	if err := s.record("UpdateTenant", req); err != nil {
		return nil, err
	}
	return &platformv1.UpdateTenantResponse{Status: okStatus(), Tenant: testTenant(req.GetTenantId())}, nil
}

func (s *recordingTenantServer) DeleteTenant(_ context.Context, req *platformv1.DeleteTenantRequest) (*platformv1.DeleteTenantResponse, error) {
	if err := s.record("DeleteTenant", req); err != nil {
		return nil, err
	}
	return &platformv1.DeleteTenantResponse{Status: okStatus()}, nil
}

func (s *recordingTenantServer) SuspendTenant(_ context.Context, req *platformv1.SuspendTenantRequest) (*platformv1.SuspendTenantResponse, error) {
	if err := s.record("SuspendTenant", req); err != nil {
		return nil, err
	}
	return &platformv1.SuspendTenantResponse{Status: okStatus()}, nil
}

func (s *recordingTenantServer) ResumeTenant(_ context.Context, req *platformv1.ResumeTenantRequest) (*platformv1.ResumeTenantResponse, error) {
	if err := s.record("ResumeTenant", req); err != nil {
		return nil, err
	}
	return &platformv1.ResumeTenantResponse{Status: okStatus()}, nil
}

func (s *recordingTenantServer) GetQuotas(_ context.Context, req *platformv1.GetQuotasRequest) (*platformv1.GetQuotasResponse, error) {
	if err := s.record("GetQuotas", req); err != nil {
		return nil, err
	}
	if s.quotas != nil {
		return s.quotas, nil
	}
	return &platformv1.GetQuotasResponse{TenantId: req.GetTenantId()}, nil
}

func (s *recordingTenantServer) UpdateQuotas(_ context.Context, req *platformv1.UpdateQuotasRequest) (*platformv1.UpdateQuotasResponse, error) {
	if err := s.record("UpdateQuotas", req); err != nil {
		return nil, err
	}
	return &platformv1.UpdateQuotasResponse{Status: okStatus()}, nil
}

func (s *recordingTenantServer) GetUsage(_ context.Context, req *platformv1.GetUsageRequest) (*platformv1.GetUsageResponse, error) {
	if err := s.record("GetUsage", req); err != nil {
		return nil, err
	}
	return &platformv1.GetUsageResponse{Usage: &platformv1.TenantUsage{TenantId: req.GetTenantId(), Vms: 2}}, nil
}

func (s *recordingTenantServer) CheckQuota(_ context.Context, req *platformv1.CheckQuotaRequest) (*platformv1.CheckQuotaResponse, error) {
	if err := s.record("CheckQuota", req); err != nil {
		return nil, err
	}
	return &platformv1.CheckQuotaResponse{
		TenantId:  req.GetTenantId(),
		Resource:  req.GetResource(),
		Amount:    req.GetAmount(),
		Available: false,
		Message:   "over quota",
	}, nil
}

func (s *recordingTenantServer) Sync(_ context.Context, req *platformv1.SyncTenantsRequest) (*platformv1.SyncTenantsResponse, error) {
	if err := s.record("Sync", req); err != nil {
		return nil, err
	}
	return &platformv1.SyncTenantsResponse{Status: okStatus()}, nil
}

func (s *recordingTenantServer) RotateTenantDEK(_ context.Context, req *platformv1.RotateTenantDEKRequest) (*platformv1.RotateTenantDEKResponse, error) {
	if err := s.record("RotateTenantDEK", req); err != nil {
		return nil, err
	}
	return &platformv1.RotateTenantDEKResponse{TenantId: req.GetTenantId(), OldVersion: 1, NewVersion: 2}, nil
}

func (s *recordingTenantServer) GetTenantDEKStatus(_ context.Context, req *platformv1.GetTenantDEKStatusRequest) (*platformv1.GetTenantDEKStatusResponse, error) {
	if err := s.record("GetTenantDEKStatus", req); err != nil {
		return nil, err
	}
	return &platformv1.GetTenantDEKStatusResponse{DekStatus: &platformv1.TenantDEKStatus{
		TenantId:          req.GetTenantId(),
		Version:           3,
		ReencryptProgress: &platformv1.DEKReencryptionProgress{InProgress: true, TotalKeys: 10},
	}}, nil
}

func (s *recordingTenantServer) InitTenantBarrier(_ context.Context, req *platformv1.InitTenantBarrierRequest) (*platformv1.InitTenantBarrierResponse, error) {
	if err := s.record("InitTenantBarrier", req); err != nil {
		return nil, err
	}
	return &platformv1.InitTenantBarrierResponse{Status: okStatus()}, nil
}

func (s *recordingTenantServer) UnsealTenantBarrier(_ context.Context, req *platformv1.UnsealTenantBarrierRequest) (*platformv1.UnsealTenantBarrierResponse, error) {
	if err := s.record("UnsealTenantBarrier", req); err != nil {
		return nil, err
	}
	return &platformv1.UnsealTenantBarrierResponse{Status: okStatus()}, nil
}

func (s *recordingTenantServer) SealTenantBarrier(_ context.Context, req *platformv1.SealTenantBarrierRequest) (*platformv1.SealTenantBarrierResponse, error) {
	if err := s.record("SealTenantBarrier", req); err != nil {
		return nil, err
	}
	return &platformv1.SealTenantBarrierResponse{Status: okStatus()}, nil
}

func (s *recordingTenantServer) GetTenantBarrierStatus(_ context.Context, req *platformv1.GetTenantBarrierStatusRequest) (*platformv1.GetTenantBarrierStatusResponse, error) {
	if err := s.record("GetTenantBarrierStatus", req); err != nil {
		return nil, err
	}
	return &platformv1.GetTenantBarrierStatusResponse{BarrierStatus: &platformv1.TenantBarrierStatus{
		TenantId:    req.GetTenantId(),
		Sealed:      true,
		Initialized: true,
		Strategy:    "software",
	}}, nil
}

// tenantServiceProvider is a ServiceProvider that serves a TenantService.
type tenantServiceProvider struct {
	*mockServiceProvider
	server platformv1.TenantServiceServer
}

func (p *tenantServiceProvider) TenantService() platformv1.TenantServiceServer {
	return p.server
}

// newTenantToolRegistry is a registry whose tenant tools call server.
func newTenantToolRegistry(server platformv1.TenantServiceServer) *ToolRegistry {
	provider := &tenantServiceProvider{mockServiceProvider: newMockServiceProvider(), server: server}
	return NewToolRegistry(provider, newTestLogger())
}

// boundContext is the context the claims path hands a tool for a caller
// bound to tenantID.
func boundContext(tenantID string) context.Context {
	return ContextWithAuthorizedContext(context.Background(), &platformtoken.AuthorizedContext{
		Subject:  "user",
		TenantID: tenantID,
	})
}

// tenantToolCase is one tenant tool: the arguments that make it succeed, the
// scope it requires and the TenantService method it reaches.
type tenantToolCase struct {
	tool   string
	args   map[string]interface{}
	scope  string
	method string
}

var tenantToolCases = []tenantToolCase{
	{"tenant_list", map[string]interface{}{}, "tenant:read", "ListTenants"},
	{"tenant_get", map[string]interface{}{"tenant_id": "t1"}, "tenant:read", "GetTenant"},
	{"tenant_get_by_name", map[string]interface{}{"name": "n"}, "tenant:read", "GetTenantByName"},
	{"tenant_get_quotas", map[string]interface{}{"tenant_id": "t1"}, "tenant:read", "GetQuotas"},
	{"tenant_get_usage", map[string]interface{}{"tenant_id": "t1"}, "tenant:read", "GetUsage"},
	{"tenant_check_quota", map[string]interface{}{"tenant_id": "t1", "resource_type": "vms", "amount": float64(1)}, "tenant:read", "CheckQuota"},
	{"tenant_get_dek_status", map[string]interface{}{"tenant_id": "t1"}, "tenant:read", "GetTenantDEKStatus"},
	{"platform_tenant_barrier_status", map[string]interface{}{"tenant_id": "t1"}, "tenant:read", "GetTenantBarrierStatus"},
	{"tenant_create", map[string]interface{}{"name": "n"}, "tenant:write", "CreateTenant"},
	{"tenant_update", map[string]interface{}{"tenant_id": "t1", "display_name": "d"}, "tenant:write", "UpdateTenant"},
	{"tenant_update_quotas", map[string]interface{}{"tenant_id": "t1", "max_vms": float64(4)}, "tenant:write", "UpdateQuotas"},
	{"tenant_suspend", map[string]interface{}{"tenant_id": "t1"}, "tenant:write", "SuspendTenant"},
	{"tenant_resume", map[string]interface{}{"tenant_id": "t1"}, "tenant:write", "ResumeTenant"},
	{"tenant_sync", map[string]interface{}{}, "tenant:write", "Sync"},
	{"tenant_rotate_dek", map[string]interface{}{"tenant_id": "t1"}, "tenant:write", "RotateTenantDEK"},
	{"platform_tenant_barrier_init", map[string]interface{}{"tenant_id": "t1"}, "tenant:write", "InitTenantBarrier"},
	{"platform_tenant_barrier_seal", map[string]interface{}{"tenant_id": "t1"}, "tenant:write", "SealTenantBarrier"},
	{"platform_tenant_barrier_unseal", map[string]interface{}{"tenant_id": "t1", "key": base64.StdEncoding.EncodeToString([]byte("k"))}, "tenant:write", "UnsealTenantBarrier"},
	{"tenant_delete", map[string]interface{}{"tenant_id": "t1"}, "tenant:delete", "DeleteTenant"},
}

// lackingScopes are scopes that do not grant scope: the same action on
// another resource, and the tenant actions below it.
var lackingScopes = map[string][]string{
	"tenant:read":   {"iam:read"},
	"tenant:write":  {"iam:write", "tenant:read"},
	"tenant:delete": {"iam:delete", "tenant:read", "tenant:write"},
}

// TestTenantToolsAreRegistered: all 19 tenant tools are served.
func TestTenantToolsAreRegistered(t *testing.T) {
	registered := make(map[string]bool)
	for _, tool := range newTenantToolRegistry(nil).ListTools() {
		registered[tool.Name] = true
	}
	for _, tc := range tenantToolCases {
		assert.True(t, registered[tc.tool], "%s must be registered", tc.tool)
	}
	assert.Len(t, tenantToolCases, 19)
}

// TestTenantToolsAreClassified pins each tenant tool to the scope of its
// TenantService method (pkg/api/grpc/method_permissions.go).
func TestTenantToolsAreClassified(t *testing.T) {
	checker := NewAuthorizationChecker(nil, nil)
	for _, tc := range tenantToolCases {
		got, ok := checker.toolPermissions[tc.tool]
		require.True(t, ok, "%s must have an explicit permission entry", tc.tool)
		assert.Equal(t, tc.scope, got, "%s", tc.tool)
	}
}

// TestTenantToolsAuthorizeByScope runs every tenant tool through the MCP
// server: a token holding the tool's scope gets the TenantService's answer;
// a token lacking it is refused and the TenantService is never reached.
func TestTenantToolsAuthorizeByScope(t *testing.T) {
	for _, tc := range tenantToolCases {
		t.Run(tc.tool, func(t *testing.T) {
			call := func(scopes []string) (*mcpwire.JSONRPCResponse, *recordingTenantServer) {
				server := newRecordingTenantServer()
				provider := &tenantServiceProvider{mockServiceProvider: newMockServiceProvider(), server: server}
				mcpServer := NewServer(provider, nil, newTestLogger())
				mcpServer.SetAuthorizationService(nil, &claimsAuthManagerStub{authCtx: &platformtoken.AuthorizedContext{
					Subject:  "user",
					TenantID: "t1",
					Scopes:   scopes,
				}})
				resp := mcpServer.handleRequest(context.Background(), &mcpwire.JSONRPCRequest{
					JSONRPC: "2.0",
					ID:      1,
					Method:  "tools/call",
					Params:  map[string]interface{}{"name": tc.tool, "arguments": tc.args, "_token": "tok"},
				})
				return resp, server
			}

			resp, server := call([]string{tc.scope})
			require.Nil(t, resp.Error, "a token granting %s must reach %s", tc.scope, tc.tool)
			assert.NotNil(t, resp.Result)
			assert.Contains(t, server.calls, tc.method)

			resp, server = call(lackingScopes[tc.scope])
			require.NotNil(t, resp.Error, "a token lacking %s must be refused %s", tc.scope, tc.tool)
			assert.Equal(t, authErrorCodes[AuthErrorPermissionDenied], resp.Error.Code)
			assert.Empty(t, server.calls, "the TenantService must not run for a refused caller")
		})
	}
}

// TestTenantToolsRefuseUnboundCaller: a caller whose identity carries no
// tenant (the legacy adapter stashes no AuthorizedContext) is refused every
// tenant tool PermissionDenied, before the TenantService is reached.
func TestTenantToolsRefuseUnboundCaller(t *testing.T) {
	server := newRecordingTenantServer()
	registry := newTenantToolRegistry(server)

	for _, tc := range tenantToolCases {
		_, err := registry.ExecuteTool(context.Background(), tc.tool, tc.args)
		require.ErrorAs(t, err, &ErrTenantCallerUnbound{}, "%s", tc.tool)
		assert.Equal(t, codes.PermissionDenied, status.Code(err), "%s", tc.tool)
	}
	assert.Empty(t, server.calls)
}

// TestTenantToolsWithoutTenantService: a bound caller on a daemon that
// serves no TenantService is told the service is unavailable.
func TestTenantToolsWithoutTenantService(t *testing.T) {
	registries := map[string]*ToolRegistry{
		"provider without TenantService": NewToolRegistry(newMockServiceProvider(), newTestLogger()),
		"nil TenantService":              newTenantToolRegistry(nil),
	}
	for name, registry := range registries {
		t.Run(name, func(t *testing.T) {
			for _, tc := range tenantToolCases {
				_, err := registry.ExecuteTool(boundContext("t1"), tc.tool, tc.args)
				assert.Equal(t, ErrTenantServiceUnavailable, err, "%s", tc.tool)
			}
		})
	}
}

// TestTenantToolsReturnServiceErrorsUnchanged: the tools answer the
// TenantService's error as it is, so MCP carries gRPC's error class.
func TestTenantToolsReturnServiceErrorsUnchanged(t *testing.T) {
	for _, code := range []codes.Code{codes.NotFound, codes.InvalidArgument, codes.PermissionDenied} {
		server := newRecordingTenantServer()
		server.err = status.Error(code, "from the service")
		registry := newTenantToolRegistry(server)

		for _, tc := range tenantToolCases {
			_, err := registry.ExecuteTool(boundContext("t1"), tc.tool, tc.args)
			assert.Equal(t, code, status.Code(err), "%s", tc.tool)
		}
	}
}

// TestTenantRotateDEKPassesBackground: the background argument reaches the
// RPC. Before #304 the tool dropped it.
func TestTenantRotateDEKPassesBackground(t *testing.T) {
	for _, background := range []bool{true, false} {
		server := newRecordingTenantServer()
		result, err := newTenantToolRegistry(server).ExecuteTool(boundContext("t1"), "tenant_rotate_dek",
			map[string]interface{}{"tenant_id": "t1", "background": background})
		require.NoError(t, err)

		req := server.requests["RotateTenantDEK"].(*platformv1.RotateTenantDEKRequest)
		assert.Equal(t, background, req.GetBackground())
		assert.Equal(t, "t1", req.GetTenantId())
		out := result.(map[string]interface{})
		assert.Equal(t, uint32(1), out["old_version"])
		assert.Equal(t, uint32(2), out["new_version"])
	}
}

// TestTenantUpdateQuotasKeepsLimitsNotGiven: UpdateQuotas replaces every
// limit, so a limit the caller left out is sent at its current value.
func TestTenantUpdateQuotasKeepsLimitsNotGiven(t *testing.T) {
	server := newRecordingTenantServer()
	server.quotas = &platformv1.GetQuotasResponse{
		TenantId: "t1",
		Compute:  &platformv1.ComputeQuota{MaxVms: 10, MaxContainers: 20, MaxVcpus: 8, MaxMemoryMb: 4096},
		Network:  &platformv1.NetworkQuota{MaxBridges: 2, MaxPorts: 30, MaxBandwidthMbps: 100},
		Storage:  &platformv1.StorageQuota{MaxVolumesGb: 50, MaxSnapshots: 5},
	}

	_, err := newTenantToolRegistry(server).ExecuteTool(boundContext("t1"), "tenant_update_quotas",
		map[string]interface{}{"tenant_id": "t1", "max_vms": float64(12), "max_snapshots": float64(9)})
	require.NoError(t, err)

	assert.Equal(t, []string{"GetQuotas", "UpdateQuotas"}, server.calls)
	req := server.requests["UpdateQuotas"].(*platformv1.UpdateQuotasRequest)
	assert.Equal(t, int64(12), req.GetCompute().GetMaxVms())
	assert.Equal(t, int64(20), req.GetCompute().GetMaxContainers())
	assert.Equal(t, int64(4096), req.GetCompute().GetMaxMemoryMb())
	assert.Equal(t, int64(30), req.GetNetwork().GetMaxPorts())
	assert.Equal(t, int64(50), req.GetStorage().GetMaxVolumesGb())
	assert.Equal(t, int64(9), req.GetStorage().GetMaxSnapshots())
}

// TestTenantUpdateQuotasStopsOnReadError: when the current quotas cannot be
// read, nothing is written.
func TestTenantUpdateQuotasStopsOnReadError(t *testing.T) {
	server := newRecordingTenantServer()
	server.err = status.Error(codes.NotFound, "tenant not found")

	_, err := newTenantToolRegistry(server).ExecuteTool(boundContext("t1"), "tenant_update_quotas",
		map[string]interface{}{"tenant_id": "t1", "max_vms": float64(12)})

	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.Equal(t, []string{"GetQuotas"}, server.calls)
}

// TestTenantBarrierInitPassesShamirParameters: threshold and shares reach
// the RPC, which decides whether they are acceptable.
func TestTenantBarrierInitPassesShamirParameters(t *testing.T) {
	server := newRecordingTenantServer()
	_, err := newTenantToolRegistry(server).ExecuteTool(boundContext("t1"), "platform_tenant_barrier_init",
		map[string]interface{}{"tenant_id": "t1", "threshold": float64(2), "shares": float64(3)})
	require.NoError(t, err)

	req := server.requests["InitTenantBarrier"].(*platformv1.InitTenantBarrierRequest)
	assert.Equal(t, int32(2), req.GetThreshold())
	assert.Equal(t, int32(3), req.GetShares())
}

// TestTenantBarrierUnsealDecodesKey: the base64 key reaches the RPC decoded;
// a key that is not base64 is refused before the RPC.
func TestTenantBarrierUnsealDecodesKey(t *testing.T) {
	server := newRecordingTenantServer()
	registry := newTenantToolRegistry(server)

	_, err := registry.ExecuteTool(boundContext("t1"), "platform_tenant_barrier_unseal",
		map[string]interface{}{"tenant_id": "t1", "key": base64.StdEncoding.EncodeToString([]byte("secret"))})
	require.NoError(t, err)
	req := server.requests["UnsealTenantBarrier"].(*platformv1.UnsealTenantBarrierRequest)
	assert.Equal(t, []byte("secret"), req.GetKey())

	server.calls = nil
	_, err = registry.ExecuteTool(boundContext("t1"), "platform_tenant_barrier_unseal",
		map[string]interface{}{"tenant_id": "t1", "key": "!not base64!"})
	assert.Equal(t, ErrTenantBarrierUnsealKeyDecode, err)
	assert.Empty(t, server.calls)
}

// TestTenantCheckQuotaTranslatesArguments: resource_type and amount reach
// the RPC, and an over-quota answer is a result, not an error.
func TestTenantCheckQuotaTranslatesArguments(t *testing.T) {
	server := newRecordingTenantServer()
	result, err := newTenantToolRegistry(server).ExecuteTool(boundContext("t1"), "tenant_check_quota",
		map[string]interface{}{"tenant_id": "t1", "resource_type": "vcpus", "amount": float64(7)})
	require.NoError(t, err)

	req := server.requests["CheckQuota"].(*platformv1.CheckQuotaRequest)
	assert.Equal(t, "vcpus", req.GetResource())
	assert.Equal(t, int64(7), req.GetAmount())
	out := result.(map[string]interface{})
	assert.Equal(t, false, out["available"])
	assert.Equal(t, "over quota", out["message"])
}

// TestTenantCreateSendsQuotasOnlyWhenGiven: a quota group the caller gave no
// limit for is left nil, so the tenant default applies.
func TestTenantCreateSendsQuotasOnlyWhenGiven(t *testing.T) {
	server := newRecordingTenantServer()
	_, err := newTenantToolRegistry(server).ExecuteTool(boundContext("t1"), "tenant_create",
		map[string]interface{}{"name": "n", "max_vms": float64(3), "labels": map[string]interface{}{"env": "test"}})
	require.NoError(t, err)

	req := server.requests["CreateTenant"].(*platformv1.CreateTenantRequest)
	assert.Equal(t, "n", req.GetName())
	assert.Equal(t, int64(3), req.GetComputeQuota().GetMaxVms())
	assert.Nil(t, req.GetNetworkQuota())
	assert.Nil(t, req.GetStorageQuota())
	assert.Equal(t, map[string]string{"env": "test"}, req.GetLabels())
}

// TestTenantListPassesPagination: limit and offset reach the RPC.
func TestTenantListPassesPagination(t *testing.T) {
	server := newRecordingTenantServer()
	result, err := newTenantToolRegistry(server).ExecuteTool(boundContext("t1"), "tenant_list",
		map[string]interface{}{"limit": float64(5), "offset": float64(10)})
	require.NoError(t, err)

	req := server.requests["ListTenants"].(*platformv1.ListTenantsRequest)
	assert.Equal(t, int32(5), req.GetLimit())
	assert.Equal(t, int32(10), req.GetOffset())
	out := result.(map[string]interface{})
	assert.Equal(t, 1, out["count"])
	assert.Equal(t, int32(1), out["total"])
}

// TestTenantDEKStatusIncludesProgress: re-encryption progress is answered
// when the RPC reports it.
func TestTenantDEKStatusIncludesProgress(t *testing.T) {
	result, err := newTenantToolRegistry(newRecordingTenantServer()).ExecuteTool(boundContext("t1"),
		"tenant_get_dek_status", map[string]interface{}{"tenant_id": "t1"})
	require.NoError(t, err)

	out := result.(map[string]interface{})
	assert.Equal(t, uint64(3), out["version"])
	progress := out["reencrypt_progress"].(map[string]interface{})
	assert.Equal(t, true, progress["in_progress"])
}

func TestFormatTenant(t *testing.T) {
	assert.Nil(t, formatTenant(nil))

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	out := formatTenant(&platformv1.Tenant{
		Id:           "t1",
		Name:         "n",
		State:        platformv1.TenantState_TENANT_STATE_SUSPENDED,
		CreatedAt:    timestamppb.New(created),
		DekPath:      "/tenant/t1/default",
		Labels:       map[string]string{"env": "test"},
		ComputeQuota: &platformv1.ComputeQuota{MaxVms: 4},
	})
	assert.Equal(t, "suspended", out["state"])
	assert.Equal(t, "2026-01-02T03:04:05Z", out["created_at"])
	assert.Equal(t, "", out["updated_at"])
	assert.Equal(t, "/tenant/t1/default", out["dek_path"])
	assert.Equal(t, map[string]string{"env": "test"}, out["labels"])
	assert.NotContains(t, out, "annotations")
	assert.Equal(t, int64(4), out["compute_quota"].(map[string]interface{})["max_vms"])
}

func TestTenantStateName(t *testing.T) {
	assert.Equal(t, "active", tenantStateName(platformv1.TenantState_TENANT_STATE_ACTIVE))
	assert.Equal(t, "TENANT_STATE_UNSPECIFIED", tenantStateName(platformv1.TenantState_TENANT_STATE_UNSPECIFIED))
}

func TestErrTenantCallerUnbound(t *testing.T) {
	err := ErrTenantCallerUnbound{}
	assert.Contains(t, err.Error(), "no tenant")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.False(t, errors.Is(err, ErrTenantServiceUnavailable))
}
