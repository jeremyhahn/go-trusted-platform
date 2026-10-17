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
	"path"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// tenantMCPTokens is the MCP server's token validator for these tests: each
// bearer token stands for one AuthorizedContext, which the tenant tools read
// the caller's tenant from.
type tenantMCPTokens struct{ tokenContexts }

func (tenantMCPTokens) GetTokenClaims(context.Context, string) (map[string]interface{}, error) {
	return map[string]interface{}{}, nil
}

// connectTenantMCP serves the harness's tenant server through the daemon's
// MCP server and connects the SDK's MCP adapter as a caller bound to the
// tenant labelled caller.
func connectTenantMCP(t *testing.T, h *tenantParityHarness, caller string) grpc.ClientConnInterface {
	t.Helper()
	provider := &MCPServiceProvider{}
	provider.SetTenantService(h.server)
	config := mcp.DefaultConfig()
	config.AuthManager = tenantMCPTokens{tokenContexts{phase35MCPToken: {
		Subject:  "operator",
		TenantID: h.id(caller),
		Scopes:   []string{"*:*"},
	}}}
	return serveMCPConfig(t, provider, config).Connection()
}

// invokeTenantServer calls method on the tenant server directly, through its
// generated service descriptor, as the caller bound to tenantID.
func invokeTenantServer(h *tenantParityHarness, tenantID, method string, req proto.Message) error {
	for _, desc := range platformv1.TenantService_ServiceDesc.Methods {
		if desc.MethodName != path.Base(method) {
			continue
		}
		decode := func(in interface{}) error {
			proto.Merge(in.(proto.Message), req)
			return nil
		}
		_, err := desc.Handler(h.server, tokenCallerContext(tenantID), decode, nil)
		return err
	}
	return status.Errorf(codes.Unimplemented, "%s is not a TenantService method", method)
}

// initTenantBarrier gives the tenant labelled label a barrier, unsealed.
func initTenantBarrier(t *testing.T, h *tenantParityHarness, label string) {
	t.Helper()
	require.NoError(t, invokeTenantServer(h, h.id(paritySystemTenant),
		platformv1.TenantService_InitTenantBarrier_FullMethodName,
		&platformv1.InitTenantBarrierRequest{TenantId: h.id(label), Threshold: 0, Shares: 0}))
}

// TestSDKMCP_TenantMethods drives every TenantService method through the
// SDK's MCP adapter and the daemon's MCP server, and checks the reply the
// tool's display shape decodes to.
func TestSDKMCP_TenantMethods(t *testing.T) {
	cases := []struct {
		name   string
		caller string
		setup  func(t *testing.T, h *tenantParityHarness)
		method string
		req    func(h *tenantParityHarness) proto.Message
		resp   proto.Message
		check  func(t *testing.T, h *tenantParityHarness, resp proto.Message)
	}{
		{
			name:   "CreateTenant carries the quotas it sets",
			caller: paritySystemTenant,
			method: platformv1.TenantService_CreateTenant_FullMethodName,
			req: func(*tenantParityHarness) proto.Message {
				return &platformv1.CreateTenantRequest{
					Name:         parityNewTenant,
					DisplayName:  "Tenant C",
					ComputeQuota: &platformv1.ComputeQuota{MaxVms: 4, MaxVcpus: 8},
				}
			},
			resp: &platformv1.CreateTenantResponse{},
			check: func(t *testing.T, _ *tenantParityHarness, resp proto.Message) {
				r := resp.(*platformv1.CreateTenantResponse)
				require.True(t, r.GetStatus().GetSuccess(), r.GetStatus().GetMessage())
				require.Equal(t, parityNewTenant, r.GetTenant().GetName())
				require.Equal(t, "Tenant C", r.GetTenant().GetDisplayName())
				require.Equal(t, int64(4), r.GetTenant().GetComputeQuota().GetMaxVms())
				require.NotEqual(t, platformv1.TenantState_TENANT_STATE_UNSPECIFIED, r.GetTenant().GetState())
			},
		},
		{
			name:   "GetTenant",
			caller: parityTenantA,
			method: platformv1.TenantService_GetTenant_FullMethodName,
			req: func(h *tenantParityHarness) proto.Message {
				return &platformv1.GetTenantRequest{TenantId: h.id(parityTenantA)}
			},
			resp: &platformv1.GetTenantResponse{},
			check: func(t *testing.T, h *tenantParityHarness, resp proto.Message) {
				got := resp.(*platformv1.GetTenantResponse).GetTenant()
				require.Equal(t, h.id(parityTenantA), got.GetId())
				require.Equal(t, parityTenantNames[parityTenantA], got.GetName())
				require.NotEqual(t, platformv1.TenantState_TENANT_STATE_UNSPECIFIED, got.GetState())
			},
		},
		{
			name:   "GetTenantByName resolves the caller's own name",
			caller: parityTenantA,
			method: platformv1.TenantService_GetTenantByName_FullMethodName,
			req: func(*tenantParityHarness) proto.Message {
				return &platformv1.GetTenantByNameRequest{Name: parityTenantNames[parityTenantA]}
			},
			resp: &platformv1.GetTenantByNameResponse{},
			check: func(t *testing.T, h *tenantParityHarness, resp proto.Message) {
				require.Equal(t, h.id(parityTenantA), resp.(*platformv1.GetTenantByNameResponse).GetTenant().GetId())
			},
		},
		{
			name:   "ListTenants",
			caller: paritySystemTenant,
			method: platformv1.TenantService_ListTenants_FullMethodName,
			req:    func(*tenantParityHarness) proto.Message { return &platformv1.ListTenantsRequest{} },
			resp:   &platformv1.ListTenantsResponse{},
			check: func(t *testing.T, _ *tenantParityHarness, resp proto.Message) {
				r := resp.(*platformv1.ListTenantsResponse)
				require.Equal(t, int32(len(parityTenantNames)), r.GetTotal())
				names := make([]string, 0, len(r.GetTenants()))
				for _, tn := range r.GetTenants() {
					names = append(names, tn.GetName())
				}
				require.ElementsMatch(t, []string{"tenant-system", "tenant-a", "tenant-b"}, names)
			},
		},
		{
			name:   "UpdateTenant",
			caller: parityTenantA,
			method: platformv1.TenantService_UpdateTenant_FullMethodName,
			req: func(h *tenantParityHarness) proto.Message {
				return &platformv1.UpdateTenantRequest{TenantId: h.id(parityTenantA), DisplayName: "Renamed"}
			},
			resp: &platformv1.UpdateTenantResponse{},
			check: func(t *testing.T, _ *tenantParityHarness, resp proto.Message) {
				r := resp.(*platformv1.UpdateTenantResponse)
				require.True(t, r.GetStatus().GetSuccess(), r.GetStatus().GetMessage())
				require.Equal(t, "Renamed", r.GetTenant().GetDisplayName())
			},
		},
		{
			name:   "SuspendTenant",
			caller: paritySystemTenant,
			method: platformv1.TenantService_SuspendTenant_FullMethodName,
			req: func(h *tenantParityHarness) proto.Message {
				return &platformv1.SuspendTenantRequest{TenantId: h.id(parityTenantA)}
			},
			resp:  &platformv1.SuspendTenantResponse{},
			check: requireTenantStatusSuccess,
		},
		{
			name:   "ResumeTenant",
			caller: paritySystemTenant,
			setup: func(t *testing.T, h *tenantParityHarness) {
				require.NoError(t, invokeTenantServer(h, h.id(paritySystemTenant),
					platformv1.TenantService_SuspendTenant_FullMethodName,
					&platformv1.SuspendTenantRequest{TenantId: h.id(parityTenantA)}))
			},
			method: platformv1.TenantService_ResumeTenant_FullMethodName,
			req: func(h *tenantParityHarness) proto.Message {
				return &platformv1.ResumeTenantRequest{TenantId: h.id(parityTenantA)}
			},
			resp:  &platformv1.ResumeTenantResponse{},
			check: requireTenantStatusSuccess,
		},
		{
			name:   "DeleteTenant",
			caller: paritySystemTenant,
			method: platformv1.TenantService_DeleteTenant_FullMethodName,
			req: func(h *tenantParityHarness) proto.Message {
				return &platformv1.DeleteTenantRequest{TenantId: h.id(parityTenantB)}
			},
			resp:  &platformv1.DeleteTenantResponse{},
			check: requireTenantStatusSuccess,
		},
		{
			name:   "GetQuotas",
			caller: parityTenantA,
			method: platformv1.TenantService_GetQuotas_FullMethodName,
			req: func(h *tenantParityHarness) proto.Message {
				return &platformv1.GetQuotasRequest{TenantId: h.id(parityTenantA)}
			},
			resp: &platformv1.GetQuotasResponse{},
			check: func(t *testing.T, h *tenantParityHarness, resp proto.Message) {
				r := resp.(*platformv1.GetQuotasResponse)
				require.Equal(t, h.id(parityTenantA), r.GetTenantId())
				require.NotNil(t, r.GetCompute())
				require.NotNil(t, r.GetNetwork())
				require.NotNil(t, r.GetStorage())
			},
		},
		{
			name:   "UpdateQuotas carries the limits it sets",
			caller: paritySystemTenant,
			method: platformv1.TenantService_UpdateQuotas_FullMethodName,
			req: func(h *tenantParityHarness) proto.Message {
				return &platformv1.UpdateQuotasRequest{
					TenantId: h.id(parityTenantA),
					Compute:  &platformv1.ComputeQuota{MaxVms: 7},
					Storage:  &platformv1.StorageQuota{MaxSnapshots: 9},
				}
			},
			resp: &platformv1.UpdateQuotasResponse{},
			check: func(t *testing.T, h *tenantParityHarness, resp proto.Message) {
				requireTenantStatusSuccess(t, h, resp)
				quotas, err := h.server.GetQuotas(tokenCallerContext(h.id(paritySystemTenant)),
					&platformv1.GetQuotasRequest{TenantId: h.id(parityTenantA)})
				require.NoError(t, err)
				require.Equal(t, int64(7), quotas.GetCompute().GetMaxVms())
				require.Equal(t, int64(9), quotas.GetStorage().GetMaxSnapshots())
			},
		},
		{
			name:   "GetUsage",
			caller: parityTenantA,
			method: platformv1.TenantService_GetUsage_FullMethodName,
			req: func(h *tenantParityHarness) proto.Message {
				return &platformv1.GetUsageRequest{TenantId: h.id(parityTenantA)}
			},
			resp: &platformv1.GetUsageResponse{},
			check: func(t *testing.T, h *tenantParityHarness, resp proto.Message) {
				usage := resp.(*platformv1.GetUsageResponse).GetUsage()
				require.Equal(t, h.id(parityTenantA), usage.GetTenantId())
				require.NotNil(t, usage.GetTimestamp())
			},
		},
		{
			name:   "CheckQuota",
			caller: parityTenantA,
			method: platformv1.TenantService_CheckQuota_FullMethodName,
			req: func(h *tenantParityHarness) proto.Message {
				return &platformv1.CheckQuotaRequest{TenantId: h.id(parityTenantA), Resource: "vms", Amount: parityQuotaOverAsk}
			},
			resp: &platformv1.CheckQuotaResponse{},
			check: func(t *testing.T, h *tenantParityHarness, resp proto.Message) {
				r := resp.(*platformv1.CheckQuotaResponse)
				require.Equal(t, h.id(parityTenantA), r.GetTenantId())
				require.Equal(t, "vms", r.GetResource())
				require.Equal(t, int64(parityQuotaOverAsk), r.GetAmount())
				// No tenant can hold this many VMs, so the answer is "not
				// available" with the exceeded quota as its reason.
				require.False(t, r.GetAvailable())
				require.Contains(t, r.GetMessage(), "quota exceeded")
			},
		},
		{
			name:   "Sync",
			caller: paritySystemTenant,
			method: platformv1.TenantService_Sync_FullMethodName,
			req:    func(*tenantParityHarness) proto.Message { return &platformv1.SyncTenantsRequest{} },
			resp:   &platformv1.SyncTenantsResponse{},
			check:  requireTenantStatusSuccess,
		},
		{
			name:   "RotateTenantDEK carries background",
			caller: parityTenantA,
			method: platformv1.TenantService_RotateTenantDEK_FullMethodName,
			req: func(h *tenantParityHarness) proto.Message {
				return &platformv1.RotateTenantDEKRequest{TenantId: h.id(parityTenantA), Background: true}
			},
			resp: &platformv1.RotateTenantDEKResponse{},
			check: func(t *testing.T, h *tenantParityHarness, resp proto.Message) {
				r := resp.(*platformv1.RotateTenantDEKResponse)
				require.Equal(t, h.id(parityTenantA), r.GetTenantId())
				require.Equal(t, r.GetOldVersion()+1, r.GetNewVersion())
				require.Equal(t, []bool{true}, h.deks.reencryptions())
			},
		},
		{
			name:   "GetTenantDEKStatus",
			caller: parityTenantA,
			method: platformv1.TenantService_GetTenantDEKStatus_FullMethodName,
			req: func(h *tenantParityHarness) proto.Message {
				return &platformv1.GetTenantDEKStatusRequest{TenantId: h.id(parityTenantA)}
			},
			resp: &platformv1.GetTenantDEKStatusResponse{},
			check: func(t *testing.T, h *tenantParityHarness, resp proto.Message) {
				dek := resp.(*platformv1.GetTenantDEKStatusResponse).GetDekStatus()
				require.Equal(t, h.id(parityTenantA), dek.GetTenantId())
				require.Equal(t, "AES-256-GCM", dek.GetAlgorithm())
			},
		},
		{
			name:   "InitTenantBarrier",
			caller: parityTenantA,
			method: platformv1.TenantService_InitTenantBarrier_FullMethodName,
			req: func(h *tenantParityHarness) proto.Message {
				return &platformv1.InitTenantBarrierRequest{TenantId: h.id(parityTenantA), Threshold: 0, Shares: 0}
			},
			resp: &platformv1.InitTenantBarrierResponse{},
			check: func(t *testing.T, h *tenantParityHarness, resp proto.Message) {
				requireTenantStatusSuccess(t, h, resp)
				require.Equal(t, "unsealed", h.barriers.state(h.id(parityTenantA)))
			},
		},
		{
			name:   "SealTenantBarrier",
			caller: parityTenantA,
			setup: func(t *testing.T, h *tenantParityHarness) {
				initTenantBarrier(t, h, parityTenantA)
			},
			method: platformv1.TenantService_SealTenantBarrier_FullMethodName,
			req: func(h *tenantParityHarness) proto.Message {
				return &platformv1.SealTenantBarrierRequest{TenantId: h.id(parityTenantA)}
			},
			resp: &platformv1.SealTenantBarrierResponse{},
			check: func(t *testing.T, h *tenantParityHarness, resp proto.Message) {
				requireTenantStatusSuccess(t, h, resp)
				require.Equal(t, "sealed", h.barriers.state(h.id(parityTenantA)))
			},
		},
		{
			name:   "UnsealTenantBarrier",
			caller: parityTenantA,
			setup: func(t *testing.T, h *tenantParityHarness) {
				initTenantBarrier(t, h, parityTenantA)
				require.NoError(t, invokeTenantServer(h, h.id(paritySystemTenant),
					platformv1.TenantService_SealTenantBarrier_FullMethodName,
					&platformv1.SealTenantBarrierRequest{TenantId: h.id(parityTenantA)}))
			},
			method: platformv1.TenantService_UnsealTenantBarrier_FullMethodName,
			req: func(h *tenantParityHarness) proto.Message {
				return &platformv1.UnsealTenantBarrierRequest{TenantId: h.id(parityTenantA), Key: []byte("share-1")}
			},
			resp: &platformv1.UnsealTenantBarrierResponse{},
			check: func(t *testing.T, h *tenantParityHarness, resp proto.Message) {
				requireTenantStatusSuccess(t, h, resp)
				require.Equal(t, "unsealed", h.barriers.state(h.id(parityTenantA)))
			},
		},
		{
			name:   "GetTenantBarrierStatus",
			caller: parityTenantA,
			setup: func(t *testing.T, h *tenantParityHarness) {
				initTenantBarrier(t, h, parityTenantA)
			},
			method: platformv1.TenantService_GetTenantBarrierStatus_FullMethodName,
			req: func(h *tenantParityHarness) proto.Message {
				return &platformv1.GetTenantBarrierStatusRequest{TenantId: h.id(parityTenantA)}
			},
			resp: &platformv1.GetTenantBarrierStatusResponse{},
			check: func(t *testing.T, h *tenantParityHarness, resp proto.Message) {
				barrier := resp.(*platformv1.GetTenantBarrierStatusResponse).GetBarrierStatus()
				require.Equal(t, h.id(parityTenantA), barrier.GetTenantId())
				require.False(t, barrier.GetSealed())
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTenantParityHarness(t)
			if tc.setup != nil {
				tc.setup(t, h)
			}
			conn := connectTenantMCP(t, h, tc.caller)
			require.NoError(t, conn.Invoke(context.Background(), tc.method, tc.req(h), tc.resp))
			tc.check(t, h, tc.resp)
		})
	}
}

// requireTenantStatusSuccess checks a reply whose only field is the Status.
func requireTenantStatusSuccess(t *testing.T, _ *tenantParityHarness, resp proto.Message) {
	t.Helper()
	reply, ok := resp.(interface{ GetStatus() *platformv1.Status })
	require.True(t, ok, "%T carries no Status", resp)
	require.True(t, reply.GetStatus().GetSuccess(), reply.GetStatus().GetMessage())
}

// TestSDKMCP_TenantMethodsRefuse checks that each TenantService method's
// refusal reaches the SDK caller over MCP as the code the tenant server
// answers the same caller with, and that the refused call changed nothing.
func TestSDKMCP_TenantMethodsRefuse(t *testing.T) {
	cases := []struct {
		name   string
		caller string
		method string
		req    func(h *tenantParityHarness) proto.Message
		resp   proto.Message
		want   codes.Code
	}{
		{
			name:   "CreateTenant is system-only",
			caller: parityTenantA,
			method: platformv1.TenantService_CreateTenant_FullMethodName,
			req: func(*tenantParityHarness) proto.Message {
				return &platformv1.CreateTenantRequest{Name: parityNewTenant}
			},
			resp: &platformv1.CreateTenantResponse{},
			want: codes.PermissionDenied,
		},
		{
			name:   "GetTenant of another tenant",
			caller: parityTenantA,
			method: platformv1.TenantService_GetTenant_FullMethodName,
			req: func(h *tenantParityHarness) proto.Message {
				return &platformv1.GetTenantRequest{TenantId: h.id(parityTenantB)}
			},
			resp: &platformv1.GetTenantResponse{},
			want: codes.PermissionDenied,
		},
		{
			name:   "GetTenantByName of another tenant's name",
			caller: parityTenantA,
			method: platformv1.TenantService_GetTenantByName_FullMethodName,
			req: func(*tenantParityHarness) proto.Message {
				return &platformv1.GetTenantByNameRequest{Name: parityTenantNames[parityTenantB]}
			},
			resp: &platformv1.GetTenantByNameResponse{},
			want: codes.PermissionDenied,
		},
		{
			name:   "GetTenantByName of an unknown name, alike",
			caller: parityTenantA,
			method: platformv1.TenantService_GetTenantByName_FullMethodName,
			req: func(*tenantParityHarness) proto.Message {
				return &platformv1.GetTenantByNameRequest{Name: parityGhostTenant}
			},
			resp: &platformv1.GetTenantByNameResponse{},
			want: codes.PermissionDenied,
		},
		{
			name:   "UpdateTenant of another tenant",
			caller: parityTenantA,
			method: platformv1.TenantService_UpdateTenant_FullMethodName,
			req: func(h *tenantParityHarness) proto.Message {
				return &platformv1.UpdateTenantRequest{TenantId: h.id(parityTenantB), DisplayName: "x"}
			},
			resp: &platformv1.UpdateTenantResponse{},
			want: codes.PermissionDenied,
		},
		{
			name:   "SuspendTenant by a tenant",
			caller: parityTenantA,
			method: platformv1.TenantService_SuspendTenant_FullMethodName,
			req: func(h *tenantParityHarness) proto.Message {
				return &platformv1.SuspendTenantRequest{TenantId: h.id(parityTenantB)}
			},
			resp: &platformv1.SuspendTenantResponse{},
			want: codes.PermissionDenied,
		},
		{
			name:   "ResumeTenant by a tenant",
			caller: parityTenantA,
			method: platformv1.TenantService_ResumeTenant_FullMethodName,
			req: func(h *tenantParityHarness) proto.Message {
				return &platformv1.ResumeTenantRequest{TenantId: h.id(parityTenantB)}
			},
			resp: &platformv1.ResumeTenantResponse{},
			want: codes.PermissionDenied,
		},
		{
			name:   "DeleteTenant by a tenant",
			caller: parityTenantA,
			method: platformv1.TenantService_DeleteTenant_FullMethodName,
			req: func(h *tenantParityHarness) proto.Message {
				return &platformv1.DeleteTenantRequest{TenantId: h.id(parityTenantB)}
			},
			resp: &platformv1.DeleteTenantResponse{},
			want: codes.PermissionDenied,
		},
		{
			name:   "GetQuotas of another tenant",
			caller: parityTenantA,
			method: platformv1.TenantService_GetQuotas_FullMethodName,
			req: func(h *tenantParityHarness) proto.Message {
				return &platformv1.GetQuotasRequest{TenantId: h.id(parityTenantB)}
			},
			resp: &platformv1.GetQuotasResponse{},
			want: codes.PermissionDenied,
		},
		{
			name:   "UpdateQuotas of another tenant",
			caller: parityTenantA,
			method: platformv1.TenantService_UpdateQuotas_FullMethodName,
			req: func(h *tenantParityHarness) proto.Message {
				return &platformv1.UpdateQuotasRequest{TenantId: h.id(parityTenantB), Compute: &platformv1.ComputeQuota{MaxVms: 99}}
			},
			resp: &platformv1.UpdateQuotasResponse{},
			want: codes.PermissionDenied,
		},
		{
			name:   "GetUsage of another tenant",
			caller: parityTenantA,
			method: platformv1.TenantService_GetUsage_FullMethodName,
			req: func(h *tenantParityHarness) proto.Message {
				return &platformv1.GetUsageRequest{TenantId: h.id(parityTenantB)}
			},
			resp: &platformv1.GetUsageResponse{},
			want: codes.PermissionDenied,
		},
		{
			name:   "CheckQuota of nothing",
			caller: parityTenantA,
			method: platformv1.TenantService_CheckQuota_FullMethodName,
			req: func(h *tenantParityHarness) proto.Message {
				return &platformv1.CheckQuotaRequest{TenantId: h.id(parityTenantA), Resource: "vms", Amount: 0}
			},
			resp: &platformv1.CheckQuotaResponse{},
			want: codes.InvalidArgument,
		},
		{
			name:   "Sync is system-only",
			caller: parityTenantA,
			method: platformv1.TenantService_Sync_FullMethodName,
			req:    func(*tenantParityHarness) proto.Message { return &platformv1.SyncTenantsRequest{} },
			resp:   &platformv1.SyncTenantsResponse{},
			want:   codes.PermissionDenied,
		},
		{
			name:   "RotateTenantDEK of another tenant",
			caller: parityTenantA,
			method: platformv1.TenantService_RotateTenantDEK_FullMethodName,
			req: func(h *tenantParityHarness) proto.Message {
				return &platformv1.RotateTenantDEKRequest{TenantId: h.id(parityTenantB), Background: true}
			},
			resp: &platformv1.RotateTenantDEKResponse{},
			want: codes.PermissionDenied,
		},
		{
			name:   "GetTenantDEKStatus without a tenant",
			caller: parityTenantA,
			method: platformv1.TenantService_GetTenantDEKStatus_FullMethodName,
			req:    func(*tenantParityHarness) proto.Message { return &platformv1.GetTenantDEKStatusRequest{} },
			resp:   &platformv1.GetTenantDEKStatusResponse{},
			want:   codes.InvalidArgument,
		},
		{
			name:   "InitTenantBarrier of another tenant",
			caller: parityTenantA,
			method: platformv1.TenantService_InitTenantBarrier_FullMethodName,
			req: func(h *tenantParityHarness) proto.Message {
				return &platformv1.InitTenantBarrierRequest{TenantId: h.id(parityTenantB), Threshold: 0, Shares: 0}
			},
			resp: &platformv1.InitTenantBarrierResponse{},
			want: codes.PermissionDenied,
		},
		{
			name:   "UnsealTenantBarrier of another tenant",
			caller: parityTenantA,
			method: platformv1.TenantService_UnsealTenantBarrier_FullMethodName,
			req: func(h *tenantParityHarness) proto.Message {
				return &platformv1.UnsealTenantBarrierRequest{TenantId: h.id(parityTenantB), Key: []byte("share-1")}
			},
			resp: &platformv1.UnsealTenantBarrierResponse{},
			want: codes.PermissionDenied,
		},
		{
			name:   "SealTenantBarrier of another tenant",
			caller: parityTenantA,
			method: platformv1.TenantService_SealTenantBarrier_FullMethodName,
			req: func(h *tenantParityHarness) proto.Message {
				return &platformv1.SealTenantBarrierRequest{TenantId: h.id(parityTenantB)}
			},
			resp: &platformv1.SealTenantBarrierResponse{},
			want: codes.PermissionDenied,
		},
		{
			name:   "GetTenantBarrierStatus of another tenant",
			caller: parityTenantA,
			method: platformv1.TenantService_GetTenantBarrierStatus_FullMethodName,
			req: func(h *tenantParityHarness) proto.Message {
				return &platformv1.GetTenantBarrierStatusRequest{TenantId: h.id(parityTenantB)}
			},
			resp: &platformv1.GetTenantBarrierStatusResponse{},
			want: codes.PermissionDenied,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTenantParityHarness(t)
			before := h.snapshot()

			direct := invokeTenantServer(h, h.id(tc.caller), tc.method, tc.req(h))
			require.Equal(t, tc.want, status.Code(direct), "tenant server: %v", direct)

			conn := connectTenantMCP(t, h, tc.caller)
			err := conn.Invoke(context.Background(), tc.method, tc.req(h), tc.resp)
			require.Equal(t, tc.want, status.Code(err), "MCP: %v", err)
			require.Equal(t, before, h.snapshot(), "a refused call changed tenant state")
		})
	}
}

// TestSDKMCP_TenantCallerWithoutTenantIsRefused checks that a token bound to
// no tenant is refused rather than read as the system tenant.
func TestSDKMCP_TenantCallerWithoutTenantIsRefused(t *testing.T) {
	h := newTenantParityHarness(t)
	provider := &MCPServiceProvider{}
	provider.SetTenantService(h.server)
	config := mcp.DefaultConfig()
	config.AuthManager = tenantMCPTokens{tokenContexts{phase35MCPToken: &platformtoken.AuthorizedContext{
		Subject: "operator",
		Scopes:  []string{"*:*"},
	}}}
	conn := serveMCPConfig(t, provider, config).Connection()

	err := conn.Invoke(context.Background(), platformv1.TenantService_Sync_FullMethodName,
		&platformv1.SyncTenantsRequest{}, &platformv1.SyncTenantsResponse{})
	require.Equal(t, codes.PermissionDenied, status.Code(err), "err = %v", err)
}
