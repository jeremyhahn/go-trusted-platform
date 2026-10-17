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

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// connectTenantQUIC serves h through the daemon QUIC handler and returns an
// SDK QUIC client connected to it over mTLS. The client certificate binds the
// caller to its Organization; asSystem makes that tenant the system tenant,
// otherwise the caller is an ordinary tenant that owns none of h's tenants.
func connectTenantQUIC(t *testing.T, h *tenantParityHarness, asSystem bool) grpc.ClientConnInterface {
	t.Helper()
	bundle := testutil.GenerateTestTLSBundle(t)
	if asSystem {
		h.server.SetSystemTenant(leafOf(t, bundle.ClientCert).Subject.Organization[0])
	}
	handler := newTestQUICServiceHandler(logging.DefaultLogger(), mtlsQUICAuth(t, bundle))
	handler.SetTenantGRPCServer(h.server)
	return newPhase35QUICClient(t, handler, bundle).Connection()
}

func (d *memoryTenantDEKs) reencryptions() []bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]bool(nil), d.reencrypt...)
}

func TestSDKQUIC_TenantCheckQuota(t *testing.T) {
	h := newTenantParityHarness(t)
	conn := connectTenantQUIC(t, h, true)

	resp := &platformv1.CheckQuotaResponse{}
	err := conn.Invoke(context.Background(), platformv1.TenantService_CheckQuota_FullMethodName,
		&platformv1.CheckQuotaRequest{TenantId: h.id(parityTenantA), Resource: "vms", Amount: parityQuotaOverAsk}, resp)
	require.NoError(t, err)
	require.Equal(t, h.id(parityTenantA), resp.GetTenantId())
	require.Equal(t, "vms", resp.GetResource())
	require.Equal(t, int64(parityQuotaOverAsk), resp.GetAmount())
	// No tenant can hold this many VMs, so the server answers "not available"
	// with its reason; that answer must cross the wire whole.
	require.False(t, resp.GetAvailable())
	require.Contains(t, resp.GetMessage(), "quota exceeded")

	err = conn.Invoke(context.Background(), platformv1.TenantService_CheckQuota_FullMethodName,
		&platformv1.CheckQuotaRequest{TenantId: h.id(parityTenantA), Resource: "vms", Amount: 0},
		&platformv1.CheckQuotaResponse{})
	require.Equal(t, codes.InvalidArgument, status.Code(err), "err = %v", err)
}

func TestSDKQUIC_TenantSync(t *testing.T) {
	h := newTenantParityHarness(t)
	conn := connectTenantQUIC(t, h, true)

	resp := &platformv1.SyncTenantsResponse{}
	err := conn.Invoke(context.Background(), platformv1.TenantService_Sync_FullMethodName,
		&platformv1.SyncTenantsRequest{}, resp)
	require.NoError(t, err)
	require.True(t, resp.GetStatus().GetSuccess(), resp.GetStatus().GetMessage())
}

func TestSDKQUIC_TenantSyncIsSystemOnly(t *testing.T) {
	h := newTenantParityHarness(t)
	conn := connectTenantQUIC(t, h, false)

	err := conn.Invoke(context.Background(), platformv1.TenantService_Sync_FullMethodName,
		&platformv1.SyncTenantsRequest{}, &platformv1.SyncTenantsResponse{})
	require.Equal(t, codes.PermissionDenied, status.Code(err), "err = %v", err)
}

func TestSDKQUIC_TenantRotateDEKCarriesBackground(t *testing.T) {
	for _, background := range []bool{true, false} {
		h := newTenantParityHarness(t)
		conn := connectTenantQUIC(t, h, true)
		tenantID := h.id(parityTenantA)

		resp := &platformv1.RotateTenantDEKResponse{}
		err := conn.Invoke(context.Background(), platformv1.TenantService_RotateTenantDEK_FullMethodName,
			&platformv1.RotateTenantDEKRequest{TenantId: tenantID, Background: background}, resp)
		require.NoError(t, err, "background=%v", background)
		require.Equal(t, tenantID, resp.GetTenantId())
		require.Equal(t, resp.GetOldVersion()+1, resp.GetNewVersion())
		require.Equal(t, []bool{background}, h.deks.reencryptions(), "background=%v", background)
	}
}

func TestSDKQUIC_TenantRotateDEKUnknownTenant(t *testing.T) {
	h := newTenantParityHarness(t)
	conn := connectTenantQUIC(t, h, true)

	err := conn.Invoke(context.Background(), platformv1.TenantService_RotateTenantDEK_FullMethodName,
		&platformv1.RotateTenantDEKRequest{TenantId: parityGhostTenant}, &platformv1.RotateTenantDEKResponse{})
	require.Equal(t, codes.NotFound, status.Code(err), "err = %v", err)
	require.Empty(t, h.deks.reencryptions())
}

func TestSDKQUIC_TenantRotateDEKRefusesAnotherTenant(t *testing.T) {
	h := newTenantParityHarness(t)
	conn := connectTenantQUIC(t, h, false)

	err := conn.Invoke(context.Background(), platformv1.TenantService_RotateTenantDEK_FullMethodName,
		&platformv1.RotateTenantDEKRequest{TenantId: h.id(parityTenantA), Background: true},
		&platformv1.RotateTenantDEKResponse{})
	require.Equal(t, codes.PermissionDenied, status.Code(err), "err = %v", err)
	require.Empty(t, h.deks.reencryptions())
}

func TestSDKQUIC_TenantGetDEKStatus(t *testing.T) {
	h := newTenantParityHarness(t)
	conn := connectTenantQUIC(t, h, true)
	tenantID := h.id(parityTenantA)

	resp := &platformv1.GetTenantDEKStatusResponse{}
	err := conn.Invoke(context.Background(), platformv1.TenantService_GetTenantDEKStatus_FullMethodName,
		&platformv1.GetTenantDEKStatusRequest{TenantId: tenantID}, resp)
	require.NoError(t, err)
	require.Equal(t, tenantID, resp.GetDekStatus().GetTenantId())
	require.Equal(t, "AES-256-GCM", resp.GetDekStatus().GetAlgorithm())

	err = conn.Invoke(context.Background(), platformv1.TenantService_GetTenantDEKStatus_FullMethodName,
		&platformv1.GetTenantDEKStatusRequest{}, &platformv1.GetTenantDEKStatusResponse{})
	require.Equal(t, codes.InvalidArgument, status.Code(err), "err = %v", err)
}
