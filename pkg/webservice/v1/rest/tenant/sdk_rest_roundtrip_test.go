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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// connectTenantSDK serves the tenant router over TLS and returns the SDK
// tenant client dialed through the REST transport. The tenant guards are
// passthrough here; they are proven in pkg/webservice/v1/router_authz_test.go.
// This proves the wire: the SDK's route for each item operation is the one
// the router registers, with the tenant in the path.
func connectTenantSDK(t *testing.T, srv platformv1.TenantServiceServer) platformv1.TenantServiceClient {
	t.Helper()

	root := newRouterWithServer(t, srv)
	root.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	server := httptest.NewTLSServer(root)
	t.Cleanup(server.Close)

	tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	adapter, err := sdkrest.Connect(context.Background(),
		platform.NewOptions(platform.WithRESTAddr(server.URL), platform.WithTLSConfig(tlsConfig)))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, adapter.Close()) })

	return platformv1.NewTenantServiceClient(adapter.Connection())
}

// TestSDKREST_TenantItemOperations proves each item operation reaches its own
// handler, which builds the request from the {id} (or {name}) path segment.
// Before #452 the first four sent tenant_id in the body of a path the router
// does not serve, and 404'd. The name lookup, quotas and usage had no REST
// route in the SDK at all (#304), so platformctl tenant show, quotas and
// usage could not run over REST.
func TestSDKREST_TenantItemOperations(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		call func(platformv1.TenantServiceClient) error
		want proto.Message
	}{
		{
			name: "UpdateTenant keeps the fields in the body",
			call: func(c platformv1.TenantServiceClient) error {
				_, err := c.UpdateTenant(ctx, &platformv1.UpdateTenantRequest{
					TenantId:    "acme-prod",
					DisplayName: "Acme Production",
					Labels:      map[string]string{"tier": "gold"},
				})
				return err
			},
			want: &platformv1.UpdateTenantRequest{
				TenantId:    "acme-prod",
				DisplayName: "Acme Production",
				Labels:      map[string]string{"tier": "gold"},
			},
		},
		{
			name: "DeleteTenant",
			call: func(c platformv1.TenantServiceClient) error {
				_, err := c.DeleteTenant(ctx, &platformv1.DeleteTenantRequest{TenantId: "acme-prod"})
				return err
			},
			want: &platformv1.DeleteTenantRequest{TenantId: "acme-prod"},
		},
		{
			name: "SuspendTenant",
			call: func(c platformv1.TenantServiceClient) error {
				_, err := c.SuspendTenant(ctx, &platformv1.SuspendTenantRequest{TenantId: "acme-prod"})
				return err
			},
			want: &platformv1.SuspendTenantRequest{TenantId: "acme-prod"},
		},
		{
			name: "ResumeTenant",
			call: func(c platformv1.TenantServiceClient) error {
				_, err := c.ResumeTenant(ctx, &platformv1.ResumeTenantRequest{TenantId: "acme-prod"})
				return err
			},
			want: &platformv1.ResumeTenantRequest{TenantId: "acme-prod"},
		},
		{
			name: "GetTenantByName takes the name from the path",
			call: func(c platformv1.TenantServiceClient) error {
				_, err := c.GetTenantByName(ctx, &platformv1.GetTenantByNameRequest{Name: "acme"})
				return err
			},
			want: &platformv1.GetTenantByNameRequest{Name: "acme"},
		},
		{
			name: "GetQuotas",
			call: func(c platformv1.TenantServiceClient) error {
				_, err := c.GetQuotas(ctx, &platformv1.GetQuotasRequest{TenantId: "acme-prod"})
				return err
			},
			want: &platformv1.GetQuotasRequest{TenantId: "acme-prod"},
		},
		{
			name: "UpdateQuotas keeps the limits in the body",
			call: func(c platformv1.TenantServiceClient) error {
				_, err := c.UpdateQuotas(ctx, &platformv1.UpdateQuotasRequest{
					TenantId: "acme-prod",
					Compute:  &platformv1.ComputeQuota{MaxVms: 12, MaxVcpus: 48},
				})
				return err
			},
			want: &platformv1.UpdateQuotasRequest{
				TenantId: "acme-prod",
				Compute:  &platformv1.ComputeQuota{MaxVms: 12, MaxVcpus: 48},
			},
		},
		{
			name: "GetUsage",
			call: func(c platformv1.TenantServiceClient) error {
				_, err := c.GetUsage(ctx, &platformv1.GetUsageRequest{TenantId: "acme-prod"})
				return err
			},
			want: &platformv1.GetUsageRequest{TenantId: "acme-prod"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := &fakeTenantServer{}
			client := connectTenantSDK(t, srv)

			require.NoError(t, tc.call(client))

			require.NotNil(t, srv.last, "the request reached no handler")
			assert.True(t, proto.Equal(tc.want, srv.last),
				"handler received %T %v, want %T %v", srv.last, srv.last, tc.want, tc.want)
		})
	}
}

// TestSDKREST_SuspendTenant_EmptyTenantNeverLeavesTheClient: the tenant is a
// path segment, so an empty one cannot be sent; the SDK refuses it the way
// gRPC refuses a missing required field, and no handler runs.
func TestSDKREST_SuspendTenant_EmptyTenantNeverLeavesTheClient(t *testing.T) {
	srv := &fakeTenantServer{}
	client := connectTenantSDK(t, srv)

	_, err := client.SuspendTenant(context.Background(), &platformv1.SuspendTenantRequest{})

	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Nil(t, srv.last, "a request with no tenant reached a handler")
}

// TestSDKREST_SuspendTenant_ServerErrorKeepsItsStatus: a NotFound from the
// server comes back to the SDK caller as NotFound, not as a transport error.
func TestSDKREST_SuspendTenant_ServerErrorKeepsItsStatus(t *testing.T) {
	srv := &fakeTenantServer{err: status.Error(codes.NotFound, "tenant not found")}
	client := connectTenantSDK(t, srv)

	_, err := client.SuspendTenant(context.Background(), &platformv1.SuspendTenantRequest{TenantId: "ghost"})

	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.True(t, proto.Equal(&platformv1.SuspendTenantRequest{TenantId: "ghost"}, srv.last))
}

// answeringTenantServer answers the name lookup, quotas and usage with
// populated responses, so a test can see the REST response reach the SDK
// caller field for field.
type answeringTenantServer struct {
	fakeTenantServer
}

func (a *answeringTenantServer) GetTenantByName(_ context.Context, r *platformv1.GetTenantByNameRequest) (*platformv1.GetTenantByNameResponse, error) {
	return &platformv1.GetTenantByNameResponse{
		Tenant: &platformv1.Tenant{Id: "8f2c", Name: r.GetName(), DisplayName: "Acme"},
	}, a.reply(r)
}

func (a *answeringTenantServer) GetQuotas(_ context.Context, r *platformv1.GetQuotasRequest) (*platformv1.GetQuotasResponse, error) {
	return &platformv1.GetQuotasResponse{
		TenantId: r.GetTenantId(),
		Compute:  &platformv1.ComputeQuota{MaxVms: 12, MaxMemoryMb: 65536},
	}, a.reply(r)
}

func (a *answeringTenantServer) GetUsage(_ context.Context, r *platformv1.GetUsageRequest) (*platformv1.GetUsageResponse, error) {
	return &platformv1.GetUsageResponse{
		Usage: &platformv1.TenantUsage{TenantId: r.GetTenantId(), Vms: 3, DiskGb: 40},
	}, a.reply(r)
}

func (a *answeringTenantServer) CheckQuota(_ context.Context, r *platformv1.CheckQuotaRequest) (*platformv1.CheckQuotaResponse, error) {
	return &platformv1.CheckQuotaResponse{
		TenantId: r.GetTenantId(), Resource: r.GetResource(), Amount: r.GetAmount(),
		Available: false, Message: "vms quota exhausted",
	}, a.reply(r)
}

func (a *answeringTenantServer) Sync(_ context.Context, r *platformv1.SyncTenantsRequest) (*platformv1.SyncTenantsResponse, error) {
	return &platformv1.SyncTenantsResponse{Status: &platformv1.Status{Success: true, Message: "synced"}}, a.reply(r)
}

func (a *answeringTenantServer) RotateTenantDEK(_ context.Context, r *platformv1.RotateTenantDEKRequest) (*platformv1.RotateTenantDEKResponse, error) {
	return &platformv1.RotateTenantDEKResponse{TenantId: r.GetTenantId(), OldVersion: 2, NewVersion: 3}, a.reply(r)
}

func (a *answeringTenantServer) GetTenantDEKStatus(_ context.Context, r *platformv1.GetTenantDEKStatusRequest) (*platformv1.GetTenantDEKStatusResponse, error) {
	return &platformv1.GetTenantDEKStatusResponse{
		DekStatus: &platformv1.TenantDEKStatus{TenantId: r.GetTenantId(), Version: 3, Algorithm: "AES-256-GCM", NeedsRotation: true},
	}, a.reply(r)
}

// TestSDKREST_TenantLookupQuotasUsage_ResponsesReachTheCaller: the response
// the server builds comes back through the REST transport unchanged, as it
// does over gRPC, QUIC and MCP.
func TestSDKREST_TenantLookupQuotasUsage_ResponsesReachTheCaller(t *testing.T) {
	ctx := context.Background()
	client := connectTenantSDK(t, &answeringTenantServer{})

	byName, err := client.GetTenantByName(ctx, &platformv1.GetTenantByNameRequest{Name: "acme"})
	require.NoError(t, err)
	assert.True(t, proto.Equal(&platformv1.Tenant{Id: "8f2c", Name: "acme", DisplayName: "Acme"}, byName.GetTenant()),
		"tenant = %v", byName.GetTenant())

	quotas, err := client.GetQuotas(ctx, &platformv1.GetQuotasRequest{TenantId: "8f2c"})
	require.NoError(t, err)
	assert.Equal(t, "8f2c", quotas.GetTenantId())
	assert.True(t, proto.Equal(&platformv1.ComputeQuota{MaxVms: 12, MaxMemoryMb: 65536}, quotas.GetCompute()),
		"compute = %v", quotas.GetCompute())

	usage, err := client.GetUsage(ctx, &platformv1.GetUsageRequest{TenantId: "8f2c"})
	require.NoError(t, err)
	assert.True(t, proto.Equal(&platformv1.TenantUsage{TenantId: "8f2c", Vms: 3, DiskGb: 40}, usage.GetUsage()),
		"usage = %v", usage.GetUsage())
}

// TestSDKREST_TenantLookupQuotasUsage_ServerErrorKeepsItsStatus: a refusal or
// a missing tenant reaches the SDK caller with the gRPC code the server gave,
// so platformctl reports it the same way on every transport.
func TestSDKREST_TenantLookupQuotasUsage_ServerErrorKeepsItsStatus(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		code codes.Code
		call func(platformv1.TenantServiceClient) error
	}{
		{"GetTenantByName", codes.PermissionDenied, func(c platformv1.TenantServiceClient) error {
			_, err := c.GetTenantByName(ctx, &platformv1.GetTenantByNameRequest{Name: "other"})
			return err
		}},
		{"GetQuotas", codes.NotFound, func(c platformv1.TenantServiceClient) error {
			_, err := c.GetQuotas(ctx, &platformv1.GetQuotasRequest{TenantId: "ghost"})
			return err
		}},
		{"UpdateQuotas", codes.InvalidArgument, func(c platformv1.TenantServiceClient) error {
			_, err := c.UpdateQuotas(ctx, &platformv1.UpdateQuotasRequest{
				TenantId: "acme-prod",
				Compute:  &platformv1.ComputeQuota{MaxVms: -1},
			})
			return err
		}},
		{"GetUsage", codes.NotFound, func(c platformv1.TenantServiceClient) error {
			_, err := c.GetUsage(ctx, &platformv1.GetUsageRequest{TenantId: "ghost"})
			return err
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := &fakeTenantServer{err: status.Error(tc.code, "refused")}
			client := connectTenantSDK(t, srv)

			err := tc.call(client)

			require.Error(t, err)
			assert.Equal(t, tc.code, status.Code(err))
			assert.NotNil(t, srv.last, "the request reached no handler")
		})
	}
}

// TestSDKREST_GetTenantByName_EmptyNameNeverLeavesTheClient: the name is a
// path segment, so an empty one is refused in the SDK and no handler runs.
func TestSDKREST_GetTenantByName_EmptyNameNeverLeavesTheClient(t *testing.T) {
	srv := &fakeTenantServer{}
	client := connectTenantSDK(t, srv)

	_, err := client.GetTenantByName(context.Background(), &platformv1.GetTenantByNameRequest{})

	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Nil(t, srv.last, "a request with no name reached a handler")
}

// TestSDKREST_QuotaCheckSyncDEK_RequestReachesTheServer drives the quota
// check, sync and DEK methods through the SDK REST transport: each lands on
// its route with the tenant from the path and the rest of the request (the
// prospective allocation, the background flag) from the body.
func TestSDKREST_QuotaCheckSyncDEK_RequestReachesTheServer(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		call func(platformv1.TenantServiceClient) error
		want proto.Message
	}{
		{
			name: "CheckQuota keeps the allocation in the body",
			call: func(c platformv1.TenantServiceClient) error {
				_, err := c.CheckQuota(ctx, &platformv1.CheckQuotaRequest{TenantId: "acme-prod", Resource: "vms", Amount: 4})
				return err
			},
			want: &platformv1.CheckQuotaRequest{TenantId: "acme-prod", Resource: "vms", Amount: 4},
		},
		{
			name: "Sync",
			call: func(c platformv1.TenantServiceClient) error {
				_, err := c.Sync(ctx, &platformv1.SyncTenantsRequest{})
				return err
			},
			want: &platformv1.SyncTenantsRequest{},
		},
		{
			name: "RotateTenantDEK in the background",
			call: func(c platformv1.TenantServiceClient) error {
				_, err := c.RotateTenantDEK(ctx, &platformv1.RotateTenantDEKRequest{TenantId: "acme-prod", Background: true})
				return err
			},
			want: &platformv1.RotateTenantDEKRequest{TenantId: "acme-prod", Background: true},
		},
		{
			name: "RotateTenantDEK in the foreground",
			call: func(c platformv1.TenantServiceClient) error {
				_, err := c.RotateTenantDEK(ctx, &platformv1.RotateTenantDEKRequest{TenantId: "acme-prod"})
				return err
			},
			want: &platformv1.RotateTenantDEKRequest{TenantId: "acme-prod"},
		},
		{
			name: "GetTenantDEKStatus",
			call: func(c platformv1.TenantServiceClient) error {
				_, err := c.GetTenantDEKStatus(ctx, &platformv1.GetTenantDEKStatusRequest{TenantId: "acme-prod"})
				return err
			},
			want: &platformv1.GetTenantDEKStatusRequest{TenantId: "acme-prod"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := &fakeTenantServer{}
			client := connectTenantSDK(t, srv)

			require.NoError(t, tc.call(client))

			require.NotNil(t, srv.last, "the request reached no handler")
			assert.True(t, proto.Equal(tc.want, srv.last),
				"handler received %T %v, want %T %v", srv.last, srv.last, tc.want, tc.want)
		})
	}
}

// TestSDKREST_QuotaCheckSyncDEK_ResponsesReachTheCaller proves each response,
// including an in-band "not available" quota answer, reaches the SDK caller.
func TestSDKREST_QuotaCheckSyncDEK_ResponsesReachTheCaller(t *testing.T) {
	ctx := context.Background()
	client := connectTenantSDK(t, &answeringTenantServer{})

	check, err := client.CheckQuota(ctx, &platformv1.CheckQuotaRequest{TenantId: "8f2c", Resource: "vms", Amount: 4})
	require.NoError(t, err)
	assert.True(t, proto.Equal(&platformv1.CheckQuotaResponse{
		TenantId: "8f2c", Resource: "vms", Amount: 4, Available: false, Message: "vms quota exhausted",
	}, check), "check = %v", check)

	synced, err := client.Sync(ctx, &platformv1.SyncTenantsRequest{})
	require.NoError(t, err)
	assert.True(t, synced.GetStatus().GetSuccess(), "status = %v", synced.GetStatus())

	rotated, err := client.RotateTenantDEK(ctx, &platformv1.RotateTenantDEKRequest{TenantId: "8f2c"})
	require.NoError(t, err)
	assert.Equal(t, "8f2c", rotated.GetTenantId())
	assert.Equal(t, uint32(3), rotated.GetNewVersion())

	dek, err := client.GetTenantDEKStatus(ctx, &platformv1.GetTenantDEKStatusRequest{TenantId: "8f2c"})
	require.NoError(t, err)
	assert.True(t, proto.Equal(&platformv1.TenantDEKStatus{
		TenantId: "8f2c", Version: 3, Algorithm: "AES-256-GCM", NeedsRotation: true,
	}, dek.GetDekStatus()), "dek = %v", dek.GetDekStatus())
}

// TestSDKREST_QuotaCheckSyncDEK_ServerErrorKeepsItsStatus proves a server
// error on each route reaches the caller with its gRPC code.
func TestSDKREST_QuotaCheckSyncDEK_ServerErrorKeepsItsStatus(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		code codes.Code
		call func(platformv1.TenantServiceClient) error
	}{
		{"CheckQuota", codes.InvalidArgument, func(c platformv1.TenantServiceClient) error {
			_, err := c.CheckQuota(ctx, &platformv1.CheckQuotaRequest{TenantId: "acme-prod", Resource: "warp-drives", Amount: 1})
			return err
		}},
		{"Sync", codes.PermissionDenied, func(c platformv1.TenantServiceClient) error {
			_, err := c.Sync(ctx, &platformv1.SyncTenantsRequest{})
			return err
		}},
		{"RotateTenantDEK", codes.Unavailable, func(c platformv1.TenantServiceClient) error {
			_, err := c.RotateTenantDEK(ctx, &platformv1.RotateTenantDEKRequest{TenantId: "acme-prod", Background: true})
			return err
		}},
		{"GetTenantDEKStatus", codes.NotFound, func(c platformv1.TenantServiceClient) error {
			_, err := c.GetTenantDEKStatus(ctx, &platformv1.GetTenantDEKStatusRequest{TenantId: "ghost"})
			return err
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := &fakeTenantServer{err: status.Error(tc.code, "refused")}
			client := connectTenantSDK(t, srv)

			err := tc.call(client)

			require.Error(t, err)
			assert.Equal(t, tc.code, status.Code(err))
			assert.NotNil(t, srv.last, "the request reached no handler")
		})
	}
}

// TestSDKREST_TenantDEK_EmptyTenantNeverLeavesTheClient proves the SDK refuses
// a DEK or quota-check call with no tenant before it builds a path.
func TestSDKREST_TenantDEK_EmptyTenantNeverLeavesTheClient(t *testing.T) {
	ctx := context.Background()
	srv := &fakeTenantServer{}
	client := connectTenantSDK(t, srv)

	_, err := client.RotateTenantDEK(ctx, &platformv1.RotateTenantDEKRequest{Background: true})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	_, err = client.CheckQuota(ctx, &platformv1.CheckQuotaRequest{Resource: "vms", Amount: 1})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	assert.Nil(t, srv.last, "a request with no tenant must not reach a handler")
}
