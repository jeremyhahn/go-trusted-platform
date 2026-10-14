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
	root.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
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

// TestSDKREST_TenantItemOperations proves each of the four item operations
// #452 repointed reaches its own handler, which builds the request from the
// {id} path segment. Before #452 each sent tenant_id in the body of a path
// the router does not serve, and 404'd.
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
