package iam

import (
	"context"
	"testing"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestAppMethodsOverSDKREST_RoundTrip drives the six IAM app methods through
// the SDK's REST transport against the real router: each reaches its
// tenant-scoped app route with the tenant and client id in the path, and
// each reply decodes into its proto response (#1957).
func TestAppMethodsOverSDKREST_RoundTrip(t *testing.T) {
	t.Parallel()
	// The admin session of adminSessionIAMServer holds tenant-a.
	const tenant = "tenant-a"
	type call struct{ op, tenant, client, name string }
	var calls []call
	var listLimit, listOffset int32
	iamClient := &mockIAMClient{
		registerAppFn: func(_ context.Context, tenantID string, req *iamsdk.RegisterAppRequest) (*iamsdk.Application, error) {
			calls = append(calls, call{"register", tenantID, "", req.Name})
			return &iamsdk.Application{ClientID: "c1", TenantID: tenantID, Name: req.Name}, nil
		},
		listAppsFn: func(_ context.Context, tenantID string, limit, offset int32) (*ListAppsResponse, error) {
			calls = append(calls, call{"list", tenantID, "", ""})
			listLimit, listOffset = limit, offset
			return &ListAppsResponse{
				PaginatedResponse: PaginatedResponse{Total: 1},
				Apps:              []AppResponse{{ClientID: "c1", TenantID: tenantID, Name: "app"}},
			}, nil
		},
		getAppFn: func(_ context.Context, tenantID, clientID string) (*iamsdk.Application, error) {
			calls = append(calls, call{"get", tenantID, clientID, ""})
			return &iamsdk.Application{ClientID: clientID, TenantID: tenantID, Name: "app"}, nil
		},
		updateAppFn: func(_ context.Context, tenantID, clientID string, req *iamsdk.UpdateAppRequest) (*iamsdk.Application, error) {
			calls = append(calls, call{"update", tenantID, clientID, req.Name})
			return &iamsdk.Application{ClientID: clientID, TenantID: tenantID, Name: req.Name}, nil
		},
		deleteAppFn: func(_ context.Context, tenantID, clientID string) error {
			calls = append(calls, call{"delete", tenantID, clientID, ""})
			return nil
		},
		rotateAppSecretFn: func(_ context.Context, tenantID, clientID string) (*RotateSecretResponse, error) {
			calls = append(calls, call{"rotate", tenantID, clientID, ""})
			return &RotateSecretResponse{ClientID: clientID, Name: "app", ClientSecret: "s3"}, nil
		},
	}
	conn := sdkRESTConnection(t, adminSessionIAMServer(t, iamClient, &mockPEPClient{}))
	client := platformv1.NewPlatformIAMServiceClient(conn)
	ctx := context.Background()

	registered, err := client.RegisterApp(ctx, &platformv1.RegisterIAMAppRequest{TenantId: tenant, Name: "app"})
	require.NoError(t, err)
	assert.Equal(t, "c1", registered.GetApp().GetClientId())
	assert.Equal(t, "app", registered.GetApp().GetName())

	listed, err := client.ListApps(ctx, &platformv1.ListIAMAppsRequest{TenantId: tenant})
	require.NoError(t, err)
	require.Len(t, listed.GetApps(), 1)
	assert.Equal(t, "c1", listed.GetApps()[0].GetClientId())
	assert.Equal(t, int64(1), listed.GetTotal())

	// A non-default page reaches the backend as limit and offset.
	_, err = client.ListApps(ctx, &platformv1.ListIAMAppsRequest{
		TenantId:   tenant,
		Pagination: &platformv1.PaginationRequest{Page: 2, PageSize: 7},
	})
	require.NoError(t, err)
	assert.Equal(t, int32(7), listLimit)
	assert.Equal(t, int32(7), listOffset)

	got, err := client.GetApp(ctx, &platformv1.GetIAMAppRequest{TenantId: tenant, ClientId: "c1"})
	require.NoError(t, err)
	assert.Equal(t, "c1", got.GetApp().GetClientId())
	assert.Equal(t, tenant, got.GetApp().GetTenantId())

	updated, err := client.UpdateApp(ctx, &platformv1.UpdateIAMAppRequest{TenantId: tenant, ClientId: "c1", Name: "renamed"})
	require.NoError(t, err)
	assert.Equal(t, "c1", updated.GetApp().GetClientId())
	assert.Equal(t, "renamed", updated.GetApp().GetName())

	deleted, err := client.DeleteApp(ctx, &platformv1.DeleteIAMAppRequest{TenantId: tenant, ClientId: "c1"})
	require.NoError(t, err)
	assert.True(t, deleted.GetStatus().GetSuccess())

	rotated, err := client.RotateAppSecret(ctx, &platformv1.RotateIAMAppSecretRequest{TenantId: tenant, ClientId: "c1"})
	require.NoError(t, err)
	assert.Equal(t, "c1", rotated.GetClientId())
	assert.Equal(t, "app", rotated.GetName())

	assert.Equal(t, []call{
		{"register", tenant, "", "app"},
		{"list", tenant, "", ""},
		{"get", tenant, "c1", ""},
		{"update", tenant, "c1", "renamed"},
		{"delete", tenant, "c1", ""},
		{"rotate", tenant, "c1", ""},
	}, calls)
}
