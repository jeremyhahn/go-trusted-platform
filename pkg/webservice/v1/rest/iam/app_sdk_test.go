package iam

import (
	"context"
	"net/http"
	"testing"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/transport/embedded"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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
		{"list", tenant, "", ""},
		{"get", tenant, "c1", ""},
		{"update", tenant, "c1", "renamed"},
		{"delete", tenant, "c1", ""},
		{"rotate", tenant, "c1", ""},
	}, calls)
}

// orderedApps is an upstream app client that keeps its apps in order, so
// the production adapter's paging and conversions can be checked.
type orderedApps struct {
	iamsdk.AppClient
	apps       []iamsdk.Application
	registered *iamsdk.RegisterAppRequest
	updated    *iamsdk.UpdateAppRequest
	updates    int
	deleted    []string
	rotated    []string
}

func (o *orderedApps) List(_ context.Context, _ string) (*iamsdk.ListAppsResponse, error) {
	return &iamsdk.ListAppsResponse{Applications: o.apps, TotalCount: len(o.apps)}, nil
}

func (o *orderedApps) Register(_ context.Context, tenantID string, req *iamsdk.RegisterAppRequest) (*iamsdk.Application, error) {
	o.registered = req
	return &iamsdk.Application{
		ClientID: "c-new", TenantID: tenantID, Name: req.Name,
		ResourcePrefix: req.ResourcePrefix, ResponseTypes: req.ResponseTypes,
	}, nil
}

func (o *orderedApps) Update(_ context.Context, tenantID, clientID string, req *iamsdk.UpdateAppRequest) (*iamsdk.Application, error) {
	o.updated = req
	o.updates++
	return &iamsdk.Application{
		ClientID: clientID, TenantID: tenantID, Name: req.Name,
		ResourcePrefix: req.ResourcePrefix, ResponseTypes: req.ResponseTypes,
	}, nil
}

func (o *orderedApps) Get(_ context.Context, _, clientID string) (*iamsdk.Application, error) {
	for i := range o.apps {
		if o.apps[i].ClientID == clientID {
			return &o.apps[i], nil
		}
	}
	return nil, cov964NotFound{Kind: "app", ID: clientID}
}

func (o *orderedApps) RotateSecret(_ context.Context, _, clientID string) (*iamsdk.RotateSecretResponse, error) {
	o.rotated = append(o.rotated, clientID)
	return &iamsdk.RotateSecretResponse{ClientID: clientID, ClientSecret: "s3"}, nil
}

func (o *orderedApps) Delete(_ context.Context, _, clientID string) error {
	o.deleted = append(o.deleted, clientID)
	return nil
}

// orderedAppsClient is the cov964 upstream client with orderedApps as its
// app client.
type orderedAppsClient struct {
	*cov964Client
	apps *orderedApps
}

func (c *orderedAppsClient) App() iamsdk.AppClient { return c.apps }

func TestAppMethodsOverSDKREST_ProductionAdapter(t *testing.T) {
	t.Parallel()
	const tenant = "tenant-a"
	apps := &orderedApps{apps: []iamsdk.Application{
		{ClientID: "c1", TenantID: tenant, Name: "one", ResourcePrefix: "one/", ResponseTypes: []string{"code"}},
		{ClientID: "c2", TenantID: tenant, Name: "two", ResourcePrefix: "two/", ResponseTypes: []string{"code"}},
		{ClientID: "c3", TenantID: tenant, Name: "three", ResourcePrefix: "three/", ResponseTypes: []string{"token"}},
	}}
	adapter := NewQuicBaaSIAMAdapter(&orderedAppsClient{cov964Client: cov964NewClient(), apps: apps})
	conn := sdkRESTConnection(t, adminSessionIAMServer(t, adapter, &mockPEPClient{}))
	client := platformv1.NewPlatformIAMServiceClient(conn)
	ctx := context.Background()

	registered, err := client.RegisterApp(ctx, &platformv1.RegisterIAMAppRequest{
		TenantId: tenant, Name: "docs", ResourcePrefix: "docs/", ResponseTypes: []string{"code"},
	})
	require.NoError(t, err)
	require.NotNil(t, apps.registered)
	assert.Equal(t, "docs/", apps.registered.ResourcePrefix)
	assert.Equal(t, []string{"code"}, apps.registered.ResponseTypes)
	assert.Equal(t, "docs/", registered.GetApp().GetResourcePrefix())
	assert.Equal(t, []string{"code"}, registered.GetApp().GetResponseTypes())

	updated, err := client.UpdateApp(ctx, &platformv1.UpdateIAMAppRequest{
		TenantId: tenant, ClientId: "c1", Name: "docs", ResourcePrefix: "docs/", ResponseTypes: []string{"code"},
	})
	require.NoError(t, err)
	require.NotNil(t, apps.updated)
	assert.Equal(t, "docs/", apps.updated.ResourcePrefix)
	assert.Equal(t, []string{"code"}, apps.updated.ResponseTypes)
	assert.Equal(t, "docs/", updated.GetApp().GetResourcePrefix())
	assert.Equal(t, []string{"code"}, updated.GetApp().GetResponseTypes())

	listed, err := client.ListApps(ctx, &platformv1.ListIAMAppsRequest{
		TenantId:   tenant,
		Pagination: &platformv1.PaginationRequest{Page: 2, PageSize: 2},
	})
	require.NoError(t, err)
	require.Len(t, listed.GetApps(), 1)
	assert.Equal(t, "c3", listed.GetApps()[0].GetClientId())
	assert.Equal(t, "three/", listed.GetApps()[0].GetResourcePrefix())
	assert.Equal(t, []string{"token"}, listed.GetApps()[0].GetResponseTypes())
	assert.Equal(t, int64(3), listed.GetTotal())

	rotated, err := client.RotateAppSecret(ctx, &platformv1.RotateIAMAppSecretRequest{TenantId: tenant, ClientId: "c1"})
	require.NoError(t, err)
	assert.Equal(t, "c1", rotated.GetClientId())
	assert.Equal(t, "one", rotated.GetName())
	assert.Equal(t, "s3", rotated.GetClientSecret())

	_, err = client.DeleteApp(ctx, &platformv1.DeleteIAMAppRequest{TenantId: tenant, ClientId: "c1"})
	require.NoError(t, err)
	assert.Equal(t, []string{"c1"}, apps.deleted)
}

// TestAppMethodsOverSDKREST_ProductionAdapterForeignApp proves the production
// adapter refuses another tenant's app: upstream looks apps up by client ID
// alone, so the adapter checks the fetched app's tenant before it returns,
// updates, deletes or rotates anything (#1957).
func TestAppMethodsOverSDKREST_ProductionAdapterForeignApp(t *testing.T) {
	t.Parallel()
	const tenant = "tenant-a"
	apps := &orderedApps{apps: []iamsdk.Application{
		{ClientID: "x9", TenantID: "tenant-b", Name: "theirs"},
	}}
	adapter := NewQuicBaaSIAMAdapter(&orderedAppsClient{cov964Client: cov964NewClient(), apps: apps})
	conn := sdkRESTConnection(t, adminSessionIAMServer(t, adapter, &mockPEPClient{}))
	client := platformv1.NewPlatformIAMServiceClient(conn)
	ctx := context.Background()

	_, err := client.GetApp(ctx, &platformv1.GetIAMAppRequest{TenantId: tenant, ClientId: "x9"})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err), "get: %v", err)

	_, err = client.UpdateApp(ctx, &platformv1.UpdateIAMAppRequest{TenantId: tenant, ClientId: "x9", Name: "mine"})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err), "update: %v", err)

	_, err = client.DeleteApp(ctx, &platformv1.DeleteIAMAppRequest{TenantId: tenant, ClientId: "x9"})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err), "delete: %v", err)

	_, err = client.RotateAppSecret(ctx, &platformv1.RotateIAMAppSecretRequest{TenantId: tenant, ClientId: "x9"})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err), "rotate: %v", err)

	assert.Empty(t, apps.deleted)
	assert.Empty(t, apps.rotated)
	assert.Zero(t, apps.updates)
}

// unimplementedApps is the pinned go-quicbaas embedded transport as seen
// through the SDK: it dispatches App Register/Get/List/Delete but answers
// an unknown-method error for Update and RotateSecret.
type unimplementedApps struct {
	*orderedApps
}

func (u *unimplementedApps) Register(_ context.Context, tenantID string, req *iamsdk.RegisterAppRequest) (*iamsdk.Application, error) {
	u.registered = req
	return &iamsdk.Application{
		ClientID: "c-new", TenantID: tenantID, Name: req.Name,
		ClientSecret: "s3cret", ResourcePrefix: "tenant-a/apps/", ResponseTypes: req.ResponseTypes,
	}, nil
}

func (u *unimplementedApps) Update(context.Context, string, string, *iamsdk.UpdateAppRequest) (*iamsdk.Application, error) {
	return nil, embedded.NewUnknownMethodError("quicbaas.IAM.App", "Update")
}

func (u *unimplementedApps) RotateSecret(context.Context, string, string) (*iamsdk.RotateSecretResponse, error) {
	return nil, embedded.NewUnknownMethodError("quicbaas.IAM.App", "RotateSecret")
}

type unimplementedAppsClient struct {
	*cov964Client
	apps *unimplementedApps
}

func (c *unimplementedAppsClient) App() iamsdk.AppClient { return c.apps }

func TestAppMethodsOverSDKREST_UnimplementedVerbs(t *testing.T) {
	t.Parallel()
	const tenant = "tenant-a"
	apps := &unimplementedApps{orderedApps: &orderedApps{apps: []iamsdk.Application{
		{ClientID: "c1", TenantID: tenant, Name: "one", ResourcePrefix: "one/", ResponseTypes: []string{"code"}},
	}}}
	adapter := NewQuicBaaSIAMAdapter(&unimplementedAppsClient{cov964Client: cov964NewClient(), apps: apps})
	server := adminSessionIAMServer(t, adapter, &mockPEPClient{})
	client := platformv1.NewPlatformIAMServiceClient(sdkRESTConnection(t, server))
	ctx := context.Background()

	t.Run("UpdateApp", func(t *testing.T) {
		_, err := client.UpdateApp(ctx, &platformv1.UpdateIAMAppRequest{TenantId: tenant, ClientId: "c1", Name: "docs"})
		require.Error(t, err)
		assert.Equal(t, codes.Unimplemented, status.Code(err), "update: %v", err)
	})

	t.Run("RotateAppSecret", func(t *testing.T) {
		_, err := client.RotateAppSecret(ctx, &platformv1.RotateIAMAppSecretRequest{TenantId: tenant, ClientId: "c1"})
		require.Error(t, err)
		assert.Equal(t, codes.Unimplemented, status.Code(err), "rotate: %v", err)
	})

	t.Run("RotateOverHTTPIs501", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			server.URL+"/api/v1/iam/tenants/"+tenant+"/apps/c1/rotate", nil)
		require.NoError(t, err)
		resp, err := server.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNotImplemented, resp.StatusCode)
	})

	t.Run("RegisterKeepsSecretAndPrefix", func(t *testing.T) {
		registered, err := client.RegisterApp(ctx, &platformv1.RegisterIAMAppRequest{
			TenantId: tenant, Name: "docs", ResourcePrefix: "tenant-a/apps/", ResponseTypes: []string{"code"},
		})
		require.NoError(t, err)
		assert.Equal(t, "s3cret", registered.GetApp().GetClientSecret())
		assert.Equal(t, "tenant-a/apps/", registered.GetApp().GetResourcePrefix())
	})
}
