package iam

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
)

var (
	protoCreated = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	protoUpdated = time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
)

func TestUserToProto_Nil(t *testing.T) {
	assert.Nil(t, UserToProto(nil))
}

func TestUserToProto_Populated(t *testing.T) {
	lastLogin := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	got := UserToProto(&iamsdk.User{
		ID: "user-1", TenantID: "tenant-a", Email: "a@example.com", DisplayName: "Alice",
		Roles: []string{"writer"}, Groups: []string{"docs"},
		Metadata:    map[string]string{"team": "core"},
		AuthMethods: []string{"webauthn"},
		LastLoginAt: &lastLogin, CreatedAt: protoCreated, UpdatedAt: protoUpdated,
	})

	require.NotNil(t, got)
	assert.Equal(t, "user-1", got.GetId())
	assert.Equal(t, "tenant-a", got.GetTenantId())
	assert.Equal(t, "a@example.com", got.GetEmail())
	assert.Equal(t, "Alice", got.GetName())
	assert.Equal(t, []string{"writer"}, got.GetRoles())
	assert.Equal(t, []string{"docs"}, got.GetGroups())
	assert.Equal(t, map[string]string{"team": "core"}, got.GetAttributes())
	assert.True(t, got.GetMfaVerified())
	assert.Equal(t, lastLogin, got.GetLastAuth().AsTime())
	assert.Equal(t, protoCreated, got.GetCreatedAt().AsTime())
	assert.Equal(t, protoUpdated, got.GetUpdatedAt().AsTime())
}

func TestUserToProto_NoLoginNoAuthMethods(t *testing.T) {
	got := UserToProto(&iamsdk.User{ID: "user-1"})

	require.NotNil(t, got)
	assert.Nil(t, got.GetLastAuth())
	assert.False(t, got.GetMfaVerified())
}

func TestRoleToProto_Nil(t *testing.T) {
	assert.Nil(t, RoleToProto(nil))
}

func TestRoleToProto_Populated(t *testing.T) {
	got := RoleToProto(&iamsdk.Role{
		ID: "writer", TenantID: "tenant-a", Name: "Writer", Description: "writes",
		Permissions: []string{"docs:write"}, CreatedAt: protoCreated, UpdatedAt: protoUpdated,
	})

	require.NotNil(t, got)
	assert.Equal(t, "writer", got.GetId())
	assert.Equal(t, "tenant-a", got.GetTenantId())
	assert.Equal(t, "Writer", got.GetName())
	assert.Equal(t, "writes", got.GetDescription())
	assert.Equal(t, []string{"docs:write"}, got.GetPermissions())
	assert.Equal(t, protoCreated, got.GetCreatedAt().AsTime())
	assert.Equal(t, protoUpdated, got.GetUpdatedAt().AsTime())
}

func TestGroupToProto_Nil(t *testing.T) {
	assert.Nil(t, GroupToProto(nil))
}

func TestGroupToProto_Populated(t *testing.T) {
	got := GroupToProto(&iamsdk.Group{
		ID: "docs", TenantID: "tenant-a", Name: "Docs", Description: "doc writers",
		CreatedAt: protoCreated, UpdatedAt: protoUpdated,
	})

	require.NotNil(t, got)
	assert.Equal(t, "docs", got.GetId())
	assert.Equal(t, "tenant-a", got.GetTenantId())
	assert.Equal(t, "Docs", got.GetName())
	assert.Equal(t, "doc writers", got.GetDescription())
	assert.Equal(t, protoCreated, got.GetCreatedAt().AsTime())
	assert.Equal(t, protoUpdated, got.GetUpdatedAt().AsTime())
}

func TestTenantToProto_Nil(t *testing.T) {
	assert.Nil(t, TenantToProto(nil))
}

func TestTenantToProto_Populated(t *testing.T) {
	got := TenantToProto(&iamsdk.Tenant{
		ID: "tenant-a", Name: "Tenant A",
		Settings:  map[string]string{"mfa_required": "true"},
		CreatedAt: protoCreated, UpdatedAt: protoUpdated,
	})

	require.NotNil(t, got)
	assert.Equal(t, "tenant-a", got.GetId())
	assert.Equal(t, "Tenant A", got.GetName())
	assert.True(t, got.GetSettings().GetMfaRequired())
	assert.Equal(t, protoCreated, got.GetCreatedAt().AsTime())
	assert.Equal(t, protoUpdated, got.GetUpdatedAt().AsTime())
}

func TestTenantToProto_NoSettings(t *testing.T) {
	got := TenantToProto(&iamsdk.Tenant{ID: "tenant-a"})

	require.NotNil(t, got)
	assert.Nil(t, got.GetSettings())
}

func TestPolicyToProto_Nil(t *testing.T) {
	assert.Nil(t, PolicyToProto(nil))
}

func TestPolicyToProto_Populated(t *testing.T) {
	got := PolicyToProto(&iamsdk.Policy{
		Name: "allow-docs", TenantID: "tenant-a", Description: "docs access", Priority: 7,
		SpecYAML: []byte("rules: []"), Labels: map[string]string{"env": "dev"},
		CreatedAt: protoCreated, UpdatedAt: protoUpdated,
	})

	require.NotNil(t, got)
	assert.Equal(t, "allow-docs", got.GetName())
	assert.Equal(t, "tenant-a", got.GetTenantId())
	assert.Equal(t, "docs access", got.GetDescription())
	assert.Equal(t, int32(7), got.GetPriority())
	assert.Equal(t, []byte("rules: []"), got.GetSpecYaml())
	assert.Equal(t, map[string]string{"env": "dev"}, got.GetLabels())
	assert.Equal(t, protoCreated, got.GetCreatedAt().AsTime())
	assert.Equal(t, protoUpdated, got.GetUpdatedAt().AsTime())
}

func TestAppToProto_Nil(t *testing.T) {
	assert.Nil(t, AppToProto(nil))
}

func TestAppToProto_Populated(t *testing.T) {
	got := AppToProto(&iamsdk.Application{
		ClientID: "client-1", ClientSecret: "s3cret", TenantID: "tenant-a", Name: "Portal",
		RedirectURIs:  []string{"https://portal.example/cb"},
		GrantTypes:    []iamsdk.GrantType{iamsdk.GrantTypeAuthorizationCode},
		ResponseTypes: []string{"code"},
		CreatedAt:     protoCreated, UpdatedAt: protoUpdated,
	})

	require.NotNil(t, got)
	assert.Equal(t, "client-1", got.GetClientId())
	assert.Equal(t, "s3cret", got.GetClientSecret())
	assert.Equal(t, "tenant-a", got.GetTenantId())
	assert.Equal(t, "Portal", got.GetName())
	assert.Equal(t, []string{"https://portal.example/cb"}, got.GetRedirectUris())
	assert.Equal(t, []string{iamsdk.GrantTypeAuthorizationCode.String()}, got.GetGrantTypes())
	assert.Equal(t, []string{"code"}, got.GetResponseTypes())
	assert.Equal(t, protoCreated, got.GetCreatedAt().AsTime())
	assert.Equal(t, protoUpdated, got.GetUpdatedAt().AsTime())
}

func TestTenantResponseToProto_Populated(t *testing.T) {
	got := tenantResponseToProto(&TenantResponse{
		ID: "tenant-a", Name: "Tenant A",
		Settings:  &TenantSettings{MaxUsers: 10, MFARequired: true},
		CreatedAt: &protoCreated, UpdatedAt: &protoUpdated,
	})

	assert.Equal(t, "tenant-a", got.GetId())
	assert.Equal(t, "Tenant A", got.GetName())
	assert.Equal(t, int32(10), got.GetSettings().GetMaxUsers())
	assert.True(t, got.GetSettings().GetMfaRequired())
	assert.Equal(t, protoCreated, got.GetCreatedAt().AsTime())
	assert.Equal(t, protoUpdated, got.GetUpdatedAt().AsTime())
}

func TestTenantResponseToProto_NoSettingsNoTimes(t *testing.T) {
	got := tenantResponseToProto(&TenantResponse{ID: "tenant-a"})

	assert.Nil(t, got.GetSettings())
	assert.Nil(t, got.GetCreatedAt())
	assert.Nil(t, got.GetUpdatedAt())
}

func TestPolicyResponseToProto_Populated(t *testing.T) {
	got := policyResponseToProto(&PolicyResponse{
		Name: "allow-docs", TenantID: "tenant-a", Description: "docs access", Priority: 7,
		SpecYAML: "rules: []", Labels: map[string]string{"env": "dev"},
		CreatedAt: &protoCreated, UpdatedAt: &protoUpdated,
	})

	assert.Equal(t, "allow-docs", got.GetName())
	assert.Equal(t, "tenant-a", got.GetTenantId())
	assert.Equal(t, "docs access", got.GetDescription())
	assert.Equal(t, int32(7), got.GetPriority())
	assert.Equal(t, []byte("rules: []"), got.GetSpecYaml())
	assert.Equal(t, map[string]string{"env": "dev"}, got.GetLabels())
	assert.Equal(t, protoCreated, got.GetCreatedAt().AsTime())
	assert.Equal(t, protoUpdated, got.GetUpdatedAt().AsTime())
}

func TestPolicyResponseToProto_NoTimes(t *testing.T) {
	got := policyResponseToProto(&PolicyResponse{Name: "allow-docs"})

	assert.Nil(t, got.GetCreatedAt())
	assert.Nil(t, got.GetUpdatedAt())
}

func TestAppResponseToProto_Populated(t *testing.T) {
	got := appResponseToProto(&AppResponse{
		ClientID: "client-1", ClientSecret: "s3cret", TenantID: "tenant-a", Name: "Portal",
		RedirectURIs: []string{"https://portal.example/cb"}, GrantTypes: []string{"authorization_code"},
		ResponseTypes: []string{"code"}, ResourcePrefix: "portal/",
		CreatedAt: &protoCreated, UpdatedAt: &protoUpdated,
	})

	assert.Equal(t, "client-1", got.GetClientId())
	assert.Equal(t, "s3cret", got.GetClientSecret())
	assert.Equal(t, "tenant-a", got.GetTenantId())
	assert.Equal(t, "Portal", got.GetName())
	assert.Equal(t, []string{"https://portal.example/cb"}, got.GetRedirectUris())
	assert.Equal(t, []string{"authorization_code"}, got.GetGrantTypes())
	assert.Equal(t, []string{"code"}, got.GetResponseTypes())
	assert.Equal(t, "portal/", got.GetResourcePrefix())
	assert.Equal(t, protoCreated, got.GetCreatedAt().AsTime())
	assert.Equal(t, protoUpdated, got.GetUpdatedAt().AsTime())
}

func TestAppResponseToProto_NoTimes(t *testing.T) {
	got := appResponseToProto(&AppResponse{ClientID: "client-1"})

	assert.Nil(t, got.GetCreatedAt())
	assert.Nil(t, got.GetUpdatedAt())
}

func TestListPagination(t *testing.T) {
	tests := []struct {
		name                                   string
		limit, offset                          int32
		total                                  int64
		wantPage, wantPageSize, wantTotalPages uint32
		wantTotalItems                         uint64
	}{
		{name: "first page", limit: 10, offset: 0, total: 25, wantPage: 1, wantPageSize: 10, wantTotalPages: 3, wantTotalItems: 25},
		{name: "middle page", limit: 10, offset: 10, total: 25, wantPage: 2, wantPageSize: 10, wantTotalPages: 3, wantTotalItems: 25},
		{name: "exact last page", limit: 5, offset: 15, total: 20, wantPage: 4, wantPageSize: 5, wantTotalPages: 4, wantTotalItems: 20},
		{name: "offset past the end", limit: 10, offset: 100, total: 25, wantPage: 11, wantPageSize: 10, wantTotalPages: 3, wantTotalItems: 25},
		{name: "empty list", limit: 50, offset: 0, total: 0, wantPage: 1, wantPageSize: 50, wantTotalPages: 0, wantTotalItems: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ListPagination(tc.limit, tc.offset, tc.total)

			assert.Equal(t, tc.wantPage, got.GetPage())
			assert.Equal(t, tc.wantPageSize, got.GetPageSize())
			assert.Equal(t, tc.wantTotalPages, got.GetTotalPages())
			assert.Equal(t, tc.wantTotalItems, got.GetTotalItems())
		})
	}
}

// TestListPagination_ZeroPageSize pins that a zero page size reports page 1
// of no pages instead of dividing by zero.
func TestListPagination_ZeroPageSize(t *testing.T) {
	got := ListPagination(0, 20, 25)

	require.NotNil(t, got)
	assert.Equal(t, uint32(1), got.GetPage())
	assert.Zero(t, got.GetPageSize())
	assert.Zero(t, got.GetTotalPages())
	assert.Equal(t, uint64(25), got.GetTotalItems())
}
