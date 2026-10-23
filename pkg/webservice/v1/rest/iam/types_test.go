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

package iam

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPaginationParams_ZeroValues(t *testing.T) {
	params := PaginationParams{}
	assert.Equal(t, int32(0), params.Limit)
	assert.Equal(t, int32(0), params.Offset)
}

func TestPaginationParams_WithValues(t *testing.T) {
	params := PaginationParams{
		Limit:  50,
		Offset: 100,
	}
	assert.Equal(t, int32(50), params.Limit)
	assert.Equal(t, int32(100), params.Offset)
}

func TestPaginatedResponse_ZeroValues(t *testing.T) {
	resp := PaginatedResponse{}
	assert.Equal(t, int64(0), resp.Total)
	assert.Equal(t, int32(0), resp.Limit)
	assert.Equal(t, int32(0), resp.Offset)
}

func TestPaginatedResponse_WithValues(t *testing.T) {
	resp := PaginatedResponse{
		Total:  100,
		Limit:  50,
		Offset: 25,
	}
	assert.Equal(t, int64(100), resp.Total)
	assert.Equal(t, int32(50), resp.Limit)
	assert.Equal(t, int32(25), resp.Offset)
}

func TestCreateUserRequest_Fields(t *testing.T) {
	req := CreateUserRequest{
		Email:      "test@example.com",
		Name:       "Test User",
		Roles:      []string{"admin", "viewer"},
		Groups:     []string{"engineering"},
		Attributes: map[string]string{"department": "engineering"},
	}

	assert.Equal(t, "test@example.com", req.Email)
	assert.Equal(t, "Test User", req.Name)
	assert.Equal(t, []string{"admin", "viewer"}, req.Roles)
	assert.Equal(t, []string{"engineering"}, req.Groups)
	assert.Equal(t, "engineering", req.Attributes["department"])
}

func TestCreateUserRequest_EmptyFields(t *testing.T) {
	req := CreateUserRequest{}
	assert.Empty(t, req.Email)
	assert.Empty(t, req.Name)
	assert.Nil(t, req.Roles)
	assert.Nil(t, req.Groups)
	assert.Nil(t, req.Attributes)
}

func TestUpdateUserRequest_Fields(t *testing.T) {
	req := UpdateUserRequest{
		Email:      "updated@example.com",
		Name:       "Updated User",
		Roles:      []string{"admin"},
		Groups:     []string{"developers"},
		Attributes: map[string]string{"level": "senior"},
	}

	assert.Equal(t, "updated@example.com", req.Email)
	assert.Equal(t, "Updated User", req.Name)
	assert.Equal(t, []string{"admin"}, req.Roles)
	assert.Equal(t, []string{"developers"}, req.Groups)
	assert.Equal(t, "senior", req.Attributes["level"])
}

func TestUserResponse_Fields(t *testing.T) {
	now := time.Now()
	resp := UserResponse{
		ID:          "user-123",
		TenantID:    "tenant-456",
		Email:       "user@example.com",
		Name:        "Test User",
		Roles:       []string{"admin"},
		Groups:      []string{"team-a"},
		Attributes:  map[string]string{"dept": "eng"},
		MFAVerified: true,
		CreatedAt:   &now,
		UpdatedAt:   &now,
		LastAuth:    &now,
	}

	assert.Equal(t, "user-123", resp.ID)
	assert.Equal(t, "tenant-456", resp.TenantID)
	assert.Equal(t, "user@example.com", resp.Email)
	assert.Equal(t, "Test User", resp.Name)
	assert.True(t, resp.MFAVerified)
	assert.NotNil(t, resp.CreatedAt)
	assert.NotNil(t, resp.UpdatedAt)
	assert.NotNil(t, resp.LastAuth)
}

func TestUserResponse_NilTimestamps(t *testing.T) {
	resp := UserResponse{
		ID:       "user-123",
		TenantID: "tenant-456",
		Email:    "user@example.com",
	}

	assert.Nil(t, resp.CreatedAt)
	assert.Nil(t, resp.UpdatedAt)
	assert.Nil(t, resp.LastAuth)
}

func TestListUsersResponse_Fields(t *testing.T) {
	resp := ListUsersResponse{
		PaginatedResponse: PaginatedResponse{
			Total:  100,
			Limit:  50,
			Offset: 0,
		},
		Users: []UserResponse{
			{ID: "user-1", Email: "user1@example.com"},
			{ID: "user-2", Email: "user2@example.com"},
		},
	}

	assert.Equal(t, int64(100), resp.Total)
	assert.Equal(t, int32(50), resp.Limit)
	assert.Equal(t, int32(0), resp.Offset)
	assert.Len(t, resp.Users, 2)
}

func TestListUsersResponse_EmptyUsers(t *testing.T) {
	resp := ListUsersResponse{
		PaginatedResponse: PaginatedResponse{
			Total:  0,
			Limit:  50,
			Offset: 0,
		},
		Users: []UserResponse{},
	}

	assert.Equal(t, int64(0), resp.Total)
	assert.Empty(t, resp.Users)
}

func TestCreateGroupRequest_Fields(t *testing.T) {
	req := CreateGroupRequest{
		ID:          "engineering",
		Name:        "Engineering Team",
		Description: "Software engineering department",
	}

	assert.Equal(t, "engineering", req.ID)
	assert.Equal(t, "Engineering Team", req.Name)
	assert.Equal(t, "Software engineering department", req.Description)
}

func TestUpdateGroupRequest_Fields(t *testing.T) {
	req := UpdateGroupRequest{
		Name:        "Updated Team",
		Description: "Updated description",
	}

	assert.Equal(t, "Updated Team", req.Name)
	assert.Equal(t, "Updated description", req.Description)
}

func TestGroupResponse_Fields(t *testing.T) {
	now := time.Now()
	resp := GroupResponse{
		ID:          "group-123",
		TenantID:    "tenant-456",
		Name:        "Engineering",
		Description: "Engineering team",
		Members:     []string{"user-1", "user-2"},
		CreatedAt:   &now,
		UpdatedAt:   &now,
	}

	assert.Equal(t, "group-123", resp.ID)
	assert.Equal(t, "tenant-456", resp.TenantID)
	assert.Len(t, resp.Members, 2)
}

func TestListGroupsResponse_Fields(t *testing.T) {
	resp := ListGroupsResponse{
		PaginatedResponse: PaginatedResponse{
			Total:  10,
			Limit:  50,
			Offset: 0,
		},
		Groups: []GroupResponse{
			{ID: "group-1", Name: "Group 1"},
		},
	}

	assert.Equal(t, int64(10), resp.Total)
	assert.Len(t, resp.Groups, 1)
}

func TestCreateRoleRequest_Fields(t *testing.T) {
	req := CreateRoleRequest{
		ID:          "admin",
		Name:        "Administrator",
		Description: "Full administrative access",
		Permissions: []string{"read", "write", "delete"},
	}

	assert.Equal(t, "admin", req.ID)
	assert.Equal(t, "Administrator", req.Name)
	assert.Len(t, req.Permissions, 3)
}

func TestUpdateRoleRequest_Fields(t *testing.T) {
	req := UpdateRoleRequest{
		Name:        "Updated Role",
		Description: "Updated description",
		Permissions: []string{"read"},
	}

	assert.Equal(t, "Updated Role", req.Name)
	assert.Len(t, req.Permissions, 1)
}

func TestRoleResponse_Fields(t *testing.T) {
	now := time.Now()
	resp := RoleResponse{
		ID:          "admin",
		TenantID:    "tenant-456",
		Name:        "Administrator",
		Description: "Admin role",
		Permissions: []string{"all"},
		CreatedAt:   &now,
		UpdatedAt:   &now,
	}

	assert.Equal(t, "admin", resp.ID)
	assert.Equal(t, "tenant-456", resp.TenantID)
	assert.Len(t, resp.Permissions, 1)
}

func TestListRolesResponse_Fields(t *testing.T) {
	resp := ListRolesResponse{
		PaginatedResponse: PaginatedResponse{
			Total: 5,
		},
		Roles: []RoleResponse{
			{ID: "admin"},
			{ID: "viewer"},
		},
	}

	assert.Equal(t, int64(5), resp.Total)
	assert.Len(t, resp.Roles, 2)
}

func TestTenantSettings_Fields(t *testing.T) {
	settings := TenantSettings{
		MaxUsers:    100,
		MFARequired: true,
	}

	assert.Equal(t, int32(100), settings.MaxUsers)
	assert.True(t, settings.MFARequired)
}

func TestTenantSettings_ZeroValues(t *testing.T) {
	settings := TenantSettings{}
	assert.Equal(t, int32(0), settings.MaxUsers)
	assert.False(t, settings.MFARequired)
}

func TestCreateTenantRequest_Fields(t *testing.T) {
	req := CreateTenantRequest{
		ID:   "acme",
		Name: "Acme Corporation",
		Settings: &TenantSettings{
			MaxUsers:    1000,
			MFARequired: true,
		},
	}

	assert.Equal(t, "acme", req.ID)
	assert.Equal(t, "Acme Corporation", req.Name)
	assert.NotNil(t, req.Settings)
	assert.Equal(t, int32(1000), req.Settings.MaxUsers)
}

func TestCreateTenantRequest_NilSettings(t *testing.T) {
	req := CreateTenantRequest{
		ID:   "acme",
		Name: "Acme Corporation",
	}

	assert.Nil(t, req.Settings)
}

func TestUpdateTenantRequest_Fields(t *testing.T) {
	req := UpdateTenantRequest{
		Name: "Updated Corp",
		Settings: &TenantSettings{
			MaxUsers: 500,
		},
	}

	assert.Equal(t, "Updated Corp", req.Name)
	assert.NotNil(t, req.Settings)
}

func TestTenantResponse_Fields(t *testing.T) {
	now := time.Now()
	resp := TenantResponse{
		ID:   "tenant-123",
		Name: "Test Tenant",
		Settings: &TenantSettings{
			MaxUsers:    100,
			MFARequired: false,
		},
		CreatedAt: &now,
		UpdatedAt: &now,
	}

	assert.Equal(t, "tenant-123", resp.ID)
	assert.Equal(t, "Test Tenant", resp.Name)
	assert.NotNil(t, resp.Settings)
}

func TestListTenantsResponse_Fields(t *testing.T) {
	resp := ListTenantsResponse{
		PaginatedResponse: PaginatedResponse{
			Total: 3,
		},
		Tenants: []TenantResponse{
			{ID: "tenant-1"},
			{ID: "tenant-2"},
		},
	}

	assert.Equal(t, int64(3), resp.Total)
	assert.Len(t, resp.Tenants, 2)
}

func TestCreatePolicyRequest_Fields(t *testing.T) {
	req := CreatePolicyRequest{
		Name:        "admin-policy",
		Description: "Admin access policy",
		Priority:    100,
		SpecYAML:    "rules:\n  - effect: allow",
		Labels:      map[string]string{"env": "production"},
	}

	assert.Equal(t, "admin-policy", req.Name)
	assert.Equal(t, int32(100), req.Priority)
	assert.Contains(t, req.SpecYAML, "rules:")
	assert.Equal(t, "production", req.Labels["env"])
}

func TestUpdatePolicyRequest_Fields(t *testing.T) {
	req := UpdatePolicyRequest{
		Description: "Updated policy",
		Priority:    200,
		SpecYAML:    "rules:\n  - effect: deny",
		Labels:      map[string]string{"version": "2"},
	}

	assert.Equal(t, int32(200), req.Priority)
	assert.Contains(t, req.SpecYAML, "deny")
}

func TestPolicyResponse_Fields(t *testing.T) {
	now := time.Now()
	resp := PolicyResponse{
		Name:        "test-policy",
		TenantID:    "tenant-123",
		Description: "Test policy",
		Priority:    50,
		SpecYAML:    "rules: []",
		Labels:      map[string]string{"test": "true"},
		CreatedAt:   &now,
		UpdatedAt:   &now,
	}

	assert.Equal(t, "test-policy", resp.Name)
	assert.Equal(t, "tenant-123", resp.TenantID)
	assert.Equal(t, int32(50), resp.Priority)
}

func TestListPoliciesResponse_Fields(t *testing.T) {
	resp := ListPoliciesResponse{
		PaginatedResponse: PaginatedResponse{
			Total: 10,
		},
		Policies: []PolicyResponse{
			{Name: "policy-1"},
			{Name: "policy-2"},
		},
	}

	assert.Equal(t, int64(10), resp.Total)
	assert.Len(t, resp.Policies, 2)
}

func TestValidatePolicyRequest_Fields(t *testing.T) {
	req := ValidatePolicyRequest{
		SpecYAML: "rules:\n  - effect: allow\n    actions: ['*']",
	}

	assert.Contains(t, req.SpecYAML, "effect: allow")
}

func TestValidatePolicyRequest_EmptySpec(t *testing.T) {
	req := ValidatePolicyRequest{}
	assert.Empty(t, req.SpecYAML)
}

func TestValidatePolicyResponse_ValidPolicy(t *testing.T) {
	resp := ValidatePolicyResponse{
		Valid:  true,
		Errors: nil,
	}

	assert.True(t, resp.Valid)
	assert.Nil(t, resp.Errors)
}

func TestValidatePolicyResponse_InvalidPolicy(t *testing.T) {
	resp := ValidatePolicyResponse{
		Valid:  false,
		Errors: []string{"missing required field 'rules'", "invalid effect value"},
	}

	assert.False(t, resp.Valid)
	assert.Len(t, resp.Errors, 2)
}

func TestTestPolicyRequest_Fields(t *testing.T) {
	req := TestPolicyRequest{
		SubjectID:  "user-123",
		Roles:      []string{"admin"},
		Groups:     []string{"engineering"},
		Action:     "write",
		Resource:   "documents/*",
		Context:    map[string]string{"ip": "192.168.1.1"},
		Attributes: map[string]string{"department": "engineering"},
	}

	assert.Equal(t, "user-123", req.SubjectID)
	assert.Equal(t, "write", req.Action)
	assert.Equal(t, "documents/*", req.Resource)
	assert.Len(t, req.Roles, 1)
	assert.Len(t, req.Groups, 1)
}

func TestTestPolicyRequest_MinimalFields(t *testing.T) {
	req := TestPolicyRequest{
		SubjectID: "user-123",
		Action:    "read",
		Resource:  "files/doc.txt",
	}

	assert.Equal(t, "user-123", req.SubjectID)
	assert.Nil(t, req.Roles)
	assert.Nil(t, req.Groups)
	assert.Nil(t, req.Context)
	assert.Nil(t, req.Attributes)
}

func TestTestPolicyResponse_Allowed(t *testing.T) {
	resp := TestPolicyResponse{
		Allowed:          true,
		MatchedPolicy:    "admin-policy",
		MatchedRule:      "rule-1",
		EvaluationTimeNs: 1500,
	}

	assert.True(t, resp.Allowed)
	assert.Equal(t, "admin-policy", resp.MatchedPolicy)
	assert.Equal(t, "rule-1", resp.MatchedRule)
	assert.Equal(t, int64(1500), resp.EvaluationTimeNs)
}

func TestTestPolicyResponse_Denied(t *testing.T) {
	resp := TestPolicyResponse{
		Allowed:          false,
		MatchedPolicy:    "",
		MatchedRule:      "",
		EvaluationTimeNs: 500,
	}

	assert.False(t, resp.Allowed)
	assert.Empty(t, resp.MatchedPolicy)
	assert.Empty(t, resp.MatchedRule)
}

func TestRegisterAppRequest_Fields(t *testing.T) {
	req := RegisterAppRequest{
		Name:           "My App",
		RedirectURIs:   []string{"https://app.example.com/callback"},
		GrantTypes:     []string{"authorization_code", "refresh_token"},
		ResponseTypes:  []string{"code"},
		ResourcePrefix: "api",
	}

	assert.Equal(t, "My App", req.Name)
	assert.Len(t, req.RedirectURIs, 1)
	assert.Len(t, req.GrantTypes, 2)
	assert.Len(t, req.ResponseTypes, 1)
	assert.Equal(t, "api", req.ResourcePrefix)
}

func TestRegisterAppRequest_MinimalFields(t *testing.T) {
	req := RegisterAppRequest{
		Name: "Simple App",
	}

	assert.Equal(t, "Simple App", req.Name)
	assert.Nil(t, req.RedirectURIs)
	assert.Nil(t, req.GrantTypes)
}

func TestUpdateAppRequest_Fields(t *testing.T) {
	req := UpdateAppRequest{
		Name:           "Updated App",
		RedirectURIs:   []string{"https://new-url.example.com"},
		GrantTypes:     []string{"client_credentials"},
		ResponseTypes:  []string{"token"},
		ResourcePrefix: "v2",
	}

	assert.Equal(t, "Updated App", req.Name)
	assert.Len(t, req.RedirectURIs, 1)
}

func TestAppResponse_Fields(t *testing.T) {
	now := time.Now()
	resp := AppResponse{
		ClientID:       "client-abc-123",
		ClientSecret:   "secret-xyz",
		TenantID:       "tenant-456",
		Name:           "Test App",
		RedirectURIs:   []string{"https://app.example.com/callback"},
		GrantTypes:     []string{"authorization_code"},
		ResponseTypes:  []string{"code"},
		ResourcePrefix: "api",
		CreatedAt:      &now,
		UpdatedAt:      &now,
	}

	assert.Equal(t, "client-abc-123", resp.ClientID)
	assert.Equal(t, "secret-xyz", resp.ClientSecret)
	assert.Equal(t, "tenant-456", resp.TenantID)
	assert.NotNil(t, resp.CreatedAt)
}

func TestAppResponse_NoSecret(t *testing.T) {
	resp := AppResponse{
		ClientID: "client-abc-123",
		TenantID: "tenant-456",
		Name:     "Test App",
	}

	assert.Empty(t, resp.ClientSecret)
}

func TestListAppsResponse_Fields(t *testing.T) {
	resp := ListAppsResponse{
		PaginatedResponse: PaginatedResponse{
			Total: 5,
		},
		Apps: []AppResponse{
			{ClientID: "app-1", Name: "App 1"},
			{ClientID: "app-2", Name: "App 2"},
		},
	}

	assert.Equal(t, int64(5), resp.Total)
	assert.Len(t, resp.Apps, 2)
}

func TestRotateSecretResponse_Fields(t *testing.T) {
	resp := RotateSecretResponse{
		ClientID:     "client-abc-123",
		Name:         "Test App",
		ClientSecret: "new-secret-xyz",
	}

	assert.Equal(t, "client-abc-123", resp.ClientID)
	assert.Equal(t, "Test App", resp.Name)
	assert.Equal(t, "new-secret-xyz", resp.ClientSecret)
}

func TestSuccessResponse_Success(t *testing.T) {
	resp := SuccessResponse{
		Success: true,
		Message: "Operation completed successfully",
	}

	assert.True(t, resp.Success)
	assert.Equal(t, "Operation completed successfully", resp.Message)
}

func TestSuccessResponse_Failure(t *testing.T) {
	resp := SuccessResponse{
		Success: false,
		Message: "Operation failed",
	}

	assert.False(t, resp.Success)
	assert.Equal(t, "Operation failed", resp.Message)
}

func TestSuccessResponse_EmptyMessage(t *testing.T) {
	resp := SuccessResponse{
		Success: true,
	}

	assert.True(t, resp.Success)
	assert.Empty(t, resp.Message)
}

func TestAssignRoleRequest_Fields(t *testing.T) {
	req := AssignRoleRequest{
		Role: "admin",
	}

	assert.Equal(t, "admin", req.Role)
}

func TestAssignRoleRequest_EmptyRole(t *testing.T) {
	req := AssignRoleRequest{}
	assert.Empty(t, req.Role)
}

func TestMembershipRequest_Fields(t *testing.T) {
	req := MembershipRequest{
		UserID: "user-123",
	}

	assert.Equal(t, "user-123", req.UserID)
}

func TestMembershipRequest_EmptyUserID(t *testing.T) {
	req := MembershipRequest{}
	assert.Empty(t, req.UserID)
}

func TestUserResponse_JSONTags(t *testing.T) {
	// This test ensures the struct has proper JSON tags for serialization
	resp := UserResponse{
		ID:          "id-123",
		TenantID:    "tenant-456",
		Email:       "test@example.com",
		Name:        "Test",
		MFAVerified: true,
	}

	// Verify fields are accessible (compile-time check for struct structure)
	assert.NotEmpty(t, resp.ID)
	assert.NotEmpty(t, resp.TenantID)
	assert.NotEmpty(t, resp.Email)
	assert.NotEmpty(t, resp.Name)
	assert.True(t, resp.MFAVerified)
}

func TestPolicyResponse_EmptyLabels(t *testing.T) {
	resp := PolicyResponse{
		Name:     "policy-1",
		TenantID: "tenant-1",
		Labels:   nil,
	}

	assert.Nil(t, resp.Labels)
}

func TestPolicyResponse_WithLabels(t *testing.T) {
	resp := PolicyResponse{
		Name:     "policy-1",
		TenantID: "tenant-1",
		Labels: map[string]string{
			"env":     "production",
			"version": "1.0",
		},
	}

	assert.Len(t, resp.Labels, 2)
	assert.Equal(t, "production", resp.Labels["env"])
	assert.Equal(t, "1.0", resp.Labels["version"])
}

// TestRegisterAppRequest_Resolve pins the contract RegisterAppRequest
// documents about itself: snake_case is canonical, the camelCase field is an
// alias, and Resolve() normalises the alias into the canonical field.
//
// Every aliased field is covered, not only the one that prompted this test.
// The contract had no coverage at all, which is how TenantID came to be
// declared camelCase-only with no arm in Resolve() (#345) — an omission a
// test over the whole struct would have caught the moment it was written.
func TestRegisterAppRequest_Resolve(t *testing.T) {
	t.Run("camelCase aliases resolve into the canonical fields", func(t *testing.T) {
		req := &RegisterAppRequest{
			Name:                "app",
			RedirectURIsCamel:   []string{"https://example.test/cb"},
			GrantTypesCamel:     []string{"authorization_code"},
			ResponseTypesCamel:  []string{"code"},
			ResourcePrefixCamel: "prefix",
			BodyTenant:          BodyTenant{TenantIDCamel: "tenant-1"},
		}

		req.Resolve()

		assert.Equal(t, []string{"https://example.test/cb"}, req.RedirectURIs)
		assert.Equal(t, []string{"authorization_code"}, req.GrantTypes)
		assert.Equal(t, []string{"code"}, req.ResponseTypes)
		assert.Equal(t, "prefix", req.ResourcePrefix)
		assert.Equal(t, "tenant-1", req.TenantID)
	})

	t.Run("canonical fields win when both spellings are present", func(t *testing.T) {
		req := &RegisterAppRequest{
			RedirectURIs:        []string{"https://canonical.test/cb"},
			RedirectURIsCamel:   []string{"https://alias.test/cb"},
			GrantTypes:          []string{"client_credentials"},
			GrantTypesCamel:     []string{"authorization_code"},
			ResponseTypes:       []string{"token"},
			ResponseTypesCamel:  []string{"code"},
			ResourcePrefix:      "canonical",
			ResourcePrefixCamel: "alias",
			BodyTenant: BodyTenant{
				TenantID:      "canonical-tenant",
				TenantIDCamel: "alias-tenant",
			},
		}

		req.Resolve()

		assert.Equal(t, []string{"https://canonical.test/cb"}, req.RedirectURIs)
		assert.Equal(t, []string{"client_credentials"}, req.GrantTypes)
		assert.Equal(t, []string{"token"}, req.ResponseTypes)
		assert.Equal(t, "canonical", req.ResourcePrefix)
		assert.Equal(t, "canonical-tenant", req.TenantID)
	})

	t.Run("resolve is a no-op when nothing is set", func(t *testing.T) {
		req := &RegisterAppRequest{Name: "app"}

		req.Resolve()

		assert.Empty(t, req.RedirectURIs)
		assert.Empty(t, req.GrantTypes)
		assert.Empty(t, req.ResponseTypes)
		assert.Empty(t, req.ResourcePrefix)
		assert.Empty(t, req.TenantID)
	})
}

// TestRegisterAppRequest_BothSpellingsUnmarshal is the wire-level half: the
// struct tags, not just Resolve(). Before #345 a body sending the canonical
// tenant_id was silently dropped, because tenantId was the only spelling the
// struct declared for that field — while AppResponse returned tenant_id.
func TestRegisterAppRequest_BothSpellingsUnmarshal(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"canonical snake_case", `{"name":"app","tenant_id":"tenant-1","grant_types":["authorization_code"]}`},
		{"camelCase alias", `{"name":"app","tenantId":"tenant-1","grantTypes":["authorization_code"]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var req RegisterAppRequest
			require.NoError(t, json.Unmarshal([]byte(tc.body), &req))

			req.Resolve()

			assert.Equal(t, "tenant-1", req.TenantID,
				"both spellings must reach the same canonical field")
			assert.Equal(t, []string{"authorization_code"}, req.GrantTypes)
		})
	}
}

// TestBodyTenant_NamesOtherThan covers both spellings: a body naming no
// tenant, or only the tenant the route acts on, names no other one; a foreign
// tenant in either spelling does.
func TestBodyTenant_NamesOtherThan(t *testing.T) {
	cases := []struct {
		name string
		body BodyTenant
		want bool
	}{
		{name: "names no tenant", body: BodyTenant{}, want: false},
		{name: "own tenant, snake_case", body: BodyTenant{TenantID: "tenant-a"}, want: false},
		{name: "own tenant, camelCase", body: BodyTenant{TenantIDCamel: "tenant-a"}, want: false},
		{name: "own tenant, both spellings", body: BodyTenant{TenantID: "tenant-a", TenantIDCamel: "tenant-a"}, want: false},
		{name: "foreign tenant, snake_case", body: BodyTenant{TenantID: "tenant-b"}, want: true},
		{name: "foreign tenant, camelCase", body: BodyTenant{TenantIDCamel: "tenant-b"}, want: true},
		{name: "spellings disagree", body: BodyTenant{TenantID: "tenant-a", TenantIDCamel: "tenant-b"}, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.body.namesOtherThan("tenant-a"))
		})
	}
}

// TestBodyTenant_EmbeddedUnmarshal pins the wire half: the embedded fields
// decode with the rest of a request body, in one pass.
func TestBodyTenant_EmbeddedUnmarshal(t *testing.T) {
	var req CreateUserRequest
	require.NoError(t, json.Unmarshal([]byte(`{"email":"u@example.test","tenant_id":"tenant-b"}`), &req))

	assert.Equal(t, "u@example.test", req.Email)
	assert.True(t, req.namesOtherThan("tenant-a"))
}
