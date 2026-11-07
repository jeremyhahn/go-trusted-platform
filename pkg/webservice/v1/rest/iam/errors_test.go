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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrMissingTenantID_Error(t *testing.T) {
	t.Parallel()
	err := ErrMissingTenantID{}
	assert.Equal(t, "tenant ID is required", err.Error())
}

func TestErrMissingTenantID_ImplementsErrorInterface(t *testing.T) {
	t.Parallel()
	var err error = ErrMissingTenantID{}
	assert.NotNil(t, err)
	assert.Equal(t, "tenant ID is required", err.Error())
}

func TestErrMissingUserID_Error(t *testing.T) {
	t.Parallel()
	err := ErrMissingUserID{}
	assert.Equal(t, "user ID is required", err.Error())
}

func TestErrMissingUserID_ImplementsErrorInterface(t *testing.T) {
	t.Parallel()
	var err error = ErrMissingUserID{}
	assert.NotNil(t, err)
	assert.Equal(t, "user ID is required", err.Error())
}

func TestErrMissingGroupID_Error(t *testing.T) {
	t.Parallel()
	err := ErrMissingGroupID{}
	assert.Equal(t, "group ID is required", err.Error())
}

func TestErrMissingGroupID_ImplementsErrorInterface(t *testing.T) {
	t.Parallel()
	var err error = ErrMissingGroupID{}
	assert.NotNil(t, err)
	assert.Equal(t, "group ID is required", err.Error())
}

func TestErrMissingRoleID_Error(t *testing.T) {
	t.Parallel()
	err := ErrMissingRoleID{}
	assert.Equal(t, "role ID is required", err.Error())
}

func TestErrMissingRoleID_ImplementsErrorInterface(t *testing.T) {
	t.Parallel()
	var err error = ErrMissingRoleID{}
	assert.NotNil(t, err)
	assert.Equal(t, "role ID is required", err.Error())
}

func TestErrMissingPolicyID_Error(t *testing.T) {
	t.Parallel()
	err := ErrMissingPolicyID{}
	assert.Equal(t, "policy ID is required", err.Error())
}

func TestErrMissingPolicyID_ImplementsErrorInterface(t *testing.T) {
	t.Parallel()
	var err error = ErrMissingPolicyID{}
	assert.NotNil(t, err)
	assert.Equal(t, "policy ID is required", err.Error())
}

func TestErrMissingAppID_Error(t *testing.T) {
	t.Parallel()
	err := ErrMissingAppID{}
	assert.Equal(t, "app ID is required", err.Error())
}

func TestErrMissingAppID_ImplementsErrorInterface(t *testing.T) {
	t.Parallel()
	var err error = ErrMissingAppID{}
	assert.NotNil(t, err)
	assert.Equal(t, "app ID is required", err.Error())
}

func TestErrInvalidRequestBody_Error(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		reason   string
		expected string
	}{
		{
			name:     "with simple reason",
			reason:   "missing email field",
			expected: "invalid request body: missing email field",
		},
		{
			name:     "with empty reason",
			reason:   "",
			expected: "invalid request body: ",
		},
		{
			name:     "with JSON parse error",
			reason:   "unexpected end of JSON input",
			expected: "invalid request body: unexpected end of JSON input",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrInvalidRequestBody{Reason: tt.reason}
			assert.Equal(t, tt.expected, err.Error())
		})
	}
}

func TestErrInvalidRequestBody_ImplementsErrorInterface(t *testing.T) {
	t.Parallel()
	var err error = ErrInvalidRequestBody{Reason: "test reason"}
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid request body")
}

func TestErrInvalidPaginationParams_Error(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		reason   string
		expected string
	}{
		{
			name:     "negative limit",
			reason:   "limit must be positive",
			expected: "invalid pagination parameters: limit must be positive",
		},
		{
			name:     "offset too large",
			reason:   "offset exceeds maximum",
			expected: "invalid pagination parameters: offset exceeds maximum",
		},
		{
			name:     "empty reason",
			reason:   "",
			expected: "invalid pagination parameters: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrInvalidPaginationParams{Reason: tt.reason}
			assert.Equal(t, tt.expected, err.Error())
		})
	}
}

func TestErrInvalidPaginationParams_ImplementsErrorInterface(t *testing.T) {
	t.Parallel()
	var err error = ErrInvalidPaginationParams{Reason: "test"}
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid pagination parameters")
}

func TestErrUserNotFound_Error(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		tenantID string
		userID   string
		expected string
	}{
		{
			name:     "with both IDs",
			tenantID: "tenant-123",
			userID:   "user-456",
			expected: "user not found: tenant=tenant-123, user=user-456",
		},
		{
			name:     "with empty tenant ID",
			tenantID: "",
			userID:   "user-456",
			expected: "user not found: tenant=, user=user-456",
		},
		{
			name:     "with empty user ID",
			tenantID: "tenant-123",
			userID:   "",
			expected: "user not found: tenant=tenant-123, user=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrUserNotFound{TenantID: tt.tenantID, UserID: tt.userID}
			assert.Equal(t, tt.expected, err.Error())
		})
	}
}

func TestErrUserNotFound_ImplementsErrorInterface(t *testing.T) {
	t.Parallel()
	var err error = ErrUserNotFound{TenantID: "t1", UserID: "u1"}
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "user not found")
}

func TestErrGroupNotFound_Error(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		tenantID string
		groupID  string
		expected string
	}{
		{
			name:     "with both IDs",
			tenantID: "tenant-123",
			groupID:  "group-456",
			expected: "group not found: tenant=tenant-123, group=group-456",
		},
		{
			name:     "with empty tenant ID",
			tenantID: "",
			groupID:  "group-456",
			expected: "group not found: tenant=, group=group-456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrGroupNotFound{TenantID: tt.tenantID, GroupID: tt.groupID}
			assert.Equal(t, tt.expected, err.Error())
		})
	}
}

func TestErrGroupNotFound_ImplementsErrorInterface(t *testing.T) {
	t.Parallel()
	var err error = ErrGroupNotFound{TenantID: "t1", GroupID: "g1"}
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "group not found")
}

func TestErrRoleNotFound_Error(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		tenantID string
		roleID   string
		expected string
	}{
		{
			name:     "with both IDs",
			tenantID: "tenant-123",
			roleID:   "admin",
			expected: "role not found: tenant=tenant-123, role=admin",
		},
		{
			name:     "with empty role ID",
			tenantID: "tenant-123",
			roleID:   "",
			expected: "role not found: tenant=tenant-123, role=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrRoleNotFound{TenantID: tt.tenantID, RoleID: tt.roleID}
			assert.Equal(t, tt.expected, err.Error())
		})
	}
}

func TestErrRoleNotFound_ImplementsErrorInterface(t *testing.T) {
	t.Parallel()
	var err error = ErrRoleNotFound{TenantID: "t1", RoleID: "r1"}
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "role not found")
}

func TestErrTenantNotFound_Error(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		tenantID string
		expected string
	}{
		{
			name:     "with tenant ID",
			tenantID: "tenant-123",
			expected: "tenant not found: tenant-123",
		},
		{
			name:     "with empty tenant ID",
			tenantID: "",
			expected: "tenant not found: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrTenantNotFound{TenantID: tt.tenantID}
			assert.Equal(t, tt.expected, err.Error())
		})
	}
}

func TestErrTenantNotFound_ImplementsErrorInterface(t *testing.T) {
	t.Parallel()
	var err error = ErrTenantNotFound{TenantID: "t1"}
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "tenant not found")
}

func TestErrPolicyNotFound_Error(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		tenantID string
		policyID string
		expected string
	}{
		{
			name:     "with both IDs",
			tenantID: "tenant-123",
			policyID: "admin-policy",
			expected: "policy not found: tenant=tenant-123, policy=admin-policy",
		},
		{
			name:     "with empty policy ID",
			tenantID: "tenant-123",
			policyID: "",
			expected: "policy not found: tenant=tenant-123, policy=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrPolicyNotFound{TenantID: tt.tenantID, PolicyID: tt.policyID}
			assert.Equal(t, tt.expected, err.Error())
		})
	}
}

func TestErrPolicyNotFound_ImplementsErrorInterface(t *testing.T) {
	t.Parallel()
	var err error = ErrPolicyNotFound{TenantID: "t1", PolicyID: "p1"}
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "policy not found")
}

func TestErrAppNotFound_Error(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		tenantID string
		appID    string
		expected string
	}{
		{
			name:     "with both IDs",
			tenantID: "tenant-123",
			appID:    "client-abc",
			expected: "application not found: tenant=tenant-123, app=client-abc",
		},
		{
			name:     "with empty app ID",
			tenantID: "tenant-123",
			appID:    "",
			expected: "application not found: tenant=tenant-123, app=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrAppNotFound{TenantID: tt.tenantID, AppID: tt.appID}
			assert.Equal(t, tt.expected, err.Error())
		})
	}
}

func TestErrAppNotFound_ImplementsErrorInterface(t *testing.T) {
	t.Parallel()
	var err error = ErrAppNotFound{TenantID: "t1", AppID: "a1"}
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "application not found")
}

func TestErrInvalidPolicySpec_Error(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		reason   string
		expected string
	}{
		{
			name:     "with syntax error",
			reason:   "invalid YAML syntax at line 5",
			expected: "invalid policy spec: invalid YAML syntax at line 5",
		},
		{
			name:     "with missing field",
			reason:   "missing required field 'rules'",
			expected: "invalid policy spec: missing required field 'rules'",
		},
		{
			name:     "with empty reason",
			reason:   "",
			expected: "invalid policy spec: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrInvalidPolicySpec{Reason: tt.reason}
			assert.Equal(t, tt.expected, err.Error())
		})
	}
}

func TestErrInvalidPolicySpec_ImplementsErrorInterface(t *testing.T) {
	t.Parallel()
	var err error = ErrInvalidPolicySpec{Reason: "test"}
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid policy spec")
}

func TestErrMissingRole_Error(t *testing.T) {
	t.Parallel()
	err := ErrMissingRole{}
	assert.Equal(t, "role is required", err.Error())
}

func TestErrMissingRole_ImplementsErrorInterface(t *testing.T) {
	t.Parallel()
	var err error = ErrMissingRole{}
	assert.NotNil(t, err)
	assert.Equal(t, "role is required", err.Error())
}

func TestErrMissingMember_Error(t *testing.T) {
	t.Parallel()
	err := ErrMissingMember{}
	assert.Equal(t, "member ID is required", err.Error())
}

func TestErrMissingMember_ImplementsErrorInterface(t *testing.T) {
	t.Parallel()
	var err error = ErrMissingMember{}
	assert.NotNil(t, err)
	assert.Equal(t, "member ID is required", err.Error())
}

func TestErrConflictingQueryTenant_Error(t *testing.T) {
	t.Parallel()
	err := ErrConflictingQueryTenant{Path: "tenant-a", Query: "tenant-b"}
	assert.Equal(t, `rest/iam: tenant_id query "tenant-b" conflicts with path tenant "tenant-a"`, err.Error())
}

func TestErrConflictingQueryTenant_ImplementsErrorInterface(t *testing.T) {
	t.Parallel()
	var err error = ErrConflictingQueryTenant{Path: "tenant-a", Query: "tenant-b"}
	var conflict ErrConflictingQueryTenant
	assert.ErrorAs(t, err, &conflict)
	assert.Equal(t, "tenant-b", conflict.Query)
}

func TestAllErrorTypesAreDistinct(t *testing.T) {
	t.Parallel()
	errors := []error{
		ErrMissingTenantID{},
		ErrMissingUserID{},
		ErrMissingGroupID{},
		ErrMissingRoleID{},
		ErrMissingPolicyID{},
		ErrMissingAppID{},
		ErrInvalidRequestBody{Reason: "test"},
		ErrInvalidPaginationParams{Reason: "test"},
		ErrUserNotFound{TenantID: "t", UserID: "u"},
		ErrGroupNotFound{TenantID: "t", GroupID: "g"},
		ErrRoleNotFound{TenantID: "t", RoleID: "r"},
		ErrTenantNotFound{TenantID: "t"},
		ErrPolicyNotFound{TenantID: "t", PolicyID: "p"},
		ErrAppNotFound{TenantID: "t", AppID: "a"},
		ErrInvalidPolicySpec{Reason: "test"},
		ErrMissingRole{},
		ErrMissingMember{},
	}

	errorMessages := make(map[string]bool)
	for _, err := range errors {
		msg := err.Error()
		if errorMessages[msg] {
			t.Errorf("Duplicate error message found: %s", msg)
		}
		errorMessages[msg] = true
	}
}
