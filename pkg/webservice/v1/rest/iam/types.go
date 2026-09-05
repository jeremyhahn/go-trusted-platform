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
	"time"
)

// PaginationParams contains common pagination parameters
type PaginationParams struct {
	Limit  int32 `json:"limit"`
	Offset int32 `json:"offset"`
}

// PaginatedResponse contains common pagination response fields
type PaginatedResponse struct {
	Total  int64 `json:"total"`
	Limit  int32 `json:"limit"`
	Offset int32 `json:"offset"`
}

// CreateUserRequest is the request body for creating a user
type CreateUserRequest struct {
	// Username is the IAM identifier (required by QuicBaaS). The handler
	// derives a sensible default from Email when callers only supply an
	// email so the WebUI's name+email form keeps working.
	Username   string            `json:"username,omitempty"`
	Email      string            `json:"email"`
	Name       string            `json:"name,omitempty"`
	Roles      []string          `json:"roles,omitempty"`
	Groups     []string          `json:"groups,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// UpdateUserRequest is the request body for updating a user
type UpdateUserRequest struct {
	Email      string            `json:"email,omitempty"`
	Name       string            `json:"name,omitempty"`
	Roles      []string          `json:"roles,omitempty"`
	Groups     []string          `json:"groups,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// UserResponse is the response for user operations
type UserResponse struct {
	ID          string            `json:"id"`
	TenantID    string            `json:"tenant_id"`
	Email       string            `json:"email"`
	Name        string            `json:"name,omitempty"`
	Roles       []string          `json:"roles,omitempty"`
	Groups      []string          `json:"groups,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	MFAVerified bool              `json:"mfa_verified"`
	CreatedAt   *time.Time        `json:"created_at,omitempty"`
	UpdatedAt   *time.Time        `json:"updated_at,omitempty"`
	LastAuth    *time.Time        `json:"last_auth,omitempty"`
}

// ListUsersResponse is the response for listing users
type ListUsersResponse struct {
	PaginatedResponse
	Users []UserResponse `json:"users"`
}

// CreateGroupRequest is the request body for creating a group
type CreateGroupRequest struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// UpdateGroupRequest is the request body for updating a group
type UpdateGroupRequest struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// GroupResponse is the response for group operations
type GroupResponse struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"tenant_id"`
	Name        string     `json:"name,omitempty"`
	Description string     `json:"description,omitempty"`
	Members     []string   `json:"members,omitempty"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
}

// ListGroupsResponse is the response for listing groups
type ListGroupsResponse struct {
	PaginatedResponse
	Groups []GroupResponse `json:"groups"`
}

// CreateRoleRequest is the request body for creating a role
type CreateRoleRequest struct {
	ID          string   `json:"id"`
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// UpdateRoleRequest is the request body for updating a role
type UpdateRoleRequest struct {
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// RoleResponse is the response for role operations
type RoleResponse struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"tenant_id"`
	Name        string     `json:"name,omitempty"`
	Description string     `json:"description,omitempty"`
	Permissions []string   `json:"permissions,omitempty"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
}

// ListRolesResponse is the response for listing roles
type ListRolesResponse struct {
	PaginatedResponse
	Roles []RoleResponse `json:"roles"`
}

// TenantSettings contains tenant configuration settings
type TenantSettings struct {
	MaxUsers    int32 `json:"max_users,omitempty"`
	MFARequired bool  `json:"mfa_required"`
}

// CreateTenantRequest is the request body for creating a tenant
type CreateTenantRequest struct {
	ID       string          `json:"id"`
	Name     string          `json:"name,omitempty"`
	Settings *TenantSettings `json:"settings,omitempty"`
}

// UpdateTenantRequest is the request body for updating a tenant
type UpdateTenantRequest struct {
	Name     string          `json:"name,omitempty"`
	Settings *TenantSettings `json:"settings,omitempty"`
}

// TenantResponse is the response for tenant operations
type TenantResponse struct {
	ID        string          `json:"id"`
	Name      string          `json:"name,omitempty"`
	Settings  *TenantSettings `json:"settings,omitempty"`
	CreatedAt *time.Time      `json:"created_at,omitempty"`
	UpdatedAt *time.Time      `json:"updated_at,omitempty"`
}

// ListTenantsResponse is the response for listing tenants
type ListTenantsResponse struct {
	PaginatedResponse
	Tenants []TenantResponse `json:"tenants"`
}

// CreatePolicyRequest is the request body for creating a policy
type CreatePolicyRequest struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Priority    int32             `json:"priority,omitempty"`
	SpecYAML    string            `json:"spec_yaml"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// UpdatePolicyRequest is the request body for updating a policy
type UpdatePolicyRequest struct {
	Description string            `json:"description,omitempty"`
	Priority    int32             `json:"priority,omitempty"`
	SpecYAML    string            `json:"spec_yaml,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// PolicyResponse is the response for policy operations
type PolicyResponse struct {
	Name        string            `json:"name"`
	TenantID    string            `json:"tenant_id"`
	Description string            `json:"description,omitempty"`
	Priority    int32             `json:"priority"`
	SpecYAML    string            `json:"spec_yaml,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	CreatedAt   *time.Time        `json:"created_at,omitempty"`
	UpdatedAt   *time.Time        `json:"updated_at,omitempty"`
}

// ListPoliciesResponse is the response for listing policies
type ListPoliciesResponse struct {
	PaginatedResponse
	Policies []PolicyResponse `json:"policies"`
}

// ValidatePolicyRequest is the request body for validating a policy
type ValidatePolicyRequest struct {
	SpecYAML string `json:"spec_yaml"`
}

// ValidatePolicyResponse is the response for policy validation
type ValidatePolicyResponse struct {
	Valid  bool     `json:"valid"`
	Errors []string `json:"errors,omitempty"`
}

// TestPolicyRequest is the request body for testing a policy
type TestPolicyRequest struct {
	SubjectID  string            `json:"subject_id"`
	Roles      []string          `json:"roles,omitempty"`
	Groups     []string          `json:"groups,omitempty"`
	Action     string            `json:"action"`
	Resource   string            `json:"resource"`
	Context    map[string]string `json:"context,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// TestPolicyResponse is the response for policy testing
type TestPolicyResponse struct {
	Allowed          bool   `json:"allowed"`
	MatchedPolicy    string `json:"matched_policy,omitempty"`
	MatchedRule      string `json:"matched_rule,omitempty"`
	EvaluationTimeNs int64  `json:"evaluation_time_ns"`
}

// RegisterAppRequest is the request body for registering an application.
// Accepts both snake_case (canonical REST) and camelCase (JS SDK) field
// names so the WebUI's `{grantTypes: [...]}` payload reaches the
// downstream SDK.
type RegisterAppRequest struct {
	Name                string   `json:"name"`
	RedirectURIs        []string `json:"redirect_uris,omitempty"`
	RedirectURIsCamel   []string `json:"redirectUris,omitempty"`
	GrantTypes          []string `json:"grant_types,omitempty"`
	GrantTypesCamel     []string `json:"grantTypes,omitempty"`
	ResponseTypes       []string `json:"response_types,omitempty"`
	ResponseTypesCamel  []string `json:"responseTypes,omitempty"`
	ResourcePrefix      string   `json:"resource_prefix,omitempty"`
	ResourcePrefixCamel string   `json:"resourcePrefix,omitempty"`
	TenantID            string   `json:"tenant_id,omitempty"`
	TenantIDCamel       string   `json:"tenantId,omitempty"`
}

// Resolve normalises camelCase aliases into the canonical snake_case
// fields so handler code only needs to read one set.
func (r *RegisterAppRequest) Resolve() {
	if len(r.RedirectURIs) == 0 && len(r.RedirectURIsCamel) > 0 {
		r.RedirectURIs = r.RedirectURIsCamel
	}
	if len(r.GrantTypes) == 0 && len(r.GrantTypesCamel) > 0 {
		r.GrantTypes = r.GrantTypesCamel
	}
	if len(r.ResponseTypes) == 0 && len(r.ResponseTypesCamel) > 0 {
		r.ResponseTypes = r.ResponseTypesCamel
	}
	if r.ResourcePrefix == "" && r.ResourcePrefixCamel != "" {
		r.ResourcePrefix = r.ResourcePrefixCamel
	}
	if r.TenantID == "" && r.TenantIDCamel != "" {
		r.TenantID = r.TenantIDCamel
	}
}

// UpdateAppRequest is the request body for updating an application
type UpdateAppRequest struct {
	Name           string   `json:"name,omitempty"`
	RedirectURIs   []string `json:"redirect_uris,omitempty"`
	GrantTypes     []string `json:"grant_types,omitempty"`
	ResponseTypes  []string `json:"response_types,omitempty"`
	ResourcePrefix string   `json:"resource_prefix,omitempty"`
}

// AppResponse is the response for application operations
type AppResponse struct {
	ClientID       string     `json:"client_id"`
	ClientSecret   string     `json:"client_secret,omitempty" secret:"true"`
	TenantID       string     `json:"tenant_id"`
	Name           string     `json:"name"`
	RedirectURIs   []string   `json:"redirect_uris,omitempty"`
	GrantTypes     []string   `json:"grant_types,omitempty"`
	ResponseTypes  []string   `json:"response_types,omitempty"`
	ResourcePrefix string     `json:"resource_prefix,omitempty"`
	CreatedAt      *time.Time `json:"created_at,omitempty"`
	UpdatedAt      *time.Time `json:"updated_at,omitempty"`
}

// ListAppsResponse is the response for listing applications
type ListAppsResponse struct {
	PaginatedResponse
	Apps []AppResponse `json:"apps"`
}

// RotateSecretResponse is the response for rotating an application secret
type RotateSecretResponse struct {
	ClientID     string `json:"client_id"`
	Name         string `json:"name"`
	ClientSecret string `json:"client_secret" secret:"true"`
}

// SuccessResponse is a generic success response
type SuccessResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// AssignRoleRequest is the request body for assigning a role
type AssignRoleRequest struct {
	Role string `json:"role"`
}

// MembershipRequest is the request body for group membership operations
type MembershipRequest struct {
	UserID string `json:"user_id"`
}
