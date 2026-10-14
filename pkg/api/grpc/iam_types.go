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

package grpc

import "context"

// IAMService defines the interface for IAM operations.
// This interface is implemented by IAM service providers and used by the gRPC service.
// Note: Password-based authentication has been removed for zero password attack surface.
// Authentication is handled via certificates, tokens, and other passwordless mechanisms.
type IAMService interface {
	// User operations
	CreateUser(ctx context.Context, req *IAMCreateUserRequest) (*IAMUserResponse, error)
	GetUser(ctx context.Context, req *IAMGetUserRequest) (*IAMUserResponse, error)
	ListUsers(ctx context.Context, req *IAMListRequest) (*IAMListUsersResponse, error)
	UpdateUser(ctx context.Context, req *IAMUpdateUserRequest) (*IAMUserResponse, error)
	DeleteUser(ctx context.Context, req *IAMDeleteUserRequest) error

	// Role operations
	CreateRole(ctx context.Context, req *IAMCreateRoleRequest) (*IAMRoleResponse, error)
	GetRole(ctx context.Context, req *IAMGetRoleRequest) (*IAMRoleResponse, error)
	ListRoles(ctx context.Context, req *IAMListRequest) (*IAMListRolesResponse, error)
	UpdateRole(ctx context.Context, req *IAMUpdateRoleRequest) (*IAMRoleResponse, error)
	DeleteRole(ctx context.Context, req *IAMDeleteRoleRequest) error
	AssignRoleToUser(ctx context.Context, req *IAMRoleAssignmentRequest) error
	RevokeRoleFromUser(ctx context.Context, req *IAMRoleAssignmentRequest) error

	// Policy operations
	CreatePolicy(ctx context.Context, req *IAMCreatePolicyRequest) (*IAMPolicyResponse, error)
	GetPolicy(ctx context.Context, req *IAMGetPolicyRequest) (*IAMPolicyResponse, error)
	ListPolicies(ctx context.Context, req *IAMListRequest) (*IAMListPoliciesResponse, error)
	UpdatePolicy(ctx context.Context, req *IAMUpdatePolicyRequest) (*IAMPolicyResponse, error)
	DeletePolicy(ctx context.Context, req *IAMDeletePolicyRequest) error

	// Authorization operations (passwordless)
	CheckPermission(ctx context.Context, req *IAMCheckPermissionRequest) (*IAMCheckPermissionResponse, error)
}

// =============================================================================
// User Request/Response Types
// =============================================================================

// IAMCreateUserRequest represents a request to create a user.
type IAMCreateUserRequest struct {
	TenantID   string
	Email      string
	Name       string
	Attributes map[string]string
}

// IAMGetUserRequest represents a request to get a user.
type IAMGetUserRequest struct {
	TenantID string
	UserID   string
}

// IAMListRequest represents a paginated list request.
type IAMListRequest struct {
	TenantID string
	Limit    int
	Offset   int
}

// IAMUserResponse represents a user response.
type IAMUserResponse struct {
	ID         string
	TenantID   string
	Email      string
	Name       string
	Roles      []string
	Attributes map[string]string
	CreatedAt  int64
	UpdatedAt  int64
}

// IAMListUsersResponse represents a list of users response.
type IAMListUsersResponse struct {
	Users []*IAMUserResponse
	Total int
}

// IAMUpdateUserRequest represents a request to update a user.
type IAMUpdateUserRequest struct {
	TenantID   string
	UserID     string
	Email      string
	Name       string
	Roles      []string
	Attributes map[string]string
}

// IAMDeleteUserRequest represents a request to delete a user.
type IAMDeleteUserRequest struct {
	TenantID string
	UserID   string
}

// =============================================================================
// Role Request/Response Types
// =============================================================================

// IAMCreateRoleRequest represents a request to create a role.
type IAMCreateRoleRequest struct {
	TenantID    string
	RoleID      string
	Name        string
	Description string
	Permissions []string
}

// IAMGetRoleRequest represents a request to get a role.
type IAMGetRoleRequest struct {
	TenantID string
	RoleID   string
}

// IAMRoleResponse represents a role response.
type IAMRoleResponse struct {
	ID          string
	TenantID    string
	Name        string
	Description string
	Permissions []string
	CreatedAt   int64
	UpdatedAt   int64
}

// IAMListRolesResponse represents a list of roles response.
type IAMListRolesResponse struct {
	Roles []*IAMRoleResponse
	Total int
}

// IAMUpdateRoleRequest represents a request to update a role.
type IAMUpdateRoleRequest struct {
	TenantID    string
	RoleID      string
	Name        string
	Description string
	Permissions []string
}

// IAMDeleteRoleRequest represents a request to delete a role.
type IAMDeleteRoleRequest struct {
	TenantID string
	RoleID   string
}

// IAMRoleAssignmentRequest represents a request to assign/revoke a role.
type IAMRoleAssignmentRequest struct {
	TenantID string
	UserID   string
	RoleID   string
}

// =============================================================================
// Policy Request/Response Types
// =============================================================================

// IAMCreatePolicyRequest represents a request to create a policy.
type IAMCreatePolicyRequest struct {
	TenantID    string
	PolicyID    string
	Name        string
	Description string
	Document    string
	Version     string
}

// IAMGetPolicyRequest represents a request to get a policy.
type IAMGetPolicyRequest struct {
	TenantID string
	PolicyID string
}

// IAMPolicyResponse represents a policy response.
type IAMPolicyResponse struct {
	ID          string
	TenantID    string
	Name        string
	Description string
	Document    string
	Version     string
	CreatedAt   int64
	UpdatedAt   int64
}

// IAMListPoliciesResponse represents a list of policies response.
type IAMListPoliciesResponse struct {
	Policies []*IAMPolicyResponse
	Total    int
}

// IAMUpdatePolicyRequest represents a request to update a policy.
type IAMUpdatePolicyRequest struct {
	TenantID    string
	PolicyID    string
	Name        string
	Description string
	Document    string
	Version     string
}

// IAMDeletePolicyRequest represents a request to delete a policy.
type IAMDeletePolicyRequest struct {
	TenantID string
	PolicyID string
}

// =============================================================================
// Authorization Request/Response Types (Passwordless)
// =============================================================================

// IAMCheckPermissionRequest represents a permission check request.
type IAMCheckPermissionRequest struct {
	TenantID  string
	SubjectID string
	Resource  string
	Action    string
	Context   map[string]string
}

// IAMCheckPermissionResponse represents a permission check response.
type IAMCheckPermissionResponse struct {
	Allowed bool
	Reason  string
}

// =============================================================================
// IAM Error Types
// =============================================================================

// ErrIAMServiceNil is returned when the IAM service is nil.
type ErrIAMServiceNil struct{}

func (e ErrIAMServiceNil) Error() string {
	return "IAM service is nil"
}

// ErrIAMTenantIDRequired is returned when tenant ID is required.
type ErrIAMTenantIDRequired struct{}

func (e ErrIAMTenantIDRequired) Error() string {
	return "tenant ID is required"
}

// ErrIAMUserIDRequired is returned when user ID is required.
type ErrIAMUserIDRequired struct{}

func (e ErrIAMUserIDRequired) Error() string {
	return "user ID is required"
}

// ErrIAMEmailRequired is returned when email is required.
type ErrIAMEmailRequired struct{}

func (e ErrIAMEmailRequired) Error() string {
	return "email is required"
}

// ErrIAMRoleIDRequired is returned when role ID is required.
type ErrIAMRoleIDRequired struct{}

func (e ErrIAMRoleIDRequired) Error() string {
	return "role ID is required"
}

// ErrIAMNameRequired is returned when name is required.
type ErrIAMNameRequired struct{}

func (e ErrIAMNameRequired) Error() string {
	return "name is required"
}

// ErrIAMTokenRequired is returned when token is required.
type ErrIAMTokenRequired struct{}

func (e ErrIAMTokenRequired) Error() string {
	return "token is required"
}

// ErrIAMSubjectIDRequired is returned when subject ID is required.
type ErrIAMSubjectIDRequired struct{}

func (e ErrIAMSubjectIDRequired) Error() string {
	return "subject ID is required"
}

// ErrIAMResourceRequired is returned when resource is required.
type ErrIAMResourceRequired struct{}

func (e ErrIAMResourceRequired) Error() string {
	return "resource is required"
}

// ErrIAMActionRequired is returned when action is required.
type ErrIAMActionRequired struct{}

func (e ErrIAMActionRequired) Error() string {
	return "action is required"
}
