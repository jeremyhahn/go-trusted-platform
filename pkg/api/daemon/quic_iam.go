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

// This file implements IAM (Identity and Access Management) operations for the
// QUIC protocol transport layer. QUIC provides low-latency, multiplexed streams
// with built-in TLS 1.3, making it ideal for mobile and high-performance clients.
//
// The QUIC IAM handlers delegate to the QUICIAMService interface, which abstracts
// the underlying IAM implementation (typically QuicBaaS IAM). All requests and
// responses use MessagePack encoding via codec tags for efficient binary serialization.
//
// # Supported Operations
//
// User management:
//   - OpIAMUserCreate: Create a new user in a tenant
//   - OpIAMUserDelete: Delete an existing user
//   - OpIAMUserGet: Retrieve user details by ID
//   - OpIAMUserList: List users with pagination
//   - OpIAMUserUpdate: Update user attributes
//
// Role management:
//   - OpIAMRoleCreate: Create a new role with permissions
//   - OpIAMRoleDelete: Delete a role
//   - OpIAMRoleGet: Retrieve role details
//   - OpIAMRoleList: List roles with pagination
//   - OpIAMRoleAssign: Assign a role to a user
//   - OpIAMRoleRevoke: Revoke a role from a user
//
// Group management:
//   - OpIAMGroupCreate: Create a new group
//   - OpIAMGroupDelete: Delete a group
//   - OpIAMGroupGet: Retrieve group details
//   - OpIAMGroupList: List groups with pagination
//   - OpIAMGroupAddMember: Add a user to a group
//   - OpIAMGroupRemoveMember: Remove a user from a group
//
// Authorization:
//   - OpIAMCheckPermission: Check if a subject has permission for an action
//
// Authentication:
//   - OpIAMAuthenticate: Authenticate a user with credentials
//
// Token Management:
//   - OpIAMTokenCreate: Create access and refresh tokens
//   - OpIAMTokenRevoke: Revoke a token
//   - OpIAMTokenVerify: Verify token validity
//
// # Error Handling
//
// All operations return typed errors using the ErrQUIC* error types defined in
// errors.go. Common error responses include:
//   - StatusInvalidRequest: Payload decoding failed
//   - StatusInvalidArgument: Required field missing
//   - StatusNotFound: Requested entity not found
//   - StatusInternalError: Operation failed
//   - StatusUnauthorized: Authentication failed
//   - StatusUnavailable: IAM service not configured

package daemon

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
)

// QUICIAMService defines the interface for IAM operations over QUIC transport.
// This interface abstracts the underlying IAM implementation (e.g., QuicBaaS IAM),
// enabling the QUIC handler to remain decoupled from specific IAM backends.
//
// All methods accept a context.Context for cancellation and deadline propagation.
// The tenantID parameter provides multi-tenant isolation for all operations.
//
// Implementations should handle:
//   - Input validation
//   - Authorization checks
//   - Audit logging
//   - Error wrapping with appropriate context
type QUICIAMService interface {
	// User operations

	// CreateUser creates a new user within the specified tenant.
	// The opts parameter contains user attributes including email, username, and name.
	// Returns the created user with generated ID and timestamps.
	CreateUser(ctx context.Context, tenantID string, opts CreateUserRequest) (*IAMUserResponse, error)

	// DeleteUser permanently removes a user from the tenant.
	// This operation cascades to remove user's role assignments and group memberships.
	DeleteUser(ctx context.Context, tenantID, userID string) error

	// GetUser retrieves a user by their unique identifier within a tenant.
	// Returns ErrNotFound if the user does not exist.
	GetUser(ctx context.Context, tenantID, userID string) (*IAMUserResponse, error)

	// ListUsers returns a paginated list of users within a tenant.
	// The opts parameter controls pagination, sorting, and filtering.
	ListUsers(ctx context.Context, tenantID string, opts ListIAMRequest) (*IAMUserListResponse, error)

	// UpdateUser modifies an existing user's attributes.
	// Only non-empty fields in opts are updated; empty fields are ignored.
	UpdateUser(ctx context.Context, tenantID, userID string, opts UpdateUserRequest) (*IAMUserResponse, error)

	// Role operations

	// CreateRole creates a new role with the specified permissions.
	// Roles are tenant-scoped and can be assigned to users.
	CreateRole(ctx context.Context, tenantID string, opts CreateRoleRequest) (*IAMRoleResponse, error)

	// DeleteRole removes a role from the tenant.
	// Users with this role assigned will lose the associated permissions.
	DeleteRole(ctx context.Context, tenantID, roleID string) error

	// GetRole retrieves a role by its unique identifier.
	// Returns the role with its associated permissions.
	GetRole(ctx context.Context, tenantID, roleID string) (*IAMRoleResponse, error)

	// ListRoles returns a paginated list of roles within a tenant.
	ListRoles(ctx context.Context, tenantID string, opts ListIAMRequest) (*IAMRoleListResponse, error)

	// UpdateRole modifies an existing role's name, description, or permissions.
	UpdateRole(ctx context.Context, tenantID, roleID string, opts UpdateRoleRequest) (*IAMRoleResponse, error)

	// AssignRoleToUser grants a role to a user, giving them the role's permissions.
	// If the user already has the role, this operation is idempotent.
	AssignRoleToUser(ctx context.Context, tenantID, userID, roleID string) error

	// RevokeRoleFromUser removes a role from a user.
	// The user loses all permissions associated with the revoked role.
	RevokeRoleFromUser(ctx context.Context, tenantID, userID, roleID string) error

	// Group operations

	// CreateGroup creates a new group within the tenant.
	// Groups provide a way to organize users and apply policies collectively.
	CreateGroup(ctx context.Context, tenantID string, opts CreateGroupRequest) (*IAMGroupResponse, error)

	// DeleteGroup removes a group from the tenant.
	// Members are not deleted but lose their group membership.
	DeleteGroup(ctx context.Context, tenantID, groupID string) error

	// GetGroup retrieves a group by its unique identifier.
	// Returns the group with its member list.
	GetGroup(ctx context.Context, tenantID, groupID string) (*IAMGroupResponse, error)

	// ListGroups returns a paginated list of groups within a tenant.
	ListGroups(ctx context.Context, tenantID string, opts ListIAMRequest) (*IAMGroupListResponse, error)

	// UpdateGroup modifies an existing group's name, description, or members.
	UpdateGroup(ctx context.Context, tenantID, groupID string, opts UpdateGroupRequest) (*IAMGroupResponse, error)

	// AddGroupMember adds a user to a group.
	// If the user is already a member, this operation is idempotent.
	AddGroupMember(ctx context.Context, tenantID, groupID, userID string) error

	// RemoveGroupMember removes a user from a group.
	// The user loses any permissions granted through group membership.
	RemoveGroupMember(ctx context.Context, tenantID, groupID, userID string) error

	// Policy operations

	// CheckPermission evaluates whether a subject (user) has permission
	// to perform an action on a resource within the given context.
	// Returns the authorization decision with optional reason.
	CheckPermission(ctx context.Context, req *CheckPermissionRequest) (*CheckPermissionResponse, error)

	// Authentication operations

	// Authenticate validates user credentials and returns authentication tokens.
	// Supports username/password, and optionally TOTP or certificate-based authentication.
	Authenticate(ctx context.Context, req *AuthenticateRequest) (*AuthenticateResponse, error)

	// Token operations

	// CreateToken generates a new access token for an authenticated user.
	// The token includes specified scopes and has a configurable expiration.
	CreateToken(ctx context.Context, tenantID, userID string, opts CreateTokenRequest) (*TokenResponse, error)

	// RevokeToken invalidates a token, preventing further use.
	// Both access and refresh tokens can be revoked.
	RevokeToken(ctx context.Context, tokenID string) error

	// VerifyToken validates a token and returns its claims if valid.
	// Returns detailed information about the token including user, tenant, and scopes.
	VerifyToken(ctx context.Context, token string) (*TokenVerifyResponse, error)
}

// =============================================================================
// IAM User Request/Response Types
// =============================================================================

// CreateUserRequest contains the parameters for creating a new IAM user.
// TenantID and Email are required fields; other fields are optional.
//
// Fields:
//   - TenantID: Required. The tenant in which to create the user.
//   - UserID: Optional. If empty, a unique ID will be generated.
//   - Email: Required. Must be unique within the tenant.
//   - Username: Optional. Alternative identifier for the user.
//   - Name: Optional. Display name for the user.
//   - Enabled: Optional. Whether the user is active. Defaults to true.
//   - Attributes: Optional. Custom key-value metadata.
type CreateUserRequest struct {
	TenantID   string            `codec:"tenant_id"`
	UserID     string            `codec:"user_id"`
	Email      string            `codec:"email"`
	Username   string            `codec:"username"`
	Name       string            `codec:"name"`
	Enabled    bool              `codec:"enabled"`
	Attributes map[string]string `codec:"attributes"`
}

// UpdateUserRequest contains the parameters for updating an existing IAM user.
// Only non-empty fields will be updated; empty fields are ignored.
//
// Fields:
//   - TenantID: Required. The tenant containing the user.
//   - UserID: Required. The unique identifier of the user to update.
//   - Email: Optional. New email address.
//   - Username: Optional. New username.
//   - Name: Optional. New display name.
//   - Enabled: Optional. New enabled state.
//   - Roles: Optional. Complete list of role IDs to assign.
//   - Groups: Optional. Complete list of group IDs for membership.
//   - Attributes: Optional. Complete attribute map (replaces existing).
type UpdateUserRequest struct {
	TenantID   string            `codec:"tenant_id"`
	UserID     string            `codec:"user_id"`
	Email      string            `codec:"email"`
	Username   string            `codec:"username"`
	Name       string            `codec:"name"`
	Enabled    bool              `codec:"enabled"`
	Roles      []string          `codec:"roles"`
	Groups     []string          `codec:"groups"`
	Attributes map[string]string `codec:"attributes"`
}

// GetUserRequest contains the parameters for retrieving an IAM user.
// Either UserID or Email must be provided to identify the user.
//
// Fields:
//   - TenantID: Required. The tenant containing the user.
//   - UserID: Optional. The unique identifier of the user.
//   - Email: Optional. The email address of the user.
type GetUserRequest struct {
	TenantID string `codec:"tenant_id"`
	UserID   string `codec:"user_id"`
	Email    string `codec:"email"`
}

// DeleteUserRequest contains the parameters for deleting an IAM user.
// Both TenantID and UserID are required.
//
// Fields:
//   - TenantID: Required. The tenant containing the user.
//   - UserID: Required. The unique identifier of the user to delete.
type DeleteUserRequest struct {
	TenantID string `codec:"tenant_id"`
	UserID   string `codec:"user_id"`
}

// ListIAMRequest contains pagination and filtering parameters for list operations.
// This request type is shared across user, role, and group list operations.
//
// Fields:
//   - TenantID: Required. The tenant to list entities from.
//   - Limit: Optional. Maximum number of results to return. Defaults to 100.
//   - Offset: Optional. Number of results to skip for pagination.
//   - SortBy: Optional. Field name to sort results by.
//   - SortDesc: Optional. If true, sort in descending order.
type ListIAMRequest struct {
	TenantID string `codec:"tenant_id"`
	Limit    int    `codec:"limit"`
	Offset   int    `codec:"offset"`
	SortBy   string `codec:"sort_by"`
	SortDesc bool   `codec:"sort_desc"`
}

// IAMUserResponse represents a user entity in API responses.
// Contains all user attributes including assigned roles and group memberships.
//
// Fields:
//   - ID: The unique identifier for the user.
//   - TenantID: The tenant the user belongs to.
//   - Email: The user's email address.
//   - Username: The user's username.
//   - Name: The user's display name.
//   - Enabled: Whether the user account is active.
//   - Roles: List of role IDs assigned to the user.
//   - Groups: List of group IDs the user is a member of.
//   - Attributes: Custom key-value metadata.
//   - CreatedAt: Unix timestamp of creation.
//   - UpdatedAt: Unix timestamp of last update.
//   - Timestamp: Unix timestamp of this response.
type IAMUserResponse struct {
	ID         string            `codec:"id"`
	TenantID   string            `codec:"tenant_id"`
	Email      string            `codec:"email"`
	Username   string            `codec:"username"`
	Name       string            `codec:"name"`
	Enabled    bool              `codec:"enabled"`
	Roles      []string          `codec:"roles"`
	Groups     []string          `codec:"groups"`
	Attributes map[string]string `codec:"attributes"`
	CreatedAt  int64             `codec:"created_at"`
	UpdatedAt  int64             `codec:"updated_at"`
	Timestamp  int64             `codec:"timestamp"`
}

// IAMUserListResponse contains a paginated list of users.
// Includes pagination metadata for iterating through large result sets.
//
// Fields:
//   - Users: The list of user entities.
//   - Total: Total number of users matching the query.
//   - Limit: The limit that was applied.
//   - Offset: The offset that was applied.
//   - Timestamp: Unix timestamp of this response.
type IAMUserListResponse struct {
	Users     []*IAMUserResponse `codec:"users"`
	Total     int                `codec:"total"`
	Limit     int                `codec:"limit"`
	Offset    int                `codec:"offset"`
	Timestamp int64              `codec:"timestamp"`
}

// =============================================================================
// IAM Role Request/Response Types
// =============================================================================

// CreateRoleRequest contains the parameters for creating a new IAM role.
// TenantID and Name are required; other fields are optional.
//
// Fields:
//   - TenantID: Required. The tenant in which to create the role.
//   - RoleID: Optional. If empty, a unique ID will be generated.
//   - Name: Required. Human-readable name for the role.
//   - Description: Optional. Detailed description of the role's purpose.
//   - Permissions: Optional. List of permission strings granted by this role.
//   - Attributes: Optional. Custom key-value metadata.
type CreateRoleRequest struct {
	TenantID    string            `codec:"tenant_id"`
	RoleID      string            `codec:"role_id"`
	Name        string            `codec:"name"`
	Description string            `codec:"description"`
	Permissions []string          `codec:"permissions"`
	Attributes  map[string]string `codec:"attributes"`
}

// UpdateRoleRequest contains the parameters for updating an existing IAM role.
// Only non-empty fields will be updated; empty fields are ignored.
//
// Fields:
//   - TenantID: Required. The tenant containing the role.
//   - RoleID: Required. The unique identifier of the role to update.
//   - Name: Optional. New name for the role.
//   - Description: Optional. New description.
//   - Permissions: Optional. Complete list of permissions (replaces existing).
//   - Attributes: Optional. Complete attribute map (replaces existing).
type UpdateRoleRequest struct {
	TenantID    string            `codec:"tenant_id"`
	RoleID      string            `codec:"role_id"`
	Name        string            `codec:"name"`
	Description string            `codec:"description"`
	Permissions []string          `codec:"permissions"`
	Attributes  map[string]string `codec:"attributes"`
}

// GetRoleRequest contains the parameters for retrieving an IAM role.
// Both TenantID and RoleID are required.
//
// Fields:
//   - TenantID: Required. The tenant containing the role.
//   - RoleID: Required. The unique identifier of the role.
type GetRoleRequest struct {
	TenantID string `codec:"tenant_id"`
	RoleID   string `codec:"role_id"`
}

// DeleteRoleRequest contains the parameters for deleting an IAM role.
// Both TenantID and RoleID are required.
//
// Fields:
//   - TenantID: Required. The tenant containing the role.
//   - RoleID: Required. The unique identifier of the role to delete.
type DeleteRoleRequest struct {
	TenantID string `codec:"tenant_id"`
	RoleID   string `codec:"role_id"`
}

// AssignRoleRequest contains the parameters for assigning a role to a user.
// All fields are required.
//
// Fields:
//   - TenantID: Required. The tenant containing the user and role.
//   - UserID: Required. The unique identifier of the user.
//   - RoleID: Required. The unique identifier of the role to assign.
type AssignRoleRequest struct {
	TenantID string `codec:"tenant_id"`
	UserID   string `codec:"user_id"`
	RoleID   string `codec:"role_id"`
}

// RevokeRoleRequest contains the parameters for revoking a role from a user.
// All fields are required.
//
// Fields:
//   - TenantID: Required. The tenant containing the user and role.
//   - UserID: Required. The unique identifier of the user.
//   - RoleID: Required. The unique identifier of the role to revoke.
type RevokeRoleRequest struct {
	TenantID string `codec:"tenant_id"`
	UserID   string `codec:"user_id"`
	RoleID   string `codec:"role_id"`
}

// IAMRoleResponse represents a role entity in API responses.
// Contains the role definition including its permissions.
//
// Fields:
//   - ID: The unique identifier for the role.
//   - TenantID: The tenant the role belongs to.
//   - Name: The human-readable name of the role.
//   - Description: Detailed description of the role.
//   - Permissions: List of permission strings granted by this role.
//   - Attributes: Custom key-value metadata.
//   - CreatedAt: Unix timestamp of creation.
//   - UpdatedAt: Unix timestamp of last update.
//   - Timestamp: Unix timestamp of this response.
type IAMRoleResponse struct {
	ID          string            `codec:"id"`
	TenantID    string            `codec:"tenant_id"`
	Name        string            `codec:"name"`
	Description string            `codec:"description"`
	Permissions []string          `codec:"permissions"`
	Attributes  map[string]string `codec:"attributes"`
	CreatedAt   int64             `codec:"created_at"`
	UpdatedAt   int64             `codec:"updated_at"`
	Timestamp   int64             `codec:"timestamp"`
}

// IAMRoleListResponse contains a paginated list of roles.
// Includes pagination metadata for iterating through large result sets.
//
// Fields:
//   - Roles: The list of role entities.
//   - Total: Total number of roles matching the query.
//   - Limit: The limit that was applied.
//   - Offset: The offset that was applied.
//   - Timestamp: Unix timestamp of this response.
type IAMRoleListResponse struct {
	Roles     []*IAMRoleResponse `codec:"roles"`
	Total     int                `codec:"total"`
	Limit     int                `codec:"limit"`
	Offset    int                `codec:"offset"`
	Timestamp int64              `codec:"timestamp"`
}

// =============================================================================
// IAM Group Request/Response Types
// =============================================================================

// CreateGroupRequest contains the parameters for creating a new IAM group.
// TenantID and Name are required; other fields are optional.
//
// Fields:
//   - TenantID: Required. The tenant in which to create the group.
//   - GroupID: Optional. If empty, a unique ID will be generated.
//   - Name: Required. Human-readable name for the group.
//   - Description: Optional. Detailed description of the group's purpose.
//   - Attributes: Optional. Custom key-value metadata.
type CreateGroupRequest struct {
	TenantID    string            `codec:"tenant_id"`
	GroupID     string            `codec:"group_id"`
	Name        string            `codec:"name"`
	Description string            `codec:"description"`
	Attributes  map[string]string `codec:"attributes"`
}

// UpdateGroupRequest contains the parameters for updating an existing IAM group.
// Only non-empty fields will be updated; empty fields are ignored.
//
// Fields:
//   - TenantID: Required. The tenant containing the group.
//   - GroupID: Required. The unique identifier of the group to update.
//   - Name: Optional. New name for the group.
//   - Description: Optional. New description.
//   - Members: Optional. Complete list of member user IDs (replaces existing).
//   - Attributes: Optional. Complete attribute map (replaces existing).
type UpdateGroupRequest struct {
	TenantID    string            `codec:"tenant_id"`
	GroupID     string            `codec:"group_id"`
	Name        string            `codec:"name"`
	Description string            `codec:"description"`
	Members     []string          `codec:"members"`
	Attributes  map[string]string `codec:"attributes"`
}

// GetGroupRequest contains the parameters for retrieving an IAM group.
// Both TenantID and GroupID are required.
//
// Fields:
//   - TenantID: Required. The tenant containing the group.
//   - GroupID: Required. The unique identifier of the group.
type GetGroupRequest struct {
	TenantID string `codec:"tenant_id"`
	GroupID  string `codec:"group_id"`
}

// DeleteGroupRequest contains the parameters for deleting an IAM group.
// Both TenantID and GroupID are required.
//
// Fields:
//   - TenantID: Required. The tenant containing the group.
//   - GroupID: Required. The unique identifier of the group to delete.
type DeleteGroupRequest struct {
	TenantID string `codec:"tenant_id"`
	GroupID  string `codec:"group_id"`
}

// GroupMemberRequest contains the parameters for adding or removing a group member.
// All fields are required.
//
// Fields:
//   - TenantID: Required. The tenant containing the group and user.
//   - GroupID: Required. The unique identifier of the group.
//   - UserID: Required. The unique identifier of the user.
type GroupMemberRequest struct {
	TenantID string `codec:"tenant_id"`
	GroupID  string `codec:"group_id"`
	UserID   string `codec:"user_id"`
}

// IAMGroupResponse represents a group entity in API responses.
// Contains the group definition including its members.
//
// Fields:
//   - ID: The unique identifier for the group.
//   - TenantID: The tenant the group belongs to.
//   - Name: The human-readable name of the group.
//   - Description: Detailed description of the group.
//   - Members: List of user IDs that are members of this group.
//   - Attributes: Custom key-value metadata.
//   - CreatedAt: Unix timestamp of creation.
//   - UpdatedAt: Unix timestamp of last update.
//   - Timestamp: Unix timestamp of this response.
type IAMGroupResponse struct {
	ID          string            `codec:"id"`
	TenantID    string            `codec:"tenant_id"`
	Name        string            `codec:"name"`
	Description string            `codec:"description"`
	Members     []string          `codec:"members"`
	Attributes  map[string]string `codec:"attributes"`
	CreatedAt   int64             `codec:"created_at"`
	UpdatedAt   int64             `codec:"updated_at"`
	Timestamp   int64             `codec:"timestamp"`
}

// IAMGroupListResponse contains a paginated list of groups.
// Includes pagination metadata for iterating through large result sets.
//
// Fields:
//   - Groups: The list of group entities.
//   - Total: Total number of groups matching the query.
//   - Limit: The limit that was applied.
//   - Offset: The offset that was applied.
//   - Timestamp: Unix timestamp of this response.
type IAMGroupListResponse struct {
	Groups    []*IAMGroupResponse `codec:"groups"`
	Total     int                 `codec:"total"`
	Limit     int                 `codec:"limit"`
	Offset    int                 `codec:"offset"`
	Timestamp int64               `codec:"timestamp"`
}

// =============================================================================
// IAM Policy/Permission Request/Response Types
// =============================================================================

// CheckPermissionRequest contains the parameters for checking authorization.
// Used to determine if a subject has permission to perform an action on a resource.
//
// Fields:
//   - TenantID: Required. The tenant context for the authorization check.
//   - SubjectID: Required. The user or entity requesting authorization.
//   - Resource: Required. The resource being accessed (e.g., "document:123").
//   - Action: Required. The action being performed (e.g., "read", "write").
//   - Context: Optional. Additional context for policy evaluation.
type CheckPermissionRequest struct {
	TenantID  string            `codec:"tenant_id"`
	SubjectID string            `codec:"subject_id"`
	Resource  string            `codec:"resource"`
	Action    string            `codec:"action"`
	Context   map[string]string `codec:"context"`
}

// CheckPermissionResponse contains the authorization decision.
// Indicates whether the requested action is allowed and provides reasoning.
//
// Fields:
//   - Allowed: Whether the action is permitted.
//   - Reason: Human-readable explanation for the decision.
//   - Timestamp: Unix timestamp of this response.
type CheckPermissionResponse struct {
	Allowed   bool   `codec:"allowed"`
	Reason    string `codec:"reason"`
	Timestamp int64  `codec:"timestamp"`
}

// =============================================================================
// IAM Authentication Request/Response Types
// =============================================================================

// AuthenticateRequest contains the parameters for user authentication.
// Used to validate user credentials and obtain authentication tokens.
//
// Fields:
//   - TenantID: Optional. The tenant context for authentication.
//   - Username: Required. The username or email to authenticate.
//   - Password: Required. The user's password.
//   - TOTPCode: Optional. Time-based one-time password for MFA.
//   - Certificate: Optional. Client certificate for certificate-based auth.
type AuthenticateRequest struct {
	TenantID    string `codec:"tenant_id"`
	Username    string `codec:"username"`
	Password    string `codec:"password" secret:"true"`
	TOTPCode    string `codec:"totp_code"`
	Certificate string `codec:"certificate"`
}

// AuthenticateResponse contains the result of a successful authentication.
// Includes access and refresh tokens for subsequent API calls.
//
// Fields:
//   - UserID: The authenticated user's unique identifier.
//   - TenantID: The tenant the user belongs to.
//   - AccessToken: JWT or opaque token for API authorization.
//   - RefreshToken: Token for obtaining new access tokens.
//   - ExpiresIn: Seconds until the access token expires.
//   - TokenType: The token type, typically "Bearer".
//   - Timestamp: Unix timestamp of this response.
type AuthenticateResponse struct {
	UserID       string `codec:"user_id"`
	TenantID     string `codec:"tenant_id"`
	AccessToken  string `codec:"access_token" secret:"true"`
	RefreshToken string `codec:"refresh_token" secret:"true"`
	ExpiresIn    int64  `codec:"expires_in"`
	TokenType    string `codec:"token_type"`
	Timestamp    int64  `codec:"timestamp"`
}

// =============================================================================
// IAM Token Request/Response Types
// =============================================================================

// CreateTokenRequest contains the parameters for creating a new token.
// Used for programmatic token generation for service accounts or API access.
//
// Fields:
//   - TenantID: Required. The tenant context for the token.
//   - UserID: Required. The user the token is issued for.
//   - Scopes: Optional. List of OAuth scopes to include in the token.
//   - ExpiresIn: Optional. Seconds until expiration. Defaults to 3600.
type CreateTokenRequest struct {
	TenantID  string   `codec:"tenant_id"`
	UserID    string   `codec:"user_id"`
	Scopes    []string `codec:"scopes"`
	ExpiresIn int64    `codec:"expires_in"`
}

// TokenResponse contains a newly created token.
// Includes both access and refresh tokens with metadata.
//
// Fields:
//   - TokenID: Unique identifier for the token (for revocation).
//   - AccessToken: JWT or opaque token for API authorization.
//   - RefreshToken: Token for obtaining new access tokens.
//   - ExpiresIn: Seconds until the access token expires.
//   - TokenType: The token type, typically "Bearer".
//   - Timestamp: Unix timestamp of this response.
type TokenResponse struct {
	TokenID      string `codec:"token_id"`
	AccessToken  string `codec:"access_token" secret:"true"`
	RefreshToken string `codec:"refresh_token" secret:"true"`
	ExpiresIn    int64  `codec:"expires_in"`
	TokenType    string `codec:"token_type"`
	Timestamp    int64  `codec:"timestamp"`
}

// RevokeTokenRequest contains the parameters for revoking a token.
// Either TokenID or Token must be provided.
//
// Fields:
//   - TokenID: Optional. The unique identifier of the token.
//   - Token: Optional. The token string itself.
type RevokeTokenRequest struct {
	TokenID string `codec:"token_id"`
	Token   string `codec:"token" secret:"true"`
}

// VerifyTokenRequest contains the parameters for verifying a token.
// The Token field is required.
//
// Fields:
//   - Token: Required. The token string to verify.
type VerifyTokenRequest struct {
	Token string `codec:"token" secret:"true"`
}

// TokenVerifyResponse contains the result of token verification.
// Provides detailed claims if the token is valid.
//
// Fields:
//   - Valid: Whether the token is valid and not expired.
//   - UserID: The user the token was issued for.
//   - TenantID: The tenant context of the token.
//   - Scopes: List of OAuth scopes in the token.
//   - ExpiresAt: Unix timestamp when the token expires.
//   - Timestamp: Unix timestamp of this response.
type TokenVerifyResponse struct {
	Valid     bool     `codec:"valid"`
	UserID    string   `codec:"user_id"`
	TenantID  string   `codec:"tenant_id"`
	Scopes    []string `codec:"scopes"`
	ExpiresAt int64    `codec:"expires_at"`
	Timestamp int64    `codec:"timestamp"`
}

// GenericIAMResponse represents a generic success/failure response.
// Used for operations that don't return entity data (e.g., delete, assign).
//
// Fields:
//   - Success: Whether the operation completed successfully.
//   - Message: Human-readable description of the result.
//   - Timestamp: Unix timestamp of this response.
type GenericIAMResponse struct {
	Success   bool   `codec:"success"`
	Message   string `codec:"message"`
	Timestamp int64  `codec:"timestamp"`
}

// =============================================================================
// QUIC Handler Methods
// =============================================================================

// handleIAMOperation routes IAM-related QUIC requests to the appropriate handler.
// This method is called by the main QUIC request router for all IAM opcodes.
//
// The method first checks if the IAM service is available, returning
// StatusUnavailable if not configured. It then dispatches based on the
// request opcode to specific handler methods for each operation type.
//
// Parameters:
//   - ctx: Context for cancellation and deadline propagation
//   - req: The QUIC request containing opcode and payload
//
// Returns:
//   - A QUIC response with status code and encoded payload
func (h *QUICServiceHandler) handleIAMOperation(ctx context.Context, req *quic.Request) *quic.Response {
	if h.iamService == nil {
		return h.errorResponse(quic.StatusUnavailable, ErrQUICServiceUnavailable{Service: "iam"})
	}

	switch req.Opcode {
	// User operations
	case quic.OpIAMUserCreate:
		return h.handleIAMUserCreate(ctx, req)
	case quic.OpIAMUserDelete:
		return h.handleIAMUserDelete(ctx, req)
	case quic.OpIAMUserGet:
		return h.handleIAMUserGet(ctx, req)
	case quic.OpIAMUserList:
		return h.handleIAMUserList(ctx, req)
	case quic.OpIAMUserUpdate:
		return h.handleIAMUserUpdate(ctx, req)

	// Role operations
	case quic.OpIAMRoleCreate:
		return h.handleIAMRoleCreate(ctx, req)
	case quic.OpIAMRoleDelete:
		return h.handleIAMRoleDelete(ctx, req)
	case quic.OpIAMRoleGet:
		return h.handleIAMRoleGet(ctx, req)
	case quic.OpIAMRoleList:
		return h.handleIAMRoleList(ctx, req)
	case quic.OpIAMRoleAssign:
		return h.handleIAMRoleAssign(ctx, req)
	case quic.OpIAMRoleRevoke:
		return h.handleIAMRoleRevoke(ctx, req)

	// Group operations
	case quic.OpIAMGroupCreate:
		return h.handleIAMGroupCreate(ctx, req)
	case quic.OpIAMGroupDelete:
		return h.handleIAMGroupDelete(ctx, req)
	case quic.OpIAMGroupGet:
		return h.handleIAMGroupGet(ctx, req)
	case quic.OpIAMGroupList:
		return h.handleIAMGroupList(ctx, req)
	case quic.OpIAMGroupAddMember:
		return h.handleIAMGroupAddMember(ctx, req)
	case quic.OpIAMGroupRemoveMember:
		return h.handleIAMGroupRemoveMember(ctx, req)

	// Permission operations
	case quic.OpIAMCheckPermission:
		return h.handleIAMCheckPermission(ctx, req)

	// Authentication operations
	case quic.OpIAMAuthenticate:
		return h.handleIAMAuthenticate(ctx, req)

	// Token operations
	case quic.OpIAMTokenCreate:
		return h.handleIAMTokenCreate(ctx, req)
	case quic.OpIAMTokenRevoke:
		return h.handleIAMTokenRevoke(ctx, req)
	case quic.OpIAMTokenVerify:
		return h.handleIAMTokenVerify(ctx, req)

	default:
		return h.errorResponse(quic.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Opcode})
	}
}

// =============================================================================
// User Operation Handlers
// =============================================================================

// handleIAMUserCreate creates a new IAM user within a tenant.
//
// Required fields in payload:
//   - tenant_id: The tenant to create the user in
//   - email: The user's email address (must be unique)
//
// Optional fields:
//   - user_id, username, name, enabled, attributes
//
// Returns:
//   - StatusOK with IAMUserResponse on success
//   - StatusInvalidRequest if payload decoding fails
//   - StatusInvalidArgument if required fields are missing
//   - StatusInternalError if creation fails
func (h *QUICServiceHandler) handleIAMUserCreate(ctx context.Context, req *quic.Request) *quic.Response {
	var createReq CreateUserRequest
	if err := quic.DecodePayload(req.Payload, &createReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if createReq.TenantID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "tenant_id"})
	}
	if createReq.Email == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "email"})
	}

	user, err := h.iamService.CreateUser(ctx, createReq.TenantID, createReq)
	if err != nil {
		h.logger.Error(err, "failed to create IAM user", "tenant_id", createReq.TenantID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "IAMUserCreate", Cause: err})
	}

	payload, err := quic.EncodePayload(user)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleIAMUserDelete removes an IAM user from a tenant.
//
// Required fields in payload:
//   - tenant_id: The tenant containing the user
//   - user_id: The unique identifier of the user to delete
//
// Returns:
//   - StatusOK with GenericIAMResponse on success
//   - StatusInvalidRequest if payload decoding fails
//   - StatusInvalidArgument if required fields are missing
//   - StatusInternalError if deletion fails
func (h *QUICServiceHandler) handleIAMUserDelete(ctx context.Context, req *quic.Request) *quic.Response {
	var deleteReq DeleteUserRequest
	if err := quic.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if deleteReq.TenantID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "tenant_id"})
	}
	if deleteReq.UserID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "user_id"})
	}

	if err := h.iamService.DeleteUser(ctx, deleteReq.TenantID, deleteReq.UserID); err != nil {
		h.logger.Error(err, "failed to delete IAM user", "tenant_id", deleteReq.TenantID, "user_id", deleteReq.UserID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "IAMUserDelete", Cause: err})
	}

	resp := &GenericIAMResponse{
		Success:   true,
		Message:   "user deleted successfully",
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleIAMUserGet retrieves an IAM user by ID or email.
//
// Required fields in payload:
//   - tenant_id: The tenant containing the user
//   - user_id OR email: Identifier for the user
//
// Returns:
//   - StatusOK with IAMUserResponse on success
//   - StatusInvalidRequest if payload decoding fails
//   - StatusInvalidArgument if required fields are missing
//   - StatusNotFound if user does not exist
func (h *QUICServiceHandler) handleIAMUserGet(ctx context.Context, req *quic.Request) *quic.Response {
	var getReq GetUserRequest
	if err := quic.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.TenantID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "tenant_id"})
	}
	if getReq.UserID == "" && getReq.Email == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "user_id or email"})
	}

	user, err := h.iamService.GetUser(ctx, getReq.TenantID, getReq.UserID)
	if err != nil {
		h.logger.Error(err, "failed to get IAM user", "tenant_id", getReq.TenantID, "user_id", getReq.UserID)
		return h.errorResponse(quic.StatusNotFound, ErrQUICOperationFailed{Op: "IAMUserGet", Cause: err})
	}

	payload, err := quic.EncodePayload(user)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleIAMUserList returns a paginated list of IAM users.
//
// Required fields in payload:
//   - tenant_id: The tenant to list users from
//
// Optional fields:
//   - limit: Maximum results to return (default 100)
//   - offset: Number of results to skip
//   - sort_by: Field to sort by
//   - sort_desc: Sort in descending order
//
// Returns:
//   - StatusOK with IAMUserListResponse on success
//   - StatusInvalidRequest if payload decoding fails
//   - StatusInvalidArgument if tenant_id is missing
//   - StatusInternalError if listing fails
func (h *QUICServiceHandler) handleIAMUserList(ctx context.Context, req *quic.Request) *quic.Response {
	var listReq ListIAMRequest
	if len(req.Payload) > 0 {
		if err := quic.DecodePayload(req.Payload, &listReq); err != nil {
			return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
		}
	}

	if listReq.TenantID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "tenant_id"})
	}

	users, err := h.iamService.ListUsers(ctx, listReq.TenantID, listReq)
	if err != nil {
		h.logger.Error(err, "failed to list IAM users", "tenant_id", listReq.TenantID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "IAMUserList", Cause: err})
	}

	payload, err := quic.EncodePayload(users)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleIAMUserUpdate modifies an existing IAM user.
//
// Required fields in payload:
//   - tenant_id: The tenant containing the user
//   - user_id: The unique identifier of the user to update
//
// Optional fields:
//   - email, username, name, enabled, roles, groups, attributes
//
// Returns:
//   - StatusOK with IAMUserResponse on success
//   - StatusInvalidRequest if payload decoding fails
//   - StatusInvalidArgument if required fields are missing
//   - StatusInternalError if update fails
func (h *QUICServiceHandler) handleIAMUserUpdate(ctx context.Context, req *quic.Request) *quic.Response {
	var updateReq UpdateUserRequest
	if err := quic.DecodePayload(req.Payload, &updateReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if updateReq.TenantID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "tenant_id"})
	}
	if updateReq.UserID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "user_id"})
	}

	user, err := h.iamService.UpdateUser(ctx, updateReq.TenantID, updateReq.UserID, updateReq)
	if err != nil {
		h.logger.Error(err, "failed to update IAM user", "tenant_id", updateReq.TenantID, "user_id", updateReq.UserID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "IAMUserUpdate", Cause: err})
	}

	payload, err := quic.EncodePayload(user)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Role Operation Handlers
// =============================================================================

// handleIAMRoleCreate creates a new IAM role within a tenant.
//
// Required fields in payload:
//   - tenant_id: The tenant to create the role in
//   - name: Human-readable name for the role
//
// Optional fields:
//   - role_id, description, permissions, attributes
//
// Returns:
//   - StatusOK with IAMRoleResponse on success
//   - StatusInvalidRequest if payload decoding fails
//   - StatusInvalidArgument if required fields are missing
//   - StatusInternalError if creation fails
func (h *QUICServiceHandler) handleIAMRoleCreate(ctx context.Context, req *quic.Request) *quic.Response {
	var createReq CreateRoleRequest
	if err := quic.DecodePayload(req.Payload, &createReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if createReq.TenantID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "tenant_id"})
	}
	if createReq.Name == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "name"})
	}

	role, err := h.iamService.CreateRole(ctx, createReq.TenantID, createReq)
	if err != nil {
		h.logger.Error(err, "failed to create IAM role", "tenant_id", createReq.TenantID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "IAMRoleCreate", Cause: err})
	}

	payload, err := quic.EncodePayload(role)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleIAMRoleDelete removes an IAM role from a tenant.
//
// Required fields in payload:
//   - tenant_id: The tenant containing the role
//   - role_id: The unique identifier of the role to delete
//
// Returns:
//   - StatusOK with GenericIAMResponse on success
//   - StatusInvalidRequest if payload decoding fails
//   - StatusInvalidArgument if required fields are missing
//   - StatusInternalError if deletion fails
func (h *QUICServiceHandler) handleIAMRoleDelete(ctx context.Context, req *quic.Request) *quic.Response {
	var deleteReq DeleteRoleRequest
	if err := quic.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if deleteReq.TenantID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "tenant_id"})
	}
	if deleteReq.RoleID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "role_id"})
	}

	if err := h.iamService.DeleteRole(ctx, deleteReq.TenantID, deleteReq.RoleID); err != nil {
		h.logger.Error(err, "failed to delete IAM role", "tenant_id", deleteReq.TenantID, "role_id", deleteReq.RoleID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "IAMRoleDelete", Cause: err})
	}

	resp := &GenericIAMResponse{
		Success:   true,
		Message:   "role deleted successfully",
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleIAMRoleGet retrieves an IAM role by ID.
//
// Required fields in payload:
//   - tenant_id: The tenant containing the role
//   - role_id: The unique identifier of the role
//
// Returns:
//   - StatusOK with IAMRoleResponse on success
//   - StatusInvalidRequest if payload decoding fails
//   - StatusInvalidArgument if required fields are missing
//   - StatusNotFound if role does not exist
func (h *QUICServiceHandler) handleIAMRoleGet(ctx context.Context, req *quic.Request) *quic.Response {
	var getReq GetRoleRequest
	if err := quic.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.TenantID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "tenant_id"})
	}
	if getReq.RoleID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "role_id"})
	}

	role, err := h.iamService.GetRole(ctx, getReq.TenantID, getReq.RoleID)
	if err != nil {
		h.logger.Error(err, "failed to get IAM role", "tenant_id", getReq.TenantID, "role_id", getReq.RoleID)
		return h.errorResponse(quic.StatusNotFound, ErrQUICOperationFailed{Op: "IAMRoleGet", Cause: err})
	}

	payload, err := quic.EncodePayload(role)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleIAMRoleList returns a paginated list of IAM roles.
//
// Required fields in payload:
//   - tenant_id: The tenant to list roles from
//
// Optional fields:
//   - limit, offset, sort_by, sort_desc
//
// Returns:
//   - StatusOK with IAMRoleListResponse on success
//   - StatusInvalidRequest if payload decoding fails
//   - StatusInvalidArgument if tenant_id is missing
//   - StatusInternalError if listing fails
func (h *QUICServiceHandler) handleIAMRoleList(ctx context.Context, req *quic.Request) *quic.Response {
	var listReq ListIAMRequest
	if len(req.Payload) > 0 {
		if err := quic.DecodePayload(req.Payload, &listReq); err != nil {
			return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
		}
	}

	if listReq.TenantID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "tenant_id"})
	}

	roles, err := h.iamService.ListRoles(ctx, listReq.TenantID, listReq)
	if err != nil {
		h.logger.Error(err, "failed to list IAM roles", "tenant_id", listReq.TenantID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "IAMRoleList", Cause: err})
	}

	payload, err := quic.EncodePayload(roles)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleIAMRoleAssign assigns a role to a user.
//
// Required fields in payload:
//   - tenant_id: The tenant containing the user and role
//   - user_id: The user to assign the role to
//   - role_id: The role to assign
//
// Returns:
//   - StatusOK with GenericIAMResponse on success
//   - StatusInvalidRequest if payload decoding fails
//   - StatusInvalidArgument if required fields are missing
//   - StatusInternalError if assignment fails
func (h *QUICServiceHandler) handleIAMRoleAssign(ctx context.Context, req *quic.Request) *quic.Response {
	var assignReq AssignRoleRequest
	if err := quic.DecodePayload(req.Payload, &assignReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if assignReq.TenantID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "tenant_id"})
	}
	if assignReq.UserID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "user_id"})
	}
	if assignReq.RoleID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "role_id"})
	}

	if err := h.iamService.AssignRoleToUser(ctx, assignReq.TenantID, assignReq.UserID, assignReq.RoleID); err != nil {
		h.logger.Error(err, "failed to assign IAM role", "tenant_id", assignReq.TenantID, "user_id", assignReq.UserID, "role_id", assignReq.RoleID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "IAMRoleAssign", Cause: err})
	}

	resp := &GenericIAMResponse{
		Success:   true,
		Message:   "role assigned successfully",
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleIAMRoleRevoke removes a role from a user.
//
// Required fields in payload:
//   - tenant_id: The tenant containing the user and role
//   - user_id: The user to revoke the role from
//   - role_id: The role to revoke
//
// Returns:
//   - StatusOK with GenericIAMResponse on success
//   - StatusInvalidRequest if payload decoding fails
//   - StatusInvalidArgument if required fields are missing
//   - StatusInternalError if revocation fails
func (h *QUICServiceHandler) handleIAMRoleRevoke(ctx context.Context, req *quic.Request) *quic.Response {
	var revokeReq RevokeRoleRequest
	if err := quic.DecodePayload(req.Payload, &revokeReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if revokeReq.TenantID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "tenant_id"})
	}
	if revokeReq.UserID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "user_id"})
	}
	if revokeReq.RoleID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "role_id"})
	}

	if err := h.iamService.RevokeRoleFromUser(ctx, revokeReq.TenantID, revokeReq.UserID, revokeReq.RoleID); err != nil {
		h.logger.Error(err, "failed to revoke IAM role", "tenant_id", revokeReq.TenantID, "user_id", revokeReq.UserID, "role_id", revokeReq.RoleID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "IAMRoleRevoke", Cause: err})
	}

	resp := &GenericIAMResponse{
		Success:   true,
		Message:   "role revoked successfully",
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Group Operation Handlers
// =============================================================================

// handleIAMGroupCreate creates a new IAM group within a tenant.
//
// Required fields in payload:
//   - tenant_id: The tenant to create the group in
//   - name: Human-readable name for the group
//
// Optional fields:
//   - group_id, description, attributes
//
// Returns:
//   - StatusOK with IAMGroupResponse on success
//   - StatusInvalidRequest if payload decoding fails
//   - StatusInvalidArgument if required fields are missing
//   - StatusInternalError if creation fails
func (h *QUICServiceHandler) handleIAMGroupCreate(ctx context.Context, req *quic.Request) *quic.Response {
	var createReq CreateGroupRequest
	if err := quic.DecodePayload(req.Payload, &createReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if createReq.TenantID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "tenant_id"})
	}
	if createReq.Name == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "name"})
	}

	group, err := h.iamService.CreateGroup(ctx, createReq.TenantID, createReq)
	if err != nil {
		h.logger.Error(err, "failed to create IAM group", "tenant_id", createReq.TenantID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "IAMGroupCreate", Cause: err})
	}

	payload, err := quic.EncodePayload(group)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleIAMGroupDelete removes an IAM group from a tenant.
//
// Required fields in payload:
//   - tenant_id: The tenant containing the group
//   - group_id: The unique identifier of the group to delete
//
// Returns:
//   - StatusOK with GenericIAMResponse on success
//   - StatusInvalidRequest if payload decoding fails
//   - StatusInvalidArgument if required fields are missing
//   - StatusInternalError if deletion fails
func (h *QUICServiceHandler) handleIAMGroupDelete(ctx context.Context, req *quic.Request) *quic.Response {
	var deleteReq DeleteGroupRequest
	if err := quic.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if deleteReq.TenantID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "tenant_id"})
	}
	if deleteReq.GroupID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "group_id"})
	}

	if err := h.iamService.DeleteGroup(ctx, deleteReq.TenantID, deleteReq.GroupID); err != nil {
		h.logger.Error(err, "failed to delete IAM group", "tenant_id", deleteReq.TenantID, "group_id", deleteReq.GroupID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "IAMGroupDelete", Cause: err})
	}

	resp := &GenericIAMResponse{
		Success:   true,
		Message:   "group deleted successfully",
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleIAMGroupGet retrieves an IAM group by ID.
//
// Required fields in payload:
//   - tenant_id: The tenant containing the group
//   - group_id: The unique identifier of the group
//
// Returns:
//   - StatusOK with IAMGroupResponse on success
//   - StatusInvalidRequest if payload decoding fails
//   - StatusInvalidArgument if required fields are missing
//   - StatusNotFound if group does not exist
func (h *QUICServiceHandler) handleIAMGroupGet(ctx context.Context, req *quic.Request) *quic.Response {
	var getReq GetGroupRequest
	if err := quic.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.TenantID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "tenant_id"})
	}
	if getReq.GroupID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "group_id"})
	}

	group, err := h.iamService.GetGroup(ctx, getReq.TenantID, getReq.GroupID)
	if err != nil {
		h.logger.Error(err, "failed to get IAM group", "tenant_id", getReq.TenantID, "group_id", getReq.GroupID)
		return h.errorResponse(quic.StatusNotFound, ErrQUICOperationFailed{Op: "IAMGroupGet", Cause: err})
	}

	payload, err := quic.EncodePayload(group)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleIAMGroupList returns a paginated list of IAM groups.
//
// Required fields in payload:
//   - tenant_id: The tenant to list groups from
//
// Optional fields:
//   - limit, offset, sort_by, sort_desc
//
// Returns:
//   - StatusOK with IAMGroupListResponse on success
//   - StatusInvalidRequest if payload decoding fails
//   - StatusInvalidArgument if tenant_id is missing
//   - StatusInternalError if listing fails
func (h *QUICServiceHandler) handleIAMGroupList(ctx context.Context, req *quic.Request) *quic.Response {
	var listReq ListIAMRequest
	if len(req.Payload) > 0 {
		if err := quic.DecodePayload(req.Payload, &listReq); err != nil {
			return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
		}
	}

	if listReq.TenantID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "tenant_id"})
	}

	groups, err := h.iamService.ListGroups(ctx, listReq.TenantID, listReq)
	if err != nil {
		h.logger.Error(err, "failed to list IAM groups", "tenant_id", listReq.TenantID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "IAMGroupList", Cause: err})
	}

	payload, err := quic.EncodePayload(groups)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleIAMGroupAddMember adds a user to a group.
//
// Required fields in payload:
//   - tenant_id: The tenant containing the group and user
//   - group_id: The group to add the member to
//   - user_id: The user to add
//
// Returns:
//   - StatusOK with GenericIAMResponse on success
//   - StatusInvalidRequest if payload decoding fails
//   - StatusInvalidArgument if required fields are missing
//   - StatusInternalError if operation fails
func (h *QUICServiceHandler) handleIAMGroupAddMember(ctx context.Context, req *quic.Request) *quic.Response {
	var memberReq GroupMemberRequest
	if err := quic.DecodePayload(req.Payload, &memberReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if memberReq.TenantID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "tenant_id"})
	}
	if memberReq.GroupID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "group_id"})
	}
	if memberReq.UserID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "user_id"})
	}

	if err := h.iamService.AddGroupMember(ctx, memberReq.TenantID, memberReq.GroupID, memberReq.UserID); err != nil {
		h.logger.Error(err, "failed to add member to IAM group", "tenant_id", memberReq.TenantID, "group_id", memberReq.GroupID, "user_id", memberReq.UserID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "IAMGroupAddMember", Cause: err})
	}

	resp := &GenericIAMResponse{
		Success:   true,
		Message:   "member added successfully",
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleIAMGroupRemoveMember removes a user from a group.
//
// Required fields in payload:
//   - tenant_id: The tenant containing the group and user
//   - group_id: The group to remove the member from
//   - user_id: The user to remove
//
// Returns:
//   - StatusOK with GenericIAMResponse on success
//   - StatusInvalidRequest if payload decoding fails
//   - StatusInvalidArgument if required fields are missing
//   - StatusInternalError if operation fails
func (h *QUICServiceHandler) handleIAMGroupRemoveMember(ctx context.Context, req *quic.Request) *quic.Response {
	var memberReq GroupMemberRequest
	if err := quic.DecodePayload(req.Payload, &memberReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if memberReq.TenantID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "tenant_id"})
	}
	if memberReq.GroupID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "group_id"})
	}
	if memberReq.UserID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "user_id"})
	}

	if err := h.iamService.RemoveGroupMember(ctx, memberReq.TenantID, memberReq.GroupID, memberReq.UserID); err != nil {
		h.logger.Error(err, "failed to remove member from IAM group", "tenant_id", memberReq.TenantID, "group_id", memberReq.GroupID, "user_id", memberReq.UserID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "IAMGroupRemoveMember", Cause: err})
	}

	resp := &GenericIAMResponse{
		Success:   true,
		Message:   "member removed successfully",
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Permission Operation Handlers
// =============================================================================

// handleIAMCheckPermission evaluates an authorization request.
//
// Required fields in payload:
//   - tenant_id: The tenant context for authorization
//   - subject_id: The user or entity requesting access
//   - resource: The resource being accessed
//   - action: The action being performed
//
// Optional fields:
//   - context: Additional context for policy evaluation
//
// Returns:
//   - StatusOK with CheckPermissionResponse on success
//   - StatusInvalidRequest if payload decoding fails
//   - StatusInvalidArgument if required fields are missing
//   - StatusInternalError if evaluation fails
func (h *QUICServiceHandler) handleIAMCheckPermission(ctx context.Context, req *quic.Request) *quic.Response {
	var checkReq CheckPermissionRequest
	if err := quic.DecodePayload(req.Payload, &checkReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if checkReq.TenantID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "tenant_id"})
	}
	if checkReq.SubjectID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "subject_id"})
	}
	if checkReq.Resource == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "resource"})
	}
	if checkReq.Action == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "action"})
	}

	result, err := h.iamService.CheckPermission(ctx, &checkReq)
	if err != nil {
		h.logger.Error(err, "failed to check IAM permission", "tenant_id", checkReq.TenantID, "subject_id", checkReq.SubjectID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "IAMCheckPermission", Cause: err})
	}

	payload, err := quic.EncodePayload(result)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Authentication Operation Handlers
// =============================================================================

// handleIAMAuthenticate authenticates a user with their credentials.
//
// Required fields in payload:
//   - username: The username or email to authenticate
//   - password: The user's password
//
// Optional fields:
//   - tenant_id: The tenant context for authentication
//   - totp_code: Time-based one-time password for MFA
//   - certificate: Client certificate for certificate-based auth
//
// Returns:
//   - StatusOK with AuthenticateResponse on success
//   - StatusInvalidRequest if payload decoding fails
//   - StatusInvalidArgument if required fields are missing
//   - StatusUnauthorized if authentication fails
func (h *QUICServiceHandler) handleIAMAuthenticate(ctx context.Context, req *quic.Request) *quic.Response {
	var authReq AuthenticateRequest
	if err := quic.DecodePayload(req.Payload, &authReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if authReq.Username == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "username"})
	}
	if authReq.Password == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "password"})
	}

	result, err := h.iamService.Authenticate(ctx, &authReq)
	if err != nil {
		h.logger.Error(err, "failed to authenticate user", "username", authReq.Username)
		return h.errorResponse(quic.StatusUnauthorized, ErrQUICOperationFailed{Op: "IAMAuthenticate", Cause: err})
	}

	payload, err := quic.EncodePayload(result)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Token Operation Handlers
// =============================================================================

// handleIAMTokenCreate generates a new access token for a user.
//
// Required fields in payload:
//   - tenant_id: The tenant context
//   - user_id: The user the token is for
//
// Optional fields:
//   - scopes: OAuth scopes to include
//   - expires_in: Token lifetime in seconds
//
// Returns:
//   - StatusOK with TokenResponse on success
//   - StatusInvalidRequest if payload decoding fails
//   - StatusInvalidArgument if required fields are missing
//   - StatusInternalError if token creation fails
func (h *QUICServiceHandler) handleIAMTokenCreate(ctx context.Context, req *quic.Request) *quic.Response {
	var tokenReq CreateTokenRequest
	if err := quic.DecodePayload(req.Payload, &tokenReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if tokenReq.TenantID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "tenant_id"})
	}
	if tokenReq.UserID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "user_id"})
	}

	result, err := h.iamService.CreateToken(ctx, tokenReq.TenantID, tokenReq.UserID, tokenReq)
	if err != nil {
		h.logger.Error(err, "failed to create token", "tenant_id", tokenReq.TenantID, "user_id", tokenReq.UserID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "IAMTokenCreate", Cause: err})
	}

	payload, err := quic.EncodePayload(result)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleIAMTokenRevoke invalidates an existing token.
//
// Required fields in payload (one of):
//   - token_id: The unique identifier of the token
//   - token: The token string itself
//
// Returns:
//   - StatusOK with GenericIAMResponse on success
//   - StatusInvalidRequest if payload decoding fails
//   - StatusInvalidArgument if neither identifier is provided
//   - StatusInternalError if revocation fails
func (h *QUICServiceHandler) handleIAMTokenRevoke(ctx context.Context, req *quic.Request) *quic.Response {
	var revokeReq RevokeTokenRequest
	if err := quic.DecodePayload(req.Payload, &revokeReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	tokenID := revokeReq.TokenID
	if tokenID == "" {
		tokenID = revokeReq.Token
	}
	if tokenID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "token_id or token"})
	}

	if err := h.iamService.RevokeToken(ctx, tokenID); err != nil {
		h.logger.Error(err, "failed to revoke token")
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "IAMTokenRevoke", Cause: err})
	}

	resp := &GenericIAMResponse{
		Success:   true,
		Message:   "token revoked successfully",
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleIAMTokenVerify validates a token and returns its claims.
//
// Required fields in payload:
//   - token: The token string to verify
//
// Returns:
//   - StatusOK with TokenVerifyResponse on success
//   - StatusInvalidRequest if payload decoding fails
//   - StatusInvalidArgument if token is missing
//   - StatusUnauthorized if token is invalid or expired
func (h *QUICServiceHandler) handleIAMTokenVerify(ctx context.Context, req *quic.Request) *quic.Response {
	var verifyReq VerifyTokenRequest
	if err := quic.DecodePayload(req.Payload, &verifyReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if verifyReq.Token == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "token"})
	}

	result, err := h.iamService.VerifyToken(ctx, verifyReq.Token)
	if err != nil {
		h.logger.Error(err, "failed to verify token")
		return h.errorResponse(quic.StatusUnauthorized, ErrQUICOperationFailed{Op: "IAMTokenVerify", Cause: err})
	}

	payload, err := quic.EncodePayload(result)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}
