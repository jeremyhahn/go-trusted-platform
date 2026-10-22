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

package mcp

import (
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
	"google.golang.org/grpc/status"
)

// =============================================================================
// IAM Error Types
// =============================================================================

// IAMError represents an IAM operation error.
type IAMError struct {
	Code    string
	Message string
}

func (e *IAMError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// GRPCStatus classifies the error by its Code (codeClass), so the MCP
// server answers it with the matching JSON-RPC code.
func (e *IAMError) GRPCStatus() *status.Status {
	return codeStatus(e.Code, e.Error())
}

// ErrIAMServiceUnavailable indicates the IAM service is not available.
var ErrIAMServiceUnavailable = &IAMError{
	Code:    "IAM_SERVICE_UNAVAILABLE",
	Message: "IAM service is not available",
}

// ErrIAMTenantIDRequired indicates tenant ID is required.
var ErrIAMTenantIDRequired = &IAMError{
	Code:    "IAM_TENANT_ID_REQUIRED",
	Message: "tenant_id is required",
}

// ErrIAMUserIDRequired indicates user ID is required.
var ErrIAMUserIDRequired = &IAMError{
	Code:    "IAM_USER_ID_REQUIRED",
	Message: "user_id is required",
}

// ErrIAMRoleIDRequired indicates role ID is required.
var ErrIAMRoleIDRequired = &IAMError{
	Code:    "IAM_ROLE_ID_REQUIRED",
	Message: "role_id is required",
}

// ErrIAMGroupIDRequired indicates group ID is required.
var ErrIAMGroupIDRequired = &IAMError{
	Code:    "IAM_GROUP_ID_REQUIRED",
	Message: "group_id is required",
}

// ErrIAMEmailRequired indicates email is required.
var ErrIAMEmailRequired = &IAMError{
	Code:    "IAM_EMAIL_REQUIRED",
	Message: "email is required",
}

// ErrIAMPasswordRequired indicates password is required.
var ErrIAMPasswordRequired = &IAMError{
	Code:    "IAM_PASSWORD_REQUIRED",
	Message: "password is required",
}

// ErrIAMResourceRequired indicates resource is required for authorization.
var ErrIAMResourceRequired = &IAMError{
	Code:    "IAM_RESOURCE_REQUIRED",
	Message: "resource is required",
}

// ErrIAMActionRequired indicates action is required for authorization.
var ErrIAMActionRequired = &IAMError{
	Code:    "IAM_ACTION_REQUIRED",
	Message: "action is required",
}

// ErrIAMRoleRequired indicates role is required.
var ErrIAMRoleRequired = &IAMError{
	Code:    "IAM_ROLE_REQUIRED",
	Message: "role is required",
}

// =============================================================================
// IAM Tool Registration
// =============================================================================

// registerIAMTools registers Identity and Access Management related tools.
func (r *ToolRegistry) registerIAMTools() {
	// User management tools
	r.registerIAMUserTools()

	// Role management tools
	r.registerIAMRoleTools()

	// Group management tools
	r.registerIAMGroupTools()

	// Authentication and authorization tools
	r.registerIAMAuthTools()

	// Tenant management tools
	r.registerIAMTenantTools()

	// Token management tools
	r.registerIAMTokenTools()
}

// iamPaginationSchema is the "pagination" argument of the IAM list tools, the
// gRPC PaginationRequest.
func iamPaginationSchema() map[string]interface{} {
	return map[string]interface{}{
		"type":        "object",
		"description": "Page to return",
		"properties": map[string]interface{}{
			"page": map[string]interface{}{
				"type":        "integer",
				"description": "Page number, counting from 1",
				"default":     1,
			},
			"page_size": map[string]interface{}{
				"type":        "integer",
				"description": "Items per page (default 50, at most 1000)",
				"default":     50,
			},
		},
	}
}

// registerIAMUserTools registers IAM user management tools.
func (r *ToolRegistry) registerIAMUserTools() {
	r.addTool(mcpwire.ToolDefinition{
		Name:        "iam_create_user",
		Description: "Create a new IAM user in a tenant",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID for the user",
				},
				"email": map[string]interface{}{
					"type":        "string",
					"description": "User email address",
				},
				"name": map[string]interface{}{
					"type":        "string",
					"description": "User display name",
				},
				"roles": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Initial roles to assign to the user",
				},
				"groups": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Initial groups to add the user to",
				},
				"attributes": map[string]interface{}{
					"type":        "object",
					"description": "Custom user attributes as key-value pairs",
				},
			},
			"required": []string{"tenant_id", "email"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "iam_delete_user",
		Description: "Delete an IAM user from a tenant",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID",
				},
				"user_id": map[string]interface{}{
					"type":        "string",
					"description": "User ID to delete",
				},
			},
			"required": []string{"tenant_id", "user_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "iam_get_user",
		Description: "Get IAM user details by ID",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID",
				},
				"user_id": map[string]interface{}{
					"type":        "string",
					"description": "User ID to retrieve",
				},
			},
			"required": []string{"tenant_id", "user_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "iam_update_user",
		Description: "Update an IAM user's email, name, roles, groups or attributes",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID",
				},
				"user_id": map[string]interface{}{
					"type":        "string",
					"description": "User ID to update",
				},
				"email": map[string]interface{}{
					"type":        "string",
					"description": "New email address",
				},
				"name": map[string]interface{}{
					"type":        "string",
					"description": "New display name",
				},
				"roles": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Roles the user holds after the update",
				},
				"groups": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Groups the user belongs to after the update",
				},
				"attributes": map[string]interface{}{
					"type":        "object",
					"description": "Custom user attributes as key-value pairs",
				},
			},
			"required": []string{"tenant_id", "user_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "iam_list_users",
		Description: "List IAM users in a tenant with pagination",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID",
				},
				"pagination": iamPaginationSchema(),
				"email_filter": map[string]interface{}{
					"type":        "string",
					"description": "Only users whose email matches this filter",
				},
				"role_filter": map[string]interface{}{
					"type":        "string",
					"description": "Only users holding this role ID",
				},
				"group_filter": map[string]interface{}{
					"type":        "string",
					"description": "Only members of this group ID",
				},
			},
			"required": []string{"tenant_id"},
		},
	})
}

// registerIAMRoleTools registers IAM role management tools.
func (r *ToolRegistry) registerIAMRoleTools() {
	r.addTool(mcpwire.ToolDefinition{
		Name:        "iam_create_role",
		Description: "Create a new IAM role in a tenant",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID for the role",
				},
				"id": map[string]interface{}{
					"type":        "string",
					"description": "Unique role identifier",
				},
				"name": map[string]interface{}{
					"type":        "string",
					"description": "Role display name",
				},
				"description": map[string]interface{}{
					"type":        "string",
					"description": "Role description",
				},
				"permissions": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "List of permissions granted by this role",
				},
			},
			"required": []string{"tenant_id", "id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "iam_delete_role",
		Description: "Delete an IAM role from a tenant",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID",
				},
				"role_id": map[string]interface{}{
					"type":        "string",
					"description": "Role ID to delete",
				},
			},
			"required": []string{"tenant_id", "role_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "iam_get_role",
		Description: "Get IAM role details by ID",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID",
				},
				"role_id": map[string]interface{}{
					"type":        "string",
					"description": "Role ID to retrieve",
				},
			},
			"required": []string{"tenant_id", "role_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "iam_list_roles",
		Description: "List IAM roles in a tenant with pagination",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID",
				},
				"pagination": iamPaginationSchema(),
			},
			"required": []string{"tenant_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "iam_assign_role",
		Description: "Assign a role to a user",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID",
				},
				"user_id": map[string]interface{}{
					"type":        "string",
					"description": "User ID to assign the role to",
				},
				"role_id": map[string]interface{}{
					"type":        "string",
					"description": "Role ID to assign",
				},
			},
			"required": []string{"tenant_id", "user_id", "role_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "iam_revoke_role",
		Description: "Revoke a role from a user",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID",
				},
				"user_id": map[string]interface{}{
					"type":        "string",
					"description": "User ID to revoke the role from",
				},
				"role_id": map[string]interface{}{
					"type":        "string",
					"description": "Role ID to revoke",
				},
			},
			"required": []string{"tenant_id", "user_id", "role_id"},
		},
	})
}

// registerIAMGroupTools registers IAM group management tools.
func (r *ToolRegistry) registerIAMGroupTools() {
	r.addTool(mcpwire.ToolDefinition{
		Name:        "iam_create_group",
		Description: "Create a new IAM group in a tenant",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID for the group",
				},
				"id": map[string]interface{}{
					"type":        "string",
					"description": "Unique group identifier",
				},
				"name": map[string]interface{}{
					"type":        "string",
					"description": "Group display name",
				},
				"description": map[string]interface{}{
					"type":        "string",
					"description": "Group description",
				},
			},
			"required": []string{"tenant_id", "id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "iam_delete_group",
		Description: "Delete an IAM group from a tenant",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID",
				},
				"group_id": map[string]interface{}{
					"type":        "string",
					"description": "Group ID to delete",
				},
			},
			"required": []string{"tenant_id", "group_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "iam_get_group",
		Description: "Get IAM group details by ID",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID",
				},
				"group_id": map[string]interface{}{
					"type":        "string",
					"description": "Group ID to retrieve",
				},
			},
			"required": []string{"tenant_id", "group_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "iam_update_group",
		Description: "Update an IAM group's name or description",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID",
				},
				"group_id": map[string]interface{}{
					"type":        "string",
					"description": "Group ID to update",
				},
				"name": map[string]interface{}{
					"type":        "string",
					"description": "New group display name",
				},
				"description": map[string]interface{}{
					"type":        "string",
					"description": "New group description",
				},
			},
			"required": []string{"tenant_id", "group_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "iam_list_groups",
		Description: "List IAM groups in a tenant with pagination",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID",
				},
				"pagination": iamPaginationSchema(),
			},
			"required": []string{"tenant_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "iam_add_group_member",
		Description: "Add a user to an IAM group",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID",
				},
				"group_id": map[string]interface{}{
					"type":        "string",
					"description": "Group ID to add the user to",
				},
				"user_id": map[string]interface{}{
					"type":        "string",
					"description": "User ID to add to the group",
				},
			},
			"required": []string{"tenant_id", "group_id", "user_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "iam_remove_group_member",
		Description: "Remove a user from an IAM group",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID",
				},
				"group_id": map[string]interface{}{
					"type":        "string",
					"description": "Group ID to remove the user from",
				},
				"user_id": map[string]interface{}{
					"type":        "string",
					"description": "User ID to remove from the group",
				},
			},
			"required": []string{"tenant_id", "group_id", "user_id"},
		},
	})
}

// registerIAMAuthTools registers IAM authentication and authorization tools.
func (r *ToolRegistry) registerIAMAuthTools() {
	r.addTool(mcpwire.ToolDefinition{
		Name:        "iam_check_permission",
		Description: "Check if a subject has permission to perform an action on a resource",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID",
				},
				"subject_id": map[string]interface{}{
					"type":        "string",
					"description": "Subject (user or application) ID to check permissions for",
				},
				"roles": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Roles the subject holds",
				},
				"groups": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Groups the subject belongs to",
				},
				"resource": map[string]interface{}{
					"type":        "string",
					"description": "Resource identifier (e.g., 'iam:users', 'ca:certificates')",
				},
				"action": map[string]interface{}{
					"type":        "string",
					"description": "Action to check (e.g., 'read', 'write', 'delete')",
				},
				"context": map[string]interface{}{
					"type":                 "object",
					"additionalProperties": map[string]interface{}{"type": "string"},
					"description":          "Request context the policies evaluate",
				},
				"attributes": map[string]interface{}{
					"type":                 "object",
					"additionalProperties": map[string]interface{}{"type": "string"},
					"description":          "Subject attributes the policies evaluate",
				},
			},
			"required": []string{"tenant_id", "subject_id", "resource", "action"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "iam_authenticate",
		Description: "Authenticate a user with credentials",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID",
				},
				"email": map[string]interface{}{
					"type":        "string",
					"description": "User email address",
				},
				"password": map[string]interface{}{
					"type":        "string",
					"description": "User password",
				},
				"totp_code": map[string]interface{}{
					"type":        "string",
					"description": "TOTP code for MFA (if enabled)",
				},
				"certificate": map[string]interface{}{
					"type":        "string",
					"description": "PEM-encoded client certificate for certificate-based auth",
				},
			},
			"required": []string{"tenant_id", "email"},
		},
	})
}

// registerIAMTenantTools registers IAM tenant management tools.
func (r *ToolRegistry) registerIAMTenantTools() {
	r.addTool(mcpwire.ToolDefinition{
		Name:        "iam_create_tenant",
		Description: "Create a new tenant in the IAM system",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "string",
					"description": "Unique tenant identifier",
				},
				"name": map[string]interface{}{
					"type":        "string",
					"description": "Tenant display name",
				},
				"settings": map[string]interface{}{
					"type":        "object",
					"description": "Tenant settings",
					"properties": map[string]interface{}{
						"max_users": map[string]interface{}{
							"type":        "integer",
							"description": "Maximum number of users in the tenant",
						},
						"mfa_required": map[string]interface{}{
							"type":        "boolean",
							"description": "Whether the tenant's users must use MFA",
						},
					},
				},
			},
			"required": []string{"id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "iam_delete_tenant",
		Description: "Delete a tenant from the IAM system",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID to delete",
				},
			},
			"required": []string{"tenant_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "iam_get_tenant",
		Description: "Get tenant details by ID",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID to retrieve",
				},
			},
			"required": []string{"tenant_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "iam_list_tenants",
		Description: "List all tenants with pagination",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"pagination": iamPaginationSchema(),
			},
		},
	})
}

// registerIAMTokenTools registers IAM token management tools.
func (r *ToolRegistry) registerIAMTokenTools() {
	r.addTool(mcpwire.ToolDefinition{
		Name:        "iam_create_token",
		Description: "Create a new access token for a user",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID",
				},
				"user_id": map[string]interface{}{
					"type":        "string",
					"description": "User ID to create the token for",
				},
				"name": map[string]interface{}{
					"type":        "string",
					"description": "Token name/description",
				},
				"expires_in": map[string]interface{}{
					"type":        "integer",
					"description": "Token expiration time in seconds",
				},
				"scopes": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Token scopes/permissions",
				},
			},
			"required": []string{"tenant_id", "user_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "iam_revoke_token",
		Description: "Revoke an access token",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"token_id": map[string]interface{}{
					"type":        "string",
					"description": "Token ID to revoke",
				},
			},
			"required": []string{"token_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "iam_verify_token",
		Description: "Verify an access token",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"token": map[string]interface{}{
					"type":        "string",
					"description": "Token to verify",
				},
			},
			"required": []string{"token"},
		},
	})
}
