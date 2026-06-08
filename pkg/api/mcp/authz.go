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
	"context"
	"strings"
)

// AuthorizationChecker validates tool authorization.
type AuthorizationChecker struct {
	authService AuthorizationService
	authManager AuthManager

	// toolPermissions maps tool names to required permissions
	toolPermissions map[string]string
}

// NewAuthorizationChecker creates a new authorization checker.
func NewAuthorizationChecker(authService AuthorizationService, authManager AuthManager) *AuthorizationChecker {
	c := &AuthorizationChecker{
		authService:     authService,
		authManager:     authManager,
		toolPermissions: make(map[string]string),
	}

	// Initialize tool permissions
	c.initToolPermissions()

	return c
}

// initToolPermissions sets up the permission mappings for tools.
func (c *AuthorizationChecker) initToolPermissions() {
	// vTPM tools
	c.toolPermissions["vtpm_create"] = "vtpm:write"
	c.toolPermissions["vtpm_delete"] = "vtpm:delete"
	c.toolPermissions["vtpm_list"] = "vtpm:read"
	c.toolPermissions["vtpm_start"] = "vtpm:write"
	c.toolPermissions["vtpm_stop"] = "vtpm:write"
	c.toolPermissions["vtpm_quote"] = "vtpm:read"
	c.toolPermissions["vtpm_seal"] = "vtpm:write"
	c.toolPermissions["vtpm_unseal"] = "vtpm:read"
	c.toolPermissions["vtpm_extend_pcr"] = "vtpm:write"
	c.toolPermissions["vtpm_read_pcr"] = "vtpm:read"

	// DNS tools
	c.toolPermissions["dns_add_record"] = "dns:write"
	c.toolPermissions["dns_delete_record"] = "dns:delete"
	c.toolPermissions["dns_get_record"] = "dns:read"
	c.toolPermissions["dns_list_records"] = "dns:read"
	c.toolPermissions["dns_resolve"] = "dns:read"
	c.toolPermissions["dns_create_zone"] = "dns:write"
	c.toolPermissions["dns_delete_zone"] = "dns:delete"
	c.toolPermissions["dns_list_zones"] = "dns:read"

	// Device tools
	c.toolPermissions["device_register"] = "device:write"
	c.toolPermissions["device_get"] = "device:read"
	c.toolPermissions["device_list"] = "device:read"
	c.toolPermissions["device_delete"] = "device:delete"
	c.toolPermissions["device_update"] = "device:write"
	c.toolPermissions["device_attest"] = "device:read"
	c.toolPermissions["device_provision"] = "device:write"

	// SDN tools
	c.toolPermissions["sdn_get_port_state"] = "sdn:read"
	c.toolPermissions["sdn_set_port_state"] = "sdn:write"
	c.toolPermissions["sdn_list_bridges"] = "sdn:read"
	c.toolPermissions["sdn_create_bridge"] = "sdn:write"
	c.toolPermissions["sdn_delete_bridge"] = "sdn:delete"
	c.toolPermissions["sdn_add_port"] = "sdn:write"
	c.toolPermissions["sdn_delete_port"] = "sdn:delete"
	c.toolPermissions["sdn_apply_policy"] = "sdn:write"
	c.toolPermissions["sdn_get_policy"] = "sdn:read"
	c.toolPermissions["sdn_list_policies"] = "sdn:read"

	// Health tools (no auth required)
	c.toolPermissions["platform_health"] = ""
	c.toolPermissions["platform_liveness"] = ""
	c.toolPermissions["platform_readiness"] = ""
}

// CheckToolAuthorization checks if the given token has permission to execute the
// tool. It is the context-less form retained for callers that do not need the
// projected AuthorizedContext; it delegates to AuthorizeTool and discards the
// returned context.
func (c *AuthorizationChecker) CheckToolAuthorization(ctx context.Context, toolName string, token string) *AuthorizationError {
	_, authErr := c.AuthorizeTool(ctx, toolName, token)
	return authErr
}

// AuthorizeTool validates the token and authorizes the tool, returning a context
// enriched with the validated AuthorizedContext (scp -> RBAC, tenant_id -> RLS)
// when the configured AuthManager supports the claims path. The returned context
// is the input context unchanged on the legacy / unauthenticated paths.
func (c *AuthorizationChecker) AuthorizeTool(ctx context.Context, toolName string, token string) (context.Context, *AuthorizationError) {
	// When no authorization backend is configured, allow all operations.
	// This supports test mode (SkipIAMValidation) and standalone deployments
	// where IAM is not available.
	if c.authService == nil && c.authManager == nil {
		return ctx, nil
	}

	// Get required permission for tool
	permission, exists := c.toolPermissions[toolName]
	if !exists {
		// Unknown tool - let the tool registry handle the error
		return ctx, nil
	}

	// If no permission required, allow
	if permission == "" {
		return ctx, nil
	}

	// Token required for protected tools
	if token == "" {
		return ctx, &AuthorizationError{
			Type:    AuthErrorMissingToken,
			Message: "Authentication required for this operation",
		}
	}

	// Prefer the platform-token (claims) path when the AuthManager supports it:
	// validate the token, project scp -> RBAC / tenant_id -> RLS, stash the
	// AuthorizedContext, and enforce the tool's required scope against it.
	if cv, ok := c.authManager.(ClaimsAuthManager); ok && cv != nil {
		authCtx, err := cv.AuthorizeToken(ctx, token, "", "", "")
		if err != nil {
			return ctx, &AuthorizationError{
				Type:    AuthErrorInvalidToken,
				Message: "Invalid or expired token",
			}
		}
		scope := scopeForToolPermission(permission)
		if scope != "" {
			if serr := authCtx.RequireScope(scope); serr != nil {
				return ctx, &AuthorizationError{
					Type:    AuthErrorPermissionDenied,
					Message: "Permission denied: insufficient privileges",
				}
			}
		}
		return ContextWithAuthorizedContext(ctx, authCtx), nil
	}

	// Validate token if auth manager configured (legacy bool-only path)
	if c.authManager != nil {
		valid, err := c.authManager.ValidateToken(ctx, token)
		if err != nil || !valid {
			return ctx, &AuthorizationError{
				Type:    AuthErrorInvalidToken,
				Message: "Invalid or expired token",
			}
		}
	}

	// Check permission if authorization service configured
	if c.authService != nil {
		// Parse permission into resource and action
		parts := strings.SplitN(permission, ":", 2)
		if len(parts) != 2 {
			return ctx, &AuthorizationError{
				Type:    AuthErrorPermissionDenied,
				Message: "Invalid permission configuration",
			}
		}

		resource := parts[0]
		action := parts[1]

		allowed, err := c.authService.CheckPermission(ctx, token, resource, action)
		if err != nil || !allowed {
			return ctx, &AuthorizationError{
				Type:    AuthErrorPermissionDenied,
				Message: "Permission denied: insufficient privileges",
			}
		}
	}

	return ctx, nil
}

// IsEnabled returns true if authorization checking is enabled.
func (c *AuthorizationChecker) IsEnabled() bool {
	return c.authService != nil || c.authManager != nil
}
