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
	"errors"
	"strings"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
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

	// Device profile tools (same scopes as the gRPC DeviceService profile
	// RPCs in pkg/api/grpc/method_permissions.go)
	c.toolPermissions["profile_create"] = "device:write"
	c.toolPermissions["profile_get_by_id"] = "device:read"
	c.toolPermissions["profile_list_all"] = "device:read"
	c.toolPermissions["profile_update_by_id"] = "device:write"
	c.toolPermissions["profile_delete_by_id"] = "device:delete"
	c.toolPermissions["profile_assign_to_device"] = "device:write"
	c.toolPermissions["profile_unassign_from_device"] = "device:write"

	// SDN tools
	// Gateway load balancer tools
	c.toolPermissions["gateway_lb_vip_add"] = "sdn:write"
	c.toolPermissions["gateway_lb_vip_remove"] = "sdn:delete"
	c.toolPermissions["gateway_lb_vip_get"] = "sdn:read"
	c.toolPermissions["gateway_lb_vip_list"] = "sdn:read"
	c.toolPermissions["gateway_lb_vip_set_backends"] = "sdn:write"
	c.toolPermissions["gateway_lb_status"] = "sdn:read"
	// gateway_perf_flows mutates bridge flow tables (ephemeral install +
	// cookie-scoped delete), so it requires sdn:write; the counters are
	// read-only.
	c.toolPermissions["gateway_perf_flows"] = "sdn:write"
	c.toolPermissions["gateway_perf_datapath"] = "sdn:read"
	c.toolPermissions["gateway_perf_conntrack"] = "sdn:read"

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

	// Proxy (reverse-proxy configuration) tools
	c.toolPermissions["proxy_route_create"] = "proxy:write"
	c.toolPermissions["proxy_route_get"] = "proxy:read"
	c.toolPermissions["proxy_route_update"] = "proxy:write"
	c.toolPermissions["proxy_route_delete"] = "proxy:delete"
	c.toolPermissions["proxy_route_list"] = "proxy:read"
	c.toolPermissions["proxy_pool_create"] = "proxy:write"
	c.toolPermissions["proxy_pool_get"] = "proxy:read"
	c.toolPermissions["proxy_pool_update"] = "proxy:write"
	c.toolPermissions["proxy_pool_delete"] = "proxy:delete"
	c.toolPermissions["proxy_pool_list"] = "proxy:read"
	c.toolPermissions["proxy_config"] = "proxy:read"
	c.toolPermissions["proxy_status"] = "proxy:read"
	c.toolPermissions["proxy_config_reload"] = "proxy:write"
	c.toolPermissions["proxy_zone_matrix"] = "proxy:read"

	// NTP (time synchronization) tools. ntp_step mutates the system clock,
	// so it requires ntp:write; the readings are ntp:read.
	c.toolPermissions["ntp_status"] = "ntp:read"
	c.toolPermissions["ntp_sources"] = "ntp:read"
	c.toolPermissions["ntp_step"] = "ntp:write"

	// Health tools (no auth required)
	c.toolPermissions["platform_health"] = ""
	c.toolPermissions["platform_liveness"] = ""
	c.toolPermissions["platform_readiness"] = ""

	// Invitation tools. These mirror the REST surface exactly, which splits by
	// principal (pkg/webservice/v1/router.go:591, and #171 for the unverified
	// decoders the gated half used to rely on):
	//
	//   RegisterRoutes       -> gated(common.ROLE_ADMIN)  — the five below
	//   RegisterInviteeRoutes -> the UNGATED router       — the two after them
	//
	// NOTE the parity is incomplete, and deliberately so rather than by
	// oversight. The REST admin half also resolves tenant and inviter from the
	// verified session via tenantMiddleware. MCP authorizes on `resource:action`
	// only and has no expression of RequireSystemTenant (#299), so these grants
	// are NECESSARY but not SUFFICIENT to match REST. Tracked in #304; do not
	// read these entries as "MCP now equals REST".
	c.toolPermissions["platform_invitation_create"] = "invitation:write"
	c.toolPermissions["platform_invitation_list"] = "invitation:read"
	c.toolPermissions["platform_invitation_get"] = "invitation:read"
	c.toolPermissions["platform_invitation_revoke"] = "invitation:write"
	c.toolPermissions["platform_invitation_delete"] = "invitation:delete"

	// The invitation token IS the credential for these two, exactly as on the
	// ungated REST routes: an invitee has no platform session by construction,
	// and both tools take `token` as a required parameter. An empty permission
	// is the faithful expression of that, not an under-authorization — but it
	// must stay an EXPLICIT entry rather than relying on a default, which is
	// the whole point of the change below.
	c.toolPermissions["platform_invitation_get_by_token"] = ""
	c.toolPermissions["platform_invitation_accept"] = ""
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
	// A tool with no entry is DENIED. The map is a permission grant, not an
	// optional annotation.
	//
	// This previously returned nil — allow — with a comment saying the tool
	// registry would handle the error. It does not: a registered tool with no
	// map entry reached its handler unauthorized, and 357 of 428 registered
	// tools had no entry, including BMC power control and virtual-media
	// mounting (#300). The gap between what that comment described and what
	// the code did is why it survived review.
	//
	// A tool that legitimately needs no permission says so with an explicit
	// empty string, which is handled just below.
	permission, exists := c.toolPermissions[toolName]
	if !exists {
		return ctx, &AuthorizationError{
			Type:    AuthErrorToolNotClassified,
			Message: "tool '" + toolName + "' has no permission mapping and cannot be authorized",
		}
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
	//
	// The tool's required scope is enforced INSIDE the validator: pass it as
	// requiredPerm so the offline scope check and online liveness run in one
	// pipeline. A scope denial surfaces as a *platformtoken.ScopeDeniedError;
	// every other failure (auth, liveness) is an invalid/expired token.
	if cv, ok := c.authManager.(ClaimsAuthManager); ok && cv != nil {
		scope := scopeForToolPermission(permission)
		authCtx, err := cv.AuthorizeToken(ctx, token, scope, "", "", "")
		if err != nil {
			var scopeErr *platformtoken.ScopeDeniedError
			if errors.As(err, &scopeErr) {
				return ctx, &AuthorizationError{
					Type:    AuthErrorPermissionDenied,
					Message: "Permission denied: insufficient privileges",
				}
			}
			return ctx, &AuthorizationError{
				Type:    AuthErrorInvalidToken,
				Message: "Invalid or expired token",
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
