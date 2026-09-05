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
	c.toolPermissions["device_record_attest_cert"] = "device:write"

	// Attestation reporting (#226). Reads serve the cache; the refresh
	// enqueues work that spends a node's TPM time, so it is a write.
	c.toolPermissions["attestation_device_report"] = "attestation:read"
	c.toolPermissions["attestation_device_reports"] = "attestation:read"
	c.toolPermissions["attestation_caller_policy"] = "attestation:read"
	c.toolPermissions["attestation_device_refresh"] = "attestation:write"
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

	// BMC tools (#304, first tranche of the 350). The authority is
	// docs/bmc/api.md, not a REST route: neither BMC REST surface can serve as
	// one. pkg/webservice/v1/router/bmc.go is never mounted (#268), and the
	// daemon RESTServer that does serve /api/v1/bmc/* applies no authentication
	// at all (rest_service.go:465) — but is reached only by a config declaring
	// neither `webservices:` nor `webservice:`, which no shipped template
	// produces (#232, #312).
	//
	// THE SCOPE VOCABULARY HERE IS OWNER-RULED, not a lane's invention. Every
	// other entry in this map is resource:read|write|delete; these four verbs
	// are the first departure from that shape, taken deliberately because REST
	// cannot express the distinction and MCP can.
	//
	// docs/bmc/api.md:64 records that all four power mutators share one REST
	// path and method with the action in the body, so REST "cannot [distinguish
	// them] by path-based authorization". MCP has them as separate tools. The
	// split below is drawn on EFFECT rather than on what REST could express:
	//
	//   bmc:read   observation. A dashboard polls these continuously.
	//   bmc:write  changes state recoverably — powering a node ON, or setting
	//              which device it will boot from next.
	//   bmc:power  interrupts a RUNNING node. Off/reset/cycle kill workloads and
	//              force re-attestation; granting them is not implied by the
	//              right to power something on.
	//   bmc:media  chooses WHAT THE MACHINE BOOTS. On a platform whose purpose
	//              is measured boot, attaching arbitrary virtual media is the
	//              single most dangerous capability in this set — ranked above
	//              power control deliberately.
	//   bmc:admin  changes which credentials the BMC trusts. A different kind of
	//              authority again: not device state, but the trust relationship.
	//
	// Splitting media from power is what stops one grant conferring the whole
	// set_boot_device + mount_iso + power_cycle sequence — "boot the machine off
	// attacker-supplied media" — which a single bmc:write did confer.
	c.toolPermissions["platform_bmc_power_status"] = "bmc:read"
	c.toolPermissions["platform_bmc_get_boot_device"] = "bmc:read"
	c.toolPermissions["platform_bmc_virtual_media_status"] = "bmc:read"
	c.toolPermissions["platform_bmc_get_sensors"] = "bmc:read"
	c.toolPermissions["platform_bmc_get_system_info"] = "bmc:read"
	c.toolPermissions["platform_bmc_list_users"] = "bmc:read"
	c.toolPermissions["platform_bmc_get_web_certificate"] = "bmc:read"

	c.toolPermissions["platform_bmc_power_on"] = "bmc:write"
	c.toolPermissions["platform_bmc_set_boot_device"] = "bmc:write"

	c.toolPermissions["platform_bmc_power_off"] = "bmc:power"
	c.toolPermissions["platform_bmc_power_reset"] = "bmc:power"
	c.toolPermissions["platform_bmc_power_cycle"] = "bmc:power"

	c.toolPermissions["platform_bmc_mount_iso"] = "bmc:media"
	c.toolPermissions["platform_bmc_unmount_iso"] = "bmc:media"

	c.toolPermissions["platform_bmc_enroll"] = "bmc:admin"
	c.toolPermissions["platform_bmc_cert_restore"] = "bmc:admin"

	// NOTE these five scopes are advertised nowhere: getSupportedScopes() offers
	// 32 and none is BMC, so a client cannot discover that it may request them.
	// That is #315 — the advertised list and this map are separate hardcoded
	// manifests with nothing asserting they agree — and is not fixed here.
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

	// With no authorization backend there is nothing that can grant the
	// permission this tool requires, so the tool is refused (#440).
	//
	// This used to be the FIRST check and it returned allow: "when no
	// authorization backend is configured, allow all operations", for test
	// mode and standalone deployments. That made a missing backend -- the
	// daemon's "MCP server running without QuicBaaS authorization" warning,
	// reached whenever the IAM wiring fails at startup -- serve every
	// registered tool to any caller with no token, including the tools #300
	// made refuse for lack of a mapping and the BMC power controls #313
	// classified. A default that allows when the deciding component is
	// absent is the shape #300 closed one layer up; this closes it here.
	// Explicitly open tools ("") stay open, because "" means no permission
	// is required of anyone, backend or not. Test code that needs a tool to
	// execute configures a backend, as production does.
	if c.authService == nil && c.authManager == nil {
		return ctx, &AuthorizationError{
			Type:    AuthErrorMissingToken,
			Message: "Authentication required for this operation: no authorization backend is configured",
		}
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
