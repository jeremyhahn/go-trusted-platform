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
	return &AuthorizationChecker{
		authService:     authService,
		authManager:     authManager,
		toolPermissions: toolPermissionCatalog(),
	}
}

// toolPermissionCatalog returns the permission each MCP tool requires, keyed
// by tool name. It is the single source of the MCP scope vocabulary: the
// authorization checker enforces it, and the OAuth protected-resource
// metadata derives scopes_supported from it (#315), so a scope cannot be
// required without being advertised, or advertised without being required.
func toolPermissionCatalog() map[string]string {
	permissions := make(map[string]string)

	// vTPM tools
	permissions["vtpm_create"] = "vtpm:write"
	permissions["vtpm_delete"] = "vtpm:delete"
	permissions["vtpm_list"] = "vtpm:read"
	permissions["vtpm_start"] = "vtpm:write"
	permissions["vtpm_stop"] = "vtpm:write"
	permissions["vtpm_quote"] = "vtpm:read"
	permissions["vtpm_seal"] = "vtpm:write"
	permissions["vtpm_unseal"] = "vtpm:read"
	permissions["vtpm_extend_pcr"] = "vtpm:write"
	permissions["vtpm_read_pcr"] = "vtpm:read"

	// DNS tools
	permissions["dns_add_record"] = "dns:write"
	permissions["dns_delete_record"] = "dns:delete"
	permissions["dns_get_record"] = "dns:read"
	permissions["dns_list_records"] = "dns:read"
	permissions["dns_resolve"] = "dns:read"
	permissions["dns_create_zone"] = "dns:write"
	permissions["dns_delete_zone"] = "dns:delete"
	permissions["dns_list_zones"] = "dns:read"

	// Device tools
	permissions["device_register"] = "device:write"
	permissions["device_get"] = "device:read"
	permissions["device_find_by_serial"] = "device:read"
	permissions["device_list"] = "device:read"
	permissions["device_delete"] = "device:delete"
	permissions["device_update"] = "device:write"
	permissions["device_attest"] = "device:write"
	permissions["device_record_attest_cert"] = "device:write"
	permissions["device_disable"] = "device:write"
	permissions["device_enable"] = "device:write"
	// Diskless boot: a node holds no token. These tools are explicitly open
	// ("") because the boot service authenticates the caller itself --
	// proof of possession of the IDevID key bound to the connection, and the
	// client certificate -- and MCP carries no TLS state, so it refuses.
	// Open tools require no scope, so they add none to scopes_supported.
	permissions["device_boot_certificate"] = ""
	permissions["device_boot_delivery"] = ""

	// Attestation reporting (#226). Reads serve the cache; the refresh
	// enqueues work that spends a node's TPM time, so it is a write.
	permissions["attestation_device_report"] = "attestation:read"
	permissions["attestation_device_reports"] = "attestation:read"
	permissions["attestation_caller_policy"] = "attestation:read"
	permissions["attestation_device_refresh"] = "attestation:write"
	// The device verdict feed (#709), the same scope as the gRPC stream.
	permissions["attestation_device_verdicts_poll"] = "attestation:read"
	permissions["device_provision"] = "device:write"

	// Device profile tools (same scopes as the gRPC DeviceService profile
	// RPCs in pkg/api/grpc/method_permissions.go)
	permissions["profile_create"] = "device:write"
	permissions["profile_get_by_id"] = "device:read"
	permissions["profile_list_all"] = "device:read"
	permissions["profile_find_matching"] = "device:read"
	permissions["profile_find_by_mac"] = "device:read"
	permissions["profile_find_by_serial"] = "device:read"
	permissions["profile_update_by_id"] = "device:write"
	permissions["profile_delete_by_id"] = "device:delete"
	permissions["profile_assign_to_device"] = "device:write"
	permissions["profile_unassign_from_device"] = "device:write"
	permissions["device_template_create"] = "device:write"
	permissions["profile_create_from_template"] = "device:write"

	// SDN tools
	// Gateway load balancer tools
	// The telemetry snapshot is a read of what the datapath programmed.
	permissions["gateway_snapshot"] = "sdn:read"
	// Gateway status and the deprecated mode bitmask (#65). Setting the mode
	// reconfigures the gateway's services, so it is a write.
	permissions["gateway_status"] = "sdn:read"
	permissions["gateway_mode_set"] = "sdn:write"
	// BGP carries the scopes of its gRPC twins: announcing or withdrawing a
	// prefix changes what the fabric advertises, so both are writes (#65).
	permissions["gateway_bgp_status"] = "sdn:read"
	permissions["gateway_bgp_peers"] = "sdn:read"
	permissions["gateway_bgp_prefixes"] = "sdn:read"
	permissions["gateway_bgp_announce"] = "sdn:write"
	permissions["gateway_bgp_withdraw"] = "sdn:write"
	// Admitted overlay VTEPs are read from the same snapshot.
	permissions["gateway_admitted_vtep"] = "sdn:read"
	permissions["gateway_admitted_vteps"] = "sdn:read"
	// Underlay zones (#708). Every change re-derives the network plan and
	// takes effect at restart; a privileged path is audited by the service.
	permissions["gateway_zone_list"] = "sdn:read"
	permissions["gateway_zone_create"] = "sdn:write"
	permissions["gateway_zone_update"] = "sdn:write"
	permissions["gateway_zone_delete"] = "sdn:delete"
	// IPAM pools and allocations. Pools carry the reserved ranges and the
	// dynamic window the network plan derives.
	permissions["gateway_ipam_pools"] = "sdn:read"
	permissions["gateway_ipam_pool_get"] = "sdn:read"
	permissions["gateway_ipam_pool_create"] = "sdn:write"
	permissions["gateway_ipam_pool_update"] = "sdn:write"
	permissions["gateway_ipam_pool_delete"] = "sdn:delete"
	permissions["gateway_ipam_allocations"] = "sdn:read"
	permissions["gateway_ipam_allocate"] = "sdn:write"
	permissions["gateway_ipam_release"] = "sdn:write"
	permissions["gateway_snapshots"] = "sdn:read"
	permissions["gateway_lb_vip_add"] = "sdn:write"
	permissions["gateway_lb_vip_remove"] = "sdn:delete"
	permissions["gateway_lb_vip_get"] = "sdn:read"
	permissions["gateway_lb_vip_list"] = "sdn:read"
	permissions["gateway_lb_vip_set_backends"] = "sdn:write"
	permissions["gateway_lb_status"] = "sdn:read"
	permissions["gateway_nat64_status"] = "sdn:read"
	// gateway_perf_flows mutates bridge flow tables (ephemeral install +
	// cookie-scoped delete), so it requires sdn:write; the counters are
	// read-only.
	permissions["gateway_perf_flows"] = "sdn:write"
	permissions["gateway_perf_datapath"] = "sdn:read"
	permissions["gateway_perf_conntrack"] = "sdn:read"

	permissions["sdn_get_port_state"] = "sdn:read"
	permissions["sdn_set_port_state"] = "sdn:write"
	permissions["sdn_list_bridges"] = "sdn:read"
	permissions["sdn_create_bridge"] = "sdn:write"
	permissions["sdn_delete_bridge"] = "sdn:delete"
	permissions["sdn_add_port"] = "sdn:write"
	permissions["sdn_delete_port"] = "sdn:delete"
	permissions["sdn_apply_policy"] = "sdn:write"
	permissions["sdn_get_policy"] = "sdn:read"
	permissions["sdn_list_policies"] = "sdn:read"

	// Proxy (reverse-proxy configuration) tools
	permissions["proxy_route_create"] = "proxy:write"
	permissions["proxy_route_get"] = "proxy:read"
	permissions["proxy_route_update"] = "proxy:write"
	permissions["proxy_route_delete"] = "proxy:delete"
	permissions["proxy_route_list"] = "proxy:read"
	permissions["proxy_pool_create"] = "proxy:write"
	permissions["proxy_pool_get"] = "proxy:read"
	permissions["proxy_pool_update"] = "proxy:write"
	permissions["proxy_pool_delete"] = "proxy:delete"
	permissions["proxy_pool_list"] = "proxy:read"
	permissions["proxy_config"] = "proxy:read"
	permissions["proxy_status"] = "proxy:read"
	permissions["proxy_config_reload"] = "proxy:write"
	permissions["proxy_zone_matrix"] = "proxy:read"

	// NTP (time synchronization) tools. ntp_step mutates the system clock,
	// so it requires ntp:write; the readings are ntp:read.
	permissions["ntp_status"] = "ntp:read"
	permissions["ntp_sources"] = "ntp:read"
	permissions["ntp_step"] = "ntp:write"

	// VPN control-plane tools. Enrolment changes are vpn:write and the
	// readings vpn:read; posture policies decide who is admitted, so every
	// posture-policy tool is vpn:admin (docs/vpn/api.md).
	permissions["vpn_peer_enrol"] = "vpn:write"
	permissions["vpn_peer_list"] = "vpn:read"
	permissions["vpn_peer_revoke"] = "vpn:write"
	permissions["vpn_status"] = "vpn:read"
	permissions["vpn_posture_policy_get"] = "vpn:admin"
	permissions["vpn_posture_policy_set"] = "vpn:admin"
	permissions["vpn_posture_policy_delete"] = "vpn:admin"
	permissions["vpn_posture_policy_list"] = "vpn:admin"

	// PIV tools. Generate, Import, Sign and Reset change key material or use a
	// private key, so they require piv:write; the rest are reads.
	permissions["platform_piv_list_devices"] = "piv:read"
	permissions["platform_piv_list_slots"] = "piv:read"
	permissions["platform_piv_slot_info"] = "piv:read"
	permissions["platform_piv_attest"] = "piv:read"
	permissions["platform_piv_generate"] = "piv:write"
	permissions["platform_piv_import"] = "piv:write"
	permissions["platform_piv_sign"] = "piv:write"
	permissions["platform_piv_reset"] = "piv:write"

	// FIDO2 tools. Register and Authenticate drive a user-presence ceremony on
	// the token; enumeration is a read.
	permissions["platform_fido2_list_devices"] = "fido2:read"
	permissions["platform_fido2_wait_device"] = "fido2:read"
	permissions["platform_fido2_info"] = "fido2:read"
	permissions["platform_fido2_register"] = "fido2:write"
	permissions["platform_fido2_authenticate"] = "fido2:write"

	// Ceremony tools. Init and Status are scoped, not pre-auth: first boot has
	// no token to present, so it runs over the Unix socket (not token-gated) or
	// the pre-auth REST /init route. Over MCP an unauthenticated Init would let
	// a remote caller seize an uninitialized platform.
	permissions["platform_ceremony_status"] = "ceremony:read"
	permissions["platform_ceremony_init"] = "ceremony:write"
	permissions["platform_ceremony_claim_cert_begin"] = "ceremony:write"
	permissions["platform_ceremony_claim_cert_complete"] = "ceremony:write"
	permissions["platform_ceremony_claim_share_begin"] = "ceremony:write"
	permissions["platform_ceremony_claim_share_complete"] = "ceremony:write"
	permissions["platform_ceremony_sign_csr"] = "ceremony:write"

	// CA: signing a CSR certifies a KMS key for code signing, which is what
	// the boot chain of every netbooted device trusts. It needs its own
	// admin-level scope; certs:generate, which issues ordinary certificates,
	// does not confer it (#691).
	permissions["ca_sign_csr"] = "ca:sign-csr"

	// The other CA tools carry exactly the scope of their gRPC CAService
	// twin (pkg/api/grpc/method_permissions.go); QUIC's opcode table
	// (pkg/api/quic/auth.go) agrees wherever it maps the operation. REST's
	// split is not a scope and cannot be copied here: issue, get, list and
	// revoke sit behind the admin role, and info, crl and bundle are public
	// (docs/ca/api.md §4). Certificates are go-qrdb's certs family; the CA's
	// own metadata, CRL and bundle are ca:read.
	permissions["ca_issue"] = "certs:generate"
	permissions["ca_renew"] = "certs:generate"
	permissions["ca_revoke"] = "certs:revoke"
	permissions["ca_get"] = "certs:read"
	permissions["ca_list"] = "certs:list"
	permissions["ca_verify"] = "certs:read"
	permissions["ca_info"] = "ca:read"
	permissions["ca_crl"] = "ca:read"
	permissions["ca_bundle"] = "ca:read"

	// Health tools (no auth required)
	permissions["platform_health"] = ""
	permissions["platform_liveness"] = ""
	permissions["platform_readiness"] = ""

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
	permissions["platform_invitation_create"] = "invitation:write"
	permissions["platform_invitation_list"] = "invitation:read"
	permissions["platform_invitation_get"] = "invitation:read"
	permissions["platform_invitation_revoke"] = "invitation:write"
	permissions["platform_invitation_delete"] = "invitation:delete"

	// The invitation token IS the credential for these two, exactly as on the
	// ungated REST routes: an invitee has no platform session by construction,
	// and both tools take `token` as a required parameter. An empty permission
	// is the faithful expression of that, not an under-authorization — but it
	// must stay an EXPLICIT entry rather than relying on a default, which is
	// the whole point of the change below.
	permissions["platform_invitation_get_by_token"] = ""
	permissions["platform_invitation_accept"] = ""

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
	permissions["platform_bmc_power_status"] = "bmc:read"
	permissions["platform_bmc_get_boot_device"] = "bmc:read"
	permissions["platform_bmc_virtual_media_status"] = "bmc:read"
	permissions["platform_bmc_get_sensors"] = "bmc:read"
	permissions["platform_bmc_get_system_info"] = "bmc:read"
	permissions["platform_bmc_list_users"] = "bmc:read"
	permissions["platform_bmc_get_web_certificate"] = "bmc:read"

	permissions["platform_bmc_power_on"] = "bmc:write"
	permissions["platform_bmc_set_boot_device"] = "bmc:write"

	permissions["platform_bmc_power_off"] = "bmc:power"
	permissions["platform_bmc_power_reset"] = "bmc:power"
	permissions["platform_bmc_power_cycle"] = "bmc:power"

	permissions["platform_bmc_mount_iso"] = "bmc:media"
	permissions["platform_bmc_unmount_iso"] = "bmc:media"

	permissions["platform_bmc_enroll"] = "bmc:admin"
	permissions["platform_bmc_cert_restore"] = "bmc:admin"

	return permissions
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
