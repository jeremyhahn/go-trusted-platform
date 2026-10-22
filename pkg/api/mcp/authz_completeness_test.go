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
	"io"
	"log/slog"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// TestEveryRegisteredToolIsClassified walks the tool registry the server
// actually builds, rather than scanning source for tool definitions. A source
// scan encodes an assumption about how tools get registered; ListTools()
// observes the result, so a tool added through any future mechanism is still
// caught.
func TestEveryRegisteredToolIsClassified(t *testing.T) {
	log := logging.NewLogger(slog.LevelError, io.Discard)
	registry := NewToolRegistry(nil, log)
	checker := NewAuthorizationChecker(nil, nil)

	var unclassified []string
	for _, tool := range registry.ListTools() {
		if _, ok := checker.toolPermissions[tool.Name]; !ok {
			unclassified = append(unclassified, tool.Name)
		}
	}

	sort.Strings(unclassified)
	assert.Empty(t, unclassified,
		"these tools are registered with no permission entry, so AuthorizeTool "+
			"refuses them. Give each the resource:action scope of its gRPC, QUIC or "+
			"REST twin in toolPermissionCatalog, or an explicit \"\" if it genuinely "+
			"needs none.")
}

// TestInvitationToolsAreClassified pins the #300 fix specifically: the seven
// invitation tools mirror the REST split by principal, five admin-gated and
// two authenticated by the invitation token itself.
func TestInvitationToolsAreClassified(t *testing.T) {
	checker := NewAuthorizationChecker(nil, nil)

	for tool, want := range map[string]string{
		"platform_invitation_create": "invitation:write",
		"platform_invitation_list":   "invitation:read",
		"platform_invitation_get":    "invitation:read",
		"platform_invitation_revoke": "invitation:write",
		"platform_invitation_delete": "invitation:delete",
		// The invitation token is the credential, exactly as on the ungated
		// REST invitee routes. Explicit, not a default.
		"platform_invitation_get_by_token": "",
		"platform_invitation_accept":       "",
	} {
		got, ok := checker.toolPermissions[tool]
		require.True(t, ok, "%s must have an explicit permission entry", tool)
		assert.Equal(t, want, got, "%s", tool)
	}
}

// allowAllAuthService is a stub that grants every permission it is asked
// about. It exists so the tests below cannot pass merely because the caller
// lacked a grant — if a tool is refused with this backend installed, it is
// refused for want of a permission MAPPING, which is the behaviour #300 is
// about.
type allowAllAuthService struct{}

func (allowAllAuthService) CheckPermission(context.Context, string, string, string) (bool, error) {
	return true, nil
}

// TestUnclassifiedToolIsDenied is the behavioural half of this change, and the
// one the completeness lists cannot provide. Reverting AuthorizeTool's default
// from deny back to allow leaves every list assertion above passing — the map
// is still complete, it is simply no longer consulted for unknown tools. Only
// calling AuthorizeTool catches that.
func TestUnclassifiedToolIsDenied(t *testing.T) {
	checker := NewAuthorizationChecker(allowAllAuthService{}, nil)

	// A name that is deliberately not registered and not in the map.
	_, err := checker.AuthorizeTool(context.Background(), "platform_not_a_real_tool", "any-token")

	require.NotNil(t, err, "a tool with no permission mapping must be refused, not served")
	assert.Equal(t, AuthErrorToolNotClassified, err.Type,
		"the refusal must say the tool is unclassified, not that permission was denied — "+
			"an operator told 'permission denied' will hunt their own grants for a gap "+
			"that is in the platform's configuration")
}

// TestClassifiedToolWithEmptyPermissionIsAllowed guards the other direction:
// an explicit "" means "no permission required" and must still be served, or
// the two invitee invitation tools break.
func TestClassifiedToolWithEmptyPermissionIsAllowed(t *testing.T) {
	checker := NewAuthorizationChecker(allowAllAuthService{}, nil)

	_, err := checker.AuthorizeTool(context.Background(), "platform_invitation_accept", "any-token")

	assert.Nil(t, err, "an explicit empty permission must still be allowed")
}

// TestBMCToolsAreClassified pins #304's first tranche. Every BMC tool is
// asserted by name and scope, so a later edit that loosens one — or drops a
// tool's entry from the map — fails here rather than silently widening
// what a single grant confers.
//
// Read/write is drawn on EFFECT, not on the REST shape: docs/bmc/api.md:64
// records that all four power mutators share one path and method, so REST
// cannot separate them by path. MCP has four tools and does.
func TestBMCToolsAreClassified(t *testing.T) {
	checker := NewAuthorizationChecker(nil, nil)

	for tool, want := range map[string]string{
		// Observation only.
		"platform_bmc_power_status":         "bmc:read",
		"platform_bmc_get_boot_device":      "bmc:read",
		"platform_bmc_virtual_media_status": "bmc:read",
		"platform_bmc_get_sensors":          "bmc:read",
		"platform_bmc_get_system_info":      "bmc:read",
		"platform_bmc_list_users":           "bmc:read",
		"platform_bmc_get_web_certificate":  "bmc:read",
		"platform_bmc_provision_status":     "bmc:read",
		// Changes the machine's state or its credentials.
		"platform_bmc_power_on":                "bmc:write",
		"platform_bmc_power_off":               "bmc:power",
		"platform_bmc_power_reset":             "bmc:power",
		"platform_bmc_power_cycle":             "bmc:power",
		"platform_bmc_set_boot_device":         "bmc:write",
		"platform_bmc_mount_iso":               "bmc:media",
		"platform_bmc_unmount_iso":             "bmc:media",
		"platform_bmc_enroll":                  "bmc:admin",
		"platform_bmc_cert_restore":            "bmc:admin",
		"platform_bmc_provision":               "bmc:admin",
		"platform_bmc_replace_web_certificate": "bmc:admin",
		"platform_bmc_create_user":             "bmc:admin",
		"platform_bmc_delete_user":             "bmc:admin",
		"platform_bmc_set_user_password":       "bmc:admin",
		"platform_bmc_set_user_privilege":      "bmc:admin",
	} {
		got, ok := checker.toolPermissions[tool]
		require.True(t, ok, "%s must have an explicit permission entry", tool)
		assert.Equal(t, want, got, "%s", tool)
	}
}

// TestPXEToolsAreClassified pins every PXE tool to the scope of its gRPC
// PXEService method by name (#704), so a later edit that loosens one fails
// here rather than silently widening what a single grant confers.
func TestPXEToolsAreClassified(t *testing.T) {
	checker := NewAuthorizationChecker(nil, nil)

	for tool, want := range map[string]string{
		// Observation only.
		"pxe_list_devices":      "pxe:read",
		"pxe_get_device":        "pxe:read",
		"pxe_get_device_by_mac": "pxe:read",
		"pxe_get_device_events": "pxe:read",
		"pxe_service_status":    "pxe:read",
		// Moves a device through the workflow, or starts and stops the service.
		"pxe_register_device":     "pxe:write",
		"pxe_update_state":        "pxe:write",
		"pxe_set_device_enrolled": "pxe:write",
		"pxe_authorize_device":    "pxe:write",
		"pxe_quarantine_device":   "pxe:write",
		"pxe_retry_device":        "pxe:write",
		"pxe_start_service":       "pxe:write",
		"pxe_stop_service":        "pxe:write",
		"pxe_webhook_complete":    "pxe:write",
		// Removes a device.
		"pxe_remove_device": "pxe:delete",
	} {
		got, ok := checker.toolPermissions[tool]
		require.True(t, ok, "%s must have an explicit permission entry", tool)
		assert.Equal(t, want, got, "%s", tool)
	}
}

// TestTPMQuoteToolsAreClassified: the quote and certify tools carry the scope
// of their gRPC TPMService twin, so an MCP caller reaches the same service
// (#482, #317).
func TestTPMQuoteToolsAreClassified(t *testing.T) {
	checker := NewAuthorizationChecker(nil, nil)

	for _, tool := range []string{"platform_tpm_quote", "platform_tpm_verify_quote", "platform_tpm_certify"} {
		got, ok := checker.toolPermissions[tool]
		require.True(t, ok, "%s must have an explicit permission entry", tool)
		assert.Equal(t, "tpm:read", got, "%s", tool)
	}
}

// TestTPMNVToolsAreClassified pins each NV tool to the scope its gRPC
// TPMService twin requires (pkg/api/grpc/method_permissions.go), and
// pcr_extend to the scope of QUIC's SubOpTPM2ExtendPCR.
func TestTPMNVToolsAreClassified(t *testing.T) {
	checker := NewAuthorizationChecker(nil, nil)

	want := map[string]string{
		"platform_tpm_nv_list":    "tpm:read",
		"platform_tpm_nv_read":    "tpm:read",
		"platform_tpm_nv_write":   "tpm:write",
		"platform_tpm_nv_delete":  "tpm:delete",
		"platform_tpm_pcr_extend": "tpm:write",
	}
	for tool, scope := range want {
		got, ok := checker.toolPermissions[tool]
		require.True(t, ok, "%s must have an explicit permission entry", tool)
		assert.Equal(t, scope, got, "%s", tool)
	}
}

// TestIAMToolClassification pins every IAM tool to the scope of its gRPC twin;
// iam_authenticate is open, as its QUIC twin is pre-auth.
func TestIAMToolClassification(t *testing.T) {
	checker := NewAuthorizationChecker(nil, nil)

	// Each scope is the one pkg/api/grpc/method_permissions.go gives the
	// PlatformIAMService method the tool answers through.
	want := map[string]string{
		"iam_create_user":         "iam:write",
		"iam_get_user":            "iam:read",
		"iam_list_users":          "iam:read",
		"iam_delete_user":         "iam:delete",
		"iam_create_role":         "iam:write",
		"iam_get_role":            "iam:read",
		"iam_list_roles":          "iam:read",
		"iam_delete_role":         "iam:delete",
		"iam_assign_role":         "iam:write",
		"iam_revoke_role":         "iam:write",
		"iam_create_group":        "iam:write",
		"iam_update_user":         "iam:write",
		"iam_update_group":        "iam:write",
		"iam_update_role":         "iam:write",
		"iam_get_group":           "iam:read",
		"iam_list_groups":         "iam:read",
		"iam_delete_group":        "iam:delete",
		"iam_add_group_member":    "iam:write",
		"iam_remove_group_member": "iam:write",
		"iam_check_permission":    "iam:read",
		"iam_create_tenant":       "iam:write",
		"iam_get_tenant":          "iam:read",
		"iam_list_tenants":        "iam:read",
		"iam_delete_tenant":       "iam:delete",
		"iam_verify_token":        "iam:read",
		"iam_create_token":        "iam:write",
		"iam_revoke_token":        "iam:write",
		// The credential exchange is open, as QUIC's preAuthOpcodes records.
		"iam_authenticate": "",
	}
	for tool, scope := range want {
		got, ok := checker.toolPermissions[tool]
		require.True(t, ok, "%s must have an explicit permission entry", tool)
		assert.Equal(t, scope, got, "%s", tool)
	}
}

// TestIAMToolsAuthorizeByScope shows the IAM entries decide access: a caller
// holding only iam:read reaches iam_list_users and is refused iam_create_user
// (iam:write) and iam_delete_user (iam:delete).
func TestIAMToolsAuthorizeByScope(t *testing.T) {
	readOnly := &mockAuthorizationService{
		checkFunc: func(_ context.Context, _, resource, action string) (bool, error) {
			return resource == "iam" && action == "read", nil
		},
	}
	checker := NewAuthorizationChecker(readOnly, nil)

	assert.Nil(t, checker.CheckToolAuthorization(context.Background(), "iam_list_users", "token"))

	for tool, action := range map[string]string{"iam_create_user": "write", "iam_delete_user": "delete"} {
		err := checker.CheckToolAuthorization(context.Background(), tool, "token")
		require.NotNil(t, err, "%s needs iam:%s", tool, action)
		assert.Equal(t, AuthErrorPermissionDenied, err.Type, "%s", tool)
		assert.Equal(t, action, readOnly.lastAction, "%s", tool)
	}
}

// TestLastClassifiedToolsAuthorizeByScope pins the tools #304 classified last
// to the scope their twin carries on the other transports: a caller holding
// that scope is admitted, and a caller holding every other action on the same
// resource is refused.
func TestLastClassifiedToolsAuthorizeByScope(t *testing.T) {
	cases := []struct {
		tool     string
		resource string
		action   string
	}{
		// gRPC TPMService DeleteEK and DeleteSRK; REST tpmScopeDelete.
		{"platform_tpm_ek_delete", "tpm", "delete"},
		{"platform_tpm_srk_delete", "tpm", "delete"},
		// QUIC SubOpTPM2DeleteIAK.
		{"platform_tpm_iak_delete", "tpm", "delete"},
		// gRPC LUKSService TestUnlock.
		{"platform_luks_test_unlock", "luks", "read"},
		// gRPC PlatformIAMService CreateToken and RevokeToken.
		{"iam_create_token", "iam", "write"},
		{"iam_revoke_token", "iam", "write"},
		// QUIC OpDaemonListProtocols.
		{"platform_daemon_list_protocols", "platform", "read"},
		// gRPC ComputeService ListSnapshots.
		{"vm_snapshot_get", "vm", "read"},
	}
	for _, tc := range cases {
		t.Run(tc.tool+"/admitted", func(t *testing.T) {
			exact := &mockAuthorizationService{
				checkFunc: func(_ context.Context, _, resource, action string) (bool, error) {
					return resource == tc.resource && action == tc.action, nil
				},
			}
			checker := NewAuthorizationChecker(exact, nil)

			assert.Nil(t, checker.CheckToolAuthorization(context.Background(), tc.tool, "token"))
		})

		t.Run(tc.tool+"/denied", func(t *testing.T) {
			otherActions := &mockAuthorizationService{
				checkFunc: func(_ context.Context, _, resource, action string) (bool, error) {
					return resource == tc.resource && action != tc.action, nil
				},
			}
			checker := NewAuthorizationChecker(otherActions, nil)

			err := checker.CheckToolAuthorization(context.Background(), tc.tool, "token")
			require.NotNil(t, err, "%s needs %s:%s", tc.tool, tc.resource, tc.action)
			assert.Equal(t, AuthErrorPermissionDenied, err.Type)
			assert.Equal(t, tc.action, otherActions.lastAction)
		})
	}
}

// TestIAMAuthenticateIsOpen: iam_authenticate is the credential exchange that
// mints a token, so it is admitted without one even by a backend that grants
// nothing, as QUIC's preAuthOpcodes admits OpIAMAuthenticate.
func TestIAMAuthenticateIsOpen(t *testing.T) {
	denyAll := &mockAuthorizationService{
		checkFunc: func(context.Context, string, string, string) (bool, error) {
			return false, nil
		},
	}
	checker := NewAuthorizationChecker(denyAll, nil)

	_, err := checker.AuthorizeTool(context.Background(), "iam_authenticate", "")

	assert.Nil(t, err, "the credential exchange cannot require the token it issues")
}

// TestOverlayToolsAreClassified pins each overlay tool to the scope its gRPC
// OverlayService twin requires (pkg/api/grpc/method_permissions.go).
func TestOverlayToolsAreClassified(t *testing.T) {
	checker := NewAuthorizationChecker(nil, nil)

	want := map[string]string{
		"overlay_status":       "sdn:read",
		"overlay_vtep_list":    "sdn:read",
		"overlay_vtep_get":     "sdn:read",
		"overlay_vni_list":     "sdn:read",
		"overlay_vni_create":   "sdn:write",
		"overlay_vni_delete":   "sdn:delete",
		"overlay_tunnel_list":  "sdn:read",
		"overlay_tunnel_stats": "sdn:read",
		"overlay_mac_list":     "sdn:read",
		"overlay_mac_forget":   "sdn:write",
	}
	for tool, scope := range want {
		got, ok := checker.toolPermissions[tool]
		require.True(t, ok, "%s must have an explicit permission entry", tool)
		assert.Equal(t, scope, got, "%s", tool)
	}
}

// TestSwitchClusterRegistryToolsAreClassified pins each switch, cluster and
// registry tool (#304) to the scope its gRPC twin requires in
// method_permissions.go.
func TestSwitchClusterRegistryToolsAreClassified(t *testing.T) {
	checker := NewAuthorizationChecker(nil, nil)

	want := map[string]string{
		"switch_list_ports":   "switch:read",
		"switch_port_status":  "switch:read",
		"switch_enable_port":  "switch:write",
		"switch_disable_port": "switch:write",
		"switch_set_vlan":     "switch:write",

		"platform_cluster_status":     "cluster:read",
		"platform_cluster_list_nodes": "cluster:read",
		"platform_cluster_bootstrap":  "cluster:write",
		"platform_cluster_join":       "cluster:write",
		"platform_cluster_leave":      "cluster:write",

		"platform_registry_status":  "registry:read",
		"platform_registry_list":    "registry:read",
		"platform_registry_inspect": "registry:read",
		"platform_registry_delete":  "registry:delete",
	}
	for tool, scope := range want {
		got, ok := checker.toolPermissions[tool]
		require.True(t, ok, "%s must have an explicit permission entry", tool)
		assert.Equal(t, scope, got, "%s", tool)
	}
}

// TestOverlayToolsAuthorizeByScope shows the overlay entries decide access: a
// caller holding only sdn:read reaches overlay_tunnel_stats and is refused
// overlay_vni_delete, which needs sdn:delete.
func TestOverlayToolsAuthorizeByScope(t *testing.T) {
	readOnly := &mockAuthorizationService{
		checkFunc: func(_ context.Context, _, resource, action string) (bool, error) {
			return resource == "sdn" && action == "read", nil
		},
	}
	checker := NewAuthorizationChecker(readOnly, nil)

	assert.Nil(t, checker.CheckToolAuthorization(context.Background(), "overlay_tunnel_stats", "token"))

	err := checker.CheckToolAuthorization(context.Background(), "overlay_vni_delete", "token")
	require.NotNil(t, err, "overlay_vni_delete needs sdn:delete")
	assert.Equal(t, AuthErrorPermissionDenied, err.Type)
	assert.Equal(t, "delete", readOnly.lastAction)
}

// TestNoBMCToolIsUnauthenticated is the one that matters if someone later adds
// a BMC tool: it walks the registry rather than a list, so a new
// platform_bmc_* tool with no entry fails even though every assertion above
// still passes.
func TestNoBMCToolIsUnauthenticated(t *testing.T) {
	log := logging.NewLogger(slog.LevelError, io.Discard)
	registry := NewToolRegistry(nil, log)
	checker := NewAuthorizationChecker(nil, nil)

	var unauthorized []string
	for _, tool := range registry.ListTools() {
		if !strings.HasPrefix(tool.Name, "platform_bmc_") {
			continue
		}
		perm, ok := checker.toolPermissions[tool.Name]
		if !ok || perm == "" {
			unauthorized = append(unauthorized, tool.Name)
		}
	}

	sort.Strings(unauthorized)
	assert.Empty(t, unauthorized,
		"BMC tools drive hardware power and virtual media; none may be "+
			"unclassified, and none may carry an empty permission")
}
