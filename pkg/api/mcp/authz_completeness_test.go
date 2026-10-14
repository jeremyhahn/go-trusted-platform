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

// knownUnclassified names every registered MCP tool that has no entry in
// AuthorizationChecker.toolPermissions.
//
// These tools are NOT safe. Until #300 they were served unauthorized by a
// default-allow in AuthorizeTool; that default is now deny, so each of these
// is refused with AuthErrorToolNotClassified rather than executed. The list
// exists so the gap is visible in the tree to anyone reading, instead of
// being discoverable only by running the registry diff.
//
// THIS LIST MAY ONLY SHRINK. The test below fails if:
//
//   - a registered tool appears in neither the permission map nor this list —
//     so a newly registered tool cannot silently join the unauthorized set;
//   - a name here also has a permission entry — a stale line to delete once
//     the tool is classified;
//   - a name here is not registered at all — a stale line for a tool that no
//     longer exists.
//
// Classifying these is #304, ordered worst-first: BMC, then KMS and IAM, then
// TPM/vTPM, then tenant. Note some tenant tools cannot be correctly authorized
// until MCP can express RequireSystemTenant (#299) — for those, leaving the
// tool unregistered is better than granting a scope weaker than its own REST
// route.
var knownUnclassified = []string{
	"activate_credential",
	"attestation_attest_workload",
	"attestation_create_manifest",
	"attestation_create_policy",
	"attestation_create_report",
	"attestation_delete_manifest",
	"attestation_delete_policy",
	"attestation_evaluate_policy",
	"attestation_get_manifest",
	"attestation_get_policy",
	"attestation_get_report",
	"attestation_list_manifests",
	"attestation_list_policies",
	"attestation_list_reports",
	"attestation_verify_manifest",
	"attestation_verify_workload",
	"container_attest",
	"container_create",
	"container_exec",
	"container_get",
	"container_list",
	"container_logs",
	"container_metrics",
	"container_remove",
	"container_start",
	"container_stop",
	"device_attributes",
	"dns_lookup",
	"dns_record_create",
	"dns_record_delete",
	"dns_record_get",
	"dns_record_list",
	"dns_record_update",
	"dns_reverse_lookup",
	"dns_zone_create",
	"dns_zone_delete",
	"dns_zone_get",
	"dns_zone_list",
	"dns_zone_update",
	"iak_csr",
	"iak_delete",
	"iak_delete_cert",
	"iak_exists",
	"iak_generate",
	"iak_get_cert",
	"iak_info",
	"iak_install_cert",
	"iam_add_group_member",
	"iam_assign_role",
	"iam_authenticate",
	"iam_check_permission",
	"iam_create_group",
	"iam_create_role",
	"iam_create_tenant",
	"iam_create_token",
	"iam_create_user",
	"iam_delete_group",
	"iam_delete_role",
	"iam_delete_tenant",
	"iam_delete_user",
	"iam_get_group",
	"iam_get_role",
	"iam_get_tenant",
	"iam_get_user",
	"iam_list_groups",
	"iam_list_roles",
	"iam_list_tenants",
	"iam_list_users",
	"iam_remove_group_member",
	"iam_revoke_role",
	"iam_revoke_token",
	"iam_verify_token",
	"idevid_create_ldevid",
	"idevid_csr",
	"idevid_delete",
	"idevid_delete_cert",
	"idevid_exists",
	"idevid_generate",
	"idevid_get_cert",
	"idevid_info",
	"idevid_install_cert",
	"kms_backend_status",
	"kms_decrypt",
	"kms_delete_key",
	"kms_encrypt",
	"kms_export_public_key",
	"kms_generate_data_key",
	"kms_generate_key",
	"kms_generate_wrapped_data_key",
	"kms_get_key",
	"kms_get_key_metadata",
	"kms_get_key_policy",
	"kms_list_keys",
	"kms_random",
	"kms_revoke_key",
	"kms_rotate_key",
	"kms_set_key_policy",
	"kms_sign",
	"kms_supported_algorithms",
	"kms_update_key_metadata",
	"kms_verify",
	"platform_cluster_bootstrap",
	"platform_cluster_join",
	"platform_cluster_leave",
	"platform_cluster_list_nodes",
	"platform_cluster_status",
	"platform_daemon_get_service",
	"platform_daemon_list_protocols",
	"platform_daemon_list_services",
	"platform_daemon_restart_service",
	"platform_daemon_start_service",
	"platform_daemon_status",
	"platform_daemon_stop_service",
	"platform_daemon_version",
	"platform_eab_cleanup_expired_credentials",
	"platform_eab_create_credential",
	"platform_eab_delete_credential",
	"platform_eab_get_credential",
	"platform_eab_get_credential_by_key_id",
	"platform_eab_get_credential_qr_code",
	"platform_eab_get_enrollment_url",
	"platform_eab_list_credentials",
	"platform_eab_mark_credential_used",
	"platform_eab_revoke_credential",
	"platform_eab_validate_credential",
	"platform_luks_change_passphrase",
	"platform_luks_enroll_fido2",
	"platform_luks_enroll_passphrase",
	"platform_luks_enroll_recovery",
	"platform_luks_enroll_tpm",
	"platform_luks_info",
	"platform_luks_list_slots",
	"platform_luks_remove_key",
	"platform_luks_status",
	"platform_luks_test_unlock",
	"platform_registry_delete",
	"platform_registry_inspect",
	"platform_registry_list",
	"platform_registry_status",
	"platform_tenant_barrier_init",
	"platform_tenant_barrier_seal",
	"platform_tenant_barrier_status",
	"platform_tenant_barrier_unseal",
	"platform_tpm_activate_credential",
	"platform_tpm_capabilities",
	"platform_tpm_certify",
	"platform_tpm_clear",
	"platform_tpm_ek",
	"platform_tpm_ek_cert",
	"platform_tpm_ek_create",
	"platform_tpm_ek_delete",
	"platform_tpm_ek_import_cert",
	"platform_tpm_eventlog",
	"platform_tpm_iak",
	"platform_tpm_iak_create",
	"platform_tpm_iak_delete",
	"platform_tpm_info",
	"platform_tpm_make_credential",
	"platform_tpm_nv_delete",
	"platform_tpm_nv_list",
	"platform_tpm_nv_read",
	"platform_tpm_nv_write",
	"platform_tpm_pcr_extend",
	"platform_tpm_pcrs",
	"platform_tpm_platform",
	"platform_tpm_provision",
	"platform_tpm_random",
	"platform_tpm_seal",
	"platform_tpm_srk",
	"platform_tpm_srk_create",
	"platform_tpm_srk_delete",
	"platform_tpm_unseal",
	"provision_fetch_config",
	"provision_fulfill_session",
	"provision_get_nonce",
	"provision_get_session",
	"provision_list_sessions",
	"provision_poll_session",
	"provision_sign_digest",
	"sdn_add_flow",
	"sdn_authenticate_port",
	"sdn_create_vlan",
	"sdn_delete_flow",
	"sdn_delete_vlan",
	"sdn_flush_flows",
	"sdn_get_flow_stats",
	"sdn_get_port_stats",
	"sdn_list_flows",
	"sdn_list_vlans",
	"sdn_revoke_port_auth",
	"secret_delete",
	"secret_get",
	"secret_get_rotation_policy",
	"secret_list",
	"secret_set_rotation_policy",
	"secret_store",
	"switch_disable_port",
	"switch_enable_port",
	"switch_list_ports",
	"switch_port_status",
	"switch_set_vlan",
	"tenant_check_quota",
	"tenant_create",
	"tenant_delete",
	"tenant_get",
	"tenant_get_by_name",
	"tenant_get_dek_status",
	"tenant_get_quotas",
	"tenant_get_usage",
	"tenant_list",
	"tenant_resume",
	"tenant_rotate_dek",
	"tenant_suspend",
	"tenant_sync",
	"tenant_update",
	"tenant_update_quotas",
	"vm_attest",
	"vm_attest_verify",
	"vm_create",
	"vm_delete",
	"vm_disk_attach",
	"vm_disk_detach",
	"vm_disk_resize",
	"vm_get",
	"vm_list",
	"vm_logs",
	"vm_metrics",
	"vm_migrate",
	"vm_reboot",
	"vm_resume",
	"vm_snapshot_create",
	"vm_snapshot_delete",
	"vm_snapshot_get",
	"vm_snapshot_list",
	"vm_snapshot_restore",
	"vm_start",
	"vm_stop",
	"vm_suspend",
	"vm_update",
	"vtpm_bundle_create",
	"vtpm_bundle_delete",
	"vtpm_bundle_get",
	"vtpm_bundle_list",
	"vtpm_bundle_pcr_extend",
	"vtpm_bundle_pcr_read",
	"vtpm_bundle_quote",
	"vtpm_bundle_seal",
	"vtpm_bundle_unseal",
	"vtpm_export",
	"vtpm_get",
	"vtpm_get_bundle_path",
	"vtpm_get_nvram_path",
	"vtpm_get_tpm_socket_path",
	"vtpm_import",
	"vtpm_is_running",
	"vtpm_template_clone",
	"vtpm_template_create",
	"vtpm_template_delete",
	"vtpm_template_get",
	"vtpm_template_list",
	"vtpm_validate",
}

// TestEveryRegisteredToolIsClassified walks the tool registry the server
// actually builds, rather than scanning source for tool definitions. A source
// scan encodes an assumption about how tools get registered; ListTools()
// observes the result, so a tool added through any future mechanism is still
// caught.
func TestEveryRegisteredToolIsClassified(t *testing.T) {
	log := logging.NewLogger(slog.LevelError, io.Discard)
	registry := NewToolRegistry(nil, log)
	checker := NewAuthorizationChecker(nil, nil)

	unclassified := make(map[string]bool, len(knownUnclassified))
	for _, name := range knownUnclassified {
		unclassified[name] = true
	}

	registered := make(map[string]bool)
	var undeclared []string
	for _, tool := range registry.ListTools() {
		registered[tool.Name] = true
		_, hasPermission := checker.toolPermissions[tool.Name]
		if !hasPermission && !unclassified[tool.Name] {
			undeclared = append(undeclared, tool.Name)
		}
	}

	sort.Strings(undeclared)
	assert.Empty(t, undeclared,
		"these tools are registered with no permission entry and are not in "+
			"knownUnclassified. Give each a resource:action entry in "+
			"toolPermissionCatalog, or an explicit \"\" if it genuinely needs none. "+
			"Do not add them to knownUnclassified — that list may only shrink.")
}

// TestKnownUnclassifiedHasNoStaleEntries is the ratchet. Once a tool is given
// a permission, its line here must go, so the list cannot quietly stop
// shrinking while #304 reports progress.
func TestKnownUnclassifiedHasNoStaleEntries(t *testing.T) {
	log := logging.NewLogger(slog.LevelError, io.Discard)
	registry := NewToolRegistry(nil, log)
	checker := NewAuthorizationChecker(nil, nil)

	registered := make(map[string]bool)
	for _, tool := range registry.ListTools() {
		registered[tool.Name] = true
	}

	listed := make(map[string]bool, len(knownUnclassified))
	var nowClassified, noLongerRegistered, listedTwice []string
	for _, name := range knownUnclassified {
		if listed[name] {
			listedTwice = append(listedTwice, name)
		}
		listed[name] = true
		if _, ok := checker.toolPermissions[name]; ok {
			nowClassified = append(nowClassified, name)
		}
		if !registered[name] {
			noLongerRegistered = append(noLongerRegistered, name)
		}
	}

	sort.Strings(nowClassified)
	sort.Strings(noLongerRegistered)
	assert.Empty(t, nowClassified,
		"these tools now have a permission entry — delete their lines from "+
			"knownUnclassified")
	assert.Empty(t, noLongerRegistered,
		"these tools are no longer registered — delete their lines from "+
			"knownUnclassified")
	assert.Empty(t, listedTwice,
		"these tools appear more than once in knownUnclassified — keep one line each")
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

// TestUnclassifiedRegisteredToolIsDenied uses a real registered tool that is
// still on knownUnclassified, so the assertion tracks the actual gap rather
// than an invented name.
func TestUnclassifiedRegisteredToolIsDenied(t *testing.T) {
	require.NotEmpty(t, knownUnclassified, "nothing left to assert once #304 completes; delete this test then")
	checker := NewAuthorizationChecker(allowAllAuthService{}, nil)

	_, err := checker.AuthorizeTool(context.Background(), knownUnclassified[0], "any-token")

	require.NotNil(t, err, "%s is registered with no permission mapping and must be refused", knownUnclassified[0])
	assert.Equal(t, AuthErrorToolNotClassified, err.Type)
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
// tool back into knownUnclassified — fails here rather than silently widening
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
		// Changes the machine's state or its credentials.
		"platform_bmc_power_on":        "bmc:write",
		"platform_bmc_power_off":       "bmc:power",
		"platform_bmc_power_reset":     "bmc:power",
		"platform_bmc_power_cycle":     "bmc:power",
		"platform_bmc_set_boot_device": "bmc:write",
		"platform_bmc_mount_iso":       "bmc:media",
		"platform_bmc_unmount_iso":     "bmc:media",
		"platform_bmc_enroll":          "bmc:admin",
		"platform_bmc_cert_restore":    "bmc:admin",
	} {
		got, ok := checker.toolPermissions[tool]
		require.True(t, ok, "%s must have an explicit permission entry", tool)
		assert.Equal(t, want, got, "%s", tool)
	}
}

// TestTPMQuoteToolsAreClassified: the quote tools carry the scope of their
// gRPC TPMService twin, so an MCP caller reaches the same service (#482).
func TestTPMQuoteToolsAreClassified(t *testing.T) {
	checker := NewAuthorizationChecker(nil, nil)

	for _, tool := range []string{"platform_tpm_quote", "platform_tpm_verify_quote"} {
		got, ok := checker.toolPermissions[tool]
		require.True(t, ok, "%s must have an explicit permission entry", tool)
		assert.Equal(t, "tpm:read", got, "%s", tool)
	}
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
