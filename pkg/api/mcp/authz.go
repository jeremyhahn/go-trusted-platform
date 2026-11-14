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
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/channelbind"
)

// AuthorizationChecker validates tool authorization.
type AuthorizationChecker struct {
	authService AuthorizationService
	authManager AuthManager

	// peerAuthenticator turns the verified client certificate of a
	// tokenless request into its principal; nil disables that path.
	peerAuthenticator PeerAuthenticator

	// toolPermissions maps tool names to required permissions
	toolPermissions map[string]string
}

// NewAuthorizationChecker creates a new authorization checker.
func NewAuthorizationChecker(authService AuthorizationService, authManager AuthManager, opts ...AuthorizationCheckerOption) *AuthorizationChecker {
	c := &AuthorizationChecker{
		authService:     authService,
		authManager:     authManager,
		toolPermissions: toolPermissionCatalog(),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
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

	// Each vtpm_bundle_* tool runs its vtpm_* twin's executor
	// (vtpmBundleAliases) and carries that twin's scope.
	permissions["vtpm_bundle_create"] = permissions["vtpm_create"]
	permissions["vtpm_bundle_delete"] = permissions["vtpm_delete"]
	permissions["vtpm_bundle_list"] = permissions["vtpm_list"]
	permissions["vtpm_bundle_quote"] = permissions["vtpm_quote"]
	permissions["vtpm_bundle_seal"] = permissions["vtpm_seal"]
	permissions["vtpm_bundle_unseal"] = permissions["vtpm_unseal"]
	permissions["vtpm_bundle_pcr_extend"] = permissions["vtpm_extend_pcr"]
	permissions["vtpm_bundle_pcr_read"] = permissions["vtpm_read_pcr"]

	// vTPM bundle and template tools carry the scope of their gRPC
	// VTPMService twin (pkg/api/grpc/method_permissions.go).
	permissions["vtpm_get"] = "vtpm:read"
	permissions["vtpm_bundle_get"] = permissions["vtpm_get"]
	permissions["vtpm_validate"] = "vtpm:read"
	permissions["vtpm_export"] = "vtpm:read"
	permissions["vtpm_get_bundle_path"] = "vtpm:read"
	permissions["vtpm_get_tpm_socket_path"] = "vtpm:read"
	permissions["vtpm_get_nvram_path"] = "vtpm:read"
	permissions["vtpm_is_running"] = "vtpm:read"
	permissions["vtpm_import"] = "vtpm:write"
	permissions["vtpm_template_get"] = "vtpm:read"
	permissions["vtpm_template_list"] = "vtpm:read"
	permissions["vtpm_template_create"] = "vtpm:write"
	permissions["vtpm_template_clone"] = "vtpm:write"
	permissions["vtpm_template_delete"] = "vtpm:delete"

	// Platform TPM quote and certify tools carry the scope of their gRPC TPMService twin
	// (pkg/api/grpc/method_permissions.go). The quote is channel-bound, so
	// over stdio, which has no TLS connection, the service refuses it (#482).
	permissions["platform_tpm_quote"] = "tpm:read"
	permissions["platform_tpm_verify_quote"] = "tpm:read"
	permissions["platform_tpm_certify"] = "tpm:read"

	// Platform TPM NV tools run on the gRPC TPMService and carry its scopes:
	// nv_list reads Info; nv_read, nv_write and nv_delete map to
	// ReadNVRAM / WriteNVRAM / UndefineNVRAM and are classified below.
	permissions["platform_tpm_nv_list"] = "tpm:read"

	// PCR extend has no gRPC twin; it carries the scope of QUIC's
	// SubOpTPM2ExtendPCR (pkg/api/quic/opcode_permissions.go).
	permissions["platform_tpm_pcr_extend"] = "tpm:write"

	// The rest of the platform TPM tools carry the scope of their gRPC
	// TPMService twin the same way: reads are tpm:read, key creation, seal,
	// NV writes and credential activation are tpm:write, and clearing the
	// TPM or undefining an NV index is tpm:delete.
	permissions["platform_tpm_info"] = "tpm:read"
	// capabilities and platform read a subset of what gRPC Info answers (the
	// fixed properties; the config and the EK/SRK/IAK attributes), and their
	// QUIC twins, TPM2 Capabilities and PlatformAttrs, are tpm:read.
	permissions["platform_tpm_capabilities"] = "tpm:read"
	permissions["platform_tpm_platform"] = "tpm:read"
	permissions["platform_tpm_ek"] = "tpm:read"
	permissions["platform_tpm_ek_cert"] = "tpm:read"
	permissions["platform_tpm_srk"] = "tpm:read"
	permissions["platform_tpm_iak"] = "tpm:read"
	permissions["platform_tpm_pcrs"] = "tpm:read"
	permissions["platform_tpm_eventlog"] = "tpm:read"
	permissions["platform_tpm_random"] = "tpm:read"
	permissions["platform_tpm_nv_read"] = "tpm:read"
	permissions["platform_tpm_make_credential"] = "tpm:read"
	permissions["platform_tpm_provision"] = "tpm:write"
	permissions["platform_tpm_ek_create"] = "tpm:write"
	permissions["platform_tpm_ek_import_cert"] = "tpm:write"
	permissions["platform_tpm_srk_create"] = "tpm:write"
	permissions["platform_tpm_iak_create"] = "tpm:write"
	permissions["platform_tpm_nv_write"] = "tpm:write"
	permissions["platform_tpm_activate_credential"] = "tpm:write"
	permissions["platform_tpm_clear"] = "tpm:delete"
	permissions["platform_tpm_nv_delete"] = "tpm:delete"
	permissions["platform_tpm_ek_delete"] = "tpm:delete"
	permissions["platform_tpm_srk_delete"] = "tpm:delete"
	// IAK delete carries the scope of its twins, gRPC TPMService DeleteAK
	// and QUIC's SubOpTPM2DeleteIAK (pkg/api/quic/opcode_permissions.go).
	permissions["platform_tpm_iak_delete"] = "tpm:delete"
	permissions["platform_tpm_seal"] = "tpm:write"
	// Unseal hands back the secret itself, so it needs tpm:write here. gRPC
	// Unseal is tpm:read; a read token is the wrong grant for releasing
	// sealed data, so MCP does not copy that.
	permissions["platform_tpm_unseal"] = "tpm:write"

	// DNS tools
	permissions["dns_add_record"] = "dns:write"
	permissions["dns_delete_record"] = "dns:delete"
	permissions["dns_get_record"] = "dns:read"
	permissions["dns_list_records"] = "dns:read"
	permissions["dns_resolve"] = "dns:read"
	permissions["dns_create_zone"] = "dns:write"
	permissions["dns_delete_zone"] = "dns:delete"
	permissions["dns_list_zones"] = "dns:read"
	// The DNS tools bound to the gRPC DNSService (#304) require the scope
	// of their gRPC method; the tool table carries it.
	for name, tool := range dnsTools {
		permissions[name] = tool.scope
	}

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
	// Host manifests (#304), each the scope of its gRPC method.
	permissions["attestation_get_manifest"] = "attestation:read"
	permissions["attestation_list_manifests"] = "attestation:read"
	permissions["attestation_verify_manifest"] = "attestation:read"
	permissions["attestation_create_manifest"] = "attestation:write"
	permissions["attestation_delete_manifest"] = "attestation:delete"
	// Quotes and collection (#704), each the scope of its gRPC method; the
	// tool table carries it.
	for name, tool := range attestationQuoteTools {
		permissions[name] = tool.scope
	}
	permissions["device_provision"] = "device:write"

	// Device profile tools (same scopes as the gRPC DeviceService profile
	// RPCs in pkg/api/grpc/method_permissions.go)
	permissions["profile_create"] = "device:write"
	permissions["profile_get_by_id"] = "device:read"
	permissions["profile_list_all"] = "device:read"
	permissions["profile_find_matching"] = "device:read"
	permissions["profile_find_by_mac"] = "device:read"
	permissions["profile_find_by_serial"] = "device:read"
	permissions["profile_find_config"] = "device:read"
	permissions["profile_update_by_id"] = "device:write"
	permissions["profile_delete_by_id"] = "device:delete"
	permissions["profile_assign_to_device"] = "device:write"
	permissions["profile_unassign_from_device"] = "device:write"
	permissions["device_template_create"] = "device:write"
	permissions["device_template_get"] = "device:read"
	permissions["device_template_list"] = "device:read"
	permissions["device_template_update"] = "device:write"
	permissions["device_template_delete"] = "device:delete"
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
	// Overlay tools carry the scopes of their gRPC OverlayService twins and
	// of the QUIC overlay sub-opcodes (#709).
	permissions["overlay_status"] = "sdn:read"
	permissions["overlay_vtep_list"] = "sdn:read"
	permissions["overlay_vtep_get"] = "sdn:read"
	permissions["overlay_vni_list"] = "sdn:read"
	permissions["overlay_vni_create"] = "sdn:write"
	permissions["overlay_vni_delete"] = "sdn:delete"
	permissions["overlay_tunnel_list"] = "sdn:read"
	permissions["overlay_tunnel_stats"] = "sdn:read"
	permissions["overlay_mac_list"] = "sdn:read"
	permissions["overlay_mac_forget"] = "sdn:write"

	// VM and container tools carry the scopes of their gRPC ComputeService
	// twins (pkg/api/grpc/method_permissions.go, #304). vm_disk_detach is
	// vm:write as DetachDisk is: the disk is unplugged, not destroyed.
	permissions["vm_create"] = "vm:write"
	permissions["vm_list"] = "vm:read"
	permissions["vm_get"] = "vm:read"
	permissions["vm_delete"] = "vm:delete"
	permissions["vm_start"] = "vm:write"
	permissions["vm_stop"] = "vm:write"
	permissions["vm_reboot"] = "vm:write"
	permissions["vm_suspend"] = "vm:write"
	permissions["vm_resume"] = "vm:write"
	permissions["vm_snapshot_create"] = "vm:write"
	permissions["vm_snapshot_list"] = "vm:read"
	permissions["vm_snapshot_get"] = "vm:read"
	permissions["vm_snapshot_restore"] = "vm:write"
	permissions["vm_snapshot_delete"] = "vm:delete"
	permissions["vm_attest"] = "vm:read"
	permissions["vm_attest_verify"] = "vm:read"
	permissions["vm_metrics"] = "vm:read"
	permissions["vm_logs"] = "vm:read"
	permissions["vm_disk_attach"] = "vm:write"
	permissions["vm_disk_detach"] = "vm:write"
	permissions["vm_disk_resize"] = "vm:write"
	permissions["vm_migrate"] = "vm:write"
	permissions["vm_migration_prepare"] = "vm:write"
	permissions["vm_migration_finalize"] = "vm:write"
	permissions["container_create"] = "container:write"
	permissions["container_start"] = "container:write"
	permissions["container_stop"] = "container:write"
	permissions["container_exec"] = "container:write"
	permissions["container_remove"] = "container:delete"
	permissions["container_get"] = "container:read"
	permissions["container_list"] = "container:read"
	permissions["container_logs"] = "container:read"
	permissions["container_metrics"] = "container:read"
	permissions["container_attest"] = "container:read"

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
	permissions["sdn_delete_policy"] = "sdn:delete"

	// SDN flow, VLAN, port-statistics and port-auth tools carry the scope of
	// their gRPC twin (pkg/api/grpc/method_permissions.go). The port-auth
	// tools then refuse with FailedPrecondition, as gRPC does (#304).
	permissions["sdn_add_flow"] = "sdn:write"
	permissions["sdn_delete_flow"] = "sdn:delete"
	permissions["sdn_flush_flows"] = "sdn:write"
	permissions["sdn_list_flows"] = "sdn:read"
	permissions["sdn_get_flow_stats"] = "sdn:read"
	permissions["sdn_create_vlan"] = "sdn:write"
	permissions["sdn_delete_vlan"] = "sdn:delete"
	permissions["sdn_list_vlans"] = "sdn:read"
	permissions["sdn_get_port_stats"] = "sdn:read"
	permissions["sdn_authenticate_port"] = "sdn:write"
	permissions["sdn_revoke_port_auth"] = "sdn:write"

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

	// IDevID and IAK tools carry exactly the scope of their gRPC
	// IDevIDService twin (pkg/api/grpc/method_permissions.go), which files
	// both device identities under the idevid resource. The provider
	// delegates each tool to that service, so the answer matches too.
	permissions["idevid_info"] = "idevid:read"
	permissions["idevid_exists"] = "idevid:read"
	permissions["idevid_get_cert"] = "idevid:read"
	permissions["idevid_generate"] = "idevid:write"
	permissions["idevid_csr"] = "idevid:write"
	permissions["idevid_install_cert"] = "idevid:write"
	permissions["idevid_create_ldevid"] = "idevid:write"
	permissions["idevid_delete"] = "idevid:delete"
	permissions["idevid_delete_cert"] = "idevid:delete"
	permissions["iak_info"] = "idevid:read"
	permissions["iak_exists"] = "idevid:read"
	permissions["iak_get_cert"] = "idevid:read"
	permissions["iak_generate"] = "idevid:write"
	permissions["iak_csr"] = "idevid:write"
	permissions["iak_install_cert"] = "idevid:write"
	permissions["iak_delete"] = "idevid:delete"
	permissions["iak_delete_cert"] = "idevid:delete"
	// device_attributes and activate_credential make the same TPM calls as
	// gRPC GetDeviceAttributes and IDevIDService ActivateCredential.
	permissions["device_attributes"] = "idevid:read"
	permissions["activate_credential"] = "idevid:write"

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
	//
	// Each tool's scope lives on its bmcTools entry and equals the scope of
	// its gRPC method in pkg/api/grpc/method_permissions.go.
	for name, tool := range bmcTools {
		permissions[name] = tool.scope
	}

	// PXE tools (#704) require the scope of their gRPC PXEService method:
	// pxe:read observes, pxe:write moves a device through the workflow or
	// starts and stops the service (WebhookComplete included), pxe:delete
	// removes a device. Each scope lives on its pxeTools entry.
	for name, tool := range pxeTools {
		permissions[name] = tool.scope
	}

	// KMS tools (#304) require the scope of the matching gRPC method on
	// platform.v1.KeyManagementService and quicbaas.kms.v1.{KeyManagement,
	// Crypto} (pkg/api/grpc/method_permissions.go). Decrypt answers
	// plaintext, so it is never open: kms:read is the gRPC Decrypt scope.
	permissions["kms_generate_key"] = "kms:write"
	permissions["kms_rotate_key"] = "kms:write"
	permissions["kms_revoke_key"] = "kms:write"
	permissions["kms_update_key_metadata"] = "kms:write"
	permissions["kms_set_key_policy"] = "kms:write"
	permissions["kms_get_key"] = "kms:read"
	permissions["kms_list_keys"] = "kms:read"
	permissions["kms_export_public_key"] = "kms:read"
	permissions["kms_get_key_metadata"] = "kms:read"
	permissions["kms_get_key_policy"] = "kms:read"
	permissions["kms_supported_algorithms"] = "kms:read"
	permissions["kms_backend_status"] = "kms:read"
	permissions["kms_delete_key"] = "kms:delete"

	permissions["kms_encrypt"] = "kms:write"
	permissions["kms_sign"] = "kms:write"
	permissions["kms_generate_data_key"] = "kms:write"
	permissions["kms_generate_wrapped_data_key"] = "kms:write"
	permissions["kms_decrypt"] = "kms:read"
	permissions["kms_verify"] = "kms:read"
	// Same scopes as the gRPC KeyManagementService methods they mirror.
	permissions["kms_hash"] = "kms:read"
	permissions["kms_hmac"] = "kms:write"
	permissions["kms_verify_hmac"] = "kms:read"
	permissions["kms_rewrap"] = "kms:write"
	permissions["kms_import_key"] = "kms:write"
	permissions["kms_update_key_status"] = "kms:write"
	permissions["kms_list_key_versions"] = "kms:read"
	permissions["kms_batch_encrypt"] = "kms:write"
	permissions["kms_batch_decrypt"] = "kms:read"
	permissions["kms_random"] = "kms:read"

	// Secret tools (#304) require the scope of the matching gRPC method on
	// quicbaas.kms.v1.SecretsManagement.
	permissions["secret_store"] = "secrets:write"
	permissions["secret_set_rotation_policy"] = "secrets:write"
	permissions["secret_get"] = "secrets:read"
	permissions["secret_get_rotation_policy"] = "secrets:read"
	permissions["secret_list"] = "secrets:list"
	permissions["secret_delete"] = "secrets:delete"
	permissions["secret_get_version"] = "secrets:read"
	permissions["secret_list_versions"] = "secrets:list"
	permissions["secret_rotate"] = "secrets:write"
	permissions["secret_rollback"] = "secrets:write"
	permissions["secret_update_status"] = "secrets:write"
	permissions["secret_get_by_prefix"] = "secrets:read"
	permissions["dek_create"] = "kms:write"
	permissions["dek_list"] = "kms:read"
	permissions["dek_get"] = "kms:read"
	permissions["dek_status"] = "kms:read"
	permissions["dek_rotate"] = "kms:write"
	permissions["dek_delete"] = "kms:delete"

	// EAB tools (#304) carry exactly the scope of their gRPC EABService
	// twin (pkg/api/grpc/method_permissions.go); both reach the same
	// eab.Service. Cleanup is eab:write on gRPC, so it is eab:write here.
	// The QR code and enrollment URL embed the HMAC key, and gRPC serves
	// them under eab:read, so MCP does too.
	permissions["platform_eab_create_credential"] = "eab:write"
	permissions["platform_eab_revoke_credential"] = "eab:write"
	permissions["platform_eab_mark_credential_used"] = "eab:write"
	permissions["platform_eab_cleanup_expired_credentials"] = "eab:write"

	permissions["platform_eab_get_credential"] = "eab:read"
	permissions["platform_eab_get_credential_by_key_id"] = "eab:read"
	permissions["platform_eab_list_credentials"] = "eab:read"
	permissions["platform_eab_validate_credential"] = "eab:read"
	permissions["platform_eab_get_credential_qr_code"] = "eab:read"
	permissions["platform_eab_get_enrollment_url"] = "eab:read"

	permissions["platform_eab_delete_credential"] = "eab:delete"

	// LUKS tools take the scopes of their gRPC LUKSService twins
	// (pkg/api/grpc/method_permissions.go).
	permissions["platform_luks_status"] = "luks:read"
	permissions["platform_luks_test_unlock"] = "luks:read"
	permissions["platform_luks_list_slots"] = "luks:read"
	permissions["platform_luks_info"] = "luks:read"

	permissions["platform_luks_enroll_passphrase"] = "luks:write"
	permissions["platform_luks_enroll_fido2"] = "luks:write"
	permissions["platform_luks_enroll_tpm"] = "luks:write"
	permissions["platform_luks_enroll_recovery"] = "luks:write"
	permissions["platform_luks_change_passphrase"] = "luks:write"

	permissions["platform_luks_remove_key"] = "luks:delete"

	// Switch, cluster and registry tools (#304) require the scope of their
	// gRPC twin in SwitchService, ClusterService and RegistryService. Each
	// switch tool's scope lives on its switchTools entry (#704): port reads
	// need switch:read, VLAN and admin-state changes need switch:write.
	for name, tool := range switchTools {
		permissions[name] = tool.scope
	}

	permissions["platform_cluster_status"] = "cluster:read"
	permissions["platform_cluster_list_nodes"] = "cluster:read"
	permissions["platform_cluster_bootstrap"] = "cluster:write"
	permissions["platform_cluster_join"] = "cluster:write"
	permissions["platform_cluster_leave"] = "cluster:write"

	permissions["platform_registry_status"] = "registry:read"
	permissions["platform_registry_list"] = "registry:read"
	permissions["platform_registry_inspect"] = "registry:read"
	permissions["platform_registry_delete"] = "registry:delete"

	// Application service tools (#704) require the scope of their gRPC
	// method; the tool table carries it.
	for name, tool := range appServiceTools {
		permissions[name] = tool.scope
	}

	// Each IAM tool carries the scope of its gRPC twin on
	// PlatformIAMService (pkg/api/grpc/method_permissions.go), whose method
	// it answers through. iam_create_token and iam_revoke_token carry the
	// scope of CreateToken and RevokeToken, which refuse on every transport
	// with the same OIDC error.
	for _, tool := range []string{
		"iam_create_user", "iam_update_user", "iam_create_role", "iam_update_role", "iam_assign_role", "iam_revoke_role",
		"iam_create_group", "iam_update_group", "iam_add_group_member", "iam_remove_group_member",
		"iam_create_tenant", "iam_create_token", "iam_revoke_token",
	} {
		permissions[tool] = "iam:write"
	}
	for _, tool := range []string{
		"iam_delete_user", "iam_delete_role", "iam_delete_group", "iam_delete_tenant",
	} {
		permissions[tool] = "iam:delete"
	}
	for _, tool := range []string{
		"iam_get_user", "iam_list_users", "iam_get_role", "iam_list_roles",
		"iam_get_group", "iam_list_groups", "iam_get_tenant", "iam_list_tenants",
		"iam_check_permission", "iam_verify_token",
	} {
		permissions[tool] = "iam:read"
	}
	// iam_authenticate is the credential exchange that mints a token, so it
	// cannot itself require one: QUIC lists OpIAMAuthenticate in
	// preAuthOpcodes (pkg/api/quic/opcode_permissions.go). It refuses with
	// the OIDC error, as QUIC does.
	permissions["iam_authenticate"] = ""

	// Tenant tools (#304) require the scope of their TenantService method
	// (pkg/api/grpc/method_permissions.go). The scope is necessary, not
	// sufficient: every tool calls the shared TenantGRPCServer, which keeps a
	// caller to its own tenant and the cross-tenant methods (list, get by
	// name, create, sync) to the system tenant (pkg/api/daemon/
	// tenant_grpc_authz.go), and the tools refuse a caller with no tenant
	// binding (ErrTenantCallerUnbound) before the server is reached.
	permissions["tenant_list"] = "tenant:read"
	permissions["tenant_get"] = "tenant:read"
	permissions["tenant_get_by_name"] = "tenant:read"
	permissions["tenant_get_quotas"] = "tenant:read"
	permissions["tenant_get_usage"] = "tenant:read"
	permissions["tenant_check_quota"] = "tenant:read"
	permissions["tenant_get_dek_status"] = "tenant:read"
	permissions["platform_tenant_barrier_status"] = "tenant:read"

	permissions["tenant_create"] = "tenant:write"
	permissions["tenant_update"] = "tenant:write"
	permissions["tenant_update_quotas"] = "tenant:write"
	permissions["tenant_suspend"] = "tenant:write"
	permissions["tenant_resume"] = "tenant:write"
	permissions["tenant_sync"] = "tenant:write"
	permissions["tenant_rotate_dek"] = "tenant:write"
	permissions["platform_tenant_barrier_init"] = "tenant:write"
	permissions["platform_tenant_barrier_seal"] = "tenant:write"
	permissions["platform_tenant_barrier_unseal"] = "tenant:write"

	permissions["tenant_delete"] = "tenant:delete"

	// Daemon read tools (#304) require the scope of their gRPC
	// PlatformDaemon twin (pkg/api/grpc/method_permissions.go); both read the
	// same daemon.Service. platform_daemon_list_protocols has no gRPC twin;
	// it carries the scope of QUIC's OpDaemonListProtocols
	// (pkg/api/quic/opcode_permissions.go).
	permissions["platform_daemon_status"] = "platform:read"
	permissions["platform_daemon_list_protocols"] = "platform:read"
	permissions["platform_daemon_version"] = "platform:read"
	permissions["platform_daemon_list_services"] = "platform:read"
	permissions["platform_daemon_get_service"] = "platform:read"
	permissions["platform_daemon_start_service"] = "platform:write"
	permissions["platform_daemon_stop_service"] = "platform:write"
	permissions["platform_daemon_restart_service"] = "platform:write"

	// Provisioning tools (#304) take the scope of their gRPC
	// ConfigDeliveryService twin. The operator session tools need a
	// provisioning scope. The device-side tools are open, as on gRPC: the
	// shared configdelivery.Service checks the EAB HMAC, the single-use
	// nonce and the EK binding before it answers, and the unguessable
	// session ID is the poll capability.
	permissions["provision_list_sessions"] = "provisioning:read"
	permissions["provision_get_session"] = "provisioning:read"
	permissions["provision_fulfill_session"] = "provisioning:write"
	permissions["provision_get_nonce"] = ""
	permissions["provision_fetch_config"] = ""
	permissions["provision_sign_digest"] = ""
	permissions["provision_poll_session"] = ""

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

	// Under mTLS the verified client certificate authenticates a tokenless
	// request, as on REST, gRPC and QUIC. A presented token never takes this
	// path: it is validated by the token backend below.
	if token == "" && c.peerAuthenticator != nil {
		return c.authorizePeer(ctx, permission)
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
		// The token goes on ctx with its grant, whether it came in the
		// params or the request: a tool that accepts only a token's grant,
		// never a peer certificate's, tells the two apart by it.
		return ContextWithAuthorizedContext(ContextWithToken(ctx, token), authCtx), nil
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

// Authenticate establishes that the caller is a principal, with the same
// authentication branches as AuthorizeTool but no tool permission lookup
// and no scope check. Listing methods (tools/list, resources/list) call it
// so an anonymous client cannot enumerate the catalogue, as the REST stack
// answers the equivalent with 401 (#414).
//
// A tokenless request under mTLS authenticates with its verified client
// certificate. With no authorization backend nothing can establish a
// principal, so the request is refused (#440). A token is validated by the
// claims path (empty requiredPerm: liveness kept, scope skipped) or the
// legacy ValidateToken. With only an authService configured a presented
// token is accepted: that service checks permissions, not identity.
func (c *AuthorizationChecker) Authenticate(ctx context.Context, token string) *AuthorizationError {
	if token == "" && c.peerAuthenticator != nil {
		state, _, _ := channelbind.ConnectionTLS(ctx)
		if state == nil || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
			return &AuthorizationError{
				Type:    AuthErrorMissingToken,
				Message: "Authentication required for this operation: no bearer token and no verified client certificate",
			}
		}
		authCtx, err := c.peerAuthenticator.AuthenticatePeer(ctx, state.VerifiedChains[0])
		if err != nil || authCtx == nil {
			return &AuthorizationError{
				Type:    AuthErrorInvalidToken,
				Message: "Invalid client certificate",
			}
		}
		return nil
	}

	if c.authService == nil && c.authManager == nil {
		return &AuthorizationError{
			Type:    AuthErrorMissingToken,
			Message: "Authentication required for this operation: no authorization backend is configured",
		}
	}

	if token == "" {
		return &AuthorizationError{
			Type:    AuthErrorMissingToken,
			Message: "Authentication required for this operation",
		}
	}

	if cv, ok := c.authManager.(ClaimsAuthManager); ok && cv != nil {
		if _, err := cv.AuthorizeToken(ctx, token, "", "", "", ""); err != nil {
			return &AuthorizationError{
				Type:    AuthErrorInvalidToken,
				Message: "Invalid or expired token",
			}
		}
		return nil
	}

	if c.authManager != nil {
		valid, err := c.authManager.ValidateToken(ctx, token)
		if err != nil || !valid {
			return &AuthorizationError{
				Type:    AuthErrorInvalidToken,
				Message: "Invalid or expired token",
			}
		}
	}

	return nil
}

// IsEnabled returns true if authorization checking is enabled.
func (c *AuthorizationChecker) IsEnabled() bool {
	return c.authService != nil || c.authManager != nil
}
