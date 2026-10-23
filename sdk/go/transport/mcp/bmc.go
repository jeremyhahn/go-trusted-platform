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

// The platform_bmc_* tools (pkg/api/mcp/bmc_tools.go, #704) call the daemon's
// gRPC BMCService servicer: they take the request and return the response in
// the proto3 JSON mapping with proto field names, so the shared protoJSON
// builder and decoder serve every method.

import (
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// bmcToolMap maps each BMCService gRPC method to the platformd MCP tool that
// serves it.
var bmcToolMap = map[string]string{
	platformv1.BMCService_PowerOn_FullMethodName:               "platform_bmc_power_on",
	platformv1.BMCService_PowerOff_FullMethodName:              "platform_bmc_power_off",
	platformv1.BMCService_PowerReset_FullMethodName:            "platform_bmc_power_reset",
	platformv1.BMCService_PowerCycle_FullMethodName:            "platform_bmc_power_cycle",
	platformv1.BMCService_PowerStatus_FullMethodName:           "platform_bmc_power_status",
	platformv1.BMCService_SetBootDevice_FullMethodName:         "platform_bmc_set_boot_device",
	platformv1.BMCService_GetBootDevice_FullMethodName:         "platform_bmc_get_boot_device",
	platformv1.BMCService_MountISO_FullMethodName:              "platform_bmc_mount_iso",
	platformv1.BMCService_UnmountISO_FullMethodName:            "platform_bmc_unmount_iso",
	platformv1.BMCService_VirtualMediaStatus_FullMethodName:    "platform_bmc_virtual_media_status",
	platformv1.BMCService_GetSensors_FullMethodName:            "platform_bmc_get_sensors",
	platformv1.BMCService_GetSystemInfo_FullMethodName:         "platform_bmc_get_system_info",
	platformv1.BMCService_Provision_FullMethodName:             "platform_bmc_provision",
	platformv1.BMCService_ProvisionStatus_FullMethodName:       "platform_bmc_provision_status",
	platformv1.BMCService_GetWebCertificate_FullMethodName:     "platform_bmc_get_web_certificate",
	platformv1.BMCService_ReplaceWebCertificate_FullMethodName: "platform_bmc_replace_web_certificate",
	platformv1.BMCService_EnrollBMC_FullMethodName:             "platform_bmc_enroll",
	platformv1.BMCService_RestoreFactoryCert_FullMethodName:    "platform_bmc_cert_restore",
	platformv1.BMCService_ListUsers_FullMethodName:             "platform_bmc_list_users",
	platformv1.BMCService_CreateUser_FullMethodName:            "platform_bmc_create_user",
	platformv1.BMCService_DeleteUser_FullMethodName:            "platform_bmc_delete_user",
	platformv1.BMCService_SetUserPassword_FullMethodName:       "platform_bmc_set_user_password",
	platformv1.BMCService_SetUserPrivilege_FullMethodName:      "platform_bmc_set_user_privilege",
}

func init() {
	for method, tool := range bmcToolMap {
		grpcMethodToMCPToolMap[method] = tool
		mcpArgBuilders[method] = protoJSONArgs(method)
		mcpReplyDecoders[method] = protoJSONReply(method)
	}
}
