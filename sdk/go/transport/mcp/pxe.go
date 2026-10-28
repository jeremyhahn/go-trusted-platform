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

// The pxe_* tools (pkg/api/mcp/pxe_tools.go, #704) call the daemon's gRPC
// PXEService servicer: they take the request and return the response in the
// proto3 JSON mapping with proto field names, so the shared protoJSON builder
// and decoder serve every method.

import (
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// pxeToolMap maps each PXEService gRPC method to the platformd MCP tool that
// serves it.
var pxeToolMap = map[string]string{
	platformv1.PXEService_RegisterDevice_FullMethodName:    "pxe_register_device",
	platformv1.PXEService_GetDevice_FullMethodName:         "pxe_get_device",
	platformv1.PXEService_GetDeviceByMAC_FullMethodName:    "pxe_get_device_by_mac",
	platformv1.PXEService_ListDevices_FullMethodName:       "pxe_list_devices",
	platformv1.PXEService_RemoveDevice_FullMethodName:      "pxe_remove_device",
	platformv1.PXEService_UpdateState_FullMethodName:       "pxe_update_state",
	platformv1.PXEService_SetDeviceEnrolled_FullMethodName: "pxe_set_device_enrolled",
	platformv1.PXEService_Authorize_FullMethodName:         "pxe_authorize_device",
	platformv1.PXEService_Quarantine_FullMethodName:        "pxe_quarantine_device",
	platformv1.PXEService_Retry_FullMethodName:             "pxe_retry_device",
	platformv1.PXEService_GetEvents_FullMethodName:         "pxe_get_device_events",
	platformv1.PXEService_GetStatus_FullMethodName:         "pxe_service_status",
	platformv1.PXEService_StartService_FullMethodName:      "pxe_start_service",
	platformv1.PXEService_StopService_FullMethodName:       "pxe_stop_service",
	platformv1.PXEService_WebhookComplete_FullMethodName:   "pxe_webhook_complete",
}

func init() {
	for method, tool := range pxeToolMap {
		grpcMethodToMCPToolMap[method] = tool
		mcpArgBuilders[method] = protoJSONArgs(method)
		mcpReplyDecoders[method] = protoJSONReply(method)
	}
}
