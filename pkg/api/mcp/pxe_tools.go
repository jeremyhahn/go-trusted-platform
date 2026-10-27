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
	"maps"
	"slices"

	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// =============================================================================
// PXE tool wiring
// =============================================================================
//
// Every gRPC PXEService method has one pxe_<verb> tool. A tool's arguments
// are the gRPC request in protojson form (proto field names, enums by name,
// 64-bit integers as JSON strings) and its result is the gRPC response in the
// same form. Each tool calls the gRPC PXEService servicer, so it validates,
// answers and fails exactly as gRPC does.

// ErrPXENotConfigured indicates the PXE service is not wired into the MCP
// tool registry. Clients see this when the daemon serves no PXEService.
var ErrPXENotConfigured = errors.New("pxe: service provider not configured")

// PXEProvider is implemented by a ServiceProvider that serves the gRPC
// PXEService. The pxe_* tools call that servicer.
type PXEProvider interface {
	// PXEServiceServer returns the gRPC PXEService servicer, or nil while
	// no PXE service is wired.
	PXEServiceServer() platformv1.PXEServiceServer
}

// pxeToolCall runs one PXE tool against the gRPC PXEService servicer.
type pxeToolCall func(server platformv1.PXEServiceServer, ctx context.Context, args map[string]interface{}) (interface{}, error)

// pxeToolBinding is how a PXE tool reaches the servicer: the schema it
// advertises and the call that serves it.
type pxeToolBinding struct {
	schema func() map[string]interface{}
	call   pxeToolCall
}

// pxeTool is one PXE tool and the permission it requires.
type pxeTool struct {
	// method is the gRPC method the tool serves.
	method string
	// scope is the permission the tool requires: the scope of its gRPC
	// method in pkg/api/grpc/method_permissions.go.
	scope       string
	description string
	binding     pxeToolBinding
}

// pxeTools are the PXE tools bound to the gRPC PXEService.
var pxeTools = map[string]pxeTool{
	"pxe_register_device": {
		method:      platformv1.PXEService_RegisterDevice_FullMethodName,
		scope:       "pxe:write",
		description: "Register a device for PXE provisioning by MAC address and OVS port; it starts on the quarantine VLAN",
		binding:     pxeToolMethod(platformv1.PXEServiceServer.RegisterDevice, "mac_address", "port_id"),
	},
	"pxe_list_devices": {
		method:      platformv1.PXEService_ListDevices_FullMethodName,
		scope:       "pxe:read",
		description: "List the devices in the PXE provisioning workflow, optionally filtered by state, MAC address or VLAN",
		binding:     pxeToolMethod(platformv1.PXEServiceServer.ListDevices),
	},
	"pxe_get_device": {
		method:      platformv1.PXEService_GetDevice_FullMethodName,
		scope:       "pxe:read",
		description: "Return a provisioning device by its device ID",
		binding:     pxeToolMethod(platformv1.PXEServiceServer.GetDevice, "device_id"),
	},
	"pxe_get_device_by_mac": {
		method:      platformv1.PXEService_GetDeviceByMAC_FullMethodName,
		scope:       "pxe:read",
		description: "Return a provisioning device by its MAC address",
		binding:     pxeToolMethod(platformv1.PXEServiceServer.GetDeviceByMAC, "mac_address"),
	},
	"pxe_remove_device": {
		method:      platformv1.PXEService_RemoveDevice_FullMethodName,
		scope:       "pxe:delete",
		description: "Remove a device from PXE provisioning",
		binding:     pxeToolMethod(platformv1.PXEServiceServer.RemoveDevice, "device_id"),
	},
	"pxe_update_state": {
		method:      platformv1.PXEService_UpdateState_FullMethodName,
		scope:       "pxe:write",
		description: "Move a device to a provisioning state (PROVISIONING_STATE_*); the transition must be one the workflow allows",
		binding:     pxeToolMethod(platformv1.PXEServiceServer.UpdateState, "device_id", "state"),
	},
	"pxe_set_device_enrolled": {
		method:      platformv1.PXEService_SetDeviceEnrolled_FullMethodName,
		scope:       "pxe:write",
		description: "Mark a device enrolled with PKI, recording its certificate serial number",
		binding:     pxeToolMethod(platformv1.PXEServiceServer.SetDeviceEnrolled, "device_id", "certificate_serial"),
	},
	"pxe_bind_device_certificate": {
		method:      platformv1.PXEService_BindDeviceCertificate_FullMethodName,
		scope:       "pxe:write",
		description: "Bind the SHA-256 fingerprint of the certificate a device's installer presents to the install-completion webhook; accepted before installation completes, without a state change",
		binding:     pxeToolMethod(platformv1.PXEServiceServer.BindDeviceCertificate, "device_id", "certificate_fingerprint"),
	},
	"pxe_authorize_device": {
		method:      platformv1.PXEService_Authorize_FullMethodName,
		scope:       "pxe:write",
		description: "Authorize a device onto its target VLAN, moving it out of the provisioning network",
		binding:     pxeToolMethod(platformv1.PXEServiceServer.Authorize, "device_id", "target_vlan"),
	},
	"pxe_quarantine_device": {
		method:      platformv1.PXEService_Quarantine_FullMethodName,
		scope:       "pxe:write",
		description: "Quarantine a device: restrict its network access and move it to the quarantine VLAN",
		binding:     pxeToolMethod(platformv1.PXEServiceServer.Quarantine, "device_id", "reason"),
	},
	"pxe_retry_device": {
		method:      platformv1.PXEService_Retry_FullMethodName,
		scope:       "pxe:write",
		description: "Retry provisioning of a failed or quarantined device, resetting it to discovered",
		binding:     pxeToolMethod(platformv1.PXEServiceServer.Retry, "device_id"),
	},
	"pxe_get_device_events": {
		method:      platformv1.PXEService_GetEvents_FullMethodName,
		scope:       "pxe:read",
		description: "Return the provisioning event audit trail of a device",
		binding:     pxeToolMethod(platformv1.PXEServiceServer.GetEvents, "device_id"),
	},
	"pxe_service_status": {
		method:      platformv1.PXEService_GetStatus_FullMethodName,
		scope:       "pxe:read",
		description: "Report whether the PXE provisioning service runs, how many devices it tracks, and its VLAN configuration",
		binding:     pxeToolMethod(platformv1.PXEServiceServer.GetStatus),
	},
	"pxe_start_service": {
		method:      platformv1.PXEService_StartService_FullMethodName,
		scope:       "pxe:write",
		description: "Start the PXE provisioning service",
		binding:     pxeToolMethod(platformv1.PXEServiceServer.StartService),
	},
	"pxe_stop_service": {
		method:      platformv1.PXEService_StopService_FullMethodName,
		scope:       "pxe:write",
		description: "Stop the PXE provisioning service; provisioning pauses until it starts again",
		binding:     pxeToolMethod(platformv1.PXEServiceServer.StopService),
	},
	"pxe_webhook_complete": {
		method:      platformv1.PXEService_WebhookComplete_FullMethodName,
		scope:       "pxe:write",
		description: "Report that the OS installation on a device finished, successfully or not",
		binding:     pxeToolMethod(platformv1.PXEServiceServer.WebhookComplete, "mac_address"),
	},
}

// pxeToolMethod binds a PXE tool to one PXEService method: the arguments
// decode into its request and its response is the tool result.
func pxeToolMethod[Req any, PReq interface {
	*Req
	proto.Message
}, Resp proto.Message](
	call func(platformv1.PXEServiceServer, context.Context, PReq) (Resp, error),
	required ...string,
) pxeToolBinding {
	descriptor := PReq(new(Req)).ProtoReflect().Descriptor()
	return pxeToolBinding{
		schema: func() map[string]interface{} {
			return appToolSchema(descriptor, required...)
		},
		call: func(server platformv1.PXEServiceServer, ctx context.Context, args map[string]interface{}) (interface{}, error) {
			request := PReq(new(Req))
			if err := decodeAppToolArgs(args, request); err != nil {
				return nil, err
			}
			response, err := call(server, ctx, request)
			if err != nil {
				return nil, err
			}
			return encodeAppToolResult(response)
		},
	}
}

// registerPXETools registers the pxe_* tools.
func (r *ToolRegistry) registerPXETools() {
	for _, name := range slices.Sorted(maps.Keys(pxeTools)) {
		tool := pxeTools[name]
		r.addTool(mcpwire.ToolDefinition{
			Name:        name,
			Description: tool.description,
			InputSchema: tool.binding.schema(),
		})
	}
}

// pxeServiceServer is the gRPC PXEService servicer the PXE tools call, or
// nil while the service provider serves none.
func (r *ToolRegistry) pxeServiceServer() platformv1.PXEServiceServer {
	if provider, ok := r.service.(PXEProvider); ok {
		return provider.PXEServiceServer()
	}
	return nil
}

// dispatchPXETool runs a pxe_* tool. handled is false when name is not a
// PXE tool, so the caller tries the next dispatcher.
func (r *ToolRegistry) dispatchPXETool(ctx context.Context, name string, args map[string]interface{}) (interface{}, bool, error) {
	tool, ok := pxeTools[name]
	if !ok {
		return nil, false, nil
	}
	server := r.pxeServiceServer()
	if server == nil {
		return nil, true, ErrPXENotConfigured
	}
	result, err := tool.binding.call(server, ctx, args)
	return result, true, err
}
