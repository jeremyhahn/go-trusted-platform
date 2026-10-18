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
// Switch tool wiring
// =============================================================================
//
// Every gRPC SwitchService method has one switch_* tool. A tool's arguments
// are the gRPC request in protojson form (proto field names) and its result
// is the gRPC response in the same form. Each tool calls the gRPC
// SwitchService servicer, so it validates, answers and fails exactly as gRPC
// does.

// ErrSwitchNotConfigured indicates no gRPC SwitchService servicer is wired
// into the MCP tool registry. It is classed Unimplemented, as an embedded
// host without the service answers: the host does not serve SwitchService.
var ErrSwitchNotConfigured = errors.New("switch: service provider not configured")

// SwitchProvider is implemented by a ServiceProvider that serves the gRPC
// SwitchService. The switch_* tools call that servicer.
type SwitchProvider interface {
	// SwitchServiceServer returns the gRPC SwitchService servicer, or nil
	// while no switch service is wired.
	SwitchServiceServer() platformv1.SwitchServiceServer
}

// switchToolCall runs one switch tool against the gRPC SwitchService servicer.
type switchToolCall func(server platformv1.SwitchServiceServer, ctx context.Context, args map[string]interface{}) (interface{}, error)

// switchToolBinding is how a switch tool reaches the servicer: the schema it
// advertises and the call that serves it.
type switchToolBinding struct {
	schema func() map[string]interface{}
	call   switchToolCall
}

// switchTool is one switch tool and the permission it requires.
type switchTool struct {
	// method is the gRPC method the tool serves.
	method string
	// scope is the permission the tool requires: the scope of its gRPC
	// method in pkg/api/grpc/method_permissions.go. Port reads need
	// switch:read; changing a port's VLAN or admin state needs switch:write.
	scope       string
	description string
	binding     switchToolBinding
}

// switchTools are the switch tools bound to the gRPC SwitchService.
var switchTools = map[string]switchTool{
	"switch_list_ports": {
		method:      platformv1.SwitchService_ListPorts_FullMethodName,
		scope:       "switch:read",
		description: "List all physical ports on a named network switch with their status, VLAN assignments, and link state",
		binding:     switchToolMethod(platformv1.SwitchServiceServer.ListPorts, "switch_name"),
	},
	"switch_port_status": {
		method:      platformv1.SwitchService_GetPortStatus_FullMethodName,
		scope:       "switch:read",
		description: "Get the full observable state of a single port on a physical network switch",
		binding:     switchToolMethod(platformv1.SwitchServiceServer.GetPortStatus, "switch_name", "port_name"),
	},
	"switch_set_vlan": {
		method:      platformv1.SwitchService_SetPortVLAN_FullMethodName,
		scope:       "switch:write",
		description: "Move an access-mode port to a VLAN (vlan_id 1-4094) on a physical network switch",
		binding:     switchToolMethod(platformv1.SwitchServiceServer.SetPortVLAN, "switch_name", "port_name", "vlan_id"),
	},
	"switch_enable_port": {
		method:      platformv1.SwitchService_EnablePort_FullMethodName,
		scope:       "switch:write",
		description: "Administratively enable a port on a physical network switch",
		binding:     switchToolMethod(platformv1.SwitchServiceServer.EnablePort, "switch_name", "port_name"),
	},
	"switch_disable_port": {
		method:      platformv1.SwitchService_DisablePort_FullMethodName,
		scope:       "switch:write",
		description: "Administratively shut down a port on a physical network switch",
		binding:     switchToolMethod(platformv1.SwitchServiceServer.DisablePort, "switch_name", "port_name"),
	},
}

// switchToolMethod binds a switch tool to one SwitchService method: the
// arguments decode into its request and its response is the tool result.
func switchToolMethod[Req any, PReq interface {
	*Req
	proto.Message
}, Resp proto.Message](
	call func(platformv1.SwitchServiceServer, context.Context, PReq) (Resp, error),
	required ...string,
) switchToolBinding {
	descriptor := PReq(new(Req)).ProtoReflect().Descriptor()
	return switchToolBinding{
		schema: func() map[string]interface{} {
			return appToolSchema(descriptor, required...)
		},
		call: func(server platformv1.SwitchServiceServer, ctx context.Context, args map[string]interface{}) (interface{}, error) {
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

// registerSwitchTools registers the switch_* tools.
func (r *ToolRegistry) registerSwitchTools() {
	for _, name := range slices.Sorted(maps.Keys(switchTools)) {
		tool := switchTools[name]
		r.addTool(mcpwire.ToolDefinition{
			Name:        name,
			Description: tool.description,
			InputSchema: tool.binding.schema(),
		})
	}
}

// switchServiceServer is the gRPC SwitchService servicer the switch tools
// call, or nil while the service provider serves none.
func (r *ToolRegistry) switchServiceServer() platformv1.SwitchServiceServer {
	if provider, ok := r.service.(SwitchProvider); ok {
		return provider.SwitchServiceServer()
	}
	return nil
}

// dispatchSwitchTool runs a switch_* tool. handled is false when name is not
// a switch tool, so the caller tries the next dispatcher.
func (r *ToolRegistry) dispatchSwitchTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, bool, error) {
	tool, ok := switchTools[name]
	if !ok {
		return nil, false, nil
	}
	server := r.switchServiceServer()
	if server == nil {
		return nil, true, ErrSwitchNotConfigured
	}
	result, err := tool.binding.call(server, ctx, args)
	return result, true, err
}
