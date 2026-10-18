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

// The switch_* tools (pkg/api/mcp/switch_tools.go, #704) call the daemon's
// gRPC SwitchService servicer: they take the request and return the response
// in the proto3 JSON mapping with proto field names, so the shared protoJSON
// builder and decoder serve every method.

import (
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// switchToolMap maps each SwitchService gRPC method to the platformd MCP tool
// that serves it.
var switchToolMap = map[string]string{
	platformv1.SwitchService_ListPorts_FullMethodName:     "switch_list_ports",
	platformv1.SwitchService_GetPortStatus_FullMethodName: "switch_port_status",
	platformv1.SwitchService_SetPortVLAN_FullMethodName:   "switch_set_vlan",
	platformv1.SwitchService_EnablePort_FullMethodName:    "switch_enable_port",
	platformv1.SwitchService_DisablePort_FullMethodName:   "switch_disable_port",
}

func init() {
	for method, tool := range switchToolMap {
		grpcMethodToMCPToolMap[method] = tool
		mcpArgBuilders[method] = protoJSONArgs(method)
		mcpReplyDecoders[method] = protoJSONReply(method)
	}
}
