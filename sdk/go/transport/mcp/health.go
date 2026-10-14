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
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The health probe tools answer in the proto3 JSON mapping of the message the
// gRPC rpc returns, so the reply decodes straight into it. platform_health is
// the status-only form of GetHealth: the tools are served without a token and
// name no component (docs/health/api.md §7).
func init() {
	for method, tool := range map[string]string{
		platformv1.PlatformDaemon_GetHealth_FullMethodName: "platform_health",
		platformv1.PlatformDaemon_Liveness_FullMethodName:  "platform_liveness",
		platformv1.PlatformDaemon_Readiness_FullMethodName: "platform_readiness",
	} {
		grpcMethodToMCPToolMap[method] = tool
		mcpReplyDecoders[method] = protoJSONReply(method)
	}
}
