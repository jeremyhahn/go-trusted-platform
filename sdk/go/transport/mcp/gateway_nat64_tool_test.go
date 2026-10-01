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

import "testing"

// TestNAT64Status_MapsToTheServerTool pins the NAT64 status tool name to the
// one pkg/api/mcp/gateway_nat64_tools.go registers. An absent mapping makes
// the adapter report the method unmapped, which reads to a caller as "this
// platform has no NAT64" rather than "this SDK forgot to wire it" (#601).
func TestNAT64Status_MapsToTheServerTool(t *testing.T) {
	const method = "/platform.v1.GatewayService/GetNAT64Status"

	tool, ok := grpcMethodToMCPToolMap[method]
	if !ok {
		t.Fatalf("%s has no MCP tool mapping; the adapter cannot dispatch it", method)
	}
	if want := "gateway_nat64_status"; tool != want {
		t.Errorf("NAT64 status tool = %q, want %q (must match the server registration)", tool, want)
	}
}
