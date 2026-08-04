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

// init registers the LDevID (IEEE 802.1AR) create RPC on the MCP transport.
// The gRPC method resolves to the idevid_create_ldevid tool registered by
// pkg/api/mcp/ldevid_tools.go, keeping adapter and server in lockstep.
func init() {
	grpcMethodToMCPToolMap[platformv1.IDevIDService_CreateLDevID_FullMethodName] = "idevid_create_ldevid"
}
