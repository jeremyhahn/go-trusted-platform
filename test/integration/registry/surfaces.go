//go:build integration

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

package registry

import "github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"

// Registry operations, named as RegistryCommands names them.
const (
	opPush              = "Push"
	opPull              = "Pull"
	opList              = "List"
	opDelete            = "Delete"
	opInspect           = "Inspect"
	opStatus            = "Status"
	opTag               = "Tag"
	opVerifyClient      = "VerifyClient"
	opGetSession        = "GetSession"
	opInvalidateSession = "InvalidateSession"
	opEncryptImage      = "EncryptImage"
	opDecryptImage      = "DecryptImage"
)

// Why a transport has no server surface for an operation.
const (
	reasonUnserved = "no transport serves it: RegistryService, the REST router, the MCP tools and platformctl registry " +
		"carry push, pull, list, inspect, delete and status only (docs/registry/api.md §2)"
	reasonQUIC = "QUIC carries no registry opcode (docs/registry/api.md §2: MISSING — docs/13 G7)"
	reasonMCP  = "push and pull are deliberately not MCP tools (docs/registry/api.md §4)"
)

// unservedOps have no server surface on any transport.
var unservedOps = map[string]bool{
	opTag:               true,
	opVerifyClient:      true,
	opGetSession:        true,
	opInvalidateSession: true,
	opEncryptImage:      true,
	opDecryptImage:      true,
}

// mcpOmittedOps are the operations docs/registry/api.md §4 keeps off MCP.
var mcpOmittedOps = map[string]bool{
	opPush: true,
	opPull: true,
}

// missingSurface reports whether transport has no server surface for op, and
// why. It is the one table both the adapters and the tests read.
func missingSurface(transport, op string) (string, bool) {
	switch {
	case transport == "QUIC":
		return reasonQUIC, true
	case unservedOps[op]:
		return reasonUnserved, true
	case transport == "MCP" && mcpOmittedOps[op]:
		return reasonMCP, true
	}
	return "", false
}

// noSurface is the error an adapter returns for an operation its transport
// does not serve.
func noSurface(transport, op string) error {
	reason, _ := missingSurface(transport, op)
	return surface.ErrNoSurface{Transport: transport, Operation: op, Reason: reason}
}
