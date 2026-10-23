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

package container

import "github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"

// Container operations, named as ContainerCommands names them.
const (
	opLogs   = "Logs"
	opAttest = "Attest"
)

// Why a transport has no surface for an operation.
const (
	reasonRESTLogs = "platformd serves no REST container logs route: the SDK maps GetContainerLogs to " +
		"GET /api/v1/compute/containers/logs, which pkg/api/rest/compute_handlers.go does not register"
	reasonQUICAttest = "the SDK QUIC transport maps no AttestContainer RPC (sdk/go/transport/quic/adapter.go); " +
		"the daemon's OpContainerAttest is reached only by the flat container handler"
	reasonMCPAttest = "the SDK MCP transport maps no AttestContainer RPC (sdk/go/transport/mcp/adapter.go); " +
		"the server's container_attest tool is not reached"
)

// missingSurfaces lists, per transport, the operations it has no surface for
// and why. It is the one table both the adapters and the tests read.
var missingSurfaces = map[string]map[string]string{
	"REST": {opLogs: reasonRESTLogs},
	"QUIC": {opAttest: reasonQUICAttest},
	"MCP":  {opAttest: reasonMCPAttest},
}

// missingSurface reports whether transport has no surface for op, and why.
func missingSurface(transport, op string) (string, bool) {
	reason, missing := missingSurfaces[transport][op]
	return reason, missing
}

// noSurface is the error an adapter returns for an operation its transport
// does not serve.
func noSurface(transport, op string) error {
	return surface.ErrNoSurface{Transport: transport, Operation: op, Reason: missingSurfaces[transport][op]}
}
