// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package daemon

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The VM lifecycle tools call the gRPC ComputeService, so each takes its
// RPC's full request and shares its validation, error class and reply
// (#304, #317, #704).
var _ mcp.ComputeProvider = (*MCPServiceProvider)(nil)

// ComputeServiceServer is the gRPC ComputeService over the daemon's compute
// orchestrator. It is never nil: a nil orchestrator answers
// FailedPrecondition as it does over gRPC.
func (m *MCPServiceProvider) ComputeServiceServer() platformv1.ComputeServiceServer {
	return NewComputeGRPCService(logging.NewFromSlog(m.logger), m.computeOrchestrator)
}
