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

package daemon

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
)

// requireSystemScopeCaller applies tenant.RequireSystemScope to the caller the
// daemon's REST scope guard authorized on the KMS routes.
func requireSystemScopeCaller(systemTenantID string, caller *platformtoken.AuthorizedContext) error {
	if caller == nil {
		return nil
	}
	return tenant.RequireSystemScope(systemTenantID, caller.TenantID)
}

// requireSystemScopeContext applies tenant.RequireSystemScope to the caller
// the gRPC, Unix, QUIC or MCP transport authorized (callerTenant).
func requireSystemScopeContext(ctx context.Context, systemTenantID string) error {
	callerTenantID, bound := callerTenant(ctx)
	if !bound {
		return nil
	}
	return tenant.RequireSystemScope(systemTenantID, callerTenantID)
}
