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

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
)

// The callers below are the identities the daemon's transports hand a
// service once a request is authenticated (#646): a tenant-bound platform
// token on QUIC or MCP, or the kernel-verified Unix-socket operator. Tests
// call as one of them; a bare context.Background() is the unbound caller
// the services refuse (TestUnboundCallerIsRefusedOnEveryTransport).

// quicTenantCaller is the context the QUIC server gives a request that
// carries a validated platform token bound to tenantID. The token grants
// iam:read and iam:write, the scopes the QUIC per-operation guard (#767)
// asks of the IAM operations, and any further scopes the test names.
func quicTenantCaller(tenantID string, scopes ...string) context.Context {
	granted := append([]string{"iam:read", "iam:write"}, scopes...)
	return quic.ContextWithAuthorizedContext(context.Background(), &platformtoken.AuthorizedContext{TenantID: tenantID, Scopes: granted})
}
