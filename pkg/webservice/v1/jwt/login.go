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

package jwt

import (
	"context"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
)

// UnifiedLoginClient is the platform-side boundary to the quicbaas SDK's
// unified login ceremony (Security().Auth().BeginLogin/FinishLogin). The
// SDK AuthService satisfies this interface directly; the platform depends
// only on the two verbs it actually consumes so the boundary stays small
// and the REST handler can be unit-tested with a mock.
//
// The locked architecture makes qrdb's LoginClient the single canonical
// login backbone and quicbaas's OIDC TokenService the SessionIssuer. The
// platform consumes the bearer returned by FinishLogin as the session
// token rather than minting a divergent local JWT.
type UnifiedLoginClient interface {
	// BeginLogin opens a login attempt for the supplied factor type and
	// returns the server-issued challenge.
	BeginLogin(ctx context.Context, req quicbaas.BeginLoginRequest) (*quicbaas.BeginLoginResponse, error)

	// FinishLogin submits the factor proof and, on success, returns the
	// issued OIDC bearer plus the resolved identity.
	FinishLogin(ctx context.Context, req quicbaas.FinishLoginRequest) (*quicbaas.FinishLoginResponse, error)
}
