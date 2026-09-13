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

// Package login drives the qrdb unified login ceremony for every factor
// the platform authenticates with.
//
// The locked architecture (../handbook/software/docs/00) makes qrdb's
// LoginClient the single canonical login backbone. Every factor proof is
// verified there and every principal is resolved there: the platform
// authenticates nobody and holds no credential store of its own.
//
// What the platform still does is ISSUE the session credential, because
// its own inbound seam (Router.authMiddleware) speaks platform-signed
// JWTs and the SDK has no working inbound validator for the backbone's
// OIDC bearer yet. That step is a projection of the backbone's verdict,
// not a second authentication, and it is confined to one seam —
// SessionIssuer in session.go, which documents exactly what has to land
// upstream for it to go away.
//
// There is ONE ceremony and one implementation of it here — Driver. What
// differs per factor is only how the HTTP request carries the proof and
// how the challenge is rendered back to the client, which is what a
// Binder supplies. A second copy of the Begin/Finish sequence per factor
// is the duplication this package exists to remove.
package login

import (
	"context"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
)

// UnifiedLoginClient is the platform-side boundary to the quicbaas SDK's
// unified login ceremony (Security().Auth().BeginLogin/FinishLogin). The
// SDK AuthService satisfies it directly; the platform depends only on the
// two verbs it consumes so the boundary stays small and the driver can be
// unit-tested against a fake.
type UnifiedLoginClient interface {
	// BeginLogin opens a login attempt for the supplied factor type and
	// returns the server-issued challenge.
	BeginLogin(ctx context.Context, req quicbaas.BeginLoginRequest) (*quicbaas.BeginLoginResponse, error)

	// FinishLogin submits the factor proof and, on success, returns the
	// issued OIDC bearer plus the resolved identity. The bearer is the
	// evidence the ceremony succeeded and the identity names who it
	// succeeded for; the platform mints its session from the latter.
	FinishLogin(ctx context.Context, req quicbaas.FinishLoginRequest) (*quicbaas.FinishLoginResponse, error)
}
