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

package login

import (
	"time"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
)

// SessionIssuer mints the platform session credential for a principal the
// backbone has already authenticated.
//
// The division of labour is the whole point, and it is not a division of
// authority: the BACKBONE authenticates — it runs the factor ceremony,
// verifies the hardware proof and resolves the principal — and the
// PLATFORM only encodes that verdict into the credential its own inbound
// seam speaks. An issuer is never handed anything but an identity the
// ceremony already established, and it decides nothing about it.
//
// It exists because the seam every protected route shares
// (Router.authMiddleware) validates platform-signed JWTs, and the SDK
// exposes no working way to validate the backbone's OIDC bearer inbound:
// quicbaas's sdk/go/client/auth ValidateToken asserts *service.TokenClaims
// while the embedded transport's quicbaas.Auth/ValidateToken answers with
// *service.ValidateTokenResponse, so the call cannot succeed on the
// default in-process deployment (filed upstream as
// jeremyhahn/go-quicbaas#955). Forwarding the backbone bearer instead
// would hand every client a credential this same server rejects.
//
// When that surface works the issuer disappears: finish forwards the
// backbone's bearer and renewal credential verbatim and the platform
// stops minting anything (#202, and phases 3 and 4 of #644). Removing the
// mint before the validating seam exists is the ordering error this
// interface makes impossible to commit by accident.
type SessionIssuer interface {
	// IssueSession mints the session credential for an authenticated
	// identity and returns it with its expiry.
	//
	// It fails — rather than issuing an anonymous credential — for an
	// identity the ceremony did not fully resolve.
	IssueSession(identity *quicbaas.Identity) (string, time.Time, error)
}

// Session is the credential set a completed ceremony hands the client.
//
// It carries no renewal credential. The backbone mints one alongside its
// own bearer, but that credential renews the BACKBONE's session, and the
// client is not holding the backbone's bearer — it is holding the
// platform's. Forwarding it would hand over a credential no route on this
// server can redeem, which is the same defect as returning a bearer no
// route can validate, one layer down. The renewal credential reaches the
// client in the same change that makes the backbone bearer the session
// (see SessionIssuer).
type Session struct {
	// Bearer is the platform session token to present on subsequent
	// requests. It is exactly what Router.authMiddleware validates, so a
	// completed login is usable against a protected route immediately.
	Bearer string `json:"bearer" secret:"true"`

	// ExpiresAt is the bearer's expiry.
	ExpiresAt time.Time `json:"expiresAt"`
}

// newSession projects a minted credential onto the client-facing session.
func newSession(bearer string, expiresAt time.Time) Session {
	return Session{Bearer: bearer, ExpiresAt: expiresAt}
}
