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
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/login"
)

// The login driver refuses to construct without an issuer, so this
// assertion is what keeps the two sides from drifting at compile time
// rather than at the first login of a deployment.
var _ login.SessionIssuer = (*Service)(nil)

var (
	// ErrIdentityRequired is returned when a session is requested for no
	// identity at all.
	ErrIdentityRequired = errors.New("jwt/service: an authenticated identity is required")

	// ErrSignerUnavailable is returned when issuance is attempted on a
	// service that was never constructed, so there is no signing key to
	// mint with. It is distinct from the identity errors on purpose: the
	// driver reports an issuance failure as a platform fault, and an
	// operator reading that log needs to know the platform has no signer
	// rather than go looking for a login that resolved nobody.
	ErrSignerUnavailable = errors.New("jwt/service: no signer is configured")

	// ErrIdentitySubjectRequired is returned when the backbone resolved an
	// identity with no subject. A session credential naming nobody would
	// authenticate as nobody downstream, so issuance fails instead.
	ErrIdentitySubjectRequired = errors.New("jwt/service: the identity carries no subject")

	// ErrIdentityTenantRequired is returned when the backbone resolved an
	// identity with no tenant. Every route guard and every row-level scope
	// downstream reads the tenant claim, so an untenanted session would be
	// a session with an undefined blast radius.
	ErrIdentityTenantRequired = errors.New("jwt/service: the identity carries no tenant")
)

// IssueSession mints the platform session credential for a principal the
// unified login backbone has already authenticated, satisfying
// login.SessionIssuer.
//
// This is a PROJECTION of the backbone's verdict, not a second
// authentication: the caller reaches it only after the ceremony verified a
// hardware proof and resolved the identity, and nothing here can widen
// what the ceremony decided. It exists because the seam every protected
// route shares validates tokens this signer produced, and the SDK's
// inbound validator for the backbone's own bearer does not work on the
// embedded transport (see login.SessionIssuer for the exact upstream
// defect). Routing a login's bearer through this signer is what makes the
// returned credential usable against a protected route in the same breath
// it is issued.
//
// Three claims are deliberately NOT what GenerateToken would put there:
//
//   - "uid" is omitted. It is the PLATFORM user-store key, and the
//     backbone's subject is a key in a DIFFERENT store; copying one into
//     the other would let a numeric collision resolve some unrelated
//     platform user. The routes that re-read the platform user from it
//     (/login/refresh and session creation) therefore refuse a
//     backbone-issued session, which is the correct fail-closed answer
//     until the two stores converge in phase 3 of #644. The client renews
//     by logging in again (docs/auth/architecture.md lists every site).
//   - "sub" and "user_id" carry the backbone's subject verbatim, which is
//     the identifier the seam republishes as the session principal.
//   - "email" carries that same subject. The backbone's identity hydrator
//     projects the principal's login name as the subject and carries no
//     separate address, and the platform enrols the operator's email
//     address AS that login name, so for a platform principal the subject
//     is the email. Inventing a metadata key no hydrator in this stack
//     writes would be worse than saying that plainly.
func (service *Service) IssueSession(identity *quicbaas.Identity) (string, time.Time, error) {
	if service == nil {
		return "", time.Time{}, ErrSignerUnavailable
	}
	if identity == nil {
		return "", time.Time{}, ErrIdentityRequired
	}
	if identity.Subject == "" {
		return "", time.Time{}, ErrIdentitySubjectRequired
	}
	if identity.TenantID == "" {
		return "", time.Time{}, ErrIdentityTenantRequired
	}

	now := time.Now()
	expiresAt := now.Add(time.Minute * time.Duration(service.params.Expiration))
	roles := append([]string(nil), identity.Roles...)

	token := jwt.NewWithClaims(service.signingMethod, TokenClaims{
		UserIDStr: identity.Subject,
		Email:     identity.Subject,
		TenantID:  identity.TenantID,
		Roles:     roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        newTokenID(),
			Subject:   identity.Subject,
			Audience:  jwt.ClaimStrings{service.params.Audience},
			Issuer:    service.params.Issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
		},
	})
	signed, err := token.SignedString(service.signer)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, expiresAt, nil
}
