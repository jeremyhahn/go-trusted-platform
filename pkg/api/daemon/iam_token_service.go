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
	"errors"
	"strings"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/jwt"
)

// IAMTokenReason classifies why a token was rejected. It is the wire value of
// VerifyIAMTokenResponse.reason and of the MCP iam_verify_token "reason" field.
type IAMTokenReason string

const (
	// IAMTokenMalformed: the token is not a well-formed token of the expected type.
	IAMTokenMalformed IAMTokenReason = "malformed"
	// IAMTokenExpired: the signature is good but the token's exp has passed.
	IAMTokenExpired IAMTokenReason = "expired"
	// IAMTokenBadSignature: the signature does not verify against any trusted
	// key, including a token signed by a key the platform does not trust.
	IAMTokenBadSignature IAMTokenReason = "bad_signature"
	// IAMTokenRevoked: the token verifies but the liveness authority reports it
	// revoked or its subject disabled.
	IAMTokenRevoked IAMTokenReason = "revoked"
	// IAMTokenWrongIssuer: the token was issued by an untrusted issuer.
	IAMTokenWrongIssuer IAMTokenReason = "wrong_issuer"
	// IAMTokenWrongAudience: the token is not addressed to this platform.
	IAMTokenWrongAudience IAMTokenReason = "wrong_audience"
	// IAMTokenRejected: the validator rejected the token without a finer class
	// (the legacy QuicBaaS validator answers only valid or not).
	IAMTokenRejected IAMTokenReason = "rejected"
)

// iamTokenOpCreate and iamTokenOpRevoke name the token operations the IAM
// service refuses because tokens are issued and revoked through OIDC flows.
const (
	iamTokenOpCreate = "create"
	iamTokenOpRevoke = "revoke"
)

// IAMTokenClaims are the verified claims a valid token carries. Fields the
// issuing validator does not supply are left empty.
type IAMTokenClaims struct {
	Subject   string
	TenantID  string
	Scopes    []string
	Roles     []string
	ExpiresAt int64
}

// IAMTokenVerification is the answer to a token verification. Claims is set
// only when Valid; Reason only when not.
type IAMTokenVerification struct {
	Valid  bool
	Reason IAMTokenReason
	Claims *IAMTokenClaims
}

// iamTokenVerifier checks a token and returns its claims. A rejected token
// returns ErrIAMTokenInvalid carrying its IAMTokenReason; any other error
// means the token could not be checked at all.
type iamTokenVerifier interface {
	verifyIAMToken(ctx context.Context, token string) (*IAMTokenClaims, error)
}

// IAMTokenService is the one service-layer entry point for the IAM token
// operations. Every transport (gRPC, QUIC, MCP and the embedded SDK
// transport) calls it, so all of them give the same answer for a token.
type IAMTokenService struct {
	verifier iamTokenVerifier
}

// newIAMTokenService returns a service backed by verifier. A nil verifier
// yields a service whose Verify always fails with
// ErrIAMTokenVerifierNotConfigured.
func newIAMTokenService(verifier iamTokenVerifier) *IAMTokenService {
	return &IAMTokenService{verifier: verifier}
}

// selectIAMTokenVerifier picks the validator the daemon authenticates
// requests with: the broker platform-token validator when platform tokens are
// enabled, otherwise the gRPC or QUIC local validator. It returns a nil
// interface when none is wired, so the service refuses rather than answers.
func selectIAMTokenVerifier(shared *platformTokenValidator, grpcValidator, quicValidator *grpcTokenValidator) iamTokenVerifier {
	switch {
	case shared != nil:
		return shared
	case grpcValidator != nil:
		return grpcValidator
	case quicValidator != nil:
		return quicValidator
	default:
		return nil
	}
}

// Verify checks token with the daemon's token validator: signature, expiry,
// issuer, audience and, where the validator has a liveness authority,
// revocation. A rejected token is an answer (Valid false with a Reason), not
// an error. Errors mean no answer: ErrIAMTokenVerifierNotConfigured when no
// validator is wired, ErrIAMMissingParameter for a blank token, and
// ErrTokenValidationFailed (or ErrQuicBaaSServiceUnavailable) when the
// validator could not be reached. The token is never logged or echoed.
func (s *IAMTokenService) Verify(ctx context.Context, token string) (*IAMTokenVerification, error) {
	if s == nil || s.verifier == nil {
		return nil, ErrIAMTokenVerifierNotConfigured{}
	}
	if strings.TrimSpace(token) == "" {
		return nil, ErrIAMMissingParameter{Parameter: "token"}
	}
	claims, err := s.verifier.verifyIAMToken(ctx, token)
	var rejected ErrIAMTokenInvalid
	if errors.As(err, &rejected) {
		return &IAMTokenVerification{Valid: false, Reason: IAMTokenReason(rejected.Reason)}, nil
	}
	if err != nil {
		return nil, err
	}
	return &IAMTokenVerification{Valid: true, Claims: claims}, nil
}

// Create refuses token issuance: the SDK IAM client has no token-issue
// operation, and platform tokens are issued by the broker's OIDC flows.
func (s *IAMTokenService) Create() error {
	return ErrIAMTokenViaOIDC{Op: iamTokenOpCreate}
}

// Revoke refuses token revocation: the SDK IAM client has no token-revoke
// operation, and platform tokens are revoked by the broker's OIDC flows.
func (s *IAMTokenService) Revoke() error {
	return ErrIAMTokenViaOIDC{Op: iamTokenOpRevoke}
}

// verifyIAMToken verifies a broker platform token: signature against the
// issuer JWKS, issuer, audience and expiry, then revocation through the
// liveness authority in online and hybrid authz modes. DPoP is not checked:
// the caller asking about a token is not the token's presenter, so there is
// no proof to bind.
func (p *platformTokenValidator) verifyIAMToken(ctx context.Context, token string) (*IAMTokenClaims, error) {
	claims, err := p.validator.ValidatePlatformToken(ctx, token)
	if err != nil {
		return nil, classifyPlatformTokenError(err)
	}
	if p.liveness != nil {
		active, err := p.liveness.CheckLiveness(ctx, token, claims)
		if err != nil {
			return nil, ErrTokenValidationFailed{Cause: err}
		}
		if !active {
			return nil, ErrIAMTokenInvalid{Reason: string(IAMTokenRevoked)}
		}
	}
	authorized := platformtoken.Authorize(claims)
	verified := &IAMTokenClaims{
		Subject:  authorized.Subject,
		TenantID: authorized.TenantID,
		Scopes:   authorized.Scopes,
		Roles:    authorized.Roles,
	}
	if claims.ExpiresAt != nil {
		verified.ExpiresAt = claims.ExpiresAt.Unix()
	}
	return verified, nil
}

// classifyPlatformTokenError maps a platformtoken rejection to
// ErrIAMTokenInvalid with its reason. Errors that are not about the token
// (a JWKS fetch failure, an unknown error) become ErrTokenValidationFailed.
func classifyPlatformTokenError(err error) error {
	var (
		expired    *platformtoken.ExpiredTokenError
		inactive   *platformtoken.TokenInactiveError
		issuer     *platformtoken.InvalidIssuerError
		audience   *platformtoken.InvalidAudienceError
		unknownKID *platformtoken.UnknownKeyIDError
		tokenType  *platformtoken.InvalidTokenTypeError
		invalid    *platformtoken.InvalidTokenError
	)
	switch {
	case errors.As(err, &expired):
		return ErrIAMTokenInvalid{Reason: string(IAMTokenExpired)}
	case errors.As(err, &inactive):
		return ErrIAMTokenInvalid{Reason: string(IAMTokenRevoked)}
	case errors.As(err, &issuer):
		return ErrIAMTokenInvalid{Reason: string(IAMTokenWrongIssuer)}
	case errors.As(err, &audience):
		return ErrIAMTokenInvalid{Reason: string(IAMTokenWrongAudience)}
	case errors.As(err, &unknownKID):
		return ErrIAMTokenInvalid{Reason: string(IAMTokenBadSignature)}
	case errors.As(err, &tokenType):
		return ErrIAMTokenInvalid{Reason: string(IAMTokenMalformed)}
	case errors.As(err, &invalid):
		return ErrIAMTokenInvalid{Reason: string(classifyJWTRejection(err))}
	default:
		return ErrTokenValidationFailed{Cause: err}
	}
}

// classifyJWTRejection reads the golang-jwt sentinel errors a JWT parser
// wraps into its rejection. A rejection that names none of them is
// IAMTokenRejected.
func classifyJWTRejection(err error) IAMTokenReason {
	switch {
	case errors.Is(err, gojwt.ErrTokenExpired):
		return IAMTokenExpired
	case errors.Is(err, gojwt.ErrTokenSignatureInvalid), errors.Is(err, gojwt.ErrTokenUnverifiable):
		return IAMTokenBadSignature
	case errors.Is(err, gojwt.ErrTokenMalformed):
		return IAMTokenMalformed
	default:
		return IAMTokenRejected
	}
}

// verifyIAMToken verifies a token the way ValidateToken authenticates one:
// the platform JWT verifiers first, then the QuicBaaS validator. A platform
// JWT that verifies but has expired is rejected as expired outright. Any
// other platform JWT rejection may still be a valid QuicBaaS-minted token,
// so QuicBaaS decides; it answers only valid or not, so its rejection is
// IAMTokenRejected. Without QuicBaaS the platform JWT rejection is the answer.
func (v *grpcTokenValidator) verifyIAMToken(ctx context.Context, token string) (*IAMTokenClaims, error) {
	claims, jwtErr := v.platformJWTClaims(token)
	if jwtErr == nil {
		return iamClaimsFromPlatformJWT(claims), nil
	}
	reason := classifyJWTRejection(jwtErr)
	if reason == IAMTokenExpired {
		return nil, ErrIAMTokenInvalid{Reason: string(reason)}
	}
	if v.service == nil {
		if errors.As(jwtErr, &ErrNoPlatformJWTVerifier{}) {
			return nil, ErrIAMTokenVerifierNotConfigured{}
		}
		return nil, ErrIAMTokenInvalid{Reason: string(reason)}
	}
	resp, err := v.validateWithQuicBaaS(ctx, token)
	if err != nil {
		return nil, err
	}
	if !resp.Valid {
		return nil, ErrIAMTokenInvalid{Reason: string(IAMTokenRejected)}
	}
	return &IAMTokenClaims{Subject: resp.UserID, Roles: resp.Roles, ExpiresAt: resp.ExpiresAt}, nil
}

// iamClaimsFromPlatformJWT maps a verified platform JWT to IAMTokenClaims.
// Platform JWTs carry no scopes.
func iamClaimsFromPlatformJWT(claims *jwt.TokenClaims) *IAMTokenClaims {
	verified := &IAMTokenClaims{
		Subject:  platformJWTSubject(claims),
		TenantID: claims.TenantID,
		Roles:    claims.Roles,
	}
	if claims.ExpiresAt != nil {
		verified.ExpiresAt = claims.ExpiresAt.Unix()
	}
	return verified
}

// platformJWTSubject is the principal a platform JWT names: its user_id
// claim, falling back to sub.
func platformJWTSubject(claims *jwt.TokenClaims) string {
	if claims.UserIDStr != "" {
		return claims.UserIDStr
	}
	return claims.Subject
}
