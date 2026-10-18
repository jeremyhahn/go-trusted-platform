package proxy

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// Token-path constants: the RFC 9449 DPoP proof header, the Authorization
// bearer scheme prefix, and the AuthMethod recorded for token identities.
const (
	headerDPoP      = "DPoP"
	bearerPrefix    = "Bearer "
	authMethodToken = "token"
)

// TokenPrincipal is the verified identity a TokenAuthenticator establishes
// from a platform access token.
type TokenPrincipal struct {
	// Subject is the stable subject identifier (the token sub claim).
	Subject string
	// TenantID is the tenant the principal operates within.
	TenantID string
	// Scopes is the granted scope set, carried for audit enrichment; scope
	// ENFORCEMENT happens inside the authenticator, which owns the
	// wildcard-aware grant semantics of the platform scope catalog.
	Scopes []string
	// Roles is the supplemental RBAC roles claim.
	Roles []string
}

// TokenAuthRequest carries one request's token credential and the route's
// authorization demands to a TokenAuthenticator.
type TokenAuthRequest struct {
	// Token is the bearer access token (Authorization header, scheme
	// stripped).
	Token string
	// DPoPProof is the RFC 9449 DPoP header value, empty when absent. It is
	// consulted when the token is sender-constrained (cnf.jkt).
	DPoPProof string
	// HTM is the request HTTP method the DPoP proof must be bound to.
	HTM string
	// HTU is the absolute request URI (scheme://host/path) the DPoP proof
	// must be bound to.
	HTU string
	// RequiredScopes are the route's required scopes. The authenticator
	// enforces every entry with the platform's wildcard-aware grant
	// semantics and returns an error wrapping ErrTokenScopeDenied when one
	// is missing. Empty means authentication without a scope requirement.
	RequiredScopes []string
}

// TokenAuthenticator validates a platform access token (including its DPoP
// sender-constraint when the token carries one) and enforces the required
// scopes. It is the seam to the platformtoken SDK validator, adapted in
// pkg/sdn/gateway/proxysvc so this package composes against behavior rather
// than the SDK's dependency graph. Scope-denial errors wrap
// ErrTokenScopeDenied; every other error denies as an invalid token.
type TokenAuthenticator interface {
	Authorize(ctx context.Context, req *TokenAuthRequest) (*TokenPrincipal, error)
}

// authenticateToken runs the bearer-token path for token and (certificate-
// less) mtls-or-token requests. It returns the authenticated identity or a
// deny decision; exactly one is non-nil.
func (c *Chain) authenticateToken(ctx context.Context, r *http.Request, route *CompiledRoute) (*ClientIdentity, *AuthDecision) {
	req := &route.cfg.Auth
	if c.token == nil {
		return nil, deny(ReasonTokenAuthNotConfigured)
	}
	// An IDevID lives in the client certificate; a token-only caller cannot
	// present one. Pure token mode rejects the combination at Validate; this
	// covers the mtls-or-token route reached without a certificate.
	if req.RequireIDevID {
		return nil, deny(ReasonIDevIDRequired)
	}
	token := bearerToken(r.Header.Get(headerAuthorization))
	if token == "" {
		return nil, deny(ReasonTokenMissing)
	}
	principal, err := c.token.Authorize(ctx, &TokenAuthRequest{
		Token:          token,
		DPoPProof:      r.Header.Get(headerDPoP),
		HTM:            r.Method,
		HTU:            requestHTU(r),
		RequiredScopes: req.RequiredScopes,
	})
	if err != nil {
		c.logger.Warn("proxy: token authentication failed",
			"route", route.cfg.ID, "error", err)
		if errors.Is(err, ErrTokenScopeDenied) {
			return nil, deny(ReasonTokenScopeDenied)
		}
		return nil, deny(ReasonTokenInvalid)
	}

	clientZone, decision := c.checkTokenZone(req)
	if decision != nil {
		return nil, decision
	}
	return &ClientIdentity{
		ID:         principal.Subject,
		Zone:       clientZone,
		AuthMethod: authMethodToken,
		Roles:      principal.Roles,
	}, nil
}

// checkTokenZone enforces the route's zone requirements for a token
// principal. Token clients carry no certificate zone; when the route demands
// zones the operator-assigned Auth.TokenZone stands in and passes the same
// AllowedZones and zone-matrix checks a certificate zone would. A
// zone-enforcing route without a TokenZone denies with "zone_requires_mtls".
func (c *Chain) checkTokenZone(req *AuthRequirements) (string, *AuthDecision) {
	required := len(req.AllowedZones) > 0 || req.BackendZone != ""
	if !required {
		// Zone-free route: the token zone, when assigned, still enriches the
		// identity and the injected headers.
		return req.TokenZone, nil
	}
	if req.TokenZone == "" {
		return "", deny(ReasonZoneRequiresMTLS)
	}
	if len(req.AllowedZones) > 0 && !containsString(req.AllowedZones, req.TokenZone) {
		return "", deny(ReasonZoneNotAllowed)
	}
	if req.BackendZone != "" {
		// The matrix capability is validated at construction for
		// zone-requiring routes; guard defensively regardless.
		if c.matrix == nil {
			return "", deny(ReasonZoneMatrixDenied)
		}
		verdict := c.matrix().Allowed(zone.Zone(req.TokenZone), zone.Zone(req.BackendZone))
		if !verdict.Allowed {
			return "", deny(ReasonZoneMatrixDenied)
		}
	}
	return req.TokenZone, nil
}

// bearerToken extracts the token from an Authorization header value using
// the case-insensitive Bearer scheme. Any other scheme (or an empty header)
// yields "".
func bearerToken(header string) string {
	if len(header) <= len(bearerPrefix) || !strings.EqualFold(header[:len(bearerPrefix)], bearerPrefix) {
		return ""
	}
	return strings.TrimSpace(header[len(bearerPrefix):])
}

// requestHTU reconstructs the RFC 9449 DPoP htu (scheme://host/path) for a
// request terminating at this proxy. The proxy IS the TLS-terminating front
// door and the trust boundary, so — unlike services deployed behind another
// proxy — it deliberately ignores inbound X-Forwarded-Proto/Host headers:
// they arrive unauthenticated from the client and honoring them would let a
// caller replay a DPoP proof bound to a different origin. Query and fragment
// are omitted per RFC 9449 §4.3 canonicalization.
func requestHTU(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host + r.URL.Path
}

// isStale reports whether an attestation gate error is the definitive stale
// verdict.
func isStale(err error) bool {
	return errors.Is(err, ErrAttestationStale)
}
