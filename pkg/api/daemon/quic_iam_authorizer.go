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
	"strconv"
	"strings"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
)

// tokenPrincipal is the caller a validated token names — the IAM subject a
// permission check is decided for.
type tokenPrincipal struct {
	Subject  string
	TenantID string
	Roles    []string
}

// principalResolver validates a bearer token and returns the principal it
// names. grpcTokenValidator is the production implementation.
type principalResolver interface {
	ResolvePrincipal(ctx context.Context, token string) (*tokenPrincipal, error)
}

// ResolvePrincipal validates token exactly as ValidateToken does and returns
// the principal it names. A platform JWT carries subject, tenant and roles; a
// QuicBaaS-minted token carries no tenant, so its principal has an empty
// TenantID.
func (v *grpcTokenValidator) ResolvePrincipal(ctx context.Context, token string) (*tokenPrincipal, error) {
	if claims, err := v.platformJWTClaims(token); err == nil {
		return &tokenPrincipal{Subject: platformJWTSubject(claims), TenantID: claims.TenantID, Roles: claims.Roles}, nil
	}
	resp, err := v.validateWithQuicBaaS(ctx, token)
	if err != nil {
		return nil, err
	}
	if !resp.Valid {
		return nil, ErrTokenValidationFailed{}
	}
	return &tokenPrincipal{Subject: resp.UserID, Roles: resp.Roles}, nil
}

// TokenPrincipal implements grpc.PrincipalTokenValidator: the gRPC
// interceptor's legacy path binds the principal and tenant a local token names,
// so tenant-scoped RPCs see the caller (SPEC row 109).
func (v *grpcTokenValidator) TokenPrincipal(ctx context.Context, token string) (*platformtoken.AuthorizedContext, error) {
	p, err := v.ResolvePrincipal(ctx, token)
	if err != nil {
		return nil, err
	}
	return &platformtoken.AuthorizedContext{Subject: p.Subject, TenantID: p.TenantID, Roles: p.Roles}, nil
}

// iamTokenAuthorizer is the QUIC AuthorizationChecker for tokens that carry no
// scope claims — the local validator used when platform tokens are off. It
// asks the IAM policy enforcement point whether the token's principal may
// perform the operation's action on its resource, the same decision
// IAMGRPCService.CheckPermission makes.
//
// It fails closed: a principal without a subject or a tenant is denied,
// because the PEP decides per tenant. QuicBaaS-minted tokens carry no tenant,
// so they cannot reach a classified QUIC operation through this path.
type iamTokenAuthorizer struct {
	principals principalResolver
	pep        quicbaassdk.IAMPEPClient
	// iam resolves a certificate principal's stored role grants; the
	// token path never uses it (its roles come from the token).
	iam quicbaassdk.IAMClient
}

// CheckPeerPermission implements quic.PeerAuthorizationChecker: a QUIC
// caller authenticated by its client certificate is decided by the IAM PEP
// for the certificate's stored IAM user in its tenant, never by a wildcard
// scope (#2016). The mTLS adapter sets the subject to the certificate's
// email SAN, else its CN, which the store does not take as a user ID, so the
// subject is first resolved to its stored user (PR #2082 review) with the
// IAM List lookup: the pinned SDK serves neither GetByEmail nor
// FindByUsername on its gRPC or REST/HTTP3 transports, and List is the user
// lookup it carries end to end. That user's canonical ID and roles go to the
// PEP, whose RBAC chain decides from the roles it is given and resolves no
// permission from none. A missing subject or tenant, a missing IAM client,
// an unknown or ambiguous subject, a user of another tenant or a lookup
// error is a denial; an error is never allow. A tenant whose users exceed
// one List page denies callers beyond it (fail closed) until the SDK
// lookups are fixed upstream.
func (a *iamTokenAuthorizer) CheckPeerPermission(ctx context.Context, authCtx *platformtoken.AuthorizedContext, resource, action string) (bool, error) {
	if authCtx == nil || authCtx.Subject == "" || authCtx.TenantID == "" {
		return false, nil
	}
	user, ok := a.certificateUser(ctx, authCtx.TenantID, authCtx.Subject)
	if !ok {
		return false, nil
	}
	return checkPrincipalPermission(ctx, a.pep, &tokenPrincipal{
		Subject:  user.ID,
		TenantID: authCtx.TenantID,
		Roles:    user.Roles,
	}, resource, action)
}

// certificateUserListPageSize is the page size certificateUser asks List
// for: the pinned server's limit cap.
const certificateUserListPageSize = 1000

// certificateUser resolves a certificate subject to the IAM user stored in
// tenantID: an email SAN subject by its email, any other subject (the CN) by
// its username. An email subject is matched after normalizeCertificateEmail,
// the IAM store's own email normalization; the username is matched as is.
// The pinned go-quicbaas SDK serves neither GetByEmail nor
// FindByUsername on its gRPC or REST/HTTP3 transports (gRPC answers
// Unimplemented; REST maps both to the users list and leaves the user
// empty), so the subject is matched in the tenant's List page, the one user
// lookup the SDK carries end to end. The SDK sends no offset, so only the
// first page is seen: a caller beyond it is denied (fail closed) until the
// SDK lookups are fixed upstream. ok is false when there is no IAM client,
// the lookup fails, no user or more than one user matches, the matched user
// has no ID or belongs to another tenant: the caller denies, and the cause
// is not passed on.
func (a *iamTokenAuthorizer) certificateUser(ctx context.Context, tenantID, subject string) (*sdkiam.User, bool) {
	if a.iam == nil {
		return nil, false
	}
	users := a.iam.User()
	if users == nil {
		return nil, false
	}
	lookupCtx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()
	resp, err := users.List(lookupCtx, tenantID, &sdkiam.ListUsersRequest{PageSize: certificateUserListPageSize})
	if err != nil || resp == nil {
		return nil, false
	}
	byEmail := strings.Contains(subject, "@")
	var normalized string
	if byEmail {
		normalized = normalizeCertificateEmail(subject)
	}
	var match *sdkiam.User
	for i := range resp.Users {
		candidate := &resp.Users[i]
		if byEmail {
			if normalizeCertificateEmail(candidate.Email) != normalized {
				continue
			}
		} else if candidate.Username != subject {
			continue
		}
		if match != nil {
			return nil, false
		}
		match = candidate
	}
	if match == nil || match.ID == "" || match.TenantID != tenantID {
		return nil, false
	}
	return match, true
}

// normalizeCertificateEmail mirrors the IAM store's NormalizeEmail
// (lowercase and trim), which canonicalizes every stored email key, so a
// certificate's email SAN is compared with stored emails in the same form.
func normalizeCertificateEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// newIAMTokenAuthorizer returns an authorizer backed by pep. Both arguments
// are required; without a PEP there is no decision to delegate to.
func newIAMTokenAuthorizer(principals principalResolver, pep quicbaassdk.IAMPEPClient) (*iamTokenAuthorizer, error) {
	if principals == nil {
		return nil, ErrInvalidConfig{Reason: "IAM token authorizer requires a token validator"}
	}
	if pep == nil {
		return nil, ErrPEPClientNotAvailable{}
	}
	return &iamTokenAuthorizer{principals: principals, pep: pep}, nil
}

// CheckPermission implements quic.AuthorizationChecker.
func (a *iamTokenAuthorizer) CheckPermission(ctx context.Context, token, resource, action string) (bool, error) {
	principal, err := a.principals.ResolvePrincipal(ctx, token)
	if err != nil {
		return false, err
	}
	return checkPrincipalPermission(ctx, a.pep, principal, resource, action)
}

// checkPrincipalPermission asks the IAM policy enforcement point whether
// principal may perform action on resource. An empty resource or action is
// refused before the PEP is asked: no permission names nothing (#926). A
// principal without a subject or tenant is denied, and a PEP that cannot
// answer fails the check closed.
func checkPrincipalPermission(ctx context.Context, pep quicbaassdk.IAMPEPClient, principal *tokenPrincipal, resource, action string) (bool, error) {
	if strings.TrimSpace(resource) == "" || strings.TrimSpace(action) == "" {
		return false, ErrEmptyPermission{Resource: resource, Action: action}
	}
	if pep == nil {
		return false, ErrPEPClientNotAvailable{}
	}
	if principal == nil || principal.Subject == "" || principal.TenantID == "" {
		return false, nil
	}

	checkCtx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	resp, err := pep.Check(checkCtx, &sdkiam.CheckRequest{
		Subject: sdkiam.CheckSubject{
			ID:       principal.Subject,
			TenantID: principal.TenantID,
			Roles:    principal.Roles,
		},
		Action:   action,
		Resource: resource,
	})
	if err != nil {
		return false, ErrIAMPermissionCheckFailed{Cause: err}
	}
	return resp != nil && resp.Allowed, nil
}

// ErrPEPClientNotAvailable is returned when the PEP client is nil.
type ErrPEPClientNotAvailable struct{}

func (e ErrPEPClientNotAvailable) Error() string {
	return "PEP client is not available"
}

// ErrEmptyPermission is returned when a permission check names no resource or
// no action. It is a denial, never an allow (#926).
type ErrEmptyPermission struct {
	Resource string
	Action   string
}

func (e ErrEmptyPermission) Error() string {
	return "permission check refused: resource " + strconv.Quote(e.Resource) + " and action " + strconv.Quote(e.Action) + " must both be named"
}
