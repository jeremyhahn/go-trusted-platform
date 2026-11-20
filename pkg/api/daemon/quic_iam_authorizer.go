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
// for the certificate's subject in its tenant, never by a wildcard scope
// (#2016). A certificate carries no roles, so the subject's stored IAM user
// in that tenant supplies them: the PEP's RBAC chain decides from the roles
// it is given and resolves no permission from none (PR #2082 review). A
// missing subject or tenant, a missing IAM client, a missing user or a
// lookup error is a denial; an error is never allow.
func (a *iamTokenAuthorizer) CheckPeerPermission(ctx context.Context, authCtx *platformtoken.AuthorizedContext, resource, action string) (bool, error) {
	if authCtx == nil || authCtx.Subject == "" || authCtx.TenantID == "" {
		return false, nil
	}
	roles, ok := a.storedRoles(ctx, authCtx.TenantID, authCtx.Subject)
	if !ok {
		return false, nil
	}
	return checkPrincipalPermission(ctx, a.pep, &tokenPrincipal{
		Subject:  authCtx.Subject,
		TenantID: authCtx.TenantID,
		Roles:    roles,
	}, resource, action)
}

// storedRoles returns the role grants the IAM store holds for userID in
// tenantID. ok is false when there is no IAM client, the lookup fails or
// no user is stored: the caller denies, and the cause is not passed on.
func (a *iamTokenAuthorizer) storedRoles(ctx context.Context, tenantID, userID string) ([]string, bool) {
	if a.iam == nil {
		return nil, false
	}
	users := a.iam.User()
	if users == nil {
		return nil, false
	}
	lookupCtx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()
	user, err := users.Get(lookupCtx, tenantID, userID)
	if err != nil || user == nil {
		return nil, false
	}
	if user.TenantID != "" && user.TenantID != tenantID {
		return nil, false
	}
	return user.Roles, true
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
