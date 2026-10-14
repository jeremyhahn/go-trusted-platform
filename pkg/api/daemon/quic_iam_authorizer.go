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

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
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
	if principal.Subject == "" || principal.TenantID == "" {
		return false, nil
	}

	checkCtx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	resp, err := a.pep.Check(checkCtx, &sdkiam.CheckRequest{
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
