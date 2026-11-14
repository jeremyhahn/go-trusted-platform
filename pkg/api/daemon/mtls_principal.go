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
	"strings"

	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/auth"
)

// CertificatePrincipal is the IAM principal a verified client certificate
// names, with the permissions IAM grants it (#1107).
type CertificatePrincipal struct {
	// Subject is the principal's IAM user id.
	Subject string
	// TenantID is the tenant the principal was resolved in.
	TenantID string
	// Roles are the role ids IAM assigns the principal.
	Roles []string
	// Scopes are the "resource:action" permissions those roles carry.
	Scopes []string
}

// CertificatePrincipalResolver maps the identity of a verified client
// certificate to its IAM principal. The mTLS peer authenticators grant the
// caller exactly what it returns, so a certificate carries its principal's
// permissions rather than every permission (#1107).
type CertificatePrincipalResolver interface {
	ResolveCertificatePrincipal(ctx context.Context, identity *auth.Identity) (*CertificatePrincipal, error)
}

// iamCertificatePrincipals resolves a certificate's principal through the
// IAM user and role clients: the user the certificate names in its tenant,
// and the permissions of the roles that user holds.
type iamCertificatePrincipals struct {
	users sdkiam.UserClient
	roles sdkiam.RoleClient
}

// newIAMCertificatePrincipals returns a resolver backed by IAM. Both clients
// are required: without them there is no principal to resolve.
func newIAMCertificatePrincipals(users sdkiam.UserClient, roles sdkiam.RoleClient) (*iamCertificatePrincipals, error) {
	if users == nil || roles == nil {
		return nil, ErrInvalidConfig{Reason: "the mTLS principal resolver requires the IAM user and role clients"}
	}
	return &iamCertificatePrincipals{users: users, roles: roles}, nil
}

// ResolveCertificatePrincipal implements CertificatePrincipalResolver. It
// fails closed: a certificate that names no principal or no tenant, a
// principal IAM does not hold or does not hold as active, and an IAM that
// cannot answer all refuse the certificate.
func (p *iamCertificatePrincipals) ResolveCertificatePrincipal(ctx context.Context, identity *auth.Identity) (*CertificatePrincipal, error) {
	if identity == nil || strings.TrimSpace(identity.TenantID) == "" ||
		(strings.TrimSpace(identity.ID) == "" && strings.TrimSpace(identity.UserID) == "") {
		return nil, ErrCertificatePrincipalUnresolved{Reason: "the certificate names no principal or no tenant"}
	}
	lookupCtx, cancel := context.WithTimeout(ctx, iamRequestTimeout)
	defer cancel()

	tenantID := identity.TenantID
	var user *sdkiam.User
	var err error
	if identity.UserID != "" {
		user, err = p.users.Get(lookupCtx, tenantID, identity.UserID)
	} else {
		user, err = p.users.FindByUsername(lookupCtx, tenantID, identity.ID)
	}
	if err != nil {
		return nil, ErrCertificatePrincipalUnresolved{Reason: "IAM holds no principal for the certificate", Cause: err}
	}
	if user == nil || user.ID == "" {
		return nil, ErrCertificatePrincipalUnresolved{Reason: "IAM holds no principal for the certificate"}
	}
	if !principalActive(user) {
		return nil, ErrCertificatePrincipalUnresolved{Reason: "the certificate's principal is not active"}
	}

	scopes := make([]string, 0)
	seen := make(map[string]struct{})
	for _, roleID := range user.Roles {
		role, roleErr := p.roles.Get(lookupCtx, tenantID, roleID)
		if roleErr != nil {
			return nil, ErrCertificatePrincipalUnresolved{Reason: "IAM could not read the principal's role " + roleID, Cause: roleErr}
		}
		if role == nil {
			continue
		}
		for _, permission := range role.Permissions {
			if _, dup := seen[permission]; dup || strings.TrimSpace(permission) == "" {
				continue
			}
			seen[permission] = struct{}{}
			scopes = append(scopes, permission)
		}
	}
	return &CertificatePrincipal{
		Subject:  user.ID,
		TenantID: tenantID,
		Roles:    append([]string(nil), user.Roles...),
		Scopes:   scopes,
	}, nil
}

// principalActive reports whether IAM holds the user as active. Lifecycle is
// the state the store holds; Status is the SDK's coarser enum, read only when
// the transport leaves Lifecycle empty.
func principalActive(user *sdkiam.User) bool {
	if user.Lifecycle != "" {
		return user.Lifecycle == "active"
	}
	return user.Status == sdkiam.UserStatusActive || user.Status == sdkiam.UserStatusUnspecified
}

// ErrCertificatePrincipalUnresolved is returned when a verified client
// certificate cannot be turned into an IAM principal. The certificate is
// refused: it is never admitted with a default grant (#1107).
type ErrCertificatePrincipalUnresolved struct {
	Reason string
	Cause  error
}

func (e ErrCertificatePrincipalUnresolved) Error() string {
	msg := "mTLS: client certificate refused: " + e.Reason
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

func (e ErrCertificatePrincipalUnresolved) Unwrap() error { return e.Cause }
