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
	"log/slog"
	"slices"
	"strings"

	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	apiquic "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/auth"
	"github.com/jeremyhahn/go-trusted-platform/pkg/auth/iamuser"
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
	// pep decides each candidate permission (IAMPEPClient.Check); the
	// roles' permission lists only name the candidates.
	pep sdkiam.PEPClient
	// catalog holds the concrete permissions a wildcard candidate is
	// expanded against before the PEP decides each of them.
	catalog []string
}

// concretePermissionCatalog returns every concrete resource:action the
// platform's transports require: the gRPC, QUIC and MCP scope catalogs,
// plus the REST method actions (read, write, delete) for each of their
// resources, since REST route scopes are computed rather than tabled.
// The result is sorted and distinct and holds no wildcard.
func concretePermissionCatalog() []string {
	var union []string
	union = append(union, grpcapi.Scopes()...)
	union = append(union, apiquic.OperationScopes()...)
	union = append(union, mcp.SupportedScopes()...)
	resources := make(map[string]struct{})
	for _, permission := range union {
		if resource, _, ok := strings.Cut(permission, ":"); ok && resource != "" {
			resources[resource] = struct{}{}
		}
	}
	for resource := range resources {
		for _, action := range restMethodActions {
			union = append(union, resource+":"+action)
		}
	}
	catalog := make([]string, 0, len(union))
	for _, permission := range union {
		if permission != "" && !strings.Contains(permission, "*") {
			catalog = append(catalog, permission)
		}
	}
	slices.Sort(catalog)
	return slices.Compact(catalog)
}

// newIAMCertificatePrincipals returns a resolver backed by IAM. Both clients
// are required: without them there is no principal to resolve.
func newIAMCertificatePrincipals(users sdkiam.UserClient, roles sdkiam.RoleClient, pep sdkiam.PEPClient) (*iamCertificatePrincipals, error) {
	if users == nil || roles == nil {
		return nil, ErrInvalidConfig{Reason: "the mTLS principal resolver requires the IAM user and role clients"}
	}
	if pep == nil {
		return nil, ErrPEPClientNotAvailable{}
	}
	return &iamCertificatePrincipals{users: users, roles: roles, pep: pep, catalog: concretePermissionCatalog()}, nil
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
		user, err = p.findPrincipal(lookupCtx, tenantID, identity)
	}
	if errors.Is(err, iamuser.ErrTruncated) {
		slog.Warn("mTLS principal refused: the IAM user listing may be truncated, so the certificate's principal could not be resolved",
			"tenant_id", tenantID, "principal", identity.ID)
		return nil, ErrCertificatePrincipalUnresolved{Reason: "the IAM user listing may be truncated", Cause: err}
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

	candidates := make([]string, 0)
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
			candidates = append(candidates, permission)
		}
	}

	// The policy decision point decides every request (docs/SPEC.md:
	// go-qrdb decides), so it is asked about every concrete permission in
	// the catalog, not only those the roles list: an explicit ABAC allow
	// with no matching role permission is a scope too, and a principal
	// with no roles is still decided (#1906 Codex). A concrete role
	// permission outside the catalog is asked as well. A wildcard is
	// never copied into Scopes (RequireScope matches a wildcard scope
	// against any operation); the catalog already holds every concrete
	// permission one covers. Only permissions the PEP allows become
	// scopes; a PEP error refuses the principal (fail closed).
	concrete := make([]string, 0, len(p.catalog)+len(candidates))
	listed := make(map[string]struct{}, len(p.catalog)+len(candidates))
	appendConcrete := func(permission string) {
		if _, dup := listed[permission]; dup {
			return
		}
		listed[permission] = struct{}{}
		concrete = append(concrete, permission)
	}
	for _, permission := range p.catalog {
		appendConcrete(permission)
	}
	for _, candidate := range candidates {
		if _, _, ok := strings.Cut(candidate, ":"); ok && !strings.Contains(candidate, "*") {
			appendConcrete(candidate)
		}
	}

	subject := &tokenPrincipal{Subject: user.ID, TenantID: tenantID, Roles: user.Roles}
	scopes := make([]string, 0, len(concrete))
	for _, permission := range concrete {
		resource, action, _ := strings.Cut(permission, ":")
		allowed, checkErr := checkPrincipalPermission(lookupCtx, p.pep, subject, resource, action)
		if checkErr != nil {
			return nil, ErrCertificatePrincipalUnresolved{
				Reason: "the IAM policy decision point could not decide the principal's permission " + permission,
				Cause:  checkErr,
			}
		}
		if allowed {
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

// findPrincipal looks the certificate's principal up by email when the
// certificate names it by an email SAN, else by username, through
// iamuser.Find: the transport's own lookup first and, where the transport
// does not register it (the pinned embedded transport has no User/GetByEmail
// or User/FindByUsername), the tenant's User/List.
func (p *iamCertificatePrincipals) findPrincipal(ctx context.Context, tenantID string, identity *auth.Identity) (*sdkiam.User, error) {
	id := strings.TrimSpace(identity.ID)
	list := func(ctx context.Context, req *sdkiam.ListUsersRequest) (*sdkiam.ListUsersResponse, error) {
		return p.users.List(ctx, tenantID, req)
	}
	if strings.Contains(id, "@") || (identity.Email != "" && strings.EqualFold(id, strings.TrimSpace(identity.Email))) {
		return iamuser.Find(ctx, func(ctx context.Context) (*sdkiam.User, error) {
			return p.users.GetByEmail(ctx, tenantID, id)
		}, list, iamuser.ByEmail(id))
	}
	return iamuser.Find(ctx, func(ctx context.Context) (*sdkiam.User, error) {
		return p.users.FindByUsername(ctx, tenantID, id)
	}, list, iamuser.ByUsername(id))
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
