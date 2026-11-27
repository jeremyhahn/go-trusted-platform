package daemon

import (
	"context"
	"slices"
	"strconv"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	webiam "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// callerTenant reports the tenant the authenticated caller is bound to. The
// second result is false when the caller carries no tenant-bound identity:
// the Unix-socket operator, authenticated by peer credentials, and a daemon
// run with SkipIAMValidation.
//
// The sources mirror the REST session: a validated platform token (gRPC,
// QUIC or MCP) carries its tenant_id claim, and an mTLS client certificate carries
// the tenant the certificate authenticator extracted from it.
func callerTenant(ctx context.Context) (string, bool) {
	if authCtx, ok := grpcapi.AuthorizedContextFromContext(ctx); ok && authCtx != nil {
		return authCtx.TenantID, true
	}
	if authCtx, ok := quic.AuthorizedContextFromContext(ctx); ok && authCtx != nil {
		return authCtx.TenantID, true
	}
	if authCtx, ok := mcp.AuthorizedContextFromContext(ctx); ok && authCtx != nil {
		return authCtx.TenantID, true
	}
	if identity := IdentityFromContext(ctx); identity != nil {
		return identity.TenantID, true
	}
	return "", false
}

// callerUserID returns the authenticated caller's numeric user id: the
// subject of a platform token (gRPC, QUIC or MCP) or the IAM user id an mTLS
// identity resolved to. It reports false when the caller has none, or when
// the id is not a positive decimal integer.
func callerUserID(ctx context.Context) (uint64, bool) {
	id, err := strconv.ParseUint(callerSubject(ctx), 10, 64)
	if err != nil || id == 0 {
		return 0, false
	}
	return id, true
}

// callerSubject returns the verified caller's raw subject: a decimal IAM
// user id, or a login name or email that has to be resolved to one.
func callerSubject(ctx context.Context) string {
	subject, _ := callerPrincipal(ctx)
	return subject
}

// callerPrincipal returns the verified caller's raw subject and, from the
// same credential, the other names it carries (the mTLS certificate email
// and common name, or the IAM session email).
func callerPrincipal(ctx context.Context) (string, []string) {
	if authCtx, ok := grpcapi.AuthorizedContextFromContext(ctx); ok && authCtx != nil {
		return authCtx.Subject, nil
	} else if authCtx, ok := quic.AuthorizedContextFromContext(ctx); ok && authCtx != nil {
		return authCtx.Subject, nil
	} else if authCtx, ok := mcp.AuthorizedContextFromContext(ctx); ok && authCtx != nil {
		return authCtx.Subject, nil
	} else if identity := IdentityFromContext(ctx); identity != nil {
		return identity.UserID, []string{identity.Email, identity.Name}
	} else if authCtx, ok := webiam.AuthorizedContextFromContext(ctx); ok && authCtx != nil {
		// The webservice REST path stores the verified platform token here.
		return authCtx.Subject, nil
	} else if session, ok := webiam.GetSessionFromContext(ctx); ok && session != nil {
		// The webservice REST path stores a verified IAM session here.
		return session.UserID(), []string{session.Email()}
	}
	return "", nil
}

// callerEmails returns the verified caller's login names or emails, in
// order and without blanks or repeats, for resolution to a stored IAM user.
func callerEmails(ctx context.Context) []string {
	subject, aliases := callerPrincipal(ctx)
	var out []string
	for _, v := range append([]string{subject}, aliases...) {
		if v == "" || slices.Contains(out, v) {
			continue
		}
		out = append(out, v)
	}
	return out
}

// authorizeIAMTenant refuses an IAM request that names a tenant other than
// the caller's own, with codes.PermissionDenied — the same refusal the REST
// IAM tree gives with 403 from RequireOwnTenant, so no transport answers a
// tenant-bound caller from another tenant.
func authorizeIAMTenant(ctx context.Context, requested string) error {
	caller, bound := callerTenant(ctx)
	if !bound {
		return nil
	}
	if err := iamTenantDecision(caller, requested); err != nil {
		return status.Error(codes.PermissionDenied, err.Error())
	}
	return nil
}

// iamTenantDecision is the own-tenant rule every transport applies to a
// bound caller: the request may name only the caller's tenant. gRPC, QUIC
// and MCP reach it through authorizeIAMTenant; REST calls it directly with
// the tenant of the authenticated caller.
func iamTenantDecision(caller, requested string) error {
	if caller == requested {
		return nil
	}
	return ErrIAMTenantForbidden{Requested: requested}
}

// authorizeSystemCaller refuses a cross-tenant request — creating or listing
// tenants — from any tenant-bound caller but the system tenant
// (tenant.AuthorizeCrossTenant), with codes.PermissionDenied. It is the rule
// the REST trees enforce with RequireSystemTenant; a caller with no
// tenant-bound identity is admitted, as callerTenant documents, and an unset
// systemTenantID admits no tenant-bound caller.
func authorizeSystemCaller(ctx context.Context, systemTenantID, method string) error {
	caller, bound := callerTenant(ctx)
	if !bound {
		return nil
	}
	if err := systemCallerDecision(systemTenantID, caller, method); err != nil {
		return status.Error(codes.PermissionDenied, err.Error())
	}
	return nil
}

// systemCallerDecision is the system-tenant rule every transport applies to
// a bound caller: only the system tenant may run a cross-tenant method.
func systemCallerDecision(systemTenantID, caller, method string) error {
	return tenant.AuthorizeCrossTenant(tenant.IsSystemTenant(systemTenantID, caller), method)
}
