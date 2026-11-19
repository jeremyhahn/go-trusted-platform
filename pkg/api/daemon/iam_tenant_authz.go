package daemon

import (
	"context"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util/peercred"
	iammw "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// callerTenant reports the tenant the authenticated caller is bound to. The
// second result is false when the caller carries no tenant-bound identity:
// the Unix-socket operator, authenticated by peer credentials, and a caller
// with no identity at all (a daemon run with SkipIAMValidation).
// authorizeUnboundCaller decides the unbound case.
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
	// REST callers: the webservice's PlatformTokenMiddleware stores the
	// verified platform token here, and its JWT handler an IAM session.
	if authCtx, ok := iammw.AuthorizedContextFromContext(ctx); ok && authCtx != nil {
		return authCtx.TenantID, true
	}
	if session, ok := iammw.GetSessionFromContext(ctx); ok && session != nil {
		return session.TenantID(), true
	}
	if identity := IdentityFromContext(ctx); identity != nil {
		return identity.TenantID, true
	}
	return "", false
}

// errUnboundCaller is the refusal a caller with no identity at all gets from
// a tenant-scoped call: no platform token, no mTLS identity and no Unix peer
// credentials, so there is no tenant to check the request against.
type errUnboundCaller struct{}

func (errUnboundCaller) Error() string {
	return "tenant-scoped call refused: the caller carries no authenticated identity"
}

// authorizeUnboundCaller decides a caller callerTenant reports unbound (SPEC
// row 109, fail closed). The local operator is admitted: a Unix-socket peer
// carries kernel-verified SO_PEERCRED credentials, and an in-process embedder
// carries the process credentials (peercred.ContextWithProcessCredentials).
// Any other caller is refused with codes.PermissionDenied.
func authorizeUnboundCaller(ctx context.Context) error {
	if _, ok := peercred.UnixCredentialsFromContext(ctx); ok {
		return nil
	}
	return status.Error(codes.PermissionDenied, errUnboundCaller{}.Error())
}

// authorizeIAMTenant refuses an IAM request that names a tenant other than
// the caller's own, with codes.PermissionDenied — the same refusal the REST
// IAM tree gives with 403 from RequireOwnTenant, so no transport answers a
// tenant-bound caller from another tenant.
func authorizeIAMTenant(ctx context.Context, requested string) error {
	caller, bound := callerTenant(ctx)
	if !bound {
		return authorizeUnboundCaller(ctx)
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
// tenant-bound identity is decided by authorizeUnboundCaller, and an unset
// systemTenantID admits no tenant-bound caller.
func authorizeSystemCaller(ctx context.Context, systemTenantID, method string) error {
	caller, bound := callerTenant(ctx)
	if !bound {
		return authorizeUnboundCaller(ctx)
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
