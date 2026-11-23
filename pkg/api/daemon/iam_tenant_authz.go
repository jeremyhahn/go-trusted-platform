package daemon

import (
	"context"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util/peercred"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// callerTenant reports the tenant the authenticated caller is bound to. The
// second result is false when the caller carries no tenant-bound identity.
// Of those callers only the Unix-socket operator, authenticated by the
// kernel-verified peer credentials the Unix-socket server attaches, is
// admitted; admitUnbound refuses every other one (a daemon run with
// SkipIAMValidation included).
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

// admitUnbound decides a caller with no tenant-bound identity: it is admitted
// only when the request context carries the kernel-verified peer credentials
// the Unix-socket gRPC server's interceptor attaches (the Unix-socket
// operator); every other unbound caller is refused with
// codes.PermissionDenied naming target, the method or tenant requested.
func admitUnbound(ctx context.Context, target string) error {
	if _, ok := peercred.UnixCredentialsFromContext(ctx); ok {
		return nil
	}
	return status.Error(codes.PermissionDenied, ErrUnboundCaller{Target: target}.Error())
}

// authorizeIAMTenant refuses an IAM request that names a tenant other than
// the caller's own, with codes.PermissionDenied — the same refusal the REST
// IAM tree gives with 403 from RequireOwnTenant, so no transport answers a
// tenant-bound caller from another tenant.
func authorizeIAMTenant(ctx context.Context, requested string) error {
	caller, bound := callerTenant(ctx)
	if !bound {
		return admitUnbound(ctx, requested)
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
// the REST trees enforce with RequireSystemTenant; of the callers with no
// tenant-bound identity only the Unix-socket operator is admitted
// (admitUnbound), and an unset systemTenantID admits no tenant-bound caller.
func authorizeSystemCaller(ctx context.Context, systemTenantID, method string) error {
	caller, bound := callerTenant(ctx)
	if !bound {
		return admitUnbound(ctx, method)
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
