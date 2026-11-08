package daemon

import (
	"context"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// callerTenant reports the tenant the authenticated caller is bound to. The
// second result is false when the caller carries no tenant-bound identity:
// the Unix-socket operator, authenticated by peer credentials, a daemon run
// with SkipIAMValidation, and an in-process REST route that forwards no
// caller.
//
// The sources mirror the REST session: a validated platform token (gRPC,
// QUIC or MCP) carries its tenant_id claim, and an mTLS client certificate carries
// the tenant the certificate authenticator extracted from it. A REST route
// that verified its caller and calls the service in-process publishes that
// caller with rest.WithCaller; it counts only when no transport identity is
// bound.
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
	if caller, ok := rest.CallerFromContext(ctx); ok {
		return caller.TenantID, true
	}
	return "", false
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
