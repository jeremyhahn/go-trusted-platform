package daemon

import (
	"context"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// callerTenant reports the tenant the authenticated caller is bound to. The
// second result is false when the caller carries no tenant-bound identity:
// the Unix-socket operator, authenticated by peer credentials, and a daemon
// run with SkipIAMValidation.
//
// The sources mirror the REST session: a validated platform token (gRPC or
// QUIC) carries its tenant_id claim, and an mTLS client certificate carries
// the tenant the certificate authenticator extracted from it.
func callerTenant(ctx context.Context) (string, bool) {
	if authCtx, ok := grpcapi.AuthorizedContextFromContext(ctx); ok && authCtx != nil {
		return authCtx.TenantID, true
	}
	if authCtx, ok := quic.AuthorizedContextFromContext(ctx); ok && authCtx != nil {
		return authCtx.TenantID, true
	}
	if identity := IdentityFromContext(ctx); identity != nil {
		return identity.TenantID, true
	}
	return "", false
}

// authorizeIAMTenant refuses an IAM request that names a tenant other than
// the caller's own, with codes.PermissionDenied — the same refusal the REST
// IAM tree gives with 403 from RequireOwnTenant, so no transport answers a
// tenant-bound caller from another tenant.
func authorizeIAMTenant(ctx context.Context, requested string) error {
	caller, bound := callerTenant(ctx)
	if !bound || caller == requested {
		return nil
	}
	return status.Error(codes.PermissionDenied, ErrIAMTenantForbidden{Requested: requested}.Error())
}
