package daemon

import (
	"context"
	"strconv"
	"strings"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util/peercred"
	iammw "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"

	"google.golang.org/grpc"
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
	// QUIC local-JWT callers on the legacy validator path.
	if p, ok := quic.LegacyPrincipalFromContext(ctx); ok {
		return p.TenantID, true
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

// errUnixPeerDenied is the refusal a Unix peer gets when the IAM decision
// point does not admit its uid/gid principal for the request.
type errUnixPeerDenied struct {
	Subject, Resource, Action string
}

func (e errUnixPeerDenied) Error() string {
	return "tenant-scoped call refused: IAM denied " + e.Subject + " " + e.Action + " on " + e.Resource
}

// operationMethodKey keys the full gRPC method name of the operation a
// handler serves (withOperationMethod).
type operationMethodKey struct{}

// withOperationMethod records fullMethod ("/platform.v1.TenantService/GetTenant")
// as the operation ctx serves. Each gRPC handler records its own method, so
// the operation is known whichever transport (gRPC, REST, QUIC, MCP or an
// in-process caller) reached the handler.
func withOperationMethod(ctx context.Context, fullMethod string) context.Context {
	return context.WithValue(ctx, operationMethodKey{}, fullMethod)
}

// operationMethod is the full method of the operation ctx serves: the one a
// handler recorded (withOperationMethod), else the gRPC server's (grpc.Method).
func operationMethod(ctx context.Context) (string, bool) {
	if method, ok := ctx.Value(operationMethodKey{}).(string); ok && method != "" {
		return method, true
	}
	return grpc.Method(ctx)
}

// unboundCallerPermission is the registered permission pair of the
// operation in ctx (operationMethod, grpcapi.ScopeForMethod), split into the
// resource and action the PEP decides. ok is false when ctx carries no
// method, the method has no catalog entry, or the entry is not a
// resource:action pair.
func unboundCallerPermission(ctx context.Context) (resource, action string, ok bool) {
	method, hasMethod := operationMethod(ctx)
	if !hasMethod || method == "" {
		return "", "", false
	}
	resource, action, ok = strings.Cut(grpcapi.ScopeForMethod(method), ":")
	if !ok || resource == "" || action == "" {
		return "", "", false
	}
	return resource, action, true
}

// unixPeerPrincipal maps kernel-verified Unix peer credentials (SO_PEERCRED,
// or the process credentials of an in-process embedder) to the principal the
// PEP decides: subject "unix:uid:<uid>", one role "unix:gid:<gid>", in the
// tenant the request acts on. The PID is not part of the principal.
func unixPeerPrincipal(creds peercred.UnixCredentials, tenantID string) *tokenPrincipal {
	return &tokenPrincipal{
		Subject:  "unix:uid:" + strconv.FormatUint(uint64(creds.UID), 10),
		TenantID: tenantID,
		Roles:    []string{"unix:gid:" + strconv.FormatUint(uint64(creds.GID), 10)},
	}
}

// authorizeUnboundCaller decides a caller callerTenant reports unbound (SPEC
// row 109, fail closed). Unix peer credentials are not a grant on their own:
// the caller's uid/gid principal (unixPeerPrincipal) must be admitted by the
// IAM decision point, pep.Check, for the registered permission pair of the
// gRPC method being served (unboundCallerPermission, SPEC row 109), in
// tenantID: the tenant is the principal's, not part of the resource. A
// caller with no peer credentials, a method with no registered scope, a
// daemon with no PEP wired, a failed check and a denial are all refused
// with codes.PermissionDenied.
func authorizeUnboundCaller(ctx context.Context, pep quicbaassdk.IAMPEPClient, tenantID string) error {
	creds, ok := peercred.UnixCredentialsFromContext(ctx)
	if !ok {
		return status.Error(codes.PermissionDenied, errUnboundCaller{}.Error())
	}
	resource, action, ok := unboundCallerPermission(ctx)
	if !ok {
		return status.Error(codes.PermissionDenied, errUnboundCaller{}.Error())
	}
	if pep == nil {
		return status.Error(codes.PermissionDenied, ErrPEPClientNotAvailable{}.Error())
	}
	// The PEP's RBAC check takes the registered resource name as is and
	// matches resource:action; the target tenant is the principal's
	// TenantID (unixPeerPrincipal), not part of the resource.
	principal := unixPeerPrincipal(creds, tenantID)
	allowed, err := checkPrincipalPermission(ctx, pep, principal, resource, action)
	if err != nil {
		return status.Error(codes.PermissionDenied, err.Error())
	}
	if !allowed {
		return status.Error(codes.PermissionDenied, errUnixPeerDenied{Subject: principal.Subject, Resource: resource, Action: action}.Error())
	}
	return nil
}

// authorizeIAMTenant refuses an IAM request that names a tenant other than
// the caller's own, with codes.PermissionDenied — the same refusal the REST
// IAM tree gives with 403 from RequireOwnTenant, so no transport answers a
// tenant-bound caller from another tenant. An unbound caller is decided by
// pep (authorizeUnboundCaller).
func authorizeIAMTenant(ctx context.Context, pep quicbaassdk.IAMPEPClient, requested string) error {
	caller, bound := callerTenant(ctx)
	if !bound {
		return authorizeUnboundCaller(ctx, pep, requested)
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
// tenant-bound identity is decided by pep in the system tenant
// (authorizeUnboundCaller), and an unset systemTenantID admits no caller.
func authorizeSystemCaller(ctx context.Context, pep quicbaassdk.IAMPEPClient, systemTenantID, method string) error {
	caller, bound := callerTenant(ctx)
	if !bound {
		return authorizeUnboundCaller(ctx, pep, systemTenantID)
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
