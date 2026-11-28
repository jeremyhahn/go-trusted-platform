package daemon

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/eab"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	iammw "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// eabCallerTenant returns the authenticated caller's tenant for an EAB RPC.
// It reads the gRPC, QUIC and MCP token contexts and the mTLS identity
// (callerTenant) and, failing those, the REST IAM session the web service
// puts on the request context. The second result is false for an unbound
// caller (the Unix-socket operator or a SkipIAMValidation context).
func eabCallerTenant(ctx context.Context) (string, bool) {
	if caller, bound := callerTenant(ctx); bound {
		return caller, true
	}
	if session, ok := iammw.GetSessionFromContext(ctx); ok && session != nil {
		return session.TenantID(), true
	}
	return "", false
}

// eabTenantScope is the EAB tenant rule. An unbound caller and the system
// tenant keep the requested tenant (an empty request means every tenant).
// A bound caller with no tenant is refused. Any other bound caller is scoped
// to its own tenant: an empty request becomes the caller's tenant, and a
// request for another tenant is refused. An empty systemTenantID makes no
// caller the system tenant.
func eabTenantScope(systemTenantID, caller string, bound bool, requested string) (string, error) {
	if !bound {
		return requested, nil
	}
	if caller == "" {
		return "", ErrIAMTenantForbidden{Requested: requested}
	}
	if tenant.IsSystemTenant(systemTenantID, caller) {
		return requested, nil
	}
	if requested == "" {
		return caller, nil
	}
	if requested != caller {
		return "", ErrIAMTenantForbidden{Requested: requested}
	}
	return caller, nil
}

// scopeTenant applies eabTenantScope to the authenticated caller of ctx and
// returns the tenant the RPC may act on. A refusal is codes.PermissionDenied.
func (s *EABGRPCService) scopeTenant(ctx context.Context, requested string) (string, error) {
	caller, bound := eabCallerTenant(ctx)
	scoped, err := eabTenantScope(s.systemTenantID, caller, bound, requested)
	if err != nil {
		return "", status.Error(codes.PermissionDenied, err.Error())
	}
	return scoped, nil
}

// authorizeCredential refuses, with codes.PermissionDenied, a credential
// owned by a tenant other than the authenticated caller's.
func (s *EABGRPCService) authorizeCredential(ctx context.Context, cred *eab.Credential) error {
	if cred == nil {
		return nil
	}
	_, err := s.scopeTenant(ctx, cred.TenantID)
	return err
}

// ownedCredential refuses, before any mutation, credential id when another
// tenant owns it. An unbound caller and the system tenant may act on any
// credential, so for them the credential is not fetched and the mutation
// reports the store's own error, as before the tenant check.
func (s *EABGRPCService) ownedCredential(ctx context.Context, id uint64) error {
	caller, bound := eabCallerTenant(ctx)
	if !bound || (caller != "" && tenant.IsSystemTenant(s.systemTenantID, caller)) {
		return nil
	}
	cred, err := s.service.Get(ctx, id)
	if err != nil {
		return eabErrorToStatus(err)
	}
	return s.authorizeCredential(ctx, cred)
}
