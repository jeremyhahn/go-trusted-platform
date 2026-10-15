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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
)

// The TenantService is shared by gRPC, QUIC, REST and MCP, so the tenant
// isolation it applies here holds on every transport. It is the rule the
// REST tenant tree enforces with its guards (docs/tenant/api.md §7):
//
//   - a method that names a tenant admits the caller's own tenant and the
//     system tenant (RequireOwnTenantOrSystem);
//   - a method that acts across tenants — list, create, sync — admits the
//     system tenant only (RequireSystemTenant);
//   - a lookup by name admits the system tenant for any name, and any other
//     caller for its own tenant's name only (tenant.AuthorizeNameLookup, the
//     rule the REST by-name guard calls too), so the name-keyed CLI works for
//     a tenant acting on itself.
//
// A caller with no tenant-bound identity (the Unix-socket operator, and a
// daemon run with SkipIAMValidation) is admitted, as callerTenant documents.
// An unset system tenant admits no tenant-bound caller as the system tenant,
// the same fail-closed reading the REST guards give an empty tenant.

// SetSystemTenant sets the platform's operating (system) tenant, the one
// tenant allowed to act on every other tenant.
func (s *TenantGRPCServer) SetSystemTenant(tenantID string) {
	s.systemTenantID = tenantID
}

// isSystemTenant reports whether tenantID is the configured system tenant.
func (s *TenantGRPCServer) isSystemTenant(tenantID string) bool {
	return tenant.IsSystemTenant(s.systemTenantID, tenantID)
}

// authorizeTenant refuses a request naming a tenant the caller may not act
// on (tenant.AuthorizeTenantAccess), with codes.PermissionDenied.
func (s *TenantGRPCServer) authorizeTenant(ctx context.Context, requested string) error {
	caller, bound := callerTenant(ctx)
	if !bound {
		return nil
	}
	if err := tenant.AuthorizeTenantAccess(caller, s.isSystemTenant(caller), requested); err != nil {
		return status.Error(codes.PermissionDenied, err.Error())
	}
	return nil
}

// authorizeSystemTenant refuses a cross-tenant request from any tenant but
// the system tenant (tenant.AuthorizeCrossTenant), with
// codes.PermissionDenied.
func (s *TenantGRPCServer) authorizeSystemTenant(ctx context.Context, method string) error {
	caller, bound := callerTenant(ctx)
	if !bound {
		return nil
	}
	if err := tenant.AuthorizeCrossTenant(s.isSystemTenant(caller), method); err != nil {
		return status.Error(codes.PermissionDenied, err.Error())
	}
	return nil
}

// authorizeTenantName decides a lookup by name once the name has been
// resolved to resolvedID ("" when it resolved to nothing), by the rule every
// transport shares, tenant.AuthorizeNameLookup. A refusal is
// codes.PermissionDenied carrying tenant.ErrNameLookupDenied, for another
// tenant's name and an unknown one alike.
func (s *TenantGRPCServer) authorizeTenantName(ctx context.Context, resolvedID string) error {
	caller, bound := callerTenant(ctx)
	if !bound {
		return nil
	}
	if err := tenant.AuthorizeNameLookup(caller, s.isSystemTenant(caller), resolvedID); err != nil {
		return status.Error(codes.PermissionDenied, err.Error())
	}
	return nil
}
