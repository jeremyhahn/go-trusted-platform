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
//     caller for its own tenant's name only (authorizeTenantName), so the
//     name-keyed CLI works for a tenant acting on itself.
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
	return s.systemTenantID != "" && tenantID == s.systemTenantID
}

// authorizeTenant refuses a request naming a tenant the caller may not act
// on, with codes.PermissionDenied.
func (s *TenantGRPCServer) authorizeTenant(ctx context.Context, requested string) error {
	caller, bound := callerTenant(ctx)
	if !bound || caller == requested || s.isSystemTenant(caller) {
		return nil
	}
	return status.Error(codes.PermissionDenied, ErrTenantForbidden{Requested: requested}.Error())
}

// authorizeSystemTenant refuses a cross-tenant request from any tenant but
// the system tenant, with codes.PermissionDenied.
func (s *TenantGRPCServer) authorizeSystemTenant(ctx context.Context, method string) error {
	caller, bound := callerTenant(ctx)
	if !bound || s.isSystemTenant(caller) {
		return nil
	}
	return status.Error(codes.PermissionDenied, ErrTenantSystemOnly{Method: method}.Error())
}

// authorizeTenantName decides a lookup by name once the name has been
// resolved to resolvedID ("" when it resolved to nothing). The system tenant
// may resolve any name; any other tenant-bound caller only its own tenant's.
// Every other name — another tenant's or one that does not exist — gets the
// same ErrTenantSystemOnly, so the answer says nothing about which names
// exist.
func (s *TenantGRPCServer) authorizeTenantName(ctx context.Context, resolvedID string) error {
	caller, bound := callerTenant(ctx)
	if !bound || s.isSystemTenant(caller) || (resolvedID != "" && resolvedID == caller) {
		return nil
	}
	return status.Error(codes.PermissionDenied, ErrTenantSystemOnly{Method: "GetTenantByName"}.Error())
}
