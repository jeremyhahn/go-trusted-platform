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
//   - a method that acts across tenants — list, create, sync, lookup by
//     name — admits the system tenant only (RequireSystemTenant).
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
