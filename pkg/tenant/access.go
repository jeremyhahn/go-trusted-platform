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

package tenant

// AuthorizeNameLookup decides a lookup by name once the name has been
// resolved to resolvedID ("" when it resolved to nothing). The system tenant
// may resolve any name; any other caller only its own tenant's. Another
// tenant's name and a name that does not exist get the same
// ErrNameLookupDenied, so the answer says nothing about which names exist.
//
// The caller is whatever the transport authenticated: TenantGRPCServer
// passes the gRPC, QUIC, MCP or mTLS caller, the daemon REST tenant routes
// the caller their scope guard verified, and the webservice REST by-name
// guard the session's tenant claim. None passes a request field.
func AuthorizeNameLookup(callerTenantID string, callerIsSystem bool, resolvedID string) error {
	if callerIsSystem {
		return nil
	}
	if resolvedID != "" && resolvedID == callerTenantID {
		return nil
	}
	return ErrNameLookupDenied{}
}

// IsSystemTenant reports whether callerTenantID is the platform's system
// tenant, systemTenantID. An unset system tenant admits no caller, the
// fail-closed reading every transport gives it.
func IsSystemTenant(systemTenantID, callerTenantID string) bool {
	return systemTenantID != "" && callerTenantID == systemTenantID
}

// RequireSystemScope admits a caller of a surface that forwards its context to
// the embedded SDK's KMS or secrets service only in the system scope: a caller
// bound to no tenant, or to the system tenant. Those services pick their
// namespace from the go-quicbaas IAM tenant in the context, and an absent one
// selects the system namespace. The SDK re-exports no setter for that tenant
// (go-quicbaas pkg/iam/tenant_context.go:43 is not under quicbaas/sdk/go, and
// the embedded transport's Request, sdk/go/transport/embedded/transport.go:414,
// does not translate sdk/go/transport.ContextWithTenant into it), so a
// tenant-bound caller would read and write the system namespace. It is refused
// with ErrSystemScopeOnly instead, the same error on every transport
// (docs/kms/api.md §6).
func RequireSystemScope(systemTenantID, callerTenantID string) error {
	if callerTenantID == "" || IsSystemTenant(systemTenantID, callerTenantID) {
		return nil
	}
	return ErrSystemScopeOnly{TenantID: callerTenantID}
}

// AuthorizeTenantAccess decides a request that names one tenant,
// requestedID. The system tenant may act on any tenant; any other caller on
// its own tenant only, and is refused with ErrTenantForbidden. A caller with
// no tenant owns none, so "" never matches an empty requestedID.
func AuthorizeTenantAccess(callerTenantID string, callerIsSystem bool, requestedID string) error {
	if callerIsSystem || (callerTenantID != "" && requestedID == callerTenantID) {
		return nil
	}
	return ErrTenantForbidden{Requested: requestedID}
}

// AuthorizeCrossTenant decides a request that acts across tenants (list,
// create, sync), named by operation. Only the system tenant may make one;
// any other caller is refused with ErrTenantSystemOnly.
func AuthorizeCrossTenant(callerIsSystem bool, operation string) error {
	if callerIsSystem {
		return nil
	}
	return ErrTenantSystemOnly{Method: operation}
}
