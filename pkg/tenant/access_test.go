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

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestAuthorizeNameLookup is the one rule every transport applies to a
// lookup by name (#304): a tenant resolves its own name, the system tenant
// resolves any, and everything else is refused with one error.
func TestAuthorizeNameLookup(t *testing.T) {
	t.Run("a tenant resolves its own name", func(t *testing.T) {
		assert.NoError(t, AuthorizeNameLookup("tenant-a", false, "tenant-a"))
	})

	t.Run("the system tenant resolves another tenant's name", func(t *testing.T) {
		assert.NoError(t, AuthorizeNameLookup("system", true, "tenant-b"))
	})

	t.Run("the system tenant resolves an unknown name", func(t *testing.T) {
		// The handler then answers NotFound: only the system tenant learns
		// that a name is missing.
		assert.NoError(t, AuthorizeNameLookup("system", true, ""))
	})

	t.Run("another tenant's name is refused", func(t *testing.T) {
		err := AuthorizeNameLookup("tenant-a", false, "tenant-b")
		assert.True(t, errors.Is(err, ErrNameLookupDenied{}), "got %v", err)
	})

	t.Run("an unknown name is refused exactly like a foreign one", func(t *testing.T) {
		foreign := AuthorizeNameLookup("tenant-a", false, "tenant-b")
		unknown := AuthorizeNameLookup("tenant-a", false, "")
		assert.Equal(t, foreign, unknown)
		assert.Equal(t, foreign.Error(), unknown.Error())
	})

	t.Run("a caller with no tenant does not match an unknown name", func(t *testing.T) {
		// "" == "" must not read as "the caller's own tenant".
		err := AuthorizeNameLookup("", false, "")
		assert.True(t, errors.Is(err, ErrNameLookupDenied{}), "got %v", err)
	})
}

// TestIsSystemTenant: only the configured system tenant is the system
// tenant, and an unset one admits nobody.
func TestIsSystemTenant(t *testing.T) {
	t.Run("the configured system tenant", func(t *testing.T) {
		assert.True(t, IsSystemTenant("system", "system"))
	})

	t.Run("another tenant", func(t *testing.T) {
		assert.False(t, IsSystemTenant("system", "tenant-a"))
	})

	t.Run("an unset system tenant admits no caller, not even an empty one", func(t *testing.T) {
		assert.False(t, IsSystemTenant("", ""))
		assert.False(t, IsSystemTenant("", "tenant-a"))
	})
}

// TestAuthorizeTenantAccess is the rule every transport applies to a request
// naming one tenant (#304): its own tenant, or any as the system tenant.
func TestAuthorizeTenantAccess(t *testing.T) {
	t.Run("a tenant acts on itself", func(t *testing.T) {
		assert.NoError(t, AuthorizeTenantAccess("tenant-a", false, "tenant-a"))
	})

	t.Run("the system tenant acts on another tenant", func(t *testing.T) {
		assert.NoError(t, AuthorizeTenantAccess("system", true, "tenant-b"))
	})

	t.Run("another tenant is refused", func(t *testing.T) {
		err := AuthorizeTenantAccess("tenant-a", false, "tenant-b")
		assert.Equal(t, ErrTenantForbidden{Requested: "tenant-b"}, err)
		assert.Contains(t, err.Error(), "tenant-b")
	})

	t.Run("a caller with no tenant does not own an empty one", func(t *testing.T) {
		err := AuthorizeTenantAccess("", false, "")
		assert.Equal(t, ErrTenantForbidden{Requested: ""}, err)
	})
}

// TestAuthorizeCrossTenant: list, create and sync are the system tenant's
// alone, and the refusal names the operation.
func TestAuthorizeCrossTenant(t *testing.T) {
	t.Run("the system tenant", func(t *testing.T) {
		assert.NoError(t, AuthorizeCrossTenant(true, "ListTenants"))
	})

	t.Run("any other caller is refused", func(t *testing.T) {
		err := AuthorizeCrossTenant(false, "ListTenants")
		assert.Equal(t, ErrTenantSystemOnly{Method: "ListTenants"}, err)
		assert.Contains(t, err.Error(), "ListTenants")
	})
}
