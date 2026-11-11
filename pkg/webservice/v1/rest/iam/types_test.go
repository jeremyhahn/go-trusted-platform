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

package iam

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegisterAppRequest_Resolve pins the contract RegisterAppRequest
// documents about itself: snake_case is canonical, the camelCase field is an
// alias, and Resolve() normalises the alias into the canonical field.
//
// Every aliased field is covered, not only the one that prompted this test.
// The contract had no coverage at all, which is how TenantID came to be
// declared camelCase-only with no arm in Resolve() (#345) — an omission a
// test over the whole struct would have caught the moment it was written.
func TestRegisterAppRequest_Resolve(t *testing.T) {
	t.Parallel()
	t.Run("camelCase aliases resolve into the canonical fields", func(t *testing.T) {
		req := &RegisterAppRequest{
			Name:                "app",
			RedirectURIsCamel:   []string{"https://example.test/cb"},
			GrantTypesCamel:     []string{"authorization_code"},
			ResponseTypesCamel:  []string{"code"},
			ResourcePrefixCamel: "prefix",
			BodyTenant:          BodyTenant{TenantIDCamel: "tenant-1"},
		}

		req.Resolve()

		assert.Equal(t, []string{"https://example.test/cb"}, req.RedirectURIs)
		assert.Equal(t, []string{"authorization_code"}, req.GrantTypes)
		assert.Equal(t, []string{"code"}, req.ResponseTypes)
		assert.Equal(t, "prefix", req.ResourcePrefix)
		assert.Equal(t, "tenant-1", req.TenantID)
	})

	t.Run("canonical fields win when both spellings are present", func(t *testing.T) {
		req := &RegisterAppRequest{
			RedirectURIs:        []string{"https://canonical.test/cb"},
			RedirectURIsCamel:   []string{"https://alias.test/cb"},
			GrantTypes:          []string{"client_credentials"},
			GrantTypesCamel:     []string{"authorization_code"},
			ResponseTypes:       []string{"token"},
			ResponseTypesCamel:  []string{"code"},
			ResourcePrefix:      "canonical",
			ResourcePrefixCamel: "alias",
			BodyTenant: BodyTenant{
				TenantID:      "canonical-tenant",
				TenantIDCamel: "alias-tenant",
			},
		}

		req.Resolve()

		assert.Equal(t, []string{"https://canonical.test/cb"}, req.RedirectURIs)
		assert.Equal(t, []string{"client_credentials"}, req.GrantTypes)
		assert.Equal(t, []string{"token"}, req.ResponseTypes)
		assert.Equal(t, "canonical", req.ResourcePrefix)
		assert.Equal(t, "canonical-tenant", req.TenantID)
	})

	t.Run("resolve is a no-op when nothing is set", func(t *testing.T) {
		req := &RegisterAppRequest{Name: "app"}

		req.Resolve()

		assert.Empty(t, req.RedirectURIs)
		assert.Empty(t, req.GrantTypes)
		assert.Empty(t, req.ResponseTypes)
		assert.Empty(t, req.ResourcePrefix)
		assert.Empty(t, req.TenantID)
	})
}

// TestRegisterAppRequest_BothSpellingsUnmarshal is the wire-level half: the
// struct tags, not just Resolve(). Before #345 a body sending the canonical
// tenant_id was silently dropped, because tenantId was the only spelling the
// struct declared for that field — while AppResponse returned tenant_id.
func TestRegisterAppRequest_BothSpellingsUnmarshal(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		body string
	}{
		{"canonical snake_case", `{"name":"app","tenant_id":"tenant-1","grant_types":["authorization_code"]}`},
		{"camelCase alias", `{"name":"app","tenantId":"tenant-1","grantTypes":["authorization_code"]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var req RegisterAppRequest
			require.NoError(t, json.Unmarshal([]byte(tc.body), &req))

			req.Resolve()

			assert.Equal(t, "tenant-1", req.TenantID,
				"both spellings must reach the same canonical field")
			assert.Equal(t, []string{"authorization_code"}, req.GrantTypes)
		})
	}
}

// TestBodyTenant_NamesOtherThan covers both spellings: a body naming no
// tenant, or only the tenant the route acts on, names no other one; a foreign
// tenant in either spelling does.
func TestBodyTenant_NamesOtherThan(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body BodyTenant
		want bool
	}{
		{name: "names no tenant", body: BodyTenant{}, want: false},
		{name: "own tenant, snake_case", body: BodyTenant{TenantID: "tenant-a"}, want: false},
		{name: "own tenant, camelCase", body: BodyTenant{TenantIDCamel: "tenant-a"}, want: false},
		{name: "own tenant, both spellings", body: BodyTenant{TenantID: "tenant-a", TenantIDCamel: "tenant-a"}, want: false},
		{name: "foreign tenant, snake_case", body: BodyTenant{TenantID: "tenant-b"}, want: true},
		{name: "foreign tenant, camelCase", body: BodyTenant{TenantIDCamel: "tenant-b"}, want: true},
		{name: "spellings disagree", body: BodyTenant{TenantID: "tenant-a", TenantIDCamel: "tenant-b"}, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.body.namesOtherThan("tenant-a"))
		})
	}
}

// TestBodyTenant_EmbeddedUnmarshal pins the wire half: the embedded fields
// decode with the rest of a request body, in one pass.
func TestBodyTenant_EmbeddedUnmarshal(t *testing.T) {
	t.Parallel()
	var req CreateUserRequest
	require.NoError(t, json.Unmarshal([]byte(`{"email":"u@example.test","tenant_id":"tenant-b"}`), &req))

	assert.Equal(t, "u@example.test", req.Email)
	assert.True(t, req.namesOtherThan("tenant-a"))
}
