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

package jwt

import (
	"context"
	"errors"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubUserGetter struct {
	user *entities.User
	err  error
}

func (s *stubUserGetter) Get(ctx context.Context, userID uint64) (*entities.User, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.user, nil
}

func newIssuerTestService(t *testing.T) *Service {
	t.Helper()
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS
	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	require.NoError(t, err)
	service, err := NewService(context.Background(), params)
	require.NoError(t, err)
	return service
}

func TestNewUserTokenIssuer_RequiresUserGetter(t *testing.T) {
	t.Parallel()
	_, err := NewUserTokenIssuer(nil, newIssuerTestService(t))
	assert.ErrorIs(t, err, ErrUserGetterRequired)
}

func TestNewUserTokenIssuer_RequiresService(t *testing.T) {
	t.Parallel()
	_, err := NewUserTokenIssuer(&stubUserGetter{}, nil)
	assert.ErrorIs(t, err, ErrTokenServiceRequired)
}

// TestUserTokenIssuer_StampsTenant proves a non-empty tenant ID
// overrides the stored assignment in the issued token without mutating
// the stored record.
func TestUserTokenIssuer_StampsTenant(t *testing.T) {
	t.Parallel()
	service := newIssuerTestService(t)
	user := entities.NewUser("owner@example.com")
	issuer, err := NewUserTokenIssuer(&stubUserGetter{user: user}, service)
	require.NoError(t, err)

	token, err := issuer.IssueToken(context.Background(), user.ID, "tenant-abc", []string{"admin", "tenant_owner"})
	require.NoError(t, err)
	require.NotEmpty(t, token)

	parsed, err := service.ParseTokenString(token)
	require.NoError(t, err)
	claims := parsed.Claims.(*TokenClaims)
	assert.Equal(t, "tenant-abc", claims.TenantID)
	assert.Equal(t, user.Email, claims.Email)
	// The caller-resolved roles — including the synthesized
	// tenant_owner — land in the roles claim verbatim.
	assert.Equal(t, []string{"admin", "tenant_owner"}, claims.Roles)
	// The stored record is untouched: only the token is stamped.
	assert.Empty(t, user.TenantID)
	assert.Empty(t, user.Roles)
}

// TestUserTokenIssuer_KeepsStoredRoles proves an empty roles argument
// falls back to the stored record's roles.
func TestUserTokenIssuer_KeepsStoredRoles(t *testing.T) {
	t.Parallel()
	service := newIssuerTestService(t)
	user := entities.NewUser("roles@example.com")
	user.Roles = []*entities.Role{{Name: "operator"}}
	issuer, err := NewUserTokenIssuer(&stubUserGetter{user: user}, service)
	require.NoError(t, err)

	token, err := issuer.IssueToken(context.Background(), user.ID, "", nil)
	require.NoError(t, err)

	parsed, err := service.ParseTokenString(token)
	require.NoError(t, err)
	claims := parsed.Claims.(*TokenClaims)
	assert.Equal(t, []string{"operator"}, claims.Roles)
}

// TestUserTokenIssuer_KeepsStoredTenant proves an empty tenant argument
// leaves the user's persisted assignment in the token.
func TestUserTokenIssuer_KeepsStoredTenant(t *testing.T) {
	t.Parallel()
	service := newIssuerTestService(t)
	user := entities.NewUser("member@example.com")
	user.TenantID = "tenant-stored"
	issuer, err := NewUserTokenIssuer(&stubUserGetter{user: user}, service)
	require.NoError(t, err)

	token, err := issuer.IssueToken(context.Background(), user.ID, "", nil)
	require.NoError(t, err)

	parsed, err := service.ParseTokenString(token)
	require.NoError(t, err)
	claims := parsed.Claims.(*TokenClaims)
	assert.Equal(t, "tenant-stored", claims.TenantID)
}

// TestUserTokenIssuer_LookupError proves a failed user lookup issues
// nothing.
func TestUserTokenIssuer_LookupError(t *testing.T) {
	t.Parallel()
	service := newIssuerTestService(t)
	lookupErr := errors.New("store unavailable")
	issuer, err := NewUserTokenIssuer(&stubUserGetter{err: lookupErr}, service)
	require.NoError(t, err)

	token, err := issuer.IssueToken(context.Background(), 42, "tenant-abc", nil)
	assert.ErrorIs(t, err, lookupErr)
	assert.Empty(t, token)
}
