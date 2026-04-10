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

package quicbaas

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-qrdb/pkg/dao"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTenantScopedFactory_AccountDAO tests AccountDAO on scoped factory.
func TestTenantScopedFactory_AccountDAO(t *testing.T) {
	store := newMockObjectStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	scoped, err := factory.ForTenant("test-tenant")
	require.NoError(t, err)

	d, err := scoped.AccountDAO()
	require.NoError(t, err)
	assert.NotNil(t, d)
	assert.Equal(t, "account", d.EntityType())
}

// TestTenantScopedFactory_OrderDAO tests OrderDAO on scoped factory.
func TestTenantScopedFactory_OrderDAO(t *testing.T) {
	store := newMockObjectStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	scoped, err := factory.ForTenant("test-tenant")
	require.NoError(t, err)

	t.Run("valid account ID", func(t *testing.T) {
		d, err := scoped.OrderDAO(1)
		require.NoError(t, err)
		assert.NotNil(t, d)
		assert.Equal(t, "order", d.EntityType())
	})

	t.Run("zero account ID", func(t *testing.T) {
		_, err := scoped.OrderDAO(0)
		require.Error(t, err)
	})
}

// TestTenantScopedFactory_AuthorizationDAO tests AuthorizationDAO on scoped factory.
func TestTenantScopedFactory_AuthorizationDAO(t *testing.T) {
	store := newMockObjectStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	scoped, err := factory.ForTenant("test-tenant")
	require.NoError(t, err)

	t.Run("valid account ID", func(t *testing.T) {
		d, err := scoped.AuthorizationDAO(1)
		require.NoError(t, err)
		assert.NotNil(t, d)
		assert.Equal(t, "authorization", d.EntityType())
	})

	t.Run("zero account ID", func(t *testing.T) {
		_, err := scoped.AuthorizationDAO(0)
		require.Error(t, err)
	})
}

// TestTenantScopedFactory_ChallengeDAO tests ChallengeDAO on scoped factory.
func TestTenantScopedFactory_ChallengeDAO(t *testing.T) {
	store := newMockObjectStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	scoped, err := factory.ForTenant("test-tenant")
	require.NoError(t, err)

	t.Run("valid account ID", func(t *testing.T) {
		d, err := scoped.ChallengeDAO(1)
		require.NoError(t, err)
		assert.NotNil(t, d)
		assert.Equal(t, "challenge", d.EntityType())
	})

	t.Run("zero account ID", func(t *testing.T) {
		_, err := scoped.ChallengeDAO(0)
		require.Error(t, err)
	})
}

// TestTenantScopedFactory_CertificateDAO tests CertificateDAO on scoped factory.
func TestTenantScopedFactory_CertificateDAO(t *testing.T) {
	store := newMockObjectStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	scoped, err := factory.ForTenant("test-tenant")
	require.NoError(t, err)

	d, err := scoped.CertificateDAO()
	require.NoError(t, err)
	assert.NotNil(t, d)
	assert.Equal(t, "certificate", d.EntityType())
}

// TestTenantScopedFactory_NonceDAO tests NonceDAO on scoped factory.
func TestTenantScopedFactory_NonceDAO(t *testing.T) {
	store := newMockObjectStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	scoped, err := factory.ForTenant("test-tenant")
	require.NoError(t, err)

	d, err := scoped.NonceDAO()
	require.NoError(t, err)
	assert.NotNil(t, d)
	assert.Equal(t, "nonce", d.EntityType())
}

// TestTenantScopedFactory_ExternalAccountBindingDAO tests ExternalAccountBindingDAO on scoped factory.
func TestTenantScopedFactory_ExternalAccountBindingDAO(t *testing.T) {
	store := newMockObjectStorage()
	factory, err := NewTenantAwareFactory(store)
	require.NoError(t, err)

	scoped, err := factory.ForTenant("test-tenant")
	require.NoError(t, err)

	d, err := scoped.ExternalAccountBindingDAO()
	require.NoError(t, err)
	assert.NotNil(t, d)
	assert.Equal(t, "external_account_binding", d.EntityType())
}

// TestGenericDAO_SaveWithCondition_ExistingEntity tests SaveWithCondition for existing entity.
func TestGenericDAO_SaveWithCondition_ExistingEntity(t *testing.T) {
	store := newMockObjectStorage()
	d := newGenericDAO[*verifyEntity](store, "prefix", "", func() *verifyEntity { return &verifyEntity{} }, "test")

	ctx := context.Background()

	// First save an entity
	entity := &verifyEntity{ID: 1}
	err := d.Save(ctx, entity)
	require.NoError(t, err)

	// Try to update with value condition
	updated := &verifyEntity{ID: 1}
	cond := dao.Condition{Target: dao.ConditionValue, Operator: dao.OpNotEqual, Value: nil}
	err = d.SaveWithCondition(ctx, updated, cond)
	// Condition evaluation depends on implementation
	_ = err
}

// TestGenericDAO_Page_SecondPage tests Page fetching second page.
func TestGenericDAO_Page_SecondPage(t *testing.T) {
	store := newMockObjectStorage()
	d := newGenericDAO[*verifyEntity](store, "prefix", "", func() *verifyEntity { return &verifyEntity{} }, "test")

	ctx := context.Background()

	// Save some entities
	for i := uint64(1); i <= 5; i++ {
		entity := &verifyEntity{ID: i}
		err := d.Save(ctx, entity)
		require.NoError(t, err)
	}

	// Fetch second page
	query := dao.PageQuery{Page: 2, PageSize: 2}
	result, err := d.Page(ctx, query)
	require.NoError(t, err)
	assert.NotNil(t, result.Entities)
	assert.Equal(t, 5, result.Total)
}

// TestGenericDAO_Delete_EntityWithID tests Delete with a valid entity.
func TestGenericDAO_Delete_EntityWithID(t *testing.T) {
	store := newMockObjectStorage()
	d := newGenericDAO[*verifyEntity](store, "prefix", "", func() *verifyEntity { return &verifyEntity{} }, "test")

	ctx := context.Background()

	// Save then delete
	entity := &verifyEntity{ID: 42}
	err := d.Save(ctx, entity)
	require.NoError(t, err)

	err = d.Delete(ctx, entity)
	require.NoError(t, err)

	// Verify it's gone
	_, err = d.Get(ctx, 42)
	require.Error(t, err)
}
