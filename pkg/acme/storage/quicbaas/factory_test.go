package quicbaas

import (
	"context"
	"errors"
	"testing"

	casdk "github.com/jeremyhahn/go-trusted-ca/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pq is a test helper to build a DAOPageQuery.
func pq(page, pageSize int) casdk.DAOPageQuery {
	return casdk.DAOPageQuery{Page: page, PageSize: pageSize}
}

func TestNewFactory(t *testing.T) {
	store := newMockObjectStorage()
	f, err := NewFactory(store)
	require.NoError(t, err)
	require.NotNil(t, f)
}

func TestNewFactory_NilStorage(t *testing.T) {
	_, err := NewFactory(nil)
	require.Error(t, err)
	var nilErr NilStorageError
	assert.True(t, errors.As(err, &nilErr))
}

func TestNewTenantFactory(t *testing.T) {
	store := newMockObjectStorage()
	f, err := NewTenantFactory(store, "tenant-1")
	require.NoError(t, err)
	require.NotNil(t, f)
	assert.Equal(t, "tenant-1", f.tenantID)
}

func TestNewTenantFactory_NilStorage(t *testing.T) {
	_, err := NewTenantFactory(nil, "tenant-1")
	require.Error(t, err)
}

func TestFactory_AccountDAO(t *testing.T) {
	store := newMockObjectStorage()
	f, err := NewFactory(store)
	require.NoError(t, err)

	d, err := f.AccountDAO()
	require.NoError(t, err)
	assert.NotNil(t, d)
}

func TestFactory_OrderDAO(t *testing.T) {
	store := newMockObjectStorage()
	f, err := NewFactory(store)
	require.NoError(t, err)

	t.Run("valid account ID", func(t *testing.T) {
		d, err := f.OrderDAO(1)
		require.NoError(t, err)
		assert.NotNil(t, d)
	})

	t.Run("zero account ID", func(t *testing.T) {
		_, err := f.OrderDAO(0)
		require.Error(t, err)
	})
}

func TestFactory_AuthorizationDAO(t *testing.T) {
	store := newMockObjectStorage()
	f, err := NewFactory(store)
	require.NoError(t, err)

	t.Run("valid account ID", func(t *testing.T) {
		d, err := f.AuthorizationDAO(1)
		require.NoError(t, err)
		assert.NotNil(t, d)
	})

	t.Run("zero account ID", func(t *testing.T) {
		_, err := f.AuthorizationDAO(0)
		require.Error(t, err)
	})
}

func TestFactory_ChallengeDAO(t *testing.T) {
	store := newMockObjectStorage()
	f, err := NewFactory(store)
	require.NoError(t, err)

	t.Run("valid account ID", func(t *testing.T) {
		d, err := f.ChallengeDAO(1)
		require.NoError(t, err)
		assert.NotNil(t, d)
	})

	t.Run("zero account ID", func(t *testing.T) {
		_, err := f.ChallengeDAO(0)
		require.Error(t, err)
	})
}

func TestFactory_CertificateDAO(t *testing.T) {
	store := newMockObjectStorage()
	f, err := NewFactory(store)
	require.NoError(t, err)

	d, err := f.CertificateDAO()
	require.NoError(t, err)
	assert.NotNil(t, d)
}

func TestFactory_NonceDAO(t *testing.T) {
	store := newMockObjectStorage()
	f, err := NewFactory(store)
	require.NoError(t, err)

	d, err := f.NonceDAO()
	require.NoError(t, err)
	assert.NotNil(t, d)
}

func TestFactory_ExternalAccountBindingDAO(t *testing.T) {
	store := newMockObjectStorage()
	f, err := NewFactory(store)
	require.NoError(t, err)

	d, err := f.ExternalAccountBindingDAO()
	require.NoError(t, err)
	assert.NotNil(t, d)
}

func TestGenericDAO_MakeKey(t *testing.T) {
	store := newMockObjectStorage()
	d := newGenericDAO[*verifyEntity](store, "prefix", "", func() *verifyEntity { return &verifyEntity{} }, "test")

	key := d.makeKey(42)
	assert.Equal(t, "prefix/42", key)
}

func TestGenericDAO_Save_ZeroID(t *testing.T) {
	store := newMockObjectStorage()
	d := newGenericDAO[*verifyEntity](store, "prefix", "", func() *verifyEntity { return &verifyEntity{} }, "test")

	err := d.Save(context.Background(), &verifyEntity{ID: 0})
	require.Error(t, err)
}

func TestGenericDAO_Save_Success(t *testing.T) {
	store := newMockObjectStorage()
	d := newGenericDAO[*verifyEntity](store, "prefix", "", func() *verifyEntity { return &verifyEntity{} }, "test")

	err := d.Save(context.Background(), &verifyEntity{ID: 1})
	require.NoError(t, err)
}

func TestGenericDAO_Get_NotFound(t *testing.T) {
	store := newMockObjectStorage()
	d := newGenericDAO[*verifyEntity](store, "prefix", "", func() *verifyEntity { return &verifyEntity{} }, "test")

	_, err := d.Get(context.Background(), 999)
	require.Error(t, err)
}

func TestGenericDAO_Get_RoundTrip(t *testing.T) {
	store := newMockObjectStorage()
	d := newGenericDAO[*verifyEntity](store, "prefix", "", func() *verifyEntity { return &verifyEntity{} }, "test")

	ctx := context.Background()
	entity := &verifyEntity{ID: 42}
	err := d.Save(ctx, entity)
	require.NoError(t, err)

	loaded, err := d.Get(ctx, 42)
	require.NoError(t, err)
	assert.Equal(t, uint64(42), loaded.EntityID())
}

func TestGenericDAO_Delete_Success(t *testing.T) {
	store := newMockObjectStorage()
	d := newGenericDAO[*verifyEntity](store, "prefix", "", func() *verifyEntity { return &verifyEntity{} }, "test")

	ctx := context.Background()
	entity := &verifyEntity{ID: 1}
	err := d.Save(ctx, entity)
	require.NoError(t, err)

	err = d.Delete(ctx, entity)
	require.NoError(t, err)

	_, err = d.Get(ctx, 1)
	require.Error(t, err)
}

func TestGenericDAO_Delete_ZeroID(t *testing.T) {
	store := newMockObjectStorage()
	d := newGenericDAO[*verifyEntity](store, "prefix", "", func() *verifyEntity { return &verifyEntity{} }, "test")

	err := d.Delete(context.Background(), &verifyEntity{ID: 0})
	require.Error(t, err)
}

func TestGenericDAO_Count(t *testing.T) {
	store := newMockObjectStorage()
	d := newGenericDAO[*verifyEntity](store, "test/count", "", func() *verifyEntity { return &verifyEntity{} }, "test")

	ctx := context.Background()

	count, err := d.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, count)

	err = d.Save(ctx, &verifyEntity{ID: 1})
	require.NoError(t, err)
	err = d.Save(ctx, &verifyEntity{ID: 2})
	require.NoError(t, err)

	count, err = d.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, count)
}

func TestGenericDAO_EntityType(t *testing.T) {
	store := newMockObjectStorage()
	d := newGenericDAO[*verifyEntity](store, "prefix", "", func() *verifyEntity { return &verifyEntity{} }, "my_entity")
	assert.Equal(t, "my_entity", d.EntityType())
}

func TestGenericDAO_Find_ReturnsNil(t *testing.T) {
	store := newMockObjectStorage()
	d := newGenericDAO[*verifyEntity](store, "prefix", "", func() *verifyEntity { return &verifyEntity{} }, "test")

	result := d.Find(context.Background())
	assert.Nil(t, result)
}

func TestFieldMatches(t *testing.T) {
	type testStruct struct {
		Name string
		ID   uint64
	}

	assert.True(t, fieldMatches(&testStruct{Name: "hello", ID: 1}, "Name", "hello"))
	assert.False(t, fieldMatches(&testStruct{Name: "hello", ID: 1}, "Name", "world"))
	assert.False(t, fieldMatches(&testStruct{}, "NonExistent", "val"))
	assert.False(t, fieldMatches(nil, "Name", "val"))
	assert.False(t, fieldMatches("not a struct", "Name", "val"))
}

func TestFieldValue(t *testing.T) {
	type testStruct struct {
		Name string
		ID   uint64
	}

	assert.Equal(t, "hello", fieldValue(&testStruct{Name: "hello"}, "Name"))
	assert.Equal(t, "42", fieldValue(&testStruct{ID: 42}, "ID"))
	assert.Equal(t, "", fieldValue(&testStruct{}, "NonExistent"))
	assert.Equal(t, "", fieldValue(nil, "Name"))
}

func TestIsNotFoundErr(t *testing.T) {
	assert.False(t, isNotFoundErr(nil))
	assert.True(t, isNotFoundErr(errors.New("not found")))
	assert.True(t, isNotFoundErr(errors.New("does not exist")))
	assert.True(t, isNotFoundErr(errors.New("no such key")))
	assert.False(t, isNotFoundErr(errors.New("some other error")))
}

func TestNilStorageError(t *testing.T) {
	err := NilStorageError{}
	assert.Contains(t, err.Error(), "must not be nil")
}

func TestStorageOperationError(t *testing.T) {
	cause := errors.New("timeout")
	err := StorageOperationError{
		Op:         "put",
		EntityType: "account",
		Key:        "acme/accounts/1",
		Cause:      cause,
	}
	assert.Contains(t, err.Error(), "put")
	assert.Contains(t, err.Error(), "account")
	assert.Contains(t, err.Error(), "acme/accounts/1")
	assert.Equal(t, cause, err.Unwrap())
}

func TestListOperationError(t *testing.T) {
	cause := errors.New("network error")
	err := ListOperationError{
		EntityType: "order",
		Prefix:     "acme/orders",
		Cause:      cause,
	}
	assert.Contains(t, err.Error(), "order")
	assert.Contains(t, err.Error(), "acme/orders")
	assert.Equal(t, cause, err.Unwrap())
}

func TestPaginate(t *testing.T) {
	entities := []*verifyEntity{
		{ID: 1}, {ID: 2}, {ID: 3}, {ID: 4}, {ID: 5},
	}

	t.Run("first page", func(t *testing.T) {
		result := paginate(entities, pq(1, 2))
		assert.Len(t, result.Entities, 2)
		assert.True(t, result.HasMore)
		assert.Equal(t, 5, result.Total)
	})

	t.Run("last page", func(t *testing.T) {
		result := paginate(entities, pq(3, 2))
		assert.Len(t, result.Entities, 1)
		assert.False(t, result.HasMore)
	})

	t.Run("beyond total", func(t *testing.T) {
		result := paginate(entities, pq(10, 2))
		assert.Empty(t, result.Entities)
		assert.False(t, result.HasMore)
	})

	t.Run("zero page uses 1", func(t *testing.T) {
		result := paginate(entities, pq(0, 3))
		assert.Len(t, result.Entities, 3)
	})

	t.Run("zero page size uses default", func(t *testing.T) {
		result := paginate(entities, pq(1, 0))
		assert.Len(t, result.Entities, 5) // default 100, but only 5 items
	})
}

func TestEvaluateCondition(t *testing.T) {
	entity := &verifyEntity{ID: 42}

	t.Run("value match", func(t *testing.T) {
		cond := casdk.DAOCondition{Target: casdk.DAOConditionValue, Value: entity}
		assert.True(t, evaluateCondition(entity, cond))
	})

	t.Run("value mismatch", func(t *testing.T) {
		cond := casdk.DAOCondition{Target: casdk.DAOConditionValue, Value: &verifyEntity{ID: 99}}
		assert.False(t, evaluateCondition(entity, cond))
	})

	t.Run("unknown target returns true", func(t *testing.T) {
		cond := casdk.DAOCondition{Target: 999}
		assert.True(t, evaluateCondition(entity, cond))
	})
}
