package quicbaas

import (
	"context"
	"testing"

	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenericDAO_Page_Empty(t *testing.T) {
	store := newMockObjectStorage()
	d := newGenericDAO[*verifyEntity](store, "page/empty", "", func() *verifyEntity { return &verifyEntity{} }, "test")

	result, err := d.Page(context.Background(), pq(1, 10))
	require.NoError(t, err)
	assert.Empty(t, result.Entities)
	assert.Equal(t, 0, result.Total)
}

func TestGenericDAO_Page_WithData(t *testing.T) {
	store := newMockObjectStorage()
	d := newGenericDAO[*verifyEntity](store, "page/data", "", func() *verifyEntity { return &verifyEntity{} }, "test")

	ctx := context.Background()
	for i := uint64(1); i <= 5; i++ {
		err := d.Save(ctx, &verifyEntity{ID: i})
		require.NoError(t, err)
	}

	result, err := d.Page(ctx, pq(1, 3))
	require.NoError(t, err)
	assert.Len(t, result.Entities, 3)
	assert.Equal(t, 5, result.Total)
	assert.True(t, result.HasMore)
}

func TestGenericDAO_ForEachPage(t *testing.T) {
	store := newMockObjectStorage()
	d := newGenericDAO[*verifyEntity](store, "foreach", "", func() *verifyEntity { return &verifyEntity{} }, "test")

	ctx := context.Background()
	for i := uint64(1); i <= 5; i++ {
		err := d.Save(ctx, &verifyEntity{ID: i})
		require.NoError(t, err)
	}

	var pages int
	var totalEntities int
	err := d.ForEachPage(ctx, pq(1, 2), func(result trustedca.DAOPageResult[*verifyEntity]) error {
		pages++
		totalEntities += len(result.Entities)
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 3, pages)
	assert.Equal(t, 5, totalEntities)
}

func TestGenericDAO_ForEachPage_StopIteration(t *testing.T) {
	store := newMockObjectStorage()
	d := newGenericDAO[*verifyEntity](store, "stop", "", func() *verifyEntity { return &verifyEntity{} }, "test")

	ctx := context.Background()
	for i := uint64(1); i <= 10; i++ {
		err := d.Save(ctx, &verifyEntity{ID: i})
		require.NoError(t, err)
	}

	var pages int
	err := d.ForEachPage(ctx, pq(1, 3), func(result trustedca.DAOPageResult[*verifyEntity]) error {
		pages++
		return trustedca.ErrDAOStopIteration
	})
	require.NoError(t, err)
	assert.Equal(t, 1, pages)
}

func TestGenericDAO_QueryByIndex(t *testing.T) {
	store := newMockObjectStorage()
	d := newGenericDAO[*verifyEntity](store, "query", "", func() *verifyEntity { return &verifyEntity{} }, "test")

	ctx := context.Background()
	err := d.Save(ctx, &verifyEntity{ID: 1})
	require.NoError(t, err)
	err = d.Save(ctx, &verifyEntity{ID: 2})
	require.NoError(t, err)

	results, err := d.QueryByIndex(ctx, "ID", uint64(1))
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, uint64(1), results[0].EntityID())
}

func TestGenericDAO_QueryByIndex_NoMatch(t *testing.T) {
	store := newMockObjectStorage()
	d := newGenericDAO[*verifyEntity](store, "qnomatch", "", func() *verifyEntity { return &verifyEntity{} }, "test")

	ctx := context.Background()
	err := d.Save(ctx, &verifyEntity{ID: 1})
	require.NoError(t, err)

	results, err := d.QueryByIndex(ctx, "ID", uint64(999))
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestGenericDAO_QueryOneByIndex(t *testing.T) {
	store := newMockObjectStorage()
	d := newGenericDAO[*verifyEntity](store, "qone", "", func() *verifyEntity { return &verifyEntity{} }, "test")

	ctx := context.Background()
	err := d.Save(ctx, &verifyEntity{ID: 42})
	require.NoError(t, err)

	entity, err := d.QueryOneByIndex(ctx, "ID", uint64(42))
	require.NoError(t, err)
	assert.Equal(t, uint64(42), entity.EntityID())
}

func TestGenericDAO_QueryOneByIndex_NotFound(t *testing.T) {
	store := newMockObjectStorage()
	d := newGenericDAO[*verifyEntity](store, "qone/nf", "", func() *verifyEntity { return &verifyEntity{} }, "test")

	_, err := d.QueryOneByIndex(context.Background(), "ID", uint64(999))
	require.Error(t, err)
}

func TestGenericDAO_ScanByIndex(t *testing.T) {
	store := newMockObjectStorage()
	d := newGenericDAO[*verifyEntity](store, "scan", "", func() *verifyEntity { return &verifyEntity{} }, "test")

	ctx := context.Background()
	for i := uint64(1); i <= 5; i++ {
		err := d.Save(ctx, &verifyEntity{ID: i})
		require.NoError(t, err)
	}

	results, err := d.ScanByIndex(ctx, "ID", uint64(2), uint64(4))
	require.NoError(t, err)
	// String comparison: "2" >= "2" and "2" < "4" -> true, "3" -> true
	assert.True(t, len(results) >= 1)
}

func TestGenericDAO_PageByIndex(t *testing.T) {
	store := newMockObjectStorage()
	d := newGenericDAO[*verifyEntity](store, "pageindex", "", func() *verifyEntity { return &verifyEntity{} }, "test")

	ctx := context.Background()
	err := d.Save(ctx, &verifyEntity{ID: 1})
	require.NoError(t, err)

	result, err := d.PageByIndex(ctx, "ID", uint64(1), pq(1, 10))
	require.NoError(t, err)
	assert.Len(t, result.Entities, 1)
}

func TestGenericDAO_CountByIndex(t *testing.T) {
	store := newMockObjectStorage()
	d := newGenericDAO[*verifyEntity](store, "countidx", "", func() *verifyEntity { return &verifyEntity{} }, "test")

	ctx := context.Background()
	err := d.Save(ctx, &verifyEntity{ID: 1})
	require.NoError(t, err)
	err = d.Save(ctx, &verifyEntity{ID: 2})
	require.NoError(t, err)

	count, err := d.CountByIndex(ctx, "ID", uint64(1))
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestGenericDAO_SaveWithCondition_NewEntity(t *testing.T) {
	store := newMockObjectStorage()
	d := newGenericDAO[*verifyEntity](store, "condnew", "", func() *verifyEntity { return &verifyEntity{} }, "test")

	ctx := context.Background()
	entity := &verifyEntity{ID: 1}
	cond := trustedca.DAOCondition{Target: trustedca.DAOConditionValue, Value: entity}

	err := d.SaveWithCondition(ctx, entity, cond)
	require.NoError(t, err)

	loaded, err := d.Get(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), loaded.EntityID())
}

func TestGenericDAO_SaveWithCondition_ZeroID(t *testing.T) {
	store := newMockObjectStorage()
	d := newGenericDAO[*verifyEntity](store, "condzero", "", func() *verifyEntity { return &verifyEntity{} }, "test")

	err := d.SaveWithCondition(context.Background(), &verifyEntity{ID: 0}, trustedca.DAOCondition{})
	require.Error(t, err)
}

func TestGenericDAO_Delete_NotFound(t *testing.T) {
	store := newMockObjectStorage()
	d := newGenericDAO[*verifyEntity](store, "delnf", "", func() *verifyEntity { return &verifyEntity{} }, "test")

	// Deleting a non-existent entity should be idempotent (no error)
	err := d.Delete(context.Background(), &verifyEntity{ID: 999})
	require.NoError(t, err)
}

func TestSortEntities_Ascending(t *testing.T) {
	entities := []*verifyEntity{{ID: 3}, {ID: 1}, {ID: 2}}
	sortEntities(entities, trustedca.DAOPageQuery{SortOrder: 1})
	assert.Equal(t, uint64(1), entities[0].ID)
	assert.Equal(t, uint64(2), entities[1].ID)
	assert.Equal(t, uint64(3), entities[2].ID)
}

func TestSortEntities_Descending(t *testing.T) {
	entities := []*verifyEntity{{ID: 1}, {ID: 3}, {ID: 2}}
	sortEntities(entities, trustedca.DAOPageQuery{SortOrder: -1})
	assert.Equal(t, uint64(3), entities[0].ID)
	assert.Equal(t, uint64(2), entities[1].ID)
	assert.Equal(t, uint64(1), entities[2].ID)
}
