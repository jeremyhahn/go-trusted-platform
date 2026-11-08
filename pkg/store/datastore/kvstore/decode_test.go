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

package kvstore

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// aboveFloat64 is 2^53 + 1, the smallest integer a float64 cannot hold: a
// float64 decode reads it back as 9007199254740992.
const aboveFloat64 uint64 = 9007199254740993

// newBlobDAO returns a GenericDAO over Blob, whose Entity field is any-typed,
// backed by in-memory storage.
func newBlobDAO(t *testing.T) (*GenericDAO[*entities.Blob], *memoryStorage) {
	t.Helper()
	storage := newMemoryStorage()
	require.NoError(t, storage.Start(context.Background()))
	dao := NewGenericDAO[*entities.Blob](
		storage, "Blob", func() *entities.Blob { return &entities.Blob{} }, logging.DefaultLogger(),
	)
	return dao, storage
}

// exactNumberBlob returns a blob whose any-typed Entity holds integers above
// 2^53 at the top level, nested in a map and in a slice, plus a negative one
// and a non-integer.
func exactNumberBlob(id uint64) *entities.Blob {
	blob := entities.NewBlob(id, []byte("data"))
	blob.SetEntity(map[string]any{
		"big":      aboveFloat64,
		"negative": -int64(aboveFloat64),
		"half":     1.5,
		"nested":   map[string]any{"big": aboveFloat64},
		"list":     []any{aboveFloat64, "text"},
	})
	return blob
}

// requireExactNumbers asserts the decoded Entity holds every number of
// exactNumberBlob with its digits unchanged.
func requireExactNumbers(t *testing.T, blob *entities.Blob) {
	t.Helper()
	entity, ok := blob.Entity.(map[string]any)
	require.True(t, ok, "entity is %T", blob.Entity)

	assert.Equal(t, json.Number("9007199254740993"), entity["big"])
	assert.Equal(t, json.Number("-9007199254740993"), entity["negative"])
	assert.Equal(t, json.Number("1.5"), entity["half"])
	assert.Equal(t, map[string]any{"big": json.Number("9007199254740993")}, entity["nested"])
	assert.Equal(t, []any{json.Number("9007199254740993"), "text"}, entity["list"])

	number, ok := entity["big"].(json.Number)
	require.True(t, ok, "big is %T", entity["big"])
	big, err := number.Int64()
	require.NoError(t, err)
	assert.Equal(t, int64(aboveFloat64), big)
}

// TestGenericDAO_Get_IntegersAbove2Pow53AreExact pins #125 for the kvstore
// DAO: it decodes with UseNumber, so an integer above 2^53 in an any-typed
// field round-trips exactly instead of being rounded through float64.
func TestGenericDAO_Get_IntegersAbove2Pow53AreExact(t *testing.T) {
	dao, _ := newBlobDAO(t)
	ctx := context.Background()

	require.NoError(t, dao.Save(ctx, exactNumberBlob(1)))

	got, err := dao.Get(ctx, 1)
	require.NoError(t, err)
	requireExactNumbers(t, got)
}

func TestGenericDAO_Page_IntegersAbove2Pow53AreExact(t *testing.T) {
	dao, _ := newBlobDAO(t)
	ctx := context.Background()

	require.NoError(t, dao.Save(ctx, exactNumberBlob(1)))
	require.NoError(t, dao.Save(ctx, exactNumberBlob(2)))

	result, err := dao.Page(ctx, datastore.PageQuery{Page: 1, PageSize: 10})
	require.NoError(t, err)
	require.Len(t, result.Entities, 2)
	for _, blob := range result.Entities {
		requireExactNumbers(t, blob)
	}
}

// A stored document followed by trailing data is refused, as json.Unmarshal
// refused it: Get reports a deserialization failure and Page skips the entry.
func TestGenericDAO_TrailingDataIsRefused(t *testing.T) {
	dao, storage := newBlobDAO(t)
	ctx := context.Background()

	require.NoError(t, storage.Put(ctx, "Blob", 1, []byte(`{"id":1} {"id":2}`), 0))

	_, err := dao.Get(ctx, 1)
	var failed ErrDeserializationFailed
	require.ErrorAs(t, err, &failed)
	assert.ErrorIs(t, failed, datastore.ErrTrailingData{})

	result, err := dao.Page(ctx, datastore.PageQuery{Page: 1, PageSize: 10})
	require.NoError(t, err)
	assert.Empty(t, result.Entities)
}
