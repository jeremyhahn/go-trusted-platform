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
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// aboveFloat64 is 2^53 + 1, the smallest integer a float64 cannot hold: a
// float64 decode reads it back as 9007199254740992.
const aboveFloat64 uint64 = 9007199254740993

// exactNumberProfile returns a profile whose any-typed Config holds integers
// above 2^53 at the top level, nested in a map and in a slice, plus a
// negative one and a non-integer.
func exactNumberProfile(id uint64) *entities.DeviceProfile {
	return &entities.DeviceProfile{
		ID:    id,
		Model: "exact-numbers",
		Config: map[string]any{
			"big":      aboveFloat64,
			"negative": -int64(aboveFloat64),
			"half":     1.5,
			"nested":   map[string]any{"big": aboveFloat64},
			"list":     []any{aboveFloat64, "text"},
		},
	}
}

// requireExactNumbers asserts the decoded Config holds every number of
// exactNumberProfile with its digits unchanged.
func requireExactNumbers(t *testing.T, profile *entities.DeviceProfile) {
	t.Helper()
	config, ok := profile.Config.(map[string]any)
	require.True(t, ok, "config is %T", profile.Config)

	assert.Equal(t, json.Number("9007199254740993"), config["big"])
	assert.Equal(t, json.Number("-9007199254740993"), config["negative"])
	assert.Equal(t, json.Number("1.5"), config["half"])
	assert.Equal(t, map[string]any{"big": json.Number("9007199254740993")}, config["nested"])
	assert.Equal(t, []any{json.Number("9007199254740993"), "text"}, config["list"])

	big, err := config["big"].(json.Number).Int64()
	require.NoError(t, err)
	assert.Equal(t, int64(aboveFloat64), big)
}

// TestGenericDAO_Get_IntegersAbove2Pow53AreExact pins #125: the DAO decodes
// with UseNumber, so an integer above 2^53 in an any-typed field round-trips
// exactly instead of being rounded through float64.
func TestGenericDAO_Get_IntegersAbove2Pow53AreExact(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())
	ctx := context.Background()

	require.NoError(t, dao.Save(ctx, exactNumberProfile(1)))

	got, err := dao.Get(ctx, 1)
	require.NoError(t, err)
	requireExactNumbers(t, got)
}

func TestGenericDAO_Page_IntegersAbove2Pow53AreExact(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())
	ctx := context.Background()

	require.NoError(t, dao.Save(ctx, exactNumberProfile(1)))
	require.NoError(t, dao.Save(ctx, exactNumberProfile(2)))

	result, err := dao.Page(ctx, datastore.PageQuery{Page: 1, PageSize: 10})
	require.NoError(t, err)
	require.Len(t, result.Entities, 2)
	for _, profile := range result.Entities {
		requireExactNumbers(t, profile)
	}
}

// The DAO's query readers share the decode path.
func TestDeviceProfileDAO_GetByModel_IntegersAbove2Pow53AreExact(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())
	ctx := context.Background()

	require.NoError(t, dao.Save(ctx, exactNumberProfile(1)))

	got, err := dao.GetByModel(ctx, "exact-numbers")
	require.NoError(t, err)
	requireExactNumbers(t, got)
}

// A stored document followed by trailing data surfaces from Get as a
// deserialization failure.
func TestGenericDAO_Get_TrailingDataIsDeserializationFailure(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())
	ctx := context.Background()

	require.NoError(t, mock.Put(ctx, entityTypeDeviceProfile, 1, []byte(`{"id":1} {"id":2}`), 0))

	_, err := dao.Get(ctx, 1)
	var failed ErrDeserializationFailed
	require.ErrorAs(t, err, &failed)
	assert.ErrorIs(t, failed, datastore.ErrTrailingData{})
}
