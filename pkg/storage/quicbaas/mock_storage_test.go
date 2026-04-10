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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMockStorage_Start_Success(t *testing.T) {
	mock := NewMockStorage()

	err := mock.Start(context.Background())

	require.NoError(t, err)
	assert.True(t, mock.IsStarted())
	assert.False(t, mock.IsClosed())
}

func TestMockStorage_Start_WithError(t *testing.T) {
	mock := NewMockStorage()
	mock.StartError = errors.New("start failed")

	err := mock.Start(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "start failed")
	assert.False(t, mock.IsStarted())
}

func TestMockStorage_Start_AfterClose(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	require.NoError(t, mock.Stop(context.Background()))

	err := mock.Start(context.Background())

	require.Error(t, err)
	var closedErr ErrServerClosed
	assert.ErrorAs(t, err, &closedErr)
}

func TestMockStorage_Stop_Success(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))

	err := mock.Stop(context.Background())

	require.NoError(t, err)
	assert.False(t, mock.IsStarted())
	assert.True(t, mock.IsClosed())
}

func TestMockStorage_Stop_WithError(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	mock.StopError = errors.New("stop failed")

	err := mock.Stop(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "stop failed")
}

func TestMockStorage_Put_Success(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))

	err := mock.Put(context.Background(), "TestEntity", 123, []byte("data"), 0)

	require.NoError(t, err)
	assert.Equal(t, 1, mock.Count("TestEntity"))
}

func TestMockStorage_Put_NotStarted(t *testing.T) {
	mock := NewMockStorage()

	err := mock.Put(context.Background(), "TestEntity", 123, []byte("data"), 0)

	require.Error(t, err)
	var notStartedErr ErrServerNotStarted
	assert.ErrorAs(t, err, &notStartedErr)
}

func TestMockStorage_Put_WithError(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	mock.PutError = errors.New("put failed")

	err := mock.Put(context.Background(), "TestEntity", 123, []byte("data"), 0)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "put failed")
}

func TestMockStorage_Get_Success(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	require.NoError(t, mock.Put(context.Background(), "TestEntity", 123, []byte("test data"), 0))

	data, found, err := mock.Get(context.Background(), "TestEntity", 123, 0)

	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, []byte("test data"), data)
}

func TestMockStorage_Get_NotFound(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))

	data, found, err := mock.Get(context.Background(), "TestEntity", 999, 0)

	require.NoError(t, err)
	assert.False(t, found)
	assert.Nil(t, data)
}

func TestMockStorage_Get_NotStarted(t *testing.T) {
	mock := NewMockStorage()

	_, _, err := mock.Get(context.Background(), "TestEntity", 123, 0)

	require.Error(t, err)
	var notStartedErr ErrServerNotStarted
	assert.ErrorAs(t, err, &notStartedErr)
}

func TestMockStorage_Get_WithError(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	mock.GetError = errors.New("get failed")

	_, _, err := mock.Get(context.Background(), "TestEntity", 123, 0)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "get failed")
}

func TestMockStorage_Delete_Success(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	require.NoError(t, mock.Put(context.Background(), "TestEntity", 123, []byte("data"), 0))
	assert.Equal(t, 1, mock.Count("TestEntity"))

	err := mock.Delete(context.Background(), "TestEntity", 123, 0)

	require.NoError(t, err)
	assert.Equal(t, 0, mock.Count("TestEntity"))
}

func TestMockStorage_Delete_NotStarted(t *testing.T) {
	mock := NewMockStorage()

	err := mock.Delete(context.Background(), "TestEntity", 123, 0)

	require.Error(t, err)
	var notStartedErr ErrServerNotStarted
	assert.ErrorAs(t, err, &notStartedErr)
}

func TestMockStorage_Delete_WithError(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	mock.DeleteError = errors.New("delete failed")

	err := mock.Delete(context.Background(), "TestEntity", 123, 0)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete failed")
}

func TestMockStorage_List_Success(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))

	// Add multiple entities
	for i := uint64(1); i <= 5; i++ {
		require.NoError(t, mock.Put(context.Background(), "TestEntity", i, []byte("data"), 0))
	}

	entities, nextToken, err := mock.List(context.Background(), "TestEntity", 10, "", 0)

	require.NoError(t, err)
	assert.Equal(t, 5, len(entities))
	assert.Empty(t, nextToken)
}

func TestMockStorage_List_NotStarted(t *testing.T) {
	mock := NewMockStorage()

	_, _, err := mock.List(context.Background(), "TestEntity", 10, "", 0)

	require.Error(t, err)
	var notStartedErr ErrServerNotStarted
	assert.ErrorAs(t, err, &notStartedErr)
}

func TestMockStorage_List_WithError(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	mock.ListError = errors.New("list failed")

	_, _, err := mock.List(context.Background(), "TestEntity", 10, "", 0)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "list failed")
}

func TestMockStorage_Query_Success(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	require.NoError(t, mock.Put(context.Background(), "TestEntity", 123, []byte("data"), 0))

	entities, err := mock.Query(context.Background(), "TestEntity", "field", []byte("value"), 0)

	require.NoError(t, err)
	assert.Equal(t, 1, len(entities))
}

func TestMockStorage_Query_NotStarted(t *testing.T) {
	mock := NewMockStorage()

	_, err := mock.Query(context.Background(), "TestEntity", "field", []byte("value"), 0)

	require.Error(t, err)
	var notStartedErr ErrServerNotStarted
	assert.ErrorAs(t, err, &notStartedErr)
}

func TestMockStorage_Query_WithError(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	mock.QueryError = errors.New("query failed")

	_, err := mock.Query(context.Background(), "TestEntity", "field", []byte("value"), 0)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "query failed")
}

func TestMockStorage_Reset(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	require.NoError(t, mock.Put(context.Background(), "TestEntity", 123, []byte("data"), 0))
	mock.PutError = errors.New("some error")

	mock.Reset()

	assert.False(t, mock.IsStarted())
	assert.False(t, mock.IsClosed())
	assert.Equal(t, 0, mock.Count("TestEntity"))
	assert.Nil(t, mock.PutError)
}

func TestMockStorage_SetData(t *testing.T) {
	mock := NewMockStorage()

	mock.SetData("TestEntity", 123, []byte("preset data"))

	// Can retrieve even without starting (SetData bypasses started check)
	require.NoError(t, mock.Start(context.Background()))
	data, found, err := mock.Get(context.Background(), "TestEntity", 123, 0)

	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, []byte("preset data"), data)
}

func TestMockStorage_GetAllData(t *testing.T) {
	mock := NewMockStorage()
	mock.SetData("TestEntity", 1, []byte("data1"))
	mock.SetData("TestEntity", 2, []byte("data2"))

	allData := mock.GetAllData("TestEntity")

	assert.Equal(t, 2, len(allData))
	assert.Equal(t, []byte("data1"), allData[1])
	assert.Equal(t, []byte("data2"), allData[2])
}

func TestMockStorage_GetAllData_Empty(t *testing.T) {
	mock := NewMockStorage()

	allData := mock.GetAllData("NonExistent")

	assert.Empty(t, allData)
}

func TestMockStorage_Count(t *testing.T) {
	mock := NewMockStorage()
	mock.SetData("TestEntity", 1, []byte("data1"))
	mock.SetData("TestEntity", 2, []byte("data2"))
	mock.SetData("OtherEntity", 1, []byte("other"))

	assert.Equal(t, 2, mock.Count("TestEntity"))
	assert.Equal(t, 1, mock.Count("OtherEntity"))
	assert.Equal(t, 0, mock.Count("NonExistent"))
}

func TestMockStorage_List_Pagination(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))

	// Add 10 entities
	for i := uint64(1); i <= 10; i++ {
		require.NoError(t, mock.Put(context.Background(), "TestEntity", i, []byte("data"), 0))
	}

	// First page
	entities, nextToken, err := mock.List(context.Background(), "TestEntity", 5, "", 0)
	require.NoError(t, err)
	assert.Equal(t, 5, len(entities))
	assert.NotEmpty(t, nextToken)

	// Second page
	entities2, _, err := mock.List(context.Background(), "TestEntity", 5, nextToken, 0)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(entities2), 5)
	// Note: Due to map iteration order, the exact results may vary
}
