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
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupMockWebAuthnDAO(t *testing.T) (*WebAuthnDAO, *MockStorage) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))

	logger := logging.DefaultLogger()
	dao := NewWebAuthnDAO(mock, logger, WithRequestTimeout(5*time.Second))

	return dao, mock
}

func TestWebAuthnDAO_Save_Mock(t *testing.T) {
	dao, mock := setupMockWebAuthnDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	blob := &entities.Blob{Bytes: []byte("webauthn credential data")}
	err := dao.Save(ctx, blob)

	require.NoError(t, err)
	assert.NotZero(t, blob.ID)
	assert.Equal(t, 1, mock.Count(entityTypeWebAuthn))
}

func TestWebAuthnDAO_Save_WithExistingID_Mock(t *testing.T) {
	dao, mock := setupMockWebAuthnDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	blob := &entities.Blob{ID: 12345, Bytes: []byte("webauthn credential data")}
	err := dao.Save(ctx, blob)

	require.NoError(t, err)
	assert.Equal(t, uint64(12345), blob.ID)
}

func TestWebAuthnDAO_Get_Mock(t *testing.T) {
	dao, mock := setupMockWebAuthnDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	blob := &entities.Blob{ID: 12345, Bytes: []byte("webauthn credential data")}
	require.NoError(t, dao.Save(ctx, blob))

	retrieved, err := dao.Get(ctx, 12345)

	require.NoError(t, err)
	assert.Equal(t, []byte("webauthn credential data"), retrieved.Bytes)
}

func TestWebAuthnDAO_Get_NotFound_Mock(t *testing.T) {
	dao, mock := setupMockWebAuthnDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Get(ctx, 99999)

	require.Error(t, err)
	var notFoundErr ErrNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestWebAuthnDAO_Delete_Mock(t *testing.T) {
	dao, mock := setupMockWebAuthnDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	blob := &entities.Blob{ID: 12345, Bytes: []byte("webauthn credential data")}
	require.NoError(t, dao.Save(ctx, blob))
	assert.Equal(t, 1, mock.Count(entityTypeWebAuthn))

	err := dao.Delete(ctx, blob)

	require.NoError(t, err)
	assert.Equal(t, 0, mock.Count(entityTypeWebAuthn))
}

func TestWebAuthnDAO_Update_Mock(t *testing.T) {
	dao, mock := setupMockWebAuthnDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	blob := &entities.Blob{ID: 12345, Bytes: []byte("initial data")}
	require.NoError(t, dao.Save(ctx, blob))

	blob.Bytes = []byte("updated credential data")
	require.NoError(t, dao.Save(ctx, blob))

	retrieved, err := dao.Get(ctx, 12345)
	require.NoError(t, err)
	assert.Equal(t, []byte("updated credential data"), retrieved.Bytes)
}

func TestWebAuthnDAO_Count_Mock(t *testing.T) {
	dao, mock := setupMockWebAuthnDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		blob := &entities.Blob{ID: uint64(i), Bytes: []byte("data")}
		require.NoError(t, dao.Save(ctx, blob))
	}

	count, err := dao.Count(ctx)

	require.NoError(t, err)
	assert.Equal(t, 5, count)
}

func TestWebAuthnDAO_Count_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockWebAuthnDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage error")

	ctx := context.Background()
	_, err := dao.Count(ctx)
	require.Error(t, err)
}

func TestWebAuthnDAO_Page_Mock(t *testing.T) {
	dao, mock := setupMockWebAuthnDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 10; i++ {
		blob := &entities.Blob{ID: uint64(i), Bytes: []byte("data")}
		require.NoError(t, dao.Save(ctx, blob))
	}

	query := datastore.PageQuery{Page: 1, PageSize: 5}
	result, err := dao.Page(ctx, query)

	require.NoError(t, err)
	assert.Equal(t, 5, len(result.Entities))
	assert.True(t, result.HasMore)
}

func TestWebAuthnDAO_Page_LastPage_Mock(t *testing.T) {
	dao, mock := setupMockWebAuthnDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 7; i++ {
		blob := &entities.Blob{ID: uint64(i), Bytes: []byte("data")}
		require.NoError(t, dao.Save(ctx, blob))
	}

	query := datastore.PageQuery{Page: 2, PageSize: 5}
	result, err := dao.Page(ctx, query)

	require.NoError(t, err)
	assert.Equal(t, 2, len(result.Entities))
	assert.False(t, result.HasMore)
}

func TestWebAuthnDAO_ForEachPage_Mock(t *testing.T) {
	dao, mock := setupMockWebAuthnDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 8; i++ {
		blob := &entities.Blob{ID: uint64(i), Bytes: []byte("data")}
		require.NoError(t, dao.Save(ctx, blob))
	}

	var allBlobs []*entities.Blob
	processor := func(result datastore.PageResult[*entities.Blob]) error {
		allBlobs = append(allBlobs, result.Entities...)
		return nil
	}

	query := datastore.PageQuery{Page: 1, PageSize: 3}
	err := dao.ForEachPage(ctx, query, processor)

	require.NoError(t, err)
	assert.Equal(t, 8, len(allBlobs))
}

func TestWebAuthnDAO_ForEachPage_ProcessorError_Mock(t *testing.T) {
	dao, mock := setupMockWebAuthnDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		blob := &entities.Blob{ID: uint64(i), Bytes: []byte("data")}
		require.NoError(t, dao.Save(ctx, blob))
	}

	expectedErr := errors.New("processor error")
	processor := func(result datastore.PageResult[*entities.Blob]) error {
		return expectedErr
	}

	query := datastore.PageQuery{Page: 1, PageSize: 3}
	err := dao.ForEachPage(ctx, query, processor)

	require.ErrorIs(t, err, expectedErr)
}

func TestWebAuthnDAO_LargeBinaryData_Mock(t *testing.T) {
	dao, mock := setupMockWebAuthnDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()

	// Create large binary data (4KB)
	largeData := make([]byte, 4096)
	_, err := rand.Read(largeData)
	require.NoError(t, err)

	blob := &entities.Blob{ID: 12345, Bytes: largeData}
	require.NoError(t, dao.Save(ctx, blob))

	retrieved, err := dao.Get(ctx, 12345)
	require.NoError(t, err)
	assert.Equal(t, largeData, retrieved.Bytes)
}

func TestWebAuthnDAO_WithEntity_Mock(t *testing.T) {
	dao, mock := setupMockWebAuthnDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	entity := map[string]interface{}{
		"credentialID": "abc123",
		"publicKey":    "xyz789",
		"counter":      42,
	}

	blob := &entities.Blob{ID: 12345, Bytes: []byte("credential data")}
	blob.SetEntity(entity)
	require.NoError(t, dao.Save(ctx, blob))

	retrieved, err := dao.Get(ctx, 12345)
	require.NoError(t, err)
	assert.NotNil(t, retrieved.Entity)
}

func TestWebAuthnDAO_EmptyBytes_Mock(t *testing.T) {
	dao, mock := setupMockWebAuthnDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	blob := &entities.Blob{ID: 12345, Bytes: []byte{}}
	require.NoError(t, dao.Save(ctx, blob))

	retrieved, err := dao.Get(ctx, 12345)
	require.NoError(t, err)
	assert.Empty(t, retrieved.Bytes)
}

func TestWebAuthnDAO_NilBytes_Mock(t *testing.T) {
	dao, mock := setupMockWebAuthnDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	blob := &entities.Blob{ID: 12345}
	require.NoError(t, dao.Save(ctx, blob))

	retrieved, err := dao.Get(ctx, 12345)
	require.NoError(t, err)
	assert.Nil(t, retrieved.Bytes)
}

func TestWebAuthnDAO_Save_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockWebAuthnDAO(t)
	defer mock.Stop(context.Background())

	mock.PutError = errors.New("storage unavailable")

	ctx := context.Background()
	blob := &entities.Blob{Bytes: []byte("data")}
	err := dao.Save(ctx, blob)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage unavailable")
}

func TestWebAuthnDAO_Get_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockWebAuthnDAO(t)
	defer mock.Stop(context.Background())

	blob := &entities.Blob{ID: 12345, Bytes: []byte("data")}
	data, _ := json.Marshal(blob)
	mock.SetData(entityTypeWebAuthn, 12345, data)

	mock.GetError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.Get(ctx, 12345)

	require.Error(t, err)
}

func TestWebAuthnDAO_Delete_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockWebAuthnDAO(t)
	defer mock.Stop(context.Background())

	mock.DeleteError = errors.New("storage unavailable")

	ctx := context.Background()
	blob := &entities.Blob{ID: 12345, Bytes: []byte("data")}
	err := dao.Delete(ctx, blob)

	require.Error(t, err)
}

func TestWebAuthnDAO_Page_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockWebAuthnDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	query := datastore.PageQuery{Page: 1, PageSize: 5}
	_, err := dao.Page(ctx, query)

	require.Error(t, err)
}

func TestWebAuthnDAO_MultipleCredentials_Mock(t *testing.T) {
	dao, mock := setupMockWebAuthnDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()

	// Simulate storing multiple WebAuthn credentials for same user
	credentials := []struct {
		id    uint64
		bytes []byte
	}{
		{1, []byte("credential_1_for_user_123")},
		{2, []byte("credential_2_for_user_123")},
		{3, []byte("credential_3_for_user_456")},
	}

	for _, cred := range credentials {
		blob := &entities.Blob{ID: cred.id, Bytes: cred.bytes}
		require.NoError(t, dao.Save(ctx, blob))
	}

	count, err := dao.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 3, count)

	// Verify each credential
	for _, cred := range credentials {
		retrieved, err := dao.Get(ctx, cred.id)
		require.NoError(t, err)
		assert.Equal(t, cred.bytes, retrieved.Bytes)
	}
}
