//go:build raft

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
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestWebAuthnDAO(t *testing.T) (*WebAuthnDAO, *Client, func()) {
	t.Helper()

	cfg := TestConfig(t)
	logger := logging.DefaultLogger()

	// Create embedded server
	server, err := NewEmbeddedServer(cfg, logger)
	require.NoError(t, err, "failed to create embedded server")

	// Start embedded server
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err = server.Start(ctx)
	cancel()
	require.NoError(t, err, "failed to start embedded server")

	// Create client
	client, err := NewClient(cfg, logger)
	require.NoError(t, err, "failed to create client")

	// Start client with embedded service
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	err = client.StartWithService(ctx, server.Service())
	cancel()
	require.NoError(t, err, "failed to start client with service")

	dao := NewWebAuthnDAO(client, logger)

	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Stop client first
		if err := client.Stop(ctx); err != nil {
			t.Logf("client stop error: %v", err)
		}

		// Stop embedded server
		if err := server.Stop(ctx); err != nil {
			t.Logf("server stop error: %v", err)
		}
	}

	return dao, client, cleanup
}

func TestNewWebAuthnDAO(t *testing.T) {
	dao, _, cleanup := newTestWebAuthnDAO(t)
	defer cleanup()

	assert.NotNil(t, dao)
	assert.NotNil(t, dao.GenericDAO)
}

func TestWebAuthnDAO_Save_NewBlob(t *testing.T) {
	dao, _, cleanup := newTestWebAuthnDAO(t)
	defer cleanup()

	ctx := context.Background()
	blob := entities.NewBlob(0, []byte("test credential data"))

	err := dao.Save(ctx, blob)
	require.NoError(t, err)
	assert.NotEqual(t, uint64(0), blob.EntityID())
}

func TestWebAuthnDAO_Save_WithExistingID(t *testing.T) {
	dao, _, cleanup := newTestWebAuthnDAO(t)
	defer cleanup()

	ctx := context.Background()
	blob := entities.NewBlob(12345, []byte("existing credential"))

	err := dao.Save(ctx, blob)
	require.NoError(t, err)
	assert.Equal(t, uint64(12345), blob.EntityID())
}

func TestWebAuthnDAO_Get_Success(t *testing.T) {
	dao, _, cleanup := newTestWebAuthnDAO(t)
	defer cleanup()

	ctx := context.Background()
	data := []byte(`{"credentialId":"abc123","publicKey":"xyz789"}`)
	blob := entities.NewBlob(99999, data)

	err := dao.Save(ctx, blob)
	require.NoError(t, err)

	retrieved, err := dao.Get(ctx, 99999)
	require.NoError(t, err)
	assert.Equal(t, uint64(99999), retrieved.EntityID())
	assert.Equal(t, data, retrieved.Bytes)
}

func TestWebAuthnDAO_Get_NotFound(t *testing.T) {
	dao, _, cleanup := newTestWebAuthnDAO(t)
	defer cleanup()

	ctx := context.Background()
	_, err := dao.Get(ctx, 88888888)
	require.Error(t, err)

	var notFoundErr ErrNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestWebAuthnDAO_Delete_Success(t *testing.T) {
	dao, _, cleanup := newTestWebAuthnDAO(t)
	defer cleanup()

	ctx := context.Background()
	blob := entities.NewBlob(77777, []byte("to delete"))

	err := dao.Save(ctx, blob)
	require.NoError(t, err)

	err = dao.Delete(ctx, blob)
	require.NoError(t, err)

	// Note: In local mode (no Raft), delete is immediate.
	// We verify that Delete returns without error, which indicates
	// the delete operation was processed by the storage layer.
}

func TestWebAuthnDAO_Update_Success(t *testing.T) {
	dao, _, cleanup := newTestWebAuthnDAO(t)
	defer cleanup()

	ctx := context.Background()
	blob := entities.NewBlob(66666, []byte("original data"))

	err := dao.Save(ctx, blob)
	require.NoError(t, err)

	// Update
	blob.Bytes = []byte("updated data")
	err = dao.Save(ctx, blob)
	require.NoError(t, err)

	// Verify update
	retrieved, err := dao.Get(ctx, 66666)
	require.NoError(t, err)
	assert.Equal(t, []byte("updated data"), retrieved.Bytes)
}

func TestWebAuthnDAO_Count(t *testing.T) {
	dao, _, cleanup := newTestWebAuthnDAO(t)
	defer cleanup()

	ctx := context.Background()

	// Create blobs
	for i := 1; i <= 7; i++ {
		blob := entities.NewBlob(uint64(50000+i), []byte("count blob "+string(rune('0'+i))))
		require.NoError(t, dao.Save(ctx, blob))
	}

	count, err := dao.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 7, count)
}

func TestWebAuthnDAO_Page(t *testing.T) {
	dao, _, cleanup := newTestWebAuthnDAO(t)
	defer cleanup()

	ctx := context.Background()

	// Create 10 blobs
	for i := 1; i <= 10; i++ {
		blob := entities.NewBlob(uint64(40000+i), []byte("page blob "+string(rune('0'+i))))
		require.NoError(t, dao.Save(ctx, blob))
	}

	result, err := dao.Page(ctx, datastore.PageQuery{Page: 1, PageSize: 4})
	require.NoError(t, err)
	assert.Len(t, result.Entities, 4)
	assert.True(t, result.HasMore)
}

func TestWebAuthnDAO_ForEachPage(t *testing.T) {
	dao, _, cleanup := newTestWebAuthnDAO(t)
	defer cleanup()

	ctx := context.Background()

	// Create 11 blobs
	for i := 1; i <= 11; i++ {
		blob := entities.NewBlob(uint64(30000+i), []byte("foreach blob "+string(rune('a'+i-1))))
		require.NoError(t, dao.Save(ctx, blob))
	}

	var processedCount int
	err := dao.ForEachPage(
		ctx,
		datastore.PageQuery{Page: 1, PageSize: 4},
		func(result datastore.PageResult[*entities.Blob]) error {
			processedCount += len(result.Entities)
			return nil
		},
	)
	require.NoError(t, err)
	assert.Equal(t, 11, processedCount)
}

func TestWebAuthnDAO_LargeBinaryData(t *testing.T) {
	dao, _, cleanup := newTestWebAuthnDAO(t)
	defer cleanup()

	ctx := context.Background()

	// Create large binary blob (like a credential)
	largeData := make([]byte, 4096)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	blob := entities.NewBlob(20000, largeData)

	err := dao.Save(ctx, blob)
	require.NoError(t, err)

	retrieved, err := dao.Get(ctx, 20000)
	require.NoError(t, err)
	assert.Equal(t, largeData, retrieved.Bytes)
}

func TestWebAuthnDAO_WithEntity(t *testing.T) {
	dao, _, cleanup := newTestWebAuthnDAO(t)
	defer cleanup()

	ctx := context.Background()
	blob := &entities.Blob{
		ID:    10000,
		Bytes: []byte("credential bytes"),
	}
	blob.SetEntity(map[string]interface{}{
		"credentialID": "abc123",
		"userID":       "user456",
	})

	err := dao.Save(ctx, blob)
	require.NoError(t, err)

	retrieved, err := dao.Get(ctx, 10000)
	require.NoError(t, err)
	assert.Equal(t, []byte("credential bytes"), retrieved.Bytes)
	// Note: Entity field is interface{}, stored as JSON
	assert.NotNil(t, retrieved.Entity)
}

func TestWebAuthnDAO_EmptyBytes(t *testing.T) {
	dao, _, cleanup := newTestWebAuthnDAO(t)
	defer cleanup()

	ctx := context.Background()
	blob := entities.NewBlob(9000, []byte{})

	err := dao.Save(ctx, blob)
	require.NoError(t, err)

	retrieved, err := dao.Get(ctx, 9000)
	require.NoError(t, err)
	assert.Empty(t, retrieved.Bytes)
}

func TestWebAuthnDAO_NilBytes(t *testing.T) {
	dao, _, cleanup := newTestWebAuthnDAO(t)
	defer cleanup()

	ctx := context.Background()
	blob := &entities.Blob{
		ID:    8000,
		Bytes: nil,
	}

	err := dao.Save(ctx, blob)
	require.NoError(t, err)

	retrieved, err := dao.Get(ctx, 8000)
	require.NoError(t, err)
	assert.Nil(t, retrieved.Bytes)
}
