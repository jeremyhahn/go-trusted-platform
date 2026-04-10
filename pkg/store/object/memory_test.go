package object

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/objectstorage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryClient_PutObject(t *testing.T) {
	t.Run("stores object successfully", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		resp, err := client.PutObject(ctx, &objectstorage.PutObjectRequest{
			Key:   "platform:test/key",
			Value: []byte("hello"),
		})
		require.NoError(t, err)
		assert.Equal(t, "platform:test/key", resp.Key)
		assert.Equal(t, int64(5), resp.Size)
	})

	t.Run("nil request returns error", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		_, err := client.PutObject(ctx, nil)
		assert.ErrorIs(t, err, ErrInvalidKey)
	})

	t.Run("empty key returns error", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		_, err := client.PutObject(ctx, &objectstorage.PutObjectRequest{
			Key:   "",
			Value: []byte("data"),
		})
		assert.ErrorIs(t, err, ErrInvalidKey)
	})
}

func TestMemoryClient_GetObject(t *testing.T) {
	t.Run("retrieves stored object", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		_, err := client.PutObject(ctx, &objectstorage.PutObjectRequest{
			Key:   "platform:file.txt",
			Value: []byte("content"),
		})
		require.NoError(t, err)

		resp, err := client.GetObject(ctx, &objectstorage.GetObjectRequest{
			Key: "platform:file.txt",
		})
		require.NoError(t, err)
		assert.Equal(t, []byte("content"), resp.Value)
		assert.Equal(t, int64(7), resp.Size)
	})

	t.Run("not found returns error", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		_, err := client.GetObject(ctx, &objectstorage.GetObjectRequest{
			Key: "platform:missing",
		})
		assert.ErrorIs(t, err, ErrObjectNotFound)
	})

	t.Run("nil request returns error", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		_, err := client.GetObject(ctx, nil)
		assert.ErrorIs(t, err, ErrInvalidKey)
	})

	t.Run("empty key returns error", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		_, err := client.GetObject(ctx, &objectstorage.GetObjectRequest{Key: ""})
		assert.ErrorIs(t, err, ErrInvalidKey)
	})

	t.Run("returns copy of data", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		original := []byte("original")
		_, err := client.PutObject(ctx, &objectstorage.PutObjectRequest{
			Key:   "platform:copy-test",
			Value: original,
		})
		require.NoError(t, err)

		resp, err := client.GetObject(ctx, &objectstorage.GetObjectRequest{
			Key: "platform:copy-test",
		})
		require.NoError(t, err)

		// Mutate returned data; re-read should be unaffected
		resp.Value[0] = 'X'
		resp2, err := client.GetObject(ctx, &objectstorage.GetObjectRequest{
			Key: "platform:copy-test",
		})
		require.NoError(t, err)
		assert.Equal(t, byte('o'), resp2.Value[0])
	})
}

func TestMemoryClient_DeleteObject(t *testing.T) {
	t.Run("deletes existing object", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		_, err := client.PutObject(ctx, &objectstorage.PutObjectRequest{
			Key:   "platform:del",
			Value: []byte("data"),
		})
		require.NoError(t, err)

		resp, err := client.DeleteObject(ctx, &objectstorage.DeleteObjectRequest{
			Key: "platform:del",
		})
		require.NoError(t, err)
		assert.True(t, resp.Success)
	})

	t.Run("delete non-existent returns error", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		_, err := client.DeleteObject(ctx, &objectstorage.DeleteObjectRequest{
			Key: "platform:no-such",
		})
		assert.ErrorIs(t, err, ErrObjectNotFound)
	})

	t.Run("nil request returns error", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		_, err := client.DeleteObject(ctx, nil)
		assert.ErrorIs(t, err, ErrInvalidKey)
	})

	t.Run("empty key returns error", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		_, err := client.DeleteObject(ctx, &objectstorage.DeleteObjectRequest{Key: ""})
		assert.ErrorIs(t, err, ErrInvalidKey)
	})
}

func TestMemoryClient_HeadObject(t *testing.T) {
	t.Run("existing object returns exists true", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		_, err := client.PutObject(ctx, &objectstorage.PutObjectRequest{
			Key:   "platform:head",
			Value: []byte("data"),
		})
		require.NoError(t, err)

		resp, err := client.HeadObject(ctx, &objectstorage.HeadObjectRequest{
			Key: "platform:head",
		})
		require.NoError(t, err)
		assert.True(t, resp.Exists)
		assert.Equal(t, int64(4), resp.Size)
	})

	t.Run("non-existent object returns exists false", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		resp, err := client.HeadObject(ctx, &objectstorage.HeadObjectRequest{
			Key: "platform:nonexistent",
		})
		require.NoError(t, err)
		assert.False(t, resp.Exists)
	})

	t.Run("nil request returns error", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		_, err := client.HeadObject(ctx, nil)
		assert.ErrorIs(t, err, ErrInvalidKey)
	})

	t.Run("empty key returns error", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		_, err := client.HeadObject(ctx, &objectstorage.HeadObjectRequest{Key: ""})
		assert.ErrorIs(t, err, ErrInvalidKey)
	})
}

func TestMemoryClient_ListByTag(t *testing.T) {
	client := NewMemoryClient()
	ctx := context.Background()

	resp, err := client.ListByTag(ctx, &objectstorage.ListByTagRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp.Objects)
	assert.Empty(t, resp.Objects)
}

func TestMemoryClient_ListByTenant(t *testing.T) {
	t.Run("returns all objects", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		_, err := client.PutObject(ctx, &objectstorage.PutObjectRequest{
			Key:   "platform:a",
			Value: []byte("data-a"),
		})
		require.NoError(t, err)
		_, err = client.PutObject(ctx, &objectstorage.PutObjectRequest{
			Key:   "platform:b",
			Value: []byte("data-b"),
		})
		require.NoError(t, err)

		resp, err := client.ListByTenant(ctx, &objectstorage.ListByTenantRequest{
			TenantID: "any",
		})
		require.NoError(t, err)
		assert.Len(t, resp.Objects, 2)
		assert.Equal(t, int64(2), resp.TotalCount)
	})

	t.Run("empty store returns empty", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		resp, err := client.ListByTenant(ctx, &objectstorage.ListByTenantRequest{})
		require.NoError(t, err)
		assert.Empty(t, resp.Objects)
	})
}

func TestMemoryClient_CopyObject(t *testing.T) {
	t.Run("copies object successfully", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		_, err := client.PutObject(ctx, &objectstorage.PutObjectRequest{
			Key:   "platform:src",
			Value: []byte("source-data"),
		})
		require.NoError(t, err)

		resp, err := client.CopyObject(ctx, &objectstorage.CopyObjectRequest{
			SourceKey:      "platform:src",
			DestinationKey: "platform:dst",
		})
		require.NoError(t, err)
		assert.Equal(t, "platform:dst", resp.Key)
		assert.Equal(t, int64(11), resp.Size)

		// Verify destination exists with correct data
		getResp, err := client.GetObject(ctx, &objectstorage.GetObjectRequest{
			Key: "platform:dst",
		})
		require.NoError(t, err)
		assert.Equal(t, []byte("source-data"), getResp.Value)
	})

	t.Run("copy non-existent source returns error", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		_, err := client.CopyObject(ctx, &objectstorage.CopyObjectRequest{
			SourceKey:      "platform:missing",
			DestinationKey: "platform:dst",
		})
		assert.ErrorIs(t, err, ErrObjectNotFound)
	})

	t.Run("nil request returns error", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		_, err := client.CopyObject(ctx, nil)
		assert.ErrorIs(t, err, ErrInvalidKey)
	})

	t.Run("empty source key returns error", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		_, err := client.CopyObject(ctx, &objectstorage.CopyObjectRequest{
			SourceKey:      "",
			DestinationKey: "platform:dst",
		})
		assert.ErrorIs(t, err, ErrInvalidKey)
	})

	t.Run("empty destination key returns error", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		_, err := client.CopyObject(ctx, &objectstorage.CopyObjectRequest{
			SourceKey:      "platform:src",
			DestinationKey: "",
		})
		assert.ErrorIs(t, err, ErrInvalidKey)
	})
}

func TestMemoryClient_ReplicateObject(t *testing.T) {
	client := NewMemoryClient()
	ctx := context.Background()

	resp, err := client.ReplicateObject(ctx, &objectstorage.ReplicateObjectRequest{
		Key: "platform:replicate",
	})
	require.NoError(t, err)
	assert.Equal(t, "platform:replicate", resp.Key)
	assert.Equal(t, "completed", resp.Status)
}

func TestMemoryClient_MigrateObject(t *testing.T) {
	client := NewMemoryClient()
	ctx := context.Background()

	resp, err := client.MigrateObject(ctx, &objectstorage.MigrateObjectRequest{
		Key: "platform:migrate",
	})
	require.NoError(t, err)
	assert.Equal(t, "platform:migrate", resp.Key)
	assert.True(t, resp.Success)
}

func TestMemoryClient_ArchiveObject(t *testing.T) {
	client := NewMemoryClient()
	ctx := context.Background()

	resp, err := client.ArchiveObject(ctx, &objectstorage.ArchiveObjectRequest{
		Key: "platform:archive",
	})
	require.NoError(t, err)
	assert.Equal(t, "platform:archive", resp.Key)
	assert.True(t, resp.Success)
}

func TestMemoryClient_RestoreObject(t *testing.T) {
	client := NewMemoryClient()
	ctx := context.Background()

	resp, err := client.RestoreObject(ctx, &objectstorage.RestoreObjectRequest{
		Key: "platform:restore",
	})
	require.NoError(t, err)
	assert.Equal(t, "platform:restore", resp.Key)
	assert.True(t, resp.Success)
}

func TestMemoryClient_VerifyObject(t *testing.T) {
	client := NewMemoryClient()
	ctx := context.Background()

	resp, err := client.VerifyObject(ctx, &objectstorage.VerifyObjectRequest{
		Key: "platform:verify",
	})
	require.NoError(t, err)
	assert.Equal(t, "platform:verify", resp.Key)
	assert.True(t, resp.Valid)
}

func TestMemoryClient_SetObjectPolicy(t *testing.T) {
	client := NewMemoryClient()
	ctx := context.Background()

	resp, err := client.SetObjectPolicy(ctx, &objectstorage.SetObjectPolicyRequest{
		Key: "platform:policy",
	})
	require.NoError(t, err)
	assert.Equal(t, "platform:policy", resp.Key)
	assert.True(t, resp.Success)
}

func TestMemoryClient_GetObjectPolicy(t *testing.T) {
	client := NewMemoryClient()
	ctx := context.Background()

	resp, err := client.GetObjectPolicy(ctx, &objectstorage.GetObjectPolicyRequest{
		Key: "platform:policy",
	})
	require.NoError(t, err)
	assert.Equal(t, "platform:policy", resp.Key)
}

func TestMemoryClient_ListBackends(t *testing.T) {
	client := NewMemoryClient()
	ctx := context.Background()

	resp, err := client.ListBackends(ctx, &objectstorage.ListBackendsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Backends, 1)
	assert.Equal(t, "memory", resp.Backends[0].Name)
	assert.True(t, resp.Backends[0].Enabled)
	assert.True(t, resp.Backends[0].Default)
}

func TestMemoryClient_GetBackendHealth(t *testing.T) {
	client := NewMemoryClient()
	ctx := context.Background()

	resp, err := client.GetBackendHealth(ctx, &objectstorage.GetBackendHealthRequest{})
	require.NoError(t, err)
	assert.Equal(t, "memory", resp.Name)
	assert.True(t, resp.Healthy)
	assert.Equal(t, "healthy", resp.Status)
}

func TestMemoryClient_GetTenantUsage(t *testing.T) {
	t.Run("returns usage for stored objects", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		_, err := client.PutObject(ctx, &objectstorage.PutObjectRequest{
			Key:   "platform:usage1",
			Value: []byte("12345"),
		})
		require.NoError(t, err)
		_, err = client.PutObject(ctx, &objectstorage.PutObjectRequest{
			Key:   "platform:usage2",
			Value: []byte("67890"),
		})
		require.NoError(t, err)

		resp, err := client.GetTenantUsage(ctx, &objectstorage.GetTenantUsageRequest{
			TenantID: "t1",
		})
		require.NoError(t, err)
		assert.Equal(t, "t1", resp.TenantID)
		assert.Equal(t, int64(2), resp.ObjectCount)
		assert.Equal(t, int64(10), resp.TotalSize)
	})

	t.Run("empty store returns zero usage", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		resp, err := client.GetTenantUsage(ctx, &objectstorage.GetTenantUsageRequest{
			TenantID: "t1",
		})
		require.NoError(t, err)
		assert.Equal(t, int64(0), resp.ObjectCount)
		assert.Equal(t, int64(0), resp.TotalSize)
	})
}

func TestMemoryClient_GetTenantQuotas(t *testing.T) {
	client := NewMemoryClient()
	ctx := context.Background()

	resp, err := client.GetTenantQuotas(ctx, &objectstorage.GetTenantQuotasRequest{
		TenantID: "t1",
	})
	require.NoError(t, err)
	assert.Equal(t, "t1", resp.TenantID)
}

func TestMemoryClient_SetTenantQuotas(t *testing.T) {
	client := NewMemoryClient()
	ctx := context.Background()

	resp, err := client.SetTenantQuotas(ctx, &objectstorage.SetTenantQuotasRequest{
		TenantID: "t1",
	})
	require.NoError(t, err)
	assert.Equal(t, "t1", resp.TenantID)
}

func TestMemoryClient_BatchPutObjects(t *testing.T) {
	t.Run("stores multiple objects", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		resp, err := client.BatchPutObjects(ctx, &objectstorage.BatchPutObjectsRequest{
			Objects: []*objectstorage.PutObjectRequest{
				{Key: "platform:b1", Value: []byte("v1")},
				{Key: "platform:b2", Value: []byte("v2")},
				{Key: "platform:b3", Value: []byte("v3")},
			},
		})
		require.NoError(t, err)
		assert.Len(t, resp.Results, 3)
		assert.Equal(t, int32(3), resp.Succeeded)
	})

	t.Run("fails on invalid object in batch", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		_, err := client.BatchPutObjects(ctx, &objectstorage.BatchPutObjectsRequest{
			Objects: []*objectstorage.PutObjectRequest{
				{Key: "platform:ok", Value: []byte("v1")},
				{Key: "", Value: []byte("v2")}, // invalid
			},
		})
		assert.Error(t, err)
	})
}

func TestMemoryClient_BatchGetObjects(t *testing.T) {
	t.Run("retrieves multiple objects", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		_, err := client.PutObject(ctx, &objectstorage.PutObjectRequest{Key: "platform:bg1", Value: []byte("v1")})
		require.NoError(t, err)
		_, err = client.PutObject(ctx, &objectstorage.PutObjectRequest{Key: "platform:bg2", Value: []byte("v2")})
		require.NoError(t, err)

		resp, err := client.BatchGetObjects(ctx, &objectstorage.BatchGetObjectsRequest{
			Keys: []string{"platform:bg1", "platform:bg2", "platform:missing"},
		})
		require.NoError(t, err)
		assert.Len(t, resp.Objects, 2)
		assert.Len(t, resp.NotFound, 1)
		assert.Contains(t, resp.NotFound, "platform:missing")
	})

	t.Run("all missing returns all in not found", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		resp, err := client.BatchGetObjects(ctx, &objectstorage.BatchGetObjectsRequest{
			Keys: []string{"platform:x", "platform:y"},
		})
		require.NoError(t, err)
		assert.Empty(t, resp.Objects)
		assert.Len(t, resp.NotFound, 2)
	})
}

func TestMemoryClient_BatchDeleteObjects(t *testing.T) {
	t.Run("deletes multiple objects", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		_, err := client.PutObject(ctx, &objectstorage.PutObjectRequest{Key: "platform:bd1", Value: []byte("v1")})
		require.NoError(t, err)
		_, err = client.PutObject(ctx, &objectstorage.PutObjectRequest{Key: "platform:bd2", Value: []byte("v2")})
		require.NoError(t, err)

		resp, err := client.BatchDeleteObjects(ctx, &objectstorage.BatchDeleteObjectsRequest{
			Keys: []string{"platform:bd1", "platform:bd2", "platform:missing"},
		})
		require.NoError(t, err)
		assert.Len(t, resp.DeletedKeys, 2)
		assert.Len(t, resp.FailedKeys, 1)
		assert.Contains(t, resp.FailedKeys, "platform:missing")
	})
}

func TestMemoryClient_StreamPutObject(t *testing.T) {
	t.Run("writes and closes successfully", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		writer, err := client.StreamPutObject(ctx, objectstorage.StreamPutOptions{
			Key: "platform:stream-put",
		})
		require.NoError(t, err)

		n, err := writer.Write([]byte("chunk1"))
		require.NoError(t, err)
		assert.Equal(t, 6, n)

		n, err = writer.Write([]byte("chunk2"))
		require.NoError(t, err)
		assert.Equal(t, 6, n)

		assert.Equal(t, int64(12), writer.BytesWritten())

		resp, err := writer.Close()
		require.NoError(t, err)
		assert.Equal(t, "platform:stream-put", resp.Key)
		assert.Equal(t, int64(12), resp.Size)

		// Verify data was stored
		getResp, err := client.GetObject(ctx, &objectstorage.GetObjectRequest{
			Key: "platform:stream-put",
		})
		require.NoError(t, err)
		assert.Equal(t, []byte("chunk1chunk2"), getResp.Value)
	})

	t.Run("abort discards data", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		writer, err := client.StreamPutObject(ctx, objectstorage.StreamPutOptions{
			Key: "platform:stream-abort",
		})
		require.NoError(t, err)

		_, err = writer.Write([]byte("data"))
		require.NoError(t, err)

		err = writer.Abort()
		require.NoError(t, err)
	})
}

func TestMemoryClient_StreamGetObject(t *testing.T) {
	t.Run("reads object via stream", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		_, err := client.PutObject(ctx, &objectstorage.PutObjectRequest{
			Key:   "platform:stream-get",
			Value: []byte("stream-data"),
		})
		require.NoError(t, err)

		reader, err := client.StreamGetObject(ctx, &objectstorage.GetObjectRequest{
			Key: "platform:stream-get",
		})
		require.NoError(t, err)

		// Read data
		buf := make([]byte, 20)
		n, err := reader.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, 11, n)
		assert.Equal(t, []byte("stream-data"), buf[:n])

		assert.Equal(t, int64(11), reader.BytesRead())
		assert.Equal(t, int64(11), reader.TotalSize())

		meta := reader.Metadata()
		assert.Equal(t, int64(11), meta.Size)

		readMeta, err := reader.ReadMetadata()
		require.NoError(t, err)
		assert.Equal(t, int64(11), readMeta.Size)

		// Read past end returns error
		_, err = reader.Read(buf)
		assert.Error(t, err)

		// Close is a no-op
		err = reader.Close()
		require.NoError(t, err)
	})

	t.Run("stream get non-existent returns error", func(t *testing.T) {
		client := NewMemoryClient()
		ctx := context.Background()

		_, err := client.StreamGetObject(ctx, &objectstorage.GetObjectRequest{
			Key: "platform:missing",
		})
		assert.ErrorIs(t, err, ErrObjectNotFound)
	})
}
