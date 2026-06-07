package object

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewObjStoreAdapter(t *testing.T) {
	client := NewMemoryClient()
	adapter := NewObjStoreAdapter(client)
	require.NotNil(t, adapter)
}

func TestNewObjStoreAdapterWithTenant(t *testing.T) {
	client := NewMemoryClient()
	adapter := NewObjStoreAdapterWithTenant(client, "tenant-1")
	require.NotNil(t, adapter)
}

func TestObjStoreAdapter_Configure(t *testing.T) {
	t.Run("sets path prefix", func(t *testing.T) {
		client := NewMemoryClient()
		adapter := NewObjStoreAdapter(client).(*ObjStoreAdapter)

		err := adapter.Configure(map[string]string{"path": "/data/certs"})
		require.NoError(t, err)
		assert.Equal(t, "/data/certs", adapter.prefix)
	})

	t.Run("no path key is no-op", func(t *testing.T) {
		client := NewMemoryClient()
		adapter := NewObjStoreAdapter(client).(*ObjStoreAdapter)

		err := adapter.Configure(map[string]string{"other": "value"})
		require.NoError(t, err)
		assert.Equal(t, "", adapter.prefix)
	})
}

func TestObjStoreAdapter_formatKey(t *testing.T) {
	t.Run("without prefix", func(t *testing.T) {
		client := NewMemoryClient()
		adapter := NewObjStoreAdapter(client).(*ObjStoreAdapter)

		key := adapter.formatKey("certs/root.pem")
		assert.Equal(t, "platform:certs/root.pem", key)
	})

	t.Run("with prefix", func(t *testing.T) {
		client := NewMemoryClient()
		adapter := NewObjStoreAdapter(client).(*ObjStoreAdapter)
		adapter.prefix = "/data/ca"

		key := adapter.formatKey("root.pem")
		assert.Equal(t, "platform:data/ca/root.pem", key)
	})

	t.Run("strips leading slashes from key", func(t *testing.T) {
		client := NewMemoryClient()
		adapter := NewObjStoreAdapter(client).(*ObjStoreAdapter)

		key := adapter.formatKey("/path/to/file")
		assert.Equal(t, "platform:path/to/file", key)
	})
}

func TestObjStoreAdapter_PutAndGet(t *testing.T) {
	t.Run("put and get round trip", func(t *testing.T) {
		client := NewMemoryClient()
		adapter := NewObjStoreAdapter(client)

		err := adapter.Put("test/file.txt", bytes.NewReader([]byte("hello world")))
		require.NoError(t, err)

		reader, err := adapter.Get("test/file.txt")
		require.NoError(t, err)
		defer reader.Close()

		data, err := io.ReadAll(reader)
		require.NoError(t, err)
		assert.Equal(t, []byte("hello world"), data)
	})

	t.Run("get non-existent returns error", func(t *testing.T) {
		client := NewMemoryClient()
		adapter := NewObjStoreAdapter(client)

		_, err := adapter.Get("nonexistent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "object not found")
	})
}

func TestObjStoreAdapter_PutWithContext(t *testing.T) {
	client := NewMemoryClient()
	adapter := NewObjStoreAdapter(client)
	ctx := context.Background()

	err := adapter.PutWithContext(ctx, "ctx-test", bytes.NewReader([]byte("ctx-data")))
	require.NoError(t, err)

	reader, err := adapter.GetWithContext(ctx, "ctx-test")
	require.NoError(t, err)
	defer reader.Close()

	data, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, []byte("ctx-data"), data)
}

func TestObjStoreAdapter_PutWithMetadata(t *testing.T) {
	t.Run("stores with metadata", func(t *testing.T) {
		client := NewMemoryClient()
		adapter := NewObjStoreAdapter(client)
		ctx := context.Background()

		meta := &xkmssdk.ObjectMetadata{
			ContentType: "application/x-pem-file",
			Custom:      map[string]string{"purpose": "root-ca"},
		}

		err := adapter.PutWithMetadata(ctx, "cert.pem", bytes.NewReader([]byte("cert-data")), meta)
		require.NoError(t, err)

		// Verify the data was stored
		reader, err := adapter.GetWithContext(ctx, "cert.pem")
		require.NoError(t, err)
		defer reader.Close()
		data, err := io.ReadAll(reader)
		require.NoError(t, err)
		assert.Equal(t, []byte("cert-data"), data)
	})

	t.Run("stores with nil metadata", func(t *testing.T) {
		client := NewMemoryClient()
		adapter := NewObjStoreAdapter(client)
		ctx := context.Background()

		err := adapter.PutWithMetadata(ctx, "no-meta.txt", bytes.NewReader([]byte("plain")), nil)
		require.NoError(t, err)
	})
}

func TestObjStoreAdapter_GetMetadata(t *testing.T) {
	t.Run("returns metadata for existing object", func(t *testing.T) {
		client := NewMemoryClient()
		adapter := NewObjStoreAdapter(client)
		ctx := context.Background()

		err := adapter.Put("meta-test", bytes.NewReader([]byte("data")))
		require.NoError(t, err)

		meta, err := adapter.GetMetadata(ctx, "meta-test")
		require.NoError(t, err)
		assert.Equal(t, int64(4), meta.Size)
	})

	t.Run("returns error for non-existent object", func(t *testing.T) {
		client := NewMemoryClient()
		adapter := NewObjStoreAdapter(client)
		ctx := context.Background()

		_, err := adapter.GetMetadata(ctx, "missing")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "object not found")
	})
}

func TestObjStoreAdapter_UpdateMetadata(t *testing.T) {
	t.Run("updates metadata on existing object", func(t *testing.T) {
		client := NewMemoryClient()
		adapter := NewObjStoreAdapter(client)
		ctx := context.Background()

		err := adapter.Put("update-meta", bytes.NewReader([]byte("original")))
		require.NoError(t, err)

		newMeta := &xkmssdk.ObjectMetadata{
			ContentType: "text/plain",
		}
		err = adapter.UpdateMetadata(ctx, "update-meta", newMeta)
		require.NoError(t, err)

		// Verify data preserved
		reader, err := adapter.GetWithContext(ctx, "update-meta")
		require.NoError(t, err)
		defer reader.Close()
		data, err := io.ReadAll(reader)
		require.NoError(t, err)
		assert.Equal(t, []byte("original"), data)
	})

	t.Run("returns error for non-existent object", func(t *testing.T) {
		client := NewMemoryClient()
		adapter := NewObjStoreAdapter(client)
		ctx := context.Background()

		err := adapter.UpdateMetadata(ctx, "missing", &xkmssdk.ObjectMetadata{})
		assert.Error(t, err)
	})
}

func TestObjStoreAdapter_Delete(t *testing.T) {
	t.Run("deletes existing object", func(t *testing.T) {
		client := NewMemoryClient()
		adapter := NewObjStoreAdapter(client)

		err := adapter.Put("del-test", bytes.NewReader([]byte("data")))
		require.NoError(t, err)

		err = adapter.Delete("del-test")
		require.NoError(t, err)
	})

	t.Run("delete non-existent returns error", func(t *testing.T) {
		client := NewMemoryClient()
		adapter := NewObjStoreAdapter(client)

		err := adapter.Delete("missing")
		assert.Error(t, err)
	})
}

func TestObjStoreAdapter_DeleteWithContext(t *testing.T) {
	client := NewMemoryClient()
	adapter := NewObjStoreAdapter(client)
	ctx := context.Background()

	err := adapter.PutWithContext(ctx, "del-ctx", bytes.NewReader([]byte("data")))
	require.NoError(t, err)

	err = adapter.DeleteWithContext(ctx, "del-ctx")
	require.NoError(t, err)
}

func TestObjStoreAdapter_Exists(t *testing.T) {
	t.Run("returns true for existing object", func(t *testing.T) {
		client := NewMemoryClient()
		adapter := NewObjStoreAdapter(client)
		ctx := context.Background()

		err := adapter.Put("exist-test", bytes.NewReader([]byte("data")))
		require.NoError(t, err)

		exists, err := adapter.Exists(ctx, "exist-test")
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("returns false for non-existent object", func(t *testing.T) {
		client := NewMemoryClient()
		adapter := NewObjStoreAdapter(client)
		ctx := context.Background()

		exists, err := adapter.Exists(ctx, "missing")
		require.NoError(t, err)
		assert.False(t, exists)
	})
}

func TestObjStoreAdapter_List(t *testing.T) {
	t.Run("lists objects by prefix", func(t *testing.T) {
		client := NewMemoryClient()
		adapter := NewObjStoreAdapter(client)

		err := adapter.Put("list/a.txt", bytes.NewReader([]byte("a")))
		require.NoError(t, err)
		err = adapter.Put("list/b.txt", bytes.NewReader([]byte("b")))
		require.NoError(t, err)
		err = adapter.Put("other/c.txt", bytes.NewReader([]byte("c")))
		require.NoError(t, err)

		keys, err := adapter.List("list")
		require.NoError(t, err)
		assert.Len(t, keys, 2)
	})

	t.Run("empty prefix lists all", func(t *testing.T) {
		client := NewMemoryClient()
		adapter := NewObjStoreAdapter(client)

		err := adapter.Put("x.txt", bytes.NewReader([]byte("x")))
		require.NoError(t, err)

		keys, err := adapter.List("")
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(keys), 1)
	})
}

func TestObjStoreAdapter_ListWithContext(t *testing.T) {
	client := NewMemoryClient()
	adapter := NewObjStoreAdapter(client)
	ctx := context.Background()

	err := adapter.PutWithContext(ctx, "lctx/a", bytes.NewReader([]byte("a")))
	require.NoError(t, err)

	keys, err := adapter.ListWithContext(ctx, "lctx")
	require.NoError(t, err)
	assert.Len(t, keys, 1)
}

func TestObjStoreAdapter_ListWithOptions(t *testing.T) {
	t.Run("with options", func(t *testing.T) {
		client := NewMemoryClient()
		adapter := NewObjStoreAdapter(client)
		ctx := context.Background()

		err := adapter.Put("opts/1.txt", bytes.NewReader([]byte("1")))
		require.NoError(t, err)
		err = adapter.Put("opts/2.txt", bytes.NewReader([]byte("2")))
		require.NoError(t, err)

		result, err := adapter.ListWithOptions(ctx, &xkmssdk.ObjectListOptions{
			Prefix:     "platform:opts",
			MaxResults: 10,
		})
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.NotNil(t, result.Objects)
	})

	t.Run("with nil options", func(t *testing.T) {
		client := NewMemoryClient()
		adapter := NewObjStoreAdapter(client)
		ctx := context.Background()

		result, err := adapter.ListWithOptions(ctx, nil)
		require.NoError(t, err)
		assert.NotNil(t, result)
	})
}

func TestObjStoreAdapter_Archive(t *testing.T) {
	client := NewMemoryClient()
	adapter := NewObjStoreAdapter(client)

	err := adapter.Archive("test", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "archive not supported")
}

func TestObjStoreAdapter_Policies(t *testing.T) {
	client := NewMemoryClient()
	adapter := NewObjStoreAdapter(client)

	t.Run("AddPolicy is no-op", func(t *testing.T) {
		err := adapter.AddPolicy(xkmssdk.ObjectLifecyclePolicy{})
		require.NoError(t, err)
	})

	t.Run("RemovePolicy is no-op", func(t *testing.T) {
		err := adapter.RemovePolicy("some-id")
		require.NoError(t, err)
	})

	t.Run("GetPolicies returns nil", func(t *testing.T) {
		policies, err := adapter.GetPolicies()
		require.NoError(t, err)
		assert.Nil(t, policies)
	})
}

func TestObjStoreAdapter_CompileTimeInterface(t *testing.T) {
	var _ xkmssdk.ObjectStorage = (*ObjStoreAdapter)(nil)
}

func TestObjectStoreWithTenant(t *testing.T) {
	t.Run("creates tenant store successfully", func(t *testing.T) {
		logger := logging.DefaultLogger()
		storage := NewMemoryClient()

		store, err := NewObjectStoreWithTenant(logger, storage, "tmp/testdata", nil, "tenant-1")
		require.NoError(t, err)
		require.NotNil(t, store)

		// Save and retrieve via tenant store
		err = store.Save([]byte("tenant-file.txt"), []byte("tenant-data"))
		require.NoError(t, err)

		data, err := store.Get([]byte("tenant-file.txt"))
		require.NoError(t, err)
		assert.Equal(t, []byte("tenant-data"), data)
	})

	t.Run("nil storage returns error", func(t *testing.T) {
		logger := logging.DefaultLogger()

		_, err := NewObjectStoreWithTenant(logger, nil, "tmp/testdata", nil, "tenant-1")
		assert.ErrorIs(t, err, ErrStorageNil)
	})
}

func TestIsNotFoundError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil error", nil, false},
		{"ErrObjectNotFound sentinel", ErrObjectNotFound, true},
		{"contains not found", errors.New("key not found in store"), true},
		{"contains does not exist", errors.New("object does not exist"), true},
		{"contains no such file", errors.New("no such file or directory"), true},
		{"contains NoSuchKey", errors.New("NoSuchKey"), true},
		{"contains 404", errors.New("status 404"), true},
		{"unrelated error", errors.New("connection refused"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isNotFoundError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestObjectStoreListWithPrefix(t *testing.T) {
	store := createStore(t)

	err := store.Save([]byte("prefix_test/a.txt"), []byte("a"))
	require.NoError(t, err)
	err = store.Save([]byte("prefix_test/b.txt"), []byte("b"))
	require.NoError(t, err)
	err = store.Save([]byte("other/c.txt"), []byte("c"))
	require.NoError(t, err)

	keys, err := store.List("prefix_test")
	require.NoError(t, err)
	assert.Len(t, keys, 2)
}
