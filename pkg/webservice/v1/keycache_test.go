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

package v1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKeyCache(t *testing.T) {
	cache := newKeyCache()
	require.NotNil(t, cache)
	assert.NotNil(t, cache.keys)
	assert.Equal(t, 0, len(cache.keys))
}

func TestKeyCache_Put(t *testing.T) {
	t.Run("stores RSA key", func(t *testing.T) {
		cache := newKeyCache()
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		cache.put("test-rsa", &key.PublicKey)

		storedKey := cache.keys["test-rsa"]
		require.NotNil(t, storedKey)
		assert.IsType(t, &rsa.PublicKey{}, storedKey)
	})

	t.Run("stores ECDSA key", func(t *testing.T) {
		cache := newKeyCache()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		cache.put("test-ecdsa", &key.PublicKey)

		storedKey := cache.keys["test-ecdsa"]
		require.NotNil(t, storedKey)
		assert.IsType(t, &ecdsa.PublicKey{}, storedKey)
	})

	t.Run("overwrites existing key", func(t *testing.T) {
		cache := newKeyCache()
		key1, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		key2, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		cache.put("test-key", &key1.PublicKey)
		cache.put("test-key", &key2.PublicKey)

		storedKey := cache.keys["test-key"]
		require.NotNil(t, storedKey)
		assert.Equal(t, &key2.PublicKey, storedKey)
	})

	t.Run("stores multiple keys", func(t *testing.T) {
		cache := newKeyCache()
		key1, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		cache.put("key1", &key1.PublicKey)
		cache.put("key2", &key2.PublicKey)

		assert.Equal(t, 2, len(cache.keys))
		assert.NotNil(t, cache.keys["key1"])
		assert.NotNil(t, cache.keys["key2"])
	})
}

func TestKeyCache_Key(t *testing.T) {
	t.Run("retrieves stored key", func(t *testing.T) {
		cache := newKeyCache()
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		cache.put("test-key", &key.PublicKey)
		retrievedKey := cache.key("test-key")

		require.NotNil(t, retrievedKey)
		assert.Equal(t, &key.PublicKey, retrievedKey)
	})

	t.Run("returns nil for non-existent key", func(t *testing.T) {
		cache := newKeyCache()
		retrievedKey := cache.key("non-existent")

		assert.Nil(t, retrievedKey)
	})

	t.Run("retrieves correct key from multiple keys", func(t *testing.T) {
		cache := newKeyCache()
		key1, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		key2, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		cache.put("key1", &key1.PublicKey)
		cache.put("key2", &key2.PublicKey)

		retrievedKey1 := cache.key("key1")
		retrievedKey2 := cache.key("key2")

		assert.Equal(t, &key1.PublicKey, retrievedKey1)
		assert.Equal(t, &key2.PublicKey, retrievedKey2)
		assert.NotEqual(t, retrievedKey1, retrievedKey2)
	})
}

func TestKeyCache_ThreadSafety(t *testing.T) {
	// One RSA key, copied per goroutine: the cache stores pointers, so each
	// copy is a distinct entry, without paying for a key generation per writer.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	t.Run("concurrent writes", func(t *testing.T) {
		cache := newKeyCache()
		var wg sync.WaitGroup

		// Start 100 goroutines writing different keys
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				pub := key.PublicKey
				cache.put(string(rune('a'+id%26))+string(rune('0'+id/26)), &pub)
			}(i)
		}

		wg.Wait()

		// Verify all keys were stored
		assert.Equal(t, 100, len(cache.keys))
	})

	t.Run("concurrent reads", func(t *testing.T) {
		cache := newKeyCache()
		cache.put("test-key", &key.PublicKey)

		var wg sync.WaitGroup
		results := make([]bool, 100)
		mu := sync.Mutex{}

		// Start 100 goroutines reading the same key
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				retrievedKey := cache.key("test-key")
				mu.Lock()
				results[idx] = retrievedKey != nil && retrievedKey == &key.PublicKey
				mu.Unlock()
			}(i)
		}

		wg.Wait()

		// Verify all reads were successful
		for i, result := range results {
			assert.True(t, result, "read %d failed", i)
		}
	})

	t.Run("concurrent reads and writes", func(t *testing.T) {
		cache := newKeyCache()
		var wg sync.WaitGroup

		// Writers
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				pub := key.PublicKey
				cache.put(string(rune('w'+id%20)), &pub)
			}(i)
		}

		// Readers
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				cache.key(string(rune('w' + id%20)))
			}(i)
		}

		wg.Wait()

		// No panic means thread safety is working
		assert.True(t, true)
	})

	t.Run("concurrent overwrites of same key", func(t *testing.T) {
		cache := newKeyCache()
		var wg sync.WaitGroup

		// Start 100 goroutines overwriting the same key
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				pub := key.PublicKey
				cache.put("contested-key", &pub)
			}()
		}

		wg.Wait()

		// Verify the key exists and is one of the written keys
		finalKey := cache.key("contested-key")
		assert.NotNil(t, finalKey)
	})
}

func TestKeyCache_GlobalInstance(t *testing.T) {
	t.Run("global cache is initialized", func(t *testing.T) {
		assert.NotNil(t, cache)
		assert.NotNil(t, cache.keys)
	})

	t.Run("global cache operations work", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		cache.put("global-test", &key.PublicKey)
		retrievedKey := cache.key("global-test")

		assert.Equal(t, &key.PublicKey, retrievedKey)
	})
}

func TestKeyCache_EdgeCases(t *testing.T) {
	t.Run("empty key id", func(t *testing.T) {
		cache := newKeyCache()
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		cache.put("", &key.PublicKey)
		retrievedKey := cache.key("")

		assert.Equal(t, &key.PublicKey, retrievedKey)
	})

	t.Run("nil key value", func(t *testing.T) {
		cache := newKeyCache()

		cache.put("nil-key", nil)
		retrievedKey := cache.key("nil-key")

		assert.Nil(t, retrievedKey)
	})

	t.Run("special characters in key id", func(t *testing.T) {
		cache := newKeyCache()
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		specialIDs := []string{
			"key-with-dashes",
			"key.with.dots",
			"key_with_underscores",
			"key@with#special$chars",
			"key with spaces",
			"🔑unicode-key",
		}

		for _, id := range specialIDs {
			cache.put(id, &key.PublicKey)
			retrievedKey := cache.key(id)
			assert.NotNil(t, retrievedKey, "failed for id: %s", id)
		}
	})

	t.Run("long key id", func(t *testing.T) {
		cache := newKeyCache()
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		longID := string(make([]byte, 1000))
		cache.put(longID, &key.PublicKey)
		retrievedKey := cache.key(longID)

		assert.Equal(t, &key.PublicKey, retrievedKey)
	})
}
