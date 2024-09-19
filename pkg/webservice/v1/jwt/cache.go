package jwt

import (
	"crypto"
	"sync"
)

var cache = newKeyCache()

type keyCache struct {
	keys  map[string]crypto.PublicKey
	mutex sync.RWMutex
}

func newKeyCache() *keyCache {
	return &keyCache{
		keys: make(map[string]crypto.PublicKey),
	}
}

func (cache *keyCache) put(id string, key crypto.PublicKey) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	cache.keys[id] = key
}

func (cache *keyCache) key(id string) crypto.PublicKey {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()
	return cache.keys[id]
}
