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
