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

package vpn

import "sync"

// keyLock serialises the multi-step lease operations for one
// (tenant, device): admit's find-replace-allocate-install-put sequence,
// renew's get-verify-put, and revoke. Without it two concurrent admissions
// for the same device could both observe "no lease", both install a peer,
// and leave one peer and one address orphaned. Locks are reference-counted
// so the map does not grow with every device ever seen.
type keyLock struct {
	mu    sync.Mutex
	locks map[string]*keyLockEntry
}

type keyLockEntry struct {
	mu   sync.Mutex
	refs int
}

func newKeyLock() *keyLock {
	return &keyLock{locks: make(map[string]*keyLockEntry)}
}

// lock acquires the entry for key and returns its unlock function.
func (k *keyLock) lock(key string) func() {
	k.mu.Lock()
	e, ok := k.locks[key]
	if !ok {
		e = &keyLockEntry{}
		k.locks[key] = e
	}
	e.refs++
	k.mu.Unlock()

	e.mu.Lock()
	return func() {
		e.mu.Unlock()
		k.mu.Lock()
		e.refs--
		if e.refs == 0 {
			delete(k.locks, key)
		}
		k.mu.Unlock()
	}
}

func deviceKey(tenantID, deviceID string) string {
	return tenantID + "/" + deviceID
}
