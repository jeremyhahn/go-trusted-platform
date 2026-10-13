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

import (
	"cmp"
	"sync"
)

// keyLock serialises the multi-step lease operations for one
// (tenant, device): admit's find-replace-allocate-install-put sequence,
// renew's get-verify-put, and revoke. Without it two concurrent admissions
// for the same device could both observe "no lease", both install a peer,
// and leave one peer and one address orphaned. Locks are reference-counted
// so the map does not grow with every device ever seen.
type keyLock struct {
	mu    sync.Mutex
	locks map[peerKey]*keyLockEntry
}

type keyLockEntry struct {
	mu   sync.Mutex
	refs int
}

func newKeyLock() *keyLock {
	return &keyLock{locks: make(map[peerKey]*keyLockEntry)}
}

// lock acquires the entry for key and returns its unlock function.
func (k *keyLock) lock(key peerKey) func() {
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

// peerKey identifies one peer, a (tenant, device) pair. The fields stay
// separate so no choice of IDs can make two peers share a key, as a joined
// string would: ("a/b", "c") and ("a", "b/c") both join to "a/b/c".
type peerKey struct {
	tenantID string
	deviceID string
}

func deviceKey(tenantID, deviceID string) peerKey {
	return peerKey{tenantID: tenantID, deviceID: deviceID}
}

// compare orders keys by tenant, then device.
func (k peerKey) compare(other peerKey) int {
	return cmp.Or(cmp.Compare(k.tenantID, other.tenantID), cmp.Compare(k.deviceID, other.deviceID))
}
