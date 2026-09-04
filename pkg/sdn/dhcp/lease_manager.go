// Copyright (c) 2025 Jeremy Hahn. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package dhcp

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// LeaseStore manages DHCP leases in memory.
// It is safe for concurrent use and provides O(1) lookup by IP or MAC.
type LeaseStore struct {
	leasesByIP  sync.Map // netip.Addr -> *Lease
	leasesByMAC sync.Map // string (MAC string) -> *Lease
	closed      atomic.Bool
}

// NewLeaseStore creates a new lease store.
func NewLeaseStore() *LeaseStore {
	return &LeaseStore{}
}

// Add adds or updates a lease.
func (m *LeaseStore) Add(lease *Lease) error {
	if m.closed.Load() {
		return ErrPluginClosed
	}
	if lease == nil {
		return ErrNilRequest
	}
	if !lease.IP.IsValid() {
		return ErrInvalidIP
	}
	if len(lease.MAC) == 0 {
		return ErrInvalidMAC
	}

	// Store by IP and MAC
	m.leasesByIP.Store(lease.IP, lease.Clone())
	m.leasesByMAC.Store(lease.MAC.String(), lease.Clone())
	return nil
}

// GetByIP retrieves a lease by IP address.
//
// The returned *Lease is a clone, so a caller cannot reach the stored struct.
// That is necessary and NOT sufficient: Clone reads the stored struct, so it
// still races anything that writes it. The mutators (Set, SetState, Renew)
// publish new *Lease values rather than writing stored ones for that reason —
// their copy-on-write is not made redundant by the clone here. See #40.
func (m *LeaseStore) GetByIP(ip netip.Addr) (*Lease, bool) {
	if m.closed.Load() {
		return nil, false
	}
	if !ip.IsValid() {
		return nil, false
	}
	value, ok := m.leasesByIP.Load(ip)
	if !ok {
		return nil, false
	}
	lease := value.(*Lease)
	return lease.Clone(), true
}

// GetByMAC retrieves a lease by MAC address.
//
// Returns a clone, with the same caveat as GetByIP: cloning on read does not
// remove the need for copy-on-write in the mutators. See #40.
func (m *LeaseStore) GetByMAC(mac net.HardwareAddr) (*Lease, bool) {
	if m.closed.Load() {
		return nil, false
	}
	if len(mac) == 0 {
		return nil, false
	}
	value, ok := m.leasesByMAC.Load(mac.String())
	if !ok {
		return nil, false
	}
	lease := value.(*Lease)
	return lease.Clone(), true
}

// Remove removes a lease by IP address.
func (m *LeaseStore) Remove(ip netip.Addr) error {
	if m.closed.Load() {
		return ErrPluginClosed
	}
	if !ip.IsValid() {
		return ErrInvalidIP
	}

	value, ok := m.leasesByIP.Load(ip)
	if !ok {
		return ErrLeaseNotFound
	}

	lease := value.(*Lease)
	m.leasesByIP.Delete(ip)
	m.leasesByMAC.Delete(lease.MAC.String())
	return nil
}

// RemoveByMAC removes a lease by MAC address.
func (m *LeaseStore) RemoveByMAC(mac net.HardwareAddr) error {
	if m.closed.Load() {
		return ErrPluginClosed
	}
	if len(mac) == 0 {
		return ErrInvalidMAC
	}

	value, ok := m.leasesByMAC.Load(mac.String())
	if !ok {
		return ErrLeaseNotFound
	}

	lease := value.(*Lease)
	m.leasesByIP.Delete(lease.IP)
	m.leasesByMAC.Delete(mac.String())
	return nil
}

// Renew extends the lease expiration time.
func (m *LeaseStore) Renew(ip netip.Addr, duration time.Duration) error {
	if m.closed.Load() {
		return ErrPluginClosed
	}
	if !ip.IsValid() {
		return ErrInvalidIP
	}

	value, ok := m.leasesByIP.Load(ip)
	if !ok {
		return ErrLeaseNotFound
	}

	lease := value.(*Lease)
	if lease.IsExpired() {
		return ErrLeaseExpired
	}

	// Copy-on-write, for the same reason as SetState above: this wrote two
	// fields of a shared struct in place.
	now := time.Now()
	updated := lease.Clone()
	updated.RenewedAt = now
	updated.ExpiresAt = now.Add(duration)

	// Update both maps
	m.leasesByIP.Store(ip, updated)
	m.leasesByMAC.Store(updated.MAC.String(), updated)
	return nil
}

// SetState updates the state of a lease.
func (m *LeaseStore) SetState(ip netip.Addr, state LeaseState) error {
	if m.closed.Load() {
		return ErrPluginClosed
	}
	if !ip.IsValid() {
		return ErrInvalidIP
	}

	value, ok := m.leasesByIP.Load(ip)
	if !ok {
		return ErrLeaseNotFound
	}

	// Copy-on-write. sync.Map makes the MAP safe for concurrent use; it says
	// nothing about the struct a stored pointer points at. Mutating that struct
	// in place raced against every reader reaching it through GetByIP/GetByMAC,
	// which hand it to Lease.Clone -- a full-struct read. Publishing a fresh
	// Lease instead means no goroutine ever writes memory another is reading.
	//
	// Returning clones from the getters is NOT sufficient on its own: the clone
	// itself reads the shared struct, so the read still races the write. The
	// write has to go. See #40.
	updated := value.(*Lease).Clone()
	updated.State = state

	// Update both maps
	m.leasesByIP.Store(ip, updated)
	m.leasesByMAC.Store(updated.MAC.String(), updated)
	return nil
}

// ExpireOld removes leases that have expired.
// Returns the number of leases removed.
func (m *LeaseStore) ExpireOld() int {
	if m.closed.Load() {
		return 0
	}

	var expired []netip.Addr
	m.leasesByIP.Range(func(key, value any) bool {
		lease := value.(*Lease)
		if lease.IsExpired() {
			expired = append(expired, key.(netip.Addr))
		}
		return true
	})

	for _, ip := range expired {
		_ = m.Remove(ip)
	}
	return len(expired)
}

// Count returns the number of leases (including expired).
func (m *LeaseStore) Count() int {
	if m.closed.Load() {
		return 0
	}

	count := 0
	m.leasesByIP.Range(func(key, value any) bool {
		count++
		return true
	})
	return count
}

// CountActive returns the number of active (non-expired) leases.
func (m *LeaseStore) CountActive() int {
	if m.closed.Load() {
		return 0
	}

	count := 0
	m.leasesByIP.Range(func(key, value any) bool {
		lease := value.(*Lease)
		if lease.IsActive() {
			count++
		}
		return true
	})
	return count
}

// All returns all leases.
func (m *LeaseStore) All() []*Lease {
	if m.closed.Load() {
		return nil
	}

	var leases []*Lease
	m.leasesByIP.Range(func(key, value any) bool {
		lease := value.(*Lease)
		leases = append(leases, lease.Clone())
		return true
	})
	return leases
}

// AllActive returns all active leases.
func (m *LeaseStore) AllActive() []*Lease {
	if m.closed.Load() {
		return nil
	}

	var leases []*Lease
	m.leasesByIP.Range(func(key, value any) bool {
		lease := value.(*Lease)
		if lease.IsActive() {
			leases = append(leases, lease.Clone())
		}
		return true
	})
	return leases
}

// Clear removes all leases.
func (m *LeaseStore) Clear() {
	if m.closed.Load() {
		return
	}

	m.leasesByIP.Range(func(key, value any) bool {
		m.leasesByIP.Delete(key)
		return true
	})
	m.leasesByMAC.Range(func(key, value any) bool {
		m.leasesByMAC.Delete(key)
		return true
	})
}

// Close closes the lease store.
func (m *LeaseStore) Close() error {
	if m.closed.CompareAndSwap(false, true) {
		m.Clear()
		return nil
	}
	return ErrPluginClosed
}
