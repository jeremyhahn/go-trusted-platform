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

package ipxe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
)

// IPAllocator defines the interface for IP address allocation.
// This allows swapping between the simple built-in allocator and IPAM-backed allocation.
type IPAllocator interface {
	// Allocate allocates an IP for the given MAC address.
	Allocate(ctx context.Context, mac net.HardwareAddr, hostname string) (net.IP, error)

	// Release releases an IP lease.
	Release(ctx context.Context, mac net.HardwareAddr) error

	// GetLease gets the current lease for a MAC address.
	GetLease(ctx context.Context, mac net.HardwareAddr) (*lease, error)

	// Renew renews a lease.
	Renew(ctx context.Context, mac net.HardwareAddr) error
}

// InMemoryAllocator is an in-memory lease table and allocates IPs sequentially from a range.
// It is useful for testing and standalone PXE boot scenarios without an external IPAM backend.
type InMemoryAllocator struct {
	leases     map[string]*lease
	nextIP     net.IP
	rangeStart net.IP
	rangeEnd   net.IP
	leaseTime  time.Duration
	mu         sync.RWMutex
}

// NewInMemoryAllocator creates an in-memory IP allocator.
func NewInMemoryAllocator(rangeStart, rangeEnd net.IP, leaseTime time.Duration) *InMemoryAllocator {
	startIP := make(net.IP, len(rangeStart))
	copy(startIP, rangeStart)

	return &InMemoryAllocator{
		leases:     make(map[string]*lease),
		nextIP:     startIP,
		rangeStart: rangeStart,
		rangeEnd:   rangeEnd,
		leaseTime:  leaseTime,
	}
}

// Allocate allocates an IP address for the given MAC.
func (a *InMemoryAllocator) Allocate(ctx context.Context, mac net.HardwareAddr, hostname string) (net.IP, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	macStr := mac.String()

	// Check if we have an existing valid lease
	if l, exists := a.leases[macStr]; exists {
		if time.Now().Before(l.ExpiresAt) {
			return l.IP, nil
		}
		// Lease expired, remove it
		delete(a.leases, macStr)
	}

	// Find an available IP
	ip := a.findAvailableIP()
	if ip == nil {
		return nil, ErrNoAvailableIPs
	}

	// Create lease
	a.leases[macStr] = &lease{
		IP:        ip,
		MAC:       mac,
		ExpiresAt: time.Now().Add(a.leaseTime),
	}

	return ip, nil
}

// Release releases a lease for the given MAC address.
func (a *InMemoryAllocator) Release(ctx context.Context, mac net.HardwareAddr) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	macStr := mac.String()
	delete(a.leases, macStr)
	return nil
}

// GetLease gets the current lease for a MAC address.
func (a *InMemoryAllocator) GetLease(ctx context.Context, mac net.HardwareAddr) (*lease, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	macStr := mac.String()
	if l, exists := a.leases[macStr]; exists {
		if time.Now().Before(l.ExpiresAt) {
			// Return a copy to prevent external modification
			leaseCopy := &lease{
				IP:        make(net.IP, len(l.IP)),
				MAC:       make(net.HardwareAddr, len(l.MAC)),
				ExpiresAt: l.ExpiresAt,
			}
			copy(leaseCopy.IP, l.IP)
			copy(leaseCopy.MAC, l.MAC)
			return leaseCopy, nil
		}
	}
	return nil, ErrNoAvailableIPs
}

// Renew renews a lease for the given MAC address.
func (a *InMemoryAllocator) Renew(ctx context.Context, mac net.HardwareAddr) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	macStr := mac.String()
	l, exists := a.leases[macStr]
	if !exists {
		return ErrLeaseNotFound
	}

	l.ExpiresAt = time.Now().Add(a.leaseTime)
	return nil
}

// findAvailableIP finds an available IP address in the configured range.
// Must be called with lock held.
func (a *InMemoryAllocator) findAvailableIP() net.IP {
	// Start from nextIP
	current := make(net.IP, len(a.nextIP))
	copy(current, a.nextIP)

	// Search for available IP
	for compareIPs(current, a.rangeEnd) <= 0 {
		// Check if IP is in use
		inUse := false
		for _, l := range a.leases {
			if l.IP.Equal(current) && time.Now().Before(l.ExpiresAt) {
				inUse = true
				break
			}
		}

		if !inUse {
			// Found available IP, update nextIP for next search
			a.nextIP = incrementIP(current)
			if compareIPs(a.nextIP, a.rangeEnd) > 0 {
				a.nextIP = make(net.IP, len(a.rangeStart))
				copy(a.nextIP, a.rangeStart)
			}
			return current
		}

		current = incrementIP(current)
	}

	// Wrap around to start of range
	current = make(net.IP, len(a.rangeStart))
	copy(current, a.rangeStart)

	for compareIPs(current, a.nextIP) < 0 {
		// Check if IP is in use
		inUse := false
		for _, l := range a.leases {
			if l.IP.Equal(current) && time.Now().Before(l.ExpiresAt) {
				inUse = true
				break
			}
		}

		if !inUse {
			a.nextIP = incrementIP(current)
			return current
		}

		current = incrementIP(current)
	}

	return nil
}

// IPAMAllocator wraps pkg/ipam for use with the PXE DHCP server.
// It provides IPAM-backed IP allocation with local caching for quick lookups.
type IPAMAllocator struct {
	allocator ipam.Allocator
	poolID    string
	leaseTime time.Duration
	leases    map[string]*lease // Local cache for quick lookups
	mu        sync.RWMutex
}

// NewIPAMAllocator creates an allocator backed by pkg/ipam.
func NewIPAMAllocator(allocator ipam.Allocator, poolID string, leaseTime time.Duration) (*IPAMAllocator, error) {
	if allocator == nil {
		return nil, &SentinelCauseError{Sentinel: ErrInvalidConfig, Cause: &MessageError{Msg: "allocator is required"}}
	}
	if poolID == "" {
		return nil, &SentinelCauseError{Sentinel: ErrInvalidConfig, Cause: &MessageError{Msg: "pool ID is required"}}
	}

	return &IPAMAllocator{
		allocator: allocator,
		poolID:    poolID,
		leaseTime: leaseTime,
		leases:    make(map[string]*lease),
	}, nil
}

// Allocate allocates an IP from the IPAM pool.
func (a *IPAMAllocator) Allocate(ctx context.Context, mac net.HardwareAddr, hostname string) (net.IP, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	macStr := mac.String()

	// Check local cache first
	if l, exists := a.leases[macStr]; exists && time.Now().Before(l.ExpiresAt) {
		// Renew the IPAM allocation
		addr, err := netip.ParseAddr(l.IP.String())
		if err == nil {
			_ = a.allocator.Renew(ctx, addr)
		}
		return l.IP, nil
	}

	// Allocate from IPAM
	allocation, err := a.allocator.Allocate(ctx, &ipam.AllocationRequest{
		PoolID:   a.poolID,
		DeviceID: macStr,
		Hostname: hostname,
		Metadata: map[string]string{
			"type":   "pxe",
			"source": "dhcp",
		},
		LeaseDuration: a.leaseTime,
	})
	if err != nil {
		// Map IPAM errors to ipxe errors
		if errors.Is(err, ipam.ErrPoolExhausted) {
			return nil, ErrNoAvailableIPs
		}
		return nil, &ErrIPAMAllocationFailed{
			PoolID: a.poolID,
			MAC:    macStr,
			Cause:  err,
		}
	}

	// Convert netip.Addr to net.IP
	ip := net.ParseIP(allocation.IP.String())
	if ip == nil {
		return nil, &ErrIPAMInvalidIP{
			IP:     allocation.IP.String(),
			Reason: "failed to parse IP from IPAM allocation",
		}
	}

	// Ensure we have IPv4 format
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}

	// Cache locally
	a.leases[macStr] = &lease{
		IP:        ip,
		MAC:       mac,
		ExpiresAt: time.Now().Add(a.leaseTime),
	}

	return ip, nil
}

// Release releases an IP back to IPAM.
func (a *IPAMAllocator) Release(ctx context.Context, mac net.HardwareAddr) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	macStr := mac.String()
	l, exists := a.leases[macStr]
	if !exists {
		return nil // No lease to release
	}

	// Release in IPAM
	addr, err := netip.ParseAddr(l.IP.String())
	if err != nil {
		return &ErrIPAMInvalidIP{
			IP:     l.IP.String(),
			Reason: "failed to parse IP for release",
		}
	}

	if err := a.allocator.Release(ctx, addr); err != nil {
		// Don't fail if allocation not found - it may have already been released
		if !errors.Is(err, ipam.ErrAllocationNotFound) {
			return &ErrIPAMReleaseFailed{
				IP:    l.IP.String(),
				MAC:   macStr,
				Cause: err,
			}
		}
	}

	delete(a.leases, macStr)
	return nil
}

// GetLease gets the current lease for a MAC address.
func (a *IPAMAllocator) GetLease(ctx context.Context, mac net.HardwareAddr) (*lease, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	macStr := mac.String()
	l, exists := a.leases[macStr]
	if !exists {
		return nil, ErrLeaseNotFound
	}

	if time.Now().After(l.ExpiresAt) {
		return nil, ErrLeaseExpired
	}

	// Return a copy to prevent external modification
	leaseCopy := &lease{
		IP:        make(net.IP, len(l.IP)),
		MAC:       make(net.HardwareAddr, len(l.MAC)),
		ExpiresAt: l.ExpiresAt,
	}
	copy(leaseCopy.IP, l.IP)
	copy(leaseCopy.MAC, l.MAC)
	return leaseCopy, nil
}

// Renew renews a lease in IPAM.
func (a *IPAMAllocator) Renew(ctx context.Context, mac net.HardwareAddr) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	macStr := mac.String()
	l, exists := a.leases[macStr]
	if !exists {
		return ErrLeaseNotFound
	}

	// Renew in IPAM
	addr, err := netip.ParseAddr(l.IP.String())
	if err != nil {
		return &ErrIPAMInvalidIP{
			IP:     l.IP.String(),
			Reason: "failed to parse IP for renewal",
		}
	}

	if err := a.allocator.Renew(ctx, addr); err != nil {
		// If the allocation expired in IPAM, try to reallocate
		if errors.Is(err, ipam.ErrAllocationExpired) || errors.Is(err, ipam.ErrAllocationNotFound) {
			return ErrLeaseExpired
		}
		return &ErrIPAMRenewFailed{
			IP:    l.IP.String(),
			MAC:   macStr,
			Cause: err,
		}
	}

	l.ExpiresAt = time.Now().Add(a.leaseTime)
	return nil
}

// PoolID returns the IPAM pool ID used by this allocator.
func (a *IPAMAllocator) PoolID() string {
	return a.poolID
}

// LeaseCount returns the number of active leases in the local cache.
func (a *IPAMAllocator) LeaseCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()

	count := 0
	now := time.Now()
	for _, l := range a.leases {
		if now.Before(l.ExpiresAt) {
			count++
		}
	}
	return count
}

// SyncFromIPAM synchronizes the local cache from IPAM allocations.
// This is useful for recovering state after a restart.
func (a *IPAMAllocator) SyncFromIPAM(ctx context.Context) error {
	allocations, err := a.allocator.GetAllocationsByPool(ctx, a.poolID)
	if err != nil {
		return &WrappedError{Msg: "failed to get allocations from IPAM", Err: err}
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Clear existing cache
	a.leases = make(map[string]*lease)

	// Populate from IPAM allocations
	for _, alloc := range allocations {
		if alloc.Status != ipam.AllocationStatusActive {
			continue
		}

		mac, err := net.ParseMAC(alloc.DeviceID)
		if err != nil {
			// Skip non-MAC device IDs
			continue
		}

		ip := net.ParseIP(alloc.IP.String())
		if ip == nil {
			continue
		}

		// Use IPv4 format if applicable
		if ip4 := ip.To4(); ip4 != nil {
			ip = ip4
		}

		expiresAt := alloc.ExpiresAt
		if expiresAt.IsZero() {
			// No expiration set, use default lease time from now
			expiresAt = time.Now().Add(a.leaseTime)
		}

		a.leases[mac.String()] = &lease{
			IP:        ip,
			MAC:       mac,
			ExpiresAt: expiresAt,
		}
	}

	return nil
}
