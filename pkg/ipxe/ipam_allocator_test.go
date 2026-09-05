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
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockIPAMAllocator implements ipam.Allocator for testing.
type mockIPAMAllocator struct {
	mu            sync.RWMutex
	allocations   map[string]*ipam.Allocation
	nextIP        netip.Addr
	poolID        string
	allocateErr   error
	releaseErr    error
	renewErr      error
	exhausted     bool
	renewCalled   int
	allocateCalls int
}

func newMockIPAMAllocator(poolID string, startIP netip.Addr) *mockIPAMAllocator {
	return &mockIPAMAllocator{
		allocations: make(map[string]*ipam.Allocation),
		nextIP:      startIP,
		poolID:      poolID,
	}
}

func (m *mockIPAMAllocator) CreatePool(ctx context.Context, pool *ipam.Pool) error {
	return nil
}

func (m *mockIPAMAllocator) GetPool(ctx context.Context, poolID string) (*ipam.Pool, error) {
	return nil, nil
}

func (m *mockIPAMAllocator) GetPoolByName(ctx context.Context, name string) (*ipam.Pool, error) {
	return nil, nil
}

func (m *mockIPAMAllocator) GetPoolByCIDR(ctx context.Context, cidr netip.Prefix) (*ipam.Pool, error) {
	return nil, nil
}

func (m *mockIPAMAllocator) ListPools(ctx context.Context) ([]*ipam.Pool, error) {
	return nil, nil
}

func (m *mockIPAMAllocator) ListPoolsByZone(ctx context.Context, zone string) ([]*ipam.Pool, error) {
	return nil, nil
}

func (m *mockIPAMAllocator) UpdatePool(ctx context.Context, pool *ipam.Pool) error {
	return nil
}

func (m *mockIPAMAllocator) DeletePool(ctx context.Context, poolID string) error {
	return nil
}

func (m *mockIPAMAllocator) GetPoolStats(ctx context.Context, poolID string) (*ipam.PoolStats, error) {
	return nil, nil
}

func (m *mockIPAMAllocator) Allocate(ctx context.Context, req *ipam.AllocationRequest) (*ipam.Allocation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.allocateCalls++

	if m.allocateErr != nil {
		return nil, m.allocateErr
	}

	if m.exhausted {
		return nil, ipam.ErrPoolExhausted
	}

	// Check if device already has an allocation
	for _, alloc := range m.allocations {
		if alloc.DeviceID == req.DeviceID && alloc.Status == ipam.AllocationStatusActive {
			return alloc, nil
		}
	}

	// Allocate new IP
	ip := m.nextIP
	m.nextIP = m.nextIP.Next()

	alloc := &ipam.Allocation{
		ID:          req.DeviceID,
		PoolID:      req.PoolID,
		IP:          ip,
		DeviceID:    req.DeviceID,
		Hostname:    req.Hostname,
		Metadata:    req.Metadata,
		AllocatedAt: time.Now(),
		LastSeen:    time.Now(),
		ExpiresAt:   time.Now().Add(req.LeaseDuration),
		Status:      ipam.AllocationStatusActive,
	}

	m.allocations[ip.String()] = alloc
	return alloc, nil
}

func (m *mockIPAMAllocator) AllocateSpecific(ctx context.Context, req *ipam.AllocationRequest) (*ipam.Allocation, error) {
	return nil, nil
}

func (m *mockIPAMAllocator) Release(ctx context.Context, ip netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.releaseErr != nil {
		return m.releaseErr
	}

	alloc, exists := m.allocations[ip.String()]
	if !exists {
		return ipam.ErrAllocationNotFound
	}

	alloc.Status = ipam.AllocationStatusReleased
	alloc.ReleasedAt = time.Now()
	return nil
}

func (m *mockIPAMAllocator) ReleaseByDeviceID(ctx context.Context, deviceID string) (int, error) {
	return 0, nil
}

func (m *mockIPAMAllocator) Renew(ctx context.Context, ip netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.renewCalled++

	if m.renewErr != nil {
		return m.renewErr
	}

	alloc, exists := m.allocations[ip.String()]
	if !exists {
		return ipam.ErrAllocationNotFound
	}

	if alloc.Status != ipam.AllocationStatusActive {
		return ipam.ErrAllocationExpired
	}

	alloc.LastSeen = time.Now()
	return nil
}

func (m *mockIPAMAllocator) GetAllocation(ctx context.Context, ip netip.Addr) (*ipam.Allocation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	alloc, exists := m.allocations[ip.String()]
	if !exists {
		return nil, ipam.ErrAllocationNotFound
	}
	return alloc, nil
}

func (m *mockIPAMAllocator) GetAllocationsByDevice(ctx context.Context, deviceID string) ([]*ipam.Allocation, error) {
	return nil, nil
}

func (m *mockIPAMAllocator) GetAllocationsByPool(ctx context.Context, poolID string) ([]*ipam.Allocation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*ipam.Allocation
	for _, alloc := range m.allocations {
		if alloc.PoolID == poolID {
			result = append(result, alloc)
		}
	}
	return result, nil
}

func (m *mockIPAMAllocator) ExpireInactive(ctx context.Context, poolID string) ([]*ipam.Allocation, error) {
	return nil, nil
}

func (m *mockIPAMAllocator) Ping(ctx context.Context) error {
	return nil
}

func (m *mockIPAMAllocator) Close() error {
	return nil
}

// TestNewInMemoryAllocator tests InMemoryAllocator creation.
func TestNewInMemoryAllocator(t *testing.T) {
	rangeStart := net.ParseIP("192.168.1.100")
	rangeEnd := net.ParseIP("192.168.1.200")
	leaseTime := time.Hour

	allocator := NewInMemoryAllocator(rangeStart, rangeEnd, leaseTime)

	require.NotNil(t, allocator)
	assert.NotNil(t, allocator.leases)
	assert.Equal(t, rangeStart, allocator.rangeStart)
	assert.Equal(t, rangeEnd, allocator.rangeEnd)
	assert.Equal(t, leaseTime, allocator.leaseTime)
	assert.True(t, allocator.nextIP.Equal(rangeStart))
}

// TestInMemoryAllocator_Allocate tests IP allocation.
func TestInMemoryAllocator_Allocate(t *testing.T) {
	t.Run("allocates new IP for new MAC", func(t *testing.T) {
		allocator := NewInMemoryAllocator(
			net.ParseIP("192.168.1.100"),
			net.ParseIP("192.168.1.200"),
			time.Hour,
		)
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ctx := context.Background()

		ip, err := allocator.Allocate(ctx, mac, "host1")

		require.NoError(t, err)
		assert.True(t, ip.Equal(net.ParseIP("192.168.1.100")))
	})

	t.Run("reuses existing valid lease", func(t *testing.T) {
		allocator := NewInMemoryAllocator(
			net.ParseIP("192.168.1.100"),
			net.ParseIP("192.168.1.200"),
			time.Hour,
		)
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ctx := context.Background()

		ip1, err := allocator.Allocate(ctx, mac, "host1")
		require.NoError(t, err)

		ip2, err := allocator.Allocate(ctx, mac, "host1")
		require.NoError(t, err)

		assert.True(t, ip1.Equal(ip2))
	})

	t.Run("assigns different IPs to different MACs", func(t *testing.T) {
		allocator := NewInMemoryAllocator(
			net.ParseIP("192.168.1.100"),
			net.ParseIP("192.168.1.200"),
			time.Hour,
		)
		mac1, _ := net.ParseMAC("00:11:22:33:44:55")
		mac2, _ := net.ParseMAC("00:11:22:33:44:66")
		ctx := context.Background()

		ip1, err := allocator.Allocate(ctx, mac1, "host1")
		require.NoError(t, err)

		ip2, err := allocator.Allocate(ctx, mac2, "host2")
		require.NoError(t, err)

		assert.False(t, ip1.Equal(ip2))
	})

	t.Run("returns error when no IPs available", func(t *testing.T) {
		allocator := NewInMemoryAllocator(
			net.ParseIP("192.168.1.100"),
			net.ParseIP("192.168.1.100"), // Only 1 IP
			time.Hour,
		)
		mac1, _ := net.ParseMAC("00:11:22:33:44:55")
		mac2, _ := net.ParseMAC("00:11:22:33:44:66")
		ctx := context.Background()

		_, err := allocator.Allocate(ctx, mac1, "host1")
		require.NoError(t, err)

		_, err = allocator.Allocate(ctx, mac2, "host2")
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrNoAvailableIPs))
	})

	t.Run("reuses expired lease", func(t *testing.T) {
		allocator := NewInMemoryAllocator(
			net.ParseIP("192.168.1.100"),
			net.ParseIP("192.168.1.100"), // Only 1 IP
			time.Millisecond,
		)
		clk := newManualClock()
		allocator.clk = clk
		mac1, _ := net.ParseMAC("00:11:22:33:44:55")
		mac2, _ := net.ParseMAC("00:11:22:33:44:66")
		ctx := context.Background()

		ip1, err := allocator.Allocate(ctx, mac1, "host1")
		require.NoError(t, err)

		// Advance past the lease lifetime. The old sleep spent this duration in
		// real time; moving the clock is instant and EXACT, where a sleep only
		// guaranteed at least it (#284).
		clk.Advance(5 * time.Millisecond)

		ip2, err := allocator.Allocate(ctx, mac2, "host2")
		require.NoError(t, err)
		assert.True(t, ip1.Equal(ip2))
	})
}

// TestInMemoryAllocator_Release tests IP release.
func TestInMemoryAllocator_Release(t *testing.T) {
	t.Run("releases existing lease", func(t *testing.T) {
		allocator := NewInMemoryAllocator(
			net.ParseIP("192.168.1.100"),
			net.ParseIP("192.168.1.200"),
			time.Hour,
		)
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ctx := context.Background()

		_, err := allocator.Allocate(ctx, mac, "host1")
		require.NoError(t, err)

		err = allocator.Release(ctx, mac)
		require.NoError(t, err)

		// Verify lease is gone
		_, err = allocator.GetLease(ctx, mac)
		assert.Error(t, err)
	})

	t.Run("no error when releasing non-existent lease", func(t *testing.T) {
		allocator := NewInMemoryAllocator(
			net.ParseIP("192.168.1.100"),
			net.ParseIP("192.168.1.200"),
			time.Hour,
		)
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ctx := context.Background()

		err := allocator.Release(ctx, mac)
		require.NoError(t, err)
	})
}

// TestInMemoryAllocator_GetLease tests lease retrieval.
func TestInMemoryAllocator_GetLease(t *testing.T) {
	t.Run("returns existing valid lease", func(t *testing.T) {
		allocator := NewInMemoryAllocator(
			net.ParseIP("192.168.1.100"),
			net.ParseIP("192.168.1.200"),
			time.Hour,
		)
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ctx := context.Background()

		ip, err := allocator.Allocate(ctx, mac, "host1")
		require.NoError(t, err)

		l, err := allocator.GetLease(ctx, mac)
		require.NoError(t, err)
		assert.True(t, l.IP.Equal(ip))
		assert.Equal(t, mac.String(), l.MAC.String())
	})

	t.Run("returns error for non-existent lease", func(t *testing.T) {
		allocator := NewInMemoryAllocator(
			net.ParseIP("192.168.1.100"),
			net.ParseIP("192.168.1.200"),
			time.Hour,
		)
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ctx := context.Background()

		_, err := allocator.GetLease(ctx, mac)
		assert.Error(t, err)
	})

	t.Run("returns error for expired lease", func(t *testing.T) {
		allocator := NewInMemoryAllocator(
			net.ParseIP("192.168.1.100"),
			net.ParseIP("192.168.1.200"),
			time.Millisecond,
		)
		clk := newManualClock()
		allocator.clk = clk
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ctx := context.Background()

		_, err := allocator.Allocate(ctx, mac, "host1")
		require.NoError(t, err)

		// Advance past the lease lifetime. The old sleep spent this duration in
		// real time; moving the clock is instant and EXACT, where a sleep only
		// guaranteed at least it (#284).
		clk.Advance(5 * time.Millisecond)

		_, err = allocator.GetLease(ctx, mac)
		assert.Error(t, err)
	})

	t.Run("returns copy of lease", func(t *testing.T) {
		allocator := NewInMemoryAllocator(
			net.ParseIP("192.168.1.100"),
			net.ParseIP("192.168.1.200"),
			time.Hour,
		)
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ctx := context.Background()

		_, err := allocator.Allocate(ctx, mac, "host1")
		require.NoError(t, err)

		l1, err := allocator.GetLease(ctx, mac)
		require.NoError(t, err)

		// Store original last byte value (which is 100 for 192.168.1.100)
		originalLastByte := l1.IP[len(l1.IP)-1]

		// Modify returned lease's last byte
		l1.IP[len(l1.IP)-1] = 255

		// Get again, should be unmodified
		l2, err := allocator.GetLease(ctx, mac)
		require.NoError(t, err)
		assert.Equal(t, originalLastByte, l2.IP[len(l2.IP)-1])
	})
}

// TestInMemoryAllocator_Renew tests lease renewal.
func TestInMemoryAllocator_Renew(t *testing.T) {
	t.Run("renews existing lease", func(t *testing.T) {
		allocator := NewInMemoryAllocator(
			net.ParseIP("192.168.1.100"),
			net.ParseIP("192.168.1.200"),
			time.Hour,
		)
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ctx := context.Background()

		_, err := allocator.Allocate(ctx, mac, "host1")
		require.NoError(t, err)

		err = allocator.Renew(ctx, mac)
		require.NoError(t, err)
	})

	t.Run("returns error for non-existent lease", func(t *testing.T) {
		allocator := NewInMemoryAllocator(
			net.ParseIP("192.168.1.100"),
			net.ParseIP("192.168.1.200"),
			time.Hour,
		)
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ctx := context.Background()

		err := allocator.Renew(ctx, mac)
		assert.True(t, errors.Is(err, ErrLeaseNotFound))
	})
}

// TestInMemoryAllocator_ThreadSafety tests concurrent access.
func TestInMemoryAllocator_ThreadSafety(t *testing.T) {
	allocator := NewInMemoryAllocator(
		net.ParseIP("192.168.1.1"),
		net.ParseIP("192.168.1.254"),
		time.Hour,
	)

	const numGoroutines = 10
	const numOperations = 50

	done := make(chan struct{}, numGoroutines)
	ctx := context.Background()

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < numOperations; j++ {
				mac := net.HardwareAddr{0x00, 0x11, 0x22, byte(id), byte(j >> 8), byte(j)}
				_, _ = allocator.Allocate(ctx, mac, "")
			}
		}(i)
	}

	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

// TestNewIPAMAllocator tests IPAMAllocator creation.
func TestNewIPAMAllocator(t *testing.T) {
	t.Run("creates allocator with valid params", func(t *testing.T) {
		mockAlloc := newMockIPAMAllocator("pool1", netip.MustParseAddr("192.168.1.100"))

		allocator, err := NewIPAMAllocator(mockAlloc, "pool1", time.Hour)

		require.NoError(t, err)
		require.NotNil(t, allocator)
		assert.Equal(t, "pool1", allocator.PoolID())
	})

	t.Run("returns error with nil allocator", func(t *testing.T) {
		allocator, err := NewIPAMAllocator(nil, "pool1", time.Hour)

		require.Error(t, err)
		assert.Nil(t, allocator)
		assert.True(t, errors.Is(err, ErrInvalidConfig))
	})

	t.Run("returns error with empty pool ID", func(t *testing.T) {
		mockAlloc := newMockIPAMAllocator("pool1", netip.MustParseAddr("192.168.1.100"))

		allocator, err := NewIPAMAllocator(mockAlloc, "", time.Hour)

		require.Error(t, err)
		assert.Nil(t, allocator)
		assert.True(t, errors.Is(err, ErrInvalidConfig))
	})
}

// TestIPAMAllocator_Allocate tests IPAM-backed allocation.
func TestIPAMAllocator_Allocate(t *testing.T) {
	t.Run("allocates from IPAM", func(t *testing.T) {
		mockAlloc := newMockIPAMAllocator("pool1", netip.MustParseAddr("192.168.1.100"))
		allocator, err := NewIPAMAllocator(mockAlloc, "pool1", time.Hour)
		require.NoError(t, err)

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ctx := context.Background()

		ip, err := allocator.Allocate(ctx, mac, "host1")

		require.NoError(t, err)
		assert.True(t, ip.Equal(net.ParseIP("192.168.1.100")))
		assert.Equal(t, 1, allocator.LeaseCount())
	})

	t.Run("returns cached IP for same MAC", func(t *testing.T) {
		mockAlloc := newMockIPAMAllocator("pool1", netip.MustParseAddr("192.168.1.100"))
		allocator, err := NewIPAMAllocator(mockAlloc, "pool1", time.Hour)
		require.NoError(t, err)

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ctx := context.Background()

		ip1, err := allocator.Allocate(ctx, mac, "host1")
		require.NoError(t, err)

		ip2, err := allocator.Allocate(ctx, mac, "host1")
		require.NoError(t, err)

		assert.True(t, ip1.Equal(ip2))
		// IPAM should be called for renew, but not allocate twice
		assert.Equal(t, 1, mockAlloc.allocateCalls)
	})

	t.Run("returns error when IPAM exhausted", func(t *testing.T) {
		mockAlloc := newMockIPAMAllocator("pool1", netip.MustParseAddr("192.168.1.100"))
		mockAlloc.exhausted = true

		allocator, err := NewIPAMAllocator(mockAlloc, "pool1", time.Hour)
		require.NoError(t, err)

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ctx := context.Background()

		_, err = allocator.Allocate(ctx, mac, "host1")

		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrNoAvailableIPs))
	})

	t.Run("returns typed error on IPAM failure", func(t *testing.T) {
		mockAlloc := newMockIPAMAllocator("pool1", netip.MustParseAddr("192.168.1.100"))
		mockAlloc.allocateErr = errors.New("IPAM backend error")

		allocator, err := NewIPAMAllocator(mockAlloc, "pool1", time.Hour)
		require.NoError(t, err)

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ctx := context.Background()

		_, err = allocator.Allocate(ctx, mac, "host1")

		require.Error(t, err)
		var ipamErr *ErrIPAMAllocationFailed
		assert.True(t, errors.As(err, &ipamErr))
	})
}

// TestIPAMAllocator_Release tests IPAM-backed release.
func TestIPAMAllocator_Release(t *testing.T) {
	t.Run("releases allocation in IPAM", func(t *testing.T) {
		mockAlloc := newMockIPAMAllocator("pool1", netip.MustParseAddr("192.168.1.100"))
		allocator, err := NewIPAMAllocator(mockAlloc, "pool1", time.Hour)
		require.NoError(t, err)

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ctx := context.Background()

		_, err = allocator.Allocate(ctx, mac, "host1")
		require.NoError(t, err)

		err = allocator.Release(ctx, mac)
		require.NoError(t, err)

		assert.Equal(t, 0, allocator.LeaseCount())
	})

	t.Run("no error when releasing non-existent lease", func(t *testing.T) {
		mockAlloc := newMockIPAMAllocator("pool1", netip.MustParseAddr("192.168.1.100"))
		allocator, err := NewIPAMAllocator(mockAlloc, "pool1", time.Hour)
		require.NoError(t, err)

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ctx := context.Background()

		err = allocator.Release(ctx, mac)
		require.NoError(t, err)
	})

	t.Run("returns error on IPAM failure", func(t *testing.T) {
		mockAlloc := newMockIPAMAllocator("pool1", netip.MustParseAddr("192.168.1.100"))
		allocator, err := NewIPAMAllocator(mockAlloc, "pool1", time.Hour)
		require.NoError(t, err)

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ctx := context.Background()

		_, err = allocator.Allocate(ctx, mac, "host1")
		require.NoError(t, err)

		mockAlloc.releaseErr = errors.New("release failed")

		err = allocator.Release(ctx, mac)
		require.Error(t, err)
		var ipamErr *ErrIPAMReleaseFailed
		assert.True(t, errors.As(err, &ipamErr))
	})
}

// TestIPAMAllocator_GetLease tests lease retrieval.
func TestIPAMAllocator_GetLease(t *testing.T) {
	t.Run("returns existing lease", func(t *testing.T) {
		mockAlloc := newMockIPAMAllocator("pool1", netip.MustParseAddr("192.168.1.100"))
		allocator, err := NewIPAMAllocator(mockAlloc, "pool1", time.Hour)
		require.NoError(t, err)

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ctx := context.Background()

		ip, err := allocator.Allocate(ctx, mac, "host1")
		require.NoError(t, err)

		l, err := allocator.GetLease(ctx, mac)
		require.NoError(t, err)
		assert.True(t, l.IP.Equal(ip))
	})

	t.Run("returns error for non-existent lease", func(t *testing.T) {
		mockAlloc := newMockIPAMAllocator("pool1", netip.MustParseAddr("192.168.1.100"))
		allocator, err := NewIPAMAllocator(mockAlloc, "pool1", time.Hour)
		require.NoError(t, err)

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ctx := context.Background()

		_, err = allocator.GetLease(ctx, mac)
		assert.True(t, errors.Is(err, ErrLeaseNotFound))
	})

	t.Run("returns error for expired lease", func(t *testing.T) {
		mockAlloc := newMockIPAMAllocator("pool1", netip.MustParseAddr("192.168.1.100"))
		allocator, err := NewIPAMAllocator(mockAlloc, "pool1", time.Millisecond)
		require.NoError(t, err)
		clk := newManualClock()
		allocator.clk = clk

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ctx := context.Background()

		_, err = allocator.Allocate(ctx, mac, "host1")
		require.NoError(t, err)

		// Advance past the lease lifetime. The old sleep spent this duration in
		// real time; moving the clock is instant and EXACT, where a sleep only
		// guaranteed at least it (#284).
		clk.Advance(5 * time.Millisecond)

		_, err = allocator.GetLease(ctx, mac)
		assert.True(t, errors.Is(err, ErrLeaseExpired))
	})

	t.Run("returns copy of lease", func(t *testing.T) {
		mockAlloc := newMockIPAMAllocator("pool1", netip.MustParseAddr("192.168.1.100"))
		allocator, err := NewIPAMAllocator(mockAlloc, "pool1", time.Hour)
		require.NoError(t, err)

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ctx := context.Background()

		_, err = allocator.Allocate(ctx, mac, "host1")
		require.NoError(t, err)

		l1, err := allocator.GetLease(ctx, mac)
		require.NoError(t, err)

		// Store original last byte value (which is 100 for 192.168.1.100)
		originalLastByte := l1.IP[len(l1.IP)-1]

		// Modify returned lease's last byte
		l1.IP[len(l1.IP)-1] = 255

		// Get again, should be unmodified
		l2, err := allocator.GetLease(ctx, mac)
		require.NoError(t, err)
		assert.Equal(t, originalLastByte, l2.IP[len(l2.IP)-1])
	})
}

// TestIPAMAllocator_Renew tests lease renewal.
func TestIPAMAllocator_Renew(t *testing.T) {
	t.Run("renews existing lease", func(t *testing.T) {
		mockAlloc := newMockIPAMAllocator("pool1", netip.MustParseAddr("192.168.1.100"))
		allocator, err := NewIPAMAllocator(mockAlloc, "pool1", time.Hour)
		require.NoError(t, err)

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ctx := context.Background()

		_, err = allocator.Allocate(ctx, mac, "host1")
		require.NoError(t, err)

		err = allocator.Renew(ctx, mac)
		require.NoError(t, err)
		assert.Equal(t, 1, mockAlloc.renewCalled)
	})

	t.Run("returns error for non-existent lease", func(t *testing.T) {
		mockAlloc := newMockIPAMAllocator("pool1", netip.MustParseAddr("192.168.1.100"))
		allocator, err := NewIPAMAllocator(mockAlloc, "pool1", time.Hour)
		require.NoError(t, err)

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ctx := context.Background()

		err = allocator.Renew(ctx, mac)
		assert.True(t, errors.Is(err, ErrLeaseNotFound))
	})

	t.Run("returns error on IPAM expiration", func(t *testing.T) {
		mockAlloc := newMockIPAMAllocator("pool1", netip.MustParseAddr("192.168.1.100"))
		allocator, err := NewIPAMAllocator(mockAlloc, "pool1", time.Hour)
		require.NoError(t, err)

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ctx := context.Background()

		_, err = allocator.Allocate(ctx, mac, "host1")
		require.NoError(t, err)

		mockAlloc.renewErr = ipam.ErrAllocationExpired

		err = allocator.Renew(ctx, mac)
		assert.True(t, errors.Is(err, ErrLeaseExpired))
	})

	t.Run("returns error on IPAM failure", func(t *testing.T) {
		mockAlloc := newMockIPAMAllocator("pool1", netip.MustParseAddr("192.168.1.100"))
		allocator, err := NewIPAMAllocator(mockAlloc, "pool1", time.Hour)
		require.NoError(t, err)

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ctx := context.Background()

		_, err = allocator.Allocate(ctx, mac, "host1")
		require.NoError(t, err)

		mockAlloc.renewErr = errors.New("renew failed")

		err = allocator.Renew(ctx, mac)
		require.Error(t, err)
		var ipamErr *ErrIPAMRenewFailed
		assert.True(t, errors.As(err, &ipamErr))
	})
}

// TestIPAMAllocator_LeaseCount tests lease counting.
func TestIPAMAllocator_LeaseCount(t *testing.T) {
	t.Run("counts active leases only", func(t *testing.T) {
		mockAlloc := newMockIPAMAllocator("pool1", netip.MustParseAddr("192.168.1.100"))
		allocator, err := NewIPAMAllocator(mockAlloc, "pool1", time.Millisecond*10)
		require.NoError(t, err)
		clk := newManualClock()
		allocator.clk = clk

		mac1, _ := net.ParseMAC("00:11:22:33:44:55")
		mac2, _ := net.ParseMAC("00:11:22:33:44:66")
		ctx := context.Background()

		_, err = allocator.Allocate(ctx, mac1, "host1")
		require.NoError(t, err)
		_, err = allocator.Allocate(ctx, mac2, "host2")
		require.NoError(t, err)

		assert.Equal(t, 2, allocator.LeaseCount())

		// Advance past the lease lifetime. The old sleep spent this duration in
		// real time; moving the clock is instant and EXACT, where a sleep only
		// guaranteed at least it (#284).
		clk.Advance(20 * time.Millisecond)

		assert.Equal(t, 0, allocator.LeaseCount())
	})
}

// TestIPAMAllocator_SyncFromIPAM tests synchronization from IPAM.
func TestIPAMAllocator_SyncFromIPAM(t *testing.T) {
	t.Run("syncs allocations from IPAM", func(t *testing.T) {
		mockAlloc := newMockIPAMAllocator("pool1", netip.MustParseAddr("192.168.1.100"))

		// Pre-populate IPAM with allocations
		mockAlloc.allocations["192.168.1.100"] = &ipam.Allocation{
			ID:       "alloc1",
			PoolID:   "pool1",
			IP:       netip.MustParseAddr("192.168.1.100"),
			DeviceID: "00:11:22:33:44:55",
			Status:   ipam.AllocationStatusActive,
		}
		mockAlloc.allocations["192.168.1.101"] = &ipam.Allocation{
			ID:       "alloc2",
			PoolID:   "pool1",
			IP:       netip.MustParseAddr("192.168.1.101"),
			DeviceID: "00:11:22:33:44:66",
			Status:   ipam.AllocationStatusActive,
		}

		allocator, err := NewIPAMAllocator(mockAlloc, "pool1", time.Hour)
		require.NoError(t, err)

		ctx := context.Background()
		err = allocator.SyncFromIPAM(ctx)
		require.NoError(t, err)

		assert.Equal(t, 2, allocator.LeaseCount())
	})

	t.Run("ignores non-active allocations", func(t *testing.T) {
		mockAlloc := newMockIPAMAllocator("pool1", netip.MustParseAddr("192.168.1.100"))

		mockAlloc.allocations["192.168.1.100"] = &ipam.Allocation{
			ID:       "alloc1",
			PoolID:   "pool1",
			IP:       netip.MustParseAddr("192.168.1.100"),
			DeviceID: "00:11:22:33:44:55",
			Status:   ipam.AllocationStatusActive,
		}
		mockAlloc.allocations["192.168.1.101"] = &ipam.Allocation{
			ID:       "alloc2",
			PoolID:   "pool1",
			IP:       netip.MustParseAddr("192.168.1.101"),
			DeviceID: "00:11:22:33:44:66",
			Status:   ipam.AllocationStatusReleased, // Should be ignored
		}

		allocator, err := NewIPAMAllocator(mockAlloc, "pool1", time.Hour)
		require.NoError(t, err)

		ctx := context.Background()
		err = allocator.SyncFromIPAM(ctx)
		require.NoError(t, err)

		assert.Equal(t, 1, allocator.LeaseCount())
	})
}

// TestIPAMAllocator_ThreadSafety tests concurrent access.
func TestIPAMAllocator_ThreadSafety(t *testing.T) {
	mockAlloc := newMockIPAMAllocator("pool1", netip.MustParseAddr("192.168.1.1"))
	allocator, err := NewIPAMAllocator(mockAlloc, "pool1", time.Hour)
	require.NoError(t, err)

	const numGoroutines = 10
	const numOperations = 50

	done := make(chan struct{}, numGoroutines)
	ctx := context.Background()

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < numOperations; j++ {
				mac := net.HardwareAddr{0x00, 0x11, 0x22, byte(id), byte(j >> 8), byte(j)}
				_, _ = allocator.Allocate(ctx, mac, "")
			}
		}(i)
	}

	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

// TestDHCPServer_WithIPAllocator tests DHCP server with custom allocator.
func TestDHCPServer_WithIPAllocator(t *testing.T) {
	t.Run("creates server with allocator option", func(t *testing.T) {
		mockAlloc := newMockIPAMAllocator("pool1", netip.MustParseAddr("192.168.1.100"))
		ipamAllocator, err := NewIPAMAllocator(mockAlloc, "pool1", time.Hour)
		require.NoError(t, err)

		config := &DHCPConfig{
			ServerIP:   net.ParseIP("192.168.1.1"),
			RangeStart: net.ParseIP("192.168.1.100"),
			RangeEnd:   net.ParseIP("192.168.1.200"),
		}

		server, err := NewDHCPServer(config, nil, WithIPAllocator(ipamAllocator))

		require.NoError(t, err)
		require.NotNil(t, server)
		assert.NotNil(t, server.GetAllocator())
	})

	t.Run("uses allocator for IP assignment", func(t *testing.T) {
		mockAlloc := newMockIPAMAllocator("pool1", netip.MustParseAddr("10.0.0.100"))
		ipamAllocator, err := NewIPAMAllocator(mockAlloc, "pool1", time.Hour)
		require.NoError(t, err)

		config := &DHCPConfig{
			ServerIP:   net.ParseIP("192.168.1.1"),
			RangeStart: net.ParseIP("192.168.1.100"),
			RangeEnd:   net.ParseIP("192.168.1.200"),
		}

		server, err := NewDHCPServer(config, nil, WithIPAllocator(ipamAllocator))
		require.NoError(t, err)

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ip, err := server.getOrAssignIP(mac)

		require.NoError(t, err)
		// Should get IP from IPAM (10.0.0.x) not from config range
		assert.True(t, ip.Equal(net.ParseIP("10.0.0.100")))
	})

	t.Run("SetAllocator updates allocator", func(t *testing.T) {
		config := &DHCPConfig{
			ServerIP:   net.ParseIP("192.168.1.1"),
			RangeStart: net.ParseIP("192.168.1.100"),
			RangeEnd:   net.ParseIP("192.168.1.200"),
		}

		server, err := NewDHCPServer(config, nil)
		require.NoError(t, err)
		assert.Nil(t, server.GetAllocator())

		mockAlloc := newMockIPAMAllocator("pool1", netip.MustParseAddr("192.168.1.100"))
		ipamAllocator, err := NewIPAMAllocator(mockAlloc, "pool1", time.Hour)
		require.NoError(t, err)

		server.SetAllocator(ipamAllocator)

		assert.NotNil(t, server.GetAllocator())
	})

	t.Run("confirmLease uses allocator", func(t *testing.T) {
		mockAlloc := newMockIPAMAllocator("pool1", netip.MustParseAddr("10.0.0.100"))
		ipamAllocator, err := NewIPAMAllocator(mockAlloc, "pool1", time.Hour)
		require.NoError(t, err)

		config := &DHCPConfig{
			ServerIP:   net.ParseIP("192.168.1.1"),
			RangeStart: net.ParseIP("192.168.1.100"),
			RangeEnd:   net.ParseIP("192.168.1.200"),
		}

		server, err := NewDHCPServer(config, nil, WithIPAllocator(ipamAllocator))
		require.NoError(t, err)

		mac, _ := net.ParseMAC("00:11:22:33:44:55")

		// First allocate
		ip1, err := server.getOrAssignIP(mac)
		require.NoError(t, err)

		// Then confirm
		ip2, err := server.confirmLease(mac, ip1)
		require.NoError(t, err)

		assert.True(t, ip1.Equal(ip2))
	})

	t.Run("fallback to built-in allocation when no allocator", func(t *testing.T) {
		config := &DHCPConfig{
			ServerIP:   net.ParseIP("192.168.1.1"),
			RangeStart: net.ParseIP("192.168.1.100"),
			RangeEnd:   net.ParseIP("192.168.1.200"),
		}

		server, err := NewDHCPServer(config, nil)
		require.NoError(t, err)

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ip, err := server.getOrAssignIP(mac)

		require.NoError(t, err)
		// Should get IP from config range
		assert.True(t, ip.Equal(net.ParseIP("192.168.1.100")))
	})
}

// TestErrorTypes tests the error type implementations.
func TestErrorTypes(t *testing.T) {
	t.Run("ErrIPAMAllocationFailed with cause", func(t *testing.T) {
		cause := errors.New("backend error")
		err := &ErrIPAMAllocationFailed{
			PoolID: "pool1",
			MAC:    "00:11:22:33:44:55",
			Cause:  cause,
		}

		assert.Contains(t, err.Error(), "pool1")
		assert.Contains(t, err.Error(), "00:11:22:33:44:55")
		assert.Contains(t, err.Error(), "backend error")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrIPAMAllocationFailed without cause", func(t *testing.T) {
		err := &ErrIPAMAllocationFailed{
			PoolID: "pool1",
			MAC:    "00:11:22:33:44:55",
		}

		assert.Contains(t, err.Error(), "pool1")
		assert.Contains(t, err.Error(), "00:11:22:33:44:55")
		assert.Nil(t, err.Unwrap())
	})

	t.Run("ErrIPAMInvalidIP", func(t *testing.T) {
		err := &ErrIPAMInvalidIP{
			IP:     "invalid",
			Reason: "parse error",
		}

		assert.Contains(t, err.Error(), "invalid")
		assert.Contains(t, err.Error(), "parse error")
	})

	t.Run("ErrIPAMReleaseFailed with cause", func(t *testing.T) {
		cause := errors.New("release error")
		err := &ErrIPAMReleaseFailed{
			IP:    "192.168.1.100",
			MAC:   "00:11:22:33:44:55",
			Cause: cause,
		}

		assert.Contains(t, err.Error(), "192.168.1.100")
		assert.Contains(t, err.Error(), "00:11:22:33:44:55")
		assert.Contains(t, err.Error(), "release error")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrIPAMReleaseFailed without cause", func(t *testing.T) {
		err := &ErrIPAMReleaseFailed{
			IP:  "192.168.1.100",
			MAC: "00:11:22:33:44:55",
		}

		assert.Contains(t, err.Error(), "192.168.1.100")
		assert.Nil(t, err.Unwrap())
	})

	t.Run("ErrIPAMRenewFailed with cause", func(t *testing.T) {
		cause := errors.New("renew error")
		err := &ErrIPAMRenewFailed{
			IP:    "192.168.1.100",
			MAC:   "00:11:22:33:44:55",
			Cause: cause,
		}

		assert.Contains(t, err.Error(), "192.168.1.100")
		assert.Contains(t, err.Error(), "00:11:22:33:44:55")
		assert.Contains(t, err.Error(), "renew error")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrIPAMRenewFailed without cause", func(t *testing.T) {
		err := &ErrIPAMRenewFailed{
			IP:  "192.168.1.100",
			MAC: "00:11:22:33:44:55",
		}

		assert.Contains(t, err.Error(), "192.168.1.100")
		assert.Nil(t, err.Unwrap())
	})
}

// TestWithPacketConnFactory tests the WithPacketConnFactory option.
func TestWithPacketConnFactory(t *testing.T) {
	mockFactory := &mockPacketConnFactory{
		conn: &mockPacketConn{},
	}

	config := &DHCPConfig{
		ServerIP:   net.ParseIP("192.168.1.1"),
		RangeStart: net.ParseIP("192.168.1.100"),
		RangeEnd:   net.ParseIP("192.168.1.200"),
	}

	server, err := NewDHCPServer(config, nil, WithPacketConnFactory(mockFactory))

	require.NoError(t, err)
	assert.Equal(t, mockFactory, server.connFactory)
}
