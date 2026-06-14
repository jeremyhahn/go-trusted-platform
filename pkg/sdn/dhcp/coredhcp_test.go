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

package dhcp

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
)

// mockAllocator implements ipam.Allocator for testing.
type mockAllocator struct {
	allocations map[string]*ipam.Allocation
	nextIP      netip.Addr
	pool        *ipam.Pool
	allocErr    error
	releaseErr  error
	renewErr    error
}

func newMockAllocator() *mockAllocator {
	return &mockAllocator{
		allocations: make(map[string]*ipam.Allocation),
		nextIP:      netip.MustParseAddr("192.168.1.100"),
		pool: &ipam.Pool{
			ID:   "test-pool",
			Name: "Test Pool",
			CIDR: netip.MustParsePrefix("192.168.1.0/24"),
		},
	}
}

func (m *mockAllocator) CreatePool(ctx context.Context, pool *ipam.Pool) error {
	return nil
}

func (m *mockAllocator) GetPool(ctx context.Context, poolID string) (*ipam.Pool, error) {
	return m.pool, nil
}

func (m *mockAllocator) GetPoolByName(ctx context.Context, name string) (*ipam.Pool, error) {
	return m.pool, nil
}

func (m *mockAllocator) GetPoolByCIDR(ctx context.Context, cidr netip.Prefix) (*ipam.Pool, error) {
	return m.pool, nil
}

func (m *mockAllocator) ListPools(ctx context.Context) ([]*ipam.Pool, error) {
	return []*ipam.Pool{m.pool}, nil
}

func (m *mockAllocator) UpdatePool(ctx context.Context, pool *ipam.Pool) error {
	return nil
}

func (m *mockAllocator) DeletePool(ctx context.Context, poolID string) error {
	return nil
}

func (m *mockAllocator) GetPoolStats(ctx context.Context, poolID string) (*ipam.PoolStats, error) {
	return &ipam.PoolStats{}, nil
}

func (m *mockAllocator) Allocate(ctx context.Context, req *ipam.AllocationRequest) (*ipam.Allocation, error) {
	if m.allocErr != nil {
		return nil, m.allocErr
	}

	ip := m.nextIP
	// Increment next IP
	bytes := ip.As4()
	bytes[3]++
	m.nextIP = netip.AddrFrom4(bytes)

	alloc := &ipam.Allocation{
		ID:          req.DeviceID,
		PoolID:      req.PoolID,
		IP:          ip,
		DeviceID:    req.DeviceID,
		Hostname:    req.Hostname,
		AllocatedAt: time.Now(),
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		Status:      ipam.AllocationStatusActive,
	}
	m.allocations[ip.String()] = alloc
	return alloc, nil
}

func (m *mockAllocator) AllocateSpecific(ctx context.Context, req *ipam.AllocationRequest) (*ipam.Allocation, error) {
	if m.allocErr != nil {
		return nil, m.allocErr
	}

	if _, ok := m.allocations[req.RequestedIP.String()]; ok {
		return nil, ipam.ErrIPAlreadyAllocated
	}

	alloc := &ipam.Allocation{
		ID:          req.DeviceID,
		PoolID:      req.PoolID,
		IP:          req.RequestedIP,
		DeviceID:    req.DeviceID,
		Hostname:    req.Hostname,
		AllocatedAt: time.Now(),
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		Status:      ipam.AllocationStatusActive,
	}
	m.allocations[req.RequestedIP.String()] = alloc
	return alloc, nil
}

func (m *mockAllocator) Release(ctx context.Context, ip netip.Addr) error {
	if m.releaseErr != nil {
		return m.releaseErr
	}
	delete(m.allocations, ip.String())
	return nil
}

func (m *mockAllocator) ReleaseByDeviceID(ctx context.Context, deviceID string) (int, error) {
	count := 0
	for ipStr, alloc := range m.allocations {
		if alloc.DeviceID == deviceID {
			delete(m.allocations, ipStr)
			count++
		}
	}
	return count, nil
}

func (m *mockAllocator) Renew(ctx context.Context, ip netip.Addr) error {
	if m.renewErr != nil {
		return m.renewErr
	}
	if alloc, ok := m.allocations[ip.String()]; ok {
		alloc.ExpiresAt = time.Now().Add(24 * time.Hour)
		return nil
	}
	return ipam.ErrAllocationNotFound
}

func (m *mockAllocator) GetAllocation(ctx context.Context, ip netip.Addr) (*ipam.Allocation, error) {
	if alloc, ok := m.allocations[ip.String()]; ok {
		return alloc, nil
	}
	return nil, ipam.ErrAllocationNotFound
}

func (m *mockAllocator) GetAllocationsByDevice(ctx context.Context, deviceID string) ([]*ipam.Allocation, error) {
	var allocs []*ipam.Allocation
	for _, alloc := range m.allocations {
		if alloc.DeviceID == deviceID {
			allocs = append(allocs, alloc)
		}
	}
	return allocs, nil
}

func (m *mockAllocator) GetAllocationsByPool(ctx context.Context, poolID string) ([]*ipam.Allocation, error) {
	var allocs []*ipam.Allocation
	for _, alloc := range m.allocations {
		if alloc.PoolID == poolID {
			allocs = append(allocs, alloc)
		}
	}
	return allocs, nil
}

func (m *mockAllocator) ListPoolsByZone(ctx context.Context, zone string) ([]*ipam.Pool, error) {
	if zone == "" {
		return m.ListPools(ctx)
	}
	if m.pool != nil && m.pool.Zone == zone {
		return []*ipam.Pool{m.pool}, nil
	}
	return nil, nil
}

func (m *mockAllocator) ExpireInactive(ctx context.Context, poolID string) ([]*ipam.Allocation, error) {
	return nil, nil
}

func (m *mockAllocator) Ping(ctx context.Context) error {
	return nil
}

func (m *mockAllocator) Close() error {
	return nil
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
}

func testServerConfig() *ServerConfig {
	return &ServerConfig{
		DefaultLeaseDuration: 24 * time.Hour,
		IPAMBackend:          IPAMBackendMemory,
		Interfaces: []InterfaceConfig{
			{
				Name:    "lo", // Use loopback for testing
				Network: NetworkPrivate,
				Address: netip.MustParseAddr("127.0.0.1"),
				PoolID:  "test-pool",
				Options: DHCPOptions{
					SubnetMask: net.IPv4Mask(255, 255, 255, 0),
					Router:     netip.MustParseAddr("192.168.1.1"),
					DNS:        []netip.Addr{netip.MustParseAddr("8.8.8.8")},
					DomainName: "example.com",
					LeaseTime:  24 * time.Hour,
				},
			},
		},
	}
}

func TestNewCoreDHCPServer(t *testing.T) {
	t.Run("creates server with valid config", func(t *testing.T) {
		cfg := testServerConfig()
		allocator := newMockAllocator()

		srv, err := NewCoreDHCPServer(cfg, allocator, WithCoreDHCPLogger(testLogger()))
		require.NoError(t, err)
		require.NotNil(t, srv)
		assert.False(t, srv.Running())
	})

	t.Run("nil config returns error", func(t *testing.T) {
		allocator := newMockAllocator()

		_, err := NewCoreDHCPServer(nil, allocator)
		assert.ErrorIs(t, err, ErrNilConfig)
	})

	t.Run("nil allocator returns error", func(t *testing.T) {
		cfg := testServerConfig()

		_, err := NewCoreDHCPServer(cfg, nil)
		assert.ErrorIs(t, err, ErrNilIPAMAllocator)
	})

	t.Run("invalid config returns error", func(t *testing.T) {
		cfg := &ServerConfig{} // No interfaces
		allocator := newMockAllocator()

		_, err := NewCoreDHCPServer(cfg, allocator)
		assert.ErrorIs(t, err, ErrNoInterfacesConfigured)
	})
}

func TestCoreDHCPServer_Running(t *testing.T) {
	t.Run("returns false when not started", func(t *testing.T) {
		cfg := testServerConfig()
		allocator := newMockAllocator()

		srv, _ := NewCoreDHCPServer(cfg, allocator)
		assert.False(t, srv.Running())
	})
}

func TestCoreDHCPServer_GetLease(t *testing.T) {
	t.Run("returns lease for existing MAC", func(t *testing.T) {
		cfg := testServerConfig()
		allocator := newMockAllocator()

		srv, _ := NewCoreDHCPServer(cfg, allocator)

		// Manually add a lease
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ip := netip.MustParseAddr("192.168.1.100")
		lease := &Lease{
			IP:    ip,
			MAC:   mac,
			State: LeaseStateActive,
		}
		err := srv.GetLeaseStore().Add(lease)
		require.NoError(t, err)

		retrieved, ok := srv.GetLease(mac)
		require.True(t, ok)
		assert.Equal(t, ip, retrieved.IP)
	})

	t.Run("returns false for non-existent MAC", func(t *testing.T) {
		cfg := testServerConfig()
		allocator := newMockAllocator()

		srv, _ := NewCoreDHCPServer(cfg, allocator)

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		_, ok := srv.GetLease(mac)
		assert.False(t, ok)
	})

	t.Run("returns false for nil MAC", func(t *testing.T) {
		cfg := testServerConfig()
		allocator := newMockAllocator()

		srv, _ := NewCoreDHCPServer(cfg, allocator)

		_, ok := srv.GetLease(nil)
		assert.False(t, ok)
	})

	t.Run("returns false for empty MAC", func(t *testing.T) {
		cfg := testServerConfig()
		allocator := newMockAllocator()

		srv, _ := NewCoreDHCPServer(cfg, allocator)

		_, ok := srv.GetLease(net.HardwareAddr{})
		assert.False(t, ok)
	})
}

func TestCoreDHCPServer_GetLeaseByIP(t *testing.T) {
	t.Run("returns lease for existing IP", func(t *testing.T) {
		cfg := testServerConfig()
		allocator := newMockAllocator()

		srv, _ := NewCoreDHCPServer(cfg, allocator)

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ip := netip.MustParseAddr("192.168.1.100")
		lease := &Lease{
			IP:    ip,
			MAC:   mac,
			State: LeaseStateActive,
		}
		err := srv.GetLeaseStore().Add(lease)
		require.NoError(t, err)

		retrieved, ok := srv.GetLeaseByIP(ip)
		require.True(t, ok)
		assert.Equal(t, mac.String(), retrieved.MAC.String())
	})

	t.Run("returns false for non-existent IP", func(t *testing.T) {
		cfg := testServerConfig()
		allocator := newMockAllocator()

		srv, _ := NewCoreDHCPServer(cfg, allocator)

		ip := netip.MustParseAddr("192.168.1.100")
		_, ok := srv.GetLeaseByIP(ip)
		assert.False(t, ok)
	})

	t.Run("returns false for invalid IP", func(t *testing.T) {
		cfg := testServerConfig()
		allocator := newMockAllocator()

		srv, _ := NewCoreDHCPServer(cfg, allocator)

		_, ok := srv.GetLeaseByIP(netip.Addr{})
		assert.False(t, ok)
	})
}

func TestCoreDHCPServer_ListLeases(t *testing.T) {
	t.Run("returns all active leases", func(t *testing.T) {
		cfg := testServerConfig()
		allocator := newMockAllocator()

		srv, _ := NewCoreDHCPServer(cfg, allocator)

		// Add multiple leases
		macs := []string{"00:11:22:33:44:01", "00:11:22:33:44:02", "00:11:22:33:44:03"}
		ips := []string{"192.168.1.101", "192.168.1.102", "192.168.1.103"}
		states := []LeaseState{LeaseStateActive, LeaseStateActive, LeaseStateReleased}

		for i := 0; i < 3; i++ {
			mac, _ := net.ParseMAC(macs[i])
			ip := netip.MustParseAddr(ips[i])
			lease := &Lease{
				IP:        ip,
				MAC:       mac,
				State:     states[i],
				ExpiresAt: time.Now().Add(24 * time.Hour),
			}
			err := srv.GetLeaseStore().Add(lease)
			require.NoError(t, err)
		}

		leases := srv.ListLeases()
		assert.Len(t, leases, 2) // Only active leases
	})

	t.Run("returns empty list when no leases", func(t *testing.T) {
		cfg := testServerConfig()
		allocator := newMockAllocator()

		srv, _ := NewCoreDHCPServer(cfg, allocator)

		leases := srv.ListLeases()
		assert.Empty(t, leases)
	})
}

func TestCoreDHCPServer_ReleaseLease(t *testing.T) {
	t.Run("releases existing lease", func(t *testing.T) {
		cfg := testServerConfig()
		allocator := newMockAllocator()

		srv, _ := NewCoreDHCPServer(cfg, allocator, WithCoreDHCPLogger(testLogger()))

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ip := netip.MustParseAddr("192.168.1.100")
		lease := &Lease{
			IP:     ip,
			MAC:    mac,
			PoolID: "test-pool",
			State:  LeaseStateActive,
		}
		err := srv.GetLeaseStore().Add(lease)
		require.NoError(t, err)

		err = srv.ReleaseLease(mac)
		require.NoError(t, err)

		// Verify lease is removed
		_, ok := srv.GetLease(mac)
		assert.False(t, ok)
	})

	t.Run("returns error for non-existent MAC", func(t *testing.T) {
		cfg := testServerConfig()
		allocator := newMockAllocator()

		srv, _ := NewCoreDHCPServer(cfg, allocator)

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		err := srv.ReleaseLease(mac)
		assert.ErrorIs(t, err, ErrLeaseNotFound)
	})

	t.Run("returns error for nil MAC", func(t *testing.T) {
		cfg := testServerConfig()
		allocator := newMockAllocator()

		srv, _ := NewCoreDHCPServer(cfg, allocator)

		err := srv.ReleaseLease(nil)
		assert.ErrorIs(t, err, ErrInvalidMAC)
	})

	t.Run("continues on IPAM release error", func(t *testing.T) {
		cfg := testServerConfig()
		allocator := newMockAllocator()
		allocator.releaseErr = errors.New("IPAM release failed")

		srv, _ := NewCoreDHCPServer(cfg, allocator, WithCoreDHCPLogger(testLogger()))

		mac, _ := net.ParseMAC("00:11:22:33:44:56")
		ip := netip.MustParseAddr("192.168.1.101")
		lease := &Lease{
			IP:     ip,
			MAC:    mac,
			PoolID: "test-pool",
			State:  LeaseStateActive,
		}
		err := srv.GetLeaseStore().Add(lease)
		require.NoError(t, err)

		// ReleaseLease should still succeed even if IPAM release fails
		// (it logs the error but continues)
		err = srv.ReleaseLease(mac)
		require.NoError(t, err)

		// Verify lease is removed
		_, ok := srv.GetLease(mac)
		assert.False(t, ok)
	})
}

func TestCoreDHCPServer_Stats(t *testing.T) {
	t.Run("returns initial stats", func(t *testing.T) {
		cfg := testServerConfig()
		allocator := newMockAllocator()

		srv, _ := NewCoreDHCPServer(cfg, allocator)

		stats := srv.Stats()
		assert.Equal(t, uint64(0), stats.PacketsReceived)
		assert.Equal(t, uint64(0), stats.PacketsSent)
		assert.Equal(t, uint64(0), stats.DiscoverCount)
		assert.Equal(t, 0, stats.ActiveLeases)
	})
}

func TestCoreDHCPServer_GetConfig(t *testing.T) {
	t.Run("returns config clone", func(t *testing.T) {
		cfg := testServerConfig()
		allocator := newMockAllocator()

		srv, _ := NewCoreDHCPServer(cfg, allocator)

		retrieved := srv.GetConfig()
		require.NotNil(t, retrieved)
		assert.Equal(t, cfg.DefaultLeaseDuration, retrieved.DefaultLeaseDuration)
		assert.Equal(t, len(cfg.Interfaces), len(retrieved.Interfaces))

		// Verify it's a clone
		retrieved.DefaultLeaseDuration = 1 * time.Hour
		original := srv.GetConfig()
		assert.NotEqual(t, retrieved.DefaultLeaseDuration, original.DefaultLeaseDuration)
	})
}

func TestCoreDHCPServer_ExpireLeases(t *testing.T) {
	t.Run("expires old leases", func(t *testing.T) {
		cfg := testServerConfig()
		allocator := newMockAllocator()

		srv, _ := NewCoreDHCPServer(cfg, allocator)

		// Add active lease
		mac1, _ := net.ParseMAC("00:11:22:33:44:01")
		ip1 := netip.MustParseAddr("192.168.1.101")
		lease1 := &Lease{
			IP:        ip1,
			MAC:       mac1,
			State:     LeaseStateActive,
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}
		err := srv.GetLeaseStore().Add(lease1)
		require.NoError(t, err)

		// Add expired lease
		mac2, _ := net.ParseMAC("00:11:22:33:44:02")
		ip2 := netip.MustParseAddr("192.168.1.102")
		lease2 := &Lease{
			IP:        ip2,
			MAC:       mac2,
			State:     LeaseStateActive,
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		}
		err = srv.GetLeaseStore().Add(lease2)
		require.NoError(t, err)

		count := srv.ExpireLeases()
		assert.Equal(t, 1, count)
	})
}

func TestCoreDHCPServer_StopNotRunning(t *testing.T) {
	t.Run("stop returns error when not running", func(t *testing.T) {
		cfg := testServerConfig()
		allocator := newMockAllocator()

		srv, _ := NewCoreDHCPServer(cfg, allocator)

		ctx := context.Background()
		err := srv.Stop(ctx)
		assert.ErrorIs(t, err, ErrServerNotRunning)
	})
}

func TestCoreDHCPServer_WithOptions(t *testing.T) {
	t.Run("applies logger option", func(t *testing.T) {
		cfg := testServerConfig()
		allocator := newMockAllocator()
		logger := testLogger()

		srv, err := NewCoreDHCPServer(cfg, allocator, WithCoreDHCPLogger(logger))
		require.NoError(t, err)
		require.NotNil(t, srv)
	})

	t.Run("applies custom lease store option", func(t *testing.T) {
		cfg := testServerConfig()
		allocator := newMockAllocator()
		ls := NewLeaseStore()

		srv, err := NewCoreDHCPServer(cfg, allocator, WithCoreDHCPLeaseStore(ls))
		require.NoError(t, err)
		require.NotNil(t, srv)

		// Verify the custom lease store is used
		assert.Same(t, ls, srv.GetLeaseStore())
	})
}
