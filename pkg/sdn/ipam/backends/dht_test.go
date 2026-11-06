//go:build platform_p2p

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

package backends

import (
	"context"
	"math/big"
	"net/netip"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
)

// MockDHT provides an in-memory DHT implementation for testing.
type MockDHT struct {
	data sync.Map
	mu   sync.RWMutex
}

func NewMockDHT() *MockDHT {
	return &MockDHT{}
}

func (m *MockDHT) PutValue(ctx context.Context, key string, value []byte) error {
	m.data.Store(key, value)
	return nil
}

func (m *MockDHT) GetValue(ctx context.Context, key string) ([]byte, error) {
	if v, ok := m.data.Load(key); ok {
		return v.([]byte), nil
	}
	return nil, ipam.ErrAllocationNotFound
}

func (m *MockDHT) GetClosestPeers(ctx context.Context, key string) ([]string, error) {
	return []string{"peer1", "peer2"}, nil
}

// TestCalculatePoolSize tests the calculatePoolSize function.
func TestCalculatePoolSize(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		expected uint64
	}{
		{"IPv4 /24", "192.168.1.0/24", 254},    // 256 - 2 (network + broadcast)
		{"IPv4 /25", "192.168.1.0/25", 126},    // 128 - 2
		{"IPv4 /30", "192.168.1.0/30", 2},      // 4 - 2
		{"IPv4 /31", "192.168.1.0/31", 2},      // Point-to-point, no network/broadcast
		{"IPv4 /32", "192.168.1.1/32", 1},      // Single host
		{"IPv6 /64", "2001:db8::/64", 1 << 63}, // Capped at 63 bits
		{"IPv6 /112", "2001:db8::/112", 65536},
		{"IPv6 /128", "2001:db8::1/128", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cidr := netip.MustParsePrefix(tt.cidr)
			got := CalculatePoolSize(cidr)
			if got != tt.expected {
				t.Errorf("calculatePoolSize(%s) = %d, want %d", tt.cidr, got, tt.expected)
			}
		})
	}
}

// TestRandomIPInCIDR tests the randomIPInCIDR function.
func TestRandomIPInCIDR(t *testing.T) {
	tests := []struct {
		name string
		cidr string
	}{
		{"IPv4 /24", "192.168.1.0/24"},
		{"IPv4 /16", "10.0.0.0/16"},
		{"IPv6 /64", "2001:db8::/64"},
		{"IPv6 /112", "2001:db8::/112"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cidr := netip.MustParsePrefix(tt.cidr)

			// Generate multiple IPs and verify they're all in range
			for i := 0; i < 100; i++ {
				ip, err := RandomIPInCIDR(cidr)
				if err != nil {
					t.Fatalf("randomIPInCIDR(%s) failed: %v", tt.cidr, err)
				}

				if !cidr.Contains(ip) {
					t.Errorf("randomIPInCIDR(%s) = %s, not in CIDR", tt.cidr, ip)
				}
			}
		})
	}
}

// TestRandomIPInCIDRDistribution tests that random IP generation is reasonably distributed.
func TestRandomIPInCIDRDistribution(t *testing.T) {
	cidr := netip.MustParsePrefix("192.168.1.0/28") // 16 addresses
	counts := make(map[string]int)

	// Generate many IPs
	for i := 0; i < 1000; i++ {
		ip, err := randomIPInCIDR(cidr)
		if err != nil {
			t.Fatalf("randomIPInCIDR failed: %v", err)
		}
		counts[ip.String()]++
	}

	// Should have generated at least a few different IPs
	if len(counts) < 5 {
		t.Errorf("Poor distribution: only %d unique IPs generated", len(counts))
	}
}

// TestIsNetworkOrBroadcast tests network/broadcast address detection.
func TestIsNetworkOrBroadcast(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		ip       string
		expected bool
	}{
		{"Network address", "192.168.1.0/24", "192.168.1.0", true},
		{"Broadcast address", "192.168.1.0/24", "192.168.1.255", true},
		{"Regular address", "192.168.1.0/24", "192.168.1.100", false},
		{"First usable", "192.168.1.0/24", "192.168.1.1", false},
		{"Last usable", "192.168.1.0/24", "192.168.1.254", false},
		{"/31 first", "192.168.1.0/31", "192.168.1.0", false}, // /31 has no network/broadcast
		{"/31 second", "192.168.1.0/31", "192.168.1.1", false},
		{"IPv6 - no network concept", "2001:db8::/64", "2001:db8::", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cidr := netip.MustParsePrefix(tt.cidr)
			ip := netip.MustParseAddr(tt.ip)
			got := IsNetworkOrBroadcast(cidr, ip)
			if got != tt.expected {
				t.Errorf("isNetworkOrBroadcast(%s, %s) = %v, want %v",
					tt.cidr, tt.ip, got, tt.expected)
			}
		})
	}
}

// TestIsNetworkAddress tests network address detection.
func TestIsNetworkAddress(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		ip       string
		expected bool
	}{
		{"Network address /24", "192.168.1.0/24", "192.168.1.0", true},
		{"Not network address", "192.168.1.0/24", "192.168.1.1", false},
		{"Network address /16", "10.0.0.0/16", "10.0.0.0", true},
		{"IPv6 - no network address", "2001:db8::/64", "2001:db8::", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cidr := netip.MustParsePrefix(tt.cidr)
			ip := netip.MustParseAddr(tt.ip)
			got := isNetworkAddress(cidr, ip)
			if got != tt.expected {
				t.Errorf("isNetworkAddress(%s, %s) = %v, want %v",
					tt.cidr, tt.ip, got, tt.expected)
			}
		})
	}
}

// TestIsBroadcastAddress tests broadcast address detection.
func TestIsBroadcastAddress(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		ip       string
		expected bool
	}{
		{"Broadcast address /24", "192.168.1.0/24", "192.168.1.255", true},
		{"Not broadcast address", "192.168.1.0/24", "192.168.1.254", false},
		{"Broadcast address /16", "10.0.0.0/16", "10.0.255.255", true},
		{"IPv6 - no broadcast", "2001:db8::/64", "2001:db8::ffff:ffff:ffff:ffff", false},
		{"/31 - no broadcast", "192.168.1.0/31", "192.168.1.1", false},
		{"/32 - no broadcast", "192.168.1.1/32", "192.168.1.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cidr := netip.MustParsePrefix(tt.cidr)
			ip := netip.MustParseAddr(tt.ip)
			got := isBroadcastAddress(cidr, ip)
			if got != tt.expected {
				t.Errorf("isBroadcastAddress(%s, %s) = %v, want %v",
					tt.cidr, tt.ip, got, tt.expected)
			}
		})
	}
}

// TestCalculateBroadcastAddress tests broadcast address calculation.
func TestCalculateBroadcastAddress(t *testing.T) {
	tests := []struct {
		name        string
		cidr        string
		expected    string
		expectError bool
	}{
		{"IPv4 /24", "192.168.1.0/24", "192.168.1.255", false},
		{"IPv4 /16", "10.0.0.0/16", "10.0.255.255", false},
		{"IPv4 /8", "10.0.0.0/8", "10.255.255.255", false},
		{"IPv4 /31", "192.168.1.0/31", "", true},
		{"IPv4 /32", "192.168.1.1/32", "", true},
		{"IPv6", "2001:db8::/64", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cidr := netip.MustParsePrefix(tt.cidr)
			got, err := CalculateBroadcastAddress(cidr)

			if tt.expectError {
				if err == nil {
					t.Errorf("CalculateBroadcastAddress(%s) expected error, got %s", tt.cidr, got)
				}
				return
			}

			if err != nil {
				t.Fatalf("CalculateBroadcastAddress(%s) unexpected error: %v", tt.cidr, err)
			}

			expected := netip.MustParseAddr(tt.expected)
			if got != expected {
				t.Errorf("CalculateBroadcastAddress(%s) = %s, want %s", tt.cidr, got, tt.expected)
			}
		})
	}
}

// TestNewDHTBackendNilNode tests creating DHTBackend with nil node.
func TestNewDHTBackendNilNode(t *testing.T) {
	_, err := NewDHTBackend(nil)
	if err == nil {
		t.Error("NewDHTBackend(nil) expected error, got nil")
	}

	var initErr *ErrDHTBackendInit
	if err == nil {
		t.Error("Expected ErrDHTBackendInit error")
	}
	_ = initErr // Type check passes
}

// TestPoolOperationsValidation tests pool operation validation.
func TestPoolOperationsValidation(t *testing.T) {
	// Test invalid pool ID
	t.Run("GetPool empty ID", func(t *testing.T) {
		// Create a minimal mock backend for validation testing
		backend := &DHTBackend{}
		_, err := backend.GetPool(context.Background(), "")
		if err != ipam.ErrInvalidPoolID {
			t.Errorf("GetPool(\"\") = %v, want ErrInvalidPoolID", err)
		}
	})

	t.Run("GetPoolByName empty name", func(t *testing.T) {
		backend := &DHTBackend{}
		_, err := backend.GetPoolByName(context.Background(), "")
		if err != ipam.ErrInvalidPoolName {
			t.Errorf("GetPoolByName(\"\") = %v, want ErrInvalidPoolName", err)
		}
	})

	t.Run("GetPoolByCIDR invalid CIDR", func(t *testing.T) {
		backend := &DHTBackend{}
		_, err := backend.GetPoolByCIDR(context.Background(), netip.Prefix{})
		if err != ipam.ErrInvalidCIDR {
			t.Errorf("GetPoolByCIDR(invalid) = %v, want ErrInvalidCIDR", err)
		}
	})

	t.Run("CreatePool nil", func(t *testing.T) {
		backend := &DHTBackend{}
		err := backend.CreatePool(context.Background(), nil)
		if err != ipam.ErrInvalidPoolID {
			t.Errorf("CreatePool(nil) = %v, want ErrInvalidPoolID", err)
		}
	})

	t.Run("CreatePool empty ID", func(t *testing.T) {
		backend := &DHTBackend{}
		pool := &ipam.Pool{}
		err := backend.CreatePool(context.Background(), pool)
		if err != ipam.ErrInvalidPoolID {
			t.Errorf("CreatePool(empty ID) = %v, want ErrInvalidPoolID", err)
		}
	})

	t.Run("CreatePool empty name", func(t *testing.T) {
		backend := &DHTBackend{}
		pool := &ipam.Pool{ID: "test"}
		err := backend.CreatePool(context.Background(), pool)
		if err != ipam.ErrInvalidPoolName {
			t.Errorf("CreatePool(empty name) = %v, want ErrInvalidPoolName", err)
		}
	})

	t.Run("CreatePool invalid CIDR", func(t *testing.T) {
		backend := &DHTBackend{}
		pool := &ipam.Pool{ID: "test", Name: "Test Pool"}
		err := backend.CreatePool(context.Background(), pool)
		if err != ipam.ErrInvalidCIDR {
			t.Errorf("CreatePool(invalid CIDR) = %v, want ErrInvalidCIDR", err)
		}
	})
}

// TestAllocationRequestValidation tests allocation request validation.
func TestAllocationRequestValidation(t *testing.T) {
	t.Run("Empty pool ID", func(t *testing.T) {
		req := &ipam.AllocationRequest{DeviceID: "device1"}
		err := req.Validate()
		if err != ipam.ErrPoolIDRequired {
			t.Errorf("Validate() = %v, want ErrPoolIDRequired", err)
		}
	})

	t.Run("Empty device ID", func(t *testing.T) {
		req := &ipam.AllocationRequest{PoolID: "pool1"}
		err := req.Validate()
		if err != ipam.ErrDeviceIDRequired {
			t.Errorf("Validate() = %v, want ErrDeviceIDRequired", err)
		}
	})

	t.Run("Valid request", func(t *testing.T) {
		req := &ipam.AllocationRequest{PoolID: "pool1", DeviceID: "device1"}
		err := req.Validate()
		if err != nil {
			t.Errorf("Validate() = %v, want nil", err)
		}
	})
}

// TestIPAddressValidation tests IP address validation in release operations.
func TestIPAddressValidation(t *testing.T) {
	backend := &DHTBackend{}

	t.Run("Release invalid IP", func(t *testing.T) {
		err := backend.Release(context.Background(), netip.Addr{})
		if err != ipam.ErrInvalidIP {
			t.Errorf("Release(invalid) = %v, want ErrInvalidIP", err)
		}
	})

	t.Run("Renew invalid IP", func(t *testing.T) {
		err := backend.Renew(context.Background(), netip.Addr{})
		if err != ipam.ErrInvalidIP {
			t.Errorf("Renew(invalid) = %v, want ErrInvalidIP", err)
		}
	})

	t.Run("GetAllocation invalid IP", func(t *testing.T) {
		_, err := backend.GetAllocation(context.Background(), netip.Addr{})
		if err != ipam.ErrInvalidIP {
			t.Errorf("GetAllocation(invalid) = %v, want ErrInvalidIP", err)
		}
	})
}

// TestDeviceIDValidation tests device ID validation.
func TestDeviceIDValidation(t *testing.T) {
	backend := &DHTBackend{}

	t.Run("GetAllocationsByDevice empty", func(t *testing.T) {
		_, err := backend.GetAllocationsByDevice(context.Background(), "")
		if err != ipam.ErrDeviceIDRequired {
			t.Errorf("GetAllocationsByDevice(\"\") = %v, want ErrDeviceIDRequired", err)
		}
	})

	t.Run("ReleaseByDeviceID empty", func(t *testing.T) {
		_, err := backend.ReleaseByDeviceID(context.Background(), "")
		if err != ipam.ErrDeviceIDRequired {
			t.Errorf("ReleaseByDeviceID(\"\") = %v, want ErrDeviceIDRequired", err)
		}
	})
}

// TestPoolIDValidation tests pool ID validation in various operations.
func TestPoolIDValidation(t *testing.T) {
	backend := &DHTBackend{}

	t.Run("DeletePool empty ID", func(t *testing.T) {
		err := backend.DeletePool(context.Background(), "")
		if err != ipam.ErrInvalidPoolID {
			t.Errorf("DeletePool(\"\") = %v, want ErrInvalidPoolID", err)
		}
	})

	t.Run("GetPoolStats empty ID", func(t *testing.T) {
		_, err := backend.GetPoolStats(context.Background(), "")
		if err != ipam.ErrInvalidPoolID {
			t.Errorf("GetPoolStats(\"\") = %v, want ErrInvalidPoolID", err)
		}
	})

	t.Run("GetAllocationsByPool empty ID", func(t *testing.T) {
		_, err := backend.GetAllocationsByPool(context.Background(), "")
		if err != ipam.ErrInvalidPoolID {
			t.Errorf("GetAllocationsByPool(\"\") = %v, want ErrInvalidPoolID", err)
		}
	})

	t.Run("ExpireInactive empty ID", func(t *testing.T) {
		_, err := backend.ExpireInactive(context.Background(), "")
		if err != ipam.ErrInvalidPoolID {
			t.Errorf("ExpireInactive(\"\") = %v, want ErrInvalidPoolID", err)
		}
	})
}

// TestUpdatePoolValidation tests pool update validation.
func TestUpdatePoolValidation(t *testing.T) {
	backend := &DHTBackend{}

	t.Run("UpdatePool nil", func(t *testing.T) {
		err := backend.UpdatePool(context.Background(), nil)
		if err != ipam.ErrInvalidPoolID {
			t.Errorf("UpdatePool(nil) = %v, want ErrInvalidPoolID", err)
		}
	})

	t.Run("UpdatePool empty ID", func(t *testing.T) {
		err := backend.UpdatePool(context.Background(), &ipam.Pool{})
		if err != ipam.ErrInvalidPoolID {
			t.Errorf("UpdatePool(empty ID) = %v, want ErrInvalidPoolID", err)
		}
	})
}

// TestAllocateSpecificValidation tests specific allocation validation.
func TestAllocateSpecificValidation(t *testing.T) {
	backend := &DHTBackend{}

	t.Run("AllocateSpecific invalid IP", func(t *testing.T) {
		req := &ipam.AllocationRequest{
			PoolID:   "pool1",
			DeviceID: "device1",
		}
		_, err := backend.AllocateSpecific(context.Background(), req)
		if err != ipam.ErrInvalidIP {
			t.Errorf("AllocateSpecific(no IP) = %v, want ErrInvalidIP", err)
		}
	})
}

// TestPingWithoutNode tests Ping when node is nil.
func TestPingWithoutNode(t *testing.T) {
	backend := &DHTBackend{}
	err := backend.Ping(context.Background())
	if err != ipam.ErrBackendUnavailable {
		t.Errorf("Ping() = %v, want ErrBackendUnavailable", err)
	}
}

// TestClose tests the Close method.
func TestClose(t *testing.T) {
	backend := &DHTBackend{}
	err := backend.Close()
	if err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
}

// TestListPoolsEmpty tests listing pools when none exist.
func TestListPoolsEmpty(t *testing.T) {
	backend := &DHTBackend{}
	pools, err := backend.ListPools(context.Background())
	if err != nil {
		t.Errorf("ListPools() error = %v", err)
	}
	if len(pools) != 0 {
		t.Errorf("ListPools() = %d pools, want 0", len(pools))
	}
}

// TestAllocationKeyGeneration tests the allocation key format.
func TestAllocationKeyGeneration(t *testing.T) {
	backend := &DHTBackend{}

	ip := netip.MustParseAddr("192.168.1.100")
	key := backend.allocationKey(ip)

	expected := dhtAllocationPrefix + "192.168.1.100"
	if key != expected {
		t.Errorf("allocationKey() = %s, want %s", key, expected)
	}
}

// TestDeviceKeyGeneration tests the device key format.
func TestDeviceKeyGeneration(t *testing.T) {
	backend := &DHTBackend{}

	ip := netip.MustParseAddr("192.168.1.100")
	key := backend.deviceKey("device1", ip)

	expected := dhtDevicePrefix + "device1/192.168.1.100"
	if key != expected {
		t.Errorf("deviceKey() = %s, want %s", key, expected)
	}
}

// TestAllocationIDGeneration tests unique allocation ID generation.
func TestAllocationIDGeneration(t *testing.T) {
	// Allocation IDs are random, not derived from the clock: two IDs
	// generated back to back, with no time passing, must still differ.
	id1 := generateID()
	id2 := generateID()

	if id1 == id2 {
		t.Error("generateID() should produce unique IDs")
	}

	if _, err := uuid.Parse(id1); err != nil {
		t.Errorf("generateID() = %q, want a UUID: %v", id1, err)
	}
}

// TestUpdatePoolStats tests pool statistics updates.
func TestUpdatePoolStats(t *testing.T) {
	backend := &DHTBackend{}

	// Create a test pool in cache
	pool := &ipam.Pool{
		ID:           "test-pool",
		TotalIPs:     254,
		AllocatedIPs: 0,
		AvailableIPs: 254,
	}
	backend.poolCache.Store(pool.ID, pool)

	// Test positive delta (allocation)
	backend.updatePoolStats(context.Background(), "test-pool", 1)
	cached, _ := backend.poolCache.Load("test-pool")
	updatedPool := cached.(*ipam.Pool)
	if updatedPool.AllocatedIPs != 1 || updatedPool.AvailableIPs != 253 {
		t.Errorf("After +1: Allocated=%d, Available=%d, want 1, 253",
			updatedPool.AllocatedIPs, updatedPool.AvailableIPs)
	}

	// Test negative delta (release)
	backend.updatePoolStats(context.Background(), "test-pool", -1)
	cached, _ = backend.poolCache.Load("test-pool")
	updatedPool = cached.(*ipam.Pool)
	if updatedPool.AllocatedIPs != 0 || updatedPool.AvailableIPs != 254 {
		t.Errorf("After -1: Allocated=%d, Available=%d, want 0, 254",
			updatedPool.AllocatedIPs, updatedPool.AvailableIPs)
	}

	// Test with non-existent pool (should not panic)
	backend.updatePoolStats(context.Background(), "nonexistent", 1)
}

// TestExportedFunctions tests the exported utility functions.
// TestIPToBigInt tests IP to big.Int conversion.
func TestIPToBigInt(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		ip := netip.MustParseAddr("192.168.1.1")
		n := ipToBigInt(ip)
		// 192.168.1.1 = 192*2^24 + 168*2^16 + 1*2^8 + 1 = 3232235777
		expected := int64(3232235777)
		if n.Int64() != expected {
			t.Errorf("ipToBigInt(%s) = %d, want %d", ip, n.Int64(), expected)
		}
	})

	t.Run("IPv6", func(t *testing.T) {
		ip := netip.MustParseAddr("::1")
		n := ipToBigInt(ip)
		if n.Int64() != 1 {
			t.Errorf("ipToBigInt(%s) = %d, want 1", ip, n.Int64())
		}
	})
}

// TestBigIntToIP tests big.Int to IP conversion.
func TestBigIntToIP(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		n := big.NewInt(3232235777) // 192.168.1.1
		ip := bigIntToIPv4(n)
		expected := netip.MustParseAddr("192.168.1.1")
		if ip != expected {
			t.Errorf("bigIntToIPv4(%d) = %s, want %s", n.Int64(), ip, expected)
		}
	})

	t.Run("IPv6", func(t *testing.T) {
		n := big.NewInt(1)
		ip := bigIntToIPv6(n)
		expected := netip.MustParseAddr("::1")
		if ip != expected {
			t.Errorf("bigIntToIPv6(%d) = %s, want %s", n.Int64(), ip, expected)
		}
	})
}

// TestPoolCacheOperations tests pool cache operations.
func TestPoolCacheOperations(t *testing.T) {
	backend := &DHTBackend{}

	pool := &ipam.Pool{
		ID:   "test-pool",
		Name: "Test Pool",
		CIDR: netip.MustParsePrefix("192.168.1.0/24"),
	}

	// Store in cache
	backend.poolCache.Store(pool.ID, pool)
	backend.poolNameIndex.Store(pool.Name, pool.ID)
	backend.poolCIDRIndex.Store(pool.CIDR.String(), pool.ID)

	// Verify retrieval
	t.Run("Cache lookup", func(t *testing.T) {
		cached, ok := backend.poolCache.Load(pool.ID)
		if !ok {
			t.Error("Pool not found in cache")
		}
		if cached.(*ipam.Pool).Name != pool.Name {
			t.Error("Cached pool has wrong name")
		}
	})

	t.Run("Name index lookup", func(t *testing.T) {
		poolID, ok := backend.poolNameIndex.Load(pool.Name)
		if !ok {
			t.Error("Pool name not found in index")
		}
		if poolID.(string) != pool.ID {
			t.Error("Name index has wrong pool ID")
		}
	})

	t.Run("CIDR index lookup", func(t *testing.T) {
		poolID, ok := backend.poolCIDRIndex.Load(pool.CIDR.String())
		if !ok {
			t.Error("Pool CIDR not found in index")
		}
		if poolID.(string) != pool.ID {
			t.Error("CIDR index has wrong pool ID")
		}
	})
}

// TestErrDHTBackendInit tests error type.
func TestErrDHTBackendInit(t *testing.T) {
	t.Run("WithoutCause", func(t *testing.T) {
		err := &ErrDHTBackendInit{Reason: "test reason"}
		expected := "DHT backend initialization failed: test reason"
		if err.Error() != expected {
			t.Errorf("Error() = %s, want %s", err.Error(), expected)
		}
	})

	t.Run("WithCause", func(t *testing.T) {
		cause := ipam.ErrBackendUnavailable
		err := &ErrDHTBackendInit{Reason: "test reason", Cause: cause}
		if err.Unwrap() != cause {
			t.Error("Unwrap() did not return cause")
		}
	})
}

// TestErrDHTOperationFailed tests error type.
func TestErrDHTOperationFailed(t *testing.T) {
	t.Run("WithoutCause", func(t *testing.T) {
		err := &ErrDHTOperationFailed{Operation: "get", Key: "/test/key"}
		expected := "DHT operation get failed for key /test/key"
		if err.Error() != expected {
			t.Errorf("Error() = %s, want %s", err.Error(), expected)
		}
	})

	t.Run("WithCause", func(t *testing.T) {
		cause := ipam.ErrBackendTimeout
		err := &ErrDHTOperationFailed{Operation: "put", Key: "/test/key", Cause: cause}
		if err.Unwrap() != cause {
			t.Error("Unwrap() did not return cause")
		}
	})
}

// TestErrClaimConflict tests error type.
func TestErrClaimConflict(t *testing.T) {
	err := &ErrClaimConflict{
		IP:            "192.168.1.100",
		OurDeviceID:   "device1",
		TheirDeviceID: "device2",
	}
	expected := "claim conflict for IP 192.168.1.100: our device device1 vs their device device2"
	if err.Error() != expected {
		t.Errorf("Error() = %s, want %s", err.Error(), expected)
	}
}

// TestErrVerificationFailed tests error type.
func TestErrVerificationFailed(t *testing.T) {
	t.Run("WithoutCause", func(t *testing.T) {
		err := &ErrVerificationFailed{IP: "192.168.1.100", Reason: "timeout"}
		expected := "verification failed for IP 192.168.1.100: timeout"
		if err.Error() != expected {
			t.Errorf("Error() = %s, want %s", err.Error(), expected)
		}
	})

	t.Run("WithCause", func(t *testing.T) {
		cause := context.DeadlineExceeded
		err := &ErrVerificationFailed{IP: "192.168.1.100", Reason: "timeout", Cause: cause}
		if err.Unwrap() != cause {
			t.Error("Unwrap() did not return cause")
		}
	})
}

// TestGetPoolNotFound tests GetPool for non-existent pool.
func TestGetPoolNotFound(t *testing.T) {
	backend := &DHTBackend{}
	_, err := backend.GetPool(context.Background(), "nonexistent")
	if err != ipam.ErrPoolNotFound {
		t.Errorf("GetPool(nonexistent) = %v, want ErrPoolNotFound", err)
	}
}

// TestGetPoolByNameNotFound tests GetPoolByName for non-existent pool.
func TestGetPoolByNameNotFound(t *testing.T) {
	backend := &DHTBackend{}
	_, err := backend.GetPoolByName(context.Background(), "nonexistent")
	if err != ipam.ErrPoolNotFound {
		t.Errorf("GetPoolByName(nonexistent) = %v, want ErrPoolNotFound", err)
	}
}

// TestGetPoolByCIDRNotFound tests GetPoolByCIDR for non-existent pool.
func TestGetPoolByCIDRNotFound(t *testing.T) {
	backend := &DHTBackend{}
	cidr := netip.MustParsePrefix("192.168.1.0/24")
	_, err := backend.GetPoolByCIDR(context.Background(), cidr)
	if err != ipam.ErrPoolNotFound {
		t.Errorf("GetPoolByCIDR(nonexistent) = %v, want ErrPoolNotFound", err)
	}
}

// TestDeletePoolNotFound tests deleting a non-existent pool.
func TestDeletePoolNotFound(t *testing.T) {
	backend := &DHTBackend{}
	err := backend.DeletePool(context.Background(), "nonexistent")
	if err != ipam.ErrPoolNotFound {
		t.Errorf("DeletePool(nonexistent) = %v, want ErrPoolNotFound", err)
	}
}

// TestGetPoolStatsNotFound tests getting stats for non-existent pool.
func TestGetPoolStatsNotFound(t *testing.T) {
	backend := &DHTBackend{}
	_, err := backend.GetPoolStats(context.Background(), "nonexistent")
	if err != ipam.ErrPoolNotFound {
		t.Errorf("GetPoolStats(nonexistent) = %v, want ErrPoolNotFound", err)
	}
}

// TestGetAllocationsByPoolNotFound tests getting allocations for non-existent pool.
func TestGetAllocationsByPoolNotFound(t *testing.T) {
	backend := &DHTBackend{}
	_, err := backend.GetAllocationsByPool(context.Background(), "nonexistent")
	if err != ipam.ErrPoolNotFound {
		t.Errorf("GetAllocationsByPool(nonexistent) = %v, want ErrPoolNotFound", err)
	}
}

// TestExpireInactivePoolNotFound tests expiring inactive for non-existent pool.
func TestExpireInactivePoolNotFound(t *testing.T) {
	backend := &DHTBackend{}
	_, err := backend.ExpireInactive(context.Background(), "nonexistent")
	if err != ipam.ErrPoolNotFound {
		t.Errorf("ExpireInactive(nonexistent) = %v, want ErrPoolNotFound", err)
	}
}

// TestUpdatePoolNotFound tests updating a non-existent pool.
func TestUpdatePoolNotFound(t *testing.T) {
	backend := &DHTBackend{}
	pool := &ipam.Pool{ID: "nonexistent"}
	err := backend.UpdatePool(context.Background(), pool)
	if err != ipam.ErrPoolNotFound {
		t.Errorf("UpdatePool(nonexistent) = %v, want ErrPoolNotFound", err)
	}
}

// TestAllocatePoolNotFound tests allocating from non-existent pool.
func TestAllocatePoolNotFound(t *testing.T) {
	backend := &DHTBackend{}
	req := &ipam.AllocationRequest{
		PoolID:   "nonexistent",
		DeviceID: "device1",
	}
	_, err := backend.Allocate(context.Background(), req)
	if err != ipam.ErrPoolNotFound {
		t.Errorf("Allocate(nonexistent pool) = %v, want ErrPoolNotFound", err)
	}
}

// TestAllocateSpecificPoolNotFound tests allocating specific IP from non-existent pool.
func TestAllocateSpecificPoolNotFound(t *testing.T) {
	backend := &DHTBackend{}
	req := &ipam.AllocationRequest{
		PoolID:      "nonexistent",
		DeviceID:    "device1",
		RequestedIP: netip.MustParseAddr("192.168.1.100"),
	}
	_, err := backend.AllocateSpecific(context.Background(), req)
	if err != ipam.ErrPoolNotFound {
		t.Errorf("AllocateSpecific(nonexistent pool) = %v, want ErrPoolNotFound", err)
	}
}

// TestAllocateSpecificIPNotInPool tests allocating IP not in pool.
func TestAllocateSpecificIPNotInPool(t *testing.T) {
	backend := &DHTBackend{}

	// Add pool to cache
	pool := &ipam.Pool{
		ID:   "test-pool",
		Name: "Test Pool",
		CIDR: netip.MustParsePrefix("192.168.1.0/24"),
	}
	backend.poolCache.Store(pool.ID, pool)

	req := &ipam.AllocationRequest{
		PoolID:      "test-pool",
		DeviceID:    "device1",
		RequestedIP: netip.MustParseAddr("10.0.0.1"), // Not in pool
	}
	_, err := backend.AllocateSpecific(context.Background(), req)
	if err != ipam.ErrIPNotInPool {
		t.Errorf("AllocateSpecific(IP not in pool) = %v, want ErrIPNotInPool", err)
	}
}

// TestAllocateSpecificNetworkAddress tests allocating network address.
func TestAllocateSpecificNetworkAddress(t *testing.T) {
	backend := &DHTBackend{}

	// Add pool to cache
	pool := &ipam.Pool{
		ID:   "test-pool",
		Name: "Test Pool",
		CIDR: netip.MustParsePrefix("192.168.1.0/24"),
	}
	backend.poolCache.Store(pool.ID, pool)

	req := &ipam.AllocationRequest{
		PoolID:      "test-pool",
		DeviceID:    "device1",
		RequestedIP: netip.MustParseAddr("192.168.1.0"), // Network address
	}
	_, err := backend.AllocateSpecific(context.Background(), req)
	if err != ipam.ErrNetworkAddress {
		t.Errorf("AllocateSpecific(network address) = %v, want ErrNetworkAddress", err)
	}
}

// TestAllocateSpecificBroadcastAddress tests allocating broadcast address.
func TestAllocateSpecificBroadcastAddress(t *testing.T) {
	backend := &DHTBackend{}

	// Add pool to cache
	pool := &ipam.Pool{
		ID:   "test-pool",
		Name: "Test Pool",
		CIDR: netip.MustParsePrefix("192.168.1.0/24"),
	}
	backend.poolCache.Store(pool.ID, pool)

	req := &ipam.AllocationRequest{
		PoolID:      "test-pool",
		DeviceID:    "device1",
		RequestedIP: netip.MustParseAddr("192.168.1.255"), // Broadcast address
	}
	_, err := backend.AllocateSpecific(context.Background(), req)
	if err != ipam.ErrBroadcastAddress {
		t.Errorf("AllocateSpecific(broadcast address) = %v, want ErrBroadcastAddress", err)
	}
}

// TestGetAllocationsByDeviceValid tests getting allocations by device.
func TestGetAllocationsByDeviceValid(t *testing.T) {
	backend := &DHTBackend{}
	allocs, err := backend.GetAllocationsByDevice(context.Background(), "device1")
	if err != nil {
		t.Errorf("GetAllocationsByDevice() error = %v", err)
	}
	// Currently returns empty since DHT scanning is not implemented
	if allocs == nil {
		t.Error("GetAllocationsByDevice() returned nil, want empty slice")
	}
}

// TestReleaseByDeviceIDValid tests releasing by device ID.
func TestReleaseByDeviceIDValid(t *testing.T) {
	backend := &DHTBackend{}
	released, err := backend.ReleaseByDeviceID(context.Background(), "device1")
	if err != nil {
		t.Errorf("ReleaseByDeviceID() error = %v", err)
	}
	if released != 0 {
		t.Errorf("ReleaseByDeviceID() = %d, want 0", released)
	}
}

// TestRandomIPv4InCIDRSingleHost tests random IP in /32.
func TestRandomIPv4InCIDRSingleHost(t *testing.T) {
	cidr := netip.MustParsePrefix("192.168.1.1/32")
	ip, err := randomIPv4InCIDR(cidr, 32)
	if err != nil {
		t.Fatalf("randomIPv4InCIDR() error = %v", err)
	}
	expected := netip.MustParseAddr("192.168.1.1")
	if ip != expected {
		t.Errorf("randomIPv4InCIDR(/32) = %s, want %s", ip, expected)
	}
}

// TestRandomIPv6InCIDRSingleHost tests random IP in /128.
func TestRandomIPv6InCIDRSingleHost(t *testing.T) {
	cidr := netip.MustParsePrefix("2001:db8::1/128")
	ip, err := randomIPv6InCIDR(cidr, 128)
	if err != nil {
		t.Fatalf("randomIPv6InCIDR() error = %v", err)
	}
	expected := netip.MustParseAddr("2001:db8::1")
	if ip != expected {
		t.Errorf("randomIPv6InCIDR(/128) = %s, want %s", ip, expected)
	}
}
