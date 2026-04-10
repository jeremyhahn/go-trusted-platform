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
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam/backends"
)

// TestIPAMPlugin_HandleRelease_ConcurrentReleases tests concurrent release
// operations to try to trigger the Remove error path.
func TestIPAMPlugin_HandleRelease_ConcurrentReleases(t *testing.T) {
	ctx := context.Background()
	allocator := backends.NewMemoryBackend()
	defer allocator.Close()

	poolID := "test-pool"
	err := allocator.CreatePool(ctx, &ipam.Pool{
		ID:                   poolID,
		Name:                 "test-pool",
		CIDR:                 netip.MustParsePrefix("192.168.0.0/16"),
		Gateway:              netip.MustParseAddr("192.168.1.1"),
		DefaultLeaseDuration: 24 * time.Hour,
	})
	require.NoError(t, err)

	opts := DHCPOptions{
		SubnetMask: net.CIDRMask(16, 32),
		Router:     netip.MustParseAddr("192.168.1.1"),
		LeaseTime:  time.Hour,
	}

	plugin, err := NewIPAMPlugin(allocator, poolID, opts)
	require.NoError(t, err)
	defer plugin.Close()

	handler := plugin.Handler4()

	t.Run("handles concurrent release attempts for same IP", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:CC:01")

		// Get a lease
		discoverReq, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		discoverResp, _ := dhcpv4.NewReplyFromRequest(discoverReq)
		discoverResp.ServerIPAddr = net.ParseIP("192.168.1.1")

		offerResult, _ := handler(discoverReq, discoverResp)
		require.NotNil(t, offerResult)
		leasedIP := offerResult.YourIPAddr

		// Try to release the same IP from multiple goroutines
		var wg sync.WaitGroup
		const numGoroutines = 10

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				releaseReq, _ := dhcpv4.New(
					dhcpv4.WithHwAddr(mac),
					dhcpv4.WithMessageType(dhcpv4.MessageTypeRelease),
					dhcpv4.WithClientIP(leasedIP),
				)
				releaseResp, _ := dhcpv4.NewReplyFromRequest(releaseReq)

				result, stop := handler(releaseReq, releaseResp)
				// Release should not return a response
				assert.Nil(t, result)
				assert.True(t, stop)
			}()
		}

		wg.Wait()

		// Verify lease is gone
		leasedIPAddr, _ := netip.AddrFromSlice(leasedIP.To4())
		_, found := plugin.GetLeaseStore().GetByIP(leasedIPAddr)
		assert.False(t, found)
	})

	t.Run("handles many concurrent releases for different IPs", func(t *testing.T) {
		const numLeases = 50
		var wg sync.WaitGroup

		// First, get leases for multiple MACs
		type leaseInfo struct {
			mac net.HardwareAddr
			ip  net.IP
		}
		leases := make([]leaseInfo, numLeases)

		for i := 0; i < numLeases; i++ {
			macBytes := []byte{0x00, 0x11, 0x22, 0x33, byte(i / 256), byte(i % 256)}
			mac := net.HardwareAddr(macBytes)

			discoverReq, _ := dhcpv4.New(
				dhcpv4.WithHwAddr(mac),
				dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
			)
			discoverResp, _ := dhcpv4.NewReplyFromRequest(discoverReq)
			discoverResp.ServerIPAddr = net.ParseIP("192.168.1.1")

			offerResult, _ := handler(discoverReq, discoverResp)
			if offerResult != nil {
				leases[i] = leaseInfo{mac: mac, ip: offerResult.YourIPAddr}
			}
		}

		// Now release all concurrently
		for i := 0; i < numLeases; i++ {
			if leases[i].ip == nil {
				continue
			}
			wg.Add(1)
			go func(lease leaseInfo) {
				defer wg.Done()
				releaseReq, _ := dhcpv4.New(
					dhcpv4.WithHwAddr(lease.mac),
					dhcpv4.WithMessageType(dhcpv4.MessageTypeRelease),
					dhcpv4.WithClientIP(lease.ip),
				)
				releaseResp, _ := dhcpv4.NewReplyFromRequest(releaseReq)

				result, stop := handler(releaseReq, releaseResp)
				assert.Nil(t, result)
				assert.True(t, stop)
			}(leases[i])
		}

		wg.Wait()

		// Verify all leases are gone
		for i := 0; i < numLeases; i++ {
			if leases[i].ip == nil {
				continue
			}
			ipAddr, _ := netip.AddrFromSlice(leases[i].ip.To4())
			_, found := plugin.GetLeaseStore().GetByIP(ipAddr)
			assert.False(t, found)
		}
	})
}

// TestCoreDHCPServer_ReleaseLease_ConcurrentOperations tests concurrent
// release operations on the server.
func TestCoreDHCPServer_ReleaseLease_ConcurrentOperations(t *testing.T) {
	cfg := testServerConfig()
	allocator := newMockAllocator()

	t.Run("handles concurrent releases of same lease with high concurrency", func(t *testing.T) {
		// Run multiple iterations to increase chance of hitting race condition
		for iteration := 0; iteration < 10; iteration++ {
			srv, err := NewCoreDHCPServer(cfg, allocator, WithCoreDHCPLogger(testLogger()))
			require.NoError(t, err)

			mac, _ := net.ParseMAC("00:11:22:33:EE:01")
			ip := netip.MustParseAddr("192.168.1.100")

			// Add a lease
			lease := &Lease{
				IP:        ip,
				MAC:       mac,
				PoolID:    "test-pool",
				State:     LeaseStateActive,
				ExpiresAt: time.Now().Add(time.Hour),
			}
			err = srv.GetLeaseStore().Add(lease)
			require.NoError(t, err)

			// Try to release from many goroutines concurrently
			var wg sync.WaitGroup
			const numGoroutines = 50

			for i := 0; i < numGoroutines; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					// Ignore errors - we expect some to fail due to race
					_ = srv.ReleaseLease(mac)
				}()
			}

			wg.Wait()

			// Verify lease is gone
			_, ok := srv.GetLease(mac)
			assert.False(t, ok)
		}
	})

	t.Run("handles release with nil MAC", func(t *testing.T) {
		srv, err := NewCoreDHCPServer(cfg, allocator, WithCoreDHCPLogger(testLogger()))
		require.NoError(t, err)

		// nil MAC should return error
		err = srv.ReleaseLease(nil)
		assert.ErrorIs(t, err, ErrInvalidMAC)
	})

	t.Run("handles release after store is modified", func(t *testing.T) {
		ls := NewLeaseStore()
		srv, err := NewCoreDHCPServer(cfg, allocator, WithCoreDHCPLogger(testLogger()), WithCoreDHCPLeaseStore(ls))
		require.NoError(t, err)

		mac, _ := net.ParseMAC("00:11:22:33:BB:02")
		ip := netip.MustParseAddr("192.168.1.101")

		// Add a lease
		lease := &Lease{
			IP:        ip,
			MAC:       mac,
			PoolID:    "test-pool",
			State:     LeaseStateActive,
			ExpiresAt: time.Now().Add(time.Hour),
		}
		err = ls.Add(lease)
		require.NoError(t, err)

		// Release should succeed
		err = srv.ReleaseLease(mac)
		require.NoError(t, err)

		// Verify lease is gone
		_, ok := srv.GetLease(mac)
		assert.False(t, ok)
	})
}
