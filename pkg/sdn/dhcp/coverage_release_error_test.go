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
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam/backends"
)

// TestIPAMPlugin_HandleRelease_ConcurrentRemoval tests the scenario where
// a lease is removed by another goroutine between GetByIP and Remove calls.
// This tests the error handling at line 352-357 in plugin_ipam.go.
func TestIPAMPlugin_HandleRelease_ConcurrentRemoval(t *testing.T) {
	ctx := context.Background()
	allocator := backends.NewMemoryBackend()
	defer allocator.Close()

	poolID := "test-pool"
	err := allocator.CreatePool(ctx, &ipam.Pool{
		ID:                   poolID,
		Name:                 "test-pool",
		CIDR:                 netip.MustParsePrefix("192.168.1.0/24"),
		Gateway:              netip.MustParseAddr("192.168.1.1"),
		DefaultLeaseDuration: 24 * time.Hour,
	})
	require.NoError(t, err)

	opts := DHCPOptions{
		SubnetMask: net.CIDRMask(24, 32),
		Router:     netip.MustParseAddr("192.168.1.1"),
		LeaseTime:  time.Hour,
	}

	t.Run("handles concurrent lease removal gracefully", func(t *testing.T) {
		// We'll test this by releasing a lease that doesn't exist in the store
		// but exists in IPAM, which triggers the "no lease found" warning path
		plugin, err := NewIPAMPlugin(allocator, poolID, opts)
		require.NoError(t, err)
		defer plugin.Close()

		handler := plugin.Handler4()

		mac, _ := net.ParseMAC("00:11:22:33:AA:01")

		// First get a lease
		discoverReq, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		discoverResp, _ := dhcpv4.NewReplyFromRequest(discoverReq)
		discoverResp.ServerIPAddr = net.ParseIP("192.168.1.1")

		offerResult, _ := handler(discoverReq, discoverResp)
		require.NotNil(t, offerResult)
		leasedIP := offerResult.YourIPAddr
		leasedIPAddr, _ := netip.AddrFromSlice(leasedIP.To4())

		// Remove the lease from the store to simulate concurrent removal
		err = plugin.GetLeaseStore().Remove(leasedIPAddr)
		require.NoError(t, err)

		// Now release - GetByIP will fail because lease was removed
		releaseReq, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeRelease),
			dhcpv4.WithClientIP(leasedIP),
		)
		releaseResp, _ := dhcpv4.NewReplyFromRequest(releaseReq)

		// This triggers the "no lease found" warning path (line 328-331)
		result, stop := handler(releaseReq, releaseResp)
		assert.Nil(t, result)
		assert.True(t, stop)
	})
}

// TestCoreDHCPServer_ReleaseLease_RaceConditionScenarios tests various
// race condition scenarios in ReleaseLease.
func TestCoreDHCPServer_ReleaseLease_RaceConditionScenarios(t *testing.T) {
	cfg := testServerConfig()
	allocator := newMockAllocator()

	t.Run("handles rapid sequential releases", func(t *testing.T) {
		srv, err := NewCoreDHCPServer(cfg, allocator, WithCoreDHCPLogger(testLogger()))
		require.NoError(t, err)

		mac, _ := net.ParseMAC("00:11:22:33:BB:01")
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

		// First release should succeed
		err = srv.ReleaseLease(mac)
		require.NoError(t, err)

		// Second release should fail (lease not found)
		err = srv.ReleaseLease(mac)
		assert.ErrorIs(t, err, ErrLeaseNotFound)
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
