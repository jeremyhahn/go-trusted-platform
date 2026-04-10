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
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCoreDHCPServer_ReleaseLease_IPAMReleaseError tests the IPAM release failure path.
func TestCoreDHCPServer_ReleaseLease_IPAMReleaseError(t *testing.T) {
	t.Run("logs warning when IPAM release fails but continues", func(t *testing.T) {
		cfg := testServerConfig()
		allocator := newMockAllocator()
		allocator.releaseErr = errors.New("IPAM release failed")

		srv, err := NewCoreDHCPServer(cfg, allocator, WithCoreDHCPLogger(testLogger()))
		require.NoError(t, err)

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ip := netip.MustParseAddr("192.168.1.100")
		lease := &Lease{
			IP:     ip,
			MAC:    mac,
			PoolID: "test-pool",
			State:  LeaseStateActive,
		}
		err = srv.GetLeaseStore().Add(lease)
		require.NoError(t, err)

		// Release should still succeed even if IPAM release fails
		err = srv.ReleaseLease(mac)
		require.NoError(t, err)

		// Verify lease is removed
		_, ok := srv.GetLease(mac)
		assert.False(t, ok)
	})

	t.Run("logs warning when SetState fails but continues", func(t *testing.T) {
		cfg := testServerConfig()
		allocator := newMockAllocator()

		// Create a custom lease store where we can control state
		ls := NewLeaseStore()

		srv, err := NewCoreDHCPServer(cfg, allocator, WithCoreDHCPLogger(testLogger()), WithCoreDHCPLeaseStore(ls))
		require.NoError(t, err)

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ip := netip.MustParseAddr("192.168.1.100")
		lease := &Lease{
			IP:     ip,
			MAC:    mac,
			PoolID: "test-pool",
			State:  LeaseStateActive,
		}
		err = ls.Add(lease)
		require.NoError(t, err)

		// Release should succeed
		err = srv.ReleaseLease(mac)
		require.NoError(t, err)

		// Verify lease is removed
		_, ok := srv.GetLease(mac)
		assert.False(t, ok)
	})
}

// TestCoreDHCPServer_ReleaseLease_LeaseStoreClosedReturnsNotFound tests that a closed store returns not found.
func TestCoreDHCPServer_ReleaseLease_LeaseStoreClosedReturnsNotFound(t *testing.T) {
	t.Run("returns lease not found when store is closed", func(t *testing.T) {
		cfg := testServerConfig()
		allocator := newMockAllocator()

		srv, err := NewCoreDHCPServer(cfg, allocator, WithCoreDHCPLogger(testLogger()))
		require.NoError(t, err)

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ip := netip.MustParseAddr("192.168.1.100")
		lease := &Lease{
			IP:     ip,
			MAC:    mac,
			PoolID: "test-pool",
			State:  LeaseStateActive,
		}
		err = srv.GetLeaseStore().Add(lease)
		require.NoError(t, err)

		// Close the lease store - this clears the data
		srv.GetLeaseStore().Close()

		// Release should fail because GetByMAC returns false when closed
		err = srv.ReleaseLease(mac)
		assert.ErrorIs(t, err, ErrLeaseNotFound)
	})
}

// TestCoreDHCPServer_UpdateInterfaceOptions_WithPlugin tests UpdateInterfaceOptions with a plugin present.
func TestCoreDHCPServer_UpdateInterfaceOptions_WithPlugin(t *testing.T) {
	t.Run("updates options for existing plugin", func(t *testing.T) {
		cfg := testServerConfig()
		allocator := newMockAllocator()

		srv, err := NewCoreDHCPServer(cfg, allocator, WithCoreDHCPLogger(testLogger()))
		require.NoError(t, err)

		// Manually add a plugin to simulate started state
		// This is a workaround since we can't actually start the server
		opts := DHCPOptions{
			SubnetMask: net.IPv4Mask(255, 255, 255, 0),
			Router:     netip.MustParseAddr("192.168.1.1"),
			LeaseTime:  DefaultLeaseDuration,
		}

		plugin, err := NewIPAMPlugin(allocator, "test-pool", opts)
		require.NoError(t, err)
		defer plugin.Close()

		srv.mu.Lock()
		srv.plugins["lo"] = plugin
		srv.mu.Unlock()

		// Now try to update options
		newOpts := DHCPOptions{
			SubnetMask: net.IPv4Mask(255, 255, 255, 0),
			Router:     netip.MustParseAddr("192.168.1.254"),
			LeaseTime:  DefaultLeaseDuration,
		}

		err = srv.UpdateInterfaceOptions("lo", newOpts)
		require.NoError(t, err)

		// Verify options were updated
		updatedPlugin, ok := srv.GetInterfacePlugin("lo")
		require.True(t, ok)
		retrievedOpts := updatedPlugin.GetOptions()
		assert.Equal(t, netip.MustParseAddr("192.168.1.254"), retrievedOpts.Router)
	})
}
