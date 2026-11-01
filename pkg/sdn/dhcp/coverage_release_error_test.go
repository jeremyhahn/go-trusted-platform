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
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
