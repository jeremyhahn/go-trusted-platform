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

// TestLeaseStore_ClosedOperations tests operations on a closed LeaseStore.
func TestLeaseStore_ClosedOperations(t *testing.T) {
	t.Run("GetByIP returns false when closed", func(t *testing.T) {
		ls := NewLeaseStore()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ip := netip.MustParseAddr("192.168.1.100")

		lease := &Lease{
			IP:    ip,
			MAC:   mac,
			State: LeaseStateActive,
		}
		err := ls.Add(lease)
		require.NoError(t, err)

		err = ls.Close()
		require.NoError(t, err)

		_, ok := ls.GetByIP(ip)
		assert.False(t, ok)
	})

	t.Run("GetByMAC returns false when closed", func(t *testing.T) {
		ls := NewLeaseStore()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ip := netip.MustParseAddr("192.168.1.100")

		lease := &Lease{
			IP:    ip,
			MAC:   mac,
			State: LeaseStateActive,
		}
		err := ls.Add(lease)
		require.NoError(t, err)

		err = ls.Close()
		require.NoError(t, err)

		_, ok := ls.GetByMAC(mac)
		assert.False(t, ok)
	})

	t.Run("Remove returns error when closed", func(t *testing.T) {
		ls := NewLeaseStore()
		ip := netip.MustParseAddr("192.168.1.100")

		err := ls.Close()
		require.NoError(t, err)

		err = ls.Remove(ip)
		assert.ErrorIs(t, err, ErrPluginClosed)
	})

	t.Run("RemoveByMAC returns error when closed", func(t *testing.T) {
		ls := NewLeaseStore()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")

		err := ls.Close()
		require.NoError(t, err)

		err = ls.RemoveByMAC(mac)
		assert.ErrorIs(t, err, ErrPluginClosed)
	})

	t.Run("Renew returns error when closed", func(t *testing.T) {
		ls := NewLeaseStore()
		ip := netip.MustParseAddr("192.168.1.100")

		err := ls.Close()
		require.NoError(t, err)

		err = ls.Renew(ip, time.Hour)
		assert.ErrorIs(t, err, ErrPluginClosed)
	})

	t.Run("SetState returns error when closed", func(t *testing.T) {
		ls := NewLeaseStore()
		ip := netip.MustParseAddr("192.168.1.100")

		err := ls.Close()
		require.NoError(t, err)

		err = ls.SetState(ip, LeaseStateReleased)
		assert.ErrorIs(t, err, ErrPluginClosed)
	})

	t.Run("ExpireOld returns 0 when closed", func(t *testing.T) {
		ls := NewLeaseStore()

		err := ls.Close()
		require.NoError(t, err)

		count := ls.ExpireOld()
		assert.Equal(t, 0, count)
	})

	t.Run("Count returns 0 when closed", func(t *testing.T) {
		ls := NewLeaseStore()

		err := ls.Close()
		require.NoError(t, err)

		count := ls.Count()
		assert.Equal(t, 0, count)
	})

	t.Run("CountActive returns 0 when closed", func(t *testing.T) {
		ls := NewLeaseStore()

		err := ls.Close()
		require.NoError(t, err)

		count := ls.CountActive()
		assert.Equal(t, 0, count)
	})

	t.Run("All returns nil when closed", func(t *testing.T) {
		ls := NewLeaseStore()

		err := ls.Close()
		require.NoError(t, err)

		leases := ls.All()
		assert.Nil(t, leases)
	})

	t.Run("AllActive returns nil when closed", func(t *testing.T) {
		ls := NewLeaseStore()

		err := ls.Close()
		require.NoError(t, err)

		leases := ls.AllActive()
		assert.Nil(t, leases)
	})

	t.Run("Clear does nothing when closed", func(t *testing.T) {
		ls := NewLeaseStore()

		err := ls.Close()
		require.NoError(t, err)

		// Should not panic
		ls.Clear()
	})
}

// TestLeaseStore_EmptyMACOperations tests operations with empty MAC addresses.
func TestLeaseStore_EmptyMACOperations(t *testing.T) {
	t.Run("GetByMAC returns false for empty MAC", func(t *testing.T) {
		ls := NewLeaseStore()

		_, ok := ls.GetByMAC(net.HardwareAddr{})
		assert.False(t, ok)
	})

	t.Run("RemoveByMAC returns error for empty MAC", func(t *testing.T) {
		ls := NewLeaseStore()

		err := ls.RemoveByMAC(net.HardwareAddr{})
		assert.ErrorIs(t, err, ErrInvalidMAC)
	})

	t.Run("Add returns error for empty MAC", func(t *testing.T) {
		ls := NewLeaseStore()
		ip := netip.MustParseAddr("192.168.1.100")

		lease := &Lease{
			IP:    ip,
			MAC:   net.HardwareAddr{},
			State: LeaseStateActive,
		}

		err := ls.Add(lease)
		assert.ErrorIs(t, err, ErrInvalidMAC)
	})
}

// TestLeaseStore_InvalidIPOperations tests operations with invalid IP addresses.
func TestLeaseStore_InvalidIPOperations(t *testing.T) {
	t.Run("Renew returns error for invalid IP", func(t *testing.T) {
		ls := NewLeaseStore()

		err := ls.Renew(netip.Addr{}, time.Hour)
		assert.ErrorIs(t, err, ErrInvalidIP)
	})

	t.Run("SetState returns error for invalid IP", func(t *testing.T) {
		ls := NewLeaseStore()

		err := ls.SetState(netip.Addr{}, LeaseStateReleased)
		assert.ErrorIs(t, err, ErrInvalidIP)
	})
}
