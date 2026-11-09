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
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLeaseStore(t *testing.T) {
	t.Run("creates empty store", func(t *testing.T) {
		ls := NewLeaseStore()
		require.NotNil(t, ls)
		assert.Equal(t, 0, ls.Count())
	})
}

func TestLeaseStore_Add(t *testing.T) {
	t.Run("adds valid lease", func(t *testing.T) {
		ls := NewLeaseStore()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ip := netip.MustParseAddr("192.168.1.100")

		lease := &Lease{
			IP:        ip,
			MAC:       mac,
			PoolID:    "pool-1",
			State:     LeaseStateActive,
			LeasedAt:  time.Now(),
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}

		err := ls.Add(lease)
		require.NoError(t, err)
		assert.Equal(t, 1, ls.Count())
	})

	t.Run("nil lease returns error", func(t *testing.T) {
		ls := NewLeaseStore()
		err := ls.Add(nil)
		assert.ErrorIs(t, err, ErrNilRequest)
	})

	t.Run("invalid IP returns error", func(t *testing.T) {
		ls := NewLeaseStore()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")

		lease := &Lease{
			MAC:    mac,
			PoolID: "pool-1",
		}

		err := ls.Add(lease)
		assert.ErrorIs(t, err, ErrInvalidIP)
	})

	t.Run("invalid MAC returns error", func(t *testing.T) {
		ls := NewLeaseStore()
		ip := netip.MustParseAddr("192.168.1.100")

		lease := &Lease{
			IP:     ip,
			PoolID: "pool-1",
		}

		err := ls.Add(lease)
		assert.ErrorIs(t, err, ErrInvalidMAC)
	})

	t.Run("updates existing lease for same MAC", func(t *testing.T) {
		ls := NewLeaseStore()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ip1 := netip.MustParseAddr("192.168.1.100")
		ip2 := netip.MustParseAddr("192.168.1.101")

		lease1 := &Lease{
			IP:       ip1,
			MAC:      mac,
			PoolID:   "pool-1",
			Hostname: "host1",
			State:    LeaseStateActive,
		}

		err := ls.Add(lease1)
		require.NoError(t, err)

		lease2 := &Lease{
			IP:       ip2,
			MAC:      mac,
			PoolID:   "pool-1",
			Hostname: "host2",
			State:    LeaseStateActive,
		}

		err = ls.Add(lease2)
		require.NoError(t, err)

		// Note: sync.Map does not automatically remove old IP entries
		// when MAC is updated, so count may be 2. The behavior is that
		// MAC lookup returns the new lease.
		retrieved, ok := ls.GetByMAC(mac)
		require.True(t, ok)
		assert.Equal(t, ip2, retrieved.IP)
		assert.Equal(t, "host2", retrieved.Hostname)
	})
}

func TestLeaseStore_GetByMAC(t *testing.T) {
	t.Run("returns lease for existing MAC", func(t *testing.T) {
		ls := NewLeaseStore()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ip := netip.MustParseAddr("192.168.1.100")

		lease := &Lease{
			IP:       ip,
			MAC:      mac,
			PoolID:   "pool-1",
			Hostname: "test-host",
			State:    LeaseStateActive,
		}

		err := ls.Add(lease)
		require.NoError(t, err)

		retrieved, ok := ls.GetByMAC(mac)
		require.True(t, ok)
		assert.Equal(t, ip, retrieved.IP)
		assert.Equal(t, "test-host", retrieved.Hostname)
	})

	t.Run("returns false for non-existent MAC", func(t *testing.T) {
		ls := NewLeaseStore()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")

		_, ok := ls.GetByMAC(mac)
		assert.False(t, ok)
	})

	t.Run("returns false for nil MAC", func(t *testing.T) {
		ls := NewLeaseStore()
		_, ok := ls.GetByMAC(nil)
		assert.False(t, ok)
	})

	t.Run("returns clone not original", func(t *testing.T) {
		ls := NewLeaseStore()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ip := netip.MustParseAddr("192.168.1.100")

		lease := &Lease{
			IP:       ip,
			MAC:      mac,
			Hostname: "original",
			State:    LeaseStateActive,
		}

		err := ls.Add(lease)
		require.NoError(t, err)

		retrieved, _ := ls.GetByMAC(mac)
		retrieved.Hostname = "modified"

		// Original should be unchanged
		original, _ := ls.GetByMAC(mac)
		assert.Equal(t, "original", original.Hostname)
	})
}

func TestLeaseStore_GetByIP(t *testing.T) {
	t.Run("returns lease for existing IP", func(t *testing.T) {
		ls := NewLeaseStore()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ip := netip.MustParseAddr("192.168.1.100")

		lease := &Lease{
			IP:     ip,
			MAC:    mac,
			PoolID: "pool-1",
			State:  LeaseStateActive,
		}

		err := ls.Add(lease)
		require.NoError(t, err)

		retrieved, ok := ls.GetByIP(ip)
		require.True(t, ok)
		assert.Equal(t, mac.String(), retrieved.MAC.String())
	})

	t.Run("returns false for non-existent IP", func(t *testing.T) {
		ls := NewLeaseStore()
		ip := netip.MustParseAddr("192.168.1.100")

		_, ok := ls.GetByIP(ip)
		assert.False(t, ok)
	})

	t.Run("returns false for invalid IP", func(t *testing.T) {
		ls := NewLeaseStore()
		_, ok := ls.GetByIP(netip.Addr{})
		assert.False(t, ok)
	})
}

func TestLeaseStore_Remove(t *testing.T) {
	t.Run("removes existing lease by IP", func(t *testing.T) {
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
		assert.Equal(t, 1, ls.Count())

		err = ls.Remove(ip)
		require.NoError(t, err)
		assert.Equal(t, 0, ls.Count())

		// Verify removed from both indices
		_, ok := ls.GetByIP(ip)
		assert.False(t, ok)
		_, ok = ls.GetByMAC(mac)
		assert.False(t, ok)
	})

	t.Run("returns error for non-existent IP", func(t *testing.T) {
		ls := NewLeaseStore()
		ip := netip.MustParseAddr("192.168.1.100")

		err := ls.Remove(ip)
		assert.ErrorIs(t, err, ErrLeaseNotFound)
	})

	t.Run("returns error for invalid IP", func(t *testing.T) {
		ls := NewLeaseStore()
		err := ls.Remove(netip.Addr{})
		assert.ErrorIs(t, err, ErrInvalidIP)
	})
}

func TestLeaseStore_RemoveByMAC(t *testing.T) {
	t.Run("removes existing lease by MAC", func(t *testing.T) {
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

		err = ls.RemoveByMAC(mac)
		require.NoError(t, err)
		assert.Equal(t, 0, ls.Count())
	})

	t.Run("returns error for non-existent MAC", func(t *testing.T) {
		ls := NewLeaseStore()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")

		err := ls.RemoveByMAC(mac)
		assert.ErrorIs(t, err, ErrLeaseNotFound)
	})

	t.Run("returns error for nil MAC", func(t *testing.T) {
		ls := NewLeaseStore()
		err := ls.RemoveByMAC(nil)
		assert.ErrorIs(t, err, ErrInvalidMAC)
	})
}

func TestLeaseStore_Renew(t *testing.T) {
	t.Run("renews active lease", func(t *testing.T) {
		ls := NewLeaseStore()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ip := netip.MustParseAddr("192.168.1.100")

		now := time.Now()
		lease := &Lease{
			IP:        ip,
			MAC:       mac,
			State:     LeaseStateActive,
			LeasedAt:  now,
			ExpiresAt: now.Add(1 * time.Hour),
		}

		err := ls.Add(lease)
		require.NoError(t, err)

		err = ls.Renew(ip, 24*time.Hour)
		require.NoError(t, err)

		renewed, _ := ls.GetByIP(ip)
		assert.True(t, renewed.ExpiresAt.After(now.Add(23*time.Hour)))
		assert.False(t, renewed.RenewedAt.IsZero())
	})

	t.Run("returns error for expired lease", func(t *testing.T) {
		ls := NewLeaseStore()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ip := netip.MustParseAddr("192.168.1.100")

		lease := &Lease{
			IP:        ip,
			MAC:       mac,
			State:     LeaseStateActive,
			ExpiresAt: time.Now().Add(-1 * time.Hour), // Already expired
		}

		err := ls.Add(lease)
		require.NoError(t, err)

		err = ls.Renew(ip, 24*time.Hour)
		assert.ErrorIs(t, err, ErrLeaseExpired)
	})

	t.Run("returns error for non-existent lease", func(t *testing.T) {
		ls := NewLeaseStore()
		ip := netip.MustParseAddr("192.168.1.100")

		err := ls.Renew(ip, 24*time.Hour)
		assert.ErrorIs(t, err, ErrLeaseNotFound)
	})
}

func TestLeaseStore_SetState(t *testing.T) {
	t.Run("sets lease state", func(t *testing.T) {
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

		err = ls.SetState(ip, LeaseStateReleased)
		require.NoError(t, err)

		updated, _ := ls.GetByIP(ip)
		assert.Equal(t, LeaseStateReleased, updated.State)
	})

	t.Run("returns error for non-existent lease", func(t *testing.T) {
		ls := NewLeaseStore()
		ip := netip.MustParseAddr("192.168.1.100")

		err := ls.SetState(ip, LeaseStateReleased)
		assert.ErrorIs(t, err, ErrLeaseNotFound)
	})
}

func TestLeaseStore_ExpireOld(t *testing.T) {
	t.Run("expires old leases", func(t *testing.T) {
		ls := NewLeaseStore()

		// Add active lease
		mac1, _ := net.ParseMAC("00:11:22:33:44:55")
		ip1 := netip.MustParseAddr("192.168.1.100")
		lease1 := &Lease{
			IP:        ip1,
			MAC:       mac1,
			State:     LeaseStateActive,
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}
		ls.Add(lease1)

		// Add expired lease
		mac2, _ := net.ParseMAC("00:11:22:33:44:66")
		ip2 := netip.MustParseAddr("192.168.1.101")
		lease2 := &Lease{
			IP:        ip2,
			MAC:       mac2,
			State:     LeaseStateActive,
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		}
		ls.Add(lease2)

		count := ls.ExpireOld()
		assert.Equal(t, 1, count)

		// Active lease still there
		active, _ := ls.GetByIP(ip1)
		assert.Equal(t, LeaseStateActive, active.State)
	})
}

func TestLeaseStore_Count(t *testing.T) {
	t.Run("returns correct count", func(t *testing.T) {
		ls := NewLeaseStore()
		assert.Equal(t, 0, ls.Count())

		// Add 3 leases
		macs := []string{"00:11:22:33:44:01", "00:11:22:33:44:02", "00:11:22:33:44:03"}
		ips := []string{"192.168.1.101", "192.168.1.102", "192.168.1.103"}

		for i := 0; i < 3; i++ {
			mac, _ := net.ParseMAC(macs[i])
			ip := netip.MustParseAddr(ips[i])
			lease := &Lease{IP: ip, MAC: mac, State: LeaseStateActive}
			ls.Add(lease)
		}

		assert.Equal(t, 3, ls.Count())
	})
}

func TestLeaseStore_CountActive(t *testing.T) {
	t.Run("counts only active leases", func(t *testing.T) {
		ls := NewLeaseStore()

		// Add active lease
		mac1, _ := net.ParseMAC("00:11:22:33:44:01")
		ip1 := netip.MustParseAddr("192.168.1.101")
		lease1 := &Lease{
			IP:        ip1,
			MAC:       mac1,
			State:     LeaseStateActive,
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}
		ls.Add(lease1)

		// Add released lease
		mac2, _ := net.ParseMAC("00:11:22:33:44:02")
		ip2 := netip.MustParseAddr("192.168.1.102")
		lease2 := &Lease{
			IP:    ip2,
			MAC:   mac2,
			State: LeaseStateReleased,
		}
		ls.Add(lease2)

		// Add expired lease
		mac3, _ := net.ParseMAC("00:11:22:33:44:03")
		ip3 := netip.MustParseAddr("192.168.1.103")
		lease3 := &Lease{
			IP:        ip3,
			MAC:       mac3,
			State:     LeaseStateActive,
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		}
		ls.Add(lease3)

		assert.Equal(t, 3, ls.Count())
		assert.Equal(t, 1, ls.CountActive())
	})
}

func TestLeaseStore_All(t *testing.T) {
	t.Run("returns all leases", func(t *testing.T) {
		ls := NewLeaseStore()

		macs := []string{"00:11:22:33:44:01", "00:11:22:33:44:02"}
		ips := []string{"192.168.1.101", "192.168.1.102"}

		for i := 0; i < 2; i++ {
			mac, _ := net.ParseMAC(macs[i])
			ip := netip.MustParseAddr(ips[i])
			lease := &Lease{IP: ip, MAC: mac, State: LeaseStateActive}
			ls.Add(lease)
		}

		leases := ls.All()
		assert.Len(t, leases, 2)
	})

	t.Run("returns clones", func(t *testing.T) {
		ls := NewLeaseStore()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ip := netip.MustParseAddr("192.168.1.100")

		lease := &Lease{
			IP:       ip,
			MAC:      mac,
			Hostname: "original",
			State:    LeaseStateActive,
		}
		ls.Add(lease)

		leases := ls.All()
		leases[0].Hostname = "modified"

		// Original should be unchanged
		retrieved, _ := ls.GetByIP(ip)
		assert.Equal(t, "original", retrieved.Hostname)
	})
}

func TestLeaseStore_AllActive(t *testing.T) {
	t.Run("returns only active leases", func(t *testing.T) {
		ls := NewLeaseStore()

		// Add active lease
		mac1, _ := net.ParseMAC("00:11:22:33:44:01")
		ip1 := netip.MustParseAddr("192.168.1.101")
		lease1 := &Lease{
			IP:        ip1,
			MAC:       mac1,
			State:     LeaseStateActive,
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}
		ls.Add(lease1)

		// Add released lease
		mac2, _ := net.ParseMAC("00:11:22:33:44:02")
		ip2 := netip.MustParseAddr("192.168.1.102")
		lease2 := &Lease{
			IP:    ip2,
			MAC:   mac2,
			State: LeaseStateReleased,
		}
		ls.Add(lease2)

		leases := ls.AllActive()
		assert.Len(t, leases, 1)
		assert.Equal(t, ip1, leases[0].IP)
	})
}

func TestLeaseStore_Clear(t *testing.T) {
	t.Run("removes all leases", func(t *testing.T) {
		ls := NewLeaseStore()

		macs := []string{"00:11:22:33:44:01", "00:11:22:33:44:02", "00:11:22:33:44:03"}
		ips := []string{"192.168.1.101", "192.168.1.102", "192.168.1.103"}

		for i := 0; i < 3; i++ {
			mac, _ := net.ParseMAC(macs[i])
			ip := netip.MustParseAddr(ips[i])
			lease := &Lease{IP: ip, MAC: mac, State: LeaseStateActive}
			ls.Add(lease)
		}

		assert.Equal(t, 3, ls.Count())

		ls.Clear()
		assert.Equal(t, 0, ls.Count())
	})
}

func TestLeaseStore_Close(t *testing.T) {
	t.Run("closes store", func(t *testing.T) {
		ls := NewLeaseStore()

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ip := netip.MustParseAddr("192.168.1.100")
		lease := &Lease{IP: ip, MAC: mac, State: LeaseStateActive}
		ls.Add(lease)

		err := ls.Close()
		require.NoError(t, err)

		// Operations after close should fail
		err = ls.Add(lease)
		assert.ErrorIs(t, err, ErrPluginClosed)

		_, ok := ls.GetByIP(ip)
		assert.False(t, ok)
	})

	t.Run("double close returns error", func(t *testing.T) {
		ls := NewLeaseStore()

		err := ls.Close()
		require.NoError(t, err)

		err = ls.Close()
		assert.ErrorIs(t, err, ErrPluginClosed)
	})
}

func TestLeaseStore_ConcurrentAccess(t *testing.T) {
	t.Run("handles concurrent reads and writes", func(t *testing.T) {
		ls := NewLeaseStore()
		done := make(chan struct{})

		// Start multiple writers
		for i := 0; i < 10; i++ {
			go func(idx int) {
				defer func() { done <- struct{}{} }()
				for j := 0; j < 100; j++ {
					mac, _ := net.ParseMAC("00:11:22:33:44:" + string(rune('0'+idx)))
					ip := netip.MustParseAddr("192.168." + string(rune('0'+idx)) + "." + string(rune('0'+(j%10))))
					if !ip.IsValid() {
						continue
					}
					lease := &Lease{IP: ip, MAC: mac, State: LeaseStateActive}
					ls.Add(lease)
				}
			}(i)
		}

		// Start multiple readers
		for i := 0; i < 10; i++ {
			go func() {
				defer func() { done <- struct{}{} }()
				for j := 0; j < 100; j++ {
					ls.Count()
					ls.All()
				}
			}()
		}

		// Wait for all goroutines
		for i := 0; i < 20; i++ {
			<-done
		}
	})
}

// clientLease builds the lease of DHCP client n: a distinct IP and MAC per n.
func clientLease(n int) *Lease {
	now := time.Now()
	return &Lease{
		IP:        netip.AddrFrom4([4]byte{10, 1, byte(n >> 8), byte(n)}),
		MAC:       net.HardwareAddr{0x52, 0x54, 0x00, 0x01, byte(n >> 8), byte(n)},
		Hostname:  fmt.Sprintf("client-%d", n),
		PoolID:    "pool-1",
		Interface: "eth0",
		LeasedAt:  now,
		ExpiresAt: now.Add(time.Hour),
		State:     LeaseStateActive,
	}
}

func TestLeaseStore_ConcurrentRenewalStorm(t *testing.T) {
	const clients = 500
	const workers = 50

	ls := NewLeaseStore()
	for n := 0; n < clients; n++ {
		require.NoError(t, ls.Add(clientLease(n)))
	}
	stormStart := time.Now()

	errs := make(chan error, clients*workers)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(offset int) {
			defer wg.Done()
			for i := 0; i < clients; i++ {
				lease := clientLease((i + offset) % clients)
				errs <- ls.Renew(lease.IP, 24*time.Hour)
			}
		}(w * 10)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err, "every renewal of a live lease must succeed")
	}

	assert.Equal(t, clients, ls.Count(), "a renewal must neither add nor drop a lease")
	for n := 0; n < clients; n++ {
		want := clientLease(n)
		byIP, ok := ls.GetByIP(want.IP)
		require.True(t, ok, "lease %d lost by IP during the storm", n)
		assert.Equal(t, want.MAC, byIP.MAC, "lease %d changed owner", n)
		assert.False(t, byIP.RenewedAt.Before(stormStart), "lease %d was not renewed", n)
		assert.True(t, byIP.ExpiresAt.After(stormStart.Add(time.Hour)), "lease %d expiry was not extended", n)

		byMAC, ok := ls.GetByMAC(want.MAC)
		require.True(t, ok, "lease %d lost by MAC during the storm", n)
		assert.Equal(t, want.IP, byMAC.IP, "lease %d MAC index points at another IP", n)
	}
}

func TestLeaseStore_ConcurrentClientChurn(t *testing.T) {
	const clients = 1000

	ls := NewLeaseStore()
	errs := make(chan error, clients*3)
	var wg sync.WaitGroup
	for n := 0; n < clients; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			lease := clientLease(n)
			errs <- ls.Add(lease)
			errs <- ls.Renew(lease.IP, 24*time.Hour)
			// One client in ten releases its lease, as in a DHCP RELEASE.
			if n%10 == 9 {
				errs <- ls.Remove(lease.IP)
			}
		}(n)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}

	assert.Equal(t, clients-clients/10, ls.Count())

	seenIPs := make(map[netip.Addr]string, clients)
	for _, lease := range ls.All() {
		owner, dup := seenIPs[lease.IP]
		require.False(t, dup, "IP %s leased to both %s and %s", lease.IP, owner, lease.MAC)
		seenIPs[lease.IP] = lease.MAC.String()
	}

	for n := 0; n < clients; n++ {
		want := clientLease(n)
		byIP, okIP := ls.GetByIP(want.IP)
		byMAC, okMAC := ls.GetByMAC(want.MAC)
		if n%10 == 9 {
			assert.False(t, okIP, "released lease %d still found by IP", n)
			assert.False(t, okMAC, "released lease %d still found by MAC", n)
			continue
		}
		require.True(t, okIP, "lease %d missing by IP", n)
		require.True(t, okMAC, "lease %d missing by MAC", n)
		assert.Equal(t, want.MAC, byIP.MAC)
		assert.Equal(t, want.IP, byMAC.IP)
	}
}

func TestLeaseStore_ConcurrentFailedRequestsLeaveStoreConsistent(t *testing.T) {
	const clients = 200

	ls := NewLeaseStore()
	type result struct {
		n   int
		err error
	}
	results := make(chan result, clients)
	var wg sync.WaitGroup
	for n := 0; n < clients; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			lease := clientLease(n)
			// Every fifth request is malformed, alternating a missing IP and a
			// missing MAC, so failures interleave with good requests.
			switch n % 10 {
			case 4:
				lease.IP = netip.Addr{}
			case 9:
				lease.MAC = nil
			}
			results <- result{n: n, err: ls.Add(lease)}
		}(n)
	}
	wg.Wait()
	close(results)

	for r := range results {
		switch r.n % 10 {
		case 4:
			assert.ErrorIs(t, r.err, ErrInvalidIP, "request %d", r.n)
		case 9:
			assert.ErrorIs(t, r.err, ErrInvalidMAC, "request %d", r.n)
		default:
			assert.NoError(t, r.err, "request %d", r.n)
		}
	}

	assert.Equal(t, clients-clients/5, ls.Count(), "only the good requests hold a lease")
	for n := 0; n < clients; n++ {
		want := clientLease(n)
		_, okIP := ls.GetByIP(want.IP)
		_, okMAC := ls.GetByMAC(want.MAC)
		failed := n%10 == 4 || n%10 == 9
		assert.Equal(t, !failed, okIP, "lease %d by IP", n)
		assert.Equal(t, !failed, okMAC, "lease %d by MAC", n)
	}

	// A renewal for a client whose request failed is refused and adds nothing.
	assert.ErrorIs(t, ls.Renew(clientLease(4).IP, time.Hour), ErrLeaseNotFound)
	assert.Equal(t, clients-clients/5, ls.Count())
}
