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

package modes

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test helper to create a valid EdgeModeConfig.
func newTestEdgeModeConfig() *EdgeModeConfig {
	_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
	return &EdgeModeConfig{
		IPv6Pool:              *ipNet,
		IPv6InactivityTimeout: time.Hour,
		ACMEEndorseEnabled:    false,
		ACMEEnrollEnabled:     false,
		FROSTPoolID:           "",
		RateLimits: RateLimitConfig{
			TrustedReqPerSec:   100,
			UntrustedReqPerSec: 10,
			TrustThreshold:     0.80,
		},
	}
}

// TestEdgeModeConfig_Validate tests EdgeModeConfig validation.
func TestEdgeModeConfig_Validate(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		var cfg *EdgeModeConfig
		err := cfg.Validate()
		assert.ErrorIs(t, err, ErrConfigNil)
	})

	t.Run("valid config", func(t *testing.T) {
		cfg := newTestEdgeModeConfig()
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("invalid IPv6 pool - wrong bits", func(t *testing.T) {
		cfg := newTestEdgeModeConfig()
		_, ipNet, _ := net.ParseCIDR("10.0.0.0/8")
		cfg.IPv6Pool = *ipNet
		err := cfg.Validate()
		assert.ErrorIs(t, err, ErrInvalidIPv6Pool)
	})

	t.Run("invalid IPv6 pool - prefix too small", func(t *testing.T) {
		cfg := newTestEdgeModeConfig()
		_, ipNet, _ := net.ParseCIDR("2001:db8:1234:5678::/96")
		cfg.IPv6Pool = *ipNet
		err := cfg.Validate()
		assert.ErrorIs(t, err, ErrInvalidIPv6Pool)
	})

	t.Run("invalid IPv6 pool - nil IP", func(t *testing.T) {
		cfg := newTestEdgeModeConfig()
		cfg.IPv6Pool.IP = nil
		err := cfg.Validate()
		assert.ErrorIs(t, err, ErrInvalidIPv6Pool)
	})

	t.Run("FROST pool required when enrollment enabled", func(t *testing.T) {
		cfg := newTestEdgeModeConfig()
		cfg.ACMEEnrollEnabled = true
		cfg.FROSTPoolID = ""
		err := cfg.Validate()
		assert.ErrorIs(t, err, ErrFROSTPoolRequired)
	})

	t.Run("FROST pool configured with enrollment enabled", func(t *testing.T) {
		cfg := newTestEdgeModeConfig()
		cfg.ACMEEnrollEnabled = true
		cfg.FROSTPoolID = "test-pool"
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("defaults applied", func(t *testing.T) {
		cfg := newTestEdgeModeConfig()
		cfg.IPv6InactivityTimeout = 0
		cfg.RateLimits.TrustedReqPerSec = 0
		cfg.RateLimits.UntrustedReqPerSec = 0
		cfg.RateLimits.TrustThreshold = 0

		err := cfg.Validate()
		require.NoError(t, err)

		assert.Equal(t, DefaultIPv6InactivityTimeout, cfg.IPv6InactivityTimeout)
		assert.Equal(t, DefaultTrustedReqPerSec, cfg.RateLimits.TrustedReqPerSec)
		assert.Equal(t, DefaultUntrustedReqPerSec, cfg.RateLimits.UntrustedReqPerSec)
		assert.Equal(t, DefaultTrustThreshold, cfg.RateLimits.TrustThreshold)
		// P2P config should be set with defaults
		assert.NotNil(t, cfg.P2PConfig)
	})
}

// TestNewEdgeModeHandler tests EdgeModeHandler creation.
func TestNewEdgeModeHandler(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		cfg := newTestEdgeModeConfig()
		handler, err := NewEdgeModeHandler(cfg)
		require.NoError(t, err)
		require.NotNil(t, handler)
		assert.NotNil(t, handler.ipv6Allocator)
		assert.NotNil(t, handler.p2pNode)
		assert.NotNil(t, handler.rateLimiter)
		assert.NotNil(t, handler.ddosProtector)
	})

	t.Run("invalid config", func(t *testing.T) {
		cfg := newTestEdgeModeConfig()
		cfg.ACMEEnrollEnabled = true
		cfg.FROSTPoolID = "" // Invalid - required when enrollment enabled
		handler, err := NewEdgeModeHandler(cfg)
		assert.ErrorIs(t, err, ErrFROSTPoolRequired)
		assert.Nil(t, handler)
	})

	t.Run("invalid IPv6 pool in config", func(t *testing.T) {
		cfg := newTestEdgeModeConfig()
		cfg.IPv6Pool.IP = nil
		handler, err := NewEdgeModeHandler(cfg)
		assert.ErrorIs(t, err, ErrInvalidIPv6Pool)
		assert.Nil(t, handler)
	})
}

// TestIPv6Allocator_Basic tests basic IPv6 allocator operations.
func TestIPv6Allocator_Basic(t *testing.T) {
	t.Run("create allocator with valid pool", func(t *testing.T) {
		_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
		allocator, err := NewIPv6Allocator(*ipNet, time.Hour)
		require.NoError(t, err)
		require.NotNil(t, allocator)
	})

	t.Run("create allocator with invalid pool", func(t *testing.T) {
		_, ipNet, _ := net.ParseCIDR("10.0.0.0/24")
		allocator, err := NewIPv6Allocator(*ipNet, time.Hour)
		assert.ErrorIs(t, err, ErrInvalidIPv6Pool)
		assert.Nil(t, allocator)
	})

	t.Run("create allocator with nil IP", func(t *testing.T) {
		ipNet := net.IPNet{
			IP:   nil,
			Mask: net.CIDRMask(48, 128),
		}
		allocator, err := NewIPv6Allocator(ipNet, time.Hour)
		assert.ErrorIs(t, err, ErrInvalidIPv6Pool)
		assert.Nil(t, allocator)
	})

	t.Run("create allocator with too small prefix", func(t *testing.T) {
		_, ipNet, _ := net.ParseCIDR("2001:db8:1234:5678::/96")
		allocator, err := NewIPv6Allocator(*ipNet, time.Hour)
		assert.ErrorIs(t, err, ErrInvalidIPv6Pool)
		assert.Nil(t, allocator)
	})

	t.Run("create allocator with default timeout", func(t *testing.T) {
		_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
		allocator, err := NewIPv6Allocator(*ipNet, 0)
		require.NoError(t, err)
		require.NotNil(t, allocator)
		assert.Equal(t, DefaultIPv6InactivityTimeout, allocator.timeout)
	})

	t.Run("allocate without starting", func(t *testing.T) {
		_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
		allocator, err := NewIPv6Allocator(*ipNet, time.Hour)
		require.NoError(t, err)

		ctx := context.Background()
		ip, err := allocator.Allocate(ctx, "device-1")
		assert.ErrorIs(t, err, ErrNotRunning)
		assert.Nil(t, ip)
	})

	t.Run("allocator double start", func(t *testing.T) {
		_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
		allocator, err := NewIPv6Allocator(*ipNet, time.Hour)
		require.NoError(t, err)

		ctx := context.Background()
		err = allocator.Start(ctx)
		require.NoError(t, err)
		defer allocator.Stop(ctx)

		err = allocator.Start(ctx)
		assert.ErrorIs(t, err, ErrAlreadyRunning)
	})

	t.Run("allocator stop without start", func(t *testing.T) {
		_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
		allocator, err := NewIPv6Allocator(*ipNet, time.Hour)
		require.NoError(t, err)

		ctx := context.Background()
		err = allocator.Stop(ctx)
		assert.ErrorIs(t, err, ErrNotRunning)
	})
}

// TestIPv6Allocator_Allocation tests IPv6 allocation operations.
func TestIPv6Allocator_Allocation(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
	allocator, err := NewIPv6Allocator(*ipNet, time.Hour)
	require.NoError(t, err)

	ctx := context.Background()
	err = allocator.Start(ctx)
	require.NoError(t, err)
	defer allocator.Stop(ctx)

	t.Run("allocate single address", func(t *testing.T) {
		ip, err := allocator.Allocate(ctx, "device-1")
		require.NoError(t, err)
		require.NotNil(t, ip)
		assert.True(t, ipNet.Contains(ip))
	})

	t.Run("allocate same device returns same IP", func(t *testing.T) {
		ip1, err := allocator.Allocate(ctx, "device-same")
		require.NoError(t, err)

		ip2, err := allocator.Allocate(ctx, "device-same")
		require.NoError(t, err)

		assert.Equal(t, ip1.String(), ip2.String())
	})

	t.Run("allocate different devices returns different IPs", func(t *testing.T) {
		ip1, err := allocator.Allocate(ctx, "device-a")
		require.NoError(t, err)

		ip2, err := allocator.Allocate(ctx, "device-b")
		require.NoError(t, err)

		assert.NotEqual(t, ip1.String(), ip2.String())
	})

	t.Run("allocate with empty device ID", func(t *testing.T) {
		ip, err := allocator.Allocate(ctx, "")
		assert.ErrorIs(t, err, ErrDeviceIDRequired)
		assert.Nil(t, ip)
	})

	t.Run("allocate specific address", func(t *testing.T) {
		specificIP := net.ParseIP("2001:db8:1234::beef")
		ip, err := allocator.AllocateSpecific(ctx, "device-specific", specificIP)
		require.NoError(t, err)
		assert.Equal(t, specificIP.String(), ip.String())
	})

	t.Run("allocate specific address already allocated", func(t *testing.T) {
		specificIP := net.ParseIP("2001:db8:1234::cafe")
		ip1, err := allocator.AllocateSpecific(ctx, "device-first", specificIP)
		require.NoError(t, err)
		assert.NotNil(t, ip1)

		ip2, err := allocator.AllocateSpecific(ctx, "device-second", specificIP)
		assert.ErrorIs(t, err, ErrIPv6AlreadyAllocated)
		assert.Nil(t, ip2)
	})

	t.Run("allocate specific address outside pool", func(t *testing.T) {
		outsideIP := net.ParseIP("2603:f5bb:1234::1")
		ip, err := allocator.AllocateSpecific(ctx, "device-outside", outsideIP)
		assert.ErrorIs(t, err, ErrIPv6OutOfPool)
		assert.Nil(t, ip)
	})
}

// TestIPv6Allocator_AllocateSpecific_EdgeCases tests AllocateSpecific edge cases.
func TestIPv6Allocator_AllocateSpecific_EdgeCases(t *testing.T) {
	ctx := context.Background()

	t.Run("allocate specific not running", func(t *testing.T) {
		_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
		allocator, err := NewIPv6Allocator(*ipNet, time.Hour)
		require.NoError(t, err)

		specificIP := net.ParseIP("2001:db8:1234::1")
		ip, err := allocator.AllocateSpecific(ctx, "device", specificIP)
		assert.ErrorIs(t, err, ErrNotRunning)
		assert.Nil(t, ip)
	})

	t.Run("allocate specific with empty device ID", func(t *testing.T) {
		_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
		allocator, err := NewIPv6Allocator(*ipNet, time.Hour)
		require.NoError(t, err)

		err = allocator.Start(ctx)
		require.NoError(t, err)
		defer allocator.Stop(ctx)

		specificIP := net.ParseIP("2001:db8:1234::1")
		ip, err := allocator.AllocateSpecific(ctx, "", specificIP)
		assert.ErrorIs(t, err, ErrDeviceIDRequired)
		assert.Nil(t, ip)
	})

	t.Run("allocate specific with nil IP", func(t *testing.T) {
		_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
		allocator, err := NewIPv6Allocator(*ipNet, time.Hour)
		require.NoError(t, err)

		err = allocator.Start(ctx)
		require.NoError(t, err)
		defer allocator.Stop(ctx)

		ip, err := allocator.AllocateSpecific(ctx, "device", nil)
		assert.ErrorIs(t, err, ErrInvalidIPv6Address)
		assert.Nil(t, ip)
	})

	t.Run("allocate specific with invalid IP length", func(t *testing.T) {
		_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
		allocator, err := NewIPv6Allocator(*ipNet, time.Hour)
		require.NoError(t, err)

		err = allocator.Start(ctx)
		require.NoError(t, err)
		defer allocator.Stop(ctx)

		shortIP := net.IP{1, 2, 3, 4}
		ip, err := allocator.AllocateSpecific(ctx, "device", shortIP)
		assert.ErrorIs(t, err, ErrInvalidIPv6Address)
		assert.Nil(t, ip)
	})
}

// TestIPv6Allocator_Release tests IPv6 release operations.
func TestIPv6Allocator_Release(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
	allocator, err := NewIPv6Allocator(*ipNet, time.Hour)
	require.NoError(t, err)

	ctx := context.Background()
	err = allocator.Start(ctx)
	require.NoError(t, err)
	defer allocator.Stop(ctx)

	t.Run("release allocated address", func(t *testing.T) {
		ip, err := allocator.Allocate(ctx, "device-release")
		require.NoError(t, err)

		err = allocator.Release(ctx, ip)
		assert.NoError(t, err)
	})

	t.Run("release not allocated address", func(t *testing.T) {
		ip := net.ParseIP("2001:db8:1234::dead")
		err := allocator.Release(ctx, ip)
		assert.ErrorIs(t, err, ErrIPv6NotAllocated)
	})

	t.Run("release nil address", func(t *testing.T) {
		err := allocator.Release(ctx, nil)
		assert.ErrorIs(t, err, ErrInvalidIPv6Address)
	})

	t.Run("release empty address", func(t *testing.T) {
		err := allocator.Release(ctx, net.IP{})
		assert.ErrorIs(t, err, ErrInvalidIPv6Address)
	})

	t.Run("release not running", func(t *testing.T) {
		_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
		allocator2, err := NewIPv6Allocator(*ipNet, time.Hour)
		require.NoError(t, err)

		ip := net.ParseIP("2001:db8:1234::1")
		err = allocator2.Release(ctx, ip)
		assert.ErrorIs(t, err, ErrNotRunning)
	})
}

// TestIPv6Allocator_RefreshLease tests lease refresh operations.
func TestIPv6Allocator_RefreshLease(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
	allocator, err := NewIPv6Allocator(*ipNet, time.Hour)
	require.NoError(t, err)

	ctx := context.Background()
	err = allocator.Start(ctx)
	require.NoError(t, err)
	defer allocator.Stop(ctx)

	t.Run("refresh allocated address", func(t *testing.T) {
		ip, err := allocator.Allocate(ctx, "device-refresh")
		require.NoError(t, err)

		err = allocator.RefreshLease(ctx, ip)
		assert.NoError(t, err)
	})

	t.Run("refresh not allocated address", func(t *testing.T) {
		ip := net.ParseIP("2001:db8:1234::ffff")
		err := allocator.RefreshLease(ctx, ip)
		assert.ErrorIs(t, err, ErrIPv6NotAllocated)
	})

	t.Run("refresh nil address", func(t *testing.T) {
		err := allocator.RefreshLease(ctx, nil)
		assert.ErrorIs(t, err, ErrInvalidIPv6Address)
	})

	t.Run("refresh not running", func(t *testing.T) {
		_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
		allocator2, err := NewIPv6Allocator(*ipNet, time.Hour)
		require.NoError(t, err)

		ip := net.ParseIP("2001:db8:1234::1")
		err = allocator2.RefreshLease(ctx, ip)
		assert.ErrorIs(t, err, ErrNotRunning)
	})
}

// TestIPv6Allocator_Status tests status retrieval.
func TestIPv6Allocator_Status(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
	allocator, err := NewIPv6Allocator(*ipNet, time.Hour)
	require.NoError(t, err)

	ctx := context.Background()
	err = allocator.Start(ctx)
	require.NoError(t, err)
	defer allocator.Stop(ctx)

	status := allocator.GetStatus()
	assert.True(t, status.PoolSize > 0)
	assert.Equal(t, uint64(0), status.Allocated)
	assert.Equal(t, status.PoolSize, status.Available)
	assert.Equal(t, uint64(0), status.ActiveDevices)

	// Allocate some addresses
	_, err = allocator.Allocate(ctx, "device-status-1")
	require.NoError(t, err)
	_, err = allocator.Allocate(ctx, "device-status-2")
	require.NoError(t, err)

	status = allocator.GetStatus()
	assert.Equal(t, uint64(2), status.Allocated)
	assert.Equal(t, status.PoolSize-2, status.Available)
	assert.Equal(t, uint64(2), status.ActiveDevices)
}

// TestIPv6Allocator_ExpireInactive tests the expireInactive method.
func TestIPv6Allocator_ExpireInactive(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
	allocator, err := NewIPv6Allocator(*ipNet, time.Millisecond) // Very short timeout
	require.NoError(t, err)

	ctx := context.Background()
	err = allocator.Start(ctx)
	require.NoError(t, err)
	defer allocator.Stop(ctx)

	// Allocate an address
	ip, err := allocator.Allocate(ctx, "device-expire")
	require.NoError(t, err)
	require.NotNil(t, ip)

	// Set allocation as inactive by directly accessing allocations map
	ipStr := ip.String()
	if alloc, ok := allocator.allocations.Load(ipStr); ok {
		allocation := alloc.(*IPv6Allocation)
		allocation.Active = false
		allocation.LastSeen = time.Now().Add(-time.Hour) // Set last seen to past
	}

	// Manually call expireInactive
	allocator.expireInactive()

	// Verify allocation is removed
	_, loaded := allocator.allocations.Load(ipStr)
	assert.False(t, loaded, "allocation should have been expired")
}

// TestIPv6Allocator_Concurrent tests concurrent allocation.
func TestIPv6Allocator_Concurrent(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
	allocator, err := NewIPv6Allocator(*ipNet, time.Hour)
	require.NoError(t, err)

	ctx := context.Background()
	err = allocator.Start(ctx)
	require.NoError(t, err)
	defer allocator.Stop(ctx)

	const numGoroutines = 100
	var wg sync.WaitGroup
	ips := make(chan string, numGoroutines)
	errCh := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(deviceID int) {
			defer wg.Done()
			ip, err := allocator.Allocate(ctx, string(rune('a'+deviceID)))
			if err != nil {
				errCh <- err
				return
			}
			ips <- ip.String()
		}(i)
	}

	wg.Wait()
	close(ips)
	close(errCh)

	// Check no errors
	for err := range errCh {
		t.Errorf("unexpected error: %v", err)
	}

	// Check all IPs are unique
	uniqueIPs := make(map[string]bool)
	for ip := range ips {
		if uniqueIPs[ip] {
			t.Errorf("duplicate IP allocated: %s", ip)
		}
		uniqueIPs[ip] = true
	}
}

// TestPerPeerRateLimiter tests rate limiter operations.
func TestPerPeerRateLimiter(t *testing.T) {
	ctx := context.Background()

	t.Run("create rate limiter", func(t *testing.T) {
		rl := NewPerPeerRateLimiter(100, 10, 0.80)
		assert.NotNil(t, rl)
	})

	t.Run("start and stop", func(t *testing.T) {
		rl := NewPerPeerRateLimiter(100, 10, 0.80)

		err := rl.Start(ctx)
		require.NoError(t, err)

		err = rl.Stop(ctx)
		require.NoError(t, err)
	})

	t.Run("double start returns error", func(t *testing.T) {
		rl := NewPerPeerRateLimiter(100, 10, 0.80)

		err := rl.Start(ctx)
		require.NoError(t, err)
		defer rl.Stop(ctx)

		err = rl.Start(ctx)
		assert.ErrorIs(t, err, ErrAlreadyRunning)
	})

	t.Run("stop not running", func(t *testing.T) {
		rl := NewPerPeerRateLimiter(100, 10, 0.80)

		err := rl.Stop(ctx)
		assert.ErrorIs(t, err, ErrNotRunning)
	})

	t.Run("check trusted peer within limit", func(t *testing.T) {
		rl := NewPerPeerRateLimiter(100, 10, 0.80)
		err := rl.Start(ctx)
		require.NoError(t, err)
		defer rl.Stop(ctx)

		// Trusted peer (reputation >= 0.80)
		for i := 0; i < 50; i++ {
			err := rl.Check(ctx, "trusted-peer", 0.85)
			assert.NoError(t, err)
		}
	})

	t.Run("check untrusted peer within limit", func(t *testing.T) {
		rl := NewPerPeerRateLimiter(100, 10, 0.80)
		err := rl.Start(ctx)
		require.NoError(t, err)
		defer rl.Stop(ctx)

		// Untrusted peer (reputation < 0.80)
		for i := 0; i < 5; i++ {
			err := rl.Check(ctx, "untrusted-peer", 0.50)
			assert.NoError(t, err)
		}
	})

	t.Run("check with empty peer ID", func(t *testing.T) {
		rl := NewPerPeerRateLimiter(100, 10, 0.80)
		err := rl.Start(ctx)
		require.NoError(t, err)
		defer rl.Stop(ctx)

		err = rl.Check(ctx, "", 0.85)
		assert.ErrorIs(t, err, ErrPeerIDRequired)
	})

	t.Run("check not running", func(t *testing.T) {
		rl := NewPerPeerRateLimiter(100, 10, 0.80)

		err := rl.Check(ctx, "peer", 0.85)
		assert.ErrorIs(t, err, ErrNotRunning)
	})

	t.Run("rate limit exceeded", func(t *testing.T) {
		// Create limiter with very low limit
		rl := NewPerPeerRateLimiter(2, 1, 0.80)
		err := rl.Start(ctx)
		require.NoError(t, err)
		defer rl.Stop(ctx)

		// First two requests should succeed
		err = rl.Check(ctx, "limited-peer", 0.85)
		assert.NoError(t, err)
		err = rl.Check(ctx, "limited-peer", 0.85)
		assert.NoError(t, err)

		// Third request should fail
		err = rl.Check(ctx, "limited-peer", 0.85)
		assert.ErrorIs(t, err, ErrRateLimitExceeded)
	})
}

// TestPerPeerRateLimiter_Cleanup tests the cleanup method.
func TestPerPeerRateLimiter_Cleanup(t *testing.T) {
	ctx := context.Background()
	rl := NewPerPeerRateLimiter(100, 10, 0.80)
	err := rl.Start(ctx)
	require.NoError(t, err)
	defer rl.Stop(ctx)

	// Add a peer
	err = rl.Check(ctx, "cleanup-peer", 0.85)
	require.NoError(t, err)

	// Verify peer exists
	_, exists := rl.peerTokens.Load("cleanup-peer")
	assert.True(t, exists)

	// Set the bucket's lastFill to past the threshold
	if bucket, ok := rl.peerTokens.Load("cleanup-peer"); ok {
		tb := bucket.(*tokenBucket)
		tb.lastFill.Store(time.Now().Add(-2 * time.Hour).UnixNano())
	}

	// Call cleanup
	rl.cleanup()

	// Verify peer is removed
	_, exists = rl.peerTokens.Load("cleanup-peer")
	assert.False(t, exists, "stale peer should be cleaned up")
}

// TestDDOSProtection tests DDoS protection operations.
func TestDDOSProtection(t *testing.T) {
	ctx := context.Background()

	t.Run("create protection", func(t *testing.T) {
		ddos := NewDDOSProtection()
		assert.NotNil(t, ddos)
	})

	t.Run("start and stop", func(t *testing.T) {
		ddos := NewDDOSProtection()

		err := ddos.Start(ctx)
		require.NoError(t, err)

		err = ddos.Stop(ctx)
		require.NoError(t, err)
	})

	t.Run("double start returns error", func(t *testing.T) {
		ddos := NewDDOSProtection()

		err := ddos.Start(ctx)
		require.NoError(t, err)
		defer ddos.Stop(ctx)

		err = ddos.Start(ctx)
		assert.ErrorIs(t, err, ErrAlreadyRunning)
	})

	t.Run("stop without start returns error", func(t *testing.T) {
		ddos := NewDDOSProtection()

		err := ddos.Stop(ctx)
		assert.ErrorIs(t, err, ErrNotRunning)
	})
}

// TestEdgeModeErrors tests error types.
func TestEdgeModeErrors(t *testing.T) {
	t.Run("ErrStartFailed", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := &ErrStartFailed{Component: "test", Cause: cause}
		assert.Contains(t, err.Error(), "test")
		assert.Contains(t, err.Error(), "underlying error")
		assert.ErrorIs(t, err, cause)
	})

	t.Run("ErrStopFailed", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := &ErrStopFailed{Component: "test", Cause: cause}
		assert.Contains(t, err.Error(), "test")
		assert.ErrorIs(t, err, cause)
	})

	t.Run("ErrMultipleFailures empty", func(t *testing.T) {
		err := &ErrMultipleFailures{}
		assert.Contains(t, err.Error(), "multiple failures")
	})

	t.Run("ErrMultipleFailures single", func(t *testing.T) {
		err := &ErrMultipleFailures{Errors: []error{errors.New("single error")}}
		assert.Equal(t, "single error", err.Error())
	})

	t.Run("ErrMultipleFailures multiple", func(t *testing.T) {
		err := &ErrMultipleFailures{Errors: []error{
			errors.New("error 1"),
			errors.New("error 2"),
		}}
		assert.Contains(t, err.Error(), "error 1")
		assert.Contains(t, err.Error(), "error 2")
	})

	t.Run("ErrOnboardingFailed", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := &ErrOnboardingFailed{Step: "validation", Cause: cause}
		assert.Contains(t, err.Error(), "validation")
		assert.ErrorIs(t, err, cause)
	})

	t.Run("ErrIPv6AllocationError with IP", func(t *testing.T) {
		err := &ErrIPv6AllocationError{DeviceID: "device", IP: "::1", Reason: "already allocated"}
		assert.Contains(t, err.Error(), "device")
		assert.Contains(t, err.Error(), "::1")
		assert.Contains(t, err.Error(), "already allocated")
	})

	t.Run("ErrIPv6AllocationError without IP", func(t *testing.T) {
		err := &ErrIPv6AllocationError{DeviceID: "device", Reason: "pool exhausted"}
		assert.Contains(t, err.Error(), "device")
		assert.Contains(t, err.Error(), "pool exhausted")
	})

	t.Run("ErrRateLimitError", func(t *testing.T) {
		err := &ErrRateLimitError{PeerID: "peer-1", Reputation: 0.50, Limit: 10}
		assert.Contains(t, err.Error(), "peer-1")
		assert.Contains(t, err.Error(), "0.50")
		assert.Contains(t, err.Error(), "10")
	})

	t.Run("ErrACMEChallengeFailed", func(t *testing.T) {
		err := &ErrACMEChallengeFailed{ChallengeType: "endorse-01", DeviceID: "device", Reason: "invalid EK"}
		assert.Contains(t, err.Error(), "endorse-01")
		assert.Contains(t, err.Error(), "device")
		assert.Contains(t, err.Error(), "invalid EK")
	})

	t.Run("ErrNATTraversalFailed", func(t *testing.T) {
		cause := errors.New("timeout")
		err := &ErrNATTraversalFailed{Method: "STUN", Cause: cause}
		assert.Contains(t, err.Error(), "STUN")
		assert.ErrorIs(t, err, cause)
	})
}

// TestEdgeModeConstants tests constant values.
func TestEdgeModeConstants(t *testing.T) {
	assert.Equal(t, 720*time.Hour, DefaultIPv6InactivityTimeout)
	assert.Equal(t, 100, DefaultTrustedReqPerSec)
	assert.Equal(t, 10, DefaultUntrustedReqPerSec)
	assert.Equal(t, 0.80, DefaultTrustThreshold)
	assert.Equal(t, 20, KademliaK)
	assert.Equal(t, 3, KademliaAlpha)
	assert.Equal(t, 3, DefaultNodeTier)
}

// TestIPv6Allocator_OffsetToIP tests the offsetToIP method.
func TestIPv6Allocator_OffsetToIP(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
	allocator, err := NewIPv6Allocator(*ipNet, time.Hour)
	require.NoError(t, err)

	t.Run("offset 0", func(t *testing.T) {
		ip := allocator.offsetToIP(0)
		assert.NotNil(t, ip)
		assert.True(t, ipNet.Contains(ip))
	})

	t.Run("offset 1", func(t *testing.T) {
		ip := allocator.offsetToIP(1)
		assert.NotNil(t, ip)
		assert.True(t, ipNet.Contains(ip))
	})

	t.Run("offset 255", func(t *testing.T) {
		ip := allocator.offsetToIP(255)
		assert.NotNil(t, ip)
		assert.True(t, ipNet.Contains(ip))
	})

	t.Run("large offset", func(t *testing.T) {
		ip := allocator.offsetToIP(1000000)
		assert.NotNil(t, ip)
		assert.True(t, ipNet.Contains(ip))
	})
}

// TestIPv6Allocation_PoolExhaustion tests the pool exhaustion error path.
func TestIPv6Allocation_PoolExhaustion(t *testing.T) {
	// Create a very small pool with only 4 addresses (use /126)
	_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/126")

	// This should fail because /126 gives only 4 addresses and we require at least /64
	allocator, err := NewIPv6Allocator(*ipNet, time.Hour)
	assert.ErrorIs(t, err, ErrInvalidIPv6Pool)
	assert.Nil(t, allocator)
}

// TestRateLimiter_TokenRefill tests token bucket refill behavior.
func TestRateLimiter_TokenRefill(t *testing.T) {
	ctx := context.Background()

	// Create a rate limiter with a limit of 2 req/s for trusted
	rl := NewPerPeerRateLimiter(2, 1, 0.80)
	err := rl.Start(ctx)
	require.NoError(t, err)
	defer rl.Stop(ctx)

	// Exhaust tokens
	err = rl.Check(ctx, "refill-peer", 0.90)
	require.NoError(t, err)
	err = rl.Check(ctx, "refill-peer", 0.90)
	require.NoError(t, err)

	// This should fail (tokens exhausted)
	err = rl.Check(ctx, "refill-peer", 0.90)
	assert.ErrorIs(t, err, ErrRateLimitExceeded)

	// Manually adjust the lastFill time to simulate time passing
	if bucket, ok := rl.peerTokens.Load("refill-peer"); ok {
		tb := bucket.(*tokenBucket)
		// Set lastFill to 2 seconds ago
		tb.lastFill.Store(time.Now().Add(-2 * time.Second).UnixNano())
	}

	// Now token should be refilled
	err = rl.Check(ctx, "refill-peer", 0.90)
	assert.NoError(t, err)
}

// TestValidateTPMEK tests the validateTPMEK method.
func TestValidateTPMEK(t *testing.T) {
	cfg := newTestEdgeModeConfig()
	handler, err := NewEdgeModeHandler(cfg)
	require.NoError(t, err)

	t.Run("valid TPM EK", func(t *testing.T) {
		err := handler.validateTPMEK(context.Background(), []byte("valid-ek-data"))
		assert.NoError(t, err)
	})

	t.Run("nil TPM EK", func(t *testing.T) {
		err := handler.validateTPMEK(context.Background(), nil)
		assert.ErrorIs(t, err, ErrTPMEKRequired)
	})

	t.Run("empty TPM EK", func(t *testing.T) {
		err := handler.validateTPMEK(context.Background(), []byte{})
		assert.ErrorIs(t, err, ErrTPMEKRequired)
	})
}

// TestIssueIDevID tests the issueIDevID method.
func TestIssueIDevID(t *testing.T) {
	cfg := newTestEdgeModeConfig()
	handler, err := NewEdgeModeHandler(cfg)
	require.NoError(t, err)

	t.Run("successful issuance returns no error", func(t *testing.T) {
		cert, err := handler.issueIDevID(context.Background(), "device-123", []byte("tpm-ek-data"))
		require.NoError(t, err)
		// Note: Currently returns nil certificate as placeholder
		_ = cert
	})

	t.Run("empty device ID", func(t *testing.T) {
		cert, err := handler.issueIDevID(context.Background(), "", []byte("tpm-ek-data"))
		assert.ErrorIs(t, err, ErrDeviceIDRequired)
		assert.Nil(t, cert)
	})

	t.Run("empty TPM EK", func(t *testing.T) {
		cert, err := handler.issueIDevID(context.Background(), "device-123", []byte{})
		assert.ErrorIs(t, err, ErrTPMEKRequired)
		assert.Nil(t, cert)
	})
}

// TestVerifyTPMQuote tests the verifyTPMQuote method.
func TestVerifyTPMQuote(t *testing.T) {
	cfg := newTestEdgeModeConfig()
	handler, err := NewEdgeModeHandler(cfg)
	require.NoError(t, err)

	t.Run("valid quote", func(t *testing.T) {
		err := handler.verifyTPMQuote(context.Background(), []byte("tpm-ek"), []byte("valid-quote"))
		assert.NoError(t, err)
	})

	t.Run("empty EK", func(t *testing.T) {
		err := handler.verifyTPMQuote(context.Background(), []byte{}, []byte("quote"))
		assert.ErrorIs(t, err, ErrTPMEKRequired)
	})

	t.Run("empty quote", func(t *testing.T) {
		err := handler.verifyTPMQuote(context.Background(), []byte("tpm-ek"), []byte{})
		assert.ErrorIs(t, err, ErrTPMQuoteRequired)
	})
}

// TestIPv6Allocator_LargePool tests allocator with a large pool (/36).
func TestIPv6Allocator_LargePool(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("2001:db8::/36")
	allocator, err := NewIPv6Allocator(*ipNet, time.Hour)
	require.NoError(t, err)

	ctx := context.Background()
	err = allocator.Start(ctx)
	require.NoError(t, err)
	defer allocator.Stop(ctx)

	// Allocate an address
	ip, err := allocator.Allocate(ctx, "large-pool-device")
	require.NoError(t, err)
	assert.NotNil(t, ip)
	assert.True(t, ipNet.Contains(ip))

	// Check status
	status := allocator.GetStatus()
	assert.True(t, status.PoolSize > 0)
	assert.Equal(t, uint64(1), status.Allocated)
}

// TestEdgeModeSentinelErrors tests all edge mode sentinel error messages.
func TestEdgeModeSentinelErrors(t *testing.T) {
	// Edge mode sentinel errors
	t.Run("ErrInvalidIPv6Pool", func(t *testing.T) {
		assert.Equal(t, "invalid IPv6 pool", ErrInvalidIPv6Pool.Error())
	})

	t.Run("ErrInvalidIPv6Address", func(t *testing.T) {
		assert.Equal(t, "invalid IPv6 address", ErrInvalidIPv6Address.Error())
	})

	t.Run("ErrIPv6PoolExhausted", func(t *testing.T) {
		assert.Equal(t, "IPv6 pool exhausted", ErrIPv6PoolExhausted.Error())
	})

	t.Run("ErrIPv6AllocationFailed", func(t *testing.T) {
		assert.Equal(t, "IPv6 allocation failed", ErrIPv6AllocationFailed.Error())
	})

	t.Run("ErrIPv6AlreadyAllocated", func(t *testing.T) {
		assert.Equal(t, "IPv6 address already allocated", ErrIPv6AlreadyAllocated.Error())
	})

	t.Run("ErrIPv6OutOfPool", func(t *testing.T) {
		assert.Equal(t, "IPv6 address outside pool", ErrIPv6OutOfPool.Error())
	})

	t.Run("ErrIPv6NotAllocated", func(t *testing.T) {
		assert.Equal(t, "IPv6 address not allocated", ErrIPv6NotAllocated.Error())
	})

	t.Run("ErrDeviceIDRequired", func(t *testing.T) {
		assert.Equal(t, "device ID required", ErrDeviceIDRequired.Error())
	})

	t.Run("ErrNodeIDRequired", func(t *testing.T) {
		assert.Equal(t, "node ID required", ErrNodeIDRequired.Error())
	})

	t.Run("ErrPeerIDRequired", func(t *testing.T) {
		assert.Equal(t, "peer ID required", ErrPeerIDRequired.Error())
	})

	t.Run("ErrRequestNil", func(t *testing.T) {
		assert.Equal(t, "request is nil", ErrRequestNil.Error())
	})

	t.Run("ErrTPMEKRequired", func(t *testing.T) {
		assert.Equal(t, "TPM endorsement key required", ErrTPMEKRequired.Error())
	})

	t.Run("ErrTPMQuoteRequired", func(t *testing.T) {
		assert.Equal(t, "TPM quote required", ErrTPMQuoteRequired.Error())
	})

	t.Run("ErrFROSTPoolRequired", func(t *testing.T) {
		assert.Equal(t, "FROST pool ID required for ACME enrollment", ErrFROSTPoolRequired.Error())
	})

	t.Run("ErrRateLimitExceeded", func(t *testing.T) {
		assert.Equal(t, "rate limit exceeded", ErrRateLimitExceeded.Error())
	})

	// Common sentinel errors
	t.Run("ErrConfigNil", func(t *testing.T) {
		assert.Equal(t, "configuration is nil", ErrConfigNil.Error())
	})

	t.Run("ErrAlreadyRunning", func(t *testing.T) {
		assert.Equal(t, "handler already running", ErrAlreadyRunning.Error())
	})

	t.Run("ErrNotRunning", func(t *testing.T) {
		assert.Equal(t, "handler not running", ErrNotRunning.Error())
	})
}

// TestEdgeModeContextualErrors tests edge mode contextual error types.
func TestEdgeModeContextualErrors(t *testing.T) {
	t.Run("ErrTPMValidationFailed", func(t *testing.T) {
		err := &ErrTPMValidationFailed{Reason: "invalid signature"}
		assert.Contains(t, err.Error(), "TPM validation failed")
		assert.Contains(t, err.Error(), "invalid signature")
	})

	t.Run("ErrIDevIDIssuanceFailed", func(t *testing.T) {
		cause := errors.New("FROST signing failed")
		err := &ErrIDevIDIssuanceFailed{DeviceID: "device-123", Cause: cause}
		assert.Contains(t, err.Error(), "IDevID")
		assert.Contains(t, err.Error(), "device-123")
		assert.ErrorIs(t, err, cause)
	})

	t.Run("ErrDHTRegistrationFailed", func(t *testing.T) {
		cause := errors.New("network timeout")
		err := &ErrDHTRegistrationFailed{DeviceID: "device-456", Cause: cause}
		assert.Contains(t, err.Error(), "DHT")
		assert.Contains(t, err.Error(), "device-456")
		assert.ErrorIs(t, err, cause)
	})
}

// TestRegionFromIP tests the regionFromIP function.
func TestRegionFromIP(t *testing.T) {
	t.Run("nil IP returns default", func(t *testing.T) {
		region := regionFromIP(nil)
		assert.Equal(t, "default", region)
	})

	t.Run("short IP returns default", func(t *testing.T) {
		shortIP := net.IP{1, 2, 3, 4}
		region := regionFromIP(shortIP)
		assert.Equal(t, "default", region)
	})

	t.Run("valid IPv6 extracts region", func(t *testing.T) {
		ip := net.ParseIP("2001:db8:1234::1")
		region := regionFromIP(ip)
		assert.NotEmpty(t, region)
	})
}

// TestEdgeModeStatus tests EdgeModeStatus fields.
func TestEdgeModeStatus(t *testing.T) {
	status := &EdgeModeStatus{
		Running:             true,
		IPv6PoolSize:        1000,
		IPv6Allocated:       10,
		IPv6Available:       990,
		ActiveDevices:       5,
		ACMEEndorseEnabled:  true,
		ACMEEnrollEnabled:   false,
		PeerID:              "12D3KooWtest",
		ConnectedPeers:      15,
		DHTRoutingTableSize: 50,
		NATReachability:     "public",
	}

	assert.True(t, status.Running)
	assert.Equal(t, uint64(1000), status.IPv6PoolSize)
	assert.Equal(t, uint64(10), status.IPv6Allocated)
	assert.Equal(t, uint64(990), status.IPv6Available)
	assert.Equal(t, uint64(5), status.ActiveDevices)
	assert.True(t, status.ACMEEndorseEnabled)
	assert.False(t, status.ACMEEnrollEnabled)
	assert.Equal(t, "12D3KooWtest", status.PeerID)
	assert.Equal(t, 15, status.ConnectedPeers)
	assert.Equal(t, 50, status.DHTRoutingTableSize)
	assert.Equal(t, "public", status.NATReachability)
}
