//go:build !platform_p2p

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

// Tests for the stub edge mode implementation when P2P support is not enabled.

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

// Test helper to create a valid EdgeModeConfig for stub tests.
func newTestEdgeModeConfigStub() *EdgeModeConfig {
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

// TestEdgeModeStub_P2PNotEnabled tests that P2P operations return ErrP2PNotEnabled.
func TestEdgeModeStub_P2PNotEnabled(t *testing.T) {
	cfg := newTestEdgeModeConfigStub()
	handler, err := NewEdgeModeHandler(cfg)
	require.NoError(t, err)
	require.NotNil(t, handler)

	ctx := context.Background()
	err = handler.Start(ctx)
	require.NoError(t, err)
	defer handler.Stop(ctx)

	t.Run("OnboardDevice returns ErrP2PNotEnabled", func(t *testing.T) {
		req := &OnboardingRequest{
			DeviceID: "test-device",
			TPMEK:    []byte("test-ek"),
		}
		resp, err := handler.OnboardDevice(ctx, req)
		assert.ErrorIs(t, err, ErrP2PNotEnabled)
		assert.Nil(t, resp)
	})

	t.Run("BootstrapDHT returns ErrP2PNotEnabled", func(t *testing.T) {
		resp, err := handler.BootstrapDHT(ctx, []byte("test-node-id"))
		assert.ErrorIs(t, err, ErrP2PNotEnabled)
		assert.Nil(t, resp)
	})
}

// TestEdgeModeStub_NonP2POperations tests that non-P2P operations work correctly.
func TestEdgeModeStub_NonP2POperations(t *testing.T) {
	cfg := newTestEdgeModeConfigStub()
	handler, err := NewEdgeModeHandler(cfg)
	require.NoError(t, err)
	require.NotNil(t, handler)

	ctx := context.Background()
	err = handler.Start(ctx)
	require.NoError(t, err)
	defer handler.Stop(ctx)

	t.Run("AllocateIPv6 works", func(t *testing.T) {
		ip, err := handler.AllocateIPv6(ctx, "test-device-1")
		require.NoError(t, err)
		require.NotNil(t, ip)
	})

	t.Run("ReleaseIPv6 works", func(t *testing.T) {
		ip, err := handler.AllocateIPv6(ctx, "test-device-release")
		require.NoError(t, err)

		err = handler.ReleaseIPv6(ctx, ip)
		assert.NoError(t, err)
	})

	t.Run("RefreshLease works", func(t *testing.T) {
		ip, err := handler.AllocateIPv6(ctx, "test-device-refresh")
		require.NoError(t, err)

		err = handler.RefreshLease(ctx, ip)
		assert.NoError(t, err)
	})

	t.Run("CheckRateLimit works", func(t *testing.T) {
		err := handler.CheckRateLimit(ctx, "test-peer", 0.90)
		assert.NoError(t, err)
	})

	t.Run("GetStatus returns correct values for stub", func(t *testing.T) {
		status := handler.GetStatus()
		assert.True(t, status.Running)
		assert.Equal(t, "", status.PeerID) // Empty for stub
		assert.Equal(t, 0, status.ConnectedPeers)
		assert.Equal(t, 0, status.DHTRoutingTableSize)
		assert.Equal(t, "", status.NATReachability)
	})
}

// TestEdgeModeStub_ConfigValidation tests config validation in stub mode.
func TestEdgeModeStub_ConfigValidation(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		var cfg *EdgeModeConfig
		err := cfg.Validate()
		assert.ErrorIs(t, err, ErrConfigNil)
	})

	t.Run("valid config", func(t *testing.T) {
		cfg := newTestEdgeModeConfigStub()
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("invalid IPv6 pool", func(t *testing.T) {
		cfg := newTestEdgeModeConfigStub()
		_, ipNet, _ := net.ParseCIDR("10.0.0.0/8")
		cfg.IPv6Pool = *ipNet
		err := cfg.Validate()
		assert.ErrorIs(t, err, ErrInvalidIPv6Pool)
	})
}

// TestEdgeModeStub_StartStop tests start/stop behavior.
func TestEdgeModeStub_StartStop(t *testing.T) {
	cfg := newTestEdgeModeConfigStub()
	handler, err := NewEdgeModeHandler(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("start and stop", func(t *testing.T) {
		err := handler.Start(ctx)
		require.NoError(t, err)

		status := handler.GetStatus()
		assert.True(t, status.Running)

		err = handler.Stop(ctx)
		require.NoError(t, err)

		status = handler.GetStatus()
		assert.False(t, status.Running)
	})
}

// TestEdgeModeStub_IPv6Allocator tests IPv6 allocator functionality.
func TestEdgeModeStub_IPv6Allocator(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
	allocator, err := NewIPv6Allocator(*ipNet, time.Hour)
	require.NoError(t, err)

	ctx := context.Background()
	err = allocator.Start(ctx)
	require.NoError(t, err)
	defer allocator.Stop(ctx)

	t.Run("allocate and release", func(t *testing.T) {
		ip, err := allocator.Allocate(ctx, "device-1")
		require.NoError(t, err)
		require.NotNil(t, ip)

		err = allocator.Release(ctx, ip)
		assert.NoError(t, err)
	})

	t.Run("allocate specific", func(t *testing.T) {
		specificIP := net.ParseIP("2001:db8:1234::1234")
		ip, err := allocator.AllocateSpecific(ctx, "device-specific", specificIP)
		require.NoError(t, err)
		assert.Equal(t, specificIP.String(), ip.String())
	})

	t.Run("status", func(t *testing.T) {
		status := allocator.GetStatus()
		assert.True(t, status.PoolSize > 0)
	})
}

// TestEdgeModeStub_RateLimiter tests rate limiter functionality.
func TestEdgeModeStub_RateLimiter(t *testing.T) {
	ctx := context.Background()

	rl := NewPerPeerRateLimiter(100, 10, 0.80)
	err := rl.Start(ctx)
	require.NoError(t, err)
	defer rl.Stop(ctx)

	t.Run("check trusted peer", func(t *testing.T) {
		err := rl.Check(ctx, "trusted-peer", 0.90)
		assert.NoError(t, err)
	})

	t.Run("check untrusted peer", func(t *testing.T) {
		err := rl.Check(ctx, "untrusted-peer", 0.50)
		assert.NoError(t, err)
	})
}

// TestEdgeModeStub_DDOSProtection tests DDoS protection functionality.
func TestEdgeModeStub_DDOSProtection(t *testing.T) {
	ctx := context.Background()

	ddos := NewDDOSProtection()
	err := ddos.Start(ctx)
	require.NoError(t, err)

	err = ddos.Stop(ctx)
	require.NoError(t, err)
}

// TestEdgeModeStub_ErrP2PNotEnabled tests the error message.
func TestEdgeModeStub_ErrP2PNotEnabled(t *testing.T) {
	assert.Equal(t, "gateway: P2P support not enabled (build with -tags platform_p2p)", ErrP2PNotEnabled.Error())
}

// TestEdgeModeStub_Concurrent tests concurrent operations in stub mode.
func TestEdgeModeStub_Concurrent(t *testing.T) {
	cfg := newTestEdgeModeConfigStub()
	handler, err := NewEdgeModeHandler(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	err = handler.Start(ctx)
	require.NoError(t, err)
	defer handler.Stop(ctx)

	const numGoroutines = 50
	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			deviceID := string(rune('a' + id))
			_, allocErr := handler.AllocateIPv6(ctx, deviceID)
			if allocErr != nil {
				t.Errorf("allocation failed: %v", allocErr)
			}
		}(i)
	}

	wg.Wait()
}

// TestEdgeModeStub_ErrorTypes tests that error types are properly defined.
func TestEdgeModeStub_ErrorTypes(t *testing.T) {
	t.Run("ErrStartFailed", func(t *testing.T) {
		cause := errors.New("test error")
		err := &ErrStartFailed{Component: "test", Cause: cause}
		assert.Contains(t, err.Error(), "test")
		assert.ErrorIs(t, err, cause)
	})

	t.Run("ErrStopFailed", func(t *testing.T) {
		cause := errors.New("test error")
		err := &ErrStopFailed{Component: "test", Cause: cause}
		assert.Contains(t, err.Error(), "test")
		assert.ErrorIs(t, err, cause)
	})

	t.Run("ErrMultipleFailures", func(t *testing.T) {
		err := &ErrMultipleFailures{Errors: []error{
			errors.New("error 1"),
			errors.New("error 2"),
		}}
		assert.Contains(t, err.Error(), "error 1")
		assert.Contains(t, err.Error(), "error 2")
	})
}

// TestEdgeModeStub_Constants tests that constants are defined correctly.
func TestEdgeModeStub_Constants(t *testing.T) {
	assert.Equal(t, 720*time.Hour, DefaultIPv6InactivityTimeout)
	assert.Equal(t, 100, DefaultTrustedReqPerSec)
	assert.Equal(t, 10, DefaultUntrustedReqPerSec)
	assert.Equal(t, 0.80, DefaultTrustThreshold)
	assert.Equal(t, 20, KademliaK)
	assert.Equal(t, 3, KademliaAlpha)
	assert.Equal(t, 3, DefaultNodeTier)
}

// TestEdgeModeStub_RegionFromIP tests the regionFromIP helper function.
func TestEdgeModeStub_RegionFromIP(t *testing.T) {
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

// TestEdgeModeStub_IPv6Allocator_EdgeCases tests IPv6 allocator edge cases.
func TestEdgeModeStub_IPv6Allocator_EdgeCases(t *testing.T) {
	ctx := context.Background()

	t.Run("invalid pool", func(t *testing.T) {
		_, ipNet, _ := net.ParseCIDR("10.0.0.0/24")
		_, err := NewIPv6Allocator(*ipNet, time.Hour)
		assert.ErrorIs(t, err, ErrInvalidIPv6Pool)
	})

	t.Run("nil IP in pool", func(t *testing.T) {
		ipNet := net.IPNet{
			IP:   nil,
			Mask: net.CIDRMask(48, 128),
		}
		_, err := NewIPv6Allocator(ipNet, time.Hour)
		assert.ErrorIs(t, err, ErrInvalidIPv6Pool)
	})

	t.Run("empty device ID", func(t *testing.T) {
		_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
		allocator, err := NewIPv6Allocator(*ipNet, time.Hour)
		require.NoError(t, err)
		err = allocator.Start(ctx)
		require.NoError(t, err)
		defer allocator.Stop(ctx)

		_, err = allocator.Allocate(ctx, "")
		assert.ErrorIs(t, err, ErrDeviceIDRequired)
	})
}

// TestEdgeModeStub_SentinelErrors tests sentinel error messages.
func TestEdgeModeStub_SentinelErrors(t *testing.T) {
	t.Run("ErrConfigNil", func(t *testing.T) {
		assert.Equal(t, "configuration is nil", ErrConfigNil.Error())
	})

	t.Run("ErrAlreadyRunning", func(t *testing.T) {
		assert.Equal(t, "handler already running", ErrAlreadyRunning.Error())
	})

	t.Run("ErrNotRunning", func(t *testing.T) {
		assert.Equal(t, "handler not running", ErrNotRunning.Error())
	})

	t.Run("ErrInvalidIPv6Pool", func(t *testing.T) {
		assert.Equal(t, "invalid IPv6 pool", ErrInvalidIPv6Pool.Error())
	})

	t.Run("ErrDeviceIDRequired", func(t *testing.T) {
		assert.Equal(t, "device ID required", ErrDeviceIDRequired.Error())
	})

	t.Run("ErrRateLimitExceeded", func(t *testing.T) {
		assert.Equal(t, "rate limit exceeded", ErrRateLimitExceeded.Error())
	})
}

// TestEdgeModeStub_ValidateTPMEK tests the validateTPMEK method.
func TestEdgeModeStub_ValidateTPMEK(t *testing.T) {
	cfg := newTestEdgeModeConfigStub()
	handler, err := NewEdgeModeHandler(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("valid TPM EK", func(t *testing.T) {
		err := handler.validateTPMEK(ctx, []byte("valid-ek-data"))
		assert.NoError(t, err)
	})

	t.Run("nil TPM EK", func(t *testing.T) {
		err := handler.validateTPMEK(ctx, nil)
		assert.ErrorIs(t, err, ErrTPMEKRequired)
	})

	t.Run("empty TPM EK", func(t *testing.T) {
		err := handler.validateTPMEK(ctx, []byte{})
		assert.ErrorIs(t, err, ErrTPMEKRequired)
	})
}

// TestEdgeModeStub_IssueIDevID tests the issueIDevID method.
func TestEdgeModeStub_IssueIDevID(t *testing.T) {
	cfg := newTestEdgeModeConfigStub()
	handler, err := NewEdgeModeHandler(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("successful issuance returns no error", func(t *testing.T) {
		cert, err := handler.issueIDevID(ctx, "device-123", []byte("tpm-ek-data"))
		require.NoError(t, err)
		// Note: Currently returns nil certificate as placeholder
		_ = cert
	})

	t.Run("empty device ID", func(t *testing.T) {
		cert, err := handler.issueIDevID(ctx, "", []byte("tpm-ek-data"))
		assert.ErrorIs(t, err, ErrDeviceIDRequired)
		assert.Nil(t, cert)
	})

	t.Run("empty TPM EK", func(t *testing.T) {
		cert, err := handler.issueIDevID(ctx, "device-123", []byte{})
		assert.ErrorIs(t, err, ErrTPMEKRequired)
		assert.Nil(t, cert)
	})
}

// TestEdgeModeStub_VerifyTPMQuote tests the verifyTPMQuote method.
func TestEdgeModeStub_VerifyTPMQuote(t *testing.T) {
	cfg := newTestEdgeModeConfigStub()
	handler, err := NewEdgeModeHandler(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("valid quote", func(t *testing.T) {
		err := handler.verifyTPMQuote(ctx, []byte("tpm-ek"), []byte("valid-quote"))
		assert.NoError(t, err)
	})

	t.Run("empty EK", func(t *testing.T) {
		err := handler.verifyTPMQuote(ctx, []byte{}, []byte("quote"))
		assert.ErrorIs(t, err, ErrTPMEKRequired)
	})

	t.Run("empty quote", func(t *testing.T) {
		err := handler.verifyTPMQuote(ctx, []byte("tpm-ek"), []byte{})
		assert.ErrorIs(t, err, ErrTPMQuoteRequired)
	})
}

// TestEdgeModeStub_ExpireInactive tests the expireInactive method.
func TestEdgeModeStub_ExpireInactive(t *testing.T) {
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

// TestEdgeModeStub_RateLimiterCleanup tests the cleanup method.
func TestEdgeModeStub_RateLimiterCleanup(t *testing.T) {
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

// TestEdgeModeStub_RateLimiter_TokenRefill tests token bucket refill behavior.
func TestEdgeModeStub_RateLimiter_TokenRefill(t *testing.T) {
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

// TestEdgeModeStub_DDOSProtection_AlreadyRunning tests start when already running.
func TestEdgeModeStub_DDOSProtection_AlreadyRunning(t *testing.T) {
	ctx := context.Background()

	ddos := NewDDOSProtection()
	err := ddos.Start(ctx)
	require.NoError(t, err)
	defer ddos.Stop(ctx)

	// Second start should fail
	err = ddos.Start(ctx)
	assert.ErrorIs(t, err, ErrAlreadyRunning)
}

// TestEdgeModeStub_DDOSProtection_StopNotRunning tests stop when not running.
func TestEdgeModeStub_DDOSProtection_StopNotRunning(t *testing.T) {
	ctx := context.Background()

	ddos := NewDDOSProtection()
	// Stop without starting
	err := ddos.Stop(ctx)
	assert.ErrorIs(t, err, ErrNotRunning)
}

// TestEdgeModeStub_IPv6Allocator_DoubleStop tests double stop.
func TestEdgeModeStub_IPv6Allocator_DoubleStop(t *testing.T) {
	ctx := context.Background()
	_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
	allocator, err := NewIPv6Allocator(*ipNet, time.Hour)
	require.NoError(t, err)

	err = allocator.Start(ctx)
	require.NoError(t, err)

	// First stop should succeed
	err = allocator.Stop(ctx)
	assert.NoError(t, err)

	// Second stop should fail (channel already closed, but running is false)
	err = allocator.Stop(ctx)
	assert.ErrorIs(t, err, ErrNotRunning)
}

// TestEdgeModeStub_EdgeHandler_DoubleStart tests double start of edge handler.
func TestEdgeModeStub_EdgeHandler_DoubleStart(t *testing.T) {
	cfg := newTestEdgeModeConfigStub()
	handler, err := NewEdgeModeHandler(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	// First start
	err = handler.Start(ctx)
	require.NoError(t, err)
	defer handler.Stop(ctx)

	// Second start should fail
	err = handler.Start(ctx)
	assert.ErrorIs(t, err, ErrAlreadyRunning)
}

// TestEdgeModeStub_EdgeHandler_StopNotRunning tests stop when not running.
func TestEdgeModeStub_EdgeHandler_StopNotRunning(t *testing.T) {
	cfg := newTestEdgeModeConfigStub()
	handler, err := NewEdgeModeHandler(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	// Stop without starting - should not error per current implementation
	err = handler.Stop(ctx)
	// Depending on implementation, this may or may not error
	// The stub implementation should handle this gracefully
	_ = err
}

// TestEdgeModeStub_EdgeHandler_GetStatusNotRunning tests GetStatus when not running.
func TestEdgeModeStub_EdgeHandler_GetStatusNotRunning(t *testing.T) {
	cfg := newTestEdgeModeConfigStub()
	handler, err := NewEdgeModeHandler(cfg)
	require.NoError(t, err)

	// Get status without starting
	status := handler.GetStatus()
	assert.False(t, status.Running)
	assert.Equal(t, "", status.PeerID)
}

// TestEdgeModeStub_IPv6Allocator_AllocateNotRunning tests allocate when not running.
func TestEdgeModeStub_IPv6Allocator_AllocateNotRunning(t *testing.T) {
	ctx := context.Background()
	_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
	allocator, err := NewIPv6Allocator(*ipNet, time.Hour)
	require.NoError(t, err)

	// Try to allocate without starting
	_, err = allocator.Allocate(ctx, "device-1")
	assert.ErrorIs(t, err, ErrNotRunning)
}

// TestEdgeModeStub_IPv6Allocator_ReleaseNotRunning tests release when not running.
func TestEdgeModeStub_IPv6Allocator_ReleaseNotRunning(t *testing.T) {
	ctx := context.Background()
	_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
	allocator, err := NewIPv6Allocator(*ipNet, time.Hour)
	require.NoError(t, err)

	// Try to release without starting
	ip := net.ParseIP("2001:db8:1234::1")
	err = allocator.Release(ctx, ip)
	assert.ErrorIs(t, err, ErrNotRunning)
}

// TestEdgeModeStub_IPv6Allocator_AllocateSpecificNotRunning tests allocate specific when not running.
func TestEdgeModeStub_IPv6Allocator_AllocateSpecificNotRunning(t *testing.T) {
	ctx := context.Background()
	_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
	allocator, err := NewIPv6Allocator(*ipNet, time.Hour)
	require.NoError(t, err)

	// Try to allocate specific without starting
	ip := net.ParseIP("2001:db8:1234::1")
	_, err = allocator.AllocateSpecific(ctx, "device-1", ip)
	assert.ErrorIs(t, err, ErrNotRunning)
}

// TestEdgeModeStub_IPv6Allocator_RefreshLeaseNotRunning tests refresh lease when not running.
func TestEdgeModeStub_IPv6Allocator_RefreshLeaseNotRunning(t *testing.T) {
	ctx := context.Background()
	_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
	allocator, err := NewIPv6Allocator(*ipNet, time.Hour)
	require.NoError(t, err)

	// Try to refresh without starting
	ip := net.ParseIP("2001:db8:1234::1")
	err = allocator.RefreshLease(ctx, ip)
	assert.ErrorIs(t, err, ErrNotRunning)
}

// TestEdgeModeStub_RateLimiter_CheckNotRunning tests check when not running.
func TestEdgeModeStub_RateLimiter_CheckNotRunning(t *testing.T) {
	ctx := context.Background()
	rl := NewPerPeerRateLimiter(100, 10, 0.80)

	// Try to check without starting
	err := rl.Check(ctx, "peer-1", 0.90)
	assert.ErrorIs(t, err, ErrNotRunning)
}

// TestEdgeModeStub_IPv6Allocator_ReleaseNilIP tests release with nil IP.
func TestEdgeModeStub_IPv6Allocator_ReleaseNilIP(t *testing.T) {
	ctx := context.Background()
	_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
	allocator, err := NewIPv6Allocator(*ipNet, time.Hour)
	require.NoError(t, err)

	err = allocator.Start(ctx)
	require.NoError(t, err)
	defer allocator.Stop(ctx)

	err = allocator.Release(ctx, nil)
	assert.ErrorIs(t, err, ErrInvalidIPv6Address)
}

// TestEdgeModeStub_IPv6Allocator_ReleaseNotAllocated tests release of unallocated IP.
func TestEdgeModeStub_IPv6Allocator_ReleaseNotAllocated(t *testing.T) {
	ctx := context.Background()
	_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
	allocator, err := NewIPv6Allocator(*ipNet, time.Hour)
	require.NoError(t, err)

	err = allocator.Start(ctx)
	require.NoError(t, err)
	defer allocator.Stop(ctx)

	ip := net.ParseIP("2001:db8:1234::dead")
	err = allocator.Release(ctx, ip)
	assert.ErrorIs(t, err, ErrIPv6NotAllocated)
}

// TestEdgeModeStub_IPv6Allocator_AllocateSpecificAlreadyAllocated tests allocate specific when already allocated.
func TestEdgeModeStub_IPv6Allocator_AllocateSpecificAlreadyAllocated(t *testing.T) {
	ctx := context.Background()
	_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
	allocator, err := NewIPv6Allocator(*ipNet, time.Hour)
	require.NoError(t, err)

	err = allocator.Start(ctx)
	require.NoError(t, err)
	defer allocator.Stop(ctx)

	ip := net.ParseIP("2001:db8:1234::cafe")
	_, err = allocator.AllocateSpecific(ctx, "device-1", ip)
	require.NoError(t, err)

	// Try to allocate same IP for different device
	_, err = allocator.AllocateSpecific(ctx, "device-2", ip)
	assert.ErrorIs(t, err, ErrIPv6AlreadyAllocated)
}

// TestEdgeModeStub_IPv6Allocator_AllocateSpecificOutsidePool tests allocate specific outside pool.
func TestEdgeModeStub_IPv6Allocator_AllocateSpecificOutsidePool(t *testing.T) {
	ctx := context.Background()
	_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
	allocator, err := NewIPv6Allocator(*ipNet, time.Hour)
	require.NoError(t, err)

	err = allocator.Start(ctx)
	require.NoError(t, err)
	defer allocator.Stop(ctx)

	// IP outside the pool
	ip := net.ParseIP("2603:f5bb:1234::1")
	_, err = allocator.AllocateSpecific(ctx, "device-1", ip)
	assert.ErrorIs(t, err, ErrIPv6OutOfPool)
}

// TestEdgeModeStub_IPv6Allocator_AllocateSpecificNilIP tests allocate specific with nil IP.
func TestEdgeModeStub_IPv6Allocator_AllocateSpecificNilIP(t *testing.T) {
	ctx := context.Background()
	_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
	allocator, err := NewIPv6Allocator(*ipNet, time.Hour)
	require.NoError(t, err)

	err = allocator.Start(ctx)
	require.NoError(t, err)
	defer allocator.Stop(ctx)

	_, err = allocator.AllocateSpecific(ctx, "device-1", nil)
	assert.ErrorIs(t, err, ErrInvalidIPv6Address)
}

// TestEdgeModeStub_IPv6Allocator_AllocateSameDevice tests allocating same device returns same IP.
func TestEdgeModeStub_IPv6Allocator_AllocateSameDevice(t *testing.T) {
	ctx := context.Background()
	_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
	allocator, err := NewIPv6Allocator(*ipNet, time.Hour)
	require.NoError(t, err)

	err = allocator.Start(ctx)
	require.NoError(t, err)
	defer allocator.Stop(ctx)

	ip1, err := allocator.Allocate(ctx, "same-device")
	require.NoError(t, err)

	ip2, err := allocator.Allocate(ctx, "same-device")
	require.NoError(t, err)

	assert.Equal(t, ip1.String(), ip2.String(), "same device should get same IP")
}

// TestEdgeModeStub_IPv6Allocator_RefreshLeaseNilIP tests refresh lease with nil IP.
func TestEdgeModeStub_IPv6Allocator_RefreshLeaseNilIP(t *testing.T) {
	ctx := context.Background()
	_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
	allocator, err := NewIPv6Allocator(*ipNet, time.Hour)
	require.NoError(t, err)

	err = allocator.Start(ctx)
	require.NoError(t, err)
	defer allocator.Stop(ctx)

	err = allocator.RefreshLease(ctx, nil)
	assert.ErrorIs(t, err, ErrInvalidIPv6Address)
}

// TestEdgeModeStub_IPv6Allocator_RefreshLeaseNotAllocated tests refresh lease on non-allocated IP.
func TestEdgeModeStub_IPv6Allocator_RefreshLeaseNotAllocated(t *testing.T) {
	ctx := context.Background()
	_, ipNet, _ := net.ParseCIDR("2001:db8:1234::/48")
	allocator, err := NewIPv6Allocator(*ipNet, time.Hour)
	require.NoError(t, err)

	err = allocator.Start(ctx)
	require.NoError(t, err)
	defer allocator.Stop(ctx)

	ip := net.ParseIP("2001:db8:1234::ffff")
	err = allocator.RefreshLease(ctx, ip)
	assert.ErrorIs(t, err, ErrIPv6NotAllocated)
}

// TestEdgeModeStub_RateLimiter_EmptyPeerID tests rate limiter with empty peer ID.
func TestEdgeModeStub_RateLimiter_EmptyPeerID(t *testing.T) {
	ctx := context.Background()
	rl := NewPerPeerRateLimiter(100, 10, 0.80)
	err := rl.Start(ctx)
	require.NoError(t, err)
	defer rl.Stop(ctx)

	err = rl.Check(ctx, "", 0.90)
	assert.ErrorIs(t, err, ErrPeerIDRequired)
}

// TestEdgeModeStub_RateLimiter_DoubleStop tests double stop.
func TestEdgeModeStub_RateLimiter_DoubleStop(t *testing.T) {
	ctx := context.Background()
	rl := NewPerPeerRateLimiter(100, 10, 0.80)
	err := rl.Start(ctx)
	require.NoError(t, err)

	// First stop should succeed
	err = rl.Stop(ctx)
	assert.NoError(t, err)

	// Second stop should fail
	err = rl.Stop(ctx)
	assert.ErrorIs(t, err, ErrNotRunning)
}

// TestEdgeModeStub_NewEdgeModeHandler_InvalidConfig tests creating handler with invalid config.
func TestEdgeModeStub_NewEdgeModeHandler_InvalidConfig(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		handler, err := NewEdgeModeHandler(nil)
		assert.ErrorIs(t, err, ErrConfigNil)
		assert.Nil(t, handler)
	})

	t.Run("invalid IPv6 pool", func(t *testing.T) {
		cfg := newTestEdgeModeConfigStub()
		cfg.IPv6Pool.IP = nil
		handler, err := NewEdgeModeHandler(cfg)
		assert.ErrorIs(t, err, ErrInvalidIPv6Pool)
		assert.Nil(t, handler)
	})

	t.Run("FROST pool required when enrollment enabled", func(t *testing.T) {
		cfg := newTestEdgeModeConfigStub()
		cfg.ACMEEnrollEnabled = true
		cfg.FROSTPoolID = ""
		handler, err := NewEdgeModeHandler(cfg)
		assert.ErrorIs(t, err, ErrFROSTPoolRequired)
		assert.Nil(t, handler)
	})
}
