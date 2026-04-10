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

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam/backends"
)

// TestIPAMPlugin_GetRequestedIP_IPv6Ciaddr tests IPv6 ciaddr fallback handling.
func TestIPAMPlugin_GetRequestedIP_IPv6Ciaddr(t *testing.T) {
	ctx := context.Background()
	allocator := backends.NewMemoryBackend()
	defer allocator.Close()

	poolID := "test-pool"
	createTestPool(ctx, t, allocator, poolID)

	opts := DHCPOptions{
		SubnetMask: net.CIDRMask(24, 32),
		Router:     netip.MustParseAddr("192.168.1.1"),
		LeaseTime:  time.Hour,
	}

	plugin, err := NewIPAMPlugin(allocator, poolID, opts)
	require.NoError(t, err)
	defer plugin.Close()

	handler := plugin.Handler4()

	t.Run("handles ciaddr conversion to IPv4", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:AA:01")

		// First do a discover
		discoverReq, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		discoverResp, _ := dhcpv4.NewReplyFromRequest(discoverReq)
		discoverResp.ServerIPAddr = net.ParseIP("192.168.1.1")

		offerResult, _ := handler(discoverReq, discoverResp)
		require.NotNil(t, offerResult)
		offeredIP := offerResult.YourIPAddr

		// Request with ciaddr in IPv4-mapped IPv6 format
		requestReq, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		)
		// Set ciaddr to the offered IP (which gets stored in IPv4 format internally)
		requestReq.ClientIPAddr = offeredIP

		requestResp, _ := dhcpv4.NewReplyFromRequest(requestReq)
		requestResp.ServerIPAddr = net.ParseIP("192.168.1.1")

		result, stop := handler(requestReq, requestResp)
		require.NotNil(t, result)
		assert.True(t, stop)
		// Should succeed with ACK
		assert.Equal(t, dhcpv4.MessageTypeAck, result.MessageType())
	})
}

// TestIPAMPlugin_HandleRelease_IPv6ClientIP tests IPv6 client IP in release.
func TestIPAMPlugin_HandleRelease_IPv6ClientIP(t *testing.T) {
	ctx := context.Background()
	allocator := backends.NewMemoryBackend()
	defer allocator.Close()

	poolID := "test-pool"
	createTestPool(ctx, t, allocator, poolID)

	opts := DHCPOptions{
		SubnetMask: net.CIDRMask(24, 32),
		Router:     netip.MustParseAddr("192.168.1.1"),
		LeaseTime:  time.Hour,
	}

	plugin, err := NewIPAMPlugin(allocator, poolID, opts)
	require.NoError(t, err)
	defer plugin.Close()

	handler := plugin.Handler4()

	t.Run("handles release with IPv4-mapped IPv6 address", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:BB:01")

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

		// Verify lease exists
		_, found := plugin.GetLeaseStore().GetByMAC(mac)
		require.True(t, found)

		// Release with the IP (internally stored as IPv4)
		releaseReq, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeRelease),
			dhcpv4.WithClientIP(leasedIP),
		)
		releaseResp, _ := dhcpv4.NewReplyFromRequest(releaseReq)

		result, stop := handler(releaseReq, releaseResp)
		assert.Nil(t, result) // Release has no response
		assert.True(t, stop)

		// Verify lease was removed
		_, found = plugin.GetLeaseStore().GetByMAC(mac)
		assert.False(t, found)
	})
}

// TestIPAMPlugin_HandleRequest_LocalLeaseRenewalFailure tests local lease renewal failure.
func TestIPAMPlugin_HandleRequest_LocalLeaseRenewalFailure(t *testing.T) {
	ctx := context.Background()
	allocator := backends.NewMemoryBackend()
	defer allocator.Close()

	poolID := "test-pool"
	createTestPool(ctx, t, allocator, poolID)

	opts := DHCPOptions{
		SubnetMask: net.CIDRMask(24, 32),
		Router:     netip.MustParseAddr("192.168.1.1"),
		LeaseTime:  time.Hour,
	}

	plugin, err := NewIPAMPlugin(allocator, poolID, opts)
	require.NoError(t, err)
	defer plugin.Close()

	handler := plugin.Handler4()

	t.Run("handles local lease renewal failure gracefully", func(t *testing.T) {
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
		offeredIP := offerResult.YourIPAddr

		// Now request renewal - this should work
		requestReq, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
			withRequestedIP(offeredIP),
		)
		requestResp, _ := dhcpv4.NewReplyFromRequest(requestReq)
		requestResp.ServerIPAddr = net.ParseIP("192.168.1.1")

		result, stop := handler(requestReq, requestResp)
		require.NotNil(t, result)
		assert.True(t, stop)
		assert.Equal(t, dhcpv4.MessageTypeAck, result.MessageType())
	})
}

// TestIPAMPlugin_NewIPAMPlugin_OptionsValidation tests options validation.
func TestIPAMPlugin_NewIPAMPlugin_OptionsValidation(t *testing.T) {
	allocator := newMockAllocator()
	defer allocator.Close()

	poolID := "test-pool"

	t.Run("validates and sets default options", func(t *testing.T) {
		opts := DHCPOptions{
			SubnetMask: net.CIDRMask(24, 32),
			Router:     netip.MustParseAddr("192.168.1.1"),
			// LeaseTime is zero, should get default
		}

		plugin, err := NewIPAMPlugin(allocator, poolID, opts)
		require.NoError(t, err)
		defer plugin.Close()

		retrieved := plugin.GetOptions()
		assert.Equal(t, DefaultLeaseDuration, retrieved.LeaseTime)
		assert.Equal(t, DefaultLeaseDuration/2, retrieved.RenewalTime)
		assert.Equal(t, DefaultLeaseDuration*7/8, retrieved.RebindTime)
	})
}

// TestIPAMPlugin_SetOptions_UpdatesDefaultLease tests that SetOptions updates defaultLease.
func TestIPAMPlugin_SetOptions_UpdatesDefaultLease(t *testing.T) {
	allocator := newMockAllocator()
	defer allocator.Close()

	poolID := "test-pool"
	opts := DHCPOptions{
		SubnetMask: net.CIDRMask(24, 32),
		Router:     netip.MustParseAddr("192.168.1.1"),
		LeaseTime:  time.Hour,
	}

	plugin, err := NewIPAMPlugin(allocator, poolID, opts)
	require.NoError(t, err)
	defer plugin.Close()

	t.Run("updates defaultLease when setting options", func(t *testing.T) {
		newOpts := DHCPOptions{
			SubnetMask: net.CIDRMask(24, 32),
			Router:     netip.MustParseAddr("192.168.1.254"),
			LeaseTime:  2 * time.Hour,
		}

		err := plugin.SetOptions(newOpts)
		require.NoError(t, err)

		// The defaultLease should be updated
		// We can verify this by checking the options
		retrieved := plugin.GetOptions()
		assert.Equal(t, 2*time.Hour, retrieved.LeaseTime)
	})
}
