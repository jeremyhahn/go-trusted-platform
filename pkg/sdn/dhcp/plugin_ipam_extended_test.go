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
	"errors"
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

// TestIPAMPlugin_HandleDiscover_AllocationFailure tests allocation failure in handleDiscover.
func TestIPAMPlugin_HandleDiscover_AllocationFailure(t *testing.T) {
	ctx := context.Background()

	t.Run("handles allocation error gracefully", func(t *testing.T) {
		allocator := newMockAllocator()
		allocator.allocErr = errors.New("pool exhausted")
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

		handler := plugin.Handler4()

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		resp, _ := dhcpv4.NewReplyFromRequest(req)
		resp.ServerIPAddr = net.ParseIP("192.168.1.1")

		result, stop := handler(req, resp)
		// Should return nil when allocation fails
		assert.Nil(t, result)
		assert.True(t, stop)
	})

	t.Run("handles lease store add failure after allocation", func(t *testing.T) {
		allocator := backends.NewMemoryBackend()
		defer allocator.Close()

		poolID := "test-pool"
		createTestPool(ctx, t, allocator, poolID)

		opts := DHCPOptions{
			SubnetMask: net.CIDRMask(24, 32),
			Router:     netip.MustParseAddr("192.168.1.1"),
			LeaseTime:  time.Hour,
		}

		// Create a custom lease store that's already closed
		closedLeaseStore := NewLeaseStore()
		closedLeaseStore.Close()

		plugin, err := NewIPAMPlugin(allocator, poolID, opts, WithLeaseStore(closedLeaseStore))
		require.NoError(t, err)
		defer plugin.Close()

		handler := plugin.Handler4()

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		resp, _ := dhcpv4.NewReplyFromRequest(req)
		resp.ServerIPAddr = net.ParseIP("192.168.1.1")

		result, stop := handler(req, resp)
		// Should return nil when lease store add fails
		assert.Nil(t, result)
		assert.True(t, stop)
	})
}

// TestIPAMPlugin_HandleDiscover_RenewalFailure tests renewal failure for existing lease.
func TestIPAMPlugin_HandleDiscover_RenewalFailure(t *testing.T) {
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

	t.Run("allocates new IP when renewal fails", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:56")

		// First discover to get a lease
		req1, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		resp1, _ := dhcpv4.NewReplyFromRequest(req1)
		resp1.ServerIPAddr = net.ParseIP("192.168.1.1")

		result1, _ := handler(req1, resp1)
		require.NotNil(t, result1)
		firstIP := result1.YourIPAddr

		// Release the IP from IPAM to make renewal fail
		ipAddr, _ := netip.AddrFromSlice(firstIP.To4())
		err := allocator.Release(ctx, ipAddr)
		require.NoError(t, err)

		// Second discover should allocate new IP
		req2, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		resp2, _ := dhcpv4.NewReplyFromRequest(req2)
		resp2.ServerIPAddr = net.ParseIP("192.168.1.1")

		result2, _ := handler(req2, resp2)
		require.NotNil(t, result2)
		assert.Equal(t, dhcpv4.MessageTypeOffer, result2.MessageType())
	})
}

// TestIPAMPlugin_HandleRequest_LeaseStoreFailure tests lease store failures in handleRequest.
func TestIPAMPlugin_HandleRequest_LeaseStoreFailure(t *testing.T) {
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

	t.Run("NAKs when specific allocation fails for new client", func(t *testing.T) {
		plugin, err := NewIPAMPlugin(allocator, poolID, opts)
		require.NoError(t, err)
		defer plugin.Close()

		handler := plugin.Handler4()

		// Another client first allocates the IP
		mac1, _ := net.ParseMAC("00:11:22:33:55:01")
		discoverReq, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac1),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		discoverResp, _ := dhcpv4.NewReplyFromRequest(discoverReq)
		discoverResp.ServerIPAddr = net.ParseIP("192.168.1.1")
		offerResult, _ := handler(discoverReq, discoverResp)
		require.NotNil(t, offerResult)
		allocatedIP := offerResult.YourIPAddr

		// New client requests the already allocated IP (not in lease store)
		mac2, _ := net.ParseMAC("00:11:22:33:55:02")
		requestReq, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac2),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
			withRequestedIP(allocatedIP),
		)
		requestResp, _ := dhcpv4.NewReplyFromRequest(requestReq)
		requestResp.ServerIPAddr = net.ParseIP("192.168.1.1")

		result, stop := handler(requestReq, requestResp)
		require.NotNil(t, result)
		assert.True(t, stop)
		assert.Equal(t, dhcpv4.MessageTypeNak, result.MessageType())
	})
}

// TestIPAMPlugin_HandleRequest_RenewalError tests renewal error handling.
func TestIPAMPlugin_HandleRequest_RenewalError(t *testing.T) {
	allocator := newMockAllocator()
	allocator.renewErr = errors.New("renewal failed")
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

	handler := plugin.Handler4()

	t.Run("NAKs when IPAM renewal fails", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:77")

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

		// Now send request - renewal will fail
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
		assert.Equal(t, dhcpv4.MessageTypeNak, result.MessageType())
	})
}

// TestIPAMPlugin_HandleRelease_IPv6Handling tests IPv6 address handling in release.
func TestIPAMPlugin_HandleRelease_IPv6Handling(t *testing.T) {
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

	handler := plugin.Handler4()

	t.Run("handles release with invalid IP conversion", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:CC")

		// Create a request with an IP that's not a valid IPv4
		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeRelease),
		)
		// Set an invalid client IP (too short to be valid)
		req.ClientIPAddr = net.IP{1, 2}

		resp, _ := dhcpv4.NewReplyFromRequest(req)

		result, stop := handler(req, resp)
		assert.Nil(t, result)
		assert.True(t, stop)
	})
}

// TestIPAMPlugin_HandleInform_IPv6Handling tests IPv6 address handling in inform.
func TestIPAMPlugin_HandleInform_IPv6Handling(t *testing.T) {
	allocator := newMockAllocator()
	defer allocator.Close()

	poolID := "test-pool"
	opts := DHCPOptions{
		SubnetMask: net.CIDRMask(24, 32),
		Router:     netip.MustParseAddr("192.168.1.1"),
		DNS:        []netip.Addr{netip.MustParseAddr("8.8.8.8")},
		DomainName: "example.com",
		LeaseTime:  time.Hour,
	}

	plugin, err := NewIPAMPlugin(allocator, poolID, opts)
	require.NoError(t, err)
	defer plugin.Close()

	handler := plugin.Handler4()

	t.Run("handles inform with invalid IP conversion", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:DD")

		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeInform),
		)
		// Set an invalid client IP
		req.ClientIPAddr = net.IP{1, 2}

		resp, _ := dhcpv4.NewReplyFromRequest(req)

		result, stop := handler(req, resp)
		assert.Nil(t, result)
		assert.True(t, stop)
	})

	t.Run("handles inform with valid IPv6 address", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:EE")

		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeInform),
		)
		// Use an IPv4 address represented as IPv6 (common in dhcp libraries)
		req.ClientIPAddr = net.ParseIP("192.168.1.50")

		resp, _ := dhcpv4.NewReplyFromRequest(req)
		resp.ServerIPAddr = net.ParseIP("192.168.1.1")

		result, stop := handler(req, resp)
		require.NotNil(t, result)
		assert.True(t, stop)
		assert.Equal(t, dhcpv4.MessageTypeAck, result.MessageType())
	})
}

// TestIPAMPlugin_SetOptions_ValidationFailure tests SetOptions validation failure.
func TestIPAMPlugin_SetOptions_ValidationFailure(t *testing.T) {
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

	t.Run("SetOptions with zero lease time gets default", func(t *testing.T) {
		// Note: Current implementation sets defaults, so this should succeed
		newOpts := DHCPOptions{
			SubnetMask: net.CIDRMask(24, 32),
			Router:     netip.MustParseAddr("192.168.1.254"),
		}

		err := plugin.SetOptions(newOpts)
		require.NoError(t, err)

		// Verify defaults were applied
		retrieved := plugin.GetOptions()
		assert.Equal(t, DefaultLeaseDuration, retrieved.LeaseTime)
	})
}

// TestIPAMPlugin_HandleRequest_LeaseStoreAddFailure tests lease store add failure in request handling.
func TestIPAMPlugin_HandleRequest_LeaseStoreAddFailure(t *testing.T) {
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

	// Create a closed lease store
	closedLeaseStore := NewLeaseStore()
	closedLeaseStore.Close()

	plugin, err := NewIPAMPlugin(allocator, poolID, opts, WithLeaseStore(closedLeaseStore))
	require.NoError(t, err)
	defer plugin.Close()

	handler := plugin.Handler4()

	t.Run("NAKs when lease store add fails for new client request", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:88:01")
		requestedIP := net.ParseIP("192.168.1.200")

		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
			withRequestedIP(requestedIP),
		)
		resp, _ := dhcpv4.NewReplyFromRequest(req)
		resp.ServerIPAddr = net.ParseIP("192.168.1.1")

		result, stop := handler(req, resp)
		require.NotNil(t, result)
		assert.True(t, stop)
		assert.Equal(t, dhcpv4.MessageTypeNak, result.MessageType())
	})
}
