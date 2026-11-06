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

// TestIPAMPlugin_GetRequestedIP_FallbackToIPv6 tests the IPv6 fallback path in getRequestedIP.
func TestIPAMPlugin_GetRequestedIP_FallbackToIPv6(t *testing.T) {
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

	t.Run("handles ciaddr that is nil for To4 but valid for To16", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:DD:01")

		// First get a lease
		discoverReq, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		discoverResp, _ := dhcpv4.NewReplyFromRequest(discoverReq)
		discoverResp.ServerIPAddr = net.ParseIP("192.168.1.1")

		offerResult, _ := handler(discoverReq, discoverResp)
		require.NotNil(t, offerResult)
		offeredIP := offerResult.YourIPAddr

		// Request using the IPv6 representation of the IPv4 address
		// net.IP can be 16 bytes (IPv4-mapped IPv6)
		requestReq, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		)
		// Set ciaddr to IPv4-mapped IPv6 form: ::ffff:192.168.1.x
		ipv4Mapped := offeredIP.To16()
		requestReq.ClientIPAddr = ipv4Mapped

		requestResp, _ := dhcpv4.NewReplyFromRequest(requestReq)
		requestResp.ServerIPAddr = net.ParseIP("192.168.1.1")

		result, stop := handler(requestReq, requestResp)
		require.NotNil(t, result)
		assert.True(t, stop)
		assert.Equal(t, dhcpv4.MessageTypeAck, result.MessageType())
	})
}

// TestIPAMPlugin_GetRequestedIP_InvalidOption50 tests handling of invalid option 50.
func TestIPAMPlugin_GetRequestedIP_InvalidOption50(t *testing.T) {
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

	t.Run("NAKs request with invalid option 50 and no ciaddr", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:EE:01")

		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		)
		// Set option 50 with invalid data (exactly 4 bytes but all zeros creates IPv4 unspecified)
		req.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionRequestedIPAddress, []byte{0, 0, 0, 0}))

		resp, _ := dhcpv4.NewReplyFromRequest(req)
		resp.ServerIPAddr = net.ParseIP("192.168.1.1")

		result, stop := handler(req, resp)
		require.NotNil(t, result)
		assert.True(t, stop)
		// Should get NAK because 0.0.0.0 is not valid
		assert.Equal(t, dhcpv4.MessageTypeNak, result.MessageType())
	})

	t.Run("uses ciaddr when option 50 has invalid length", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:EE:02")

		// First get a lease
		discoverReq, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		discoverResp, _ := dhcpv4.NewReplyFromRequest(discoverReq)
		discoverResp.ServerIPAddr = net.ParseIP("192.168.1.1")

		offerResult, _ := handler(discoverReq, discoverResp)
		require.NotNil(t, offerResult)
		offeredIP := offerResult.YourIPAddr

		// Request with invalid option 50 but valid ciaddr
		requestReq, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		)
		// Set option 50 with invalid length (only 2 bytes)
		requestReq.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionRequestedIPAddress, []byte{1, 2}))
		// Set valid ciaddr
		requestReq.ClientIPAddr = offeredIP

		requestResp, _ := dhcpv4.NewReplyFromRequest(requestReq)
		requestResp.ServerIPAddr = net.ParseIP("192.168.1.1")

		result, stop := handler(requestReq, requestResp)
		require.NotNil(t, result)
		assert.True(t, stop)
		// Should ACK because ciaddr is valid
		assert.Equal(t, dhcpv4.MessageTypeAck, result.MessageType())
	})
}

// TestIPAMPlugin_HandleRelease_ReleaseError tests IPAM release error handling.
func TestIPAMPlugin_HandleRelease_ReleaseError(t *testing.T) {
	allocator := newMockAllocator()
	allocator.releaseErr = assert.AnError
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

	t.Run("logs warning when IPAM release fails but continues", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:FF:01")

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

		// Release - should succeed even though IPAM release fails
		releaseReq, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeRelease),
			dhcpv4.WithClientIP(leasedIP),
		)
		releaseResp, _ := dhcpv4.NewReplyFromRequest(releaseReq)

		result, stop := handler(releaseReq, releaseResp)
		assert.Nil(t, result)
		assert.True(t, stop)

		// Lease should still be removed from local store
		_, found = plugin.GetLeaseStore().GetByMAC(mac)
		assert.False(t, found)
	})
}
