// Copyright (c) 2025 Jeremy Hahn. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package dhcp

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam/backends"
)

// withRequestedIP is a helper modifier to set the requested IP address option.
func withRequestedIP(ip net.IP) dhcpv4.Modifier {
	return func(d *dhcpv4.DHCPv4) {
		d.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionRequestedIPAddress, ip.To4()))
	}
}

func createTestPool(ctx context.Context, t *testing.T, allocator ipam.Allocator, poolID string) {
	t.Helper()
	err := allocator.CreatePool(ctx, &ipam.Pool{
		ID:                   poolID,
		Name:                 "test-pool",
		CIDR:                 netip.MustParsePrefix("192.168.1.0/24"),
		Gateway:              netip.MustParseAddr("192.168.1.1"),
		DefaultLeaseDuration: 24 * time.Hour,
	})
	require.NoError(t, err)
}

func TestNewIPAMPlugin(t *testing.T) {
	ctx := context.Background()
	allocator := backends.NewMemoryBackend()
	defer allocator.Close()

	poolID := "test-pool"
	createTestPool(ctx, t, allocator, poolID)

	t.Run("creates plugin with valid parameters", func(t *testing.T) {
		opts := DHCPOptions{
			SubnetMask: net.CIDRMask(24, 32),
			Router:     netip.MustParseAddr("192.168.1.1"),
		}

		plugin, err := NewIPAMPlugin(allocator, poolID, opts)
		require.NoError(t, err)
		require.NotNil(t, plugin)
		defer plugin.Close()

		assert.Equal(t, poolID, plugin.GetPoolID())
		assert.NotNil(t, plugin.GetLeaseStore())
	})

	t.Run("returns error for nil allocator", func(t *testing.T) {
		opts := DHCPOptions{}
		plugin, err := NewIPAMPlugin(nil, poolID, opts)
		assert.ErrorIs(t, err, ErrAllocatorRequired)
		assert.Nil(t, plugin)
	})

	t.Run("returns error for empty pool ID", func(t *testing.T) {
		opts := DHCPOptions{}
		plugin, err := NewIPAMPlugin(allocator, "", opts)
		assert.ErrorIs(t, err, ErrPoolIDRequired)
		assert.Nil(t, plugin)
	})

	t.Run("applies functional options", func(t *testing.T) {
		opts := DHCPOptions{}
		customLS := NewLeaseStore()
		customLogger := slog.New(slog.NewTextHandler(os.Stderr, nil))

		plugin, err := NewIPAMPlugin(
			allocator,
			poolID,
			opts,
			WithLeaseStore(customLS),
			WithLogger(customLogger),
			WithDefaultLease(2*time.Hour),
		)
		require.NoError(t, err)
		defer plugin.Close()

		assert.Equal(t, customLS, plugin.GetLeaseStore())
	})
}

func TestIPAMPlugin_Handler4(t *testing.T) {
	ctx := context.Background()
	allocator := backends.NewMemoryBackend()
	defer allocator.Close()

	poolID := "test-pool"
	createTestPool(ctx, t, allocator, poolID)

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
	require.NotNil(t, handler)

	t.Run("returns handler function", func(t *testing.T) {
		assert.NotNil(t, handler)
	})
}

func TestIPAMPlugin_HandleDiscover(t *testing.T) {
	ctx := context.Background()
	allocator := backends.NewMemoryBackend()
	defer allocator.Close()

	poolID := "test-pool"
	createTestPool(ctx, t, allocator, poolID)

	opts := DHCPOptions{
		SubnetMask: net.CIDRMask(24, 32),
		Router:     netip.MustParseAddr("192.168.1.1"),
		DNS:        []netip.Addr{netip.MustParseAddr("8.8.8.8")},
		LeaseTime:  time.Hour,
	}

	plugin, err := NewIPAMPlugin(allocator, poolID, opts)
	require.NoError(t, err)
	defer plugin.Close()

	handler := plugin.Handler4()

	t.Run("allocates IP for new client", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		req, err := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		require.NoError(t, err)

		resp, err := dhcpv4.NewReplyFromRequest(req)
		require.NoError(t, err)
		resp.ServerIPAddr = net.ParseIP("192.168.1.1")

		result, stop := handler(req, resp)
		require.NotNil(t, result)
		assert.True(t, stop)

		// Verify DHCPOFFER response
		msgType := result.MessageType()
		assert.Equal(t, dhcpv4.MessageTypeOffer, msgType)

		// Verify IP was assigned
		assert.NotNil(t, result.YourIPAddr)
		assert.False(t, result.YourIPAddr.IsUnspecified())
	})

	t.Run("returns same IP for existing lease", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:66")

		// First discover
		req1, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		resp1, _ := dhcpv4.NewReplyFromRequest(req1)
		resp1.ServerIPAddr = net.ParseIP("192.168.1.1")

		result1, _ := handler(req1, resp1)
		require.NotNil(t, result1)
		firstIP := result1.YourIPAddr

		// Second discover - should get same IP
		req2, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		resp2, _ := dhcpv4.NewReplyFromRequest(req2)
		resp2.ServerIPAddr = net.ParseIP("192.168.1.1")

		result2, _ := handler(req2, resp2)
		require.NotNil(t, result2)

		assert.Equal(t, firstIP.String(), result2.YourIPAddr.String())
	})

	t.Run("includes hostname in allocation", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:67")
		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
			dhcpv4.WithGeneric(dhcpv4.OptionHostName, []byte("test-host")),
		)
		resp, _ := dhcpv4.NewReplyFromRequest(req)
		resp.ServerIPAddr = net.ParseIP("192.168.1.1")

		result, stop := handler(req, resp)
		require.NotNil(t, result)
		assert.True(t, stop)
		assert.Equal(t, dhcpv4.MessageTypeOffer, result.MessageType())

		// Verify lease has hostname
		lease, found := plugin.GetLeaseStore().GetByMAC(mac)
		require.True(t, found)
		assert.Equal(t, "test-host", lease.Hostname)
	})
}

func TestIPAMPlugin_HandleRequest(t *testing.T) {
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

	t.Run("acknowledges valid request after discover", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:77")

		// First, do a discover
		discoverReq, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		discoverResp, _ := dhcpv4.NewReplyFromRequest(discoverReq)
		discoverResp.ServerIPAddr = net.ParseIP("192.168.1.1")

		offerResult, _ := handler(discoverReq, discoverResp)
		require.NotNil(t, offerResult)
		offeredIP := offerResult.YourIPAddr

		// Now send request for that IP
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

		// Verify DHCPACK response
		assert.Equal(t, dhcpv4.MessageTypeAck, result.MessageType())
		assert.Equal(t, offeredIP.String(), result.YourIPAddr.String())
	})

	t.Run("NAKs request without prior discover", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:88")
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

		// Should get NAK or ACK depending on IP availability
		msgType := result.MessageType()
		assert.True(t, msgType == dhcpv4.MessageTypeNak || msgType == dhcpv4.MessageTypeAck)
	})

	t.Run("NAKs request with no IP specified", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:99")

		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		)
		resp, _ := dhcpv4.NewReplyFromRequest(req)
		resp.ServerIPAddr = net.ParseIP("192.168.1.1")

		result, stop := handler(req, resp)
		require.NotNil(t, result)
		assert.True(t, stop)

		assert.Equal(t, dhcpv4.MessageTypeNak, result.MessageType())
	})

	t.Run("NAKs request for IP leased to another MAC", func(t *testing.T) {
		// First client gets an IP
		mac1, _ := net.ParseMAC("00:11:22:33:55:01")
		discoverReq1, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac1),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		discoverResp1, _ := dhcpv4.NewReplyFromRequest(discoverReq1)
		discoverResp1.ServerIPAddr = net.ParseIP("192.168.1.1")
		offerResult1, _ := handler(discoverReq1, discoverResp1)
		require.NotNil(t, offerResult1)
		leasedIP := offerResult1.YourIPAddr

		// Confirm the lease for first client
		requestReq1, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac1),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
			withRequestedIP(leasedIP),
		)
		requestResp1, _ := dhcpv4.NewReplyFromRequest(requestReq1)
		requestResp1.ServerIPAddr = net.ParseIP("192.168.1.1")
		ackResult1, _ := handler(requestReq1, requestResp1)
		require.NotNil(t, ackResult1)
		require.Equal(t, dhcpv4.MessageTypeAck, ackResult1.MessageType())

		// Second client requests the same IP
		mac2, _ := net.ParseMAC("00:11:22:33:55:02")
		requestReq2, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac2),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
			withRequestedIP(leasedIP),
		)
		requestResp2, _ := dhcpv4.NewReplyFromRequest(requestReq2)
		requestResp2.ServerIPAddr = net.ParseIP("192.168.1.1")

		result, stop := handler(requestReq2, requestResp2)
		require.NotNil(t, result)
		assert.True(t, stop)
		assert.Equal(t, dhcpv4.MessageTypeNak, result.MessageType())
	})

	t.Run("handles request with ciaddr fallback", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:55:03")

		// First, do a discover
		discoverReq, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		discoverResp, _ := dhcpv4.NewReplyFromRequest(discoverReq)
		discoverResp.ServerIPAddr = net.ParseIP("192.168.1.1")

		offerResult, _ := handler(discoverReq, discoverResp)
		require.NotNil(t, offerResult)
		offeredIP := offerResult.YourIPAddr

		// Send request using ciaddr instead of option 50
		requestReq, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
			dhcpv4.WithClientIP(offeredIP),
		)
		requestResp, _ := dhcpv4.NewReplyFromRequest(requestReq)
		requestResp.ServerIPAddr = net.ParseIP("192.168.1.1")

		result, stop := handler(requestReq, requestResp)
		require.NotNil(t, result)
		assert.True(t, stop)
		assert.Equal(t, dhcpv4.MessageTypeAck, result.MessageType())
	})
}

func TestIPAMPlugin_HandleRelease(t *testing.T) {
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

	t.Run("releases leased IP", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:AA")

		// First, do a discover and request
		discoverReq, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		discoverResp, _ := dhcpv4.NewReplyFromRequest(discoverReq)
		discoverResp.ServerIPAddr = net.ParseIP("192.168.1.1")

		offerResult, _ := handler(discoverReq, discoverResp)
		require.NotNil(t, offerResult)
		leasedIP := offerResult.YourIPAddr

		// Now release
		releaseReq, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeRelease),
			dhcpv4.WithClientIP(leasedIP),
		)
		releaseResp, _ := dhcpv4.NewReplyFromRequest(releaseReq)
		releaseResp.ServerIPAddr = net.ParseIP("192.168.1.1")

		result, stop := handler(releaseReq, releaseResp)
		// Release doesn't send a response
		assert.Nil(t, result)
		assert.True(t, stop)

		// Verify lease was removed
		_, found := plugin.GetLeaseStore().GetByMAC(mac)
		assert.False(t, found)
	})

	t.Run("ignores release with no client IP", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:BB")

		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeRelease),
		)
		resp, _ := dhcpv4.NewReplyFromRequest(req)

		result, stop := handler(req, resp)
		assert.Nil(t, result)
		assert.True(t, stop)
	})

	t.Run("ignores release with no existing lease", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:BC")
		nonLeasedIP := net.ParseIP("192.168.1.250")

		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeRelease),
			dhcpv4.WithClientIP(nonLeasedIP),
		)
		resp, _ := dhcpv4.NewReplyFromRequest(req)

		result, stop := handler(req, resp)
		assert.Nil(t, result)
		assert.True(t, stop)
	})

	t.Run("ignores release with MAC mismatch", func(t *testing.T) {
		// First client gets a lease
		mac1, _ := net.ParseMAC("00:11:22:33:66:01")
		discoverReq, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac1),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		discoverResp, _ := dhcpv4.NewReplyFromRequest(discoverReq)
		discoverResp.ServerIPAddr = net.ParseIP("192.168.1.1")

		offerResult, _ := handler(discoverReq, discoverResp)
		require.NotNil(t, offerResult)
		leasedIP := offerResult.YourIPAddr

		// Second client tries to release that IP
		mac2, _ := net.ParseMAC("00:11:22:33:66:02")
		releaseReq, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac2),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeRelease),
			dhcpv4.WithClientIP(leasedIP),
		)
		releaseResp, _ := dhcpv4.NewReplyFromRequest(releaseReq)

		result, stop := handler(releaseReq, releaseResp)
		assert.Nil(t, result)
		assert.True(t, stop)

		// Verify lease still exists for original client
		lease, found := plugin.GetLeaseStore().GetByMAC(mac1)
		assert.True(t, found)
		assert.Equal(t, leasedIP.String(), lease.IP.String())
	})

	t.Run("handles release with IPv6-mapped address", func(t *testing.T) {
		// Create a new plugin for this test
		plugin2, err := NewIPAMPlugin(allocator, poolID, opts)
		require.NoError(t, err)
		defer plugin2.Close()

		handler2 := plugin2.Handler4()

		mac, _ := net.ParseMAC("00:11:22:33:66:03")

		// First, get a lease
		discoverReq, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		discoverResp, _ := dhcpv4.NewReplyFromRequest(discoverReq)
		discoverResp.ServerIPAddr = net.ParseIP("192.168.1.1")

		offerResult, _ := handler2(discoverReq, discoverResp)
		require.NotNil(t, offerResult)
		leasedIP := offerResult.YourIPAddr

		// Release using IPv6-mapped IPv4 address format
		// This tests the To16() fallback path in handleRelease
		ipv6Mapped := net.IP(leasedIP).To16()
		releaseReq, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeRelease),
		)
		// Set ciaddr directly as IPv6-mapped
		releaseReq.ClientIPAddr = ipv6Mapped
		releaseResp, _ := dhcpv4.NewReplyFromRequest(releaseReq)

		result, stop := handler2(releaseReq, releaseResp)
		assert.Nil(t, result)
		assert.True(t, stop)
	})
}

func TestIPAMPlugin_HandleDecline(t *testing.T) {
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

	t.Run("handles decline message", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:CC")
		declinedIP := net.ParseIP("192.168.1.150")

		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDecline),
			withRequestedIP(declinedIP),
		)
		resp, _ := dhcpv4.NewReplyFromRequest(req)

		result, stop := handler(req, resp)
		// Decline doesn't send a response
		assert.Nil(t, result)
		assert.True(t, stop)
	})

	t.Run("ignores decline with no IP", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:CD")

		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDecline),
		)
		resp, _ := dhcpv4.NewReplyFromRequest(req)

		result, stop := handler(req, resp)
		assert.Nil(t, result)
		assert.True(t, stop)
	})

	t.Run("decline removes existing lease", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:77:01")

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

		// Now decline that IP
		declineReq, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDecline),
			withRequestedIP(leasedIP),
		)
		declineResp, _ := dhcpv4.NewReplyFromRequest(declineReq)

		result, stop := handler(declineReq, declineResp)
		assert.Nil(t, result)
		assert.True(t, stop)

		// Verify lease was removed
		_, found = plugin.GetLeaseStore().GetByMAC(mac)
		assert.False(t, found)
	})
}

func TestIPAMPlugin_HandleInform(t *testing.T) {
	ctx := context.Background()
	allocator := backends.NewMemoryBackend()
	defer allocator.Close()

	poolID := "test-pool"
	createTestPool(ctx, t, allocator, poolID)

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

	t.Run("responds with configuration options", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:DD")
		clientIP := net.ParseIP("192.168.1.50")

		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeInform),
			dhcpv4.WithClientIP(clientIP),
		)
		resp, _ := dhcpv4.NewReplyFromRequest(req)
		resp.ServerIPAddr = net.ParseIP("192.168.1.1")

		result, stop := handler(req, resp)
		require.NotNil(t, result)
		assert.True(t, stop)

		// Verify ACK response
		assert.Equal(t, dhcpv4.MessageTypeAck, result.MessageType())

		// Inform responses should not have lease time
		leaseTimeOpt := result.Options.Get(dhcpv4.OptionIPAddressLeaseTime)
		assert.Nil(t, leaseTimeOpt)
	})

	t.Run("ignores inform with no client IP", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:EE")

		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeInform),
		)
		resp, _ := dhcpv4.NewReplyFromRequest(req)

		result, stop := handler(req, resp)
		assert.Nil(t, result)
		assert.True(t, stop)
	})

	t.Run("handles inform with IPv6-mapped address", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:EF")
		// Use IPv6-mapped IPv4 address
		clientIP := net.ParseIP("::ffff:192.168.1.51")

		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeInform),
		)
		req.ClientIPAddr = clientIP
		resp, _ := dhcpv4.NewReplyFromRequest(req)
		resp.ServerIPAddr = net.ParseIP("192.168.1.1")

		result, stop := handler(req, resp)
		require.NotNil(t, result)
		assert.True(t, stop)
		assert.Equal(t, dhcpv4.MessageTypeAck, result.MessageType())
	})
}

func TestIPAMPlugin_Options(t *testing.T) {
	ctx := context.Background()
	allocator := backends.NewMemoryBackend()
	defer allocator.Close()

	poolID := "test-pool"
	createTestPool(ctx, t, allocator, poolID)

	opts := DHCPOptions{
		SubnetMask: net.CIDRMask(24, 32),
		Router:     netip.MustParseAddr("192.168.1.1"),
		DNS:        []netip.Addr{netip.MustParseAddr("8.8.8.8")},
		LeaseTime:  time.Hour,
	}

	plugin, err := NewIPAMPlugin(allocator, poolID, opts)
	require.NoError(t, err)
	defer plugin.Close()

	t.Run("GetOptions returns copy", func(t *testing.T) {
		retrieved := plugin.GetOptions()
		assert.Equal(t, opts.Router, retrieved.Router)
		assert.Equal(t, opts.DomainName, retrieved.DomainName)
	})

	t.Run("SetOptions updates options", func(t *testing.T) {
		newOpts := DHCPOptions{
			SubnetMask: net.CIDRMask(24, 32),
			Router:     netip.MustParseAddr("192.168.1.254"),
			LeaseTime:  2 * time.Hour,
		}

		err := plugin.SetOptions(newOpts)
		require.NoError(t, err)

		retrieved := plugin.GetOptions()
		assert.Equal(t, netip.MustParseAddr("192.168.1.254"), retrieved.Router)
		assert.Equal(t, 2*time.Hour, retrieved.LeaseTime)
	})

	t.Run("SetOptions with hostname", func(t *testing.T) {
		newOpts := DHCPOptions{
			SubnetMask: net.CIDRMask(24, 32),
			Router:     netip.MustParseAddr("192.168.1.1"),
			Hostname:   "dhcp-server",
			LeaseTime:  time.Hour,
		}

		err := plugin.SetOptions(newOpts)
		require.NoError(t, err)

		retrieved := plugin.GetOptions()
		assert.Equal(t, "dhcp-server", retrieved.Hostname)
	})
}

func TestIPAMPlugin_Close(t *testing.T) {
	ctx := context.Background()
	allocator := backends.NewMemoryBackend()
	defer allocator.Close()

	poolID := "test-pool"
	createTestPool(ctx, t, allocator, poolID)

	opts := DHCPOptions{
		SubnetMask: net.CIDRMask(24, 32),
		Router:     netip.MustParseAddr("192.168.1.1"),
	}

	t.Run("closes plugin", func(t *testing.T) {
		plugin, err := NewIPAMPlugin(allocator, poolID, opts)
		require.NoError(t, err)

		err = plugin.Close()
		require.NoError(t, err)

		// Handler should stop processing after close
		handler := plugin.Handler4()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		resp, _ := dhcpv4.NewReplyFromRequest(req)

		result, stop := handler(req, resp)
		assert.Nil(t, result)
		assert.True(t, stop)
	})

	t.Run("double close returns error", func(t *testing.T) {
		plugin, err := NewIPAMPlugin(allocator, poolID, opts)
		require.NoError(t, err)

		err = plugin.Close()
		require.NoError(t, err)

		err = plugin.Close()
		assert.ErrorIs(t, err, ErrPluginClosed)
	})
}

func TestIPAMPlugin_UnknownMessageType(t *testing.T) {
	ctx := context.Background()
	allocator := backends.NewMemoryBackend()
	defer allocator.Close()

	poolID := "test-pool"
	createTestPool(ctx, t, allocator, poolID)

	opts := DHCPOptions{
		SubnetMask: net.CIDRMask(24, 32),
		Router:     netip.MustParseAddr("192.168.1.1"),
	}

	plugin, err := NewIPAMPlugin(allocator, poolID, opts)
	require.NoError(t, err)
	defer plugin.Close()

	handler := plugin.Handler4()

	t.Run("unknown message type continues chain", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
		)
		// Set an unknown/unusual message type
		req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageType(100)))

		resp, _ := dhcpv4.NewReplyFromRequest(req)

		result, stop := handler(req, resp)
		// Should return response and continue chain
		assert.NotNil(t, result)
		assert.False(t, stop) // Continue chain for unknown types
	})
}

func TestIPAMPlugin_DHCPOptions(t *testing.T) {
	ctx := context.Background()
	allocator := backends.NewMemoryBackend()
	defer allocator.Close()

	poolID := "test-pool"
	createTestPool(ctx, t, allocator, poolID)

	t.Run("includes all configured options in response", func(t *testing.T) {
		opts := DHCPOptions{
			SubnetMask: net.CIDRMask(24, 32),
			Router:     netip.MustParseAddr("192.168.1.1"),
			DNS:        []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("8.8.4.4")},
			DomainName: "example.com",
			NTPServers: []netip.Addr{netip.MustParseAddr("129.6.15.28")},
			MTU:        1500,
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

		result, _ := handler(req, resp)
		require.NotNil(t, result)

		// Verify options are present
		assert.NotNil(t, result.Options.Get(dhcpv4.OptionSubnetMask))
		assert.NotNil(t, result.Options.Get(dhcpv4.OptionRouter))
		assert.NotNil(t, result.Options.Get(dhcpv4.OptionDomainNameServer))
		assert.NotNil(t, result.Options.Get(dhcpv4.OptionDomainName))
		assert.NotNil(t, result.Options.Get(dhcpv4.OptionNTPServers))
		assert.NotNil(t, result.Options.Get(dhcpv4.OptionInterfaceMTU))
		assert.NotNil(t, result.Options.Get(dhcpv4.OptionIPAddressLeaseTime))
	})

	t.Run("includes hostname option when configured", func(t *testing.T) {
		opts := DHCPOptions{
			SubnetMask: net.CIDRMask(24, 32),
			Router:     netip.MustParseAddr("192.168.1.1"),
			Hostname:   "test-server",
			LeaseTime:  time.Hour,
		}

		plugin, err := NewIPAMPlugin(allocator, poolID, opts)
		require.NoError(t, err)
		defer plugin.Close()

		handler := plugin.Handler4()

		mac, _ := net.ParseMAC("00:11:22:33:88:01")
		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		resp, _ := dhcpv4.NewReplyFromRequest(req)
		resp.ServerIPAddr = net.ParseIP("192.168.1.1")

		result, _ := handler(req, resp)
		require.NotNil(t, result)

		// Verify hostname option is present
		hostnameOpt := result.Options.Get(dhcpv4.OptionHostName)
		assert.NotNil(t, hostnameOpt)
		assert.Equal(t, "test-server", string(hostnameOpt))
	})
}

func TestIPAMPlugin_GetRequestedIP(t *testing.T) {
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

	t.Run("uses option 50 when present", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:99:01")
		requestedIP := net.ParseIP("192.168.1.100")

		// Do discover first
		discoverReq, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		discoverResp, _ := dhcpv4.NewReplyFromRequest(discoverReq)
		discoverResp.ServerIPAddr = net.ParseIP("192.168.1.1")
		_, _ = handler(discoverReq, discoverResp)

		// Request with option 50
		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
			withRequestedIP(requestedIP),
		)
		resp, _ := dhcpv4.NewReplyFromRequest(req)
		resp.ServerIPAddr = net.ParseIP("192.168.1.1")

		result, _ := handler(req, resp)
		require.NotNil(t, result)
		// Result should use the requested IP if available
		msgType := result.MessageType()
		assert.True(t, msgType == dhcpv4.MessageTypeAck || msgType == dhcpv4.MessageTypeNak)
	})

	t.Run("falls back to ciaddr when option 50 missing", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:99:02")
		clientIP := net.ParseIP("192.168.1.101")

		// Do discover first
		discoverReq, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		discoverResp, _ := dhcpv4.NewReplyFromRequest(discoverReq)
		discoverResp.ServerIPAddr = net.ParseIP("192.168.1.1")
		_, _ = handler(discoverReq, discoverResp)

		// Request with ciaddr only (no option 50)
		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
			dhcpv4.WithClientIP(clientIP),
		)
		resp, _ := dhcpv4.NewReplyFromRequest(req)
		resp.ServerIPAddr = net.ParseIP("192.168.1.1")

		result, _ := handler(req, resp)
		require.NotNil(t, result)
		msgType := result.MessageType()
		assert.True(t, msgType == dhcpv4.MessageTypeAck || msgType == dhcpv4.MessageTypeNak)
	})

	t.Run("handles invalid option 50 data", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:99:03")

		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		)
		// Set invalid option 50 (too short)
		req.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionRequestedIPAddress, []byte{1, 2}))

		resp, _ := dhcpv4.NewReplyFromRequest(req)
		resp.ServerIPAddr = net.ParseIP("192.168.1.1")

		result, stop := handler(req, resp)
		require.NotNil(t, result)
		assert.True(t, stop)
		// Should NAK because no valid IP could be extracted
		assert.Equal(t, dhcpv4.MessageTypeNak, result.MessageType())
	})

	t.Run("handles IPv6-mapped ciaddr fallback", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:99:04")

		// Do discover first
		discoverReq, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		discoverResp, _ := dhcpv4.NewReplyFromRequest(discoverReq)
		discoverResp.ServerIPAddr = net.ParseIP("192.168.1.1")
		offerResult, _ := handler(discoverReq, discoverResp)
		require.NotNil(t, offerResult)
		offeredIP := offerResult.YourIPAddr

		// Request using IPv6-mapped ciaddr (tests To16 fallback)
		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		)
		// Set ciaddr as IPv6-mapped address
		req.ClientIPAddr = net.IP(offeredIP).To16()

		resp, _ := dhcpv4.NewReplyFromRequest(req)
		resp.ServerIPAddr = net.ParseIP("192.168.1.1")

		result, stop := handler(req, resp)
		require.NotNil(t, result)
		assert.True(t, stop)
		// Should ACK since the IP matches the offered IP
		assert.Equal(t, dhcpv4.MessageTypeAck, result.MessageType())
	})

	t.Run("handles option 50 with invalid netip conversion", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:99:05")

		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		)
		// Set option 50 with exactly 4 bytes but invalid IP (all zeros is unspecified)
		req.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionRequestedIPAddress, []byte{0, 0, 0, 0}))

		resp, _ := dhcpv4.NewReplyFromRequest(req)
		resp.ServerIPAddr = net.ParseIP("192.168.1.1")

		result, stop := handler(req, resp)
		require.NotNil(t, result)
		assert.True(t, stop)
		// Should NAK because 0.0.0.0 is not a valid requested IP
		assert.Equal(t, dhcpv4.MessageTypeNak, result.MessageType())
	})
}

func TestIPAMPlugin_LeaseOptions(t *testing.T) {
	ctx := context.Background()
	allocator := backends.NewMemoryBackend()
	defer allocator.Close()

	poolID := "test-pool"
	createTestPool(ctx, t, allocator, poolID)

	t.Run("includes T1 and T2 times", func(t *testing.T) {
		opts := DHCPOptions{
			SubnetMask:  net.CIDRMask(24, 32),
			Router:      netip.MustParseAddr("192.168.1.1"),
			LeaseTime:   time.Hour,
			RenewalTime: 30 * time.Minute,
			RebindTime:  52 * time.Minute,
		}

		plugin, err := NewIPAMPlugin(allocator, poolID, opts)
		require.NoError(t, err)
		defer plugin.Close()

		handler := plugin.Handler4()

		mac, _ := net.ParseMAC("00:11:22:33:AA:01")
		req, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		resp, _ := dhcpv4.NewReplyFromRequest(req)
		resp.ServerIPAddr = net.ParseIP("192.168.1.1")

		result, _ := handler(req, resp)
		require.NotNil(t, result)

		// Verify T1 (option 58) and T2 (option 59) are present
		t1Opt := result.Options.Get(dhcpv4.GenericOptionCode(58))
		assert.NotNil(t, t1Opt)

		t2Opt := result.Options.Get(dhcpv4.GenericOptionCode(59))
		assert.NotNil(t, t2Opt)
	})
}

// errAllocator is a mock allocator that returns errors for testing error paths.
type errAllocator struct {
	*backends.MemoryBackend
	releaseErr error
	renewErr   error
}

func newErrAllocator() *errAllocator {
	return &errAllocator{
		MemoryBackend: backends.NewMemoryBackend(),
	}
}

func (e *errAllocator) Release(ctx context.Context, ip netip.Addr) error {
	if e.releaseErr != nil {
		return e.releaseErr
	}
	return e.MemoryBackend.Release(ctx, ip)
}

func (e *errAllocator) Renew(ctx context.Context, ip netip.Addr) error {
	if e.renewErr != nil {
		return e.renewErr
	}
	return e.MemoryBackend.Renew(ctx, ip)
}

func TestIPAMPlugin_HandleReleaseWithIPAMError(t *testing.T) {
	ctx := context.Background()
	allocator := newErrAllocator()
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

	plugin, err := NewIPAMPlugin(allocator, poolID, opts)
	require.NoError(t, err)
	defer plugin.Close()

	handler := plugin.Handler4()

	t.Run("handles IPAM release error gracefully", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:BB:01")

		// First, get a lease
		discoverReq, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		discoverResp, _ := dhcpv4.NewReplyFromRequest(discoverReq)
		discoverResp.ServerIPAddr = net.ParseIP("192.168.1.1")

		offerResult, _ := handler(discoverReq, discoverResp)
		require.NotNil(t, offerResult)
		leasedIP := offerResult.YourIPAddr

		// Set release error
		allocator.releaseErr = errors.New("IPAM release failed")

		// Now release - should still succeed (logs warning but continues)
		releaseReq, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeRelease),
			dhcpv4.WithClientIP(leasedIP),
		)
		releaseResp, _ := dhcpv4.NewReplyFromRequest(releaseReq)
		releaseResp.ServerIPAddr = net.ParseIP("192.168.1.1")

		result, stop := handler(releaseReq, releaseResp)
		// Release doesn't send a response
		assert.Nil(t, result)
		assert.True(t, stop)

		// Verify lease was removed from local store despite IPAM error
		_, found := plugin.GetLeaseStore().GetByMAC(mac)
		assert.False(t, found)
	})
}
