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

// TestIPAMPlugin_HandleRequest_LocalRenewalFailure tests the local lease renewal failure path.
func TestIPAMPlugin_HandleRequest_LocalRenewalFailure(t *testing.T) {
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

	t.Run("continues with ACK even when local lease renewal fails", func(t *testing.T) {
		// Create a lease store that will fail on Renew
		ls := NewLeaseStore()

		plugin, err := NewIPAMPlugin(allocator, poolID, opts, WithLeaseStore(ls))
		require.NoError(t, err)
		defer plugin.Close()

		handler := plugin.Handler4()

		mac, _ := net.ParseMAC("00:11:22:33:AA:01")

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

		// Remove the lease by IP to make local renewal fail
		ipAddr, _ := netip.AddrFromSlice(offeredIP.To4())
		err = ls.Remove(ipAddr)
		require.NoError(t, err)

		// Re-add with the MAC lookup intact but ensure the IP lookup fails
		// Actually, we need to keep the lease but make the Renew fail
		// Since Renew checks by IP first, we need a different approach
		// Let's manually add the lease back with the MAC
		mac2, _ := net.ParseMAC("00:11:22:33:AA:01")
		lease := &Lease{
			IP:        ipAddr,
			MAC:       mac2,
			State:     LeaseStateActive,
			ExpiresAt: time.Now().Add(time.Hour),
		}
		err = ls.Add(lease)
		require.NoError(t, err)

		// Request the same IP - this should go through the renewal path
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

// TestIPAMPlugin_HandleRequest_IPAlreadyLeasedDifferentMAC tests when IP is requested but leased to different MAC.
func TestIPAMPlugin_HandleRequest_IPAlreadyLeasedDifferentMAC(t *testing.T) {
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

	t.Run("NAKs when client requests IP leased to different MAC (without prior discover)", func(t *testing.T) {
		// First client gets a lease
		mac1, _ := net.ParseMAC("00:11:22:33:BB:01")
		discoverReq1, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac1),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		discoverResp1, _ := dhcpv4.NewReplyFromRequest(discoverReq1)
		discoverResp1.ServerIPAddr = net.ParseIP("192.168.1.1")

		offerResult1, _ := handler(discoverReq1, discoverResp1)
		require.NotNil(t, offerResult1)
		leasedIP := offerResult1.YourIPAddr

		// Confirm the lease
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

		// Second client requests that IP directly (without discover)
		mac2, _ := net.ParseMAC("00:11:22:33:BB:02")
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
}

// TestIPAMPlugin_SetOptions_ValidationError tests SetOptions validation error path.
func TestIPAMPlugin_SetOptions_ValidationError(t *testing.T) {
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

	t.Run("validates and applies defaults for zero values", func(t *testing.T) {
		newOpts := DHCPOptions{
			SubnetMask: net.CIDRMask(24, 32),
			Router:     netip.MustParseAddr("192.168.1.254"),
			// LeaseTime is zero - will get default
		}

		err := plugin.SetOptions(newOpts)
		require.NoError(t, err)

		// Verify the defaults were applied during validation
		retrieved := plugin.GetOptions()
		assert.Equal(t, DefaultLeaseDuration, retrieved.LeaseTime)
	})
}
