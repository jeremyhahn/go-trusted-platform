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

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam/backends"
)

// TestIPAMPlugin_HandleDiscover_RenewalFallback tests renewal failure fallback.
func TestIPAMPlugin_HandleDiscover_RenewalFallback(t *testing.T) {
	t.Run("allocates new IP when renewal fails for existing lease", func(t *testing.T) {
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

		mac, _ := net.ParseMAC("00:11:22:33:AA:01")

		// First discover
		discoverReq1, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		discoverResp1, _ := dhcpv4.NewReplyFromRequest(discoverReq1)
		discoverResp1.ServerIPAddr = net.ParseIP("192.168.1.1")

		result1, _ := handler(discoverReq1, discoverResp1)
		require.NotNil(t, result1)
		firstIP := result1.YourIPAddr

		// Second discover - renewal will fail, so new allocation
		discoverReq2, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		discoverResp2, _ := dhcpv4.NewReplyFromRequest(discoverReq2)
		discoverResp2.ServerIPAddr = net.ParseIP("192.168.1.1")

		result2, stop := handler(discoverReq2, discoverResp2)
		require.NotNil(t, result2)
		assert.True(t, stop)

		// Should get a new IP since renewal failed
		assert.NotEqual(t, firstIP.String(), result2.YourIPAddr.String())
	})
}

// TestIPAMPlugin_HandleDiscover_ExistingLeaseRenewalSuccess tests successful renewal.
func TestIPAMPlugin_HandleDiscover_ExistingLeaseRenewalSuccess(t *testing.T) {
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

	t.Run("returns same IP on subsequent discovers with successful renewal", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:BB:01")

		// First discover
		discoverReq1, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		discoverResp1, _ := dhcpv4.NewReplyFromRequest(discoverReq1)
		discoverResp1.ServerIPAddr = net.ParseIP("192.168.1.1")

		result1, _ := handler(discoverReq1, discoverResp1)
		require.NotNil(t, result1)
		firstIP := result1.YourIPAddr

		// Second discover - should get same IP
		discoverReq2, _ := dhcpv4.New(
			dhcpv4.WithHwAddr(mac),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		discoverResp2, _ := dhcpv4.NewReplyFromRequest(discoverReq2)
		discoverResp2.ServerIPAddr = net.ParseIP("192.168.1.1")

		result2, stop := handler(discoverReq2, discoverResp2)
		require.NotNil(t, result2)
		assert.True(t, stop)
		assert.Equal(t, firstIP.String(), result2.YourIPAddr.String())
	})
}
