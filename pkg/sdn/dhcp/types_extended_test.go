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

// TestLease_NilMAC tests Lease.Clone with nil MAC.
func TestLease_NilMAC(t *testing.T) {
	t.Run("clone handles nil MAC", func(t *testing.T) {
		l := &Lease{
			IP:        netip.MustParseAddr("192.168.1.100"),
			State:     LeaseStateActive,
			ExpiresAt: time.Now().Add(time.Hour),
		}

		clone := l.Clone()
		require.NotNil(t, clone)
		assert.Nil(t, clone.MAC)
	})
}

// TestLeaseRequest_NilMAC tests LeaseRequest.Clone with nil MAC.
func TestLeaseRequest_NilMAC(t *testing.T) {
	t.Run("clone handles nil MAC", func(t *testing.T) {
		r := &LeaseRequest{
			PoolID:   "pool-1",
			Hostname: "host1",
		}

		clone := r.Clone()
		require.NotNil(t, clone)
		assert.Nil(t, clone.MAC)
	})

	t.Run("clone handles nil client ID", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		r := &LeaseRequest{
			MAC:    mac,
			PoolID: "pool-1",
		}

		clone := r.Clone()
		require.NotNil(t, clone)
		assert.Nil(t, clone.ClientID)
	})
}

// TestDHCPOptions_NilSlices tests DHCPOptions.Clone with nil slices.
func TestDHCPOptions_NilSlices(t *testing.T) {
	t.Run("clone handles nil DNS slice", func(t *testing.T) {
		opts := &DHCPOptions{
			SubnetMask: net.CIDRMask(24, 32),
			Router:     netip.MustParseAddr("192.168.1.1"),
			LeaseTime:  time.Hour,
		}

		clone := opts.Clone()
		require.NotNil(t, clone)
		assert.Nil(t, clone.DNS)
	})

	t.Run("clone handles nil NTP servers slice", func(t *testing.T) {
		opts := &DHCPOptions{
			SubnetMask: net.CIDRMask(24, 32),
			Router:     netip.MustParseAddr("192.168.1.1"),
			DNS:        []netip.Addr{netip.MustParseAddr("8.8.8.8")},
			LeaseTime:  time.Hour,
		}

		clone := opts.Clone()
		require.NotNil(t, clone)
		assert.Nil(t, clone.NTPServers)
	})

	t.Run("clone handles nil subnet mask", func(t *testing.T) {
		opts := &DHCPOptions{
			Router:    netip.MustParseAddr("192.168.1.1"),
			LeaseTime: time.Hour,
		}

		clone := opts.Clone()
		require.NotNil(t, clone)
		assert.Nil(t, clone.SubnetMask)
	})

	t.Run("clone handles nil next server", func(t *testing.T) {
		opts := &DHCPOptions{
			SubnetMask: net.CIDRMask(24, 32),
			Router:     netip.MustParseAddr("192.168.1.1"),
			LeaseTime:  time.Hour,
		}

		clone := opts.Clone()
		require.NotNil(t, clone)
		assert.Nil(t, clone.NextServer)
	})
}

// TestServerConfig_NilMaps tests ServerConfig.Clone with nil maps.
func TestServerConfig_NilMaps(t *testing.T) {
	t.Run("clone handles populated config", func(t *testing.T) {
		cfg := &ServerConfig{
			DefaultLeaseDuration: 24 * time.Hour,
			IPAMBackend:          IPAMBackendMemory,
			Interfaces: []InterfaceConfig{
				{
					Name:    "eth0",
					Address: netip.MustParseAddr("192.168.1.1"),
					PoolID:  "pool-1",
				},
				{
					Name:    "eth1",
					Address: netip.MustParseAddr("10.0.0.1"),
					PoolID:  "pool-2",
				},
			},
			IPAMConfig: map[string]string{
				"key1": "value1",
			},
		}

		clone := cfg.Clone()
		require.NotNil(t, clone)
		assert.Equal(t, 2, len(clone.Interfaces))
		assert.Equal(t, "value1", clone.IPAMConfig["key1"])
	})
}

// TestPXEOptions_NilMap tests PXEOptions.Clone with nil map.
func TestPXEOptions_NilMap(t *testing.T) {
	t.Run("clone handles nil architecture filters", func(t *testing.T) {
		opts := &PXEOptions{
			NextServer:   net.ParseIP("192.168.1.10"),
			BootFileName: "/pxelinux.0",
		}

		clone := opts.Clone()
		require.NotNil(t, clone)
		assert.Nil(t, clone.ArchitectureFilters)
	})
}

// TestServerStats_Fields tests all ServerStats fields.
func TestServerStats_Fields(t *testing.T) {
	t.Run("clone preserves all fields", func(t *testing.T) {
		now := time.Now()
		s := &ServerStats{
			StartedAt:       now,
			PacketsReceived: 100,
			PacketsSent:     95,
			DiscoverCount:   30,
			OfferCount:      30,
			RequestCount:    28,
			AckCount:        25,
			NakCount:        3,
			ReleaseCount:    10,
			DeclineCount:    2,
			InformCount:     5,
			ErrorCount:      1,
			ActiveLeases:    20,
		}

		clone := s.Clone()
		require.NotNil(t, clone)
		assert.Equal(t, s.StartedAt, clone.StartedAt)
		assert.Equal(t, s.PacketsReceived, clone.PacketsReceived)
		assert.Equal(t, s.PacketsSent, clone.PacketsSent)
		assert.Equal(t, s.DiscoverCount, clone.DiscoverCount)
		assert.Equal(t, s.OfferCount, clone.OfferCount)
		assert.Equal(t, s.RequestCount, clone.RequestCount)
		assert.Equal(t, s.AckCount, clone.AckCount)
		assert.Equal(t, s.NakCount, clone.NakCount)
		assert.Equal(t, s.ReleaseCount, clone.ReleaseCount)
		assert.Equal(t, s.DeclineCount, clone.DeclineCount)
		assert.Equal(t, s.InformCount, clone.InformCount)
		assert.Equal(t, s.ErrorCount, clone.ErrorCount)
		assert.Equal(t, s.ActiveLeases, clone.ActiveLeases)
	})
}

// TestInterfaceConfig_FullOptions tests InterfaceConfig with full options set.
func TestInterfaceConfig_FullOptions(t *testing.T) {
	t.Run("clone handles full options", func(t *testing.T) {
		cfg := &InterfaceConfig{
			Name:    "eth0",
			Network: NetworkPublic,
			Address: netip.MustParseAddr("192.168.1.1"),
			PoolID:  "pool-1",
			Options: DHCPOptions{
				SubnetMask:   net.CIDRMask(24, 32),
				Router:       netip.MustParseAddr("192.168.1.1"),
				DNS:          []netip.Addr{netip.MustParseAddr("8.8.8.8")},
				DomainName:   "example.com",
				LeaseTime:    time.Hour,
				RenewalTime:  30 * time.Minute,
				RebindTime:   52 * time.Minute,
				NTPServers:   []netip.Addr{netip.MustParseAddr("129.6.15.28")},
				MTU:          1500,
				Hostname:     "server1",
				NextServer:   net.ParseIP("192.168.1.10"),
				BootFileName: "/pxelinux.0",
			},
		}

		clone := cfg.Clone()
		require.NotNil(t, clone)
		assert.Equal(t, cfg.Name, clone.Name)
		assert.Equal(t, cfg.Network, clone.Network)
		assert.Equal(t, cfg.Options.DomainName, clone.Options.DomainName)
		assert.Equal(t, cfg.Options.MTU, clone.Options.MTU)
		assert.Equal(t, cfg.Options.Hostname, clone.Options.Hostname)
	})
}
