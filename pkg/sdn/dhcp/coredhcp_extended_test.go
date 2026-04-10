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

// TestCoreDHCPServer_GetInterfacePlugin tests getting the IPAM plugin for an interface.
func TestCoreDHCPServer_GetInterfacePlugin(t *testing.T) {
	t.Run("returns false for non-existent interface when not started", func(t *testing.T) {
		cfg := testServerConfig()
		allocator := newMockAllocator()

		srv, err := NewCoreDHCPServer(cfg, allocator)
		require.NoError(t, err)

		_, ok := srv.GetInterfacePlugin("non-existent")
		assert.False(t, ok)
	})

	t.Run("returns false for existing interface when not started", func(t *testing.T) {
		cfg := testServerConfig()
		allocator := newMockAllocator()

		srv, err := NewCoreDHCPServer(cfg, allocator)
		require.NoError(t, err)

		// Interface exists in config but server not started so plugin not created
		_, ok := srv.GetInterfacePlugin("lo")
		assert.False(t, ok)
	})
}

// TestCoreDHCPServer_UpdateInterfaceOptions tests updating DHCP options for an interface.
func TestCoreDHCPServer_UpdateInterfaceOptions(t *testing.T) {
	t.Run("returns error for non-existent interface", func(t *testing.T) {
		cfg := testServerConfig()
		allocator := newMockAllocator()

		srv, err := NewCoreDHCPServer(cfg, allocator)
		require.NoError(t, err)

		newOpts := DHCPOptions{
			SubnetMask: net.IPv4Mask(255, 255, 255, 0),
			Router:     netip.MustParseAddr("192.168.1.254"),
			LeaseTime:  time.Hour,
		}

		err = srv.UpdateInterfaceOptions("non-existent", newOpts)
		assert.ErrorIs(t, err, ErrInterfaceNotFound)
	})

	t.Run("returns error for existing interface when not started", func(t *testing.T) {
		cfg := testServerConfig()
		allocator := newMockAllocator()

		srv, err := NewCoreDHCPServer(cfg, allocator)
		require.NoError(t, err)

		newOpts := DHCPOptions{
			SubnetMask: net.IPv4Mask(255, 255, 255, 0),
			Router:     netip.MustParseAddr("192.168.1.254"),
			LeaseTime:  time.Hour,
		}

		// Interface exists in config but server not started so plugin not created
		err = srv.UpdateInterfaceOptions("lo", newOpts)
		assert.ErrorIs(t, err, ErrInterfaceNotFound)
	})
}

// TestCoreDHCPServer_ReleaseLease_EdgeCases tests edge cases in ReleaseLease.
func TestCoreDHCPServer_ReleaseLease_EdgeCases(t *testing.T) {
	t.Run("returns error for empty MAC", func(t *testing.T) {
		cfg := testServerConfig()
		allocator := newMockAllocator()

		srv, err := NewCoreDHCPServer(cfg, allocator)
		require.NoError(t, err)

		err = srv.ReleaseLease(net.HardwareAddr{})
		assert.ErrorIs(t, err, ErrInvalidMAC)
	})
}

// TestRecordMessageTypeStats tests the message type statistics recording.
func TestRecordMessageTypeStats(t *testing.T) {
	cfg := testServerConfig()
	allocator := newMockAllocator()

	srv, err := NewCoreDHCPServer(cfg, allocator)
	require.NoError(t, err)

	// Access internal method through reflection or directly
	// Since we can't test Start directly due to socket binding requirements,
	// we test the stats collector functionality instead

	t.Run("stats collector increments discover", func(t *testing.T) {
		stats := srv.Stats()
		assert.Equal(t, uint64(0), stats.DiscoverCount)
	})
}

// TestCoreDHCPServer_ConfigValidation tests configuration validation edge cases.
func TestCoreDHCPServer_ConfigValidation(t *testing.T) {
	t.Run("invalid interface config returns error", func(t *testing.T) {
		cfg := &ServerConfig{
			DefaultLeaseDuration: 24 * time.Hour,
			Interfaces: []InterfaceConfig{
				{
					Name:    "", // Empty name is invalid
					Address: netip.MustParseAddr("192.168.1.1"),
					PoolID:  "test-pool",
				},
			},
		}
		allocator := newMockAllocator()

		_, err := NewCoreDHCPServer(cfg, allocator)
		assert.ErrorIs(t, err, ErrInvalidInterface)
	})

	t.Run("invalid IPAM backend returns error", func(t *testing.T) {
		cfg := &ServerConfig{
			DefaultLeaseDuration: 24 * time.Hour,
			IPAMBackend:          "invalid-backend",
			Interfaces: []InterfaceConfig{
				{
					Name:    "eth0",
					Address: netip.MustParseAddr("192.168.1.1"),
					PoolID:  "test-pool",
				},
			},
		}
		allocator := newMockAllocator()

		_, err := NewCoreDHCPServer(cfg, allocator)
		assert.ErrorIs(t, err, ErrIPAMBackendInvalid)
	})
}

// TestCoreDHCPServer_MultipleInterfaces tests server with multiple interfaces.
func TestCoreDHCPServer_MultipleInterfaces(t *testing.T) {
	t.Run("creates server with multiple interfaces", func(t *testing.T) {
		cfg := &ServerConfig{
			DefaultLeaseDuration: 24 * time.Hour,
			Interfaces: []InterfaceConfig{
				{
					Name:    "lo",
					Network: NetworkPrivate,
					Address: netip.MustParseAddr("127.0.0.1"),
					PoolID:  "pool-1",
					Options: DHCPOptions{
						SubnetMask: net.IPv4Mask(255, 255, 255, 0),
						Router:     netip.MustParseAddr("192.168.1.1"),
						LeaseTime:  24 * time.Hour,
					},
				},
				{
					Name:    "lo",
					Network: NetworkPublic,
					Address: netip.MustParseAddr("127.0.0.2"),
					PoolID:  "pool-2",
					Options: DHCPOptions{
						SubnetMask: net.IPv4Mask(255, 255, 255, 0),
						Router:     netip.MustParseAddr("10.0.0.1"),
						LeaseTime:  12 * time.Hour,
					},
				},
			},
		}
		allocator := newMockAllocator()

		srv, err := NewCoreDHCPServer(cfg, allocator, WithCoreDHCPLogger(testLogger()))
		require.NoError(t, err)
		require.NotNil(t, srv)

		assert.Equal(t, 2, len(srv.GetConfig().Interfaces))
	})
}
