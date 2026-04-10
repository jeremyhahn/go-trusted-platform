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

package bgp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Route Handling Tests ---

func TestEVPNManager_OnRouteReceived_Type2(t *testing.T) {
	t.Run("valid Type-2 route", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")

		route := &EVPNRouteData{
			Type: EVPNTypeMACIPAdvertisement,
			MACIP: &MACIPEntry{
				MAC:    mac,
				IP:     netip.MustParseAddr("192.168.1.100"),
				VNI:    100,
				VTEPIP: netip.MustParseAddr("10.0.0.2"),
			},
			NextHop: netip.MustParseAddr("10.0.0.2"),
		}

		err = manager.OnRouteReceived(ctx, route)
		assert.NoError(t, err)
	})

	t.Run("Type-2 with nil MACIP", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		route := &EVPNRouteData{
			Type:  EVPNTypeMACIPAdvertisement,
			MACIP: nil,
		}

		err = manager.OnRouteReceived(ctx, route)
		assert.Error(t, err)
	})
}

func TestEVPNManager_OnRouteReceived_Type3(t *testing.T) {
	t.Run("valid Type-3 route", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		route := &EVPNRouteData{
			Type: EVPNTypeInclusiveMulticast,
			IMET: &IMETEntry{
				VNI:    100,
				VTEPIP: netip.MustParseAddr("10.0.0.2"),
			},
			NextHop: netip.MustParseAddr("10.0.0.2"),
		}

		err = manager.OnRouteReceived(ctx, route)
		assert.NoError(t, err)
	})

	t.Run("Type-3 with nil IMET", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		route := &EVPNRouteData{
			Type: EVPNTypeInclusiveMulticast,
			IMET: nil,
		}

		err = manager.OnRouteReceived(ctx, route)
		assert.Error(t, err)
	})
}

func TestEVPNManager_OnRouteReceived_Type5(t *testing.T) {
	t.Run("valid Type-5 route", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		route := &EVPNRouteData{
			Type: EVPNTypeIPPrefix,
			PrefixData: &PrefixRoute{
				Prefix:    netip.MustParsePrefix("192.168.1.0/24"),
				VNI:       100,
				GatewayIP: netip.MustParseAddr("10.0.0.254"),
			},
			NextHop: netip.MustParseAddr("10.0.0.2"),
		}

		err = manager.OnRouteReceived(ctx, route)
		assert.NoError(t, err)
	})

	t.Run("Type-5 with nil PrefixData", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		route := &EVPNRouteData{
			Type:       EVPNTypeIPPrefix,
			PrefixData: nil,
		}

		err = manager.OnRouteReceived(ctx, route)
		assert.Error(t, err)
	})
}

func TestEVPNManager_OnRouteReceived_UnsupportedType(t *testing.T) {
	speaker := newMockSpeaker()
	config := testConfig(speaker)
	manager, err := NewEVPNManager(config)
	require.NoError(t, err)

	ctx := context.Background()
	route := &EVPNRouteData{
		Type: EVPNRouteType(99), // Unsupported type
	}

	err = manager.OnRouteReceived(ctx, route)
	assert.Error(t, err)
	assert.IsType(t, ErrUnsupportedRouteType{}, err)
}

func TestEVPNManager_OnRouteReceived_NilRoute(t *testing.T) {
	speaker := newMockSpeaker()
	config := testConfig(speaker)
	manager, err := NewEVPNManager(config)
	require.NoError(t, err)

	ctx := context.Background()
	err = manager.OnRouteReceived(ctx, nil)
	assert.Error(t, err)
}

// --- Route Withdrawn Tests ---

func TestEVPNManager_OnRouteWithdrawn_Type2(t *testing.T) {
	t.Run("valid Type-2 withdrawal", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")

		// First add a MAC
		entry := &MACIPEntry{
			MAC:    mac,
			IP:     netip.MustParseAddr("192.168.1.100"),
			VNI:    100,
			VTEPIP: netip.MustParseAddr("10.0.0.2"),
		}
		manager.remoteMACs.Store(entry.Key(), entry)

		route := &EVPNRouteData{
			Type: EVPNTypeMACIPAdvertisement,
			MACIP: &MACIPEntry{
				MAC:    mac,
				IP:     netip.MustParseAddr("192.168.1.100"),
				VNI:    100,
				VTEPIP: netip.MustParseAddr("10.0.0.2"),
			},
		}

		err = manager.OnRouteWithdrawn(ctx, route)
		assert.NoError(t, err)
	})

	t.Run("Type-2 withdrawal with nil MACIP", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		route := &EVPNRouteData{
			Type:  EVPNTypeMACIPAdvertisement,
			MACIP: nil,
		}

		err = manager.OnRouteWithdrawn(ctx, route)
		assert.Error(t, err)
	})
}

func TestEVPNManager_OnRouteWithdrawn_Type3(t *testing.T) {
	t.Run("valid Type-3 withdrawal", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()

		// First add IMET entry
		entry := &IMETEntry{
			VNI:    100,
			VTEPIP: netip.MustParseAddr("10.0.0.2"),
		}
		manager.imetEntries.Store(entry.Key(), entry)
		manager.addVNIVTEP(100, entry.VTEPIP)

		route := &EVPNRouteData{
			Type: EVPNTypeInclusiveMulticast,
			IMET: &IMETEntry{
				VNI:    100,
				VTEPIP: netip.MustParseAddr("10.0.0.2"),
			},
		}

		err = manager.OnRouteWithdrawn(ctx, route)
		assert.NoError(t, err)
	})

	t.Run("Type-3 withdrawal with nil IMET", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		route := &EVPNRouteData{
			Type: EVPNTypeInclusiveMulticast,
			IMET: nil,
		}

		err = manager.OnRouteWithdrawn(ctx, route)
		assert.Error(t, err)
	})
}

func TestEVPNManager_OnRouteWithdrawn_Type5(t *testing.T) {
	t.Run("valid Type-5 withdrawal", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()

		// First add prefix route
		prefixRoute := &PrefixRoute{
			Prefix:    netip.MustParsePrefix("192.168.1.0/24"),
			VNI:       100,
			GatewayIP: netip.MustParseAddr("10.0.0.254"),
		}
		manager.prefixRoutes.Store(prefixRoute.Key(), prefixRoute)

		route := &EVPNRouteData{
			Type: EVPNTypeIPPrefix,
			PrefixData: &PrefixRoute{
				Prefix:    netip.MustParsePrefix("192.168.1.0/24"),
				VNI:       100,
				GatewayIP: netip.MustParseAddr("10.0.0.254"),
			},
		}

		err = manager.OnRouteWithdrawn(ctx, route)
		assert.NoError(t, err)
	})

	t.Run("Type-5 withdrawal with nil PrefixData", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		route := &EVPNRouteData{
			Type:       EVPNTypeIPPrefix,
			PrefixData: nil,
		}

		err = manager.OnRouteWithdrawn(ctx, route)
		assert.Error(t, err)
	})
}

func TestEVPNManager_OnRouteWithdrawn_UnsupportedType(t *testing.T) {
	speaker := newMockSpeaker()
	config := testConfig(speaker)
	manager, err := NewEVPNManager(config)
	require.NoError(t, err)

	ctx := context.Background()
	route := &EVPNRouteData{
		Type: EVPNRouteType(99), // Unsupported type
	}

	err = manager.OnRouteWithdrawn(ctx, route)
	assert.Error(t, err)
	assert.IsType(t, ErrUnsupportedRouteType{}, err)
}

func TestEVPNManager_OnRouteWithdrawn_NilRoute(t *testing.T) {
	speaker := newMockSpeaker()
	config := testConfig(speaker)
	manager, err := NewEVPNManager(config)
	require.NoError(t, err)

	ctx := context.Background()
	err = manager.OnRouteWithdrawn(ctx, nil)
	assert.Error(t, err)
}

// --- Handler with Route Notification Tests ---

func TestEVPNManager_RouteReceivedWithHandler(t *testing.T) {
	t.Run("Type-3 route notifies handler", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		handlerCalled := false
		manager.RegisterHandler(func(ctx context.Context, route *EVPNRouteData) error {
			handlerCalled = true
			return nil
		})

		ctx := context.Background()
		route := &EVPNRouteData{
			Type: EVPNTypeInclusiveMulticast,
			IMET: &IMETEntry{
				VNI:    100,
				VTEPIP: netip.MustParseAddr("10.0.0.2"),
			},
			NextHop: netip.MustParseAddr("10.0.0.2"),
		}

		err = manager.OnRouteReceived(ctx, route)
		assert.NoError(t, err)
		assert.True(t, handlerCalled)
	})

	t.Run("Type-5 route notifies handler", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		handlerCalled := false
		manager.RegisterHandler(func(ctx context.Context, route *EVPNRouteData) error {
			handlerCalled = true
			return nil
		})

		ctx := context.Background()
		route := &EVPNRouteData{
			Type: EVPNTypeIPPrefix,
			PrefixData: &PrefixRoute{
				Prefix:    netip.MustParsePrefix("192.168.1.0/24"),
				VNI:       100,
				GatewayIP: netip.MustParseAddr("10.0.0.254"),
			},
			NextHop: netip.MustParseAddr("10.0.0.2"),
		}

		err = manager.OnRouteReceived(ctx, route)
		assert.NoError(t, err)
		assert.True(t, handlerCalled)
	})

	t.Run("handler error is logged but not returned", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		manager.RegisterHandler(func(ctx context.Context, route *EVPNRouteData) error {
			return errors.New("handler failed")
		})

		ctx := context.Background()
		route := &EVPNRouteData{
			Type: EVPNTypeInclusiveMulticast,
			IMET: &IMETEntry{
				VNI:    100,
				VTEPIP: netip.MustParseAddr("10.0.0.2"),
			},
			NextHop: netip.MustParseAddr("10.0.0.2"),
		}

		err = manager.OnRouteReceived(ctx, route)
		assert.NoError(t, err) // Handler errors are logged, not returned
	})
}

// --- Withdrawal Notification Tests ---

func TestEVPNManager_RouteWithdrawnWithHandler(t *testing.T) {
	t.Run("Type-2 withdrawal notifies handler", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		handlerCalled := false
		manager.RegisterHandler(func(ctx context.Context, route *EVPNRouteData) error {
			handlerCalled = true
			return nil
		})

		ctx := context.Background()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")

		// First add a MAC
		entry := &MACIPEntry{
			MAC:    mac,
			IP:     netip.MustParseAddr("192.168.1.100"),
			VNI:    100,
			VTEPIP: netip.MustParseAddr("10.0.0.2"),
		}
		manager.remoteMACs.Store(entry.Key(), entry)

		route := &EVPNRouteData{
			Type: EVPNTypeMACIPAdvertisement,
			MACIP: &MACIPEntry{
				MAC:    mac,
				IP:     netip.MustParseAddr("192.168.1.100"),
				VNI:    100,
				VTEPIP: netip.MustParseAddr("10.0.0.2"),
			},
		}

		err = manager.OnRouteWithdrawn(ctx, route)
		assert.NoError(t, err)
		assert.True(t, handlerCalled)
	})
}

// --- MACIPKey Tests ---

func TestMACIPEntry_MACIPKeyExtended(t *testing.T) {
	t.Run("key without IP", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		entry := &MACIPEntry{
			MAC: mac,
			VNI: 100,
		}

		key := entry.MACIPKey()
		assert.Contains(t, key, "100")
		assert.Contains(t, key, mac.String())
	})

	t.Run("key with IPv4", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		entry := &MACIPEntry{
			MAC: mac,
			IP:  netip.MustParseAddr("192.168.1.100"),
			VNI: 100,
		}

		key := entry.MACIPKey()
		assert.Contains(t, key, "192.168.1.100")
	})

	t.Run("key with IPv6", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		entry := &MACIPEntry{
			MAC: mac,
			IP:  netip.MustParseAddr("2001:db8::1"),
			VNI: 100,
		}

		key := entry.MACIPKey()
		assert.Contains(t, key, "2001:db8::1")
	})
}

// --- GetRemoteMAC Tests ---

func TestEVPNManager_GetRemoteMACExtended(t *testing.T) {
	t.Run("get existing MAC", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		entry := &MACIPEntry{
			MAC:    mac,
			VNI:    100,
			VTEPIP: netip.MustParseAddr("10.0.0.2"),
		}
		manager.remoteMACs.Store(entry.Key(), entry)

		ctx := context.Background()
		result, err := manager.GetRemoteMAC(ctx, 100, mac)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, mac.String(), result.MAC.String())
	})

	t.Run("get non-existent MAC", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		mac, _ := net.ParseMAC("00:11:22:33:44:55")

		ctx := context.Background()
		_, err = manager.GetRemoteMAC(ctx, 100, mac)
		assert.Error(t, err)
		assert.IsType(t, ErrMACNotFound{}, err)
	})

	t.Run("nil MAC", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		_, err = manager.GetRemoteMAC(ctx, 100, nil)
		assert.Error(t, err)
	})
}

// --- WithdrawIMET Tests ---

func TestEVPNManager_WithdrawIMETExtended(t *testing.T) {
	t.Run("withdraw non-existent IMET", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = manager.WithdrawIMET(ctx, 100)
		assert.Error(t, err)
		assert.IsType(t, ErrIMETNotFound{}, err)
	})
}

// --- GetPrefixRoutes Tests ---

func TestEVPNManager_GetPrefixRoutesExtended(t *testing.T) {
	t.Run("get prefix routes for VNI", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		// Add prefix routes
		route1 := &PrefixRoute{
			Prefix: netip.MustParsePrefix("192.168.1.0/24"),
			VNI:    100,
		}
		route2 := &PrefixRoute{
			Prefix: netip.MustParsePrefix("192.168.2.0/24"),
			VNI:    100,
		}
		manager.prefixRoutes.Store(route1.Key(), route1)
		manager.prefixRoutes.Store(route2.Key(), route2)

		ctx := context.Background()
		routes, err := manager.GetPrefixRoutes(ctx, 100)
		assert.NoError(t, err)
		assert.Len(t, routes, 2)
	})

	t.Run("get prefix routes for different VNI", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		// Add prefix route for VNI 100
		route := &PrefixRoute{
			Prefix: netip.MustParsePrefix("192.168.1.0/24"),
			VNI:    100,
		}
		manager.prefixRoutes.Store(route.Key(), route)

		ctx := context.Background()
		routes, err := manager.GetPrefixRoutes(ctx, 200)
		assert.NoError(t, err)
		assert.Len(t, routes, 0)
	})
}
