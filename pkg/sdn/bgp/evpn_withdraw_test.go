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

// --- WithdrawPrefix Extended Tests ---

func TestEVPNManager_WithdrawPrefix_SpeakerErrors(t *testing.T) {
	t.Run("speaker delete error", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		prefix := netip.MustParsePrefix("192.168.1.0/24")
		gwIP := netip.MustParseAddr("10.0.0.254")

		// First advertise the prefix
		err = manager.AdvertisePrefix(ctx, prefix, 100, gwIP)
		require.NoError(t, err)

		// Set error for delete
		speaker.deleteErr = errors.New("speaker delete error")

		err = manager.WithdrawPrefix(ctx, prefix, 100)
		assert.Error(t, err)
	})

	t.Run("invalid prefix", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = manager.WithdrawPrefix(ctx, netip.Prefix{}, 100)
		assert.Error(t, err)
	})

	t.Run("invalid VNI", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		prefix := netip.MustParsePrefix("192.168.1.0/24")
		err = manager.WithdrawPrefix(ctx, prefix, 0)
		assert.Error(t, err)
	})
}

// --- WithdrawIMET Extended Tests ---

func TestEVPNManager_WithdrawIMET_SpeakerErrors(t *testing.T) {
	t.Run("speaker delete error", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		vtep := netip.MustParseAddr("10.0.0.1")

		// First advertise the IMET
		err = manager.AdvertiseIMET(ctx, 100, vtep)
		require.NoError(t, err)

		// Set error for delete
		speaker.deleteErr = errors.New("speaker delete error")

		err = manager.WithdrawIMET(ctx, 100)
		assert.Error(t, err)
	})

	t.Run("invalid VNI", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = manager.WithdrawIMET(ctx, 0)
		assert.Error(t, err)
	})
}

// --- AdvertiseMACIP Extended Tests ---

func TestEVPNManager_AdvertiseMACIP_SpeakerErrors(t *testing.T) {
	t.Run("nil entry", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = manager.AdvertiseMACIP(ctx, nil)
		assert.Error(t, err)
	})

	t.Run("invalid VNI in entry", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		entry := &MACIPEntry{
			MAC: mac,
			IP:  netip.MustParseAddr("192.168.1.100"),
			VNI: 0,
		}
		err = manager.AdvertiseMACIP(ctx, entry)
		assert.Error(t, err)
	})

	t.Run("nil MAC in entry", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		entry := &MACIPEntry{
			MAC: nil,
			IP:  netip.MustParseAddr("192.168.1.100"),
			VNI: 100,
		}
		err = manager.AdvertiseMACIP(ctx, entry)
		assert.Error(t, err)
	})

	t.Run("speaker add error", func(t *testing.T) {
		speaker := newMockSpeaker()
		speaker.addErr = errors.New("speaker add error")
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		entry := &MACIPEntry{
			MAC: mac,
			IP:  netip.MustParseAddr("192.168.1.100"),
			VNI: 100,
		}
		err = manager.AdvertiseMACIP(ctx, entry)
		assert.Error(t, err)
	})
}

// --- WithdrawMACIP Extended Tests ---

func TestEVPNManager_WithdrawMACIP_SpeakerErrors(t *testing.T) {
	t.Run("nil MAC", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		ip := netip.MustParseAddr("192.168.1.100")
		err = manager.WithdrawMACIP(ctx, 100, nil, ip)
		assert.Error(t, err)
	})

	t.Run("invalid VNI", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ip := netip.MustParseAddr("192.168.1.100")
		err = manager.WithdrawMACIP(ctx, 0, mac, ip)
		assert.Error(t, err)
	})

	t.Run("speaker delete error", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ip := netip.MustParseAddr("192.168.1.100")

		// First advertise
		entry := &MACIPEntry{
			MAC:    mac,
			IP:     ip,
			VNI:    100,
			VTEPIP: netip.MustParseAddr("10.0.0.1"),
		}
		err = manager.AdvertiseMACIP(ctx, entry)
		require.NoError(t, err)

		// Set error for delete
		speaker.deleteErr = errors.New("speaker delete error")

		err = manager.WithdrawMACIP(ctx, 100, mac, ip)
		assert.Error(t, err)
	})
}

// --- AdvertiseMAC Extended Tests ---

func TestEVPNManager_AdvertiseMAC_SpeakerErrors(t *testing.T) {
	t.Run("nil entry", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = manager.AdvertiseMAC(ctx, nil)
		assert.Error(t, err)
	})

	t.Run("invalid VNI in entry", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		entry := &MACIPEntry{
			MAC: mac,
			VNI: 0,
		}
		err = manager.AdvertiseMAC(ctx, entry)
		assert.Error(t, err)
	})
}

// --- WithdrawMAC Extended Tests ---

func TestEVPNManager_WithdrawMAC_SpeakerErrors(t *testing.T) {
	t.Run("nil MAC", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = manager.WithdrawMAC(ctx, 100, nil)
		assert.Error(t, err)
	})

	t.Run("invalid VNI", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		err = manager.WithdrawMAC(ctx, 0, mac)
		assert.Error(t, err)
	})
}

// --- ListRemoteMACs Tests ---

func TestEVPNManager_ListRemoteMACs_SpeakerErrors(t *testing.T) {
	t.Run("invalid VNI", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		_, err = manager.ListRemoteMACs(ctx, 0)
		assert.Error(t, err)
	})

	t.Run("list multiple MACs", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		// Add multiple MACs
		mac1, _ := net.ParseMAC("00:11:22:33:44:55")
		mac2, _ := net.ParseMAC("00:11:22:33:44:66")
		entry1 := &MACIPEntry{MAC: mac1, VNI: 100, VTEPIP: netip.MustParseAddr("10.0.0.2")}
		entry2 := &MACIPEntry{MAC: mac2, VNI: 100, VTEPIP: netip.MustParseAddr("10.0.0.3")}
		manager.remoteMACs.Store(entry1.Key(), entry1)
		manager.remoteMACs.Store(entry2.Key(), entry2)

		ctx := context.Background()
		macs, err := manager.ListRemoteMACs(ctx, 100)
		assert.NoError(t, err)
		assert.Len(t, macs, 2)
	})
}

// --- GetIMETVTEPs Tests ---

func TestEVPNManager_GetIMETVTEPs_SpeakerErrors(t *testing.T) {
	t.Run("invalid VNI", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		_, err = manager.GetIMETVTEPs(ctx, 0)
		assert.Error(t, err)
	})

	t.Run("VNI with no VTEPs", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		vteps, err := manager.GetIMETVTEPs(ctx, 100)
		assert.NoError(t, err)
		assert.Len(t, vteps, 0)
	})
}

// --- AdvertisePrefix Extended Tests ---

func TestEVPNManager_AdvertisePrefix_Validation(t *testing.T) {
	t.Run("invalid prefix", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		gwIP := netip.MustParseAddr("10.0.0.254")
		err = manager.AdvertisePrefix(ctx, netip.Prefix{}, 100, gwIP)
		assert.Error(t, err)
	})

	t.Run("invalid VNI", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		prefix := netip.MustParsePrefix("192.168.1.0/24")
		gwIP := netip.MustParseAddr("10.0.0.254")
		err = manager.AdvertisePrefix(ctx, prefix, 0, gwIP)
		assert.Error(t, err)
	})

	t.Run("zero gateway IP is valid", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		prefix := netip.MustParsePrefix("192.168.1.0/24")
		// A zero gateway IP is valid - it means no gateway is specified
		err = manager.AdvertisePrefix(ctx, prefix, 100, netip.Addr{})
		assert.NoError(t, err)
	})
}

// --- AdvertiseIMET Extended Tests ---

func TestEVPNManager_AdvertiseIMET_Validation(t *testing.T) {
	t.Run("invalid VNI", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		vtep := netip.MustParseAddr("10.0.0.1")
		err = manager.AdvertiseIMET(ctx, 0, vtep)
		assert.Error(t, err)
	})

	t.Run("invalid VTEP", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = manager.AdvertiseIMET(ctx, 100, netip.Addr{})
		assert.Error(t, err)
	})
}

// --- GetPrefixRoutes Extended Tests ---

func TestEVPNManager_GetPrefixRoutes_Validation(t *testing.T) {
	speaker := newMockSpeaker()
	config := testConfig(speaker)
	manager, err := NewEVPNManager(config)
	require.NoError(t, err)

	ctx := context.Background()
	_, err = manager.GetPrefixRoutes(ctx, 0)
	assert.Error(t, err)
}

// --- MACIPEntry Method Tests ---

func TestMACIPEntry_NilMACIPKey(t *testing.T) {
	var nilEntry *MACIPEntry
	assert.Equal(t, "", nilEntry.MACIPKey())
}

// --- EVPN Handler Error Tests ---

func TestEVPNManager_OnRouteWithdrawn_Type3_NilIMET(t *testing.T) {
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
}

func TestEVPNManager_OnRouteWithdrawn_Type5_NilPrefix(t *testing.T) {
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
}

func TestEVPNManager_OnRouteReceived_Type3_NilIMET(t *testing.T) {
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
}

func TestEVPNManager_OnRouteReceived_Type5_NilPrefix(t *testing.T) {
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
}

// --- Additional Tests to Improve Coverage ---

func TestEVPNManager_OnRouteWithdrawn_Type3_HandlerErrors(t *testing.T) {
	speaker := newMockSpeaker()
	config := testConfig(speaker)
	manager, err := NewEVPNManager(config)
	require.NoError(t, err)

	// Register a handler that returns an error
	handlerCalled := false
	manager.RegisterHandler(func(ctx context.Context, route *EVPNRouteData) error {
		handlerCalled = true
		return errors.New("handler error")
	})

	ctx := context.Background()

	// First, add an IMET entry to the table so withdrawal can find it
	imet := &IMETEntry{
		VNI:    100,
		VTEPIP: netip.MustParseAddr("10.0.0.2"),
	}
	manager.imetEntries.Store(imet.Key(), imet)

	route := &EVPNRouteData{
		Type: EVPNTypeInclusiveMulticast,
		IMET: imet,
	}
	err = manager.OnRouteWithdrawn(ctx, route)
	// Handler errors are logged but don't stop processing
	assert.NoError(t, err)
	assert.True(t, handlerCalled)
}

func TestEVPNManager_OnRouteWithdrawn_Type5_HandlerErrors(t *testing.T) {
	speaker := newMockSpeaker()
	config := testConfig(speaker)
	manager, err := NewEVPNManager(config)
	require.NoError(t, err)

	// Register a handler that returns an error
	handlerCalled := false
	manager.RegisterHandler(func(ctx context.Context, route *EVPNRouteData) error {
		handlerCalled = true
		return errors.New("handler error")
	})

	ctx := context.Background()

	// First, add a prefix route to the table so withdrawal can find it
	prefixRoute := &PrefixRoute{
		Prefix:    netip.MustParsePrefix("192.168.1.0/24"),
		VNI:       100,
		GatewayIP: netip.MustParseAddr("10.0.0.254"),
		NextHop:   netip.MustParseAddr("10.0.0.1"),
	}
	manager.prefixRoutes.Store(prefixRoute.Key(), prefixRoute)

	route := &EVPNRouteData{
		Type:       EVPNTypeIPPrefix,
		PrefixData: prefixRoute,
	}
	err = manager.OnRouteWithdrawn(ctx, route)
	// Handler errors are logged but don't stop processing
	assert.NoError(t, err)
	assert.True(t, handlerCalled)
}

func TestEVPNManager_OnRouteReceived_Type2_HandlerErrors(t *testing.T) {
	speaker := newMockSpeaker()
	config := testConfig(speaker)
	manager, err := NewEVPNManager(config)
	require.NoError(t, err)

	// Register a handler that returns an error
	handlerCalled := false
	manager.RegisterHandler(func(ctx context.Context, route *EVPNRouteData) error {
		handlerCalled = true
		return errors.New("handler error")
	})

	ctx := context.Background()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	entry := &MACIPEntry{
		MAC:    mac,
		IP:     netip.MustParseAddr("192.168.1.100"),
		VNI:    100,
		VTEPIP: netip.MustParseAddr("10.0.0.2"),
	}

	route := &EVPNRouteData{
		Type:  EVPNTypeMACIPAdvertisement,
		MACIP: entry,
	}
	err = manager.OnRouteReceived(ctx, route)
	// Handler errors are logged but don't stop processing
	assert.NoError(t, err)
	assert.True(t, handlerCalled)
}

func TestEVPNManager_OnRouteReceived_Type3_HandlerErrors(t *testing.T) {
	speaker := newMockSpeaker()
	config := testConfig(speaker)
	manager, err := NewEVPNManager(config)
	require.NoError(t, err)

	// Register a handler that returns an error
	handlerCalled := false
	manager.RegisterHandler(func(ctx context.Context, route *EVPNRouteData) error {
		handlerCalled = true
		return errors.New("handler error")
	})

	ctx := context.Background()
	imet := &IMETEntry{
		VNI:    100,
		VTEPIP: netip.MustParseAddr("10.0.0.2"),
	}

	route := &EVPNRouteData{
		Type: EVPNTypeInclusiveMulticast,
		IMET: imet,
	}
	err = manager.OnRouteReceived(ctx, route)
	// Handler errors are logged but don't stop processing
	assert.NoError(t, err)
	assert.True(t, handlerCalled)
}

func TestEVPNManager_OnRouteReceived_Type5_HandlerErrors(t *testing.T) {
	speaker := newMockSpeaker()
	config := testConfig(speaker)
	manager, err := NewEVPNManager(config)
	require.NoError(t, err)

	// Register a handler that returns an error
	handlerCalled := false
	manager.RegisterHandler(func(ctx context.Context, route *EVPNRouteData) error {
		handlerCalled = true
		return errors.New("handler error")
	})

	ctx := context.Background()
	prefixRoute := &PrefixRoute{
		Prefix:    netip.MustParsePrefix("192.168.1.0/24"),
		VNI:       100,
		GatewayIP: netip.MustParseAddr("10.0.0.254"),
		NextHop:   netip.MustParseAddr("10.0.0.1"),
	}

	route := &EVPNRouteData{
		Type:       EVPNTypeIPPrefix,
		PrefixData: prefixRoute,
	}
	err = manager.OnRouteReceived(ctx, route)
	// Handler errors are logged but don't stop processing
	assert.NoError(t, err)
	assert.True(t, handlerCalled)
}

// --- PeerManager Stop Tests ---

func TestPeerManager_StartThenStop(t *testing.T) {
	speaker := newMockPeerSpeaker()
	pm, err := NewPeerManager(speaker, testLogger())
	require.NoError(t, err)

	ctx := context.Background()
	err = pm.Start(ctx)
	require.NoError(t, err)

	// Ensure it's started
	assert.True(t, pm.IsStarted())

	// Now stop it - this should exercise the Stop code path after the early return check
	err = pm.Stop()
	assert.NoError(t, err)
	assert.False(t, pm.IsStarted())
}

// --- DampeningManager Stop Tests ---

func TestDampeningManager_StartThenStop(t *testing.T) {
	speaker := newMockDampeningSpeaker()
	cfg := DefaultDampeningConfig()
	dm, err := NewDampeningManager(speaker, cfg, testLogger())
	require.NoError(t, err)

	ctx := context.Background()
	err = dm.Start(ctx)
	require.NoError(t, err)

	// Ensure it's started
	assert.True(t, dm.IsStarted())

	// Now stop it - this should exercise the Stop code path after the early return check
	err = dm.Stop()
	assert.NoError(t, err)
	assert.False(t, dm.IsStarted())
}

// --- OnRouteWithdrawn Type2 with nil MACIP Tests ---

func TestEVPNManager_OnRouteWithdrawn_Type2_NilMACIP(t *testing.T) {
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
}

func TestEVPNManager_OnRouteReceived_Type2_NilMACIP(t *testing.T) {
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
}
