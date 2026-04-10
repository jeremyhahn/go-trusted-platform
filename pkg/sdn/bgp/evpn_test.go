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
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSpeaker implements the Speaker interface for testing.
type mockSpeaker struct {
	mu          sync.Mutex
	paths       map[string][]byte
	addErr      error
	deleteErr   error
	localASN    uint32
	routerID    netip.Addr
	addCalls    int
	deleteCalls int
}

func newMockSpeaker() *mockSpeaker {
	return &mockSpeaker{
		paths:    make(map[string][]byte),
		localASN: 65000,
		routerID: netip.MustParseAddr("10.0.0.1"),
	}
}

func (m *mockSpeaker) AddEVPNPath(ctx context.Context, nlri []byte, attrs []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addCalls++
	if m.addErr != nil {
		return m.addErr
	}
	key := string(nlri)
	m.paths[key] = attrs
	return nil
}

func (m *mockSpeaker) DeleteEVPNPath(ctx context.Context, nlri []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteCalls++
	if m.deleteErr != nil {
		return m.deleteErr
	}
	key := string(nlri)
	delete(m.paths, key)
	return nil
}

func (m *mockSpeaker) LocalASN() uint32 {
	return m.localASN
}

func (m *mockSpeaker) RouterID() netip.Addr {
	return m.routerID
}

func (m *mockSpeaker) GetAddCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.addCalls
}

func (m *mockSpeaker) GetDeleteCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.deleteCalls
}

func (m *mockSpeaker) GetPathCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.paths)
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func testConfig(speaker EVPNSpeaker) *EVPNManagerConfig {
	return &EVPNManagerConfig{
		Speaker:   speaker,
		Logger:    testLogger(),
		LocalVTEP: netip.MustParseAddr("10.0.0.1"),
		RD: RouteDistinguisher{
			Type:           0,
			Administrator:  65000,
			AssignedNumber: 1,
		},
		ImportRT: []RouteTarget{
			{Type: 0, GlobalAdmin: 65000, LocalAdmin: 100},
		},
		ExportRT: []RouteTarget{
			{Type: 0, GlobalAdmin: 65000, LocalAdmin: 100},
		},
	}
}

// --- EVPNManager Tests ---

func TestNewEVPNManager(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)

		manager, err := NewEVPNManager(config)
		require.NoError(t, err)
		assert.NotNil(t, manager)
		assert.Equal(t, config.LocalVTEP, manager.localVTEP)
	})

	t.Run("nil config", func(t *testing.T) {
		manager, err := NewEVPNManager(nil)
		assert.Error(t, err)
		assert.Nil(t, manager)
		assert.IsType(t, ErrEntryNil{}, err)
	})

	t.Run("nil speaker", func(t *testing.T) {
		config := testConfig(nil)
		config.Speaker = nil

		manager, err := NewEVPNManager(config)
		assert.Error(t, err)
		assert.Nil(t, manager)
		assert.ErrorIs(t, err, ErrSpeakerNil)
	})

	t.Run("nil logger", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		config.Logger = nil

		manager, err := NewEVPNManager(config)
		assert.Error(t, err)
		assert.Nil(t, manager)
		assert.ErrorIs(t, err, ErrLoggerNil)
	})

	t.Run("invalid local VTEP", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		config.LocalVTEP = netip.Addr{}

		manager, err := NewEVPNManager(config)
		assert.Error(t, err)
		assert.Nil(t, manager)
		assert.IsType(t, ErrInvalidIP{}, err)
	})

	t.Run("unspecified local VTEP", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		config.LocalVTEP = netip.MustParseAddr("0.0.0.0")

		manager, err := NewEVPNManager(config)
		assert.Error(t, err)
		assert.Nil(t, manager)
	})
}

func TestEVPNManager_StartStop(t *testing.T) {
	t.Run("start and stop", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()

		err = manager.Start(ctx)
		assert.NoError(t, err)
		assert.True(t, manager.started.Load())

		err = manager.Stop(ctx)
		assert.NoError(t, err)
		assert.False(t, manager.started.Load())
	})

	t.Run("double start", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()

		err = manager.Start(ctx)
		assert.NoError(t, err)

		err = manager.Start(ctx)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrManagerAlreadyStarted)

		_ = manager.Stop(ctx)
	})

	t.Run("stop without start", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()

		err = manager.Stop(ctx)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrManagerNotStarted)
	})
}

// --- Type-2 MAC/IP Advertisement Tests ---

func TestEVPNManager_AdvertiseMAC(t *testing.T) {
	t.Run("valid MAC advertisement", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		entry := &MACIPEntry{
			MAC: mac,
			VNI: 100,
		}

		err = manager.AdvertiseMAC(ctx, entry)
		assert.NoError(t, err)
		assert.Equal(t, 1, speaker.GetAddCalls())
	})

	t.Run("nil entry", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()

		err = manager.AdvertiseMAC(ctx, nil)
		assert.Error(t, err)
		assert.IsType(t, ErrEntryNil{}, err)
	})

	t.Run("invalid VNI", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		entry := &MACIPEntry{
			MAC: mac,
			VNI: 0, // Invalid
		}

		err = manager.AdvertiseMAC(ctx, entry)
		assert.Error(t, err)
		assert.IsType(t, ErrInvalidVNI{}, err)
	})

	t.Run("nil MAC", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		entry := &MACIPEntry{
			MAC: nil,
			VNI: 100,
		}

		err = manager.AdvertiseMAC(ctx, entry)
		assert.Error(t, err)
		assert.IsType(t, ErrInvalidMAC{}, err)
	})

	t.Run("speaker error", func(t *testing.T) {
		speaker := newMockSpeaker()
		speaker.addErr = assert.AnError
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		entry := &MACIPEntry{
			MAC: mac,
			VNI: 100,
		}

		err = manager.AdvertiseMAC(ctx, entry)
		assert.Error(t, err)
		assert.IsType(t, ErrRouteAdvertisementFailed{}, err)
	})
}

func TestEVPNManager_WithdrawMAC(t *testing.T) {
	t.Run("withdraw existing MAC", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		entry := &MACIPEntry{
			MAC: mac,
			VNI: 100,
		}

		// First advertise
		err = manager.AdvertiseMAC(ctx, entry)
		require.NoError(t, err)

		// Then withdraw
		err = manager.WithdrawMAC(ctx, 100, mac)
		assert.NoError(t, err)
		assert.Equal(t, 1, speaker.GetDeleteCalls())
	})

	t.Run("withdraw non-existent MAC", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")

		err = manager.WithdrawMAC(ctx, 100, mac)
		assert.Error(t, err)
		assert.IsType(t, ErrMACNotFound{}, err)
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
		assert.IsType(t, ErrInvalidVNI{}, err)
	})

	t.Run("nil MAC", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()

		err = manager.WithdrawMAC(ctx, 100, nil)
		assert.Error(t, err)
		assert.IsType(t, ErrInvalidMAC{}, err)
	})
}

func TestEVPNManager_AdvertiseMACIP(t *testing.T) {
	t.Run("valid MAC/IP advertisement", func(t *testing.T) {
		speaker := newMockSpeaker()
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
		assert.NoError(t, err)
		assert.Equal(t, 1, speaker.GetAddCalls())

		// Verify ARP suppression tables updated
		ip, found := manager.LookupIPForMAC(100, mac)
		assert.True(t, found)
		assert.Equal(t, entry.IP, ip)

		foundMAC, found := manager.LookupMACForIP(100, entry.IP)
		assert.True(t, found)
		assert.Equal(t, mac.String(), foundMAC.String())
	})

	t.Run("MAC/IP without IP", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		entry := &MACIPEntry{
			MAC: mac,
			VNI: 100,
		}

		err = manager.AdvertiseMACIP(ctx, entry)
		assert.Error(t, err)
		assert.IsType(t, ErrInvalidIP{}, err)
	})

	t.Run("IPv6 MAC/IP advertisement", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		entry := &MACIPEntry{
			MAC: mac,
			IP:  netip.MustParseAddr("2001:db8::1"),
			VNI: 100,
		}

		err = manager.AdvertiseMACIP(ctx, entry)
		assert.NoError(t, err)
	})
}

func TestEVPNManager_WithdrawMACIP(t *testing.T) {
	t.Run("withdraw existing MAC/IP", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ip := netip.MustParseAddr("192.168.1.100")
		entry := &MACIPEntry{
			MAC: mac,
			IP:  ip,
			VNI: 100,
		}

		err = manager.AdvertiseMACIP(ctx, entry)
		require.NoError(t, err)

		err = manager.WithdrawMACIP(ctx, 100, mac, ip)
		assert.NoError(t, err)

		// Verify ARP suppression tables cleared
		_, found := manager.LookupIPForMAC(100, mac)
		assert.False(t, found)

		_, found = manager.LookupMACForIP(100, ip)
		assert.False(t, found)
	})

	t.Run("withdraw non-existent MAC/IP", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ip := netip.MustParseAddr("192.168.1.100")

		err = manager.WithdrawMACIP(ctx, 100, mac, ip)
		assert.Error(t, err)
		assert.IsType(t, ErrMACIPNotFound{}, err)
	})

	t.Run("invalid IP", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")

		err = manager.WithdrawMACIP(ctx, 100, mac, netip.Addr{})
		assert.Error(t, err)
		assert.IsType(t, ErrInvalidIP{}, err)
	})
}

func TestEVPNManager_GetRemoteMAC(t *testing.T) {
	t.Run("get existing remote MAC", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")

		// Simulate receiving a remote MAC
		entry := &MACIPEntry{
			MAC:    mac,
			VNI:    100,
			VTEPIP: netip.MustParseAddr("10.0.0.2"),
		}
		manager.remoteMACs.Store(entry.Key(), entry)

		result, err := manager.GetRemoteMAC(ctx, 100, mac)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, mac.String(), result.MAC.String())
	})

	t.Run("get non-existent remote MAC", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")

		result, err := manager.GetRemoteMAC(ctx, 100, mac)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.IsType(t, ErrMACNotFound{}, err)
	})
}

func TestEVPNManager_ListRemoteMACs(t *testing.T) {
	t.Run("list remote MACs for VNI", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()

		// Add multiple remote MACs
		macs := []string{"00:11:22:33:44:01", "00:11:22:33:44:02", "00:11:22:33:44:03"}
		for _, macStr := range macs {
			mac, _ := net.ParseMAC(macStr)
			entry := &MACIPEntry{
				MAC:    mac,
				VNI:    100,
				VTEPIP: netip.MustParseAddr("10.0.0.2"),
			}
			manager.remoteMACs.Store(entry.Key(), entry)
		}

		// Add MAC for different VNI
		otherMAC, _ := net.ParseMAC("00:11:22:33:44:99")
		otherEntry := &MACIPEntry{
			MAC:    otherMAC,
			VNI:    200,
			VTEPIP: netip.MustParseAddr("10.0.0.3"),
		}
		manager.remoteMACs.Store(otherEntry.Key(), otherEntry)

		results, err := manager.ListRemoteMACs(ctx, 100)
		assert.NoError(t, err)
		assert.Len(t, results, 3)
	})

	t.Run("list remote MACs for empty VNI", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()

		results, err := manager.ListRemoteMACs(ctx, 100)
		assert.NoError(t, err)
		assert.Empty(t, results)
	})
}

// --- Type-3 Inclusive Multicast Tests ---

func TestEVPNManager_AdvertiseIMET(t *testing.T) {
	t.Run("valid IMET advertisement", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		vtepIP := netip.MustParseAddr("10.0.0.1")

		err = manager.AdvertiseIMET(ctx, 100, vtepIP)
		assert.NoError(t, err)
		assert.Equal(t, 1, speaker.GetAddCalls())

		// Verify VTEP added to VNI list
		vteps, err := manager.GetIMETVTEPs(ctx, 100)
		assert.NoError(t, err)
		assert.Len(t, vteps, 1)
		assert.Equal(t, vtepIP, vteps[0])
	})

	t.Run("invalid VNI", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		vtepIP := netip.MustParseAddr("10.0.0.1")

		err = manager.AdvertiseIMET(ctx, 0, vtepIP)
		assert.Error(t, err)
		assert.IsType(t, ErrInvalidVNI{}, err)
	})

	t.Run("invalid VTEP IP", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()

		err = manager.AdvertiseIMET(ctx, 100, netip.Addr{})
		assert.Error(t, err)
		assert.IsType(t, ErrInvalidIP{}, err)
	})

	t.Run("unspecified VTEP IP", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()

		err = manager.AdvertiseIMET(ctx, 100, netip.MustParseAddr("0.0.0.0"))
		assert.Error(t, err)
	})
}

func TestEVPNManager_WithdrawIMET(t *testing.T) {
	t.Run("withdraw existing IMET", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		vtepIP := netip.MustParseAddr("10.0.0.1")

		err = manager.AdvertiseIMET(ctx, 100, vtepIP)
		require.NoError(t, err)

		err = manager.WithdrawIMET(ctx, 100)
		assert.NoError(t, err)
		assert.Equal(t, 1, speaker.GetDeleteCalls())

		// Verify VTEP removed from list
		vteps, err := manager.GetIMETVTEPs(ctx, 100)
		assert.NoError(t, err)
		assert.Empty(t, vteps)
	})

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

func TestEVPNManager_GetIMETVTEPs(t *testing.T) {
	t.Run("get VTEPs for VNI", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()

		// Simulate multiple VTEPs for same VNI
		vteps := []netip.Addr{
			netip.MustParseAddr("10.0.0.1"),
			netip.MustParseAddr("10.0.0.2"),
			netip.MustParseAddr("10.0.0.3"),
		}
		for _, vtep := range vteps {
			manager.addVNIVTEP(100, vtep)
		}

		result, err := manager.GetIMETVTEPs(ctx, 100)
		assert.NoError(t, err)
		assert.Len(t, result, 3)
	})

	t.Run("get VTEPs for empty VNI", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()

		result, err := manager.GetIMETVTEPs(ctx, 100)
		assert.NoError(t, err)
		assert.Empty(t, result)
	})
}

// --- Type-5 IP Prefix Tests ---

func TestEVPNManager_AdvertisePrefix(t *testing.T) {
	t.Run("valid prefix advertisement", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		prefix := netip.MustParsePrefix("192.168.1.0/24")
		gateway := netip.MustParseAddr("192.168.1.1")

		err = manager.AdvertisePrefix(ctx, prefix, 100, gateway)
		assert.NoError(t, err)
		assert.Equal(t, 1, speaker.GetAddCalls())
	})

	t.Run("prefix without gateway", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		prefix := netip.MustParsePrefix("192.168.1.0/24")

		err = manager.AdvertisePrefix(ctx, prefix, 100, netip.Addr{})
		assert.NoError(t, err)
	})

	t.Run("IPv6 prefix", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		prefix := netip.MustParsePrefix("2001:db8::/32")
		gateway := netip.MustParseAddr("2001:db8::1")

		err = manager.AdvertisePrefix(ctx, prefix, 100, gateway)
		assert.NoError(t, err)
	})

	t.Run("invalid prefix", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()

		err = manager.AdvertisePrefix(ctx, netip.Prefix{}, 100, netip.Addr{})
		assert.Error(t, err)
		var prefixErr ErrPrefixInvalid
		assert.ErrorAs(t, err, &prefixErr)
	})

	t.Run("invalid VNI", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		prefix := netip.MustParsePrefix("192.168.1.0/24")

		err = manager.AdvertisePrefix(ctx, prefix, 0, netip.Addr{})
		assert.Error(t, err)
		assert.IsType(t, ErrInvalidVNI{}, err)
	})
}

func TestEVPNManager_WithdrawPrefix(t *testing.T) {
	t.Run("withdraw existing prefix", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		prefix := netip.MustParsePrefix("192.168.1.0/24")
		gateway := netip.MustParseAddr("192.168.1.1")

		err = manager.AdvertisePrefix(ctx, prefix, 100, gateway)
		require.NoError(t, err)

		err = manager.WithdrawPrefix(ctx, prefix, 100)
		assert.NoError(t, err)
		assert.Equal(t, 1, speaker.GetDeleteCalls())
	})

	t.Run("withdraw non-existent prefix", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		prefix := netip.MustParsePrefix("192.168.1.0/24")

		err = manager.WithdrawPrefix(ctx, prefix, 100)
		assert.Error(t, err)
		assert.IsType(t, ErrPrefixNotFound{}, err)
	})
}

func TestEVPNManager_GetPrefixRoutes(t *testing.T) {
	t.Run("get prefix routes for VNI", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()

		// Add multiple prefixes
		prefixes := []string{"192.168.1.0/24", "192.168.2.0/24", "192.168.3.0/24"}
		for _, p := range prefixes {
			prefix := netip.MustParsePrefix(p)
			err = manager.AdvertisePrefix(ctx, prefix, 100, netip.Addr{})
			require.NoError(t, err)
		}

		// Add prefix for different VNI
		otherPrefix := netip.MustParsePrefix("10.0.0.0/8")
		err = manager.AdvertisePrefix(ctx, otherPrefix, 200, netip.Addr{})
		require.NoError(t, err)

		results, err := manager.GetPrefixRoutes(ctx, 100)
		assert.NoError(t, err)
		assert.Len(t, results, 3)
	})
}

// --- Route Encoding/Decoding Tests ---

func TestBuildType2NLRI(t *testing.T) {
	t.Run("MAC only", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		entry := &MACIPEntry{
			MAC: mac,
			VNI: 100,
		}

		nlri, err := manager.buildType2NLRI(entry)
		assert.NoError(t, err)
		assert.NotEmpty(t, nlri)
		assert.Equal(t, byte(EVPNTypeMACIPAdvertisement), nlri[0])
	})

	t.Run("MAC with IPv4", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		entry := &MACIPEntry{
			MAC: mac,
			IP:  netip.MustParseAddr("192.168.1.100"),
			VNI: 100,
		}

		nlri, err := manager.buildType2NLRI(entry)
		assert.NoError(t, err)
		assert.NotEmpty(t, nlri)
	})

	t.Run("MAC with IPv6", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		entry := &MACIPEntry{
			MAC: mac,
			IP:  netip.MustParseAddr("2001:db8::1"),
			VNI: 100,
		}

		nlri, err := manager.buildType2NLRI(entry)
		assert.NoError(t, err)
		assert.NotEmpty(t, nlri)
	})
}

func TestBuildType3NLRI(t *testing.T) {
	t.Run("IPv4 VTEP", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		entry := &IMETEntry{
			VNI:        100,
			VTEPIP:     netip.MustParseAddr("10.0.0.1"),
			TunnelType: TunnelTypeIngressReplication,
		}

		nlri, err := manager.buildType3NLRI(entry)
		assert.NoError(t, err)
		assert.NotEmpty(t, nlri)
		assert.Equal(t, byte(EVPNTypeInclusiveMulticast), nlri[0])
	})

	t.Run("IPv6 VTEP", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		entry := &IMETEntry{
			VNI:        100,
			VTEPIP:     netip.MustParseAddr("2001:db8::1"),
			TunnelType: TunnelTypeIngressReplication,
		}

		nlri, err := manager.buildType3NLRI(entry)
		assert.NoError(t, err)
		assert.NotEmpty(t, nlri)
	})
}

func TestBuildType5NLRI(t *testing.T) {
	t.Run("IPv4 prefix with gateway", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		route := &PrefixRoute{
			Prefix:    netip.MustParsePrefix("192.168.1.0/24"),
			VNI:       100,
			GatewayIP: netip.MustParseAddr("192.168.1.1"),
		}

		nlri, err := manager.buildType5NLRI(route)
		assert.NoError(t, err)
		assert.NotEmpty(t, nlri)
		assert.Equal(t, byte(EVPNTypeIPPrefix), nlri[0])
	})

	t.Run("IPv4 prefix without gateway", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		route := &PrefixRoute{
			Prefix: netip.MustParsePrefix("192.168.1.0/24"),
			VNI:    100,
		}

		nlri, err := manager.buildType5NLRI(route)
		assert.NoError(t, err)
		assert.NotEmpty(t, nlri)
	})
}

func TestParseEVPNRoute(t *testing.T) {
	t.Run("NLRI too short", func(t *testing.T) {
		_, err := parseEVPNRoute([]byte{})
		assert.Error(t, err)
		assert.IsType(t, ErrNLRITooShort{}, err)
	})

	t.Run("unsupported route type", func(t *testing.T) {
		nlri := make([]byte, 20)
		nlri[0] = 99 // Unknown type
		nlri[1] = 18 // Length

		_, err := parseEVPNRoute(nlri)
		assert.Error(t, err)
		assert.IsType(t, ErrUnsupportedRouteType{}, err)
	})
}

func TestEncodeEVPNRoute(t *testing.T) {
	t.Run("nil route", func(t *testing.T) {
		_, err := encodeEVPNRoute(nil, RouteDistinguisher{})
		assert.Error(t, err)
		assert.IsType(t, ErrEntryNil{}, err)
	})

	t.Run("Type-2 with nil MACIP", func(t *testing.T) {
		route := &EVPNRouteData{
			Type: EVPNTypeMACIPAdvertisement,
		}
		_, err := encodeEVPNRoute(route, RouteDistinguisher{})
		assert.Error(t, err)
		assert.IsType(t, ErrInvalidEVPNRoute{}, err)
	})

	t.Run("Type-3 with nil IMET", func(t *testing.T) {
		route := &EVPNRouteData{
			Type: EVPNTypeInclusiveMulticast,
		}
		_, err := encodeEVPNRoute(route, RouteDistinguisher{})
		assert.Error(t, err)
		assert.IsType(t, ErrInvalidEVPNRoute{}, err)
	})

	t.Run("Type-5 with nil Prefix", func(t *testing.T) {
		route := &EVPNRouteData{
			Type: EVPNTypeIPPrefix,
		}
		_, err := encodeEVPNRoute(route, RouteDistinguisher{})
		assert.Error(t, err)
		assert.IsType(t, ErrInvalidEVPNRoute{}, err)
	})

	t.Run("unsupported route type", func(t *testing.T) {
		route := &EVPNRouteData{
			Type: EVPNRouteType(99),
		}
		_, err := encodeEVPNRoute(route, RouteDistinguisher{})
		assert.Error(t, err)
		assert.IsType(t, ErrUnsupportedRouteType{}, err)
	})
}

// --- MAC Mobility Tests ---

func TestEVPNManager_HandleMACMove(t *testing.T) {
	t.Run("new MAC", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		entry := &MACIPEntry{
			MAC:    mac,
			VNI:    100,
			VTEPIP: netip.MustParseAddr("10.0.0.2"),
		}

		err = manager.HandleMACMove(ctx, entry)
		assert.NoError(t, err)
	})

	t.Run("MAC from same VTEP", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		vtep := netip.MustParseAddr("10.0.0.2")

		// First entry
		entry1 := &MACIPEntry{
			MAC:    mac,
			VNI:    100,
			VTEPIP: vtep,
		}
		err = manager.HandleMACMove(ctx, entry1)
		require.NoError(t, err)

		// Update from same VTEP
		entry2 := &MACIPEntry{
			MAC:    mac,
			IP:     netip.MustParseAddr("192.168.1.100"),
			VNI:    100,
			VTEPIP: vtep,
		}
		err = manager.HandleMACMove(ctx, entry2)
		assert.NoError(t, err)
	})

	t.Run("MAC moved to different VTEP with higher sequence", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")

		// First entry
		entry1 := &MACIPEntry{
			MAC:      mac,
			VNI:      100,
			VTEPIP:   netip.MustParseAddr("10.0.0.2"),
			Sequence: 0,
		}
		err = manager.HandleMACMove(ctx, entry1)
		require.NoError(t, err)

		// MAC moved to different VTEP with higher sequence
		entry2 := &MACIPEntry{
			MAC:      mac,
			VNI:      100,
			VTEPIP:   netip.MustParseAddr("10.0.0.3"),
			Sequence: 1,
		}
		err = manager.HandleMACMove(ctx, entry2)
		assert.NoError(t, err)

		// Verify mobility tracking updated
		seq := manager.GetMACSequence(100, mac)
		assert.Equal(t, uint32(1), seq)
	})

	t.Run("MAC mobility conflict with lower sequence", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")

		// First entry with sequence 1
		entry1 := &MACIPEntry{
			MAC:      mac,
			VNI:      100,
			VTEPIP:   netip.MustParseAddr("10.0.0.2"),
			Sequence: 1,
		}
		err = manager.HandleMACMove(ctx, entry1)
		require.NoError(t, err)

		// Set mobility sequence
		manager.IncrementMACSequence(100, mac)

		// Attempt move with lower sequence
		entry2 := &MACIPEntry{
			MAC:      mac,
			VNI:      100,
			VTEPIP:   netip.MustParseAddr("10.0.0.3"),
			Sequence: 0,
		}
		err = manager.HandleMACMove(ctx, entry2)
		assert.Error(t, err)
		assert.IsType(t, ErrMACMobilityConflict{}, err)
	})

	t.Run("nil entry", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()

		err = manager.HandleMACMove(ctx, nil)
		assert.Error(t, err)
		assert.IsType(t, ErrEntryNil{}, err)
	})
}

func TestEVPNManager_MACSequence(t *testing.T) {
	t.Run("get non-existent sequence", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		seq := manager.GetMACSequence(100, mac)
		assert.Equal(t, uint32(0), seq)
	})

	t.Run("increment sequence", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		mac, _ := net.ParseMAC("00:11:22:33:44:55")

		seq := manager.IncrementMACSequence(100, mac)
		assert.Equal(t, uint32(1), seq)

		seq = manager.IncrementMACSequence(100, mac)
		assert.Equal(t, uint32(2), seq)

		seq = manager.GetMACSequence(100, mac)
		assert.Equal(t, uint32(2), seq)
	})
}

// --- Event Handling Tests ---

func TestEVPNManager_OnRouteReceived(t *testing.T) {
	t.Run("Type-2 route received", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")

		route := &EVPNRouteData{
			Type:    EVPNTypeMACIPAdvertisement,
			NextHop: netip.MustParseAddr("10.0.0.2"),
			MACIP: &MACIPEntry{
				MAC: mac,
				VNI: 100,
			},
		}

		err = manager.OnRouteReceived(ctx, route)
		assert.NoError(t, err)
	})

	t.Run("Type-3 route received", func(t *testing.T) {
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
		}

		err = manager.OnRouteReceived(ctx, route)
		assert.NoError(t, err)

		// Verify VTEP added
		vteps, err := manager.GetIMETVTEPs(ctx, 100)
		assert.NoError(t, err)
		assert.Len(t, vteps, 1)
	})

	t.Run("Type-5 route received", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()

		route := &EVPNRouteData{
			Type:    EVPNTypeIPPrefix,
			NextHop: netip.MustParseAddr("10.0.0.2"),
			PrefixData: &PrefixRoute{
				Prefix: netip.MustParsePrefix("192.168.1.0/24"),
				VNI:    100,
			},
		}

		err = manager.OnRouteReceived(ctx, route)
		assert.NoError(t, err)
	})

	t.Run("nil route", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()

		err = manager.OnRouteReceived(ctx, nil)
		assert.Error(t, err)
		assert.IsType(t, ErrEntryNil{}, err)
	})

	t.Run("unsupported route type", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()

		route := &EVPNRouteData{
			Type: EVPNRouteType(99),
		}

		err = manager.OnRouteReceived(ctx, route)
		assert.Error(t, err)
		assert.IsType(t, ErrUnsupportedRouteType{}, err)
	})
}

func TestEVPNManager_OnRouteWithdrawn(t *testing.T) {
	t.Run("Type-2 route withdrawn", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")

		// First add the route
		entry := &MACIPEntry{
			MAC:    mac,
			IP:     netip.MustParseAddr("192.168.1.100"),
			VNI:    100,
			VTEPIP: netip.MustParseAddr("10.0.0.2"),
		}
		manager.remoteMACs.Store(entry.Key(), entry)
		ipKey := formatKey(entry.VNI, entry.IP.String())
		manager.ipToMAC.Store(ipKey, entry.MAC)
		manager.macToIP.Store(entry.Key(), entry.IP)

		// Withdraw
		route := &EVPNRouteData{
			Type: EVPNTypeMACIPAdvertisement,
			MACIP: &MACIPEntry{
				MAC: mac,
				IP:  netip.MustParseAddr("192.168.1.100"),
				VNI: 100,
			},
		}

		err = manager.OnRouteWithdrawn(ctx, route)
		assert.NoError(t, err)

		// Verify removed
		_, found := manager.LookupMACForIP(100, entry.IP)
		assert.False(t, found)
	})

	t.Run("Type-3 route withdrawn", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()

		// Add VTEP first
		manager.addVNIVTEP(100, netip.MustParseAddr("10.0.0.2"))
		entry := &IMETEntry{
			VNI:    100,
			VTEPIP: netip.MustParseAddr("10.0.0.2"),
		}
		manager.imetEntries.Store(entry.Key(), entry)

		// Withdraw
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

	t.Run("Type-5 route withdrawn", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()

		// Add prefix first
		prefix := netip.MustParsePrefix("192.168.1.0/24")
		prefixRoute := &PrefixRoute{
			Prefix: prefix,
			VNI:    100,
		}
		manager.prefixRoutes.Store(prefixRoute.Key(), prefixRoute)

		// Withdraw
		route := &EVPNRouteData{
			Type: EVPNTypeIPPrefix,
			PrefixData: &PrefixRoute{
				Prefix: prefix,
				VNI:    100,
			},
		}

		err = manager.OnRouteWithdrawn(ctx, route)
		assert.NoError(t, err)
	})
}

func TestEVPNManager_RegisterHandler(t *testing.T) {
	t.Run("handler called on route received", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ctx := context.Background()
		handlerCalled := false

		manager.RegisterHandler(func(ctx context.Context, route *EVPNRouteData) error {
			handlerCalled = true
			return nil
		})

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		route := &EVPNRouteData{
			Type:    EVPNTypeMACIPAdvertisement,
			NextHop: netip.MustParseAddr("10.0.0.2"),
			MACIP: &MACIPEntry{
				MAC: mac,
				VNI: 100,
			},
		}

		err = manager.OnRouteReceived(ctx, route)
		assert.NoError(t, err)
		assert.True(t, handlerCalled)
	})
}

// --- ARP Suppression Tests ---

func TestEVPNManager_ARPSuppression(t *testing.T) {
	t.Run("lookup IP for MAC", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ip := netip.MustParseAddr("192.168.1.100")

		// Add to table
		key := formatKey(100, mac.String())
		manager.macToIP.Store(key, ip)

		result, found := manager.LookupIPForMAC(100, mac)
		assert.True(t, found)
		assert.Equal(t, ip, result)
	})

	t.Run("lookup IP for non-existent MAC", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		mac, _ := net.ParseMAC("00:11:22:33:44:55")

		_, found := manager.LookupIPForMAC(100, mac)
		assert.False(t, found)
	})

	t.Run("lookup MAC for IP", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		ip := netip.MustParseAddr("192.168.1.100")

		// Add to table
		key := formatKey(100, ip.String())
		manager.ipToMAC.Store(key, mac)

		result, found := manager.LookupMACForIP(100, ip)
		assert.True(t, found)
		assert.Equal(t, mac.String(), result.String())
	})

	t.Run("lookup MAC for non-existent IP", func(t *testing.T) {
		speaker := newMockSpeaker()
		config := testConfig(speaker)
		manager, err := NewEVPNManager(config)
		require.NoError(t, err)

		ip := netip.MustParseAddr("192.168.1.100")

		_, found := manager.LookupMACForIP(100, ip)
		assert.False(t, found)
	})
}

// --- Type Tests ---

func TestRouteDistinguisher(t *testing.T) {
	t.Run("Type 0 bytes", func(t *testing.T) {
		rd := RouteDistinguisher{
			Type:           0,
			Administrator:  65000,
			AssignedNumber: 100,
		}
		bytes := rd.Bytes()
		assert.Len(t, bytes, 8)
	})

	t.Run("Type 1 bytes", func(t *testing.T) {
		rd := RouteDistinguisher{
			Type:           1,
			Administrator:  0x0A000001, // 10.0.0.1
			AssignedNumber: 100,
		}
		bytes := rd.Bytes()
		assert.Len(t, bytes, 8)
	})

	t.Run("Type 2 bytes", func(t *testing.T) {
		rd := RouteDistinguisher{
			Type:           2,
			Administrator:  4200000000,
			AssignedNumber: 100,
		}
		bytes := rd.Bytes()
		assert.Len(t, bytes, 8)
	})

	t.Run("parse round trip", func(t *testing.T) {
		original := RouteDistinguisher{
			Type:           0,
			Administrator:  65000,
			AssignedNumber: 100,
		}
		bytes := original.Bytes()
		parsed := ParseRouteDistinguisher(bytes)

		assert.Equal(t, original.Type, parsed.Type)
		assert.Equal(t, original.Administrator, parsed.Administrator)
		assert.Equal(t, original.AssignedNumber, parsed.AssignedNumber)
	})
}

func TestRouteTarget(t *testing.T) {
	t.Run("Type 0 bytes", func(t *testing.T) {
		rt := RouteTarget{
			Type:        0,
			GlobalAdmin: 65000,
			LocalAdmin:  100,
		}
		bytes := rt.Bytes()
		assert.Len(t, bytes, 8)
		assert.Equal(t, byte(0x00), bytes[0])
		assert.Equal(t, byte(0x02), bytes[1])
	})

	t.Run("Type 1 bytes", func(t *testing.T) {
		rt := RouteTarget{
			Type:        1,
			GlobalAdmin: 0x0A000001,
			LocalAdmin:  100,
		}
		bytes := rt.Bytes()
		assert.Len(t, bytes, 8)
		assert.Equal(t, byte(0x01), bytes[0])
	})

	t.Run("Type 2 bytes", func(t *testing.T) {
		rt := RouteTarget{
			Type:        2,
			GlobalAdmin: 4200000000,
			LocalAdmin:  100,
		}
		bytes := rt.Bytes()
		assert.Len(t, bytes, 8)
		assert.Equal(t, byte(0x02), bytes[0])
	})

	t.Run("parse round trip", func(t *testing.T) {
		original := RouteTarget{
			Type:        0,
			GlobalAdmin: 65000,
			LocalAdmin:  100,
		}
		bytes := original.Bytes()
		parsed := ParseRouteTarget(bytes)

		assert.Equal(t, original.Type, parsed.Type)
		assert.Equal(t, original.GlobalAdmin, parsed.GlobalAdmin)
		assert.Equal(t, original.LocalAdmin, parsed.LocalAdmin)
	})
}

func TestMACIPEntry(t *testing.T) {
	t.Run("Key", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		entry := &MACIPEntry{
			MAC: mac,
			VNI: 100,
		}
		key := entry.Key()
		assert.Equal(t, "100:00:11:22:33:44:55", key)
	})

	t.Run("Key nil entry", func(t *testing.T) {
		var entry *MACIPEntry
		assert.Equal(t, "", entry.Key())
	})

	t.Run("MACIPKey with IP", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		entry := &MACIPEntry{
			MAC: mac,
			IP:  netip.MustParseAddr("192.168.1.100"),
			VNI: 100,
		}
		key := entry.MACIPKey()
		assert.Equal(t, "100:00:11:22:33:44:55:192.168.1.100", key)
	})

	t.Run("MACIPKey without IP", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		entry := &MACIPEntry{
			MAC: mac,
			VNI: 100,
		}
		key := entry.MACIPKey()
		assert.Equal(t, "100:00:11:22:33:44:55", key)
	})

	t.Run("HasIP", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")

		entryWithIP := &MACIPEntry{
			MAC: mac,
			IP:  netip.MustParseAddr("192.168.1.100"),
			VNI: 100,
		}
		assert.True(t, entryWithIP.HasIP())

		entryWithoutIP := &MACIPEntry{
			MAC: mac,
			VNI: 100,
		}
		assert.False(t, entryWithoutIP.HasIP())

		var nilEntry *MACIPEntry
		assert.False(t, nilEntry.HasIP())
	})

	t.Run("Clone", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		original := &MACIPEntry{
			MAC:       mac,
			IP:        netip.MustParseAddr("192.168.1.100"),
			VNI:       100,
			VTEPIP:    netip.MustParseAddr("10.0.0.1"),
			Sequence:  5,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		clone := original.Clone()
		assert.NotNil(t, clone)
		assert.Equal(t, original.MAC.String(), clone.MAC.String())
		assert.Equal(t, original.IP, clone.IP)
		assert.Equal(t, original.VNI, clone.VNI)

		// Verify deep copy of MAC
		clone.MAC[0] = 0xFF
		assert.NotEqual(t, original.MAC[0], clone.MAC[0])
	})

	t.Run("Clone nil", func(t *testing.T) {
		var entry *MACIPEntry
		assert.Nil(t, entry.Clone())
	})
}

func TestIMETEntry(t *testing.T) {
	t.Run("Key", func(t *testing.T) {
		entry := &IMETEntry{
			VNI:    100,
			VTEPIP: netip.MustParseAddr("10.0.0.1"),
		}
		key := entry.Key()
		assert.Equal(t, "100:10.0.0.1", key)
	})

	t.Run("Key nil entry", func(t *testing.T) {
		var entry *IMETEntry
		assert.Equal(t, "", entry.Key())
	})

	t.Run("Clone", func(t *testing.T) {
		original := &IMETEntry{
			VNI:           100,
			VTEPIP:        netip.MustParseAddr("10.0.0.1"),
			EthernetTagID: 0,
			TunnelType:    TunnelTypeIngressReplication,
			CreatedAt:     time.Now(),
		}

		clone := original.Clone()
		assert.NotNil(t, clone)
		assert.Equal(t, original.VNI, clone.VNI)
		assert.Equal(t, original.VTEPIP, clone.VTEPIP)
	})

	t.Run("Clone nil", func(t *testing.T) {
		var entry *IMETEntry
		assert.Nil(t, entry.Clone())
	})
}

func TestPrefixRoute(t *testing.T) {
	t.Run("Key", func(t *testing.T) {
		route := &PrefixRoute{
			Prefix: netip.MustParsePrefix("192.168.1.0/24"),
			VNI:    100,
		}
		key := route.Key()
		assert.Equal(t, "100:192.168.1.0/24", key)
	})

	t.Run("Key nil route", func(t *testing.T) {
		var route *PrefixRoute
		assert.Equal(t, "", route.Key())
	})

	t.Run("HasGateway", func(t *testing.T) {
		routeWithGW := &PrefixRoute{
			Prefix:    netip.MustParsePrefix("192.168.1.0/24"),
			VNI:       100,
			GatewayIP: netip.MustParseAddr("192.168.1.1"),
		}
		assert.True(t, routeWithGW.HasGateway())

		routeWithoutGW := &PrefixRoute{
			Prefix: netip.MustParsePrefix("192.168.1.0/24"),
			VNI:    100,
		}
		assert.False(t, routeWithoutGW.HasGateway())

		var nilRoute *PrefixRoute
		assert.False(t, nilRoute.HasGateway())
	})

	t.Run("Clone", func(t *testing.T) {
		gwMAC, _ := net.ParseMAC("00:11:22:33:44:55")
		original := &PrefixRoute{
			Prefix:    netip.MustParsePrefix("192.168.1.0/24"),
			VNI:       100,
			GatewayIP: netip.MustParseAddr("192.168.1.1"),
			NextHop:   netip.MustParseAddr("10.0.0.1"),
			RouteTargets: []RouteTarget{
				{Type: 0, GlobalAdmin: 65000, LocalAdmin: 100},
			},
			GatewayMAC: gwMAC,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		}

		clone := original.Clone()
		assert.NotNil(t, clone)
		assert.Equal(t, original.Prefix, clone.Prefix)
		assert.Equal(t, original.VNI, clone.VNI)
		assert.Len(t, clone.RouteTargets, 1)

		// Verify deep copy of RouteTargets
		clone.RouteTargets[0].LocalAdmin = 999
		assert.NotEqual(t, original.RouteTargets[0].LocalAdmin, clone.RouteTargets[0].LocalAdmin)

		// Verify deep copy of GatewayMAC
		clone.GatewayMAC[0] = 0xFF
		assert.NotEqual(t, original.GatewayMAC[0], clone.GatewayMAC[0])
	})

	t.Run("Clone nil", func(t *testing.T) {
		var route *PrefixRoute
		assert.Nil(t, route.Clone())
	})
}

func TestEVPNRouteData(t *testing.T) {
	t.Run("Clone", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		original := &EVPNRouteData{
			Type: EVPNTypeMACIPAdvertisement,
			RD: RouteDistinguisher{
				Type:           0,
				Administrator:  65000,
				AssignedNumber: 1,
			},
			RouteTargets: []RouteTarget{
				{Type: 0, GlobalAdmin: 65000, LocalAdmin: 100},
			},
			MACIP: &MACIPEntry{
				MAC: mac,
				VNI: 100,
			},
			NextHop:    netip.MustParseAddr("10.0.0.1"),
			Label:      100,
			IsWithdraw: false,
			ReceivedAt: time.Now(),
		}

		clone := original.Clone()
		assert.NotNil(t, clone)
		assert.Equal(t, original.Type, clone.Type)
		assert.NotNil(t, clone.MACIP)
		assert.Len(t, clone.RouteTargets, 1)
	})

	t.Run("Clone nil", func(t *testing.T) {
		var route *EVPNRouteData
		assert.Nil(t, route.Clone())
	})
}

func TestMACMobilityEntry(t *testing.T) {
	t.Run("Key", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		entry := &MACMobilityEntry{
			VNI: 100,
			MAC: mac,
		}
		key := entry.Key()
		assert.Equal(t, "100:00:11:22:33:44:55", key)
	})

	t.Run("Key nil entry", func(t *testing.T) {
		var entry *MACMobilityEntry
		assert.Equal(t, "", entry.Key())
	})
}

// --- Validation Tests ---

func TestValidateVNI(t *testing.T) {
	t.Run("valid VNI", func(t *testing.T) {
		assert.NoError(t, validateVNI(1))
		assert.NoError(t, validateVNI(100))
		assert.NoError(t, validateVNI(16777215))
	})

	t.Run("invalid VNI zero", func(t *testing.T) {
		err := validateVNI(0)
		assert.Error(t, err)
		assert.IsType(t, ErrInvalidVNI{}, err)
	})

	t.Run("invalid VNI too large", func(t *testing.T) {
		err := validateVNI(16777216)
		assert.Error(t, err)
		assert.IsType(t, ErrInvalidVNI{}, err)
	})
}

func TestValidateMAC(t *testing.T) {
	t.Run("valid MAC", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		assert.NoError(t, validateMAC(mac))
	})

	t.Run("nil MAC", func(t *testing.T) {
		err := validateMAC(nil)
		assert.Error(t, err)
		assert.IsType(t, ErrInvalidMAC{}, err)
	})

	t.Run("short MAC", func(t *testing.T) {
		mac := net.HardwareAddr{0x00, 0x11, 0x22}
		err := validateMAC(mac)
		assert.Error(t, err)
		assert.IsType(t, ErrInvalidMAC{}, err)
	})
}

// --- Helper Function Tests ---

func TestFormatKey(t *testing.T) {
	t.Run("format key", func(t *testing.T) {
		key := formatKey(100, "test")
		assert.Equal(t, "100:test", key)
	})

	t.Run("format key zero VNI", func(t *testing.T) {
		key := formatKey(0, "test")
		assert.Equal(t, "0:test", key)
	})
}

func TestFormatKeyThree(t *testing.T) {
	t.Run("format key three", func(t *testing.T) {
		key := formatKeyThree(100, "a", "b")
		assert.Equal(t, "100:a:b", key)
	})
}

func TestFormatUint32(t *testing.T) {
	t.Run("zero", func(t *testing.T) {
		assert.Equal(t, "0", formatUint32(0))
	})

	t.Run("positive", func(t *testing.T) {
		assert.Equal(t, "123", formatUint32(123))
	})

	t.Run("large number", func(t *testing.T) {
		assert.Equal(t, "4294967295", formatUint32(4294967295))
	})
}
