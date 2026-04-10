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

package vxlan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockOVSClient implements OVSClient for testing
type mockOVSClient struct {
	mu            sync.Mutex
	connected     bool
	ports         map[string]*mockPort
	addPortErr    error
	deletePortErr error
	getOFPortErr  error
	nextOFPort    int32
}

type mockPort struct {
	bridge   string
	name     string
	remoteIP string
	vni      uint32
	dstPort  uint16
	ofPort   int32
}

func newMockOVSClient() *mockOVSClient {
	return &mockOVSClient{
		connected:  true,
		ports:      make(map[string]*mockPort),
		nextOFPort: 1,
	}
}

func (m *mockOVSClient) AddVXLANPort(ctx context.Context, bridge, port string, remoteIP string, vni uint32, dstPort uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.addPortErr != nil {
		return m.addPortErr
	}

	m.ports[port] = &mockPort{
		bridge:   bridge,
		name:     port,
		remoteIP: remoteIP,
		vni:      vni,
		dstPort:  dstPort,
		ofPort:   m.nextOFPort,
	}
	m.nextOFPort++

	return nil
}

func (m *mockOVSClient) DeletePort(ctx context.Context, bridge, port string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.deletePortErr != nil {
		return m.deletePortErr
	}

	delete(m.ports, port)
	return nil
}

func (m *mockOVSClient) GetOFPort(ctx context.Context, portName string) (int32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.getOFPortErr != nil {
		return 0, m.getOFPortErr
	}

	port, ok := m.ports[portName]
	if !ok {
		return 0, errors.New("port not found")
	}

	return port.ofPort, nil
}

func (m *mockOVSClient) IsConnected() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.connected
}

func (m *mockOVSClient) setConnected(connected bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connected = connected
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func validVTEPConfig() VTEPConfig {
	return VTEPConfig{
		LocalIP:       netip.MustParseAddr("10.0.0.1"),
		UnderlayIface: "eth0",
		UnderlayMTU:   9000,
		VXLANPort:     DefaultVXLANPort,
	}
}

func TestNewVTEPManager(t *testing.T) {
	t.Run("creates manager with valid config", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()

		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)

		require.NoError(t, err)
		require.NotNil(t, manager)
		assert.False(t, manager.IsStarted())
	})

	t.Run("returns error for invalid config - bad IP", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()
		config := VTEPConfig{
			LocalIP:       netip.Addr{},
			UnderlayIface: "eth0",
			UnderlayMTU:   9000,
			VXLANPort:     DefaultVXLANPort,
		}

		_, err := NewVTEPManager(config, client, "br-int", logger)

		require.Error(t, err)
		var validationErr *ErrVTEPValidationFailed
		assert.True(t, errors.As(err, &validationErr))
	})

	t.Run("returns error for nil OVS client", func(t *testing.T) {
		logger := testLogger()

		_, err := NewVTEPManager(validVTEPConfig(), nil, "br-int", logger)

		assert.ErrorIs(t, err, ErrOVSClientNil)
	})

	t.Run("returns error for empty bridge name", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()

		_, err := NewVTEPManager(validVTEPConfig(), client, "", logger)

		assert.ErrorIs(t, err, ErrBridgeNameEmpty)
	})

	t.Run("returns error for nil logger", func(t *testing.T) {
		client := newMockOVSClient()

		_, err := NewVTEPManager(validVTEPConfig(), client, "br-int", nil)

		assert.ErrorIs(t, err, ErrLoggerNil)
	})
}

func TestVTEPManager_Start(t *testing.T) {
	t.Run("starts successfully when OVS is connected", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)

		err = manager.Start(context.Background())

		require.NoError(t, err)
		assert.True(t, manager.IsStarted())
	})

	t.Run("returns error when already started", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)
		err = manager.Start(context.Background())
		require.NoError(t, err)

		err = manager.Start(context.Background())

		assert.ErrorIs(t, err, ErrManagerAlreadyStarted)
	})

	t.Run("returns error when OVS not connected", func(t *testing.T) {
		client := newMockOVSClient()
		client.setConnected(false)
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)

		err = manager.Start(context.Background())

		require.Error(t, err)
		var ovsErr *ErrOVSOperationFailed
		assert.True(t, errors.As(err, &ovsErr))
	})
}

func TestVTEPManager_Stop(t *testing.T) {
	t.Run("stops successfully and removes tunnels", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)
		err = manager.Start(context.Background())
		require.NoError(t, err)

		// Add a tunnel
		_, err = manager.AddTunnel(context.Background(), netip.MustParseAddr("10.0.0.2"), 1000100)
		require.NoError(t, err)

		err = manager.Stop()

		require.NoError(t, err)
		assert.False(t, manager.IsStarted())
		assert.Equal(t, 0, manager.TunnelCount())
	})

	t.Run("returns nil when not started", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)

		err = manager.Stop()

		assert.NoError(t, err)
	})
}

func TestVTEPManager_AddTunnel(t *testing.T) {
	t.Run("creates tunnel successfully", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)
		err = manager.Start(context.Background())
		require.NoError(t, err)

		remoteVTEP := netip.MustParseAddr("10.0.0.2")
		vni := VNI(1000100)

		tunnel, err := manager.AddTunnel(context.Background(), remoteVTEP, vni)

		require.NoError(t, err)
		require.NotNil(t, tunnel)
		assert.Equal(t, remoteVTEP, tunnel.RemoteVTEP)
		assert.Equal(t, vni, tunnel.VNI)
		assert.Equal(t, TunnelStatusUp, tunnel.State)
		assert.NotEmpty(t, tunnel.OVSPort)
		assert.Greater(t, tunnel.OFPort, int32(0))
	})

	t.Run("returns error when not started", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)

		_, err = manager.AddTunnel(context.Background(), netip.MustParseAddr("10.0.0.2"), 1000100)

		assert.ErrorIs(t, err, ErrManagerNotStarted)
	})

	t.Run("returns error for invalid remote VTEP", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)
		err = manager.Start(context.Background())
		require.NoError(t, err)

		_, err = manager.AddTunnel(context.Background(), netip.Addr{}, 1000100)

		assert.ErrorIs(t, err, ErrInvalidVTEPIP)
	})

	t.Run("returns error for zero VTEP", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)
		err = manager.Start(context.Background())
		require.NoError(t, err)

		_, err = manager.AddTunnel(context.Background(), netip.MustParseAddr("0.0.0.0"), 1000100)

		assert.ErrorIs(t, err, ErrInvalidVTEPIP)
	})

	t.Run("returns error for invalid VNI", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)
		err = manager.Start(context.Background())
		require.NoError(t, err)

		_, err = manager.AddTunnel(context.Background(), netip.MustParseAddr("10.0.0.2"), 0)

		assert.ErrorIs(t, err, ErrVNIOutOfRange)
	})

	t.Run("returns error when tunnel already exists", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)
		err = manager.Start(context.Background())
		require.NoError(t, err)

		remoteVTEP := netip.MustParseAddr("10.0.0.2")
		vni := VNI(1000100)

		_, err = manager.AddTunnel(context.Background(), remoteVTEP, vni)
		require.NoError(t, err)

		_, err = manager.AddTunnel(context.Background(), remoteVTEP, vni)

		assert.ErrorIs(t, err, ErrTunnelExists)
	})

	t.Run("returns error when OVS add port fails", func(t *testing.T) {
		client := newMockOVSClient()
		client.addPortErr = errors.New("OVS error")
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)
		err = manager.Start(context.Background())
		require.NoError(t, err)

		_, err = manager.AddTunnel(context.Background(), netip.MustParseAddr("10.0.0.2"), 1000100)

		require.Error(t, err)
		var tunnelErr *ErrTunnelCreationFailed
		assert.True(t, errors.As(err, &tunnelErr))
	})

	t.Run("cleans up on GetOFPort failure", func(t *testing.T) {
		client := newMockOVSClient()
		client.getOFPortErr = errors.New("OFPort error")
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)
		err = manager.Start(context.Background())
		require.NoError(t, err)

		_, err = manager.AddTunnel(context.Background(), netip.MustParseAddr("10.0.0.2"), 1000100)

		require.Error(t, err)
		assert.Equal(t, 0, len(client.ports)) // Port should be cleaned up
	})
}

func TestVTEPManager_RemoveTunnel(t *testing.T) {
	t.Run("removes tunnel successfully", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)
		err = manager.Start(context.Background())
		require.NoError(t, err)

		remoteVTEP := netip.MustParseAddr("10.0.0.2")
		vni := VNI(1000100)

		_, err = manager.AddTunnel(context.Background(), remoteVTEP, vni)
		require.NoError(t, err)

		err = manager.RemoveTunnel(context.Background(), remoteVTEP, vni)

		require.NoError(t, err)
		assert.Equal(t, 0, manager.TunnelCount())
	})

	t.Run("returns error when not started", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)

		err = manager.RemoveTunnel(context.Background(), netip.MustParseAddr("10.0.0.2"), 1000100)

		assert.ErrorIs(t, err, ErrManagerNotStarted)
	})

	t.Run("returns error when tunnel not found", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)
		err = manager.Start(context.Background())
		require.NoError(t, err)

		err = manager.RemoveTunnel(context.Background(), netip.MustParseAddr("10.0.0.2"), 1000100)

		assert.ErrorIs(t, err, ErrTunnelNotFound)
	})

	t.Run("returns error when OVS delete fails", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)
		err = manager.Start(context.Background())
		require.NoError(t, err)

		remoteVTEP := netip.MustParseAddr("10.0.0.2")
		vni := VNI(1000100)

		_, err = manager.AddTunnel(context.Background(), remoteVTEP, vni)
		require.NoError(t, err)

		client.deletePortErr = errors.New("delete error")

		err = manager.RemoveTunnel(context.Background(), remoteVTEP, vni)

		require.Error(t, err)
		var tunnelErr *ErrTunnelDeletionFailed
		assert.True(t, errors.As(err, &tunnelErr))
	})
}

func TestVTEPManager_GetTunnel(t *testing.T) {
	t.Run("returns tunnel when found", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)
		err = manager.Start(context.Background())
		require.NoError(t, err)

		remoteVTEP := netip.MustParseAddr("10.0.0.2")
		vni := VNI(1000100)

		created, err := manager.AddTunnel(context.Background(), remoteVTEP, vni)
		require.NoError(t, err)

		tunnel, err := manager.GetTunnel(remoteVTEP, vni)

		require.NoError(t, err)
		assert.Equal(t, created.ID, tunnel.ID)
	})

	t.Run("returns error when not started", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)

		_, err = manager.GetTunnel(netip.MustParseAddr("10.0.0.2"), 1000100)

		assert.ErrorIs(t, err, ErrManagerNotStarted)
	})

	t.Run("returns error when tunnel not found", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)
		err = manager.Start(context.Background())
		require.NoError(t, err)

		_, err = manager.GetTunnel(netip.MustParseAddr("10.0.0.2"), 1000100)

		assert.ErrorIs(t, err, ErrTunnelNotFound)
	})

	t.Run("returns a copy of tunnel", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)
		err = manager.Start(context.Background())
		require.NoError(t, err)

		remoteVTEP := netip.MustParseAddr("10.0.0.2")
		vni := VNI(1000100)

		_, err = manager.AddTunnel(context.Background(), remoteVTEP, vni)
		require.NoError(t, err)

		tunnel, err := manager.GetTunnel(remoteVTEP, vni)
		require.NoError(t, err)
		tunnel.State = TunnelStatusDown // Modify copy

		// Original should be unchanged
		original, err := manager.GetTunnel(remoteVTEP, vni)
		require.NoError(t, err)
		assert.Equal(t, TunnelStatusUp, original.State)
	})
}

func TestVTEPManager_GetTunnelByID(t *testing.T) {
	t.Run("returns tunnel when found", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)
		err = manager.Start(context.Background())
		require.NoError(t, err)

		created, err := manager.AddTunnel(context.Background(), netip.MustParseAddr("10.0.0.2"), 1000100)
		require.NoError(t, err)

		tunnel, err := manager.GetTunnelByID(created.ID)

		require.NoError(t, err)
		assert.Equal(t, created.ID, tunnel.ID)
	})

	t.Run("returns error for empty tunnel ID", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)
		err = manager.Start(context.Background())
		require.NoError(t, err)

		_, err = manager.GetTunnelByID("")

		assert.ErrorIs(t, err, ErrInvalidTunnelID)
	})

	t.Run("returns error when tunnel not found", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)
		err = manager.Start(context.Background())
		require.NoError(t, err)

		_, err = manager.GetTunnelByID("nonexistent")

		assert.ErrorIs(t, err, ErrTunnelNotFound)
	})
}

func TestVTEPManager_ListTunnels(t *testing.T) {
	t.Run("returns empty list when no tunnels", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)

		tunnels := manager.ListTunnels()

		assert.Empty(t, tunnels)
	})

	t.Run("returns all tunnels", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)
		err = manager.Start(context.Background())
		require.NoError(t, err)

		_, err = manager.AddTunnel(context.Background(), netip.MustParseAddr("10.0.0.2"), 1000100)
		require.NoError(t, err)
		_, err = manager.AddTunnel(context.Background(), netip.MustParseAddr("10.0.0.3"), 1000100)
		require.NoError(t, err)

		tunnels := manager.ListTunnels()

		assert.Len(t, tunnels, 2)
	})
}

func TestVTEPManager_GetLocalVTEP(t *testing.T) {
	client := newMockOVSClient()
	logger := testLogger()
	config := validVTEPConfig()
	manager, err := NewVTEPManager(config, client, "br-int", logger)
	require.NoError(t, err)

	localVTEP := manager.GetLocalVTEP()

	assert.Equal(t, config.LocalIP, localVTEP)
}

func TestVTEPManager_GetConfig(t *testing.T) {
	client := newMockOVSClient()
	logger := testLogger()
	config := validVTEPConfig()
	manager, err := NewVTEPManager(config, client, "br-int", logger)
	require.NoError(t, err)

	result := manager.GetConfig()

	assert.Equal(t, config.LocalIP, result.LocalIP)
	assert.Equal(t, config.UnderlayIface, result.UnderlayIface)
	assert.Equal(t, config.UnderlayMTU, result.UnderlayMTU)
	assert.Equal(t, config.VXLANPort, result.VXLANPort)
}

func TestVTEPManager_GetBridgeName(t *testing.T) {
	client := newMockOVSClient()
	logger := testLogger()
	manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
	require.NoError(t, err)

	assert.Equal(t, "br-int", manager.GetBridgeName())
}

func TestVTEPManager_TunnelCount(t *testing.T) {
	client := newMockOVSClient()
	logger := testLogger()
	manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
	require.NoError(t, err)
	err = manager.Start(context.Background())
	require.NoError(t, err)

	assert.Equal(t, 0, manager.TunnelCount())

	_, err = manager.AddTunnel(context.Background(), netip.MustParseAddr("10.0.0.2"), 1000100)
	require.NoError(t, err)

	assert.Equal(t, 1, manager.TunnelCount())
}

func TestVTEPManager_UpdateTunnelState(t *testing.T) {
	t.Run("updates state successfully", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)
		err = manager.Start(context.Background())
		require.NoError(t, err)

		remoteVTEP := netip.MustParseAddr("10.0.0.2")
		vni := VNI(1000100)

		_, err = manager.AddTunnel(context.Background(), remoteVTEP, vni)
		require.NoError(t, err)

		err = manager.UpdateTunnelState(remoteVTEP, vni, TunnelStatusDown)

		require.NoError(t, err)
		tunnel, err := manager.GetTunnel(remoteVTEP, vni)
		require.NoError(t, err)
		assert.Equal(t, TunnelStatusDown, tunnel.State)
	})

	t.Run("returns error when not started", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)

		err = manager.UpdateTunnelState(netip.MustParseAddr("10.0.0.2"), 1000100, TunnelStatusDown)

		assert.ErrorIs(t, err, ErrManagerNotStarted)
	})

	t.Run("returns error when tunnel not found", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)
		err = manager.Start(context.Background())
		require.NoError(t, err)

		err = manager.UpdateTunnelState(netip.MustParseAddr("10.0.0.2"), 1000100, TunnelStatusDown)

		assert.ErrorIs(t, err, ErrTunnelNotFound)
	})
}

func TestVTEPManager_UpdateTunnelStats(t *testing.T) {
	t.Run("updates stats successfully", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)
		err = manager.Start(context.Background())
		require.NoError(t, err)

		remoteVTEP := netip.MustParseAddr("10.0.0.2")
		vni := VNI(1000100)

		_, err = manager.AddTunnel(context.Background(), remoteVTEP, vni)
		require.NoError(t, err)

		err = manager.UpdateTunnelStats(remoteVTEP, vni, 1000, 2000)

		require.NoError(t, err)
		tunnel, err := manager.GetTunnel(remoteVTEP, vni)
		require.NoError(t, err)
		assert.Equal(t, uint64(1000), tunnel.BytesSent)
		assert.Equal(t, uint64(2000), tunnel.BytesRecv)
	})

	t.Run("returns error when not started", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)

		err = manager.UpdateTunnelStats(netip.MustParseAddr("10.0.0.2"), 1000100, 0, 0)

		assert.ErrorIs(t, err, ErrManagerNotStarted)
	})

	t.Run("returns error when tunnel not found", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)
		err = manager.Start(context.Background())
		require.NoError(t, err)

		err = manager.UpdateTunnelStats(netip.MustParseAddr("10.0.0.2"), 1000100, 0, 0)

		assert.ErrorIs(t, err, ErrTunnelNotFound)
	})
}

func TestVTEPManager_GeneratePortName(t *testing.T) {
	client := newMockOVSClient()
	logger := testLogger()
	manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
	require.NoError(t, err)

	t.Run("generates deterministic port names", func(t *testing.T) {
		remoteVTEP := netip.MustParseAddr("10.0.0.2")
		vni := VNI(1000100)

		name1 := manager.generatePortName(remoteVTEP, vni)
		name2 := manager.generatePortName(remoteVTEP, vni)

		assert.Equal(t, name1, name2)
	})

	t.Run("generates different names for different tunnels", func(t *testing.T) {
		name1 := manager.generatePortName(netip.MustParseAddr("10.0.0.2"), 1000100)
		name2 := manager.generatePortName(netip.MustParseAddr("10.0.0.3"), 1000100)
		name3 := manager.generatePortName(netip.MustParseAddr("10.0.0.2"), 1000200)

		assert.NotEqual(t, name1, name2)
		assert.NotEqual(t, name1, name3)
		assert.NotEqual(t, name2, name3)
	})

	t.Run("port names are within OVS limit", func(t *testing.T) {
		name := manager.generatePortName(netip.MustParseAddr("10.0.0.2"), 1000100)

		assert.LessOrEqual(t, len(name), 15)
		assert.True(t, len(name) > 0)
		assert.True(t, len(name) >= 6) // "vxlan-" prefix
	})
}

func TestVTEPManager_Concurrency(t *testing.T) {
	client := newMockOVSClient()
	logger := testLogger()
	manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
	require.NoError(t, err)
	err = manager.Start(context.Background())
	require.NoError(t, err)

	var wg sync.WaitGroup
	numGoroutines := 50

	// Concurrent tunnel additions with properly formatted IPs
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			// Generate valid IP: 10.0.{third octet}.{fourth octet}
			thirdOctet := idx / 254
			fourthOctet := (idx % 254) + 2 // Start from .2 to avoid .0 and .1
			ipStr := fmt.Sprintf("10.0.%d.%d", thirdOctet, fourthOctet)
			remoteIP := netip.MustParseAddr(ipStr)
			_, _ = manager.AddTunnel(context.Background(), remoteIP, VNI(1000100+uint32(idx)))
		}(i)
	}
	wg.Wait()

	// Concurrent reads
	wg.Add(numGoroutines * 2)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			_ = manager.ListTunnels()
		}()
		go func() {
			defer wg.Done()
			_ = manager.TunnelCount()
		}()
	}
	wg.Wait()

	// Concurrent state updates
	tunnels := manager.ListTunnels()
	wg.Add(len(tunnels))
	for _, tunnel := range tunnels {
		go func(t *TunnelState) {
			defer wg.Done()
			_ = manager.UpdateTunnelState(t.RemoteVTEP, t.VNI, TunnelStatusUp)
		}(tunnel)
	}
	wg.Wait()
}

func TestVTEPManager_TunnelTimestamps(t *testing.T) {
	client := newMockOVSClient()
	logger := testLogger()
	manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
	require.NoError(t, err)
	err = manager.Start(context.Background())
	require.NoError(t, err)

	before := time.Now()
	tunnel, err := manager.AddTunnel(context.Background(), netip.MustParseAddr("10.0.0.2"), 1000100)
	require.NoError(t, err)
	after := time.Now()

	assert.True(t, tunnel.CreatedAt.After(before) || tunnel.CreatedAt.Equal(before))
	assert.True(t, tunnel.CreatedAt.Before(after) || tunnel.CreatedAt.Equal(after))
	assert.Equal(t, tunnel.CreatedAt, tunnel.UpdatedAt)
}
