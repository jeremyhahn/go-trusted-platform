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
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTunnelOperations(t *testing.T) (*TunnelOperations, *VTEPManager, *mockOVSClient) {
	client := newMockOVSClient()
	logger := testLogger()
	manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
	require.NoError(t, err)
	err = manager.Start(context.Background())
	require.NoError(t, err)

	ops, err := NewTunnelOperations(manager, logger)
	require.NoError(t, err)

	return ops, manager, client
}

func TestNewTunnelOperations(t *testing.T) {
	t.Run("creates operations with valid manager", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)

		ops, err := NewTunnelOperations(manager, logger)

		require.NoError(t, err)
		require.NotNil(t, ops)
	})

	t.Run("returns error for nil manager", func(t *testing.T) {
		logger := testLogger()

		_, err := NewTunnelOperations(nil, logger)

		assert.ErrorIs(t, err, ErrVTEPNotConfigured)
	})

	t.Run("returns error for nil logger", func(t *testing.T) {
		client := newMockOVSClient()
		logger := testLogger()
		manager, err := NewVTEPManager(validVTEPConfig(), client, "br-int", logger)
		require.NoError(t, err)

		_, err = NewTunnelOperations(manager, nil)

		assert.ErrorIs(t, err, ErrLoggerNil)
	})
}

func TestTunnelOperations_CreateTunnel(t *testing.T) {
	t.Run("creates tunnel successfully", func(t *testing.T) {
		ops, _, _ := setupTunnelOperations(t)

		tunnel, err := ops.CreateTunnel(context.Background(), netip.MustParseAddr("10.0.0.2"), 1000100)

		require.NoError(t, err)
		require.NotNil(t, tunnel)
		assert.Equal(t, TunnelStatusUp, tunnel.State)
	})

	t.Run("returns error for invalid VTEP", func(t *testing.T) {
		ops, _, _ := setupTunnelOperations(t)

		_, err := ops.CreateTunnel(context.Background(), netip.Addr{}, 1000100)

		assert.ErrorIs(t, err, ErrInvalidVTEPIP)
	})

	t.Run("returns error for zero VTEP", func(t *testing.T) {
		ops, _, _ := setupTunnelOperations(t)

		_, err := ops.CreateTunnel(context.Background(), netip.MustParseAddr("0.0.0.0"), 1000100)

		assert.ErrorIs(t, err, ErrInvalidVTEPIP)
	})

	t.Run("returns error for invalid VNI", func(t *testing.T) {
		ops, _, _ := setupTunnelOperations(t)

		_, err := ops.CreateTunnel(context.Background(), netip.MustParseAddr("10.0.0.2"), 0)

		assert.ErrorIs(t, err, ErrVNIOutOfRange)
	})
}

func TestTunnelOperations_DestroyTunnel(t *testing.T) {
	t.Run("destroys tunnel by ID successfully", func(t *testing.T) {
		ops, _, _ := setupTunnelOperations(t)

		tunnel, err := ops.CreateTunnel(context.Background(), netip.MustParseAddr("10.0.0.2"), 1000100)
		require.NoError(t, err)

		err = ops.DestroyTunnel(context.Background(), tunnel.ID)

		require.NoError(t, err)
		assert.Equal(t, 0, ops.TunnelCount())
	})

	t.Run("returns error for empty tunnel ID", func(t *testing.T) {
		ops, _, _ := setupTunnelOperations(t)

		err := ops.DestroyTunnel(context.Background(), "")

		assert.ErrorIs(t, err, ErrInvalidTunnelID)
	})

	t.Run("returns error when tunnel not found", func(t *testing.T) {
		ops, _, _ := setupTunnelOperations(t)

		err := ops.DestroyTunnel(context.Background(), "nonexistent")

		assert.ErrorIs(t, err, ErrTunnelNotFound)
	})
}

func TestTunnelOperations_DestroyTunnelByVTEP(t *testing.T) {
	t.Run("destroys tunnel by VTEP and VNI", func(t *testing.T) {
		ops, _, _ := setupTunnelOperations(t)

		remoteVTEP := netip.MustParseAddr("10.0.0.2")
		vni := VNI(1000100)

		_, err := ops.CreateTunnel(context.Background(), remoteVTEP, vni)
		require.NoError(t, err)

		err = ops.DestroyTunnelByVTEP(context.Background(), remoteVTEP, vni)

		require.NoError(t, err)
		assert.Equal(t, 0, ops.TunnelCount())
	})
}

func TestTunnelOperations_GetTunnelStats(t *testing.T) {
	t.Run("returns stats for existing tunnel", func(t *testing.T) {
		ops, manager, _ := setupTunnelOperations(t)

		remoteVTEP := netip.MustParseAddr("10.0.0.2")
		vni := VNI(1000100)

		tunnel, err := ops.CreateTunnel(context.Background(), remoteVTEP, vni)
		require.NoError(t, err)

		err = manager.UpdateTunnelStats(remoteVTEP, vni, 1000, 2000)
		require.NoError(t, err)

		stats, err := ops.GetTunnelStats(context.Background(), tunnel.ID)

		require.NoError(t, err)
		assert.Equal(t, uint64(1000), stats.BytesSent)
		assert.Equal(t, uint64(2000), stats.BytesRecv)
	})

	t.Run("returns error for empty tunnel ID", func(t *testing.T) {
		ops, _, _ := setupTunnelOperations(t)

		_, err := ops.GetTunnelStats(context.Background(), "")

		assert.ErrorIs(t, err, ErrInvalidTunnelID)
	})

	t.Run("returns error when tunnel not found", func(t *testing.T) {
		ops, _, _ := setupTunnelOperations(t)

		_, err := ops.GetTunnelStats(context.Background(), "nonexistent")

		assert.ErrorIs(t, err, ErrTunnelNotFound)
	})
}

func TestTunnelOperations_HealthCheck(t *testing.T) {
	t.Run("returns true for healthy tunnel", func(t *testing.T) {
		ops, _, _ := setupTunnelOperations(t)

		tunnel, err := ops.CreateTunnel(context.Background(), netip.MustParseAddr("10.0.0.2"), 1000100)
		require.NoError(t, err)

		healthy, err := ops.HealthCheck(context.Background(), tunnel.ID)

		require.NoError(t, err)
		assert.True(t, healthy)
	})

	t.Run("returns false for down tunnel", func(t *testing.T) {
		ops, manager, _ := setupTunnelOperations(t)

		remoteVTEP := netip.MustParseAddr("10.0.0.2")
		vni := VNI(1000100)

		tunnel, err := ops.CreateTunnel(context.Background(), remoteVTEP, vni)
		require.NoError(t, err)

		err = manager.UpdateTunnelState(remoteVTEP, vni, TunnelStatusDown)
		require.NoError(t, err)

		healthy, err := ops.HealthCheck(context.Background(), tunnel.ID)

		require.NoError(t, err)
		assert.False(t, healthy)
	})

	t.Run("returns error for empty tunnel ID", func(t *testing.T) {
		ops, _, _ := setupTunnelOperations(t)

		_, err := ops.HealthCheck(context.Background(), "")

		assert.ErrorIs(t, err, ErrInvalidTunnelID)
	})
}

func TestTunnelOperations_ListAllTunnels(t *testing.T) {
	t.Run("returns all tunnels", func(t *testing.T) {
		ops, _, _ := setupTunnelOperations(t)

		_, err := ops.CreateTunnel(context.Background(), netip.MustParseAddr("10.0.0.2"), 1000100)
		require.NoError(t, err)
		_, err = ops.CreateTunnel(context.Background(), netip.MustParseAddr("10.0.0.3"), 1000100)
		require.NoError(t, err)

		tunnels := ops.ListAllTunnels()

		assert.Len(t, tunnels, 2)
	})

	t.Run("returns empty list when no tunnels", func(t *testing.T) {
		ops, _, _ := setupTunnelOperations(t)

		tunnels := ops.ListAllTunnels()

		assert.Empty(t, tunnels)
	})
}

func TestTunnelOperations_ListTunnelsByVNI(t *testing.T) {
	t.Run("returns tunnels for specific VNI", func(t *testing.T) {
		ops, _, _ := setupTunnelOperations(t)

		_, err := ops.CreateTunnel(context.Background(), netip.MustParseAddr("10.0.0.2"), 1000100)
		require.NoError(t, err)
		_, err = ops.CreateTunnel(context.Background(), netip.MustParseAddr("10.0.0.3"), 1000100)
		require.NoError(t, err)
		_, err = ops.CreateTunnel(context.Background(), netip.MustParseAddr("10.0.0.4"), 1000200)
		require.NoError(t, err)

		tunnels := ops.ListTunnelsByVNI(1000100)

		assert.Len(t, tunnels, 2)
	})

	t.Run("returns empty list for non-existent VNI", func(t *testing.T) {
		ops, _, _ := setupTunnelOperations(t)

		tunnels := ops.ListTunnelsByVNI(9999999)

		assert.Empty(t, tunnels)
	})
}

func TestTunnelOperations_ListTunnelsByRemoteVTEP(t *testing.T) {
	t.Run("returns tunnels for specific remote VTEP", func(t *testing.T) {
		ops, _, _ := setupTunnelOperations(t)

		remoteVTEP := netip.MustParseAddr("10.0.0.2")

		_, err := ops.CreateTunnel(context.Background(), remoteVTEP, 1000100)
		require.NoError(t, err)
		_, err = ops.CreateTunnel(context.Background(), remoteVTEP, 1000200)
		require.NoError(t, err)
		_, err = ops.CreateTunnel(context.Background(), netip.MustParseAddr("10.0.0.3"), 1000100)
		require.NoError(t, err)

		tunnels := ops.ListTunnelsByRemoteVTEP(remoteVTEP)

		assert.Len(t, tunnels, 2)
	})

	t.Run("returns empty list for non-existent VTEP", func(t *testing.T) {
		ops, _, _ := setupTunnelOperations(t)

		tunnels := ops.ListTunnelsByRemoteVTEP(netip.MustParseAddr("192.168.1.1"))

		assert.Empty(t, tunnels)
	})
}

func TestTunnelOperations_GetTunnel(t *testing.T) {
	t.Run("returns tunnel by VTEP and VNI", func(t *testing.T) {
		ops, _, _ := setupTunnelOperations(t)

		remoteVTEP := netip.MustParseAddr("10.0.0.2")
		vni := VNI(1000100)

		created, err := ops.CreateTunnel(context.Background(), remoteVTEP, vni)
		require.NoError(t, err)

		tunnel, err := ops.GetTunnel(remoteVTEP, vni)

		require.NoError(t, err)
		assert.Equal(t, created.ID, tunnel.ID)
	})
}

func TestTunnelOperations_GetTunnelByID(t *testing.T) {
	t.Run("returns tunnel by ID", func(t *testing.T) {
		ops, _, _ := setupTunnelOperations(t)

		created, err := ops.CreateTunnel(context.Background(), netip.MustParseAddr("10.0.0.2"), 1000100)
		require.NoError(t, err)

		tunnel, err := ops.GetTunnelByID(created.ID)

		require.NoError(t, err)
		assert.Equal(t, created.ID, tunnel.ID)
	})

	t.Run("returns error for empty ID", func(t *testing.T) {
		ops, _, _ := setupTunnelOperations(t)

		_, err := ops.GetTunnelByID("")

		assert.ErrorIs(t, err, ErrInvalidTunnelID)
	})
}

func TestTunnelOperations_SetTunnelState(t *testing.T) {
	t.Run("sets tunnel state successfully", func(t *testing.T) {
		ops, _, _ := setupTunnelOperations(t)

		remoteVTEP := netip.MustParseAddr("10.0.0.2")
		vni := VNI(1000100)

		_, err := ops.CreateTunnel(context.Background(), remoteVTEP, vni)
		require.NoError(t, err)

		err = ops.SetTunnelState(remoteVTEP, vni, TunnelStatusError)

		require.NoError(t, err)
		tunnel, err := ops.GetTunnel(remoteVTEP, vni)
		require.NoError(t, err)
		assert.Equal(t, TunnelStatusError, tunnel.State)
	})
}

func TestTunnelOperations_GetLocalVTEP(t *testing.T) {
	ops, _, _ := setupTunnelOperations(t)

	localVTEP := ops.GetLocalVTEP()

	assert.Equal(t, validVTEPConfig().LocalIP, localVTEP)
}

func TestTunnelOperations_TunnelCount(t *testing.T) {
	ops, _, _ := setupTunnelOperations(t)

	assert.Equal(t, 0, ops.TunnelCount())

	_, err := ops.CreateTunnel(context.Background(), netip.MustParseAddr("10.0.0.2"), 1000100)
	require.NoError(t, err)

	assert.Equal(t, 1, ops.TunnelCount())
}

func TestTunnelOperations_TunnelCountByStatus(t *testing.T) {
	t.Run("returns counts by status", func(t *testing.T) {
		ops, manager, _ := setupTunnelOperations(t)

		// Create tunnels with different states
		_, err := ops.CreateTunnel(context.Background(), netip.MustParseAddr("10.0.0.2"), 1000100)
		require.NoError(t, err)
		_, err = ops.CreateTunnel(context.Background(), netip.MustParseAddr("10.0.0.3"), 1000100)
		require.NoError(t, err)
		_, err = ops.CreateTunnel(context.Background(), netip.MustParseAddr("10.0.0.4"), 1000100)
		require.NoError(t, err)

		err = manager.UpdateTunnelState(netip.MustParseAddr("10.0.0.3"), 1000100, TunnelStatusDown)
		require.NoError(t, err)
		err = manager.UpdateTunnelState(netip.MustParseAddr("10.0.0.4"), 1000100, TunnelStatusError)
		require.NoError(t, err)

		counts := ops.TunnelCountByStatus()

		assert.Equal(t, 1, counts[TunnelStatusUp])
		assert.Equal(t, 1, counts[TunnelStatusDown])
		assert.Equal(t, 1, counts[TunnelStatusError])
		assert.Equal(t, 0, counts[TunnelStatusUnknown])
	})
}

func TestTunnelOperations_GetHealthyTunnels(t *testing.T) {
	ops, manager, _ := setupTunnelOperations(t)

	_, err := ops.CreateTunnel(context.Background(), netip.MustParseAddr("10.0.0.2"), 1000100)
	require.NoError(t, err)
	_, err = ops.CreateTunnel(context.Background(), netip.MustParseAddr("10.0.0.3"), 1000100)
	require.NoError(t, err)

	err = manager.UpdateTunnelState(netip.MustParseAddr("10.0.0.3"), 1000100, TunnelStatusDown)
	require.NoError(t, err)

	healthy := ops.GetHealthyTunnels()

	assert.Len(t, healthy, 1)
	assert.Equal(t, TunnelStatusUp, healthy[0].State)
}

func TestTunnelOperations_GetUnhealthyTunnels(t *testing.T) {
	ops, manager, _ := setupTunnelOperations(t)

	_, err := ops.CreateTunnel(context.Background(), netip.MustParseAddr("10.0.0.2"), 1000100)
	require.NoError(t, err)
	_, err = ops.CreateTunnel(context.Background(), netip.MustParseAddr("10.0.0.3"), 1000100)
	require.NoError(t, err)

	err = manager.UpdateTunnelState(netip.MustParseAddr("10.0.0.3"), 1000100, TunnelStatusDown)
	require.NoError(t, err)

	unhealthy := ops.GetUnhealthyTunnels()

	assert.Len(t, unhealthy, 1)
	assert.Equal(t, TunnelStatusDown, unhealthy[0].State)
}

func TestTunnelOperations_GetStaleTunnels(t *testing.T) {
	ops, _, _ := setupTunnelOperations(t)

	_, err := ops.CreateTunnel(context.Background(), netip.MustParseAddr("10.0.0.2"), 1000100)
	require.NoError(t, err)

	// With a very short threshold, tunnel should be stale
	stale := ops.GetStaleTunnels(0)
	assert.Len(t, stale, 1)

	// With a long threshold, no tunnels should be stale
	stale = ops.GetStaleTunnels(time.Hour)
	assert.Empty(t, stale)
}

func TestTunnelOperations_EnsureTunnel(t *testing.T) {
	t.Run("creates tunnel if not exists", func(t *testing.T) {
		ops, _, _ := setupTunnelOperations(t)

		remoteVTEP := netip.MustParseAddr("10.0.0.2")
		vni := VNI(1000100)

		tunnel, err := ops.EnsureTunnel(context.Background(), remoteVTEP, vni)

		require.NoError(t, err)
		require.NotNil(t, tunnel)
		assert.Equal(t, 1, ops.TunnelCount())
	})

	t.Run("returns existing tunnel", func(t *testing.T) {
		ops, _, _ := setupTunnelOperations(t)

		remoteVTEP := netip.MustParseAddr("10.0.0.2")
		vni := VNI(1000100)

		created, err := ops.CreateTunnel(context.Background(), remoteVTEP, vni)
		require.NoError(t, err)

		tunnel, err := ops.EnsureTunnel(context.Background(), remoteVTEP, vni)

		require.NoError(t, err)
		assert.Equal(t, created.ID, tunnel.ID)
		assert.Equal(t, 1, ops.TunnelCount())
	})
}

func TestTunnelOperations_RemoveAllTunnels(t *testing.T) {
	ops, _, _ := setupTunnelOperations(t)

	_, err := ops.CreateTunnel(context.Background(), netip.MustParseAddr("10.0.0.2"), 1000100)
	require.NoError(t, err)
	_, err = ops.CreateTunnel(context.Background(), netip.MustParseAddr("10.0.0.3"), 1000100)
	require.NoError(t, err)

	err = ops.RemoveAllTunnels(context.Background())

	require.NoError(t, err)
	assert.Equal(t, 0, ops.TunnelCount())
}

func TestTunnelOperations_RemoveTunnelsByVNI(t *testing.T) {
	ops, _, _ := setupTunnelOperations(t)

	_, err := ops.CreateTunnel(context.Background(), netip.MustParseAddr("10.0.0.2"), 1000100)
	require.NoError(t, err)
	_, err = ops.CreateTunnel(context.Background(), netip.MustParseAddr("10.0.0.3"), 1000100)
	require.NoError(t, err)
	_, err = ops.CreateTunnel(context.Background(), netip.MustParseAddr("10.0.0.4"), 1000200)
	require.NoError(t, err)

	err = ops.RemoveTunnelsByVNI(context.Background(), 1000100)

	require.NoError(t, err)
	assert.Equal(t, 1, ops.TunnelCount())
	tunnels := ops.ListTunnelsByVNI(1000100)
	assert.Empty(t, tunnels)
}

func TestTunnelOperations_RemoveTunnelsByRemoteVTEP(t *testing.T) {
	ops, _, _ := setupTunnelOperations(t)

	remoteVTEP := netip.MustParseAddr("10.0.0.2")

	_, err := ops.CreateTunnel(context.Background(), remoteVTEP, 1000100)
	require.NoError(t, err)
	_, err = ops.CreateTunnel(context.Background(), remoteVTEP, 1000200)
	require.NoError(t, err)
	_, err = ops.CreateTunnel(context.Background(), netip.MustParseAddr("10.0.0.3"), 1000100)
	require.NoError(t, err)

	err = ops.RemoveTunnelsByRemoteVTEP(context.Background(), remoteVTEP)

	require.NoError(t, err)
	assert.Equal(t, 1, ops.TunnelCount())
	tunnels := ops.ListTunnelsByRemoteVTEP(remoteVTEP)
	assert.Empty(t, tunnels)
}
