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

package qemu

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newDisconnectedMonitor returns a Monitor that has never connected, so every
// command wrapper takes its not-connected guard.
func newDisconnectedMonitor() *Monitor {
	return NewMonitor("/tmp/does-not-exist.sock", time.Second, nil)
}

func TestBlockStatsNotConnected(t *testing.T) {
	m := newDisconnectedMonitor()
	stats, err := m.BlockStats(context.Background())
	assert.Nil(t, stats)
	require.Error(t, err)
	assert.IsType(t, ErrMonitorNotConnected{}, err)
}

func TestBlockdevAddQcow2(t *testing.T) {
	m := newDisconnectedMonitor()

	t.Run("not connected", func(t *testing.T) {
		err := m.BlockdevAddQcow2(context.Background(), "node0", "/disk.qcow2")
		require.Error(t, err)
		assert.IsType(t, ErrMonitorNotConnected{}, err)
	})

	// Argument validation is reached only once connected; force the connected
	// flag to exercise the validation branch without a real socket.
	m.connected.Store(true)
	t.Cleanup(func() { m.connected.Store(false) })

	t.Run("missing node name", func(t *testing.T) {
		err := m.BlockdevAddQcow2(context.Background(), "", "/disk.qcow2")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "required")
	})

	t.Run("missing filename", func(t *testing.T) {
		err := m.BlockdevAddQcow2(context.Background(), "node0", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "required")
	})
}

func TestBlockdevDel(t *testing.T) {
	m := newDisconnectedMonitor()

	t.Run("not connected", func(t *testing.T) {
		err := m.BlockdevDel(context.Background(), "node0")
		require.Error(t, err)
		assert.IsType(t, ErrMonitorNotConnected{}, err)
	})

	m.connected.Store(true)
	t.Cleanup(func() { m.connected.Store(false) })

	t.Run("missing node name", func(t *testing.T) {
		err := m.BlockdevDel(context.Background(), "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "required")
	})
}

func TestAddVirtioBlkDevice(t *testing.T) {
	m := newDisconnectedMonitor()

	t.Run("not connected", func(t *testing.T) {
		err := m.AddVirtioBlkDevice(context.Background(), "dev0", "node0")
		require.Error(t, err)
		assert.IsType(t, ErrMonitorNotConnected{}, err)
	})

	m.connected.Store(true)
	t.Cleanup(func() { m.connected.Store(false) })

	t.Run("missing ids", func(t *testing.T) {
		err := m.AddVirtioBlkDevice(context.Background(), "", "node0")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "required")

		err = m.AddVirtioBlkDevice(context.Background(), "dev0", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "required")
	})
}

func TestDeviceDel(t *testing.T) {
	m := newDisconnectedMonitor()

	t.Run("not connected", func(t *testing.T) {
		err := m.DeviceDel(context.Background(), "dev0")
		require.Error(t, err)
		assert.IsType(t, ErrMonitorNotConnected{}, err)
	})

	m.connected.Store(true)
	t.Cleanup(func() { m.connected.Store(false) })

	t.Run("missing device id", func(t *testing.T) {
		err := m.DeviceDel(context.Background(), "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "required")
	})
}

func TestBlockResize(t *testing.T) {
	m := newDisconnectedMonitor()

	t.Run("not connected", func(t *testing.T) {
		err := m.BlockResize(context.Background(), "node0", "", 1<<30)
		require.Error(t, err)
		assert.IsType(t, ErrMonitorNotConnected{}, err)
	})

	m.connected.Store(true)
	t.Cleanup(func() { m.connected.Store(false) })

	t.Run("non-positive size", func(t *testing.T) {
		err := m.BlockResize(context.Background(), "node0", "", 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "greater than zero")
	})

	t.Run("missing target", func(t *testing.T) {
		err := m.BlockResize(context.Background(), "", "", 1<<30)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "required")
	})
}

func TestBlockStatTypes(t *testing.T) {
	s := BlockStat{
		Device:   "",
		NodeName: "node0",
		Stats: BlockStatCounters{
			RdBytes:         100,
			WrBytes:         200,
			RdOperations:    3,
			WrOperations:    4,
			FlushOperations: 1,
		},
	}
	assert.Equal(t, "node0", s.NodeName)
	assert.Equal(t, int64(100), s.Stats.RdBytes)
	assert.Equal(t, int64(200), s.Stats.WrBytes)
}
