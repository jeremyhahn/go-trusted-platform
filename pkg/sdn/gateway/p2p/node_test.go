//go:build platform_p2p

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

package p2p

import (
	"context"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

func TestNodeConfig_Validate(t *testing.T) {
	t.Run("valid config with defaults", func(t *testing.T) {
		config := &NodeConfig{
			Logger: testLogger(),
		}
		err := config.Validate()
		assert.NoError(t, err)
		assert.Equal(t, DefaultConnManagerLowWater, config.ConnManagerLowWater)
		assert.Equal(t, DefaultConnManagerHighWater, config.ConnManagerHighWater)
	})

	t.Run("nil config", func(t *testing.T) {
		var config *NodeConfig
		err := config.Validate()
		assert.ErrorIs(t, err, ErrConfigNil)
	})

	t.Run("custom connection limits", func(t *testing.T) {
		config := &NodeConfig{
			ConnManagerLowWater:  50,
			ConnManagerHighWater: 200,
			Logger:               testLogger(),
		}
		err := config.Validate()
		assert.NoError(t, err)
		assert.Equal(t, 50, config.ConnManagerLowWater)
		assert.Equal(t, 200, config.ConnManagerHighWater)
	})

	t.Run("high water adjusted when less than low water", func(t *testing.T) {
		config := &NodeConfig{
			ConnManagerLowWater:  200,
			ConnManagerHighWater: 100,
			Logger:               testLogger(),
		}
		err := config.Validate()
		assert.NoError(t, err)
		assert.Equal(t, 200, config.ConnManagerLowWater)
		assert.Equal(t, 300, config.ConnManagerHighWater)
	})

	t.Run("nil logger defaults to slog.Default", func(t *testing.T) {
		config := &NodeConfig{}
		err := config.Validate()
		assert.NoError(t, err)
		assert.NotNil(t, config.Logger)
	})
}

func TestDHTMode_String(t *testing.T) {
	tests := []struct {
		mode     DHTMode
		expected string
	}{
		{DHTModeAuto, "auto"},
		{DHTModeServer, "server"},
		{DHTModeClient, "client"},
		{DHTMode(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.mode.String())
		})
	}
}

func TestNewNode(t *testing.T) {
	t.Run("successful creation", func(t *testing.T) {
		config := &NodeConfig{
			Logger: testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)
		assert.NotNil(t, node)
		assert.NotNil(t, node.config)
		assert.NotNil(t, node.logger)
	})

	t.Run("nil config fails", func(t *testing.T) {
		node, err := NewNode(nil)
		assert.ErrorIs(t, err, ErrConfigNil)
		assert.Nil(t, node)
	})
}

func TestNode_StartStop(t *testing.T) {
	t.Run("successful start and stop", func(t *testing.T) {
		config := &NodeConfig{
			ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
			DHTMode:     DHTModeClient,
			Logger:      testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = node.Start(ctx)
		require.NoError(t, err)

		assert.True(t, node.IsRunning())
		assert.NotEmpty(t, node.PeerID())

		err = node.Stop(ctx)
		require.NoError(t, err)
		assert.False(t, node.IsRunning())
	})

	t.Run("double start fails", func(t *testing.T) {
		config := &NodeConfig{
			ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
			DHTMode:     DHTModeClient,
			Logger:      testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = node.Start(ctx)
		require.NoError(t, err)
		defer node.Stop(ctx)

		err = node.Start(ctx)
		assert.ErrorIs(t, err, ErrAlreadyRunning)
	})

	t.Run("stop without start fails", func(t *testing.T) {
		config := &NodeConfig{
			Logger: testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = node.Stop(ctx)
		assert.ErrorIs(t, err, ErrNotRunning)
	})
}

func TestNode_IsRunning(t *testing.T) {
	config := &NodeConfig{
		ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
		DHTMode:     DHTModeClient,
		Logger:      testLogger(),
	}
	node, err := NewNode(config)
	require.NoError(t, err)

	assert.False(t, node.IsRunning())

	ctx := context.Background()
	err = node.Start(ctx)
	require.NoError(t, err)

	assert.True(t, node.IsRunning())

	err = node.Stop(ctx)
	require.NoError(t, err)

	assert.False(t, node.IsRunning())
}

func TestNode_Host(t *testing.T) {
	t.Run("returns nil when not started", func(t *testing.T) {
		config := &NodeConfig{
			Logger: testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		assert.Nil(t, node.Host())
	})

	t.Run("returns host when running", func(t *testing.T) {
		config := &NodeConfig{
			ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
			DHTMode:     DHTModeClient,
			Logger:      testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = node.Start(ctx)
		require.NoError(t, err)
		defer node.Stop(ctx)

		assert.NotNil(t, node.Host())
	})
}

func TestNode_DHT(t *testing.T) {
	t.Run("returns nil when not started", func(t *testing.T) {
		config := &NodeConfig{
			Logger: testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		assert.Nil(t, node.DHT())
	})

	t.Run("returns dht when running", func(t *testing.T) {
		config := &NodeConfig{
			ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
			DHTMode:     DHTModeClient,
			Logger:      testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = node.Start(ctx)
		require.NoError(t, err)
		defer node.Stop(ctx)

		assert.NotNil(t, node.DHT())
	})
}

func TestNode_PeerID(t *testing.T) {
	t.Run("returns empty when not started", func(t *testing.T) {
		config := &NodeConfig{
			Logger: testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		assert.Equal(t, peer.ID(""), node.PeerID())
	})

	t.Run("returns peer ID when running", func(t *testing.T) {
		config := &NodeConfig{
			ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
			DHTMode:     DHTModeClient,
			Logger:      testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = node.Start(ctx)
		require.NoError(t, err)
		defer node.Stop(ctx)

		peerID := node.PeerID()
		assert.NotEmpty(t, peerID)
	})
}

func TestNode_ConnectedPeers(t *testing.T) {
	t.Run("returns nil when not started", func(t *testing.T) {
		config := &NodeConfig{
			Logger: testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		assert.Nil(t, node.ConnectedPeers())
	})

	t.Run("returns empty slice when no peers connected", func(t *testing.T) {
		config := &NodeConfig{
			ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
			DHTMode:     DHTModeClient,
			Logger:      testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = node.Start(ctx)
		require.NoError(t, err)
		defer node.Stop(ctx)

		peers := node.ConnectedPeers()
		assert.NotNil(t, peers)
		assert.Empty(t, peers)
	})
}

func TestNode_IsConnected(t *testing.T) {
	t.Run("returns false when not started", func(t *testing.T) {
		config := &NodeConfig{
			Logger: testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		// Create a dummy peer ID
		peerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")
		assert.False(t, node.IsConnected(peerID))
	})

	t.Run("returns false for non-connected peer", func(t *testing.T) {
		config := &NodeConfig{
			ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
			DHTMode:     DHTModeClient,
			Logger:      testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = node.Start(ctx)
		require.NoError(t, err)
		defer node.Stop(ctx)

		peerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")
		assert.False(t, node.IsConnected(peerID))
	})
}

func TestNode_Connect(t *testing.T) {
	t.Run("fails when not running", func(t *testing.T) {
		config := &NodeConfig{
			Logger: testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = node.Connect(ctx, "/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")
		assert.ErrorIs(t, err, ErrNotRunning)
	})

	t.Run("fails with invalid multiaddr", func(t *testing.T) {
		config := &NodeConfig{
			ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
			DHTMode:     DHTModeClient,
			Logger:      testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = node.Start(ctx)
		require.NoError(t, err)
		defer node.Stop(ctx)

		err = node.Connect(ctx, "invalid-multiaddr")
		assert.Error(t, err)
		var invalidErr *ErrInvalidMultiaddr
		assert.ErrorAs(t, err, &invalidErr)
	})
}

func TestNode_Disconnect(t *testing.T) {
	t.Run("fails when not running", func(t *testing.T) {
		config := &NodeConfig{
			Logger: testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		peerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")
		err = node.Disconnect(peerID)
		assert.ErrorIs(t, err, ErrNotRunning)
	})
}

func TestNode_GetStatus(t *testing.T) {
	t.Run("returns status with unknown NAT when not started", func(t *testing.T) {
		config := &NodeConfig{
			Logger: testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		status := node.GetStatus()
		assert.NotNil(t, status)
		assert.Equal(t, "unknown", status.NATStatus.Reachability)
		assert.Equal(t, peer.ID(""), status.PeerID)
	})

	t.Run("returns full status when running", func(t *testing.T) {
		config := &NodeConfig{
			ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
			DHTMode:     DHTModeClient,
			Logger:      testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = node.Start(ctx)
		require.NoError(t, err)
		defer node.Stop(ctx)

		// Give node some time to initialize
		time.Sleep(100 * time.Millisecond)

		status := node.GetStatus()
		assert.NotNil(t, status)
		assert.NotEmpty(t, status.PeerID)
		assert.NotEmpty(t, status.ListenAddrs)
		assert.GreaterOrEqual(t, status.Uptime, time.Duration(0))
	})
}

func TestNode_FindPeers(t *testing.T) {
	t.Run("fails when not running", func(t *testing.T) {
		config := &NodeConfig{
			Logger: testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		ctx := context.Background()
		_, err = node.FindPeers(ctx, "test-namespace")
		assert.ErrorIs(t, err, ErrNotRunning)
	})
}

func TestNode_Advertise(t *testing.T) {
	t.Run("fails when not running", func(t *testing.T) {
		config := &NodeConfig{
			Logger: testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = node.Advertise(ctx, "test-namespace")
		assert.ErrorIs(t, err, ErrNotRunning)
	})
}

func TestNode_GetClosestPeers(t *testing.T) {
	t.Run("fails when not running", func(t *testing.T) {
		config := &NodeConfig{
			Logger: testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		ctx := context.Background()
		_, err = node.GetClosestPeers(ctx, "test-key")
		assert.ErrorIs(t, err, ErrNotRunning)
	})
}

func TestNode_FindPeer(t *testing.T) {
	t.Run("fails when not running", func(t *testing.T) {
		config := &NodeConfig{
			Logger: testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		peerID, _ := peer.Decode("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")
		ctx := context.Background()
		_, err = node.FindPeer(ctx, peerID)
		assert.ErrorIs(t, err, ErrNotRunning)
	})
}

func TestNode_GetBootstrapPeers(t *testing.T) {
	t.Run("returns nil when not running", func(t *testing.T) {
		config := &NodeConfig{
			Logger: testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		peers := node.GetBootstrapPeers(10)
		assert.Nil(t, peers)
	})

	t.Run("returns empty when no peers connected", func(t *testing.T) {
		config := &NodeConfig{
			ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
			DHTMode:     DHTModeClient,
			Logger:      testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = node.Start(ctx)
		require.NoError(t, err)
		defer node.Stop(ctx)

		peers := node.GetBootstrapPeers(10)
		assert.Empty(t, peers)
	})

	t.Run("uses default limit when zero provided", func(t *testing.T) {
		config := &NodeConfig{
			ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
			DHTMode:     DHTModeClient,
			Logger:      testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = node.Start(ctx)
		require.NoError(t, err)
		defer node.Stop(ctx)

		peers := node.GetBootstrapPeers(0)
		assert.Empty(t, peers) // No connected peers
	})
}

func TestNode_RegisterNode(t *testing.T) {
	t.Run("fails when not running", func(t *testing.T) {
		config := &NodeConfig{
			Logger: testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		ctx := context.Background()
		_, _, err = node.RegisterNode(ctx, "device-1", net.ParseIP("192.168.1.1"), 1)
		assert.ErrorIs(t, err, ErrNotRunning)
	})

	t.Run("fails with empty device ID", func(t *testing.T) {
		config := &NodeConfig{
			ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
			DHTMode:     DHTModeClient,
			Logger:      testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = node.Start(ctx)
		require.NoError(t, err)
		defer node.Stop(ctx)

		_, _, err = node.RegisterNode(ctx, "", net.ParseIP("192.168.1.1"), 1)
		assert.ErrorIs(t, err, ErrDeviceIDRequired)
	})

	t.Run("successful registration", func(t *testing.T) {
		config := &NodeConfig{
			ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
			DHTMode:     DHTModeClient,
			Logger:      testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = node.Start(ctx)
		require.NoError(t, err)
		defer node.Stop(ctx)

		nodeID, bootstrapPeers, err := node.RegisterNode(ctx, "device-1", net.ParseIP("192.168.1.1"), 1)
		assert.NoError(t, err)
		assert.NotEmpty(t, nodeID)
		// bootstrapPeers may be nil or empty when no peers are connected
		_ = bootstrapPeers
	})
}

func TestNode_Bootstrap(t *testing.T) {
	t.Run("fails when not running", func(t *testing.T) {
		config := &NodeConfig{
			Logger: testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		ctx := context.Background()
		_, _, _, err = node.Bootstrap(ctx, []byte("node-id"))
		assert.ErrorIs(t, err, ErrNotRunning)
	})

	t.Run("fails with empty node ID", func(t *testing.T) {
		config := &NodeConfig{
			ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
			DHTMode:     DHTModeClient,
			Logger:      testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = node.Start(ctx)
		require.NoError(t, err)
		defer node.Stop(ctx)

		_, _, _, err = node.Bootstrap(ctx, nil)
		assert.ErrorIs(t, err, ErrNodeIDRequired)
	})

	t.Run("successful bootstrap", func(t *testing.T) {
		config := &NodeConfig{
			ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
			DHTMode:     DHTModeClient,
			Logger:      testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = node.Start(ctx)
		require.NoError(t, err)
		defer node.Stop(ctx)

		peers, region, bucket, err := node.Bootstrap(ctx, []byte{0x12, 0x34, 0x56})
		assert.NoError(t, err)
		// peers may be nil or empty when no peers are connected
		_ = peers
		assert.Equal(t, "default", region)
		assert.GreaterOrEqual(t, bucket, 0)
	})
}

func TestNode_calculateBucket(t *testing.T) {
	config := &NodeConfig{
		Logger: testLogger(),
	}
	node, err := NewNode(config)
	require.NoError(t, err)

	tests := []struct {
		name     string
		nodeID   []byte
		expected int
	}{
		{"all zeros", []byte{0, 0, 0, 0}, 0},
		{"first bit set", []byte{0x80, 0, 0, 0}, 0},
		{"second bit set", []byte{0x40, 0, 0, 0}, 1},
		{"eighth bit set", []byte{0x01, 0, 0, 0}, 7},
		{"ninth bit set", []byte{0, 0x80, 0, 0}, 8},
		{"sixteenth bit set", []byte{0, 0x01, 0, 0}, 15},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bucket := node.calculateBucket(tt.nodeID)
			assert.Equal(t, tt.expected, bucket)
		})
	}
}

func TestNode_WithDHTModes(t *testing.T) {
	modes := []struct {
		mode     DHTMode
		expected string
	}{
		{DHTModeAuto, "auto"},
		{DHTModeServer, "server"},
		{DHTModeClient, "client"},
	}

	for _, tt := range modes {
		t.Run(tt.expected, func(t *testing.T) {
			config := &NodeConfig{
				ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
				DHTMode:     tt.mode,
				Logger:      testLogger(),
			}
			node, err := NewNode(config)
			require.NoError(t, err)

			ctx := context.Background()
			err = node.Start(ctx)
			require.NoError(t, err)
			defer node.Stop(ctx)

			assert.True(t, node.IsRunning())
		})
	}
}

func TestNode_WithOptions(t *testing.T) {
	t.Run("with relay enabled", func(t *testing.T) {
		config := &NodeConfig{
			ListenAddrs:       []string{"/ip4/127.0.0.1/tcp/0"},
			DHTMode:           DHTModeClient,
			EnableRelayClient: true,
			Logger:            testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = node.Start(ctx)
		require.NoError(t, err)
		defer node.Stop(ctx)

		assert.True(t, node.IsRunning())
	})

	t.Run("with hole punching enabled", func(t *testing.T) {
		config := &NodeConfig{
			ListenAddrs:        []string{"/ip4/127.0.0.1/tcp/0"},
			DHTMode:            DHTModeClient,
			EnableHolePunching: true,
			Logger:             testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = node.Start(ctx)
		require.NoError(t, err)
		defer node.Stop(ctx)

		assert.True(t, node.IsRunning())
	})

	t.Run("with auto NAT enabled", func(t *testing.T) {
		config := &NodeConfig{
			ListenAddrs:   []string{"/ip4/127.0.0.1/tcp/0"},
			DHTMode:       DHTModeClient,
			EnableAutoNAT: true,
			Logger:        testLogger(),
		}
		node, err := NewNode(config)
		require.NoError(t, err)

		ctx := context.Background()
		err = node.Start(ctx)
		require.NoError(t, err)
		defer node.Stop(ctx)

		assert.True(t, node.IsRunning())
	})
}

func TestNode_InvalidListenAddr(t *testing.T) {
	config := &NodeConfig{
		ListenAddrs: []string{"invalid-address"},
		Logger:      testLogger(),
	}
	node, err := NewNode(config)
	require.NoError(t, err)

	ctx := context.Background()
	err = node.Start(ctx)
	assert.Error(t, err)
	var initErr *ErrNodeInitFailed
	assert.ErrorAs(t, err, &initErr)
	assert.Equal(t, "listen_addr", initErr.Component)
}
