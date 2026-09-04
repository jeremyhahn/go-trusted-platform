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
	"net/netip"
	"testing"
	"time"
)

// mockPeerSpeaker implements PeerSpeakerInterface for testing.
type mockPeerSpeaker struct {
	started       bool
	addPeerErr    error
	removePeerErr error
	enableErr     error
	disableErr    error
	getPeerState  PeerState
	getPeerErr    error
	peers         map[string]*PeerNeighborConfig
}

func newMockPeerSpeaker() *mockPeerSpeaker {
	return &mockPeerSpeaker{
		started:      true,
		getPeerState: PeerStateIdle,
		peers:        make(map[string]*PeerNeighborConfig),
	}
}

func (m *mockPeerSpeaker) AddPeer(ctx context.Context, cfg *PeerNeighborConfig) error {
	if m.addPeerErr != nil {
		return m.addPeerErr
	}
	m.peers[cfg.Address.String()] = cfg
	return nil
}

func (m *mockPeerSpeaker) RemovePeer(ctx context.Context, addr netip.Addr) error {
	if m.removePeerErr != nil {
		return m.removePeerErr
	}
	delete(m.peers, addr.String())
	return nil
}

func (m *mockPeerSpeaker) GetPeerState(ctx context.Context, addr netip.Addr) (PeerState, error) {
	if m.getPeerErr != nil {
		return PeerStateIdle, m.getPeerErr
	}
	return m.getPeerState, nil
}

func (m *mockPeerSpeaker) EnablePeer(ctx context.Context, addr netip.Addr) error {
	return m.enableErr
}

func (m *mockPeerSpeaker) DisablePeer(ctx context.Context, addr netip.Addr) error {
	return m.disableErr
}

func (m *mockPeerSpeaker) IsStarted() bool {
	return m.started
}

func validNeighborConfig() *PeerNeighborConfig {
	return &PeerNeighborConfig{
		Address:     netip.MustParseAddr("192.168.1.1"),
		RemoteAS:    65001,
		LocalAS:     65000,
		Type:        PeerTypeEBGP,
		Description: "Test peer",
		HoldTime:    90,
	}
}

// TestNewPeerManager tests peer manager creation.
func TestNewPeerManager(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		speaker     PeerSpeakerInterface
		logger      interface{}
		opts        []PeerManagerOption
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid creation",
			speaker: newMockPeerSpeaker(),
			logger:  testLogger(),
			wantErr: false,
		},
		{
			name:    "valid creation with options",
			speaker: newMockPeerSpeaker(),
			logger:  testLogger(),
			opts: []PeerManagerOption{
				WithHealthCheckInterval(time.Minute),
				WithUnhealthyThreshold(5),
			},
			wantErr: false,
		},
		{
			name:        "nil speaker",
			speaker:     nil,
			logger:      testLogger(),
			wantErr:     true,
			errContains: "speaker is nil",
		},
		{
			name:        "nil logger",
			speaker:     newMockPeerSpeaker(),
			logger:      nil,
			wantErr:     true,
			errContains: "logger is nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var pm *PeerManager
			var err error
			if tt.logger == nil {
				pm, err = NewPeerManager(tt.speaker, nil, tt.opts...)
			} else {
				pm, err = NewPeerManager(tt.speaker, testLogger(), tt.opts...)
			}

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errContains != "" && !containsString(err.Error(), tt.errContains) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errContains)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if pm == nil {
				t.Fatal("expected peer manager, got nil")
			}
		})
	}
}

// TestPeerManagerStartStop tests start and stop operations.
func TestPeerManagerStartStop(t *testing.T) {
	t.Parallel()

	t.Run("start success", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeaker()
		pm, err := NewPeerManager(speaker, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := pm.Start(ctx); err != nil {
			t.Errorf("Start() error = %v", err)
		}

		if !pm.IsStarted() {
			t.Error("expected IsStarted() = true")
		}
	})

	t.Run("start when already started", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeaker()
		pm, err := NewPeerManager(speaker, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := pm.Start(ctx); err != nil {
			t.Fatalf("first Start() error = %v", err)
		}

		err = pm.Start(ctx)
		if err == nil {
			t.Error("expected error on second Start()")
		}
	})

	t.Run("start with speaker not started", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeaker()
		speaker.started = false
		pm, err := NewPeerManager(speaker, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		err = pm.Start(ctx)
		if err == nil {
			t.Error("expected error when speaker not started")
		}
	})

	t.Run("stop success", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeaker()
		pm, err := NewPeerManager(speaker, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := pm.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		if err := pm.Stop(); err != nil {
			t.Errorf("Stop() error = %v", err)
		}

		if pm.IsStarted() {
			t.Error("expected IsStarted() = false after stop")
		}
	})

	t.Run("stop when not started", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeaker()
		pm, err := NewPeerManager(speaker, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		if err := pm.Stop(); err != nil {
			t.Errorf("Stop() when not started should not error: %v", err)
		}
	})
}

// TestAddPeer tests adding peers.
func TestAddPeer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		config      *PeerNeighborConfig
		setupFn     func(*mockPeerSpeaker)
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid eBGP peer",
			config:  validNeighborConfig(),
			wantErr: false,
		},
		{
			name: "valid iBGP peer",
			config: func() *PeerNeighborConfig {
				cfg := validNeighborConfig()
				cfg.Type = PeerTypeIBGP
				cfg.RemoteAS = 65000
				return cfg
			}(),
			wantErr: false,
		},
		{
			name:        "nil config",
			config:      nil,
			wantErr:     true,
			errContains: "invalid",
		},
		{
			name: "invalid address",
			config: func() *PeerNeighborConfig {
				cfg := validNeighborConfig()
				cfg.Address = netip.Addr{}
				return cfg
			}(),
			wantErr:     true,
			errContains: "invalid",
		},
		{
			name: "zero remote AS",
			config: func() *PeerNeighborConfig {
				cfg := validNeighborConfig()
				cfg.RemoteAS = 0
				return cfg
			}(),
			wantErr:     true,
			errContains: "invalid",
		},
		{
			name: "unknown peer type",
			config: func() *PeerNeighborConfig {
				cfg := validNeighborConfig()
				cfg.Type = PeerTypeUnknown
				return cfg
			}(),
			wantErr:     true,
			errContains: "invalid",
		},
		{
			name:   "speaker add error",
			config: validNeighborConfig(),
			setupFn: func(m *mockPeerSpeaker) {
				m.addPeerErr = errors.New("mock add error")
			},
			wantErr:     true,
			errContains: "add",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			speaker := newMockPeerSpeaker()
			if tt.setupFn != nil {
				tt.setupFn(speaker)
			}

			pm, err := NewPeerManager(speaker, testLogger())
			if err != nil {
				t.Fatalf("failed to create manager: %v", err)
			}

			ctx := context.Background()
			if err := pm.Start(ctx); err != nil {
				t.Fatalf("Start() error = %v", err)
			}

			err = pm.AddPeer(ctx, tt.config)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errContains != "" && !containsString(err.Error(), tt.errContains) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestRemovePeer tests removing peers.
func TestRemovePeer(t *testing.T) {
	t.Parallel()

	t.Run("remove existing peer", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeaker()
		pm, err := NewPeerManager(speaker, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := pm.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		cfg := validNeighborConfig()
		if err := pm.AddPeer(ctx, cfg); err != nil {
			t.Fatalf("AddPeer() error = %v", err)
		}

		if err := pm.RemovePeer(ctx, cfg.Address); err != nil {
			t.Errorf("RemovePeer() error = %v", err)
		}

		// Verify peer is removed
		_, err = pm.GetPeer(cfg.Address)
		if err == nil {
			t.Error("expected error for removed peer")
		}
	})

	t.Run("remove non-existent peer", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeaker()
		pm, err := NewPeerManager(speaker, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := pm.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		err = pm.RemovePeer(ctx, netip.MustParseAddr("192.168.1.100"))
		if err == nil {
			t.Error("expected error for non-existent peer")
		}
	})

	t.Run("remove with invalid address", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeaker()
		pm, err := NewPeerManager(speaker, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := pm.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		err = pm.RemovePeer(ctx, netip.Addr{})
		if err == nil {
			t.Error("expected error for invalid address")
		}
	})

	t.Run("remove with speaker error", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeaker()
		pm, err := NewPeerManager(speaker, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := pm.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		cfg := validNeighborConfig()
		if err := pm.AddPeer(ctx, cfg); err != nil {
			t.Fatalf("AddPeer() error = %v", err)
		}

		speaker.removePeerErr = errors.New("mock remove error")

		err = pm.RemovePeer(ctx, cfg.Address)
		if err == nil {
			t.Error("expected error on speaker remove failure")
		}
	})
}

// TestGetPeer tests retrieving peer information.
func TestGetPeer(t *testing.T) {
	t.Parallel()

	t.Run("get existing peer", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeaker()
		pm, err := NewPeerManager(speaker, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := pm.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		cfg := validNeighborConfig()
		if err := pm.AddPeer(ctx, cfg); err != nil {
			t.Fatalf("AddPeer() error = %v", err)
		}

		peer, err := pm.GetPeer(cfg.Address)
		if err != nil {
			t.Errorf("GetPeer() error = %v", err)
		}

		if peer.Config.Address != cfg.Address {
			t.Errorf("peer address = %v, want %v", peer.Config.Address, cfg.Address)
		}

		if peer.Config.RemoteAS != cfg.RemoteAS {
			t.Errorf("peer RemoteAS = %d, want %d", peer.Config.RemoteAS, cfg.RemoteAS)
		}
	})

	t.Run("get non-existent peer", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeaker()
		pm, err := NewPeerManager(speaker, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		_, err = pm.GetPeer(netip.MustParseAddr("192.168.1.100"))
		if err == nil {
			t.Error("expected error for non-existent peer")
		}
	})

	t.Run("get with invalid address", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeaker()
		pm, err := NewPeerManager(speaker, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		_, err = pm.GetPeer(netip.Addr{})
		if err == nil {
			t.Error("expected error for invalid address")
		}
	})
}

// TestGetPeerHealth tests retrieving peer health.
func TestGetPeerHealth(t *testing.T) {
	t.Parallel()

	t.Run("healthy peer", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeaker()
		pm, err := NewPeerManager(speaker, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := pm.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		cfg := validNeighborConfig()
		if err := pm.AddPeer(ctx, cfg); err != nil {
			t.Fatalf("AddPeer() error = %v", err)
		}

		// Update peer to established state
		if err := pm.UpdatePeerState(cfg.Address, PeerStateEstablished); err != nil {
			t.Fatalf("UpdatePeerState() error = %v", err)
		}

		health, err := pm.GetPeerHealth(cfg.Address)
		if err != nil {
			t.Errorf("GetPeerHealth() error = %v", err)
		}

		if !health.Healthy {
			t.Error("expected healthy = true for established peer")
		}

		if health.State != PeerStateEstablished {
			t.Errorf("state = %v, want %v", health.State, PeerStateEstablished)
		}
	})

	t.Run("unhealthy peer", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeaker()
		pm, err := NewPeerManager(speaker, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := pm.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		cfg := validNeighborConfig()
		if err := pm.AddPeer(ctx, cfg); err != nil {
			t.Fatalf("AddPeer() error = %v", err)
		}

		health, err := pm.GetPeerHealth(cfg.Address)
		if err != nil {
			t.Errorf("GetPeerHealth() error = %v", err)
		}

		if health.Healthy {
			t.Error("expected healthy = false for idle peer")
		}
	})

	t.Run("non-existent peer", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeaker()
		pm, err := NewPeerManager(speaker, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		_, err = pm.GetPeerHealth(netip.MustParseAddr("192.168.1.100"))
		if err == nil {
			t.Error("expected error for non-existent peer")
		}
	})
}

// TestListPeers tests listing all peers.
func TestListPeers(t *testing.T) {
	t.Parallel()

	speaker := newMockPeerSpeaker()
	pm, err := NewPeerManager(speaker, testLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()
	if err := pm.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Initially empty
	peers := pm.ListPeers()
	if len(peers) != 0 {
		t.Errorf("expected 0 peers, got %d", len(peers))
	}

	// Add some peers
	for i, addr := range []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"} {
		cfg := &PeerNeighborConfig{
			Address:  netip.MustParseAddr(addr),
			RemoteAS: uint32(65001 + i),
			Type:     PeerTypeEBGP,
		}
		if err := pm.AddPeer(ctx, cfg); err != nil {
			t.Fatalf("AddPeer() error = %v", err)
		}
	}

	peers = pm.ListPeers()
	if len(peers) != 3 {
		t.Errorf("expected 3 peers, got %d", len(peers))
	}
}

// TestListUnhealthyPeers tests listing unhealthy peers.
func TestListUnhealthyPeers(t *testing.T) {
	t.Parallel()

	speaker := newMockPeerSpeaker()
	pm, err := NewPeerManager(speaker, testLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()
	if err := pm.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Add peers
	addresses := []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"}
	for i, addr := range addresses {
		cfg := &PeerNeighborConfig{
			Address:  netip.MustParseAddr(addr),
			RemoteAS: uint32(65001 + i),
			Type:     PeerTypeEBGP,
		}
		if err := pm.AddPeer(ctx, cfg); err != nil {
			t.Fatalf("AddPeer() error = %v", err)
		}
	}

	// Make first peer established
	if err := pm.UpdatePeerState(netip.MustParseAddr("192.168.1.1"), PeerStateEstablished); err != nil {
		t.Fatalf("UpdatePeerState() error = %v", err)
	}

	unhealthy := pm.ListUnhealthyPeers()
	if len(unhealthy) != 2 {
		t.Errorf("expected 2 unhealthy peers, got %d", len(unhealthy))
	}
}

// TestListEstablishedPeers tests listing established peers.
func TestListEstablishedPeers(t *testing.T) {
	t.Parallel()

	speaker := newMockPeerSpeaker()
	pm, err := NewPeerManager(speaker, testLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()
	if err := pm.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Add peers
	addresses := []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"}
	for i, addr := range addresses {
		cfg := &PeerNeighborConfig{
			Address:  netip.MustParseAddr(addr),
			RemoteAS: uint32(65001 + i),
			Type:     PeerTypeEBGP,
		}
		if err := pm.AddPeer(ctx, cfg); err != nil {
			t.Fatalf("AddPeer() error = %v", err)
		}
	}

	// Make some peers established
	for _, addr := range addresses[:2] {
		if err := pm.UpdatePeerState(netip.MustParseAddr(addr), PeerStateEstablished); err != nil {
			t.Fatalf("UpdatePeerState() error = %v", err)
		}
	}

	established := pm.ListEstablishedPeers()
	if len(established) != 2 {
		t.Errorf("expected 2 established peers, got %d", len(established))
	}
}

// TestEnableDisablePeer tests enabling and disabling peers.
func TestEnableDisablePeer(t *testing.T) {
	t.Parallel()

	t.Run("enable peer", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeaker()
		pm, err := NewPeerManager(speaker, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := pm.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		cfg := validNeighborConfig()
		cfg.AdminDown = true
		if err := pm.AddPeer(ctx, cfg); err != nil {
			t.Fatalf("AddPeer() error = %v", err)
		}

		if err := pm.EnablePeer(ctx, cfg.Address); err != nil {
			t.Errorf("EnablePeer() error = %v", err)
		}

		peer, _ := pm.GetPeer(cfg.Address)
		if peer.AdminDown {
			t.Error("expected AdminDown = false after enable")
		}
	})

	t.Run("disable peer", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeaker()
		pm, err := NewPeerManager(speaker, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := pm.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		cfg := validNeighborConfig()
		if err := pm.AddPeer(ctx, cfg); err != nil {
			t.Fatalf("AddPeer() error = %v", err)
		}

		if err := pm.DisablePeer(ctx, cfg.Address); err != nil {
			t.Errorf("DisablePeer() error = %v", err)
		}

		peer, _ := pm.GetPeer(cfg.Address)
		if !peer.AdminDown {
			t.Error("expected AdminDown = true after disable")
		}
	})

	t.Run("enable non-existent peer", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeaker()
		pm, err := NewPeerManager(speaker, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := pm.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		err = pm.EnablePeer(ctx, netip.MustParseAddr("192.168.1.100"))
		if err == nil {
			t.Error("expected error for non-existent peer")
		}
	})

	t.Run("disable non-existent peer", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeaker()
		pm, err := NewPeerManager(speaker, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := pm.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		err = pm.DisablePeer(ctx, netip.MustParseAddr("192.168.1.100"))
		if err == nil {
			t.Error("expected error for non-existent peer")
		}
	})

	t.Run("enable with speaker error", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeaker()
		speaker.enableErr = errors.New("mock enable error")
		pm, err := NewPeerManager(speaker, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := pm.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		cfg := validNeighborConfig()
		cfg.AdminDown = true
		if err := pm.AddPeer(ctx, cfg); err != nil {
			t.Fatalf("AddPeer() error = %v", err)
		}

		err = pm.EnablePeer(ctx, cfg.Address)
		if err == nil {
			t.Error("expected error on speaker enable failure")
		}
	})
}

// TestHealthMonitor tests health monitoring functionality.
func TestHealthMonitor(t *testing.T) {
	t.Parallel()

	t.Run("start and stop health monitor", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeaker()
		pm, err := NewPeerManager(speaker, testLogger(), WithHealthCheckInterval(100*time.Millisecond))
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := pm.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		if err := pm.StartHealthMonitor(ctx); err != nil {
			t.Errorf("StartHealthMonitor() error = %v", err)
		}

		// No sleep: this subtest asserts only that start and stop succeed,
		// and StopHealthMonitor joins the monitor goroutine itself. The
		// manager has no peers, so no health check would run however long
		// the test waited. That the monitor performs checks is covered by
		// TestCheckPeerHealth_StateChanges (#223).
		pm.StopHealthMonitor()
	})

	t.Run("start health monitor twice", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeaker()
		pm, err := NewPeerManager(speaker, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := pm.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		if err := pm.StartHealthMonitor(ctx); err != nil {
			t.Fatalf("first StartHealthMonitor() error = %v", err)
		}

		err = pm.StartHealthMonitor(ctx)
		if err == nil {
			t.Error("expected error on second StartHealthMonitor()")
		}

		pm.StopHealthMonitor()
	})

	t.Run("start health monitor when not started", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeaker()
		pm, err := NewPeerManager(speaker, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		err = pm.StartHealthMonitor(ctx)
		if err == nil {
			t.Error("expected error when manager not started")
		}
	})
}

// TestUpdatePeerState tests updating peer state.
func TestUpdatePeerState(t *testing.T) {
	t.Parallel()

	t.Run("update to established", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeaker()
		pm, err := NewPeerManager(speaker, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := pm.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		cfg := validNeighborConfig()
		if err := pm.AddPeer(ctx, cfg); err != nil {
			t.Fatalf("AddPeer() error = %v", err)
		}

		if err := pm.UpdatePeerState(cfg.Address, PeerStateEstablished); err != nil {
			t.Errorf("UpdatePeerState() error = %v", err)
		}

		peer, _ := pm.GetPeer(cfg.Address)
		if peer.State != PeerStateEstablished {
			t.Errorf("state = %v, want %v", peer.State, PeerStateEstablished)
		}
	})

	t.Run("update same state", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeaker()
		pm, err := NewPeerManager(speaker, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		ctx := context.Background()
		if err := pm.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		cfg := validNeighborConfig()
		if err := pm.AddPeer(ctx, cfg); err != nil {
			t.Fatalf("AddPeer() error = %v", err)
		}

		// Update to same state should be no-op
		if err := pm.UpdatePeerState(cfg.Address, PeerStateIdle); err != nil {
			t.Errorf("UpdatePeerState() error = %v", err)
		}
	})

	t.Run("update non-existent peer", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeaker()
		pm, err := NewPeerManager(speaker, testLogger())
		if err != nil {
			t.Fatalf("failed to create manager: %v", err)
		}

		err = pm.UpdatePeerState(netip.MustParseAddr("192.168.1.100"), PeerStateEstablished)
		if err == nil {
			t.Error("expected error for non-existent peer")
		}
	})
}

// TestUpdatePeerRouteCount tests updating route counts.
func TestUpdatePeerRouteCount(t *testing.T) {
	t.Parallel()

	speaker := newMockPeerSpeaker()
	pm, err := NewPeerManager(speaker, testLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()
	if err := pm.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	cfg := validNeighborConfig()
	if err := pm.AddPeer(ctx, cfg); err != nil {
		t.Fatalf("AddPeer() error = %v", err)
	}

	if err := pm.UpdatePeerRouteCount(cfg.Address, 100, 50); err != nil {
		t.Errorf("UpdatePeerRouteCount() error = %v", err)
	}

	peer, _ := pm.GetPeer(cfg.Address)
	if peer.RoutesReceived != 100 {
		t.Errorf("RoutesReceived = %d, want 100", peer.RoutesReceived)
	}
	if peer.RoutesSent != 50 {
		t.Errorf("RoutesSent = %d, want 50", peer.RoutesSent)
	}
}

// TestSetPeerError tests setting peer error message.
func TestSetPeerError(t *testing.T) {
	t.Parallel()

	speaker := newMockPeerSpeaker()
	pm, err := NewPeerManager(speaker, testLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()
	if err := pm.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	cfg := validNeighborConfig()
	if err := pm.AddPeer(ctx, cfg); err != nil {
		t.Fatalf("AddPeer() error = %v", err)
	}

	if err := pm.SetPeerError(cfg.Address, "connection refused"); err != nil {
		t.Errorf("SetPeerError() error = %v", err)
	}

	peer, _ := pm.GetPeer(cfg.Address)
	if peer.LastError != "connection refused" {
		t.Errorf("LastError = %q, want %q", peer.LastError, "connection refused")
	}
}

// TestClearPeerFailures tests clearing peer failures.
func TestClearPeerFailures(t *testing.T) {
	t.Parallel()

	speaker := newMockPeerSpeaker()
	pm, err := NewPeerManager(speaker, testLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()
	if err := pm.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	cfg := validNeighborConfig()
	if err := pm.AddPeer(ctx, cfg); err != nil {
		t.Fatalf("AddPeer() error = %v", err)
	}

	// Set some error
	if err := pm.SetPeerError(cfg.Address, "test error"); err != nil {
		t.Fatalf("SetPeerError() error = %v", err)
	}

	if err := pm.ClearPeerFailures(cfg.Address); err != nil {
		t.Errorf("ClearPeerFailures() error = %v", err)
	}

	peer, _ := pm.GetPeer(cfg.Address)
	if peer.LastError != "" {
		t.Errorf("LastError = %q, want empty", peer.LastError)
	}
	if peer.ConsecutiveFails != 0 {
		t.Errorf("ConsecutiveFails = %d, want 0", peer.ConsecutiveFails)
	}
}

// TestPeerCounts tests count methods.
func TestPeerCounts(t *testing.T) {
	t.Parallel()

	speaker := newMockPeerSpeaker()
	pm, err := NewPeerManager(speaker, testLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()
	if err := pm.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if pm.PeerCount() != 0 {
		t.Errorf("PeerCount() = %d, want 0", pm.PeerCount())
	}
	if pm.EstablishedCount() != 0 {
		t.Errorf("EstablishedCount() = %d, want 0", pm.EstablishedCount())
	}

	// Add peers
	for i, addr := range []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"} {
		cfg := &PeerNeighborConfig{
			Address:  netip.MustParseAddr(addr),
			RemoteAS: uint32(65001 + i),
			Type:     PeerTypeEBGP,
		}
		if err := pm.AddPeer(ctx, cfg); err != nil {
			t.Fatalf("AddPeer() error = %v", err)
		}
	}

	if pm.PeerCount() != 3 {
		t.Errorf("PeerCount() = %d, want 3", pm.PeerCount())
	}

	// Make some established
	for _, addr := range []string{"192.168.1.1", "192.168.1.2"} {
		if err := pm.UpdatePeerState(netip.MustParseAddr(addr), PeerStateEstablished); err != nil {
			t.Fatalf("UpdatePeerState() error = %v", err)
		}
	}

	if pm.EstablishedCount() != 2 {
		t.Errorf("EstablishedCount() = %d, want 2", pm.EstablishedCount())
	}
}

// TestGetPeersByType tests filtering peers by type.
func TestGetPeersByType(t *testing.T) {
	t.Parallel()

	speaker := newMockPeerSpeaker()
	pm, err := NewPeerManager(speaker, testLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()
	if err := pm.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Add eBGP peers
	for _, addr := range []string{"192.168.1.1", "192.168.1.2"} {
		cfg := &PeerNeighborConfig{
			Address:  netip.MustParseAddr(addr),
			RemoteAS: 65001,
			Type:     PeerTypeEBGP,
		}
		if err := pm.AddPeer(ctx, cfg); err != nil {
			t.Fatalf("AddPeer() error = %v", err)
		}
	}

	// Add iBGP peer
	cfg := &PeerNeighborConfig{
		Address:  netip.MustParseAddr("192.168.1.3"),
		RemoteAS: 65000,
		Type:     PeerTypeIBGP,
	}
	if err := pm.AddPeer(ctx, cfg); err != nil {
		t.Fatalf("AddPeer() error = %v", err)
	}

	ebgpPeers := pm.GetPeersByType(PeerTypeEBGP)
	if len(ebgpPeers) != 2 {
		t.Errorf("eBGP peers = %d, want 2", len(ebgpPeers))
	}

	ibgpPeers := pm.GetPeersByType(PeerTypeIBGP)
	if len(ibgpPeers) != 1 {
		t.Errorf("iBGP peers = %d, want 1", len(ibgpPeers))
	}
}

// TestGetPeersByAS tests filtering peers by AS number.
func TestGetPeersByAS(t *testing.T) {
	t.Parallel()

	speaker := newMockPeerSpeaker()
	pm, err := NewPeerManager(speaker, testLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()
	if err := pm.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Add peers with different ASNs
	configs := []struct {
		addr     string
		remoteAS uint32
	}{
		{"192.168.1.1", 65001},
		{"192.168.1.2", 65001},
		{"192.168.1.3", 65002},
	}

	for _, c := range configs {
		cfg := &PeerNeighborConfig{
			Address:  netip.MustParseAddr(c.addr),
			RemoteAS: c.remoteAS,
			Type:     PeerTypeEBGP,
		}
		if err := pm.AddPeer(ctx, cfg); err != nil {
			t.Fatalf("AddPeer() error = %v", err)
		}
	}

	as65001Peers := pm.GetPeersByAS(65001)
	if len(as65001Peers) != 2 {
		t.Errorf("AS65001 peers = %d, want 2", len(as65001Peers))
	}

	as65002Peers := pm.GetPeersByAS(65002)
	if len(as65002Peers) != 1 {
		t.Errorf("AS65002 peers = %d, want 1", len(as65002Peers))
	}

	as65003Peers := pm.GetPeersByAS(65003)
	if len(as65003Peers) != 0 {
		t.Errorf("AS65003 peers = %d, want 0", len(as65003Peers))
	}
}

// TestDuplicatePeer tests adding duplicate peer.
func TestDuplicatePeer(t *testing.T) {
	t.Parallel()

	speaker := newMockPeerSpeaker()
	pm, err := NewPeerManager(speaker, testLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()
	if err := pm.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	cfg := validNeighborConfig()
	if err := pm.AddPeer(ctx, cfg); err != nil {
		t.Fatalf("first AddPeer() error = %v", err)
	}

	err = pm.AddPeer(ctx, cfg)
	if err == nil {
		t.Error("expected error for duplicate peer")
	}
}

// TestManagedPeerUptime tests the Uptime method.
func TestManagedPeerUptime(t *testing.T) {
	t.Parallel()

	t.Run("not established", func(t *testing.T) {
		t.Parallel()

		peer := &ManagedPeer{
			State: PeerStateIdle,
		}

		if peer.Uptime() != 0 {
			t.Error("expected 0 uptime for non-established peer")
		}
	})

	t.Run("established", func(t *testing.T) {
		t.Parallel()

		peer := &ManagedPeer{
			State:         PeerStateEstablished,
			EstablishedAt: time.Now().Add(-time.Minute),
		}

		uptime := peer.Uptime()
		if uptime < time.Minute-time.Second || uptime > time.Minute+time.Second {
			t.Errorf("uptime = %v, expected ~1 minute", uptime)
		}
	})
}

// TestPeerStateString tests PeerState String method.
func TestPeerStateString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state PeerState
		want  string
	}{
		{PeerStateIdle, "Idle"},
		{PeerStateConnect, "Connect"},
		{PeerStateActive, "Active"},
		{PeerStateOpenSent, "OpenSent"},
		{PeerStateOpenConfirm, "OpenConfirm"},
		{PeerStateEstablished, "Established"},
		{PeerState(255), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			if got := tt.state.String(); got != tt.want {
				t.Errorf("PeerState.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestPeerTypeString tests PeerType String method.
func TestPeerTypeString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		peerType PeerType
		want     string
	}{
		{PeerTypeIBGP, "iBGP"},
		{PeerTypeEBGP, "eBGP"},
		{PeerTypeUnknown, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			if got := tt.peerType.String(); got != tt.want {
				t.Errorf("PeerType.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestOperationsNotStarted tests operations when manager is not started.
func TestPeerManagerOperationsNotStarted(t *testing.T) {
	t.Parallel()

	speaker := newMockPeerSpeaker()
	pm, err := NewPeerManager(speaker, testLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()
	cfg := validNeighborConfig()

	t.Run("AddPeer", func(t *testing.T) {
		err := pm.AddPeer(ctx, cfg)
		if err == nil {
			t.Error("expected error when not started")
		}
	})

	t.Run("RemovePeer", func(t *testing.T) {
		err := pm.RemovePeer(ctx, cfg.Address)
		if err == nil {
			t.Error("expected error when not started")
		}
	})

	t.Run("EnablePeer", func(t *testing.T) {
		err := pm.EnablePeer(ctx, cfg.Address)
		if err == nil {
			t.Error("expected error when not started")
		}
	})

	t.Run("DisablePeer", func(t *testing.T) {
		err := pm.DisablePeer(ctx, cfg.Address)
		if err == nil {
			t.Error("expected error when not started")
		}
	})
}

// TestWithHealthCheckIntervalOption tests the option function.
func TestWithHealthCheckIntervalOption(t *testing.T) {
	t.Parallel()

	t.Run("valid interval", func(t *testing.T) {
		t.Parallel()

		pm := &PeerManager{healthCheckInterval: time.Second}
		opt := WithHealthCheckInterval(time.Minute)
		opt(pm)

		if pm.healthCheckInterval != time.Minute {
			t.Errorf("healthCheckInterval = %v, want %v", pm.healthCheckInterval, time.Minute)
		}
	})

	t.Run("zero interval", func(t *testing.T) {
		t.Parallel()

		pm := &PeerManager{healthCheckInterval: time.Second}
		opt := WithHealthCheckInterval(0)
		opt(pm)

		if pm.healthCheckInterval != time.Second {
			t.Errorf("healthCheckInterval should not change for zero value")
		}
	})
}

// TestWithUnhealthyThresholdOption tests the option function.
func TestWithUnhealthyThresholdOption(t *testing.T) {
	t.Parallel()

	t.Run("valid threshold", func(t *testing.T) {
		t.Parallel()

		pm := &PeerManager{unhealthyThreshold: 1}
		opt := WithUnhealthyThreshold(5)
		opt(pm)

		if pm.unhealthyThreshold != 5 {
			t.Errorf("unhealthyThreshold = %d, want 5", pm.unhealthyThreshold)
		}
	})

	t.Run("zero threshold", func(t *testing.T) {
		t.Parallel()

		pm := &PeerManager{unhealthyThreshold: 1}
		opt := WithUnhealthyThreshold(0)
		opt(pm)

		if pm.unhealthyThreshold != 1 {
			t.Errorf("unhealthyThreshold should not change for zero value")
		}
	})
}
