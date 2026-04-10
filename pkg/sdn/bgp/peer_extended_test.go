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
	"sync"
	"testing"
	"time"
)

// mockPeerSpeakerExtended is an enhanced mock with dynamic state behavior.
type mockPeerSpeakerExtended struct {
	mu                  sync.Mutex
	started             bool
	addPeerErr          error
	removePeerErr       error
	enableErr           error
	disableErr          error
	peerStates          map[string]PeerState
	getPeerErr          map[string]error
	defaultState        PeerState
	defaultErr          error
	peers               map[string]*PeerNeighborConfig
	getStateCallCount   int
	stateTransitions    []PeerState
	currentTransitionAt int
}

func newMockPeerSpeakerExtended() *mockPeerSpeakerExtended {
	return &mockPeerSpeakerExtended{
		started:      true,
		peerStates:   make(map[string]PeerState),
		getPeerErr:   make(map[string]error),
		defaultState: PeerStateIdle,
		peers:        make(map[string]*PeerNeighborConfig),
	}
}

func (m *mockPeerSpeakerExtended) AddPeer(ctx context.Context, cfg *PeerNeighborConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.addPeerErr != nil {
		return m.addPeerErr
	}
	m.peers[cfg.Address.String()] = cfg
	return nil
}

func (m *mockPeerSpeakerExtended) RemovePeer(ctx context.Context, addr netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.removePeerErr != nil {
		return m.removePeerErr
	}
	delete(m.peers, addr.String())
	return nil
}

func (m *mockPeerSpeakerExtended) GetPeerState(ctx context.Context, addr netip.Addr) (PeerState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := addr.String()
	m.getStateCallCount++

	// Check for state transitions
	if len(m.stateTransitions) > 0 {
		if m.currentTransitionAt < len(m.stateTransitions) {
			state := m.stateTransitions[m.currentTransitionAt]
			m.currentTransitionAt++
			return state, nil
		}
		// Return the last state if we've exhausted transitions
		return m.stateTransitions[len(m.stateTransitions)-1], nil
	}

	// Check for per-peer error
	if err, ok := m.getPeerErr[key]; ok && err != nil {
		return PeerStateIdle, err
	}

	// Check for default error
	if m.defaultErr != nil {
		return PeerStateIdle, m.defaultErr
	}

	// Check for per-peer state
	if state, ok := m.peerStates[key]; ok {
		return state, nil
	}

	return m.defaultState, nil
}

func (m *mockPeerSpeakerExtended) EnablePeer(ctx context.Context, addr netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.enableErr
}

func (m *mockPeerSpeakerExtended) DisablePeer(ctx context.Context, addr netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.disableErr
}

func (m *mockPeerSpeakerExtended) IsStarted() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.started
}

func (m *mockPeerSpeakerExtended) SetPeerState(addr string, state PeerState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peerStates[addr] = state
}

func (m *mockPeerSpeakerExtended) SetPeerError(addr string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getPeerErr[addr] = err
}

func (m *mockPeerSpeakerExtended) SetStateTransitions(transitions []PeerState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stateTransitions = transitions
	m.currentTransitionAt = 0
}

func (m *mockPeerSpeakerExtended) GetStateCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getStateCallCount
}

// TestCheckPeerHealth_StateChanges tests state changes during health check.
func TestCheckPeerHealth_StateChanges(t *testing.T) {
	t.Parallel()

	t.Run("state change from idle to established", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeakerExtended()
		// Set state transitions: first call returns idle, subsequent returns established
		speaker.SetStateTransitions([]PeerState{PeerStateIdle, PeerStateEstablished, PeerStateEstablished})

		pm, err := NewPeerManager(speaker, testLogger(), WithHealthCheckInterval(50*time.Millisecond))
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

		// Start health monitor
		if err := pm.StartHealthMonitor(ctx); err != nil {
			t.Fatalf("StartHealthMonitor() error = %v", err)
		}

		// Wait for health checks to run
		time.Sleep(200 * time.Millisecond)

		pm.StopHealthMonitor()

		// Verify peer state was updated
		peer, err := pm.GetPeer(cfg.Address)
		if err != nil {
			t.Fatalf("GetPeer() error = %v", err)
		}

		// The test verifies that health check processes state changes
		// Since health check ran multiple times, state should have been updated
		if peer.State != PeerStateEstablished {
			t.Errorf("state = %v, want %v", peer.State, PeerStateEstablished)
		}
	})

	t.Run("state change from established to idle", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeakerExtended()
		// Set state transitions: established then idle
		speaker.SetStateTransitions([]PeerState{PeerStateEstablished, PeerStateIdle})

		pm, err := NewPeerManager(speaker, testLogger(), WithHealthCheckInterval(50*time.Millisecond))
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

		// Start health monitor
		if err := pm.StartHealthMonitor(ctx); err != nil {
			t.Fatalf("StartHealthMonitor() error = %v", err)
		}

		// Wait for health checks to run
		time.Sleep(200 * time.Millisecond)

		pm.StopHealthMonitor()

		// Verify peer state was updated to idle
		peer, err := pm.GetPeer(cfg.Address)
		if err != nil {
			t.Fatalf("GetPeer() error = %v", err)
		}

		if peer.State != PeerStateIdle {
			t.Errorf("state = %v, want %v", peer.State, PeerStateIdle)
		}
	})

	t.Run("health check with GetPeerState error", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeakerExtended()
		speaker.defaultErr = errors.New("mock error")

		pm, err := NewPeerManager(speaker, testLogger(), WithHealthCheckInterval(50*time.Millisecond))
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

		// Start health monitor
		if err := pm.StartHealthMonitor(ctx); err != nil {
			t.Fatalf("StartHealthMonitor() error = %v", err)
		}

		// Wait for health checks to run
		time.Sleep(150 * time.Millisecond)

		pm.StopHealthMonitor()

		// Verify consecutive failures increased
		peer, err := pm.GetPeer(cfg.Address)
		if err != nil {
			t.Fatalf("GetPeer() error = %v", err)
		}

		if peer.ConsecutiveFails == 0 {
			t.Error("expected ConsecutiveFails > 0 after errors")
		}

		if peer.LastError == "" {
			t.Error("expected LastError to be set")
		}
	})

	t.Run("admin down peer skipped in health check", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeakerExtended()

		pm, err := NewPeerManager(speaker, testLogger(), WithHealthCheckInterval(50*time.Millisecond))
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

		// Start health monitor
		if err := pm.StartHealthMonitor(ctx); err != nil {
			t.Fatalf("StartHealthMonitor() error = %v", err)
		}

		// Wait for health checks to run
		time.Sleep(150 * time.Millisecond)

		pm.StopHealthMonitor()

		// Verify GetPeerState was not called (because peer is admin down)
		// Admin down peers should be skipped
		callCount := speaker.GetStateCallCount()
		if callCount > 0 {
			t.Errorf("expected 0 GetPeerState calls for admin down peer, got %d", callCount)
		}
	})

	t.Run("failure tracking for non-established enabled peer", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeakerExtended()
		// Always return Active state (not established)
		speaker.defaultState = PeerStateActive

		pm, err := NewPeerManager(speaker, testLogger(), WithHealthCheckInterval(50*time.Millisecond))
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

		// Start health monitor
		if err := pm.StartHealthMonitor(ctx); err != nil {
			t.Fatalf("StartHealthMonitor() error = %v", err)
		}

		// Wait for several health checks to run
		time.Sleep(200 * time.Millisecond)

		pm.StopHealthMonitor()

		// Verify consecutive failures increased for non-established peer
		peer, err := pm.GetPeer(cfg.Address)
		if err != nil {
			t.Fatalf("GetPeer() error = %v", err)
		}

		// Should have multiple failures tracked
		if peer.ConsecutiveFails == 0 {
			t.Error("expected ConsecutiveFails > 0 for non-established peer")
		}
	})
}

// TestPeerManagerConcurrency tests thread safety of peer operations.
func TestPeerManagerConcurrency(t *testing.T) {
	t.Parallel()

	speaker := newMockPeerSpeakerExtended()
	pm, err := NewPeerManager(speaker, testLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()
	if err := pm.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Add initial peer
	cfg := validNeighborConfig()
	if err := pm.AddPeer(ctx, cfg); err != nil {
		t.Fatalf("AddPeer() error = %v", err)
	}

	// Run concurrent operations
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pm.ListPeers()
			pm.ListEstablishedPeers()
			pm.ListUnhealthyPeers()
			pm.PeerCount()
			pm.EstablishedCount()
		}()
	}

	// Concurrent state updates
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(state PeerState) {
			defer wg.Done()
			pm.UpdatePeerState(cfg.Address, state)
		}(PeerState(i % 6))
	}

	wg.Wait()
}

// TestUpdatePeerStateInvalidAddress tests update with invalid address.
func TestUpdatePeerStateInvalidAddress(t *testing.T) {
	t.Parallel()

	speaker := newMockPeerSpeakerExtended()
	pm, err := NewPeerManager(speaker, testLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	err = pm.UpdatePeerState(netip.Addr{}, PeerStateEstablished)
	if err == nil {
		t.Error("expected error for invalid address")
	}
}

// TestUpdatePeerRouteCountErrors tests error cases.
func TestUpdatePeerRouteCountErrors(t *testing.T) {
	t.Parallel()

	speaker := newMockPeerSpeakerExtended()
	pm, err := NewPeerManager(speaker, testLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	t.Run("invalid address", func(t *testing.T) {
		err := pm.UpdatePeerRouteCount(netip.Addr{}, 10, 5)
		if err == nil {
			t.Error("expected error for invalid address")
		}
	})

	t.Run("non-existent peer", func(t *testing.T) {
		err := pm.UpdatePeerRouteCount(netip.MustParseAddr("192.168.1.100"), 10, 5)
		if err == nil {
			t.Error("expected error for non-existent peer")
		}
	})
}

// TestSetPeerErrorErrors tests error cases.
func TestSetPeerErrorErrors(t *testing.T) {
	t.Parallel()

	speaker := newMockPeerSpeakerExtended()
	pm, err := NewPeerManager(speaker, testLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	t.Run("invalid address", func(t *testing.T) {
		err := pm.SetPeerError(netip.Addr{}, "error message")
		if err == nil {
			t.Error("expected error for invalid address")
		}
	})

	t.Run("non-existent peer", func(t *testing.T) {
		err := pm.SetPeerError(netip.MustParseAddr("192.168.1.100"), "error message")
		if err == nil {
			t.Error("expected error for non-existent peer")
		}
	})
}

// TestClearPeerFailuresErrors tests error cases.
func TestClearPeerFailuresErrors(t *testing.T) {
	t.Parallel()

	speaker := newMockPeerSpeakerExtended()
	pm, err := NewPeerManager(speaker, testLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	t.Run("invalid address", func(t *testing.T) {
		err := pm.ClearPeerFailures(netip.Addr{})
		if err == nil {
			t.Error("expected error for invalid address")
		}
	})

	t.Run("non-existent peer", func(t *testing.T) {
		err := pm.ClearPeerFailures(netip.MustParseAddr("192.168.1.100"))
		if err == nil {
			t.Error("expected error for non-existent peer")
		}
	})
}

// TestDisablePeerWithSpeakerError tests disable with speaker error.
func TestDisablePeerWithSpeakerError(t *testing.T) {
	t.Parallel()

	speaker := newMockPeerSpeakerExtended()
	speaker.disableErr = errors.New("mock disable error")

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

	err = pm.DisablePeer(ctx, cfg.Address)
	if err == nil {
		t.Error("expected error on speaker disable failure")
	}
}

// TestGetPeerHealthInvalidAddress tests invalid address.
func TestGetPeerHealthInvalidAddress(t *testing.T) {
	t.Parallel()

	speaker := newMockPeerSpeakerExtended()
	pm, err := NewPeerManager(speaker, testLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	_, err = pm.GetPeerHealth(netip.Addr{})
	if err == nil {
		t.Error("expected error for invalid address")
	}
}

// TestEnablePeerInvalidAddress tests invalid address.
func TestEnablePeerInvalidAddress(t *testing.T) {
	t.Parallel()

	speaker := newMockPeerSpeakerExtended()
	pm, err := NewPeerManager(speaker, testLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()
	if err := pm.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	err = pm.EnablePeer(ctx, netip.Addr{})
	if err == nil {
		t.Error("expected error for invalid address")
	}
}

// TestDisablePeerInvalidAddress tests invalid address.
func TestDisablePeerInvalidAddress(t *testing.T) {
	t.Parallel()

	speaker := newMockPeerSpeakerExtended()
	pm, err := NewPeerManager(speaker, testLogger())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx := context.Background()
	if err := pm.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	err = pm.DisablePeer(ctx, netip.Addr{})
	if err == nil {
		t.Error("expected error for invalid address")
	}
}

// TestPeerNeighborConfigValidation tests neighbor config validation.
func TestPeerNeighborConfigValidation(t *testing.T) {
	t.Parallel()

	t.Run("valid iBGP config", func(t *testing.T) {
		cfg := &PeerNeighborConfig{
			Address:  netip.MustParseAddr("192.168.1.1"),
			RemoteAS: 65000,
			LocalAS:  65000,
			Type:     PeerTypeIBGP,
		}
		err := cfg.Validate()
		if err != nil {
			t.Errorf("Validate() error = %v for valid iBGP config", err)
		}
	})

	t.Run("valid eBGP config", func(t *testing.T) {
		cfg := &PeerNeighborConfig{
			Address:  netip.MustParseAddr("192.168.1.1"),
			RemoteAS: 65001,
			LocalAS:  65000,
			Type:     PeerTypeEBGP,
		}
		err := cfg.Validate()
		if err != nil {
			t.Errorf("Validate() error = %v for valid eBGP config", err)
		}
	})

	t.Run("invalid address", func(t *testing.T) {
		cfg := &PeerNeighborConfig{
			Address:  netip.Addr{},
			RemoteAS: 65001,
			Type:     PeerTypeEBGP,
		}
		err := cfg.Validate()
		if err == nil {
			t.Error("expected error for invalid address")
		}
	})

	t.Run("zero remote AS", func(t *testing.T) {
		cfg := &PeerNeighborConfig{
			Address:  netip.MustParseAddr("192.168.1.1"),
			RemoteAS: 0,
			Type:     PeerTypeEBGP,
		}
		err := cfg.Validate()
		if err == nil {
			t.Error("expected error for zero remote AS")
		}
	})

	t.Run("unknown peer type", func(t *testing.T) {
		cfg := &PeerNeighborConfig{
			Address:  netip.MustParseAddr("192.168.1.1"),
			RemoteAS: 65001,
			Type:     PeerTypeUnknown,
		}
		err := cfg.Validate()
		if err == nil {
			t.Error("expected error for unknown peer type")
		}
	})
}
