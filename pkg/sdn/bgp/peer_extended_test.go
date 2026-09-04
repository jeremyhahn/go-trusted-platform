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

	// stateCalls carries a wakeup per GetPeerState call, so a test can
	// advance on health checks that actually happened instead of guessing
	// how many fit in a wall-clock window. Sends are non-blocking: the
	// health monitor is never stalled by a test that is not waiting, and
	// getStateCallCount stays the authoritative count, so a dropped wakeup
	// cannot make awaitStateCalls miss a call.
	stateCalls chan struct{}
}

// healthTestDeadline bounds how long a test waits for health checks that must
// eventually happen. It is a liveness backstop, not a timing assumption: these
// tests advance on the calls themselves, so a loaded host only takes longer and
// the deadline is reached only by a monitor that has stopped making progress.
const healthTestDeadline = 10 * time.Second

func newMockPeerSpeakerExtended() *mockPeerSpeakerExtended {
	return &mockPeerSpeakerExtended{
		started:      true,
		peerStates:   make(map[string]PeerState),
		getPeerErr:   make(map[string]error),
		defaultState: PeerStateIdle,
		peers:        make(map[string]*PeerNeighborConfig),
		stateCalls:   make(chan struct{}, 1),
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
	m.notifyStateCall()

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

// notifyStateCall records that a health check queried this speaker. It runs
// under m.mu on the health-monitor goroutine, so it must never block.
func (m *mockPeerSpeakerExtended) notifyStateCall() {
	select {
	case m.stateCalls <- struct{}{}:
	default: // a wakeup is already pending and unconsumed; one is enough
	}
}

// awaitStateCalls blocks until the speaker has served at least n GetPeerState
// calls. The count is authoritative and the channel is only a wakeup, so a
// wakeup dropped while nobody was waiting cannot make this miss a call.
func (m *mockPeerSpeakerExtended) awaitStateCalls(t *testing.T, n int) {
	t.Helper()

	deadline := time.After(healthTestDeadline)
	for {
		if m.GetStateCallCount() >= n {
			return
		}
		select {
		case <-m.stateCalls:
		case <-deadline:
			t.Fatalf("health monitor made %d of %d GetPeerState calls within %s",
				m.GetStateCallCount(), n, healthTestDeadline)
		}
	}
}

// TestCheckPeerHealth_StateChanges tests state changes during health check.
//
// These subtests drive checkPeerHealth directly. What each of them asserts is
// what a health check does to a peer, and that is a property of the check, not
// of how many checks fit inside a wall-clock window. Driving it directly makes
// the assertion exact — "after N checks the state is X" rather than "after
// 200ms of luck" — and removes the load sensitivity that failed two of these
// subtests in 8 consecutive runs on a loaded host (#223). The monitor loop that
// calls it on a ticker is covered separately, below.
func TestCheckPeerHealth_StateChanges(t *testing.T) {
	t.Parallel()

	// healthPeer starts a manager with one peer and returns both, ready for
	// checkPeerHealth to be called directly.
	healthPeer := func(t *testing.T, speaker *mockPeerSpeakerExtended, opts ...PeerManagerOption) (*PeerManager, *PeerNeighborConfig) {
		t.Helper()

		pm, err := NewPeerManager(speaker, testLogger(), opts...)
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
		return pm, cfg
	}

	t.Run("state change from idle to established", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeakerExtended()
		// First check sees idle, the second sees the session come up.
		speaker.SetStateTransitions([]PeerState{PeerStateIdle, PeerStateEstablished})

		pm, cfg := healthPeer(t, speaker)

		ctx := context.Background()
		pm.checkPeerHealth(ctx)
		pm.checkPeerHealth(ctx)

		peer, err := pm.GetPeer(cfg.Address)
		if err != nil {
			t.Fatalf("GetPeer() error = %v", err)
		}
		if peer.State != PeerStateEstablished {
			t.Errorf("state = %v, want %v", peer.State, PeerStateEstablished)
		}
		if peer.EstablishedAt.IsZero() {
			t.Error("coming up must stamp EstablishedAt")
		}
		if peer.ConsecutiveFails != 0 {
			t.Errorf("ConsecutiveFails = %d, want 0 once established", peer.ConsecutiveFails)
		}
	})

	t.Run("state change from established to idle", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeakerExtended()
		// The session is up, then drops.
		speaker.SetStateTransitions([]PeerState{PeerStateEstablished, PeerStateIdle})

		pm, cfg := healthPeer(t, speaker)

		ctx := context.Background()
		pm.checkPeerHealth(ctx)
		pm.checkPeerHealth(ctx)

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

		pm, cfg := healthPeer(t, speaker)

		ctx := context.Background()
		pm.checkPeerHealth(ctx)

		peer, err := pm.GetPeer(cfg.Address)
		if err != nil {
			t.Fatalf("GetPeer() error = %v", err)
		}
		if peer.ConsecutiveFails != 1 {
			t.Errorf("ConsecutiveFails = %d, want 1 after one failed check", peer.ConsecutiveFails)
		}
		if peer.LastError != "mock error" {
			t.Errorf("LastError = %q, want the speaker's error", peer.LastError)
		}
	})

	t.Run("admin down peer skipped in health check", func(t *testing.T) {
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

		cfg := validNeighborConfig()
		cfg.AdminDown = true
		if err := pm.AddPeer(ctx, cfg); err != nil {
			t.Fatalf("AddPeer() error = %v", err)
		}

		// A negative assertion cannot be reached by waiting for events, so
		// the check is driven directly: after a check has provably run, the
		// admin-down peer was not queried.
		pm.checkPeerHealth(ctx)

		if callCount := speaker.GetStateCallCount(); callCount != 0 {
			t.Errorf("expected 0 GetPeerState calls for admin down peer, got %d", callCount)
		}
	})

	t.Run("failure tracking for non-established enabled peer", func(t *testing.T) {
		t.Parallel()

		speaker := newMockPeerSpeakerExtended()
		// Always return Active state (not established)
		speaker.defaultState = PeerStateActive

		pm, cfg := healthPeer(t, speaker)

		ctx := context.Background()
		const checks = 3
		for i := 0; i < checks; i++ {
			pm.checkPeerHealth(ctx)
		}

		peer, err := pm.GetPeer(cfg.Address)
		if err != nil {
			t.Fatalf("GetPeer() error = %v", err)
		}
		if peer.ConsecutiveFails != checks {
			t.Errorf("ConsecutiveFails = %d, want %d — one per check on a peer that never establishes",
				peer.ConsecutiveFails, checks)
		}
	})

	t.Run("the running monitor drives health checks", func(t *testing.T) {
		t.Parallel()

		// The subtests above pin what a check does; this one pins that the
		// monitor loop actually performs them. It advances on observed
		// GetPeerState calls, so the interval only sets how fast they
		// arrive: a loaded host makes this slower, never wrong.
		speaker := newMockPeerSpeakerExtended()
		speaker.SetStateTransitions([]PeerState{PeerStateIdle, PeerStateEstablished})

		pm, cfg := healthPeer(t, speaker, WithHealthCheckInterval(time.Millisecond))

		ctx := context.Background()
		if err := pm.StartHealthMonitor(ctx); err != nil {
			t.Fatalf("StartHealthMonitor() error = %v", err)
		}
		speaker.awaitStateCalls(t, 2)

		// StopHealthMonitor joins the monitor goroutine, so no check is in
		// flight once it returns and the read below is not a race.
		pm.StopHealthMonitor()

		peer, err := pm.GetPeer(cfg.Address)
		if err != nil {
			t.Fatalf("GetPeer() error = %v", err)
		}
		if peer.State != PeerStateEstablished {
			t.Errorf("state = %v, want %v", peer.State, PeerStateEstablished)
		}
	})
}

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
