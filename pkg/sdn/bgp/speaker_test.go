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
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v3/api"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// mockBGPServer implements BGPServerInterface for testing.
type mockBGPServer struct {
	mu      sync.RWMutex
	started bool
	stopped bool
	global  *api.Global
	peers   map[string]*api.Peer
	paths   []*api.Path

	// Error injection
	startErr      error
	startBgpErr   error
	stopBgpErr    error
	addPeerErr    error
	deletePeerErr error
	updatePeerErr error
	getBgpErr     error
	listPeerErr   error
	resetPeerErr  error
	addPathErr    error
	deletePathErr error
	listPathErr   error
	watchEventErr error

	// Callback for watch events
	watchCallback func(*api.WatchEventResponse)
}

func newMockBGPServer() *mockBGPServer {
	return &mockBGPServer{
		peers: make(map[string]*api.Peer),
		paths: make([]*api.Path, 0),
	}
}

func (m *mockBGPServer) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.startErr != nil {
		return m.startErr
	}
	m.started = true
	return nil
}

func (m *mockBGPServer) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopped = true
	m.started = false
}

func (m *mockBGPServer) StartBgp(ctx context.Context, req *api.StartBgpRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.startBgpErr != nil {
		return m.startBgpErr
	}
	m.global = req.Global
	return nil
}

func (m *mockBGPServer) StopBgp(ctx context.Context, req *api.StopBgpRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.stopBgpErr != nil {
		return m.stopBgpErr
	}
	return nil
}

func (m *mockBGPServer) AddPeer(ctx context.Context, req *api.AddPeerRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.addPeerErr != nil {
		return m.addPeerErr
	}

	if req.Peer != nil && req.Peer.Conf != nil {
		addr := req.Peer.Conf.NeighborAddress
		if _, exists := m.peers[addr]; exists {
			return errors.New("peer already exists")
		}
		m.peers[addr] = req.Peer
	}
	return nil
}

func (m *mockBGPServer) DeletePeer(ctx context.Context, req *api.DeletePeerRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.deletePeerErr != nil {
		return m.deletePeerErr
	}

	if _, exists := m.peers[req.Address]; !exists {
		return errors.New("peer not found")
	}
	delete(m.peers, req.Address)
	return nil
}

func (m *mockBGPServer) UpdatePeer(ctx context.Context, req *api.UpdatePeerRequest, doSoftResetIn bool) (*api.UpdatePeerResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.updatePeerErr != nil {
		return nil, m.updatePeerErr
	}

	if req.Peer != nil && req.Peer.Conf != nil {
		addr := req.Peer.Conf.NeighborAddress
		if existing, exists := m.peers[addr]; exists {
			// Update state
			if req.Peer.State != nil {
				existing.State = req.Peer.State
			}
		}
	}

	return &api.UpdatePeerResponse{
		NeedsSoftResetIn: false,
	}, nil
}

func (m *mockBGPServer) GetBgp(ctx context.Context, req *api.GetBgpRequest) (*api.GetBgpResponse, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.getBgpErr != nil {
		return nil, m.getBgpErr
	}

	return &api.GetBgpResponse{
		Global: m.global,
	}, nil
}

func (m *mockBGPServer) ListPeer(ctx context.Context, req *api.ListPeerRequest, fn func(*api.Peer)) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.listPeerErr != nil {
		return m.listPeerErr
	}

	if req.Address != "" {
		if peer, exists := m.peers[req.Address]; exists {
			fn(peer)
		}
	} else {
		for _, peer := range m.peers {
			fn(peer)
		}
	}
	return nil
}

func (m *mockBGPServer) ResetPeer(ctx context.Context, req *api.ResetPeerRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.resetPeerErr != nil {
		return m.resetPeerErr
	}

	if _, exists := m.peers[req.Address]; !exists {
		return errors.New("peer not found")
	}
	return nil
}

func (m *mockBGPServer) EnableMrt(ctx context.Context, req *api.EnableMrtRequest) error {
	return nil
}

func (m *mockBGPServer) DisableMrt(ctx context.Context, req *api.DisableMrtRequest) error {
	return nil
}

func (m *mockBGPServer) AddPath(ctx context.Context, req *api.AddPathRequest) (*api.AddPathResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.addPathErr != nil {
		return nil, m.addPathErr
	}

	m.paths = append(m.paths, req.Path)
	return &api.AddPathResponse{
		Uuid: []byte("test-uuid"),
	}, nil
}

func (m *mockBGPServer) DeletePath(ctx context.Context, req *api.DeletePathRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.deletePathErr != nil {
		return m.deletePathErr
	}

	// In a real implementation, we'd find and remove the path
	return nil
}

func (m *mockBGPServer) ListPath(ctx context.Context, req *api.ListPathRequest, fn func(*api.Destination)) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.listPathErr != nil {
		return m.listPathErr
	}

	// Return mock destinations
	if len(m.paths) > 0 {
		dest := &api.Destination{
			Prefix: "10.0.0.0/24",
			Paths:  m.paths,
		}
		fn(dest)
	}
	return nil
}

func (m *mockBGPServer) WatchEvent(ctx context.Context, req *api.WatchEventRequest, fn func(*api.WatchEventResponse)) error {
	if m.watchEventErr != nil {
		return m.watchEventErr
	}

	// Simulate some events
	if m.watchCallback != nil {
		m.watchCallback(&api.WatchEventResponse{})
	}

	<-ctx.Done()
	return ctx.Err()
}

func (m *mockBGPServer) addMockPeer(addr string, asn uint32, state api.PeerState_SessionState) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.peers[addr] = &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: addr,
			PeerAsn:         asn,
			Description:     "Mock peer",
		},
		State: &api.PeerState{
			SessionState: state,
			RouterId:     "192.168.1.1",
			Messages: &api.Messages{
				Received: &api.Message{Total: 100},
				Sent:     &api.Message{Total: 50},
			},
		},
		Timers: &api.Timers{
			State: &api.TimersState{
				NegotiatedHoldTime: 90,
				Uptime:             timestamppb.New(time.Now()),
			},
		},
		Transport: &api.Transport{
			LocalAddress: "10.0.0.1",
		},
		AfiSafis: []*api.AfiSafi{
			{
				Config: &api.AfiSafiConfig{
					Enabled: true,
					Family: &api.Family{
						Afi:  api.Family_AFI_IP,
						Safi: api.Family_SAFI_UNICAST,
					},
				},
			},
		},
	}
}

// Test helper functions
func speakerTestConfig() *BGPConfig {
	return &BGPConfig{
		RouterID:        netip.MustParseAddr("10.0.0.1"),
		ASN:             65001,
		ListenPort:      1179, // Non-privileged port for testing
		EnabledFamilies: []AddressFamily{AFamilyIPv4Unicast},
	}
}

func testNeighborConfig() *NeighborConfig {
	return &NeighborConfig{
		Address:           netip.MustParseAddr("10.0.0.2"),
		ASN:               65002,
		Description:       "Test peer",
		HoldTime:          90,
		KeepaliveInterval: 30,
		ConnectRetry:      120,
		EnabledFamilies:   []AddressFamily{AFamilyIPv4Unicast},
	}
}

func speakerTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
}

// TestNewSpeaker tests speaker creation.
func TestNewSpeaker(t *testing.T) {
	tests := []struct {
		name        string
		config      *BGPConfig
		logger      *slog.Logger
		expectError bool
		errorType   error
	}{
		{
			name:        "valid configuration",
			config:      speakerTestConfig(),
			logger:      speakerTestLogger(),
			expectError: false,
		},
		{
			name:        "nil configuration",
			config:      nil,
			logger:      speakerTestLogger(),
			expectError: true,
			errorType:   ErrConfigNil,
		},
		{
			name:        "nil logger",
			config:      speakerTestConfig(),
			logger:      nil,
			expectError: true,
		},
		{
			name: "invalid router ID",
			config: &BGPConfig{
				RouterID:   netip.Addr{},
				ASN:        65001,
				ListenPort: 179,
			},
			logger:      speakerTestLogger(),
			expectError: true,
			errorType:   ErrInvalidRouterID,
		},
		{
			name: "invalid ASN - zero",
			config: &BGPConfig{
				RouterID:   netip.MustParseAddr("10.0.0.1"),
				ASN:        0,
				ListenPort: 179,
			},
			logger:      speakerTestLogger(),
			expectError: true,
			errorType:   ErrInvalidASN,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockBGPServer()
			var speaker *Speaker
			var err error

			if tt.logger != nil {
				speaker, err = NewSpeaker(tt.config, tt.logger, WithBGPServer(mock))
			} else {
				speaker, err = NewSpeaker(tt.config, tt.logger)
			}

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				if tt.errorType != nil && !errors.Is(err, tt.errorType) {
					t.Errorf("expected error type %T, got %T: %v", tt.errorType, err, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if speaker == nil {
					t.Fatal("expected speaker but got nil")
				}
			}
		})
	}
}

// TestSpeakerStartStop tests starting and stopping the speaker.
func TestSpeakerStartStop(t *testing.T) {
	ctx := context.Background()
	mock := newMockBGPServer()
	logger := speakerTestLogger()
	config := speakerTestConfig()

	speaker, err := NewSpeaker(config, logger, WithBGPServer(mock))
	if err != nil {
		t.Fatalf("failed to create speaker: %v", err)
	}

	// Test start
	err = speaker.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start speaker: %v", err)
	}

	if !speaker.IsStarted() {
		t.Error("speaker should be started")
	}

	// Test double start
	err = speaker.Start(ctx)
	if !errors.Is(err, ErrSpeakerAlreadyRunning) {
		t.Errorf("expected ErrSpeakerAlreadyRunning, got: %v", err)
	}

	// Test stop
	err = speaker.Stop(ctx)
	if err != nil {
		t.Fatalf("failed to stop speaker: %v", err)
	}

	if speaker.IsStarted() {
		t.Error("speaker should be stopped")
	}

	// Test stop when not started
	err = speaker.Stop(ctx)
	if !errors.Is(err, ErrSpeakerNotStarted) {
		t.Errorf("expected ErrSpeakerNotStarted, got: %v", err)
	}
}

// TestSpeakerStartError tests error handling during start.
func TestSpeakerStartError(t *testing.T) {
	ctx := context.Background()
	logger := speakerTestLogger()
	config := speakerTestConfig()

	tests := []struct {
		name      string
		setupMock func(*mockBGPServer)
	}{
		{
			name: "server start error",
			setupMock: func(m *mockBGPServer) {
				m.startErr = errors.New("start failed")
			},
		},
		{
			name: "start bgp error",
			setupMock: func(m *mockBGPServer) {
				m.startBgpErr = errors.New("start bgp failed")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockBGPServer()
			tt.setupMock(mock)

			speaker, err := NewSpeaker(config, logger, WithBGPServer(mock))
			if err != nil {
				t.Fatalf("failed to create speaker: %v", err)
			}

			err = speaker.Start(ctx)
			if err == nil {
				t.Fatal("expected error but got none")
			}
		})
	}
}

// TestAddPeer tests adding a BGP peer.
func TestSpeakerAddPeer(t *testing.T) {
	ctx := context.Background()
	mock := newMockBGPServer()
	logger := speakerTestLogger()
	config := speakerTestConfig()

	speaker, err := NewSpeaker(config, logger, WithBGPServer(mock))
	if err != nil {
		t.Fatalf("failed to create speaker: %v", err)
	}

	// Test add peer when not started
	err = speaker.AddPeer(ctx, testNeighborConfig())
	if !errors.Is(err, ErrSpeakerNotStarted) {
		t.Errorf("expected ErrSpeakerNotStarted, got: %v", err)
	}

	// Start speaker
	err = speaker.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start speaker: %v", err)
	}
	defer func() {
		closeErr := speaker.Stop(ctx)
		if closeErr != nil {
			t.Logf("failed to stop speaker: %v", closeErr)
		}
	}()

	// Test add peer with nil config
	err = speaker.AddPeer(ctx, nil)
	if !errors.Is(err, ErrConfigNil) {
		t.Errorf("expected ErrConfigNil, got: %v", err)
	}

	// Test add peer with invalid config
	invalidConfig := &NeighborConfig{
		Address: netip.Addr{}, // Invalid address
		ASN:     65002,
	}
	err = speaker.AddPeer(ctx, invalidConfig)
	if !errors.Is(err, ErrInvalidPeerAddress) {
		t.Errorf("expected ErrInvalidPeerAddress, got: %v", err)
	}

	// Test successful add peer
	err = speaker.AddPeer(ctx, testNeighborConfig())
	if err != nil {
		t.Fatalf("failed to add peer: %v", err)
	}

	// Verify peer was added
	if len(mock.peers) != 1 {
		t.Errorf("expected 1 peer, got %d", len(mock.peers))
	}
}

// TestAddPeerError tests error handling when adding a peer.
func TestAddPeerError(t *testing.T) {
	ctx := context.Background()
	mock := newMockBGPServer()
	mock.addPeerErr = errors.New("add peer failed")
	logger := speakerTestLogger()
	config := speakerTestConfig()

	speaker, err := NewSpeaker(config, logger, WithBGPServer(mock))
	if err != nil {
		t.Fatalf("failed to create speaker: %v", err)
	}

	err = speaker.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start speaker: %v", err)
	}
	defer func() {
		closeErr := speaker.Stop(ctx)
		if closeErr != nil {
			t.Logf("failed to stop speaker: %v", closeErr)
		}
	}()

	err = speaker.AddPeer(ctx, testNeighborConfig())
	if err == nil {
		t.Fatal("expected error but got none")
	}

	var peerErr *ErrPeerOperationFailed
	if !errors.As(err, &peerErr) {
		t.Errorf("expected ErrPeerOperationFailed, got: %T", err)
	}
}

// TestDeletePeer tests deleting a BGP peer.
func TestDeletePeer(t *testing.T) {
	ctx := context.Background()
	mock := newMockBGPServer()
	logger := speakerTestLogger()
	config := speakerTestConfig()

	speaker, err := NewSpeaker(config, logger, WithBGPServer(mock))
	if err != nil {
		t.Fatalf("failed to create speaker: %v", err)
	}

	peerAddr := netip.MustParseAddr("10.0.0.2")

	// Test delete peer when not started
	err = speaker.DeletePeer(ctx, peerAddr)
	if !errors.Is(err, ErrSpeakerNotStarted) {
		t.Errorf("expected ErrSpeakerNotStarted, got: %v", err)
	}

	// Start speaker and add peer
	err = speaker.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start speaker: %v", err)
	}
	defer func() {
		closeErr := speaker.Stop(ctx)
		if closeErr != nil {
			t.Logf("failed to stop speaker: %v", closeErr)
		}
	}()

	err = speaker.AddPeer(ctx, testNeighborConfig())
	if err != nil {
		t.Fatalf("failed to add peer: %v", err)
	}

	// Test delete with invalid address
	err = speaker.DeletePeer(ctx, netip.Addr{})
	if !errors.Is(err, ErrInvalidPeerAddress) {
		t.Errorf("expected ErrInvalidPeerAddress, got: %v", err)
	}

	// Test successful delete
	err = speaker.DeletePeer(ctx, peerAddr)
	if err != nil {
		t.Fatalf("failed to delete peer: %v", err)
	}

	if len(mock.peers) != 0 {
		t.Errorf("expected 0 peers, got %d", len(mock.peers))
	}
}

// TestGetPeer tests getting peer information.
func TestSpeakerGetPeer(t *testing.T) {
	ctx := context.Background()
	mock := newMockBGPServer()
	logger := speakerTestLogger()
	config := speakerTestConfig()

	speaker, err := NewSpeaker(config, logger, WithBGPServer(mock))
	if err != nil {
		t.Fatalf("failed to create speaker: %v", err)
	}

	peerAddr := netip.MustParseAddr("10.0.0.2")

	// Test get peer when not started
	_, err = speaker.GetPeer(ctx, peerAddr)
	if !errors.Is(err, ErrSpeakerNotStarted) {
		t.Errorf("expected ErrSpeakerNotStarted, got: %v", err)
	}

	// Start speaker
	err = speaker.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start speaker: %v", err)
	}
	defer func() {
		closeErr := speaker.Stop(ctx)
		if closeErr != nil {
			t.Logf("failed to stop speaker: %v", closeErr)
		}
	}()

	// Test get with invalid address
	_, err = speaker.GetPeer(ctx, netip.Addr{})
	if !errors.Is(err, ErrInvalidPeerAddress) {
		t.Errorf("expected ErrInvalidPeerAddress, got: %v", err)
	}

	// Test get non-existent peer
	_, err = speaker.GetPeer(ctx, peerAddr)
	if !errors.Is(err, ErrPeerNotFound) {
		t.Errorf("expected ErrPeerNotFound, got: %v", err)
	}

	// Add mock peer and test get
	mock.addMockPeer("10.0.0.2", 65002, api.PeerState_ESTABLISHED)

	info, err := speaker.GetPeer(ctx, peerAddr)
	if err != nil {
		t.Fatalf("failed to get peer: %v", err)
	}

	if info.Address != peerAddr {
		t.Errorf("expected address %s, got %s", peerAddr, info.Address)
	}
	if info.ASN != 65002 {
		t.Errorf("expected ASN 65002, got %d", info.ASN)
	}
	if info.State != PeerStateEstablished {
		t.Errorf("expected state established, got %s", info.State)
	}
}

// TestListPeers tests listing all peers.
func TestSpeakerListPeers(t *testing.T) {
	ctx := context.Background()
	mock := newMockBGPServer()
	logger := speakerTestLogger()
	config := speakerTestConfig()

	speaker, err := NewSpeaker(config, logger, WithBGPServer(mock))
	if err != nil {
		t.Fatalf("failed to create speaker: %v", err)
	}

	// Test list when not started
	_, err = speaker.ListPeers(ctx)
	if !errors.Is(err, ErrSpeakerNotStarted) {
		t.Errorf("expected ErrSpeakerNotStarted, got: %v", err)
	}

	// Start speaker
	err = speaker.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start speaker: %v", err)
	}
	defer func() {
		closeErr := speaker.Stop(ctx)
		if closeErr != nil {
			t.Logf("failed to stop speaker: %v", closeErr)
		}
	}()

	// Test empty list
	peers, err := speaker.ListPeers(ctx)
	if err != nil {
		t.Fatalf("failed to list peers: %v", err)
	}
	if len(peers) != 0 {
		t.Errorf("expected 0 peers, got %d", len(peers))
	}

	// Add mock peers
	mock.addMockPeer("10.0.0.2", 65002, api.PeerState_ESTABLISHED)
	mock.addMockPeer("10.0.0.3", 65003, api.PeerState_ACTIVE)

	peers, err = speaker.ListPeers(ctx)
	if err != nil {
		t.Fatalf("failed to list peers: %v", err)
	}
	if len(peers) != 2 {
		t.Errorf("expected 2 peers, got %d", len(peers))
	}
}

// TestGetPeerState tests getting peer state.
func TestGetPeerState(t *testing.T) {
	ctx := context.Background()
	mock := newMockBGPServer()
	logger := speakerTestLogger()
	config := speakerTestConfig()

	speaker, err := NewSpeaker(config, logger, WithBGPServer(mock))
	if err != nil {
		t.Fatalf("failed to create speaker: %v", err)
	}

	err = speaker.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start speaker: %v", err)
	}
	defer func() {
		closeErr := speaker.Stop(ctx)
		if closeErr != nil {
			t.Logf("failed to stop speaker: %v", closeErr)
		}
	}()

	peerAddr := netip.MustParseAddr("10.0.0.2")
	mock.addMockPeer("10.0.0.2", 65002, api.PeerState_ESTABLISHED)

	state, err := speaker.GetPeerState(ctx, peerAddr)
	if err != nil {
		t.Fatalf("failed to get peer state: %v", err)
	}

	if state != PeerStateEstablished {
		t.Errorf("expected established, got %s", state)
	}
}

// TestResetPeer tests resetting a peer session.
func TestResetPeer(t *testing.T) {
	ctx := context.Background()
	mock := newMockBGPServer()
	logger := speakerTestLogger()
	config := speakerTestConfig()

	speaker, err := NewSpeaker(config, logger, WithBGPServer(mock))
	if err != nil {
		t.Fatalf("failed to create speaker: %v", err)
	}

	peerAddr := netip.MustParseAddr("10.0.0.2")

	// Test reset when not started
	err = speaker.ResetPeer(ctx, peerAddr, false)
	if !errors.Is(err, ErrSpeakerNotStarted) {
		t.Errorf("expected ErrSpeakerNotStarted, got: %v", err)
	}

	// Start speaker
	err = speaker.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start speaker: %v", err)
	}
	defer func() {
		closeErr := speaker.Stop(ctx)
		if closeErr != nil {
			t.Logf("failed to stop speaker: %v", closeErr)
		}
	}()

	// Test reset with invalid address
	err = speaker.ResetPeer(ctx, netip.Addr{}, false)
	if !errors.Is(err, ErrInvalidPeerAddress) {
		t.Errorf("expected ErrInvalidPeerAddress, got: %v", err)
	}

	// Add peer and test reset
	mock.addMockPeer("10.0.0.2", 65002, api.PeerState_ESTABLISHED)

	// Test hard reset
	err = speaker.ResetPeer(ctx, peerAddr, false)
	if err != nil {
		t.Fatalf("failed to hard reset peer: %v", err)
	}

	// Test soft reset
	err = speaker.ResetPeer(ctx, peerAddr, true)
	if err != nil {
		t.Fatalf("failed to soft reset peer: %v", err)
	}
}

// TestEnableDisablePeer tests enabling and disabling a peer.
func TestSpeakerEnableDisablePeer(t *testing.T) {
	ctx := context.Background()
	mock := newMockBGPServer()
	logger := speakerTestLogger()
	config := speakerTestConfig()

	speaker, err := NewSpeaker(config, logger, WithBGPServer(mock))
	if err != nil {
		t.Fatalf("failed to create speaker: %v", err)
	}

	peerAddr := netip.MustParseAddr("10.0.0.2")

	// Test when not started
	err = speaker.EnablePeer(ctx, peerAddr)
	if !errors.Is(err, ErrSpeakerNotStarted) {
		t.Errorf("expected ErrSpeakerNotStarted, got: %v", err)
	}

	err = speaker.DisablePeer(ctx, peerAddr)
	if !errors.Is(err, ErrSpeakerNotStarted) {
		t.Errorf("expected ErrSpeakerNotStarted, got: %v", err)
	}

	// Start speaker
	err = speaker.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start speaker: %v", err)
	}
	defer func() {
		closeErr := speaker.Stop(ctx)
		if closeErr != nil {
			t.Logf("failed to stop speaker: %v", closeErr)
		}
	}()

	// Add peer
	mock.addMockPeer("10.0.0.2", 65002, api.PeerState_ESTABLISHED)

	// Test with invalid address
	err = speaker.EnablePeer(ctx, netip.Addr{})
	if !errors.Is(err, ErrInvalidPeerAddress) {
		t.Errorf("expected ErrInvalidPeerAddress, got: %v", err)
	}

	err = speaker.DisablePeer(ctx, netip.Addr{})
	if !errors.Is(err, ErrInvalidPeerAddress) {
		t.Errorf("expected ErrInvalidPeerAddress, got: %v", err)
	}

	// Test disable
	err = speaker.DisablePeer(ctx, peerAddr)
	if err != nil {
		t.Fatalf("failed to disable peer: %v", err)
	}

	// Test enable
	err = speaker.EnablePeer(ctx, peerAddr)
	if err != nil {
		t.Fatalf("failed to enable peer: %v", err)
	}
}

// TestAddPath tests adding a BGP path.
func TestAddPath(t *testing.T) {
	ctx := context.Background()
	mock := newMockBGPServer()
	logger := speakerTestLogger()
	config := speakerTestConfig()

	speaker, err := NewSpeaker(config, logger, WithBGPServer(mock))
	if err != nil {
		t.Fatalf("failed to create speaker: %v", err)
	}

	path := &Path{
		Family:    AFamilyIPv4Unicast,
		Prefix:    netip.MustParsePrefix("192.168.1.0/24"),
		NextHop:   netip.MustParseAddr("10.0.0.1"),
		Origin:    OriginIGP,
		LocalPref: 100,
	}

	// Test when not started
	err = speaker.AddPath(ctx, path)
	if !errors.Is(err, ErrSpeakerNotStarted) {
		t.Errorf("expected ErrSpeakerNotStarted, got: %v", err)
	}

	// Start speaker
	err = speaker.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start speaker: %v", err)
	}
	defer func() {
		closeErr := speaker.Stop(ctx)
		if closeErr != nil {
			t.Logf("failed to stop speaker: %v", closeErr)
		}
	}()

	// Test nil path
	err = speaker.AddPath(ctx, nil)
	if err == nil {
		t.Fatal("expected error for nil path")
	}

	// Test successful add
	err = speaker.AddPath(ctx, path)
	if err != nil {
		t.Fatalf("failed to add path: %v", err)
	}

	if len(mock.paths) != 1 {
		t.Errorf("expected 1 path, got %d", len(mock.paths))
	}
}

// TestDeletePath tests deleting a BGP path.
func TestDeletePath(t *testing.T) {
	ctx := context.Background()
	mock := newMockBGPServer()
	logger := speakerTestLogger()
	config := speakerTestConfig()

	speaker, err := NewSpeaker(config, logger, WithBGPServer(mock))
	if err != nil {
		t.Fatalf("failed to create speaker: %v", err)
	}

	path := &Path{
		Family:  AFamilyIPv4Unicast,
		Prefix:  netip.MustParsePrefix("192.168.1.0/24"),
		NextHop: netip.MustParseAddr("10.0.0.1"),
	}

	// Test when not started
	err = speaker.DeletePath(ctx, path)
	if !errors.Is(err, ErrSpeakerNotStarted) {
		t.Errorf("expected ErrSpeakerNotStarted, got: %v", err)
	}

	// Start speaker
	err = speaker.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start speaker: %v", err)
	}
	defer func() {
		closeErr := speaker.Stop(ctx)
		if closeErr != nil {
			t.Logf("failed to stop speaker: %v", closeErr)
		}
	}()

	// Test nil path
	err = speaker.DeletePath(ctx, nil)
	if err == nil {
		t.Fatal("expected error for nil path")
	}

	// Test successful delete
	err = speaker.DeletePath(ctx, path)
	if err != nil {
		t.Fatalf("failed to delete path: %v", err)
	}
}

// TestGetRIB tests getting routes from the RIB.
func TestGetRIB(t *testing.T) {
	ctx := context.Background()
	mock := newMockBGPServer()
	logger := speakerTestLogger()
	config := speakerTestConfig()

	speaker, err := NewSpeaker(config, logger, WithBGPServer(mock))
	if err != nil {
		t.Fatalf("failed to create speaker: %v", err)
	}

	// Test when not started
	_, err = speaker.GetRIB(ctx, AFamilyIPv4Unicast, RIBLocal)
	if !errors.Is(err, ErrSpeakerNotStarted) {
		t.Errorf("expected ErrSpeakerNotStarted, got: %v", err)
	}

	// Start speaker
	err = speaker.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start speaker: %v", err)
	}
	defer func() {
		closeErr := speaker.Stop(ctx)
		if closeErr != nil {
			t.Logf("failed to stop speaker: %v", closeErr)
		}
	}()

	// Test get RIB
	paths, err := speaker.GetRIB(ctx, AFamilyIPv4Unicast, RIBLocal)
	if err != nil {
		t.Fatalf("failed to get RIB: %v", err)
	}

	// Initially empty (nil or empty slice both acceptable)
	if len(paths) != 0 {
		t.Errorf("expected empty paths, got %d", len(paths))
	}
}

// TestGetRIBError tests error handling for RIB query.
func TestGetRIBError(t *testing.T) {
	ctx := context.Background()
	mock := newMockBGPServer()
	mock.listPathErr = errors.New("list path failed")
	logger := speakerTestLogger()
	config := speakerTestConfig()

	speaker, err := NewSpeaker(config, logger, WithBGPServer(mock))
	if err != nil {
		t.Fatalf("failed to create speaker: %v", err)
	}

	err = speaker.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start speaker: %v", err)
	}
	defer func() {
		closeErr := speaker.Stop(ctx)
		if closeErr != nil {
			t.Logf("failed to stop speaker: %v", closeErr)
		}
	}()

	_, err = speaker.GetRIB(ctx, AFamilyIPv4Unicast, RIBLocal)
	if err == nil {
		t.Fatal("expected error but got none")
	}

	var ribErr *ErrRIBQueryFailed
	if !errors.As(err, &ribErr) {
		t.Errorf("expected ErrRIBQueryFailed, got: %T", err)
	}
}

// TestWatchEvent tests event watching.
func TestWatchEvent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	mock := newMockBGPServer()
	logger := speakerTestLogger()
	config := speakerTestConfig()

	speaker, err := NewSpeaker(config, logger, WithBGPServer(mock))
	if err != nil {
		t.Fatalf("failed to create speaker: %v", err)
	}

	// Test when not started
	_, err = speaker.WatchEvent(ctx)
	if !errors.Is(err, ErrSpeakerNotStarted) {
		t.Errorf("expected ErrSpeakerNotStarted, got: %v", err)
	}

	// Start speaker
	err = speaker.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start speaker: %v", err)
	}
	defer func() {
		closeErr := speaker.Stop(context.Background())
		if closeErr != nil {
			t.Logf("failed to stop speaker: %v", closeErr)
		}
	}()

	// Test watch with options
	eventCh, err := speaker.WatchEvent(ctx,
		WithPeerStateChanges(),
		WithPathChanges(),
		WithBestPathOnly(),
		WithFamilies(AFamilyIPv4Unicast),
	)
	if err != nil {
		t.Fatalf("failed to watch events: %v", err)
	}

	// Wait for channel to close due to context cancellation
	<-eventCh
}

// TestGetServerInfo tests getting server information.
func TestGetServerInfo(t *testing.T) {
	ctx := context.Background()
	mock := newMockBGPServer()
	logger := speakerTestLogger()
	config := speakerTestConfig()

	speaker, err := NewSpeaker(config, logger, WithBGPServer(mock))
	if err != nil {
		t.Fatalf("failed to create speaker: %v", err)
	}

	// Test when not started
	_, err = speaker.GetServerInfo(ctx)
	if !errors.Is(err, ErrSpeakerNotStarted) {
		t.Errorf("expected ErrSpeakerNotStarted, got: %v", err)
	}

	// Start speaker
	err = speaker.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start speaker: %v", err)
	}
	defer func() {
		closeErr := speaker.Stop(ctx)
		if closeErr != nil {
			t.Logf("failed to stop speaker: %v", closeErr)
		}
	}()

	// Add some mock peers
	mock.addMockPeer("10.0.0.2", 65002, api.PeerState_ESTABLISHED)
	mock.addMockPeer("10.0.0.3", 65003, api.PeerState_ACTIVE)

	info, err := speaker.GetServerInfo(ctx)
	if err != nil {
		t.Fatalf("failed to get server info: %v", err)
	}

	if info.ASN != config.ASN {
		t.Errorf("expected ASN %d, got %d", config.ASN, info.ASN)
	}
	if info.PeerCount != 2 {
		t.Errorf("expected 2 peers, got %d", info.PeerCount)
	}
	if info.EstablishedCount != 1 {
		t.Errorf("expected 1 established, got %d", info.EstablishedCount)
	}
}

// TestSpeakerCallbacks tests callback invocation.
func TestSpeakerCallbacks(t *testing.T) {
	_, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	mock := newMockBGPServer()
	logger := speakerTestLogger()
	config := speakerTestConfig()

	peerStateCallbackCalled := false
	routeReceivedCallbackCalled := false

	speaker, err := NewSpeaker(config, logger,
		WithBGPServer(mock),
		WithPeerStateCallback(func(addr netip.Addr, state PeerState) {
			peerStateCallbackCalled = true
		}),
		WithRouteReceivedCallback(func(route interface{}) {
			routeReceivedCallbackCalled = true
		}),
	)
	if err != nil {
		t.Fatalf("failed to create speaker: %v", err)
	}

	// The callbacks would be invoked via WatchEvent in real usage
	// Just verify they were set
	if speaker.onPeerStateChange == nil {
		t.Error("peer state callback not set")
	}
	if speaker.onRouteReceived == nil {
		t.Error("route received callback not set")
	}

	// Simulate callback invocation
	speaker.onPeerStateChange(netip.MustParseAddr("10.0.0.1"), PeerStateEstablished)
	if !peerStateCallbackCalled {
		t.Error("peer state callback not invoked")
	}

	speaker.onRouteReceived(&Path{})
	if !routeReceivedCallbackCalled {
		t.Error("route received callback not invoked")
	}
}

// TestNeighborConfigWithAllOptions tests neighbor config with all options set.
func TestNeighborConfigWithAllOptions(t *testing.T) {
	ctx := context.Background()
	mock := newMockBGPServer()
	logger := speakerTestLogger()
	config := speakerTestConfig()

	speaker, err := NewSpeaker(config, logger, WithBGPServer(mock))
	if err != nil {
		t.Fatalf("failed to create speaker: %v", err)
	}

	err = speaker.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start speaker: %v", err)
	}
	defer func() {
		closeErr := speaker.Stop(ctx)
		if closeErr != nil {
			t.Logf("failed to stop speaker: %v", closeErr)
		}
	}()

	// Create neighbor config with all options
	neighborCfg := &NeighborConfig{
		Address:              netip.MustParseAddr("10.0.0.2"),
		ASN:                  65002,
		Description:          "Full config peer",
		HoldTime:             180,
		KeepaliveInterval:    60,
		ConnectRetry:         30,
		Password:             "secret",
		PassiveMode:          true,
		EBGPMultihop:         3,
		EnabledFamilies:      []AddressFamily{AFamilyIPv4Unicast, AFamilyIPv6Unicast, AFamilyEVPN},
		RouteReflectorClient: true,
		RemovePrivateAS:      true,
		AdminDown:            true,
	}

	err = speaker.AddPeer(ctx, neighborCfg)
	if err != nil {
		t.Fatalf("failed to add peer with full config: %v", err)
	}

	// Verify peer was added with correct settings
	peer := mock.peers["10.0.0.2"]
	if peer == nil {
		t.Fatal("peer not found")
	}

	if peer.Conf.Description != "Full config peer" {
		t.Errorf("description mismatch: %s", peer.Conf.Description)
	}
	if peer.Conf.AuthPassword != "secret" {
		t.Error("password not set")
	}
	if !peer.Transport.PassiveMode {
		t.Error("passive mode not set")
	}
	if peer.EbgpMultihop == nil || !peer.EbgpMultihop.Enabled {
		t.Error("EBGP multihop not enabled")
	}
	if peer.RouteReflector == nil || !peer.RouteReflector.RouteReflectorClient {
		t.Error("route reflector client not set")
	}
	if len(peer.AfiSafis) != 3 {
		t.Errorf("expected 3 address families, got %d", len(peer.AfiSafis))
	}
}

// TestPathWithCommunities tests adding paths with communities.
func TestPathWithCommunities(t *testing.T) {
	ctx := context.Background()
	mock := newMockBGPServer()
	logger := speakerTestLogger()
	config := speakerTestConfig()

	speaker, err := NewSpeaker(config, logger, WithBGPServer(mock))
	if err != nil {
		t.Fatalf("failed to create speaker: %v", err)
	}

	err = speaker.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start speaker: %v", err)
	}
	defer func() {
		closeErr := speaker.Stop(ctx)
		if closeErr != nil {
			t.Logf("failed to stop speaker: %v", closeErr)
		}
	}()

	path := &Path{
		Family:      AFamilyIPv4Unicast,
		Prefix:      netip.MustParsePrefix("192.168.1.0/24"),
		NextHop:     netip.MustParseAddr("10.0.0.1"),
		Origin:      OriginIGP,
		ASPath:      []uint32{65001, 65002, 65003},
		LocalPref:   100,
		MED:         50,
		Communities: []uint32{0xFFFF029A, 0xFFFF029B}, // NO_EXPORT, NO_ADVERTISE
	}

	err = speaker.AddPath(ctx, path)
	if err != nil {
		t.Fatalf("failed to add path with communities: %v", err)
	}
}

// TestConfig tests the Config() method.
func TestConfig(t *testing.T) {
	mock := newMockBGPServer()
	logger := speakerTestLogger()
	config := speakerTestConfig()

	speaker, err := NewSpeaker(config, logger, WithBGPServer(mock))
	if err != nil {
		t.Fatalf("failed to create speaker: %v", err)
	}

	returnedConfig := speaker.Config()
	if returnedConfig != config {
		t.Error("Config() did not return the same config")
	}
}

// TestAddPathError tests error handling when adding a path.
func TestAddPathError(t *testing.T) {
	ctx := context.Background()
	mock := newMockBGPServer()
	mock.addPathErr = errors.New("add path failed")
	logger := speakerTestLogger()
	config := speakerTestConfig()

	speaker, err := NewSpeaker(config, logger, WithBGPServer(mock))
	if err != nil {
		t.Fatalf("failed to create speaker: %v", err)
	}

	err = speaker.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start speaker: %v", err)
	}
	defer func() {
		closeErr := speaker.Stop(ctx)
		if closeErr != nil {
			t.Logf("failed to stop speaker: %v", closeErr)
		}
	}()

	path := &Path{
		Family:  AFamilyIPv4Unicast,
		Prefix:  netip.MustParsePrefix("192.168.1.0/24"),
		NextHop: netip.MustParseAddr("10.0.0.1"),
	}

	err = speaker.AddPath(ctx, path)
	if err == nil {
		t.Fatal("expected error but got none")
	}

	var pathErr *ErrPathOperationFailed
	if !errors.As(err, &pathErr) {
		t.Errorf("expected ErrPathOperationFailed, got: %T", err)
	}
}

// TestDeletePathError tests error handling when deleting a path.
func TestDeletePathError(t *testing.T) {
	ctx := context.Background()
	mock := newMockBGPServer()
	mock.deletePathErr = errors.New("delete path failed")
	logger := speakerTestLogger()
	config := speakerTestConfig()

	speaker, err := NewSpeaker(config, logger, WithBGPServer(mock))
	if err != nil {
		t.Fatalf("failed to create speaker: %v", err)
	}

	err = speaker.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start speaker: %v", err)
	}
	defer func() {
		closeErr := speaker.Stop(ctx)
		if closeErr != nil {
			t.Logf("failed to stop speaker: %v", closeErr)
		}
	}()

	path := &Path{
		Family:  AFamilyIPv4Unicast,
		Prefix:  netip.MustParsePrefix("192.168.1.0/24"),
		NextHop: netip.MustParseAddr("10.0.0.1"),
	}

	err = speaker.DeletePath(ctx, path)
	if err == nil {
		t.Fatal("expected error but got none")
	}

	var pathErr *ErrPathOperationFailed
	if !errors.As(err, &pathErr) {
		t.Errorf("expected ErrPathOperationFailed, got: %T", err)
	}
}

// TestPeerInfoConversion tests the peer info conversion helper.
func TestPeerInfoConversion(t *testing.T) {
	mock := newMockBGPServer()
	logger := speakerTestLogger()
	config := speakerTestConfig()

	speaker, err := NewSpeaker(config, logger, WithBGPServer(mock))
	if err != nil {
		t.Fatalf("failed to create speaker: %v", err)
	}

	// Test nil peer
	info := speaker.peerToPeerInfo(nil)
	if info != nil {
		t.Error("expected nil for nil peer")
	}

	// Test peer with nil conf
	peer := &api.Peer{}
	info = speaker.peerToPeerInfo(peer)
	if info != nil {
		t.Error("expected nil for peer with nil conf")
	}

	// Test full peer conversion
	peer = &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "10.0.0.2",
			PeerAsn:         65002,
			Description:     "Test peer",
		},
		State: &api.PeerState{
			SessionState: api.PeerState_ESTABLISHED,
			AdminState:   api.PeerState_UP,
			RouterId:     "192.168.1.1",
			Messages: &api.Messages{
				Received: &api.Message{Total: 100},
				Sent:     &api.Message{Total: 50},
			},
		},
		Timers: &api.Timers{
			State: &api.TimersState{
				NegotiatedHoldTime: 90,
				Uptime:             timestamppb.New(time.Now()),
			},
		},
		Transport: &api.Transport{
			LocalAddress: "10.0.0.1",
		},
		AfiSafis: []*api.AfiSafi{
			{
				Config: &api.AfiSafiConfig{
					Enabled: true,
					Family: &api.Family{
						Afi:  api.Family_AFI_IP,
						Safi: api.Family_SAFI_UNICAST,
					},
				},
			},
		},
	}

	info = speaker.peerToPeerInfo(peer)
	if info == nil {
		t.Fatal("expected non-nil peer info")
	}

	if info.Address != netip.MustParseAddr("10.0.0.2") {
		t.Errorf("unexpected address: %s", info.Address)
	}
	if info.ASN != 65002 {
		t.Errorf("unexpected ASN: %d", info.ASN)
	}
	if info.State != PeerStateEstablished {
		t.Errorf("unexpected state: %s", info.State)
	}
	if info.MessagesReceived != 100 {
		t.Errorf("unexpected messages received: %d", info.MessagesReceived)
	}
	if info.MessagesSent != 50 {
		t.Errorf("unexpected messages sent: %d", info.MessagesSent)
	}
	if info.NegotiatedHoldTime != 90 {
		t.Errorf("unexpected hold time: %d", info.NegotiatedHoldTime)
	}
	if info.LocalAddress != netip.MustParseAddr("10.0.0.1") {
		t.Errorf("unexpected local address: %s", info.LocalAddress)
	}
}

// TestSessionStateConversion tests session state conversion.
func TestSessionStateConversion(t *testing.T) {
	mock := newMockBGPServer()
	logger := speakerTestLogger()
	config := speakerTestConfig()

	speaker, err := NewSpeaker(config, logger, WithBGPServer(mock))
	if err != nil {
		t.Fatalf("failed to create speaker: %v", err)
	}

	tests := []struct {
		input    api.PeerState_SessionState
		expected PeerState
	}{
		{api.PeerState_IDLE, PeerStateIdle},
		{api.PeerState_CONNECT, PeerStateConnect},
		{api.PeerState_ACTIVE, PeerStateActive},
		{api.PeerState_OPENSENT, PeerStateOpenSent},
		{api.PeerState_OPENCONFIRM, PeerStateOpenConfirm},
		{api.PeerState_ESTABLISHED, PeerStateEstablished},
		{api.PeerState_SessionState(99), PeerStateIdle}, // Unknown
	}

	for _, tt := range tests {
		result := speaker.sessionStateToState(tt.input)
		if result != tt.expected {
			t.Errorf("sessionStateToState(%v) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

// TestAddressFamilyConversion tests address family conversion.
func TestAddressFamilyConversion(t *testing.T) {
	mock := newMockBGPServer()
	logger := speakerTestLogger()
	config := speakerTestConfig()

	speaker, err := NewSpeaker(config, logger, WithBGPServer(mock))
	if err != nil {
		t.Fatalf("failed to create speaker: %v", err)
	}

	// Test to API
	tests := []struct {
		input    AddressFamily
		expected *api.Family
	}{
		{AFamilyIPv4Unicast, &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST}},
		{AFamilyIPv6Unicast, &api.Family{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_UNICAST}},
		{AFamilyEVPN, &api.Family{Afi: api.Family_AFI_L2VPN, Safi: api.Family_SAFI_EVPN}},
		{AddressFamily(99), &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST}}, // Default
	}

	for _, tt := range tests {
		result := speaker.addressFamilyToAPI(tt.input)
		if result.Afi != tt.expected.Afi || result.Safi != tt.expected.Safi {
			t.Errorf("addressFamilyToAPI(%v) = %v, want %v", tt.input, result, tt.expected)
		}
	}

	// Test from API
	fromAPITests := []struct {
		input    *api.Family
		expected AddressFamily
	}{
		{&api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST}, AFamilyIPv4Unicast},
		{&api.Family{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_UNICAST}, AFamilyIPv6Unicast},
		{&api.Family{Afi: api.Family_AFI_L2VPN, Safi: api.Family_SAFI_EVPN}, AFamilyEVPN},
		{nil, AFamilyIPv4Unicast}, // Default for nil
	}

	for _, tt := range fromAPITests {
		result := speaker.apiFamilyToAddressFamily(tt.input)
		if result != tt.expected {
			t.Errorf("apiFamilyToAddressFamily(%v) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

// TestRIBTypeConversion tests RIB type conversion.
func TestRIBTypeConversion(t *testing.T) {
	mock := newMockBGPServer()
	logger := speakerTestLogger()
	config := speakerTestConfig()

	speaker, err := NewSpeaker(config, logger, WithBGPServer(mock))
	if err != nil {
		t.Fatalf("failed to create speaker: %v", err)
	}

	tests := []struct {
		input    RIBType
		expected api.TableType
	}{
		{RIBLocal, api.TableType_LOCAL},
		{RIBAdjIn, api.TableType_ADJ_IN},
		{RIBAdjOut, api.TableType_ADJ_OUT},
		{RIBType(99), api.TableType_GLOBAL}, // Default
	}

	for _, tt := range tests {
		result := speaker.ribTypeToTableType(tt.input)
		if result != tt.expected {
			t.Errorf("ribTypeToTableType(%v) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

// TestAPIPathConversion tests path conversion to/from API.
func TestAPIPathConversion(t *testing.T) {
	mock := newMockBGPServer()
	logger := speakerTestLogger()
	config := speakerTestConfig()

	speaker, err := NewSpeaker(config, logger, WithBGPServer(mock))
	if err != nil {
		t.Fatalf("failed to create speaker: %v", err)
	}

	// Test nil path conversion
	result := speaker.apiPathToPath(nil, AFamilyIPv4Unicast)
	if result != nil {
		t.Error("expected nil for nil path")
	}

	// Test path with flags
	apiPath := &api.Path{
		Best:  true,
		Stale: true,
		Age:   timestamppb.Now(),
	}

	result = speaker.apiPathToPath(apiPath, AFamilyIPv4Unicast)
	if result == nil {
		t.Fatal("expected non-nil path")
	}
	if !result.Best {
		t.Error("expected Best to be true")
	}
	if !result.Stale {
		t.Error("expected Stale to be true")
	}
}

// TestPathWithIPv6NextHop tests path with IPv6 next hop.
func TestPathWithIPv6NextHop(t *testing.T) {
	ctx := context.Background()
	mock := newMockBGPServer()
	logger := speakerTestLogger()
	config := speakerTestConfig()

	speaker, err := NewSpeaker(config, logger, WithBGPServer(mock))
	if err != nil {
		t.Fatalf("failed to create speaker: %v", err)
	}

	err = speaker.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start speaker: %v", err)
	}
	defer func() {
		closeErr := speaker.Stop(ctx)
		if closeErr != nil {
			t.Logf("failed to stop speaker: %v", closeErr)
		}
	}()

	path := &Path{
		Family:    AFamilyIPv6Unicast,
		Prefix:    netip.MustParsePrefix("2001:db8::/32"),
		NextHop:   netip.MustParseAddr("2001:db8::1"),
		Origin:    OriginIGP,
		LocalPref: 100,
	}

	err = speaker.AddPath(ctx, path)
	if err != nil {
		t.Fatalf("failed to add IPv6 path: %v", err)
	}
}

// TestPathWithInvalidPrefix tests adding path with invalid prefix.
func TestPathWithInvalidPrefix(t *testing.T) {
	ctx := context.Background()
	mock := newMockBGPServer()
	logger := speakerTestLogger()
	config := speakerTestConfig()

	speaker, err := NewSpeaker(config, logger, WithBGPServer(mock))
	if err != nil {
		t.Fatalf("failed to create speaker: %v", err)
	}

	err = speaker.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start speaker: %v", err)
	}
	defer func() {
		closeErr := speaker.Stop(ctx)
		if closeErr != nil {
			t.Logf("failed to stop speaker: %v", closeErr)
		}
	}()

	path := &Path{
		Family:  AFamilyIPv4Unicast,
		Prefix:  netip.Prefix{}, // Invalid prefix
		NextHop: netip.MustParseAddr("10.0.0.1"),
	}

	err = speaker.AddPath(ctx, path)
	if err == nil {
		t.Fatal("expected error for invalid prefix")
	}
}

// TestGracefulRestartConfig tests configuration with graceful restart enabled.
func TestGracefulRestartConfig(t *testing.T) {
	ctx := context.Background()
	mock := newMockBGPServer()
	logger := speakerTestLogger()

	config := &BGPConfig{
		RouterID:               netip.MustParseAddr("10.0.0.1"),
		ASN:                    65001,
		ListenPort:             1179,
		ListenAddresses:        []netip.Addr{netip.MustParseAddr("10.0.0.1")},
		GracefulRestartEnabled: true,
		GracefulRestartTime:    120,
		EnabledFamilies:        []AddressFamily{AFamilyIPv4Unicast},
	}

	speaker, err := NewSpeaker(config, logger, WithBGPServer(mock))
	if err != nil {
		t.Fatalf("failed to create speaker: %v", err)
	}

	err = speaker.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start speaker: %v", err)
	}
	defer func() {
		closeErr := speaker.Stop(ctx)
		if closeErr != nil {
			t.Logf("failed to stop speaker: %v", closeErr)
		}
	}()

	// Verify graceful restart was configured
	if mock.global.GracefulRestart == nil {
		t.Fatal("graceful restart not configured")
	}
	if !mock.global.GracefulRestart.Enabled {
		t.Error("graceful restart not enabled")
	}
	if mock.global.GracefulRestart.RestartTime != 120 {
		t.Errorf("unexpected restart time: %d", mock.global.GracefulRestart.RestartTime)
	}

	// Verify listen addresses
	if len(mock.global.ListenAddresses) != 1 {
		t.Errorf("expected 1 listen address, got %d", len(mock.global.ListenAddresses))
	}
}

// TestUpdatePeerError tests error handling when updating a peer.
func TestUpdatePeerError(t *testing.T) {
	ctx := context.Background()
	mock := newMockBGPServer()
	mock.updatePeerErr = errors.New("update peer failed")
	logger := speakerTestLogger()
	config := speakerTestConfig()

	speaker, err := NewSpeaker(config, logger, WithBGPServer(mock))
	if err != nil {
		t.Fatalf("failed to create speaker: %v", err)
	}

	err = speaker.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start speaker: %v", err)
	}
	defer func() {
		closeErr := speaker.Stop(ctx)
		if closeErr != nil {
			t.Logf("failed to stop speaker: %v", closeErr)
		}
	}()

	peerAddr := netip.MustParseAddr("10.0.0.2")
	mock.addMockPeer("10.0.0.2", 65002, api.PeerState_ESTABLISHED)

	err = speaker.EnablePeer(ctx, peerAddr)
	if err == nil {
		t.Fatal("expected error but got none")
	}

	var peerErr *ErrPeerOperationFailed
	if !errors.As(err, &peerErr) {
		t.Errorf("expected ErrPeerOperationFailed, got: %T", err)
	}
}
