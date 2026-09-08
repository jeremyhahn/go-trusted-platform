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

package modes

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v4/api"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
)

// mockBGPServer implements bgp.BGPServerInterface for testing.
type mockBGPServer struct {
	keychains      []*api.TcpAoKeychain
	policies       *api.SetPoliciesRequest
	mu             sync.Mutex
	started        bool
	peers          map[string]*api.Peer
	paths          []*api.Path
	startErr       error
	startBgpErr    error
	addPeerErr     error
	deletePeerErr  error
	addPathErr     error
	deletePathErr  error
	watchResponses []*api.WatchEventResponse
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
	m.started = false
}

func (m *mockBGPServer) StartBgp(ctx context.Context, req *api.StartBgpRequest) error {
	return m.startBgpErr
}

func (m *mockBGPServer) StopBgp(ctx context.Context, req *api.StopBgpRequest) error {
	return nil
}

func (m *mockBGPServer) AddPeer(ctx context.Context, req *api.AddPeerRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.addPeerErr != nil {
		return m.addPeerErr
	}
	m.peers[req.Peer.Conf.NeighborAddress] = req.Peer
	return nil
}

func (m *mockBGPServer) DeletePeer(ctx context.Context, req *api.DeletePeerRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deletePeerErr != nil {
		return m.deletePeerErr
	}
	delete(m.peers, req.Address)
	return nil
}

func (m *mockBGPServer) UpdatePeer(ctx context.Context, req *api.UpdatePeerRequest) (*api.UpdatePeerResponse, error) {
	return &api.UpdatePeerResponse{}, nil
}

func (m *mockBGPServer) GetBgp(ctx context.Context, req *api.GetBgpRequest) (*api.GetBgpResponse, error) {
	return &api.GetBgpResponse{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "10.0.0.1",
			ListenPort: 179,
		},
	}, nil
}

func (m *mockBGPServer) ListPeer(ctx context.Context, req *api.ListPeerRequest, fn func(*api.Peer)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, peer := range m.peers {
		fn(peer)
	}
	return nil
}

func (m *mockBGPServer) ResetPeer(ctx context.Context, req *api.ResetPeerRequest) error {
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
	return &api.AddPathResponse{Uuid: []byte("test-uuid")}, nil
}

func (m *mockBGPServer) DeletePath(ctx context.Context, req *api.DeletePathRequest) error {
	return m.deletePathErr
}

func (m *mockBGPServer) ListPath(ctx context.Context, req *api.ListPathRequest, fn func(*api.Destination)) error {
	return nil
}

func (m *mockBGPServer) WatchEvent(ctx context.Context, req *api.WatchEventRequest, fn func(*api.WatchEventResponse)) error {
	for _, resp := range m.watchResponses {
		fn(resp)
	}
	return nil
}

func (m *mockBGPServer) AddTcpAoKeychain(ctx context.Context, req *api.AddTcpAoKeychainRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if req == nil || req.Keychain == nil {
		return errors.New("keychain is required")
	}
	m.keychains = append(m.keychains, req.Keychain)
	return nil
}

func (m *mockBGPServer) SetPolicies(ctx context.Context, req *api.SetPoliciesRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policies = req
	return nil
}

// Helper functions for tests

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func testBGPConfig() *bgp.BGPConfig {
	return &bgp.BGPConfig{
		RouterID:   netip.MustParseAddr("10.0.0.1"),
		ASN:        65001,
		ListenPort: 1179, // Non-privileged port for testing
		Tier:       bgp.SpeakerTierBackbone,
	}
}

func createTestSpeaker(t *testing.T) (*bgp.Speaker, *mockBGPServer) {
	t.Helper()

	mockServer := newMockBGPServer()
	config := testBGPConfig()

	speaker, err := bgp.NewSpeaker(
		config,
		testLogger(),
		bgp.WithBGPServer(mockServer),
	)
	if err != nil {
		t.Fatalf("failed to create speaker: %v", err)
	}

	ctx := context.Background()
	if err := speaker.Start(ctx); err != nil {
		t.Fatalf("failed to start speaker: %v", err)
	}

	return speaker, mockServer
}

func createTestIPv6Prefix() net.IPNet {
	_, prefix, _ := net.ParseCIDR("2602:F5BB::/36")
	return *prefix
}

func createTestIPv4Prefix() net.IPNet {
	_, prefix, _ := net.ParseCIDR("23.143.36.0/24")
	return *prefix
}

func createTestSigningKey(t *testing.T) *RouteSigningKey {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate signing key: %v", err)
	}

	return &RouteSigningKey{
		KeyID:      "test-key-001",
		PublicKey:  pub,
		PrivateKey: priv,
	}
}

func validBackboneConfig() *TransitModeConfig {
	return &TransitModeConfig{
		Tier:                bgp.SpeakerTierBackbone,
		IPv6Prefixes:        []net.IPNet{createTestIPv6Prefix()},
		IPv4Prefixes:        []net.IPNet{createTestIPv4Prefix()},
		LocalASN:            65001,
		NextHop:             netip.MustParseAddr("10.0.0.1"),
		LocalPref:           100,
		MED:                 0,
		MinGatewaysForRoute: 3,
	}
}

func validDatacenterConfig() *TransitModeConfig {
	_, ipv6Prefix, _ := net.ParseCIDR("2602:F5BB:1::/48")
	return &TransitModeConfig{
		Tier:                bgp.SpeakerTierDatacenter,
		IPv6Prefixes:        []net.IPNet{*ipv6Prefix},
		IPv4Prefixes:        []net.IPNet{createTestIPv4Prefix()},
		LocalASN:            65001,
		NextHop:             netip.MustParseAddr("10.0.0.1"),
		LocalPref:           100,
		MinGatewaysForRoute: 3,
	}
}

func validCoordinatorConfig(t *testing.T) *TransitModeConfig {
	return &TransitModeConfig{
		Tier:                bgp.SpeakerTierCoordinator,
		IPv6Prefixes:        []net.IPNet{createTestIPv6Prefix()},
		IPv4Prefixes:        []net.IPNet{createTestIPv4Prefix()},
		LocalASN:            65001,
		NextHop:             netip.MustParseAddr("10.0.0.1"),
		RouteSigningKey:     createTestSigningKey(t),
		MinGatewaysForRoute: 3,
	}
}

// Test cases

func TestNewTransitModeHandler_Success(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()

	handler, err := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if handler == nil {
		t.Fatal("expected non-nil handler")
	}

	if handler.config != config {
		t.Error("config not set correctly")
	}

	if handler.bgpSpeaker != speaker {
		t.Error("speaker not set correctly")
	}
}

func TestNewTransitModeHandler_NilConfig(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	_, err := NewTransitModeHandler(nil, speaker)
	if !errors.Is(err, ErrConfigNil) {
		t.Errorf("expected ErrConfigNil, got: %v", err)
	}
}

func TestNewTransitModeHandler_NilSpeaker(t *testing.T) {
	config := validBackboneConfig()

	_, err := NewTransitModeHandler(config, nil)
	if !errors.Is(err, ErrSpeakerNil) {
		t.Errorf("expected ErrSpeakerNil, got: %v", err)
	}
}

func TestNewTransitModeHandler_InvalidTier(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	config.Tier = bgp.SpeakerTierUnknown

	_, err := NewTransitModeHandler(config, speaker)
	if !errors.Is(err, ErrInvalidTier) {
		t.Errorf("expected ErrInvalidTier, got: %v", err)
	}
}

func TestNewTransitModeHandler_NoPrefixes(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := &TransitModeConfig{
		Tier:     bgp.SpeakerTierBackbone,
		LocalASN: 65001,
	}

	_, err := NewTransitModeHandler(config, speaker)
	if !errors.Is(err, ErrNoPrefixesConfigured) {
		t.Errorf("expected ErrNoPrefixesConfigured, got: %v", err)
	}
}

func TestNewTransitModeHandler_InvalidASN(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	config.LocalASN = 0

	_, err := NewTransitModeHandler(config, speaker)
	if !errors.Is(err, ErrInvalidASN) {
		t.Errorf("expected ErrInvalidASN, got: %v", err)
	}
}

func TestNewTransitModeHandler_RPKIEnabledNoValidators(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	config.RPKIEnabled = true
	config.RPKIValidators = nil

	_, err := NewTransitModeHandler(config, speaker)
	if !errors.Is(err, ErrNoRPKIValidators) {
		t.Errorf("expected ErrNoRPKIValidators, got: %v", err)
	}
}

func TestNewTransitModeHandler_CoordinatorWithoutSigningKey(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := &TransitModeConfig{
		Tier:         bgp.SpeakerTierCoordinator,
		IPv6Prefixes: []net.IPNet{createTestIPv6Prefix()},
		LocalASN:     65001,
	}

	_, err := NewTransitModeHandler(config, speaker)
	if !errors.Is(err, ErrSigningKeyRequired) {
		t.Errorf("expected ErrSigningKeyRequired, got: %v", err)
	}
}

func TestTransitModeConfig_Validate_Success(t *testing.T) {
	tests := []struct {
		name   string
		config *TransitModeConfig
	}{
		{
			name:   "backbone config",
			config: validBackboneConfig(),
		},
		{
			name:   "datacenter config",
			config: validDatacenterConfig(),
		},
		{
			name:   "coordinator config",
			config: validCoordinatorConfig(t),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.config.Validate(); err != nil {
				t.Errorf("expected valid config, got error: %v", err)
			}
		})
	}
}

func TestTransitModeConfig_Validate_InvalidIPv6Prefix(t *testing.T) {
	config := validBackboneConfig()
	config.IPv6Prefixes = []net.IPNet{{IP: net.ParseIP("192.168.1.0"), Mask: net.CIDRMask(24, 32)}}

	err := config.Validate()
	if !errors.Is(err, ErrInvalidIPv6Prefix) {
		t.Errorf("expected ErrInvalidIPv6Prefix, got: %v", err)
	}
}

func TestTransitModeConfig_Validate_InvalidIPv4Prefix(t *testing.T) {
	config := validBackboneConfig()
	config.IPv4Prefixes = []net.IPNet{{IP: net.ParseIP("2001:db8::"), Mask: net.CIDRMask(32, 128)}}

	err := config.Validate()
	if !errors.Is(err, ErrInvalidIPv4Prefix) {
		t.Errorf("expected ErrInvalidIPv4Prefix, got: %v", err)
	}
}

func TestTransitModeConfig_Validate_NegativeMinGateways(t *testing.T) {
	config := validBackboneConfig()
	config.MinGatewaysForRoute = -1

	err := config.Validate()
	if !errors.Is(err, ErrInvalidMinGateways) {
		t.Errorf("expected ErrInvalidMinGateways, got: %v", err)
	}
}

func TestTransitModeHandler_Start_Success(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	handler, err := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := context.Background()
	if err := handler.Start(ctx); err != nil {
		t.Fatalf("expected no error starting handler, got: %v", err)
	}
	defer handler.Stop(ctx)

	if !handler.running.Load() {
		t.Error("expected handler to be running")
	}

	status := handler.GetStatus()
	if !status.Running {
		t.Error("expected status to show running")
	}
}

func TestTransitModeHandler_Start_AlreadyRunning(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	handler, _ := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))

	ctx := context.Background()
	_ = handler.Start(ctx)
	defer handler.Stop(ctx)

	err := handler.Start(ctx)
	if !errors.Is(err, ErrAlreadyRunning) {
		t.Errorf("expected ErrAlreadyRunning, got: %v", err)
	}
}

func TestTransitModeHandler_Stop_Success(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	handler, _ := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))

	ctx := context.Background()
	_ = handler.Start(ctx)

	if err := handler.Stop(ctx); err != nil {
		t.Fatalf("expected no error stopping handler, got: %v", err)
	}

	if handler.running.Load() {
		t.Error("expected handler to not be running")
	}
}

func TestTransitModeHandler_Stop_NotRunning(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	handler, _ := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))

	ctx := context.Background()
	err := handler.Stop(ctx)
	if err != nil {
		t.Errorf("expected no error stopping non-running handler, got: %v", err)
	}
}

func TestTransitModeHandler_AnnouncePrefix_Success(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	config.IPv6Prefixes = nil
	config.IPv4Prefixes = nil

	handler, _ := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))

	ctx := context.Background()
	config.IPv6Prefixes = []net.IPNet{createTestIPv6Prefix()}
	config.IPv4Prefixes = []net.IPNet{createTestIPv4Prefix()}

	handler2, _ := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))
	_ = handler2.Start(ctx)
	defer handler2.Stop(ctx)

	// Additional prefix announcement
	_, additionalPrefix, _ := net.ParseCIDR("10.0.0.0/8")
	err := handler2.AnnouncePrefix(ctx, *additionalPrefix)
	if err != nil {
		t.Fatalf("expected no error announcing prefix, got: %v", err)
	}

	announced := handler2.ListAnnouncedPrefixes()
	found := false
	for _, p := range announced {
		if p.String() == additionalPrefix.String() {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected additional prefix to be in announced list")
	}

	// Verify we don't reference handler (which wasn't started)
	_ = handler
}

func TestTransitModeHandler_AnnouncePrefix_NotRunning(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	handler, _ := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))

	ctx := context.Background()
	prefix := createTestIPv6Prefix()
	err := handler.AnnouncePrefix(ctx, prefix)
	if !errors.Is(err, ErrNotRunning) {
		t.Errorf("expected ErrNotRunning, got: %v", err)
	}
}

func TestTransitModeHandler_AnnouncePrefix_AlreadyAnnounced(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	handler, _ := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))

	ctx := context.Background()
	_ = handler.Start(ctx)
	defer handler.Stop(ctx)

	// IPv6 prefix is already announced during Start
	prefix := createTestIPv6Prefix()
	err := handler.AnnouncePrefix(ctx, prefix)

	var alreadyAnnounced *ErrPrefixAlreadyAnnounced
	if !errors.As(err, &alreadyAnnounced) {
		t.Errorf("expected ErrPrefixAlreadyAnnounced, got: %v", err)
	}
}

func TestTransitModeHandler_WithdrawPrefix_Success(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	handler, _ := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))

	ctx := context.Background()
	_ = handler.Start(ctx)
	defer handler.Stop(ctx)

	prefix := createTestIPv6Prefix()
	err := handler.WithdrawPrefix(ctx, prefix)
	if err != nil {
		t.Fatalf("expected no error withdrawing prefix, got: %v", err)
	}

	announced := handler.ListAnnouncedPrefixes()
	for _, p := range announced {
		if p.String() == prefix.String() {
			t.Error("expected prefix to be withdrawn")
		}
	}
}

func TestTransitModeHandler_WithdrawPrefix_NotRunning(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	handler, _ := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))

	ctx := context.Background()
	prefix := createTestIPv6Prefix()
	err := handler.WithdrawPrefix(ctx, prefix)
	if !errors.Is(err, ErrNotRunning) {
		t.Errorf("expected ErrNotRunning, got: %v", err)
	}
}

func TestTransitModeHandler_WithdrawPrefix_NotAnnounced(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	handler, _ := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))

	ctx := context.Background()
	_ = handler.Start(ctx)
	defer handler.Stop(ctx)

	_, prefix, _ := net.ParseCIDR("192.168.99.0/24")
	err := handler.WithdrawPrefix(ctx, *prefix)

	var notAnnounced *ErrPrefixNotAnnounced
	if !errors.As(err, &notAnnounced) {
		t.Errorf("expected ErrPrefixNotAnnounced, got: %v", err)
	}
}

func TestTransitModeHandler_ListAnnouncedPrefixes(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	handler, _ := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))

	ctx := context.Background()
	_ = handler.Start(ctx)
	defer handler.Stop(ctx)

	prefixes := handler.ListAnnouncedPrefixes()

	// Should have both IPv6 and IPv4 configured prefixes
	if len(prefixes) < 2 {
		t.Errorf("expected at least 2 announced prefixes, got: %d", len(prefixes))
	}
}

func TestTransitModeHandler_ValidateRoute_RPKIDisabled(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	config.RPKIEnabled = false

	handler, _ := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))

	ctx := context.Background()
	_ = handler.Start(ctx)
	defer handler.Stop(ctx)

	prefix := createTestIPv6Prefix()
	state, err := handler.ValidateRoute(ctx, prefix, 65001)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if state != bgp.RPKIStateNotFound {
		t.Errorf("expected RPKIStateNotFound when RPKI disabled, got: %v", state)
	}
}

func TestTransitModeHandler_ValidateRoute_NotRunning(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	handler, _ := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))

	ctx := context.Background()
	prefix := createTestIPv6Prefix()
	_, err := handler.ValidateRoute(ctx, prefix, 65001)
	if !errors.Is(err, ErrNotRunning) {
		t.Errorf("expected ErrNotRunning, got: %v", err)
	}
}

func TestTransitModeHandler_SignRoute_Success(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validCoordinatorConfig(t)
	handler, _ := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))

	ctx := context.Background()
	_ = handler.Start(ctx)
	defer handler.Stop(ctx)

	prefix := netip.MustParsePrefix("2602:F5BB::/36")
	signature, err := handler.SignRoute(ctx, prefix)
	if err != nil {
		t.Fatalf("expected no error signing route, got: %v", err)
	}

	if len(signature) == 0 {
		t.Error("expected non-empty signature")
	}

	// Verify signature is cached
	handler.signaturesMu.RLock()
	cached, exists := handler.signatures[prefix.String()]
	handler.signaturesMu.RUnlock()

	if !exists {
		t.Error("expected signature to be cached")
	}

	if cached.signerID != config.RouteSigningKey.KeyID {
		t.Errorf("expected signer ID %s, got %s", config.RouteSigningKey.KeyID, cached.signerID)
	}
}

func TestTransitModeHandler_SignRoute_NotCoordinator(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	handler, _ := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))

	ctx := context.Background()
	_ = handler.Start(ctx)
	defer handler.Stop(ctx)

	prefix := netip.MustParsePrefix("2602:F5BB::/36")
	_, err := handler.SignRoute(ctx, prefix)
	if !errors.Is(err, ErrNotCoordinatorTier) {
		t.Errorf("expected ErrNotCoordinatorTier, got: %v", err)
	}
}

func TestTransitModeHandler_SignRoute_NotRunning(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validCoordinatorConfig(t)
	handler, _ := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))

	ctx := context.Background()
	prefix := netip.MustParsePrefix("2602:F5BB::/36")
	_, err := handler.SignRoute(ctx, prefix)
	if !errors.Is(err, ErrNotRunning) {
		t.Errorf("expected ErrNotRunning, got: %v", err)
	}
}

func TestTransitModeHandler_VerifyRouteSignature_Success(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validCoordinatorConfig(t)
	handler, _ := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))

	ctx := context.Background()
	_ = handler.Start(ctx)
	defer handler.Stop(ctx)

	prefix := netip.MustParsePrefix("2602:F5BB::/36")
	signature, _ := handler.SignRoute(ctx, prefix)

	err := handler.VerifyRouteSignature(ctx, prefix, signature, config.RouteSigningKey.KeyID)
	if err != nil {
		t.Fatalf("expected no error verifying signature, got: %v", err)
	}
}

func TestTransitModeHandler_VerifyRouteSignature_EmptySignature(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validCoordinatorConfig(t)
	handler, _ := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))

	ctx := context.Background()
	_ = handler.Start(ctx)
	defer handler.Stop(ctx)

	prefix := netip.MustParsePrefix("2602:F5BB::/36")
	err := handler.VerifyRouteSignature(ctx, prefix, nil, config.RouteSigningKey.KeyID)
	if !errors.Is(err, ErrEmptySignature) {
		t.Errorf("expected ErrEmptySignature, got: %v", err)
	}
}

func TestTransitModeHandler_VerifyRouteSignature_EmptySignerID(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validCoordinatorConfig(t)
	handler, _ := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))

	ctx := context.Background()
	_ = handler.Start(ctx)
	defer handler.Stop(ctx)

	prefix := netip.MustParsePrefix("2602:F5BB::/36")
	err := handler.VerifyRouteSignature(ctx, prefix, []byte("signature"), "")
	if !errors.Is(err, ErrEmptySignerID) {
		t.Errorf("expected ErrEmptySignerID, got: %v", err)
	}
}

func TestTransitModeHandler_VerifyRouteSignature_SignerNotFound(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validCoordinatorConfig(t)
	handler, _ := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))

	ctx := context.Background()
	_ = handler.Start(ctx)
	defer handler.Stop(ctx)

	prefix := netip.MustParsePrefix("2602:F5BB::/36")
	err := handler.VerifyRouteSignature(ctx, prefix, []byte("signature"), "unknown-signer")

	var signerNotFound ErrSignerNotFound
	if !errors.As(err, &signerNotFound) {
		t.Errorf("expected ErrSignerNotFound, got: %v", err)
	}
}

func TestTransitModeHandler_VerifyRouteSignature_InvalidSignature(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validCoordinatorConfig(t)
	handler, _ := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))

	ctx := context.Background()
	_ = handler.Start(ctx)
	defer handler.Stop(ctx)

	prefix := netip.MustParsePrefix("2602:F5BB::/36")
	invalidSignature := make([]byte, 64)

	err := handler.VerifyRouteSignature(ctx, prefix, invalidSignature, config.RouteSigningKey.KeyID)

	var sigInvalid *ErrSignatureInvalid
	if !errors.As(err, &sigInvalid) {
		t.Errorf("expected ErrSignatureInvalid, got: %v", err)
	}
}

func TestTransitModeHandler_VerifyRouteSignature_NotRunning(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validCoordinatorConfig(t)
	handler, _ := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))

	ctx := context.Background()
	prefix := netip.MustParsePrefix("2602:F5BB::/36")
	err := handler.VerifyRouteSignature(ctx, prefix, []byte("sig"), "signer")
	if !errors.Is(err, ErrNotRunning) {
		t.Errorf("expected ErrNotRunning, got: %v", err)
	}
}

func TestTransitModeHandler_GetStatus(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	handler, _ := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))

	ctx := context.Background()
	_ = handler.Start(ctx)
	defer handler.Stop(ctx)

	status := handler.GetStatus()

	if !status.Running {
		t.Error("expected running status")
	}

	if status.Tier != bgp.SpeakerTierBackbone {
		t.Errorf("expected backbone tier, got: %v", status.Tier)
	}

	if status.AnnouncedPrefixes < 2 {
		t.Errorf("expected at least 2 announced prefixes, got: %d", status.AnnouncedPrefixes)
	}

	if status.StartedAt.IsZero() {
		t.Error("expected non-zero started time")
	}
}

func TestTransitModeHandler_IsRouteVerified_NoMinGateways(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	config.MinGatewaysForRoute = 0

	handler, _ := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))

	ctx := context.Background()
	_ = handler.Start(ctx)
	defer handler.Stop(ctx)

	prefix := netip.MustParsePrefix("2602:F5BB::/36")
	if !handler.IsRouteVerified(prefix) {
		t.Error("expected route to be verified when MinGatewaysForRoute is 0")
	}
}

func TestTransitModeHandler_IsRouteVerified_BelowThreshold(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	config.MinGatewaysForRoute = 3

	handler, _ := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))

	ctx := context.Background()
	_ = handler.Start(ctx)
	defer handler.Stop(ctx)

	prefix := netip.MustParsePrefix("2602:F5BB::/36")

	// Add 2 verifications (below threshold of 3)
	handler.recordRouteVerification(prefix, "gateway-1")
	handler.recordRouteVerification(prefix, "gateway-2")

	if handler.IsRouteVerified(prefix) {
		t.Error("expected route to not be verified below threshold")
	}

	count := handler.GetRouteVerificationCount(prefix)
	if count != 2 {
		t.Errorf("expected 2 verifiers, got: %d", count)
	}
}

func TestTransitModeHandler_IsRouteVerified_AtThreshold(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	config.MinGatewaysForRoute = 3

	handler, _ := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))

	ctx := context.Background()
	_ = handler.Start(ctx)
	defer handler.Stop(ctx)

	prefix := netip.MustParsePrefix("2602:F5BB::/36")

	// Add 3 verifications (at threshold)
	handler.recordRouteVerification(prefix, "gateway-1")
	handler.recordRouteVerification(prefix, "gateway-2")
	handler.recordRouteVerification(prefix, "gateway-3")

	if !handler.IsRouteVerified(prefix) {
		t.Error("expected route to be verified at threshold")
	}

	count := handler.GetRouteVerificationCount(prefix)
	if count != 3 {
		t.Errorf("expected 3 verifiers, got: %d", count)
	}
}

func TestTransitModeHandler_DatacenterTierPrefixScope(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validDatacenterConfig()
	handler, _ := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))

	ctx := context.Background()
	_ = handler.Start(ctx)
	defer handler.Stop(ctx)

	// Try to announce a /36 prefix (too large for datacenter)
	_, largePrefix, _ := net.ParseCIDR("2602:F5BB::/36")
	err := handler.AnnouncePrefix(ctx, *largePrefix)

	var tooLarge *ErrPrefixTooLarge
	if !errors.As(err, &tooLarge) {
		t.Errorf("expected ErrPrefixTooLarge, got: %v", err)
	}
}

func TestTransitModeHandler_ConcurrentOperations(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	handler, _ := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))

	ctx := context.Background()
	_ = handler.Start(ctx)
	defer handler.Stop(ctx)

	var wg sync.WaitGroup
	errCh := make(chan error, 100)

	// Concurrent prefix announcements
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, prefix, _ := net.ParseCIDR("10.0." + string(rune('0'+idx)) + ".0/24")
			if err := handler.AnnouncePrefix(ctx, *prefix); err != nil {
				errCh <- err
			}
		}(i)
	}

	// Concurrent status reads
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = handler.GetStatus()
			_ = handler.ListAnnouncedPrefixes()
		}()
	}

	wg.Wait()
	close(errCh)

	// Check for unexpected errors
	for err := range errCh {
		t.Errorf("unexpected error during concurrent operations: %v", err)
	}
}

func TestTransitModeHandler_WithOptions(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()

	customLogger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	handler, err := NewTransitModeHandler(
		config,
		speaker,
		WithTransitLogger(customLogger),
	)
	if err != nil {
		t.Fatalf("failed to create handler with options: %v", err)
	}

	if handler.logger != customLogger {
		t.Error("expected custom logger to be set")
	}
}

func TestTransitModeHandler_ErrorRecording(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	handler, _ := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))

	ctx := context.Background()
	_ = handler.Start(ctx)
	defer handler.Stop(ctx)

	// Record an error
	testErr := errors.New("test error")
	handler.recordError("test operation failed", testErr)

	status := handler.GetStatus()
	if status.LastError == "" {
		t.Error("expected last error to be recorded")
	}

	if status.LastErrorTime.IsZero() {
		t.Error("expected last error time to be set")
	}
}

func TestTransitModeHandler_NetIPNetConversion(t *testing.T) {
	speaker, _ := createTestSpeaker(t)
	defer speaker.Stop(context.Background())

	config := validBackboneConfig()
	handler, _ := NewTransitModeHandler(config, speaker, WithTransitLogger(testLogger()))

	// Test IPv6 conversion
	ipv6Net := createTestIPv6Prefix()
	prefix, err := handler.netIPNetToPrefix(ipv6Net)
	if err != nil {
		t.Fatalf("failed to convert IPv6 net.IPNet: %v", err)
	}

	if !prefix.IsValid() {
		t.Error("expected valid prefix after conversion")
	}

	// Convert back
	backToNet := handler.prefixToNetIPNet(prefix)
	if backToNet.IP.String() != ipv6Net.IP.String() {
		t.Errorf("round-trip conversion failed: got %s, want %s", backToNet.IP, ipv6Net.IP)
	}

	// Test IPv4 conversion
	ipv4Net := createTestIPv4Prefix()
	prefix4, err := handler.netIPNetToPrefix(ipv4Net)
	if err != nil {
		t.Fatalf("failed to convert IPv4 net.IPNet: %v", err)
	}

	if !prefix4.IsValid() {
		t.Error("expected valid IPv4 prefix after conversion")
	}
}

func TestRouteSigningKey_Structure(t *testing.T) {
	key := createTestSigningKey(t)

	if key.KeyID == "" {
		t.Error("expected non-empty key ID")
	}

	if len(key.PublicKey) != ed25519.PublicKeySize {
		t.Errorf("expected public key size %d, got %d", ed25519.PublicKeySize, len(key.PublicKey))
	}

	if len(key.PrivateKey) != ed25519.PrivateKeySize {
		t.Errorf("expected private key size %d, got %d", ed25519.PrivateKeySize, len(key.PrivateKey))
	}
}

func TestTransitModeStatus_Structure(t *testing.T) {
	status := &TransitModeStatus{
		Running:           true,
		Tier:              bgp.SpeakerTierBackbone,
		AnnouncedPrefixes: 5,
		ExternalPeers:     3,
		EstablishedPeers:  2,
		RPKIEnabled:       true,
		DampenedRoutes:    1,
		StartedAt:         time.Now(),
	}

	if !status.Running {
		t.Error("expected running to be true")
	}

	if status.AnnouncedPrefixes != 5 {
		t.Errorf("expected 5 announced prefixes, got %d", status.AnnouncedPrefixes)
	}
}

func TestRPKIValidatorStatus_Structure(t *testing.T) {
	status := RPKIValidatorStatus{
		Address:    "10.0.0.1:8282",
		Connected:  true,
		ROACount:   1000,
		LastUpdate: time.Now(),
	}

	if status.Address != "10.0.0.1:8282" {
		t.Errorf("expected address 10.0.0.1:8282, got %s", status.Address)
	}

	if !status.Connected {
		t.Error("expected connected to be true")
	}
}

// Benchmark tests

func BenchmarkTransitModeHandler_AnnouncePrefix(b *testing.B) {
	mockServer := newMockBGPServer()
	config := testBGPConfig()

	speaker, _ := bgp.NewSpeaker(config, testLogger(), bgp.WithBGPServer(mockServer))
	ctx := context.Background()
	_ = speaker.Start(ctx)
	defer speaker.Stop(ctx)

	handlerConfig := validBackboneConfig()
	handlerConfig.IPv6Prefixes = nil
	handlerConfig.IPv4Prefixes = nil

	handler, _ := NewTransitModeHandler(handlerConfig, speaker, WithTransitLogger(testLogger()))
	_ = handler.Start(ctx)
	defer handler.Stop(ctx)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, prefix, _ := net.ParseCIDR("10." + string(rune(i%256)) + ".0.0/16")
		_ = handler.AnnouncePrefix(ctx, *prefix)
	}
}

func BenchmarkTransitModeHandler_GetStatus(b *testing.B) {
	mockServer := newMockBGPServer()
	config := testBGPConfig()

	speaker, _ := bgp.NewSpeaker(config, testLogger(), bgp.WithBGPServer(mockServer))
	ctx := context.Background()
	_ = speaker.Start(ctx)
	defer speaker.Stop(ctx)

	handlerConfig := validBackboneConfig()
	handler, _ := NewTransitModeHandler(handlerConfig, speaker, WithTransitLogger(testLogger()))
	_ = handler.Start(ctx)
	defer handler.Stop(ctx)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = handler.GetStatus()
	}
}

func BenchmarkTransitModeHandler_SignRoute(b *testing.B) {
	mockServer := newMockBGPServer()
	config := testBGPConfig()

	speaker, _ := bgp.NewSpeaker(config, testLogger(), bgp.WithBGPServer(mockServer))
	ctx := context.Background()
	_ = speaker.Start(ctx)
	defer speaker.Stop(ctx)

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	handlerConfig := &TransitModeConfig{
		Tier:         bgp.SpeakerTierCoordinator,
		IPv6Prefixes: []net.IPNet{createTestIPv6Prefix()},
		LocalASN:     65001,
		RouteSigningKey: &RouteSigningKey{
			KeyID:      "bench-key",
			PublicKey:  pub,
			PrivateKey: priv,
		},
	}

	handler, _ := NewTransitModeHandler(handlerConfig, speaker, WithTransitLogger(testLogger()))
	_ = handler.Start(ctx)
	defer handler.Stop(ctx)

	prefix := netip.MustParsePrefix("2602:F5BB::/36")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = handler.SignRoute(ctx, prefix)
	}
}
