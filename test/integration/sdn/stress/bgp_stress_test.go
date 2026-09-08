//go:build integration

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

package stress

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	api "github.com/osrg/gobgp/v4/api"
)

// mockBGPServer implements bgp.BGPServerInterface for stress testing.
type mockBGPServer struct {
	keychains    []*api.TcpAoKeychain
	policies     *api.SetPoliciesRequest
	mu           sync.RWMutex
	paths        map[string]*api.Path
	peers        map[string]*api.Peer
	pathCounter  atomic.Uint64
	addPathDelay time.Duration
	delPathDelay time.Duration
	addPeerDelay time.Duration
	started      atomic.Bool
	errorRate    float64 // Percentage of operations that should fail (0-100)
	errorCounter atomic.Uint64
}

func newMockBGPServer() *mockBGPServer {
	return &mockBGPServer{
		paths: make(map[string]*api.Path),
		peers: make(map[string]*api.Peer),
	}
}

func (m *mockBGPServer) SetAddPathDelay(d time.Duration) {
	m.addPathDelay = d
}

func (m *mockBGPServer) SetErrorRate(rate float64) {
	m.errorRate = rate
}

func (m *mockBGPServer) Start() error {
	m.started.Store(true)
	return nil
}

func (m *mockBGPServer) Stop() {
	m.started.Store(false)
}

func (m *mockBGPServer) StartBgp(ctx context.Context, req *api.StartBgpRequest) error {
	return nil
}

func (m *mockBGPServer) StopBgp(ctx context.Context, req *api.StopBgpRequest) error {
	return nil
}

func (m *mockBGPServer) AddPeer(ctx context.Context, req *api.AddPeerRequest) error {
	if m.addPeerDelay > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(m.addPeerDelay):
		}
	}

	if m.shouldFail() {
		return fmt.Errorf("simulated peer add failure")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if req.Peer != nil && req.Peer.Conf != nil {
		m.peers[req.Peer.Conf.NeighborAddress] = req.Peer
	}
	return nil
}

func (m *mockBGPServer) DeletePeer(ctx context.Context, req *api.DeletePeerRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.peers, req.Address)
	return nil
}

func (m *mockBGPServer) UpdatePeer(ctx context.Context, req *api.UpdatePeerRequest) (*api.UpdatePeerResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if req.Peer != nil && req.Peer.Conf != nil {
		m.peers[req.Peer.Conf.NeighborAddress] = req.Peer
	}
	return &api.UpdatePeerResponse{}, nil
}

func (m *mockBGPServer) GetBgp(ctx context.Context, req *api.GetBgpRequest) (*api.GetBgpResponse, error) {
	return &api.GetBgpResponse{
		Global: &api.Global{
			Asn:        65001,
			RouterId:   "1.1.1.1",
			ListenPort: 179,
		},
	}, nil
}

func (m *mockBGPServer) ListPeer(ctx context.Context, req *api.ListPeerRequest, fn func(*api.Peer)) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

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
	if m.addPathDelay > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(m.addPathDelay):
		}
	}

	if m.shouldFail() {
		return nil, fmt.Errorf("simulated path add failure")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	pathID := m.pathCounter.Add(1)
	pathKey := fmt.Sprintf("path-%d", pathID)
	m.paths[pathKey] = req.Path

	return &api.AddPathResponse{Uuid: []byte(pathKey)}, nil
}

func (m *mockBGPServer) DeletePath(ctx context.Context, req *api.DeletePathRequest) error {
	if m.delPathDelay > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(m.delPathDelay):
		}
	}

	if m.shouldFail() {
		return fmt.Errorf("simulated path delete failure")
	}

	return nil
}

func (m *mockBGPServer) ListPath(ctx context.Context, req *api.ListPathRequest, fn func(*api.Destination)) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return paths as destinations
	for _, path := range m.paths {
		fn(&api.Destination{
			Paths: []*api.Path{path},
		})
	}
	return nil
}

func (m *mockBGPServer) WatchEvent(ctx context.Context, req *api.WatchEventRequest, fn func(*api.WatchEventResponse)) error {
	<-ctx.Done()
	return ctx.Err()
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

func (m *mockBGPServer) shouldFail() bool {
	if m.errorRate <= 0 {
		return false
	}
	count := m.errorCounter.Add(1)
	return float64(count%100) < m.errorRate
}

func (m *mockBGPServer) PathCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.paths)
}

func (m *mockBGPServer) PeerCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.peers)
}

// createTestSpeaker creates a BGP speaker with a mock server for testing.
func createTestSpeaker(t *testing.T, mockServer *mockBGPServer) *bgp.Speaker {
	t.Helper()

	config := &bgp.BGPConfig{
		RouterID:        netip.MustParseAddr("10.0.0.1"),
		ASN:             65001,
		ListenPort:      1179, // Non-privileged port
		EnabledFamilies: []bgp.AddressFamily{bgp.AFamilyIPv4Unicast},
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	speaker, err := bgp.NewSpeaker(config, logger, bgp.WithBGPServer(mockServer))
	if err != nil {
		t.Fatalf("Failed to create speaker: %v", err)
	}

	return speaker
}

// TestBGPRouteChurnStress tests rapid route announcements/withdrawals.
func TestBGPRouteChurnStress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	mockServer := newMockBGPServer()
	speaker := createTestSpeaker(t, mockServer)

	if err := speaker.Start(ctx); err != nil {
		t.Fatalf("Failed to start speaker: %v", err)
	}
	defer func() {
		if err := speaker.Stop(ctx); err != nil {
			t.Logf("Error stopping speaker: %v", err)
		}
	}()

	config := StressConfig{
		Name:           "BGP Route Churn Stress",
		Duration:       8 * time.Second,
		Concurrency:    20,
		RateLimit:      500,
		ReportInterval: 4 * time.Second,
		WarmupDuration: 1 * time.Second,
	}

	prefixCounter := atomic.Uint64{}
	announceCount := atomic.Int64{}
	withdrawCount := atomic.Int64{}

	op := func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		counter := prefixCounter.Add(1)

		// Calculate prefix from counter
		octet3 := byte((counter >> 8) & 0xFF)
		octet4 := byte(counter & 0xFF)
		prefix, _ := netip.ParsePrefix(fmt.Sprintf("100.64.%d.%d/32", octet3, octet4))

		if counter%3 == 0 {
			// Withdraw
			path := &bgp.Path{
				Family:  bgp.AFamilyIPv4Unicast,
				Prefix:  prefix,
				NextHop: netip.MustParseAddr("10.0.0.1"),
				Origin:  bgp.OriginIGP,
			}
			err := speaker.DeletePath(ctx, path)
			if err == nil {
				withdrawCount.Add(1)
			}
			return err
		}

		// Announce
		path := &bgp.Path{
			Family:    bgp.AFamilyIPv4Unicast,
			Prefix:    prefix,
			NextHop:   netip.MustParseAddr("10.0.0.1"),
			Origin:    bgp.OriginIGP,
			LocalPref: 100,
		}
		err := speaker.AddPath(ctx, path)
		if err == nil {
			announceCount.Add(1)
		}
		return err
	}

	reporter := NewTableReporter(os.Stdout)
	result, err := RunStressTest(ctx, config.Name, config, op, reporter)
	if err != nil {
		t.Fatalf("Stress test failed: %v", err)
	}

	t.Logf("Announcements: %d, Withdrawals: %d, Total: %d",
		announceCount.Load(), withdrawCount.Load(), result.TotalOperations)

	if result.SuccessRate() < 90 {
		t.Errorf("Success rate too low: %.2f%% (expected >= 90%%)", result.SuccessRate())
	}
}

// TestBGPPeerFlapStress tests peer session flapping scenarios.
func TestBGPPeerFlapStress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	mockServer := newMockBGPServer()
	speaker := createTestSpeaker(t, mockServer)

	if err := speaker.Start(ctx); err != nil {
		t.Fatalf("Failed to start speaker: %v", err)
	}
	defer func() {
		if err := speaker.Stop(ctx); err != nil {
			t.Logf("Error stopping speaker: %v", err)
		}
	}()

	config := StressConfig{
		Name:           "BGP Peer Flap Stress",
		Duration:       8 * time.Second,
		Concurrency:    10,
		RateLimit:      100, // Moderate rate for peer operations
		ReportInterval: 4 * time.Second,
		WarmupDuration: 1 * time.Second,
	}

	peerCounter := atomic.Uint64{}
	addCount := atomic.Int64{}
	deleteCount := atomic.Int64{}

	// Track active peers for deletion
	activePeers := make(chan netip.Addr, 100)

	op := func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		counter := peerCounter.Add(1)

		if counter%4 == 0 {
			// Try to delete a peer
			select {
			case addr := <-activePeers:
				err := speaker.DeletePeer(ctx, addr)
				if err == nil {
					deleteCount.Add(1)
				}
				return err
			default:
				// No peers to delete
			}
		}

		// Add a peer
		octet := byte(counter & 0xFF)
		peerAddr := netip.MustParseAddr(fmt.Sprintf("192.168.1.%d", octet))

		peerConfig := &bgp.NeighborConfig{
			Address:         peerAddr,
			ASN:             65000 + uint32(counter%100),
			EnabledFamilies: []bgp.AddressFamily{bgp.AFamilyIPv4Unicast},
		}

		err := speaker.AddPeer(ctx, peerConfig)
		if err == nil {
			addCount.Add(1)
			select {
			case activePeers <- peerAddr:
			default:
				// Channel full, delete immediately
				_ = speaker.DeletePeer(ctx, peerAddr)
			}
		}
		return err
	}

	reporter := NewTableReporter(os.Stdout)
	result, err := RunStressTest(ctx, config.Name, config, op, reporter)
	if err != nil {
		t.Fatalf("Stress test failed: %v", err)
	}

	t.Logf("Peer Adds: %d, Peer Deletes: %d, Total: %d",
		addCount.Load(), deleteCount.Load(), result.TotalOperations)

	if result.SuccessRate() < 80 {
		t.Errorf("Success rate too low: %.2f%% (expected >= 80%%)", result.SuccessRate())
	}
}

// TestBGPLargeTableStress tests handling of large routing tables.
func TestBGPLargeTableStress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	mockServer := newMockBGPServer()
	speaker := createTestSpeaker(t, mockServer)

	if err := speaker.Start(ctx); err != nil {
		t.Fatalf("Failed to start speaker: %v", err)
	}
	defer func() {
		if err := speaker.Stop(ctx); err != nil {
			t.Logf("Error stopping speaker: %v", err)
		}
	}()

	config := StressConfig{
		Name:           "BGP Large Table Stress",
		Duration:       8 * time.Second,
		Concurrency:    30,
		RateLimit:      2000, // High rate for bulk injection
		ReportInterval: 4 * time.Second,
		WarmupDuration: 1 * time.Second,
	}

	prefixCounter := atomic.Uint64{}

	op := func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		counter := prefixCounter.Add(1)

		// Generate diverse prefixes across multiple blocks
		block := counter % 10
		octet2 := byte((counter >> 16) & 0xFF)
		octet3 := byte((counter >> 8) & 0xFF)
		octet4 := byte(counter & 0xFF)

		prefixStr := fmt.Sprintf("%d.%d.%d.%d/24", 10+block, octet2, octet3, octet4)
		prefix, err := netip.ParsePrefix(prefixStr)
		if err != nil {
			// If prefix is invalid, use a fallback
			prefix = netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.0/24", octet3, octet4))
		}

		path := &bgp.Path{
			Family:    bgp.AFamilyIPv4Unicast,
			Prefix:    prefix,
			NextHop:   netip.MustParseAddr("10.0.0.1"),
			Origin:    bgp.OriginIGP,
			LocalPref: 100,
			ASPath:    []uint32{65001, 65002, 65003},
		}

		return speaker.AddPath(ctx, path)
	}

	reporter := NewTableReporter(os.Stdout)
	result, err := RunStressTest(ctx, config.Name, config, op, reporter)
	if err != nil {
		t.Fatalf("Stress test failed: %v", err)
	}

	pathCount := mockServer.PathCount()
	t.Logf("Total routes injected: %d, Mock server path count: %d", result.SuccessCount, pathCount)

	if result.SuccessRate() < 95 {
		t.Errorf("Success rate too low: %.2f%% (expected >= 95%%)", result.SuccessRate())
	}

	// Verify latency under load
	if result.Latencies.P99 > 50*time.Millisecond {
		t.Logf("Warning: P99 latency elevated under large table stress: %s", result.Latencies.P99)
	}
}

// TestBGPConvergenceStress tests convergence under load.
func TestBGPConvergenceStress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	mockServer := newMockBGPServer()
	// Simulate realistic latency
	mockServer.SetAddPathDelay(1 * time.Millisecond)

	speaker := createTestSpeaker(t, mockServer)

	if err := speaker.Start(ctx); err != nil {
		t.Fatalf("Failed to start speaker: %v", err)
	}
	defer func() {
		if err := speaker.Stop(ctx); err != nil {
			t.Logf("Error stopping speaker: %v", err)
		}
	}()

	config := StressConfig{
		Name:           "BGP Convergence Stress",
		Duration:       8 * time.Second,
		Concurrency:    25,
		RateLimit:      300,
		ReportInterval: 4 * time.Second,
		WarmupDuration: 1 * time.Second,
	}

	prefixCounter := atomic.Uint64{}
	updateCount := atomic.Int64{}

	op := func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		counter := prefixCounter.Add(1)

		// Simulate route updates (same prefix, different attributes)
		prefixNum := counter % 1000 // Reuse prefixes to simulate updates
		prefix := netip.MustParsePrefix(fmt.Sprintf("100.64.%d.%d/32", prefixNum/256, prefixNum%256))

		// Vary attributes to simulate convergence
		localPref := uint32(100 + (counter % 50))
		med := uint32(counter % 100)

		path := &bgp.Path{
			Family:    bgp.AFamilyIPv4Unicast,
			Prefix:    prefix,
			NextHop:   netip.MustParseAddr("10.0.0.1"),
			Origin:    bgp.OriginIGP,
			LocalPref: localPref,
			MED:       med,
		}

		err := speaker.AddPath(ctx, path)
		if err == nil {
			updateCount.Add(1)
		}
		return err
	}

	metricsReporter := NewMetricsReporter()
	tableReporter := NewTableReporter(os.Stdout)
	multiReporter := NewMultiReporter(metricsReporter, tableReporter)

	result, err := RunStressTest(ctx, config.Name, config, op, multiReporter)
	if err != nil {
		t.Fatalf("Stress test failed: %v", err)
	}

	t.Logf("Route updates: %d, Unique prefixes: ~1000", updateCount.Load())

	// Convergence test should maintain good throughput
	if result.Throughput < 200 {
		t.Errorf("Throughput too low: %.2f ops/s (expected >= 200)", result.Throughput)
	}
}

// TestBGPErrorRecoveryStress tests recovery from errors under load.
func TestBGPErrorRecoveryStress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	mockServer := newMockBGPServer()
	mockServer.SetErrorRate(10) // 10% error rate

	speaker := createTestSpeaker(t, mockServer)

	if err := speaker.Start(ctx); err != nil {
		t.Fatalf("Failed to start speaker: %v", err)
	}
	defer func() {
		if err := speaker.Stop(ctx); err != nil {
			t.Logf("Error stopping speaker: %v", err)
		}
	}()

	config := StressConfig{
		Name:           "BGP Error Recovery Stress",
		Duration:       8 * time.Second,
		Concurrency:    15,
		RateLimit:      400,
		ReportInterval: 4 * time.Second,
		WarmupDuration: 1 * time.Second,
	}

	prefixCounter := atomic.Uint64{}

	op := func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		counter := prefixCounter.Add(1)
		prefix := netip.MustParsePrefix(fmt.Sprintf("172.16.%d.%d/32", (counter>>8)&0xFF, counter&0xFF))

		path := &bgp.Path{
			Family:  bgp.AFamilyIPv4Unicast,
			Prefix:  prefix,
			NextHop: netip.MustParseAddr("10.0.0.1"),
			Origin:  bgp.OriginIGP,
		}

		return speaker.AddPath(ctx, path)
	}

	reporter := NewTableReporter(os.Stdout)
	result, err := RunStressTest(ctx, config.Name, config, op, reporter)
	if err != nil {
		t.Fatalf("Stress test failed: %v", err)
	}

	// With 10% error rate, expect ~90% success
	if result.SuccessRate() < 85 || result.SuccessRate() > 95 {
		t.Errorf("Success rate outside expected range: %.2f%% (expected 85-95%%)", result.SuccessRate())
	}

	t.Logf("Success rate with 10%% simulated errors: %.2f%%", result.SuccessRate())
}
