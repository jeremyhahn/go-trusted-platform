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
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/dhcp"
)

// mockDHCPServer implements dhcp.Server for stress testing.
type mockDHCPServer struct {
	mu           sync.RWMutex
	leases       map[string]*dhcp.Lease // key: MAC address string
	leasesByIP   map[netip.Addr]*dhcp.Lease
	stats        *dhcp.StatsCollector
	running      atomic.Bool
	leaseCounter atomic.Uint64
	ipCounter    atomic.Uint64
	baseIP       netip.Addr
	requestDelay time.Duration
	errorRate    float64
	errorCounter atomic.Uint64
}

func newMockDHCPServer() *mockDHCPServer {
	return &mockDHCPServer{
		leases:     make(map[string]*dhcp.Lease),
		leasesByIP: make(map[netip.Addr]*dhcp.Lease),
		stats:      dhcp.NewStatsCollector(),
		baseIP:     netip.MustParseAddr("10.0.0.1"),
	}
}

func (m *mockDHCPServer) SetRequestDelay(d time.Duration) {
	m.requestDelay = d
}

func (m *mockDHCPServer) SetErrorRate(rate float64) {
	m.errorRate = rate
}

func (m *mockDHCPServer) Start(ctx context.Context) error {
	m.running.Store(true)
	m.stats.Start()
	return nil
}

func (m *mockDHCPServer) Stop(ctx context.Context) error {
	m.running.Store(false)
	return nil
}

func (m *mockDHCPServer) Running() bool {
	return m.running.Load()
}

func (m *mockDHCPServer) GetLease(mac net.HardwareAddr) (*dhcp.Lease, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	lease, exists := m.leases[mac.String()]
	if !exists || lease.IsExpired() {
		return nil, false
	}
	return lease.Clone(), true
}

func (m *mockDHCPServer) GetLeaseByIP(ip netip.Addr) (*dhcp.Lease, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	lease, exists := m.leasesByIP[ip]
	if !exists || lease.IsExpired() {
		return nil, false
	}
	return lease.Clone(), true
}

func (m *mockDHCPServer) ListLeases() []*dhcp.Lease {
	m.mu.RLock()
	defer m.mu.RUnlock()

	leases := make([]*dhcp.Lease, 0, len(m.leases))
	for _, lease := range m.leases {
		if !lease.IsExpired() {
			leases = append(leases, lease.Clone())
		}
	}
	return leases
}

func (m *mockDHCPServer) ReleaseLease(mac net.HardwareAddr) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	lease, exists := m.leases[mac.String()]
	if !exists {
		return dhcp.ErrLeaseNotFound
	}

	delete(m.leasesByIP, lease.IP)
	delete(m.leases, mac.String())
	m.stats.DecActiveLeases()
	m.stats.IncRelease()

	return nil
}

func (m *mockDHCPServer) Stats() dhcp.ServerStats {
	return m.stats.Snapshot()
}

// RequestLease simulates a DHCP lease request.
func (m *mockDHCPServer) RequestLease(ctx context.Context, mac net.HardwareAddr, hostname string) (*dhcp.Lease, error) {
	if m.requestDelay > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(m.requestDelay):
		}
	}

	if m.shouldFail() {
		m.stats.IncError()
		return nil, fmt.Errorf("simulated DHCP failure")
	}

	m.stats.IncDiscover()
	m.stats.IncRequest()

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if MAC already has a lease
	macStr := mac.String()
	if existing, exists := m.leases[macStr]; exists && !existing.IsExpired() {
		// Renew existing lease
		existing.RenewedAt = time.Now()
		existing.ExpiresAt = time.Now().Add(24 * time.Hour)
		m.stats.IncAck()
		return existing.Clone(), nil
	}

	// Allocate new IP
	ipNum := m.ipCounter.Add(1)
	ip := incrementIP(m.baseIP, int(ipNum))

	lease := &dhcp.Lease{
		IP:        ip,
		MAC:       mac,
		Hostname:  hostname,
		PoolID:    "default",
		Interface: "eth0",
		LeasedAt:  time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		State:     dhcp.LeaseStateActive,
	}

	m.leases[macStr] = lease
	m.leasesByIP[ip] = lease
	m.leaseCounter.Add(1)
	m.stats.IncOffer()
	m.stats.IncAck()
	m.stats.IncActiveLeases()

	return lease.Clone(), nil
}

// RenewLease simulates a DHCP renewal.
func (m *mockDHCPServer) RenewLease(ctx context.Context, mac net.HardwareAddr) (*dhcp.Lease, error) {
	if m.requestDelay > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(m.requestDelay):
		}
	}

	if m.shouldFail() {
		m.stats.IncError()
		return nil, fmt.Errorf("simulated renewal failure")
	}

	m.stats.IncRequest()

	m.mu.Lock()
	defer m.mu.Unlock()

	lease, exists := m.leases[mac.String()]
	if !exists {
		m.stats.IncNak()
		return nil, dhcp.ErrLeaseNotFound
	}

	if lease.IsExpired() {
		m.stats.IncNak()
		return nil, dhcp.ErrLeaseExpired
	}

	// Renew
	lease.RenewedAt = time.Now()
	lease.ExpiresAt = time.Now().Add(24 * time.Hour)
	m.stats.IncAck()

	return lease.Clone(), nil
}

func (m *mockDHCPServer) shouldFail() bool {
	if m.errorRate <= 0 {
		return false
	}
	count := m.errorCounter.Add(1)
	return float64(count%100) < m.errorRate
}

func (m *mockDHCPServer) LeaseCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.leases)
}

// incrementIP adds an offset to an IP address.
func incrementIP(base netip.Addr, offset int) netip.Addr {
	if base.Is4() {
		b := base.As4()
		val := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		val += uint32(offset)
		return netip.AddrFrom4([4]byte{
			byte(val >> 24),
			byte(val >> 16),
			byte(val >> 8),
			byte(val),
		})
	}
	// Simplified IPv6 handling
	return base
}

// generateMAC generates a unique MAC address for testing.
func generateMAC(counter uint64) net.HardwareAddr {
	return net.HardwareAddr{
		0x02, // Locally administered
		byte((counter >> 40) & 0xFF),
		byte((counter >> 32) & 0xFF),
		byte((counter >> 24) & 0xFF),
		byte((counter >> 8) & 0xFF),
		byte(counter & 0xFF),
	}
}

// TestDHCPLeaseStress tests high volume lease requests.
func TestDHCPLeaseStress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	server := newMockDHCPServer()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer func() {
		if err := server.Stop(ctx); err != nil {
			t.Logf("Error stopping server: %v", err)
		}
	}()

	config := StressConfig{
		Name:           "DHCP Lease Stress",
		Duration:       8 * time.Second,
		Concurrency:    25,
		RateLimit:      1000,
		ReportInterval: 4 * time.Second,
		WarmupDuration: 1 * time.Second,
	}

	macCounter := atomic.Uint64{}

	op := func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		counter := macCounter.Add(1)
		mac := generateMAC(counter)
		hostname := fmt.Sprintf("client-%d", counter)

		_, err := server.RequestLease(ctx, mac, hostname)
		return err
	}

	reporter := NewTableReporter(os.Stdout)
	result, err := RunStressTest(ctx, config.Name, config, op, reporter)
	if err != nil {
		t.Fatalf("Stress test failed: %v", err)
	}

	stats := server.Stats()
	t.Logf("DHCP Stats - Discovers: %d, Offers: %d, Requests: %d, Acks: %d",
		stats.DiscoverCount, stats.OfferCount, stats.RequestCount, stats.AckCount)

	if result.SuccessRate() < 95 {
		t.Errorf("Success rate too low: %.2f%% (expected >= 95%%)", result.SuccessRate())
	}

	if result.Latencies.P99 > 50*time.Millisecond {
		t.Errorf("P99 latency too high: %s (expected <= 50ms)", result.Latencies.P99)
	}
}

// TestDHCPRenewalStorm tests many simultaneous renewals.
func TestDHCPRenewalStorm(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	server := newMockDHCPServer()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer func() {
		if err := server.Stop(ctx); err != nil {
			t.Logf("Error stopping server: %v", err)
		}
	}()

	// Pre-allocate leases
	numClients := 500
	macs := make([]net.HardwareAddr, numClients)
	for i := 0; i < numClients; i++ {
		mac := generateMAC(uint64(i))
		macs[i] = mac
		_, err := server.RequestLease(ctx, mac, fmt.Sprintf("client-%d", i))
		if err != nil {
			t.Fatalf("Failed to pre-allocate lease %d: %v", i, err)
		}
	}

	t.Logf("Pre-allocated %d leases", numClients)

	config := StressConfig{
		Name:           "DHCP Renewal Storm",
		Duration:       8 * time.Second,
		Concurrency:    50, // High concurrency for storm simulation
		RateLimit:      0,  // Unlimited
		ReportInterval: 4 * time.Second,
		WarmupDuration: 1 * time.Second,
	}

	macIndex := atomic.Uint64{}
	renewCount := atomic.Int64{}

	op := func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		idx := macIndex.Add(1) % uint64(numClients)
		mac := macs[idx]

		_, err := server.RenewLease(ctx, mac)
		if err == nil {
			renewCount.Add(1)
		}
		return err
	}

	reporter := NewTableReporter(os.Stdout)
	result, err := RunStressTest(ctx, config.Name, config, op, reporter)
	if err != nil {
		t.Fatalf("Stress test failed: %v", err)
	}

	t.Logf("Successful renewals: %d, Total operations: %d", renewCount.Load(), result.TotalOperations)

	if result.SuccessRate() < 95 {
		t.Errorf("Success rate too low: %.2f%% (expected >= 95%%)", result.SuccessRate())
	}
}

// TestDHCPConcurrentClients tests many parallel DHCP clients.
func TestDHCPConcurrentClients(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	server := newMockDHCPServer()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer func() {
		if err := server.Stop(ctx); err != nil {
			t.Logf("Error stopping server: %v", err)
		}
	}()

	config := StressConfig{
		Name:           "DHCP Concurrent Clients",
		Duration:       8 * time.Second,
		Concurrency:    100, // Simulating 100 concurrent clients
		RateLimit:      500,
		ReportInterval: 4 * time.Second,
		WarmupDuration: 1 * time.Second,
	}

	macCounter := atomic.Uint64{}
	leaseCount := atomic.Int64{}
	renewCount := atomic.Int64{}
	releaseCount := atomic.Int64{}

	// Track active MACs for renewal/release
	activeMACs := make(chan net.HardwareAddr, 500)

	op := func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		counter := macCounter.Add(1)

		// Simulate DHCP client lifecycle
		action := counter % 10

		switch {
		case action < 6: // 60% new leases
			mac := generateMAC(counter)
			_, err := server.RequestLease(ctx, mac, fmt.Sprintf("client-%d", counter))
			if err == nil {
				leaseCount.Add(1)
				select {
				case activeMACs <- mac:
				default:
				}
			}
			return err

		case action < 9: // 30% renewals
			select {
			case mac := <-activeMACs:
				_, err := server.RenewLease(ctx, mac)
				if err == nil {
					renewCount.Add(1)
					select {
					case activeMACs <- mac:
					default:
					}
				}
				return err
			default:
				// No active leases, get new one
				mac := generateMAC(counter)
				_, err := server.RequestLease(ctx, mac, fmt.Sprintf("client-%d", counter))
				if err == nil {
					leaseCount.Add(1)
				}
				return err
			}

		default: // 10% releases
			select {
			case mac := <-activeMACs:
				err := server.ReleaseLease(mac)
				if err == nil {
					releaseCount.Add(1)
				}
				return err
			default:
				return nil
			}
		}
	}

	reporter := NewTableReporter(os.Stdout)
	result, err := RunStressTest(ctx, config.Name, config, op, reporter)
	if err != nil {
		t.Fatalf("Stress test failed: %v", err)
	}

	stats := server.Stats()
	t.Logf("New Leases: %d, Renewals: %d, Releases: %d",
		leaseCount.Load(), renewCount.Load(), releaseCount.Load())
	t.Logf("Active leases: %d", stats.ActiveLeases)

	if result.SuccessRate() < 90 {
		t.Errorf("Success rate too low: %.2f%% (expected >= 90%%)", result.SuccessRate())
	}
}

// TestDHCPLatencyUnderLoad tests DHCP response times under various loads.
func TestDHCPLatencyUnderLoad(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	loadLevels := []struct {
		name        string
		concurrency int
		rateLimit   int
		delay       time.Duration
	}{
		{"Light Load", 10, 100, 0},
		{"Medium Load", 50, 500, 0},
		{"Heavy Load", 100, 0, 0},
	}

	for _, level := range loadLevels {
		t.Run(level.name, func(t *testing.T) {
			// Create subtest context with shorter timeout
			subCtx, subCancel := context.WithTimeout(ctx, 8*time.Second)
			defer subCancel()

			server := newMockDHCPServer()
			server.SetRequestDelay(level.delay)

			if err := server.Start(subCtx); err != nil {
				t.Fatalf("Failed to start server: %v", err)
			}

			config := StressConfig{
				Name:           fmt.Sprintf("DHCP Latency - %s", level.name),
				Duration:       4 * time.Second,
				Concurrency:    level.concurrency,
				RateLimit:      level.rateLimit,
				ReportInterval: 2 * time.Second,
				WarmupDuration: 500 * time.Millisecond,
			}

			macCounter := atomic.Uint64{}
			op := func(ctx context.Context) error {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}
				counter := macCounter.Add(1)
				mac := generateMAC(counter)
				_, err := server.RequestLease(ctx, mac, fmt.Sprintf("client-%d", counter))
				return err
			}

			metricsReporter := NewMetricsReporter()
			result, err := RunStressTest(subCtx, config.Name, config, op, metricsReporter)
			if err != nil {
				t.Fatalf("Stress test failed: %v", err)
			}

			t.Logf("%s: Throughput=%.2f ops/s, P50=%s, P95=%s, P99=%s",
				level.name,
				result.Throughput,
				result.Latencies.P50.Round(time.Microsecond),
				result.Latencies.P95.Round(time.Microsecond),
				result.Latencies.P99.Round(time.Microsecond))

			if err := server.Stop(subCtx); err != nil {
				t.Logf("Error stopping server: %v", err)
			}
		})
	}
}

// TestDHCPErrorRecovery tests DHCP behavior with simulated errors.
func TestDHCPErrorRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	server := newMockDHCPServer()
	server.SetErrorRate(5) // 5% error rate

	if err := server.Start(ctx); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer func() {
		if err := server.Stop(ctx); err != nil {
			t.Logf("Error stopping server: %v", err)
		}
	}()

	config := StressConfig{
		Name:           "DHCP Error Recovery",
		Duration:       8 * time.Second,
		Concurrency:    30,
		RateLimit:      400,
		ReportInterval: 4 * time.Second,
		WarmupDuration: 1 * time.Second,
	}

	macCounter := atomic.Uint64{}

	op := func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		counter := macCounter.Add(1)
		mac := generateMAC(counter)
		_, err := server.RequestLease(ctx, mac, fmt.Sprintf("client-%d", counter))
		return err
	}

	reporter := NewTableReporter(os.Stdout)
	result, err := RunStressTest(ctx, config.Name, config, op, reporter)
	if err != nil {
		t.Fatalf("Stress test failed: %v", err)
	}

	stats := server.Stats()
	t.Logf("Error count: %d", stats.ErrorCount)

	// With 5% error rate, expect ~95% success
	if result.SuccessRate() < 90 || result.SuccessRate() > 98 {
		t.Errorf("Success rate outside expected range: %.2f%% (expected 90-98%%)", result.SuccessRate())
	}
}
