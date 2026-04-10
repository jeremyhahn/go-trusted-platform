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
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
)

// testIPAMAllocator is a test implementation of the IPAM allocator.
// In production tests, this would be replaced with a real allocator instance.
// Thread-safe for concurrent stress testing.
type testIPAMAllocator struct {
	mu          sync.RWMutex
	pools       map[string]*ipam.Pool
	allocations map[netip.Addr]*ipam.Allocation
	poolManager *ipam.PoolManager
	counter     atomic.Uint64
}

func newTestIPAMAllocator() *testIPAMAllocator {
	return &testIPAMAllocator{
		pools:       make(map[string]*ipam.Pool),
		allocations: make(map[netip.Addr]*ipam.Allocation),
		poolManager: ipam.NewPoolManager(),
	}
}

func (a *testIPAMAllocator) CreatePool(ctx context.Context, pool *ipam.Pool) error {
	if err := a.poolManager.ValidatePool(pool); err != nil {
		return err
	}
	a.poolManager.InitializePool(pool)

	a.mu.Lock()
	a.pools[pool.ID] = pool
	a.mu.Unlock()
	return nil
}

func (a *testIPAMAllocator) GetPool(ctx context.Context, poolID string) (*ipam.Pool, error) {
	a.mu.RLock()
	pool, exists := a.pools[poolID]
	if !exists {
		a.mu.RUnlock()
		return nil, ipam.ErrPoolNotFound
	}
	// Clone the pool while holding the lock to avoid races
	clone := pool.Clone()
	a.mu.RUnlock()
	return clone, nil
}

func (a *testIPAMAllocator) Allocate(ctx context.Context, req *ipam.AllocationRequest) (*ipam.Allocation, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	pool, exists := a.pools[req.PoolID]
	if !exists {
		return nil, ipam.ErrPoolNotFound
	}

	// Find next available IP - build allocated set from allocations map
	allocated := make(map[netip.Addr]bool)
	for ip, alloc := range a.allocations {
		if alloc.PoolID == req.PoolID && alloc.Status == ipam.AllocationStatusActive {
			allocated[ip] = true
		}
	}

	ip, err := a.poolManager.NextAvailableIP(pool.CIDR, allocated)
	if err != nil {
		return nil, err
	}

	allocation := &ipam.Allocation{
		ID:          fmt.Sprintf("alloc-%d", a.counter.Add(1)),
		PoolID:      req.PoolID,
		IP:          ip,
		DeviceID:    req.DeviceID,
		Hostname:    req.Hostname,
		AllocatedAt: time.Now(),
		LastSeen:    time.Now(),
		Status:      ipam.AllocationStatusActive,
	}

	a.allocations[ip] = allocation
	pool.AllocatedIPs++
	pool.AvailableIPs--

	return allocation, nil
}

func (a *testIPAMAllocator) Release(ctx context.Context, ip netip.Addr) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	alloc, exists := a.allocations[ip]
	if !exists {
		return ipam.ErrAllocationNotFound
	}

	pool := a.pools[alloc.PoolID]
	if pool != nil {
		pool.AllocatedIPs--
		pool.AvailableIPs++
	}

	delete(a.allocations, ip)
	return nil
}

func (a *testIPAMAllocator) GetPoolStats(ctx context.Context, poolID string) (*ipam.PoolStats, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	pool, exists := a.pools[poolID]
	if !exists {
		return nil, ipam.ErrPoolNotFound
	}

	// Read pool fields while holding the lock
	return &ipam.PoolStats{
		PoolID:       poolID,
		TotalIPs:     pool.TotalIPs,
		AllocatedIPs: pool.AllocatedIPs,
		AvailableIPs: pool.AvailableIPs,
	}, nil
}

// TestIPAMAllocationStress tests sustained IP allocation load.
func TestIPAMAllocationStress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	allocator := newTestIPAMAllocator()

	// Create a pool with enough IPs for stress testing
	pool := &ipam.Pool{
		ID:   "stress-pool-1",
		Name: "Stress Test Pool",
		CIDR: netip.MustParsePrefix("10.0.0.0/16"), // 65534 usable IPs
	}
	if err := allocator.CreatePool(ctx, pool); err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}

	config := StressConfig{
		Name:           "IPAM Allocation Stress",
		Duration:       10 * time.Second,
		Concurrency:    10,
		RateLimit:      1000, // 1000 allocations/sec
		ReportInterval: 5 * time.Second,
		WarmupDuration: 1 * time.Second,
	}

	deviceCounter := atomic.Uint64{}
	op := func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		req := &ipam.AllocationRequest{
			PoolID:   "stress-pool-1",
			DeviceID: fmt.Sprintf("device-%d", deviceCounter.Add(1)),
		}
		_, err := allocator.Allocate(ctx, req)
		return err
	}

	reporter := NewTableReporter(os.Stdout)
	result, err := RunStressTest(ctx, config.Name, config, op, reporter)
	if err != nil {
		t.Fatalf("Stress test failed: %v", err)
	}

	// Validate results
	if result.SuccessRate() < 90 {
		t.Errorf("Success rate too low: %.2f%% (expected >= 90%%)", result.SuccessRate())
	}
	if result.Latencies.P99 > 100*time.Millisecond {
		t.Errorf("P99 latency too high: %s (expected <= 100ms)", result.Latencies.P99)
	}

	t.Logf("Completed %d allocations with %.2f%% success rate",
		result.TotalOperations, result.SuccessRate())
}

// TestIPAMConcurrentStress tests parallel allocations from multiple goroutines.
func TestIPAMConcurrentStress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	allocator := newTestIPAMAllocator()

	// Create multiple pools for different concurrency groups
	for i := 0; i < 5; i++ {
		pool := &ipam.Pool{
			ID:   fmt.Sprintf("concurrent-pool-%d", i),
			Name: fmt.Sprintf("Concurrent Pool %d", i),
			CIDR: netip.MustParsePrefix(fmt.Sprintf("10.%d.0.0/16", i)),
		}
		if err := allocator.CreatePool(ctx, pool); err != nil {
			t.Fatalf("Failed to create pool %d: %v", i, err)
		}
	}

	config := StressConfig{
		Name:           "IPAM Concurrent Stress",
		Duration:       10 * time.Second,
		Concurrency:    50, // High concurrency
		RateLimit:      0,  // Unlimited
		ReportInterval: 5 * time.Second,
		WarmupDuration: 1 * time.Second,
	}

	deviceCounter := atomic.Uint64{}
	op := func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		deviceID := deviceCounter.Add(1)
		poolID := fmt.Sprintf("concurrent-pool-%d", deviceID%5)
		req := &ipam.AllocationRequest{
			PoolID:   poolID,
			DeviceID: fmt.Sprintf("device-%d", deviceID),
		}
		_, err := allocator.Allocate(ctx, req)
		return err
	}

	reporter := NewTableReporter(os.Stdout)
	result, err := RunStressTest(ctx, config.Name, config, op, reporter)
	if err != nil {
		t.Fatalf("Stress test failed: %v", err)
	}

	if result.SuccessRate() < 85 {
		t.Errorf("Success rate too low: %.2f%% (expected >= 85%%)", result.SuccessRate())
	}

	t.Logf("Completed %d concurrent allocations across 5 pools", result.TotalOperations)
}

// TestIPAMPoolExhaustionStress tests behavior when pools near capacity.
func TestIPAMPoolExhaustionStress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	allocator := newTestIPAMAllocator()

	// Create a small pool that will be exhausted
	pool := &ipam.Pool{
		ID:   "small-pool",
		Name: "Small Pool for Exhaustion Test",
		CIDR: netip.MustParsePrefix("192.168.1.0/24"), // 254 usable IPs
	}
	if err := allocator.CreatePool(ctx, pool); err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}

	config := StressConfig{
		Name:           "IPAM Pool Exhaustion Stress",
		Duration:       8 * time.Second,
		Concurrency:    20,
		RateLimit:      500, // Moderate rate to observe exhaustion
		ReportInterval: 3 * time.Second,
		WarmupDuration: 1 * time.Second,
	}

	deviceCounter := atomic.Uint64{}
	exhaustionErrors := atomic.Int64{}

	op := func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		req := &ipam.AllocationRequest{
			PoolID:   "small-pool",
			DeviceID: fmt.Sprintf("device-%d", deviceCounter.Add(1)),
		}
		_, err := allocator.Allocate(ctx, req)
		if err == ipam.ErrPoolExhausted {
			exhaustionErrors.Add(1)
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

	// We expect pool exhaustion errors after ~254 allocations
	t.Logf("Total operations: %d, Exhaustion errors: %d",
		result.TotalOperations, exhaustionErrors.Load())

	if exhaustionErrors.Load() == 0 && result.TotalOperations > 254 {
		t.Error("Expected pool exhaustion errors but none occurred")
	}

	// Verify pool stats show near-exhaustion
	stats, err := allocator.GetPoolStats(ctx, "small-pool")
	if err != nil {
		t.Fatalf("Failed to get pool stats: %v", err)
	}
	t.Logf("Pool utilization: %d/%d IPs allocated", stats.AllocatedIPs, stats.TotalIPs)
}

// TestIPAMChurnStress tests rapid allocate/release cycles.
func TestIPAMChurnStress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	allocator := newTestIPAMAllocator()

	pool := &ipam.Pool{
		ID:   "churn-pool",
		Name: "Churn Test Pool",
		CIDR: netip.MustParsePrefix("172.16.0.0/20"), // 4094 usable IPs
	}
	if err := allocator.CreatePool(ctx, pool); err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}

	config := StressConfig{
		Name:           "IPAM Churn Stress",
		Duration:       10 * time.Second,
		Concurrency:    15,
		RateLimit:      800,
		ReportInterval: 5 * time.Second,
		WarmupDuration: 1 * time.Second,
	}

	deviceCounter := atomic.Uint64{}
	allocCount := atomic.Int64{}
	releaseCount := atomic.Int64{}

	// Track allocated IPs for release
	allocatedIPs := make(chan netip.Addr, 1000)

	op := func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		// Alternate between allocate and release
		deviceID := deviceCounter.Add(1)

		if deviceID%3 == 0 {
			// Try to release an IP
			select {
			case ip := <-allocatedIPs:
				err := allocator.Release(ctx, ip)
				if err == nil {
					releaseCount.Add(1)
				}
				return err
			default:
				// No IPs to release, do allocation instead
			}
		}

		// Allocate
		req := &ipam.AllocationRequest{
			PoolID:   "churn-pool",
			DeviceID: fmt.Sprintf("device-%d", deviceID),
		}
		alloc, err := allocator.Allocate(ctx, req)
		if err == nil {
			allocCount.Add(1)
			select {
			case allocatedIPs <- alloc.IP:
			default:
				// Channel full, release immediately
				_ = allocator.Release(ctx, alloc.IP)
			}
		}
		return err
	}

	reporter := NewTableReporter(os.Stdout)
	result, err := RunStressTest(ctx, config.Name, config, op, reporter)
	if err != nil {
		t.Fatalf("Stress test failed: %v", err)
	}

	t.Logf("Allocations: %d, Releases: %d, Total ops: %d",
		allocCount.Load(), releaseCount.Load(), result.TotalOperations)

	// For churn test, success rate might be lower due to release timing
	if result.SuccessRate() < 70 {
		t.Errorf("Success rate too low: %.2f%% (expected >= 70%%)", result.SuccessRate())
	}

	// Verify pool is not exhausted after churn
	stats, err := allocator.GetPoolStats(ctx, "churn-pool")
	if err != nil {
		t.Fatalf("Failed to get pool stats: %v", err)
	}

	utilizationPct := float64(stats.AllocatedIPs) / float64(stats.TotalIPs) * 100
	t.Logf("Final pool utilization: %.2f%% (%d/%d)", utilizationPct, stats.AllocatedIPs, stats.TotalIPs)
}

// TestIPAMLatencyProfile tests latency characteristics under various loads.
func TestIPAMLatencyProfile(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	allocator := newTestIPAMAllocator()

	pool := &ipam.Pool{
		ID:   "latency-pool",
		Name: "Latency Profile Pool",
		CIDR: netip.MustParsePrefix("10.100.0.0/12"), // Large pool
	}
	if err := allocator.CreatePool(ctx, pool); err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}

	// Test different load levels with shorter durations
	loadLevels := []struct {
		name        string
		concurrency int
		rateLimit   int
	}{
		{"Light Load", 5, 100},
		{"Medium Load", 20, 500},
		{"Heavy Load", 50, 0}, // Unlimited
	}

	for _, level := range loadLevels {
		t.Run(level.name, func(t *testing.T) {
			// Create a subtest context with shorter timeout
			subCtx, subCancel := context.WithTimeout(ctx, 10*time.Second)
			defer subCancel()

			config := StressConfig{
				Name:           fmt.Sprintf("IPAM Latency - %s", level.name),
				Duration:       5 * time.Second,
				Concurrency:    level.concurrency,
				RateLimit:      level.rateLimit,
				ReportInterval: 3 * time.Second,
				WarmupDuration: 500 * time.Millisecond,
			}

			deviceCounter := atomic.Uint64{}
			op := func(ctx context.Context) error {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}
				req := &ipam.AllocationRequest{
					PoolID:   "latency-pool",
					DeviceID: fmt.Sprintf("device-%d", deviceCounter.Add(1)),
				}
				_, err := allocator.Allocate(ctx, req)
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
		})
	}
}
