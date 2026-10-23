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

//go:build integration

// Package container provides benchmark tests for container operations.
// These benchmarks measure performance of container lifecycle operations
// across different protocol adapters.
//
// Run benchmarks via:
//
//	make bench-container
package container

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// =============================================================================
// Container Operation Benchmarks
// =============================================================================

// BenchmarkContainerCreate benchmarks container creation time.
func BenchmarkContainerCreate(b *testing.B) {

	ctx := context.Background()
	adapter := NewMockAdapter()

	if err := adapter.Setup(ctx); err != nil {
		b.Fatalf("Setup failed: %v", err)
	}
	defer adapter.Teardown()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		name := fmt.Sprintf("bench-create-%d", i)
		opts := CreateOptions{
			Name:  name,
			Image: TestImageAlpine,
		}

		container, err := adapter.Create(ctx, opts)
		if err != nil {
			b.Fatalf("Create failed: %v", err)
		}

		// Cleanup
		adapter.Remove(ctx, container.ID, true)
	}
}

// BenchmarkContainerLifecycle benchmarks full container lifecycle.
func BenchmarkContainerLifecycle(b *testing.B) {

	ctx := context.Background()
	adapter := NewMockAdapter()

	if err := adapter.Setup(ctx); err != nil {
		b.Fatalf("Setup failed: %v", err)
	}
	defer adapter.Teardown()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		name := fmt.Sprintf("bench-lifecycle-%d", i)
		opts := CreateOptions{
			Name:    name,
			Image:   TestImageAlpine,
			Command: []string{"sleep", "1"},
		}

		// Create
		container, err := adapter.Create(ctx, opts)
		if err != nil {
			b.Fatalf("Create failed: %v", err)
		}

		// Start
		if err := adapter.Start(ctx, container.ID); err != nil {
			b.Fatalf("Start failed: %v", err)
		}

		// Stop
		if err := adapter.Stop(ctx, container.ID, 5*time.Second); err != nil {
			b.Fatalf("Stop failed: %v", err)
		}

		// Remove
		if err := adapter.Remove(ctx, container.ID, false); err != nil {
			b.Fatalf("Remove failed: %v", err)
		}
	}
}

// BenchmarkContainerGet benchmarks container retrieval.
func BenchmarkContainerGet(b *testing.B) {

	ctx := context.Background()
	adapter := NewMockAdapter()

	if err := adapter.Setup(ctx); err != nil {
		b.Fatalf("Setup failed: %v", err)
	}
	defer adapter.Teardown()

	// Create a container to get
	opts := CreateOptions{
		Name:  "bench-get-target",
		Image: TestImageAlpine,
	}
	container, err := adapter.Create(ctx, opts)
	if err != nil {
		b.Fatalf("Setup container creation failed: %v", err)
	}
	defer adapter.Remove(ctx, container.ID, true)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := adapter.Get(ctx, container.ID)
		if err != nil {
			b.Fatalf("Get failed: %v", err)
		}
	}
}

// BenchmarkContainerList benchmarks container listing.
func BenchmarkContainerList(b *testing.B) {

	ctx := context.Background()
	adapter := NewMockAdapter()

	if err := adapter.Setup(ctx); err != nil {
		b.Fatalf("Setup failed: %v", err)
	}
	defer adapter.Teardown()

	// Create multiple containers
	var containerIDs []string
	for i := 0; i < 10; i++ {
		opts := CreateOptions{
			Name:  fmt.Sprintf("bench-list-%d", i),
			Image: TestImageAlpine,
		}
		container, err := adapter.Create(ctx, opts)
		if err != nil {
			b.Fatalf("Setup container creation failed: %v", err)
		}
		containerIDs = append(containerIDs, container.ID)
	}
	defer func() {
		for _, id := range containerIDs {
			adapter.Remove(ctx, id, true)
		}
	}()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := adapter.List(ctx, ListOptions{All: true})
		if err != nil {
			b.Fatalf("List failed: %v", err)
		}
	}
}

// BenchmarkContainerAttest benchmarks container attestation.
func BenchmarkContainerAttest(b *testing.B) {

	ctx := context.Background()
	adapter := NewMockAdapter()

	if err := adapter.Setup(ctx); err != nil {
		b.Fatalf("Setup failed: %v", err)
	}
	defer adapter.Teardown()

	// Create and start a container
	opts := CreateOptions{
		Name:  "bench-attest-target",
		Image: TestImageAlpine,
	}
	container, err := adapter.Create(ctx, opts)
	if err != nil {
		b.Fatalf("Setup container creation failed: %v", err)
	}
	defer adapter.Remove(ctx, container.ID, true)

	if err := adapter.Start(ctx, container.ID); err != nil {
		b.Fatalf("Setup container start failed: %v", err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := adapter.Attest(ctx, container.ID)
		if err != nil {
			b.Fatalf("Attest failed: %v", err)
		}
	}
}

// =============================================================================
// Parallel Operation Benchmarks
// =============================================================================

// BenchmarkContainerCreateParallel benchmarks parallel container creation.
func BenchmarkContainerCreateParallel(b *testing.B) {

	ctx := context.Background()
	adapter := NewMockAdapter()

	if err := adapter.Setup(ctx); err != nil {
		b.Fatalf("Setup failed: %v", err)
	}
	defer adapter.Teardown()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			name := fmt.Sprintf("bench-parallel-%d-%d", time.Now().UnixNano(), i)
			i++
			opts := CreateOptions{
				Name:  name,
				Image: TestImageAlpine,
			}

			container, err := adapter.Create(ctx, opts)
			if err != nil {
				b.Errorf("Create failed: %v", err)
				continue
			}

			adapter.Remove(ctx, container.ID, true)
		}
	})
}

// BenchmarkContainerGetParallel benchmarks parallel container retrieval.
func BenchmarkContainerGetParallel(b *testing.B) {

	ctx := context.Background()
	adapter := NewMockAdapter()

	if err := adapter.Setup(ctx); err != nil {
		b.Fatalf("Setup failed: %v", err)
	}
	defer adapter.Teardown()

	// Create a container to get
	opts := CreateOptions{
		Name:  "bench-get-parallel-target",
		Image: TestImageAlpine,
	}
	container, err := adapter.Create(ctx, opts)
	if err != nil {
		b.Fatalf("Setup container creation failed: %v", err)
	}
	defer adapter.Remove(ctx, container.ID, true)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := adapter.Get(ctx, container.ID)
			if err != nil {
				b.Errorf("Get failed: %v", err)
			}
		}
	})
}

// =============================================================================
// Memory Allocation Benchmarks
// =============================================================================

// BenchmarkContainerCreateAlloc benchmarks memory allocations for container creation.
func BenchmarkContainerCreateAlloc(b *testing.B) {

	ctx := context.Background()
	adapter := NewMockAdapter()

	if err := adapter.Setup(ctx); err != nil {
		b.Fatalf("Setup failed: %v", err)
	}
	defer adapter.Teardown()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		name := fmt.Sprintf("bench-alloc-%d", i)
		opts := CreateOptions{
			Name:  name,
			Image: TestImageAlpine,
			Labels: map[string]string{
				"test": "alloc",
			},
			Environment: map[string]string{
				"VAR1": "value1",
				"VAR2": "value2",
			},
		}

		container, err := adapter.Create(ctx, opts)
		if err != nil {
			b.Fatalf("Create failed: %v", err)
		}

		adapter.Remove(ctx, container.ID, true)
	}
}

// BenchmarkContainerAttestAlloc benchmarks memory allocations for attestation.
func BenchmarkContainerAttestAlloc(b *testing.B) {

	ctx := context.Background()
	adapter := NewMockAdapter()

	if err := adapter.Setup(ctx); err != nil {
		b.Fatalf("Setup failed: %v", err)
	}
	defer adapter.Teardown()

	opts := CreateOptions{
		Name:  "bench-attest-alloc-target",
		Image: TestImageAlpine,
	}
	container, err := adapter.Create(ctx, opts)
	if err != nil {
		b.Fatalf("Setup container creation failed: %v", err)
	}
	defer adapter.Remove(ctx, container.ID, true)

	if err := adapter.Start(ctx, container.ID); err != nil {
		b.Fatalf("Setup container start failed: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := adapter.Attest(ctx, container.ID)
		if err != nil {
			b.Fatalf("Attest failed: %v", err)
		}
	}
}

// =============================================================================
// Throughput Tests
// =============================================================================

// TestContainerThroughput measures container operation throughput.
func TestContainerThroughput(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	adapter := NewMockAdapter()
	require.NoError(t, adapter.Setup(ctx))
	defer adapter.Teardown()

	t.Run("CreateThroughput", func(t *testing.T) {
		count := 100
		start := time.Now()

		for i := 0; i < count; i++ {
			opts := CreateOptions{
				Name:  fmt.Sprintf("throughput-%d", i),
				Image: TestImageAlpine,
			}
			container, err := adapter.Create(ctx, opts)
			require.NoError(t, err)
			adapter.Remove(ctx, container.ID, true)
		}

		elapsed := time.Since(start)
		throughput := float64(count) / elapsed.Seconds()
		t.Logf("Create throughput: %.2f containers/second", throughput)
	})

	t.Run("LifecycleThroughput", func(t *testing.T) {
		count := 50
		start := time.Now()

		for i := 0; i < count; i++ {
			opts := CreateOptions{
				Name:  fmt.Sprintf("lifecycle-throughput-%d", i),
				Image: TestImageAlpine,
			}
			container, err := adapter.Create(ctx, opts)
			require.NoError(t, err)

			require.NoError(t, adapter.Start(ctx, container.ID))
			require.NoError(t, adapter.Stop(ctx, container.ID, 5*time.Second))
			require.NoError(t, adapter.Remove(ctx, container.ID, false))
		}

		elapsed := time.Since(start)
		throughput := float64(count) / elapsed.Seconds()
		t.Logf("Lifecycle throughput: %.2f containers/second", throughput)
	})
}

// =============================================================================
// Latency Tests
// =============================================================================

// TestContainerLatency measures container operation latencies.
func TestContainerLatency(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	adapter := NewMockAdapter()
	require.NoError(t, adapter.Setup(ctx))
	defer adapter.Teardown()

	t.Run("CreateLatency", func(t *testing.T) {
		var durations []time.Duration

		for i := 0; i < 10; i++ {
			start := time.Now()
			opts := CreateOptions{
				Name:  fmt.Sprintf("latency-create-%d", i),
				Image: TestImageAlpine,
			}
			container, err := adapter.Create(ctx, opts)
			require.NoError(t, err)
			durations = append(durations, time.Since(start))
			adapter.Remove(ctx, container.ID, true)
		}

		avg, p50, p99 := calculateLatencyStats(durations)
		t.Logf("Create latency - Avg: %v, P50: %v, P99: %v", avg, p50, p99)
	})

	t.Run("StartLatency", func(t *testing.T) {
		var durations []time.Duration

		for i := 0; i < 10; i++ {
			opts := CreateOptions{
				Name:  fmt.Sprintf("latency-start-%d", i),
				Image: TestImageAlpine,
			}
			container, err := adapter.Create(ctx, opts)
			require.NoError(t, err)

			start := time.Now()
			require.NoError(t, adapter.Start(ctx, container.ID))
			durations = append(durations, time.Since(start))

			adapter.Remove(ctx, container.ID, true)
		}

		avg, p50, p99 := calculateLatencyStats(durations)
		t.Logf("Start latency - Avg: %v, P50: %v, P99: %v", avg, p50, p99)
	})

	t.Run("AttestLatency", func(t *testing.T) {
		opts := CreateOptions{
			Name:  "latency-attest-target",
			Image: TestImageAlpine,
		}
		container, err := adapter.Create(ctx, opts)
		require.NoError(t, err)
		defer adapter.Remove(ctx, container.ID, true)

		require.NoError(t, adapter.Start(ctx, container.ID))

		var durations []time.Duration
		for i := 0; i < 10; i++ {
			start := time.Now()
			_, err := adapter.Attest(ctx, container.ID)
			require.NoError(t, err)
			durations = append(durations, time.Since(start))
		}

		avg, p50, p99 := calculateLatencyStats(durations)
		t.Logf("Attest latency - Avg: %v, P50: %v, P99: %v", avg, p50, p99)
	})
}

// calculateLatencyStats calculates average, P50, and P99 latencies.
func calculateLatencyStats(durations []time.Duration) (avg, p50, p99 time.Duration) {
	if len(durations) == 0 {
		return
	}

	// Sort durations
	sorted := make([]time.Duration, len(durations))
	copy(sorted, durations)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j] < sorted[i] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	// Calculate average
	var total time.Duration
	for _, d := range sorted {
		total += d
	}
	avg = total / time.Duration(len(sorted))

	// Calculate percentiles
	p50 = sorted[len(sorted)*50/100]
	p99 = sorted[len(sorted)*99/100]

	return
}
