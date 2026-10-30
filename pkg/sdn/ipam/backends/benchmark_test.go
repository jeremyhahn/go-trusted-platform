package backends

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
)

// benchPoolCIDR is the pool every single-pool benchmark allocates from:
// 4094 usable addresses, refilled by a fresh backend when exhausted.
var benchPoolCIDR = netip.MustParsePrefix("10.0.0.0/20")

// newBenchBackend returns a memory backend holding one pool with the given
// ID and CIDR.
func newBenchBackend(b *testing.B, poolID string, cidr netip.Prefix) *MemoryBackend {
	b.Helper()
	backend := NewMemoryBackend()
	pool := &ipam.Pool{ID: poolID, Name: poolID, CIDR: cidr}
	if err := backend.CreatePool(context.Background(), pool); err != nil {
		b.Fatalf("create pool %s: %v", poolID, err)
	}
	return backend
}

// closeBenchBackend closes a backend and fails the benchmark on error.
func closeBenchBackend(b *testing.B, backend *MemoryBackend) {
	b.Helper()
	if err := backend.Close(); err != nil {
		b.Fatalf("close backend: %v", err)
	}
}

// fillPool allocates count addresses from the pool.
func fillPool(b *testing.B, backend *MemoryBackend, poolID string, count int) []netip.Addr {
	b.Helper()
	ctx := context.Background()
	ips := make([]netip.Addr, 0, count)
	for i := 0; i < count; i++ {
		alloc, err := backend.Allocate(ctx, &ipam.AllocationRequest{
			PoolID:   poolID,
			DeviceID: "fill-" + strconv.Itoa(i),
		})
		if err != nil {
			b.Fatalf("fill allocation %d: %v", i, err)
		}
		ips = append(ips, alloc.IP)
	}
	return ips
}

// BenchmarkMemoryBackend_Allocate measures next-free allocation from one
// pool. When the pool is exhausted the backend is replaced off the clock.
func BenchmarkMemoryBackend_Allocate(b *testing.B) {
	ctx := context.Background()
	backend := newBenchBackend(b, "bench", benchPoolCIDR)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := backend.Allocate(ctx, &ipam.AllocationRequest{
			PoolID:   "bench",
			DeviceID: "device-" + strconv.Itoa(i),
		})
		if errors.Is(err, ipam.ErrPoolExhausted) {
			b.StopTimer()
			closeBenchBackend(b, backend)
			backend = newBenchBackend(b, "bench", benchPoolCIDR)
			b.StartTimer()
			continue
		}
		if err != nil {
			b.Fatalf("allocate: %v", err)
		}
	}
	b.StopTimer()
	closeBenchBackend(b, backend)
}

// BenchmarkMemoryBackend_AllocateParallelPools measures allocation under
// contention: each goroutine allocates from and releases into its own pool
// on one shared backend.
func BenchmarkMemoryBackend_AllocateParallelPools(b *testing.B) {
	ctx := context.Background()
	backend := NewMemoryBackend()
	var nextPool atomic.Int32
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		n := nextPool.Add(1)
		poolID := "pool-" + strconv.Itoa(int(n))
		// The worker index spans two octets, so 65536 workers stay valid.
		i := n - 1
		pool := &ipam.Pool{
			ID:   poolID,
			Name: poolID,
			CIDR: netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)),
		}
		if err := backend.CreatePool(ctx, pool); err != nil {
			b.Errorf("create pool %s: %v", poolID, err)
			return
		}
		for pb.Next() {
			alloc, err := backend.Allocate(ctx, &ipam.AllocationRequest{
				PoolID:   poolID,
				DeviceID: poolID + "-device",
			})
			if err != nil {
				b.Errorf("allocate from %s: %v", poolID, err)
				return
			}
			if err := backend.Release(ctx, alloc.IP); err != nil {
				b.Errorf("release %v: %v", alloc.IP, err)
				return
			}
		}
	})
	b.StopTimer()
	closeBenchBackend(b, backend)
}

// BenchmarkMemoryBackend_AllocateExhaustedPool measures the refusal path:
// every allocation against a full pool returns ErrPoolExhausted.
func BenchmarkMemoryBackend_AllocateExhaustedPool(b *testing.B) {
	ctx := context.Background()
	cidr := netip.MustParsePrefix("10.0.0.0/28")
	backend := newBenchBackend(b, "full", cidr)
	fillPool(b, backend, "full", 14)
	req := &ipam.AllocationRequest{PoolID: "full", DeviceID: "late"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := backend.Allocate(ctx, req)
		if !errors.Is(err, ipam.ErrPoolExhausted) {
			b.Fatalf("allocate from a full pool: err = %v, want ErrPoolExhausted", err)
		}
	}
	b.StopTimer()
	closeBenchBackend(b, backend)
}

// BenchmarkMemoryBackend_AllocateReleaseChurn measures one allocate and
// one release per iteration, the steady state of a pool under churn.
func BenchmarkMemoryBackend_AllocateReleaseChurn(b *testing.B) {
	ctx := context.Background()
	backend := newBenchBackend(b, "churn", benchPoolCIDR)
	req := &ipam.AllocationRequest{PoolID: "churn", DeviceID: "churner"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		alloc, err := backend.Allocate(ctx, req)
		if err != nil {
			b.Fatalf("allocate: %v", err)
		}
		if err := backend.Release(ctx, alloc.IP); err != nil {
			b.Fatalf("release %v: %v", alloc.IP, err)
		}
	}
	b.StopTimer()
	closeBenchBackend(b, backend)
}

// BenchmarkMemoryBackend_AllocateLoadLevels measures allocate and release
// in a pool already filled to 10, 50 and 90 percent, where the free-address
// search has progressively more set bits to skip.
func BenchmarkMemoryBackend_AllocateLoadLevels(b *testing.B) {
	const capacity = 4094 // usable addresses in benchPoolCIDR
	for _, percent := range []int{10, 50, 90} {
		b.Run(strconv.Itoa(percent)+"pct", func(b *testing.B) {
			ctx := context.Background()
			backend := newBenchBackend(b, "load", benchPoolCIDR)
			fillPool(b, backend, "load", capacity*percent/100)
			req := &ipam.AllocationRequest{PoolID: "load", DeviceID: "load-device"}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				alloc, err := backend.Allocate(ctx, req)
				if err != nil {
					b.Fatalf("allocate at %d%% fill: %v", percent, err)
				}
				if err := backend.Release(ctx, alloc.IP); err != nil {
					b.Fatalf("release %v: %v", alloc.IP, err)
				}
			}
			b.StopTimer()
			closeBenchBackend(b, backend)
		})
	}
}
