package overlay

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"testing"
)

// Load profiles formerly driven by test/integration/sdn/stress
// (overlay_stress_test.go). The correctness assertions those generators
// carried live in controller_test.go (TestController_ConcurrentMACChurn,
// TestController_ConcurrentVTEPAddRemove); these benchmarks measure cost.

const benchVNICount = 8

// newBenchController returns a started controller with benchVNICount VNIs
// (100..107) and a discard logger, stopped when the benchmark ends.
func newBenchController(b *testing.B) (*Controller, context.Context) {
	b.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctrl := newTestController(b, WithLogger(logger))
	ctx := context.Background()
	if err := ctrl.Start(ctx); err != nil {
		b.Fatalf("Start() error = %v", err)
	}
	b.Cleanup(func() {
		if err := ctrl.Stop(ctx); err != nil {
			b.Errorf("Stop() error = %v", err)
		}
	})

	for i := uint32(0); i < benchVNICount; i++ {
		if err := ctrl.AddVNI(ctx, &VNIConfig{VNI: 100 + i, VLAN: uint16(10 + i)}); err != nil {
			b.Fatalf("AddVNI(%d) error = %v", 100+i, err)
		}
	}
	return ctrl, ctx
}

func benchVNI(n uint64) uint32 {
	return 100 + uint32(n%benchVNICount)
}

// BenchmarkController_LearnMAC measures learning distinct remote MACs
// spread across the VNIs and remote VTEPs.
func BenchmarkController_LearnMAC(b *testing.B) {
	ctrl, ctx := newBenchController(b)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		n := uint64(i)
		if err := ctrl.LearnMAC(ctx, testMAC(n), benchVNI(n), testVTEPIP(n%254+1)); err != nil {
			b.Fatalf("LearnMAC() error = %v", err)
		}
	}
}

// BenchmarkController_LearnForgetMACChurn measures a learn followed by a
// forget of the same MAC, from parallel goroutines.
func BenchmarkController_LearnForgetMACChurn(b *testing.B) {
	ctrl, ctx := newBenchController(b)
	b.ReportAllocs()
	b.ResetTimer()

	var worker atomic.Uint64
	b.RunParallel(func(pb *testing.PB) {
		base := worker.Add(1) << 24 // testMAC encodes the low 32 bits
		for n := base; pb.Next(); n++ {
			vni := benchVNI(n)
			if err := ctrl.LearnMAC(ctx, testMAC(n), vni, testVTEPIP(n%254+1)); err != nil {
				b.Errorf("LearnMAC() error = %v", err)
				return
			}
			if err := ctrl.ForgetMAC(ctx, testMAC(n), vni); err != nil {
				b.Errorf("ForgetMAC() error = %v", err)
				return
			}
		}
	})
}

// BenchmarkController_AddRemoveVTEP measures adding and removing a remote VTEP.
func BenchmarkController_AddRemoveVTEP(b *testing.B) {
	ctrl, ctx := newBenchController(b)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ip := testVTEPIP(uint64(i)%250 + 2)
		if err := ctrl.AddVTEP(ctx, &VTEPInfo{NodeID: "remote", IP: ip, Healthy: true}); err != nil {
			b.Fatalf("AddVTEP() error = %v", err)
		}
		if err := ctrl.RemoveVTEP(ctx, ip); err != nil {
			b.Fatalf("RemoveVTEP() error = %v", err)
		}
	}
}

// BenchmarkController_VNIAddGetRemove measures the full lifecycle of a VNI.
func BenchmarkController_VNIAddGetRemove(b *testing.B) {
	ctrl, ctx := newBenchController(b)
	b.ReportAllocs()
	b.ResetTimer()

	const vni = 5000
	for i := 0; i < b.N; i++ {
		if err := ctrl.AddVNI(ctx, &VNIConfig{VNI: vni, VLAN: 500}); err != nil {
			b.Fatalf("AddVNI() error = %v", err)
		}
		if _, err := ctrl.GetVNI(ctx, vni); err != nil {
			b.Fatalf("GetVNI() error = %v", err)
		}
		if err := ctrl.RemoveVNI(ctx, vni); err != nil {
			b.Fatalf("RemoveVNI() error = %v", err)
		}
	}
}

// BenchmarkController_LearnMACWithIP measures learning a MAC/IP binding.
func BenchmarkController_LearnMACWithIP(b *testing.B) {
	ctrl, ctx := newBenchController(b)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		n := uint64(i)
		ip := netip.AddrFrom4([4]byte{172, 16, byte(n >> 8), byte(n)})
		if err := ctrl.LearnMACWithIP(ctx, testMAC(n), ip, benchVNI(n), testVTEPIP(n%254+1)); err != nil {
			b.Fatalf("LearnMACWithIP() error = %v", err)
		}
	}
}

// BenchmarkController_CombinedLoad runs MAC churn, VNI lookups and VTEP
// listing together from parallel goroutines, the mix the combined stress
// generator applied.
func BenchmarkController_CombinedLoad(b *testing.B) {
	ctrl, ctx := newBenchController(b)
	b.ReportAllocs()
	b.ResetTimer()

	var worker atomic.Uint64
	b.RunParallel(func(pb *testing.PB) {
		base := worker.Add(1) << 24 // testMAC encodes the low 32 bits
		for n := base; pb.Next(); n++ {
			vni := benchVNI(n)
			switch n % 4 {
			case 0:
				if err := ctrl.LearnMAC(ctx, testMAC(n), vni, testVTEPIP(n%254+1)); err != nil {
					b.Errorf("LearnMAC() error = %v", err)
					return
				}
			case 1:
				if _, err := ctrl.GetVNI(ctx, vni); err != nil {
					b.Errorf("GetVNI() error = %v", err)
					return
				}
			case 2:
				if _, err := ctrl.GetRemoteMACs(ctx, vni); err != nil {
					b.Errorf("GetRemoteMACs() error = %v", err)
					return
				}
			default:
				if _, err := ctrl.ListVTEPs(ctx); err != nil {
					b.Errorf("ListVTEPs() error = %v", err)
					return
				}
			}
		}
	})
}
