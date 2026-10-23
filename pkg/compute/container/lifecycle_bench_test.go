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

package container

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

// newBenchOrchestrator returns an orchestrator over the in-memory podman
// backend, so the benchmarks measure the orchestrator's own bookkeeping.
func newBenchOrchestrator(b *testing.B, opts ...OrchestratorOption) *Orchestrator {
	b.Helper()
	orch, err := NewOrchestrator(OrchestratorConfig{Logger: testLogger()},
		append([]OrchestratorOption{WithPodmanBackend(NewMockPodmanBackend())}, opts...)...)
	if err != nil {
		b.Fatalf("NewOrchestrator: %v", err)
	}
	b.Cleanup(func() { orch.Close() })
	return orch
}

// benchCreate creates one container named name, failing the benchmark on error.
func benchCreate(b *testing.B, orch *Orchestrator, name string) *Container {
	container, err := orch.Create(context.Background(), &OrchestratorContainerSpec{Name: name, Image: "alpine:latest"})
	if err != nil {
		b.Fatalf("Create %s: %v", name, err)
	}
	return container
}

func BenchmarkOrchestratorCreate(b *testing.B) {
	orch := newBenchOrchestrator(b)
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		benchCreate(b, orch, fmt.Sprintf("bench-create-%d", i))
		i++
	}
}

func BenchmarkOrchestratorCreateParallel(b *testing.B) {
	orch := newBenchOrchestrator(b)
	var counter atomic.Int64
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			name := fmt.Sprintf("bench-create-parallel-%d", counter.Add(1))
			if _, err := orch.Create(context.Background(), &OrchestratorContainerSpec{Name: name, Image: "alpine:latest"}); err != nil {
				b.Errorf("Create %s: %v", name, err)
				return
			}
		}
	})
}

func BenchmarkOrchestratorLifecycle(b *testing.B) {
	orch := newBenchOrchestrator(b)
	ctx := context.Background()
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		container := benchCreate(b, orch, fmt.Sprintf("bench-lifecycle-%d", i))
		i++
		if err := orch.Start(ctx, container.ID); err != nil {
			b.Fatalf("Start: %v", err)
		}
		if err := orch.Stop(ctx, container.ID, time.Second); err != nil {
			b.Fatalf("Stop: %v", err)
		}
		if err := orch.Remove(ctx, container.ID, false); err != nil {
			b.Fatalf("Remove: %v", err)
		}
	}
}

func BenchmarkOrchestratorGet(b *testing.B) {
	orch := newBenchOrchestrator(b)
	container := benchCreate(b, orch, "bench-get")
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := orch.Get(ctx, container.ID); err != nil {
			b.Fatalf("Get: %v", err)
		}
	}
}

func BenchmarkOrchestratorGetParallel(b *testing.B) {
	orch := newBenchOrchestrator(b)
	container := benchCreate(b, orch, "bench-get-parallel")
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := orch.Get(context.Background(), container.ID); err != nil {
				b.Errorf("Get: %v", err)
				return
			}
		}
	})
}

func BenchmarkOrchestratorList(b *testing.B) {
	orch := newBenchOrchestrator(b)
	for i := range 100 {
		benchCreate(b, orch, fmt.Sprintf("bench-list-%d", i))
	}
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := orch.List(ctx, ListOptions{}); err != nil {
			b.Fatalf("List: %v", err)
		}
	}
}

func BenchmarkOrchestratorAttest(b *testing.B) {
	tpm := NewMockTPMProvider()
	attestor, err := NewContainerAttestor(tpm, WithAttestingRuntime(newTestAttestingRuntime(b, tpm)))
	if err != nil {
		b.Fatalf("NewContainerAttestor: %v", err)
	}
	orch, err := NewOrchestrator(OrchestratorConfig{Logger: testLogger(), EnableAttestation: true},
		WithPodmanBackend(NewMockPodmanBackend()),
		WithAttestor(attestor),
		WithImageDigestResolver(fixedDigestResolver{}),
	)
	if err != nil {
		b.Fatalf("NewOrchestrator: %v", err)
	}
	b.Cleanup(func() { orch.Close() })

	container := benchCreate(b, orch, "bench-attest")
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := orch.Attest(ctx, container.ID); err != nil {
			b.Fatalf("Attest: %v", err)
		}
	}
}
