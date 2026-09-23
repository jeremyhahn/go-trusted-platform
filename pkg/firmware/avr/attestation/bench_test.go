// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// Dual-licensed under AGPL-3.0 or a commercial license.

package attestation

import (
	"context"
	"testing"

	bmcattestation "github.com/jeremyhahn/go-trusted-platform/pkg/bmc/attestation"
)

// These benchmarks measure the HOST side only. A real device answers over a
// serial link at kilobaud and dominates any wall clock a fleet sees, so what
// is worth watching here is the per-record cost of parsing and appraisal,
// which a gateway pays once per device per collection round.

func BenchmarkGetInfo_Frame(b *testing.B) {
	backend := newBenchBackend(b)
	ev := evidenceFor(defaultFrame(attestNonce(0x42)))
	ctx := context.Background()

	b.ReportAllocs()
	for b.Loop() {
		if _, err := backend.GetInfo(ctx, ev); err != nil {
			b.Fatalf("GetInfo: %v", err)
		}
	}
}

func BenchmarkCompare_GoldenBuild(b *testing.B) {
	backend := newBenchBackend(b)
	live := evidenceFor(defaultFrame(attestNonce(0x42)))
	ref := evidenceFor(defaultFrame(attestNonce(0x43)))
	ctx := context.Background()

	b.ReportAllocs()
	for b.Loop() {
		if _, err := backend.Compare(ctx, live, ref); err != nil {
			b.Fatalf("Compare: %v", err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	backend := newBenchBackend(b)
	nonce := attestNonce(0x42)
	ev := evidenceFor(defaultFrame(nonce))
	ev.Nonce = nonce
	verifier, err := NewVerifier(backend)
	if err != nil {
		b.Fatalf("NewVerifier: %v", err)
	}
	pol := &bmcattestation.Policy{
		AllowedVendors:   []bmcattestation.Vendor{Vendor},
		RequireNonceEcho: true,
		Reference:        evidenceFor(defaultFrame(attestNonce(0x43))),
		MaxAgeSeconds:    300,
	}
	ctx := context.Background()

	b.ReportAllocs()
	for b.Loop() {
		res, err := verifier.Verify(ctx, ev, pol)
		if err != nil {
			b.Fatalf("Verify: %v", err)
		}
		if !res.Passed {
			b.Fatalf("Passed = false: %v", res.Reasons)
		}
	}
}

// newBenchBackend attaches a backend for a benchmark, failing it when the
// fake device cannot be reached.
func newBenchBackend(b *testing.B) *Backend {
	b.Helper()
	backend, err := New(context.Background(), testConfig(frozenNow), newTestDevice(secureElementLink()))
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	return backend
}
