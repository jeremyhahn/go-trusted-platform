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

package barrier_gate

import (
	"context"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
)

// TestM6_SealedDaemonRefusesRemotePorts asserts that a freshly-booted
// platformd configured with seal_strategy=software
// comes up in the uninitialized state, binds the gate /healthz endpoint on
// 127.0.0.1:9446, and does NOT bind any production transport ports.
func TestM6_SealedDaemonRefusesRemotePorts(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	cfg := DefaultHarnessConfig()
	h := NewHarness(cfg)
	if err := h.WipeDataDir(); err != nil {
		t.Fatalf("wipe data dir: %v", err)
	}
	if err := h.Start(ctx); err != nil {
		t.Fatalf("harness start: %v", err)
	}
	t.Cleanup(func() {
		_ = h.Stop()
	})

	if err := h.WaitGateReady(ctx, rest.PlatformStateUninitialized, 60*time.Second); err != nil {
		t.Fatalf("gate did not report uninitialized: %v", err)
	}

	body, err := h.FetchGateHealth(ctx)
	if err != nil {
		t.Fatalf("fetch gate /healthz: %v", err)
	}
	if body.State != rest.PlatformStateUninitialized {
		t.Fatalf("unexpected gate state: want=%q got=%q",
			rest.PlatformStateUninitialized, body.State)
	}
	if body.Ready {
		t.Fatalf("gate /healthz ready=true while uninitialized; want false")
	}

	if err := h.AssertRemoteTransportsRefused(ctx); err != nil {
		t.Fatalf("production ports must refuse while gated: %v", err)
	}
}

// TestM6_GateAcceptsInitThenTransitions drives a cold-boot /init through
// the gate and verifies the M6 production handoff contract:
//
//  1. Gate boots in uninitialized state.
//  2. POST /init returns 200 with a non-empty ceremony_id.
//  3. Gate listener (port 9446) stops accepting new connections.
//  4. Production REST listener begins accepting connections.
//  5. Production gRPC and QUIC ports accept TCP-probe connections.
func TestM6_GateAcceptsInitThenTransitions(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancel)

	cfg := DefaultHarnessConfig()
	h := NewHarness(cfg)
	if err := h.WipeDataDir(); err != nil {
		t.Fatalf("wipe data dir: %v", err)
	}
	if err := h.Start(ctx); err != nil {
		t.Fatalf("harness start: %v", err)
	}
	t.Cleanup(func() {
		_ = h.Stop()
	})

	if err := h.WaitGateReady(ctx, rest.PlatformStateUninitialized, 60*time.Second); err != nil {
		t.Fatalf("gate did not report uninitialized: %v", err)
	}

	resp, err := postInitJSON(ctx, cfg, &rest.BarrierInitRequest{
		SOPIN:    cfg.SOPin,
		UserPIN:  cfg.UserPin,
		Hostname: "cp.test",
		SANs:     []string{"cp.test", "127.0.0.1"},
	})
	if err != nil {
		t.Fatalf("POST /init: %v", err)
	}
	if resp == nil {
		t.Fatalf("POST /init: nil response")
	}
	if resp.CeremonyID == "" {
		t.Fatalf("POST /init: response missing ceremony_id: %+v", resp)
	}

	// Gate must shut down — production listeners cannot bind on the
	// gate's loopback :9446 because it's a unique port, but the
	// canonical M6 contract states the gate listener stops accepting
	// once the barrier transitions.
	if err := h.WaitGateGone(ctx, 90*time.Second); err != nil {
		t.Fatalf("gate listener did not shut down after init: %v", err)
	}

	// Production REST listener must come up.
	if err := h.WaitProductionRESTReady(ctx, 90*time.Second); err != nil {
		t.Fatalf("production REST did not bind after gate release: %v", err)
	}

	// Sanity-check: every production transport accepts TCP connections.
	if err := h.AssertProductionTransportsAccept(ctx); err != nil {
		t.Fatalf("production transports must accept after handoff: %v", err)
	}
}

// TestM6_WarmBoot_UnsealThenTransitions covers the warm-boot path.
//
// The originally-specified "already-unsealed daemon skips gate entirely
// on restart" assertion cannot be exercised: the platform has no
// automatic unseal, so the restarted daemon comes up sealed.
//
// This test therefore proves the same M6 transition contract (gate →
// production handoff) via the warm-boot /unseal path:
//
//  1. Fresh init (cold path) so the barrier is initialized.
//  2. Stop platformd, then Start it again.
//  3. Gate /healthz reports state=sealed (barrier persisted, no
//     automatic unseal).
//  4. POST /unseal with the master credentials returns 200.
//  5. Gate listener shuts down; production REST listener binds.
func TestM6_WarmBoot_UnsealThenTransitions(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	t.Cleanup(cancel)

	cfg := DefaultHarnessConfig()
	h := NewHarness(cfg)
	if err := h.WipeDataDir(); err != nil {
		t.Fatalf("wipe data dir: %v", err)
	}
	if err := h.Start(ctx); err != nil {
		t.Fatalf("harness initial start: %v", err)
	}
	t.Cleanup(func() {
		_ = h.Stop()
	})

	// ---- Cold init so the barrier is initialized & unsealed ----------------
	if err := h.WaitGateReady(ctx, rest.PlatformStateUninitialized, 60*time.Second); err != nil {
		t.Fatalf("gate did not report uninitialized: %v", err)
	}
	initResp, err := postInitJSON(ctx, cfg, &rest.BarrierInitRequest{
		SOPIN:    cfg.SOPin,
		UserPIN:  cfg.UserPin,
		Hostname: "cp.test",
		SANs:     []string{"cp.test", "127.0.0.1"},
	})
	if err != nil {
		t.Fatalf("POST /init (cold): %v", err)
	}
	if initResp == nil || initResp.CeremonyID == "" {
		t.Fatalf("POST /init (cold): missing ceremony_id: %+v", initResp)
	}
	if err := h.WaitGateGone(ctx, 90*time.Second); err != nil {
		t.Fatalf("gate did not shut down after cold init: %v", err)
	}
	if err := h.WaitProductionRESTReady(ctx, 90*time.Second); err != nil {
		t.Fatalf("production REST did not bind after cold init: %v", err)
	}

	// ---- Warm restart -----------------------------------------------------
	if err := h.Restart(ctx); err != nil {
		t.Fatalf("harness restart: %v", err)
	}

	// The gate must rebind in the sealed state. We tolerate `sealed` and
	// `unsealing` as valid intermediate states; there is no automatic
	// unseal, so the steady state is `sealed`.
	if err := h.WaitGateReady(ctx, rest.PlatformStateSealed, 60*time.Second); err != nil {
		t.Fatalf("post-restart gate did not report sealed: %v", err)
	}
	body, err := h.FetchGateHealth(ctx)
	if err != nil {
		t.Fatalf("post-restart fetch gate /healthz: %v", err)
	}
	if body.State != rest.PlatformStateSealed {
		t.Fatalf("post-restart gate state: want=%q got=%q",
			rest.PlatformStateSealed, body.State)
	}
	if body.Ready {
		t.Fatalf("post-restart gate /healthz ready=true while sealed; want false")
	}

	// Production transports must still refuse — the gate is up again.
	if err := h.AssertRemoteTransportsRefused(ctx); err != nil {
		t.Fatalf("post-restart production ports must refuse while gated: %v", err)
	}

	// ---- Unseal via the gate ----------------------------------------------
	unsealResp, err := postUnsealJSON(ctx, cfg, &rest.BarrierUnsealRequest{
		Secret: cfg.UserPin,
	})
	if err != nil {
		t.Fatalf("POST /unseal: %v", err)
	}
	if unsealResp == nil {
		t.Fatalf("POST /unseal: nil response")
	}
	if unsealResp.Sealed {
		t.Fatalf("POST /unseal: response indicates still sealed: %+v", unsealResp)
	}

	// Gate must shut down and production REST must bind.
	if err := h.WaitGateGone(ctx, 90*time.Second); err != nil {
		t.Fatalf("gate did not shut down after unseal: %v", err)
	}
	if err := h.WaitProductionRESTReady(ctx, 90*time.Second); err != nil {
		t.Fatalf("production REST did not bind after unseal: %v", err)
	}
}
