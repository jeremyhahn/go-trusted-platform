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

package loadbalancer

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// fakeConn is a no-op net.Conn returned by the fake dialer.
type fakeConn struct{ net.Conn }

func (fakeConn) Close() error { return nil }

// proberHarness drives the prober state machine directly (probeAll) without
// the ticker loop, using a scripted dialer.
type proberHarness struct {
	prober *prober

	mu          sync.Mutex
	reachable   map[string]bool
	transitions []struct {
		target  probeTarget
		healthy bool
	}
}

func newProberHarness(rise, fall int, targets []probeTarget) *proberHarness {
	h := &proberHarness{reachable: make(map[string]bool)}
	h.prober = newProber(proberConfig{
		Interval: time.Hour,
		Timeout:  time.Millisecond,
		Rise:     rise,
		Fall:     fall,
		Logger:   slog.Default(),
	}, func() []probeTarget { return targets }, func(_ context.Context, target probeTarget, healthy bool) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.transitions = append(h.transitions, struct {
			target  probeTarget
			healthy bool
		}{target, healthy})
	})
	h.prober.dial = func(network, address string, timeout time.Duration) (net.Conn, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.reachable[address] {
			return fakeConn{}, nil
		}
		return nil, errors.New("connection refused")
	}
	return h
}

func (h *proberHarness) setReachable(addr string, up bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.reachable[addr] = up
}

func (h *proberHarness) transitionCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.transitions)
}

func (h *proberHarness) lastTransition() (probeTarget, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	last := h.transitions[len(h.transitions)-1]
	return last.target, last.healthy
}

func testTarget() probeTarget {
	return probeTarget{
		vip:     vipKey{proto: ProtocolTCP, addr: netip.MustParseAddr("10.100.0.10"), port: 443},
		backend: netip.MustParseAddrPort("10.0.1.5:8443"),
	}
}

func TestProberFallThenRise(t *testing.T) {
	target := testTarget()
	h := newProberHarness(2, 3, []probeTarget{target})
	ctx := context.Background()

	// Backend down: no transition until Fall (3) consecutive failures.
	h.prober.probeAll(ctx)
	h.prober.probeAll(ctx)
	if h.transitionCount() != 0 {
		t.Fatalf("transition before Fall reached: %d", h.transitionCount())
	}
	h.prober.probeAll(ctx)
	if h.transitionCount() != 1 {
		t.Fatalf("transitions = %d, want 1 after Fall failures", h.transitionCount())
	}
	if _, healthy := h.lastTransition(); healthy {
		t.Fatal("expected unhealthy transition")
	}

	// Additional failures do not re-fire.
	h.prober.probeAll(ctx)
	if h.transitionCount() != 1 {
		t.Fatalf("repeated failure re-fired transition: %d", h.transitionCount())
	}

	// Recovery: no transition until Rise (2) consecutive successes.
	h.setReachable(target.backend.String(), true)
	h.prober.probeAll(ctx)
	if h.transitionCount() != 1 {
		t.Fatalf("transition before Rise reached: %d", h.transitionCount())
	}
	h.prober.probeAll(ctx)
	if h.transitionCount() != 2 {
		t.Fatalf("transitions = %d, want 2 after Rise successes", h.transitionCount())
	}
	if _, healthy := h.lastTransition(); !healthy {
		t.Fatal("expected healthy transition")
	}
}

func TestProberFlappingResetsCounters(t *testing.T) {
	target := testTarget()
	h := newProberHarness(2, 3, []probeTarget{target})
	ctx := context.Background()

	// Two failures, one success, two failures: counters reset on the
	// success, so no transition fires.
	h.prober.probeAll(ctx)
	h.prober.probeAll(ctx)
	h.setReachable(target.backend.String(), true)
	h.prober.probeAll(ctx)
	h.setReachable(target.backend.String(), false)
	h.prober.probeAll(ctx)
	h.prober.probeAll(ctx)
	if h.transitionCount() != 0 {
		t.Fatalf("flapping fired a transition: %d", h.transitionCount())
	}
	// The third consecutive failure fires.
	h.prober.probeAll(ctx)
	if h.transitionCount() != 1 {
		t.Fatalf("transitions = %d, want 1", h.transitionCount())
	}
}

func TestProberPrunesRemovedTargets(t *testing.T) {
	target := testTarget()
	targets := []probeTarget{target}
	var mu sync.Mutex
	h := &proberHarness{reachable: make(map[string]bool)}
	h.prober = newProber(proberConfig{
		Interval: time.Hour,
		Timeout:  time.Millisecond,
		Rise:     2,
		Fall:     3,
		Logger:   slog.Default(),
	}, func() []probeTarget {
		mu.Lock()
		defer mu.Unlock()
		return targets
	}, func(context.Context, probeTarget, bool) {})
	h.prober.dial = func(string, string, time.Duration) (net.Conn, error) {
		return nil, errors.New("down")
	}

	ctx := context.Background()
	h.prober.probeAll(ctx)
	h.prober.mu.Lock()
	if len(h.prober.state) != 1 {
		t.Fatalf("state entries = %d, want 1", len(h.prober.state))
	}
	h.prober.mu.Unlock()

	mu.Lock()
	targets = nil
	mu.Unlock()
	h.prober.probeAll(ctx)
	h.prober.mu.Lock()
	defer h.prober.mu.Unlock()
	if len(h.prober.state) != 0 {
		t.Fatalf("stale state entries = %d, want 0", len(h.prober.state))
	}
}

func TestProberRunStopsOnCancel(t *testing.T) {
	h := newProberHarness(1, 1, nil)
	h.prober.cfg.Interval = time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		h.prober.run(ctx)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("prober did not stop on context cancellation")
	}
}

func TestProberRunProbesOnTick(t *testing.T) {
	target := testTarget()
	probed := make(chan struct{}, 1)
	p := newProber(proberConfig{
		Interval: time.Millisecond,
		Timeout:  time.Millisecond,
		Rise:     1,
		Fall:     1,
		Logger:   slog.Default(),
	}, func() []probeTarget { return []probeTarget{target} }, func(context.Context, probeTarget, bool) {})
	p.dial = func(string, string, time.Duration) (net.Conn, error) {
		select {
		case probed <- struct{}{}:
		default:
		}
		return fakeConn{}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		p.run(ctx)
		close(done)
	}()

	select {
	case <-probed:
	case <-time.After(5 * time.Second):
		t.Fatal("prober never probed")
	}
	cancel()
	<-done
}

// TestServiceProbeTargetsExcludesUDP verifies the service only schedules
// TCP backends for probing.
func TestServiceProbeTargetsExcludesUDP(t *testing.T) {
	udpVIP := VIP{
		Address:  netip.MustParseAddr("10.100.0.20"),
		Port:     53,
		Protocol: ProtocolUDP,
		Backends: []Backend{{Address: netip.MustParseAddr("10.0.1.9"), Port: 53}},
	}
	deps, _, _, _ := testDeps(testVIP(), udpVIP)
	svc := startService(t, deps)

	targets := svc.probeTargets()
	if len(targets) != 2 {
		t.Fatalf("targets = %d, want 2 (TCP backends only)", len(targets))
	}
	for _, target := range targets {
		if target.vip.proto != ProtocolTCP {
			t.Errorf("UDP backend scheduled for probing: %+v", target)
		}
	}
}

// TestServiceProbeTransitionRebuildsGroup exercises the full path from a
// probe transition callback into the select group rebuild.
func TestServiceProbeTransitionRebuildsGroup(t *testing.T) {
	deps, _, _, groups := testDeps(testVIP())
	svc := startService(t, deps)

	status, err := svc.GetVIP(ProtocolTCP, netip.MustParseAddrPort("10.100.0.10:443"))
	if err != nil {
		t.Fatalf("GetVIP: %v", err)
	}

	target := probeTarget{
		vip:     vipKey{proto: ProtocolTCP, addr: netip.MustParseAddr("10.100.0.10"), port: 443},
		backend: netip.MustParseAddrPort("10.0.1.5:8443"),
	}
	svc.applyProbeResult(context.Background(), target, false)
	if got := groups.bucketCount(status.GroupID); got != 1 {
		t.Errorf("bucket count = %d, want 1 after probe demotion", got)
	}

	// Unknown targets are swallowed (VIP may have been removed between
	// snapshot and transition).
	svc.applyProbeResult(context.Background(), probeTarget{
		vip:     vipKey{proto: ProtocolTCP, addr: netip.MustParseAddr("10.9.9.9"), port: 1},
		backend: netip.MustParseAddrPort("10.0.1.5:8443"),
	}, false)
}
