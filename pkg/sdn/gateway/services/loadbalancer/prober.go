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
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"
)

// probeTarget identifies one backend of one VIP for health probing.
type probeTarget struct {
	vip     vipKey
	backend netip.AddrPort
}

// probeState tracks the rise/fall counters of one target.
type probeState struct {
	healthy   bool
	successes int
	failures  int
}

// proberConfig carries the prober tuning parameters.
type proberConfig struct {
	// Interval is the probe period.
	Interval time.Duration

	// Timeout is the per-probe dial timeout.
	Timeout time.Duration

	// Rise is the consecutive successes required to mark a target healthy.
	Rise int

	// Fall is the consecutive failures required to mark a target unhealthy.
	Fall int

	// Logger receives probe transition logs.
	Logger *slog.Logger
}

// targetsFunc snapshots the current probe targets.
type targetsFunc func() []probeTarget

// transitionFunc applies a health transition for a target.
type transitionFunc func(ctx context.Context, target probeTarget, healthy bool)

// dialFunc is the connection-probe seam (net.DialTimeout in production).
type dialFunc func(network, address string, timeout time.Duration) (net.Conn, error)

// prober drives per-backend TCP health probing with a rise/fall state
// machine. A backend transitions unhealthy after Fall consecutive failed
// probes and back to healthy after Rise consecutive successes; every
// transition is reported through the transition callback, which rebuilds
// the VIP's select group from the healthy set.
type prober struct {
	cfg        proberConfig
	targets    targetsFunc
	transition transitionFunc
	dial       dialFunc

	mu    sync.Mutex
	state map[probeTarget]*probeState
}

// newProber creates a prober. Rise and Fall must already be defaulted by
// the caller (Config.withDefaults).
func newProber(cfg proberConfig, targets targetsFunc, transition transitionFunc) *prober {
	return &prober{
		cfg:        cfg,
		targets:    targets,
		transition: transition,
		dial:       net.DialTimeout,
		state:      make(map[probeTarget]*probeState),
	}
}

// run drives the probe loop until ctx is cancelled. Each tick probes every
// current TCP target concurrently and applies rise/fall transitions.
func (p *prober) run(ctx context.Context) {
	ticker := time.NewTicker(p.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.probeAll(ctx)
		}
	}
}

// probeAll probes every current target concurrently and applies the
// resulting transitions.
func (p *prober) probeAll(ctx context.Context) {
	targets := p.targets()
	p.prune(targets)
	if len(targets) == 0 {
		return
	}

	type result struct {
		target probeTarget
		up     bool
	}
	results := make([]result, len(targets))

	var wg sync.WaitGroup
	for i, target := range targets {
		wg.Add(1)
		go func(i int, target probeTarget) {
			defer wg.Done()
			results[i] = result{target: target, up: p.probe(target)}
		}(i, target)
	}
	wg.Wait()

	for _, r := range results {
		if transitioned, healthy := p.record(r.target, r.up); transitioned {
			p.cfg.Logger.Info("load balancer probe transition",
				slog.String("vip", r.target.vip.String()),
				slog.String("backend", r.target.backend.String()),
				slog.Bool("healthy", healthy),
			)
			p.transition(ctx, r.target, healthy)
		}
	}
}

// probe dials the target once and reports reachability.
func (p *prober) probe(target probeTarget) bool {
	conn, err := p.dial("tcp", target.backend.String(), p.cfg.Timeout)
	if err != nil {
		return false
	}
	if closeErr := conn.Close(); closeErr != nil {
		p.cfg.Logger.Warn("load balancer probe connection close failed",
			slog.String("backend", target.backend.String()),
			slog.String("error", closeErr.Error()),
		)
	}
	return true
}

// record feeds one probe outcome into the target's rise/fall state machine.
// It returns whether the target transitioned, and the new health value.
func (p *prober) record(target probeTarget, up bool) (bool, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	st, ok := p.state[target]
	if !ok {
		// Targets start healthy (matching the service's initial group
		// programming); the first Fall failures demote them.
		st = &probeState{healthy: true}
		p.state[target] = st
	}

	if up {
		st.failures = 0
		st.successes++
		if !st.healthy && st.successes >= p.cfg.Rise {
			st.healthy = true
			st.successes = 0
			return true, true
		}
		return false, st.healthy
	}

	st.successes = 0
	st.failures++
	if st.healthy && st.failures >= p.cfg.Fall {
		st.healthy = false
		st.failures = 0
		return true, false
	}
	return false, st.healthy
}

// prune drops state for targets that no longer exist (removed VIPs or
// replaced backends) so stale counters never leak into re-added targets.
func (p *prober) prune(current []probeTarget) {
	p.mu.Lock()
	defer p.mu.Unlock()

	keep := make(map[probeTarget]struct{}, len(current))
	for _, t := range current {
		keep[t] = struct{}{}
	}
	for t := range p.state {
		if _, ok := keep[t]; !ok {
			delete(p.state, t)
		}
	}
}
