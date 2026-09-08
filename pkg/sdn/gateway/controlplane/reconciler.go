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

package controlplane

import (
	"context"
	"sync"
	"time"

	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
)

// DesiredConfigFetcher pulls the control plane's intended configuration.
// *Reporter satisfies it.
type DesiredConfigFetcher interface {
	FetchDesiredConfig(ctx context.Context) (*gwstate.DesiredConfig, error)
}

// DesiredConfigApplier brings the gateway to a desired configuration.
// *gateway.Gateway satisfies it.
type DesiredConfigApplier interface {
	Apply(ctx context.Context, desired *gwstate.DesiredConfig) error
}

// ReconcilerConfig configures the desired-config reconcile loop.
type ReconcilerConfig struct {
	// Fetcher pulls the desired document; required.
	Fetcher DesiredConfigFetcher
	// Applier applies it; required.
	Applier DesiredConfigApplier
	// Interval is the poll period; must be positive.
	Interval time.Duration
	// Logger is optional; nil disables logging.
	Logger Logger
}

// Reconciler is the pull half of the platformd↔gatewayd control loop
// (#555): on every tick it fetches the desired configuration and applies
// the difference. The applier owns idempotence — an unchanged document is
// its no-op, not the reconciler's — so a gateway that restarts converges
// on its first tick without the control plane doing anything.
type Reconciler struct {
	cfg     ReconcilerConfig
	mu      sync.Mutex
	running bool
	// lastErr is the most recent pass's failure, nil after a clean pass.
	// The loop keeps it rather than dropping the error: the next tick
	// retries, and LastError lets a caller see why the last one failed.
	lastErr error
}

// NewReconciler validates the configuration and builds the loop.
func NewReconciler(cfg ReconcilerConfig) (*Reconciler, error) {
	if cfg.Fetcher == nil {
		return nil, ErrMissingField{Field: "fetcher"}
	}
	if cfg.Applier == nil {
		return nil, ErrMissingField{Field: "applier"}
	}
	if cfg.Interval <= 0 {
		return nil, &ErrConfigInvalid{Field: "reconcile-interval", Reason: "must be positive"}
	}
	return &Reconciler{cfg: cfg}, nil
}

// Start runs the loop until ctx is cancelled: one pass immediately so a
// booting gateway converges before its first tick, then one per Interval.
// A second concurrent Start returns ErrAlreadyRunning.
func (r *Reconciler) Start(ctx context.Context) error {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return ErrAlreadyRunning{}
	}
	r.running = true
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.running = false
		r.mu.Unlock()
	}()

	r.tick(ctx)
	ticker := time.NewTicker(r.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			r.tick(ctx)
		}
	}
}

// tick runs one pass and records its outcome for LastError.
func (r *Reconciler) tick(ctx context.Context) {
	err := r.ReconcileOnce(ctx)
	r.mu.Lock()
	r.lastErr = err
	r.mu.Unlock()
}

// LastError reports the outcome of the most recent pass the loop ran: nil
// after a clean pass, the typed ErrReconcileFailed otherwise.
func (r *Reconciler) LastError() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastErr
}

// ReconcileOnce performs one fetch-and-apply pass and reports its
// outcome. Public so tests and operators can drive it without the ticker.
// A fetch or apply failure is logged and returned; the next tick retries,
// and the applier's recorded state carries the error to the snapshot.
func (r *Reconciler) ReconcileOnce(ctx context.Context) error {
	desired, err := r.cfg.Fetcher.FetchDesiredConfig(ctx)
	if err != nil {
		r.logWarn("desired config fetch failed", "error", err.Error())
		return &ErrReconcileFailed{Stage: "fetch", Cause: err}
	}
	if err := r.cfg.Applier.Apply(ctx, desired); err != nil {
		r.logWarn("desired config apply failed", "version", desired.EffectiveVersion(), "error", err.Error())
		return &ErrReconcileFailed{Stage: "apply", Cause: err}
	}
	r.logInfo("desired config reconciled", "version", desired.EffectiveVersion())
	return nil
}

func (r *Reconciler) logInfo(msg string, args ...any) {
	if r.cfg.Logger != nil {
		r.cfg.Logger.Info(msg, args...)
	}
}

func (r *Reconciler) logWarn(msg string, args ...any) {
	if r.cfg.Logger != nil {
		r.cfg.Logger.Warn(msg, args...)
	}
}

// ErrReconcileFailed reports which stage of a reconcile pass failed.
type ErrReconcileFailed struct {
	Stage string
	Cause error
}

// Error implements the error interface.
func (e *ErrReconcileFailed) Error() string {
	return "desired config reconcile: " + e.Stage + ": " + e.Cause.Error()
}

// Unwrap returns the stage's failure.
func (e *ErrReconcileFailed) Unwrap() error { return e.Cause }
