// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package proxysvc

import (
	"context"
	"log/slog"
	"sync"

	"github.com/jeremyhahn/go-trusted-platform/pkg/proxy"
)

// HandlerConfig configures a Handler.
type HandlerConfig struct {
	// Engine is the composed proxy engine (required).
	Engine *proxy.Engine

	// Syncer is the optional platformd control-plane sync loop. Nil when
	// sync is disabled; the engine then serves its static configuration.
	Syncer *ConfigSyncer

	// Logger is optional; nil uses slog.Default().
	Logger *slog.Logger
}

// Handler is the gateway ServiceHandler that owns the proxy engine
// lifecycle. Start binds the engine listeners and launches the sync loop;
// Stop cancels the sync loop, waits for it, and gracefully shuts the engine
// down.
type Handler struct {
	engine *proxy.Engine
	syncer *ConfigSyncer
	logger *slog.Logger

	mu     sync.Mutex
	active bool
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewHandler validates the configuration and builds a Handler.
func NewHandler(cfg HandlerConfig) (*Handler, error) {
	if cfg.Engine == nil {
		return nil, &ErrNilEngine{}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Handler{
		engine: cfg.Engine,
		syncer: cfg.Syncer,
		logger: cfg.Logger,
	}, nil
}

// Name implements the gateway ServiceHandler interface.
func (h *Handler) Name() string { return ServiceName }

// Start implements the gateway ServiceHandler interface. It binds the
// engine listeners synchronously and launches the control-plane sync loop
// in the background. The sync loop's lifetime is owned by Stop, not by the
// (request-scoped) Start context.
func (h *Handler) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.active {
		return proxy.ErrEngineStarted
	}
	if err := h.engine.Start(); err != nil {
		return err
	}
	if h.syncer != nil {
		syncCtx, cancel := context.WithCancel(context.Background())
		h.cancel = cancel
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			h.syncer.Run(syncCtx)
		}()
	}
	h.active = true
	h.logger.Info("proxysvc: proxy service started",
		"listeners", len(h.engine.Status().Listeners), "sync", h.syncer != nil)
	return nil
}

// Stop implements the gateway ServiceHandler interface. The context bounds
// the graceful drain of in-flight requests.
func (h *Handler) Stop(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.active {
		return nil
	}
	if h.cancel != nil {
		h.cancel()
		h.cancel = nil
	}
	h.wg.Wait()
	if err := h.engine.Stop(ctx); err != nil {
		return err
	}
	h.active = false
	h.logger.Info("proxysvc: proxy service stopped")
	return nil
}

// IsActive implements the gateway ServiceHandler interface.
func (h *Handler) IsActive() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.active
}

// Health implements the gateway ServiceHandler interface. The proxy stays
// healthy on control-plane sync failures — it keeps serving the last
// applied configuration by design; sync detail is surfaced through
// HealthSnapshot.
func (h *Handler) Health() error {
	if !h.IsActive() {
		return &ErrProxyDisabled{}
	}
	return nil
}

// HealthSnapshot reports the engine status plus the last control-plane sync
// bookkeeping. Sync is nil when the sync loop is disabled.
type HealthSnapshot struct {
	// Active reports whether the handler is started.
	Active bool
	// Engine is the proxy engine status (routes, pools, listeners, reload
	// count).
	Engine *proxy.Status
	// Sync is the last control-plane sync status, nil when sync is
	// disabled.
	Sync *SyncStatus
}

// HealthSnapshot returns the current health snapshot.
func (h *Handler) HealthSnapshot() HealthSnapshot {
	snap := HealthSnapshot{
		Active: h.IsActive(),
		Engine: h.engine.Status(),
	}
	if h.syncer != nil {
		st := h.syncer.Status()
		snap.Sync = &st
	}
	return snap
}
