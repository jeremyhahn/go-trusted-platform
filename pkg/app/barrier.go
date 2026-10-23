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

package app

import (
	"context"
	"log/slog"

	"github.com/jeremyhahn/go-trusted-platform/pkg/barrier"
)

// Barrier returns the barrier manager, or nil if not configured.
func (app *App) Barrier() *barrier.Manager {
	return app.barrier
}

// initBarrier creates and initializes the barrier manager using the
// QuicBaaS SDK client. The barrier is non-blocking: if sealed, the
// platform continues running but services that require unsealed storage
// may be unavailable until the barrier is manually unsealed.
func (app *App) initBarrier(ctx context.Context) error {
	sdk := app.QuicBaaSSDKClient()
	if sdk == nil {
		return ErrBarrierRequiresQuicBaaS{}
	}

	mgr, err := barrier.NewManager(sdk, app.BarrierConfig, app.Logger.Slog())
	if err != nil {
		return ErrBarrierInit{Cause: err}
	}
	app.barrier = mgr

	// Sync status with QuicBaaS. This is non-fatal because the barrier
	// may not have been initialized yet (first-boot scenario).
	if err := mgr.SyncStatus(ctx); err != nil {
		app.Logger.Warn("barrier: failed to sync status, barrier may need initialization",
			slog.String("error", err.Error()))
		return nil
	}

	// Log barrier state for operator awareness
	if mgr.IsSealed() {
		app.Logger.Info("barrier: sealed, waiting for unseal command")
	} else {
		app.Logger.Info("barrier: unsealed and ready")
	}

	return nil
}
