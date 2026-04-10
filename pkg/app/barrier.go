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

	// Attempt auto-unseal if configured and barrier is sealed
	if mgr.IsSealed() && app.BarrierConfig.AutoUnseal {
		if err := app.autoUnsealBarrier(ctx, mgr); err != nil {
			app.Logger.Warn("barrier: auto-unseal failed, manual unseal required",
				slog.String("error", err.Error()))
		}
	}

	// Log barrier state for operator awareness
	if mgr.IsSealed() {
		app.Logger.Info("barrier: sealed, waiting for unseal command")
	} else {
		app.Logger.Info("barrier: unsealed and ready")
	}

	return nil
}

// autoUnsealBarrier attempts to automatically unseal the barrier based on
// the configured seal strategy. Software strategy cannot auto-unseal
// without user input. TPM2 and PKCS11 strategies can unseal using
// hardware-bound keys.
func (app *App) autoUnsealBarrier(ctx context.Context, mgr *barrier.Manager) error {
	switch app.BarrierConfig.SealStrategy {
	case barrier.SealStrategyTPM2:
		// DEFERRED: Implement TPM2 auto-unseal using NVRAM-sealed key. Blocked by: TPM2 NVRAM sealing API.
		return nil
	case barrier.SealStrategyPKCS11:
		// DEFERRED: Implement PKCS11 auto-unseal using hardware token. Blocked by: PKCS11 provider integration.
		return nil
	case barrier.SealStrategySoftware:
		// Software strategy requires interactive user input
		return nil
	default:
		return nil
	}
}
