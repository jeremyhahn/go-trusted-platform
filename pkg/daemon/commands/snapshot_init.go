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

package commands

import (
	"path/filepath"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	tpconfig "github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// initSnapshotStore returns the daemon's snapshot store backed by a
// directory under <PlatformDir>/config-snapshots. Failures are
// non-fatal: when the store can't be created, the daemon continues
// without a snapshot history and rollback / capture REST endpoints
// surface a 503 via the loud-failure pattern.
func initSnapshotStore(logger *logging.Logger, a *app.App) tpconfig.SnapshotStore {
	if a == nil {
		return nil
	}
	root := filepath.Join(a.PlatformDir, "config-snapshots")
	store, err := tpconfig.NewFileSnapshotStore(root)
	if err != nil {
		logger.Warnf("config snapshot store unavailable: %v", err)
		return nil
	}
	logger.Info("config snapshot store wired", "root", root)
	return store
}
