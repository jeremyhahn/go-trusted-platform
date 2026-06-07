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

package daemon

import (
	tpconfig "github.com/jeremyhahn/go-trusted-platform/pkg/config"
)

// SetSnapshotStore installs the snapshot store used by reload to
// capture a pre-reload snapshot before applying the reload. Safe to
// call after construction; when unset, reload still works but no
// rollback handle is created.
func (s *Service) SetSnapshotStore(store tpconfig.SnapshotStore) {
	s.snapshotStore = store
}

// SnapshotStore returns the configured snapshot store, or nil.
func (s *Service) SnapshotStore() tpconfig.SnapshotStore {
	return s.snapshotStore
}

// ReloadConfigFromDisk re-reads the active Viper configuration file
// and re-runs viper.Unmarshal against the bound *app.App, if any.
// Returns the list of top-level sections present after the reload so
// the daemon can broadcast a CONFIG_CHANGED event with section
// granularity. Delegates the actual file IO to the config package so
// the same logic can be reused from REST without an import cycle
// through pkg/api/daemon.
//
// When a snapshot store is wired, a pre-reload snapshot is captured
// automatically. The snapshot ID is logged but not returned through
// this signature to preserve API compatibility — callers wanting the
// handle should call ReloadConfigWithSnapshot directly.
func (s *Service) ReloadConfigFromDisk() ([]string, error) {
	sections, _, err := s.ReloadConfigWithSnapshot("daemon")
	return sections, err
}

// ReloadConfigWithSnapshot performs ReloadConfigFromDisk plus
// snapshot capture, returning the pre-reload snapshot ID for audit /
// rollback. A nil snapshot store yields an empty snapshot ID.
func (s *Service) ReloadConfigWithSnapshot(actor string) ([]string, string, error) {
	var target interface{}
	if s.config != nil && s.config.App != nil {
		target = s.config.App
	}
	sections, snapID, snapErr, reloadErr := tpconfig.ReloadFromDiskWithSnapshot(s.snapshotStore, target, actor)
	if reloadErr != nil {
		return nil, snapID, ErrConfigReloadFailed{Cause: reloadErr}
	}
	if snapErr != nil && s.config != nil && s.config.Logger != nil {
		// Snapshot failures don't stop the reload; surface them in
		// the log so operators can decide whether to investigate.
		s.config.Logger.Warnf("config: pre-reload snapshot failed: %v", snapErr)
	}
	return sections, snapID, nil
}

// RollbackConfig replays a previously-captured snapshot. Returns the
// new snapshot ID representing the pre-rollback state (so the
// rollback itself is reversible).
func (s *Service) RollbackConfig(snapshotID, actor string) (string, error) {
	if s.snapshotStore == nil {
		return "", ErrSnapshotStoreNotConfigured{}
	}
	var target interface{}
	if s.config != nil && s.config.App != nil {
		target = s.config.App
	}
	return tpconfig.RollbackTo(s.snapshotStore, snapshotID, actor, target)
}

// ErrSnapshotStoreNotConfigured is returned when rollback / snapshot
// CRUD is invoked before the daemon has wired a snapshot store.
type ErrSnapshotStoreNotConfigured struct{}

func (ErrSnapshotStoreNotConfigured) Error() string {
	return "daemon: snapshot store not configured"
}
