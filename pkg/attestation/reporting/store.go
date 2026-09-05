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

package reporting

import "log/slog"

// Store persists the most recent report per device so a control plane that
// restarts still knows the last verdict and its age, rather than presenting
// every device as never collected until the first cycle completes.
//
// It is deliberately a write-through behind the Cache: the Cache remains the
// only thing a handler reads, and the Store has no way to reach a device.
type Store interface {
	// PutReport records r as the device's current report, replacing any
	// previous one.
	PutReport(r *Report) error
	// Reports returns every persisted report.
	Reports() ([]*Report, error)
}

// Persist attaches a Store to the cache. Existing persisted reports are
// loaded first, so a cache warmed from disk serves the last known verdict
// with its ORIGINAL CollectedAt — an old report is presented as old, never
// as fresh.
func (c *Cache) Persist(store Store, logger *slog.Logger) error {
	if store == nil {
		return ErrNoStore{}
	}
	if logger == nil {
		logger = slog.Default()
	}
	reports, err := store.Reports()
	if err != nil {
		return ErrStoreLoad{Cause: err}
	}
	c.mu.Lock()
	for _, r := range reports {
		if r == nil || r.DeviceID == "" {
			continue
		}
		if existing, ok := c.reports[r.DeviceID]; ok && !existing.CollectedAt.Before(r.CollectedAt) {
			continue
		}
		c.reports[r.DeviceID] = r
	}
	c.store = store
	c.logger = logger
	c.mu.Unlock()
	return nil
}

// persist writes through to the store. Called with the cache lock held so a
// concurrent Store cannot interleave a newer in-memory report with an older
// on-disk one. A persistence failure is logged and does not undo the
// in-memory update: the live verdict is correct, only its durability is in
// question, and refusing to serve a correct verdict because the disk is
// full would be the wrong trade.
func (c *Cache) persist(r *Report) {
	if c.store == nil {
		return
	}
	if err := c.store.PutReport(r); err != nil {
		logger := c.logger
		if logger == nil {
			logger = slog.Default()
		}
		logger.Error("attestation reporting: report could not be persisted; the in-memory verdict is current but will not survive a restart",
			"device_id", r.DeviceID, "error", err)
	}
}

// ErrNoStore reports Persist called without a store.
type ErrNoStore struct{}

func (ErrNoStore) Error() string {
	return "attestation reporting: a report store is required"
}

// ErrStoreLoad reports that persisted reports could not be read.
type ErrStoreLoad struct {
	Cause error
}

func (e ErrStoreLoad) Error() string {
	return "attestation reporting: could not load persisted reports: " + e.Cause.Error()
}

func (e ErrStoreLoad) Unwrap() error { return e.Cause }
