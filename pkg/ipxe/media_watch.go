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

package ipxe

import (
	"context"
	"sort"
	"sync/atomic"
	"time"
)

// defaultMediaSampleInterval is how often the media watcher scans /proc.
// The BMC's virtual-media client holds the ISO open for as long as the
// host is reading it — a boot is tens of seconds of I/O at the least — so
// a quarter-second sampler cannot miss a boot; it exists so that a client
// asking once every ten seconds sees history, not a coin flip.
const defaultMediaSampleInterval = 250 * time.Millisecond

// mediaWatcher samples open files under DataDir continuously and keeps a
// cumulative record per file since it started. Readers get an immutable
// snapshot through an atomic pointer; the sampler is the only writer, so
// there is no lock on either side.
type mediaWatcher struct {
	procRoot string
	dataDir  string
	selfPID  int
	interval time.Duration
	now      func() time.Time
	started  time.Time
	state    atomic.Pointer[mediaState]
	// lastErr records the most recent failed sample, for tests and
	// diagnostics; a later successful sample does not clear it.
	lastErr atomic.Pointer[error]
	// lastOK is when the most recent sample succeeded; zero until one
	// has. status() refuses to serve a record older than staleAfter.
	lastOK atomic.Pointer[time.Time]
}

// staleFactor is how many sampling intervals may pass without a
// successful sample before the record is refused as stale.
const staleFactor = 4

// mediaState is one immutable snapshot of the watcher's record.
type mediaState struct {
	sampledAt time.Time
	files     map[string]MediaOpen
}

// newMediaWatcher builds a watcher over dataDir. procRoot and now are
// injectable for tests; empty/nil select /proc and time.Now.
func newMediaWatcher(procRoot, dataDir string, selfPID int, interval time.Duration, now func() time.Time) *mediaWatcher {
	if procRoot == "" {
		procRoot = defaultProcRoot
	}
	if interval <= 0 {
		interval = defaultMediaSampleInterval
	}
	if now == nil {
		now = time.Now
	}
	w := &mediaWatcher{procRoot: procRoot, dataDir: dataDir, selfPID: selfPID, interval: interval, now: now}
	w.started = now()
	w.state.Store(&mediaState{sampledAt: w.started, files: map[string]MediaOpen{}})
	return w
}

// run samples on every tick until ctx is done. The caller takes the
// first sample itself (startMediaWatcher does, before it returns) so the
// record is populated before the route can be served; a sample error
// here is transient and the next tick retries.
func (w *mediaWatcher) run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := w.sample(); err != nil {
				// Recorded in lastErr by sample(); the next tick retries
				// and status() answers 503 meanwhile.
				continue
			}
		}
	}
}

// sample scans /proc once and folds the result into a new snapshot. A
// scan failure (procfs unreadable) leaves the previous snapshot in place,
// records itself as lastErr, and is returned.
func (w *mediaWatcher) sample() error {
	scan, err := scanMediaOpens(w.procRoot, w.dataDir, w.selfPID)
	if err != nil {
		w.lastErr.Store(&err)
		return err
	}
	now := w.now()
	prev := w.state.Load()
	next := &mediaState{sampledAt: now, files: make(map[string]MediaOpen, len(prev.files)+len(scan.files))}

	// Files seen before keep their history; those not open right now
	// show Opens 0 (per file and per opener) but retain everything else.
	for path, rec := range prev.files {
		rec.Opens = 0
		rec.Openers = append([]MediaOpener(nil), rec.Openers...)
		for i := range rec.Openers {
			rec.Openers[i].heldPrev = rec.Openers[i].Opens > 0
			rec.Openers[i].Opens = 0
		}
		next.files[path] = rec
	}
	for path, cur := range scan.files {
		rec, seen := next.files[path]
		if !seen {
			rec = MediaOpen{Path: path, FirstSeen: now}
		}
		rec.Opens = cur.opens
		rec.OpenSamples++
		rec.LastSeen = now
		if cur.maxPos > rec.MaxPos {
			rec.MaxPos = cur.maxPos
		}
		for key, curOpener := range cur.byName {
			rec.Openers = foldOpener(rec.Openers, key, curOpener, now)
		}
		sort.Slice(rec.Openers, func(i, j int) bool {
			if rec.Openers[i].Name != rec.Openers[j].Name {
				return rec.Openers[i].Name < rec.Openers[j].Name
			}
			return rec.Openers[i].Client < rec.Openers[j].Client
		})
		next.files[path] = rec
	}
	w.state.Store(next)
	w.lastOK.Store(&now)
	return nil
}

// healthy reports whether the record is fresh enough to serve: at least
// one successful sample, and the latest no older than staleFactor
// intervals. A watcher whose scans keep failing must not answer with the
// last thing it saw, because a client would take that for evidence.
func (w *mediaWatcher) healthy() error {
	last := w.lastOK.Load()
	if last == nil {
		return ErrMediaWatcherUnhealthy{Reason: "no successful sample yet", Cause: w.lastError()}
	}
	if age := w.now().Sub(*last); age > staleFactor*w.interval {
		return ErrMediaWatcherUnhealthy{Reason: "last successful sample " + age.Round(time.Millisecond).String() + " ago", Cause: w.lastError()}
	}
	return nil
}

// lastError returns the most recent sample error, or nil.
func (w *mediaWatcher) lastError() error {
	if e := w.lastErr.Load(); e != nil {
		return *e
	}
	return nil
}

// foldOpener merges one (process name, client) pair's current
// descriptors into its record in openers (appending a new record on
// first sight) and returns the slice. An open event is a process holding the file that did not at
// the previous sample; a position change is its summed offsets moving.
func foldOpener(openers []MediaOpener, key openerKey, cur *scannedOpener, now time.Time) []MediaOpener {
	idx := -1
	for i := range openers {
		if openers[i].Name == key.name && openers[i].Client == key.client {
			idx = i
			break
		}
	}
	if idx < 0 {
		openers = append(openers, MediaOpener{Name: key.name, Client: key.client, FirstSeen: now})
		idx = len(openers) - 1
	}
	o := &openers[idx]
	newlyOpen := !o.heldPrev
	moved := o.heldPrev && cur.posSum != o.posSum
	o.Opens = cur.opens
	o.OpenSamples++
	o.LastSeen = now
	if cur.maxPos > o.MaxPos {
		o.MaxPos = cur.maxPos
	}
	if newlyOpen {
		o.OpenEvents++
		o.LastActivity = now
	}
	if moved {
		o.PosChanges++
		o.LastActivity = now
	}
	o.posSum = cur.posSum
	o.heldPrev = true
	return openers
}

// status renders the current snapshot for /media/status.
func (w *mediaWatcher) status() *MediaStatus {
	snap := w.state.Load()
	out := &MediaStatus{
		DataDir:   w.dataDir,
		Since:     w.started,
		SampledAt: snap.sampledAt,
		Interval:  w.interval,
		Files:     make([]MediaOpen, 0, len(snap.files)),
	}
	for _, rec := range snap.files {
		out.Files = append(out.Files, rec)
	}
	sort.Slice(out.Files, func(i, j int) bool { return out.Files[i].Path < out.Files[j].Path })
	return out
}
