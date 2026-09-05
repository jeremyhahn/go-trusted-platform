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

import (
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type memStore struct {
	reports map[string]*Report
	putErr  error
	listErr error
	puts    int
}

func newMemStore() *memStore { return &memStore{reports: make(map[string]*Report)} }

func (s *memStore) PutReport(r *Report) error {
	s.puts++
	if s.putErr != nil {
		return s.putErr
	}
	s.reports[r.DeviceID] = r
	return nil
}

func (s *memStore) Reports() ([]*Report, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	out := make([]*Report, 0, len(s.reports))
	for _, r := range s.reports {
		out = append(out, r)
	}
	return out, nil
}

func TestCachePersist_WarmsFromStoreAndWritesThrough(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	clk := newFakeClock(now)
	store := newMemStore()
	old := &Report{DeviceID: "1", Verified: true, CollectedAt: now.Add(-3 * time.Hour)}
	store.reports["1"] = old
	store.reports[""] = &Report{}
	store.reports["nil"] = nil

	c := newCacheWithClock(time.Hour, clk)
	require.NoError(t, c.Persist(store, nil))

	got, ok := c.Report("1")
	require.True(t, ok)
	assert.Equal(t, old.CollectedAt, got.CollectedAt, "a warmed report keeps its original age")
	assert.False(t, c.Fresh("1"), "three-hour-old evidence is presented as stale, not fresh")
	assert.Equal(t, 1, c.Len())

	fresh := &Report{DeviceID: "2", Verified: false, CollectedAt: now}
	c.Store(fresh)
	assert.Equal(t, 1, store.puts)
	assert.Same(t, fresh, store.reports["2"])
}

func TestCachePersist_DoesNotDowngradeANewerInMemoryReport(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	c := newCacheWithClock(time.Hour, newFakeClock(now))
	newer := &Report{DeviceID: "1", CollectedAt: now}
	c.Store(newer)
	store := newMemStore()
	store.reports["1"] = &Report{DeviceID: "1", CollectedAt: now.Add(-time.Hour)}
	require.NoError(t, c.Persist(store, nil))
	got, _ := c.Report("1")
	assert.Same(t, newer, got)
}

func TestCachePersist_FailsClosedOnNilStoreAndLoadError(t *testing.T) {
	c := NewCache(0)
	err := c.Persist(nil, nil)
	var noStore ErrNoStore
	require.ErrorAs(t, err, &noStore)

	store := newMemStore()
	store.listErr = errors.New("corrupt")
	err = c.Persist(store, nil)
	var load ErrStoreLoad
	require.ErrorAs(t, err, &load)
	assert.ErrorIs(t, err, store.listErr)
	assert.Contains(t, err.Error(), "corrupt")
}

func TestCacheStore_PersistFailureKeepsTheLiveVerdict(t *testing.T) {
	c := NewCache(0)
	store := newMemStore()
	store.putErr = errors.New("disk full")
	require.NoError(t, c.Persist(store, slog.New(slog.NewTextHandler(io.Discard, nil))))
	r := &Report{DeviceID: "9", Verified: true, CollectedAt: time.Now()}
	c.Store(r)
	got, ok := c.Report("9")
	require.True(t, ok)
	assert.Same(t, r, got)
	assert.Equal(t, 1, store.puts)
}

func TestCacheStore_WithoutStoreDoesNotPersist(t *testing.T) {
	c := NewCache(0)
	c.Store(&Report{DeviceID: "1", CollectedAt: time.Now()})
	assert.Equal(t, 1, c.Len())
}
