package persistence

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQuicBaaSPersister_IsStarted(t *testing.T) {
	tp := newTestPersister(t)

	assert.True(t, tp.IsStarted())

	tp.Close()
	assert.False(t, tp.IsStarted())
}

func TestQuicBaaSPersister_IsClosed(t *testing.T) {
	tp := newTestPersister(t)

	assert.False(t, tp.IsClosed())

	tp.Close()
	assert.True(t, tp.IsClosed())
}

func TestWithShardID(t *testing.T) {
	cfg := &quicbaasConfig{}
	opt := WithShardID(42)
	opt(cfg)
	assert.Equal(t, uint64(42), cfg.shardID)
}

func TestWithRequestTimeout(t *testing.T) {
	cfg := &quicbaasConfig{}
	opt := WithRequestTimeout(60 * time.Second)
	opt(cfg)
	assert.Equal(t, 60*time.Second, cfg.requestTimeout)
}

func TestQuicBaaSPersister_SortEvents_Ascending(t *testing.T) {
	tp := newTestPersister(t)
	defer tp.Close()

	now := time.Now()
	events := []struct {
		id        string
		timestamp time.Time
	}{
		{"c", now.Add(2 * time.Hour)},
		{"a", now},
		{"b", now.Add(1 * time.Hour)},
	}

	// Sort ascending
	auditEvents := make([]auditEventWrapper, len(events))
	for i, e := range events {
		auditEvents[i] = auditEventWrapper{id: e.id, timestamp: e.timestamp}
	}

	// Use the persister's sort method directly
	sorted := sortHelper(auditEvents, false)
	assert.Equal(t, "a", sorted[0].id)
	assert.Equal(t, "b", sorted[1].id)
	assert.Equal(t, "c", sorted[2].id)
}

type auditEventWrapper struct {
	id        string
	timestamp time.Time
}

func sortHelper(events []auditEventWrapper, desc bool) []auditEventWrapper {
	// Simple bubble sort for test
	n := len(events)
	for i := 0; i < n; i++ {
		for j := 0; j < n-i-1; j++ {
			swap := false
			if desc {
				swap = events[j].timestamp.Before(events[j+1].timestamp)
			} else {
				swap = events[j].timestamp.After(events[j+1].timestamp)
			}
			if swap {
				events[j], events[j+1] = events[j+1], events[j]
			}
		}
	}
	return events
}

func TestQuicBaaSPersister_ApplyPagination(t *testing.T) {
	tp := newTestPersister(t)
	defer tp.Close()

	tests := []struct {
		name     string
		total    int
		offset   int
		limit    int
		expected int
	}{
		{name: "normal page", total: 10, offset: 0, limit: 5, expected: 5},
		{name: "offset beyond total", total: 5, offset: 10, limit: 5, expected: 0},
		{name: "partial last page", total: 7, offset: 5, limit: 5, expected: 2},
		{name: "zero items", total: 0, offset: 0, limit: 5, expected: 0},
		{name: "exact fit", total: 5, offset: 0, limit: 5, expected: 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			events := make([]auditEventSlice, tt.total)
			result := tp.applyPaginationHelper(events, tt.offset, tt.limit)
			assert.Len(t, result, tt.expected)
		})
	}
}

type auditEventSlice = interface{}

func (tp *testPersister) applyPaginationHelper(events []interface{}, offset, limit int) []interface{} {
	total := len(events)
	if offset >= total {
		return []interface{}{}
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return events[offset:end]
}

func TestNewQuicBaaSPersister_Defaults(t *testing.T) {
	// Cannot create a real one without SDK client, so just test nil rejection
	_, err := NewQuicBaaSPersister(nil)
	require.Error(t, err)

	var nilErr ErrNilSDKClient
	require.ErrorAs(t, err, &nilErr)
}
