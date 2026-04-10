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

package persistence

import (
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/security/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStoredEvent_EntityID(t *testing.T) {
	event := audit.AuditEvent{
		ID:        "test-event",
		Timestamp: time.Now(),
		Actor:     "user@example.com",
		Action:    "test",
		Outcome:   audit.OutcomeSuccess,
	}

	stored := newStoredEvent(event)

	assert.Equal(t, uint64(event.Timestamp.UnixNano()), stored.EntityID())
	assert.Equal(t, event.Timestamp.UnixNano(), stored.TimestampNanos)
}

func TestStoredEvent_SetEntityID(t *testing.T) {
	stored := &storedEvent{}
	stored.SetEntityID(12345)

	assert.Equal(t, uint64(12345), stored.EntityID())
}

func TestNewStoredEvent(t *testing.T) {
	now := time.Now()
	event := audit.AuditEvent{
		ID:           "evt-001",
		Timestamp:    now,
		Actor:        "admin@example.com",
		Action:       "delete",
		Resource:     "user:123",
		ResourceType: "user",
		Outcome:      audit.OutcomeSuccess,
		SourceIP:     "10.0.0.1",
		RequestID:    "req-abc",
	}

	stored := newStoredEvent(event)

	assert.Equal(t, uint64(now.UnixNano()), stored.ID)
	assert.Equal(t, now.UnixNano(), stored.TimestampNanos)
	assert.Equal(t, event.ID, stored.Event.ID)
	assert.Equal(t, event.Actor, stored.Event.Actor)
	assert.Equal(t, event.Action, stored.Event.Action)
}

func TestQueryBuilder_MatchesEvent_NoFilters(t *testing.T) {
	filter := audit.AuditFilter{}
	qb := newQueryBuilder(filter)

	event := &audit.AuditEvent{
		ID:        "evt-001",
		Timestamp: time.Now(),
		Actor:     "user@example.com",
		Action:    "login",
		Outcome:   audit.OutcomeSuccess,
	}

	assert.True(t, qb.matchesEvent(event))
}

func TestQueryBuilder_MatchesEvent_TimeRange(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		startTime time.Time
		endTime   time.Time
		eventTime time.Time
		expected  bool
	}{
		{
			name:      "event within range",
			startTime: now.Add(-1 * time.Hour),
			endTime:   now.Add(1 * time.Hour),
			eventTime: now,
			expected:  true,
		},
		{
			name:      "event before start",
			startTime: now,
			endTime:   now.Add(1 * time.Hour),
			eventTime: now.Add(-1 * time.Hour),
			expected:  false,
		},
		{
			name:      "event after end",
			startTime: now.Add(-1 * time.Hour),
			endTime:   now,
			eventTime: now.Add(1 * time.Hour),
			expected:  false,
		},
		{
			name:      "no start time filter",
			startTime: time.Time{},
			endTime:   now.Add(1 * time.Hour),
			eventTime: now.Add(-10 * time.Hour),
			expected:  true,
		},
		{
			name:      "no end time filter",
			startTime: now.Add(-1 * time.Hour),
			endTime:   time.Time{},
			eventTime: now.Add(10 * time.Hour),
			expected:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filter := audit.AuditFilter{
				StartTime: tc.startTime,
				EndTime:   tc.endTime,
			}
			qb := newQueryBuilder(filter)

			event := &audit.AuditEvent{
				ID:        "evt-001",
				Timestamp: tc.eventTime,
				Actor:     "user@example.com",
				Action:    "login",
				Outcome:   audit.OutcomeSuccess,
			}

			assert.Equal(t, tc.expected, qb.matchesEvent(event))
		})
	}
}

func TestQueryBuilder_MatchesEvent_Actor(t *testing.T) {
	filter := audit.AuditFilter{Actor: "admin@example.com"}
	qb := newQueryBuilder(filter)

	event1 := &audit.AuditEvent{
		ID:        "evt-001",
		Timestamp: time.Now(),
		Actor:     "admin@example.com",
		Action:    "login",
		Outcome:   audit.OutcomeSuccess,
	}
	assert.True(t, qb.matchesEvent(event1))

	event2 := &audit.AuditEvent{
		ID:        "evt-002",
		Timestamp: time.Now(),
		Actor:     "user@example.com",
		Action:    "login",
		Outcome:   audit.OutcomeSuccess,
	}
	assert.False(t, qb.matchesEvent(event2))
}

func TestQueryBuilder_MatchesEvent_Action(t *testing.T) {
	filter := audit.AuditFilter{Action: "delete"}
	qb := newQueryBuilder(filter)

	event1 := &audit.AuditEvent{
		ID:        "evt-001",
		Timestamp: time.Now(),
		Actor:     "user@example.com",
		Action:    "delete",
		Outcome:   audit.OutcomeSuccess,
	}
	assert.True(t, qb.matchesEvent(event1))

	event2 := &audit.AuditEvent{
		ID:        "evt-002",
		Timestamp: time.Now(),
		Actor:     "user@example.com",
		Action:    "create",
		Outcome:   audit.OutcomeSuccess,
	}
	assert.False(t, qb.matchesEvent(event2))
}

func TestQueryBuilder_MatchesEvent_Resource(t *testing.T) {
	filter := audit.AuditFilter{Resource: "cert:abc123"}
	qb := newQueryBuilder(filter)

	event1 := &audit.AuditEvent{
		ID:        "evt-001",
		Timestamp: time.Now(),
		Actor:     "user@example.com",
		Action:    "revoke",
		Resource:  "cert:abc123",
		Outcome:   audit.OutcomeSuccess,
	}
	assert.True(t, qb.matchesEvent(event1))

	event2 := &audit.AuditEvent{
		ID:        "evt-002",
		Timestamp: time.Now(),
		Actor:     "user@example.com",
		Action:    "revoke",
		Resource:  "cert:xyz789",
		Outcome:   audit.OutcomeSuccess,
	}
	assert.False(t, qb.matchesEvent(event2))
}

func TestQueryBuilder_MatchesEvent_ResourceType(t *testing.T) {
	filter := audit.AuditFilter{ResourceType: "certificate"}
	qb := newQueryBuilder(filter)

	event1 := &audit.AuditEvent{
		ID:           "evt-001",
		Timestamp:    time.Now(),
		Actor:        "user@example.com",
		Action:       "create",
		ResourceType: "certificate",
		Outcome:      audit.OutcomeSuccess,
	}
	assert.True(t, qb.matchesEvent(event1))

	event2 := &audit.AuditEvent{
		ID:           "evt-002",
		Timestamp:    time.Now(),
		Actor:        "user@example.com",
		Action:       "create",
		ResourceType: "key",
		Outcome:      audit.OutcomeSuccess,
	}
	assert.False(t, qb.matchesEvent(event2))
}

func TestQueryBuilder_MatchesEvent_Outcome(t *testing.T) {
	filter := audit.AuditFilter{Outcome: audit.OutcomeFailure}
	qb := newQueryBuilder(filter)

	event1 := &audit.AuditEvent{
		ID:        "evt-001",
		Timestamp: time.Now(),
		Actor:     "user@example.com",
		Action:    "login",
		Outcome:   audit.OutcomeFailure,
	}
	assert.True(t, qb.matchesEvent(event1))

	event2 := &audit.AuditEvent{
		ID:        "evt-002",
		Timestamp: time.Now(),
		Actor:     "user@example.com",
		Action:    "login",
		Outcome:   audit.OutcomeSuccess,
	}
	assert.False(t, qb.matchesEvent(event2))
}

func TestQueryBuilder_MatchesEvent_SourceIP(t *testing.T) {
	filter := audit.AuditFilter{SourceIP: "192.168.1.100"}
	qb := newQueryBuilder(filter)

	event1 := &audit.AuditEvent{
		ID:        "evt-001",
		Timestamp: time.Now(),
		Actor:     "user@example.com",
		Action:    "login",
		Outcome:   audit.OutcomeSuccess,
		SourceIP:  "192.168.1.100",
	}
	assert.True(t, qb.matchesEvent(event1))

	event2 := &audit.AuditEvent{
		ID:        "evt-002",
		Timestamp: time.Now(),
		Actor:     "user@example.com",
		Action:    "login",
		Outcome:   audit.OutcomeSuccess,
		SourceIP:  "10.0.0.1",
	}
	assert.False(t, qb.matchesEvent(event2))
}

func TestQueryBuilder_MatchesEvent_RequestID(t *testing.T) {
	filter := audit.AuditFilter{RequestID: "req-12345"}
	qb := newQueryBuilder(filter)

	event1 := &audit.AuditEvent{
		ID:        "evt-001",
		Timestamp: time.Now(),
		Actor:     "user@example.com",
		Action:    "action",
		Outcome:   audit.OutcomeSuccess,
		RequestID: "req-12345",
	}
	assert.True(t, qb.matchesEvent(event1))

	event2 := &audit.AuditEvent{
		ID:        "evt-002",
		Timestamp: time.Now(),
		Actor:     "user@example.com",
		Action:    "action",
		Outcome:   audit.OutcomeSuccess,
		RequestID: "req-67890",
	}
	assert.False(t, qb.matchesEvent(event2))
}

func TestQueryBuilder_MatchesEvent_MultipleFilters(t *testing.T) {
	filter := audit.AuditFilter{
		Actor:   "admin@example.com",
		Action:  "delete",
		Outcome: audit.OutcomeSuccess,
	}
	qb := newQueryBuilder(filter)

	// Event matching all criteria
	event1 := &audit.AuditEvent{
		ID:        "evt-001",
		Timestamp: time.Now(),
		Actor:     "admin@example.com",
		Action:    "delete",
		Outcome:   audit.OutcomeSuccess,
	}
	assert.True(t, qb.matchesEvent(event1))

	// Event with wrong actor
	event2 := &audit.AuditEvent{
		ID:        "evt-002",
		Timestamp: time.Now(),
		Actor:     "user@example.com",
		Action:    "delete",
		Outcome:   audit.OutcomeSuccess,
	}
	assert.False(t, qb.matchesEvent(event2))

	// Event with wrong action
	event3 := &audit.AuditEvent{
		ID:        "evt-003",
		Timestamp: time.Now(),
		Actor:     "admin@example.com",
		Action:    "create",
		Outcome:   audit.OutcomeSuccess,
	}
	assert.False(t, qb.matchesEvent(event3))

	// Event with wrong outcome
	event4 := &audit.AuditEvent{
		ID:        "evt-004",
		Timestamp: time.Now(),
		Actor:     "admin@example.com",
		Action:    "delete",
		Outcome:   audit.OutcomeFailure,
	}
	assert.False(t, qb.matchesEvent(event4))
}

func TestQueryBuilder_HasTimeFilter(t *testing.T) {
	tests := []struct {
		name      string
		startTime time.Time
		endTime   time.Time
		expected  bool
	}{
		{
			name:      "no time filter",
			startTime: time.Time{},
			endTime:   time.Time{},
			expected:  false,
		},
		{
			name:      "start time only",
			startTime: time.Now(),
			endTime:   time.Time{},
			expected:  true,
		},
		{
			name:      "end time only",
			startTime: time.Time{},
			endTime:   time.Now(),
			expected:  true,
		},
		{
			name:      "both times",
			startTime: time.Now().Add(-1 * time.Hour),
			endTime:   time.Now(),
			expected:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filter := audit.AuditFilter{
				StartTime: tc.startTime,
				EndTime:   tc.endTime,
			}
			qb := newQueryBuilder(filter)
			assert.Equal(t, tc.expected, qb.hasTimeFilter())
		})
	}
}

func TestQueryBuilder_GetStartTimeNanos(t *testing.T) {
	now := time.Now()

	// No start time
	filter1 := audit.AuditFilter{}
	qb1 := newQueryBuilder(filter1)
	assert.Equal(t, int64(0), qb1.getStartTimeNanos())

	// With start time
	filter2 := audit.AuditFilter{StartTime: now}
	qb2 := newQueryBuilder(filter2)
	assert.Equal(t, now.UnixNano(), qb2.getStartTimeNanos())
}

func TestQueryBuilder_GetEndTimeNanos(t *testing.T) {
	now := time.Now()

	// No end time - should return max int64
	filter1 := audit.AuditFilter{}
	qb1 := newQueryBuilder(filter1)
	assert.Equal(t, int64(1<<63-1), qb1.getEndTimeNanos())

	// With end time
	filter2 := audit.AuditFilter{EndTime: now}
	qb2 := newQueryBuilder(filter2)
	assert.Equal(t, now.UnixNano(), qb2.getEndTimeNanos())
}

func TestQueryBuilder_GetEffectiveLimit(t *testing.T) {
	tests := []struct {
		name     string
		limit    int
		expected int
	}{
		{
			name:     "zero limit uses default",
			limit:    0,
			expected: DefaultPageSize,
		},
		{
			name:     "negative limit uses default",
			limit:    -1,
			expected: DefaultPageSize,
		},
		{
			name:     "valid limit",
			limit:    50,
			expected: 50,
		},
		{
			name:     "exceeds max uses max",
			limit:    2000,
			expected: MaxPageSize,
		},
		{
			name:     "exactly max",
			limit:    MaxPageSize,
			expected: MaxPageSize,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filter := audit.AuditFilter{Limit: tc.limit}
			qb := newQueryBuilder(filter)
			assert.Equal(t, tc.expected, qb.getEffectiveLimit())
		})
	}
}

func TestQueryBuilder_GetEffectiveOffset(t *testing.T) {
	tests := []struct {
		name     string
		offset   int
		expected int
	}{
		{
			name:     "zero offset",
			offset:   0,
			expected: 0,
		},
		{
			name:     "negative offset uses zero",
			offset:   -1,
			expected: 0,
		},
		{
			name:     "positive offset",
			offset:   50,
			expected: 50,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filter := audit.AuditFilter{Offset: tc.offset}
			qb := newQueryBuilder(filter)
			assert.Equal(t, tc.expected, qb.getEffectiveOffset())
		})
	}
}

func TestConstants(t *testing.T) {
	require.Equal(t, "AuditEvent", EntityTypeAuditEvent)
	require.Equal(t, uint64(0), DefaultShardID)
	require.Equal(t, 30*time.Second, DefaultRequestTimeout)
	require.Equal(t, 100, DefaultPageSize)
	require.Equal(t, 1000, MaxPageSize)

	// Index constants
	require.Equal(t, "actor", IndexActor)
	require.Equal(t, "action", IndexAction)
	require.Equal(t, "resource", IndexResource)
	require.Equal(t, "resource_type", IndexResourceType)
	require.Equal(t, "outcome", IndexOutcome)
	require.Equal(t, "source_ip", IndexSourceIP)
	require.Equal(t, "request_id", IndexRequestID)
	require.Equal(t, "timestamp", IndexTimestamp)
}
