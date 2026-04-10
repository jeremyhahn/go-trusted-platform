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
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/security/audit"
)

const (
	// EntityTypeAuditEvent is the QuicBaaS entity type for audit events.
	EntityTypeAuditEvent = "AuditEvent"

	// DefaultShardID is the default shard for audit events.
	DefaultShardID uint64 = 0

	// DefaultRequestTimeout is the default timeout for storage operations.
	DefaultRequestTimeout = 30 * time.Second

	// DefaultPageSize is the default number of events per page.
	DefaultPageSize = 100

	// MaxPageSize is the maximum allowed page size.
	MaxPageSize = 1000

	// IndexActor is the secondary index for actor field.
	IndexActor = "actor"

	// IndexAction is the secondary index for action field.
	IndexAction = "action"

	// IndexResource is the secondary index for resource field.
	IndexResource = "resource"

	// IndexResourceType is the secondary index for resource type field.
	IndexResourceType = "resource_type"

	// IndexOutcome is the secondary index for outcome field.
	IndexOutcome = "outcome"

	// IndexSourceIP is the secondary index for source IP field.
	IndexSourceIP = "source_ip"

	// IndexRequestID is the secondary index for request ID field.
	IndexRequestID = "request_id"

	// IndexTimestamp is the secondary index for timestamp field.
	IndexTimestamp = "timestamp"
)

// storedEvent is the internal representation used for QuicBaaS storage.
// It wraps AuditEvent with storage-specific fields.
type storedEvent struct {
	// ID is the storage key (time-based for efficient range queries).
	ID uint64 `json:"id"`

	// Event is the actual audit event.
	Event audit.AuditEvent `json:"event"`

	// TimestampNanos stores the timestamp as nanoseconds for indexing.
	TimestampNanos int64 `json:"timestamp_nanos"`
}

// EntityID returns the storage ID for KeyValueEntity interface compatibility.
func (s *storedEvent) EntityID() uint64 {
	return s.ID
}

// SetEntityID sets the storage ID for KeyValueEntity interface compatibility.
func (s *storedEvent) SetEntityID(id uint64) {
	s.ID = id
}

// newStoredEvent creates a storedEvent from an AuditEvent.
func newStoredEvent(event audit.AuditEvent) *storedEvent {
	id := uint64(event.Timestamp.UnixNano())
	return &storedEvent{
		ID:             id,
		Event:          event,
		TimestampNanos: event.Timestamp.UnixNano(),
	}
}

// queryBuilder helps construct filter predicates for audit queries.
type queryBuilder struct {
	filter audit.AuditFilter
}

// newQueryBuilder creates a new query builder from an audit filter.
func newQueryBuilder(filter audit.AuditFilter) *queryBuilder {
	return &queryBuilder{filter: filter}
}

// matchesEvent returns true if the event matches all filter criteria.
func (qb *queryBuilder) matchesEvent(event *audit.AuditEvent) bool {
	// Time range filter
	if !qb.filter.StartTime.IsZero() && event.Timestamp.Before(qb.filter.StartTime) {
		return false
	}
	if !qb.filter.EndTime.IsZero() && event.Timestamp.After(qb.filter.EndTime) {
		return false
	}

	// Actor filter
	if qb.filter.Actor != "" && event.Actor != qb.filter.Actor {
		return false
	}

	// Action filter
	if qb.filter.Action != "" && event.Action != qb.filter.Action {
		return false
	}

	// Resource filter
	if qb.filter.Resource != "" && event.Resource != qb.filter.Resource {
		return false
	}

	// Resource type filter
	if qb.filter.ResourceType != "" && event.ResourceType != qb.filter.ResourceType {
		return false
	}

	// Outcome filter
	if qb.filter.Outcome != "" && event.Outcome != qb.filter.Outcome {
		return false
	}

	// Source IP filter
	if qb.filter.SourceIP != "" && event.SourceIP != qb.filter.SourceIP {
		return false
	}

	// Request ID filter
	if qb.filter.RequestID != "" && event.RequestID != qb.filter.RequestID {
		return false
	}

	return true
}

// hasTimeFilter returns true if the query has time-based filters.
func (qb *queryBuilder) hasTimeFilter() bool {
	return !qb.filter.StartTime.IsZero() || !qb.filter.EndTime.IsZero()
}

// getStartTimeNanos returns the start time as nanoseconds, or 0 if not set.
func (qb *queryBuilder) getStartTimeNanos() int64 {
	if qb.filter.StartTime.IsZero() {
		return 0
	}
	return qb.filter.StartTime.UnixNano()
}

// getEndTimeNanos returns the end time as nanoseconds, or max int64 if not set.
func (qb *queryBuilder) getEndTimeNanos() int64 {
	if qb.filter.EndTime.IsZero() {
		return 1<<63 - 1 // max int64
	}
	return qb.filter.EndTime.UnixNano()
}

// getEffectiveLimit returns the effective limit for the query.
func (qb *queryBuilder) getEffectiveLimit() int {
	if qb.filter.Limit <= 0 {
		return DefaultPageSize
	}
	if qb.filter.Limit > MaxPageSize {
		return MaxPageSize
	}
	return qb.filter.Limit
}

// getEffectiveOffset returns the effective offset for the query.
func (qb *queryBuilder) getEffectiveOffset() int {
	if qb.filter.Offset < 0 {
		return 0
	}
	return qb.filter.Offset
}
