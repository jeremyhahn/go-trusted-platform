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
	"context"
	"encoding/json"
	"sort"
	"sync/atomic"
	"time"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/security/audit"
)

// QuicBaaSPersister implements the audit.EventPersister interface using QuicBaaS.
// It stores audit events with time-based keys for efficient range queries and
// supports filtering by various event attributes.
type QuicBaaSPersister struct {
	sdk            quicbaas.Client
	shardID        uint64
	requestTimeout time.Duration
	started        atomic.Bool
	closed         atomic.Bool
}

// QuicBaaSOption is a functional option for configuring QuicBaaSPersister.
type QuicBaaSOption func(*quicbaasConfig)

type quicbaasConfig struct {
	shardID        uint64
	requestTimeout time.Duration
}

// WithShardID sets the shard ID for audit event storage.
func WithShardID(shardID uint64) QuicBaaSOption {
	return func(c *quicbaasConfig) {
		c.shardID = shardID
	}
}

// WithRequestTimeout sets the timeout for storage operations.
func WithRequestTimeout(timeout time.Duration) QuicBaaSOption {
	return func(c *quicbaasConfig) {
		c.requestTimeout = timeout
	}
}

// NewQuicBaaSPersister creates a new QuicBaaS-backed audit event persister.
func NewQuicBaaSPersister(sdk quicbaas.Client, opts ...QuicBaaSOption) (*QuicBaaSPersister, error) {
	if sdk == nil {
		return nil, ErrNilSDKClient{}
	}

	cfg := &quicbaasConfig{
		shardID:        DefaultShardID,
		requestTimeout: DefaultRequestTimeout,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	p := &QuicBaaSPersister{
		sdk:            sdk,
		shardID:        cfg.shardID,
		requestTimeout: cfg.requestTimeout,
	}

	// Mark as started immediately since SDK client is already connected
	p.started.Store(true)

	return p, nil
}

// Persist stores an audit event in QuicBaaS.
func (p *QuicBaaSPersister) Persist(ctx context.Context, event audit.AuditEvent) error {
	if p.closed.Load() {
		return ErrStorageClosed{}
	}
	if !p.started.Load() {
		return ErrStorageNotStarted{}
	}

	// Wrap the event for storage
	stored := newStoredEvent(event)

	// Serialize to JSON
	data, err := json.Marshal(stored)
	if err != nil {
		return ErrSerializationFailed{EventID: event.ID, Cause: err}
	}

	// Create timeout context
	ctx, cancel := context.WithTimeout(ctx, p.requestTimeout)
	defer cancel()

	// Store in QuicBaaS using KV client
	req := &service.PutRequest{
		EntityType:  EntityTypeAuditEvent,
		ID:          stored.ID,
		Data:        data,
		ShardID:     p.shardID,
		Consistency: service.ConsistencyLevelLinearizable,
	}

	if _, err := p.sdk.KV().Put(ctx, req); err != nil {
		return ErrPutFailed{EventID: event.ID, Cause: err}
	}

	return nil
}

// Query retrieves audit events matching the filter criteria.
func (p *QuicBaaSPersister) Query(ctx context.Context, filter audit.AuditFilter) ([]audit.AuditEvent, error) {
	if p.closed.Load() {
		return nil, ErrStorageClosed{}
	}
	if !p.started.Load() {
		return nil, ErrStorageNotStarted{}
	}

	// Validate filter
	if err := filter.Validate(); err != nil {
		return nil, err
	}

	// Create timeout context
	ctx, cancel := context.WithTimeout(ctx, p.requestTimeout)
	defer cancel()

	// Build query helper
	qb := newQueryBuilder(filter)

	// Fetch events from QuicBaaS
	events, err := p.fetchAndFilterEvents(ctx, qb)
	if err != nil {
		return nil, ErrQueryFailed{Reason: "fetch failed", Cause: err}
	}

	// Sort events by timestamp
	p.sortEvents(events, filter.SortDesc)

	// Apply pagination
	events = p.applyPagination(events, qb.getEffectiveOffset(), qb.getEffectiveLimit())

	return events, nil
}

// Close releases resources held by the persister.
func (p *QuicBaaSPersister) Close() error {
	if p.closed.Load() {
		return nil
	}

	p.started.Store(false)
	p.closed.Store(true)

	// Note: We don't close the SDK client here as it's managed externally
	return nil
}

// fetchAndFilterEvents retrieves events from QuicBaaS and applies filters.
func (p *QuicBaaSPersister) fetchAndFilterEvents(ctx context.Context, qb *queryBuilder) ([]audit.AuditEvent, error) {
	var events []audit.AuditEvent
	pageToken := ""

	// Use a reasonable batch size for fetching
	const fetchSize uint64 = 1000

	for {
		req := &service.ListRequest{
			EntityType: EntityTypeAuditEvent,
			PageSize:   fetchSize,
			PageToken:  pageToken,
			ShardID:    p.shardID,
		}

		resp, err := p.sdk.KV().List(ctx, req)
		if err != nil {
			return nil, err
		}

		for _, entity := range resp.Entities {
			var stored storedEvent
			if err := json.Unmarshal(entity.Data, &stored); err != nil {
				// Skip malformed events but don't fail the entire query
				continue
			}

			// Apply filter criteria
			if qb.matchesEvent(&stored.Event) {
				events = append(events, stored.Event)
			}
		}

		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}

	return events, nil
}

// sortEvents sorts events by timestamp.
func (p *QuicBaaSPersister) sortEvents(events []audit.AuditEvent, descending bool) {
	sort.Slice(events, func(i, j int) bool {
		if descending {
			return events[i].Timestamp.After(events[j].Timestamp)
		}
		return events[i].Timestamp.Before(events[j].Timestamp)
	})
}

// applyPagination applies offset and limit to the event slice.
func (p *QuicBaaSPersister) applyPagination(events []audit.AuditEvent, offset, limit int) []audit.AuditEvent {
	total := len(events)

	if offset >= total {
		return []audit.AuditEvent{}
	}

	end := offset + limit
	if end > total {
		end = total
	}

	return events[offset:end]
}

// IsStarted returns true if the persister is ready to accept operations.
func (p *QuicBaaSPersister) IsStarted() bool {
	return p.started.Load() && !p.closed.Load()
}

// IsClosed returns true if the persister has been closed.
func (p *QuicBaaSPersister) IsClosed() bool {
	return p.closed.Load()
}

// Compile-time interface implementation check.
var _ audit.EventPersister = (*QuicBaaSPersister)(nil)
