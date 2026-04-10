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

// Package persistence provides implementations of the audit.EventPersister
// interface for storing and querying audit events.
//
// The primary implementation is QuicBaaSPersister which stores audit events
// in QuicBaaS using time-based keys for efficient range queries. Events are
// stored as JSON documents and support filtering by various attributes
// including actor, action, resource, outcome, time range, and more.
//
// # Usage
//
// Create a new persister with a QuicBaaS SDK client:
//
//	sdk, err := quicbaas.NewClient(addr, quicbaas.WithEmbedded(service))
//	if err != nil {
//		return err
//	}
//
//	persister, err := persistence.NewQuicBaaSPersister(sdk,
//		persistence.WithShardID(1),
//		persistence.WithRequestTimeout(60*time.Second),
//	)
//	if err != nil {
//		return err
//	}
//	defer persister.Close()
//
// Store an audit event:
//
//	event := audit.AuditEvent{
//		ID:        uuid.New().String(),
//		Timestamp: time.Now(),
//		Actor:     "user@example.com",
//		Action:    "login",
//		Outcome:   audit.OutcomeSuccess,
//	}
//
//	if err := persister.Persist(ctx, event); err != nil {
//		return err
//	}
//
// Query audit events:
//
//	filter := audit.AuditFilter{
//		Actor:     "user@example.com",
//		StartTime: time.Now().Add(-24 * time.Hour),
//		EndTime:   time.Now(),
//		Limit:     100,
//		SortDesc:  true,
//	}
//
//	events, err := persister.Query(ctx, filter)
//	if err != nil {
//		return err
//	}
//
// # Storage Model
//
// Audit events are stored with time-based keys (Unix nanoseconds) which
// enables efficient chronological ordering and range queries. The events
// are serialized as JSON documents containing both the original AuditEvent
// and storage metadata.
//
// # Secondary Indexes
//
// The following secondary indexes are defined for query optimization:
//   - actor: Filter by the user or service performing the action
//   - action: Filter by the action type (login, create, delete, etc.)
//   - resource: Filter by the specific resource identifier
//   - resource_type: Filter by resource category (user, certificate, key, etc.)
//   - outcome: Filter by result (success, failure, denied, error)
//   - source_ip: Filter by request origin IP address
//   - request_id: Filter by correlation ID
//   - timestamp: Filter by event time
//
// Note: Index utilization depends on QuicBaaS's query planner. Currently,
// filtering is performed in-memory after fetching events.
package persistence
