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

package audit

import (
	"context"
	"log/slog"
	"time"
)

// Outcome represents the outcome of an audited action
type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
	OutcomeDenied  Outcome = "denied"
	OutcomeError   Outcome = "error"
)

// AuditEvent represents a single audit log entry
type AuditEvent struct {
	// ID is a unique identifier for the event
	ID string

	// Timestamp is when the event occurred
	Timestamp time.Time

	// Actor is the user or service performing the action
	Actor string

	// Action is what was done (e.g., "create", "delete", "login")
	Action string

	// Resource is what was acted upon (e.g., "user:123", "certificate:abc")
	Resource string

	// ResourceType categorizes the resource (e.g., "user", "certificate", "key")
	ResourceType string

	// Outcome is the result of the action
	Outcome Outcome

	// Details contains additional context about the event
	Details map[string]any

	// SourceIP is the IP address of the request origin
	SourceIP string

	// RequestID is the correlation ID for the request
	RequestID string

	// SessionID is the session identifier if applicable
	SessionID string

	// UserAgent is the user agent string if applicable
	UserAgent string

	// Method is the HTTP method or gRPC method name
	Method string

	// Path is the request path
	Path string

	// StatusCode is the HTTP status code or gRPC status code
	StatusCode int

	// Duration is how long the action took
	Duration time.Duration

	// Metadata contains any additional metadata
	Metadata map[string]string
}

// Validate checks if the audit event is valid
func (e AuditEvent) Validate() error {
	if e.ID == "" {
		return ErrInvalidEvent{Field: "ID", Reason: "cannot be empty"}
	}
	if e.Timestamp.IsZero() {
		return ErrInvalidEvent{Field: "Timestamp", Reason: "cannot be zero"}
	}
	if e.Actor == "" {
		return ErrInvalidEvent{Field: "Actor", Reason: "cannot be empty"}
	}
	if e.Action == "" {
		return ErrInvalidEvent{Field: "Action", Reason: "cannot be empty"}
	}
	if e.Outcome == "" {
		return ErrInvalidEvent{Field: "Outcome", Reason: "cannot be empty"}
	}
	return nil
}

// AuditFilter defines criteria for querying audit events
type AuditFilter struct {
	// StartTime filters events after this time
	StartTime time.Time

	// EndTime filters events before this time
	EndTime time.Time

	// Actor filters by actor
	Actor string

	// Action filters by action
	Action string

	// Resource filters by resource
	Resource string

	// ResourceType filters by resource type
	ResourceType string

	// Outcome filters by outcome
	Outcome Outcome

	// SourceIP filters by source IP
	SourceIP string

	// RequestID filters by request ID
	RequestID string

	// Limit limits the number of results
	Limit int

	// Offset skips the first n results
	Offset int

	// SortBy specifies the field to sort by
	SortBy string

	// SortDesc sorts in descending order if true
	SortDesc bool
}

// Validate checks if the audit filter is valid
func (f AuditFilter) Validate() error {
	if !f.StartTime.IsZero() && !f.EndTime.IsZero() && f.StartTime.After(f.EndTime) {
		return ErrInvalidFilter{Field: "StartTime/EndTime", Reason: "start time cannot be after end time"}
	}
	if f.Limit < 0 {
		return ErrInvalidFilter{Field: "Limit", Reason: "cannot be negative"}
	}
	if f.Offset < 0 {
		return ErrInvalidFilter{Field: "Offset", Reason: "cannot be negative"}
	}
	return nil
}

// AuditLogger defines the interface for audit logging
type AuditLogger interface {
	// Log writes an audit event
	Log(ctx context.Context, event AuditEvent) error

	// LogAsync writes an audit event asynchronously
	LogAsync(event AuditEvent) error

	// Query retrieves audit events matching the filter
	Query(ctx context.Context, filter AuditFilter) ([]AuditEvent, error)

	// Close releases resources held by the logger
	Close() error
}

// EventPersister defines the interface for persisting audit events
type EventPersister interface {
	// Persist stores an audit event
	Persist(ctx context.Context, event AuditEvent) error

	// Query retrieves audit events matching the filter
	Query(ctx context.Context, filter AuditFilter) ([]AuditEvent, error)

	// Close releases resources
	Close() error
}

// LoggerConfig holds configuration for the audit logger
type LoggerConfig struct {
	// Logger is the structured logger for output
	Logger *slog.Logger

	// Persister is optional storage for audit events
	Persister EventPersister

	// BufferSize is the size of the async buffer
	BufferSize int

	// FlushInterval is how often to flush buffered events
	FlushInterval time.Duration

	// EnableAsync enables asynchronous logging
	EnableAsync bool

	// DropOnFull drops events when buffer is full instead of blocking
	DropOnFull bool

	// ValidateEvents validates events before logging
	ValidateEvents bool
}

// DefaultLoggerConfig returns a sensible default configuration
func DefaultLoggerConfig() LoggerConfig {
	return LoggerConfig{
		Logger:         slog.Default(),
		BufferSize:     1000,
		FlushInterval:  5 * time.Second,
		EnableAsync:    true,
		DropOnFull:     false,
		ValidateEvents: true,
	}
}

// Validate checks if the configuration is valid
func (c LoggerConfig) Validate() error {
	if c.Logger == nil {
		return ErrInvalidConfig{Field: "Logger", Reason: "cannot be nil"}
	}
	if c.EnableAsync && c.BufferSize <= 0 {
		return ErrInvalidConfig{Field: "BufferSize", Reason: "must be positive when async is enabled"}
	}
	if c.EnableAsync && c.FlushInterval <= 0 {
		return ErrInvalidConfig{Field: "FlushInterval", Reason: "must be positive when async is enabled"}
	}
	return nil
}

// QueryResult holds the result of an audit query
type QueryResult struct {
	// Events is the list of matching events
	Events []AuditEvent

	// Total is the total number of matching events (ignoring limit/offset)
	Total int64

	// HasMore indicates if there are more results available
	HasMore bool
}
