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
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// Logger implements the AuditLogger interface
type Logger struct {
	config LoggerConfig

	// buffer holds events for async processing
	buffer chan AuditEvent

	// closed indicates if the logger has been closed
	closed atomic.Bool

	// wg waits for background goroutines to finish
	wg sync.WaitGroup

	// stopChan signals background goroutines to stop
	stopChan chan struct{}

	// droppedEvents counts events dropped due to full buffer
	droppedEvents atomic.Int64
}

// NewLogger creates a new audit logger
func NewLogger(config LoggerConfig) (*Logger, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	l := &Logger{
		config:   config,
		stopChan: make(chan struct{}),
	}

	if config.EnableAsync {
		l.buffer = make(chan AuditEvent, config.BufferSize)
		l.wg.Add(1)
		go l.processLoop()
	}

	return l, nil
}

// Log writes an audit event synchronously
func (l *Logger) Log(ctx context.Context, event AuditEvent) error {
	if l.closed.Load() {
		return ErrLoggerClosed{}
	}

	// Generate ID if not set
	if event.ID == "" {
		event.ID = uuid.New().String()
	}

	// Set timestamp if not set
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Validate if enabled
	if l.config.ValidateEvents {
		if err := event.Validate(); err != nil {
			return err
		}
	}

	// Log to structured logger
	l.logEvent(event)

	// Persist if persister is configured
	if l.config.Persister != nil {
		if err := l.config.Persister.Persist(ctx, event); err != nil {
			return ErrPersistenceFailed{EventID: event.ID, Err: err}
		}
	}

	return nil
}

// LogAsync writes an audit event asynchronously
func (l *Logger) LogAsync(event AuditEvent) error {
	if l.closed.Load() {
		return ErrLoggerClosed{}
	}

	if !l.config.EnableAsync {
		// Fall back to sync logging
		return l.Log(context.Background(), event)
	}

	// Generate ID if not set
	if event.ID == "" {
		event.ID = uuid.New().String()
	}

	// Set timestamp if not set
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Validate if enabled
	if l.config.ValidateEvents {
		if err := event.Validate(); err != nil {
			return err
		}
	}

	// Try to send to buffer
	if l.config.DropOnFull {
		select {
		case l.buffer <- event:
			return nil
		default:
			l.droppedEvents.Add(1)
			return ErrBufferFull{Size: l.config.BufferSize}
		}
	}

	// Block until buffer has space
	select {
	case l.buffer <- event:
		return nil
	case <-l.stopChan:
		return ErrLoggerClosed{}
	}
}

// Query retrieves audit events matching the filter
func (l *Logger) Query(ctx context.Context, filter AuditFilter) ([]AuditEvent, error) {
	if l.closed.Load() {
		return nil, ErrLoggerClosed{}
	}

	if err := filter.Validate(); err != nil {
		return nil, err
	}

	if l.config.Persister == nil {
		return nil, ErrQueryFailed{Reason: "no persister configured"}
	}

	events, err := l.config.Persister.Query(ctx, filter)
	if err != nil {
		return nil, ErrQueryFailed{Reason: "query execution failed", Err: err}
	}

	return events, nil
}

// Close releases resources held by the logger
func (l *Logger) Close() error {
	if l.closed.Swap(true) {
		return ErrLoggerClosed{}
	}

	close(l.stopChan)

	if l.config.EnableAsync {
		// Wait for buffer to drain
		l.wg.Wait()
		close(l.buffer)
	}

	if l.config.Persister != nil {
		return l.config.Persister.Close()
	}

	return nil
}

// Stats returns statistics about the logger
func (l *Logger) Stats() LoggerStats {
	var buffered int
	if l.config.EnableAsync {
		buffered = len(l.buffer)
	}

	return LoggerStats{
		BufferedEvents: buffered,
		DroppedEvents:  l.droppedEvents.Load(),
		BufferSize:     l.config.BufferSize,
		Closed:         l.closed.Load(),
	}
}

// LoggerStats holds statistics about the logger
type LoggerStats struct {
	BufferedEvents int
	DroppedEvents  int64
	BufferSize     int
	Closed         bool
}

// processLoop processes events from the buffer
func (l *Logger) processLoop() {
	defer l.wg.Done()

	ticker := time.NewTicker(l.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-l.stopChan:
			// Drain remaining events
			l.drainBuffer()
			return

		case event := <-l.buffer:
			l.processEvent(event)

		case <-ticker.C:
			// Periodic flush - process any pending events
			l.flushBuffer()
		}
	}
}

// processEvent processes a single event
func (l *Logger) processEvent(event AuditEvent) {
	// Log to structured logger
	l.logEvent(event)

	// Persist if persister is configured
	if l.config.Persister != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := l.config.Persister.Persist(ctx, event); err != nil {
			l.config.Logger.Error("failed to persist audit event",
				slog.String("event_id", event.ID),
				slog.Any("error", err),
			)
		}
		cancel()
	}
}

// flushBuffer processes all pending events in the buffer
func (l *Logger) flushBuffer() {
	for {
		select {
		case event := <-l.buffer:
			l.processEvent(event)
		default:
			return
		}
	}
}

// drainBuffer drains all remaining events from the buffer
func (l *Logger) drainBuffer() {
	for {
		select {
		case event := <-l.buffer:
			l.processEvent(event)
		default:
			return
		}
	}
}

// logEvent logs an event to the structured logger
func (l *Logger) logEvent(event AuditEvent) {
	attrs := []slog.Attr{
		slog.String("event_id", event.ID),
		slog.Time("timestamp", event.Timestamp),
		slog.String("actor", event.Actor),
		slog.String("action", event.Action),
		slog.String("outcome", string(event.Outcome)),
	}

	if event.Resource != "" {
		attrs = append(attrs, slog.String("resource", event.Resource))
	}
	if event.ResourceType != "" {
		attrs = append(attrs, slog.String("resource_type", event.ResourceType))
	}
	if event.SourceIP != "" {
		attrs = append(attrs, slog.String("source_ip", event.SourceIP))
	}
	if event.RequestID != "" {
		attrs = append(attrs, slog.String("request_id", event.RequestID))
	}
	if event.SessionID != "" {
		attrs = append(attrs, slog.String("session_id", event.SessionID))
	}
	if event.Method != "" {
		attrs = append(attrs, slog.String("method", event.Method))
	}
	if event.Path != "" {
		attrs = append(attrs, slog.String("path", event.Path))
	}
	if event.StatusCode != 0 {
		attrs = append(attrs, slog.Int("status_code", event.StatusCode))
	}
	if event.Duration > 0 {
		attrs = append(attrs, slog.Duration("duration", event.Duration))
	}
	if len(event.Details) > 0 {
		attrs = append(attrs, slog.Any("details", event.Details))
	}
	if len(event.Metadata) > 0 {
		attrs = append(attrs, slog.Any("metadata", event.Metadata))
	}

	// Convert to []any for LogAttrs
	args := make([]any, len(attrs))
	for i, attr := range attrs {
		args[i] = attr
	}

	l.config.Logger.LogAttrs(context.Background(), slog.LevelInfo, "audit", attrs...)
}

// NewEvent creates a new audit event with common fields populated
func NewEvent(actor, action string, outcome Outcome) AuditEvent {
	return AuditEvent{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		Actor:     actor,
		Action:    action,
		Outcome:   outcome,
	}
}

// EventBuilder provides a fluent interface for building audit events
type EventBuilder struct {
	event AuditEvent
}

// NewEventBuilder creates a new event builder
func NewEventBuilder() *EventBuilder {
	return &EventBuilder{
		event: AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
		},
	}
}

// WithActor sets the actor
func (b *EventBuilder) WithActor(actor string) *EventBuilder {
	b.event.Actor = actor
	return b
}

// WithAction sets the action
func (b *EventBuilder) WithAction(action string) *EventBuilder {
	b.event.Action = action
	return b
}

// WithResource sets the resource and resource type
func (b *EventBuilder) WithResource(resource, resourceType string) *EventBuilder {
	b.event.Resource = resource
	b.event.ResourceType = resourceType
	return b
}

// WithOutcome sets the outcome
func (b *EventBuilder) WithOutcome(outcome Outcome) *EventBuilder {
	b.event.Outcome = outcome
	return b
}

// WithSourceIP sets the source IP
func (b *EventBuilder) WithSourceIP(ip string) *EventBuilder {
	b.event.SourceIP = ip
	return b
}

// WithRequestID sets the request ID
func (b *EventBuilder) WithRequestID(id string) *EventBuilder {
	b.event.RequestID = id
	return b
}

// WithSessionID sets the session ID
func (b *EventBuilder) WithSessionID(id string) *EventBuilder {
	b.event.SessionID = id
	return b
}

// WithMethod sets the method
func (b *EventBuilder) WithMethod(method string) *EventBuilder {
	b.event.Method = method
	return b
}

// WithPath sets the path
func (b *EventBuilder) WithPath(path string) *EventBuilder {
	b.event.Path = path
	return b
}

// WithStatusCode sets the status code
func (b *EventBuilder) WithStatusCode(code int) *EventBuilder {
	b.event.StatusCode = code
	return b
}

// WithDuration sets the duration
func (b *EventBuilder) WithDuration(d time.Duration) *EventBuilder {
	b.event.Duration = d
	return b
}

// WithDetail adds a detail
func (b *EventBuilder) WithDetail(key string, value any) *EventBuilder {
	if b.event.Details == nil {
		b.event.Details = make(map[string]any)
	}
	b.event.Details[key] = value
	return b
}

// WithMetadata adds metadata
func (b *EventBuilder) WithMetadata(key, value string) *EventBuilder {
	if b.event.Metadata == nil {
		b.event.Metadata = make(map[string]string)
	}
	b.event.Metadata[key] = value
	return b
}

// Build returns the built event
func (b *EventBuilder) Build() AuditEvent {
	return b.event
}
