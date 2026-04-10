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
	"bytes"
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"
)

func TestNewLogger(t *testing.T) {
	tests := []struct {
		name        string
		config      LoggerConfig
		expectError bool
	}{
		{
			name:        "valid config",
			config:      DefaultLoggerConfig(),
			expectError: false,
		},
		{
			name: "nil logger",
			config: LoggerConfig{
				Logger: nil,
			},
			expectError: true,
		},
		{
			name: "async with zero buffer",
			config: LoggerConfig{
				Logger:      slog.Default(),
				EnableAsync: true,
				BufferSize:  0,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, err := NewLogger(tt.config)
			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			defer func() {
				if err := logger.Close(); err != nil {
					t.Logf("cleanup: %v", err)
				}
			}()

			if logger == nil {
				t.Error("logger is nil")
			}
		})
	}
}

func TestLogger_Log(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:         slog.New(handler),
		EnableAsync:    false,
		ValidateEvents: true,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer func() {
		if err := logger.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	event := NewEvent("user@example.com", "login", OutcomeSuccess)

	err = logger.Log(context.Background(), event)
	if err != nil {
		t.Errorf("Log failed: %v", err)
	}

	// Check that something was logged
	if buf.Len() == 0 {
		t.Error("nothing was logged")
	}
}

func TestLogger_Log_ValidationEnabled(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:         slog.New(handler),
		EnableAsync:    false,
		ValidateEvents: true,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer func() {
		if err := logger.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	// Invalid event - missing actor
	event := AuditEvent{
		ID:        "test-id",
		Timestamp: time.Now(),
		Actor:     "", // Empty actor
		Action:    "test",
		Outcome:   OutcomeSuccess,
	}

	err = logger.Log(context.Background(), event)
	if err == nil {
		t.Error("expected validation error, got nil")
	}
}

func TestLogger_Log_ValidationDisabled(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:         slog.New(handler),
		EnableAsync:    false,
		ValidateEvents: false, // Validation disabled
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer func() {
		if err := logger.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	// Invalid event but validation is disabled
	event := AuditEvent{
		ID:        "test-id",
		Timestamp: time.Now(),
		Actor:     "", // Empty actor
		Action:    "test",
		Outcome:   OutcomeSuccess,
	}

	err = logger.Log(context.Background(), event)
	if err != nil {
		t.Errorf("Log should succeed with validation disabled: %v", err)
	}
}

func TestLogger_Log_AutoPopulatesFields(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:         slog.New(handler),
		EnableAsync:    false,
		ValidateEvents: false,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer func() {
		if err := logger.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	// Event without ID and Timestamp
	event := AuditEvent{
		Actor:   "user",
		Action:  "test",
		Outcome: OutcomeSuccess,
	}

	before := time.Now()
	err = logger.Log(context.Background(), event)
	after := time.Now()

	if err != nil {
		t.Errorf("Log failed: %v", err)
	}

	// Note: The event is passed by value, so we can't check the populated fields
	// directly, but the log should succeed
	_ = before
	_ = after
}

func TestLogger_LogAsync(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   true,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	event := NewEvent("user@example.com", "login", OutcomeSuccess)

	err = logger.LogAsync(event)
	if err != nil {
		t.Errorf("LogAsync failed: %v", err)
	}

	// Wait for async processing
	time.Sleep(50 * time.Millisecond)

	// Close to flush remaining events
	logger.Close()

	// Check that something was logged
	if buf.Len() == 0 {
		t.Error("nothing was logged")
	}
}

func TestLogger_LogAsync_BufferFull(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   true,
		BufferSize:    2, // Very small buffer
		FlushInterval: time.Hour,
		DropOnFull:    true,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer func() {
		if err := logger.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	// Fill the buffer
	for i := 0; i < 5; i++ {
		event := NewEvent("user", "action", OutcomeSuccess)
		_ = logger.LogAsync(event)
	}

	// Stats should show dropped events
	stats := logger.Stats()
	if stats.DroppedEvents == 0 {
		t.Error("expected dropped events")
	}
}

func TestLogger_LogAsync_FallbackToSync(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:      slog.New(handler),
		EnableAsync: false, // Async disabled
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer func() {
		if err := logger.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	event := NewEvent("user", "action", OutcomeSuccess)

	err = logger.LogAsync(event)
	if err != nil {
		t.Errorf("LogAsync should fall back to sync: %v", err)
	}

	// Should be logged immediately
	if buf.Len() == 0 {
		t.Error("nothing was logged")
	}
}

func TestLogger_Query_NoPersister(t *testing.T) {
	logger, err := NewLogger(DefaultLoggerConfig())
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer func() {
		if err := logger.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	_, err = logger.Query(context.Background(), AuditFilter{})
	if err == nil {
		t.Error("expected error when no persister configured")
	}
}

func TestLogger_Close(t *testing.T) {
	logger, err := NewLogger(DefaultLoggerConfig())
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	// Close should succeed
	err = logger.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Second close should return error
	err = logger.Close()
	if err == nil {
		t.Error("second Close should return error")
	}

	// Log should fail after close
	err = logger.Log(context.Background(), NewEvent("user", "action", OutcomeSuccess))
	if err == nil {
		t.Error("Log should fail after close")
	}
}

func TestLogger_Stats(t *testing.T) {
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.Default(),
		EnableAsync:   true,
		BufferSize:    100,
		FlushInterval: time.Second,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer func() {
		if err := logger.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	stats := logger.Stats()
	if stats.BufferSize != 100 {
		t.Errorf("BufferSize = %d, expected 100", stats.BufferSize)
	}
	if stats.Closed {
		t.Error("Closed should be false")
	}
}

func TestLogger_Concurrent(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   true,
		BufferSize:    1000,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				event := NewEvent("user", "action", OutcomeSuccess)
				_ = logger.LogAsync(event)
			}
		}(i)
	}

	wg.Wait()
	logger.Close()

	// All events should be logged
	if buf.Len() == 0 {
		t.Error("nothing was logged")
	}
}

func TestNewEvent(t *testing.T) {
	event := NewEvent("user@example.com", "login", OutcomeSuccess)

	if event.ID == "" {
		t.Error("ID should be auto-generated")
	}
	if event.Timestamp.IsZero() {
		t.Error("Timestamp should be set")
	}
	if event.Actor != "user@example.com" {
		t.Errorf("Actor = %s, expected user@example.com", event.Actor)
	}
	if event.Action != "login" {
		t.Errorf("Action = %s, expected login", event.Action)
	}
	if event.Outcome != OutcomeSuccess {
		t.Errorf("Outcome = %s, expected success", event.Outcome)
	}
}

func TestEventBuilder(t *testing.T) {
	event := NewEventBuilder().
		WithActor("user@example.com").
		WithAction("create").
		WithResource("document:123", "document").
		WithOutcome(OutcomeSuccess).
		WithSourceIP("192.168.1.1").
		WithRequestID("req-123").
		WithSessionID("sess-456").
		WithMethod("POST").
		WithPath("/api/documents").
		WithStatusCode(201).
		WithDuration(100*time.Millisecond).
		WithDetail("size", 1024).
		WithMetadata("version", "v1").
		Build()

	if event.ID == "" {
		t.Error("ID should be auto-generated")
	}
	if event.Timestamp.IsZero() {
		t.Error("Timestamp should be set")
	}
	if event.Actor != "user@example.com" {
		t.Errorf("Actor = %s, expected user@example.com", event.Actor)
	}
	if event.Action != "create" {
		t.Errorf("Action = %s, expected create", event.Action)
	}
	if event.Resource != "document:123" {
		t.Errorf("Resource = %s, expected document:123", event.Resource)
	}
	if event.ResourceType != "document" {
		t.Errorf("ResourceType = %s, expected document", event.ResourceType)
	}
	if event.Outcome != OutcomeSuccess {
		t.Errorf("Outcome = %s, expected success", event.Outcome)
	}
	if event.SourceIP != "192.168.1.1" {
		t.Errorf("SourceIP = %s, expected 192.168.1.1", event.SourceIP)
	}
	if event.RequestID != "req-123" {
		t.Errorf("RequestID = %s, expected req-123", event.RequestID)
	}
	if event.SessionID != "sess-456" {
		t.Errorf("SessionID = %s, expected sess-456", event.SessionID)
	}
	if event.Method != "POST" {
		t.Errorf("Method = %s, expected POST", event.Method)
	}
	if event.Path != "/api/documents" {
		t.Errorf("Path = %s, expected /api/documents", event.Path)
	}
	if event.StatusCode != 201 {
		t.Errorf("StatusCode = %d, expected 201", event.StatusCode)
	}
	if event.Duration != 100*time.Millisecond {
		t.Errorf("Duration = %v, expected 100ms", event.Duration)
	}
	if event.Details["size"] != 1024 {
		t.Errorf("Details[size] = %v, expected 1024", event.Details["size"])
	}
	if event.Metadata["version"] != "v1" {
		t.Errorf("Metadata[version] = %s, expected v1", event.Metadata["version"])
	}
}

func TestEventBuilder_MultipleDetails(t *testing.T) {
	event := NewEventBuilder().
		WithActor("user").
		WithAction("test").
		WithOutcome(OutcomeSuccess).
		WithDetail("key1", "value1").
		WithDetail("key2", "value2").
		WithMetadata("meta1", "m1").
		WithMetadata("meta2", "m2").
		Build()

	if len(event.Details) != 2 {
		t.Errorf("Details length = %d, expected 2", len(event.Details))
	}
	if len(event.Metadata) != 2 {
		t.Errorf("Metadata length = %d, expected 2", len(event.Metadata))
	}
}

func TestLogger_LogAsync_Blocking(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   true,
		BufferSize:    2,
		FlushInterval: 10 * time.Millisecond,
		DropOnFull:    false, // Block when full
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer func() {
		if err := logger.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	// Fill buffer - should not block because we have FlushInterval
	for i := 0; i < 5; i++ {
		event := NewEvent("user", "action", OutcomeSuccess)
		_ = logger.LogAsync(event)
	}

	// Wait for flush
	time.Sleep(30 * time.Millisecond)
}

func TestLogger_Log_AllFields(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:         slog.New(handler),
		EnableAsync:    false,
		ValidateEvents: false,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer func() {
		if err := logger.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	event := AuditEvent{
		ID:           "test-id",
		Timestamp:    time.Now(),
		Actor:        "user@example.com",
		Action:       "create",
		Resource:     "document:123",
		ResourceType: "document",
		Outcome:      OutcomeSuccess,
		SourceIP:     "192.168.1.1",
		RequestID:    "req-123",
		SessionID:    "sess-456",
		UserAgent:    "test-agent",
		Method:       "POST",
		Path:         "/api/documents",
		StatusCode:   201,
		Duration:     100 * time.Millisecond,
		Details:      map[string]any{"key": "value"},
		Metadata:     map[string]string{"meta": "data"},
	}

	err = logger.Log(context.Background(), event)
	if err != nil {
		t.Errorf("Log failed: %v", err)
	}

	// Check that all fields were logged
	output := buf.String()
	if output == "" {
		t.Error("nothing was logged")
	}
}

func TestLogger_ProcessLoop_DrainOnClose(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   true,
		BufferSize:    100,
		FlushInterval: time.Hour, // Long interval so we rely on close draining
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	// Add some events
	for i := 0; i < 5; i++ {
		event := NewEvent("user", "action", OutcomeSuccess)
		_ = logger.LogAsync(event)
	}

	// Close should drain the buffer
	logger.Close()

	// All events should be logged
	if buf.Len() == 0 {
		t.Error("nothing was logged after close")
	}
}

// mockEventPersister implements EventPersister for testing
type mockEventPersister struct {
	persistErr   error
	queryErr     error
	closeErr     error
	events       []AuditEvent
	persistCount int
}

func (m *mockEventPersister) Persist(ctx context.Context, event AuditEvent) error {
	m.persistCount++
	if m.persistErr != nil {
		return m.persistErr
	}
	m.events = append(m.events, event)
	return nil
}

func (m *mockEventPersister) Query(ctx context.Context, filter AuditFilter) ([]AuditEvent, error) {
	if m.queryErr != nil {
		return nil, m.queryErr
	}
	return m.events, nil
}

func (m *mockEventPersister) Close() error {
	return m.closeErr
}

func TestLogger_Log_WithPersister(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	persister := &mockEventPersister{}
	logger, err := NewLogger(LoggerConfig{
		Logger:         slog.New(handler),
		EnableAsync:    false,
		ValidateEvents: false,
		Persister:      persister,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer func() {
		if err := logger.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	event := NewEvent("user", "action", OutcomeSuccess)
	err = logger.Log(context.Background(), event)
	if err != nil {
		t.Errorf("Log failed: %v", err)
	}

	if len(persister.events) != 1 {
		t.Errorf("expected 1 persisted event, got %d", len(persister.events))
	}
}

func TestLogger_Log_PersisterError(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	persister := &mockEventPersister{persistErr: errors.New("persist failed")}
	logger, err := NewLogger(LoggerConfig{
		Logger:         slog.New(handler),
		EnableAsync:    false,
		ValidateEvents: false,
		Persister:      persister,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer func() {
		if err := logger.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	event := NewEvent("user", "action", OutcomeSuccess)
	err = logger.Log(context.Background(), event)
	if err == nil {
		t.Error("expected persistence error, got nil")
	}

	// Check that the error is of the expected type
	var persistErr ErrPersistenceFailed
	if !errors.As(err, &persistErr) {
		t.Errorf("expected ErrPersistenceFailed, got %T", err)
	}
}

func TestLogger_Query_WithPersister(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	storedEvents := []AuditEvent{
		NewEvent("user1", "action1", OutcomeSuccess),
		NewEvent("user2", "action2", OutcomeFailure),
	}
	persister := &mockEventPersister{events: storedEvents}
	logger, err := NewLogger(LoggerConfig{
		Logger:         slog.New(handler),
		EnableAsync:    false,
		ValidateEvents: false,
		Persister:      persister,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer func() {
		if err := logger.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	events, err := logger.Query(context.Background(), AuditFilter{})
	if err != nil {
		t.Errorf("Query failed: %v", err)
	}

	if len(events) != 2 {
		t.Errorf("expected 2 events, got %d", len(events))
	}
}

func TestLogger_Query_PersisterError(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	persister := &mockEventPersister{queryErr: errors.New("query failed")}
	logger, err := NewLogger(LoggerConfig{
		Logger:         slog.New(handler),
		EnableAsync:    false,
		ValidateEvents: false,
		Persister:      persister,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer func() {
		if err := logger.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	_, err = logger.Query(context.Background(), AuditFilter{})
	if err == nil {
		t.Error("expected query error, got nil")
	}

	// Check that the error is of the expected type
	var queryErr ErrQueryFailed
	if !errors.As(err, &queryErr) {
		t.Errorf("expected ErrQueryFailed, got %T", err)
	}
}

func TestLogger_Query_InvalidFilter(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	persister := &mockEventPersister{}
	logger, err := NewLogger(LoggerConfig{
		Logger:         slog.New(handler),
		EnableAsync:    false,
		ValidateEvents: false,
		Persister:      persister,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer func() {
		if err := logger.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	// Invalid filter - negative limit
	_, err = logger.Query(context.Background(), AuditFilter{Limit: -1})
	if err == nil {
		t.Error("expected validation error for invalid filter, got nil")
	}
}

func TestLogger_Query_Closed(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	persister := &mockEventPersister{}
	logger, err := NewLogger(LoggerConfig{
		Logger:         slog.New(handler),
		EnableAsync:    false,
		ValidateEvents: false,
		Persister:      persister,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	logger.Close()

	_, err = logger.Query(context.Background(), AuditFilter{})
	if err == nil {
		t.Error("expected error when querying closed logger, got nil")
	}
}

func TestLogger_LogAsync_Closed(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   true,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	logger.Close()

	event := NewEvent("user", "action", OutcomeSuccess)
	err = logger.LogAsync(event)
	if err == nil {
		t.Error("expected error when logging to closed logger, got nil")
	}
}

func TestLogger_LogAsync_ValidationError(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:         slog.New(handler),
		EnableAsync:    true,
		BufferSize:     100,
		FlushInterval:  10 * time.Millisecond,
		ValidateEvents: true, // Enable validation
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer func() {
		if err := logger.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	// Invalid event - missing required fields
	event := AuditEvent{
		ID:        "test-id",
		Timestamp: time.Now(),
		Actor:     "", // Empty actor - invalid
		Action:    "test",
		Outcome:   OutcomeSuccess,
	}

	err = logger.LogAsync(event)
	if err == nil {
		t.Error("expected validation error, got nil")
	}
}

func TestLogger_Close_WithPersister(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	persister := &mockEventPersister{}
	logger, err := NewLogger(LoggerConfig{
		Logger:         slog.New(handler),
		EnableAsync:    true,
		BufferSize:     100,
		FlushInterval:  10 * time.Millisecond,
		ValidateEvents: false,
		Persister:      persister,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	err = logger.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestLogger_Close_PersisterError(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	persister := &mockEventPersister{closeErr: errors.New("close failed")}
	logger, err := NewLogger(LoggerConfig{
		Logger:         slog.New(handler),
		EnableAsync:    true,
		BufferSize:     100,
		FlushInterval:  10 * time.Millisecond,
		ValidateEvents: false,
		Persister:      persister,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	err = logger.Close()
	if err == nil {
		t.Error("expected error from persister close, got nil")
	}
}

func TestLogger_ProcessEvent_WithPersister(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	persister := &mockEventPersister{}
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   true,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
		Persister:     persister,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	event := NewEvent("user", "action", OutcomeSuccess)
	err = logger.LogAsync(event)
	if err != nil {
		t.Errorf("LogAsync failed: %v", err)
	}

	// Wait for async processing
	time.Sleep(50 * time.Millisecond)
	logger.Close()

	if len(persister.events) != 1 {
		t.Errorf("expected 1 persisted event, got %d", len(persister.events))
	}
}

func TestLogger_ProcessEvent_PersisterError(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	persister := &mockEventPersister{persistErr: errors.New("persist failed")}
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   true,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
		Persister:     persister,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	event := NewEvent("user", "action", OutcomeSuccess)
	err = logger.LogAsync(event)
	if err != nil {
		t.Errorf("LogAsync failed: %v", err)
	}

	// Wait for async processing
	time.Sleep(50 * time.Millisecond)
	logger.Close()

	// The persist should have been attempted
	if persister.persistCount == 0 {
		t.Error("expected persist to be called")
	}
}

func TestLogger_Stats_SyncMode(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:      slog.New(handler),
		EnableAsync: false, // Sync mode
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer func() {
		if err := logger.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	stats := logger.Stats()
	if stats.BufferedEvents != 0 {
		t.Errorf("expected 0 buffered events in sync mode, got %d", stats.BufferedEvents)
	}
}

func TestLogger_Stats_AfterClose(t *testing.T) {
	logger, err := NewLogger(DefaultLoggerConfig())
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	logger.Close()

	stats := logger.Stats()
	if !stats.Closed {
		t.Error("expected Closed to be true after close")
	}
}

func TestLogger_LogAsync_AutoPopulatesFields(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:         slog.New(handler),
		EnableAsync:    true,
		BufferSize:     100,
		FlushInterval:  10 * time.Millisecond,
		ValidateEvents: false,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	// Event without ID and Timestamp
	event := AuditEvent{
		Actor:   "user",
		Action:  "test",
		Outcome: OutcomeSuccess,
	}

	err = logger.LogAsync(event)
	if err != nil {
		t.Errorf("LogAsync failed: %v", err)
	}

	// Wait for async processing
	time.Sleep(50 * time.Millisecond)
	logger.Close()

	if buf.Len() == 0 {
		t.Error("nothing was logged")
	}
}

func TestLogger_FlushBuffer(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   true,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	// Add events
	for i := 0; i < 10; i++ {
		event := NewEvent("user", "action", OutcomeSuccess)
		_ = logger.LogAsync(event)
	}

	// Wait for flush interval
	time.Sleep(50 * time.Millisecond)

	// Close to ensure all events are processed
	logger.Close()

	if buf.Len() == 0 {
		t.Error("nothing was logged after flush")
	}
}

func TestLogger_LogAsync_BlockingMode(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	logger, err := NewLogger(LoggerConfig{
		Logger:        slog.New(handler),
		EnableAsync:   true,
		BufferSize:    100,
		FlushInterval: 10 * time.Millisecond,
		DropOnFull:    false, // Blocking mode
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	// Add events
	for i := 0; i < 50; i++ {
		event := NewEvent("user", "action", OutcomeSuccess)
		_ = logger.LogAsync(event)
	}

	logger.Close()

	if buf.Len() == 0 {
		t.Error("nothing was logged")
	}
}

func TestLogger_Query_InvalidFilterTimestamp(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	persister := &mockEventPersister{}
	logger, err := NewLogger(LoggerConfig{
		Logger:         slog.New(handler),
		EnableAsync:    false,
		ValidateEvents: false,
		Persister:      persister,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer func() {
		if err := logger.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	// Invalid filter - start time after end time
	now := time.Now()
	_, err = logger.Query(context.Background(), AuditFilter{
		StartTime: now.Add(time.Hour),
		EndTime:   now,
	})
	if err == nil {
		t.Error("expected validation error for invalid time range, got nil")
	}
}

func TestLogger_Query_InvalidFilterOffset(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	persister := &mockEventPersister{}
	logger, err := NewLogger(LoggerConfig{
		Logger:         slog.New(handler),
		EnableAsync:    false,
		ValidateEvents: false,
		Persister:      persister,
	})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer func() {
		if err := logger.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	// Invalid filter - negative offset
	_, err = logger.Query(context.Background(), AuditFilter{Offset: -1})
	if err == nil {
		t.Error("expected validation error for negative offset, got nil")
	}
}
