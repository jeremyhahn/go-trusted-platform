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

package events

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/security/audit"
)

// mockAuditLogger implements audit.AuditLogger for testing.
type mockAuditLogger struct {
	loggedEvents []audit.AuditEvent
	logError     error
	queryCalled  bool
	closeCalled  bool
}

func newMockAuditLogger() *mockAuditLogger {
	return &mockAuditLogger{
		loggedEvents: make([]audit.AuditEvent, 0),
	}
}

func (m *mockAuditLogger) Log(ctx context.Context, event audit.AuditEvent) error {
	if m.logError != nil {
		return m.logError
	}
	m.loggedEvents = append(m.loggedEvents, event)
	return nil
}

func (m *mockAuditLogger) LogAsync(event audit.AuditEvent) error {
	return m.Log(context.Background(), event)
}

func (m *mockAuditLogger) Query(ctx context.Context, filter audit.AuditFilter) ([]audit.AuditEvent, error) {
	m.queryCalled = true
	return m.loggedEvents, nil
}

func (m *mockAuditLogger) Close() error {
	m.closeCalled = true
	return nil
}

func (m *mockAuditLogger) setLogError(err error) {
	m.logError = err
}

func (m *mockAuditLogger) lastEvent() audit.AuditEvent {
	if len(m.loggedEvents) == 0 {
		return audit.AuditEvent{}
	}
	return m.loggedEvents[len(m.loggedEvents)-1]
}

func TestNewEnrollmentEventBuilder(t *testing.T) {
	t.Run("with valid logger", func(t *testing.T) {
		logger := newMockAuditLogger()
		builder := NewEnrollmentEventBuilder(logger)

		if builder == nil {
			t.Fatal("expected non-nil builder")
		}
		if builder.logger != logger {
			t.Error("expected logger to be set")
		}
	})

	t.Run("with nil logger", func(t *testing.T) {
		builder := NewEnrollmentEventBuilder(nil)

		if builder != nil {
			t.Error("expected nil builder when logger is nil")
		}
	})
}

func TestEnrollmentEventBuilder_LogDeviceCreated(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		logger := newMockAuditLogger()
		builder := NewEnrollmentEventBuilder(logger)
		ctx := context.Background()

		deviceID := "device-123"
		tenantID := "tenant-456"
		profileID := uint64(789)

		err := builder.LogDeviceCreated(ctx, deviceID, tenantID, profileID)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if len(logger.loggedEvents) != 1 {
			t.Fatalf("expected 1 event, got %d", len(logger.loggedEvents))
		}

		event := logger.lastEvent()

		if event.ID == "" {
			t.Error("expected event ID to be set")
		}
		if event.Timestamp.IsZero() {
			t.Error("expected timestamp to be set")
		}
		if event.Timestamp.After(time.Now()) {
			t.Error("timestamp should not be in the future")
		}
		if event.Actor != ActorSystem {
			t.Errorf("expected actor %q, got %q", ActorSystem, event.Actor)
		}
		if event.Action != ActionDeviceCreated {
			t.Errorf("expected action %q, got %q", ActionDeviceCreated, event.Action)
		}
		if event.Resource != deviceID {
			t.Errorf("expected resource %q, got %q", deviceID, event.Resource)
		}
		if event.ResourceType != ResourceTypeDeviceEnrollment {
			t.Errorf("expected resource type %q, got %q", ResourceTypeDeviceEnrollment, event.ResourceType)
		}
		if event.Outcome != audit.OutcomeSuccess {
			t.Errorf("expected outcome %q, got %q", audit.OutcomeSuccess, event.Outcome)
		}

		if event.Details[DetailKeyTenantID] != tenantID {
			t.Errorf("expected tenant_id %q, got %q", tenantID, event.Details[DetailKeyTenantID])
		}
		if event.Details[DetailKeyProfileID] != profileID {
			t.Errorf("expected profile_id %d, got %v", profileID, event.Details[DetailKeyProfileID])
		}
	})

	t.Run("logger error", func(t *testing.T) {
		logger := newMockAuditLogger()
		expectedErr := errors.New("log failed")
		logger.setLogError(expectedErr)

		builder := NewEnrollmentEventBuilder(logger)
		ctx := context.Background()

		err := builder.LogDeviceCreated(ctx, "device-123", "tenant-456", 789)

		if err == nil {
			t.Error("expected error")
		}
		if err != expectedErr {
			t.Errorf("expected error %v, got %v", expectedErr, err)
		}
	})

	t.Run("nil builder", func(t *testing.T) {
		var builder *EnrollmentEventBuilder
		ctx := context.Background()

		err := builder.LogDeviceCreated(ctx, "device-123", "tenant-456", 789)

		if err == nil {
			t.Error("expected error for nil builder")
		}
		var nilErr ErrNilBuilder
		if !errors.As(err, &nilErr) {
			t.Errorf("expected ErrNilBuilder, got %T", err)
		}
	})
}

func TestEnrollmentEventBuilder_LogEnrollmentStarted(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		logger := newMockAuditLogger()
		builder := NewEnrollmentEventBuilder(logger)
		ctx := context.Background()

		deviceID := "device-123"
		tenantID := "tenant-456"
		csrHash := "sha256:abc123def456"

		err := builder.LogEnrollmentStarted(ctx, deviceID, tenantID, csrHash)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if len(logger.loggedEvents) != 1 {
			t.Fatalf("expected 1 event, got %d", len(logger.loggedEvents))
		}

		event := logger.lastEvent()

		if event.ID == "" {
			t.Error("expected event ID to be set")
		}
		if event.Timestamp.IsZero() {
			t.Error("expected timestamp to be set")
		}
		if event.Actor != deviceID {
			t.Errorf("expected actor %q, got %q", deviceID, event.Actor)
		}
		if event.Action != ActionEnrollmentStarted {
			t.Errorf("expected action %q, got %q", ActionEnrollmentStarted, event.Action)
		}
		if event.Resource != deviceID {
			t.Errorf("expected resource %q, got %q", deviceID, event.Resource)
		}
		if event.ResourceType != ResourceTypeDeviceEnrollment {
			t.Errorf("expected resource type %q, got %q", ResourceTypeDeviceEnrollment, event.ResourceType)
		}
		if event.Outcome != audit.OutcomeSuccess {
			t.Errorf("expected outcome %q, got %q", audit.OutcomeSuccess, event.Outcome)
		}

		if event.Details[DetailKeyTenantID] != tenantID {
			t.Errorf("expected tenant_id %q, got %q", tenantID, event.Details[DetailKeyTenantID])
		}
		if event.Details[DetailKeyCSRHash] != csrHash {
			t.Errorf("expected csr_hash %q, got %q", csrHash, event.Details[DetailKeyCSRHash])
		}
	})

	t.Run("logger error", func(t *testing.T) {
		logger := newMockAuditLogger()
		expectedErr := errors.New("log failed")
		logger.setLogError(expectedErr)

		builder := NewEnrollmentEventBuilder(logger)
		ctx := context.Background()

		err := builder.LogEnrollmentStarted(ctx, "device-123", "tenant-456", "sha256:abc")

		if err == nil {
			t.Error("expected error")
		}
		if err != expectedErr {
			t.Errorf("expected error %v, got %v", expectedErr, err)
		}
	})

	t.Run("nil builder", func(t *testing.T) {
		var builder *EnrollmentEventBuilder
		ctx := context.Background()

		err := builder.LogEnrollmentStarted(ctx, "device-123", "tenant-456", "sha256:abc")

		if err == nil {
			t.Error("expected error for nil builder")
		}
		var nilErr ErrNilBuilder
		if !errors.As(err, &nilErr) {
			t.Errorf("expected ErrNilBuilder, got %T", err)
		}
	})
}

func TestEnrollmentEventBuilder_LogEnrollmentCompleted(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		logger := newMockAuditLogger()
		builder := NewEnrollmentEventBuilder(logger)
		ctx := context.Background()

		deviceID := "device-123"
		tenantID := "tenant-456"
		certSerial := "0A:1B:2C:3D:4E:5F"

		err := builder.LogEnrollmentCompleted(ctx, deviceID, tenantID, certSerial)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if len(logger.loggedEvents) != 1 {
			t.Fatalf("expected 1 event, got %d", len(logger.loggedEvents))
		}

		event := logger.lastEvent()

		if event.ID == "" {
			t.Error("expected event ID to be set")
		}
		if event.Timestamp.IsZero() {
			t.Error("expected timestamp to be set")
		}
		if event.Actor != deviceID {
			t.Errorf("expected actor %q, got %q", deviceID, event.Actor)
		}
		if event.Action != ActionEnrollmentCompleted {
			t.Errorf("expected action %q, got %q", ActionEnrollmentCompleted, event.Action)
		}
		if event.Resource != deviceID {
			t.Errorf("expected resource %q, got %q", deviceID, event.Resource)
		}
		if event.ResourceType != ResourceTypeDeviceEnrollment {
			t.Errorf("expected resource type %q, got %q", ResourceTypeDeviceEnrollment, event.ResourceType)
		}
		if event.Outcome != audit.OutcomeSuccess {
			t.Errorf("expected outcome %q, got %q", audit.OutcomeSuccess, event.Outcome)
		}

		if event.Details[DetailKeyTenantID] != tenantID {
			t.Errorf("expected tenant_id %q, got %q", tenantID, event.Details[DetailKeyTenantID])
		}
		if event.Details[DetailKeyCertSerial] != certSerial {
			t.Errorf("expected cert_serial %q, got %q", certSerial, event.Details[DetailKeyCertSerial])
		}
	})

	t.Run("logger error", func(t *testing.T) {
		logger := newMockAuditLogger()
		expectedErr := errors.New("log failed")
		logger.setLogError(expectedErr)

		builder := NewEnrollmentEventBuilder(logger)
		ctx := context.Background()

		err := builder.LogEnrollmentCompleted(ctx, "device-123", "tenant-456", "0A:1B:2C")

		if err == nil {
			t.Error("expected error")
		}
		if err != expectedErr {
			t.Errorf("expected error %v, got %v", expectedErr, err)
		}
	})

	t.Run("nil builder", func(t *testing.T) {
		var builder *EnrollmentEventBuilder
		ctx := context.Background()

		err := builder.LogEnrollmentCompleted(ctx, "device-123", "tenant-456", "0A:1B:2C")

		if err == nil {
			t.Error("expected error for nil builder")
		}
		var nilErr ErrNilBuilder
		if !errors.As(err, &nilErr) {
			t.Errorf("expected ErrNilBuilder, got %T", err)
		}
	})
}

func TestEnrollmentEventBuilder_LogEnrollmentFailed(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		logger := newMockAuditLogger()
		builder := NewEnrollmentEventBuilder(logger)
		ctx := context.Background()

		deviceID := "device-123"
		tenantID := "tenant-456"
		reason := "CSR validation failed: invalid signature"

		err := builder.LogEnrollmentFailed(ctx, deviceID, tenantID, reason)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if len(logger.loggedEvents) != 1 {
			t.Fatalf("expected 1 event, got %d", len(logger.loggedEvents))
		}

		event := logger.lastEvent()

		if event.ID == "" {
			t.Error("expected event ID to be set")
		}
		if event.Timestamp.IsZero() {
			t.Error("expected timestamp to be set")
		}
		if event.Actor != deviceID {
			t.Errorf("expected actor %q, got %q", deviceID, event.Actor)
		}
		if event.Action != ActionEnrollmentFailed {
			t.Errorf("expected action %q, got %q", ActionEnrollmentFailed, event.Action)
		}
		if event.Resource != deviceID {
			t.Errorf("expected resource %q, got %q", deviceID, event.Resource)
		}
		if event.ResourceType != ResourceTypeDeviceEnrollment {
			t.Errorf("expected resource type %q, got %q", ResourceTypeDeviceEnrollment, event.ResourceType)
		}
		if event.Outcome != audit.OutcomeFailure {
			t.Errorf("expected outcome %q, got %q", audit.OutcomeFailure, event.Outcome)
		}

		if event.Details[DetailKeyTenantID] != tenantID {
			t.Errorf("expected tenant_id %q, got %q", tenantID, event.Details[DetailKeyTenantID])
		}
		if event.Details[DetailKeyFailedReason] != reason {
			t.Errorf("expected reason %q, got %q", reason, event.Details[DetailKeyFailedReason])
		}
	})

	t.Run("logger error", func(t *testing.T) {
		logger := newMockAuditLogger()
		expectedErr := errors.New("log failed")
		logger.setLogError(expectedErr)

		builder := NewEnrollmentEventBuilder(logger)
		ctx := context.Background()

		err := builder.LogEnrollmentFailed(ctx, "device-123", "tenant-456", "some error")

		if err == nil {
			t.Error("expected error")
		}
		if err != expectedErr {
			t.Errorf("expected error %v, got %v", expectedErr, err)
		}
	})

	t.Run("nil builder", func(t *testing.T) {
		var builder *EnrollmentEventBuilder
		ctx := context.Background()

		err := builder.LogEnrollmentFailed(ctx, "device-123", "tenant-456", "some error")

		if err == nil {
			t.Error("expected error for nil builder")
		}
		var nilErr ErrNilBuilder
		if !errors.As(err, &nilErr) {
			t.Errorf("expected ErrNilBuilder, got %T", err)
		}
	})
}

func TestEnrollmentEventBuilder_EventValidation(t *testing.T) {
	t.Run("events pass validation", func(t *testing.T) {
		logger := newMockAuditLogger()
		builder := NewEnrollmentEventBuilder(logger)
		ctx := context.Background()

		// Log all event types
		if err := builder.LogDeviceCreated(ctx, "device-1", "tenant-1", 1); err != nil {
			t.Errorf("LogDeviceCreated failed: %v", err)
		}
		if err := builder.LogEnrollmentStarted(ctx, "device-2", "tenant-2", "hash"); err != nil {
			t.Errorf("LogEnrollmentStarted failed: %v", err)
		}
		if err := builder.LogEnrollmentCompleted(ctx, "device-3", "tenant-3", "serial"); err != nil {
			t.Errorf("LogEnrollmentCompleted failed: %v", err)
		}
		if err := builder.LogEnrollmentFailed(ctx, "device-4", "tenant-4", "reason"); err != nil {
			t.Errorf("LogEnrollmentFailed failed: %v", err)
		}

		// Verify all events would pass validation
		for i, event := range logger.loggedEvents {
			if err := event.Validate(); err != nil {
				t.Errorf("event %d failed validation: %v", i, err)
			}
		}
	})
}

func TestEnrollmentEventBuilder_UniqueIDs(t *testing.T) {
	t.Run("each event has unique ID", func(t *testing.T) {
		logger := newMockAuditLogger()
		builder := NewEnrollmentEventBuilder(logger)
		ctx := context.Background()

		// Log multiple events
		for i := 0; i < 10; i++ {
			if err := builder.LogDeviceCreated(ctx, "device", "tenant", uint64(i)); err != nil {
				t.Fatalf("LogDeviceCreated failed: %v", err)
			}
		}

		// Check all IDs are unique
		seenIDs := make(map[string]bool)
		for _, event := range logger.loggedEvents {
			if seenIDs[event.ID] {
				t.Errorf("duplicate event ID: %s", event.ID)
			}
			seenIDs[event.ID] = true
		}
	})
}

func TestEnrollmentConstants(t *testing.T) {
	t.Run("action constants are defined", func(t *testing.T) {
		if ActionDeviceCreated == "" {
			t.Error("ActionDeviceCreated should not be empty")
		}
		if ActionEnrollmentStarted == "" {
			t.Error("ActionEnrollmentStarted should not be empty")
		}
		if ActionEnrollmentCompleted == "" {
			t.Error("ActionEnrollmentCompleted should not be empty")
		}
		if ActionEnrollmentFailed == "" {
			t.Error("ActionEnrollmentFailed should not be empty")
		}
	})

	t.Run("resource type constant is defined", func(t *testing.T) {
		if ResourceTypeDeviceEnrollment == "" {
			t.Error("ResourceTypeDeviceEnrollment should not be empty")
		}
	})

	t.Run("detail key constants are defined", func(t *testing.T) {
		if DetailKeyTenantID == "" {
			t.Error("DetailKeyTenantID should not be empty")
		}
		if DetailKeyProfileID == "" {
			t.Error("DetailKeyProfileID should not be empty")
		}
		if DetailKeyCSRHash == "" {
			t.Error("DetailKeyCSRHash should not be empty")
		}
		if DetailKeyCertSerial == "" {
			t.Error("DetailKeyCertSerial should not be empty")
		}
		if DetailKeyFailedReason == "" {
			t.Error("DetailKeyFailedReason should not be empty")
		}
	})

	t.Run("actor system constant is defined", func(t *testing.T) {
		if ActorSystem == "" {
			t.Error("ActorSystem should not be empty")
		}
	})
}
