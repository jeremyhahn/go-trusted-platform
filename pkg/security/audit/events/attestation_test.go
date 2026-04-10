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

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/security/audit"
)

func TestNewAttestationEventBuilder(t *testing.T) {
	t.Run("with valid logger", func(t *testing.T) {
		logger := newMockAuditLogger()
		builder, err := NewAttestationEventBuilder(logger)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if builder == nil {
			t.Fatal("expected non-nil builder")
		}
		if builder.logger != logger {
			t.Error("expected logger to be set")
		}
	})

	t.Run("with nil logger", func(t *testing.T) {
		builder, err := NewAttestationEventBuilder(nil)

		if err == nil {
			t.Error("expected error for nil logger")
		}
		if builder != nil {
			t.Error("expected nil builder when logger is nil")
		}
		var nilErr ErrNilLogger
		if !errors.As(err, &nilErr) {
			t.Errorf("expected ErrNilLogger, got %T", err)
		}
	})
}

func TestAttestationEventBuilder_LogQuoteVerification(t *testing.T) {
	t.Run("success case", func(t *testing.T) {
		logger := newMockAuditLogger()
		builder, err := NewAttestationEventBuilder(logger)
		if err != nil {
			t.Fatalf("failed to create builder: %v", err)
		}
		ctx := context.Background()

		deviceID := "device-123"
		details := map[string]any{
			"nonce":     "abc123",
			"algorithm": "sha256",
		}

		err = builder.LogQuoteVerification(ctx, deviceID, true, details)

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
		if event.Timestamp.After(time.Now().Add(time.Second)) {
			t.Error("timestamp should not be in the future")
		}
		if event.Actor != deviceID {
			t.Errorf("expected actor %q, got %q", deviceID, event.Actor)
		}
		if event.Action != ActionQuoteVerification {
			t.Errorf("expected action %q, got %q", ActionQuoteVerification, event.Action)
		}
		if event.Resource != deviceID {
			t.Errorf("expected resource %q, got %q", deviceID, event.Resource)
		}
		if event.ResourceType != ResourceTypeAttestation {
			t.Errorf("expected resource type %q, got %q", ResourceTypeAttestation, event.ResourceType)
		}
		if event.Outcome != audit.OutcomeSuccess {
			t.Errorf("expected outcome %q, got %q", audit.OutcomeSuccess, event.Outcome)
		}
		if event.Details["verification_type"] != "tpm_quote" {
			t.Errorf("expected verification_type %q, got %q", "tpm_quote", event.Details["verification_type"])
		}
		if event.Details["nonce"] != "abc123" {
			t.Errorf("expected nonce %q, got %q", "abc123", event.Details["nonce"])
		}
	})

	t.Run("failure case", func(t *testing.T) {
		logger := newMockAuditLogger()
		builder, err := NewAttestationEventBuilder(logger)
		if err != nil {
			t.Fatalf("failed to create builder: %v", err)
		}
		ctx := context.Background()

		err = builder.LogQuoteVerification(ctx, "device-123", false, nil)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		event := logger.lastEvent()
		if event.Outcome != audit.OutcomeFailure {
			t.Errorf("expected outcome %q, got %q", audit.OutcomeFailure, event.Outcome)
		}
	})

	t.Run("empty device ID", func(t *testing.T) {
		logger := newMockAuditLogger()
		builder, err := NewAttestationEventBuilder(logger)
		if err != nil {
			t.Fatalf("failed to create builder: %v", err)
		}
		ctx := context.Background()

		err = builder.LogQuoteVerification(ctx, "", true, nil)

		if err == nil {
			t.Error("expected error for empty device ID")
		}
		var emptyErr ErrEmptyDeviceID
		if !errors.As(err, &emptyErr) {
			t.Errorf("expected ErrEmptyDeviceID, got %T", err)
		}
	})

	t.Run("logger error", func(t *testing.T) {
		logger := newMockAuditLogger()
		expectedErr := errors.New("log failed")
		logger.setLogError(expectedErr)

		builder, err := NewAttestationEventBuilder(logger)
		if err != nil {
			t.Fatalf("failed to create builder: %v", err)
		}
		ctx := context.Background()

		err = builder.LogQuoteVerification(ctx, "device-123", true, nil)

		if err == nil {
			t.Error("expected error")
		}
		if err != expectedErr {
			t.Errorf("expected error %v, got %v", expectedErr, err)
		}
	})

	t.Run("nil details map", func(t *testing.T) {
		logger := newMockAuditLogger()
		builder, err := NewAttestationEventBuilder(logger)
		if err != nil {
			t.Fatalf("failed to create builder: %v", err)
		}
		ctx := context.Background()

		err = builder.LogQuoteVerification(ctx, "device-123", true, nil)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		event := logger.lastEvent()
		if event.Details["verification_type"] != "tpm_quote" {
			t.Error("expected verification_type to be set even with nil details")
		}
	})
}

func TestAttestationEventBuilder_LogPCRValidation(t *testing.T) {
	t.Run("success with no failed PCRs", func(t *testing.T) {
		logger := newMockAuditLogger()
		builder, err := NewAttestationEventBuilder(logger)
		if err != nil {
			t.Fatalf("failed to create builder: %v", err)
		}
		ctx := context.Background()

		deviceID := "device-456"
		failedPCRs := []int{}

		err = builder.LogPCRValidation(ctx, deviceID, true, failedPCRs)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		event := logger.lastEvent()

		if event.Action != ActionPCRValidation {
			t.Errorf("expected action %q, got %q", ActionPCRValidation, event.Action)
		}
		if event.Outcome != audit.OutcomeSuccess {
			t.Errorf("expected outcome %q, got %q", audit.OutcomeSuccess, event.Outcome)
		}
		if event.Details["verification_type"] != "pcr_validation" {
			t.Errorf("expected verification_type %q, got %q", "pcr_validation", event.Details["verification_type"])
		}
		if event.Details["pcr_count"] != 0 {
			t.Errorf("expected pcr_count 0, got %v", event.Details["pcr_count"])
		}
	})

	t.Run("failure with failed PCRs", func(t *testing.T) {
		logger := newMockAuditLogger()
		builder, err := NewAttestationEventBuilder(logger)
		if err != nil {
			t.Fatalf("failed to create builder: %v", err)
		}
		ctx := context.Background()

		deviceID := "device-456"
		failedPCRs := []int{0, 7, 14}

		err = builder.LogPCRValidation(ctx, deviceID, false, failedPCRs)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		event := logger.lastEvent()

		if event.Outcome != audit.OutcomeFailure {
			t.Errorf("expected outcome %q, got %q", audit.OutcomeFailure, event.Outcome)
		}
		if event.Details["pcr_count"] != 3 {
			t.Errorf("expected pcr_count 3, got %v", event.Details["pcr_count"])
		}

		failedPCRsValue, ok := event.Details["failed_pcrs"].([]int)
		if !ok {
			t.Errorf("expected failed_pcrs to be []int, got %T", event.Details["failed_pcrs"])
		} else {
			if len(failedPCRsValue) != 3 {
				t.Errorf("expected 3 failed PCRs, got %d", len(failedPCRsValue))
			}
		}
	})

	t.Run("empty device ID", func(t *testing.T) {
		logger := newMockAuditLogger()
		builder, err := NewAttestationEventBuilder(logger)
		if err != nil {
			t.Fatalf("failed to create builder: %v", err)
		}
		ctx := context.Background()

		err = builder.LogPCRValidation(ctx, "", true, nil)

		if err == nil {
			t.Error("expected error for empty device ID")
		}
		var emptyErr ErrEmptyDeviceID
		if !errors.As(err, &emptyErr) {
			t.Errorf("expected ErrEmptyDeviceID, got %T", err)
		}
	})

	t.Run("logger error", func(t *testing.T) {
		logger := newMockAuditLogger()
		expectedErr := errors.New("log failed")
		logger.setLogError(expectedErr)

		builder, err := NewAttestationEventBuilder(logger)
		if err != nil {
			t.Fatalf("failed to create builder: %v", err)
		}
		ctx := context.Background()

		err = builder.LogPCRValidation(ctx, "device-123", true, nil)

		if err == nil {
			t.Error("expected error")
		}
		if err != expectedErr {
			t.Errorf("expected error %v, got %v", expectedErr, err)
		}
	})
}

func TestAttestationEventBuilder_LogEventLogVerification(t *testing.T) {
	t.Run("success case", func(t *testing.T) {
		logger := newMockAuditLogger()
		builder, err := NewAttestationEventBuilder(logger)
		if err != nil {
			t.Fatalf("failed to create builder: %v", err)
		}
		ctx := context.Background()

		deviceID := "device-789"
		details := map[string]any{
			"event_count":   100,
			"replay_result": "matched",
		}

		err = builder.LogEventLogVerification(ctx, deviceID, true, details)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		event := logger.lastEvent()

		if event.Action != ActionEventLogVerification {
			t.Errorf("expected action %q, got %q", ActionEventLogVerification, event.Action)
		}
		if event.Outcome != audit.OutcomeSuccess {
			t.Errorf("expected outcome %q, got %q", audit.OutcomeSuccess, event.Outcome)
		}
		if event.Details["verification_type"] != "event_log" {
			t.Errorf("expected verification_type %q, got %q", "event_log", event.Details["verification_type"])
		}
		if event.Details["event_count"] != 100 {
			t.Errorf("expected event_count 100, got %v", event.Details["event_count"])
		}
	})

	t.Run("failure case", func(t *testing.T) {
		logger := newMockAuditLogger()
		builder, err := NewAttestationEventBuilder(logger)
		if err != nil {
			t.Fatalf("failed to create builder: %v", err)
		}
		ctx := context.Background()

		details := map[string]any{
			"error": "replay mismatch at PCR 7",
		}

		err = builder.LogEventLogVerification(ctx, "device-789", false, details)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		event := logger.lastEvent()
		if event.Outcome != audit.OutcomeFailure {
			t.Errorf("expected outcome %q, got %q", audit.OutcomeFailure, event.Outcome)
		}
	})

	t.Run("empty device ID", func(t *testing.T) {
		logger := newMockAuditLogger()
		builder, err := NewAttestationEventBuilder(logger)
		if err != nil {
			t.Fatalf("failed to create builder: %v", err)
		}
		ctx := context.Background()

		err = builder.LogEventLogVerification(ctx, "", true, nil)

		if err == nil {
			t.Error("expected error for empty device ID")
		}
		var emptyErr ErrEmptyDeviceID
		if !errors.As(err, &emptyErr) {
			t.Errorf("expected ErrEmptyDeviceID, got %T", err)
		}
	})

	t.Run("logger error", func(t *testing.T) {
		logger := newMockAuditLogger()
		expectedErr := errors.New("log failed")
		logger.setLogError(expectedErr)

		builder, err := NewAttestationEventBuilder(logger)
		if err != nil {
			t.Fatalf("failed to create builder: %v", err)
		}
		ctx := context.Background()

		err = builder.LogEventLogVerification(ctx, "device-123", true, nil)

		if err == nil {
			t.Error("expected error")
		}
		if err != expectedErr {
			t.Errorf("expected error %v, got %v", expectedErr, err)
		}
	})
}

func TestAttestationEventBuilder_LogAttestationComplete(t *testing.T) {
	t.Run("verified status", func(t *testing.T) {
		logger := newMockAuditLogger()
		builder, err := NewAttestationEventBuilder(logger)
		if err != nil {
			t.Fatalf("failed to create builder: %v", err)
		}
		ctx := context.Background()

		deviceID := "device-complete"

		err = builder.LogAttestationComplete(ctx, deviceID, manifest.VerificationStatusVerified)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		event := logger.lastEvent()

		if event.Action != ActionAttestationComplete {
			t.Errorf("expected action %q, got %q", ActionAttestationComplete, event.Action)
		}
		if event.Outcome != audit.OutcomeSuccess {
			t.Errorf("expected outcome %q, got %q", audit.OutcomeSuccess, event.Outcome)
		}
		if event.Details["verification_status"] != "verified" {
			t.Errorf("expected verification_status %q, got %q", "verified", event.Details["verification_status"])
		}
	})

	t.Run("failed status", func(t *testing.T) {
		logger := newMockAuditLogger()
		builder, err := NewAttestationEventBuilder(logger)
		if err != nil {
			t.Fatalf("failed to create builder: %v", err)
		}
		ctx := context.Background()

		err = builder.LogAttestationComplete(ctx, "device-complete", manifest.VerificationStatusFailed)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		event := logger.lastEvent()
		if event.Outcome != audit.OutcomeFailure {
			t.Errorf("expected outcome %q, got %q", audit.OutcomeFailure, event.Outcome)
		}
		if event.Details["verification_status"] != "failed" {
			t.Errorf("expected verification_status %q, got %q", "failed", event.Details["verification_status"])
		}
	})

	t.Run("pending status", func(t *testing.T) {
		logger := newMockAuditLogger()
		builder, err := NewAttestationEventBuilder(logger)
		if err != nil {
			t.Fatalf("failed to create builder: %v", err)
		}
		ctx := context.Background()

		err = builder.LogAttestationComplete(ctx, "device-complete", manifest.VerificationStatusPending)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		event := logger.lastEvent()
		if event.Outcome != audit.OutcomeSuccess {
			t.Errorf("expected outcome %q for pending, got %q", audit.OutcomeSuccess, event.Outcome)
		}
	})

	t.Run("unknown status", func(t *testing.T) {
		logger := newMockAuditLogger()
		builder, err := NewAttestationEventBuilder(logger)
		if err != nil {
			t.Fatalf("failed to create builder: %v", err)
		}
		ctx := context.Background()

		err = builder.LogAttestationComplete(ctx, "device-complete", manifest.VerificationStatusUnknown)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		event := logger.lastEvent()
		if event.Outcome != audit.OutcomeError {
			t.Errorf("expected outcome %q for unknown, got %q", audit.OutcomeError, event.Outcome)
		}
	})

	t.Run("empty device ID", func(t *testing.T) {
		logger := newMockAuditLogger()
		builder, err := NewAttestationEventBuilder(logger)
		if err != nil {
			t.Fatalf("failed to create builder: %v", err)
		}
		ctx := context.Background()

		err = builder.LogAttestationComplete(ctx, "", manifest.VerificationStatusVerified)

		if err == nil {
			t.Error("expected error for empty device ID")
		}
		var emptyErr ErrEmptyDeviceID
		if !errors.As(err, &emptyErr) {
			t.Errorf("expected ErrEmptyDeviceID, got %T", err)
		}
	})

	t.Run("logger error", func(t *testing.T) {
		logger := newMockAuditLogger()
		expectedErr := errors.New("log failed")
		logger.setLogError(expectedErr)

		builder, err := NewAttestationEventBuilder(logger)
		if err != nil {
			t.Fatalf("failed to create builder: %v", err)
		}
		ctx := context.Background()

		err = builder.LogAttestationComplete(ctx, "device-123", manifest.VerificationStatusVerified)

		if err == nil {
			t.Error("expected error")
		}
		if err != expectedErr {
			t.Errorf("expected error %v, got %v", expectedErr, err)
		}
	})
}

func TestAttestationEventBuilder_LogQuoteVerificationWithPCRs(t *testing.T) {
	t.Run("success with PCR values", func(t *testing.T) {
		logger := newMockAuditLogger()
		builder, err := NewAttestationEventBuilder(logger)
		if err != nil {
			t.Fatalf("failed to create builder: %v", err)
		}
		ctx := context.Background()

		deviceID := "device-pcr"
		pcrs := []manifest.PCRValue{
			{Index: 0, Value: []byte{0x01, 0x02, 0x03}, Algorithm: manifest.HashAlgorithmSHA256},
			{Index: 7, Value: []byte{0x04, 0x05, 0x06}, Algorithm: manifest.HashAlgorithmSHA256},
		}
		details := map[string]any{
			"nonce": "test-nonce",
		}

		err = builder.LogQuoteVerificationWithPCRs(ctx, deviceID, true, pcrs, details)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		event := logger.lastEvent()

		if event.Action != ActionQuoteVerification {
			t.Errorf("expected action %q, got %q", ActionQuoteVerification, event.Action)
		}
		if event.Outcome != audit.OutcomeSuccess {
			t.Errorf("expected outcome %q, got %q", audit.OutcomeSuccess, event.Outcome)
		}

		pcrValues, ok := event.Details["pcr_values"].([]map[string]any)
		if !ok {
			t.Errorf("expected pcr_values to be []map[string]any, got %T", event.Details["pcr_values"])
		} else {
			if len(pcrValues) != 2 {
				t.Errorf("expected 2 PCR values, got %d", len(pcrValues))
			}
			if pcrValues[0]["index"] != 0 {
				t.Errorf("expected first PCR index 0, got %v", pcrValues[0]["index"])
			}
			if pcrValues[0]["algorithm"] != "sha256" {
				t.Errorf("expected algorithm sha256, got %v", pcrValues[0]["algorithm"])
			}
		}
	})

	t.Run("failure case", func(t *testing.T) {
		logger := newMockAuditLogger()
		builder, err := NewAttestationEventBuilder(logger)
		if err != nil {
			t.Fatalf("failed to create builder: %v", err)
		}
		ctx := context.Background()

		err = builder.LogQuoteVerificationWithPCRs(ctx, "device-pcr", false, nil, nil)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		event := logger.lastEvent()
		if event.Outcome != audit.OutcomeFailure {
			t.Errorf("expected outcome %q, got %q", audit.OutcomeFailure, event.Outcome)
		}
	})

	t.Run("empty device ID", func(t *testing.T) {
		logger := newMockAuditLogger()
		builder, err := NewAttestationEventBuilder(logger)
		if err != nil {
			t.Fatalf("failed to create builder: %v", err)
		}
		ctx := context.Background()

		err = builder.LogQuoteVerificationWithPCRs(ctx, "", true, nil, nil)

		if err == nil {
			t.Error("expected error for empty device ID")
		}
		var emptyErr ErrEmptyDeviceID
		if !errors.As(err, &emptyErr) {
			t.Errorf("expected ErrEmptyDeviceID, got %T", err)
		}
	})

	t.Run("logger error", func(t *testing.T) {
		logger := newMockAuditLogger()
		expectedErr := errors.New("log failed")
		logger.setLogError(expectedErr)

		builder, err := NewAttestationEventBuilder(logger)
		if err != nil {
			t.Fatalf("failed to create builder: %v", err)
		}
		ctx := context.Background()

		err = builder.LogQuoteVerificationWithPCRs(ctx, "device-123", true, nil, nil)

		if err == nil {
			t.Error("expected error")
		}
		if err != expectedErr {
			t.Errorf("expected error %v, got %v", expectedErr, err)
		}
	})
}

func TestAttestationEventBuilder_LogAttestationCompleteWithDetails(t *testing.T) {
	t.Run("success with all details", func(t *testing.T) {
		logger := newMockAuditLogger()
		builder, err := NewAttestationEventBuilder(logger)
		if err != nil {
			t.Fatalf("failed to create builder: %v", err)
		}
		ctx := context.Background()

		deviceID := "device-full"
		result := &manifest.VerificationResult{
			Status:                     manifest.VerificationStatusVerified,
			SignatureValid:             true,
			MerkleRootValid:            true,
			NonceValid:                 true,
			TimestampValid:             true,
			HostAttestationValid:       true,
			VMAttestationsValid:        true,
			ContainerAttestationsValid: true,
			VerifiedAt:                 time.Now(),
		}

		err = builder.LogAttestationCompleteWithDetails(ctx, deviceID, result)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		event := logger.lastEvent()

		if event.Action != ActionAttestationComplete {
			t.Errorf("expected action %q, got %q", ActionAttestationComplete, event.Action)
		}
		if event.Outcome != audit.OutcomeSuccess {
			t.Errorf("expected outcome %q, got %q", audit.OutcomeSuccess, event.Outcome)
		}
		if event.Details["signature_valid"] != true {
			t.Error("expected signature_valid to be true")
		}
		if event.Details["merkle_root_valid"] != true {
			t.Error("expected merkle_root_valid to be true")
		}
		if event.Details["nonce_valid"] != true {
			t.Error("expected nonce_valid to be true")
		}
		if event.Details["timestamp_valid"] != true {
			t.Error("expected timestamp_valid to be true")
		}
		if event.Details["host_attestation_valid"] != true {
			t.Error("expected host_attestation_valid to be true")
		}
	})

	t.Run("failure with errors", func(t *testing.T) {
		logger := newMockAuditLogger()
		builder, err := NewAttestationEventBuilder(logger)
		if err != nil {
			t.Fatalf("failed to create builder: %v", err)
		}
		ctx := context.Background()

		result := &manifest.VerificationResult{
			Status:               manifest.VerificationStatusFailed,
			SignatureValid:       false,
			MerkleRootValid:      true,
			NonceValid:           true,
			TimestampValid:       true,
			HostAttestationValid: false,
			Errors:               []string{"signature verification failed", "host attestation invalid"},
			VMErrors:             map[string]string{"vm-1": "PCR mismatch"},
			ContainerErrors:      map[string]string{"container-1": "image digest mismatch"},
		}

		err = builder.LogAttestationCompleteWithDetails(ctx, "device-full", result)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		event := logger.lastEvent()

		if event.Outcome != audit.OutcomeFailure {
			t.Errorf("expected outcome %q, got %q", audit.OutcomeFailure, event.Outcome)
		}
		if event.Details["signature_valid"] != false {
			t.Error("expected signature_valid to be false")
		}

		errors, ok := event.Details["errors"].([]string)
		if !ok {
			t.Errorf("expected errors to be []string, got %T", event.Details["errors"])
		} else if len(errors) != 2 {
			t.Errorf("expected 2 errors, got %d", len(errors))
		}

		vmErrors, ok := event.Details["vm_errors"].(map[string]string)
		if !ok {
			t.Errorf("expected vm_errors to be map[string]string, got %T", event.Details["vm_errors"])
		} else if len(vmErrors) != 1 {
			t.Errorf("expected 1 VM error, got %d", len(vmErrors))
		}

		containerErrors, ok := event.Details["container_errors"].(map[string]string)
		if !ok {
			t.Errorf("expected container_errors to be map[string]string, got %T", event.Details["container_errors"])
		} else if len(containerErrors) != 1 {
			t.Errorf("expected 1 container error, got %d", len(containerErrors))
		}
	})

	t.Run("empty device ID", func(t *testing.T) {
		logger := newMockAuditLogger()
		builder, err := NewAttestationEventBuilder(logger)
		if err != nil {
			t.Fatalf("failed to create builder: %v", err)
		}
		ctx := context.Background()

		result := &manifest.VerificationResult{
			Status: manifest.VerificationStatusVerified,
		}

		err = builder.LogAttestationCompleteWithDetails(ctx, "", result)

		if err == nil {
			t.Error("expected error for empty device ID")
		}
		var emptyErr ErrEmptyDeviceID
		if !errors.As(err, &emptyErr) {
			t.Errorf("expected ErrEmptyDeviceID, got %T", err)
		}
	})

	t.Run("nil verification result", func(t *testing.T) {
		logger := newMockAuditLogger()
		builder, err := NewAttestationEventBuilder(logger)
		if err != nil {
			t.Fatalf("failed to create builder: %v", err)
		}
		ctx := context.Background()

		err = builder.LogAttestationCompleteWithDetails(ctx, "device-123", nil)

		if err == nil {
			t.Error("expected error for nil verification result")
		}
		var nilErr ErrNilVerificationResult
		if !errors.As(err, &nilErr) {
			t.Errorf("expected ErrNilVerificationResult, got %T", err)
		}
	})

	t.Run("logger error", func(t *testing.T) {
		logger := newMockAuditLogger()
		expectedErr := errors.New("log failed")
		logger.setLogError(expectedErr)

		builder, err := NewAttestationEventBuilder(logger)
		if err != nil {
			t.Fatalf("failed to create builder: %v", err)
		}
		ctx := context.Background()

		result := &manifest.VerificationResult{
			Status: manifest.VerificationStatusVerified,
		}

		err = builder.LogAttestationCompleteWithDetails(ctx, "device-123", result)

		if err == nil {
			t.Error("expected error")
		}
		if err != expectedErr {
			t.Errorf("expected error %v, got %v", expectedErr, err)
		}
	})
}

func TestAttestationEventBuilder_EventValidation(t *testing.T) {
	t.Run("events pass validation", func(t *testing.T) {
		logger := newMockAuditLogger()
		builder, err := NewAttestationEventBuilder(logger)
		if err != nil {
			t.Fatalf("failed to create builder: %v", err)
		}
		ctx := context.Background()

		// Log all event types
		if err := builder.LogQuoteVerification(ctx, "device-1", true, nil); err != nil {
			t.Errorf("LogQuoteVerification failed: %v", err)
		}
		if err := builder.LogPCRValidation(ctx, "device-2", true, nil); err != nil {
			t.Errorf("LogPCRValidation failed: %v", err)
		}
		if err := builder.LogEventLogVerification(ctx, "device-3", true, nil); err != nil {
			t.Errorf("LogEventLogVerification failed: %v", err)
		}
		if err := builder.LogAttestationComplete(ctx, "device-4", manifest.VerificationStatusVerified); err != nil {
			t.Errorf("LogAttestationComplete failed: %v", err)
		}

		// Verify all events would pass validation
		for i, event := range logger.loggedEvents {
			if err := event.Validate(); err != nil {
				t.Errorf("event %d failed validation: %v", i, err)
			}
		}
	})
}

func TestAttestationEventBuilder_UniqueIDs(t *testing.T) {
	t.Run("each event has unique ID", func(t *testing.T) {
		logger := newMockAuditLogger()
		builder, err := NewAttestationEventBuilder(logger)
		if err != nil {
			t.Fatalf("failed to create builder: %v", err)
		}
		ctx := context.Background()

		// Log multiple events
		for i := 0; i < 10; i++ {
			if err := builder.LogQuoteVerification(ctx, "device", true, nil); err != nil {
				t.Fatalf("LogQuoteVerification failed: %v", err)
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

func TestAttestationConstants(t *testing.T) {
	t.Run("action constants are defined", func(t *testing.T) {
		if ActionQuoteVerification == "" {
			t.Error("ActionQuoteVerification should not be empty")
		}
		if ActionPCRValidation == "" {
			t.Error("ActionPCRValidation should not be empty")
		}
		if ActionEventLogVerification == "" {
			t.Error("ActionEventLogVerification should not be empty")
		}
		if ActionAttestationComplete == "" {
			t.Error("ActionAttestationComplete should not be empty")
		}
	})

	t.Run("resource type constant is defined", func(t *testing.T) {
		if ResourceTypeAttestation == "" {
			t.Error("ResourceTypeAttestation should not be empty")
		}
	})

	t.Run("action constants have expected values", func(t *testing.T) {
		if ActionQuoteVerification != "quote_verification" {
			t.Errorf("expected ActionQuoteVerification to be 'quote_verification', got %q", ActionQuoteVerification)
		}
		if ActionPCRValidation != "pcr_validation" {
			t.Errorf("expected ActionPCRValidation to be 'pcr_validation', got %q", ActionPCRValidation)
		}
		if ActionEventLogVerification != "eventlog_verification" {
			t.Errorf("expected ActionEventLogVerification to be 'eventlog_verification', got %q", ActionEventLogVerification)
		}
		if ActionAttestationComplete != "attestation_complete" {
			t.Errorf("expected ActionAttestationComplete to be 'attestation_complete', got %q", ActionAttestationComplete)
		}
	})
}

func TestStatusToOutcome(t *testing.T) {
	tests := []struct {
		name     string
		status   manifest.VerificationStatus
		expected audit.Outcome
	}{
		{
			name:     "verified maps to success",
			status:   manifest.VerificationStatusVerified,
			expected: audit.OutcomeSuccess,
		},
		{
			name:     "failed maps to failure",
			status:   manifest.VerificationStatusFailed,
			expected: audit.OutcomeFailure,
		},
		{
			name:     "pending maps to success",
			status:   manifest.VerificationStatusPending,
			expected: audit.OutcomeSuccess,
		},
		{
			name:     "unknown maps to error",
			status:   manifest.VerificationStatusUnknown,
			expected: audit.OutcomeError,
		},
		{
			name:     "invalid status maps to error",
			status:   manifest.VerificationStatus("invalid"),
			expected: audit.OutcomeError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := statusToOutcome(tt.status)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestFormatPCRValues(t *testing.T) {
	t.Run("formats PCR values correctly", func(t *testing.T) {
		pcrs := []manifest.PCRValue{
			{Index: 0, Value: []byte{0xab, 0xcd}, Algorithm: manifest.HashAlgorithmSHA256},
			{Index: 7, Value: []byte{0x12, 0x34}, Algorithm: manifest.HashAlgorithmSHA384},
		}

		result := formatPCRValues(pcrs)

		if len(result) != 2 {
			t.Fatalf("expected 2 results, got %d", len(result))
		}

		if result[0]["index"] != 0 {
			t.Errorf("expected index 0, got %v", result[0]["index"])
		}
		if result[0]["algorithm"] != "sha256" {
			t.Errorf("expected algorithm sha256, got %v", result[0]["algorithm"])
		}
		if result[0]["value"] != "abcd" {
			t.Errorf("expected value abcd, got %v", result[0]["value"])
		}

		if result[1]["index"] != 7 {
			t.Errorf("expected index 7, got %v", result[1]["index"])
		}
		if result[1]["algorithm"] != "sha384" {
			t.Errorf("expected algorithm sha384, got %v", result[1]["algorithm"])
		}
		if result[1]["value"] != "1234" {
			t.Errorf("expected value 1234, got %v", result[1]["value"])
		}
	})

	t.Run("handles empty slice", func(t *testing.T) {
		result := formatPCRValues(nil)
		if len(result) != 0 {
			t.Errorf("expected empty result, got %d items", len(result))
		}
	})

	t.Run("handles empty PCR value", func(t *testing.T) {
		pcrs := []manifest.PCRValue{
			{Index: 0, Value: []byte{}, Algorithm: manifest.HashAlgorithmSHA256},
		}

		result := formatPCRValues(pcrs)

		if len(result) != 1 {
			t.Fatalf("expected 1 result, got %d", len(result))
		}
		if result[0]["value"] != "" {
			t.Errorf("expected empty value, got %v", result[0]["value"])
		}
	})
}

func TestAttestationErrors(t *testing.T) {
	t.Run("ErrEmptyDeviceID message", func(t *testing.T) {
		err := ErrEmptyDeviceID{}
		expected := "device ID cannot be empty"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("ErrNilVerificationResult message", func(t *testing.T) {
		err := ErrNilVerificationResult{}
		expected := "verification result cannot be nil"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})
}
