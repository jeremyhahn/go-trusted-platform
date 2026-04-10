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
	"encoding/hex"
	"time"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/security/audit"
)

// Attestation action constants.
const (
	ActionQuoteVerification    = "quote_verification"
	ActionPCRValidation        = "pcr_validation"
	ActionEventLogVerification = "eventlog_verification"
	ActionAttestationComplete  = "attestation_complete"
)

// ResourceTypeAttestation is the resource type for attestation events.
const ResourceTypeAttestation = "attestation"

// AttestationEventBuilder creates audit events for attestation operations.
type AttestationEventBuilder struct {
	logger audit.AuditLogger
}

// NewAttestationEventBuilder creates a new builder with the given audit logger.
func NewAttestationEventBuilder(logger audit.AuditLogger) (*AttestationEventBuilder, error) {
	if logger == nil {
		return nil, ErrNilLogger{}
	}
	return &AttestationEventBuilder{
		logger: logger,
	}, nil
}

// LogQuoteVerification logs TPM quote verification result.
func (b *AttestationEventBuilder) LogQuoteVerification(
	ctx context.Context,
	deviceID string,
	success bool,
	details map[string]any,
) error {
	if deviceID == "" {
		return ErrEmptyDeviceID{}
	}

	outcome := audit.OutcomeSuccess
	if !success {
		outcome = audit.OutcomeFailure
	}

	eventDetails := make(map[string]any)
	for k, v := range details {
		eventDetails[k] = v
	}
	eventDetails["verification_type"] = "tpm_quote"

	event := audit.AuditEvent{
		ID:           uuid.New().String(),
		Timestamp:    time.Now().UTC(),
		Actor:        deviceID,
		Action:       ActionQuoteVerification,
		Resource:     deviceID,
		ResourceType: ResourceTypeAttestation,
		Outcome:      outcome,
		Details:      eventDetails,
	}

	return b.logger.Log(ctx, event)
}

// LogPCRValidation logs PCR bank validation result.
func (b *AttestationEventBuilder) LogPCRValidation(
	ctx context.Context,
	deviceID string,
	success bool,
	failedPCRs []int,
) error {
	if deviceID == "" {
		return ErrEmptyDeviceID{}
	}

	outcome := audit.OutcomeSuccess
	if !success {
		outcome = audit.OutcomeFailure
	}

	eventDetails := make(map[string]any)
	eventDetails["verification_type"] = "pcr_validation"
	eventDetails["failed_pcrs"] = failedPCRs
	eventDetails["pcr_count"] = len(failedPCRs)

	event := audit.AuditEvent{
		ID:           uuid.New().String(),
		Timestamp:    time.Now().UTC(),
		Actor:        deviceID,
		Action:       ActionPCRValidation,
		Resource:     deviceID,
		ResourceType: ResourceTypeAttestation,
		Outcome:      outcome,
		Details:      eventDetails,
	}

	return b.logger.Log(ctx, event)
}

// LogEventLogVerification logs event log verification result.
func (b *AttestationEventBuilder) LogEventLogVerification(
	ctx context.Context,
	deviceID string,
	success bool,
	details map[string]any,
) error {
	if deviceID == "" {
		return ErrEmptyDeviceID{}
	}

	outcome := audit.OutcomeSuccess
	if !success {
		outcome = audit.OutcomeFailure
	}

	eventDetails := make(map[string]any)
	for k, v := range details {
		eventDetails[k] = v
	}
	eventDetails["verification_type"] = "event_log"

	event := audit.AuditEvent{
		ID:           uuid.New().String(),
		Timestamp:    time.Now().UTC(),
		Actor:        deviceID,
		Action:       ActionEventLogVerification,
		Resource:     deviceID,
		ResourceType: ResourceTypeAttestation,
		Outcome:      outcome,
		Details:      eventDetails,
	}

	return b.logger.Log(ctx, event)
}

// LogAttestationComplete logs full attestation verification completion.
func (b *AttestationEventBuilder) LogAttestationComplete(
	ctx context.Context,
	deviceID string,
	result manifest.VerificationStatus,
) error {
	if deviceID == "" {
		return ErrEmptyDeviceID{}
	}

	outcome := statusToOutcome(result)

	eventDetails := make(map[string]any)
	eventDetails["verification_type"] = "attestation_complete"
	eventDetails["verification_status"] = result.String()

	event := audit.AuditEvent{
		ID:           uuid.New().String(),
		Timestamp:    time.Now().UTC(),
		Actor:        deviceID,
		Action:       ActionAttestationComplete,
		Resource:     deviceID,
		ResourceType: ResourceTypeAttestation,
		Outcome:      outcome,
		Details:      eventDetails,
	}

	return b.logger.Log(ctx, event)
}

// LogQuoteVerificationWithPCRs logs TPM quote verification with PCR values included.
func (b *AttestationEventBuilder) LogQuoteVerificationWithPCRs(
	ctx context.Context,
	deviceID string,
	success bool,
	pcrs []manifest.PCRValue,
	details map[string]any,
) error {
	if deviceID == "" {
		return ErrEmptyDeviceID{}
	}

	outcome := audit.OutcomeSuccess
	if !success {
		outcome = audit.OutcomeFailure
	}

	eventDetails := make(map[string]any)
	for k, v := range details {
		eventDetails[k] = v
	}
	eventDetails["verification_type"] = "tpm_quote"
	eventDetails["pcr_values"] = formatPCRValues(pcrs)

	event := audit.AuditEvent{
		ID:           uuid.New().String(),
		Timestamp:    time.Now().UTC(),
		Actor:        deviceID,
		Action:       ActionQuoteVerification,
		Resource:     deviceID,
		ResourceType: ResourceTypeAttestation,
		Outcome:      outcome,
		Details:      eventDetails,
	}

	return b.logger.Log(ctx, event)
}

// LogAttestationCompleteWithDetails logs full attestation verification with detailed result.
func (b *AttestationEventBuilder) LogAttestationCompleteWithDetails(
	ctx context.Context,
	deviceID string,
	verificationResult *manifest.VerificationResult,
) error {
	if deviceID == "" {
		return ErrEmptyDeviceID{}
	}

	if verificationResult == nil {
		return ErrNilVerificationResult{}
	}

	outcome := statusToOutcome(verificationResult.Status)

	eventDetails := make(map[string]any)
	eventDetails["verification_type"] = "attestation_complete"
	eventDetails["verification_status"] = verificationResult.Status.String()
	eventDetails["signature_valid"] = verificationResult.SignatureValid
	eventDetails["merkle_root_valid"] = verificationResult.MerkleRootValid
	eventDetails["nonce_valid"] = verificationResult.NonceValid
	eventDetails["timestamp_valid"] = verificationResult.TimestampValid
	eventDetails["host_attestation_valid"] = verificationResult.HostAttestationValid
	eventDetails["vm_attestations_valid"] = verificationResult.VMAttestationsValid
	eventDetails["container_attestations_valid"] = verificationResult.ContainerAttestationsValid

	if len(verificationResult.Errors) > 0 {
		eventDetails["errors"] = verificationResult.Errors
	}

	if len(verificationResult.VMErrors) > 0 {
		eventDetails["vm_errors"] = verificationResult.VMErrors
	}

	if len(verificationResult.ContainerErrors) > 0 {
		eventDetails["container_errors"] = verificationResult.ContainerErrors
	}

	event := audit.AuditEvent{
		ID:           uuid.New().String(),
		Timestamp:    time.Now().UTC(),
		Actor:        deviceID,
		Action:       ActionAttestationComplete,
		Resource:     deviceID,
		ResourceType: ResourceTypeAttestation,
		Outcome:      outcome,
		Details:      eventDetails,
	}

	return b.logger.Log(ctx, event)
}

// statusToOutcome converts a VerificationStatus to an audit Outcome.
func statusToOutcome(status manifest.VerificationStatus) audit.Outcome {
	switch status {
	case manifest.VerificationStatusVerified:
		return audit.OutcomeSuccess
	case manifest.VerificationStatusFailed:
		return audit.OutcomeFailure
	case manifest.VerificationStatusPending:
		return audit.OutcomeSuccess
	default:
		return audit.OutcomeError
	}
}

// formatPCRValues formats PCR values for audit logging.
func formatPCRValues(pcrs []manifest.PCRValue) []map[string]any {
	result := make([]map[string]any, 0, len(pcrs))
	for _, pcr := range pcrs {
		pcrMap := map[string]any{
			"index":     pcr.Index,
			"algorithm": pcr.Algorithm.String(),
			"value":     hex.EncodeToString(pcr.Value),
		}
		result = append(result, pcrMap)
	}
	return result
}
