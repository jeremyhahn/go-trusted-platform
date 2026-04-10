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
	"time"

	"github.com/google/uuid"
	"github.com/jeremyhahn/go-trusted-platform/pkg/security/audit"
)

// Enrollment action constants define the possible actions for device enrollment events.
const (
	ActionDeviceCreated       = "device_created"
	ActionEnrollmentStarted   = "enrollment_started"
	ActionEnrollmentCompleted = "enrollment_completed"
	ActionEnrollmentFailed    = "enrollment_failed"
)

// ResourceTypeDeviceEnrollment is the resource type for device enrollment events.
const ResourceTypeDeviceEnrollment = "device_enrollment"

// Detail key constants for enrollment events.
const (
	DetailKeyTenantID     = "tenant_id"
	DetailKeyProfileID    = "profile_id"
	DetailKeyCSRHash      = "csr_hash"
	DetailKeyCertSerial   = "cert_serial"
	DetailKeyFailedReason = "reason"
)

// ActorSystem is used when no specific actor initiated the action.
const ActorSystem = "system"

// EnrollmentEventBuilder creates audit events for device enrollment operations.
type EnrollmentEventBuilder struct {
	logger audit.AuditLogger
}

// NewEnrollmentEventBuilder creates a new builder with the given audit logger.
func NewEnrollmentEventBuilder(logger audit.AuditLogger) *EnrollmentEventBuilder {
	if logger == nil {
		return nil
	}
	return &EnrollmentEventBuilder{
		logger: logger,
	}
}

// LogDeviceCreated logs a device creation event.
func (b *EnrollmentEventBuilder) LogDeviceCreated(
	ctx context.Context,
	deviceID string,
	tenantID string,
	profileID uint64,
) error {
	if b == nil {
		return ErrNilBuilder{}
	}

	event := audit.AuditEvent{
		ID:           uuid.New().String(),
		Timestamp:    time.Now(),
		Actor:        ActorSystem,
		Action:       ActionDeviceCreated,
		Resource:     deviceID,
		ResourceType: ResourceTypeDeviceEnrollment,
		Outcome:      audit.OutcomeSuccess,
		Details: map[string]any{
			DetailKeyTenantID:  tenantID,
			DetailKeyProfileID: profileID,
		},
	}

	return b.logger.Log(ctx, event)
}

// LogEnrollmentStarted logs enrollment initiation with CSR hash.
func (b *EnrollmentEventBuilder) LogEnrollmentStarted(
	ctx context.Context,
	deviceID string,
	tenantID string,
	csrHash string,
) error {
	if b == nil {
		return ErrNilBuilder{}
	}

	event := audit.AuditEvent{
		ID:           uuid.New().String(),
		Timestamp:    time.Now(),
		Actor:        deviceID,
		Action:       ActionEnrollmentStarted,
		Resource:     deviceID,
		ResourceType: ResourceTypeDeviceEnrollment,
		Outcome:      audit.OutcomeSuccess,
		Details: map[string]any{
			DetailKeyTenantID: tenantID,
			DetailKeyCSRHash:  csrHash,
		},
	}

	return b.logger.Log(ctx, event)
}

// LogEnrollmentCompleted logs successful enrollment completion.
func (b *EnrollmentEventBuilder) LogEnrollmentCompleted(
	ctx context.Context,
	deviceID string,
	tenantID string,
	certSerial string,
) error {
	if b == nil {
		return ErrNilBuilder{}
	}

	event := audit.AuditEvent{
		ID:           uuid.New().String(),
		Timestamp:    time.Now(),
		Actor:        deviceID,
		Action:       ActionEnrollmentCompleted,
		Resource:     deviceID,
		ResourceType: ResourceTypeDeviceEnrollment,
		Outcome:      audit.OutcomeSuccess,
		Details: map[string]any{
			DetailKeyTenantID:   tenantID,
			DetailKeyCertSerial: certSerial,
		},
	}

	return b.logger.Log(ctx, event)
}

// LogEnrollmentFailed logs enrollment failure.
func (b *EnrollmentEventBuilder) LogEnrollmentFailed(
	ctx context.Context,
	deviceID string,
	tenantID string,
	reason string,
) error {
	if b == nil {
		return ErrNilBuilder{}
	}

	event := audit.AuditEvent{
		ID:           uuid.New().String(),
		Timestamp:    time.Now(),
		Actor:        deviceID,
		Action:       ActionEnrollmentFailed,
		Resource:     deviceID,
		ResourceType: ResourceTypeDeviceEnrollment,
		Outcome:      audit.OutcomeFailure,
		Details: map[string]any{
			DetailKeyTenantID:     tenantID,
			DetailKeyFailedReason: reason,
		},
	}

	return b.logger.Log(ctx, event)
}
