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

package cluster

import (
	"fmt"
	"time"
)

// ErrCertificateNotFound indicates that a requested certificate does not exist.
type ErrCertificateNotFound struct {
	SerialNumber string
	TenantID     string
}

// Error implements the error interface.
func (e ErrCertificateNotFound) Error() string {
	if e.TenantID != "" {
		return fmt.Sprintf("cluster: certificate not found: serial=%s tenant=%s", e.SerialNumber, e.TenantID)
	}
	return fmt.Sprintf("cluster: certificate not found: serial=%s", e.SerialNumber)
}

// ErrCertificateAlreadyExists indicates that a certificate with the given serial already exists.
type ErrCertificateAlreadyExists struct {
	SerialNumber string
	TenantID     string
}

// Error implements the error interface.
func (e ErrCertificateAlreadyExists) Error() string {
	if e.TenantID != "" {
		return fmt.Sprintf("cluster: certificate already exists: serial=%s tenant=%s", e.SerialNumber, e.TenantID)
	}
	return fmt.Sprintf("cluster: certificate already exists: serial=%s", e.SerialNumber)
}

// ErrCertificateAlreadyRevoked indicates that a certificate is already revoked.
type ErrCertificateAlreadyRevoked struct {
	SerialNumber string
	RevokedAt    string
}

// Error implements the error interface.
func (e ErrCertificateAlreadyRevoked) Error() string {
	return fmt.Sprintf("cluster: certificate already revoked: serial=%s revoked_at=%s", e.SerialNumber, e.RevokedAt)
}

// ErrInvalidCertificate indicates that the certificate data is invalid or malformed.
type ErrInvalidCertificate struct {
	Reason string
	Cause  error
}

// Error implements the error interface.
func (e ErrInvalidCertificate) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("cluster: invalid certificate: %s: %v", e.Reason, e.Cause)
	}
	return fmt.Sprintf("cluster: invalid certificate: %s", e.Reason)
}

// Unwrap returns the underlying cause.
func (e ErrInvalidCertificate) Unwrap() error {
	return e.Cause
}

// ErrCRLNotFound indicates that a requested CRL does not exist.
type ErrCRLNotFound struct {
	CRLID    string
	TenantID string
}

// Error implements the error interface.
func (e ErrCRLNotFound) Error() string {
	if e.TenantID != "" {
		return fmt.Sprintf("cluster: CRL not found: id=%s tenant=%s", e.CRLID, e.TenantID)
	}
	return fmt.Sprintf("cluster: CRL not found: id=%s", e.CRLID)
}

// ErrInvalidCRL indicates that the CRL data is invalid or malformed.
type ErrInvalidCRL struct {
	Reason string
	Cause  error
}

// Error implements the error interface.
func (e ErrInvalidCRL) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("cluster: invalid CRL: %s: %v", e.Reason, e.Cause)
	}
	return fmt.Sprintf("cluster: invalid CRL: %s", e.Reason)
}

// Unwrap returns the underlying cause.
func (e ErrInvalidCRL) Unwrap() error {
	return e.Cause
}

// ErrACMEAccountNotFound indicates that a requested ACME account does not exist.
type ErrACMEAccountNotFound struct {
	AccountID string
	TenantID  string
}

// Error implements the error interface.
func (e ErrACMEAccountNotFound) Error() string {
	if e.TenantID != "" {
		return fmt.Sprintf("cluster: ACME account not found: id=%s tenant=%s", e.AccountID, e.TenantID)
	}
	return fmt.Sprintf("cluster: ACME account not found: id=%s", e.AccountID)
}

// ErrACMEAccountAlreadyExists indicates that an ACME account with the given ID already exists.
type ErrACMEAccountAlreadyExists struct {
	AccountID string
	TenantID  string
}

// Error implements the error interface.
func (e ErrACMEAccountAlreadyExists) Error() string {
	if e.TenantID != "" {
		return fmt.Sprintf("cluster: ACME account already exists: id=%s tenant=%s", e.AccountID, e.TenantID)
	}
	return fmt.Sprintf("cluster: ACME account already exists: id=%s", e.AccountID)
}

// ErrACMEAccountInactive indicates that an ACME account is not in an active state.
type ErrACMEAccountInactive struct {
	AccountID string
	Status    string
}

// Error implements the error interface.
func (e ErrACMEAccountInactive) Error() string {
	return fmt.Sprintf("cluster: ACME account inactive: id=%s status=%s", e.AccountID, e.Status)
}

// ErrACMEOrderNotFound indicates that a requested ACME order does not exist.
type ErrACMEOrderNotFound struct {
	OrderID  string
	TenantID string
}

// Error implements the error interface.
func (e ErrACMEOrderNotFound) Error() string {
	if e.TenantID != "" {
		return fmt.Sprintf("cluster: ACME order not found: id=%s tenant=%s", e.OrderID, e.TenantID)
	}
	return fmt.Sprintf("cluster: ACME order not found: id=%s", e.OrderID)
}

// ErrACMEOrderExpired indicates that an ACME order has expired.
type ErrACMEOrderExpired struct {
	OrderID   string
	ExpiresAt string
}

// Error implements the error interface.
func (e ErrACMEOrderExpired) Error() string {
	return fmt.Sprintf("cluster: ACME order expired: id=%s expired_at=%s", e.OrderID, e.ExpiresAt)
}

// ErrACMEOrderInvalidStatus indicates that an operation cannot be performed in the current order status.
type ErrACMEOrderInvalidStatus struct {
	OrderID  string
	Status   string
	Expected string
}

// Error implements the error interface.
func (e ErrACMEOrderInvalidStatus) Error() string {
	return fmt.Sprintf("cluster: ACME order invalid status: id=%s status=%s expected=%s", e.OrderID, e.Status, e.Expected)
}

// ErrACMEAuthorizationNotFound indicates that a requested ACME authorization does not exist.
type ErrACMEAuthorizationNotFound struct {
	AuthorizationID string
	TenantID        string
}

// Error implements the error interface.
func (e ErrACMEAuthorizationNotFound) Error() string {
	if e.TenantID != "" {
		return fmt.Sprintf("cluster: ACME authorization not found: id=%s tenant=%s", e.AuthorizationID, e.TenantID)
	}
	return fmt.Sprintf("cluster: ACME authorization not found: id=%s", e.AuthorizationID)
}

// ErrACMEAuthorizationExpired indicates that an ACME authorization has expired.
type ErrACMEAuthorizationExpired struct {
	AuthorizationID string
	ExpiresAt       string
}

// Error implements the error interface.
func (e ErrACMEAuthorizationExpired) Error() string {
	return fmt.Sprintf("cluster: ACME authorization expired: id=%s expired_at=%s", e.AuthorizationID, e.ExpiresAt)
}

// ErrACMEChallengeNotFound indicates that a requested ACME challenge does not exist.
type ErrACMEChallengeNotFound struct {
	ChallengeID     string
	AuthorizationID string
}

// Error implements the error interface.
func (e ErrACMEChallengeNotFound) Error() string {
	return fmt.Sprintf("cluster: ACME challenge not found: id=%s authorization=%s", e.ChallengeID, e.AuthorizationID)
}

// ErrACMEChallengeInvalidStatus indicates that an operation cannot be performed in the current challenge status.
type ErrACMEChallengeInvalidStatus struct {
	ChallengeID string
	Status      string
	Expected    string
}

// Error implements the error interface.
func (e ErrACMEChallengeInvalidStatus) Error() string {
	return fmt.Sprintf("cluster: ACME challenge invalid status: id=%s status=%s expected=%s", e.ChallengeID, e.Status, e.Expected)
}

// ErrInvalidInput indicates that input validation failed.
type ErrInvalidInput struct {
	Field  string
	Reason string
}

// Error implements the error interface.
func (e ErrInvalidInput) Error() string {
	return fmt.Sprintf("cluster: invalid input: %s: %s", e.Field, e.Reason)
}

// ErrVersionConflict indicates an optimistic locking version conflict.
type ErrVersionConflict struct {
	EntityType      string
	EntityID        string
	ExpectedVersion uint64
	ActualVersion   uint64
}

// Error implements the error interface.
func (e ErrVersionConflict) Error() string {
	return fmt.Sprintf("cluster: version conflict: type=%s id=%s expected=%d actual=%d",
		e.EntityType, e.EntityID, e.ExpectedVersion, e.ActualVersion)
}

// ErrTenantMismatch indicates that an entity does not belong to the expected tenant.
type ErrTenantMismatch struct {
	EntityType     string
	EntityID       string
	ExpectedTenant string
	ActualTenant   string
}

// Error implements the error interface.
func (e ErrTenantMismatch) Error() string {
	return fmt.Sprintf("cluster: tenant mismatch: type=%s id=%s expected=%s actual=%s",
		e.EntityType, e.EntityID, e.ExpectedTenant, e.ActualTenant)
}

// ErrOperationFailed indicates that a storage operation failed.
type ErrOperationFailed struct {
	Operation string
	Cause     error
}

// Error implements the error interface.
func (e ErrOperationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("cluster: operation failed: %s: %v", e.Operation, e.Cause)
	}
	return fmt.Sprintf("cluster: operation failed: %s", e.Operation)
}

// Unwrap returns the underlying cause.
func (e ErrOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrStorageUnavailable indicates that the underlying storage backend is unavailable.
type ErrStorageUnavailable struct {
	Cause error
}

// Error implements the error interface.
func (e ErrStorageUnavailable) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("cluster: storage unavailable: %v", e.Cause)
	}
	return "cluster: storage unavailable"
}

// Unwrap returns the underlying cause.
func (e ErrStorageUnavailable) Unwrap() error {
	return e.Cause
}

// ============================================================================
// CRL Coordinator Errors
// ============================================================================

// ErrCRLCoordinatorAlreadyRunning indicates the coordinator is already running.
type ErrCRLCoordinatorAlreadyRunning struct{}

// Error implements the error interface.
func (e ErrCRLCoordinatorAlreadyRunning) Error() string {
	return "cluster: CRL coordinator is already running"
}

// ErrCRLCoordinatorNotRunning indicates the coordinator is not running.
type ErrCRLCoordinatorNotRunning struct{}

// Error implements the error interface.
func (e ErrCRLCoordinatorNotRunning) Error() string {
	return "cluster: CRL coordinator is not running"
}

// ErrCRLCoordinatorStopped indicates the coordinator has been stopped.
type ErrCRLCoordinatorStopped struct{}

// Error implements the error interface.
func (e ErrCRLCoordinatorStopped) Error() string {
	return "cluster: CRL coordinator has been stopped and cannot be restarted"
}

// ErrNotLeader indicates that the operation requires leadership.
type ErrNotLeader struct {
	NodeID   string
	LeaderID string
}

// Error implements the error interface.
func (e ErrNotLeader) Error() string {
	if e.LeaderID != "" {
		return fmt.Sprintf("cluster: node %s is not the leader; current leader is %s", e.NodeID, e.LeaderID)
	}
	return fmt.Sprintf("cluster: node %s is not the leader", e.NodeID)
}

// ErrCRLGenerationFailed indicates that CRL generation failed.
type ErrCRLGenerationFailed struct {
	Reason string
	Cause  error
}

// Error implements the error interface.
func (e ErrCRLGenerationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("cluster: CRL generation failed: %s: %v", e.Reason, e.Cause)
	}
	return fmt.Sprintf("cluster: CRL generation failed: %s", e.Reason)
}

// Unwrap returns the underlying cause.
func (e ErrCRLGenerationFailed) Unwrap() error {
	return e.Cause
}

// ErrCRLExpired indicates that the CRL has expired.
type ErrCRLExpired struct {
	CRLID       string
	ExpiredAt   time.Time
	RetrievedAt time.Time
}

// Error implements the error interface.
func (e ErrCRLExpired) Error() string {
	return fmt.Sprintf("cluster: CRL expired: id=%s expired_at=%s", e.CRLID, e.ExpiredAt.Format(time.RFC3339))
}
