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

package iam

import (
	"time"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
)

// iamSession implements the IAMSession interface wrapping a QuicBaaS IAM User.
type iamSession struct {
	user                *iamsdk.User
	mfaVerified         bool
	mfaTimestamp        time.Time
	roleSet             map[string]struct{}
	attestationVerified bool
	attestationTime     time.Time
	deviceID            string
}

// NewIAMSession creates a new IAM session from a QuicBaaS IAM User.
func NewIAMSession(user *iamsdk.User) IAMSession {
	if user == nil {
		return nil
	}

	session := &iamSession{
		user:    user,
		roleSet: make(map[string]struct{}, len(user.Roles)),
	}

	// Pre-compute the role set for O(1) lookups
	for _, role := range user.Roles {
		session.roleSet[role] = struct{}{}
	}

	// MFA is not asserted by this constructor. iam.User no longer carries an
	// MFAEnabled flag (quicbaas v0.8.0 models permitted methods as
	// AuthMethods instead), and a session built without explicit MFA
	// evidence must not claim to have it. NewIAMSessionWithMFA is the
	// constructor that carries a real verification result.

	return session
}

// NewIAMSessionWithMFA creates a new IAM session with explicit MFA status.
func NewIAMSessionWithMFA(user *iamsdk.User, mfaVerified bool, mfaTimestamp time.Time) IAMSession {
	session := NewIAMSession(user)
	if session == nil {
		return nil
	}

	s := session.(*iamSession)
	s.mfaVerified = mfaVerified
	s.mfaTimestamp = mfaTimestamp
	return s
}

// NewIAMSessionWithAttestation creates a new IAM session with explicit attestation status.
func NewIAMSessionWithAttestation(user *iamsdk.User, mfaVerified bool, mfaTimestamp time.Time, attestationVerified bool, attestationTime time.Time, deviceID string) IAMSession {
	session := NewIAMSession(user)
	if session == nil {
		return nil
	}
	s := session.(*iamSession)
	s.mfaVerified = mfaVerified
	s.mfaTimestamp = mfaTimestamp
	s.attestationVerified = attestationVerified
	s.attestationTime = attestationTime
	s.deviceID = deviceID
	return s
}

// User returns the underlying IAM user.
func (s *iamSession) User() *iamsdk.User {
	return s.user
}

// TenantID returns the tenant identifier.
func (s *iamSession) TenantID() string {
	if s.user == nil {
		return ""
	}
	return s.user.TenantID
}

// UserID returns the user identifier.
func (s *iamSession) UserID() string {
	if s.user == nil {
		return ""
	}
	return s.user.ID
}

// Email returns the user's email address.
func (s *iamSession) Email() string {
	if s.user == nil {
		return ""
	}
	return s.user.Email
}

// Name returns the user's display name.
func (s *iamSession) Name() string {
	if s.user == nil {
		return ""
	}
	return s.user.DisplayName
}

// Roles returns the user's assigned roles.
func (s *iamSession) Roles() []string {
	if s.user == nil {
		return nil
	}
	// Return a copy to prevent modification
	roles := make([]string, len(s.user.Roles))
	copy(roles, s.user.Roles)
	return roles
}

// HasRole checks if the user has a specific role.
func (s *iamSession) HasRole(role string) bool {
	_, ok := s.roleSet[role]
	return ok
}

// HasAnyRole checks if the user has any of the specified roles.
func (s *iamSession) HasAnyRole(roles ...string) bool {
	for _, role := range roles {
		if s.HasRole(role) {
			return true
		}
	}
	return false
}

// HasAllRoles checks if the user has all of the specified roles.
func (s *iamSession) HasAllRoles(roles ...string) bool {
	for _, role := range roles {
		if !s.HasRole(role) {
			return false
		}
	}
	return true
}

// IsMFAVerified returns whether MFA has been verified for this session.
func (s *iamSession) IsMFAVerified() bool {
	return s.mfaVerified
}

// MFATimestamp returns when MFA was last verified.
func (s *iamSession) MFATimestamp() time.Time {
	return s.mfaTimestamp
}

// Attributes returns the user's custom attributes.
func (s *iamSession) Attributes() map[string]string {
	if s.user == nil || s.user.Metadata == nil {
		return nil
	}
	// Return a copy to prevent modification
	attrs := make(map[string]string, len(s.user.Metadata))
	for k, v := range s.user.Metadata {
		attrs[k] = v
	}
	return attrs
}

// GetAttribute returns a specific attribute value.
func (s *iamSession) GetAttribute(key string) (string, bool) {
	if s.user == nil || s.user.Metadata == nil {
		return "", false
	}
	val, ok := s.user.Metadata[key]
	return val, ok
}

// ToSubject converts the session to a PEP CheckSubject for authorization checks.
func (s *iamSession) ToSubject() *iamsdk.CheckSubject {
	if s.user == nil {
		return nil
	}

	// Convert metadata to interface map for CheckSubject attributes
	var attrs map[string]interface{}
	if s.user.Metadata != nil {
		attrs = make(map[string]interface{}, len(s.user.Metadata))
		for k, v := range s.user.Metadata {
			attrs[k] = v
		}
	}

	subject := &iamsdk.CheckSubject{
		ID:         s.user.ID,
		TenantID:   s.user.TenantID,
		Roles:      s.user.Roles,
		Attributes: attrs,
	}

	return subject
}

// IsAttestationVerified returns whether TPM attestation was verified.
func (s *iamSession) IsAttestationVerified() bool {
	return s.attestationVerified
}

// AttestationTime returns when attestation was verified.
func (s *iamSession) AttestationTime() time.Time {
	return s.attestationTime
}

// DeviceID returns the device identifier from the IDevID certificate.
func (s *iamSession) DeviceID() string {
	return s.deviceID
}
