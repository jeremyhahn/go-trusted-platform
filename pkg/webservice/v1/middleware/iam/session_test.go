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
	"testing"
	"time"

	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
)

// createTestUser creates a test IAM user with the provided options.
func createTestUser(opts ...func(*sdkiam.User)) *sdkiam.User {
	user := &sdkiam.User{
		ID:          "user-123",
		TenantID:    "tenant-456",
		Email:       "test@example.com",
		DisplayName: "Test User",
		Roles:       []string{"admin", "user"},
		Metadata:    map[string]string{"department": "engineering", "level": "senior"},
	}
	for _, opt := range opts {
		opt(user)
	}
	return user
}

// TestNewIAMSession tests the NewIAMSession constructor.
func TestNewIAMSession(t *testing.T) {
	t.Run("creates_session_from_valid_user", func(t *testing.T) {
		user := createTestUser()
		session := NewIAMSession(user)

		if session == nil {
			t.Fatal("expected session to be non-nil")
		}

		if session.UserID() != user.ID {
			t.Errorf("expected UserID %q, got %q", user.ID, session.UserID())
		}
		if session.TenantID() != user.TenantID {
			t.Errorf("expected TenantID %q, got %q", user.TenantID, session.TenantID())
		}
		if session.Email() != user.Email {
			t.Errorf("expected Email %q, got %q", user.Email, session.Email())
		}
		if session.Name() != user.DisplayName {
			t.Errorf("expected Name %q, got %q", user.DisplayName, session.Name())
		}
	})

	t.Run("returns_nil_for_nil_user", func(t *testing.T) {
		session := NewIAMSession(nil)
		if session != nil {
			t.Error("expected nil session for nil user")
		}
	})

	t.Run("copies_roles_correctly", func(t *testing.T) {
		user := createTestUser()
		session := NewIAMSession(user)

		roles := session.Roles()
		if len(roles) != len(user.Roles) {
			t.Errorf("expected %d roles, got %d", len(user.Roles), len(roles))
		}

		// Verify the roles are a copy and not the same slice
		roles[0] = "modified"
		if session.Roles()[0] == "modified" {
			t.Error("expected roles to be a copy, not the same slice")
		}
	})

	// NewIAMSession never asserts MFA. iam.User carried an MFAEnabled flag
	// until go-quicbaas v0.8.0, which models the account's permitted methods
	// as AuthMethods instead; verification is a property of a SESSION, not of
	// a user record. A session built without explicit verification evidence
	// must therefore report not-verified — fail closed — and
	// NewIAMSessionWithMFA is the constructor that carries a real result.
	t.Run("never_claims_mfa_without_explicit_evidence", func(t *testing.T) {
		session := NewIAMSession(createTestUser())
		if session.IsMFAVerified() {
			t.Error("expected MFA not to be verified: this constructor is given no verification evidence")
		}
		if !session.MFATimestamp().IsZero() {
			t.Error("expected a zero MFA timestamp when MFA was never verified")
		}
		if !session.MFATimestamp().IsZero() {
			t.Error("expected MFA timestamp to be zero")
		}
	})
}

// TestNewIAMSessionWithMFA tests the NewIAMSessionWithMFA constructor.
func TestNewIAMSessionWithMFA(t *testing.T) {
	t.Run("sets_explicit_mfa_status", func(t *testing.T) {
		user := createTestUser()
		mfaTime := time.Now()

		session := NewIAMSessionWithMFA(user, true, mfaTime)

		if session == nil {
			t.Fatal("expected session to be non-nil")
		}
		if !session.IsMFAVerified() {
			t.Error("expected MFA to be verified")
		}
		if !session.MFATimestamp().Equal(mfaTime) {
			t.Errorf("expected MFA timestamp %v, got %v", mfaTime, session.MFATimestamp())
		}
	})

	t.Run("returns_nil_for_nil_user", func(t *testing.T) {
		session := NewIAMSessionWithMFA(nil, true, time.Now())
		if session != nil {
			t.Error("expected nil session for nil user")
		}
	})

	t.Run("explicit_false_is_honoured", func(t *testing.T) {
		user := createTestUser()
		mfaTime := time.Now().Add(-2 * time.Hour)

		session := NewIAMSessionWithMFA(user, false, mfaTime)

		if session.IsMFAVerified() {
			t.Error("expected MFA not to be verified when passed false")
		}
	})
}

// TestIAMSession_HasRole tests the HasRole method.
func TestIAMSession_HasRole(t *testing.T) {
	user := createTestUser(func(u *sdkiam.User) {
		u.Roles = []string{"admin", "user", "viewer"}
	})
	session := NewIAMSession(user)

	t.Run("returns_true_for_existing_role", func(t *testing.T) {
		if !session.HasRole("admin") {
			t.Error("expected HasRole('admin') to return true")
		}
		if !session.HasRole("user") {
			t.Error("expected HasRole('user') to return true")
		}
		if !session.HasRole("viewer") {
			t.Error("expected HasRole('viewer') to return true")
		}
	})

	t.Run("returns_false_for_non_existing_role", func(t *testing.T) {
		if session.HasRole("superadmin") {
			t.Error("expected HasRole('superadmin') to return false")
		}
		if session.HasRole("") {
			t.Error("expected HasRole('') to return false")
		}
	})

	t.Run("is_case_sensitive", func(t *testing.T) {
		if session.HasRole("Admin") {
			t.Error("expected HasRole('Admin') to return false (case sensitive)")
		}
		if session.HasRole("ADMIN") {
			t.Error("expected HasRole('ADMIN') to return false (case sensitive)")
		}
	})
}

// TestIAMSession_HasAllRoles tests the HasAllRoles method.
func TestIAMSession_HasAllRoles(t *testing.T) {
	user := createTestUser(func(u *sdkiam.User) {
		u.Roles = []string{"admin", "user", "viewer"}
	})
	session := NewIAMSession(user)

	t.Run("returns_true_when_has_all_roles", func(t *testing.T) {
		if !session.HasAllRoles("admin", "user") {
			t.Error("expected HasAllRoles('admin', 'user') to return true")
		}
		if !session.HasAllRoles("admin", "user", "viewer") {
			t.Error("expected HasAllRoles('admin', 'user', 'viewer') to return true")
		}
	})

	t.Run("returns_false_when_missing_role", func(t *testing.T) {
		if session.HasAllRoles("admin", "superadmin") {
			t.Error("expected HasAllRoles('admin', 'superadmin') to return false")
		}
	})

	t.Run("returns_true_for_single_existing_role", func(t *testing.T) {
		if !session.HasAllRoles("admin") {
			t.Error("expected HasAllRoles('admin') to return true")
		}
	})

	t.Run("returns_true_for_empty_roles", func(t *testing.T) {
		if !session.HasAllRoles() {
			t.Error("expected HasAllRoles() with no args to return true")
		}
	})
}

// TestIAMSession_HasAnyRole tests the HasAnyRole method.
func TestIAMSession_HasAnyRole(t *testing.T) {
	user := createTestUser(func(u *sdkiam.User) {
		u.Roles = []string{"admin", "user"}
	})
	session := NewIAMSession(user)

	t.Run("returns_true_when_has_at_least_one_role", func(t *testing.T) {
		if !session.HasAnyRole("admin", "superadmin") {
			t.Error("expected HasAnyRole('admin', 'superadmin') to return true")
		}
		if !session.HasAnyRole("superadmin", "user") {
			t.Error("expected HasAnyRole('superadmin', 'user') to return true")
		}
	})

	t.Run("returns_false_when_has_no_matching_roles", func(t *testing.T) {
		if session.HasAnyRole("superadmin", "moderator") {
			t.Error("expected HasAnyRole('superadmin', 'moderator') to return false")
		}
	})

	t.Run("returns_true_for_single_existing_role", func(t *testing.T) {
		if !session.HasAnyRole("admin") {
			t.Error("expected HasAnyRole('admin') to return true")
		}
	})

	t.Run("returns_false_for_empty_roles", func(t *testing.T) {
		if session.HasAnyRole() {
			t.Error("expected HasAnyRole() with no args to return false")
		}
	})
}

// TestIAMSession_Attributes tests the Attributes and GetAttribute methods.
func TestIAMSession_Attributes(t *testing.T) {
	user := createTestUser(func(u *sdkiam.User) {
		u.Metadata = map[string]string{
			"department": "engineering",
			"level":      "senior",
			"location":   "remote",
		}
	})
	session := NewIAMSession(user)

	t.Run("returns_copy_of_attributes", func(t *testing.T) {
		attrs := session.Attributes()
		if len(attrs) != 3 {
			t.Errorf("expected 3 attributes, got %d", len(attrs))
		}

		// Verify it's a copy
		attrs["new_key"] = "new_value"
		if _, ok := session.Attributes()["new_key"]; ok {
			t.Error("expected attributes to be a copy")
		}
	})

	t.Run("GetAttribute_returns_existing_value", func(t *testing.T) {
		val, ok := session.GetAttribute("department")
		if !ok {
			t.Error("expected GetAttribute('department') to return ok=true")
		}
		if val != "engineering" {
			t.Errorf("expected 'engineering', got %q", val)
		}
	})

	t.Run("GetAttribute_returns_false_for_missing_key", func(t *testing.T) {
		val, ok := session.GetAttribute("nonexistent")
		if ok {
			t.Error("expected GetAttribute('nonexistent') to return ok=false")
		}
		if val != "" {
			t.Errorf("expected empty string, got %q", val)
		}
	})

	t.Run("handles_nil_attributes", func(t *testing.T) {
		user := createTestUser(func(u *sdkiam.User) {
			u.Metadata = nil
		})
		session := NewIAMSession(user)

		attrs := session.Attributes()
		if attrs != nil {
			t.Error("expected nil attributes")
		}

		_, ok := session.GetAttribute("any")
		if ok {
			t.Error("expected GetAttribute on nil attributes to return false")
		}
	})
}

// TestIAMSession_User tests the User method.
func TestIAMSession_User(t *testing.T) {
	t.Run("returns_underlying_user", func(t *testing.T) {
		user := createTestUser()
		session := NewIAMSession(user)

		if session.User() != user {
			t.Error("expected User() to return the same user object")
		}
	})
}

// TestIAMSession_ToSubject tests the ToSubject method.
func TestIAMSession_ToSubject(t *testing.T) {
	t.Run("converts_session_to_subject", func(t *testing.T) {
		mfaTime := time.Now()
		user := createTestUser(func(u *sdkiam.User) {
			u.Metadata = map[string]string{"key": "value"}
		})
		session := NewIAMSessionWithMFA(user, true, mfaTime)

		subject := session.ToSubject()

		if subject == nil {
			t.Fatal("expected subject to be non-nil")
		}
		if subject.ID != user.ID {
			t.Errorf("expected ID %q, got %q", user.ID, subject.ID)
		}
		if subject.TenantID != user.TenantID {
			t.Errorf("expected TenantID %q, got %q", user.TenantID, subject.TenantID)
		}
		if len(subject.Roles) != len(user.Roles) {
			t.Errorf("expected %d roles, got %d", len(user.Roles), len(subject.Roles))
		}
	})

	t.Run("handles_zero_mfa_timestamp", func(t *testing.T) {
		user := createTestUser()
		session := NewIAMSessionWithMFA(user, false, time.Time{})

		subject := session.ToSubject()

		if subject == nil {
			t.Fatal("expected subject to be non-nil")
		}
		if subject.ID != user.ID {
			t.Errorf("expected ID %q, got %q", user.ID, subject.ID)
		}
	})
}

// TestIAMSession_NilUserHandling tests that session methods handle nil user correctly.
func TestIAMSession_NilUserHandling(t *testing.T) {
	// Create a session with nil user through type assertion trick
	// This tests edge cases in the session implementation
	session := &iamSession{user: nil}

	t.Run("TenantID_returns_empty_for_nil_user", func(t *testing.T) {
		if session.TenantID() != "" {
			t.Error("expected empty TenantID for nil user")
		}
	})

	t.Run("UserID_returns_empty_for_nil_user", func(t *testing.T) {
		if session.UserID() != "" {
			t.Error("expected empty UserID for nil user")
		}
	})

	t.Run("Email_returns_empty_for_nil_user", func(t *testing.T) {
		if session.Email() != "" {
			t.Error("expected empty Email for nil user")
		}
	})

	t.Run("Name_returns_empty_for_nil_user", func(t *testing.T) {
		if session.Name() != "" {
			t.Error("expected empty Name for nil user")
		}
	})

	t.Run("Roles_returns_nil_for_nil_user", func(t *testing.T) {
		if session.Roles() != nil {
			t.Error("expected nil Roles for nil user")
		}
	})

	t.Run("Attributes_returns_nil_for_nil_user", func(t *testing.T) {
		if session.Attributes() != nil {
			t.Error("expected nil Attributes for nil user")
		}
	})

	t.Run("ToSubject_returns_nil_for_nil_user", func(t *testing.T) {
		if session.ToSubject() != nil {
			t.Error("expected nil Subject for nil user")
		}
	})
}

// TestIAMSession_ImplementsInterface verifies iamSession implements IAMSession interface.
func TestIAMSession_ImplementsInterface(t *testing.T) {
	user := createTestUser()
	var _ = NewIAMSession(user)
}
