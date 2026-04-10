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

package invitation

import (
	"testing"
	"time"
)

func TestInvitationStatus_String(t *testing.T) {
	tests := []struct {
		name   string
		status InvitationStatus
		want   string
	}{
		{"pending", StatusPending, "pending"},
		{"accepted", StatusAccepted, "accepted"},
		{"expired", StatusExpired, "expired"},
		{"revoked", StatusRevoked, "revoked"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.status.String(); got != tt.want {
				t.Errorf("InvitationStatus.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInvitationStatus_IsValid(t *testing.T) {
	tests := []struct {
		name   string
		status InvitationStatus
		want   bool
	}{
		{"pending is valid", StatusPending, true},
		{"accepted is valid", StatusAccepted, true},
		{"expired is valid", StatusExpired, true},
		{"revoked is valid", StatusRevoked, true},
		{"invalid status", InvitationStatus("invalid"), false},
		{"empty status", InvitationStatus(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.status.IsValid(); got != tt.want {
				t.Errorf("InvitationStatus.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInvitation_IsExpired(t *testing.T) {
	t.Run("returns true for past expiration", func(t *testing.T) {
		inv := &Invitation{
			ExpiresAt: time.Now().UTC().Add(-time.Hour),
		}
		if !inv.IsExpired() {
			t.Error("IsExpired() should return true for past expiration")
		}
	})

	t.Run("returns false for future expiration", func(t *testing.T) {
		inv := &Invitation{
			ExpiresAt: time.Now().UTC().Add(time.Hour),
		}
		if inv.IsExpired() {
			t.Error("IsExpired() should return false for future expiration")
		}
	})
}

func TestInvitation_IsPending(t *testing.T) {
	t.Run("returns true for pending status", func(t *testing.T) {
		inv := &Invitation{Status: StatusPending}
		if !inv.IsPending() {
			t.Error("IsPending() should return true for pending status")
		}
	})

	t.Run("returns false for accepted status", func(t *testing.T) {
		inv := &Invitation{Status: StatusAccepted}
		if inv.IsPending() {
			t.Error("IsPending() should return false for accepted status")
		}
	})

	t.Run("returns false for expired status", func(t *testing.T) {
		inv := &Invitation{Status: StatusExpired}
		if inv.IsPending() {
			t.Error("IsPending() should return false for expired status")
		}
	})

	t.Run("returns false for revoked status", func(t *testing.T) {
		inv := &Invitation{Status: StatusRevoked}
		if inv.IsPending() {
			t.Error("IsPending() should return false for revoked status")
		}
	})
}

func TestInvitation_CanAccept(t *testing.T) {
	t.Run("returns true for pending and not expired", func(t *testing.T) {
		inv := &Invitation{
			Status:    StatusPending,
			ExpiresAt: time.Now().UTC().Add(time.Hour),
		}
		if !inv.CanAccept() {
			t.Error("CanAccept() should return true for pending and not expired")
		}
	})

	t.Run("returns false for pending but expired", func(t *testing.T) {
		inv := &Invitation{
			Status:    StatusPending,
			ExpiresAt: time.Now().UTC().Add(-time.Hour),
		}
		if inv.CanAccept() {
			t.Error("CanAccept() should return false for pending but expired")
		}
	})

	t.Run("returns false for accepted status", func(t *testing.T) {
		inv := &Invitation{
			Status:    StatusAccepted,
			ExpiresAt: time.Now().UTC().Add(time.Hour),
		}
		if inv.CanAccept() {
			t.Error("CanAccept() should return false for accepted status")
		}
	})

	t.Run("returns false for revoked status", func(t *testing.T) {
		inv := &Invitation{
			Status:    StatusRevoked,
			ExpiresAt: time.Now().UTC().Add(time.Hour),
		}
		if inv.CanAccept() {
			t.Error("CanAccept() should return false for revoked status")
		}
	})
}

func TestCreateInvitationRequest_Validate(t *testing.T) {
	t.Run("valid request passes validation", func(t *testing.T) {
		req := &CreateInvitationRequest{
			Email: "test@example.com",
			Role:  "member",
		}
		if err := req.Validate(); err != nil {
			t.Errorf("Validate() error = %v, want nil", err)
		}
	})

	t.Run("missing email fails validation", func(t *testing.T) {
		req := &CreateInvitationRequest{
			Email: "",
			Role:  "member",
		}
		err := req.Validate()
		if err == nil {
			t.Error("Validate() should fail for missing email")
		}
		validErr, ok := err.(*ErrValidationFailed)
		if !ok {
			t.Errorf("Validate() error type = %T, want *ErrValidationFailed", err)
		}
		if validErr.Field != "email" {
			t.Errorf("Validate() error field = %v, want 'email'", validErr.Field)
		}
	})

	t.Run("missing role fails validation", func(t *testing.T) {
		req := &CreateInvitationRequest{
			Email: "test@example.com",
			Role:  "",
		}
		err := req.Validate()
		if err == nil {
			t.Error("Validate() should fail for missing role")
		}
		validErr, ok := err.(*ErrValidationFailed)
		if !ok {
			t.Errorf("Validate() error type = %T, want *ErrValidationFailed", err)
		}
		if validErr.Field != "role" {
			t.Errorf("Validate() error field = %v, want 'role'", validErr.Field)
		}
	})

	t.Run("optional expires_in is allowed", func(t *testing.T) {
		req := &CreateInvitationRequest{
			Email:     "test@example.com",
			Role:      "member",
			ExpiresIn: 24 * time.Hour,
		}
		if err := req.Validate(); err != nil {
			t.Errorf("Validate() error = %v, want nil", err)
		}
	})
}
