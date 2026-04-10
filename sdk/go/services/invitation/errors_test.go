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
	"errors"
	"testing"
)

func TestErrValidationFailed(t *testing.T) {
	t.Run("formats with field", func(t *testing.T) {
		err := &ErrValidationFailed{Field: "email", Reason: "is required"}
		want := "validation failed for email: is required"
		if err.Error() != want {
			t.Errorf("Error() = %v, want %v", err.Error(), want)
		}
	})

	t.Run("formats without field", func(t *testing.T) {
		err := &ErrValidationFailed{Reason: "invalid request"}
		want := "validation failed: invalid request"
		if err.Error() != want {
			t.Errorf("Error() = %v, want %v", err.Error(), want)
		}
	})
}

func TestErrCreateInvitationFailed(t *testing.T) {
	t.Run("formats error message", func(t *testing.T) {
		cause := errors.New("connection refused")
		err := &ErrCreateInvitationFailed{Cause: cause}
		want := "failed to create invitation: connection refused"
		if err.Error() != want {
			t.Errorf("Error() = %v, want %v", err.Error(), want)
		}
	})

	t.Run("unwraps to cause", func(t *testing.T) {
		cause := errors.New("network error")
		err := &ErrCreateInvitationFailed{Cause: cause}
		if !errors.Is(err, cause) {
			t.Error("Unwrap() should return cause")
		}
	})
}

func TestErrGetInvitationFailed(t *testing.T) {
	t.Run("formats with ID", func(t *testing.T) {
		cause := errors.New("database error")
		err := &ErrGetInvitationFailed{ID: 123, Cause: cause}
		want := "failed to get invitation 123: database error"
		if err.Error() != want {
			t.Errorf("Error() = %v, want %v", err.Error(), want)
		}
	})

	t.Run("formats with token", func(t *testing.T) {
		cause := errors.New("timeout")
		err := &ErrGetInvitationFailed{Token: "abc123", Cause: cause}
		want := "failed to get invitation by token: timeout"
		if err.Error() != want {
			t.Errorf("Error() = %v, want %v", err.Error(), want)
		}
	})

	t.Run("unwraps to cause", func(t *testing.T) {
		cause := errors.New("network error")
		err := &ErrGetInvitationFailed{ID: 1, Cause: cause}
		if !errors.Is(err, cause) {
			t.Error("Unwrap() should return cause")
		}
	})
}

func TestErrListInvitationsFailed(t *testing.T) {
	t.Run("formats error message", func(t *testing.T) {
		cause := errors.New("unauthorized")
		err := &ErrListInvitationsFailed{Cause: cause}
		want := "failed to list invitations: unauthorized"
		if err.Error() != want {
			t.Errorf("Error() = %v, want %v", err.Error(), want)
		}
	})

	t.Run("unwraps to cause", func(t *testing.T) {
		cause := errors.New("forbidden")
		err := &ErrListInvitationsFailed{Cause: cause}
		if !errors.Is(err, cause) {
			t.Error("Unwrap() should return cause")
		}
	})
}

func TestErrRevokeInvitationFailed(t *testing.T) {
	t.Run("formats error message", func(t *testing.T) {
		cause := errors.New("permission denied")
		err := &ErrRevokeInvitationFailed{ID: 456, Cause: cause}
		want := "failed to revoke invitation 456: permission denied"
		if err.Error() != want {
			t.Errorf("Error() = %v, want %v", err.Error(), want)
		}
	})

	t.Run("unwraps to cause", func(t *testing.T) {
		cause := errors.New("internal error")
		err := &ErrRevokeInvitationFailed{ID: 1, Cause: cause}
		if !errors.Is(err, cause) {
			t.Error("Unwrap() should return cause")
		}
	})
}

func TestErrInvitationNotFound(t *testing.T) {
	t.Run("formats with ID", func(t *testing.T) {
		err := &ErrInvitationNotFound{ID: 789}
		want := "invitation not found: id=789"
		if err.Error() != want {
			t.Errorf("Error() = %v, want %v", err.Error(), want)
		}
	})

	t.Run("formats with token", func(t *testing.T) {
		err := &ErrInvitationNotFound{Token: "xyz456"}
		want := "invitation not found: token=xyz456"
		if err.Error() != want {
			t.Errorf("Error() = %v, want %v", err.Error(), want)
		}
	})
}

func TestErrInvitationExpired(t *testing.T) {
	t.Run("formats with ID", func(t *testing.T) {
		err := &ErrInvitationExpired{ID: 123}
		want := "invitation expired: id=123"
		if err.Error() != want {
			t.Errorf("Error() = %v, want %v", err.Error(), want)
		}
	})

	t.Run("formats with token", func(t *testing.T) {
		err := &ErrInvitationExpired{Token: "abc"}
		want := "invitation expired: token=abc"
		if err.Error() != want {
			t.Errorf("Error() = %v, want %v", err.Error(), want)
		}
	})
}

func TestErrInvitationAlreadyAccepted(t *testing.T) {
	t.Run("formats with ID", func(t *testing.T) {
		err := &ErrInvitationAlreadyAccepted{ID: 111}
		want := "invitation already accepted: id=111"
		if err.Error() != want {
			t.Errorf("Error() = %v, want %v", err.Error(), want)
		}
	})

	t.Run("formats with token", func(t *testing.T) {
		err := &ErrInvitationAlreadyAccepted{Token: "tok"}
		want := "invitation already accepted: token=tok"
		if err.Error() != want {
			t.Errorf("Error() = %v, want %v", err.Error(), want)
		}
	})
}

func TestErrInvitationAlreadyRevoked(t *testing.T) {
	t.Run("formats with ID", func(t *testing.T) {
		err := &ErrInvitationAlreadyRevoked{ID: 222}
		want := "invitation already revoked: id=222"
		if err.Error() != want {
			t.Errorf("Error() = %v, want %v", err.Error(), want)
		}
	})

	t.Run("formats with token", func(t *testing.T) {
		err := &ErrInvitationAlreadyRevoked{Token: "rev"}
		want := "invitation already revoked: token=rev"
		if err.Error() != want {
			t.Errorf("Error() = %v, want %v", err.Error(), want)
		}
	})
}

func TestErrEmailAlreadyRegistered(t *testing.T) {
	t.Run("formats error message", func(t *testing.T) {
		err := &ErrEmailAlreadyRegistered{Email: "test@example.com", TenantID: "tenant-123"}
		want := "email already registered in tenant: email=test@example.com, tenant_id=tenant-123"
		if err.Error() != want {
			t.Errorf("Error() = %v, want %v", err.Error(), want)
		}
	})
}
