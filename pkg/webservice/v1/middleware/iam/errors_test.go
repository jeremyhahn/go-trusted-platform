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
)

// TestErrUnauthorized tests the ErrUnauthorized error type.
func TestErrUnauthorized(t *testing.T) {
	t.Parallel()
	t.Run("without_reason", func(t *testing.T) {
		err := ErrUnauthorized{}
		expected := "unauthorized"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("with_reason", func(t *testing.T) {
		err := ErrUnauthorized{Reason: "invalid credentials"}
		expected := "unauthorized: invalid credentials"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("implements_error_interface", func(t *testing.T) {
		var _ error = ErrUnauthorized{}
	})
}

// TestErrForbidden tests the ErrForbidden error type.
func TestErrForbidden(t *testing.T) {
	t.Parallel()
	t.Run("with_reason", func(t *testing.T) {
		err := ErrForbidden{Reason: "access denied"}
		expected := "forbidden: access denied"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("with_action_and_resource", func(t *testing.T) {
		err := ErrForbidden{Action: "delete", Resource: "/users/123"}
		expected := "forbidden: action \"delete\" on resource \"/users/123\" denied"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("reason_takes_precedence", func(t *testing.T) {
		err := ErrForbidden{
			Action:   "delete",
			Resource: "/users/123",
			Reason:   "custom reason",
		}
		expected := "forbidden: custom reason"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("implements_error_interface", func(t *testing.T) {
		var _ error = ErrForbidden{}
	})
}

// TestErrTLSRequired tests the ErrTLSRequired error type.
func TestErrTLSRequired(t *testing.T) {
	t.Parallel()
	t.Run("error_message", func(t *testing.T) {
		err := ErrTLSRequired{}
		expected := "TLS connection required"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("implements_error_interface", func(t *testing.T) {
		var _ error = ErrTLSRequired{}
	})
}

// TestErrMTLSRequired tests the ErrMTLSRequired error type.
func TestErrMTLSRequired(t *testing.T) {
	t.Parallel()
	t.Run("error_message", func(t *testing.T) {
		err := ErrMTLSRequired{}
		expected := "client certificate required"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("implements_error_interface", func(t *testing.T) {
		var _ error = ErrMTLSRequired{}
	})
}

// TestErrCertificateInvalid tests the ErrCertificateInvalid error type.
func TestErrCertificateInvalid(t *testing.T) {
	t.Parallel()
	t.Run("without_reason", func(t *testing.T) {
		err := ErrCertificateInvalid{}
		expected := "certificate validation failed"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("with_reason", func(t *testing.T) {
		err := ErrCertificateInvalid{Reason: "certificate expired"}
		expected := "certificate validation failed: certificate expired"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("implements_error_interface", func(t *testing.T) {
		var _ error = ErrCertificateInvalid{}
	})
}

// TestErrTokenInvalid tests the ErrTokenInvalid error type.
func TestErrTokenInvalid(t *testing.T) {
	t.Parallel()
	t.Run("without_reason", func(t *testing.T) {
		err := ErrTokenInvalid{}
		expected := "invalid token"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("with_reason", func(t *testing.T) {
		err := ErrTokenInvalid{Reason: "malformed header"}
		expected := "invalid token: malformed header"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("implements_error_interface", func(t *testing.T) {
		var _ error = ErrTokenInvalid{}
	})
}

// TestErrTokenExpired tests the ErrTokenExpired error type.
func TestErrTokenExpired(t *testing.T) {
	t.Parallel()
	t.Run("without_expired_at", func(t *testing.T) {
		err := ErrTokenExpired{}
		expected := "token expired"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("with_expired_at", func(t *testing.T) {
		err := ErrTokenExpired{ExpiredAt: "2024-01-01T00:00:00Z"}
		expected := "token expired at 2024-01-01T00:00:00Z"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("implements_error_interface", func(t *testing.T) {
		var _ error = ErrTokenExpired{}
	})
}

// TestErrTokenNotYetValid tests the ErrTokenNotYetValid error type.
func TestErrTokenNotYetValid(t *testing.T) {
	t.Parallel()
	t.Run("without_not_before", func(t *testing.T) {
		err := ErrTokenNotYetValid{}
		expected := "token not yet valid"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("with_not_before", func(t *testing.T) {
		err := ErrTokenNotYetValid{NotBefore: "2025-01-01T00:00:00Z"}
		expected := "token not valid before 2025-01-01T00:00:00Z"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("implements_error_interface", func(t *testing.T) {
		var _ error = ErrTokenNotYetValid{}
	})
}

// TestErrMissingToken tests the ErrMissingToken error type.
func TestErrMissingToken(t *testing.T) {
	t.Parallel()
	t.Run("error_message", func(t *testing.T) {
		err := ErrMissingToken{}
		expected := "authentication token required"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("implements_error_interface", func(t *testing.T) {
		var _ error = ErrMissingToken{}
	})
}

// TestErrMissingTenantID tests the ErrMissingTenantID error type.
func TestErrMissingTenantID(t *testing.T) {
	t.Parallel()
	t.Run("error_message", func(t *testing.T) {
		err := ErrMissingTenantID{}
		expected := "tenant ID required"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("implements_error_interface", func(t *testing.T) {
		var _ error = ErrMissingTenantID{}
	})
}

// TestErrUserNotFound tests the ErrUserNotFound error type.
func TestErrUserNotFound(t *testing.T) {
	t.Parallel()
	t.Run("without_identifier", func(t *testing.T) {
		err := ErrUserNotFound{}
		expected := "user not found"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("with_identifier", func(t *testing.T) {
		err := ErrUserNotFound{Identifier: "user@example.com"}
		expected := "user not found: user@example.com"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("implements_error_interface", func(t *testing.T) {
		var _ error = ErrUserNotFound{}
	})
}

// TestErrMFARequired tests the ErrMFARequired error type.
func TestErrMFARequired(t *testing.T) {
	t.Parallel()
	t.Run("error_message", func(t *testing.T) {
		err := ErrMFARequired{}
		expected := "MFA verification required"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("implements_error_interface", func(t *testing.T) {
		var _ error = ErrMFARequired{}
	})
}

// TestErrMFAExpired tests the ErrMFAExpired error type.
func TestErrMFAExpired(t *testing.T) {
	t.Parallel()
	t.Run("error_message", func(t *testing.T) {
		err := ErrMFAExpired{}
		expected := "MFA verification expired"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("implements_error_interface", func(t *testing.T) {
		var _ error = ErrMFAExpired{}
	})
}

// TestErrSessionInvalid tests the ErrSessionInvalid error type.
func TestErrSessionInvalid(t *testing.T) {
	t.Parallel()
	t.Run("without_fields", func(t *testing.T) {
		err := ErrSessionInvalid{}
		expected := "invalid session"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("with_session_id_only", func(t *testing.T) {
		err := ErrSessionInvalid{SessionID: "sess-12345"}
		expected := "invalid session: sess-12345"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("with_reason", func(t *testing.T) {
		err := ErrSessionInvalid{Reason: "session revoked"}
		expected := "invalid session: session revoked"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("reason_takes_precedence", func(t *testing.T) {
		err := ErrSessionInvalid{
			SessionID: "sess-12345",
			Reason:    "session revoked",
		}
		expected := "invalid session: session revoked"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("implements_error_interface", func(t *testing.T) {
		var _ error = ErrSessionInvalid{}
	})
}

// TestErrServiceUnavailable tests the ErrServiceUnavailable error type.
func TestErrServiceUnavailable(t *testing.T) {
	t.Parallel()
	t.Run("without_reason", func(t *testing.T) {
		err := ErrServiceUnavailable{Service: "IAM"}
		expected := "service unavailable: IAM"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("with_reason", func(t *testing.T) {
		err := ErrServiceUnavailable{Service: "IAM", Reason: "connection timeout"}
		expected := "service unavailable: IAM - connection timeout"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("implements_error_interface", func(t *testing.T) {
		var _ error = ErrServiceUnavailable{}
	})
}

// TestErrInvalidConfig tests the ErrInvalidConfig error type.
func TestErrInvalidConfig(t *testing.T) {
	t.Parallel()
	t.Run("without_reason", func(t *testing.T) {
		err := ErrInvalidConfig{Field: "signingKey"}
		expected := "invalid configuration: signingKey"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("with_reason", func(t *testing.T) {
		err := ErrInvalidConfig{Field: "signingKey", Reason: "key too short"}
		expected := "invalid configuration: signingKey - key too short"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("implements_error_interface", func(t *testing.T) {
		var _ error = ErrInvalidConfig{}
	})
}

// TestErrAudienceMismatch tests the ErrAudienceMismatch error type.
func TestErrAudienceMismatch(t *testing.T) {
	t.Parallel()
	t.Run("error_message", func(t *testing.T) {
		err := ErrAudienceMismatch{
			Expected: []string{"api.example.com"},
			Actual:   []string{"other.example.com"},
		}
		expected := "audience mismatch: expected [api.example.com], got [other.example.com]"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("multiple_audiences", func(t *testing.T) {
		err := ErrAudienceMismatch{
			Expected: []string{"api.example.com", "admin.example.com"},
			Actual:   []string{"unknown.example.com"},
		}
		expected := "audience mismatch: expected [api.example.com admin.example.com], got [unknown.example.com]"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("implements_error_interface", func(t *testing.T) {
		var _ error = ErrAudienceMismatch{}
	})
}

// TestErrIssuerMismatch tests the ErrIssuerMismatch error type.
func TestErrIssuerMismatch(t *testing.T) {
	t.Parallel()
	t.Run("error_message", func(t *testing.T) {
		err := ErrIssuerMismatch{
			Expected: "https://auth.example.com",
			Actual:   "https://other.example.com",
		}
		expected := "issuer mismatch: expected \"https://auth.example.com\", got \"https://other.example.com\""
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("implements_error_interface", func(t *testing.T) {
		var _ error = ErrIssuerMismatch{}
	})
}

// TestAllErrorsImplementErrorInterface verifies all error types implement the error interface.
func TestAllErrorsImplementErrorInterface(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
	}{
		{"ErrUnauthorized", ErrUnauthorized{}},
		{"ErrForbidden", ErrForbidden{}},
		{"ErrTLSRequired", ErrTLSRequired{}},
		{"ErrMTLSRequired", ErrMTLSRequired{}},
		{"ErrCertificateInvalid", ErrCertificateInvalid{}},
		{"ErrTokenInvalid", ErrTokenInvalid{}},
		{"ErrTokenExpired", ErrTokenExpired{}},
		{"ErrTokenNotYetValid", ErrTokenNotYetValid{}},
		{"ErrMissingToken", ErrMissingToken{}},
		{"ErrMissingTenantID", ErrMissingTenantID{}},
		{"ErrUserNotFound", ErrUserNotFound{}},
		{"ErrMFARequired", ErrMFARequired{}},
		{"ErrMFAExpired", ErrMFAExpired{}},
		{"ErrSessionInvalid", ErrSessionInvalid{}},
		{"ErrServiceUnavailable", ErrServiceUnavailable{Service: "test"}},
		{"ErrInvalidConfig", ErrInvalidConfig{Field: "test"}},
		{"ErrAudienceMismatch", ErrAudienceMismatch{}},
		{"ErrIssuerMismatch", ErrIssuerMismatch{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() == "" {
				t.Errorf("%s.Error() returned empty string", tt.name)
			}
		})
	}
}
