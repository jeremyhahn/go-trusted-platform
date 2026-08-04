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

package configdelivery

import (
	"errors"
	"testing"
)

func TestErrInvalidRequest_Error(t *testing.T) {
	err := ErrInvalidRequest{Reason: "missing field"}
	expected := "configdelivery: invalid request: missing field"
	if err.Error() != expected {
		t.Fatalf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrEABValidationFailed_Error(t *testing.T) {
	cause := errors.New("bad key")
	err := ErrEABValidationFailed{Cause: cause}
	expected := "configdelivery: eab validation failed: bad key"
	if err.Error() != expected {
		t.Fatalf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrEABValidationFailed_Unwrap(t *testing.T) {
	cause := errors.New("bad key")
	err := ErrEABValidationFailed{Cause: cause}
	if err.Unwrap() != cause {
		t.Fatal("expected Unwrap to return cause")
	}
}

func TestErrNonceExpired_Error(t *testing.T) {
	err := ErrNonceExpired{}
	if err.Error() == "" {
		t.Fatal("expected non-empty error string")
	}
}

func TestErrNonceRequired_Error(t *testing.T) {
	err := ErrNonceRequired{}
	if err.Error() == "" {
		t.Fatal("expected non-empty error string")
	}
}

func TestErrNonceGenerationFailed_Error(t *testing.T) {
	cause := errors.New("rand failure")
	err := ErrNonceGenerationFailed{Cause: cause}
	if err.Error() == "" {
		t.Fatal("expected non-empty error string")
	}
	if err.Unwrap() != cause {
		t.Fatal("expected Unwrap to return cause")
	}
}

func TestErrSessionNotFound_Error(t *testing.T) {
	err := ErrSessionNotFound{SessionID: "abc-123"}
	if err.Error() == "" {
		t.Fatal("expected non-empty error string")
	}
}

func TestErrSessionExpired_Error(t *testing.T) {
	err := ErrSessionExpired{SessionID: "abc-123"}
	if err.Error() == "" {
		t.Fatal("expected non-empty error string")
	}
}

func TestErrSessionAlreadyFulfilled_Error(t *testing.T) {
	err := ErrSessionAlreadyFulfilled{SessionID: "abc-123"}
	if err.Error() == "" {
		t.Fatal("expected non-empty error string")
	}
}

func TestErrSessionProfileMissing_Error(t *testing.T) {
	err := ErrSessionProfileMissing{SessionID: "sess-1"}
	expected := "configdelivery: session fulfilled without a resolved profile: sess-1"
	if err.Error() != expected {
		t.Fatalf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrHMACMismatch_Error(t *testing.T) {
	err := ErrHMACMismatch{}
	if err.Error() == "" {
		t.Fatal("expected non-empty error string")
	}
}

func TestErrProfileNotFound_Error(t *testing.T) {
	err := ErrProfileNotFound{ProfileID: 42}
	if err.Error() == "" {
		t.Fatal("expected non-empty error string")
	}
}

func TestErrMissingLogger_Error(t *testing.T) {
	err := ErrMissingLogger{}
	if err.Error() == "" {
		t.Fatal("expected non-empty error string")
	}
}

func TestErrMissingProfileService_Error(t *testing.T) {
	err := ErrMissingProfileService{}
	if err.Error() == "" {
		t.Fatal("expected non-empty error string")
	}
}

func TestErrMissingEABService_Error(t *testing.T) {
	err := ErrMissingEABService{}
	if err.Error() == "" {
		t.Fatal("expected non-empty error string")
	}
}

func TestErrMissingResponseWriter_Error(t *testing.T) {
	err := ErrMissingResponseWriter{}
	if err.Error() == "" {
		t.Fatal("expected non-empty error string")
	}
}

func TestErrMissingService_Error(t *testing.T) {
	err := ErrMissingService{}
	if err.Error() == "" {
		t.Fatal("expected non-empty error string")
	}
}
