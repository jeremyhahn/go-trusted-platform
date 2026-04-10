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

package noise

import (
	"errors"
	"testing"
)

func TestErrServerNotStarted_Error(t *testing.T) {
	err := &ErrServerNotStarted{}
	want := "noise: server not started"
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

func TestErrServerAlreadyStarted_Error(t *testing.T) {
	err := &ErrServerAlreadyStarted{}
	want := "noise: server already started"
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

func TestErrServerStartFailed_Error(t *testing.T) {
	cause := errors.New("bind failed")
	err := &ErrServerStartFailed{Cause: cause}
	want := "noise: server start failed: bind failed"
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

func TestErrServerStartFailed_Unwrap(t *testing.T) {
	cause := errors.New("bind failed")
	err := &ErrServerStartFailed{Cause: cause}
	if err.Unwrap() != cause {
		t.Errorf("Unwrap returned %v, want %v", err.Unwrap(), cause)
	}
}

func TestErrServerStopFailed_Error(t *testing.T) {
	cause := errors.New("shutdown error")
	err := &ErrServerStopFailed{Cause: cause}
	want := "noise: server stop failed: shutdown error"
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

func TestErrServerStopFailed_Unwrap(t *testing.T) {
	cause := errors.New("shutdown error")
	err := &ErrServerStopFailed{Cause: cause}
	if err.Unwrap() != cause {
		t.Errorf("Unwrap returned %v, want %v", err.Unwrap(), cause)
	}
}

func TestErrNilConfig_Error(t *testing.T) {
	err := &ErrNilConfig{}
	want := "noise: configuration is nil"
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

func TestErrNilBundleProvider_Error(t *testing.T) {
	err := &ErrNilBundleProvider{}
	want := "noise: bundle provider is nil"
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

func TestErrNilLogger_Error(t *testing.T) {
	err := &ErrNilLogger{}
	want := "noise: logger is nil"
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

func TestErrKeyGenerationFailed_Error(t *testing.T) {
	cause := errors.New("entropy exhausted")
	err := &ErrKeyGenerationFailed{Cause: cause}
	want := "noise: key generation failed: entropy exhausted"
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

func TestErrKeyGenerationFailed_Unwrap(t *testing.T) {
	cause := errors.New("entropy exhausted")
	err := &ErrKeyGenerationFailed{Cause: cause}
	if err.Unwrap() != cause {
		t.Errorf("Unwrap returned %v, want %v", err.Unwrap(), cause)
	}
}

func TestErrorTypes_ImplementError(t *testing.T) {
	// Compile-time interface checks are in the type definitions,
	// but verify at runtime that all types satisfy the error interface.
	var errs []error
	errs = append(errs, &ErrServerNotStarted{})
	errs = append(errs, &ErrServerAlreadyStarted{})
	errs = append(errs, &ErrServerStartFailed{Cause: errors.New("x")})
	errs = append(errs, &ErrServerStopFailed{Cause: errors.New("x")})
	errs = append(errs, &ErrNilConfig{})
	errs = append(errs, &ErrNilBundleProvider{})
	errs = append(errs, &ErrNilLogger{})
	errs = append(errs, &ErrKeyGenerationFailed{Cause: errors.New("x")})

	for _, err := range errs {
		if err.Error() == "" {
			t.Errorf("Error() returned empty string for %T", err)
		}
	}
}
