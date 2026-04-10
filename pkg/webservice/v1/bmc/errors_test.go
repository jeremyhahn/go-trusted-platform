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

package bmc

import (
	"errors"
	"strings"
	"testing"
)

func TestErrorMessages(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		contains string
	}{
		{"ErrInvalidProfileID/empty", ErrInvalidProfileID{}, "invalid profile id"},
		{"ErrInvalidProfileID/with_id", ErrInvalidProfileID{ID: "abc"}, "abc"},
		{"ErrMissingAction", ErrMissingAction{}, "action is required"},
		{"ErrInvalidAction", ErrInvalidAction{Action: "destroy"}, "destroy"},
		{"ErrMissingISOURL", ErrMissingISOURL{}, "iso_url is required"},
		{"ErrBMCServiceNotAvailable", ErrBMCServiceNotAvailable{}, "service not available"},
		{"ErrBaremetalServiceNotAvailable", ErrBaremetalServiceNotAvailable{}, "bare metal"},
		{"ErrInvalidRequestBody/empty", ErrInvalidRequestBody{}, "invalid request body"},
		{"ErrInvalidRequestBody/reason", ErrInvalidRequestBody{Reason: "bad json"}, "bad json"},
		{"ErrMissingLogger", ErrMissingLogger{}, "logger is required"},
		{"ErrMissingResponseWriter", ErrMissingResponseWriter{}, "response writer is required"},
		{"ErrMissingBMCService", ErrMissingBMCService{}, "bmc service is required"},
		{"ErrServiceError/with_cause", ErrServiceError{Operation: "test", Cause: errors.New("fail")}, "test failed: fail"},
		{"ErrServiceError/no_cause", ErrServiceError{Operation: "test"}, "test failed"},
		{"ErrMissingBootDevice", ErrMissingBootDevice{}, "device is required"},
		{"ErrInvalidBootDevice", ErrInvalidBootDevice{Device: "floppy"}, "floppy"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.err.Error()
			if !strings.Contains(msg, tc.contains) {
				t.Errorf("error message %q does not contain %q", msg, tc.contains)
			}
		})
	}
}

func TestErrServiceErrorUnwrap(t *testing.T) {
	cause := errors.New("root cause")
	err := ErrServiceError{Operation: "op", Cause: cause}
	if !errors.Is(err, cause) {
		t.Error("expected Unwrap to return the cause")
	}
}
