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

package compute

import (
	"errors"
	"testing"
)

func TestErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"ErrInstanceNotFound", ErrInstanceNotFound},
		{"ErrInstanceAlreadyExists", ErrInstanceAlreadyExists},
		{"ErrInstanceNotRunning", ErrInstanceNotRunning},
		{"ErrInstanceAlreadyRunning", ErrInstanceAlreadyRunning},
		{"ErrInvalidConfiguration", ErrInvalidConfiguration},
		{"ErrInvalidInstanceID", ErrInvalidInstanceID},
		{"ErrInvalidProfile", ErrInvalidProfile},
		{"ErrNetworkAttachmentFailed", ErrNetworkAttachmentFailed},
		{"ErrNetworkDetachmentFailed", ErrNetworkDetachmentFailed},
		{"ErrOrchestratorNotInitialized", ErrOrchestratorNotInitialized},
		{"ErrUnsupportedOperation", ErrUnsupportedOperation},
		{"ErrInvalidState", ErrInvalidState},
		{"ErrTimeout", ErrTimeout},
		{"ErrResourceExhausted", ErrResourceExhausted},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Errorf("%s should not be nil", tt.name)
			}
			if tt.err.Error() == "" {
				t.Errorf("%s should have a non-empty error message", tt.name)
			}
		})
	}
}

func TestErrorEquality(t *testing.T) {
	// Test that errors are sentinel values
	if !errors.Is(ErrInstanceNotFound, ErrInstanceNotFound) {
		t.Error("ErrInstanceNotFound should equal itself")
	}

	if errors.Is(ErrInstanceNotFound, ErrInstanceAlreadyExists) {
		t.Error("Different errors should not be equal")
	}
}

func TestErrorWrapping(t *testing.T) {
	// Test that our errors can be wrapped
	wrappedErr := errors.Join(ErrInstanceNotFound, errors.New("additional context"))
	if wrappedErr == nil {
		t.Error("Wrapped error should not be nil")
	}

	if !errors.Is(wrappedErr, ErrInstanceNotFound) {
		t.Error("Wrapped error should be detected by errors.Is")
	}
}
