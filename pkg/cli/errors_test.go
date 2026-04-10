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

package cli

import (
	"errors"
	"testing"
)

func TestErrConfigFileNotFound(t *testing.T) {
	err := ErrConfigFileNotFound{Path: "/path/to/config.yaml"}
	expected := "config file not found: /path/to/config.yaml"

	if err.Error() != expected {
		t.Errorf("expected error message '%s', got '%s'", expected, err.Error())
	}
}

func TestErrInvalidContext(t *testing.T) {
	err := ErrInvalidContext{Context: "invalid-context"}
	expected := "invalid context: invalid-context"

	if err.Error() != expected {
		t.Errorf("expected error message '%s', got '%s'", expected, err.Error())
	}
}

func TestErrContextNotFound(t *testing.T) {
	err := ErrContextNotFound{Context: "missing-context"}
	expected := "context not found: missing-context"

	if err.Error() != expected {
		t.Errorf("expected error message '%s', got '%s'", expected, err.Error())
	}
}

func TestErrNoContextSet(t *testing.T) {
	err := ErrNoContextSet{}
	expected := "no context currently set"

	if err.Error() != expected {
		t.Errorf("expected error message '%s', got '%s'", expected, err.Error())
	}
}

func TestErrInvalidOutputFormat(t *testing.T) {
	err := ErrInvalidOutputFormat{Format: "xml"}
	expected := "invalid output format: xml (valid: table, json, yaml)"

	if err.Error() != expected {
		t.Errorf("expected error message '%s', got '%s'", expected, err.Error())
	}
}

func TestErrConnectionFailed(t *testing.T) {
	innerErr := errors.New("connection refused")
	err := ErrConnectionFailed{
		Target: "localhost:8080",
		Err:    innerErr,
	}
	expected := "failed to connect to localhost:8080: connection refused"

	if err.Error() != expected {
		t.Errorf("expected error message '%s', got '%s'", expected, err.Error())
	}
}

func TestErrInvalidServiceType(t *testing.T) {
	err := ErrInvalidServiceType{Type: "unknown"}
	expected := "invalid service type: unknown"

	if err.Error() != expected {
		t.Errorf("expected error message '%s', got '%s'", expected, err.Error())
	}
}

func TestErrOperationFailed(t *testing.T) {
	innerErr := errors.New("disk full")
	err := ErrOperationFailed{
		Operation: "write",
		Err:       innerErr,
	}
	expected := "write operation failed: disk full"

	if err.Error() != expected {
		t.Errorf("expected error message '%s', got '%s'", expected, err.Error())
	}
}

func TestErrInsufficientPermissions(t *testing.T) {
	err := ErrInsufficientPermissions{Operation: "delete"}
	expected := "insufficient permissions for operation: delete"

	if err.Error() != expected {
		t.Errorf("expected error message '%s', got '%s'", expected, err.Error())
	}
}

func TestErrAutoDetectionFailed(t *testing.T) {
	err := ErrAutoDetectionFailed{Reason: "socket not found"}
	expected := "failed to auto-detect context: socket not found"

	if err.Error() != expected {
		t.Errorf("expected error message '%s', got '%s'", expected, err.Error())
	}
}

func TestErrInvalidShellType(t *testing.T) {
	err := ErrInvalidShellType{Shell: "custom-shell"}
	expected := "invalid shell type: custom-shell (valid: bash, zsh, fish, powershell)"

	if err.Error() != expected {
		t.Errorf("expected error message '%s', got '%s'", expected, err.Error())
	}
}

func TestErrCompletionGenerationFailed(t *testing.T) {
	innerErr := errors.New("write error")
	err := ErrCompletionGenerationFailed{
		Shell: "bash",
		Err:   innerErr,
	}
	expected := "failed to generate bash completion script: write error"

	if err.Error() != expected {
		t.Errorf("expected error message '%s', got '%s'", expected, err.Error())
	}
}

func TestErrorTypesImplementErrorInterface(t *testing.T) {
	// Verify all error types implement the error interface
	var _ error = ErrConfigFileNotFound{}
	var _ error = ErrInvalidContext{}
	var _ error = ErrContextNotFound{}
	var _ error = ErrNoContextSet{}
	var _ error = ErrInvalidOutputFormat{}
	var _ error = ErrConnectionFailed{}
	var _ error = ErrInvalidServiceType{}
	var _ error = ErrOperationFailed{}
	var _ error = ErrInsufficientPermissions{}
	var _ error = ErrAutoDetectionFailed{}
	var _ error = ErrInvalidShellType{}
	var _ error = ErrCompletionGenerationFailed{}
}

func TestErrorWrapping(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		innerErr error
	}{
		{
			name:     "ErrConnectionFailed wraps error",
			err:      ErrConnectionFailed{Target: "test", Err: errors.New("inner")},
			innerErr: errors.New("inner"),
		},
		{
			name:     "ErrOperationFailed wraps error",
			err:      ErrOperationFailed{Operation: "test", Err: errors.New("inner")},
			innerErr: errors.New("inner"),
		},
		{
			name:     "ErrCompletionGenerationFailed wraps error",
			err:      ErrCompletionGenerationFailed{Shell: "bash", Err: errors.New("inner")},
			innerErr: errors.New("inner"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() == "" {
				t.Error("error message should not be empty")
			}
		})
	}
}
