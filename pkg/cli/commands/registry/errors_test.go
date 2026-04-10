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

package registry

import (
	"errors"
	"testing"
)

func TestErrRegistryClientNotInitialized(t *testing.T) {
	err := ErrRegistryClientNotInitialized{}
	expected := "registry client not initialized"

	if err.Error() != expected {
		t.Errorf("ErrRegistryClientNotInitialized.Error() = %q, want %q", err.Error(), expected)
	}
}

func TestErrPushFailed(t *testing.T) {
	t.Run("with underlying error", func(t *testing.T) {
		underlying := errors.New("network error")
		err := ErrPushFailed{Reference: "myrepo/myimage:v1.0", Err: underlying}
		expected := "failed to push image myrepo/myimage:v1.0: network error"

		if err.Error() != expected {
			t.Errorf("ErrPushFailed.Error() = %q, want %q", err.Error(), expected)
		}

		if err.Unwrap() != underlying {
			t.Errorf("ErrPushFailed.Unwrap() = %v, want %v", err.Unwrap(), underlying)
		}
	})

	t.Run("without underlying error", func(t *testing.T) {
		err := ErrPushFailed{Reference: "myrepo/myimage:v1.0"}
		expected := "failed to push image myrepo/myimage:v1.0"

		if err.Error() != expected {
			t.Errorf("ErrPushFailed.Error() = %q, want %q", err.Error(), expected)
		}

		if err.Unwrap() != nil {
			t.Errorf("ErrPushFailed.Unwrap() = %v, want nil", err.Unwrap())
		}
	})
}

func TestErrPullFailed(t *testing.T) {
	t.Run("with underlying error", func(t *testing.T) {
		underlying := errors.New("not found")
		err := ErrPullFailed{Reference: "myrepo/myimage:v1.0", Err: underlying}
		expected := "failed to pull image myrepo/myimage:v1.0: not found"

		if err.Error() != expected {
			t.Errorf("ErrPullFailed.Error() = %q, want %q", err.Error(), expected)
		}

		if err.Unwrap() != underlying {
			t.Errorf("ErrPullFailed.Unwrap() = %v, want %v", err.Unwrap(), underlying)
		}
	})

	t.Run("without underlying error", func(t *testing.T) {
		err := ErrPullFailed{Reference: "myrepo/myimage:v1.0"}
		expected := "failed to pull image myrepo/myimage:v1.0"

		if err.Error() != expected {
			t.Errorf("ErrPullFailed.Error() = %q, want %q", err.Error(), expected)
		}
	})
}

func TestErrDeleteFailed(t *testing.T) {
	t.Run("with underlying error", func(t *testing.T) {
		underlying := errors.New("permission denied")
		err := ErrDeleteFailed{Reference: "myrepo/myimage:v1.0", Err: underlying}
		expected := "failed to delete image myrepo/myimage:v1.0: permission denied"

		if err.Error() != expected {
			t.Errorf("ErrDeleteFailed.Error() = %q, want %q", err.Error(), expected)
		}

		if err.Unwrap() != underlying {
			t.Errorf("ErrDeleteFailed.Unwrap() = %v, want %v", err.Unwrap(), underlying)
		}
	})

	t.Run("without underlying error", func(t *testing.T) {
		err := ErrDeleteFailed{Reference: "myrepo/myimage:v1.0"}
		expected := "failed to delete image myrepo/myimage:v1.0"

		if err.Error() != expected {
			t.Errorf("ErrDeleteFailed.Error() = %q, want %q", err.Error(), expected)
		}
	})
}

func TestErrListFailed(t *testing.T) {
	t.Run("with underlying error", func(t *testing.T) {
		underlying := errors.New("timeout")
		err := ErrListFailed{Err: underlying}
		expected := "failed to list images: timeout"

		if err.Error() != expected {
			t.Errorf("ErrListFailed.Error() = %q, want %q", err.Error(), expected)
		}

		if err.Unwrap() != underlying {
			t.Errorf("ErrListFailed.Unwrap() = %v, want %v", err.Unwrap(), underlying)
		}
	})

	t.Run("without underlying error", func(t *testing.T) {
		err := ErrListFailed{}
		expected := "failed to list images"

		if err.Error() != expected {
			t.Errorf("ErrListFailed.Error() = %q, want %q", err.Error(), expected)
		}
	})
}

func TestErrInspectFailed(t *testing.T) {
	t.Run("with underlying error", func(t *testing.T) {
		underlying := errors.New("manifest not found")
		err := ErrInspectFailed{Reference: "myrepo/myimage:v1.0", Err: underlying}
		expected := "failed to inspect image myrepo/myimage:v1.0: manifest not found"

		if err.Error() != expected {
			t.Errorf("ErrInspectFailed.Error() = %q, want %q", err.Error(), expected)
		}

		if err.Unwrap() != underlying {
			t.Errorf("ErrInspectFailed.Unwrap() = %v, want %v", err.Unwrap(), underlying)
		}
	})

	t.Run("without underlying error", func(t *testing.T) {
		err := ErrInspectFailed{Reference: "myrepo/myimage:v1.0"}
		expected := "failed to inspect image myrepo/myimage:v1.0"

		if err.Error() != expected {
			t.Errorf("ErrInspectFailed.Error() = %q, want %q", err.Error(), expected)
		}
	})
}

func TestErrStatusFailed(t *testing.T) {
	t.Run("with underlying error", func(t *testing.T) {
		underlying := errors.New("connection refused")
		err := ErrStatusFailed{Err: underlying}
		expected := "failed to get registry status: connection refused"

		if err.Error() != expected {
			t.Errorf("ErrStatusFailed.Error() = %q, want %q", err.Error(), expected)
		}

		if err.Unwrap() != underlying {
			t.Errorf("ErrStatusFailed.Unwrap() = %v, want %v", err.Unwrap(), underlying)
		}
	})

	t.Run("without underlying error", func(t *testing.T) {
		err := ErrStatusFailed{}
		expected := "failed to get registry status"

		if err.Error() != expected {
			t.Errorf("ErrStatusFailed.Error() = %q, want %q", err.Error(), expected)
		}
	})
}

func TestErrAttestationFailed(t *testing.T) {
	t.Run("with reason and error", func(t *testing.T) {
		underlying := errors.New("TPM error")
		err := ErrAttestationFailed{Reason: "quote generation failed", Err: underlying}
		expected := "attestation failed: quote generation failed: TPM error"

		if err.Error() != expected {
			t.Errorf("ErrAttestationFailed.Error() = %q, want %q", err.Error(), expected)
		}

		if err.Unwrap() != underlying {
			t.Errorf("ErrAttestationFailed.Unwrap() = %v, want %v", err.Unwrap(), underlying)
		}
	})

	t.Run("with error only", func(t *testing.T) {
		underlying := errors.New("TPM error")
		err := ErrAttestationFailed{Err: underlying}
		expected := "attestation failed: TPM error"

		if err.Error() != expected {
			t.Errorf("ErrAttestationFailed.Error() = %q, want %q", err.Error(), expected)
		}
	})

	t.Run("with reason only", func(t *testing.T) {
		err := ErrAttestationFailed{Reason: "PCR mismatch"}
		expected := "attestation failed: PCR mismatch"

		if err.Error() != expected {
			t.Errorf("ErrAttestationFailed.Error() = %q, want %q", err.Error(), expected)
		}
	})

	t.Run("without reason or error", func(t *testing.T) {
		err := ErrAttestationFailed{}
		expected := "attestation failed"

		if err.Error() != expected {
			t.Errorf("ErrAttestationFailed.Error() = %q, want %q", err.Error(), expected)
		}
	})
}

func TestErrEncryptionKeyRequired(t *testing.T) {
	err := ErrEncryptionKeyRequired{}
	expected := "encryption key ID is required when --encrypt is specified"

	if err.Error() != expected {
		t.Errorf("ErrEncryptionKeyRequired.Error() = %q, want %q", err.Error(), expected)
	}
}

func TestErrInvalidImageReference(t *testing.T) {
	t.Run("with reason", func(t *testing.T) {
		err := ErrInvalidImageReference{Reference: "INVALID", Reason: "uppercase not allowed"}
		expected := `invalid image reference "INVALID": uppercase not allowed`

		if err.Error() != expected {
			t.Errorf("ErrInvalidImageReference.Error() = %q, want %q", err.Error(), expected)
		}
	})

	t.Run("without reason", func(t *testing.T) {
		err := ErrInvalidImageReference{Reference: "invalid ref"}
		expected := `invalid image reference: "invalid ref"`

		if err.Error() != expected {
			t.Errorf("ErrInvalidImageReference.Error() = %q, want %q", err.Error(), expected)
		}
	})
}

func TestErrInvalidFormat(t *testing.T) {
	err := ErrInvalidFormat{Format: "xml"}
	expected := "invalid format: xml (valid: json, yaml, table)"

	if err.Error() != expected {
		t.Errorf("ErrInvalidFormat.Error() = %q, want %q", err.Error(), expected)
	}
}

func TestErrorsImplementError(t *testing.T) {
	// Ensure all error types implement the error interface
	var _ error = ErrRegistryClientNotInitialized{}
	var _ error = ErrPushFailed{}
	var _ error = ErrPullFailed{}
	var _ error = ErrDeleteFailed{}
	var _ error = ErrListFailed{}
	var _ error = ErrInspectFailed{}
	var _ error = ErrStatusFailed{}
	var _ error = ErrAttestationFailed{}
	var _ error = ErrEncryptionKeyRequired{}
	var _ error = ErrInvalidImageReference{}
	var _ error = ErrInvalidFormat{}
}

func TestUnwrapErrors(t *testing.T) {
	underlying := errors.New("test error")

	tests := []struct {
		name string
		err  error
	}{
		{"ErrPushFailed", ErrPushFailed{Reference: "test", Err: underlying}},
		{"ErrPullFailed", ErrPullFailed{Reference: "test", Err: underlying}},
		{"ErrDeleteFailed", ErrDeleteFailed{Reference: "test", Err: underlying}},
		{"ErrListFailed", ErrListFailed{Err: underlying}},
		{"ErrInspectFailed", ErrInspectFailed{Reference: "test", Err: underlying}},
		{"ErrStatusFailed", ErrStatusFailed{Err: underlying}},
		{"ErrAttestationFailed", ErrAttestationFailed{Err: underlying}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unwrapped := errors.Unwrap(tt.err)
			if unwrapped != underlying {
				t.Errorf("errors.Unwrap(%T) = %v, want %v", tt.err, unwrapped, underlying)
			}
		})
	}
}

func TestErrorsIs(t *testing.T) {
	underlying := errors.New("test error")
	pushErr := ErrPushFailed{Reference: "test", Err: underlying}

	// errors.Is should work with Unwrap
	if !errors.Is(pushErr, underlying) {
		t.Error("errors.Is should find underlying error")
	}
}

func TestZeroValueErrors(t *testing.T) {
	// Test that zero-value errors still produce reasonable messages
	t.Run("ErrPushFailed zero", func(t *testing.T) {
		err := ErrPushFailed{}
		if err.Error() == "" {
			t.Error("zero-value ErrPushFailed should produce non-empty message")
		}
	})

	t.Run("ErrPullFailed zero", func(t *testing.T) {
		err := ErrPullFailed{}
		if err.Error() == "" {
			t.Error("zero-value ErrPullFailed should produce non-empty message")
		}
	})

	t.Run("ErrInvalidImageReference zero", func(t *testing.T) {
		err := ErrInvalidImageReference{}
		if err.Error() == "" {
			t.Error("zero-value ErrInvalidImageReference should produce non-empty message")
		}
	})
}
