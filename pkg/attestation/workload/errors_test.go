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

package workload

import (
	"errors"
	"strings"
	"testing"
)

func TestErrChainNotInitialized(t *testing.T) {
	err := ErrChainNotInitialized{}
	errStr := err.Error()

	if !strings.Contains(errStr, "workload:") {
		t.Errorf("error should contain 'workload:': %s", errStr)
	}
	if !strings.Contains(errStr, "not initialized") {
		t.Errorf("error should contain 'not initialized': %s", errStr)
	}
}

func TestErrInvalidWorkloadType(t *testing.T) {
	t.Run("with type", func(t *testing.T) {
		err := ErrInvalidWorkloadType{Type: "invalid"}
		errStr := err.Error()

		if !strings.Contains(errStr, "workload:") {
			t.Errorf("error should contain 'workload:': %s", errStr)
		}
		if !strings.Contains(errStr, "invalid workload type") {
			t.Errorf("error should contain 'invalid workload type': %s", errStr)
		}
		if !strings.Contains(errStr, "invalid") {
			t.Errorf("error should contain the invalid type: %s", errStr)
		}
	})

	t.Run("without type", func(t *testing.T) {
		err := ErrInvalidWorkloadType{}
		errStr := err.Error()

		if !strings.Contains(errStr, "must be 'vm' or 'container'") {
			t.Errorf("error should contain valid types: %s", errStr)
		}
	})
}

func TestErrInvalidWorkloadID(t *testing.T) {
	t.Run("with reason", func(t *testing.T) {
		err := ErrInvalidWorkloadID{Reason: "cannot be empty"}
		errStr := err.Error()

		if !strings.Contains(errStr, "workload:") {
			t.Errorf("error should contain 'workload:': %s", errStr)
		}
		if !strings.Contains(errStr, "invalid workload ID") {
			t.Errorf("error should contain 'invalid workload ID': %s", errStr)
		}
		if !strings.Contains(errStr, "cannot be empty") {
			t.Errorf("error should contain reason: %s", errStr)
		}
	})

	t.Run("without reason", func(t *testing.T) {
		err := ErrInvalidWorkloadID{}
		errStr := err.Error()

		if errStr != "workload: invalid workload ID" {
			t.Errorf("error should be 'workload: invalid workload ID': %s", errStr)
		}
	})
}

func TestErrPCRExtensionFailed(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("TPM error")
		err := ErrPCRExtensionFailed{PCR: 14, Cause: cause}
		errStr := err.Error()

		if !strings.Contains(errStr, "PCR 14") {
			t.Errorf("error should contain 'PCR 14': %s", errStr)
		}
		if !strings.Contains(errStr, "extension failed") {
			t.Errorf("error should contain 'extension failed': %s", errStr)
		}
		if !strings.Contains(errStr, "TPM error") {
			t.Errorf("error should contain cause: %s", errStr)
		}

		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrPCRExtensionFailed{PCR: 14}
		errStr := err.Error()

		if !strings.Contains(errStr, "PCR 14 extension failed") {
			t.Errorf("error should be 'PCR 14 extension failed': %s", errStr)
		}
	})
}

func TestErrChainVerificationFailed(t *testing.T) {
	t.Run("with reason and cause", func(t *testing.T) {
		cause := errors.New("mismatch")
		err := ErrChainVerificationFailed{Reason: "PCR mismatch", Cause: cause}
		errStr := err.Error()

		if !strings.Contains(errStr, "verification failed") {
			t.Errorf("error should contain 'verification failed': %s", errStr)
		}
		if !strings.Contains(errStr, "PCR mismatch") {
			t.Errorf("error should contain reason: %s", errStr)
		}
		if !strings.Contains(errStr, "mismatch") {
			t.Errorf("error should contain cause: %s", errStr)
		}

		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("with reason only", func(t *testing.T) {
		err := ErrChainVerificationFailed{Reason: "invalid hash"}
		errStr := err.Error()

		if !strings.Contains(errStr, "invalid hash") {
			t.Errorf("error should contain reason: %s", errStr)
		}
	})

	t.Run("empty", func(t *testing.T) {
		err := ErrChainVerificationFailed{}
		errStr := err.Error()

		if errStr != "workload: chain verification failed" {
			t.Errorf("error should be base message: %s", errStr)
		}
	})
}

func TestErrTPMNotAvailable(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("device not found")
		err := ErrTPMNotAvailable{Cause: cause}
		errStr := err.Error()

		if !strings.Contains(errStr, "TPM not available") {
			t.Errorf("error should contain 'TPM not available': %s", errStr)
		}
		if !strings.Contains(errStr, "device not found") {
			t.Errorf("error should contain cause: %s", errStr)
		}

		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrTPMNotAvailable{}
		errStr := err.Error()

		if errStr != "workload: TPM not available" {
			t.Errorf("error should be 'workload: TPM not available': %s", errStr)
		}
	})
}

func TestErrInvalidConfig(t *testing.T) {
	t.Run("with field", func(t *testing.T) {
		err := ErrInvalidConfig{Field: "PCR", Reason: "out of range"}
		errStr := err.Error()

		if !strings.Contains(errStr, "invalid config") {
			t.Errorf("error should contain 'invalid config': %s", errStr)
		}
		if !strings.Contains(errStr, "PCR") {
			t.Errorf("error should contain field: %s", errStr)
		}
		if !strings.Contains(errStr, "out of range") {
			t.Errorf("error should contain reason: %s", errStr)
		}
	})

	t.Run("without field", func(t *testing.T) {
		err := ErrInvalidConfig{Reason: "missing required field"}
		errStr := err.Error()

		if !strings.Contains(errStr, "missing required field") {
			t.Errorf("error should contain reason: %s", errStr)
		}
	})
}

func TestErrPCRReadFailed(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("auth error")
		err := ErrPCRReadFailed{PCR: 10, Cause: cause}
		errStr := err.Error()

		if !strings.Contains(errStr, "PCR 10") {
			t.Errorf("error should contain 'PCR 10': %s", errStr)
		}
		if !strings.Contains(errStr, "read failed") {
			t.Errorf("error should contain 'read failed': %s", errStr)
		}
		if !strings.Contains(errStr, "auth error") {
			t.Errorf("error should contain cause: %s", errStr)
		}

		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrPCRReadFailed{PCR: 10}
		errStr := err.Error()

		if !strings.Contains(errStr, "PCR 10 read failed") {
			t.Errorf("error should be 'PCR 10 read failed': %s", errStr)
		}
	})
}

func TestErrInvalidHashAlgorithm(t *testing.T) {
	t.Run("with algorithm", func(t *testing.T) {
		err := ErrInvalidHashAlgorithm{Algorithm: "md5"}
		errStr := err.Error()

		if !strings.Contains(errStr, "invalid hash algorithm") {
			t.Errorf("error should contain 'invalid hash algorithm': %s", errStr)
		}
		if !strings.Contains(errStr, "md5") {
			t.Errorf("error should contain algorithm: %s", errStr)
		}
	})

	t.Run("without algorithm", func(t *testing.T) {
		err := ErrInvalidHashAlgorithm{}
		errStr := err.Error()

		if errStr != "workload: invalid hash algorithm" {
			t.Errorf("error should be 'workload: invalid hash algorithm': %s", errStr)
		}
	})
}

func TestErrContextCanceled(t *testing.T) {
	t.Run("with operation", func(t *testing.T) {
		err := ErrContextCanceled{Operation: "ExtendPCR"}
		errStr := err.Error()

		if !strings.Contains(errStr, "ExtendPCR") {
			t.Errorf("error should contain operation: %s", errStr)
		}
		if !strings.Contains(errStr, "canceled") {
			t.Errorf("error should contain 'canceled': %s", errStr)
		}
	})

	t.Run("without operation", func(t *testing.T) {
		err := ErrContextCanceled{}
		errStr := err.Error()

		if errStr != "workload: operation canceled" {
			t.Errorf("error should be 'workload: operation canceled': %s", errStr)
		}
	})
}

func TestErrChainEmpty(t *testing.T) {
	err := ErrChainEmpty{}
	errStr := err.Error()

	if !strings.Contains(errStr, "no entries") {
		t.Errorf("error should contain 'no entries': %s", errStr)
	}
}

func TestErrChainAlreadyInitialized(t *testing.T) {
	err := ErrChainAlreadyInitialized{}
	errStr := err.Error()

	if !strings.Contains(errStr, "already initialized") {
		t.Errorf("error should contain 'already initialized': %s", errStr)
	}
}

func TestErrLifecycleNotInitialized(t *testing.T) {
	err := ErrLifecycleNotInitialized{}
	errStr := err.Error()

	if !strings.Contains(errStr, "lifecycle manager") {
		t.Errorf("error should contain 'lifecycle manager': %s", errStr)
	}
	if !strings.Contains(errStr, "not initialized") {
		t.Errorf("error should contain 'not initialized': %s", errStr)
	}
}

func TestErrWorkloadNotFound(t *testing.T) {
	t.Run("with ID", func(t *testing.T) {
		err := ErrWorkloadNotFound{WorkloadID: "container-123"}
		errStr := err.Error()

		if !strings.Contains(errStr, "container-123") {
			t.Errorf("error should contain workload ID: %s", errStr)
		}
		if !strings.Contains(errStr, "not found") {
			t.Errorf("error should contain 'not found': %s", errStr)
		}
	})

	t.Run("without ID", func(t *testing.T) {
		err := ErrWorkloadNotFound{}
		errStr := err.Error()

		if errStr != "workload: workload not found" {
			t.Errorf("error should be 'workload: workload not found': %s", errStr)
		}
	})
}

// Test that all errors implement the error interface
func TestErrorsImplementErrorInterface(t *testing.T) {
	errs := []error{
		ErrChainNotInitialized{},
		ErrInvalidWorkloadType{Type: "invalid"},
		ErrInvalidWorkloadID{Reason: "empty"},
		ErrPCRExtensionFailed{PCR: 14, Cause: errors.New("test")},
		ErrChainVerificationFailed{Reason: "mismatch"},
		ErrTPMNotAvailable{Cause: errors.New("test")},
		ErrInvalidConfig{Field: "test", Reason: "invalid"},
		ErrPCRReadFailed{PCR: 10, Cause: errors.New("test")},
		ErrInvalidHashAlgorithm{Algorithm: "md5"},
		ErrContextCanceled{Operation: "test"},
		ErrChainEmpty{},
		ErrChainAlreadyInitialized{},
		ErrLifecycleNotInitialized{},
		ErrWorkloadNotFound{WorkloadID: "test"},
	}

	for _, err := range errs {
		if err.Error() == "" {
			t.Errorf("Error() returned empty string for %T", err)
		}
	}
}

// Test error unwrapping with errors.Is and errors.As
func TestErrorUnwrapping(t *testing.T) {
	baseErr := errors.New("base error")

	t.Run("PCRExtensionFailed", func(t *testing.T) {
		err := ErrPCRExtensionFailed{PCR: 14, Cause: baseErr}
		if !errors.Is(err, baseErr) {
			t.Error("errors.Is should find base error")
		}
	})

	t.Run("ChainVerificationFailed", func(t *testing.T) {
		err := ErrChainVerificationFailed{Cause: baseErr}
		if !errors.Is(err, baseErr) {
			t.Error("errors.Is should find base error")
		}
	})

	t.Run("TPMNotAvailable", func(t *testing.T) {
		err := ErrTPMNotAvailable{Cause: baseErr}
		if !errors.Is(err, baseErr) {
			t.Error("errors.Is should find base error")
		}
	})

	t.Run("PCRReadFailed", func(t *testing.T) {
		err := ErrPCRReadFailed{PCR: 10, Cause: baseErr}
		if !errors.Is(err, baseErr) {
			t.Error("errors.Is should find base error")
		}
	})

	t.Run("errors.As", func(t *testing.T) {
		err := ErrPCRExtensionFailed{PCR: 14, Cause: baseErr}
		var target ErrPCRExtensionFailed
		if !errors.As(err, &target) {
			t.Error("errors.As should match ErrPCRExtensionFailed")
		}
		if target.PCR != 14 {
			t.Errorf("PCR = %d, want 14", target.PCR)
		}
	})
}
