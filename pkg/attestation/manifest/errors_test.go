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

package manifest

import (
	"errors"
	"testing"
)

func TestErrManifestBuildFailed(t *testing.T) {
	t.Run("ErrorWithReason", func(t *testing.T) {
		err := ErrManifestBuildFailed{Reason: "test reason"}
		expected := "manifest: build failed: test reason"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("ErrorWithCause", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := ErrManifestBuildFailed{Reason: "test reason", Cause: cause}
		expected := "manifest: build failed: test reason: underlying error"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("ErrorEmpty", func(t *testing.T) {
		err := ErrManifestBuildFailed{}
		expected := "manifest: build failed"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("Unwrap", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := ErrManifestBuildFailed{Cause: cause}
		if err.Unwrap() != cause {
			t.Error("expected unwrap to return cause")
		}
	})
}

func TestErrManifestSignFailed(t *testing.T) {
	t.Run("ErrorWithReason", func(t *testing.T) {
		err := ErrManifestSignFailed{Reason: "test reason"}
		expected := "manifest: sign failed: test reason"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("ErrorWithCause", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := ErrManifestSignFailed{Cause: cause}
		expected := "manifest: sign failed: underlying error"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("Unwrap", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := ErrManifestSignFailed{Cause: cause}
		if err.Unwrap() != cause {
			t.Error("expected unwrap to return cause")
		}
	})
}

func TestErrManifestVerifyFailed(t *testing.T) {
	t.Run("ErrorWithReason", func(t *testing.T) {
		err := ErrManifestVerifyFailed{Reason: "test reason"}
		expected := "manifest: verification failed: test reason"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("ErrorWithCause", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := ErrManifestVerifyFailed{Reason: "test", Cause: cause}
		expected := "manifest: verification failed: test: underlying error"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("Unwrap", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := ErrManifestVerifyFailed{Cause: cause}
		if err.Unwrap() != cause {
			t.Error("expected unwrap to return cause")
		}
	})
}

func TestErrInvalidManifest(t *testing.T) {
	t.Run("ErrorWithFieldAndReason", func(t *testing.T) {
		err := ErrInvalidManifest{Field: "TestField", Reason: "test reason"}
		expected := "manifest: invalid manifest for TestField: test reason"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("ErrorWithReasonOnly", func(t *testing.T) {
		err := ErrInvalidManifest{Reason: "test reason"}
		expected := "manifest: invalid manifest: test reason"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("ErrorEmpty", func(t *testing.T) {
		err := ErrInvalidManifest{}
		expected := "manifest: invalid manifest"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})
}

func TestErrManifestExpired(t *testing.T) {
	t.Run("Error", func(t *testing.T) {
		err := ErrManifestExpired{Age: 600, MaxAge: 300}
		expected := "manifest: expired: age 600 seconds exceeds max 300 seconds"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})
}

func TestErrMerkleRootMismatch(t *testing.T) {
	t.Run("Error", func(t *testing.T) {
		err := ErrMerkleRootMismatch{
			Expected: []byte{0x01, 0x02, 0x03},
			Actual:   []byte{0x04, 0x05, 0x06},
		}
		expected := "manifest: Merkle root mismatch: expected 010203, got 040506"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})
}

func TestErrBuilderNotInitialized(t *testing.T) {
	t.Run("Error", func(t *testing.T) {
		err := ErrBuilderNotInitialized{}
		expected := "manifest: builder not initialized"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})
}

func TestErrSignerNotInitialized(t *testing.T) {
	t.Run("Error", func(t *testing.T) {
		err := ErrSignerNotInitialized{}
		expected := "manifest: signer not initialized"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})
}

func TestErrVerifierNotInitialized(t *testing.T) {
	t.Run("Error", func(t *testing.T) {
		err := ErrVerifierNotInitialized{}
		expected := "manifest: verifier not initialized"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})
}

func TestErrInvalidConfig(t *testing.T) {
	t.Run("ErrorWithField", func(t *testing.T) {
		err := ErrInvalidConfig{Field: "TestField", Reason: "test reason"}
		expected := "manifest: invalid config for TestField: test reason"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("ErrorWithoutField", func(t *testing.T) {
		err := ErrInvalidConfig{Reason: "test reason"}
		expected := "manifest: invalid config: test reason"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})
}

func TestErrContextCanceled(t *testing.T) {
	t.Run("ErrorWithOperation", func(t *testing.T) {
		err := ErrContextCanceled{Operation: "Build"}
		expected := "manifest: Build canceled"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("ErrorWithoutOperation", func(t *testing.T) {
		err := ErrContextCanceled{}
		expected := "manifest: operation canceled"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})
}

func TestErrNonceMismatch(t *testing.T) {
	t.Run("Error", func(t *testing.T) {
		err := ErrNonceMismatch{
			Expected: []byte{0x01, 0x02},
			Actual:   []byte{0x03, 0x04},
		}
		expected := "manifest: nonce mismatch: expected 0102, got 0304"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})
}

func TestErrTPMNotAvailable(t *testing.T) {
	t.Run("ErrorWithReason", func(t *testing.T) {
		err := ErrTPMNotAvailable{Reason: "device not found"}
		expected := "manifest: TPM not available: device not found"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("ErrorWithCause", func(t *testing.T) {
		cause := errors.New("io error")
		err := ErrTPMNotAvailable{Cause: cause}
		expected := "manifest: TPM not available: io error"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("ErrorEmpty", func(t *testing.T) {
		err := ErrTPMNotAvailable{}
		expected := "manifest: TPM not available"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("Unwrap", func(t *testing.T) {
		cause := errors.New("io error")
		err := ErrTPMNotAvailable{Cause: cause}
		if err.Unwrap() != cause {
			t.Error("expected unwrap to return cause")
		}
	})
}

func TestErrAKNotFound(t *testing.T) {
	t.Run("ErrorWithReason", func(t *testing.T) {
		err := ErrAKNotFound{Reason: "handle invalid"}
		expected := "manifest: AK not found: handle invalid"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("ErrorEmpty", func(t *testing.T) {
		err := ErrAKNotFound{}
		expected := "manifest: AK not found"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})
}

func TestErrSignatureInvalid(t *testing.T) {
	t.Run("ErrorWithReason", func(t *testing.T) {
		err := ErrSignatureInvalid{Reason: "verification failed"}
		expected := "manifest: signature invalid: verification failed"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("ErrorWithCause", func(t *testing.T) {
		cause := errors.New("crypto error")
		err := ErrSignatureInvalid{Reason: "test", Cause: cause}
		expected := "manifest: signature invalid: test: crypto error"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("Unwrap", func(t *testing.T) {
		cause := errors.New("crypto error")
		err := ErrSignatureInvalid{Cause: cause}
		if err.Unwrap() != cause {
			t.Error("expected unwrap to return cause")
		}
	})
}

func TestErrAttestationFailed(t *testing.T) {
	t.Run("ErrorFull", func(t *testing.T) {
		cause := errors.New("attestation error")
		err := ErrAttestationFailed{
			WorkloadType: "vm",
			WorkloadID:   "vm-123",
			Reason:       "quote failed",
			Cause:        cause,
		}
		expected := "manifest: attestation failed for vm vm-123: quote failed: attestation error"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("ErrorEmpty", func(t *testing.T) {
		err := ErrAttestationFailed{}
		expected := "manifest: attestation failed"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("Unwrap", func(t *testing.T) {
		cause := errors.New("attestation error")
		err := ErrAttestationFailed{Cause: cause}
		if err.Unwrap() != cause {
			t.Error("expected unwrap to return cause")
		}
	})
}

func TestErrInvalidHashAlgorithm(t *testing.T) {
	t.Run("ErrorWithAlgorithm", func(t *testing.T) {
		err := ErrInvalidHashAlgorithm{Algorithm: "md5"}
		expected := "manifest: invalid hash algorithm \"md5\""
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("ErrorEmpty", func(t *testing.T) {
		err := ErrInvalidHashAlgorithm{}
		expected := "manifest: invalid hash algorithm"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})
}

func TestErrHostNotAttested(t *testing.T) {
	t.Run("Error", func(t *testing.T) {
		err := ErrHostNotAttested{}
		expected := "manifest: host not attested"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})
}

func TestErrEmptyManifest(t *testing.T) {
	t.Run("Error", func(t *testing.T) {
		err := ErrEmptyManifest{}
		expected := "manifest: empty manifest (no attestations)"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})
}
