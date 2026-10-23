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

package vm

import (
	"errors"
	"strings"
	"testing"
)

func TestErrQuoteGenerationFailed(t *testing.T) {
	t.Run("with reason and cause", func(t *testing.T) {
		cause := errors.New("TPM error")
		err := ErrQuoteGenerationFailed{Reason: "failed to sign", Cause: cause}
		errStr := err.Error()

		if !strings.Contains(errStr, "vm:") {
			t.Errorf("error should contain 'vm:': %s", errStr)
		}
		if !strings.Contains(errStr, "quote generation failed") {
			t.Errorf("error should contain 'quote generation failed': %s", errStr)
		}
		if !strings.Contains(errStr, "failed to sign") {
			t.Errorf("error should contain reason: %s", errStr)
		}
		if !strings.Contains(errStr, "TPM error") {
			t.Errorf("error should contain cause: %s", errStr)
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("with reason only", func(t *testing.T) {
		err := ErrQuoteGenerationFailed{Reason: "AIK not available"}
		errStr := err.Error()

		if !strings.Contains(errStr, "AIK not available") {
			t.Errorf("error should contain reason: %s", errStr)
		}
	})

	t.Run("empty", func(t *testing.T) {
		err := ErrQuoteGenerationFailed{}
		errStr := err.Error()

		if errStr != "vm: quote generation failed" {
			t.Errorf("error should be base message: %s", errStr)
		}
	})
}

func TestErrQuoteVerificationFailed(t *testing.T) {
	t.Run("with reason and cause", func(t *testing.T) {
		cause := errors.New("signature invalid")
		err := ErrQuoteVerificationFailed{Reason: "verification error", Cause: cause}
		errStr := err.Error()

		if !strings.Contains(errStr, "quote verification failed") {
			t.Errorf("error should contain 'quote verification failed': %s", errStr)
		}
		if !strings.Contains(errStr, "verification error") {
			t.Errorf("error should contain reason: %s", errStr)
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("empty", func(t *testing.T) {
		err := ErrQuoteVerificationFailed{}
		if err.Error() != "vm: quote verification failed" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})
}

func TestErrInvalidVMIdentity(t *testing.T) {
	t.Run("with all fields", func(t *testing.T) {
		err := ErrInvalidVMIdentity{VMID: "vm-123", HostID: "host-456", Reason: "malformed"}
		errStr := err.Error()

		if !strings.Contains(errStr, "invalid VM identity") {
			t.Errorf("error should contain 'invalid VM identity': %s", errStr)
		}
		if !strings.Contains(errStr, "malformed") {
			t.Errorf("error should contain reason: %s", errStr)
		}
		if !strings.Contains(errStr, "vm-123") {
			t.Errorf("error should contain vmID: %s", errStr)
		}
		if !strings.Contains(errStr, "host-456") {
			t.Errorf("error should contain hostID: %s", errStr)
		}
	})

	t.Run("with reason only", func(t *testing.T) {
		err := ErrInvalidVMIdentity{Reason: "empty vmID"}
		errStr := err.Error()

		if !strings.Contains(errStr, "empty vmID") {
			t.Errorf("error should contain reason: %s", errStr)
		}
	})

	t.Run("empty", func(t *testing.T) {
		err := ErrInvalidVMIdentity{}
		if err.Error() != "vm: invalid VM identity" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})
}

func TestErrEKCertificateInvalid(t *testing.T) {
	t.Run("with reason and cause", func(t *testing.T) {
		cause := errors.New("parse error")
		err := ErrEKCertificateInvalid{Reason: "malformed DER", Cause: cause}
		errStr := err.Error()

		if !strings.Contains(errStr, "EK certificate invalid") {
			t.Errorf("error should contain 'EK certificate invalid': %s", errStr)
		}
		if !strings.Contains(errStr, "malformed DER") {
			t.Errorf("error should contain reason: %s", errStr)
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("empty", func(t *testing.T) {
		err := ErrEKCertificateInvalid{}
		if err.Error() != "vm: EK certificate invalid" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})
}

func TestErrPCRMismatch(t *testing.T) {
	err := ErrPCRMismatch{
		PCRIndex:      14,
		ExpectedValue: []byte{0x01, 0x02, 0x03},
		ActualValue:   []byte{0x04, 0x05, 0x06},
	}
	errStr := err.Error()

	if !strings.Contains(errStr, "PCR 14") {
		t.Errorf("error should contain 'PCR 14': %s", errStr)
	}
	if !strings.Contains(errStr, "mismatch") {
		t.Errorf("error should contain 'mismatch': %s", errStr)
	}
	if !strings.Contains(errStr, "010203") {
		t.Errorf("error should contain expected value: %s", errStr)
	}
	if !strings.Contains(errStr, "040506") {
		t.Errorf("error should contain actual value: %s", errStr)
	}
}

func TestErrNonceMismatch(t *testing.T) {
	err := ErrNonceMismatch{
		Expected: []byte{0xaa, 0xbb},
		Actual:   []byte{0xcc, 0xdd},
	}
	errStr := err.Error()

	if !strings.Contains(errStr, "nonce mismatch") {
		t.Errorf("error should contain 'nonce mismatch': %s", errStr)
	}
	if !strings.Contains(errStr, "aabb") {
		t.Errorf("error should contain expected nonce: %s", errStr)
	}
	if !strings.Contains(errStr, "ccdd") {
		t.Errorf("error should contain actual nonce: %s", errStr)
	}
}

func TestErrVTPMNotAvailable(t *testing.T) {
	t.Run("with reason and cause", func(t *testing.T) {
		cause := errors.New("device not found")
		err := ErrVTPMNotAvailable{Reason: "device path invalid", Cause: cause}
		errStr := err.Error()

		if !strings.Contains(errStr, "vTPM not available") {
			t.Errorf("error should contain 'vTPM not available': %s", errStr)
		}
		if !strings.Contains(errStr, "device path invalid") {
			t.Errorf("error should contain reason: %s", errStr)
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("empty", func(t *testing.T) {
		err := ErrVTPMNotAvailable{}
		if err.Error() != "vm: vTPM not available" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})
}

func TestErrAIKNotFound(t *testing.T) {
	t.Run("with reason", func(t *testing.T) {
		err := ErrAIKNotFound{Reason: "handle not loaded"}
		errStr := err.Error()

		if !strings.Contains(errStr, "AIK/AK not found") {
			t.Errorf("error should contain 'AIK/AK not found': %s", errStr)
		}
		if !strings.Contains(errStr, "handle not loaded") {
			t.Errorf("error should contain reason: %s", errStr)
		}
	})

	t.Run("empty", func(t *testing.T) {
		err := ErrAIKNotFound{}
		if err.Error() != "vm: AIK/AK not found" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})
}

func TestErrAttestorNotInitialized(t *testing.T) {
	err := ErrAttestorNotInitialized{}
	errStr := err.Error()

	if !strings.Contains(errStr, "attestor not initialized") {
		t.Errorf("error should contain 'attestor not initialized': %s", errStr)
	}
}

func TestErrVerifierNotInitialized(t *testing.T) {
	err := ErrVerifierNotInitialized{}
	errStr := err.Error()

	if !strings.Contains(errStr, "verifier not initialized") {
		t.Errorf("error should contain 'verifier not initialized': %s", errStr)
	}
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

func TestErrContextCanceled(t *testing.T) {
	t.Run("with operation", func(t *testing.T) {
		err := ErrContextCanceled{Operation: "GenerateQuote"}
		errStr := err.Error()

		if !strings.Contains(errStr, "GenerateQuote") {
			t.Errorf("error should contain operation: %s", errStr)
		}
		if !strings.Contains(errStr, "canceled") {
			t.Errorf("error should contain 'canceled': %s", errStr)
		}
	})

	t.Run("empty", func(t *testing.T) {
		err := ErrContextCanceled{}
		if err.Error() != "vm: operation canceled" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})
}

func TestErrCertificateChainInvalid(t *testing.T) {
	t.Run("with reason and cause", func(t *testing.T) {
		cause := errors.New("expired")
		err := ErrCertificateChainInvalid{Reason: "chain broken", Cause: cause}
		errStr := err.Error()

		if !strings.Contains(errStr, "certificate chain invalid") {
			t.Errorf("error should contain 'certificate chain invalid': %s", errStr)
		}
		if !strings.Contains(errStr, "chain broken") {
			t.Errorf("error should contain reason: %s", errStr)
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("empty", func(t *testing.T) {
		err := ErrCertificateChainInvalid{}
		if err.Error() != "vm: certificate chain invalid" {
			t.Errorf("unexpected error message: %s", err.Error())
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

	t.Run("empty", func(t *testing.T) {
		err := ErrInvalidHashAlgorithm{}
		if err.Error() != "vm: invalid hash algorithm" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})
}

func TestErrSignatureInvalid(t *testing.T) {
	t.Run("with reason and cause", func(t *testing.T) {
		cause := errors.New("crypto error")
		err := ErrSignatureInvalid{Reason: "verification failed", Cause: cause}
		errStr := err.Error()

		if !strings.Contains(errStr, "signature invalid") {
			t.Errorf("error should contain 'signature invalid': %s", errStr)
		}
		if !strings.Contains(errStr, "verification failed") {
			t.Errorf("error should contain reason: %s", errStr)
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("empty", func(t *testing.T) {
		err := ErrSignatureInvalid{}
		if err.Error() != "vm: signature invalid" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})
}

func TestErrUnsupportedSignatureAlgorithm(t *testing.T) {
	err := ErrUnsupportedSignatureAlgorithm{Algorithm: "SHA1-RSA"}
	if err.Error() != `vm: unsupported quote signature algorithm "SHA1-RSA"` {
		t.Errorf("unexpected error message: %s", err.Error())
	}
	if (ErrUnsupportedSignatureAlgorithm{}).Error() != `vm: unsupported quote signature algorithm ""` {
		t.Errorf("an undeclared algorithm must show as empty: %s", ErrUnsupportedSignatureAlgorithm{}.Error())
	}
}

func TestErrSignatureSchemeMismatch(t *testing.T) {
	err := ErrSignatureSchemeMismatch{Scheme: "RSASSA-PSS", KeyType: "*ecdsa.PublicKey"}
	if err.Error() != "vm: RSASSA-PSS quote signature cannot be verified with a *ecdsa.PublicKey AK" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestErrQuoteSchemeUnavailable(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("TPM_RC_HANDLE")
		err := ErrQuoteSchemeUnavailable{Cause: cause}
		if err.Error() != "vm: IAK signature scheme unavailable: TPM_RC_HANDLE" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
		if !errors.Is(err, cause) {
			t.Error("expected error to unwrap to its cause")
		}
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrQuoteSchemeUnavailable{}
		if err.Error() != "vm: the IAK declares no signature scheme" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
		if err.Unwrap() != nil {
			t.Error("expected nil unwrap without a cause")
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
		if err.Unwrap() != cause {
			t.Error("Unwrap() should return cause")
		}
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrPCRReadFailed{PCR: 5}
		if !strings.Contains(err.Error(), "PCR 5 read failed") {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})
}

func TestErrQuoteExpired(t *testing.T) {
	err := ErrQuoteExpired{Age: 3600, MaxAge: 300}
	errStr := err.Error()

	if !strings.Contains(errStr, "quote expired") {
		t.Errorf("error should contain 'quote expired': %s", errStr)
	}
	if !strings.Contains(errStr, "3600") {
		t.Errorf("error should contain age: %s", errStr)
	}
	if !strings.Contains(errStr, "300") {
		t.Errorf("error should contain max age: %s", errStr)
	}
}

func TestErrHostBindingInvalid(t *testing.T) {
	err := ErrHostBindingInvalid{
		ExpectedHostID: "host-expected",
		ActualHostID:   "host-actual",
	}
	errStr := err.Error()

	if !strings.Contains(errStr, "host binding invalid") {
		t.Errorf("error should contain 'host binding invalid': %s", errStr)
	}
	if !strings.Contains(errStr, "host-expected") {
		t.Errorf("error should contain expected host: %s", errStr)
	}
	if !strings.Contains(errStr, "host-actual") {
		t.Errorf("error should contain actual host: %s", errStr)
	}
}

func TestErrorsImplementErrorInterface(t *testing.T) {
	errs := []error{
		ErrQuoteGenerationFailed{Reason: "test"},
		ErrQuoteVerificationFailed{Reason: "test"},
		ErrInvalidVMIdentity{Reason: "test"},
		ErrEKCertificateInvalid{Reason: "test"},
		ErrPCRMismatch{PCRIndex: 0},
		ErrNonceMismatch{},
		ErrVTPMNotAvailable{Reason: "test"},
		ErrAIKNotFound{Reason: "test"},
		ErrAttestorNotInitialized{},
		ErrVerifierNotInitialized{},
		ErrInvalidConfig{Reason: "test"},
		ErrContextCanceled{Operation: "test"},
		ErrCertificateChainInvalid{Reason: "test"},
		ErrInvalidHashAlgorithm{Algorithm: "test"},
		ErrSignatureInvalid{Reason: "test"},
		ErrPCRReadFailed{PCR: 0},
		ErrQuoteExpired{Age: 0, MaxAge: 0},
		ErrHostBindingInvalid{},
	}

	for _, err := range errs {
		if err.Error() == "" {
			t.Errorf("Error() returned empty string for %T", err)
		}
	}
}

func TestErrorUnwrapping(t *testing.T) {
	baseErr := errors.New("base error")

	t.Run("QuoteGenerationFailed", func(t *testing.T) {
		err := ErrQuoteGenerationFailed{Cause: baseErr}
		if !errors.Is(err, baseErr) {
			t.Error("errors.Is should find base error")
		}
	})

	t.Run("QuoteVerificationFailed", func(t *testing.T) {
		err := ErrQuoteVerificationFailed{Cause: baseErr}
		if !errors.Is(err, baseErr) {
			t.Error("errors.Is should find base error")
		}
	})

	t.Run("EKCertificateInvalid", func(t *testing.T) {
		err := ErrEKCertificateInvalid{Cause: baseErr}
		if !errors.Is(err, baseErr) {
			t.Error("errors.Is should find base error")
		}
	})

	t.Run("VTPMNotAvailable", func(t *testing.T) {
		err := ErrVTPMNotAvailable{Cause: baseErr}
		if !errors.Is(err, baseErr) {
			t.Error("errors.Is should find base error")
		}
	})

	t.Run("CertificateChainInvalid", func(t *testing.T) {
		err := ErrCertificateChainInvalid{Cause: baseErr}
		if !errors.Is(err, baseErr) {
			t.Error("errors.Is should find base error")
		}
	})

	t.Run("SignatureInvalid", func(t *testing.T) {
		err := ErrSignatureInvalid{Cause: baseErr}
		if !errors.Is(err, baseErr) {
			t.Error("errors.Is should find base error")
		}
	})

	t.Run("PCRReadFailed", func(t *testing.T) {
		err := ErrPCRReadFailed{Cause: baseErr}
		if !errors.Is(err, baseErr) {
			t.Error("errors.Is should find base error")
		}
	})

	t.Run("errors.As", func(t *testing.T) {
		err := ErrQuoteGenerationFailed{Reason: "test", Cause: baseErr}
		var target ErrQuoteGenerationFailed
		if !errors.As(err, &target) {
			t.Error("errors.As should match ErrQuoteGenerationFailed")
		}
		if target.Reason != "test" {
			t.Errorf("Reason = %s, want test", target.Reason)
		}
	})
}
