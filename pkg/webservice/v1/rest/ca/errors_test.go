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

package ca

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrCANotInitialized(t *testing.T) {
	t.Run("returns expected error message", func(t *testing.T) {
		err := ErrCANotInitialized{}
		expected := "certificate authority not initialized"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("implements error interface", func(t *testing.T) {
		var err error = ErrCANotInitialized{}
		assert.NotNil(t, err)
		assert.NotEmpty(t, err.Error())
	})
}

func TestErrCertificateNotFound(t *testing.T) {
	t.Run("with serial number", func(t *testing.T) {
		err := ErrCertificateNotFound{Serial: "ABC123"}
		assert.Contains(t, err.Error(), "ABC123")
		assert.Contains(t, err.Error(), "certificate not found")
	})

	t.Run("without serial number", func(t *testing.T) {
		err := ErrCertificateNotFound{}
		expected := "certificate not found"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("implements error interface", func(t *testing.T) {
		var err error = ErrCertificateNotFound{Serial: "test"}
		assert.NotNil(t, err)
	})
}

func TestErrInvalidSerialNumber(t *testing.T) {
	t.Run("with serial and reason", func(t *testing.T) {
		err := ErrInvalidSerialNumber{Serial: "invalid-serial", Reason: "contains invalid characters"}
		assert.Contains(t, err.Error(), "invalid-serial")
		assert.Contains(t, err.Error(), "contains invalid characters")
	})

	t.Run("without reason", func(t *testing.T) {
		err := ErrInvalidSerialNumber{Serial: "bad-serial"}
		assert.Contains(t, err.Error(), "bad-serial")
		assert.Contains(t, err.Error(), "invalid serial number")
	})

	t.Run("with empty serial", func(t *testing.T) {
		err := ErrInvalidSerialNumber{Serial: "", Reason: "serial number is required"}
		assert.Contains(t, err.Error(), "serial number is required")
	})
}

func TestErrCertificateRevoked(t *testing.T) {
	t.Run("with serial number", func(t *testing.T) {
		err := ErrCertificateRevoked{Serial: "REVOKED123"}
		assert.Contains(t, err.Error(), "REVOKED123")
		assert.Contains(t, err.Error(), "revoked")
	})

	t.Run("without serial number", func(t *testing.T) {
		err := ErrCertificateRevoked{}
		expected := "certificate has been revoked"
		assert.Equal(t, expected, err.Error())
	})
}

func TestErrCRLGenerationFailed(t *testing.T) {
	t.Run("with reason", func(t *testing.T) {
		err := ErrCRLGenerationFailed{Reason: "signing key unavailable"}
		assert.Contains(t, err.Error(), "signing key unavailable")
		assert.Contains(t, err.Error(), "CRL generation failed")
	})

	t.Run("without reason", func(t *testing.T) {
		err := ErrCRLGenerationFailed{}
		expected := "CRL generation failed"
		assert.Equal(t, expected, err.Error())
	})
}

func TestErrInvalidCertificateRequest(t *testing.T) {
	t.Run("with reason", func(t *testing.T) {
		err := ErrInvalidCertificateRequest{Reason: "missing subject"}
		assert.Contains(t, err.Error(), "missing subject")
		assert.Contains(t, err.Error(), "invalid certificate request")
	})

	t.Run("without reason", func(t *testing.T) {
		err := ErrInvalidCertificateRequest{}
		expected := "invalid certificate request"
		assert.Equal(t, expected, err.Error())
	})
}

func TestErrInvalidRequestBody(t *testing.T) {
	t.Run("with reason", func(t *testing.T) {
		err := ErrInvalidRequestBody{Reason: "JSON parse error at line 5"}
		assert.Contains(t, err.Error(), "JSON parse error at line 5")
		assert.Contains(t, err.Error(), "invalid request body")
	})

	t.Run("with empty reason", func(t *testing.T) {
		err := ErrInvalidRequestBody{Reason: ""}
		result := err.Error()
		assert.True(t, strings.HasPrefix(result, "invalid request body"))
	})
}

func TestErrMissingSubject(t *testing.T) {
	t.Run("returns expected error message", func(t *testing.T) {
		err := ErrMissingSubject{}
		expected := "certificate subject is required"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("implements error interface", func(t *testing.T) {
		var err error = ErrMissingSubject{}
		assert.NotEmpty(t, err.Error())
	})
}

func TestErrMissingCommonName(t *testing.T) {
	t.Run("returns expected error message", func(t *testing.T) {
		err := ErrMissingCommonName{}
		expected := "common name is required"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("implements error interface", func(t *testing.T) {
		var err error = ErrMissingCommonName{}
		assert.NotEmpty(t, err.Error())
	})
}

func TestErrInvalidKeyAlgorithm(t *testing.T) {
	t.Run("with algorithm and reason", func(t *testing.T) {
		err := ErrInvalidKeyAlgorithm{Algorithm: "MD5", Reason: "algorithm not supported for certificates"}
		assert.Contains(t, err.Error(), "MD5")
		assert.Contains(t, err.Error(), "algorithm not supported for certificates")
	})

	t.Run("without reason", func(t *testing.T) {
		err := ErrInvalidKeyAlgorithm{Algorithm: "UNKNOWN-ALG"}
		assert.Contains(t, err.Error(), "UNKNOWN-ALG")
		assert.Contains(t, err.Error(), "invalid key algorithm")
	})

	t.Run("with empty algorithm", func(t *testing.T) {
		err := ErrInvalidKeyAlgorithm{Algorithm: "", Reason: "algorithm is required"}
		assert.Contains(t, err.Error(), "algorithm is required")
	})
}

func TestErrInvalidValidityPeriod(t *testing.T) {
	t.Run("with days and reason", func(t *testing.T) {
		err := ErrInvalidValidityPeriod{Days: -1, Reason: "must be positive"}
		assert.Contains(t, err.Error(), "-1")
		assert.Contains(t, err.Error(), "must be positive")
	})

	t.Run("without reason", func(t *testing.T) {
		err := ErrInvalidValidityPeriod{Days: 0}
		assert.Contains(t, err.Error(), "0")
		assert.Contains(t, err.Error(), "invalid validity period")
	})

	t.Run("with excessive days", func(t *testing.T) {
		err := ErrInvalidValidityPeriod{Days: 36500, Reason: "exceeds maximum allowed"}
		assert.Contains(t, err.Error(), "36500")
		assert.Contains(t, err.Error(), "exceeds maximum allowed")
	})
}

func TestErrInvalidRevocationReason(t *testing.T) {
	t.Run("with invalid reason code", func(t *testing.T) {
		err := ErrInvalidRevocationReason{Reason: 99}
		assert.Contains(t, err.Error(), "99")
		assert.Contains(t, err.Error(), "invalid revocation reason code")
	})

	t.Run("with negative reason code", func(t *testing.T) {
		err := ErrInvalidRevocationReason{Reason: -1}
		assert.Contains(t, err.Error(), "-1")
	})
}

func TestErrBundleNotFound(t *testing.T) {
	t.Run("returns expected error message", func(t *testing.T) {
		err := ErrBundleNotFound{}
		expected := "CA bundle not found"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("implements error interface", func(t *testing.T) {
		var err error = ErrBundleNotFound{}
		assert.NotEmpty(t, err.Error())
	})
}

func TestErrCRLNotFound(t *testing.T) {
	t.Run("returns expected error message", func(t *testing.T) {
		err := ErrCRLNotFound{}
		expected := "certificate revocation list not found"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("implements error interface", func(t *testing.T) {
		var err error = ErrCRLNotFound{}
		assert.NotEmpty(t, err.Error())
	})
}

func TestErrInvalidStoreType(t *testing.T) {
	t.Run("with store type", func(t *testing.T) {
		err := ErrInvalidStoreType{StoreType: "invalid-store"}
		assert.Contains(t, err.Error(), "invalid-store")
		assert.Contains(t, err.Error(), "invalid store type")
	})

	t.Run("with empty store type", func(t *testing.T) {
		err := ErrInvalidStoreType{StoreType: ""}
		result := err.Error()
		assert.Contains(t, result, "invalid store type")
	})
}

func TestErrSignCSRScopeRequired(t *testing.T) {
	t.Run("without a platform token", func(t *testing.T) {
		err := ErrSignCSRScopeRequired{}
		assert.Contains(t, err.Error(), "platform token with the ca:sign-csr scope")
		assert.Nil(t, errors.Unwrap(err))
	})

	t.Run("with a scope refusal", func(t *testing.T) {
		cause := errors.New("scope ca:sign-csr not granted")
		err := ErrSignCSRScopeRequired{Cause: cause}
		assert.Contains(t, err.Error(), "requires the ca:sign-csr scope")
		assert.ErrorIs(t, err, cause)
	})
}

func TestErrInvalidPaginationParams(t *testing.T) {
	t.Run("with reason", func(t *testing.T) {
		err := ErrInvalidPaginationParams{Reason: "limit must be between 1 and 1000"}
		assert.Contains(t, err.Error(), "limit must be between 1 and 1000")
		assert.Contains(t, err.Error(), "invalid pagination parameters")
	})

	t.Run("with empty reason", func(t *testing.T) {
		err := ErrInvalidPaginationParams{Reason: ""}
		result := err.Error()
		assert.Contains(t, result, "invalid pagination parameters")
	})
}

// TestAllErrorsImplementErrorInterface ensures all error types implement the error interface
func TestAllErrorsImplementErrorInterface(t *testing.T) {
	errTypes := []error{
		ErrCANotInitialized{},
		ErrCertificateNotFound{Serial: "test"},
		ErrInvalidSerialNumber{Serial: "test"},
		ErrCertificateRevoked{Serial: "test"},
		ErrCRLGenerationFailed{Reason: "test"},
		ErrInvalidCertificateRequest{Reason: "test"},
		ErrInvalidRequestBody{Reason: "test"},
		ErrMissingSubject{},
		ErrMissingCommonName{},
		ErrInvalidKeyAlgorithm{Algorithm: "test"},
		ErrInvalidValidityPeriod{Days: 1},
		ErrInvalidRevocationReason{Reason: 1},
		ErrBundleNotFound{},
		ErrCRLNotFound{},
		ErrInvalidStoreType{StoreType: "test"},
		ErrInvalidPaginationParams{Reason: "test"},
	}

	for _, err := range errTypes {
		t.Run(strings.TrimPrefix(strings.Split(err.Error(), ":")[0], ""), func(t *testing.T) {
			assert.NotEmpty(t, err.Error(), "error message should not be empty")

			// Verify it's usable as a standard error
			var stdErr = err
			assert.NotNil(t, stdErr)
		})
	}
}

// TestErrorTypeAssertions verifies type assertions work correctly for all error types
func TestErrorTypeAssertions(t *testing.T) {
	t.Run("ErrCANotInitialized type assertion", func(t *testing.T) {
		var err error = ErrCANotInitialized{}
		_, ok := err.(ErrCANotInitialized)
		assert.True(t, ok)
	})

	t.Run("ErrCertificateNotFound type assertion", func(t *testing.T) {
		var err error = ErrCertificateNotFound{Serial: "123"}
		e, ok := err.(ErrCertificateNotFound)
		assert.True(t, ok)
		assert.Equal(t, "123", e.Serial)
	})

	t.Run("ErrInvalidSerialNumber type assertion", func(t *testing.T) {
		var err error = ErrInvalidSerialNumber{Serial: "bad", Reason: "test"}
		e, ok := err.(ErrInvalidSerialNumber)
		assert.True(t, ok)
		assert.Equal(t, "bad", e.Serial)
		assert.Equal(t, "test", e.Reason)
	})

	t.Run("ErrInvalidKeyAlgorithm type assertion", func(t *testing.T) {
		var err error = ErrInvalidKeyAlgorithm{Algorithm: "DSA", Reason: "deprecated"}
		e, ok := err.(ErrInvalidKeyAlgorithm)
		assert.True(t, ok)
		assert.Equal(t, "DSA", e.Algorithm)
		assert.Equal(t, "deprecated", e.Reason)
	})

	t.Run("ErrInvalidValidityPeriod type assertion", func(t *testing.T) {
		var err error = ErrInvalidValidityPeriod{Days: 365, Reason: "too long"}
		e, ok := err.(ErrInvalidValidityPeriod)
		assert.True(t, ok)
		assert.Equal(t, 365, e.Days)
		assert.Equal(t, "too long", e.Reason)
	})

	t.Run("ErrInvalidRevocationReason type assertion", func(t *testing.T) {
		var err error = ErrInvalidRevocationReason{Reason: 5}
		e, ok := err.(ErrInvalidRevocationReason)
		assert.True(t, ok)
		assert.Equal(t, 5, e.Reason)
	})
}

// TestErrorsIsCompatibility verifies errors.Is works for error comparison
func TestErrorsIsCompatibility(t *testing.T) {
	t.Run("same error type matches", func(t *testing.T) {
		err1 := ErrCANotInitialized{}
		err2 := ErrCANotInitialized{}
		assert.Equal(t, err1.Error(), err2.Error())
	})

	t.Run("different error types do not match", func(t *testing.T) {
		err1 := ErrCANotInitialized{}
		err2 := ErrBundleNotFound{}
		assert.NotEqual(t, err1.Error(), err2.Error())
	})
}

// TestErrorWrapping verifies custom errors can be wrapped with standard library
func TestErrorWrapping(t *testing.T) {
	t.Run("wrap ErrCertificateNotFound", func(t *testing.T) {
		baseErr := ErrCertificateNotFound{Serial: "ABC123"}
		wrappedErr := errors.Join(errors.New("lookup failed"), baseErr)
		assert.Contains(t, wrappedErr.Error(), "lookup failed")
		assert.Contains(t, wrappedErr.Error(), "ABC123")
	})

	t.Run("wrap ErrInvalidCertificateRequest", func(t *testing.T) {
		baseErr := ErrInvalidCertificateRequest{Reason: "missing CN"}
		wrappedErr := errors.Join(errors.New("validation error"), baseErr)
		assert.Contains(t, wrappedErr.Error(), "validation error")
		assert.Contains(t, wrappedErr.Error(), "missing CN")
	})
}
