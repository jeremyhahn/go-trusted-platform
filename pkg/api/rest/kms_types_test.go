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

package rest

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// KMS Types Error Tests
// =============================================================================

func TestKMSTypesErrors(t *testing.T) {
	t.Parallel()

	t.Run("ErrKMSBatchOperationFailed", func(t *testing.T) {
		t.Parallel()
		err := ErrKMSBatchOperationFailed{
			Operation:    "encrypt",
			SuccessCount: 5,
			FailureCount: 2,
		}
		assert.Equal(t, "batch encrypt operation had failures", err.Error())
	})

	t.Run("ErrKMSBatchOperationFailed_decrypt", func(t *testing.T) {
		t.Parallel()
		err := ErrKMSBatchOperationFailed{
			Operation:    "decrypt",
			SuccessCount: 10,
			FailureCount: 3,
		}
		assert.Equal(t, "batch decrypt operation had failures", err.Error())
	})

	t.Run("ErrKMSRewrapFailed", func(t *testing.T) {
		t.Parallel()
		err := ErrKMSRewrapFailed{Reason: "key rotation in progress"}
		assert.Equal(t, "rewrap failed: key rotation in progress", err.Error())
	})

	t.Run("ErrKMSRewrapFailed_empty_reason", func(t *testing.T) {
		t.Parallel()
		err := ErrKMSRewrapFailed{Reason: ""}
		assert.Equal(t, "rewrap failed: ", err.Error())
	})

	t.Run("ErrKMSBatchItemsEmpty", func(t *testing.T) {
		t.Parallel()
		err := ErrKMSBatchItemsEmpty{}
		assert.Equal(t, "batch items cannot be empty", err.Error())
	})

	t.Run("ErrKMSBatchItemsTooMany", func(t *testing.T) {
		t.Parallel()
		err := ErrKMSBatchItemsTooMany{Count: 1000, Max: 100}
		assert.Equal(t, "batch items exceed maximum allowed", err.Error())
	})

	t.Run("ErrKMSServiceUnavailable_empty_reason", func(t *testing.T) {
		t.Parallel()
		err := ErrKMSServiceUnavailable{Reason: ""}
		assert.Equal(t, "KMS service unavailable", err.Error())
	})

	t.Run("ErrKMSServiceUnavailable_with_reason", func(t *testing.T) {
		t.Parallel()
		err := ErrKMSServiceUnavailable{Reason: "backend maintenance"}
		assert.Equal(t, "KMS service unavailable: backend maintenance", err.Error())
	})
}

// =============================================================================
// KMS Types Error Interface Compliance Tests
// =============================================================================

func TestKMSTypesErrorsImplementError(t *testing.T) {
	t.Parallel()

	// Verify all KMS types error types implement the error interface
	tests := []struct {
		name string
		err  error
	}{
		{"ErrKMSBatchOperationFailed", ErrKMSBatchOperationFailed{Operation: "test"}},
		{"ErrKMSRewrapFailed", ErrKMSRewrapFailed{Reason: "test"}},
		{"ErrKMSBatchItemsEmpty", ErrKMSBatchItemsEmpty{}},
		{"ErrKMSBatchItemsTooMany", ErrKMSBatchItemsTooMany{Count: 100, Max: 50}},
		{"ErrKMSServiceUnavailable", ErrKMSServiceUnavailable{Reason: "test"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Type assertion to verify error interface implementation
			var _ = tt.err
			assert.NotEmpty(t, tt.err.Error())
		})
	}
}
