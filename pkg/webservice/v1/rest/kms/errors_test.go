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

package kms

import (
	"strings"
	"testing"
)

func TestErrKeyManagementClientNotInitialized(t *testing.T) {
	err := ErrKeyManagementClientNotInitialized{}
	expected := "key management client not initialized"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrCryptoClientNotInitialized(t *testing.T) {
	err := ErrCryptoClientNotInitialized{}
	expected := "crypto client not initialized"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrDEKManagementClientNotInitialized(t *testing.T) {
	err := ErrDEKManagementClientNotInitialized{}
	expected := "DEK management client not initialized"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrSecretsManagementClientNotInitialized(t *testing.T) {
	err := ErrSecretsManagementClientNotInitialized{}
	expected := "secrets management client not initialized"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrMissingKeyName(t *testing.T) {
	err := ErrMissingKeyName{}
	expected := "key name is required"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrMissingKeyID(t *testing.T) {
	err := ErrMissingKeyID{}
	expected := "key ID is required"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrInvalidKeyID(t *testing.T) {
	t.Run("with reason", func(t *testing.T) {
		err := ErrInvalidKeyID{KeyID: "test-key", Reason: "contains invalid characters"}
		if !strings.Contains(err.Error(), "test-key") {
			t.Errorf("expected error to contain key ID, got %q", err.Error())
		}
		if !strings.Contains(err.Error(), "contains invalid characters") {
			t.Errorf("expected error to contain reason, got %q", err.Error())
		}
	})

	t.Run("without reason", func(t *testing.T) {
		err := ErrInvalidKeyID{KeyID: "test-key"}
		if !strings.Contains(err.Error(), "test-key") {
			t.Errorf("expected error to contain key ID, got %q", err.Error())
		}
	})
}

func TestErrMissingDEKPath(t *testing.T) {
	err := ErrMissingDEKPath{}
	expected := "DEK path is required"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrInvalidDEKPath(t *testing.T) {
	t.Run("with reason", func(t *testing.T) {
		err := ErrInvalidDEKPath{Path: "/tenant/app", Reason: "path too short"}
		if !strings.Contains(err.Error(), "/tenant/app") {
			t.Errorf("expected error to contain path, got %q", err.Error())
		}
		if !strings.Contains(err.Error(), "path too short") {
			t.Errorf("expected error to contain reason, got %q", err.Error())
		}
	})

	t.Run("without reason", func(t *testing.T) {
		err := ErrInvalidDEKPath{Path: "/tenant/app"}
		if !strings.Contains(err.Error(), "/tenant/app") {
			t.Errorf("expected error to contain path, got %q", err.Error())
		}
	})
}

func TestErrInvalidRequest(t *testing.T) {
	t.Run("with reason", func(t *testing.T) {
		err := ErrInvalidRequest{Reason: "missing required field"}
		if !strings.Contains(err.Error(), "missing required field") {
			t.Errorf("expected error to contain reason, got %q", err.Error())
		}
	})

	t.Run("without reason", func(t *testing.T) {
		err := ErrInvalidRequest{}
		expected := "invalid request"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})
}

func TestErrInvalidRequestBody(t *testing.T) {
	err := ErrInvalidRequestBody{Reason: "JSON parse error"}
	if !strings.Contains(err.Error(), "JSON parse error") {
		t.Errorf("expected error to contain reason, got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "invalid request body") {
		t.Errorf("expected error to contain 'invalid request body', got %q", err.Error())
	}
}

func TestErrMissingPlaintext(t *testing.T) {
	err := ErrMissingPlaintext{}
	expected := "plaintext data is required"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrMissingCiphertext(t *testing.T) {
	err := ErrMissingCiphertext{}
	expected := "ciphertext data is required"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrKeyNotFound(t *testing.T) {
	err := ErrKeyNotFound{KeyID: "my-key-123"}
	if !strings.Contains(err.Error(), "my-key-123") {
		t.Errorf("expected error to contain key ID, got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "key not found") {
		t.Errorf("expected error to contain 'key not found', got %q", err.Error())
	}
}

func TestErrDEKNotFound(t *testing.T) {
	err := ErrDEKNotFound{Path: "/tenant/app/key"}
	if !strings.Contains(err.Error(), "/tenant/app/key") {
		t.Errorf("expected error to contain path, got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "DEK not found") {
		t.Errorf("expected error to contain 'DEK not found', got %q", err.Error())
	}
}

func TestErrInvalidAlgorithm(t *testing.T) {
	t.Run("with reason", func(t *testing.T) {
		err := ErrInvalidAlgorithm{Algorithm: "UNKNOWN-ALG", Reason: "not supported"}
		if !strings.Contains(err.Error(), "UNKNOWN-ALG") {
			t.Errorf("expected error to contain algorithm, got %q", err.Error())
		}
		if !strings.Contains(err.Error(), "not supported") {
			t.Errorf("expected error to contain reason, got %q", err.Error())
		}
	})

	t.Run("without reason", func(t *testing.T) {
		err := ErrInvalidAlgorithm{Algorithm: "UNKNOWN-ALG"}
		if !strings.Contains(err.Error(), "UNKNOWN-ALG") {
			t.Errorf("expected error to contain algorithm, got %q", err.Error())
		}
	})
}

func TestErrInvalidKeyStatus(t *testing.T) {
	t.Run("with reason", func(t *testing.T) {
		err := ErrInvalidKeyStatus{Status: "INVALID", Reason: "unknown status value"}
		if !strings.Contains(err.Error(), "INVALID") {
			t.Errorf("expected error to contain status, got %q", err.Error())
		}
		if !strings.Contains(err.Error(), "unknown status value") {
			t.Errorf("expected error to contain reason, got %q", err.Error())
		}
	})

	t.Run("without reason", func(t *testing.T) {
		err := ErrInvalidKeyStatus{Status: "INVALID"}
		if !strings.Contains(err.Error(), "INVALID") {
			t.Errorf("expected error to contain status, got %q", err.Error())
		}
	})
}

func TestErrMissingKeySpec(t *testing.T) {
	err := ErrMissingKeySpec{}
	expected := "key spec is required"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrInvalidPaginationParams(t *testing.T) {
	err := ErrInvalidPaginationParams{Reason: "limit must be positive"}
	if !strings.Contains(err.Error(), "limit must be positive") {
		t.Errorf("expected error to contain reason, got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "invalid pagination parameters") {
		t.Errorf("expected error to contain 'invalid pagination parameters', got %q", err.Error())
	}
}

func TestErrOperationNotSupported(t *testing.T) {
	t.Run("with reason", func(t *testing.T) {
		err := ErrOperationNotSupported{Operation: "export", Reason: "key is not exportable"}
		if !strings.Contains(err.Error(), "export") {
			t.Errorf("expected error to contain operation, got %q", err.Error())
		}
		if !strings.Contains(err.Error(), "key is not exportable") {
			t.Errorf("expected error to contain reason, got %q", err.Error())
		}
	})

	t.Run("without reason", func(t *testing.T) {
		err := ErrOperationNotSupported{Operation: "export"}
		if !strings.Contains(err.Error(), "export") {
			t.Errorf("expected error to contain operation, got %q", err.Error())
		}
	})
}

func TestErrKeyMaterialRequired(t *testing.T) {
	err := ErrKeyMaterialRequired{}
	expected := "key material is required for import"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrInvalidKeyVersion(t *testing.T) {
	t.Run("with reason", func(t *testing.T) {
		err := ErrInvalidKeyVersion{Version: 5, Reason: "version does not exist"}
		if !strings.Contains(err.Error(), "5") {
			t.Errorf("expected error to contain version, got %q", err.Error())
		}
		if !strings.Contains(err.Error(), "version does not exist") {
			t.Errorf("expected error to contain reason, got %q", err.Error())
		}
	})

	t.Run("without reason", func(t *testing.T) {
		err := ErrInvalidKeyVersion{Version: 5}
		if !strings.Contains(err.Error(), "5") {
			t.Errorf("expected error to contain version, got %q", err.Error())
		}
	})
}

// =============================================================================
// Secrets Error Types
// =============================================================================

func TestErrMissingSecretName(t *testing.T) {
	err := ErrMissingSecretName{}
	expected := "secret name is required"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrMissingSecretID(t *testing.T) {
	err := ErrMissingSecretID{}
	expected := "secret ID is required"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrSecretNotFound(t *testing.T) {
	err := ErrSecretNotFound{SecretID: "my-secret-123"}
	if !strings.Contains(err.Error(), "my-secret-123") {
		t.Errorf("expected error to contain secret ID, got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "secret not found") {
		t.Errorf("expected error to contain 'secret not found', got %q", err.Error())
	}
}

func TestErrMissingSecretData(t *testing.T) {
	err := ErrMissingSecretData{}
	expected := "secret data is required"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrInvalidSecretVersion(t *testing.T) {
	t.Run("with reason", func(t *testing.T) {
		err := ErrInvalidSecretVersion{Version: 3, Reason: "version does not exist"}
		if !strings.Contains(err.Error(), "3") {
			t.Errorf("expected error to contain version, got %q", err.Error())
		}
		if !strings.Contains(err.Error(), "version does not exist") {
			t.Errorf("expected error to contain reason, got %q", err.Error())
		}
	})

	t.Run("without reason", func(t *testing.T) {
		err := ErrInvalidSecretVersion{Version: 3}
		if !strings.Contains(err.Error(), "3") {
			t.Errorf("expected error to contain version, got %q", err.Error())
		}
	})
}

func TestErrInvalidSecretStatus(t *testing.T) {
	t.Run("with reason", func(t *testing.T) {
		err := ErrInvalidSecretStatus{Status: "INVALID", Reason: "unknown status value"}
		if !strings.Contains(err.Error(), "INVALID") {
			t.Errorf("expected error to contain status, got %q", err.Error())
		}
		if !strings.Contains(err.Error(), "unknown status value") {
			t.Errorf("expected error to contain reason, got %q", err.Error())
		}
	})

	t.Run("without reason", func(t *testing.T) {
		err := ErrInvalidSecretStatus{Status: "INVALID"}
		if !strings.Contains(err.Error(), "INVALID") {
			t.Errorf("expected error to contain status, got %q", err.Error())
		}
	})
}

func TestErrMissingTargetVersion(t *testing.T) {
	err := ErrMissingTargetVersion{}
	expected := "target version is required for rollback"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrInvalidRotationPolicy(t *testing.T) {
	t.Run("with reason", func(t *testing.T) {
		err := ErrInvalidRotationPolicy{Reason: "interval must be positive"}
		if !strings.Contains(err.Error(), "interval must be positive") {
			t.Errorf("expected error to contain reason, got %q", err.Error())
		}
		if !strings.Contains(err.Error(), "invalid rotation policy") {
			t.Errorf("expected error to contain 'invalid rotation policy', got %q", err.Error())
		}
	})

	t.Run("without reason", func(t *testing.T) {
		err := ErrInvalidRotationPolicy{}
		expected := "invalid rotation policy"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})
}

// =============================================================================
// Crypto Error Types
// =============================================================================

func TestErrMissingMessage(t *testing.T) {
	err := ErrMissingMessage{}
	expected := "message data is required"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrMissingSignature(t *testing.T) {
	err := ErrMissingSignature{}
	expected := "signature is required"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrMissingData(t *testing.T) {
	err := ErrMissingData{}
	expected := "data is required"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrMissingHMAC(t *testing.T) {
	err := ErrMissingHMAC{}
	expected := "HMAC is required"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrInvalidNumBytes(t *testing.T) {
	t.Run("with reason", func(t *testing.T) {
		err := ErrInvalidNumBytes{NumBytes: 0, Reason: "must be greater than 0"}
		if !strings.Contains(err.Error(), "0") {
			t.Errorf("expected error to contain number, got %q", err.Error())
		}
		if !strings.Contains(err.Error(), "must be greater than 0") {
			t.Errorf("expected error to contain reason, got %q", err.Error())
		}
	})

	t.Run("without reason", func(t *testing.T) {
		err := ErrInvalidNumBytes{NumBytes: -5}
		if !strings.Contains(err.Error(), "-5") {
			t.Errorf("expected error to contain number, got %q", err.Error())
		}
	})
}

func TestErrInvalidHashAlgorithm(t *testing.T) {
	t.Run("with reason", func(t *testing.T) {
		err := ErrInvalidHashAlgorithm{Algorithm: "MD5", Reason: "not supported"}
		if !strings.Contains(err.Error(), "MD5") {
			t.Errorf("expected error to contain algorithm, got %q", err.Error())
		}
		if !strings.Contains(err.Error(), "not supported") {
			t.Errorf("expected error to contain reason, got %q", err.Error())
		}
	})

	t.Run("without reason", func(t *testing.T) {
		err := ErrInvalidHashAlgorithm{Algorithm: "MD5"}
		if !strings.Contains(err.Error(), "MD5") {
			t.Errorf("expected error to contain algorithm, got %q", err.Error())
		}
	})
}

func TestErrMissingBatchItems(t *testing.T) {
	err := ErrMissingBatchItems{}
	expected := "batch items are required"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrInvalidBatchOperation(t *testing.T) {
	err := ErrInvalidBatchOperation{Operation: "transform"}
	if !strings.Contains(err.Error(), "transform") {
		t.Errorf("expected error to contain operation, got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "encrypt") {
		t.Errorf("expected error to mention 'encrypt', got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "decrypt") {
		t.Errorf("expected error to mention 'decrypt', got %q", err.Error())
	}
}

// Test that all errors implement the error interface
func TestErrorInterface(t *testing.T) {
	errors := []error{
		ErrKeyManagementClientNotInitialized{},
		ErrCryptoClientNotInitialized{},
		ErrDEKManagementClientNotInitialized{},
		ErrSecretsManagementClientNotInitialized{},
		ErrMissingKeyName{},
		ErrMissingKeyID{},
		ErrInvalidKeyID{KeyID: "test"},
		ErrMissingDEKPath{},
		ErrInvalidDEKPath{Path: "test"},
		ErrInvalidRequest{},
		ErrInvalidRequestBody{Reason: "test"},
		ErrMissingPlaintext{},
		ErrMissingCiphertext{},
		ErrKeyNotFound{KeyID: "test"},
		ErrDEKNotFound{Path: "test"},
		ErrInvalidAlgorithm{Algorithm: "test"},
		ErrInvalidKeyStatus{Status: "test"},
		ErrMissingKeySpec{},
		ErrInvalidPaginationParams{Reason: "test"},
		ErrOperationNotSupported{Operation: "test"},
		ErrKeyMaterialRequired{},
		ErrInvalidKeyVersion{Version: 1},
		// Secrets errors
		ErrMissingSecretName{},
		ErrMissingSecretID{},
		ErrSecretNotFound{SecretID: "test"},
		ErrMissingSecretData{},
		ErrInvalidSecretVersion{Version: 1},
		ErrInvalidSecretStatus{Status: "test"},
		ErrMissingTargetVersion{},
		ErrInvalidRotationPolicy{},
		// Crypto errors
		ErrMissingMessage{},
		ErrMissingSignature{},
		ErrMissingData{},
		ErrMissingHMAC{},
		ErrInvalidNumBytes{NumBytes: 0},
		ErrInvalidHashAlgorithm{Algorithm: "test"},
		ErrMissingBatchItems{},
		ErrInvalidBatchOperation{Operation: "test"},
	}

	for _, err := range errors {
		if err.Error() == "" {
			t.Errorf("error %T returned empty string", err)
		}
	}
}
